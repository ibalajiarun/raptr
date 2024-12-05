// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{crypto::SignatureVerifier, NodeId},
    raikou::{
        protocol,
        types::{BatchInfo, Payload, AC},
    },
};
use anyhow::Context;
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, HashValue};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    cmp::Ordering,
    fmt::{Debug, Formatter},
};

pub type Txn = aptos_types::transaction::SignedTransaction;

pub type Round = i64; // Round number.

pub type Prefix = aptos_consensus_types::payload::Prefix;

pub type PrefixSet = aptos_consensus_types::payload::PrefixSet;

pub type BlockSize = usize;

pub type BatchHash = HashValue;

pub type BlockHash = HashValue;

// Must not exceed 14 due to the implementation of `PrefixSet`.
pub const N_SUB_BLOCKS: Prefix = aptos_consensus_types::payload::N_SUB_BLOCKS;

#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "BlockSerialization")]
pub struct Block {
    pub data: BlockData,
    pub signature: Signature,
    #[serde(skip)]
    pub digest: BlockHash,
}

#[derive(Deserialize)]
struct BlockSerialization {
    data: BlockData,
    signature: Signature,
}

impl From<BlockSerialization> for Block {
    fn from(serialized: BlockSerialization) -> Self {
        Block::new(serialized.data, serialized.signature)
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct BlockData {
    pub payload: Payload,
    pub parent_qc: QC,
    pub reason: RoundEnterReason,
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct BlockSignatureData {
    pub digest: BlockHash,
}

impl Block {
    pub fn new(data: BlockData, signature: Signature) -> Self {
        Block {
            digest: data.hash(),
            data,
            signature,
        }
    }

    pub fn round(&self) -> Round {
        self.payload().round()
    }

    pub fn author(&self) -> NodeId {
        self.payload().author()
    }

    pub fn payload(&self) -> &Payload {
        &self.data.payload
    }

    pub fn parent_qc(&self) -> &QC {
        &self.data.parent_qc
    }

    pub fn reason(&self) -> &RoundEnterReason {
        &self.data.reason
    }

    pub fn acs(&self) -> &Vec<AC> {
        self.payload().acs()
    }

    pub fn sub_blocks(&self) -> impl ExactSizeIterator<Item = &Vec<BatchInfo>> {
        self.payload().sub_blocks()
    }

    pub fn sub_block(&self, index: usize) -> &[BatchInfo] {
        self.sub_blocks().nth(index).unwrap()
    }

    pub fn verify<S>(&self, verifier: &protocol::Verifier<S>) -> anyhow::Result<()> {
        if self.round() == 0 {
            return Err(anyhow::anyhow!("Invalid Block round: 0"));
        }

        let sig_verifier = &verifier.sig_verifier;
        let quorum = verifier.config.ac_quorum;

        self.payload()
            .verify(verifier)
            .context("Error verifying payload")?;
        self.parent_qc()
            .verify(sig_verifier, quorum)
            .context("Error verifying parent_qc")?;
        self.reason()
            .verify(self.round(), &self.parent_qc(), sig_verifier, quorum)
            .context("Error verifying entry reason")?;

        let sig_data = BlockSignatureData {
            digest: self.digest.clone(),
        };

        sig_verifier
            .verify(self.author(), &sig_data, &self.signature)
            .context("Error verifying author signature")?;

        Ok(())
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct QcVoteSignatureData {
    pub round: Round,
    pub prefix: Prefix,
    pub block_digest: BlockHash,
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct TcVoteSignatureData {
    pub timeout_round: Round,
    pub qc_high_id: SubBlockId,
}

#[derive(
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    CryptoHasher,
    BCSCryptoHash,
    Serialize,
    Deserialize,
)]
pub struct SubBlockId {
    pub round: Round,
    pub prefix: Prefix,
}

impl SubBlockId {
    pub fn new(round: Round, prefix: Prefix) -> Self {
        SubBlockId { round, prefix }
    }

    pub fn genesis() -> Self {
        SubBlockId::new(0, 0)
    }
}

impl From<(Round, Prefix)> for SubBlockId {
    fn from(tuple: (Round, Prefix)) -> Self {
        let (round, prefix) = tuple;
        SubBlockId { round, prefix }
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct QC {
    pub round: Round,
    pub prefix: Prefix,
    pub block_digest: HashValue,
    pub vote_prefixes: PrefixSet,
    pub aggregated_signature: Option<Signature>, // `None` only for the genesis QC.
}

impl Debug for QC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QC")
            .field("round", &self.round)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl QC {
    pub fn genesis() -> Self {
        QC {
            round: 0,
            prefix: N_SUB_BLOCKS,
            block_digest: HashValue::zero(),
            vote_prefixes: PrefixSet::empty(),
            aggregated_signature: None,
        }
    }

    pub fn signer_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.vote_prefixes.node_ids()
    }

    pub fn is_genesis(&self) -> bool {
        self.round == 0
    }

    pub fn is_full(&self) -> bool {
        self.prefix == N_SUB_BLOCKS
    }

    pub fn sub_block_id(&self) -> SubBlockId {
        (self.round, self.prefix).into()
    }

    pub fn verify(&self, sig_verifier: &SignatureVerifier, quorum: usize) -> anyhow::Result<()> {
        if self.is_genesis() {
            return if self.vote_prefixes.is_empty()
                && self.block_digest == HashValue::zero()
                && self.aggregated_signature.is_none()
            {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Invalid genesis QC"))
            };
        }

        if self.aggregated_signature.is_none() {
            return Err(anyhow::anyhow!("Missing aggregated signature"));
        }

        let sig_data: Vec<_> = self
            .vote_prefixes
            .prefixes()
            .map(|prefix| QcVoteSignatureData {
                round: self.round,
                prefix,
                block_digest: self.block_digest.clone(),
            })
            .collect();

        if sig_data.len() < quorum {
            return Err(anyhow::anyhow!("Not enough signers"));
        }

        sig_verifier.verify_aggregate_signatures(
            self.vote_prefixes.node_ids(),
            sig_data.iter().collect(),
            self.aggregated_signature.as_ref().unwrap(),
        )
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.sub_block_id() == other.sub_block_id()
    }
}

impl Eq for QC {}

impl PartialOrd for QC {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.sub_block_id().partial_cmp(&other.sub_block_id())
    }
}

impl Ord for QC {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sub_block_id().cmp(&other.sub_block_id())
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
#[serde(from = "CcSerialization")]
pub struct CC {
    round: Round,
    block_digest: HashValue,
    vote_prefixes: PrefixSet,
    aggregated_signature: Signature,

    #[serde(skip)]
    min_prefix: Prefix,
    #[serde(skip)]
    max_prefix: Prefix,
}

#[derive(Deserialize)]
struct CcSerialization {
    round: Round,
    block_digest: HashValue,
    vote_prefixes: PrefixSet,
    aggregated_signature: Signature,
}

impl From<CcSerialization> for CC {
    fn from(serialized: CcSerialization) -> Self {
        CC::new(
            serialized.round,
            serialized.block_digest,
            serialized.vote_prefixes,
            serialized.aggregated_signature,
        )
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct CcVoteSignatureData {
    pub round: Round,
    pub block_digest: BlockHash,
    pub prefix: Prefix,
}

impl CC {
    pub fn new(
        round: Round,
        block_digest: BlockHash,
        vote_prefixes: PrefixSet,
        aggregated_signature: Signature,
    ) -> Self {
        CC {
            round,
            block_digest,
            aggregated_signature,
            min_prefix: vote_prefixes.prefixes().min().unwrap(),
            max_prefix: vote_prefixes.prefixes().max().unwrap(),
            vote_prefixes,
        }
    }

    pub fn lowest_qc_id(&self) -> SubBlockId {
        (self.round, self.min_prefix).into()
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        (self.round, self.max_prefix).into()
    }

    pub fn verify(&self, verifier: &SignatureVerifier, quorum: usize) -> anyhow::Result<()> {
        let sig_data: Vec<_> = self
            .vote_prefixes
            .prefixes()
            .map(|prefix| CcVoteSignatureData {
                round: self.round,
                prefix,
                block_digest: self.block_digest,
            })
            .collect();

        if sig_data.len() < quorum {
            return Err(anyhow::anyhow!("Not enough signers"));
        }

        verifier.verify_aggregate_signatures(
            self.vote_prefixes.node_ids(),
            sig_data.iter().collect(),
            &self.aggregated_signature,
        )
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
#[serde(from = "TcSerialization")]
pub struct TC {
    timeout_round: Round,
    vote_data: Vec<(NodeId, SubBlockId)>,
    aggregated_signature: Signature,

    #[serde(skip)]
    max_vote: SubBlockId,
}

#[derive(Deserialize)]
struct TcSerialization {
    timeout_round: Round,
    vote_data: Vec<(NodeId, SubBlockId)>,
    aggregated_signature: Signature,
}

impl From<TcSerialization> for TC {
    fn from(serialized: TcSerialization) -> Self {
        TC::new(
            serialized.timeout_round,
            serialized.vote_data,
            serialized.aggregated_signature,
        )
    }
}

impl TC {
    pub fn new(
        timeout_round: Round,
        vote_data: Vec<(NodeId, SubBlockId)>,
        aggregated_signature: Signature,
    ) -> Self {
        TC {
            timeout_round,
            max_vote: vote_data
                .iter()
                .map(|(_, qc_high_id)| *qc_high_id)
                .max()
                .unwrap(),
            vote_data,
            aggregated_signature,
        }
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        self.max_vote
    }

    pub fn verify(&self, verifier: &SignatureVerifier, quorum: usize) -> anyhow::Result<()> {
        let sig_data: Vec<_> = self
            .vote_data
            .iter()
            .map(|(node_id, qc_high_id)| TcVoteSignatureData {
                timeout_round: self.timeout_round,
                qc_high_id: *qc_high_id,
            })
            .collect();

        if sig_data.len() < quorum {
            return Err(anyhow::anyhow!("Not enough signers"));
        }

        verifier.verify_aggregate_signatures(
            self.vote_data.iter().map(|(node_id, _)| *node_id),
            sig_data.iter().collect(),
            &self.aggregated_signature,
        )
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub enum RoundEnterReason {
    /// When a node receives a QC for the full prefix of round r, it enters round r+1.
    FullPrefixQC,
    /// When a node receives a CC for round r, it enters round r+1.
    CC(CC),
    /// When a node receives a TC for round r, it enters round r+1.
    TC(TC),
}

impl Debug for RoundEnterReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundEnterReason::FullPrefixQC => write!(f, "Full Prefix QC"),
            RoundEnterReason::CC(cc) => write!(f, "CC({})", cc.round),
            RoundEnterReason::TC(tc) => write!(f, "TC({})", tc.timeout_round),
        }
    }
}

impl RoundEnterReason {
    pub fn verify(
        &self,
        round: Round,
        qc: &QC,
        verifier: &SignatureVerifier,
        quorum: usize,
    ) -> anyhow::Result<()> {
        match self {
            RoundEnterReason::FullPrefixQC => {
                if !(qc.round == round - 1 && qc.is_full()) {
                    return Err(anyhow::anyhow!("Invalid FullPrefixQC entry reason"));
                }
                Ok(())
            },
            RoundEnterReason::CC(cc) => {
                if !(cc.round == round - 1 && qc.sub_block_id() >= cc.highest_qc_id()) {
                    return Err(anyhow::anyhow!("Invalid CC entry reason"));
                }
                cc.verify(verifier, quorum)
                    .context("Error verifying the CC")
            },
            RoundEnterReason::TC(tc) => {
                if !(tc.timeout_round == round - 1 && qc.sub_block_id() >= tc.highest_qc_id()) {
                    return Err(anyhow::anyhow!("Invalid TC entry reason"));
                }
                tc.verify(verifier, quorum)
                    .context("Error verifying the TC")
            },
        }
    }
}
