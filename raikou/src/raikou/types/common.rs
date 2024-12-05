// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{crypto::Verifier, NodeId},
    raikou::types::{BatchInfo, Payload, AC},
};
use anyhow::Context;
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, Genesis, HashValue};
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

    pub fn validate(&self, verifier: &Verifier) -> anyhow::Result<()> {
        if self.round() == 0 {
            return Err(anyhow::anyhow!("Invalid Block round: 0"));
        }

        self.payload()
            .validate(verifier)
            .context("Error verifying payload")?;
        self.parent_qc()
            .validate(verifier)
            .context("Error verifying parent_qc")?;
        self.reason()
            .validate(self.round(), &self.parent_qc(), verifier)
            .context("Error verifying entry reason")?;

        verifier
            .verify(
                self.author(),
                &BlockSignatureData {
                    digest: self.digest.clone(),
                },
                &self.signature,
            )
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

    fn validate_structure(&self) -> bool {
        if self.is_genesis() {
            return self.vote_prefixes.is_empty()
                && self.block_digest == HashValue::zero()
                && self.aggregated_signature.is_none();
        }

        if self.aggregated_signature.is_none() {
            return false; // Non-genesis block without a signature.
        }

        // TODO: verify that `vote_data.len() >= quorum` and `prefix` is the S+1'st maximum.
        //       The issue is that we would have to pass these parameters here from the config.

        true
    }

    pub fn validate(&self, verifier: &Verifier) -> anyhow::Result<()> {
        if !self.validate_structure() {
            return Err(anyhow::anyhow!("Invalid QC structure"));
        }

        if self.is_genesis() {
            return Ok(());
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

        verifier.verify_aggregate_signatures(
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

    pub fn validate(&self, verifier: &Verifier) -> anyhow::Result<()> {
        let sig_data: Vec<_> = self
            .vote_prefixes
            .prefixes()
            .map(|prefix| CcVoteSignatureData {
                round: self.round,
                prefix,
                block_digest: self.block_digest,
            })
            .collect();

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

    pub fn validate(&self, verifier: &Verifier) -> anyhow::Result<()> {
        let sig_data: Vec<_> = self
            .vote_data
            .iter()
            .map(|(node_id, qc_high_id)| TcVoteSignatureData {
                timeout_round: self.timeout_round,
                qc_high_id: *qc_high_id,
            })
            .collect();

        verifier.verify_aggregate_signatures(
            self.vote_data.iter().map(|(node_id, _)| *node_id),
            sig_data.iter().collect(),
            &self.aggregated_signature,
        )
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub enum RoundEnterReason {
    /// Special case for the genesis block.
    Genesis,
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
            RoundEnterReason::Genesis => write!(f, "Genesis"),
            RoundEnterReason::FullPrefixQC => write!(f, "Full Prefix QC"),
            RoundEnterReason::CC(cc) => write!(f, "CC({})", cc.round),
            RoundEnterReason::TC(tc) => write!(f, "TC({})", tc.timeout_round),
        }
    }
}

impl RoundEnterReason {
    pub fn validate(&self, round: Round, qc: &QC, verifier: &Verifier) -> anyhow::Result<()> {
        match self {
            RoundEnterReason::Genesis => {
                if round != 0 {
                    return Err(anyhow::anyhow!("Invalid Genesis entry reason"));
                }
            },
            RoundEnterReason::FullPrefixQC => {
                if !(qc.round == round - 1 && qc.is_full()) {
                    return Err(anyhow::anyhow!("Invalid FullPrefixQC entry reason"));
                }
                qc.validate(verifier)?;
            },
            RoundEnterReason::CC(cc) => {
                if !(cc.round == round - 1 && qc.sub_block_id() >= cc.highest_qc_id()) {
                    return Err(anyhow::anyhow!("Invalid CC entry reason"));
                }
                cc.validate(verifier)?;
            },
            RoundEnterReason::TC(tc) => {
                if !(tc.timeout_round == round - 1 && qc.sub_block_id() >= tc.highest_qc_id()) {
                    return Err(anyhow::anyhow!("Invalid TC entry reason"));
                }
                tc.validate(verifier)?;
            },
        }

        Ok(())
    }
}
