// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{crypto::SignatureVerifier, NodeId},
    monitor,
    raikou::{
        protocol,
        types::{BatchInfo, Payload, PoA},
    },
};
use anyhow::{ensure, Context};
use aptos_bitvec::BitVec;
use aptos_consensus_types::{proof_of_store::ProofCache, round_timeout::RoundTimeoutReason};
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, HashValue};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fmt::{Debug, Display, Formatter},
    sync::Arc,
    time::Instant,
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
    pub timestamp_usecs: u64,
    pub payload: Payload,
    pub reason: RoundEntryReason,
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

    pub fn parent_qc(&self) -> &QC {
        self.reason().qc()
    }

    pub fn payload(&self) -> &Payload {
        &self.data.payload
    }

    pub fn reason(&self) -> &RoundEntryReason {
        &self.data.reason
    }

    pub fn poas(&self) -> &Vec<PoA> {
        self.payload().poas()
    }

    pub fn sub_blocks(&self) -> impl ExactSizeIterator<Item = &Vec<BatchInfo>> {
        self.payload().sub_blocks()
    }

    pub fn sub_block(&self, index: usize) -> &[BatchInfo] {
        self.sub_blocks().nth(index).unwrap()
    }

    pub fn verify<S: Sync>(&self, verifier: &protocol::Verifier<S>) -> anyhow::Result<()> {
        if self.round() == 0 {
            return Err(anyhow::anyhow!("Invalid Block round: 0"));
        }

        ensure!(
            !matches!(self.reason(), RoundEntryReason::ThisRoundQC(_)),
            "ThisRoundQC cannot be used as entry reason in a block"
        );

        let sig_verifier = &verifier.sig_verifier;
        let quorum = verifier.config.poa_quorum;

        self.payload()
            .verify(verifier)
            .context("Error verifying payload")?;
        self.reason()
            .verify(self.round(), sig_verifier, quorum)
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
pub struct QcVoteSignatureCommonData {
    pub round: Round,
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
    data: Arc<QcData>,
}

#[derive(CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
struct QcData {
    round: Round,
    block_digest: HashValue,
    vote_prefixes: PrefixSet,
    tagged_multi_signature: Option<Signature>, // `None` only for the genesis QC.

    missing_authors: Option<BitVec>,

    // Unlike in the pseudocode, for convenience, we include the prefix as part of the QC
    // and check it as part of the verification.
    prefix: Prefix,
}

impl Debug for QC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QC")
            .field("round", &self.round())
            .field("prefix", &self.prefix())
            .finish()
    }
}

impl QC {
    pub fn new(
        round: Round,
        block_digest: HashValue,
        vote_prefixes: PrefixSet,
        tagged_multi_signature: Signature,
        missing_authors: BitVec,
        storage_requirement: usize,
    ) -> Self {
        // `prefix` is the maximum number such that at least `storage_requirement` nodes
        // have voted for a prefix of size `prefix` or larger.
        let prefix = vote_prefixes
            .prefixes()
            .sorted()
            .skip(storage_requirement - 1)
            .next()
            .unwrap();

        QC {
            data: Arc::new(QcData {
                round,
                block_digest,
                vote_prefixes,
                tagged_multi_signature: Some(tagged_multi_signature),
                missing_authors: Some(missing_authors),
                prefix,
            }),
        }
    }

    pub fn genesis() -> Self {
        QC {
            data: Arc::new(QcData {
                round: 0,
                prefix: N_SUB_BLOCKS,
                block_digest: HashValue::zero(),
                vote_prefixes: PrefixSet::empty(),
                tagged_multi_signature: None,
                missing_authors: None,
            }),
        }
    }

    pub fn round(&self) -> Round {
        self.data.round
    }

    pub fn block_digest(&self) -> &HashValue {
        &self.data.block_digest
    }

    pub fn vote_prefixes(&self) -> &PrefixSet {
        &self.data.vote_prefixes
    }

    pub fn tagged_multi_signature(&self) -> &Option<Signature> {
        &self.data.tagged_multi_signature
    }

    pub fn missing_authors(&self) -> &Option<BitVec> {
        &self.data.missing_authors
    }

    pub fn prefix(&self) -> Prefix {
        self.data.prefix
    }

    pub fn signer_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.vote_prefixes().node_ids()
    }

    pub fn is_genesis(&self) -> bool {
        self.round() == 0
    }

    pub fn is_full(&self) -> bool {
        self.prefix() == N_SUB_BLOCKS
    }

    pub fn id(&self) -> SubBlockId {
        (self.round(), self.prefix()).into()
    }

    pub fn verify(&self, sig_verifier: &SignatureVerifier, quorum: usize) -> anyhow::Result<()> {
        if self.is_genesis() {
            return if self.vote_prefixes().is_empty()
                && *self.block_digest() == HashValue::zero()
                && self.tagged_multi_signature().is_none()
            {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Invalid genesis QC"))
            };
        }

        if self.tagged_multi_signature().is_none() {
            return Err(anyhow::anyhow!("Missing aggregated signature"));
        }

        let message = QcVoteSignatureCommonData {
            round: self.round(),
            block_digest: self.block_digest().clone(),
        };

        let node_ids = self.vote_prefixes().node_ids().collect_vec();
        let tags = self.vote_prefixes().prefixes().collect_vec();

        if node_ids.len() < quorum {
            return Err(anyhow::anyhow!("Not enough signers"));
        }

        sig_verifier.verify_tagged_multi_signature(
            node_ids,
            &message,
            tags,
            self.tagged_multi_signature().as_ref().unwrap(),
        )
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
#[serde(from = "CcSerialization")]
pub struct CC {
    round: Round,
    block_digest: HashValue,
    vote_prefixes: PrefixSet,
    tagged_multi_signature: Signature,

    #[serde(skip)]
    min_prefix: Prefix,
    #[serde(skip)]
    max_prefix: Prefix,
}

impl Debug for CC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CC")
            .field("round", &self.round)
            .field("min_prefix", &self.min_prefix)
            .field("max_prefix", &self.max_prefix)
            .finish()
    }
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
pub struct CcVoteSignatureCommonData {
    pub round: Round,
    pub block_digest: BlockHash,
}

impl CC {
    pub fn new(
        round: Round,
        block_digest: BlockHash,
        vote_prefixes: PrefixSet,
        tagged_multi_signature: Signature,
    ) -> Self {
        CC {
            round,
            block_digest,
            tagged_multi_signature,
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
        let message = CcVoteSignatureCommonData {
            round: self.round,
            block_digest: self.block_digest,
        };

        let nodes = self.vote_prefixes.node_ids().collect_vec();
        let tags = self.vote_prefixes.prefixes().collect_vec();

        if nodes.len() < quorum {
            return Err(anyhow::anyhow!("Not enough signers"));
        }

        verifier.verify_tagged_multi_signature(nodes, &message, tags, &self.tagged_multi_signature)
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
#[serde(from = "TcSerialization")]
pub struct TC {
    timeout_round: Round,
    vote_data: Vec<(NodeId, SubBlockId)>,
    aggregated_signature: Signature,
    round_timeout_reason: RoundTimeoutReason,

    #[serde(skip)]
    max_vote: SubBlockId,
}

impl Debug for TC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TC")
            .field("timeout_round", &self.timeout_round)
            .field("max_vote", &self.max_vote)
            .finish()
    }
}

impl TC {
    pub fn reason(&self) -> RoundTimeoutReason {
        self.round_timeout_reason.clone()
    }
}

#[derive(Deserialize)]
struct TcSerialization {
    timeout_round: Round,
    vote_data: Vec<(NodeId, SubBlockId)>,
    aggregated_signature: Signature,
    timeout_reason: RoundTimeoutReason,
}

impl From<TcSerialization> for TC {
    fn from(serialized: TcSerialization) -> Self {
        TC::new(
            serialized.timeout_round,
            serialized.vote_data,
            serialized.aggregated_signature,
            serialized.timeout_reason,
        )
    }
}

impl TC {
    pub fn new(
        timeout_round: Round,
        vote_data: Vec<(NodeId, SubBlockId)>,
        aggregated_signature: Signature,
        round_timeout_reason: RoundTimeoutReason,
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
            round_timeout_reason,
        }
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        self.max_vote
    }

    pub fn verify(&self, verifier: &SignatureVerifier, quorum: usize) -> anyhow::Result<()> {
        let nodes = self
            .vote_data
            .iter()
            .map(|(node_id, _)| *node_id)
            .collect_vec();

        ensure!(
            nodes.windows(2).all(|w| w[0] < w[1]),
            "TC nodes must be sorted and unique"
        );

        let sig_data: Vec<_> = self
            .vote_data
            .iter()
            .map(|(_node_id, qc_high_id)| TcVoteSignatureData {
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
pub enum RoundEntryReason {
    /// When a node receives a QC for round r, it can enter round r.
    ThisRoundQC(QC),
    /// When a node receives a full-prefix QC for round r, it can enter round r+1.
    FullPrefixQC(QC),
    /// When a node receives a CC for round r, it can enter round r+1.
    CC(CC, QC),
    /// When a node receives a TC for round r, it can enter round r+1.
    TC(TC, QC),
}

impl Display for RoundEntryReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundEntryReason::ThisRoundQC(_) => write!(f, "ThisRoundQC"),
            RoundEntryReason::FullPrefixQC(_) => write!(f, "FullPrefixQC"),
            RoundEntryReason::CC(_, _) => write!(f, "CC"),
            RoundEntryReason::TC(_, _) => write!(f, "TC"),
        }
    }
}

impl Debug for RoundEntryReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundEntryReason::ThisRoundQC(qc) => write!(f, "ThisRoundQC({:?})", qc),
            RoundEntryReason::FullPrefixQC(qc) => write!(f, "Full Prefix {:?}", qc),
            RoundEntryReason::CC(cc, qc) => write!(f, "CC({:?}, {:?})", cc, qc),
            RoundEntryReason::TC(tc, qc) => write!(f, "TC({:?}, {:?})", tc, qc),
        }
    }
}

impl RoundEntryReason {
    pub fn qc(&self) -> &QC {
        match self {
            RoundEntryReason::ThisRoundQC(qc) => qc,
            RoundEntryReason::FullPrefixQC(qc) => qc,
            RoundEntryReason::CC(_, qc) => qc,
            RoundEntryReason::TC(_, qc) => qc,
        }
    }

    pub fn verify(
        &self,
        round: Round,
        verifier: &SignatureVerifier,
        quorum: usize,
    ) -> anyhow::Result<()> {
        match self {
            RoundEntryReason::ThisRoundQC(qc) => {
                ensure!(
                    qc.round() == round,
                    "Invalid QC round in ThisRoundQC entry reason"
                );

                qc.verify(verifier, quorum)
                    .context("Error verifying the QC")
            },
            RoundEntryReason::FullPrefixQC(qc) => {
                if !(qc.round() == round - 1 && qc.is_full()) {
                    return Err(anyhow::anyhow!("Invalid FullPrefixQC entry reason"));
                }
                qc.verify(verifier, quorum)
                    .context("Error verifying the QC")
            },
            RoundEntryReason::CC(cc, qc) => {
                if !(cc.round == round - 1 && qc.id() >= cc.highest_qc_id()) {
                    return Err(anyhow::anyhow!("Invalid CC entry reason"));
                }
                cc.verify(verifier, quorum)
                    .context("Error verifying the CC")?;
                qc.verify(verifier, quorum)
                    .context("Error verifying the QC")
            },
            RoundEntryReason::TC(tc, qc) => {
                if !(tc.timeout_round == round - 1 && qc.id() >= tc.highest_qc_id()) {
                    return Err(anyhow::anyhow!("Invalid TC entry reason"));
                }
                tc.verify(verifier, quorum)
                    .context("Error verifying the TC")?;
                qc.verify(verifier, quorum)
                    .context("Error verifying the QC")
            },
        }
    }
}
