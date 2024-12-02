// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::NodeId,
    raikou::types::{BatchInfo, Payload, AC},
};
use aptos_consensus_types::common::Author;
use aptos_crypto::{
    bls12381::Signature, hash::CryptoHash, CryptoMaterialError, Genesis, HashValue,
};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::{
    aggregate_signature::AggregateSignature, validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    cmp::Ordering,
    fmt::{Debug, Formatter},
};

pub type Round = i64; // Round number.

pub type Prefix = aptos_consensus_types::payload::Prefix;

pub type PrefixSet = aptos_consensus_types::payload::PrefixSet;

pub type BlockSize = usize;

pub type BatchHash = HashValue;

pub type BlockHash = HashValue;

#[derive(Clone, Serialize)]
pub struct Block {
    #[serde(skip)]
    pub digest: BlockHash,
    pub data: BlockData,
    pub signature: Option<Signature>,
}

impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename = "Block")]
        struct BlockWithoutId {
            block_data: BlockData,
            signature: Option<Signature>,
        }

        let BlockWithoutId {
            block_data,
            signature,
        } = BlockWithoutId::deserialize(deserializer)?;

        Ok(Block {
            digest: block_data.hash(),
            data: block_data,
            signature,
        })
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct BlockData {
    pub round: Round,
    pub payload: Payload,
    pub parent_qc: Option<QC>, // `None` only for the genesis block.
    pub author: Option<Author>,
    pub reason: RoundEnterReason,
}

impl BlockData {
    pub fn sign(&self, signer: &ValidatorSigner) -> Result<Signature, CryptoMaterialError> {
        signer.sign(self)
    }
}

impl Block {
    pub fn genesis() -> Self {
        let data = BlockData {
            round: 0,
            payload: Payload::empty(-1, 999999999),
            parent_qc: None,
            author: None,
            reason: RoundEnterReason::Genesis,
        };
        Block {
            digest: data.hash(),
            data,
            signature: None,
        }
    }

    pub fn round(&self) -> Round {
        self.data.round
    }

    pub fn payload(&self) -> &Payload {
        &self.data.payload
    }

    pub fn parent_qc(&self) -> Option<&QC> {
        self.data.parent_qc.as_ref()
    }

    pub fn reason(&self) -> &RoundEnterReason {
        &self.data.reason
    }

    pub fn n_sub_blocks(&self) -> usize {
        self.payload().sub_blocks().len()
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

    pub fn is_genesis(&self) -> bool {
        self.round() == 0
    }

    /// A non-genesis block is considered valid if:
    /// 1. It contains a valid multi-signature (omitted in the prototype);
    /// 2. It contains a valid parent QC;
    /// 3. At least one of the three conditions hold:
    ///    - `parent_qc.round == round - 1` and `parent_qc.is_full()`;
    ///    - `cc` is not None, `cc.round == round - 1`, and `parent_qc.id() >= cc.highest_qc_id()`.
    ///    - `tc` is not None, `cc.round == round - 1`, and `parent_qc.id() >= tc.highest_qc_id()`.
    pub fn is_valid(&self) -> bool {
        // TODO: add digest verification.

        if self.is_genesis() {
            return true;
        }

        let Some(parent_qc) = &self.parent_qc() else {
            return false;
        };

        match &self.reason() {
            RoundEnterReason::Genesis => false, // Should not be used in a non-genesis block.
            RoundEnterReason::FullPrefixQC => {
                parent_qc.common_data.round == self.round() - 1 && parent_qc.is_full()
            },
            RoundEnterReason::CC(cc) => {
                cc.round == self.round() - 1 && parent_qc.sub_block_id() >= cc.highest_qc_id()
            },
            RoundEnterReason::TC(tc) => {
                tc.timeout_round == self.round() - 1
                    && parent_qc.sub_block_id() >= tc.highest_qc_id()
            },
        }
    }

    pub fn verify(&self, validator_verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match &self.data.reason {
            RoundEnterReason::Genesis => Ok(()),
            _ => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing signature"))?;
                let author = self
                    .data
                    .author
                    .ok_or_else(|| anyhow::anyhow!("Missing author"))?;
                validator_verifier.verify(author, &self.data, &signature)?;
                Ok(())
            },
        }
    }
}

#[derive(
    Clone, CryptoHasher, BCSCryptoHash, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct CommonData {
    pub round: Round,
    pub hash: BlockHash,
    pub size: BlockSize,
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct VoteData {
    // author of the vote
    pub author: Author,
    pub common_data: CommonData,
    pub prefix: Prefix,
}

impl VoteData {
    pub fn sign(&self, signer: &ValidatorSigner) -> Result<Signature, CryptoMaterialError> {
        signer.sign(&self.signing_format())
    }

    pub fn signing_format(&self) -> VoteDataSigningRepr {
        VoteDataSigningRepr {
            common_data: self.common_data.clone(),
            prefix: self.prefix,
        }
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct VoteDataSigningRepr {
    pub common_data: CommonData,
    pub prefix: Prefix,
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct TimeoutData {
    // author of the timeout
    pub author: Author,
    pub timeout_round: Round,
    pub prefix: Prefix,
    pub qc_high: QC,
}

impl TimeoutData {
    pub fn sign(&self, signer: &ValidatorSigner) -> Result<Signature, CryptoMaterialError> {
        signer.sign(&self.signing_format())
    }

    pub fn signing_format(&self) -> TimeoutDataSigningRepr {
        TimeoutDataSigningRepr {
            timeout_round: self.timeout_round,
            common_data: self.qc_high.common_data.clone(),
            prefix: self.prefix,
        }
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct TimeoutDataSigningRepr {
    pub timeout_round: Round,
    pub common_data: CommonData,
    pub prefix: Prefix,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AggregateSignatureWithPrefixes {
    pub sig: AggregateSignature,
    pub prefixes: PrefixSet,
}

impl AggregateSignatureWithPrefixes {
    pub fn new(sig: AggregateSignature, prefixes: PrefixSet) -> Self {
        assert_eq!(sig.get_num_voters(), prefixes.iter().count());
        Self { sig, prefixes }
    }

    pub fn empty() -> Self {
        Self {
            sig: AggregateSignature::empty(),
            prefixes: PrefixSet::empty(),
        }
    }

    pub fn get_voters(&self, ordered_validator_addresses: &[Author]) -> Vec<Author> {
        self.sig.get_signers_addresses(ordered_validator_addresses)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AggregateSignatureWithTimeouts {
    sig: AggregateSignature,
    timeouts: Vec<TimeoutDataSigningRepr>,
}

impl AggregateSignatureWithTimeouts {
    pub fn new(sig: AggregateSignature, timeouts: Vec<TimeoutDataSigningRepr>) -> Self {
        assert_eq!(sig.get_num_voters(), timeouts.len());
        Self { sig, timeouts }
    }

    pub fn empty() -> Self {
        Self {
            sig: AggregateSignature::empty(),
            timeouts: vec![],
        }
    }

    pub fn get_voters(&self, ordered_validator_addresses: &[Author]) -> Vec<Author> {
        self.sig.get_signers_addresses(ordered_validator_addresses)
    }

    pub fn max_vote(&self) -> SubBlockId {
        self.timeouts
            .iter()
            .map(|timeout| (timeout.common_data.round, timeout.prefix))
            .max()
            .unwrap()
            .into()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AggregateSignatureWithQCs {
    sig: AggregateSignature,
    qcs: Vec<QCSigningRepr>,
}

impl AggregateSignatureWithQCs {
    pub fn new(sig: AggregateSignature, qcs: Vec<QCSigningRepr>) -> Self {
        assert_eq!(sig.get_num_voters(), qcs.len());
        Self { sig, qcs }
    }

    pub fn empty() -> Self {
        Self {
            sig: AggregateSignature::empty(),
            qcs: vec![],
        }
    }

    pub fn get_voters(&self, ordered_validator_addresses: &[Author]) -> Vec<Author> {
        self.sig.get_signers_addresses(ordered_validator_addresses)
    }

    pub fn max_prefix(&self) -> Prefix {
        self.qcs.iter().map(|qc| qc.prefix).max().unwrap()
    }

    pub fn min_prefix(&self) -> Prefix {
        self.qcs.iter().map(|qc| qc.prefix).min().unwrap()
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct QC {
    pub common_data: CommonData,
    pub prefix: Prefix,

    // TODO: wrap in an Arc to avoid cloning?
    pub signatures_with_prefixes: AggregateSignatureWithPrefixes,
}

impl QC {
    pub fn signers(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.signatures_with_prefixes
            .sig
            .get_signers_bitvec()
            .iter_ones()
    }

    pub fn verify(&self, validator_verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        let vote_datas: Vec<_> = self
            .signatures_with_prefixes
            .prefixes
            .iter()
            .map(|(_node_id, prefix)| VoteDataSigningRepr {
                common_data: self.common_data.clone(),
                prefix,
            })
            .collect();
        let vote_datas_ref: Vec<_> = vote_datas.iter().collect();
        validator_verifier
            .verify_aggregate_signatures(&vote_datas_ref, &self.signatures_with_prefixes.sig)?;
        Ok(())
    }
}

impl QC {
    pub fn sign(&self, signer: &ValidatorSigner) -> Result<Signature, CryptoMaterialError> {
        signer.sign(&self.signing_format())
    }

    pub fn signing_format(&self) -> QCSigningRepr {
        QCSigningRepr {
            common_data: self.common_data.clone(),
            prefix: self.prefix,
        }
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct QCSigningRepr {
    pub common_data: CommonData,
    pub prefix: Prefix,
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

impl QC {
    pub fn genesis() -> Self {
        QC {
            common_data: CommonData {
                round: 0,
                hash: Block::genesis().digest,
                size: 0,
            },
            prefix: 0,
            // signature_data: QcSignatureData::new(&vec![], 0),
            signatures_with_prefixes: AggregateSignatureWithPrefixes::empty(),
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.common_data.round == 0
    }

    pub fn is_full(&self) -> bool {
        self.prefix == self.common_data.size
    }

    pub fn sub_block_id(&self) -> SubBlockId {
        (self.common_data.round, self.prefix).into()
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
pub struct SignedQC {
    pub qc: QC,
    pub author: Author,
    pub signature: Signature,
}

impl SignedQC {
    pub fn new(qc: QC, author: Author, signature: Signature) -> Self {
        Self {
            qc,
            author,
            signature,
        }
    }
}

impl PartialEq for SignedQC {
    fn eq(&self, other: &Self) -> bool {
        self.qc.sub_block_id() == other.qc.sub_block_id()
    }
}

impl Eq for SignedQC {}

impl PartialOrd for SignedQC {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.qc.sub_block_id().partial_cmp(&other.qc.sub_block_id())
    }
}

impl Ord for SignedQC {
    fn cmp(&self, other: &Self) -> Ordering {
        self.qc.sub_block_id().cmp(&other.qc.sub_block_id())
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct CC {
    round: Round,
    min_prefix: Prefix,
    max_prefix: Prefix,

    // TODO: wrap in an Arc to avoid cloning?
    signatures_with_qcs: AggregateSignatureWithQCs,
}

impl CC {
    pub fn new(
        round: Round,
        min_prefix: Prefix,
        max_prefix: Prefix,
        signatures_with_qcs: AggregateSignatureWithQCs,
    ) -> Self {
        CC {
            round,
            min_prefix,
            max_prefix,
            signatures_with_qcs,
        }
    }

    pub fn genesis() -> Self {
        CC {
            round: 0,
            min_prefix: 0,
            max_prefix: 0,
            signatures_with_qcs: AggregateSignatureWithQCs::empty(),
        }
    }

    pub fn lowest_qc_id(&self) -> SubBlockId {
        (self.round, self.min_prefix).into()
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        (self.round, self.max_prefix).into()
    }

    pub fn verify(&self, validator_verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        let qcs_ref: Vec<_> = self.signatures_with_qcs.qcs.iter().collect();
        validator_verifier.verify_aggregate_signatures(&qcs_ref, &self.signatures_with_qcs.sig)?;
        Ok(())
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct TC {
    timeout_round: Round,
    max_vote: SubBlockId,

    // TODO: wrap in an Arc to avoid cloning?
    signatures_with_timeouts: AggregateSignatureWithTimeouts,
}

impl TC {
    pub fn genesis() -> Self {
        TC {
            timeout_round: 0,
            max_vote: (0, 0).into(),
            signatures_with_timeouts: AggregateSignatureWithTimeouts::empty(),
        }
    }

    pub fn new(
        timeout_round: Round,
        max_vote: SubBlockId,
        signatures_with_timeouts: AggregateSignatureWithTimeouts,
    ) -> Self {
        TC {
            timeout_round,
            max_vote,
            signatures_with_timeouts,
        }
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        self.max_vote
    }

    pub fn verify(&self, validator_verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        let timeout_data_ref: Vec<_> = self.signatures_with_timeouts.timeouts.iter().collect();
        validator_verifier
            .verify_aggregate_signatures(&timeout_data_ref, &self.signatures_with_timeouts.sig)?;
        Ok(())
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
