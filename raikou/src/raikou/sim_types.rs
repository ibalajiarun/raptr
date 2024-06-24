use crate::{
    framework::NodeId,
    raikou::types::{BatchHash, Round},
};
use bitvec::prelude::BitVec;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    sync::Arc,
};
use std::ops::Range;
use crate::raikou::types::Prefix;

// Unsafe crypto, for simulation and testing purposes only.
pub type HashValue = u64;

// TODO: add signatures to the protocol
// pub struct Signature(NodeId, HashValue);
// pub struct SignatureShare(NodeId, HashValue);
// pub struct MultiSignature(BitVec, HashValue);

pub type BatchId = i64;

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct BatchInfo {
    pub author: NodeId,
    pub batch_id: BatchId,
    pub digest: BatchHash,
}

pub fn hash(x: impl Hash) -> HashValue {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    x.hash(&mut hasher);
    hasher.finish()
}

impl Debug for BatchInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ node: {}, sn: {}, hash: {:#x} }}",
            self.author, self.batch_id, &self.digest
        )
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct AC {
    // In practice, this would be a hash pointer.
    pub batch: BatchInfo,
    pub signers: BitVec,
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct Payload {
    round: Round,
    leader: NodeId,
    data: Arc<PayloadData>,
    include_acs: bool,
    sub_blocks: Range<Prefix>,
}

#[derive(Hash, Serialize, Deserialize)]
struct PayloadData {
    acs: Vec<AC>,
    batches: Vec<Vec<BatchInfo>>,
}

impl Payload {
    pub fn new(round: Round, leader: NodeId, acs: Vec<AC>, sub_blocks: Vec<Vec<BatchInfo>>) -> Self {
        let n_sub_blocks = sub_blocks.len();

        Self {
            round,
            leader,
            data: Arc::new(PayloadData { acs, batches: sub_blocks }),
            include_acs: true,
            sub_blocks: 0..n_sub_blocks,
        }
    }

    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        assert!(prefix <= self.data.batches.len());

        Self {
            round: self.round,
            leader: self.leader,
            data: self.data.clone(),
            include_acs: true,
            sub_blocks: 0..prefix,
        }
    }

    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        assert!(range.end <= self.data.batches.len());

        Self {
            round: self.round,
            leader: self.leader,
            data: self.data.clone(),
            include_acs: false,
            sub_blocks: range,
        }
    }

    pub fn empty(round: Round, leader: NodeId) -> Self {
        Self::new(round, leader, vec![], vec![])
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn leader(&self) -> NodeId {
        self.leader
    }

    pub fn acs(&self) -> &Vec<AC> {
        &self.data.acs
    }

    pub fn sub_blocks(&self) -> &[Vec<BatchInfo>] {
        &self.data.batches[self.sub_blocks.clone()]
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.data
            .acs
            .iter()
            .map(|ac| &ac.batch)
            .chain(self.sub_blocks().iter().flatten())
    }
}
