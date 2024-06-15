use crate::{framework::NodeId, raikou::types::Round};
use bitvec::prelude::BitVec;
use std::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    sync::Arc,
};

// Unsafe crypto, for simulation and testing purposes only.
pub type HashValue = u64;

// TODO: add signatures to the protocol
// pub struct Signature(NodeId, HashValue);
// pub struct SignatureShare(NodeId, HashValue);
// pub struct MultiSignature(BitVec, HashValue);

pub type BatchId = i64;

#[derive(Clone)]
pub struct BatchInfo {
    pub author: NodeId,
    pub batch_id: BatchId,
    pub digest: HashValue,
}

pub fn hash(x: impl Hash) -> HashValue {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    x.hash(&mut hasher);
    hasher.finish()
}

impl Debug for crate::raikou::types::BatchInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ node: {}, sn: {}, hash: {:#x} }}",
            self.author, self.batch_id, self.digest
        )
    }
}

#[derive(Clone)]
pub struct AC {
    // In practice, this would be a hash pointer.
    pub batch: BatchInfo,
    pub signers: BitVec,
}

#[derive(Clone)]
pub struct Payload {
    round: Round,
    leader: NodeId,
    data: Arc<PayloadData>,
}

struct PayloadData {
    acs: Vec<AC>,
    batches: Vec<BatchInfo>,
}

impl Payload {
    pub fn new(round: Round, leader: NodeId, acs: Vec<AC>, batches: Vec<BatchInfo>) -> Self {
        Self {
            round,
            leader,
            data: Arc::new(PayloadData { acs, batches }),
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

    pub fn batches(&self) -> &Vec<BatchInfo> {
        &self.data.batches
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.data
            .acs
            .iter()
            .map(|ac| &ac.batch)
            .chain(self.data.batches.iter())
    }
}
