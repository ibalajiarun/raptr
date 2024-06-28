// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::hash::{Hash, Hasher};
use std::ops::Range;

use serde::{Deserialize, Serialize};

use aptos_crypto::hash::{CryptoHash, CryptoHasher};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};

use crate::framework::NodeId;
use crate::raikou::types::common::{Prefix, Round};

pub use aptos_consensus_types::proof_of_store::BatchId;
pub use aptos_consensus_types::proof_of_store::BatchInfo;
pub use aptos_crypto::hash::HashValue;
pub type Txn = aptos_types::transaction::Transaction;
pub type AC = aptos_consensus_types::proof_of_store::ProofOfStore;

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct Payload {
    pub round: Round,
    pub leader: NodeId,
    pub inner: aptos_consensus_types::common::Payload,
}

pub fn hash(x: &impl CryptoHash) -> HashValue {
    x.hash()
}

// impl `Hash` just for compatibility with `sim_types`.
impl std::hash::Hash for Payload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        unimplemented!()
    }
}

impl Payload {
    /// Creates a new block payload.
    pub fn new(round: Round, leader: NodeId, acs: Vec<AC>, sub_blocks: Vec<Vec<crate::raikou::types::BatchInfo>>) -> Self {
        todo!()
    }

    /// Return a truncated payload that contains only `prefix` of the sub-blocks.
    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        todo!()
    }

    /// Returns a new payload that does not include any of the ACs and only includes sub-blocks
    /// from `range`.
    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        todo!()
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
        todo!()
    }

    pub fn sub_blocks(&self) -> &[Vec<BatchInfo>] {
        todo!()
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.acs()
            .iter()
            .map(|ac| ac.info())
            .chain(self.sub_blocks().iter().flatten())
    }
}
