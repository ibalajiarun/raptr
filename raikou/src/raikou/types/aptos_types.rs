// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::NodeId,
    raikou::types::common::{Prefix, Round},
};
pub use aptos_consensus_types::proof_of_store::{BatchId, BatchInfo};
pub use aptos_crypto::hash::HashValue;
use aptos_crypto::hash::{CryptoHash, CryptoHasher};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::ops::Range;

pub type Txn = aptos_types::transaction::Transaction;
pub type AC = aptos_consensus_types::proof_of_store::ProofOfStore;

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct Payload {
    round: Round,
    leader: NodeId,
    pub inner: aptos_consensus_types::common::Payload,
}

pub fn hash(x: &impl CryptoHash) -> HashValue {
    x.hash()
}

impl Payload {
    /// Creates a new block payload.
    pub fn new(
        round: Round,
        leader: NodeId,
        inner: aptos_consensus_types::common::Payload,
    ) -> Self {
        Self {
            round,
            leader,
            inner,
        }
    }

    /// Return a truncated payload that contains only `prefix` of the sub-blocks.
    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        Self {
            round: self.round,
            leader: self.leader,
            inner: self.inner.as_raikou_payload().with_prefix(prefix).into(),
        }
    }

    /// Returns a new payload that does not include any of the ACs and only includes sub-blocks
    /// from `range`.
    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        Self {
            round: self.round,
            leader: self.leader,
            inner: self.inner.as_raikou_payload().take_sub_blocks(range).into(),
        }
    }

    pub fn empty(round: Round, leader: NodeId) -> Self {
        Self::new(
            round,
            leader,
            aptos_consensus_types::common::Payload::Raikou(
                aptos_consensus_types::payload::RaikouPayload::new_empty(),
            ),
        )
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn leader(&self) -> NodeId {
        self.leader
    }

    pub fn acs(&self) -> &Vec<AC> {
        self.inner.as_raikou_payload().proofs()
    }

    pub fn sub_blocks(&self) -> impl ExactSizeIterator<Item = &Vec<BatchInfo>> {
        self.inner
            .as_raikou_payload()
            .sub_blocks()
            .iter()
            .map(|inner| &inner.batch_summary)
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.acs()
            .iter()
            .map(|ac| ac.info())
            .chain(self.sub_blocks().flatten())
    }
}
