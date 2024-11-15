// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::NodeId,
    raikou::types::common::{Prefix, Round},
};
use aptos_consensus_types::payload::{BatchPointer, OptQuorumStorePayload, RaikouPayload};
pub use aptos_consensus_types::proof_of_store::{BatchId, BatchInfo};
pub use aptos_crypto::hash::HashValue;
use aptos_crypto::hash::{CryptoHash, CryptoHasher};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use futures::stream::Once;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    cell::OnceCell,
    ops::{Deref, Range},
    sync::{Arc, OnceLock},
};

pub type Txn = aptos_types::transaction::Transaction;
pub type AC = aptos_consensus_types::proof_of_store::ProofOfStore;

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct Payload {
    round: Round,
    leader: NodeId,
    pub data: Arc<aptos_consensus_types::common::Payload>,
    include_acs: bool,
    sub_blocks: Range<Prefix>,
}

pub fn hash(x: &impl CryptoHash) -> HashValue {
    x.hash()
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
struct PayloadData {
    acs: Vec<AC>,
    batches: Vec<Vec<BatchInfo>>,
}

impl Payload {
    /// Creates a new block payload.
    pub fn new(
        round: Round,
        leader: NodeId,
        payload: aptos_consensus_types::common::Payload,
    ) -> Self {
        let n_sub_blocks = payload.as_raikou_payload().sub_blocks().len();
        Self {
            round,
            leader,
            data: Arc::new(payload),
            include_acs: true,
            sub_blocks: 0..n_sub_blocks,
        }
    }

    /// Return a truncated payload that contains only `prefix` of the sub-blocks.
    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        assert!(prefix <= self.data.as_raikou_payload().sub_blocks().len());

        Self {
            round: self.round,
            leader: self.leader,
            data: self.data.clone(),
            include_acs: true,
            sub_blocks: 0..prefix,
        }
    }

    /// Returns a new payload that does not include any of the ACs and only includes sub-blocks
    /// from `range`.
    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        assert!(range.end <= self.data.len());

        Self {
            round: self.round,
            leader: self.leader,
            data: self.data.clone(),
            include_acs: false,
            sub_blocks: range,
        }
    }

    pub fn empty(round: Round, leader: NodeId) -> Self {
        Self::new(
            round,
            leader,
            aptos_consensus_types::common::Payload::Raikou(RaikouPayload::new_empty()),
        )
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn leader(&self) -> NodeId {
        self.leader
    }

    pub fn acs(&self) -> &Vec<AC> {
        &self
            .data
            .as_raikou_payload()
            .proof_with_data()
            .batch_summary
    }

    pub fn sub_blocks(&self) -> &[BatchPointer<BatchInfo>] {
        self.data.as_raikou_payload().sub_blocks()
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.acs().iter().map(|ac| ac.info()).chain(
            self.sub_blocks()
                .iter()
                .map(|inner| &inner.batch_summary)
                .flatten(),
        )
    }
}
