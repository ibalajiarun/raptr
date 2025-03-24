// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::NodeId,
    raikou::{
        protocol,
        types::{
            common::{Prefix, Round},
            Block, N_SUB_BLOCKS,
        },
    },
};
use anyhow::ensure;
use aptos_bitvec::BitVec;
pub use aptos_consensus_types::proof_of_store::{BatchId, BatchInfo};
use aptos_consensus_types::{payload::RaikouPayload, proof_of_store::ProofCache};
use aptos_crypto::hash::{CryptoHash, CryptoHasher};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::validator_verifier::ValidatorVerifier;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Range};

pub type PoA = aptos_consensus_types::proof_of_store::ProofOfStore;

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct Payload {
    round: Option<Round>,
    author: NodeId,
    pub inner: aptos_consensus_types::common::Payload,
}

impl Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("round", &self.round)
            .field("author", &self.author)
            .finish()
    }
}

impl Payload {
    /// Creates a new block payload.
    pub fn new(
        round: Option<Round>,
        leader: NodeId,
        inner: aptos_consensus_types::common::Payload,
    ) -> Self {
        Self {
            round,
            author: leader,
            inner,
        }
    }

    pub fn author(&self) -> NodeId {
        self.author
    }

    /// Return a truncated payload that contains only `prefix` of the sub-blocks.
    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        Self {
            round: self.round,
            author: self.author,
            inner: self.inner.as_raikou_payload().with_prefix(prefix).into(),
        }
    }

    /// Returns a new payload that does not include any of the PoAs and only includes sub-blocks
    /// from `range`.
    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        Self {
            round: self.round,
            author: self.author,
            inner: self.inner.as_raikou_payload().take_sub_blocks(range).into(),
        }
    }

    pub fn empty(round: Round, leader: NodeId) -> Self {
        Self::new(
            Some(round),
            leader,
            aptos_consensus_types::common::Payload::Raikou(
                aptos_consensus_types::payload::RaikouPayload::new_empty(),
            ),
        )
    }

    pub fn round(&self) -> Round {
        self.round.unwrap()
    }

    pub fn leader(&self) -> NodeId {
        self.author
    }

    pub fn poas(&self) -> &Vec<PoA> {
        self.inner.as_raikou_payload().proofs()
    }

    pub fn sub_blocks(&self) -> impl ExactSizeIterator<Item = &Vec<BatchInfo>> {
        self.inner
            .as_raikou_payload()
            .sub_blocks()
            .iter()
            .map(|inner| &inner.batch_summary)
    }

    pub fn num_opt_batches(&self) -> usize {
        self.sub_blocks()
            .map(|sub_block| sub_block.len())
            .sum::<usize>()
    }

    pub fn verify(
        &self,
        verifier: &protocol::Verifier,
        round: Option<Round>,
        author: NodeId,
    ) -> anyhow::Result<()> {
        ensure!(
            self.round == round,
            "Invalid round. Expected: {:?}, got: {:?}",
            round,
            self.round
        );
        ensure!(
            self.author == author,
            "Invalid author. Expected: {:?}, got: {:?}",
            author,
            self.author
        );
        ensure!(
            self.sub_blocks().len() == N_SUB_BLOCKS,
            "Received a partial payload: Sub-blocks excluded"
        );

        self.inner.verify(
            verifier.sig_verifier.aptos_verifier(),
            &verifier.proof_cache,
            true,
        )
    }
}

pub fn merge_payloads(
    round: Round,
    author: NodeId,
    payloads: impl IntoIterator<Item = (Payload, BitVec, BitVec)>,
) -> Payload {
    let inners = payloads
        .into_iter()
        .map(|(payload, proof_mask, batch_mask)| {
            (
                payload.inner.as_raikou_payload().clone(),
                proof_mask,
                batch_mask,
            )
        })
        .collect_vec();

    if inners.is_empty() {
        return Payload::empty(round, author);
    }

    let merged_inner = RaikouPayload::merge(&inners);

    Payload::new(
        Some(round),
        author,
        aptos_consensus_types::common::Payload::Raikou(merged_inner),
    )
}
