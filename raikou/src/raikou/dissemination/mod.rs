// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{module_network::ModuleId, NamedAny, NodeId},
    metrics,
    raikou::types::*,
};
use aptos_consensus_types::common::Author;
use std::{collections::HashSet, future::Future};
use tokio::time::Instant;

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod native;

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod penalty_tracker;

/// Event sent by the consensus module to the dissemination layer to notify of a new block.
pub struct ProposalReceived {
    pub leader: NodeId,
    pub leader_account: Option<Author>,
    pub round: Round,
    pub payload: Payload,
}

pub struct NewQCWithPayload {
    pub payload: Payload,
    pub qc: QC,
}

/// Event sent by the consensus module to the dissemination layer to notify that it should stop.
pub struct Kill();

/// Event sent by the dissemination layer to the consensus module in response to `ProposalReceived`
/// to notify that all data from the proposed block is available.
pub struct FullBlockAvailable {
    pub round: Round,
}

pub trait DisseminationLayer: Send + Sync + 'static {
    fn module_id(&self) -> ModuleId;

    fn prepare_block(
        &self,
        round: Round,
        exclude: HashSet<BatchHash>,
    ) -> impl Future<Output = Payload> + Send;

    fn available_prefix(
        &self,
        payload: &Payload,
        cached_value: Prefix,
    ) -> impl Future<Output = Prefix> + Send;

    fn notify_commit(&self, payloads: Vec<Payload>) -> impl Future<Output = ()> + Send;
}

pub struct Metrics {
    pub batch_commit_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub batch_execute_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub queueing_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub penalty_wait_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub fetch_wait_time_after_commit: Option<metrics::UnorderedSender<(Instant, f64)>>,
    // pub average_penalty: Option<metrics::UnorderedSender<(Instant, f64)>>,
    // pub total_committed_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub two_chain_commit_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub order_vote_committed_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub committed_acs: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub optimistically_committed_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
}
