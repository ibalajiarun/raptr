// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    derive_module_event,
    framework::{
        module_network::{ModuleEventTrait, ModuleId},
        NodeId,
    },
    metrics,
    raikou::types::*,
};
use aptos_bitvec::BitVec;
use aptos_consensus_types::common::Author;
use std::{any::Any, collections::HashSet, fmt::Debug, future::Future, time::SystemTime};
use tokio::time::Instant;

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod native;

pub mod bundler;
#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod penalty_tracker;

derive_module_event!(ProposalReceived);
derive_module_event!(NewQCWithPayload);
derive_module_event!(Kill);
derive_module_event!(FullBlockAvailable);
derive_module_event!(SetLoggingBaseTimestamp);
derive_module_event!(NotifyCommit);
derive_module_event!(BlockPrepareTime);
derive_module_event!(PreparePayload);
derive_module_event!(PayloadReady);

/// Event sent to the dissemination layer to prepare a payload.
#[derive(Debug)]
pub struct PreparePayload {
    pub request_uid: u64,
    pub round: Option<Round>,
    pub exclude_everywhere: HashSet<BatchInfo>,
    pub exclude_optimistic: HashSet<BatchInfo>,
    pub exclude_authors: Option<BitVec>,
}

/// Response from the dissemination layer to the `PreparePayload` event.
#[derive(Debug)]
pub struct PayloadReady {
    pub request_uid: u64,
    pub payload: Payload,
}

/// Event sent from the bundler to the dissemination layer for metrics tracking.
#[derive(Debug)]
pub struct BlockPrepareTime {
    pub round: Round,
    pub time: Instant,
}

/// Event sent by the consensus module to the dissemination layer to notify of a new block.
#[derive(Debug)]
pub struct ProposalReceived {
    pub leader: NodeId,
    pub round: Round,
    pub payload: Payload,
}

#[derive(Debug)]
pub struct NewQCWithPayload {
    pub payload: Payload,
    pub qc: QC,
}

#[derive(Debug)]
pub struct NotifyCommit {
    pub payloads: Vec<Payload>,
    pub block_timestamp_usecs: u64,
    pub voters: Option<BitVec>,
}

/// Event sent by the consensus module to the dissemination layer to notify that it should stop.
#[derive(Debug)]
pub struct Kill();

/// Event sent by the dissemination layer to the consensus module in response to `ProposalReceived`
/// to notify that all data from the proposed block is available.
#[derive(Debug)]
pub struct FullBlockAvailable {
    pub round: Round,
}

/// Sets a common timestamp for logging.
#[derive(Debug)]
pub struct SetLoggingBaseTimestamp(pub SystemTime);

pub trait DisseminationLayer: Send + Sync + 'static {
    fn module_id(&self) -> ModuleId;

    fn available_prefix(
        &self,
        payload: &Payload,
        cached_value: Prefix,
    ) -> impl Future<Output = (Prefix, BitVec)> + Send;

    fn check_payload(&self, payload: &Payload) -> Result<(), BitVec> {
        Ok(())
    }
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
