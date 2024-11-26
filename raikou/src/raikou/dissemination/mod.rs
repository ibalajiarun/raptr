// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{module_network::ModuleId, NamedAny, NodeId},
    raikou::types::*,
};
use aptos_consensus_types::common::Author;
use std::{collections::HashSet, future::Future};

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod fake; // pub mod multichain_raikou;

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod penalty_tracker;

/// Event sent by the consensus module to the dissemination layer to notify of a new block.
pub struct ProposalReceived {
    pub leader: NodeId,
    pub leader_account: Option<Author>,
    pub round: Round,
    pub payload: Payload,
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

    fn notify_commit(
        &self,
        payloads: Vec<Payload>,
        signers: Vec<Vec<Prefix>>,
    ) -> impl Future<Output = ()> + Send;
}
