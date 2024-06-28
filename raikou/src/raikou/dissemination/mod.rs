// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{module_network::ModuleId, NamedAny, NodeId},
    raikou::types::*,
};
use std::{collections::HashSet, future::Future};

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod fake; // pub mod multichain_raikou;

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod penalty_tracker;

/// Event sent by the consensus module to the dissemination layer to notify of a new block.
pub struct BlockReceived {
    pub leader: NodeId,
    pub round: Round,
    pub payload: Payload,
}

impl NamedAny for BlockReceived {
    fn type_name(&self) -> &'static str {
        "dissemination::BlockReceived"
    }
}

/// Event sent by the consensus module to the dissemination layer to notify that it should stop.
pub struct Kill();

impl NamedAny for Kill {
    fn type_name(&self) -> &'static str {
        "dissemination::Kill"
    }
}

impl BlockReceived {
    pub fn new(leader: NodeId, round: Round, payload: Payload) -> Self {
        Self {
            leader,
            round,
            payload,
        }
    }
}

pub trait DisseminationLayer: Send + Sync + 'static {
    fn module_id(&self) -> ModuleId;

    // TODO: accept exclude by ref?
    fn prepare_block(
        &self,
        round: Round,
        exclude: HashSet<BatchHash>,
    ) -> impl Future<Output = Payload> + Send;

    fn prefetch_payload_data(&self, payload: Payload) -> impl Future<Output = ()> + Send;

    fn check_stored_all(&self, batches: &[BatchInfo]) -> impl Future<Output = bool> + Send;

    fn notify_commit(&self, payloads: Vec<Payload>) -> impl Future<Output = ()> + Send;
}
