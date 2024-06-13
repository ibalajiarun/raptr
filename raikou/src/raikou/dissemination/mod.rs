use crate::{
    framework::{module_network::ModuleId, NodeId},
    raikou::types::*,
};
use std::{collections::HashSet, future::Future};

pub mod fake;

pub struct BlockReceived {
    pub leader: NodeId,
    pub round: Round,
    pub payload: Payload,
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

    fn check_stored_all(&self, batch: &Vec<BatchHash>) -> impl Future<Output = bool> + Send;

    fn notify_commit(&self, payloads: Vec<Payload>) -> impl Future<Output = ()> + Send;
}
