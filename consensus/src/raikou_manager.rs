use crate::{
    dag::DAGNetworkMessage,
    network::NetworkSender,
    network_interface::{ConsensusMsg, ConsensusNetworkClient},
};
use ::raikou::{leader_schedule::round_robin, raikou::dissemination::fake::FakeDisseminationLayer};
use aptos_consensus_types::common::Author;
use aptos_types::epoch_state::EpochState;
use chrono::Local;
use futures::StreamExt;
use futures_channel::oneshot;
use raikou::{
    framework::{
        network::{Network, NetworkService},
        timer::LocalTimerService,
        Protocol,
    },
    metrics,
    raikou::{dissemination, RaikouNode},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};
use tokio::time::Instant;

const JOLTEON_TIMEOUT: u32 = 3; // in Deltas

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RaikouNetworkMessage {
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

impl From<raikou::raikou::Message> for RaikouNetworkMessage {
    fn from(message: raikou::raikou::Message) -> Self {
        Self {
            data: bcs::to_bytes(&message).unwrap(),
        }
    }
}

impl From<raikou::raikou::dissemination::fake::Message> for RaikouNetworkMessage {
    fn from(value: raikou::raikou::dissemination::fake::Message) -> Self {
        Self {
            data: bcs::to_bytes(&value).unwrap(),
        }
    }
}

pub struct RaikouManager {}

impl RaikouManager {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run(
        self,
        self_author: Author,
        epoch_state: Arc<EpochState>,
        network_sender: Arc<NetworkSender>,
        delta: f64,
        total_duration_in_delta: u32,
        enable_optimistic_dissemination: bool,
        messages_rx: aptos_channels::aptos_channel::Receiver<
            aptos_types::PeerId,
            (Author, RaikouNetworkMessage),
        >,
        diss_rx: aptos_channels::aptos_channel::Receiver<
            aptos_types::PeerId,
            (Author, RaikouNetworkMessage),
        >,
        mut shutdown_rx: oneshot::Receiver<oneshot::Sender<()>>,
    ) {
        let n_nodes = epoch_state.verifier.len();
        let f = (n_nodes - 1) / 3;
        let start_time = Instant::now();
        let txns_iter = std::iter::repeat_with(|| vec![]);

        let diss_timer = LocalTimerService::new();
        let timer = LocalTimerService::new();

        let mut batch_commit_time = metrics::UnorderedBuilder::new();
        let batch_commit_time_sender = Some(batch_commit_time.new_sender());

        let address_to_index = epoch_state.verifier.address_to_validator_index().clone();
        let node_id = *address_to_index.get(&self_author).unwrap();

        let network_service =
            RaikouNetworkService::new(epoch_state.clone(), messages_rx, network_sender.clone());

        let diss_network_service =
            RaikouDissNetworkService::new(epoch_state.clone(), diss_rx, network_sender);

        let config = raikou::raikou::Config {
            n_nodes,
            f,
            storage_requirement: f + (f / 2 + 1),
            leader_timeout: JOLTEON_TIMEOUT,
            leader_schedule: round_robin(n_nodes),
            delta: Duration::from_secs_f64(delta),
            batch_interval: Duration::from_secs_f64(delta * 0.1),
            end_of_run: Instant::now() + Duration::from_secs_f64(delta) * total_duration_in_delta,
            enable_optimistic_dissemination,
            extra_wait_before_qc_vote: Duration::from_secs_f64(delta * 0.1),
            enable_round_entry_permission: false,
            enable_commit_votes: true,
        };

        let dissemination = FakeDisseminationLayer::new(
            node_id,
            dissemination::fake::Config {
                n_nodes,
                ac_quorum: 2 * f + 1,
                batch_interval: Duration::from_secs_f64(delta * 0.1),
            },
            txns_iter,
        );

        let node = Arc::new(tokio::sync::Mutex::new(RaikouNode::new(
            node_id,
            config,
            dissemination.clone(),
            start_time,
            true,
            raikou::raikou::Metrics {
                // propose_time: propose_time_sender,
                // enter_time: enter_time_sender,
                batch_commit_time: batch_commit_time_sender,
                // indirectly_committed_slots: indirectly_committed_slots_sender,
            },
        )));

        tokio::spawn(Protocol::run(
            dissemination.protocol(),
            node_id,
            diss_network_service,
            diss_timer,
        ));

        tokio::select! {
            Ok(ack_tx) = &mut shutdown_rx => {
                let _ = ack_tx.send(());
                return;
            },
            _ = Protocol::run(node, node_id, network_service, timer) => {
                unreachable!()
            },
        }
    }
}

pub struct RaikouNetworkService {
    n_nodes: usize,
    index_to_address: HashMap<usize, Author>,
    address_to_index: HashMap<Author, usize>,
    network_sender: Arc<NetworkSender>,
    messages_rx: aptos_channels::aptos_channel::Receiver<Author, (Author, RaikouNetworkMessage)>,
}

impl RaikouNetworkService {
    pub fn new(
        epoch_state: Arc<EpochState>,
        messages_rx: aptos_channels::aptos_channel::Receiver<
            aptos_types::PeerId,
            (Author, RaikouNetworkMessage),
        >,
        network_sender: Arc<NetworkSender>,
    ) -> Self {
        let address_to_index = epoch_state.verifier.address_to_validator_index().clone();
        let index_to_address = address_to_index
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();
        Self {
            n_nodes: epoch_state.verifier.len(),
            index_to_address,
            address_to_index,
            network_sender,
            messages_rx,
        }
    }
}

impl NetworkService for RaikouNetworkService {
    type Message = raikou::raikou::Message;

    fn send(
        &self,
        target: raikou::framework::NodeId,
        data: Self::Message,
    ) -> impl futures::Future<Output = ()> + Send {
        let remote_peer_id = *self.index_to_address.get(&target).unwrap();
        let msg: ConsensusMsg = ConsensusMsg::RaikouMessage(data.into());
        self.network_sender.send(msg, vec![remote_peer_id])
    }

    fn recv(
        &mut self,
    ) -> impl futures::Future<Output = (raikou::framework::NodeId, Self::Message)> + Send {
        async {
            let (sender, msg) = self.messages_rx.select_next_some().await;
            let sender = *self.address_to_index.get(&sender).unwrap();
            let msg = bcs::from_bytes(&msg.data).unwrap();
            return (sender, msg);
        }
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }
}

pub struct RaikouDissNetworkService {
    n_nodes: usize,
    index_to_address: HashMap<usize, Author>,
    address_to_index: HashMap<Author, usize>,
    network_sender: Arc<NetworkSender>,
    messages_rx: aptos_channels::aptos_channel::Receiver<Author, (Author, RaikouNetworkMessage)>,
}

impl RaikouDissNetworkService {
    pub fn new(
        epoch_state: Arc<EpochState>,
        messages_rx: aptos_channels::aptos_channel::Receiver<
            aptos_types::PeerId,
            (Author, RaikouNetworkMessage),
        >,
        network_sender: Arc<NetworkSender>,
    ) -> Self {
        let address_to_index = epoch_state.verifier.address_to_validator_index().clone();
        let index_to_address = address_to_index
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();
        Self {
            n_nodes: epoch_state.verifier.len(),
            index_to_address,
            address_to_index,
            network_sender,
            messages_rx,
        }
    }
}

impl NetworkService for RaikouDissNetworkService {
    type Message = raikou::raikou::dissemination::fake::Message;

    fn send(
        &self,
        target: raikou::framework::NodeId,
        data: Self::Message,
    ) -> impl futures::Future<Output = ()> + Send {
        let remote_peer_id = *self.index_to_address.get(&target).unwrap();
        let msg: ConsensusMsg = ConsensusMsg::RaikouMessage(data.into());
        self.network_sender.send(msg, vec![remote_peer_id])
    }

    fn recv(
        &mut self,
    ) -> impl futures::Future<Output = (raikou::framework::NodeId, Self::Message)> + Send {
        async {
            let (sender, msg) = self.messages_rx.select_next_some().await;
            let sender = *self.address_to_index.get(&sender).unwrap();
            let msg = bcs::from_bytes(&msg.data).unwrap();
            return (sender, msg);
        }
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }
}
