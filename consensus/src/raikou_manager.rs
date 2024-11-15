// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    network::NetworkSender,
    network_interface::ConsensusMsg,
    payload_client::PayloadClient,
    payload_manager::{QuorumStorePayloadManager, TPayloadManager},
    pipeline::buffer_manager::OrderedBlocks,
};
use ::raikou::leader_schedule::round_robin;
use aptos_config::config::ConsensusConfig;
use aptos_consensus_types::{
    block::Block,
    common::{Author, PayloadFilter},
    payload::{InlineBatches, OptQuorumStorePayload},
    payload_pull_params::{OptQSPayloadPullParams, PayloadPullParameters},
    proof_of_store::BatchInfo,
    utils::PayloadTxnsSize,
};
use aptos_types::{
    epoch_state::EpochState, on_chain_config::ValidatorSet, validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};
use aptos_validator_transaction_pool::TransactionFilter;
use futures::{future::BoxFuture, FutureExt, StreamExt};
use futures_channel::{mpsc::UnboundedSender, oneshot};
use raikou::{
    framework::{
        injection::{delay_injection, drop_injection},
        module_network::{ModuleId, ModuleNetwork, ModuleNetworkService},
        network::{Network, NetworkService},
        tcp_network::TcpNetworkService,
        timer::LocalTimerService,
        udp_network,
        udp_network::UdpNetworkService,
        NodeId, Protocol,
    },
    metrics,
    raikou::{
        dissemination::{self, DisseminationLayer},
        RaikouNode,
    },
};
use rayon::slice::ParallelSlice;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

const JOLTEON_TIMEOUT: u32 = 3; // in Deltas
const CONS_BASE_PORT: u16 = 12000;
const DISS_BASE_PORT: u16 = 32000;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RaikouNetworkMessage {
    epoch: u64,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}
impl RaikouNetworkMessage {
    pub(crate) fn epoch(&self) -> anyhow::Result<u64> {
        Ok(self.epoch)
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
        payload_client: Arc<dyn PayloadClient>,
        payload_manager: Arc<dyn TPayloadManager>,
        consensus_config: ConsensusConfig,
        validator_set: ValidatorSet,
        validator_signer: Arc<ValidatorSigner>,
    ) {
        let n_nodes = epoch_state.verifier.len();
        let f = (n_nodes - 1) / 3;
        let start_time = Instant::now();

        let timer = LocalTimerService::new();

        let address_to_index = epoch_state.verifier.address_to_validator_index().clone();
        let node_id = *address_to_index.get(&self_author).unwrap();

        // let network_service: RaikouNetworkService<raikou::raikou::Message> =
        //     RaikouNetworkService::new(epoch_state.clone(), messages_rx, network_sender.clone());
        //
        // network_service.multicast(raikou::raikou::Message::AdvanceRound(
        //     0,
        //     raikou::raikou::QC::genesis(),
        //     RoundEnterReason::Genesis
        // )).await;

        // let network_service = UdpNetworkService::new(
        //     node_id,
        //     validator_set.active_validators[node_id].config().find_ip_addr().unwrap(),
        //     // base_port is chosen to avoid any collisions when running
        //     // multiple instances on the same machine.
        //     BASE_PORT + (node_id * n_nodes) as u16,
        //     udp_network::Config {
        //         peers: validator_set
        //             .active_validators
        //             .iter()
        //             .enumerate()
        //             .map(|(peer_id, info)| (
        //                 info.config().find_ip_addr().unwrap(),
        //                 BASE_PORT + (peer_id * n_nodes) as u16,
        //             ))
        //             .collect(),
        //         peer_concurrency_level: 4,
        //     },
        // ).await;

        let network_service = TcpNetworkService::new(
            node_id,
            format!(
                "{}:{}",
                validator_set.active_validators[node_id]
                    .config()
                    .find_ip_addr()
                    .unwrap(),
                CONS_BASE_PORT + node_id as u16,
            )
            .parse()
            .unwrap(),
            raikou::framework::tcp_network::Config {
                peers: validator_set
                    .active_validators
                    .iter()
                    .enumerate()
                    .map(|(peer_id, info)| {
                        (format!(
                            "{}:{}",
                            info.config().find_ip_addr().unwrap(),
                            CONS_BASE_PORT + peer_id as u16,
                        )
                        .parse()
                        .unwrap())
                    })
                    .collect(),
                streams_per_peer: 4,
            },
            epoch_state.verifier.clone(),
        )
        .await;

        let config = raikou::raikou::Config {
            n_nodes,
            f,
            storage_requirement: f + 1, // f + (f / 2 + 1),
            leader_timeout: JOLTEON_TIMEOUT,
            leader_schedule: round_robin(n_nodes),
            delta: Duration::from_secs_f64(delta),
            end_of_run: Instant::now() + Duration::from_secs_f64(delta) * total_duration_in_delta,
            extra_wait_before_qc_vote: Duration::from_secs_f64(delta * 0.1),
            extra_wait_before_commit_vote: Duration::from_secs_f64(delta * 0.1),
            enable_round_entry_permission: false,
            enable_commit_votes: true,
            status_interval: Duration::from_secs_f64(delta * 10.),
            round_sync_interval: Duration::from_secs_f64(delta * 15.),
            block_fetch_multiplicity: 1,
        };

        let mut module_network = ModuleNetwork::new();
        let diss_module_network = module_network.register().await;
        let cons_module_network = module_network.register().await;

        let mut block_consensus_latency = metrics::UnorderedBuilder::new();
        let mut batch_consensus_latency = metrics::UnorderedBuilder::new();

        let block_consensus_latency_sender = Some(block_consensus_latency.new_sender());
        let batch_consensus_latency_sender = Some(batch_consensus_latency.new_sender());

        #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
        let dissemination = Self::spawn_fake_dissemination_layer(
            node_id,
            n_nodes,
            f,
            diss_module_network,
            delta,
            start_time,
            epoch_state.clone(),
            diss_rx,
            network_sender.clone(),
            validator_set,
            Arc::new(epoch_state.verifier.clone()),
            enable_optimistic_dissemination,
        )
        .await;

        #[cfg(any(feature = "force-aptos-types", not(feature = "sim-types")))]
        let dissemination = Self::spawn_qs_dissemination_layer(
            node_id,
            payload_client,
            consensus_config,
            payload_manager,
            diss_module_network,
        )
        .await;

        let node = Arc::new(tokio::sync::Mutex::new(RaikouNode::new(
            node_id,
            config,
            dissemination,
            start_time,
            true,
            raikou::raikou::Metrics {
                // propose_time: propose_time_sender,
                // enter_time: enter_time_sender,
                block_consensus_latency: block_consensus_latency_sender,
                batch_consensus_latency: batch_consensus_latency_sender,
                // indirectly_committed_slots: indirectly_committed_slots_sender,
            },
            epoch_state.verifier.clone(),
            validator_signer,
            // ordered_nodes_tx,
        )));

        tokio::select! {
            Ok(ack_tx) = &mut shutdown_rx => {
                let _ = ack_tx.send(());
                return;
            },
            _ = Protocol::run(node, node_id, network_service, cons_module_network, timer) => {
                unreachable!()
            },
        }
    }

    #[cfg(any(feature = "force-aptos-types", not(feature = "sim-types")))]
    async fn spawn_qs_dissemination_layer(
        node_id: NodeId,
        payload_client: Arc<dyn PayloadClient>,
        consensus_config: ConsensusConfig,
        payload_manager: Arc<dyn TPayloadManager>,
        module_network: ModuleNetworkService,
    ) -> impl DisseminationLayer {
        let dissemination = RaikouQSDisseminationLayer {
            node_id,
            payload_client,
            config: consensus_config,
            payload_manager,
            module_id: module_network.module_id(),
        };

        // Ignore all module network messages.
        tokio::spawn(async move {
            let mut module_network = module_network;
            loop {
                let _ = module_network.recv().await;
            }
        });

        dissemination
    }

    #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
    async fn spawn_fake_dissemination_layer(
        node_id: NodeId,
        n_nodes: usize,
        f: usize,
        diss_module_network: ModuleNetworkService,
        delta: f64,
        start_time: Instant,
        epoch_state: Arc<EpochState>,
        diss_rx: aptos_channels::aptos_channel::Receiver<
            aptos_types::PeerId,
            (Author, RaikouNetworkMessage),
        >,
        network_sender: Arc<NetworkSender>,
        validator_set: ValidatorSet,
        validator_verifier: Arc<ValidatorVerifier>,
        enable_optimistic_dissemination: bool,
    ) -> impl DisseminationLayer {
        // let diss_network_service =
        //     RaikouDissNetworkService::new(epoch_state, diss_rx, network_sender);

        // let diss_network_service = UdpNetworkService::new(
        //     node_id,
        //     validator_set.active_validators[node_id].config().find_ip_addr().unwrap(),
        //     // base_port is chosen to avoid any collisions when running
        //     // multiple instances on the same machine.
        //     DISS_BASE_PORT + (node_id * n_nodes) as u16,
        //     udp_network::Config {
        //         peers: validator_set
        //             .active_validators
        //             .iter()
        //             .enumerate()
        //             .map(|(peer_id, info)| (
        //                 info.config().find_ip_addr().unwrap(),
        //                 DISS_BASE_PORT + (peer_id * n_nodes) as u16,
        //             ))
        //             .collect(),
        //         peer_concurrency_level: 4,
        //     },
        // ).await;

        use aptos_types::validator_verifier::{self, ValidatorVerifier};

        let diss_network_service = TcpNetworkService::new(
            node_id,
            format!(
                "{}:{}",
                validator_set.active_validators[node_id]
                    .config()
                    .find_ip_addr()
                    .unwrap(),
                DISS_BASE_PORT + node_id as u16,
            )
            .parse()
            .unwrap(),
            raikou::framework::tcp_network::Config {
                peers: validator_set
                    .active_validators
                    .iter()
                    .enumerate()
                    .map(|(peer_id, info)| {
                        (format!(
                            "{}:{}",
                            info.config().find_ip_addr().unwrap(),
                            DISS_BASE_PORT + peer_id as u16,
                        )
                        .parse()
                        .unwrap())
                    })
                    .collect(),
                streams_per_peer: 4,
            },
            validator_verifier,
        )
        .await;

        let diss_timer = LocalTimerService::new();

        let mut batch_commit_time = metrics::UnorderedBuilder::new();
        let mut queueing_time = metrics::UnorderedBuilder::new();
        let mut penalty_wait_time = metrics::UnorderedBuilder::new();
        let batch_commit_time_sender = Some(batch_commit_time.new_sender());
        let queueing_time_sender = Some(queueing_time.new_sender());
        let penalty_wait_time_sender = Some(penalty_wait_time.new_sender());

        let dissemination = dissemination::fake::FakeDisseminationLayer::new(
            node_id,
            dissemination::fake::Config {
                module_id: diss_module_network.module_id(),
                n_nodes,
                f,
                ac_quorum: 2 * f + 1,
                delta: Duration::from_secs_f64(delta),
                batch_interval: Duration::from_secs_f64(delta), // * 0.1),
                enable_optimistic_dissemination,
                enable_penalty_tracker: true,
                penalty_tracker_report_delay: Duration::from_secs_f64(delta * 5.),
                n_sub_blocks: 7,
            },
            std::iter::repeat_with(|| vec![]),
            start_time,
            true,
            dissemination::fake::Metrics {
                batch_commit_time: batch_commit_time_sender,
                queueing_time: queueing_time_sender,
                penalty_wait_time: penalty_wait_time_sender,
            },
        );

        tokio::spawn(Protocol::run(
            dissemination.protocol(),
            node_id,
            diss_network_service,
            diss_module_network,
            diss_timer,
        ));

        dissemination
    }
}

pub struct RaikouNetworkService<M> {
    epoch: u64,
    n_nodes: usize,
    index_to_address: HashMap<usize, Author>,
    all_peer_addresses: Vec<Author>,
    address_to_index: HashMap<Author, usize>,
    network_sender: Arc<NetworkSender>,
    messages_rx: aptos_channels::aptos_channel::Receiver<Author, (Author, RaikouNetworkMessage)>,
    _phantom: PhantomData<M>,
}

impl<M> RaikouNetworkService<M> {
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
            epoch: epoch_state.epoch,
            n_nodes: epoch_state.verifier.len(),
            index_to_address,
            all_peer_addresses: address_to_index.keys().cloned().collect(),
            address_to_index,
            network_sender,
            messages_rx,
            _phantom: PhantomData,
        }
    }
}

impl<M> NetworkService for RaikouNetworkService<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    type Message = M;

    async fn unicast(&self, data: Self::Message, target: raikou::framework::NodeId) {
        let epoch = self.epoch;
        let remote_peer_id = *self.index_to_address.get(&target).unwrap();
        let network_sender = self.network_sender.clone();

        if drop_injection() {
            return;
        }

        tokio::spawn(async move {
            delay_injection().await;

            let raikou_msg = RaikouNetworkMessage {
                epoch,
                data: bcs::to_bytes(&data).unwrap(),
            };
            // assert!(raikou_msg.data.len() > 0);
            // eprintln!("FOOBAR1: {:#x}", hash(&raikou_msg.data));

            let msg: ConsensusMsg = ConsensusMsg::RaikouMessage(raikou_msg);
            network_sender.send(msg, vec![remote_peer_id]).await
        });
    }

    async fn multicast(&self, data: Self::Message) {
        let epoch = self.epoch;
        // let remote_peer_ids = self.all_peer_addresses.clone();
        let remote_peer_ids = (0..self.n_nodes)
            .map(|i| *self.index_to_address.get(&i).unwrap())
            .filter(|_| !drop_injection())
            .collect();
        let network_sender = self.network_sender.clone();

        tokio::spawn(async move {
            delay_injection().await;

            let raikou_msg = RaikouNetworkMessage {
                epoch,
                data: bcs::to_bytes(&data).unwrap(),
            };
            let msg: ConsensusMsg = ConsensusMsg::RaikouMessage(raikou_msg);

            network_sender.send(msg, remote_peer_ids).await;
        });
    }

    async fn recv(&mut self) -> (raikou::framework::NodeId, Self::Message) {
        // TODO: should we spawn a task for async deserialization?

        let (sender, msg) = self.messages_rx.select_next_some().await;
        let sender = *self.address_to_index.get(&sender).unwrap();
        // assert!(msg.data.len() > 0);
        // eprintln!("FOOBAR2: {:#x}", hash(&msg.data));

        let msg = bcs::from_bytes(&msg.data).unwrap();
        (sender, msg)
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }
}

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub struct RaikouDissNetworkService {
    epoch: u64,
    n_nodes: usize,
    index_to_address: HashMap<usize, Author>,
    all_peer_addresses: Vec<Author>,
    address_to_index: HashMap<Author, usize>,
    network_sender: Arc<NetworkSender>,
    messages_rx: aptos_channels::aptos_channel::Receiver<Author, (Author, RaikouNetworkMessage)>,
}

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
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
            epoch: epoch_state.epoch,
            n_nodes: epoch_state.verifier.len(),
            index_to_address,
            all_peer_addresses: address_to_index.keys().cloned().collect(),
            address_to_index,
            network_sender,
            messages_rx,
        }
    }
}

#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
impl NetworkService for RaikouDissNetworkService {
    type Message = dissemination::fake::Message;

    async fn unicast(&self, data: Self::Message, target: raikou::framework::NodeId) {
        let epoch = self.epoch;
        let remote_peer_id = *self.index_to_address.get(&target).unwrap();
        let network_sender = self.network_sender.clone();

        tokio::spawn(async move {
            delay_injection().await;

            let raikou_msg = RaikouNetworkMessage {
                epoch,
                data: bcs::to_bytes(&data).unwrap(),
            };
            // assert!(raikou_msg.data.len() > 0);
            // eprintln!("BARBAR1: {:#x}", hash(&raikou_msg.data));

            let msg: ConsensusMsg = ConsensusMsg::RaikouDissMessage(raikou_msg);
            network_sender.send(msg, vec![remote_peer_id]).await
        });
    }

    async fn multicast(&self, data: Self::Message) {
        let epoch = self.epoch;
        // let remote_peer_ids = self.all_peer_addresses.clone();
        let remote_peer_ids = (0..self.n_nodes)
            .map(|i| *self.index_to_address.get(&i).unwrap())
            .collect();
        let network_sender = self.network_sender.clone();

        tokio::spawn(async move {
            delay_injection().await;

            let raikou_msg = RaikouNetworkMessage {
                epoch,
                data: bcs::to_bytes(&data).unwrap(),
            };

            let msg: ConsensusMsg = ConsensusMsg::RaikouDissMessage(raikou_msg);
            network_sender.send(msg, remote_peer_ids).await;
        });
    }

    async fn recv(&mut self) -> (raikou::framework::NodeId, Self::Message) {
        // TODO: should we spawn a task for async deserialization?
        let (sender, msg) = self.messages_rx.select_next_some().await;
        let sender = *self.address_to_index.get(&sender).unwrap();
        // eprintln!("BARBAR2: {:#x}", hash(&msg.data));
        let msg = bcs::from_bytes(&msg.data).unwrap();
        (sender, msg)
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }
}

#[cfg(any(feature = "force-aptos-types", not(feature = "sim-types")))]
struct RaikouQSDisseminationLayer {
    node_id: usize,
    payload_client: Arc<dyn PayloadClient>,
    config: ConsensusConfig,
    payload_manager: Arc<dyn TPayloadManager>,
    module_id: ModuleId,
}

#[cfg(any(feature = "force-aptos-types", not(feature = "sim-types")))]
impl RaikouQSDisseminationLayer {}

#[cfg(any(feature = "force-aptos-types", not(feature = "sim-types")))]
impl DisseminationLayer for RaikouQSDisseminationLayer {
    fn module_id(&self) -> raikou::framework::module_network::ModuleId {
        self.module_id
    }

    async fn prepare_block(
        &self,
        round: raikou::raikou::types::Round,
        exclude: std::collections::HashSet<raikou::raikou::types::BatchHash>,
    ) -> raikou::raikou::types::Payload {
        // TODO: Fix the payload filter
        let (_, payload) = self
            .payload_client
            .pull_payload(
                PayloadPullParameters {
                    max_poll_time: Duration::from_millis(self.config.quorum_store_poll_time_ms),
                    max_txns: PayloadTxnsSize::new(
                        self.config.max_sending_block_txns,
                        self.config.max_sending_block_bytes,
                    ),
                    max_txns_after_filtering: self.config.max_sending_block_txns,
                    soft_max_txns_after_filtering: self.config.max_sending_block_txns,
                    max_inline_txns: PayloadTxnsSize::new(
                        self.config.max_sending_inline_txns,
                        self.config.max_sending_inline_bytes,
                    ),
                    user_txn_filter: PayloadFilter::Empty,
                    pending_ordering: false,
                    pending_uncommitted_blocks: 0,
                    recent_max_fill_fraction: 0.0,
                    block_timestamp: aptos_infallible::duration_since_epoch(),
                    maybe_optqs_payload_pull_params: Some(OptQSPayloadPullParams {
                        exclude_authors: HashSet::new(),
                        minimum_batch_age_usecs: 0,
                    }),
                },
                TransactionFilter::no_op(),
                async {}.boxed(),
            )
            .await
            .unwrap();

        raikou::raikou::types::Payload::new(round, self.node_id, payload)
    }

    async fn prefetch_payload_data(&self, payload: &raikou::raikou::types::Payload) {
        self.payload_manager.prefetch_payload_data(
            &payload.data,
            aptos_infallible::duration_since_epoch().as_micros() as u64,
        );
    }

    async fn check_stored_all(&self, payload: &raikou::raikou::types::Payload) -> bool {
        self.payload_manager
            .check_payload_availability(&payload.data)
            .is_ok()
    }

    async fn notify_commit(&self, payloads: Vec<raikou::raikou::types::Payload>) {
        let payloads = payloads
            .iter()
            .map(|payload| {
                aptos_consensus_types::common::Payload::Raikou(
                    payload.data.as_raikou_payload().clone(),
                )
            })
            .collect();
        self.payload_manager.notify_commit(
            aptos_infallible::duration_since_epoch().as_micros() as u64,
            payloads,
        );
    }
}
