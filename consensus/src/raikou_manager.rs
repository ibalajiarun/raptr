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
use aptos_bitvec::BitVec;
use aptos_config::config::ConsensusConfig;
use aptos_consensus_notifications::ConsensusNotificationSender;
use aptos_consensus_types::{
    block::Block,
    block_data::{BlockData, BlockType},
    common::{Author, Payload, PayloadFilter},
    payload::{InlineBatches, OptQuorumStorePayload},
    payload_pull_params::{OptQSPayloadPullParams, PayloadPullParameters},
    proof_of_store::BatchInfo,
    quorum_cert::QuorumCert,
    utils::PayloadTxnsSize,
};
use aptos_crypto::HashValue;
use aptos_logger::error;
use aptos_types::{
    chain_id::ChainId,
    epoch_state::EpochState,
    network_address::parse_ip_tcp,
    on_chain_config::ValidatorSet,
    transaction::{
        authenticator::AccountAuthenticator, RawTransaction, Script, SignedTransaction,
        Transaction, TransactionPayload,
    },
    validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
    PeerId,
};
use aptos_validator_transaction_pool::TransactionFilter;
use futures::{executor::block_on, future::BoxFuture, FutureExt, StreamExt};
use futures_channel::{mpsc::UnboundedSender, oneshot};
use itertools::Itertools;
use raikou::{
    framework::{
        injection::{delay_injection, drop_injection},
        module_network::{match_event_type, ModuleId, ModuleNetwork, ModuleNetworkService},
        network::{MessageCertifier, Network, NetworkService},
        tcp_network::TcpNetworkService,
        timer::LocalTimerService,
        NodeId, Protocol,
    },
    metrics,
    metrics::{display_metric, display_metric_to},
    raikou::{
        dissemination::{self, DisseminationLayer},
        types as raikou_types,
        types::Prefix,
        RaikouNode,
    },
};
use rayon::slice::ParallelSlice;
use serde::{Deserialize, Serialize};
use std::{
    any::{Any, TypeId},
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    marker::PhantomData,
    net::SocketAddr,
    ops::Deref,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::lookup_host, time::Instant};

const JOLTEON_TIMEOUT: u32 = 3; // in Deltas
const CONS_BASE_PORT: u16 = 12000;
const DISS_BASE_PORT: u16 = 12500;

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
        state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    ) {
        let n_nodes = epoch_state.verifier.len();
        let f = (n_nodes - 1) / 3;
        let ac_quorum = 2 * f + 1;
        let start_time = Instant::now();

        let timer = LocalTimerService::new();

        let address_to_index = epoch_state.verifier.address_to_validator_index().clone();
        let index_to_address = address_to_index
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect::<HashMap<_, _>>();

        let node_id = *address_to_index.get(&self_author).unwrap();

        if validator_set.active_validators[node_id]
            .config()
            .find_ip_addr()
            .is_none()
        {
            error!("ip missing for self: {:?}", validator_set);
        }

        let signer = raikou::framework::crypto::Signer::new(validator_signer.clone());

        let sig_verifier = raikou::framework::crypto::SignatureVerifier::new(
            index_to_address
                .iter()
                .sorted_by_key(|(&index, _)| index)
                .map(|(_, address)| epoch_state.verifier.get_public_key(address).unwrap())
                .collect(),
        );

        // let network_service: RaikouNetworkService<raikou::raikou::Message> =
        //     RaikouNetworkService::new(epoch_state.clone(), messages_rx, network_sender.clone());
        //
        // network_service.multicast(raikou::raikou::Message::AdvanceRound(
        //     0,
        //     raikou::raikou::QC::genesis(),
        //     RoundEnterReason::Genesis
        // )).await;

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
            status_interval: Duration::from_secs_f64(delta) * 10,
            round_sync_interval: Duration::from_secs_f64(delta) * 15,
            block_fetch_multiplicity: std::cmp::min(2, n_nodes),
            block_fetch_interval: Duration::from_secs_f64(delta) * 2,
            ac_quorum,
        };

        let mut module_network = ModuleNetwork::new();
        let diss_module_network = module_network.register().await;
        let cons_module_network = module_network.register().await;
        let diss_module_id = diss_module_network.module_id();
        let cons_module_id = cons_module_network.module_id();

        // Consensus metrics
        let mut block_consensus_latency = metrics::UnorderedBuilder::new();
        let mut batch_consensus_latency = metrics::UnorderedBuilder::new();

        // Dissemination layer metrics
        let mut batch_commit_time = metrics::UnorderedBuilder::new();
        let mut batch_execute_time = metrics::UnorderedBuilder::new();
        let mut queueing_time = metrics::UnorderedBuilder::new();
        let mut penalty_wait_time = metrics::UnorderedBuilder::new();
        let mut fetch_wait_time_after_commit = metrics::UnorderedBuilder::new();
        let executed_txns_counter = Arc::new(AtomicUsize::new(0));

        let diss_metrics = dissemination::Metrics {
            batch_commit_time: Some(batch_commit_time.new_sender()),
            batch_execute_time: Some(batch_execute_time.new_sender()),
            queueing_time: Some(queueing_time.new_sender()),
            penalty_wait_time: Some(penalty_wait_time.new_sender()),
            fetch_wait_time_after_commit: Some(fetch_wait_time_after_commit.new_sender()),
        };

        // #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
        let dissemination = Self::spawn_fake_dissemination_layer(
            node_id,
            n_nodes,
            f,
            ac_quorum,
            diss_module_network,
            delta,
            cons_module_id,
            start_time,
            &validator_set,
            signer.clone(),
            sig_verifier.clone(),
            enable_optimistic_dissemination,
            diss_metrics,
            executed_txns_counter.clone(),
        )
        .await;

        #[cfg(none)]
        let dissemination = Self::spawn_qs_dissemination_layer(
            node_id,
            payload_client,
            consensus_config,
            payload_manager,
            diss_module_network,
            state_sync_notifier,
            index_to_address,
        )
        .await;

        let raikou_node = Arc::new(tokio::sync::Mutex::new(RaikouNode::new(
            node_id,
            config,
            dissemination,
            true,
            raikou::raikou::Metrics {
                // propose_time: propose_time_sender,
                // enter_time: enter_time_sender,
                block_consensus_latency: Some(block_consensus_latency.new_sender()),
                batch_consensus_latency: Some(batch_consensus_latency.new_sender()),
                // indirectly_committed_slots: indirectly_committed_slots_sender,
            },
            signer.clone(),
            sig_verifier.clone(),
            // ordered_nodes_tx,
        )));

        let network_service = TcpNetworkService::new(
            node_id,
            format!("0.0.0.0:{}", CONS_BASE_PORT + node_id as u16)
                .parse()
                .unwrap(),
            raikou::framework::tcp_network::Config {
                peers: validator_set
                    .active_validators
                    .iter()
                    .enumerate()
                    .map(|(peer_id, info)| {
                        let ip = info.config().find_ip_addr();
                        let addr = if let Some(addr) = ip {
                            addr
                        } else {
                            let dns = info.config().find_dns_name().unwrap();
                            block_on(lookup_host((
                                dns.to_string(),
                                CONS_BASE_PORT + peer_id as u16,
                            )))
                            .expect(&format!("{}", dns))
                            .next()
                            .unwrap()
                            .ip()
                        };

                        format!("{}:{}", addr, CONS_BASE_PORT + peer_id as u16)
                            .parse()
                            .unwrap()
                    })
                    .collect(),
                streams_per_peer: 4,
            },
            Arc::new(raikou::raikou::protocol::Certifier::new()),
            Arc::new(raikou::raikou::protocol::Verifier::new(
                raikou_node.lock().await.deref(),
            )),
            32 * 1024 * 1024, // 32MB max block size
        )
        .await;

        let print_metrics = async {
            // Notify the protocol to stop.
            let module_net = module_network.register().await;
            module_net
                .notify(cons_module_id, dissemination::Kill())
                .await;

            // All data from the warmup period is discarded.
            let warmup_period_in_delta = 50;

            let mut metrics_output_buf = Vec::new();

            // Printing metrics, internally, will wait for the protocol to halt.
            display_metric_to(
                &mut metrics_output_buf,
                "Fetch wait time after commit",
                "The duration from committing a block until being able to execute it, i.e., \
                    until we have the whole prefix of the chain fetched.",
                fetch_wait_time_after_commit,
                start_time,
                delta,
                warmup_period_in_delta,
            )
            .await
            .unwrap();

            display_metric_to(
                &mut metrics_output_buf,
                "Penalty system delay",
                "The penalties for optimistically committed batches. \
                    Measured on the leader.",
                penalty_wait_time,
                start_time,
                delta,
                warmup_period_in_delta,
            )
            .await
            .unwrap();

            display_metric_to(
                &mut metrics_output_buf,
                "Optimistic batch queueing time",
                "The duration from when the batch is received by leader until the block \
                    containing this batch is proposed. \
                    Only measured if the block is committed. \
                    Only measured for optimistically committed batches. \
                    Measured on the leader.",
                queueing_time,
                start_time,
                delta,
                warmup_period_in_delta,
            )
            .await
            .unwrap();

            display_metric_to(
                &mut metrics_output_buf,
                "Batch consensus latency",
                "The duration from when the batch is included in a block until \
                    the block is committed. \
                    Measured on the leader.",
                batch_consensus_latency,
                start_time,
                delta,
                warmup_period_in_delta,
            )
            .await
            .unwrap();

            display_metric_to(
                &mut metrics_output_buf,
                "Batch commit time",
                "The duration from creating the batch until committing it. \
                    After committing, we may have to wait for the data to be fetched. \
                    Measured on the batch creator.",
                batch_commit_time,
                start_time,
                delta,
                warmup_period_in_delta,
            )
            .await
            .unwrap();

            display_metric_to(
                &mut metrics_output_buf,
                "Batch execute time (the end-to-end latency)",
                "The duration from creating the batch until executing it. \
                    Measured on the batch creator.",
                batch_execute_time,
                start_time,
                delta,
                warmup_period_in_delta,
            )
            .await
            .unwrap();

            aptos_logger::info!(
                "Metrics: \n{}",
                std::str::from_utf8(&metrics_output_buf).unwrap(),
            );

            let executed_txns = executed_txns_counter.load(Ordering::SeqCst);
            aptos_logger::info!(
                "Executed transactions: {} ({:.0} TPS)",
                executed_txns,
                executed_txns as f64 / (delta * total_duration_in_delta as f64)
            );
        };

        tokio::select! {
            Ok(ack_tx) = &mut shutdown_rx => {
                print_metrics.await;
                let _ = ack_tx.send(());
            },
            _ = Protocol::run(raikou_node, node_id, network_service, cons_module_network, timer) => {
                print_metrics.await;
            },
        }
    }

    #[cfg(none)]
    async fn spawn_qs_dissemination_layer(
        node_id: NodeId,
        payload_client: Arc<dyn PayloadClient>,
        consensus_config: ConsensusConfig,
        payload_manager: Arc<dyn TPayloadManager>,
        mut module_network: ModuleNetworkService,
        state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
        index_to_address: HashMap<usize, Author>,
    ) -> impl DisseminationLayer {
        let round_initial_timeout =
            Duration::from_millis(consensus_config.round_initial_timeout_ms);

        let dissemination = RaikouQSDisseminationLayer {
            node_id,
            payload_client,
            config: consensus_config,
            payload_manager: payload_manager.clone(),
            module_id: module_network.module_id(),
            state_sync_notifier,
        };

        tokio::spawn(async move {
            loop {
                let (consensus_module, event) = module_network.recv().await;

                if match_event_type::<dissemination::ProposalReceived>(&event) {
                    let event: Box<_> = event
                        .as_any()
                        .downcast::<dissemination::ProposalReceived>()
                        .ok()
                        .unwrap();
                    let dissemination::ProposalReceived { round, payload, .. } = *event;

                    payload_manager.prefetch_payload_data(
                        &payload.inner,
                        aptos_infallible::duration_since_epoch().as_micros() as u64,
                    );

                    let module_network_sender = module_network.new_sender();
                    let payload_manager = payload_manager.clone();
                    let block_author = Some(index_to_address[&payload.author()]);

                    tokio::spawn(async move {
                        if let Ok(_) = payload_manager
                            .wait_for_payload(
                                &payload.inner,
                                block_author,
                                // timestamp is only used for batch expiration, which is not
                                // supported in this prototype.
                                0,
                                round_initial_timeout,
                            )
                            .await
                        {
                            module_network_sender
                                .notify(consensus_module, dissemination::FullBlockAvailable {
                                    round,
                                })
                                .await;
                        }
                    });
                } else if match_event_type::<dissemination::NewQCWithPayload>(&event) {
                    let event: Box<_> = event
                        .as_any()
                        .downcast::<dissemination::NewQCWithPayload>()
                        .ok()
                        .unwrap();
                    let dissemination::NewQCWithPayload { payload, qc } = *event;
                    // TODO: add fetching here
                } else if match_event_type::<dissemination::Kill>(&event) {
                    break;
                } else {
                    panic!("Unhandled module event: {}", event.debug_string());
                }
            }
        });

        dissemination
    }

    // #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
    async fn spawn_fake_dissemination_layer(
        node_id: NodeId,
        n_nodes: usize,
        f: usize,
        ac_quorum: usize,
        diss_module_network: ModuleNetworkService,
        delta: f64,
        consensus_module_id: ModuleId,
        start_time: Instant,
        validator_set: &ValidatorSet,
        signer: raikou::framework::crypto::Signer,
        sig_verifier: raikou::framework::crypto::SignatureVerifier,
        enable_optimistic_dissemination: bool,
        metrics: dissemination::Metrics,
        executed_txns_counter: Arc<AtomicUsize>,
    ) -> impl DisseminationLayer {
        let batch_interval_secs = delta * 0.2;

        let config = dissemination::native::Config {
            module_id: diss_module_network.module_id(),
            n_nodes,
            f,
            ac_quorum,
            delta: Duration::from_secs_f64(delta),
            batch_interval: Duration::from_secs_f64(batch_interval_secs),
            enable_optimistic_dissemination,
            // penalty tracker doesn't work with 0 delays
            enable_penalty_tracker: false,
            penalty_tracker_report_delay: Duration::from_secs_f64(delta * 5.),
            batch_fetch_multiplicity: std::cmp::min(2, n_nodes),
            batch_fetch_interval: Duration::from_secs_f64(delta) * 2,
            status_interval: Duration::from_secs_f64(delta) * 10,
        };

        let diss_timer = LocalTimerService::new();

        // TODO: make these into parameters.
        let target_tps = 100_000;
        let n_client_workers = 5;

        let batch_size =
            f64::ceil(target_tps as f64 * batch_interval_secs / n_nodes as f64) as usize;

        let txns_iter = run_fake_client(batch_size, n_client_workers).await;

        let (execute_tx, mut execute_rx) =
            tokio::sync::mpsc::channel::<dissemination::native::Batch>(1024);

        tokio::spawn(async move {
            while let Some(batch) = execute_rx.recv().await {
                executed_txns_counter.fetch_add(batch.txns().len(), Ordering::SeqCst);
            }
        });

        let dissemination = dissemination::native::NativeDisseminationLayer::new(
            node_id,
            config,
            txns_iter,
            consensus_module_id,
            start_time,
            true,
            metrics,
            signer.clone(),
            sig_verifier,
            execute_tx,
        );

        let diss_network_service = TcpNetworkService::new(
            node_id,
            format!("0.0.0.0:{}", DISS_BASE_PORT + node_id as u16)
                .parse()
                .unwrap(),
            raikou::framework::tcp_network::Config {
                peers: validator_set
                    .active_validators
                    .iter()
                    .enumerate()
                    .map(|(peer_id, info)| {
                        let ip = info.config().find_ip_addr();
                        let addr = if let Some(addr) = ip {
                            addr
                        } else {
                            let dns = info.config().find_dns_name().unwrap();
                            block_on(lookup_host((
                                dns.to_string(),
                                DISS_BASE_PORT + peer_id as u16,
                            )))
                            .expect(&format!("{}", dns))
                            .next()
                            .unwrap()
                            .ip()
                        };

                        format!("{}:{}", addr, DISS_BASE_PORT + peer_id as u16)
                            .parse()
                            .unwrap()
                    })
                    .collect(),
                streams_per_peer: 4,
            },
            Arc::new(dissemination::native::Certifier::new(signer)),
            Arc::new(dissemination::native::Verifier::new(&dissemination).await),
            1 * 1024 * 1024,
        )
        .await;

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

async fn run_fake_client(
    batch_size: usize,
    n_workers: usize,
) -> impl Iterator<Item = Vec<SignedTransaction>> {
    let (txns_tx, mut txns_rx) = tokio::sync::mpsc::channel(5);

    for _ in 0..n_workers {
        let txns_tx = txns_tx.clone();

        tokio::spawn(async move {
            let mut seq_num = 0;
            let sender = PeerId::random();

            loop {
                let mut txns = vec![];
                txns.reserve_exact(batch_size);

                for _ in 0..batch_size {
                    let txn = SignedTransaction::new_single_sender(
                        RawTransaction::new(
                            sender,
                            seq_num,
                            TransactionPayload::Script(Script::new(
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                            )),
                            0,
                            0,
                            Duration::from_secs(60).as_secs(),
                            ChainId::test(),
                        ),
                        AccountAuthenticator::NoAccountAuthenticator,
                    );
                    seq_num += 1;

                    txns.push(txn);
                }

                if txns_tx.send(txns).await.is_err() {
                    // The execution ended.
                    break;
                }
            }
        });
    }

    std::iter::from_fn(move || {
        if let Ok(txns) = txns_rx.try_recv() {
            Some(txns)
        } else {
            aptos_logger::warn!("Fake client is not fast enough! Consider adding more workers.");
            None
        }
    })
}

pub struct RaikouNetworkSenderInner<M, C> {
    epoch: u64,
    n_nodes: usize,
    index_to_address: HashMap<usize, Author>,
    network_sender: Arc<NetworkSender>,
    certifier: Arc<C>,
    _phantom: PhantomData<M>,
}

impl<M, C> RaikouNetworkSenderInner<M, C>
where
    M: raikou::framework::network::NetworkMessage + Serialize + for<'de> Deserialize<'de>,
    C: raikou::framework::network::MessageCertifier<Message = M>,
{
    async fn send(&self, mut msg: M, targets: Vec<NodeId>) {
        let epoch = self.epoch;
        let remote_peer_ids = targets
            .into_iter()
            .map(|i| *self.index_to_address.get(&i).unwrap())
            .collect();

        let aptos_network_sender = self.network_sender.clone();
        let certifier = self.certifier.clone();

        // Serialization and signing are done in a separate task to avoid blocking the main loop.
        tokio::spawn(async move {
            certifier.certify(&mut msg).await.unwrap();

            let raikou_msg = RaikouNetworkMessage {
                epoch,
                data: bcs::to_bytes(&msg).unwrap(),
            };

            let mut msg: ConsensusMsg = ConsensusMsg::RaikouMessage(raikou_msg);

            aptos_network_sender.send(msg, remote_peer_ids).await;
        });
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }
}

pub struct RaikouNetworkSender<M, C> {
    inner: Arc<RaikouNetworkSenderInner<M, C>>,
}

// #[derive(Clone)] doesn't work for `M` and `C` that are not `Clone`.
impl<M, C> Clone for RaikouNetworkSender<M, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<M, C> raikou::framework::network::NetworkSender for RaikouNetworkSender<M, C>
where
    M: raikou::framework::network::NetworkMessage + Serialize + for<'de> Deserialize<'de>,
    C: raikou::framework::network::MessageCertifier<Message = M>,
{
    type Message = M;

    async fn send(&self, data: Self::Message, targets: Vec<NodeId>) {
        self.inner.send(data, targets).await;
    }

    fn n_nodes(&self) -> usize {
        self.inner.n_nodes()
    }
}

pub struct RaikouNetworkService<M, C> {
    sender: RaikouNetworkSender<M, C>,
    deserialized_messages_rx: tokio::sync::mpsc::Receiver<(NodeId, M)>,
}

impl<M, C> RaikouNetworkService<M, C>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
    C: MessageCertifier<Message = M> + Send + Sync + 'static,
{
    pub async fn new(
        epoch_state: Arc<EpochState>,
        mut messages_rx: aptos_channels::aptos_channel::Receiver<
            PeerId,
            (Author, RaikouNetworkMessage),
        >,
        network_sender: Arc<NetworkSender>,
        certifier: Arc<C>,
    ) -> Self {
        let address_to_index = epoch_state.verifier.address_to_validator_index().clone();
        let index_to_address = address_to_index
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();

        let (deserialized_messages_tx, deserialized_messages_rx) = tokio::sync::mpsc::channel(1024);

        // Spawn a separate task to deserialize messages.
        // This helps to avoid blocking the main loop.
        tokio::spawn(async move {
            loop {
                let (sender, msg) = messages_rx.select_next_some().await;
                let sender = *address_to_index.get(&sender).unwrap();

                if drop_injection() {
                    aptos_logger::info!("APTNET: CONS: Dropping a message from {}", sender);
                    continue;
                }

                // Deserialize the message concurrently.
                let deserialized_messages_tx = deserialized_messages_tx.clone();
                tokio::spawn(async move {
                    let msg = bcs::from_bytes(&msg.data).unwrap();

                    delay_injection().await;

                    // TODO: add validation

                    if deserialized_messages_tx.send((sender, msg)).await.is_err() {
                        // no-op.
                    }
                });
            }
        });

        Self {
            sender: RaikouNetworkSender {
                inner: Arc::new(RaikouNetworkSenderInner {
                    epoch: epoch_state.epoch,
                    n_nodes: epoch_state.verifier.len(),
                    index_to_address,
                    network_sender,
                    certifier,
                    _phantom: PhantomData,
                }),
            },
            deserialized_messages_rx,
        }
    }
}

impl<M, C> raikou::framework::network::NetworkSender for RaikouNetworkService<M, C>
where
    M: raikou::framework::network::NetworkMessage + Serialize + for<'de> Deserialize<'de>,
    C: raikou::framework::network::MessageCertifier<Message = M>,
{
    type Message = M;

    async fn send(&self, msg: Self::Message, targets: Vec<NodeId>) {
        self.sender.send(msg, targets).await;
    }

    fn n_nodes(&self) -> usize {
        self.sender.n_nodes()
    }
}

impl<M, C> NetworkService for RaikouNetworkService<M, C>
where
    M: raikou::framework::network::NetworkMessage + Serialize + for<'de> Deserialize<'de>,
    C: raikou::framework::network::MessageCertifier<Message = M>,
{
    type Sender = RaikouNetworkSender<M, C>;

    fn new_sender(&self) -> Self::Sender {
        self.sender.clone()
    }

    async fn recv(&mut self) -> (NodeId, Self::Message) {
        self.deserialized_messages_rx.recv().await.unwrap()
    }
}

#[cfg(none)]
struct RaikouQSDisseminationLayer {
    node_id: usize,
    payload_client: Arc<dyn PayloadClient>,
    config: ConsensusConfig,
    payload_manager: Arc<dyn TPayloadManager>,
    module_id: ModuleId,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
}

#[cfg(none)]
impl RaikouQSDisseminationLayer {}

#[cfg(none)]
impl DisseminationLayer for RaikouQSDisseminationLayer {
    fn module_id(&self) -> ModuleId {
        self.module_id
    }

    async fn prepare_block(
        &self,
        round: raikou_types::Round,
        exclude: HashSet<raikou_types::BatchHash>,
    ) -> raikou_types::Payload {
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

        raikou_types::Payload::new(round, self.node_id, payload)
    }

    async fn available_prefix(
        &self,
        payload: &raikou_types::Payload,
        cached_value: Prefix,
    ) -> Prefix {
        self.payload_manager.prefetch_payload_data(
            &payload.inner,
            aptos_infallible::duration_since_epoch().as_micros() as u64,
        );
        self.payload_manager
            .available_prefix(payload.inner.as_raikou_payload(), cached_value)
    }

    async fn notify_commit(&self, payloads: Vec<raikou_types::Payload>) {
        let payload_manager = self.payload_manager.clone();
        let state_sync_notifier = self.state_sync_notifier.clone();

        tokio::spawn(async move {
            let payloads: Vec<Payload> =
                payloads.into_iter().map(|payload| payload.inner).collect();

            for payload in &payloads {
                payload_manager.prefetch_payload_data(
                    payload,
                    aptos_infallible::duration_since_epoch().as_micros() as u64,
                );
            }
            payload_manager.notify_commit(
                aptos_infallible::duration_since_epoch().as_micros() as u64,
                payloads.clone(),
            );

            for payload in payloads {
                while let Err(_) = payload_manager
                    .wait_for_payload(&payload, None, 0, Duration::from_secs(1))
                    .await
                {
                    // TODO: add a logging / metric?
                }

                let block = Block::new_for_dag(
                    0,
                    0,
                    0,
                    Vec::new(),
                    payload,
                    PeerId::ZERO,
                    Vec::new(),
                    HashValue::zero(),
                    BitVec::with_num_bits(8),
                    Vec::new(),
                );

                match payload_manager.get_transactions(&block).await {
                    Ok((txns, _)) => {
                        let txns = txns.into_iter().map(Transaction::UserTransaction).collect();
                        state_sync_notifier
                            .notify_new_commit(txns, Vec::new())
                            .await
                            .unwrap();
                    },
                    Err(_e) => unreachable!("Failed to get transactions for block {:?} even after waiting for the payload", block),
                }
            }
        });
    }
}
