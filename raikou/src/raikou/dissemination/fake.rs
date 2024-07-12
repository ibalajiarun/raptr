// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{
        module_network::ModuleId,
        network::{NetworkService, Validate},
        timer::TimerService,
        ContextFor, NodeId, Protocol,
    },
    metrics,
    metrics::Sender,
    protocol,
    raikou::{
        dissemination::{
            penalty_tracker,
            penalty_tracker::{PenaltyTracker, PenaltyTrackerReports},
            BlockReceived, DisseminationLayer, Kill,
        },
        types::*,
    },
};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use bitvec::prelude::BitVec;
use defaultmap::DefaultBTreeMap;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    future::Future,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Serialize)]
pub struct Batch {
    data: BatchData,
    #[serde(skip)]
    digest: BatchHash,
}

#[derive(Clone, Hash, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
struct BatchData {
    author: NodeId,
    batch_id: BatchId,
    txns: Arc<Vec<Txn>>,
}

impl<'de> Deserialize<'de> for Batch {
    fn deserialize<D>(deserializer: D) -> Result<Batch, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = BatchData::deserialize(deserializer)?;
        let digest = hash(&data);
        Ok(Batch { data, digest })
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        BatchData::deserialize_in_place(deserializer, &mut place.data)?;
        place.digest = hash(&place.data);
        Ok(())
    }
}

impl Batch {
    pub fn get_info(&self) -> BatchInfo {
        BatchInfo {
            author: self.author(),
            batch_id: self.batch_id(),
            digest: self.digest.clone(),
        }
    }

    pub fn author(&self) -> NodeId {
        self.data.author
    }

    pub fn batch_id(&self) -> BatchId {
        self.data.batch_id
    }

    pub fn txns(&self) -> &[Txn] {
        &self.data.txns
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    Batch(Batch),
    BatchStored(BatchId),
    AvailabilityCert(AC),
    // Fetch(BatchHash),
    PenaltyTrackerReport(Round, PenaltyTrackerReports),
}

impl Validate for Message {
    fn validate(&self) -> anyhow::Result<()> {
        // TODO: implement validation
        Ok(())
    }
}

#[derive(Clone)]
pub enum TimerEvent {
    NewBatch(BatchId),
    PenaltyTrackerReport(NodeId, Round, Instant, Payload),
}

#[derive(Clone)]
pub struct Config {
    pub module_id: ModuleId,
    pub n_nodes: usize,
    pub f: usize,
    pub ac_quorum: usize,
    pub delta: Duration,
    pub batch_interval: Duration,
    pub enable_optimistic_dissemination: bool,
    pub enable_penalty_tracker: bool,
    pub penalty_tracker_report_delay: Duration,
    pub n_sub_blocks: usize,
}

pub struct Metrics {
    pub batch_commit_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub queueing_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub penalty_wait_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
    // pub average_penalty: Option<metrics::UnorderedSender<(Instant, f64)>>,
    // pub total_committed_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub two_chain_commit_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub order_vote_committed_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub committed_acs: Option<metrics::UnorderedSender<(Instant, usize)>>,
    // pub optimistically_committed_batches: Option<metrics::UnorderedSender<(Instant, usize)>>,
}

#[derive(Clone)]
pub struct FakeDisseminationLayer<TI> {
    config: Config,
    inner: Arc<tokio::sync::Mutex<FakeDisseminationLayerProtocol<TI>>>,
}

impl<TI> FakeDisseminationLayer<TI>
where
    TI: Iterator<Item = Vec<Txn>> + Send + Sync,
{
    pub fn new(
        node_id: NodeId,
        mut config: Config,
        txns_iter: TI,
        start_time: Instant,
        detailed_logging: bool,
        metrics: Metrics,
    ) -> Self {
        if !config.enable_optimistic_dissemination && !config.enable_penalty_tracker {
            aptos_logger::warn!(
                "Disabling the penalty tracker because optimistic dissemination is disabled."
            );
            config.enable_penalty_tracker = false;
        }

        Self {
            config: config.clone(),
            inner: Arc::new(tokio::sync::Mutex::new(
                FakeDisseminationLayerProtocol::new(
                    node_id,
                    config,
                    txns_iter,
                    start_time,
                    detailed_logging,
                    metrics,
                ),
            )),
        }
    }

    pub fn protocol(
        &self,
    ) -> Arc<tokio::sync::Mutex<impl Protocol<Message = Message, TimerEvent = TimerEvent>>> {
        self.inner.clone()
    }
}

impl<TI> DisseminationLayer for FakeDisseminationLayer<TI>
where
    TI: Iterator<Item = Vec<Txn>> + Send + Sync + 'static,
{
    fn module_id(&self) -> ModuleId {
        self.config.module_id
    }

    async fn prepare_block(&self, round: Round, exclude: HashSet<BatchHash>) -> Payload {
        let mut inner = self.inner.lock().await;

        let acs = inner
            .new_acs
            .iter()
            .filter(|&batch_hash| !exclude.contains(batch_hash))
            .map(|batch_hash| inner.acs[batch_hash].clone()) // WARNING: potentially expensive clone
            .collect();

        let batches = if inner.config.enable_optimistic_dissemination {
            let batches = inner
                .new_batches
                .iter()
                .filter(|&batch_hash| !exclude.contains(batch_hash))
                .map(|batch_hash| inner.batches[batch_hash].get_info())
                .collect();

            // If the penalty tracker is disabled, this will sort the batches
            // by the order they were received.
            inner.penalty_tracker.prepare_new_block(round, batches)
        } else {
            vec![]
        };

        Payload::new(round, inner.node_id, acs, batches)
    }

    async fn prefetch_payload_data(&self, payload: Payload) {
        let new_acs = payload
            .acs()
            .into_iter()
            .cloned()
            .map(|ac| (ac.info.digest.clone(), ac));
        self.inner.lock().await.acs.extend(new_acs);
    }

    async fn check_stored_all(&self, batches: &[BatchInfo]) -> bool {
        let inner = self.inner.lock().await;
        if let Some(_missing) = batches
            .into_iter()
            .find(|batch| !inner.batches.contains_key(&batch.digest))
        {
            // inner.log_detail(format!(
            //     "Missing batch #{} from node {} with digest {:#x}",
            //     _missing.batch_id, _missing.author, _missing.digest,
            // ));
            false
        } else {
            true
        }
    }

    async fn notify_commit(&self, payloads: Vec<Payload>) {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();

        for payload in &payloads {
            for batch in payload.all() {
                if inner.committed_batches.contains(&batch.digest) {
                    // TODO: add a metric for batch duplication.
                    continue;
                }

                inner.committed_batches.insert(batch.digest.clone());
                inner.new_acs.remove(&batch.digest);
                inner.new_batches.remove(&batch.digest);

                if batch.author == inner.node_id {
                    let commit_time =
                        inner.to_deltas(inner.batch_send_time[&batch.digest].elapsed());
                    inner.metrics.batch_commit_time.push((now, commit_time));
                }
            }
        }

        // Metrics:
        // Only track queueing time and penalties for the committed batches.
        // At the moment, they are only tracked for optimistically committed batches.
        for payload in &payloads {
            for batch in payload.sub_blocks().iter().flatten() {
                if payload.leader() == inner.node_id {
                    let block_prepare_time =
                        inner.penalty_tracker.block_prepare_time(payload.round());
                    let batch_receive_time = inner
                        .penalty_tracker
                        .batch_receive_time(batch.digest.clone());
                    let penalty = inner
                        .penalty_tracker
                        .block_prepare_penalty(payload.round(), batch.author);
                    let batch_propose_delay = block_prepare_time - batch_receive_time;

                    assert!(batch_propose_delay >= penalty);
                    let queueing_time_in_deltas = inner.to_deltas(batch_propose_delay - penalty);
                    inner
                        .metrics
                        .queueing_time
                        .push((now, queueing_time_in_deltas));

                    let penalty_in_deltas = inner.to_deltas(penalty);
                    inner
                        .metrics
                        .penalty_wait_time
                        .push((now, penalty_in_deltas));
                }
            }
        }
    }
}

pub struct FakeDisseminationLayerProtocol<TI> {
    txns_iter: TI,
    config: Config,
    node_id: NodeId,

    penalty_tracker: PenaltyTracker,

    // Storage for all received batches and the time when they were.
    batches: BTreeMap<BatchHash, Batch>,
    my_batches: BTreeMap<BatchId, BatchHash>,
    // Storage of all received ACs.
    acs: BTreeMap<BatchHash, AC>,
    // Set of committed batches.
    committed_batches: BTreeSet<BatchHash>,
    // Set of known ACs that are not yet committed.
    new_acs: BTreeSet<BatchHash>,
    // Set of known uncertified batches that are not yet committed.
    new_batches: BTreeSet<BatchHash>,

    // The set of nodes that have stored this node's batch with the given sequence number.
    batch_stored_votes: DefaultBTreeMap<BatchId, BitVec>,

    batch_created_time: DefaultBTreeMap<BatchId, Instant>,

    // Logging and metrics
    detailed_logging: bool,
    start_time: Instant,
    metrics: Metrics,
    batch_send_time: BTreeMap<BatchHash, Instant>,
}

impl<TI> FakeDisseminationLayerProtocol<TI>
where
    TI: Iterator<Item = Vec<Txn>> + Send + Sync,
{
    pub fn new(
        node_id: NodeId,
        config: Config,
        txns_iter: TI,
        start_time: Instant,
        detailed_logging: bool,
        metrics: Metrics,
    ) -> Self {
        let n_nodes = config.n_nodes;
        let penalty_tracker_config = penalty_tracker::Config {
            n_nodes: config.n_nodes,
            f: config.f,
            enable: config.enable_penalty_tracker,
            n_sub_blocks: config.n_sub_blocks,
            batch_expiration_time: config.delta * 3,
        };

        Self {
            txns_iter,
            config,
            node_id,
            penalty_tracker: PenaltyTracker::new(node_id, penalty_tracker_config, detailed_logging),
            batches: BTreeMap::new(),
            my_batches: Default::default(),
            acs: BTreeMap::new(),
            committed_batches: BTreeSet::new(),
            new_acs: BTreeSet::new(),
            new_batches: BTreeSet::new(),
            batch_stored_votes: DefaultBTreeMap::new(BitVec::repeat(false, n_nodes)),
            batch_created_time: DefaultBTreeMap::new(Instant::now()),
            detailed_logging,
            start_time,
            metrics,
            batch_send_time: Default::default(),
        }
    }

    async fn on_new_batch(&mut self, batch: Batch, ctx: &mut impl ContextFor<Self>) {
        let digest = batch.digest.clone();
        let batch_id = batch.batch_id();
        let author = batch.author();

        self.penalty_tracker.on_new_batch(digest.clone());
        self.batches.insert(digest.clone(), batch);

        ctx.unicast(Message::BatchStored(batch_id), author).await;

        // Track the list of known uncommitted uncertified batches.
        if !self.acs.contains_key(&digest) && !self.committed_batches.contains(&digest) {
            self.new_batches.insert(digest);
        }
    }

    fn to_deltas(&self, duration: Duration) -> f64 {
        duration.as_secs_f64() / self.config.delta.as_secs_f64()
    }

    fn log_info(&self, msg: String) {
        aptos_logger::info!("Node {}: Dissemination Layer: {}", self.node_id, msg,);
    }

    fn log_detail(&self, msg: String) {
        if self.detailed_logging {
            self.log_info(msg);
        }
    }
}

impl<TI> Protocol for FakeDisseminationLayerProtocol<TI>
where
    TI: Iterator<Item = Vec<Txn>> + Send + Sync,
{
    type Message = Message;
    type TimerEvent = TimerEvent;

    protocol! {
        self: self;
        ctx: ctx;

        // Dissemination layer
        // In this implementation, batches are simply sent periodically, by a timer.

        upon start {
            // The first batch is sent immediately.
            ctx.set_timer(Duration::ZERO, TimerEvent::NewBatch(1));
        };

        // Creating and certifying batches

        upon timer [TimerEvent::NewBatch(batch_id)] {
            // Multicast a new batch
            let batch_data = BatchData {
                author: self.node_id,
                batch_id,
                txns: Arc::new(self.txns_iter.next().unwrap()),
            };
            let digest = hash(&batch_data);
            let batch = Batch { data: batch_data, digest: digest.clone() };

            self.log_detail(format!(
                "Creating batch #{} with digest {:#x}",
                batch_id,
                digest,
            ));
            ctx.multicast(Message::Batch(batch.clone())).await;

            self.batch_created_time[batch_id] = Instant::now();
            self.my_batches.insert(batch_id, digest.clone());
            self.on_new_batch(batch, ctx).await;

            // Reset the timer.
            ctx.set_timer(self.config.batch_interval, TimerEvent::NewBatch(batch_id + 1));

            self.batch_send_time.insert(digest, Instant::now());
        };

        // Upon receiving a batch, store it, reply with a BatchStored message,
        // and execute try_vote.
        upon receive [Message::Batch(batch)] from node [p] {
            // TODO: add it to the message validation.
            // if batch.author() == p {
            //     break 'handler;
            // }

            // self.log_detail(format!(
            //     "Received batch #{} from node {} with digest {:#x}",
            //     batch.batch_id(),
            //     batch.author(),
            //     batch.digest,
            // ));

            if !self.batches.contains_key(&batch.digest) {
                self.on_new_batch(batch, ctx).await;
            }
        };

        // Upon receiving a quorum of BatchStored messages for a batch,
        // form an AC and broadcast it.
        upon receive [Message::BatchStored(batch_id)] from node [p] {
            self.batch_stored_votes[batch_id].set(p, true);

            if self.batch_stored_votes[batch_id].count_ones() == self.config.ac_quorum {
                self.log_detail(format!(
                    "Forming the AC for batch #{} with digest {:#x}",
                    batch_id,
                    self.batches[&self.my_batches[&batch_id]].digest,
                ));
                ctx.multicast(Message::AvailabilityCert(AC {
                    info: self.batches[&self.my_batches[&batch_id]].get_info(),
                    signers: self.batch_stored_votes[batch_id].clone(),
                })).await;
            }
        };

        upon receive [Message::AvailabilityCert(ac)] from [_any_node] {
            // Track the list of known uncommitted ACs
            // and the list of known uncommitted uncertified batches.
            if !self.committed_batches.contains(&ac.info.digest) {
                self.new_acs.insert(ac.info.digest.clone());
                self.new_batches.remove(&ac.info.digest);
            }

            self.acs.insert(ac.info.digest.clone(), ac.clone());
        };

        // Penalty tracking

        upon event of type [BlockReceived] from [_any_module] {
            upon [BlockReceived { leader, round, payload }] {
                if self.config.enable_penalty_tracker {
                    ctx.set_timer(
                        self.config.penalty_tracker_report_delay,
                        TimerEvent::PenaltyTrackerReport(
                            leader,
                            round,
                            Instant::now(),
                            payload,
                        )
                    );
                }
            };
        };

        upon timer event [TimerEvent::PenaltyTrackerReport(leader, round, block_receive_time, payload)] {
            let reports = self.penalty_tracker.prepare_reports(payload, block_receive_time);
            ctx.unicast(Message::PenaltyTrackerReport(round, reports), leader).await;
        };

        upon receive [Message::PenaltyTrackerReport(round, reports)] from node [p] {
            if self.config.enable_penalty_tracker {
                self.penalty_tracker.register_reports(round, p, reports);
            }
        };

        // upon receive [Message::Fetch(digest)] from node [p] {
        //     // FIXME: fetching is not actually being used yet.
        //     //        `Message::Fetch` is never sent.
        //     // If receive a Fetch message, reply with the batch if it is known.
        //     if let Some(batch) = self.batches.get(&digest) {
        //         ctx.unicast(Message::Batch(batch.clone()), p).await;
        //     }
        // };

        // Halting

        upon event of type [Kill] from [_any_module] {
            upon [Kill()] {
                self.log_detail("Halting".to_string());
                ctx.halt();
            };
        };
    }
}
