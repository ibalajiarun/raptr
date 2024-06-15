use crate::{
    framework::{
        module_network::ModuleId, network::NetworkService, timer::TimerService, NodeId, Protocol,
    },
    metrics,
    metrics::Sender,
    protocol,
    raikou::{
        dissemination::{BlockReceived, DisseminationLayer, Kill},
        penalty_tracker,
        penalty_tracker::{PenaltyTracker, PenaltyTrackerReports},
        types::*,
    },
};
use bitvec::prelude::BitVec;
use defaultmap::DefaultBTreeMap;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    future::Future,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone)]
pub struct Batch {
    author: NodeId,
    batch_id: BatchId,
    digest: HashValue,
    txns: Option<Vec<Txn>>,
}

impl Batch {
    pub fn get_info(&self) -> BatchInfo {
        BatchInfo {
            author: self.author,
            batch_id: self.batch_id,
            digest: self.digest,
        }
    }
}

#[derive(Clone)]
pub enum Message {
    Batch(Batch),
    BatchStored(BatchId),
    AvailabilityCert(AC),
    // Fetch(BatchHash),
    PenaltyTrackerReport(Round, PenaltyTrackerReports),
}

#[derive(Clone)]
pub enum TimerEvent {
    NewBatch(BatchId),
    PenaltyTrackerReport(NodeId, Round, Instant, Vec<BatchInfo>),
}

#[derive(Clone)]
pub struct Config {
    pub module_id: ModuleId,
    pub n_nodes: usize,
    pub f: usize,
    pub ac_quorum: usize,
    pub delta: Duration,
    pub batch_interval: Duration,
    pub enable_penalty_tracker: bool,
    pub penalty_tracker_report_delay: Duration,
}

pub struct Metrics {
    pub batch_commit_time: Option<metrics::UnorderedSender<(Instant, f64)>>,
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
        config: Config,
        txns_iter: TI,
        start_time: Instant,
        detailed_logging: bool,
        metrics: Metrics,
    ) -> Self {
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

        let batches = inner
            .new_batches
            .iter()
            .filter(|&batch_hash| !exclude.contains(batch_hash))
            .map(|batch_hash| inner.batches[batch_hash].get_info()) // WARNING: potentially expensive clone
            .collect();

        let batches = inner.penalty_tracker.prepare_new_block(round, batches);

        Payload::new(acs, batches)
    }

    async fn prefetch_payload_data(&self, payload: Payload) {
        let new_acs = payload
            .acs()
            .into_iter()
            .cloned()
            .map(|ac| (ac.batch.digest, ac));
        self.inner.lock().await.acs.extend(new_acs);
    }

    async fn check_stored_all(&self, batches: &Vec<BatchHash>) -> bool {
        let inner = self.inner.lock().await;
        batches
            .into_iter()
            .all(|batch| inner.batches.contains_key(&batch))
    }

    async fn notify_commit(&self, payloads: Vec<Payload>) {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();

        for payload in payloads {
            for batch in payload.all() {
                assert!(!inner.committed_batches.contains(&batch.digest));

                inner.committed_batches.insert(batch.digest);
                inner.new_acs.remove(&batch.digest);
                inner.new_batches.remove(&batch.digest);

                if batch.author == inner.node_id {
                    let commit_time =
                        inner.to_deltas(inner.batch_send_time[&batch.digest].elapsed());
                    inner.metrics.batch_commit_time.push((now, commit_time));
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

    fn to_deltas(&self, duration: Duration) -> f64 {
        duration.as_secs_f64() / self.config.delta.as_secs_f64()
    }

    fn log_info(&self, msg: String) {
        log::info!("Node {}: Dissemination Layer: {}", self.node_id, msg,);
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

        upon timer [TimerEvent::NewBatch(sn)] {
            let txns = self.txns_iter.next();
            let digest = hash((self.node_id, sn, &txns));

            // Multicast a new batch
            ctx.multicast(Message::Batch(Batch {
                author: self.node_id,
                batch_id: sn,
                digest,
                txns,
            })).await;

            self.batch_created_time[sn] = Instant::now();
            self.my_batches.insert(sn, digest);

            // Reset the timer.
            ctx.set_timer(self.config.batch_interval, TimerEvent::NewBatch(sn + 1));

            self.batch_send_time.insert(digest, Instant::now());
        };

        // Upon receiving a batch, store it, reply with a BatchStored message,
        // and execute try_vote.
        upon receive [Message::Batch(batch)] from node [p] {
            // TODO: add verification of the digest?
            let digest = batch.digest;
            let batch_id = batch.batch_id;

            if !self.batches.contains_key(&digest) {
                self.penalty_tracker.on_new_batch(digest);

                self.batches.insert(digest, batch);

                ctx.unicast(Message::BatchStored(batch_id), p).await;

                // Track the list of known uncommitted uncertified batches.
                if !self.acs.contains_key(&digest) && !self.committed_batches.contains(&digest) {
                    self.new_batches.insert(digest);
                }
            }
        };

        // Upon receiving a quorum of BatchStored messages for a batch,
        // form an AC and broadcast it.
        upon receive [Message::BatchStored(batch_id)] from node [p] {
            self.batch_stored_votes[batch_id].set(p, true);

            if self.batch_stored_votes[batch_id].count_ones() == self.config.ac_quorum {
                let digest = self.my_batches[&batch_id];
                ctx.multicast(Message::AvailabilityCert(AC {
                    batch: self.batches[&digest].get_info(),
                    signers: self.batch_stored_votes[batch_id].clone(),
                })).await;
            }
        };

        upon receive [Message::AvailabilityCert(ac)] from [_any_node] {
            // Track the list of known uncommitted ACs
            // and the list of known uncommitted uncertified batches.
            if !self.committed_batches.contains(&ac.batch.digest) {
                self.new_acs.insert(ac.batch.digest);
                self.new_batches.remove(&ac.batch.digest);
            }

            self.acs.insert(ac.batch.digest, ac.clone());
        };

        // Penalty tracking

        upon event of type [BlockReceived] from [_any_module] {
            upon [BlockReceived { leader, round, payload }] {
                if self.config.enable_penalty_tracker {
                    ctx.set_timer(
                        self.config.penalty_tracker_report_delay,
                        TimerEvent::PenaltyTrackerReport(leader, round, Instant::now(), payload.batches().clone())
                    );
                }
            };
        };

        upon timer event [TimerEvent::PenaltyTrackerReport(leader, round, block_receive_time, batches)] {
            let reports = self.penalty_tracker.prepare_reports(&batches, block_receive_time);
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
