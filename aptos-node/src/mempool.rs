// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use aptos_config::config::NodeConfig;
use aptos_consensus_notifications::{
    ConsensusNotification, ConsensusNotificationListener, ConsensusNotifier,
};
use aptos_crypto::HashValue;
use aptos_framework::natives::debug;
use aptos_infallible::Mutex;
use aptos_logger::{debug, error, info, sample, sample::SampleRate};
use aptos_mempool::{QuorumStoreRequest, QuorumStoreResponse};
use aptos_mempool_notifications::{
    CommittedTransaction, MempoolCommitNotification, MempoolNotificationListener, MempoolNotifier,
};
use aptos_metrics_core::{register_gauge, register_histogram, Gauge, Histogram};
use aptos_types::{
    transaction::{SignedTransaction, Transaction},
    PeerId,
};
use futures::{
    channel::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    future::Pending,
    select, StreamExt,
};
use itertools::zip_eq;
use once_cell::sync::Lazy;
use std::{
    cmp::min,
    collections::{BTreeMap, HashMap, VecDeque},
    convert::Infallible,
    iter::zip,
    mem,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{runtime::Runtime, task::JoinHandle};
use warp::{
    filters::BoxedFilter,
    reject::Rejection,
    reply::{self, Reply},
    Filter,
};

pub type TransactionStore = VecDeque<(SignedTransaction, oneshot::Sender<()>, Instant)>;

struct TrackingItem {
    tx: oneshot::Sender<()>,
    insert_time: Instant,
}

pub struct PendingTracker {
    tracker: HashMap<(PeerId, u64), TrackingItem>,
}

impl PendingTracker {
    fn register(&mut self, txn: &SignedTransaction, tx: oneshot::Sender<()>, insert_time: Instant) {
        self.tracker
            .insert((txn.sender(), txn.sequence_number()), TrackingItem {
                tx,
                insert_time,
            });
    }

    fn notify(&mut self, txn: &Transaction) {
        let txn = txn.try_as_signed_user_txn().unwrap();
        if let Some(item) = self.tracker.remove(&(txn.sender(), txn.sequence_number())) {
            RAIKOU_MEMPOOL_INSERT_TO_COMMIT_LATENCY
                .observe(item.insert_time.elapsed().as_secs_f64());
            if item.tx.send(()).is_err() {
                error!("client timedout: {}", txn.sender());
            }
        }
    }
}

const COMMIT_LATENCY_BUCKETS: &[f64] = &[
    0.05, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7,
    0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0, 2.2, 2.4, 2.6, 2.8, 3.0, 3.2,
    3.4, 3.6, 3.8, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5, 7.0, 7.5, 10.0,
];

pub static RAIKOU_MEMPOOL_PULL_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "raikou_mempool_insert_to_pull_latency",
        "Raikou Mempool Insert to Pull Latency",
        COMMIT_LATENCY_BUCKETS.to_vec(),
    )
    .unwrap()
});

pub static RAIKOU_MEMPOOL_INSERT_TO_COMMIT_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "raikou_mempool_insert_to_commit_latency",
        "Raikou Pull to Commit Latnecy",
        COMMIT_LATENCY_BUCKETS.to_vec()
    )
    .unwrap()
});

pub static RAIKOU_MEMPOOL_SIZE: Lazy<Gauge> =
    Lazy::new(|| register_gauge!("raikou_mempool_size", "Raikou mempool size").unwrap());

pub static RAIKOU_MEMPOOL_SIZE_HISTOGRAM: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!("raikou_mempool_size_histogram", "raikou mempool size").unwrap()
});

pub struct SimpleMempool {
    pub transaction_store: Arc<Mutex<TransactionStore>>,
    pub pending_tracker: PendingTracker,
}

impl SimpleMempool {
    fn handle_quorum_store_request(&mut self, req: QuorumStoreRequest) {
        let QuorumStoreRequest::GetBatchRequest(max_txns, max_bytes, _, _, sender) = req else {
            unreachable!();
        };
        let mut store = self.transaction_store.lock();

        info!("pulling: store len: {}", store.len());

        let to_pull = min(store.len(), max_txns as usize);
        let pulled = store.drain(..to_pull);
        let mut pulled_txns = Vec::with_capacity(to_pull);

        for (txn, tx, insert_time) in pulled {
            RAIKOU_MEMPOOL_PULL_LATENCY.observe(insert_time.elapsed().as_secs_f64());
            self.pending_tracker.register(&txn, tx, insert_time);
            pulled_txns.push(txn);
        }
        if pulled_txns.is_empty() {
            sample!(
                SampleRate::Duration(Duration::from_secs(10)),
                info!("pulled_txns empty");
            );
        } else {
            info!(
                "pulled txns: {}; store len: {}",
                pulled_txns.len(),
                store.len()
            );
        }
        RAIKOU_MEMPOOL_SIZE.set(store.len() as f64);
        RAIKOU_MEMPOOL_SIZE_HISTOGRAM.observe(store.len() as f64);

        drop(store);
        sender
            .send(Ok(QuorumStoreResponse::GetBatchResponse(pulled_txns)))
            .unwrap();
    }

    fn handle_notification_command(
        &mut self,
        cmd: ConsensusNotification,
        listener: &mut ConsensusNotificationListener,
    ) {
        let ConsensusNotification::NotifyCommit(notif) = cmd else {
            return;
        };
        for txn in notif.get_transactions() {
            self.pending_tracker.notify(txn);
        }
        listener
            .respond_to_commit_notification(notif, Ok(()))
            .unwrap();
    }

    async fn run(
        mut self,
        mut consensus_rx: Receiver<QuorumStoreRequest>,
        mut commit_notif_rx: ConsensusNotificationListener,
    ) {
        loop {
            tokio::select! {
                Some(req) = consensus_rx.next() => {
                    self.handle_quorum_store_request(req);
                },
                Some(cmd) = commit_notif_rx.next() => {
                    self.handle_notification_command(cmd, &mut commit_notif_rx);
                },
            };
        }
    }
}

pub fn create_mempool_runtime(
    config: &NodeConfig,
    health_check: Arc<AtomicBool>,
) -> (Runtime, Sender<QuorumStoreRequest>, ConsensusNotifier) {
    let (consensus_to_mempool_sender, consensus_to_mempool_receiver) =
        futures::channel::mpsc::channel(100);

    let (consensus_notifier, consensus_listener) =
        aptos_consensus_notifications::new_consensus_notifier_listener_pair(1000);

    let runtime = aptos_runtimes::spawn_named_runtime("mempool".into(), None);

    let store = Arc::new(Mutex::new(TransactionStore::with_capacity(100_000)));
    let mempool = SimpleMempool {
        transaction_store: store.clone(),
        pending_tracker: PendingTracker {
            tracker: HashMap::new(),
        },
    };

    runtime.spawn(mempool.run(consensus_to_mempool_receiver, consensus_listener));
    runtime.spawn(start_mempool_api(health_check, store, config.api.address));

    (runtime, consensus_to_mempool_sender, consensus_notifier)
}

#[derive(Clone)]
pub struct SimpleMempoolApiContext {
    store: Arc<Mutex<TransactionStore>>,
    health_check: Arc<AtomicBool>,
}

impl SimpleMempoolApiContext {
    pub fn filter(
        self,
    ) -> impl Filter<Extract = (SimpleMempoolApiContext,), Error = Infallible> + Clone {
        warp::any().map(move || self.clone())
    }
}

async fn start_mempool_api(
    health_check: Arc<AtomicBool>,
    store: Arc<Mutex<TransactionStore>>,
    api_address: SocketAddr,
) {
    let context = SimpleMempoolApiContext {
        health_check,
        store,
    };
    let ctx_filter = context.filter().clone();

    let submit = warp::path!("submit_txn")
        .and(warp::post())
        .and(ctx_filter.clone())
        .and(warp::body::bytes())
        .and_then(handle_txn)
        .boxed();

    let submit_batch = warp::path!("submit_txn_batch")
        .and(warp::post())
        .and(ctx_filter.clone())
        .and(warp::body::bytes())
        .and_then(handle_txn_batch)
        .boxed();

    let health_check = warp::path!("health_check")
        .and(warp::get())
        .and(ctx_filter)
        .and_then(handle_health_check)
        .boxed();

    let api = submit.or(health_check).or(submit_batch);

    warp::serve(api).bind(api_address).await
}

pub async fn handle_txn(
    context: SimpleMempoolApiContext,
    request: bytes::Bytes,
) -> anyhow::Result<impl Reply, Rejection> {
    if !context.health_check.load(Ordering::Relaxed) {
        return Err(warp::reject::not_found());
    }

    let txn: SignedTransaction = bcs::from_bytes(&request).unwrap();
    let (tx, rx) = oneshot::channel();

    context.store.lock().push_back((txn, tx, Instant::now()));

    if let Err(_) = rx.await {
        debug!("api: response channel dropped unexpectedly");
        return Ok(reply::with_status(
            reply::reply(),
            warp::hyper::StatusCode::BAD_REQUEST,
        ));
    }

    debug!("api: txn successfully committed");
    Ok(reply::with_status(
        reply::reply(),
        warp::hyper::StatusCode::CREATED,
    ))
}

pub async fn handle_health_check(
    context: SimpleMempoolApiContext,
) -> anyhow::Result<impl Reply, Rejection> {
    if context.health_check.load(Ordering::Relaxed) {
        Ok(reply::with_status(
            reply::reply(),
            warp::hyper::StatusCode::CREATED,
        ))
    } else {
        Err(warp::reject::not_found())
    }
}

pub async fn handle_txn_batch(
    context: SimpleMempoolApiContext,
    request: bytes::Bytes,
) -> anyhow::Result<impl Reply, Rejection> {
    if !context.health_check.load(Ordering::Relaxed) {
        return Err(warp::reject::not_found());
    }

    let txn_batch: Vec<SignedTransaction> = bcs::from_bytes(&request).unwrap();

    let now = Instant::now();
    let mut rxs = Vec::new();
    {
        let mut locked_store = context.store.lock();
        for txn in txn_batch {
            let (tx, rx) = oneshot::channel();
            locked_store.push_back((txn, tx, now));
            rxs.push(rx);
        }
    }

    for rx in rxs {
        if let Err(_) = rx.await {
            debug!("api: response channel dropped unexpectedly");
            return Ok(reply::with_status(
                reply::reply(),
                warp::hyper::StatusCode::BAD_REQUEST,
            ));
        }
    }

    debug!("api: batch txn successfully committed");
    Ok(reply::with_status(
        reply::reply(),
        warp::hyper::StatusCode::CREATED,
    ))
}
