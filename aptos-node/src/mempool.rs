use aptos_config::config::NodeConfig;
use aptos_consensus_notifications::{
    ConsensusNotification, ConsensusNotificationListener, ConsensusNotifier,
};
use aptos_crypto::HashValue;
use aptos_framework::natives::debug;
use aptos_infallible::Mutex;
use aptos_logger::{debug, info};
use aptos_mempool::{QuorumStoreRequest, QuorumStoreResponse};
use aptos_mempool_notifications::{
    CommittedTransaction, MempoolCommitNotification, MempoolNotificationListener, MempoolNotifier,
};
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
use std::{
    cmp::min,
    collections::{BTreeMap, HashMap, VecDeque},
    convert::Infallible,
    iter::zip,
    mem,
    net::SocketAddr,
    sync::Arc,
};
use tokio::{runtime::Runtime, task::JoinHandle};
use warp::{
    filters::BoxedFilter,
    reject::Rejection,
    reply::{self, Reply},
    Filter,
};

pub type TransactionStore = VecDeque<(SignedTransaction, oneshot::Sender<()>)>;

pub struct PendingTracker {
    tracker: HashMap<(PeerId, u64), oneshot::Sender<()>>,
}

impl PendingTracker {
    fn register(&mut self, txn: &SignedTransaction, tx: oneshot::Sender<()>) {
        debug!("register: {}, {}", txn.sender(), txn.sequence_number());
        self.tracker
            .insert((txn.sender(), txn.sequence_number()), tx);
    }

    fn notify(&mut self, txn: &Transaction) {
        let txn = txn.try_as_signed_user_txn().unwrap();
        debug!("notify: {}. {}", txn.sender(), txn.sequence_number());
        if let Some(sender) = self.tracker.remove(&(txn.sender(), txn.sequence_number())) {
            sender.send(()).unwrap();
        }
    }
}

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

        let to_pull = min(store.len(), max_txns as usize);
        let pulled = store.drain(..to_pull);
        let mut pulled_txns = Vec::with_capacity(to_pull);

        for (txn, tx) in pulled {
            self.pending_tracker.register(&txn, tx);
            pulled_txns.push(txn);
        }
        info!("pulled txns: {}", pulled_txns.len());
        drop(store);
        sender
            .send(Ok(QuorumStoreResponse::GetBatchResponse(pulled_txns)))
            .unwrap();
    }

    fn handle_notification_command(&mut self, cmd: ConsensusNotification) {
        let ConsensusNotification::NotifyCommit(notif) = cmd else {
            return;
        };
        for txn in notif.get_transactions() {
            self.pending_tracker.notify(txn)
        }
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
                    self.handle_notification_command(cmd);
                },
            };
        }
    }
}

pub fn create_mempool_runtime(
    config: &NodeConfig,
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
    runtime.spawn(start_mempool_api(store, config.api.address));

    (runtime, consensus_to_mempool_sender, consensus_notifier)
}

#[derive(Clone)]
pub struct SimpleMempoolApiContext {
    store: Arc<Mutex<TransactionStore>>,
}

impl SimpleMempoolApiContext {
    pub fn filter(
        self,
    ) -> impl Filter<Extract = (SimpleMempoolApiContext,), Error = Infallible> + Clone {
        warp::any().map(move || self.clone())
    }
}

async fn start_mempool_api(store: Arc<Mutex<TransactionStore>>, api_address: SocketAddr) {
    let context = SimpleMempoolApiContext { store };

    let api = warp::path!("submit_txn")
        .and(warp::post())
        .and(context.filter())
        .and(warp::body::bytes())
        .and_then(handle_txn)
        .boxed();

    warp::serve(api).bind(api_address).await
}

pub async fn handle_txn(
    context: SimpleMempoolApiContext,
    request: bytes::Bytes,
) -> anyhow::Result<impl Reply, Rejection> {
    debug!("api: handle_txn");

    let txn: SignedTransaction = bcs::from_bytes(&request).unwrap();
    let (tx, rx) = oneshot::channel();

    context.store.lock().push_back((txn, tx));

    if let Err(_) = rx.await {
        debug!("api: response channel dropped unexpectedly");
        return Ok(reply::with_status(
            reply::reply(),
            warp::hyper::StatusCode::NOT_FOUND,
        ));
    }

    debug!("api: txn successfully committed");
    Ok(reply::with_status(
        reply::reply(),
        warp::hyper::StatusCode::CREATED,
    ))
}
