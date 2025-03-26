// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    derive_module_event,
    framework::{
        crypto,
        crypto::{dummy_signature, SignatureVerifier, Signer},
        module_network::{ModuleEventTrait, ModuleId},
        network::{
            MessageCertifier, MessageVerifier, NetworkSender, NetworkService, NoopCertifier,
            NoopVerifier, ShardMessage,
        },
        timer::TimerService,
        ContextFor, NodeId, Protocol,
    },
    metrics,
    metrics::Sender,
    monitor, protocol,
    raikou::{
        counters::OP_COUNTERS,
        dissemination::{
            BlockPrepareTime, DisseminationLayer, FullBlockAvailable, Kill, Metrics,
            NewQCWithPayload, NotifyCommit, PayloadReady, PreparePayload, ProposalReceived,
            SetLoggingBaseTimestamp,
        },
        duration_since_epoch, protocol,
        types::*,
    },
};
use anyhow::{ensure, Context};
use aptos_bitvec::BitVec;
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, Genesis};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_logger::warn;
use aptos_types::block_executor::partitioner::ShardId;
use defaultmap::DefaultBTreeMap;
use itertools::{traits::IteratorIndex, Itertools};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    cmp::max,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    future::Future,
    ops::Range,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::RwLock, time::Instant};

pub type BundleIndex = usize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderData {
    round: Round,
    author: NodeId,
    timestamp_usecs: u64,
    masked_bundles: Vec<(BundleIndex, (BitVec, BitVec))>,
    digest: HashValue,
    reason: RoundEntryReason,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    data: Arc<BlockHeaderData>,
}

impl BlockHeader {
    pub fn new(
        round: Round,
        author: NodeId,
        timestamp_usecs: u64,
        masked_bundles: Vec<(BundleIndex, (BitVec, BitVec))>,
        digest: HashValue,
        reason: RoundEntryReason,
        signature: Signature,
    ) -> Self {
        Self {
            data: Arc::new(BlockHeaderData {
                round,
                author,
                timestamp_usecs,
                masked_bundles,
                digest,
                reason,
                signature,
            }),
        }
    }

    pub fn round(&self) -> Round {
        self.data.round
    }

    pub fn author(&self) -> NodeId {
        self.data.author
    }

    pub fn timestamp_usecs(&self) -> u64 {
        self.data.timestamp_usecs
    }

    pub fn bundle_indices(&self) -> impl ExactSizeIterator<Item = BundleIndex> + '_ {
        self.data.masked_bundles.iter().map(|(index, _)| *index)
    }

    pub fn n_bundles(&self) -> usize {
        self.data.masked_bundles.len()
    }

    pub fn masked_bundles(&self) -> &Vec<(BundleIndex, (BitVec, BitVec))> {
        &self.data.masked_bundles
    }

    pub fn digest(&self) -> HashValue {
        self.data.digest
    }

    pub fn reason(&self) -> &RoundEntryReason {
        &self.data.reason
    }

    pub fn signature(&self) -> &Signature {
        &self.data.signature
    }
}

derive_module_event!(CreateBlock);
derive_module_event!(BlockCreated);
derive_module_event!(ReconstructBlock);
derive_module_event!(BlockReconstructed);

/// Request for a new block.
#[derive(Debug)]
pub struct CreateBlock {
    pub round: Round,
    pub timestamp_usecs: u64,
    pub reason: RoundEntryReason,
    pub exclude: HashSet<BatchInfo>,
}

#[derive(Debug)]
pub struct BlockCreated {
    pub header: BlockHeader,
}

/// Event sent by the consensus module to reconstruct a block from its header.
#[derive(Debug)]
pub struct ReconstructBlock {
    pub block_header: BlockHeader,
}

/// Event sent to the consensus module in response to `ReconstructBlock`
#[derive(Debug)]
pub struct BlockReconstructed {
    pub block: Block,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "BundleSerialization")]
pub struct Bundle {
    data: BundleData,

    #[serde(skip)]
    digest: BatchHash,
}

impl Bundle {
    pub fn payload(&self) -> &Payload {
        &self.data.payload
    }

    pub fn index(&self) -> BundleIndex {
        self.data.index
    }
}

#[derive(Deserialize)]
struct BundleSerialization {
    data: BundleData,
}

impl From<BundleSerialization> for Bundle {
    fn from(serialized: BundleSerialization) -> Self {
        Self {
            digest: serialized.data.hash(),
            data: serialized.data,
        }
    }
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
struct BundleData {
    payload: Payload,
    index: BundleIndex,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    Bundle(Bundle, u64),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Bundle(bundle, _ts) => {
                write!(
                    f,
                    "Bundle({}, {})",
                    bundle.data.payload.author(),
                    bundle.data.index
                )
            },
        }
    }
}

pub type Certifier = NoopCertifier;

impl MessageVerifier<ShardMessage<Message>> for protocol::Verifier {
    async fn verify(&self, sender: NodeId, message: &ShardMessage<Message>) -> anyhow::Result<()> {
        let (shard_id, message) = message;

        match message {
            Message::Bundle(bundle, _ts) => monitor!("verify_bundle", {
                // TODO: verify payload size.

                ensure!(bundle.data.payload.author() == *shard_id, "Invalid author");
                ensure!(
                    bundle.data.payload.author() == sender,
                    "Author is not sender"
                );
                bundle.data.payload.verify(self, None, sender)
            }),
        }
    }
}

#[derive(Clone)]
pub enum TimerEvent {
    NewBundle(BundleIndex),
    Status,
}

#[derive(Clone)]
pub struct Config {
    pub module_id: ModuleId,
    pub n_nodes: usize,
    // pub f: usize,
    // pub poa_quorum: usize,
    pub delta: Duration,
    pub bundle_window: BundleIndex,
    pub bundle_store_window: BundleIndex,
    pub bundle_interval: Duration,
    pub min_bundle_interval: Duration,
    pub max_pending_requests_per_node: usize,
    // pub batch_fetch_interval: Duration,
    // pub batch_fetch_multiplicity: usize,
    // pub enable_optimistic_dissemination: bool,
    // pub enable_penalty_tracker: bool,
    // pub penalty_tracker_report_delay: Duration,
    pub status_interval: Duration,
    // pub block_size_limit: BlockSizeLimit,
    // pub push_bundle_when_proposing: bool,
}

#[derive(Clone)]
pub struct Bundler {
    config: Config,
    inner: Arc<tokio::sync::Mutex<BundlerProtocol>>,
}

impl Bundler {
    pub fn new(
        node_id: NodeId,
        shard_author: NodeId,
        config: Config,
        consensus_module_id: ModuleId,
        dissemination_module_id: ModuleId,
        detailed_logging: bool,
        // metrics: Metrics,
        signer: Signer,
        // sig_verifier: SignatureVerifier,
    ) -> Self {
        Self {
            config: config.clone(),
            inner: Arc::new(tokio::sync::Mutex::new(BundlerProtocol::new(
                node_id,
                shard_author,
                config,
                consensus_module_id,
                dissemination_module_id,
                detailed_logging,
                // metrics,
                signer,
                // sig_verifier,
            ))),
        }
    }

    pub fn protocol(
        &self,
    ) -> Arc<tokio::sync::Mutex<impl Protocol<Message = Message, TimerEvent = TimerEvent>>> {
        self.inner.clone()
    }
}

struct ProducerData {
    ongoing_payload_request: Option<(BundleIndex, Instant)>,
    my_bundles: VecDeque<Bundle>,
    included_poas: HashSet<BatchInfo>,
    included_batches: HashSet<BatchInfo>,
    committed_batches: HashSet<BatchInfo>,
}

struct Logger {
    node_id: NodeId,
    config: Config,
    shard_author: NodeId,
    detailed_logging: bool,
    logging_base_timestamp: Option<SystemTime>,
}

impl Logger {
    fn to_deltas(&self, duration: Duration) -> f64 {
        duration.as_secs_f64() / self.config.delta.as_secs_f64()
    }

    fn time_in_delta(&self) -> Option<f64> {
        Some(
            self.to_deltas(
                SystemTime::now()
                    .duration_since(self.logging_base_timestamp?)
                    .ok()?,
            ),
        )
    }

    fn log_info(&self, msg: String) {
        let time_str = self
            .time_in_delta()
            .map(|t| format!("{:.2}Δ", t))
            .unwrap_or_else(|| "???Δ".to_string());

        aptos_logger::info!(
            "Node {} at {}: Bundler shard {}: {}",
            self.node_id,
            self.shard_author,
            time_str,
            msg
        );
    }

    fn log_detail(&self, msg: String) {
        if self.detailed_logging {
            self.log_info(msg);
        }
    }
}

pub struct BundlerProtocol {
    node_id: NodeId,
    shard_author: NodeId,

    config: Config,
    dissemination_module_id: ModuleId,
    consensus_module_id: ModuleId,

    producer_data: Option<ProducerData>,

    reconstruction_requests: BTreeMap<Round, (BlockHeader, Instant)>,
    bundles: BTreeMap<BundleIndex, Bundle>,

    signer: Signer,
    logger: Logger,
}

impl BundlerProtocol {
    pub fn new(
        node_id: NodeId,
        shard_author: NodeId,
        config: Config,
        consensus_module_id: ModuleId,
        dissemination_module_id: ModuleId,
        detailed_logging: bool,
        // metrics: Metrics,
        signer: Signer,
        // sig_verifier: SignatureVerifier,
    ) -> Self {
        let n_nodes = config.n_nodes;

        let producer_data = if node_id == shard_author {
            Some(ProducerData {
                ongoing_payload_request: None,
                my_bundles: Default::default(),
                included_poas: Default::default(),
                included_batches: Default::default(),
                committed_batches: Default::default(),
            })
        } else {
            None
        };

        Self {
            config: config.clone(),
            node_id,
            shard_author,
            consensus_module_id,
            dissemination_module_id,
            producer_data,
            reconstruction_requests: BTreeMap::new(),
            bundles: BTreeMap::new(),
            signer,
            logger: Logger {
                node_id,
                config,
                shard_author,
                detailed_logging,
                logging_base_timestamp: None,
            },
        }
    }

    async fn on_new_bundle(
        &mut self,
        author: NodeId,
        bundle: Bundle,
        ctx: &mut impl ContextFor<Self>,
    ) {
        let index = bundle.data.index;

        // Remove old bundles from this author.
        loop {
            let Some((&first_index, _)) = self.bundles.first_key_value() else {
                break;
            };

            if first_index + self.config.bundle_store_window < index {
                self.bundles.pop_first();
            } else {
                break;
            }
        }

        self.bundles.insert(index, bundle);

        let mut satisfied_requests = vec![];
        for (&req_id, (block_header, ts)) in &self.reconstruction_requests {
            if self.try_reconstruct(block_header, ts, ctx).await {
                satisfied_requests.push(req_id);
            }
        }

        for req_id in satisfied_requests {
            self.reconstruction_requests.remove(&req_id);
        }
    }

    fn select_bundles(&self, exclude: HashSet<BatchInfo>) -> Vec<(BundleIndex, (BitVec, BitVec))> {
        let prod = self.producer_data.as_ref().unwrap();
        let mut masked_bundles = vec![];

        for bundle in &prod.my_bundles {
            let payload = &bundle.data.payload;

            let mut proof_mask = BitVec::with_num_bits(payload.poas().len() as u16);
            let mut batch_mask = BitVec::with_num_bits(payload.num_opt_batches() as u16);

            for (i, poa) in payload.poas().iter().enumerate() {
                if !exclude.contains(poa.info()) && !prod.committed_batches.contains(poa.info()) {
                    proof_mask.set(i as u16);
                }
            }

            for (i, batch) in payload.sub_blocks().flatten().enumerate() {
                if !exclude.contains(batch) && !prod.committed_batches.contains(batch) {
                    batch_mask.set(i as u16);
                }
            }

            if proof_mask.count_ones() > 0 || batch_mask.count_ones() > 0 {
                masked_bundles.push((bundle.data.index, (proof_mask, batch_mask)));
            }
        }

        masked_bundles
    }

    fn reconstruct_block_data(
        &self,
        round: Round,
        author: NodeId,
        masked_bundles: Vec<(BundleIndex, (BitVec, BitVec))>,
        timestamp_usecs: u64,
        reason: RoundEntryReason,
    ) -> BlockData {
        let payloads =
            masked_bundles
                .clone()
                .into_iter()
                .map(|(index, (proof_mask, batch_mask))| {
                    (
                        self.bundles[&index].data.payload.clone(),
                        proof_mask,
                        batch_mask,
                    )
                });

        let payload = merge_payloads(round, author, payloads);

        BlockData {
            timestamp_usecs,
            payload,
            reason,
        }
    }

    async fn try_reconstruct(
        &self,
        block_header: &BlockHeader,
        request_timestamp: &Instant,
        ctx: &mut impl ContextFor<Self>,
    ) -> bool {
        let bundles_available = block_header
            .bundle_indices()
            .filter(|index| self.bundles.contains_key(&index))
            .count();

        if bundles_available != block_header.n_bundles() {
            self.logger.log_detail(format!(
                "Missing bundles for block {} proposed by node: {:?}: {}/{}",
                block_header.round(),
                block_header.author(),
                bundles_available,
                block_header.n_bundles(),
            ));

            return false;
        }

        OP_COUNTERS.observe_duration("bundler_wait", request_timestamp.elapsed());

        self.logger.log_detail(format!(
            "Reconstructing block {} proposed by node: {:?}",
            block_header.round(),
            block_header.author(),
        ));

        let block_data = monitor!(
            "reconstruct_block_received",
            self.reconstruct_block_data(
                block_header.round(),
                block_header.author(),
                block_header.masked_bundles().clone(),
                block_header.timestamp_usecs(),
                block_header.reason().clone(),
            )
        );

        if block_data.hash() == block_header.digest() {
            let block = Block {
                data: block_data,
                signature: block_header.signature().clone(),
                digest: block_header.digest(),
            };

            ctx.notify(self.consensus_module_id, BlockReconstructed { block })
                .await;

            true
        } else {
            warn!(
                "Digest mismatch for block {} proposed by node {}",
                block_header.round(),
                block_header.author(),
            );

            // Still return true to remove the request.
            true
        }
    }
}

impl Protocol for BundlerProtocol {
    type Message = Message;
    type TimerEvent = TimerEvent;

    protocol! {
        self: self;
        ctx: ctx;

        upon start {
            // The first bundle is created immediately.
            if self.producer_data.is_some() {
                ctx.set_timer(Duration::ZERO, TimerEvent::NewBundle(1));
            }
        };

        // Creating and certifying batches

        upon timer [TimerEvent::NewBundle(index)] {
            let prod = self.producer_data.as_mut().unwrap();

            assert!(prod.my_bundles.is_empty() || index == prod.my_bundles.back().unwrap().data.index + 1);
            assert!(prod.ongoing_payload_request.is_none());

            self.logger.log_detail(format!("Preparing payload for bundle #{} ...", index));

            prod.ongoing_payload_request = Some((index, Instant::now()));

            ctx.notify(
                self.dissemination_module_id,
                PreparePayload {
                    request_uid: index as u64,
                    round: None,
                    exclude_everywhere: prod.included_poas.clone(),
                    exclude_optimistic: prod.included_batches.clone(),
                    exclude_authors: None,
                }
            )
            .await;
        };

        upon event of type [PayloadReady] from [_] {
            upon [PayloadReady { request_uid, payload } ] {
                let prod = self.producer_data.as_mut().unwrap();

                let (index, ts) = prod.ongoing_payload_request.take().unwrap();
                assert_eq!(request_uid, index as u64);

                OP_COUNTERS.observe_duration("prepare_bundle", ts.elapsed());

                self.logger.log_detail(format!("Creating bundle #{} ...", index));

                if prod.my_bundles.len() >= self.config.bundle_window {
                    let preempted = prod.my_bundles.pop_front().unwrap();
                    self.logger.log_detail(format!(
                        "Preempting bundle #{} with digest {:#x}",
                        preempted.data.index, preempted.digest,
                    ));

                    for poa in preempted.data.payload.poas() {
                        prod.included_poas.remove(poa.info());
                    }
                    for batch in preempted.data.payload.sub_blocks().flatten() {
                        prod.included_batches.remove(batch);
                    }
                }

                for poa in payload.poas() {
                    let inserted = prod.included_poas.insert(poa.info().clone());
                    assert!(inserted);
                }

                for batch_info in payload.sub_blocks().flatten() {
                    let inserted = prod.included_batches.insert(batch_info.clone());
                    assert!(inserted);
                }

                let bundle_data = BundleData { payload, index };

                let digest = bundle_data.hash();
                let bundle = Bundle {
                    data: bundle_data,
                    digest,
                };

                self.logger.log_detail(format!(
                    "Created bundle #{} with {} PoAs, {} batches, digest {:#x}",
                    index,
                    bundle.payload().poas().len(),
                    bundle.payload().num_opt_batches(),
                    digest,
                ));

                OP_COUNTERS.observe(
                    "bundle_poas",
                    bundle.payload().poas().len() as f64,
                );
                OP_COUNTERS.observe(
                    "bundle_batches",
                    bundle.payload().poas().len() as f64,
                );

                prod.my_bundles.push_back(bundle.clone());
                self.on_new_bundle(self.node_id, bundle.clone(), ctx).await;

                ctx.multicast(Message::Bundle(bundle, duration_since_epoch().as_micros() as u64)).await;

                OP_COUNTERS.observe_duration("create_bundle", ts.elapsed());

                let timer_duration = max(
                    self.config.bundle_interval.saturating_sub(ts.elapsed()),
                    self.config.min_bundle_interval,
                );
                ctx.set_timer(timer_duration, TimerEvent::NewBundle(index + 1));
            };
        };

        upon receive [Message::Bundle(bundle, ts)] from [author] 'handler: {
            if author != self.shard_author {
                warn!("Unexpected sender: {}. Expected: {}", author, self.shard_author);
                break 'handler;
            }

            let index = bundle.data.index;

            if author == self.node_id {
                assert!(self.bundles.contains_key(&index));
                break 'handler;
            }

            if self.bundles.contains_key(&index) {
                warn!("Received a duplicate bundle #{} from author {}", index, author);
                break 'handler;
            }

            OP_COUNTERS.observe_duration(
                "bundle_message_delay",
                duration_since_epoch().saturating_sub(Duration::from_micros(ts)),
            );

            let _timer = OP_COUNTERS.timer("bundle_message_handler");

            self.logger.log_detail(
                format!(
                    "Received bundle #{} from author {} with digest {:#x}",
                    index,
                    author,
                    bundle.digest,
                )
            );

            self.on_new_bundle(author, bundle, ctx).await;
        };

        upon event of type [CreateBlock] from [_consensus_module] {
            upon [CreateBlock { round, timestamp_usecs, reason, exclude }] {
                let _timer = OP_COUNTERS.timer("create_block");

                // TODO: broken by moving to async `prepare_payload`.
                // if self.config.push_bundle_when_proposing {
                //     self.create_bundle(ctx).await;
                // }

                ctx.notify(
                    self.dissemination_module_id,
                    BlockPrepareTime {
                        round,
                        time: Instant::now(),
                    },
                )
                .await;

                let masked_bundles = monitor!("select_bundles", self.select_bundles(exclude));

                let block_data = monitor!(
                    "reconstruct_block_leader",
                    self.reconstruct_block_data(
                        round,
                        self.node_id,
                        masked_bundles.clone(),
                        timestamp_usecs,
                        reason.clone(),
                    )
                );

                let digest = block_data.hash();

                let block = Block {
                    data: block_data,
                    signature: self.signer.sign(&BlockSignatureData { digest }).unwrap(),
                    digest,
                };

                self.logger.log_detail(format!(
                    "Created block {} with {} bundles, {} PoAs, and {} opt batches",
                    round,
                    masked_bundles.len(),
                    block.payload().poas().len(),
                    block.payload().num_opt_batches(),
                ));

                OP_COUNTERS.observe("bundle_count", masked_bundles.len() as f64);

                let block_header = BlockHeader {
                    data: Arc::new(BlockHeaderData {
                        round,
                        author: self.node_id,
                        timestamp_usecs,
                        masked_bundles,
                        digest: block.digest,
                        reason,
                        signature: block.signature,
                    }),
                };

                ctx.notify(
                    self.consensus_module_id,
                    BlockCreated {
                        header: block_header,
                    },
                )
                .await;
            };
        };

        upon event of type [ReconstructBlock] from [_consensus_module] {
            upon [ReconstructBlock { block_header }] {
                assert_eq!(block_header.author(), self.shard_author);

                self.logger.log_detail(format!(
                    "Received a request to reconstruct block {} proposed by node {}",
                    block_header.round(),
                    block_header.author(),
                ));

                let author = block_header.author();
                let round = block_header.round();

                assert!(!self.reconstruction_requests.contains_key(&round));
                if self.reconstruction_requests.len() >= self.config.max_pending_requests_per_node {
                    let (_, (old_header, old_ts)) =
                        self.reconstruction_requests.first_key_value().unwrap();

                    let elapsed = old_ts.elapsed();

                    self.logger.log_detail(format!(
                        "Preempted request to reconstruct block {} proposed by node {} \
                        after waiting for {:.3}s ({:.2}Δ)",
                        old_header.round(),
                        old_header.author(),
                        elapsed.as_secs_f64(),
                        self.logger.to_deltas(elapsed),
                    ));

                    OP_COUNTERS.inc("reconstruction_preempted");
                }

                let ts = Instant::now();
                if !self.try_reconstruct(&block_header, &ts, ctx).await {
                    self.reconstruction_requests.insert(round, (block_header, ts));
                }
            };
        };

        upon event of type [NotifyCommit] from [_any_module] {
            upon [NotifyCommit { payloads, .. }] {
                let mut prod = self.producer_data.as_mut().unwrap();

                for payload in payloads {
                    for poa in payload.poas() {
                        prod.committed_batches.insert(poa.info().clone());
                    }
                    for batch in payload.sub_blocks().flatten() {
                        prod.committed_batches.insert(batch.clone());
                    }
                }
            };
        };

        // Logging and halting

        upon start {
            self.logger.log_detail("Started".to_string());
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };

        upon event of type [SetLoggingBaseTimestamp] from [_any_module] {
            upon [SetLoggingBaseTimestamp(base_timestamp)] {
                self.logger.log_detail(format!("Setting logging base timestamp to {:?}", base_timestamp));
                self.logger.logging_base_timestamp = Some(base_timestamp);
            };
        };

        upon event of type [Kill] from [_any_module] {
            upon [Kill()] {
                self.logger.log_detail("Halting by Kill event".to_string());
                ctx.halt();
            };
        };

        upon timer [TimerEvent::Status] {
            self.logger.log_detail(format!(
                "STATUS (shard):\n\
                \tpending reconstruction requests: {:?}",
                self.reconstruction_requests.len(),
            ));

            if let Some(prod) = &self.producer_data {
                self.logger.log_detail(format!(
                    "STATUS (producer):\n\
                    \tlast produced bundle index: {:?}\n\
                    \tongoing payload request index: {:?}\n\
                    \tongoing payload request elapsed: {:?}\n\
                    \tnumber of included PoAs: {}\n\
                    \tnumber of included opt. batches: {}\n\
                    \tnumber of committed batches: {}",
                    prod.my_bundles.back().map(|bundle| bundle.data.index),
                    prod.ongoing_payload_request.map(|(index, _)| index),
                    prod.ongoing_payload_request.map(|(_, ts)| ts.elapsed()),
                    prod.included_poas.len(),
                    prod.included_batches.len(),
                    prod.committed_batches.len(),
                ));
            }

            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };
    }

    fn name(&self) -> &str {
        "bundler"
    }
}

impl Drop for BundlerProtocol {
    fn drop(&mut self) {
        self.logger.log_detail("Halting by Drop".to_string());
    }
}
