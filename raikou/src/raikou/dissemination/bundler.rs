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
            NoopVerifier,
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
            DisseminationLayer, FullBlockAvailable, Kill, Metrics, NewQCWithPayload,
            ProposalReceived, SetLoggingBaseTimestamp,
        },
        protocol,
        types::*,
    },
};
use anyhow::{ensure, Context};
use aptos_bitvec::BitVec;
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, Genesis};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_logger::warn;
use defaultmap::DefaultBTreeMap;
use itertools::{traits::IteratorIndex, Itertools};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    future::Future,
    ops::Range,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime},
};
use tokio::{sync::RwLock, time::Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderData {
    round: Round,
    author: NodeId,
    timestamp_usecs: u64,
    bundles: Range<usize>,
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
        bundles: Range<usize>,
        digest: HashValue,
        reason: RoundEntryReason,
        signature: Signature,
    ) -> Self {
        Self {
            data: Arc::new(BlockHeaderData {
                round,
                author,
                timestamp_usecs,
                bundles,
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

    pub fn bundles(&self) -> &Range<usize> {
        &self.data.bundles
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
    index: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    Bundle(Bundle),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Bundle(bundle) => {
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

impl MessageVerifier<Message> for protocol::Verifier {
    async fn verify(&self, sender: NodeId, message: &Message) -> anyhow::Result<()> {
        match message {
            Message::Bundle(bundle) => monitor!("verify_bundle", {
                // TODO: verify payload size.

                bundle.data.payload.verify(self, None, sender)
            }),
        }
    }
}

#[derive(Clone)]
pub enum TimerEvent {
    NewBundle(usize),
    Status,
}

#[derive(Clone)]
pub struct Config {
    pub module_id: ModuleId,
    pub n_nodes: usize,
    // pub f: usize,
    // pub poa_quorum: usize,
    pub delta: Duration,
    pub bundle_window: usize,
    pub bundle_store_window: usize,
    pub bundle_interval: Duration,
    pub max_pending_requests_per_node: usize,
    // pub batch_fetch_interval: Duration,
    // pub batch_fetch_multiplicity: usize,
    // pub enable_optimistic_dissemination: bool,
    // pub enable_penalty_tracker: bool,
    // pub penalty_tracker_report_delay: Duration,
    pub status_interval: Duration,
    // pub block_size_limit: BlockSizeLimit,
    pub push_bundle_when_proposing: bool,
}

#[derive(Clone)]
pub struct Bundler<DL> {
    config: Config,
    inner: Arc<tokio::sync::Mutex<BundlerProtocol<DL>>>,
}

impl<DL: DisseminationLayer> Bundler<DL> {
    pub fn new(
        node_id: NodeId,
        config: Config,
        consensus_module_id: ModuleId,
        detailed_logging: bool,
        // metrics: Metrics,
        signer: Signer,
        // sig_verifier: SignatureVerifier,
        dissemination: Arc<DL>,
    ) -> Self {
        Self {
            config: config.clone(),
            inner: Arc::new(tokio::sync::Mutex::new(BundlerProtocol::new(
                node_id,
                config,
                consensus_module_id,
                detailed_logging,
                // metrics,
                signer,
                // sig_verifier,
                dissemination,
            ))),
        }
    }

    pub fn protocol(
        &self,
    ) -> Arc<tokio::sync::Mutex<impl Protocol<Message = Message, TimerEvent = TimerEvent>>> {
        self.inner.clone()
    }
}

pub struct BundlerProtocol<DL> {
    node_id: NodeId,
    config: Config,
    dissemination: Arc<DL>,
    consensus_module_id: ModuleId,

    my_bundles: VecDeque<Bundle>,
    included_poas: HashSet<BatchInfo>,
    included_batches: HashSet<BatchInfo>,

    reconstruction_requests: Vec<BTreeMap<Round, (BlockHeader, Instant)>>,

    bundles: Vec<BTreeMap<usize, Bundle>>,

    // Crypto
    signer: Signer,
    // sig_verifier: SignatureVerifier,

    // Logging and metrics
    detailed_logging: bool,
    logging_base_timestamp: Option<SystemTime>,
    // metrics: Metrics,
}

impl<DL> BundlerProtocol<DL> {
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
            "Node {} at {}: Dissemination Layer: {}",
            self.node_id,
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

impl<DL: DisseminationLayer> BundlerProtocol<DL> {
    pub fn new(
        node_id: NodeId,
        config: Config,
        consensus_module_id: ModuleId,
        detailed_logging: bool,
        // metrics: Metrics,
        signer: Signer,
        // sig_verifier: SignatureVerifier,
        dissemination: Arc<DL>,
    ) -> Self {
        let n_nodes = config.n_nodes;

        Self {
            config,
            node_id,
            consensus_module_id,
            my_bundles: Default::default(),
            included_poas: Default::default(),
            included_batches: Default::default(),
            reconstruction_requests: vec![BTreeMap::new(); n_nodes],
            bundles: vec![BTreeMap::new(); n_nodes],
            signer,
            // sig_verifier,
            detailed_logging,
            logging_base_timestamp: None,
            // metrics,
            dissemination,
        }
    }

    async fn create_bundle(&mut self, ctx: &mut impl ContextFor<Self>) {
        monitor!("create_bundle", self.create_bundle_impl(ctx).await);
    }

    async fn create_bundle_impl(&mut self, ctx: &mut impl ContextFor<Self>) {
        let index = if let Some(last_bundle) = self.my_bundles.back() {
            last_bundle.data.index + 1
        } else {
            1
        };

        // Schedule the next bundle.
        ctx.set_timer(
            self.config.bundle_interval,
            TimerEvent::NewBundle(index + 1),
        );

        self.log_detail(format!("Creating bundle #{} ...", index));

        if self.my_bundles.len() >= self.config.bundle_window {
            let preempted = self.my_bundles.pop_front().unwrap();
            self.log_detail(format!(
                "Preempting bundle #{} with digest {:#x}",
                preempted.data.index, preempted.digest,
            ));

            for poa in preempted.data.payload.poas() {
                self.included_poas.remove(poa.info());
            }
            for batch in preempted.data.payload.sub_blocks().flatten() {
                self.included_batches.remove(batch);
            }
        }

        let payload = monitor!("prepare_bundle", {
            self.dissemination
                .prepare_payload(
                    None,
                    // NB: these clones are unnecessary and expensive.
                    self.included_poas.clone(),
                    self.included_batches.clone(),
                    None,
                )
                .await
        });

        for poa in payload.poas() {
            let inserted = self.included_poas.insert(poa.info().clone());
            assert!(inserted);
        }

        for batch_info in payload.sub_blocks().flatten() {
            let inserted = self.included_batches.insert(batch_info.clone());
            assert!(inserted);
        }

        let bundle_data = BundleData { payload, index };

        let digest = bundle_data.hash();
        let bundle = Bundle {
            data: bundle_data,
            digest,
        };

        self.log_detail(format!(
            "Created bundle #{} with digest {:#x}, {} PoAs, {} batches",
            index,
            digest,
            bundle.data.payload.poas().len(),
            bundle
                .data
                .payload
                .sub_blocks()
                .map(|sub_block| sub_block.len())
                .sum::<usize>(),
        ));
        self.my_bundles.push_back(bundle.clone());
        ctx.multicast(Message::Bundle(bundle)).await;
    }

    fn reconstruct_block_data(
        &self,
        round: Round,
        author: NodeId,
        bundles: Range<usize>,
        timestamp_usecs: u64,
        reason: RoundEntryReason,
    ) -> BlockData {
        let payloads = bundles
            .clone()
            .into_iter()
            .map(|index| self.bundles[author][&index].data.payload.clone());

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
            .bundles()
            .clone()
            .into_iter()
            .filter(|index| self.bundles[block_header.author()].contains_key(&index))
            .count();

        if bundles_available != block_header.bundles().len() {
            self.log_detail(format!(
                "Missing bundles for block {} proposed by node: {:?}: {}/{}",
                block_header.round(),
                block_header.author(),
                bundles_available,
                block_header.bundles().len(),
            ));

            return false;
        }

        OP_COUNTERS.observe_duration("bundler_wait", request_timestamp.elapsed());

        self.log_detail(format!(
            "Reconstructing block {} proposed by node: {:?}",
            block_header.round(),
            block_header.author(),
        ));

        let block_data = monitor!(
            "reconstruct_block_received",
            self.reconstruct_block_data(
                block_header.round(),
                block_header.author(),
                block_header.bundles().clone(),
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

impl<DL: DisseminationLayer> Protocol for BundlerProtocol<DL> {
    type Message = Message;
    type TimerEvent = TimerEvent;

    protocol! {
        self: self;
        ctx: ctx;

        upon start {
            // The first bundle is created immediately.
            self.create_bundle(ctx).await;
        };

        // Creating and certifying batches

        upon timer [TimerEvent::NewBundle(index)] {
            if let Some(last_bundle) = self.my_bundles.back() {
                if last_bundle.data.index < index {
                    assert_eq!(index, last_bundle.data.index + 1);
                    self.create_bundle(ctx).await;
                }
            }
        };

        // Upon receiving a batch, store it, reply with a BatchStored message,
        // and execute try_vote.
        upon receive [Message::Bundle(bundle)] from [author] {
            let index = bundle.data.index;

            if self.bundles[author].contains_key(&index) {
                warn!("Received a duplicate bundle #{} from author {}", index, author);
                return;
            }

            self.log_detail(
                format!(
                    "Received bundle #{} with digest {:#x} from author {}",
                    index,
                    bundle.digest,
                    author,
                )
            );

            // Remove old bundles from this author.
            loop {
                let Some((&first_index, _)) = self.bundles[author].first_key_value() else {
                    break;
                };

                if first_index + self.config.bundle_store_window < index {
                    self.bundles[author].pop_first();
                } else {
                    break;
                }
            }

            self.bundles[author].insert(index, bundle);

            let mut satisfied_requests = vec![];
            for (&req_id, (block_header, ts)) in &self.reconstruction_requests[author] {
                if self.try_reconstruct(block_header, ts, ctx).await {
                    satisfied_requests.push(req_id);
                }
            }

            for req_id in satisfied_requests {
                self.reconstruction_requests[author].remove(&req_id);
            }
        };

        upon event of type [CreateBlock] from [_consensus_module] {
            upon [CreateBlock { round, timestamp_usecs, reason }] {
                assert!(!self.my_bundles.is_empty());

                if self.config.push_bundle_when_proposing {
                    self.create_bundle(ctx).await;
                }

                let from = self.my_bundles.front().unwrap().data.index;
                let to = self.my_bundles.back().unwrap().data.index;
                let bundles = from..(to + 1);

                let block_data = monitor!(
                    "reconstruct_block_leader",
                    self.reconstruct_block_data(
                        round,
                        self.node_id,
                        bundles.clone(),
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

                self.log_detail(format!(
                    "Created block {} with {} ACs and {} sub-blocks",
                    round,
                    block.poas().len(),
                    N_SUB_BLOCKS,
                ));

                let block_header = BlockHeader {
                    data: Arc::new(BlockHeaderData {
                        round,
                        author: self.node_id,
                        timestamp_usecs,
                        bundles,
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
                self.log_detail(format!(
                    "Received a request to reconstruct block {} proposed by node {}",
                    block_header.round(),
                    block_header.author(),
                ));

                let author = block_header.author();
                let round = block_header.round();

                assert!(!self.reconstruction_requests[author].contains_key(&round));
                if self.reconstruction_requests[author].len() >= self.config.max_pending_requests_per_node {
                    let (_, (old_header, old_ts)) =
                        self.reconstruction_requests[author].first_key_value().unwrap();

                    let elapsed = old_ts.elapsed();

                    self.log_detail(format!(
                        "Preempted request to reconstruct block {} proposed by node {} \
                        after waiting for {:.3}s ({}Δ)",
                        old_header.round(),
                        old_header.author(),
                        elapsed.as_secs_f64(),
                        self.to_deltas(elapsed),
                    ));

                    OP_COUNTERS.inc("reconstruction_preempted");
                }

                let ts = Instant::now();
                if !self.try_reconstruct(&block_header, &ts, ctx).await {
                    self.reconstruction_requests[author].insert(round, (block_header, ts));
                }
            };
        };

        // Logging and halting

        upon start {
            self.log_detail("Started".to_string());
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };

        upon event of type [SetLoggingBaseTimestamp] from [_any_module] {
            upon [SetLoggingBaseTimestamp(base_timestamp)] {
                self.log_detail(format!("Setting logging base timestamp to {:?}", base_timestamp));
                self.logging_base_timestamp = Some(base_timestamp);
            };
        };

        upon event of type [Kill] from [_any_module] {
            upon [Kill()] {
                self.log_detail("Halting by Kill event".to_string());
                ctx.halt();
            };
        };

        upon timer [TimerEvent::Status] {
            self.log_detail(format!(
                "STATUS:\n\
                \tlast produced bundle index: {:?}\n",
                self.my_bundles.back().map(|bundle| bundle.data.index),
            ));
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };
    }
}

impl<DL> Drop for BundlerProtocol<DL> {
    fn drop(&mut self) {
        self.log_detail("Halting by Drop".to_string());
    }
}
