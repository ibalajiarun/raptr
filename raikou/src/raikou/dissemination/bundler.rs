// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{
        crypto,
        crypto::{dummy_signature, SignatureVerifier, Signer},
        module_network::ModuleId,
        network::{MessageCertifier, MessageVerifier, NetworkSender, NetworkService},
        timer::TimerService,
        ContextFor, NodeId, Protocol,
    },
    metrics,
    metrics::Sender,
    protocol,
    raikou::{
        dissemination::{
            DisseminationLayer, FullBlockAvailable, Kill, Metrics, NewQCWithPayload,
            ProposalReceived,
        },
        types::*,
    },
};
use anyhow::Context;
use aptos_bitvec::BitVec;
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, Genesis};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use defaultmap::DefaultBTreeMap;
use itertools::Itertools;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    future::Future,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime},
};
use std::any::Any;
use std::ops::{RangeInclusive, RangeToInclusive};
use tokio::{sync::RwLock, time::Instant};
use aptos_logger::warn;
use crate::framework::module_network::ModuleEventTrait;
use crate::framework::network::{NoopCertifier, NoopVerifier};



pub struct BlockHeader {
    pub bundles: RangeInclusive<usize>,
    pub digest: Signature,
}

/// Event sent by the consensus module to the dissemination layer to notify of a new block.
#[derive(Debug)]
pub struct ReconstructBlock {
    pub leader: NodeId,
    pub round: Round,
    pub payload: Payload,
}

impl ModuleEventTrait for crate::raikou::dissemination::ProposalReceived {
    fn as_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
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
                write!(f, "Bundle({}, {})", bundle.data.payload.author(), bundle.data.index)
            },
        }
    }
}

pub type Certifier = NoopCertifier<Message>;

pub type Verifier = NoopVerifier<Message>;

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
    // pub batch_fetch_interval: Duration,
    // pub batch_fetch_multiplicity: usize,
    // pub enable_optimistic_dissemination: bool,
    // pub enable_penalty_tracker: bool,
    // pub penalty_tracker_report_delay: Duration,
    pub status_interval: Duration,
    // pub block_size_limit: BlockSizeLimit,
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
        dissemination: DL,
    ) -> Self {
        Self {
            config: config.clone(),
            inner: Arc::new(tokio::sync::Mutex::new(BundlerProtocol::new(
                node_id,
                config,
                consensus_module_id,
                detailed_logging,
                // metrics,
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
    dissemination: DL,
    consensus_module_id: ModuleId,

    my_bundles: VecDeque<Bundle>,
    included_poas: HashSet<BatchInfo>,
    included_batches: HashSet<BatchInfo>,

    bundles: Vec<BTreeMap<usize, Bundle>>,

    // Logging and metrics
    detailed_logging: bool,
    first_committed_block_timestamp: Option<SystemTime>,
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
                    .duration_since(self.first_committed_block_timestamp?)
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
        dissemination: DL,
    ) -> Self {
        let n_nodes = config.n_nodes;

        Self {
            config,
            node_id,
            consensus_module_id,
            my_bundles: Default::default(),
            included_poas: Default::default(),
            included_batches: Default::default(),
            bundles: vec![BTreeMap::new(); n_nodes],
            detailed_logging,
            first_committed_block_timestamp: None,
            // metrics,
            dissemination,
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
            // The first batch is sent immediately.
            ctx.set_timer(Duration::ZERO, TimerEvent::NewBundle(1));
        };

        // Creating and certifying batches

        upon timer [TimerEvent::NewBundle(index)] {
            // Reset the timer.
            ctx.set_timer(self.config.bundle_interval, TimerEvent::NewBundle(index + 1));

            self.log_detail(format!("Creating bundle #{} ...", index));

            if self.my_bundles.len() >= self.config.bundle_window {
                let preempted = self.my_bundles.pop_front().unwrap();
                self.log_detail(format!(
                    "Preempting bundle #{} with digest {:#x}",
                    preempted.data.index,
                    preempted.digest,
                ));

                for poa in preempted.data.payload.poas() {
                    self.included_poas.remove(poa.info());
                }
                for batch in preempted.data.payload.sub_blocks().flatten() {
                    self.included_batches.remove(batch);
                }
            }


            let payload = self.dissemination.prepare_block(
                777,
                // NB: these clones are unnecessary and expensive.
                self.included_poas.clone(),
                self.included_batches.clone(),
                None,
            )
            .await;

            for poa in payload.poas() {
                let inserted = self.included_poas.insert(poa.info().clone());
                assert!(inserted);
            }

            for batch_info in payload.sub_blocks().flatten() {
                let inserted = self.included_batches.insert(batch_info.clone());
                assert!(inserted);
            }

            let bundle_data = BundleData {
                payload,
                index,
            };

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
                bundle.data.payload.sub_blocks().map(|sub_block| sub_block.len()).sum::<usize>(),
            ));
            self.my_bundles.push_back(bundle.clone());
            ctx.multicast(Message::Bundle(bundle)).await;
        };

        // Upon receiving a batch, store it, reply with a BatchStored message,
        // and execute try_vote.
        upon receive [Message::Bundle(bundle)] from [author_id] {
            let index = bundle.data.index;

            if self.bundles[author_id].contains_key(&index) {
                warn!("Received a duplicate bundle #{} from author {}", index, author_id);
                return;
            }

            self.log_detail(
                format!(
                    "Received bundle #{} with digest {:#x} from author {}",
                    index,
                    bundle.digest,
                    author_id,
                )
            );

            // Remove old bundles from this author.
            loop {
                let Some((&first_index, _)) = self.bundles[author_id].first_key_value() else {
                    break;
                };

                if first_index + self.config.bundle_store_window < index {
                    self.bundles[author_id].pop_first();
                } else {
                    break;
                }
            }

            self.bundles[author_id].insert(index, bundle);
        };

        // Logging and halting

        upon start {
            self.log_detail("Started".to_string());
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
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
