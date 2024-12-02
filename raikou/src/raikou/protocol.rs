// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{network::Validate, ContextFor, NodeId, Protocol},
    leader_schedule::LeaderSchedule,
    metrics,
    metrics::Sender,
    protocol,
    raikou::{
        dissemination,
        dissemination::{
            DisseminationLayer, FullBlockAvailable, NewQCWithPayload, ProposalReceived,
        },
        types::*,
    },
    utils::kth_max_set::KthMaxSet,
};
use aptos_consensus_types::{common::Author, payload::BatchPointer};
use aptos_crypto::{bls12381::Signature, hash::CryptoHash, CryptoMaterialError, Genesis};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::{
    aggregate_signature::{AggregateSignature, PartialSignatures},
    validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};
use bitvec::vec::BitVec;
use defaultmap::DefaultBTreeMap;
use futures_channel::mpsc::UnboundedSender;
use itertools::Itertools;
use nanovec::NanoArrayBit;
use rand::prelude::SliceRandom;
use serde::{ser::SerializeTuple, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cmp::{max, max_by, max_by_key, min, Ordering},
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt::{Debug, Formatter},
    num::NonZeroU8,
    ops::Deref,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    // Consensus
    Propose(Block),
    QcVote(VoteData, Signature),
    CommitVote(SignedQC),
    Timeout(TimeoutData, Signature),
    AdvanceRound(Round, QC, RoundEnterReason),
    FetchReq(BlockHash),
    FetchResp(Block),
}

impl Debug for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Propose(block) => write!(f, "Propose({})", block.data.round),
            Message::QcVote(vote_data, _) => write!(f, "QcVote({})", vote_data.common_data.round),
            Message::CommitVote(signed_qc) => {
                write!(f, "CommitVote({})", signed_qc.qc.common_data.round)
            },
            Message::Timeout(timeout_data, _) => {
                write!(f, "Timeout({})", timeout_data.timeout_round)
            },
            Message::AdvanceRound(round, _, reason) => {
                write!(f, "AdvanceRound({:?}, {:?})", round, reason)
            },
            Message::FetchReq(block_hash) => write!(f, "FetchReq({})", block_hash),
            Message::FetchResp(block) => write!(f, "FetchResp({})", block.data.round),
        }
    }
}

impl Validate for Message {
    fn validate(&self, validator_verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            Message::Propose(block) => {
                block.verify(validator_verifier)?;
            },
            Message::QcVote(vote_data, signature) => {
                validator_verifier.verify(
                    vote_data.author,
                    &vote_data.signing_format(),
                    signature,
                )?;
            },
            Message::CommitVote(signed_qc) => {
                let SignedQC {
                    qc,
                    author,
                    signature,
                } = signed_qc;
                qc.verify(validator_verifier)?;
                validator_verifier.verify(*author, &qc.signing_format(), signature)?;
            },
            Message::AdvanceRound(round, qc, reason) => {
                if *round == 1 && qc.is_genesis() {
                    return Ok(());
                }
                qc.verify(validator_verifier)?;
                match reason {
                    RoundEnterReason::CC(cc) => {
                        cc.verify(validator_verifier)?;
                    },
                    RoundEnterReason::TC(tc) => {
                        tc.verify(validator_verifier)?;
                    },
                    _ => {},
                }
            },
            _ => {},
        }

        Ok(())
    }
}

#[derive(Clone)]
pub enum TimerEvent {
    // Consensus
    QcVote(Round),
    Timeout(Round),
    FetchBlock(Round, BlockHash, Vec<NodeId>),

    // Other
    EndOfRun,
    Status,
    RoundSync,
}

#[derive(Clone, Debug)]
pub enum CommitReason {
    CC,
    TwoChainRule,
    Indirect,
}

#[derive(Clone, Copy)]
pub struct Config<S> {
    pub n_nodes: usize,
    pub f: usize,
    pub storage_requirement: usize,
    pub leader_timeout: u32, // in deltas
    pub leader_schedule: S,
    pub delta: Duration,
    pub enable_commit_votes: bool,
    pub enable_round_entry_permission: bool,

    /// The time validator waits after receiving a block before voting for a QC for it
    /// if it doesn't have all the batches yet.
    pub extra_wait_before_qc_vote: Duration,
    pub extra_wait_before_commit_vote: Duration,

    pub block_fetch_multiplicity: usize,
    pub block_fetch_interval: Duration,

    pub round_sync_interval: Duration,

    pub status_interval: Duration,
    pub end_of_run: Instant,
}

impl<S: LeaderSchedule> Config<S> {
    fn leader(&self, round: Round) -> NodeId {
        (self.leader_schedule)(round)
    }

    fn quorum(&self) -> usize {
        // Using more general quorum formula that works not only for n = 3f+1,
        // but for any n >= 3f+1.
        (self.n_nodes + self.f) / 2 + 1
    }
}

pub struct Metrics {
    pub block_consensus_latency: Option<metrics::UnorderedSender<(Instant, f64)>>,
    pub batch_consensus_latency: Option<metrics::UnorderedSender<(Instant, f64)>>,
}

pub struct RaikouNode<S, DL> {
    node_id: NodeId,
    config: Config<S>,
    dissemination: DL,

    // Logging and metrics
    start_time: Instant,
    detailed_logging: bool,
    metrics: Metrics,
    block_create_time: BTreeMap<Round, Instant>,

    // Protocol state for the pseudocode
    r_ready: Round,                 // The highest round the node is ready to enter.
    enter_reason: RoundEnterReason, // The justification for entering the round r_read.
    r_allowed: Round,               // The highest round the node is allowed to enter.
    r_cur: Round,                   // The current round the node is in.
    r_timeout: Round,               // The highest round the node has voted to time out.
    last_qc_vote: SubBlockId,
    last_commit_vote: SubBlockId,
    qc_high: QC,
    committed_qc: QC,

    // Additional variables necessary for an efficient implementation

    // Set of already processed QCs.
    known_qcs: BTreeSet<SubBlockId>,

    // Map from a QC id to the list of blocks that wait for this QC to be satisfied.
    pending_blocks: DefaultBTreeMap<SubBlockId, Vec<BlockHash>>,

    // Set of blocks for which we have the full causal history available.
    satisfied_blocks: BTreeSet<BlockHash>,

    // Map from an unsatisfied block hash to the list of QCs for this block.
    pending_qcs: DefaultBTreeMap<BlockHash, Vec<QC>>,

    // Map from an unavailable block hash to the list of QCs for this block.
    qcs_without_blocks: DefaultBTreeMap<BlockHash, Vec<QC>>,

    // QCs for which we have the full causal history available.
    satisfied_qcs: BTreeSet<SubBlockId>,

    // QCs that are committed via direct commit votes, for which we do not yet have their full causal history available.
    qcs_to_commit: BTreeMap<SubBlockId, (QC, CommitReason)>,

    leader_proposal: BTreeMap<Round, BlockHash>,
    blocks: BTreeMap<BlockHash, Block>,
    available_prefix_cache: SubBlockId,
    // In practice, all votes should also include a signature.
    // In this prototype, signatures are omitted.
    qc_votes: DefaultBTreeMap<CommonData, BTreeMap<NodeId, (Prefix, Signature)>>,
    received_cc_vote: DefaultBTreeMap<Round, BTreeSet<NodeId>>,
    cc_votes: DefaultBTreeMap<Round, KthMaxSet<(SignedQC, NodeId)>>,
    tc_votes: DefaultBTreeMap<Round, BTreeMap<NodeId, (TimeoutData, Signature)>>,

    validator_verifier: Arc<ValidatorVerifier>,
    validator_signer: Arc<ValidatorSigner>,
    // ordered_nodes_tx: UnboundedSender<OrderedBlocks>,
}

impl<S: LeaderSchedule, DL: DisseminationLayer> RaikouNode<S, DL> {
    pub fn new(
        id: NodeId,
        config: Config<S>,
        dissemination: DL,
        start_time: Instant,
        detailed_logging: bool,
        metrics: Metrics,
        validator_verifier: Arc<ValidatorVerifier>,
        validator_signer: Arc<ValidatorSigner>,
        // ordered_nodes_tx: UnboundedSender<OrderedBlocks>,
    ) -> Self {
        let quorum = config.quorum();
        assert!(config.block_fetch_multiplicity <= quorum);

        RaikouNode {
            node_id: id,
            config: config.clone(),
            dissemination,
            start_time,
            detailed_logging,
            metrics,
            block_create_time: Default::default(),
            r_ready: 0,
            r_allowed: 0,
            enter_reason: RoundEnterReason::Genesis,
            r_cur: 0,
            last_qc_vote: (0, 0).into(),
            last_commit_vote: (0, 0).into(),
            r_timeout: 0,
            qc_high: QC::genesis(),
            committed_qc: QC::genesis(),
            known_qcs: Default::default(),
            pending_blocks: Default::default(),
            satisfied_blocks: Default::default(),
            pending_qcs: Default::default(),
            qcs_without_blocks: Default::default(),
            satisfied_qcs: Default::default(),
            qcs_to_commit: Default::default(),
            leader_proposal: Default::default(),
            blocks: Default::default(),
            available_prefix_cache: (0, 0).into(),
            qc_votes: Default::default(),
            received_cc_vote: Default::default(),
            cc_votes: DefaultBTreeMap::new(KthMaxSet::new(quorum)),
            tc_votes: Default::default(),
            validator_verifier,
            validator_signer,
            // ordered_nodes_tx,
        }
    }

    fn on_new_satisfied_block(&mut self, block_digest: BlockHash) {
        assert!(!self.satisfied_blocks.contains(&block_digest));

        self.satisfied_blocks.insert(block_digest.clone());
        if let Some(pending_qcs) = self.pending_qcs.remove(&block_digest) {
            for pending_qc in pending_qcs {
                self.on_new_satisfied_qc(pending_qc);
            }
        }
    }

    fn on_new_satisfied_qc(&mut self, qc: QC) {
        assert!(
            !self.satisfied_qcs.contains(&qc.sub_block_id()),
            "QC {:?} already satisfied",
            qc.sub_block_id()
        );

        self.satisfied_qcs.insert(qc.sub_block_id());

        if let Some(pending_blocks) = self.pending_blocks.remove(&qc.sub_block_id()) {
            for pending_block in pending_blocks {
                self.on_new_satisfied_block(pending_block);
            }
        }

        // Two-chain commit rule:
        // If there exists two adjacent certified blocks B and B' in the chain with consecutive
        // round numbers, i.e., B'.r = B.r + 1, the replica commits B and all its ancestors.
        if let Some(parent_qc) = self.blocks[&qc.common_data.hash].parent_qc() {
            if qc.common_data.round == parent_qc.common_data.round + 1 {
                if !self.qcs_to_commit.contains_key(&parent_qc.sub_block_id()) {
                    self.qcs_to_commit.insert(
                        parent_qc.sub_block_id(),
                        (parent_qc.clone(), CommitReason::TwoChainRule),
                    );
                }
            }
        }
    }

    async fn on_new_qc_with_available_block(
        &self,
        qc: QC,
        block: &Block,
        ctx: &mut impl ContextFor<Self>,
    ) {
        ctx.notify(self.dissemination.module_id(), NewQCWithPayload {
            payload: block.payload().clone(),
            qc,
        }).await;
    }

    async fn on_new_block(&mut self, block: &Block, ctx: &mut impl ContextFor<Self>) {
        if self.blocks.contains_key(&block.digest) {
            return;
        }

        for qc in self
            .qcs_without_blocks
            .remove(&block.digest)
            .unwrap_or_default()
        {
            self.on_new_qc_with_available_block(qc, block, ctx).await;
        }

        self.blocks.insert(block.digest.clone(), block.clone());
        let parent_qc = block.parent_qc().unwrap();

        if !self.known_qcs.contains(&parent_qc.sub_block_id()) {
            self.on_new_qc(parent_qc.clone(), ctx).await;
        }

        if self.satisfied_qcs.contains(&parent_qc.sub_block_id()) {
            self.on_new_satisfied_block(block.digest.clone());
        } else {
            self.pending_blocks[parent_qc.sub_block_id()].push(block.digest.clone());
        }
    }

    async fn on_new_qc(&mut self, new_qc: QC, ctx: &mut impl ContextFor<Self>) {
        if self.known_qcs.contains(&new_qc.sub_block_id()) {
            return;
        }

        // Update `qc_high`
        if new_qc > self.qc_high {
            self.qc_high = new_qc.clone();
        }

        // If new_qc.round > r_commit_vote and new_qc.round > r_timeout,
        // multicast a commit vote and update r_commit_vote.
        if self.config.enable_commit_votes {
            if new_qc.common_data.round > self.last_commit_vote.round
                && new_qc.common_data.round > self.r_timeout
            {
                self.last_commit_vote = new_qc.sub_block_id();
                let signature = new_qc.sign(&self.validator_signer).unwrap();
                let signed_qc =
                    SignedQC::new(new_qc.clone(), self.validator_signer.author(), signature);
                ctx.multicast(Message::CommitVote(signed_qc)).await;
            }
        }

        if new_qc.is_full() {
            // If form or receive a qc for the largest possible prefix of a round,
            // advance to the next round after that.
            self.advance_r_ready(
                new_qc.common_data.round + 1,
                RoundEnterReason::FullPrefixQC,
                ctx,
            )
            .await;
        }

        self.known_qcs.insert(new_qc.sub_block_id());

        if let Some(block) = self.blocks.get(&new_qc.common_data.hash) {
            self.on_new_qc_with_available_block(new_qc.clone(), block, ctx)
                .await;
        } else {
            self.qcs_without_blocks[new_qc.common_data.hash].push(new_qc.clone());
        }

        if self.satisfied_blocks.contains(&new_qc.common_data.hash) {
            self.on_new_satisfied_qc(new_qc);
        } else {
            if !self.pending_qcs.contains_key(&new_qc.common_data.hash) {
                ctx.set_timer(
                    Duration::ZERO,
                    TimerEvent::FetchBlock(
                        new_qc.common_data.round,
                        new_qc.common_data.hash,
                        new_qc.signers().collect(),
                    ),
                )
            }

            self.pending_qcs[new_qc.common_data.hash].push(new_qc);
        }
    }

    async fn advance_r_ready(
        &mut self,
        round: Round,
        reason: RoundEnterReason,
        ctx: &mut impl ContextFor<Self>,
    ) {
        if round > self.r_ready {
            self.r_ready = round;
            self.enter_reason = reason.clone();

            // Upon getting a justification to enter a higher round,
            // send it to the leader of that round.
            // NB: consider broadcasting to all the nodes instead.
            ctx.unicast(
                Message::AdvanceRound(round, self.qc_high.clone(), reason),
                self.config.leader(round),
            )
            .await;
        }
    }

    async fn available_prefix(&mut self) -> Prefix {
        assert!(self.leader_proposal.contains_key(&self.r_cur));

        let block_digest = &self.leader_proposal[&self.r_cur];
        let block = &self.blocks[block_digest];

        if self.available_prefix_cache.round != self.r_cur {
            self.available_prefix_cache = (self.r_cur, 0).into();
        }

        self.available_prefix_cache.prefix = self
            .dissemination
            .available_prefix(&block.payload(), self.available_prefix_cache.prefix)
            .await;

        self.available_prefix_cache.prefix
    }

    async fn commit_qc(&mut self, qc: QC, commit_reason: CommitReason) {
        let payloads = self.commit_qc_impl(qc, commit_reason);
        self.dissemination.notify_commit(payloads).await;
    }

    fn commit_qc_impl(&mut self, qc: QC, commit_reason: CommitReason) -> Vec<Payload> {
        if qc <= self.committed_qc {
            return vec![];
        }

        let parent = self.blocks[&qc.common_data.hash]
            .parent_qc()
            .unwrap()
            .clone();

        // Check for safety violations:
        if qc.common_data.round > self.committed_qc.common_data.round
            && parent.common_data.round < self.committed_qc.common_data.round
        {
            panic!("Safety violation: committed block was rolled back");
        }
        if parent.common_data.round == self.committed_qc.common_data.round
            && parent.prefix < self.committed_qc.prefix
        {
            panic!("Safety violation: optimistically committed transactions were rolled back");
        }

        // First commit the parent block.
        let mut res = self.commit_qc_impl(parent, CommitReason::Indirect);

        // Then, commit the transactions of this block.
        let block = &self.blocks[&qc.common_data.hash];

        if qc.common_data.round == self.committed_qc.common_data.round {
            // Extending the prefix of an already committed block.

            assert!(qc.prefix > self.committed_qc.prefix);

            self.log_detail(format!(
                "Extending the prefix of committed block {}: {} -> {} / {}{} ({:?})",
                qc.common_data.round,
                self.committed_qc.prefix,
                qc.prefix,
                block.n_sub_blocks(),
                if qc.is_full() { " (full)" } else { "" },
                commit_reason,
            ));

            res.push(
                block
                    .payload()
                    .take_sub_blocks(self.committed_qc.prefix..qc.prefix),
            );

            // Record the metrics
            let now = Instant::now();
            if self.config.leader(qc.common_data.round) == self.node_id {
                for _ in 0..(qc.prefix - self.committed_qc.prefix) {
                    self.metrics.batch_consensus_latency.push((
                        now,
                        self.to_deltas(now - self.block_create_time[&qc.common_data.round]),
                    ));
                }
            }
        } else {
            // Committing a new block.

            self.log_detail(format!(
                "Committing block {} proposed by node {} with {} ACs \
                and prefix {}/{} [{}/{} batches]{} ({:?}).",
                qc.common_data.round,
                self.config.leader(qc.common_data.round),
                block.acs().len(),
                qc.prefix,
                block.n_sub_blocks(),
                block
                    .sub_blocks()
                    .take(qc.prefix)
                    .map(|b| b.len())
                    .sum::<usize>(),
                block.sub_blocks().map(|b| b.len()).sum::<usize>(),
                if qc.is_full() { " (full)" } else { "" },
                commit_reason,
            ));

            res.push(block.payload().with_prefix(qc.prefix));

            // Record the metrics
            let now = Instant::now();
            if self.config.leader(qc.common_data.round) == self.node_id {
                self.metrics.block_consensus_latency.push((
                    now,
                    self.to_deltas(now - self.block_create_time[&qc.common_data.round]),
                ));
                for _ in 0..(block.acs().len() + qc.prefix) {
                    self.metrics.batch_consensus_latency.push((
                        now,
                        self.to_deltas(now - self.block_create_time[&qc.common_data.round]),
                    ));
                }
            }
        }

        // Finally, update the committed QC variable.
        self.committed_qc = qc;
        res
    }

    fn uncommitted_batches(&self, qc: &QC) -> HashSet<BatchHash> {
        let mut uncommitted = HashSet::new();

        let mut cur = qc;
        while cur.common_data.round != self.committed_qc.common_data.round {
            // assert!(self.blocks.contains_key(&cur.block_digest),
            //     "Block {:#x} not found for qc {:?}",
            //     cur.block_digest,
            //     cur.sub_block_id(),
            // );

            if !self.blocks.contains_key(&cur.common_data.hash) {
                aptos_logger::warn!(
                    "Deduplication failed for QC {:?}. Block from round {} is missing. \
                    This may often happen in an asynchronous network or a \
                    network where the triangle inequality doesn't hold.",
                    cur.sub_block_id(),
                    cur.common_data.round
                );
                return uncommitted;
            }

            let block = &self.blocks[&cur.common_data.hash];
            uncommitted.extend(block.acs().iter().map(|ac| ac.info().digest.clone()));
            uncommitted.extend(
                block
                    .sub_blocks()
                    .take(cur.prefix)
                    .flatten()
                    .map(|batch| batch.digest().clone()),
            );
            cur = block.parent_qc().unwrap();
        }

        if cur.prefix > self.committed_qc.prefix {
            let block = &self.blocks[&cur.common_data.hash];
            uncommitted.extend(
                block
                    .sub_blocks()
                    .take(cur.prefix)
                    .skip(self.committed_qc.prefix)
                    .flatten()
                    .map(|batch| batch.digest().clone()),
            );
        }

        uncommitted
    }

    fn n_sub_blocks_in_proposal(&self, round: Round) -> Prefix {
        assert!(self.leader_proposal.contains_key(&round));

        self.blocks[&self.leader_proposal[&round]].n_sub_blocks()
    }

    fn quorum(&self) -> usize {
        self.config.quorum()
    }

    fn to_deltas(&self, duration: Duration) -> f64 {
        duration.as_secs_f64() / self.config.delta.as_secs_f64()
    }

    fn time_in_delta(&self) -> f64 {
        self.to_deltas(Instant::now() - self.start_time)
    }

    fn log_info(&self, msg: String) {
        aptos_logger::info!(
            "Node {} at {:.2}Δ: Raikou: {}",
            self.node_id,
            self.time_in_delta(),
            msg
        );
    }

    fn log_detail(&self, msg: String) {
        if self.detailed_logging {
            self.log_info(msg);
        }
    }
}

impl<S, DL> Protocol for RaikouNode<S, DL>
where
    S: LeaderSchedule,
    DL: DisseminationLayer,
{
    type Message = Message;
    type TimerEvent = TimerEvent;

    protocol! {
        self: self;
        ctx: ctx;

        // Nodes start the protocol by entering round 1.
        upon start {
            // self.blocks.insert(BlockHash::genesis(), Block::genesis());
            let genesis_qc = QC::genesis();
            self.satisfied_blocks.insert(genesis_qc.common_data.hash);
            self.satisfied_qcs.insert(genesis_qc.sub_block_id());
            self.known_qcs.insert(genesis_qc.sub_block_id());
            self.advance_r_ready(1, RoundEnterReason::FullPrefixQC, ctx).await;
        };

        upon [
            self.r_cur < self.r_ready
            && (self.r_ready == self.r_allowed || !self.config.enable_round_entry_permission)
        ] {
            let round = self.r_ready;

            self.r_cur = round;

            self.log_detail(format!("Entering round {} by {:?}", round, self.enter_reason));

            if self.node_id == self.config.leader(round) {
                // Upon entering round r, the leader L_r multicasts a signed block
                // B = [r, parent_qc, cc, tc, acs, batches], where cc or tc is not ⊥
                // if the leader enters the round by forming or receiving a CC or TC
                // for round r-1 respectively.

                let parent_qc = self.qc_high.clone();

                let payload = self.dissemination.prepare_block(
                    round,
                    self.uncommitted_batches(&parent_qc),
                ).await;

                let block_data = BlockData {
                    round,
                    payload,
                    parent_qc: Some(parent_qc),
                    author: Some(self.validator_signer.author()),
                    reason: self.enter_reason.clone(),
                };

                let signature = block_data.sign(&self.validator_signer).unwrap();

                let block = Block {
                    digest: block_data.hash(),
                    data: block_data,
                    signature: Some(signature),
                };

                // self.leader_proposal.insert(round, digest.clone());
                // self.blocks.insert(digest, block.clone());

                self.log_detail(format!(
                    "Proposing block {} with {} ACs and {} sub-blocks",
                    round,
                    block.acs().len(),
                    block.n_sub_blocks(),
                ));

                self.block_create_time.insert(round, Instant::now());
                ctx.multicast(Message::Propose(block)).await;
            }

            // Upon entering round r, the node starts a timer for leader timeout.
            let timeout = self.config.leader_timeout * self.config.delta;
            ctx.set_timer(timeout, TimerEvent::Timeout(round));
        };

        // Upon receiving a valid block B = [r, parent_qc, cc, tc, acs, batches] from L_r
        // for the first time, if r >= r_cur and r > r_timeout, store the block,
        // execute on_new_qc and advance_round, start a timer for qc-vote,
        // and report missing batches to the leader.
        upon receive [Message::Propose(block)] from [leader] {
            if
                block.is_valid()
                && leader == self.config.leader(block.round())
                && !self.leader_proposal.contains_key(&block.round())
            {
                self.log_detail(format!(
                    "Received block {} proposed by node {}",
                    block.round(),
                    leader
                ));

                self.leader_proposal.insert(block.round(), block.digest.clone());
                self.on_new_block(&block, ctx).await;

                let BlockData { round, payload, author, reason, .. } = block.data;
                self.advance_r_ready(round, reason, ctx).await;

                let leader_account = author;
                ctx.notify(
                    self.dissemination.module_id(),
                    ProposalReceived { leader, leader_account, round, payload },
                ).await;

                if round < self.r_cur {
                    self.log_detail(format!(
                        "Ignoring proposal of block {} by node {} because already in round {}",
                        round,
                        leader,
                        self.r_cur,
                    ));
                } else if round <= self.r_timeout {
                    self.log_detail(format!(
                        "Ignoring proposal of block {} by node {} because already timed out round {}",
                        round,
                        leader,
                        self.r_timeout,
                    ));
                } else {
                    self.log_detail(format!(
                        "Processing proposal of block {} by node {}",
                        round,
                        leader,
                    ));

                    ctx.set_timer(self.config.extra_wait_before_qc_vote, TimerEvent::QcVote(round));
                }
            }
        };

        // A node issues a qc-vote in its current round r_cur up to 2 times:
        // 1. After a timeout after receiving the block,
        //    if not yet voted in this or greater round.
        // 2. When received all optimistically proposed batches.
        //
        // A node only qc-votes if r_cur > r_timeout.

        upon timer [TimerEvent::QcVote(round)] {
            if round == self.r_cur && self.last_qc_vote.round < round && round > self.r_timeout {
                let available_prefix = self.available_prefix().await;
                let n_sub_blocks = self.n_sub_blocks_in_proposal(round);

                self.log_detail(format!(
                    "QC-voting for block {} proposed by node {} by Timer with prefix {}/{}",
                    round,
                    self.config.leader(round),
                    available_prefix,
                    n_sub_blocks,
                ));

                self.last_qc_vote = (self.r_cur, available_prefix).into();
                let common_data = CommonData {
                    round,
                    hash: self.leader_proposal[&round].clone(),
                    size: self.n_sub_blocks_in_proposal(round),
                };
                let vote_data = VoteData {
                    author: self.validator_signer.author(),
                    common_data,
                    prefix: available_prefix,
                };
                let signature = vote_data.sign(&self.validator_signer).unwrap();
                ctx.multicast(Message::QcVote(vote_data, signature)).await;
            }
        };

        upon event of type [FullBlockAvailable] from [_dissemination_module] {
            upon [FullBlockAvailable { round }] {
                if round == self.r_cur {
                    let round = self.r_cur;
                    let digest = self.leader_proposal[&self.r_cur].clone();
                    let n_sub_blocks = self.n_sub_blocks_in_proposal(self.r_cur);

                    self.log_detail(format!(
                        "QC-voting for block {} proposed by node {} by Full Prefix with prefix {}",
                        round,
                        self.config.leader(round),
                        n_sub_blocks,
                    ));
                    self.last_qc_vote = (round, n_sub_blocks).into();

                    let common_data = CommonData {
                        round,
                        hash: digest.clone(),
                        size: n_sub_blocks,
                    };

                    let vote_data = VoteData {
                        author: self.validator_signer.author(),
                        common_data,
                        prefix: n_sub_blocks,
                    };

                    let signature = vote_data.sign(&self.validator_signer).unwrap();

                    ctx.multicast(Message::QcVote(vote_data, signature)).await;
                }
            };
        };

        // Upon receiving the block for round r_cur and a quorum of qc-votes for this block,
        // form a QC and execute on_new_qc if one of the two conditions hold:
        // 1. When it will be the first QC observed by the node in this round;
        // 2. When it will be the first full-prefix QC observed by the node in this round.

        upon receive [Message::QcVote(vote_data, signature)] from node [p] {
            let VoteData { author: _, common_data, prefix } = vote_data;
            let CommonData { round, hash: digest, size: n_sub_blocks } = common_data;
            if round >= self.r_cur {
                let common_data = CommonData { round, hash: digest.clone(), size: n_sub_blocks };
                self.qc_votes[common_data.clone()].insert(p, (prefix, signature));
                let votes = &self.qc_votes[common_data];
                let all_addresses = self.validator_verifier.get_ordered_account_addresses();
                let authors = votes.keys().map(|&v| all_addresses[v]).collect_vec();

                // A node forms a QC when it has received a quorum of votes
                // with matching block digest and n_sub_blocks and either:
                // 1. the node has not yet received or formed any QC for this round; or
                // 2. it can form a full-prefix QC.
                if self.validator_verifier.check_voting_power(authors.iter(), true).is_ok() {
                    let n_full_prefix_votes = votes.values().filter(|&&(vote, _)| vote == n_sub_blocks).count();
                    let cond_1 = self.qc_high.common_data.round < round;
                    let cond_2 = self.qc_high.sub_block_id() < (round, n_sub_blocks).into()
                        && n_full_prefix_votes >= self.config.storage_requirement;

                    if cond_1 || cond_2 {
                        // Take the quorum of the largest-prefix votes.
                        // todo: may need to change to be consistent with validator_verifier
                        let prefixes = votes
                            .iter()
                            .map(|(&node, &(prefix, _))| (node, prefix))
                            .sorted_by_key(|(_, prefix)| std::cmp::Reverse(*prefix))
                            .take(self.quorum())
                            .collect_vec();

                        // `certified_prefix` is the maximum number such that at least
                        // `storage_requirement` nodes have voted for a prefix of size
                        // `certified_prefix` or larger.
                        let certified_prefix = prefixes
                            .iter()
                            .skip(self.config.storage_requirement - 1)
                            .map(|(_, prefix)| *prefix)
                            .next()
                            .expect("storage_requirement cannot be bigger than the quorum size");

                        let mut partial_sigs = PartialSignatures::empty();
                        let authors = self.validator_verifier.get_ordered_account_addresses();
                        for (node, (_, signature)) in votes {
                            partial_sigs.add_signature(
                                authors[*node],
                                signature.clone(),
                            );
                        }

                        let aggregated_signature = self.validator_verifier.aggregate_signatures(partial_sigs.signatures_iter()).unwrap();
                        let prefix_set =
                            votes
                            .iter()
                            .map(|(node_id, (prefix, _signature))| (*node_id, *prefix))
                            .collect();
                        let signatures_with_prefixes = AggregateSignatureWithPrefixes::new(aggregated_signature, prefix_set);

                        let qc = QC {
                            common_data: CommonData {
                                round,
                                hash: digest,
                                size: n_sub_blocks,
                            },
                            prefix: certified_prefix,
                            signatures_with_prefixes,
                        };

                        self.on_new_qc(qc, ctx).await;
                    }
                }
            }
        };

        // Upon receiving a commit vote for a round-r qc from a node for the
        // first time, store it and execute on_new_qc.
        // Upon having gathered a quorum of commit votes, form a CC,
        // commit the smallest prefix, and execute advance_round.
        upon receive [Message::CommitVote(signed_qc)] from node [p] {
            let SignedQC { qc, author: _, signature } = signed_qc.clone();
            if !self.received_cc_vote[qc.common_data.round].contains(&p) {
                if !self.known_qcs.contains(&qc.sub_block_id()) {
                    self.on_new_qc(qc.clone(), ctx).await;
                }

                self.received_cc_vote[qc.common_data.round].insert(p);
                self.cc_votes[qc.common_data.round].insert((signed_qc, p));

                if let Some((committed_signed_qc, _)) = self.cc_votes[qc.common_data.round].kth_max() {
                    let committed_qc = committed_signed_qc.qc.clone();
                    // Form a CC each time we can commit something new, possibly several
                    // times for the same round.
                    if committed_qc > self.committed_qc {
                        let committed_qc = committed_qc.clone();

                        if !self.qcs_to_commit.contains_key(&committed_qc.sub_block_id()) {
                            self.qcs_to_commit.insert(
                                committed_qc.sub_block_id(),
                                (committed_qc, CommitReason::CC),
                            );
                        }

                        let signed_qcs = self.cc_votes[qc.common_data.round].k_max_set().iter().map(|(signed_qc, _)| signed_qc.clone()).collect_vec();

                        let mut partial_sigs = PartialSignatures::empty();
                        for signed_qc in signed_qcs.iter() {
                            partial_sigs.add_signature(
                                signed_qc.author,
                                signed_qc.signature.clone(),
                            );
                        }
                        let aggregated_signature = self.validator_verifier.aggregate_signatures(partial_sigs.signatures_iter()).unwrap();
                        let qcs = signed_qcs.iter().map(|signed_qc| signed_qc.qc.signing_format()).collect();
                        let signatures_with_qcs = AggregateSignatureWithQCs::new(aggregated_signature, qcs);
                        let min_prefix = signatures_with_qcs.min_prefix();
                        let max_prefix = signatures_with_qcs.max_prefix();

                        let cc = CC::new(
                            qc.common_data.round,
                            min_prefix,
                            max_prefix,
                            signatures_with_qcs,
                        );
                        self.advance_r_ready(qc.common_data.round + 1, RoundEnterReason::CC(cc), ctx).await;
                    }
                }
            }
        };

        upon [
            !self.qcs_to_commit.is_empty()
            && self.satisfied_qcs.contains(self.qcs_to_commit.keys().next().unwrap())
        ] {
            let (_, (qc, commit_reason)) = self.qcs_to_commit.pop_first().unwrap();
            self.commit_qc(qc, commit_reason).await;
        };

        // When the timeout expires, multicast a signed timeout message
        // with qc_high attached.
        upon timer [TimerEvent::Timeout(round)] {
            if round == self.r_cur {
                self.r_timeout = round;
                let timeout_data = TimeoutData {
                    author: self.validator_signer.author(),
                    timeout_round: round,
                    prefix: self.qc_high.prefix,
                    qc_high: self.qc_high.clone(),
                };
                let signature = timeout_data.sign(&self.validator_signer).unwrap();
                ctx.multicast(Message::Timeout(timeout_data, signature)).await;
            }
        };

        // Upon receiving a valid timeout message, execute on_new_qc.
        // Upon gathering a quorum of matching timeout messages,
        // form the TC and execute advance_round.
        upon receive [Message::Timeout(timeout_data, signature)] from node [p] {
            let TimeoutData { author: _, timeout_round: round, prefix: _, qc_high: qc } = timeout_data.clone();
            self.tc_votes[round].insert(p, (timeout_data, signature));
            self.on_new_qc(qc, ctx).await;

            let all_addresses = self.validator_verifier.get_ordered_account_addresses();
            let authors = self.tc_votes[round].keys().map(|&v| all_addresses[v]).collect_vec();

            if self.validator_verifier.check_voting_power(authors.iter(), true).is_ok(){
                let mut partial_sigs = PartialSignatures::empty();
                let authors = self.validator_verifier.get_ordered_account_addresses();
                for (node, (_, signature)) in self.tc_votes[round].iter() {
                    partial_sigs.add_signature(
                        authors[*node],
                        signature.clone(),
                    );
                }
                let aggregated_signature = self.validator_verifier.aggregate_signatures(partial_sigs.signatures_iter()).unwrap();
                let timeouts = self.tc_votes[round].iter().map(|(_, (timeout_data, _))| timeout_data.signing_format()).collect();
                let signatures_with_timeouts = AggregateSignatureWithTimeouts::new(aggregated_signature, timeouts);

                let max_vote = signatures_with_timeouts.max_vote();

                let tc = TC::new(
                    round,
                    max_vote,
                    signatures_with_timeouts,
                );
                self.advance_r_ready(round + 1, RoundEnterReason::TC(tc), ctx).await;
            }
        };

        // Upon receiving an AdvanceRound message, execute on_new_qc and advance_round.
        upon receive [Message::AdvanceRound(round, qc, reason)] from [_any_node] {
            self.on_new_qc(qc, ctx).await;
            self.advance_r_ready(round, reason, ctx).await;
        };

        // Block fetching

        upon timer event [TimerEvent::FetchBlock(block_round, digest, qc_signers)] {
            if !self.blocks.contains_key(&digest) {
                let sample = qc_signers.choose_multiple(
                    &mut rand::thread_rng(),
                    self.config.block_fetch_multiplicity,
                ).collect_vec();

                self.log_detail(format!(
                    "Fetching block {} ({:#x}) from nodes {:?}",
                    block_round,
                    digest,
                    sample,
                ));

                for node in sample {
                    ctx.unicast(Message::FetchReq(digest.clone()), *node).await;
                }

                ctx.set_timer(
                    self.config.block_fetch_interval,
                    TimerEvent::FetchBlock(block_round, digest, qc_signers),
                );
            }
        };

        upon receive [Message::FetchReq(digest)] from [p] {
            if let Some(block) = self.blocks.get(&digest) {
                self.log_detail(format!(
                    "Sending block {} ({:#x}) to {}",
                    block.round(),
                    digest,
                    p,
                ));

                ctx.unicast(Message::FetchResp(block.clone()), p).await;
            } else {
                aptos_logger::warn!("Received FetchReq for unknown block {:#x}", digest);
            }
        };

        upon receive [Message::FetchResp(block)] from [_any_node] {
            self.on_new_block(&block, ctx).await;
        };

        // State sync

        upon start {
            ctx.set_timer(self.config.round_sync_interval, TimerEvent::RoundSync);
        };

        // To tolerate message loss during asynchronous periods, nodes periodically
        // broadcast their current round with the proof that they have a valid reason
        // to enter it and the highest QC they have seen.
        // Additionally, if the node has voted to time out the current round,
        // it repeats the timeout message.
        upon timer event [TimerEvent::RoundSync] {
            ctx.multicast(Message::AdvanceRound(
                self.r_ready,
                self.qc_high.clone(),
                self.enter_reason.clone(),
            )).await;

            if self.r_timeout == self.r_cur {
                let timeout_data = TimeoutData {
                    author: self.validator_signer.author(),
                    timeout_round: self.r_cur,
                    prefix: self.qc_high.prefix,
                    qc_high: self.qc_high.clone(),
                };
                let signature = timeout_data.sign(&self.validator_signer).unwrap();
                ctx.multicast(Message::Timeout(timeout_data, signature)).await;
            }

            ctx.set_timer(self.config.round_sync_interval, TimerEvent::RoundSync);
        };

        // Logging and halting

        upon start {
            self.log_detail("Started".to_string());
            ctx.set_timer(self.config.end_of_run - Instant::now(), TimerEvent::EndOfRun);
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };

        upon timer [TimerEvent::EndOfRun] {
            self.log_detail("Halting".to_string());
            ctx.notify(self.dissemination.module_id(), dissemination::Kill()).await;
            ctx.halt();
        };

        upon timer [TimerEvent::Status] {
            if self.detailed_logging {
                self.log_info(format!(
                    "STATUS:\n\
                    \tRound: {}\n\
                    \tr_cur: {}\n\
                    \tr_ready: {}\n\
                    \tr_allowed: {}\n\
                    \tr_timeout: {}\n\
                    \tqc_high: {:?}\n\
                    \tcommitted_qc: {:?}\n\
                    \tqcs_to_commit.len(): {}\n\
                    \tqcs_to_commit.first(): {:?}\n\
                    \tqcs_to_commit.last(): {:?}\n\
                    \tlast satisfied qc: {:?}\n\
                    \tnum of qc votes: {:?}\n\
                    \tnum of cc votes: {:?}\n\
                    \tnum of tc votes: {:?}\n",
                    self.r_cur,
                    self.r_cur,
                    self.r_ready,
                    self.r_allowed,
                    self.r_timeout,
                    self.qc_high.sub_block_id(),
                    self.committed_qc.sub_block_id(),
                    self.qcs_to_commit.len(),
                    self.qcs_to_commit.first_key_value().map(|(k, _)| k),
                    self.qcs_to_commit.last_key_value().map(|(k, _)| k),
                    self.satisfied_qcs.last(),
                    self.qc_votes.iter().filter(|(common_data, _)| common_data.round == self.r_cur).map(|(_, v)| v.len()).collect_vec(),
                    self.received_cc_vote.get(self.r_cur).len(),
                    self.tc_votes.get(self.r_cur).len(),
                ));
            }
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };
    }
}
