// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp::{max, max_by, max_by_key, min, Ordering},
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt::{Debug, Formatter},
    sync::Arc,
    time::Duration,
};

use bitvec::vec::BitVec;
use defaultmap::DefaultBTreeMap;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    framework::{ContextFor, NodeId, Protocol},
    leader_schedule::LeaderSchedule,
    metrics,
    metrics::Sender,
    protocol,
    raikou::{
        dissemination,
        dissemination::{BlockReceived, DisseminationLayer},
        types::*,
    },
    utils::kth_max_set::KthMaxSet,
};

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct Block {
    pub round: Round,
    pub payload: Payload,
    pub parent_qc: Option<QC>, // `None` only for the genesis block.
    pub reason: RoundEnterReason,
    pub digest: BlockHash,
}

impl Block {
    pub fn genesis() -> Self {
        Block {
            round: 0,
            payload: Payload::empty(-1, 999999999),
            parent_qc: None,
            reason: RoundEnterReason::Genesis,
            digest: BlockHash::genesis(),
        }
    }

    pub fn n_sub_blocks(&self) -> usize {
        self.payload.sub_blocks().len()
    }

    pub fn sub_block(&self, index: usize) -> &[BatchInfo] {
        &self.payload.sub_blocks()[index]
    }

    pub fn acs(&self) -> &Vec<AC> {
        self.payload.acs()
    }

    pub fn sub_blocks(&self) -> &[Vec<BatchInfo>] {
        self.payload.sub_blocks()
    }

    pub fn is_genesis(&self) -> bool {
        self.round == 0
    }

    /// A non-genesis block is considered valid if:
    /// 1. It contains a valid multi-signature (omitted in the prototype);
    /// 2. It contains a valid parent QC;
    /// 3. At least one of the three conditions hold:
    ///    - `parent_qc.round == round - 1` and `parent_qc.is_full()`;
    ///    - `cc` is not None, `cc.round == round - 1`, and `parent_qc.id() >= cc.highest_qc_id()`.
    ///    - `tc` is not None, `cc.round == round - 1`, and `parent_qc.id() >= tc.highest_qc_id()`.
    pub fn is_valid(&self) -> bool {
        // TODO: add digest verification.

        if self.is_genesis() {
            return true;
        }

        let Some(parent_qc) = &self.parent_qc else {
            return false;
        };

        match &self.reason {
            RoundEnterReason::Genesis => false, // Should not be used in a non-genesis block.
            RoundEnterReason::FullPrefixQC => {
                parent_qc.round == self.round - 1 && parent_qc.is_full()
            },
            RoundEnterReason::CC(cc) => {
                cc.round == self.round - 1 && parent_qc.sub_block_id() >= cc.highest_qc_id()
            },
            RoundEnterReason::TC(tc) => {
                tc.round == self.round - 1 && parent_qc.sub_block_id() >= tc.highest_qc_id()
            },
        }
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct QC {
    round: Round,
    prefix: Prefix,
    n_sub_blocks: usize,
    block_digest: BlockHash,
}

#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct SubBlockId {
    round: Round,
    prefix: Prefix,
}

impl SubBlockId {
    pub fn new(round: Round, prefix: Prefix) -> Self {
        SubBlockId { round, prefix }
    }

    pub fn genesis() -> Self {
        SubBlockId::new(0, 0)
    }
}

impl From<(Round, Prefix)> for SubBlockId {
    fn from(tuple: (Round, Prefix)) -> Self {
        let (round, prefix) = tuple;
        SubBlockId { round, prefix }
    }
}

impl QC {
    pub fn genesis() -> Self {
        QC {
            round: 0,
            prefix: 0,
            n_sub_blocks: 0,
            block_digest: BlockHash::genesis(),
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.round == 0
    }

    pub fn is_full(&self) -> bool {
        self.prefix == self.n_sub_blocks
    }

    pub fn sub_block_id(&self) -> SubBlockId {
        (self.round, self.prefix).into()
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.sub_block_id() == other.sub_block_id()
    }
}

impl Eq for QC {}

impl PartialOrd for QC {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.sub_block_id().partial_cmp(&other.sub_block_id())
    }
}

impl Ord for QC {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sub_block_id().cmp(&other.sub_block_id())
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct CC {
    round: Round,
    min_prefix: Prefix,
    max_prefix: Prefix,
    // NB: a real implementation should include votes and a multisignature.
    // votes: Vec<Option<Prefix>>,
    // multisig: Multisig,
}

impl CC {
    pub fn new(round: Round, votes: &BTreeSet<(QC, NodeId)>) -> Self {
        CC {
            round,
            min_prefix: votes.iter().map(|(qc, _)| qc.prefix).min().unwrap(),
            max_prefix: votes.iter().map(|(qc, _)| qc.prefix).max().unwrap(),
        }
    }

    pub fn genesis() -> Self {
        CC {
            round: 0,
            min_prefix: 0,
            max_prefix: 0,
        }
    }

    pub fn lowest_qc_id(&self) -> SubBlockId {
        (self.round, self.min_prefix).into()
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        (self.round, self.max_prefix).into()
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct TC {
    round: Round,
    max_vote: SubBlockId,
    // NB: a real implementation should include votes and a multisignature.
    // votes: Vec<Option<QCId>>,
    // multisig: Multisig,
}

impl TC {
    pub fn genesis() -> Self {
        TC {
            round: 0,
            max_vote: (0, 0).into(),
        }
    }

    pub fn new(round: Round, votes: &BTreeMap<NodeId, SubBlockId>) -> TC {
        TC {
            round,
            max_vote: votes.into_iter().map(|(_node, &vote)| vote).max().unwrap(),
        }
    }

    pub fn highest_qc_id(&self) -> SubBlockId {
        self.max_vote
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub enum RoundEnterReason {
    /// Special case for the genesis block.
    Genesis,
    /// When a node receives a QC for the full prefix of round r, it enters round r+1.
    FullPrefixQC,
    /// When a node receives a CC for round r, it enters round r+1.
    CC(CC),
    /// When a node receives a TC for round r, it enters round r+1.
    TC(TC),
}

impl Debug for RoundEnterReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundEnterReason::Genesis => write!(f, "Genesis"),
            RoundEnterReason::FullPrefixQC => write!(f, "Full Prefix QC"),
            RoundEnterReason::CC(cc) => write!(f, "CC({})", cc.round),
            RoundEnterReason::TC(tc) => write!(f, "TC({})", tc.round),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    // Consensus
    Propose(Block),
    QcVote(Round, BlockHash, Prefix, usize),
    CommitVote(QC),
    Timeout(Round, QC),
    AdvanceRound(Round, QC, RoundEnterReason),
    FetchReq(BlockHash),
    FetchResp(Block),
}

#[derive(Clone)]
pub enum TimerEvent {
    // Consensus
    QcVote(Round),
    Timeout(Round),

    // Other
    EndOfRun,
    Status,
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
    pub enable_optimistic_dissemination: bool,
    pub enable_round_entry_permission: bool,

    /// The time validator waits after receiving a block before voting for a QC for it
    /// if it doesn't have all the batches yet.
    pub extra_wait_before_qc_vote: Duration,
    pub extra_wait_before_commit_vote: Duration,

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

    // Map from a block id to the list of QCs that wait for this block to be satisfied.
    pending_qcs: DefaultBTreeMap<BlockHash, Vec<QC>>,

    // QCs for which we have the full causal history available.
    satisfied_qcs: BTreeSet<SubBlockId>,

    // QCs that are committed via direct commit votes, for which we do not yet have their full causal history available.
    qcs_to_commit: BTreeMap<SubBlockId, (QC, CommitReason)>,

    leader_proposal: BTreeMap<Round, BlockHash>,
    blocks: BTreeMap<BlockHash, Block>,
    stored_prefix_cache: SubBlockId,
    // In practice, all votes should also include a signature.
    // In this prototype, signatures are omitted.
    qc_votes: DefaultBTreeMap<(BlockHash, usize), BTreeMap<NodeId, Prefix>>,
    received_cc_vote: DefaultBTreeMap<Round, BTreeSet<NodeId>>,
    cc_votes: DefaultBTreeMap<Round, KthMaxSet<(QC, NodeId)>>,
    tc_votes: DefaultBTreeMap<Round, BTreeMap<NodeId, SubBlockId>>,
}

impl<S: LeaderSchedule, DL: DisseminationLayer> RaikouNode<S, DL> {
    pub fn new(
        id: NodeId,
        config: Config<S>,
        dissemination: DL,
        start_time: Instant,
        detailed_logging: bool,
        metrics: Metrics,
    ) -> Self {
        let quorum = config.quorum();

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
            satisfied_qcs: Default::default(),
            qcs_to_commit: Default::default(),
            leader_proposal: Default::default(),
            blocks: Default::default(),
            stored_prefix_cache: (0, 0).into(),
            qc_votes: Default::default(),
            received_cc_vote: Default::default(),
            cc_votes: DefaultBTreeMap::new(KthMaxSet::new(quorum)),
            tc_votes: Default::default(),
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
        if let Some(parent_qc) = self.blocks[&qc.block_digest].parent_qc.as_ref() {
            if qc.round == parent_qc.round + 1 {
                if !self.qcs_to_commit.contains_key(&parent_qc.sub_block_id()) {
                    self.qcs_to_commit.insert(
                        parent_qc.sub_block_id(),
                        (parent_qc.clone(), CommitReason::TwoChainRule),
                    );
                }
            }
        }
    }

    async fn on_new_block(&mut self, block: &Block, ctx: &mut impl ContextFor<Self>) {
        assert!(!self.blocks.contains_key(&block.digest));

        self.blocks.insert(block.digest.clone(), block.clone());
        let parent_qc = block.parent_qc.as_ref().unwrap();

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
            if new_qc.round > self.last_commit_vote.round && new_qc.round > self.r_timeout {
                self.last_commit_vote = new_qc.sub_block_id();
                ctx.multicast(Message::CommitVote(new_qc.clone())).await;
            }
        }

        if new_qc.is_full() {
            // If form or receive a qc for the largest possible prefix of a round,
            // advance to the next round after that.
            self.advance_r_ready(new_qc.round + 1, RoundEnterReason::FullPrefixQC, ctx)
                .await;
        }

        self.known_qcs.insert(new_qc.sub_block_id());
        if self.satisfied_blocks.contains(&new_qc.block_digest) {
            self.on_new_satisfied_qc(new_qc);
        } else {
            self.pending_qcs[new_qc.block_digest.clone()].push(new_qc);
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

    async fn stored_prefix(&mut self) -> Prefix {
        assert!(self.leader_proposal.contains_key(&self.r_cur));

        let block_digest = &self.leader_proposal[&self.r_cur];
        let block = &self.blocks[block_digest];

        if self.stored_prefix_cache.round != self.r_cur {
            self.stored_prefix_cache = (self.r_cur, 0).into();
        }

        while self.stored_prefix_cache.prefix < block.n_sub_blocks()
            && self
                .dissemination
                .check_stored_all(block.sub_block(self.stored_prefix_cache.prefix))
                .await
        {
            self.stored_prefix_cache.prefix += 1;
        }

        self.stored_prefix_cache.prefix
    }

    async fn commit_qc(&mut self, qc: QC, commit_reason: CommitReason) {
        let committed = self.commit_qc_impl(qc, commit_reason);
        self.dissemination.notify_commit(committed).await;
    }

    fn commit_qc_impl(&mut self, qc: QC, commit_reason: CommitReason) -> Vec<Payload> {
        if qc <= self.committed_qc {
            return vec![];
        }

        let parent = self.blocks[&qc.block_digest]
            .parent_qc
            .as_ref()
            .unwrap()
            .clone();

        // Check for safety violations:
        if qc.round > self.committed_qc.round && parent.round < self.committed_qc.round {
            panic!("Safety violation: committed block was rolled back");
        }
        if parent.round == self.committed_qc.round && parent.prefix < self.committed_qc.prefix {
            panic!("Safety violation: optimistically committed transactions were rolled back");
        }

        // First commit the parent block.
        let mut res = self.commit_qc_impl(parent, CommitReason::Indirect);

        // Then, commit the transactions of this block.
        let block = &self.blocks[&qc.block_digest];

        if qc.round == self.committed_qc.round {
            // Extending the prefix of an already committed block.

            assert!(qc.prefix > self.committed_qc.prefix);

            self.log_detail(format!(
                "Extending the prefix of committed block {}: {} -> {} / {}{} ({:?})",
                qc.round,
                self.committed_qc.prefix,
                qc.prefix,
                block.n_sub_blocks(),
                if qc.is_full() {
                    " (full)"
                } else {
                    ""
                },
                commit_reason,
            ));

            res.push(block.payload.take_sub_blocks(self.committed_qc.prefix..qc.prefix));

            // Record the metrics
            let now = Instant::now();
            if self.config.leader(qc.round) == self.node_id {
                for _ in 0..(qc.prefix - self.committed_qc.prefix) {
                    self.metrics
                        .batch_consensus_latency
                        .push((now, self.to_deltas(now - self.block_create_time[&qc.round])));
                }
            }
        } else {
            // Committing a new block.

            self.log_detail(format!(
                "Committing block {} proposed by node {} with {} ACs \
                and prefix {}/{} [{}/{} batches]{} ({:?}).",
                qc.round,
                self.config.leader(qc.round),
                block.acs().len(),
                qc.prefix,
                block.n_sub_blocks(),
                block.sub_blocks().iter().take(qc.prefix).map(|b| b.len()).sum::<usize>(),
                block.sub_blocks().iter().map(|b| b.len()).sum::<usize>(),
                if qc.is_full() {
                    " (full)"
                } else {
                    ""
                },
                commit_reason,
            ));

            res.push(Payload::new(
                qc.round,
                self.config.leader(qc.round),
                block.payload.acs().clone(),
                block
                    .payload
                    .sub_blocks()
                    .iter()
                    .take(qc.prefix)
                    .cloned()
                    .collect_vec(),
            ));

            // Record the metrics
            let now = Instant::now();
            if self.config.leader(qc.round) == self.node_id {
                self.metrics
                    .block_consensus_latency
                    .push((now, self.to_deltas(now - self.block_create_time[&qc.round])));
                for _ in 0..(block.acs().len() + qc.prefix) {
                    self.metrics
                        .batch_consensus_latency
                        .push((now, self.to_deltas(now - self.block_create_time[&qc.round])));
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
        while cur.round != self.committed_qc.round {
            // assert!(self.blocks.contains_key(&cur.block_digest),
            //     "Block {:#x} not found for qc {:?}",
            //     cur.block_digest,
            //     cur.sub_block_id(),
            // );

            if !self.blocks.contains_key(&cur.block_digest) {
                aptos_logger::warn!(
                    "Deduplication failed for QC {:?}. Block from round {} is missing. \
                    This may often happen in an asynchronous network or a \
                    network where the triangle inequality doesn't hold.",
                    cur.sub_block_id(),
                    cur.round
                );
                return uncommitted;
            }

            let block = &self.blocks[&cur.block_digest];
            uncommitted.extend(block.acs().iter().map(|ac| ac.batch.digest.clone()));
            uncommitted.extend(block.sub_blocks().iter().take(cur.prefix).flatten().map(|batch| batch.digest.clone()));
            cur = block.parent_qc.as_ref().unwrap();
        }

        if cur.prefix > self.committed_qc.prefix {
            let block = &self.blocks[&cur.block_digest];
            uncommitted.extend(
                block
                    .sub_blocks()
                    .iter()
                    .take(cur.prefix)
                    .skip(self.committed_qc.prefix)
                    .flatten()
                    .map(|batch| batch.digest.clone()),
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
            self.satisfied_blocks.insert(BlockHash::genesis());
            self.satisfied_qcs.insert(QC::genesis().sub_block_id());
            self.known_qcs.insert(QC::genesis().sub_block_id());
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

                let digest = BlockHash(hash((&round, &payload, &parent_qc, &self.enter_reason)));
                let block = Block {
                    round,
                    payload,
                    parent_qc: Some(parent_qc),
                    reason: self.enter_reason.clone(),
                    digest: digest.clone(),
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
                && leader == self.config.leader(block.round)
                && !self.leader_proposal.contains_key(&block.round)
            {
                self.log_detail(format!(
                    "Received block {} proposed by node {}",
                    block.round,
                    leader
                ));

                self.leader_proposal.insert(block.round, block.digest.clone());
                self.on_new_block(&block, ctx).await;

                let Block { round, payload, reason, .. } = block;
                self.advance_r_ready(round, reason, ctx).await;

                ctx.notify(
                    self.dissemination.module_id(),
                    BlockReceived::new(leader, round, payload),
                ).await;

                if block.round < self.r_cur {
                    self.log_detail(format!(
                        "Ignoring proposal of block {} by node {} because already in round {}",
                        block.round,
                        leader,
                        self.r_cur,
                    ));
                } else if block.round <= self.r_timeout {
                    self.log_detail(format!(
                        "Ignoring proposal of block {} by node {} because already timed out round {}",
                        block.round,
                        leader,
                        self.r_timeout,
                    ));
                } else {
                    self.log_detail(format!(
                        "Processing proposal of block {} by node {}",
                        block.round,
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
                let stored_prefix = self.stored_prefix().await;

                self.log_detail(format!(
                    "QC-voting for block {} proposed by node {} by Timer with prefix {}",
                    round,
                    self.config.leader(round),
                    stored_prefix,
                ));

                self.last_qc_vote = (self.r_cur, stored_prefix).into();
                ctx.multicast(Message::QcVote(
                    round,
                    self.leader_proposal[&round].clone(),
                    stored_prefix,
                    self.n_sub_blocks_in_proposal(round),
                )).await;
            }
        };

        upon [
            self.r_cur > self.r_timeout
            && self.leader_proposal.contains_key(&self.r_cur)
            && {
                let stored_prefix = self.stored_prefix().await;

                stored_prefix == self.n_sub_blocks_in_proposal(self.r_cur)
                && self.last_qc_vote < (self.r_cur, stored_prefix).into()
            }
        ] {
            let round = self.r_cur;
            let digest = self.leader_proposal[&self.r_cur].clone();
            let n_sub_blocks = self.n_sub_blocks_in_proposal(self.r_cur);

            self.last_qc_vote = (round, n_sub_blocks).into();
            ctx.multicast(Message::QcVote(
                round,
                digest,
                n_sub_blocks,
                n_sub_blocks,
            )).await;
        };

        // Upon receiving the block for round r_cur and a quorum of qc-votes for this block,
        // form a QC and execute on_new_qc if one of the two conditions hold:
        // 1. When it will be the first QC observed by the node in this round;
        // 2. When it will be the first full-prefix QC observed by the node in this round.

        upon receive [Message::QcVote(round, digest, prefix, n_sub_blocks)] from node [p] {
            if round >= self.r_cur {
                self.qc_votes[(digest.clone(), n_sub_blocks)].insert(p, prefix);
                let votes = &self.qc_votes[(digest.clone(), n_sub_blocks)];

                // A node forms a QC when it has received a quorum of votes
                // with matching block digest and n_sub_blocks and either:
                // 1. the node has not yet received or formed any QC for this round; or
                // 2. it can form a full-prefix QC.
                if votes.len() >= self.quorum() {
                    let n_full_prefix_votes = votes.values().filter(|&&vote| vote == n_sub_blocks).count();
                    let cond_1 = self.qc_high.round < round;
                    let cond_2 = self.qc_high.sub_block_id() < (round, n_sub_blocks).into()
                        && n_full_prefix_votes >= self.config.storage_requirement;

                    if cond_1 || cond_2 {
                        // `certified_prefix` is the maximum number such that at least
                        // `storage_requirement` nodes have voted for a prefix of size
                        // `certified_prefix` or larger.
                        let certified_prefix = votes
                            .values()
                            .copied()
                            .sorted_by_key(|x| std::cmp::Reverse(*x))
                            .skip(self.config.storage_requirement - 1)
                            .next()
                            .expect("storage_requirement cannot be bigger than the quorum size");

                        let qc = QC {
                            round,
                            prefix: certified_prefix,
                            n_sub_blocks,
                            block_digest: digest,
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
        upon receive [Message::CommitVote(qc)] from node [p] {
            if !self.received_cc_vote[qc.round].contains(&p) {
                if !self.known_qcs.contains(&qc.sub_block_id()) {
                    self.on_new_qc(qc.clone(), ctx).await;
                }

                self.received_cc_vote[qc.round].insert(p);
                self.cc_votes[qc.round].insert((qc.clone(), p));

                if let Some((committed_qc, _)) = self.cc_votes[qc.round].kth_max() {
                    // Form a CC each time we can commit something new, possibly several
                    // times for the same round.
                    if *committed_qc > self.committed_qc {
                        let committed_qc = committed_qc.clone();

                        if !self.qcs_to_commit.contains_key(&committed_qc.sub_block_id()) {
                            self.qcs_to_commit.insert(
                                committed_qc.sub_block_id(),
                                (committed_qc, CommitReason::CC),
                            );
                        }

                        let cc = CC::new(qc.round, &self.cc_votes[qc.round].k_max_set());
                        self.advance_r_ready(qc.round + 1, RoundEnterReason::CC(cc), ctx).await;
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
                ctx.multicast(Message::Timeout(round, self.qc_high.clone())).await;
            }
        };

        // Upon receiving a valid timeout message, execute on_new_qc.
        // Upon gathering a quorum of matching timeout messages,
        // form the TC and execute advance_round.
        upon receive [Message::Timeout(round, qc)] from node [p] {
            self.tc_votes[round].insert(p, qc.sub_block_id());
            self.on_new_qc(qc, ctx).await;

            if self.tc_votes[round].len() == self.quorum() {
                let tc = TC::new(round, &self.tc_votes[round]);
                self.advance_r_ready(round + 1, RoundEnterReason::TC(tc), ctx).await;
            }
        };

        // Upon receiving an AdvanceRound message, execute on_new_qc and advance_round.
        upon receive [Message::AdvanceRound(round, qc, reason)] from [_any_node] {
            self.on_new_qc(qc, ctx).await;
            self.advance_r_ready(round, reason, ctx).await;
        };

        // Block fetching

        upon receive [Message::FetchReq(digest)] from [p] {
            if let Some(block) = self.blocks.get(&digest) {
                ctx.unicast(Message::FetchResp(block.clone()), p).await;
            } else {
                aptos_logger::warn!("Received FetchReq for unknown block {:#x}", digest);
            }
        };

        upon receive [Message::FetchResp(block)] from [_any_node] {
            if !self.blocks.contains_key(&block.digest) {
                self.on_new_block(&block, ctx).await;
            }
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
                    \tlast satisfied qc: {:?}\n",
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
                ));
            }
            ctx.set_timer(self.config.status_interval, TimerEvent::Status);
        };
    }
}
