use crate::{
    framework::NodeId,
    raikou::{
        types::{Round, *},
    },
};
use itertools::Itertools;
use std::{
    cmp::{max, min},
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use log::{info, warn};
use tokio::time::Instant;

pub trait Millis {
    fn as_millis_f32(&self) -> f32;

    fn from_millis_f32(millis: f32) -> Self;
}

#[derive(Copy, Clone, Debug, PartialEq)]
/// Penalty tracker report for the optimistically proposed batches from a single node for
/// a single node. See the description of `PenaltyTrackerReport` for details.
pub enum PenaltyTrackerReportEntry {
    Delay(usize, f32),

    Missing(usize, f32),

    None,
}

/// Type alias for readability.
type NodeIdMap<T> = Vec<T>;

/// `Delay(k, x)` on position `i` in the report means that the sender of the report had all the
/// optimistically proposed batches issued by node `i` `x` milliseconds after (if `x` is positive)
/// or `-x` milliseconds before (if `x` is negative) the sender of the report received the block
/// from the leader and the batch that was on the `k`th position in the block was received last
/// among all optimistically proposed batches issued by node `i`.
///
/// `Missing(k, x)` on position `i` in the report means that the sender of the report was missing
/// the batch that was on `k`th position in the block issued by node `i` has not been yet received
/// when the report was prepared, `x` seconds after the sender of the report received the block
/// from the leader. Of all such batches, the smallest `k` is reported as it was supposedly
/// received the earliest by the leader.
///
/// `None` on position `i` in the report  means that there were no optimistically proposed batches
/// issued by node `i` in the block.
pub type PenaltyTrackerReports = NodeIdMap<PenaltyTrackerReportEntry>;

#[derive(Clone)]
pub struct Config {
    pub n_nodes: usize,
    pub f: usize,
    pub enable: bool,
}

pub struct PenaltyTracker {
    config: Config,

    batch_receive_time: BTreeMap<BatchHash, Instant>,
    penalties: NodeIdMap<Duration>,

    // The variables below are relative to the last round this node was leader.
    last_round_this_node_was_leader: Round,
    block_issue_time: Instant,
    proposed_batches: Vec<BatchInfo>,
    batch_authors: BTreeSet<NodeId>,
    reports: BTreeMap<NodeId, BTreeMap<NodeId, f32>>,
}

impl PenaltyTracker {
    pub fn new(config: Config) -> Self {
        let n_nodes = config.n_nodes;

        Self {
            config,
            batch_receive_time: Default::default(),
            penalties: vec![Duration::ZERO; n_nodes],
            last_round_this_node_was_leader: -1,
            proposed_batches: vec![],
            batch_authors: Default::default(),
            block_issue_time: Instant::now(),
            reports: Default::default(),
        }
    }

    pub fn prepare_reports(
        &self,
        batches: &Vec<BatchInfo>,
        block_receive_time: Instant,
    ) -> PenaltyTrackerReports {
        assert!(self.config.enable);

        let now = Instant::now();
        assert!(now >= block_receive_time);

        let mut delays = vec![(0, f32::MIN); self.config.n_nodes];
        let mut missing = vec![None; self.config.n_nodes];
        let mut has_batches = vec![false; self.config.n_nodes];

        for (batch_num, batch_info) in batches.iter().enumerate() {
            has_batches[batch_info.author] = true;

            if let Some(batch_receive_time) = self.batch_receive_time.get(&batch_info.digest).copied() {

                let batch_delay = if batch_receive_time > block_receive_time {
                    (batch_receive_time - block_receive_time).as_secs_f32()
                } else {
                    -(block_receive_time - batch_receive_time).as_secs_f32()
                };

                if batch_delay > delays[batch_info.author].1 {
                    delays[batch_info.author] = (batch_num, batch_delay);
                }
            } else if missing[batch_info.author].is_none() {
                missing[batch_info.author] = Some(batch_num);
            }
        }

        (0..self.config.n_nodes)
            .map(|node_id| {
                if !has_batches[node_id] {
                    PenaltyTrackerReportEntry::None
                } else if let Some(batch_num) = missing[node_id] {
                    PenaltyTrackerReportEntry::Missing(batch_num, (now - block_receive_time).as_secs_f32())
                } else {
                    let (batch_num, delay) = delays[node_id];
                    assert_ne!(delay, f32::MIN);
                    PenaltyTrackerReportEntry::Delay(batch_num, delay)
                }
            })
            .collect()
    }

    pub fn register_reports(
        &mut self,
        round: Round,
        reporter: NodeId,
        reports: PenaltyTrackerReports,
    ) {
        assert!(self.config.enable);

        if round != self.last_round_this_node_was_leader || self.reports.contains_key(&reporter) {
            return;
        }

        let mut processed_reports = BTreeMap::new();

        for (node_id, report) in reports.into_iter().enumerate() {
            match report {
                PenaltyTrackerReportEntry::Delay(batch_num, delay) => {
                    if self.proposed_batches[batch_num].author != node_id {
                        warn!("Received invalid penalty tracker report from node {}", reporter);
                        return;
                    }

                    let adjusted_delay = delay + self.batch_propose_delay(&self.proposed_batches[batch_num]).as_secs_f32();
                    processed_reports.insert(node_id, adjusted_delay);
                },
                PenaltyTrackerReportEntry::Missing(batch_num, delay) => {
                    if self.proposed_batches[batch_num].author != node_id {
                        warn!("Received invalid penalty tracker report from node {}", reporter);
                        return;
                    }

                    // For now, missing votes are treated the same as Delay votes.
                    let adjusted_delay = delay + self.batch_propose_delay(&self.proposed_batches[batch_num]).as_secs_f32();
                    processed_reports.insert(node_id, adjusted_delay);
                },
                PenaltyTrackerReportEntry::None => {
                    if self.batch_authors.contains(&node_id) {
                        warn!("Received invalid penalty tracker report from node {}", reporter);
                        return
                    }
                },
            }
        }

        self.reports.insert(reporter, processed_reports);
    }

    fn batch_propose_delay(&self, batch_info: &BatchInfo) -> Duration {
        self.block_issue_time - self.batch_receive_time[&batch_info.digest]
    }

    fn compute_new_penalties(&self) -> Vec<Duration> {
        assert!(self.config.enable);

        if self.last_round_this_node_was_leader == -1 {
            // This node has not been a leader yet. No information to compute penalties.
            return self.penalties.clone();
        }

        // TODO: check for missing votes to ban Byzantine nodes.

        // For each node that sent a report, compute the sum of reported delays.
        let mut delay_sums = self
            .reports
            .iter()
            .map(|(reporter, reports)| {
                let delay_sum = reports
                    .iter()
                    .map(|(_, delay)| *delay as f64)
                    .sum::<f64>();

                (*reporter, delay_sum)
            })
            .collect_vec();

        // Sort by the sum of reported delays in the ascending order.
        delay_sums.sort_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap());

        // Select a quorum of nodes whose reports we will consider.
        let quorum = delay_sums
            .into_iter()
            // Keep the n-f reports with the smallest sum of delays.
            .take(self.config.n_nodes - self.config.f)
            // Get the IDs of the reporting nodes.
            .map(|(node_id, _)| node_id)
            .collect_vec();

        if quorum.len() < self.config.n_nodes - self.config.f {
            // If there are not enough reports, the network must be in an asynchronous period.
            // Do not change the penalties.
            // TODO: What's the best strategy fo this case?
            warn!("Not enough reports to compute new penalties ({} / {}). Either the network is \
                   asynchronous or the penalty tracker is misconfigured.",
            quorum.len(),
            self.config.n_nodes - self.config.f);
            return self.penalties.clone();
        }

        // Compute the new penalties.
        // The new penalties are computed in such a way that, if the next time this node is
        // the leader all the message delays stay the same, the nodes in `quorum` will have
        // all the batches optimistically proposed by the leader.

        let mut updated_penalties = vec![Duration::ZERO; self.config.n_nodes];

        for node_id in 0..self.config.n_nodes {
            if self.batch_authors.contains(&node_id) {
                let max_reported_delay_in_a_quorum = quorum
                    .iter()
                    .copied()
                    .map(|reporter| self.reports[&reporter][&node_id])
                    .max_by(|x, y| x.partial_cmp(y).unwrap())
                    .unwrap();

                if max_reported_delay_in_a_quorum > 0. {
                    // Increase penalty.
                    // Always at least double the penalty when increasing it.
                    updated_penalties[node_id] = self.penalties[node_id] + max(
                        self.penalties[node_id],
                        Duration::from_secs_f32(max_reported_delay_in_a_quorum),
                    );
                } else {
                    // Decrease penalty.
                    // Always at most halve the penalty when decreasing it.
                    updated_penalties[node_id] = self.penalties[node_id] - min(
                        self.penalties[node_id] / 2,
                        Duration::from_secs_f32(-max_reported_delay_in_a_quorum),
                    );
                }
            } else {
                // TODO: What to do with nodes that have no optimistically proposed batches?
                //       Most likely, it happens because they already have too large penalty
                //       and their transactions go through the slow path.
                //       At some point we should give them a chance to rehabilitate themselves.
                // TODO: Idea: include their batch hashes in the block, but do not actually
                //       commit them, just to collect reports.
                updated_penalties[node_id] = self.penalties[node_id];
            }
        }

        updated_penalties
    }

    pub fn on_new_batch(&mut self, digest: BatchHash) {
        // This should be executed even when the penalty system is turned off.
        self.batch_receive_time.insert(digest, Instant::now());
    }

    pub fn prepare_new_block(
        &mut self,
        round: Round,
        batches: Vec<BatchInfo>,
    ) -> Vec<BatchInfo> {
        if !self.config.enable {
            return batches
                .into_iter()
                .sorted_by_key(|batch_info| self.batch_receive_time[&batch_info.digest])
                .collect();
        }

        // `compute_new_penalties` must be called before any parts of the state are updated.
        let new_penalties = self.compute_new_penalties();

        if round % self.config.n_nodes as i64 == 3 {
            info!("New penalties: {:?}", new_penalties);
        }

        let now = Instant::now();

        let batches_to_propose: Vec<BatchInfo> = batches
            .into_iter()
            .map(|batch_info| {
                let receive_time = self.batch_receive_time[&batch_info.digest];
                let safe_propose_time = receive_time + new_penalties[batch_info.author];
                (safe_propose_time, batch_info)
            })
            .sorted_by_key(|(safe_propose_time, _)| *safe_propose_time)
            .take_while(|&(safe_propose_time, _)| safe_propose_time <= now)
            .map(|(_, batch_info)| batch_info)
            .collect_vec();

        self.penalties = new_penalties;

        self.last_round_this_node_was_leader = round;
        self.block_issue_time = now;
        self.proposed_batches = batches_to_propose.clone();
        self.batch_authors = batches_to_propose.iter().map(|batch_info| batch_info.author).collect();
        self.reports.clear();

        batches_to_propose
    }
}
