use crate::{
    delays::{heterogeneous_symmetric_delay, DelayFunction},
    framework::{
        crypto::{SignatureVerifier, Signer},
        module_network::ModuleNetwork,
        network::{InjectedLocalNetwork, Network, NetworkInjection, NetworkService},
        timer::{clock_skew_injection, InjectedTimerService},
        NodeId, Protocol,
    },
    metrics,
    metrics::display_metric,
    raikou,
    raikou::{
        dissemination,
        dissemination::native::{Batch, NativeDisseminationLayer},
        types::N_SUB_BLOCKS,
        RaikouNode,
    },
};
use aptos_crypto::bls12381::{PrivateKey, PublicKey};
use aptos_types::{
    account_address::AccountAddress, validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};
use rand::{thread_rng, Rng};
use std::{
    collections::BTreeMap,
    iter,
    ops::Deref,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{time, time::Instant};

fn network_injection<M: Send>(
    delay_function: impl DelayFunction,
    // crashes: Vec<(NodeId, Instant)>,
) -> impl NetworkInjection<M> {
    move |from, to, message| {
        let delay_function = delay_function.clone();

        async move {
            let delay = f64::max(delay_function(from, to), 0.);
            tokio::time::sleep(Duration::from_secs_f64(delay)).await;
            Some(message)
        }
    }
}

async fn test_raikou(
    delay_function: impl DelayFunction + Clone,
    n_nodes: usize,
    delta: f64,
    spawn_period_in_delta: u32,
    warmup_period_in_delta: u32,
    total_duration_in_delta: u32,
    // crashes: Vec<(NodeId, Slot)>,
    // choose one arbitrary correct node to monitor it more closely.
    monitored_node: NodeId,
    enable_optimistic_dissemination: bool,
) {
    // if 3 * crashes.len() + 1 > n_nodes {
    //     println!("WARNING: too many crashes, the protocol may stall.");
    // }

    let spawn_delay_distr =
        rand_distr::Uniform::new(1. * delta, spawn_period_in_delta as f64 * delta);
    let clock_speed_distr = rand_distr::Normal::new(1., 0.01).unwrap();

    let mut diss_network =
        InjectedLocalNetwork::new(n_nodes, network_injection(delay_function.clone()));
    let mut network = InjectedLocalNetwork::new(n_nodes, network_injection(delay_function));

    let f = (n_nodes - 1) / 3;
    let poa_quorum = 2 * f + 1;

    let config = raikou::Config {
        n_nodes,
        f,
        storage_requirement: f + 1, // f + (f / 2 + 1),
        leader_timeout: Duration::from_secs_f64(delta * 4.5),
        delta: Duration::from_secs_f64(delta),
        end_of_run: Instant::now() + Duration::from_secs_f64(delta) * total_duration_in_delta,
        extra_wait_before_qc_vote: Duration::from_secs_f64(delta * 0.1),
        enable_partial_qc_votes: true,
        enable_commit_votes: true,
        status_interval: Duration::from_secs_f64(delta) * 10,
        round_sync_interval: Duration::from_secs_f64(delta * 15.),
        block_fetch_multiplicity: std::cmp::min(2, n_nodes),
        block_fetch_interval: Duration::from_secs_f64(delta) * 2,
        poa_quorum,
    };

    let mut join_handles = Vec::new();

    // Semaphore is used to track the number of nodes that have started.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(0));
    // let mut propose_time = metrics::UnorderedBuilder::new();
    // let mut enter_time = metrics::UnorderedBuilder::new();
    let mut batch_commit_time = metrics::UnorderedBuilder::new();
    let mut queueing_time = metrics::UnorderedBuilder::new();
    let mut penalty_wait_time = metrics::UnorderedBuilder::new();
    let mut block_consensus_latency = metrics::UnorderedBuilder::new();
    let mut batch_consensus_latency = metrics::UnorderedBuilder::new();
    let mut batch_execute_time = metrics::UnorderedBuilder::new();
    let mut fetch_wait_time_after_commit = metrics::UnorderedBuilder::new();
    // let mut indirectly_committed_slots = metrics::UnorderedBuilder::new();
    let executed_txns_counter = Arc::new(AtomicUsize::new(0));

    let private_keys: Vec<_> = (0..n_nodes)
        .map(|node_id| {
            use aptos_crypto::traits::Uniform;
            Arc::new(PrivateKey::generate(&mut thread_rng()))
        })
        .collect();

    let public_keys: Vec<_> = (0..n_nodes)
        .map(|node_id| PublicKey::from(private_keys[node_id].deref()))
        .collect();

    let start_time = Instant::now();
    for node_id in 0..n_nodes {
        let config = config.clone();

        let sig_verifier = SignatureVerifier::new(
            public_keys.clone(),
            // Not going to be actually used with --features sim-types.
            Arc::new(ValidatorVerifier::new(vec![])),
            N_SUB_BLOCKS + 1,
        );

        let signer = Signer::new(
            Arc::new(ValidatorSigner::new(
                AccountAddress::new([node_id as u8; 32]), // this is not actually used.
                private_keys[node_id].clone(),
            )),
            node_id,
            N_SUB_BLOCKS + 1,
        );

        let mut diss_network_service = diss_network.service(
            node_id,
            Arc::new(dissemination::native::Certifier::new(signer.clone())),
        );
        let mut network_service =
            network.service(node_id, Arc::new(raikou::protocol::Certifier::new()));

        let clock_speed = { thread_rng().sample(clock_speed_distr) };

        // introduce artificial clock skew.
        let diss_timer = InjectedTimerService::local(clock_skew_injection(clock_speed));
        let timer = InjectedTimerService::local(clock_skew_injection(clock_speed));

        // let propose_time_sender = Some(propose_time.new_sender());
        // let enter_time_sender = if node_id == monitored_node {
        //     Some(enter_time.new_sender())
        // } else {
        //     None
        // };
        let batch_commit_time_sender = Some(batch_commit_time.new_sender());
        let queueing_time_sender = Some(queueing_time.new_sender());
        let penalty_wait_time_sender = Some(penalty_wait_time.new_sender());
        let block_consensus_latency_sender = Some(block_consensus_latency.new_sender());
        let batch_consensus_latency_sender = Some(batch_consensus_latency.new_sender());
        let batch_execute_time_sender = Some(batch_execute_time.new_sender());
        let fetch_wait_time_after_commit_sender = Some(fetch_wait_time_after_commit.new_sender());
        let executed_txns_counter = executed_txns_counter.clone();
        // let indirectly_committed_slots_sender = if node_id == monitored_node {
        //     Some(indirectly_committed_slots.new_sender())
        // } else {
        //     None
        // };

        let semaphore = semaphore.clone();
        join_handles.push(tokio::spawn(async move {
            // Sleep for a random duration before spawning the node.
            let spawn_delay = {
                let mut rng = thread_rng();
                rng.sample(spawn_delay_distr)
            };
            time::sleep(Duration::from_secs_f64(spawn_delay)).await;

            // Before starting the node, "drop" all messages sent to it during the spawn delay.
            network_service.clear_inbox().await;
            diss_network_service.clear_inbox().await;

            let txns_iter = iter::repeat_with(|| vec![]);

            let mut module_network = ModuleNetwork::new();
            let diss_module_network = module_network.register().await;
            let cons_module_network = module_network.register().await;

            let (execute_tx, mut execute_rx) = tokio::sync::mpsc::channel::<Batch>(1024);

            let executed_txns_counter = executed_txns_counter.clone();
            tokio::spawn(async move {
                while let Some(batch) = execute_rx.recv().await {
                    if node_id == monitored_node {
                        executed_txns_counter.fetch_add(batch.txns().len(), Ordering::SeqCst);
                    }
                }
            });

            let batch_interval_secs = delta * 0.1;
            let expected_load =
                f64::ceil(n_nodes as f64 * (3. * delta) / batch_interval_secs) as usize;

            let dissemination = NativeDisseminationLayer::new(
                node_id,
                dissemination::native::Config {
                    module_id: diss_module_network.module_id(),
                    n_nodes,
                    f,
                    poa_quorum,
                    delta: Duration::from_secs_f64(delta),
                    batch_interval: Duration::from_secs_f64(batch_interval_secs),
                    enable_optimistic_dissemination,
                    enable_penalty_tracker: true,
                    penalty_tracker_report_delay: Duration::from_secs_f64(delta * 5.),
                    batch_fetch_multiplicity: std::cmp::min(2, n_nodes),
                    batch_fetch_interval: Duration::from_secs_f64(delta) * 2,
                    status_interval: Duration::from_secs_f64(delta) * 10,
                    block_size_limit:
                        dissemination::native::BlockSizeLimit::from_max_number_of_poas(
                            f64::ceil(expected_load as f64 * 1.5) as usize,
                            n_nodes,
                        ),
                },
                txns_iter,
                cons_module_network.module_id(),
                node_id == monitored_node,
                dissemination::Metrics {
                    batch_commit_time: batch_commit_time_sender,
                    queueing_time: queueing_time_sender,
                    penalty_wait_time: penalty_wait_time_sender,
                    batch_execute_time: batch_execute_time_sender,
                    fetch_wait_time_after_commit: fetch_wait_time_after_commit_sender,
                },
                signer.clone(),
                sig_verifier.clone(),
                execute_tx,
            );

            // println!("Spawning node {node_id}");
            let node = Arc::new(tokio::sync::Mutex::new(RaikouNode::new(
                node_id,
                config,
                dissemination.clone(),
                node_id == monitored_node,
                raikou::Metrics {
                    block_consensus_latency: block_consensus_latency_sender,
                    batch_consensus_latency: batch_consensus_latency_sender,
                    // propose_time: propose_time_sender,
                    // enter_time: enter_time_sender,
                    // indirectly_committed_slots: indirectly_committed_slots_sender,
                },
                signer,
                sig_verifier,
                None, // failure_tracker
            )));

            semaphore.add_permits(1);

            tokio::spawn(Protocol::run(
                dissemination.protocol(),
                node_id,
                diss_network_service,
                diss_module_network,
                diss_timer,
            ));

            Protocol::run(node, node_id, network_service, cons_module_network, timer).await;
            println!("Node {} finished", node_id);
        }));
    }

    let _ = semaphore.acquire_many(n_nodes as u32).await.unwrap();
    println!("All nodes are running!");

    for join_handle in join_handles {
        join_handle.await.unwrap();
    }
    println!("All nodes finished");

    // let propose_time = propose_time
    //     .build()
    //     .await
    //     .sort()
    //     .drop_first(29)
    //     .drop_last(10)
    //     .derivative();
    // println!("Propose Time:");
    // propose_time.print_stats();
    // propose_time.show_histogram(n_slots as usize / 5, 10);
    // println!();

    // let enter_time = enter_time
    //     .build()
    //     .await
    //     .sort()
    //     .drop_first(19)
    //     .drop_last(10)
    //     .derivative();
    // println!("Enter Time:");
    // enter_time.print_stats();
    // enter_time.show_histogram(n_slots as usize / 5, 10);
    // println!();

    display_metric(
        "Fetch wait time after commit",
        "The duration from committing a block until being able to execute it, i.e.,\
        until we have the whole prefix of the chain fetched.",
        fetch_wait_time_after_commit,
        start_time,
        delta,
        warmup_period_in_delta,
    )
    .await;

    display_metric(
        "Penalty system delay",
        "The penalties for optimistically committed batches. \
        Measured on the leader.",
        penalty_wait_time,
        start_time,
        delta,
        warmup_period_in_delta,
    )
    .await;

    display_metric(
        "Optimistic batch queueing time",
        "The duration from when the batch is received by leader until the block \
        containing this batch is proposed. \
        Only measured if the block is committed. \
        Only measured for optimistically committed batches. \
        Measured on the leader.",
        queueing_time,
        start_time,
        delta,
        warmup_period_in_delta,
    )
    .await;

    display_metric(
        "Batch consensus latency",
        "The duration from when the batch is included in a block until \
        the block is committed. \
        Measured on the leader.",
        batch_consensus_latency,
        start_time,
        delta,
        warmup_period_in_delta,
    )
    .await;

    display_metric(
        "Batch commit time",
        "The duration from creating the batch until committing it. \
        After committing, we may have to wait for the data to be fetched. \
        Measured on the batch creator.",
        batch_commit_time,
        start_time,
        delta,
        warmup_period_in_delta,
    )
    .await;

    display_metric(
        "Batch execute time (the end-to-end latency)",
        "The duration from creating the batch until executing it. \
        Measured on the batch creator.",
        batch_execute_time,
        start_time,
        delta,
        warmup_period_in_delta,
    )
    .await;

    println!(
        "Executed transactions: {}",
        executed_txns_counter.load(Ordering::SeqCst)
    );
}

pub async fn main() {
    aptos_logger::Logger::builder()
        .level(aptos_logger::Level::Info)
        .build();

    let n_nodes = 31;
    let delta = 1.;
    let spawn_period_in_delta = 10;
    let warmup_period_in_delta = 70;
    let total_duration_in_delta = 150;
    let monitored_node = 3;

    test_raikou(
        heterogeneous_symmetric_delay(
            // the mean delay between a pair of nodes is uniformly sampled between 0 and 0.9 delta.
            rand_distr::Uniform::new(0., 0.9 * delta),
            // 2% standard deviation from the mean in all delays.
            rand_distr::Normal::new(1., 0.02).unwrap(),
            // Fixed additive noise of 0.01 delta to make sure there are no 0-delay messages.
            rand_distr::Uniform::new(0.01 * delta, 0.0100001 * delta),
        ),
        n_nodes,
        delta,
        spawn_period_in_delta,
        warmup_period_in_delta,
        total_duration_in_delta,
        monitored_node,
        true,
    )
    .await;
}
