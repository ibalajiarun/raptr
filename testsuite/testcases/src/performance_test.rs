// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::NetworkLoadTest;
use anyhow::anyhow;
use aptos_forge::{NetworkContextSynchronizer, NetworkTest, NodeExt, Result, Test};
use aptos_logger::{debug, info};
use aptos_types::{
    chain_id::ChainId,
    transaction::{
        authenticator::AccountAuthenticator, EntryFunction, RawTransaction, Script,
        SignedTransaction, TransactionPayload,
    },
    PeerId,
};
use async_trait::async_trait;
use balter::{prelude::ConfigurableScenario, scenario, transaction};
use futures::stream::FuturesUnordered;
use rand::{thread_rng, RngCore};
use reqwest::{StatusCode, Url};
use std::{
    cell::OnceCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Duration,
};

pub struct PerformanceBenchmark;

impl Test for PerformanceBenchmark {
    fn name(&self) -> &'static str {
        "performance benchmark"
    }
}

impl NetworkLoadTest for PerformanceBenchmark {}

#[async_trait]
impl NetworkTest for PerformanceBenchmark {
    async fn run<'a>(&self, ctx: NetworkContextSynchronizer<'a>) -> Result<()> {
        <dyn NetworkLoadTest>::run(self, ctx).await
    }
}

pub struct ConsensusOnlyBenchmark;

impl Test for ConsensusOnlyBenchmark {
    fn name(&self) -> &'static str {
        "consensus-only benchmark"
    }
}

const MAX_BATCH_SIZE: usize = 1;

#[async_trait]
impl NetworkTest for ConsensusOnlyBenchmark {
    async fn run<'a>(&self, ctx: NetworkContextSynchronizer<'a>) -> Result<()> {
        let ctx = ctx.ctx.lock().await;

        // Get all URLs
        let clients = ctx
            .swarm
            .read()
            .await
            .validators()
            .map(|val| val.rest_client())
            .collect();

        // Create Balter
        BALTER_CONTEXT
            .set(BalterContext {
                clients,
                idx: AtomicU64::new(0),
                batch_size: MAX_BATCH_SIZE,
            })
            .map_err(|_| anyhow!("couldn't set context"))
            .unwrap();

        // let result = batch_load_test()
        //     .tps(10000)
        //     .duration(Duration::from_secs(600))
        //     .error_rate(0.0)
        //     .hint(balter::Hint::Concurrency(20000))
        //     .await;

        let concurrency = 81_000;
        let test_time = Duration::from_secs(600);
        let mut futures = Vec::new();
        for i in 0..concurrency {
            if i % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            futures.push(tokio::spawn(async move {
                tokio::time::timeout(test_time, batch_load_test()).await
            }));
        }
        let _result = futures::future::join_all(futures).await;

        info!("test complete");

        // let result = tokio::time::timeout(Duration::from_secs(60), load_test()).await;

        // info!("{:?}", result);
        // println!("{:?}", result);

        Ok(())
    }
}

static BALTER_CONTEXT: OnceLock<BalterContext> = OnceLock::new();

pub struct BalterContext {
    clients: Vec<aptos_rest_client::Client>,
    idx: AtomicU64,
    batch_size: usize,
}

impl BalterContext {
    fn next_client(&self) -> aptos_rest_client::Client {
        let idx = self.idx.fetch_add(1, Ordering::Relaxed) % self.clients.len() as u64;
        self.clients[idx as usize].clone()
    }
}

#[scenario]
async fn load_test() {
    let client = { BALTER_CONTEXT.get().unwrap().next_client() };
    let (txn_tx, mut txn_rx) = tokio::sync::mpsc::channel(100);
    tokio::spawn(async move {
        let mut seq_num = 0;
        let sender = PeerId::random();
        loop {
            let txn = SignedTransaction::new_single_sender(
                RawTransaction::new(
                    sender,
                    seq_num,
                    TransactionPayload::Script(Script::new(Vec::new(), Vec::new(), Vec::new())),
                    0,
                    0,
                    Duration::from_secs(60).as_secs(),
                    ChainId::test(),
                ),
                AccountAuthenticator::NoAccountAuthenticator,
            );
            txn_tx.send(txn).await.ok();
            seq_num = seq_num + 1;
        }
    });
    while let Some(txn) = txn_rx.recv().await {
        let txn_payload = bcs::to_bytes(&txn).unwrap();
        let _ = transaction(&client, txn_payload).await;
    }
}

#[transaction]
async fn transaction(
    client: &aptos_rest_client::Client,
    txn_payload: Vec<u8>,
) -> anyhow::Result<()> {
    let res = client
        .post(client.build_path("submit_txn").unwrap())
        .body(txn_payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    if res.status() != StatusCode::NOT_FOUND {
        let _ = res.error_for_status()?;
    }

    Ok(())
}

// #[scenario]
async fn batch_load_test() {
    let (client, batch_size) = {
        let ctx = BALTER_CONTEXT.get().unwrap();
        (ctx.next_client(), ctx.batch_size)
    };
    let (txn_tx, mut txn_rx) = tokio::sync::mpsc::channel(100);
    tokio::spawn(async move {
        let mut seq_num = 0;
        let sender = PeerId::random();
        loop {
            let mut batch = Vec::new();
            for i in 0..batch_size {
                let txn = SignedTransaction::new_single_sender(
                    RawTransaction::new(
                        sender,
                        seq_num,
                        TransactionPayload::Script(Script::new(Vec::new(), Vec::new(), Vec::new())),
                        0,
                        0,
                        Duration::from_secs(60).as_secs(),
                        ChainId::test(),
                    ),
                    AccountAuthenticator::NoAccountAuthenticator,
                );
                batch.push(txn);
                seq_num = seq_num + 1;
            }
            txn_tx.send(batch).await.ok();
        }
    });
    while let Some(batch_txn) = txn_rx.recv().await {
        let txn_payload = bcs::to_bytes(&batch_txn).unwrap();
        let _ = batch_transaction(&client, txn_payload).await;
    }
}

// #[transaction]
async fn batch_transaction(
    client: &aptos_rest_client::Client,
    txn_payload: Vec<u8>,
) -> anyhow::Result<()> {
    let res = client
        .post(client.build_path("submit_txn_batch").unwrap())
        .body(txn_payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    if res.status() != StatusCode::NOT_FOUND {
        let _ = res.error_for_status()?;
    }

    Ok(())
}
