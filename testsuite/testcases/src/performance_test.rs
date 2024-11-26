// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::NetworkLoadTest;
use anyhow::anyhow;
use aptos_forge::{NetworkContextSynchronizer, NetworkTest, NodeExt, Result, Test};
use aptos_logger::debug;
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
use rand::{thread_rng, RngCore};
use reqwest::Url;
use std::{cell::OnceCell, sync::OnceLock, time::Duration};

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
            .set(BalterContext { clients })
            .map_err(|_| anyhow!("couldn't set context"))
            .unwrap();

        let result = load_test()
            .tps(10)
            .duration(Duration::from_secs(60))
            .error_rate(0.0)
            .hint(balter::Hint::Concurrency(1))
            .await;

        println!("{:?}", result);

        Ok(())
    }
}

static BALTER_CONTEXT: OnceLock<BalterContext> = OnceLock::new();

pub struct BalterContext {
    clients: Vec<aptos_rest_client::Client>,
}

impl BalterContext {
    fn new(clients: Vec<aptos_rest_client::Client>) -> Self {
        Self { clients }
    }

    fn next_client(&self) -> aptos_rest_client::Client {
        let idx = thread_rng().next_u32() as usize % self.clients.len();
        self.clients[idx].clone()
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
        transaction(&client, txn_payload).await.unwrap();
    }
}

#[transaction]
async fn transaction(
    client: &aptos_rest_client::Client,
    txn_payload: Vec<u8>,
) -> anyhow::Result<()> {
    let response = client
        .post(client.build_path("submit_txn").unwrap())
        .body(txn_payload)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .unwrap();

    response.error_for_status().unwrap();

    Ok(())
}
