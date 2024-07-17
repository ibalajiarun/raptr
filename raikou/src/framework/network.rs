// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::framework::{timer::NeverReturn, NodeId};
use aptos_types::validator_verifier::{self, ValidatorVerifier};
use futures::poll;
use rand::{distributions::Distribution, Rng};
use std::{future::Future, marker::PhantomData, task::Poll::Ready, time::Duration};
use tokio::sync::mpsc;

pub trait Validate {
    fn validate(&self, validator_verifier: &ValidatorVerifier) -> anyhow::Result<()>;
}

pub trait NetworkService: Send + Sync + 'static {
    type Message: Send + Sync + 'static;

    fn unicast(&self, data: Self::Message, target: NodeId) -> impl Future<Output = ()> + Send;

    fn multicast(&self, data: Self::Message) -> impl Future<Output = ()> + Send;

    fn recv(&mut self) -> impl Future<Output = (NodeId, Self::Message)> + Send;

    fn n_nodes(&self) -> usize;

    fn drop_one(&mut self) -> impl Future<Output = bool> + Send {
        async {
            let recv = self.recv();
            tokio::pin!(recv);
            return matches!(poll!(recv.as_mut()), Ready(_));
        }
    }

    fn clear_inbox(&mut self) -> impl Future<Output = ()> + Send {
        async { while self.drop_one().await {} }
    }
}

pub trait Network {
    type Message;
    type Service: NetworkService<Message = Self::Message>;

    fn service(&mut self, node_id: NodeId) -> Self::Service;
}

pub struct InjectedLocalNetworkService<M, I> {
    send: Vec<mpsc::Sender<(NodeId, M)>>,
    recv: mpsc::Receiver<(NodeId, M)>,
    node_id: NodeId,
    injection: I,
}

impl<M, I> NetworkService for InjectedLocalNetworkService<M, I>
where
    M: Send + Sync + Clone + 'static,
    I: NetworkInjection<M>,
{
    type Message = M;

    /// `send` spawns a separate task that calls `self.injection` on the message before
    /// sending it to `target`. The injection may:
    ///   1. sleep to simulate a message delay
    ///   2. drop the message to simulate message loss;
    ///   3. modify the message to simulate message corruption.
    ///
    /// Since the injection happens in a new task, `send` always returns immediately, not
    /// affected by any injected delay.
    async fn unicast(&self, data: M, target: NodeId) {
        let sender = self.node_id;
        let channel = self.send[target].clone();
        let injection = self.injection.clone();

        tokio::spawn(async move {
            // if let Some(message) = injection(message, target).await {
            //     send_channel.send(message).await.unwrap();
            // }
            if let Some(data) = injection(sender, target, data).await {
                // Ignoring send errors.
                let _ = channel.send((sender, data)).await;
            }
        });
    }

    /// `multicast` sends the message to all nodes in the network, including itself.
    async fn multicast(&self, data: M) {
        for target in 0..self.n_nodes() {
            self.unicast(data.clone(), target as NodeId).await;
        }
    }

    async fn recv(&mut self) -> (NodeId, M) {
        self.recv.recv().await.unwrap()
    }

    fn n_nodes(&self) -> usize {
        self.send.len()
    }
}

pub struct InjectedLocalNetwork<M, I> {
    send: Vec<mpsc::Sender<(NodeId, M)>>,
    recv: Vec<Option<mpsc::Receiver<(NodeId, M)>>>,
    injection: I,
}

impl<M, I: NetworkInjection<M>> InjectedLocalNetwork<M, I> {
    pub fn new(n_nodes: usize, injection: I) -> Self {
        let (send, recv) = (0..n_nodes)
            .map(|_| {
                let (send, recv) = mpsc::channel(1024);
                (send, Some(recv))
            })
            .unzip();
        InjectedLocalNetwork {
            send,
            recv,
            injection,
        }
    }
}

impl<M, I> Network for InjectedLocalNetwork<M, I>
where
    M: Send + Sync + Clone + 'static,
    I: NetworkInjection<M>,
{
    type Message = M;
    type Service = InjectedLocalNetworkService<M, I>;

    fn service(&mut self, node_id: NodeId) -> Self::Service {
        InjectedLocalNetworkService {
            send: self.send.clone(),
            recv: self.recv[node_id].take().unwrap(),
            node_id,
            injection: self.injection.clone(),
        }
    }
}

pub trait NetworkInjection<M>:
    Fn(NodeId, NodeId, M) -> Self::Future + Send + Sync + Clone + 'static
{
    type Future: Future<Output = Option<M>> + Send;
}

impl<I, F, M> NetworkInjection<M> for I
where
    I: Fn(NodeId, NodeId, M) -> F + Send + Sync + Clone + 'static,
    F: Future<Output = Option<M>> + Send,
{
    type Future = F;
}

pub fn random_delay_injection<M, D>(distr: D) -> impl NetworkInjection<M>
where
    M: Send,
    D: Distribution<f64> + Copy + Send + Sync + 'static,
{
    move |_, _, message| async move {
        let delay = {
            let mut rng = rand::thread_rng();
            rng.sample(distr)
        };
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
        Some(message)
    }
}

pub struct DropAllNetworkService<M> {
    n_nodes: usize,
    _phantom: PhantomData<M>,
}

impl<M> DropAllNetworkService<M> {
    pub fn new(n_nodes: usize) -> Self {
        DropAllNetworkService {
            n_nodes,
            _phantom: PhantomData,
        }
    }
}

impl<M> NetworkService for DropAllNetworkService<M>
where
    M: Send + Sync + Clone + 'static,
{
    type Message = M;

    async fn unicast(&self, _: M, _: NodeId) {}

    async fn multicast(&self, _: M) {}

    async fn recv(&mut self) -> (NodeId, M) {
        NeverReturn {}.await;
        unreachable!()
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }
}
