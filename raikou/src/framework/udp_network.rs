// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::framework::{
    injection::{delay_injection, drop_injection},
    network::{NetworkService, Validate},
    NodeId,
};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use futures::{future::join_all, stream::FuturesUnordered, FutureExt, StreamExt};
use aptos_types::validator_verifier::ValidatorVerifier;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::format,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    join,
    net::UdpSocket,
    sync::{Mutex, OwnedMutexGuard},
};

pub const MAX_MESSAGE_SIZE: usize = 1024;

pub struct Config {
    pub peers: Vec<(IpAddr, u16)>,
    pub peer_concurrency_level: usize,
}

pub struct UdpNetworkService<M> {
    recv: aptos_channel::Receiver<NodeId, (NodeId, M)>,
    // recv: tokio::sync::mpsc::Receiver<(NodeId, M)>,
    sender: Arc<UdpNetworkServiceSender<M>>,
}

struct UdpNetworkServiceSender<M> {
    node_id: NodeId,
    self_send: aptos_channel::Sender<NodeId, (NodeId, M)>,
    socks: Vec<Arc<UdpSocket>>,
}

impl<M> UdpNetworkServiceSender<M> {
    fn self_send(&self, msg: M) {
        self.self_send
            .push(self.node_id, (self.node_id, msg))
            .unwrap();
    }
}

impl<M> UdpNetworkService<M>
where
    M: Send + Sync + 'static + Serialize + for<'de> Deserialize<'de> + Validate,
{
    pub async fn new(
        node_id: NodeId,
        addr: IpAddr,
        base_port: u16,
        config: Config,
        validator_verifier: Arc<ValidatorVerifier>,
    ) -> Self {
        aptos_logger::info!(
            "Starting UDP network service for node {} at {}:{}-{}",
            node_id,
            addr,
            base_port,
            base_port + config.peers.len() as u16 - 1
        );

        let (tx, rx) = aptos_channel::new(QueueStyle::LIFO, 16, None);
        let mut socks = vec![];

        for (peer_id, (peer_addr, peer_base_port)) in config.peers.iter().cloned().enumerate() {
            let bind_addr = SocketAddr::new(addr, base_port + peer_id as u16);
            let sock = Arc::new(UdpSocket::bind(bind_addr).await.unwrap());
            let peer_addr = SocketAddr::new(peer_addr, peer_base_port + node_id as u16);

            sock.connect(peer_addr).await.unwrap();
            socks.push(sock.clone());
            tokio::spawn(Self::recv_loop(
                peer_id,
                sock,
                tx.clone(),
                config.peer_concurrency_level,
                validator_verifier.clone(),
            ));
        }

        Self {
            recv: rx,
            sender: Arc::new(UdpNetworkServiceSender {
                node_id,
                self_send: tx,
                socks,
            }),
        }
    }

    async fn send(&self, peers: std::ops::Range<NodeId>, msg: M) {
        let sender = self.sender.clone();

        tokio::spawn(async move {
            // Avoid serializing the message if we are sending the message only to ourselves.
            if peers.len() == 1 && peers.start == sender.node_id {
                sender.self_send(msg);
                return;
            }

            let data = bcs::to_bytes(&msg).unwrap();

            if data.len() > MAX_MESSAGE_SIZE {
                // Panicking because this is most likely caused by a bug in the code and needs
                // to be discovered ASAP.
                panic!("Trying to send a message that is too large: {}", data.len());
            }

            // Bypass the network for self-sends.
            if peers.contains(&sender.node_id) {
                sender.self_send(msg);
            }

            delay_injection().await;

            // TODO: should I use FuturesUnordered instead?
            let mut futures = vec![];
            for peer in peers {
                if peer != sender.node_id {
                    if drop_injection() {
                        aptos_logger::warn!("Dropping a message to {}", peer);
                        continue;
                    }
                    futures.push(sender.socks[peer as usize].send(&data).map(|_| ()));
                }
            }
            join_all(futures).await;
        });
    }

    async fn recv_loop(
        peer_id: NodeId,
        recv_socket: Arc<UdpSocket>,
        tx: aptos_channel::Sender<NodeId, (NodeId, M)>,
        concurrency_level: usize,
        validator_verifier: Arc<ValidatorVerifier>,
    ) {
        let mut bufs = Vec::new();
        for _ in 0..concurrency_level {
            bufs.push(Arc::new(Mutex::new([0; MAX_MESSAGE_SIZE])));
        }

        let mut cur_buf = 0;

        loop {
            let mut buf = bufs[cur_buf].clone().lock_owned().await;
            match recv_socket.recv(&mut *buf).await {
                Ok(n) => {
                    if n == 0 {
                        aptos_logger::error!("Received empty message from {}", peer_id);
                        continue;
                    }
                    if n == MAX_MESSAGE_SIZE {
                        aptos_logger::error!("Received message too large from {}", peer_id);
                        continue;
                    }

                    let tx = tx.clone();
                    cur_buf = (cur_buf + 1) % bufs.len();

                    if concurrency_level == 1 {
                        Self::process_message(buf, n, peer_id, tx, validator_verifier.clone()).await;
                    } else {
                        tokio::spawn(Self::process_message(buf, n, peer_id, tx, validator_verifier.clone()));
                    }
                },
                Err(err) => {
                    aptos_logger::error!("Error receiving message from {}: {}", peer_id, err);
                    break;
                },
            }
        }
    }

    async fn process_message(
        buf: OwnedMutexGuard<[u8; MAX_MESSAGE_SIZE]>,
        msg_len: usize,
        peer_id: NodeId,
        tx: aptos_channel::Sender<NodeId, (NodeId, M)>,
        validator_verifier: Arc<ValidatorVerifier>,
    ) {
        let data = &*buf;
        if let Ok(msg) = bcs::from_bytes::<M>(&data[..msg_len]) {
            if let Ok(()) = msg.validate(&validator_verifier) {
                tx.push(peer_id, (peer_id, msg)).unwrap();
            } else {
                aptos_logger::error!("Invalid message from {}", peer_id);
            }
        } else {
            aptos_logger::error!("Failed to deserialize message from {}", peer_id);
        }
    }
}

impl<M> NetworkService for UdpNetworkService<M>
where
    M: Send + Sync + 'static + Serialize + for<'de> Deserialize<'de> + Validate,
{
    type Message = M;

    async fn unicast(&self, data: Self::Message, target: NodeId) {
        self.send(target..target + 1, data).await
    }

    async fn multicast(&self, data: Self::Message) {
        self.send(0..self.sender.socks.len() as NodeId, data).await
    }

    async fn recv(&mut self) -> (NodeId, M) {
        self.recv.select_next_some().await
    }

    fn n_nodes(&self) -> usize {
        self.sender.socks.len()
    }
}
