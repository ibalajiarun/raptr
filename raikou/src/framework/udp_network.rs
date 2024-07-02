// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::format;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::{FutureExt, StreamExt};
use futures::future::join_all;
use futures::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use tokio::join;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use aptos_channels::aptos_channel;
use aptos_channels::message_queues::QueueStyle;

use crate::framework::network::NetworkService;
use crate::framework::NodeId;

pub trait Validate {
    fn validate(&self) -> anyhow::Result<()>;
}

pub struct Config {
    pub peers: Vec<String>,
    pub base_port: u16,
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
        self.self_send.push(self.node_id, (self.node_id, msg)).unwrap();
    }
}

impl<M> UdpNetworkService<M>
where
    M: Send + Sync + 'static + Serialize + for<'de> Deserialize<'de> + Validate,
{
    pub async fn new(node_id: NodeId, addr: String, config: Config) -> Self {
        let (tx, rx) = aptos_channel::new(
            QueueStyle::LIFO,
            16,
            None,
        );
        let mut socks = vec![];

        for (peer_id, peer) in config.peers.iter().cloned().enumerate() {
            let bind_addr = format!("{}:{}", addr, config.base_port + peer_id as u16);
            let sock = Arc::new(UdpSocket::bind(bind_addr).await.unwrap());
            let peer_addr = format!("{}:{}", peer, config.base_port + node_id as u16);
            sock.connect(peer_addr).await.unwrap();
            socks.push(sock.clone());
            tokio::spawn(Self::recv_loop(
                peer_id,
                sock,
                tx.clone(),
                config.peer_concurrency_level
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

            // Bypass the network for self-sends.
            if peers.contains(&sender.node_id) {
                sender.self_send(msg);
            }

            // TODO: should I use FuturesUnordered instead?
            let mut futures = vec![];
            for peer in peers {
                if peer != sender.node_id {
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
    ) {
        let mut bufs = Vec::new();
        for _ in 0..concurrency_level {
            bufs.push(Arc::new(Mutex::new([0; 1024])));
        }

        let mut cur_buf = 0;

        loop {
            let mut buf = bufs[cur_buf].clone().lock_owned().await;
            let n = recv_socket.recv(&mut *buf).await.unwrap();

            let tx = tx.clone();
            cur_buf = (cur_buf + 1) % bufs.len();

            tokio::spawn(async move {
                let data = &*buf;
                if let Ok(msg) = bcs::from_bytes::<M>(&data[..n]) {
                    if let Ok(()) = msg.validate() {
                        tx.push(peer_id, (peer_id, msg)).unwrap();
                    } else {
                        aptos_logger::error!("Invalid message from {}", peer_id);
                    }
                } else {
                    aptos_logger::error!("Failed to deserialize message from {}", peer_id);
                }
            });
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
