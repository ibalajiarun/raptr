// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::framework::{
    crypto::{Signer, Verifier},
    injection::{delay_injection, drop_injection},
    network::{NetworkMessage, NetworkSender, NetworkService, Validate},
    NodeId,
};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use futures::{future::join_all, stream::FuturesUnordered, FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{format, Debug},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, OwnedMutexGuard},
};

pub const MAX_MESSAGE_SIZE: usize = 1024;

pub struct Config {
    pub peers: Vec<(IpAddr, u16)>,
    pub peer_concurrency_level: usize,
}

struct UdpNetworkSenderInner<M> {
    node_id: NodeId,
    self_send: aptos_channel::Sender<NodeId, (NodeId, M)>,
    socks: Vec<Arc<UdpSocket>>,
    signer: Signer,
}

impl<M> UdpNetworkSenderInner<M> {
    fn self_send(&self, msg: M) {
        self.self_send
            .push(self.node_id, (self.node_id, msg))
            .unwrap();
    }
}

pub struct UdpNetworkSender<M> {
    inner: Arc<UdpNetworkSenderInner<M>>,
}

impl<M> Clone for UdpNetworkSender<M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<M> NetworkSender for UdpNetworkSender<M>
where
    M: NetworkMessage + Serialize + for<'de> Deserialize<'de> + Debug,
{
    type Message = M;

    async fn send(&self, mut msg: Self::Message, targets: Vec<NodeId>) {
        let inner = self.inner.clone();

        tokio::spawn(async move {
            if let Err(err) = msg.sign(&inner.signer) {
                panic!("UPDNET: Failed to sign message: {:#}", err);
            }

            // Avoid serializing the message if we are sending the message only to ourselves.
            if targets.len() == 1 && targets[0] == inner.node_id {
                inner.self_send(msg);
                return;
            }

            let data = bcs::to_bytes(&msg).unwrap();

            if data.len() > MAX_MESSAGE_SIZE {
                // Panicking because this is most likely caused by a bug in the code and needs
                // to be discovered ASAP.
                panic!("Trying to send a message that is too large: {}", data.len());
            }

            // Bypass the network for self-sends.
            if targets.contains(&inner.node_id) {
                inner.self_send(msg);
            }

            delay_injection().await;

            // TODO: should I use FuturesUnordered instead?
            let mut futures = vec![];

            for peer_id in targets {
                if peer_id == inner.node_id {
                    continue;
                }

                // TODO: should we `spawn` this instead?
                futures.push(inner.socks[peer_id as usize].send(&data).map(|_| ()));
            }
            join_all(futures).await;
        });
    }

    fn n_nodes(&self) -> usize {
        self.inner.socks.len()
    }
}

pub struct UdpNetworkService<M> {
    recv: aptos_channel::Receiver<NodeId, (NodeId, M)>,
    sender: UdpNetworkSender<M>,
}

impl<M> UdpNetworkService<M>
where
    M: NetworkMessage + Serialize + for<'de> Deserialize<'de> + Debug,
{
    pub async fn new(
        node_id: NodeId,
        addr: IpAddr,
        base_port: u16,
        config: Config,
        signer: Signer,
        verifier: Verifier,
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
                verifier.clone(),
            ));
        }

        Self {
            recv: rx,
            sender: UdpNetworkSender {
                inner: Arc::new(UdpNetworkSenderInner {
                    node_id,
                    self_send: tx,
                    socks,
                    signer,
                }),
            },
        }
    }

    async fn recv_loop(
        peer_id: NodeId,
        recv_socket: Arc<UdpSocket>,
        tx: aptos_channel::Sender<NodeId, (NodeId, M)>,
        concurrency_level: usize,
        verifier: Verifier,
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

                    if drop_injection() {
                        aptos_logger::warn!("UPDNET: Dropping a message from {}", peer_id);
                        continue;
                    }

                    let tx = tx.clone();
                    cur_buf = (cur_buf + 1) % bufs.len();

                    if concurrency_level > 1 || cfg!(feature = "inject-delays") {
                        let verifier = verifier.clone();

                        tokio::spawn(async move {
                            delay_injection().await;
                            Self::process_message(buf, n, peer_id, tx, verifier);
                        });
                    } else {
                        Self::process_message(buf, n, peer_id, tx, verifier.clone());
                    }
                },

                Err(err) => {
                    aptos_logger::error!("Error receiving message from {}: {:#}", peer_id, err);
                    break;
                },
            }
        }
    }

    fn parse_and_validate_message(
        buf: OwnedMutexGuard<[u8; MAX_MESSAGE_SIZE]>,
        msg_len: usize,
        peer_id: NodeId,
        verifier: Verifier,
    ) -> anyhow::Result<M> {
        let data = &*buf;

        let msg = bcs::from_bytes::<M>(&data[..msg_len])?;

        if let Err(e) = msg.validate(peer_id, &verifier) {
            return Err(anyhow::anyhow!(
                "Failed to validate message {:?} due to error {}",
                msg,
                e
            ));
        }

        Ok(msg)
    }

    fn process_message(
        buf: OwnedMutexGuard<[u8; MAX_MESSAGE_SIZE]>,
        msg_len: usize,
        peer_id: NodeId,
        tx: aptos_channel::Sender<NodeId, (NodeId, M)>,
        verifier: Verifier,
    ) {
        match Self::parse_and_validate_message(buf, msg_len, peer_id, verifier) {
            Ok(msg) => tx.push(peer_id, (peer_id, msg)).unwrap(),
            Err(e) => aptos_logger::error!("Error processing message from {}: {:#}", peer_id, e),
        }
    }
}

impl<M> NetworkSender for UdpNetworkService<M>
where
    M: NetworkMessage + Serialize + for<'de> Deserialize<'de> + Debug,
{
    type Message = M;

    async fn send(&self, msg: Self::Message, targets: Vec<NodeId>) {
        self.sender.send(msg, targets).await;
    }

    fn n_nodes(&self) -> usize {
        self.sender.n_nodes()
    }
}

impl<M> NetworkService for UdpNetworkService<M>
where
    M: NetworkMessage + Serialize + for<'de> Deserialize<'de> + Debug,
{
    type Sender = UdpNetworkSender<M>;

    fn new_sender(&self) -> Self::Sender {
        self.sender.clone()
    }

    async fn recv(&mut self) -> (NodeId, M) {
        self.recv.select_next_some().await
    }
}
