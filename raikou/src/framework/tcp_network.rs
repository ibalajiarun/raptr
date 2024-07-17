// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::framework::{
    injection::{delay_injection, drop_injection},
    network::{NetworkService, Validate},
    NodeId,
};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use futures::{future::join_all, stream::FuturesUnordered, FutureExt, StreamExt};
use aptos_types::validator_verifier::{self, ValidatorVerifier};

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    mem::size_of,
    net::{IpAddr, SocketAddr},
    sync::{atomic::AtomicUsize, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    join,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, OwnedMutexGuard},
};

pub type MessageSizeTag = u32;
pub const BUF_SIZE: usize = 32 * 1024;
pub const MAX_MESSAGE_SIZE: usize = BUF_SIZE;

pub const RETRY_MILLIS: u64 = 1000;

pub struct Config {
    pub peers: Vec<SocketAddr>,
    pub streams_per_peer: usize,
}

pub struct TcpNetworkService<M> {
    recv: aptos_channel::Receiver<NodeId, (NodeId, M)>,
    sender: Arc<TcpNetworkServiceSender<M>>,
}

struct TcpNetworkServiceSender<M> {
    node_id: NodeId,
    self_send: aptos_channel::Sender<NodeId, (NodeId, M)>,
    streams: Vec<PeerStreams>,
}

struct PeerStreams {
    streams: Vec<Arc<Mutex<TcpStream>>>,
    next: AtomicUsize,
}

impl PeerStreams {
    async fn next(&self) -> OwnedMutexGuard<TcpStream> {
        let next = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.streams[next % self.streams.len()]
            .clone()
            .lock_owned()
            .await
    }
}

impl<M> TcpNetworkServiceSender<M> {
    fn self_send(&self, msg: M) {
        self.self_send
            .push(self.node_id, (self.node_id, msg))
            .unwrap();
    }
}

impl<M> TcpNetworkService<M>
where
    M: Send + Sync + 'static + Serialize + for<'de> Deserialize<'de> + Validate + std::fmt::Debug,
{
    pub async fn new(
        node_id: NodeId,
        addr: SocketAddr,
        config: Config,
        validator_verifier: Arc<ValidatorVerifier>,
    ) -> Self {
        aptos_logger::info!("TCPNET: Starting TCP network service for node {} at {}", node_id, addr);

        let (self_send, recv) = aptos_channel::new(QueueStyle::LIFO, 16, None);

        // Start the receiver task
        let listener = Self::create_listener(addr).await;
        tokio::spawn(Self::listen_loop(listener, self_send.clone(), validator_verifier));

        let mut streams = Vec::new();

        // NB: can (should?) be parallelized
        for (peer_id, peer_addr) in config.peers.iter().enumerate() {
            let mut peer_streams = Vec::new();

            if peer_id != node_id {
                for _ in 0..config.streams_per_peer {
                    let mut stream = Self::create_stream(peer_addr).await;
                    stream.write_all(&node_id.to_be_bytes()).await.unwrap();
                    peer_streams.push(Arc::new(Mutex::new(stream)));
                }
            }

            streams.push(PeerStreams {
                streams: peer_streams,
                next: AtomicUsize::new(0),
            });
        }

        let sender = Arc::new(TcpNetworkServiceSender {
            node_id,
            self_send,
            streams,
        });

        TcpNetworkService { recv, sender }
    }

    async fn create_listener(addr: SocketAddr) -> TcpListener {
        loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    return listener;
                },
                Err(err) => {
                    aptos_logger::error!(
                        "TCPNET: Failed to bind listener to {}: {}. Retry in {} millis",
                        addr,
                        err,
                        RETRY_MILLIS,
                    );
                    tokio::time::sleep(Duration::from_millis(RETRY_MILLIS)).await;
                },
            }
        }
    }

    async fn create_stream(peer_addr: &SocketAddr) -> TcpStream {
        loop {
            match TcpStream::connect(peer_addr).await {
                Ok(stream) => {
                    aptos_logger::info!("TCPNET: Connected to peer {}", peer_addr);
                    return stream;
                },
                Err(err) => {
                    aptos_logger::error!(
                        "TCPNET: Failed to connect to peer {}: {}. Retry in {} millis",
                        peer_addr,
                        err,
                        RETRY_MILLIS,
                    );
                    tokio::time::sleep(Duration::from_millis(RETRY_MILLIS)).await;
                },
            }
        }
    }

    async fn send(&self, target: std::ops::Range<NodeId>, msg: M) {
        let sender = self.sender.clone();

        tokio::spawn(async move {
            // Avoid serializing the message if we are sending the message only to ourselves.
            if target.len() == 1 && target.start == sender.node_id {
                sender.self_send(msg);
                return;
            }

            let data = Arc::new(bcs::to_bytes(&msg).unwrap());

            if data.len() > MAX_MESSAGE_SIZE {
                // Panicking because this is most likely caused by a bug in the code and needs
                // to be discovered ASAP.
                panic!("Trying to send a message that is too large: {}", data.len());
            }

            // Bypass the network for self-sends.
            if target.contains(&sender.node_id) {
                sender.self_send(msg);
            }

            for peer_id in target {
                if peer_id == sender.node_id {
                    continue;
                }

                let data = data.clone();
                let stream = sender.streams[peer_id].next().await;
                tokio::spawn(async move {
                    if drop_injection() {
                        aptos_logger::warn!("TCPNET: Dropping a message to {}", peer_id);
                        return;
                    }

                    delay_injection().await;

                    if let Err(err) = Self::send_msg(stream, data).await {
                        aptos_logger::error!(
                            "TCPNET: Failed to send message to peer {}: {}",
                            peer_id,
                            err,
                        );
                    }
                });
            }
        });
    }

    async fn send_msg(
        mut stream: OwnedMutexGuard<TcpStream>,
        data: Arc<Vec<u8>>,
    ) -> anyhow::Result<()> {
        stream
            .write_all(&(data.len() as MessageSizeTag).to_be_bytes())
            .await?;
        stream.write_all(&data).await?;
        Ok(())
    }

    async fn listen_loop(
        tcp_listener: TcpListener,
        self_send: aptos_channel::Sender<NodeId, (NodeId, M)>,
        validator_verifier: Arc<ValidatorVerifier>,
    ) {
        loop {
            let (stream, _) = tcp_listener.accept().await.unwrap();
            tokio::spawn(Self::listen_stream(stream, self_send.clone(), validator_verifier.clone()));
        }
    }

    async fn listen_stream(
        mut stream: TcpStream,
        self_send: aptos_channel::Sender<NodeId, (NodeId, M)>,
        validator_verifier: Arc<ValidatorVerifier>,
    ) {
        let mut buf = [0; BUF_SIZE];

        stream
            .read_exact(&mut buf[..size_of::<NodeId>()])
            .await
            .unwrap();
        let peer_id = NodeId::from_be_bytes(buf[..size_of::<NodeId>()].try_into().unwrap());

        loop {
            match Self::read_message(&mut stream, validator_verifier.clone(), &mut buf).await {
                Ok(msg) => {
                    self_send.push(peer_id, (peer_id, msg)).unwrap();
                },
                Err(err) => {
                    aptos_logger::error!(
                        "TCPNET: Failed to read message from peer {}, closing the stream: {}",
                        peer_id,
                        err
                    );
                    break;
                },
            }
        }
    }

    async fn read_message(stream: &mut TcpStream, validator_verifier: Arc<ValidatorVerifier>, buf: &mut [u8; BUF_SIZE]) -> anyhow::Result<M> {
        stream
            .read_exact(&mut buf[..size_of::<MessageSizeTag>()])
            .await?;
        let msg_size =
            MessageSizeTag::from_be_bytes(buf[..size_of::<MessageSizeTag>()].try_into().unwrap())
                as usize;
        if msg_size > MAX_MESSAGE_SIZE {
            return Err(anyhow::anyhow!("Message size too large: {}", msg_size));
        }
        stream.read_exact(&mut buf[..msg_size]).await?;
        let msg: M = bcs::from_bytes(&buf[..msg_size])?;
        match msg.validate(&validator_verifier) {
            Ok(()) => Ok(msg),
            Err(err) => Err(anyhow::anyhow!("Failed to validate message {:?} due to error {}", msg, err)),
        }
    }
}

impl<M> NetworkService for TcpNetworkService<M>
where
    M: Send + Sync + 'static + Serialize + for<'de> Deserialize<'de> + Validate + std::fmt::Debug,
{
    type Message = M;

    async fn unicast(&self, data: Self::Message, target: NodeId) {
        self.send(target..target + 1, data).await
    }

    async fn multicast(&self, data: Self::Message) {
        self.send(0..self.sender.streams.len() as NodeId, data)
            .await
    }

    async fn recv(&mut self) -> (NodeId, M) {
        self.recv.select_next_some().await
    }

    fn n_nodes(&self) -> usize {
        self.sender.streams.len()
    }
}
