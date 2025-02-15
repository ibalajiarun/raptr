// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{crypto::SignatureVerifier, NodeId},
    raikou::{
        protocol,
        types::{BatchHash, Prefix, Round, N_SUB_BLOCKS},
    },
};
use anyhow::Context;
use aptos_crypto::bls12381::Signature;
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use bitvec::prelude::BitVec;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    ops::Range,
    sync::Arc,
};

pub type BatchId = i64;

#[derive(Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchInfo {
    pub author: NodeId,
    pub batch_id: BatchId,
    pub digest: BatchHash,
}

impl BatchInfo {
    pub fn author(&self) -> NodeId {
        self.author
    }

    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    pub fn digest(&self) -> &BatchHash {
        &self.digest
    }
}

impl Debug for BatchInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ node: {}, sn: {}, digest: {:#x} }}",
            self.author, self.batch_id, &self.digest
        )
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct AC {
    pub info: BatchInfo,
    pub signers: BitVec,
    pub multi_signature: Signature,
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct AcVoteSignatureData {
    pub batch_digest: BatchHash,
}

impl AC {
    pub fn info(&self) -> &BatchInfo {
        &self.info
    }

    pub fn verify(&self, sig_verifier: &SignatureVerifier, ac_quorum: usize) -> anyhow::Result<()> {
        let signers = self.signers.iter_ones().collect_vec();

        if signers.len() < ac_quorum {
            return Err(anyhow::anyhow!("AC has too few signers"));
        }

        let sig_data = AcVoteSignatureData {
            batch_digest: self.info.digest,
        };

        sig_verifier.verify_multi_signature(signers, &sig_data, &self.multi_signature)
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct Payload {
    round: Round,
    author: NodeId,
    data: Arc<PayloadData>,
    include_acs: bool,
    sub_blocks: Range<Prefix>,
}

impl Debug for Payload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("round", &self.round)
            .field("author", &self.author)
            .finish()
    }
}

#[derive(Hash, Serialize, Deserialize)]
struct PayloadData {
    acs: Vec<AC>,
    sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS],
}

impl Payload {
    pub fn new(
        round: Round,
        author: NodeId,
        acs: Vec<AC>,
        sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS],
    ) -> Self {
        Self {
            round,
            author,
            data: Arc::new(PayloadData { acs, sub_blocks }),
            include_acs: true,
            sub_blocks: 0..N_SUB_BLOCKS,
        }
    }

    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        assert!(prefix <= self.data.sub_blocks.len());

        Self {
            round: self.round,
            author: self.author,
            data: self.data.clone(),
            include_acs: true,
            sub_blocks: 0..prefix,
        }
    }

    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        assert!(range.end <= self.data.sub_blocks.len());

        Self {
            round: self.round,
            author: self.author,
            data: self.data.clone(),
            include_acs: false,
            sub_blocks: range,
        }
    }

    pub fn empty(round: Round, leader: NodeId) -> Self {
        let sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS] = Default::default();
        Self::new(round, leader, vec![], sub_blocks)
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn author(&self) -> NodeId {
        self.author
    }

    pub fn acs(&self) -> &Vec<AC> {
        if self.include_acs {
            &self.data.acs
        } else {
            static EMPTY: Vec<AC> = Vec::new();
            &EMPTY
        }
    }

    pub fn sub_blocks(&self) -> impl ExactSizeIterator<Item = &Vec<BatchInfo>> {
        (&self.data.sub_blocks[self.sub_blocks.clone()]).into_iter()
    }

    pub fn sub_block(&self, index: usize) -> &Vec<BatchInfo> {
        &self.data.sub_blocks[index]
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.acs()
            .iter()
            .map(|ac| &ac.info)
            .chain(self.sub_blocks().flatten())
    }

    pub fn verify<S>(&self, verifier: &protocol::Verifier<S>) -> anyhow::Result<()> {
        for ac in self.acs() {
            ac.verify(&verifier.sig_verifier, verifier.config.ac_quorum)
                .context("Invalid AC")?;
        }
        Ok(())
    }
}
