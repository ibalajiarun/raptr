// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{crypto::SignatureVerifier, NodeId},
    raikou::{
        protocol,
        types::{BatchHash, Prefix, Round, N_SUB_BLOCKS},
    },
};
use anyhow::{ensure, Context};
use aptos_bitvec::BitVec;
use aptos_crypto::bls12381::Signature;
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
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
pub struct PoA {
    pub info: BatchInfo,
    pub signers: BitVec,
    pub multi_signature: Signature,
}

#[derive(Clone, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
pub struct PoAVoteSignatureData {
    pub batch_digest: BatchHash,
}

impl PoA {
    pub fn info(&self) -> &BatchInfo {
        &self.info
    }

    pub fn verify(
        &self,
        sig_verifier: &SignatureVerifier,
        poa_quorum: usize,
    ) -> anyhow::Result<()> {
        let signers = self.signers.iter_ones().collect_vec();

        if signers.len() < poa_quorum {
            return Err(anyhow::anyhow!("PoA has too few signers"));
        }

        let sig_data = PoAVoteSignatureData {
            batch_digest: self.info.digest,
        };

        sig_verifier.verify_multi_signature(signers, &sig_data, &self.multi_signature)
    }
}

#[derive(Clone, Hash, Serialize, Deserialize)]
pub struct Payload {
    round: Option<Round>,
    author: NodeId,
    data: Arc<PayloadData>,
    include_poas: bool,
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
    poas: Vec<PoA>,
    sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS],
}

impl Payload {
    pub fn new(
        round: Option<Round>,
        author: NodeId,
        poas: Vec<PoA>,
        sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS],
    ) -> Self {
        Self {
            round,
            author,
            data: Arc::new(PayloadData { poas, sub_blocks }),
            include_poas: true,
            sub_blocks: 0..N_SUB_BLOCKS,
        }
    }

    pub fn with_prefix(&self, prefix: Prefix) -> Self {
        assert!(prefix <= self.data.sub_blocks.len());

        Self {
            round: self.round,
            author: self.author,
            data: self.data.clone(),
            include_poas: true,
            sub_blocks: 0..prefix,
        }
    }

    pub fn take_sub_blocks(&self, range: Range<Prefix>) -> Self {
        assert!(range.end <= self.data.sub_blocks.len());

        Self {
            round: self.round,
            author: self.author,
            data: self.data.clone(),
            include_poas: false,
            sub_blocks: range,
        }
    }

    pub fn empty(round: Round, leader: NodeId) -> Self {
        let sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS] = Default::default();
        Self::new(Some(round), leader, vec![], sub_blocks)
    }

    pub fn round(&self) -> Round {
        self.round.unwrap()
    }

    pub fn author(&self) -> NodeId {
        self.author
    }

    pub fn poas(&self) -> &Vec<PoA> {
        if self.include_poas {
            &self.data.poas
        } else {
            static EMPTY: Vec<PoA> = Vec::new();
            &EMPTY
        }
    }

    pub fn sub_blocks(&self) -> impl ExactSizeIterator<Item = &Vec<BatchInfo>> {
        (&self.data.sub_blocks[self.sub_blocks.clone()]).into_iter()
    }

    pub fn num_opt_batches(&self) -> usize {
        self.sub_blocks()
            .map(|sub_block| sub_block.len())
            .sum::<usize>()
    }

    pub fn sub_block(&self, index: usize) -> &Vec<BatchInfo> {
        &self.data.sub_blocks[index]
    }

    pub fn all(&self) -> impl Iterator<Item = &BatchInfo> {
        self.poas()
            .iter()
            .map(|poa| &poa.info)
            .chain(self.sub_blocks().flatten())
    }

    pub fn verify(
        &self,
        verifier: &protocol::Verifier,
        round: Option<Round>,
        author: NodeId,
    ) -> anyhow::Result<()> {
        ensure!(
            self.round == round,
            "Invalid round. Expected: {:?}, got: {:?}",
            round,
            self.round
        );
        ensure!(
            self.author == author,
            "Invalid author. Expected: {:?}, got: {:?}",
            author,
            self.author
        );
        ensure!(
            self.sub_blocks().len() == N_SUB_BLOCKS,
            "Received a partial payload: Sub-blocks excluded"
        );

        for poa in self.poas() {
            poa.verify(&verifier.sig_verifier, verifier.config.poa_quorum)
                .context("Invalid PoA")?;
        }
        Ok(())
    }
}

pub fn split_into_sub_blocks(mut opt_batches: Vec<BatchInfo>) -> [Vec<BatchInfo>; N_SUB_BLOCKS] {
    let mut sub_blocks: [Vec<BatchInfo>; N_SUB_BLOCKS] = Default::default();

    fn div_ceil(dividend: usize, divisor: usize) -> usize {
        if dividend % divisor == 0 {
            dividend / divisor
        } else {
            dividend / divisor + 1
        }
    }

    let num_chunks = sub_blocks.len();
    let mut chunks_remaining = num_chunks;
    while chunks_remaining > 0 {
        let chunk_size = div_ceil(opt_batches.len(), chunks_remaining);
        let remaining = opt_batches.split_off(chunk_size);
        sub_blocks[num_chunks - chunks_remaining] = opt_batches;
        opt_batches = remaining;

        chunks_remaining -= 1;
    }

    sub_blocks
}

pub fn merge_payloads(
    round: Round,
    author: NodeId,
    payloads: impl IntoIterator<Item = (Payload, BitVec, BitVec)>,
) -> Payload {
    let payloads = payloads.into_iter().collect_vec();

    let proofs = payloads
        .iter()
        .flat_map(|(payload, proofs_mask, _)| {
            payload
                .poas()
                .iter()
                .enumerate()
                .filter(|(i, _)| proofs_mask.is_set(*i as u16))
                .map(|(_, proof)| proof.clone())
        })
        .collect_vec()
        .into();

    let n_opt_batches = payloads
        .iter()
        .map(|(_, _, batches_mask)| batches_mask.count_ones())
        .sum::<u32>() as usize;

    let mut opt_batches = Vec::with_capacity(n_opt_batches);
    for (payload, _, batch_mask) in payloads {
        for (i, batch) in payload
            .sub_blocks()
            .flat_map(|sub_block| sub_block.iter())
            .enumerate()
        {
            if batch_mask.is_set(i as u16) {
                opt_batches.push(batch.clone());
            }
        }
    }

    let sub_blocks = split_into_sub_blocks(opt_batches);
    Payload::new(Some(round), author, proofs, sub_blocks)
}
