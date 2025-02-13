// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::framework::NodeId;
use aptos_crypto::{
    bls12381::{self, PublicKey},
    hash::CryptoHash,
    Genesis, PrivateKey, Signature, SigningKey, Uniform,
};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::{validator_signer::ValidatorSigner, validator_verifier::ValidatorVerifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// FIXME: for testing and prototyping only, obviously not safe in prod.
fn deterministic_tag_private_keys(node_id: usize, n_tags: usize) -> Vec<bls12381::PrivateKey> {
    use rand::SeedableRng;

    let mut seed = [0; 32];
    seed[0..8].copy_from_slice(&node_id.to_le_bytes());
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    (0..n_tags)
        .map(|_| bls12381::PrivateKey::generate(&mut rng))
        .collect()
}

#[derive(Clone)]
pub struct SignatureVerifier {
    inner: Arc<VerifierInner>,
}

struct VerifierInner {
    public_keys: Vec<PublicKey>,
    tag_public_keys: Vec<Vec<PublicKey>>,
    // For compatibility with aptos codebase.
    verifier: Arc<ValidatorVerifier>,
}

impl SignatureVerifier {
    pub fn new(
        public_keys: Vec<PublicKey>,
        verifier: Arc<ValidatorVerifier>,
        n_tags: usize,
    ) -> Self {
        let tag_public_keys = (0..public_keys.len())
            .into_iter()
            .map(|node_id| {
                deterministic_tag_private_keys(node_id, n_tags)
                    .into_iter()
                    .map(|private_key| private_key.public_key())
                    .collect()
            })
            .collect();

        SignatureVerifier {
            inner: Arc::new(VerifierInner {
                public_keys,
                tag_public_keys,
                verifier,
            }),
        }
    }

    /// Verify the correctness of a signature of a message by a known author.
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        author: NodeId,
        message: &T,
        signature: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        signature.verify(message, &self.inner.public_keys[author])
    }

    pub fn verify_aggregate_signatures<T: CryptoHash + Serialize>(
        &self,
        nodes: impl IntoIterator<Item = NodeId>,
        messages: Vec<&T>,
        signature: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        let public_keys: Vec<_> = nodes
            .into_iter()
            .map(|node| &self.inner.public_keys[node])
            .collect();

        signature.verify_aggregate(&messages, &public_keys)
    }

    pub fn verify_multi_signature<T: CryptoHash + Serialize>(
        &self,
        nodes: impl IntoIterator<Item = NodeId>,
        message: &T,
        multi_sig: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        let pub_keys: Vec<_> = nodes
            .into_iter()
            .map(|node| &self.inner.public_keys[node])
            .collect();

        let aggregated_key = PublicKey::aggregate(pub_keys)?;

        multi_sig.verify(message, &aggregated_key)
    }

    pub fn verify_tagged<T: CryptoHash + Serialize>(
        &self,
        author: NodeId,
        message: &T,
        tag: usize,
        signature: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        signature.verify(message, &self.inner.tag_public_keys[author][tag])
    }

    pub fn verify_tagged_multi_signature<T: CryptoHash + Serialize>(
        &self,
        nodes: impl IntoIterator<Item = NodeId>,
        message: &T,
        tags: impl IntoIterator<Item = usize>,
        signature: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        let pub_keys: Vec<_> = nodes
            .into_iter()
            .zip(tags.into_iter())
            .map(|(node, tag)| &self.inner.tag_public_keys[node][tag])
            .collect();

        let aggregated_key = PublicKey::aggregate(pub_keys)?;
        signature.verify(message, &aggregated_key)
    }

    pub fn aggregate_signatures(
        &self,
        partial_signatures: impl IntoIterator<Item = bls12381::Signature>,
    ) -> anyhow::Result<bls12381::Signature> {
        let signatures = partial_signatures.into_iter().collect();

        bls12381::Signature::aggregate(signatures)
    }

    pub fn aptos_verifier(&self) -> &ValidatorVerifier {
        &self.inner.verifier
    }
}

#[derive(Clone)]
pub struct Signer {
    inner: Arc<SignerInner>,
}

struct SignerInner {
    // A hack to be compatible with aptos codebase.
    // ValidatorSigner does not expose the private key.
    aptos_signer: Arc<ValidatorSigner>,
    tag_private_keys: Vec<bls12381::PrivateKey>,
}

impl Signer {
    pub fn new(aptos_signer: Arc<ValidatorSigner>, node_id: NodeId, n_tags: usize) -> Self {
        Signer {
            inner: Arc::new(SignerInner {
                aptos_signer,
                tag_private_keys: deterministic_tag_private_keys(node_id, n_tags),
            }),
        }
    }

    pub fn sign<T: Serialize + CryptoHash>(
        &self,
        message: &T,
    ) -> anyhow::Result<bls12381::Signature> {
        Ok(self.inner.aptos_signer.sign(message)?)
    }

    pub fn sign_tagged<T: Serialize + CryptoHash>(
        &self,
        message: &T,
        tag: usize,
    ) -> anyhow::Result<bls12381::Signature> {
        Ok(self.inner.tag_private_keys[tag].sign(message)?)
    }
}

/// Returns a nonsense signature.
/// Used as a placeholder.
pub fn dummy_signature() -> bls12381::Signature {
    static SIGNATURE: std::sync::OnceLock<bls12381::Signature> = std::sync::OnceLock::new();

    #[derive(CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
    struct DummyMessage {}

    SIGNATURE
        .get_or_init(|| {
            let private_key = bls12381::PrivateKey::genesis();
            private_key.sign(&DummyMessage {}).unwrap()
        })
        .clone()
}
