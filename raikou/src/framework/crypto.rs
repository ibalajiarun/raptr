// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::framework::NodeId;
use aptos_crypto::{
    bls12381,
    bls12381::{PrivateKey, PublicKey},
    hash::CryptoHash,
    Genesis, SigningKey, VerifyingKey,
};
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_types::validator_signer::ValidatorSigner;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct SignatureVerifier {
    public_keys: Arc<Vec<PublicKey>>,
}

impl SignatureVerifier {
    pub fn new(public_keys: Vec<PublicKey>) -> Self {
        SignatureVerifier {
            public_keys: Arc::new(public_keys),
        }
    }

    /// Verify the correctness of a signature of a message by a known author.
    pub fn verify<T: Serialize + CryptoHash>(
        &self,
        author: NodeId,
        message: &T,
        signature: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        self.public_keys[author].verify_struct_signature(message, signature)
    }

    pub fn verify_aggregate_signatures<T: CryptoHash + Serialize>(
        &self,
        nodes: impl IntoIterator<Item = NodeId>,
        messages: Vec<&T>,
        signature: &bls12381::Signature,
    ) -> anyhow::Result<()> {
        let public_keys: Vec<_> = nodes
            .into_iter()
            .map(|node| &self.public_keys[node])
            .collect();

        signature.verify_aggregate(&messages, &public_keys)
    }

    pub fn aggregate_signatures(
        &self,
        partial_signatures: impl IntoIterator<Item = bls12381::Signature>,
    ) -> anyhow::Result<bls12381::Signature> {
        let signatures = partial_signatures.into_iter().collect();

        bls12381::Signature::aggregate(signatures)
    }
}

#[derive(Clone)]
pub struct Signer {
    // A hack to be compatible with aptos codebase.
    // ValidatorSigner does not expose the private key.
    aptos_signer: Arc<ValidatorSigner>,
}

impl Signer {
    pub fn new(aptos_signer: Arc<ValidatorSigner>) -> Self {
        Signer { aptos_signer }
    }

    pub fn sign<T: Serialize + CryptoHash>(
        &self,
        message: &T,
    ) -> anyhow::Result<bls12381::Signature> {
        Ok(self.aptos_signer.sign(message)?)
    }
}

/// Returns a nonsense signature.
/// Used as a placeholder.
pub fn empty_signature() -> bls12381::Signature {
    static SIGNATURE: std::sync::OnceLock<bls12381::Signature> = std::sync::OnceLock::new();

    #[derive(CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
    struct DummyMessage {}

    SIGNATURE
        .get_or_init(|| {
            let private_key = PrivateKey::genesis();
            private_key.sign(&DummyMessage {}).unwrap()
        })
        .clone()
}
