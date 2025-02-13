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

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_crypto::hash::CryptoHash;
    use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
    use rand::{rngs::StdRng, SeedableRng};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    /// A simple test message.
    /// The derives enable both BCS hashing and Serde serialization.
    #[derive(CryptoHasher, BCSCryptoHash, Serialize, Deserialize, Debug, PartialEq)]
    struct TestMessage {
        value: u64,
    }

    /// Helper: Create a deterministic private key for testing purposes.
    /// This is used for aggregate and multi-signature tests.
    fn deterministic_main_private_key(node_id: usize) -> bls12381::PrivateKey {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&node_id.to_le_bytes());
        let mut rng = StdRng::from_seed(seed);
        bls12381::PrivateKey::generate(&mut rng)
    }

    // ============================
    // Positive Tests
    // ============================

    /// Verify that a tagged signature (created via `Signer::sign_tagged`)
    /// is correctly verified.
    #[test]
    fn test_tagged_signature_verification() -> anyhow::Result<()> {
        let n_tags = 3;
        let node_id = 0;
        let vs = ValidatorSigner::random(None);

        // Use the validator signer's public key.
        let public_keys = vec![vs.public_key()];
        let signer = Signer::new(Arc::new(vs), node_id, n_tags);
        let msg = TestMessage { value: 42 };

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, n_tags);

        // Sign and verify for each tag.
        for tag in 0..n_tags {
            let sig = signer.sign_tagged(&msg, tag)?;
            signature_verifier.verify_tagged(node_id, &msg, tag, &sig)?;
        }
        Ok(())
    }

    /// Verify that multiple tagged signatures (from different nodes and tags)
    /// can be aggregated and verified as a tagged multi-signature.
    #[test]
    fn test_tagged_multi_signature_verification() -> anyhow::Result<()> {
        let n_tags = 3;
        let num_nodes: usize = 3;
        let mut signers = Vec::new();
        let mut public_keys = Vec::new();

        // Create a signer for each node.
        for node_id in 0..num_nodes {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&node_id.to_le_bytes());
            let vs = ValidatorSigner::random(seed);
            public_keys.push(vs.public_key());
            signers.push(Signer::new(Arc::new(vs), node_id, n_tags));
        }

        let msg = TestMessage { value: 100 };

        // Let each node use a tag equal to (node_id mod n_tags).
        let tags: Vec<usize> = (0..num_nodes).map(|node_id| node_id % n_tags).collect();

        // Each signer signs with its corresponding tag.
        let mut sigs = Vec::new();
        for (node_id, signer) in signers.iter().enumerate() {
            let tag = tags[node_id];
            let sig = signer.sign_tagged(&msg, tag)?;
            sigs.push(sig);
        }

        // Aggregate the signatures.
        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, n_tags);
        let aggregated_sig = signature_verifier.aggregate_signatures(sigs)?;

        // Verify the aggregated tagged multi-signature.
        signature_verifier.verify_tagged_multi_signature(
            0..num_nodes,
            &msg,
            tags,
            &aggregated_sig,
        )?;
        Ok(())
    }

    /// Verify that a “normal” (non-tagged) signature is correctly verified.
    #[test]
    fn test_non_tagged_signature_verification() -> anyhow::Result<()> {
        let vs = ValidatorSigner::random(None);
        let node_id = 0;
        let msg = TestMessage { value: 7 };
        let sig = vs.sign(&msg)?;
        let public_keys = vec![vs.public_key()];
        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, 1);
        signature_verifier.verify(node_id, &msg, &sig)?;
        Ok(())
    }

    /// Verify aggregate signature verification for a set of (different) messages,
    /// where only a subset (7 out of 10) of the nodes participate.
    #[test]
    fn test_aggregate_signature_verification() -> anyhow::Result<()> {
        let total_nodes = 10;
        // Define participating nodes (7 out of 10).
        let participating_nodes = vec![0, 2, 4, 6, 7, 8, 9];

        let mut msgs = Vec::new();
        let mut individual_sigs = Vec::new();
        let mut public_keys = Vec::new();

        // Create distinct messages for each node.
        for node_id in 0..total_nodes {
            msgs.push(TestMessage {
                value: node_id as u64,
            });
        }

        // Sign each message using a deterministic private key.
        for node_id in 0..total_nodes {
            let private_key = deterministic_main_private_key(node_id);
            let sig = private_key.sign(&msgs[node_id])?;
            individual_sigs.push(sig);
            public_keys.push(private_key.public_key());
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, 1);

        // Only consider messages and signatures from participating nodes.
        let participating_msgs: Vec<&TestMessage> =
            participating_nodes.iter().map(|&i| &msgs[i]).collect();
        let participating_sigs: Vec<bls12381::Signature> = participating_nodes
            .iter()
            .map(|&i| individual_sigs[i].clone())
            .collect();

        // Aggregate the partial signatures.
        let aggregated_sig = signature_verifier.aggregate_signatures(participating_sigs)?;

        // Verify the aggregated signature.
        signature_verifier.verify_aggregate_signatures(
            participating_nodes,
            participating_msgs,
            &aggregated_sig,
        )?;
        Ok(())
    }

    /// Verify multi-signature verification where all nodes sign the same message,
    /// but only a subset (7 out of 10) of the nodes participate.
    #[test]
    fn test_multi_signature_verification() -> anyhow::Result<()> {
        let total_nodes = 10;
        // Define participating nodes (7 out of 10).
        let participating_nodes = vec![1, 3, 4, 6, 7, 8, 9];
        let msg = TestMessage { value: 999 };

        let mut individual_sigs = Vec::new();
        let mut public_keys = Vec::new();

        // All nodes sign the same message.
        for node_id in 0..total_nodes {
            let private_key = deterministic_main_private_key(node_id);
            let sig = private_key.sign(&msg)?;
            individual_sigs.push(sig);
            public_keys.push(private_key.public_key());
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, 1);

        // Filter the signatures for participating nodes.
        let participating_sigs: Vec<bls12381::Signature> = participating_nodes
            .iter()
            .map(|&i| individual_sigs[i].clone())
            .collect();

        // Aggregate the signatures.
        let aggregated_sig = signature_verifier.aggregate_signatures(participating_sigs)?;

        // Verify the multi-signature.
        signature_verifier.verify_multi_signature(participating_nodes, &msg, &aggregated_sig)?;
        Ok(())
    }

    /// Verify tagged multi-signature verification where only a subset (5 out of 10)
    /// of the nodes participate.
    #[test]
    fn test_tagged_multi_signature_verification_subset() -> anyhow::Result<()> {
        let total_nodes: usize = 10;
        let n_tags = 3;

        // Create signers and collect public keys.
        let mut signers = Vec::new();
        let mut public_keys = Vec::new();
        for node_id in 0..total_nodes {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&node_id.to_le_bytes());
            let vs = ValidatorSigner::random(seed);
            public_keys.push(vs.public_key());
            signers.push(Signer::new(Arc::new(vs), node_id, n_tags));
        }

        let msg = TestMessage { value: 500 };

        // Select a subset of participating nodes.
        let participating_nodes = vec![1, 3, 5, 7, 9];

        // Each participating node uses a tag (node_id mod n_tags).
        let tags: Vec<usize> = participating_nodes
            .iter()
            .map(|&node_id| node_id % n_tags)
            .collect();

        let mut sigs = Vec::new();
        for &node_id in &participating_nodes {
            let signer = &signers[node_id];
            let tag = node_id % n_tags;
            let sig = signer.sign_tagged(&msg, tag)?;
            sigs.push(sig);
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, n_tags);
        let aggregated_sig = signature_verifier.aggregate_signatures(sigs)?;

        // Verify the tagged multi-signature.
        signature_verifier.verify_tagged_multi_signature(
            participating_nodes,
            &msg,
            tags,
            &aggregated_sig,
        )?;
        Ok(())
    }

    // ============================
    // Negative Tests
    // ============================

    /// Aggregate signature negative test:
    /// Verification should fail if one of the messages is altered.
    #[test]
    fn test_aggregate_signature_negative() -> anyhow::Result<()> {
        let total_nodes = 10;
        let participating_nodes = vec![0, 2, 4, 6, 7, 8, 9];

        let mut msgs = Vec::new();
        let mut individual_sigs = Vec::new();
        let mut public_keys = Vec::new();

        // Create messages for all nodes.
        for node_id in 0..total_nodes {
            msgs.push(TestMessage {
                value: node_id as u64,
            });
        }

        // Sign each message.
        for node_id in 0..total_nodes {
            let private_key = deterministic_main_private_key(node_id);
            let sig = private_key.sign(&msgs[node_id])?;
            individual_sigs.push(sig);
            public_keys.push(private_key.public_key());
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, 1);

        let participating_msgs: Vec<&TestMessage> =
            participating_nodes.iter().map(|&i| &msgs[i]).collect();
        let participating_sigs: Vec<bls12381::Signature> = participating_nodes
            .iter()
            .map(|&i| individual_sigs[i].clone())
            .collect();

        let aggregated_sig = signature_verifier.aggregate_signatures(participating_sigs)?;

        // Deliberately alter one message.
        let mut wrong_msgs = participating_msgs.clone();
        if let Some(first_msg) = wrong_msgs.get_mut(0) {
            *first_msg = &TestMessage { value: 9999 };
        }

        let result = signature_verifier.verify_aggregate_signatures(
            participating_nodes.clone(),
            wrong_msgs,
            &aggregated_sig,
        );
        assert!(
            result.is_err(),
            "Aggregate signature verification should fail when messages are altered"
        );
        Ok(())
    }

    /// Multi-signature negative test:
    /// Verification should fail when using the wrong message.
    #[test]
    fn test_multi_signature_negative() -> anyhow::Result<()> {
        let total_nodes = 10;
        let participating_nodes = vec![1, 3, 4, 6, 7, 8, 9];
        let msg = TestMessage { value: 999 };

        let mut individual_sigs = Vec::new();
        let mut public_keys = Vec::new();

        // All nodes sign the same message.
        for node_id in 0..total_nodes {
            let private_key = deterministic_main_private_key(node_id);
            let sig = private_key.sign(&msg)?;
            individual_sigs.push(sig);
            public_keys.push(private_key.public_key());
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, 1);

        let participating_sigs: Vec<bls12381::Signature> = participating_nodes
            .iter()
            .map(|&i| individual_sigs[i].clone())
            .collect();

        let aggregated_sig = signature_verifier.aggregate_signatures(participating_sigs)?;

        // Use a wrong message for verification.
        let wrong_msg = TestMessage { value: 1234 };
        let result = signature_verifier.verify_multi_signature(
            participating_nodes,
            &wrong_msg,
            &aggregated_sig,
        );
        assert!(
            result.is_err(),
            "Multi-signature verification should fail when using the wrong message"
        );
        Ok(())
    }

    /// Tagged multi-signature negative test:
    /// Verification should fail if an incorrect tag vector is provided.
    #[test]
    fn test_tagged_multi_signature_negative() -> anyhow::Result<()> {
        let total_nodes: usize = 10;
        let n_tags = 3;

        let mut signers = Vec::new();
        let mut public_keys = Vec::new();
        for node_id in 0..total_nodes {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&node_id.to_le_bytes());
            let vs = ValidatorSigner::random(seed);
            public_keys.push(vs.public_key());
            signers.push(Signer::new(Arc::new(vs), node_id, n_tags));
        }

        let msg = TestMessage { value: 500 };
        let participating_nodes = vec![1, 3, 5, 7, 9];

        // Build the correct tags vector...
        let mut correct_tags: Vec<usize> = participating_nodes
            .iter()
            .map(|&node_id| node_id % n_tags)
            .collect();
        // ...and then modify one tag to be incorrect.
        if let Some(first) = correct_tags.get_mut(0) {
            *first = (*first + 1) % n_tags;
        }

        let mut sigs = Vec::new();
        // Each signer signs with the proper (correct) tag.
        for &node_id in &participating_nodes {
            let signer = &signers[node_id];
            let correct_tag = node_id % n_tags;
            let sig = signer.sign_tagged(&msg, correct_tag)?;
            sigs.push(sig);
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier = SignatureVerifier::new(public_keys, dummy_verifier, n_tags);
        let aggregated_sig = signature_verifier.aggregate_signatures(sigs)?;

        // Verification using the modified (incorrect) tag vector should fail.
        let result = signature_verifier.verify_tagged_multi_signature(
            participating_nodes,
            &msg,
            correct_tags,
            &aggregated_sig,
        );
        assert!(
            result.is_err(),
            "Tagged multi-signature verification should fail when tag indices are incorrect"
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "bench"))]
mod benches {
    use super::*;
    use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
    use criterion::{criterion_group, criterion_main, Criterion};
    use rand::{rngs::StdRng, SeedableRng};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    // --------------------------------------------------------------------------
    // Data Structures for Benchmarking
    // --------------------------------------------------------------------------

    /// Message for the aggregate signature benchmark.
    /// Here the tag (a small number from 0 to 8) is embedded as part of the message.
    #[derive(CryptoHasher, BCSCryptoHash, Serialize, Deserialize, Debug, PartialEq)]
    struct AggMessage {
        base: u64,
        tag: u8,
    }

    /// Message for the tagged multi-signature benchmark.
    /// This message is identical across nodes; the tag is applied via the signing key.
    #[derive(CryptoHasher, BCSCryptoHash, Serialize, Deserialize, Debug, PartialEq)]
    struct BaseMessage {
        base: u64,
    }

    // --------------------------------------------------------------------------
    // Benchmark: 75-out-of-100 Aggregate Signatures
    // (Tag is embedded in the message)
    // --------------------------------------------------------------------------
    fn bench_aggregate_signatures(c: &mut Criterion) {
        const TOTAL_NODES: usize = 100;
        const PARTICIPANTS: usize = 75;

        // Generate 100 deterministic private keys and corresponding public keys.
        let mut private_keys = Vec::with_capacity(TOTAL_NODES);
        let mut public_keys = Vec::with_capacity(TOTAL_NODES);
        for i in 0..TOTAL_NODES {
            let pk = deterministic_main_private_key(i);
            public_keys.push(pk.public_key());
            private_keys.push(pk);
        }

        // For each participating node, create a message that embeds a small tag.
        // (We use i mod 9 to ensure the tag is a number from 0 to 8.)
        let mut messages = Vec::with_capacity(PARTICIPANTS);
        for i in 0..PARTICIPANTS {
            messages.push(AggMessage {
                base: 42,
                tag: (i % 9) as u8,
            });
        }

        // Each participating node signs its corresponding message.
        let mut signatures = Vec::with_capacity(PARTICIPANTS);
        for i in 0..PARTICIPANTS {
            let sig = private_keys[i]
                .sign(&messages[i])
                .expect("failed to sign aggregate message");
            signatures.push(sig);
        }

        // List of participating node indices.
        let participating_nodes: Vec<usize> = (0..PARTICIPANTS).collect();

        // Create a dummy validator verifier (required for constructing SignatureVerifier).
        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        // Use the full set of 100 public keys.
        let signature_verifier = SignatureVerifier::new(public_keys.clone(), dummy_verifier, 1);

        // Prepare a vector of references to messages.
        let message_refs: Vec<&AggMessage> = messages.iter().collect();

        c.bench_function("Aggregate Signatures (75/100)", |b| {
            b.iter(|| {
                // Aggregate the 75 signatures.
                let aggregated_sig = signature_verifier
                    .aggregate_signatures(signatures.clone())
                    .unwrap();
                // Verify the aggregated signature.
                signature_verifier
                    .verify_aggregate_signatures(
                        participating_nodes.clone(),
                        message_refs.clone(),
                        &aggregated_sig,
                    )
                    .unwrap();
            })
        });
    }

    // --------------------------------------------------------------------------
    // Benchmark: 75-out-of-100 Tagged Multi-Signatures
    // (The tag is provided via the signer’s tagged key, not embedded in the message)
    // --------------------------------------------------------------------------
    fn bench_tagged_multi_signatures(c: &mut Criterion) {
        const TOTAL_NODES: usize = 100;
        const PARTICIPANTS: usize = 75;
        const N_TAGS: usize = 9; // small tags: 0 to 8

        // Create 100 signers using ValidatorSigner::random.
        // Each signer has an associated set of tag keys.
        let mut signers = Vec::with_capacity(TOTAL_NODES);
        let mut public_keys = Vec::with_capacity(TOTAL_NODES);
        for i in 0..TOTAL_NODES {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&i.to_le_bytes());
            let vs = ValidatorSigner::random(seed);
            public_keys.push(vs.public_key());
            signers.push(Signer::new(Arc::new(vs), i, N_TAGS));
        }

        // The base message is the same for all participating nodes.
        let msg = BaseMessage { base: 42 };

        // Select the first 75 nodes as participants and assign each a tag (i mod N_TAGS).
        let participating_nodes: Vec<usize> = (0..PARTICIPANTS).collect();
        let tags: Vec<usize> = participating_nodes.iter().map(|&i| i % N_TAGS).collect();

        // Each participating node produces a tag signature.
        let mut signatures = Vec::with_capacity(PARTICIPANTS);
        for &i in &participating_nodes {
            let tag = i % N_TAGS;
            let sig = signers[i]
                .sign_tagged(&msg, tag)
                .expect("failed to sign tagged message");
            signatures.push(sig);
        }

        let dummy_verifier = Arc::new(ValidatorVerifier::new(vec![]));
        let signature_verifier =
            SignatureVerifier::new(public_keys.clone(), dummy_verifier, N_TAGS);

        c.bench_function("Tagged Multi Signatures (75/100)", |b| {
            b.iter(|| {
                let aggregated_sig = signature_verifier
                    .aggregate_signatures(signatures.clone())
                    .unwrap();
                signature_verifier
                    .verify_tagged_multi_signature(
                        participating_nodes.clone(),
                        &msg,
                        tags.clone(),
                        &aggregated_sig,
                    )
                    .unwrap();
            })
        });
    }

    criterion_group!(
        benches,
        bench_aggregate_signatures,
        bench_tagged_multi_signatures
    );
    criterion_main!(benches);
}
