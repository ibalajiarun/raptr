use crate::raikou::sim_types;

// To avoid having numerous generic parameters while still maintaining some flexibility,
// a bunch of type aliases are used.

// Common types:

/// Type-safe wrapper for a batch hash value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BatchHash(pub HashValue);

impl std::fmt::LowerHex for BatchHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::LowerHex;
        self.0.fmt(f)
    }
}

impl std::fmt::UpperHex for BatchHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::UpperHex;
        self.0.fmt(f)
    }
}

/// Type-safe wrapper for a block hash value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockHash(pub HashValue);

impl BlockHash {
    pub fn genesis() -> Self {
        Self(0)
    }
}

impl std::fmt::LowerHex for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::UpperHex for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

pub type Round = i64; // Round number.

pub type Prefix = usize;

// Aptos types and functions:
//
// pub type HashValue = aptos_crypto::hash::HashValue;
// pub type BatchInfo = aptos_consensus_types::proof_of_store::BatchInfo;
// pub type AC = aptos_consensus_types::proof_of_store::ProofOfStore;
// pub type BlockPayload = ...

// Simulator types and functions:

pub use sim_types::hash;
pub type Txn = ();
pub type BatchId = sim_types::BatchId;
pub type HashValue = sim_types::HashValue;
pub type BatchInfo = sim_types::BatchInfo;
pub type AC = sim_types::AC;
pub type Payload = sim_types::Payload;
