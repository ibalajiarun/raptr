//! Use `--features sim-types` to run with native (simulator) types.
//! Otherwise, aptos-compatible types will be used (for reusing Aptos quorum store).

#[cfg(any(not(feature = "sim-types"), feature = "force-aptos-types"))]
pub use aptos_types::*;
pub use common::*;
#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub use native_types::*;

#[cfg(any(not(feature = "sim-types"), feature = "force-aptos-types"))]
mod aptos_types;
pub mod common;
#[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod native_types;
