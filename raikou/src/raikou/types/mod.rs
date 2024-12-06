// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

//! Use `--features sim-types` to run with simulator types.
//! Otherwise, aptos types will be used.

#[cfg(none)]
pub use aptos_types::*;
pub use common::*;
// #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub use sim_types::*;

#[cfg(none)]
mod aptos_types;
pub mod common;
// #[cfg(all(feature = "sim-types", not(feature = "force-aptos-types")))]
pub mod sim_types;
