// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

//! Use `--features sim-types` to run with simulator types.
//! Otherwise, aptos types will be used.

#[cfg(not(feature = "sim-types"))]
pub use aptos_types::*;

#[cfg(feature = "sim-types")]
pub use sim_types::*;

pub use common::*;

mod aptos_types;
mod common;
mod sim_types;
