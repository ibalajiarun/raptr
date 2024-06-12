pub mod delays;
pub mod framework;
pub mod jolteon;
pub mod jolteon_fast_qs;
pub mod leader_schedule;
pub mod metrics;
pub mod multichain;
pub mod raikou;
pub mod utils;

pub type Slot = i64;

pub const PBFT_TIMEOUT: u32 = 5; // in Deltas
pub const JOLTEON_TIMEOUT: u32 = 3; // in Deltas
