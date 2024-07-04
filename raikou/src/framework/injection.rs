// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;
use rand::{Rng, thread_rng};

pub async fn delay_injection() {
    if cfg!(feature = "inject-delays") {
        let delay = Duration::from_millis(thread_rng().gen_range(50, 150));
        tokio::time::sleep(delay).await;
    }
}

pub fn drop_injection() -> bool {
    if cfg!(feature = "inject-drops") {
        thread_rng().gen_bool(0.01)
    } else {
        false
    }
}
