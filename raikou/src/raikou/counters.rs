use aptos_metrics_core::{register_histogram, register_histogram_vec, Histogram, HistogramVec};
use once_cell::sync::Lazy;

pub static RAIKOU_BATCH_CONSENSUS_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "raikou_batch_consensus_latency",
        "Raikou Batch Consensus Latency",
    )
    .unwrap()
});

pub static RAIKOU_BLOCK_CONSENSUS_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "raikou_block_consensus_latency",
        "Raikou Block Consensus Latnecy",
        &["is_proposer"],
    )
    .unwrap()
});
