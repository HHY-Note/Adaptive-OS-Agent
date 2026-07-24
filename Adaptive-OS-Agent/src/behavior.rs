// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::identity::{ProcessKey, TaskClass, TaskKey};

/// Scheduler-provided quality marker for one behavior window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowQuality {
    /// Event continuity was sufficient for behavior voting.
    Good,
    /// Event overflow, gaps, or timestamp reversal invalidated this window.
    Bad,
}

/// Fixed-period execution facts received over the local scheduler socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BehaviorWindow {
    /// Stable task lifetime.
    pub task: TaskKey,
    /// Stable owning process image.
    pub process: ProcessKey,
    /// Monotonic report sequence within this task lifetime.
    pub window_sequence: u64,
    /// First monotonic timestamp represented by this report.
    pub window_start_ns: u64,
    /// Closing monotonic timestamp.
    pub window_end_ns: u64,
    /// Actual runtime accumulated from STOP events.
    pub runtime_ns: u64,
    /// Enqueue-to-running delay accumulated by the scheduler.
    pub runnable_wait_ns: u64,
    /// Time spent sleeping after voluntary blocking.
    pub sleep_ns: u64,
    /// Number of accepted runnable incarnations.
    pub enqueue_count: u64,
    /// Number of enqueues following a voluntary block.
    pub wakeup_count: u64,
    /// Number of actual starts.
    pub run_count: u64,
    /// Runtime samples in <250 us, <1 ms, <4 ms, and >=4 ms bins.
    pub run_burst_histogram: [u64; 4],
    /// Runnable-wait samples using the same four bins.
    pub wait_histogram: [u64; 4],
    /// Stops that remained runnable after using at least 90% of their slice.
    pub slice_exhaustion_count: u64,
    /// Stops that blocked rather than remaining runnable.
    pub voluntary_block_count: u64,
    /// Number of observed CPU migrations.
    pub migration_count: u64,
    /// Number of starts on the previous CPU.
    pub previous_cpu_hit_count: u64,
    /// Age of this stable task lifetime at the end of the window.
    pub task_age_ns: u64,
    /// Whether this report can participate in classification evidence.
    pub quality: WindowQuality,
}

/// Derives only strong evidence; ordinary mixed work deliberately returns None.
pub(crate) fn classify_window(window: BehaviorWindow) -> Option<TaskClass> {
    const MIN_TASK_AGE_NS: u64 = 5_000_000_000;
    const MIN_RUNTIME_NS: u64 = 20_000_000;
    const MIN_SAMPLES: u64 = 32;

    if window.quality != WindowQuality::Good
        || window.window_sequence == 0
        || window.window_end_ns <= window.window_start_ns
        || window.task_age_ns < MIN_TASK_AGE_NS
    {
        return None;
    }
    if window.enqueue_count.max(window.run_count) < MIN_SAMPLES
        && window.wakeup_count < MIN_SAMPLES
        && window.runtime_ns < MIN_RUNTIME_NS
    {
        return None;
    }

    let duration = window.window_end_ns - window.window_start_ns;
    let utilization_per_mille = window.runtime_ns.saturating_mul(1000) / duration;
    let short_bursts = window.run_burst_histogram[0].saturating_add(window.run_burst_histogram[1]);
    let long_bursts = window.run_burst_histogram[2].saturating_add(window.run_burst_histogram[3]);

    if window.wakeup_count.saturating_mul(2) >= window.enqueue_count
        && short_bursts.saturating_mul(10) >= window.run_count.saturating_mul(7)
        && window.voluntary_block_count.saturating_mul(2) >= window.run_count
        && window.slice_exhaustion_count.saturating_mul(10) <= window.run_count
        && utilization_per_mille <= 500
        && window.runnable_wait_ns > 0
    {
        return Some(TaskClass::Latency);
    }
    if window.run_count > 0
        && long_bursts.saturating_mul(10) >= window.run_count.saturating_mul(7)
        && window.slice_exhaustion_count.saturating_mul(2) >= window.run_count
        && window.voluntary_block_count.saturating_mul(10) <= window.run_count
        && utilization_per_mille >= 700
    {
        return Some(TaskClass::Throughput);
    }
    None
}
