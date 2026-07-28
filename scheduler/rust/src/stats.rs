// SPDX-License-Identifier: GPL-2.0-only

use crate::identity::{ProcessKey, TaskKey};
use serde::{Deserialize, Serialize};

/// Monotonic userspace counters describing scheduling decisions and failures.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchedulerStats {
    /// Valid kernel events consumed by the engine.
    pub events_processed: u64,
    /// Events rejected because their identity or generation was stale.
    pub stale_events: u64,
    /// New task identities rejected at the configured engine bound.
    pub task_capacity_hits: u64,
    /// Behavior windows suppressed because their event history was incomplete.
    pub bad_behavior_windows: u64,
    /// Number of transitions into a state that requires controlled detach.
    pub degraded_transitions: u64,
}

/// Whether a per-task behavior window is complete enough for Agent voting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowQuality {
    /// Sequence and timestamp checks found no event gap.
    Good,
    /// Missing, out-of-order, or contradictory events make the window advisory only.
    Bad,
}

/// One fixed-period task behavior report sent from scheduler to Agent.
///
/// These are scheduling facts, not a classification decision. Agent combines
/// them with process/thread semantics and may perform at most one correction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskBehaviorWindow {
    /// Stable task lifetime observed in this period.
    pub task: TaskKey,
    /// Stable process image owning the task.
    pub process: ProcessKey,
    /// Monotonic report sequence within this task lifetime.
    pub window_sequence: u64,
    /// First monotonic timestamp represented by the accumulator.
    pub window_start_ns: u64,
    /// Snapshot timestamp closing the period.
    pub window_end_ns: u64,
    /// Actual CPU service from matching STOP events.
    pub runtime_ns: u64,
    /// ENQUEUE-to-RUNNING delay accumulated in the period.
    pub runnable_wait_ns: u64,
    /// Time spent sleeping after a voluntary block.
    pub sleep_ns: u64,
    /// Number of accepted runnable incarnations.
    pub enqueue_count: u64,
    /// Enqueues following a voluntary block.
    pub wakeup_count: u64,
    /// Number of matching RUNNING events.
    pub run_count: u64,
    /// Runtime sample counts in <250 us, <1 ms, <4 ms, and >=4 ms bins.
    pub run_burst_histogram: [u64; 4],
    /// Runnable-wait sample counts using the same four bins.
    pub wait_histogram: [u64; 4],
    /// Stops that remained runnable after consuming at least 90% of the slice.
    pub slice_exhaustion_count: u64,
    /// Stops that blocked instead of remaining runnable.
    pub voluntary_block_count: u64,
    /// Runs whose actual CPU differed from the previous actual CPU.
    pub migration_count: u64,
    /// Runs that returned to the previous CPU.
    pub previous_cpu_hit_count: u64,
    /// Age of the stable task lifetime at the end of this window.
    pub task_age_ns: u64,
    /// Completeness result used to suppress unsafe behavior votes.
    pub quality: WindowQuality,
}
