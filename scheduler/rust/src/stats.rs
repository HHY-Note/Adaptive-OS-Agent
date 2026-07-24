// SPDX-License-Identifier: GPL-2.0-only

use crate::identity::TaskClass;
use crate::identity::{ProcessKey, TaskKey};
use serde::{Deserialize, Serialize};

/// Monotonic userspace counters describing scheduling decisions and failures.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchedulerStats {
    /// Valid kernel events consumed by the engine.
    pub events_processed: u64,
    /// Events rejected because their identity or generation was stale.
    pub stale_events: u64,
    /// Commands successfully queued for BPF consumption.
    pub refill_commands: u64,
    /// Commands rolled back because the BPF queue was full.
    pub command_queue_full: u64,
    /// BPF command rejection events matched to reservations.
    pub command_rejects: u64,
    /// Rejections indexed by the stable ABI reason code; index zero is unknown.
    pub command_rejects_by_reason: [u64; 13],
    /// Commands submitted through the bounded urgent preemption lane.
    pub preempt_dispatches: u64,
    /// Latency requests that actually overrode a non-latency root EEVDF choice.
    pub latency_slo_admissions: u64,
    /// Latency commands selected directly by root EEVDF without an SLO override.
    pub root_latency_dispatches: u64,
    /// At-risk latency requests left to root EEVDF because the SLO budget was empty.
    pub latency_budget_denials: u64,
    /// Urgent candidates rejected because their disruption cost budget was empty.
    pub preemption_budget_denials: u64,
    /// Urgent candidates suppressed until the latency request or victim made progress.
    pub repeated_preemptions_avoided: u64,
    /// Urgent latency dispatches indexed by the class they displaced.
    pub latency_preemptions_by_victim_class: [u64; 3],
    /// Partially consumed EEVDF requests resumed with their original deadline.
    pub request_resumptions: u64,
    /// Planned cross-CPU placements indexed by selected workload class.
    pub planned_migrations_by_class: [u64; 3],
    /// Placements sharing a physical core with staged or running sibling work.
    pub smt_busy_placements_by_class: [u64; 3],
    /// Samples used to estimate the userspace-to-BPF command delivery overhead.
    pub dispatch_overhead_samples: u64,
    /// Sum of bounded command delivery overhead samples.
    pub dispatch_overhead_ns: u64,
    /// Maximum Rust-side submitted slot depth observed for any CPU.
    pub max_normal_staged_depth: u64,
    /// Actual runtime charged to each workload class.
    pub runtime_by_class_ns: [u64; 3],
    /// Commands generated for each workload class.
    pub dispatches_by_class: [u64; 3],
    /// New task identities rejected at the configured engine bound.
    pub task_capacity_hits: u64,
    /// Dispatches deferred while the reservation table was full.
    pub reservation_capacity_hits: u64,
    /// Lazy pool indexes rebuilt before reaching their physical-node bound.
    pub pool_compactions: u64,
    /// Behavior windows suppressed because their event history was incomplete.
    pub bad_behavior_windows: u64,
    /// Number of transitions into a state that requires controlled detach.
    pub degraded_transitions: u64,
}

impl SchedulerStats {
    /// Charges actual CPU service to one workload class with saturation.
    pub fn record_runtime(&mut self, class: TaskClass, runtime_ns: u64) {
        let value = &mut self.runtime_by_class_ns[class.index()];
        *value = value.saturating_add(runtime_ns);
    }

    /// Records one submitted command and the hard depth-one invariant.
    pub fn record_dispatch(&mut self, class: TaskClass, staged_depth: u64) {
        let value = &mut self.dispatches_by_class[class.index()];
        *value = value.saturating_add(1);
        self.refill_commands = self.refill_commands.saturating_add(1);
        self.max_normal_staged_depth = self.max_normal_staged_depth.max(staged_depth);
    }

    /// Records one command that may preempt a less urgent local task.
    pub fn record_preempt(&mut self, victim_class: TaskClass) {
        self.preempt_dispatches = self.preempt_dispatches.saturating_add(1);
        let value = &mut self.latency_preemptions_by_victim_class[victim_class.index()];
        *value = value.saturating_add(1);
    }

    /// Records the locality and SMT consequences of one planned placement.
    pub fn record_placement(
        &mut self,
        class: TaskClass,
        previous_cpu: Option<u32>,
        target_cpu: u32,
        sibling_busy: bool,
    ) {
        if previous_cpu.is_some_and(|previous| previous != target_cpu) {
            let value = &mut self.planned_migrations_by_class[class.index()];
            *value = value.saturating_add(1);
        }
        if sibling_busy {
            let value = &mut self.smt_busy_placements_by_class[class.index()];
            *value = value.saturating_add(1);
        }
    }

    /// Adds one bounded residual between predicted CPU wait and actual start.
    pub fn record_dispatch_overhead(&mut self, sample_ns: u64) {
        self.dispatch_overhead_samples = self.dispatch_overhead_samples.saturating_add(1);
        self.dispatch_overhead_ns = self.dispatch_overhead_ns.saturating_add(sample_ns);
    }
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
