// SPDX-License-Identifier: GPL-2.0-only

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::mem::{self, MaybeUninit};
use std::rc::Rc;
use std::slice;

use anyhow::{Context, Result};
use libbpf_rs::libbpf_sys::bpf_object_open_opts;
use libbpf_rs::{Link, MapCore, MapFlags, OpenObject, RingBuffer, RingBufferBuilder};
use log::error;

use crate::bpf_intf;
use crate::bpf_skel::*;
use crate::config::SchedulerConfig;
use crate::identity::TaskKey;
use crate::policy::{CpuPressure, PolicySnapshot};
use crate::process::TaskClassCache;
use crate::topology::CpuTopology;
use crate::wire::{task_control_raw, KernelEvent, WireError};

const VERIFIER_LOG_BYTES: usize = 16 * 1024 * 1024;
const VERIFIER_LOG_REPORT_BYTES: usize = 512 * 1024;

/// Userspace projection of the aggregated per-CPU BPF diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataPlaneStats {
    /// Lifecycle events that could not enter the bounded BPF queue.
    pub event_overflows: u64,
    /// Tasks sent to the global DSQ by safe, missing-context, or liveness paths.
    pub fallback_dispatches: u64,
    /// Runnable instances admitted directly into BPF class pools.
    pub fast_path_enqueues: u64,
    /// Tasks selected by the BPF root and class EEVDF policy.
    pub fast_path_dispatches: u64,
    /// BPF class selections that lost a dequeue or affinity race.
    pub fast_path_dispatch_failures: u64,
    /// Latency tasks dispatched through the native urgent lane.
    pub fast_path_preemptions: u64,
    /// BPF dispatches indexed by Latency, Balanced, and Throughput.
    pub fast_path_dispatches_by_class: [u64; 3],
    /// Dispatches served from the destination CPU's own class queues.
    pub fast_path_local_dispatches: u64,
    /// Bounded remote scans started after local queues were exhausted.
    pub fast_path_steal_attempts: u64,
    /// Tasks moved from a remote CPU-owned class queue.
    pub fast_path_remote_steals: u64,
    /// Fast-path lifecycle events omitted after a task reached Locked stage.
    pub fast_path_events_suppressed: u64,
    /// Fast-path tasks inserted directly into an atomically claimed idle CPU.
    pub fast_path_direct_dispatches: u64,
    /// Uncontended Throughput epochs continued without a dispatch cycle.
    pub fast_path_prev_continuations: u64,
    /// Small Normal sources admitted for stealing while their CPU ran Latency.
    pub fast_path_steal_latency_source_admissions: u64,
    /// Sole Normal successors retained during one bounded Latency request.
    pub fast_path_steal_latency_successor_deferrals: u64,
    /// Remote Normal scans that found no source allowed to spare work.
    pub fast_path_steal_scan_exhaustions: u64,
    /// Dispatches that ended empty while classified remote backlog remained.
    pub fast_path_remote_backlog_no_dispatches: u64,
    /// Remote steal attempts rejected by another destination's source claim.
    pub fast_path_steal_claim_conflicts: u64,
    /// Dispatch callbacks skipped remote scanning because no fast task waited.
    pub fast_path_empty_steal_skips: u64,
    /// Urgent fast-path requests held back by victim-runtime or rate limits.
    pub fast_path_preemption_throttles: u64,
    /// Urgent requests retained until the victim reaches its bounded granule.
    pub fast_path_preemption_deferrals: u64,
    /// Latency dispatches given temporary root weight because peers were queued.
    pub fast_path_latency_backlog_boosts: u64,
    /// Bounded scans for Latency work queued on another CPU or core shard.
    pub fast_path_latency_steal_attempts: u64,
    /// Latency requests rescued from another CPU or core shard.
    pub fast_path_latency_remote_steals: u64,
    /// Wake selections that moved away from the task's previous CPU, by class.
    pub fast_path_select_migrations_by_class: [u64; 3],
    /// Tasks that ran on a CPU other than their selected owner, by class.
    pub fast_path_remote_dispatches_by_class: [u64; 3],
    /// Successfully consumed urgent reschedule requests, by requesting class.
    pub fast_path_preemptions_by_class: [u64; 3],
    /// Running classes displaced by successfully consumed urgent reschedules.
    pub fast_path_preemption_victims_by_class: [u64; 3],
    /// Latency dispatches charged against a competing-work budget.
    pub fast_path_latency_budget_charge_events: u64,
    /// Actual Latency runtime charged across competing-work dispatches.
    pub fast_path_latency_budget_runtime_ns: u64,
    /// Sampled task stops with at least one local successor ready.
    pub fast_path_pipeline_ready_samples: u64,
    /// Sampled task stops without a local successor ready.
    pub fast_path_pipeline_empty_samples: u64,
    /// Sum of local Normal queue depths across pipeline samples.
    pub fast_path_pipeline_normal_depth_sum: u64,
    /// Sum of local Latency queue depths across pipeline samples.
    pub fast_path_pipeline_latency_depth_sum: u64,
    /// Throughput wake selections that moved CPU, bucketed by topology distance.
    pub fast_path_throughput_select_migrations_by_locality: [u64; 4],
    /// Throughput work run away from its owner, bucketed by topology distance.
    pub fast_path_throughput_remote_dispatches_by_locality: [u64; 4],
    /// Completed fraction of a Throughput request when it was preempted.
    pub fast_path_throughput_preemption_service_bins: [u64; 4],
    /// Uninterrupted Throughput service before preemption: <500us, <1ms, <2ms, >=2ms.
    pub fast_path_throughput_preemption_runtime_bins: [u64; 4],
    /// Total uninterrupted Throughput runtime before urgent preemption.
    pub fast_path_throughput_preemption_runtime_ns: u64,
    /// Total remaining Throughput request size at urgent preemption.
    pub fast_path_throughput_preemption_request_ns: u64,
    /// Idle source CPUs admitted for stealing despite one queued Normal task.
    pub fast_path_steal_idle_source_admissions: u64,
    /// Idle sources retaining a sole Throughput task for local dispatch.
    pub fast_path_steal_idle_throughput_deferrals: u64,
    /// Latency wake selections that moved CPU, bucketed by topology distance.
    pub fast_path_latency_select_migrations_by_locality: [u64; 4],
    /// Latency work run away from its owner, bucketed by topology distance.
    pub fast_path_latency_remote_dispatches_by_locality: [u64; 4],
    /// Latency steals that kept one request queued on the source lane.
    pub fast_path_latency_remote_steals_preserving_successor: u64,
    /// Last-resort Latency steals that admitted a sole source request.
    pub fast_path_latency_remote_steals_fallback: u64,
    /// Sole Latency requests retained on an already-idle home CPU or core.
    pub fast_path_latency_idle_source_deferrals: u64,
    /// Latency select_cpu calls by default-idle, default-busy, policy-victim, and fallback path.
    pub fast_path_latency_selects_by_path: [u64; 4],
    /// Latency final selections that moved CPU, bucketed by selection path.
    pub fast_path_latency_select_migrations_by_path: [u64; 4],
    /// Immediate PREEMPT kicks indexed by Latency, Balanced, and Throughput.
    pub fast_path_immediate_preemption_kicks_by_class: [u64; 3],
    /// select_cpu calls carrying SCX_WAKE_SYNC, indexed by task class.
    pub fast_path_select_sync_wakeups_by_class: [u64; 3],
    /// SCX_WAKE_SYNC final selections that moved away from prev_cpu, by class.
    pub fast_path_select_sync_migrations_by_class: [u64; 3],
    /// Wide-affinity Balanced tasks inserted into a shared domain overflow.
    pub fast_path_shared_balanced_enqueues: u64,
    /// Shared domain consume calls made while overflow work existed.
    pub fast_path_shared_balanced_dispatch_attempts: u64,
    /// Shared Balanced tasks successfully moved into a local DSQ.
    pub fast_path_shared_balanced_dispatches: u64,
    /// Shared consume attempts that lost a queue or affinity race.
    pub fast_path_shared_balanced_dispatch_failures: u64,
    /// Full-affinity blocked Latency wakeups inserted into a physical-core shard.
    pub fast_path_shared_latency_enqueues: u64,
    /// Shared Latency consume calls made while core-shard work existed.
    pub fast_path_shared_latency_dispatch_attempts: u64,
    /// Shared Latency tasks successfully moved into a local DSQ.
    pub fast_path_shared_latency_dispatches: u64,
    /// Shared Latency consume attempts that lost a queue or affinity race.
    pub fast_path_shared_latency_dispatch_failures: u64,
}

impl From<bpf_intf::adaptive_global_stats> for DataPlaneStats {
    /// Copies the fixed-width BPF record into a stable public Rust type.
    fn from(raw: bpf_intf::adaptive_global_stats) -> Self {
        Self {
            event_overflows: raw.event_overflows,
            fallback_dispatches: raw.fallback_dispatches,
            fast_path_enqueues: raw.fast_path_enqueues,
            fast_path_dispatches: raw.fast_path_dispatches,
            fast_path_dispatch_failures: raw.fast_path_dispatch_failures,
            fast_path_preemptions: raw.fast_path_preemptions,
            fast_path_dispatches_by_class: raw.fast_path_dispatches_by_class,
            fast_path_local_dispatches: raw.fast_path_local_dispatches,
            fast_path_steal_attempts: raw.fast_path_steal_attempts,
            fast_path_remote_steals: raw.fast_path_remote_steals,
            fast_path_events_suppressed: raw.fast_path_events_suppressed,
            fast_path_direct_dispatches: raw.fast_path_direct_dispatches,
            fast_path_prev_continuations: raw.fast_path_prev_continuations,
            fast_path_steal_latency_source_admissions: raw
                .fast_path_steal_latency_source_admissions,
            fast_path_steal_latency_successor_deferrals: raw
                .fast_path_steal_latency_successor_deferrals,
            fast_path_steal_scan_exhaustions: raw.fast_path_steal_scan_exhaustions,
            fast_path_remote_backlog_no_dispatches: raw.fast_path_remote_backlog_no_dispatches,
            fast_path_steal_claim_conflicts: raw.fast_path_steal_claim_conflicts,
            fast_path_empty_steal_skips: raw.fast_path_empty_steal_skips,
            fast_path_preemption_throttles: raw.fast_path_preemption_throttles,
            fast_path_preemption_deferrals: raw.fast_path_preemption_deferrals,
            fast_path_latency_backlog_boosts: raw.fast_path_latency_backlog_boosts,
            fast_path_latency_steal_attempts: raw.fast_path_latency_steal_attempts,
            fast_path_latency_remote_steals: raw.fast_path_latency_remote_steals,
            fast_path_select_migrations_by_class: raw.fast_path_select_migrations_by_class,
            fast_path_remote_dispatches_by_class: raw.fast_path_remote_dispatches_by_class,
            fast_path_preemptions_by_class: raw.fast_path_preemptions_by_class,
            fast_path_preemption_victims_by_class: raw.fast_path_preemption_victims_by_class,
            fast_path_latency_budget_charge_events: raw.fast_path_latency_budget_charge_events,
            fast_path_latency_budget_runtime_ns: raw.fast_path_latency_budget_runtime_ns,
            fast_path_pipeline_ready_samples: raw.fast_path_pipeline_ready_samples,
            fast_path_pipeline_empty_samples: raw.fast_path_pipeline_empty_samples,
            fast_path_pipeline_normal_depth_sum: raw.fast_path_pipeline_normal_depth_sum,
            fast_path_pipeline_latency_depth_sum: raw.fast_path_pipeline_latency_depth_sum,
            fast_path_throughput_select_migrations_by_locality: raw
                .fast_path_throughput_select_migrations_by_locality,
            fast_path_throughput_remote_dispatches_by_locality: raw
                .fast_path_throughput_remote_dispatches_by_locality,
            fast_path_throughput_preemption_service_bins: raw
                .fast_path_throughput_preemption_service_bins,
            fast_path_throughput_preemption_runtime_bins: raw
                .fast_path_throughput_preemption_runtime_bins,
            fast_path_throughput_preemption_runtime_ns: raw
                .fast_path_throughput_preemption_runtime_ns,
            fast_path_throughput_preemption_request_ns: raw
                .fast_path_throughput_preemption_request_ns,
            fast_path_steal_idle_source_admissions: raw.fast_path_steal_idle_source_admissions,
            fast_path_steal_idle_throughput_deferrals: raw
                .fast_path_steal_idle_throughput_deferrals,
            fast_path_latency_select_migrations_by_locality: raw
                .fast_path_latency_select_migrations_by_locality,
            fast_path_latency_remote_dispatches_by_locality: raw
                .fast_path_latency_remote_dispatches_by_locality,
            fast_path_latency_remote_steals_preserving_successor: raw
                .fast_path_latency_remote_steals_preserving_successor,
            fast_path_latency_remote_steals_fallback: raw.fast_path_latency_remote_steals_fallback,
            fast_path_latency_idle_source_deferrals: raw.fast_path_latency_idle_source_deferrals,
            fast_path_latency_selects_by_path: raw.fast_path_latency_selects_by_path,
            fast_path_latency_select_migrations_by_path: raw
                .fast_path_latency_select_migrations_by_path,
            fast_path_immediate_preemption_kicks_by_class: raw
                .fast_path_immediate_preemption_kicks_by_class,
            fast_path_select_sync_wakeups_by_class: raw.fast_path_select_sync_wakeups_by_class,
            fast_path_select_sync_migrations_by_class: raw
                .fast_path_select_sync_migrations_by_class,
            fast_path_shared_balanced_enqueues: raw.fast_path_shared_balanced_enqueues,
            fast_path_shared_balanced_dispatch_attempts: raw
                .fast_path_shared_balanced_dispatch_attempts,
            fast_path_shared_balanced_dispatches: raw.fast_path_shared_balanced_dispatches,
            fast_path_shared_balanced_dispatch_failures: raw
                .fast_path_shared_balanced_dispatch_failures,
            fast_path_shared_latency_enqueues: raw.fast_path_shared_latency_enqueues,
            fast_path_shared_latency_dispatch_attempts: raw
                .fast_path_shared_latency_dispatch_attempts,
            fast_path_shared_latency_dispatches: raw.fast_path_shared_latency_dispatches,
            fast_path_shared_latency_dispatch_failures: raw
                .fast_path_shared_latency_dispatch_failures,
        }
    }
}

impl DataPlaneStats {
    /// Merges one CPU's counters into the process-wide diagnostics snapshot.
    fn accumulate(&mut self, sample: Self) {
        self.event_overflows = self.event_overflows.saturating_add(sample.event_overflows);
        self.fallback_dispatches = self
            .fallback_dispatches
            .saturating_add(sample.fallback_dispatches);
        self.fast_path_enqueues = self
            .fast_path_enqueues
            .saturating_add(sample.fast_path_enqueues);
        self.fast_path_dispatches = self
            .fast_path_dispatches
            .saturating_add(sample.fast_path_dispatches);
        self.fast_path_dispatch_failures = self
            .fast_path_dispatch_failures
            .saturating_add(sample.fast_path_dispatch_failures);
        self.fast_path_preemptions = self
            .fast_path_preemptions
            .saturating_add(sample.fast_path_preemptions);
        for (total, value) in self
            .fast_path_dispatches_by_class
            .iter_mut()
            .zip(sample.fast_path_dispatches_by_class)
        {
            *total = total.saturating_add(value);
        }
        self.fast_path_pipeline_ready_samples = self
            .fast_path_pipeline_ready_samples
            .saturating_add(sample.fast_path_pipeline_ready_samples);
        self.fast_path_pipeline_empty_samples = self
            .fast_path_pipeline_empty_samples
            .saturating_add(sample.fast_path_pipeline_empty_samples);
        self.fast_path_pipeline_normal_depth_sum = self
            .fast_path_pipeline_normal_depth_sum
            .saturating_add(sample.fast_path_pipeline_normal_depth_sum);
        self.fast_path_pipeline_latency_depth_sum = self
            .fast_path_pipeline_latency_depth_sum
            .saturating_add(sample.fast_path_pipeline_latency_depth_sum);
        self.fast_path_local_dispatches = self
            .fast_path_local_dispatches
            .saturating_add(sample.fast_path_local_dispatches);
        self.fast_path_steal_attempts = self
            .fast_path_steal_attempts
            .saturating_add(sample.fast_path_steal_attempts);
        self.fast_path_remote_steals = self
            .fast_path_remote_steals
            .saturating_add(sample.fast_path_remote_steals);
        self.fast_path_events_suppressed = self
            .fast_path_events_suppressed
            .saturating_add(sample.fast_path_events_suppressed);
        self.fast_path_direct_dispatches = self
            .fast_path_direct_dispatches
            .saturating_add(sample.fast_path_direct_dispatches);
        self.fast_path_prev_continuations = self
            .fast_path_prev_continuations
            .saturating_add(sample.fast_path_prev_continuations);
        self.fast_path_steal_latency_source_admissions = self
            .fast_path_steal_latency_source_admissions
            .saturating_add(sample.fast_path_steal_latency_source_admissions);
        self.fast_path_steal_latency_successor_deferrals = self
            .fast_path_steal_latency_successor_deferrals
            .saturating_add(sample.fast_path_steal_latency_successor_deferrals);
        self.fast_path_steal_scan_exhaustions = self
            .fast_path_steal_scan_exhaustions
            .saturating_add(sample.fast_path_steal_scan_exhaustions);
        self.fast_path_remote_backlog_no_dispatches = self
            .fast_path_remote_backlog_no_dispatches
            .saturating_add(sample.fast_path_remote_backlog_no_dispatches);
        self.fast_path_steal_claim_conflicts = self
            .fast_path_steal_claim_conflicts
            .saturating_add(sample.fast_path_steal_claim_conflicts);
        self.fast_path_empty_steal_skips = self
            .fast_path_empty_steal_skips
            .saturating_add(sample.fast_path_empty_steal_skips);
        self.fast_path_preemption_throttles = self
            .fast_path_preemption_throttles
            .saturating_add(sample.fast_path_preemption_throttles);
        self.fast_path_preemption_deferrals = self
            .fast_path_preemption_deferrals
            .saturating_add(sample.fast_path_preemption_deferrals);
        self.fast_path_latency_backlog_boosts = self
            .fast_path_latency_backlog_boosts
            .saturating_add(sample.fast_path_latency_backlog_boosts);
        self.fast_path_latency_steal_attempts = self
            .fast_path_latency_steal_attempts
            .saturating_add(sample.fast_path_latency_steal_attempts);
        self.fast_path_latency_remote_steals = self
            .fast_path_latency_remote_steals
            .saturating_add(sample.fast_path_latency_remote_steals);
        for (total, value) in self
            .fast_path_select_migrations_by_class
            .iter_mut()
            .zip(sample.fast_path_select_migrations_by_class)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_remote_dispatches_by_class
            .iter_mut()
            .zip(sample.fast_path_remote_dispatches_by_class)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_preemptions_by_class
            .iter_mut()
            .zip(sample.fast_path_preemptions_by_class)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_preemption_victims_by_class
            .iter_mut()
            .zip(sample.fast_path_preemption_victims_by_class)
        {
            *total = total.saturating_add(value);
        }
        self.fast_path_latency_budget_charge_events = self
            .fast_path_latency_budget_charge_events
            .saturating_add(sample.fast_path_latency_budget_charge_events);
        self.fast_path_latency_budget_runtime_ns = self
            .fast_path_latency_budget_runtime_ns
            .saturating_add(sample.fast_path_latency_budget_runtime_ns);
        for (total, value) in self
            .fast_path_throughput_select_migrations_by_locality
            .iter_mut()
            .zip(sample.fast_path_throughput_select_migrations_by_locality)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_throughput_remote_dispatches_by_locality
            .iter_mut()
            .zip(sample.fast_path_throughput_remote_dispatches_by_locality)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_throughput_preemption_service_bins
            .iter_mut()
            .zip(sample.fast_path_throughput_preemption_service_bins)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_throughput_preemption_runtime_bins
            .iter_mut()
            .zip(sample.fast_path_throughput_preemption_runtime_bins)
        {
            *total = total.saturating_add(value);
        }
        self.fast_path_throughput_preemption_runtime_ns = self
            .fast_path_throughput_preemption_runtime_ns
            .saturating_add(sample.fast_path_throughput_preemption_runtime_ns);
        self.fast_path_throughput_preemption_request_ns = self
            .fast_path_throughput_preemption_request_ns
            .saturating_add(sample.fast_path_throughput_preemption_request_ns);
        self.fast_path_steal_idle_source_admissions = self
            .fast_path_steal_idle_source_admissions
            .saturating_add(sample.fast_path_steal_idle_source_admissions);
        self.fast_path_steal_idle_throughput_deferrals = self
            .fast_path_steal_idle_throughput_deferrals
            .saturating_add(sample.fast_path_steal_idle_throughput_deferrals);
        for (total, value) in self
            .fast_path_latency_select_migrations_by_locality
            .iter_mut()
            .zip(sample.fast_path_latency_select_migrations_by_locality)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_latency_remote_dispatches_by_locality
            .iter_mut()
            .zip(sample.fast_path_latency_remote_dispatches_by_locality)
        {
            *total = total.saturating_add(value);
        }
        self.fast_path_latency_remote_steals_preserving_successor = self
            .fast_path_latency_remote_steals_preserving_successor
            .saturating_add(sample.fast_path_latency_remote_steals_preserving_successor);
        self.fast_path_latency_remote_steals_fallback = self
            .fast_path_latency_remote_steals_fallback
            .saturating_add(sample.fast_path_latency_remote_steals_fallback);
        self.fast_path_latency_idle_source_deferrals = self
            .fast_path_latency_idle_source_deferrals
            .saturating_add(sample.fast_path_latency_idle_source_deferrals);
        for (total, value) in self
            .fast_path_latency_selects_by_path
            .iter_mut()
            .zip(sample.fast_path_latency_selects_by_path)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_latency_select_migrations_by_path
            .iter_mut()
            .zip(sample.fast_path_latency_select_migrations_by_path)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_immediate_preemption_kicks_by_class
            .iter_mut()
            .zip(sample.fast_path_immediate_preemption_kicks_by_class)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_select_sync_wakeups_by_class
            .iter_mut()
            .zip(sample.fast_path_select_sync_wakeups_by_class)
        {
            *total = total.saturating_add(value);
        }
        for (total, value) in self
            .fast_path_select_sync_migrations_by_class
            .iter_mut()
            .zip(sample.fast_path_select_sync_migrations_by_class)
        {
            *total = total.saturating_add(value);
        }
        self.fast_path_shared_balanced_enqueues = self
            .fast_path_shared_balanced_enqueues
            .saturating_add(sample.fast_path_shared_balanced_enqueues);
        self.fast_path_shared_balanced_dispatch_attempts = self
            .fast_path_shared_balanced_dispatch_attempts
            .saturating_add(sample.fast_path_shared_balanced_dispatch_attempts);
        self.fast_path_shared_balanced_dispatches = self
            .fast_path_shared_balanced_dispatches
            .saturating_add(sample.fast_path_shared_balanced_dispatches);
        self.fast_path_shared_balanced_dispatch_failures = self
            .fast_path_shared_balanced_dispatch_failures
            .saturating_add(sample.fast_path_shared_balanced_dispatch_failures);
        self.fast_path_shared_latency_enqueues = self
            .fast_path_shared_latency_enqueues
            .saturating_add(sample.fast_path_shared_latency_enqueues);
        self.fast_path_shared_latency_dispatch_attempts = self
            .fast_path_shared_latency_dispatch_attempts
            .saturating_add(sample.fast_path_shared_latency_dispatch_attempts);
        self.fast_path_shared_latency_dispatches = self
            .fast_path_shared_latency_dispatches
            .saturating_add(sample.fast_path_shared_latency_dispatches);
        self.fast_path_shared_latency_dispatch_failures = self
            .fast_path_shared_latency_dispatch_failures
            .saturating_add(sample.fast_path_shared_latency_dispatch_failures);
    }
}

/// Loaded sched_ext data plane and its struct-ops attachment.
///
/// The `OpenObject` storage is owned by the caller and must outlive this value,
/// matching libbpf skeleton lifetime requirements.
pub struct BpfRuntime<'obj> {
    /// Owning link whose drop detaches sched_ext and restores the kernel scheduler.
    struct_ops: Option<Link>,
    /// mmap-backed event consumer; it must be dropped before the skeleton maps.
    event_ring: RingBuffer<'static>,
    /// At most one bounded consume batch decoded by the ring callback.
    pending_events: Rc<RefCell<VecDeque<Result<KernelEvent>>>>,
    /// Generated map/program skeleton.
    skel: BpfSkel<'obj>,
}

impl<'obj> BpfRuntime<'obj> {
    /// Opens, configures, loads, and attaches the BPF scheduler.
    pub fn load(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        config: &SchedulerConfig,
        topology: &CpuTopology,
        initial_policy: &PolicySnapshot,
        agent_pid: u32,
        debug: bool,
    ) -> Result<Self> {
        let mut builder = BpfSkelBuilder::default();
        builder.obj_builder.debug(debug);
        let mut verifier_log = if debug {
            vec![0_u8; VERIFIER_LOG_BYTES]
        } else {
            Vec::new()
        };
        let mut open_opts_storage = bpf_object_open_opts::default();
        let open_opts = if debug {
            open_opts_storage.sz = mem::size_of::<bpf_object_open_opts>() as u64;
            open_opts_storage.kernel_log_buf = verifier_log.as_mut_ptr().cast();
            open_opts_storage.kernel_log_size = verifier_log.len() as u64;
            open_opts_storage.kernel_log_level = 1;
            Some(open_opts_storage)
        } else {
            None
        };
        let mut skel = scx_utils::scx_ops_open!(builder, open_object, scx_adaptive, open_opts)?;

        let core_leaders = topology.core_leaders();

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata map is not memory mapped")?;
        rodata.usersched_pid = std::process::id();
        rodata.agent_pid = agent_pid;
        rodata.num_possible_cpus = topology.cpu_count() as u32;
        rodata.num_domains = topology.domain_count();
        rodata.num_core_leaders = core_leaders.len() as u32;
        for (index, leader) in core_leaders.into_iter().enumerate() {
            rodata.core_leader_cpu_map[index] = leader;
        }
        for cpu in topology.cpus() {
            let core_leader = topology.core_leader_id(cpu);
            let core_peer = topology.core_peer_id(cpu);

            rodata.cpu_domain_id_map[cpu.id as usize] = cpu.domain_id;
            rodata.cpu_core_leader_map[cpu.id as usize] = core_leader;
            rodata.cpu_core_peer_map[cpu.id as usize] = core_peer;
        }
        rodata.latency_slice_ns = config.latency_slice_ns;
        rodata.balanced_slice_ns = config.balanced_slice_ns;
        rodata.throughput_slice_ns = config.throughput_slice_ns;
        rodata.min_slice_ns = config.min_slice_ns;
        rodata.max_slice_ns = config.max_slice_ns;
        rodata.latency_budget_percent = config.latency_budget_percent;
        rodata.latency_preemption_interval_ns = config.latency_preemption_interval_ns();
        rodata.throughput_preemption_min_runtime_ns = config.throughput_preemption_min_runtime_ns();

        let mut skel = match scx_utils::scx_ops_load!(skel, scx_adaptive, uei) {
            Ok(skel) => skel,
            Err(load_error) => {
                if let Some(end) = verifier_log.iter().position(|byte| *byte == 0) {
                    if end > 0 {
                        let start = end.saturating_sub(VERIFIER_LOG_REPORT_BYTES);
                        error!(
                            "BPF verifier log (last {} of {} bytes):\n{}",
                            end - start,
                            end,
                            String::from_utf8_lossy(&verifier_log[start..end])
                        );
                    }
                }
                return Err(load_error);
            }
        };
        for cpu in topology.cpus() {
            let state = initial_cpu_state(cpu.online);
            update_array_value(&skel.maps.cpu_state, cpu.id, &state)
                .with_context(|| format!("initialize BPF state for CPU {}", cpu.id))?;
        }
        publish_policy_maps(&skel, initial_policy)
            .context("publish initial BPF policy snapshot")?;

        let pending_events = Rc::new(RefCell::new(VecDeque::new()));
        let event_sink = Rc::clone(&pending_events);
        let mut ring_builder = RingBufferBuilder::new();
        ring_builder
            .add(&skel.maps.task_events, move |bytes| {
                let event = copy_from_bytes::<bpf_intf::task_event>(bytes)
                    .context("decode task_events value")
                    .and_then(|raw| {
                        KernelEvent::try_from(raw).map_err(|error: WireError| error.into())
                    });
                event_sink.borrow_mut().push_back(event);
                0
            })
            .context("register task_events ring buffer")?;
        let event_ring = ring_builder
            .build()
            .context("build task_events ring buffer")?;
        let struct_ops = Some(scx_utils::scx_ops_attach!(skel, scx_adaptive)?);

        Ok(Self {
            struct_ops,
            event_ring,
            pending_events,
            skel,
        })
    }

    /// Pops one decoded event after greedily consuming a bounded mmap batch.
    pub fn pop_event(&self) -> Result<Option<KernelEvent>> {
        if let Some(event) = self.pending_events.borrow_mut().pop_front() {
            return event.map(Some);
        }

        let consumed = self.event_ring.consume_raw_n(4096);
        if consumed < 0 {
            return Err(io::Error::from_raw_os_error(-consumed))
                .context("consume task_events ring buffer");
        }
        match self.pending_events.borrow_mut().pop_front() {
            Some(event) => event.map(Some),
            None => Ok(None),
        }
    }

    /// Mirrors one task class generation before the engine commits its update.
    pub fn update_task_control(&self, task: TaskKey, cache: TaskClassCache) -> Result<()> {
        let (key, value) = task_control_raw(task, cache);
        self.skel
            .maps
            .task_control
            .update(&key.to_ne_bytes(), bytes_of(&value), MapFlags::ANY)
            .with_context(|| format!("update BPF scheduling control for task {task:?}"))
    }

    /// Deletes a task-control record during explicit userspace reconciliation.
    pub fn delete_task_control(&self, task: TaskKey) -> Result<()> {
        self.skel
            .maps
            .task_control
            .delete(&task.tid.to_ne_bytes())
            .with_context(|| format!("delete BPF class generation for task {task:?}"))
    }

    /// Publishes a complete new policy generation and switches slots last.
    pub fn publish_policy(&self, snapshot: &PolicySnapshot) -> Result<()> {
        publish_policy_maps(&self.skel, snapshot)
    }

    /// Extends only the active snapshot lease with one atomic map update.
    pub fn renew_policy_lease(&self, snapshot: &PolicySnapshot) -> Result<()> {
        snapshot.validate()?;
        let control = policy_control_raw(snapshot);
        update_array_value(&self.skel.maps.policy_control, 0, &control)
            .context("renew active BPF policy lease")
    }

    /// Reads and aggregates the per-CPU BPF diagnostics records.
    pub fn data_plane_stats(&self) -> Result<DataPlaneStats> {
        let values = self
            .skel
            .maps
            .global_stats
            .lookup_percpu(&0_u32.to_ne_bytes(), MapFlags::ANY)
            .context("lookup per-CPU BPF statistics")?
            .context("per-CPU BPF statistics entry zero is missing")?;
        let mut total = DataPlaneStats::default();
        for bytes in values {
            let raw = copy_from_bytes::<bpf_intf::adaptive_global_stats>(&bytes)
                .context("decode per-CPU BPF statistics")?;
            total.accumulate(raw.into());
        }
        Ok(total)
    }

    /// Reads one coherent userspace projection of every CPU scheduling state.
    pub fn cpu_pressure(&self, cpu_count: usize) -> Result<Vec<CpuPressure>> {
        if cpu_count > bpf_intf::SCX_ADAPTIVE_MAX_CPUS as usize {
            anyhow::bail!("CPU pressure count exceeds BPF map capacity");
        }
        let mut pressure = Vec::with_capacity(cpu_count);
        for cpu in 0..cpu_count {
            let bytes = self
                .skel
                .maps
                .cpu_state
                .lookup(&(cpu as u32).to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("lookup BPF runtime state for CPU {cpu}"))?
                .with_context(|| format!("BPF runtime state for CPU {cpu} is missing"))?;
            let state = copy_from_bytes::<bpf_intf::adaptive_cpu_state>(&bytes)
                .with_context(|| format!("decode BPF runtime state for CPU {cpu}"))?;
            pressure.push(CpuPressure {
                cpu: cpu as u32,
                online: state.online != 0,
                idle: state.idle != 0,
                running_class: state.running_class,
                latency_credit_ns: state.latency_credit_ns,
                latency_debt_ns: state.latency_debt_ns,
                last_preemption_ns: state.last_preemption_ns,
                runtime_ns_by_class: state.runtime_ns_by_class,
                queued_tasks_by_class: state.queued_tasks_by_class,
            });
        }
        Ok(pressure)
    }

    /// Returns whether BPF recorded a sched_ext exit condition.
    pub fn exited(&self) -> bool {
        scx_utils::uei_exited!(&self.skel, uei)
    }

    /// Detaches struct_ops exactly once; dropping the runtime is also sufficient.
    pub fn detach(&mut self) {
        self.struct_ops.take();
    }

    /// Reports BPF's exit reason after detach or an unexpected sched_ext exit.
    pub fn report_exit(&self) -> Result<scx_utils::UserExitInfo> {
        scx_utils::uei_report!(&self.skel, uei)
    }
}

/// Returns CLOCK_MONOTONIC nanoseconds, matching `bpf_ktime_get_ns()`.
pub fn monotonic_now_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is valid writable storage and CLOCK_MONOTONIC has no
    // additional pointer arguments or retained state.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("read CLOCK_MONOTONIC");
    }
    Ok((time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64))
}

/// Updates one ARRAY map entry using native-endian fixed-width bytes.
fn update_array_value<T>(map: &impl MapCore, key: u32, value: &T) -> Result<()> {
    map.update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
        .map_err(Into::into)
}

/// Builds the pre-attach BPF state matching the scheduler's topology snapshot.
fn initial_cpu_state(online: bool) -> bpf_intf::adaptive_cpu_state {
    bpf_intf::adaptive_cpu_state {
        urgent_dispatch_id: 0,
        online: u32::from(online),
        idle: 0,
        running_class: bpf_intf::SCX_ADAPTIVE_CLASS_COUNT,
        steal_claim: 0,
        steal_cursor: 0,
        latency_dispatch_charged: 0,
        running_started_ns: 0,
        running_deadline_ns: 0,
        latency_credit_ns: 0,
        latency_debt_ns: 0,
        latency_credit_updated_ns: 0,
        last_preemption_ns: 0,
        runtime_ns_by_class: [0; 3],
        queued_tasks_by_class: [0; 3],
        virtual_time_ns: 0,
    }
}

fn publish_policy_maps(skel: &BpfSkel<'_>, snapshot: &PolicySnapshot) -> Result<()> {
    snapshot.validate()?;
    if snapshot.cpus.len() > bpf_intf::SCX_ADAPTIVE_MAX_CPUS as usize {
        anyhow::bail!("policy CPU count exceeds BPF map capacity");
    }
    let slot_base = snapshot
        .active_slot()
        .checked_mul(bpf_intf::SCX_ADAPTIVE_MAX_CPUS)
        .context("policy slot index overflow")?;
    for cpu in &snapshot.cpus {
        let raw = bpf_intf::adaptive_cpu_policy {
            generation: snapshot.generation,
            domain_id: cpu.domain_id,
            llc_id: cpu.llc_id,
            numa_id: cpu.numa_id,
            package_id: cpu.package_id,
            core_id: cpu.core_id,
            smt_index: cpu.smt_index,
            capacity: cpu.capacity,
            core_type: cpu.core_type,
            latency_candidate_cpu: cpu.latency_candidate_cpu,
            normal_candidate_cpu: cpu.normal_candidate_cpu,
        };
        let key = slot_base
            .checked_add(cpu.cpu)
            .context("policy CPU map index overflow")?;
        update_array_value(&skel.maps.cpu_policy, key, &raw)
            .with_context(|| format!("publish policy for CPU {}", cpu.cpu))?;
    }

    let control = policy_control_raw(snapshot);
    update_array_value(&skel.maps.policy_control, 0, &control)
        .context("activate BPF policy generation")
}

fn policy_control_raw(snapshot: &PolicySnapshot) -> bpf_intf::adaptive_policy_control {
    bpf_intf::adaptive_policy_control {
        generation: snapshot.generation,
        valid_until_ns: snapshot.valid_until_ns,
        preemption_interval_ns: snapshot.preemption_interval_ns,
        latency_successor_lease_ns: snapshot.latency_successor_lease_ns,
        balanced_preemption_granularity_ns: snapshot.balanced_preemption_granularity_ns,
        cross_domain_cost_ns: snapshot.cross_domain_cost_ns,
        active_slot: snapshot.active_slot(),
        flags: bpf_intf::SCX_ADAPTIVE_POLICY_VALID,
        latency_budget_percent: snapshot.latency_budget_percent,
        domain_count: snapshot.domain_count,
    }
}

/// Views a plain fixed-width ABI value as immutable bytes for libbpf.
fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the returned slice borrows `value`, spans exactly its initialized
    // object representation, and cannot outlive or mutate the source.
    unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>()) }
}

/// Copies an unaligned byte slice into a fixed-width ABI value.
fn copy_from_bytes<T: Copy>(bytes: &[u8]) -> Result<T> {
    if bytes.len() != mem::size_of::<T>() {
        anyhow::bail!(
            "map value has {} bytes; expected {}",
            bytes.len(),
            mem::size_of::<T>()
        );
    }
    // SAFETY: size equality above guarantees a complete object representation;
    // read_unaligned handles Vec<u8>'s one-byte alignment and returns an owned copy.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

#[cfg(test)]
mod tests {
    use super::{
        copy_from_bytes, initial_cpu_state, monotonic_now_ns, policy_control_raw, DataPlaneStats,
    };
    use crate::config::SchedulerConfig;
    use crate::policy::PolicyController;
    use crate::topology::CpuTopology;

    /// Kernel-compatible monotonic time must be non-zero on a running system.
    #[test]
    fn monotonic_clock_is_available() {
        assert!(monotonic_now_ns().unwrap() > 0);
    }

    /// ABI decoding rejects a map value with the wrong fixed size.
    #[test]
    fn fixed_width_decode_checks_size() {
        assert!(copy_from_bytes::<u64>(&[0; 7]).is_err());
    }

    /// The generated Rust view must match the append-only C statistics ABI.
    #[test]
    fn global_stats_abi_version_and_size_are_current() {
        assert_eq!(crate::bpf_intf::SCX_ADAPTIVE_ABI_VERSION, 35);
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::adaptive_global_stats>(),
            800
        );
    }

    /// BPF CPU availability must be initialized before struct_ops attachment.
    #[test]
    fn initial_cpu_state_tracks_topology_online_bit() {
        let online = initial_cpu_state(true);
        let offline = initial_cpu_state(false);
        assert_eq!(online.online, 1);
        assert_eq!(offline.online, 0);
        assert_eq!(online.urgent_dispatch_id, 0);
        assert_eq!(online.running_deadline_ns, 0);
        assert_eq!(online.virtual_time_ns, 0);
        assert_eq!(online.runtime_ns_by_class, [0; 3]);
        assert_eq!(online.queued_tasks_by_class, [0; 3]);
    }

    #[test]
    fn policy_control_switches_one_valid_complete_slot() {
        let policy =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(2), 100).unwrap();
        let raw = policy_control_raw(policy.snapshot());
        assert_eq!(raw.generation, 1);
        assert_eq!(raw.active_slot, 1);
        assert_eq!(raw.domain_count, 1);
        assert_eq!(raw.latency_successor_lease_ns, 250_000);
        assert_eq!(raw.balanced_preemption_granularity_ns, 1_000_000);
        assert_eq!(raw.flags, crate::bpf_intf::SCX_ADAPTIVE_POLICY_VALID);
    }

    /// Per-CPU aggregation saturates counters and preserves class indexes.
    #[test]
    fn data_plane_stats_aggregate_per_cpu_values() {
        let mut total = DataPlaneStats {
            fast_path_enqueues: u64::MAX - 1,
            fast_path_dispatches_by_class: [1, 2, 3],
            fast_path_pipeline_ready_samples: 5,
            fast_path_pipeline_normal_depth_sum: 8,
            ..DataPlaneStats::default()
        };
        total.accumulate(DataPlaneStats {
            fast_path_enqueues: 5,
            fast_path_dispatches_by_class: [4, 5, 6],
            fast_path_prev_continuations: 7,
            fast_path_steal_latency_source_admissions: 13,
            fast_path_steal_latency_successor_deferrals: 29,
            fast_path_steal_scan_exhaustions: 5,
            fast_path_remote_backlog_no_dispatches: 3,
            fast_path_latency_remote_steals: 11,
            fast_path_select_migrations_by_class: [2, 3, 4],
            fast_path_remote_dispatches_by_class: [5, 6, 7],
            fast_path_preemption_victims_by_class: [8, 9, 10],
            fast_path_throughput_select_migrations_by_locality: [11, 12, 13, 14],
            fast_path_throughput_remote_dispatches_by_locality: [15, 16, 17, 18],
            fast_path_throughput_preemption_service_bins: [19, 20, 21, 22],
            fast_path_throughput_preemption_runtime_bins: [23, 24, 25, 26],
            fast_path_throughput_preemption_runtime_ns: 27,
            fast_path_throughput_preemption_request_ns: 28,
            fast_path_steal_idle_source_admissions: 30,
            fast_path_steal_idle_throughput_deferrals: 31,
            fast_path_latency_select_migrations_by_locality: [32, 33, 34, 35],
            fast_path_latency_remote_dispatches_by_locality: [36, 37, 38, 39],
            fast_path_latency_remote_steals_preserving_successor: 40,
            fast_path_latency_remote_steals_fallback: 41,
            fast_path_latency_idle_source_deferrals: 42,
            fast_path_latency_selects_by_path: [43, 44, 45, 46],
            fast_path_latency_select_migrations_by_path: [47, 48, 49, 50],
            fast_path_immediate_preemption_kicks_by_class: [51, 52, 53],
            fast_path_select_sync_wakeups_by_class: [54, 55, 56],
            fast_path_select_sync_migrations_by_class: [57, 58, 59],
            fast_path_shared_balanced_enqueues: 60,
            fast_path_shared_balanced_dispatch_attempts: 61,
            fast_path_shared_balanced_dispatches: 62,
            fast_path_shared_balanced_dispatch_failures: 63,
            fast_path_shared_latency_enqueues: 64,
            fast_path_shared_latency_dispatch_attempts: 65,
            fast_path_shared_latency_dispatches: 66,
            fast_path_shared_latency_dispatch_failures: 67,
            fast_path_latency_budget_charge_events: 17,
            fast_path_latency_budget_runtime_ns: 19,
            fast_path_pipeline_ready_samples: 11,
            fast_path_pipeline_empty_samples: 3,
            fast_path_pipeline_normal_depth_sum: 13,
            fast_path_pipeline_latency_depth_sum: 2,
            ..DataPlaneStats::default()
        });

        assert_eq!(total.fast_path_enqueues, u64::MAX);
        assert_eq!(total.fast_path_dispatches_by_class, [5, 7, 9]);
        assert_eq!(total.fast_path_prev_continuations, 7);
        assert_eq!(total.fast_path_steal_latency_source_admissions, 13);
        assert_eq!(total.fast_path_steal_latency_successor_deferrals, 29);
        assert_eq!(total.fast_path_steal_scan_exhaustions, 5);
        assert_eq!(total.fast_path_remote_backlog_no_dispatches, 3);
        assert_eq!(total.fast_path_latency_remote_steals, 11);
        assert_eq!(total.fast_path_select_migrations_by_class, [2, 3, 4]);
        assert_eq!(total.fast_path_remote_dispatches_by_class, [5, 6, 7]);
        assert_eq!(total.fast_path_preemption_victims_by_class, [8, 9, 10]);
        assert_eq!(
            total.fast_path_throughput_select_migrations_by_locality,
            [11, 12, 13, 14]
        );
        assert_eq!(
            total.fast_path_throughput_remote_dispatches_by_locality,
            [15, 16, 17, 18]
        );
        assert_eq!(
            total.fast_path_throughput_preemption_service_bins,
            [19, 20, 21, 22]
        );
        assert_eq!(
            total.fast_path_throughput_preemption_runtime_bins,
            [23, 24, 25, 26]
        );
        assert_eq!(total.fast_path_throughput_preemption_runtime_ns, 27);
        assert_eq!(total.fast_path_throughput_preemption_request_ns, 28);
        assert_eq!(total.fast_path_steal_idle_source_admissions, 30);
        assert_eq!(total.fast_path_steal_idle_throughput_deferrals, 31);
        assert_eq!(
            total.fast_path_latency_select_migrations_by_locality,
            [32, 33, 34, 35]
        );
        assert_eq!(
            total.fast_path_latency_remote_dispatches_by_locality,
            [36, 37, 38, 39]
        );
        assert_eq!(
            total.fast_path_latency_remote_steals_preserving_successor,
            40
        );
        assert_eq!(total.fast_path_latency_remote_steals_fallback, 41);
        assert_eq!(total.fast_path_latency_idle_source_deferrals, 42);
        assert_eq!(total.fast_path_latency_selects_by_path, [43, 44, 45, 46]);
        assert_eq!(
            total.fast_path_latency_select_migrations_by_path,
            [47, 48, 49, 50]
        );
        assert_eq!(
            total.fast_path_immediate_preemption_kicks_by_class,
            [51, 52, 53]
        );
        assert_eq!(total.fast_path_select_sync_wakeups_by_class, [54, 55, 56]);
        assert_eq!(
            total.fast_path_select_sync_migrations_by_class,
            [57, 58, 59]
        );
        assert_eq!(total.fast_path_shared_balanced_enqueues, 60);
        assert_eq!(total.fast_path_shared_balanced_dispatch_attempts, 61);
        assert_eq!(total.fast_path_shared_balanced_dispatches, 62);
        assert_eq!(total.fast_path_shared_balanced_dispatch_failures, 63);
        assert_eq!(total.fast_path_shared_latency_enqueues, 64);
        assert_eq!(total.fast_path_shared_latency_dispatch_attempts, 65);
        assert_eq!(total.fast_path_shared_latency_dispatches, 66);
        assert_eq!(total.fast_path_shared_latency_dispatch_failures, 67);
        assert_eq!(total.fast_path_latency_budget_charge_events, 17);
        assert_eq!(total.fast_path_latency_budget_runtime_ns, 19);
        assert_eq!(total.fast_path_pipeline_ready_samples, 16);
        assert_eq!(total.fast_path_pipeline_empty_samples, 3);
        assert_eq!(total.fast_path_pipeline_normal_depth_sum, 21);
        assert_eq!(total.fast_path_pipeline_latency_depth_sum, 2);
    }
}
