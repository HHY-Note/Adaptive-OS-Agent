/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SCX_ADAPTIVE_INTF_H
#define __SCX_ADAPTIVE_INTF_H

/*
 * This header is the only binary ABI shared by the Rust scheduler and BPF.
 * Keep every structure fixed-width, naturally aligned, and append-only.
 */

#ifndef __VMLINUX_H__
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;
#endif

#define SCX_ADAPTIVE_ABI_VERSION 35U
#define SCX_ADAPTIVE_MAX_CPUS 1024U
#define SCX_ADAPTIVE_POLICY_SLOT_COUNT 2U
#define SCX_ADAPTIVE_LATENCY_CANDIDATE_COUNT 2U
#define SCX_ADAPTIVE_NORMAL_CANDIDATE_COUNT 2U
#define SCX_ADAPTIVE_CPU_LOCALITY_COUNT 4U
#define SCX_ADAPTIVE_PREEMPTION_SERVICE_BIN_COUNT 4U
#define SCX_ADAPTIVE_PREEMPTION_RUNTIME_BIN_COUNT 4U
#define SCX_ADAPTIVE_LATENCY_SELECT_PATH_COUNT 4U
#define SCX_ADAPTIVE_LATENCY_SELECT_DEFAULT_IDLE 0U
#define SCX_ADAPTIVE_LATENCY_SELECT_DEFAULT_BUSY 1U
#define SCX_ADAPTIVE_LATENCY_SELECT_POLICY_VICTIM 2U
#define SCX_ADAPTIVE_LATENCY_SELECT_FALLBACK 3U
#define SCX_ADAPTIVE_INVALID_CPU (~0U)
#define SCX_ADAPTIVE_EVENT_RING_BYTES (2U * 1024U * 1024U)
#define SCX_ADAPTIVE_MAX_DISPATCH_BATCH 64U

/* Values used in task_event.event_kind. */
#define SCX_ADAPTIVE_EVENT_INIT 1U
#define SCX_ADAPTIVE_EVENT_EXEC 2U
#define SCX_ADAPTIVE_EVENT_ENQUEUE 3U
#define SCX_ADAPTIVE_EVENT_CANCEL 4U
#define SCX_ADAPTIVE_EVENT_RUNNING 5U
#define SCX_ADAPTIVE_EVENT_STOP 6U
#define SCX_ADAPTIVE_EVENT_EXIT 7U

/* Values stored in task_event.flags for observed scheduling events. */
#define SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE (1ULL << 0)
#define SCX_ADAPTIVE_EVENT_FLAG_WAKEUP (1ULL << 3)

/* Values stored in task_control_value.class_id. */
#define SCX_ADAPTIVE_CLASS_LATENCY 0U
#define SCX_ADAPTIVE_CLASS_BALANCED 1U
#define SCX_ADAPTIVE_CLASS_THROUGHPUT 2U
#define SCX_ADAPTIVE_CLASS_COUNT 3U

/* Values stored in task_control_value.flags. */
#define SCX_ADAPTIVE_CONTROL_BPF_SCHED (1U << 0)
#define SCX_ADAPTIVE_CONTROL_OBSERVE (1U << 1)
#define SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE (1U << 2)
#define SCX_ADAPTIVE_CONTROL_FLAG_MASK \
	(SCX_ADAPTIVE_CONTROL_BPF_SCHED | SCX_ADAPTIVE_CONTROL_OBSERVE | \
	 SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE)

/* Values stored in adaptive_policy_control.flags. */
#define SCX_ADAPTIVE_POLICY_VALID (1U << 0)

/*
 * Kernel-to-Rust lifecycle event. Identity fields describe one kernel task;
 * enqueue_sequence additionally identifies one runnable incarnation.
 */
struct task_event {
	u16 abi_version;
	u16 event_kind;
	u32 struct_size;

	u32 tid;
	u32 tgid;
	u64 task_cookie;
	u64 process_cookie;
	u64 exec_generation;

	u64 enqueue_sequence;
	u64 timestamp_ns;
	u64 runtime_ns;
	u64 sleep_ns;

	s32 previous_cpu;
	s32 actual_cpu;
	u64 flags;
};

/*
 * Scheduler-owned task class generation mirrored into BPF. The cookie fields
 * prevent a reused TID from inheriting a stale generation.
 */
struct task_control_value {
	u64 task_cookie;
	u64 process_cookie;
	u64 exec_generation;
	u64 class_generation;
	u32 class_id;
	u32 flags;
};

/* Atomically selected userspace policy generation. */
struct adaptive_policy_control {
	u64 generation;
	u64 valid_until_ns;
	u64 preemption_interval_ns;
	u64 balanced_preemption_granularity_ns;
	u64 cross_domain_cost_ns;
	u32 active_slot;
	u32 flags;
	u32 latency_budget_percent;
	u32 domain_count;
	/* Expected uninterrupted Latency service before one Normal successor may move. */
	u64 latency_successor_lease_ns;
};

/* One CPU's topology projection in a double-buffered policy slot. */
struct adaptive_cpu_policy {
	u64 generation;
	u32 domain_id;
	u32 llc_id;
	u32 numa_id;
	u32 package_id;
	u32 core_id;
	u32 smt_index;
	u32 capacity;
	u32 core_type;
	u32 latency_candidate_cpu[SCX_ADAPTIVE_LATENCY_CANDIDATE_COUNT];
	u32 normal_candidate_cpu[SCX_ADAPTIVE_NORMAL_CANDIDATE_COUNT];
};

/* Shared per-CPU preemption, locality, and work-stealing state. */
struct adaptive_cpu_state {
	u64 urgent_dispatch_id;
	u32 online;
	u32 idle;
	u32 running_class;
	u32 steal_claim;
	u32 steal_cursor;
	u32 latency_dispatch_charged;
	u64 running_started_ns;
	u64 running_deadline_ns;
	u64 latency_credit_ns;
	u64 latency_debt_ns;
	u64 latency_credit_updated_ns;
	u64 last_preemption_ns;
	u64 runtime_ns_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 queued_tasks_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 virtual_time_ns;
};

/* Data-plane counters, stored as one entry per CPU and summed by Rust. */
struct adaptive_global_stats {
	u64 event_overflows;
	u64 fallback_dispatches;
	u64 fast_path_enqueues;
	u64 fast_path_dispatches;
	u64 fast_path_dispatch_failures;
	u64 fast_path_preemptions;
	u64 fast_path_dispatches_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 fast_path_local_dispatches;
	u64 fast_path_steal_attempts;
	u64 fast_path_remote_steals;
	u64 fast_path_events_suppressed;
	u64 fast_path_direct_dispatches;
	u64 fast_path_prev_continuations;
	u64 fast_path_steal_latency_source_admissions;
	u64 fast_path_steal_scan_exhaustions;
	u64 fast_path_remote_backlog_no_dispatches;
	u64 fast_path_steal_claim_conflicts;
	u64 fast_path_empty_steal_skips;
	u64 fast_path_preemption_throttles;
	u64 fast_path_preemption_deferrals;
	u64 fast_path_latency_backlog_boosts;
	u64 fast_path_latency_steal_attempts;
	u64 fast_path_latency_remote_steals;
	u64 fast_path_select_migrations_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 fast_path_remote_dispatches_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 fast_path_preemptions_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 fast_path_preemption_victims_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	u64 fast_path_latency_budget_charge_events;
	u64 fast_path_latency_budget_runtime_ns;
	u64 fast_path_pipeline_ready_samples;
	u64 fast_path_pipeline_empty_samples;
	u64 fast_path_pipeline_normal_depth_sum;
	u64 fast_path_pipeline_latency_depth_sum;
	u64 fast_path_throughput_select_migrations_by_locality[
		SCX_ADAPTIVE_CPU_LOCALITY_COUNT];
	u64 fast_path_throughput_remote_dispatches_by_locality[
		SCX_ADAPTIVE_CPU_LOCALITY_COUNT];
	u64 fast_path_throughput_preemption_service_bins[
		SCX_ADAPTIVE_PREEMPTION_SERVICE_BIN_COUNT];
	u64 fast_path_throughput_preemption_runtime_bins[
		SCX_ADAPTIVE_PREEMPTION_RUNTIME_BIN_COUNT];
	u64 fast_path_throughput_preemption_runtime_ns;
	u64 fast_path_throughput_preemption_request_ns;
	u64 fast_path_steal_latency_successor_deferrals;
	/* Idle source CPUs admitted for stealing despite one queued Normal task. */
	u64 fast_path_steal_idle_source_admissions;
	/* Idle sources retaining a sole Throughput task for local dispatch. */
	u64 fast_path_steal_idle_throughput_deferrals;
	/* Latency wake selections that moved CPU, bucketed by topology distance. */
	u64 fast_path_latency_select_migrations_by_locality[
		SCX_ADAPTIVE_CPU_LOCALITY_COUNT];
	/* Latency work run away from its owner, bucketed by topology distance. */
	u64 fast_path_latency_remote_dispatches_by_locality[
		SCX_ADAPTIVE_CPU_LOCALITY_COUNT];
	/* Latency steals that kept one request on the source CPU or core shard. */
	u64 fast_path_latency_remote_steals_preserving_successor;
	/* Last-resort Latency steals that admitted a sole queued request. */
	u64 fast_path_latency_remote_steals_fallback;
	/* Sole Latency requests retained on an already-idle home CPU or core. */
	u64 fast_path_latency_idle_source_deferrals;
	/* Latency select_cpu calls bucketed by the final selection path. */
	u64 fast_path_latency_selects_by_path[
		SCX_ADAPTIVE_LATENCY_SELECT_PATH_COUNT];
	/* Latency final selections that moved CPU, bucketed by selection path. */
	u64 fast_path_latency_select_migrations_by_path[
		SCX_ADAPTIVE_LATENCY_SELECT_PATH_COUNT];
	/* Immediate PREEMPT kicks issued after Latency or Balanced wakeups. */
	u64 fast_path_immediate_preemption_kicks_by_class[
		SCX_ADAPTIVE_CLASS_COUNT];
	/* select_cpu calls carrying SCX_WAKE_SYNC, bucketed by task class. */
	u64 fast_path_select_sync_wakeups_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	/* SCX_WAKE_SYNC final selections that moved away from prev_cpu. */
	u64 fast_path_select_sync_migrations_by_class[SCX_ADAPTIVE_CLASS_COUNT];
	/* Wide-affinity Balanced tasks routed through a domain overflow DSQ. */
	u64 fast_path_shared_balanced_enqueues;
	/* O(1) domain overflow consume calls made while shared work existed. */
	u64 fast_path_shared_balanced_dispatch_attempts;
	/* Domain overflow tasks successfully moved into a local DSQ. */
	u64 fast_path_shared_balanced_dispatches;
	/* Shared count said work existed but the local domain move lost a race. */
	u64 fast_path_shared_balanced_dispatch_failures;
	/* Full-affinity blocked Latency wakeups routed through a core shard. */
	u64 fast_path_shared_latency_enqueues;
	/* O(1) core-shard Latency consume calls made while shared work existed. */
	u64 fast_path_shared_latency_dispatch_attempts;
	/* Domain Latency tasks successfully moved into a local DSQ. */
	u64 fast_path_shared_latency_dispatches;
	/* Shared Latency count said work existed but the move lost a race. */
	u64 fast_path_shared_latency_dispatch_failures;
};

_Static_assert(sizeof(struct task_event) == 88, "task_event ABI size changed");
_Static_assert(sizeof(struct task_control_value) == 40,
	       "task_control_value ABI size changed");
_Static_assert(sizeof(struct adaptive_policy_control) == 64,
	       "adaptive_policy_control ABI size changed");
_Static_assert(sizeof(struct adaptive_cpu_policy) == 56,
	       "adaptive_cpu_policy ABI size changed");
_Static_assert(sizeof(struct adaptive_cpu_state) == 136,
	       "adaptive_cpu_state ABI size changed");
_Static_assert(sizeof(struct adaptive_global_stats) == 800,
	       "adaptive_global_stats ABI size changed");

#endif /* __SCX_ADAPTIVE_INTF_H */
