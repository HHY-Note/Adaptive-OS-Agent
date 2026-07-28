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

#define SCX_ADAPTIVE_ABI_VERSION 8U
#define SCX_ADAPTIVE_MAX_CPUS 1024U
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

/* Shared per-CPU preemption, locality, and root EEVDF state. */
struct adaptive_cpu_state {
	u64 urgent_dispatch_id;
	u32 online;
	u32 idle;
	u32 running_class;
	u32 steal_claim;
	u32 steal_cursor;
	u32 padding;
	u64 running_started_ns;
	u64 last_preemption_ns;
	u64 root_virtual_time_ns;
	u64 root_vruntime_ns[SCX_ADAPTIVE_CLASS_COUNT];
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
	u64 fast_path_steal_claim_conflicts;
	u64 fast_path_empty_steal_skips;
	u64 fast_path_preemption_throttles;
	u64 fast_path_latency_backlog_boosts;
};

_Static_assert(sizeof(struct task_event) == 88, "task_event ABI size changed");
_Static_assert(sizeof(struct task_control_value) == 40,
	       "task_control_value ABI size changed");
_Static_assert(sizeof(struct adaptive_cpu_state) == 80,
	       "adaptive_cpu_state ABI size changed");
_Static_assert(sizeof(struct adaptive_global_stats) == 152,
	       "adaptive_global_stats ABI size changed");

#endif /* __SCX_ADAPTIVE_INTF_H */
