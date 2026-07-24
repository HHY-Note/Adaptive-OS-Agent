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

#define SCX_ADAPTIVE_ABI_VERSION 6U
#define SCX_ADAPTIVE_MAX_CPUS 1024U
#define SCX_ADAPTIVE_EVENT_CAPACITY 16384U
#define SCX_ADAPTIVE_COMMAND_CAPACITY 16384U
#define SCX_ADAPTIVE_MAX_DISPATCH_BATCH 64U

/* Values used in task_event.event_kind. */
#define SCX_ADAPTIVE_EVENT_INIT 1U
#define SCX_ADAPTIVE_EVENT_EXEC 2U
#define SCX_ADAPTIVE_EVENT_ENQUEUE 3U
#define SCX_ADAPTIVE_EVENT_CANCEL 4U
#define SCX_ADAPTIVE_EVENT_RUNNING 5U
#define SCX_ADAPTIVE_EVENT_STOP 6U
#define SCX_ADAPTIVE_EVENT_EXIT 7U
#define SCX_ADAPTIVE_EVENT_CPU_STATE 8U
#define SCX_ADAPTIVE_EVENT_COMMAND_REJECT 9U

/* Values stored in task_event.flags for STOP and CPU_STATE events. */
#define SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE (1ULL << 0)
#define SCX_ADAPTIVE_EVENT_FLAG_CPU_ONLINE (1ULL << 1)
#define SCX_ADAPTIVE_EVENT_FLAG_CPU_IDLE (1ULL << 2)
#define SCX_ADAPTIVE_EVENT_FLAG_WAKEUP (1ULL << 3)
#define SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED (1ULL << 4)

/* Values stored in task_control_value.class_id. */
#define SCX_ADAPTIVE_CLASS_LATENCY 0U
#define SCX_ADAPTIVE_CLASS_BALANCED 1U
#define SCX_ADAPTIVE_CLASS_THROUGHPUT 2U
#define SCX_ADAPTIVE_CLASS_COUNT 3U

/* Values stored in task_control_value.flags. */
#define SCX_ADAPTIVE_CONTROL_BPF_SCHED (1U << 0)
#define SCX_ADAPTIVE_CONTROL_OBSERVE (1U << 1)
#define SCX_ADAPTIVE_CONTROL_FLAG_MASK \
	(SCX_ADAPTIVE_CONTROL_BPF_SCHED | SCX_ADAPTIVE_CONTROL_OBSERVE)

/* Values stored in dispatch_command.flags. */
#define SCX_ADAPTIVE_DISPATCH_PREEMPT (1U << 0)
#define SCX_ADAPTIVE_DISPATCH_FLAG_MASK SCX_ADAPTIVE_DISPATCH_PREEMPT

/* Stable rejection codes reported in COMMAND_REJECT event flags. */
#define SCX_ADAPTIVE_REJECT_TASK_GONE 1U
#define SCX_ADAPTIVE_REJECT_IDENTITY 2U
#define SCX_ADAPTIVE_REJECT_NOT_PENDING 3U
#define SCX_ADAPTIVE_REJECT_SEQUENCE 4U
#define SCX_ADAPTIVE_REJECT_CLASS_GENERATION 5U
#define SCX_ADAPTIVE_REJECT_CPU_OFFLINE 6U
#define SCX_ADAPTIVE_REJECT_AFFINITY 7U
#define SCX_ADAPTIVE_REJECT_TARGET_SLOT_BUSY 8U
#define SCX_ADAPTIVE_REJECT_SLICE 9U
#define SCX_ADAPTIVE_REJECT_DUPLICATE_DISPATCH 10U
#define SCX_ADAPTIVE_REJECT_MIGRATION_DISABLED 11U
#define SCX_ADAPTIVE_REJECT_FLAGS 12U

/* Internal values exported for diagnostics and map inspection. */
#define SCX_ADAPTIVE_TASK_BLOCKED 0U
#define SCX_ADAPTIVE_TASK_PENDING_USER 1U
#define SCX_ADAPTIVE_TASK_STAGED 2U
#define SCX_ADAPTIVE_TASK_RUNNING 3U
#define SCX_ADAPTIVE_TASK_EXITED 4U
#define SCX_ADAPTIVE_TASK_PENDING_BPF 5U

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
	u64 dispatch_id;
	u64 timestamp_ns;
	u64 runtime_ns;
	u64 sleep_ns;

	s32 previous_cpu;
	s32 actual_cpu;
	u64 flags;
};

/*
 * Rust-to-kernel dispatch request. BPF accepts it only when every identity,
 * generation, affinity, state, slot, and slice field is still current.
 */
struct dispatch_command {
	u16 abi_version;
	u16 flags;
	u32 struct_size;

	u32 tid;
	u32 target_cpu;
	u64 task_cookie;
	u64 process_cookie;
	u64 exec_generation;

	u64 enqueue_sequence;
	u64 class_generation;
	u64 dispatch_id;
	u64 slice_ns;
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

/* Shared per-CPU pipeline guards, liveness state, and root EEVDF entities. */
struct adaptive_cpu_state {
	u64 staged_dispatch_id;
	u64 urgent_dispatch_id;
	u32 online;
	u32 idle;
	u32 running_class;
	u32 steal_claim;
	u32 steal_cursor;
	u32 padding;
	u64 last_idle_event_ns;
	u64 accepted_commands;
	u64 rejected_commands;
	u64 root_virtual_time_ns;
	u64 root_vruntime_ns[SCX_ADAPTIVE_CLASS_COUNT];
};

/* Data-plane counters, stored as one entry per CPU and summed by Rust. */
struct adaptive_global_stats {
	u64 event_overflows;
	u64 fallback_dispatches;
	u64 commands_accepted;
	u64 commands_rejected;
	u64 target_slot_busy_rejects;
	u64 pipeline_hits;
	u64 pipeline_misses;
	u64 max_normal_staged_depth;
	u64 stale_heartbeat_fallbacks;
	u64 identity_rejects;
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
	u64 cpu_state_events_suppressed;
	u64 fast_path_empty_steal_skips;
};

_Static_assert(sizeof(struct task_event) == 96, "task_event ABI size changed");
_Static_assert(sizeof(struct dispatch_command) == 72,
	       "dispatch_command ABI size changed");
_Static_assert(sizeof(struct task_control_value) == 40,
	       "task_control_value ABI size changed");
_Static_assert(sizeof(struct adaptive_cpu_state) == 96,
	       "adaptive_cpu_state ABI size changed");
_Static_assert(sizeof(struct adaptive_global_stats) == 208,
	       "adaptive_global_stats ABI size changed");

#endif /* __SCX_ADAPTIVE_INTF_H */
