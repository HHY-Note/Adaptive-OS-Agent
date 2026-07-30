/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * scx_adaptive sched_ext data plane.
 *
 * Ordinary tasks run through per-CPU BPF EEVDF queues, defaulting to
 * observable Balanced service until Rust publishes a precise classification.
 * Rust remains a bounded classification and observation control plane.
 */
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>

#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* Loader supplied scheduler and Agent thread-group IDs. */
const volatile u32 usersched_pid;
const volatile u32 agent_pid;

/* Loader supplied immutable validation and iteration bounds. */
const volatile u32 num_possible_cpus;
const volatile u32 num_domains;
const volatile u32 num_core_leaders;
const volatile u32 cpu_domain_id_map[SCX_ADAPTIVE_MAX_CPUS];
const volatile u32 cpu_core_leader_map[SCX_ADAPTIVE_MAX_CPUS];
const volatile u32 cpu_core_peer_map[SCX_ADAPTIVE_MAX_CPUS];
const volatile u32 core_leader_cpu_map[SCX_ADAPTIVE_MAX_CPUS];
const volatile u64 latency_slice_ns = 250000ULL;
const volatile u64 balanced_slice_ns = 4000000ULL;
const volatile u64 throughput_slice_ns = 8000000ULL;
const volatile u64 min_slice_ns = 250000ULL;
const volatile u64 max_slice_ns = 64000000ULL;
const volatile u32 latency_budget_percent = 20U;
/* Immutable fallback matching one full Latency request at the configured share. */
const volatile u64 latency_preemption_interval_ns = 1250000ULL;
/* Minimum uninterrupted service before Latency may displace Throughput. */
const volatile u64 throughput_preemption_min_runtime_ns = 1000000ULL;

#define FAST_TASK_DSQ_BASE 0x10000ULL
#define FAST_LATENCY_DSQ_BASE 0x20000ULL
#define FAST_BALANCED_OVERFLOW_DSQ_BASE 0x30000ULL
#define FAST_SHARED_LATENCY_DSQ_BASE 0x40000ULL
#define FAST_LATENCY_RESCHED_ID (~0ULL)
#define FAST_BALANCED_RESCHED_ID (~0ULL - 1ULL)
#define FAST_NO_RUNNING_CLASS SCX_ADAPTIVE_CLASS_COUNT
#define FAST_STEAL_SCAN_LIMIT 8U
#define FAST_BALANCED_THROUGHPUT_MIN_RUNTIME_SLICES 8U
#define FAST_LATENCY_DEBT_CAP_SLICES 4U
#define FAST_BALANCED_PLACEMENT_HYSTERESIS 6ULL
#define FAST_CPU_LOCALITY_SMT 0U
#define FAST_CPU_LOCALITY_SAME_LLC 1U
#define FAST_CPU_LOCALITY_CROSS_LLC 2U
#define FAST_CPU_LOCALITY_UNKNOWN 3U
#define FAST_THROUGHPUT_PREEMPTION_BIN_EARLY 0U
#define FAST_THROUGHPUT_PREEMPTION_BIN_MID 1U
#define FAST_THROUGHPUT_PREEMPTION_BIN_LATE 2U
#define FAST_THROUGHPUT_PREEMPTION_BIN_COMPLETE 3U
#define FAST_THROUGHPUT_PREEMPTION_BIN_UNKNOWN \
	SCX_ADAPTIVE_PREEMPTION_SERVICE_BIN_COUNT
#define FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_UNDER_500US 0U
#define FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_500US_TO_1MS 1U
#define FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_1MS_TO_2MS 2U
#define FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_AT_LEAST_2MS 3U
#define FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_UNKNOWN \
	SCX_ADAPTIVE_PREEMPTION_RUNTIME_BIN_COUNT
/* Inherited tasks need enough samples for one-second behavior windows. */
#define FAST_EVENT_SAMPLE_INTERVAL_NS 4000000ULL
#define FAST_COARSE_EVENT_SAMPLE_INTERVAL_NS 16000000ULL
#define FAST_PIPELINE_SAMPLE_MASK 15ULL
#define FAST_DEFAULT_STATIC_PRIO 120U
#define FAST_QUEUE_SCOPE_NONE 0U
#define FAST_QUEUE_SCOPE_PRIVATE 1U
#define FAST_QUEUE_SCOPE_SHARED_BALANCED 2U
#define FAST_QUEUE_SCOPE_SHARED_LATENCY 3U

/* Non-zero monotonic source shared by task and process cookie allocation. */
static u64 next_identity_cookie = 1;

/* Number of tasks waiting in custom task DSQs (local DSQs are excluded). */
static volatile u64 class_queued_tasks;
/* Exact lane totals prevent one class from triggering another class's scan. */
static volatile u64 latency_queued_tasks;
/* Private Latency backlog remains distinguishable from the movable lane. */
static volatile u64 private_latency_queued_tasks;
static volatile u64 normal_queued_tasks;
static volatile u64 shared_balanced_queued_tasks;
static volatile u64 shared_latency_queued_tasks;

/*
 * Process map key combines a numeric TGID with the group leader start time.
 * The start time separates different lifetimes even when Linux reuses a TGID.
 */
struct process_identity_key {
	u32 tgid;
	u32 padding;
	u64 leader_start_boottime;
};

/*
 * Kernel-owned process identity state shared by every thread in a group.
 * active_threads allows deletion as soon as the final task exits.
 */
struct process_context {
	u64 process_cookie;
	u64 exec_generation;
	u32 active_threads;
	u32 padding;
};

/* Cache-line isolated claim and singleton locality lease for one core shard. */
struct core_latency_state {
	u64 singleton_release_ns;
	u32 dispatch_claim;
	u32 padding;
	u64 reserved[6];
};

_Static_assert(sizeof(struct core_latency_state) == 64,
	       "core_latency_state must remain cache-line isolated");

/*
 * Task-local data needed to validate one runnable instance and report runtime.
 * Every field is written by BPF; userspace observes only the event projection.
 */
struct task_context {
	u64 task_cookie;
	u64 process_cookie;
	u64 exec_generation;
	u64 enqueue_sequence;
	u64 enqueue_ns;
	u64 start_ns;
	u64 stop_ns;
	u64 last_observed_enqueue_ns;
	u64 vruntime_ns;
	u64 request_ns;
	u64 request_deadline_ns;
	u64 throughput_epoch_ns;
	s32 previous_cpu;
	s32 target_cpu;
	s32 vruntime_cpu;
	u32 tgid;
	u32 policy_class;
	u32 fast_path;
	u32 last_stop_blocked;
	u32 observe_fast_events;
	s32 selected_idle_cpu;
	u32 selected_class_id;
	u32 selected_control_flags;
	u32 selected_control_valid;
	u32 class_queue_accounted;
	u32 latency_budget_charged;
	struct process_identity_key process_key;
};

/* Per-task lifetime state; task_struct is the storage key. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_context);
} task_ctx_stor SEC(".maps");

/* Process identity and exec generation indexed by stable kernel lifetime key. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, struct process_identity_key);
	__type(value, struct process_context);
} process_ctx SEC(".maps");

/* BPF-to-Rust bounded lifecycle and behavior ring. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, SCX_ADAPTIVE_EVENT_RING_BYTES);
} task_events SEC(".maps");

/* Agent class generation mirrored by Rust and keyed by numeric TID. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);
	__type(value, struct task_control_value);
} task_control SEC(".maps");

/* One atomically replaced selector for the active userspace policy slot. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct adaptive_policy_control);
} policy_control SEC(".maps");

/* Two complete topology generations; userspace writes only the inactive one. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries,
	       SCX_ADAPTIVE_POLICY_SLOT_COUNT * SCX_ADAPTIVE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct adaptive_cpu_policy);
} cpu_policy SEC(".maps");

/* Shared bounded pipeline and liveness state for every possible CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SCX_ADAPTIVE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct adaptive_cpu_state);
} cpu_state SEC(".maps");

/* Separate shard state keeps cross-core claims off hot per-CPU ledgers. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SCX_ADAPTIVE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct core_latency_state);
} core_latency_state SEC(".maps");

/* Per-CPU statistics avoid cross-CPU cache-line contention on the fast path. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct adaptive_global_stats);
} global_stats SEC(".maps");

/** Returns the global statistics entry, or NULL only on an impossible map error. */
static __always_inline struct adaptive_global_stats *stats_value(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&global_stats, &key);
}

/** Increments the current CPU's statistics record when it is available. */
#define STAT_INC(field) do {                                              \
	struct adaptive_global_stats *stats = stats_value();                \
	if (stats)                                                           \
		stats->field++;                                                \
} while (0)

/** Returns one CPU's unified virtual-deadline task queue. */
static __always_inline u64 task_dsq(u32 cpu)
{
	return FAST_TASK_DSQ_BASE + cpu;
}

/** Returns one CPU's deadline-ordered latency lane. */
static __always_inline u64 latency_dsq(u32 cpu)
{
	return FAST_LATENCY_DSQ_BASE + cpu;
}

/** Returns one scheduling domain's shared Balanced overflow queue. */
static __always_inline u64 balanced_overflow_dsq(u32 domain_id)
{
	return FAST_BALANCED_OVERFLOW_DSQ_BASE + domain_id;
}

/** Returns one physical core's shared blocked-wakeup Latency queue. */
static __always_inline u64 shared_latency_dsq(u32 core_leader)
{
	return FAST_SHARED_LATENCY_DSQ_BASE + core_leader;
}

/** Resolves immutable scheduler-lifetime topology without a policy lease. */
static __always_inline u32 immutable_domain_for_cpu(s32 cpu)
{
	const volatile u32 *domain_id;

	if (cpu < 0 || cpu >= num_possible_cpus ||
	    cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	domain_id = MEMBER_VPTR(cpu_domain_id_map, [cpu]);
	if (!domain_id || *domain_id >= num_domains ||
	    *domain_id >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	return *domain_id;
}

/** Resolves the immutable representative used by one physical-core shard. */
static __always_inline u32 immutable_core_leader_for_cpu(s32 cpu)
{
	const volatile u32 *leader;

	if (cpu < 0 || cpu >= num_possible_cpus ||
	    cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	leader = MEMBER_VPTR(cpu_core_leader_map, [cpu]);
	if (!leader || *leader >= num_possible_cpus ||
	    *leader >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	return *leader;
}

/** Returns one representative SMT peer, or the leader on a single-thread core. */
static __always_inline u32 immutable_core_peer_for_leader(u32 leader)
{
	const volatile u32 *peer;

	if (leader >= num_possible_cpus || leader >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	peer = MEMBER_VPTR(cpu_core_peer_map, [leader]);
	if (!peer || *peer >= num_possible_cpus ||
	    *peer >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	return *peer;
}

/** Resolves one dense physical-core representative published by the loader. */
static __always_inline u32 immutable_core_leader_at(u32 index)
{
	const volatile u32 *leader;

	if (index >= num_core_leaders || index >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	leader = MEMBER_VPTR(core_leader_cpu_map, [index]);
	if (!leader || *leader >= num_possible_cpus ||
	    *leader >= SCX_ADAPTIVE_MAX_CPUS)
		return SCX_ADAPTIVE_INVALID_CPU;
	return *leader;
}

/** Returns the configured maximum request for one workload class. */
static __always_inline u64 class_slice(u32 class_id)
{
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		return latency_slice_ns;
	if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		return throughput_slice_ns;
	return balanced_slice_ns;
}

/** Converts service into weighted virtual time; Latency receives 2x weight. */
static __always_inline u64 task_virtual_service(
	const struct task_struct *p, u32 class_id, u64 service_ns)
{
	u64 service = scale_by_task_weight_inverse(p, service_ns);

	if (service_ns && !service)
		return 1;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		service = (service >> 1) + (service & 1);
	return service;
}

/** Returns the request retained by one task's current class epoch. */
static __always_inline u64 task_request_size(const struct task_context *taskc,
						      u32 class_id)
{
	u64 request;

	if (class_id != SCX_ADAPTIVE_CLASS_THROUGHPUT)
		return class_slice(class_id);
	request = taskc->throughput_epoch_ns;
	if (request < throughput_slice_ns)
		return throughput_slice_ns;
	if (request > max_slice_ns)
		return max_slice_ns;
	return request;
}
/** Grows a Throughput epoch only while no other classified task is waiting. */
static __always_inline u64 next_throughput_epoch(
	const struct task_context *taskc)
{
	u64 request = task_request_size(taskc, SCX_ADAPTIVE_CLASS_THROUGHPUT);

	if (__sync_fetch_and_add(&class_queued_tasks, 0) > 0)
		return throughput_slice_ns;
	return request <= max_slice_ns / 2 ? request * 2 : max_slice_ns;
}

/** Ends one custom-DSQ accounting lifetime exactly once. */
static __always_inline void clear_class_queue_account(
	struct task_context *taskc)
{
	struct adaptive_cpu_state *cpuc;
	u32 key;
	u32 queue_scope;
	u64 *queued = 0;

	if (!taskc || !taskc->class_queue_accounted)
		return;
	queue_scope = taskc->class_queue_accounted;

	taskc->class_queue_accounted = FAST_QUEUE_SCOPE_NONE;
	__sync_fetch_and_sub(&class_queued_tasks, 1);
	if (taskc->policy_class == SCX_ADAPTIVE_CLASS_LATENCY) {
		__sync_fetch_and_sub(&latency_queued_tasks, 1);
		if (queue_scope == FAST_QUEUE_SCOPE_SHARED_LATENCY)
			__sync_fetch_and_sub(&shared_latency_queued_tasks, 1);
		else
			__sync_fetch_and_sub(&private_latency_queued_tasks, 1);
	} else if (queue_scope == FAST_QUEUE_SCOPE_SHARED_BALANCED)
		__sync_fetch_and_sub(&shared_balanced_queued_tasks, 1);
	else
		__sync_fetch_and_sub(&normal_queued_tasks, 1);
	if (queue_scope == FAST_QUEUE_SCOPE_SHARED_BALANCED ||
	    queue_scope == FAST_QUEUE_SCOPE_SHARED_LATENCY)
		return;
	if (taskc->target_cpu < 0 ||
	    taskc->target_cpu >= num_possible_cpus ||
	    taskc->target_cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return;
	key = taskc->target_cpu;
	cpuc = bpf_map_lookup_elem(&cpu_state, &key);
	if (!cpuc)
		return;
	if (taskc->policy_class == SCX_ADAPTIVE_CLASS_LATENCY)
		queued = &cpuc->queued_tasks_by_class[0];
	else if (taskc->policy_class == SCX_ADAPTIVE_CLASS_BALANCED)
		queued = &cpuc->queued_tasks_by_class[1];
	else if (taskc->policy_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		queued = &cpuc->queued_tasks_by_class[2];
	if (queued && __sync_fetch_and_add(queued, 0) > 0)
		__sync_fetch_and_sub(queued, 1);
}

/** Looks up one bounded CPU state entry. */
static __always_inline struct adaptive_cpu_state *cpu_state_for(s32 cpu)
{
	u32 key;

	if (cpu < 0 || cpu >= num_possible_cpus || cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return 0;
	key = cpu;
	return bpf_map_lookup_elem(&cpu_state, &key);
}

/** Looks up the cache-line isolated state owned by one physical-core shard. */
static __always_inline struct core_latency_state *core_latency_state_for(
	u32 leader)
{
	if (leader >= num_possible_cpus || leader >= SCX_ADAPTIVE_MAX_CPUS)
		return 0;
	return bpf_map_lookup_elem(&core_latency_state, &leader);
}

/** Returns the active policy only while its lease and generation are valid. */
static __always_inline struct adaptive_policy_control *active_policy(u64 now)
{
	u32 key = 0;
	struct adaptive_policy_control *policy;

	policy = bpf_map_lookup_elem(&policy_control, &key);
	if (!policy || !(policy->flags & SCX_ADAPTIVE_POLICY_VALID) ||
	    policy->active_slot >= SCX_ADAPTIVE_POLICY_SLOT_COUNT ||
	    !policy->generation || policy->valid_until_ns <= now ||
	    !policy->domain_count || !policy->latency_budget_percent ||
	    policy->latency_budget_percent > 100)
		return 0;
	return policy;
}

/** Uses the leased userspace budget, with immutable rodata as safe fallback. */
static __always_inline u32 active_latency_budget(u64 now)
{
	struct adaptive_policy_control *policy = active_policy(now);

	return policy ? policy->latency_budget_percent : latency_budget_percent;
}

/** Bounds one singleton's home-core locality lease by a Latency request. */
static __always_inline u64 active_latency_locality_lease(u64 now)
{
	struct adaptive_policy_control *policy = active_policy(now);
	u64 lease = policy ? policy->latency_successor_lease_ns : latency_slice_ns;

	if (!lease || lease > latency_slice_ns)
		lease = latency_slice_ns;
	return lease;
}

/** Returns a bounded userspace-selected Balanced preemption granule. */
static __always_inline u64 active_balanced_granularity(u64 now)
{
	struct adaptive_policy_control *policy = active_policy(now);
	u64 granularity = policy ? policy->balanced_preemption_granularity_ns :
		balanced_slice_ns / 4;

	if (granularity < min_slice_ns)
		granularity = min_slice_ns;
	if (granularity > balanced_slice_ns)
		granularity = balanced_slice_ns;
	return granularity;
}

/** Resolves one CPU record from the atomically selected complete policy slot. */
static __always_inline struct adaptive_cpu_policy *policy_cpu_for(
	const struct adaptive_policy_control *policy, s32 cpu)
{
	u32 key;
	struct adaptive_cpu_policy *cpu_policy_value;

	if (!policy || cpu < 0 || cpu >= num_possible_cpus ||
	    cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return 0;
	key = policy->active_slot * SCX_ADAPTIVE_MAX_CPUS + (u32)cpu;
	cpu_policy_value = bpf_map_lookup_elem(&cpu_policy, &key);
	if (!cpu_policy_value || cpu_policy_value->generation != policy->generation)
		return 0;
	return cpu_policy_value;
}

/** Categorizes a cross-CPU handoff using the active immutable topology view. */
static __always_inline u32 cpu_locality(s32 from_cpu, s32 to_cpu, u64 now)
{
	struct adaptive_policy_control *policy = active_policy(now);
	struct adaptive_cpu_policy *from;
	struct adaptive_cpu_policy *to;

	if (!policy || from_cpu < 0 || to_cpu < 0 ||
	    from_cpu >= num_possible_cpus || to_cpu >= num_possible_cpus ||
	    from_cpu == to_cpu)
		return FAST_CPU_LOCALITY_UNKNOWN;
	from = policy_cpu_for(policy, from_cpu);
	to = policy_cpu_for(policy, to_cpu);
	if (!from || !to)
		return FAST_CPU_LOCALITY_UNKNOWN;
	if (from->package_id == to->package_id &&
	    from->core_id == to->core_id)
		return FAST_CPU_LOCALITY_SMT;
	if (from->llc_id == to->llc_id)
		return FAST_CPU_LOCALITY_SAME_LLC;
	return FAST_CPU_LOCALITY_CROSS_LLC;
}

/** Updates one already-looked-up per-CPU record for a class dispatch. */
static __always_inline void account_fast_dispatch(
	struct adaptive_global_stats *stats, u32 class_id, bool remote)
{
	if (!stats)
		return;
	stats->fast_path_dispatches++;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		stats->fast_path_dispatches_by_class[0]++;
	else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED)
		stats->fast_path_dispatches_by_class[1]++;
	else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		stats->fast_path_dispatches_by_class[2]++;
	if (remote) {
		stats->fast_path_remote_steals++;
		if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
			stats->fast_path_remote_dispatches_by_class[0]++;
		else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED)
			stats->fast_path_remote_dispatches_by_class[1]++;
		else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
			stats->fast_path_remote_dispatches_by_class[2]++;
	} else {
		stats->fast_path_local_dispatches++;
	}
}

/** Records one local or remote class dispatch. */
static __always_inline void record_fast_dispatch(u32 class_id, bool remote,
	s32 owner_cpu, s32 actual_cpu, u64 now)
{
	struct adaptive_global_stats *stats = stats_value();
	u32 locality;

	account_fast_dispatch(stats, class_id, remote);
	if (!stats || !remote)
		return;
	locality = cpu_locality(owner_cpu, actual_cpu, now);
	if (locality >= SCX_ADAPTIVE_CPU_LOCALITY_COUNT)
		return;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		stats->fast_path_latency_remote_dispatches_by_locality[locality]++;
	else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		stats->fast_path_throughput_remote_dispatches_by_locality[locality]++;
}

/** Records one enqueue and its observation/direct-dispatch properties. */
static __always_inline void record_fast_enqueue(
	u32 class_id, bool direct, bool events_suppressed,
	bool selected_migration, u32 selected_locality)
{
	struct adaptive_global_stats *stats = stats_value();

	if (!stats)
		return;
	stats->fast_path_enqueues++;
	if (events_suppressed)
		stats->fast_path_events_suppressed++;
	if (direct)
		stats->fast_path_direct_dispatches++;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY) {
		if (selected_migration) {
			stats->fast_path_select_migrations_by_class[0]++;
			if (selected_locality < SCX_ADAPTIVE_CPU_LOCALITY_COUNT)
				stats->fast_path_latency_select_migrations_by_locality[
					selected_locality]++;
		}
	} else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED) {
		if (selected_migration)
			stats->fast_path_select_migrations_by_class[1]++;
	} else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT) {
		if (selected_migration) {
			stats->fast_path_select_migrations_by_class[2]++;
			if (selected_locality < SCX_ADAPTIVE_CPU_LOCALITY_COUNT)
				stats->fast_path_throughput_select_migrations_by_locality[
					selected_locality]++;
		}
	}
}

/** Records only final select_cpu outcomes, after every candidate override. */
static __always_inline void record_select_cpu_diagnostics(
	u32 class_id, u32 latency_path, s32 cpu, s32 prev_cpu, u64 wake_flags)
{
	struct adaptive_global_stats *stats;
	bool migrated = cpu != prev_cpu;

	if (class_id != SCX_ADAPTIVE_CLASS_LATENCY &&
	    !(wake_flags & SCX_WAKE_SYNC))
		return;
	stats = stats_value();
	if (!stats)
		return;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY) {
		if (latency_path == SCX_ADAPTIVE_LATENCY_SELECT_DEFAULT_IDLE) {
			stats->fast_path_latency_selects_by_path[0]++;
			if (migrated)
				stats->fast_path_latency_select_migrations_by_path[0]++;
		} else if (latency_path == SCX_ADAPTIVE_LATENCY_SELECT_DEFAULT_BUSY) {
			stats->fast_path_latency_selects_by_path[1]++;
			if (migrated)
				stats->fast_path_latency_select_migrations_by_path[1]++;
		} else if (latency_path == SCX_ADAPTIVE_LATENCY_SELECT_POLICY_VICTIM) {
			stats->fast_path_latency_selects_by_path[2]++;
			if (migrated)
				stats->fast_path_latency_select_migrations_by_path[2]++;
		} else {
			stats->fast_path_latency_selects_by_path[3]++;
			if (migrated)
				stats->fast_path_latency_select_migrations_by_path[3]++;
		}
	}
	if (!(wake_flags & SCX_WAKE_SYNC))
		return;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY) {
		stats->fast_path_select_sync_wakeups_by_class[0]++;
		if (migrated)
			stats->fast_path_select_sync_migrations_by_class[0]++;
	} else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED) {
		stats->fast_path_select_sync_wakeups_by_class[1]++;
		if (migrated)
			stats->fast_path_select_sync_migrations_by_class[1]++;
	} else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT) {
		stats->fast_path_select_sync_wakeups_by_class[2]++;
		if (migrated)
			stats->fast_path_select_sync_migrations_by_class[2]++;
	}
}

/** Records a PREEMPT kick only at the call site that actually issues it. */
static __always_inline void record_immediate_preemption_kick(u32 class_id)
{
	struct adaptive_global_stats *stats = stats_value();

	if (!stats)
		return;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		stats->fast_path_immediate_preemption_kicks_by_class[0]++;
	else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED)
		stats->fast_path_immediate_preemption_kicks_by_class[1]++;
}

static __always_inline struct task_context *task_ctx_for(struct task_struct *p);

/** Bins one Throughput victim's uninterrupted service before a reschedule. */
static __always_inline u32 throughput_preemption_runtime_bin(u64 runtime)
{
	if (runtime < 500000ULL)
		return FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_UNDER_500US;
	if (runtime < 1000000ULL)
		return FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_500US_TO_1MS;
	if (runtime < 2000000ULL)
		return FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_1MS_TO_2MS;
	return FAST_THROUGHPUT_PREEMPTION_RUNTIME_BIN_AT_LEAST_2MS;
}

/** Accounts the service a Throughput victim received before an urgent reschedule. */
static __always_inline void account_throughput_preemption_service(
	struct adaptive_global_stats *stats, struct task_struct *prev,
	const struct adaptive_cpu_state *cpuc, u64 now)
{
	struct task_context *taskc;
	u32 service_bin;
	u32 runtime_bin;
	u64 runtime;
	u64 request;

	if (!stats || !prev || !cpuc)
		return;
	taskc = task_ctx_for(prev);
	if (!taskc || taskc->policy_class != SCX_ADAPTIVE_CLASS_THROUGHPUT ||
	    !taskc->start_ns || now < taskc->start_ns)
		return;
	request = taskc->request_ns;
	if (!request)
		return;
	runtime = now - taskc->start_ns;
	if (runtime < request / 4)
		service_bin = FAST_THROUGHPUT_PREEMPTION_BIN_EARLY;
	else if (runtime < request / 2)
		service_bin = FAST_THROUGHPUT_PREEMPTION_BIN_MID;
	else if (runtime < request - request / 10)
		service_bin = FAST_THROUGHPUT_PREEMPTION_BIN_LATE;
	else
		service_bin = FAST_THROUGHPUT_PREEMPTION_BIN_COMPLETE;
	runtime_bin = throughput_preemption_runtime_bin(runtime);
	stats->fast_path_throughput_preemption_service_bins[service_bin]++;
	if (runtime_bin < SCX_ADAPTIVE_PREEMPTION_RUNTIME_BIN_COUNT)
		stats->fast_path_throughput_preemption_runtime_bins[runtime_bin]++;
	stats->fast_path_throughput_preemption_runtime_ns += runtime;
	stats->fast_path_throughput_preemption_request_ns += request;
}

/** Records the requester and victim of one successfully consumed reschedule. */
static __always_inline void record_fast_preemption(
	u32 class_id, u32 victim_class, struct task_struct *prev,
	const struct adaptive_cpu_state *cpuc, u64 now)
{
	struct adaptive_global_stats *stats = stats_value();

	if (!stats)
		return;
	stats->fast_path_preemptions++;
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		stats->fast_path_preemptions_by_class[0]++;
	else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED)
		stats->fast_path_preemptions_by_class[1]++;
	else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		stats->fast_path_preemptions_by_class[2]++;
	if (victim_class == SCX_ADAPTIVE_CLASS_LATENCY)
		stats->fast_path_preemption_victims_by_class[0]++;
	else if (victim_class == SCX_ADAPTIVE_CLASS_BALANCED)
		stats->fast_path_preemption_victims_by_class[1]++;
	else if (victim_class == SCX_ADAPTIVE_CLASS_THROUGHPUT) {
		stats->fast_path_preemption_victims_by_class[2]++;
		account_throughput_preemption_service(stats, prev, cpuc, now);
	}
}

/** Allocates a non-zero cookie; zero is reserved for "identity unavailable". */
static __always_inline u64 allocate_cookie(void)
{
	u64 cookie = __sync_fetch_and_add(&next_identity_cookie, 1);

	if (cookie == 0)
		cookie = __sync_fetch_and_add(&next_identity_cookie, 1);
	return cookie;
}

/** Builds the stable process-map key for a task's current thread group. */
static __always_inline struct process_identity_key process_key_for(struct task_struct *p)
{
	struct process_identity_key key = {};

	key.tgid = p->tgid;
	key.leader_start_boottime = BPF_CORE_READ(p, group_leader, start_boottime);
	return key;
}

/** Looks up task storage without creating it on an unsafe callback path. */
static __always_inline struct task_context *task_ctx_for(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

/** Returns true for tasks that must never wait on Rust scheduling decisions. */
static __always_inline bool is_safe_task(const struct task_struct *p)
{
	if (p->tgid == 1)
		return true;
	if (p->flags & PF_KTHREAD)
		return true;
	if (usersched_pid && p->tgid == usersched_pid)
		return true;
	return agent_pid && p->tgid == agent_pid;
}

/** Returns a complete BPF scheduling control record for this exact task image. */
static __always_inline struct task_control_value *fast_control_for(
	struct task_struct *p, struct task_context *taskc)
{
	struct task_control_value *control;
	u32 tid = p->pid;

	control = bpf_map_lookup_elem(&task_control, &tid);
	if (!control || !(control->flags & SCX_ADAPTIVE_CONTROL_BPF_SCHED) ||
	    (control->flags & ~SCX_ADAPTIVE_CONTROL_FLAG_MASK) ||
	    control->class_id >= SCX_ADAPTIVE_CLASS_COUNT)
		return 0;
	if (control->task_cookie != taskc->task_cookie ||
	    control->process_cookie != taskc->process_cookie ||
	    control->exec_generation != taskc->exec_generation)
		return 0;
	return control;
}

/** Pushes one event and optionally forces an immediate ring-buffer wakeup. */
static __always_inline bool queue_event(struct task_event *event, bool force_wakeup)
{
	u64 ring_flags = force_wakeup ? BPF_RB_FORCE_WAKEUP :
		BPF_RB_NO_WAKEUP;

	if (bpf_ringbuf_output(&task_events, event, sizeof(*event), ring_flags)) {
		STAT_INC(event_overflows);
		return false;
	}

	return true;
}

/** Keeps unclassified observation useful without taxing every wakeup. */
static __always_inline u64 fast_event_sample_interval(u32 control_flags)
{
	return control_flags & SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE ?
		FAST_COARSE_EVENT_SAMPLE_INTERVAL_NS : FAST_EVENT_SAMPLE_INTERVAL_NS;
}

/** Pushes a slow-path or control event that requires immediate Rust work. */
static __always_inline bool emit_event(struct task_event *event)
{
	return queue_event(event, true);
}

/** Pushes ordered fast-path telemetry without a scheduler wakeup. */
static __always_inline bool emit_fast_event(struct task_event *event)
{
	return queue_event(event, false);
}

/** Fills the identity fields common to all task lifecycle events. */
static __always_inline void fill_task_event(struct task_event *event,
					     struct task_struct *p,
					     struct task_context *taskc,
					     u16 event_kind,
					     u64 now)
{
	event->abi_version = SCX_ADAPTIVE_ABI_VERSION;
	event->event_kind = event_kind;
	event->struct_size = sizeof(*event);
	event->tid = p->pid;
	event->tgid = taskc->tgid;
	event->task_cookie = taskc->task_cookie;
	event->process_cookie = taskc->process_cookie;
	event->exec_generation = taskc->exec_generation;
	event->enqueue_sequence = taskc->enqueue_sequence;
	event->timestamp_ns = now;
	event->previous_cpu = taskc->previous_cpu;
	event->actual_cpu = -1;
}

static __always_inline u64 fast_queued_on_cpu(s32 cpu);

/** Returns true when an idle target already has local work to preserve. */
static __always_inline bool cpu_has_local_work(
	s32 cpu, const struct adaptive_cpu_state *cpuc)
{
	if (!cpuc)
		return true;
	return cpuc->urgent_dispatch_id ||
		scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) > 0 ||
		fast_queued_on_cpu(cpu) > 0;
}

/** Holds enough credit to preserve the configured share across a Normal slice. */
static __always_inline u64 latency_credit_cap_ns(u32 budget)
{
	u64 competing_slice = balanced_slice_ns > throughput_slice_ns ?
		balanced_slice_ns : throughput_slice_ns;
	u64 cap = competing_slice * budget / 100;

	return cap < latency_slice_ns ? latency_slice_ns : cap;
}

/** Bounds wakeup borrowing so a continuously runnable task cannot monopolize. */
static __always_inline u64 latency_debt_cap_ns(void)
{
	return latency_slice_ns * FAST_LATENCY_DEBT_CAP_SLICES;
}

/** Computes signed credit minus debt without mutating remote per-CPU state. */
static __always_inline s64 latency_balance_for(
	const struct adaptive_cpu_state *cpuc, u64 now, u32 budget)
{
	u64 credit_cap = latency_credit_cap_ns(budget);
	u64 debt_cap = latency_debt_cap_ns();
	u64 credit;
	u64 debt;
	u64 elapsed;
	u64 accrued;
	u64 horizon;
	if (!cpuc || !budget || budget > 100)
		return 0;
	credit = cpuc->latency_credit_ns;
	debt = cpuc->latency_debt_ns;
	if (credit > credit_cap)
		credit = credit_cap;
	if (debt > debt_cap)
		debt = debt_cap;
	if (!cpuc->latency_credit_updated_ns)
		return latency_slice_ns < credit_cap ?
			(s64)latency_slice_ns : (s64)credit_cap;
	if (now <= cpuc->latency_credit_updated_ns)
		return credit >= debt ? (s64)(credit - debt) :
			-(s64)(debt - credit);

	elapsed = now - cpuc->latency_credit_updated_ns;
	horizon = credit_cap + debt_cap;
	if (elapsed > horizon * 100 / budget)
		elapsed = horizon * 100 / budget;
	accrued = elapsed * budget / 100;
	if (accrued < debt)
		return -(s64)(debt - accrued);
	accrued -= debt;
	return accrued >= credit_cap - credit ? (s64)credit_cap :
		(s64)(credit + accrued);
}

/** Refreshes one CPU's bounded credit and debt at a scheduling boundary. */
static __always_inline s64 refresh_latency_budget(
	struct adaptive_cpu_state *cpuc, u64 now, u32 budget)
{
	s64 balance = latency_balance_for(cpuc, now, budget);

	if (cpuc) {
		if (balance >= 0) {
			cpuc->latency_credit_ns = balance;
			cpuc->latency_debt_ns = 0;
		} else {
			cpuc->latency_credit_ns = 0;
			cpuc->latency_debt_ns = -balance;
		}
		cpuc->latency_credit_updated_ns = now;
	}
	return balance;
}

/** Charges actual competing Latency runtime and saturates bounded wake debt. */
static __always_inline void charge_latency_budget(
	struct adaptive_cpu_state *cpuc, u64 now, u64 runtime_ns, u32 budget)
{
	struct adaptive_global_stats *stats;
	s64 balance;
	u64 debt_cap = latency_debt_cap_ns();
	u64 debt;

	if (!cpuc || !runtime_ns)
		return;
	stats = stats_value();
	if (stats) {
		stats->fast_path_latency_budget_charge_events++;
		stats->fast_path_latency_budget_runtime_ns += runtime_ns;
	}
	balance = refresh_latency_budget(cpuc, now, budget);
	if (balance >= 0) {
		u64 credit = balance;

		if (runtime_ns <= credit) {
			cpuc->latency_credit_ns = credit - runtime_ns;
			return;
		}
		cpuc->latency_credit_ns = 0;
		debt = runtime_ns - credit;
		cpuc->latency_debt_ns = debt < debt_cap ? debt : debt_cap;
		return;
	}
	debt = -balance;
	if (debt >= debt_cap || runtime_ns >= debt_cap - debt)
		cpuc->latency_debt_ns = debt_cap;
	else
		cpuc->latency_debt_ns = debt + runtime_ns;
}

/** Allows a true blocked wakeup to borrow only inside the bounded debt window. */
static __always_inline bool latency_wakeup_budget_available(
	const struct adaptive_cpu_state *cpuc, u64 now, u32 budget)
{
	return latency_balance_for(cpuc, now, budget) >
		-(s64)latency_debt_cap_ns();
}

/** Bounds cache-disrupting urgent service to one request per Normal quantum. */
static __always_inline bool latency_preemption_time_allowed(
	const struct adaptive_cpu_state *cpuc, u64 now,
	const struct adaptive_policy_control *policy)
{
	u64 interval = latency_preemption_interval_ns;
	u64 min_runtime = latency_slice_ns;

	if (policy && policy->preemption_interval_ns)
		interval = policy->preemption_interval_ns;
	if (cpuc && cpuc->running_class == SCX_ADAPTIVE_CLASS_THROUGHPUT) {
		min_runtime = throughput_preemption_min_runtime_ns;
		if (min_runtime < latency_slice_ns)
			min_runtime = latency_slice_ns;
		if (min_runtime > throughput_slice_ns)
			min_runtime = throughput_slice_ns;
	}
	if (!cpuc || !cpuc->running_started_ns ||
	    now < cpuc->running_started_ns ||
	    now - cpuc->running_started_ns < min_runtime)
		return false;
	if (cpuc->last_preemption_ns &&
	    (now < cpuc->last_preemption_ns ||
	     now - cpuc->last_preemption_ns < interval))
		return false;
	return true;
}

/** Claims or upgrades the reschedule marker for a blocked Latency wakeup. */
static __always_inline bool claim_latency_resched(
	struct adaptive_cpu_state *cpuc)
{
	u64 marker;

	marker = __sync_val_compare_and_swap(&cpuc->urgent_dispatch_id, 0,
					     FAST_LATENCY_RESCHED_ID);
	if (!marker)
		return true;
	return marker == FAST_BALANCED_RESCHED_ID &&
		__sync_val_compare_and_swap(&cpuc->urgent_dispatch_id,
			FAST_BALANCED_RESCHED_ID, FAST_LATENCY_RESCHED_ID) ==
			FAST_BALANCED_RESCHED_ID;
}

/** Requests bounded preemption of a non-Latency userspace victim. */
static __always_inline bool arm_latency_preemption(s32 cpu, u64 now)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	struct adaptive_policy_control *policy = active_policy(now);
	u32 budget = policy ? policy->latency_budget_percent :
		latency_budget_percent;

	if (!cpuc || !cpuc->online || cpuc->idle ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY)
		return false;
	if (!latency_wakeup_budget_available(cpuc, now, budget)) {
		STAT_INC(fast_path_preemption_throttles);
		return false;
	}
	if (!claim_latency_resched(cpuc))
		return false;
	if (!latency_preemption_time_allowed(cpuc, now, policy)) {
		STAT_INC(fast_path_preemption_deferrals);
		return false;
	}
	cpuc->last_preemption_ns = now;
	return true;
}

/** Preempts only a material EEVDF deadline inversion after a blocked wakeup. */
static __always_inline bool arm_balanced_preemption(
	struct task_struct *p, struct task_context *taskc, s32 cpu, u64 now)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	u64 granularity;
	u64 balanced_granularity;
	u64 min_runtime;
	u64 runtime;

	if (!cpuc || !cpuc->online || cpuc->idle ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY ||
	    !cpuc->running_started_ns || !cpuc->running_deadline_ns ||
	    !taskc->request_deadline_ns || now < cpuc->running_started_ns ||
	    taskc->request_deadline_ns >= cpuc->running_deadline_ns)
		return false;
	balanced_granularity = active_balanced_granularity(now);
	granularity = task_virtual_service(
		p, SCX_ADAPTIVE_CLASS_BALANCED,
		cpuc->running_class == SCX_ADAPTIVE_CLASS_THROUGHPUT ?
			balanced_slice_ns : balanced_granularity);
	if (cpuc->running_deadline_ns - taskc->request_deadline_ns <= granularity)
		return false;

	min_runtime = balanced_granularity;
	if (cpuc->running_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		min_runtime = min_slice_ns *
			FAST_BALANCED_THROUGHPUT_MIN_RUNTIME_SLICES;
	runtime = now - cpuc->running_started_ns;
	if (__sync_val_compare_and_swap(&cpuc->urgent_dispatch_id, 0,
					FAST_BALANCED_RESCHED_ID) != 0)
		return false;
	return runtime >= min_runtime;
}

/** Starts one runnable incarnation after its scheduling path is known. */
static __always_inline void begin_enqueue(struct task_context *taskc, u64 now)
{
	taskc->enqueue_sequence++;
	if (taskc->enqueue_sequence == 0)
		taskc->enqueue_sequence++;
	taskc->enqueue_ns = now;
	taskc->selected_control_valid = 0;
}

/** Inserts one ordinary runnable incarnation by its effective virtual deadline. */
static __always_inline bool fast_enqueue(struct task_struct *p,
					 struct task_context *taskc,
					 u32 class_id, u32 control_flags,
					 u64 enq_flags, u64 now,
					 s32 owner_cpu, bool from_select)
{
	struct adaptive_cpu_state *ownerc;
	struct task_event event = {};
	s32 selected_idle_cpu = taskc->selected_idle_cpu;
	u64 request;
	u64 sleep_credit;
	u64 virtual_request;
	bool credit_eligible;
	bool class_changed;
	bool clock_changed;
	bool had_clock;
	bool direct;
	bool preempt;
	bool shared_balanced;
	bool shared_latency;
	bool selected_migration;
	u32 shared_domain = SCX_ADAPTIVE_INVALID_CPU;
	u32 shared_latency_shard = SCX_ADAPTIVE_INVALID_CPU;
	bool woke_from_sleep;
	u32 selected_locality = FAST_CPU_LOCALITY_UNKNOWN;

	ownerc = cpu_state_for(owner_cpu);
	if (!ownerc || !ownerc->online ||
	    !bpf_cpumask_test_cpu(owner_cpu, p->cpus_ptr))
		return false;
	selected_migration = taskc->selected_control_valid &&
		owner_cpu != taskc->previous_cpu;
	if (selected_migration &&
	    (class_id == SCX_ADAPTIVE_CLASS_LATENCY ||
	     class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT))
		selected_locality = cpu_locality(
			taskc->previous_cpu, owner_cpu, now);
	woke_from_sleep = taskc->last_stop_blocked;
	begin_enqueue(taskc, now);
	taskc->selected_idle_cpu = -1;
	class_changed = !taskc->fast_path || taskc->policy_class != class_id;
	credit_eligible = class_changed || woke_from_sleep;
	had_clock = taskc->vruntime_cpu >= 0;
	clock_changed = taskc->vruntime_cpu != owner_cpu;
	if (class_changed) {
		taskc->request_ns = 0;
		taskc->request_deadline_ns = 0;
		taskc->throughput_epoch_ns =
			class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT ?
				throughput_slice_ns : 0;
	}
	request = task_request_size(taskc, class_id);
	virtual_request = task_virtual_service(p, class_id, request);
	if (clock_changed) {
		if (had_clock && credit_eligible)
			taskc->vruntime_ns = ownerc->virtual_time_ns < virtual_request ?
				0 : ownerc->virtual_time_ns - virtual_request;
		else
			taskc->vruntime_ns = ownerc->virtual_time_ns;
		taskc->vruntime_cpu = owner_cpu;
		if (taskc->request_ns)
			taskc->request_deadline_ns = taskc->vruntime_ns +
				task_virtual_service(
					p, class_id, taskc->request_ns);
	}
	if (!taskc->request_ns) {
		if (credit_eligible && !clock_changed) {
			sleep_credit = ownerc->virtual_time_ns < virtual_request ?
				ownerc->virtual_time_ns : virtual_request;
			if (taskc->vruntime_ns <
			    ownerc->virtual_time_ns - sleep_credit)
				taskc->vruntime_ns =
					ownerc->virtual_time_ns - sleep_credit;
		}
		taskc->request_ns = request;
		taskc->request_deadline_ns = taskc->vruntime_ns + virtual_request;
	}

	taskc->policy_class = class_id;
	taskc->fast_path = 1;
	taskc->observe_fast_events =
		!!(control_flags & SCX_ADAPTIVE_CONTROL_OBSERVE) &&
		(!taskc->last_observed_enqueue_ns ||
		 now < taskc->last_observed_enqueue_ns ||
			now - taskc->last_observed_enqueue_ns >=
				 fast_event_sample_interval(control_flags));
	if (taskc->observe_fast_events)
		taskc->last_observed_enqueue_ns = now;
	taskc->target_cpu = owner_cpu;
	if (taskc->observe_fast_events) {
		fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_ENQUEUE, now);
		if (taskc->last_stop_blocked) {
			event.flags |= SCX_ADAPTIVE_EVENT_FLAG_WAKEUP;
			event.sleep_ns = taskc->stop_ns && now >= taskc->stop_ns ?
					 now - taskc->stop_ns : 0;
		}
		emit_fast_event(&event);
	}
	taskc->last_stop_blocked = 0;

	direct = selected_idle_cpu == owner_cpu &&
		 !cpu_has_local_work(owner_cpu, ownerc);
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY && !direct &&
	    woke_from_sleep && p->nr_cpus_allowed == num_possible_cpus &&
	    !is_migration_disabled(p) && p->static_prio == FAST_DEFAULT_STATIC_PRIO) {
		shared_domain = immutable_domain_for_cpu(owner_cpu);
		shared_latency_shard = immutable_core_leader_for_cpu(owner_cpu);
	} else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED && !direct &&
	    !woke_from_sleep && p->nr_cpus_allowed == num_possible_cpus &&
	    !is_migration_disabled(p) && p->static_prio == FAST_DEFAULT_STATIC_PRIO)
		shared_domain = immutable_domain_for_cpu(owner_cpu);
	shared_latency = class_id == SCX_ADAPTIVE_CLASS_LATENCY &&
		shared_domain < num_domains &&
		shared_latency_shard < num_possible_cpus &&
		immutable_domain_for_cpu(shared_latency_shard) == shared_domain;
	shared_balanced = class_id == SCX_ADAPTIVE_CLASS_BALANCED &&
		shared_domain < num_domains;
	preempt = false;
	if (shared_latency) {
		struct core_latency_state *shardc =
			core_latency_state_for(shared_latency_shard);

		if (shardc && scx_bpf_dsq_nr_queued(
				shared_latency_dsq(shared_latency_shard)) <= 0)
			shardc->singleton_release_ns = now +
				active_latency_locality_lease(now);
	}
	if (direct) {
		taskc->class_queue_accounted = FAST_QUEUE_SCOPE_NONE;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | owner_cpu,
				   taskc->request_ns, enq_flags);
	} else {
		taskc->class_queue_accounted = shared_latency ?
			FAST_QUEUE_SCOPE_SHARED_LATENCY :
			(shared_balanced ? FAST_QUEUE_SCOPE_SHARED_BALANCED :
			 FAST_QUEUE_SCOPE_PRIVATE);
		__sync_fetch_and_add(&class_queued_tasks, 1);
		if (class_id == SCX_ADAPTIVE_CLASS_LATENCY) {
			__sync_fetch_and_add(&latency_queued_tasks, 1);
			if (shared_latency) {
				__sync_fetch_and_add(&shared_latency_queued_tasks, 1);
				STAT_INC(fast_path_shared_latency_enqueues);
			} else {
				__sync_fetch_and_add(&private_latency_queued_tasks, 1);
				__sync_fetch_and_add(
					&ownerc->queued_tasks_by_class[0], 1);
			}
		} else if (shared_balanced) {
			__sync_fetch_and_add(&shared_balanced_queued_tasks, 1);
			STAT_INC(fast_path_shared_balanced_enqueues);
		} else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED) {
			__sync_fetch_and_add(&normal_queued_tasks, 1);
			__sync_fetch_and_add(
				&ownerc->queued_tasks_by_class[1], 1);
		} else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT) {
			__sync_fetch_and_add(&normal_queued_tasks, 1);
			__sync_fetch_and_add(
				&ownerc->queued_tasks_by_class[2], 1);
		}
		if (shared_latency)
			scx_bpf_dsq_insert(
				p, shared_latency_dsq(shared_latency_shard),
				taskc->request_ns, enq_flags);
		else if (shared_balanced)
			scx_bpf_dsq_insert(
				p, balanced_overflow_dsq(shared_domain),
				taskc->request_ns, enq_flags);
		else
			scx_bpf_dsq_insert_vtime(
				p, class_id == SCX_ADAPTIVE_CLASS_LATENCY ?
					latency_dsq(owner_cpu) : task_dsq(owner_cpu),
				taskc->request_ns, taskc->request_deadline_ns,
				enq_flags);
		if (woke_from_sleep && class_id == SCX_ADAPTIVE_CLASS_LATENCY)
			preempt = arm_latency_preemption(owner_cpu, now);
		else if (woke_from_sleep && class_id == SCX_ADAPTIVE_CLASS_BALANCED)
			preempt = arm_balanced_preemption(
				p, taskc, owner_cpu, now);
	}
	record_fast_enqueue(class_id, direct, !taskc->observe_fast_events,
			 selected_migration, selected_locality);
	/* A custom DSQ does not inherit select_cpu's idle wakeup guarantee. */
	if (!direct && !preempt && ownerc->idle &&
	    (selected_idle_cpu == owner_cpu || !from_select))
		scx_bpf_kick_cpu(owner_cpu, SCX_KICK_IDLE);
	if (!from_select) {
		if (preempt) {
			record_immediate_preemption_kick(class_id);
			scx_bpf_kick_cpu(owner_cpu, SCX_KICK_PREEMPT);
		}
	}
	return true;
}

/** Keeps fallback work local when its current CPU is still a valid target. */
static __always_inline void fallback_dispatch(struct task_struct *p,
					       struct task_context *taskc,
					       u64 enq_flags)
{
	struct adaptive_cpu_state *cpuc;
	s32 cpu = scx_bpf_task_cpu(p);

	taskc->target_cpu = -1;
	cpuc = cpu_state_for(cpu);
	if (cpu >= 0 && cpu < num_possible_cpus && cpuc && cpuc->online &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
				   SCX_SLICE_DFL, enq_flags);
	else
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	STAT_INC(fallback_dispatches);
}

/** Preserves observable BPF ownership when an exceptional CPU target is unusable. */
static __always_inline void fallback_fast_enqueue(
	struct task_struct *p, struct task_context *taskc, u32 class_id,
	u32 control_flags, u64 enq_flags, u64 now)
{
	struct task_event event = {};
	bool woke_from_sleep = taskc->last_stop_blocked;

	begin_enqueue(taskc, now);
	taskc->selected_idle_cpu = -1;
	taskc->target_cpu = -1;
	taskc->policy_class = class_id;
	taskc->fast_path = 1;
	taskc->request_ns = 0;
	taskc->request_deadline_ns = 0;
	taskc->throughput_epoch_ns =
		class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT ?
			throughput_slice_ns : 0;
	taskc->class_queue_accounted = 0;
	taskc->observe_fast_events =
		!!(control_flags & SCX_ADAPTIVE_CONTROL_OBSERVE) &&
		(!taskc->last_observed_enqueue_ns ||
		 now < taskc->last_observed_enqueue_ns ||
			now - taskc->last_observed_enqueue_ns >=
				 fast_event_sample_interval(control_flags));
	if (taskc->observe_fast_events) {
		taskc->last_observed_enqueue_ns = now;
		fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_ENQUEUE, now);
		if (woke_from_sleep) {
			event.flags |= SCX_ADAPTIVE_EVENT_FLAG_WAKEUP;
			event.sleep_ns = taskc->stop_ns && now >= taskc->stop_ns ?
					 now - taskc->stop_ns : 0;
		}
		emit_fast_event(&event);
	}
	taskc->last_stop_blocked = 0;
	fallback_dispatch(p, taskc, enq_flags);
}

/** Moves the earliest unified task from one CPU into the caller's local DSQ. */
static __always_inline bool dispatch_fast_task(s32 src_cpu)
{
	if (src_cpu < 0 || src_cpu >= num_possible_cpus)
		return false;
	return scx_bpf_dsq_move_to_local(task_dsq(src_cpu));
}

/** Moves the earliest latency request into the caller's local DSQ. */
static __always_inline bool dispatch_latency_task(s32 cpu)
{
	if (cpu < 0 || cpu >= num_possible_cpus)
		return false;
	return scx_bpf_dsq_move_to_local(latency_dsq(cpu));
}

/** Returns the caller's physical-core Latency shard depth. */
static __always_inline s64 shared_latency_depth(s32 cpu)
{
	u32 leader = immutable_core_leader_for_cpu(cpu);

	if (leader >= num_possible_cpus)
		return 0;
	return scx_bpf_dsq_nr_queued(shared_latency_dsq(leader));
}

/** Returns one domain's current movable Balanced queue depth. */
static __always_inline s64 shared_balanced_depth(s32 cpu)
{
	u32 domain_id = immutable_domain_for_cpu(cpu);

	if (domain_id >= num_domains)
		return 0;
	return scx_bpf_dsq_nr_queued(balanced_overflow_dsq(domain_id));
}

/** Consumes one wide-affinity Balanced overflow task from the local domain. */
static __always_inline bool dispatch_shared_balanced(s32 cpu)
{
	u32 domain_id;

	domain_id = immutable_domain_for_cpu(cpu);
	if (domain_id >= num_domains)
		return false;
	if (shared_balanced_depth(cpu) <= 0)
		return false;
	STAT_INC(fast_path_shared_balanced_dispatch_attempts);
	if (scx_bpf_dsq_move_to_local(balanced_overflow_dsq(domain_id))) {
		STAT_INC(fast_path_shared_balanced_dispatches);
		return true;
	}
	STAT_INC(fast_path_shared_balanced_dispatch_failures);
	return false;
}

/** Leaves a singleton on its core when either representative SMT is idle. */
static __always_inline bool defer_shared_latency_to_idle_core(u32 leader)
{
	struct adaptive_cpu_state *cpuc;
	u32 peer = immutable_core_peer_for_leader(leader);

	cpuc = cpu_state_for(leader);
	if (cpuc && cpuc->online && cpuc->idle) {
		STAT_INC(fast_path_latency_idle_source_deferrals);
		scx_bpf_kick_cpu(leader, SCX_KICK_IDLE);
		return true;
	}
	if (peer == leader || peer >= num_possible_cpus)
		return false;
	cpuc = cpu_state_for(peer);
	if (!cpuc || !cpuc->online || !cpuc->idle)
		return false;
	STAT_INC(fast_path_latency_idle_source_deferrals);
	scx_bpf_kick_cpu(peer, SCX_KICK_IDLE);
	return true;
}

/** Serializes one physical-core Latency shard move and rechecks its depth. */
static __always_inline bool dispatch_shared_latency_shard(
	u32 leader, s32 dst_cpu, bool preserve_successor, u64 now)
{
	struct core_latency_state *shardc = core_latency_state_for(leader);
	u32 claim = dst_cpu + 1;
	u64 previous_release;
	s64 queued;
	bool moved;

	if (!shardc || leader >= num_possible_cpus || dst_cpu < 0 ||
	    dst_cpu >= num_possible_cpus)
		return false;
	if (scx_bpf_dsq_nr_queued(shared_latency_dsq(leader)) <= 0)
		return false;
	if (__sync_val_compare_and_swap(&shardc->dispatch_claim, 0, claim) != 0) {
		STAT_INC(fast_path_steal_claim_conflicts);
		return false;
	}
	queued = scx_bpf_dsq_nr_queued(shared_latency_dsq(leader));
	if (queued <= 0 || (preserve_successor && queued <= 1)) {
		__sync_val_compare_and_swap(&shardc->dispatch_claim, claim, 0);
		return false;
	}
	previous_release = shardc->singleton_release_ns;
	STAT_INC(fast_path_shared_latency_dispatch_attempts);
	moved = scx_bpf_dsq_move_to_local(shared_latency_dsq(leader));
	queued = scx_bpf_dsq_nr_queued(shared_latency_dsq(leader));
	if (queued <= 0)
		__sync_val_compare_and_swap(
			&shardc->singleton_release_ns, previous_release, 0);
	else if (moved && preserve_successor && queued <= 1)
		shardc->singleton_release_ns = now +
			active_latency_locality_lease(now);
	__sync_val_compare_and_swap(&shardc->dispatch_claim, claim, 0);
	if (moved) {
		STAT_INC(fast_path_shared_latency_dispatches);
		return true;
	}
	STAT_INC(fast_path_shared_latency_dispatch_failures);
	return false;
}

/** Consumes one blocked Latency wakeup assigned to the caller's core. */
static __always_inline bool dispatch_shared_latency(s32 cpu, u64 now)
{
	return dispatch_shared_latency_shard(
		immutable_core_leader_for_cpu(cpu), cpu, false, now);
}

/**
 * Lets credit-backed capacity rescue another core's backlog immediately and
 * its singleton after a bounded locality lease. Repeated bounded windows cover
 * large CPU sets without a full topology scan on every dispatch callback.
 */
static __always_inline bool spill_shared_latency_backlog(s32 dst_cpu, u64 now)
{
	struct adaptive_cpu_state *dst = cpu_state_for(dst_cpu);
	u32 dst_domain = immutable_domain_for_cpu(dst_cpu);
	u32 dst_leader = immutable_core_leader_for_cpu(dst_cpu);
	u32 cursor;
	u32 scan;

	if (!dst || num_core_leaders <= 1 || dst_domain >= num_domains ||
	    dst_leader >= num_possible_cpus ||
	    !__sync_fetch_and_add(&shared_latency_queued_tasks, 0))
		return false;
	STAT_INC(fast_path_latency_steal_attempts);
	cursor = dst->steal_cursor++;

	bpf_for(scan, 0, FAST_STEAL_SCAN_LIMIT) {
		struct core_latency_state *shardc;
		u32 leader;
		s32 src_cpu;
		s64 queued;
		bool preserve_successor;

		if (scan >= num_core_leaders)
			break;
		leader = immutable_core_leader_at(
			(cursor + scan) % num_core_leaders);
		src_cpu = leader;
		if (leader == dst_leader ||
		    immutable_domain_for_cpu(src_cpu) != dst_domain)
			continue;
		queued = scx_bpf_dsq_nr_queued(shared_latency_dsq(leader));
		if (queued <= 0)
			continue;
		preserve_successor = queued > 1;
		if (!preserve_successor) {
			if (defer_shared_latency_to_idle_core(leader))
				continue;
			shardc = core_latency_state_for(leader);
			if (!shardc || (shardc->singleton_release_ns &&
			    now < shardc->singleton_release_ns))
				continue;
		}
		if (dispatch_shared_latency_shard(
			leader, dst_cpu, preserve_successor, now)) {
			STAT_INC(fast_path_latency_remote_steals);
			if (preserve_successor)
				STAT_INC(fast_path_latency_remote_steals_preserving_successor);
			else
				STAT_INC(fast_path_latency_remote_steals_fallback);
			return true;
		}
	}
	return false;
}

/** Final idle-only rescue scans every core shard, including other domains. */
static __always_inline bool rescue_shared_latency_when_idle(s32 dst_cpu, u64 now)
{
	u32 dst_leader = immutable_core_leader_for_cpu(dst_cpu);
	u32 scan;

	if (num_core_leaders <= 1 || dst_leader >= num_possible_cpus ||
	    !__sync_fetch_and_add(&shared_latency_queued_tasks, 0))
		return false;
	STAT_INC(fast_path_latency_steal_attempts);
	bpf_for(scan, 0, SCX_ADAPTIVE_MAX_CPUS) {
		u32 leader;
		s64 queued;

		if (scan >= num_core_leaders)
			break;
		leader = immutable_core_leader_at(scan);
		if (leader == dst_leader)
			continue;
		queued = scx_bpf_dsq_nr_queued(shared_latency_dsq(leader));
		if (queued <= 0)
			continue;
		if (queued == 1 && defer_shared_latency_to_idle_core(leader))
			continue;
		if (dispatch_shared_latency_shard(
			leader, dst_cpu, false, now)) {
			STAT_INC(fast_path_latency_remote_steals);
			STAT_INC(fast_path_latency_remote_steals_fallback);
			return true;
		}
	}
	return false;
}

/** Preserves private affinity work before consuming the movable request lane. */
static __always_inline bool dispatch_latency_work(
	s32 cpu, s64 private_queued, u64 now)
{
	if (private_queued > 0 && dispatch_latency_task(cpu))
		return true;
	return dispatch_shared_latency(cpu, now);
}

/** Rescues Latency backlog while optionally preserving one local successor. */
static __always_inline bool steal_latency_task(s32 dst_cpu,
	bool preserve_successor)
{
	struct adaptive_cpu_state *dst = cpu_state_for(dst_cpu);
	u64 private_latency;
	u32 cursor;
	u32 scan;

	private_latency = __sync_fetch_and_add(&private_latency_queued_tasks, 0);
	if (!dst || num_possible_cpus <= 1 || !private_latency)
		return false;
	STAT_INC(fast_path_latency_steal_attempts);
	cursor = dst->steal_cursor++;

	bpf_for(scan, 0, FAST_STEAL_SCAN_LIMIT) {
		struct adaptive_cpu_state *src;
		s32 src_cpu;

		if (scan >= num_possible_cpus - 1)
			break;
		src_cpu = (dst_cpu + 1 +
			   (cursor + scan) % (num_possible_cpus - 1)) %
			  num_possible_cpus;
		s64 queued = scx_bpf_dsq_nr_queued(latency_dsq(src_cpu));

		if (queued <= 0 || (preserve_successor && queued <= 1))
			continue;
		src = cpu_state_for(src_cpu);
		if (!src)
			continue;
		if (!preserve_successor && queued == 1 && src->online && src->idle) {
			STAT_INC(fast_path_latency_idle_source_deferrals);
			scx_bpf_kick_cpu(src_cpu, SCX_KICK_IDLE);
			continue;
		}
		if (__sync_val_compare_and_swap(&src->steal_claim, 0,
						  dst_cpu + 1) != 0) {
			STAT_INC(fast_path_steal_claim_conflicts);
			continue;
		}
		if (dispatch_latency_task(src_cpu)) {
			__sync_val_compare_and_swap(
				&src->steal_claim, dst_cpu + 1, 0);
			STAT_INC(fast_path_latency_remote_steals);
			if (preserve_successor)
				STAT_INC(fast_path_latency_remote_steals_preserving_successor);
			else
				STAT_INC(fast_path_latency_remote_steals_fallback);
			return true;
		}
		__sync_val_compare_and_swap(&src->steal_claim, dst_cpu + 1, 0);
	}
	return false;
}

/** Returns the number of classified tasks queued on one CPU. */
static __always_inline u64 fast_queued_on_cpu(s32 cpu)
{
	s32 count;
	u64 queued = 0;

	if (cpu < 0 || cpu >= num_possible_cpus)
		return 0;
	count = scx_bpf_dsq_nr_queued(task_dsq(cpu));
	if (count > 0)
		queued += count;
	count = scx_bpf_dsq_nr_queued(latency_dsq(cpu));
	if (count > 0)
		queued += count;
	return queued;
}

/**
 * Lets an idle destination drain a source while preserving the short Normal
 * successor set behind a running Latency request until no stronger donor
 * exists. This keeps a long CPU task cache-local when another source already
 * has real backlog, without allowing the destination to remain idle.
 */
static __always_inline bool source_can_spare(s32 cpu, u64 now,
					       u64 successor_lease_ns)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	s64 count = scx_bpf_dsq_nr_queued(task_dsq(cpu));
	u64 queued = count > 0 ? count : 0;

	if (!cpuc || !queued)
		return false;
	if (!cpuc->online)
		return true;
	/* An idle source cannot be running the sole queued task; taking it is
	 * work-conserving and avoids leaving a destination idle behind stale
	 * per-CPU queue state. */
	if (cpuc->idle) {
		if (queued == 1 &&
		    cpuc->queued_tasks_by_class[SCX_ADAPTIVE_CLASS_THROUGHPUT] == 1 &&
		    cpuc->queued_tasks_by_class[SCX_ADAPTIVE_CLASS_BALANCED] == 0) {
			STAT_INC(fast_path_steal_idle_throughput_deferrals);
			/* The owner is already idle; make its local dispatch runnable. */
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return false;
		}
		STAT_INC(fast_path_steal_idle_source_admissions);
		return true;
	}
	/* Preserve one cache-hot successor for the measured Latency stopping time. */
	if (queued == 1 && !cpuc->idle &&
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY &&
	    (!cpuc->running_started_ns || now < cpuc->running_started_ns ||
	     now - cpuc->running_started_ns < successor_lease_ns)) {
		STAT_INC(fast_path_steal_latency_successor_deferrals);
		return false;
	}
	if (queued > 1)
		return true;
	if (!cpuc->idle &&
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY)
		STAT_INC(fast_path_steal_latency_source_admissions);
	return !cpuc->idle;
}

/** Scans once from a rotating origin and serializes movers per source CPU. */
static __always_inline bool steal_fast_task(s32 dst_cpu, u64 now,
					      u64 successor_lease_ns)
{
	struct adaptive_cpu_state *dst = cpu_state_for(dst_cpu);
	u32 cursor;
	u32 scan;

	if (!dst || num_possible_cpus <= 1)
		return false;

	if (__sync_fetch_and_add(&normal_queued_tasks, 0) == 0) {
		STAT_INC(fast_path_empty_steal_skips);
		return false;
	}
	STAT_INC(fast_path_steal_attempts);
	cursor = dst->steal_cursor++;
	bpf_for(scan, 0, FAST_STEAL_SCAN_LIMIT) {
		struct adaptive_cpu_state *src;
		s32 src_cpu;

		if (scan >= num_possible_cpus - 1)
			break;
		src_cpu = (dst_cpu + 1 +
			   (cursor + scan) % (num_possible_cpus - 1)) %
			  num_possible_cpus;
		if (!source_can_spare(src_cpu, now, successor_lease_ns))
			continue;
		src = cpu_state_for(src_cpu);
		if (!src)
			continue;
		if (__sync_val_compare_and_swap(&src->steal_claim, 0,
							  dst_cpu + 1) != 0) {
			STAT_INC(fast_path_steal_claim_conflicts);
			continue;
		}

		if (dispatch_fast_task(src_cpu)) {
			__sync_val_compare_and_swap(
				&src->steal_claim, dst_cpu + 1, 0);
			return true;
		}
		__sync_val_compare_and_swap(&src->steal_claim, dst_cpu + 1, 0);
	}
	STAT_INC(fast_path_steal_scan_exhaustions);
	return false;
}

/** Performs the constant-time safety check for one userspace-selected CPU. */
static __noinline u32 policy_latency_victim_class(
	struct task_struct *p, s32 cpu, u64 now,
	const struct adaptive_policy_control *policy)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	u32 budget = policy ? policy->latency_budget_percent :
		latency_budget_percent;

	if (!cpuc || !cpuc->online || cpuc->idle || cpuc->urgent_dispatch_id ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr) ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY ||
	    scx_bpf_dsq_nr_queued(latency_dsq(cpu)) > 0 ||
	    !latency_wakeup_budget_available(cpuc, now, budget) ||
	    !latency_preemption_time_allowed(cpuc, now, policy))
		return FAST_NO_RUNNING_CLASS;
	return cpuc->running_class;
}

/** Checks at most two topology candidates published by the Rust policy. */
static __always_inline s32 pick_policy_latency_victim(
	struct task_struct *p, s32 prev_cpu, u64 now,
	const struct adaptive_policy_control *policy)
{
	struct adaptive_cpu_state *prevc = cpu_state_for(prev_cpu);
	struct adaptive_cpu_policy *prevc_policy;
	u32 first_class = FAST_NO_RUNNING_CLASS;
	u32 second_class = FAST_NO_RUNNING_CLASS;
	u32 first;
	u32 second;

	if (prevc && prevc->online && !prevc->idle &&
	    prevc->running_class == SCX_ADAPTIVE_CLASS_LATENCY &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_dsq_nr_queued(latency_dsq(prev_cpu)) <= 0)
		return prev_cpu;
	if (policy_latency_victim_class(p, prev_cpu, now, policy) <
	    SCX_ADAPTIVE_CLASS_COUNT)
		return prev_cpu;
	prevc_policy = policy_cpu_for(policy, prev_cpu);
	if (!prevc_policy)
		return -1;
	first = prevc_policy->latency_candidate_cpu[0];
	second = prevc_policy->latency_candidate_cpu[1];
	if (first < num_possible_cpus)
		first_class = policy_latency_victim_class(p, first, now, policy);
	if (second < num_possible_cpus)
		second_class = policy_latency_victim_class(p, second, now, policy);
	if (first_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		return first;
	if (second_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		return second;
	if (first_class == SCX_ADAPTIVE_CLASS_BALANCED)
		return first;
	if (second_class == SCX_ADAPTIVE_CLASS_BALANCED)
		return second;
	return -1;
}

/** Scores one CPU's live Normal pressure without scanning any runqueue. */
static __always_inline u64 balanced_cpu_pressure(
	const struct adaptive_cpu_state *cpuc)
{
	u64 pressure;

	if (!cpuc)
		return ~0ULL;
	pressure = cpuc->queued_tasks_by_class[SCX_ADAPTIVE_CLASS_BALANCED] +
		   cpuc->queued_tasks_by_class[SCX_ADAPTIVE_CLASS_THROUGHPUT];
	if (cpuc->running_class == SCX_ADAPTIVE_CLASS_BALANCED)
		pressure += 1;
	else if (cpuc->running_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		pressure += 3;
	else if (cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY)
		pressure += 4;
	if (cpuc->urgent_dispatch_id == FAST_BALANCED_RESCHED_ID)
		pressure += 1;
	else if (cpuc->urgent_dispatch_id == FAST_LATENCY_RESCHED_ID)
		pressure += 4;
	return pressure;
}

/** Revalidates one userspace Normal candidate against current kernel state. */
static __noinline u64 policy_balanced_candidate_pressure(
	struct task_struct *p, s32 cpu)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);

	if (!cpuc || !cpuc->online || cpuc->idle ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr) ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY ||
	    cpuc->urgent_dispatch_id == FAST_LATENCY_RESCHED_ID ||
	    cpuc->queued_tasks_by_class[SCX_ADAPTIVE_CLASS_LATENCY] > 0)
		return ~0ULL;
	return balanced_cpu_pressure(cpuc);
}

/** Uses two slow-path candidates only when their live pressure is materially lower. */
static __always_inline s32 pick_policy_balanced_target(
	struct task_struct *p, s32 prev_cpu,
	const struct adaptive_policy_control *policy)
{
	struct adaptive_cpu_state *prevc = cpu_state_for(prev_cpu);
	struct adaptive_cpu_policy *prevc_policy;
	u64 prev_pressure;
	u64 first_pressure = ~0ULL;
	u64 second_pressure = ~0ULL;
	u64 best_pressure;
	u32 first;
	u32 second;
	s32 best;

	if (!prevc || !prevc->online || prevc->idle ||
	    !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		return -1;
	prevc_policy = policy_cpu_for(policy, prev_cpu);
	if (!prevc_policy)
		return -1;
	prev_pressure = balanced_cpu_pressure(prevc);
	first = prevc_policy->normal_candidate_cpu[0];
	second = prevc_policy->normal_candidate_cpu[1];
	if (first < num_possible_cpus)
		first_pressure = policy_balanced_candidate_pressure(p, first);
	if (second < num_possible_cpus)
		second_pressure = policy_balanced_candidate_pressure(p, second);
	if (first_pressure <= second_pressure) {
		best = first;
		best_pressure = first_pressure;
	} else {
		best = second;
		best_pressure = second_pressure;
	}
	if (best_pressure == ~0ULL ||
	    best_pressure + FAST_BALANCED_PLACEMENT_HYSTERESIS > prev_pressure)
		return -1;
	return best;
}

/** Preserves kernel wake affinity while retaining class-specific idle handling. */
s32 BPF_STRUCT_OPS(adaptive_select_cpu, struct task_struct *p, s32 prev_cpu,
			   u64 wake_flags)
{
	struct task_context *taskc = task_ctx_for(p);
	struct task_control_value *control;
	struct adaptive_cpu_state *prevc;
	u32 class_id = SCX_ADAPTIVE_CLASS_BALANCED;
	u32 control_flags = SCX_ADAPTIVE_CONTROL_BPF_SCHED |
			    SCX_ADAPTIVE_CONTROL_OBSERVE |
			    SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE;
	u32 latency_select_path = SCX_ADAPTIVE_LATENCY_SELECT_FALLBACK;
	u32 selected;
	s32 cpu = -1;
	bool is_idle = false;

	if (!taskc)
		return prev_cpu;
	taskc->previous_cpu = prev_cpu;
	taskc->selected_idle_cpu = -1;
	control = fast_control_for(p, taskc);
	if (control) {
		class_id = control->class_id;
		control_flags = control->flags;
	}
	taskc->selected_control_flags = control_flags;
	taskc->selected_control_valid = 1;
	taskc->selected_class_id = class_id;
	prevc = cpu_state_for(prev_cpu);
	if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT &&
	    prevc && prevc->online &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		taskc->selected_idle_cpu = prev_cpu;
		cpu = prev_cpu;
		goto selected;
	}
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (cpu >= 0 && cpu < num_possible_cpus &&
	    bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
			latency_select_path = is_idle ?
				SCX_ADAPTIVE_LATENCY_SELECT_DEFAULT_IDLE :
				SCX_ADAPTIVE_LATENCY_SELECT_DEFAULT_BUSY;
		if (!is_idle && taskc->last_stop_blocked &&
		    (class_id == SCX_ADAPTIVE_CLASS_LATENCY ||
		     class_id == SCX_ADAPTIVE_CLASS_BALANCED)) {
			u64 now = bpf_ktime_get_ns();
			struct adaptive_policy_control *policy = active_policy(now);
			s32 target;

			if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
				target = pick_policy_latency_victim(
					p, prev_cpu, now, policy);
			else
				target = pick_policy_balanced_target(
					p, prev_cpu, policy);
			if (target >= 0) {
				cpu = target;
				if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
					latency_select_path =
						SCX_ADAPTIVE_LATENCY_SELECT_POLICY_VICTIM;
			}
		}
		if (is_idle)
			taskc->selected_idle_cpu = cpu;
		goto selected;
	}
	if (prev_cpu >= 0 && prev_cpu < num_possible_cpus &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		cpu = prev_cpu;
	else {
		selected = bpf_cpumask_any_distribute(p->cpus_ptr);
		cpu = selected < num_possible_cpus ? selected : -1;
	}

selected:
	record_select_cpu_diagnostics(class_id, latency_select_path, cpu, prev_cpu,
				      wake_flags);
	if (cpu >= 0 && taskc->selected_idle_cpu == cpu &&
	    class_id == SCX_ADAPTIVE_CLASS_LATENCY &&
	    !cpu_has_local_work(cpu, cpu_state_for(cpu)) &&
	    fast_enqueue(p, taskc, class_id, control_flags, 0,
			 bpf_ktime_get_ns(), cpu, true))
		return cpu;
	taskc->target_cpu = cpu;
	return cpu;
}

/** Routes every ordinary runnable incarnation through the BPF data plane. */
void BPF_STRUCT_OPS(adaptive_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_context *taskc = task_ctx_for(p);
	struct task_control_value *control;
	u32 class_id = SCX_ADAPTIVE_CLASS_BALANCED;
	u32 control_flags = SCX_ADAPTIVE_CONTROL_BPF_SCHED |
			    SCX_ADAPTIVE_CONTROL_OBSERVE |
			    SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE;
	u64 now = bpf_ktime_get_ns();

	if (!taskc) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
		STAT_INC(fallback_dispatches);
		goto out;
	}

	if (is_safe_task(p)) {
		begin_enqueue(taskc, now);
		taskc->selected_idle_cpu = -1;
		taskc->fast_path = 0;
		fallback_dispatch(p, taskc, enq_flags);
		goto out;
	}
	if (__COMPAT_is_enq_cpu_selected(enq_flags) &&
	    taskc->selected_control_valid &&
	    taskc->selected_class_id < SCX_ADAPTIVE_CLASS_COUNT &&
	    (taskc->selected_control_flags & SCX_ADAPTIVE_CONTROL_BPF_SCHED) &&
	    !(taskc->selected_control_flags &
	      ~SCX_ADAPTIVE_CONTROL_FLAG_MASK)) {
		class_id = taskc->selected_class_id;
		control_flags = taskc->selected_control_flags;
	} else {
		control = fast_control_for(p, taskc);
		if (control) {
			class_id = control->class_id;
			control_flags = control->flags;
		}
	}
	if (fast_enqueue(p, taskc, class_id, control_flags, enq_flags, now,
			 scx_bpf_task_cpu(p), false))
		goto out;
	fallback_fast_enqueue(p, taskc, class_id, control_flags, enq_flags, now);

out:
	/* A non-local ENQ_LAST insert must trigger a follow-up scheduling event. */
	if (enq_flags & SCX_ENQ_LAST) {
		s32 cpu = scx_bpf_task_cpu(p);

		if (cpu >= 0 && cpu < num_possible_cpus)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}
}

/** Wakes the control plane when requested and dispatches bounded BPF work. */
void BPF_STRUCT_OPS(adaptive_dispatch, s32 cpu, struct task_struct *prev)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	s64 latency_queued;
	s64 normal_queued;
	u64 now = bpf_ktime_get_ns();
	struct adaptive_policy_control *policy = active_policy(now);
	u32 budget = policy ? policy->latency_budget_percent :
		latency_budget_percent;
	u64 successor_lease_ns = policy ? policy->latency_successor_lease_ns :
		latency_slice_ns;
	s64 balance = refresh_latency_budget(cpuc, now, budget);
	bool remote_latency_queued;
	bool remote_normal_queued;
	bool latency_work_queued;
	bool latency_resched = false;
	bool balanced_resched = false;
	bool rescheduled;
	u32 preemption_victim_class = FAST_NO_RUNNING_CLASS;

	/* A missing or stale policy must retain the immutable bounded fallback. */
	if (!successor_lease_ns || successor_lease_ns > latency_slice_ns)
		successor_lease_ns = latency_slice_ns;

	if (cpuc)
		cpuc->latency_dispatch_charged = 0;
	if (scx_bpf_dispatch_nr_slots() > 0 && cpuc &&
	    __sync_val_compare_and_swap(&cpuc->urgent_dispatch_id,
					FAST_LATENCY_RESCHED_ID, 0) ==
					FAST_LATENCY_RESCHED_ID) {
		latency_resched = true;
	} else if (scx_bpf_dispatch_nr_slots() > 0 && cpuc &&
		   __sync_val_compare_and_swap(&cpuc->urgent_dispatch_id,
					       FAST_BALANCED_RESCHED_ID, 0) ==
					       FAST_BALANCED_RESCHED_ID) {
		balanced_resched = true;
	}
	rescheduled = latency_resched || balanced_resched;
	if (rescheduled && cpuc)
		preemption_victim_class = cpuc->running_class;
	latency_queued = scx_bpf_dsq_nr_queued(latency_dsq(cpu));
	normal_queued = scx_bpf_dsq_nr_queued(task_dsq(cpu));
	latency_work_queued = latency_queued > 0 || shared_latency_depth(cpu) > 0;
	if (scx_bpf_dispatch_nr_slots() > 0 && latency_work_queued &&
	    (normal_queued <= 0 || latency_resched ||
	     (cpuc && balance >= (s64)latency_slice_ns))) {
		if (dispatch_latency_work(cpu, latency_queued, now)) {
			if (cpuc && (normal_queued > 0 || latency_resched)) {
				cpuc->latency_dispatch_charged = 1;
				STAT_INC(fast_path_latency_backlog_boosts);
			} else if (cpuc) {
				cpuc->latency_dispatch_charged = 0;
			}
			if (rescheduled)
				record_fast_preemption(
					latency_resched ? SCX_ADAPTIVE_CLASS_LATENCY :
						SCX_ADAPTIVE_CLASS_BALANCED,
					preemption_victim_class, prev, cpuc, now);
			return;
		}
	}
	/* Spend available credit on another core only when its burst has backlog. */
	if (scx_bpf_dispatch_nr_slots() > 0 && cpuc &&
	    balance >= (s64)latency_slice_ns &&
	    __sync_fetch_and_add(&shared_latency_queued_tasks, 0) > 0 &&
	    (dispatch_shared_latency(cpu, now) ||
	     spill_shared_latency_backlog(cpu, now))) {
		cpuc->latency_dispatch_charged = 1;
		STAT_INC(fast_path_latency_backlog_boosts);
		return;
	}
	if (scx_bpf_dispatch_nr_slots() > 0 && normal_queued > 0 &&
	    dispatch_fast_task(cpu)) {
		if (rescheduled)
			record_fast_preemption(
				latency_resched ? SCX_ADAPTIVE_CLASS_LATENCY :
					SCX_ADAPTIVE_CLASS_BALANCED,
				preemption_victim_class, prev, cpuc, now);
		return;
	}
	/* Races must remain work-conserving even when the normal head vanished. */
	if (scx_bpf_dispatch_nr_slots() > 0 && latency_work_queued &&
	    dispatch_latency_work(cpu, latency_queued, now)) {
		if (cpuc)
			cpuc->latency_dispatch_charged = 0;
		if (rescheduled)
			record_fast_preemption(
				latency_resched ? SCX_ADAPTIVE_CLASS_LATENCY :
					SCX_ADAPTIVE_CLASS_BALANCED,
				preemption_victim_class, prev, cpuc, now);
		return;
	}
	if (rescheduled)
		STAT_INC(fast_path_dispatch_failures);
	remote_latency_queued =
		__sync_fetch_and_add(&latency_queued_tasks, 0) > 0;
	remote_normal_queued =
		__sync_fetch_and_add(&normal_queued_tasks, 0) > 0;
	if (scx_bpf_dispatch_nr_slots() > 0 && remote_latency_queued && cpuc &&
	    balance >= (s64)latency_slice_ns &&
	    (dispatch_shared_latency(cpu, now) ||
	     spill_shared_latency_backlog(cpu, now) ||
	     steal_latency_task(cpu, true))) {
		cpuc->latency_dispatch_charged = 1;
		STAT_INC(fast_path_latency_backlog_boosts);
		return;
	}
	if (scx_bpf_dispatch_nr_slots() > 0 &&
	    dispatch_shared_balanced(cpu))
		return;
	if (scx_bpf_dispatch_nr_slots() > 0 && remote_normal_queued &&
	    steal_fast_task(cpu, now, successor_lease_ns))
		return;
	/* Only a truly idle destination rescues Latency without available credit. */
	if (scx_bpf_dispatch_nr_slots() > 0 && remote_latency_queued &&
	    (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))) {
		if (dispatch_shared_latency(cpu, now) ||
		    rescue_shared_latency_when_idle(cpu, now) ||
		    steal_latency_task(cpu, false))
			return;
		STAT_INC(fast_path_remote_backlog_no_dispatches);
	}
}

/** Clears the staged slot and reports the actual CPU when a task begins. */
void BPF_STRUCT_OPS(adaptive_running, struct task_struct *p)
{
	struct task_context *taskc = task_ctx_for(p);
	struct adaptive_cpu_state *cpuc;
	struct task_event event = {};
	u32 cpu = bpf_get_smp_processor_id();
	u64 now = bpf_ktime_get_ns();

	if (!taskc)
		return;
	clear_class_queue_account(taskc);
	taskc->start_ns = now;
	cpuc = cpu_state_for(cpu);
	if (cpuc && taskc->fast_path &&
	    taskc->policy_class < SCX_ADAPTIVE_CLASS_COUNT) {
		if (taskc->vruntime_cpu != (s32)cpu) {
			taskc->vruntime_ns = cpuc->virtual_time_ns;
			taskc->vruntime_cpu = cpu;
			if (taskc->request_ns)
				taskc->request_deadline_ns = taskc->vruntime_ns +
					task_virtual_service(
						p, taskc->policy_class,
						taskc->request_ns);
		}
		if (cpuc->virtual_time_ns < taskc->vruntime_ns)
			cpuc->virtual_time_ns = taskc->vruntime_ns;
	}
	if (cpuc) {
		cpuc->running_class =
			taskc->policy_class < SCX_ADAPTIVE_CLASS_COUNT ?
			taskc->policy_class : SCX_ADAPTIVE_CLASS_BALANCED;
		cpuc->running_started_ns = now;
		cpuc->running_deadline_ns =
			taskc->fast_path ? taskc->request_deadline_ns : 0;
		taskc->latency_budget_charged =
			taskc->fast_path &&
			taskc->policy_class == SCX_ADAPTIVE_CLASS_LATENCY &&
			cpuc->latency_dispatch_charged;
		cpuc->latency_dispatch_charged = 0;
	}

	/* Pre-existing tasks may run once before this scheduler sees an enqueue. */
	if (!taskc->enqueue_sequence)
		return;
	if (taskc->fast_path) {
		if (taskc->target_cpu >= 0)
			record_fast_dispatch(
				taskc->policy_class, taskc->target_cpu != (s32)cpu,
				taskc->target_cpu, cpu, now);
		if (taskc->observe_fast_events) {
			fill_task_event(&event, p, taskc,
					SCX_ADAPTIVE_EVENT_RUNNING, now);
			event.actual_cpu = cpu;
			event.runtime_ns = taskc->request_ns;
			emit_fast_event(&event);
		}
	} else {
		fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_RUNNING, now);
		event.actual_cpu = cpu;
		emit_event(&event);
	}
}

/** Reports actual service, pipeline hit/miss, and returns the task to blocked state. */
void BPF_STRUCT_OPS(adaptive_stopping, struct task_struct *p, bool runnable)
{
	struct task_context *taskc = task_ctx_for(p);
	struct task_event event = {};
	struct adaptive_cpu_state *cpuc;
	u32 cpu = bpf_get_smp_processor_id();
	u64 now = bpf_ktime_get_ns();
	u64 runtime_ns;

	if (!taskc)
		return;
	cpuc = cpu_state_for(cpu);
	if (cpuc) {
		cpuc->running_class = FAST_NO_RUNNING_CLASS;
		cpuc->running_started_ns = 0;
		cpuc->running_deadline_ns = 0;
	}
	taskc->stop_ns = now;
	taskc->last_stop_blocked = !runnable;
	runtime_ns = taskc->start_ns && now >= taskc->start_ns ?
		     now - taskc->start_ns : 0;
	if (cpuc && taskc->fast_path) {
		if (taskc->policy_class == SCX_ADAPTIVE_CLASS_LATENCY)
			__sync_fetch_and_add(&cpuc->runtime_ns_by_class[0], runtime_ns);
		else if (taskc->policy_class == SCX_ADAPTIVE_CLASS_BALANCED)
			__sync_fetch_and_add(&cpuc->runtime_ns_by_class[1], runtime_ns);
		else if (taskc->policy_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
			__sync_fetch_and_add(&cpuc->runtime_ns_by_class[2], runtime_ns);
	}
	if (cpuc && taskc->latency_budget_charged)
		charge_latency_budget(
			cpuc, now, runtime_ns, active_latency_budget(now));
	taskc->latency_budget_charged = 0;
	/* A pre-existing task can stop before its first scheduler enqueue. */
	if (!taskc->enqueue_sequence) {
		taskc->target_cpu = -1;
		return;
	}
	/* Sample one in sixteen stops so diagnostics do not become a hot-path cost. */
	if (taskc->fast_path &&
	    !(taskc->enqueue_sequence & FAST_PIPELINE_SAMPLE_MASK)) {
		struct adaptive_global_stats *stats = stats_value();
		s64 normal_depth = scx_bpf_dsq_nr_queued(task_dsq(cpu));
		s64 latency_depth = scx_bpf_dsq_nr_queued(latency_dsq(cpu));
		u32 core_leader = immutable_core_leader_for_cpu(cpu);

		if (core_leader < num_possible_cpus) {
			s64 shared_depth = scx_bpf_dsq_nr_queued(
				shared_latency_dsq(core_leader));

			if (shared_depth > 0)
				latency_depth += shared_depth;
		}

		if (stats) {
			if (normal_depth > 0)
				stats->fast_path_pipeline_normal_depth_sum +=
					normal_depth;
			if (latency_depth > 0)
				stats->fast_path_pipeline_latency_depth_sum +=
					latency_depth;
			if (normal_depth > 0 || latency_depth > 0)
				stats->fast_path_pipeline_ready_samples++;
			else
				stats->fast_path_pipeline_empty_samples++;
		}
	}

	if (taskc->fast_path) {
		u64 assigned_ns = taskc->request_ns;
		u64 remaining_ns = assigned_ns > runtime_ns ?
			assigned_ns - runtime_ns : 0;
		bool interrupted = runnable && assigned_ns &&
			runtime_ns < assigned_ns * 9 / 10;

		taskc->vruntime_ns += task_virtual_service(
			p, taskc->policy_class, runtime_ns);
		if (interrupted && remaining_ns >= min_slice_ns) {
			taskc->request_ns = remaining_ns;
		} else {
			taskc->request_ns = 0;
			taskc->request_deadline_ns = 0;
			if (taskc->policy_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
				taskc->throughput_epoch_ns = runnable && assigned_ns ?
					next_throughput_epoch(taskc) : throughput_slice_ns;
		}

		if (taskc->observe_fast_events) {
			fill_task_event(&event, p, taskc,
					SCX_ADAPTIVE_EVENT_STOP, now);
			event.actual_cpu = cpu;
			event.runtime_ns = runtime_ns;
			if (runnable)
				event.flags |= SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE;
			emit_fast_event(&event);
		}
		taskc->target_cpu = -1;
		return;
	}

	if (!is_safe_task(p)) {
		fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_STOP, now);
		event.actual_cpu = cpu;
		event.runtime_ns = runtime_ns;
		if (runnable)
			event.flags |= SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE;
		emit_event(&event);
	}

	taskc->target_cpu = -1;
}

/** Cancels an outstanding runnable identity and releases a matching slot. */
void BPF_STRUCT_OPS(adaptive_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct task_context *taskc = task_ctx_for(p);
	struct task_event event = {};
	u64 now;

	if (!taskc)
		return;
	if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		return;
	now = bpf_ktime_get_ns();
	clear_class_queue_account(taskc);
	/* A pre-attach dequeue has no runnable incarnation to cancel. */
	if (!taskc->enqueue_sequence) {
		taskc->target_cpu = -1;
		return;
	}
	if (taskc->fast_path) {
		taskc->request_ns = 0;
		taskc->request_deadline_ns = 0;
		if (taskc->policy_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
			taskc->throughput_epoch_ns = throughput_slice_ns;
		if (taskc->observe_fast_events) {
			fill_task_event(&event, p, taskc,
					SCX_ADAPTIVE_EVENT_CANCEL, now);
			event.flags = deq_flags;
			emit_fast_event(&event);
		}
	} else {
		fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_CANCEL, now);
		event.flags = deq_flags;
		emit_event(&event);
	}
	taskc->target_cpu = -1;
}

/** Completes a coalesced wakeup reschedule after one bounded victim granule. */
void BPF_STRUCT_OPS(adaptive_tick, struct task_struct *p)
{
	struct adaptive_cpu_state *cpuc;
	u32 cpu = bpf_get_smp_processor_id();
	u64 marker;
	u64 min_runtime;
	u64 now;

	cpuc = cpu_state_for(cpu);
	if (!cpuc ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY ||
	    !cpuc->running_started_ns)
		return;
	marker = cpuc->urgent_dispatch_id;
	if (marker != FAST_LATENCY_RESCHED_ID &&
	    marker != FAST_BALANCED_RESCHED_ID)
		return;
	now = bpf_ktime_get_ns();
	if (now < cpuc->running_started_ns)
		return;
	if (marker == FAST_LATENCY_RESCHED_ID) {
		struct adaptive_policy_control *policy = active_policy(now);

		if (!latency_preemption_time_allowed(cpuc, now, policy))
			return;
		cpuc->last_preemption_ns = now;
		p->scx.slice = 0;
		return;
	}
	min_runtime = active_balanced_granularity(now);
	if (marker == FAST_BALANCED_RESCHED_ID &&
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		min_runtime = min_slice_ns *
			FAST_BALANCED_THROUGHPUT_MIN_RUNTIME_SLICES;
	if (now - cpuc->running_started_ns < min_runtime)
		return;
	p->scx.slice = 0;
}

/** Updates the BPF-owned per-CPU idle state. */
static __always_inline void update_cpu_state(s32 cpu, bool idle)
{
	struct adaptive_cpu_state *cpuc;
	u32 key;

	if (cpu < 0 || cpu >= num_possible_cpus || cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return;
	key = cpu;
	cpuc = bpf_map_lookup_elem(&cpu_state, &key);
	if (!cpuc)
		return;
	cpuc->online = 1;
	cpuc->idle = idle;
	if (idle) {
		cpuc->running_class = FAST_NO_RUNNING_CLASS;
		cpuc->running_started_ns = 0;
		cpuc->running_deadline_ns = 0;
		cpuc->latency_dispatch_charged = 0;
	}
}

/** sched_ext callback wrapper for an idle-state transition. */
void BPF_STRUCT_OPS(adaptive_update_idle, s32 cpu, bool idle)
{
	update_cpu_state(cpu, idle);
}

/** Marks a CPU available and publishes the hotplug transition. */
void BPF_STRUCT_OPS(adaptive_cpu_online, s32 cpu)
{
	update_cpu_state(cpu, false);
}

/** Clears a CPU slot and publishes the hotplug transition. */
void BPF_STRUCT_OPS(adaptive_cpu_offline, s32 cpu)
{
	struct adaptive_cpu_state *cpuc;
	u32 key;

	if (cpu < 0 || cpu >= num_possible_cpus || cpu >= SCX_ADAPTIVE_MAX_CPUS)
		return;
	key = cpu;
	cpuc = bpf_map_lookup_elem(&cpu_state, &key);
	if (!cpuc)
		return;
	cpuc->online = 0;
	cpuc->idle = 0;
	cpuc->urgent_dispatch_id = 0;
	cpuc->steal_claim = 0;
	cpuc->running_class = FAST_NO_RUNNING_CLASS;
	cpuc->latency_dispatch_charged = 0;
	cpuc->running_started_ns = 0;
	cpuc->running_deadline_ns = 0;
	cpuc->latency_credit_ns = 0;
	cpuc->latency_debt_ns = 0;
	cpuc->latency_credit_updated_ns = 0;
}

/** Allocates stable task/process identities before sched_ext enables a task. */
s32 BPF_STRUCT_OPS(adaptive_init_task, struct task_struct *p,
			   struct scx_init_task_args *args)
{
	struct process_identity_key key;
	struct process_context initial = {};
	struct process_context *processc;
	struct task_context *taskc;
	struct task_event event = {};
	u64 now;

	/* Keep control-plane and kernel tasks on the native Linux scheduler. */
	if (is_safe_task(p)) {
		if (!args->fork)
			p->scx.disallow = true;
		return 0;
	}

	key = process_key_for(p);
	now = bpf_ktime_get_ns();

	processc = bpf_map_lookup_elem(&process_ctx, &key);
	if (!processc) {
		initial.process_cookie = allocate_cookie();
		initial.exec_generation = 1;
		initial.active_threads = 0;
		bpf_map_update_elem(&process_ctx, &key, &initial, BPF_NOEXIST);
		processc = bpf_map_lookup_elem(&process_ctx, &key);
	}
	if (!processc)
		return -ENOMEM;

	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc)
		return -ENOMEM;

	__builtin_memset(taskc, 0, sizeof(*taskc));
	taskc->task_cookie = allocate_cookie();
	taskc->process_cookie = processc->process_cookie;
	taskc->exec_generation = processc->exec_generation;
	taskc->previous_cpu = -1;
	taskc->target_cpu = -1;
	taskc->vruntime_cpu = -1;
	taskc->selected_idle_cpu = -1;
	taskc->class_queue_accounted = 0;
	taskc->selected_class_id = SCX_ADAPTIVE_CLASS_BALANCED;
	taskc->tgid = p->tgid;
	taskc->policy_class = SCX_ADAPTIVE_CLASS_BALANCED;
	taskc->process_key = key;
	__sync_fetch_and_add(&processc->active_threads, 1);

	fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_INIT, now);
	emit_event(&event);
	return 0;
}

/** Reports task exit, drops task control, and reclaims the final process entry. */
void BPF_STRUCT_OPS(adaptive_exit_task, struct task_struct *p,
			    struct scx_exit_task_args *args)
{
	struct task_context *taskc = task_ctx_for(p);
	struct process_context *processc;
	struct task_event event = {};
	u32 tid = p->pid;

	if (!taskc)
		return;
	clear_class_queue_account(taskc);
	fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_EXIT,
			bpf_ktime_get_ns());
	emit_event(&event);
	bpf_map_delete_elem(&task_control, &tid);

	processc = bpf_map_lookup_elem(&process_ctx, &taskc->process_key);
	if (processc && __sync_sub_and_fetch(&processc->active_threads, 1) == 0)
		bpf_map_delete_elem(&process_ctx, &taskc->process_key);
}

/** Increments the process image generation and reports a sched_process_exec. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(adaptive_process_exec, struct task_struct *p, u32 old_pid,
	     struct linux_binprm *bprm)
{
	struct process_identity_key key = process_key_for(p);
	struct process_context *processc = bpf_map_lookup_elem(&process_ctx, &key);
	struct task_context *taskc = task_ctx_for(p);
	struct task_event event = {};

	if (!processc || !taskc)
		return 0;
	clear_class_queue_account(taskc);
	processc->exec_generation++;
	if (processc->exec_generation == 0)
		processc->exec_generation++;
	taskc->exec_generation = processc->exec_generation;
	taskc->process_cookie = processc->process_cookie;
	taskc->fast_path = 0;
	taskc->observe_fast_events = 0;
	taskc->last_observed_enqueue_ns = 0;
	taskc->selected_idle_cpu = -1;
	taskc->class_queue_accounted = 0;
	taskc->selected_class_id = SCX_ADAPTIVE_CLASS_BALANCED;
	taskc->selected_control_flags = 0;
	taskc->selected_control_valid = 0;
	taskc->latency_budget_charged = 0;
	taskc->vruntime_ns = 0;
	taskc->vruntime_cpu = -1;
	taskc->request_ns = 0;
	taskc->request_deadline_ns = 0;
	taskc->throughput_epoch_ns = 0;
	taskc->policy_class = SCX_ADAPTIVE_CLASS_BALANCED;

	fill_task_event(&event, p, taskc, SCX_ADAPTIVE_EVENT_EXEC,
			bpf_ktime_get_ns());
	emit_event(&event);
	return 0;
}

/** Validates loader parameters before sched_ext takes control of normal tasks. */
s32 BPF_STRUCT_OPS_SLEEPABLE(adaptive_init)
{
	u32 core_index;
	u32 cpu;
	u32 domain_id;
	s32 ret;

	if (!usersched_pid || !num_possible_cpus || !num_domains ||
	    !num_core_leaders || num_core_leaders > num_possible_cpus ||
	    num_possible_cpus > SCX_ADAPTIVE_MAX_CPUS)
		return -EINVAL;
	if (num_domains > num_possible_cpus ||
	    num_domains > SCX_ADAPTIVE_MAX_CPUS)
		return -EINVAL;
	if (!min_slice_ns || min_slice_ns > max_slice_ns)
		return -EINVAL;
	if (!latency_budget_percent || latency_budget_percent > 100 ||
	    !latency_preemption_interval_ns)
		return -EINVAL;
	if (latency_slice_ns < min_slice_ns || latency_slice_ns > max_slice_ns ||
	    balanced_slice_ns < min_slice_ns || balanced_slice_ns > max_slice_ns ||
	    throughput_slice_ns < min_slice_ns || throughput_slice_ns > max_slice_ns)
		return -EINVAL;
	bpf_for(cpu, 0, SCX_ADAPTIVE_MAX_CPUS) {
		u32 leader;
		u32 peer;

		if (cpu >= num_possible_cpus)
			break;
		leader = immutable_core_leader_for_cpu(cpu);
		peer = immutable_core_peer_for_leader(leader);
		if (immutable_domain_for_cpu(cpu) >= num_domains ||
		    leader >= num_possible_cpus ||
		    immutable_core_leader_for_cpu(leader) != leader ||
		    immutable_domain_for_cpu(leader) != immutable_domain_for_cpu(cpu) ||
		    peer >= num_possible_cpus ||
		    immutable_core_leader_for_cpu(peer) != leader ||
		    immutable_domain_for_cpu(peer) != immutable_domain_for_cpu(leader))
			return -EINVAL;
		ret = scx_bpf_create_dsq(task_dsq(cpu), -1);
		if (ret)
			return ret;
		ret = scx_bpf_create_dsq(latency_dsq(cpu), -1);
		if (ret)
			return ret;
	}
	bpf_for(core_index, 0, SCX_ADAPTIVE_MAX_CPUS) {
		u32 leader;

		if (core_index >= num_core_leaders)
			break;
		leader = immutable_core_leader_at(core_index);
		if (leader >= num_possible_cpus ||
		    immutable_core_leader_for_cpu(leader) != leader ||
		    immutable_domain_for_cpu(leader) >= num_domains)
			return -EINVAL;
		ret = scx_bpf_create_dsq(shared_latency_dsq(leader), -1);
		if (ret)
			return ret;
	}
	bpf_for(domain_id, 0, SCX_ADAPTIVE_MAX_CPUS) {
		if (domain_id >= num_domains)
			break;
		ret = scx_bpf_create_dsq(
			balanced_overflow_dsq(domain_id), -1);
		if (ret)
			return ret;
	}
	return 0;
}

/** Captures the sched_ext exit reason for the Rust process to report. */
void BPF_STRUCT_OPS(adaptive_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Ordinary work uses CPU-owned virtual-deadline queues with bounded
 * idle stealing. Userspace changes policy through task_control only.
 */
SCX_OPS_DEFINE(scx_adaptive,
	.select_cpu		= (void *)adaptive_select_cpu,
	.enqueue		= (void *)adaptive_enqueue,
	.dequeue		= (void *)adaptive_dequeue,
	.dispatch		= (void *)adaptive_dispatch,
	.running		= (void *)adaptive_running,
	.stopping		= (void *)adaptive_stopping,
	.tick			= (void *)adaptive_tick,
	.update_idle		= (void *)adaptive_update_idle,
	.cpu_online		= (void *)adaptive_cpu_online,
	.cpu_offline		= (void *)adaptive_cpu_offline,
	.init_task		= (void *)adaptive_init_task,
	.exit_task		= (void *)adaptive_exit_task,
	.init			= (void *)adaptive_init,
	.exit			= (void *)adaptive_exit,
	.dispatch_max_batch	= SCX_ADAPTIVE_MAX_DISPATCH_BATCH,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE |
				  SCX_OPS_SWITCH_PARTIAL,
	.name			= "scx_adaptive");
