/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * scx_adaptive sched_ext data plane.
 *
 * Ordinary tasks run through hierarchical BPF EEVDF queues, defaulting to
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
const volatile u64 latency_slice_ns = 250000ULL;
const volatile u64 balanced_slice_ns = 4000000ULL;
const volatile u64 throughput_slice_ns = 8000000ULL;
const volatile u64 min_slice_ns = 250000ULL;
const volatile u64 max_slice_ns = 64000000ULL;
const volatile u64 preemption_min_runtime_ns = 250000ULL;
const volatile u64 fast_preemption_interval_ns = 5000000ULL;
const volatile u64 latency_backlog_request_ns = 227273ULL;

#define FAST_CLASS_DSQ_BASE 0x10000ULL
#define FAST_LATENCY_OVERFLOW_DSQ \
	(FAST_CLASS_DSQ_BASE + \
	 (u64)SCX_ADAPTIVE_CLASS_COUNT * SCX_ADAPTIVE_MAX_CPUS)
#define FAST_BPF_URGENT_DISPATCH_ID (~0ULL)
#define FAST_NO_RUNNING_CLASS SCX_ADAPTIVE_CLASS_COUNT
#define FAST_STEAL_SCAN_LIMIT 8U
#define FAST_LATENCY_SCAN_LIMIT 8U
/* Inherited tasks need enough samples for one-second behavior windows. */
#define FAST_EVENT_SAMPLE_INTERVAL_NS 4000000ULL
#define FAST_COARSE_EVENT_SAMPLE_INTERVAL_NS 16000000ULL

/* Non-zero monotonic source shared by task and process cookie allocation. */
static u64 next_identity_cookie = 1;

/* Number of tasks waiting in custom class DSQs (local DSQs are excluded). */
static volatile u64 class_queued_tasks;

/* Number of live tasks whose effective policy is not Balanced. */
static volatile u64 specialized_tasks;

/* Serializes the short shared-overflow move without locking private queues. */
static volatile u32 latency_overflow_claim;

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
	u32 counted_specialized;
	u32 padding;
	struct process_identity_key process_key;
};

/* Global virtual time used by each class's per-CPU task queues. */
struct fast_class_state {
	u64 virtual_time_ns;
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

/* Three dense class entities; queue contents live in custom sched_ext DSQs. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SCX_ADAPTIVE_CLASS_COUNT);
	__type(key, u32);
	__type(value, struct fast_class_state);
} class_state SEC(".maps");

/* Shared bounded pipeline and liveness state for every possible CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SCX_ADAPTIVE_MAX_CPUS);
	__type(key, u32);
	__type(value, struct adaptive_cpu_state);
} cpu_state SEC(".maps");

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

/** Returns the virtual-deadline queue for a workload class. */
static __always_inline u64 class_dsq(u32 class_id, u32 cpu)
{
	return FAST_CLASS_DSQ_BASE +
	       (u64)class_id * SCX_ADAPTIVE_MAX_CPUS + cpu;
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

/** Converts real service into EEVDF virtual service using Linux task weight. */
static __always_inline u64 task_virtual_service(
	const struct task_struct *p, u64 service_ns)
{
	u64 service = scale_by_task_weight_inverse(p, service_ns);

	return service_ns && !service ? 1 : service;
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
	if (!taskc || !taskc->class_queue_accounted)
		return;
	taskc->class_queue_accounted = 0;
	__sync_fetch_and_sub(&class_queued_tasks, 1);
}

/** Tracks whether any live task requires the mixed-class root scheduler. */
static __always_inline void sync_specialized_task(
	struct task_context *taskc, u32 class_id)
{
	bool specialized = class_id != SCX_ADAPTIVE_CLASS_BALANCED;

	if (specialized == !!taskc->counted_specialized)
		return;
	taskc->counted_specialized = specialized;
	if (specialized)
		__sync_fetch_and_add(&specialized_tasks, 1);
	else
		__sync_fetch_and_sub(&specialized_tasks, 1);
}

/** Drops a task's mixed-class membership during exec or exit. */
static __always_inline void clear_specialized_task(
	struct task_context *taskc)
{
	if (!taskc || !taskc->counted_specialized)
		return;
	taskc->counted_specialized = 0;
	__sync_fetch_and_sub(&specialized_tasks, 1);
}

/** Looks up one class state after validating its dense index. */
static __always_inline struct fast_class_state *class_state_for(u32 class_id)
{
	if (class_id >= SCX_ADAPTIVE_CLASS_COUNT)
		return 0;
	return bpf_map_lookup_elem(&class_state, &class_id);
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

/** Reads one dense root entity without verifier-visible array indexing. */
static __always_inline u64 root_vruntime_for(
	const struct adaptive_cpu_state *cpuc, u32 class_id)
{
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		return cpuc->root_vruntime_ns[0];
	if (class_id == SCX_ADAPTIVE_CLASS_BALANCED)
		return cpuc->root_vruntime_ns[1];
	if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		return cpuc->root_vruntime_ns[2];
	return ~0ULL;
}

/** Writes one dense root entity without verifier-visible array indexing. */
static __always_inline void set_root_vruntime(
	struct adaptive_cpu_state *cpuc, u32 class_id, u64 vruntime)
{
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY)
		cpuc->root_vruntime_ns[0] = vruntime;
	else if (class_id == SCX_ADAPTIVE_CLASS_BALANCED)
		cpuc->root_vruntime_ns[1] = vruntime;
	else if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT)
		cpuc->root_vruntime_ns[2] = vruntime;
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
	if (remote)
		stats->fast_path_remote_steals++;
	else
		stats->fast_path_local_dispatches++;
}

/** Records one local or remote class dispatch. */
static __always_inline void record_fast_dispatch(u32 class_id, bool remote)
{
	account_fast_dispatch(stats_value(), class_id, remote);
}

/** Records one enqueue and folds direct-dispatch counters into one lookup. */
static __always_inline void record_fast_enqueue(
	u32 class_id, bool direct, bool events_suppressed)
{
	struct adaptive_global_stats *stats = stats_value();

	if (!stats)
		return;
	stats->fast_path_enqueues++;
	if (events_suppressed)
		stats->fast_path_events_suppressed++;
	if (direct) {
		account_fast_dispatch(stats, class_id, false);
		stats->fast_path_direct_dispatches++;
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

/** Preserves at most one request of lag while entering or changing a class. */
static __always_inline void rebase_fast_vruntime(
	struct task_struct *p, struct task_context *taskc,
	u32 target_class, u64 target_request)
{
	struct fast_class_state *target = class_state_for(target_class);
	struct fast_class_state *source;
	u64 lag;
	u64 floor;
	u64 source_request;

	if (!target)
		return;
	if (!taskc->fast_path || taskc->policy_class >= SCX_ADAPTIVE_CLASS_COUNT) {
		floor = target->virtual_time_ns > target_request ?
			target->virtual_time_ns - target_request : 0;
		if (taskc->vruntime_ns < floor)
			taskc->vruntime_ns = floor;
		return;
	}
	if (taskc->policy_class == target_class)
		return;

	source = class_state_for(taskc->policy_class);
	if (!source) {
		taskc->vruntime_ns = target->virtual_time_ns;
		return;
	}
	source_request = task_virtual_service(
		p, class_slice(taskc->policy_class));
	if (source->virtual_time_ns >= taskc->vruntime_ns) {
		lag = source->virtual_time_ns - taskc->vruntime_ns;
		if (lag > source_request)
			lag = source_request;
		if (lag > target_request)
			lag = target_request;
		taskc->vruntime_ns = target->virtual_time_ns > lag ?
			target->virtual_time_ns - lag : 0;
	} else {
		lag = taskc->vruntime_ns - source->virtual_time_ns;
		if (lag > source_request)
			lag = source_request;
		if (lag > target_request)
			lag = target_request;
		taskc->vruntime_ns = target->virtual_time_ns + lag;
	}
}

/** Bounds a returning root entity to one request of per-CPU sleep credit. */
static __always_inline u64 activate_root_entity(
	struct adaptive_cpu_state *cpuc, u32 class_id, u64 request)
{
	u64 vruntime = root_vruntime_for(cpuc, class_id);
	u64 floor = cpuc->root_virtual_time_ns > request ?
		cpuc->root_virtual_time_ns - request : 0;

	if (vruntime < floor) {
		vruntime = floor;
		set_root_vruntime(cpuc, class_id, vruntime);
	}
	return vruntime;
}

/** Charges one class request to a CPU's root EEVDF entity. */
static __always_inline u64 charge_root_entity(
	struct adaptive_cpu_state *cpuc, u32 class_id, u64 request)
{
	u64 vruntime = activate_root_entity(cpuc, class_id, request);

	set_root_vruntime(cpuc, class_id, vruntime + request);
	return vruntime;
}

/** Charges a continued request while preserving the class's root fairness. */
static __always_inline void charge_root_continuation(
	struct adaptive_cpu_state *cpuc, u32 class_id, u64 request)
{
	u64 vruntime = activate_root_entity(cpuc, class_id, request);

	set_root_vruntime(cpuc, class_id, vruntime + request);
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
		scx_bpf_dsq_nr_queued(FAST_LATENCY_OVERFLOW_DSQ) > 0 ||
		fast_queued_on_cpu(cpu) > 0;
}

/** Bounds urgent latency service to one root request ahead on the target CPU. */
static __always_inline bool latency_urgent_allowed(s32 cpu)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);

	return cpuc && root_vruntime_for(cpuc, SCX_ADAPTIVE_CLASS_LATENCY) <
		cpuc->root_virtual_time_ns + latency_slice_ns;
}

/** Prevents repeated urgent kicks from exceeding the configured disruption budget. */
static __always_inline bool fast_preemption_time_allowed(
	const struct adaptive_cpu_state *cpuc, u64 now)
{
	if (!cpuc || !cpuc->running_started_ns ||
	    now < cpuc->running_started_ns ||
	    now - cpuc->running_started_ns < preemption_min_runtime_ns)
		return false;
	if (cpuc->last_preemption_ns &&
	    (now < cpuc->last_preemption_ns ||
	     now - cpuc->last_preemption_ns < fast_preemption_interval_ns))
		return false;
	return true;
}

/** Claims the existing urgent lane only for a non-latency userspace victim. */
static __always_inline bool arm_fast_preemption(s32 cpu, u64 now)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);

	if (!cpuc || !cpuc->online || cpuc->idle ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY ||
	    !latency_urgent_allowed(cpu))
		return false;
	if (!fast_preemption_time_allowed(cpuc, now)) {
		STAT_INC(fast_path_preemption_throttles);
		return false;
	}
	if (__sync_val_compare_and_swap(&cpuc->urgent_dispatch_id, 0,
					FAST_BPF_URGENT_DISPATCH_ID) != 0)
		return false;
	cpuc->last_preemption_ns = now;
	return true;
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
	struct fast_class_state *classc = class_state_for(class_id);
	struct adaptive_cpu_state *ownerc;
	struct task_event event = {};
	s32 selected_idle_cpu = taskc->selected_idle_cpu;
	u64 request;
	u64 sleep_credit;
	u64 virtual_request;
	bool class_changed;
	bool direct;
	bool latency_overflow;
	bool preempt;
	bool woke_from_sleep;

	ownerc = cpu_state_for(owner_cpu);
	if (!classc || !ownerc || !ownerc->online ||
	    !bpf_cpumask_test_cpu(owner_cpu, p->cpus_ptr))
		return false;
	sync_specialized_task(taskc, class_id);
	woke_from_sleep = taskc->last_stop_blocked;
	begin_enqueue(taskc, now);
	taskc->selected_idle_cpu = -1;
	class_changed = !taskc->fast_path || taskc->policy_class != class_id;
	if (class_changed) {
		rebase_fast_vruntime(
			p, taskc, class_id,
			task_virtual_service(p, class_slice(class_id)));
		taskc->request_ns = 0;
		taskc->request_deadline_ns = 0;
		taskc->throughput_epoch_ns =
			class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT ?
			throughput_slice_ns : 0;
	}
	request = task_request_size(taskc, class_id);
	virtual_request = task_virtual_service(p, request);
	if (!taskc->request_ns) {
		sleep_credit = classc->virtual_time_ns < virtual_request ?
			classc->virtual_time_ns : virtual_request;
		if (taskc->vruntime_ns < classc->virtual_time_ns - sleep_credit)
			taskc->vruntime_ns = classc->virtual_time_ns - sleep_credit;
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
	latency_overflow = class_id == SCX_ADAPTIVE_CLASS_LATENCY &&
		(scx_bpf_dsq_nr_queued(FAST_LATENCY_OVERFLOW_DSQ) > 0 ||
		 scx_bpf_dsq_nr_queued(class_dsq(
			SCX_ADAPTIVE_CLASS_LATENCY, owner_cpu)) > 0);
	if (direct) {
		taskc->class_queue_accounted = 0;
		charge_root_entity(ownerc, class_id, class_slice(class_id));
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | owner_cpu,
				   taskc->request_ns, enq_flags);
	} else {
		taskc->class_queue_accounted = 1;
		__sync_fetch_and_add(&class_queued_tasks, 1);
		scx_bpf_dsq_insert_vtime(p,
				  latency_overflow ? FAST_LATENCY_OVERFLOW_DSQ :
					  class_dsq(class_id, owner_cpu),
				  taskc->request_ns,
				  taskc->request_deadline_ns, enq_flags);
	}
	record_fast_enqueue(class_id, direct,
			    !taskc->observe_fast_events);
	preempt = !direct &&
		  woke_from_sleep &&
		  class_id == SCX_ADAPTIVE_CLASS_LATENCY &&
		  arm_fast_preemption(owner_cpu, now);
	if (!from_select) {
		if (preempt)
			scx_bpf_kick_cpu(owner_cpu, SCX_KICK_PREEMPT);
		else if (selected_idle_cpu == owner_cpu)
			scx_bpf_kick_cpu(owner_cpu, SCX_KICK_IDLE);
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

	sync_specialized_task(taskc, class_id);
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

/** Selects a class by per-CPU root EEVDF from one CPU's task queues. */
static __always_inline s32 select_fast_class(
	struct adaptive_cpu_state *cpuc, s32 queue_cpu, u32 excluded,
	bool include_latency_overflow)
{
	u64 best_deadline = ~0ULL;
	u64 next_deadline = ~0ULL;
	u64 next_vruntime = ~0ULL;
	s32 best = -1;
	s32 next = -1;
	u32 class_id;

	if (!cpuc || queue_cpu < 0 || queue_cpu >= num_possible_cpus)
		return -1;

	#pragma unroll
	for (class_id = 0; class_id < SCX_ADAPTIVE_CLASS_COUNT; class_id++) {
		u64 effective;
		u64 deadline;
		u64 request;
		s64 queued;

		if (excluded & (1U << class_id))
			continue;
		queued = scx_bpf_dsq_nr_queued(class_dsq(class_id, queue_cpu));
		if (include_latency_overflow &&
		    class_id == SCX_ADAPTIVE_CLASS_LATENCY)
			queued += scx_bpf_dsq_nr_queued(
				FAST_LATENCY_OVERFLOW_DSQ);
		if (queued <= 0)
			continue;
		request = class_id == SCX_ADAPTIVE_CLASS_LATENCY && queued > 1 ?
			latency_backlog_request_ns : class_slice(class_id);
		effective = activate_root_entity(cpuc, class_id, request);
		deadline = effective + request;
		if (effective < next_vruntime ||
		    (effective == next_vruntime && deadline < next_deadline)) {
			next_vruntime = effective;
			next_deadline = deadline;
			next = class_id;
		}
		if (effective <= cpuc->root_virtual_time_ns &&
		    (deadline < best_deadline ||
		     (deadline == best_deadline &&
		      (best < 0 || class_id < best)))) {
			best_deadline = deadline;
			best = class_id;
		}
	}
	if (best >= 0 || next < 0)
		return best;
	cpuc->root_virtual_time_ns = next_vruntime;
	return next;
}

/** Prefers a shared latency task's target CPU until one latency slice elapses. */
static __always_inline bool dispatch_latency_overflow(s32 dst_cpu,
						       bool *remote)
{
	struct task_struct *p;
	u32 claim = dst_cpu + 1;
	u32 scanned = 0;
	u64 now = bpf_ktime_get_ns();
	bool moved = false;

	*remote = false;

	if (__sync_val_compare_and_swap(&latency_overflow_claim, 0, claim) != 0)
		return false;
	bpf_for_each(scx_dsq, p, FAST_LATENCY_OVERFLOW_DSQ, 0) {
		struct task_context *taskc;
		u64 wait_ns;

		if (scanned++ >= FAST_LATENCY_SCAN_LIMIT)
			break;
		if (!bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr))
			continue;
		taskc = task_ctx_for(p);
		if (!taskc)
			continue;
		wait_ns = now >= taskc->enqueue_ns ? now - taskc->enqueue_ns : 0;
		if (taskc->target_cpu != dst_cpu && wait_ns < latency_slice_ns)
			continue;
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0))
			continue;
		*remote = taskc->target_cpu != dst_cpu;
		moved = true;
		break;
	}
	__sync_val_compare_and_swap(&latency_overflow_claim, claim, 0);
	return moved;
}

/** Moves one task from a class queue into the caller's local DSQ. */
static __always_inline bool dispatch_fast_class(
	s32 dst_cpu, s32 src_cpu, u32 class_id, bool remote)
{
	struct adaptive_cpu_state *dst = cpu_state_for(dst_cpu);
	bool latency_backlog;
	bool overflow_remote;
	u64 request;
	u64 vruntime;

	if (!dst || src_cpu < 0 || src_cpu >= num_possible_cpus ||
	    class_id >= SCX_ADAPTIVE_CLASS_COUNT)
		return false;
	latency_backlog = class_id == SCX_ADAPTIVE_CLASS_LATENCY &&
		(scx_bpf_dsq_nr_queued(class_dsq(class_id, src_cpu)) +
		 (!remote ?
		  scx_bpf_dsq_nr_queued(FAST_LATENCY_OVERFLOW_DSQ) : 0)) > 1;
	request = latency_backlog ? latency_backlog_request_ns :
		class_slice(class_id);
	vruntime = charge_root_entity(dst, class_id, request);
	if (scx_bpf_dsq_move_to_local(class_dsq(class_id, src_cpu))) {
		record_fast_dispatch(class_id, remote);
		if (latency_backlog)
			STAT_INC(fast_path_latency_backlog_boosts);
		return true;
	}
	if (class_id == SCX_ADAPTIVE_CLASS_LATENCY && !remote &&
	    dispatch_latency_overflow(dst_cpu, &overflow_remote)) {
		record_fast_dispatch(class_id, overflow_remote);
		if (latency_backlog)
			STAT_INC(fast_path_latency_backlog_boosts);
		return true;
	}
	set_root_vruntime(dst, class_id, vruntime);
	STAT_INC(fast_path_dispatch_failures);
	return false;
}

/** Returns the number of classified tasks queued on one CPU. */
static __always_inline u64 fast_queued_on_cpu(s32 cpu)
{
	s32 count;
	u64 queued = 0;

	if (cpu < 0 || cpu >= num_possible_cpus)
		return 0;
	count = scx_bpf_dsq_nr_queued(
		class_dsq(SCX_ADAPTIVE_CLASS_LATENCY, cpu));
	if (count > 0)
		queued += count;
	count = scx_bpf_dsq_nr_queued(
		class_dsq(SCX_ADAPTIVE_CLASS_BALANCED, cpu));
	if (count > 0)
		queued += count;
	count = scx_bpf_dsq_nr_queued(
		class_dsq(SCX_ADAPTIVE_CLASS_THROUGHPUT, cpu));
	if (count > 0)
		queued += count;
	return queued;
}

/** Preserves a small local successor set while still draining real backlog. */
static __always_inline bool source_can_spare(s32 cpu)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	u64 queued;

	if (!specialized_tasks) {
		s64 balanced = scx_bpf_dsq_nr_queued(
			class_dsq(SCX_ADAPTIVE_CLASS_BALANCED, cpu));

		queued = balanced > 0 ? balanced : 0;
	} else {
		queued = fast_queued_on_cpu(cpu);
	}

	if (!cpuc || !queued)
		return false;
	if (!cpuc->online)
		return true;
	if (queued > 2)
		return true;
	return !cpuc->idle &&
		cpuc->running_class != SCX_ADAPTIVE_CLASS_LATENCY;
}

/** Scans once from a rotating origin and serializes movers per source CPU. */
static __always_inline bool steal_fast_task(s32 dst_cpu)
{
	struct adaptive_cpu_state *dst = cpu_state_for(dst_cpu);
	u32 cursor;
	u32 scan;

	if (!dst || num_possible_cpus <= 1)
		return false;

	if (__sync_fetch_and_add(&class_queued_tasks, 0) == 0) {
		STAT_INC(fast_path_empty_steal_skips);
		return false;
	}
	STAT_INC(fast_path_steal_attempts);
	cursor = dst->steal_cursor++;

	bpf_for(scan, 0, FAST_STEAL_SCAN_LIMIT) {
		struct adaptive_cpu_state *src;
		u32 excluded = 0;
		s32 src_cpu;
		bool dispatched = false;

		if (scan >= num_possible_cpus - 1)
			break;
		src_cpu = (dst_cpu + 1 +
			   (cursor + scan) % (num_possible_cpus - 1)) %
			  num_possible_cpus;
		if (!source_can_spare(src_cpu))
			continue;
		src = cpu_state_for(src_cpu);
		if (!src)
			continue;
		if (__sync_val_compare_and_swap(&src->steal_claim, 0,
							  dst_cpu + 1) != 0) {
			STAT_INC(fast_path_steal_claim_conflicts);
			continue;
		}

		if (!specialized_tasks &&
		    scx_bpf_dsq_move_to_local(class_dsq(
			    SCX_ADAPTIVE_CLASS_BALANCED, src_cpu))) {
			record_fast_dispatch(SCX_ADAPTIVE_CLASS_BALANCED, true);
			dispatched = true;
		}

		bpf_repeat(SCX_ADAPTIVE_CLASS_COUNT) {
			s32 class_id;

			if (dispatched)
				break;
			class_id = select_fast_class(
				dst, src_cpu, excluded, false);
			if (class_id < 0)
				break;
			if (dispatch_fast_class(
				dst_cpu, src_cpu, class_id, true)) {
				dispatched = true;
				break;
			}
			excluded |= 1U << class_id;
		}
		__sync_val_compare_and_swap(&src->steal_claim, dst_cpu + 1, 0);
		if (dispatched)
			return true;
	}
	return false;
}

/** Moves Balanced work directly while no task needs class arbitration. */
static __always_inline bool dispatch_balanced_only(s32 cpu)
{
	if (specialized_tasks ||
	    !scx_bpf_dsq_move_to_local(
		class_dsq(SCX_ADAPTIVE_CLASS_BALANCED, cpu)))
		return false;
	record_fast_dispatch(SCX_ADAPTIVE_CLASS_BALANCED, false);
	return true;
}

/** Returns a preemptible running class on one allowed CPU, or the sentinel. */
static __always_inline u32 preemptible_class(
	struct task_struct *p, s32 cpu, u64 now)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);

	if (!cpuc || !cpuc->online || cpuc->idle || cpuc->urgent_dispatch_id ||
	    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr) ||
	    cpuc->running_class >= SCX_ADAPTIVE_CLASS_COUNT ||
	    cpuc->running_class == SCX_ADAPTIVE_CLASS_LATENCY ||
	    !fast_preemption_time_allowed(cpuc, now))
		return FAST_NO_RUNNING_CLASS;
	return cpuc->running_class;
}

/** Prefers the previous CPU, then any throughput CPU, then Balanced. */
static __always_inline s32 pick_latency_victim(struct task_struct *p,
					   s32 prev_cpu, u64 now)
{
	struct adaptive_cpu_state *prevc;
	s32 balanced = -1;
	s32 throughput = -1;
	u32 class_id;
	u32 cpu;

	prevc = cpu_state_for(prev_cpu);
	if (prevc && prevc->online && !prevc->idle &&
	    prevc->running_class == SCX_ADAPTIVE_CLASS_LATENCY &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_dsq_nr_queued(
		class_dsq(SCX_ADAPTIVE_CLASS_LATENCY, prev_cpu)) <= 0)
		return prev_cpu;

	class_id = preemptible_class(p, prev_cpu, now);
	if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT ||
	    class_id == SCX_ADAPTIVE_CLASS_BALANCED)
		return prev_cpu;

	bpf_for(cpu, 0, SCX_ADAPTIVE_MAX_CPUS) {
		if (cpu >= num_possible_cpus)
			break;
		if ((s32)cpu == prev_cpu)
			continue;
		class_id = preemptible_class(p, cpu, now);
		if (class_id == SCX_ADAPTIVE_CLASS_THROUGHPUT) {
			throughput = cpu;
			break;
		}
		if (class_id == SCX_ADAPTIVE_CLASS_BALANCED && balanced < 0)
			balanced = cpu;
	}
	return throughput >= 0 ? throughput : balanced;
}

/** Atomically claims one allowed idle CPU from a scheduler-owned mask. */
static __always_inline s32 claim_idle_cpu(struct task_struct *p, s32 prev_cpu,
						  const struct cpumask *idle_mask)
{
	u32 selected;

	if (!idle_mask)
		return -1;
	if (prev_cpu >= 0 && prev_cpu < num_possible_cpus &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    bpf_cpumask_test_cpu(prev_cpu, idle_mask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	selected = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_mask);
	if (selected < num_possible_cpus &&
	    scx_bpf_test_and_clear_cpu_idle(selected))
		return selected;
	return -1;
}

/** Preserves bulk locality and gives latency work an idle core or victim. */
s32 BPF_STRUCT_OPS(adaptive_select_cpu, struct task_struct *p, s32 prev_cpu,
			   u64 wake_flags)
{
	struct task_context *taskc = task_ctx_for(p);
	struct task_control_value *control;
	struct adaptive_cpu_state *prevc;
	const struct cpumask *idle_smtmask;
	const struct cpumask *idle_mask;
	u32 class_id = SCX_ADAPTIVE_CLASS_BALANCED;
	u32 control_flags = SCX_ADAPTIVE_CONTROL_BPF_SCHED |
			    SCX_ADAPTIVE_CONTROL_OBSERVE |
			    SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE;
	u32 selected;
	s32 cpu = -1;
	u64 now = bpf_ktime_get_ns();

	if (!taskc)
		return prev_cpu;
	taskc->previous_cpu = prev_cpu;
	taskc->selected_idle_cpu = -1;
	control = fast_control_for(p, taskc);
	if (control) {
		class_id = control->class_id;
		control_flags = control->flags;
	}
	taskc->selected_class_id = class_id;
	taskc->selected_control_flags = control_flags;
	taskc->selected_control_valid = 1;
	if (class_id != SCX_ADAPTIVE_CLASS_LATENCY) {
		bool is_idle = false;

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
		goto selected;
	}

	idle_smtmask = scx_bpf_get_idle_smtmask();
	cpu = claim_idle_cpu(p, prev_cpu, idle_smtmask);
	if (idle_smtmask)
		scx_bpf_put_idle_cpumask(idle_smtmask);
	if (cpu >= 0) {
		taskc->selected_idle_cpu = cpu;
		goto selected;
	}

	idle_mask = scx_bpf_get_idle_cpumask();
	cpu = claim_idle_cpu(p, prev_cpu, idle_mask);
	if (idle_mask)
		scx_bpf_put_idle_cpumask(idle_mask);
	if (cpu >= 0)
		taskc->selected_idle_cpu = cpu;
	if (cpu < 0)
		cpu = pick_latency_victim(p, prev_cpu, now);
	if (cpu < 0 && prev_cpu >= 0 &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		cpu = prev_cpu;
	if (cpu < 0) {
		selected = bpf_cpumask_any_distribute(p->cpus_ptr);
		if (selected < num_possible_cpus)
			cpu = selected;
	}

selected:
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
		return;
	}

	if (is_safe_task(p)) {
		begin_enqueue(taskc, now);
		taskc->selected_idle_cpu = -1;
		taskc->fast_path = 0;
		fallback_dispatch(p, taskc, enq_flags);
		return;
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
		return;
	fallback_fast_enqueue(
		p, taskc, class_id, control_flags, enq_flags, now);
}

/** Extends an uncontended Throughput epoch without a dequeue/dispatch cycle. */
static __always_inline bool continue_throughput_task(
	struct task_struct *prev, s32 cpu, struct adaptive_cpu_state *cpuc)
{
	struct task_context *taskc;
	struct task_control_value *control;
	struct fast_class_state *classc;
	u64 consumed;
	u64 request;
	u64 now;

	if (!prev || !cpuc || cpuc->running_class != SCX_ADAPTIVE_CLASS_THROUGHPUT ||
	    !(prev->scx.flags & SCX_TASK_QUEUED) ||
	    scx_bpf_task_cpu(prev) != cpu ||
	    !bpf_cpumask_test_cpu(cpu, prev->cpus_ptr) ||
	    __sync_fetch_and_add(&class_queued_tasks, 0) > 0 ||
	    cpu_has_local_work(cpu, cpuc))
		return false;
	taskc = task_ctx_for(prev);
	if (!taskc || !taskc->fast_path || taskc->observe_fast_events ||
	    taskc->policy_class != SCX_ADAPTIVE_CLASS_THROUGHPUT)
		return false;
	control = fast_control_for(prev, taskc);
	if (!control || control->class_id != SCX_ADAPTIVE_CLASS_THROUGHPUT ||
	    (control->flags & SCX_ADAPTIVE_CONTROL_OBSERVE))
		return false;
	consumed = taskc->request_ns;
	if (consumed < min_slice_ns || consumed > max_slice_ns)
		consumed = throughput_slice_ns;
	taskc->vruntime_ns += task_virtual_service(prev, consumed);
	classc = class_state_for(SCX_ADAPTIVE_CLASS_THROUGHPUT);
	if (classc && classc->virtual_time_ns < taskc->vruntime_ns)
		classc->virtual_time_ns = taskc->vruntime_ns;

	request = task_request_size(taskc, SCX_ADAPTIVE_CLASS_THROUGHPUT);
	request = request <= max_slice_ns / 2 ? request * 2 : max_slice_ns;
	taskc->throughput_epoch_ns = request;
	taskc->request_ns = request;
	taskc->request_deadline_ns = taskc->vruntime_ns +
		task_virtual_service(prev, request);
	now = bpf_ktime_get_ns();
	taskc->start_ns = now;
	prev->scx.slice = request;
	charge_root_continuation(cpuc, SCX_ADAPTIVE_CLASS_THROUGHPUT, request);
	STAT_INC(fast_path_prev_continuations);
	return true;
}

/** Wakes the control plane when requested and dispatches bounded BPF work. */
void BPF_STRUCT_OPS(adaptive_dispatch, s32 cpu, struct task_struct *prev)
{
	struct adaptive_cpu_state *cpuc = cpu_state_for(cpu);
	u32 excluded = 0;

	if (cpuc &&
	    __sync_val_compare_and_swap(&cpuc->urgent_dispatch_id,
					FAST_BPF_URGENT_DISPATCH_ID, 0) ==
					FAST_BPF_URGENT_DISPATCH_ID &&
	    scx_bpf_dispatch_nr_slots() > 0 &&
	    dispatch_fast_class(
		cpu, cpu, SCX_ADAPTIVE_CLASS_LATENCY, false)) {
		STAT_INC(fast_path_preemptions);
		return;
	}
	if (!specialized_tasks) {
		if (scx_bpf_dispatch_nr_slots() > 0 &&
		    dispatch_balanced_only(cpu))
			return;
		if (scx_bpf_dispatch_nr_slots() > 0)
			steal_fast_task(cpu);
		return;
	}

	bpf_repeat(SCX_ADAPTIVE_CLASS_COUNT) {
		s32 class_id;

		if (scx_bpf_dispatch_nr_slots() == 0)
			break;
		class_id = select_fast_class(cpuc, cpu, excluded, true);
		if (class_id < 0)
			break;
		if (dispatch_fast_class(cpu, cpu, class_id, false))
			return;
		excluded |= 1U << class_id;
	}
	if (continue_throughput_task(prev, cpu, cpuc))
		return;
	if (scx_bpf_dispatch_nr_slots() > 0)
		steal_fast_task(cpu);
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
	if (cpuc) {
		cpuc->running_class =
			taskc->policy_class < SCX_ADAPTIVE_CLASS_COUNT ?
			taskc->policy_class : SCX_ADAPTIVE_CLASS_BALANCED;
		cpuc->running_started_ns = now;
	}

	if (taskc->fast_path && taskc->policy_class < SCX_ADAPTIVE_CLASS_COUNT) {
		struct fast_class_state *classc = class_state_for(taskc->policy_class);

		if (classc && classc->virtual_time_ns < taskc->vruntime_ns)
			classc->virtual_time_ns = taskc->vruntime_ns;
	}
	if (taskc->fast_path) {
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
	}
	taskc->stop_ns = now;
	taskc->last_stop_blocked = !runnable;
	runtime_ns = taskc->start_ns && now >= taskc->start_ns ?
		     now - taskc->start_ns : 0;

	if (taskc->fast_path) {
		u64 assigned_ns = taskc->request_ns;
		u64 remaining_ns = assigned_ns > runtime_ns ?
			assigned_ns - runtime_ns : 0;
		bool interrupted = runnable && assigned_ns &&
			runtime_ns < assigned_ns * 9 / 10;

		taskc->vruntime_ns += task_virtual_service(p, runtime_ns);
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
	if (idle)
		cpuc->running_class = FAST_NO_RUNNING_CLASS;
	if (idle)
		cpuc->running_started_ns = 0;
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
	cpuc->running_started_ns = 0;
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
	clear_specialized_task(taskc);
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
	clear_specialized_task(taskc);
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
	taskc->vruntime_ns = 0;
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
	u32 cpu;
	u32 class_id;
	s32 ret;

	if (!usersched_pid || !num_possible_cpus ||
	    num_possible_cpus > SCX_ADAPTIVE_MAX_CPUS)
		return -EINVAL;
	if (!min_slice_ns || min_slice_ns > max_slice_ns)
		return -EINVAL;
	if (!preemption_min_runtime_ns ||
	    fast_preemption_interval_ns < preemption_min_runtime_ns)
		return -EINVAL;
	if (latency_slice_ns < min_slice_ns || latency_slice_ns > max_slice_ns ||
	    balanced_slice_ns < min_slice_ns || balanced_slice_ns > max_slice_ns ||
	    throughput_slice_ns < min_slice_ns || throughput_slice_ns > max_slice_ns)
		return -EINVAL;
	bpf_for(cpu, 0, SCX_ADAPTIVE_MAX_CPUS) {
		if (cpu >= num_possible_cpus)
			break;
		#pragma unroll
		for (class_id = 0; class_id < SCX_ADAPTIVE_CLASS_COUNT;
		     class_id++) {
			ret = scx_bpf_create_dsq(class_dsq(class_id, cpu), -1);
			if (ret)
				return ret;
		}
	}
	ret = scx_bpf_create_dsq(FAST_LATENCY_OVERFLOW_DSQ, -1);
	if (ret)
		return ret;
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
