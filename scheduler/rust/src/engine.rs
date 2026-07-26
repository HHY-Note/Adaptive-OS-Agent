// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::admission::TimeBudget;
use crate::config::{ConfigError, SchedulerConfig};
use crate::eevdf::{RootDecision, RootEevdf};
use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
use crate::placement::{
    choose_cpu, predicted_completion_delay, CpuState, PlacementDecision, PreemptionVictim,
    TaskPlacement,
};
use crate::pool::{PoolNode, TaskPools};
use crate::process::{
    ClassUpdateError, ProcessClassUpdate, ProcessDefaultCache, TaskClassCache, TaskClassUpdate,
};
use crate::stats::{SchedulerStats, TaskBehaviorWindow, WindowQuality};
use crate::topology::{read_task_affinity, CpuMask, CpuTopology};
use crate::wire::{DispatchRequest, EventKind, KernelEvent, RejectReason};

const BEHAVIOR_HISTOGRAM_BOUNDS_NS: [u64; 3] = [250_000, 1_000_000, 4_000_000];
const HOME_REBASE_RUNS: [u32; 3] = [4, 8, 32];

/// Userspace lifecycle state of one stable task identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunState {
    /// Task is sleeping, cancelled, or otherwise not runnable.
    Blocked,
    /// Runnable identity has one valid node in a Rust class pool.
    Queued,
    /// Runnable identity is owned by a BPF class DSQ and needs no Rust command.
    KernelQueued,
    /// Locked task whose runnable transitions are intentionally BPF-only.
    KernelManaged,
    /// Rust submitted a command and reserved a CPU staging slot.
    Reserved,
    /// Matching RUNNING event confirmed actual execution.
    Running,
    /// Task lifetime ended; retained only transiently during cleanup.
    Exited,
}

/// Temporary protection preventing one running victim from being preempted repeatedly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PreemptionGuard {
    #[default]
    None,
    /// An urgent command was submitted but the victim has not stopped yet.
    AwaitingStop,
    /// The victim must receive useful service before becoming eligible again.
    Recovering,
}

/// Complete scheduler-owned state for one stable task lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskState {
    /// Stable task lifetime key.
    pub identity: TaskKey,
    /// Stable process image currently owning the task.
    pub process: ProcessKey,
    /// Current scheduler lifecycle state.
    pub run_state: RunState,
    /// Latest BPF runnable sequence accepted by Rust.
    pub enqueue_sequence: u64,
    /// Reservation currently submitted or running for this sequence.
    pub active_dispatch_id: Option<u64>,
    /// Last actual CPU confirmed by RUNNING.
    pub previous_cpu: Option<u32>,
    /// Stable locality preference established by successful execution.
    pub home_cpu: Option<u32>,
    /// LLC group corresponding to `home_cpu`.
    pub home_llc: Option<u32>,
    /// Consecutive runs away from home before rebasing locality.
    pub consecutive_home_misses: u32,
    /// Timestamp of the latest accepted ENQUEUE event.
    pub enqueue_time_ns: u64,
    /// Timestamp of the latest matching RUNNING event.
    pub last_start_ns: u64,
    /// Actual service accumulated in the task's EEVDF time domain.
    pub vruntime_ns: u64,
    /// Pool whose virtual-time domain currently owns `vruntime_ns`.
    pub eevdf_class: TaskClass,
    /// Planned slice of the current reservation.
    pub assigned_slice_ns: u64,
    /// Service left in the current EEVDF request after a forced preemption.
    pub request_remaining_ns: u64,
    /// Original finish deadline retained while `request_remaining_ns` is non-zero.
    pub request_deadline_ns: u64,
    /// EWMA of completed run bursts used only when starting a new request.
    pub service_estimate_ns: u64,
    /// Whether the preceding STOP interrupted an unfinished request.
    pub was_preempted: bool,
    /// Runnable sequence for which this latency task already issued one preemption.
    pub last_preempt_sequence: u64,
    /// Recovery state when this task was displaced by urgent latency work.
    pub preemption_guard: PreemptionGuard,
    /// Cached task affinity; BPF revalidates the live mask before dispatch.
    pub affinity: CpuMask,
}

impl TaskState {
    /// Creates a blocked task with conservative burst and affinity defaults.
    fn new(identity: TaskKey, process: ProcessKey, affinity: CpuMask) -> Self {
        Self {
            identity,
            process,
            run_state: RunState::Blocked,
            enqueue_sequence: 0,
            active_dispatch_id: None,
            previous_cpu: None,
            home_cpu: None,
            home_llc: None,
            consecutive_home_misses: 0,
            enqueue_time_ns: 0,
            last_start_ns: 0,
            vruntime_ns: 0,
            eevdf_class: TaskClass::Balanced,
            assigned_slice_ns: 0,
            request_remaining_ns: 0,
            request_deadline_ns: 0,
            service_estimate_ns: 0,
            was_preempted: false,
            last_preempt_sequence: 0,
            preemption_guard: PreemptionGuard::None,
            affinity,
        }
    }
}

/// Reservation phase retained until actual runtime accounting at STOP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationPhase {
    /// Command is queued or waiting in the target local DSQ.
    Submitted,
    /// Matching RUNNING occurred; CPU staging slot is already free.
    Running,
}

/// Planned service and identity attached to one dispatch command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    /// Non-zero command and reservation identity.
    pub dispatch_id: u64,
    /// Stable selected task lifetime.
    pub task: TaskKey,
    /// Runnable generation selected from the pool.
    pub enqueue_sequence: u64,
    /// Class charged by root EEVDF when this command was planned.
    pub class: TaskClass,
    /// Agent generation serialized into the BPF command.
    pub class_generation: u64,
    /// CPU whose normal or urgent lane was reserved.
    pub target_cpu: u32,
    /// Planned service held in `reserved_runtime_ns` until cancel or STOP.
    pub planned_slice_ns: u64,
    /// Task deadline selected inside its class pool.
    pub task_deadline_ns: u64,
    /// Root class deadline snapshot retained for scheduling diagnostics.
    pub pool_deadline_ns: u64,
    /// Userspace timestamp immediately before the command was queued to BPF.
    pub submitted_ns: u64,
    /// CPU wait predicted when the command was created.
    pub predicted_start_delay_ns: u64,
    /// Whether this reservation consumed latency service from the SLO budget.
    pub slo_admitted: bool,
    /// Victim and non-refundable disruption charge for an urgent command.
    pub preemption: Option<PreemptionReservation>,
    /// Submitted or running reservation phase.
    pub phase: ReservationPhase,
}

/// Cost reservation attached to one urgent dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreemptionReservation {
    pub victim: PreemptionVictim,
    pub charge_ns: u64,
}

/// Why a class was selected at the root scheduling level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchReason {
    Root,
    Rescue,
    SloOverride,
}

/// One latency request whose predicted completion would miss the local target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LatencyRisk {
    request_ns: u64,
    slack_ns: u64,
}

/// Mutable facts accumulated between two Agent behavior reports.
#[derive(Clone, Debug)]
struct BehaviorAccumulator {
    /// Task creation timestamp retained across window resets.
    created_ns: u64,
    /// Sequence assigned to the next non-empty report.
    next_window_sequence: u64,
    /// First timestamp represented by this window.
    window_start_ns: u64,
    /// Most recent event timestamp used to detect time reversal.
    last_event_ns: u64,
    /// Actual service accumulated from STOP.
    runtime_ns: u64,
    /// Runnable delay accumulated from RUNNING.
    runnable_wait_ns: u64,
    /// Time spent asleep after voluntary blocking.
    sleep_ns: u64,
    /// Accepted ENQUEUE count.
    enqueue_count: u64,
    /// ENQUEUE events following voluntary blocking.
    wakeup_count: u64,
    /// Matching RUNNING count.
    run_count: u64,
    /// Fixed runtime histogram.
    run_burst_histogram: [u64; 4],
    /// Fixed runnable-wait histogram.
    wait_histogram: [u64; 4],
    /// Stops that consumed nearly all of their assigned slice.
    slice_exhaustion_count: u64,
    /// Stops that entered a blocked state.
    voluntary_block_count: u64,
    /// Runs on a different CPU than the preceding run.
    migration_count: u64,
    /// Runs on the same CPU as the preceding run.
    previous_cpu_hit_count: u64,
    /// Set when sequence or timestamp continuity is not trustworthy.
    bad: bool,
}

impl BehaviorAccumulator {
    fn new(created_ns: u64) -> Self {
        Self {
            created_ns,
            next_window_sequence: 1,
            window_start_ns: 0,
            last_event_ns: 0,
            runtime_ns: 0,
            runnable_wait_ns: 0,
            sleep_ns: 0,
            enqueue_count: 0,
            wakeup_count: 0,
            run_count: 0,
            run_burst_histogram: [0; 4],
            wait_histogram: [0; 4],
            slice_exhaustion_count: 0,
            voluntary_block_count: 0,
            migration_count: 0,
            previous_cpu_hit_count: 0,
            bad: false,
        }
    }

    /// Records timestamp continuity and starts a new window on first activity.
    fn observe_timestamp(&mut self, timestamp_ns: u64) {
        if self.window_start_ns == 0 {
            self.window_start_ns = timestamp_ns;
        }
        if self.last_event_ns != 0 && timestamp_ns < self.last_event_ns {
            self.bad = true;
        }
        self.last_event_ns = self.last_event_ns.max(timestamp_ns);
    }

    /// Builds a report and resets counters for the next fixed period.
    fn take(
        &mut self,
        task: TaskKey,
        process: ProcessKey,
        window_end_ns: u64,
    ) -> Option<TaskBehaviorWindow> {
        if self.window_start_ns == 0
            || (self.enqueue_count == 0 && self.run_count == 0 && self.runtime_ns == 0)
        {
            return None;
        }
        if window_end_ns < self.last_event_ns {
            self.bad = true;
        }
        let window = TaskBehaviorWindow {
            task,
            process,
            window_sequence: self.next_window_sequence,
            window_start_ns: self.window_start_ns,
            window_end_ns,
            runtime_ns: self.runtime_ns,
            runnable_wait_ns: self.runnable_wait_ns,
            sleep_ns: self.sleep_ns,
            enqueue_count: self.enqueue_count,
            wakeup_count: self.wakeup_count,
            run_count: self.run_count,
            run_burst_histogram: self.run_burst_histogram,
            wait_histogram: self.wait_histogram,
            slice_exhaustion_count: self.slice_exhaustion_count,
            voluntary_block_count: self.voluntary_block_count,
            migration_count: self.migration_count,
            previous_cpu_hit_count: self.previous_cpu_hit_count,
            task_age_ns: window_end_ns.saturating_sub(self.created_ns),
            quality: if self.bad {
                WindowQuality::Bad
            } else {
                WindowQuality::Good
            },
        };
        *self = Self::new(self.created_ns);
        self.next_window_sequence = window.window_sequence.saturating_add(1);
        Some(window)
    }

    fn record_histogram(histogram: &mut [u64; 4], sample_ns: u64) {
        let index = BEHAVIOR_HISTOGRAM_BOUNDS_NS
            .iter()
            .position(|bound| sample_ns < *bound)
            .unwrap_or(3);
        histogram[index] = histogram[index].saturating_add(1);
    }
}

/// Non-blocking discovery or repair work for the scheduler control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineNotice {
    /// Agent should create or reconcile a process registry entry.
    ProcessDiscovered(ProcessKey),
    /// Agent should create or reconcile a task registry entry.
    TaskDiscovered {
        /// Stable task lifetime.
        task: TaskKey,
        /// Stable owning process image.
        process: ProcessKey,
    },
    /// One task entered a new process image generation through exec.
    ProcessExec {
        /// Surviving task lifetime.
        task: TaskKey,
        /// Process image invalidated by exec.
        previous_process: ProcessKey,
        /// Newly created process image generation.
        process: ProcessKey,
    },
    /// Cached affinity caused a BPF rejection and should be refreshed.
    RefreshAffinity(TaskKey),
    /// Stable task lifetime ended and Agent should delete its TaskRegistry row.
    TaskExited {
        /// Exited task lifetime.
        task: TaskKey,
        /// Process image that owned the task at exit.
        process: ProcessKey,
    },
    /// Final task of a process image exited and Agent should delete its process row.
    ProcessExited(ProcessKey),
}

/// Single-owner policy state machine driven by BPF and control events.
#[derive(Clone, Debug)]
pub struct SchedulerEngine {
    /// Validated immutable policy configuration.
    config: SchedulerConfig,
    /// Agent process-default cache.
    process_defaults: HashMap<ProcessKey, ProcessDefaultCache>,
    /// Agent effective task-class cache.
    task_classes: HashMap<TaskKey, TaskClassCache>,
    /// Runtime and locality state for active task lifetimes.
    tasks: HashMap<TaskKey, TaskState>,
    /// Reverse index used for process updates and lifecycle cleanup.
    tasks_by_process: HashMap<ProcessKey, HashSet<TaskKey>>,
    /// Three identical class-indexed EEVDF queues.
    pools: TaskPools,
    /// Root EEVDF treating each non-empty pool as one schedulable entity.
    root: RootEevdf,
    /// Bounded service available to latency work selected ahead of root EEVDF.
    latency_budget: TimeBudget,
    /// Disruption cost available to urgent preemption independently of service share.
    preemption_budget: TimeBudget,
    /// EWMA of command delivery overhead not explained by predicted CPU wait.
    dispatch_overhead_ns: u64,
    /// Dense per-CPU current and staged state.
    cpus: Vec<CpuState>,
    /// Static CPU/core/LLC relationships.
    topology: CpuTopology,
    /// Submitted and running reservations indexed by dispatch ID.
    reservations: HashMap<u64, Reservation>,
    /// Next non-zero dispatch identity.
    next_dispatch_id: u64,
    /// Monotonic scheduler diagnostics.
    stats: SchedulerStats,
    /// Per-task facts periodically drained by the Agent control connection.
    behavior: HashMap<TaskKey, BehaviorAccumulator>,
    /// A bounded-state invariant failed and continuing would be misleading.
    degraded: bool,
}

impl SchedulerEngine {
    /// Constructs an empty engine from validated configuration and topology.
    pub fn new(config: SchedulerConfig, topology: CpuTopology) -> Result<Self, EngineError> {
        config.validate()?;
        let online_cpus = topology.cpus().filter(|cpu| cpu.online).count();
        let latency_budget = TimeBudget::new(online_cpus, config.slice_for(TaskClass::Latency));
        let preemption_capacity_ns = config
            .slice_for(TaskClass::Throughput)
            .saturating_add(config.preemption_min_runtime_ns);
        let preemption_budget = TimeBudget::new(online_cpus, preemption_capacity_ns);
        let dispatch_overhead_ns = (config.poll_interval.as_nanos() as u64) / 2;
        let cpus = topology
            .cpus()
            .map(|cpu| CpuState::from_topology(cpu.online))
            .collect();

        Ok(Self {
            config,
            process_defaults: HashMap::new(),
            task_classes: HashMap::new(),
            tasks: HashMap::new(),
            tasks_by_process: HashMap::new(),
            pools: TaskPools::default(),
            root: RootEevdf::default(),
            latency_budget,
            preemption_budget,
            dispatch_overhead_ns,
            cpus,
            topology,
            reservations: HashMap::new(),
            next_dispatch_id: 1,
            stats: SchedulerStats::default(),
            behavior: HashMap::new(),
            degraded: false,
        })
    }

    /// Returns immutable counters for status reporting.
    pub fn stats(&self) -> &SchedulerStats {
        &self.stats
    }

    /// Returns one task state for diagnostics or control-plane validation.
    pub fn task(&self, task: TaskKey) -> Option<&TaskState> {
        self.tasks.get(&task)
    }

    /// Returns one effective task-class cache entry.
    pub fn task_class(&self, task: TaskKey) -> Option<&TaskClassCache> {
        self.task_classes.get(&task)
    }

    /// Returns one process-default cache entry.
    pub fn process_default(&self, process: ProcessKey) -> Option<&ProcessDefaultCache> {
        self.process_defaults.get(&process)
    }

    /// Returns dense CPU state for bounded-lane invariant inspection.
    pub fn cpus(&self) -> &[CpuState] {
        &self.cpus
    }

    /// Returns the number of reservations still awaiting STOP or cancellation.
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Returns the number of live task records for capacity and Tool reporting.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Returns physical pool entries, including lazily invalidated nodes.
    pub fn pool_node_count(&self) -> usize {
        self.pools.node_count()
    }

    /// Returns true when an invariant requires the scheduler to detach.
    pub const fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Replays all live identities after a new Agent connection completes Hello.
    pub fn lifecycle_notices(&self) -> Vec<EngineNotice> {
        let mut processes: Vec<_> = self.process_defaults.keys().copied().collect();
        processes.sort_unstable();
        let mut tasks: Vec<_> = self
            .tasks
            .values()
            .map(|state| (state.identity, state.process))
            .collect();
        tasks.sort_unstable();
        processes
            .into_iter()
            .map(EngineNotice::ProcessDiscovered)
            .chain(
                tasks
                    .into_iter()
                    .map(|(task, process)| EngineNotice::TaskDiscovered { task, process }),
            )
            .collect()
    }

    /// Returns task generations that must be reset in BPF before a new baseline.
    pub fn task_controls(&self) -> Vec<(TaskKey, TaskClassCache)> {
        let mut controls: Vec<_> = self
            .task_classes
            .iter()
            .map(|(task, cache)| (*task, *cache))
            .collect();
        controls.sort_unstable_by_key(|(task, _)| *task);
        controls
    }

    /// Resets all Agent-owned classifications while preserving lifecycle state.
    pub fn reset_classifications(&mut self, now_ns: u64) {
        for process in self.process_defaults.values_mut() {
            *process = ProcessDefaultCache::default();
        }
        for cache in self.task_classes.values_mut() {
            let process = cache.process;
            *cache = TaskClassCache::inherited(process, ProcessDefaultCache::default());
        }
        for (task, state) in &mut self.tasks {
            if state.run_state == RunState::KernelManaged {
                state.run_state = RunState::Blocked;
                state.enqueue_sequence = 0;
                state.active_dispatch_id = None;
                state.assigned_slice_ns = 0;
                state.request_remaining_ns = 0;
                state.request_deadline_ns = 0;
                state.preemption_guard = PreemptionGuard::None;
                self.behavior
                    .insert(*task, BehaviorAccumulator::new(now_ns));
            }
        }
        self.rebuild_pools();
    }

    /// Restores one process baseline; unlike an increment, non-zero starts are valid.
    pub fn restore_process_class(
        &mut self,
        process: ProcessKey,
        class: TaskClass,
        class_generation: u64,
    ) -> Result<Vec<TaskKey>, EngineError> {
        let Some(default) = self.process_defaults.get_mut(&process) else {
            return Err(EngineError::UnknownProcess(process));
        };
        *default = ProcessDefaultCache {
            default_class: class,
            class_generation,
        };
        let affected = self.inherited_tasks(process);
        for task in &affected {
            if let Some(cache) = self.task_classes.get_mut(task) {
                cache.effective_class = class;
                cache.class_generation = class_generation;
            }
            self.push_task_node(*task);
        }
        Ok(affected)
    }

    /// Restores one semantic/locked task baseline after a scheduler restart.
    pub fn restore_task_class(
        &mut self,
        task: TaskKey,
        process: ProcessKey,
        class: TaskClass,
        stage: ClassStage,
        class_generation: u64,
    ) -> Result<(), EngineError> {
        if stage == ClassStage::Inherited {
            return Err(EngineError::InvalidSnapshotStage(task));
        }
        let cache = self
            .task_classes
            .get_mut(&task)
            .ok_or(EngineError::UnknownTask(task))?;
        if cache.process != process {
            return Err(EngineError::ClassUpdate(
                ClassUpdateError::ProcessIdentity { task },
            ));
        }
        *cache = TaskClassCache {
            process,
            effective_class: class,
            stage,
            class_generation,
        };
        if stage == ClassStage::Locked {
            self.quiesce_task_observation(task);
        } else {
            self.push_task_node(task);
        }
        Ok(())
    }

    /// Drains non-empty behavior accumulators into one fixed-period report batch.
    pub fn take_behavior_windows(&mut self, now_ns: u64) -> Vec<TaskBehaviorWindow> {
        let identities: Vec<_> = self
            .behavior
            .keys()
            .filter_map(|task| self.tasks.get(task).map(|state| (*task, state.process)))
            .collect();
        let mut windows = Vec::new();
        for (task, process) in identities {
            if let Some(window) = self
                .behavior
                .get_mut(&task)
                .and_then(|accumulator| accumulator.take(task, process, now_ns))
            {
                if window.quality == WindowQuality::Bad {
                    self.stats.bad_behavior_windows =
                        self.stats.bad_behavior_windows.saturating_add(1);
                }
                windows.push(window);
            }
        }
        windows
    }

    /// Marks every current behavior accumulator unusable after a BPF event overflow.
    pub fn mark_behavior_gap(&mut self) {
        for accumulator in self.behavior.values_mut() {
            accumulator.bad = true;
        }
    }

    /// Applies one validated kernel event and returns asynchronous Agent notices.
    pub fn handle_event(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        self.stats.events_processed = self.stats.events_processed.saturating_add(1);
        if event.bpf_scheduled()
            && matches!(
                event.kind,
                EventKind::Enqueue | EventKind::Cancel | EventKind::Running | EventKind::Stop
            )
            && event.task.is_some_and(|task| {
                self.task_classes
                    .get(&task)
                    .is_some_and(|cache| cache.stage == ClassStage::Locked)
            })
        {
            return Vec::new();
        }
        match event.kind {
            EventKind::Init => self.handle_init(event),
            EventKind::Exec => self.handle_exec(event),
            EventKind::Enqueue => self.handle_enqueue(event),
            EventKind::Cancel => self.handle_cancel(event),
            EventKind::Running => self.handle_running(event),
            EventKind::Stop => self.handle_stop(event),
            EventKind::Exit => self.handle_exit(event),
            EventKind::CpuState => self.handle_cpu_state(event),
            EventKind::CommandReject => self.handle_reject(event),
        }
    }

    /// Produces a bounded set of hierarchical EEVDF dispatch requests.
    ///
    /// Planned service participates immediately in both EEVDF levels, preventing
    /// one refill pass from reserving every CPU for the same task or class.
    pub fn refill(&mut self, now_ns: u64) -> Vec<DispatchRequest> {
        let mut commands = Vec::new();
        let mut unavailable = [false; 3];
        let mut budget_denial_recorded = false;
        let requests_ns = self.class_requests();
        self.latency_budget.refresh(
            now_ns,
            self.cpus.iter().filter(|cpu| cpu.online).count(),
            self.config.latency_guarantee_percent,
        );
        self.preemption_budget.refresh(
            now_ns,
            self.cpus.iter().filter(|cpu| cpu.online).count(),
            self.config.preemption_budget_percent,
        );

        while commands.len() < self.config.dispatch_batch_limit {
            let active = TaskClass::all().map(|class| !self.pools.is_empty(class));
            let available =
                TaskClass::all().map(|class| active[class.index()] && !unavailable[class.index()]);
            if !available.into_iter().any(|value| value) {
                break;
            }

            self.root.update_activity(active, requests_ns);
            let Some(root_decision) = self.root.select(available, requests_ns) else {
                break;
            };
            let latency_risk = self.latency_risk(available, now_ns);
            let slo_override = root_decision.class != TaskClass::Latency
                && latency_risk.is_some_and(|risk| {
                    if self.latency_budget.can_reserve(risk.request_ns) {
                        true
                    } else {
                        if !budget_denial_recorded {
                            self.stats.latency_budget_denials =
                                self.stats.latency_budget_denials.saturating_add(1);
                            budget_denial_recorded = true;
                        }
                        false
                    }
                });
            let rescue_class = (!slo_override)
                .then(|| self.select_rescue_class(available, now_ns))
                .flatten();
            let (decision, reason) = if slo_override {
                (
                    RootDecision {
                        class: TaskClass::Latency,
                        deadline_ns: self
                            .root
                            .deadline(TaskClass::Latency, requests_ns[TaskClass::Latency.index()]),
                    },
                    DispatchReason::SloOverride,
                )
            } else if let Some(class) = rescue_class {
                (
                    RootDecision {
                        class,
                        deadline_ns: self.root.deadline(class, requests_ns[class.index()]),
                    },
                    DispatchReason::Rescue,
                )
            } else {
                (root_decision, DispatchReason::Root)
            };
            let class = decision.class;
            let urgency = (class == TaskClass::Latency)
                .then_some(latency_risk)
                .flatten();

            let oldest_first = urgency.is_some() || reason == DispatchReason::Rescue;
            let Some((node, placement)) =
                self.take_placeable_node(class, oldest_first, urgency, now_ns)
            else {
                unavailable[class.index()] = true;
                continue;
            };

            let Some(command) =
                self.reserve_node(node, placement, decision.deadline_ns, reason, now_ns)
            else {
                unavailable[class.index()] = true;
                continue;
            };
            commands.push(command);
        }

        commands
    }

    fn class_requests(&self) -> [u64; 3] {
        TaskClass::all().map(|class| self.config.slice_for(class))
    }

    /// Detects a latency request that cannot complete within the local target.
    fn latency_risk(&mut self, available: [bool; 3], now_ns: u64) -> Option<LatencyRisk> {
        if !available[TaskClass::Latency.index()] {
            return None;
        }
        let node = self.oldest_valid_node(TaskClass::Latency)?;
        let waited_ns = now_ns.saturating_sub(node.enqueue_time_ns);
        let fixed_delay_ns = waited_ns
            .saturating_add(self.dispatch_overhead_ns)
            .saturating_add(node.request_ns);
        let slack_ns = self.config.latency_target_ns.saturating_sub(fixed_delay_ns);
        let affinity = self.tasks.get(&node.task).map(|state| &state.affinity)?;
        let best_normal_delay_ns = self
            .cpus
            .iter()
            .enumerate()
            .filter(|(cpu, state)| {
                state.is_fillable() && state.urgent_dispatch.is_none() && affinity.contains(*cpu)
            })
            .filter_map(|(cpu, _)| {
                predicted_completion_delay(
                    TaskClass::Latency,
                    node.request_ns,
                    cpu as u32,
                    &self.cpus,
                    &self.topology,
                    now_ns,
                )
            })
            .min()
            .unwrap_or(u64::MAX);
        if fixed_delay_ns <= self.config.latency_target_ns && best_normal_delay_ns <= slack_ns {
            return None;
        }
        Some(LatencyRisk {
            request_ns: node.request_ns,
            slack_ns,
        })
    }

    /// Rolls back a request that userspace could not push into the BPF queue.
    pub fn command_submission_failed(&mut self, dispatch_id: u64) {
        self.stats.command_queue_full = self.stats.command_queue_full.saturating_add(1);
        self.rollback_reservation(dispatch_id, true);
    }

    /// Refreshes the scheduler's affinity hint after BPF reports a mismatch.
    pub fn refresh_affinity(&mut self, task: TaskKey) -> Result<(), EngineError> {
        let state = self
            .tasks
            .get_mut(&task)
            .ok_or(EngineError::UnknownTask(task))?;
        state.affinity = read_task_affinity(task.tid, self.topology.cpu_count())
            .unwrap_or_else(|_| CpuMask::all(self.topology.cpu_count()));
        Self::clear_invalid_home(state, &self.cpus);
        Ok(())
    }

    /// Replaces one cached affinity hint after an external reconciliation.
    ///
    /// This is also the deterministic unit-test entry point; BPF remains the
    /// final authority and validates `p->cpus_ptr` for every command.
    pub fn set_cached_affinity(
        &mut self,
        task: TaskKey,
        affinity: CpuMask,
    ) -> Result<(), EngineError> {
        if affinity.cpu_count() != self.topology.cpu_count() {
            return Err(EngineError::AffinityWidth {
                expected: self.topology.cpu_count(),
                received: affinity.cpu_count(),
            });
        }
        let state = self
            .tasks
            .get_mut(&task)
            .ok_or(EngineError::UnknownTask(task))?;
        state.affinity = affinity;
        Self::clear_invalid_home(state, &self.cpus);
        Ok(())
    }

    /// Applies a process default after the control layer mirrored all affected
    /// task generations into BPF. Queued tasks get new lazy pool nodes.
    pub fn apply_process_class_update(
        &mut self,
        update: ProcessClassUpdate,
    ) -> Result<Vec<TaskKey>, EngineError> {
        if let Some(current) = self.process_defaults.get(&update.process) {
            if update.class_generation <= current.class_generation {
                return Err(EngineError::StaleProcessGeneration {
                    process: update.process,
                    current: current.class_generation,
                    received: update.class_generation,
                });
            }
        }

        let affected: Vec<_> = self
            .tasks_by_process
            .get(&update.process)
            .into_iter()
            .flatten()
            .copied()
            .filter(|task| {
                self.task_classes
                    .get(task)
                    .is_some_and(|cache| cache.stage == ClassStage::Inherited)
            })
            .collect();

        self.process_defaults.insert(
            update.process,
            ProcessDefaultCache {
                default_class: update.class,
                class_generation: update.class_generation,
            },
        );

        for task in &affected {
            if let Some(cache) = self.task_classes.get_mut(task) {
                cache.effective_class = update.class;
                cache.class_generation = update.class_generation;
            }
            if self
                .tasks
                .get(task)
                .is_some_and(|state| state.run_state == RunState::Queued)
            {
                self.push_task_node(*task);
            }
        }
        Ok(affected)
    }

    /// Applies a task semantic/locked update after BPF task_control succeeds.
    pub fn apply_task_class_update(&mut self, update: TaskClassUpdate) -> Result<(), EngineError> {
        let locked = {
            let cache = self
                .task_classes
                .get_mut(&update.task)
                .ok_or(EngineError::UnknownTask(update.task))?;
            cache.apply(update.task, update)?;
            cache.stage == ClassStage::Locked
        };
        if locked {
            self.quiesce_task_observation(update.task);
        } else if self
            .tasks
            .get(&update.task)
            .is_some_and(|state| state.run_state == RunState::Queued)
        {
            self.push_task_node(update.task);
        }
        Ok(())
    }

    /// Stops mirroring runtime state once Agent classification is permanent.
    fn quiesce_task_observation(&mut self, task: TaskKey) {
        self.cancel_task(task, false);
        for cpu in &mut self.cpus {
            if cpu.current_task == Some(task) {
                cpu.current_task = None;
                cpu.current_class = None;
                cpu.current_started_ns = 0;
                cpu.current_slice_ns = 0;
            }
        }
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::KernelManaged;
            state.active_dispatch_id = None;
            state.assigned_slice_ns = 0;
            state.request_remaining_ns = 0;
            state.request_deadline_ns = 0;
            state.was_preempted = false;
            state.preemption_guard = PreemptionGuard::None;
        }
        self.behavior.remove(&task);
    }

    /// Returns inherited tasks whose BPF generations must be updated atomically
    /// before committing a process-default change in this engine.
    pub fn inherited_tasks(&self, process: ProcessKey) -> Vec<TaskKey> {
        self.tasks_by_process
            .get(&process)
            .into_iter()
            .flatten()
            .copied()
            .filter(|task| {
                self.task_classes
                    .get(task)
                    .is_some_and(|cache| cache.stage == ClassStage::Inherited)
            })
            .collect()
    }

    /// Creates missing process/task caches and returns discovery notices.
    fn discover_task(
        &mut self,
        task: TaskKey,
        process: ProcessKey,
        timestamp_ns: u64,
    ) -> Vec<EngineNotice> {
        if self.tasks.contains_key(&task) {
            return Vec::new();
        }
        if self.tasks.len() >= self.config.max_tasks {
            self.stats.task_capacity_hits = self.stats.task_capacity_hits.saturating_add(1);
            self.mark_degraded();
            return Vec::new();
        }

        let mut notices = Vec::new();
        let is_new_process = !self.process_defaults.contains_key(&process);
        let process_default = *self.process_defaults.entry(process).or_default();
        let affinity = read_task_affinity(task.tid, self.topology.cpu_count())
            .unwrap_or_else(|_| CpuMask::all(self.topology.cpu_count()));

        self.tasks
            .insert(task, TaskState::new(task, process, affinity));
        self.behavior
            .insert(task, BehaviorAccumulator::new(timestamp_ns));
        self.task_classes
            .insert(task, TaskClassCache::inherited(process, process_default));
        self.tasks_by_process
            .entry(process)
            .or_default()
            .insert(task);

        if is_new_process {
            notices.push(EngineNotice::ProcessDiscovered(process));
        }
        notices.push(EngineNotice::TaskDiscovered { task, process });
        notices
    }

    /// Handles initial task discovery without changing runnable state.
    fn handle_init(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        match (event.task, event.process) {
            (Some(task), Some(process)) => self.discover_task(task, process, event.timestamp_ns),
            _ => {
                self.record_stale_event();
                Vec::new()
            }
        }
    }

    /// Moves an existing task to a new exec generation and resets classification.
    fn handle_exec(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let (Some(task), Some(process)) = (event.task, event.process) else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self.tasks.contains_key(&task) {
            return self.discover_task(task, process, event.timestamp_ns);
        }

        self.cancel_task(task, false);
        let Some(previous_process) = self.tasks.get(&task).map(|state| state.process) else {
            self.record_stale_event();
            return Vec::new();
        };
        self.remove_process_member(previous_process, task);

        let process_default = *self.process_defaults.entry(process).or_default();
        if let Some(state) = self.tasks.get_mut(&task) {
            let affinity = state.affinity.clone();
            *state = TaskState::new(task, process, affinity);
        }
        self.behavior
            .insert(task, BehaviorAccumulator::new(event.timestamp_ns));
        self.task_classes
            .insert(task, TaskClassCache::inherited(process, process_default));
        self.tasks_by_process
            .entry(process)
            .or_default()
            .insert(task);

        vec![EngineNotice::ProcessExec {
            task,
            previous_process,
            process,
        }]
    }

    /// Accepts a strictly newer runnable generation and inserts one pool node.
    fn handle_enqueue(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let (Some(task), Some(process)) = (event.task, event.process) else {
            self.record_stale_event();
            return Vec::new();
        };
        let mut notices = self.discover_task(task, process, event.timestamp_ns);
        if self
            .tasks
            .get(&task)
            .is_some_and(|state| state.process != process)
        {
            notices.extend(self.handle_exec(KernelEvent {
                kind: EventKind::Exec,
                ..event
            }));
        }

        let stale = self.tasks.get(&task).is_none_or(|state| {
            event.enqueue_sequence == 0 || event.enqueue_sequence <= state.enqueue_sequence
        });
        if stale {
            self.record_stale_event();
            return notices;
        }

        let previous_sequence = self
            .tasks
            .get(&task)
            .map(|state| state.enqueue_sequence)
            .unwrap_or(0);
        if let Some(accumulator) = self.behavior.get_mut(&task) {
            accumulator.observe_timestamp(event.timestamp_ns);
            accumulator.enqueue_count = accumulator.enqueue_count.saturating_add(1);
            if event.was_wakeup() {
                accumulator.wakeup_count = accumulator.wakeup_count.saturating_add(1);
                accumulator.sleep_ns = accumulator.sleep_ns.saturating_add(event.sleep_ns);
            }
            if !event.bpf_scheduled()
                && previous_sequence != 0
                && event.enqueue_sequence > previous_sequence.saturating_add(1)
            {
                accumulator.bad = true;
            }
        }

        self.cancel_task(task, false);
        let bpf_scheduled = event.bpf_scheduled();
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = if bpf_scheduled {
                RunState::KernelQueued
            } else {
                RunState::Queued
            };
            state.enqueue_sequence = event.enqueue_sequence;
            state.enqueue_time_ns = event.timestamp_ns;
            state.previous_cpu = event.previous_cpu.or(state.previous_cpu);
            state.active_dispatch_id = None;
        }

        if !bpf_scheduled {
            self.push_task_node(task);
        }
        notices
    }

    /// Cancels a matching queued or submitted runnable generation.
    fn handle_cancel(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(task) = event.task else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self
            .tasks
            .get(&task)
            .is_some_and(|state| state.enqueue_sequence == event.enqueue_sequence)
        {
            self.record_stale_event();
            return Vec::new();
        }
        self.cancel_task(task, false);
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Blocked;
            state.request_remaining_ns = 0;
            state.request_deadline_ns = 0;
            state.was_preempted = false;
        }
        Vec::new()
    }

    /// Confirms actual execution, releases the staging slot, and keeps reservation service.
    fn handle_running(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let (Some(task), Some(actual_cpu)) = (event.task, event.actual_cpu) else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self.tasks.contains_key(&task) {
            let Some(process) = event.process else {
                self.record_stale_event();
                return Vec::new();
            };
            self.discover_task(task, process, event.timestamp_ns);
        }

        let mut running_class = self
            .task_classes
            .get(&task)
            .map(|cache| cache.effective_class)
            .unwrap_or(TaskClass::Balanced);
        let mut planned_slice = self.config.slice_for(running_class);
        if event.dispatch_id != 0 {
            let (slot_to_release, dispatch_overhead_ns) = {
                let Some(reservation) = self.reservations.get_mut(&event.dispatch_id) else {
                    self.record_stale_event();
                    return Vec::new();
                };
                if reservation.task != task
                    || reservation.enqueue_sequence != event.enqueue_sequence
                    || reservation.phase != ReservationPhase::Submitted
                {
                    self.record_stale_event();
                    return Vec::new();
                }
                reservation.phase = ReservationPhase::Running;
                planned_slice = reservation.planned_slice_ns;
                running_class = reservation.class;
                let observed_ns = event
                    .timestamp_ns
                    .saturating_sub(reservation.submitted_ns)
                    .saturating_sub(reservation.predicted_start_delay_ns)
                    .min(self.config.latency_target_ns);
                (
                    (reservation.target_cpu, reservation.dispatch_id),
                    observed_ns,
                )
            };
            self.release_cpu_slot(slot_to_release.0, slot_to_release.1);
            self.dispatch_overhead_ns = self
                .dispatch_overhead_ns
                .saturating_mul(7)
                .saturating_add(dispatch_overhead_ns)
                / 8;
            self.stats.record_dispatch_overhead(dispatch_overhead_ns);
        } else if event.bpf_scheduled() {
            planned_slice = event.runtime_ns.clamp(
                self.config.min_slice_ns,
                self.config.slice_for(running_class),
            );
        }

        let (previous_actual_cpu, enqueue_time_ns, sequence_matches) = self
            .tasks
            .get(&task)
            .map(|state| {
                (
                    state.previous_cpu,
                    state.enqueue_time_ns,
                    state.enqueue_sequence == event.enqueue_sequence,
                )
            })
            .unwrap_or((None, 0, false));
        if let Some(cpu) = self.cpus.get_mut(actual_cpu as usize) {
            cpu.idle = false;
            cpu.current_task = Some(task);
            cpu.current_class = Some(running_class);
            cpu.current_started_ns = event.timestamp_ns;
            cpu.current_slice_ns = planned_slice;
        }
        let actual_llc = self.topology.cpu(actual_cpu).map(|cpu| cpu.llc_id);
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Running;
            state.active_dispatch_id = (event.dispatch_id != 0).then_some(event.dispatch_id);
            state.previous_cpu = Some(actual_cpu);
            state.last_start_ns = event.timestamp_ns;
            state.assigned_slice_ns = planned_slice;
            let interrupted = state.was_preempted;
            state.was_preempted = false;
            if !interrupted {
                Self::update_home(state, running_class, actual_cpu, actual_llc);
            }
        }
        if let Some(accumulator) = self.behavior.get_mut(&task) {
            accumulator.observe_timestamp(event.timestamp_ns);
            accumulator.run_count = accumulator.run_count.saturating_add(1);
            if enqueue_time_ns == 0 || !sequence_matches || event.timestamp_ns < enqueue_time_ns {
                accumulator.bad = true;
            }
            let wait_ns = event.timestamp_ns.saturating_sub(enqueue_time_ns);
            accumulator.runnable_wait_ns = accumulator.runnable_wait_ns.saturating_add(wait_ns);
            BehaviorAccumulator::record_histogram(&mut accumulator.wait_histogram, wait_ns);
            if previous_actual_cpu == Some(actual_cpu) {
                accumulator.previous_cpu_hit_count =
                    accumulator.previous_cpu_hit_count.saturating_add(1);
            } else if previous_actual_cpu.is_some() {
                accumulator.migration_count = accumulator.migration_count.saturating_add(1);
            }
        }
        Vec::new()
    }

    /// Charges actual runtime, clears CPU current state, and blocks the task.
    fn handle_stop(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(task) = event.task else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self.tasks.contains_key(&task) {
            self.record_stale_event();
            return Vec::new();
        }

        let (was_running, assigned_slice_ns) = self
            .tasks
            .get(&task)
            .map(|state| {
                (
                    state.run_state == RunState::Running,
                    state.assigned_slice_ns,
                )
            })
            .unwrap_or((false, 0));
        let reservation = (event.dispatch_id != 0)
            .then(|| self.reservations.remove(&event.dispatch_id))
            .flatten();
        let class = reservation
            .as_ref()
            .map(|item| item.class)
            .or_else(|| {
                self.task_classes
                    .get(&task)
                    .map(|cache| cache.effective_class)
            })
            .unwrap_or(TaskClass::Balanced);
        let mut reservation_deadline_ns = None;
        if let Some(reservation) = reservation.as_ref() {
            if reservation.task == task {
                reservation_deadline_ns = Some(reservation.task_deadline_ns);
                self.root.complete(
                    reservation.class,
                    reservation.planned_slice_ns,
                    event.runtime_ns,
                );
                if reservation.slo_admitted {
                    self.latency_budget
                        .complete(reservation.planned_slice_ns, event.runtime_ns);
                }
            } else {
                self.root
                    .cancel(reservation.class, reservation.planned_slice_ns);
                if reservation.slo_admitted {
                    self.latency_budget.cancel(reservation.planned_slice_ns);
                }
                self.stats.stale_events = self.stats.stale_events.saturating_add(1);
            }
        }

        if let Some(actual_cpu) = event.actual_cpu {
            if let Some(cpu) = self.cpus.get_mut(actual_cpu as usize) {
                if cpu.current_task == Some(task) {
                    cpu.current_task = None;
                    cpu.current_class = None;
                    cpu.current_started_ns = 0;
                    cpu.current_slice_ns = 0;
                }
            }
        }

        let interrupted_request = event.remained_runnable()
            && assigned_slice_ns != 0
            && event.runtime_ns < assigned_slice_ns.saturating_mul(9) / 10;
        let request_remaining_ns = assigned_slice_ns.saturating_sub(event.runtime_ns);
        let resumable_request =
            interrupted_request && request_remaining_ns >= self.config.min_slice_ns;
        let mut request_resumed = false;
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Blocked;
            state.active_dispatch_id = None;
            state.assigned_slice_ns = 0;
            state.vruntime_ns = state.vruntime_ns.saturating_add(event.runtime_ns);
            state.preemption_guard = match state.preemption_guard {
                PreemptionGuard::AwaitingStop if event.remained_runnable() => {
                    PreemptionGuard::Recovering
                }
                PreemptionGuard::Recovering
                    if event.remained_runnable()
                        && event.runtime_ns < self.config.preemption_min_runtime_ns =>
                {
                    PreemptionGuard::Recovering
                }
                _ => PreemptionGuard::None,
            };
            if resumable_request {
                state.request_remaining_ns = request_remaining_ns;
                state.request_deadline_ns = reservation_deadline_ns
                    .filter(|deadline| *deadline != 0)
                    .unwrap_or_else(|| {
                        state
                            .request_deadline_ns
                            .max(state.vruntime_ns.saturating_add(state.request_remaining_ns))
                    });
                state.was_preempted = true;
                request_resumed = state.request_remaining_ns != 0;
            } else {
                state.request_remaining_ns = 0;
                state.request_deadline_ns = 0;
                state.was_preempted = false;
                if !interrupted_request && event.runtime_ns != 0 {
                    let sample_ns = event
                        .runtime_ns
                        .clamp(self.config.min_slice_ns, self.config.slice_for(class));
                    state.service_estimate_ns = if state.service_estimate_ns == 0 {
                        sample_ns
                    } else {
                        state
                            .service_estimate_ns
                            .saturating_mul(7)
                            .saturating_add(sample_ns)
                            / 8
                    };
                }
            }
        }
        if request_resumed {
            self.stats.request_resumptions = self.stats.request_resumptions.saturating_add(1);
        }
        if let Some(accumulator) = self.behavior.get_mut(&task) {
            accumulator.observe_timestamp(event.timestamp_ns);
            if !was_running {
                accumulator.bad = true;
            }
            accumulator.runtime_ns = accumulator.runtime_ns.saturating_add(event.runtime_ns);
            BehaviorAccumulator::record_histogram(
                &mut accumulator.run_burst_histogram,
                event.runtime_ns,
            );
            if event.remained_runnable()
                && assigned_slice_ns != 0
                && event.runtime_ns >= assigned_slice_ns.saturating_mul(9) / 10
            {
                accumulator.slice_exhaustion_count =
                    accumulator.slice_exhaustion_count.saturating_add(1);
            } else if !event.remained_runnable() {
                accumulator.voluntary_block_count =
                    accumulator.voluntary_block_count.saturating_add(1);
            }
        }
        self.stats.record_runtime(class, event.runtime_ns);
        Vec::new()
    }

    /// Removes all scheduler state for one stable task lifetime.
    fn handle_exit(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(task) = event.task else {
            self.record_stale_event();
            return Vec::new();
        };
        self.cancel_task(task, false);
        let mut notices = Vec::new();
        if let Some(mut state) = self.tasks.remove(&task) {
            state.run_state = RunState::Exited;
            let process = state.process;
            let process_exited = self.remove_process_member(process, task);
            notices.push(EngineNotice::TaskExited { task, process });
            if process_exited {
                notices.push(EngineNotice::ProcessExited(process));
            }
        }
        self.task_classes.remove(&task);
        self.behavior.remove(&task);
        notices
    }

    /// Updates online/idle state and requeues submitted work from an offline CPU.
    fn handle_cpu_state(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(cpu_id) = event.actual_cpu else {
            self.record_stale_event();
            return Vec::new();
        };
        let Some(cpu) = self.cpus.get_mut(cpu_id as usize) else {
            self.record_stale_event();
            return Vec::new();
        };
        cpu.online = event.cpu_online();
        cpu.idle = event.cpu_idle();

        if !cpu.online {
            let reservations: Vec<_> = self
                .reservations
                .values()
                .filter(|reservation| {
                    reservation.target_cpu == cpu_id
                        && reservation.phase == ReservationPhase::Submitted
                })
                .map(|reservation| reservation.dispatch_id)
                .collect();
            for dispatch_id in reservations {
                self.rollback_reservation(dispatch_id, true);
            }
        }
        Vec::new()
    }

    /// Rolls a rejected command back into its current effective class pool.
    fn handle_reject(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        self.stats.command_rejects = self.stats.command_rejects.saturating_add(1);
        let reason = event.reject_reason();
        let reason_index = reason.counter_index();
        self.stats.command_rejects_by_reason[reason_index] =
            self.stats.command_rejects_by_reason[reason_index].saturating_add(1);
        let task = self
            .reservations
            .get(&event.dispatch_id)
            .map(|reservation| reservation.task)
            .or(event.task);
        let repair_slice = reason == RejectReason::Slice;
        if repair_slice {
            if let Some(state) = task.and_then(|task| self.tasks.get_mut(&task)) {
                state.request_remaining_ns = 0;
                state.request_deadline_ns = 0;
            }
        }
        self.rollback_reservation(event.dispatch_id, reason.is_retryable() || repair_slice);
        if reason == RejectReason::Affinity {
            if let Some(task) = task {
                return vec![EngineNotice::RefreshAffinity(task)];
            }
        }
        Vec::new()
    }

    /// Inserts a fresh lazy-invalidation node for a currently queued task.
    fn push_task_node(&mut self, task: TaskKey) {
        let Some(node) = self.pool_node(task) else {
            return;
        };
        let required = Self::pool_node_weight(node.class);
        if self.pools.node_count().saturating_add(required) > self.config.max_pool_nodes {
            self.stats.pool_compactions = self.stats.pool_compactions.saturating_add(1);
            self.rebuild_pools();
            return;
        }
        self.pools.push(node);
    }

    /// Constructs one current token, preserving unfinished EEVDF request service.
    fn pool_node(&mut self, task: TaskKey) -> Option<PoolNode> {
        let cache = *self.task_classes.get(&task)?;
        let state = self.tasks.get(&task)?;
        if state.run_state != RunState::Queued || state.process != cache.process {
            return None;
        }
        let (
            enqueue_sequence,
            enqueue_time_ns,
            current_class,
            current_vruntime_ns,
            request_remaining_ns,
            request_deadline_ns,
            service_estimate_ns,
        ) = (
            state.enqueue_sequence,
            state.enqueue_time_ns,
            state.eevdf_class,
            state.vruntime_ns,
            state.request_remaining_ns,
            state.request_deadline_ns,
            state.service_estimate_ns,
        );
        let target_class = cache.effective_class;
        let new_request_ns = self
            .config
            .request_for_estimate(target_class, service_estimate_ns);
        let (vruntime_ns, request_ns, deadline_ns) = if current_class != target_class {
            let source_request_ns = if request_remaining_ns == 0 {
                self.config.slice_for(current_class)
            } else {
                request_remaining_ns
                    .max(self.config.min_request_for(current_class))
                    .min(self.config.slice_for(current_class))
            };
            let vruntime_ns = self.pools.rebase_vruntime(
                current_class,
                target_class,
                current_vruntime_ns,
                source_request_ns,
                new_request_ns,
            );
            (
                vruntime_ns,
                new_request_ns,
                vruntime_ns.saturating_add(new_request_ns),
            )
        } else if request_remaining_ns != 0 {
            let deadline_ns = if request_deadline_ns == 0 {
                current_vruntime_ns.saturating_add(request_remaining_ns)
            } else {
                request_deadline_ns
            };
            (current_vruntime_ns, request_remaining_ns, deadline_ns)
        } else {
            let vruntime_ns =
                self.pools
                    .place_vruntime(target_class, current_vruntime_ns, new_request_ns);
            (
                vruntime_ns,
                new_request_ns,
                vruntime_ns.saturating_add(new_request_ns),
            )
        };
        if let Some(state) = self.tasks.get_mut(&task) {
            state.vruntime_ns = vruntime_ns;
            state.eevdf_class = target_class;
            state.request_remaining_ns = request_ns;
            state.request_deadline_ns = deadline_ns;
        }

        Some(PoolNode {
            task,
            enqueue_sequence,
            class_generation: cache.class_generation,
            class: target_class,
            enqueue_time_ns,
            vruntime_ns,
            request_ns,
            deadline_ns,
        })
    }

    const fn pool_node_weight(_class: TaskClass) -> usize {
        2
    }

    /// Removes stale lazy nodes and recreates one current node per queued task.
    fn rebuild_pools(&mut self) {
        let mut tasks: Vec<_> = self.tasks.keys().copied().collect();
        tasks.sort_unstable();
        let mut nodes = Vec::new();
        for task in tasks {
            if let Some(node) = self.pool_node(task) {
                nodes.push(node);
            }
        }
        self.pools.clear();
        for node in nodes {
            self.pools.push(node);
        }
        if self.pools.node_count() > self.config.max_pool_nodes {
            self.mark_degraded();
        }
    }

    /// Checks every lazy-invalidation field before a node may be dispatched.
    fn node_is_valid(&self, node: PoolNode) -> bool {
        let Some(state) = self.tasks.get(&node.task) else {
            return false;
        };
        let Some(cache) = self.task_classes.get(&node.task) else {
            return false;
        };
        state.run_state == RunState::Queued
            && state.enqueue_sequence == node.enqueue_sequence
            && cache.class_generation == node.class_generation
            && cache.effective_class == node.class
            && state.process == cache.process
    }

    /// Cleans stale wait-index heads and returns one valid oldest node.
    fn oldest_valid_node(&mut self, class: TaskClass) -> Option<PoolNode> {
        loop {
            let node = self.pools.peek_oldest(class)?;
            if self.node_is_valid(node) {
                return Some(node);
            }
            self.pools.pop_oldest(class);
        }
    }

    /// Selects a class whose oldest valid task exceeded its bounded wait threshold.
    fn select_rescue_class(&mut self, available: [bool; 3], now_ns: u64) -> Option<TaskClass> {
        let mut rescued: Option<(u64, TaskClass)> = None;
        for class in TaskClass::all() {
            if !available[class.index()] {
                continue;
            }
            let Some(node) = self.oldest_valid_node(class) else {
                continue;
            };
            let waited = now_ns.saturating_sub(node.enqueue_time_ns);
            let threshold = self.config.max_wait_for(class);
            if waited < threshold {
                continue;
            }
            let excess = waited.saturating_sub(threshold);
            if rescued.as_ref().is_none_or(|(best_excess, best_class)| {
                (excess, std::cmp::Reverse(class.index()))
                    > (*best_excess, std::cmp::Reverse(best_class.index()))
            }) {
                rescued = Some((excess, class));
            }
        }
        rescued.map(|(_, class)| class)
    }

    /// Scans a bounded policy window for a valid task with a fillable CPU.
    fn take_placeable_node(
        &mut self,
        class: TaskClass,
        oldest_first: bool,
        urgency: Option<LatencyRisk>,
        now_ns: u64,
    ) -> Option<(PoolNode, PlacementDecision)> {
        let mut deferred = Vec::new();
        let scan_limit = if urgency.is_some() {
            1
        } else {
            self.config.placement_scan_limit
        };
        for _ in 0..scan_limit {
            let next = if oldest_first {
                self.pools.pop_oldest(class)
            } else {
                self.pools.pop(class)
            };
            let Some(node) = next else {
                break;
            };
            if !self.node_is_valid(node) {
                continue;
            }
            let preemptible = self.preemptible_cpus(node, urgency, now_ns);
            let Some(state) = self.tasks.get(&node.task) else {
                continue;
            };
            let placement = choose_cpu(
                TaskPlacement {
                    class,
                    request_ns: node.request_ns,
                    previous_cpu: state.previous_cpu,
                    home_cpu: state.home_cpu,
                    home_llc: state.home_llc,
                    affinity: &state.affinity,
                    preemptible: &preemptible,
                    migration_hysteresis_ns: self.config.min_request_for(class),
                    max_completion_delay_ns: urgency.map(|risk| risk.slack_ns),
                },
                &self.cpus,
                &self.topology,
                now_ns,
            );
            if let Some(placement) = placement {
                self.restore_deferred(deferred, oldest_first);
                return Some((node, placement));
            }
            deferred.push(node);
        }
        self.restore_deferred(deferred, oldest_first);
        None
    }

    /// Builds non-latency victim CPUs for one budgeted latency SLO request.
    fn preemptible_cpus(
        &mut self,
        node: PoolNode,
        urgency: Option<LatencyRisk>,
        now_ns: u64,
    ) -> CpuMask {
        let mut mask = CpuMask::none(self.cpus.len());
        let Some(_urgency) = urgency.filter(|_| node.class == TaskClass::Latency) else {
            return mask;
        };
        if self
            .tasks
            .get(&node.task)
            .is_some_and(|state| state.last_preempt_sequence == node.enqueue_sequence)
        {
            self.stats.repeated_preemptions_avoided =
                self.stats.repeated_preemptions_avoided.saturating_add(1);
            return mask;
        }
        let mut budget_denied = false;
        let mut recovery_denied = false;
        for (cpu_id, cpu) in self.cpus.iter().enumerate() {
            if !cpu.online || cpu.idle || !cpu.is_urgent_fillable() {
                continue;
            }
            let Some(current_task) = cpu.current_task else {
                continue;
            };
            let Some(current_dispatch_id) = self
                .tasks
                .get(&current_task)
                .and_then(|state| state.active_dispatch_id)
            else {
                continue;
            };
            let Some(current) = self.reservations.get(&current_dispatch_id) else {
                continue;
            };
            if current.phase != ReservationPhase::Running {
                continue;
            }
            if current.class == TaskClass::Latency {
                continue;
            }
            if self
                .tasks
                .get(&current_task)
                .is_some_and(|state| state.preemption_guard != PreemptionGuard::None)
            {
                recovery_denied = true;
                continue;
            }

            let remaining_ns = cpu.predicted_start_delay(now_ns);
            let benefit_ns = remaining_ns.saturating_sub(self.dispatch_overhead_ns);
            if benefit_ns <= self.config.preemption_min_runtime_ns {
                continue;
            }
            let cost_ns = self.preemption_cost_ns(cpu_id as u32, now_ns);
            if !self.preemption_budget.can_reserve(cost_ns) {
                budget_denied = true;
                continue;
            }
            mask.set(cpu_id, true);
        }
        if budget_denied {
            self.stats.preemption_budget_denials =
                self.stats.preemption_budget_denials.saturating_add(1);
        }
        if recovery_denied {
            self.stats.repeated_preemptions_avoided =
                self.stats.repeated_preemptions_avoided.saturating_add(1);
        }
        mask
    }

    fn preemption_cost_ns(&self, cpu: u32, now_ns: u64) -> u64 {
        self.config.preemption_min_runtime_ns.saturating_add(
            self.cpus
                .get(cpu as usize)
                .map(|state| state.predicted_start_delay(now_ns))
                .unwrap_or_default()
                .min(self.config.slice_for(TaskClass::Throughput)),
        )
    }

    /// Restores placement-skipped nodes to the correct primary or rescue index.
    fn restore_deferred(&mut self, deferred: Vec<PoolNode>, rescue: bool) {
        if rescue {
            for node in deferred.into_iter().rev() {
                self.pools.restore_oldest(node);
            }
        } else {
            for node in deferred {
                self.pools.requeue_primary(node);
            }
        }
    }

    /// Creates one reservation, occupies one Rust slot, and builds its command.
    fn reserve_node(
        &mut self,
        node: PoolNode,
        placement: PlacementDecision,
        pool_deadline_ns: u64,
        reason: DispatchReason,
        now_ns: u64,
    ) -> Option<DispatchRequest> {
        if !self.node_is_valid(node) {
            return None;
        }
        let target_cpu = placement.cpu;
        let lane_available = self.cpus.get(target_cpu as usize).is_some_and(|cpu| {
            if placement.preempt() {
                cpu.is_urgent_fillable()
            } else {
                cpu.is_fillable()
            }
        });
        if !lane_available {
            self.pools.requeue_primary(node);
            return None;
        }
        if self.reservations.len() >= self.config.max_reservations {
            self.stats.reservation_capacity_hits =
                self.stats.reservation_capacity_hits.saturating_add(1);
            self.pools.requeue_primary(node);
            return None;
        }

        let cache = *self.task_classes.get(&node.task)?;
        let (process, previous_cpu, already_preempted) =
            self.tasks.get(&node.task).map(|state| {
                (
                    state.process,
                    state.previous_cpu,
                    state.last_preempt_sequence == node.enqueue_sequence,
                )
            })?;
        let slice_ns = node.request_ns;
        let slo_admitted = reason == DispatchReason::SloOverride;
        if slo_admitted && !self.latency_budget.can_reserve(slice_ns) {
            self.stats.latency_budget_denials = self.stats.latency_budget_denials.saturating_add(1);
            self.pools.requeue_primary(node);
            return None;
        }
        let preemption = if let Some(victim) = placement.preemption {
            let victim_valid = victim.class != TaskClass::Latency
                && self.cpus.get(target_cpu as usize).is_some_and(|cpu| {
                    cpu.current_task == Some(victim.task) && cpu.current_class == Some(victim.class)
                })
                && self
                    .tasks
                    .get(&victim.task)
                    .is_some_and(|state| state.preemption_guard == PreemptionGuard::None);
            if already_preempted || !victim_valid {
                self.stats.repeated_preemptions_avoided =
                    self.stats.repeated_preemptions_avoided.saturating_add(1);
                self.pools.requeue_primary(node);
                return None;
            }
            let charge_ns = self.preemption_cost_ns(target_cpu, now_ns);
            if !self.preemption_budget.can_reserve(charge_ns) {
                self.stats.preemption_budget_denials =
                    self.stats.preemption_budget_denials.saturating_add(1);
                self.pools.requeue_primary(node);
                return None;
            }
            Some(PreemptionReservation { victim, charge_ns })
        } else {
            None
        };
        if slo_admitted {
            assert!(self.latency_budget.reserve(slice_ns));
        }
        if let Some(preemption) = preemption {
            assert!(self.preemption_budget.reserve(preemption.charge_ns));
        }
        let dispatch_id = self.allocate_dispatch_id();
        let reservation = Reservation {
            dispatch_id,
            task: node.task,
            enqueue_sequence: node.enqueue_sequence,
            class: node.class,
            class_generation: node.class_generation,
            target_cpu,
            planned_slice_ns: slice_ns,
            task_deadline_ns: node.deadline_ns,
            pool_deadline_ns,
            submitted_ns: now_ns,
            predicted_start_delay_ns: placement.predicted_start_delay_ns,
            slo_admitted,
            preemption,
            phase: ReservationPhase::Submitted,
        };

        if let Some(state) = self.tasks.get_mut(&node.task) {
            state.run_state = RunState::Reserved;
            state.active_dispatch_id = Some(dispatch_id);
            state.assigned_slice_ns = slice_ns;
            if preemption.is_some() {
                state.last_preempt_sequence = node.enqueue_sequence;
            }
        }
        if let Some(preemption) = preemption {
            if let Some(victim) = self.tasks.get_mut(&preemption.victim.task) {
                victim.preemption_guard = PreemptionGuard::AwaitingStop;
            }
        }
        if let Some(cpu) = self.cpus.get_mut(target_cpu as usize) {
            if placement.preempt() {
                cpu.urgent_dispatch = Some(dispatch_id);
                cpu.urgent_task = Some(node.task);
            } else {
                cpu.staged_dispatch = Some(dispatch_id);
                cpu.staged_task = Some(node.task);
            }
        }
        self.reservations.insert(dispatch_id, reservation);
        self.root.reserve(node.class, slice_ns);
        self.stats.record_dispatch(node.class, 1);
        self.stats
            .record_placement(node.class, previous_cpu, target_cpu, placement.sibling_busy);
        if slo_admitted {
            self.stats.latency_slo_admissions = self.stats.latency_slo_admissions.saturating_add(1);
        }
        if reason == DispatchReason::Root && node.class == TaskClass::Latency {
            self.stats.root_latency_dispatches =
                self.stats.root_latency_dispatches.saturating_add(1);
        }
        if let Some(preemption) = preemption {
            self.stats.record_preempt(preemption.victim.class);
        }

        Some(DispatchRequest {
            task: node.task,
            process,
            enqueue_sequence: node.enqueue_sequence,
            class_generation: cache.class_generation,
            dispatch_id,
            target_cpu,
            slice_ns,
            preempt: placement.preempt(),
        })
    }

    /// Allocates a non-zero dispatch ID with wraparound protection.
    fn allocate_dispatch_id(&mut self) -> u64 {
        let id = self.next_dispatch_id;
        self.next_dispatch_id = self.next_dispatch_id.wrapping_add(1);
        if self.next_dispatch_id == 0 {
            self.next_dispatch_id = 1;
        }
        id
    }

    /// Cancels a task's active reservation and optionally restores its queue node.
    fn cancel_task(&mut self, task: TaskKey, requeue: bool) {
        let dispatch_id = self
            .tasks
            .get(&task)
            .and_then(|state| state.active_dispatch_id);
        if let Some(dispatch_id) = dispatch_id {
            self.rollback_reservation(dispatch_id, requeue);
        } else if let Some(state) = self.tasks.get_mut(&task) {
            state.active_dispatch_id = None;
            if !requeue {
                state.run_state = RunState::Blocked;
            }
        }
    }

    /// Removes reservation service and slot state, then optionally requeues it.
    fn rollback_reservation(&mut self, dispatch_id: u64, requeue: bool) {
        let Some(reservation) = self.reservations.remove(&dispatch_id) else {
            return;
        };
        self.release_cpu_slot(reservation.target_cpu, dispatch_id);
        self.root
            .cancel(reservation.class, reservation.planned_slice_ns);
        if reservation.slo_admitted {
            self.latency_budget.cancel(reservation.planned_slice_ns);
        }
        let mut refunded_charge_ns = None;
        if let Some(preemption) = reservation.preemption {
            if let Some(victim) = self.tasks.get_mut(&preemption.victim.task) {
                if victim.preemption_guard == PreemptionGuard::AwaitingStop {
                    victim.preemption_guard = PreemptionGuard::None;
                    refunded_charge_ns = Some(preemption.charge_ns);
                }
            }
        }
        if let Some(charge_ns) = refunded_charge_ns {
            self.preemption_budget.cancel(charge_ns);
        }
        let preemption_refunded = refunded_charge_ns.is_some();

        let mut should_requeue = false;
        if let Some(state) = self.tasks.get_mut(&reservation.task) {
            if state.active_dispatch_id == Some(dispatch_id)
                && state.enqueue_sequence == reservation.enqueue_sequence
            {
                state.active_dispatch_id = None;
                state.assigned_slice_ns = 0;
                if preemption_refunded {
                    state.last_preempt_sequence = 0;
                }
                if requeue && state.run_state != RunState::Exited {
                    state.run_state = RunState::Queued;
                    should_requeue = true;
                } else {
                    state.run_state = RunState::Blocked;
                }
            }
        }
        if should_requeue {
            self.push_task_node(reservation.task);
        }
    }

    /// Clears the normal or urgent Rust slot only when its dispatch ID matches.
    fn release_cpu_slot(&mut self, cpu: u32, dispatch_id: u64) {
        if let Some(state) = self.cpus.get_mut(cpu as usize) {
            if state.staged_dispatch == Some(dispatch_id) {
                state.staged_dispatch = None;
                state.staged_task = None;
            }
            if state.urgent_dispatch == Some(dispatch_id) {
                state.urgent_dispatch = None;
                state.urgent_task = None;
            }
        }
    }

    /// Establishes or slowly rebases a task's home CPU and LLC.
    fn update_home(
        state: &mut TaskState,
        class: TaskClass,
        actual_cpu: u32,
        actual_llc: Option<u32>,
    ) {
        if state.home_cpu.is_none() {
            state.home_cpu = Some(actual_cpu);
            state.home_llc = actual_llc;
            state.consecutive_home_misses = 0;
            return;
        }
        if state.home_cpu == Some(actual_cpu) {
            state.consecutive_home_misses = 0;
            return;
        }
        state.consecutive_home_misses = state.consecutive_home_misses.saturating_add(1);
        if state.consecutive_home_misses >= HOME_REBASE_RUNS[class.index()] {
            state.home_cpu = Some(actual_cpu);
            state.home_llc = actual_llc;
            state.consecutive_home_misses = 0;
        }
    }

    /// Clears home locality when hotplug or refreshed affinity makes it invalid.
    fn clear_invalid_home(state: &mut TaskState, cpus: &[CpuState]) {
        let valid = state.home_cpu.is_some_and(|cpu| {
            state.affinity.contains(cpu as usize)
                && cpus.get(cpu as usize).is_some_and(|item| item.online)
        });
        if !valid {
            state.home_cpu = None;
            state.home_llc = None;
            state.consecutive_home_misses = 0;
        }
    }

    /// Removes one reverse-index member and its process cache when it becomes empty.
    fn remove_process_member(&mut self, process: ProcessKey, task: TaskKey) -> bool {
        let empty = self
            .tasks_by_process
            .get_mut(&process)
            .map(|tasks| {
                tasks.remove(&task);
                tasks.is_empty()
            })
            .unwrap_or(false);
        if empty {
            self.tasks_by_process.remove(&process);
            self.process_defaults.remove(&process);
        }
        empty
    }

    /// Increments the stale-event counter for any rejected transition.
    fn record_stale_event(&mut self) {
        self.stats.stale_events = self.stats.stale_events.saturating_add(1);
    }

    fn mark_degraded(&mut self) {
        if !self.degraded {
            self.degraded = true;
            self.stats.degraded_transitions = self.stats.degraded_transitions.saturating_add(1);
        }
    }
}

/// Engine construction or control-update failure.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Configuration failed cross-field validation.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Control plane referenced a task lifetime no longer present.
    #[error("unknown task identity {0:?}")]
    UnknownTask(TaskKey),
    /// Snapshot or update referenced a process image absent from the engine.
    #[error("unknown process identity {0:?}")]
    UnknownProcess(ProcessKey),
    /// Registry snapshots only carry task overrides, never inherited entries.
    #[error("task snapshot for {0:?} must be semantic or locked")]
    InvalidSnapshotStage(TaskKey),
    /// Process generation update was duplicate or delayed.
    #[error("process {process:?} received stale generation {received}; current is {current}")]
    StaleProcessGeneration {
        /// Stable process image receiving the stale command.
        process: ProcessKey,
        /// Scheduler's current process generation.
        current: u64,
        /// Delayed generation supplied by Agent.
        received: u64,
    },
    /// Task class transition violated identity, generation, or lock rules.
    #[error(transparent)]
    ClassUpdate(#[from] ClassUpdateError),
    /// Reconciled affinity mask does not match scheduler topology width.
    #[error("affinity width {received} does not match topology width {expected}")]
    AffinityWidth {
        /// Number of CPUs represented by the engine.
        expected: usize,
        /// Number of CPUs represented by the supplied mask.
        received: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        EngineNotice, PreemptionGuard, ReservationPhase, RunState, SchedulerEngine, WindowQuality,
    };
    use crate::config::SchedulerConfig;
    use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
    use crate::process::TaskClassUpdate;
    use crate::topology::{CpuMask, CpuTopology};
    use crate::wire::{EventKind, KernelEvent};

    /// Builds one task lifecycle event without depending on raw BPF structs.
    fn event(kind: EventKind, tid: u32, sequence: u64, dispatch_id: u64) -> KernelEvent {
        KernelEvent {
            kind,
            task: TaskKey::new(tid, tid as u64 + 100),
            process: ProcessKey::new(10, 200, 1),
            enqueue_sequence: sequence,
            dispatch_id,
            timestamp_ns: 1_000,
            runtime_ns: 0,
            sleep_ns: 0,
            previous_cpu: Some(0),
            actual_cpu: Some(0),
            flags: 0,
        }
    }

    /// Unknown processes/tasks default to Balanced without synchronous Agent IPC.
    #[test]
    fn enqueue_discovers_balanced_task_and_dispatches_it() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let notices = engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        assert!(matches!(notices[0], EngineNotice::ProcessDiscovered(_)));

        let commands = engine.refill(1_000);
        assert_eq!(commands.len(), 1);
        let task = commands[0].task;
        assert_eq!(
            engine.task_class(task).unwrap().effective_class,
            TaskClass::Balanced
        );
        assert_eq!(engine.task(task).unwrap().run_state, RunState::Reserved);
        assert_eq!(
            engine.cpus()[0].staged_dispatch,
            Some(commands[0].dispatch_id)
        );
        assert!(engine.refill(1_000).is_empty());
    }

    /// BPF-owned runnable instances remain telemetry-only in the Rust engine.
    #[test]
    fn bpf_scheduled_enqueue_never_creates_a_duplicate_command() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let mut enqueue = event(EventKind::Enqueue, 11, 1, 0);
        enqueue.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;

        engine.handle_event(enqueue);
        let task = enqueue.task.unwrap();
        assert_eq!(engine.task(task).unwrap().run_state, RunState::KernelQueued);
        assert!(engine.refill(enqueue.timestamp_ns).is_empty());

        let mut running = event(EventKind::Running, 11, 1, 0);
        running.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;
        running.runtime_ns = 1_000_000;
        running.timestamp_ns = 2_000;
        engine.handle_event(running);
        assert_eq!(engine.task(task).unwrap().run_state, RunState::Running);
        assert_eq!(engine.task(task).unwrap().assigned_slice_ns, 1_000_000);
        assert_eq!(engine.reservation_count(), 0);
    }

    #[test]
    fn sampled_bpf_sequence_gap_keeps_behavior_window_valid() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let mut first = event(EventKind::Enqueue, 11, 1, 0);
        first.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;
        engine.handle_event(first);

        let mut sampled = event(EventKind::Enqueue, 11, 3, 0);
        sampled.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;
        sampled.timestamp_ns = 2_000;
        engine.handle_event(sampled);

        let window = engine.take_behavior_windows(3_000).remove(0);
        assert_eq!(window.enqueue_count, 2);
        assert_eq!(window.quality, WindowQuality::Good);
    }

    /// Locked tasks leave behavior tracking until a Registry reset resumes it.
    #[test]
    fn locked_task_quiesces_and_reset_resumes_observation() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let process = ProcessKey::new(10, 200, 1).unwrap();
        let task = TaskKey::new(11, 111).unwrap();
        let mut enqueue = event(EventKind::Enqueue, task.tid, 1, 0);
        enqueue.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;
        engine.handle_event(enqueue);

        engine
            .apply_task_class_update(TaskClassUpdate {
                task,
                process,
                class: TaskClass::Latency,
                stage: ClassStage::Locked,
                class_generation: 1,
            })
            .unwrap();
        assert_eq!(
            engine.task(task).unwrap().run_state,
            RunState::KernelManaged
        );
        assert!(engine.take_behavior_windows(2_000).is_empty());

        let mut trailing = event(EventKind::Running, task.tid, 1, 0);
        trailing.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;
        engine.handle_event(trailing);
        assert_eq!(
            engine.task(task).unwrap().run_state,
            RunState::KernelManaged
        );

        engine.reset_classifications(3_000);
        assert_eq!(engine.task(task).unwrap().run_state, RunState::Blocked);
        assert_eq!(
            engine.task_class(task).unwrap().stage,
            ClassStage::Inherited
        );

        let mut resumed = event(EventKind::Enqueue, task.tid, 2, 0);
        resumed.timestamp_ns = 4_000;
        resumed.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64;
        engine.handle_event(resumed);
        assert_eq!(engine.task(task).unwrap().run_state, RunState::KernelQueued);
    }

    /// RUNNING frees the depth-one slot while retaining service reservation to STOP.
    #[test]
    fn running_opens_pipeline_slot_before_stop() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        engine.handle_event(event(EventKind::Enqueue, 12, 1, 0));
        engine
            .set_cached_affinity(TaskKey::new(11, 111).unwrap(), CpuMask::all(1))
            .unwrap();
        engine
            .set_cached_affinity(TaskKey::new(12, 112).unwrap(), CpuMask::all(1))
            .unwrap();
        let first = engine.refill(1_000).remove(0);

        let mut running = event(EventKind::Running, first.task.tid, 1, first.dispatch_id);
        running.timestamp_ns = 2_000;
        engine.handle_event(running);
        assert_eq!(engine.cpus()[0].staged_dispatch, None);
        assert_eq!(
            engine.reservations[&first.dispatch_id].phase,
            ReservationPhase::Running
        );

        let second = engine.refill(2_000);
        assert_eq!(second.len(), 1);
        assert_ne!(second[0].task, first.task);
        assert_eq!(engine.reservation_count(), 2);
    }

    /// A newly eligible latency deadline bypasses one normal prefetched task.
    #[test]
    fn latency_uses_urgent_lane_over_staged_throughput() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let process = ProcessKey::new(10, 200, 1).unwrap();

        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let throughput = TaskKey::new(11, 111).unwrap();
        engine
            .apply_task_class_update(TaskClassUpdate {
                task: throughput,
                process,
                class: TaskClass::Throughput,
                stage: ClassStage::Semantic,
                class_generation: 1,
            })
            .unwrap();
        let running_command = engine.refill(1_000).remove(0);
        let mut running = event(
            EventKind::Running,
            throughput.tid,
            1,
            running_command.dispatch_id,
        );
        running.timestamp_ns = 2_000;
        engine.handle_event(running);

        engine.handle_event(event(EventKind::Enqueue, 12, 1, 0));
        let staged = TaskKey::new(12, 112).unwrap();
        engine
            .apply_task_class_update(TaskClassUpdate {
                task: staged,
                process,
                class: TaskClass::Throughput,
                stage: ClassStage::Semantic,
                class_generation: 1,
            })
            .unwrap();
        let staged_command = engine.refill(2_100).remove(0);
        assert!(!staged_command.preempt);
        assert_eq!(
            engine.cpus()[0].staged_dispatch,
            Some(staged_command.dispatch_id)
        );

        engine.handle_event(event(EventKind::Enqueue, 13, 1, 0));
        let latency = TaskKey::new(13, 113).unwrap();
        engine
            .apply_task_class_update(TaskClassUpdate {
                task: latency,
                process,
                class: TaskClass::Latency,
                stage: ClassStage::Semantic,
                class_generation: 1,
            })
            .unwrap();
        let urgent = engine.refill(752_000).remove(0);

        assert_eq!(urgent.task, latency);
        assert!(urgent.preempt);
        assert_eq!(engine.cpus()[0].urgent_dispatch, Some(urgent.dispatch_id));
        assert_eq!(engine.stats().preempt_dispatches, 1);
        assert_eq!(engine.stats().latency_slo_admissions, 0);
        assert_eq!(engine.stats().root_latency_dispatches, 1);
        assert_eq!(
            engine.task(throughput).unwrap().preemption_guard,
            PreemptionGuard::AwaitingStop
        );
        assert_eq!(
            engine.stats().latency_preemptions_by_victim_class,
            [0, 0, 1]
        );
    }

    /// SLO accounting is used only when latency replaces a non-latency root choice.
    #[test]
    fn slo_admission_records_a_true_root_override() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let process = ProcessKey::new(10, 200, 1).unwrap();
        let latency = TaskKey::new(11, 111).unwrap();

        engine.handle_event(event(EventKind::Enqueue, latency.tid, 1, 0));
        engine
            .apply_task_class_update(TaskClassUpdate {
                task: latency,
                process,
                class: TaskClass::Latency,
                stage: ClassStage::Semantic,
                class_generation: 1,
            })
            .unwrap();
        let first = engine.refill(1_000).remove(0);
        let mut running = event(EventKind::Running, latency.tid, 1, first.dispatch_id);
        running.timestamp_ns = 2_000;
        engine.handle_event(running);
        let mut stop = event(EventKind::Stop, latency.tid, 1, first.dispatch_id);
        stop.timestamp_ns = 1_002_000;
        stop.runtime_ns = 1_000_000;
        engine.handle_event(stop);

        let mut latency_enqueue = event(EventKind::Enqueue, latency.tid, 2, 0);
        latency_enqueue.timestamp_ns = 2_000_000;
        engine.handle_event(latency_enqueue);
        let throughput = TaskKey::new(12, 112).unwrap();
        let mut throughput_enqueue = event(EventKind::Enqueue, throughput.tid, 1, 0);
        throughput_enqueue.timestamp_ns = 2_000_000;
        engine.handle_event(throughput_enqueue);
        engine
            .apply_task_class_update(TaskClassUpdate {
                task: throughput,
                process,
                class: TaskClass::Throughput,
                stage: ClassStage::Semantic,
                class_generation: 1,
            })
            .unwrap();

        let selected = engine.refill(4_000_000).remove(0);
        assert_eq!(selected.task, latency);
        assert!(!selected.preempt);
        assert_eq!(engine.stats().root_latency_dispatches, 1);
        assert_eq!(engine.stats().latency_slo_admissions, 1);
    }

    /// An interrupted request keeps both its remaining service and finish deadline.
    #[test]
    fn forced_preemption_resumes_the_same_eevdf_request() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let first = engine.refill(1_000).remove(0);
        let original_deadline = engine.reservations[&first.dispatch_id].task_deadline_ns;

        let mut running = event(EventKind::Running, 11, 1, first.dispatch_id);
        running.timestamp_ns = 2_000;
        engine.handle_event(running);
        let mut stop = event(EventKind::Stop, 11, 1, first.dispatch_id);
        stop.timestamp_ns = 1_002_000;
        stop.runtime_ns = 1_000_000;
        stop.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE as u64;
        engine.handle_event(stop);

        let task = first.task;
        assert_eq!(engine.task(task).unwrap().request_remaining_ns, 3_000_000);
        assert_eq!(
            engine.task(task).unwrap().request_deadline_ns,
            original_deadline
        );
        assert_eq!(engine.stats().request_resumptions, 1);

        let mut enqueue = event(EventKind::Enqueue, 11, 2, 0);
        enqueue.timestamp_ns = 1_003_000;
        engine.handle_event(enqueue);
        let resumed = engine.refill(1_003_000).remove(0);
        assert_eq!(resumed.slice_ns, 3_000_000);
        assert_eq!(
            engine.reservations[&resumed.dispatch_id].task_deadline_ns,
            original_deadline
        );
    }

    /// A sub-minimum tail is closed instead of producing an invalid BPF slice.
    #[test]
    fn sub_minimum_request_tail_starts_a_new_request() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let process = ProcessKey::new(10, 200, 1).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let task = TaskKey::new(11, 111).unwrap();
        engine
            .apply_task_class_update(TaskClassUpdate {
                task,
                process,
                class: TaskClass::Latency,
                stage: ClassStage::Semantic,
                class_generation: 1,
            })
            .unwrap();
        let first = engine.refill(1_000).remove(0);
        assert_eq!(first.slice_ns, 250_000);

        let mut running = event(EventKind::Running, 11, 1, first.dispatch_id);
        running.timestamp_ns = 2_000;
        engine.handle_event(running);
        let mut stop = event(EventKind::Stop, 11, 1, first.dispatch_id);
        stop.timestamp_ns = 202_000;
        stop.runtime_ns = 200_000;
        stop.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE as u64;
        engine.handle_event(stop);

        assert_eq!(engine.task(task).unwrap().request_remaining_ns, 0);
        assert_eq!(engine.stats().request_resumptions, 0);
        let mut enqueue = event(EventKind::Enqueue, 11, 2, 0);
        enqueue.timestamp_ns = 803_000;
        engine.handle_event(enqueue);
        let next = engine.refill(803_000).remove(0);
        assert!(next.slice_ns >= SchedulerConfig::default().min_slice_ns);
    }

    /// A defensive SLICE rejection discards the bad request and remains runnable.
    #[test]
    fn invalid_slice_reject_repairs_request_before_requeue() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let first = engine.refill(1_000).remove(0);
        let mut reject = event(EventKind::CommandReject, 11, 1, first.dispatch_id);
        reject.flags = crate::bpf_intf::SCX_ADAPTIVE_REJECT_SLICE as u64;
        engine.handle_event(reject);

        assert_eq!(engine.task(first.task).unwrap().run_state, RunState::Queued);
        let repaired = engine.refill(2_000).remove(0);
        assert!(repaired.slice_ns >= SchedulerConfig::default().min_slice_ns);
    }

    /// Latency SLO service may queue behind latency work but never preempt it.
    #[test]
    fn latency_never_preempts_running_latency() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let process = ProcessKey::new(10, 200, 1).unwrap();

        for tid in [11, 12] {
            engine.handle_event(event(EventKind::Enqueue, tid, 1, 0));
            engine
                .apply_task_class_update(TaskClassUpdate {
                    task: TaskKey::new(tid, tid as u64 + 100).unwrap(),
                    process,
                    class: TaskClass::Latency,
                    stage: ClassStage::Semantic,
                    class_generation: 1,
                })
                .unwrap();
            if tid == 11 {
                let first = engine.refill(1_000).remove(0);
                let mut running = event(EventKind::Running, tid, 1, first.dispatch_id);
                running.timestamp_ns = 2_000;
                engine.handle_event(running);
            }
        }

        let queued = engine.refill(752_000).remove(0);
        assert!(!queued.preempt);
        assert_eq!(engine.stats().preempt_dispatches, 0);
        assert_eq!(
            engine.stats().latency_preemptions_by_victim_class,
            [0, 0, 0]
        );
    }

    /// BPF rejection releases service and slot reservations then requeues the task.
    #[test]
    fn command_reject_rolls_back_reservation() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let command = engine.refill(1_000).remove(0);
        let mut reject = event(EventKind::CommandReject, 11, 1, command.dispatch_id);
        reject.flags = crate::bpf_intf::SCX_ADAPTIVE_REJECT_TARGET_SLOT_BUSY as u64;
        engine.handle_event(reject);

        assert_eq!(engine.reservation_count(), 0);
        assert_eq!(engine.cpus()[0].staged_dispatch, None);
        assert_eq!(
            engine.task(command.task).unwrap().run_state,
            RunState::Queued
        );
        assert_eq!(engine.refill(2_000).len(), 1);
        assert_eq!(
            engine.stats().command_rejects_by_reason
                [crate::bpf_intf::SCX_ADAPTIVE_REJECT_TARGET_SLOT_BUSY as usize],
            1
        );
    }

    /// A migration-disabled task remains runnable for a fresh placement attempt.
    #[test]
    fn migration_disabled_reject_requeues_task() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let command = engine.refill(1_000).remove(0);
        let mut reject = event(EventKind::CommandReject, 11, 1, command.dispatch_id);
        reject.flags = crate::bpf_intf::SCX_ADAPTIVE_REJECT_MIGRATION_DISABLED as u64;
        engine.handle_event(reject);

        assert_eq!(engine.reservation_count(), 0);
        assert_eq!(
            engine.task(command.task).unwrap().run_state,
            RunState::Queued
        );
        assert_eq!(engine.refill(2_000).len(), 1);
    }

    /// A stale command must wait for a new lifecycle event instead of spinning.
    #[test]
    fn non_retryable_reject_does_not_requeue_task() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        let command = engine.refill(1_000).remove(0);
        let mut reject = event(EventKind::CommandReject, 11, 1, command.dispatch_id);
        reject.flags = crate::bpf_intf::SCX_ADAPTIVE_REJECT_NOT_PENDING as u64;
        engine.handle_event(reject);

        assert_eq!(
            engine.task(command.task).unwrap().run_state,
            RunState::Blocked
        );
        assert!(engine.refill(2_000).is_empty());
    }

    #[test]
    fn task_capacity_marks_engine_degraded() {
        let config = SchedulerConfig {
            max_tasks: 1,
            ..SchedulerConfig::default()
        };
        let mut engine = SchedulerEngine::new(config, CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Init, 11, 0, 0));
        engine.handle_event(event(EventKind::Init, 12, 0, 0));

        assert!(engine.is_degraded());
        assert_eq!(engine.task_count(), 1);
        assert_eq!(engine.stats().task_capacity_hits, 1);
    }

    #[test]
    fn stale_pool_nodes_are_compacted_at_the_bound() {
        let config = SchedulerConfig {
            max_tasks: 2,
            max_pool_nodes: 4,
            ..SchedulerConfig::default()
        };
        let mut engine = SchedulerEngine::new(config, CpuTopology::flat(1)).unwrap();
        for sequence in 1..=3 {
            engine.handle_event(event(EventKind::Enqueue, 11, sequence, 0));
        }

        assert!(!engine.is_degraded());
        assert!(engine.pool_node_count() <= 4);
        assert_eq!(engine.stats().pool_compactions, 1);
    }

    #[test]
    fn reservation_capacity_defers_additional_dispatches() {
        let config = SchedulerConfig {
            max_reservations: 1,
            ..SchedulerConfig::default()
        };
        let mut engine = SchedulerEngine::new(config, CpuTopology::flat(2)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1, 0));
        engine.handle_event(event(EventKind::Enqueue, 12, 1, 0));

        assert_eq!(engine.refill(1_000).len(), 1);
        assert_eq!(engine.reservation_count(), 1);
        assert_eq!(engine.stats().reservation_capacity_hits, 1);
    }

    #[test]
    fn behavior_window_contains_ordered_scheduler_facts() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let mut enqueue = event(EventKind::Enqueue, 11, 1, 0);
        enqueue.timestamp_ns = 1_000_000_000;
        enqueue.sleep_ns = 500;
        enqueue.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_WAKEUP as u64;
        engine.handle_event(enqueue);
        let command = engine.refill(enqueue.timestamp_ns).remove(0);

        let mut running = event(EventKind::Running, 11, 1, command.dispatch_id);
        running.timestamp_ns = 1_000_100_000;
        engine.handle_event(running);
        let mut stop = event(EventKind::Stop, 11, 1, command.dispatch_id);
        stop.timestamp_ns = 1_004_100_000;
        stop.runtime_ns = 4_000_000;
        stop.flags = crate::bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE as u64;
        engine.handle_event(stop);

        let window = engine.take_behavior_windows(6_000_000_000).remove(0);
        assert_eq!(window.window_sequence, 1);
        assert_eq!(window.sleep_ns, 500);
        assert_eq!(window.enqueue_count, 1);
        assert_eq!(window.wakeup_count, 1);
        assert_eq!(window.run_burst_histogram, [0, 0, 0, 1]);
        assert_eq!(window.wait_histogram, [1, 0, 0, 0]);
        assert_eq!(window.slice_exhaustion_count, 1);
        assert_eq!(window.task_age_ns, 5_000_000_000);
    }

    #[test]
    fn exec_emits_one_explicit_generation_notice() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Init, 11, 0, 0));
        let mut exec = event(EventKind::Exec, 11, 0, 0);
        exec.process.as_mut().unwrap().exec_generation = 2;
        let notices = engine.handle_event(exec);

        assert!(matches!(
            notices.as_slice(),
            [EngineNotice::ProcessExec {
                previous_process,
                process,
                ..
            }] if previous_process.exec_generation == 1 && process.exec_generation == 2
        ));
    }
}
