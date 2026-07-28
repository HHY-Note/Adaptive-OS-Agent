// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::config::{ConfigError, SchedulerConfig};
use crate::identity::{ClassStage, ProcessKey, TaskKey};
use crate::process::{
    ClassUpdateError, ProcessClassUpdate, ProcessDefaultCache, TaskClassCache, TaskClassUpdate,
};
use crate::stats::{SchedulerStats, TaskBehaviorWindow, WindowQuality};
use crate::topology::CpuTopology;
use crate::wire::{EventKind, KernelEvent};

const BEHAVIOR_HISTOGRAM_BOUNDS_NS: [u64; 3] = [250_000, 1_000_000, 4_000_000];

/// Observed lifecycle state of one stable task identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunState {
    /// Task is sleeping, cancelled, or otherwise not runnable.
    Blocked,
    /// Task is runnable in a BPF-owned dispatch queue.
    Queued,
    /// A matching BPF RUNNING event confirmed execution.
    Running,
}

/// Minimal userspace observation state for one stable task lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskState {
    /// Stable task lifetime key.
    pub identity: TaskKey,
    /// Stable process image currently owning the task.
    pub process: ProcessKey,
    /// Task discovery timestamp used to report lifetime age.
    pub created_ns: u64,
    /// Latest observed lifecycle state.
    pub run_state: RunState,
    /// Latest BPF runnable sequence accepted by userspace.
    pub enqueue_sequence: u64,
    /// Last actual CPU confirmed by RUNNING.
    pub previous_cpu: Option<u32>,
    /// Timestamp of the latest accepted ENQUEUE event.
    pub enqueue_time_ns: u64,
    /// Timestamp of the latest matching RUNNING event.
    pub last_start_ns: u64,
    /// Slice reported by BPF for the current runnable incarnation.
    pub assigned_slice_ns: u64,
}

impl TaskState {
    fn new(identity: TaskKey, process: ProcessKey, created_ns: u64) -> Self {
        Self {
            identity,
            process,
            created_ns,
            run_state: RunState::Blocked,
            enqueue_sequence: 0,
            previous_cpu: None,
            enqueue_time_ns: 0,
            last_start_ns: 0,
            assigned_slice_ns: 0,
        }
    }
}

/// Mutable facts accumulated between two Agent behavior reports.
#[derive(Clone, Debug)]
struct BehaviorAccumulator {
    created_ns: u64,
    next_window_sequence: u64,
    window_start_ns: u64,
    last_event_ns: u64,
    runtime_ns: u64,
    runnable_wait_ns: u64,
    sleep_ns: u64,
    enqueue_count: u64,
    wakeup_count: u64,
    run_count: u64,
    run_burst_histogram: [u64; 4],
    wait_histogram: [u64; 4],
    slice_exhaustion_count: u64,
    voluntary_block_count: u64,
    migration_count: u64,
    previous_cpu_hit_count: u64,
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

    fn observe_timestamp(&mut self, timestamp_ns: u64) {
        if self.window_start_ns == 0 {
            self.window_start_ns = timestamp_ns;
        }
        if self.last_event_ns != 0 && timestamp_ns < self.last_event_ns {
            self.bad = true;
        }
        self.last_event_ns = self.last_event_ns.max(timestamp_ns);
    }

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

/// Non-blocking lifecycle work forwarded to the Agent control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineNotice {
    ProcessDiscovered(ProcessKey),
    TaskDiscovered {
        task: TaskKey,
        process: ProcessKey,
    },
    ProcessExec {
        task: TaskKey,
        previous_process: ProcessKey,
        process: ProcessKey,
    },
    TaskExited {
        task: TaskKey,
        process: ProcessKey,
    },
    ProcessExited(ProcessKey),
}

/// Single-owner identity, classification, and behavior state.
///
/// Ordinary scheduling decisions are made exclusively by the BPF data plane.
/// This engine never owns a runnable queue and never emits dispatch commands.
#[derive(Clone, Debug)]
pub struct SchedulerEngine {
    config: SchedulerConfig,
    cpu_count: usize,
    process_defaults: HashMap<ProcessKey, ProcessDefaultCache>,
    task_classes: HashMap<TaskKey, TaskClassCache>,
    tasks: HashMap<TaskKey, TaskState>,
    tasks_by_process: HashMap<ProcessKey, HashSet<TaskKey>>,
    stats: SchedulerStats,
    behavior: HashMap<TaskKey, BehaviorAccumulator>,
    degraded: bool,
}

impl SchedulerEngine {
    pub fn new(config: SchedulerConfig, topology: CpuTopology) -> Result<Self, EngineError> {
        config.validate()?;
        Ok(Self {
            config,
            cpu_count: topology.cpu_count(),
            process_defaults: HashMap::new(),
            task_classes: HashMap::new(),
            tasks: HashMap::new(),
            tasks_by_process: HashMap::new(),
            stats: SchedulerStats::default(),
            behavior: HashMap::new(),
            degraded: false,
        })
    }

    pub fn stats(&self) -> &SchedulerStats {
        &self.stats
    }

    pub fn task(&self, task: TaskKey) -> Option<&TaskState> {
        self.tasks.get(&task)
    }

    pub fn task_class(&self, task: TaskKey) -> Option<&TaskClassCache> {
        self.task_classes.get(&task)
    }

    pub fn process_default(&self, process: ProcessKey) -> Option<&ProcessDefaultCache> {
        self.process_defaults.get(&process)
    }

    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub const fn is_degraded(&self) -> bool {
        self.degraded
    }

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

    pub fn task_controls(&self) -> Vec<(TaskKey, TaskClassCache)> {
        let mut controls: Vec<_> = self
            .task_classes
            .iter()
            .map(|(task, cache)| (*task, *cache))
            .collect();
        controls.sort_unstable_by_key(|(task, _)| *task);
        controls
    }

    pub fn reset_classifications(&mut self, now_ns: u64) {
        let previously_locked: Vec<_> = self
            .task_classes
            .iter()
            .filter_map(|(task, cache)| (cache.stage == ClassStage::Locked).then_some(*task))
            .collect();
        for process in self.process_defaults.values_mut() {
            *process = ProcessDefaultCache::default();
        }
        for cache in self.task_classes.values_mut() {
            *cache = TaskClassCache::inherited(cache.process, ProcessDefaultCache::default());
        }
        for task in previously_locked {
            let created_ns = self
                .tasks
                .get(&task)
                .map(|state| state.created_ns)
                .unwrap_or(now_ns);
            self.behavior
                .insert(task, BehaviorAccumulator::new(created_ns));
        }
    }

    pub fn restore_process_class(
        &mut self,
        process: ProcessKey,
        class: crate::identity::TaskClass,
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
        }
        Ok(affected)
    }

    pub fn restore_task_class(
        &mut self,
        task: TaskKey,
        process: ProcessKey,
        class: crate::identity::TaskClass,
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
            self.ensure_behavior(task);
        }
        Ok(())
    }

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

    pub fn mark_behavior_gap(&mut self) {
        for accumulator in self.behavior.values_mut() {
            accumulator.bad = true;
        }
    }

    pub fn handle_event(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        self.stats.events_processed = self.stats.events_processed.saturating_add(1);
        if matches!(
            event.kind,
            EventKind::Enqueue | EventKind::Cancel | EventKind::Running | EventKind::Stop
        ) && event.task.is_some_and(|task| {
            self.task_classes
                .get(&task)
                .is_some_and(|cache| cache.stage == ClassStage::Locked)
        }) {
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
        }
    }

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
        let affected = self.inherited_tasks(update.process);
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
        }
        Ok(affected)
    }

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
        } else {
            self.ensure_behavior(update.task);
        }
        Ok(())
    }

    pub fn inherited_tasks(&self, process: ProcessKey) -> Vec<TaskKey> {
        let mut tasks: Vec<_> = self
            .tasks_by_process
            .get(&process)
            .into_iter()
            .flatten()
            .copied()
            .filter(|task| {
                self.task_classes
                    .get(task)
                    .is_some_and(|cache| cache.stage == ClassStage::Inherited)
            })
            .collect();
        tasks.sort_unstable();
        tasks
    }

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
        self.tasks
            .insert(task, TaskState::new(task, process, timestamp_ns));
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

    fn handle_init(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        match (event.task, event.process) {
            (Some(task), Some(process)) => self.discover_task(task, process, event.timestamp_ns),
            _ => {
                self.record_stale_event();
                Vec::new()
            }
        }
    }

    fn handle_exec(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let (Some(task), Some(process)) = (event.task, event.process) else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self.tasks.contains_key(&task) {
            return self.discover_task(task, process, event.timestamp_ns);
        }
        let Some(previous_process) = self.tasks.get(&task).map(|state| state.process) else {
            self.record_stale_event();
            return Vec::new();
        };
        self.remove_process_member(previous_process, task);

        let process_default = *self.process_defaults.entry(process).or_default();
        self.tasks
            .insert(task, TaskState::new(task, process, event.timestamp_ns));
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

        let previous_sequence = self
            .tasks
            .get(&task)
            .map(|state| state.enqueue_sequence)
            .unwrap_or(0);
        if event.enqueue_sequence == 0 || event.enqueue_sequence <= previous_sequence {
            self.record_stale_event();
            return notices;
        }
        if let Some(accumulator) = self.behavior.get_mut(&task) {
            accumulator.observe_timestamp(event.timestamp_ns);
            accumulator.enqueue_count = accumulator.enqueue_count.saturating_add(1);
            if event.was_wakeup() {
                accumulator.wakeup_count = accumulator.wakeup_count.saturating_add(1);
                accumulator.sleep_ns = accumulator.sleep_ns.saturating_add(event.sleep_ns);
            }
        }
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Queued;
            state.enqueue_sequence = event.enqueue_sequence;
            state.enqueue_time_ns = event.timestamp_ns;
            state.previous_cpu = event.previous_cpu.or(state.previous_cpu);
            state.assigned_slice_ns = 0;
        }
        notices
    }

    fn handle_cancel(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(task) = event.task else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self.sequence_matches(task, event.enqueue_sequence) {
            self.record_stale_event();
            return Vec::new();
        }
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Blocked;
            state.assigned_slice_ns = 0;
        }
        Vec::new()
    }

    fn handle_running(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let (Some(task), Some(process), Some(actual_cpu)) =
            (event.task, event.process, event.actual_cpu)
        else {
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
        if !self.sequence_matches(task, event.enqueue_sequence) {
            self.record_stale_event();
            if let Some(accumulator) = self.behavior.get_mut(&task) {
                accumulator.bad = true;
            }
            return notices;
        }

        let (previous_cpu, enqueue_time_ns, was_queued) = self
            .tasks
            .get(&task)
            .map(|state| {
                (
                    state.previous_cpu,
                    state.enqueue_time_ns,
                    state.run_state == RunState::Queued,
                )
            })
            .unwrap_or((None, 0, false));
        let fallback_slice = self
            .task_classes
            .get(&task)
            .map(|cache| self.config.slice_for(cache.effective_class))
            .unwrap_or(self.config.balanced_slice_ns);
        let assigned_slice_ns = if event.runtime_ns == 0 {
            fallback_slice
        } else {
            event
                .runtime_ns
                .clamp(self.config.min_slice_ns, self.config.max_slice_ns)
        };
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Running;
            state.previous_cpu = Some(actual_cpu);
            state.last_start_ns = event.timestamp_ns;
            state.assigned_slice_ns = assigned_slice_ns;
        }
        if let Some(accumulator) = self.behavior.get_mut(&task) {
            accumulator.observe_timestamp(event.timestamp_ns);
            accumulator.run_count = accumulator.run_count.saturating_add(1);
            if !was_queued || enqueue_time_ns == 0 || event.timestamp_ns < enqueue_time_ns {
                accumulator.bad = true;
            }
            let wait_ns = event.timestamp_ns.saturating_sub(enqueue_time_ns);
            accumulator.runnable_wait_ns = accumulator.runnable_wait_ns.saturating_add(wait_ns);
            BehaviorAccumulator::record_histogram(&mut accumulator.wait_histogram, wait_ns);
            if previous_cpu == Some(actual_cpu) {
                accumulator.previous_cpu_hit_count =
                    accumulator.previous_cpu_hit_count.saturating_add(1);
            } else if previous_cpu.is_some() {
                accumulator.migration_count = accumulator.migration_count.saturating_add(1);
            }
        }
        notices
    }

    fn handle_stop(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(task) = event.task else {
            self.record_stale_event();
            return Vec::new();
        };
        if !self.sequence_matches(task, event.enqueue_sequence) {
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
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Blocked;
            state.assigned_slice_ns = 0;
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
        Vec::new()
    }

    fn handle_exit(&mut self, event: KernelEvent) -> Vec<EngineNotice> {
        let Some(task) = event.task else {
            self.record_stale_event();
            return Vec::new();
        };
        let mut notices = Vec::new();
        if let Some(state) = self.tasks.remove(&task) {
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

    fn sequence_matches(&self, task: TaskKey, sequence: u64) -> bool {
        sequence != 0
            && self
                .tasks
                .get(&task)
                .is_some_and(|state| state.enqueue_sequence == sequence)
    }

    fn ensure_behavior(&mut self, task: TaskKey) {
        if self.behavior.contains_key(&task) {
            return;
        }
        if let Some(state) = self.tasks.get(&task) {
            self.behavior
                .insert(task, BehaviorAccumulator::new(state.created_ns));
        }
    }

    fn quiesce_task_observation(&mut self, task: TaskKey) {
        if let Some(state) = self.tasks.get_mut(&task) {
            state.run_state = RunState::Blocked;
            state.assigned_slice_ns = 0;
        }
        self.behavior.remove(&task);
    }

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
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("unknown task identity {0:?}")]
    UnknownTask(TaskKey),
    #[error("unknown process identity {0:?}")]
    UnknownProcess(ProcessKey),
    #[error("task snapshot for {0:?} must be semantic or locked")]
    InvalidSnapshotStage(TaskKey),
    #[error("process {process:?} received stale generation {received}; current is {current}")]
    StaleProcessGeneration {
        process: ProcessKey,
        current: u64,
        received: u64,
    },
    #[error(transparent)]
    ClassUpdate(#[from] ClassUpdateError),
}

#[cfg(test)]
mod tests {
    use super::{EngineNotice, RunState, SchedulerEngine, WindowQuality};
    use crate::config::SchedulerConfig;
    use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
    use crate::process::TaskClassUpdate;
    use crate::topology::CpuTopology;
    use crate::wire::{EventKind, KernelEvent};

    fn event(kind: EventKind, tid: u32, sequence: u64) -> KernelEvent {
        KernelEvent {
            kind,
            task: TaskKey::new(tid, u64::from(tid) * 10),
            process: ProcessKey::new(10, 100, 1),
            enqueue_sequence: sequence,
            timestamp_ns: 100 + sequence * 100,
            runtime_ns: 0,
            sleep_ns: 0,
            previous_cpu: Some(0),
            actual_cpu: None,
            flags: 0,
        }
    }

    #[test]
    fn enqueue_tracks_bpf_owned_task_without_dispatch_state() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let enqueue = event(EventKind::Enqueue, 11, 1);
        let notices = engine.handle_event(enqueue);
        assert_eq!(notices.len(), 2);
        assert_eq!(
            engine.task(enqueue.task.unwrap()).unwrap().run_state,
            RunState::Queued
        );
        assert_eq!(engine.task_count(), 1);
    }

    #[test]
    fn sampled_bpf_sequence_gap_keeps_behavior_window_valid() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Enqueue, 11, 1));
        engine.handle_event(event(EventKind::Cancel, 11, 1));
        engine.handle_event(event(EventKind::Enqueue, 11, 4));
        let windows = engine.take_behavior_windows(1_000);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].quality, WindowQuality::Good);
        assert_eq!(windows[0].enqueue_count, 2);
    }

    #[test]
    fn locked_task_quiesces_and_registry_reset_resumes_observation() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let enqueue = event(EventKind::Enqueue, 11, 1);
        let task = enqueue.task.unwrap();
        let process = enqueue.process.unwrap();
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
        engine.handle_event(event(EventKind::Enqueue, 11, 2));
        assert!(engine.take_behavior_windows(1_000).is_empty());

        engine.reset_classifications(1_100);
        engine.handle_event(event(EventKind::Enqueue, 11, 3));
        assert_eq!(engine.take_behavior_windows(2_000).len(), 1);
    }

    #[test]
    fn behavior_window_contains_ordered_scheduler_facts() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let mut enqueue = event(EventKind::Enqueue, 11, 1);
        enqueue.timestamp_ns = 100;
        engine.handle_event(enqueue);

        let mut running = event(EventKind::Running, 11, 1);
        running.timestamp_ns = 200;
        running.actual_cpu = Some(0);
        running.runtime_ns = 1_000;
        engine.handle_event(running);

        let mut stop = event(EventKind::Stop, 11, 1);
        stop.timestamp_ns = 700;
        stop.actual_cpu = Some(0);
        stop.runtime_ns = 500;
        engine.handle_event(stop);

        let windows = engine.take_behavior_windows(1_000);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].quality, WindowQuality::Good);
        assert_eq!(windows[0].runnable_wait_ns, 100);
        assert_eq!(windows[0].runtime_ns, 500);
        assert_eq!(windows[0].voluntary_block_count, 1);
    }

    #[test]
    fn exec_emits_explicit_generation_notice() {
        let mut engine =
            SchedulerEngine::new(SchedulerConfig::default(), CpuTopology::flat(1)).unwrap();
        let init = event(EventKind::Init, 11, 0);
        let task = init.task.unwrap();
        let previous_process = init.process.unwrap();
        engine.handle_event(init);

        let process = ProcessKey::new(10, 100, 2).unwrap();
        let notices = engine.handle_event(KernelEvent {
            kind: EventKind::Exec,
            process: Some(process),
            ..event(EventKind::Exec, 11, 0)
        });
        assert_eq!(
            notices,
            vec![EngineNotice::ProcessExec {
                task,
                previous_process,
                process,
            }]
        );
    }

    #[test]
    fn task_capacity_marks_engine_degraded() {
        let config = SchedulerConfig {
            max_tasks: 1,
            ..SchedulerConfig::default()
        };
        let mut engine = SchedulerEngine::new(config, CpuTopology::flat(1)).unwrap();
        engine.handle_event(event(EventKind::Init, 11, 0));
        engine.handle_event(event(EventKind::Init, 12, 0));
        assert!(engine.is_degraded());
        assert_eq!(engine.stats().task_capacity_hits, 1);
    }
}
