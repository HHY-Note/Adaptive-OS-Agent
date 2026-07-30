// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Read;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_adaptive::bpf::{monotonic_now_ns, BpfRuntime};
use scx_adaptive::config::SchedulerConfig;
use scx_adaptive::control::{
    ControlEnvelope, ControlHandle, ControlRequest, ControlSnapshot, ProcessSnapshot,
    SchedulerMessage, TaskSnapshot, DEFAULT_CONTROL_SOCKET,
};
use scx_adaptive::engine::{EngineNotice, SchedulerEngine};
use scx_adaptive::identity::{ClassStage, ProcessKey, TaskKey};
use scx_adaptive::policy::{aggregate_runtime_ns, PolicyController, PolicyObservation};
use scx_adaptive::process::{
    ProcessClassUpdate, ProcessDefaultCache, TaskClassCache, TaskClassUpdate,
};
use scx_adaptive::topology::CpuTopology;
use simplelog::{ColorChoice, Config as LogConfig, LevelFilter, TermLogger, TerminalMode};

const EVENT_BATCH_LIMIT: usize = 4096;
const LIFECYCLE_REPLAY_BATCH_LIMIT: usize = 128;
const MAX_PENDING_CONTROL_EVENTS: usize = EVENT_BATCH_LIMIT * 2;
const BEHAVIOR_REPORT_INTERVAL_NS: u64 = 1_000_000_000;
const MAX_CONSECUTIVE_OVERFLOW_WINDOWS: u32 = 3;
const AGENT_WATCH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, Parser)]
#[command(name = "scx_adaptive")]
#[command(about = "Agent-classified sched_ext userspace scheduler")]
struct Cli {
    /// Agent TGID placed on the BPF safe path and monitored for exit.
    #[arg(long, default_value_t = 0)]
    agent_pid: u32,

    /// Unix socket used by the local Agent control connection.
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET)]
    control_socket: String,

    /// Enable libbpf and scheduler debug logging.
    #[arg(long)]
    debug: bool,

    /// Validate configuration/topology and exit without loading BPF.
    #[arg(long)]
    validate_only: bool,
}

fn init_logging(debug_enabled: bool) -> Result<()> {
    let level = if debug_enabled {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    TermLogger::init(
        level,
        LogConfig::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .context("initialize terminal logger")
}

fn install_shutdown_handler(shutdown: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || shutdown.store(true, Ordering::Release))
        .context("install SIGINT/SIGTERM handler")
}

fn handle_notices(
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
    pending: &mut VecDeque<SchedulerMessage>,
    publish_events: bool,
    notices: Vec<EngineNotice>,
) {
    for notice in notices {
        let message = match notice {
            EngineNotice::ProcessDiscovered(process) => {
                debug!("discovered process {process:?}; defaulting to Balanced");
                Some(SchedulerMessage::ProcessDiscovered { process })
            }
            EngineNotice::TaskDiscovered { task, process } => {
                debug!("discovered task {task:?} in process {process:?}");
                mirror_current_task_control(engine, bpf, task);
                Some(SchedulerMessage::TaskDiscovered { task, process })
            }
            EngineNotice::ProcessExec {
                task,
                previous_process,
                process,
            } => {
                debug!("task {task:?} exec changed {previous_process:?} to {process:?}");
                mirror_current_task_control(engine, bpf, task);
                Some(SchedulerMessage::ProcessExec {
                    task,
                    previous_process,
                    process,
                })
            }
            EngineNotice::TaskExited { task, process } => {
                Some(SchedulerMessage::TaskExited { task, process })
            }
            EngineNotice::ProcessExited(process) => {
                Some(SchedulerMessage::ProcessExited { process })
            }
        };
        if publish_events {
            pending.extend(message);
        }
    }
}

fn mirror_current_task_control(engine: &SchedulerEngine, bpf: &BpfRuntime<'_>, task: TaskKey) {
    let Some(cache) = engine.task_class(task).copied() else {
        warn!("cannot mirror missing task control for {task:?}");
        return;
    };
    if let Err(error) = bpf.update_task_control(task, cache) {
        warn!("failed to mirror task control for {task:?}: {error:#}");
    }
}

fn publish_pending_events(
    control: &ControlHandle,
    pending: &mut VecDeque<SchedulerMessage>,
) -> bool {
    let mut published = false;
    while let Some(message) = pending.front().cloned() {
        if !control.try_publish(message) {
            break;
        }
        pending.pop_front();
        published = true;
    }
    published
}

fn publish_lifecycle_replay(
    control: &ControlHandle,
    notices: &mut VecDeque<EngineNotice>,
    complete_pending: &mut bool,
) {
    for _ in 0..LIFECYCLE_REPLAY_BATCH_LIMIT {
        let Some(notice) = notices.pop_front() else {
            break;
        };
        let message = match notice {
            EngineNotice::ProcessDiscovered(process) => {
                SchedulerMessage::ProcessDiscovered { process }
            }
            EngineNotice::TaskDiscovered { task, process } => {
                SchedulerMessage::TaskDiscovered { task, process }
            }
            _ => continue,
        };
        if !control.try_publish(message) {
            notices.push_front(notice);
            return;
        }
    }
    if notices.is_empty()
        && *complete_pending
        && control.try_publish(SchedulerMessage::LifecycleReplayComplete)
    {
        *complete_pending = false;
    }
}

fn rollback_task_controls(bpf: &BpfRuntime<'_>, previous: &[(TaskKey, TaskClassCache)]) {
    for (task, cache) in previous {
        if let Err(error) = bpf.update_task_control(*task, *cache) {
            warn!("failed to roll back BPF task control for {task:?}: {error:#}");
        }
    }
}

fn apply_process_update(
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
    update: ProcessClassUpdate,
) -> Result<()> {
    let affected = engine.inherited_tasks(update.process);
    let previous: Vec<_> = affected
        .iter()
        .filter_map(|task| engine.task_class(*task).map(|cache| (*task, *cache)))
        .collect();
    let mut written = Vec::new();
    for (task, previous_cache) in &previous {
        let next = TaskClassCache {
            effective_class: update.class,
            class_generation: update.class_generation,
            ..*previous_cache
        };
        if let Err(error) = bpf.update_task_control(*task, next) {
            rollback_task_controls(bpf, &written);
            return Err(error).context("mirror process scheduling control into BPF");
        }
        written.push((*task, *previous_cache));
    }
    if let Err(error) = engine.apply_process_class_update(update) {
        rollback_task_controls(bpf, &written);
        return Err(error.into());
    }
    Ok(())
}

fn apply_task_update(
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
    update: TaskClassUpdate,
) -> Result<()> {
    let previous = *engine
        .task_class(update.task)
        .with_context(|| format!("unknown task identity {:?}", update.task))?;
    let mut validation = previous;
    validation.apply(update.task, update)?;
    bpf.update_task_control(update.task, validation)?;
    if let Err(error) = engine.apply_task_class_update(update) {
        let _ = bpf.update_task_control(update.task, previous);
        return Err(error.into());
    }
    Ok(())
}

#[derive(Default)]
struct RegistrySyncState {
    ready: bool,
    snapshot_id: Option<u64>,
    next_batch: u32,
}

impl RegistrySyncState {
    fn begin(
        &mut self,
        snapshot_id: u64,
        batch_index: u32,
        engine: &mut SchedulerEngine,
        bpf: &BpfRuntime<'_>,
    ) -> Result<()> {
        if snapshot_id == 0 || batch_index != 0 {
            anyhow::bail!("a Registry snapshot must start at batch zero with a non-zero id");
        }
        reset_classifications(engine, bpf)?;
        self.ready = false;
        self.snapshot_id = Some(snapshot_id);
        self.next_batch = 0;
        Ok(())
    }

    fn validate_batch(&self, snapshot_id: u64, batch_index: u32) -> Result<()> {
        if self.snapshot_id != Some(snapshot_id) || self.next_batch != batch_index {
            anyhow::bail!(
                "Registry snapshot batch is out of order: expected id={:?} batch={}, received id={} batch={}",
                self.snapshot_id,
                self.next_batch,
                snapshot_id,
                batch_index
            );
        }
        Ok(())
    }

    fn committed(&mut self, is_last: bool) {
        self.next_batch = self.next_batch.saturating_add(1);
        if is_last {
            self.ready = true;
            self.snapshot_id = None;
            self.next_batch = 0;
        }
    }
}

fn reset_classifications(engine: &mut SchedulerEngine, bpf: &BpfRuntime<'_>) -> Result<()> {
    let previous = engine.task_controls();
    let mut written = Vec::new();
    for (task, cache) in &previous {
        let reset = TaskClassCache::inherited(cache.process, ProcessDefaultCache::default());
        if let Err(error) = bpf.update_task_control(*task, reset) {
            rollback_task_controls(bpf, &written);
            return Err(error).context("reset BPF task control for Registry rebuild");
        }
        written.push((*task, *cache));
    }
    engine.reset_classifications(monotonic_now_ns()?);
    Ok(())
}

fn restore_process_snapshot(
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
    snapshot: ProcessSnapshot,
) -> Result<()> {
    if engine.process_default(snapshot.process).is_none() {
        return Ok(());
    }
    let affected = engine.inherited_tasks(snapshot.process);
    let previous: Vec<_> = affected
        .iter()
        .filter_map(|task| engine.task_class(*task).map(|cache| (*task, *cache)))
        .collect();
    let mut written = Vec::new();
    for (task, previous_cache) in &previous {
        let next = TaskClassCache {
            effective_class: snapshot.class,
            class_generation: snapshot.class_generation,
            ..*previous_cache
        };
        if let Err(error) = bpf.update_task_control(*task, next) {
            rollback_task_controls(bpf, &written);
            return Err(error).context("restore process snapshot control in BPF");
        }
        written.push((*task, *previous_cache));
    }
    if let Err(error) =
        engine.restore_process_class(snapshot.process, snapshot.class, snapshot.class_generation)
    {
        rollback_task_controls(bpf, &written);
        return Err(error.into());
    }
    Ok(())
}

fn restore_task_snapshot(
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
    snapshot: TaskSnapshot,
) -> Result<()> {
    let Some(previous) = engine.task_class(snapshot.task).copied() else {
        return Ok(());
    };
    if previous.process != snapshot.process {
        return Ok(());
    }
    let restored = TaskClassCache {
        process: snapshot.process,
        effective_class: snapshot.class,
        stage: snapshot.stage,
        class_generation: snapshot.class_generation,
    };
    bpf.update_task_control(snapshot.task, restored)?;
    if let Err(error) = engine.restore_task_class(
        snapshot.task,
        snapshot.process,
        snapshot.class,
        snapshot.stage,
        snapshot.class_generation,
    ) {
        let _ = bpf.update_task_control(snapshot.task, previous);
        return Err(error.into());
    }
    Ok(())
}

fn validate_increment(current: u64, expected: u64, new: u64) -> Result<()> {
    if new
        != expected
            .checked_add(1)
            .context("classification generation overflow")?
    {
        anyhow::bail!("new_generation must equal expected_generation + 1");
    }
    if current != expected {
        anyhow::bail!("expected generation {expected}, scheduler currently has {current}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_control_request(
    envelope: &ControlEnvelope,
    expected_agent_pid: u32,
    scheduler_epoch: u64,
    config: &SchedulerConfig,
    sync: &mut RegistrySyncState,
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
    policy: &PolicyController,
    control: &ControlHandle,
) -> SchedulerMessage {
    let request_id = envelope.request_id;
    if !matches!(envelope.request, ControlRequest::Hello { .. })
        && envelope.scheduler_epoch != scheduler_epoch
    {
        return SchedulerMessage::failure(
            request_id,
            "epoch_mismatch",
            "request names a different scheduler epoch",
            None,
        );
    }

    match &envelope.request {
        ControlRequest::Hello {
            agent_pid,
            known_scheduler_epoch,
        } => {
            if *agent_pid != expected_agent_pid {
                return SchedulerMessage::failure(
                    request_id,
                    "agent_identity",
                    "Hello agent_pid does not match scheduler supervisor identity",
                    None,
                );
            }
            SchedulerMessage::hello_success(
                request_id,
                *known_scheduler_epoch != scheduler_epoch || !sync.ready,
            )
        }
        ControlRequest::RegistrySnapshotBatch {
            snapshot_id,
            batch_index,
            is_last,
            processes,
            tasks,
        } => {
            if processes.len().saturating_add(tasks.len()) > config.max_snapshot_items {
                return SchedulerMessage::failure(
                    request_id,
                    "snapshot_too_large",
                    "Registry snapshot batch exceeds configured item limit",
                    None,
                );
            }
            let result = (|| {
                if *batch_index == 0 {
                    sync.begin(*snapshot_id, *batch_index, engine, bpf)?;
                }
                sync.validate_batch(*snapshot_id, *batch_index)?;
                let mut process_keys = HashSet::new();
                for snapshot in processes {
                    if !process_keys.insert(snapshot.process) {
                        anyhow::bail!("duplicate process identity in Registry snapshot batch");
                    }
                    restore_process_snapshot(engine, bpf, *snapshot)?;
                }
                let mut task_keys = HashSet::new();
                for snapshot in tasks {
                    if !task_keys.insert(snapshot.task) {
                        anyhow::bail!("duplicate task identity in Registry snapshot batch");
                    }
                    restore_task_snapshot(engine, bpf, *snapshot)?;
                }
                sync.committed(*is_last);
                Ok(())
            })();
            match result {
                Ok(()) => SchedulerMessage::snapshot_success(request_id, *is_last),
                Err(error) => SchedulerMessage::failure(
                    request_id,
                    "snapshot_rejected",
                    format!("{error:#}"),
                    None,
                ),
            }
        }
        ControlRequest::GetSnapshot => {
            let result = bpf.data_plane_stats().map(|data_plane| ControlSnapshot {
                scheduler_epoch,
                registry_ready: sync.ready,
                degraded: engine.is_degraded(),
                control_connected: control.connected(),
                control_messages_dropped: control.dropped_messages(),
                scheduler: engine.stats().clone(),
                data_plane,
                policy: policy.status(),
                cpu_count: engine.cpu_count(),
                tasks: engine.task_count(),
            });
            match result {
                Ok(snapshot) => SchedulerMessage::snapshot(request_id, snapshot),
                Err(error) => SchedulerMessage::failure(
                    request_id,
                    "snapshot_failed",
                    format!("{error:#}"),
                    None,
                ),
            }
        }
        ControlRequest::SetProcessDefault {
            process,
            class,
            expected_generation,
            new_generation,
        } => {
            if !sync.ready {
                return not_ready(request_id);
            }
            let Some(current) = engine.process_default(*process).copied() else {
                return unknown_identity(request_id, "process");
            };
            if let Err(error) = validate_increment(
                current.class_generation,
                *expected_generation,
                *new_generation,
            ) {
                return generation_failure(request_id, error, current.class_generation);
            }
            match apply_process_update(
                engine,
                bpf,
                ProcessClassUpdate {
                    process: *process,
                    class: *class,
                    class_generation: *new_generation,
                },
            ) {
                Ok(()) => SchedulerMessage::generation_success(request_id, *new_generation),
                Err(error) => apply_failure(request_id, error),
            }
        }
        ControlRequest::SetTaskProvisional {
            task,
            process,
            class,
            expected_generation,
            new_generation,
        } => apply_incremental_task(
            request_id,
            sync.ready,
            *task,
            *process,
            *class,
            ClassStage::Semantic,
            *expected_generation,
            *new_generation,
            engine,
            bpf,
        ),
        ControlRequest::LockTaskClass {
            task,
            process,
            class,
            expected_generation,
            new_generation,
        } => apply_incremental_task(
            request_id,
            sync.ready,
            *task,
            *process,
            *class,
            ClassStage::Locked,
            *expected_generation,
            *new_generation,
            engine,
            bpf,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_incremental_task(
    request_id: u64,
    registry_ready: bool,
    task: TaskKey,
    process: ProcessKey,
    class: scx_adaptive::identity::TaskClass,
    stage: ClassStage,
    expected_generation: u64,
    new_generation: u64,
    engine: &mut SchedulerEngine,
    bpf: &BpfRuntime<'_>,
) -> SchedulerMessage {
    if !registry_ready {
        return not_ready(request_id);
    }
    let Some(current) = engine.task_class(task).copied() else {
        return unknown_identity(request_id, "task");
    };
    if let Err(error) = validate_increment(
        current.class_generation,
        expected_generation,
        new_generation,
    ) {
        return generation_failure(request_id, error, current.class_generation);
    }
    match apply_task_update(
        engine,
        bpf,
        TaskClassUpdate {
            task,
            process,
            class,
            stage,
            class_generation: new_generation,
        },
    ) {
        Ok(()) => SchedulerMessage::generation_success(request_id, new_generation),
        Err(error) => apply_failure(request_id, error),
    }
}

fn not_ready(request_id: u64) -> SchedulerMessage {
    SchedulerMessage::failure(
        request_id,
        "registry_not_ready",
        "Registry snapshot has not completed for this scheduler epoch",
        None,
    )
}

fn unknown_identity(request_id: u64, kind: &str) -> SchedulerMessage {
    SchedulerMessage::failure(
        request_id,
        "unknown_identity",
        format!("{kind} identity is no longer live"),
        None,
    )
}

fn generation_failure(request_id: u64, error: anyhow::Error, current: u64) -> SchedulerMessage {
    SchedulerMessage::failure(
        request_id,
        "generation_mismatch",
        error.to_string(),
        Some(current),
    )
}

fn apply_failure(request_id: u64, error: anyhow::Error) -> SchedulerMessage {
    SchedulerMessage::failure(request_id, "apply_failed", format!("{error:#}"), None)
}

struct ResponseCache {
    capacity: usize,
    entries: HashMap<u64, (ControlRequest, SchedulerMessage)>,
    order: VecDeque<u64>,
}

impl ResponseCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn lookup(&self, envelope: &ControlEnvelope) -> Option<SchedulerMessage> {
        let (request, response) = self.entries.get(&envelope.request_id)?;
        Some(if request == &envelope.request {
            response.clone()
        } else {
            SchedulerMessage::failure(
                envelope.request_id,
                "request_id_collision",
                "request_id was already used for a different payload",
                None,
            )
        })
    }

    fn insert(&mut self, envelope: &ControlEnvelope, response: &SchedulerMessage) {
        if !response.is_success() || self.entries.contains_key(&envelope.request_id) {
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(id) = self.order.pop_front() {
                self.entries.remove(&id);
            }
        }
        self.order.push_back(envelope.request_id);
        self.entries.insert(
            envelope.request_id,
            (envelope.request.clone(), response.clone()),
        );
    }
}

struct AgentWatch {
    pid: u32,
    start_time_ticks: u64,
    next_check: Instant,
    missing_since: Option<Instant>,
}

impl AgentWatch {
    fn new(pid: u32) -> Result<Self> {
        if pid == 0 {
            anyhow::bail!("--agent-pid must be non-zero outside --validate-only");
        }
        Ok(Self {
            pid,
            start_time_ticks: read_process_start_time(pid)
                .with_context(|| format!("read Agent process identity for PID {pid}"))?,
            next_check: Instant::now() + AGENT_WATCH_INTERVAL,
            missing_since: None,
        })
    }

    fn expired(&mut self, grace: Duration) -> bool {
        let now = Instant::now();
        if now >= self.next_check {
            self.next_check = now + AGENT_WATCH_INTERVAL;
            let same_process = read_process_start_time(self.pid)
                .is_ok_and(|start_time| start_time == self.start_time_ticks);
            if same_process {
                self.missing_since = None;
            } else {
                self.missing_since.get_or_insert(now);
            }
        }
        self.missing_since
            .is_some_and(|since| now.duration_since(since) >= grace)
    }
}

fn read_process_start_time(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .context("malformed /proc stat command field")?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .context("missing /proc stat starttime")?
        .parse()
        .context("parse /proc stat starttime")
}

fn generate_scheduler_epoch() -> Result<u64> {
    let mut bytes = [0_u8; 8];
    fs::File::open("/dev/urandom")
        .context("open /dev/urandom for scheduler epoch")?
        .read_exact(&mut bytes)
        .context("read scheduler epoch")?;
    let epoch = u64::from_ne_bytes(bytes);
    Ok(if epoch == 0 { 1 } else { epoch })
}

fn run_scheduler(
    cli: &Cli,
    config: SchedulerConfig,
    topology: CpuTopology,
    scheduler_epoch: u64,
) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_handler(shutdown.clone())?;
    let mut agent_watch = AgentWatch::new(cli.agent_pid)?;
    let mut policy = PolicyController::new(&config, &topology, monotonic_now_ns()?)
        .context("build initial topology policy")?;

    let mut open_object = MaybeUninit::<OpenObject>::uninit();
    let mut bpf = BpfRuntime::load(
        &mut open_object,
        &config,
        &topology,
        policy.snapshot(),
        cli.agent_pid,
        cli.debug,
    )
    .context("load and attach scx_adaptive BPF scheduler")?;
    let mut engine = SchedulerEngine::new(config.clone(), topology)?;
    let control = ControlHandle::spawn(
        &cli.control_socket,
        config.control_queue_capacity,
        config.max_control_frame_bytes,
        scheduler_epoch,
        shutdown.clone(),
    )
    .context("start Agent control socket")?;
    info!("scx_adaptive attached epoch={scheduler_epoch}; unclassified tasks use Balanced");

    let mut sync = RegistrySyncState::default();
    let mut response_cache = ResponseCache::new(config.response_cache_capacity);
    let mut lifecycle_replay = VecDeque::new();
    let mut replay_complete_pending = false;
    let mut pending_events = VecDeque::new();
    let mut next_behavior_report_ns =
        monotonic_now_ns()?.saturating_add(BEHAVIOR_REPORT_INTERVAL_NS);
    let mut last_event_overflows = 0;
    let mut overflow_windows = 0_u32;

    while !shutdown.load(Ordering::Acquire) && !bpf.exited() {
        if agent_watch.expired(config.agent_exit_grace) {
            warn!("Agent exited; detaching sched_ext after configured grace period");
            break;
        }

        let policy_now_ns = monotonic_now_ns()?;
        if policy.lease_refresh_due(policy_now_ns) {
            policy.renew_lease(policy_now_ns);
            bpf.renew_policy_lease(policy.snapshot())?;
        }

        let mut did_work = false;

        if lifecycle_replay.is_empty() && !replay_complete_pending && pending_events.is_empty() {
            for _ in 0..EVENT_BATCH_LIMIT {
                let Some(event) = bpf.pop_event()? else {
                    break;
                };
                did_work = true;
                let notices = engine.handle_event(event);
                handle_notices(
                    &mut engine,
                    &bpf,
                    &mut pending_events,
                    control.connected(),
                    notices,
                );
                if engine.is_degraded() || pending_events.len() >= MAX_PENDING_CONTROL_EVENTS {
                    break;
                }
            }
        }

        while let Some(envelope) = control.try_recv() {
            did_work = true;
            if let Some(response) = response_cache.lookup(&envelope) {
                let start_replay = matches!(envelope.request, ControlRequest::Hello { .. })
                    && response.is_success();
                if control.try_publish(response) && start_replay {
                    pending_events.clear();
                    lifecycle_replay = engine.lifecycle_notices().into();
                    replay_complete_pending = true;
                }
                continue;
            }
            let start_replay = matches!(envelope.request, ControlRequest::Hello { .. });
            let response = apply_control_request(
                &envelope,
                cli.agent_pid,
                scheduler_epoch,
                &config,
                &mut sync,
                &mut engine,
                &bpf,
                &policy,
                &control,
            );
            response_cache.insert(&envelope, &response);
            let succeeded = response.is_success();
            if control.try_publish(response) && start_replay && succeeded {
                pending_events.clear();
                lifecycle_replay = engine.lifecycle_notices().into();
                replay_complete_pending = true;
            }
        }

        if !lifecycle_replay.is_empty() || replay_complete_pending {
            did_work = true;
            publish_lifecycle_replay(
                &control,
                &mut lifecycle_replay,
                &mut replay_complete_pending,
            );
        } else if publish_pending_events(&control, &mut pending_events) {
            did_work = true;
        }

        if engine.is_degraded() {
            warn!("scheduler entered degraded state after reaching a runtime capacity; detaching");
            break;
        }

        let now_ns = monotonic_now_ns()?;
        if lifecycle_replay.is_empty()
            && !replay_complete_pending
            && now_ns >= next_behavior_report_ns
        {
            if let Ok(stats) = bpf.data_plane_stats() {
                if stats.event_overflows != last_event_overflows {
                    engine.mark_behavior_gap();
                    overflow_windows = overflow_windows.saturating_add(1);
                    last_event_overflows = stats.event_overflows;
                } else {
                    overflow_windows = 0;
                }
                if let Ok(cpu_pressure) = bpf.cpu_pressure(engine.cpu_count()) {
                    let observation = PolicyObservation {
                        runtime_ns_by_class: aggregate_runtime_ns(&cpu_pressure),
                        dispatches_by_class: stats.fast_path_dispatches_by_class,
                        preemptions_by_class: stats.fast_path_preemptions_by_class,
                        preemption_throttles: stats.fast_path_preemption_throttles,
                        latency_backlog_boosts: stats.fast_path_latency_backlog_boosts,
                        latency_budget_charge_events: stats.fast_path_latency_budget_charge_events,
                        latency_budget_runtime_ns: stats.fast_path_latency_budget_runtime_ns,
                    };
                    if policy.observe(now_ns, observation, &cpu_pressure) {
                        bpf.publish_policy(policy.snapshot())
                            .context("publish runtime-adapted scheduler policy")?;
                        debug!(
                            "policy generation={} latency_share_per_mille={} budget={}pct service={}ns successor_lease={}ns preemption_floor={}ns preemption_interval={}ns balanced_granularity={}ns balanced_preemption_rate={}permille",
                            policy.status().generation,
                            policy.status().last_latency_share_per_mille,
                            policy.status().latency_budget_percent,
                            policy.status().observed_latency_service_ns,
                            policy.status().latency_successor_lease_ns,
                            policy.status().preemption_interval_floor_ns,
                            policy.status().preemption_interval_ns,
                            policy.status().balanced_preemption_granularity_ns,
                            policy.status().last_balanced_preemption_rate_per_mille,
                        );
                    }
                }
            }
            if overflow_windows >= MAX_CONSECUTIVE_OVERFLOW_WINDOWS {
                warn!("persistent BPF event overflow made scheduler state unreliable; detaching");
                break;
            }
            let windows = engine.take_behavior_windows(now_ns);
            if !windows.is_empty() && control.connected() {
                pending_events.push_back(SchedulerMessage::TaskStatsBatch {
                    timestamp_ns: now_ns,
                    windows,
                });
            }
            next_behavior_report_ns = now_ns.saturating_add(BEHAVIOR_REPORT_INTERVAL_NS);
        }

        if !did_work {
            thread::sleep(config.poll_interval);
        } else {
            thread::yield_now();
        }
    }

    let data_stats = bpf.data_plane_stats().unwrap_or_default();
    let scheduler_stats = engine.stats().clone();
    if bpf.exited() {
        if let Err(error) = bpf.report_exit() {
            warn!("sched_ext BPF exit: {error:#}");
        }
    }
    shutdown.store(true, Ordering::Release);
    bpf.detach();
    control.join();
    info!(
        "detached: events={} fast_enqueues={} fast_dispatches={} fallbacks={}",
        scheduler_stats.events_processed,
        data_stats.fast_path_enqueues,
        data_stats.fast_path_dispatches,
        data_stats.fallback_dispatches,
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.debug)?;

    let config = SchedulerConfig::default();
    config
        .validate()
        .context("validate scheduler configuration")?;
    let topology = CpuTopology::discover().context("discover CPU/core/LLC topology")?;

    if cli.validate_only {
        info!(
            "configuration valid: cpus={} domains={} slices={}/{}/{} ns tasks={} frame={}",
            topology.cpu_count(),
            topology.domain_count(),
            config.latency_slice_ns,
            config.balanced_slice_ns,
            config.throughput_slice_ns,
            config.max_tasks,
            config.max_control_frame_bytes,
        );
        return Ok(());
    }

    let scheduler_epoch = generate_scheduler_epoch()?;
    run_scheduler(&cli, config, topology, scheduler_epoch)
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{read_process_start_time, validate_increment, AgentWatch, ResponseCache};

    #[test]
    fn reads_current_process_start_time() {
        assert!(read_process_start_time(std::process::id()).unwrap() > 0);
    }

    #[test]
    fn response_cache_is_bounded() {
        let cache = ResponseCache::new(2);
        assert_eq!(cache.capacity, 2);
    }

    #[test]
    fn generation_increment_requires_exact_compare_and_swap() {
        assert!(validate_increment(4, 4, 5).is_ok());
        assert!(validate_increment(4, 3, 4).is_err());
        assert!(validate_increment(4, 4, 6).is_err());
        assert!(validate_increment(u64::MAX, u64::MAX, 0).is_err());
    }

    #[test]
    fn agent_watch_detaches_only_after_the_missing_grace() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let mut watch = AgentWatch::new(child.id()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();

        watch.next_check = Instant::now();
        assert!(!watch.expired(Duration::from_millis(10)));
        thread::sleep(Duration::from_millis(20));
        watch.next_check = Instant::now();
        assert!(watch.expired(Duration::from_millis(10)));
    }
}
