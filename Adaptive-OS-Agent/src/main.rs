// SPDX-License-Identifier: Apache-2.0

//! Executable Agent service.
//!
//! The Agent is the sole service entry point: it starts the sched_ext
//! scheduler, owns its only control-socket connection, and keeps semantic
//! classification separate from deterministic scheduling decisions.

use std::collections::{hash_map::Entry, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use log::{debug, info, warn};
use simplelog::{ColorChoice, Config as LogConfig, LevelFilter, TermLogger, TerminalMode};

use adaptive_os_agent::behavior::BehaviorWindow;
use adaptive_os_agent::config::AgentConfig;
use adaptive_os_agent::discovery::scan_processes;
use adaptive_os_agent::identity::TaskClass;
use adaptive_os_agent::limits::RuntimeLimits;
use adaptive_os_agent::metadata::{read_process, read_task_start_time, read_threads};
use adaptive_os_agent::registry::{
    ClassificationRegistry, ProcessBatchPlan, RegistryAction, ThreadBatchPlan,
};
use adaptive_os_agent::scheduler_client::{
    ConnectionStatus, SchedulerClient, SchedulerEvent, TaskClassRequest,
};
use adaptive_os_agent::skills::{
    BehaviorClassificationSkill, DeepSeekClient, ProcessClassificationProposal,
    ProcessSemanticClassificationSkill, ThreadClassificationInput, ThreadClassificationProposal,
    ThreadSemanticClassificationSkill,
};
use adaptive_os_agent::supervisor::SchedulerSupervisor;
use adaptive_os_agent::tools::{self, ToolServer};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const MAIN_LOOP_SLEEP: Duration = Duration::from_millis(20);
const MAX_EVENTS_PER_TICK: usize = 512;
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Counts one `/proc` pass without retaining process metadata outside Registry.
#[derive(Clone, Copy, Debug)]
struct ReconcileStats {
    examined: usize,
    ordinary: usize,
    skipped: usize,
}

/// Command-line configuration for the Agent service.
#[derive(Clone, Debug, Parser)]
#[command(name = "adaptive-os-agent")]
#[command(about = "Agent service for the scx_adaptive sched_ext scheduler")]
struct Cli {
    /// Optional TOML Agent configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Scheduler executable started and supervised by this process.
    #[arg(long, default_value = "scx_adaptive")]
    scheduler_bin: PathBuf,

    /// Disable remote semantic requests and retain Balanced defaults initially.
    #[arg(long)]
    offline: bool,

    /// Write the latest scheduler control snapshot atomically to this path.
    #[arg(long)]
    snapshot_file: Option<PathBuf>,

    /// Enable debug logging in the Agent and its scheduler child.
    #[arg(long)]
    debug: bool,

    /// Validate Agent configuration without starting a scheduler or reading a secret.
    #[arg(long)]
    validate_only: bool,
}

/// Bounded semantic work item sent to one DeepSeek worker.
#[derive(Clone, Debug)]
enum ClassificationWork {
    Process {
        plan: ProcessBatchPlan,
    },
    Thread {
        plan: ThreadBatchPlan,
        threads: Vec<ThreadClassificationInput>,
    },
}

/// Classification outcome returned to the Agent main loop.
#[derive(Debug)]
enum ClassificationOutcome {
    Process {
        plan: ProcessBatchPlan,
        result: std::result::Result<Vec<ProcessClassificationProposal>, String>,
    },
    Thread {
        plan: ThreadBatchPlan,
        result: std::result::Result<Vec<ThreadClassificationProposal>, String>,
    },
}

/// Small fixed worker pool. All registry mutation remains on Agent main.
struct ClassifierPool {
    work_tx: Option<Sender<ClassificationWork>>,
    outcomes: Receiver<ClassificationOutcome>,
    workers: Vec<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl ClassifierPool {
    fn spawn(client: DeepSeekClient, workers: usize, capacity: usize) -> Result<Self> {
        let (work_tx, work_rx) = bounded(capacity);
        let (outcome_tx, outcomes) = bounded(capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(workers);
        for index in 0..workers {
            let worker_client = client.clone();
            let worker_rx = work_rx.clone();
            let worker_outcomes = outcome_tx.clone();
            let worker_shutdown = shutdown.clone();
            let handle = thread::Builder::new()
                .name(format!("adaptive-agent-llm-{index}"))
                .spawn(move || {
                    worker_loop(worker_client, worker_rx, worker_outcomes, worker_shutdown)
                })
                .context("spawn Agent semantic worker")?;
            handles.push(handle);
        }
        Ok(Self {
            work_tx: Some(work_tx),
            outcomes,
            workers: handles,
            shutdown,
        })
    }

    fn submit(&self, work: ClassificationWork) -> bool {
        let Some(work_tx) = self.work_tx.as_ref() else {
            return false;
        };
        match work_tx.try_send(work) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    fn try_recv(&self) -> Option<ClassificationOutcome> {
        self.outcomes.try_recv().ok()
    }

    fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.work_tx.take();
        let deadline = Instant::now() + WORKER_SHUTDOWN_GRACE;
        while self.workers.iter().any(|worker| !worker.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        for worker in self.workers.drain(..) {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                warn!("semantic worker did not stop within shutdown grace period");
            }
        }
    }
}

fn worker_loop(
    client: DeepSeekClient,
    work_rx: Receiver<ClassificationWork>,
    outcomes: Sender<ClassificationOutcome>,
    shutdown: Arc<AtomicBool>,
) {
    let process_skill = ProcessSemanticClassificationSkill;
    let thread_skill = ThreadSemanticClassificationSkill;
    while let Ok(work) = work_rx.recv() {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let outcome = match work {
            ClassificationWork::Process { plan } => {
                let result = process_skill
                    .propose(&client, &plan.processes)
                    .map_err(|error| format!("{error:#}"));
                ClassificationOutcome::Process { plan, result }
            }
            ClassificationWork::Thread { plan, threads } => {
                let result = thread_skill
                    .propose(&client, plan.process, &plan.metadata, &threads)
                    .map_err(|error| format!("{error:#}"));
                ClassificationOutcome::Thread { plan, result }
            }
        };
        if outcomes
            .send_timeout(outcome, Duration::from_secs(1))
            .is_err()
        {
            break;
        }
    }
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
    .context("initialize Agent logging")
}

fn install_shutdown_handler(shutdown: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || shutdown.store(true, Ordering::Release))
        .context("install Agent SIGINT/SIGTERM handler")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.debug)?;
    let config = AgentConfig::load(cli.config.as_deref())?;

    if cli.validate_only {
        info!(
            "Agent configuration valid: socket={} offline={}",
            config.scheduler_socket, cli.offline
        );
        return Ok(());
    }

    run_agent(cli, config)
}

fn run_agent(cli: Cli, config: AgentConfig) -> Result<()> {
    let limits = RuntimeLimits::default();
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_handler(shutdown.clone())?;
    let mut scheduler =
        SchedulerSupervisor::spawn(&cli.scheduler_bin, &config.scheduler_socket, cli.debug)?;
    let scheduler_pid = scheduler.pid();
    let client = SchedulerClient::spawn(
        &config.scheduler_socket,
        limits.control_queue_capacity,
        limits.max_control_frame_bytes,
    )?;
    let tools = ToolServer::spawn(
        &config.tool_socket,
        limits.tool_queue_capacity,
        limits.max_tool_frame_bytes,
        shutdown.clone(),
    )?;

    let result = (|| {
        scheduler.wait_ready(&client, READY_TIMEOUT)?;
        let mut excluded_tgids = vec![std::process::id(), scheduler_pid];
        let mut registry = ClassificationRegistry::new(limits, config.deepseek.min_confidence);
        let initial = reconcile_metadata(&mut registry, &excluded_tgids)?;
        let logical_batches = if initial.ordinary == 0 {
            0
        } else {
            initial.ordinary.div_ceil(config.deepseek.batch_size)
        };
        info!(
            "initial process discovery examined={} ordinary={} skipped={} batch_size={} logical_batches={}",
            initial.examined,
            initial.ordinary,
            initial.skipped,
            config.deepseek.batch_size,
            logical_batches
        );

        let classifiers = if cli.offline {
            None
        } else {
            Some(ClassifierPool::spawn(
                DeepSeekClient::new(config.deepseek.clone())?,
                config.deepseek.worker_count,
                limits.llm_pending_batches,
            )?)
        };

        let started = Instant::now();
        let now = started;
        let reconcile_interval = Duration::from_secs(config.reconcile_interval_secs);
        let semantic_interval = Duration::from_secs(config.behavior_window_secs);
        let snapshot_interval = Duration::from_secs(config.behavior_window_secs);
        let mut next_reconcile = now + reconcile_interval;
        let mut next_semantic = now;
        let mut next_snapshot = now;
        let mut next_sync_attempt = now;
        let mut replay_ready_epoch = 0;

        info!(
            "Agent started scheduler pid={} offline={} thread_semantic_enabled={} scheduler_socket={} tool_socket={}",
            scheduler_pid,
            cli.offline,
            config.classification.thread_semantic_enabled,
            config.scheduler_socket,
            config.tool_socket
        );

        while !shutdown.load(Ordering::Acquire) {
            if let Some(new_pid) = scheduler.check()? {
                warn!("scheduler child restarted pid={new_pid}; awaiting new epoch snapshot");
                excluded_tgids.clear();
                excluded_tgids.extend([std::process::id(), new_pid]);
                client.invalidate_synchronization();
                replay_ready_epoch = 0;
            }

            drain_scheduler_events(
                &client,
                &mut registry,
                &excluded_tgids,
                &config,
                started,
                &mut replay_ready_epoch,
            )?;
            let loop_now = Instant::now();
            if client.connected_epoch() != 0
                && replay_ready_epoch == client.connected_epoch()
                && !client.is_synchronized()
                && loop_now >= next_sync_attempt
            {
                if let Err(error) = synchronize_registry(
                    &client,
                    &mut registry,
                    ConnectionStatus {
                        scheduler_epoch: client.connected_epoch(),
                        rebuild_required: true,
                    },
                    limits.snapshot_batch_size,
                ) {
                    warn!("Registry synchronization deferred: {error:#}");
                    next_sync_attempt = loop_now + Duration::from_millis(500);
                }
            }
            if let Some(pool) = classifiers.as_ref() {
                drain_classifier_outcomes(pool, &mut registry, &client)?;
            }
            drain_tool_requests(&tools, &registry, &client);
            let pending = registry.pending_actions();
            if !pending.is_empty() && client.is_synchronized() {
                commit_actions(&client, &mut registry, pending);
            }

            let now = Instant::now();
            if now >= next_reconcile {
                let _ = reconcile_metadata(&mut registry, &excluded_tgids)?;
                next_reconcile = now + reconcile_interval;
            }
            if now >= next_semantic {
                // Classify newly discovered processes without waiting for the
                // slower full `/proc` reconciliation cadence.
                schedule_process_batches(
                    &mut registry,
                    classifiers.as_ref(),
                    &config,
                    limits.llm_pending_batches,
                    cli.offline,
                );
                schedule_thread_batches(
                    &mut registry,
                    classifiers.as_ref(),
                    &config,
                    limits.llm_pending_batches,
                    cli.offline || !config.classification.thread_semantic_enabled,
                    monotonic_elapsed_ns(started),
                );
                next_semantic = now + semantic_interval;
            }
            if let Some(path) = cli.snapshot_file.as_deref() {
                if now >= next_snapshot {
                    match client.snapshot(CONTROL_TIMEOUT) {
                        Ok(snapshot) => write_snapshot(path, &snapshot)?,
                        Err(error) => warn!("scheduler snapshot deferred: {error:#}"),
                    }
                    next_snapshot = now + snapshot_interval;
                }
            }
            thread::sleep(MAIN_LOOP_SLEEP);
        }

        if let Some(pool) = classifiers {
            pool.shutdown();
        }
        Ok(())
    })();

    shutdown.store(true, Ordering::Release);
    tools.join();
    client.shutdown();
    scheduler.stop();
    result
}

fn drain_tool_requests(
    server: &ToolServer,
    registry: &ClassificationRegistry,
    client: &SchedulerClient,
) {
    while let Some(call) = server.try_recv() {
        let scheduler_snapshot = call
            .request
            .tool
            .starts_with("scheduler.")
            .then(|| client.snapshot(CONTROL_TIMEOUT).ok())
            .flatten();
        let response = tools::execute(&call.request, registry, scheduler_snapshot.as_ref());
        call.respond(response);
    }
}

fn reconcile_metadata(
    registry: &mut ClassificationRegistry,
    excluded_tgids: &[u32],
) -> Result<ReconcileStats> {
    let snapshot = scan_processes(excluded_tgids).context("scan /proc for Agent reconciliation")?;
    let stats = ReconcileStats {
        examined: snapshot.examined,
        ordinary: snapshot.processes.len(),
        skipped: snapshot.skipped,
    };
    debug!(
        "reconciled /proc: examined={} ordinary={} skipped={}",
        stats.examined, stats.ordinary, stats.skipped
    );
    let live = snapshot.processes.keys().copied().collect();
    for metadata in snapshot.sorted_processes() {
        registry.remember_metadata(metadata);
    }
    registry.retain_live_instances(&live);
    Ok(stats)
}

fn synchronize_registry(
    client: &SchedulerClient,
    registry: &mut ClassificationRegistry,
    status: ConnectionStatus,
    batch_size: usize,
) -> Result<()> {
    if client.connected_epoch() != status.scheduler_epoch {
        anyhow::bail!("scheduler connection changed before Registry synchronization");
    }
    let snapshot_id = registry.allocate_snapshot_id();
    let batches = registry.snapshot_batches(snapshot_id, batch_size);
    let batch_count = batches.len();
    for batch in batches {
        let is_last = batch.is_last;
        let response = client.send_registry_snapshot_batch(batch, CONTROL_TIMEOUT)?;
        if response.scheduler_epoch != status.scheduler_epoch {
            anyhow::bail!("scheduler epoch changed during Registry snapshot");
        }
        if !response.ok {
            anyhow::bail!(
                "Registry snapshot rejected [{}]: {}",
                response.error_code.as_deref().unwrap_or("unknown"),
                response.error.as_deref().unwrap_or("no detail")
            );
        }
        if is_last && response.snapshot_complete != Some(true) {
            anyhow::bail!("final Registry snapshot ACK did not confirm completion");
        }
    }
    client.mark_synchronized(status.scheduler_epoch)?;
    registry.mark_snapshot_applied();
    info!(
        "Registry synchronized epoch={} batches={} rebuild_required={}",
        status.scheduler_epoch, batch_count, status.rebuild_required
    );
    Ok(())
}

fn drain_scheduler_events(
    client: &SchedulerClient,
    registry: &mut ClassificationRegistry,
    excluded_tgids: &[u32],
    config: &AgentConfig,
    started: Instant,
    replay_ready_epoch: &mut u64,
) -> Result<()> {
    for _ in 0..MAX_EVENTS_PER_TICK {
        let Some(event) = client.try_recv_event() else {
            break;
        };
        let now_ns = monotonic_elapsed_ns(started);
        let actions = match event {
            SchedulerEvent::Connected(status) => {
                client.invalidate_synchronization();
                registry.begin_scheduler_replay();
                *replay_ready_epoch = 0;
                info!(
                    "scheduler control connected epoch={} rebuild_required={}",
                    status.scheduler_epoch, status.rebuild_required
                );
                Vec::new()
            }
            SchedulerEvent::ProcessDiscovered(process) => {
                if excluded_tgids.contains(&process.tgid) {
                    Vec::new()
                } else {
                    let metadata = read_process(process.tgid).ok().flatten();
                    registry.on_process_discovered(process, metadata, now_ns)
                }
            }
            SchedulerEvent::TaskDiscovered { task, process } => {
                if excluded_tgids.contains(&process.tgid) {
                    Vec::new()
                } else {
                    let start_time = read_task_start_time(process.tgid, task.tid).ok();
                    registry.on_task_discovered_with_start_time(task, process, start_time, now_ns);
                    Vec::new()
                }
            }
            SchedulerEvent::ProcessExec {
                task,
                previous_process,
                process,
            } => {
                if excluded_tgids.contains(&process.tgid) {
                    Vec::new()
                } else {
                    let metadata = read_process(process.tgid).ok().flatten();
                    let start_time = read_task_start_time(process.tgid, task.tid).ok();
                    registry.on_process_exec(
                        task,
                        previous_process,
                        process,
                        metadata,
                        start_time,
                        now_ns,
                    )
                }
            }
            SchedulerEvent::LifecycleReplayComplete => {
                registry.finish_scheduler_replay();
                *replay_ready_epoch = client.connected_epoch();
                Vec::new()
            }
            SchedulerEvent::TaskExited { task, process } => {
                registry.on_task_exited(task, process);
                Vec::new()
            }
            SchedulerEvent::ProcessExited(process) => {
                registry.on_process_exited(process);
                Vec::new()
            }
            SchedulerEvent::BehaviorWindows {
                timestamp_ns: _,
                windows,
            } => apply_behavior_windows(registry, windows, &config.classification),
        };
        if client.is_synchronized() {
            commit_actions(client, registry, actions);
        }
    }
    Ok(())
}

fn apply_behavior_windows(
    registry: &mut ClassificationRegistry,
    windows: Vec<BehaviorWindow>,
    config: &adaptive_os_agent::config::ClassificationConfig,
) -> Vec<RegistryAction> {
    let skill = BehaviorClassificationSkill;
    let mut actions = Vec::new();
    for window in windows {
        let proposal = skill.propose(window);
        actions.extend(registry.apply_behavior_window(window, proposal, config));
    }
    actions
}

fn drain_classifier_outcomes(
    pool: &ClassifierPool,
    registry: &mut ClassificationRegistry,
    client: &SchedulerClient,
) -> Result<()> {
    while let Some(outcome) = pool.try_recv() {
        match outcome {
            ClassificationOutcome::Process { plan, result } => match result {
                Ok(proposals) => {
                    let known = proposals
                        .iter()
                        .filter(|proposal| proposal.class.is_some())
                        .count();
                    info!(
                        "semantic batch completed scope=process request_id={} items={} known={} unknown={}",
                        plan.request_id,
                        proposals.len(),
                        known,
                        proposals.len().saturating_sub(known)
                    );
                    for proposal in &proposals {
                        info!(
                            "semantic result scope=process request_id={} tgid={} start_time_ticks={} class={} confidence={:.3}",
                            plan.request_id,
                            proposal.instance.tgid,
                            proposal.instance.start_time_ticks,
                            class_label(proposal.class),
                            proposal.confidence
                        );
                    }
                    let actions = registry.apply_process_proposals(plan.request_id, proposals);
                    commit_actions(client, registry, actions);
                }
                Err(error) => {
                    warn!(
                        "semantic batch failed scope=process request_id={} items={} error={error}",
                        plan.request_id,
                        plan.processes.len()
                    );
                    registry.mark_process_batch_failed(&plan);
                }
            },
            ClassificationOutcome::Thread { plan, result } => match result {
                Ok(proposals) => {
                    let known = proposals
                        .iter()
                        .filter(|proposal| proposal.class.is_some())
                        .count();
                    info!(
                        "semantic batch completed scope=thread tgid={} items={} known={} unknown={}",
                        plan.process.tgid,
                        proposals.len(),
                        known,
                        proposals.len().saturating_sub(known)
                    );
                    for proposal in &proposals {
                        info!(
                            "semantic result scope=thread tgid={} tid={} task_cookie={} class={} confidence={:.3}",
                            proposal.process.tgid,
                            proposal.task.tid,
                            proposal.task.task_cookie,
                            class_label(proposal.class),
                            proposal.confidence
                        );
                    }
                    let actions = registry.apply_thread_proposals(proposals);
                    commit_actions(client, registry, actions);
                }
                Err(error) => {
                    warn!(
                        "semantic batch failed scope=thread tgid={} items={} error={error}",
                        plan.process.tgid,
                        plan.tasks.len()
                    );
                    registry.mark_thread_batch_failed(&plan.tasks);
                }
            },
        }
    }
    Ok(())
}

fn schedule_process_batches(
    registry: &mut ClassificationRegistry,
    pool: Option<&ClassifierPool>,
    config: &AgentConfig,
    max_batches: usize,
    offline: bool,
) {
    for plan in registry.take_process_batches(config.deepseek.batch_size, max_batches) {
        if offline {
            registry.mark_process_batch_failed(&plan);
            continue;
        }
        let submitted = pool
            .is_some_and(|pool| pool.submit(ClassificationWork::Process { plan: plan.clone() }));
        if submitted {
            info!(
                "semantic batch queued scope=process request_id={} items={}",
                plan.request_id,
                plan.processes.len()
            );
        } else {
            registry.defer_process_batch(&plan);
            debug!("process semantic worker queue is full; deferring batch");
        }
    }
}

fn class_label(class: Option<TaskClass>) -> &'static str {
    match class {
        Some(TaskClass::Latency) => "latency",
        Some(TaskClass::Balanced) => "balanced",
        Some(TaskClass::Throughput) => "throughput",
        None => "unknown",
    }
}

fn schedule_thread_batches(
    registry: &mut ClassificationRegistry,
    pool: Option<&ClassifierPool>,
    config: &AgentConfig,
    max_batches: usize,
    offline: bool,
    now_ns: u64,
) {
    let plans = registry.take_thread_batch_plans(
        now_ns,
        &config.classification,
        config.deepseek.batch_size,
        max_batches,
    );
    let mut thread_snapshots = HashMap::new();
    for plan in plans {
        if offline {
            registry.mark_thread_batch_failed(&plan.tasks);
            continue;
        }

        let snapshot = match thread_snapshots.entry(plan.process) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let snapshot = match read_threads(plan.process.tgid) {
                    Ok(threads) => Some(
                        threads
                            .into_iter()
                            .map(|thread| (thread.tid, thread))
                            .collect::<HashMap<_, _>>(),
                    ),
                    Err(error) => {
                        warn!("read threads for {} failed: {error}", plan.process.tgid);
                        None
                    }
                };
                entry.insert(snapshot)
            }
        };
        let Some(available) = snapshot.as_ref() else {
            registry.mark_thread_batch_failed(&plan.tasks);
            continue;
        };

        let mut threads = Vec::new();
        let mut missing = Vec::new();
        for task in &plan.tasks {
            match available.get(&task.tid) {
                Some(metadata) => threads.push(ThreadClassificationInput {
                    task: *task,
                    metadata: metadata.clone(),
                }),
                None => missing.push(*task),
            }
        }
        if !missing.is_empty() {
            registry.mark_thread_batch_failed(&missing);
        }
        if threads.is_empty() {
            registry.mark_thread_batch_failed(&plan.tasks);
            continue;
        }
        let item_count = threads.len();
        let submitted = pool.is_some_and(|pool| {
            pool.submit(ClassificationWork::Thread {
                plan: plan.clone(),
                threads,
            })
        });
        if submitted {
            info!(
                "semantic batch queued scope=thread tgid={} items={}",
                plan.process.tgid, item_count
            );
        } else {
            registry.defer_thread_batch(&plan.tasks);
            debug!("thread semantic worker queue is full; deferring batch");
        }
    }
}

fn commit_actions(
    client: &SchedulerClient,
    registry: &mut ClassificationRegistry,
    actions: Vec<RegistryAction>,
) {
    for action in actions {
        let response = match action {
            RegistryAction::SetProcessDefault {
                request_id,
                process,
                class,
                expected_generation,
                new_generation,
            } => client.set_process_default(
                request_id,
                process,
                class,
                expected_generation,
                new_generation,
                CONTROL_TIMEOUT,
            ),
            RegistryAction::SetTaskClass {
                request_id,
                task,
                process,
                class,
                stage,
                expected_generation,
                new_generation,
            } => {
                let update = TaskClassRequest {
                    request_id,
                    task,
                    process,
                    class,
                    expected_generation,
                    new_generation,
                };
                match stage {
                    adaptive_os_agent::identity::ClassStage::Semantic => {
                        client.set_task_provisional(update, CONTROL_TIMEOUT)
                    }
                    adaptive_os_agent::identity::ClassStage::Locked => {
                        client.lock_task_class(update, CONTROL_TIMEOUT)
                    }
                    adaptive_os_agent::identity::ClassStage::Inherited => Err(anyhow::anyhow!(
                        "Registry emitted an inherited task override"
                    )),
                }
            }
        };

        match response {
            Ok(response) if response.ok => {
                let applied = response.applied_generation.unwrap_or(0);
                if registry.acknowledge(action, applied) {
                    log_committed_action(action);
                } else {
                    warn!("scheduler ACK did not match the current pending Registry action");
                    client.invalidate_synchronization();
                    break;
                }
            }
            Ok(response) if response.error_code.as_deref() == Some("unknown_identity") => {
                let removed = registry.reject_unknown_identity(action);
                debug!(
                    "discarded classification for scheduler-confirmed exited identity removed={removed} action={action:?}"
                );
            }
            Ok(response) => {
                warn!(
                    "scheduler rejected classification [{}]: {}",
                    response.error_code.as_deref().unwrap_or("unknown"),
                    response.error.as_deref().unwrap_or("no detail")
                );
                client.invalidate_synchronization();
                break;
            }
            Err(error) => {
                warn!("scheduler control update was not committed: {error:#}");
                client.invalidate_synchronization();
                break;
            }
        }
    }
}

fn log_committed_action(action: RegistryAction) {
    match action {
        RegistryAction::SetProcessDefault {
            process,
            class,
            new_generation,
            ..
        } => info!(
            "classification committed scope=process tgid={} process_cookie={} exec_generation={} class={class:?} generation={new_generation}",
            process.tgid, process.process_cookie, process.exec_generation
        ),
        RegistryAction::SetTaskClass {
            task,
            process,
            class,
            stage,
            new_generation,
            ..
        } => info!(
            "classification committed scope=task tgid={} process_cookie={} exec_generation={} tid={} task_cookie={} class={class:?} stage={stage:?} generation={new_generation}",
            process.tgid,
            process.process_cookie,
            process.exec_generation,
            task.tid,
            task.task_cookie
        ),
    }
}

fn monotonic_elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn write_snapshot(path: &Path, snapshot: &serde_json::Value) -> Result<()> {
    let parent = path
        .parent()
        .context("snapshot path must have a parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create snapshot directory {}", parent.display()))?;
    let temp = path.with_extension("tmp");
    let encoded = serde_json::to_vec_pretty(snapshot).context("encode scheduler snapshot")?;
    fs::write(&temp, encoded).with_context(|| format!("write snapshot {}", temp.display()))?;
    fs::rename(&temp, path)
        .with_context(|| format!("atomically publish snapshot {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_snapshot;

    /// Snapshot publication writes valid JSON at the requested final path.
    #[test]
    fn publishes_snapshot_atomically() {
        let path = std::env::temp_dir().join(format!(
            "adaptive-agent-snapshot-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        write_snapshot(
            &path,
            &serde_json::json!({"data_plane": {"max_normal_staged_depth": 1}}),
        )
        .unwrap();
        let decoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(decoded["data_plane"]["max_normal_staged_depth"], 1);
        std::fs::remove_file(path).unwrap();
    }
}
