// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, versioned Agent control transport.
//!
//! The socket thread only frames, validates, and forwards typed messages. It
//! never owns or mutates scheduler policy state.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bpf::DataPlaneStats;
use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
use crate::stats::{SchedulerStats, TaskBehaviorWindow};

/// Default local Agent/scheduler control socket.
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/scx_adaptive.sock";
/// First stable version of the length-prefixed control protocol.
pub const PROTOCOL_VERSION: u16 = 1;
/// Smallest useful frame limit, including the JSON envelope.
const MIN_FRAME_BYTES: usize = 256;
/// Bytes used by the network-order frame-length prefix.
const FRAME_PREFIX_BYTES: usize = std::mem::size_of::<u32>();

/// Process classification restored at the start of one scheduler epoch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessSnapshot {
    /// Exact process image receiving the default.
    pub process: ProcessKey,
    /// Agent-owned inherited class.
    pub class: TaskClass,
    /// Current Agent generation; snapshots may start above zero.
    pub class_generation: u64,
}

/// Task classification restored at the start of one scheduler epoch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskSnapshot {
    /// Exact task lifetime receiving the class.
    pub task: TaskKey,
    /// Exact owning process image.
    pub process: ProcessKey,
    /// Effective semantic or locked class.
    pub class: TaskClass,
    /// Semantic or permanently locked stage.
    pub stage: ClassStage,
    /// Current Agent generation; snapshots may start above zero.
    pub class_generation: u64,
}

/// Request accepted by the scheduler engine owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlRequest {
    /// Establishes one connection and reports whether state rebuild is needed.
    Hello {
        /// Connecting Agent process ID.
        agent_pid: u32,
        /// Epoch fully synchronized by the Agent before this connection.
        known_scheduler_epoch: u64,
    },
    /// Restores a bounded slice of the Agent classification Registry.
    RegistrySnapshotBatch {
        /// Non-zero identity shared by every batch in this snapshot.
        snapshot_id: u64,
        /// Zero-based contiguous batch index.
        batch_index: u32,
        /// True only for the final batch, including an empty snapshot.
        is_last: bool,
        /// Process defaults in this batch.
        processes: Vec<ProcessSnapshot>,
        /// Semantic or locked task overrides in this batch.
        tasks: Vec<TaskSnapshot>,
    },
    /// Updates one process default using an exact compare-and-swap generation.
    SetProcessDefault {
        /// Exact process image receiving the classification.
        process: ProcessKey,
        /// New process default.
        class: TaskClass,
        /// Generation scheduler must currently hold.
        expected_generation: u64,
        /// Exactly `expected_generation + 1`.
        new_generation: u64,
    },
    /// Applies one provisional thread-semantic classification.
    SetTaskProvisional {
        /// Exact task lifetime receiving the classification.
        task: TaskKey,
        /// Exact owning process image.
        process: ProcessKey,
        /// New effective class.
        class: TaskClass,
        /// Generation scheduler must currently hold.
        expected_generation: u64,
        /// Exactly `expected_generation + 1`.
        new_generation: u64,
    },
    /// Applies the one final behavior confirmation or correction.
    LockTaskClass {
        /// Exact task lifetime receiving the classification.
        task: TaskKey,
        /// Exact owning process image.
        process: ProcessKey,
        /// Final effective class.
        class: TaskClass,
        /// Generation scheduler must currently hold.
        expected_generation: u64,
        /// Exactly `expected_generation + 1`.
        new_generation: u64,
    },
    /// Requests scheduler and BPF diagnostics.
    GetSnapshot,
}

/// Validated request envelope forwarded by the control thread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEnvelope {
    /// Agent-generated idempotency and correlation identity.
    pub request_id: u64,
    /// Scheduler incarnation named by the Agent; zero is allowed only for Hello.
    pub scheduler_epoch: u64,
    /// Typed request payload.
    pub request: ControlRequest,
}

/// Point-in-time scheduler and BPF diagnostics returned to Agent.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ControlSnapshot {
    /// Incarnation that produced this snapshot.
    pub scheduler_epoch: u64,
    /// Whether the current Agent connection completed Registry synchronization.
    pub registry_ready: bool,
    /// Whether userspace state is still trusted for continued scheduling.
    pub degraded: bool,
    /// Whether an Agent socket is currently connected.
    pub control_connected: bool,
    /// Bounded messages dropped because no Agent or queue capacity was available.
    pub control_messages_dropped: u64,
    /// Userspace policy counters.
    pub scheduler: SchedulerStats,
    /// BPF data-plane counters.
    pub data_plane: DataPlaneStats,
    /// Number of possible CPUs represented by the engine.
    pub cpu_count: usize,
    /// Number of submitted or running reservations.
    pub reservations: usize,
    /// Number of live scheduler task records.
    pub tasks: usize,
    /// Current number of primary and wait-index pool nodes.
    pub pool_nodes: usize,
}

impl Serialize for DataPlaneStats {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Fields {
            event_overflows: u64,
            fallback_dispatches: u64,
            commands_accepted: u64,
            commands_rejected: u64,
            target_slot_busy_rejects: u64,
            pipeline_hits: u64,
            pipeline_misses: u64,
            max_normal_staged_depth: u64,
            stale_heartbeat_fallbacks: u64,
            identity_rejects: u64,
            fast_path_enqueues: u64,
            fast_path_dispatches: u64,
            fast_path_dispatch_failures: u64,
            fast_path_preemptions: u64,
            fast_path_dispatches_by_class: [u64; 3],
            fast_path_local_dispatches: u64,
            fast_path_steal_attempts: u64,
            fast_path_remote_steals: u64,
            fast_path_events_suppressed: u64,
            fast_path_direct_dispatches: u64,
            fast_path_prev_continuations: u64,
            fast_path_steal_claim_conflicts: u64,
            cpu_state_events_suppressed: u64,
            fast_path_empty_steal_skips: u64,
        }

        Fields {
            event_overflows: self.event_overflows,
            fallback_dispatches: self.fallback_dispatches,
            commands_accepted: self.commands_accepted,
            commands_rejected: self.commands_rejected,
            target_slot_busy_rejects: self.target_slot_busy_rejects,
            pipeline_hits: self.pipeline_hits,
            pipeline_misses: self.pipeline_misses,
            max_normal_staged_depth: self.max_normal_staged_depth,
            stale_heartbeat_fallbacks: self.stale_heartbeat_fallbacks,
            identity_rejects: self.identity_rejects,
            fast_path_enqueues: self.fast_path_enqueues,
            fast_path_dispatches: self.fast_path_dispatches,
            fast_path_dispatch_failures: self.fast_path_dispatch_failures,
            fast_path_preemptions: self.fast_path_preemptions,
            fast_path_dispatches_by_class: self.fast_path_dispatches_by_class,
            fast_path_local_dispatches: self.fast_path_local_dispatches,
            fast_path_steal_attempts: self.fast_path_steal_attempts,
            fast_path_remote_steals: self.fast_path_remote_steals,
            fast_path_events_suppressed: self.fast_path_events_suppressed,
            fast_path_direct_dispatches: self.fast_path_direct_dispatches,
            fast_path_prev_continuations: self.fast_path_prev_continuations,
            fast_path_steal_claim_conflicts: self.fast_path_steal_claim_conflicts,
            cpu_state_events_suppressed: self.cpu_state_events_suppressed,
            fast_path_empty_steal_skips: self.fast_path_empty_steal_skips,
        }
        .serialize(serializer)
    }
}

/// Scheduler-to-Agent message before the transport envelope is added.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerMessage {
    /// Correlated command completion.
    Ack {
        /// Request ID supplied by Agent.
        request_id: u64,
        /// True only after all scheduler and BPF state committed.
        ok: bool,
        /// Stable short error code suitable for recovery decisions.
        error_code: Option<String>,
        /// Actionable local error text.
        error: Option<String>,
        /// Generation committed by this request.
        applied_generation: Option<u64>,
        /// Scheduler generation returned on a compare mismatch.
        current_generation: Option<u64>,
        /// Hello result; true when Agent must send a Registry snapshot.
        rebuild_required: Option<bool>,
        /// Snapshot-batch result; true after the final batch committed.
        snapshot_complete: Option<bool>,
        /// Diagnostic payload for GetSnapshot.
        snapshot: Option<Box<ControlSnapshot>>,
    },
    /// Scheduler replay or discovery of a process image.
    ProcessDiscovered { process: ProcessKey },
    /// Scheduler replay or discovery of a task lifetime.
    TaskDiscovered { task: TaskKey, process: ProcessKey },
    /// A surviving task entered a new process image generation.
    ProcessExec {
        task: TaskKey,
        previous_process: ProcessKey,
        process: ProcessKey,
    },
    /// Marks the end of the bounded identity replay following Hello.
    LifecycleReplayComplete,
    /// Stable task lifetime exited.
    TaskExited { task: TaskKey, process: ProcessKey },
    /// Final task of a stable process image exited.
    ProcessExited { process: ProcessKey },
    /// Fixed-frequency behavior facts; never changes class by itself.
    TaskStatsBatch {
        timestamp_ns: u64,
        windows: Vec<TaskBehaviorWindow>,
    },
}

impl SchedulerMessage {
    /// Creates an ordinary successful ACK.
    pub fn success(request_id: u64) -> Self {
        Self::ack(request_id, true, None, None)
    }

    /// Creates a successful classification-generation ACK.
    pub fn generation_success(request_id: u64, generation: u64) -> Self {
        let mut message = Self::ack(request_id, true, None, None);
        if let Self::Ack {
            applied_generation, ..
        } = &mut message
        {
            *applied_generation = Some(generation);
        }
        message
    }

    /// Creates a successful Hello ACK.
    pub fn hello_success(request_id: u64, rebuild_required: bool) -> Self {
        let mut message = Self::success(request_id);
        if let Self::Ack {
            rebuild_required: value,
            ..
        } = &mut message
        {
            *value = Some(rebuild_required);
        }
        message
    }

    /// Creates a successful snapshot-batch ACK.
    pub fn snapshot_success(request_id: u64, complete: bool) -> Self {
        let mut message = Self::success(request_id);
        if let Self::Ack {
            snapshot_complete, ..
        } = &mut message
        {
            *snapshot_complete = Some(complete);
        }
        message
    }

    /// Creates a successful diagnostics ACK.
    pub fn snapshot(request_id: u64, snapshot: ControlSnapshot) -> Self {
        let mut message = Self::success(request_id);
        if let Self::Ack {
            snapshot: value, ..
        } = &mut message
        {
            *value = Some(Box::new(snapshot));
        }
        message
    }

    /// Creates a failed ACK with an optional current generation.
    pub fn failure(
        request_id: u64,
        error_code: impl Into<String>,
        error: impl Into<String>,
        current_generation: Option<u64>,
    ) -> Self {
        Self::ack(
            request_id,
            false,
            Some(error_code.into()),
            Some(error.into()),
        )
        .with_current_generation(current_generation)
    }

    fn ack(request_id: u64, ok: bool, error_code: Option<String>, error: Option<String>) -> Self {
        Self::Ack {
            request_id,
            ok,
            error_code,
            error,
            applied_generation: None,
            current_generation: None,
            rebuild_required: None,
            snapshot_complete: None,
            snapshot: None,
        }
    }

    fn with_current_generation(mut self, generation: Option<u64>) -> Self {
        if let Self::Ack {
            current_generation, ..
        } = &mut self
        {
            *current_generation = generation;
        }
        self
    }

    fn request_id(&self) -> u64 {
        match self {
            Self::Ack { request_id, .. } => *request_id,
            _ => 0,
        }
    }

    /// Returns whether this response/event represents a successful command ACK.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Ack { ok: true, .. })
    }

    fn message_type(&self) -> &'static str {
        match self {
            Self::Ack { .. } => "ack",
            Self::ProcessDiscovered { .. } => "process_discovered",
            Self::TaskDiscovered { .. } => "task_discovered",
            Self::ProcessExec { .. } => "process_exec",
            Self::LifecycleReplayComplete => "lifecycle_replay_complete",
            Self::TaskExited { .. } => "task_exited",
            Self::ProcessExited { .. } => "process_exited",
            Self::TaskStatsBatch { .. } => "task_stats_batch",
        }
    }

    fn payload(&self) -> Value {
        match self {
            Self::Ack {
                ok,
                error_code,
                error,
                applied_generation,
                current_generation,
                rebuild_required,
                snapshot_complete,
                snapshot,
                ..
            } => json!({
                "ok": ok,
                "error_code": error_code,
                "error": error,
                "applied_generation": applied_generation,
                "current_generation": current_generation,
                "rebuild_required": rebuild_required,
                "snapshot_complete": snapshot_complete,
                "snapshot": snapshot,
            }),
            Self::ProcessDiscovered { process } => json!({"process": process}),
            Self::TaskDiscovered { task, process } => {
                json!({"task": task, "process": process})
            }
            Self::ProcessExec {
                task,
                previous_process,
                process,
            } => json!({
                "task": task,
                "previous_process": previous_process,
                "process": process,
            }),
            Self::LifecycleReplayComplete => json!({}),
            Self::TaskExited { task, process } => json!({"task": task, "process": process}),
            Self::ProcessExited { process } => json!({"process": process}),
            Self::TaskStatsBatch {
                timestamp_ns,
                windows,
            } => json!({"timestamp_ns": timestamp_ns, "windows": windows}),
        }
    }
}

/// Bounded control-thread channels owned by the scheduler main thread.
pub struct ControlHandle {
    requests: Receiver<ControlEnvelope>,
    outgoing: SyncSender<SchedulerMessage>,
    connected: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

impl ControlHandle {
    /// Binds the socket and starts one framing/validation thread.
    pub fn spawn(
        path: impl AsRef<Path>,
        capacity: usize,
        max_frame_bytes: usize,
        scheduler_epoch: u64,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        if capacity == 0 {
            anyhow::bail!("control channel capacity must be non-zero");
        }
        if !(MIN_FRAME_BYTES..=u32::MAX as usize).contains(&max_frame_bytes) {
            anyhow::bail!("control max frame must be in {MIN_FRAME_BYTES}..=u32::MAX");
        }
        if scheduler_epoch == 0 {
            anyhow::bail!("scheduler epoch must be non-zero");
        }

        let path = path.as_ref().to_path_buf();
        prepare_socket_path(&path)?;
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("bind control socket {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("make control listener non-blocking")?;

        let (request_tx, requests) = mpsc::sync_channel(capacity);
        let (outgoing, outgoing_rx) = mpsc::sync_channel(capacity);
        let connected = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));
        let thread_connected = connected.clone();
        let thread_dropped = dropped.clone();
        let thread = thread::Builder::new()
            .name("scx-adaptive-control".into())
            .spawn(move || {
                control_loop(
                    listener,
                    path,
                    request_tx,
                    outgoing_rx,
                    max_frame_bytes,
                    scheduler_epoch,
                    thread_connected,
                    thread_dropped,
                    shutdown,
                )
            })
            .context("spawn scheduler control thread")?;

        Ok(Self {
            requests,
            outgoing,
            connected,
            dropped,
            thread: Some(thread),
        })
    }

    /// Receives one parsed Agent command without blocking the scheduling loop.
    pub fn try_recv(&self) -> Option<ControlEnvelope> {
        self.requests.try_recv().ok()
    }

    /// Publishes one bounded response or asynchronous event.
    pub fn try_publish(&self, message: SchedulerMessage) -> bool {
        if self.outgoing.try_send(message).is_ok() {
            true
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Reports whether the socket thread currently owns an Agent connection.
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Returns messages dropped at the bounded control boundary.
    pub fn dropped_messages(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Joins the control thread after the shared shutdown flag is set.
    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Socket state retaining partial length-prefixed reads across timeouts.
struct Connection {
    stream: UnixStream,
    read_buffer: Vec<u8>,
}

impl Connection {
    fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(Duration::from_millis(20)))?;
        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
        Ok(Self {
            stream,
            read_buffer: Vec::new(),
        })
    }

    fn write_message(
        &mut self,
        message: &SchedulerMessage,
        scheduler_epoch: u64,
        max_frame_bytes: usize,
    ) -> io::Result<()> {
        let frame = encode_frame(
            message.message_type(),
            message.request_id(),
            scheduler_epoch,
            message.payload(),
            max_frame_bytes,
        )?;
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    fn read_request(&mut self, max_frame_bytes: usize) -> io::Result<Option<ControlEnvelope>> {
        if let Some(frame) = take_frame(&mut self.read_buffer, max_frame_bytes)? {
            return decode_request(&frame).map(Some);
        }

        let mut chunk = [0_u8; 8192];
        match self.stream.read(&mut chunk) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => self.read_buffer.extend_from_slice(&chunk[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        if self.read_buffer.len() > max_frame_bytes.saturating_add(FRAME_PREFIX_BYTES) {
            return Err(invalid_data(
                "control read buffer exceeded configured limit",
            ));
        }
        take_frame(&mut self.read_buffer, max_frame_bytes)?
            .map(|frame| decode_request(&frame))
            .transpose()
    }
}

#[allow(clippy::too_many_arguments)]
fn control_loop(
    listener: UnixListener,
    socket_path: PathBuf,
    requests: SyncSender<ControlEnvelope>,
    outgoing: Receiver<SchedulerMessage>,
    max_frame_bytes: usize,
    scheduler_epoch: u64,
    connected: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
) {
    let mut connection: Option<Connection> = None;
    while !shutdown.load(Ordering::Acquire) {
        if connection.is_none() {
            connected.store(false, Ordering::Release);
            match listener.accept() {
                Ok((stream, _)) => {
                    connection = Connection::new(stream).ok();
                    connected.store(connection.is_some(), Ordering::Release);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    drain_disconnected_messages(&outgoing, &dropped);
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
            }
        }

        let Some(active) = connection.as_mut() else {
            continue;
        };
        while let Ok(message) = outgoing.try_recv() {
            if active
                .write_message(&message, scheduler_epoch, max_frame_bytes)
                .is_err()
            {
                dropped.fetch_add(1, Ordering::Relaxed);
                connection = None;
                break;
            }
        }
        let Some(active) = connection.as_mut() else {
            continue;
        };

        match active.read_request(max_frame_bytes) {
            Ok(Some(request)) => match requests.try_send(request) {
                Ok(()) => {}
                Err(TrySendError::Full(request)) => {
                    let _ = active.write_message(
                        &SchedulerMessage::failure(
                            request.request_id,
                            "control_queue_full",
                            "scheduler control queue is full",
                            None,
                        ),
                        scheduler_epoch,
                        max_frame_bytes,
                    );
                }
                Err(TrySendError::Disconnected(_)) => break,
            },
            Ok(None) => {}
            Err(error) => {
                let _ = active.write_message(
                    &SchedulerMessage::failure(0, "invalid_frame", error.to_string(), None),
                    scheduler_epoch,
                    max_frame_bytes,
                );
                connection = None;
            }
        }
    }
    connected.store(false, Ordering::Release);
    let _ = fs::remove_file(socket_path);
}

fn drain_disconnected_messages(outgoing: &Receiver<SchedulerMessage>, dropped: &AtomicU64) {
    while outgoing.try_recv().is_ok() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct WireEnvelope {
    protocol_version: u16,
    message_type: String,
    request_id: u64,
    scheduler_epoch: u64,
    payload_length: u32,
    payload: Value,
}

fn encode_frame(
    message_type: &str,
    request_id: u64,
    scheduler_epoch: u64,
    payload: Value,
    max_frame_bytes: usize,
) -> io::Result<Vec<u8>> {
    let payload_length = serde_json::to_vec(&payload)
        .map_err(json_error)?
        .len()
        .try_into()
        .map_err(|_| invalid_data("control payload exceeds u32"))?;
    let body = serde_json::to_vec(&WireEnvelope {
        protocol_version: PROTOCOL_VERSION,
        message_type: message_type.to_string(),
        request_id,
        scheduler_epoch,
        payload_length,
        payload,
    })
    .map_err(json_error)?;
    if body.is_empty() || body.len() > max_frame_bytes {
        return Err(invalid_data("control frame exceeds configured limit"));
    }
    let body_len: u32 = body
        .len()
        .try_into()
        .map_err(|_| invalid_data("control frame exceeds u32"))?;
    let mut frame = Vec::with_capacity(FRAME_PREFIX_BYTES + body.len());
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn take_frame(buffer: &mut Vec<u8>, max_frame_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < FRAME_PREFIX_BYTES {
        return Ok(None);
    }
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    prefix.copy_from_slice(&buffer[..FRAME_PREFIX_BYTES]);
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > max_frame_bytes {
        return Err(invalid_data("invalid control frame length"));
    }
    let total = FRAME_PREFIX_BYTES + length;
    if buffer.len() < total {
        return Ok(None);
    }
    let frame = buffer[FRAME_PREFIX_BYTES..total].to_vec();
    buffer.drain(..total);
    Ok(Some(frame))
}

fn decode_request(frame: &[u8]) -> io::Result<ControlEnvelope> {
    let wire: WireEnvelope = serde_json::from_slice(frame).map_err(json_error)?;
    if wire.protocol_version != PROTOCOL_VERSION {
        return Err(invalid_data("unsupported control protocol version"));
    }
    if wire.request_id == 0 {
        return Err(invalid_data("control request_id must be non-zero"));
    }
    let actual_payload_length = serde_json::to_vec(&wire.payload).map_err(json_error)?.len();
    if actual_payload_length != wire.payload_length as usize {
        return Err(invalid_data("control payload_length mismatch"));
    }

    let request = match wire.message_type.as_str() {
        "hello" => {
            #[derive(Deserialize)]
            struct Payload {
                agent_pid: u32,
                known_scheduler_epoch: u64,
            }
            let payload: Payload = decode_payload(wire.payload)?;
            ControlRequest::Hello {
                agent_pid: payload.agent_pid,
                known_scheduler_epoch: payload.known_scheduler_epoch,
            }
        }
        "registry_snapshot_batch" => {
            #[derive(Deserialize)]
            struct Payload {
                snapshot_id: u64,
                batch_index: u32,
                is_last: bool,
                processes: Vec<ProcessSnapshot>,
                tasks: Vec<TaskSnapshot>,
            }
            let payload: Payload = decode_payload(wire.payload)?;
            ControlRequest::RegistrySnapshotBatch {
                snapshot_id: payload.snapshot_id,
                batch_index: payload.batch_index,
                is_last: payload.is_last,
                processes: payload.processes,
                tasks: payload.tasks,
            }
        }
        "set_process_default" => {
            #[derive(Deserialize)]
            struct Payload {
                process: ProcessKey,
                class: TaskClass,
                expected_generation: u64,
                new_generation: u64,
            }
            let payload: Payload = decode_payload(wire.payload)?;
            ControlRequest::SetProcessDefault {
                process: payload.process,
                class: payload.class,
                expected_generation: payload.expected_generation,
                new_generation: payload.new_generation,
            }
        }
        "set_task_provisional" | "lock_task_class" => {
            #[derive(Deserialize)]
            struct Payload {
                task: TaskKey,
                process: ProcessKey,
                class: TaskClass,
                expected_generation: u64,
                new_generation: u64,
            }
            let payload: Payload = decode_payload(wire.payload)?;
            if wire.message_type == "set_task_provisional" {
                ControlRequest::SetTaskProvisional {
                    task: payload.task,
                    process: payload.process,
                    class: payload.class,
                    expected_generation: payload.expected_generation,
                    new_generation: payload.new_generation,
                }
            } else {
                ControlRequest::LockTaskClass {
                    task: payload.task,
                    process: payload.process,
                    class: payload.class,
                    expected_generation: payload.expected_generation,
                    new_generation: payload.new_generation,
                }
            }
        }
        "get_snapshot" => {
            let payload: Value = decode_payload(wire.payload)?;
            if payload != json!({}) {
                return Err(invalid_data("get_snapshot payload must be empty"));
            }
            ControlRequest::GetSnapshot
        }
        _ => return Err(invalid_data("unknown control message_type")),
    };

    if !matches!(request, ControlRequest::Hello { .. }) && wire.scheduler_epoch == 0 {
        return Err(invalid_data("scheduler_epoch must be non-zero after Hello"));
    }
    Ok(ControlEnvelope {
        request_id: wire.request_id,
        scheduler_epoch: wire.scheduler_epoch,
        request,
    })
}

fn decode_payload<T: DeserializeOwned>(payload: Value) -> io::Result<T> {
    serde_json::from_value(payload).map_err(json_error)
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create control socket directory {}", parent.display()))?;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() {
        anyhow::bail!("refusing to replace non-socket path {}", path.display());
    }
    if UnixStream::connect(path).is_ok() {
        anyhow::bail!(
            "scheduler control socket {} is already active",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{decode_request, encode_frame, take_frame, ControlRequest, SchedulerMessage};
    use serde_json::json;

    /// Fixed fixture shared with Agent catches envelope compatibility drift.
    #[test]
    fn decodes_versioned_hello_fixture() {
        let frame = encode_frame(
            "hello",
            7,
            0,
            json!({"agent_pid": 42, "known_scheduler_epoch": 0}),
            4096,
        )
        .unwrap();
        let mut buffer = frame;
        let body = take_frame(&mut buffer, 4096).unwrap().unwrap();
        let request = decode_request(&body).unwrap();
        assert_eq!(request.request_id, 7);
        assert!(matches!(
            request.request,
            ControlRequest::Hello {
                agent_pid: 42,
                known_scheduler_epoch: 0
            }
        ));
    }

    /// A frame claiming a different payload size is rejected before dispatch.
    #[test]
    fn rejects_payload_length_mismatch() {
        let body = br#"{"protocol_version":1,"message_type":"get_snapshot","request_id":9,"scheduler_epoch":2,"payload_length":1,"payload":{}}"#;
        assert!(decode_request(body).is_err());
    }

    /// ACK payload retains generation and error-recovery fields.
    #[test]
    fn generation_ack_round_trips_through_frame() {
        let message = SchedulerMessage::generation_success(9, 4);
        let frame = encode_frame(
            message.message_type(),
            message.request_id(),
            3,
            message.payload(),
            4096,
        )
        .unwrap();
        assert!(frame.len() > 4);
    }
}
