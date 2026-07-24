// SPDX-License-Identifier: Apache-2.0

//! Reconnecting, bounded scheduler control client.
//!
//! A dedicated I/O thread owns framing and socket state. The Agent main thread
//! owns Registry synchronization and may send ordinary updates only after it
//! explicitly marks the current scheduler epoch synchronized.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{
    bounded, Receiver, RecvTimeoutError, SendTimeoutError, Sender, TryRecvError,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::behavior::BehaviorWindow;
use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
use crate::local_frame::{encode as encode_local_frame, FrameReader};

const PROTOCOL_VERSION: u16 = 1;
const RECONNECT_DELAY: Duration = Duration::from_millis(100);
const IO_POLL: Duration = Duration::from_millis(20);
const HELLO_TIMEOUT: Duration = Duration::from_secs(3);
const ACTION_REQUEST_ID_START: u64 = 1_u64 << 63;

/// Process classification serialized in a Registry snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessSnapshot {
    pub process: ProcessKey,
    pub class: TaskClass,
    pub class_generation: u64,
}

/// Semantic or locked task classification serialized in a Registry snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TaskSnapshot {
    pub task: TaskKey,
    pub process: ProcessKey,
    pub class: TaskClass,
    pub stage: ClassStage,
    pub class_generation: u64,
}

/// Complete identity and compare-and-swap values for one task class update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskClassRequest {
    pub request_id: u64,
    pub task: TaskKey,
    pub process: ProcessKey,
    pub class: TaskClass,
    pub expected_generation: u64,
    pub new_generation: u64,
}

/// One bounded snapshot message sent before incremental updates resume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrySnapshotBatch {
    pub snapshot_id: u64,
    pub batch_index: u32,
    pub is_last: bool,
    pub processes: Vec<ProcessSnapshot>,
    pub tasks: Vec<TaskSnapshot>,
}

/// Scheduler connection established by an automatic Hello exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionStatus {
    /// Non-zero scheduler process incarnation.
    pub scheduler_epoch: u64,
    /// Whether scheduler explicitly requires a Registry baseline.
    pub rebuild_required: bool,
}

/// Typed scheduler lifecycle, connection, or behavior event.
#[derive(Clone, Debug, PartialEq)]
pub enum SchedulerEvent {
    /// A socket completed Hello and now requires an explicit synchronization step.
    Connected(ConnectionStatus),
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
    LifecycleReplayComplete,
    TaskExited {
        task: TaskKey,
        process: ProcessKey,
    },
    ProcessExited(ProcessKey),
    BehaviorWindows {
        timestamp_ns: u64,
        windows: Vec<BehaviorWindow>,
    },
}

/// Correlated scheduler ACK returned only after engine and BPF handling.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlResponse {
    pub scheduler_epoch: u64,
    pub ok: bool,
    pub error_code: Option<String>,
    pub error: Option<String>,
    pub applied_generation: Option<u64>,
    pub current_generation: Option<u64>,
    pub rebuild_required: Option<bool>,
    pub snapshot_complete: Option<bool>,
    pub snapshot: Option<Value>,
}

#[derive(Debug)]
struct OutboundRequest {
    id: u64,
    message_type: &'static str,
    payload: Value,
    allowed_before_sync: bool,
    reply: Sender<Result<ControlResponse>>,
}

/// One Agent-owned control connection and asynchronous event receiver.
pub struct SchedulerClient {
    outgoing: Sender<OutboundRequest>,
    events: Receiver<SchedulerEvent>,
    next_id: AtomicU64,
    connected_epoch: Arc<AtomicU64>,
    synchronized_epoch: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SchedulerClient {
    /// Starts the reconnecting I/O thread with explicit queue and frame bounds.
    pub fn spawn(
        socket_path: impl AsRef<Path>,
        queue_capacity: usize,
        max_frame_bytes: usize,
    ) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();
        if socket_path.as_os_str().is_empty() {
            anyhow::bail!("scheduler socket path must not be empty");
        }
        if queue_capacity == 0 || max_frame_bytes < 256 || max_frame_bytes > u32::MAX as usize {
            anyhow::bail!("scheduler client limits are invalid");
        }
        let (outgoing, outgoing_rx) = bounded(queue_capacity);
        let (event_tx, events) = bounded(queue_capacity);
        let connected_epoch = Arc::new(AtomicU64::new(0));
        let synchronized_epoch = Arc::new(AtomicU64::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = spawn_control_thread(
            socket_path,
            outgoing_rx,
            event_tx,
            connected_epoch.clone(),
            synchronized_epoch.clone(),
            ready.clone(),
            shutdown.clone(),
            max_frame_bytes,
        )?;
        Ok(Self {
            outgoing,
            events,
            next_id: AtomicU64::new(1),
            connected_epoch,
            synchronized_epoch,
            ready,
            shutdown,
            thread: Some(thread),
        })
    }

    /// Waits for the automatic Hello exchange without consuming lifecycle events.
    pub fn wait_for_connection(&self, timeout: Duration) -> Result<ConnectionStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let scheduler_epoch = self.connected_epoch.load(Ordering::Acquire);
            if scheduler_epoch != 0 {
                return Ok(ConnectionStatus {
                    scheduler_epoch,
                    rebuild_required: self.synchronized_epoch.load(Ordering::Acquire)
                        != scheduler_epoch,
                });
            }
            thread::sleep(Duration::from_millis(20));
        }
        anyhow::bail!("timed out waiting for scheduler Hello")
    }

    /// Marks the current connection ready only after its complete snapshot ACK.
    pub fn mark_synchronized(&self, scheduler_epoch: u64) -> Result<()> {
        if scheduler_epoch == 0 || self.connected_epoch.load(Ordering::Acquire) != scheduler_epoch {
            anyhow::bail!("scheduler epoch changed during Registry synchronization");
        }
        self.synchronized_epoch
            .store(scheduler_epoch, Ordering::Release);
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Returns the current connected epoch, or zero while disconnected.
    pub fn connected_epoch(&self) -> u64 {
        self.connected_epoch.load(Ordering::Acquire)
    }

    /// Returns true only after the current connection completed a Registry snapshot.
    pub fn is_synchronized(&self) -> bool {
        let epoch = self.connected_epoch.load(Ordering::Acquire);
        epoch != 0
            && self.ready.load(Ordering::Acquire)
            && self.synchronized_epoch.load(Ordering::Acquire) == epoch
    }

    /// Prevents further incremental updates until Agent sends a fresh snapshot.
    pub fn invalidate_synchronization(&self) {
        self.ready.store(false, Ordering::Release);
    }

    /// Sends one bounded Registry snapshot batch before ordinary updates resume.
    pub fn send_registry_snapshot_batch(
        &self,
        batch: RegistrySnapshotBatch,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        self.request(
            self.allocate_request_id()?,
            "registry_snapshot_batch",
            json!({
                "snapshot_id": batch.snapshot_id,
                "batch_index": batch.batch_index,
                "is_last": batch.is_last,
                "processes": batch.processes,
                "tasks": batch.tasks,
            }),
            true,
            timeout,
        )
    }

    /// Commits a process default with an exact generation comparison.
    pub fn set_process_default(
        &self,
        request_id: u64,
        process: ProcessKey,
        class: TaskClass,
        expected_generation: u64,
        new_generation: u64,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        self.request(
            request_id,
            "set_process_default",
            json!({
                "process": process,
                "class": class,
                "expected_generation": expected_generation,
                "new_generation": new_generation,
            }),
            false,
            timeout,
        )
    }

    /// Commits one semantic task classification.
    pub fn set_task_provisional(
        &self,
        update: TaskClassRequest,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        self.set_task("set_task_provisional", update, timeout)
    }

    /// Commits one final behavior confirmation or correction.
    pub fn lock_task_class(
        &self,
        update: TaskClassRequest,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        self.set_task("lock_task_class", update, timeout)
    }

    /// Returns current scheduler diagnostics after synchronization.
    pub fn snapshot(&self, timeout: Duration) -> Result<Value> {
        let response = self.request(
            self.allocate_request_id()?,
            "get_snapshot",
            json!({}),
            false,
            timeout,
        )?;
        ensure_ok(&response, "get_snapshot")?;
        response
            .snapshot
            .context("scheduler get_snapshot omitted snapshot")
    }

    /// Returns one asynchronous scheduler event without blocking.
    pub fn try_recv_event(&self) -> Option<SchedulerEvent> {
        self.events.try_recv().ok()
    }

    /// Allocates a stable high-range ID for Registry actions and retries.
    pub fn first_action_request_id() -> u64 {
        ACTION_REQUEST_ID_START
    }

    /// Stops the I/O thread and fails any in-flight control requests.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    fn set_task(
        &self,
        message_type: &'static str,
        update: TaskClassRequest,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        self.request(
            update.request_id,
            message_type,
            json!({
                "task": update.task,
                "process": update.process,
                "class": update.class,
                "expected_generation": update.expected_generation,
                "new_generation": update.new_generation,
            }),
            false,
            timeout,
        )
    }

    fn request(
        &self,
        id: u64,
        message_type: &'static str,
        payload: Value,
        allowed_before_sync: bool,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        if id == 0 {
            anyhow::bail!("scheduler control request ID must be non-zero");
        }
        let epoch = self.connected_epoch.load(Ordering::Acquire);
        if epoch == 0 {
            anyhow::bail!("scheduler control connection is unavailable");
        }
        if !allowed_before_sync && !self.ready.load(Ordering::Acquire) {
            anyhow::bail!("scheduler Registry is not synchronized for epoch {epoch}");
        }
        let (reply_tx, reply_rx) = bounded(1);
        self.outgoing
            .send(OutboundRequest {
                id,
                message_type,
                payload,
                allowed_before_sync,
                reply: reply_tx,
            })
            .context("scheduler control client stopped")?;
        match reply_rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                anyhow::bail!("scheduler control request {id} timed out")
            }
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("scheduler control I/O thread stopped")
            }
        }
    }

    fn allocate_request_id(&self) -> Result<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id >= ACTION_REQUEST_ID_START {
            anyhow::bail!("scheduler control request ID space exhausted");
        }
        Ok(id)
    }
}

impl Drop for SchedulerClient {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn ensure_ok(response: &ControlResponse, operation: &str) -> Result<()> {
    if response.ok {
        Ok(())
    } else {
        anyhow::bail!(
            "scheduler {operation} rejected [{}]: {}",
            response.error_code.as_deref().unwrap_or("unknown"),
            response.error.as_deref().unwrap_or("no detail")
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_control_thread(
    socket_path: PathBuf,
    outgoing: Receiver<OutboundRequest>,
    events: Sender<SchedulerEvent>,
    connected_epoch: Arc<AtomicU64>,
    synchronized_epoch: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    max_frame_bytes: usize,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("adaptive-agent-control".into())
        .spawn(move || {
            control_loop(
                socket_path,
                outgoing,
                events,
                connected_epoch,
                synchronized_epoch,
                ready,
                shutdown,
                max_frame_bytes,
            )
        })
        .context("spawn Agent scheduler control thread")
}

#[allow(clippy::too_many_arguments)]
fn control_loop(
    socket_path: PathBuf,
    outgoing: Receiver<OutboundRequest>,
    events: Sender<SchedulerEvent>,
    connected_epoch: Arc<AtomicU64>,
    synchronized_epoch: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    max_frame_bytes: usize,
) {
    let mut queued = VecDeque::new();
    let mut pending: HashMap<u64, Sender<Result<ControlResponse>>> = HashMap::new();
    let mut last_connect_attempt = Instant::now() - RECONNECT_DELAY;
    let mut connection: Option<Connection> = None;
    let mut connection_sequence = 0_u64;

    while !shutdown.load(Ordering::Acquire) {
        drain_outgoing(&outgoing, &mut queued, &shutdown);
        if connection.is_none() && last_connect_attempt.elapsed() >= RECONNECT_DELAY {
            last_connect_attempt = Instant::now();
            if let Ok(mut stream) = Connection::connect(&socket_path) {
                connection_sequence = connection_sequence.wrapping_add(1).max(1);
                let known_epoch = synchronized_epoch.load(Ordering::Acquire);
                let hello_id = u64::MAX.saturating_sub(connection_sequence);
                match handshake(
                    &mut stream,
                    hello_id,
                    known_epoch,
                    max_frame_bytes,
                    &shutdown,
                ) {
                    Ok(status) => {
                        ready.store(false, Ordering::Release);
                        connected_epoch.store(status.scheduler_epoch, Ordering::Release);
                        connection = Some(stream);
                        let _ = events.send(SchedulerEvent::Connected(status));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }

        let Some(active) = connection.as_mut() else {
            fail_queued(&mut queued, "scheduler control connection is unavailable");
            thread::sleep(Duration::from_millis(10));
            continue;
        };

        let epoch = connected_epoch.load(Ordering::Acquire);
        if flush_queued(
            active,
            &mut queued,
            &mut pending,
            epoch,
            ready.load(Ordering::Acquire),
            max_frame_bytes,
        )
        .is_err()
        {
            disconnect(
                &mut connection,
                &connected_epoch,
                &ready,
                &mut queued,
                &mut pending,
            );
            continue;
        }

        let Some(active) = connection.as_mut() else {
            continue;
        };
        match active.read_message(max_frame_bytes) {
            Ok(Some(message)) if message.scheduler_epoch != epoch => {
                disconnect(
                    &mut connection,
                    &connected_epoch,
                    &ready,
                    &mut queued,
                    &mut pending,
                );
            }
            Ok(Some(message)) => match message.message {
                IncomingMessage::Ack(response) => {
                    if let Some(reply) = pending.remove(&message.request_id) {
                        let _ = reply.send(Ok(ControlResponse {
                            scheduler_epoch: message.scheduler_epoch,
                            ok: response.ok,
                            error_code: response.error_code,
                            error: response.error,
                            applied_generation: response.applied_generation,
                            current_generation: response.current_generation,
                            rebuild_required: response.rebuild_required,
                            snapshot_complete: response.snapshot_complete,
                            snapshot: response.snapshot,
                        }));
                    }
                }
                event => {
                    if let Some(event) = scheduler_event(event) {
                        if !send_event(&events, event, &shutdown) {
                            break;
                        }
                    }
                }
            },
            Ok(None) => {}
            Err(_) => disconnect(
                &mut connection,
                &connected_epoch,
                &ready,
                &mut queued,
                &mut pending,
            ),
        }
    }

    connected_epoch.store(0, Ordering::Release);
    ready.store(false, Ordering::Release);
    fail_queued(&mut queued, "scheduler control client stopped");
    fail_pending(&mut pending, "scheduler control client stopped");
}

fn send_event(
    events: &Sender<SchedulerEvent>,
    mut event: SchedulerEvent,
    shutdown: &AtomicBool,
) -> bool {
    while !shutdown.load(Ordering::Acquire) {
        match events.send_timeout(event, IO_POLL) {
            Ok(()) => return true,
            Err(SendTimeoutError::Timeout(returned)) => event = returned,
            Err(SendTimeoutError::Disconnected(_)) => return false,
        }
    }
    false
}

fn handshake(
    connection: &mut Connection,
    request_id: u64,
    known_epoch: u64,
    max_frame_bytes: usize,
    shutdown: &AtomicBool,
) -> Result<ConnectionStatus> {
    connection.write_message(
        "hello",
        request_id,
        known_epoch,
        json!({
            "agent_pid": std::process::id(),
            "known_scheduler_epoch": known_epoch,
        }),
        max_frame_bytes,
    )?;
    let deadline = Instant::now() + HELLO_TIMEOUT;
    while Instant::now() < deadline && !shutdown.load(Ordering::Acquire) {
        let Some(message) = connection.read_message(max_frame_bytes)? else {
            continue;
        };
        if message.request_id != request_id {
            continue;
        }
        let IncomingMessage::Ack(response) = message.message else {
            continue;
        };
        if !response.ok || message.scheduler_epoch == 0 {
            anyhow::bail!(
                "scheduler Hello rejected: {}",
                response.error.unwrap_or_else(|| "unknown error".into())
            );
        }
        return Ok(ConnectionStatus {
            scheduler_epoch: message.scheduler_epoch,
            rebuild_required: response.rebuild_required.unwrap_or(true),
        });
    }
    anyhow::bail!("scheduler Hello timed out")
}

fn disconnect(
    connection: &mut Option<Connection>,
    connected_epoch: &AtomicU64,
    ready: &AtomicBool,
    queued: &mut VecDeque<OutboundRequest>,
    pending: &mut HashMap<u64, Sender<Result<ControlResponse>>>,
) {
    *connection = None;
    connected_epoch.store(0, Ordering::Release);
    ready.store(false, Ordering::Release);
    fail_queued(queued, "scheduler control connection was lost");
    fail_pending(pending, "scheduler control connection was lost");
}

fn drain_outgoing(
    outgoing: &Receiver<OutboundRequest>,
    queued: &mut VecDeque<OutboundRequest>,
    shutdown: &AtomicBool,
) {
    loop {
        match outgoing.try_recv() {
            Ok(request) => queued.push_back(request),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                shutdown.store(true, Ordering::Release);
                break;
            }
        }
    }
}

fn flush_queued(
    connection: &mut Connection,
    queued: &mut VecDeque<OutboundRequest>,
    pending: &mut HashMap<u64, Sender<Result<ControlResponse>>>,
    scheduler_epoch: u64,
    ready: bool,
    max_frame_bytes: usize,
) -> io::Result<()> {
    while let Some(request) = queued.pop_front() {
        if !request.allowed_before_sync && !ready {
            let _ = request.reply.send(Err(anyhow::anyhow!(
                "scheduler Registry is not synchronized"
            )));
            continue;
        }
        if pending.contains_key(&request.id) {
            let _ = request.reply.send(Err(anyhow::anyhow!(
                "scheduler request {} is already in flight",
                request.id
            )));
            continue;
        }
        if let Err(error) = connection.write_message(
            request.message_type,
            request.id,
            scheduler_epoch,
            request.payload.clone(),
            max_frame_bytes,
        ) {
            queued.push_front(request);
            return Err(error);
        }
        pending.insert(request.id, request.reply);
    }
    Ok(())
}

fn fail_pending(pending: &mut HashMap<u64, Sender<Result<ControlResponse>>>, reason: &str) {
    for (_, reply) in pending.drain() {
        let _ = reply.send(Err(anyhow::anyhow!(reason.to_string())));
    }
}

fn fail_queued(queued: &mut VecDeque<OutboundRequest>, reason: &str) {
    while let Some(request) = queued.pop_front() {
        let _ = request.reply.send(Err(anyhow::anyhow!(reason.to_string())));
    }
}

struct Connection {
    stream: UnixStream,
    reader: FrameReader,
}

impl Connection {
    fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(IO_POLL))?;
        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
        Ok(Self {
            stream,
            reader: FrameReader::default(),
        })
    }

    fn write_message(
        &mut self,
        message_type: &str,
        request_id: u64,
        scheduler_epoch: u64,
        payload: Value,
        max_frame_bytes: usize,
    ) -> io::Result<()> {
        let frame = encode_frame(
            message_type,
            request_id,
            scheduler_epoch,
            payload,
            max_frame_bytes,
        )?;
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    fn read_message(&mut self, max_frame_bytes: usize) -> io::Result<Option<IncomingEnvelope>> {
        self.reader
            .read(&mut self.stream, max_frame_bytes)?
            .map(|frame| decode_message(&frame))
            .transpose()
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

struct IncomingEnvelope {
    request_id: u64,
    scheduler_epoch: u64,
    message: IncomingMessage,
}

enum IncomingMessage {
    Ack(AckPayload),
    ProcessDiscovered(ProcessPayload),
    TaskDiscovered(TaskPayload),
    ProcessExec(ExecPayload),
    LifecycleReplayComplete,
    TaskExited(TaskPayload),
    ProcessExited(ProcessPayload),
    TaskStatsBatch(StatsPayload),
}

#[derive(Deserialize)]
struct AckPayload {
    ok: bool,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    applied_generation: Option<u64>,
    #[serde(default)]
    current_generation: Option<u64>,
    #[serde(default)]
    rebuild_required: Option<bool>,
    #[serde(default)]
    snapshot_complete: Option<bool>,
    #[serde(default)]
    snapshot: Option<Value>,
}

#[derive(Deserialize)]
struct ProcessPayload {
    process: ProcessKey,
}

#[derive(Deserialize)]
struct TaskPayload {
    task: TaskKey,
    process: ProcessKey,
}

#[derive(Deserialize)]
struct ExecPayload {
    task: TaskKey,
    previous_process: ProcessKey,
    process: ProcessKey,
}

#[derive(Deserialize)]
struct StatsPayload {
    timestamp_ns: u64,
    windows: Vec<BehaviorWindow>,
}

fn scheduler_event(message: IncomingMessage) -> Option<SchedulerEvent> {
    match message {
        IncomingMessage::Ack(_) => None,
        IncomingMessage::ProcessDiscovered(payload) => {
            Some(SchedulerEvent::ProcessDiscovered(payload.process))
        }
        IncomingMessage::TaskDiscovered(payload) => Some(SchedulerEvent::TaskDiscovered {
            task: payload.task,
            process: payload.process,
        }),
        IncomingMessage::ProcessExec(payload) => Some(SchedulerEvent::ProcessExec {
            task: payload.task,
            previous_process: payload.previous_process,
            process: payload.process,
        }),
        IncomingMessage::LifecycleReplayComplete => Some(SchedulerEvent::LifecycleReplayComplete),
        IncomingMessage::TaskExited(payload) => Some(SchedulerEvent::TaskExited {
            task: payload.task,
            process: payload.process,
        }),
        IncomingMessage::ProcessExited(payload) => {
            Some(SchedulerEvent::ProcessExited(payload.process))
        }
        IncomingMessage::TaskStatsBatch(payload) => Some(SchedulerEvent::BehaviorWindows {
            timestamp_ns: payload.timestamp_ns,
            windows: payload.windows,
        }),
    }
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
    encode_local_frame(&body, max_frame_bytes)
}

fn decode_message(frame: &[u8]) -> io::Result<IncomingEnvelope> {
    let wire: WireEnvelope = serde_json::from_slice(frame).map_err(json_error)?;
    if wire.protocol_version != PROTOCOL_VERSION || wire.scheduler_epoch == 0 {
        return Err(invalid_data("invalid scheduler protocol version or epoch"));
    }
    let actual_payload_length = serde_json::to_vec(&wire.payload).map_err(json_error)?.len();
    if actual_payload_length != wire.payload_length as usize {
        return Err(invalid_data("control payload_length mismatch"));
    }
    let message = match wire.message_type.as_str() {
        "ack" => IncomingMessage::Ack(decode_payload(wire.payload)?),
        "process_discovered" => IncomingMessage::ProcessDiscovered(decode_payload(wire.payload)?),
        "task_discovered" => IncomingMessage::TaskDiscovered(decode_payload(wire.payload)?),
        "process_exec" => IncomingMessage::ProcessExec(decode_payload(wire.payload)?),
        "lifecycle_replay_complete" => {
            if wire.payload != json!({}) {
                return Err(invalid_data("lifecycle replay payload must be empty"));
            }
            IncomingMessage::LifecycleReplayComplete
        }
        "task_exited" => IncomingMessage::TaskExited(decode_payload(wire.payload)?),
        "process_exited" => IncomingMessage::ProcessExited(decode_payload(wire.payload)?),
        "task_stats_batch" => IncomingMessage::TaskStatsBatch(decode_payload(wire.payload)?),
        _ => return Err(invalid_data("unknown scheduler message_type")),
    };
    Ok(IncomingEnvelope {
        request_id: wire.request_id,
        scheduler_epoch: wire.scheduler_epoch,
        message,
    })
}

fn decode_payload<T: DeserializeOwned>(payload: Value) -> io::Result<T> {
    serde_json::from_value(payload).map_err(json_error)
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{decode_message, encode_frame, scheduler_event, IncomingMessage, SchedulerEvent};
    use crate::local_frame::FrameReader;
    use serde_json::json;

    /// The Agent emits the same fixed Hello envelope accepted by scheduler tests.
    #[test]
    fn encodes_versioned_hello_fixture() {
        let frame = encode_frame(
            "hello",
            7,
            0,
            json!({"agent_pid": 42, "known_scheduler_epoch": 0}),
            4096,
        )
        .unwrap();
        let mut buffered = FrameReader::default();
        buffered.push(&frame);
        let body = buffered.take(4096).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["protocol_version"], 1);
        assert_eq!(value["payload_length"], 42);
    }

    /// Event parsing retains every cookie-bearing identity field.
    #[test]
    fn parses_task_discovery_event() {
        let frame = encode_frame(
            "task_discovered",
            0,
            5,
            json!({
                "task": {"tid": 7, "task_cookie": 8},
                "process": {"tgid": 6, "process_cookie": 9, "exec_generation": 2}
            }),
            4096,
        )
        .unwrap();
        let mut buffered = FrameReader::default();
        buffered.push(&frame);
        let body = buffered.take(4096).unwrap().unwrap();
        let message = decode_message(&body).unwrap().message;
        assert!(matches!(
            scheduler_event(message),
            Some(SchedulerEvent::TaskDiscovered { task, process })
                if task.tid == 7 && task.task_cookie == 8 && process.exec_generation == 2
        ));
    }

    #[test]
    fn parses_explicit_process_exec_event() {
        let frame = encode_frame(
            "process_exec",
            0,
            5,
            json!({
                "task": {"tid": 7, "task_cookie": 8},
                "previous_process": {"tgid": 7, "process_cookie": 9, "exec_generation": 1},
                "process": {"tgid": 7, "process_cookie": 9, "exec_generation": 2}
            }),
            4096,
        )
        .unwrap();
        let mut buffered = FrameReader::default();
        buffered.push(&frame);
        let body = buffered.take(4096).unwrap().unwrap();
        let message = decode_message(&body).unwrap().message;
        assert!(matches!(
            scheduler_event(message),
            Some(SchedulerEvent::ProcessExec {
                previous_process,
                process,
                ..
            }) if previous_process.exec_generation == 1 && process.exec_generation == 2
        ));
    }

    #[test]
    fn parses_lifecycle_replay_completion() {
        let frame = encode_frame("lifecycle_replay_complete", 0, 5, json!({}), 4096).unwrap();
        let mut buffered = FrameReader::default();
        buffered.push(&frame);
        let body = buffered.take(4096).unwrap().unwrap();
        let message = decode_message(&body).unwrap().message;
        assert!(matches!(
            scheduler_event(message),
            Some(SchedulerEvent::LifecycleReplayComplete)
        ));
    }

    /// Unknown scheduler messages fail closed rather than disappearing silently.
    #[test]
    fn rejects_unknown_message_type() {
        let frame = encode_frame("future_message", 0, 5, json!({}), 4096).unwrap();
        let mut buffered = FrameReader::default();
        buffered.push(&frame);
        let body = buffered.take(4096).unwrap().unwrap();
        assert!(decode_message(&body).is_err());
        let _ = std::mem::size_of::<IncomingMessage>();
    }
}
