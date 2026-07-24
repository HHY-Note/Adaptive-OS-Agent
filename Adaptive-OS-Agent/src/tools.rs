// SPDX-License-Identifier: Apache-2.0

//! Read-only standardized Agent Tool interface over a bounded local socket.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::{ClassStage, ProcessKey, TaskKey};
use crate::local_frame::{encode as encode_frame, FrameReader};
use crate::registry::{ClassificationRegistry, SemanticState};

const TOOL_REPLY_TIMEOUT: Duration = Duration::from_secs(4);

/// One validated external Tool request.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ToolRequest {
    pub request_id: u64,
    pub tool: String,
    #[serde(default = "empty_object")]
    pub arguments: Value,
}

/// Stable Tool response envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ToolResponse {
    pub request_id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ToolResponse {
    fn success(request_id: u64, result: Value) -> Self {
        Self {
            request_id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn failure(request_id: u64, error: impl Into<String>) -> Self {
        Self {
            request_id,
            ok: false,
            result: None,
            error: Some(error.into()),
        }
    }
}

/// Tool call transferred to the Agent owner thread for a consistent read.
pub struct ToolCall {
    pub request: ToolRequest,
    reply: Sender<ToolResponse>,
}

impl ToolCall {
    /// Completes one request exactly once.
    pub fn respond(self, response: ToolResponse) {
        let _ = self.reply.send(response);
    }
}

/// Bounded request receiver and owned Tool listener thread.
pub struct ToolServer {
    requests: Receiver<ToolCall>,
    thread: Option<JoinHandle<()>>,
}

impl ToolServer {
    /// Starts the local read-only interface.
    pub fn spawn(
        path: impl AsRef<Path>,
        capacity: usize,
        max_frame_bytes: usize,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        if capacity == 0 || !(256..=u32::MAX as usize).contains(&max_frame_bytes) {
            anyhow::bail!("invalid Tool queue or frame limit");
        }
        let path = path.as_ref().to_path_buf();
        prepare_socket_path(&path)?;
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("bind Tool socket {}", path.display()))?;
        listener.set_nonblocking(true)?;
        let (request_tx, requests) = bounded(capacity);
        let thread = thread::Builder::new()
            .name("adaptive-agent-tools".into())
            .spawn(move || tool_loop(listener, path, request_tx, max_frame_bytes, shutdown))
            .context("spawn Agent Tool thread")?;
        Ok(Self {
            requests,
            thread: Some(thread),
        })
    }

    /// Returns one call without blocking the Agent loop.
    pub fn try_recv(&self) -> Option<ToolCall> {
        self.requests.try_recv().ok()
    }

    /// Joins after the shared Agent shutdown flag is set.
    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Executes one read-only Tool against a single-owner Registry snapshot.
pub fn execute(
    request: &ToolRequest,
    registry: &ClassificationRegistry,
    scheduler_snapshot: Option<&Value>,
) -> ToolResponse {
    let result = match request.tool.as_str() {
        "workload.list" => workload_list(registry, &request.arguments),
        "workload.get" => workload_get(registry, &request.arguments),
        "classification.get" => classification_get(registry, &request.arguments),
        "scheduler.health" => scheduler_health(scheduler_snapshot),
        "scheduler.stats" => scheduler_stats(scheduler_snapshot),
        _ => Err(format!("unknown Tool: {}", request.tool)),
    };
    match result {
        Ok(value) => ToolResponse::success(request.request_id, value),
        Err(error) => ToolResponse::failure(request.request_id, error),
    }
}

#[derive(Deserialize)]
struct ListArguments {
    #[serde(default)]
    scope: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn workload_list(registry: &ClassificationRegistry, arguments: &Value) -> Result<Value, String> {
    let args: ListArguments = parse_arguments(arguments)?;
    if args.limit == 0 || args.limit > 1000 {
        return Err("limit must be in 1..=1000".into());
    }
    let scope = args.scope.as_deref().unwrap_or("all");
    if !matches!(scope, "all" | "process" | "task") {
        return Err("scope must be all, process, or task".into());
    }

    let mut rows = Vec::new();
    if scope != "task" {
        let mut records: Vec<_> = registry.processes().collect();
        records.sort_unstable_by_key(|record| record.identity);
        rows.extend(records.into_iter().map(|record| {
            json!({
                "kind": "process",
                "identity": record.identity,
                "comm": record.metadata.as_ref().map(|metadata| metadata.comm.as_str()),
                "tasks": record.tasks.len(),
            })
        }));
    }
    if scope != "process" {
        let mut records: Vec<_> = registry.tasks().collect();
        records.sort_unstable_by_key(|record| record.identity);
        rows.extend(records.into_iter().map(|record| {
            json!({
                "kind": "task",
                "identity": record.identity,
                "process": record.process,
            })
        }));
    }
    let total = rows.len();
    let items: Vec<_> = rows
        .into_iter()
        .skip(args.offset)
        .take(args.limit)
        .collect();
    Ok(json!({"items": items, "total": total, "registry": registry.stats()}))
}

#[derive(Deserialize)]
struct TargetArguments {
    #[serde(default)]
    process: Option<ProcessKey>,
    #[serde(default)]
    task: Option<TaskKey>,
}

fn workload_get(registry: &ClassificationRegistry, arguments: &Value) -> Result<Value, String> {
    match parse_target(arguments)? {
        Target::Process(process) => {
            let record = registry
                .process(process)
                .ok_or_else(|| "process identity not found".to_string())?;
            Ok(json!({
                "kind": "process",
                "identity": record.identity,
                "comm": record.metadata.as_ref().map(|metadata| metadata.comm.as_str()),
                "executable": record.metadata.as_ref().and_then(|metadata| metadata.executable.as_deref()),
                "uid": record.metadata.as_ref().and_then(|metadata| metadata.uid),
                "created_ns": record.created_ns,
                "tasks": record.tasks.len(),
            }))
        }
        Target::Task(task) => {
            let record = registry
                .task(task)
                .ok_or_else(|| "task identity not found".to_string())?;
            Ok(json!({
                "kind": "task",
                "identity": record.identity,
                "process": record.process,
                "created_ns": record.created_ns,
            }))
        }
    }
}

fn classification_get(
    registry: &ClassificationRegistry,
    arguments: &Value,
) -> Result<Value, String> {
    match parse_target(arguments)? {
        Target::Process(process) => {
            let record = registry
                .process(process)
                .ok_or_else(|| "process identity not found".to_string())?;
            Ok(json!({
                "kind": "process",
                "identity": record.identity,
                "class": record.default_class,
                "stage": "process_default",
                "source": semantic_source(record.semantic),
                "confidence": semantic_confidence(record.semantic),
                "generation": record.class_generation,
                "applied_generation": record.applied_generation,
            }))
        }
        Target::Task(task) => {
            let record = registry
                .task(task)
                .ok_or_else(|| "task identity not found".to_string())?;
            let source = match record.stage {
                ClassStage::Inherited => "process_default",
                ClassStage::Semantic => "llm",
                ClassStage::Locked => "behavior",
            };
            Ok(json!({
                "kind": "task",
                "identity": record.identity,
                "process": record.process,
                "class": record.effective_class,
                "stage": record.stage,
                "source": source,
                "confidence": semantic_confidence(record.semantic),
                "generation": record.class_generation,
                "applied_generation": record.applied_generation,
            }))
        }
    }
}

fn scheduler_health(snapshot: Option<&Value>) -> Result<Value, String> {
    let snapshot = snapshot.ok_or_else(|| "scheduler snapshot is unavailable".to_string())?;
    Ok(json!({
        "attached": true,
        "scheduler_epoch": snapshot.get("scheduler_epoch"),
        "registry_ready": snapshot.get("registry_ready"),
        "degraded": snapshot.get("degraded"),
        "control_connected": snapshot.get("control_connected"),
        "control_messages_dropped": snapshot.get("control_messages_dropped"),
        "event_overflows": snapshot.pointer("/data_plane/event_overflows"),
        "fallback_dispatches": snapshot.pointer("/data_plane/fallback_dispatches"),
        "stale_heartbeat_fallbacks": snapshot.pointer("/data_plane/stale_heartbeat_fallbacks"),
    }))
}

fn scheduler_stats(snapshot: Option<&Value>) -> Result<Value, String> {
    let snapshot = snapshot.ok_or_else(|| "scheduler snapshot is unavailable".to_string())?;
    Ok(json!({
        "scheduler_epoch": snapshot.get("scheduler_epoch"),
        "cpu_count": snapshot.get("cpu_count"),
        "tasks": snapshot.get("tasks"),
        "pool_nodes": snapshot.get("pool_nodes"),
        "reservations": snapshot.get("reservations"),
        "scheduler": snapshot.get("scheduler"),
        "data_plane": snapshot.get("data_plane"),
    }))
}

enum Target {
    Process(ProcessKey),
    Task(TaskKey),
}

fn parse_target(arguments: &Value) -> Result<Target, String> {
    let args: TargetArguments = parse_arguments(arguments)?;
    match (args.process, args.task) {
        (Some(process), None) => Ok(Target::Process(process)),
        (None, Some(task)) => Ok(Target::Task(task)),
        _ => Err("exactly one of process or task is required".into()),
    }
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(arguments: &Value) -> Result<T, String> {
    if !arguments.is_object() {
        return Err("Tool arguments must be a JSON object".into());
    }
    serde_json::from_value(arguments.clone()).map_err(|error| error.to_string())
}

fn semantic_source(state: SemanticState) -> &'static str {
    match state {
        SemanticState::Classified { .. } => "llm",
        SemanticState::Unknown | SemanticState::Failed => "fallback",
        SemanticState::Pending | SemanticState::Requested => "default",
    }
}

fn semantic_confidence(state: SemanticState) -> Option<f32> {
    match state {
        SemanticState::Classified {
            confidence_per_mille,
            ..
        } => Some(f32::from(confidence_per_mille) / 1000.0),
        _ => None,
    }
}

fn empty_object() -> Value {
    json!({})
}

const fn default_limit() -> usize {
    100
}

struct Connection {
    stream: UnixStream,
    reader: FrameReader,
}

impl Connection {
    fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(Duration::from_millis(20)))?;
        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
        Ok(Self {
            stream,
            reader: FrameReader::default(),
        })
    }

    fn read_request(&mut self, max_frame_bytes: usize) -> io::Result<Option<ToolRequest>> {
        self.reader
            .read(&mut self.stream, max_frame_bytes)?
            .map(|body| serde_json::from_slice(&body).map_err(json_error))
            .transpose()
    }

    fn write_response(
        &mut self,
        response: &ToolResponse,
        max_frame_bytes: usize,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(response).map_err(json_error)?;
        let frame = encode_frame(&body, max_frame_bytes)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }
}

fn tool_loop(
    listener: UnixListener,
    socket_path: PathBuf,
    requests: Sender<ToolCall>,
    max_frame_bytes: usize,
    shutdown: Arc<AtomicBool>,
) {
    let mut connection: Option<Connection> = None;
    while !shutdown.load(Ordering::Acquire) {
        if connection.is_none() {
            match listener.accept() {
                Ok((stream, _)) => connection = Connection::new(stream).ok(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
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
        match active.read_request(max_frame_bytes) {
            Ok(Some(request)) => {
                let request_id = request.request_id;
                if request_id == 0 || request.tool.is_empty() || !request.arguments.is_object() {
                    let _ = active.write_response(
                        &ToolResponse::failure(request_id, "invalid Tool request"),
                        max_frame_bytes,
                    );
                    continue;
                }
                let (reply, response) = bounded(1);
                match requests.try_send(ToolCall { request, reply }) {
                    Ok(()) => match response.recv_timeout(TOOL_REPLY_TIMEOUT) {
                        Ok(response) => {
                            if active.write_response(&response, max_frame_bytes).is_err() {
                                connection = None;
                            }
                        }
                        Err(_) => {
                            let _ = active.write_response(
                                &ToolResponse::failure(request_id, "Tool execution timed out"),
                                max_frame_bytes,
                            );
                        }
                    },
                    Err(TrySendError::Full(_)) => {
                        let _ = active.write_response(
                            &ToolResponse::failure(request_id, "Tool queue is full"),
                            max_frame_bytes,
                        );
                    }
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
            Ok(None) => {}
            Err(_) => connection = None,
        }
    }
    let _ = fs::remove_file(socket_path);
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create Tool socket directory {}", parent.display()))?;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() {
        anyhow::bail!(
            "refusing to replace non-socket Tool path {}",
            path.display()
        );
    }
    if UnixStream::connect(path).is_ok() {
        anyhow::bail!("Tool socket {} is already active", path.display());
    }
    fs::remove_file(path).with_context(|| format!("remove stale Tool socket {}", path.display()))
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime};

    use super::{execute, ToolRequest, ToolResponse, ToolServer};
    use crate::identity::{ProcessKey, TaskKey};
    use crate::local_frame::{encode, FrameReader};
    use crate::registry::ClassificationRegistry;
    use serde_json::json;

    #[test]
    fn workload_list_and_classification_are_read_only() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 1,
            process_cookie: 2,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 3,
            task_cookie: 4,
        };
        registry.on_process_discovered(process, None, 0);
        registry.on_task_discovered(task, process, 0);
        let request = ToolRequest {
            request_id: 1,
            tool: "workload.list".into(),
            arguments: json!({}),
        };
        let response = execute(&request, &registry, None);
        assert!(response.ok);
        assert_eq!(response.result.unwrap()["total"], 2);
        assert_eq!(registry.stats().tasks, 1);
    }

    #[test]
    fn scheduler_tool_requires_live_snapshot() {
        let request = ToolRequest {
            request_id: 2,
            tool: "scheduler.health".into(),
            arguments: json!({}),
        };
        assert!(!execute(&request, &ClassificationRegistry::default(), None).ok);
    }

    #[test]
    fn unix_socket_serves_a_framed_query() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "adaptive-agent-tool-test-{}-{nonce}.sock",
                std::process::id()
            ));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = match ToolServer::spawn(&path, 2, 4096, shutdown.clone()) {
            Ok(server) => server,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied) =>
            {
                return;
            }
            Err(error) => panic!("{error:#}"),
        };
        let mut stream = UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let request = ToolRequest {
            request_id: 3,
            tool: "workload.list".into(),
            arguments: json!({}),
        };
        let body = serde_json::to_vec(&request).unwrap();
        stream.write_all(&encode(&body, 4096).unwrap()).unwrap();

        let call = loop {
            if let Some(call) = server.try_recv() {
                break call;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let response = execute(&call.request, &ClassificationRegistry::default(), None);
        call.respond(response);

        let mut reader = FrameReader::default();
        let body = loop {
            if let Some(body) = reader.read(&mut stream, 4096).unwrap() {
                break body;
            }
        };
        let response: ToolResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.ok);
        assert_eq!(response.request_id, 3);

        shutdown.store(true, Ordering::Release);
        server.join();
        assert!(!path.exists());
    }
}
