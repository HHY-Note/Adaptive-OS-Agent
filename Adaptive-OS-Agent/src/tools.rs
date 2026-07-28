// SPDX-License-Identifier: Apache-2.0

//! Read-only standardized Agent Tool interface over a bounded local socket.

use std::collections::HashSet;
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
use crate::registry::{ClassificationRegistry, ClassificationTiming, SemanticState};

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
    #[serde(default)]
    tgids: Vec<u32>,
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
    if args.tgids.len() > 256 || args.tgids.contains(&0) {
        return Err("tgids must contain at most 256 non-zero process IDs".into());
    }
    let tgids: HashSet<_> = args.tgids.into_iter().collect();
    let includes = |tgid: u32| tgids.is_empty() || tgids.contains(&tgid);

    let mut rows = Vec::new();
    if scope != "task" {
        let mut retired: Vec<_> = registry
            .retired_processes()
            .filter(|record| includes(record.identity.tgid))
            .collect();
        retired.sort_unstable_by_key(|record| record.identity);
        rows.extend(
            retired
                .into_iter()
                .map(|record| process_list_item(record, "exited")),
        );
        let mut records: Vec<_> = registry
            .processes()
            .filter(|record| includes(record.identity.tgid))
            .collect();
        records.sort_unstable_by_key(|record| record.identity);
        rows.extend(
            records
                .into_iter()
                .map(|record| process_list_item(record, "active")),
        );
    }
    if scope != "process" {
        let mut retired: Vec<_> = registry
            .retired_tasks()
            .filter(|record| includes(record.process.tgid))
            .collect();
        retired.sort_unstable_by_key(|record| record.identity);
        rows.extend(
            retired
                .into_iter()
                .map(|record| task_list_item(record, "exited")),
        );
        let mut records: Vec<_> = registry
            .tasks()
            .filter(|record| includes(record.process.tgid))
            .collect();
        records.sort_unstable_by_key(|record| record.identity);
        rows.extend(
            records
                .into_iter()
                .map(|record| task_list_item(record, "active")),
        );
    }
    let total = rows.len();
    let items: Vec<_> = rows
        .into_iter()
        .skip(args.offset)
        .take(args.limit)
        .collect();
    Ok(json!({"items": items, "total": total, "registry": registry.stats()}))
}

fn process_list_item(record: &crate::registry::ProcessRecord, lifecycle: &str) -> Value {
    json!({
        "kind": "process",
        "identity": record.identity,
        "lifecycle": lifecycle,
        "comm": record.metadata.as_ref().map(|metadata| metadata.comm.as_str()),
        "tasks": record.tasks.len(),
        "classification": process_classification(record),
    })
}

fn task_list_item(record: &crate::registry::TaskRecord, lifecycle: &str) -> Value {
    json!({
        "kind": "task",
        "identity": record.identity,
        "process": record.process,
        "lifecycle": lifecycle,
        "classification": task_classification(record),
    })
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
            Ok(process_classification(record))
        }
        Target::Task(task) => {
            let record = registry
                .task(task)
                .ok_or_else(|| "task identity not found".to_string())?;
            Ok(task_classification(record))
        }
    }
}

fn process_classification(record: &crate::registry::ProcessRecord) -> Value {
    json!({
        "kind": "process",
        "identity": record.identity,
        "class": record.default_class,
        "stage": "process_default",
        "source": process_source(record),
        "confidence": process_confidence(record),
        "generation": record.class_generation,
        "applied_generation": record.applied_generation,
        "timing": classification_timing(record.created_ns, &record.timing),
    })
}

fn task_classification(record: &crate::registry::TaskRecord) -> Value {
    let source = match record.stage {
        ClassStage::Inherited if matches!(record.semantic, SemanticState::Classified { class, .. } if class != record.effective_class) => {
            "llm_pending_behavior"
        }
        ClassStage::Inherited => "process_default",
        ClassStage::Semantic => "llm",
        ClassStage::Locked => "behavior",
    };
    json!({
        "kind": "task",
        "identity": record.identity,
        "process": record.process,
        "class": record.effective_class,
        "stage": record.stage,
        "source": source,
        "confidence": task_confidence(record),
        "generation": record.class_generation,
        "applied_generation": record.applied_generation,
        "timing": classification_timing(record.created_ns, &record.timing),
    })
}

fn classification_timing(created_ns: u64, timing: &ClassificationTiming) -> Value {
    json!({
        "discovered_ns": created_ns,
        "semantic_requested_ns": timing.semantic_requested_ns,
        "semantic_resolved_ns": timing.semantic_resolved_ns,
        "behavior_evidence_ns": timing.behavior_evidence_ns,
        "decided_ns": timing.decided_ns,
        "locked_ns": timing.locked_ns,
        "applied_ns": timing.applied_ns,
        "request_delay_ns": elapsed_from(created_ns, timing.semantic_requested_ns),
        "semantic_latency_ns": elapsed_between(
            timing.semantic_requested_ns,
            timing.semantic_resolved_ns,
        ),
        "behavior_delay_ns": elapsed_from(created_ns, timing.behavior_evidence_ns),
        "decision_delay_ns": elapsed_from(created_ns, timing.decided_ns),
        "lock_delay_ns": elapsed_from(created_ns, timing.locked_ns),
        "apply_delay_ns": elapsed_from(created_ns, timing.applied_ns),
    })
}

fn elapsed_from(start_ns: u64, end_ns: Option<u64>) -> Option<u64> {
    end_ns.map(|end_ns| end_ns.saturating_sub(start_ns))
}

fn elapsed_between(start_ns: Option<u64>, end_ns: Option<u64>) -> Option<u64> {
    start_ns
        .zip(end_ns)
        .map(|(start_ns, end_ns)| end_ns.saturating_sub(start_ns))
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
    }))
}

fn scheduler_stats(snapshot: Option<&Value>) -> Result<Value, String> {
    let snapshot = snapshot.ok_or_else(|| "scheduler snapshot is unavailable".to_string())?;
    Ok(json!({
        "scheduler_epoch": snapshot.get("scheduler_epoch"),
        "cpu_count": snapshot.get("cpu_count"),
        "tasks": snapshot.get("tasks"),
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

fn process_source(record: &crate::registry::ProcessRecord) -> &'static str {
    if record.behavior_override {
        return if matches!(record.semantic, SemanticState::Classified { .. })
            || record.local_class.is_some()
        {
            "hybrid"
        } else {
            "behavior"
        };
    }
    if record.inherited_from.is_some() {
        return "parent_default";
    }
    match record.semantic {
        SemanticState::Classified { class, .. }
            if class != record.default_class && record.local_class.is_none() =>
        {
            if record.timing.semantic_requested_ns.is_none() {
                "semantic_cache_pending_behavior"
            } else {
                "llm_pending_behavior"
            }
        }
        SemanticState::Classified { .. } if record.timing.semantic_requested_ns.is_none() => {
            "semantic_cache"
        }
        SemanticState::Classified { .. } if record.local_class.is_some() => "hybrid",
        SemanticState::Classified { .. } => "llm",
        _ if record.local_class.is_some() => "local_metadata",
        SemanticState::Unknown | SemanticState::Failed => "fallback",
        SemanticState::Pending | SemanticState::Requested => "default",
    }
}

fn process_confidence(record: &crate::registry::ProcessRecord) -> Option<f32> {
    if record.behavior_override {
        return record
            .behavior_confidence_per_mille
            .map(|confidence| f32::from(confidence) / 1000.0);
    }
    let semantic = semantic_confidence(record.semantic);
    let local = record
        .local_confidence_per_mille
        .map(|confidence| f32::from(confidence) / 1000.0);
    match (semantic, local) {
        (Some(semantic), Some(local)) => Some(semantic.min(local)),
        (Some(confidence), None) | (None, Some(confidence)) => Some(confidence),
        (None, None) => None,
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

fn task_confidence(record: &crate::registry::TaskRecord) -> Option<f32> {
    match record.stage {
        ClassStage::Locked => record
            .behavior_confidence_per_mille
            .map(|confidence| f32::from(confidence) / 1000.0),
        ClassStage::Inherited => None,
        ClassStage::Semantic => semantic_confidence(record.semantic),
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
        let result = response.result.unwrap();
        assert_eq!(result["total"], 2);
        assert!(result["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["classification"].is_object()));
        assert_eq!(registry.stats().tasks, 1);
    }

    #[test]
    fn workload_list_includes_recently_exited_classification() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 11,
            process_cookie: 12,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 13,
            task_cookie: 14,
        };
        registry.on_task_discovered(task, process, 1);
        registry.on_task_exited(task, process);
        let request = ToolRequest {
            request_id: 3,
            tool: "workload.list".into(),
            arguments: json!({"scope": "task"}),
        };

        let result = execute(&request, &registry, None).result.unwrap();
        assert_eq!(result["total"], 1);
        assert_eq!(result["items"][0]["lifecycle"], "exited");
        assert_eq!(result["items"][0]["identity"], json!(task));
        assert!(result["items"][0]["classification"].is_object());

        let filtered = ToolRequest {
            request_id: 4,
            tool: "workload.list".into(),
            arguments: json!({"scope": "task", "tgids": [99]}),
        };
        assert_eq!(
            execute(&filtered, &registry, None).result.unwrap()["total"],
            0
        );
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
