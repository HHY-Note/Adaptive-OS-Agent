// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet, VecDeque};

use crate::behavior::{BehaviorWindow, WindowQuality};
use crate::config::ClassificationConfig;
use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
use crate::limits::RuntimeLimits;
use crate::metadata::{redact_command, ProcessInstanceKey, ProcessMetadata};
use crate::process_classifier::classify_process_metadata;
use crate::scheduler_client::{
    ProcessSnapshot, RegistrySnapshotBatch, SchedulerClient, TaskSnapshot,
};
use crate::skills::{
    BehaviorClassificationProposal, ProcessClassificationProposal, ThreadClassificationProposal,
};

/// Lifecycle state of one bounded semantic LLM request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticState {
    /// Metadata is known but no request has been submitted yet.
    Pending,
    /// One request is in flight; results must still match current identity.
    Requested,
    /// Semantic model returned a known class and confidence.
    Classified {
        /// Model-selected class.
        class: TaskClass,
        /// Strictly validated confidence.
        confidence_per_mille: u16,
    },
    /// Model returned Unknown or omitted the item; no re-query is allowed.
    Unknown,
    /// Bounded HTTP/schema retries failed; behavior may provide fallback evidence.
    Failed,
}

/// Exact bounded metadata reused only within one Agent lifetime.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProcessSemanticFingerprint {
    comm: String,
    command: Vec<String>,
    executable: Option<String>,
    cgroups: Vec<String>,
    uid: Option<u32>,
}

impl From<&ProcessMetadata> for ProcessSemanticFingerprint {
    fn from(metadata: &ProcessMetadata) -> Self {
        Self {
            comm: metadata.comm.clone(),
            command: redact_command(&metadata.command),
            executable: metadata.executable.clone(),
            cgroups: metadata.cgroups.clone(),
            uid: metadata.uid,
        }
    }
}

/// Consecutive strong behavior evidence retained for one possible correction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EvidenceStreak {
    /// Candidate class seen in consecutive good windows.
    class: Option<TaskClass>,
    /// Consecutive count for that candidate.
    windows: u32,
    /// Lowest confidence across the current consecutive evidence streak.
    confidence_per_mille: u16,
}

#[derive(Clone, Copy, Debug)]
struct TaskReplay {
    effective_class: TaskClass,
    stage: ClassStage,
    class_generation: u64,
    semantic: SemanticState,
    behavior_confidence_per_mille: Option<u16>,
    created_ns: u64,
    timing: ClassificationTiming,
}

/// Monotonic milestones for one process or task classification lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClassificationTiming {
    /// First successful semantic queue submission.
    pub semantic_requested_ns: Option<u64>,
    /// First terminal semantic response, including unknown or failed results.
    pub semantic_resolved_ns: Option<u64>,
    /// First behavior window containing usable local classification evidence.
    pub behavior_evidence_ns: Option<u64>,
    /// First explicit semantic or behavior decision.
    pub decided_ns: Option<u64>,
    /// Time at which a task entered its final local lock stage.
    pub locked_ns: Option<u64>,
    /// First matching scheduler acknowledgement for the current decision.
    pub applied_ns: Option<u64>,
}

impl EvidenceStreak {
    /// Records one strong evidence class or resets on contradictory/weak evidence.
    fn record(&mut self, proposal: Option<(TaskClass, u16)>) {
        match proposal {
            Some((class, confidence)) if self.class == Some(class) => {
                self.windows = self.windows.saturating_add(1);
                self.confidence_per_mille = self.confidence_per_mille.min(confidence);
            }
            Some((class, confidence)) => {
                self.class = Some(class);
                self.windows = 1;
                self.confidence_per_mille = confidence.min(1000);
            }
            None => {
                self.clear();
            }
        }
    }

    /// Clears all accumulated evidence after a class match or lock transition.
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Independent locked task decisions aggregated within one process image.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProcessBehaviorEvidence {
    latency: u32,
    balanced: u32,
    throughput: u32,
}

impl ProcessBehaviorEvidence {
    fn record(&mut self, class: TaskClass) {
        let count = match class {
            TaskClass::Latency => &mut self.latency,
            TaskClass::Balanced => &mut self.balanced,
            TaskClass::Throughput => &mut self.throughput,
        };
        *count = count.saturating_add(1);
    }

    /// Requires two task decisions before changing a process-wide default.
    fn candidate(self) -> Option<(TaskClass, u16)> {
        let total = self
            .latency
            .saturating_add(self.balanced)
            .saturating_add(self.throughput);
        if total < 2 {
            return None;
        }
        let class = if self.balanced > 0 || (self.latency > 0 && self.throughput > 0) {
            TaskClass::Balanced
        } else if self.latency >= 2 {
            TaskClass::Latency
        } else if self.throughput >= 2 {
            TaskClass::Throughput
        } else {
            return None;
        };
        let confidence = 750_u16.saturating_add(total.min(5) as u16 * 50);
        Some((class, confidence))
    }
}

/// Agent-owned record for one process image.
#[derive(Clone, Debug)]
pub struct ProcessRecord {
    /// Stable scheduler identity.
    pub identity: ProcessKey,
    /// Current proc start-time key, absent if process disappeared before metadata read.
    pub instance: Option<ProcessInstanceKey>,
    /// Bounded process context for LLM thread batches.
    pub metadata: Option<ProcessMetadata>,
    /// Effective default class supplied to inherited scheduler tasks.
    pub default_class: TaskClass,
    /// Parent process default followed until this process gets its own known class.
    pub inherited_from: Option<ProcessKey>,
    /// Process default generation mirrored to every inherited task.
    pub class_generation: u64,
    /// Last generation explicitly acknowledged by scheduler or a completed snapshot.
    pub applied_generation: u64,
    /// One-time process semantic request status.
    pub semantic: SemanticState,
    /// Immediate high-confidence class derived from explicit process metadata.
    pub local_class: Option<TaskClass>,
    /// Confidence attached to the immediate metadata decision.
    pub local_confidence_per_mille: Option<u16>,
    /// Whether local task evidence contributes to the current process default.
    pub behavior_override: bool,
    /// Confidence of the aggregated local process decision.
    pub behavior_confidence_per_mille: Option<u16>,
    /// Monotonic creation time used for long-lived thread eligibility.
    pub created_ns: u64,
    /// Classification lifecycle milestones relative to Agent startup.
    pub timing: ClassificationTiming,
    /// Stable task lifetimes currently known to belong to this process image.
    pub tasks: HashSet<TaskKey>,
    /// Locked task decisions used for conservative process-level fallback.
    behavior: ProcessBehaviorEvidence,
    /// Stable control request reused until this desired generation is acknowledged.
    pending_request_id: Option<u64>,
}

/// Agent-owned record for one task lifetime.
#[derive(Clone, Debug)]
pub struct TaskRecord {
    /// Stable scheduler task identity.
    pub identity: TaskKey,
    /// Current owning process image.
    pub process: ProcessKey,
    /// Effective class submitted to scheduler.
    pub effective_class: TaskClass,
    /// Inherited, semantic, or one-time locked stage.
    pub stage: ClassStage,
    /// Task class generation mirrored into BPF by scheduler control path.
    pub class_generation: u64,
    /// Last generation explicitly acknowledged by scheduler or a completed snapshot.
    pub applied_generation: u64,
    /// One-time thread semantic request status.
    pub semantic: SemanticState,
    /// Confidence of a locked local behavior decision, when present.
    pub behavior_confidence_per_mille: Option<u16>,
    /// Monotonic task discovery time.
    pub created_ns: u64,
    /// Classification lifecycle milestones relative to Agent startup.
    pub timing: ClassificationTiming,
    /// `/proc` start time used to reject TID reuse during scheduler replay.
    pub start_time_ticks: Option<u64>,
    /// Consecutive strong contrary evidence for the one lock transition.
    behavior: EvidenceStreak,
    /// Last accepted scheduler behavior sequence for replay and gap detection.
    last_behavior_window_sequence: u64,
    /// Stable control request reused until this desired generation is acknowledged.
    pending_request_id: Option<u64>,
}

/// Validated Agent decision requiring scheduler control-plane commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryAction {
    /// Update process default and every inherited BPF task generation atomically.
    SetProcessDefault {
        /// Stable idempotency ID retained across retries.
        request_id: u64,
        /// Exact process image.
        process: ProcessKey,
        /// New process default class.
        class: TaskClass,
        /// Scheduler generation required before the update.
        expected_generation: u64,
        /// Desired generation after the update.
        new_generation: u64,
    },
    /// Update one semantic or permanently locked task class.
    SetTaskClass {
        /// Stable idempotency ID retained across retries.
        request_id: u64,
        /// Exact task lifetime.
        task: TaskKey,
        /// Exact owning process image.
        process: ProcessKey,
        /// New effective class.
        class: TaskClass,
        /// Semantic or locked lifecycle stage.
        stage: ClassStage,
        /// Scheduler generation required before the update.
        expected_generation: u64,
        /// Desired generation after the update.
        new_generation: u64,
    },
}

impl RegistryAction {
    /// Returns the stable request identity used by scheduler replay protection.
    pub const fn request_id(self) -> u64 {
        match self {
            Self::SetProcessDefault { request_id, .. } | Self::SetTaskClass { request_id, .. } => {
                request_id
            }
        }
    }

    /// Returns the generation scheduler should acknowledge.
    pub const fn new_generation(self) -> u64 {
        match self {
            Self::SetProcessDefault { new_generation, .. }
            | Self::SetTaskClass { new_generation, .. } => new_generation,
        }
    }
}

/// Long-lived TGID thread batch plan; process context is kept outside the LLM ID.
#[derive(Clone, Debug)]
pub struct ThreadBatchPlan {
    /// Stable owning process image.
    pub process: ProcessKey,
    /// Bounded process metadata shared with all thread rows.
    pub metadata: ProcessMetadata,
    /// Stable task lifetimes eligible for exactly one semantic request.
    pub tasks: Vec<TaskKey>,
}

/// One process semantic batch tied to a unique Agent request generation.
#[derive(Clone, Debug)]
pub struct ProcessBatchPlan {
    /// Non-zero generation used to reject results that arrive after exit/exec.
    pub request_id: u64,
    /// Bounded metadata rows submitted in this logical request.
    pub processes: Vec<ProcessMetadata>,
}

/// Classification registry keyed exclusively by BPF scheduler identities.
#[derive(Clone, Debug)]
pub struct ClassificationRegistry {
    /// Stable process image records.
    processes: HashMap<ProcessKey, ProcessRecord>,
    /// Exact proc lifetimes bound to their current scheduler process image.
    process_by_instance: HashMap<ProcessInstanceKey, ProcessKey>,
    /// Stable task lifetime records.
    tasks: HashMap<TaskKey, TaskRecord>,
    /// Recently exited process projections retained for bounded observability.
    retired_processes: VecDeque<ProcessRecord>,
    /// Recently exited task projections retained for bounded observability.
    retired_tasks: VecDeque<TaskRecord>,
    /// Task classifications awaiting new BPF cookies during lifecycle replay.
    replay_tasks: HashMap<(ProcessInstanceKey, u32, u64), TaskReplay>,
    /// Startup/reconciliation metadata indexed before cookie binding.
    metadata_by_instance: HashMap<ProcessInstanceKey, ProcessMetadata>,
    /// Process LLM states indexed before scheduler identity is observed.
    process_semantics: HashMap<ProcessInstanceKey, SemanticState>,
    /// Known exact metadata signatures, bounded to process registry capacity.
    semantic_cache: HashMap<ProcessSemanticFingerprint, SemanticState>,
    semantic_cache_order: VecDeque<ProcessSemanticFingerprint>,
    /// Active semantic request generation for each pre-cookie process instance.
    process_request_ids: HashMap<ProcessInstanceKey, u64>,
    /// Semantic timing retained before a process receives its scheduler cookie.
    process_timings: HashMap<ProcessInstanceKey, ClassificationTiming>,
    /// Monotonic source for non-zero process request generations.
    next_process_request_id: u64,
    /// Monotonic high-range source for idempotent scheduler requests.
    next_control_request_id: u64,
    /// Monotonic non-zero source for Registry snapshot sessions.
    next_snapshot_id: u64,
    /// Configured semantic acceptance threshold in per-mille units.
    min_confidence_per_mille: u16,
    /// Confidence required before semantics may specialize a whole process.
    specialization_confidence_per_mille: u16,
    /// Immutable process and task capacity bounds.
    limits: RuntimeLimits,
    /// Process/metadata records skipped at the configured capacity.
    dropped_process_records: u64,
    /// Task records skipped at the configured capacity.
    dropped_task_records: u64,
}

/// Small public projection used by standardized Tool responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RegistryStats {
    pub processes: usize,
    pub tasks: usize,
    pub pending_actions: usize,
    pub dropped_process_records: u64,
    pub dropped_task_records: u64,
}

impl Default for ClassificationRegistry {
    fn default() -> Self {
        let config = ClassificationConfig::default();
        Self::new(
            RuntimeLimits::default(),
            0.60,
            config.high_confidence_threshold,
        )
    }
}

impl ClassificationRegistry {
    /// Creates a bounded Registry with explicit semantic confidence thresholds.
    pub fn new(limits: RuntimeLimits, min_confidence: f32, specialization_confidence: f32) -> Self {
        let min_confidence_per_mille = (min_confidence * 1000.0).round().clamp(0.0, 1000.0) as u16;
        let specialization_confidence_per_mille = (specialization_confidence * 1000.0)
            .round()
            .clamp(0.0, 1000.0) as u16;
        Self {
            processes: HashMap::new(),
            process_by_instance: HashMap::new(),
            tasks: HashMap::new(),
            retired_processes: VecDeque::new(),
            retired_tasks: VecDeque::new(),
            replay_tasks: HashMap::new(),
            metadata_by_instance: HashMap::new(),
            process_semantics: HashMap::new(),
            semantic_cache: HashMap::new(),
            semantic_cache_order: VecDeque::new(),
            process_request_ids: HashMap::new(),
            process_timings: HashMap::new(),
            next_process_request_id: 1,
            next_control_request_id: SchedulerClient::first_action_request_id(),
            next_snapshot_id: 1,
            min_confidence_per_mille,
            specialization_confidence_per_mille,
            limits,
            dropped_process_records: 0,
            dropped_task_records: 0,
        }
    }

    /// Stores a `/proc` metadata snapshot without creating a cookie-based record.
    pub fn remember_metadata(&mut self, metadata: ProcessMetadata) {
        let instance = metadata.instance;
        if !self.metadata_by_instance.contains_key(&instance)
            && self.metadata_by_instance.len() >= self.limits.registry_processes
        {
            self.dropped_process_records = self.dropped_process_records.saturating_add(1);
            return;
        }
        let cached = self
            .semantic_cache
            .get(&ProcessSemanticFingerprint::from(&metadata))
            .copied();
        self.metadata_by_instance.insert(instance, metadata);
        let state = self
            .process_semantics
            .entry(instance)
            .or_insert(cached.unwrap_or(SemanticState::Pending));
        if *state == SemanticState::Pending {
            if let Some(cached) = cached {
                *state = cached;
            }
        }
    }

    /// Returns newest unrequested process metadata in deterministic bounded batches.
    pub fn take_process_batches(
        &mut self,
        batch_size: usize,
        max_batches: usize,
    ) -> Vec<ProcessBatchPlan> {
        self.take_process_batches_at(0, 0, batch_size, max_batches)
    }

    /// Returns newest scheduler-observed processes old enough for remote semantics.
    pub fn take_process_batches_at(
        &mut self,
        now_ns: u64,
        min_age_ns: u64,
        batch_size: usize,
        max_batches: usize,
    ) -> Vec<ProcessBatchPlan> {
        let mut instances: Vec<_> = self
            .process_semantics
            .iter()
            .filter_map(|(instance, state)| {
                if *state != SemanticState::Pending {
                    return None;
                }
                if min_age_ns == 0 {
                    return Some(*instance);
                }
                let process = self.process_by_instance.get(instance)?;
                let record = self.processes.get(process)?;
                (now_ns.saturating_sub(record.created_ns) >= min_age_ns).then_some(*instance)
            })
            .collect();
        instances.sort_unstable_by(|left, right| {
            right
                .start_time_ticks
                .cmp(&left.start_time_ticks)
                .then_with(|| left.tgid.cmp(&right.tgid))
        });
        let mut batches = Vec::new();
        for chunk in instances.chunks(batch_size.max(1)).take(max_batches.max(1)) {
            let batch: Vec<_> = chunk
                .iter()
                .filter_map(|instance| self.metadata_by_instance.get(instance).cloned())
                .collect();
            if batch.is_empty() {
                continue;
            }
            let request_id = self.allocate_process_request_id();
            for metadata in &batch {
                self.process_semantics
                    .insert(metadata.instance, SemanticState::Requested);
                self.process_request_ids
                    .insert(metadata.instance, request_id);
            }
            batches.push(ProcessBatchPlan {
                request_id,
                processes: batch,
            });
        }
        batches
    }

    /// Returns an unsent process batch to Pending without consuming its one attempt.
    pub fn defer_process_batch(&mut self, plan: &ProcessBatchPlan) {
        for process in &plan.processes {
            if self.process_request_ids.get(&process.instance) == Some(&plan.request_id) {
                self.process_request_ids.remove(&process.instance);
                self.process_semantics
                    .insert(process.instance, SemanticState::Pending);
            }
        }
    }

    /// Records the first successful queue submission for one process batch.
    pub fn mark_process_batch_submitted(&mut self, plan: &ProcessBatchPlan, now_ns: u64) {
        for process in &plan.processes {
            if self.process_request_ids.get(&process.instance) != Some(&plan.request_id) {
                continue;
            }
            let timing = self.process_timings.entry(process.instance).or_default();
            set_once(&mut timing.semantic_requested_ns, now_ns);
            for record in self
                .processes
                .values_mut()
                .filter(|record| record.instance == Some(process.instance))
            {
                set_once(&mut record.timing.semantic_requested_ns, now_ns);
            }
        }
    }

    /// Marks one failed process batch as fallback exactly once; it is never requeued.
    pub fn mark_process_batch_failed(&mut self, plan: &ProcessBatchPlan) {
        self.mark_process_batch_failed_at(plan, 0);
    }

    /// Marks one failed process batch and records its terminal response time.
    pub fn mark_process_batch_failed_at(&mut self, plan: &ProcessBatchPlan, now_ns: u64) {
        for process in &plan.processes {
            self.mark_process_request_failed(process.instance, plan.request_id, now_ns);
        }
    }

    /// Finalizes one exact request item that failed or disappeared before inference.
    fn mark_process_request_failed(
        &mut self,
        instance: ProcessInstanceKey,
        request_id: u64,
        now_ns: u64,
    ) {
        if self.process_request_ids.get(&instance) != Some(&request_id) {
            return;
        }
        self.process_request_ids.remove(&instance);
        self.process_semantics
            .insert(instance, SemanticState::Failed);
        let timing = self.process_timings.entry(instance).or_default();
        set_once(&mut timing.semantic_resolved_ns, now_ns);
        for record in self
            .processes
            .values_mut()
            .filter(|record| record.instance == Some(instance))
        {
            record.semantic = SemanticState::Failed;
            set_once(&mut record.timing.semantic_resolved_ns, now_ns);
        }
    }

    /// Binds process metadata and any completed proposal to BPF identity.
    pub fn on_process_discovered(
        &mut self,
        identity: ProcessKey,
        metadata: Option<ProcessMetadata>,
        now_ns: u64,
    ) -> Vec<RegistryAction> {
        if self.processes.contains_key(&identity) {
            return Vec::new();
        }
        if self.processes.len() >= self.limits.registry_processes {
            self.dropped_process_records = self.dropped_process_records.saturating_add(1);
            return Vec::new();
        }
        if let Some(metadata) = metadata.clone() {
            self.remember_metadata(metadata);
        }
        let instance = metadata.as_ref().map(|metadata| metadata.instance);
        let metadata =
            instance.and_then(|instance| self.metadata_by_instance.get(&instance).cloned());
        let inherited_from = metadata
            .as_ref()
            .and_then(|metadata| metadata.parent)
            .and_then(|parent| self.process_by_instance.get(&parent))
            .copied();
        let inherited_class = inherited_from
            .and_then(|parent| self.processes.get(&parent))
            .map(|parent| parent.default_class)
            .unwrap_or(TaskClass::Balanced);
        let semantic = instance
            .and_then(|instance| self.process_semantics.get(&instance).copied())
            .unwrap_or(SemanticState::Pending);
        let local = metadata.as_ref().and_then(classify_process_metadata);
        let timing = instance
            .and_then(|instance| self.process_timings.get(&instance).copied())
            .unwrap_or_default();
        let mut record = ProcessRecord {
            identity,
            instance,
            metadata,
            default_class: inherited_class,
            inherited_from,
            class_generation: 0,
            applied_generation: 0,
            semantic,
            local_class: local.map(|decision| decision.class),
            local_confidence_per_mille: local.map(|decision| decision.confidence_per_mille),
            behavior_override: false,
            behavior_confidence_per_mille: None,
            created_ns: now_ns,
            timing,
            tasks: HashSet::new(),
            behavior: ProcessBehaviorEvidence::default(),
            pending_request_id: None,
        };
        let mut actions = Vec::new();
        if let SemanticState::Classified {
            class,
            confidence_per_mille,
        } = record.semantic
        {
            set_once(&mut record.timing.semantic_resolved_ns, now_ns);
            if let Some((class, behavior_override, behavior_confidence, _)) =
                process_default_decision(
                    class,
                    confidence_per_mille,
                    record.local_class.zip(record.local_confidence_per_mille),
                    record.behavior.candidate(),
                    self.specialization_confidence_per_mille,
                )
            {
                record.default_class = class;
                record.inherited_from = None;
                record.behavior_override = behavior_override;
                record.behavior_confidence_per_mille = behavior_confidence;
                set_once(&mut record.timing.decided_ns, now_ns);
            }
        } else if let Some(local) = local {
            record.default_class = local.class;
            record.inherited_from = None;
            set_once(&mut record.timing.decided_ns, now_ns);
        }
        if record.default_class != TaskClass::Balanced {
            record.class_generation = 1;
            let request_id = self.allocate_control_request_id();
            record.pending_request_id = Some(request_id);
            actions.push(RegistryAction::SetProcessDefault {
                request_id,
                process: identity,
                class: record.default_class,
                expected_generation: 0,
                new_generation: 1,
            });
        }
        let default_class = record.default_class;
        self.processes.insert(identity, record);
        if let Some(instance) = instance {
            self.process_by_instance.insert(instance, identity);
            self.attach_waiting_children(identity, instance);
        }
        actions.extend(self.propagate_inherited_process_default(identity, default_class));
        for action in &actions {
            self.sync_inherited_tasks(*action);
        }
        actions
    }

    /// Creates or rebinds a task record, always inheriting the current process default.
    pub fn on_task_discovered(&mut self, task: TaskKey, process: ProcessKey, now_ns: u64) {
        self.on_task_discovered_with_start_time(task, process, None, now_ns);
    }

    /// Rebinds a task and restores prior state only for the same `/proc` lifetime.
    pub fn on_task_discovered_with_start_time(
        &mut self,
        task: TaskKey,
        process: ProcessKey,
        start_time_ticks: Option<u64>,
        now_ns: u64,
    ) {
        if self
            .tasks
            .get(&task)
            .is_some_and(|record| record.process == process)
        {
            return;
        }
        if !self.tasks.contains_key(&task) && self.tasks.len() >= self.limits.registry_tasks {
            self.dropped_task_records = self.dropped_task_records.saturating_add(1);
            return;
        }
        if let Some(previous) = self.tasks.remove(&task) {
            if let Some(process_record) = self.processes.get_mut(&previous.process) {
                process_record.tasks.remove(&task);
            }
            self.retire_task(previous);
        }
        if !self.processes.contains_key(&process)
            && self.processes.len() >= self.limits.registry_processes
        {
            self.dropped_process_records = self.dropped_process_records.saturating_add(1);
            return;
        }
        let replay_key = self
            .processes
            .get(&process)
            .and_then(|record| record.instance)
            .zip(start_time_ticks)
            .map(|(instance, start_time)| (instance, task.tid, start_time));
        let replay = replay_key.and_then(|key| self.replay_tasks.remove(&key));
        let process_record = self
            .processes
            .entry(process)
            .or_insert_with(|| ProcessRecord {
                identity: process,
                instance: None,
                metadata: None,
                default_class: TaskClass::Balanced,
                inherited_from: None,
                class_generation: 0,
                applied_generation: 0,
                semantic: SemanticState::Pending,
                local_class: None,
                local_confidence_per_mille: None,
                behavior_override: false,
                behavior_confidence_per_mille: None,
                created_ns: now_ns,
                timing: ClassificationTiming::default(),
                tasks: HashSet::new(),
                behavior: ProcessBehaviorEvidence::default(),
                pending_request_id: None,
            });
        let mut record = TaskRecord {
            identity: task,
            process,
            effective_class: process_record.default_class,
            stage: ClassStage::Inherited,
            class_generation: process_record.class_generation,
            applied_generation: process_record.applied_generation,
            semantic: SemanticState::Pending,
            behavior_confidence_per_mille: None,
            created_ns: now_ns,
            timing: ClassificationTiming::default(),
            start_time_ticks,
            behavior: EvidenceStreak::default(),
            last_behavior_window_sequence: 0,
            pending_request_id: None,
        };
        if let Some(replay) = replay {
            record.semantic = match replay.semantic {
                SemanticState::Requested => SemanticState::Pending,
                state => state,
            };
            record.created_ns = replay.created_ns;
            record.timing = replay.timing;
            record.behavior_confidence_per_mille = replay.behavior_confidence_per_mille;
            if replay.stage != ClassStage::Inherited {
                record.effective_class = replay.effective_class;
                record.stage = replay.stage;
                record.class_generation = replay.class_generation;
                record.applied_generation = 0;
            }
        }
        process_record.tasks.insert(task);
        self.tasks.insert(task, record);
    }

    /// Saves semantic projections while scheduler/BPF identities are replayed.
    pub fn begin_scheduler_replay(&mut self) {
        self.replay_tasks.clear();
        let instances: HashMap<_, _> = self
            .processes
            .values()
            .filter_map(|record| record.instance.map(|instance| (record.identity, instance)))
            .collect();
        for record in self.tasks.values() {
            let (Some(instance), Some(start_time)) = (
                instances.get(&record.process).copied(),
                record.start_time_ticks,
            ) else {
                continue;
            };
            self.replay_tasks.insert(
                (instance, record.identity.tid, start_time),
                TaskReplay {
                    effective_class: record.effective_class,
                    stage: record.stage,
                    class_generation: record.class_generation,
                    semantic: record.semantic,
                    behavior_confidence_per_mille: record.behavior_confidence_per_mille,
                    created_ns: record.created_ns,
                    timing: record.timing,
                },
            );
        }
        self.processes.clear();
        self.process_by_instance.clear();
        self.tasks.clear();
    }

    /// Discards projections for tasks that did not survive the scheduler restart.
    pub fn finish_scheduler_replay(&mut self) {
        self.replay_tasks.clear();
    }

    /// Replaces all state from an old process image with its new exec generation.
    pub fn on_process_exec(
        &mut self,
        task: TaskKey,
        previous_process: ProcessKey,
        process: ProcessKey,
        metadata: Option<ProcessMetadata>,
        task_start_time_ticks: Option<u64>,
        now_ns: u64,
    ) -> Vec<RegistryAction> {
        if previous_process.tgid != process.tgid
            || previous_process.process_cookie != process.process_cookie
            || process.exec_generation <= previous_process.exec_generation
        {
            return Vec::new();
        }
        self.on_process_exited(previous_process);
        let actions = self.on_process_discovered(process, metadata, now_ns);
        self.on_task_discovered_with_start_time(task, process, task_start_time_ticks, now_ns);
        actions
    }

    /// Deletes only an exact task cookie/process pairing to prevent reuse pollution.
    pub fn on_task_exited(&mut self, task: TaskKey, process: ProcessKey) {
        if !self
            .tasks
            .get(&task)
            .is_some_and(|record| record.process == process)
        {
            return;
        }
        let retired = self.tasks.remove(&task);
        if let Some(process_record) = self.processes.get_mut(&process) {
            process_record.tasks.remove(&task);
        }
        if let Some(record) = retired {
            self.retire_task(record);
        }
    }

    /// Deletes a process and only tasks still bound to the exact process identity.
    pub fn on_process_exited(&mut self, process: ProcessKey) {
        let retired_process = self.processes.remove(&process);
        let instance = retired_process.as_ref().and_then(|record| record.instance);
        let retired_tasks: Vec<_> = self
            .tasks
            .iter()
            .filter_map(|(task, record)| (record.process == process).then_some(*task))
            .collect();
        for task in retired_tasks {
            if let Some(record) = self.tasks.remove(&task) {
                self.retire_task(record);
            }
        }
        for record in self.processes.values_mut() {
            if record.inherited_from == Some(process) {
                record.inherited_from = None;
            }
        }
        if let Some(instance) = instance {
            if self.process_by_instance.get(&instance) == Some(&process) {
                self.process_by_instance.remove(&instance);
            }
            let still_bound = self
                .processes
                .values()
                .any(|record| record.instance == Some(instance));
            if !still_bound {
                self.forget_instance(instance);
            }
        }
        if let Some(record) = retired_process {
            self.retire_process(record);
        }
    }

    /// Applies one completed process proposal batch after request validation.
    pub fn apply_process_proposals(
        &mut self,
        request_id: u64,
        proposals: Vec<ProcessClassificationProposal>,
    ) -> Vec<RegistryAction> {
        self.apply_process_proposals_at(request_id, proposals, 0)
    }

    /// Applies one completed process proposal batch with a monotonic response time.
    pub fn apply_process_proposals_at(
        &mut self,
        request_id: u64,
        proposals: Vec<ProcessClassificationProposal>,
        now_ns: u64,
    ) -> Vec<RegistryAction> {
        let mut classified = Vec::new();
        for proposal in proposals {
            if self.process_request_ids.get(&proposal.instance) != Some(&request_id) {
                continue;
            }
            self.process_request_ids.remove(&proposal.instance);
            let state = semantic_from_proposal(&proposal, self.min_confidence_per_mille);
            if let Some(metadata) = self.metadata_by_instance.get(&proposal.instance).cloned() {
                self.cache_process_semantic(&metadata, state);
            }
            self.process_semantics.insert(proposal.instance, state);
            let timing = self.process_timings.entry(proposal.instance).or_default();
            set_once(&mut timing.semantic_resolved_ns, now_ns);
            let timing = *timing;
            let specialization_confidence = self.specialization_confidence_per_mille;
            let mut identities: Vec<_> = self
                .processes
                .values()
                .filter(|record| record.instance == Some(proposal.instance))
                .map(|record| record.identity)
                .collect();
            identities.sort_unstable();
            for identity in identities {
                let Some(record) = self.processes.get_mut(&identity) else {
                    continue;
                };
                record.semantic = state;
                record.timing.semantic_requested_ns = timing.semantic_requested_ns;
                record.timing.semantic_resolved_ns = timing.semantic_resolved_ns;
                if let SemanticState::Classified {
                    class,
                    confidence_per_mille,
                } = state
                {
                    let Some((class, behavior_override, behavior_confidence, confidence)) =
                        process_default_decision(
                            class,
                            confidence_per_mille,
                            record.local_class.zip(record.local_confidence_per_mille),
                            record.behavior.candidate(),
                            specialization_confidence,
                        )
                    else {
                        continue;
                    };
                    record.inherited_from = None;
                    record.behavior_override = behavior_override;
                    record.behavior_confidence_per_mille = behavior_confidence;
                    set_once(&mut record.timing.decided_ns, now_ns);
                    classified.push((identity, class, confidence));
                }
            }
        }
        let missing: Vec<_> = self
            .process_request_ids
            .iter()
            .filter_map(|(instance, active_request)| {
                (*active_request == request_id).then_some(*instance)
            })
            .collect();
        for instance in missing {
            self.mark_process_request_failed(instance, request_id, now_ns);
        }
        let mut actions = Vec::new();
        for (identity, class, _) in &classified {
            if let Some(action) = self.update_process_default(*identity, *class) {
                actions.push(action);
            }
        }
        for (identity, class, confidence) in classified {
            actions.extend(self.propagate_inherited_process_default(identity, class));
            actions.extend(self.reconcile_locked_tasks(identity, class, confidence));
        }
        for action in &actions {
            self.sync_inherited_tasks(*action);
        }
        actions
    }

    /// Connects children observed before their exact parent scheduler identity.
    fn attach_waiting_children(&mut self, parent: ProcessKey, instance: ProcessInstanceKey) {
        let mut children: Vec<_> = self
            .processes
            .values()
            .filter(|record| {
                record.identity != parent
                    && record.inherited_from.is_none()
                    && !matches!(record.semantic, SemanticState::Classified { .. })
                    && record.local_class.is_none()
                    && record
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.parent == Some(instance))
            })
            .map(|record| record.identity)
            .collect();
        children.sort_unstable();
        for child in children {
            if let Some(record) = self.processes.get_mut(&child) {
                record.inherited_from = Some(parent);
            }
        }
    }

    /// Updates unresolved descendants after a parent receives its semantic class.
    fn propagate_inherited_process_default(
        &mut self,
        parent: ProcessKey,
        class: TaskClass,
    ) -> Vec<RegistryAction> {
        let mut children_by_parent: HashMap<_, Vec<_>> = HashMap::new();
        for record in self.processes.values() {
            if let Some(parent) = record.inherited_from {
                children_by_parent
                    .entry(parent)
                    .or_default()
                    .push(record.identity);
            }
        }
        for children in children_by_parent.values_mut() {
            children.sort_unstable_by(|left, right| right.cmp(left));
        }

        let mut actions = Vec::new();
        let mut stack = vec![parent];
        while let Some(parent) = stack.pop() {
            let Some(children) = children_by_parent.remove(&parent) else {
                continue;
            };
            for child in children {
                if let Some(action) = self.update_process_default(child, class) {
                    actions.push(action);
                }
                stack.push(child);
            }
        }
        actions
    }

    /// Promotes independent locked task decisions into a provisional process default.
    fn record_process_behavior(
        &mut self,
        process: ProcessKey,
        class: TaskClass,
        now_ns: u64,
    ) -> Vec<RegistryAction> {
        let specialization_confidence = self.specialization_confidence_per_mille;
        let (candidate, can_update) = {
            let Some(record) = self.processes.get_mut(&process) else {
                return Vec::new();
            };
            set_once(&mut record.timing.behavior_evidence_ns, now_ns);
            record.behavior.record(class);
            let Some((behavior_class, behavior_confidence)) = record.behavior.candidate() else {
                return Vec::new();
            };
            let (class, behavior_override, confidence) = match record.semantic {
                SemanticState::Classified {
                    class,
                    confidence_per_mille,
                } => {
                    let Some((class, behavior_override, confidence, _)) = process_default_decision(
                        class,
                        confidence_per_mille,
                        record.local_class.zip(record.local_confidence_per_mille),
                        Some((behavior_class, behavior_confidence)),
                        specialization_confidence,
                    ) else {
                        return Vec::new();
                    };
                    (class, behavior_override, confidence)
                }
                _ if record.inherited_from.is_some()
                    && record.default_class != TaskClass::Balanced
                    && record.default_class != behavior_class =>
                {
                    (TaskClass::Balanced, true, Some(behavior_confidence))
                }
                _ => (behavior_class, true, Some(behavior_confidence)),
            };
            record.behavior_override = behavior_override;
            record.behavior_confidence_per_mille = confidence;
            record.inherited_from = None;
            set_once(&mut record.timing.decided_ns, now_ns);
            (
                class,
                record.pending_request_id.is_none()
                    && record.applied_generation == record.class_generation,
            )
        };
        if !can_update {
            return Vec::new();
        }
        let mut actions = Vec::new();
        if let Some(action) = self.update_process_default(process, candidate) {
            actions.push(action);
        }
        actions.extend(self.propagate_inherited_process_default(process, candidate));
        for action in &actions {
            self.sync_inherited_tasks(*action);
        }
        actions
    }

    /// Reconciles local early locks once the owning process decision arrives.
    fn reconcile_locked_tasks(
        &mut self,
        process: ProcessKey,
        process_class: TaskClass,
        process_confidence_per_mille: u16,
    ) -> Vec<RegistryAction> {
        if process_class == TaskClass::Balanced {
            return Vec::new();
        }
        let mut tasks: Vec<_> = self
            .tasks
            .values()
            .filter(|task| {
                task.process == process
                    && task.stage == ClassStage::Locked
                    && task.behavior_confidence_per_mille.is_some()
                    && task.effective_class != TaskClass::Balanced
                    && task.effective_class != process_class
                    && task.pending_request_id.is_none()
                    && task.applied_generation == task.class_generation
            })
            .map(|task| task.identity)
            .collect();
        tasks.sort_unstable();

        let mut actions = Vec::new();
        for task_key in tasks {
            let request_id = self.allocate_control_request_id();
            let Some(task) = self.tasks.get_mut(&task_key) else {
                continue;
            };
            let expected_generation = task.applied_generation;
            task.effective_class = TaskClass::Balanced;
            task.behavior_confidence_per_mille = task
                .behavior_confidence_per_mille
                .map(|confidence| confidence.min(process_confidence_per_mille));
            task.class_generation = task.class_generation.saturating_add(1);
            task.pending_request_id = Some(request_id);
            actions.push(RegistryAction::SetTaskClass {
                request_id,
                task: task.identity,
                process,
                class: TaskClass::Balanced,
                stage: ClassStage::Locked,
                expected_generation,
                new_generation: task.class_generation,
            });
        }
        actions
    }

    /// Creates one generation-checked process action only when its class changes.
    fn update_process_default(
        &mut self,
        process: ProcessKey,
        class: TaskClass,
    ) -> Option<RegistryAction> {
        if self
            .processes
            .get(&process)
            .is_none_or(|record| record.default_class == class)
        {
            return None;
        }
        let request_id = self.allocate_control_request_id();
        let record = self.processes.get_mut(&process)?;
        let expected_generation = record.applied_generation;
        record.default_class = class;
        record.class_generation = record.class_generation.saturating_add(1);
        record.pending_request_id = Some(request_id);
        Some(RegistryAction::SetProcessDefault {
            request_id,
            process,
            class,
            expected_generation,
            new_generation: record.class_generation,
        })
    }

    /// Drops unbound `/proc` instances missing from the latest full scan.
    pub fn retain_live_instances(&mut self, live: &HashSet<ProcessInstanceKey>) {
        let bound: HashSet<_> = self
            .processes
            .values()
            .filter_map(|record| record.instance)
            .collect();
        let keep =
            |instance: &ProcessInstanceKey| live.contains(instance) || bound.contains(instance);
        self.metadata_by_instance
            .retain(|instance, _| keep(instance));
        self.process_semantics.retain(|instance, _| keep(instance));
        self.process_request_ids
            .retain(|instance, _| keep(instance));
        self.process_timings.retain(|instance, _| keep(instance));
    }

    /// Allocates a non-zero process request generation with wrap protection.
    fn allocate_process_request_id(&mut self) -> u64 {
        if self.next_process_request_id == 0 {
            self.next_process_request_id = 1;
        }
        let request_id = self.next_process_request_id;
        self.next_process_request_id = self.next_process_request_id.wrapping_add(1);
        if self.next_process_request_id == 0 {
            self.next_process_request_id = 1;
        }
        request_id
    }

    /// Allocates a stable high-range ID retained with one pending action.
    fn allocate_control_request_id(&mut self) -> u64 {
        if self.next_control_request_id < SchedulerClient::first_action_request_id() {
            self.next_control_request_id = SchedulerClient::first_action_request_id();
        }
        let request_id = self.next_control_request_id;
        self.next_control_request_id = self.next_control_request_id.wrapping_add(1);
        if self.next_control_request_id < SchedulerClient::first_action_request_id() {
            self.next_control_request_id = SchedulerClient::first_action_request_id();
        }
        request_id
    }

    /// Allocates one non-zero Registry snapshot session identity.
    pub fn allocate_snapshot_id(&mut self) -> u64 {
        if self.next_snapshot_id == 0 {
            self.next_snapshot_id = 1;
        }
        let snapshot_id = self.next_snapshot_id;
        self.next_snapshot_id = self.next_snapshot_id.wrapping_add(1);
        if self.next_snapshot_id == 0 {
            self.next_snapshot_id = 1;
        }
        snapshot_id
    }

    /// Removes all pre-cookie state for one process lifetime.
    fn forget_instance(&mut self, instance: ProcessInstanceKey) {
        self.process_by_instance.remove(&instance);
        self.metadata_by_instance.remove(&instance);
        self.process_semantics.remove(&instance);
        self.process_request_ids.remove(&instance);
        self.process_timings.remove(&instance);
    }

    fn cache_process_semantic(&mut self, metadata: &ProcessMetadata, state: SemanticState) {
        if !matches!(state, SemanticState::Classified { .. }) {
            return;
        }
        let fingerprint = ProcessSemanticFingerprint::from(metadata);
        if let Some(cached) = self.semantic_cache.get_mut(&fingerprint) {
            *cached = state;
            return;
        }
        while self.semantic_cache.len() >= self.limits.registry_processes {
            let Some(oldest) = self.semantic_cache_order.pop_front() else {
                break;
            };
            self.semantic_cache.remove(&oldest);
        }
        self.semantic_cache.insert(fingerprint.clone(), state);
        self.semantic_cache_order.push_back(fingerprint);
    }

    fn retire_process(&mut self, record: ProcessRecord) {
        while self.retired_processes.len() >= self.limits.registry_processes {
            self.retired_processes.pop_front();
        }
        self.retired_processes.push_back(record);
    }

    fn retire_task(&mut self, record: TaskRecord) {
        while self.retired_tasks.len() >= self.limits.registry_tasks {
            self.retired_tasks.pop_front();
        }
        self.retired_tasks.push_back(record);
    }

    /// Returns deterministic bounded thread batches and marks them Requested.
    pub fn take_thread_batch_plans(
        &mut self,
        now_ns: u64,
        config: &ClassificationConfig,
        batch_size: usize,
        max_batches: usize,
    ) -> Vec<ThreadBatchPlan> {
        let min_process_age = config.process_long_lived_secs.saturating_mul(1_000_000_000);
        let min_task_age = config.task_long_lived_secs.saturating_mul(1_000_000_000);
        let mut processes: Vec<_> = self.processes.keys().copied().collect();
        processes.sort_unstable_by(|left, right| {
            let left_tasks = self
                .processes
                .get(left)
                .map_or(0, |record| record.tasks.len());
            let right_tasks = self
                .processes
                .get(right)
                .map_or(0, |record| record.tasks.len());
            right_tasks.cmp(&left_tasks).then_with(|| left.cmp(right))
        });
        let mut plans = Vec::new();
        for process in processes {
            let Some(record) = self.processes.get(&process) else {
                continue;
            };
            if now_ns.saturating_sub(record.created_ns) < min_process_age {
                continue;
            }
            if matches!(
                record.semantic,
                SemanticState::Pending | SemanticState::Requested
            ) {
                continue;
            }
            let Some(metadata) = record.metadata.clone() else {
                continue;
            };
            let mut eligible: Vec<_> = record
                .tasks
                .iter()
                .copied()
                .filter(|task| {
                    self.tasks.get(task).is_some_and(|task_record| {
                        task_record.stage != ClassStage::Locked
                            && task_record.semantic == SemanticState::Pending
                            && now_ns.saturating_sub(task_record.created_ns) >= min_task_age
                    })
                })
                .collect();
            if eligible.len() < config.thread_semantic_min_tasks {
                continue;
            }

            eligible.sort_unstable();
            for chunk in eligible.chunks(batch_size.max(1)) {
                if plans.len() >= max_batches.max(1) {
                    return plans;
                }
                let tasks = chunk.to_vec();
                for task in &tasks {
                    if let Some(record) = self.tasks.get_mut(task) {
                        record.semantic = SemanticState::Requested;
                    }
                }
                plans.push(ThreadBatchPlan {
                    process,
                    metadata: metadata.clone(),
                    tasks,
                });
            }
        }
        plans
    }

    /// Returns an unsent thread batch to Pending without consuming its one attempt.
    pub fn defer_thread_batch(&mut self, tasks: &[TaskKey]) {
        for task in tasks {
            if let Some(record) = self.tasks.get_mut(task) {
                if record.semantic == SemanticState::Requested {
                    record.semantic = SemanticState::Pending;
                }
            }
        }
    }

    /// Records the first successful queue submission for one thread batch.
    pub fn mark_thread_batch_submitted(&mut self, tasks: &[TaskKey], now_ns: u64) {
        for task in tasks {
            if let Some(record) = self.tasks.get_mut(task) {
                if record.semantic == SemanticState::Requested {
                    set_once(&mut record.timing.semantic_requested_ns, now_ns);
                }
            }
        }
    }

    /// Marks a failed thread batch as Failed exactly once, enabling behavior fallback.
    pub fn mark_thread_batch_failed(&mut self, tasks: &[TaskKey]) {
        self.mark_thread_batch_failed_at(tasks, 0);
    }

    /// Marks a failed thread batch and records its terminal response time.
    pub fn mark_thread_batch_failed_at(&mut self, tasks: &[TaskKey], now_ns: u64) {
        for task in tasks {
            if let Some(record) = self.tasks.get_mut(task) {
                if record.semantic == SemanticState::Requested {
                    record.semantic = SemanticState::Failed;
                    set_once(&mut record.timing.semantic_resolved_ns, now_ns);
                }
            }
        }
    }

    /// Records thread semantics while rechecking current cookie/process identity.
    pub fn apply_thread_proposals(
        &mut self,
        proposals: Vec<ThreadClassificationProposal>,
    ) -> Vec<RegistryAction> {
        self.apply_thread_proposals_at(proposals, 0)
    }

    /// Applies thread proposals with their monotonic response time.
    pub fn apply_thread_proposals_at(
        &mut self,
        proposals: Vec<ThreadClassificationProposal>,
        now_ns: u64,
    ) -> Vec<RegistryAction> {
        for proposal in proposals {
            let Some(record) = self.tasks.get_mut(&proposal.task) else {
                continue;
            };
            if record.process != proposal.process
                || record.semantic != SemanticState::Requested
                || record.stage == ClassStage::Locked
                || record.pending_request_id.is_some()
                || record.applied_generation != record.class_generation
            {
                continue;
            }
            let state = semantic_from_parts(
                proposal.class,
                proposal.confidence,
                self.min_confidence_per_mille,
            );
            record.semantic = state;
            set_once(&mut record.timing.semantic_resolved_ns, now_ns);
        }
        Vec::new()
    }

    /// Applies one ordered behavior window and at most one strong Skill proposal.
    pub fn apply_behavior_window(
        &mut self,
        window: BehaviorWindow,
        proposal: Option<BehaviorClassificationProposal>,
        config: &ClassificationConfig,
    ) -> Vec<RegistryAction> {
        let now_ns = window.task_age_ns.saturating_add(
            self.tasks
                .get(&window.task)
                .map_or(0, |task| task.created_ns),
        );
        self.apply_behavior_window_at(window, proposal, config, now_ns)
    }

    /// Applies one behavior window with an Agent-monotonic observation time.
    pub fn apply_behavior_window_at(
        &mut self,
        window: BehaviorWindow,
        proposal: Option<BehaviorClassificationProposal>,
        config: &ClassificationConfig,
        now_ns: u64,
    ) -> Vec<RegistryAction> {
        let (process_semantic, process_default_class) = self
            .processes
            .get(&window.process)
            .map_or((SemanticState::Pending, TaskClass::Balanced), |process| {
                (process.semantic, process.default_class)
            });
        let specialization_confidence = self.specialization_confidence_per_mille;
        let Some(task) = self.tasks.get_mut(&window.task) else {
            return Vec::new();
        };
        if task.process != window.process || task.stage == ClassStage::Locked {
            return Vec::new();
        }
        if window.window_sequence == 0
            || window.window_sequence <= task.last_behavior_window_sequence
        {
            return Vec::new();
        }
        let sequence_gap = task.last_behavior_window_sequence != 0
            && window.window_sequence != task.last_behavior_window_sequence.saturating_add(1);
        task.last_behavior_window_sequence = window.window_sequence;
        if sequence_gap {
            task.behavior.clear();
        }
        if window.quality != WindowQuality::Good {
            task.behavior.clear();
            return Vec::new();
        }
        if task.pending_request_id.is_some() || task.applied_generation != task.class_generation {
            task.behavior.clear();
            return Vec::new();
        }

        let timeout_ns = config
            .behavior_lock_timeout_secs
            .saturating_mul(1_000_000_000);
        let timed_out = window.task_age_ns >= timeout_ns;
        let candidate = proposal.and_then(|proposal| {
            (proposal.task == window.task && proposal.process == window.process)
                .then_some((proposal.class, proposal.confidence_per_mille.min(1000)))
        });
        if candidate.is_some() {
            set_once(&mut task.timing.behavior_evidence_ns, now_ns);
        }
        task.behavior.record(candidate);
        let semantic_evidence = [
            semantic_evidence(task.semantic),
            semantic_evidence(process_semantic),
        ];
        let evidence_decision = if let Some((candidate, _)) = candidate {
            let latency_objective_known = candidate != TaskClass::Latency
                || process_default_class == TaskClass::Latency
                || semantic_evidence
                    .iter()
                    .flatten()
                    .any(|(class, confidence)| {
                        *class == TaskClass::Latency && *confidence >= specialization_confidence
                    });
            if !latency_objective_known {
                None
            } else {
                let supports_candidate = semantic_evidence
                    .iter()
                    .flatten()
                    .any(|(class, _)| *class == candidate);
                let contradiction_confidence = semantic_evidence
                    .iter()
                    .flatten()
                    .filter_map(|(class, confidence)| {
                        (*class != candidate && *class != TaskClass::Balanced)
                            .then_some(*confidence)
                    })
                    .max()
                    .unwrap_or(0);
                let unsupported_contradiction = contradiction_confidence > 0 && !supports_candidate;
                let threshold = if (unsupported_contradiction
                    && contradiction_confidence
                        >= (config.high_confidence_threshold * 1000.0) as u16)
                    || (candidate == TaskClass::Balanced
                        && task.behavior.confidence_per_mille < 800)
                {
                    config.high_confidence_correction_windows
                } else {
                    config.low_confidence_correction_windows
                };
                (task.behavior.windows >= threshold).then_some((
                    if unsupported_contradiction {
                        TaskClass::Balanced
                    } else {
                        candidate
                    },
                    Some(if unsupported_contradiction {
                        task.behavior
                            .confidence_per_mille
                            .min(contradiction_confidence)
                    } else {
                        task.behavior.confidence_per_mille
                    }),
                ))
            }
        } else {
            None
        };
        let final_decision =
            evidence_decision.or_else(|| timed_out.then_some((task.effective_class, None)));
        let Some((final_class, behavior_confidence_per_mille)) = final_decision else {
            return Vec::new();
        };

        if matches!(
            task.semantic,
            SemanticState::Pending | SemanticState::Requested
        ) {
            task.semantic = SemanticState::Failed;
        }
        task.effective_class = final_class;
        task.stage = ClassStage::Locked;
        task.behavior_confidence_per_mille = behavior_confidence_per_mille;
        set_once(&mut task.timing.decided_ns, now_ns);
        set_once(&mut task.timing.locked_ns, now_ns);
        let expected_generation = task.applied_generation;
        task.class_generation = task.class_generation.saturating_add(1);
        task.behavior.clear();
        let (task_key, process, new_generation) =
            (task.identity, task.process, task.class_generation);
        let _ = task;
        let request_id = self.allocate_control_request_id();
        let Some(task) = self.tasks.get_mut(&task_key) else {
            return Vec::new();
        };
        task.pending_request_id = Some(request_id);
        let mut actions = vec![RegistryAction::SetTaskClass {
            request_id,
            task: task_key,
            process,
            class: final_class,
            stage: ClassStage::Locked,
            expected_generation,
            new_generation,
        }];
        if behavior_confidence_per_mille.is_some() {
            actions.extend(self.record_process_behavior(process, final_class, now_ns));
        }
        actions
    }

    /// Mirrors one process default into every task that still inherits it.
    fn sync_inherited_tasks(&mut self, action: RegistryAction) {
        let RegistryAction::SetProcessDefault {
            process,
            class,
            new_generation,
            ..
        } = action
        else {
            return;
        };
        for task in self.tasks.values_mut() {
            if task.process == process && task.stage == ClassStage::Inherited {
                task.effective_class = class;
                task.class_generation = new_generation;
            }
        }
    }

    /// Exports a deterministic, bounded baseline for a newly connected scheduler.
    pub fn snapshot_batches(
        &self,
        snapshot_id: u64,
        batch_size: usize,
    ) -> Vec<RegistrySnapshotBatch> {
        let limit = batch_size.max(1);
        let mut processes: Vec<_> = self
            .processes
            .values()
            .map(|record| ProcessSnapshot {
                process: record.identity,
                class: record.default_class,
                class_generation: record.class_generation,
            })
            .collect();
        processes.sort_unstable_by_key(|item| item.process);
        let mut tasks: Vec<_> = self
            .tasks
            .values()
            .filter(|record| record.stage != ClassStage::Inherited)
            .map(|record| TaskSnapshot {
                task: record.identity,
                process: record.process,
                class: record.effective_class,
                stage: record.stage,
                class_generation: record.class_generation,
            })
            .collect();
        tasks.sort_unstable_by_key(|item| item.task);

        let mut batches = Vec::new();
        let (mut process_index, mut task_index) = (0, 0);
        loop {
            let mut batch_processes = Vec::new();
            let mut batch_tasks = Vec::new();
            while batch_processes.len() < limit && process_index < processes.len() {
                batch_processes.push(processes[process_index]);
                process_index += 1;
            }
            while batch_processes.len() + batch_tasks.len() < limit && task_index < tasks.len() {
                batch_tasks.push(tasks[task_index]);
                task_index += 1;
            }
            let is_last = process_index == processes.len() && task_index == tasks.len();
            batches.push(RegistrySnapshotBatch {
                snapshot_id,
                batch_index: (batches.len() as u32),
                is_last,
                processes: batch_processes,
                tasks: batch_tasks,
            });
            if is_last {
                break;
            }
        }
        batches
    }

    /// Marks every current desired classification confirmed by a completed snapshot.
    pub fn mark_snapshot_applied(&mut self) {
        self.mark_snapshot_applied_at(0);
    }

    /// Marks current desired state confirmed at one monotonic snapshot time.
    pub fn mark_snapshot_applied_at(&mut self, now_ns: u64) {
        for record in self.processes.values_mut() {
            record.applied_generation = record.class_generation;
            record.pending_request_id = None;
            if record.class_generation > 0 {
                set_once(&mut record.timing.applied_ns, now_ns);
            }
        }
        for record in self.tasks.values_mut() {
            record.applied_generation = record.class_generation;
            record.pending_request_id = None;
            if record.class_generation > 0 && record.stage != ClassStage::Inherited {
                set_once(&mut record.timing.applied_ns, now_ns);
            }
        }
    }

    /// Reconstructs stable actions that still lack scheduler acknowledgement.
    pub fn pending_actions(&self) -> Vec<RegistryAction> {
        let mut actions = Vec::new();
        for record in self.processes.values() {
            if let Some(request_id) = record.pending_request_id {
                actions.push(RegistryAction::SetProcessDefault {
                    request_id,
                    process: record.identity,
                    class: record.default_class,
                    expected_generation: record.applied_generation,
                    new_generation: record.class_generation,
                });
            }
        }
        for record in self.tasks.values() {
            if let Some(request_id) = record.pending_request_id {
                actions.push(RegistryAction::SetTaskClass {
                    request_id,
                    task: record.identity,
                    process: record.process,
                    class: record.effective_class,
                    stage: record.stage,
                    expected_generation: record.applied_generation,
                    new_generation: record.class_generation,
                });
            }
        }
        actions.sort_unstable_by_key(|action| action.request_id());
        actions
    }

    /// Advances applied state only when an ACK exactly matches the pending action.
    pub fn acknowledge(&mut self, action: RegistryAction, applied_generation: u64) -> bool {
        self.acknowledge_at(action, applied_generation, 0)
    }

    /// Advances applied state and records a matching scheduler acknowledgement.
    pub fn acknowledge_at(
        &mut self,
        action: RegistryAction,
        applied_generation: u64,
        now_ns: u64,
    ) -> bool {
        if applied_generation != action.new_generation() {
            return false;
        }
        match action {
            RegistryAction::SetProcessDefault {
                request_id,
                process,
                class,
                new_generation,
                ..
            } => {
                let Some(record) = self.processes.get_mut(&process) else {
                    return false;
                };
                if record.pending_request_id != Some(request_id)
                    || record.default_class != class
                    || record.class_generation != new_generation
                {
                    return false;
                }
                record.applied_generation = new_generation;
                record.pending_request_id = None;
                set_once(&mut record.timing.applied_ns, now_ns);
                for task in self.tasks.values_mut() {
                    if task.process == process
                        && task.stage == ClassStage::Inherited
                        && task.class_generation == new_generation
                    {
                        task.applied_generation = new_generation;
                    }
                }
                true
            }
            RegistryAction::SetTaskClass {
                request_id,
                task,
                process,
                class,
                stage,
                new_generation,
                ..
            } => {
                let Some(record) = self.tasks.get_mut(&task) else {
                    return false;
                };
                if record.pending_request_id != Some(request_id)
                    || record.process != process
                    || record.effective_class != class
                    || record.stage != stage
                    || record.class_generation != new_generation
                {
                    return false;
                }
                record.applied_generation = new_generation;
                record.pending_request_id = None;
                set_once(&mut record.timing.applied_ns, now_ns);
                true
            }
        }
    }

    /// Drops an exact identity after scheduler confirms it is no longer live.
    pub fn reject_unknown_identity(&mut self, action: RegistryAction) -> bool {
        match action {
            RegistryAction::SetProcessDefault { process, .. } => {
                let existed = self.processes.contains_key(&process);
                self.on_process_exited(process);
                existed
            }
            RegistryAction::SetTaskClass { task, process, .. } => {
                let existed = self
                    .tasks
                    .get(&task)
                    .is_some_and(|record| record.process == process);
                self.on_task_exited(task, process);
                existed
            }
        }
    }

    /// Returns capacity and pending-state diagnostics for Tool consumers.
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            processes: self.processes.len(),
            tasks: self.tasks.len(),
            pending_actions: self.pending_actions().len(),
            dropped_process_records: self.dropped_process_records,
            dropped_task_records: self.dropped_task_records,
        }
    }

    /// Iterates process records without exposing mutable Registry ownership.
    pub fn processes(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.processes.values()
    }

    /// Iterates bounded recently exited process projections.
    pub fn retired_processes(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.retired_processes.iter()
    }

    /// Iterates task records without exposing mutable Registry ownership.
    pub fn tasks(&self) -> impl Iterator<Item = &TaskRecord> {
        self.tasks.values()
    }

    /// Iterates bounded recently exited task projections.
    pub fn retired_tasks(&self) -> impl Iterator<Item = &TaskRecord> {
        self.retired_tasks.iter()
    }

    /// Returns a process record for main-loop metadata reconciliation.
    pub fn process(&self, process: ProcessKey) -> Option<&ProcessRecord> {
        self.processes.get(&process)
    }

    /// Returns a task record for tests and thread metadata reconciliation.
    pub fn task(&self, task: TaskKey) -> Option<&TaskRecord> {
        self.tasks.get(&task)
    }
}

/// Keeps positive local evidence when remote semantics only reports no preference.
fn fuse_local_process_class(
    semantic_class: TaskClass,
    semantic_confidence_per_mille: u16,
    local: Option<(TaskClass, u16)>,
) -> (TaskClass, u16) {
    let Some((local_class, local_confidence_per_mille)) = local else {
        return (semantic_class, semantic_confidence_per_mille);
    };
    let confidence = semantic_confidence_per_mille.min(local_confidence_per_mille);
    if local_class == semantic_class {
        (semantic_class, confidence)
    } else if semantic_class == TaskClass::Balanced && local_class != TaskClass::Balanced {
        (local_class, confidence)
    } else {
        (TaskClass::Balanced, confidence)
    }
}

/// Accepts high-confidence process objectives while keeping weaker semantics provisional.
fn process_default_decision(
    semantic_class: TaskClass,
    semantic_confidence_per_mille: u16,
    local: Option<(TaskClass, u16)>,
    behavior: Option<(TaskClass, u16)>,
    specialization_confidence_per_mille: u16,
) -> Option<(TaskClass, bool, Option<u16>, u16)> {
    let has_local_evidence = local.is_some();
    let (semantic_class, confidence) =
        fuse_local_process_class(semantic_class, semantic_confidence_per_mille, local);
    if semantic_class != TaskClass::Balanced
        && !has_local_evidence
        && behavior.is_none()
        && semantic_confidence_per_mille < specialization_confidence_per_mille
    {
        return None;
    }

    let (mut class, mut behavior_override, mut behavior_confidence) =
        fuse_process_class(semantic_class, confidence, behavior);
    if class != TaskClass::Balanced
        && semantic_class != TaskClass::Balanced
        && !has_local_evidence
        && semantic_confidence_per_mille < specialization_confidence_per_mille
    {
        class = TaskClass::Balanced;
        behavior_override = true;
        behavior_confidence = behavior.map(|(_, value)| {
            value
                .min(semantic_confidence_per_mille)
                .min(specialization_confidence_per_mille)
        });
    }
    let effective_confidence = behavior_confidence.unwrap_or(confidence);
    Some((
        class,
        behavior_override,
        behavior_confidence,
        effective_confidence,
    ))
}

/// Combines process semantics with independent locked task behavior.
fn fuse_process_class(
    semantic_class: TaskClass,
    semantic_confidence_per_mille: u16,
    behavior: Option<(TaskClass, u16)>,
) -> (TaskClass, bool, Option<u16>) {
    let Some((behavior_class, behavior_confidence)) = behavior else {
        return (semantic_class, false, None);
    };
    if behavior_class == semantic_class {
        return (semantic_class, false, None);
    }
    if semantic_class == TaskClass::Balanced {
        return (
            behavior_class,
            behavior_class != TaskClass::Balanced,
            Some(behavior_confidence.min(1000)),
        );
    }
    (
        TaskClass::Balanced,
        true,
        Some(
            semantic_confidence_per_mille
                .min(behavior_confidence)
                .min(1000),
        ),
    )
}

/// Records a real monotonic milestone without replacing its first occurrence.
fn set_once(slot: &mut Option<u64>, now_ns: u64) {
    if now_ns > 0 && slot.is_none() {
        *slot = Some(now_ns);
    }
}

/// Converts a process proposal to one non-retry semantic state.
fn semantic_from_proposal(
    proposal: &ProcessClassificationProposal,
    min_confidence_per_mille: u16,
) -> SemanticState {
    semantic_from_parts(
        proposal.class,
        proposal.confidence,
        min_confidence_per_mille,
    )
}

/// Converts optional model class/confidence to a strict registry state.
fn semantic_from_parts(
    class: Option<TaskClass>,
    confidence: f32,
    min_confidence_per_mille: u16,
) -> SemanticState {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return SemanticState::Unknown;
    }
    let confidence_per_mille = (confidence * 1000.0).round().clamp(0.0, 1000.0) as u16;
    if confidence_per_mille < min_confidence_per_mille {
        return SemanticState::Unknown;
    }
    match class {
        Some(class) => SemanticState::Classified {
            class,
            confidence_per_mille,
        },
        None => SemanticState::Unknown,
    }
}

/// Projects a known semantic result into one fusion vote.
const fn semantic_evidence(semantic: SemanticState) -> Option<(TaskClass, u16)> {
    match semantic {
        SemanticState::Classified {
            class,
            confidence_per_mille,
        } => Some((class, confidence_per_mille)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        fuse_local_process_class, process_default_decision, ClassificationRegistry, RegistryAction,
        SemanticState,
    };
    use crate::behavior::{BehaviorWindow, WindowQuality};
    use crate::config::ClassificationConfig;
    use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
    use crate::limits::RuntimeLimits;
    use crate::metadata::{ProcessInstanceKey, ProcessMetadata};
    use crate::skills::{
        BehaviorClassificationProposal, ProcessClassificationProposal, ThreadClassificationProposal,
    };

    fn behavior_window(task: TaskKey, process: ProcessKey, window_sequence: u64) -> BehaviorWindow {
        BehaviorWindow {
            task,
            process,
            window_sequence,
            window_start_ns: 5_000_000_000,
            window_end_ns: 6_000_000_000,
            runtime_ns: 900_000_000,
            runnable_wait_ns: 1,
            sleep_ns: 0,
            enqueue_count: 100,
            wakeup_count: 0,
            run_count: 100,
            run_burst_histogram: [0, 0, 0, 100],
            wait_histogram: [100, 0, 0, 0],
            slice_exhaustion_count: 100,
            voluntary_block_count: 0,
            migration_count: 0,
            previous_cpu_hit_count: 100,
            task_age_ns: 6_000_000_000,
            quality: WindowQuality::Good,
        }
    }

    fn process_metadata(
        tgid: u32,
        start_time_ticks: u64,
        parent: Option<ProcessInstanceKey>,
    ) -> ProcessMetadata {
        ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid,
                start_time_ticks,
            },
            parent,
            comm: format!("process-{tgid}"),
            command: vec![format!("/bin/process-{tgid}")],
            executable: Some(format!("/bin/process-{tgid}")),
            cgroups: Vec::new(),
            uid: Some(1000),
        }
    }

    #[test]
    fn process_batches_prioritize_newest_lifetimes() {
        let mut registry = ClassificationRegistry::default();
        registry.remember_metadata(process_metadata(11, 100, None));
        registry.remember_metadata(process_metadata(12, 300, None));
        registry.remember_metadata(process_metadata(13, 200, None));

        let newest = registry.take_process_batches(2, 1).remove(0);
        let selected: Vec<_> = newest
            .processes
            .iter()
            .map(|metadata| metadata.instance)
            .collect();
        assert_eq!(
            selected,
            vec![
                ProcessInstanceKey {
                    tgid: 12,
                    start_time_ticks: 300,
                },
                ProcessInstanceKey {
                    tgid: 13,
                    start_time_ticks: 200,
                },
            ]
        );

        let oldest = registry.take_process_batches(2, 1).remove(0);
        assert_eq!(oldest.processes[0].instance.tgid, 11);
    }

    #[test]
    fn process_semantics_wait_for_scheduler_observation_and_minimum_age() {
        let mut registry = ClassificationRegistry::default();
        let metadata = process_metadata(14, 400, None);
        let process = ProcessKey {
            tgid: 14,
            process_cookie: 15,
            exec_generation: 1,
        };
        registry.remember_metadata(metadata.clone());
        assert!(registry
            .take_process_batches_at(2_000_000_000, 1_000_000_000, 1, 1)
            .is_empty());

        registry.on_process_discovered(process, Some(metadata), 2_000_000_000);
        assert!(registry
            .take_process_batches_at(2_999_999_999, 1_000_000_000, 1, 1)
            .is_empty());
        assert_eq!(
            registry
                .take_process_batches_at(3_000_000_000, 1_000_000_000, 1, 1)
                .remove(0)
                .processes[0]
                .instance
                .tgid,
            14
        );
    }

    #[test]
    fn local_metadata_applies_immediately_without_suppressing_remote_semantics() {
        let mut registry = ClassificationRegistry::default();
        let mut metadata = process_metadata(15, 500, None);
        metadata.comm = "time".into();
        metadata.executable = Some("/usr/bin/time".into());
        metadata.command = vec![
            "/usr/bin/time".into(),
            "bash".into(),
            "-c".into(),
            "job-runner --throughput --input data.bin".into(),
        ];
        let process = ProcessKey {
            tgid: 15,
            process_cookie: 16,
            exec_generation: 1,
        };

        let actions = registry.on_process_discovered(process, Some(metadata), 2_000_000_000);

        assert!(matches!(
            actions.as_slice(),
            [RegistryAction::SetProcessDefault {
                process: observed,
                class: TaskClass::Throughput,
                ..
            }] if *observed == process
        ));
        let record = registry.process(process).unwrap();
        assert_eq!(record.default_class, TaskClass::Throughput);
        assert_eq!(record.local_class, Some(TaskClass::Throughput));
        assert_eq!(record.semantic, SemanticState::Pending);
        assert_eq!(record.timing.decided_ns, Some(2_000_000_000));
        let plan = registry
            .take_process_batches_at(2_000_000_000, 0, 8, 1)
            .remove(0);
        let corrections = registry.apply_process_proposals_at(
            plan.request_id,
            vec![ProcessClassificationProposal {
                instance: plan.processes[0].instance,
                class: Some(TaskClass::Balanced),
                confidence: 0.95,
            }],
            3_000_000_000,
        );
        assert!(corrections.is_empty());
        assert_eq!(
            registry.process(process).unwrap().default_class,
            TaskClass::Throughput
        );
    }

    #[test]
    fn conflicting_positive_process_classes_remain_balanced() {
        assert_eq!(
            fuse_local_process_class(TaskClass::Latency, 950, Some((TaskClass::Throughput, 900)),),
            (TaskClass::Balanced, 900)
        );
    }

    #[test]
    fn process_specialization_uses_confidence_and_independent_behavior() {
        assert_eq!(
            process_default_decision(TaskClass::Throughput, 900, None, None, 900),
            Some((TaskClass::Throughput, false, None, 900))
        );
        assert_eq!(
            process_default_decision(TaskClass::Throughput, 800, None, None, 900),
            None
        );
        assert_eq!(
            process_default_decision(
                TaskClass::Throughput,
                900,
                None,
                Some((TaskClass::Throughput, 900)),
                900,
            ),
            Some((TaskClass::Throughput, false, None, 900))
        );
        assert_eq!(
            process_default_decision(
                TaskClass::Throughput,
                800,
                None,
                Some((TaskClass::Throughput, 900)),
                900,
            ),
            Some((TaskClass::Balanced, true, Some(800), 800))
        );
    }

    #[test]
    fn startup_inventory_remains_eligible_for_remote_semantics() {
        let mut registry = ClassificationRegistry::default();
        let startup_metadata = process_metadata(21, 100, None);
        let startup_process = ProcessKey {
            tgid: 21,
            process_cookie: 22,
            exec_generation: 1,
        };
        registry.on_process_discovered(startup_process, Some(startup_metadata), 0);

        let startup_batch = registry.take_process_batches(8, 8).remove(0);
        assert_eq!(startup_batch.processes.len(), 1);
        assert_eq!(startup_batch.processes[0].instance.tgid, 21);

        let new_metadata = process_metadata(31, 200, None);
        registry.remember_metadata(new_metadata);
        let batch = registry.take_process_batches(8, 8).remove(0);
        assert_eq!(batch.processes.len(), 1);
        assert_eq!(batch.processes[0].instance.tgid, 31);
    }

    #[test]
    fn exact_semantic_fingerprint_reuses_a_high_confidence_objective() {
        let mut registry = ClassificationRegistry::default();
        let first_metadata = process_metadata(51, 500, None);
        let first_process = ProcessKey {
            tgid: 51,
            process_cookie: 52,
            exec_generation: 1,
        };
        registry.on_process_discovered(first_process, Some(first_metadata.clone()), 1_000);
        let plan = registry.take_process_batches(1, 1).remove(0);
        registry.apply_process_proposals_at(
            plan.request_id,
            vec![ProcessClassificationProposal {
                instance: first_metadata.instance,
                class: Some(TaskClass::Throughput),
                confidence: 0.9,
            }],
            2_000,
        );

        let mut repeated = first_metadata.clone();
        repeated.instance = ProcessInstanceKey {
            tgid: 61,
            start_time_ticks: 600,
        };
        let repeated_process = ProcessKey {
            tgid: 61,
            process_cookie: 62,
            exec_generation: 1,
        };
        let actions = registry.on_process_discovered(repeated_process, Some(repeated), 3_000);

        assert!(matches!(
            actions.as_slice(),
            [RegistryAction::SetProcessDefault {
                process,
                class: TaskClass::Throughput,
                expected_generation: 0,
                new_generation: 1,
                ..
            }] if *process == repeated_process
        ));
        let record = registry.process(repeated_process).unwrap();
        assert!(matches!(
            record.semantic,
            SemanticState::Classified {
                class: TaskClass::Throughput,
                confidence_per_mille: 900
            }
        ));
        assert_eq!(record.default_class, TaskClass::Throughput);
        assert_eq!(record.timing.semantic_requested_ns, None);
        assert_eq!(record.timing.semantic_resolved_ns, Some(3_000));
        assert_eq!(record.timing.decided_ns, Some(3_000));
        assert!(registry.take_process_batches(8, 8).is_empty());

        let mut changed = first_metadata;
        changed.instance = ProcessInstanceKey {
            tgid: 71,
            start_time_ticks: 700,
        };
        changed.command.push("--different".into());
        registry.remember_metadata(changed);
        assert_eq!(
            registry.take_process_batches(8, 8).remove(0).processes[0]
                .instance
                .tgid,
            71
        );
    }

    #[test]
    fn low_confidence_process_timing_separates_resolution_from_a_decision() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 15,
            process_cookie: 16,
            exec_generation: 1,
        };
        let metadata = process_metadata(15, 150, None);
        registry.on_process_discovered(process, Some(metadata.clone()), 1_000);
        let plan = registry.take_process_batches(1, 1).remove(0);
        registry.mark_process_batch_submitted(&plan, 2_000);
        let actions = registry.apply_process_proposals_at(
            plan.request_id,
            vec![ProcessClassificationProposal {
                instance: metadata.instance,
                class: Some(TaskClass::Latency),
                confidence: 0.8,
            }],
            4_000,
        );
        assert!(actions.is_empty());

        let timing = registry.process(process).unwrap().timing;
        assert_eq!(timing.semantic_requested_ns, Some(2_000));
        assert_eq!(timing.semantic_resolved_ns, Some(4_000));
        assert_eq!(timing.decided_ns, None);
        assert_eq!(timing.applied_ns, None);
        assert_eq!(timing.behavior_evidence_ns, None);
    }

    #[test]
    fn task_timing_tracks_first_behavior_evidence_and_lock() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 17,
            process_cookie: 18,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 19,
            task_cookie: 20,
        };
        registry.on_task_discovered(task, process, 1_000);
        registry.processes.get_mut(&process).unwrap().semantic = SemanticState::Failed;
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        assert!(registry
            .apply_behavior_window_at(
                behavior_window(task, process, 1),
                Some(proposal),
                &config,
                2_000,
            )
            .is_empty());
        assert!(registry
            .apply_behavior_window_at(
                behavior_window(task, process, 2),
                Some(proposal),
                &config,
                3_000,
            )
            .is_empty());
        let action = registry
            .apply_behavior_window_at(
                behavior_window(task, process, 3),
                Some(proposal),
                &config,
                4_000,
            )
            .remove(0);
        assert!(registry.acknowledge_at(action, 1, 5_000));

        let timing = registry.task(task).unwrap().timing;
        assert_eq!(timing.behavior_evidence_ns, Some(2_000));
        assert_eq!(timing.decided_ns, Some(4_000));
        assert_eq!(timing.locked_ns, Some(4_000));
        assert_eq!(timing.applied_ns, Some(5_000));
    }

    #[test]
    fn child_keeps_exact_parent_class_while_semantics_are_provisional() {
        let mut registry = ClassificationRegistry::default();
        let parent = ProcessKey {
            tgid: 101,
            process_cookie: 102,
            exec_generation: 1,
        };
        let mut parent_metadata = process_metadata(parent.tgid, 103, None);
        parent_metadata.command.push("--throughput".into());
        let parent_actions =
            registry.on_process_discovered(parent, Some(parent_metadata.clone()), 0);
        assert!(registry.acknowledge(parent_actions[0], 1));
        let parent_plan = registry.take_process_batches(1, usize::MAX).remove(0);
        assert!(registry
            .apply_process_proposals(
                parent_plan.request_id,
                vec![ProcessClassificationProposal {
                    instance: parent_metadata.instance,
                    class: Some(TaskClass::Throughput),
                    confidence: 0.9,
                }],
            )
            .is_empty());

        let child = ProcessKey {
            tgid: 201,
            process_cookie: 202,
            exec_generation: 1,
        };
        let child_metadata = process_metadata(child.tgid, 203, Some(parent_metadata.instance));
        let inherited = registry.on_process_discovered(child, Some(child_metadata.clone()), 1);
        assert!(matches!(
            inherited.as_slice(),
            [RegistryAction::SetProcessDefault {
                class: TaskClass::Throughput,
                expected_generation: 0,
                new_generation: 1,
                ..
            }]
        ));
        assert!(registry.acknowledge(inherited[0], 1));

        let child_plan = registry.take_process_batches(1, usize::MAX).remove(0);
        let override_actions = registry.apply_process_proposals(
            child_plan.request_id,
            vec![ProcessClassificationProposal {
                instance: child_metadata.instance,
                class: Some(TaskClass::Latency),
                confidence: 0.8,
            }],
        );
        assert!(override_actions.is_empty());
        let record = registry.process(child).unwrap();
        assert_eq!(record.default_class, TaskClass::Throughput);
        assert_eq!(record.inherited_from, Some(parent));
    }

    #[test]
    fn child_does_not_inherit_reused_parent_pid() {
        let mut registry = ClassificationRegistry::default();
        let parent = ProcessKey {
            tgid: 301,
            process_cookie: 302,
            exec_generation: 1,
        };
        let parent_metadata = process_metadata(parent.tgid, 303, None);
        registry.on_process_discovered(parent, Some(parent_metadata.clone()), 0);
        registry.processes.get_mut(&parent).unwrap().default_class = TaskClass::Throughput;

        let reused_parent = ProcessInstanceKey {
            start_time_ticks: parent_metadata.instance.start_time_ticks + 1,
            ..parent_metadata.instance
        };
        let child_metadata = process_metadata(401, 403, Some(reused_parent));
        let child = ProcessKey {
            tgid: child_metadata.instance.tgid,
            process_cookie: 402,
            exec_generation: 1,
        };

        assert!(registry
            .on_process_discovered(child, Some(child_metadata), 1)
            .is_empty());
        assert_eq!(
            registry.process(child).unwrap().default_class,
            TaskClass::Balanced
        );
    }

    #[test]
    fn late_parent_semantics_remain_provisional_for_descendants() {
        let mut registry = ClassificationRegistry::default();
        let parent = ProcessKey {
            tgid: 501,
            process_cookie: 502,
            exec_generation: 1,
        };
        let parent_metadata = process_metadata(parent.tgid, 503, None);
        registry.on_process_discovered(parent, Some(parent_metadata.clone()), 0);
        let parent_plan = registry.take_process_batches(1, usize::MAX).remove(0);

        let child = ProcessKey {
            tgid: 601,
            process_cookie: 602,
            exec_generation: 1,
        };
        let child_metadata = process_metadata(child.tgid, 603, Some(parent_metadata.instance));
        assert!(registry
            .on_process_discovered(child, Some(child_metadata), 1)
            .is_empty());

        let actions = registry.apply_process_proposals(
            parent_plan.request_id,
            vec![ProcessClassificationProposal {
                instance: parent_metadata.instance,
                class: Some(TaskClass::Throughput),
                confidence: 0.8,
            }],
        );
        assert!(actions.is_empty());
        assert_eq!(
            registry.process(parent).unwrap().default_class,
            TaskClass::Balanced
        );
        assert_eq!(
            registry.process(child).unwrap().default_class,
            TaskClass::Balanced
        );
        assert_eq!(
            registry.process(child).unwrap().inherited_from,
            Some(parent)
        );
    }

    #[test]
    fn high_confidence_parent_objective_updates_descendants() {
        let mut registry = ClassificationRegistry::default();
        let parent = ProcessKey {
            tgid: 611,
            process_cookie: 612,
            exec_generation: 1,
        };
        let parent_metadata = process_metadata(parent.tgid, 613, None);
        registry.on_process_discovered(parent, Some(parent_metadata.clone()), 0);
        let parent_plan = registry.take_process_batches(1, usize::MAX).remove(0);
        let child = ProcessKey {
            tgid: 621,
            process_cookie: 622,
            exec_generation: 1,
        };
        let child_metadata = process_metadata(child.tgid, 623, Some(parent_metadata.instance));
        registry.on_process_discovered(child, Some(child_metadata), 1);

        let actions = registry.apply_process_proposals(
            parent_plan.request_id,
            vec![ProcessClassificationProposal {
                instance: parent_metadata.instance,
                class: Some(TaskClass::Throughput),
                confidence: 0.9,
            }],
        );

        assert_eq!(actions.len(), 2);
        assert_eq!(
            registry.process(parent).unwrap().default_class,
            TaskClass::Throughput
        );
        assert_eq!(
            registry.process(child).unwrap().default_class,
            TaskClass::Throughput
        );
        assert_eq!(
            registry.process(child).unwrap().inherited_from,
            Some(parent)
        );
    }

    #[test]
    fn parent_and_child_semantics_stay_provisional_in_the_same_batch() {
        let mut registry = ClassificationRegistry::default();
        let parent = ProcessKey {
            tgid: 701,
            process_cookie: 702,
            exec_generation: 1,
        };
        let parent_metadata = process_metadata(parent.tgid, 703, None);
        registry.on_process_discovered(parent, Some(parent_metadata.clone()), 0);
        let child = ProcessKey {
            tgid: 801,
            process_cookie: 802,
            exec_generation: 1,
        };
        let child_metadata = process_metadata(child.tgid, 803, Some(parent_metadata.instance));
        registry.on_process_discovered(child, Some(child_metadata.clone()), 1);
        let plan = registry.take_process_batches(2, usize::MAX).remove(0);

        let actions = registry.apply_process_proposals(
            plan.request_id,
            vec![
                ProcessClassificationProposal {
                    instance: parent_metadata.instance,
                    class: Some(TaskClass::Throughput),
                    confidence: 0.8,
                },
                ProcessClassificationProposal {
                    instance: child_metadata.instance,
                    class: Some(TaskClass::Latency),
                    confidence: 0.8,
                },
            ],
        );

        assert!(actions.is_empty());
        assert_eq!(
            registry.process(child).unwrap().default_class,
            TaskClass::Balanced
        );
        assert_eq!(
            registry.process(child).unwrap().inherited_from,
            Some(parent)
        );
        assert!(matches!(
            registry.process(parent).unwrap().semantic,
            SemanticState::Classified {
                class: TaskClass::Throughput,
                confidence_per_mille: 800
            }
        ));
        assert!(matches!(
            registry.process(child).unwrap().semantic,
            SemanticState::Classified {
                class: TaskClass::Latency,
                confidence_per_mille: 800
            }
        ));
    }

    /// Reused numeric TIDs cannot delete a different task cookie record.
    #[test]
    fn exit_requires_exact_task_cookie() {
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
        registry.on_task_discovered(task, process, 1);
        registry.on_task_exited(
            TaskKey {
                tid: 3,
                task_cookie: 5,
            },
            process,
        );
        assert!(registry.task(task).is_some());
    }

    #[test]
    fn exited_classification_history_is_bounded() {
        let limits = RuntimeLimits {
            registry_processes: 2,
            registry_tasks: 1,
            ..RuntimeLimits::default()
        };
        let mut registry = ClassificationRegistry::new(limits, 0.6, 0.9);
        let process = ProcessKey {
            tgid: 41,
            process_cookie: 42,
            exec_generation: 1,
        };
        for cookie in [44, 46] {
            let task = TaskKey {
                tid: cookie - 1,
                task_cookie: u64::from(cookie),
            };
            registry.on_task_discovered(task, process, cookie as u64);
            registry.on_task_exited(task, process);
        }

        let retired: Vec<_> = registry.retired_tasks().collect();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].identity.task_cookie, 46);

        registry.on_process_exited(process);
        assert_eq!(registry.retired_processes().count(), 1);
    }

    #[test]
    fn unknown_identity_rejection_removes_only_the_exact_lifetime() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 901,
            process_cookie: 902,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 903,
            task_cookie: 904,
        };
        registry.on_task_discovered(task, process, 0);
        let wrong_process = ProcessKey {
            process_cookie: process.process_cookie + 1,
            ..process
        };
        let rejected_task = RegistryAction::SetTaskClass {
            request_id: 1,
            task,
            process: wrong_process,
            class: TaskClass::Throughput,
            stage: ClassStage::Locked,
            expected_generation: 0,
            new_generation: 1,
        };
        assert!(!registry.reject_unknown_identity(rejected_task));
        assert!(registry.task(task).is_some());

        let rejected_process = RegistryAction::SetProcessDefault {
            request_id: 2,
            process,
            class: TaskClass::Throughput,
            expected_generation: 0,
            new_generation: 1,
        };
        assert!(registry.reject_unknown_identity(rejected_process));
        assert!(registry.process(process).is_none());
        assert!(registry.task(task).is_none());
    }

    /// Unknown semantic classification locks only after three good contrary windows.
    #[test]
    fn behavior_requires_consecutive_good_windows() {
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
        registry.on_task_discovered(task, process, 1);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Unknown;
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 1), Some(proposal), &config)
            .is_empty());
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 2), Some(proposal), &config)
            .is_empty());
        assert!(matches!(
            registry
                .apply_behavior_window(behavior_window(task, process, 3), Some(proposal), &config)
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Throughput,
                ..
            }]
        ));
    }

    /// The observation deadline locks the current class when a candidate has
    /// not accumulated enough consecutive evidence to justify a correction.
    #[test]
    fn behavior_timeout_bounds_weak_candidate_observation() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 101,
            process_cookie: 102,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 103,
            task_cookie: 104,
        };
        registry.on_task_discovered(task, process, 1);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Unknown;
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        let timeout_ns = config.behavior_lock_timeout_secs * 1_000_000_000;
        let mut before_timeout = behavior_window(task, process, 1);
        before_timeout.task_age_ns = timeout_ns - 1;
        assert!(registry
            .apply_behavior_window(before_timeout, Some(proposal), &config)
            .is_empty());

        let mut at_timeout = behavior_window(task, process, 2);
        at_timeout.task_age_ns = timeout_ns;
        assert!(matches!(
            registry
                .apply_behavior_window(at_timeout, Some(proposal), &config)
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Balanced,
                stage: ClassStage::Locked,
                ..
            }]
        ));
        assert_eq!(registry.task(task).unwrap().stage, ClassStage::Locked);
    }

    /// Strong local evidence resolves a task after three windows even while its
    /// remote semantic request remains pending.
    #[test]
    fn pending_semantics_fall_back_to_strong_behavior() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 111,
            process_cookie: 112,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 113,
            task_cookie: 114,
        };
        registry.on_task_discovered(task, process, 1);
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };

        for sequence in 1..=2 {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, sequence),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        let record = registry.tasks.get_mut(&task).unwrap();
        assert_eq!(record.behavior.windows, 2);
        assert_eq!(record.stage, ClassStage::Inherited);

        assert!(matches!(
            registry
                .apply_behavior_window(behavior_window(task, process, 3), Some(proposal), &config,)
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Throughput,
                stage: ClassStage::Locked,
                ..
            }]
        ));
        let record = registry.task(task).unwrap();
        assert_eq!(record.semantic, SemanticState::Failed);
        assert_eq!(record.stage, ClassStage::Locked);
    }

    #[test]
    fn two_locked_tasks_promote_a_local_process_default() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 131,
            process_cookie: 132,
            exec_generation: 1,
        };
        let tasks = [
            TaskKey {
                tid: 133,
                task_cookie: 134,
            },
            TaskKey {
                tid: 135,
                task_cookie: 136,
            },
        ];
        let config = ClassificationConfig::default();
        let mut final_actions = Vec::new();

        registry.on_task_discovered(tasks[0], process, 1);
        registry.processes.get_mut(&process).unwrap().semantic = SemanticState::Classified {
            class: TaskClass::Balanced,
            confidence_per_mille: 900,
        };

        for task in tasks {
            registry.on_task_discovered(task, process, 1);
            let proposal = BehaviorClassificationProposal {
                task,
                process,
                class: TaskClass::Throughput,
                confidence_per_mille: 900,
            };
            for sequence in 1..=3 {
                final_actions = registry.apply_behavior_window(
                    behavior_window(task, process, sequence),
                    Some(proposal),
                    &config,
                );
            }
        }

        assert!(final_actions.iter().any(|action| matches!(
            action,
            RegistryAction::SetProcessDefault {
                process: action_process,
                class: TaskClass::Throughput,
                ..
            } if *action_process == process
        )));
        let record = registry.process(process).unwrap();
        assert_eq!(record.default_class, TaskClass::Throughput);
        assert!(record.behavior_override);
        assert_eq!(record.behavior_confidence_per_mille, Some(850));
    }

    #[test]
    fn balanced_process_semantics_preserve_a_strong_local_lock() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 141,
            process_cookie: 142,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 143,
            task_cookie: 144,
        };
        let metadata = process_metadata(141, 145, None);
        registry.remember_metadata(metadata.clone());
        registry.on_process_discovered(process, Some(metadata.clone()), 1);
        registry.on_task_discovered(task, process, 1);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Classified {
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        let plan = registry.take_process_batches(1, 1).remove(0);
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        let mut local_actions = Vec::new();
        for sequence in 1..=3 {
            local_actions = registry.apply_behavior_window(
                behavior_window(task, process, sequence),
                Some(proposal),
                &config,
            );
        }
        let local_action = local_actions
            .into_iter()
            .find(|action| matches!(action, RegistryAction::SetTaskClass { .. }))
            .unwrap();
        assert!(registry.acknowledge(local_action, 1));

        let actions = registry.apply_process_proposals(
            plan.request_id,
            vec![ProcessClassificationProposal {
                instance: metadata.instance,
                class: Some(TaskClass::Balanced),
                confidence: 0.8,
            }],
        );

        assert!(actions.is_empty());
        let record = registry.task(task).unwrap();
        assert_eq!(record.effective_class, TaskClass::Latency);
        assert_eq!(record.behavior_confidence_per_mille, Some(900));
    }

    #[test]
    fn io_shaped_behavior_does_not_invent_a_latency_objective() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 151,
            process_cookie: 152,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 153,
            task_cookie: 154,
        };
        registry.on_task_discovered(task, process, 1);
        registry.processes.get_mut(&process).unwrap().semantic = SemanticState::Classified {
            class: TaskClass::Balanced,
            confidence_per_mille: 900,
        };
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        let config = ClassificationConfig::default();

        for sequence in 1..=5 {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, sequence),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        let record = registry.task(task).unwrap();
        assert_eq!(record.effective_class, TaskClass::Balanced);
        assert_eq!(record.stage, ClassStage::Inherited);
    }

    #[test]
    fn low_confidence_latency_semantics_do_not_unlock_io_shape() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 161,
            process_cookie: 162,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 163,
            task_cookie: 164,
        };
        registry.on_task_discovered(task, process, 1);
        registry.processes.get_mut(&process).unwrap().semantic = SemanticState::Classified {
            class: TaskClass::Latency,
            confidence_per_mille: 800,
        };
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        let config = ClassificationConfig::default();

        for sequence in 1..=config.high_confidence_correction_windows {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, u64::from(sequence)),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        let record = registry.task(task).unwrap();
        assert_eq!(record.effective_class, TaskClass::Balanced);
        assert_eq!(record.stage, ClassStage::Inherited);
    }

    #[test]
    fn high_confidence_latency_semantics_unlock_matching_behavior() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 171,
            process_cookie: 172,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 173,
            task_cookie: 174,
        };
        registry.on_task_discovered(task, process, 1);
        registry.processes.get_mut(&process).unwrap().semantic = SemanticState::Classified {
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        let config = ClassificationConfig::default();

        for sequence in 1..config.low_confidence_correction_windows {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, u64::from(sequence)),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        assert!(matches!(
            registry
                .apply_behavior_window(
                    behavior_window(
                        task,
                        process,
                        u64::from(config.low_confidence_correction_windows),
                    ),
                    Some(proposal),
                    &config,
                )
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Latency,
                stage: ClassStage::Locked,
                ..
            }]
        ));
    }

    /// Conflicting process semantics and local behavior converge to Balanced.
    #[test]
    fn behavior_fuses_conflicting_process_semantics_as_balanced() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 121,
            process_cookie: 122,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 123,
            task_cookie: 124,
        };
        registry.on_task_discovered(task, process, 1);
        let process_record = registry.processes.get_mut(&process).unwrap();
        process_record.semantic = SemanticState::Classified {
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        process_record.default_class = TaskClass::Latency;
        registry.tasks.get_mut(&task).unwrap().effective_class = TaskClass::Latency;
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };

        for sequence in 1..=4 {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, sequence),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        assert!(matches!(
            registry
                .apply_behavior_window(behavior_window(task, process, 5), Some(proposal), &config)
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Balanced,
                stage: ClassStage::Locked,
                ..
            }]
        ));
        let record = registry.task(task).unwrap();
        assert_eq!(record.semantic, SemanticState::Failed);
        assert_eq!(record.behavior_confidence_per_mille, Some(900));
    }

    /// A behavior proposal from another process image cannot contribute a vote.
    #[test]
    fn behavior_proposal_requires_matching_process_image() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 5,
            process_cookie: 6,
            exec_generation: 2,
        };
        let task = TaskKey {
            tid: 7,
            task_cookie: 8,
        };
        registry.on_task_discovered(task, process, 0);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Unknown;
        let config = ClassificationConfig::default();
        let wrong_process = ProcessKey {
            exec_generation: 1,
            ..process
        };

        assert!(registry
            .apply_behavior_window(
                behavior_window(task, process, 1),
                Some(BehaviorClassificationProposal {
                    task,
                    process: wrong_process,
                    class: TaskClass::Throughput,
                    confidence_per_mille: 900,
                }),
                &config,
            )
            .is_empty());
        assert_eq!(
            registry.task(task).unwrap().effective_class,
            TaskClass::Balanced
        );
    }

    /// A failed process request must unlock behavior fallback for an already
    /// cookie-bound process, not only for future discoveries.
    #[test]
    fn process_failure_updates_bound_record() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 11,
            process_cookie: 12,
            exec_generation: 1,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 11,
                start_time_ticks: 13,
            },
            parent: None,
            comm: "job".into(),
            command: vec!["job".into()],
            executable: Some("/bin/job".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.remember_metadata(metadata.clone());
        registry.on_process_discovered(process, Some(metadata.clone()), 0);
        let batches = registry.take_process_batches(16, usize::MAX);
        registry.mark_process_batch_failed(&batches[0]);
        assert_eq!(
            registry.process(process).unwrap().semantic,
            SemanticState::Failed
        );
    }

    #[test]
    fn omitted_process_results_enter_fallback_instead_of_staying_requested() {
        let mut registry = ClassificationRegistry::default();
        let metadata = process_metadata(21, 23, None);
        let process = ProcessKey {
            tgid: metadata.instance.tgid,
            process_cookie: 22,
            exec_generation: 1,
        };
        registry.remember_metadata(metadata.clone());
        registry.on_process_discovered(process, Some(metadata), 0);
        let plan = registry.take_process_batches(16, usize::MAX).remove(0);

        assert!(registry
            .apply_process_proposals(plan.request_id, Vec::new())
            .is_empty());
        assert_eq!(
            registry.process(process).unwrap().semantic,
            SemanticState::Failed
        );
        assert!(registry.take_process_batches(16, usize::MAX).is_empty());
    }

    /// Thread semantic work waits until the owning process request has
    /// completed or entered fallback instead of racing it.
    #[test]
    fn thread_batch_waits_for_process_semantic_completion() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 51,
            process_cookie: 52,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 53,
            task_cookie: 54,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 51,
                start_time_ticks: 55,
            },
            parent: None,
            comm: "job".into(),
            command: vec!["job".into()],
            executable: Some("/bin/job".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.remember_metadata(metadata.clone());
        registry.on_process_discovered(process, Some(metadata), 0);
        registry.on_task_discovered(task, process, 0);
        let config = ClassificationConfig {
            thread_semantic_min_tasks: 1,
            ..ClassificationConfig::default()
        };
        assert!(registry
            .take_thread_batch_plans(6_000_000_000, &config, 16, usize::MAX)
            .is_empty());

        let process_plan = registry.take_process_batches(16, usize::MAX).remove(0);
        registry.mark_process_batch_failed(&process_plan);
        let plans = registry.take_thread_batch_plans(6_000_000_000, &config, 16, usize::MAX);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].tasks, vec![task]);
    }

    /// Eligibility is decided per process before deterministic bounded chunks
    /// are created, and one failed chunk cannot affect its siblings.
    #[test]
    fn thread_batches_respect_limit_and_isolate_failures() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 101,
            process_cookie: 102,
            exec_generation: 1,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: process.tgid,
                start_time_ticks: 103,
            },
            parent: None,
            comm: "many-threads".into(),
            command: vec!["many-threads".into()],
            executable: Some("/bin/many-threads".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.on_process_discovered(process, Some(metadata), 0);

        let tasks: Vec<_> = (0..25_u32)
            .map(|index| TaskKey {
                tid: 1_000 + index,
                task_cookie: 2_000 + u64::from(index),
            })
            .collect();
        for task in tasks.iter().rev() {
            registry.on_task_discovered(*task, process, 0);
        }

        let process_plan = registry.take_process_batches(12, usize::MAX).remove(0);
        registry.mark_process_batch_failed(&process_plan);
        let config = ClassificationConfig {
            thread_semantic_min_tasks: 20,
            ..ClassificationConfig::default()
        };
        let plans = registry.take_thread_batch_plans(6_000_000_000, &config, 12, usize::MAX);

        assert_eq!(
            plans
                .iter()
                .map(|plan| plan.tasks.len())
                .collect::<Vec<_>>(),
            vec![12, 12, 1]
        );
        assert_eq!(
            plans
                .iter()
                .flat_map(|plan| plan.tasks.iter().copied())
                .collect::<Vec<_>>(),
            tasks
        );
        assert!(tasks
            .iter()
            .all(|task| { registry.task(*task).unwrap().semantic == SemanticState::Requested }));

        registry.mark_thread_batch_failed(&plans[1].tasks);
        let failed: HashSet<_> = plans[1].tasks.iter().copied().collect();
        for task in tasks {
            let expected = if failed.contains(&task) {
                SemanticState::Failed
            } else {
                SemanticState::Requested
            };
            assert_eq!(registry.task(task).unwrap().semantic, expected);
        }
    }

    /// A process default update mirrors its generation into inherited tasks.
    #[test]
    fn process_default_syncs_inherited_task_generation() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 61,
            process_cookie: 62,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 63,
            task_cookie: 64,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 61,
                start_time_ticks: 65,
            },
            parent: None,
            comm: "job".into(),
            command: vec!["job".into()],
            executable: Some("/bin/job".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.on_process_discovered(process, Some(metadata.clone()), 0);
        registry.on_task_discovered(task, process, 0);
        assert!(registry
            .record_process_behavior(process, TaskClass::Throughput, 1)
            .is_empty());
        let actions = registry.record_process_behavior(process, TaskClass::Throughput, 2);
        assert!(matches!(
            actions.as_slice(),
            [RegistryAction::SetProcessDefault {
                class: TaskClass::Throughput,
                new_generation: 1,
                ..
            }]
        ));
        let task_record = registry.task(task).unwrap();
        assert_eq!(task_record.effective_class, TaskClass::Throughput);
        assert_eq!(task_record.class_generation, 1);
        assert_eq!(task_record.stage, ClassStage::Inherited);
    }

    #[test]
    fn scheduler_replay_restores_only_the_same_thread_lifetime() {
        let mut registry = ClassificationRegistry::default();
        let old_process = ProcessKey {
            tgid: 66,
            process_cookie: 67,
            exec_generation: 1,
        };
        let old_task = TaskKey {
            tid: 68,
            task_cookie: 69,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 66,
                start_time_ticks: 70,
            },
            parent: None,
            comm: "worker".into(),
            command: vec!["worker".into()],
            executable: Some("/bin/worker".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.on_process_discovered(old_process, Some(metadata.clone()), 1);
        registry.on_task_discovered_with_start_time(old_task, old_process, Some(71), 2);
        let old_record = registry.tasks.get_mut(&old_task).unwrap();
        old_record.effective_class = TaskClass::Throughput;
        old_record.stage = ClassStage::Locked;
        old_record.class_generation = 2;
        old_record.applied_generation = 2;
        old_record.semantic = SemanticState::Classified {
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };

        registry.begin_scheduler_replay();
        let new_process = ProcessKey {
            process_cookie: 72,
            ..old_process
        };
        let new_task = TaskKey {
            task_cookie: 73,
            ..old_task
        };
        registry.on_process_discovered(new_process, Some(metadata), 3);
        registry.on_task_discovered_with_start_time(new_task, new_process, Some(71), 4);
        registry.finish_scheduler_replay();

        assert!(registry.process(old_process).is_none());
        assert!(registry.task(old_task).is_none());
        let restored = registry.task(new_task).unwrap();
        assert_eq!(restored.effective_class, TaskClass::Throughput);
        assert_eq!(restored.stage, ClassStage::Locked);
        assert_eq!(restored.class_generation, 2);
        assert_eq!(restored.applied_generation, 0);
    }

    #[test]
    fn scheduler_replay_rejects_reused_tid() {
        let mut registry = ClassificationRegistry::default();
        let old_process = ProcessKey {
            tgid: 76,
            process_cookie: 77,
            exec_generation: 1,
        };
        let old_task = TaskKey {
            tid: 78,
            task_cookie: 79,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 76,
                start_time_ticks: 80,
            },
            parent: None,
            comm: "worker".into(),
            command: vec!["worker".into()],
            executable: Some("/bin/worker".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.on_process_discovered(old_process, Some(metadata.clone()), 1);
        registry.on_task_discovered_with_start_time(old_task, old_process, Some(81), 2);
        let old_record = registry.tasks.get_mut(&old_task).unwrap();
        old_record.effective_class = TaskClass::Latency;
        old_record.stage = ClassStage::Semantic;
        old_record.class_generation = 1;

        registry.begin_scheduler_replay();
        let new_process = ProcessKey {
            process_cookie: 82,
            ..old_process
        };
        let new_task = TaskKey {
            task_cookie: 83,
            ..old_task
        };
        registry.on_process_discovered(new_process, Some(metadata), 3);
        registry.on_task_discovered_with_start_time(new_task, new_process, Some(84), 4);
        registry.finish_scheduler_replay();

        let new_record = registry.task(new_task).unwrap();
        assert_eq!(new_record.effective_class, TaskClass::Balanced);
        assert_eq!(new_record.stage, ClassStage::Inherited);
        assert_eq!(new_record.class_generation, 0);
    }

    /// Failed semantics allow a task lock without changing the process default.
    #[test]
    fn behavior_locks_only_task_after_three_windows() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 71,
            process_cookie: 72,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 73,
            task_cookie: 74,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 71,
                start_time_ticks: 75,
            },
            parent: None,
            comm: "job".into(),
            command: vec!["job".into()],
            executable: Some("/bin/job".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.remember_metadata(metadata.clone());
        registry.on_process_discovered(process, Some(metadata), 0);
        registry.on_task_discovered(task, process, 0);
        let process_plan = registry.take_process_batches(16, usize::MAX).remove(0);
        registry.mark_process_batch_failed(&process_plan);
        let config = ClassificationConfig {
            thread_semantic_min_tasks: 1,
            ..ClassificationConfig::default()
        };
        let task_plan = registry
            .take_thread_batch_plans(6_000_000_000, &config, 16, usize::MAX)
            .remove(0);
        registry.mark_thread_batch_failed(&task_plan.tasks);

        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 1), Some(proposal), &config)
            .is_empty());
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 2), Some(proposal), &config)
            .is_empty());
        let actions = registry.apply_behavior_window(
            behavior_window(task, process, 3),
            Some(proposal),
            &config,
        );
        assert!(matches!(
            actions.as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Throughput,
                stage: ClassStage::Locked,
                new_generation: 1,
                ..
            }]
        ));
        assert_eq!(
            registry.process(process).unwrap().default_class,
            TaskClass::Balanced
        );
    }

    /// A result created before exec cannot classify the same task cookie in a
    /// new process image generation.
    #[test]
    fn thread_proposal_requires_matching_process_image() {
        let mut registry = ClassificationRegistry::default();
        let old_process = ProcessKey {
            tgid: 21,
            process_cookie: 22,
            exec_generation: 1,
        };
        let new_process = ProcessKey {
            exec_generation: 2,
            ..old_process
        };
        let task = TaskKey {
            tid: 23,
            task_cookie: 24,
        };
        registry.on_task_discovered(task, new_process, 0);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Requested;
        let actions = registry.apply_thread_proposals(vec![ThreadClassificationProposal {
            process: old_process,
            task,
            class: Some(TaskClass::Latency),
            confidence: 0.9,
        }]);
        assert!(actions.is_empty());
        assert_eq!(
            registry.task(task).unwrap().effective_class,
            TaskClass::Balanced
        );
    }

    #[test]
    fn specialized_thread_semantics_wait_for_behavior_corroboration() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 71,
            process_cookie: 72,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 73,
            task_cookie: 74,
        };
        registry.on_task_discovered(task, process, 0);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Requested;

        let actions = registry.apply_thread_proposals(vec![ThreadClassificationProposal {
            process,
            task,
            class: Some(TaskClass::Throughput),
            confidence: 0.9,
        }]);

        assert!(actions.is_empty());
        let record = registry.task(task).unwrap();
        assert_eq!(record.effective_class, TaskClass::Balanced);
        assert_eq!(record.stage, ClassStage::Inherited);
        assert_eq!(
            record.semantic,
            SemanticState::Classified {
                class: TaskClass::Throughput,
                confidence_per_mille: 900,
            }
        );

        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        for sequence in 1..config.low_confidence_correction_windows {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, u64::from(sequence)),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        let actions = registry.apply_behavior_window(
            behavior_window(
                task,
                process,
                u64::from(config.low_confidence_correction_windows),
            ),
            Some(proposal),
            &config,
        );
        assert!(matches!(
            actions.as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Throughput,
                stage: ClassStage::Locked,
                ..
            }]
        ));
    }

    #[test]
    fn conflicting_thread_semantics_wait_for_local_corroboration() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 81,
            process_cookie: 82,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 83,
            task_cookie: 84,
        };
        registry.on_task_discovered(task, process, 0);
        let process_record = registry.processes.get_mut(&process).unwrap();
        process_record.default_class = TaskClass::Throughput;
        process_record.semantic = SemanticState::Classified {
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        let task_record = registry.tasks.get_mut(&task).unwrap();
        task_record.effective_class = TaskClass::Throughput;
        task_record.semantic = SemanticState::Requested;

        let actions = registry.apply_thread_proposals(vec![ThreadClassificationProposal {
            process,
            task,
            class: Some(TaskClass::Balanced),
            confidence: 0.8,
        }]);

        assert!(actions.is_empty());
        let record = registry.task(task).unwrap();
        assert_eq!(record.effective_class, TaskClass::Throughput);
        assert_eq!(record.stage, ClassStage::Inherited);
        assert_eq!(
            record.semantic,
            SemanticState::Classified {
                class: TaskClass::Balanced,
                confidence_per_mille: 800,
            }
        );

        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        for sequence in 1..=2 {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, sequence),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        assert!(matches!(
            registry
                .apply_behavior_window(behavior_window(task, process, 3), Some(proposal), &config)
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Throughput,
                stage: ClassStage::Locked,
                ..
            }]
        ));
    }

    #[test]
    fn behavior_and_thread_semantics_can_override_process_semantics() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 91,
            process_cookie: 92,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 93,
            task_cookie: 94,
        };
        registry.on_task_discovered(task, process, 0);
        let process_record = registry.processes.get_mut(&process).unwrap();
        process_record.default_class = TaskClass::Throughput;
        process_record.semantic = SemanticState::Classified {
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        let task_record = registry.tasks.get_mut(&task).unwrap();
        task_record.effective_class = TaskClass::Throughput;
        task_record.semantic = SemanticState::Requested;
        assert!(registry
            .apply_thread_proposals(vec![ThreadClassificationProposal {
                process,
                task,
                class: Some(TaskClass::Latency),
                confidence: 0.9,
            }])
            .is_empty());

        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        };
        for sequence in 1..=2 {
            assert!(registry
                .apply_behavior_window(
                    behavior_window(task, process, sequence),
                    Some(proposal),
                    &config,
                )
                .is_empty());
        }
        assert!(matches!(
            registry
                .apply_behavior_window(behavior_window(task, process, 3), Some(proposal), &config)
                .as_slice(),
            [RegistryAction::SetTaskClass {
                class: TaskClass::Latency,
                stage: ClassStage::Locked,
                ..
            }]
        ));
    }

    /// Public proposal inputs cannot bypass confidence validation.
    #[test]
    fn semantic_proposal_rejects_invalid_confidence() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 25,
            process_cookie: 26,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 27,
            task_cookie: 28,
        };
        registry.on_task_discovered(task, process, 0);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Requested;

        let actions = registry.apply_thread_proposals(vec![ThreadClassificationProposal {
            process,
            task,
            class: Some(TaskClass::Throughput),
            confidence: f32::NAN,
        }]);

        assert!(actions.is_empty());
        let record = registry.task(task).unwrap();
        assert_eq!(record.semantic, SemanticState::Unknown);
        assert_eq!(record.effective_class, TaskClass::Balanced);
        assert_eq!(record.stage, ClassStage::Inherited);
    }

    /// An old semantic request cannot classify a new exec generation even
    /// when Linux preserves the TGID and `/proc` start-time value.
    #[test]
    fn process_proposal_requires_current_request_generation() {
        let mut registry = ClassificationRegistry::default();
        let old_process = ProcessKey {
            tgid: 31,
            process_cookie: 32,
            exec_generation: 1,
        };
        let new_process = ProcessKey {
            exec_generation: 2,
            ..old_process
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 31,
                start_time_ticks: 33,
            },
            parent: None,
            comm: "job".into(),
            command: vec!["job".into()],
            executable: Some("/bin/job".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };

        registry.on_process_discovered(old_process, Some(metadata.clone()), 0);
        let old_plan = registry.take_process_batches(16, usize::MAX).remove(0);
        registry.on_process_exited(old_process);
        registry.on_process_discovered(new_process, Some(metadata.clone()), 1);
        let new_plan = registry.take_process_batches(16, usize::MAX).remove(0);

        let actions = registry.apply_process_proposals(
            old_plan.request_id,
            vec![ProcessClassificationProposal {
                instance: metadata.instance,
                class: Some(TaskClass::Throughput),
                confidence: 0.9,
            }],
        );
        assert!(actions.is_empty());
        assert_eq!(
            registry.process(new_process).unwrap().default_class,
            TaskClass::Balanced
        );
        assert_eq!(
            registry.process_request_ids.get(&metadata.instance),
            Some(&new_plan.request_id)
        );
    }

    /// Reconciliation bounds pre-cookie metadata and invalidates its in-flight request.
    #[test]
    fn reconciliation_drops_missing_unbound_instance() {
        let mut registry = ClassificationRegistry::default();
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 41,
                start_time_ticks: 42,
            },
            parent: None,
            comm: "short-lived".into(),
            command: vec!["short-lived".into()],
            executable: Some("/bin/short-lived".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.remember_metadata(metadata.clone());
        let plan = registry.take_process_batches(16, usize::MAX).remove(0);
        registry.retain_live_instances(&HashSet::new());

        assert!(!registry
            .metadata_by_instance
            .contains_key(&metadata.instance));
        assert!(registry
            .apply_process_proposals(
                plan.request_id,
                vec![ProcessClassificationProposal {
                    instance: metadata.instance,
                    class: Some(TaskClass::Latency),
                    confidence: 0.9,
                }],
            )
            .is_empty());
    }

    #[test]
    fn confidence_below_configured_threshold_becomes_unknown() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 51,
            process_cookie: 52,
            exec_generation: 1,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 51,
                start_time_ticks: 53,
            },
            parent: None,
            comm: "low-confidence".into(),
            command: vec!["low-confidence".into()],
            executable: Some("/bin/low-confidence".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.on_process_discovered(process, Some(metadata.clone()), 0);
        let request = registry.take_process_batches(1, usize::MAX).remove(0);
        let actions = registry.apply_process_proposals(
            request.request_id,
            vec![ProcessClassificationProposal {
                instance: metadata.instance,
                class: Some(TaskClass::Latency),
                confidence: 0.599,
            }],
        );

        assert!(actions.is_empty());
        assert_eq!(
            registry.process(process).unwrap().semantic,
            SemanticState::Unknown
        );
        assert_eq!(
            registry.process(process).unwrap().default_class,
            TaskClass::Balanced
        );
    }

    #[test]
    fn snapshot_is_bounded_and_confirms_pending_generation() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 61,
            process_cookie: 62,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 63,
            task_cookie: 64,
        };
        registry.on_task_discovered(task, process, 0);
        registry.processes.get_mut(&process).unwrap().semantic = SemanticState::Failed;
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Failed;
        let config = ClassificationConfig::default();
        let proposal = BehaviorClassificationProposal {
            process,
            task,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 1), Some(proposal), &config)
            .is_empty());
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 2), Some(proposal), &config)
            .is_empty());
        let action = registry
            .apply_behavior_window(behavior_window(task, process, 3), Some(proposal), &config)
            .remove(0);
        assert!(!registry.acknowledge(action, 0));
        assert_eq!(registry.pending_actions(), vec![action]);

        let batches = registry.snapshot_batches(7, 1);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].processes.len(), 1);
        assert!(batches[0].tasks.is_empty());
        assert_eq!(batches[1].tasks.len(), 1);
        assert!(batches[1].is_last);

        registry.mark_snapshot_applied();
        assert!(registry.pending_actions().is_empty());
        assert_eq!(registry.task(task).unwrap().applied_generation, 1);
    }

    #[test]
    fn exec_invalidates_old_image_and_requeues_semantics() {
        let mut registry = ClassificationRegistry::default();
        let previous_process = ProcessKey {
            tgid: 71,
            process_cookie: 72,
            exec_generation: 1,
        };
        let process = ProcessKey {
            exec_generation: 2,
            ..previous_process
        };
        let task = TaskKey {
            tid: 71,
            task_cookie: 73,
        };
        let metadata = ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid: 71,
                start_time_ticks: 74,
            },
            parent: None,
            comm: "new-image".into(),
            command: vec!["new-image".into()],
            executable: Some("/bin/new-image".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        };
        registry.on_task_discovered(task, previous_process, 0);
        registry.on_process_exec(task, previous_process, process, Some(metadata), None, 1);

        assert!(registry.process(previous_process).is_none());
        assert_eq!(registry.task(task).unwrap().process, process);
        assert_eq!(registry.take_process_batches(1, usize::MAX).len(), 1);
    }

    #[test]
    fn behavior_sequence_gap_breaks_consecutive_votes() {
        let mut registry = ClassificationRegistry::default();
        let process = ProcessKey {
            tgid: 81,
            process_cookie: 82,
            exec_generation: 1,
        };
        let task = TaskKey {
            tid: 83,
            task_cookie: 84,
        };
        registry.on_task_discovered(task, process, 0);
        registry.tasks.get_mut(&task).unwrap().semantic = SemanticState::Unknown;
        let proposal = BehaviorClassificationProposal {
            task,
            process,
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        };
        let config = ClassificationConfig::default();

        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 1), Some(proposal), &config)
            .is_empty());
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 3), Some(proposal), &config)
            .is_empty());
        assert!(registry
            .apply_behavior_window(behavior_window(task, process, 4), Some(proposal), &config)
            .is_empty());
        assert_eq!(
            registry
                .apply_behavior_window(behavior_window(task, process, 5), Some(proposal), &config)
                .len(),
            1
        );
    }

    #[test]
    fn registry_drops_records_at_configured_capacity() {
        let limits = RuntimeLimits {
            registry_processes: 1,
            registry_tasks: 1,
            ..RuntimeLimits::default()
        };
        let mut registry = ClassificationRegistry::new(limits, 0.60, 0.90);
        let process = ProcessKey {
            tgid: 91,
            process_cookie: 92,
            exec_generation: 1,
        };
        registry.on_task_discovered(
            TaskKey {
                tid: 93,
                task_cookie: 94,
            },
            process,
            0,
        );
        registry.on_task_discovered(
            TaskKey {
                tid: 95,
                task_cookie: 96,
            },
            process,
            0,
        );

        assert_eq!(registry.stats().tasks, 1);
        assert_eq!(registry.stats().dropped_task_records, 1);
    }
}
