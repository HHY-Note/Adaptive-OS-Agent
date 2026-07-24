// SPDX-License-Identifier: GPL-2.0-only

use std::mem;

use thiserror::Error;

use crate::bpf_intf;
use crate::identity::{ClassStage, ProcessKey, TaskKey};
use crate::process::TaskClassCache;

/// Validated kernel event kind used by the policy state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// New task lifetime initialized by sched_ext.
    Init,
    /// Existing process lifetime entered a new exec generation.
    Exec,
    /// New runnable incarnation waiting in a Rust pool.
    Enqueue,
    /// Runnable incarnation was dequeued or cancelled.
    Cancel,
    /// Staged task actually began on a CPU.
    Running,
    /// Running task stopped and reports actual service.
    Stop,
    /// Task lifetime exited.
    Exit,
    /// CPU idle or hotplug state changed.
    CpuState,
    /// BPF rejected a stale or invalid dispatch command.
    CommandReject,
}

impl TryFrom<u16> for EventKind {
    type Error = WireError;

    /// Converts the stable C event number into a Rust enum.
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value as u32 {
            bpf_intf::SCX_ADAPTIVE_EVENT_INIT => Ok(Self::Init),
            bpf_intf::SCX_ADAPTIVE_EVENT_EXEC => Ok(Self::Exec),
            bpf_intf::SCX_ADAPTIVE_EVENT_ENQUEUE => Ok(Self::Enqueue),
            bpf_intf::SCX_ADAPTIVE_EVENT_CANCEL => Ok(Self::Cancel),
            bpf_intf::SCX_ADAPTIVE_EVENT_RUNNING => Ok(Self::Running),
            bpf_intf::SCX_ADAPTIVE_EVENT_STOP => Ok(Self::Stop),
            bpf_intf::SCX_ADAPTIVE_EVENT_EXIT => Ok(Self::Exit),
            bpf_intf::SCX_ADAPTIVE_EVENT_CPU_STATE => Ok(Self::CpuState),
            bpf_intf::SCX_ADAPTIVE_EVENT_COMMAND_REJECT => Ok(Self::CommandReject),
            _ => Err(WireError::UnknownEventKind(value)),
        }
    }
}

/// Stable BPF command-rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// Task exited before BPF consumed its command.
    TaskGone,
    /// Task/process cookies or exec generation did not match.
    Identity,
    /// Task was no longer waiting for a userspace decision.
    NotPending,
    /// Runnable enqueue sequence changed.
    Sequence,
    /// Agent class generation changed.
    ClassGeneration,
    /// Target CPU was absent or offline.
    CpuOffline,
    /// Target CPU was no longer in the live affinity mask.
    Affinity,
    /// Another dispatch callback atomically claimed the selected CPU lane.
    TargetSlotBusy,
    /// Planned slice fell outside loader bounds.
    Slice,
    /// Runnable incarnation already consumed another dispatch ID.
    DuplicateDispatch,
    /// Task temporarily cannot move away from its current CPU.
    MigrationDisabled,
    /// Dispatch command contained an unsupported flag bit.
    Flags,
    /// Future BPF reason not known to this userspace binary.
    Unknown(u32),
}

impl From<u64> for RejectReason {
    /// Decodes the rejection code carried in `task_event.flags`.
    fn from(value: u64) -> Self {
        match value as u32 {
            bpf_intf::SCX_ADAPTIVE_REJECT_TASK_GONE => Self::TaskGone,
            bpf_intf::SCX_ADAPTIVE_REJECT_IDENTITY => Self::Identity,
            bpf_intf::SCX_ADAPTIVE_REJECT_NOT_PENDING => Self::NotPending,
            bpf_intf::SCX_ADAPTIVE_REJECT_SEQUENCE => Self::Sequence,
            bpf_intf::SCX_ADAPTIVE_REJECT_CLASS_GENERATION => Self::ClassGeneration,
            bpf_intf::SCX_ADAPTIVE_REJECT_CPU_OFFLINE => Self::CpuOffline,
            bpf_intf::SCX_ADAPTIVE_REJECT_AFFINITY => Self::Affinity,
            bpf_intf::SCX_ADAPTIVE_REJECT_TARGET_SLOT_BUSY => Self::TargetSlotBusy,
            bpf_intf::SCX_ADAPTIVE_REJECT_SLICE => Self::Slice,
            bpf_intf::SCX_ADAPTIVE_REJECT_DUPLICATE_DISPATCH => Self::DuplicateDispatch,
            bpf_intf::SCX_ADAPTIVE_REJECT_MIGRATION_DISABLED => Self::MigrationDisabled,
            bpf_intf::SCX_ADAPTIVE_REJECT_FLAGS => Self::Flags,
            unknown => Self::Unknown(unknown),
        }
    }
}

impl RejectReason {
    /// Returns the stable BPF reason code, with unknown values folded into zero.
    pub const fn counter_index(self) -> usize {
        match self {
            Self::TaskGone => bpf_intf::SCX_ADAPTIVE_REJECT_TASK_GONE as usize,
            Self::Identity => bpf_intf::SCX_ADAPTIVE_REJECT_IDENTITY as usize,
            Self::NotPending => bpf_intf::SCX_ADAPTIVE_REJECT_NOT_PENDING as usize,
            Self::Sequence => bpf_intf::SCX_ADAPTIVE_REJECT_SEQUENCE as usize,
            Self::ClassGeneration => bpf_intf::SCX_ADAPTIVE_REJECT_CLASS_GENERATION as usize,
            Self::CpuOffline => bpf_intf::SCX_ADAPTIVE_REJECT_CPU_OFFLINE as usize,
            Self::Affinity => bpf_intf::SCX_ADAPTIVE_REJECT_AFFINITY as usize,
            Self::TargetSlotBusy => bpf_intf::SCX_ADAPTIVE_REJECT_TARGET_SLOT_BUSY as usize,
            Self::Slice => bpf_intf::SCX_ADAPTIVE_REJECT_SLICE as usize,
            Self::DuplicateDispatch => bpf_intf::SCX_ADAPTIVE_REJECT_DUPLICATE_DISPATCH as usize,
            Self::MigrationDisabled => bpf_intf::SCX_ADAPTIVE_REJECT_MIGRATION_DISABLED as usize,
            Self::Flags => bpf_intf::SCX_ADAPTIVE_REJECT_FLAGS as usize,
            Self::Unknown(_) => 0,
        }
    }

    /// Returns true only when a fresh placement attempt can resolve the rejection.
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::ClassGeneration
                | Self::CpuOffline
                | Self::Affinity
                | Self::TargetSlotBusy
                | Self::MigrationDisabled
        )
    }
}

/// Fully validated event consumed by `SchedulerEngine`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelEvent {
    /// Lifecycle transition represented by this record.
    pub kind: EventKind,
    /// Stable task identity; absent only for CPU events or malformed rejection context.
    pub task: Option<TaskKey>,
    /// Stable process image; absent for CPU events and task-gone rejections.
    pub process: Option<ProcessKey>,
    /// Runnable generation owned by BPF.
    pub enqueue_sequence: u64,
    /// Dispatch reservation identity, zero before dispatch.
    pub dispatch_id: u64,
    /// Monotonic BPF timestamp.
    pub timestamp_ns: u64,
    /// Actual service reported by STOP.
    pub runtime_ns: u64,
    /// Time since the previous stop reported by ENQUEUE.
    pub sleep_ns: u64,
    /// CPU passed to select_cpu for locality history.
    pub previous_cpu: Option<u32>,
    /// CPU that actually ran the task or changed state.
    pub actual_cpu: Option<u32>,
    /// Event-specific stable bit flags or rejection reason.
    pub flags: u64,
}

impl KernelEvent {
    /// Returns whether STOP said the task remained runnable.
    pub fn remained_runnable(&self) -> bool {
        self.flags & bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_RUNNABLE as u64 != 0
    }

    /// Returns whether ENQUEUE followed a voluntary blocking stop.
    pub fn was_wakeup(&self) -> bool {
        self.flags & bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_WAKEUP as u64 != 0
    }

    /// Returns whether BPF selected this runnable instance without a Rust command.
    pub fn bpf_scheduled(&self) -> bool {
        self.flags & bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_BPF_SCHEDULED as u64 != 0
    }

    /// Returns CPU online state from a CPU_STATE event.
    pub fn cpu_online(&self) -> bool {
        self.flags & bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_CPU_ONLINE as u64 != 0
    }

    /// Returns CPU idle state from a CPU_STATE event.
    pub fn cpu_idle(&self) -> bool {
        self.flags & bpf_intf::SCX_ADAPTIVE_EVENT_FLAG_CPU_IDLE as u64 != 0
    }

    /// Returns the decoded command rejection reason.
    pub fn reject_reason(&self) -> RejectReason {
        RejectReason::from(self.flags)
    }
}

impl TryFrom<bpf_intf::task_event> for KernelEvent {
    type Error = WireError;

    /// Checks ABI version, size, event number, and required identity fields.
    fn try_from(raw: bpf_intf::task_event) -> Result<Self, Self::Error> {
        if raw.abi_version as u32 != bpf_intf::SCX_ADAPTIVE_ABI_VERSION {
            return Err(WireError::AbiVersion(raw.abi_version));
        }
        if raw.struct_size as usize != mem::size_of::<bpf_intf::task_event>() {
            return Err(WireError::StructSize {
                expected: mem::size_of::<bpf_intf::task_event>(),
                received: raw.struct_size as usize,
            });
        }
        let kind = EventKind::try_from(raw.event_kind)?;
        let task = TaskKey::new(raw.tid, raw.task_cookie);
        let process = ProcessKey::new(raw.tgid, raw.process_cookie, raw.exec_generation);

        if !matches!(kind, EventKind::CpuState | EventKind::CommandReject)
            && (task.is_none() || process.is_none())
        {
            return Err(WireError::MissingIdentity(kind));
        }
        if matches!(kind, EventKind::Enqueue) && raw.enqueue_sequence == 0 {
            return Err(WireError::MissingRunnableSequence);
        }
        if matches!(kind, EventKind::CommandReject) && raw.dispatch_id == 0 {
            return Err(WireError::MissingDispatchId(kind));
        }

        Ok(Self {
            kind,
            task,
            process,
            enqueue_sequence: raw.enqueue_sequence,
            dispatch_id: raw.dispatch_id,
            timestamp_ns: raw.timestamp_ns,
            runtime_ns: raw.runtime_ns,
            sleep_ns: raw.sleep_ns,
            previous_cpu: (raw.previous_cpu >= 0).then_some(raw.previous_cpu as u32),
            actual_cpu: (raw.actual_cpu >= 0).then_some(raw.actual_cpu as u32),
            flags: raw.flags,
        })
    }
}

/// Policy decision ready to be serialized into the BPF command queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchRequest {
    /// Stable task lifetime selected from a Rust pool.
    pub task: TaskKey,
    /// Stable owning process image.
    pub process: ProcessKey,
    /// Runnable generation selected from the pool node.
    pub enqueue_sequence: u64,
    /// Agent class generation used for BPF lazy invalidation.
    pub class_generation: u64,
    /// Non-zero scheduler reservation identity.
    pub dispatch_id: u64,
    /// CPU whose unique staging slot Rust reserved.
    pub target_cpu: u32,
    /// Planned EEVDF request and dispatch slice.
    pub slice_ns: u64,
    /// Insert at the head of a local DSQ and preempt its current task.
    pub preempt: bool,
}

impl DispatchRequest {
    /// Serializes this decision into the exact fixed-width C ABI.
    pub fn to_raw(self) -> bpf_intf::dispatch_command {
        bpf_intf::dispatch_command {
            abi_version: bpf_intf::SCX_ADAPTIVE_ABI_VERSION as u16,
            flags: if self.preempt {
                bpf_intf::SCX_ADAPTIVE_DISPATCH_PREEMPT as u16
            } else {
                0
            },
            struct_size: mem::size_of::<bpf_intf::dispatch_command>() as u32,
            tid: self.task.tid,
            target_cpu: self.target_cpu,
            task_cookie: self.task.task_cookie,
            process_cookie: self.process.process_cookie,
            exec_generation: self.process.exec_generation,
            enqueue_sequence: self.enqueue_sequence,
            class_generation: self.class_generation,
            dispatch_id: self.dispatch_id,
            slice_ns: self.slice_ns,
        }
    }
}

/// Converts a validated task class cache into a BPF generation value.
pub fn task_control_raw(
    task: TaskKey,
    cache: TaskClassCache,
) -> (u32, bpf_intf::task_control_value) {
    let observe = if cache.stage == ClassStage::Locked {
        0
    } else {
        bpf_intf::SCX_ADAPTIVE_CONTROL_OBSERVE
    };
    (
        task.tid,
        bpf_intf::task_control_value {
            task_cookie: task.task_cookie,
            process_cookie: cache.process.process_cookie,
            exec_generation: cache.process.exec_generation,
            class_generation: cache.class_generation,
            class_id: cache.effective_class as u32,
            flags: bpf_intf::SCX_ADAPTIVE_CONTROL_BPF_SCHED | observe,
        },
    )
}

/// Binary ABI record rejected before it can mutate scheduler state.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WireError {
    /// Userspace and BPF were compiled against different ABI versions.
    #[error("unsupported BPF ABI version {0}")]
    AbiVersion(u16),
    /// Event record size differs from the compiled Rust layout.
    #[error("BPF event size {received} does not match expected {expected}")]
    StructSize {
        /// Rust layout size.
        expected: usize,
        /// BPF supplied layout size.
        received: usize,
    },
    /// Event kind number is not part of this ABI version.
    #[error("unknown BPF event kind {0}")]
    UnknownEventKind(u16),
    /// Task lifecycle event omitted stable task or process identity.
    #[error("{0:?} event has no complete stable identity")]
    MissingIdentity(EventKind),
    /// ENQUEUE omitted the runnable generation.
    #[error("enqueue event has sequence zero")]
    MissingRunnableSequence,
    /// RUNNING or reject event omitted its reservation identity.
    #[error("{0:?} event has dispatch id zero")]
    MissingDispatchId(EventKind),
}

#[cfg(test)]
mod tests {
    use super::{
        task_control_raw, DispatchRequest, EventKind, KernelEvent, RejectReason, WireError,
    };
    use crate::bpf_intf;
    use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
    use crate::process::TaskClassCache;

    /// Dispatch serialization carries complete runnable identity, not only TID.
    #[test]
    fn dispatch_request_serializes_complete_identity() {
        let raw = DispatchRequest {
            task: TaskKey::new(7, 70).unwrap(),
            process: ProcessKey::new(6, 60, 2).unwrap(),
            enqueue_sequence: 3,
            class_generation: 4,
            dispatch_id: 5,
            target_cpu: 1,
            slice_ns: 1_000_000,
            preempt: true,
        }
        .to_raw();
        assert_eq!(raw.task_cookie, 70);
        assert_eq!(raw.process_cookie, 60);
        assert_eq!(raw.exec_generation, 2);
        assert_eq!(raw.enqueue_sequence, 3);
        assert_eq!(raw.flags, bpf_intf::SCX_ADAPTIVE_DISPATCH_PREEMPT as u16);
    }

    /// Only terminal Locked generations suppress fast-path behavior events.
    #[test]
    fn task_control_serializes_class_and_fast_path_gate() {
        let task = TaskKey::new(7, 70).unwrap();
        let process = ProcessKey::new(6, 60, 2).unwrap();
        let (_, classified) = task_control_raw(
            task,
            TaskClassCache {
                process,
                effective_class: TaskClass::Throughput,
                stage: ClassStage::Semantic,
                class_generation: 4,
            },
        );
        assert_eq!(classified.class_id, bpf_intf::SCX_ADAPTIVE_CLASS_THROUGHPUT);
        assert_eq!(
            classified.flags,
            bpf_intf::SCX_ADAPTIVE_CONTROL_BPF_SCHED | bpf_intf::SCX_ADAPTIVE_CONTROL_OBSERVE
        );

        let (_, baseline) = task_control_raw(
            task,
            TaskClassCache {
                process,
                effective_class: TaskClass::Balanced,
                stage: ClassStage::Inherited,
                class_generation: 0,
            },
        );
        assert_eq!(
            baseline.flags,
            bpf_intf::SCX_ADAPTIVE_CONTROL_BPF_SCHED | bpf_intf::SCX_ADAPTIVE_CONTROL_OBSERVE
        );

        let (_, locked) = task_control_raw(
            task,
            TaskClassCache {
                process,
                effective_class: TaskClass::Latency,
                stage: ClassStage::Locked,
                class_generation: 5,
            },
        );
        assert_eq!(locked.flags, bpf_intf::SCX_ADAPTIVE_CONTROL_BPF_SCHED);
    }

    /// A lifecycle event without cookies cannot enter the scheduler engine.
    #[test]
    fn rejects_missing_task_identity() {
        let raw = bpf_intf::task_event {
            abi_version: bpf_intf::SCX_ADAPTIVE_ABI_VERSION as u16,
            event_kind: bpf_intf::SCX_ADAPTIVE_EVENT_ENQUEUE as u16,
            struct_size: std::mem::size_of::<bpf_intf::task_event>() as u32,
            tid: 1,
            tgid: 1,
            task_cookie: 0,
            process_cookie: 1,
            exec_generation: 1,
            enqueue_sequence: 1,
            dispatch_id: 0,
            timestamp_ns: 0,
            runtime_ns: 0,
            sleep_ns: 0,
            previous_cpu: -1,
            actual_cpu: -1,
            flags: 0,
        };
        assert_eq!(
            KernelEvent::try_from(raw),
            Err(WireError::MissingIdentity(EventKind::Enqueue))
        );
    }

    /// A transient migration-disable race is decoded and retried explicitly.
    #[test]
    fn migration_disabled_rejection_is_retryable() {
        let reason = RejectReason::from(bpf_intf::SCX_ADAPTIVE_REJECT_MIGRATION_DISABLED as u64);
        assert_eq!(reason, RejectReason::MigrationDisabled);
        assert!(reason.is_retryable());
        assert_eq!(
            reason.counter_index(),
            bpf_intf::SCX_ADAPTIVE_REJECT_MIGRATION_DISABLED as usize
        );
    }
}
