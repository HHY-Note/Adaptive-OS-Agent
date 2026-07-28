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
    /// New runnable incarnation waiting in a BPF-owned queue.
    Enqueue,
    /// Runnable incarnation was dequeued or cancelled.
    Cancel,
    /// A BPF-selected task actually began on a CPU.
    Running,
    /// Running task stopped and reports actual service.
    Stop,
    /// Task lifetime exited.
    Exit,
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
            _ => Err(WireError::UnknownEventKind(value)),
        }
    }
}

/// Fully validated event consumed by `SchedulerEngine`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelEvent {
    /// Lifecycle transition represented by this record.
    pub kind: EventKind,
    /// Stable task identity.
    pub task: Option<TaskKey>,
    /// Stable process image.
    pub process: Option<ProcessKey>,
    /// Runnable generation owned by BPF.
    pub enqueue_sequence: u64,
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

        if task.is_none() || process.is_none() {
            return Err(WireError::MissingIdentity(kind));
        }
        if matches!(
            kind,
            EventKind::Enqueue | EventKind::Cancel | EventKind::Running | EventKind::Stop
        ) && raw.enqueue_sequence == 0
        {
            return Err(WireError::MissingRunnableSequence);
        }

        Ok(Self {
            kind,
            task,
            process,
            enqueue_sequence: raw.enqueue_sequence,
            timestamp_ns: raw.timestamp_ns,
            runtime_ns: raw.runtime_ns,
            sleep_ns: raw.sleep_ns,
            previous_cpu: (raw.previous_cpu >= 0).then_some(raw.previous_cpu as u32),
            actual_cpu: (raw.actual_cpu >= 0).then_some(raw.actual_cpu as u32),
            flags: raw.flags,
        })
    }
}

/// Converts a validated task class cache into a BPF generation value.
pub fn task_control_raw(
    task: TaskKey,
    cache: TaskClassCache,
) -> (u32, bpf_intf::task_control_value) {
    let observe = match cache.stage {
        ClassStage::Inherited => {
            bpf_intf::SCX_ADAPTIVE_CONTROL_OBSERVE | bpf_intf::SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE
        }
        ClassStage::Semantic => bpf_intf::SCX_ADAPTIVE_CONTROL_OBSERVE,
        ClassStage::Locked => 0,
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
}

#[cfg(test)]
mod tests {
    use super::{task_control_raw, EventKind, KernelEvent, WireError};
    use crate::bpf_intf;
    use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
    use crate::process::TaskClassCache;

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
            bpf_intf::SCX_ADAPTIVE_CONTROL_BPF_SCHED
                | bpf_intf::SCX_ADAPTIVE_CONTROL_OBSERVE
                | bpf_intf::SCX_ADAPTIVE_CONTROL_COARSE_OBSERVE
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
}
