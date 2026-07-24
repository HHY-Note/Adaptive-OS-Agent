// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};

/// Stable identity of one process image for a single `exec` generation.
///
/// A numeric TGID alone is unsafe because Linux can reuse it. `process_cookie`
/// is allocated by BPF for the lifetime of the thread group, while
/// `exec_generation` changes whenever that group executes a new image.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProcessKey {
    /// Numeric thread-group ID visible in `/proc`.
    pub tgid: u32,
    /// Non-zero BPF allocated identity for this thread-group lifetime.
    pub process_cookie: u64,
    /// Monotonic image generation within the process lifetime.
    pub exec_generation: u64,
}

impl ProcessKey {
    /// Constructs a process identity after checking all non-zero invariants.
    pub fn new(tgid: u32, process_cookie: u64, exec_generation: u64) -> Option<Self> {
        (tgid != 0 && process_cookie != 0 && exec_generation != 0).then_some(Self {
            tgid,
            process_cookie,
            exec_generation,
        })
    }
}

/// Stable identity of one kernel-scheduled thread.
///
/// `task_cookie` prevents delayed events for an exited thread from matching a
/// later thread that happens to reuse the same TID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct TaskKey {
    /// Numeric Linux thread ID.
    pub tid: u32,
    /// Non-zero BPF allocated identity for this task lifetime.
    pub task_cookie: u64,
}

impl TaskKey {
    /// Constructs a task identity after checking its non-zero invariants.
    pub fn new(tid: u32, task_cookie: u64) -> Option<Self> {
        (tid != 0 && task_cookie != 0).then_some(Self { tid, task_cookie })
    }
}

/// Identity of exactly one runnable incarnation of a task.
///
/// A task receives a new `enqueue_sequence` whenever BPF hands a new runnable
/// instance to Rust. Dispatch commands must match all three fields.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnableKey {
    /// Stable lifetime identity of the task.
    pub task: TaskKey,
    /// BPF-owned generation of this runnable instance.
    pub enqueue_sequence: u64,
}

impl RunnableKey {
    /// Constructs a runnable identity when the sequence is valid.
    pub fn new(task: TaskKey, enqueue_sequence: u64) -> Option<Self> {
        (enqueue_sequence != 0).then_some(Self {
            task,
            enqueue_sequence,
        })
    }
}

/// Workload class selected by Agent and consumed by the scheduler.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    /// Interactive or response-bound work with short slices and wait rescue.
    Latency = 0,
    /// Unknown and general work with a medium EEVDF request.
    #[default]
    Balanced = 1,
    /// CPU-throughput work with longer slices and stronger locality preference.
    Throughput = 2,
}

impl TaskClass {
    /// Returns the stable array index used by per-class scheduler ledgers.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Returns all classes in stable EEVDF tiebreak order.
    pub const fn all() -> [Self; 3] {
        [Self::Latency, Self::Balanced, Self::Throughput]
    }
}

/// Origin and mutability stage of the effective task classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassStage {
    /// Task currently inherits its process default.
    #[default]
    Inherited,
    /// Agent supplied a thread-semantic result which may be corrected once.
    Semantic,
    /// Agent consumed the one-time correction and the class is permanent.
    Locked,
}

#[cfg(test)]
mod tests {
    use super::{ProcessKey, RunnableKey, TaskClass, TaskKey};

    /// Invalid numeric identities must be rejected before reaching caches.
    #[test]
    fn identity_constructors_reject_zero_components() {
        assert!(ProcessKey::new(0, 1, 1).is_none());
        assert!(ProcessKey::new(1, 0, 1).is_none());
        assert!(ProcessKey::new(1, 1, 0).is_none());
        assert!(TaskKey::new(0, 1).is_none());
        assert!(TaskKey::new(1, 0).is_none());
        assert!(RunnableKey::new(TaskKey::new(1, 1).unwrap(), 0).is_none());
    }

    /// Class indexes are an ABI internal to dense Rust scheduler arrays.
    #[test]
    fn classes_have_dense_stable_indexes() {
        assert_eq!(TaskClass::all().map(TaskClass::index), [0, 1, 2]);
    }
}
