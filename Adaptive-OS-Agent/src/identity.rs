// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Stable process image identity received from the scheduler data plane.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProcessKey {
    /// Numeric Linux thread-group ID.
    pub tgid: u32,
    /// Non-zero BPF lifetime cookie.
    pub process_cookie: u64,
    /// Non-zero exec generation within that lifetime.
    pub exec_generation: u64,
}

/// Stable task lifetime identity received from the scheduler data plane.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct TaskKey {
    /// Numeric Linux thread ID.
    pub tid: u32,
    /// Non-zero BPF lifetime cookie preventing TID reuse collisions.
    pub task_cookie: u64,
}

/// Semantic workload class shared by Agent JSON and scheduler control JSON.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    /// Response-bound or interactive work.
    Latency,
    /// Unknown and general-purpose work.
    #[default]
    Balanced,
    /// Sustained CPU-throughput work.
    Throughput,
}

/// Task-level classification transition stage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassStage {
    /// Task currently follows its process default.
    #[default]
    Inherited,
    /// Thread semantic classification may be corrected once by behavior.
    Semantic,
    /// One-time correction has been consumed and the class is permanent.
    Locked,
}
