// SPDX-License-Identifier: GPL-2.0-only

use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};
use thiserror::Error;

/// Scheduler-side cache of Agent's default class for one process image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessDefaultCache {
    /// Default inherited by tasks without a semantic or locked override.
    pub default_class: TaskClass,
    /// Agent-owned generation used to reject delayed updates.
    pub class_generation: u64,
}

impl Default for ProcessDefaultCache {
    /// Creates the mandatory non-blocking fallback classification.
    fn default() -> Self {
        Self {
            default_class: TaskClass::Balanced,
            class_generation: 0,
        }
    }
}

/// Scheduler-side effective class and transition stage for one task lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskClassCache {
    /// Process image from which this task inherited its initial semantics.
    pub process: ProcessKey,
    /// Class currently used to choose a Rust pool and time slice.
    pub effective_class: TaskClass,
    /// Whether the class is inherited, semantic, or locally locked.
    pub stage: ClassStage,
    /// Agent-owned generation mirrored into the BPF `task_control` map.
    pub class_generation: u64,
}

impl TaskClassCache {
    /// Creates an inherited entry from a process default.
    pub fn inherited(process: ProcessKey, process_default: ProcessDefaultCache) -> Self {
        Self {
            process,
            effective_class: process_default.default_class,
            stage: ClassStage::Inherited,
            class_generation: process_default.class_generation,
        }
    }

    /// Validates and applies one Agent task-class transition.
    ///
    /// The control plane writes the same generation to BPF before committing
    /// this update. A locked extreme may converge once to conservative
    /// Balanced when later independent evidence conflicts.
    pub fn apply(
        &mut self,
        task: TaskKey,
        update: TaskClassUpdate,
    ) -> Result<(), ClassUpdateError> {
        if self.process != update.process {
            return Err(ClassUpdateError::ProcessIdentity { task });
        }
        let resolves_locked_conflict = self.stage == ClassStage::Locked
            && self.effective_class != TaskClass::Balanced
            && update.stage == ClassStage::Locked
            && update.class == TaskClass::Balanced;
        if self.stage == ClassStage::Locked && !resolves_locked_conflict {
            return Err(ClassUpdateError::AlreadyLocked { task });
        }
        if update.class_generation <= self.class_generation {
            return Err(ClassUpdateError::StaleGeneration {
                task,
                current: self.class_generation,
                received: update.class_generation,
            });
        }
        if !resolves_locked_conflict && !valid_stage_transition(self.stage, update.stage) {
            return Err(ClassUpdateError::InvalidStage {
                task,
                from: self.stage,
                to: update.stage,
            });
        }

        self.effective_class = update.class;
        self.stage = update.stage;
        self.class_generation = update.class_generation;
        Ok(())
    }
}

/// Agent command changing the process default for one exact process image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessClassUpdate {
    /// Stable process image receiving the update.
    pub process: ProcessKey,
    /// New default class for inherited tasks.
    pub class: TaskClass,
    /// Strictly increasing process classification generation.
    pub class_generation: u64,
}

/// Agent command changing one exact task lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskClassUpdate {
    /// Stable task lifetime receiving the update.
    pub task: TaskKey,
    /// Stable owning process image, checked independently of TID.
    pub process: ProcessKey,
    /// New effective task class.
    pub class: TaskClass,
    /// Semantic or final locked stage.
    pub stage: ClassStage,
    /// Strictly increasing task classification generation.
    pub class_generation: u64,
}

/// Returns whether a classification-stage transition follows the one-correction rule.
fn valid_stage_transition(from: ClassStage, to: ClassStage) -> bool {
    matches!(
        (from, to),
        (ClassStage::Inherited, ClassStage::Semantic)
            | (ClassStage::Inherited, ClassStage::Locked)
            | (ClassStage::Semantic, ClassStage::Locked)
    )
}

/// Classification update rejected before it can affect a pool or BPF command.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ClassUpdateError {
    /// Task update names a different process lifetime or exec generation.
    #[error("task {task:?} does not belong to the supplied process identity")]
    ProcessIdentity {
        /// Task whose process identity did not match.
        task: TaskKey,
    },
    /// Locked tasks reject changes except one conservative conflict resolution.
    #[error("task {task:?} classification is already locked")]
    AlreadyLocked {
        /// Permanently classified task.
        task: TaskKey,
    },
    /// Delayed or duplicate generation would roll state backward.
    #[error("task {task:?} received stale generation {received}; current is {current}")]
    StaleGeneration {
        /// Task receiving the delayed update.
        task: TaskKey,
        /// Scheduler's current generation.
        current: u64,
        /// Generation carried by the update.
        received: u64,
    },
    /// Update attempted to skip outside the allowed stage graph.
    #[error("task {task:?} cannot transition classification from {from:?} to {to:?}")]
    InvalidStage {
        /// Task receiving the invalid transition.
        task: TaskKey,
        /// Current transition stage.
        from: ClassStage,
        /// Requested transition stage.
        to: ClassStage,
    },
}

#[cfg(test)]
mod tests {
    use super::{ClassUpdateError, ProcessDefaultCache, TaskClassCache, TaskClassUpdate};
    use crate::identity::{ClassStage, ProcessKey, TaskClass, TaskKey};

    /// A locked extreme can resolve one late conflict only toward Balanced.
    #[test]
    fn enforces_one_correction_transition() {
        let process = ProcessKey::new(10, 20, 1).unwrap();
        let task = TaskKey::new(11, 30).unwrap();
        let mut cache = TaskClassCache::inherited(process, ProcessDefaultCache::default());

        cache
            .apply(
                task,
                TaskClassUpdate {
                    task,
                    process,
                    class: TaskClass::Latency,
                    stage: ClassStage::Semantic,
                    class_generation: 1,
                },
            )
            .unwrap();
        cache
            .apply(
                task,
                TaskClassUpdate {
                    task,
                    process,
                    class: TaskClass::Throughput,
                    stage: ClassStage::Locked,
                    class_generation: 2,
                },
            )
            .unwrap();

        assert_eq!(cache.effective_class, TaskClass::Throughput);
        cache
            .apply(
                task,
                TaskClassUpdate {
                    task,
                    process,
                    class: TaskClass::Balanced,
                    stage: ClassStage::Locked,
                    class_generation: 3,
                },
            )
            .unwrap();
        assert_eq!(cache.effective_class, TaskClass::Balanced);
        assert!(matches!(
            cache.apply(
                task,
                TaskClassUpdate {
                    task,
                    process,
                    class: TaskClass::Latency,
                    stage: ClassStage::Locked,
                    class_generation: 4,
                }
            ),
            Err(ClassUpdateError::AlreadyLocked { .. })
        ));
    }
}
