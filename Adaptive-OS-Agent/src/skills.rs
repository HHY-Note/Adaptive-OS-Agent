// SPDX-License-Identifier: Apache-2.0

//! Standard classification capabilities exposed by the Agent library.
//!
//! Skills only turn bounded inputs into identity-bound proposals. They never
//! mutate the classification registry or communicate with the scheduler.

use anyhow::Result;

use crate::behavior::{classify_window, BehaviorWindow};
use crate::identity::{ProcessKey, TaskClass, TaskKey};
use crate::metadata::ProcessMetadata;
use crate::process_classifier::classify_process_batch;
use crate::thread_classifier::classify_thread_batch;

pub use crate::deepseek::DeepSeekClient;
pub use crate::process_classifier::ProcessClassificationProposal;
pub use crate::thread_classifier::{ThreadClassificationInput, ThreadClassificationProposal};

/// Identity-bound behavior proposal eligible for one contrary-window vote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BehaviorClassificationProposal {
    /// Stable task lifetime observed by the scheduler.
    pub task: TaskKey,
    /// Stable owning process image observed in the same window.
    pub process: ProcessKey,
    /// Class suggested by measurable scheduling facts.
    pub class: TaskClass,
}

/// Produces one-time process semantic proposals from bounded `/proc` metadata.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessSemanticClassificationSkill;

impl ProcessSemanticClassificationSkill {
    /// Calls the semantic client without mutating Agent or scheduler state.
    pub fn propose(
        &self,
        client: &DeepSeekClient,
        processes: &[ProcessMetadata],
    ) -> Result<Vec<ProcessClassificationProposal>> {
        classify_process_batch(client, processes)
    }
}

/// Produces one-time thread semantic proposals within one process context.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadSemanticClassificationSkill;

impl ThreadSemanticClassificationSkill {
    /// Calls the semantic client for one already bounded thread chunk.
    pub fn propose(
        &self,
        client: &DeepSeekClient,
        process: ProcessKey,
        process_metadata: &ProcessMetadata,
        threads: &[ThreadClassificationInput],
    ) -> Result<Vec<ThreadClassificationProposal>> {
        classify_thread_batch(client, process, process_metadata, threads)
    }
}

/// Produces deterministic local proposals from scheduler behavior windows.
#[derive(Clone, Copy, Debug, Default)]
pub struct BehaviorClassificationSkill;

impl BehaviorClassificationSkill {
    /// Returns only strong, identity-bound evidence suitable for Registry voting.
    pub fn propose(&self, window: BehaviorWindow) -> Option<BehaviorClassificationProposal> {
        let class = classify_window(window)?;
        Some(BehaviorClassificationProposal {
            task: window.task,
            process: window.process,
            class,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BehaviorClassificationSkill;
    use crate::behavior::{BehaviorWindow, WindowQuality};
    use crate::identity::{ProcessKey, TaskClass, TaskKey};

    fn behavior_window(quality: WindowQuality) -> BehaviorWindow {
        BehaviorWindow {
            task: TaskKey {
                tid: 1,
                task_cookie: 2,
            },
            process: ProcessKey {
                tgid: 1,
                process_cookie: 3,
                exec_generation: 1,
            },
            window_sequence: 1,
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
            quality,
        }
    }

    /// Behavior proposals retain both scheduler identities for Registry checks.
    #[test]
    fn behavior_proposal_is_identity_bound() {
        let window = behavior_window(WindowQuality::Good);
        let proposal = BehaviorClassificationSkill.propose(window).unwrap();

        assert_eq!(proposal.task, window.task);
        assert_eq!(proposal.process, window.process);
        assert_eq!(proposal.class, TaskClass::Throughput);
    }

    /// Invalid windows cannot produce proposals.
    #[test]
    fn behavior_skill_rejects_bad_windows() {
        assert_eq!(
            BehaviorClassificationSkill.propose(behavior_window(WindowQuality::Bad)),
            None
        );
    }
}
