// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use crate::deepseek::{DeepSeekClient, PromptItem, SemanticResult};
use crate::identity::{ProcessKey, TaskClass, TaskKey};
use crate::metadata::{redact_command, ProcessMetadata, ThreadMetadata};

/// Stable task plus its current comm feature for one TGID batch.
#[derive(Clone, Debug)]
pub struct ThreadClassificationInput {
    /// Scheduler-supplied task lifetime.
    pub task: TaskKey,
    /// Current proc comm, which may change and is never used as identity.
    pub metadata: ThreadMetadata,
}

/// Thread semantic proposal mapped back to stable task identity.
#[derive(Clone, Debug, PartialEq)]
pub struct ThreadClassificationProposal {
    /// Exact process image present when the semantic request was created.
    pub process: ProcessKey,
    /// Exact task lifetime classified.
    pub task: TaskKey,
    /// Semantic class or None for Unknown/failure.
    pub class: Option<TaskClass>,
    /// Validated model confidence.
    pub confidence: f32,
}

/// Thread feature projection intentionally limited to comm and process context.
#[derive(Clone, Debug, Serialize)]
struct ThreadFeatures<'a> {
    /// Thread comm semantic feature.
    comm: &'a str,
}

/// Process context excludes UID and identity fields and redacts argv secrets.
#[derive(Clone, Debug, Serialize)]
struct ProcessContext<'a> {
    /// Short executable name.
    comm: &'a str,
    /// Bounded, credential-redacted argv.
    command: Vec<String>,
    /// Executable path when proc permissions allow it.
    executable: &'a Option<String>,
    /// Service/container placement hints.
    cgroups: &'a [String],
}

/// Classifies one bounded chunk of eligible threads from a long-lived process.
pub(crate) fn classify_thread_batch(
    client: &DeepSeekClient,
    process: ProcessKey,
    process_metadata: &ProcessMetadata,
    threads: &[ThreadClassificationInput],
) -> Result<Vec<ThreadClassificationProposal>> {
    let context = serde_json::to_string(&ProcessContext {
        comm: &process_metadata.comm,
        command: redact_command(&process_metadata.command),
        executable: &process_metadata.executable,
        cgroups: &process_metadata.cgroups,
    })?;
    let items: Vec<_> = threads
        .iter()
        .enumerate()
        .map(|(index, thread)| PromptItem {
            id: thread_id(index),
            features: ThreadFeatures {
                comm: &thread.metadata.comm,
            },
        })
        .collect();
    let results = client.classify("thread", &context, &items)?;
    Ok(map_thread_results(process, threads, results))
}

/// Creates a request-local ID; real task identities never leave Agent memory.
fn thread_id(index: usize) -> String {
    format!("t{index}")
}

/// Maps validated opaque IDs back to stable task lifetimes.
fn map_thread_results(
    process: ProcessKey,
    threads: &[ThreadClassificationInput],
    results: Vec<SemanticResult>,
) -> Vec<ThreadClassificationProposal> {
    let by_id: HashMap<_, _> = results
        .into_iter()
        .map(|result| (result.id.clone(), result))
        .collect();
    threads
        .iter()
        .enumerate()
        .filter_map(|(index, thread)| {
            let result = by_id.get(&thread_id(index))?;
            Some(ThreadClassificationProposal {
                process,
                task: thread.task,
                class: result.class,
                confidence: result.confidence,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_reordered_short_ids_to_task_lifetimes() {
        let process = ProcessKey {
            tgid: 300,
            process_cookie: 33,
            exec_generation: 3,
        };
        let threads = vec![
            ThreadClassificationInput {
                task: TaskKey {
                    tid: 301,
                    task_cookie: 3010,
                },
                metadata: ThreadMetadata {
                    tid: 301,
                    comm: "request-loop".to_string(),
                },
            },
            ThreadClassificationInput {
                task: TaskKey {
                    tid: 302,
                    task_cookie: 3020,
                },
                metadata: ThreadMetadata {
                    tid: 302,
                    comm: "batch-worker".to_string(),
                },
            },
        ];
        let results = vec![
            SemanticResult {
                id: "t1".to_string(),
                class: Some(TaskClass::Throughput),
                confidence: 0.94,
            },
            SemanticResult {
                id: "t0".to_string(),
                class: Some(TaskClass::Latency),
                confidence: 0.88,
            },
        ];

        let mapped = map_thread_results(process, &threads, results);

        assert_eq!(mapped.len(), 2);
        assert_eq!(mapped[0].process, process);
        assert_eq!(mapped[0].task, threads[0].task);
        assert_eq!(mapped[0].class, Some(TaskClass::Latency));
        assert_eq!(mapped[1].task, threads[1].task);
        assert_eq!(mapped[1].class, Some(TaskClass::Throughput));
    }
}
