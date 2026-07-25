// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use crate::deepseek::{DeepSeekClient, PromptItem, SemanticResult};
use crate::identity::TaskClass;
use crate::metadata::{redact_command, ProcessInstanceKey, ProcessMetadata};

/// Bounded process feature projection sent to the remote model.
#[derive(Clone, Debug, Serialize)]
struct ProcessFeatures<'a> {
    /// Short comm feature.
    comm: &'a str,
    /// Bounded argv copied from proc.
    command: Vec<String>,
    /// Resolved executable path when visible.
    executable: &'a Option<String>,
    /// Cgroup paths providing service context.
    cgroups: &'a [String],
}

/// Process semantic proposal mapped back to the pre-cookie proc identity.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessClassificationProposal {
    /// Process lifetime used to reject PID reuse.
    pub instance: ProcessInstanceKey,
    /// Semantic class or None for Unknown/failure.
    pub class: Option<TaskClass>,
    /// Validated model confidence.
    pub confidence: f32,
}

/// Classifies many startup/new processes in a single bounded remote request.
pub(crate) fn classify_process_batch(
    client: &DeepSeekClient,
    processes: &[ProcessMetadata],
) -> Result<Vec<ProcessClassificationProposal>> {
    let items: Vec<_> = processes
        .iter()
        .enumerate()
        .map(|(index, process)| PromptItem {
            id: process_id(index),
            features: ProcessFeatures {
                comm: &process.comm,
                command: redact_command(&process.command),
                executable: &process.executable,
                cgroups: &process.cgroups,
            },
        })
        .collect();
    let results = client.classify("process", "", &items)?;
    Ok(map_process_results(processes, results))
}

/// Creates the opaque ID that a process result must echo exactly.
fn process_id(index: usize) -> String {
    format!("p{index}")
}

/// Maps validated opaque IDs back to process instances.
fn map_process_results(
    processes: &[ProcessMetadata],
    results: Vec<SemanticResult>,
) -> Vec<ProcessClassificationProposal> {
    let by_id: HashMap<_, _> = results
        .into_iter()
        .map(|result| (result.id.clone(), result))
        .collect();
    processes
        .iter()
        .enumerate()
        .filter_map(|(index, process)| {
            let result = by_id.get(&process_id(index))?;
            Some(ProcessClassificationProposal {
                instance: process.instance,
                class: result.class,
                confidence: result.confidence,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(tgid: u32, start_time_ticks: u64) -> ProcessMetadata {
        ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid,
                start_time_ticks,
            },
            parent: None,
            comm: format!("process-{tgid}"),
            command: vec![format!("/usr/bin/process-{tgid}")],
            executable: Some(format!("/usr/bin/process-{tgid}")),
            cgroups: vec!["/test.slice".to_string()],
            uid: Some(1000),
        }
    }

    #[test]
    fn maps_reordered_short_ids_to_process_instances() {
        let processes = vec![process(101, 1_001), process(202, 2_002)];
        let results = vec![
            SemanticResult {
                id: "p1".to_string(),
                class: Some(TaskClass::Throughput),
                confidence: 0.91,
            },
            SemanticResult {
                id: "p0".to_string(),
                class: Some(TaskClass::Latency),
                confidence: 0.82,
            },
        ];

        let mapped = map_process_results(&processes, results);

        assert_eq!(mapped.len(), 2);
        assert_eq!(mapped[0].instance, processes[0].instance);
        assert_eq!(mapped[0].class, Some(TaskClass::Latency));
        assert_eq!(mapped[1].instance, processes[1].instance);
        assert_eq!(mapped[1].class, Some(TaskClass::Throughput));
    }
}
