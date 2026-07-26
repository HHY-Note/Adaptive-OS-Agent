// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use crate::deepseek::{DeepSeekClient, PromptItem, SemanticResult};
use crate::identity::TaskClass;
use crate::metadata::{redact_command, ProcessInstanceKey, ProcessMetadata};

/// Conservative process decision available without remote inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalProcessClassification {
    pub(crate) class: TaskClass,
    pub(crate) confidence_per_mille: u16,
}

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

/// Recognizes only explicit scheduling objectives that do not depend on program names.
///
/// Returning `None` is intentional: ambiguous metadata remains Balanced until
/// behavior or remote semantics supplies stronger evidence.
pub(crate) fn classify_process_metadata(
    process: &ProcessMetadata,
) -> Option<LocalProcessClassification> {
    let tokens = metadata_tokens(process);
    if tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "--latency" | "--deadline" | "--response-time" | "--slo"
        ) || token.starts_with("--latency-")
            || token.starts_with("--deadline-")
            || token.starts_with("--response-time-")
            || token.starts_with("--slo-")
    }) {
        return Some(LocalProcessClassification {
            class: TaskClass::Latency,
            confidence_per_mille: 950,
        });
    }

    let has_rate_control = command_has_option(
        &process.command,
        &[
            "--fixed-rate",
            "--qps",
            "--rate",
            "--rate-limit",
            "--rate-limiting",
            "--requests-per-second",
            "--rps",
            "--transactions-per-second",
        ],
    );
    let has_tail_latency_report = command_has_option(
        &process.command,
        &[
            "--hdr-file",
            "--hdr-file-prefix",
            "--latency-percentile",
            "--percentile",
            "--percentiles",
            "--print-percentiles",
        ],
    );
    if has_rate_control && has_tail_latency_report {
        return Some(LocalProcessClassification {
            class: TaskClass::Latency,
            confidence_per_mille: 950,
        });
    }

    if tokens
        .iter()
        .any(|token| matches!(token.as_str(), "--throughput" | "--throughput-mode"))
    {
        return Some(LocalProcessClassification {
            class: TaskClass::Throughput,
            confidence_per_mille: 950,
        });
    }

    let has_remote_endpoint = process.command.iter().any(|argument| {
        let argument = argument.to_ascii_lowercase();
        argument.contains("://")
            || argument.starts_with("--endpoint=")
            || argument.starts_with("--endpoints=")
            || argument.starts_with("--server=")
    });
    let has_benchmark_operation = command_has_option(
        &process.command,
        &["--bench", "--benchmark", "--benchmarks"],
    ) || contains_any(&tokens, &["bench", "benchmark"]);
    let has_work_budget = command_has_option(
        &process.command,
        &[
            "--count",
            "--duration",
            "--iterations",
            "--jobs",
            "--num",
            "--operations",
            "--threads",
        ],
    );
    if !has_remote_endpoint && has_benchmark_operation && has_work_budget {
        return Some(LocalProcessClassification {
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        });
    }

    let has_remote_benchmark_operation = contains_any(&tokens, &["bench"])
        || (contains_any(&tokens, &["check"]) && contains_any(&tokens, &["perf"]));
    if has_remote_endpoint && has_remote_benchmark_operation {
        return Some(LocalProcessClassification {
            class: TaskClass::Balanced,
            confidence_per_mille: 900,
        });
    }

    None
}

fn metadata_tokens(process: &ProcessMetadata) -> Vec<String> {
    let mut values = Vec::with_capacity(process.command.len() + 2);
    values.push(process.comm.as_str());
    if let Some(executable) = process.executable.as_deref() {
        values.push(executable);
    }
    values.extend(process.command.iter().map(String::as_str));
    values
        .into_iter()
        .flat_map(|value| {
            value.split(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '+'))
            })
        })
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn contains_any(tokens: &[String], candidates: &[&str]) -> bool {
    tokens
        .iter()
        .any(|token| candidates.contains(&token.as_str()))
}

fn command_has_option(command: &[String], candidates: &[&str]) -> bool {
    command.iter().any(|argument| {
        let option = argument
            .split_once('=')
            .map_or(argument.as_str(), |(option, _)| option)
            .to_ascii_lowercase();
        candidates.contains(&option.as_str())
    })
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

    #[test]
    fn local_metadata_recognizes_explicit_latency_objective() {
        let mut metadata = process(101, 1_001);
        metadata.command = vec![
            "/usr/bin/time".into(),
            "/usr/bin/request-client".into(),
            "--latency-limit=20".into(),
        ];

        assert_eq!(
            classify_process_metadata(&metadata),
            Some(LocalProcessClassification {
                class: TaskClass::Latency,
                confidence_per_mille: 950,
            })
        );
    }

    #[test]
    fn local_metadata_recognizes_explicit_throughput_objective_inside_a_wrapper() {
        let mut metadata = process(102, 1_002);
        metadata.comm = "time".into();
        metadata.executable = Some("/usr/bin/time".into());
        metadata.command = vec![
            "/usr/bin/time".into(),
            "bash".into(),
            "-c".into(),
            "job-runner --throughput --input data.bin".into(),
        ];

        assert_eq!(
            classify_process_metadata(&metadata),
            Some(LocalProcessClassification {
                class: TaskClass::Throughput,
                confidence_per_mille: 950,
            })
        );
    }

    #[test]
    fn bounded_local_benchmark_is_a_throughput_objective() {
        let mut metadata = process(103, 1_003);
        metadata.comm = "time".into();
        metadata.executable = Some("/usr/bin/time".into());
        metadata.command = vec![
            "/usr/bin/time".into(),
            "/opt/workloads/local-runner".into(),
            "--benchmarks=readwrite".into(),
            "--duration=60".into(),
            "--threads=4".into(),
        ];

        assert_eq!(
            classify_process_metadata(&metadata),
            Some(LocalProcessClassification {
                class: TaskClass::Throughput,
                confidence_per_mille: 900,
            })
        );
    }

    #[test]
    fn local_benchmark_without_a_work_budget_remains_ambiguous() {
        let mut metadata = process(104, 1_004);
        metadata.command = vec![
            "/opt/workloads/local-runner".into(),
            "--benchmark=single-request".into(),
        ];

        assert_eq!(classify_process_metadata(&metadata), None);
    }

    #[test]
    fn remote_benchmark_without_a_specialized_objective_is_balanced() {
        let mut metadata = process(105, 1_005);
        metadata.command = vec![
            "/usr/bin/request-tool".into(),
            "--endpoints=http://127.0.0.1:2379".into(),
            "check".into(),
            "perf".into(),
        ];

        assert_eq!(
            classify_process_metadata(&metadata),
            Some(LocalProcessClassification {
                class: TaskClass::Balanced,
                confidence_per_mille: 900,
            })
        );
    }

    #[test]
    fn remote_message_benchmark_is_balanced_without_an_slo() {
        let mut metadata = process(104, 1_004);
        metadata.command = vec![
            "/usr/bin/message-tool".into(),
            "--server=protocol://127.0.0.1:4222".into(),
            "bench".into(),
            "pub".into(),
            "subject".into(),
        ];

        assert_eq!(
            classify_process_metadata(&metadata),
            Some(LocalProcessClassification {
                class: TaskClass::Balanced,
                confidence_per_mille: 900,
            })
        );
    }

    #[test]
    fn local_metadata_does_not_treat_tool_name_as_benchmark_operation() {
        let mut metadata = process(105, 1_005);
        metadata.comm = "network_benchmark".into();
        metadata.executable = Some("/usr/bin/network_benchmark".into());
        metadata.command = vec![
            "/usr/bin/time".into(),
            "/usr/bin/network_benchmark".into(),
            "--server=127.0.0.1".into(),
            "--json-out-file=/run/benchmark/performance/result.json".into(),
        ];

        assert_eq!(classify_process_metadata(&metadata), None);
    }

    #[test]
    fn local_metadata_recognizes_paced_tail_latency_objective() {
        let mut metadata = process(106, 1_006);
        metadata.command = vec![
            "/usr/bin/request-client".into(),
            "--server=127.0.0.1".into(),
            "--rate-limiting=2000".into(),
            "--print-percentiles=50,90,99,99.9".into(),
        ];

        assert_eq!(
            classify_process_metadata(&metadata),
            Some(LocalProcessClassification {
                class: TaskClass::Latency,
                confidence_per_mille: 950,
            })
        );
    }

    #[test]
    fn local_metadata_requires_both_pacing_and_tail_latency_evidence() {
        let mut metadata = process(107, 1_007);
        metadata.command = vec![
            "/usr/bin/request-client".into(),
            "--server=127.0.0.1".into(),
            "--rate-limiting=2000".into(),
        ];
        assert_eq!(classify_process_metadata(&metadata), None);

        metadata.command = vec![
            "/usr/bin/request-client".into(),
            "--server=127.0.0.1".into(),
            "--print-percentiles=50,90,99,99.9".into(),
        ];
        assert_eq!(classify_process_metadata(&metadata), None);
    }
}
