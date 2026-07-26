// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Complete validated Agent configuration.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Scheduler Unix socket; no shared protocol crate is required.
    pub scheduler_socket: String,
    /// Read-only standardized Tool Unix socket.
    pub tool_socket: String,
    /// Low-frequency `/proc` reconciliation period.
    pub reconcile_interval_secs: u64,
    /// Scheduler behavior-report period expected by Agent.
    pub behavior_window_secs: u64,
    /// Remote DeepSeek request settings.
    pub deepseek: DeepSeekConfig,
    /// Long-lived task and one-correction thresholds.
    pub classification: ClassificationConfig,
}

impl Default for AgentConfig {
    /// Builds conservative defaults matching the current design document.
    fn default() -> Self {
        Self {
            scheduler_socket: "/run/scx_adaptive.sock".into(),
            tool_socket: "/run/adaptive-os-agent-tools.sock".into(),
            reconcile_interval_secs: 10,
            behavior_window_secs: 1,
            deepseek: DeepSeekConfig::default(),
            classification: ClassificationConfig::default(),
        }
    }
}

impl AgentConfig {
    /// Loads TOML when supplied, otherwise returns validated defaults.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config = match path {
            Some(path) => {
                let text = fs::read_to_string(path)
                    .with_context(|| format!("read Agent config {}", path.display()))?;
                toml::from_str(&text)
                    .with_context(|| format!("parse Agent config {}", path.display()))?
            }
            None => Self::default(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates socket paths, timings, URL scheme, and confidence ranges.
    pub fn validate(&self) -> Result<()> {
        if self.scheduler_socket.is_empty() || self.tool_socket.is_empty() {
            anyhow::bail!("scheduler_socket and tool_socket must not be empty");
        }
        if self.scheduler_socket == self.tool_socket {
            anyhow::bail!("scheduler_socket and tool_socket must differ");
        }
        if self.reconcile_interval_secs == 0 || self.behavior_window_secs == 0 {
            anyhow::bail!("reconcile and behavior intervals must be non-zero");
        }
        self.deepseek.validate()?;
        self.classification.validate()?;
        Ok(())
    }
}

/// DeepSeek HTTP and batching configuration.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DeepSeekConfig {
    /// API origin without a trailing slash requirement.
    pub base_url: String,
    /// Configurable model alias; avoids hard-coding future provider upgrades.
    pub model: String,
    /// Environment variable containing the secret API key.
    pub api_key_env: String,
    /// Optional file containing `api_key_env=...`; used by VM tests and service units.
    pub api_key_file: Option<String>,
    /// Per-request blocking HTTP timeout.
    pub timeout_secs: u64,
    /// TCP/TLS connection timeout, kept shorter than the full response timeout.
    pub connect_timeout_secs: u64,
    /// Maximum process/thread items in one logical LLM request.
    pub batch_size: usize,
    /// Number of retries after the initial request.
    pub max_retries: usize,
    /// Small worker pool bounding simultaneous remote requests.
    pub worker_count: usize,
    /// Minimum confidence accepted as a semantic classification.
    pub min_confidence: f32,
}

impl Default for DeepSeekConfig {
    /// Uses the low-latency model while retaining an explicit override.
    fn default() -> Self {
        Self {
            base_url: "https://api.deepseek.com".into(),
            model: "deepseek-v4-flash".into(),
            api_key_env: "DEEPSEEK_API_KEY".into(),
            api_key_file: None,
            timeout_secs: 45,
            connect_timeout_secs: 5,
            batch_size: 24,
            max_retries: 2,
            worker_count: 2,
            min_confidence: 0.60,
        }
    }
}

impl DeepSeekConfig {
    /// Returns the API key without persisting or logging it.
    pub fn api_key(&self) -> Result<String> {
        if let Ok(value) = env::var(&self.api_key_env) {
            if !value.trim().is_empty() {
                return Ok(value.trim().to_string());
            }
        }
        if let Some(path) = self.api_key_file.as_deref() {
            let text = fs::read_to_string(path)
                .with_context(|| format!("read DeepSeek API key file {path}"))?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((name, value)) = line.split_once('=') else {
                    continue;
                };
                if name.trim() == self.api_key_env {
                    let value = value.trim().trim_matches(['\'', '"']);
                    if !value.is_empty() {
                        return Ok(value.to_string());
                    }
                }
            }
        }
        anyhow::bail!(
            "DeepSeek API key is not set in environment variable {} or configured file",
            self.api_key_env
        )
    }

    /// Checks remote request and bounded-concurrency settings.
    fn validate(&self) -> Result<()> {
        if !self.base_url.starts_with("https://") {
            anyhow::bail!("deepseek.base_url must use https");
        }
        if self.model.trim().is_empty() || self.api_key_env.trim().is_empty() {
            anyhow::bail!("DeepSeek model and API-key environment name must not be empty");
        }
        if self
            .api_key_file
            .as_deref()
            .is_some_and(|path| path.trim().is_empty())
        {
            anyhow::bail!("DeepSeek API-key file path must not be empty when configured");
        }
        if self.timeout_secs == 0
            || self.connect_timeout_secs == 0
            || self.batch_size == 0
            || self.worker_count == 0
        {
            anyhow::bail!(
                "DeepSeek response/connect timeouts, batch_size, and worker_count must be non-zero"
            );
        }
        if self.connect_timeout_secs > self.timeout_secs {
            anyhow::bail!("DeepSeek connect timeout must not exceed the response timeout");
        }
        if self.batch_size > 128 || self.worker_count > 8 {
            anyhow::bail!("DeepSeek batch_size must be <=128 and worker_count <=8");
        }
        if !self.min_confidence.is_finite() || !(0.0..=1.0).contains(&self.min_confidence) {
            anyhow::bail!("DeepSeek min_confidence must be in 0..=1");
        }
        Ok(())
    }
}

/// Semantic and behavior transition thresholds.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ClassificationConfig {
    /// Minimum scheduler-observed process age before process semantic batching.
    /// Zero submits new processes on the next bounded semantic tick.
    pub process_semantic_min_age_secs: u64,
    /// Minimum process age before thread semantic batching.
    pub process_long_lived_secs: u64,
    /// Minimum task age before thread semantic batching.
    pub task_long_lived_secs: u64,
    /// Confidence that can establish a process objective and resists correction.
    pub high_confidence_threshold: f32,
    /// Contrary good windows required after high-confidence semantics.
    pub high_confidence_correction_windows: u32,
    /// Contrary good windows required after low/unknown semantics.
    pub low_confidence_correction_windows: u32,
    /// Task age at which weak behavior locks the current effective class.
    pub behavior_lock_timeout_secs: u64,
    /// Whether long-lived threads should issue their own remote semantic request.
    pub thread_semantic_enabled: bool,
    /// Minimum eligible tasks in one process before thread semantics add value.
    pub thread_semantic_min_tasks: usize,
}

impl Default for ClassificationConfig {
    /// Uses a short-process filter plus conservative semantic corroboration.
    fn default() -> Self {
        Self {
            process_semantic_min_age_secs: 1,
            process_long_lived_secs: 5,
            task_long_lived_secs: 2,
            high_confidence_threshold: 0.90,
            high_confidence_correction_windows: 5,
            low_confidence_correction_windows: 3,
            behavior_lock_timeout_secs: 30,
            thread_semantic_enabled: true,
            thread_semantic_min_tasks: 2,
        }
    }
}

impl ClassificationConfig {
    /// Validates that a correction always requires multiple good windows.
    fn validate(&self) -> Result<()> {
        if self.process_long_lived_secs == 0
            || self.task_long_lived_secs == 0
            || self.behavior_lock_timeout_secs < 5
        {
            anyhow::bail!(
                "long-lived semantic thresholds must be non-zero and behavior timeout at least 5 s"
            );
        }
        if !(0.0..=1.0).contains(&self.high_confidence_threshold) {
            anyhow::bail!("high_confidence_threshold must be in 0..=1");
        }
        if self.high_confidence_correction_windows < 2 || self.low_confidence_correction_windows < 2
        {
            anyhow::bail!("behavior correction must require at least two windows");
        }
        if !(1..=128).contains(&self.thread_semantic_min_tasks) {
            anyhow::bail!("thread_semantic_min_tasks must be in 1..=128");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::AgentConfig;

    /// Shipped defaults must be runnable once the secret environment exists.
    #[test]
    fn defaults_validate_without_reading_secret() {
        let config = AgentConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.deepseek.model, "deepseek-v4-flash");
        assert_eq!(config.deepseek.api_key_env, "DEEPSEEK_API_KEY");
        assert_eq!(config.deepseek.api_key_file, None);
        assert_eq!(config.deepseek.batch_size, 24);
        assert_eq!(config.deepseek.connect_timeout_secs, 5);
        assert_eq!(config.deepseek.min_confidence, 0.60);
        assert!(config.classification.thread_semantic_enabled);
        assert_eq!(config.classification.thread_semantic_min_tasks, 2);
    }

    #[test]
    fn partial_sections_inherit_validated_defaults() {
        let config: AgentConfig = toml::from_str(
            "[deepseek]\nworker_count = 3\n[classification]\nbehavior_lock_timeout_secs = 20\n",
        )
        .unwrap();
        assert_eq!(config.deepseek.worker_count, 3);
        assert_eq!(config.deepseek.batch_size, 24);
        assert_eq!(config.classification.behavior_lock_timeout_secs, 20);
        assert_eq!(config.classification.process_semantic_min_age_secs, 1);
        assert_eq!(config.classification.high_confidence_threshold, 0.90);
        assert_eq!(config.classification.process_long_lived_secs, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_removed_runtime_limits_section() {
        let result = toml::from_str::<AgentConfig>("[limits]\nregistry_processes = 1\n");
        assert!(result.is_err());
    }

    /// A service or VM may read the ignored secret file without sourcing it.
    #[test]
    fn reads_key_from_configured_env_file() {
        let path = std::env::temp_dir().join(format!(
            "adaptive-agent-key-{}-{}.env",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let mut config = AgentConfig::default();
        config.deepseek.api_key_env = "DEEPSEEK_TEST_FILE_KEY".into();
        config.deepseek.api_key_file = Some(path.to_string_lossy().into_owned());
        fs::write(&path, "DEEPSEEK_TEST_FILE_KEY='test-key'\n").unwrap();
        assert_eq!(config.deepseek.api_key().unwrap(), "test-key");
        fs::remove_file(path).unwrap();
    }
}
