// SPDX-License-Identifier: GPL-2.0-only

use std::time::Duration;

use thiserror::Error;

/// Nanoseconds in one millisecond, used for readable default construction.
pub const NSEC_PER_MSEC: u64 = 1_000_000;
const THROUGHPUT_PREEMPTION_LOCALITY_CAP_NS: u64 = NSEC_PER_MSEC;

/// Validated scheduler policy and data-plane limits.
///
/// Values are immutable after BPF attach. Keeping the slice and queue limits in
/// one object ensures the Rust control plane and BPF data plane receive the
/// same immutable bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    /// Initial and maximum latency-class request.
    pub latency_slice_ns: u64,
    /// Initial and maximum balanced-class request.
    pub balanced_slice_ns: u64,
    /// Initial throughput-class request; uncontended epochs grow up to the
    /// global bounded maximum.
    pub throughput_slice_ns: u64,
    /// Smallest time slice BPF may accept.
    pub min_slice_ns: u64,
    /// Largest time slice BPF may accept.
    pub max_slice_ns: u64,
    /// CPU-time share reserved for latency service while other work is queued.
    pub latency_budget_percent: u32,
    /// Maximum sleep between scheduler event-queue polls.
    pub poll_interval: Duration,
    /// Maximum live task identities retained by the userspace engine.
    pub max_tasks: usize,
    /// Bounded Agent/control-thread channel capacity.
    pub control_queue_capacity: usize,
    /// Maximum JSON envelope bytes accepted on the local socket.
    pub max_control_frame_bytes: usize,
    /// Maximum process plus task rows accepted in one Registry batch.
    pub max_snapshot_items: usize,
    /// Successful idempotency responses retained for replay.
    pub response_cache_capacity: usize,
    /// Time an absent Agent is tolerated before controlled detach.
    pub agent_exit_grace: Duration,
}

impl Default for SchedulerConfig {
    /// Builds 0.25/4/8 ms request ceilings and bounded control defaults.
    fn default() -> Self {
        Self {
            latency_slice_ns: 250_000,
            balanced_slice_ns: 4 * NSEC_PER_MSEC,
            throughput_slice_ns: 8 * NSEC_PER_MSEC,
            min_slice_ns: 250_000,
            max_slice_ns: 64 * NSEC_PER_MSEC,
            latency_budget_percent: 20,
            poll_interval: Duration::from_millis(4),
            max_tasks: 65_536,
            control_queue_capacity: 1_024,
            max_control_frame_bytes: 1024 * 1024,
            max_snapshot_items: 256,
            response_cache_capacity: 4_096,
            agent_exit_grace: Duration::from_secs(2),
        }
    }
}

impl SchedulerConfig {
    /// Verifies cross-field constraints before any BPF object is opened.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.min_slice_ns == 0 || self.min_slice_ns > self.max_slice_ns {
            return Err(ConfigError::SliceBounds);
        }

        for (name, value) in [
            ("latency", self.latency_slice_ns),
            ("balanced", self.balanced_slice_ns),
            ("throughput", self.throughput_slice_ns),
        ] {
            if !(self.min_slice_ns..=self.max_slice_ns).contains(&value) {
                return Err(ConfigError::ClassSlice { class: name, value });
            }
        }

        if !(1..=100).contains(&self.latency_budget_percent) {
            return Err(ConfigError::LatencyAdmission);
        }
        if self.poll_interval.is_zero() {
            return Err(ConfigError::Timing);
        }
        if !(1..=65_536).contains(&self.max_tasks) {
            return Err(ConfigError::RuntimeCapacity);
        }
        if self.control_queue_capacity == 0
            || !(256..=u32::MAX as usize).contains(&self.max_control_frame_bytes)
            || self.max_snapshot_items == 0
            || self.response_cache_capacity == 0
        {
            return Err(ConfigError::ControlCapacity);
        }
        if self.agent_exit_grace.is_zero() {
            return Err(ConfigError::AgentGrace);
        }

        Ok(())
    }

    /// Returns the shortest preemption cadence that can admit one full
    /// Latency request without exceeding the configured CPU share.
    ///
    /// This is deliberately derived from immutable loader configuration so
    /// the BPF lease fallback and the userspace policy use the same bound.
    pub fn latency_preemption_interval_ns(&self) -> u64 {
        let budget = u128::from(self.latency_budget_percent.max(1));
        let numerator = u128::from(self.latency_slice_ns).saturating_mul(100);
        let interval = numerator.saturating_add(budget - 1) / budget;

        interval.min(u128::from(u64::MAX)) as u64
    }

    /// Returns the minimum uninterrupted service given to a Throughput victim.
    ///
    /// Gives a Throughput victim one eighth of its base request, capped at
    /// one millisecond, before Latency may interrupt it. Credit/debt and the
    /// separate cadence still bound how often Latency can displace work; this
    /// floor protects cache locality from repeated 1-2 ms fragmentation.
    pub fn throughput_preemption_min_runtime_ns(&self) -> u64 {
        let locality_cap = THROUGHPUT_PREEMPTION_LOCALITY_CAP_NS
            .max(self.latency_slice_ns)
            .min(self.throughput_slice_ns);

        self.throughput_slice_ns
            .saturating_div(8)
            .max(self.latency_slice_ns)
            .min(locality_cap)
    }

    /// Returns the configured initial and maximum request for a class.
    pub const fn slice_for(&self, class: crate::identity::TaskClass) -> u64 {
        match class {
            crate::identity::TaskClass::Latency => self.latency_slice_ns,
            crate::identity::TaskClass::Balanced => self.balanced_slice_ns,
            crate::identity::TaskClass::Throughput => self.throughput_slice_ns,
        }
    }
}

/// Actionable configuration validation failures.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    /// Minimum and maximum slice bounds are inconsistent.
    #[error("min_slice_ns must be non-zero and no larger than max_slice_ns")]
    SliceBounds,
    /// A class slice falls outside the globally accepted range.
    #[error("{class} slice {value} ns is outside the configured slice bounds")]
    ClassSlice {
        /// Name of the invalid class.
        class: &'static str,
        /// Invalid slice value in nanoseconds.
        value: u64,
    },
    /// Latency admission needs a meaningful target and bounded share.
    #[error("preemption runtime must be non-zero and admission percentages must be in 1..=100")]
    LatencyAdmission,
    /// Event polling must make progress without a busy loop.
    #[error("poll_interval must be non-zero")]
    Timing,
    /// Runtime task identity capacity is inconsistent with the BPF map.
    #[error("max_tasks must fit the BPF task-control map")]
    RuntimeCapacity,
    /// Control transport and replay bounds are invalid.
    #[error("control queue/frame/snapshot/response-cache limits are invalid")]
    ControlCapacity,
    /// Agent exit detection must allow a non-zero grace interval.
    #[error("agent_exit_grace must be non-zero")]
    AgentGrace,
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, SchedulerConfig};

    /// The shipped defaults must always be internally consistent.
    #[test]
    fn defaults_validate() {
        assert_eq!(SchedulerConfig::default().validate(), Ok(()));
    }

    /// Class slices are constrained by the same bounds used in BPF.
    #[test]
    fn rejects_slice_outside_global_bounds() {
        let mut config = SchedulerConfig::default();
        config.latency_slice_ns = config.min_slice_ns - 1;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ClassSlice {
                class: "latency",
                ..
            })
        ));
    }

    #[test]
    fn latency_budget_is_explicit_and_bounded() {
        let config = SchedulerConfig::default();
        assert_eq!(config.latency_budget_percent, 20);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn latency_preemption_interval_rounds_up_without_overflowing_u64() {
        let mut config = SchedulerConfig {
            latency_budget_percent: 33,
            ..SchedulerConfig::default()
        };
        assert_eq!(config.latency_preemption_interval_ns(), 757_576);

        config.latency_budget_percent = 1;
        assert_eq!(config.latency_preemption_interval_ns(), 25_000_000);

        config.latency_budget_percent = 100;
        assert_eq!(config.latency_preemption_interval_ns(), 250_000);
    }

    #[test]
    fn throughput_preemption_runtime_is_bounded_by_epoch_and_locality_cap() {
        let mut config = SchedulerConfig::default();
        assert_eq!(config.throughput_preemption_min_runtime_ns(), 1_000_000);

        config.latency_budget_percent = 100;
        assert_eq!(config.throughput_preemption_min_runtime_ns(), 1_000_000);

        config.latency_budget_percent = 1;
        assert_eq!(config.throughput_preemption_min_runtime_ns(), 1_000_000);

        config.throughput_slice_ns = 16_000_000;
        config.latency_budget_percent = 20;
        assert_eq!(config.throughput_preemption_min_runtime_ns(), 1_000_000);

        config.throughput_slice_ns = 250_000;
        config.latency_slice_ns = 1_000_000;
        assert_eq!(config.throughput_preemption_min_runtime_ns(), 250_000);
    }
}
