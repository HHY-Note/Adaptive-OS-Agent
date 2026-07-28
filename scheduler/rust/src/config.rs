// SPDX-License-Identifier: GPL-2.0-only

use std::time::Duration;

use thiserror::Error;

/// Nanoseconds in one millisecond, used for readable default construction.
pub const NSEC_PER_MSEC: u64 = 1_000_000;

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
    /// Minimum victim runtime before an SLO dispatch may preempt it.
    pub preemption_min_runtime_ns: u64,
    /// Maximum CPU-time share available to latency selections ahead of root EEVDF.
    pub latency_guarantee_percent: u32,
    /// CPU-time share available to compensate the disruption of urgent preemption.
    pub preemption_budget_percent: u32,
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
            preemption_min_runtime_ns: 250_000,
            latency_guarantee_percent: 10,
            preemption_budget_percent: 10,
            poll_interval: Duration::from_millis(1),
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

        if self.preemption_min_runtime_ns == 0
            || !(1..=100).contains(&self.latency_guarantee_percent)
            || !(1..=100).contains(&self.preemption_budget_percent)
        {
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

    /// Returns the configured initial and maximum request for a class.
    pub const fn slice_for(&self, class: crate::identity::TaskClass) -> u64 {
        match class {
            crate::identity::TaskClass::Latency => self.latency_slice_ns,
            crate::identity::TaskClass::Balanced => self.balanced_slice_ns,
            crate::identity::TaskClass::Throughput => self.throughput_slice_ns,
        }
    }

    /// Minimum wall-clock spacing that keeps urgent disruption within budget.
    pub fn fast_preemption_interval_ns(&self) -> u64 {
        self.preemption_min_runtime_ns
            .saturating_mul(100)
            .div_ceil(u64::from(self.preemption_budget_percent))
    }

    /// Root request used only while more than one latency task is queued.
    pub fn latency_backlog_request_ns(&self) -> u64 {
        self.latency_slice_ns
            .saturating_mul(100)
            .div_ceil(100 + u64::from(self.latency_guarantee_percent))
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
    fn bpf_derived_intervals_are_bounded() {
        let config = SchedulerConfig::default();
        assert_eq!(config.fast_preemption_interval_ns(), 2_500_000);
        assert_eq!(config.latency_backlog_request_ns(), 227_273);
    }
}
