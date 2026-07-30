// SPDX-License-Identifier: GPL-2.0-only

//! Slow-path policy snapshots published atomically to the BPF data plane.

use std::cmp::Reverse;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::config::SchedulerConfig;
use crate::topology::{CpuDescriptor, CpuTopology};

pub const POLICY_SLOT_COUNT: u32 = 2;
pub const POLICY_LEASE_NS: u64 = 2_000_000_000;
pub const POLICY_REFRESH_NS: u64 = 500_000_000;
const MIN_FEEDBACK_RUNTIME_NS: u64 = 100_000_000;
const MIN_LATENCY_BUDGET_SAMPLES: u64 = 64;
const MIN_BALANCED_DISPATCH_SAMPLES: u64 = 64;
const POLICY_CHANGE_DENOMINATOR: u64 = 8;
const BALANCED_GRANULARITY_DIVISOR: u64 = 4;
const BALANCED_GRANULARITY_STEP_NUMERATOR: u64 = 3;
const BALANCED_GRANULARITY_STEP_DENOMINATOR: u64 = 4;
const BALANCED_GRANULARITY_RAISE_NUMERATOR: u64 = 4;
const BALANCED_GRANULARITY_RAISE_DENOMINATOR: u64 = 3;
const BALANCED_PREEMPTION_TARGET_PER_MILLE: u64 = 80;
const BALANCED_PREEMPTION_DEADBAND_PER_MILLE: u64 = 20;
const BALANCED_LATENCY_PRESSURE_TARGET_PER_MILLE: u64 = 100;
const BALANCED_LATENCY_PRESSURE_DEADBAND_PER_MILLE: u64 = 10;
const BALANCED_GRANULARITY_MIN_DIVISOR: u64 = 8;
const BALANCED_GRANULARITY_MAX_DIVISOR: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuPressure {
    pub cpu: u32,
    pub online: bool,
    pub idle: bool,
    pub running_class: u32,
    pub latency_credit_ns: u64,
    pub latency_debt_ns: u64,
    pub last_preemption_ns: u64,
    pub runtime_ns_by_class: [u64; 3],
    pub queued_tasks_by_class: [u64; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyObservation {
    pub runtime_ns_by_class: [u64; 3],
    pub dispatches_by_class: [u64; 3],
    pub preemptions_by_class: [u64; 3],
    pub preemption_throttles: u64,
    pub latency_backlog_boosts: u64,
    pub latency_budget_charge_events: u64,
    pub latency_budget_runtime_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuPolicy {
    pub cpu: u32,
    pub domain_id: u32,
    pub llc_id: u32,
    pub numa_id: u32,
    pub package_id: u32,
    pub core_id: u32,
    pub smt_index: u32,
    pub capacity: u32,
    pub core_type: u32,
    pub latency_candidate_cpu: [u32; 2],
    pub normal_candidate_cpu: [u32; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    pub generation: u64,
    pub valid_until_ns: u64,
    pub latency_budget_percent: u32,
    pub preemption_interval_ns: u64,
    pub latency_successor_lease_ns: u64,
    pub balanced_preemption_granularity_ns: u64,
    pub cross_domain_cost_ns: u64,
    pub domain_count: u32,
    pub cpus: Vec<CpuPolicy>,
}

impl PolicySnapshot {
    pub fn active_slot(&self) -> u32 {
        (self.generation % u64::from(POLICY_SLOT_COUNT)) as u32
    }

    pub fn validate(&self) -> Result<()> {
        if self.generation == 0 {
            anyhow::bail!("policy generation must be non-zero");
        }
        if self.valid_until_ns == 0 {
            anyhow::bail!("policy lease must be non-zero");
        }
        if !(1..=100).contains(&self.latency_budget_percent) {
            anyhow::bail!("policy latency budget must be in 1..=100");
        }
        if self.preemption_interval_ns == 0 {
            anyhow::bail!("policy preemption interval must be non-zero");
        }
        if self.latency_successor_lease_ns == 0 {
            anyhow::bail!("policy Latency successor lease must be non-zero");
        }
        if self.balanced_preemption_granularity_ns == 0 {
            anyhow::bail!("policy Balanced preemption granularity must be non-zero");
        }
        if self.domain_count == 0 || self.cpus.is_empty() {
            anyhow::bail!("policy requires at least one CPU and domain");
        }
        for (index, cpu) in self.cpus.iter().enumerate() {
            if cpu.cpu as usize != index {
                anyhow::bail!("policy CPU IDs must be dense and ordered");
            }
            if cpu.domain_id >= self.domain_count || cpu.capacity == 0 {
                anyhow::bail!("policy CPU {index} has invalid topology data");
            }
            for candidate in cpu
                .latency_candidate_cpu
                .into_iter()
                .chain(cpu.normal_candidate_cpu)
            {
                if candidate == u32::MAX {
                    continue;
                }
                let Some(_target) = self.cpus.get(candidate as usize) else {
                    anyhow::bail!("policy CPU {index} has an out-of-range candidate");
                };
                if candidate == cpu.cpu {
                    anyhow::bail!("policy CPU {index} has an invalid candidate");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyStatus {
    pub generation: u64,
    pub active_slot: u32,
    pub valid_until_ns: u64,
    pub domain_count: u32,
    pub latency_budget_percent: u32,
    pub preemption_interval_ns: u64,
    pub preemption_interval_floor_ns: u64,
    pub latency_successor_lease_ns: u64,
    pub throughput_preemption_min_runtime_ns: u64,
    pub balanced_preemption_granularity_ns: u64,
    pub observed_latency_service_ns: u64,
    pub last_latency_share_per_mille: u32,
    pub last_balanced_preemption_rate_per_mille: u32,
    pub feedback_updates: u64,
    pub placement_updates: u64,
}

pub struct PolicyController {
    snapshot: PolicySnapshot,
    next_refresh_ns: u64,
    absolute_min_preemption_interval_ns: u64,
    max_preemption_interval_ns: u64,
    throughput_preemption_min_runtime_ns: u64,
    min_balanced_granularity_ns: u64,
    latency_pressure_granularity_cap_ns: u64,
    max_balanced_granularity_ns: u64,
    observed_latency_service_ns: u64,
    last_latency_share_per_mille: u32,
    last_balanced_preemption_rate_per_mille: u32,
    feedback_updates: u64,
    placement_updates: u64,
    last_observation: Option<PolicyObservation>,
}

impl PolicyController {
    pub fn new(config: &SchedulerConfig, topology: &CpuTopology, now_ns: u64) -> Result<Self> {
        let descriptors: Vec<_> = topology.cpus().copied().collect();
        if config.latency_budget_percent == 0 {
            anyhow::bail!("policy latency budget must be non-zero");
        }
        let preemption_interval_ns = config.latency_preemption_interval_ns();
        let balanced_preemption_granularity_ns = config
            .balanced_slice_ns
            .saturating_div(BALANCED_GRANULARITY_DIVISOR)
            .max(config.min_slice_ns)
            .min(config.balanced_slice_ns);
        let snapshot = PolicySnapshot {
            generation: 1,
            valid_until_ns: now_ns.saturating_add(POLICY_LEASE_NS),
            latency_budget_percent: config.latency_budget_percent,
            preemption_interval_ns,
            latency_successor_lease_ns: config.latency_slice_ns,
            balanced_preemption_granularity_ns,
            cross_domain_cost_ns: config.balanced_slice_ns.saturating_mul(2),
            domain_count: topology.domain_count(),
            cpus: descriptors
                .iter()
                .map(|cpu| CpuPolicy {
                    cpu: cpu.id,
                    domain_id: cpu.domain_id,
                    llc_id: cpu.llc_id,
                    numa_id: cpu.numa_id,
                    package_id: cpu.package_id,
                    core_id: cpu.core_id,
                    smt_index: cpu.smt_index,
                    capacity: cpu.capacity,
                    core_type: cpu.core_type,
                    latency_candidate_cpu: latency_candidates(cpu, &descriptors),
                    normal_candidate_cpu: normal_candidates(cpu, &descriptors),
                })
                .collect(),
        };
        snapshot
            .validate()
            .context("validate initial policy snapshot")?;
        Ok(Self {
            snapshot,
            next_refresh_ns: now_ns.saturating_add(POLICY_REFRESH_NS),
            // Active policy may use measured service time, but never publish
            // a cadence shorter than one immutable Latency request.
            absolute_min_preemption_interval_ns: config.latency_slice_ns,
            // A low configured latency share can imply a floor above the
            // Balanced request. Keep the feedback range ordered in that
            // valid configuration rather than relying on clamp preconditions.
            max_preemption_interval_ns: config.balanced_slice_ns.max(preemption_interval_ns),
            throughput_preemption_min_runtime_ns: config.throughput_preemption_min_runtime_ns(),
            min_balanced_granularity_ns: config
                .balanced_slice_ns
                .saturating_div(BALANCED_GRANULARITY_MIN_DIVISOR)
                .max(config.min_slice_ns)
                .min(config.balanced_slice_ns),
            latency_pressure_granularity_cap_ns: balanced_preemption_granularity_ns,
            max_balanced_granularity_ns: config
                .balanced_slice_ns
                .saturating_div(BALANCED_GRANULARITY_MAX_DIVISOR)
                .max(config.min_slice_ns)
                .min(config.balanced_slice_ns),
            observed_latency_service_ns: config.latency_slice_ns,
            last_latency_share_per_mille: 0,
            last_balanced_preemption_rate_per_mille: 0,
            feedback_updates: 0,
            placement_updates: 0,
            last_observation: None,
        })
    }

    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    pub fn status(&self) -> PolicyStatus {
        PolicyStatus {
            generation: self.snapshot.generation,
            active_slot: self.snapshot.active_slot(),
            valid_until_ns: self.snapshot.valid_until_ns,
            domain_count: self.snapshot.domain_count,
            latency_budget_percent: self.snapshot.latency_budget_percent,
            preemption_interval_ns: self.snapshot.preemption_interval_ns,
            preemption_interval_floor_ns: self.preemption_interval_floor_ns(),
            latency_successor_lease_ns: self.snapshot.latency_successor_lease_ns,
            throughput_preemption_min_runtime_ns: self.throughput_preemption_min_runtime_ns,
            balanced_preemption_granularity_ns: self.snapshot.balanced_preemption_granularity_ns,
            observed_latency_service_ns: self.observed_latency_service_ns,
            last_latency_share_per_mille: self.last_latency_share_per_mille,
            last_balanced_preemption_rate_per_mille: self.last_balanced_preemption_rate_per_mille,
            feedback_updates: self.feedback_updates,
            placement_updates: self.placement_updates,
        }
    }

    pub fn lease_refresh_due(&self, now_ns: u64) -> bool {
        now_ns >= self.next_refresh_ns
    }

    pub fn renew_lease(&mut self, now_ns: u64) {
        self.snapshot.valid_until_ns = now_ns.saturating_add(POLICY_LEASE_NS);
        self.next_refresh_ns = now_ns.saturating_add(POLICY_REFRESH_NS);
    }

    /// Adjusts preemption cadence and victim candidates from cumulative facts.
    pub fn observe(
        &mut self,
        now_ns: u64,
        current: PolicyObservation,
        cpu_pressure: &[CpuPressure],
    ) -> bool {
        let mut changed = self.refresh_latency_candidates(cpu_pressure);
        let Some(previous) = self.last_observation.replace(current) else {
            return self.commit_update(now_ns, changed);
        };
        if counters_went_backwards(previous, current) {
            return self.commit_update(now_ns, changed);
        }

        let runtime = subtract_array(current.runtime_ns_by_class, previous.runtime_ns_by_class);
        let dispatches = subtract_array(current.dispatches_by_class, previous.dispatches_by_class);
        let preemptions =
            subtract_array(current.preemptions_by_class, previous.preemptions_by_class);
        let total_runtime = runtime.iter().copied().fold(0_u64, u64::saturating_add);
        let latency_budget_charge_events = current
            .latency_budget_charge_events
            .saturating_sub(previous.latency_budget_charge_events);
        let latency_budget_runtime_ns = current
            .latency_budget_runtime_ns
            .saturating_sub(previous.latency_budget_runtime_ns);
        // The configured budget bounds only Latency service that displaced
        // queued Normal work. Direct service on otherwise idle capacity is
        // intentionally free and must not make the controller penalize the
        // non-saturated workload this scheduler is designed to exploit.
        let latency_share_per_mille = latency_budget_runtime_ns
            .saturating_mul(1_000)
            .checked_div(total_runtime)
            .unwrap_or(0)
            .min(1_000) as u32;
        if self.adjust_balanced_granularity(
            current,
            previous,
            dispatches[1],
            preemptions[1],
            latency_share_per_mille,
        ) {
            changed = true;
        }
        if total_runtime < MIN_FEEDBACK_RUNTIME_NS
            || latency_budget_charge_events < MIN_LATENCY_BUDGET_SAMPLES
            || latency_budget_runtime_ns == 0
        {
            return self.commit_update(now_ns, changed);
        }

        let service_sample = latency_budget_runtime_ns / latency_budget_charge_events;
        self.observed_latency_service_ns = self
            .observed_latency_service_ns
            .saturating_add(service_sample)
            / 2;
        self.last_latency_share_per_mille = latency_share_per_mille;

        let target = u64::from(self.snapshot.latency_budget_percent);
        let actual_percent = latency_budget_runtime_ns
            .saturating_mul(100)
            .checked_div(total_runtime)
            .unwrap_or(0);
        let deadband = (target / 10).max(1);
        let throttled = current.preemption_throttles > previous.preemption_throttles;
        let current_interval = self.snapshot.preemption_interval_ns;
        let interval_floor = self.preemption_interval_floor_ns();
        let floor_violated = current_interval < interval_floor;
        let proportional_interval = proportional_interval_ns(
            current_interval,
            latency_budget_runtime_ns,
            total_runtime,
            target,
        );

        let desired = if floor_violated {
            interval_floor
        } else if throttled && actual_percent.saturating_add(deadband) < target {
            proportional_interval
                .clamp((current_interval / 2).max(interval_floor), current_interval)
        } else if actual_percent > target.saturating_add(deadband) {
            proportional_interval.clamp(
                current_interval,
                current_interval
                    .saturating_mul(2)
                    .min(self.max_preemption_interval_ns),
            )
        } else {
            current_interval
        };

        let change = desired.abs_diff(current_interval);
        let mut feedback_changed = false;
        if floor_violated || change.saturating_mul(POLICY_CHANGE_DENOMINATOR) >= current_interval {
            self.snapshot.preemption_interval_ns = desired;
            feedback_changed = true;
        }

        // A sole Normal successor should remain with its current CPU only for
        // the expected stopping time of the running Latency request. This is
        // the measured service EWMA, capped by the immutable request bound;
        // it avoids both premature cross-core steals and a worst-case lease
        // that leaves otherwise idle CPUs unused.
        let successor_lease = self
            .observed_latency_service_ns
            .max(1)
            .min(self.absolute_min_preemption_interval_ns);
        if self.snapshot.latency_successor_lease_ns != successor_lease {
            self.snapshot.latency_successor_lease_ns = successor_lease;
            feedback_changed = true;
        }
        if feedback_changed {
            self.feedback_updates = self.feedback_updates.saturating_add(1);
            changed = true;
        }
        self.commit_update(now_ns, changed)
    }

    /// Derives the fastest active cadence whose measured competing service
    /// consumes no more than the configured share on average. The BPF
    /// credit/debt bound remains the hard guard for short-term variation.
    fn preemption_interval_floor_ns(&self) -> u64 {
        let budget = u128::from(self.snapshot.latency_budget_percent.max(1));
        let numerator = u128::from(self.observed_latency_service_ns).saturating_mul(100);
        let interval = numerator.saturating_add(budget - 1) / budget;

        (interval.min(u128::from(u64::MAX)) as u64).clamp(
            self.absolute_min_preemption_interval_ns,
            self.max_preemption_interval_ns,
        )
    }

    /// Adapts the Balanced victim granule without moving scheduling logic into BPF.
    ///
    /// A high Balanced preemption rate is an observable context-switch pressure
    /// signal. When budget throttling proves Latency demand is unsatisfied and
    /// competing service remains below its reserved share, the controller
    /// targets a bounded 10% Balanced-preemption rate. A mere competing
    /// dispatch is not pressure; treating it as such collapses the granule in
    /// every mixed-load window. In a quiet window, a high rate grows the
    /// granule to reduce avoidable preemptions.
    fn adjust_balanced_granularity(
        &mut self,
        current: PolicyObservation,
        previous: PolicyObservation,
        balanced_dispatches: u64,
        balanced_preemptions: u64,
        latency_share_per_mille: u32,
    ) -> bool {
        if balanced_dispatches < MIN_BALANCED_DISPATCH_SAMPLES {
            return false;
        }

        let rate = balanced_preemptions
            .saturating_mul(1_000)
            .checked_div(balanced_dispatches)
            .unwrap_or(0)
            .min(1_000);
        self.last_balanced_preemption_rate_per_mille = rate as u32;

        let quiet_target = BALANCED_PREEMPTION_TARGET_PER_MILLE;
        let quiet_deadband = BALANCED_PREEMPTION_DEADBAND_PER_MILLE;
        let latency_budget_per_mille =
            u64::from(self.snapshot.latency_budget_percent).saturating_mul(10);
        let latency_deadband = (latency_budget_per_mille / 10).max(10);
        let latency_throttled = current.preemption_throttles > previous.preemption_throttles;
        let latency_under_budget = u64::from(latency_share_per_mille)
            .saturating_add(latency_deadband)
            < latency_budget_per_mille;
        let latency_over_budget = u64::from(latency_share_per_mille)
            > latency_budget_per_mille.saturating_add(latency_deadband);
        let preemption_over_target = rate > quiet_target.saturating_add(quiet_deadband);
        let current_granularity = self.snapshot.balanced_preemption_granularity_ns;
        let increase_cap = if latency_throttled {
            self.latency_pressure_granularity_cap_ns
        } else {
            self.max_balanced_granularity_ns
        };
        let desired = if latency_over_budget || preemption_over_target {
            // Once competing Latency service is over budget (or Balanced is
            // being preempted too often), give normal work back some slice.
            // Keep recovery bounded while budget throttling proves Latency
            // demand is currently unsatisfied.
            if current_granularity > increase_cap {
                increase_cap
            } else {
                current_granularity
                    .saturating_mul(BALANCED_GRANULARITY_RAISE_NUMERATOR)
                    .checked_div(BALANCED_GRANULARITY_RAISE_DENOMINATOR)
                    .unwrap_or(increase_cap)
                    .min(increase_cap)
            }
        } else if latency_throttled
            && latency_under_budget
            && balanced_preemptions > 0
            && rate
                < BALANCED_LATENCY_PRESSURE_TARGET_PER_MILLE
                    .saturating_sub(BALANCED_LATENCY_PRESSURE_DEADBAND_PER_MILLE)
        {
            current_granularity
                .saturating_mul(BALANCED_GRANULARITY_STEP_NUMERATOR)
                .checked_div(BALANCED_GRANULARITY_STEP_DENOMINATOR)
                .unwrap_or(self.min_balanced_granularity_ns)
                .max(self.min_balanced_granularity_ns)
        } else {
            current_granularity
        };

        let change = desired.abs_diff(current_granularity);
        if change.saturating_mul(POLICY_CHANGE_DENOMINATOR) < current_granularity {
            return false;
        }
        self.snapshot.balanced_preemption_granularity_ns = desired;
        self.feedback_updates = self.feedback_updates.saturating_add(1);
        true
    }

    fn refresh_latency_candidates(&mut self, pressure: &[CpuPressure]) -> bool {
        if pressure.len() != self.snapshot.cpus.len()
            || pressure
                .iter()
                .enumerate()
                .any(|(cpu, state)| state.cpu as usize != cpu)
        {
            return false;
        }
        let latency_candidates: Vec<_> = self
            .snapshot
            .cpus
            .iter()
            .map(|source| pressure_latency_candidates(source, &self.snapshot.cpus, pressure))
            .collect();
        let normal_candidates: Vec<_> = self
            .snapshot
            .cpus
            .iter()
            .map(|source| pressure_normal_candidates(source, &self.snapshot.cpus, pressure))
            .collect();
        let mut changed = false;
        for ((cpu, latency_candidates), normal_candidates) in self
            .snapshot
            .cpus
            .iter_mut()
            .zip(latency_candidates)
            .zip(normal_candidates)
        {
            if cpu.latency_candidate_cpu != latency_candidates {
                cpu.latency_candidate_cpu = latency_candidates;
                changed = true;
            }
            if cpu.normal_candidate_cpu != normal_candidates {
                cpu.normal_candidate_cpu = normal_candidates;
                changed = true;
            }
        }
        if changed {
            self.placement_updates = self.placement_updates.saturating_add(1);
        }
        changed
    }

    fn commit_update(&mut self, now_ns: u64, changed: bool) -> bool {
        if !changed {
            return false;
        }
        self.snapshot.generation = self.snapshot.generation.wrapping_add(1);
        if self.snapshot.generation == 0 {
            self.snapshot.generation = 1;
        }
        self.snapshot.valid_until_ns = now_ns.saturating_add(POLICY_LEASE_NS);
        self.next_refresh_ns = now_ns.saturating_add(POLICY_REFRESH_NS);
        true
    }
}

pub fn aggregate_runtime_ns(pressure: &[CpuPressure]) -> [u64; 3] {
    let mut total = [0_u64; 3];
    for cpu in pressure {
        for (sum, runtime) in total.iter_mut().zip(cpu.runtime_ns_by_class) {
            *sum = sum.saturating_add(runtime);
        }
    }
    total
}

fn subtract_array(current: [u64; 3], previous: [u64; 3]) -> [u64; 3] {
    std::array::from_fn(|index| current[index] - previous[index])
}

fn proportional_interval_ns(
    current_interval_ns: u64,
    competing_runtime_ns: u64,
    total_runtime_ns: u64,
    target_percent: u64,
) -> u64 {
    let numerator = u128::from(current_interval_ns)
        .saturating_mul(u128::from(competing_runtime_ns))
        .saturating_mul(100);
    let denominator = u128::from(total_runtime_ns).saturating_mul(u128::from(target_percent));
    if denominator == 0 {
        return current_interval_ns;
    }
    (numerator / denominator).min(u128::from(u64::MAX)) as u64
}

fn counters_went_backwards(previous: PolicyObservation, current: PolicyObservation) -> bool {
    current
        .runtime_ns_by_class
        .iter()
        .zip(previous.runtime_ns_by_class)
        .any(|(current, previous)| *current < previous)
        || current
            .dispatches_by_class
            .iter()
            .zip(previous.dispatches_by_class)
            .any(|(current, previous)| *current < previous)
        || current
            .preemptions_by_class
            .iter()
            .zip(previous.preemptions_by_class)
            .any(|(current, previous)| *current < previous)
        || current.preemption_throttles < previous.preemption_throttles
        || current.latency_backlog_boosts < previous.latency_backlog_boosts
        || current.latency_budget_charge_events < previous.latency_budget_charge_events
        || current.latency_budget_runtime_ns < previous.latency_budget_runtime_ns
}

fn latency_candidates(source: &CpuDescriptor, cpus: &[CpuDescriptor]) -> [u32; 2] {
    let cpu_count = cpus.len() as u32;
    let mut candidates: Vec<_> = cpus
        .iter()
        .filter(|candidate| candidate.online && candidate.id != source.id)
        .collect();
    candidates.sort_by_key(|candidate| {
        let same_core =
            candidate.package_id == source.package_id && candidate.core_id == source.core_id;
        let capacity_deficit = source.capacity.saturating_sub(candidate.capacity);
        let ring_distance = if cpu_count > 0 {
            (candidate.id + cpu_count - source.id) % cpu_count
        } else {
            candidate.id
        };
        (
            candidate.domain_id != source.domain_id,
            // Keep the sibling of the source CPU ahead of another core when
            // all other topology attributes are equivalent. This is the
            // cache-local wake/victim preference described by the scheduler
            // contract; sorting the raw bool would put `false` first.
            !same_core,
            capacity_deficit,
            ring_distance,
            candidate.id,
        )
    });
    let mut selected = [u32::MAX; 2];
    for (slot, candidate) in selected.iter_mut().zip(candidates) {
        *slot = candidate.id;
    }
    selected
}

fn normal_candidates(source: &CpuDescriptor, cpus: &[CpuDescriptor]) -> [u32; 2] {
    latency_candidates(source, cpus)
}

fn pressure_latency_candidates(
    source: &CpuPolicy,
    cpus: &[CpuPolicy],
    pressure: &[CpuPressure],
) -> [u32; 2] {
    let cpu_count = cpus.len() as u32;
    let mut candidates: Vec<_> = cpus
        .iter()
        .filter(|candidate| candidate.cpu != source.cpu && pressure[candidate.cpu as usize].online)
        .collect();
    candidates.sort_by_key(|candidate| {
        let state = pressure[candidate.cpu as usize];
        let same_core =
            candidate.package_id == source.package_id && candidate.core_id == source.core_id;
        let capacity_deficit = source.capacity.saturating_sub(candidate.capacity);
        let ring_distance = if cpu_count > 0 {
            (candidate.cpu + cpu_count - source.cpu) % cpu_count
        } else {
            candidate.cpu
        };
        let total_queued = state
            .queued_tasks_by_class
            .into_iter()
            .fold(0_u64, u64::saturating_add);
        let unusable_running = state.idle || state.running_class >= 3 || state.running_class == 0;
        (
            unusable_running,
            state.queued_tasks_by_class[0],
            state.latency_debt_ns,
            Reverse(state.latency_credit_ns),
            state.last_preemption_ns,
            candidate.domain_id != source.domain_id,
            !same_core,
            state.running_class != 2,
            total_queued,
            capacity_deficit,
            ring_distance,
            candidate.cpu,
        )
    });
    let mut selected = [u32::MAX; 2];
    for (slot, candidate) in selected.iter_mut().zip(candidates) {
        *slot = candidate.cpu;
    }
    selected
}

fn pressure_normal_candidates(
    source: &CpuPolicy,
    cpus: &[CpuPolicy],
    pressure: &[CpuPressure],
) -> [u32; 2] {
    let cpu_count = cpus.len() as u32;
    let mut candidates: Vec<_> = cpus
        .iter()
        .filter(|candidate| candidate.cpu != source.cpu && pressure[candidate.cpu as usize].online)
        .collect();
    candidates.sort_by_key(|candidate| {
        let state = pressure[candidate.cpu as usize];
        let same_core =
            candidate.package_id == source.package_id && candidate.core_id == source.core_id;
        let capacity_deficit = source.capacity.saturating_sub(candidate.capacity);
        let ring_distance = if cpu_count > 0 {
            (candidate.cpu + cpu_count - source.cpu) % cpu_count
        } else {
            candidate.cpu
        };
        let normal_queued =
            state.queued_tasks_by_class[1].saturating_add(state.queued_tasks_by_class[2]);
        let latency_blocked = state.running_class == 0 || state.queued_tasks_by_class[0] > 0;
        let running_penalty = match state.running_class {
            1 => 1,
            2 => 3,
            0 => 4,
            _ => 0,
        };
        let normal_pressure = normal_queued.saturating_add(running_penalty);
        (
            candidate.domain_id != source.domain_id,
            !same_core,
            latency_blocked,
            normal_pressure,
            capacity_deficit,
            ring_distance,
            candidate.cpu,
        )
    });
    let mut selected = [u32::MAX; 2];
    for (slot, candidate) in selected.iter_mut().zip(candidates) {
        *slot = candidate.cpu;
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::{
        latency_candidates, pressure_latency_candidates, pressure_normal_candidates, CpuPolicy,
        CpuPressure, PolicyController, PolicyObservation, POLICY_LEASE_NS,
    };
    use crate::config::SchedulerConfig;
    use crate::topology::{CpuDescriptor, CpuTopology};

    fn smt_descriptors() -> Vec<CpuDescriptor> {
        (0..4)
            .map(|cpu| CpuDescriptor {
                id: cpu,
                possible: true,
                online: true,
                package_id: 0,
                core_id: cpu / 2,
                llc_id: 0,
                numa_id: 0,
                domain_id: 0,
                smt_index: cpu % 2,
                capacity: 1024,
                core_type: 0,
            })
            .collect()
    }

    fn smt_policies() -> Vec<CpuPolicy> {
        smt_descriptors()
            .into_iter()
            .map(|cpu| CpuPolicy {
                cpu: cpu.id,
                domain_id: cpu.domain_id,
                llc_id: cpu.llc_id,
                numa_id: cpu.numa_id,
                package_id: cpu.package_id,
                core_id: cpu.core_id,
                smt_index: cpu.smt_index,
                capacity: cpu.capacity,
                core_type: cpu.core_type,
                latency_candidate_cpu: [u32::MAX; 2],
                normal_candidate_cpu: [u32::MAX; 2],
            })
            .collect()
    }

    #[test]
    fn topology_candidates_prefer_same_core_sibling_before_other_core() {
        let descriptors = smt_descriptors();
        assert_eq!(latency_candidates(&descriptors[0], &descriptors), [1, 2]);

        let policies = smt_policies();
        let pressure = (0..4)
            .map(|cpu| CpuPressure {
                cpu,
                online: true,
                idle: false,
                running_class: 1,
                latency_credit_ns: 0,
                latency_debt_ns: 0,
                last_preemption_ns: 0,
                runtime_ns_by_class: [0; 3],
                queued_tasks_by_class: [0; 3],
            })
            .collect::<Vec<_>>();
        assert_eq!(
            pressure_latency_candidates(&policies[0], &policies, &pressure),
            [1, 2]
        );
        assert_eq!(
            pressure_normal_candidates(&policies[0], &policies, &pressure),
            [1, 2]
        );
    }

    #[test]
    fn initial_policy_is_dense_and_uses_one_complete_slot() {
        let controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.active_slot(), 1);
        assert_eq!(snapshot.domain_count, 1);
        assert_eq!(snapshot.cpus.len(), 4);
        assert_eq!(snapshot.preemption_interval_ns, 1_250_000);
        assert_eq!(snapshot.latency_successor_lease_ns, 250_000);
        assert_eq!(snapshot.balanced_preemption_granularity_ns, 1_000_000);
        assert_eq!(snapshot.cpus[0].latency_candidate_cpu, [1, 2]);
        assert_eq!(snapshot.cpus[0].normal_candidate_cpu, [1, 2]);
        assert!(snapshot.validate().is_ok());
    }

    #[test]
    fn lease_renewal_does_not_change_policy_generation() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(2), 100).unwrap();
        controller.renew_lease(1_000);
        assert_eq!(controller.snapshot().generation, 1);
        assert_eq!(
            controller.snapshot().valid_until_ns,
            1_000 + POLICY_LEASE_NS
        );
    }

    #[test]
    fn runtime_feedback_preserves_the_configured_share_interval_for_full_service() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let pressure = PolicyObservation {
            runtime_ns_by_class: [600_000_000, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 1,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 600_000_000,
        };
        assert!(!controller.observe(1_000_000_000, pressure, &[]));
        let status = controller.status();
        assert_eq!(status.generation, 1);
        assert_eq!(status.preemption_interval_ns, 1_250_000);
        assert_eq!(status.throughput_preemption_min_runtime_ns, 1_000_000);
        assert_eq!(status.latency_budget_percent, 20);
        assert_eq!(status.observed_latency_service_ns, 250_000);
        assert_eq!(status.preemption_interval_floor_ns, 1_250_000);
        assert_eq!(status.latency_successor_lease_ns, 250_000);
        assert_eq!(status.last_latency_share_per_mille, 100);
        assert_eq!(status.feedback_updates, 0);
    }

    #[test]
    fn runtime_feedback_share_excludes_uncontended_latency_service() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let window = PolicyObservation {
            runtime_ns_by_class: [1_800_000_000, 2_100_000_000, 2_100_000_000],
            dispatches_by_class: [8_000, 8_000, 8_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 1_000,
            latency_budget_runtime_ns: 200_000_000,
        };
        assert!(controller.observe(1_000_000_000, window, &[]));
        let status = controller.status();
        assert_eq!(status.last_latency_share_per_mille, 33);
        assert_eq!(status.preemption_interval_ns, 1_250_000);
    }

    #[test]
    fn runtime_feedback_uses_measured_competing_service_floor() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let first_window = PolicyObservation {
            runtime_ns_by_class: [450_000_000, 2_550_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 1,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 6_000,
            latency_budget_runtime_ns: 450_000_000,
        };
        assert!(controller.observe(1_000_000_000, first_window, &[]));
        let status = controller.status();
        assert_eq!(status.observed_latency_service_ns, 162_500);
        assert_eq!(status.preemption_interval_floor_ns, 812_500);
        assert_eq!(status.preemption_interval_ns, 812_500);
        assert_eq!(status.latency_successor_lease_ns, 162_500);
        assert_eq!(status.last_latency_share_per_mille, 75);

        let second_window = PolicyObservation {
            runtime_ns_by_class: [900_000_000, 5_100_000_000, 6_000_000_000],
            dispatches_by_class: [12_000, 16_000, 8_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 2,
            latency_backlog_boosts: 2,
            latency_budget_charge_events: 12_000,
            latency_budget_runtime_ns: 900_000_000,
        };
        assert!(controller.observe(2_000_000_000, second_window, &[]));
        let status = controller.status();
        assert_eq!(status.observed_latency_service_ns, 118_750);
        assert_eq!(status.preemption_interval_floor_ns, 593_750);
        assert_eq!(status.preemption_interval_ns, 593_750);
        assert_eq!(status.latency_successor_lease_ns, 118_750);
    }

    #[test]
    fn successor_lease_never_exceeds_the_immutable_latency_request() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let long_service = PolicyObservation {
            runtime_ns_by_class: [1_200_000_000, 2_400_000_000, 2_400_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 1_200_000_000,
        };
        assert!(controller.observe(1_000_000_000, long_service, &[]));

        let status = controller.status();
        assert_eq!(status.observed_latency_service_ns, 375_000);
        assert_eq!(status.latency_successor_lease_ns, 250_000);
    }

    #[test]
    fn successor_lease_survives_insufficient_or_reset_observations() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));
        let learned = PolicyObservation {
            runtime_ns_by_class: [450_000_000, 2_550_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 6_000,
            latency_budget_runtime_ns: 450_000_000,
        };
        assert!(controller.observe(1_000_000_000, learned, &[]));
        assert_eq!(controller.status().latency_successor_lease_ns, 162_500);

        let insufficient = PolicyObservation {
            runtime_ns_by_class: [451_000_000, 2_551_000_000, 3_001_000_000],
            dispatches_by_class: [6_001, 8_001, 4_001],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 6_001,
            latency_budget_runtime_ns: 450_075_000,
        };
        assert!(!controller.observe(2_000_000_000, insufficient, &[]));
        assert_eq!(controller.status().latency_successor_lease_ns, 162_500);

        assert!(!controller.observe(3_000_000_000, baseline, &[]));
        assert_eq!(controller.status().latency_successor_lease_ns, 162_500);
    }

    #[test]
    fn runtime_feedback_increases_interval_above_the_share_budget() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let over_budget = PolicyObservation {
            runtime_ns_by_class: [1_800_000_000, 2_100_000_000, 2_100_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 7_200,
            latency_budget_runtime_ns: 1_800_000_000,
        };
        assert!(controller.observe(1_000_000_000, over_budget, &[]));
        assert_eq!(controller.status().preemption_interval_ns, 1_875_000);
    }

    #[test]
    fn runtime_feedback_never_falls_below_the_share_floor_after_recovery() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let over_budget = PolicyObservation {
            runtime_ns_by_class: [1_800_000_000, 2_100_000_000, 2_100_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 7_200,
            latency_budget_runtime_ns: 1_800_000_000,
        };
        assert!(controller.observe(1_000_000_000, over_budget, &[]));
        assert_eq!(controller.status().preemption_interval_ns, 1_875_000);

        let under_budget_with_throttling = PolicyObservation {
            runtime_ns_by_class: [2_100_000_000, 3_800_000_000, 3_100_000_000],
            dispatches_by_class: [12_000, 16_000, 8_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 1,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 8_400,
            latency_budget_runtime_ns: 2_100_000_000,
        };
        assert!(controller.observe(2_000_000_000, under_budget_with_throttling, &[]));
        assert_eq!(controller.status().preemption_interval_ns, 1_250_000);
    }

    #[test]
    fn low_budget_floor_above_balanced_request_remains_safe_under_feedback() {
        let config = SchedulerConfig {
            latency_budget_percent: 1,
            ..SchedulerConfig::default()
        };
        let mut controller = PolicyController::new(&config, &CpuTopology::flat(4), 100).unwrap();
        assert_eq!(controller.status().preemption_interval_ns, 25_000_000);

        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        assert!(!controller.observe(1_000, baseline, &[]));

        let over_budget = PolicyObservation {
            runtime_ns_by_class: [1_800_000_000, 2_100_000_000, 2_100_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 7_200,
            latency_budget_runtime_ns: 1_800_000_000,
        };
        controller.observe(1_000_000_000, over_budget, &[]);
        assert_eq!(controller.status().preemption_interval_ns, 25_000_000);
    }

    #[test]
    fn runtime_feedback_does_not_chase_uncontended_low_share() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(2), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        controller.observe(1_000, baseline, &[]);
        let quiet = PolicyObservation {
            runtime_ns_by_class: [600_000_000, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 600_000_000,
        };
        assert!(!controller.observe(1_000_000_000, quiet, &[]));
        assert_eq!(controller.status().preemption_interval_ns, 1_250_000);
        assert_eq!(controller.status().latency_budget_percent, 20);
        assert_eq!(controller.status().feedback_updates, 0);
    }

    #[test]
    fn balanced_feedback_reduces_granularity_under_latency_pressure() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        controller.observe(1_000, baseline, &[]);
        let pressure = PolicyObservation {
            runtime_ns_by_class: [600_000_000, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0, 640, 0],
            preemption_throttles: 1,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 600_000_000,
        };

        assert!(controller.observe(1_000_000_000, pressure, &[]));
        let status = controller.status();
        assert_eq!(status.balanced_preemption_granularity_ns, 750_000);
        assert_eq!(status.last_balanced_preemption_rate_per_mille, 80);
    }

    #[test]
    fn competing_dispatches_alone_do_not_create_latency_pressure() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        controller.observe(1_000, baseline, &[]);

        let competing = PolicyObservation {
            runtime_ns_by_class: [600_000_000, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0, 640, 0],
            preemption_throttles: 0,
            latency_backlog_boosts: 2_400,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 600_000_000,
        };
        assert!(!controller.observe(1_000_000_000, competing, &[]));
        let status = controller.status();
        assert_eq!(status.preemption_interval_ns, 1_250_000);
        assert_eq!(status.balanced_preemption_granularity_ns, 1_000_000);
        assert_eq!(status.last_latency_share_per_mille, 100);
    }

    #[test]
    fn balanced_feedback_recovers_when_latency_exceeds_budget_with_throttling() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        controller.observe(1_000, baseline, &[]);

        // First reproduce the measured warmup transition from 1 ms to 750 us.
        let under_budget = PolicyObservation {
            runtime_ns_by_class: [600_000_000, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0, 640, 0],
            preemption_throttles: 1,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 600_000_000,
        };
        assert!(controller.observe(1_000_000_000, under_budget, &[]));
        assert_eq!(
            controller.status().balanced_preemption_granularity_ns,
            750_000
        );

        // Continuing budget pressure must not suppress recovery once Latency
        // has crossed its 20% budget plus the 2% deadband.
        let over_budget = PolicyObservation {
            runtime_ns_by_class: [2_400_000_000, 4_800_000_000, 6_000_000_000],
            dispatches_by_class: [12_000, 16_000, 8_000],
            preemptions_by_class: [0, 1_280, 0],
            preemption_throttles: 2,
            latency_backlog_boosts: 2,
            latency_budget_charge_events: 9_600,
            latency_budget_runtime_ns: 2_400_000_000,
        };
        assert!(controller.observe(2_000_000_000, over_budget, &[]));
        let status = controller.status();
        assert_eq!(status.balanced_preemption_granularity_ns, 1_000_000);
        assert_eq!(status.last_latency_share_per_mille, 250);
        assert_eq!(status.last_balanced_preemption_rate_per_mille, 80);
    }

    #[test]
    fn balanced_feedback_ignores_counter_reset_without_changing_granularity() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        controller.observe(1_000, baseline, &[]);
        let pressure = PolicyObservation {
            runtime_ns_by_class: [600_000_000, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [6_000, 8_000, 4_000],
            preemptions_by_class: [0, 640, 0],
            preemption_throttles: 1,
            latency_backlog_boosts: 1,
            latency_budget_charge_events: 2_400,
            latency_budget_runtime_ns: 600_000_000,
        };
        controller.observe(1_000_000_000, pressure, &[]);
        assert_eq!(
            controller.status().balanced_preemption_granularity_ns,
            750_000
        );

        // A BPF restart/reset must establish a new baseline, not produce a
        // synthetic delta that changes the policy.
        let reset = PolicyObservation {
            runtime_ns_by_class: [10, 10, 10],
            dispatches_by_class: [1, 1, 1],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 1,
            latency_budget_runtime_ns: 10,
        };
        assert!(!controller.observe(2_000_000_000, reset, &[]));
        assert_eq!(
            controller.status().balanced_preemption_granularity_ns,
            750_000
        );
    }

    #[test]
    fn balanced_feedback_expands_granularity_for_quiet_preemption_storm() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };
        controller.observe(1_000, baseline, &[]);
        let pressure = PolicyObservation {
            runtime_ns_by_class: [0, 2_400_000_000, 3_000_000_000],
            dispatches_by_class: [0, 8_000, 4_000],
            preemptions_by_class: [0, 1_000, 0],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };

        assert!(controller.observe(1_000_000_000, pressure, &[]));
        let status = controller.status();
        assert_eq!(status.balanced_preemption_granularity_ns, 1_333_333);
        assert_eq!(status.last_balanced_preemption_rate_per_mille, 125);
    }

    #[test]
    fn pressure_refresh_prefers_usable_cpu_with_available_credit() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let mut pressure = Vec::new();
        for cpu in 0..4 {
            pressure.push(CpuPressure {
                cpu,
                online: true,
                idle: false,
                running_class: 1,
                latency_credit_ns: 0,
                latency_debt_ns: 0,
                last_preemption_ns: 0,
                runtime_ns_by_class: [0; 3],
                queued_tasks_by_class: [0; 3],
            });
        }
        pressure[1].running_class = 0;
        pressure[1].queued_tasks_by_class[0] = 4;
        pressure[2].latency_debt_ns = 1_000_000;
        pressure[3].running_class = 2;
        pressure[3].latency_credit_ns = 1_000_000;
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };

        assert!(controller.observe(1_000, baseline, &pressure));
        assert_eq!(controller.snapshot().cpus[0].latency_candidate_cpu, [3, 2]);
        assert_eq!(controller.status().placement_updates, 1);
    }

    #[test]
    fn pressure_refresh_prefers_less_loaded_normal_cpu() {
        let mut controller =
            PolicyController::new(&SchedulerConfig::default(), &CpuTopology::flat(4), 100).unwrap();
        let mut pressure = Vec::new();
        for cpu in 0..4 {
            pressure.push(CpuPressure {
                cpu,
                online: true,
                idle: false,
                running_class: 1,
                latency_credit_ns: 0,
                latency_debt_ns: 0,
                last_preemption_ns: 0,
                runtime_ns_by_class: [0; 3],
                queued_tasks_by_class: [0; 3],
            });
        }
        pressure[1].queued_tasks_by_class[1] = 5;
        pressure[2].running_class = 2;
        pressure[3].queued_tasks_by_class[1] = 1;
        let baseline = PolicyObservation {
            runtime_ns_by_class: [0; 3],
            dispatches_by_class: [0; 3],
            preemptions_by_class: [0; 3],
            preemption_throttles: 0,
            latency_backlog_boosts: 0,
            latency_budget_charge_events: 0,
            latency_budget_runtime_ns: 0,
        };

        assert!(controller.observe(1_000, baseline, &pressure));
        assert_eq!(controller.snapshot().cpus[0].normal_candidate_cpu, [3, 2]);
    }
}
