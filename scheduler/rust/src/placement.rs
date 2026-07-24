// SPDX-License-Identifier: GPL-2.0-only

use crate::identity::{TaskClass, TaskKey};
use crate::topology::{CpuMask, CpuTopology};

/// Mutable scheduler view of one CPU's current and bounded staged work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuState {
    /// Hotplug availability confirmed by BPF CPU_STATE events.
    pub online: bool,
    /// Kernel idle state used to estimate immediate start time.
    pub idle: bool,
    /// Task currently executing and therefore no longer in a DSQ.
    pub current_task: Option<TaskKey>,
    /// Class of `current_task`, retained for victim selection and diagnostics.
    pub current_class: Option<TaskClass>,
    /// Start timestamp of `current_task` from a RUNNING event.
    pub current_started_ns: u64,
    /// Planned slice of `current_task`, used only as a start-delay estimate.
    pub current_slice_ns: u64,
    /// Submitted command occupying this CPU's unique normal staging slot.
    pub staged_dispatch: Option<u64>,
    /// Task belonging to `staged_dispatch`.
    pub staged_task: Option<TaskKey>,
    /// Urgent command allowed to precede the normal staged task.
    pub urgent_dispatch: Option<u64>,
    /// Task belonging to `urgent_dispatch`.
    pub urgent_task: Option<TaskKey>,
}

impl CpuState {
    /// Creates initial CPU state from static topology discovery.
    pub fn from_topology(online: bool) -> Self {
        Self {
            online,
            idle: false,
            current_task: None,
            current_class: None,
            current_started_ns: 0,
            current_slice_ns: 0,
            staged_dispatch: None,
            staged_task: None,
            urgent_dispatch: None,
            urgent_task: None,
        }
    }

    /// Returns whether Rust may reserve one normal task for this CPU.
    pub fn is_fillable(&self) -> bool {
        self.online && self.staged_dispatch.is_none()
    }

    /// Returns whether the one-entry urgent lane is available.
    pub fn is_urgent_fillable(&self) -> bool {
        self.online && self.urgent_dispatch.is_none()
    }

    /// Estimates nanoseconds until a newly staged task can begin.
    pub fn predicted_start_delay(&self, now_ns: u64) -> u64 {
        if self.idle || self.current_task.is_none() {
            return 0;
        }
        let elapsed = now_ns.saturating_sub(self.current_started_ns);
        self.current_slice_ns.saturating_sub(elapsed)
    }
}

/// Read-only task locality and affinity input to CPU placement.
#[derive(Clone, Copy, Debug)]
pub struct TaskPlacement<'a> {
    /// Workload class selecting delay-versus-locality weights.
    pub class: TaskClass,
    /// Current EEVDF request used to bound SMT interference.
    pub request_ns: u64,
    /// Kernel-confirmed CPU used by the previous execution.
    pub previous_cpu: Option<u32>,
    /// Stable preferred CPU established after successful runs.
    pub home_cpu: Option<u32>,
    /// Stable preferred LLC established with the home CPU.
    pub home_llc: Option<u32>,
    /// Cached allowed CPU mask; BPF validates the current mask again.
    pub affinity: &'a CpuMask,
    /// CPUs on which this task is allowed to use the urgent lane.
    pub preemptible: &'a CpuMask,
    /// Delay improvement required before abandoning cache locality.
    pub migration_hysteresis_ns: u64,
    /// Maximum CPU-side delay that still satisfies the latency target.
    pub max_completion_delay_ns: Option<u64>,
}

/// Running task displaced by one urgent placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreemptionVictim {
    pub task: TaskKey,
    pub class: TaskClass,
}

/// CPU and lane chosen by topology-aware placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementDecision {
    pub cpu: u32,
    pub preemption: Option<PreemptionVictim>,
    pub predicted_start_delay_ns: u64,
    pub sibling_busy: bool,
}

impl PlacementDecision {
    pub const fn preempt(&self) -> bool {
        self.preemption.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Candidate {
    cpu: u32,
    preemption: Option<PreemptionVictim>,
    predicted_start_delay_ns: u64,
    completion_delay_ns: u64,
    sibling_rank: u8,
    sibling_busy: bool,
    locality_rank: u8,
}

/// Returns logical-CPU wait plus bounded service interference from SMT siblings.
pub fn predicted_completion_delay(
    class: TaskClass,
    request_ns: u64,
    cpu: u32,
    cpus: &[CpuState],
    topology: &CpuTopology,
    now_ns: u64,
) -> Option<u64> {
    let state = cpus.get(cpu as usize)?;
    if !state.online {
        return None;
    }
    let (_, sibling_delay_ns, _) = sibling_load(class, request_ns, cpu, cpus, topology, now_ns);
    Some(
        state
            .predicted_start_delay(now_ns)
            .saturating_add(sibling_delay_ns),
    )
}

fn sibling_load(
    class: TaskClass,
    request_ns: u64,
    cpu: u32,
    cpus: &[CpuState],
    topology: &CpuTopology,
    now_ns: u64,
) -> (u8, u64, bool) {
    let mut rank = 0;
    let mut delay_ns = 0;
    let mut busy = false;
    for (sibling_id, sibling) in cpus.iter().enumerate() {
        if !sibling.online
            || !topology.shares_core(cpu, sibling_id as u32)
            || (sibling.current_task.is_none()
                && sibling.staged_task.is_none()
                && sibling.urgent_task.is_none())
        {
            continue;
        }
        busy = true;
        let sibling_class = sibling.current_class.unwrap_or(TaskClass::Balanced);
        let class_rank = match sibling_class {
            TaskClass::Latency => 1,
            TaskClass::Balanced => 2,
            TaskClass::Throughput => 3,
        };
        rank = rank.max(class_rank);
        let remaining_ns = if sibling.current_task.is_some() {
            sibling.predicted_start_delay(now_ns)
        } else {
            request_ns
        };
        let penalty_ns = match class {
            TaskClass::Latency => remaining_ns.min(request_ns),
            TaskClass::Balanced => remaining_ns.min(request_ns) / 2,
            TaskClass::Throughput => 0,
        };
        delay_ns = delay_ns.max(penalty_ns);
    }
    (rank, delay_ns, busy)
}

fn candidate(
    task: TaskPlacement<'_>,
    cpu: usize,
    state: &CpuState,
    cpus: &[CpuState],
    topology: &CpuTopology,
    now_ns: u64,
) -> Option<Candidate> {
    if !task.affinity.contains(cpu) {
        return None;
    }
    let preempt = task.preemptible.contains(cpu);
    if preempt {
        if !state.is_urgent_fillable() {
            return None;
        }
    } else if !state.is_fillable() {
        return None;
    }

    let cpu = cpu as u32;
    let descriptor = topology.cpu(cpu)?;
    let preemption = if preempt {
        Some(PreemptionVictim {
            task: state.current_task?,
            class: state.current_class?,
        })
    } else {
        None
    };
    let predicted_start_delay_ns = if preempt {
        0
    } else {
        state.predicted_start_delay(now_ns)
    };
    let (sibling_rank, sibling_delay_ns, sibling_busy) =
        sibling_load(task.class, task.request_ns, cpu, cpus, topology, now_ns);
    let locality_rank = if task.previous_cpu == Some(cpu) {
        0
    } else if task.home_cpu == Some(cpu) {
        1
    } else if task.home_llc == Some(descriptor.llc_id) {
        2
    } else {
        3
    };
    Some(Candidate {
        cpu,
        preemption,
        predicted_start_delay_ns,
        completion_delay_ns: predicted_start_delay_ns.saturating_add(sibling_delay_ns),
        sibling_rank,
        sibling_busy,
        locality_rank,
    })
}

/// Chooses an affinity-compatible CPU using deadline feasibility and locality hysteresis.
///
/// The returned CPU is a hint until BPF revalidates online state and the task's
/// live `cpus_ptr`. A small delay improvement does not justify migration, and
/// non-preemptive service wins whenever it can still satisfy the latency target.
pub fn choose_cpu(
    task: TaskPlacement<'_>,
    cpus: &[CpuState],
    topology: &CpuTopology,
    now_ns: u64,
) -> Option<PlacementDecision> {
    let mut best_delay_ns = None;
    let mut has_deadline_candidate = false;
    for (cpu, state) in cpus.iter().enumerate() {
        let Some(candidate) = candidate(task, cpu, state, cpus, topology, now_ns) else {
            continue;
        };
        best_delay_ns = Some(
            best_delay_ns.map_or(candidate.completion_delay_ns, |best: u64| {
                best.min(candidate.completion_delay_ns)
            }),
        );
        has_deadline_candidate |= task
            .max_completion_delay_ns
            .is_some_and(|limit| candidate.completion_delay_ns <= limit);
    }
    let best_delay_ns = best_delay_ns?;
    let delay_limit_ns = best_delay_ns.saturating_add(task.migration_hysteresis_ns);

    cpus.iter()
        .enumerate()
        .filter_map(|(cpu, state)| candidate(task, cpu, state, cpus, topology, now_ns))
        .filter(|candidate| candidate.completion_delay_ns <= delay_limit_ns)
        .filter(|candidate| {
            !has_deadline_candidate
                || task
                    .max_completion_delay_ns
                    .is_some_and(|limit| candidate.completion_delay_ns <= limit)
        })
        .min_by_key(|candidate| {
            let preempt_rank = u8::from(candidate.preemption.is_some());
            let victim_rank = match candidate.preemption.map(|victim| victim.class) {
                Some(TaskClass::Throughput) => 0,
                Some(TaskClass::Balanced) => 1,
                Some(TaskClass::Latency) => 2,
                None => 0,
            };
            let (policy_rank, secondary_rank) = if task.class == TaskClass::Latency {
                (candidate.sibling_rank, candidate.locality_rank)
            } else {
                (candidate.locality_rank, candidate.sibling_rank)
            };
            (
                preempt_rank,
                victim_rank,
                policy_rank,
                secondary_rank,
                candidate.completion_delay_ns,
                candidate.cpu,
            )
        })
        .map(|candidate| PlacementDecision {
            cpu: candidate.cpu,
            preemption: candidate.preemption,
            predicted_start_delay_ns: candidate.predicted_start_delay_ns,
            sibling_busy: candidate.sibling_busy,
        })
}

#[cfg(test)]
mod tests {
    use super::{choose_cpu, CpuState, PlacementDecision, PreemptionVictim, TaskPlacement};
    use crate::identity::{TaskClass, TaskKey};
    use crate::topology::{CpuMask, CpuTopology};

    fn placement<'a>(
        class: TaskClass,
        previous_cpu: Option<u32>,
        home_cpu: Option<u32>,
        affinity: &'a CpuMask,
        preemptible: &'a CpuMask,
    ) -> TaskPlacement<'a> {
        let (request_ns, migration_hysteresis_ns) = match class {
            TaskClass::Latency => (1_000_000, 250_000),
            TaskClass::Balanced => (4_000_000, 500_000),
            TaskClass::Throughput => (8_000_000, 2_000_000),
        };
        TaskPlacement {
            class,
            request_ns,
            previous_cpu,
            home_cpu,
            home_llc: Some(0),
            affinity,
            preemptible,
            migration_hysteresis_ns,
            max_completion_delay_ns: None,
        }
    }

    /// Latency work chooses an immediately idle CPU over a busy previous CPU.
    #[test]
    fn latency_prefers_short_start_delay() {
        let topology = CpuTopology::flat(2);
        let mut cpus = vec![CpuState::from_topology(true), CpuState::from_topology(true)];
        cpus[0].current_task = TaskKey::new(10, 10);
        cpus[0].current_slice_ns = 4_000_000;
        cpus[0].current_started_ns = 1;
        cpus[1].idle = true;
        let affinity = CpuMask::all(2);
        let preemptible = CpuMask::none(2);

        assert_eq!(
            choose_cpu(
                placement(
                    TaskClass::Latency,
                    Some(0),
                    Some(0),
                    &affinity,
                    &preemptible
                ),
                &cpus,
                &topology,
                1,
            ),
            Some(PlacementDecision {
                cpu: 1,
                preemption: None,
                predicted_start_delay_ns: 0,
                sibling_busy: false,
            })
        );
    }

    #[test]
    fn latency_keeps_locality_when_delay_gain_is_small() {
        let topology = CpuTopology::flat(2);
        let mut cpus = vec![CpuState::from_topology(true), CpuState::from_topology(true)];
        cpus[0].current_task = TaskKey::new(10, 10);
        cpus[0].current_slice_ns = 100_000;
        cpus[1].idle = true;
        let affinity = CpuMask::all(2);
        let preemptible = CpuMask::none(2);

        assert_eq!(
            choose_cpu(
                placement(
                    TaskClass::Latency,
                    Some(0),
                    Some(0),
                    &affinity,
                    &preemptible
                ),
                &cpus,
                &topology,
                0,
            ),
            Some(PlacementDecision {
                cpu: 0,
                preemption: None,
                predicted_start_delay_ns: 100_000,
                sibling_busy: false,
            })
        );
    }

    /// A staged slot is never considered fillable, enforcing depth one in Rust.
    #[test]
    fn excludes_cpu_with_staged_dispatch() {
        let topology = CpuTopology::flat(1);
        let mut cpu = CpuState::from_topology(true);
        cpu.staged_dispatch = Some(1);
        let affinity = CpuMask::all(1);
        let preemptible = CpuMask::none(1);
        assert_eq!(
            choose_cpu(
                placement(TaskClass::Balanced, None, None, &affinity, &preemptible),
                &[cpu],
                &topology,
                0,
            ),
            None
        );
    }

    #[test]
    fn urgent_lane_can_bypass_an_occupied_normal_slot() {
        let topology = CpuTopology::flat(1);
        let mut cpu = CpuState::from_topology(true);
        let victim = TaskKey::new(10, 10).unwrap();
        cpu.current_task = Some(victim);
        cpu.current_class = Some(TaskClass::Throughput);
        cpu.staged_dispatch = Some(1);
        let affinity = CpuMask::all(1);
        let preemptible = CpuMask::all(1);
        assert_eq!(
            choose_cpu(
                placement(TaskClass::Latency, None, None, &affinity, &preemptible),
                &[cpu],
                &topology,
                0,
            ),
            Some(PlacementDecision {
                cpu: 0,
                preemption: Some(PreemptionVictim {
                    task: victim,
                    class: TaskClass::Throughput,
                }),
                predicted_start_delay_ns: 0,
                sibling_busy: false,
            })
        );
    }

    #[test]
    fn deadline_filters_a_nonpreemptive_candidate_inside_hysteresis() {
        let topology = CpuTopology::flat(2);
        let victim = TaskKey::new(10, 10).unwrap();
        let mut cpus = vec![CpuState::from_topology(true), CpuState::from_topology(true)];
        cpus[0].current_task = Some(victim);
        cpus[0].current_class = Some(TaskClass::Throughput);
        cpus[0].current_slice_ns = 1_000_000;
        cpus[1].current_task = TaskKey::new(11, 11);
        cpus[1].current_class = Some(TaskClass::Balanced);
        cpus[1].current_slice_ns = 100_000;
        let affinity = CpuMask::all(2);
        let mut preemptible = CpuMask::none(2);
        preemptible.set(0, true);
        let mut task = placement(TaskClass::Latency, None, None, &affinity, &preemptible);
        task.max_completion_delay_ns = Some(50_000);

        assert_eq!(
            choose_cpu(task, &cpus, &topology, 0),
            Some(PlacementDecision {
                cpu: 0,
                preemption: Some(PreemptionVictim {
                    task: victim,
                    class: TaskClass::Throughput,
                }),
                predicted_start_delay_ns: 0,
                sibling_busy: false,
            })
        );
    }

    #[test]
    fn ordinary_throughput_placement_keeps_locality_when_delay_is_bounded() {
        let topology = CpuTopology::flat(2);
        let mut cpus = vec![CpuState::from_topology(true), CpuState::from_topology(true)];
        cpus[0].current_task = TaskKey::new(10, 10);
        cpus[0].current_class = Some(TaskClass::Throughput);
        cpus[0].current_slice_ns = 1_000_000;
        cpus[1].idle = true;
        let affinity = CpuMask::all(2);
        let preemptible = CpuMask::none(2);

        assert_eq!(
            choose_cpu(
                placement(
                    TaskClass::Throughput,
                    Some(0),
                    Some(0),
                    &affinity,
                    &preemptible,
                ),
                &cpus,
                &topology,
                0,
            ),
            Some(PlacementDecision {
                cpu: 0,
                preemption: None,
                predicted_start_delay_ns: 1_000_000,
                sibling_busy: false,
            })
        );
    }

    #[test]
    fn latency_avoids_a_throughput_smt_sibling() {
        let topology = CpuTopology::for_test(&[(0, 0, 0), (0, 0, 0), (0, 1, 0)]);
        let mut cpus = vec![
            CpuState::from_topology(true),
            CpuState::from_topology(true),
            CpuState::from_topology(true),
        ];
        cpus[0].idle = true;
        cpus[1].current_task = TaskKey::new(10, 10);
        cpus[1].current_class = Some(TaskClass::Throughput);
        cpus[1].current_slice_ns = 8_000_000;
        cpus[2].idle = true;
        let affinity = CpuMask::all(3);
        let preemptible = CpuMask::none(3);

        assert_eq!(
            choose_cpu(
                placement(
                    TaskClass::Latency,
                    Some(0),
                    Some(0),
                    &affinity,
                    &preemptible
                ),
                &cpus,
                &topology,
                0,
            ),
            Some(PlacementDecision {
                cpu: 2,
                preemption: None,
                predicted_start_delay_ns: 0,
                sibling_busy: false,
            })
        );
    }
}
