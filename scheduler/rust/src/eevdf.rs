// SPDX-License-Identifier: GPL-2.0-only

//! Shared EEVDF arithmetic for tasks and the three class pools.

use crate::identity::TaskClass;

/// Equal default weight keeps class bandwidth fair; request length expresses latency.
const DEFAULT_WEIGHT: u64 = 1024;

/// One class entity in the root EEVDF scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootEntity {
    /// Actual normalized service completed by this class.
    vruntime_ns: u64,
    /// Planned service already submitted to CPUs but not completed.
    reserved_ns: u64,
    /// Stable proportional-share weight.
    weight: u64,
    /// Whether the class had queued work at the previous update.
    active: bool,
}

impl Default for RootEntity {
    fn default() -> Self {
        Self {
            vruntime_ns: 0,
            reserved_ns: 0,
            weight: DEFAULT_WEIGHT,
            active: false,
        }
    }
}

impl RootEntity {
    fn effective_vruntime(self) -> u64 {
        self.vruntime_ns.saturating_add(self.reserved_ns)
    }

    fn deadline(self, request_ns: u64) -> u64 {
        self.effective_vruntime()
            .saturating_add(scale_request(request_ns, self.weight))
    }
}

/// Root-level selection and its virtual finish deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootDecision {
    /// Selected workload pool.
    pub class: TaskClass,
    /// Pool virtual deadline at selection time.
    pub deadline_ns: u64,
}

/// EEVDF scheduler treating each non-empty workload pool as one entity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RootEevdf {
    entities: [RootEntity; 3],
    virtual_time_ns: u64,
}

impl RootEevdf {
    /// Updates active state and limits a returning pool to one request of saved lag.
    pub fn update_activity(&mut self, active: [bool; 3], requests_ns: [u64; 3]) {
        for class in TaskClass::all() {
            let index = class.index();
            let entity = &mut self.entities[index];
            if active[index] && !entity.active {
                let lag_cap = scale_request(requests_ns[index], entity.weight);
                entity.vruntime_ns = entity
                    .vruntime_ns
                    .max(self.virtual_time_ns.saturating_sub(lag_cap));
            }
            entity.active = active[index];
        }
    }

    /// Selects the eligible pool with the earliest virtual deadline.
    pub fn select(&mut self, available: [bool; 3], requests_ns: [u64; 3]) -> Option<RootDecision> {
        let mut eligible = self.earliest(available, requests_ns);
        if eligible.is_none() {
            let next = TaskClass::all()
                .into_iter()
                .filter(|class| available[class.index()])
                .map(|class| self.entities[class.index()].effective_vruntime())
                .min()?;
            self.virtual_time_ns = self.virtual_time_ns.max(next);
            eligible = self.earliest(available, requests_ns);
        }
        eligible
    }

    /// Accounts planned service immediately so one refill cannot monopolize CPUs.
    pub fn reserve(&mut self, class: TaskClass, planned_runtime_ns: u64) {
        let entity = &mut self.entities[class.index()];
        entity.reserved_ns = entity.reserved_ns.saturating_add(planned_runtime_ns);
    }

    /// Removes a reservation that never produced runtime.
    pub fn cancel(&mut self, class: TaskClass, planned_runtime_ns: u64) {
        let entity = &mut self.entities[class.index()];
        entity.reserved_ns = entity.reserved_ns.saturating_sub(planned_runtime_ns);
    }

    /// Replaces a planned reservation with actual normalized service.
    pub fn complete(&mut self, class: TaskClass, planned_runtime_ns: u64, actual_runtime_ns: u64) {
        self.cancel(class, planned_runtime_ns);
        let entity = &mut self.entities[class.index()];
        entity.vruntime_ns = entity.vruntime_ns.saturating_add(actual_runtime_ns);
    }

    /// Returns the current virtual finish deadline of one class request.
    pub fn deadline(&self, class: TaskClass, request_ns: u64) -> u64 {
        self.entities[class.index()].deadline(request_ns)
    }

    fn earliest(&self, available: [bool; 3], requests_ns: [u64; 3]) -> Option<RootDecision> {
        TaskClass::all()
            .into_iter()
            .filter(|class| available[class.index()])
            .filter(|class| {
                self.entities[class.index()].effective_vruntime() <= self.virtual_time_ns
            })
            .map(|class| RootDecision {
                class,
                deadline_ns: self.entities[class.index()].deadline(requests_ns[class.index()]),
            })
            .min_by_key(|decision| (decision.deadline_ns, decision.class.index()))
    }
}

/// Preserves bounded normalized lag when a task changes pools.
pub fn rebase_vruntime(
    source_virtual_time_ns: u64,
    target_virtual_time_ns: u64,
    vruntime_ns: u64,
    source_request_ns: u64,
    target_request_ns: u64,
) -> u64 {
    let lag = source_virtual_time_ns as i128 - vruntime_ns as i128;
    let bounded_source = lag.clamp(-(source_request_ns as i128), source_request_ns as i128);
    let bounded_target =
        bounded_source.clamp(-(target_request_ns as i128), target_request_ns as i128);
    apply_lag(target_virtual_time_ns, bounded_target)
}

/// Limits sleep credit to one request while leaving negative lag to decay naturally.
pub fn place_vruntime(virtual_time_ns: u64, vruntime_ns: u64, request_ns: u64) -> u64 {
    vruntime_ns.max(virtual_time_ns.saturating_sub(request_ns))
}

fn scale_request(request_ns: u64, weight: u64) -> u64 {
    ((request_ns as u128)
        .saturating_mul(DEFAULT_WEIGHT as u128)
        .saturating_div(weight.max(1) as u128))
    .min(u64::MAX as u128) as u64
}

fn apply_lag(virtual_time_ns: u64, lag: i128) -> u64 {
    if lag >= 0 {
        virtual_time_ns.saturating_sub(lag as u64)
    } else {
        virtual_time_ns.saturating_add((-lag) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::{place_vruntime, rebase_vruntime, RootEevdf};
    use crate::identity::TaskClass;

    #[test]
    fn root_uses_deadline_then_service_eligibility() {
        let requests = [1, 4, 8];
        let active = [true; 3];
        let mut root = RootEevdf::default();
        root.update_activity(active, requests);

        let first = root.select(active, requests).unwrap();
        assert_eq!(first.class, TaskClass::Latency);
        root.reserve(first.class, requests[first.class.index()]);
        assert_eq!(
            root.select(active, requests).unwrap().class,
            TaskClass::Balanced
        );
    }

    #[test]
    fn reservations_bound_one_refill_fairly() {
        let requests = [1, 4, 8];
        let active = [true; 3];
        let mut root = RootEevdf::default();
        root.update_activity(active, requests);
        let mut selected = Vec::new();
        for _ in 0..6 {
            let decision = root.select(active, requests).unwrap();
            selected.push(decision.class);
            root.reserve(decision.class, requests[decision.class.index()]);
        }
        assert_eq!(selected[0], TaskClass::Latency);
        assert!(selected.contains(&TaskClass::Balanced));
        assert!(selected.contains(&TaskClass::Throughput));
    }

    #[test]
    fn sleep_and_class_change_preserve_only_bounded_lag() {
        assert_eq!(place_vruntime(10_000, 0, 1_000), 9_000);
        assert_eq!(rebase_vruntime(10_000, 20_000, 8_000, 1_000, 4_000), 19_000);
        assert_eq!(
            rebase_vruntime(10_000, 20_000, 14_000, 1_000, 4_000),
            21_000
        );
    }
}
