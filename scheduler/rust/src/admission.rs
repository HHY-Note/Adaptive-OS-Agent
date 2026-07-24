// SPDX-License-Identifier: GPL-2.0-only

//! Reusable time budget for bounded latency overrides and preemption cost.

/// Nanosecond token bucket refilled as a percentage of online CPU capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeBudget {
    tokens_ns: u64,
    capacity_ns: u64,
    capacity_per_cpu_ns: u64,
    last_update_ns: u64,
}

impl TimeBudget {
    /// Starts full so the scheduler can absorb one bounded startup burst.
    pub fn new(online_cpus: usize, capacity_per_cpu_ns: u64) -> Self {
        let capacity_ns = capacity(online_cpus, capacity_per_cpu_ns);
        Self {
            tokens_ns: capacity_ns,
            capacity_ns,
            capacity_per_cpu_ns,
            last_update_ns: 0,
        }
    }

    /// Refills at `online_cpus * guarantee_percent` CPU time per wall-clock time.
    pub fn refresh(&mut self, now_ns: u64, online_cpus: usize, guarantee_percent: u32) {
        let new_capacity = capacity(online_cpus, self.capacity_per_cpu_ns);
        self.capacity_ns = new_capacity;
        self.tokens_ns = self.tokens_ns.min(new_capacity);

        if self.last_update_ns == 0 {
            self.last_update_ns = now_ns;
            return;
        }
        let elapsed_ns = now_ns.saturating_sub(self.last_update_ns);
        self.last_update_ns = self.last_update_ns.max(now_ns);
        let refill_ns = (elapsed_ns as u128)
            .saturating_mul(online_cpus as u128)
            .saturating_mul(guarantee_percent as u128)
            .saturating_div(100)
            .min(u64::MAX as u128) as u64;
        self.tokens_ns = self.tokens_ns.saturating_add(refill_ns).min(new_capacity);
    }

    /// Returns whether a complete EEVDF request fits the current bypass budget.
    pub const fn can_reserve(&self, request_ns: u64) -> bool {
        request_ns <= self.tokens_ns
    }

    /// Charges one admitted request. Callers refund it if dispatch is cancelled.
    pub fn reserve(&mut self, request_ns: u64) -> bool {
        if !self.can_reserve(request_ns) {
            return false;
        }
        self.tokens_ns -= request_ns;
        true
    }

    /// Refunds a reservation that produced no service.
    pub fn cancel(&mut self, planned_ns: u64) {
        self.tokens_ns = self
            .tokens_ns
            .saturating_add(planned_ns)
            .min(self.capacity_ns);
    }

    /// Reconciles a planned charge with the service that actually ran.
    pub fn complete(&mut self, planned_ns: u64, actual_ns: u64) {
        if actual_ns <= planned_ns {
            self.cancel(planned_ns - actual_ns);
        } else {
            self.tokens_ns = self.tokens_ns.saturating_sub(actual_ns - planned_ns);
        }
    }
}

fn capacity(online_cpus: usize, capacity_per_cpu_ns: u64) -> u64 {
    (online_cpus as u128)
        .saturating_mul(capacity_per_cpu_ns as u128)
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::TimeBudget;

    #[test]
    fn startup_burst_is_bounded_by_online_cpu_capacity() {
        let mut budget = TimeBudget::new(2, 1_000);
        assert!(budget.reserve(1_000));
        assert!(budget.reserve(1_000));
        assert!(!budget.reserve(1));
    }

    #[test]
    fn refill_and_actual_service_are_reconciled() {
        let mut budget = TimeBudget::new(1, 1_000);
        assert!(budget.reserve(1_000));
        budget.refresh(1_000, 1, 10);
        budget.refresh(2_000, 1, 10);
        assert!(budget.reserve(100));
        budget.complete(100, 40);
        assert!(budget.reserve(60));
    }

    #[test]
    fn cancelled_reservation_returns_its_tokens() {
        let mut budget = TimeBudget::new(1, 1_000);
        assert!(budget.reserve(1_000));
        budget.cancel(1_000);
        assert!(budget.reserve(1_000));
    }
}
