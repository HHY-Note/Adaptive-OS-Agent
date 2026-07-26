// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::identity::{ProcessKey, TaskClass, TaskKey};

/// One deterministic behavior decision with bounded local confidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BehaviorAssessment {
    /// Scheduling class supported by the current runtime window.
    pub class: TaskClass,
    /// Conservative confidence in per-mille units.
    pub confidence_per_mille: u16,
}

/// Scheduler-provided quality marker for one behavior window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowQuality {
    /// Event continuity was sufficient for behavior voting.
    Good,
    /// Event overflow, gaps, or timestamp reversal invalidated this window.
    Bad,
}

/// Fixed-period execution facts received over the local scheduler socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BehaviorWindow {
    /// Stable task lifetime.
    pub task: TaskKey,
    /// Stable owning process image.
    pub process: ProcessKey,
    /// Monotonic report sequence within this task lifetime.
    pub window_sequence: u64,
    /// First monotonic timestamp represented by this report.
    pub window_start_ns: u64,
    /// Closing monotonic timestamp.
    pub window_end_ns: u64,
    /// Actual runtime accumulated from STOP events.
    pub runtime_ns: u64,
    /// Enqueue-to-running delay accumulated by the scheduler.
    pub runnable_wait_ns: u64,
    /// Time spent sleeping after voluntary blocking.
    pub sleep_ns: u64,
    /// Number of accepted runnable incarnations.
    pub enqueue_count: u64,
    /// Number of enqueues following a voluntary block.
    pub wakeup_count: u64,
    /// Number of actual starts.
    pub run_count: u64,
    /// Runtime samples in <250 us, <1 ms, <4 ms, and >=4 ms bins.
    pub run_burst_histogram: [u64; 4],
    /// Runnable-wait samples using the same four bins.
    pub wait_histogram: [u64; 4],
    /// Stops that remained runnable after using at least 90% of their slice.
    pub slice_exhaustion_count: u64,
    /// Stops that blocked rather than remaining runnable.
    pub voluntary_block_count: u64,
    /// Number of observed CPU migrations.
    pub migration_count: u64,
    /// Number of starts on the previous CPU.
    pub previous_cpu_hit_count: u64,
    /// Age of this stable task lifetime at the end of the window.
    pub task_age_ns: u64,
    /// Whether this report can participate in classification evidence.
    pub quality: WindowQuality,
}

/// Derives a high-precision class from one scheduler behavior window.
pub(crate) fn classify_window(window: BehaviorWindow) -> Option<BehaviorAssessment> {
    const MIN_TASK_AGE_NS: u64 = 2_000_000_000;
    const MIN_RUNTIME_NS: u64 = 20_000_000;
    const MIN_SAMPLES: u64 = 32;
    const MIN_BALANCED_RUNS: u64 = 64;

    if window.quality != WindowQuality::Good
        || window.window_sequence == 0
        || window.window_end_ns <= window.window_start_ns
        || window.task_age_ns < MIN_TASK_AGE_NS
    {
        return None;
    }
    if window.enqueue_count.max(window.run_count) < MIN_SAMPLES
        && window.wakeup_count < MIN_SAMPLES
        && window.runtime_ns < MIN_RUNTIME_NS
    {
        return None;
    }

    let duration = window.window_end_ns - window.window_start_ns;
    let utilization_per_mille = ratio_per_mille(window.runtime_ns, duration);
    let short_bursts = window.run_burst_histogram[0].saturating_add(window.run_burst_histogram[1]);
    let long_bursts = window.run_burst_histogram[2].saturating_add(window.run_burst_histogram[3]);
    let short_per_mille = ratio_per_mille(short_bursts, window.run_count);
    let long_per_mille = ratio_per_mille(long_bursts, window.run_count);
    let wakeup_per_mille = ratio_per_mille(window.wakeup_count, window.enqueue_count);
    let block_per_mille = ratio_per_mille(window.voluntary_block_count, window.run_count);
    let exhaustion_per_mille = ratio_per_mille(window.slice_exhaustion_count, window.run_count);

    if wakeup_per_mille >= 500
        && short_per_mille >= 700
        && block_per_mille >= 500
        && exhaustion_per_mille <= 100
        && utilization_per_mille <= 500
        && window.runnable_wait_ns > 0
    {
        return Some(BehaviorAssessment {
            class: TaskClass::Latency,
            confidence_per_mille: 900,
        });
    }
    if window.run_count > 0
        && long_per_mille >= 700
        && exhaustion_per_mille >= 500
        && block_per_mille <= 100
    {
        return Some(BehaviorAssessment {
            class: TaskClass::Throughput,
            confidence_per_mille: 900,
        });
    }

    let balanced_signals = [
        (200..=800).contains(&utilization_per_mille),
        (150..=850).contains(&block_per_mille),
        short_per_mille >= 200 && long_per_mille >= 200,
        (100..=800).contains(&wakeup_per_mille),
        (100..=600).contains(&exhaustion_per_mille),
    ]
    .into_iter()
    .filter(|signal| *signal)
    .count();
    if window.run_count >= MIN_BALANCED_RUNS && balanced_signals >= 3 {
        return Some(BehaviorAssessment {
            class: TaskClass::Balanced,
            confidence_per_mille: 700 + 50 * (balanced_signals as u16 - 3),
        });
    }
    None
}

fn ratio_per_mille(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1000)
        .saturating_div(denominator)
        .min(1000)
}

#[cfg(test)]
mod tests {
    use super::{classify_window, BehaviorAssessment, BehaviorWindow, WindowQuality};
    use crate::identity::{ProcessKey, TaskClass, TaskKey};

    fn mixed_window() -> BehaviorWindow {
        BehaviorWindow {
            task: TaskKey {
                tid: 11,
                task_cookie: 12,
            },
            process: ProcessKey {
                tgid: 11,
                process_cookie: 13,
                exec_generation: 1,
            },
            window_sequence: 2,
            window_start_ns: 1_000_000_000,
            window_end_ns: 2_000_000_000,
            runtime_ns: 500_000_000,
            runnable_wait_ns: 10_000_000,
            sleep_ns: 400_000_000,
            enqueue_count: 100,
            wakeup_count: 40,
            run_count: 100,
            run_burst_histogram: [25, 25, 25, 25],
            wait_histogram: [25, 25, 25, 25],
            slice_exhaustion_count: 30,
            voluntary_block_count: 40,
            migration_count: 5,
            previous_cpu_hit_count: 95,
            task_age_ns: 2_000_000_000,
            quality: WindowQuality::Good,
        }
    }

    #[test]
    fn classifies_sustained_mixed_behavior_as_balanced() {
        assert_eq!(
            classify_window(mixed_window()),
            Some(BehaviorAssessment {
                class: TaskClass::Balanced,
                confidence_per_mille: 800,
            })
        );
    }

    #[test]
    fn behavior_evidence_starts_at_two_seconds() {
        let mut too_young = mixed_window();
        too_young.task_age_ns -= 1;

        assert_eq!(classify_window(too_young), None);
        assert!(classify_window(mixed_window()).is_some());
    }

    #[test]
    fn weak_mixed_window_remains_unknown() {
        let mut weak = mixed_window();
        weak.run_count = 10;
        weak.enqueue_count = 10;
        weak.wakeup_count = 4;
        weak.runtime_ns = 10_000_000;

        assert_eq!(classify_window(weak), None);
    }

    #[test]
    fn classifies_contended_slice_exhausting_work_as_throughput() {
        let mut contended = mixed_window();
        contended.runtime_ns = 100_000_000;
        contended.run_burst_histogram = [0, 0, 10, 90];
        contended.slice_exhaustion_count = 90;
        contended.voluntary_block_count = 2;

        assert_eq!(
            classify_window(contended),
            Some(BehaviorAssessment {
                class: TaskClass::Throughput,
                confidence_per_mille: 900,
            })
        );
    }
}
