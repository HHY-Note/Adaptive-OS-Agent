// SPDX-License-Identifier: Apache-2.0

//! Safe admission of ordinary userspace threads into partial sched_ext mode.

use std::mem;

use crate::metadata::{read_process, read_task_start_time, read_threads, ProcessMetadata};

/// Linux UAPI policy number for SCHED_EXT.
const SCHED_EXT: i32 = 7;

/// Counters from one bounded admission attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionStats {
    pub threads_examined: usize,
    pub threads_admitted: usize,
    pub threads_already_ext: usize,
    pub threads_skipped_policy: usize,
    pub identity_races: usize,
    pub errors: usize,
}

impl AdmissionStats {
    pub fn merge(&mut self, other: Self) {
        self.threads_examined = self.threads_examined.saturating_add(other.threads_examined);
        self.threads_admitted = self.threads_admitted.saturating_add(other.threads_admitted);
        self.threads_already_ext = self
            .threads_already_ext
            .saturating_add(other.threads_already_ext);
        self.threads_skipped_policy = self
            .threads_skipped_policy
            .saturating_add(other.threads_skipped_policy);
        self.identity_races = self.identity_races.saturating_add(other.identity_races);
        self.errors = self.errors.saturating_add(other.errors);
    }
}

/// Admits every stable SCHED_NORMAL thread in one ordinary process image.
///
/// Explicit non-default policies are left untouched. Any read, identity, or
/// syscall failure is fail-closed: that thread remains on the native scheduler.
pub fn admit_process(metadata: &ProcessMetadata, excluded_tgids: &[u32]) -> AdmissionStats {
    let mut stats = AdmissionStats::default();
    if !is_admissible_process(metadata, excluded_tgids) {
        return stats;
    }

    match read_process(metadata.instance.tgid) {
        Ok(Some(current)) if current.instance == metadata.instance => {}
        Ok(_) => {
            stats.identity_races += 1;
            return stats;
        }
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    }
    let threads = match read_threads(metadata.instance.tgid) {
        Ok(threads) => threads,
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    };
    for thread in threads {
        stats.threads_examined += 1;
        let start_time = match read_task_start_time(metadata.instance.tgid, thread.tid) {
            Ok(start_time) => start_time,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        let tid = match libc::pid_t::try_from(thread.tid) {
            Ok(tid) => tid,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };

        // SAFETY: sched_getscheduler only reads scheduler state for a numeric TID.
        let policy = unsafe { libc::sched_getscheduler(tid) };
        if policy < 0 {
            stats.errors += 1;
            continue;
        }
        if policy == SCHED_EXT {
            stats.threads_already_ext += 1;
            continue;
        }
        if policy != libc::SCHED_OTHER {
            stats.threads_skipped_policy += 1;
            continue;
        }

        // Zero is a valid initialization for every platform sched_param field.
        let mut parameter: libc::sched_param = unsafe { mem::zeroed() };
        parameter.sched_priority = 0;
        // SAFETY: parameter is initialized and points to a live sched_param.
        if unsafe { libc::sched_setscheduler(tid, SCHED_EXT, &parameter) } != 0 {
            stats.errors += 1;
            continue;
        }
        match read_task_start_time(metadata.instance.tgid, thread.tid) {
            Ok(current_start) if current_start == start_time => stats.threads_admitted += 1,
            _ => stats.identity_races += 1,
        }
    }

    match read_process(metadata.instance.tgid) {
        Ok(Some(after)) if after.instance == metadata.instance => {}
        _ => stats.identity_races += 1,
    }
    stats
}

fn is_admissible_process(metadata: &ProcessMetadata, excluded_tgids: &[u32]) -> bool {
    metadata.instance.tgid > 1
        && !excluded_tgids.contains(&metadata.instance.tgid)
        && metadata.is_ordinary()
}

#[cfg(test)]
mod tests {
    use super::is_admissible_process;
    use crate::metadata::{ProcessInstanceKey, ProcessMetadata};

    fn metadata(tgid: u32) -> ProcessMetadata {
        ProcessMetadata {
            instance: ProcessInstanceKey {
                tgid,
                start_time_ticks: 10,
            },
            parent: None,
            comm: "worker".into(),
            command: vec!["/usr/bin/worker".into()],
            executable: Some("/usr/bin/worker".into()),
            cgroups: Vec::new(),
            uid: Some(1000),
        }
    }

    #[test]
    fn admits_only_unprotected_ordinary_processes() {
        assert!(is_admissible_process(&metadata(100), &[200]));
        assert!(!is_admissible_process(&metadata(1), &[]));
        assert!(!is_admissible_process(&metadata(100), &[100]));

        let mut nonordinary = metadata(101);
        nonordinary.command.clear();
        nonordinary.executable = None;
        assert!(!is_admissible_process(&nonordinary, &[]));
    }
}
