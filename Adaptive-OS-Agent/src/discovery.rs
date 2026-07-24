// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::io;

use crate::metadata::{read_process, ProcessInstanceKey, ProcessMetadata};

/// Result of one bounded `/proc` discovery or reconciliation pass.
#[derive(Clone, Debug, Default)]
pub struct DiscoverySnapshot {
    /// Ordinary process metadata keyed by start-time-stable proc identity.
    pub processes: HashMap<ProcessInstanceKey, ProcessMetadata>,
    /// Numeric process directories examined in this pass.
    pub examined: usize,
    /// Entries skipped because they exited or were unreadable during the pass.
    pub skipped: usize,
}

impl DiscoverySnapshot {
    /// Returns metadata in deterministic process-instance order for LLM batching.
    pub fn sorted_processes(&self) -> Vec<ProcessMetadata> {
        let mut values: Vec<_> = self.processes.values().cloned().collect();
        values.sort_unstable_by_key(|metadata| metadata.instance);
        values
    }
}

/// Scans `/proc` once, reading all ordinary process metadata without remote calls.
///
/// This intentionally gathers many processes before batching them to DeepSeek;
/// no per-process HTTP request is performed on the startup path.
pub fn scan_processes(excluded_tgids: &[u32]) -> io::Result<DiscoverySnapshot> {
    let mut snapshot = DiscoverySnapshot::default();
    for entry in fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                snapshot.skipped += 1;
                continue;
            }
        };
        let Some(tgid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if excluded_tgids.contains(&tgid) {
            continue;
        }
        snapshot.examined += 1;
        match read_process(tgid) {
            Ok(Some(metadata)) => {
                snapshot.processes.insert(metadata.instance, metadata);
            }
            Ok(None) | Err(_) => snapshot.skipped += 1,
        }
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::scan_processes;

    /// The current test process is ordinary and should be visible to discovery.
    #[test]
    fn discovers_current_process() {
        let snapshot = scan_processes(&[]).unwrap();
        assert!(snapshot
            .processes
            .keys()
            .any(|instance| instance.tgid == std::process::id()));
    }
}
