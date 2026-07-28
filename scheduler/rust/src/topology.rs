// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashSet;
use std::fs;
use std::io;

/// Maximum CPU identifier supported by the shared BPF ABI.
pub const MAX_CPUS: usize = 1024;

/// Static logical CPU attributes needed to initialize BPF state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuDescriptor {
    /// Linux logical CPU ID and index into the BPF CPU array.
    pub id: u32,
    /// Whether sysfs reported the CPU online during discovery.
    pub online: bool,
}

/// Dense possible/online CPU snapshot discovered before BPF attach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuTopology {
    cpus: Vec<CpuDescriptor>,
}

impl CpuTopology {
    /// Discovers possible CPUs and their current online state.
    pub fn discover() -> io::Result<Self> {
        let possible = parse_cpu_list(&fs::read_to_string("/sys/devices/system/cpu/possible")?)?;
        let cpu_count = possible
            .iter()
            .copied()
            .max()
            .map(|cpu| cpu + 1)
            .unwrap_or(1)
            .min(MAX_CPUS);
        let online: HashSet<_> =
            parse_cpu_list(&fs::read_to_string("/sys/devices/system/cpu/online")?)?
                .into_iter()
                .collect();
        Ok(Self {
            cpus: (0..cpu_count)
                .map(|cpu| CpuDescriptor {
                    id: cpu as u32,
                    online: online.contains(&cpu),
                })
                .collect(),
        })
    }

    /// Constructs a dense online topology for deterministic tests.
    pub fn flat(cpu_count: usize) -> Self {
        let count = cpu_count.clamp(1, MAX_CPUS);
        Self {
            cpus: (0..count)
                .map(|cpu| CpuDescriptor {
                    id: cpu as u32,
                    online: true,
                })
                .collect(),
        }
    }

    pub fn cpu_count(&self) -> usize {
        self.cpus.len()
    }

    pub fn cpus(&self) -> impl Iterator<Item = &CpuDescriptor> {
        self.cpus.iter()
    }
}

/// Parses Linux cpulist syntax such as `0-3,8,10-11` into sorted CPU IDs.
pub fn parse_cpu_list(input: &str) -> io::Result<Vec<usize>> {
    let mut cpus = Vec::new();
    for segment in input
        .trim()
        .split(',')
        .filter(|segment| !segment.is_empty())
    {
        if let Some((start, end)) = segment.split_once('-') {
            let start = parse_cpu_id(start)?;
            let end = parse_cpu_id(end)?;
            if start > end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cpulist range starts after it ends",
                ));
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(parse_cpu_id(segment)?);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

fn parse_cpu_id(value: &str) -> io::Result<usize> {
    value.trim().parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid CPU id {value:?}: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_cpu_list, CpuTopology};

    #[test]
    fn parses_linux_cpu_lists() {
        assert_eq!(
            parse_cpu_list("0-2,5,7-8\n").unwrap(),
            vec![0, 1, 2, 5, 7, 8]
        );
    }

    #[test]
    fn flat_topology_is_dense_and_online() {
        let topology = CpuTopology::flat(3);
        assert_eq!(topology.cpu_count(), 3);
        assert!(topology.cpus().all(|cpu| cpu.online));
    }
}
