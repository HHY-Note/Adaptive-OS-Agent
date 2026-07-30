// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;

/// Maximum CPU identifier supported by the shared BPF ABI.
pub const MAX_CPUS: usize = 1024;

/// Static logical CPU attributes needed to initialize BPF state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuDescriptor {
    /// Linux logical CPU ID and index into the BPF CPU array.
    pub id: u32,
    /// Whether the CPU identifier is present in the kernel's possible set.
    pub possible: bool,
    /// Whether sysfs reported the CPU online during discovery.
    pub online: bool,
    /// Physical package reported by sysfs, or zero when unavailable.
    pub package_id: u32,
    /// Physical core identifier inside the package.
    pub core_id: u32,
    /// Last-level cache identifier inside the package.
    pub llc_id: u32,
    /// NUMA node containing this logical CPU.
    pub numa_id: u32,
    /// Dense scheduling domain formed from NUMA, LLC, and core type.
    pub domain_id: u32,
    /// Position in the core's thread-sibling list.
    pub smt_index: u32,
    /// Relative CPU capacity; homogeneous machines use 1024.
    pub capacity: u32,
    /// Kernel-reported core type, or zero on homogeneous/older systems.
    pub core_type: u32,
}

/// Dense possible/online CPU snapshot discovered before BPF attach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuTopology {
    cpus: Vec<CpuDescriptor>,
    domain_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DomainKey {
    numa_id: u32,
    package_id: u32,
    llc_id: u32,
    core_type: u32,
}

impl CpuTopology {
    /// Discovers possible CPUs and their current online state.
    pub fn discover() -> io::Result<Self> {
        Self::discover_from(Path::new("/sys/devices/system/cpu"))
    }

    fn discover_from(root: &Path) -> io::Result<Self> {
        let possible = parse_cpu_list(&fs::read_to_string(root.join("possible"))?)?;
        let possible_set: HashSet<_> = possible.iter().copied().collect();
        let cpu_count = possible
            .iter()
            .copied()
            .max()
            .map(|cpu| cpu + 1)
            .unwrap_or(1)
            .min(MAX_CPUS);
        let online: HashSet<_> = parse_cpu_list(&fs::read_to_string(root.join("online"))?)?
            .into_iter()
            .collect();
        let mut descriptors = Vec::with_capacity(cpu_count);
        for cpu in 0..cpu_count {
            let cpu_root = root.join(format!("cpu{cpu}"));
            let package_id = read_u32(cpu_root.join("topology/physical_package_id")).unwrap_or(0);
            let core_id = read_u32(cpu_root.join("topology/core_id")).unwrap_or(cpu as u32);
            let numa_id = discover_numa_id(&cpu_root).unwrap_or(package_id);
            let llc_id = discover_llc_id(&cpu_root, cpu as u32);
            let siblings = fs::read_to_string(cpu_root.join("topology/thread_siblings_list"))
                .ok()
                .and_then(|value| parse_cpu_list(&value).ok())
                .unwrap_or_else(|| vec![cpu]);
            let smt_index = siblings
                .iter()
                .position(|sibling| *sibling == cpu)
                .unwrap_or(0) as u32;
            let capacity = read_u32(cpu_root.join("cpu_capacity"))
                .filter(|value| *value > 0)
                .unwrap_or(1024);
            let core_type = read_u32(cpu_root.join("topology/core_type")).unwrap_or(0);
            descriptors.push(CpuDescriptor {
                id: cpu as u32,
                possible: possible_set.contains(&cpu),
                online: possible_set.contains(&cpu) && online.contains(&cpu),
                package_id,
                core_id,
                llc_id,
                numa_id,
                domain_id: 0,
                smt_index,
                capacity,
                core_type,
            });
        }

        let mut domains = BTreeMap::new();
        for cpu in descriptors.iter().filter(|cpu| cpu.online) {
            let key = DomainKey {
                numa_id: cpu.numa_id,
                package_id: cpu.package_id,
                llc_id: cpu.llc_id,
                core_type: cpu.core_type,
            };
            let next = domains.len() as u32;
            domains.entry(key).or_insert(next);
        }
        if domains.is_empty() {
            domains.insert(
                DomainKey {
                    numa_id: 0,
                    package_id: 0,
                    llc_id: 0,
                    core_type: 0,
                },
                0,
            );
        }
        for cpu in &mut descriptors {
            let key = DomainKey {
                numa_id: cpu.numa_id,
                package_id: cpu.package_id,
                llc_id: cpu.llc_id,
                core_type: cpu.core_type,
            };
            cpu.domain_id = domains.get(&key).copied().unwrap_or(0);
        }
        Ok(Self {
            cpus: descriptors,
            domain_count: domains.len() as u32,
        })
    }

    /// Constructs a dense online topology for deterministic tests.
    pub fn flat(cpu_count: usize) -> Self {
        let count = cpu_count.clamp(1, MAX_CPUS);
        Self {
            cpus: (0..count)
                .map(|cpu| CpuDescriptor {
                    id: cpu as u32,
                    possible: true,
                    online: true,
                    package_id: 0,
                    core_id: cpu as u32,
                    llc_id: 0,
                    numa_id: 0,
                    domain_id: 0,
                    smt_index: 0,
                    capacity: 1024,
                    core_type: 0,
                })
                .collect(),
            domain_count: 1,
        }
    }

    pub fn cpu_count(&self) -> usize {
        self.cpus.len()
    }

    pub fn cpus(&self) -> impl Iterator<Item = &CpuDescriptor> {
        self.cpus.iter()
    }

    pub fn domain_count(&self) -> u32 {
        self.domain_count
    }

    /// Returns the stable lowest possible CPU identifier for one physical core.
    pub fn core_leader_id(&self, cpu: &CpuDescriptor) -> u32 {
        if !cpu.possible {
            return cpu.id;
        }
        self.cpus
            .iter()
            .filter(|candidate| {
                candidate.possible
                    && candidate.package_id == cpu.package_id
                    && candidate.core_id == cpu.core_id
            })
            .map(|candidate| candidate.id)
            .min()
            .unwrap_or(cpu.id)
    }

    /// Returns one possible SMT peer, or the leader for a single-thread core.
    pub fn core_peer_id(&self, cpu: &CpuDescriptor) -> u32 {
        let leader = self.core_leader_id(cpu);
        if !cpu.possible {
            return leader;
        }
        self.cpus
            .iter()
            .filter(|candidate| {
                candidate.possible
                    && candidate.package_id == cpu.package_id
                    && candidate.core_id == cpu.core_id
                    && candidate.id != leader
            })
            .map(|candidate| candidate.id)
            .min()
            .unwrap_or(leader)
    }

    /// Returns one dense representative list covering every possible core.
    pub fn core_leaders(&self) -> Vec<u32> {
        self.cpus
            .iter()
            .filter(|cpu| cpu.possible && self.core_leader_id(cpu) == cpu.id)
            .map(|cpu| cpu.id)
            .collect()
    }
}

fn read_u32(path: impl AsRef<Path>) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn discover_numa_id(cpu_root: &Path) -> Option<u32> {
    fs::read_dir(cpu_root).ok()?.flatten().find_map(|entry| {
        entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix("node"))
            .and_then(|value| value.parse().ok())
    })
}

fn discover_llc_id(cpu_root: &Path, fallback: u32) -> u32 {
    let mut best: Option<(u32, u32)> = None;
    let Ok(entries) = fs::read_dir(cpu_root.join("cache")) else {
        return fallback;
    };
    for entry in entries.flatten() {
        let root = entry.path();
        let Some(level) = read_u32(root.join("level")) else {
            continue;
        };
        let cache_type = fs::read_to_string(root.join("type"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if cache_type == "instruction" {
            continue;
        }
        let id = read_u32(root.join("id")).or_else(|| {
            fs::read_to_string(root.join("shared_cpu_list"))
                .ok()
                .and_then(|value| parse_cpu_list(&value).ok())
                .and_then(|cpus| cpus.first().copied())
                .map(|cpu| cpu as u32)
        });
        let Some(id) = id else {
            continue;
        };
        if best.is_none_or(|(best_level, _)| level > best_level) {
            best = Some((level, id));
        }
    }
    best.map(|(_, id)| id).unwrap_or(fallback)
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
    use super::{parse_cpu_list, CpuDescriptor, CpuTopology};

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
        assert_eq!(topology.domain_count(), 1);
        assert!(topology.cpus().all(|cpu| cpu.online));
        assert!(topology.cpus().all(|cpu| cpu.possible));
        assert!(topology
            .cpus()
            .all(|cpu| cpu.capacity == 1024 && cpu.domain_id == 0));
    }

    #[test]
    fn core_shards_ignore_cpu_id_holes_but_keep_offline_possible_peers() {
        let descriptor = |id, possible, online, core_id| CpuDescriptor {
            id,
            possible,
            online,
            package_id: 0,
            core_id,
            llc_id: 0,
            numa_id: 0,
            domain_id: 0,
            smt_index: u32::from(id == 2),
            capacity: 1024,
            core_type: 0,
        };
        let topology = CpuTopology {
            cpus: vec![
                descriptor(0, true, true, 0),
                descriptor(1, false, false, 0),
                descriptor(2, true, false, 0),
                descriptor(3, true, true, 1),
            ],
            domain_count: 1,
        };
        let cpus: Vec<_> = topology.cpus().copied().collect();

        assert_eq!(topology.core_leaders(), vec![0, 3]);
        assert_eq!(topology.core_leader_id(&cpus[1]), 1);
        assert_eq!(topology.core_leader_id(&cpus[2]), 0);
        assert_eq!(topology.core_peer_id(&cpus[0]), 2);
        assert_eq!(topology.core_peer_id(&cpus[2]), 2);
        assert_eq!(topology.core_peer_id(&cpus[3]), 3);
    }
}
