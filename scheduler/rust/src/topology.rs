// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::io;
use std::mem;
use std::path::Path;

/// Maximum CPU identifier supported by the shared BPF ABI.
pub const MAX_CPUS: usize = 1024;

/// Dynamically sized CPU bitmap used for cached task affinity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuMask {
    /// Little-endian 64-bit bitmap words.
    words: Vec<u64>,
    /// Number of meaningful CPU bits.
    cpu_count: usize,
}

impl CpuMask {
    /// Creates a mask with every CPU in `0..cpu_count` allowed.
    pub fn all(cpu_count: usize) -> Self {
        let mut mask = Self::none(cpu_count);
        for cpu in 0..cpu_count {
            mask.set(cpu, true);
        }
        mask
    }

    /// Creates an empty mask for the requested topology width.
    pub fn none(cpu_count: usize) -> Self {
        Self {
            words: vec![0; cpu_count.div_ceil(64)],
            cpu_count,
        }
    }

    /// Returns the number of representable CPU IDs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns whether a CPU is present and allowed by this mask.
    pub fn contains(&self, cpu: usize) -> bool {
        if cpu >= self.cpu_count {
            return false;
        }
        self.words[cpu / 64] & (1_u64 << (cpu % 64)) != 0
    }

    /// Adds or removes one CPU when it is inside the represented width.
    pub fn set(&mut self, cpu: usize, allowed: bool) {
        if cpu >= self.cpu_count {
            return;
        }
        let bit = 1_u64 << (cpu % 64);
        if allowed {
            self.words[cpu / 64] |= bit;
        } else {
            self.words[cpu / 64] &= !bit;
        }
    }

    /// Returns allowed CPU IDs in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.cpu_count).filter(|cpu| self.contains(*cpu))
    }
}

/// Static topology attributes used for cache and SMT-aware placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuDescriptor {
    /// Linux logical CPU ID and index into scheduler CPU state.
    pub id: u32,
    /// Whether sysfs reported the CPU online during discovery.
    pub online: bool,
    /// Physical package identifier qualifying `core_id` on multi-socket hosts.
    pub package_id: u32,
    /// Physical core identifier within the package.
    pub core_id: u32,
    /// Stable representative CPU of the last-level-cache sharing set.
    pub llc_id: u32,
}

/// Snapshot of CPU/package/core/LLC relationships discovered before BPF attach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuTopology {
    /// Dense logical-CPU-indexed descriptors.
    cpus: Vec<CpuDescriptor>,
}

impl CpuTopology {
    /// Discovers possible/online CPUs and their package, core, and LLC identifiers.
    pub fn discover() -> io::Result<Self> {
        let possible_text = fs::read_to_string("/sys/devices/system/cpu/possible")?;
        let possible = parse_cpu_list(&possible_text)?;
        let cpu_count = possible
            .iter()
            .copied()
            .max()
            .map(|cpu| cpu + 1)
            .unwrap_or(1)
            .min(MAX_CPUS);

        let online_text = fs::read_to_string("/sys/devices/system/cpu/online")?;
        let online_ids = parse_cpu_list(&online_text)?;
        let mut online = CpuMask::none(cpu_count);
        for cpu in online_ids {
            online.set(cpu, true);
        }

        let mut cpus = Vec::with_capacity(cpu_count);
        for cpu in 0..cpu_count {
            let base = format!("/sys/devices/system/cpu/cpu{cpu}");
            let package_id =
                read_u32(Path::new(&base).join("topology/physical_package_id")).unwrap_or_default();
            let core_id = read_u32(Path::new(&base).join("topology/core_id")).unwrap_or(cpu as u32);
            let llc_id = discover_llc_id(Path::new(&base)).unwrap_or(cpu as u32);
            cpus.push(CpuDescriptor {
                id: cpu as u32,
                online: online.contains(cpu),
                package_id,
                core_id,
                llc_id,
            });
        }

        Ok(Self { cpus })
    }

    /// Constructs a synthetic topology for unit tests and degraded discovery.
    pub fn flat(cpu_count: usize) -> Self {
        let count = cpu_count.clamp(1, MAX_CPUS);
        Self {
            cpus: (0..count)
                .map(|cpu| CpuDescriptor {
                    id: cpu as u32,
                    online: true,
                    package_id: 0,
                    core_id: cpu as u32,
                    llc_id: 0,
                })
                .collect(),
        }
    }

    /// Returns the number of representable logical CPUs.
    pub fn cpu_count(&self) -> usize {
        self.cpus.len()
    }

    /// Returns one CPU descriptor when the ID is in range.
    pub fn cpu(&self, cpu: u32) -> Option<&CpuDescriptor> {
        self.cpus.get(cpu as usize)
    }

    /// Iterates all dense CPU descriptors in numeric order.
    pub fn cpus(&self) -> impl Iterator<Item = &CpuDescriptor> {
        self.cpus.iter()
    }

    /// Returns whether two logical CPUs are SMT siblings on one physical core.
    pub fn shares_core(&self, first: u32, second: u32) -> bool {
        if first == second {
            return false;
        }
        self.cpu(first)
            .zip(self.cpu(second))
            .is_some_and(|(first, second)| {
                first.package_id == second.package_id && first.core_id == second.core_id
            })
    }

    /// Constructs a dense synthetic topology for cross-module scheduler tests.
    #[cfg(test)]
    pub(crate) fn for_test(core_ids: &[(u32, u32, u32)]) -> Self {
        Self {
            cpus: core_ids
                .iter()
                .enumerate()
                .map(|(id, (package_id, core_id, llc_id))| CpuDescriptor {
                    id: id as u32,
                    online: true,
                    package_id: *package_id,
                    core_id: *core_id,
                    llc_id: *llc_id,
                })
                .collect(),
        }
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

/// Reads the current kernel affinity for a TID into the scheduler bitmap format.
pub fn read_task_affinity(tid: u32, cpu_count: usize) -> io::Result<CpuMask> {
    // SAFETY: cpu_set_t is a plain C bitmap. It is zero-initialized before the
    // kernel writes at most the exact object size supplied to sched_getaffinity.
    let mut native: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: `native` is valid writable memory for `size_of::<cpu_set_t>()` and
    // `tid` is passed as a numeric pid_t without retaining any pointer.
    let result = unsafe {
        libc::sched_getaffinity(
            tid as libc::pid_t,
            mem::size_of::<libc::cpu_set_t>(),
            &mut native,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut mask = CpuMask::none(cpu_count);
    for cpu in 0..cpu_count.min(libc::CPU_SETSIZE as usize) {
        // SAFETY: CPU_ISSET reads a valid initialized cpu_set_t and `cpu` is
        // explicitly bounded by CPU_SETSIZE.
        if unsafe { libc::CPU_ISSET(cpu, &native) } {
            mask.set(cpu, true);
        }
    }
    Ok(mask)
}

/// Parses one CPU identifier with a consistent InvalidData error.
fn parse_cpu_id(value: &str) -> io::Result<usize> {
    value.trim().parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid CPU id {value:?}: {error}"),
        )
    })
}

/// Reads one decimal sysfs value as u32.
fn read_u32(path: impl AsRef<Path>) -> io::Result<u32> {
    let text = fs::read_to_string(path)?;
    text.trim().parse::<u32>().map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid u32: {error}"))
    })
}

/// Uses the first CPU in the highest cache index sharing list as an LLC ID.
fn discover_llc_id(cpu_path: &Path) -> io::Result<u32> {
    let cache_path = cpu_path.join("cache");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(cache_path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(index) = name.strip_prefix("index") {
            if let Ok(index) = index.parse::<u32>() {
                candidates.push((index, entry.path()));
            }
        }
    }
    candidates.sort_unstable_by_key(|(index, _)| *index);
    let (_, path) = candidates
        .last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CPU has no cache index"))?;
    let shared = fs::read_to_string(path.join("shared_cpu_list"))?;
    parse_cpu_list(&shared)?
        .first()
        .copied()
        .map(|cpu| cpu as u32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty LLC CPU list"))
}

#[cfg(test)]
mod tests {
    use super::{parse_cpu_list, CpuMask, CpuTopology};

    /// Linux range and singleton syntax must produce a dense sorted set.
    #[test]
    fn parses_linux_cpu_lists() {
        assert_eq!(
            parse_cpu_list("0-2,5,7-8\n").unwrap(),
            vec![0, 1, 2, 5, 7, 8]
        );
    }

    /// Bitmap set and iteration operations preserve numeric CPU order.
    #[test]
    fn cpu_mask_tracks_allowed_cpus() {
        let mut mask = CpuMask::none(70);
        mask.set(69, true);
        mask.set(2, true);
        assert_eq!(mask.iter().collect::<Vec<_>>(), vec![2, 69]);
        assert!(!mask.contains(70));
    }

    #[test]
    fn physical_package_qualifies_core_identity() {
        let topology = CpuTopology::for_test(&[(0, 0, 0), (0, 0, 0), (1, 0, 2)]);
        assert!(topology.shares_core(0, 1));
        assert!(!topology.shares_core(0, 2));
    }
}
