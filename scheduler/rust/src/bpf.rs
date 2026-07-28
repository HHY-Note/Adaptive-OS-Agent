// SPDX-License-Identifier: GPL-2.0-only

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::mem::{self, MaybeUninit};
use std::rc::Rc;
use std::slice;

use anyhow::{Context, Result};
use libbpf_rs::libbpf_sys::bpf_object_open_opts;
use libbpf_rs::{Link, MapCore, MapFlags, OpenObject, RingBuffer, RingBufferBuilder};
use log::error;

use crate::bpf_intf;
use crate::bpf_skel::*;
use crate::config::SchedulerConfig;
use crate::identity::TaskKey;
use crate::process::TaskClassCache;
use crate::topology::CpuTopology;
use crate::wire::{task_control_raw, KernelEvent, WireError};

const VERIFIER_LOG_BYTES: usize = 16 * 1024 * 1024;
const VERIFIER_LOG_REPORT_BYTES: usize = 512 * 1024;

/// Userspace projection of the aggregated per-CPU BPF diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataPlaneStats {
    /// Lifecycle events that could not enter the bounded BPF queue.
    pub event_overflows: u64,
    /// Tasks sent to the global DSQ by safe, missing-context, or liveness paths.
    pub fallback_dispatches: u64,
    /// Runnable instances admitted directly into BPF class pools.
    pub fast_path_enqueues: u64,
    /// Tasks selected by the BPF root and class EEVDF policy.
    pub fast_path_dispatches: u64,
    /// BPF class selections that lost a dequeue or affinity race.
    pub fast_path_dispatch_failures: u64,
    /// Latency tasks dispatched through the native urgent lane.
    pub fast_path_preemptions: u64,
    /// BPF dispatches indexed by Latency, Balanced, and Throughput.
    pub fast_path_dispatches_by_class: [u64; 3],
    /// Dispatches served from the destination CPU's own class queues.
    pub fast_path_local_dispatches: u64,
    /// Bounded remote scans started after local queues were exhausted.
    pub fast_path_steal_attempts: u64,
    /// Tasks moved from a remote CPU-owned class queue.
    pub fast_path_remote_steals: u64,
    /// Fast-path lifecycle events omitted after a task reached Locked stage.
    pub fast_path_events_suppressed: u64,
    /// Fast-path tasks inserted directly into an atomically claimed idle CPU.
    pub fast_path_direct_dispatches: u64,
    /// Uncontended Throughput epochs continued without a dispatch cycle.
    pub fast_path_prev_continuations: u64,
    /// Remote steal attempts rejected by another destination's source claim.
    pub fast_path_steal_claim_conflicts: u64,
    /// Dispatch callbacks skipped remote scanning because no fast task waited.
    pub fast_path_empty_steal_skips: u64,
    /// Urgent fast-path requests held back by victim-runtime or rate limits.
    pub fast_path_preemption_throttles: u64,
    /// Latency dispatches given temporary root weight because peers were queued.
    pub fast_path_latency_backlog_boosts: u64,
}

impl From<bpf_intf::adaptive_global_stats> for DataPlaneStats {
    /// Copies the fixed-width BPF record into a stable public Rust type.
    fn from(raw: bpf_intf::adaptive_global_stats) -> Self {
        Self {
            event_overflows: raw.event_overflows,
            fallback_dispatches: raw.fallback_dispatches,
            fast_path_enqueues: raw.fast_path_enqueues,
            fast_path_dispatches: raw.fast_path_dispatches,
            fast_path_dispatch_failures: raw.fast_path_dispatch_failures,
            fast_path_preemptions: raw.fast_path_preemptions,
            fast_path_dispatches_by_class: raw.fast_path_dispatches_by_class,
            fast_path_local_dispatches: raw.fast_path_local_dispatches,
            fast_path_steal_attempts: raw.fast_path_steal_attempts,
            fast_path_remote_steals: raw.fast_path_remote_steals,
            fast_path_events_suppressed: raw.fast_path_events_suppressed,
            fast_path_direct_dispatches: raw.fast_path_direct_dispatches,
            fast_path_prev_continuations: raw.fast_path_prev_continuations,
            fast_path_steal_claim_conflicts: raw.fast_path_steal_claim_conflicts,
            fast_path_empty_steal_skips: raw.fast_path_empty_steal_skips,
            fast_path_preemption_throttles: raw.fast_path_preemption_throttles,
            fast_path_latency_backlog_boosts: raw.fast_path_latency_backlog_boosts,
        }
    }
}

impl DataPlaneStats {
    /// Merges one CPU's counters into the process-wide diagnostics snapshot.
    fn accumulate(&mut self, sample: Self) {
        self.event_overflows = self.event_overflows.saturating_add(sample.event_overflows);
        self.fallback_dispatches = self
            .fallback_dispatches
            .saturating_add(sample.fallback_dispatches);
        self.fast_path_enqueues = self
            .fast_path_enqueues
            .saturating_add(sample.fast_path_enqueues);
        self.fast_path_dispatches = self
            .fast_path_dispatches
            .saturating_add(sample.fast_path_dispatches);
        self.fast_path_dispatch_failures = self
            .fast_path_dispatch_failures
            .saturating_add(sample.fast_path_dispatch_failures);
        self.fast_path_preemptions = self
            .fast_path_preemptions
            .saturating_add(sample.fast_path_preemptions);
        for (total, value) in self
            .fast_path_dispatches_by_class
            .iter_mut()
            .zip(sample.fast_path_dispatches_by_class)
        {
            *total = total.saturating_add(value);
        }
        self.fast_path_local_dispatches = self
            .fast_path_local_dispatches
            .saturating_add(sample.fast_path_local_dispatches);
        self.fast_path_steal_attempts = self
            .fast_path_steal_attempts
            .saturating_add(sample.fast_path_steal_attempts);
        self.fast_path_remote_steals = self
            .fast_path_remote_steals
            .saturating_add(sample.fast_path_remote_steals);
        self.fast_path_events_suppressed = self
            .fast_path_events_suppressed
            .saturating_add(sample.fast_path_events_suppressed);
        self.fast_path_direct_dispatches = self
            .fast_path_direct_dispatches
            .saturating_add(sample.fast_path_direct_dispatches);
        self.fast_path_prev_continuations = self
            .fast_path_prev_continuations
            .saturating_add(sample.fast_path_prev_continuations);
        self.fast_path_steal_claim_conflicts = self
            .fast_path_steal_claim_conflicts
            .saturating_add(sample.fast_path_steal_claim_conflicts);
        self.fast_path_empty_steal_skips = self
            .fast_path_empty_steal_skips
            .saturating_add(sample.fast_path_empty_steal_skips);
        self.fast_path_preemption_throttles = self
            .fast_path_preemption_throttles
            .saturating_add(sample.fast_path_preemption_throttles);
        self.fast_path_latency_backlog_boosts = self
            .fast_path_latency_backlog_boosts
            .saturating_add(sample.fast_path_latency_backlog_boosts);
    }
}

/// Loaded sched_ext data plane and its struct-ops attachment.
///
/// The `OpenObject` storage is owned by the caller and must outlive this value,
/// matching libbpf skeleton lifetime requirements.
pub struct BpfRuntime<'obj> {
    /// Owning link whose drop detaches sched_ext and restores the kernel scheduler.
    struct_ops: Option<Link>,
    /// mmap-backed event consumer; it must be dropped before the skeleton maps.
    event_ring: RingBuffer<'static>,
    /// At most one bounded consume batch decoded by the ring callback.
    pending_events: Rc<RefCell<VecDeque<Result<KernelEvent>>>>,
    /// Generated map/program skeleton.
    skel: BpfSkel<'obj>,
}

impl<'obj> BpfRuntime<'obj> {
    /// Opens, configures, loads, and attaches the BPF scheduler.
    pub fn load(
        open_object: &'obj mut MaybeUninit<OpenObject>,
        config: &SchedulerConfig,
        topology: &CpuTopology,
        agent_pid: u32,
        debug: bool,
    ) -> Result<Self> {
        let mut builder = BpfSkelBuilder::default();
        builder.obj_builder.debug(debug);
        let mut verifier_log = if debug {
            vec![0_u8; VERIFIER_LOG_BYTES]
        } else {
            Vec::new()
        };
        let mut open_opts_storage = bpf_object_open_opts::default();
        let open_opts = if debug {
            open_opts_storage.sz = mem::size_of::<bpf_object_open_opts>() as u64;
            open_opts_storage.kernel_log_buf = verifier_log.as_mut_ptr().cast();
            open_opts_storage.kernel_log_size = verifier_log.len() as u64;
            open_opts_storage.kernel_log_level = 1;
            Some(open_opts_storage)
        } else {
            None
        };
        let mut skel = scx_utils::scx_ops_open!(builder, open_object, scx_adaptive, open_opts)?;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata map is not memory mapped")?;
        rodata.usersched_pid = std::process::id();
        rodata.agent_pid = agent_pid;
        rodata.num_possible_cpus = topology.cpu_count() as u32;
        rodata.latency_slice_ns = config.latency_slice_ns;
        rodata.balanced_slice_ns = config.balanced_slice_ns;
        rodata.throughput_slice_ns = config.throughput_slice_ns;
        rodata.min_slice_ns = config.min_slice_ns;
        rodata.max_slice_ns = config.max_slice_ns;
        rodata.preemption_min_runtime_ns = config.preemption_min_runtime_ns;
        rodata.fast_preemption_interval_ns = config.fast_preemption_interval_ns();
        rodata.latency_backlog_request_ns = config.latency_backlog_request_ns();

        let mut skel = match scx_utils::scx_ops_load!(skel, scx_adaptive, uei) {
            Ok(skel) => skel,
            Err(load_error) => {
                if let Some(end) = verifier_log.iter().position(|byte| *byte == 0) {
                    if end > 0 {
                        let start = end.saturating_sub(VERIFIER_LOG_REPORT_BYTES);
                        error!(
                            "BPF verifier log (last {} of {} bytes):\n{}",
                            end - start,
                            end,
                            String::from_utf8_lossy(&verifier_log[start..end])
                        );
                    }
                }
                return Err(load_error);
            }
        };
        for cpu in topology.cpus() {
            let state = initial_cpu_state(cpu.online);
            update_array_value(&skel.maps.cpu_state, cpu.id, &state)
                .with_context(|| format!("initialize BPF state for CPU {}", cpu.id))?;
        }

        let pending_events = Rc::new(RefCell::new(VecDeque::new()));
        let event_sink = Rc::clone(&pending_events);
        let mut ring_builder = RingBufferBuilder::new();
        ring_builder
            .add(&skel.maps.task_events, move |bytes| {
                let event = copy_from_bytes::<bpf_intf::task_event>(bytes)
                    .context("decode task_events value")
                    .and_then(|raw| {
                        KernelEvent::try_from(raw).map_err(|error: WireError| error.into())
                    });
                event_sink.borrow_mut().push_back(event);
                0
            })
            .context("register task_events ring buffer")?;
        let event_ring = ring_builder
            .build()
            .context("build task_events ring buffer")?;
        let struct_ops = Some(scx_utils::scx_ops_attach!(skel, scx_adaptive)?);

        Ok(Self {
            struct_ops,
            event_ring,
            pending_events,
            skel,
        })
    }

    /// Pops one decoded event after greedily consuming a bounded mmap batch.
    pub fn pop_event(&self) -> Result<Option<KernelEvent>> {
        if let Some(event) = self.pending_events.borrow_mut().pop_front() {
            return event.map(Some);
        }

        let consumed = self.event_ring.consume_raw_n(4096);
        if consumed < 0 {
            return Err(io::Error::from_raw_os_error(-consumed))
                .context("consume task_events ring buffer");
        }
        match self.pending_events.borrow_mut().pop_front() {
            Some(event) => event.map(Some),
            None => Ok(None),
        }
    }

    /// Mirrors one task class generation before the engine commits its update.
    pub fn update_task_control(&self, task: TaskKey, cache: TaskClassCache) -> Result<()> {
        let (key, value) = task_control_raw(task, cache);
        self.skel
            .maps
            .task_control
            .update(&key.to_ne_bytes(), bytes_of(&value), MapFlags::ANY)
            .with_context(|| format!("update BPF scheduling control for task {task:?}"))
    }

    /// Deletes a task-control record during explicit userspace reconciliation.
    pub fn delete_task_control(&self, task: TaskKey) -> Result<()> {
        self.skel
            .maps
            .task_control
            .delete(&task.tid.to_ne_bytes())
            .with_context(|| format!("delete BPF class generation for task {task:?}"))
    }

    /// Reads and aggregates the per-CPU BPF diagnostics records.
    pub fn data_plane_stats(&self) -> Result<DataPlaneStats> {
        let values = self
            .skel
            .maps
            .global_stats
            .lookup_percpu(&0_u32.to_ne_bytes(), MapFlags::ANY)
            .context("lookup per-CPU BPF statistics")?
            .context("per-CPU BPF statistics entry zero is missing")?;
        let mut total = DataPlaneStats::default();
        for bytes in values {
            let raw = copy_from_bytes::<bpf_intf::adaptive_global_stats>(&bytes)
                .context("decode per-CPU BPF statistics")?;
            total.accumulate(raw.into());
        }
        Ok(total)
    }

    /// Returns whether BPF recorded a sched_ext exit condition.
    pub fn exited(&self) -> bool {
        scx_utils::uei_exited!(&self.skel, uei)
    }

    /// Detaches struct_ops exactly once; dropping the runtime is also sufficient.
    pub fn detach(&mut self) {
        self.struct_ops.take();
    }

    /// Reports BPF's exit reason after detach or an unexpected sched_ext exit.
    pub fn report_exit(&self) -> Result<scx_utils::UserExitInfo> {
        scx_utils::uei_report!(&self.skel, uei)
    }
}

/// Returns CLOCK_MONOTONIC nanoseconds, matching `bpf_ktime_get_ns()`.
pub fn monotonic_now_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is valid writable storage and CLOCK_MONOTONIC has no
    // additional pointer arguments or retained state.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("read CLOCK_MONOTONIC");
    }
    Ok((time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64))
}

/// Updates one ARRAY map entry using native-endian fixed-width bytes.
fn update_array_value<T>(map: &impl MapCore, key: u32, value: &T) -> Result<()> {
    map.update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
        .map_err(Into::into)
}

/// Builds the pre-attach BPF state matching the scheduler's topology snapshot.
fn initial_cpu_state(online: bool) -> bpf_intf::adaptive_cpu_state {
    bpf_intf::adaptive_cpu_state {
        urgent_dispatch_id: 0,
        online: u32::from(online),
        idle: 0,
        running_class: bpf_intf::SCX_ADAPTIVE_CLASS_COUNT,
        steal_claim: 0,
        steal_cursor: 0,
        padding: 0,
        running_started_ns: 0,
        last_preemption_ns: 0,
        root_virtual_time_ns: 0,
        root_vruntime_ns: [0; 3],
    }
}

/// Views a plain fixed-width ABI value as immutable bytes for libbpf.
fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the returned slice borrows `value`, spans exactly its initialized
    // object representation, and cannot outlive or mutate the source.
    unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>()) }
}

/// Copies an unaligned byte slice into a fixed-width ABI value.
fn copy_from_bytes<T: Copy>(bytes: &[u8]) -> Result<T> {
    if bytes.len() != mem::size_of::<T>() {
        anyhow::bail!(
            "map value has {} bytes; expected {}",
            bytes.len(),
            mem::size_of::<T>()
        );
    }
    // SAFETY: size equality above guarantees a complete object representation;
    // read_unaligned handles Vec<u8>'s one-byte alignment and returns an owned copy.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

#[cfg(test)]
mod tests {
    use super::{copy_from_bytes, initial_cpu_state, monotonic_now_ns, DataPlaneStats};

    /// Kernel-compatible monotonic time must be non-zero on a running system.
    #[test]
    fn monotonic_clock_is_available() {
        assert!(monotonic_now_ns().unwrap() > 0);
    }

    /// ABI decoding rejects a map value with the wrong fixed size.
    #[test]
    fn fixed_width_decode_checks_size() {
        assert!(copy_from_bytes::<u64>(&[0; 7]).is_err());
    }

    /// BPF CPU availability must be initialized before struct_ops attachment.
    #[test]
    fn initial_cpu_state_tracks_topology_online_bit() {
        let online = initial_cpu_state(true);
        let offline = initial_cpu_state(false);
        assert_eq!(online.online, 1);
        assert_eq!(offline.online, 0);
        assert_eq!(online.urgent_dispatch_id, 0);
    }

    /// Per-CPU aggregation saturates counters and preserves class indexes.
    #[test]
    fn data_plane_stats_aggregate_per_cpu_values() {
        let mut total = DataPlaneStats {
            fast_path_enqueues: u64::MAX - 1,
            fast_path_dispatches_by_class: [1, 2, 3],
            ..DataPlaneStats::default()
        };
        total.accumulate(DataPlaneStats {
            fast_path_enqueues: 5,
            fast_path_dispatches_by_class: [4, 5, 6],
            fast_path_prev_continuations: 7,
            ..DataPlaneStats::default()
        });

        assert_eq!(total.fast_path_enqueues, u64::MAX);
        assert_eq!(total.fast_path_dispatches_by_class, [5, 7, 9]);
        assert_eq!(total.fast_path_prev_continuations, 7);
    }
}
