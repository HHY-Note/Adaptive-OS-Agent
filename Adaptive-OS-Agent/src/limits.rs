// SPDX-License-Identifier: Apache-2.0

/// Fixed bounds for Agent-owned queues, frames, and registries.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeLimits {
    pub registry_processes: usize,
    pub registry_tasks: usize,
    pub llm_pending_batches: usize,
    pub control_queue_capacity: usize,
    pub max_control_frame_bytes: usize,
    pub snapshot_batch_size: usize,
    pub tool_queue_capacity: usize,
    pub max_tool_frame_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            registry_processes: 32_768,
            registry_tasks: 65_536,
            llm_pending_batches: 32,
            control_queue_capacity: 1_024,
            max_control_frame_bytes: 1024 * 1024,
            snapshot_batch_size: 128,
            tool_queue_capacity: 128,
            max_tool_frame_bytes: 256 * 1024,
        }
    }
}
