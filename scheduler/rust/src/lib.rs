// SPDX-License-Identifier: GPL-2.0-only

//! Policy and state-machine implementation for `scx_adaptive`.
//!
//! The library deliberately keeps all policy code independent from libbpf so
//! unit tests can drive the same state transitions without attaching sched_ext.

pub mod bpf;
pub(crate) mod bpf_intf;
pub(crate) mod bpf_skel;
pub mod config;
pub mod control;
pub mod engine;
pub mod identity;
pub mod process;
pub mod stats;
pub mod topology;
pub mod wire;
