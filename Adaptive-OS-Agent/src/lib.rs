// SPDX-License-Identifier: Apache-2.0

//! Agent-side process discovery, semantic classification, and registry state.

pub mod behavior;
pub mod config;
mod deepseek;
pub mod discovery;
pub mod identity;
pub mod limits;
mod local_frame;
pub mod metadata;
mod process_classifier;
pub mod registry;
pub mod scheduler_client;
pub mod skills;
pub mod supervisor;
mod thread_classifier;
pub mod tools;
