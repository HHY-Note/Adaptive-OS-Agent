// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{Context, Result};
use scx_cargo::BpfBuilder;
use std::env;
use std::process::{Command, ExitCode};

/// Returns true when `program` can be executed successfully.
///
/// The repository requires clang 16 or newer because older compilers truncate
/// high bits in sched_ext's 64-bit enum constants when targeting BPF.
fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Selects a supported BPF compiler when the caller did not set `BPF_CLANG`.
///
/// An explicit environment value always wins. This keeps release builders in
/// control while making development hosts whose default `clang` is old use an
/// installed versioned compiler automatically.
fn select_bpf_clang() {
    if env::var_os("BPF_CLANG").is_some() {
        return;
    }

    for candidate in ["clang-18", "clang-17", "clang-16"] {
        if command_exists(candidate) {
            // SAFETY: build scripts execute before Cargo starts compiling this
            // package and this process has no application threads.
            unsafe { env::set_var("BPF_CLANG", candidate) };
            return;
        }
    }
}

/// Generates the shared ABI bindings and the libbpf skeleton.
fn build() -> Result<()> {
    select_bpf_clang();

    let mut builder = BpfBuilder::new().context("initialize sched_ext BPF builder")?;
    builder
        .enable_intf("bpf/intf.h", "bpf_intf.rs")
        .enable_skel("bpf/scx_adaptive.bpf.c", "bpf")
        .build()
        .context("compile scx_adaptive BPF data plane")
}

/// Build-script entry point with a concise error chain for Cargo output.
fn main() -> ExitCode {
    match build() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scx_adaptive build failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}
