// SPDX-License-Identifier: GPL-2.0-only

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! Bindgen output for the fixed-width Rust/BPF ABI.

include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
