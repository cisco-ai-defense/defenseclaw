// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(all(
    any(target_os = "linux", target_os = "windows"),
    target_arch = "x86_64"
)))]
compile_error!("the private AXIS peer requires native Linux or Windows x86_64");

pub mod conversation;
#[cfg(target_os = "linux")]
pub mod custody;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod namespace;
pub mod owner;
#[cfg(target_os = "linux")]
pub mod transport;
pub mod wire;

#[cfg(target_os = "windows")]
#[path = "windows_transport.rs"]
pub mod transport;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod windows_bootstrap;
#[cfg(target_os = "windows")]
pub mod windows_io;
