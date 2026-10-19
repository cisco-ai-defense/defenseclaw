// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Contributor experiment only: MXC Bubblewrap owns execution and the PTY;
//! AXIS guards restrict the fixed final child. This is not a runtime adapter.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod probe;

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    match probe::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            // Probe errors contain no captured child output or environment.
            eprintln!("AXIS/MXC contributor probe refused: {error:#}");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("AXIS/MXC contributor probe requires Linux x86_64");
        std::process::exit(3);
    }
}
