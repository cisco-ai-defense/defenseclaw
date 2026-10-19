// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Fixed macOS contributor experiment: AXIS policy admission, MXC typed Seatbelt execution.
//! This is not an AXIS runtime adapter or a DefenseClaw provider.

#[cfg(target_os = "macos")]
mod probe;
#[cfg(target_os = "macos")]
mod strict_profile;

fn main() {
    #[cfg(target_os = "macos")]
    match probe::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            // Probe errors contain no child output or inherited environment.
            eprintln!("AXIS/MXC macOS contributor probe refused: {error:#}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("AXIS/MXC Seatbelt contributor probe requires macOS");
        std::process::exit(3);
    }
}
