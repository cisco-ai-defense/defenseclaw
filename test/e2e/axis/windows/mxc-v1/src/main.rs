// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(windows, target_arch = "x86_64"))]
mod probe;

fn main() {
    #[cfg(all(windows, target_arch = "x86_64"))]
    match probe::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("this fixed contributor probe requires native Windows x86_64");
        std::process::exit(2);
    }
}
