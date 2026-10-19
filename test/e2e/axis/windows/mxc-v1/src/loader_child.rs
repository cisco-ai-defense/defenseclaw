// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Deliberately separate from the SDK-bearing supervisor's Windows imports.
// This fixed payload uses std only, accepts no arguments and performs no host
// discovery, filesystem access, networking or process creation.
use std::io::Write;

fn main() {
    if std::env::args_os().count() != 1 {
        std::process::exit(2);
    }
    let mut output = std::io::stdout().lock();
    if output
        .write_all(b"FIXED_PSEC_LOADER_STARTED\n")
        .and_then(|_| output.flush())
        .is_err()
    {
        std::process::exit(3);
    }
    std::process::exit(23);
}
