<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# MXC literal argv compile and pure-unit gate

This contributor gate builds the additive argv patch against exact MXC
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2` with Rust 1.95.0. It does not
launch a sandbox, shell payload, PTY workload, proxy, Windows PSEC process or
agent. It enables no DefenseClaw provider. Native isolation, lifecycle and
interactive qualification require separate reviewed artifacts and live probes.

The dedicated workflow supplies a fresh native Linux or macOS runner, pinned
toolchain and exact clean MXC checkout. It copies this directory and the reviewed
[argv patch](../patches/mxc-literal-argv.patch) into a fresh staging directory,
with MXC at `mxc-source/`. The helper never installs a tool or changes a Cargo
manifest. It requires the existing upstream workspace lock unchanged, SHA-256
`2d145ff3861cd19d1f50969083f8ac59e4d4fd50b030bef12f365a5fcc87afa0`.

`python3 build_sdk.py` checks source identity/cleanliness, exact patch digest and
14-path inventory, applies the patch and checks all resulting dirty/new paths.
It checks Rust syntax immediately and formatting of the three added files.
It builds only `mxc-sdk --lib`, debug profile, with `--locked` and
`--no-default-features`. It then compiles/lists library tests and runs only the
reviewed exact-name pure allowlist: 10 Linux tests and 11 macOS tests, including
the platform-independent Bubblewrap command-builder test on both systems.
Missing, duplicated, ignored or zero selected tests fail the gate. Existing SDK
tests and test cases that launch real processes are not run.

Each command has a deadline and an 8 MiB log bound. Cargo receives private
HOME/CARGO_HOME/tmp directories, the explicitly provisioned RUSTUP_HOME, PATH
and optional CA file settings. Tokens, proxy credentials, dynamic-loader
overrides, Git environment overrides and caller Rust flags/wrappers are not
forwarded. The helper requires the existing native toolchain binaries under
that RUSTUP_HOME and invokes them directly, preventing rustup shim auto-install
when a toolchain is missing. Cargo's ordinary locked registry downloads use crates.io over HTTPS;
this gate has no credentialed/private feed. The disposable workflow explicitly
provisions Rust and native compiler prerequisites before the helper starts.
Each build command owns a new process session. A capture deadline or log-limit
failure stops that exact group before reaping its retained leader, then waits
the tracked command. No group signal is sent after a successful wait/reap.
This covers ordinary inherited build children, including a compiler holding
stdout after Cargo exits; it does not certify deliberately detached descendants.
The disposable runner/job deadline is the final build-environment boundary.

The artifact contains all 14 patched source files, the exact patch, original
upstream lock and license, helper/test/workflow sources, bounded logs, selected
test names, toolchain/platform information, command arguments/results and
SHA-256 provenance. It contains no SDK test executable, library binary or
workload. A successful gate establishes compilation and these pure assertions,
not runtime or security qualification. Failure still uploads available logs and
a failed provenance record for review.

The helper admission tests execute no Rust code and can be run locally:

```text
python3 -m unittest discover -s test/e2e/axis/mxc-argv-build -p test_build_sdk.py
```
