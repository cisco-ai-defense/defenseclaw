<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributor MXC literal argv seam

This is an additive source proposal for MXC commit
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`. Its SDK compiled on native Linux
and macOS, and the selected pure tests passed. It enables no DefenseClaw
provider and establishes no workload/platform qualification. Execution still
requires a separate reviewed, pinned artifact and fixed platform probe.

[Compile/unit run 39115208856](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39115208856)
at DefenseClaw `232ba9033d55e0b22e8db20045dcaa8decc06974` passed exactly ten
reviewed Linux and eleven macOS tests, each selected with `--exact` and checked
for one non-ignored pass. Independent root review verified all 58 Linux and 59
macOS manifest files, reproduced all 14 patched Rust files from clean pinned
upstream source, checked unchanged lock and exact toolchain/provenance, and
matched the selected test names and results. No sandbox payload ran.
The Linux artifact `12131707913` ZIP SHA256 is
`bc5100ac4e4bbf3095232065566e6ed8ca09828089639a478ee5a865cc6d8011`;
macOS artifact `12131978568` ZIP SHA256 is
`5b6de79e2399563407e34ec82ba106d6424bc2fc1604a2fbfc9b68ecd45b9b55`.

## Public API and dispatch

[mxc-literal-argv.patch](mxc-literal-argv.patch) proposes two Rust-only entry
points alongside the existing command-string API:

```rust,ignore
use std::ffi::OsString;
use mxc_sdk::v1;

let request = v1::ContainerRequest {
    containment: v1::Containment::Bubblewrap,
    // Supply the actual admitted policy, environment and timeout here.
    ..v1::ContainerRequest::new("")
};
let arguments: Vec<OsString> = vec![
    "/absolute/admitted/bootstrap".into(),
    "".into(),
    "literal spaces, quotes ' and $()".into(),
];
let process = v1::argv::spawn(request, arguments, v1::SpawnOptions::default())?;
// Or v1::argv::spawn_with_pty(request, arguments, options).
```

Patch SHA-256:
`7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d`.

`LiteralArgv` owns private `OsString` values, has no serialization implementation,
and redacts values from `Debug`. It requires 1–4096 arguments, an absolute
nonempty executable, no embedded NUL and at most 1 MiB of native encoded data
including terminators. These bounds do not guarantee that an operating system
will accept the process; native argument limits remain enforced at spawn.
The Rust API preserves native Unix bytes. A future JSON bridge must reject
invalid UTF-8 rather than replace it and change an argument.

The request must select Bubblewrap on Linux or Seatbelt on macOS explicitly;
the abstract `Process` intent is refused. A dedicated dispatcher calls only
backends implementing literal argv. Other backends refuse; the default trait
method never invokes legacy spawn. This patch implements no Windows literal
path, no automatic provider selection and no tier/backend retry.

Bubblewrap keeps its generated policy, mounts, environment and network options
and replaces only the verified fixed `-- sh -c <script>` tail with `--` and
native argv. An unexpected tail layout refuses launch and tears down any
prepared proxy handle. Seatbelt passes a native `Command` through the existing
sandbox/profile/PTY preparation. Its literal path never constructs `/bin/sh`.
The existing string APIs retain their signatures and behavior.

## Policy preparation boundary

MXC's exact V1 policy mapping requires a nonempty `process.commandLine`, even
when the caller has supplied typed argv. Reimplementing that mapper would
duplicate security rules. The proposal instead uses one private, fixed
normalization token solely inside the existing exact-contract policy mapper.
The mapper clears `script_code` immediately before returning. It uses only its
private buffered policy logger; it does not emit the token or register
telemetry. Invocation options and telemetry are applied after clearing.

The opaque `PreparedArgvRequest` has private fields and no serialization or
debug implementation. It can be constructed only after literal validation
requires an empty legacy command and the shared policy checks pass. Every
legacy entry point still rejects its empty `script_code`. Neither a caller
nor a legacy backend receives the normalization token. This is a narrowly
scoped compatibility step; extracting a policy-only exact mapper is the
preferred future upstream design.

The existing mapper, common policy checks, backend filesystem/network
validation, environment handling, timeout and process-handle ownership remain
shared. The proposal neither adds AXIS guards nor replaces DefenseClaw's host
policy evaluator or admission authority.

## Source checks completed

- `git apply --check --whitespace=error-all` passes against the exact unmodified
  MXC commit above. The patch is 14 paths; it introduces no dependency or lock
  change.
- The patch and the existing Windows strict PSEC overlay apply in both orders
  to private copies of those exact upstream source files. The overlay checked
  was SHA-256
  `2afaa15f4387f8104c1dfe01f6f7c98a7ba6cd248d611139d2dbd04c2f39c6b2`.
  Composition is a source check and grants no Windows argv support.
- Task-local Rust 1.95 formatting parses the edited source. Added source is
  formatted; the three new files pass `rustfmt --check`. Unrelated upstream
  formatting changes were excluded.

The proposed unit tests inspect `Command` arguments without executing them:
empty, quoted, Unicode and metacharacter arguments; native Unix non-UTF-8
bytes; malformed/NUL/oversized input; Bubblewrap tail replacement and refusal;
Seatbelt native command preparation; preserved policy/environment/timeout;
cleared token plus legacy-validator refusal; retained common policy rejection;
and a legacy-only fake backend whose spawn panics if fallback occurs. A
separate unsupported-backend dispatcher test must fail before backend launch.
These tests are source additions and have not run yet.

## Build and execution gates

The separate [compile/pure-unit gate](../mxc-argv-build/README.md) supplies this
first qualification step. It runs no sandbox or workload and enables no provider.

After source review, apply this asset to the pinned clean MXC tree and build
with its reviewed lock unchanged. Compile both native backend implementations
and run the added unit tests on their native CI platforms, alongside relevant
existing SDK tests. Reject compilation failures or policy regressions before
packaging. Record the complete source/patch/lock/toolchain identity, provenance
and artifact hashes before any execution.

Then adapt a fixed self-payload probe to the literal API. It must discriminate
empty/Unicode/metacharacter arguments, verify private environment and the
unchanged strict filesystem/network denials, and qualify owned PTY input,
resize, foreground signals, timeout, wait and cleanup. No arbitrary caller
command or credentials belong in that contributor probe. Existing Linux and
macOS probe results do not qualify this new API.

Windows needs a separate reviewed companion seam that composes with the strict
PSEC overlay: direct `.exe` launch through `CreateProcessW` with an explicit
application name, validated UTF-16 and native Windows/MSVCRT argument quoting.
Its tests must include empty arguments, whitespace, embedded quotes,
backslashes before quotes, trailing backslashes, Unicode, NUL and native
command-line size refusal. It must never route literal input through `cmd`,
PowerShell, shell text or an alternative backend.

The proposed production ownership and admission flow is documented in
[runtime-bridge-design.md](../runtime-bridge-design.md).
