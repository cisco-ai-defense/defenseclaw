<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Proposed DefenseClaw runtime bridge

This is a contributor design, not an implemented execution path. The current
product still refuses active AXIS configuration. The shared controller alias,
selection/capability contracts and immutable execution-policy resolver exist;
the router, AXIS adapter, native bridge peer/supervisor and production
qualification below do not. The private Go frame codec/state machine now
exists; the offline probes are separate feasibility evidence.

## Ownership boundaries

| Owner | Responsibility | Existing seam or required change |
| --- | --- | --- |
| Common Go control plane | Current config and administrative/repository resolution, session ownership, policy generations, approvals, hook health, audit and workspace review/pull/undo | `internal/sandboxruntime.Controller`, existing manager/workspace logic and `ResolveExecutionPolicy`; extract shared orchestration incrementally |
| OpenShell implementation | Its vendor gateway, images, profiles, discovery and existing execution/transport | Retain `internal/openshell/manager` and current CLI transport while adding a common facade |
| Go AXIS adapter | Translate a frozen admitted policy, prepare session state, invoke the host bridge and check its exact evidence | New adapter beneath the common control plane; no new configuration authority |
| Typed Rust host bridge | Own the selected MXC SDK backend and all resulting process/PTY handles, bounded I/O, resize, wait, cancellation and cleanup | New pinned executable bundle; no daemon/listener when disabled |
| Trusted final child bootstrap | Validate its private launch plan, establish platform execution state, apply AXIS guards and exec the admitted literal agent argv | Executes inside MXC containment before untrusted code; receives no provider credentials |
| Host credential/egress broker | Evaluate the original host policy and approvals, bind requests to the admitted executable/session, hold and inject credentials | Existing Go authority retained; platform attribution/transport must be qualified before granting credential capabilities |

The original private policy evaluator remains authoritative. Its inspection
JSON omits host evaluator facts and cannot be reconstructed into executable
authority. Never flatten curated/operator rules into an MXC allowlist and
treat that list as equivalent policy. `strict` still permits separately
authorized broker traffic; explicit offline execution is a separate posture.

## Prepare, admit, then launch

The optional `Backend` now prepares from the private resolved policy and full
host-owned specification, returning a prepared resource handle and complete
translation receipt. Create and restart both dispatch that handle through
`LaunchGate`; there is no direct provision/start method on this lower-level
contract. It has no production implementation yet. Never implement launch by
deserializing a `Spec` or accepting its runtime identity as admission.

The concrete flow should be:

1. Under the current trusted configuration snapshot, Go resolves the complete
   execution policy and captures its host authority snapshot ID/generation.
   It validates the chosen exact runtime/harness artifacts and capabilities.
2. Go creates an immutable, bounded typed translation for one private staged
   workspace and one exact session identity. The trusted adapter/host bridge
   prepares resources and returns a prepared handle plus its complete policy
   translation receipt. Preparation runs no agent and grants no credentials.
3. While holding the authority-generation serialization boundary, Go checks
   the receipt against the frozen policy, current authority binding, complete
   component coverage and exact runtime/harness identities. It checks current
   owner, listeners, repository identity and prepared workspace custody too.
4. Go submits a one-use launch authorization bound to that prepared handle,
   policy digest and still-current generation. The bridge must reject reused,
   changed or stale requests. Authority rotation cannot race between this
   admission and the untrusted process launch.
5. The trusted child bootstrap reads only its guest-safe launch subset, closes
   the plan transport, establishes containment-specific process/terminal
   state, sets `no_new_privs` and applies required AXIS guards before literal
   `execve`/native process launch. Provider credentials stay on the host.
6. Policy/broker revocation closes grants and contains the running session.
   Reattachment, resize, stop, export and deletion compare the full recorded
   owner/session/runtime identity and applicable current generation.

The shared `LaunchGate` now supplies host-side admission/launch serialization,
one-use private prepared handles, copied full launch specifications and receipt
evidence, actual authority-source/history checks, and bounded owned cleanup on
refusal or partial launch. All host authority writers must enter its rotation
transaction; the adapter/controller must reserve unique session identities and
own successful workloads. It is not yet wired to a production adapter, policy
translator, workspace preparer or credential broker. The remaining bridge flow
above is still a protocol requirement.
The policy inspection snapshot contains host-confidential workspace paths and
provenance; it must stay on the trusted host. The child receives a deliberately
restricted execution plan, not the original snapshot or broker authority.

## Existing integration points

The public `gateway.SandboxController` name is a compatibility alias for
`sandboxruntime.Controller`. A router implementing that full contract can
preserve existing REST and managed behavior. Creation needs an additive
runtime selector. A missing selector/default/legacy record continues to mean
OpenShell. After creation, route from the private stored full identity, never
from the current default or a guessed platform. Refusal never changes runtime.

`sandboxapi` currently lives under OpenShell and the common controller imports
it. Importing `sandboxruntime.RuntimeIdentity` back into those wire structs
would create a cycle. Use a scalar runtime selector initially, with full
identity in owned state, or first extract dependency-free identity wire types.

Session execution now uses an explicitly bound `SessionTransport` in
`internal/openshell/sandboxcli/session_transport.go`. The OpenShell adapter
constructs the existing vendor invocation; the session retains output filtering,
interrupts, diagnostics, notices and lifecycle orchestration. Missing transports
and another provider's unsupported fixed Unix recipes refuse without fallback.
The copy workflow likewise retains one bound existing `workspace.Transport`
through upload, baseline, refresh and pull; standalone commands bind their
already resolved target explicitly. This does not yet select an AXIS transport.

The current guest copy operations still use POSIX paths, shell, git and core
utilities. Native Windows host staging still requires ACL, reparse-point,
identity and locking qualification. Implement typed guest workspace operations
and that host layer before advertising native Windows copied-workspace support;
preserve bounded base64/git-bundle pull, secret filtering and review/apply/undo.

The gateway and managed per-user daemon remain the execution owners. The CLI
should attach to their authenticated execution stream on the existing API
listener rather than launch an unsupervised host bridge itself. A bounded
stream carrying stdin/output, resize and completion can adapt
`Backend.Exec(ProcessIO)` and `TerminalBackend.Resize`. The repository already
uses `gorilla/websocket`; no additional network listener or transport
dependency is necessary merely to provide this stream.

`buildSandboxRuntime` still constructs the OpenShell manager. Runtime
supervision and the managed controller now consume a shared controller
interface, including policy refresh and managed views. OpenShell gateway
cache/reconciliation/idle-stop maintenance has its own dependency, so those
vendor operations are not requirements for a native controller. The concrete
OpenShell ingress/broker setup and managed create/start preparation still need
extraction before wiring a second implementation. Preserve the managed
registration, generation and listener-loss transactions. Copying the manager
into a second provider would duplicate its authority and lifecycle behavior.

## Host bridge transport and launch data

`internal/axis/bridgeproto` now defines versioned, length-bounded private pipe
frames, typed offline preparation and launch/I/O/resize/wait/cancel/destroy
messages, exact correlation digests and a one-session state machine. Strict
JSON validation refuses ambiguous keys/encodings; monotonic sequences,
phase checks and aggregate output accounting close on invalid peer behavior.
An independent binary preparation digest avoids Go/Rust JSON serializer drift.
`internal/axis/bridgeowner` implements the Go pipe side with serialized command
admission/encoding, absolute parent and per-write deadlines, a fixed event queue,
discarded bounded diagnostics and cancellation checks before queued delivery.
Windows uses immediately connected owner-only local pipes with overlapped parent
ends; anonymous pipes refuse. Duplicate kernel objects refuse even under
different handle values. Native pipe tests exercise these mechanics with fake
custody. The actual launcher must supply independent native `StopAndWait`
custody, and callers must require its successful completion after Destroyed.
This is not an implemented adapter or contained-process qualification.

The Rust peer and actual native process supervisor are still required. Do not
introduce a long-running listener or an unbounded queue. Closing the owner channel must
revoke grants, kill and wait the owned SDK handle; helper/descendant behavior
still needs separate platform qualification.

The Rust API can preserve native Unix `OsString` bytes internally. A JSON IPC
protocol has a narrower string domain: reject invalid UTF-8 at that wire
boundary, rather than replace bytes lossily. Preserve empty arguments,
Unicode, quotes and shell metacharacters as data. They are never command text.
Windows needs native UTF-16 command-line quoting and an explicit application
name when it gains literal argv support.

MXC V1 currently takes a string command. Bubblewrap appends `-- sh -c`; Seatbelt
launches `/bin/sh -c`. The separate
[literal-argv contributor patch](patches/mxc-literal-argv.patch) proposes an
additive typed route while retaining existing public command-string APIs.
That SDK patch now compiles on both Unix platforms, passes the selected pure
tests and passes fixed native literal workload probes. Production support remains pending.
Unsupported backends must refuse the literal request without shell rendering
or a generic fallback. A future bootstrap uses its actual admitted argv,
not string interpolation into those legacy command paths.

## Platform-specific outstanding work

For Linux, preserve MXC's user/PID/IPC/UTS/network namespaces and owned PTY.
MXC establishes its controlling PTY before entering Bubblewrap's PID namespace,
so a trusted final bootstrap may need to establish the visible child process
group and set it as foreground, temporarily blocking/restoring SIGTTOU. Zero
namespace group IDs are not positive foreground evidence. Actual positive
IDs, input/resize and fixed foreground-signal acknowledgement must pass without
dropping PID isolation or weakening AXIS guards.

MXC's newer proxy-only slirp/firewall route is not executable-bound credential
authority. Pinned AXIS connect-time attribution is private and its older MXC
integration accepts a different network strategy. A maintained attribution
handoff to the host broker, with peer/executable/session verification, is
required before the new route can advertise `HostCredentials` or
`ExecutableCredentialBinding`. A namespace allowlist or a transferable
placeholder alone is insufficient.

Native Windows uses its own strict PSEC ownership and qualification route;
native macOS uses Seatbelt. Their argv, terminal, broker and credential
evidence must be independently qualified. A result on Linux or WSL does not
enable either platform. Keep platform patches composable at the exact reviewed
upstream source, with explicit artifacts and no provider/tier fallback.

## Implementation order

Finish the discriminating Windows literal-argv/platform probes. Next implement
the Rust peer and owned native supervisor for the private typed host protocol,
then a synthetic offline adapter with no production activation. Connect the common CLI transport,
policy preparation/admission/launch serialization and owned workspace flow.
Add authenticated hook and host broker/credential binding with real denial
tests, followed by listener loss, parent/descendant cleanup and managed
ownership/generation tests. Finally run real headless/interactive Claude and
review packaging, installation, upgrade and rollback before enabling a
qualified platform/runtime option.
