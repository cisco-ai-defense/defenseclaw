<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed native peer contributor harness

This is source for a separate Linux amd64 experiment. Its compiled registry
admits only receipt SHA256
`6db10d2a73ee7860bb0d7ad8a6155166d2b59e7d504513e1222a634aac55c668`
for the closed baseline/lifecycle suites and the exact reviewed c914 build
(byte-identical aa215 Rust peer and revised static Bubblewrap), with the
corrected 6a1 payload. This pairing has not executed. The previous 3f295
pairing passed the two fixed wait cases but failed the tree precondition; see
the [actual result](../README.md#lifecycle-probe-revision-and-first-failed-attempt).
Historically, the c914
Bubblewrap, d074 payload, ae9 wrapper and 5125 driver
passed one [fixed four-case attempt](../README.md#first-passing-native-attempt-four-fixed-offline-cases)
at source `2e494e16e75410903577f62fa07cb9a009711f70`. The `wait`/`tree-*`,
guest FD/namespace-ID, terminal, Claude, hook and credential gates remain
untested by that run. Historical failed attempts remain recorded in the parent
README. Nothing here activates a customer runtime.

The separate `axis-native-harness-build.yml` workflow builds this fixed wrapper
twice with Go1.26.5, `CGO_ENABLED=0` and independent build caches. It verifies the
complete committed source inventory before dependency/build commands, retains
the exact x/sys module archive and notices, and checks static ELF structure and
identical output bytes. The wrapper is never executed there. Source, toolchain,
dependency and run evidence must be independently admitted before any later
native invocation. The workflow pins the exact registry source and receipt,
declares the distinct reviewed fixed-contributor build scope, and never accepts
a caller hash or executable override. The earlier closed-registry wrapper
artifact from 4e5683c4 cannot execute this experiment; a fresh source-bound
wrapper build and independent artifact review are required.

The first slice connects the actual `bridgeprocess` factory and Rust protocol
to four fixed payload cases: literal argv, binary stdin plus EOF and separate
stderr, exit23, and filesystem/offline-socket boundaries. Tests use fake owners,
public synthetic files and deliberately non-runnable ELF headers only. They
never call `bridgeprocess.Start`, create a namespace or execute a native image.

## External artifact review remains mandatory

The compiled registry entry is a source-reviewed exact receipt digest and
complete typed contents. There is no executable/hash/argv/policy CLI override,
discovery, network request, download or fallback. An independent reviewer must
first verify source Git blobs/patches, both build run/artifact/archive/provenance
identities, reviewed locks and all static-musl compiler/UAPI/startup/link inputs.
The two independently staged Bubblewrap builds must reproduce the admitted
image. ELF structure alone cannot qualify this closure. The Go payload must be
source-bound and built using Go1.26.5 with `CGO_ENABLED=0`.

The exact receipt is named `REVIEWED-ARTIFACTS.json`. Its directory contains:

```text
images/peer
images/bwrap-static-musl
images/fixed-payload
proofs/STATIC-CLOSURE.json
proofs/peer-PROVENANCE.json
proofs/payload-PROVENANCE.json
source/payload-main_linux.go
```

The receipt binds version1/scope, no prior execution or production certification,
the three upstream commits, static-closure/payload-source SHA256, ordered peer
and payload build identities, and the exact three image roles/paths/sizes/hashes.
Only an independently reviewed source change can replace these pins. The
running harness verifies the exact receipt/proof/source/image
bytes through nonfollowing held-relative reads and copies admitted images into
sealed memfds. The static Bubblewrap and payload also refuse ELF interpreter or
dynamic program headers. The trusted peer permits only the known system ELF
interpreter and libc/libgcc dependencies, without RPATH/RUNPATH; those host
loader objects remain part of the independently reviewed native host floor.

## Fixed host capabilities and protocol

The live entry requires non-root native Linux amd64, equal real/effective IDs,
the factory's supported unprivileged user/PID/network namespaces and atomic
pidfd custody. It changes no host sysctl, namespace mapping, capability,
privilege, ACL or firewall configuration. Missing kernel/host prerequisites
refuse; disposable-runner preparation belongs to a separately reviewed recipe.

The normal fixed selector always creates a separate guardian-owned PID
namespace for a sealed copy of its own already externally admitted running
static wrapper image. It never executes a caller-selected wrapper. The guardian
retains the atomic clone pidfd and its creating OS thread through native wait.
Worker PID1 first verifies its inherited private pipes and sealed self identity,
installs `PR_SET_PDEATHSIG`, then sends fixed READY. Only after READY does the
guardian write one exact GRANT and EOF. There is no queued future work before
READY: parent loss before that guard yields no GRANT; after it, kernel SIGKILL
of namespace init also terminates its descendants, including nested peer PID
namespaces. This avoids Go's pre-exec parent-PID comparison across a new PID
namespace. An explicit hidden worker selector refuses outside PID1/getppid0,
without the exact descriptors, or without the grant. No test exercises clone,
prctl, the hidden worker or this death/cleanup behavior; it needs independent
source/artifact review and actual native qualification.

One fresh random `/tmp/dc-axis-native-peer-<32 lowercase hex>` root is created
by the trusted host driver before its first user namespace clone. That creator
checks held `/tmp` is root-owned and sticky. Held parent/root capabilities cross
the trusted wrapper and worker; the worker does not infer root ownership from
an unmapped UID or reopen a host source path. Its owner-private root has distinct
`work`, `home`, `tmp`, `outside` directories, readonly file and fixed public
canaries. Before launch the host proves outside read and write-open positives
without changing bytes. Original canary file identities/bytes and grant modes
are checked before/after execution. The held `/tmp` parent, original root name
and outside child name must still resolve without links to the held directory
identities at each check. These are sampled checks, not an atomic guarantee
against a same-UID actor renaming an object mid-case. Negative payload probes only open/close
without truncation, creation or writes. The fixture is retained on all outcomes;
partial setup errors report its new name, and no previous fixture is removed.

Only held readonly/work/home/tmp objects cross the factory's exact capability
table, with work also supplied as held cwd. Outside descriptors never cross.
The peer receives no host object path for its grant table, full policy snapshot,
credential or broker binding. Guest mappings are exactly `/readonly`, `/work`,
`/home`, `/tmp`; argv0 is the sealed `/.defenseclaw/payload`. The only supplied
environment values are HOME=/home, TMPDIR=/tmp and the fixed public selector;
the payload separately requires Bubblewrap's exact derived PWD=/work.

Each fixed case uses a fresh unique correlated session and serialized
Prepare→Prepared→Launch→Started, Input/EOF where applicable, Wait/Exited23,
Destroy/Destroyed. The first three cases check exact byte streams; boundaries
also checks host-visible writes to all three grants and unchanged original
canaries. The owner enforces sequence/request/state/output limits; the harness
checks expected replies, exact binding, aggregate output, typed exit/timeout/
truncation and markers. It drains while running, rather than waiting for process
completion before receiving. The fixed policy is offline with 5-second workload
and 64KiB output bounds, a 20-second owner deadline per case and 90-second total
context. Cleanup gets a fresh bounded context; success additionally requires
the factory's independent namespace-init pidfd termination/wait through Close.
The loop stops on the first failure, without releasing a failed reservation to
start another case. Receipt JSON/peer completion does not substitute for native
cleanup. A failed cleanup retains the exact Session in a reachable owner and
retries native StopAndWait with a fresh bounded context, including before final
reporting. The original failure remains a failed case even if retry cleans.
The outer guardian independently kills and waits the worker PID namespace at
the total deadline and on every return, with its own retained owner and bounded
retry. Remaining cleanup capability stays reachable through final reporting;
unobserved cleanup is a failure, never a success or an assertion of no residue.
After a pending native start, an unobserved creation result is reported as
unknown. A peer Started reply and validated fixed child output markers are
separate fields; a launch acknowledgment alone is not payload-code evidence.

The 90-second context is an execution deadline, not a promise that every host
filesystem syscall completes within 90 seconds. Artifact/fixture filesystem
operations run inside the guardian-owned namespace once admitted; the guardian
can terminate that namespace without depending on the worker's filesystem call
returning. Self-image preparation before clone has no descendants. A separately
owned outer wrapper deadline must also cover this pre-clone stage. Native kill
or wait that cannot complete within cleanup bounds remains explicitly pending.

Binding digests correlate only this contributor experiment. Production
`LaunchGate`/`ExecutionPolicy` require managed hooks and admitted harness
evidence that this canary does not implement. This source does not fabricate
ManagedHooks or a Claude identity to satisfy them. Common-gate integration,
hooks, broker/proxy, model/credentials, interactive terminals and customer
workspace import/export remain unqualified. Deadline/cancel/close, malformed
peer, root-parent-death/descendant and renamed/stale-grant live cases are
separate future experiments; a short successful exit is not those tests.

## Inert validation and later explicit invocation

```text
go test -race -p 1 ./test/e2e/axis/native-peer/harness -count=1 -timeout=2m
go vet -p 1 ./test/e2e/axis/native-peer/harness
```

Linux adds held-file/symlink/FIFO/identity and anonymous sealing tests. Other
platforms run only portable fake-protocol/admission tests and refuse native use.
No test installs or runs an artifact. Cross-compilation is not Linux execution.
Entry-point tests inject an explicitly unreviewed registry and a must-not-call
supervisor. Reviewed-admission tests use a fake supervisor only; the exact live
registry is tested through pure JSON/digest validation. The hidden-worker test
injects an unreviewed registry before native descriptor or PID-namespace checks.

After exact artifacts are independently admitted, the source registry is
reviewed, and one fresh native run is separately authorized, the only invocation
shape is `reviewed-harness --run-fixed --receipt <admitted-directory>/REVIEWED-ARTIFACTS.json --evidence <private-parent>/native-peer-fixed-01`.
The evidence parent must already be owner-private. The separate outer driver
must pin the wrapper/source identity, bound its retained process handle and
streams, and retain raw evidence even on early refusal. Acceptance requires
zero wrapper exit, the guardian's successful native wait in final stdout, and
matching worker observations in stdout/`RESULT.json`. Guardian-only fields are
added to final stdout after the worker's file receipt. A final result-file or
directory close failure may leave an earlier file image and must fail the run.
The wrapper reports bounded fixed reason codes rather than private backend
diagnostics. A future native run's actual result must be recorded separately.

## Private proc bootstrap source revision

The proc bootstrap source revision adds a fresh mount namespace and a fixed sealed FD3
parent-identity proof to each owned child. Before READY/control/backend work,
the child proves kernel ownership and single nonzero UID/GID mappings, makes
mount propagation private, mounts matching procfs and clears startup capabilities.
Only SYS_ADMIN inside the new user namespace crosses the trusted initialization
interval; all Go threads use the CGO0 all-thread barrier, and the Rust peer proves
it is single threaded with signals blocked until cap-zero. No host capability,
UID0 mapping, grant, alternate backend or customer activation is added.

This changes the private FD handoff. Existing e054 peer and d056 wrapper/c8d4
driver artifacts remain historical evidence and cannot qualify this source.
Fresh source-bound artifacts, registry pins and one separately reviewed runtime
attempt are required. The two earlier native failures remain failures.

## Host-created fixture capability revision

The new driver bootstrap carries held `/tmp` and the fresh empty fixture root
at FD8 and FD9 through its exact wrapper exec. The wrapper marks those borrowed
originals CLOEXEC and supplies owned duplicates as worker FD7 and FD8 (proof3,
grant4, ready5, sealed-self6 stay unchanged). The worker initializes the root only
after private owner/mode, empty-directory and held parent-entry identity checks.
Its bounded direct `/tmp/dc-axis-native-peer-<32hex>` display name is correlation
metadata, never a source used to select an object. The driver retains its
originally created label; the worker derives the current held-object label. A
concurrent same-UID rename can make those labels differ, outside the declared
sampled correlation guarantee. The parent/root remain held by the outside
driver for failure evidence; no prior fixture is removed.

Pre-peer refusal reports fixed `native_stage`/`native_errno` vocabulary. Fixed
case failures also record protocol stage and validated closed peer failure codes,
never arbitrary backend errors or diagnostics. These fields do not certify a
payload start. The fixture revision needs fresh wrapper/driver artifacts and one
separately reviewed native attempt; no peer or payload artifact changes.

## Current namespace source-view revision

The c914 Bubblewrap revision uses the identity-checked cached reopen's mount
ID for the current namespace inventory. The incoming FD still supplies the
held object and restrictive-flag authority; both namespace views still refuse
nested mounts. This contract requires the trusted clone-only creator chain,
not arbitrary foreign FDs with matching inode numbers. Its paired driver must
verify current-namespace reachable source mounts with unique mount IDs and
`statmount` basic attributes before the first clone, refusing ID-mapped or
unsupported sources. The reviewed c914 build and combined receipt change only
the Bubblewrap image/static closure and first build identity; peer bytes and
the d074 payload remain unchanged. A fresh wrapper, paired driver and separately
reviewed native attempt are required.

## Fixed lifecycle suite

The explicit `--suite lifecycle` selector adds three bounded experiments while
the default `--suite baseline` retains the four original cases. It requires a
new reviewed wrapper and paired driver artifact; the historical ae9/5125
artifacts do not accept these selectors. The peer, static Bubblewrap and offline
policy stay unchanged. Historical d074 requested setsid for its grandchild;
3f295 instead required denial before normal descendant creation. The first
3f295 attempt under receipt
`8b50970b9636ff84ff6ed0aa3ae7d68d2bc063809e5d8af9073d8e4c804a3e9b`
failed the group-query precondition after its two wait cases passed. It did not
observe tree cancellation or stability, and remains failed historical evidence.

The corrected 6a1 payload uses raw allowed amd64 `SYS_GETPGRP` with errno checked
before the same positive nonleader predicate. The peer/filter stay unchanged.
New receipt `6db10d2a73ee7860bb0d7ad8a6155166d2b59e7d504513e1222a634aac55c668`
binds payload run `39171740021`, artifact `12152816365`, image
`3990927d43320f78586fc669c1a700ecf4c7c8359ba6ada3e41ccd56d4e78e9d`
(1,929,342 bytes) and main source SHA256
`aa695d4df73865cce90afd8dab41c819949a6f8dec66b9fe1a641be035df815e`.
Its injected-function unit test passed without an actual group query. Fresh
wrapper/driver artifacts and their review remain required before another
separately authorized attempt. The wrapper build also selects the existing
pure canonical-registry test alongside the six lifecycle unit roots (ten
passes including nested tests), without any namespace or workload execution.

`wait-timeout` requires the fixed payload's ready marker before its five-second
native plan deadline, then a Launch-correlated `Exited(-1)` with `timed_out`
true. `wait-cancel` observes the same marker before sending Cancel, requiring
`Exited(-1)` with `timed_out` false. `tree-cancel` requires all three exact
parent/child/grandchild markers once, in any order, plus held-work ready files
and heartbeat progress from every process before Cancel. Each role must first
observe Setsid returning EPERM under the unchanged filter, then spawn its fixed
normal descendant. Only the child and grandchild substantiate filter denial:
each first requires a positive group ID different from its own PID. The
parent's EPERM is consistency only because group leadership can cause it
naturally. Cancel cases use a fifteen-second
plan deadline but refuse readiness arriving five seconds after Started; the
tree file observer has an additional two-second bound within that window.

Wait and Cancel have no separate success reply. Both complete through the
original Launch binding, followed by separate Destroy/Destroyed and retained
native cleanup. Every frame, byte stream and file read is bounded. Before any
host Session.Close, the tree case samples unchanged held heartbeat bytes and
mtime six times over 600ms after Exited but before sending Destroy. This is
inside the peer's existing five-second exited idle window. A subsequent
Destroy/Destroyed exchange is mandatory; protocol EOF automatically starts
outer cleanup, so sampling after Destroyed would not distinguish that fallback.
The heartbeat sample is corroboration from
known synthetic writers, not proof of universal descendant absence. The pinned
peer's Exited requires native terminal observation and both native output EOFs;
independent owned native wait and zero cleanup-pending remain mandatory. Host
Close itself can force the outer namespace down, so these observations are
recorded separately. Public count snapshots for the three fixed roles retain
before/progress/post-terminal values and exactly six stable samples; the driver
requires every role to progress and final counts to remain at least those
values. Failures preserve fixtures and stop the suite.

This suite does not qualify root-parent death, control-pipe loss, guest FD or
namespace-ID assertions, terminals, Claude, hooks or broker/model credentials.


## Separate real Claude version canary (source only)

The new closed `claude-version` selector uses the existing owned peer/protocol,
not another launcher. It is distinct from the synthetic baseline and lifecycle
receipts: official signed Claude Code 2.1.292 `linux-x64-musl`, SHA256
`d23f28ef84f5459a25d2d4cf999a7debd41df83507160446983d4ca65554e50f`
(245,203,032 bytes), and independently reviewed shared musl 1.2.6 loader
`76b812138a1d4be51ae095e94920e1fd1c5d25f793651baf834d05a2c455c040`
(853,616 bytes; loader build 39193900521/artifact 12161286875). Peer c914,
static Bubblewrap, seccomp and network policy are unchanged. The typed receipt
also pins the signed manifest, signature, key, official inspection archive and
loader build/closure provenance. No caller chooses image hashes or library paths.

The only command is `/.defenseclaw/payload --version`, with offline/headless
policy, HOME `/home`, TMPDIR `/tmp`, a ten-second workload deadline and 4096-byte
output bound. A pass requires exactly the 22 stdout bytes
`2.1.292 (Claude Code)\n`, empty stderr, exit zero, Destroyed and separately
confirmed native/outer cleanup. It claims no hooks, authentication, network,
agent-session, arbitrary dlopen or common-policy qualification.

The host driver creates one exclusive `claude-runtime-loader` file under its
held fresh 0700 fixture, closes its writer after fsync, and retains a verified
readonly descriptor on the same local executable, non-idmapped creator mount.
The fixed tables pass loader FD10 to the wrapper and FD9 to its worker. The
wrapper/worker mark their copies CLOEXEC; only the first bootstrap deliberately
keeps FD10 through its one fixed wrapper exec. Two owned source duplicates mount
the same held file readonly at `/lib/ld-musl-x86_64.so.1` and
`/lib/libc.musl-x86_64.so.1`; no library directory is granted. Held identity,
size/hash, single-link status, flags and fixed entry correlation are rechecked.
The existing cleanup owner retains version source descriptors while native wait
is uncertain. These are sampled checks against same-UID host renames/mutation,
not an atomic host filesystem snapshot. The new wrapper/driver/artifact chain
and a separately approved actual run remain required; this source is unrun.
