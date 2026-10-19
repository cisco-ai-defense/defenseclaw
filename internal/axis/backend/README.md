# Native AXIS backend ownership slice

This package connects `sandboxruntime.Backend` and `PreparedProcess` to the
existing concrete `bridgeprocess.Session`. It starts nothing at construction.
Its public installation catalog is unavailable, with no advertised capabilities
or qualified harnesses. The gateway does not activate this backend.

The manager supplies a bounded session-lifetime context and binds one complete
session identity to exclusively owned image/directory handles. Artifact admission
and sanitized host staging belong to that trusted producer. `Spec.HostWorkspace`
is metadata; it is never reopened or used to select a host object. No caller hash,
PID, executable name, environment variable or serialized receipt grants authority.
The private owner permits at most 64 active records and 4,096 lifetime IDs.
Deleting a record never permits its immutable session ID to be reused.

The concrete native path prepares the trusted peer, checks its correlated
`Prepared` frame, freezes the specification, and exposes one `Launch` operation.
The existing manager must reserve the identity and dispatch that handle through
its common `LaunchGate`. Preparation starts no agent or credential grant. A
request cancellation closes partial preparation with a fresh bounded cleanup;
successful preparation remains owned by the manager lifetime. Failed native
cleanup retains the exact session and assets for retry. Asset release requires
joined protocol workers and independent native wait success under a still-live
cleanup context, not a `Destroyed` frame. A sticky protocol failure is reported
even when that verified cleanup releases assets; the phase is `failed_closed`.
An exclusive file/image close failure stays sticky and cannot become successful
on retry.

`NewHostStageAssets` adds a custody handoff for an already prepared Windows
host stage and an explicit MXC ProcessContainer session identity. It fills an
empty CWD and `/work` slot with two
independent, full-identity-checked, non-inheritable copies obtained through the
stage's held root lease. It never reopens `TreePath`. The read/query handle
rights and `/work` association do not grant guest write permission or qualify
the Windows native bridge. Other supplied grants remain the trusted producer's
responsibility; this handoff does not establish their confinement or lineage.

A successful return transfers all inputs and stage custody. A nonnil result
with an error owns only its allocated copies, lease and stage; the caller must
close that cleanup-only result and keeps ownership of supplied images and
other files. Cleanup-only assets cannot be bound. After independent native
cleanup, every exclusive file/image must close successfully before lease
release and stage deletion. Uncertain exclusive close keeps that barrier and
reports a sticky failure. If another stage lease prevents deletion, no child
is removed; explicit asset-close retry can finish after that consumer releases.

The same custody constructor accepts a Linux MXC Bubblewrap identity and a
Linux host stage. It retains the same two exclusive descriptors and lease
release order. It does not certify the copied root's current mount/no-IDMAP
lineage, installation images, policy translation or native execution. Those
remain independent admission checks; this addition does not open the catalog.
A cleanup-only stage returned with a preparation error cannot issue the root
lease required by this constructor; its caller retains cleanup ownership.

`PreparePolicyHostStageAssets` derives capture options from the same opaque
host-resolved `ExecutionPolicy` used by the backend. It accepts only copied,
canonical Windows/Linux projects within the current producer's size floor.
Masks, unmask entries, protected policy sources, history depth and byte cap
come from the policy; callers supply only the trusted home/data location and
already-held image/file inputs. There is no detector or scan-disable override.
Successful assets retain a private association with that policy, complete
session identity, workspace component and actual stage summary. Caller-created
`NewAssets` values cannot manufacture this association. Partial preparation or
handoff retains a cleanup-only owner, with supplied images transferring only
on success.

The compiler validates an existing preparation association but still refuses
the complete workspace component. Bounded result export, review, on-exit and
undo semantics remain unfinished; capture does not acknowledge them. The
merged policy also lacks the explicit-request subset used for unmatched
`--unmask` warnings, so this producer claims no warning parity. It installs no
runtime or artifact capability and does not check current publication itself;
the future controller must use the owner's launch gate and complete admission.

The complete affected Windows backend race suite passed 58 tests/subtests with
zero failures or skips (9.362 seconds); Windows vet and Linux compilation/vet
also passed. The fresh [three-platform host matrix](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39179169402)
at **2d679e73** then passed full workspace/backend race suites and vet on Ubuntu,
Windows and macOS. Its Linux case exercises the actual policy-derived
sanitizer, mask/unmask selection, full session association, held assets,
original-source preservation and cleanup. It starts no sandbox; complete
workspace policy translation and runtime qualification remain unavailable.

The native Windows filesystem custody regression passed under the race
detector, without executing an image, child process or sandbox:

```powershell
go test -race '-ldflags=-w -s' -p 1 ./internal/axis/backend -run '^TestHostStageAssetsWindowsHeldDuplicatesAndCleanupRetry$' -count=1
```

It verifies the full native identity, private/non-inheritable handles, two
independent exclusive copies, retained child bytes during an in-use cleanup
refusal, and successful release/retry without owned residue.

The policy compiler refuses all incomplete components and emits no partial
`PolicyReceipt`. Sparse filesystem/native offline canaries do not implement
common policy, administrative authority, workspace provenance, managed hooks,
MCP or a credential broker. Runtime/harness qualification and each complete
component translation must be added explicitly before the catalog can open.
The initial native mechanism is Linux MXC Bubblewrap. Other platforms,
interactive execution and repeated execution remain unavailable here.
The generic `Backend.Exec` refuses rather than starting an unqualified process
or creating an uncancellable worker around a caller's arbitrary stream.

`OpenAttachment` implements the bounded headless transport for one already
launched concrete session. The default unavailable catalog refuses admission.
The existing manager must verify current policy and the complete owned identity
before calling it; a client name or session ID is insufficient. One immutable
session admits one consumer for its lifetime. Attachment input is literal binary
stdin, EOF or cancellation, bounded to 64MiB and 8,192 successful input frames;
resize remains refused. It cannot start a command,
change environment or extend the original execution deadline. The HTTP admission
context detaches on success; the manager lifetime and requested shorter timeout
still cancel the owned native session. Output and exit are correlated to the
original Launch request and complete bridge binding, with aggregate output bounds.

Send and Receive use the existing cancellable protocol owner directly. They do
not hold the entry lifecycle token during stream I/O, so Stop/Close can terminate
a blocked receiver. Disconnect/Close uses the same retained native custody and
independent wait as every other teardown. Failed cleanup retains assets; retry
does not erase the attachment's original failure. A peer exit event alone never
releases assets. This source implementation does not qualify production streaming
or activate a gateway manager route.

Lifecycle and transport tests use private function injection over the existing
concrete session and inert held files. Stage handoff tests also cover partial
allocation, cancellation, mismatched driver metadata and sticky close errors.
These tests never execute images, clone namespaces, mount, change capabilities
or call a native worker entry point. Fixed test qualification is never
registered as production evidence.
