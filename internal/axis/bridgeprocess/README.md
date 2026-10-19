<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private native process custody

This disconnected Linux and Windows x86_64 source owns a trusted private peer,
not a customer sandbox. No production caller, artifact registry, broker,
provider capability claim or configuration activation is supplied here.
Ordinary `SealImage` remains Linux-only. Windows requires the separate held-root
image constructor below. `Start` refuses on other hosts. The matching Windows
Rust peer/engine is unfinished, so its Go transport cannot yet run a session.

Windows-only `SealImageIn` copies an already-open admitted artifact into one
fresh protected directory beneath an explicit held private NTFS root. It retains
a read-only `SEC_IMAGE_NO_EXECUTE` view before closing its sole writer, then
acquires a strict read/execute pin without write/delete sharing and rechecks
full file identity and digest. It never executes or loads the image. The source
and root remain caller-owned; no ambient TEMP, path discovery or wire credential
selects them. This constructor is private source, with no production caller.

The owned Windows copy has independent cleanup through the same Image.Close.
A consumer duplicate can postpone deletion; retain the Image and retry Close
after that duplicate releases. A partial constructor can likewise return a
nonnull cleanup-only Image with an error; its missing file/digest refuse
launch or duplication. Uncertain native close/unmap errors remain sticky and
are not blindly retried. Cleanup checks the full file ID, disposes only the
fixed owned leaf and its empty held directory, and never recursively traverses
unexpected children. A context bounds copy iterations, not synchronous
filesystem calls; a separately bounded owner must supply a total deadline.
The native image/view tests use copies as inert data and never execute a PE,
create a child, or qualify Windows peer/PSEC transport or a customer runtime.

Windows `Start` uses the existing `Session` and protocol owner. Its cleanup owner
exists before any allocation, including partial pipe, image, grant and Job
setup. It creates only the admitted trusted peer with argv0, an explicit empty
environment and no console. A single kill-on-close Job and the explicit inherited
handle list are assigned atomically at suspended creation. Membership and the
class44 comparison of the actual process image to the held peer must pass before
resume. No PID, process-name lookup, NULL application or pathname fallback grants
identity. Original images and grants remain caller-owned.

The private command pipe first transfers a fixed capability prefix: 56-byte
header, then at most 514 forty-byte records (20,616 bytes total). It contains
version1, read/write counts, preparation digest, payload/CWD/read/write roles,
inherited handles and full volume/FileID values; reserved bytes are zero. It
contains no paths, argv, environment or credentials. The Windows peer must
validate each actual object and correlate the next Prepare digest before the
existing LaunchGate-controlled protocol can launch a workload.

Both child pipe endpoints are explicitly overlapped; the ordinary private pipe
constructor keeps its existing behavior. The new construction owner retains raw
server/client/event handles and pinned OVERLAPPED storage on partial failure.
Cancellation polls terminal completion without a blocking native wait; a timeout
retains storage for retry. The Windows Rust transport must likewise own each
buffer/event/OVERLAPPED through CancelIoEx and terminal GetOverlappedResult. It
must not wrap these inherited endpoints in synchronous Rust File/stdin/stdout.
Each Rust OVERLAPPED must set the low bit of its event handle to suppress a
completion packet to any inherited host IOCP association, while retaining the
untagged event for wait and close. Go's File.Fd disassociation attempt is not a
proof that this association was cleared. See the documented
[completion notification rule](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus).

Cancellation latches closed admission while native creation is pending. A late
creator signals its exact Job/root before completing startup; cleanup requires
both a signaled root and Job active count zero. A nonnil partial Session owns
cleanup even when Start fails. Use StopAndWait for a cleanup-only Session without
a Protocol; retain it after timeout or uncertain close. Native close uncertainty
is sticky. Ordinary filesystem calls remain synchronous and need a separately
bounded caller. Pure admission/bootstrap/custody tests do not establish actual
Windows peer interoperability, descendant/parent-death behavior or PSEC policy.

The remaining description concerns the Linux native path.

The host must independently admit runtime and harness artifacts and obtain
their digests from its trusted registry. `SealImage` copies an already-open
regular file, checks the exact copied bytes, and seals an anonymous memfd.
It never discovers a path or accepts wire digests as authority. ELF structure
alone does not establish provenance or a static-musl loader closure.

The factory duplicates held images and filesystem objects into the Rust peer's
fixed FD table. Its only executable name is its own remapped sealed descriptor
through `/proc/self/fd`; it supplies zero arguments and an empty environment.
The peer starts inside fresh unprivileged user/mount/PID/network/IPC/UTS namespaces.
FD3 is a sealed parent namespace-identity proof; image/root capabilities begin
at FD4. Before control or backend work, the trusted peer proves new namespace
ownership, mounts a private matching procfs and clears its startup capability.
The only ambient startup capability is SYS_ADMIN in the new user namespace;
the verified parent has none. See [namespace bootstrap](../namespaceinit/README.md)
for the exact trusted initialization interval and refusal gates. This new
private handoff needs a freshly admitted peer and harness artifact; prior
artifact/runtime observations do not qualify it.
An atomic clone pidfd owns the exact namespace init; no workload name, PID
enumeration, process group or protocol completion is used for cleanup.
The PID namespace is an outer lifecycle boundary; the peer's inner MXC/
Bubblewrap route supplies the separately admitted filesystem/syscall boundary.

A pending native custody latch exists before protocol workers or clone.
Cancellation before native start permanently closes admission. A kernel start
already in progress retains all child-side image/pipe copies until remapping
finishes, even if the caller times out. Its creating thread then stops any late
trusted peer before completing cleanup; no workload Launch can follow closed
protocol admission. A dedicated locked Go OS thread performs both start and
native wait, keeping the peer's creating parent thread alive for that lifetime.
No custody mutex is held across the kernel start or native wait, so pending
creation cannot block the cleanup context's deadline.
Every post-constructor failure returns the nonnil `Session`; keep it after
cleanup errors. Its independent `StopAndWait` can retry native cleanup after
the protocol owner's one-use cleanup has failed. A protocol failure remains
a failed session even if native cleanup later succeeds.

Stopping signals the exact init pidfd and observes its owned native wait.
Linux kernel PID namespace teardown kills and waits for namespace members
before init can be reaped. Go's `SysProcAttr.Pdeathsig` is deliberately absent:
its post-clone parent-PID comparison cannot use an ancestor namespace PID.
The trusted peer sets its own parent-death signal before processing commands;
private protocol EOF covers host death before that setup. Creating-thread death
can still precede host process death, so this is additional defense rather than
the authoritative process-lifetime signal. A cleanup timeout retains custody
and reports failure. Hosts lacking atomic pidfds are refused; any already
created direct child remains owned through its exact Go process object and
reaper while cleanup is observed.

Tests cover inert sealed-image copying, ownership after source mutation,
closed-image refusal, cancellation before native creation, unsupported-host
refusal and independent cleanup retries using fake native custody. They do
not execute the private peer or a contained workload. Exact native clone,
descriptor transfer, nested namespace/deadline/parent-death cleanup, and
read-only/read-write boundary tests remain required before activation.
