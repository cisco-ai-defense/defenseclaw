<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private helper pipe owner

This package owns one private helper's parent stdio ends and the Go side of
`bridgeproto`. It starts no process, daemon or customer runtime. It grants no
policy authority. The actual native launcher, artifact admission, session
reservation, prepared-resource translation and `LaunchGate` remain mandatory.
No production caller activates AXIS through this package yet.

The launcher must first establish independently owned native custody, then
transfer three distinct pipe objects and its `Custody` implementation to
`New`. A nonnil returned owner accepts those resources, including when pipe
admission fails; a nil return leaves cleanup with the caller. `StopAndWait`
must terminate and observe the actual helper/workload tree within its supplied
context, independently of protocol cooperation. Its implementation remains
required; tests here use an explicit fake and do not establish process custody.

An absolute parent deadline covers preparation and the admitted execution
timeout. Command issuance holds one lock across sequence/request assignment,
conversation admission and complete frame encoding. Writes have a bounded
deadline; cancellation closes all owned parent ends. Decoding admits one frame
at a time into a 32-frame queue. Queue saturation, malformed input, unexpected
EOF, excessive diagnostics or cancellation close the pipes and invoke custody
once. Diagnostics are discarded, never logged or included in errors. Aggregate
workload output bounds are enforced by `bridgeproto` as frames are admitted.

The Windows parent endpoints are overlapped single-instance local named pipes,
with 192-bit random names, protected owner/SYSTEM DACLs, remote-client refusal
and both endpoint creator PIDs checked against this process before return.
The child endpoints are synchronous for Rust stdio. Both ends start
noninheritable; the launcher must explicitly inherit only the child ends and
close its copies. These are immediately connected private channels, without an
accept loop or public service. Anonymous Windows pipes refuse the deadline
contract. Duplicate parent kernel objects refuse even when their handle
numbers differ. The launcher must preserve each endpoint's role.

`Receive` checks both its caller and owner context before delivering queued
events. After a valid `Destroyed` event, the caller must still call `Close` and
require successful native cleanup before releasing the complete session
reservation. A protocol event or pipe closure does not prove containment,
cleanup or policy enforcement. Cleanup failures preserve caller responsibility;
the controller must remain closed to new launches until custody is repaired.

Native Windows race tests exercise actual private pipes: literal lifecycle
frames, blocked-write deadline, concurrent command serialization, canceled
queued events, malformed input, peer loss, output/diagnostic backpressure,
anonymous-pipe refusal and duplicate-handle refusal. They launch no helper,
contained workload or PSEC process. Linux/macOS execution and actual native
helper integration need their own observed results.

References: [Microsoft overlapped pipe connection contract](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe),
[kernel object comparison](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles).
