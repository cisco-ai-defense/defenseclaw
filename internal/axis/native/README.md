<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private AXIS native peer: source-build slice

This private, unqualified Linux x86_64 implementation is not connected to
`defenseclaw sandbox run`, a customer configuration switch or a native launcher.
It accepts exactly zero CLI arguments and uses only the existing private
`bridgeproto` length-prefixed stdin/stdout contract. The Go host keeps full
authority, credentials, artifact verification, policy generation and outer
native process custody. Correlation digests do not grant authority.

The additive Windows source path uses the same protocol and Owner with native
PSEC and owned overlapped transport. Its separate build, held-capability floor,
external ancestor/image leases and unverified runtime gates are documented in
[the Windows source contract](WINDOWS.md). Linux keeps its existing overlay and
native test inventories; Windows-only inputs are retained as source data.

Preparation consumes the trusted **unprivileged** factory's inherited table:
fd3 = sealed namespace bootstrap proof (consumed before control),
fd4 = immutable sealed static-musl Bubblewrap image, fd5 = sealed ELF payload,
fd6 = held cwd directory, then read and write object descriptors in exact plan
order. Every fd is close-on-exec before library preparation. A guest path label
never authorizes a host source lookup. The cwd must be an exact grant naming the same held
object. Images and grant objects stay held until their single-use launch.

The initial sparse filesystem contract accepts explicit Bubblewrap, offline
network, headless stdio and `/.defenseclaw/payload` as guest argv[0]. Deny masks,
overlapping grants, synthetic `/dev`/`/proc` overlaps, root grants, terminal
requests and other backends refuse. It never drops an unsupported component or
claims that the full resolver projection was enforced. Future production
translation must separately support or refuse every resolved policy component.

The adapter validates an AXIS policy projection, exports AXIS's default-deny
seccomp BPF with all socket creation denied (including Unix sockets), seals the
filter and passes it to Bubblewrap. Bubblewrap applies it before executing the
payload. Read/write mounts originate from owned descriptors through the new
detached-mount seam; there is no host-root mount or path-source fallback. The
seam captures a reachable source locator while comparing it with the held
original object and mount identity. In a distinct recursively private mount
namespace, it reopens that locator using cached lookup without symlink or magic-link traversal and
rechecks object, filesystem, restrictive flags and complete mount topology.
Both namespace views must have no nested mounts within a grant. Deleted,
renamed, ambiguous, unsupported or changing views refuse. An inode comparison
alone is insufficient. Source roots covering Bubblewrap's `/tmp` staging mount
also refuse. This first implementation does not support submounted grant trees.

The sealed payload takes a separate fixed route: a new exclusive private-tmpfs
file receives at most 512MiB, followed by a complete byte comparison against the
same held sealed source, size/identity/seal checks and a readonly mount. It does
not copy mutable grant files. After setup, the held private root mount becomes
readonly nonrecursively, preserving explicit writable submounts. Synthetic
`/dev` remains its separate private device mount. Payload
dynamic interpreters/libraries must exist only within the explicitly admitted
guest read mounts. No additional child plan contains host policy or bindings.

The additive MXC seam executes the held static image via `execveat`, never PATH,
and retains a pidfd for the exact Bubblewrap monitor. The private bwrap route
uses `execv` and requires an absolute guest executable, with no shell fallback.
Both static ELF structure and separate reviewed static-musl build provenance
are mandatory. Static glibc or a missing interpreter entry alone cannot prove
the loader closure. The optional static build supplies only an unexecuted
candidate and its evidence, without runtime admission.

The host must create the peer as PID1 of a fresh outer PID namespace. Before
environment, descriptor or backend preparation, the peer requires PID1/parent0
and installs its own `PR_SET_PDEATHSIG(SIGKILL)`. Go's post-clone host-PID check
is incompatible with this namespace. Host protocol EOF refuses a host death
before this prctl; Linux ties the signal to the creating thread, so an early
thread death may stop the peer even while the host process survives. These
availability and parent-death properties still need actual native clone tests.

One polling owner serializes protocol admission, native state and frame output.
Child pipes and protocol pipes are nonblocking; input is capped at 64KiB, output
frames at 16KiB, and the outbound queue at eight frames. A stalled protocol
writer refuses after 500ms without progress. Deadline/cancel/malformed input /
backpressure stop the exact owned pidfd, with a two-second cleanup bound.
Success needs native terminal observation and both output EOFs. `Destroy` has
its own acknowledgement. Failed cleanup never becomes successful destruction;
the Go host must independently stop/wait its exact helper custody on every
failure. This source has not established namespace/descendant lifecycle proof.

The dedicated build workflow uses exact AXIS fb5, MXC fda and Bubblewrap 0.9.0
commits and pinned action SHAs. It starts from the already reviewed Linux probe
lock. Before compilation, any registry package/version/checksum absent from
that seed refuses. Discovery produces the new root lock for independent review;
only a committed reviewed lock permits the later locked rebuild. Python 3.11+,
Rust1.95, a C compiler, Meson, Ninja, pkg-config and libcap headers are build-only
requirements on a disposable runner. Nothing installs an AXIS service/runtime.

CI compiles the Rust peer and runs protocol/fake-process/owned inert-FD tests.
It separately compiles the C extension using ordinary dynamic host libraries,
without running it; that output is not an admitted runtime and is not packaged
as one. Six selected dependency unit gates separately exercise the AXIS BPF
export and MXC inert-image/guest-path/compiled-image and private-filter admission against unchanged
upstream workspace locks; these tests never install a filter or spawn a backend.
Four separately compiled C unit tests exercise topology parsing, locator
validation, restrictive flags and an owned inert sealed-byte copy. Their entry
point never calls Bubblewrap's main, namespace/mount setup or workload launch. The
explicit `--static-musl` build-only extension uses pinned musl/libcap sources,
the exact GCC13/Ubuntu package byte inventory, an allowlisted static link closure
and two independent staging roots. It never executes either Bubblewrap image.
See [static closure requirements](static/README.md). Artifact evidence retains
source overlays, exact licenses, upstream and
combined locks, toolchain, checksums and explicit unqualified scope. A discovery
artifact, green unit tests or a C compile do not authorize native execution.

Before runtime use: independent source/artifact/lock review; reviewed static-musl
Bubblewrap/libcap closure; native sealed-image copy/mounting; no-host-root read,
readonly private root and read/write boundaries; refusal of nested mounts
(including same-filesystem aliases); source rename/replacement;
no foreign namespace/source mutations; namespace/syscall refusal; complete
nonstdio-FD closure; actual binary stdio/exit; parent EOF/death, timeout and
descendant cleanup. This is a new enforcement posture and inherits none of the
earlier Landlock contributor probe's successful boundary assertions. PTY,
Windows/macOS peers, brokers, hooks, credentials and model traffic remain later
gates. See [patch source contracts](patches/README.md).

## Private proc bootstrap source revision

The next source revision adds a fresh mount namespace and a fixed sealed FD3
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
