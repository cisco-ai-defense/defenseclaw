<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private namespace bootstrap

This internal Linux amd64 package creates no process and activates no provider.
The trusted private child consumes one sealed 64-byte parent identity proof at
FD3. Parent namespace identities come from held NSFS handles; the retained parent
process keeps those namespaces alive. The proof carries nonzero UID/GID and
user/mount/PID namespace device/inode identities, never a pathname or host PID.

The parent clones new USER, MNT, PID, NET, IPC and UTS namespaces with a single
nonzero identity map and only namespace-local ambient `CAP_SYS_ADMIN`. Before
any mount, the child checks distinct kernel namespace identities and
`NS_GET_USERNS` ownership, exact maps and the expected startup capability sets.
Inherited `/proc/self/ns/*` identifies the current task even while the inherited
procfs exposes an ancestor numeric PID view. It makes all mount propagation
private recursively, attaches a fresh procfs through owned mount/destination FDs,
then clears ambient, effective, permitted and inheritable capabilities on **all
Go OS threads** with Go's CGO0 `AllThreadsSyscall`. It sets no-new-privileges on
all threads and reads bounded per-thread status to verify all four capability
sets are zero and NNP is set. It verifies unchanged namespaces and a matching proc PID
view before READY or another execution stage. No bounding-set expansion occurs;
bounding bits cannot grant anything after cap-zero plus no-new-privileges.

The pinned CGO0 compiler/runtime and package initialization are trusted while
the startup capability exists only in the new user namespace. No untrusted
callback, input, backend or workload runs during this interval. Go's documented
all-thread syscall barrier handles existing runtime threads; future threads
inherit the cleared state. A cgo/foreign-thread runtime is refused. The Rust
peer performs the same checks before backend/control work, while proven single
threaded with signal delivery blocked; it restores signals after cap-zero.

Failure is terminal for the owned PID namespace. There is no setns, host mount,
UID0 mapping, pathname mount fallback, policy relaxation or customer activation.
PDEATHSIG is installed before proof inspection. Protocol/GRANT EOF covers parent
death before that installation; the creating OS thread remains held through
wait. A creating-thread early death may still cause an availability failure.

Default tests use synthetic proofs, maps, identities and fake ordered bootstrap
operations. They never clone, mount, change capabilities or execute a workload.
Actual namespace ownership, proc mounting, all-thread cap state and cleanup need
fresh reviewed Linux runtime evidence; previous failed canaries remain failed.

Primary contracts: [Linux self lookup](https://github.com/torvalds/linux/blob/v6.17/fs/proc/self.c),
[namespace lookup](https://github.com/torvalds/linux/blob/v6.17/fs/proc/namespaces.c),
[PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html),
[user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
[Go all-thread syscall](https://pkg.go.dev/syscall#AllThreadsSyscall6).
