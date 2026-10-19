<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private owned-descriptor mount experiment

This is uncompiled contributor source. It is not an installed runtime or a
customer sandbox. No native execution is authorized by this directory.

`bwrap-owned-fds.patch` applies only to Bubblewrap 0.9.0 commit
`8e51677abd7e3338e4952370bf7d902e37d8cbb6`. It modifies only `bubblewrap.c`.
The patch remains LGPL-2.0-or-later, matching that source; `bwrap-COPYING`
retains the exact upstream license. The source and license Git blob identities
were independently matched to the upstream Git tree before authoring.

| Upstream file | Git blob | SHA256 |
| --- | --- | --- |
| bubblewrap.c | 9b78a9ae30dd8f3361f95ae0132d1c32a4ac3329 | 6a89bc9b7a794d19e2bdb1e139ab9d5bba84e807b330336f363f88f130cfeab6 |
| COPYING | 5bc8fb2c8f757e34a0d8f4644f589d57609e213f | b7993225104d90ddd8024fd838faf300bea5e83d91203eab98e29512acebd69c |

The stock [source](https://github.com/containers/bubblewrap/blob/8e51677abd7e3338e4952370bf7d902e37d8cbb6/bubblewrap.c)
resolves pathname bind sources with `realpath`. A `/proc/self/fd/N` pathname
therefore does not preserve source-object custody. `--ro-bind-data` copies file
contents; it is not a directory-descriptor bind operation.

The additive `--dc-bind-fd` / `--dc-ro-bind-fd` experiment retains each source
descriptor. `OPEN_TREE_CLONE` cannot clone an ordinary source mount belonging
to the old mount namespace after unshare: the kernel requires a source in the
current namespace, and an unprivileged original namespace cannot safely
pre-clone it. The private route therefore admits a deliberately narrower view:

1. Before Bubblewrap's own unshare, hold its current root and namespace. Capture the source
   descriptor's canonical `/proc/self/fd` locator and reopen it beneath that
   root using `openat2` with `RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|CACHED`.
   Compare device/inode/type, filesystem identity and every mount flag bit
   with the original held source. Obtain the `statx` mount ID from this
   reopened current view. A descriptor inherited across an earlier trusted
   namespace clone still refers to its old mount ID; that ID cannot identify
   the cloned view. Refuse deleted, unreachable,
   non-normalized or unrepresentable locators. Any lookup needing I/O or
   revalidation refuses with no weaker retry, including intermediate automounts.
2. Parse the complete bounded mountinfo inventory, not only `st_dev`. Require
   the reopened current source mount ID and refuse every nested mountpoint beneath the source,
   including bind aliases on the same filesystem. Before/after inventories
   must match byte-for-byte. Unparseable or truncated inventories refuse.
3. Prove the active namespace differs from the held original before any mount
   mutation, then make `/` recursively private. Reopen the locator beneath a
   held namespace-local root with the same no-follow rules. Recheck object,
   filesystem, all original flag bits and a complete stable no-submount view.
   Inode equality alone is not topology equivalence. A source covering `/tmp`
   refuses because Bubblewrap creates its own staging mount there.
4. Clone only that held namespace-local object with `open_tree`, reinforce
   `NOSUID|NODEV`, the original `NOEXEC`/readonly restrictions and readonly
   grants, then use `move_mount` with a held destination. No source lookup
   occurs at mount time and no original source attributes change. There is no
   path-authority or mutable snapshot fallback.

This rebind is limited to the trusted private factory's clone-only namespace
chain. It is not proof that an arbitrary foreign or idmapped FD is equivalent
to a different bind alias with the same inode. Before its first clone, the fixed
host driver checks its held temporary parent and fresh empty fixture root using
`STATX_MNT_ID_UNIQUE` and current-namespace `statmount(STATMOUNT_MNT_BASIC)`.
Both must identify the same reachable mount, return the required fields, and
have no `MOUNT_ATTR_IDMAP`; unsupported queries refuse. Subsequent trusted
bootstraps only clone the namespace and replace reserved `/proc`, which no
source grant can cover. The kernel preserves each cloned mount's idmap.
There is no untrusted workload before the later current-view admission.
General production producers still need explicit source-origin/idmap admission;
the unavailable catalog does not advertise that qualification.

`--dc-ro-image-fd` is a separate, exactly-one fixed payload operation at
`/.defenseclaw/payload`. It accepts a held immutable sealed regular file up to
512MiB, creates an exclusive file on the held private tmpfs, copies bounded
bytes and compares the complete copy a second time. Original identity, size
and seals must remain unchanged. The copied file stays held, receives mode
0555 and a readonly mount; the trusted host's admission digest still describes
the identical immutable source. This is not a general grant-copy operation.

Destination lookup is component-relative and rejects symbolic links. Missing
placeholders are created only on the new root's private tmpfs device. An
earlier grant covering a target parent permits only opening an existing target;
the extension never creates files through that source mount. Host source
symlinks such as a reviewed `/lib` alias must already resolve to the trusted
factory's held canonical object. The verified source locator contains no
symlinks. After setup, the held private root tmpfs becomes readonly through a
nonrecursive `mount_setattr`, leaving explicit RW submounts writable. The
separate synthetic `/dev` device tmpfs is not a host-write grant.

Admission requires x86_64, a non-root unprivileged caller, fresh user/mount/PID/
network/IPC/UTS namespaces, and no joined user/PID namespace or setuid helper.
The original mount namespace remains held and must differ from the active one
before any destination mutation. Operation descriptors close after setup, and
original source descriptors are close-on-exec. No weakened or pathname fallback
exists. Mixed legacy setup operations refuse. Only synthetic `/dev` and `/proc`
roots may precede the held mounts; no held destination may cover those roots.
Missing syscalls, mount permissions, headers or mount attributes fail. This
initial route refuses submount-bearing grant trees rather than claiming
recursive policy coverage. Renamed sources can legitimately refuse.

The contracts are the Linux man-pages for
[open_tree](https://man7.org/linux/man-pages/man2/open_tree.2.html),
[mount_setattr](https://man7.org/linux/man-pages/man2/mount_setattr.2.html) and
[move_mount](https://man7.org/linux/man-pages/man2/move_mount.2.html).
`open_tree`/`move_mount` require Linux 5.2; `mount_setattr` requires 5.12. These
version numbers are necessary floors, not sufficient capability admission.
`openat2` requires 5.6, its mandatory `RESOLVE_CACHED` requires 5.12 and `statx`
mount IDs require 5.8. Locked mount attributes
and user-namespace restrictions can still refuse. The pinned
[Linux namespace implementation](https://github.com/torvalds/linux/blob/v6.18/fs/namespace.c)
contains the `may_mount` and `may_copy_tree`/`check_mnt` constraints that prohibit
using the original mount as a clone source after namespace creation.

The pinned [Meson build](https://github.com/containers/bubblewrap/blob/8e51677abd7e3338e4952370bf7d902e37d8cbb6/meson.build)
requires a C compiler, Meson >=0.49, Ninja, Python3 and libcap development files.
SELinux is optional. A disposable build should disable SELinux, completions and
man-page generation explicitly and retain the exact source, patch, license,
compiler, flags and output hash. No install or privileged build is needed.

The separate `bwrap-owned-fd-tests.c` entry point includes this source with its
main renamed and never called. Five inert tests cover mountinfo/locator
refusals, current-versus-imported mount IDs and nested aliases, source/root flag predicates and a fixed sealed memfd byte copy into
an exclusive task-owned temporary file. They never create a namespace, mount,
backend or contained workload. The build records their exact names and results.

Before any use, a reviewed source build must compile this patch with strict
warnings, then qualify read/write grants, readonly root and nested-mount refusal,
source-rename replacement, nested targets, missing targets, denied syscall /
namespace support, descriptor closure and parent-death containment. It must
prove that no source or foreign namespace was mutated. The private peer also
needs a reviewed static-musl loader/bwrap-image execution contract. ELF
`PT_INTERP`/`PT_DYNAMIC` absence alone does not prove that static glibc cannot
load NSS or other modules. Executing a sealed dynamic ELF alone does not pin its
interpreter or libraries.
