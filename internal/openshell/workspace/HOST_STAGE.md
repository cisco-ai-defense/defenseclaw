<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Captured host staging

`stageCapturedSHA1` is a private host staging engine used by `PrepareHostStage`.
It is not connected to `Stage`, a provider, a CLI flag, or agent execution. Its
controlled native fixtures establish the behavior they assert; they do not
qualify native Windows guest operations, AXIS, credentials, or a production
workspace import/export lifecycle.

## Linux held-root producer

Linux host preparation reuses the same captured SHA1 decoder, sanitizer,
history withholding and operator-setting rules; it does not execute Git.
Its initial floor accepts only clean absolute paths on the process's root
mount, using one existing path component per `openat2` call with
beneath/no-symlink/no-magic-link/no-mount-crossing resolution. Each call uses
`O_PATH|O_NOFOLLOW|O_CLOEXEC`, without `O_DIRECTORY`, trailing slash or multiple
components. Before descending, its held object must be a directory on the same
root mount and admitted local filesystem. Separate mounts and bind aliases
refuse, including otherwise ordinary separate home or data volumes. An
unsupported kernel or ambiguous lookup fails without a retry or pathname
fallback. The
admitted local filesystem types are ext4, XFS, Btrfs, tmpfs and OverlayFS; this
assumes the host's root mount and its backing configuration are trusted.
For an existing positive terminal dentry, Linux's `O_PATH` lookup does not
trigger an unmounted automount point; an autofs object refuses before the next
descent. The reviewed kernel paths are [O_PATH intent construction](https://github.com/torvalds/linux/blob/v6.14/fs/open.c#L1244)
and [terminal automount handling](https://github.com/torvalds/linux/blob/v6.14/fs/namei.c#L1346).
This is an existing local-directory floor, not support for arbitrary
negative/dynamic automount dentries. The local filesystem calls can block in
the kernel and are not hard-deadline-interruptible by context cancellation.

The first host regression run, `39177612908` at `9406422c`, refused its positive
Linux fixtures at the initial source lookup with `EAGAIN` under the earlier
full-path `RESOLVE_CACHED` implementation. That run did not qualify Linux
capture; Windows and macOS workspace/backend race and vet gates passed. The
component-only correction retains the four confinement flags
without a cached/uncached retry; the subsequent run is recorded below.

The corrected lookup run `39178507434` at `72749796` reached Linux capture,
sanitization and the held-assets custody regression (backend race package
passed in 2.612 s). Its workspace package still failed: two accepted-mode
subcases wrongly expected an unborn repository's guest index to contain the
synthetic baseline. The index intentionally reflects the original empty HEAD;
the separate baseline commit/tree records the captured working files. The
test-only correction checks both representations and the copied POSIX mode.
This remains a failed run, not a complete workspace regression pass.

The fresh [host regression matrix 39179169402](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39179169402)
at exact source **2d679e73ef4fb8767bced5d78c7e01e83316f972** passed workspace and
backend race suites and vet on Ubuntu 24.04, Windows 2025 and macOS 15. Linux
workspace/backend package times were 13.224/2.864 seconds, Windows
21.571/2.922 seconds and macOS 44.735/2.961 seconds. Root and GPT-6 Sol Max
independently checked API records and saved log hashes. This includes the
corrected mode oracle, cleanup-only ownership, held-root/asset barriers and the
actual policy-derived sanitizer/asset producer. These are ordinary host
filesystem assertions; no namespace, filter or sandbox payload was executed.
The two earlier failed runs remain failed.

The staging parent must already belong to the current effective UID with no
group/other mode permissions. No permissions repair occurs. Fresh artifact,
capture, sanitized and scratch objects are private and created relative to
held parents. Only directories and single-link regular files enter capture;
links, devices, sockets, FIFOs and mount traversal refuse before data opens.
The entire source, including `.git` and later withheld files, is bounded to
500 MiB, 250,000 entries, 128 levels and the existing component/path limits.
Linux deliberately retains the conservative Windows-compatible name subset
and refuses case-colliding entries. The normal sanitizer/object limits also
apply. Tracked files whose working execute bit differs from their captured
Git index refuse; the initial floor does not silently discard chmod-only
changes. Accepted executable working files are materialized as private mode
0700; other emitted working files are mode 0600.

Original entries are pinned with `O_PATH` before type admission. Readable
handles and `os.Root` adapters use only the exact numeric alias of a still-held
descriptor under verified procfs, with matching PID view and before/after
object, mount, type and private-mode checks. This intentional capability alias
never selects an original display path or `TreePath`. The initial full source
metadata snapshot must still match when capture starts. Source identity and
size/mode/ctime/mtime are also sampled around each read and directory traversal;
the retained private capture is then the sanitizer's only input. This is not
an atomic multi-file snapshot or protection against a malicious same-UID host
process mutating the private capture. Private producer custody is required.

The sanitized root remains held, and consumer copies use
`F_DUPFD_CLOEXEC` with checked object identity and private mode. The existing
lease barrier prevents deletion or producer-root closure before consumers
release. Cleanup traverses only the held private parent with bounded
nonfollowing opens, sampled identity checks and `unlinkat`; it never calls
`RemoveAll` or reopens a display path. Linux has no unlink-by-handle comparison:
the final name check is a sample, not an immutable-parent guarantee against
same-UID host renames. Failures report retained residue rather than selecting
a fallback target. If Linux preparation cannot complete cleanup, it returns a
nonnil cleanup-only `HostStage` with the error. The caller must retain that
owner and call `Close`; it cannot acquire a root or expose `TreePath`. An
uncertain native file or root close stays sticky, retains producer custody and
prevents deletion. A known bounded-removal refusal permits explicit cleanup
retry through the same owner.

This producer and `backend.NewHostStageAssets` do not certify native source
mount topology/no-IDMAP lineage, guest permission, runtime/harness images,
policy translation or production launch. The adapter must independently check
those requirements before its first namespace clone. The host regression pass
above establishes only the assertions exercised by those synthetic fixtures.

## Owned sanitized-root custody

`HostStage.AcquireRoot` returns a tracked `RootLease` for the already-held
sanitized tree. Windows acquires it through the held artifact, `sanitized`
directory and repository directory handles; `TreePath` is never reopened.
Each duplicate retains the same native identity, private-handle checks and
non-inheritable read/query access. Those handle rights are custody limits,
not guest read-only enforcement: relative child access still uses the
caller's token and requires separate native filesystem policy.

At most 64 acquisitions can be pending or held. `HostStage.Close` blocks new
acquisitions, `TreePath` and new `RootLease.File` borrows, then refuses with
`ErrHostStageInUse` before deleting any child or closing producer pins while
consumer custody remains. Previously borrowed files remain owned by their
leases. Acquisition and release perform native I/O outside the stage mutex;
pending operations keep their tracked slots. A nonnil lease returned with an
error still requires explicit release. An uncertain lease close retains its
slot and sticky error. Releasing the last lease does not implicitly clean up
the stage; the owner must retry `HostStage.Close`.

`RootLease.File` is borrowed and must not be closed or passed directly to
`backend.NewAssets`, which consumes exclusive handles. `RootLease.Duplicate`
returns an independently owned copy through the same native validator. Pending
duplication prevents lease release; if stage close wins during duplication,
any allocated file is returned with an error for cleanup only. The trusted
consumer must keep the lease until every returned copy has definitely closed,
including copies returned with errors. This contract cannot stop a host
consumer from releasing its lease prematurely.

`backend.NewHostStageAssets` uses two such copies for CWD and the `/work`
association and retains the lease through confirmed native cleanup and
successful asset closure, then releases the lease and stage in that order.
Its native Windows filesystem regression verifies full identity, private and
non-inheritable handles, retained child bytes when another lease prevents
cleanup, and successful explicit cleanup retry after release. This handoff
does not activate a Windows runtime. For the Windows producer, before preparation
returns a stage, a producer-pin close failure prevents recursive deletion and
can leave residue; that error path does not return a stage owner for retry.

The native Windows custody regression passed under the race detector:

```powershell
go test -race '-ldflags=-w -s' -p 1 ./internal/openshell/workspace -run '^TestHostStageWindowsRootLeaseHeldObjectAndCleanupBarrier$' -count=1
```

It verifies a decoy display path cannot select the tree, two duplicate native
identities are non-inheritable, child bytes survive premature cleanup, and
explicit release followed by cleanup removes the owned fixture. Separate
fake-only tests cover pending acquisition/release, the 64-lease bound, partial
allocation and sticky close failure. No child program or sandbox is launched
by these custody tests.

The caller must retain the private captured-source, output and scratch
`os.Root` handles and clean them up on every refusal. The source has already
passed the NTFS/local-drive, private DACL, held-source, reparse/stream/hardlink,
case/name and complete-capture checks. Root identity and original policy
identity belong to that caller. The engine never rebinds policy to a temporary
capture, reopens a drive-letter path, or starts stock Git. `opts.Project` is a
name/policy fact, not an I/O path in this engine.

Private host preparation freezes operator line-ending fallback facts through
bounded nonfollowing held reads in `operatorConfigDirs` order: home `.gitconfig`
then XDG `git/config`. Missing parents/files are known absent through held
ancestors; unreadable, linked, streamed, oversized or include-based config
refuses. The engine merges local values from its exact captured `.git/config`
over those facts before validating transformations. Plain snapshots preserve
their existing raw-byte baseline and need no operator Git config. Unsupported
transformations refuse instead of silently changing snapshot bytes. Existing
POSIX staging and customer Windows platform availability are unchanged.

## Dependencies and call boundary

The optional implementation is compiled from go-git **v5.19.3** and its Billy
**v5.9.2** transitive dependency. Go module checksums pin source bytes in
`go.sum`. The reviewed module closure raises the existing `golang.org/x/crypto`
floor from v0.55.0 to v0.56.0 and `golang.org/x/exp` from
v0.0.0-20250305212735-054e65f0b394 to
v0.0.0-20260410095643-746e56fc9e2f.

Only plumbing object/hash, stream config/index/pack codecs and the ignore
matcher are used. `plumbing/object` transitively links go-git's config, storage
and Billy osfs packages. This is a linked dependency distinction: the engine
does **not** call ambient config loading, Billy/osfs, filesystem storage,
repository discovery, clone/fetch, transport, subprocess or mmap APIs. Every
actual filesystem access is relative to an already-held `os.Root`.

Review source and published advisories when changing either pin:

- [go-git v5.19.3](https://github.com/go-git/go-git/releases/tag/v5.19.3)
- [Billy v5.9.2](https://github.com/go-git/go-billy/releases/tag/v5.9.2)
- [go-git published security advisories](https://github.com/go-git/go-git/security/advisories)
- [Billy published security advisories](https://github.com/go-git/go-billy/security/advisories)

## Bounded accepted format

Limits refuse the entire candidate; selection is never silently truncated.

| Resource | Bound |
| --- | --- |
| Complete raw capture | Existing `MaxBytes`, 250,000 entries, 128 directory levels |
| Engine deadline | 5 minutes, respecting an earlier caller deadline |
| A decoded object or delta payload/result | 32 MiB |
| Aggregate inflated pack/loose payloads and reconstructed/generated objects | 512 MiB |
| Physical object entries and new distinct objects | 100,000 |
| Delta dependency depth | 64, including already-cached bases; cycles refuse |
| Index/packed refs/shallow input | 16 MiB per file |
| Repository config or an ignore/attributes file | 1 MiB per file |
| Relative path | 4,096 UTF-8 bytes; validated NTFS component names; 128 levels |
| Working path count and total path bytes | 100,000 and 16 MiB |
| Cumulative flattened tree entries and path bytes | 100,000 and 16 MiB |
| Commit metadata / parents | 1 MiB / 64 parents |
| Ignore pattern length / aggregate pattern+domain metadata | 4,096 bytes / 1 MiB |
| Ignore patterns / matching work | 100,000 / 10 million pattern-prefix comparisons, plus 4 Gi weighted pattern/path work units |
| Emitted files, complete host object store and guest metadata together | `MaxBytes` |

Pack/index counts, canonical index layout bounds and object lengths are checked
before codec allocations. Loose object headers are capped before parsing;
the upstream loose-reader's unbounded header API is not used. Delta source and
target sizes are checked before patch allocation. Dependency traversal retains
metadata rather than one payload per recursion level; the actual base, delta
and result each have the per-object bound, plus codec/allocator overhead.
Inflated packed entries spill into held private scratch, and a full entry is
reused rather than copied into a second decoded file. All compressed writes
count toward the output budget while writing, including headers and trailers.

The accepted format is SHA1 loose objects or PACK v2 with an accompanying IDX
v2; both indexed REF and OFS deltas are supported. Pack checksums, index
checksums, entry CRCs and reconstructed object IDs are verified. Missing/thin
bases refuse. Optional reverse-index, bitmap, keep and cruft timestamp sidecars
and the multi-pack index are not used or copied. Each pack still needs its own
verified IDX v2. A promisor source refuses because the capture may be incomplete.

Index v2/v3 regular/executable files are supported. Unmerged, intent-to-add,
sparse, split and v4 indexes refuse. SHA256, linked worktrees, alternates,
grafts/replacement refs, config includes, filters, attributes transformations,
submodules, symlinks and unsupported line-ending transforms refuse. Standard
repository `.gitignore` and `.git/info/exclude` rules are evaluated without
global config, matching the existing hardened Git command's private HOME and
hidden global configuration. Backslash-escaped, double-star, negated bracket
and POSIX character-class syntax explicitly refuse. Non-ASCII ignore patterns
and untracked Git paths also refuse because the pinned matcher uses runes
where Git wildmatch uses bytes. Tracked Unicode paths bypass ignore selection
and remain supported. The admitted ASCII literal/basic-glob/positive-range
subset uses ASCII case folding and is compared with native Git in fixtures;
there is no fallback to a broader or incomplete matcher.

Original reachable commits and trees retain their exact encoded bytes and
object IDs. The configured depth creates real shallow boundaries; the engine
does not flatten existing history. The baseline is a separate synthetic commit
parented by the original HEAD. History traversal reuses identical subtrees only
at identical path prefixes, keeping path-dependent withholding intact. Its
count and path-byte bounds apply to distinct tree/prefix visits, rather than a
fresh flattened copy of every commit. Head and baseline flattening remain bounded.
Shared `selectFilesFrom`/`detectSecretsFrom`
decisions apply to the captured working files. A held tracked path retains
skip-worktree semantics. Captured candidate read/stat errors refuse the whole
selection, preserving the I/O cause before any selected file is emitted.
Historical secret-named/held blobs are excluded from
the guest promisor pack; public duplicate content needed at HEAD or baseline
remains. The full object store stays outside the guest tree in `.dc-objects`.
Only sanitized remote URLs and matching branch tracking are copied into fresh
config. Each remote receives the fixed heads-to-remote-tracking fetch refspec
used by the existing staging path; source fetch destinations are discarded.
Source hooks and executable config are omitted.

## Focused native validation

Run sequentially on a native Windows host; fixture Git is required to create
and independently read the fixed synthetic compatibility repositories. It is
not called by the engine, which is also exercised with `PATH` empty.

```powershell
go test -race '-ldflags=-w -s' -p 1 ./internal/openshell/workspace -run '^Test(HostStageWindows|CapturedSHA1)' -count=1 -timeout=4m
go vet -p 1 ./internal/openshell/workspace
```

The two-commit fixture requires a real native Git pack containing deltas,
verifies unchanged commit bytes, baseline parentage, configured shallow depth,
tracked/untracked/nested ignores, history withholding and public duplicate
blobs. Other cases attack compressed/header expansion, index fanout allocation,
delta depth/cycles/cache depth, entry CRC/OID mismatch, thin bases, output
overflow, Windows metadata/casing, unsupported formats and matching work.

The private preparation fixtures also verify original source identity/unmask,
held-identity ancestry overlap in both directions, operator fallback/local
config precedence and refusal, raw plain CRLF bytes, DACL/reparse/hardlink/stream
boundaries, owner-lock custody and identity-bound cleanup. The guest Git oracle
runs only fixed commands under a bounded non-breakaway Job with bounded output
and `--no-lazy-fetch`/`GIT_NO_LAZY_FETCH=1`; missing objects cannot start a
promisor fetch. It reads public HEAD and baseline blobs from an independent copy
of the guest repo, with no sibling host `.dc-objects`, capture, scratch or
object alternates, and requires withheld object reads by path and OID to fail.
The engine runs with `PATH` empty for that fixture. A separate compatibility
read uses a held-identity-checked DOS spelling because Git for Windows may
normalize a volume-GUID cwd; that spelling is test-only and does not grant
production path authority.
