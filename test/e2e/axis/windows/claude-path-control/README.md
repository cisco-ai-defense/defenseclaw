<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed native application-path control

One separately reviewed native run completed this contributor measurement. The
volume-GUID and GLOBALROOT application spellings failed at creation; the ordinary
DOS spelling ran the pinned Claude `--version` successfully. All three Jobs ended
empty. See the [actual results](../mxc-v1/manual-results.md#uncontained-application-path-control-dos-starts-the-fixed-image).
No customer provider, SDK, PSEC object, AXIS process, policy fallback or network
rule was used. The run was **uncontained** and establishes no agent or sandbox
qualification. Any new execution requires a separately reviewed concrete scope.

The only selector is `--run-fixed`. The executable's already protected private
directory must contain `claude-2.1.292-root-image-review.json` with the exact
source-pinned independent receipt digest. That receipt cannot select another
image: image SHA256, 254,858,400-byte size, version and reviewed signature facts
are fixed in source. The image is hashed while held without write/delete sharing,
then copied into a fresh private `claude-path-control-fixture/bin`. All image
ancestors are retained with list-directory access and without delete sharing;
the leaf remains read-only with no write/delete sharing. Directory metadata and
contents are not immutable. The fresh fixture is retained on success or failure.
Existing directories, failed fixtures, profiles and ACLs are never repaired or
deleted.

Three application strings are derived from this same held image: volume GUID,
`GLOBALROOT` plus native volume-device name, and ordinary DOS spelling. Every
spelling must open to the same full 128-bit file ID and volume before any process
creation. These are three fixed observations; success never chooses a fallback.
The literal command line always contains the same quoted verbatim-DOS argv0 and
quoted `--version`, matching the reviewed downstream Rust encoder. Cwd is the
same canonical verbatim-DOS private workspace. Exactly eight environment values
are supplied: native canonical verbatim-DOS SYSTEMROOT/WINDIR plus private HOME,
USERPROFILE, APPDATA, LOCALAPPDATA, TEMP and TMP. No host environment or PATH is
inherited. This records supplied values, not realized child environment.

Each raw `CreateProcessW` call uses the same flags as the downstream pipe control:
SUSPENDED, UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT and NO_WINDOW. One
HANDLE_LIST attribute carries three anonymous-pipe handles; stdin is already at
EOF. Pipe handle values necessarily differ between fresh cases, while their
shape is fixed. Other startup fields, desktop and security-attribute pointers
are zero/null. There is no SECURITY_ENVIRONMENT attribute, reference PSEC object
or SDK normalization. This is not byte equality with an earlier process or its
different private path values. The only within-run intended input change is
lpApplicationName; per-case handles and mutable command buffers are newly owned.

Successful creation stays suspended until its retained process handle is in a
kill-on-close, nonbreakaway Job and `QueryFullProcessImageName` on that **same
handle** has been opened and matched to the held image's full file ID. A refusal
cannot reach ResumeThread. No PID reopening or PID-based termination is used.
The exact held root and its Job are stopped/waited on all post-creation error
paths; Job active-process accounting must reach zero. Each child has a five-second
deadline. Output has a 64 KiB aggregate budget over both streams and all cases;
only byte counts/digests, numeric diagnostics and exact version-output equality
are reported. Raw path/environment/handle/file-ID values are not printed.
The same-thread NTSTATUS sample may be stale and cannot establish a cause.
Reader completion timeout closes the exact owned pipe and bounded-joins its
worker. The timeout remains a failure even if cancellation then joins; no later
case starts. A failed close/join is explicit and leaves the independent outer
Job responsible, rather than claiming complete custody.

The independent outer controller MUST pin the reviewed helper image and enforce
a **30-second wall-clock deadline over the complete helper**, with owned Job
custody and bounded capture. The internal 25-second admission budget does not
make regular-file/NTFS setup syscalls interruptible. Same-user concurrent object
namespace mutation is not qualified by this synthetic control. Parent mount
validation and held ancestry are checks, not a general namespace isolation claim.

Build-only and pure/inert filesystem checks (never invoke `--run-fixed` here):

```powershell
go test -race -p 1 '-ldflags=-w -s' ./test/e2e/axis/windows/claude-path-control -count=1 -timeout=60s
go vet -p 1 ./test/e2e/axis/windows/claude-path-control
```

The tests exercise selector/receipt refusal, exact literal/environment shape,
identity-before-resume ordering with callbacks, aggregate output bounds, and
real fresh synthetic directory rename/read-only file custody and blocked-pipe
close/join cancellation. They do not
exercise CreateProcess, Job assignment, process-image querying or Claude.

Primary API contracts:
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[QueryFullProcessImageNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew),
[GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew),
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The separately built `supervisor_windows.go` is excluded from the helper's
ordinary package build. Build it explicitly with `authority_windows.go` and
`native_windows.go`, excluding `main_windows.go`. It pins the independently
reviewed helper build from `17ebe67f`: SHA256
`a78aef62fd7f1b98293cf570a87e672fc3cb7b20d922748d7f34931b34adf823`,
2,830,848 bytes. There is no image/hash/argument override.

The supervisor uses a kill-on-close Job through the documented
[JOB_LIST creation attribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
It samples membership using the retained process handle and checks that
handle's image identity before resuming the retained primary thread. It never
enumerates or adopts PIDs. The helper has a 24-second run budget, reserving six
seconds for cleanup within the 30-second absolute admission/acceptance limit.
The root controller must also enforce a 30-second wall-clock cutoff for the
supervisor, since filesystem setup calls cannot be interrupted by a Go context.
The outer Job retains all helper descendants even if the supervisor is stopped.
Capture, cleanup, close or deadline errors prevent a completed observation.
`supervision_completed` means that the measurement helper exited successfully;
the root controller must inspect each of its three case outcomes separately.
Neither a completed measurement nor a passing version check qualifies a sandbox.
The one recorded run used helper source `17ebe67f` and supervisor source
`b00149e1`. Its retained result SHA256 is
`f38e14ee23f64a46d5e1a6950efac46b6311b0beea7479e8293cbb69881cce53`.
The outer observation reported Job-at-creation membership, image binding before
resume, empty Job/zero active processes, joined/closed readers and no deadline,
overflow or error. Successful version output was observed only for the DOS case;
realized Claude environment, authentication, hooks and model use were untested.
