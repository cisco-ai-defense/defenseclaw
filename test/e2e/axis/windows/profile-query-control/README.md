<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed read-only native profile-query control

This contributor diagnostic has one retained query02 refusal, described in
[manual results](manual-results.md). It neither changes the failed Case10 result
nor authorizes another boundary attempt. Its only
selector is `--query-fixed`; default/unknown invocations refuse before queries.
It accepts no SID, path, executable, command or policy arguments.

A separately reviewed driver must prepare a fresh protected
`environment-control-private-02/profile-query-control-<fresh>` fixture containing
the exact helper image, `workspace`, `home/AppData/{Roaming,Local}` and `tmp`.
It runs with cwd `workspace` and exactly the same eight explicitly constructed
SYSTEMROOT/WINDIR/HOME/USERPROFILE/APPDATA/LOCALAPPDATA/TEMP/TMP values as the
fixed parent shape. The helper validates those values against its own fixed
fixture/image location. It makes no direct filesystem write calls and imports no host HOME/PATH,
credentials or token environment overrides.

After requiring an absent impersonating thread token on one locked OS thread,
it queries only SHGetKnownFolderPath(LocalAppData,
DONT_VERIFY|NO_PACKAGE_REDIRECTION) and GetAppContainerFolderPath for the fixed
public synthetic package SID `S-1-15-2-1-2-3-4-5-6-7`. It frees both native outputs
with CoTaskMemFree even on API failure. A missing profile/API, malformed result
or unknown token state records refusal and stops. It never creates/registers a
profile, changes a registry/ACL/device mapping, grants a capability, impersonates
a token or launches a process. No alternate SID or retry exists.

Outputs contain only HRESULTs, explicit unknown/refusal stages and fixed boolean
path classes: exact/ASCII-fold prefix comparisons against the protected private
base and caller known-folder base, optional verbatim prefixes and the bounded
Packages/profile/AC tail shape. Raw native paths, profile components, handles,
SIDs from tokens and environment contents are never printed. These classes are
observations; they supply no filesystem grant or accepted child expectation.
The false creation/write-call flags describe the helper's explicit API surface,
not an instrumented audit of all operating-system internal side effects.

This fixed unregistered SID may be refused. Even a successful query is outside
PSEC and does not bind the failed child's SID or explain its precise runtime
environment. The Rust supervisor imports DLLs before replacing its outer eight
environment values with inner fixture values; this separate lazily loaded Go
control does not establish equivalent startup/cache timing. No mapper should
accept an additional path class merely because this control reports it.

Build/test the explicit source files on native Windows with Go 1.26.5:

```powershell
go test -race -p 1 '-ldflags=-w -s' -count=1 main_windows.go classify_windows.go classify_windows_test.go
go vet main_windows.go classify_windows.go classify_windows_test.go
go build -o <new-protected-fixture>/profile-query-control.exe main_windows.go classify_windows.go
```

These tests exercise synthetic classification only; they call no native profile
query. Source/image hashes, the fresh fixture/environment and one bounded
held-image/owned-process invocation require separate root/independent review.
The outer owner must bound the whole synchronous query and retain its receipt
on refusal; no native invocation is authorized by these build instructions.

Primary API contracts:
[SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath),
[KNOWN_FOLDER_FLAG](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ne-shlobj_core-known_folder_flag),
[GetAppContainerFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath).
