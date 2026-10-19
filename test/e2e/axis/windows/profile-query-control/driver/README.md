<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed read-only query supervisor

This supervisor has one retained fixed query attempt, described in the
[control results](../manual-results.md). It accepts only `--run-fixed` and the
fixed sibling `profile-query-control.exe` with source-pinned SHA256
`0e5123f5f20d992b36f07ce8a6670675996e1d333e37bf07ea5668e9cae8d24e`,
2158592 bytes. That helper was compiled without execution from the separately
reviewed four-file control source using Go 1.26.5, CGO=0, trimpath/buildvcs=false.
Its build/source receipt is retained in the fresh protected
`environment-control-private-02/profile-query-control-01` fixture. No target,
hash, argument, SID or environment option is accepted from a caller.

The supervisor retains list-access non-reparse ancestors and the read-only,
single-link helper image; creates only new owned synthetic directories; then
uses existing `processutil.CommandContext` and `RunTree` with a five-second
context, exact eight-value private environment, workspace cwd and fixed query
selector. Existing RunTree assigns its kill-on-close Job before resuming the
child. Managed breakaway, alternate launchers and process-name/PID kills are
not used. Any RunTree/cleanup error fails, even if child JSON claims completion.
Output is drained into separate bounded 8 KiB captures. Pins close before the
final JSON is emitted; pin-close failures cannot leave `passed=true`.

No `job_empty`, complete descendant enumeration or full-tree qualification is
claimed. This is one trusted read-only helper with no child-launch API. The
outer reviewed owner must retain the exact supervisor image/process handle and
bound the whole invocation, including pre-launch filesystem/hash operations,
with a separate deadline. Query refusal, unknown state, output overflow or
cleanup errors remain failed observations. Fixtures and output are retained;
the supervisor deletes nothing and repairs no existing ACL.

Source and actual helper/supervisor image hashes, exact fresh fixture/cwd/env
and the bounded outer invocation require root/independent review before ONE
query. Build/test commands below execute synthetic tests only:

```powershell
go test -race -p 1 '-ldflags=-w -s' -count=1 main_windows.go main_windows_test.go
go vet main_windows.go main_windows_test.go
go build -o <same-new-protected-fixture>/profile-query-supervisor.exe main_windows.go
```
