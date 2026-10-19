<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reviewed246 outside-PSEC environment control

This contributor-only Windows control starts the **same fixed std boundary
child** from build `246210c3b484ea1de0785756dd4410beda25adfb`, outside PSEC,
with the same eight explicit system/private environment entries and fixture
shape. It changes no SDK policy, provider activation, environment assertion,
existing host ACL, device map, firewall or privilege. No default invocation executes.

The control admits only the independently verified receipt SHA256
`b257b27b49f1cf7ee4fa510e17e198760f77a31a409d9188d8458f054a720612`, exact
build run `39129614000`, artifact `12137991365`, reviewed archive/provenance,
all three images and the packaged boundary source. Their files and ancestors
remain pinned against writes/replacement through owned child termination.
The source SHA256 is
`3809389bab54663d6c1d1975602af80b03571239bad2a425523153c8e5dd375d`; its
exact packaged bytes have Git blob identity
`fa175b755c79189e5edb2ce1fe71e9cf6fd3f684` at that build commit. The earlier
independent artifact/source review is authority for the receipt; this helper
does not download artifacts, install runtimes or invoke Git.

The existing evidence parent must already be private. Only one new
`environment-control-*` directory and its fixed
`dc-axis-windows-psec-environment-control` fixture are created. All contents
are public synthetic bytes. System/private paths use canonical verbatim local
disk spelling; the child's existing comparison still accepts only its exact
optional verbatim prefix difference. The child receives exactly `SYSTEMROOT`,
`WINDIR`, `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, and `TMP`.
No PATH, credentials or caller environment is forwarded.

The sole literal child vector is `--fixed-child boundary 1 1 1 1`. The four
nonzero placeholder ports are only parsed. No endpoints are started. Expected
source progression is six exact environment comparisons, absent credentials
and parent-only marker, two permitted synthetic writes, then successful read
of the uncontained `outside.txt`. That read must produce exit **1** with
`outside read was not denied`, before the negative write, read-only actions or
socket operations. The helper requires the exact late-failure transcript,
both positive write contents and unchanged outside/read-only/seal bytes.
Environment assertion success is inferred from this pinned source order; the
child does not emit six independent success markers.

`processutil.RunTree` assigns the suspended child to a non-breakaway,
kill-on-close owned Job before resume. A 30-second context bounds the workload,
with the existing bounded Job/pipe teardown allowance. Each stream retains at
most 64 KiB while draining excess; overflow/deadline/reader/Job errors fail.
Only an exact `*exec.ExitError` with exit1 qualifies: a joined cleanup error
containing exit1 cannot pass. The helper makes no independently sampled
Job-empty claim. It retains the fresh fixture and a private result JSON on
both success and failure; no old fixture is deleted or retried. The outer
reviewed invocation must retain the wrapper image/process, bound its deadline
and streams, and check its exit/result along with the persisted report.

Inert checks create synthetic files/receipts only, without child, PSEC, map or
socket execution:

```powershell
go test -race '-ldflags=-w -s' -p 1 ./test/e2e/axis/windows/environment-control -count=1 -timeout=1m
go vet -p 1 ./test/e2e/axis/windows/environment-control
```

After independent source review and separate authorization for one fresh,
non-elevated native run,
build the reviewed source into a new private evidence directory and record Go
version, build metadata, source/binary hashes and bounded raw output. The only
live shape is:

```powershell
<reviewed-control.exe> --run-fixed --receipt <exact-reviewed246-ROOT-REVIEW.json> --evidence <fresh-private-parent>/environment-control-01
```

One fresh control passed on the native Windows host using this exact source,
Go 1.26.5 and wrapper SHA256
`fd5132faff988a3a7ac7f96ff4bc878e15528c9993e30ea94754692d81b9c349`.
The wrapper exited zero in 0.156 seconds; bounded stdout matched the persisted
result, all six environment assertions passed by the reviewed child source
order, both private permitted writes appeared and original sentinels remained
unchanged. It stopped at the expected outside-read failure before negative
writes or sockets. Evidence SHA256 is
`e075cb59147d03e72695946c2a97a0148a79c4b314a6ed943d7091ab33317fbd`.
The first attempt refused its evidence parent's DACL before fixture or child
creation; the passing attempt used a fresh atomically private parent and
retained its fixture. See `../mxc-v1/manual-results.md` for the paired PSEC
failure. This isolates an environment-construction comparison; it does not
qualify PSEC, filesystem/network containment, child lifetime, Claude or production.
