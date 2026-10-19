<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Windows contributor probes

These explicit, offline probes qualify fixed AXIS/MXC behaviors in a private
task directory. They do not install a customer runtime or activate AXIS in
DefenseClaw. They use native Windows ProcessContainer and require no WSL.
Actual results and precise limits are in [manual-results.md](manual-results.md).

Use a source-built contributor artifact from the pinned workflow. Never swap
its paired MXC executor for another release. `verify_artifact.py` validates
archive paths, the complete checksum inventory, source/patch metadata and
binary hashes before extraction is accepted. It fetches only the two pinned
public MXC metadata files for comparison. Download and compare the GitHub outer
artifact digest separately as well.

```powershell
python test/e2e/axis/windows/verify_artifact.py `
  --artifact-dir <download-directory> --output-dir <fresh-extraction-directory> `
  --axis-source <clean-fb5fd5f-checkout> --workflow-commit <build-workflow-commit> `
  > <task-directory>/verification.json
```

Stop if verification fails. Build the fixed probe explicitly; these Go files
are excluded from ordinary package builds and tests:

```powershell
go build -trimpath -ldflags='-s -w' -o <task-directory>/fixed-probe.exe test/e2e/axis/windows/probe_windows.go
python test/e2e/axis/windows/run_headless.py `
  --verification <task-directory>/verification.json --probe <task-directory>/fixed-probe.exe `
  --case-root <fresh-private-case-directory> --mode boundary
```

Repeat with fresh case roots and `--mode exit23` and `--mode timeout`.
The scripts retain exact policies, commands, bounded output and hashes. Each
process receives a constructed private environment. The only credential-like
value is a synthetic canary. TCP/UDP listeners are private loopback canaries
with positive host controls; no Internet or DNS probe runs. Exit zero is
accepted only when the fixed case's explicit observations pass. Inspect owned
processes after every case; a reaped leader alone does not prove tree cleanup.

The inherited-console build is a distinct experiment. Require the explicit
variant and compare the retained overlay with the reviewed local patch:

```powershell
python test/e2e/axis/windows/verify_artifact.py `
  --variant inherited-console --reviewed-overlay test/e2e/axis/windows/patches/axis-inherited-console.patch `
  --artifact-dir <overlay-download-directory> --output-dir <fresh-overlay-extraction-directory> `
  --axis-source <clean-fb5fd5f-checkout> --workflow-commit <overlay-workflow-commit> `
  > <task-directory>/inherited-console-verification.json
go build -trimpath -ldflags='-s -w' -o <task-directory>/console-harness.exe test/e2e/axis/windows/console_harness_windows.go
<task-directory>/console-harness.exe `
  -verification <task-directory>/inherited-console-verification.json `
  -probe <task-directory>/fixed-probe.exe -probe-sha256 <reviewed-fixed-probe-hash> `
  -case-root <fresh-private-terminal-case-directory>
```

The fixed harness creates an outer ConPTY, keeps `interactive_terminal=true`
inside AXIS, and checks console handles, keyboard acknowledgement, resize from
100×30 to 160×40, Ctrl-C acknowledgement, subsequent input and exit 7. It assigns
the suspended AXIS supervisor to a kill-on-close Job before resuming it, drains
bounded output on a separate goroutine, and signals only owned live handles on
failure. Recorded fixed relay results are in `manual-results.md`. It offers no arbitrary
workload-command flag and makes no completed descendant-cleanup claim.

The earlier inherited-console variant passes basic terminal input and resize
on the recorded host, but fails Ctrl-C continuity. A separate paired relay
variant must retain and verify both additional reviewed patches:

```powershell
python test/e2e/axis/windows/verify_artifact.py `
  --variant inherited-console-relay `
  --reviewed-overlay test/e2e/axis/windows/patches/axis-inherited-console.patch `
  --reviewed-axis-relay test/e2e/axis/windows/patches/axis-console-ctrl-c-relay.patch `
  --reviewed-mxc-relay test/e2e/axis/windows/patches/mxc-console-ctrl-c-relay.patch `
  --artifact-dir <relay-download-directory> --output-dir <fresh-relay-extraction-directory> `
  --axis-source <clean-fb5fd5f-checkout> --workflow-commit <relay-workflow-commit> `
  > <task-directory>/relay-verification.json
```

Run the same fixed console harness with that verification record. The explicit
`-mode outer-control` checks only the fixed benign host probe's ConPTY plumbing;
it is uncontained, clearly marked in its result, and never a runtime fallback.
`-mode terminal-basic` omits Ctrl-C for diagnosis. `-mode timeout` and
`-mode close-session` start only the probe's fixed, bounded descendant tree and
record supervisor termination. Inspect the known child PIDs and owned executable
paths separately before making a process-tree observation.

For abrupt parent death, use the fixed controller:

```powershell
python test/e2e/axis/windows/run_parent_death.py `
  --harness <task-directory>/console-harness.exe --verification <task-directory>/relay-verification.json `
  --probe <task-directory>/fixed-probe.exe --probe-sha256 <reviewed-fixed-probe-hash> `
  --case-root <fresh-private-parent-death-case-directory>
```

The controller requires the known AXIS, payload and leaf processes to be visible
in CIM before it kills its own tracked harness handle. It then checks for
remaining known or task-owned processes without signaling inferred child PIDs.
An inspection failure is a failed qualification. These process checks do not
prove cleanup of profile, policy or tracking resources; the pinned MXC cleanup
stub requires separate review and explicit task-owned cleanup.

After the fixed relay cases pass, `run_claude_version.py` accepts only the
reviewed SHA256 and Anthropic Authenticode signature of Claude 2.1.292. It
copies that binary into one private fixture and runs exactly `--version` with
blocked networking and a constructed private environment:

```powershell
python test/e2e/axis/windows/run_claude_version.py `
  --verification <task-directory>/relay-verification.json `
  --claude <canonical-signed-Claude-2.1.292.exe> --case-root <fresh-private-Claude-version-case>
```

This requires approximately 255 MB for its single retained binary fixture.
It supplies no credentials and makes no authentication or model request.

Do not supply real credentials or start Claude until hook relay, credential
confidentiality, network confinement and lifecycle gates pass review. Strict
AXIS proxy mode additionally needs an explicitly installed privileged WFP
broker; these scripts do not install or start it. Default unit-test success or
an SDK's advertised PTY surface does not qualify these live behaviors.
