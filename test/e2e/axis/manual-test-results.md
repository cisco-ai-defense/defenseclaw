# AXIS manual feasibility results

Qualification is incomplete. These results do not enable AXIS in DefenseClaw
or certify `defenseclaw sandbox run claude` with AXIS.

## Host and artifact identity

Recorded 2026-10-18 on Windows 11 Enterprise, build 26200.9457, x86-64.
Native Windows and Windows-hosted Linux are separate test routes.

Later [native Windows AXIS/MXC results](windows/manual-results.md) record actual
ProcessContainer headless launches without WSL, including fixed filesystem,
private-state, loopback receiver, exit-code and timeout observations. The Linux
and initial CLI results below remain historical evidence and do not substitute
for native Windows qualification. Customer AXIS support is still unavailable.

The isolated `DefenseClawAXISTest` WSL2 distribution used Ubuntu 24.04 and
kernel `6.18.40.1-microsoft-standard-WSL2`. The probe account is unprivileged;
Windows drive automount and Windows process interoperability are disabled in
this distribution. The Landlock version syscall returned ABI **7**.

The Ubuntu rootfs was verified against Canonical's
[published checksum](https://cloud-images.ubuntu.com/wsl/releases/noble/current/SHA256SUMS):
`2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934`.
No existing WSL distribution, host ACL, or host security setting was changed.

The first live probes used the unmodified AXIS source at
[`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c`](https://github.com/ROCm/axis/tree/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c),
built by the scoped
[contributor workflow run](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39102704837)
from DefenseClaw commit `9513714d5725190d078385e615700ce8439d9f0e`.
The upstream lockfile was unchanged and the compiler was Rust 1.95.0.

| Artifact | SHA256 |
| --- | --- |
| Downloaded source-build archive | `3e53c27e4811fde149589f90d3d99fbf40f3dd09cc0175f44c8c0c70bf6dd35a` |
| `axis` executable | `fcd8216d3c18eef4d697b817d95f92ea25fae6a71118924819262405330ffe8c` |
| Upstream `Cargo.lock` | `788c5b5ea12b19176969d495f53d2c97a8e056d035832ec529ffc042fd97f3b2` |

Before installation into the disposable distribution, the archive checksum,
source/workflow identity, archive paths and every binary's manifest digest
were checked. Files were installed root-owned without setuid bits or file
capabilities. No daemon or privileged network helper was started.

The direct Rust API probe was built and executed separately from
[run 39103325033](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39103325033),
using DefenseClaw commit `d099e791ad697bf2546943dd856c76548d3bcc7a` and
the same unmodified upstream source and lockfile. Its example overlay is
contributor code, not an upstream runtime change.

| Direct probe artifact | SHA256 |
| --- | --- |
| Archive | `828a92f39f5c3b9be880073d41b97b96c5e8d4790d9d059a71c61cf0529e2722` |
| Example source overlay | `45e47f1370c2297bff650653fb06c095ba66391bddb439b78ecf17f6f0640e7c` |
| `defenseclaw-axis-offline-probe` | `2d6a93413bd8c7ed24dfdc0b38ad201f4015b513f8a22d38d76b762f1e267d86` |

The overlay digest was compared with the committed source, and every packaged
binary digest was checked before installation and execution.

The final native Windows CLI checks used DefenseClaw source commit
`6348d3594b3cb5a930dd6c1245ab0be28fcffd69`, compiled with debug symbols omitted
(`go build -ldflags='-w -s'`). The executable SHA256 was
`2c2ca05c2d66953b7bb41ae9137f39f1ddb1a9fc4fd11043c844c5d4ee5b7f27`.

## Observations

| Case | Observed result | Meaning |
| --- | --- | --- |
| Native Windows `defenseclaw sandbox run claude` | Exit **3** with the existing platform refusal | The current product command does not run a Windows sandbox. |
| Native Windows `config-v8 validate`, active AXIS | Exit **1**, path `$.sandbox.runtime`, explicit unavailable reason | Fail-closed activation with an actionable diagnostic; input bytes unchanged. |
| Native Windows validator, stored AXIS choice with master off | Exit **0**, `valid: true` | Inactive configuration can be stored; this starts no runtime. Input bytes unchanged. |
| Native Windows validator, conflicting explicit `yolo` policy | Exit **1**, path `$.sandbox.yolo`, explicit conflict reason | Conflicting authority is rejected; input bytes unchanged. |
| Native Windows offline Go probe tests | Race tests passed | Harness validation only; AXIS was not executed on Windows. |
| Linux Go probe unit tests at `9513714d` executed inside WSL2 | All six top-level tests passed, including real supervisor exit and timeout | Linux helper execution, without AXIS. |
| Pinned CLI version | `axis 0.3.5`, entrypoint hash verified | Source identity comes from the build manifest, not this version string. |
| Explicit MXC, strict filesystem, block networking | Both tagged lifecycle/timeout acceptance tests **failed**, exit **1** before payload | MXC feasibility remains failed. |
| Manual MXC diagnostics using the same strict filesystem policy | Refused `/lib` resolving to `/usr/lib` because the distinct mount alias cannot be represented | This was the first observed refusal; the later host-root substrate restriction was not reached. |
| Explicit `axis_native`, strict filesystem, block networking | Private HOME/CWD and allowed writes verified; outside-canary read and write returned **EACCES**; IPv4/IPv6 TCP/UDP socket creation returned **EPERM**; child exit **23** preserved | Passed these fixed benign offline boundary cases. No DNS, connect, or outbound packet was attempted. |
| Direct Rust API runner, explicitly native with the same strict controls | Exit **0** after all ten fixed checks: private HOME/CWD, outside read/write denial, read-only write denial, four socket denials, exit 23, configured timeout, tracked direct child stopped, repeated destroy, and owned temporary-file cleanup | Passed this reproducible offline runner on this WSL2 host. No CLI missing-socket workaround was used. |
| Native provider in a real Linux controlling PTY | Payload printed `isatty=True foreground=False`; input was sent but no acknowledgement arrived; AXIS killed the child at its four-second timeout | **Failed** interactive keyboard input. A terminal descriptor alone does not qualify interactive use. |
| CLI status for that timed-out PTY workload | Exit **0** | A zero CLI exit is insufficient evidence; payload acknowledgement and lifecycle state must also be checked. |
| Post-probe process/listener inspection | No AXIS workload, AXIS daemon, or AXIS listener remained; only WSL infrastructure and the inspection command were present | An observation after these runs, not general process-tree custody proof. |

The manual policies explicitly selected one provider per experiment. Neither
experiment changed provider or weakened filesystem compatibility after failure.
Each received newly created private HOME, workspace, temporary/cache directories
and an environment constructed from a fixed allowlist. No real Claude account,
provider key, OAuth token or developer project was exposed to the payloads.

## Reproduction inputs

The tagged Go acceptance target was cross-compiled on Windows, transferred
through standard input into the isolated distribution, and executed as its
unprivileged account:

```sh
./axis-live.test -test.run='^TestLiveAXISOffline' -test.v -test.count=1 \
  -test.timeout=90s \
  -axis-path /opt/<reviewed-source-build>/bin/axis \
  -axis-sha256 fcd8216d3c18eef4d697b817d95f92ea25fae6a71118924819262405330ffe8c
```

It returned **1**. Do not turn this failure into a successful skip.

The separate native experiment used the same fixed policy shape as
`probeSession.policyYAML`, with `runtime.provider: axis_native` selected
explicitly. A fixed Python payload wrote only in its private workspace/HOME,
checked the synthetic outside canary with both read and write operations,
called `socket()` for AF_INET/AF_INET6 and SOCK_STREAM/SOCK_DGRAM without
connecting, printed a completion marker, and exited 23. The host verified the
outside canary was unchanged and removed only the temporary root it created.

The interactive experiment used Python's `pty.fork()` to give AXIS a controlling
terminal, set its initial geometry to 100 columns by 30 rows, and ran a fixed
payload that printed `isatty()` and foreground-group equality before reading
one line. The host sent `manual-input` after the readiness marker. The payload
never printed its input acknowledgement; the four-second AXIS policy timeout
ended the run. This does not verify resize or signal forwarding.

The committed direct Rust API runner was executed as the unprivileged account:

```sh
timeout --signal=TERM --kill-after=2 30s \
  /opt/<reviewed-source-build>/bin/defenseclaw-axis-offline-probe
```

It returned **0** with the fixed JSON check list, Landlock ABI 7, and
`claude_or_production_certification: false`. See the
[runner source](runner/main.rs) for the exact payload and assertions.

After testing, both verified contributor bundles were archived together and
their eleven binary digests checked again. That archive's SHA256 is
`d46903473ec5d9943de4da6b0c3bf2527b791a5d019da7e65ddfa7f5a101c34d`.
The disposable WSL distribution was then unregistered to recover disk space
for native validation. The archive contains contributor artifacts and
provenance only; no HOME or credentials. Transcripts were retained separately.
No test runtime is left installed as a customer option.

## Unqualified gates

Real Claude, interactive/headless model requests, hook allow/block enforcement,
API-key/OAuth credential transport, HTTP streaming, proxy-only egress, resize,
foreground signals, parent death, descendant custody, cross-user ownership,
managed deployment, copied-workspace review/pull/undo, and production artifact
installation have not passed. The direct native runner's successful observation
of its tracked child does not establish complete descendant custody or
production lifecycle safety.

Native Windows interactive AXIS remains unsupported by the pinned source.
The Windows-hosted WSL2 experiment does not change that claim. The
[integration plan](../../../docs/design/axis-sandbox-integration-plan.md)
retains its acceptance gates.
