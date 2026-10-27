# External requirements, sandboxes, local models and scanners

Open this when: your change adds or depends on something outside the Python wheel and Go binaries (Docker, a VM or microVM, KVM, a GPU, a local model server, a node or python extra, a system package, an OS version, network egress), or you touch OpenShell, sandboxes, judges or scanners.

Heavy requirements stay optional, off by default and never installed silently. Sandboxes are off until `openshell.enabled` is set by `defenseclaw sandbox setup`.

## Requirements: disclosure

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| A new external requirement is optional and off by default. It becomes essential only if the core guardrail path cannot run without it. | A hard dependency breaks per-user installs that never asked for the feature. | diff `pyproject.toml`, packaging and install scripts; confirm a switch gates it and a host without it passes `defenseclaw doctor` | `pyproject.toml`, `cli/defenseclaw/commands/cmd_doctor.py` (`@sym:_check_sandbox`) |
| Never install or download a requirement silently. Show a plan, ask or require an explicit flag, pin the artifact by tag and sha256, refuse on mismatch. Doctor prints fixes and never runs them. | Silent installs are a supply-chain and consent problem. | `go test ./internal/openshell -run 'Installer\|Digest'` | `internal/openshell/version.go` (`@sym:InstallerURL`, `@sym:InstallerSHA256`), `internal/openshell/install.go` (`@sym:ErrDigestMismatch`) |
| Every requirement has a detection check with a stable check ID ending in pass, warn, fail or skip, never a traceback. The detail names what is missing; the fix is a copy-paste command with sudo marked. | Operators act on the row. | `defenseclaw doctor --json` on a host without the requirement shows `check_id`, `reason_code`, remediation | `internal/openshell/doctor.go` (`@sym:Check`, `@sym:Fix`), `cli/defenseclaw/commands/cmd_doctor.py` (`@sym:_emit`) |
| Document it in `docs-site` as a "You need / Details" table: version floors, disk and RAM, account rights, first-start caveats, network endpoints. Update `docs-site/content/docs/get-started/install.mdx` when a source build needs it, and `docs-site/content/docs/enterprise/sandboxes.mdx` when managed hosts need it. | The tables are the operator's pre-flight list. | grep docs-site for the new binary or package name | `docs-site/content/docs/sandboxes/linux.mdx`, `docs-site/content/docs/sandboxes/macos.mdx`, `docs-site/content/docs/get-started/install.mdx` |
| Test the missing case: binary, daemon, KVM, kernel feature or key absent. Assert severity, reason code and fix text. Use monkeypatch seams (`host_os`, `resolve_gateway_binary`). | A happy-path-only test hides the failure operators hit. | `pytest cli/tests/test_cmd_doctor_sandbox.py`; `go test ./internal/openshell/...` | `cli/tests/test_cmd_doctor_sandbox.py`, `internal/openshell/doctor_test.go` |
| On managed hosts, check and report; never install. Publish the result as a root-owned record the unprivileged gateway reads, and refuse the dependent feature with a stable code and a fix line. | A user-writable record would let an account mark a host ready. | `go test ./internal/openshell -run Prerequisites` | `internal/openshell/prerequisites.go` (`@sym:ReadPrerequisites`), `docs-site/content/docs/enterprise/sandboxes.mdx` |
| The platform is a requirement. Refuse unsupported platforms by name even when config says enabled. | A config copied from Linux to Windows must not read as active. | `pytest cli/tests/test_cmd_doctor_sandbox.py` | `internal/openshell/driver_select.go`, `internal/openshell/probe_windows.go` |
| Bump a pinned artifact (installer version, sha256, base image digest, scanner wheels) as one change: version, URL and digest together, with tests. | A partial bump makes setup refuse its own installer. | `go test ./internal/openshell -run Version`; `uv lock --check` | `internal/openshell/version.go`, `pyproject.toml`, `uv.lock` |
| Pick severity by who is hurt: fail only when an enabled feature cannot work; warn when degraded or slow; skip when off or not applicable. | Wrong severity blocks healthy hosts or hides broken ones. | read new check against `_check_scanners` | `cli/defenseclaw/commands/cmd_doctor.py` |
| Keep numeric floors in code constants and mirror them in docs. | Drift gives operators contradictory instructions. | grep docs for the numbers in `doctor.go` and `version.go` | `internal/openshell/doctor.go`, `internal/openshell/version.go` |
| Pin documentation claims about requirements and limits with a static docs test. | Unpinned docs can prescribe flags that do not exist. | `pytest cli/tests/test_docs_managed_sandbox_claims.py` | `cli/tests/test_docs_managed_sandbox_claims.py` |
| Keep Python extras and heavy transitive dependencies opt-in and named. A new base dependency needs a justification and the CVE-floor comment style used in the file. | Base dependencies bloat every install. | `git diff pyproject.toml` | `pyproject.toml` (`vertex` extra) |
| Go, Node, npm, uv, make and Docker belong to source-build or optional-bundle prerequisites only. Fail fast naming the tool and a download link. | Release installs must not need a toolchain. | run the make target without the tool | `Makefile` (`plugin`, `_source-install-preflight`), `scripts/source-install-preflight.sh` |
| Surface the requirement in `defenseclaw status` and the TUI when operators act on it, not only in doctor. | Operators look at status first. | compare `defenseclaw sandbox doctor --json` with the Sandbox section of `defenseclaw doctor` | `internal/openshell/sandboxcli/doctor.go`, `cli/defenseclaw/tui/panels/setup.py` |
| Uninstall and upgrade tolerate a missing optional dependency: offer a skip flag, say what is left behind, never fail the whole operation. | Operators get stuck if Docker is already gone. | `pytest cli/tests/test_cmd_uninstall_sandbox.py` | `cli/defenseclaw/commands/cmd_uninstall.py` |

## Requirements: sandboxes

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Driver choice (`docker`, `vm`, `auto`, fallback) is an explicit setting. When the required backend cannot run, refuse with a typed `DriverUnavailableError`; never fall back silently. macOS has no Docker fallback. | A silent downgrade weakens isolation an administrator required. | `go test ./internal/openshell -run SelectDriver` | `internal/openshell/driver_select.go` |
| Keep the Python `defenseclaw sandbox` surface in lockstep with the Go command tree. Update the golden, the TUI panel and the reference docs together. | The two CLIs drift otherwise. | `go test ./internal/cli ./internal/openshell/sandboxcli`; `pytest cli/tests/test_cmd_sandbox.py` | `internal/cli/testdata/sandbox_commands.json`, `cli/defenseclaw/commands/cmd_sandbox.py`, `docs-site/content/docs/reference/sandbox-cli.mdx` |
| Recognise an OpenShell installed outside the supported route and say DefenseClaw cannot manage its gateway; do not edit it. | A service the user owns must not be restarted or rewritten. | `go test ./internal/openshell -run DoctorOnReleaseBinaries` | `internal/openshell/doctor.go` (`@sym:OpenShellOutsideFormula`, `@sym:OpenShellOutsideUnit`) |
| Probes read world-readable information only. Mark a fix that restarts the gateway (it stops running sandboxes). | Probes must not touch other users' state. | review the probe | `internal/openshell/doctor.go` (`Fix.RestartsGateway`), `cli/defenseclaw/commands/cmd_doctor.py` (`@sym:_check_kernel_sensor`) |

## Requirements: judges, local models, scanners

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Scanners are pinned wheels resolved from the managed environment first, then PATH. Doctor probes the launcher with a bounded `--version`; the missing case fails with a repair hint. Do not ask users to install scanners separately. | PATH must not shadow the managed scanner; a stale launcher on PATH can run a different scanner version. | `pytest cli/tests/test_cmd_doctor.py -k scanner` | `cli/defenseclaw/scanner_binary.py`, `cli/defenseclaw/commands/cmd_doctor.py` |
| The LLM judge is recommended but never a hard dependency. Accept local OpenAI-compatible servers (vLLM, Ollama, LM Studio) without a key, route through the shared `llm:` block, and make doctor probe key plausibility and reachability with a distinct skip when the judge is off. | Judge-less hosts must stay healthy; a silent judge outage must show up. | run doctor with the judge off, a bad key and an unreachable local server | `cli/defenseclaw/config.py` (`@sym:_LOCAL_LLM_PROVIDERS`), `cli/defenseclaw/commands/cmd_doctor.py` (`@sym:_check_llm_reachable`) |
| Surface local-model serving requirements as an actionable hint in settings, not only docs. | A server with padded JSON breaks many judge answers. | grep usages of the hint | `cli/defenseclaw/scanner/settings.py` (`@sym:VLLM_SERVE_HINT`) |
| Optional third-party services get their own doctor row: skip when off, warn when enabled with a missing key (naming the variable and the `defenseclaw keys set` fix), fail only on a rejected credential, warn when the network is unreachable. | Offline hosts stay green. | read the new check against `_check_virustotal` | `cli/defenseclaw/commands/cmd_doctor.py` |

## Worked template: disclosing a new requirement

Example: a new optional feature needs a local container runtime.

1. Config: add `feature.enabled` default false (see `reference/config.md`). Nothing starts when false.
2. Detect: add a check with ID `feature-runtime` returning skip when disabled, fail when enabled and absent, warn when older than the floor. Put the floor in a Go or Python constant.
3. Fix text: `Fix{Summary, Command, Sudo}` with the exact install command. Doctor does not run it.
4. Setup: if setup can install it, show a plan, ask, pin by version and sha256, refuse on mismatch.
5. Managed: record the check in a root-owned file; refuse with a stable code and a fix line; never install.
6. Docs page table:

| You need | Tier | Details |
|---|---|---|
| Container runtime | Optional | Version floor, who may run it, disk needed, first-start notes |
| OS and CPU | Required | Supported releases; unsupported ones are refused by name |
| Network | Optional | Hosts contacted at install and run time |

7. Test the missing case: runtime absent, too old, daemon stopped, feature disabled, unsupported OS. Assert severity, `reason_code` and fix text.
8. Pin the doc numbers with a static docs test. Add the code to the error table in the enterprise docs.

## Where it lives

`internal/openshell/` (doctor, driver_select, prerequisites, version, install, sandboxcli), `cli/defenseclaw/commands/cmd_doctor.py`, `cmd_sandbox.py`, `cli/defenseclaw/scanner/`, `docs/SANDBOX.md` (contributor notes only), `docs-site/content/docs/reference/sandbox-cli.mdx`, `docs-site/content/docs/sandboxes/`.

## How to verify

`go test ./internal/openshell/...`, `pytest cli/tests/test_cmd_doctor_sandbox.py cli/tests/test_docs_managed_sandbox_claims.py`, then `defenseclaw doctor` on a host that has the requirement and one that does not.

## Common mistakes

- Docs naming flags or bypass switches that do not exist, or describing a bypass as unconditional.
- Reading `openshell.enabled` and ignoring the platform.
- Adding a Docker fallback on macOS.
- Counting the first scanner start against a short probe timeout; first start can be slow.
- Changing a pinned digest without the version and URL.
- Updating `docs/SANDBOX.md` and leaving the published page stale; the code and the published page win.
