# Hermes Agent native Windows research and acceptance matrix

Last verified: **2026-08-04**

DefenseClaw status: **preview / not certified**
Latest upstream version examined: **Hermes Agent v0.20.0, tag `v2026.8.3`,
released 2026-08-03**, commit
[`3c27eb6234bf91b8ceee9e9071591b31e9b148cb`](https://github.com/NousResearch/hermes-agent/commit/3c27eb6234bf91b8ceee9e9071591b31e9b148cb).

## Eligibility decision

Hermes is eligible for a DefenseClaw native-Windows **preview**. Upstream calls
Windows 10/11 x86_64 and aarch64 Tier 1, offers Hermes Desktop and
`install.ps1`, and documents direct Hermes CLI use from PowerShell. The
DefenseClaw integration does not install, find, configure, invoke, or depend on
WSL, Docker, a VM, Git Bash, MSYS, Cygwin, or another compatibility layer. It
registers one absolute `defenseclaw-hook.exe` command and Hermes starts that
argv with `subprocess.run(..., shell=False)`.

DefenseClaw reports a healthy installed Hermes v0.17.0 as
`detected-but-unsupported-version`. A requested action setup emits that exact
version plus the `hermes-hooks-v1 >=0.19.0` requirement, downgrades once to
observe, and saves without rerunning discovery or claiming the client is
absent. DefenseClaw does not wrap or repair the vendor launcher.

This decision does **not** make Hermes Bash-free. The official Windows guide
says Hermes's own terminal tool uses installer-managed PortableGit/Git Bash,
sets `HERMES_GIT_BASH_PATH`, and can discover other compatibility Bash
installations. That is an upstream Hermes implementation detail outside the
DefenseClaw hook path and must remain visible to operators. The dashboard
`/chat` terminal is unavailable natively because it requires a POSIX PTY.

## Official evidence

| Evidence | Exact official source | Recorded result |
| --- | --- | --- |
| Release | [Hermes Agent v0.20.0 / `v2026.8.3` release](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.3) | Published 2026-08-03. The source recheck confirms the identical reviewed 23-event shell-hook contract at the latest official release; it does not certify DefenseClaw packaging or client behavior. |
| Platform tier and install | [Platform support at `v2026.7.30`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/getting-started/platform-support.md) | Windows 10/11 x86_64 and aarch64 are Tier 1; Hermes Desktop and `install.ps1` are supported distribution methods. PyPI and Homebrew installs are unsupported. |
| Native installation | [Native Windows guide at `v2026.7.30`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/user-guide/windows-native.md) and [official `install.ps1`](https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.ps1) | Official PowerShell command is `iex (irm https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.ps1)`; Hermes Desktop is the GUI alternative. The upstream command tracks `main`, while the shell-hook contract recheck is pinned to release `v2026.8.3`. |
| Native layout and limits | [Native Windows guide at `v2026.7.30`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/user-guide/windows-native.md) | No administrator required; `%LOCALAPPDATA%\hermes`; `HERMES_HOME` override; CLI/TUI/gateway/MCP work natively; embedded dashboard terminal is unavailable; terminal tool uses Git Bash/PortableGit. |
| Config resolution | [`hermes_constants.py` at `v2026.7.30`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_constants.py) | Context override, then `HERMES_HOME`, then `%LOCALAPPDATA%\hermes` on Windows; the effective file is `<home>/config.yaml`. The hook guide sometimes calls the same logical file `cli-config.yaml`; source and the Windows layout resolve it as `config.yaml`. |
| Hook schema and responses | [Hook documentation at `v2026.8.3`](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/hooks.md) | `hooks.<event>[]` entries have `command`, optional matcher (honored only for pre/post tool), and timeout (60-second default, 300-second cap); JSON event on stdin; JSON response on stdout; `pre_tool_call` can block, `pre_llm_call` can add context, and `pre_verify` can continue the bounded verification loop. |
| Native process behavior | [`agent/shell_hooks.py` at `v2026.8.3`](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/agent/shell_hooks.py) | Command is expanded, split with `shlex.split`, and passed as argv to synchronous `subprocess.run` with `shell=False`, captured UTF-8 stdout/stderr, timeout, and Windows no-window flags. Nonzero, timeout, and malformed output warn and do not enforce. |
| Hook/event inventory | [`hermes_cli/plugins.py` at `v2026.8.3`](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/hermes_cli/plugins.py) | `VALID_HOOKS` retains the same 23 events reviewed at v0.19.0. DefenseClaw registers every one, but classifies response authority independently rather than treating membership as enforcement. |
| Shell-hook approval | [`agent/shell_hooks.py` at `v2026.8.3`](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/agent/shell_hooks.py) | Consent remains persisted in `<home>/shell-hooks-allowlist.json` as exact `event` + `command` approvals. DefenseClaw preserves `hooks_auto_accept` and transactionally owns only its exact 23 approval pairs. |
| Callback lifecycle | [`agent/shell_hooks.py` at `v2026.8.3`](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/agent/shell_hooks.py) and [hook documentation at `v2026.8.3`](https://github.com/NousResearch/hermes-agent/blob/v2026.8.3/website/docs/user-guide/features/hooks.md) | Shell callbacks are registered into a running process. On-disk registration or revocation therefore requires reloading/restarting every affected Hermes host before it is live. No vendor-proven in-process reload command is claimed. |
| Profiles and multiplexing | [`hermes_cli/profiles.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_cli/profiles.py), [`hermes_cli/main.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_cli/main.py), and [`gateway/config.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/gateway/config.py) at `v2026.7.30` | Named profiles use `<root>/profiles/<name>` and `active_profile`; gateways can multiplex through top-level/nested config or `GATEWAY_MULTIPLEX_PROFILES`. One DefenseClaw `HERMES_HOME` cannot cover those topologies, so Setup and Doctor report them unsupported. |
| Effective inventory | [`agent/skill_utils.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/agent/skill_utils.py), [`agent/prompt_builder.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/agent/prompt_builder.py), [`hermes_cli/doctor.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_cli/doctor.py), and [`hermes_cli/plugins.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_cli/plugins.py) at `v2026.7.30` | The bounded default-profile inventory includes `skills.external_dirs`, `SOUL.md`, `memories/MEMORY.md`, `memories/USER.md`, `memory.provider`, bundled or Nix plugin roots, user plugins, and pip `hermes_agent.plugins` entry points with activation provenance. Project plugins are conditional on the launch cwd and environment and remain unverified. |

## Native hook contract

DefenseClaw writes this logical command shape (the actual absolute path is
installer-proven and quotes are literal):

```text
"C:/.../DefenseClaw/HookRuntime/defenseclaw-hook.exe" hook --connector hermes
```

There is no PowerShell call operator, encoded command, `.ps1`, `.cmd`, `.sh`,
`bash`, PATH lookup, or shell fallback. Forward slashes prevent Python
`shlex.split` from treating a Windows backslash before a shell metacharacter as
an escape. Windows accepts the resulting absolute native path.

DefenseClaw registers all 23 v0.19 shell-hook-valid events:

| Hermes event(s) | Matcher | Official input/output semantics | DefenseClaw classification |
| --- | --- | --- | --- |
| `pre_tool_call` | `.*` | Tool name/input plus event fields on JSON stdin; canonical or Claude-style block JSON is parsed from stdout. | **Enforce/block:** the only tool veto. |
| `post_tool_call` | `.*` | Completed tool result on stdin; return ignored. | **Observe/audit:** cannot undo a side effect. |
| `pre_llm_call` | none | Prompt/model context on stdin; non-empty `{"context":"..."}` is parsed. | **Context transform:** no tool veto or ask. |
| `post_llm_call` | none | Completed model-loop fields on stdin; return ignored. | **Observe/audit.** |
| `pre_verify` | none | Coding/attempt/changed paths/final response arrive under `extra`; `continue` or normalized stop-block JSON with a message keeps the bounded verification loop going. | **Control/continue:** not a tool deny, fail-closed result, or ask. |
| `transform_terminal_output` | none | Python callback receives command/raw output/exit/cwd/task and must return a Python `str` to replace content. | **Audit-only; transform N/A:** shell JSON cannot return the required Python string. |
| `transform_tool_result` | none | Python callback receives tool/arguments/result/task and must return a Python `str`. | **Audit-only; transform N/A** in the shell lane. |
| `transform_llm_output` | none | Python callback receives final response/session/model/platform and must return a Python `str`. | **Audit-only; transform N/A** in the shell lane. |
| `pre_gateway_dispatch` | none | Python plugins can return `skip`, `rewrite`, or `allow`. | **Audit-only; gateway mutation N/A:** the shell parser does not pass these shapes through. |
| `pre_approval_request`, `post_approval_response` | none | Approval request/result fields on stdin; official return values ignored. | **Audit-only:** no DefenseClaw approve, deny, ask, or prompt answer. |
| `pre_api_request`, `post_api_request`, `api_request_error` | none | Declared in v0.19 `VALID_HOOKS`; the v0.19 hook guide does not publish a shell response effect. | **Partial audit-only:** no response authority inferred from membership. |
| `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset` | none | Session lifecycle fields on stdin; return ignored. | **Observe/audit.** |
| `subagent_start`, `subagent_stop` | none | Delegation lifecycle fields on stdin; return ignored. | **Observe/audit.** |
| `kanban_task_claimed`, `kanban_task_completed`, `kanban_task_blocked` | none | Durable task-transition fields on stdin; returns ignored. | **Audit-only:** `blocked` names an already-recorded transition, not a veto. |

Setup does not change `hooks_auto_accept`. It transactionally adds only the
exact DefenseClaw `(event, command)` approval objects to
`shell-hooks-allowlist.json`, marks those entries for narrow teardown custody,
and preserves all operator and third-party entries. Rollback restores both
files together. Teardown restores the pristine allowlist when unchanged, or
removes only unambiguously owned entries after benign third-party drift; an
ambiguous or tampered owned entry stops cleanup instead of broadening custody.

Hermes registers callbacks in each running host. Setup therefore reports
`live: false` / `pending_reload` until every affected CLI, gateway, desktop, or
service process is reloaded or restarted. On Windows, teardown writes an exact
direct-native disabled tombstone before revoking config and allowlist entries,
so a stale cached callback safely no-ops while revocation is still pending.
DefenseClaw does not claim a Hermes reload mechanism that the examined release
does not prove, and it never manages Hermes PortableGit terminal behavior.

This connector covers only the default profile selected by one resolved
`HERMES_HOME`. Named profile homes, a non-default `active_profile`, and gateway
multiplexing are unsupported rather than partially protected. Enterprise,
managed, Team, ProgramData, cloud-dashboard, and MDM surfaces are outside this
connector and remain unverified.

Hermes has no native ask/approve or general message response. A DefenseClaw
`confirm` verdict is recorded and alerted without hook output; it cannot pause
and resume the tool call. Exit status is not an enforcement surface.
Missing home/token, oversized stdin, gateway auth/network failure, timeout,
nonzero execution, gateway 4xx/5xx, and malformed/missing response fields all
fail open without synthesizing block JSON, even if a global strict or
fail-closed setting is requested. Only a valid gateway response containing a
valid Hermes block object is passed through.

## Cross-surface connector acceptance matrix

Cell vocabulary is **Implemented**, **Officially limited**, **N/A**, or
**Blocked**. Claude Code and Codex are coverage references; this task changes
only Hermes-owned gaps.

| # | Surface | Hermes preview | Claude Code reference | Codex reference |
| --- | --- | --- | --- | --- |
| 1 | Go/Python registry, discovery, version, platform mirrors | **Implemented** — Go/Python registries, `hermes --version`, `HERMES_HOME`/LocalAppData paths, `hermes-hooks-v1 >=0.19.0`, and Windows `preview` mirrors. Installed v0.17.0 is detected but unsupported, produces one observe downgrade with upgrade guidance, and is never accepted for the 23-event contract. Official v0.20.0 source retains the reviewed v0.19 shape; packaged compatibility remains uncertified. | **Implemented** — supported native-Windows registry and versioned hook contract. | **Implemented** — supported native-Windows registry and versioned hook contracts. |
| 2 | CLI commands/help/aliases/parity | **Implemented** — `setup hermes`, guardrail lifecycle, hidden connector reconcile/teardown/verify, Windows bootstrap and Setup quiet `CONNECTOR=hermes`. **Officially limited:** no Hermes ask or fail-closed command claim. | **Implemented** — `claude-code` alias and lifecycle commands. | **Implemented** — `codex` alias and lifecycle commands. |
| 3 | TUI visibility/setup/status/health/repair | **Implemented/limited** — visible as `(preview)` with direct-JSON-block, fail-open, no-ask wording; Doctor reports pending reload as unhealthy and rejects named/multiplex profile topologies. | **Implemented** — supported picker/status/Doctor path. | **Implemented** — supported picker/status/Doctor path and effective managed policy check. |
| 4 | Windows Setup GUI/quiet/bootstrap/transaction/repair/upgrade/reconcile/uninstall | **Implemented/limited** — default-profile config plus exact allowlist custody, transactional rollback, exact restore, reconcile, VerifyClean, and direct-native disabled teardown tombstone. Registration/revocation remains pending reload; named/multiplex and managed/ProgramData surfaces are unsupported/unverified. | **Implemented** reference. | **Implemented** reference. |
| 5 | Hook/policy version, events, matcher, wire, wait/timeout, modes | **Implemented** — all 23 v0.19 events above, flat YAML entry shape, JSON stdin/stdout, synchronous wait, and 30-second DefenseClaw registration. **Officially limited:** block only `pre_tool_call`; context at `pre_llm_call`; bounded continue at `pre_verify`; transform/gateway/approval/API/Kanban/lifecycle behavior classified independently; no DefenseClaw ask; failures open. | **Implemented** — connector-specific documented matrix; ask/block/fail-mode varies by event. | **Implemented** — connector-specific documented matrix; no native ask. |
| 6 | Native process adapter/path quoting/provenance/no fallback | **Implemented** — directly quoted absolute stable PE plus fixed argv; `shlex.split`/`shell=False`; passive provenance inspection; no compatibility fallback. | **Implemented** — native executable command through the host's documented PowerShell command evaluator. | **Implemented** — native executable through the Codex Windows command boundary. |
| 7 | Gateway/sidecar auth/mode/status/lifecycle | **Implemented** — connector-scoped token preferred over legacy token, authenticated loopback request, protected sidecars/stable launcher, recovery and teardown. **Officially limited:** auth failure still fails open upstream. | **Implemented** reference. | **Implemented** reference. |
| 8 | Doctor passive health/tamper/drift/repair/TUI | **Implemented/limited** — YAML schema, exact 23-event and approval matrix, direct argv, PE ownership, pending-reload state, profile topology, contract lock, version drift, and repair command; registered command is never executed by Doctor and no running host is claimed healthy before reload evidence. | **Implemented** reference. | **Implemented** reference, including bounded trusted policy inspection. |
| 9 | Observability/audit/OTLP/correlation/alerts/attribution | **Implemented downstream** — hook-derived logs/metrics/traces, v8 audit and connector/session/event correlation, alerts/export routing. **Officially limited:** Hermes has no documented native OTLP; source is attributed as hook-derived, never native. | **Implemented** — native OTLP where host documents it plus hook audit. | **Implemented** — native OTLP where host documents it plus hook audit/notify. |
| 10 | Skills/MCP/plugins/rules/agents/config inventory | **Implemented where applicable for the default profile** — config and MCP in resolved `config.yaml`; local skills plus existing `skills.external_dirs`; `SOUL.md`; built-in memory files and `memory.provider` provenance; bundled/Nix, user, and pip plugins with activation provenance. **Unverified:** project plugins depend on launch cwd/environment, and named-profile/project-conditional rules or context sources are not claimed. | **Implemented/limited by documented host roots.** | **Implemented/limited by documented host roots.** |
| 11 | Docs/site/CLI matrices/operator limits | **Implemented** — connector page, Windows platform/enforcement/capability/lifecycle pages, connector matrix, install guide, and this evidence matrix. | **Implemented** reference. | **Implemented** reference. |
| 12 | Deterministic/packaged/live/manual validation definitions | **Implemented definitions** — focused unit/Doctor/lifecycle tests plus Windows contract fixture. **Blocked for certification:** packaged `windows-latest`, signed-Setup lifecycle, and real official-client block-visibility/manual tests are deferred to the single integration pass. | **Implemented/certified** reference gates. | **Implemented/certified** reference gates. |

## DefenseClaw feature compatibility audit

| Feature | Hermes classification and evidence |
| --- | --- |
| Native OTel logs, metrics, traces, resources | **Officially limited:** no official Hermes native OTLP surface is documented in the examined release. DefenseClaw must report `native_otlp=false`. |
| Hook-derived telemetry | **Implemented:** authenticated gateway hook events generate connector-labelled audit, log, metric, and trace signals downstream. This does not relabel them as host-native OTLP. |
| v8 audit and correlation | **Implemented downstream:** `connector=hermes`, hook contract/profile, session/event IDs, trace context when supplied, tool/prompt identity, and subagent correlation reach canonical v8 audit and routed copies. Legacy events that omit IDs remain explicitly partial. |
| Observe/action modes | **Implemented:** observe records and may inject advisory context; action may block only valid `pre_tool_call` JSON or continue a bounded `pre_verify` loop. Post and audit-only events cannot undo side effects. |
| Allow/block/ask/HILT/message | **Implemented/limited:** valid allow/block JSON is supported at `pre_tool_call`, including a block reason. Whether a particular Hermes UI renders that reason is pending real-client certification. **No native ask/HILT or general message response**; confirm is audit/alert-only with no hook output. |
| Fail-mode provenance | **Officially limited:** Hermes upstream ignores exit status for enforcement and warns on errors. DefenseClaw records configured/effective provenance but forcibly executes Hermes failures open and never claims fail-closed. |
| Judge | **Applicable only in the hook lane:** a judge may contribute a policy verdict before a block-capable hook response. **N/A for proxy-lane scanning:** Hermes is not a DefenseClaw model proxy. Judge timeout/error cannot create a proven Hermes fail-closed result. |
| Scoped gateway token | **Implemented:** connector-scoped sidecar, validation, rotation/reconciliation, authenticated readiness, and teardown revocation follow the shared protected hook runtime. Authentication drift is actionable in Doctor/status but still fails open at the Hermes boundary. |
| Notifications/webhooks/alerts | **Implemented downstream:** correlated audit findings can create alerts and route to configured webhooks/native Windows notifications. **Officially limited:** Hermes exposes no additional native DefenseClaw notification callback in this contract. |
| Inventory/policy monitoring | **Implemented where applicable for the default profile:** config/MCP, local and external skills, `SOUL.md`, built-in memory/provider provenance, and bundled/Nix, user, and pip plugins are bounded and read-only except the existing opt-in user-skill write surface. Project-conditional and named-profile sources are explicitly unverified. |
| Tamper/drift watcher | **Implemented:** owned hook presence, exact command/config/allowlist reference, allowlist ownership markers, hook lock, version, token/runtime, pending-reload state, and current/previous home drift feed reconciliation and Doctor. Plugin inventory does not grant mutation ownership. |
| Status/TUI/Doctor | **Implemented/limited:** preview/not-certified, `live:false`, action/observe posture, fail-open/no-ask limits, pending reload, unsupported profile topology, passive native runtime evidence, drift, and repair guidance. |
| SIEM/exporter routing | **Implemented downstream:** authenticated canonical events retain connector/correlation labels through v8 routing to configured OpenTelemetry and Splunk sinks. Export availability depends on the selected sink, credentials, and network. |
| Sandbox/firewall/egress | **N/A for connector parity:** Hermes is hook-only and retains its direct upstream/model/tool topology. DefenseClaw does not claim a Hermes native sandbox, proxy firewall, or terminal egress interception. Generic policy can evaluate observed hook content only. |

## Certification blockers and later broad pass

Do not promote Hermes beyond preview/not-certified until one integrated
Windows pass has:

1. built the packaged x64 distribution and signed/release-equivalent Setup;
2. exercised fresh GUI and quiet install, repair, same-version repair, upgrade,
   preservation, changed-home reconciliation, rollback/handoff, uninstall,
   deferred cleanup, and byte-exact third-party config restoration;
3. run the deterministic installed-hook matrix with paths containing spaces and
   metacharacters and with allow, valid block, context, malformed, nonzero,
   timeout, auth, network, and gateway-response failures;
4. installed the official Hermes `v2026.8.3` client natively, without
   DefenseClaw touching its Git Bash dependency, and visibly demonstrated a
   benign `pre_tool_call` block plus observe-only lifecycle events;
5. verified status/TUI/Doctor, token rotation/revocation, tamper repair,
   v8 audit correlation, alerts, and configured OTLP/Splunk exporter routes;
6. confirmed teardown/VerifyClean and byte-exact restoration after the real
   client has reloaded its configuration.

The later pass may document Hermes's upstream PortableGit behavior but must not
invoke, locate, configure, or test it as part of DefenseClaw.
