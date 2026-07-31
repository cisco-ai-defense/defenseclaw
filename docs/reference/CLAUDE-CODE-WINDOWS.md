# Claude Code native Windows reference

This is the evidence gate and reusable coverage checklist for the DefenseClaw
Claude Code connector preview on native Windows. It was reverified on
**2026-07-30**. No immutable packaged plus official-client Windows validation
record is persisted, so this document does not establish certification.
The eligible platform is a Windows process launched directly from PowerShell
or CMD with Windows paths and native executables. WSL, Docker, virtual
machines, Bash, Git Bash, Cygwin, MSYS, and compatibility shims are not valid
evidence for this certification.

## Eligibility decision

**Eligible.** Anthropic documents:

- Windows 10 version 1809 or newer and Windows Server 2019 or newer on x64 or
  ARM64.
- direct native installation and launch from PowerShell or CMD;
- command hooks whose `args` form executes a real `.exe` directly without a
  shell; and
- an explicit `powershell` hook shell plus native `.ps1` examples.

Git for Windows is recommended, not required. Anthropic documents that Claude
Code uses its native PowerShell tool when Git Bash is absent. DefenseClaw uses
the shell-free `command` plus `args` form with the native DefenseClaw
executable, so Git Bash is not in the enforcement path.

## Official evidence snapshot

| Evidence | Version/date | Contract fact |
| --- | --- | --- |
| [Setup](https://code.claude.com/docs/en/setup) | checked 2026-07-30 | native Windows requirements; PowerShell, CMD, and WinGet installs; update/uninstall behavior |
| [Installation troubleshooting](https://code.claude.com/docs/en/troubleshoot-install) | checked 2026-07-30 | native binary at `%USERPROFILE%\.local\bin\claude.exe`; `where.exe claude` |
| [Hooks reference](https://code.claude.com/docs/en/hooks) | checked 2026-07-30 | hook config, input, command execution, output, exit, timeout, event, and blocking semantics |
| [Settings](https://code.claude.com/docs/en/settings) | checked 2026-07-30 | native paths, scopes, Windows managed policy, and MCP/settings separation |
| [`.claude` directory](https://code.claude.com/docs/en/claude-directory) | checked 2026-07-30 | skills, agents, rules, commands, plugins, and `CLAUDE_CONFIG_DIR` layout |
| [Skills](https://code.claude.com/docs/en/slash-commands) | checked 2026-07-30 | launch-directory ancestors through repository root, lazy nested skill roots, skill-over-command precedence, directory symlinks, and `--add-dir` exception |
| [Subagents](https://code.claude.com/docs/en/sub-agents) | checked 2026-07-30 | recursive agent roots, frontmatter identity, closest-project precedence, and managed/session/plugin scopes |
| [Memory](https://code.claude.com/docs/en/memory) | checked 2026-07-30 | project-derived auto-memory path, linked-worktree sharing, and `autoMemoryDirectory` override |
| [Environment variables](https://code.claude.com/docs/en/env-vars) | checked 2026-07-30 | `CLAUDE_CONFIG_DIR` relocates settings/state/plugins; native PowerShell behavior |
| [MCP](https://code.claude.com/docs/en/mcp) | checked 2026-07-30 | user/local `~/.claude.json`, project `.mcp.json`, approval, and precedence |
| [Monitoring](https://code.claude.com/docs/en/monitoring-usage) | checked 2026-07-30 | native OpenTelemetry environment contract |
| [v2.1.139](https://github.com/anthropics/claude-code/releases/tag/v2.1.139) | 2026-05-11 | introduced hook `args: string[]` direct-exec form |
| [v2.1.152](https://github.com/anthropics/claude-code/releases/tag/v2.1.152) | 2026-05-27 | introduced `MessageDisplay` |
| [v2.1.154](https://github.com/anthropics/claude-code/releases/tag/v2.1.154) | 2026-05-28 | added plugin `defaultEnabled`; DefenseClaw's current minimum contract version |
| [v2.1.214](https://github.com/anthropics/claude-code/releases/tag/v2.1.214) | 2026-07-18 | fixed exit-code 2 blocking when stdout JSON fails schema validation |
| [v2.1.219](https://github.com/anthropics/claude-code/releases/tag/v2.1.219) | 2026-07-24 | release notes mention `DirectoryAdded`; current hooks reference has no published schema |
| [v2.1.220](https://github.com/anthropics/claude-code/releases/tag/v2.1.220) | 2026-07-25 | latest official non-prerelease observed during this audit |

The audit host had the native binary at
`C:\Users\kevin\.local\bin\claude.exe` and a read-only `claude --version`
probe returned `2.1.211 (Claude Code)`. That local observation is not a
substitute for the official contract or the later real-client E2E phase.

### Native install methods

Anthropic publishes these direct native methods:

```powershell
irm https://claude.ai/install.ps1 | iex
```

```bat
curl -fsSL https://claude.ai/install.cmd -o install.cmd && install.cmd && del install.cmd
```

```powershell
winget install Anthropic.ClaudeCode
```

The native installer auto-updates. WinGet installations do not auto-update.
The setup reference also documents stable/latest and version-pinned installer
channels. Release validation must record both the requested channel/version
and the exact `claude --version` result.

## Native path and scope model

`~/.claude` resolves to `%USERPROFILE%\.claude` on Windows. When
`CLAUDE_CONFIG_DIR` is set, Claude Code stores its settings, session history,
plugins, and Windows credentials under that configured directory; DefenseClaw
uses that same effective root. `CLAUDE_CODE_PLUGIN_CACHE_DIR` independently
overrides the plugin parent (despite the variable name); its `cache`
subdirectory holds marketplace copies.

| Surface | User/native path | Project/local path |
| --- | --- | --- |
| Hook and environment settings | `%USERPROFILE%\.claude\settings.json` | `<repo>\.claude\settings.json`, `<repo>\.claude\settings.local.json` |
| MCP user/local state | `%USERPROFILE%\.claude.json` | local scope is nested by project in that file |
| MCP project state | n/a | `<repo>\.mcp.json` |
| Skills | `%USERPROFILE%\.claude\skills\` | launch directory and every parent through the repository root, plus nested `<subdir>\.claude\skills\` after file activity; documented skill-directory symlinks are resolved and canonical targets de-duplicated |
| Agents | recursive `%USERPROFILE%\.claude\agents\` | recursive `.claude\agents\` in every directory from the launch directory through the repository root; identity is required `name` frontmatter and the closest project definition wins |
| Rules | `%USERPROFILE%\.claude\CLAUDE.md`, `%USERPROFILE%\.claude\rules\` | `CLAUDE.md`, `CLAUDE.local.md`, `.claude\CLAUDE.md`, `.claude\rules\` |
| Auto memory | `%USERPROFILE%\.claude\projects\<project>\memory\` by default | the project identity is derived from the repository; all linked worktrees resolve to the main repository identity; `autoMemoryDirectory` can override the path from any settings scope |
| Commands | `%USERPROFILE%\.claude\commands\` | `<repo>\.claude\commands\` |
| Plugin cache/state | `%USERPROFILE%\.claude\plugins\cache\` plus scoped settings | project/local enablement is in scoped settings; manifest-bearing project skills-directory plugins live under `<repo>\.claude\skills\` |

With `CLAUDE_CONFIG_DIR=C:\ClaudeProfile`, the user settings path is
`C:\ClaudeProfile\settings.json` and the relocated user/local state path is
`C:\ClaudeProfile\.claude.json`.

Windows managed settings use:

- `HKLM\SOFTWARE\Policies\ClaudeCode` (`Settings` REG_SZ or REG_EXPAND_SZ);
- lower-priority `HKCU\SOFTWARE\Policies\ClaudeCode`; or
- `C:\Program Files\ClaudeCode\managed-settings.json` and its documented
  `managed-settings.d` drop-in directory.

The legacy ProgramData managed-settings location is unsupported as of
Claude Code v2.1.75.

## Hook contract

### Configuration and invocation

Hook configuration is nested as:

`hooks.<Event>[] -> { matcher, hooks: [{ type, command, args, timeout, async }] }`.

Command hooks receive one JSON object on stdin. The current common fields are
`session_id`, `prompt_id` (v2.1.196+), `transcript_path`, `cwd`,
`permission_mode`, `effort`, `hook_event_name`, `agent_id`, and
`agent_type`, plus event-specific fields. Transcript writes can lag the hook
input, so enforcement must use stdin as the authoritative current event.

On Windows, DefenseClaw registers:

```json
{
  "type": "command",
  "command": "C:\\absolute\\path\\to\\defenseclaw-hook.exe",
  "args": ["hook", "--connector", "claudecode"]
}
```

This is the v2.1.139+ direct-exec form. Anthropic requires a real executable
for Windows exec form: `.cmd` and `.bat` files cannot be used as the direct
`command`. A native PowerShell hook is also supported by specifying the
`powershell` shell or invoking `powershell.exe` with fixed arguments and an
absolute `.ps1` path. DefenseClaw does not need a PowerShell wrapper.
Doctor rejects owned `.cmd` and `.bat` targets. It also rejects a shell-form
registration unless `shell` is explicitly `powershell`; otherwise Claude Code
can select Git Bash when it is installed. A quoted executable in explicit
PowerShell shell form must use PowerShell's `&` call operator. The canonical
DefenseClaw registration remains the shell-free executable form above.

All matching hooks run in parallel, and identical handlers are deduplicated.
The process working directory is the session directory. DefenseClaw therefore
uses an absolute executable and fixed arguments; it never constructs a shell
command from hook input.

`FileChanged` has a two-stage matcher contract: Claude Code first splits the
matcher on `|` and registers each segment as a literal filename in the current
working directory, then applies the same matcher to the basename of a changed
file. DefenseClaw uses `.+`, which is both a valid literal Windows filename and
a regular expression matching every non-empty basename. It does not put user
or project paths in that matcher. Instead, it returns absolute `watchPaths`
from:

- `SessionStart` in nested `hookSpecificOutput` (for
  `startup|resume|clear|compact|fork`);
- `CwdChanged` as a top-level field; and
- `FileChanged` as a top-level field, refreshing the list after each change.

The dynamic list uses the same `CLAUDE_CONFIG_DIR`-aware path model as setup
and inventory. It covers user settings, user MCP state, resolved project auto-memory
and rule files, project `.mcp.json`, project settings, selected project
manifest/environment files, and existing `SKILL.md` entrypoints from the user,
launch-ancestor, and lazily discoverable nested skill roots. It also includes
recursive user/project agent Markdown files. The component scanner covers the
full skill/plugin directories plus commands, agents, and resolved memory.
Rule, skill, agent, and memory topic files are included only when they exist;
all returned paths are absolute. Passive memory attribution is marked
unverified because session `--settings`, remote managed settings, and native
registry/MDM policy are not observable from filesystem state alone; operators
confirm the active source with Claude Code `/memory` or `/status`.

### Documented events

The current hooks reference documents:

`SessionStart`, `Setup`, `UserPromptSubmit`, `UserPromptExpansion`,
`PreToolUse`, `PermissionRequest`, `PermissionDenied`, `PostToolUse`,
`PostToolUseFailure`, `PostToolBatch`, `Notification`, `MessageDisplay`,
`SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`,
`StopFailure`, `TeammateIdle`, `InstructionsLoaded`, `ConfigChange`,
`CwdChanged`, `FileChanged`, `WorktreeCreate`, `WorktreeRemove`,
`PreCompact`, `PostCompact`, `Elicitation`, `ElicitationResult`, and
`SessionEnd`.

DefenseClaw registers 28 of those events. It intentionally excludes:

- `Setup`, which is observation-only and runs only for explicit
  initialization/maintenance invocations; and
- `WorktreeCreate`, because registering it replaces Claude Code's default Git
  behavior and the handler must create and return a worktree path.

Claude Code v2.1.219 release notes also mention `DirectoryAdded`, but the
current hooks reference does not list the event or define its input, ordering,
matcher, output, or blocking behavior. It remains unregistered until Anthropic
publishes that contract.

### Wait, stdout, and exit behavior

- A synchronous command hook waits for process completion or timeout.
- Exit `0`: Claude Code parses stdout as structured JSON. JSON output is
  processed only on exit `0`.
- Exit `2`: blocking error. Stdout is ignored and stderr is used as the reason
  where the event supports blocking.
- Other nonzero exit codes: non-blocking errors for most events.
- `WorktreeCreate` is special: any nonzero exit fails worktree creation.
- Async command hooks cannot block and their output is not applied to the
  current action.
- `InstructionsLoaded` is host-defined asynchronous observability even when a
  handler is not marked with `async: true`.
- `PostToolUse` and other post-result events cannot undo a side effect that
  already occurred.

Anthropic waits synchronously by default and makes async execution opt-in.
DefenseClaw deliberately marks `MessageDisplay` async because it is
observational; its output therefore cannot affect the current action. It keeps
the remaining registered handlers in synchronous command form so every
decision-capable event waits for the gateway verdict; host-defined
non-blocking events remain observational.

Anthropic's default command timeout is 600 seconds, with shorter event
defaults for `UserPromptSubmit` (30 seconds), `MessageDisplay` (10 seconds),
and a shared 1.5-second `SessionEnd` budget unless explicitly overridden
(up to 60 seconds). DefenseClaw sets explicit bounded timeouts and gives its
gateway request a one-second-smaller deadline so the hook can still render a
deterministic response before Claude Code terminates it.

### Decision and mode mapping

| DefenseClaw behavior | Claude Code output |
| --- | --- |
| allow/action continue | exit 0 with the event's allow/continue output |
| block `PreToolUse` | `hookSpecificOutput.permissionDecision="deny"` |
| ask `PreToolUse` | `hookSpecificOutput.permissionDecision="ask"` |
| deny `PermissionRequest` | event-specific nested deny decision |
| block `TaskCreated`, `TaskCompleted`, or `TeammateIdle` | stderr feedback and exit 2; never `continue:false`, which stops the teammate |
| block other supported prompt/lifecycle event | documented top-level block decision or event-specific decline |
| transport/parse failure in fail-closed mode | stderr reason and exit 2 |
| observe mode policy hit | non-blocking response with `would_block` audit evidence |

`ConfigChange` cannot be blocked when `source=policy_settings`. HTTP hooks fail
open on non-2xx responses and timeouts, so DefenseClaw uses command hooks for
local enforcement. Structured JSON output is capped by Claude Code; reasons
must be concise.

## DefenseClaw lifecycle and security invariants

- Discovery checks the documented native `%USERPROFILE%\.local\bin\claude.exe`
  location and runs `claude --version`.
- Setup/repair/upgrade reconcile the exact event, matcher, timeout, async
  setting, executable identity, and fixed argument vector.
- Action mode refuses an unsupported hook-contract version; observe mode can
  proceed with an explicit warning and contract-lock evidence.
- The hook uses a connector-scoped gateway bearer. The token cannot access
  management routes or impersonate another connector.
- The native hook launcher, credential sidecars, and contract evidence are
  protected with Windows owner-only ACL checks and digest/identity validation.
- The launcher can cold-start the gateway, but only through the protected
  runtime record and validated native executable identity.
- Doctor checks contract lock, hook matrix, executable/argument identity,
  script/runtime digests, ACLs, scoped auth, telemetry, and drift.
- Teardown restores the exact pristine settings bytes when the protected
  identity still matches. If the operator edited the file, it surgically
  removes only DefenseClaw-owned hooks/environment keys and preserves operator
  changes. Token revocation follows clean verification.
- Native telemetry uses Claude Code's documented OTel environment settings and
  a connector-scoped authorization header. Logs and metrics are enabled;
  traces are deliberately disabled in the current connector. Every documented
  content gate is explicitly off: user prompts, assistant responses, tool
  details, tool input/output content, and raw API bodies. Downstream routing or
  redaction is not treated as informed source-capture opt-in.

## Reusable golden coverage checklist

Use this checklist for every Claude Code contract change and native Windows
release. “Audited” is source/contract review; “verified” requires the named
test layer.

| Surface | Golden requirement | Current evidence | Release verification |
| --- | --- | --- | --- |
| Research gate | official direct native support, paths, and hook interface; no compatibility layer | eligible, sources above | recheck on every upstream contract/release change |
| Discovery/version | documented native binary candidates; trusted path; exact version normalization | implemented | focused unit plus packaged native discovery |
| Hook config | absolute `.exe`, `args` exec form, no shell, exact event/matcher/timeout/async matrix; dynamic absolute watch paths | implemented | focused unit, packaged setup, real-client settings inspection |
| Synchronous enforcement | stdin JSON, bounded wait, exit 0 JSON, exit 2 stderr, exit propagation | implemented | hookexec unit, packaged fake client, real-client block |
| Modes | observe, action allow/block, native ask, fail-open/closed boundaries | implementation exists; the PowerShell-only official-client allow/block lane is defined but unexecuted, while official-client ask/fail cases are still pending | per-mode integration and real-client E2E |
| Auth/runtime | connector bearer, route binding, protected HookRuntime ACL/digest/identity, cold start | implemented | Windows ACL/auth/tamper tests |
| Inventory | skills, MCP, plugins, rules/memory, agents, commands; correct user/project attribution | user skills plus launch-ancestor and bounded lazy nested project skill roots, commands, recursive user/project Markdown agents, settings, rules, local/project/user MCP, auto memory, and skills-directory plugins are implemented. Nested skills remain `discoverable-unverified` until file activity proves activation; true skills precede legacy commands, and documented skill-directory symlinks are canonicalized/de-duplicated. Auto-memory uses bounded stable settings reads and shared linked-worktree identity, but session/remote/native-policy activation is unverified. Managed `enabledPlugins` overrides lower scopes; dynamic `policyHelper` and retained-version ambiguity remain unverified rather than falsely active. Marketplace cache artifacts honor the cache-parent override. Managed/plugin agents, session `--agents`, plugin-provided MCP, claude.ai connector MCP, and runtime `/add-dir` roots require authoritative client/session evidence and are not claimed by the filesystem inventory. | focused path/precedence tests; later official-client semantic inventory |
| Setup/repair/upgrade | idempotent reconciliation; stale owned handlers removed; operator handlers preserved | implemented | setup refresh and packaged upgrade/repair |
| Doctor/recovery | detect version, matrix, token, ACL, digest, config, telemetry, and drift; repair safely | implemented | focused unit plus tamper/drift/recovery matrix |
| Teardown/uninstall | exact restore when unchanged; surgical cleanup after drift; revoke credential only after clean state | implemented | restoration and uninstall matrix |
| Audit/telemetry | hook decision audit, `would_block`, correlation, scoped OTLP auth, no credential logging | implemented | focused audit tests plus native OTLP integration |
| Deterministic Windows CI | PowerShell-only packaged fixture with native `.exe`; no Bash/WSL/container dependency | definition present; it is not certification evidence until run and persisted | run the packaged Windows workflow |
| Official-client E2E | official native installer/client, protected gateway, allow/block/ask/fail and cleanup | PowerShell-only lifecycle plus allow/block cases are defined but have no persisted qualifying run; ask/fail cases are not yet defined | define missing cases and persist a qualifying run before any certification promotion |
| Documentation | platform matrix, native prerequisites, limitations, version floor, sources | corrected in this audit | docs build/link check |

## Comparison with the Codex reference

The Codex connector is useful as a coverage baseline, not a schema template.
The following differences must remain explicit:

| Concern | Claude Code | Codex |
| --- | --- | --- |
| Native hook schema | nested settings events with command `args` exec form | Codex-specific hook configuration and trust introspection |
| Decision output | event-specific `hookSpecificOutput`, top-level decisions, exit 2 | Codex-specific response envelope and event behavior |
| Native ask | `PreToolUse` supports `permissionDecision="ask"` | current DefenseClaw Codex contract has no native ask surface |
| Event set | 28 registered Claude lifecycle events | a smaller, independently versioned Codex event matrix |
| MCP state | `~/.claude.json` plus project `.mcp.json` | `$CODEX_HOME/config.toml` plus trusted project `.codex/config.toml` layers |
| Managed policy | Windows registry and `C:\Program Files\ClaudeCode` policy chain | Codex-specific managed configuration |
| Worktree hooks | `WorktreeCreate` replaces default behavior and is excluded | different host semantics; no equivalence assumed |
| Telemetry | hook bus plus native OTel logs/metrics | hook/notify surfaces plus Codex-native telemetry |

Parity means both connectors cover discovery, protected invocation, enforcement
modes, auth, reconciliation, doctor, teardown, audit, deterministic CI, and
official-client E2E. It does not mean copying event names, output fields,
blocking rules, trust behavior, or configuration paths between hosts.

## Known limitations and revalidation triggers

- `DirectoryAdded` remains release-only and unregistered until the official
  hooks reference documents its complete contract.
- `Setup`, `InstructionsLoaded`, `MessageDisplay`, and post-result events are
  observational or otherwise non-blocking according to host semantics.
- Native ask exists only where Anthropic documents it; DefenseClaw does not
  synthesize a resumable ask for other events.
- The current official-client Windows harness definition statically requires
  Claude's `PowerShell` tool and rejects captured Bash/Git-Bash/MSYS/Cygwin
  processes for its allow/block cases. It has not produced immutable
  qualifying evidence, and official-client ask/fail cases remain to be
  defined and run.
- WinGet does not auto-update, so release automation must upgrade it
  explicitly before compatibility verification.
- ARM64 is supported upstream but DefenseClaw has no current native Windows
  connector certification; every architecture requires its own packaged and
  real-client run.
- Any upstream change to events, decision JSON, exit behavior, managed paths,
  `CLAUDE_CONFIG_DIR`, MCP scopes, or PowerShell/direct-exec behavior reopens
  the research gate before implementation.
