# GitHub Copilot CLI native Windows contract

Research was refreshed on **2026-07-30** before implementing the DefenseClaw
Windows connector path. This is an upstream-eligibility record, not a
DefenseClaw certification result.

## Eligibility decision

GitHub officially supports running Copilot CLI directly from Windows
PowerShell. The current stable release inspected for this decision was
**1.0.77**, released **2026-07-30**. The official release channel publishes
native Windows x64/ARM64 ZIP and MSI assets.
GitHub documents PowerShell 6+ for the CLI; its Windows hook tutorial requires
PowerShell 7 (`pwsh`) on `PATH`.

That makes a direct native-Windows DefenseClaw integration eligible. WSL,
Git Bash, Cygwin, MSYS, Docker, VMs, and Unix shell shims are not part of this
contract.

DefenseClaw supports ordinary Copilot setup on native Windows. That product
availability does not certify an official-client run: validated Windows
version, timestamp, run URL, authentication, HITL, and live evidence remain
empty or unverified, and `live` remains `false`.

The native Setup executable includes Copilot in its staged connector selection
and durable lifecycle. It records the exact `COPILOT_HOME`, replays the
home-bound maintenance command during repair and upgrade, carries the binding
through uninstall handoff and deferred cleanup, and consumes the managed hook
backup only during exact restoration. The ordinary CLI, TUI, and Setup
surfaces use this same guarded lifecycle; there is no hidden public-platform
bypass.

## Official sources

- [About GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-copilot-cli)
- [Install GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli)
- [Use hooks with GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks)
- [Copilot CLI hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Pinned hooks-reference source snapshot (GitHub Docs commit `2f383aa`, 2026-07-28)](https://github.com/github/docs/blob/2f383aa194327fbe933682cbe01dd4c5625f5239/content/copilot/reference/hooks-reference.md)
- [PowerShell hook tutorial](https://docs.github.com/en/copilot/tutorials/copilot-cli-hooks)
- [Copilot CLI configuration directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference)
- [Copilot CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference)
- [Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [Official `github/copilot-cli` repository](https://github.com/github/copilot-cli)
- [Official releases](https://github.com/github/copilot-cli/releases)
- [Current stable 1.0.77 release](https://github.com/github/copilot-cli/releases/tag/v1.0.77)
- [Official changelog](https://raw.githubusercontent.com/github/copilot-cli/main/changelog.md)

## Installation, configuration, and inventory

Official native Windows installation paths include:

- `winget install GitHub.Copilot`;
- npm with Node.js 22 or later; and
- the official Windows executable archives/MSI.

Copilot reads user configuration under `%USERPROFILE%\.copilot` by default,
or under `%COPILOT_HOME%` when that variable is set. The documented inventory
includes `settings.json`, internal `config.json`, `mcp-config.json`, `agents`,
`skills`, `hooks`, and `installed-plugins`. Workspace surfaces include
`.github/hooks` and these ordered asset locations:

- agents: `.github/agents` then `.claude/agents` at every ancestor from the
  pinned workspace to the Git root, followed by `%COPILOT_HOME%\agents`;
  only `.md` and `.agent.md` files are agents, and the complete suffix is
  removed for identity (`reviewer.agent.md` is `reviewer`);
- MCP: `.mcp.json` then `.github/mcp.json` at every ancestor from the pinned
  workspace to the Git root, followed by `%COPILOT_HOME%\mcp-config.json`;
  higher-priority duplicate server names win. Static inventory reports
  declarations regardless of folder trust; effective workspace activation
  requires a trusted folder, or
  `GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP=true` in untrusted `-p` mode;
- skills: immediate `.github/skills`, `.agents/skills`, and `.claude/skills`,
  inherited parent `.github/skills`, `%COPILOT_HOME%\skills`,
  `%USERPROFILE%\.agents\skills`, then `COPILOT_SKILLS_DIRS`.

DefenseClaw inventories those documented local paths from the explicitly
pinned workspace rather than its daemon working directory. Session
`--additional-mcp-config`, plugin-provided/built-in/remote runtime MCP servers,
plugin-owned agents/skills, and remote organization/enterprise agents/skills
are not expanded from private or remote stores; the owning plugins are
reported separately through the official read-only command below. The
reviewed Copilot CLI 1.0.77 built-in agent IDs are emitted as immutable
versioned-contract rows, and local files with those IDs cannot shadow them.

The current official references disagree on custom-agent precedence. The
dedicated [CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference#custom-agent-locations)
puts project/ancestor agents before the user directory and gives `.github`
precedence over `.claude` at each level. The
[plugin-reference loading diagram](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference#loading-order-and-precedence)
places the user directory first and groups the project conventions
differently. DefenseClaw follows the dedicated custom-agent reference; real
official-client validation must confirm the effective order before any live
evidence or certification claim can be recorded.

The official read-only inventory command is
`copilot plugins list --kind plugin --json`. DefenseClaw uses it only to
discover Copilot-owned plugins. It does not install, enable, disable, remove,
back up, or restore plugins through that command.

DefenseClaw uses a standalone version-1 hook file:

- user scope: `%USERPROFILE%\.copilot\hooks\defenseclaw.json` (or the
  corresponding `%COPILOT_HOME%\hooks` location);
- workspace scope: `<workspace>\.github\hooks\defenseclaw.json`.

Repository hooks in programmatic `copilot -p` runs require the documented
`GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS=true` opt-in unless the repository is
already trusted or the run allows all paths/tools. User hooks remain the
certification driver's default.

## Hook process contract

Version-1 command entries select exactly one of `bash`, `powershell`, or
`command`. On direct Windows, DefenseClaw writes only `powershell`. Copilot
starts the hook locally in the same shell context and sends one event object as
JSON on stdin. The official PowerShell tutorial consumes it with
`[Console]::In.ReadToEnd() | ConvertFrom-Json`.

Decision hooks are synchronous: stdout is processed after the command exits.
Progress JSON lines may precede the one final decision object. DefenseClaw's
PowerShell command starts its no-console launcher with inherited standard
handles, `-NoNewWindow -Wait -PassThru`, and exits with the launcher's exact
exit code. It never nests Bash, WSL, or another PowerShell process inside
Copilot's own `powershell` boundary.

The current documented events are `sessionStart`, `sessionEnd`,
`userPromptSubmitted`, `userPromptTransformed`, `preToolUse`, `postToolUse`,
`postToolUseFailure`, `permissionRequest`, `agentStop`, `subagentStart`,
`subagentStop`, `errorOccurred`, `preCompact`, and `notification`.
DefenseClaw's `copilot-hooks-v2` contract registers that exact 14-event matrix
for reviewed versions `>=1.0.76`; the bounded `copilot-hooks-v1` contract
retains the earlier 13-event matrix for `>=1.0.18, <1.0.76`.
Setup binds each registration to its exact event name and passes that trusted
identity out-of-band to the authenticated gateway while preserving the
official JSON body. Missing, unknown, wrong-case, or out-of-contract identities
are rejected rather than inferred from body fields. Local, authentication,
transport, timeout, and malformed-response failures always return empty stdout
and exit 0; an inherited closed/strict setting cannot manufacture a Copilot
deny.
`userPromptTransformed` is mutation-only, so DefenseClaw observes its
`transformedPrompt` but returns no modification. `notification` is explicitly
asynchronous and fire-and-forget upstream; the other registered command hooks
are synchronously awaited under the event-specific output and exit rules.

Exit behavior is event-specific:

- exit 0 processes the final JSON decision;
- exit 2 is a denial for `preToolUse` and `permissionRequest`, a warning for
  other events, and adds context for `postToolUseFailure`;
- other nonzero exits fail open except `preToolUse`, which fails closed; and
- timeouts fail open.

For decision JSON, `preToolUse` uses `allow`, `deny`, or `ask`;
`permissionRequest` uses `allow` or `deny`; and stop events use block/allow
behavior. Copilot loads hook configuration changes on its next CLI start.

## Telemetry boundary

Current upstream documentation says Copilot CLI can export OTel **traces and
metrics** when its documented `COPILOT_OTEL_ENABLED`,
`OTEL_EXPORTER_OTLP_ENDPOINT`, or `COPILOT_OTEL_FILE_EXPORTER_PATH` controls
enable monitoring. This is upstream capability evidence, not a DefenseClaw
integration claim.

The current DefenseClaw Copilot connector does not configure those variables,
does not place a gateway credential in Copilot's process environment, and does
not claim native OTLP custody or correlation. Its connector status and API
therefore expose hook-derived telemetry only. Implementing a native path later
requires a separate reviewed scoped-auth, signal-binding, content-capture,
rotation, repair, and exact-teardown contract.

## Known upstream Windows limitation

The 1.0.76 release notes state that sandbox denials for individual paths cannot
be enforced on Windows. DefenseClaw hook decisions still operate on their
documented surfaces, but documentation and certification evidence must not
claim that Copilot's Windows sandbox provides per-path filesystem enforcement.

## Live evidence still required

Before recording validated-version or live evidence, the later Windows
verification phase must run the packaged deterministic contract and a real
official 1.0.77 or newer client with an entitled credential. It must prove
user-scope setup,
restart/reconciliation, allow/ask/block/failure behavior, stdin/stdout/exit
propagation, audit and protected-runtime evidence, tamper repair, exact
restoration, and teardown without WSL or a Unix shell.

The prepared native driver is
`scripts/live-connector-e2e/run-windows.ps1 -Connector copilot`. Its live layer
uses the official `@github/copilot` Windows package (or an explicitly pinned
official client for release validation), `copilot --version`, the documented
headless `copilot -p` surface, and the official token precedence. Its setup
transitions use the same transaction-shaped and explicitly home-bound
maintenance command as ordinary native Setup. The driver is not certification
evidence until that later run completes
successfully.
