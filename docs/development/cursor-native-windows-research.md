# Cursor native Windows research gate

Last verified: 2026-07-30

Decision: eligible for a native Windows x64 DefenseClaw connector. Cursor
publishes both a native Windows Agent installation and native desktop
installers, and its command-hook interface provides synchronous pre-action
decisions over JSON stdin/stdout with an exit-code block signal. No WSL,
container, VM, Bash, Git Bash, Cygwin, or MSYS component is required by the
DefenseClaw path.

## Official sources and versions

- [Cursor CLI installation](https://cursor.com/docs/cli/installation) — the
  current Windows-native install command is
  `irm 'https://cursor.com/install?win32=true' | iex`. The same page documents
  `agent --version`, `agent`, and `agent update`. Its separate
  macOS/Linux/Windows-WSL command does not replace the native Windows method.
- [Cursor native Windows installer](https://cursor.com/install?win32=true) —
  inspected as plain PowerShell on 2026-07-30. It identifies build
  `2026.07.23-e383d2b`, downloads the x64 or ARM64
  `agent-cli-package.zip`, installs versioned files beneath
  `%LOCALAPPDATA%\cursor-agent\versions`, copies the native `cursor-agent`
  launchers to `%LOCALAPPDATA%\cursor-agent`, creates available
  `agent.exe`/`agent.cmd`/`agent.ps1` aliases, and adds only that product root
  to the user and current-process `PATH`.
- [Cursor downloads](https://cursor.com/download) — on 2026-07-30 the page
  identified desktop release `3.13` and offered native Windows x64 and ARM64
  system and user installers. DefenseClaw's present Windows certification
  remains x64; an upstream ARM64 download is not a DefenseClaw ARM64
  certification.
- [Cursor 1.7 changelog](https://cursor.com/changelog/1-7) — dated
  2025-09-29. This release introduced beta hooks and states that Windows Agent
  commands use PowerShell. It does not identify the event inventory present in
  that release.
- [Cursor 2.4 changelog](https://cursor.com/changelog/2-4) — dated 2026-01-22.
  It explicitly records improved or added coverage for `stop`,
  `beforeSubmitPrompt`, `preToolUse`, and `postToolUse`, plus broader CLI hook
  coverage. This contradicts treating the current 21-event reference as a
  proven Cursor 1.7 contract.
- [Cursor CLI changelog](https://cursor.com/docs/cli/changelog) — the newest
  entry visible during verification was dated 2026-07-20. The changelog
  records native Windows reliability/update fixes and stdin hook payload
  support. The 2026-01-08 entry makes `agent` the primary CLI command while
  retaining `cursor-agent` as a compatibility alias.
- [Cursor hooks reference](https://cursor.com/docs/hooks) — current schema,
  event, I/O, configuration, failure, reload, and cloud-support contract.
- [Cursor plugins](https://cursor.com/docs/plugins) — local plugins are
  discovered under `~/.cursor/plugins/local/<plugin>` and carry a root
  `.cursor-plugin/plugin.json` manifest.
- [Cursor subagents](https://cursor.com/docs/subagents) — project subagents
  are stored under `<project>/.cursor/agents`; user subagents are stored under
  `~/.cursor/agents` and apply to all projects.

Local observation is not used as upstream proof: the workstation used for this
review had Cursor desktop `3.9.16` at
`%LOCALAPPDATA%\Programs\cursor\resources\app\bin\cursor.cmd`; the separate
native `agent` command was not installed.

## Install and configuration contract

- Primary native CLI executable: `agent`; compatibility alias:
  `cursor-agent`. Desktop discovery also recognizes `cursor`.
- The official native CLI root is `%LOCALAPPDATA%\cursor-agent`. DefenseClaw
  resolves it from the current Windows token's LocalAppData Known Folder,
  admits only that narrow product directory, and still applies its executable
  and ancestor ownership/DACL checks before running `agent --version`.
- User hook file: `%USERPROFILE%\.cursor\hooks.json`
  (`~/.cursor/hooks.json` in Cursor's portable notation).
- Project hook file: `<project>\.cursor\hooks.json`.
- Windows enterprise hook file: `C:\ProgramData\Cursor\hooks.json`.
- Precedence: enterprise, team, project, user. Relative project commands run
  from the project root; relative user and enterprise commands run from their
  respective configuration directories.
- Hook configuration is schema version `1`. Per-command fields include
  `type: "command"`, `command`, `timeout` in **seconds**, and `failClosed`.
  Cursor automatically reloads configuration changes; if a change is not
  loaded, the documented recovery is to restart Cursor.

Because Cursor does not publish per-event introduction versions, DefenseClaw
does not invent version tiers for the 21-event surface. The supported contract is
pinned only to Cursor Agent build `2026.07.23-e383d2b`, the exact date-hash
published by the official native Windows installer inspected on 2026-07-30.
The separate Cursor Desktop `3.13` release remains desktop discovery evidence,
not an Agent CLI compatibility version. Every other Agent build requires a
refreshed official-source review and focused client validation.

DefenseClaw writes the user hook file, uses a 30-second host timeout, and on
native Windows registers a PowerShell command that waits synchronously for the
native `defenseclaw-hook.exe` verdict. Setup/repair replaces only
DefenseClaw-owned entries and preserves foreign entries. Teardown restores the
captured file byte-for-byte when unchanged, otherwise removes only managed
entries. It then removes its owned Cursor scripts. It does not claim or depend
on an undocumented cached Cursor hook process/path.

Cursor's local plugin and subagent directories are read-only inventory
surfaces. DefenseClaw recognizes `.cursor-plugin/plugin.json` under the
official local plugin root and user/project Markdown subagents, but Setup,
repair, teardown, and the plugin installer do not create, remove, or claim
custody of those vendor-owned assets.

## Synchronous I/O and enforcement

Cursor starts command hooks as spawned processes, writes one JSON document to
stdin, and reads one JSON document from stdout:

- exit `0`: hook succeeded and Cursor uses the JSON response;
- exit `2`: permission denied/block;
- other failures, crashes, timeouts, and invalid JSON: fail open by default;
- `failClosed: true`: those hook failures block instead.

DefenseClaw preserves the vendor default with `failClosed: false`. An explicit
action-mode closed failure setting writes `failClosed: true` and renders the
Windows adapter itself fail-closed, so an adapter/launcher failure returns a
deny object and exit `2`.

The current blocking/decision surfaces used by DefenseClaw are:

- `preToolUse`: `allow`/`deny`;
- `subagentStart`: `allow`/`deny`; `ask` is unsupported and DefenseClaw never
  emits it;
- `beforeShellExecution` and `beforeMCPExecution`:
  `allow`/`deny`/`ask`;
- `beforeReadFile` and `beforeTabFileRead`: `allow`/`deny`;
- `beforeSubmitPrompt`: `continue: false` blocks prompt submission.

`stop` and `subagentStop` are not permission gates; their only documented
response is `followup_message`. `sessionStart` and `sessionEnd` are described
as fire-and-forget for policy enforcement: Cursor does not enforce a blocking
response. The same reference documents `env`/`additional_context` output for
`sessionStart`, while `sessionEnd` has no output fields.

## Event inventory and limitations

The installed contract observes the current documented events:
`sessionStart`, `sessionEnd`, `preToolUse`, `postToolUse`,
`postToolUseFailure`, `subagentStart`, `subagentStop`,
`beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`,
`afterMCPExecution`, `beforeReadFile`, `afterFileEdit`,
`beforeTabFileRead`, `afterTabFileEdit`, `beforeSubmitPrompt`, `preCompact`,
`stop`, `afterAgentResponse`, `afterAgentThought`, and `workspaceOpen`.

Important limitations:

- Ask is enforceable only for shell and MCP pre-execution events.
- `beforeSubmitPrompt` uses `continue`; permission events use only their
  documented per-event `permission` and message fields. `postToolUse` accepts
  `updated_mcp_tool_output`/`additional_context`, `preCompact` accepts
  `user_message`, `workspaceOpen` accepts `pluginPaths`, and events documented
  without output fields receive `{}`. DefenseClaw does not invent output fields
  or plugin paths it does not own.
- Post-action and fire-and-forget events provide observation, audit, and
  telemetry, not retroactive enforcement.
- User hooks are unavailable in Cursor cloud agents; cloud support is limited
  to command hooks and not every IDE event is available there. DefenseClaw's
  certification in this document is the local native Windows path.
- Cursor documents spawned hook processes and configuration reload. It does
  not document a persistent/cached hook-process lifecycle, so DefenseClaw does
  not invent one for repair or teardown.
