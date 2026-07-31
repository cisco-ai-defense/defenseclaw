# Native Windows connector reference checklist

This checklist captures the evidence and coverage required before a connector
can claim native Windows support. It is intentionally stricter than a generic
Windows compatibility claim: the vendor client, DefenseClaw setup, every hook,
and all validation must run directly from PowerShell or `cmd.exe` with native
Windows paths and native executables or PowerShell. WSL, Docker, virtual
machines, Bash, Git Bash, Cygwin, and MSYS are not qualifying evidence.

## OpenAI Codex reference evidence

Evidence was rechecked on 2026-07-30.

### Eligibility and installation

- Decision: eligible for native Windows implementation.
- Official CLI install reference:
  <https://learn.chatgpt.com/docs/codex/cli>
- Official native Windows reference:
  <https://learn.chatgpt.com/docs/windows/windows-sandbox>
- Native standalone install or update from PowerShell:
  `powershell -ExecutionPolicy ByPass -c "irm https://chatgpt.com/codex/install.ps1 | iex"`
- Official npm alternative: `npm install -g @openai/codex`.
- Default standalone binary directory:
  `%LOCALAPPDATA%\Programs\OpenAI\Codex\bin`. The installer supports
  `CODEX_INSTALL_DIR`; its package cache is below
  `%USERPROFILE%\.codex\packages\standalone` unless `CODEX_HOME` is set.
- Windows 11 is recommended. Fully updated Windows 10 is best effort and
  version 1809 or newer is required for ConPTY. The elevated sandbox needs an
  administrator-approved setup and can be blocked by enterprise policy; the
  unelevated sandbox is a weaker fallback.
- Native Windows application announcement: 2026-03-04,
  <https://learn.chatgpt.com/docs/changelog#codex-2026-03-04-app>.
- Hook GA announcement: 2026-05-13/14,
  <https://learn.chatgpt.com/docs/changelog#codex-2026-05-13-app>.
- Reviewed official releases:
  [`0.144.0`, published 2026-07-09](https://github.com/openai/codex/releases/tag/rust-v0.144.0),
  [`0.145.0`, published 2026-07-21](https://github.com/openai/codex/releases/tag/rust-v0.145.0),
  and
  [`0.146.0`, published 2026-07-29](https://github.com/openai/codex/releases/tag/rust-v0.146.0).
  Each release publishes native Windows MSVC artifacts.

### Native paths and configuration

- Default `CODEX_HOME`: `%USERPROFILE%\.codex`.
- User configuration: `%CODEX_HOME%\config.toml`.
- Managed configuration on Windows:
  `%CODEX_HOME%\managed_config.toml`.
- Machine requirements:
  `%ProgramData%\OpenAI\Codex\requirements.toml`.
- Project configuration: `<workspace>\.codex\config.toml`.
- MCP servers use `[mcp_servers.<name>]` in `$CODEX_HOME/config.toml` and
  trusted project `.codex/config.toml` layers. Candidate project layers run
  from repository root to the active directory, with the closest layer taking
  precedence; Codex does not use Claude Code's `.mcp.json` convention.
- Skills load from `.agents\skills` at candidate project layers and
  `%USERPROFILE%\.agents\skills`; `CODEX_HOME` does not redirect the personal
  skill directory.
- Custom agents and rules load from `.codex\agents\*.toml` and
  `.codex\rules\*.rules` beside candidate project configs, followed by
  `%CODEX_HOME%\agents` and `%CODEX_HOME%\rules`. Project assets require a
  trusted project; filesystem presence alone does not prove activation.
- Plugin marketplace precedence is repository
  `.agents\plugins\marketplace.json`, legacy-compatible repository
  `.claude-plugin\marketplace.json`, then personal
  `%USERPROFILE%\.agents\plugins\marketplace.json`. Local `source.path`
  entries are exact roots relative to the marketplace root, and each plugin's
  official manifest is `.codex-plugin\plugin.json`. Git, URL, and npm sources
  have no stable source path in the public Codex CLI contract. Preview
  inventory may inspect installed copies actually observed below
  `%CODEX_HOME%\plugins\cache`, but that hierarchy is implementation evidence,
  not a promised stable CLI layout; there is no fixed repository plugin
  directory.
- Hook configuration can be declared in TOML at the active configuration
  layers. JSON hook files use `commandWindows`; TOML uses `command_windows`.
- DefenseClaw's native user setup writes the owned hook matrix to
  `%CODEX_HOME%\managed_config.toml`, and its marked OTel and `notify` fields to
  `%CODEX_HOME%\config.toml`.
- Official configuration references:
  <https://learn.chatgpt.com/docs/codex/config-reference> and
  <https://learn.chatgpt.com/docs/hooks>.
- Official asset references:
  [skills](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills),
  [MCP](https://learn.chatgpt.com/docs/extend/mcp#connect-codex-to-an-mcp-server),
  [custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents#custom-agents),
  [rules](https://learn.chatgpt.com/docs/agent-configuration/rules#create-a-rules-file),
  and [plugins](https://developers.openai.com/plugins/build/plugins).

### Versioned hook boundary

The official `0.144.0` generated schema directory contains ten DefenseClaw
events and no `SessionEnd`:
<https://github.com/openai/codex/tree/rust-v0.144.0/codex-rs/hooks/schema/generated>.

The official `0.145.0` generated schema adds
`session-end.command.input.schema.json`:
<https://github.com/openai/codex/blob/rust-v0.145.0/codex-rs/hooks/schema/generated/session-end.command.input.schema.json>.
The `0.145.0` release notes identify the corresponding SessionEnd teardown
change.

| Contract | Client range | Events |
| --- | --- | --- |
| `codex-hooks-v1` | `>=0.124.0, <0.129.0` | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Stop` |
| `codex-hooks-v2` | `>=0.129.0, <0.133.0` | v1 plus `PreCompact`, `PostCompact` |
| `codex-hooks-v3` | `>=0.133.0, <0.145.0` | v2 plus `SubagentStart`, `SubagentStop` |
| `codex-hooks-v4` | `>=0.145.0` | v3 plus `SessionEnd` |

The current official hook reference lists eleven events:
`SessionStart`, `SessionEnd`, `SubagentStart`, `PreToolUse`,
`PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`,
`UserPromptSubmit`, `SubagentStop`, and `Stop`.

### Execution and response contract

- Command hooks receive one JSON object on standard input.
- Command hooks are synchronous. The `async` setting is parsed but is not
  supported.
- Commands run with the session working directory.
- Default command timeout is 600 seconds. `SessionEnd` defaults to one second
  and is capped at three seconds.
- Exit 0 with no output continues normally.
- Exit 2 uses standard error as block, feedback, or continuation context only
  for events whose official response contract supports it.
- `PreToolUse` JSON output can deny. Native `ask` is parsed but unsupported.
  DefenseClaw therefore treats confirm as an alert/system message, not an
  approval dialog.
- `SessionEnd` is best-effort observation and telemetry. It is not a block or
  native ask surface.

The following matcher and continuation details are contract-supported only
for the v3/v4 boundary (`>=0.133.0`). This is not a release-certification
claim, and the details are not inferred or backfilled onto the legacy v1/v2
tiers:

- `SessionStart` `continue: false` ends the turn. Its matcher has the four
  official sources: `startup`, `resume`, `clear`, and `compact`.
- `SubagentStop` `decision: "block"` continues the subagent rather than
  terminating it.
- `PreCompact` `continue: false` stops before compaction; `PostCompact`
  `continue: false` stops only after compaction has completed.
- `Stop` `decision: "block"` prevents stopping and continues with its reason
  as a new prompt.
- `PostToolUse` `decision: "block"` cannot undo the completed side effect. It
  replaces the result fed to the next interactive loop; in code mode, the
  corresponding tool promise rejects.

### Official limitations that must stay visible

- The transcript format is unstable.
- Hosted tools and specialized execution paths may bypass the tool-hook path.
- Only command hook handlers run; prompt and agent handlers are not supported.
- Several documented fields, including `suppressOutput`, are parsed but not
  supported.
- The schema on the repository's main branch may be ahead of a release. Use
  tagged release schemas and the published hook reference for the versioned
  contract boundary; those sources alone are not release-certification
  evidence.

## Reusable connector coverage gate

Every Windows connector worker should record a pass, fail, or not-applicable
result for each item and link immutable or versioned evidence.

### Research and eligibility

- [ ] Read every applicable `AGENTS.md` before editing.
- [ ] Record official vendor URLs, release versions, publication dates, and
  native Windows artifacts.
- [ ] Prove direct PowerShell or `cmd.exe` installation and execution.
- [ ] Record minimum Windows version, architectures, prerequisites,
  administrator requirements, and enterprise-policy limitations.
- [ ] Stop implementation if native Windows or a required enforcement
  interface cannot be proven.

### Discovery and version contract

- [ ] Discover only native executables from trusted Windows prefixes; reject
  scripts, reparse escapes, and ambiguous command resolution.
- [ ] Capture the exact executable, raw version, normalized version, and
  resolved closed contract ID.
- [ ] Give every upstream event-set change a new bounded contract. Test both
  sides of every inclusive/exclusive boundary.
- [ ] Keep the packaged manifest, runtime contract, Doctor allowlists,
  fail-mode allowlists, correlation profile, and docs table in lockstep.

### Configuration and hook execution

- [ ] Use documented native user, project, managed, and machine paths, including
  vendor home-directory overrides.
- [ ] Render native Windows commands and Windows paths. Do not register a Unix
  fallback on Windows.
- [ ] Verify exact event, matcher, timeout, command, Windows override,
  synchronous behavior, standard input/output schema, and exit propagation.
- [ ] Prove observe, action, block, ask/fallback, fail-open, and fail-closed
  behavior only on vendor-supported response surfaces.
- [ ] Treat post-action and teardown events according to their real
  non-reversible or best-effort limitations.

### Security and evidence

- [ ] Protect hook runtime provenance, executable digest, configuration
  ancestry, ACLs, credentials, and contract-lock evidence.
- [ ] Bind each fixed registered event and versioned contract to the official
  stdin event at invocation time, carry both over the authenticated hook
  request, and reject any mismatch with the gateway's protected contract lock
  before policy evaluation or audit attribution.
- [ ] Authenticate hook and native telemetry rails with connector-scoped,
  least-privilege credentials.
- [ ] Reject or repair disabled, asynchronous, untrusted, duplicated, moved,
  tampered, or partial registrations.
- [ ] Inventory skills, MCP servers, plugins, rules, instructions, agents, and
  other vendor extension surfaces that exist for the connector. Document
  categories the vendor does not expose.
- [ ] Keep audit records and telemetry truthful about source, version, mode,
  verdict, enforcement timing, and correlation limitations.

### Lifecycle

- [ ] Setup is idempotent, reconciles upgrades and downgrades, preserves
  unrelated operator configuration, and verifies the persisted post-image.
- [ ] Repair and Doctor detect version drift, hook drift, tamper, trust loss,
  policy-precedence changes, and stale runtime evidence.
- [ ] Recovery is crash-safe and refuses unsafe path or ownership states.
- [ ] Teardown revokes credentials, removes only owned artifacts, preserves
  concurrent operator edits, and restores the exact pre-image when its
  comparison-and-swap evidence still matches.
- [ ] Uninstall and upgrade from every supported older contract are tested.

### Validation and release truth

- [ ] Add focused unit tests for contract resolution and generated native hook
  shape.
- [ ] Run packaged deterministic Windows CI for every certified architecture.
- [ ] Run a real official-client Windows E2E at each supported contract
  boundary, including synchronous wait and exit-code propagation.
- [ ] Exercise setup, repair, Doctor, tamper, drift, recovery, teardown,
  uninstall, and exact restoration in the packaged build.
- [ ] Verify gateway authentication, protected runtime evidence, OTel/audit
  records, and every supported enforcement mode.
- [ ] Update the platform matrix only after the release workflow records
  reproducible certification evidence; do not infer certification from unit
  tests or local source runs.
