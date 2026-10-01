# DeepSeek Harness connector evidence

This preview integrates the DeepSeek Harness CLI (`dsh`), independently of
DefenseClaw's DeepSeek model provider. The source-reviewed contract is
`deepseek-hooks-v1`, pinned to vendor version `0.2.0-rc.2` and revision
`639ed015397290b3745d163aafe02ffee4aa3f84`.

## Vendor evidence

- [Shipped command-hook bridge](https://github.com/deepseek-ai/deepseek-harness/blob/639ed015397290b3745d163aafe02ffee4aa3f84/packages/hooks/hooks-claude-code/src/index.ts)
- [Hook transport and error handling](https://github.com/deepseek-ai/deepseek-harness/blob/639ed015397290b3745d163aafe02ffee4aa3f84/packages/hooks/hook-protocol/src/runner.ts)
- [Tool execution pipeline](https://github.com/deepseek-ai/deepseek-harness/blob/639ed015397290b3745d163aafe02ffee4aa3f84/docs/tool-execution-pipeline.md)

The route uses the shipped `@deepseek-ai/dsh-hooks-claude-code` Cordis plugin,
not a new third-party plugin. It adds an owned insertion to the user-level
`$DSH_HOME/cordis.patch.yml` (default `~/.dsh`) and points it to the dedicated
`defenseclaw-hooks.json`. Config and user hooks are preserved through repeat
setup and teardown. A later profile or CLI overlay can disable the bridge;
registration on disk is not proof a running session loaded it. Restart `dsh`
after setup and teardown. Profiles need the plugin and its shell/session
projection services. `dsh --version` supplies version evidence.

The actual bridge supplies `hook_event_name`, `session_id`, `cwd`, an empty
`transcript_path`, and for tools `tool_name`, `tool_input`, `tool_use_id`.
`bash` uses the `command` argument. The integration registers SessionStart,
UserPromptSubmit, PreToolUse, PostToolUse, Stop, SubagentStart and SubagentStop.
PreToolUse consumes Claude-compatible `hookSpecificOutput.permissionDecision`
with `deny` or `ask`; UserPromptSubmit accepts top-level `decision: block`.
Stop and result callbacks are observational. PostToolUse flattens output text
and does not carry `isError`, so it cannot prove successful tool state changes.

## Verification

The ordinary Go tests cover configuration round trips, repeated setup with
operator edits, mixed foreign handlers, invalid/duplicate/disabled Cordis
registrations, symlink rejection, and backup path binding. Gateway full-chain
tests include DeepSeek's `bash` payload, and the lifecycle/golden matrix includes
this connector. Python checks cover taxonomy, discovery paths, schemas,
readiness, unsupported MCP writes and effective fail-open reporting.

For the optional vendor test, install exactly
`@deepseek-ai/dsh-hooks-claude-code@0.2.0-rc.2` in an isolated temporary npm prefix
with `--ignore-scripts --no-audit --no-fund`. Point `DEEPSEEK_BRIDGE_MODULE` at its
`lib/index.js` and run:

```bash
go test ./internal/gateway/connector -run TestDeepSeekPublishedBridge -v
```

The test checks package identity/version, invokes the published bridge's real
callbacks against a local shell/session fixture, executes the rendered hook,
and verifies allow, deny, ask, prompt block, correlation, observational results
and non-looping Stop. It uses a local test HTTP server and random test-scoped
credentials; it does not invoke a model or install a user gateway.

This is executable bridge evidence, not live end-to-end OS certification.
macOS/Linux remain preview and `validated_versions.json` is unchanged.
Windows transport, managed enterprise, ACP, native OTLP, OpenShell sandbox,
and profile-dependent MCP/skills/plugins/rules/agents are explicitly unsupported
or unclaimed. The vendor allows execution after configuration errors, hook
crashes or timeouts; fail-closed enforcement is not claimed.
