# Native Windows CI certification

The `Windows Native CI` workflow is DefenseClaw's deterministic native Windows
x64 merge gate. It runs on pull requests, pushes to `main`, and manual dispatches
without provider secrets, WSL, MSYS, or Git Bash.

Repository branch protection must require the exact aggregate check name
`Windows Native Required`. Requiring individual matrix cell names is not a
substitute: the aggregate explicitly fails when any required job is failed,
cancelled, or skipped.

The gate certifies:

- the full Go suite plus `go vet` and native gateway/hook builds;
- every Python test, including the headless Textual TUI suite;
- PowerShell parsing, timeout/process-tree cleanup, redaction, and workflow
  contracts;
- a release-shaped Windows x64 gateway zip and Python wheel;
- a fresh install whose profile, application data, caches, connector homes,
  temp directories, DefenseClaw home, and PATH are disposable;
- an explicit `uv pip check`, managed-venv import provenance, installed CLI,
  doctor, skill/MCP scanner, and bounded headless-TUI smoke checks;
- gateway start/status/restart/stop behavior, stopped-status nonzero exit,
  reset idempotency, full uninstall, packaged reinstall, and cleanup; and
- required PowerShell contract cells for Codex and Claude Code covering setup,
  observe/action allow/block behavior, audit correlation, telemetry, bounded
  timeout handling, teardown, and cleanup.

The packaged artifact is built once and reused by the install/lifecycle and
connector jobs. Failure diagnostics are bounded, secret-redacted, retained for
five days, and followed by an unconditional isolated-process/listener/temp
cleanup step.

Real upstream Codex and Claude Code tests stay in `Connector Live E2E`. Those
jobs require provider credentials and remain `workflow_dispatch`-only; they are
an alerting/regression radar and must not be configured as a pull-request merge
gate, especially for fork pull requests.
