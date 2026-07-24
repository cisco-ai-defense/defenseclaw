# Cursor hook: emit an explicit allow on every fail-open path

## Summary

The Cursor connector installs `cursor-hook.sh` into `~/.cursor/hooks.json`.
Cursor treats a `failClosed: true` hook that produces **empty stdout** as a hook
failure and blocks the operation.

The original v6 hook had several fail-**open** paths that exited `0` with no
stdout. The most dangerous was the early `.disabled` path: a user could disable
DefenseClaw while a previously written `failClosed: true` entry remained in
`hooks.json`, and Cursor would reinterpret the silent allow as a failure. Since
the hook is wired onto `preToolUse` / `beforeShellExecution` /
`beforeReadFile`, that could block every tool at once and prevent the agent from
self-recovering.

Current `main` has since made failure-mode handling consistent and emits
`{"continue":true}` on its allow paths. This reconciled change retains those
semantics and strengthens the invariant by using one explicit
`{"continue":true,"permission":"allow"}` envelope everywhere the shell hook
allows.

This change makes `cursor-hook.sh` emit an explicit allow envelope
(`{"continue":true,"permission":"allow"}`) on every allow / observe / fail-open
path, so a fail-open can never be read as a fail-closed block. Block paths keep
emitting an explicit deny, and strict-availability installs still fail closed.

## Scope

This affects only the Cursor shell hook. It does not change the selected failure
mode:

- `FAIL_MODE=open` transport, response, token, and oversized-input failures
  continue to allow.
- `FAIL_MODE=closed`, managed hooks, and
  `DEFENSECLAW_STRICT_AVAILABILITY=1` continue to block availability failures
  with an explicit deny and the existing exit status.
- The `.disabled` / absent-install path remains an unconditional allow, which is
  the recovery path that must work even when an older `failClosed: true`
  declaration is still present.

The gateway already returns a concrete Cursor envelope on the normal response
path. This change makes the shell layer follow the same "never rely on empty
stdout for an allow" invariant.

## Root cause

Cursor's documented behavior: a hook entry marked `failClosed: true` that
returns no output is treated as a failure, and the gated operation is blocked.

On the original PR base, these branches in `cursor-hook.sh` fell through to a
bare `exit 0` with no stdout:

- the `.disabled` marker / absent-install early exit (non-managed installs)
- the missing-token branch in open mode
- `fail_unreachable` on the fail-open (non-strict) path
- `fail_response` when `FAIL_MODE=open`
- the oversized-payload guard on the fail-open path
- the success path when the gateway answered with no `hook_output`

Newer `main` already replaced those silent exits with `{"continue":true}` and
made closed, managed, and strict availability paths block consistently. The
remaining change is to centralize the richer allow envelope without regressing
those newer deny paths.

## The fix

All changes are contained in `internal/gateway/connector/hooks/cursor-hook.sh`
(Cursor only). No shared helper and no other connector is touched, so the blast
radius is limited to Cursor.

- A small `emit_cursor_allow` helper is defined before the early disabled check
  and prints the allow envelope.
- Every fail-open path above now emits that envelope before `exit 0`.
- The missing-token branch in open mode logs, warns, and emits an explicit
  allow.
- Closed, managed, and strict availability paths retain current `main`'s
  `{"continue":false,"permission":"deny",...}` envelopes and exit behavior.

Relative to current `main`, exit codes and block semantics are unchanged. The
behavioral difference is that every shell-generated allow now also carries
`"permission":"allow"`.

## Tests

`internal/gateway/connector/cursor_hook_failopen_test.go` renders the real hook
template and runs it under `bash`:

- `TestCursorHook_FailOpenOnUnreachableEmitsAllow` — unreachable gateway,
  open mode: exit `0` with an explicit allow.
- `TestCursorHook_FailClosedOnUnreachableEmitsDeny` — closed mode: exit `2`
  with current `main`'s explicit `continue:false` deny.
- `TestCursorHook_DisabledMarkerEmitsAllow` — `.disabled` present: exit `0`
  with an explicit allow.
- `TestCursorHook_MissingTokenFailsOpenWithAllow` — no token, open mode:
  exit `0` with an explicit allow and an "allowing cursor tool" stderr line.
- `TestCursorHook_StrictMissingTokenBlocks` — `DEFENSECLAW_STRICT_AVAILABILITY=1`:
  exits `2` with an explicit deny even when `FAIL_MODE=open`.

`internal/gateway/connector/cursor_hook_invariant_test.go` runs the real hook
against a stub gateway to lock the invariant so this can never regress:

- `TestCursorHook_ObserveEmptyHookOutputEmitsAllow` — gateway answers `200`
  with no `hook_output` (the exact original observe-mode lockout trigger): the
  hook emits an explicit allow.
- `TestCursorHook_GatewayAllowEnvelopePassedThrough` /
  `TestCursorHook_GatewayDenyEnvelopePassedThrough` — real allow/deny verdicts
  reach Cursor verbatim (the hardening does not swallow decisions).
- `TestCursorHook_NeverEmptyStdout` — table across observe-empty, null
  `hook_output`, `5xx`, unreachable, and a payload larger than 1 MiB: every
  fail-open case exits `0` with a valid, non-empty permission object.
- `TestCursorHooks_ObserveModeWritesFailClosedFalse` — a default / observe
  install writes `failClosed:false` (pairs with the existing
  `TestCursorHooks_FailClosedOnlyWhenExplicit`).

The focused Cursor connector-hook tests pass with Go 1.26.4.

## Preventing recurrence

Two defenses in this change stop the class of bug, not just the instances:

- The hook can no longer exit with empty stdout on any allow / fail-open path
  (the runtime fix).
- `TestCursorHook_NeverEmptyStdout` runs the real hook end to end, so any
  future edit that reintroduces a silent `exit 0` fails CI.

Two follow-ups are outside the scope of this connector change but are the rest
of the story for "no user hits this again", and are called out here for the
maintainers:

1. Ship the fix in a release and bump the pinned `VERSION` in the README /
   install script. Users install releases, not `main`; a `main`-only fix does
   not protect anyone until it ships.
2. Add a `doctor` heal that detects an already-installed Cursor `hooks.json`
   wired `failClosed:true` against a hook script predating this fix, warns, and
   offers to re-run setup (which rewrites the managed hook). This protects users
   who installed an affected build before upgrading.

This change is intentionally Cursor-scoped, matching the connector where the
lockout was observed. Other connectors that advertise `SupportsFailClosed`
(geminicli, openhands, codex, claudecode) are worth a separate audit for the
same empty-stdout-on-fail-open pattern, but each agent's empty-output semantics
differ and should be verified individually rather than changed blind.

## Why this helps

An open-mode Cursor install no longer depends on Cursor's empty-output fallback,
and an intentional `.disabled` remains a reliable recovery path even if an old
`failClosed: true` declaration is still present. Operators who deliberately
select closed, managed, or strict availability behavior still receive an
explicit deny on gateway or token failures.
