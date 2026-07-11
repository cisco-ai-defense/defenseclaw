# Cursor hook: emit an explicit allow on every fail-open path

## Summary

The Cursor connector installs `cursor-hook.sh` into `~/.cursor/hooks.json`. When
an operator chooses a fail-closed install, those entries are written with
`"failClosed": true`. Cursor treats a `failClosed: true` hook that produces
**empty stdout** as a hook failure and blocks the operation.

Several fail-**open** paths in `cursor-hook.sh` exited `0` with no stdout. On a
fail-closed install that silent exit was misread by Cursor as a fail-closed
"no output" failure, so a deliberate fail-open (a gateway outage, a missing
token, or a disabled install) was silently inverted into a block. Because the
hook is wired onto `preToolUse` / `beforeShellExecution` / `beforeReadFile`,
that block hit every tool at once, and the agent could not self-recover.

This change makes `cursor-hook.sh` emit an explicit allow envelope
(`{"continue":true,"permission":"allow"}`) on every allow / observe / fail-open
path, so a fail-open can never be read as a fail-closed block. Block paths keep
emitting an explicit deny, and strict-availability installs still fail closed.

## Scope

This affects only fail-closed Cursor installs (`failClosed: true` in
`hooks.json`, which requires an explicit fail-closed opt-in at setup).

Observe-mode and default installs already write `failClosed: false`, and the
gateway already returns a concrete allow envelope for Cursor on the normal
response path, so those installs were never at risk. This is a hardening of the
transport and disabled paths for the fail-closed case, and it lines up the
shell with the same "never emit empty stdout for Cursor" invariant the gateway
already enforces on its side.

## Root cause

Cursor's documented behavior: a hook entry marked `failClosed: true` that
returns no output is treated as a failure, and the gated operation is blocked.

Before this change, these branches in `cursor-hook.sh` fell through to a bare
`exit 0` with no stdout:

- the `.disabled` marker / absent-install early exit (non-managed installs)
- the missing-token branch (non-strict), via the shared
  `defenseclaw_handle_missing_token`
- `fail_unreachable` on the fail-open (non-strict) path
- `fail_response` when `FAIL_MODE=open`
- the oversized-payload guard on the fail-open path
- the success path when the gateway answered with no `hook_output`

On a fail-closed install each of these turned into a block, contradicting the
project's own stated contract that "a DefenseClaw outage must NEVER brick the
user's coding agent" (see `_hardening.sh`).

## The fix

All changes are contained in `internal/gateway/connector/hooks/cursor-hook.sh`
(Cursor only). No shared helper and no other connector is touched, so the blast
radius is limited to Cursor.

- A small `emit_cursor_allow` helper prints the allow envelope.
- Every fail-open path above now emits that envelope before `exit 0`.
- The missing-token branch keeps the shared helper for the strict / managed
  fail-closed case (it logs, warns on stderr, and exits `2`), and on the
  fail-open case it logs, warns, and emits an explicit allow.
- Block decisions still emit an explicit deny; strict-availability installs
  still exit `2` and block.

Exit codes are unchanged on every path. The only behavioral difference is that
paths which previously produced empty stdout now produce an explicit allow (or
deny) object. On a fail-open (`failClosed:false`) install this is a no-op,
because Cursor allowed regardless. On a fail-closed install it restores the
intended allow instead of an accidental block.

## Tests

`internal/gateway/connector/cursor_hook_failopen_test.go` renders the real
hook template with `FAIL_MODE=closed` and runs it under `bash`:

- `TestCursorHook_FailOpenOnUnreachableEmitsAllow` — unreachable gateway,
  non-strict: exit `0` with an explicit allow.
- `TestCursorHook_DisabledMarkerEmitsAllow` — `.disabled` present: exit `0`
  with an explicit allow.
- `TestCursorHook_MissingTokenFailsOpenWithAllow` — no token, non-strict:
  exit `0` with an explicit allow and an "allowing cursor tool" stderr line.
- `TestCursorHook_StrictMissingTokenBlocks` — `DEFENSECLAW_STRICT_AVAILABILITY=1`:
  still exits `2` and blocks (the fail-closed contract is preserved).

`internal/gateway/connector/cursor_hook_invariant_test.go` runs the real hook
against a stub gateway to lock the invariant so this can never regress:

- `TestCursorHook_ObserveEmptyHookOutputEmitsAllow` — gateway answers `200`
  with no `hook_output` (the exact original observe-mode lockout trigger): the
  hook emits an explicit allow.
- `TestCursorHook_GatewayAllowEnvelopePassedThrough` /
  `TestCursorHook_GatewayDenyEnvelopePassedThrough` — real allow/deny verdicts
  reach Cursor verbatim (the hardening does not swallow decisions).
- `TestCursorHook_NeverEmptyStdout` — table across observe-empty, null
  `hook_output`, `5xx`, and unreachable: stdout is always a valid, non-empty
  permission object.
- `TestCursorHooks_ObserveModeWritesFailClosedFalse` — a default / observe
  install writes `failClosed:false` (pairs with the existing
  `TestCursorHooks_FailClosedOnlyWhenExplicit`).

The full `internal/gateway/connector` and `internal/gateway` suites pass with
the change (Go 1.26.4).

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

Any operator who runs Cursor in a fail-closed configuration is protected from
being locked out by a gateway restart, a token rotation, or an intentional
`.disabled`. The transport and disabled paths now behave the way the code
already documents them, and the shell layer matches the gateway's existing
guarantee that a Cursor response is never empty stdout.
