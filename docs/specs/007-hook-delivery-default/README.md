# Spec 007 — Fail-open hook delivery default

## Requirements

- Unset hook delivery policy defaults to `open` in the Go and Python loaders,
  schema, setup flows and generated hook runtimes, including action mode.
- Explicit `closed` remains supported. Invalid non-empty policy remains closed
  rather than being treated as an availability opt-in.
- Managed macOS and Windows hooks honor their installer-owned delivery policy
  instead of forcing closed solely because they are managed.
- Valid policy denials, runtime integrity, target authorization and protected
  credential custody are not weakened. Strict availability remains a closed
  override.
- Existing explicit settings are preserved; no local deployment or build is
  modified. Speculative provisioning without agent presence remains out of scope.
- Unknown or incompatible agent versions use the best-effort event union and
  open delivery on both platforms, while protected Windows readers, enrollment
  and authenticated runtime generations retain their integrity checks.
- Both changes ship on the existing branch and PR. Diagnose failing CI and fix
  code-related failures; report infrastructure failures separately.
- Inspection failures that allow delivery emit an explicit fail-open warning
  and an `outcome: fail_open` in the existing local hook failure JSONL log.
  Record actual delivery outcomes separately from configured fail mode so
  strict/managed overrides are not mislabeled. Never include payloads or tokens;
  diagnostic writes must not change hook decisions.
- Cursor's protected machine adapter must preserve each enrolled SID's effective
  delivery mode. Adding, refreshing, removing or deferring one user must not
  change another user's launcher-failure behavior. Verification must compare
  the target's adapter mode with its authenticated runtime policy.

## Design / decision

Separate availability from enforcement. Missing policy means open; malformed
policy means closed; action mode does not implicitly request closed delivery.
Remove the shell managed-hook availability override, retaining managed identity
and protected-state validation. Do not migrate explicit closed installations.

The native Windows hook executor can continue honoring its configured delivery
mode without relaxing enrollment, peer authentication or tamper validation.
Carry the effective mode in the authenticated Windows runtime bundle and verify
it against protected installation state. Never accept project or environment
overrides that weaken an explicitly closed managed runtime.

Cursor embeds a canonical, token-free SID-to-mode map in the protected adapter
and ownership state. The current Windows process SID selects launcher-error and
timeout behavior; absent/unrecognized identity remains closed. Its machine-wide
`failClosed` flag is conservative (closed if any enrolled SID is closed), while
the adapter emits explicit allow/deny responses for each resolved SID. Failure
to start the PowerShell host itself cannot select a SID and follows that shared
flag. Legacy single-mode adapters remain valid until authorized reconciliation.
Deferred staging uses configured policy (open when unset), applying version
fallback without overwriting peer modes. Target revocation updates the map and
adapter transactionally, with the existing protected rollback checks.

Codex, Claude Code and Cursor shell delivery failures and the shared native
executor emit `WARNING hook fail-open; inspection bypassed` on stderr only when
the failure permits delivery. Reuse `<runtime-home>/logs/hook-failures.jsonl`
(`$DEFENSECLAW_HOME/logs/hook-failures.jsonl` for shell hooks), retaining timestamp,
connector, hook, reason, category and configured `fail_mode`, and adding actual
`outcome` (`fail_open` or `fail_closed`). An open mode plus strict transport
availability therefore records `fail_closed`, not a bypass. Legacy shell
diagnostic-only records use `unknown`: invalid trace metadata is not evidence
that inspection was skipped. Logging is best-effort and content-free; the
stderr warning remains available when the local log cannot be written.

## Plan

Epic HD-DEFAULT: align hook availability defaults without weakening policy.

- HD-01 [done]: align Go/Python defaults, configuration schema and render selection.
- HD-02 [done]: repair managed macOS delivery behavior and add executable regressions.
- HD-03 [implemented; native execution pending]: carry fallback contracts and delivery policy through Windows managed
  installation, registration, verification and native execution.
- HD-04 [done; environment limitations noted]: verify packages, diagnose CI and
  update guidance and branch context.
- HD-05 [done]: create a fresh Apple Silicon managed macOS bundle for
  local testing, link the real ai-common CMID provider and verify the package
  without running its installer.
- HD-06 [done]: remove the added root CONTEXT.md at the user's request;
  add content-free fail-open diagnostics and regression tests for macOS shell
  and shared native Windows execution. Keep work notes in this spec instead.
- HD-07 [done]: address CodeRabbit's remaining schema embedding assertion
  and Windows test-comment drift. Both must describe the existing open default;
  no runtime policy, schema acceptance or security boundary changes.
- HD-08 [implemented; native execution pending]: repair Windows Cursor per-SID adapter policy and deferred
  staging; align the Windows Amp contract harness with the open default while
  retaining explicit-closed regression coverage.
- HD-09 [implemented; native execution pending]: fix the Amp self-heal test's read/publication race. Retry
  only file-not-found, sharing-violation and lock-violation read errors within
  the existing 80-attempt, 250-ms polling budget. Exact bytes and private ACL
  verification remain mandatory; unrelated errors fail immediately. Cover
  transient and persistent locks, wrong bytes, rejected ACLs and exception
  classification.

HD-09 is a test-only follow-up on the existing PR, with no release/version bump
or production changes. CI at `9ed37a2a` failed when the restored Amp plugin was
visible but still held by its protected publication handle: `ReadAllBytes`
threw a sharing violation and aborted the poll. Production locking and
publication validation must remain unchanged. Root CONTEXT.md stays absent
per the user's request; this spec carries the scoped work notes.

HD-08 review fixes preserve singleton enrollment and administrator-only rollback
receipts, bind per-user fallback to authenticated runtime generations, and keep
legacy v9 adapter bytes identical. Canonical partial publication is recoverable
from the protected lifecycle journal during both fresh install and upgrade.
The Amp connector and wizard harnesses now expect the open default; the connector
contract independently installs and verifies closed before restoring open.

CI diagnosis: both failing leaf jobs at `791af585` read LiteLLM's mutable remote
model-cost map despite documenting a bundled, locked registry. Read the installed
wheel's JSON directly using package metadata, including when LiteLLM was already
imported elsewhere. Keep model membership and deprecation validation intact.

The updated CI run passes Schema & Parity. Connector Matrix exposes a stale
init-command assertion for the former closed default; align it with the new
default and add preservation coverage for an existing explicit closed policy.

## Verification

Test unset, open, closed and invalid configuration; action-mode rendering;
managed gateway outage, missing token, malformed response, strict availability
and explicit policy denial. Run Go config/connector/enterprise-hook tests and
focused Python configuration tests. Windows changes need Windows-native tests.

Local results: Go config, connector, hook executor, enterprise-hook and CLI tests
pass; the focused Python suite has 379 passed, 6 skipped and 12 passing subtests.
Go vet passes for macOS and Windows, and all changed Windows packages and their
tests cross-compile. Schema/reference, catalog and upgrade-manifest checks pass.
The Python connector matrix passes (483 passed, 20 skipped, 128 passing subtests)
with isolated DefenseClaw state. Full `make check` stops at npm authentication E401 during provider dependency
installation; native Windows execution and the new remote CI run remain pending.

Local test bundle: managed macOS 0.8.6 arm64, built from source commit
`3eb105e09f84ce2f5fd7bf9a32ff1c785d94d954` with the real ai-common CMID provider
`v0.0.0-20261009205442-7eff5156d292`. Binary version/architecture, provider linkage,
ad-hoc code-signature integrity, tar checksum and zip integrity checks pass.
No installer was run. Build logs and extra handoff notes are not in the archive.

Logging verification: the executable shell matrix (54 cases), shared native
matrix (84 cases), JSON/line-injection tests, unwritable-log tests and full
shell-hook regression set pass. Native hook executor, enterprise-hook and CLI
suites pass; macOS/Windows Go vet and Windows cross-compilation pass. The full
connector suite has one unrelated failure because the optional OpenClaw bundle
is incomplete locally (`extensions/defenseclaw/dist/index.js` is missing).
Native Windows execution remains a CI/Windows-host check. The existing macOS
test bundle is preserved and predates this logging-only change; it was not rebuilt.

CodeRabbit follow-up: reproduced the schemas package failure from the stale
`closed` default assertion, aligned it with the canonical `open` default, and
corrected the managed Windows open-contract test comment. The full schemas
suite now passes; schemas vet, Windows enterprise-hook/schema cross-compilation
and Windows vet pass. This follow-up changes tests/comments only, not runtime
policy or security validation. Windows-native test execution remains pending.

Windows review-fix verification: focused Cursor/Windows registration, hook
contract and Amp connector tests pass on macOS, including the legacy v9 adapter
golden hashes. Config, native executor, enterprise-hook, CLI and schemas suites
pass; changed packages and tests cross-compile for Windows amd64. macOS and
Windows Go vet pass. Windows-only regressions cover mixed SID modes, missing
launcher/timeout/valid denial behavior, deferred fallback, enrollment/generation
mode mismatches, revocation, and canonical fresh/upgrade rollback prefixes.
Those tests and the PowerShell contract/wizard harness require native Windows
CI execution; they have not been executed on this macOS host. No bundle or
installer was created or run, and CONTEXT.md remains removed.

Amp race verification: both edited PowerShell scripts parse with PowerShell
7.5.4. The exception classifier accepts only Win32 file-not-found/sharing/lock
violations, including invocation wrappers, and rejects access-denied, malformed
path and unrelated I/O errors. Five polling scenarios pass locally with
simulated Windows sharing errors; the unchanged parent polling code fails the
transient-lock case. macOS reports a different native sharing-error code, so
real FileShare.None regression execution remains a Windows CI gate. Persistent
locks, missing files and wrong bytes retain the 80-attempt budget; rejected ACLs
cannot produce success. Runtime code and its private publication handles are
unchanged. A portable, digest-verified PowerShell runtime was used only under
/private/tmp; no system installation was changed.

The completed `9ed37a2a` run also reveals separate Windows Go fixture failures:
protected StateRoot/runtime and gateway-service bindings are missing in some
enterprise-hook fixtures, while managed-contract cleanup fixtures omit delivery
mode and still expect closed. These are not addressed by HD-09 and require a
separate follow-up before the entire Windows gate can pass.

## Top-level doc impact

- readme: updated
- architecture: updated
- adr-readme: not-applicable
- specs-readme: added
- cp-dp-schema-workbench: not-applicable
- rationale: Repository uses docs/ARCHITECTURE.md and docs/README.md rather than the skill's architecture/ADR indexes; no schema ownership or database changes.
