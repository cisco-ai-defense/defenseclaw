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

## Top-level doc impact

- readme: updated
- architecture: updated
- adr-readme: not-applicable
- specs-readme: added
- cp-dp-schema-workbench: not-applicable
- rationale: Repository uses docs/ARCHITECTURE.md and docs/README.md rather than the skill's architecture/ADR indexes; no schema ownership or database changes.
