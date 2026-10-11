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

## Plan

Epic HD-DEFAULT: align hook availability defaults without weakening policy.

- HD-01 [done]: align Go/Python defaults, configuration schema and render selection.
- HD-02 [done]: repair managed macOS delivery behavior and add executable regressions.
- HD-03 [implemented; native execution pending]: carry fallback contracts and delivery policy through Windows managed
  installation, registration, verification and native execution.
- HD-04 [done; environment limitations noted]: verify packages, diagnose CI and
  update guidance and branch context.

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

## Top-level doc impact

- readme: updated
- architecture: updated
- adr-readme: not-applicable
- specs-readme: added
- cp-dp-schema-workbench: not-applicable
- rationale: Repository uses docs/ARCHITECTURE.md and docs/README.md rather than the skill's architecture/ADR indexes; no schema ownership or database changes.
