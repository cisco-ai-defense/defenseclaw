# Unverified hook-contract fallback

## Problem

The enterprise hook guardian historically rejected an action-mode target
when the discovered agent version was empty, malformed, outside every registered
range, or different from the persisted hook-contract lock. That made version
discovery a hard prerequisite for installation even though version-gated hook
connectors such as Codex, Claude Code, and Cursor can render and structurally
verify a reviewed hook configuration without an exact version match.

The result was a worse protection state: no hook was installed, so the runtime
hook failure policy could never run. This is the failure behind macOS targets
whose `agent_version` is empty even though the native application is present.

## Requirements

The overall delivery default is now governed by
[spec 007](../specs/007-hook-delivery-default/README.md): unset policy is open,
explicit closed remains supported, and managed macOS and Windows hooks honor
the installer-selected delivery mode. Windows enrollment and strict artifact
readers remain mandatory even when compatibility is unverified.

- A missing or unsupported agent version must not prevent enterprise hook
  installation.
- An unverified target must use the connector's reviewed default contract and
  run with `DEFENSECLAW_FAIL_MODE=open`.
- The default contract used for an unverified target must cover the union of
  events in the registered contracts for that connector. An unknown event is a
  best-effort registration; this design does not assume that every upstream
  version accepts it.
- An exact version change that remains inside the same registered contract is
  compatible and must retain the configured hook failure mode.
- A version change that selects a different registered contract must install
  the newly selected contract in fail-open mode for that reconciliation.
- A later reconciliation may restore the configured failure mode after the
  actual version resolves to a known contract and the installed registration
  verifies against the new lock.
- `DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1` remains an explicit exploratory
  override for non-strict runtimes and preserves the caller-selected failure
  mode. It must not bypass native Windows managed contract validation.
- Hook configuration verification, ownership checks, atomic writes, rollback,
  and unrelated manually configured hooks must retain their existing behavior.
- Native Windows discovery emits an enabled target when static agent presence
  is proven even if version metadata is missing. Existing authorization flags
  survive refresh; stale versions do not. No profile-owned code is executed.
- Shared preparation reached by native Windows managed Install or Verify must
  retain the bounded, identity-stable managed lock reader and runtime hasher in
  every guardrail mode. The Unix fallback must not widen the Windows managed
  file-read trust boundary.
- Native Windows managed compatibility drift selects open delivery, but read,
  ownership, enrollment and runtime-integrity failures still reject preparation.

## Design

`ResolveHookContract` continues to distinguish `known`, `unversioned`, and
`unknown` compatibility. A best-effort contract selector returns the resolved
contract when one exists and otherwise returns the connector's reviewed
`default_for_unversioned` contract. The default's event metadata is the stable
union of registered events, while response format, script version, and other
runtime details remain those of the reviewed default contract.

Before enterprise Install or Verify examines the target, it prepares the
effective setup options:

1. select the resolved or best-effort hook contract;
2. force `HookFailMode=open` for `unversioned` or `unknown` compatibility;
3. compare the selected contract with the persisted lock;
4. force `HookFailMode=open` when the contract identifier changed;
5. retain the configured mode when only the raw/normalized version changed
   inside the same contract range.

The existing lock records the raw version, normalized version, compatibility
status, selected contract, and effective hook failure mode. Install still
verifies the agent-visible registration before committing that lock. On the
next reconciliation, a known version whose selected contract matches the lock
is eligible to return to the configured failure mode.

Windows managed callers use the strict bounded lock reader and runtime hasher
in every guardrail mode. The exploratory drift override cannot bypass these
readers or force a closed compatibility fallback. Windows runtime generations
authenticate the effective delivery mode together with endpoint, token and
contract identity. Older authenticated closed bundles remain valid until an
authorized reconciliation republishes them. Cursor's protected machine state
records its adapter delivery mode; pre-upgrade state without this field still
verifies as closed. Enrollment and integrity failures are not availability
failures and remain closed before network contact.

Fail-open applies only to hook delivery, authentication, timeout, and malformed
response failures. A successfully delivered DefenseClaw deny verdict remains a
deny; this change does not turn action mode into observe mode.

## Verification

- Unit-test missing, malformed, and below-minimum versions selecting the
  best-effort contract with fail-open, including installer coverage for Codex,
  Claude Code, and Cursor.
- Unit-test same-contract patch-version drift retaining fail-closed.
- Unit-test cross-contract drift using fail-open for the first reconciliation.
- Unit-test the explicit drift override retaining the configured mode on
  non-strict runtimes.
- Unit-test native Windows managed action and non-action preparation rejecting
  oversized lock and hook-runtime artifacts through the strict bounded readers.
- Unit-test native Windows managed action and non-action preparation using open
  delivery for contract drift while retaining strict artifact readers.
- Unit-test the explicit drift override retaining native Windows managed
  bounded reads and compatibility fallback in action and non-action modes.
- Run focused connector and enterprise-hook installer tests.

## Top-level documentation impact

- `README.md`: no change; this is not a new top-level capability.
- `docs/ARCHITECTURE.md`: updated with the compatibility-versus-availability
  invariant and a pointer to this implementation contract.
- `docs/README.md`: updated to index this active engineering reference.
