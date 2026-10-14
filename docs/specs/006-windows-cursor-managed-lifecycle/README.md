# Spec 006 — Windows Cursor managed-enterprise lifecycle

**Status:** Proposed. This design has not shipped.

> **Scope/status:** This is an engineering specification for the separate
> machine-wide managed-enterprise path. PR #655 shipped ordinary per-user
> [native Windows Cursor support](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/cursor/)
> through the user hook and managed PowerShell adapter. That general support
> does not qualify this machine-wide enterprise design; the published managed-
> enterprise connector set remains authoritative.

This specification proposes extending Windows managed-enterprise to Cursor
through Cursor's documented machine-wide enterprise hook source:

`C:\ProgramData\Cursor\hooks.json`

This path has higher priority than team, project, and user hook files. The
designed integration would not modify `%USERPROFILE%\.cursor\hooks.json`.
The behavior below is proposed design and acceptance criteria, not shipped or
qualified managed-enterprise support.

## Proposed architecture

- Setup installs one administrator-owned `defenseclaw-hook.ps1` adapter under
  `C:\ProgramData\Cursor` and registers it in the enterprise `hooks.json`.
- The adapter contains no credential or user identity. It streams Cursor's
  JSON from stdin to the existing signed `defenseclaw-hook.exe` with
  `hook --connector cursor --enterprise-managed` and returns its JSON verdict.
- Cursor action hooks set `failClosed: true`; adapter startup, timeout, or
  malformed-response failures return an explicit deny result.
- Each enabled Windows user retains a separate ACL-protected DefenseClaw
  runtime under `%USERPROFILE%\.defenseclaw\hooks`.
- Protected, user-readable machine state contains only the non-secret mapping
  from the current process SID to that
  user's canonical runtime directory. The native hook derives the SID from its
  process token; neither `USERPROFILE` nor a caller-supplied path selects a
  runtime.
- The original third-party configuration and its security metadata live in a
  separate Administrator/SYSTEM-only rollback receipt; they are never copied
  into the user-readable SID registry.
- An unregistered SID, a changed path, an invalid ACL, or a drifted contract
  fails closed.

## Proposed ownership and lifecycle

Under this design, DefenseClaw would own only entries whose command exactly
matches its protected adapter path. Reconcile would preserve unrelated
enterprise hooks and settings. The protected ownership state would record the
installed adapter digest, machine identity, and exact enrolled SID set. The
separate private receipt would record the original configuration and security
metadata and be hash-bound to that state.

Install and repair would reconcile all per-user runtimes before publishing the
machine hook. Guardian would revoke stale SIDs and publish the exact desired
set. Rollback and uninstall would snapshot all four global artifacts
(configuration, adapter, public ownership state, and private receipt) in the
protected lifecycle journal. Teardown would remove DefenseClaw-owned entries
while preserving unrelated hooks; it would leave a credential-free allow-only
adapter tombstone for Cursor processes that may have cached the old command.

## Native Cursor scope

The supported Windows lifecycle is for native Cursor installations. Known
per-user and machine application roots provide version metadata. When a native
installation uses another binary location, a real, non-reparse
`%USERPROFILE%\.cursor\extensions` directory supplies best-effort presence
evidence. A newly discovered target is emitted enabled with an empty version,
then uses the existing unverified-contract fail-open path from spec 007
(which applies under Secure Client only; elsewhere delivery stays closed).
Discovery does not execute the binary, read extension contents, or treat
`.cursor` / `hooks.json` alone as presence; DefenseClaw can create those itself.
It does not treat `cursor-agent` in WSL or an npm package as native installation
evidence. An extensions directory can survive uninstall, so this is a presence
hint, not proof of a currently installed binary or active hook protection.

The marker must be a directory, not a regular file, and the existing ancestor
reparse checks remain mandatory. Existing disabled targets stay disabled.
Machine policy locations, SID enrollment, runtime integrity, and authenticated
session requirements are unchanged. `argv.json` is not added as a Windows
signal because its location and creation are not consistently documented.

This machine-wide Cursor lifecycle remains outside the published managed-
enterprise connector set until its native install, multi-user, Guardian,
repair, rollback, non-purge reinstall, purge, and fail-closed test matrix
completes. That boundary does not downgrade the separate supported per-user
Windows connector. Amp remains out of scope for this specification.

## Cursor home-state discovery follow-up

Continue release-defenseclaw-enterprise-26.8.4 without a version bump or new
architecture decision. CURSOR-DISCOVERY-01 adds the presence signal and native
Windows regressions for a custom-location installation, target emission without
version evidence, disabled-row preservation, bootstrap-only absence, wrong
object types, and reparse rejection. Verification must distinguish Windows
cross-compilation from Windows-native execution. Scoped work notes remain in
this spec; the removed root CONTEXT.md is not recreated.

Implementation: only the presence predicate changes. Its shared directory
markers (Cursor extensions, Claude projects, Codex sessions) now require actual
directories; ordinary-file markers still require regular files. No credentials,
certificates, cryptographic algorithms, policy configuration, or machine hook
registration are changed. CodeGuard file-handling and input-validation rules
preserve no-follow traversal and passive discovery.

Verification: the full enterprise-hook suite passes on macOS. macOS and Windows
amd64 `go vet` pass, and the enterprise-hook test binary cross-compiles for
Windows amd64. Windows-only presence/emission/reparse tests require native CI
execution; these local checks do not claim Windows execution. No installed
runtime, agent configuration, or build has been replaced.

Sources: [Cursor support confirms the Windows extensions location](https://forum.cursor.com/t/cursor-shortcut-suddenly-program-not-found/82868/5)
and [Cursor hook configuration locations](https://cursor.com/docs/hooks).

## Top-level doc impact

- readme: already-correct
- architecture: already-correct
- adr-readme: not-applicable
- specs-readme: already-correct
- cp-dp-schema-workbench: not-applicable
- rationale: Small discovery correction within the existing native Windows lifecycle; no new component, protocol, database schema, or policy boundary.
