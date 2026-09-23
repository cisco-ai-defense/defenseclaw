# Spec 006 — Windows Cursor managed-enterprise lifecycle

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

The proposed Windows lifecycle is for native Cursor installations under the
per-user or machine application roots. It does not treat `cursor-agent` in WSL
or an npm package as a native Windows installation.

This machine-wide Cursor lifecycle remains outside the published managed-
enterprise connector set until its native install, multi-user, Guardian,
repair, rollback, non-purge reinstall, purge, and fail-closed test matrix
completes. That boundary does not downgrade the separate supported per-user
Windows connector. Amp remains out of scope for this specification.
