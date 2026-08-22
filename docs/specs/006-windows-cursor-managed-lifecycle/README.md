# Spec 006 — Windows Cursor managed-enterprise lifecycle

Windows managed-enterprise supports Cursor through Cursor's documented
machine-wide enterprise hook source:

`C:\ProgramData\Cursor\hooks.json`

This path has higher priority than team, project, and user hook files. The
integration deliberately does not modify `%USERPROFILE%\.cursor\hooks.json`.

## Architecture

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

## Ownership and lifecycle

DefenseClaw owns only entries whose command exactly matches its protected
adapter path. Reconcile preserves unrelated enterprise hooks and settings.
The protected ownership state records the installed adapter digest, machine
identity, and exact enrolled SID set. The separate private receipt records the
original configuration and security metadata and is hash-bound to that state.

Install and repair reconcile all per-user runtimes before publishing the
machine hook. Guardian revokes stale SIDs and publishes the exact desired set.
Rollback and uninstall snapshot all four global artifacts (configuration,
adapter, public ownership state, and private receipt) in the protected
lifecycle journal. Teardown
removes DefenseClaw-owned entries while preserving unrelated hooks; it leaves
a credential-free allow-only adapter tombstone for Cursor processes that may
have cached the old command.

## Native Cursor scope

The supported Windows lifecycle is for native Cursor installations under the
per-user or machine application roots. It does not treat `cursor-agent` in WSL
or an npm package as a native Windows installation.

Cursor remains enterprise-scoped and not certified for general Windows use
until the native install, multi-user, Guardian, repair, rollback, non-purge
reinstall, purge, and fail-closed test matrix completes. Amp support remains
out of scope.
