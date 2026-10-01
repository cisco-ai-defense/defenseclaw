# Spec 005: Windows per-user hook lifecycle

**Status:** Implemented, with two follow-ups open:
- enumerator health is not yet carried across processes;
- the F1 targeted uninstall has no caller yet.

A third SCM service, `DefenseClawHookEnumerator`, keeps the hook-guardian
`targets.yaml` in step with the local user profiles of a managed-enterprise
Windows host. It walks the profile registry, keeps the decisions already in
the manifest, adds a row for each new profile that has a supported agent CLI
installed, and publishes the manifest only when its bytes change. This
matches the macOS hook enumerator and `render-targets.sh`.

- [Requirements](requirements.md)
- [Design](design.md)
- [Tasks](tasks.md)

Related:
- [spec 003](../003-windows-deferred-config/) covers the missing-config wait;
- [spec 004](../004-windows-ui-ipc/) covers the IPC health surface.
