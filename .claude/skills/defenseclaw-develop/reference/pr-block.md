# PR description block

The PR template already contains this block. When you open a PR without the template (for example `gh pr create --body`), paste it yourself before your first commit and keep it current. Delete lines that do not apply, with a reason. IDs are defined only in `reference/checklist.md`.

```markdown
## Contributor checklist (defenseclaw-develop)
Areas touched: <codes from CFG POL ID DEP REQ SBX SCN TST PERF OBS DOC SEC PKG PR>
- [ ] Every MUST for these areas is met. MUST items that do not apply, each with a reason: M-___ (reason) / none
- [ ] SHOULD items skipped, each with a one-line reason: S-___ (reason) / none
- [ ] Off switch per mode: OSS `<key>` / standalone and MDM `enterprise.<key>: off` / Secure Client unreachable. Off-path test: <test name>. Cost when off: <none / measured>
- [ ] New external requirement: none / <name>, tier Required / Recommended / Optional; detected in doctor, in docs-site, missing case tested, never installed silently
- [ ] Applies as one atomic unit with rollback; no out-of-band step: yes / n.a.
- [ ] Every layer of the change is in this PR (schema, mirrors, migration, docs, tests per mode, packaging, audit): yes / n.a. with a reason
- [ ] Hot-path impact (hooks, gateway, SQLite): none / <measurement>
- [ ] Size delta (binaries, wheel, packages): <before -> after> / none
- [ ] Observability: audit action / error code / telemetry / redaction profile: <what> / n.a.
- [ ] Dead or legacy code removed: <what and why> / kept for <upgrade path> until <version> / none found
- [ ] Stop-and-ask trigger hit: no / yes, discussed in #<issue>
- [ ] Does this change an architecture rule, so the skill must be updated? no / yes, updated
- Commands run and results: <make lint ..., make test ..., area checks ...>
```
