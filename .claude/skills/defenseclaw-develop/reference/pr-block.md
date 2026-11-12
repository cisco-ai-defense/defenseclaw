# PR description block

The PR template already contains this block. When you open a PR without the template (for example `gh pr create --body`), paste it yourself before your first commit and keep it current. Delete lines that do not apply, with a reason. IDs are defined only in `reference/checklist.md`.

```markdown
## Contributor checklist (defenseclaw-develop)
Areas touched: <codes from CFG POL ID DEP REQ SBX SCN TST PERF OBS DOC SEC PKG PR>
Modes changed: <OSS per-user / standalone managed (packages, MDM) / Secure Client>. Modes that must not change: <the rest>
- [ ] Mode-specific behavior is gated on the resolved deployment mode and profile, never on a user-writable key or environment variable. Gate: <helper>
- [ ] Every mode not listed above behaves exactly as before. Proof: <test per unchanged mode>
- [ ] Shared defaults unchanged (config defaults, hook answers, hook fail modes, installer paths, telemetry routing, CI gates): yes / changed <what>, agreed in #<issue>
- [ ] Gateway-outage behavior unchanged or as in docs-site/content/docs/reference/fail-modes.mdx:
      - per-user default and permissive: open with a warning;
      - per-user strict: closed;
      - managed standalone: closed unless an administrator sets `open`;
      - Secure Client: open unless set `closed`;
      - a saved mode wins.
      yes / n.a.
- [ ] The default and permissive policies block nothing new; new blocks are strict or action mode only: yes / n.a.
- [ ] Policy, profile, group or account data is shown only to that user or to an administrator, checked server-side: yes / n.a.
- [ ] Management features are standalone managed only, never Secure Client: yes / n.a.
- [ ] Every MUST for these areas is met. MUST items that do not apply, each with a reason: M-___ (reason) / none
- [ ] SHOULD items skipped, each with a one-line reason: S-___ (reason) / none
- [ ] Off switch per mode: OSS `<key>` / standalone and MDM `enterprise.<key>: off` / Secure Client `<switch>` or unreachable. In each mode the feature is not for, a test shows it starts nothing: <tests>. Cost when off: <none / measured>
- [ ] New external requirement: none / <name>, tier Required / Recommended / Optional; detected in doctor, in docs-site, missing case tested, never installed silently
- [ ] Applies as one atomic unit with rollback; no out-of-band step: yes / n.a.
- [ ] Every layer of the change is in this PR (schema, mirrors, migration, docs, tests per mode, packaging, audit): yes / n.a. with a reason
- [ ] Hot-path impact (hooks, gateway, SQLite): none / <measurement>
- [ ] Size delta (binaries, wheel, packages): <before -> after> / none
- [ ] Observability: audit action / error code / telemetry / redaction profile: <what> / n.a.
- [ ] Dead or legacy code removed: <what and why> / kept for <upgrade path> until <version> / none found. Upgrades are supported from 1.0.0; 0.8.x-only code is legacy.
- [ ] Required CI for every mode changed or at risk is green, not skipped: <job names>
- [ ] A widened CI timing limit is test-only, for slow hosted runners, with old and new values; hook-deadline assertions are unchanged: yes / n.a.
- [ ] Stop-and-ask trigger hit: no / yes, discussed in #<issue>
- [ ] Does this change an architecture rule, so the skill must be updated? no / yes, updated
- Commands run and results: <make lint ..., make test ..., area checks ...>
```
