---
name: defenseclaw-develop
description: Use before writing or reviewing any DefenseClaw change that is not a new connector: config keys, policy and guardrail rules, identity and profiles, managed (enterprise) behavior, sandboxes, new external requirements, hooks and gateway hot paths, telemetry, docs, packaging and upgrades. It gives the design principles, a routing table, a tiered MUST/SHOULD/MAY requirement checklist to paste into the PR description, and the stop-and-ask triggers. For a new or changed agent connector, start with defenseclaw-add-connector, then use this skill for the shared gates.
---

# Develop DefenseClaw

DefenseClaw governs AI agents on a developer laptop (OSS, per user) and on managed machines (standalone enterprise, one gateway serving many users). One Go gateway, one Python CLI, one TUI and one docs site serve both. Most regressions in this repository are silent: a closed list that misses an entry, a lenient fallback, a mirror that drifted, a feature that costs CPU when off.

Source code and tests are authoritative. Last full sweep: not yet run (set by the first quarterly sweep). If this skill disagrees with them, trust the code and fix the skill (`reference/maintenance.md`). The skill names files, symbols and make targets, never line numbers. Find a symbol with `git grep -n '<symbol>'`.

## When to use

| Situation | Use |
| --- | --- |
| Any change except a new or changed agent connector | this skill |
| A new or changed connector (hook, plugin, proxy, ACP route) | `defenseclaw-add-connector`, then the connector rows here for the shared gates |
| TUI panels, modals, Setup wizards | `defenseclaw-tui`, plus the TUI rows here |
| Commands, toolchain, PR hygiene | `CONTRIBUTING.md` and `docs/TESTING.md` (this skill links, it does not copy) |

## Architecture map

```
agent hook / plugin / proxy / ACP
  -> defenseclaw-hook (cmd/defenseclaw-hook): one bounded local call
  -> defenseclaw-gateway (cmd/defenseclaw): config generation snapshot, policy (internal/policy, Rego + Go twin),
     guardrail rule packs (internal/guardrail), identity -> profile (internal/useridentity), audit SQLite (internal/audit),
     telemetry (internal/observability), sandboxes (internal/openshell)
defenseclaw CLI + TUI (cli/defenseclaw): writes config.yaml only through the shared writer; doctor, setup, migrate
managed hosts: lifecycle transaction (internal/enterpriseunix, packaging/windows), guardian and enumerator
  (internal/enterprisehooks), packages (.goreleaser.yaml, packaging/)
docs: docs-site/content/docs (operator), docs/ (contributor)
```

## The ten design principles

Each principle maps to requirement IDs in `reference/checklist.md`.

1. **Config is the single source of truth.** `config.yaml` decides policy. Hook scripts, provider files and machine policy are derived from it. No hidden env var, side file or second writer. (CFG, DEP)
2. **Fail closed, never silently lenient.** A failed lookup, bad pack, missing scan result or unreachable gateway resolves to the stricter outcome, with a reason code. Removed keys say what replaced them. (POL, ID, CFG)
3. **Managed hosts never allow what policy denies.** Mode comes from the pinned service environment, not a user-writable file. Environment overrides on managed hosts only tighten. Local writers are refused. (DEP, SEC)
4. **Identity-scoped policy with per-user privacy.** Only kernel- or credential-verified identity selects a profile. A user sees only their own effective policy; everything else is admin-only, enforced server side. (ID)
5. **Everything is switchable and costs nothing when off.** Every feature has an off switch, starts no goroutine, watcher, timer or listener while off, and is covered by a test that proves it. (PERF, DEP)
6. **Hot-path discipline.** Hooks run on every agent tool call. One bounded local call, bounded inputs, immediate refusal under load, no queued judge, no per-event heavy work. (PERF)
7. **Bundle-at-once, atomic apply with rollback.** Config, policy, rule packs and assets are one unit: pinned by digest, applied together, rolled back together. A feature that needs a second manual step breaks managed deployments. (DEP, CFG, POL)
8. **Disclose every external requirement.** Docker, a VM, a local model, a GPU, an extra, a system package, an OS floor or new network egress is optional where possible, detected with an actionable message, documented, tested when missing, and never installed silently. Each one is tiered Required, Recommended or Optional. (REQ, SBX)
9. **Observability and audit for every state change.** Typed audit actions, registered error codes, generated telemetry, redaction at the projection boundary. (OBS)
10. **One upgrade path, no dead code.** The 0.8.x to 1.x upgrade keeps working. Each change removes the dead or legacy code it touches, and keeps a shim only for a named supported upgrade. (PKG, PR)

## Before you code

1. **Classify the change.** Use the routing table. A change usually has two to four areas.
2. **Open only what you need.** Read the area sections of `reference/checklist.md` (`grep -n -- '-CFG-' .claude/skills/defenseclaw-develop/reference/checklist.md`, swap the area code); it is the only place requirement IDs are defined. Open the one or two area references from the table below for detail. Do not load the rest.
3. **Check the stop-and-ask list** below. If any trigger applies, ask a maintainer in the issue or PR before building.
4. **Write the checklist block first.** Copy `reference/pr-block.md` into the PR description (or a draft PR) before the first commit. List the area IDs that apply and mark non-applicable ones with a reason.
5. **Code, then verify.** Run the gates in `docs/TESTING.md` ("Before a PR") and the area checks named by each requirement. Tick the block with the commands you ran and the results you saw.
6. **Update this skill** when the change alters an architecture rule (`reference/maintenance.md`, update map).

## Routing table

| You change | Areas | Also open |
| --- | --- | --- |
| A config key, schema, default, migration | CFG, DOC, PKG | `docs/CONFIG_FILES.md`, `schemas/README.md` |
| A `DEFENSECLAW_*` environment variable | CFG, DEP, DOC | `internal/envvars/registry.json` |
| Rego, admission, rule packs, detections | POL, TST, PERF | `docs/GUARDRAIL_RULE_PACKS.md` |
| Profiles, assignments, directory facts, agent identity | ID, POL, SEC | `docs-site/content/docs/reference/policy/guardrail-profiles.mdx` |
| Enterprise, MDM, guardian, lifecycle, machine policy | DEP, PKG, SEC, TST | `docs-site/content/docs/enterprise/configure/machine-policy.mdx`, `.github/managed-paths.txt` |
| Sandboxes, OpenShell, drivers | SBX, REQ, DEP | `docs/SANDBOX.md` (contributor notes) |
| Scanners, judges, local models | SCN, REQ | `reference/requirements-and-sandboxes.md` |
| A new tool, model, daemon, package or network call | REQ, DEP, DOC | `internal/openshell/doctor.go` as the detection model |
| Hook binary, gateway endpoint, SQLite, scanning, exporters | PERF, OBS, TST | `cmd/defenseclaw-hook/main.go` |
| Audit actions, error codes, telemetry, redaction, dashboards | OBS, DOC, TST | `schemas/README.md` |
| Docs, CHANGELOG, generated references | DOC, PR | `docs-site/README.md` |
| Installers, packages, upgrade, release, versions | PKG, TST, SEC | `docs/RELEASE_RUNBOOK.md` |
| Workflows, CI path rules | TST, SEC | `scripts/ci_changes.py`, `.github/managed-paths.txt` |
| Any pull request | PR | `.github/pull_request_template.md` |
| TUI | TST, PERF | `defenseclaw-tui` skill |
| Audit store schema, inventory or other on-disk state format | PKG, PERF, TST | `internal/audit/pending_migrations.go` |
| `.proto` files or vendored code in `third_party/` | TST, SEC, PKG | `third_party/tetragon/README.md`; run `make proto-check` |
| The macOS app (`macos/DefenseClawMac`) | TST, SEC, PKG | `macos/DefenseClawMac/UPDATING.md`; run `make macos-app-test` |
| The OpenClaw extension (`extensions/defenseclaw`) | TST, SEC, PKG | `scripts/extension_runtime_fingerprint.py`; run `make ts-test` |
| Scanner plugins, YARA or scanner policies, `skills/codeguard` | POL, SEC, TST | `internal/policy/first_party_verify.go` (update the codeguard content signatures with `skills/codeguard`) |
| Kernel sensor, Tetragon, egress firewall | REQ, DEP, SEC, PERF | `docs-site/content/docs/enterprise/runtime/tetragon.mdx`, `internal/firewall` |
| Splunk bridge or dashboards | OBS, DOC | `bundles/splunk_o11y_dashboards` |
| Connector | all that apply | `defenseclaw-add-connector` skill |

## Stop and ask a maintainer

Open an issue or ask in the PR before writing code when the change would:

| Trigger | Why it needs a decision |
| --- | --- |
| Change a default so it weakens security, or loosen a managed knob | Defaults reach every install; managed hosts must keep denying what policy denies |
| Add a daemon, background service or listening port | New attack surface and per-user cost; managed listeners must stay on loopback |
| Add a network egress (new host, new outbound call, new update or telemetry path) | Needs disclosure, an off switch and a firewall note |
| Add a dependency or external requirement (module, extra, binary, VM, GPU, OS floor) | Disclosure, packaging and upgrade impact on every channel |
| Change the config schema version or the migration chain | A one-sided bump locks out upgrades |
| Touch signing, checksums, package formats or any bundle or digest format | Operators pin these; a change breaks verification and rollback |
| Alter identity or privacy rules (who selects a profile, who can read policy) | Policy bypass or cross-user leak |
| Touch the Secure Client profile paths | They must stay byte-identical; maintainers run a separate invariance check |

## Tier legend

| Tier | ID prefix | Meaning |
| --- | --- | --- |
| MUST | `M-` | The PR is not mergeable without it: it breaks a gate, a security property, an upgrade path or an operator |
| SHOULD | `S-` | Expected. A reviewer will ask. Skipping needs a one-line justification in the PR |
| MAY | `O-` | Optional polish |

IDs look like `M-CFG-1` (tier, area, number). Areas: CFG config, POL policy and guardrails, ID identity, DEP deployment modes and bundles, REQ external requirements, SBX sandbox, SCN scanners, judges and local models, TST testing, PERF performance and size, OBS observability and audit, DOC docs, SEC security, PKG packaging and upgrade, PR pull request hygiene.

## References

| File | Open when |
| --- | --- |
| `reference/checklist.md` | Always, for the sections of your areas; the only place requirement IDs are defined |
| `reference/pr-block.md` | Opening or updating a PR description |
| `reference/config.md` | Adding or changing a config key, default, migration, environment variable, writer or reload path |
| `reference/identity-policy.md` | Rego, rule packs, guardrail profiles, assignments, identity sources, policy visibility |
| `reference/deployment-modes.md` | Behavior that differs per mode, feature switches, `enterprise.*` keys, lifecycle, MDM, bundle-at-once apply, upgrade and downgrade |
| `reference/requirements-and-sandboxes.md` | Anything outside the wheel and binaries: Docker, VM, local model, GPU, extras, packages, OS floors, egress, sandboxes, scanners |
| `reference/performance.md` | Hook path, gateway request path, audit store, telemetry export, scanning, TUI refresh, new background work or binaries |
| `reference/observability-docs.md` | Audit actions, error codes, telemetry, redaction, docs-site pages, CLI doc references, changelog |
| `reference/security-packaging.md` | Secrets, permissions, fail-closed behavior, dependencies, licensing, release and package formats, upgrade path, dead code, opening a PR |
| `reference/testing.md` | Choosing which gates and tests to run, goldens, CI classification, installers, Windows or enterprise code |
| `reference/maintenance.md` | You change an architecture rule, add a requirement, or run the freshness check or quarterly sweep |
| `CONTRIBUTING.md` | Toolchain versions and the common checks |
| `docs/TESTING.md` | Which gate covers which change, install scenarios, CI workflow map |
| `.github/pull_request_template.md` | Writing the PR body |
| `.claude/skills/defenseclaw-add-connector/SKILL.md` | The change adds or alters a connector |
| `.claude/skills/defenseclaw-tui/SKILL.md` | The change touches `cli/defenseclaw/tui` |

Freshness: run `make skill-check` (or `python3 .claude/skills/defenseclaw-develop/scripts/check_skill_fresh.py`) from the repo root. It fails when a cited path, make target or `@sym:` symbol no longer exists, when a `go test -run` pattern matches no test, when a requirement ID is cited but not defined in the checklist, or when a file exceeds its size limit.
