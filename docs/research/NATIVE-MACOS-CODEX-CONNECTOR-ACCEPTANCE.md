# Native macOS Codex connector acceptance

Last integration audit: **2026-07-30**

This ledger applies the twelve surfaces from
[`NATIVE-WINDOWS-CONNECTOR-ACCEPTANCE.md`](NATIVE-WINDOWS-CONNECTOR-ACCEPTANCE.md)
to the native Codex CLI on macOS. It records implementation coverage, not a
release certification.

Cell vocabulary:

- **I — Implemented:** code and a deterministic check or exact validation
  definition exist.
- **L — Officially limited:** the implementation stops at a documented Codex
  or macOS boundary.
- **N/A:** Codex does not publish that extension or enforcement surface.
- **B — Blocked:** the durable authentic evidence required to promote the
  connector is unavailable.

## Outdatedness decision

These are separate determinations. A current compatibility range is not a
validation record, and a published upstream release is not a DefenseClaw
certification.

| Decision | Scope | Evidence |
| --- | --- | --- |
| **OUTDATED** | Installed/authenticated live validation evidence | The audit host's installed CLI is `0.145.0`, while the current stable macOS release and npm `latest` are `0.146.0`. An isolated official `0.146.0` package was inspected statically, but it was not used for an authenticated lifecycle run. |
| **CURRENT** | Version compatibility and implemented contract | `0.146.0` selects the open-ended `codex-hooks-v4` range (`>=0.145.0`). Its 11 generated hook schemas match DefenseClaw's 11 events, and the current Codex schema/source still provides log, metric, and trace exporters plus W3C trace context. |
| **UNCERTIFIED** | Native macOS support status | `cli/defenseclaw/inventory/validated_versions.json` has an empty macOS `last_validated_version`, timestamp, and run URL for Codex. No green packaged, authenticated `0.146.0` lifecycle record exists, so macOS remains preview. |

The `alpha` channel currently points to `0.147.0-alpha.2` for both macOS
architectures. It is not the stable support target and is not treated as
validated merely because the v4 compatibility range has no upper ceiling.

### Required version-surface reconciliation

| Surface | DefenseClaw value | Comparison with stable `0.146.0` | Decision |
| --- | --- | --- | --- |
| Latest official macOS package | npm `latest`, `darwin-arm64`, and `darwin-x64`: `0.146.0` | Exact current stable release | **CURRENT upstream** |
| Version floors and ceilings | v1 `>=0.124.0,<0.129.0`; v2 `>=0.129.0,<0.133.0`; v3 `>=0.133.0,<0.145.0`; v4 `>=0.145.0`, no ceiling | `0.146.0` falls only in v4; no gap or overlap | **CURRENT compatibility** |
| `last_validated_version` | macOS value is empty | No version, date, or run URL supports certification | **UNCERTIFIED** |
| Versioned hook inventory | v4 has 11 events, adding observation-only `SessionEnd` | The `0.146.0` generated schema directory has the same 11 events; `SessionEnd` still has a three-second maximum | **CURRENT** |
| Discovery/version probe | `codex --version`; user `config.toml`; exact architecture-specific official npm native layout or OpenAI standalone release; selected real Mach-O is signature/quarantine/path/digest checked | Resolves current official macOS package layouts without treating a launcher symlink as executable authority | **CURRENT implementation; UNCERTIFIED run** |
| Extension discovery paths | User plus every repository `.agents/skills` layer from CWD to root, `/etc/codex/skills`, installed plugin cache and four official marketplace manifest forms, and system/user/project-layer `config.toml` for MCP | Matches the current documented/source-backed Codex surfaces; obsolete `.codex/skills` and project `.mcp.json` are excluded | **CURRENT** |
| Hook capabilities | Block on the declared prompt/tool/permission/post-tool/`SubagentStop`/`Stop` events; no native ask; session/compact start/end events observe only | `SubagentStop` and `Stop` block responses continue the agent/subagent; DefenseClaw deliberately does not use `continue:false` on session/compact lifecycle events | **CURRENT/LIMITED** |
| Native OTEL and correlation | Log exporter, metrics exporter, trace exporter, per-signal `/v1/<signal>`, scoped headers, W3C trace context | Matches the strict `0.146.0` `OtelConfigToml` and `codex-otel` source | **CURRENT** |

`supports_traceparent` describes DefenseClaw's correlation bridge and Codex's
native W3C trace context support. It does not claim that every Codex hook JSON
input contains a `traceparent`; the current generated hook schemas expose
`turn_id` on turn-scoped events instead.

## Current upstream and local evidence

The official [`@openai/codex` npm package](https://www.npmjs.com/package/@openai/codex)
and [OpenAI Codex `0.146.0` release](https://github.com/openai/codex/releases/tag/rust-v0.146.0)
were current on 2026-07-30. The npm release publishes native
`darwin-arm64` and `darwin-x64` packages. Codex `0.146.0` remains inside
DefenseClaw's open-ended `codex-hooks-v4` range; `0.145.0` introduced the
eleventh event, `SessionEnd`.

The registry metadata for `@openai/codex@0.146.0-darwin-arm64` resolved to
`codex-0.146.0-darwin-arm64.tgz` with integrity
`sha512-nb61yX4r5L6Z0dlC4o3u0GAK1YCd4TUvjaB382bajDoh84V+uv2hTBIVZ++fgXWV9yoeuNrNnNcn7GoTGOe2Tg==`.
This pins research provenance only; release promotion still requires the
durable gate below.

The audit host had an older standalone `codex-cli 0.145.0` arm64 binary. It was
a native Mach-O with a strict-valid Developer ID signature:

- identifier `codex`;
- Team ID `2DC432GLL2`;
- authority `Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)`;
- no `com.apple.quarantine` attribute.

An isolated npm install of the official `0.146.0-darwin-arm64` package also
reported `codex-cli 0.146.0`. Its native image was arm64 Mach-O, passed strict
code-signature verification with the same identifier/authority/Team ID, had no
quarantine attribute, and had SHA-256
`ae1d3ffe6d48aec6a4dc3f50e7eb8e0d11962485a6a9406c5a7012139383da02`.
The `0.146.0` help surface retained the expected commands and aliases.

Those static provenance and CLI checks establish current package shape, but
they are not a packaged DefenseClaw Setup or authenticated lifecycle run. The
macOS status is therefore **`preview`**, and no `last_validated_version` is
recorded.

## Twelve-surface matrix

| # | Acceptance surface | Classification | Result |
| --- | --- | --- | --- |
| 1 | Registry, discovery, version, platform | **I/B** | Go and Python classify Codex as available macOS preview. Discovery accepts only a native architecture-matching official npm layout or OpenAI standalone layout, probes `codex --version`, and binds version/path/SHA-256 in protected setup evidence. Promotion is blocked on a green latest-version record. |
| 2 | CLI, help, aliases | **I** | `defenseclaw setup codex`, shared setup flags, status, Doctor, repair, disable, and teardown retain the existing cross-platform aliases. The isolated official `0.146.0` CLI retained `exec`/`e`, `apply`/`a`, `mcp`, `plugin`, `app-server`, `doctor`, `completion`, `resume`, and `fork`. DefenseClaw does not wrap or replace them. |
| 3 | TUI, setup, status, repair | **I** | Codex remains selectable and is labeled preview on Darwin. Status/Doctor inspect the selected version, contract lock, managed config, scripts, credentials, native telemetry, and repairable drift. |
| 4 | complete Setup lifecycle and exact restoration | **I/B** | Existing transactional setup covers fresh install, idempotent setup, reconfigure, repair, rollback, upgrade, disable, and teardown. The persistent-macOS harness snapshots the exact Codex config, rejects link/non-regular inputs, preserves mode/content, and restores it even on failure. A latest packaged run proving the full lifecycle remains blocked. |
| 5 | versioned hook, notify, app-server contract | **I/L** | `>=0.145.0` selects `codex-hooks-v4`: 11 exact events. `SubagentStop` and `Stop` accept `decision:block` as feedback and continue execution; they are included in changed-file scanning. `SessionStart`, `PreCompact`, `PostCompact`, and `SessionEnd` remain observation-only in DefenseClaw even where Codex supports `continue:false`, because stopping lifecycle transitions is not exposed as a policy enforcement promise. Notify remains the documented agent-turn-complete channel. Effective managed requirements are read through the selected binary's `app-server` `configRequirements/read` RPC. Codex has no native hook-side ask. |
| 6 | native process and provenance | **I** | Setup resolves the selected file, rejects symlinks/non-regular files and unapproved ancestry, requires Mach-O magic, verifies `codesign --strict`, pins identifier/Team ID/authority, rejects quarantine, hashes the stable file, and executes argument vectors without a shell. Gatekeeper `spctl --type execute` is not used because this signed CLI is not an application bundle. |
| 7 | gateway, auth, lifecycle | **I** | Hook and OTLP credentials remain connector-scoped and protected, loopback routes are source-bound, and setup/repair/teardown rotate or revoke credentials. The selected executable contract is bound into the same lock used by reconcile. |
| 8 | Doctor, tamper, repair | **I** | Doctor passively checks config ownership, hook assets and digests, contract/version drift, selected executable path/digest/signature/quarantine, scoped authentication, and effective managed policy. Repair requires fresh trusted discovery after protected evidence becomes invalid or expires. |
| 9 | native OTEL, audit, correlation | **I/L** | Codex native logs, metrics, and traces route to `/v1/{logs,metrics,traces}` using a separate scoped header token. Hook, notify, and native telemetry retain connector/session/event/trace correlation into canonical v8 audit. Native OTLP does not make the hook connector an LLM proxy or a macOS sandbox. |
| 10 | official extension inventory | **I/L/N/A** | See the complete surface table below. Inventory is read-only outside DefenseClaw-owned config and runtime assets. The optional CodeGuard skill installer fetches the immutable, audit-reviewed upstream commit `a6aaed7bba31cfc68463fa5bb69e8ea24f9d5ad0` instead of mutable `main`. |
| 11 | docs, matrices, limits | **I** | Connector and compatibility docs identify the macOS preview state, current upstream version, signed executable trust boundary, exact restore behavior, hook/OTLP limits, and absence of proxy/sandbox/native ask claims. |
| 12 | deterministic, packaged, live, manual evidence | **I/B** | Deterministic Python and Go checks plus the existing macOS contract and upgrade-regression harnesses are implemented. `assert-macos-codex-evidence.py` rejects incomplete, wrong-architecture, unsigned, stale, unauthenticated, non-restoring, uncorrelated, or unnamed/incomplete artifact evidence. The validator is not yet invoked by a hosted packaged-live workflow, and no manifest from a latest `0.146.0` packaged authenticated run exists, so promotion is blocked. |

## Official extension inventory

The inventory paths and classifications follow the current official
[MCP](https://learn.chatgpt.com/docs/extend/mcp),
[skills](https://learn.chatgpt.com/docs/build-skills),
[plugins](https://learn.chatgpt.com/docs/plugins),
[rules](https://learn.chatgpt.com/docs/agent-configuration/rules),
[`AGENTS.md`](https://learn.chatgpt.com/docs/agent-configuration/agents-md),
[custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents),
and [custom prompts](https://learn.chatgpt.com/docs/custom-prompts) references.

| Surface | Classification | Inventory boundary |
| --- | --- | --- |
| Config | **I** | System and user config plus every trusted project `.codex/config.toml` layer from repository root through CWD; the nearest project layer wins. |
| Hooks, notify, native OTEL | **I/L** | Managed fields in Codex config plus protected DefenseClaw runtime assets; native ask is unavailable. |
| MCP | **I** | System, user, and every trusted-project `config.toml` MCP table; closest project entries win, with no invented `.mcp.json`. |
| Skills | **I/L** | Repository `.agents/skills` from the workspace toward the repo root, user `~/.agents/skills`, administrator `/etc/codex/skills`, and bundled system skills. Symlinked skill folders are official, so inventory may follow them read-only; executable admission never does. |
| Plugins | **I** | Installed cache `~/.codex/plugins/cache`; home/repository `.agents/plugins/{marketplace,api_marketplace}.json`; compatible `.claude-plugin/marketplace.json` and `.cursor-plugin/marketplace.json`; packages require `.codex-plugin/plugin.json`. |
| Rules | **I/L** | `.codex/rules` in active config layers, including user, trusted project, and administrator/requirements layers. |
| Instructions / `AGENTS.md` | **I/L** | `AGENTS.md`/fallback instruction discovery from the Codex home and workspace ancestry, with nearer files taking precedence. |
| Custom agents / subagents | **I** | User and project `.codex/agents/*.toml`; inventory requires `name`, `description`, and `developer_instructions`. Built-in agent roles are host-provided, not filesystem artifacts. |
| Separate microagents directory | **N/A** | Codex publishes custom agents/subagents, not a separate connector-owned microagents extension root. |
| Custom commands | **L** | Deprecated `~/.codex/prompts/*.md` exposed as `/prompts:<name>`; reusable workflows should migrate to skills. Built-in CLI commands are not inventoried as user extensions. |
| Legacy generic extensions directory | **N/A** | Codex publishes skills and plugins, not a generic `~/.codex/extensions` contract. |
| Separate memory files | **N/A** | Persistent instructions use `AGENTS.md`; DefenseClaw does not invent a separate Codex memory-file category. |

## Durable promotion gate

Promotion from preview requires a macOS run that:

1. requests npm `latest` and resolves the then-current official version;
2. records package integrity plus native binary SHA-256 and the exact OpenAI
   signing identity;
3. runs packaged DefenseClaw Setup, authenticated official Codex, action-mode
   block visibility, hook/notify/native-OTLP correlation, Doctor, repair, and
   teardown;
4. proves byte-for-byte content and exact mode restoration for the pre-run
   Codex config; and
5. retains hashed logs, JSONL, audit database, setup/status/Doctor output, and
   restoration/provenance reports.

The manifest must pass:

```bash
python3 scripts/live-connector-e2e/assert-macos-codex-evidence.py \
  --manifest /path/to/evidence.json \
  --expected-version 0.146.0
```

Synthetic, skipped, `continue-on-error`, older-version, or unhashed artifacts
cannot satisfy this gate.
