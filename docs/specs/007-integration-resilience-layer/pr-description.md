Introduces a technical specification for three new optional connector interfaces (`InterceptionVerifier`, `CredentialHydrator`, `CompatibilityProbe`) that address silent integration failures, centralized credential management, and version compatibility verification across all 14 supported connectors. No changes to the existing `Connector` interface.

## Problem

DefenseClaw's 14 connector integrations (OpenClaw, ZeptoClaw, Claude Code, Codex, Hermes, Cursor, Devin, Gemini CLI, Copilot, OpenHands, Antigravity, OpenCode, Amp, OmniGent) are tightly coupled to upstream agent internals — hardcoded file paths, config format assumptions, version-pinned response shapes, and transport layer monkey-patches. When any upstream agent releases a new version, DefenseClaw can break silently: LLM traffic flows unguarded, hook events stop arriving, or block verdicts are shaped incorrectly. There is no runtime detection of these failures, no centralized credential management across agents, and `validated_versions.json` is empty for every connector — no version has ever been programmatically certified as working.

## Current Situation

- **Observe/act pipeline fragility:** OpenClaw's fetch interceptor patches 5 Node.js transport layers (`globalThis.fetch`, `https.request`, `http.request`, `http.get`, undici dispatcher) but nothing verifies these patches remain intact. ZeptoClaw rewrites `api_base` in `config.json` but nothing detects when the user or agent overwrites it. Hook connectors register shell scripts or plugin artifacts but nothing confirms the agent actually invokes them.
- **No centralized credentials:** Each agent manages its own LLM provider API keys independently. `TokenResolverFunc` and `DisableLocalKeyResolution()` exist in `internal/gateway/token_resolver.go` but have no shipped implementation. ZeptoClaw's provider snapshot (captured at setup) goes stale when users rotate keys.
- **No version verification:** The hook contract system declares version bands per connector (e.g., Hermes v0.19.0–0.21.0, Codex v1–v4), but no automated test exercises real traffic at any version. The `doctor` command checks file presence, not pipeline health.
- **Cross-language drift:** The Python CLI (`connector_paths.py`, `claw_inventory.py`) and macOS app (`SkillScanner.swift`) reimplement all connector path resolution and config parsing instead of consuming the Go gateway's `ConnectorCapabilities`, `AgentPaths`, and `ConnectorLocations` structs.

## Solution

Three new **optional** connector interfaces in `internal/gateway/connector/resilience.go`, following the established pattern of the existing 18 optional interfaces (`HookProfileProvider`, `ComponentScanner`, `AllowedHostsProvider`, etc.):

### 1. `InterceptionVerifier` — Detect broken observe/act pipelines

Each connector probes its own interception mechanism and reports per-layer health:

- **Proxy connectors (OpenClaw):** Surface the existing TypeScript self-test results (5 transport layers) into Go. Report gaps when layers fail.
- **Proxy connectors (ZeptoClaw):** Read `config.json` and verify each provider's `api_base` still points at the proxy. Detect drift on config file changes via watcher.
- **Hook connectors (all 12):** Verify hook config file contains expected entries, hook scripts/plugin artifacts exist on disk, and are executable/readable.

Gateway runs verification at boot and on a configurable timer (default 60s). Gaps emit audit events and telemetry.

### 2. `CredentialHydrator` — Centralized API key management

Proxy connectors receive LLM provider keys from DefenseClaw instead of requiring per-agent configuration:

- **OpenClaw:** Keys stored in-memory, served via new `GET /v1/credentials/{provider}` endpoint. Fetch interceptor reads keys at intercept time.
- **ZeptoClaw:** Keys written to both in-memory snapshot and on-disk `config.json`. `RefreshSnapshot()` reloads on external changes.
- **Hook-only connectors:** Not applicable (no LLM traffic through proxy).

New API: `PUT/GET/DELETE /v1/credentials/{provider}` with X-DC-Auth authentication. In-memory only — no new secret files on disk.

### 3. `CompatibilityProbe` — Verify end-to-end health

Sends synthetic events through the full pipeline and reports four boolean results:

- **`Intercepting`** — Can DefenseClaw see the agent's traffic/events?
- **`Authenticating`** — Does the agent present valid credentials?
- **`Blocking`** — Does the agent honor block verdicts?
- **`Reporting`** — Do telemetry events arrive?

Per-connector verdict shape assertions:

| Connector | Expected block shape |
|-----------|---------------------|
| Hermes | `{"decision":"block","reason":"..."}` |
| Claude Code | `claude_code_output` with `result="deny"` |
| Codex | `codex_output` field |
| Cursor | Per-event `permission`/`deny`/`ask` |
| Copilot | `copilot_output` field |
| OpenCode, Amp | Empty JSON (plugin translates internally) |
| OmniGent | Empty JSON (Python policy translates) |
| Devin, OpenHands | Generic `hook_output` field |
| Antigravity | Antigravity-specific shape |

Wired into `defenseclaw doctor --verify-connector` and new `make connector-certify` CI target. Successful probes populate `validated_versions.json`.

### 4. Supporting changes

- **Connector metadata API** (`GET /v1/connectors/{name}/metadata`): Exposes `ConnectorCapabilities`, `AgentPaths`, `ConnectorLocations` so Python CLI and macOS app stop reimplementing connector logic.
- **Version-aware config profiles:** Each connector's hardcoded constants (home dir, config file, event lists, default URLs) move into version-indexed lookup structs. Unrecognized versions fall back to latest profile with a warning.
- **ZeptoClaw snapshot refresh:** Config file watcher triggers `RefreshSnapshot()` on changes, re-verifies `api_base` values, emits `zeptoclaw-config-drift` audit event on drift.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw Gateway                             │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Connector Registry (14 connectors)                           │   │
│  │                                                              │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │   │
│  │  │ OpenClaw   │  │ ZeptoClaw  │  │ Hook-only (12 conns)   │ │   │
│  │  │ (proxy)    │  │ (proxy)    │  │ claude,codex,hermes,   │ │   │
│  │  │            │  │            │  │ cursor,devin,copilot,  │ │   │
│  │  │            │  │            │  │ openhands,antigravity, │ │   │
│  │  │            │  │            │  │ opencode,amp,omnigent  │ │   │
│  │  └─────┬──────┘  └─────┬──────┘  └──────────┬─────────────┘ │   │
│  │        │               │                     │               │   │
│  │  ┌─────┴───────────────┴─────────────────────┴────────────┐  │   │
│  │  │              NEW: Optional Interfaces                   │  │   │
│  │  │                                                        │  │   │
│  │  │  InterceptionVerifier    CredentialHydrator             │  │   │
│  │  │  ┌──────────────────┐    ┌──────────────────┐          │  │   │
│  │  │  │ Proxy: probe 5   │    │ Proxy only:      │          │  │   │
│  │  │  │  transport layers│    │  OpenClaw: serve  │          │  │   │
│  │  │  │  or api_base     │    │   via /v1/creds   │          │  │   │
│  │  │  │ Hook: verify     │    │  ZeptoClaw: patch │          │  │   │
│  │  │  │  config entries  │    │   config + snap   │          │  │   │
│  │  │  │  + scripts/arts  │    │ Hook: N/A         │          │  │   │
│  │  │  └──────────────────┘    └──────────────────┘          │  │   │
│  │  │                                                        │  │   │
│  │  │  CompatibilityProbe                                    │  │   │
│  │  │  ┌──────────────────────────────────────────────────┐  │  │   │
│  │  │  │ Synthetic event → full pipeline → ProbeResult    │  │  │   │
│  │  │  │ {Intercepting, Authenticating, Blocking,         │  │  │   │
│  │  │  │  Reporting, Failures[]}                          │  │  │   │
│  │  │  │ → doctor --verify-connector                      │  │  │   │
│  │  │  │ → validated_versions.json                        │  │  │   │
│  │  │  └──────────────────────────────────────────────────┘  │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐    │
│  │ CredentialStore   │  │ NEW: API Endpoints                   │    │
│  │ (in-memory)       │  │  GET/PUT/DELETE /v1/credentials/{p}  │    │
│  │ provider → key    │◄─┤  GET /v1/connectors/{name}/metadata  │    │
│  └──────────────────┘  └──────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Existing (UNCHANGED)                                         │   │
│  │  Connector interface ─ 18 optional interfaces ─ Registry     │   │
│  │  ConnectorSignals ─ HookProfile ─ TokenResolverFunc          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## What Changed (Where & How)

| File | Summary |
| --- | --- |
| `docs/specs/007-integration-resilience-layer/README.md` | New spec index page with status and file links |
| `docs/specs/007-integration-resilience-layer/requirements.md` | 32 EARS requirements (REQ-01–32) across 6 areas: interception verification, credential hydration, compatibility probing, metadata API, version-aware config, ZeptoClaw snapshot refresh. 12 acceptance criteria with full traceability. |
| `docs/specs/007-integration-resilience-layer/design.md` | Three Go interface definitions with types. Per-connector implementation matrix for all 14 connectors. Four data flow diagrams (interception verification, credential hydration, compatibility probing, metadata API). Four new API endpoints. Tradeoffs and risk analysis. |
| `docs/specs/007-integration-resilience-layer/plan.md` | 5-phase rollout (proxy connectors → hook connectors → metadata API → doctor/CI → extension transport negotiator). Scope boundaries, observability plan (4 metrics, 3 audit events), security plan with threat model for credential endpoint. |
| `docs/specs/007-integration-resilience-layer/tasks.md` | 26 ordered tasks mapped to requirements. Test plan with unit, integration, and per-connector golden fixtures (38 new golden files across 13 connectors). CI integration via `make connector-certify`. |

## Breaking Changes

None. This PR is a spec-only addition. All proposed interfaces are optional — connectors that do not implement them continue to work unchanged. No existing interfaces, endpoints, configs, or workflows are modified.

## Open Issues / Follow-ups

- Enterprise cloud credential push channel (external source → `PUT /v1/credentials/{provider}`) is out of scope; needs its own spec for cloud-to-sidecar key delivery
- macOS Swift app refactor to consume `GET /v1/connectors/{name}/metadata` deferred; Python CLI demonstrates the pattern first
- Automated credential rotation scheduling (TTL-based re-push) deferred; this spec builds the hydration infrastructure only
- Windsurf connector (legacy/removed from registry) is excluded from the implementation matrix

## Test Plan

Spec-only PR — no code changes to test. Verification:

```bash
# Confirm all 5 spec files are present and well-formed
ls docs/specs/007-integration-resilience-layer/
# README.md  design.md  plan.md  requirements.md  tasks.md

# Confirm no code files changed
git diff --stat main..spec/007-integration-resilience-layer
# 5 files changed, 1385 insertions(+)
# All under docs/specs/007-integration-resilience-layer/

# Confirm requirements trace to architecture
grep -c "REQ-" docs/specs/007-integration-resilience-layer/requirements.md
# 32 requirements

# Confirm tasks map to requirements
grep -c "Maps to:" docs/specs/007-integration-resilience-layer/tasks.md
# 26 task-to-requirement mappings

# Confirm all 14 connectors covered in design matrix
grep -c "openclaw\|zeptoclaw\|claudecode\|codex\|hermes\|cursor\|devin\|geminicli\|copilot\|openhands\|antigravity\|opencode\|amp\|omnigent" docs/specs/007-integration-resilience-layer/design.md
# 14 connectors referenced
```

Review checklist:
- [ ] Requirements are testable (each REQ has a corresponding AC)
- [ ] Interface definitions are compatible with all 14 connector struct types
- [ ] No contradiction with existing hook contracts or connector capabilities
- [ ] Per-connector verdict shapes match `HookProfile.Respond` output in code
- [ ] Security plan addresses credential endpoint threat surface
