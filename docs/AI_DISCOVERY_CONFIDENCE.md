# AI Discovery Confidence Engine

DefenseClaw's AI inventory pipeline does not just say "OpenAI Python SDK installed". For every deduped component it produces two scores:

- **`identity_score`** — the probability that this component really is what we think it is (e.g. *this really is `openai==1.45.0`*, not a same-named library that happens to share a basename).
- **`presence_score`** — the probability that the component is actually installed and reachable *now*, not just mentioned somewhere stale.

Both scores live in `[0, 1]`, are mapped to one of five operator-friendly bands (`very_high`, `high`, `medium`, `low`, `very_low`), and ship with a per-evidence breakdown so an operator can answer "why 92% and not 99%?" without reading source.

This document describes the algorithm, the inputs, the policy file that calibrates it, and the operator surface (CLI commands, API endpoints, persistent SQL store).

---

## TL;DR

```
ContinuousDiscoveryService.classifyAndPersist
        │
        ├──→ aiStateFile.json    (fast hydration, kept for v1+v2 back-compat)
        │
        └──→ inventory.db
                  ├── ai_scans                  (one row per scan)
                  ├── ai_signals                (one row per detected signal)
                  └── ai_confidence_snapshots   (one row per (scan, component))
                                                            │
                                       inventory.ComputeComponentConfidence
                                                            │
                                                            └── reads confidence_policy.yaml
```

The Bayesian engine is a pure function of `[]AISignal + now + ConfidenceParams`, so the same inputs always produce the same output. Tunable knobs live in `internal/inventory/confidence_policy.yaml` (embedded by default; operators can override on disk).

---

## Why two axes?

A single confidence number conflates two questions an operator actually needs to answer separately:

| Scenario | Identity | Presence |
|---|---|---|
| Lockfile mentions `openai==1.45.0` in a workspace nobody touches | very_high | very_low |
| Live `python` process matches our catalog comm but no manifest evidence | medium | very_high |
| Lockfile + binary on disk + live PID, all consistent | very_high | very_high |
| Two lockfiles on disk disagree on the OpenAI version | medium (penalty fires) | high |

A flat 78% would fail to distinguish the first row from the third. The two-axis output lets the CLI render `identity=very_high (96%)  presence=very_low (12%)` and lets an operator filter with `--min-presence 0.8` for "what's actually running right now".

---

## Algorithm

The engine is a **Bayesian log-odds combination of likelihood ratios**, with per-evidence quality and recency multipliers, and explicit negative-signal penalties.

### Inputs

For one component (group of signals sharing `(ecosystem, name)`):

- `signals []AISignal` — every detection that contributed to this rollup. Each signal carries:
  - `Detector` — stable identifier (e.g. `process`, `package_manifest`, `binary`, …) — keys into `confidence_policy.yaml`.
  - `Evidence []AIEvidence` — basenames + path hashes + workspace hashes + per-evidence `Quality` (0..1) and `MatchKind` (`exact|substring|heuristic`).
  - `LastActiveAt *time.Time` — used for presence recency decay.
- `now time.Time` — caller-supplied so the engine stays trivially testable; in production it's `time.Now().UTC()`.
- `params ConfidenceParams{ Policy ConfidencePolicy }` — loaded from the YAML below.

### The math

Given a prior probability `p`, the corresponding logit is `ln(p / (1 - p))`. The engine starts each axis at the policy's prior:

```
logit_identity₀ = logit(prior_identity)   # default: max(curator_confidence) over signals
logit_presence₀ = logit(prior_presence)   # default: 0.05
```

Then for every `(detector, evidence)` pair, we accumulate a contribution:

```
identity_factor = quality * specificity                        # both in [0, 1]
adj_identity_lr = identity_lr ^ identity_factor

presence_factor = quality * recency
adj_presence_lr = presence_lr ^ presence_factor

logit_identity += ln(adj_identity_lr)
logit_presence += ln(adj_presence_lr)
```

Where:

- `identity_lr`, `presence_lr` come from the per-detector row in the policy file (see *Calibration* below).
- `quality` is per-evidence (`AIEvidence.Quality`): 1.0 for exact matches, 0.6 for substring matches, 0.5 for heuristic matches, 0.4 for transitive lockfile entries, etc.
- `specificity` is per-signature (`AISignature.Specificity`): how distinctive this catalog match is (default 0.7 when a legacy signature didn't set it).
- `recency` is a continuous logistic decay on hours since `LastActiveAt`:

```
recency = exp(-ln(2) * hours_since_active / half_life_hours)
```

  Default `half_life_hours = 168` (7 days). Identity does **not** decay — an SDK that hasn't been used in a year is still the same SDK; only its presence weakens.

### Penalties

Negative signals subtract from the relevant axis's logit:

| Penalty | Axis | Default logit |
|---|---|---|
| `version_conflict` (lockfiles disagree on version) | identity | `-1.5` |
| `stale_binary` (binary present, no process, mtime > 90d) | presence | `-2.0` |
| `signature_collision` (n signatures match the same string) | identity | `-0.5 × (n − 1)` |
| `weak_evidence_only` (env-var or shell-history only) | presence | `-1.0` |
| `heuristic_only` (no exact match anywhere) | both | `-0.7` |

### Final score

```
identity_score = sigmoid(logit_identity)   = 1 / (1 + exp(-logit_identity))
presence_score = sigmoid(logit_presence)
```

The sigmoid keeps both scores in `(0, 1)` even when the accumulated logit is large in magnitude — independent evidence multiplies on the odds scale, but the probability output stays well-behaved at the ends. This is the property the previous additive design lacked: it saturated at 1.0 and lost discrimination exactly where operators need it.

### Bands

Each score is mapped to a label by the first matching band:

| Band | Min score |
|---|---|
| `very_high` | `>= 0.95` |
| `high` | `>= 0.80` |
| `medium` | `>= 0.60` |
| `low` | `>= 0.30` |
| `very_low` | otherwise |

Bands are configured in `confidence_policy.yaml` so operators can tighten them without recompiling.

### Explainability — `agent confidence explain NAME`

The engine returns each evidence row as a `ConfidenceFactor`:

```go
type ConfidenceFactor struct {
    Detector    string  // "process", "package_manifest", …
    EvidenceID  string  // "pyproject.toml#openai", "pid=1234"
    MatchKind   string  // "exact" | "substring" | "heuristic"
    Quality     float64 // per-evidence
    Specificity float64 // per-signature (or recency for presence factors)
    LR          float64 // detector LR from policy
    LogitDelta  float64 // signed contribution to the logit
}
```

`ConfidenceFactor.PercentagePointShift(score)` converts `LogitDelta` to a percentage-point shift in the underlying probability *at the current score*, using the local derivative of sigmoid (`P*(1-P)`). The CLI uses this so an operator sees `+12.4pp` rather than raw log-odds.

```
$ defenseclaw agent confidence explain openai --ecosystem pypi
Confidence: openai (pypi)
  identity=very_high (96%)  presence=very_high (91%)

Identity factors
  Detector          Evidence                    Match     Quality  Spec/Recency  LR     Logit Δ  Shift
  package_manifest  pyproject.toml#openai       exact     1        0.85          30     3.4      +12.4pp
  process           pid=1234                    exact     1        1             8      2.1      +0.7pp

Presence factors
  Detector          Evidence                    Match     Quality  Spec/Recency  LR     Logit Δ  Shift
  process           pid=1234                    exact     1        1             250    5.5      +67.5pp
  package_manifest  pyproject.toml#openai       exact     1        0.85          5      1.4      +18.8pp
```

---

## Calibration: `confidence_policy.yaml`

The policy is embedded via `//go:embed` and lives at `internal/inventory/confidence_policy.yaml`. The defaults ship as:

```yaml
version: 1

priors:
  identity: signature        # use per-signature curator_confidence as the prior
  presence: 0.05             # base rate — most boxes do not have most SDKs

half_life_hours: 168         # 7-day half-life on presence recency decay

detectors:
  process:          { identity_lr: 8,  presence_lr: 250 }
  package_manifest: { identity_lr: 30, presence_lr: 5 }
  binary:           { identity_lr: 10, presence_lr: 50 }
  mcp:              { identity_lr: 20, presence_lr: 15 }
  config:           { identity_lr: 15, presence_lr: 8 }
  local_endpoint:   { identity_lr: 12, presence_lr: 200 }
  editor_extension: { identity_lr: 12, presence_lr: 10 }
  application:      { identity_lr: 10, presence_lr: 6 }
  env:              { identity_lr: 3,  presence_lr: 1.5 }
  shell_history:    { identity_lr: 4,  presence_lr: 2 }

penalties:
  version_conflict:    { axis: identity, logit: -1.5 }
  stale_binary:        { axis: presence, logit: -2.0 }
  signature_collision: { axis: identity, logit: -0.5, scale_with_count: true }
  weak_evidence_only:  { axis: presence, logit: -1.0 }
  heuristic_only:      { axis: both,     logit: -0.7 }

bands:
  - { min: 0.95, label: very_high }
  - { min: 0.80, label: high }
  - { min: 0.60, label: medium }
  - { min: 0.30, label: low }
  - { min: 0.00, label: very_low }
```

### Override path

If `~/.defenseclaw/confidence.yaml` exists (or the path pointed to by `ai_discovery.confidence_policy_path`), the loader **deep-merges** it on top of the embedded default:

- Override of one detector's `identity_lr` leaves all other detectors untouched.
- Override of `bands` is replaced wholesale (partial band lists almost always indicate operator confusion).
- Unknown top-level keys, unknown detectors, or unknown penalty names are rejected as typos. There is no silent fallback — if the file fails to validate, the loader returns an error and the gateway fails to construct the discovery service (the operator sees the error at boot, not three days later when a score looks wrong).

### Operator workflow

```bash
# Print the embedded default as a starting template.
defenseclaw agent confidence policy default > ~/.defenseclaw/confidence.yaml

# Edit values, then dry-run validate before restarting the gateway.
$EDITOR ~/.defenseclaw/confidence.yaml
defenseclaw agent confidence policy validate ~/.defenseclaw/confidence.yaml

# Inspect the merged (effective) policy the engine is using.
defenseclaw agent confidence policy show
```

Hot-reload is intentionally out of scope for v1 — policy is loaded once at sidecar boot, matching every other config knob's lifecycle.

---

## Persistent history (`inventory.db`)

The SQLite store at `~/.defenseclaw/inventory.db` (separate from `audit.db` so retention is independent) has three tables and one view:

| Table | What it holds |
|---|---|
| `ai_scans` | One row per scan envelope (id, scanned_at, duration, total_signals). |
| `ai_signals` | One row per detected signal, including the JSON-encoded evidence and runtime blocks. |
| `ai_confidence_snapshots` | One row per (scan, component) with both axes' scores, bands, and the factor JSON. Powers the history view. |

`ai_components_v` is a SQL view that aggregates `ai_signals` against the most-recent `ai_confidence_snapshots` row per `(ecosystem, name)`. The gateway's `/api/v1/ai-usage/components` endpoint computes the rollup in memory (see `rollupComponents` in `internal/gateway/ai_usage.go`); the view exists for ad-hoc operator inspection via the `sqlite3` CLI (e.g. `sqlite3 inventory.db "select * from ai_components_v"`). The v2 schema migration rebuilds the view with `LOWER()` on both sides of the JOIN so mixed-case ecosystems like `PyPI` resolve to their lowercased confidence rows.

Writes happen at the **end** of `classifyAndPersist`, in a single transaction, after the JSON `aiStateFile` write succeeds. Inventory persistence is best-effort by design; if the SQL store can't be opened (e.g. read-only filesystem), the gateway logs a warning and continues without it — every endpoint that depends on the store falls back to the in-memory snapshot or returns `enabled=false`.

---

## Privacy contract

The engine and rollup respect two existing flags:

| Flag | Default | Effect on confidence surface |
|---|---|---|
| `ai_discovery.store_raw_local_paths` | `false` | When `false`, raw paths are never persisted to `aiStateFile.json` or `inventory.db`. Locations always include path hashes + workspace hashes; the raw path is simply absent. |
| `privacy.disable_redaction` | `false` | When `false`, raw paths and full evidence records are stripped from outbound payloads (gateway events, OTel logs, webhooks) regardless of what was captured to disk. |

**Raw paths only ever surface (in the CLI, in the API, on the wire) when both flags are `true`.** This matches how `disable_redaction` already behaves for the audit DB, OTel logs, and webhook sinks.

---

## OTel / OTLP emissions

The two-axis engine surfaces every scored component on three OTel paths so dashboards (metrics) and SIEMs (logs) and downstream automation (gateway events / webhooks) can all act on the same numbers without re-running the engine.

### Metrics (per scan, per component)

Cardinality is bounded by the discovered component set (typically tens to low hundreds per host), not by signal volume.

| Instrument | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `defenseclaw.ai.components.observations` | Int64Counter | `{observation}` | `ecosystem`, `name`, `identity_band`, `presence_band` | One increment per scan that scored this component. Use to graph "components in `presence_band=very_low` over time". |
| `defenseclaw.ai.components.installs` | Int64Gauge | `{install}` | `ecosystem`, `name` | Distinct install evidences as of the latest scan. |
| `defenseclaw.ai.components.workspaces` | Int64Gauge | `{workspace}` | `ecosystem`, `name` | Distinct workspace_hash values for this component as of the latest scan. |
| `defenseclaw.ai.confidence.identity_score` | Float64Histogram | `1` | `ecosystem`, `name`, `framework` | Calibrated identity score in `[0,1]`. One sample per component per scan. |
| `defenseclaw.ai.confidence.presence_score` | Float64Histogram | `1` | `ecosystem`, `name`, `framework` | Calibrated presence score in `[0,1]`. One sample per component per scan. |

Score values are clamped to `[0,1]` on the way out so a future calibration bug can't poison the `+Inf` bucket; `NaN` becomes `0`.

The pre-existing per-signal metrics (`defenseclaw.ai.discovery.runs`, `defenseclaw.ai.discovery.signals`, `defenseclaw.ai.discovery.errors`, etc.) are unchanged — the new component instruments are additive.

### Logs (event-driven, not per scan)

| Event name | When | Severity |
|---|---|---|
| `defenseclaw.ai.discovery` | Once per scan with the run summary. | `INFO` (`WARN` if any detector returned an error) |
| `defenseclaw.ai.discovery.signal` | Per signal in `state ∈ {new, changed, gone}`. | `INFO` |
| `defenseclaw.ai.confidence.component` | Per component when at least one signal in the group has `state ∈ {new, changed, gone}`. | `INFO` (`WARN` when `identity_score ≥ 0.7` AND `presence_score ≤ 0.2` — the "SDK was removed but manifest is still around" pattern) |

`defenseclaw.ai.confidence.component` carries: `ai.component.{ecosystem,name,framework,install_count,workspace_count,detector_count}`, `ai.confidence.{identity_score,identity_band,presence_score,presence_band,policy_version}`, plus `event.domain="defenseclaw.ai_visibility"` for SIEM filtering.

The component-level log is gated to lifecycle changes only so a steady-state monorepo doesn't flood the SIEM; the metrics path always emits so dashboards see the current confidence distribution every scan.

### Gateway events / webhook sinks

When `privacy.disable_redaction=true`, every per-signal `AIDiscoveryPayload` on the gateway events bus is enriched with the component's identity / presence scores, bands, factor breakdowns, and detector list. All signals in the same `(ecosystem, name)` group ship the same scores so receivers can dedupe on those keys without re-running the engine.

When `disable_redaction=false` (the shipping default) the payload omits every confidence field — receivers can rely on the absence of `identity_score` to mean "redaction is on".

`raw_paths` and per-evidence `raw_path` additionally require `ai_discovery.store_raw_local_paths=true`, matching the existing privacy-flag composition.

### Cross-emitter consistency

Both the OTel histogram samples (`defenseclaw.ai.confidence.{identity,presence}_score`) and the per-signal gateway payload (`payload.identity_score`, `payload.presence_score`) come from a single `componentRollupSnapshot` computed once per scan. The snapshot pins the engine's `now` value so the recency-decayed presence factor produces byte-identical numbers across both paths — operators reconciling a Prometheus query with a Splunk lookup of the gateway events bus see no drift.

In default-config installs (no OTel, redaction enabled) the snapshot is skipped entirely so we don't pay for confidence math whose result both consumers would discard.

---

## API surface

| Endpoint | Returns |
|---|---|
| `GET /api/v1/ai-usage` | All raw signals from the latest scan (the unfiltered fan-out — used by `agent usage`). |
| `POST /api/v1/ai-usage/scan` | Trigger an immediate scan and return the report (used by `--refresh`). |
| `GET /api/v1/ai-usage/components` | The deduped component rollup (one row per `(ecosystem, name)`) including identity/presence scores + bands + factor breakdowns. |
| `GET /api/v1/ai-usage/components/{ecosystem}/{name}/locations` | Per-install location detail (one row per evidence record). |
| `GET /api/v1/ai-usage/components/{ecosystem}/{name}/history` | Up to 50 confidence snapshots, most-recent-first. |
| `GET /api/v1/ai-usage/confidence/policy?source=merged\|default` | Active confidence policy (merged or embedded default). |
| `POST /api/v1/ai-usage/confidence/policy/validate` | Dry-run a candidate policy. Body MUST be a JSON envelope `{"yaml": "<raw policy YAML>"}` with `Content-Type: application/json` (the `policy` key is accepted as an alias). The wire is JSON — not raw `application/x-yaml` — because the sidecar's CSRF gate rejects every non-OTLP POST that doesn't advertise `application/json`. Returns `{valid, version, error}`. |

All endpoints are gated by the existing sidecar token + CSRF protection.

Example (the same call the CLI's `agent confidence policy validate` makes):

```bash
curl -sS -X POST \
  -H "Authorization: Bearer ${DEFENSECLAW_GATEWAY_TOKEN}" \
  -H "X-DefenseClaw-Client: curl" \
  -H "Content-Type: application/json" \
  --data "$(jq -Rs '{yaml: .}' < ~/.defenseclaw/confidence.yaml)" \
  http://127.0.0.1:18970/api/v1/ai-usage/confidence/policy/validate \
  | jq -e '.valid'
```

---

## CLI surface

See [docs/CLI.md](CLI.md) for the full table. Quick reference:

```bash
# Listing — default view, with two-axis confidence + detector columns.
defenseclaw agent components

# Filter by score (great for triage).
defenseclaw agent components --min-identity 0.8 --min-presence 0.5

# Drill into one component.
defenseclaw agent components show openai --ecosystem pypi

# Trend over time.
defenseclaw agent components history openai --ecosystem pypi --limit 10

# Why is this 92% and not 99%?
defenseclaw agent confidence explain openai --ecosystem pypi

# Tune the policy.
defenseclaw agent confidence policy default > ~/.defenseclaw/confidence.yaml
$EDITOR ~/.defenseclaw/confidence.yaml
defenseclaw agent confidence policy validate ~/.defenseclaw/confidence.yaml
defenseclaw agent confidence policy show
```

---

## Backward compatibility

- **State file** — the v2 `aiStateFile.json` schema is unchanged; the engine just reads richer fields out of it. v1 files are still loaded in degraded mode (no per-evidence quality, no specificity).
- **Catalog** — legacy signatures with only the flat `confidence` field are auto-upgraded: `curator_confidence` defaults to that value, `specificity` defaults to 0.7. No catalog edits are required to ship the engine; tighten signatures opportunistically.
- **Rollup payload** — the gateway's `componentRollup` JSON keeps every existing field. New fields (`identity_score`, `identity_band`, `presence_score`, `presence_band`, `identity_factors`, `presence_factors`, `locations`, `detectors`) are all `omitempty`. Older sidecars therefore round-trip cleanly through new clients; the new CLI hides the confidence columns when the payload doesn't carry them.
- **Wire payloads** — `AIDiscoveryPayload` extensions (Phase 7) are gated by `privacy.disable_redaction`. Default-config installs see the same JSON they always saw on the gateway-events bus and OTel logs.
