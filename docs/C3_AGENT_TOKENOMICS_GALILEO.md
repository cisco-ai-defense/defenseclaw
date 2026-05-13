# Cisco Cloud Control Tokenomics + Galileo Runtime Governance Demo

This demo adds a thin Cisco Cloud Control-facing bridge for the executive Agent
Tokenomics view. It keeps Splunk Observability as the source of truth for
tokenomics and adds Galileo as an optional runtime controls and eval enrichment
layer.

The repo still uses `c3` in some live identifiers, paths, modules, and demo
endpoints, such as `/v1/c3/agent-tokenomics/summary` and
`c3-agent-tokenomics-demo`. In demo narration, read `c3` as Cisco Cloud
Control.

## Customer story

> O11y shows which agents, models, services, and workflows are consuming tokens.
> Galileo evaluates and controls what the agents actually do at runtime. Cisco
> Cloud Control gives executives one management-plane governance surface.

## Cisco Cloud Control fit

[Cisco Cloud Control](https://cloud.cisco.com/) is positioned as a unified
management experience for Cisco products and beyond. In the security domain,
[Cisco Security Cloud Control](https://www.cisco.com/c/en/us/products/collateral/security/security-cloud-control/security-cloud-control-faq.html)
centralizes management, visibility, and automation across Cisco security
products, including Cisco AI Defense. The
[Security Cloud Control API](https://developer.cisco.com/docs/security-cloud-control/)
documents programmatic management for organizations, users, roles, network
objects, and integrated products such as AI Defense.

This repo does not call Cisco Cloud Control or Security Cloud Control APIs
directly. The demo bridge models the server-side payload a Cisco Cloud
Control-native experience could consume: Splunk Observability token usage plus
Galileo and Agent Control governance evidence. That keeps credentials and raw
telemetry server-side while exposing a concise executive rollup.

The base endpoint remains:

```http
GET /v1/c3/agent-tokenomics/summary
```

The Galileo-enriched view is opt-in:

```http
GET /v1/c3/agent-tokenomics/summary?include_galileo=true
```

When `include_galileo=false`, the response is the O11y-only tokenomics DTO.
When `include_galileo=true`, the response adds:

- top-level `galileo` rollups
- per-agent `top_agents[].galileo` runtime summaries
- `runtime_governance_cards` for the four Cisco Cloud Control executive cards
- `runtime_governance_evidence` for the evidence table
- an executive banner that explains the O11y + Galileo + Cisco Cloud Control split

## Data sources and ownership

| Data | Source of truth | Cisco Cloud Control use |
|------|-----------------|--------|
| Token counts, token mix, models, services, traces | Splunk Observability / SignalFlow | KPI cards, top-agent/model tables, token pressure |
| Trace summaries, runtime evals, Agent Control decisions | Galileo | Runtime controls cards and governance evidence table |
| Unified executive view | Cisco Cloud Control-native app | One page for agent cost, behavior, and runtime governance |

The Cisco Cloud Control browser experience must not receive O11y or Galileo API
keys. This bridge is a server-side BFF shape only.

## Cisco Cloud Control visual additions

The existing tokenomics page should keep the O11y KPI row and add a second row:

1. **Runtime Controls** - `galileo.runtime_control_events`
2. **Blocked Unsafe Actions** - `galileo.denies`
3. **Human Reviews** - `galileo.human_reviews`
4. **Failed Runtime Evals** - `galileo.failed_evals`

Add a table named **Runtime Governance Evidence** backed by
`runtime_governance_evidence`:

| Column | Field |
|--------|-------|
| Agent | `agent_name` |
| Decision | `decision` |
| Severity | `severity` |
| Reason | `reason` |
| Target / Tool | `target` and `action` |
| Token pressure | `token_pressure.tokens`, `token_pressure.percentage_of_total`, `token_pressure.rank` |
| Trace link | `deep_link` |

## Join strategy

Galileo enrichment joins to O11y rows in this order:

1. `trace_id`
2. `session_id` / `gen_ai.conversation.id`
3. `agent_name` / `gen_ai.agent.name`

The response includes `join_key` on each governance evidence row so the UI can
annotate lower-confidence joins later without changing the DTO.

## Local commands

Generate the O11y-only response:

```bash
PYTHONPATH=cli python -m defenseclaw.c3_agent_tokenomics.cli \
  --tenant-id c3-demo-tenant \
  --workspace-id wayne-demo \
  --output artifacts/c3_agent_tokenomics_o11y.json
```

Generate the O11y + Galileo response:

```bash
PYTHONPATH=cli python -m defenseclaw.c3_agent_tokenomics.cli \
  --tenant-id c3-demo-tenant \
  --workspace-id wayne-demo \
  --include-galileo \
  --output artifacts/c3_agent_tokenomics_with_galileo.json
```

Use the DefenseClaw CLI wrapper:

```bash
PYTHONPATH=cli python -m defenseclaw.main c3-tokenomics generate \
  --include-galileo \
  --output artifacts/c3_agent_tokenomics_with_galileo.json
```

Serve the mock BFF for Cisco Cloud Control frontend wiring:

```bash
PYTHONPATH=cli python -m defenseclaw.c3_agent_tokenomics.mock_api --port 8787
curl http://127.0.0.1:8787/healthz
curl 'http://127.0.0.1:8787/v1/c3/agent-tokenomics/summary?include_galileo=true'
```

## Environment knobs

| Variable | Use |
|----------|-----|
| `TOKENOMICS_DEMO_FIXTURE_PATH` | Override packaged O11y metric rows fixture |
| `TOKENOMICS_DEMO_ALLOW_FIXTURE_FALLBACK` | Stage-demo fallback guard; defaults to `true` |
| `GALILEO_RUNTIME_CONTROLS_FIXTURE_PATH` | Override packaged Galileo runtime controls fixture |
| `O11Y_REALM` | Fill O11y deep-link host, for example `us0` |
| `GALILEO_API_BASE` | Galileo API host; defaults to `https://api.galileo.ai` |
| `GALILEO_API_KEY` | Server-side Galileo API key for live checks; never returned to browser |
| `GALILEO_PROJECT` | Galileo project name; repo default is `clus-demo` |
| `GALILEO_PROJECT_ID` | Galileo project UUID; repo default is `0ba7b20d-8262-44c4-b230-547a0cd74b2b` |
| `GALILEO_LOG_STREAM` | Galileo log stream name; repo default is `clus-demo` |
| `GALILEO_LOG_STREAM_ID` | Galileo log stream UUID; repo default is `82b893bd-fa1f-411e-81e8-e12ca66692ad` |

## Galileo credential check

Local fixture-backed generation can incorporate the project/log-stream metadata
without storing credentials:

```bash
export GALILEO_API_KEY="<redacted>"
export GALILEO_PROJECT="clus-demo"
export GALILEO_PROJECT_ID="0ba7b20d-8262-44c4-b230-547a0cd74b2b"
export GALILEO_LOG_STREAM="clus-demo"
export GALILEO_LOG_STREAM_ID="82b893bd-fa1f-411e-81e8-e12ca66692ad"
PYTHONPATH=cli python -m defenseclaw.main c3-tokenomics generate \
  --include-galileo \
  --output artifacts/c3_agent_tokenomics_with_galileo.json
```

To verify the key can resolve the configured project, run a live server-side
check. The command prints only safe status and project metadata, not the API key.

```bash
PYTHONPATH=cli python -m defenseclaw.main c3-tokenomics galileo-check --live
```

## SignalFlow starting points

Confirm the exact metric names and dimensions in the demo org's Metric Finder.
The fixture-backed transform expects rows equivalent to these rollups:

```python
# Total tokens by type
A = data('gen_ai.client.token.usage', rollup='sum').sum(by=['gen_ai.token.type']).publish(label='tokens_by_type')
```

```python
# Tokens by agent/model/provider/type
A = data('gen_ai.client.token.usage', rollup='sum').sum(by=['gen_ai.agent.name', 'gen_ai.request.model', 'gen_ai.provider.name', 'gen_ai.token.type']).publish(label='tokens_by_agent_model')
```

```python
# Duration pressure by agent/model when available
A = data('gen_ai.client.operation.duration', rollup='average').mean(by=['gen_ai.agent.name', 'gen_ai.request.model']).publish(label='operation_duration')
```

## Kubernetes demo path

`deploy/k8s/defenseclaw/c3-agent-tokenomics-demo.yaml` adds a hardened,
fixture-backed Cisco Cloud Control BFF deployment that can sit beside the
live-derived DefenseClaw lab manifests. It uses the pinned ECR image currently
running in the Isovalent demo cluster and does not embed any API keys. The
ConfigMap carries safe defaults such as
`O11Y_REALM=us1`, `GALILEO_PROJECT=clus-demo`, and
`GALILEO_PROJECT_ID=0ba7b20d-8262-44c4-b230-547a0cd74b2b`; it also pins the
demo log stream ID. The API key comes from an optional Secret:

```bash
kubectl -n defenseclaw create secret generic c3-agent-tokenomics-galileo \
  --from-literal=GALILEO_API_KEY="$GALILEO_API_KEY"
```

Keep the Cisco Cloud Control frontend pointed at the BFF service, not at Galileo
directly.

The demo HTTP surface is exposed as a Kubernetes `LoadBalancer` Service so a
browser-facing Cisco Cloud Control UI or test client can reach it in EKS. Future
API-only dependencies should remain `ClusterIP` unless they serve a user-visible
UI.

## Acceptance criteria

- The service returns a non-empty O11y-backed tokenomics payload.
- Missing optional dimensions become `unknown` rather than endpoint failures.
- `include_galileo=true` returns runtime-control cards and governance evidence.
- The runtime governance evidence includes deny, steer, warn, and human-review outcomes.
- O11y and Galileo credentials remain server-side.
- Dollar cost is not treated as authoritative; token counts are the demo source of truth.
