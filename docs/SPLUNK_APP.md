# DefenseClaw Splunk App

The bundled local Splunk workflow installs a Splunk app named
`DefenseClaw Local Mode` automatically.

The app gives users a purpose-built investigation surface for `DefenseClaw` and
`OpenClaw` activity. It is not a general Splunk deployment guide, and it is
not a replacement for direct Splunk Observability Cloud setup. It is a local,
single-instance investigation surface for development, testing, and security
workflow validation.

For an existing remote Splunk Enterprise deployment, use
`defenseclaw setup splunk --enterprise` instead. That path forwards audit
events to an existing HEC endpoint and does not install this local Splunk app.

For the legal and local-scope guardrails for this workflow, see
[INSTALL.md](INSTALL.md).

## Access

When you run:

```bash
defenseclaw setup splunk --logs --accept-splunk-license --non-interactive
```

`DefenseClaw` starts the bundled local Splunk runtime and installs the local
Splunk app automatically.

The setup creates a restricted Splunk user:

- username: `defenseclaw_local_user`
- default app: `defenseclaw_local_mode`
- default index scope: `defenseclaw_local`

The setup command prints the local Splunk URL and credentials after bootstrap.

## What Data The App Uses

The app is built on a narrow local signal model. The current shipped signal
families are:

- `defenseclaw:json`
  - DefenseClaw audit and policy decision events
- `openclaw:gateway:json`
  - structured OpenClaw gateway and runtime evidence
- `openclaw:diagnostics:json`
  - queue, session, retry, and runtime-diagnostics events
- `otel:metric`
  - event-indexed usage, cost, duration, and queue-pressure metrics
- `otel:trace`
  - trace spans for usage and run/session correlation

The default local search contract is:

- index: `defenseclaw_local`
- source: `defenseclaw`
- sourcetype: `defenseclaw:json`
- local HEC endpoint: `http://127.0.0.1:8088/services/collector/event`

The app layers macros, eventtypes, saved searches, and dashboards on top of
those signal families.

## What The App Is For

The current app is optimized for four local questions:

- what did `DefenseClaw` allow, deny, block, quarantine, or enforce?
- which runs or sessions look risky and need review?
- what runtime, queue, or diagnostics evidence explains that risk?
- what should the operator investigate next in raw Splunk search?

The app intentionally stops at:

- detect
- explain
- investigate
- recommend the next useful check

It does not imply automated response, multi-instance deployment, or unsupported
enrichment domains.

## App Navigation

The app ships with three navigation groups.

### Overview

`Overview` is the narrow security-operations command center.

It shows:

- risk-state distribution
- highest-priority investigations
- packaged detection activity
- direct filters for `run_id` and `session_id`

This is the best landing page for deciding what to inspect first.

### Investigate

#### Audit And Security

Primary page for `DefenseClaw` audit and control outcomes.

Use it to answer:

- what actions happened recently
- which actions were deny, block, quarantine, or enforce
- which actors and targets were involved
- which high-severity audit outcomes are present

#### Runs And Sessions

Primary run/session investigation workbench.

Use it to:

- pick a candidate investigation
- review the current risk state and risk reason
- inspect correlated policy, runtime, diagnostics, usage, and trace evidence
- follow the recommended next pivots

This is the main investigation surface in the current app.

#### Queue And Runtime Health

Diagnostics-driven runtime health page.

Use it to inspect:

- active queue lanes
- stuck sessions
- retry storms
- message-processing failures
- wait behavior and queue pressure

### Observe

#### Gateway Logs

Structured gateway-log troubleshooting page backed by
`openclaw:gateway:json`.

Use it to inspect:

- log volume by level
- noisy subsystems
- repeated error signatures
- recent gateway errors

#### Model Usage And Cost

Structured metrics and traces page.

Use it to inspect:

- token activity
- local cost estimates
- long-duration or slow runs
- queue pressure from metrics
- trace spans by run and session

This page is for local investigation, not billing-authoritative reporting.

### Operate

#### Alerts And Saved Searches

Packaged detection and saved-search page.

The current shipped detection pack includes:

- repeated deny activity
- dangerous command or tool denied
- policy bypass or retry after denial
- stuck or retry-storm session
- runtime error burst around a risky run
- high-cost or long-duration risky run

These saved searches are disabled by default. The page explains what each one
does and what signal families it depends on.

#### Search And Drilldown

Raw search pivot page.

Use it to:

- scope by `run_id`
- scope by `session_id`
- narrow by pivot family such as `policy`, `runtime`, `diagnostics`, `usage`,
  or `trace`
- inspect the underlying evidence as raw searchable records

This is the bridge between dashboards and direct SPL.

## Investigation Model

The current app uses a seeded local investigation model built around:

- `run_id`
- `session_id`
- `session_key`
- `event_domain`
- `event_type`
- `action`
- `status`
- `severity`
- `actor`
- `target`
- `request_id`
- `trace_id`

The normalized evidence domains are:

- `policy`
- `runtime`
- `operations`
- `usage`
- `trace`

The current risk states are:

- `observed`
- `needs_review`
- `risky`
- `critical`

The command center and workbench are driven from the `dcso_*` support layer
that ships with the app bundle.

## Useful Searches

See what signal families are present:

```spl
index=defenseclaw_local
| stats count by sourcetype
| sort - count
```

See recent DefenseClaw audit activity:

```spl
index=defenseclaw_local source=defenseclaw sourcetype="defenseclaw:json"
| spath
| table timestamp action severity actor target details component status
| sort - timestamp
| head 20
```

See seeded investigation candidates:

```spl
`dcso_top_risky_runs_sessions`
```

See investigation evidence for a specific run or session:

```spl
`dcso_investigation_events("*","<session_id>")`
| table timestamp event_domain event_type component action status severity actor target message
| sort - timestamp
```

## Current Boundaries

This app is intentionally scoped.

- It is local-only and single-instance.
- It is optimized for `DefenseClaw` and `OpenClaw` investigation workflows.
- It does not promise a supported upgrade or migration path.
- It does not guarantee every Splunk Enterprise capability in every license
  mode.
- It does not replace a direct Splunk O11y deployment.
- It does not provide automated response or broad third-party enrichment.
