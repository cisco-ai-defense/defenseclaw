# DefenseClaw Layout Guide

This guide defines original layout patterns for DefenseClaw operational
surfaces. It borrows only broad observability-console principles: fast status
scanning, panel grids, time-scoped evidence, and drilldown from summary to raw
records. It must not copy Grafana screen layouts, dashboard JSON, screenshots,
CSS, component code, navigation labels, or brand styling.

The reference implementation lives in [`web/`](../../web/). See
[`style-guide.md`](style-guide.md) for the palette, typography, and CRT
effects layer.

## Layout Principles

- Status first: the top of a screen should answer whether DefenseClaw is
  healthy, enforcing, and receiving current data.
- Evidence nearby: summaries must link directly to the audit rows, logs,
  traces, policies, or scanner findings that explain them.
- Stable controls: global filters, time range, and tenant/profile scope should
  stay in predictable positions.
- Dense alignment: use grids, tables, and compact panels. Avoid decorative
  nested cards.
- Operator continuity: preserve filters and selected row state as users move
  between overview, investigation, and raw evidence.

## Global Shell

Wide web layout:

```text
+--------------+------------------------------------------------------+
| primary nav  | top status: gateway | guardrail | sinks | time range |
|              +------------------------------------------------------+
|              | page title + scope filters + primary action          |
|              +------------------------------------------------------+
|              | content grid / workbench                             |
|              |                                                      |
+--------------+------------------------------------------------------+
```

TUI layout:

```text
+---------------------------------------------------------------------+
| DefenseClaw  tabs/panels                         status indicators |
+---------------------------------------------------------------------+
| panel content: overview, table, detail, form, or activity stream    |
+---------------------------------------------------------------------+
| hints: keys, current filter, freshness, command output state        |
+---------------------------------------------------------------------+
```

Responsive web layout:

- `>= 1200px`: persistent left nav, 12-column content grid, right-side detail
  drawer allowed.
- `900-1199px`: compact left nav, 8-column grid, details below selected table.
- `600-899px`: top navigation tabs, 4-column grid, no side drawers.
- `< 600px`: single-column stack, sticky filter bar, tables become row lists.

## Navigation Model

Use these first-level destinations across TUI, web, and local apps. The
web shell groups them into **OPERATE** and **EVIDENCE** sections in the
left nav; the TUI uses a single tab strip with number shortcuts:

| Destination | Group | Purpose |
|-------------|-------|---------|
| Overview | Operate | Health, risk, SLO, recent activity, next thing to inspect |
| Alerts | Operate | Current security alerts and enriched findings |
| Inventory | Operate | Skills, MCP servers, plugins, models, tools, AIBOM (scope chips) |
| Policy | Operate | Rule packs, suppressions, allow/block controls, tests |
| Audit | Evidence | Append-only evidence trail |
| Logs | Evidence | Gateway, guardrail, watchdog, and runtime logs |
| Setup | Evidence | Wizards + config editor: providers, guardrails, sinks, webhooks, sandbox |

Navigation labels are rendered all-caps mono (`OVERVIEW`, `ALERTS`, …)
with `letter-spacing: 0.10em` to match the TUI's tab bar voice. The
`Activity` panel from the TUI folds into Audit + Overview on the web —
the dedicated activity stream is a TUI affordance for command output.

For Splunk or observability-only surfaces, group pages by operator intent:

- Observe: health, metrics, traces, logs.
- Investigate: alerts, runs, sessions, risky evidence.
- Operate: rules, saved searches, sinks, setup checks.

Do not reuse Grafana's exact navigation structure or labels as the product
model. DefenseClaw navigation should reflect security governance workflows.

## Global Controls

Place global controls in this order:

1. Environment/profile scope.
2. Time range.
3. Refresh or live-tail state.
4. Severity/risk filters.
5. Entity filters: run, session, actor, target, scanner, policy.
6. Export or raw-view action.

Rules:

- Global controls affect every panel on the page.
- Panel-local controls live in the panel header.
- Filters should be visible as chips after selection.
- Every filtered page should provide a one-action clear path.
- Show data freshness near refresh controls: `live`, `30s ago`, `stale`.

## Panel Grid

Use a 12-column grid on wide web surfaces:

| Panel kind | Width | Height | Notes |
|------------|-------|--------|-------|
| Stat | 2-3 cols | 96-128px | One metric, delta, state |
| Small trend | 3-4 cols | 160-220px | One main series |
| Distribution | 4-6 cols | 220-300px | Severity or outcome breakdown |
| Primary table | 8-12 cols | 360-640px | Main work surface |
| Detail panel | 4 cols | 360-640px | Selected row evidence |
| Timeline | 12 cols | 240-360px | Trace/run/session sequence |

Spacing:

- Grid gap: 12px.
- Page padding: 16px desktop, 12px tablet, 8px mobile.
- Panel padding: 12px web.
- Table cell horizontal padding: 10-12px.
- TUI panels should use one-cell borders and avoid wrapping labels when a
  concise label is available.

## Panel Anatomy

```text
+-------------------------------------------------------------+
| title                  local filter  view toggle  actions   |
+-------------------------------------------------------------+
| summary/stat/chart/table/detail body                        |
|                                                             |
+-------------------------------------------------------------+
| optional footer: freshness, query, drilldown, warning        |
+-------------------------------------------------------------+
```

Panel header rules:

- Title is a noun phrase: `Guardrail verdicts`, `Sink batches`, `Risky runs`.
- Include one short qualifier if needed: `last 15m`, `selected session`.
- Put panel-local controls on the right.
- Do not place paragraph help text inside panel headers.

Panel footer rules:

- Use for freshness, query scope, drilldown links, and warnings.
- Keep footer one line when possible.
- Hide footers when they add no operational value.

## Standard Page Templates

### Overview

Purpose: answer "What needs attention now?"

Order:

1. Status strip: gateway, guardrail mode, scanner reachability, sink health.
2. Critical stat row: open alerts, block rate, failed sinks, SLO health.
3. Primary table: highest-priority investigations or recent blocks.
4. Supporting panels: severity trend, queue pressure, recent activity.
5. Footer/detail: stale data notice, doctor snapshot, raw audit link.

Do not put long explanations on the Overview. Every item should be actionable
or link to a page that is.

### Alerts

Purpose: triage current security findings.

Layout:

- Left or top: filters for severity, state, scanner, actor, target.
- Center: alerts table sorted by severity, recency, and unresolved state.
- Right or below: selected alert detail with finding, remediation, policy,
  request ID, trace ID, and related audit rows.
- Bottom: raw evidence or command output when an action runs.

Required columns:

- Time.
- Severity.
- Verdict/outcome.
- Target.
- Rule or scanner.
- Actor/session.
- Status.

### Inventory

Purpose: inspect and act on skills, MCP servers, plugins, and other agent
components.

Layout:

- Scope chips: skills, MCPs, plugins, agents, tools, models, memory.
- Search and status filters.
- Main table with scan status, severity, source, installed version, last scan.
- Action menu on selected row: scan, block, allow, quarantine, restore, info.
- Detail area shows latest findings, source path, provenance, and audit trail.

### Policy

Purpose: manage enforcement rules without hiding the consequences.

Layout:

- Tabs or segmented control: rule packs, suppressions, allow/block, tests.
- Main table or editor.
- Side detail: effective decision, matching rules, last modified, audit event.
- Test run area: input fixture, expected result, actual result, trace output.

Dangerous policy changes should show:

- Affected scope.
- Previous value.
- New value.
- Dry-run/test affordance.
- Audit event after save.

### Logs

Purpose: troubleshoot runtime behavior.

Layout:

- Top controls: subsystem, level, search, live/pause, time range.
- Main log stream with fixed-width timestamp and level columns.
- Selected row detail with structured fields.
- Links to related trace ID, request ID, run ID, and audit event.

### Setup

Purpose: configure without losing audit parity.

Layout:

- Left/top section list: scanners, gateway, guardrail, providers, OTel, sinks,
  webhooks, sandbox, local observability.
- Main form for selected section.
- Right/bottom effective config summary.
- Test button close to each external integration.
- Save path must route through the same CLI flow used outside the UI.

## Drilldown Pattern

All summary surfaces should support this path:

```text
summary metric -> filtered table -> selected row detail -> raw evidence
```

Example:

```text
Critical blocks stat
  -> Alerts filtered to CRITICAL + blocked
  -> Alert detail with scanner finding and policy ID
  -> Audit row, gateway log, trace span, or source finding JSON
```

Rules:

- Preserve time range and filters across drilldown.
- Add filters when drilling from a specific value.
- Make raw evidence copyable.
- Provide a way back to the prior result set.

## Empty, Loading, Error, And Stale States

Every panel needs explicit non-happy states.

Loading:

- Show the action being performed: `Loading scanner inventory`.
- Keep previous data visible if it is still useful and mark it refreshing.

Empty:

- State the scope: `No blocked tool calls in the last 15m`.
- Offer the next relevant action if one exists: `Run doctor`, `Clear filters`,
  `Start gateway`, `Scan inventory`.

Error:

- Say what failed and which dependency was involved.
- Include a retry action.
- Include the command or endpoint when useful.

Stale:

- Show last successful refresh time.
- Keep stale data visually usable but clearly marked.
- Do not silently replace stale data with empty panels.

## TUI Translation

The TUI should preserve the same information hierarchy while respecting
terminal constraints.

Use:

- One-line tab bar for panels.
- A compact status strip with gateway, guardrail mode, and data freshness.
- Tables as the default primary layout.
- Detail panes opened by `Enter` or a panel-specific key.
- Bottom hints from `internal/tui/hints.go`.
- Activity panel for command output.

Avoid:

- Deeply nested boxes.
- Wide ASCII diagrams in primary workflows.
- Long prose blocks inside panels.
- Color-only severity.
- Hidden commands without command palette entries.

## Splunk And Local Observability Surfaces

DefenseClaw has both local Splunk and local Grafana-based observability
workflows. Product-owned layout guidance still applies:

- Dashboards should be named around DefenseClaw operator tasks.
- Panels should use DefenseClaw vocabulary and evidence fields.
- Cross-links should preserve `run_id`, `session_id`, `trace_id`, and time.
- Local observability dashboards can target Prometheus, Loki, and Tempo, but
  the visual design language for DefenseClaw-owned UI should remain original.
- Do not copy Grafana dashboard layouts when designing first-party web or TUI
  surfaces.

## Page Quality Checklist

Before accepting a new layout:

- The first viewport shows status, scope, and at least one actionable signal.
- Global filters are stable and visible.
- Every summary has a drilldown path to evidence.
- Empty, loading, error, and stale states are designed.
- Tables remain readable at expected data volume.
- IDs and commands are copyable or easy to select.
- Destructive actions show target and consequence.
- The page does not depend on Grafana assets, UI code, dashboard JSON, or
  copied composition.
