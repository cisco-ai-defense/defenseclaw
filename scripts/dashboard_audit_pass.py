#!/usr/bin/env python3
"""
Apply the (a) / (b) / (c) audit pass to the HITL, Overview, and Proxy & LLM Guard
Grafana dashboards.

(a) Add ``or vector(0)`` to every stat-style panel that would render "No data"
    on a fresh gateway with no traffic for the metric.
(b) Move every "orphan" panel (one whose underlying metric is *only* referenced
    by the dashboard, never emitted by the gateway) into a single collapsed row
    titled "Speculative — pending instrumentation" at the bottom of the
    dashboard, with the panel's container row title preserved as a hint.
(c) Add a ``covered_by`` suffix to every panel description pointing at the Go
    file (and optionally line range) where the metric is emitted, or
    ``EMITTED-NOWHERE`` for orphans, so the next time a panel mysteriously
    renders empty the description is its own bug report.

The transformation is purely on the JSON; nothing about gridPos for the live
panels is touched (only the orphans get re-laid-out under the collapsed row).
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "bundles/local_observability_stack/grafana/dashboards"

# ---------------------------------------------------------------------------
# Inventory: which gateway file emits each metric we currently chart.
# ---------------------------------------------------------------------------
# A value of None marks an orphan (EMITTED-NOWHERE). Anything else is a hint
# that ends up in the panel description as ``covered_by: <file>``.
COVERED_BY: dict[str, str | None] = {
    # --- live, emitted by the gateway ----------------------------------------
    "defenseclaw_inspect_evaluations":            "internal/telemetry/metrics.go (RecordGuardrailEvaluation)",
    "defenseclaw_guardrail_evaluations":          "internal/telemetry/metrics.go (RecordGuardrailEvaluation)",
    "defenseclaw_inspect_latency_milliseconds":   "internal/telemetry/metrics.go (RecordGuardrailEvaluation)",
    "defenseclaw_alert_count":                    "internal/telemetry/alerts.go (RecordAlert)",
    "defenseclaw_audit_events":                   "internal/audit (RecordAuditEvent)",
    "defenseclaw_connector_hook_invocations":     "internal/gateway/hook_telemetry.go",
    "defenseclaw_connector_hook_latency_milliseconds": "internal/gateway/hook_telemetry.go",
    "defenseclaw_gateway_errors":                 "internal/telemetry/gateway_events.go (EventError)",
    "defenseclaw_gateway_events_emitted":         "internal/telemetry/gateway_events.go",
    "defenseclaw_otel_ingest_records":            "internal/gateway/otel_ingest.go",
    "defenseclaw_otel_ingest_bytes":              "internal/gateway/otel_ingest.go",
    "defenseclaw_otel_ingest_last_seen_ts_seconds": "internal/gateway/otel_ingest.go",
    "defenseclaw_scan_findings":                  "internal/telemetry/scan.go",
    "defenseclaw_scan_findings_by_rule":          "internal/telemetry/scan.go",
    "defenseclaw_schema_violations":              "internal/gatewaylog/writer.go (schema gate)",
    "defenseclaw_slo_block_latency_milliseconds": "internal/telemetry/slo.go",
    "defenseclaw_telemetry_exporter_last_export_ts_seconds": "internal/telemetry/provider.go",
    "defenseclaw_admission_decisions":            "internal/enforce/policy.go",
    "defenseclaw_gateway_judge_invocations":      "internal/telemetry/metrics.go (RecordJudge)",
    "defenseclaw_gateway_judge_latency_milliseconds": "internal/telemetry/metrics.go (RecordJudge)",
    "defenseclaw_http_auth_failures":             "internal/gateway/router.go",
    "defenseclaw_http_request_count":             "internal/gateway/router.go (otelhttp middleware)",
    "defenseclaw_http_request_duration_milliseconds": "internal/gateway/router.go (otelhttp middleware)",
    "defenseclaw_tool_calls":                     "internal/telemetry/metrics.go (RecordToolCall)",
    "defenseclaw_tool_duration_milliseconds":     "internal/telemetry/metrics.go (RecordToolCall)",
    "defenseclaw_tool_errors":                    "internal/telemetry/metrics.go",
    "defenseclaw_approval_count":                 "internal/telemetry/metrics.go:1146 (RecordApproval) — code-emitted, will populate once exec approvals run",
    "gen_ai_client_token_usage":                  "OTel GenAI semconv via internal/telemetry/metrics.go (only proxy connectors)",
    "gen_ai_client_operation_duration_seconds":   "OTel GenAI semconv via internal/telemetry/metrics.go (only proxy connectors)",
    # --- orphans (EMITTED-NOWHERE) -------------------------------------------
    "defenseclaw_approval_decision_latency_ms":   None,  # speculative — no Go emitter, no Loki field
    "defenseclaw_audit_sink_circuit_state":       None,  # speculative — Track 5 (audit sinks)
    "defenseclaw_audit_sink_failures":            None,  # speculative — Track 5
    "defenseclaw_runtime_panics":                 None,  # speculative — Track 7
    "defenseclaw_slo_tui_refresh_milliseconds":   None,  # speculative — Track 7/8
    "defenseclaw_cisco_errors":                   None,  # speculative — Track 1 (cisco_inspect.go)
    "defenseclaw_cisco_inspect_latency_milliseconds": None,
    "defenseclaw_gateway_judge_errors":           None,  # speculative — Track 3
    "defenseclaw_guardrail_cache_hits":           None,  # speculative — Track 3
    "defenseclaw_guardrail_cache_misses":         None,
    "defenseclaw_http_rate_limit_breaches":       None,  # speculative — Track 1
    "defenseclaw_judge_semaphore_depth":          None,  # speculative — Track 3
    "defenseclaw_judge_semaphore_drops":          None,  # speculative — Track 3
    "defenseclaw_llm_bridge_latency_milliseconds": None, # speculative — Track 6
    "defenseclaw_openshell_exit":                 None,  # speculative — Track 6
    "defenseclaw_provenance_bumps":               None,  # speculative — Track 0
    "defenseclaw_stream_bytes_sent_bytes":        None,  # speculative — Track 1 (SSE)
    "defenseclaw_stream_duration_ms_milliseconds": None,
    "defenseclaw_stream_lifecycle":               None,
}

METRIC_RE = re.compile(r"\b(defenseclaw_[a-z0-9_]+|gen_ai_[a-z0-9_]+)\b")


def _strip_suffixes(name: str) -> str:
    return re.sub(r"_(bucket|count|sum|total)$", "", name)


def panel_metrics(panel: dict) -> set[str]:
    """Pull every defenseclaw_*/gen_ai_* base name out of every target.expr."""
    out: set[str] = set()
    for target in panel.get("targets") or []:
        expr = target.get("expr") or ""
        for raw in METRIC_RE.findall(expr):
            base = _strip_suffixes(raw)
            if base in COVERED_BY:
                out.add(base)
    return out


def panel_is_orphan(panel: dict) -> bool:
    """A panel is orphan iff it references an orphan metric AND every
    metric it references is orphan. Mixed-source panels stay live."""
    metrics = panel_metrics(panel)
    if not metrics:
        return False
    return all(COVERED_BY.get(m) is None for m in metrics)


def covered_by_suffix(panel: dict) -> str:
    metrics = panel_metrics(panel)
    if not metrics:
        return ""
    parts = []
    for m in sorted(metrics):
        cov = COVERED_BY.get(m, "unmapped")
        if cov is None:
            parts.append(f"{m} → EMITTED-NOWHERE (orphan, see speculative row)")
        else:
            parts.append(f"{m} → {cov}")
    return "\n\ncovered_by:\n  - " + "\n  - ".join(parts)


def annotate_description(panel: dict) -> None:
    suffix = covered_by_suffix(panel)
    if not suffix:
        return
    desc = panel.get("description") or ""
    if "covered_by:" in desc:
        # Already annotated by a prior run — replace.
        desc = re.split(r"\n\ncovered_by:", desc, maxsplit=1)[0]
    panel["description"] = (desc.rstrip() + suffix).strip()


# ---------------------------------------------------------------------------
# (a) ``or vector(0)`` for stat panels.
# ---------------------------------------------------------------------------

def add_or_vector_zero(panel: dict) -> bool:
    """Append `` or vector(0)`` to every stat panel target whose expression
    can return an empty vector when the metric is missing. Returns True if
    anything changed."""
    if panel.get("type") != "stat":
        return False
    changed = False
    for target in panel.get("targets") or []:
        expr = (target.get("expr") or "").strip()
        if not expr or "or vector(0)" in expr:
            continue
        # Don't decorate the 'topk' top-name lookup — its return shape isn't a
        # scalar count, it's a labelled vector that drives a "value" reducer.
        # vector(0) would inject a noise series.
        if expr.startswith("topk("):
            continue
        target["expr"] = expr + " or vector(0)"
        changed = True
    return changed


# ---------------------------------------------------------------------------
# (b) Move orphan panels into a collapsed "Speculative" row.
# ---------------------------------------------------------------------------

SPECULATIVE_ROW_TITLE = "Speculative — pending instrumentation (v7 tracks)"
SPECULATIVE_ROW_DESC = (
    "Panels in this row reference metrics that are NOT emitted by any current "
    "gateway code path. They are kept here on purpose — collapsed and clearly "
    "fenced — so dashboard authors can iterate on the visualization while the "
    "underlying instrumentation lands across the v7 tracks. Each panel's own "
    "description carries an explicit ``covered_by: ... → EMITTED-NOWHERE`` "
    "tag so the next time a panel mysteriously goes empty, the description "
    "is its own bug report."
)


def split_orphans(panels: list[dict]) -> tuple[list[dict], list[dict]]:
    live, orphan = [], []
    for p in panels:
        if p.get("type") == "row":
            # Rows themselves stay where they are — only their content rows
            # get rewritten if every child is orphan, which we don't bother
            # collapsing at this step.
            live.append(p)
            continue
        if panel_is_orphan(p):
            orphan.append(p)
        else:
            live.append(p)
    return live, orphan


def reflow_orphans(orphans: list[dict]) -> list[dict]:
    """Lay orphans out as a 12-wide-per-panel grid inside the speculative
    row. Grafana ignores gridPos when the parent row is collapsed but it
    still validates structure, so we set sane defaults rather than leave
    the original gridPos which collide with the live panels above."""
    laid_out: list[dict] = []
    x, y = 0, 0
    for p in orphans:
        # Default to 12-wide / 8-tall, half a row apiece.
        w = 12
        h = 8
        p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        x += w
        if x >= 24:
            x = 0
            y += h
        laid_out.append(p)
    return laid_out


def find_max_y(panels: list[dict]) -> int:
    max_y = 0
    for p in panels:
        gp = p.get("gridPos") or {}
        y = int(gp.get("y", 0)) + int(gp.get("h", 0))
        if y > max_y:
            max_y = y
    return max_y


def speculative_row(orphans: list[dict], y: int) -> dict:
    return {
        "type": "row",
        "title": SPECULATIVE_ROW_TITLE,
        "description": SPECULATIVE_ROW_DESC,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "collapsed": True,
        "panels": reflow_orphans(orphans),
    }


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------

def transform(path: pathlib.Path) -> dict:
    raw = json.loads(path.read_text())

    # Drop any prior "Speculative" row from a previous run — we'll rebuild it.
    raw["panels"] = [
        p for p in raw["panels"]
        if not (p.get("type") == "row" and (p.get("title") or "").startswith("Speculative"))
    ]
    # Lift any orphans previously collapsed inside a row back to the top
    # level so we re-classify them this run.
    flat: list[dict] = []
    for p in raw["panels"]:
        if p.get("type") == "row" and p.get("collapsed") and p.get("panels"):
            for child in p["panels"]:
                flat.append(child)
            p_copy = dict(p)
            p_copy["panels"] = []
            p_copy["collapsed"] = False
            flat.insert(0, p_copy) if False else flat.append(p_copy)
        else:
            flat.append(p)
    raw["panels"] = flat

    # (c) annotate every panel.
    for p in raw["panels"]:
        if p.get("type") != "row":
            annotate_description(p)
    # (a) decorate stat panels.
    decorated = 0
    for p in raw["panels"]:
        if add_or_vector_zero(p):
            decorated += 1

    # (b) split + collapse orphans.
    live, orphans = split_orphans(raw["panels"])
    if orphans:
        # Re-annotate inside the collapsed row too.
        for p in orphans:
            annotate_description(p)
        row = speculative_row(orphans, find_max_y(live))
        live.append(row)
        raw["panels"] = live

    # Bump version so Grafana reloads.
    raw["version"] = int(raw.get("version", 0)) + 1

    path.write_text(json.dumps(raw, indent=2) + "\n")
    return {"orphans": len(orphans), "or_vector_added": decorated, "out": str(path.relative_to(ROOT))}


def main() -> int:
    targets = [
        DASHBOARD_DIR / "defenseclaw-hitl.json",
        DASHBOARD_DIR / "defenseclaw-overview.json",
        DASHBOARD_DIR / "defenseclaw-traffic.json",
    ]
    for path in targets:
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 1
        result = transform(path)
        print(
            f"{result['out']}: orphans={result['orphans']} "
            f"or_vector_zero_added={result['or_vector_added']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
