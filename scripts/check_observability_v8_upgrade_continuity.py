#!/usr/bin/env python3
"""Verify live observability-v8 history and dashboards across an upgrade.

This is the assertion half of ``test-observability-v8-upgrade-continuity.sh``.
It queries the real local Prometheus, Loki, Tempo, and Grafana services. Empty
dashboard panels are allowed when their source event did not occur; query
errors, missing producer facts, duplicate canonical occurrences, or missing
pre-upgrade history are not.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_grafana_dashboards as dashboards  # noqa: E402

ROLE_RE = re.compile(r"^golden-agent-(root|direct|nested)-([0-9]+)$")
PHASE_CODES = {
    "session": 1,
    "planning": 2,
    "model": 3,
    "tool": 4,
    "approval": 5,
    "waiting": 6,
    "responding": 7,
    "maintenance": 8,
    "completed": 9,
    "failed": 10,
    "interrupted": 11,
    "observed": 12,
}
LIFECYCLE_EVENTS = {
    "session_start",
    "session_end",
    "subagent_start",
    "subagent_stop",
    "turn_start",
    "turn_end",
    "compact_start",
    "compact_end",
    "tool_start",
    "tool_end",
    "event",
}


class ContinuityError(RuntimeError):
    """A content-free release-gate failure."""


def _role_stamp(body: dict[str, Any]) -> tuple[str, str] | None:
    value = body.get("gen_ai.agent.id")
    if not isinstance(value, str):
        return None
    match = ROLE_RE.fullmatch(value)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _body(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("body")
    return value if isinstance(value, dict) else {}


def _timestamp(record: dict[str, Any]) -> dt.datetime:
    value = record.get("timestamp")
    if not isinstance(value, str):
        raise ContinuityError("canonical record is missing its timestamp")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityError("canonical record has a malformed timestamp") from exc


def _records_by_stamp(records: list[dict[str, Any]], stamp: str) -> list[dict[str, Any]]:
    return [record for record in records if (_role_stamp(_body(record)) or ("", ""))[1] == stamp]


def _exact_record(
    records: list[dict[str, Any]],
    *,
    role: str,
    event_name: str,
    predicate: Any | None = None,
) -> dict[str, Any]:
    selected = [
        record
        for record in records
        if (_role_stamp(_body(record)) or ("", ""))[0] == role
        and record.get("event_name") == event_name
        and (predicate is None or predicate(_body(record)))
    ]
    if len(selected) != 1:
        raise ContinuityError(
            f"{role} {event_name} occurrences={len(selected)}, want exactly one",
        )
    return selected[0]


def _assert_occurrences(records: list[dict[str, Any]], stamp: str) -> None:
    expected = Counter(
        {
            ("root", "session_start"): 2,
            ("root", "compact_start"): 1,
            ("root", "compact_end"): 1,
            ("root", "event"): 1,
            ("root", "session_end"): 1,
            ("direct", "subagent_start"): 1,
            ("direct", "turn_start"): 2,
            ("direct", "turn_end"): 2,
            ("direct", "model.request"): 2,
            ("direct", "model.response"): 2,
            ("direct", "subagent_stop"): 1,
            ("nested", "subagent_start"): 1,
            ("nested", "tool.invocation.requested"): 1,
            ("nested", "tool.invocation.completed"): 1,
            ("nested", "tool_end"): 1,
            ("nested", "approval.requested"): 1,
            ("nested", "approval.resolved"): 1,
            ("nested", "hook_decision"): 1,
            ("nested", "subagent_stop"): 1,
        },
    )
    actual: Counter[tuple[str, str]] = Counter()
    for record in records:
        identity = _role_stamp(_body(record))
        event_name = record.get("event_name")
        if identity is not None and isinstance(event_name, str):
            actual[(identity[0], event_name)] += 1
    for key, count in expected.items():
        if actual[key] != count:
            raise ContinuityError(
                f"run {stamp} {key[0]} {key[1]} occurrences={actual[key]}, want {count}",
            )

    unexpected = actual - expected
    if unexpected:
        raise ContinuityError(
            f"run {stamp} contains unexpected canonical occurrences: {sorted(unexpected.items())}",
        )

    record_ids = [record.get("record_id") for record in records]
    if any(not isinstance(record_id, str) or not record_id for record_id in record_ids):
        raise ContinuityError(f"run {stamp} contains a record without a stable occurrence ID")
    if len(record_ids) != len(set(record_ids)):
        raise ContinuityError(f"run {stamp} contains duplicate canonical occurrence IDs")


def _assert_lineage_sequence_phase(records: list[dict[str, Any]], stamp: str) -> None:
    root_id = f"golden-agent-root-{stamp}"
    direct_id = f"golden-agent-direct-{stamp}"
    expected_parent = {"root": None, "direct": root_id, "nested": direct_id}
    expected_sequences = {
        "root": [1, 4, 5, 6, 9, 10],
        "direct": [1, 2, 3, 4, 5, 6],
        "nested": [1, 2, 3],
    }
    observed_sequences: dict[str, list[int]] = defaultdict(list)

    for record in sorted(records, key=_timestamp):
        event_name = record.get("event_name")
        if event_name not in LIFECYCLE_EVENTS:
            continue
        body = _body(record)
        identity = _role_stamp(body)
        if identity is None:
            continue
        role = identity[0]
        if body.get("defenseclaw.agent.root.id") != root_id:
            raise ContinuityError(f"run {stamp} {role} lost root lineage")
        if body.get("defenseclaw.agent.lifecycle.id") != f"golden-lifecycle-{role}-{stamp}":
            raise ContinuityError(f"run {stamp} {role} lost its lifecycle identity")
        if body.get("defenseclaw.agent.execution.id") != f"golden-execution-{role}-{stamp}":
            raise ContinuityError(f"run {stamp} {role} lost its execution identity")
        parent = body.get("defenseclaw.agent.parent.id")
        if expected_parent[role] is None:
            if parent is not None:
                raise ContinuityError(f"run {stamp} root fabricated a parent")
        elif parent != expected_parent[role]:
            raise ContinuityError(f"run {stamp} {role} lost parent lineage")
        phase = body.get("defenseclaw.agent.phase")
        phase_code = body.get("defenseclaw.agent.phase.code")
        if phase not in PHASE_CODES or phase_code != PHASE_CODES[phase]:
            raise ContinuityError(
                f"run {stamp} {role}/{event_name} has inconsistent phase code",
            )
        sequence = body.get("defenseclaw.agent.sequence")
        if not isinstance(sequence, int):
            raise ContinuityError(f"run {stamp} {role}/{event_name} has no sequence")
        observed_sequences[role].append(sequence)

    for role, want in expected_sequences.items():
        got = observed_sequences.get(role, [])
        if got != want or any(right <= left for left, right in zip(got, got[1:])):
            raise ContinuityError(f"run {stamp} {role} sequence={got}, want {want}")


def _assert_compaction_resume_and_completion(records: list[dict[str, Any]], stamp: str) -> None:
    _exact_record(records, role="root", event_name="compact_start")
    _exact_record(records, role="root", event_name="compact_end")
    resume = _exact_record(
        records,
        role="root",
        event_name="session_start",
        predicate=lambda body: body.get("defenseclaw.session.source") == "resume",
    )
    resume_body = _body(resume)
    if resume_body.get("defenseclaw.session.resumed") is not True:
        raise ContinuityError(f"run {stamp} resume did not retain resumed=true")

    completed = _exact_record(
        records,
        role="root",
        event_name="event",
        predicate=lambda body: body.get("defenseclaw.operation.id") == f"continuity-prestop-operation-{stamp}",
    )
    stop = _exact_record(records, role="root", event_name="session_end")
    completed_body = _body(completed)
    if (
        completed_body.get("defenseclaw.agent.lifecycle.state") != "completed"
        or completed_body.get("defenseclaw.agent.phase") != "completed"
    ):
        raise ContinuityError(f"run {stamp} pre-Stop operation is not completed")
    if "defenseclaw.outcome" in completed_body:
        raise ContinuityError(f"run {stamp} generic lifecycle event invented a forbidden outcome")
    if _timestamp(completed) >= _timestamp(stop):
        raise ContinuityError(f"run {stamp} operation completion was not visible before Stop")


def _assert_decision(records: list[dict[str, Any]], stamp: str) -> None:
    decision = _exact_record(records, role="nested", event_name="hook_decision")
    body = _body(decision)
    expected = {
        "defenseclaw.guardrail.raw_action": "block",
        "defenseclaw.guardrail.effective_action": "allow",
        "defenseclaw.guardrail.mode": "observe",
        "defenseclaw.guardrail.would_block": True,
        "defenseclaw.guardrail.enforced": False,
        "defenseclaw.evaluation.id": f"continuity-evaluation-{stamp}",
    }
    if any(body.get(key) != value for key, value in expected.items()):
        raise ContinuityError(f"run {stamp} raw/effective hook decision drifted")


def _canonical_tempo_trace_id(value: object) -> str | None:
    """Restore Tempo search IDs to the canonical 16-byte W3C spelling."""

    if not isinstance(value, str) or value != value.strip():
        return None
    raw = value
    if re.fullmatch(r"[0-9a-fA-F]{1,32}", raw) is None:
        return None
    canonical = raw.lower().zfill(32)
    return None if canonical == "0" * 32 else canonical


def _tempo_spans(stamps: tuple[str, str], lookback_seconds: int) -> list[dict[str, Any]]:
    stamp_expression = "|".join(re.escape(stamp) for stamp in stamps)
    now = time.time()
    response = dashboards.request_json(
        "http://127.0.0.1:3200/api/search",
        {
            "q": (f'{{ span.gen_ai.agent.id =~ "golden-agent-(root|direct|nested)-({stamp_expression})" }}'),
            "limit": "200",
            "start": str(int(now - lookback_seconds)),
            "end": str(int(now)),
        },
        timeout_seconds=60,
    )
    trace_ids = {
        canonical
        for item in response.get("traces", [])
        if isinstance(item, dict)
        and (canonical := _canonical_tempo_trace_id(item.get("traceID", ""))) is not None
    }
    return [
        span
        for trace_id in sorted(trace_ids)
        for span in dashboards._tempo_trace_spans(trace_id, timeout_seconds=60)  # noqa: SLF001
    ]


def _assert_trace(stamp: str, spans: list[dict[str, Any]]) -> str:
    selected = [
        span for span in spans if str(span.get("attributes", {}).get("gen_ai.agent.id", "")).endswith(f"-{stamp}")
    ]
    traces = {span["trace_id"] for span in selected}
    if len(traces) != 1:
        raise ContinuityError(f"run {stamp} trace count={len(traces)}, want one coherent W3C trace")
    trace_id = next(iter(traces))
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for span in selected:
        attributes = span["attributes"]
        by_family[str(attributes.get("defenseclaw.span.family", ""))].append(span)
        by_agent[str(attributes.get("gen_ai.agent.id", ""))].append(span)
    if len(by_family["span.agent.invoke"]) != 3:
        raise ContinuityError(f"run {stamp} does not contain root/direct/nested agent spans")
    if len(by_family["span.model.chat"]) != 2:
        raise ContinuityError(f"run {stamp} model spans={len(by_family['span.model.chat'])}, want two turns")
    if len(by_family["span.tool.execute"]) != 1 or len(by_family["span.approval.resolve"]) != 1:
        raise ContinuityError(f"run {stamp} tool/approval topology is incomplete")

    agent_spans: dict[str, dict[str, Any]] = {}
    for role in ("root", "direct", "nested"):
        agent_id = f"golden-agent-{role}-{stamp}"
        candidates = by_agent.get(agent_id, [])
        invocation_candidates = [
            span
            for span in candidates
            if span["attributes"].get("defenseclaw.span.family") == "span.agent.invoke"
        ]
        if len(invocation_candidates) != 1:
            raise ContinuityError(
                f"run {stamp} {role} invocation spans={len(invocation_candidates)}, want one",
            )
        invocation = invocation_candidates[0]
        expected_execution = f"golden-execution-{role}-{stamp}"
        if invocation["attributes"].get("defenseclaw.agent.execution.id") != expected_execution:
            raise ContinuityError(f"run {stamp} {role} invocation lost its execution identity")
        agent_spans[role] = invocation

    root = agent_spans["root"]
    direct = agent_spans["direct"]
    nested = agent_spans["nested"]
    tool = by_family["span.tool.execute"][0]
    approval = by_family["span.approval.resolve"][0]
    if root["parent_span_id"] or direct["parent_span_id"] != root["span_id"]:
        raise ContinuityError(f"run {stamp} root/direct W3C topology drifted")
    if nested["parent_span_id"] != direct["span_id"] or tool["parent_span_id"] != nested["span_id"]:
        raise ContinuityError(f"run {stamp} nested/tool W3C topology drifted")
    if approval["parent_span_id"] != tool["span_id"]:
        raise ContinuityError(f"run {stamp} approval is not a tool child")
    if any(span["parent_span_id"] != direct["span_id"] for span in by_family["span.model.chat"]):
        raise ContinuityError(f"run {stamp} model turn is not a direct-agent child")

    by_turn = {span["attributes"].get("defenseclaw.turn.id"): span for span in by_family["span.model.chat"]}
    reported = by_turn.get(f"continuity-turn-1-{stamp}")
    unreported = by_turn.get(f"continuity-turn-2-{stamp}")
    if reported is None or unreported is None:
        raise ContinuityError(f"run {stamp} does not retain both turn identities")
    if reported["attributes"].get("defenseclaw.telemetry.tokens.reported") is not True:
        raise ContinuityError(f"run {stamp} reported usage lost its presence bit")
    if unreported["attributes"].get("defenseclaw.telemetry.tokens.reported") is not False:
        raise ContinuityError(f"run {stamp} missing usage was rendered as reported")
    if any(key in unreported["attributes"] for key in ("gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens")):
        raise ContinuityError(f"run {stamp} missing usage was invented as zero")

    span_ids = [span["span_id"] for span in selected]
    if "" in span_ids or len(span_ids) != len(set(span_ids)):
        raise ContinuityError(f"run {stamp} has missing or duplicate W3C span IDs")
    return trace_id


def _assert_metrics(metric_cutover_seconds: float, lookback_hours: int) -> None:
    """Prove low-cardinality lifecycle series have samples on both sides.

    Agent IDs are intentionally forbidden Prometheus labels in v8. The
    last-seen gauge value is itself an epoch timestamp, so min/max over the
    retained range proves that the same bounded role series contains a sample
    from before the upgrade and a newer sample emitted after it.
    """

    if not math.isfinite(metric_cutover_seconds) or metric_cutover_seconds <= 0:
        raise ContinuityError("metric cutover must be a finite positive epoch")

    selector = (
        'defenseclaw_agent_last_seen_seconds{connector="codex",'
        'gen_ai_agent_type=~"root|direct|nested"}'
    )
    window = f"{lookback_hours}h"
    minimum = dashboards._prometheus_vector(  # noqa: SLF001
        f"min_over_time({selector}[{window}])",
        timeout_seconds=60,
    )
    maximum = dashboards._prometheus_vector(  # noqa: SLF001
        f"max_over_time({selector}[{window}])",
        timeout_seconds=60,
    )

    def by_role(
        series: list[dict[str, Any]],
        *,
        aggregate: Any,
        query_name: str,
    ) -> dict[str, float]:
        observed: dict[str, float] = {}
        for item in series:
            metric = item.get("metric")
            if not isinstance(metric, dict):
                continue
            role = metric.get("gen_ai_agent_type")
            value = item.get("value")
            if role not in {"root", "direct", "nested"}:
                continue
            if not isinstance(value, list) or len(value) != 2:
                raise ContinuityError(
                    f"Prometheus {query_name} lifecycle metric for {role} is malformed",
                )
            try:
                metric_value = float(value[1])
            except (TypeError, ValueError):
                raise ContinuityError(
                    f"Prometheus {query_name} lifecycle metric for {role} is not numeric",
                ) from None
            if not math.isfinite(metric_value) or metric_value <= 0:
                raise ContinuityError(
                    f"Prometheus {query_name} lifecycle metric for {role} "
                    "is non-finite or non-positive",
                )
            if role in observed:
                observed[role] = aggregate(observed[role], metric_value)
            else:
                observed[role] = metric_value
        return observed

    minimum_by_role = by_role(minimum, aggregate=min, query_name="minimum")
    maximum_by_role = by_role(maximum, aggregate=max, query_name="maximum")
    expected = {"root", "direct", "nested"}
    missing = sorted(expected - (minimum_by_role.keys() & maximum_by_role.keys()))
    if missing:
        raise ContinuityError(f"Prometheus lost lifecycle role series: {missing}")
    not_pre = sorted(role for role in expected if minimum_by_role[role] >= metric_cutover_seconds)
    not_post = sorted(role for role in expected if maximum_by_role[role] <= metric_cutover_seconds)
    if not_pre or not_post:
        raise ContinuityError(
            "Prometheus lifecycle history does not straddle the upgrade boundary: "
            f"missing_pre={not_pre} missing_post={not_post}",
        )


def _assert_dashboards(
    *,
    lookback_hours: int,
    deadline: float,
) -> dict[str, Any]:
    authored, errors = dashboards.static_audit(require_packaged=True)
    if errors:
        raise ContinuityError("static dashboard contract failed: " + "; ".join(errors))
    if len(authored) != 14:
        raise ContinuityError(f"dashboard count={len(authored)}, want 14")
    expected_uids = {dashboard["uid"] for _, dashboard in authored}
    search = dashboards.request_json(
        "http://127.0.0.1:3000/api/search",
        {"type": "dash-db", "tag": "defenseclaw", "limit": "100"},
        timeout_seconds=30,
    )
    if not isinstance(search, list):
        raise ContinuityError("Grafana dashboard search returned an invalid result")
    actual_uids = {item.get("uid") for item in search if isinstance(item, dict) and isinstance(item.get("uid"), str)}
    if expected_uids != actual_uids:
        raise ContinuityError(
            f"Grafana UID inventory drifted: missing={sorted(expected_uids - actual_uids)} "
            f"extra={sorted(actual_uids - expected_uids)}",
        )
    live_errors = dashboards.live_audit(authored, deadline=deadline, query_timeout_seconds=60)
    if live_errors:
        raise ContinuityError("live dashboard query compilation failed: " + "; ".join(live_errors))
    inventory, inventory_errors = dashboards.live_inventory(
        authored,
        range_seconds=lookback_hours * 60 * 60,
        deadline=deadline,
        query_timeout_seconds=60,
    )
    if inventory_errors:
        raise ContinuityError("live dashboard inventory failed: " + "; ".join(inventory_errors))
    if len(inventory) != 14 or any(item["status_counts"]["error"] for item in inventory):
        raise ContinuityError("live dashboard inventory is incomplete or contains query errors")
    return {
        "uids": len(actual_uids),
        "panels": sum(len(item["panels"]) for item in inventory),
        "data": sum(item["status_counts"]["data"] for item in inventory),
        "zero": sum(item["status_counts"]["zero"] for item in inventory),
        "empty": sum(item["status_counts"]["empty"] for item in inventory),
        "interactive": sum(item["status_counts"]["interactive"] for item in inventory),
    }


def verify(
    pre_stamp: str,
    post_stamp: str,
    *,
    metric_cutover_seconds: float,
    lookback_hours: int,
    dashboard_deadline_seconds: int,
) -> dict[str, Any]:
    readiness = dashboards.backend_readiness_errors()
    if readiness:
        raise ContinuityError("; ".join(readiness))
    now = time.time()
    records = dashboards._loki_golden_records(  # noqa: SLF001
        start_ns=int((now - lookback_hours * 60 * 60) * 1_000_000_000),
        end_ns=int(now * 1_000_000_000),
        timeout_seconds=60,
    )
    spans = _tempo_spans((pre_stamp, post_stamp), lookback_hours * 60 * 60)
    trace_ids: dict[str, str] = {}
    record_counts: dict[str, int] = {}
    for stamp in (pre_stamp, post_stamp):
        run_records = _records_by_stamp(records, stamp)
        if not run_records:
            raise ContinuityError(f"Loki has no records for run {stamp}")
        _assert_occurrences(run_records, stamp)
        _assert_lineage_sequence_phase(run_records, stamp)
        _assert_compaction_resume_and_completion(run_records, stamp)
        _assert_decision(run_records, stamp)
        trace_ids[stamp] = _assert_trace(stamp, spans)
        record_counts[stamp] = len(run_records)
    if trace_ids[pre_stamp] == trace_ids[post_stamp]:
        raise ContinuityError("post-upgrade execution reused the pre-upgrade W3C trace")
    _assert_metrics(metric_cutover_seconds, lookback_hours)
    dashboard_report = _assert_dashboards(
        lookback_hours=lookback_hours,
        deadline=time.monotonic() + dashboard_deadline_seconds,
    )
    return {
        "pre_stamp": pre_stamp,
        "post_stamp": post_stamp,
        "pre_trace_id": trace_ids[pre_stamp],
        "post_trace_id": trace_ids[post_stamp],
        "record_counts": record_counts,
        "dashboards": dashboard_report,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pre-stamp", required=True)
    parser.add_argument("--post-stamp", required=True)
    parser.add_argument("--metric-cutover-seconds", required=True, type=float)
    parser.add_argument("--lookback-hours", type=int, default=2)
    parser.add_argument("--wait-seconds", type=int, default=60)
    parser.add_argument("--dashboard-deadline-seconds", type=int, default=300)
    args = parser.parse_args()
    for name, value in (("pre", args.pre_stamp), ("post", args.post_stamp)):
        if not value.isdigit():
            parser.error(f"--{name}-stamp must be numeric")
    if args.pre_stamp == args.post_stamp:
        parser.error("pre- and post-stamps must differ")
    if not math.isfinite(args.metric_cutover_seconds) or args.metric_cutover_seconds <= 0:
        parser.error("--metric-cutover-seconds must be finite and positive")
    if args.lookback_hours <= 0 or args.wait_seconds <= 0 or args.dashboard_deadline_seconds <= 0:
        parser.error("lookback and deadline values must be positive")

    deadline = time.monotonic() + args.wait_seconds
    last_error: ContinuityError | None = None
    while time.monotonic() < deadline:
        try:
            report = verify(
                args.pre_stamp,
                args.post_stamp,
                metric_cutover_seconds=args.metric_cutover_seconds,
                lookback_hours=args.lookback_hours,
                dashboard_deadline_seconds=args.dashboard_deadline_seconds,
            )
            print(json.dumps(report, sort_keys=True))
            return 0
        except (ContinuityError, dashboards.AuditError) as exc:
            last_error = ContinuityError(str(exc))
            time.sleep(2)
    print(f"ERROR: {last_error or 'continuity verification timed out'}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
