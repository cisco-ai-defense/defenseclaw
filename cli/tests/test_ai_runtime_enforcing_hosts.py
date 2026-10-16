"""AI Runtime enforcing-host stat reflects each host's latest reported state.

The stat query is evaluated here against plane_health records shaped like the
real OTLP export: every record carries its own ``defenseclaw_record_id`` and
``observed_timestamp`` (structured metadata), so a range aggregation that does
not group by host keeps one series per record. The small evaluator below
implements only the LogQL the stat uses (stream selector, ``json``, label
matchers, ``unwrap``, ``last_over_time ... by``, ``> 0``, ``count`` and
``or vector(0)``); a query outside that shape fails the test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DASHBOARD = (
    Path(__file__).resolve().parents[2]
    / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-ai-runtime.json"
)
TITLE = "Hosts with enforcing controls"
NOW = 10_000.0  # seconds; the evaluation instant
MINUTE = 60.0

_SHAPE = re.compile(
    r"^count\(last_over_time\((?P<selector>\{[^}]*\})(?P<pipeline>(?: \| [^\[]+?)*) "
    r"\[(?P<minutes>\d+)m\]\) by \((?P<group>[^)]*)\) > 0\) or vector\(0\)$"
)
_MATCHER = re.compile(r'^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<op>=~|!~|!=|=)"(?P<value>[^"]*)"$')


def _stat_expr(board: dict) -> str:
    panel = next(p for p in board["panels"] if p.get("title") == TITLE)
    assert panel["type"] == "stat"
    assert len(panel["targets"]) == 1
    return panel["targets"][0]["expr"]


def _flatten(prefix: str, value: object, out: dict[str, str]) -> None:
    # Loki's json parser: nested keys joined with "_", other characters to "_".
    if isinstance(value, dict):
        for key, item in value.items():
            name = re.sub(r"[^A-Za-z0-9_]", "_", key)
            _flatten(f"{prefix}_{name}" if prefix else name, item, out)
    elif isinstance(value, bool):
        out[prefix] = "true" if value else "false"
    elif value is not None:
        out[prefix] = str(value)


def _matches(labels: dict[str, str], matcher: str) -> bool:
    found = _MATCHER.match(matcher)
    assert found, f"unsupported matcher {matcher!r}"
    have = labels.get(found["name"], "")
    want = found["value"]
    op = found["op"]
    if op == "=":
        return have == want
    if op == "!=":
        return have != want
    hit = re.fullmatch(want, have) is not None
    return hit if op == "=~" else not hit


def evaluate(expr: str, records: list[dict], host_regex: str = ".*") -> int:
    """Evaluate the stat query over ``records`` at ``NOW`` and return its value."""
    shape = _SHAPE.match(expr.replace("$host", host_regex))
    assert shape, f"stat query is not count(last_over_time(... [Nm]) by (...) > 0) or vector(0): {expr}"
    selector = [m.strip() for m in shape["selector"][1:-1].split(",") if m.strip()]
    stages = [s.strip() for s in shape["pipeline"].split(" | ") if s.strip()]
    window = int(shape["minutes"]) * MINUTE
    group = [g.strip() for g in shape["group"].split(",") if g.strip()]
    assert group, "the range aggregation must group by host"

    latest: dict[tuple[str, ...], tuple[float, float]] = {}
    for record in records:
        labels = dict(record["stream"])
        labels.update(record.get("metadata", {}))
        if not all(_matches(labels, m) for m in selector):
            continue
        if not NOW - window < record["ts"] <= NOW:
            continue
        error = ""
        value = None
        kept = True
        for stage in stages:
            if stage == "json":
                parsed: dict[str, str] = {}
                _flatten("", record["line"], parsed)
                for key, item in parsed.items():
                    labels.setdefault(key, item)
            elif stage.startswith("unwrap "):
                name = stage.split(" ", 1)[1]
                try:
                    value = float(labels.pop(name))
                except (KeyError, ValueError):
                    error = "SampleExtractionErr"
            elif stage.startswith("__error__"):
                if not _matches({"__error__": error}, stage):
                    kept = False
                    break
            else:
                if not _matches(labels, stage):
                    kept = False
                    break
        if not kept:
            continue
        assert not error, "a sample that failed to unwrap would fail the query"
        assert value is not None, "the stat must unwrap users_enforced"
        key = tuple(labels.get(name, "") for name in group)
        if key not in latest or record["ts"] >= latest[key][0]:
            latest[key] = (record["ts"], value)
    return sum(1 for _, value in latest.values() if value > 0)


_SEQ = iter(range(1, 1_000_000))


def _health(
    host: str, minutes_ago: float, enforced: int | None, *, mode: str | None = "enforce", plane: str = "c"
) -> dict:
    body: dict[str, object] = {
        "defenseclaw.ai.runtime.plane": plane,
        "defenseclaw.ai.runtime.plane_backend": "tetragon",
    }
    if enforced is not None:
        body.update(
            {
                "defenseclaw.ai.runtime.tetragon.version": "v1.7.1",
                "defenseclaw.ai.runtime.kernel.approval": "approved",
                "defenseclaw.ai.runtime.kernel.paused": False,
                "defenseclaw.policy.version": "sha256:08b71155b713",
                "defenseclaw.ai.runtime.kernel.users_enforced": enforced,
            }
        )
        if mode is not None:
            body["defenseclaw.ai.runtime.kernel.helper_mode"] = mode
    ts = NOW - minutes_ago * MINUTE
    return {
        "stream": {"service_name": "defenseclaw", "host_name": host},
        "metadata": {"defenseclaw_record_id": f"rec-{next(_SEQ)}", "observed_timestamp": str(int(ts * 1e9))},
        "ts": ts,
        "line": {"event_name": "ai.runtime.plane_health", "body": body},
    }


@pytest.fixture(scope="module")
def expr() -> str:
    return _stat_expr(json.loads(DASHBOARD.read_text(encoding="utf-8")))


def test_a_host_that_stops_enforcing_is_no_longer_counted(expr: str) -> None:
    # 2 enforced users, then 0 with the same state labels: the latest value wins.
    records = [_health("h1", 5, 2), _health("h1", 1, 0)]
    assert evaluate(expr, records) == 0


def test_a_host_that_starts_enforcing_is_counted_once(expr: str) -> None:
    records = [_health("h1", 5, 0), _health("h1", 3, 1), _health("h1", 1, 2)]
    assert evaluate(expr, records) == 1


def test_a_mode_change_to_observe_with_no_enforced_users_is_not_counted(expr: str) -> None:
    records = [_health("h1", 5, 2), _health("h1", 1, 0, mode="observe")]
    assert evaluate(expr, records) == 0


def test_a_record_without_helper_mode_still_counts(expr: str) -> None:
    # Newer plane_health records may leave out kernel.helper_mode (an unknown mode is absent).
    assert evaluate(expr, [_health("h1", 1, 1, mode=None)]) == 1


def test_only_the_last_ten_minutes_count(expr: str) -> None:
    assert evaluate(expr, [_health("h1", 15, 3)]) == 0
    assert evaluate(expr, [_health("h1", 15, 0), _health("h1", 2, 1)]) == 1


def test_other_planes_and_records_without_kernel_state_are_ignored(expr: str) -> None:
    records = [_health("h1", 1, None, plane="b"), _health("h2", 1, None), _health("h3", 1, 1)]
    assert evaluate(expr, records) == 1


def test_hosts_are_counted_separately_and_the_host_filter_applies(expr: str) -> None:
    records = [
        _health("web-1", 4, 1),
        _health("web-1", 1, 1),
        _health("web-2", 4, 2),
        _health("web-2", 1, 0),
        _health("db-1", 1, 4),
    ]
    assert evaluate(expr, records) == 2
    assert evaluate(expr, records, host_regex="web-.*") == 1
    assert evaluate(expr, records, host_regex="none") == 0


def test_the_stat_and_its_neighbours_describe_current_state() -> None:
    board = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    by_title = {panel.get("title"): panel for panel in board["panels"]}
    stat = by_title[TITLE]
    expr = _stat_expr(board)
    assert 'host_name=~"$host"' in expr and "$user" not in expr
    assert "latest" in stat["description"].lower() and "10 minutes" in stat["description"]

    user = next(v for v in board["templating"]["list"] if v["name"] == "user")
    assert TITLE in user["description"]

    description = by_title["DefenseClaw kernel policies"]["description"]
    assert "counts" in description.lower() and "change events" in description.lower()
    assert TITLE in description
    assert "Kernel controls per host" in description
