#!/usr/bin/env python3
"""Validate the bundled Grafana dashboard contract.

The static pass is suitable for CI.  ``--live`` additionally asks the local
Prometheus, Loki, Tempo, and Grafana APIs to parse every retained query.  A
query may legitimately return no rows (for example, no approval was denied),
but it must be syntactically valid and target a configured datasource.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "bundles/local_observability_stack/grafana/dashboards"
PACKAGED_DIR = ROOT / "cli/defenseclaw/_data/local_observability_stack/grafana/dashboards"

DATASOURCES = {
    "prometheus": "defenseclaw-prometheus",
    "loki": "defenseclaw-loki",
    "tempo": "defenseclaw-tempo",
}

VARIABLES = {
    "$__range_s": "300",
    "$__rate_interval": "5m",
    "$__interval": "5m",
    "$__range": "5m",
    "$scope_label": "gen_ai_agent_id",
    "$connector": "codex",
    "$agent": ".*",
    "$lifecycle": ".*",
    "$execution": ".*",
    "$session": ".*",
    "$user": ".*",
    "$vendor": ".*",
    "$category": ".*",
    "$state": ".*",
    "$source": ".*",
    "$scanner": ".*",
    "$severity": ".*",
    "$rule_id": ".*",
    "$target_type": ".*",
    "$stage": ".*",
    "$action": ".*",
    "$egress_branch": ".*",
    "${connector:regex}": "codex",
    "${connector:pipe}": "codex",
    "${agent:regex}": ".*",
    "${lifecycle:regex}": ".*",
    "${execution:regex}": ".*",
}

INVENTORY_VARIABLES = {
    **VARIABLES,
    "$__range_s": "172800",
    "$__range": "48h",
    "$agent": ".*",
}


class AuditError(RuntimeError):
    pass


def load_dashboards(path: Path) -> list[tuple[Path, dict[str, Any]]]:
    dashboards: list[tuple[Path, dict[str, Any]]] = []
    for dashboard_path in sorted(path.glob("*.json")):
        dashboards.append((dashboard_path, json.loads(dashboard_path.read_text(encoding="utf-8"))))
    return dashboards


def panels(dashboard: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for panel in dashboard.get("panels", []):
        yield panel
        yield from panel.get("panels", [])


def dashboard_links(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "url" and isinstance(child, str) and child.startswith("/d/"):
                yield child
            else:
                yield from dashboard_links(child)
    elif isinstance(value, list):
        for child in value:
            yield from dashboard_links(child)


def target_datasource(panel: dict[str, Any], target: dict[str, Any]) -> str | None:
    value = target.get("datasource") or panel.get("datasource") or {}
    return value.get("type")


def interpolate(query: str, variables: dict[str, str] | None = None) -> str:
    replacements = VARIABLES if variables is None else variables
    for variable, value in sorted(replacements.items(), key=lambda item: -len(item[0])):
        query = query.replace(variable, value)
    query = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[^}]*)?\}", ".*", query)
    return re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", ".*", query)


def static_audit(
    *,
    require_packaged: bool = False,
) -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
    dashboards = load_dashboards(SOURCE_DIR)
    errors: list[str] = []
    if not dashboards:
        return dashboards, [f"no dashboards found under {SOURCE_DIR}"]

    for path, dashboard in dashboards:
        if not dashboard.get("uid"):
            errors.append(f"{path.name}: dashboard UID is required")
        if not dashboard.get("title"):
            errors.append(f"{path.name}: dashboard title is required")
    uids = [dashboard.get("uid") for _, dashboard in dashboards if dashboard.get("uid")]
    titles = [dashboard.get("title") for _, dashboard in dashboards if dashboard.get("title")]
    if len(set(uids)) != len(uids):
        errors.append("dashboard UIDs must be unique")
    if len(set(titles)) != len(titles):
        errors.append("dashboard titles must be unique")
    known_uids = set(uids)

    if "defenseclaw-reliability" in known_uids:
        errors.append("the retired Reliability board must stay consolidated into Runtime")

    for path, dashboard in dashboards:
        uid = dashboard.get("uid") or path.name
        if not dashboard.get("description"):
            errors.append(f"{uid}: dashboard description is required")
        serialized = json.dumps(dashboard)
        if "Speculative — pending instrumentation" in serialized:
            errors.append(f"{uid}: speculative/uninstrumented panels are not shippable")
        if "EMITTED-NOWHERE" in serialized:
            errors.append(f"{uid}: panel references explicitly orphaned instrumentation")

        top_level = dashboard.get("panels", [])
        for index, panel in enumerate(top_level):
            if panel.get("type") != "row" or panel.get("panels"):
                continue
            following = top_level[index + 1] if index + 1 < len(top_level) else None
            if following is None or following.get("type") == "row":
                errors.append(f"{uid}: empty row {panel.get('title')!r}")

        for section in ("templating", "annotations"):
            for item in dashboard.get(section, {}).get("list", []):
                datasource = item.get("datasource")
                if datasource is None:
                    continue
                if not isinstance(datasource, dict):
                    errors.append(f"{uid}/{section}: datasource must be an object")
                    continue
                datasource_type = datasource.get("type")
                datasource_uid = datasource.get("uid")
                if datasource_type == "grafana" and datasource_uid == "-- Grafana --":
                    continue
                if datasource_type not in DATASOURCES:
                    errors.append(
                        f"{uid}/{section}: unsupported datasource {datasource_type!r}",
                    )
                    continue
                if datasource_uid != DATASOURCES[datasource_type]:
                    errors.append(
                        f"{uid}/{section}: {datasource_type} must use {DATASOURCES[datasource_type]!r}",
                    )

        for panel in panels(dashboard):
            title = panel.get("title")
            kind = panel.get("type")
            if not title:
                errors.append(f"{uid}: every panel and row needs a title")
            if kind not in {"row", "text"} and not panel.get("targets"):
                errors.append(f"{uid}/{title}: panel has no query target")
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                if datasource not in DATASOURCES:
                    errors.append(f"{uid}/{title}: unsupported datasource {datasource!r}")
                    continue
                configured = (target.get("datasource") or panel.get("datasource") or {}).get("uid")
                if configured != DATASOURCES[datasource]:
                    errors.append(f"{uid}/{title}: {datasource} must use {DATASOURCES[datasource]!r}")

                expression = target.get("expr", "")
                if datasource == "loki" and "| json" in expression and '__error__=""' not in expression:
                    errors.append(f"{uid}/{title}: JSON parsing must discard malformed log lines")
                range_function = re.search(
                    r"\b(?:increase|i?rate|i?delta|changes|resets|deriv|predict_linear|holt_winters|[A-Za-z_][A-Za-z0-9_]*_over_time)\(",
                    expression,
                )
                if datasource == "prometheus" and kind == "stat" and range_function and not target.get("instant"):
                    errors.append(f"{uid}/{title}: range-aggregate stat targets must be instant queries")
                if (
                    datasource == "prometheus"
                    and re.search(r"gen_ai_client_token_usage_(?:sum|count)", expression)
                    and not range_function
                ):
                    errors.append(f"{uid}/{title}: historical token panels must use a range function")
                if (
                    datasource == "prometheus"
                    and re.match(
                        r"^\s*(?:sum|avg|max|min|count)\s+by\s*\([^)]*\)",
                        expression,
                    )
                    and re.search(r"\bor\s+vector\(0\)", expression)
                ):
                    errors.append(
                        f"{uid}/{title}: grouped zero fallbacks must use `or on() vector(0)` "
                        "to avoid an unlabeled series",
                    )

        for link in dashboard_links(dashboard):
            match = re.match(r"/d/([^/?]+)", link)
            if match and match.group(1) not in known_uids:
                errors.append(f"{uid}: dashboard link targets missing UID {match.group(1)!r}")

    if require_packaged and not PACKAGED_DIR.is_dir():
        errors.append(f"CLI packaged Grafana dashboard directory is missing: {PACKAGED_DIR}")
    elif PACKAGED_DIR.is_dir():
        packaged = load_dashboards(PACKAGED_DIR)
        source_by_name = {path.name: dashboard for path, dashboard in dashboards}
        packaged_by_name = {path.name: dashboard for path, dashboard in packaged}
        if source_by_name != packaged_by_name:
            errors.append("CLI packaged Grafana dashboards do not match bundle sources")

    return dashboards, errors


def request_json(url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise AuditError(f"{url}: HTTP {exc.code}: {body[:400]}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"{url}: {exc}") from exc


def _numeric_result_status(result: Any) -> str:
    """Classify a Prometheus or metric-LogQL result without inventing data."""

    if not result:
        return "empty"
    values: list[Any] = []
    for series in result:
        if not isinstance(series, dict):
            continue
        if "value" in series:
            values.append(series["value"][-1])
        values.extend(value[-1] for value in series.get("values", []))
    saw_finite_value = False
    for raw_value in values:
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(value):
            continue
        saw_finite_value = True
        if value != 0:
            return "data"
    return "zero" if saw_finite_value else "empty"


def _inventory_variables(range_seconds: int) -> dict[str, str]:
    variables = dict(INVENTORY_VARIABLES)
    variables["$__range_s"] = str(range_seconds)
    variables["$__range"] = f"{max(1, range_seconds // 3600)}h"
    return variables


def tempo_readiness_error(*, attempts: int = 6, retry_delay_seconds: float = 2) -> str | None:
    """Wait up to ten seconds for transient Tempo startup/compaction readiness."""

    tempo_error: OSError | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen("http://127.0.0.1:3200/ready", timeout=10) as response:
                if response.status == 200:
                    return None
                tempo_error = OSError(f"HTTP {response.status}")
        except OSError as exc:
            tempo_error = exc
        if attempt < attempts - 1:
            time.sleep(retry_delay_seconds)
    return f"Tempo readiness failed after {attempts} attempts: {tempo_error}"


def live_inventory(
    dashboards: list[tuple[Path, dict[str, Any]]],
    *,
    range_seconds: int = 48 * 60 * 60,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Measure whether every retained panel can render against the local stack.

    Empty and zero are intentionally different: ``zero`` proves a signal is
    instrumented but no matching event occurred, while ``empty`` means the
    selected deployment/range has no matching series or event.  Trace
    waterfalls that require a user-selected trace are reported as
    ``interactive`` instead of being mislabeled as broken.
    """

    errors: list[str] = []
    inventory: list[dict[str, Any]] = []
    now_seconds = time.time()
    start_seconds = now_seconds - range_seconds
    now_ns = int(now_seconds * 1_000_000_000)
    start_ns = int(start_seconds * 1_000_000_000)
    variables = _inventory_variables(range_seconds)
    step_seconds = max(60, min(900, range_seconds // 200))
    has_tempo_search = any(
        (query := target.get("query", ""))
        and not any(variable in query for variable in ("$trace", "$agent", "$scope_label"))
        for _, dashboard in dashboards
        for panel in panels(dashboard)
        for target in panel.get("targets", [])
        if target_datasource(panel, target) == "tempo"
    )
    tempo_error = tempo_readiness_error() if has_tempo_search else None

    for _, dashboard in dashboards:
        panel_results: list[dict[str, Any]] = []
        for panel in panels(dashboard):
            if panel.get("type") in {"row", "text"}:
                continue
            target_statuses: list[str] = []
            target_errors: list[str] = []
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                expression = target.get("expr", "")
                trace_query = target.get("query", "")
                try:
                    if datasource == "prometheus" and expression:
                        params = {"query": interpolate(expression, variables)}
                        if target.get("instant"):
                            params["time"] = str(now_seconds)
                            endpoint = "http://127.0.0.1:9090/api/v1/query"
                        else:
                            params.update(
                                {
                                    "start": str(start_seconds),
                                    "end": str(now_seconds),
                                    "step": str(step_seconds),
                                },
                            )
                            endpoint = "http://127.0.0.1:9090/api/v1/query_range"
                        result = request_json(endpoint, params)
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                        target_statuses.append(
                            _numeric_result_status(result.get("data", {}).get("result")),
                        )
                    elif datasource == "loki" and expression:
                        params = {
                            "query": interpolate(expression, variables),
                            "limit": "10",
                        }
                        if target.get("instant") or target.get("queryType") == "instant":
                            params["time"] = str(now_ns)
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query"
                        else:
                            params.update(
                                {
                                    "start": str(start_ns),
                                    "end": str(now_ns),
                                    "step": str(step_seconds),
                                    "direction": "backward",
                                },
                            )
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query_range"
                        result = request_json(
                            endpoint,
                            params,
                        )
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                        data = result.get("data", {})
                        rows = data.get("result", [])
                        if data.get("resultType") == "streams":
                            target_statuses.append("data" if rows else "empty")
                        else:
                            target_statuses.append(_numeric_result_status(rows))
                    elif datasource == "tempo" and trace_query:
                        if any(variable in trace_query for variable in ("$trace", "$agent", "$scope_label")):
                            target_statuses.append("interactive")
                        else:
                            if tempo_error is not None:
                                raise AuditError(tempo_error)
                            result = request_json(
                                "http://127.0.0.1:3200/api/search",
                                {
                                    "q": interpolate(trace_query, variables),
                                    "limit": "10",
                                    "start": str(int(start_seconds)),
                                    "end": str(int(now_seconds)),
                                },
                            )
                            target_statuses.append("data" if result.get("traces") else "empty")
                except AuditError as exc:
                    target_errors.append(str(exc))

            if not target_statuses and not target_errors:
                continue
            if target_errors:
                status = "error"
            elif "data" in target_statuses:
                status = "data"
            elif "zero" in target_statuses:
                status = "zero"
            elif set(target_statuses) == {"interactive"}:
                status = "interactive"
            else:
                status = "empty"
            panel_result = {
                "title": panel.get("title", "untitled"),
                "type": panel.get("type", "unknown"),
                "status": status,
            }
            if target_errors:
                panel_result["errors"] = target_errors
                errors.extend(
                    f"{dashboard['uid']}/{panel_result['title']}: {error}" for error in target_errors
                )
            panel_results.append(panel_result)

        status_counts = {
            status: sum(result["status"] == status for result in panel_results)
            for status in ("data", "zero", "empty", "interactive", "error")
        }
        inventory.append(
            {
                "uid": dashboard["uid"],
                "title": dashboard["title"],
                "description": dashboard.get("description", ""),
                "panels": panel_results,
                "status_counts": status_counts,
            },
        )
    return inventory, errors


def print_inventory(inventory: list[dict[str, Any]], *, range_seconds: int) -> None:
    hours = range_seconds / 3600
    print(f"Live Grafana inventory ({hours:g}h, representative connector=codex, all agents)")
    print("| Dashboard | Panels | Data | Zero | Empty | Interactive | Errors | Empty panels |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for dashboard in inventory:
        counts = dashboard["status_counts"]
        empty_titles = [
            result["title"] for result in dashboard["panels"] if result["status"] == "empty"
        ]
        print(
            f"| {dashboard['title']} (`{dashboard['uid']}`) "
            f"| {len(dashboard['panels'])} | {counts['data']} | {counts['zero']} "
            f"| {counts['empty']} | {counts['interactive']} | {counts['error']} "
            f"| {', '.join(empty_titles) or 'None'} |",
        )


def live_audit(dashboards: list[tuple[Path, dict[str, Any]]]) -> list[str]:
    errors: list[str] = []
    try:
        health = request_json("http://127.0.0.1:3000/api/health")
    except AuditError as exc:
        return [f"Grafana health failed: {exc}"]
    if health.get("database") != "ok":
        errors.append("Grafana database health is not ok")

    tempo_error = tempo_readiness_error()
    if tempo_error is not None:
        errors.append(tempo_error)

    now_ns = int(time.time() * 1_000_000_000)
    start_ns = now_ns - 300 * 1_000_000_000

    for _, dashboard in dashboards:
        uid = dashboard["uid"]
        for panel in panels(dashboard):
            title = panel.get("title", "untitled")
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                expression = target.get("expr", "")
                try:
                    if datasource == "prometheus" and expression:
                        result = request_json(
                            "http://127.0.0.1:9090/api/v1/query",
                            {"query": interpolate(expression)},
                        )
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                    elif datasource == "loki" and expression:
                        query = interpolate(expression).replace("[1h]", "[5m]").replace("[24h]", "[5m]")
                        if panel.get("type") == "logs":
                            params = {
                                "query": query,
                                "start": str(start_ns),
                                "end": str(now_ns),
                                "limit": "1",
                                "direction": "backward",
                            }
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query_range"
                        else:
                            params = {"query": query, "time": str(now_ns), "limit": "1"}
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query"
                        result = request_json(endpoint, params)
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                    elif datasource == "tempo" and tempo_error is None:
                        query = target.get("query")
                        if query and query != "$trace":
                            request_json(
                                "http://127.0.0.1:3200/api/search",
                                {"q": interpolate(query), "limit": "1"},
                            )
                except AuditError as exc:
                    errors.append(f"{uid}/{title}: {exc}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also compile every query against the local stack")
    parser.add_argument(
        "--require-packaged",
        action="store_true",
        help="fail if the generated CLI dashboard mirror is absent",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="report data/zero/empty/interactive/error panels against the local stack",
    )
    parser.add_argument(
        "--inventory-hours",
        type=int,
        default=48,
        help="lookback used by --inventory (default: 48 hours)",
    )
    args = parser.parse_args()

    if args.inventory_hours <= 0:
        parser.error("--inventory-hours must be greater than zero")

    dashboards, errors = static_audit(require_packaged=args.require_packaged)
    if args.live and not errors:
        errors.extend(live_audit(dashboards))
    inventory: list[dict[str, Any]] = []
    if args.inventory and not errors:
        inventory, inventory_errors = live_inventory(
            dashboards,
            range_seconds=args.inventory_hours * 60 * 60,
        )
        errors.extend(inventory_errors)

    if args.inventory and inventory:
        print_inventory(inventory, range_seconds=args.inventory_hours * 60 * 60)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"Grafana audit passed: {len(dashboards)} dashboards, "
        f"{sum(1 for _, dashboard in dashboards for panel in panels(dashboard) if panel.get('type') != 'row')} panels"
        + (", live queries compiled" if args.live else "")
        + (", live data inventoried" if args.inventory else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
