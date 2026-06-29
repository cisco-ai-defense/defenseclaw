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


def interpolate(query: str) -> str:
    for variable, value in sorted(VARIABLES.items(), key=lambda item: -len(item[0])):
        query = query.replace(variable, value)
    query = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[^}]*)?\}", ".*", query)
    return re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", ".*", query)


def static_audit() -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
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
                    r"\b(?:increase|rate|max_over_time|last_over_time)\(", expression,
                )
                if datasource == "prometheus" and kind == "stat" and range_function and not target.get("instant"):
                    errors.append(f"{uid}/{title}: range-aggregate stat targets must be instant queries")
                if (
                    datasource == "prometheus"
                    and re.search(r"gen_ai_client_token_usage_(?:sum|count)", expression)
                    and not range_function
                ):
                    errors.append(f"{uid}/{title}: historical token panels must use a range function")

        for link in dashboard_links(dashboard):
            match = re.match(r"/d/([^/?]+)", link)
            if match and match.group(1) not in known_uids:
                errors.append(f"{uid}: dashboard link targets missing UID {match.group(1)!r}")

    if not PACKAGED_DIR.is_dir():
        errors.append(f"CLI packaged Grafana dashboard directory is missing: {PACKAGED_DIR}")
    else:
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


def live_audit(dashboards: list[tuple[Path, dict[str, Any]]]) -> list[str]:
    errors: list[str] = []
    try:
        health = request_json("http://127.0.0.1:3000/api/health")
    except AuditError as exc:
        return [f"Grafana health failed: {exc}"]
    if health.get("database") != "ok":
        errors.append("Grafana database health is not ok")

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
                    elif datasource == "tempo":
                        query = target.get("query")
                        if query and query != "$trace":
                            request_json(
                                "http://127.0.0.1:3200/api/search",
                                {"q": interpolate(query), "limit": "1"},
                            )
                except AuditError as exc:
                    errors.append(f"{uid}/{title}: {exc}")

    try:
        with urllib.request.urlopen("http://127.0.0.1:3200/ready", timeout=10) as response:
            if response.status != 200:
                errors.append(f"Tempo readiness returned HTTP {response.status}")
    except OSError as exc:
        errors.append(f"Tempo readiness failed: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also compile every query against the local stack")
    args = parser.parse_args()

    dashboards, errors = static_audit()
    if args.live and not errors:
        errors.extend(live_audit(dashboards))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"Grafana audit passed: {len(dashboards)} dashboards, "
        f"{sum(1 for _, dashboard in dashboards for panel in panels(dashboard) if panel.get('type') != 'row')} panels"
        + (", live queries compiled" if args.live else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
