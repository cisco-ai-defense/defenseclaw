#!/usr/bin/env python3
"""Static local-observability-v1 compatibility inventory and validator.

This module derives every dashboard/rule dependency from the shipped assets and
validates it against the generated local-observability-v1 consumer profile.
Semantic validation, rather than hashes or hand-maintained instrument counts,
keeps PR #412 compatible as additive telemetry families are introduced.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

try:
    from scripts.telemetry_runtime_assets import read_logical_asset
except ModuleNotFoundError:  # direct ``python scripts/local_observability_v1.py``
    from telemetry_runtime_assets import read_logical_asset

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bundles/local_observability_stack"
PACKAGED = ROOT / "cli/defenseclaw/_data/local_observability_stack"
METRIC_MANIFEST = "schemas/telemetry/generated/compatibility/local-observability-v1.json"
METRIC_EMITTER = ROOT / "internal/telemetry/metrics.go"
TELEMETRY_CATALOG = "schemas/telemetry/generated/catalog.json"
COLLECTOR = BUNDLE / "otel-collector/config.yaml"
COMPOSE = BUNDLE / "docker-compose.yml"
RULES = BUNDLE / "prometheus/rules"

EXPECTED_DASHBOARD_UIDS = {
    "defenseclaw-activity",
    "defenseclaw-agent-360",
    "defenseclaw-agent-identity",
    "defenseclaw-ai-discovery",
    "defenseclaw-connector-detail",
    "defenseclaw-connectors",
    "defenseclaw-findings",
    "defenseclaw-hitl",
    "defenseclaw-overview",
    "defenseclaw-policy-decisions",
    "defenseclaw-runtime",
    "defenseclaw-scanners",
    "defenseclaw-security",
    "defenseclaw-traffic",
}
EXPECTED_DATASOURCE_UIDS = {
    "prometheus": "defenseclaw-prometheus",
    "loki": "defenseclaw-loki",
    "tempo": "defenseclaw-tempo",
}
EXPECTED_SPANMETRICS_DIMENSIONS = {
    "gen_ai.operation.name",
    "gen_ai.agent.id",
    "gen_ai.agent.name",
    "gen_ai.agent.type",
    "defenseclaw.agent.root.id",
    "defenseclaw.agent.parent.id",
    "defenseclaw.agent.lifecycle.id",
    "defenseclaw.agent.execution.id",
    "defenseclaw.agent.lifecycle.event",
    "defenseclaw.agent.lifecycle.state",
    "defenseclaw.agent.phase",
    "defenseclaw.agent.phase.previous",
    "defenseclaw.agent.phase.code",
    "connector",
    "gen_ai.tool.name",
    "defenseclaw.destination.app",
    "gen_ai.provider.name",
    "gen_ai.request.model",
}
EXPECTED_SPANMETRICS_BUCKETS = [
    "5ms",
    "10ms",
    "25ms",
    "50ms",
    "100ms",
    "250ms",
    "500ms",
    "1s",
    "2s",
    "5s",
    "10s",
    "30s",
    "1m",
    "5m",
]
EXPECTED_CANARY_ATTRIBUTE = "defenseclaw.telemetry.canary"
EXPECTED_CANARY_FILTER_CONDITION = 'span.attributes["defenseclaw.telemetry.canary"] == true'
EXPECTED_RESOURCE_ATTRIBUTE_ACTIONS = [
    {"key": "service.namespace", "value": "defenseclaw", "action": "insert"},
    {
        "key": "deployment.environment",
        "from_attribute": "deployment.environment.name",
        "action": "insert",
    },
    {"key": "deployment.environment", "value": "local-dev", "action": "insert"},
]
EXPECTED_VOLUMES = {"prometheus-data", "loki-data", "tempo-data", "grafana-data"}

EXPECTED_HISTOGRAM_SHA256 = "5fcf36c247ed6a483bd5b9d53a0c9c1105c6210d8eb0d9ec18bdf94b80850f9c"

PROMETHEUS_RESOURCE_LABELS = {
    "deployment_environment",
    "host_arch",
    "host_name",
    "instance",
    "job",
    "os_type",
    "otel_scope_name",
    "otel_scope_version",
    "service_name",
    "service_namespace",
    "service_version",
}
PROMETHEUS_DERIVED_LABELS = {
    "alertstate",
    "hook_event",
    "le",
    "quantile",
    "span_name",
    "status_code",
}
EXTERNAL_PROMETHEUS_METRICS = {
    "loki_discarded_samples_total",
    "loki_distributor_lines_received_total",
    "up",
}
LOKI_BUILTIN_FIELDS = {
    "__error__",
    # Native OTLP ingestion preserves the canonical record attribute
    # `defenseclaw.event.name` as structured metadata. Loki normalizes dots
    # to underscores, so it is queryable before `| json` under this spelling.
    "defenseclaw_event_name",
    "level",
    "severity_text",
    "service_name",
    "span_id",
    "trace_id",
}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _load_telemetry_json(logical_path: str) -> dict[str, Any]:
    value = json.loads(read_logical_asset(ROOT, logical_path))
    return value if isinstance(value, dict) else {}


def _panels(dashboard: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for panel in dashboard.get("panels", []):
        yield panel
        yield from _panels(panel)


def _query_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        query = value.get("query")
        return query if isinstance(query, str) else ""
    return ""


def dashboard_queries(
    dashboards: list[tuple[Path, dict[str, Any]]],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for path, dashboard in dashboards:
        uid = str(dashboard.get("uid", path.stem))
        for panel in _panels(dashboard):
            for target in panel.get("targets", []):
                datasource = target.get("datasource") or panel.get("datasource") or {}
                datasource_type = datasource.get("type", "") if isinstance(datasource, dict) else ""
                expression = target.get("expr") or target.get("query") or ""
                if not expression and datasource_type == "tempo" and target.get("filters"):
                    conditions = []
                    for item in target["filters"]:
                        scope = item.get("scope")
                        tag = item.get("tag")
                        if scope and tag:
                            conditions.append(f"{scope}.{tag}")
                    structured = json.dumps(
                        {
                            "queryType": target.get("queryType"),
                            "filters": target.get("filters"),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    expression = "{ " + " && ".join(conditions) + " } # " + structured
                if expression:
                    result.append(
                        {
                            "source": f"dashboard:{uid}",
                            "consumer": str(panel.get("title", "untitled")),
                            "ref": str(target.get("refId", "?")),
                            "datasource": str(datasource_type),
                            "query": str(expression),
                        },
                    )
        for section in ("templating", "annotations"):
            for index, item in enumerate(dashboard.get(section, {}).get("list", [])):
                datasource = item.get("datasource") or {}
                datasource_type = datasource.get("type", "") if isinstance(datasource, dict) else ""
                expression = _query_text(item.get("query")) or _query_text(item.get("definition"))
                # Grafana custom variables store comma-separated choices in
                # `query` but do not execute a datasource query. Inventory
                # only executable templating/annotation dependencies.
                if expression and datasource_type:
                    result.append(
                        {
                            "source": f"dashboard:{uid}",
                            "consumer": f"{section}:{item.get('name', index)}",
                            "ref": str(index),
                            "datasource": str(datasource_type),
                            "query": expression,
                        },
                    )
    return result


def rule_queries() -> tuple[list[dict[str, str]], set[str]]:
    result: list[dict[str, str]] = []
    recording_names: set[str] = set()
    for path in sorted(RULES.glob("*.yml")):
        for group in _load_yaml(path).get("groups", []):
            for index, rule in enumerate(group.get("rules", [])):
                name = rule.get("record") or rule.get("alert") or str(index)
                if rule.get("record"):
                    recording_names.add(str(rule["record"]))
                if rule.get("expr"):
                    result.append(
                        {
                            "source": f"rule:{path.name}",
                            "consumer": f"{group.get('name', '?')}:{name}",
                            "ref": str(index),
                            "datasource": "prometheus",
                            "query": str(rule["expr"]),
                        },
                    )
    return result, recording_names


def _prometheus_projection(metric: dict[str, Any]) -> set[str]:
    name = str(metric["name"]).replace(".", "_").replace("-", "_")
    kind = str(metric["type"])
    unit = str(metric.get("unit", ""))
    unit_suffix = {"ms": "milliseconds", "s": "seconds", "ns": "nanoseconds"}.get(unit)
    if unit_suffix:
        name += f"_{unit_suffix}"
    elif unit == "USD":
        name += "_USD"
    elif unit == "1" and kind == "gauge":
        name += "_ratio"
    if kind == "counter" and not name.endswith("_total"):
        name += "_total"
    if kind == "histogram":
        return {f"{name}_bucket", f"{name}_sum", f"{name}_count"}
    return {name}


def prometheus_inputs(recording_names: set[str]) -> set[str]:
    manifest = _load_telemetry_json(METRIC_MANIFEST)
    result = set(EXTERNAL_PROMETHEUS_METRICS) | set(recording_names)
    for family in manifest.get("families", []):
        if family.get("signal") != "metrics":
            continue
        projection = family.get("projection", {})
        result.update(
            _prometheus_projection(
                {
                    "name": family.get("event_name", ""),
                    "type": projection.get("instrument_type", ""),
                    "unit": projection.get("unit", ""),
                },
            ),
        )
    result.update(
        {
            "defenseclaw_agent_span_calls_total",
            "defenseclaw_agent_span_duration_milliseconds_bucket",
            "defenseclaw_agent_span_duration_milliseconds_sum",
            "defenseclaw_agent_span_duration_milliseconds_count",
        },
    )
    return result


def _prometheus_metric_dependencies(query: str, known: set[str]) -> set[str]:
    unquoted = re.sub(r'"(?:\\.|[^"\\])*"', "", query)
    result = {
        match
        for match in re.findall(
            r"\b((?:defenseclaw|gen_ai|loki|otelcol|prometheus)_[A-Za-z0-9_:]+)\s*(?=\{|\[)",
            unquoted,
        )
    }
    for name in known:
        if re.search(rf"(?<![A-Za-z0-9_:]){re.escape(name)}(?![A-Za-z0-9_:])", unquoted):
            result.add(name)
    return result


def _prometheus_label_dependencies(query: str) -> set[str]:
    result: set[str] = set()
    for selector in re.findall(r"\{([^{}]*)\}", query):
        result.update(
            re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|=|!=)", selector),
        )
    for group in re.findall(r"\b(?:by|without|on)\s*\(([^)]*)\)", query):
        result.update(item.strip() for item in group.split(",") if item.strip())
    for function in ("label_replace", "label_join"):
        for call in re.findall(rf"{function}\((.*?)\)", query):
            result.update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', call))
    result.discard("scope_label")
    return result


def prometheus_label_inputs() -> set[str]:
    result = set(PROMETHEUS_RESOURCE_LABELS) | set(PROMETHEUS_DERIVED_LABELS)
    manifest = _load_telemetry_json(METRIC_MANIFEST)
    local_metric_projections: dict[str, dict[str, str]] = {}
    for family in manifest.get("families", []):
        if family.get("signal") != "metrics" or family.get("eligibility") != "eligible":
            continue
        projection = family.get("projection", {})
        label_projection = projection.get("label_projection", {})
        aliases: dict[str, str] = {}
        for mapping in label_projection.get("mappings", []):
            if isinstance(mapping, list) and len(mapping) == 2:
                aliases[str(mapping[0])] = str(mapping[1])
        family_id = family.get("family_id")
        if isinstance(family_id, str) and family_id:
            local_metric_projections[family_id] = aliases

    # An explicit local mapping renames one canonical label. Every omitted
    # canonical label projects unchanged and is normalized by Prometheus. Read
    # both halves from generated authority so additive schema fields require no
    # checker allowlist update and a renamed field is not accidentally accepted
    # under both spellings.
    catalog = _load_telemetry_json(TELEMETRY_CATALOG)
    for family in catalog.get("families", []):
        aliases = local_metric_projections.get(family.get("id"))
        if aliases is None:
            continue
        for field in family.get("fields", []):
            ref = field.get("ref")
            if not isinstance(ref, str) or not ref:
                continue
            projected = aliases.get(ref, ref)
            result.add(projected.replace(".", "_").replace("-", "_"))
    source = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in (ROOT / "internal").rglob("*.go"))
    for key in re.findall(
        r'(?:attribute|otellog|log)\.(?:String|Int|Int64|Bool|Float64|StringSlice)\(\s*"([^"]+)"',
        source,
    ):
        result.add(key.replace(".", "_").replace("-", "_"))
    result.update(item.replace(".", "_") for item in EXPECTED_SPANMETRICS_DIMENSIONS)
    return result


def _loki_dependencies(query: str) -> set[str]:
    # Go-template field references are dot-prefixed, while canonical event
    # values also contain dots (for example ``model.response``). Restrict this
    # pass to dots that start a template expression or follow whitespace so
    # family-name segments are not mistaken for log fields.
    result = set(
        re.findall(
            r"(?:(?<={)|(?<=\s))\.([A-Za-z_][A-Za-z0-9_]*)",
            query,
        ),
    )
    unquoted = re.sub(r'"(?:\\.|[^"\\])*"', "", query)
    for field in re.findall(r"(?<![.$])\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|=|!=)", unquoted):
        if field not in {"job", "level", "service_name", "stream"}:
            result.add(field)
    # Labels materialized by this same LogQL expression are valid downstream
    # grouping/filter inputs even though they are not present in the record.
    for label_format in re.findall(r"\blabel_format\s+([^|\[]+)", query):
        result.difference_update(
            re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", label_format),
        )
    result.difference_update(
        re.findall(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>", query),
    )
    result.discard("_")
    return result


def loki_inputs() -> set[str]:
    result = set(LOKI_BUILTIN_FIELDS)
    result.update(
        {
            "schema_version",
            "bucket_catalog_version",
            "timestamp",
            "observed_at",
            "record_id",
            "bucket",
            "signal",
            "event_name",
            "span_name",
            "severity",
            "log_level",
            "source",
            "connector",
            "action",
            "phase",
            "outcome",
            "mandatory",
        },
    )
    for name in (
        "run_id",
        "request_id",
        "session_id",
        "turn_id",
        "trace_id",
        "span_id",
        "agent_id",
        "agent_instance_id",
        "policy_id",
        "policy_version",
        "evaluation_id",
        "scan_id",
        "finding_occurrence_id",
        "enforcement_action_id",
        "model_request_id",
        "model_response_id",
        "tool_invocation_id",
        "destination_id",
        "connector_id",
        "sidecar_instance_id",
    ):
        result.add(f"correlation_{name}")
    for name in (
        "producer",
        "binary_version",
        "registry_schema_version",
        "config_generation",
        "build_commit",
        "config_digest",
    ):
        result.add(f"provenance_{name}")

    # The generated catalog is the only body-field authority. Loki's JSON
    # parser flattens the canonical ``body`` object and normalizes dots/dashes
    # to underscores, so derive exactly that query vocabulary here.
    catalog = _load_telemetry_json(TELEMETRY_CATALOG)
    for family in catalog.get("families", []):
        if family.get("signal") != "logs":
            continue
        if not any(
            profile.get("id") == "local-observability-v1"
            and profile.get("availability") == "available"
            for profile in family.get("compatibility_profiles", [])
            if isinstance(profile, dict)
        ):
            continue
        for field in family.get("fields", []):
            if field.get("role") != "body_fields":
                continue
            ref = field.get("ref")
            if isinstance(ref, str) and ref:
                result.add(f"body_{ref.replace('.', '_').replace('-', '_')}")

    # ``gen_ai.tool.call.arguments`` is a schema-owned structured value. The
    # Codex collaboration bridge reports its bounded routing target as the
    # nested ``target`` member; Loki's JSON parser flattens that member one
    # level further. This is not a parallel legacy field: it is the canonical
    # child used to group truthful send_message relationships without parsing
    # or exposing the message body.
    result.add("body_gen_ai_tool_call_arguments_target")
    return result


def _tempo_dependencies(query: str) -> set[str]:
    unquoted = re.sub(r'"(?:\\.|[^"\\])*"', "", query)
    return set(re.findall(r"\b(?:span|resource)\.([A-Za-z_][A-Za-z0-9_.]*)", unquoted))


def tempo_inputs() -> set[str]:
    result: set[str] = {"name", "service.name"}

    # Generated v8 trace families are emitted through descriptor-driven
    # builders, so their attribute keys do not appear as literal
    # attribute.String("...") calls in Go. The generated catalog is the
    # authoritative current vocabulary and keeps dashboard validation in step
    # with additive schema changes without another hand-maintained allowlist.
    catalog = _load_telemetry_json(TELEMETRY_CATALOG)
    for family in catalog.get("families", []):
        if family.get("signal") != "traces":
            continue
        for field in family.get("fields", []):
            ref = field.get("ref")
            if isinstance(ref, str) and "." in ref:
                result.add(ref)
    resources = catalog.get("resource_attributes", {})
    if isinstance(resources, dict):
        result.update(
            ref
            for ref in resources.get("fixed_keys", [])
            if isinstance(ref, str) and "." in ref
        )
        for alias in resources.get("compatibility_aliases", []):
            if isinstance(alias, dict):
                result.update(
                    ref
                    for ref in (alias.get("alias"), alias.get("canonical"))
                    if isinstance(ref, str) and "." in ref
                )

    for path in (ROOT / "schemas/otel").glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        stack: list[Any] = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                properties = item.get("properties")
                if isinstance(properties, dict):
                    result.update(name for name in properties if "." in name)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    for path in (ROOT / "internal").rglob("*.go"):
        source = path.read_text(encoding="utf-8", errors="ignore")
        result.update(
            re.findall(
                r'attribute\.(?:String|Int|Int64|Bool|Float64|StringSlice)\(\s*"([^"]+)"',
                source,
            ),
        )
    return result


def histogram_inventory() -> dict[str, str]:
    source = METRIC_EMITTER.read_text(encoding="utf-8")
    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    sdk_version_match = re.search(
        r"^\s*go\.opentelemetry\.io/otel/sdk\s+(v[^\s]+)",
        go_mod,
        re.MULTILINE,
    )
    sdk_version = sdk_version_match.group(1) if sdk_version_match else "unresolved"
    variables: dict[str, str] = {}
    for name, body in re.findall(r"(\w+)\s*:=\s*\[\]float64\s*\{([^}]*)\}", source, re.DOTALL):
        values = [
            part.strip()
            for part in body.replace("\n", " ").split(",")
            if part.strip() and not part.strip().startswith("//")
        ]
        variables[name] = ",".join(values)
    result: dict[str, str] = {}
    pattern = re.compile(
        r'ms\.\w+,\s*err\s*=\s*m\.(?:Float64|Int64)Histogram\("([^"]+)"(.*?)(?=\n\tif err != nil)',
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        name, body = match.groups()
        boundaries = re.search(r"WithExplicitBucketBoundaries\((.*?)\)", body, re.DOTALL)
        if boundaries is None:
            result[name] = f"otel-sdk-default-{sdk_version}"
            continue
        value = " ".join(boundaries.group(1).split())
        if value.endswith("...") and value[:-3] in variables:
            value = variables[value[:-3]]
        result[name] = re.sub(r"\s*,\s*", ",", value)
    return result


def _bundle_parity_errors() -> list[str]:
    errors: list[str] = []
    source_files = {path.relative_to(BUNDLE) for path in BUNDLE.rglob("*") if path.is_file()}
    packaged_files = {path.relative_to(PACKAGED) for path in PACKAGED.rglob("*") if path.is_file()}
    if source_files != packaged_files:
        errors.append(
            "local-observability source/packaged file inventories differ: "
            f"source_only={sorted(map(str, source_files - packaged_files))}, "
            f"packaged_only={sorted(map(str, packaged_files - source_files))}",
        )
    for relative in sorted(source_files & packaged_files):
        if (BUNDLE / relative).read_bytes() != (PACKAGED / relative).read_bytes():
            errors.append(f"local-observability packaged file differs: {relative}")
    return errors


def _collector_errors() -> list[str]:
    errors: list[str] = []
    collector = _load_yaml(COLLECTOR)
    pipelines = collector.get("service", {}).get("pipelines", {})
    expected_pipelines = {
        "traces": {
            "receivers": ["otlp"],
            "processors": ["resource", "batch"],
            "exporters": ["otlp/tempo", "forward/agent360", "debug"],
        },
        "traces/agent360-spanmetrics": {
            "receivers": ["forward/agent360"],
            "processors": ["filter/agent360-canary"],
            "exporters": ["spanmetrics/agent360"],
        },
        "metrics": {
            "receivers": ["otlp", "spanmetrics/agent360"],
            "processors": ["resource", "deltatocumulative", "batch"],
            "exporters": ["prometheusremotewrite/prometheus", "debug"],
        },
        "logs": {
            "receivers": ["otlp"],
            "processors": ["resource", "batch"],
            "exporters": ["otlphttp/loki", "debug"],
        },
    }
    if pipelines != expected_pipelines:
        errors.append("Collector signal pipelines drifted from local-observability-v1")
    content_mutators = {"attributes/strip-bodies", "transform/loki-payload-cap"}
    configured_mutators = content_mutators.intersection(collector.get("processors", {}))
    if configured_mutators:
        errors.append(
            "Collector must not mutate the canonical post-redaction OTEL projection: "
            f"{sorted(configured_mutators)}",
        )
    connectors = collector.get("connectors", {})
    if "forward/agent360" not in connectors or connectors.get("forward/agent360") not in (None, {}):
        errors.append("forward/agent360 must remain an unconfigured trace branch connector")
    canary_filter = collector.get("processors", {}).get("filter/agent360-canary", {})
    if canary_filter != {
        "error_mode": "ignore",
        "trace_conditions": [EXPECTED_CANARY_FILTER_CONDITION],
    }:
        errors.append(
            "Agent360 canary filter must drop only the exact canonical boolean span attribute",
        )
    resource_actions = collector.get("processors", {}).get("resource", {}).get("attributes")
    if resource_actions != EXPECTED_RESOURCE_ATTRIBUTE_ACTIONS:
        errors.append(
            "Collector resource aliases must preserve explicit legacy values, derive "
            "deployment.environment from deployment.environment.name, and default only when both are absent",
        )
    spanmetrics = collector.get("connectors", {}).get("spanmetrics/agent360", {})
    dimensions = {item.get("name") for item in spanmetrics.get("dimensions", [])}
    if dimensions != EXPECTED_SPANMETRICS_DIMENSIONS:
        errors.append(
            "spanmetrics/agent360 dimensions drifted: "
            f"missing={sorted(EXPECTED_SPANMETRICS_DIMENSIONS - dimensions)}, "
            f"extra={sorted(dimensions - EXPECTED_SPANMETRICS_DIMENSIONS)}",
        )
    buckets = spanmetrics.get("histogram", {}).get("explicit", {}).get("buckets")
    if buckets != EXPECTED_SPANMETRICS_BUCKETS:
        errors.append(f"spanmetrics/agent360 buckets drifted: {buckets!r}")
    if spanmetrics.get("metrics_flush_interval") != "15s":
        errors.append("spanmetrics/agent360 metrics_flush_interval must remain 15s")
    compose = _load_yaml(COMPOSE)
    collector_image = compose.get("services", {}).get("otel-collector", {}).get("image")
    if collector_image != "otel/opentelemetry-collector-contrib:0.153.0":
        errors.append(f"Collector image drifted from 0.153.0: {collector_image!r}")
    if set(compose.get("volumes", {})) != EXPECTED_VOLUMES:
        errors.append("persistent local-observability volume inventory drifted")
    expected_mounts = {
        "prometheus": "prometheus-data:/prometheus",
        "loki": "loki-data:/loki",
        "tempo": "tempo-data:/var/tempo",
        "grafana": "grafana-data:/var/lib/grafana",
    }
    for service_name, expected_mount in expected_mounts.items():
        mounts = compose.get("services", {}).get(service_name, {}).get("volumes", []) or []
        if expected_mount not in mounts:
            errors.append(
                f"{service_name} no longer mounts persistent volume {expected_mount}",
            )
    for service in compose.get("services", {}).values():
        for port in service.get("ports", []) or []:
            if isinstance(port, str) and not port.startswith("${HOST_BIND:-127.0.0.1}:"):
                errors.append(f"local-observability host port is not loopback-defaulted: {port}")
    return errors


def build_inventory(
    dashboards: list[tuple[Path, dict[str, Any]]],
) -> dict[str, Any]:
    dashboard_items = dashboard_queries(dashboards)
    rules, recording_names = rule_queries()
    all_queries = dashboard_items + rules
    known_metrics = prometheus_inputs(recording_names)
    metric_dependencies: set[str] = set()
    label_dependencies: set[str] = set()
    loki_dependencies: set[str] = set()
    tempo_dependencies: set[str] = set()
    counts = {"prometheus": 0, "loki": 0, "tempo": 0}
    for item in all_queries:
        datasource = item["datasource"]
        if datasource in counts:
            counts[datasource] += 1
        if datasource == "prometheus":
            metric_dependencies.update(_prometheus_metric_dependencies(item["query"], known_metrics))
            label_dependencies.update(_prometheus_label_dependencies(item["query"]))
        elif datasource == "loki":
            loki_dependencies.update(_loki_dependencies(item["query"]))
        elif datasource == "tempo":
            tempo_dependencies.update(_tempo_dependencies(item["query"]))
    dependency_inventory = {
        "prometheus_metrics": sorted(metric_dependencies),
        "prometheus_labels": sorted(label_dependencies),
        "loki_fields": sorted(loki_dependencies),
        "tempo_attributes": sorted(tempo_dependencies),
    }
    return {
        "query_count": len(all_queries),
        "query_counts_by_datasource": counts,
        "query_sha256": _digest(all_queries),
        "dependency_sha256": _digest(dependency_inventory),
        "histogram_sha256": _digest(histogram_inventory()),
        "dependencies": dependency_inventory,
        "known_metrics": known_metrics,
    }


def compatibility_errors(
    dashboards: list[tuple[Path, dict[str, Any]]],
    *,
    require_packaged: bool,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    inventory = build_inventory(dashboards)
    uids = {str(dashboard.get("uid", "")) for _, dashboard in dashboards}
    if uids != EXPECTED_DASHBOARD_UIDS:
        missing_uids = sorted(EXPECTED_DASHBOARD_UIDS - uids)
        extra_uids = sorted(uids - EXPECTED_DASHBOARD_UIDS)
        errors.append(
            f"local-observability-v1 dashboard UIDs drifted: missing={missing_uids}, extra={extra_uids}",
        )
    datasource_config = _load_yaml(BUNDLE / "grafana/provisioning/datasources/datasources.yml")
    datasource_uids = {
        item.get("type"): item.get("uid")
        for item in datasource_config.get("datasources", [])
        if item.get("type") in EXPECTED_DATASOURCE_UIDS
    }
    if datasource_uids != EXPECTED_DATASOURCE_UIDS:
        errors.append(f"local-observability-v1 datasource UIDs drifted: {datasource_uids!r}")

    dependencies = inventory["dependencies"]
    unknown_metrics = set(dependencies["prometheus_metrics"]) - inventory["known_metrics"]
    if unknown_metrics:
        errors.append(f"Prometheus queries reference unknown current inputs: {sorted(unknown_metrics)}")
    unknown_labels = set(dependencies["prometheus_labels"]) - prometheus_label_inputs()
    if unknown_labels:
        errors.append(f"Prometheus queries reference unknown current labels: {sorted(unknown_labels)}")
    unknown_loki = set(dependencies["loki_fields"]) - loki_inputs()
    if unknown_loki:
        errors.append(f"Loki queries reference unknown current fields: {sorted(unknown_loki)}")
    unknown_tempo = set(dependencies["tempo_attributes"]) - tempo_inputs()
    if unknown_tempo:
        errors.append(f"Tempo queries reference unknown current attributes: {sorted(unknown_tempo)}")

    for field, expected in (("histogram_sha256", EXPECTED_HISTOGRAM_SHA256),):
        if expected != "PENDING" and inventory[field] != expected:
            errors.append(f"local-observability-v1 {field} drifted: got {inventory[field]}, want {expected}")

    errors.extend(_collector_errors())
    if require_packaged:
        errors.extend(_bundle_parity_errors())
    return inventory, errors
