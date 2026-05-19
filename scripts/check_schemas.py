#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Validate every JSON schema in ``schemas/`` is:

1. Syntactically valid JSON.
2. A valid Draft 2020-12 schema per the official meta-schema.
3. Consistent with the v7 envelope expectations — specifically:
   - ``audit-event.json`` declares ``schema_version`` as an integer
     with minimum >= 7.
   - ``gateway-event-envelope.json`` declares the full provenance
     quartet and the v7 event_type enum (verdict / judge / lifecycle
     / error / diagnostic / scan / scan_finding / activity / egress
     / LLM/tool telemetry events / AI discovery events).

Run via ``make check-schemas``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"

EXPECTED_ENVELOPE_EVENT_TYPES = {
    "verdict", "judge", "lifecycle", "error", "diagnostic",
    "scan", "scan_finding", "activity", "egress",
    "llm_prompt", "llm_response", "tool_invocation",
    "ai_discovery",
}

EXPECTED_PROVENANCE_FIELDS = {
    "schema_version", "content_hash", "generation", "binary_version",
}

# Connector names emitted by Connector.Name() in internal/gateway/connector.
# The empty string is a legal "no connector picked yet" placeholder
# emitted by the gateway before `defenseclaw setup connector` has run.
# These names are the contract every downstream consumer
# (Splunk APM dashboards, OTLP collector validation, audit drill-down)
# pivots on; drift here is a multi-week diagnostic rabbit-hole.
EXPECTED_CLAW_MODE_ENUM = {
    "openclaw",
    "zeptoclaw",
    "claudecode",
    "codex",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "",
}

METRICS_GO = ROOT / "internal" / "telemetry" / "metrics.go"
OTEL_METRIC_INSTRUMENT_TYPES = {
    "Int64Counter": "counter",
    "Float64Histogram": "histogram",
    "Int64Histogram": "histogram",
    "Int64UpDownCounter": "updowncounter",
    "Int64Gauge": "gauge",
    "Float64Gauge": "gauge",
}


def load_json(path: Path) -> dict:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
        out = {}
        seen = set()
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON object key {key!r}")
            seen.add(key)
            out[key] = value
        return out

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except json.JSONDecodeError as exc:
        print(f"check_schemas: {path} is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:
        print(f"check_schemas: {path} is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(1)


def ensure_valid_meta(doc: dict, path: Path) -> bool:
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        # Running without jsonschema installed — fall back to a
        # lightweight sanity check (do not fail CI, but warn).
        print(
            "check_schemas: warning — jsonschema not installed; "
            "skipping strict meta-validation",
            file=sys.stderr,
        )
        return "$schema" in doc

    try:
        jsonschema.Draft202012Validator.check_schema(doc)
        return True
    except jsonschema.exceptions.SchemaError as exc:
        print(f"check_schemas: {path} fails Draft 2020-12 meta-validation: {exc.message}", file=sys.stderr)
        return False


def check_audit_event(doc: dict) -> bool:
    props = doc.get("properties", {})
    sv = props.get("schema_version")
    if not isinstance(sv, dict):
        print("check_schemas: audit-event.json: missing schema_version property", file=sys.stderr)
        return False
    if sv.get("type") != "integer":
        print(f"check_schemas: audit-event.json: schema_version.type={sv.get('type')!r}, want 'integer'", file=sys.stderr)
        return False
    if (sv.get("minimum") or 0) < 7:
        print(f"check_schemas: audit-event.json: schema_version.minimum={sv.get('minimum')}, want >= 7", file=sys.stderr)
        return False
    required = set(doc.get("required", []))
    if "schema_version" not in required:
        print("check_schemas: audit-event.json: 'schema_version' must be in required[]", file=sys.stderr)
        return False
    return True


def check_envelope(doc: dict) -> bool:
    ok = True
    props = doc.get("properties", {})

    for field in EXPECTED_PROVENANCE_FIELDS:
        if field not in props:
            print(f"check_schemas: gateway-event-envelope.json: missing '{field}'", file=sys.stderr)
            ok = False

    etype = props.get("event_type", {})
    enum = set(etype.get("enum") or [])
    missing = EXPECTED_ENVELOPE_EVENT_TYPES - enum
    extra = enum - EXPECTED_ENVELOPE_EVENT_TYPES
    if missing or extra:
        print(f"check_schemas: gateway-event-envelope.json: event_type drift missing={sorted(missing)} extra={sorted(extra)}", file=sys.stderr)
        ok = False
    return ok


def check_resource(doc: dict) -> bool:
    """Pin the claw.mode enum on schemas/otel/resource.schema.json.

    Splunk APM dashboards, OTLP collector validation, and audit
    drill-down all key off this attribute. If a developer adds a new
    connector and forgets to update the schema, downstream consumers
    silently start dropping records — and the empty-string fallback
    masks it for fresh installs that haven't picked a connector yet.
    Pin the enum here so the drift is caught at lint time, not at
    incident time.
    """
    props = doc.get("properties", {})
    mode = props.get("defenseclaw.claw.mode", {})
    enum = set(mode.get("enum") or [])
    missing = EXPECTED_CLAW_MODE_ENUM - enum
    extra = enum - EXPECTED_CLAW_MODE_ENUM
    if missing or extra:
        print(
            "check_schemas: otel/resource.schema.json: defenseclaw.claw.mode "
            f"enum drift missing={sorted(missing)} extra={sorted(extra)}",
            file=sys.stderr,
        )
        return False
    return True


def discover_otel_metric_instruments() -> dict[str, dict[str, str]]:
    """Read internal/telemetry/metrics.go and return declared instruments.

    The public metrics schema says it is the downstream contract for emitted
    DefenseClaw OTel metrics. A JSON schema can be perfectly valid but still
    stale if a new meter is added in Go and forgotten in the schema catalog.
    Keep this lightweight parser intentionally narrow: it only follows the
    canonical metricsSet constructor pattern used in metrics.go.
    """
    text = METRICS_GO.read_text(encoding="utf-8")
    lines = text.splitlines()
    out: dict[str, dict[str, str]] = {}
    pattern = re.compile(
        r"ms\.\w+,\s+err\s+=\s+m\."
        r"(Int64Counter|Float64Histogram|Int64Histogram|"
        r"Int64UpDownCounter|Int64Gauge|Float64Gauge)"
        r"\(\"([^\"]+)\""
    )
    for idx, line in enumerate(lines):
        match = pattern.search(line)
        if not match:
            continue
        instrument_type, name = match.groups()
        block = "\n".join(lines[idx : idx + 24])
        unit_match = re.search(r"metric\.WithUnit\(\"([^\"]*)\"\)", block)
        desc_match = re.search(r"metric\.WithDescription\(\"([^\"]*)\"\)", block)
        out[name] = {
            "type": OTEL_METRIC_INSTRUMENT_TYPES[instrument_type],
            "unit": unit_match.group(1) if unit_match else "",
            "description": desc_match.group(1) if desc_match else "",
        }
    return out


def check_metrics_catalog(doc: dict) -> bool:
    """Verify schemas/otel/metrics.schema.json names every emitted metric."""
    ok = True
    catalog = doc.get("x-emitted-metrics")
    if not isinstance(catalog, list):
        print(
            "check_schemas: otel/metrics.schema.json: missing x-emitted-metrics catalog",
            file=sys.stderr,
        )
        return False

    schema_metrics: dict[str, dict] = {}
    duplicates: set[str] = set()
    for item in catalog:
        if not isinstance(item, dict):
            print(
                f"check_schemas: otel/metrics.schema.json: non-object catalog item {item!r}",
                file=sys.stderr,
            )
            ok = False
            continue
        name = str(item.get("name") or "")
        if not name:
            print(
                "check_schemas: otel/metrics.schema.json: catalog item missing name",
                file=sys.stderr,
            )
            ok = False
            continue
        if name in schema_metrics:
            duplicates.add(name)
        schema_metrics[name] = item

    if duplicates:
        print(
            "check_schemas: otel/metrics.schema.json: duplicate metric names "
            f"{sorted(duplicates)}",
            file=sys.stderr,
        )
        ok = False

    emitted = discover_otel_metric_instruments()
    missing = sorted(set(emitted) - set(schema_metrics))
    extra = sorted(set(schema_metrics) - set(emitted))
    if missing or extra:
        print(
            "check_schemas: otel/metrics.schema.json: emitted metric catalog drift "
            f"missing={missing} extra={extra}",
            file=sys.stderr,
        )
        ok = False

    for name in sorted(set(emitted) & set(schema_metrics)):
        expected = emitted[name]
        got = schema_metrics[name]
        for field in ("type", "unit"):
            if got.get(field) != expected[field]:
                print(
                    "check_schemas: otel/metrics.schema.json: "
                    f"{name}.{field}={got.get(field)!r}, want {expected[field]!r}",
                    file=sys.stderr,
                )
                ok = False
        if not str(got.get("description") or "").strip():
            print(
                "check_schemas: otel/metrics.schema.json: "
                f"{name} missing description",
                file=sys.stderr,
            )
            ok = False

    if ok:
        print(f"check_schemas: otel/metrics.schema.json catalog OK ({len(emitted)} metrics)")
    return ok


GATEWAYLOG_SCHEMA_DIR = ROOT / "internal" / "gatewaylog" / "schemas"


def check_schema_mirrors() -> bool:
    """Verify every schema present in both schemas/ and the
    internal/gatewaylog/schemas/ mirror is byte-for-byte identical.

    The Go code at gateway boot time ALWAYS reads the mirror under
    internal/gatewaylog/schemas/ (via go:embed). The top-level
    schemas/ directory is the source of truth for downstream
    consumers (assert scripts, docs site, examples). Drift between
    the two means the gateway is enforcing one contract while the
    public-facing tooling believes another — which has caused real
    incidents in the past. CI must catch the drift, not production.
    """
    if not GATEWAYLOG_SCHEMA_DIR.is_dir():
        # Mirror not present yet (rare in CI, common in fresh checkouts
        # after a clean clone). Treat as a soft warning rather than a
        # hard failure so this script keeps working in those flows.
        print(
            "check_schemas: warning — internal/gatewaylog/schemas not present; skipping mirror check",
            file=sys.stderr,
        )
        return True

    ok = True
    for mirror_path in sorted(GATEWAYLOG_SCHEMA_DIR.rglob("*.json")):
        rel = mirror_path.relative_to(GATEWAYLOG_SCHEMA_DIR)
        canonical_path = SCHEMA_DIR / rel
        if not canonical_path.exists():
            # Mirror has files the canonical dir doesn't — fine, it's
            # allowed to ship internal-only schemas.
            continue
        canonical_bytes = canonical_path.read_bytes()
        mirror_bytes = mirror_path.read_bytes()
        if canonical_bytes != mirror_bytes:
            print(
                f"check_schemas: mirror drift between schemas/{rel} and internal/gatewaylog/schemas/{rel}",
                file=sys.stderr,
            )
            ok = False
        else:
            print(f"check_schemas: mirror {rel} OK")
    return ok


def main() -> int:
    if not SCHEMA_DIR.is_dir():
        print(f"check_schemas: schema dir not found: {SCHEMA_DIR}", file=sys.stderr)
        return 2

    ok = True
    # Validate top-level schemas/*.json plus subtree schemas (e.g.
    # schemas/otel/*.json). The recursive walk catches additions like
    # the OTel resource/metrics/span schemas that ship in nested
    # directories and would otherwise drift unchecked.
    for path in sorted(SCHEMA_DIR.rglob("*.json")):
        doc = load_json(path)
        if not ensure_valid_meta(doc, path):
            ok = False
            continue
        rel = path.relative_to(SCHEMA_DIR)
        print(f"check_schemas: {rel} OK")

    audit_path = SCHEMA_DIR / "audit-event.json"
    if audit_path.exists():
        if not check_audit_event(load_json(audit_path)):
            ok = False

    envelope_path = SCHEMA_DIR / "gateway-event-envelope.json"
    if envelope_path.exists():
        if not check_envelope(load_json(envelope_path)):
            ok = False
    else:
        print("check_schemas: gateway-event-envelope.json missing", file=sys.stderr)
        ok = False

    resource_path = SCHEMA_DIR / "otel" / "resource.schema.json"
    if resource_path.exists():
        if not check_resource(load_json(resource_path)):
            ok = False
    else:
        print("check_schemas: schemas/otel/resource.schema.json missing", file=sys.stderr)
        ok = False

    metrics_path = SCHEMA_DIR / "otel" / "metrics.schema.json"
    if metrics_path.exists():
        if not check_metrics_catalog(load_json(metrics_path)):
            ok = False
    else:
        print("check_schemas: schemas/otel/metrics.schema.json missing", file=sys.stderr)
        ok = False

    if not check_schema_mirrors():
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
