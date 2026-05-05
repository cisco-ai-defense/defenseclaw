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


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
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

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
