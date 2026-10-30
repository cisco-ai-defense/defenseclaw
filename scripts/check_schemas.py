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
4. The management contract under ``packaging/mdm/contract/`` (the JSON
   documents MDM kits and management agents parse): every schema is a
   valid Draft 2020-12 schema with a DefenseClaw ``$id``, the guide names
   it, its examples validate, and the contract rules in
   ``MANAGEMENT_CONTRACT_RULES`` hold. The Go contract tests validate real
   command output against the same files.

Run via ``make check-schemas``.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"
OBSERVABILITY_V8_REFERENCE_GENERATOR = (
    ROOT / "scripts" / "generate_observability_v8_reference.py"
)
OBSERVABILITY_REDACTION_UNICODE_GENERATOR = (
    ROOT / "scripts" / "generate_unicode13_repertoire.py"
)
OBSERVABILITY_REDACTION_CATALOG_GENERATOR = (
    ROOT / "scripts" / "generate_observability_redaction_catalog.py"
)
TELEMETRY_REGISTRY_GENERATOR = ROOT / "scripts" / "generate_telemetry_registry.py"

# The envelope's event_type enum, which is narrower than gatewaylog's EventType
# constants and deliberately so. "ai_discovery" is absent: the v7 payload was
# retired, and the envelope's oneOf requires a payload object per event_type, so
# listing a type with no payload would name a shape nothing can satisfy. The
# EventAIDiscovery constant survives as an observability classification key --
# a different contract, pinned by internal/observability/classification_test.go.
EXPECTED_ENVELOPE_EVENT_TYPES = {
    "verdict", "judge", "lifecycle", "error", "diagnostic",
    "scan", "scan_finding", "activity", "egress",
    "llm_prompt", "llm_response", "tool_invocation",
    "hook_decision",
    "connector_inventory", "mcp_inventory", "agent_inventory",
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
    "devin",
    "copilot",
    "antigravity",
    "opencode",
    "amp",
    "kiro",
    # Sentinel emitted when one gateway process serves >1 connector at once.
    # Not a connector name: the true connector is carried per-event by the
    # `connector` metric label / `defenseclaw.connector.source` span attribute.
    "multi",
    "",
}

METRICS_GO = ROOT / "internal" / "telemetry" / "metrics.go"
HOOK_AUDIT_GO = ROOT / "internal" / "gateway" / "hook_audit_envelope.go"
OTEL_METRIC_INSTRUMENT_TYPES = {
    "Int64Counter": "counter",
    "Float64Histogram": "histogram",
    "Int64Histogram": "histogram",
    "Int64UpDownCounter": "updowncounter",
    "Int64Gauge": "gauge",
    "Float64Gauge": "gauge",
}

RUNTIME_SPAN_SCHEMA_NAMES = (
    "runtime-agent-span.schema.json",
    "runtime-approval-span.schema.json",
    "runtime-llm-span.schema.json",
    "runtime-tool-span.schema.json",
)

PUBLIC_SCHEMA_PATHS = (
    "activity-event.json",
    "audit-event.json",
    "gateway-event-envelope.json",
    "hook-audit-envelope.json",
    "network-egress-event.json",
    "otel/agent-lifecycle-event.schema.json",
    "otel/asset-lifecycle-event.schema.json",
    "otel/connector-telemetry-event.schema.json",
    "otel/galileo-export-profile.schema.json",
    "otel/metrics.schema.json",
    "otel/resource.schema.json",
    "otel/runtime-agent-span.schema.json",
    "otel/runtime-alert-event.schema.json",
    "otel/runtime-approval-span.schema.json",
    "otel/runtime-llm-span.schema.json",
    "otel/runtime-tool-span.schema.json",
    "otel/scan-finding-event.schema.json",
    "otel/scan-result-event.schema.json",
    "scan-event.json",
    "scan-finding-event.json",
    "scan-result.json",
)

MDM_CONTRACT_DIR = ROOT / "packaging" / "mdm" / "contract"
MANAGEMENT_CONTRACT_GUIDE = "management-agent.md"
MDM_CONTRACT_ID_PREFIX = "https://defenseclaw.cisco.com/schemas/enterprise/"
# Every JSON Schema in packaging/mdm/contract. A new schema is added here
# and to the guide; an unlisted file fails the check.
MDM_CONTRACT_SCHEMAS = (
    "anchors-install.schema.json",
    "bundle-anchors.schema.json",
    "bundle-receipt.schema.json",
    "bundle-refused.schema.json",
    "bundle-status.schema.json",
    "bundle-verify.schema.json",
    "lifecycle-result.schema.json",
    "secret-result.schema.json",
    "version.schema.json",
)

# A Windows lifecycle result refused with lifecycle_busy: the base of the
# exit-code rules (lifecycle-result.schema.json carries no examples).
_WINDOWS_BUSY_RESULT = {
    "schema_version": 2, "ok": False, "action": "ensure", "noop": False, "profile": "standalone",
    "platform": "windows", "product_version": "1.0.3", "installed_version": "1.0.3", "installed": True,
    "transaction_pending": False, "services": [],
    "readiness": {"gateway": False, "guardian": False, "enumerator": False, "sensor_helper": False},
    "inspection": {"local": "", "ai_defense": ""}, "machine_policy": {},
    "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
    "coverage_complete": False, "security_complete": False,
    "errors": [{"code": "lifecycle_busy", "message": "another lifecycle run holds the lock"}],
    "exit_code": 1618,
}


def _from_example(schema: str, index: int, change):
    def build(schemas: dict[str, dict]) -> object:
        document = copy.deepcopy(schemas[schema]["examples"][index])
        change(document)
        return document
    return build


# The openshell block every Windows status carries (OpenShellUnsupportedCapability).
_WINDOWS_OPENSHELL = {"enabled": False, "driver_available": "none", "reason_code": "platform_unsupported"}


def _windows_status(d):
    d.update(platform="windows", openshell=dict(_WINDOWS_OPENSHELL))


def _windows_result(change):
    def build(_: dict[str, dict]) -> object:
        document = copy.deepcopy(_WINDOWS_BUSY_RESULT)
        change(document)
        return document
    return build


def _set(**members):
    return lambda document: document.update(members)


# The status v2 blocks of a Linux status (connectors, openshell, identity),
# from 1.0.3: codes, connector ids, counts, versions and ages only.
_STATUS_V2_BLOCKS = {
    "connectors": {
        "codex": {"enabled": True, "detected": True, "versions": ["0.160.0"], "hooks_installed": "all",
                  "targets": {"total": 2, "protected": 2, "pending": 0, "failed": 0},
                  "effective_mode": "action", "effective_hook_fail_mode": "closed", "managed_hook": True},
        "amp": {"enabled": True, "detected": False, "hooks_installed": "none",
                "targets": {"total": 0, "protected": 0, "pending": 0, "failed": 0},
                "effective_mode": "observe", "effective_hook_fail_mode": "closed", "managed_hook": False},
    },
    "openshell": {"enabled": True, "install": "prerequisite", "installed": True, "version": "0.0.36", "driver": "vm",
                  "driver_available": "docker", "reason_code": "openshell_driver_fallback"},
    "identity": {"state": "ok", "sources": [{"source": "sssd", "directory": "active_directory", "last_ok_age_seconds": 42}],
                 "failing_accounts": 0, "stale_accounts": 0, "serving_offline_cache": False},
}


def _linux_status(change):
    def build(_: dict[str, dict]) -> object:
        document = copy.deepcopy(_WINDOWS_BUSY_RESULT)
        document.update(copy.deepcopy(_STATUS_V2_BLOCKS), action="status", ok=True, platform="linux", errors=[],
                        exit_code=0, coverage_complete=True, security_complete=True)
        change(document)
        return document
    return build


def _not_root_with_connectors(document: dict) -> None:
    for name in ("installed", "installed_version", "transaction_pending", "services", "readiness", "inspection",
                 "machine_policy", "enrollment", "openshell", "identity"):
        document.pop(name, None)
    document.update(ok=False, exit_code=1, errors=[{"code": "not_root", "message": "run this command as root"}])


def _elevation_required(platform: str):
    return _set(platform=platform, exit_code=5,
                errors=[{"code": "elevation_required", "message": "run this command elevated"}])


def _status_last_good_from_current(document: dict) -> None:
    document["last_good"] = dict(document["current"], delivery_id="a" * 128)


def _refused_status_with_go_zero_value(document: dict) -> None:
    document.update(ok=False, errors=[{"code": "not_managed", "message": "not a managed device"}],
                    sessions_restart_required={"state": "", "count": 0, "entries": None})


# Contract rules a schema edit must not loosen (or tighten): label, schema,
# document builder, whether the document must validate.
MANAGEMENT_CONTRACT_RULES = (
    ("version without management_contract (a build before the contract)", "version.schema.json",
     _from_example("version.schema.json", 0, lambda d: None), True),
    ("version with a features list", "version.schema.json",
     _from_example("version.schema.json", 1, _set(features=["receipt_id"])), False),
    ("version with an unknown management_contract", "version.schema.json",
     _from_example("version.schema.json", 1, _set(management_contract=2)), False),
    ("receipt id outside the Crockford alphabet", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(receipt_id="b-01JAB3K9QX4M2N8P6R5T0V1WYU")), False),
    ("failed receipt without error_code", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 1, lambda d: d.pop("error_code")), False),
    ("public receipt in a non-terminal state", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(state="applied")), False),
    ("receipt delivery_id of 128 bytes", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(delivery_id="a" * 128)), True),
    ("receipt delivery_id over 128 bytes", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(delivery_id="a" * 129)), False),
    ("receipt delivery_id with a space", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(delivery_id="agent 7")), False),
    ("receipt delivery_id with a control character", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(delivery_id="agent\x1b7")), False),
    ("empty receipt delivery_id", "bundle-receipt.schema.json",
     _from_example("bundle-receipt.schema.json", 0, _set(delivery_id="")), False),
    ("verify ok:true with errors", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(errors=[{"code": "x", "message": "m"}])), False),
    ("verify with every credential stored and no restart prediction", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, lambda d: d.pop("restart_prediction")), True),
    ("verify secret_refs_missing name with a dot", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(secret_refs_missing=["ai.key"])), False),
    ("verify secret_refs_missing entry that carries a value", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(secret_refs_missing=[{"name": "k", "value": "x"}])), False),
    ("verify secret_refs_mismatch entry that carries a value", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(secret_refs_mismatch=[{"name": "k", "value": "x"}])), False),
    ("verify secret_refs entry that carries value_sha256", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(secret_refs=[{"name": "k", "required": True, "present": True,
                                                                      "value_match": True, "value_sha256": "0" * 64}])), False),
    ("verify secret_refs entry without value_match", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(secret_refs=[{"name": "k", "required": True, "present": True}])), False),
    ("verify secret_refs_mismatch naming a stored credential", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, _set(secret_refs_mismatch=["ai-defense-api-key"])), True),
    ("verify restart prediction outside the enum", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, lambda d: d["restart_prediction"].update(gateway_restart="maybe")), False),
    ("verify restart prediction with a concrete change path", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0,
                   lambda d: d["restart_prediction"].update(settings=['enterprise.profiles["alice team"].mode'])), False),
    ("verify restart prediction required without a reason", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 0, lambda d: d["restart_prediction"].update(reason_codes=[])), False),
    ("verify refused secret_ref_missing listing every missing credential", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 2, lambda d: None), True),
    ("verify refusal with a restart prediction", "bundle-verify.schema.json",
     _from_example("bundle-verify.schema.json", 2,
                   _set(restart_prediction={"gateway_restart": "not_required", "reason_codes": []})), False),
    ("bundle status with an unknown member", "bundle-status.schema.json",
     _from_example("bundle-status.schema.json", 0, _set(user="alice")), False),
    ("bundle status last_good with a delivery_id of 128 bytes", "bundle-status.schema.json",
     _from_example("bundle-status.schema.json", 0, _status_last_good_from_current), True),
    ("bundle status current delivery_id with a space", "bundle-status.schema.json",
     _from_example("bundle-status.schema.json", 0, lambda d: d["current"].update(delivery_id="agent 7")), False),
    ("refused bundle status with the Go zero value for sessions", "bundle-status.schema.json",
     _from_example("bundle-status.schema.json", 0, _refused_status_with_go_zero_value), False),
    ("anchor key time not ending in Z", "bundle-anchors.schema.json",
     _from_example("bundle-anchors.schema.json", 0,
                   lambda d: d["keys"][0].update(not_after="2027-01-01T00:00:00+00:00")), False),
    ("anchors with an unknown member", "bundle-anchors.schema.json",
     _from_example("bundle-anchors.schema.json", 0, _set(extra=1)), False),
    ("anchors install replaced without previous_sha256", "anchors-install.schema.json",
     _from_example("anchors-install.schema.json", 0, lambda d: d.pop("previous_sha256")), False),
    ("anchors install refused with result replaced", "anchors-install.schema.json",
     _from_example("anchors-install.schema.json", 2, _set(result="replaced")), False),
    ("anchors install with a warning code the verb does not emit", "anchors-install.schema.json",
     _from_example("anchors-install.schema.json", 3,
                   lambda d: d["warnings"][0].update(code="anchors_any_group")), False),
    ("Windows secret result that carries a value", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 0, _set(value="secret")), False),
    ("Windows secret result with an identical-value no-op", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 0, _set(noop=True)), False),
    ("Windows secret failure without errors", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 1, _set(errors=[])), False),
    ("Windows secret failure with a non-MSI exit code", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 1, _set(exit_code=1)), False),
    ("secret status that carries a value", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 2, lambda d: d["secrets"][0].update(value="x")), False),
    ("Windows secret status failure (GAP-0029)", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3, lambda d: None), True),
    ("Windows secret status failure that claims a restart", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3, _set(gateway_restarted=True)), False),
    ("Windows secret status failure with an unreadable store", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3,
                   _set(exit_code=1603, errors=[{"code": "state_invalid", "message": "m"}])), True),
    ("Windows secret status failure with bad arguments (1639)", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3,
                   _set(exit_code=1639, errors=[{"code": "invalid_arguments", "message": "m"}])), True),
    ("Windows secret status failure state_invalid with the bad-arguments exit", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3,
                   _set(exit_code=1639, errors=[{"code": "state_invalid", "message": "m"}])), False),
    ("Windows secret status failure invalid_arguments with the state exit", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3,
                   _set(exit_code=1603, errors=[{"code": "invalid_arguments", "message": "m"}])), False),
    ("Windows secret status failure with a set or remove code", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 3,
                   _set(exit_code=1603, errors=[{"code": "restart_failed", "message": "m"}])), False),
    ("Linux or macOS secret set refused before the lifecycle (GAP-0031)", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 4, lambda d: None), True),
    ("Linux or macOS secret failure with the busy exit (a lifecycle result v2)", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 4, _set(exit_code=75)), False),
    ("Linux or macOS secret failure with a Windows-only code", "secret-result.schema.json",
     _from_example("secret-result.schema.json", 4, _set(errors=[{"code": "restart_failed", "message": "m"}])), False),
    ("Windows lifecycle result elevation_required with exit 5", "lifecycle-result.schema.json",
     _windows_result(_elevation_required("windows")), True),
    ("Linux lifecycle result with exit 5", "lifecycle-result.schema.json",
     _windows_result(_elevation_required("linux")), False),
    ("Linux status with the connectors, openshell and identity blocks", "lifecycle-result.schema.json",
     _linux_status(lambda d: None), True),
    ("status connector entry that names an account", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["connectors"]["codex"].update(user="alice")), False),
    ("status connector fail mode that is not open or closed", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["connectors"]["codex"].update(effective_hook_fail_mode="fail_open")), False),
    ("status connector version that is not a version token", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["connectors"]["codex"].update(versions=["1.0 beta"])), False),
    ("status connector with unknown hooks and target counts", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["connectors"]["codex"].update(hooks_installed="unknown")), False),
    ("status machine-policy-only connector without detected, versions or targets", "lifecycle-result.schema.json",
     _linux_status(lambda d: [d["connectors"]["codex"].pop(k) for k in ("detected", "versions", "targets")]), True),
    ("status per-user connector without target counts", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["connectors"]["amp"].pop("targets")), False),
    ("status connector without managed_hook or target counts", "lifecycle-result.schema.json",
     _linux_status(lambda d: [d["connectors"]["amp"].pop(k) for k in ("managed_hook", "targets")]), False),
    ("Windows status with connector target counts", "lifecycle-result.schema.json",
     _linux_status(_windows_status), True),
    ("Windows status managed_hook connector without target counts", "lifecycle-result.schema.json",
     _linux_status(lambda d: [_windows_status(d), d["connectors"]["codex"].pop("targets")]), False),
    ("Windows status connector with unknown hooks and no target counts", "lifecycle-result.schema.json",
     _linux_status(lambda d: [_windows_status(d), d["connectors"]["codex"].pop("targets"),
                              d["connectors"]["codex"].update(hooks_installed="unknown")]), True),
    ("status openshell driver_available outside vm, docker, none", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["openshell"].update(driver_available="kvm")), False),
    ("status identity source that lists accounts", "lifecycle-result.schema.json",
     _linux_status(lambda d: d["identity"]["sources"][0].update(accounts=["1001"])), False),
    ("status identity unknown without reason_code", "lifecycle-result.schema.json",
     _linux_status(lambda d: d.update(identity={"state": "unknown"})), False),
    ("status identity gateway_not_ready", "lifecycle-result.schema.json",
     _linux_status(lambda d: d.update(identity={"state": "unknown", "reason_code": "gateway_not_ready"})), True),
    ("not_root result with a connectors block", "lifecycle-result.schema.json",
     _linux_status(_not_root_with_connectors), False),
    ("Windows status openshell platform_unsupported", "lifecycle-result.schema.json",
     _linux_status(_windows_status), True),
    ("Windows status openshell enabled with a docker driver", "lifecycle-result.schema.json",
     _linux_status(lambda d: d.update(platform="windows", openshell={
         "enabled": True, "install": "prerequisite", "installed": True, "driver": "docker",
         "driver_available": "docker"})), False),
    ("Windows status openshell disabled with a Linux reason code", "lifecycle-result.schema.json",
     _linux_status(lambda d: d.update(platform="windows", openshell={
         "enabled": False, "driver_available": "none", "reason_code": "openshell_disabled"})), False),
    ("Linux status openshell disabled keeps its own reason code", "lifecycle-result.schema.json",
     _linux_status(lambda d: d.update(openshell={
         "enabled": False, "driver_available": "none", "reason_code": "openshell_disabled"})), True),
)


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
        print("check_schemas: jsonschema is required for meta-validation (make pycli)", file=sys.stderr)
        return False

    try:
        jsonschema.Draft202012Validator.check_schema(doc)
        return True
    except jsonschema.exceptions.SchemaError as exc:
        print(f"check_schemas: {path} fails Draft 2020-12 meta-validation: {exc.message}", file=sys.stderr)
        return False


def check_public_schema_inventory() -> bool:
    """Require every directly owned public schema without duplicating its content."""

    missing = [relative for relative in PUBLIC_SCHEMA_PATHS if not (SCHEMA_DIR / relative).is_file()]
    if missing:
        print(f"check_schemas: missing public schemas {missing}", file=sys.stderr)
        return False
    return True


def check_audit_event(doc: dict) -> bool:
    ok = True
    props = doc.get("properties", {})
    sv = props.get("schema_version")
    if not isinstance(sv, dict):
        print("check_schemas: audit-event.json: missing schema_version property", file=sys.stderr)
        return False
    if sv.get("type") != "integer":
        print(
            "check_schemas: audit-event.json: "
            f"schema_version.type={sv.get('type')!r}, want 'integer'",
            file=sys.stderr,
        )
        return False
    if (sv.get("minimum") or 0) < 7:
        print(
            "check_schemas: audit-event.json: "
            f"schema_version.minimum={sv.get('minimum')}, want >= 7",
            file=sys.stderr,
        )
        return False
    required = set(doc.get("required", []))
    if "schema_version" not in required:
        print("check_schemas: audit-event.json: 'schema_version' must be in required[]", file=sys.stderr)
        ok = False
    structured = props.get("structured")
    if not isinstance(structured, dict):
        print("check_schemas: audit-event.json: missing structured property", file=sys.stderr)
        ok = False
    elif "object" not in structured.get("type", []):
        print("check_schemas: audit-event.json: structured must allow object", file=sys.stderr)
        ok = False
    return ok


def discover_hook_audit_schema_const() -> str:
    text = HOOK_AUDIT_GO.read_text(encoding="utf-8")
    match = re.search(r'HookAuditEnvelopeSchema\s*=\s*"([^"]+)"', text)
    if not match:
        raise RuntimeError("HookAuditEnvelopeSchema constant not found")
    return match.group(1)


def check_hook_audit_envelope(doc: dict) -> bool:
    ok = True
    props = doc.get("properties", {})
    schema = props.get("schema", {})
    expected = discover_hook_audit_schema_const()
    if schema.get("const") != expected:
        print(
            "check_schemas: hook-audit-envelope.json: "
            f"schema.const={schema.get('const')!r}, want {expected!r}",
            file=sys.stderr,
        )
        ok = False
    required = set(doc.get("required", []))
    expected_required = {"schema", "timestamp", "connector", "event", "result", "would_block"}
    missing = expected_required - required
    if missing:
        print(
            "check_schemas: hook-audit-envelope.json: missing required fields "
            f"{sorted(missing)}",
            file=sys.stderr,
        )
        ok = False
    result = set((props.get("result") or {}).get("enum") or [])
    expected_results = {"ok", "panic", "rejected", "encode_error"}
    if result != expected_results:
        print(
            "check_schemas: hook-audit-envelope.json: result enum drift "
            f"got={sorted(result)} want={sorted(expected_results)}",
            file=sys.stderr,
        )
        ok = False
    return ok


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
        print(
            "check_schemas: gateway-event-envelope.json: event_type drift "
            f"missing={sorted(missing)} extra={sorted(extra)}",
            file=sys.stderr,
        )
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


def check_runtime_span_schema(doc: dict, name: str) -> bool:
    """Require machine-readable attribute contracts on every runtime span."""
    ok = True
    required = doc.get("x-required-attribute-keys")
    if not isinstance(required, list) or not required:
        print(
            f"check_schemas: otel/{name}: missing x-required-attribute-keys",
            file=sys.stderr,
        )
        return False
    definitions = (
        ((doc.get("$defs") or {}).get("attributeDefinitions") or {}).get("properties")
    )
    if not isinstance(definitions, dict) or not definitions:
        print(
            f"check_schemas: otel/{name}: missing attributeDefinitions.properties",
            file=sys.stderr,
        )
        return False
    missing = sorted(set(required) - set(definitions))
    if missing:
        print(
            f"check_schemas: otel/{name}: required attributes are undeclared: {missing}",
            file=sys.stderr,
        )
        ok = False
    return ok


def check_galileo_export_profile(doc: dict, runtime_docs: dict[str, dict]) -> bool:
    """Keep each Galileo filter branch aligned with its runtime span schema."""
    props = doc.get("properties") or {}
    signals = (props.get("signals") or {}).get("const")
    operations = (props.get("operations") or {}).get("const")
    expected = [
        {
            "name": operation,
            "required_attributes": runtime_docs[schema_name].get(
                "x-required-attribute-keys"
            ),
        }
        for operation, schema_name in (
            ("chat", "runtime-llm-span.schema.json"),
            ("invoke_agent", "runtime-agent-span.schema.json"),
            ("execute_tool", "runtime-tool-span.schema.json"),
        )
    ]
    ok = True
    if signals != ["traces"]:
        print(
            f"check_schemas: otel/galileo-export-profile: signals={signals!r}, want ['traces']",
            file=sys.stderr,
        )
        ok = False
    if operations != expected:
        print(
            "check_schemas: otel/galileo-export-profile operations drift from "
            f"runtime span schemas: got={operations!r} want={expected!r}",
            file=sys.stderr,
        )
        ok = False
    return ok


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
CLI_EMBED_SCHEMA_DIR = ROOT / "internal" / "cli" / "embed"
CLI_GO_DIR = ROOT / "internal" / "cli"


def check_cli_embed_mirrors() -> bool:
    """Verify the CLI-embedded schema copies match schemas/ byte-for-byte.

    Discover the actual ``//go:embed embed/*.json`` directives rather than
    maintaining a second allow-list. Every JSON file in the embed directory
    must be referenced by Go code, have a canonical copy under schemas/, and
    be byte-identical to that canonical copy. This both catches drift and
    prevents unexplained duplicate schema files from accumulating.
    """
    if not CLI_EMBED_SCHEMA_DIR.is_dir():
        print(
            "check_schemas: warning — internal/cli/embed not present; skipping CLI embed check",
            file=sys.stderr,
        )
        return True

    embedded = set()
    pattern = re.compile(r"//go:embed\s+embed/([^\s]+\.json)")
    for go_path in CLI_GO_DIR.glob("*.go"):
        embedded.update(pattern.findall(go_path.read_text(encoding="utf-8")))

    present = {path.name for path in CLI_EMBED_SCHEMA_DIR.glob("*.json")}
    orphaned = sorted(present - embedded)
    missing = sorted(embedded - present)
    ok = True
    if orphaned:
        print(
            "check_schemas: unreferenced CLI embed schema copies "
            f"{orphaned}; remove them or add an explicit //go:embed consumer",
            file=sys.stderr,
        )
        ok = False
    if missing:
        print(
            f"check_schemas: CLI go:embed schemas missing from disk {missing}",
            file=sys.stderr,
        )
        ok = False

    for name in sorted(embedded):
        embed_path = CLI_EMBED_SCHEMA_DIR / name
        canonical_path = SCHEMA_DIR / name
        if not embed_path.exists():
            continue
        if not canonical_path.exists():
            print(
                f"check_schemas: canonical schemas/{name} missing for CLI embed",
                file=sys.stderr,
            )
            ok = False
            continue
        if canonical_path.read_bytes() != embed_path.read_bytes():
            print(
                f"check_schemas: CLI embed drift between schemas/{name} and internal/cli/embed/{name}",
                file=sys.stderr,
            )
            ok = False
        else:
            print(f"check_schemas: CLI embed {name} OK")
    return ok


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


def check_observability_v8_reference() -> bool:
    """Reject generated reference, docs mirror, or staged wheel-data drift."""
    result = subprocess.run(
        [sys.executable, str(OBSERVABILITY_V8_REFERENCE_GENERATOR), "--check"],
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0


def check_observability_redaction_unicode() -> bool:
    """Reject Unicode repertoire manifest or generated-language drift."""
    result = subprocess.run(
        [sys.executable, str(OBSERVABILITY_REDACTION_UNICODE_GENERATOR), "--check"],
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0


def check_observability_redaction_catalog() -> bool:
    """Reject detector catalog manifest or generated-Go drift."""
    result = subprocess.run(
        [sys.executable, str(OBSERVABILITY_REDACTION_CATALOG_GENERATOR), "--check"],
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0


def check_telemetry_registry() -> bool:
    """Reject canonical telemetry input, provenance, or generated-output drift."""
    result = subprocess.run(
        [sys.executable, str(TELEMETRY_REGISTRY_GENERATOR), "--check"],
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0


def check_acp_inventory_instances() -> bool:
    """Validate ACP registry/evidence documents and the packaged mirror."""
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        print(
            "check_schemas: jsonschema is required for ACP inventory validation",
            file=sys.stderr,
        )
        return False

    pairs = (
        (SCHEMA_DIR / "acp" / "registry.schema.json", ROOT / "internal" / "inventory" / "acp_registry.json"),
        (
            SCHEMA_DIR / "acp" / "certifications.schema.json",
            ROOT / "internal" / "inventory" / "acp_certifications.json",
        ),
    )
    ok = True
    for schema_path, instance_path in pairs:
        schema = load_json(schema_path)
        instance = load_json(instance_path)
        errors = sorted(
            jsonschema.Draft202012Validator(schema).iter_errors(instance),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            ok = False
            for error in errors:
                location = ".".join(str(part) for part in error.absolute_path) or "<root>"
                print(
                    f"check_schemas: {instance_path.relative_to(ROOT)} {location}: {error.message}",
                    file=sys.stderr,
                )
        else:
            print(f"check_schemas: {instance_path.relative_to(ROOT)} OK")

    canonical = ROOT / "internal" / "inventory" / "acp_registry.json"
    packaged = ROOT / "cli" / "defenseclaw" / "inventory" / "acp_registry.json"
    canonical_doc = load_json(canonical)
    protocol = canonical_doc.get("protocol", {})
    release = protocol.get("release")
    expected_source = (
        "https://github.com/agentclientprotocol/agent-client-protocol/"
        f"releases/download/{release}/schema.json"
    )
    if protocol.get("source_url") != expected_source:
        print("check_schemas: ACP protocol source URL does not match its pinned release", file=sys.stderr)
        ok = False
    certifications = load_json(ROOT / "internal" / "inventory" / "acp_certifications.json")
    if any(item.get("protocol_release") != release for item in certifications.get("certifications", [])):
        print("check_schemas: ACP certification protocol release has drifted", file=sys.stderr)
        ok = False
    if canonical.read_bytes() != packaged.read_bytes():
        print("check_schemas: packaged ACP registry mirror has drifted", file=sys.stderr)
        ok = False
    else:
        print("check_schemas: packaged ACP registry mirror OK")
    return ok


def check_management_contract() -> bool:
    """Validate the management contract schemas, their examples and rules.

    The schemas are closed (``additionalProperties: false``) so the Go
    contract tests catch output drift; this check catches schema drift: a
    schema that no longer accepts its own examples, a loosened rule, or a
    schema the guide does not describe.
    """
    try:
        import jsonschema  # type: ignore[import-not-found]
        from referencing import Registry, Resource  # type: ignore[import-not-found]
        from referencing.exceptions import Unresolvable  # type: ignore[import-not-found]
    except ImportError:
        print(
            "check_schemas: jsonschema is required for the management contract",
            file=sys.stderr,
        )
        return False

    ok = True
    present = {path.name for path in MDM_CONTRACT_DIR.glob("*.schema.json")}
    missing = sorted(set(MDM_CONTRACT_SCHEMAS) - present)
    unlisted = sorted(present - set(MDM_CONTRACT_SCHEMAS))
    if missing or unlisted:
        print(
            f"check_schemas: packaging/mdm/contract schema drift missing={missing} unlisted={unlisted}",
            file=sys.stderr,
        )
        ok = False
    guide_path = MDM_CONTRACT_DIR / MANAGEMENT_CONTRACT_GUIDE
    guide = guide_path.read_text(encoding="utf-8") if guide_path.is_file() else ""
    if not guide:
        print(f"check_schemas: packaging/mdm/contract/{MANAGEMENT_CONTRACT_GUIDE} missing", file=sys.stderr)
        ok = False

    schemas: dict[str, dict] = {}
    ids: dict[str, str] = {}
    for name in sorted(present & set(MDM_CONTRACT_SCHEMAS)):
        path = MDM_CONTRACT_DIR / name
        doc = load_json(path)
        if not ensure_valid_meta(doc, path):
            ok = False
            continue
        schema_id = str(doc.get("$id") or "")
        if doc.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            print(f"check_schemas: packaging/mdm/contract/{name}: $schema is not Draft 2020-12", file=sys.stderr)
            ok = False
        if not schema_id.startswith(MDM_CONTRACT_ID_PREFIX):
            print(
                f"check_schemas: packaging/mdm/contract/{name}: $id {schema_id!r} "
                f"is not under {MDM_CONTRACT_ID_PREFIX}",
                file=sys.stderr,
            )
            ok = False
        if schema_id in ids:
            print(f"check_schemas: packaging/mdm/contract/{name}: $id repeats {ids[schema_id]}", file=sys.stderr)
            ok = False
        ids[schema_id] = name
        if guide and f"`{name}`" not in guide:
            print(f"check_schemas: {MANAGEMENT_CONTRACT_GUIDE} does not describe {name}", file=sys.stderr)
            ok = False
        schemas[name] = doc

    registry = Registry().with_resources(
        (doc["$id"], Resource.from_contents(doc)) for doc in schemas.values() if doc.get("$id")
    )
    format_checker = jsonschema.FormatChecker()

    def problems(name: str, instance: object) -> list[str]:
        validator = jsonschema.Draft202012Validator(schemas[name], registry=registry, format_checker=format_checker)
        return [
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in sorted(validator.iter_errors(instance), key=lambda error: list(error.absolute_path))
        ]

    examples = 0
    try:
        for name, doc in schemas.items():
            for index, example in enumerate(doc.get("examples", [])):
                examples += 1
                found = problems(name, example)
                if found:
                    print(f"check_schemas: packaging/mdm/contract/{name} examples[{index}] {found[0]}", file=sys.stderr)
                    ok = False
        for label, name, build, want_valid in MANAGEMENT_CONTRACT_RULES:
            if name not in schemas:
                ok = False
                continue
            try:
                document = build(schemas)
            except (KeyError, IndexError, TypeError, AttributeError) as exc:
                # A rule edits a fixed schema example: a removed example or
                # nested member is drift of that rule; the others still run.
                print(
                    f"check_schemas: {name} rule {label!r} cannot be built from the schema examples: {exc!r}",
                    file=sys.stderr,
                )
                ok = False
                continue
            found = problems(name, document)
            if want_valid and found:
                print(f"check_schemas: {name} must accept {label}: {found[0]}", file=sys.stderr)
                ok = False
            elif not want_valid and not found:
                print(f"check_schemas: {name} must reject {label}", file=sys.stderr)
                ok = False
    except (jsonschema.exceptions.SchemaError, Unresolvable) as exc:
        # An unresolvable $ref between contract schemas is drift too.
        print(f"check_schemas: packaging/mdm/contract: {exc}", file=sys.stderr)
        return False
    if ok:
        print(
            f"check_schemas: packaging/mdm/contract OK ({len(schemas)} schemas, {examples} examples, "
            f"{len(MANAGEMENT_CONTRACT_RULES)} rules)"
        )
    return ok


# Each forward schema and the contract schema whose documents it projects.
MDM_FORWARD_SCHEMAS = {
    "lifecycle-result-forward.schema.json": "lifecycle-result.schema.json",
    "bundle-verify-forward.schema.json": "bundle-verify.schema.json",
    "bundle-status-forward.schema.json": "bundle-status.schema.json",
    "bundle-receipt-forward.schema.json": "bundle-receipt.schema.json",
    "identity-refresh-forward.schema.json": None,
}
# Member names a forward schema must never list: they name accounts, hold
# free text or local detail.
MDM_FORWARD_BANNED_MEMBERS = {
    "user", "users", "user_id", "uid", "gid", "sid", "upn", "account", "accounts", "name", "names",
    "group", "groups", "principal", "actor", "created_by", "change_summary", "message", "messages",
    "subject", "path", "paths", "pid", "entries", "changes", "home", "tenant_id", "device_group",
    "signer_key_id", "key_id", "anchors", "log_path", "last_reload_error", "reason", "detail",
}
# Strings that must not survive a projection of the fixtures: account
# names, identifiers (SID, UPN, uid forms), group names and paths.
MDM_FORWARD_LEAKS = re.compile(
    r"S-1-5-|@dclab\.test|@example\.com|dcad-|\buid\b|DCLAB\\|/home/|/Users/|C:\\\\Users|C:\\Users|dc-r102-eng|wheel"
)


def _forward_schema_rule_errors(node, where: str) -> list[str]:
    """Structural rules of a forward schema: closed objects, constrained
    strings, no banned member names."""
    errors: list[str] = []
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node and node.get("additionalProperties") is not False:
            errors.append(f"{where}: an object with properties must be closed")
        if node.get("type") == "object" and isinstance(node.get("additionalProperties"), dict) and "propertyNames" not in node:
            errors.append(f"{where}: a map must constrain its keys with propertyNames")
        if node.get("type") == "string" and not any(key in node for key in ("pattern", "enum", "const")):
            errors.append(f"{where}: a string must have a pattern, enum or const")
        for member in node.get("properties", {}):
            if member in MDM_FORWARD_BANNED_MEMBERS:
                errors.append(f"{where}: lists the member {member!r}, which can name an account or hold free text")
        for key, child in node.items():
            if key in ("description", "title", "examples", "$id", "$schema", "pattern"):
                continue
            errors.extend(_forward_schema_rule_errors(child, f"{where}/{key}"))
    elif isinstance(node, list):
        for i, child in enumerate(node):
            errors.extend(_forward_schema_rule_errors(child, f"{where}[{i}]"))
    return errors


def check_forward_schemas() -> bool:
    """private #14 option A: the forward schemas are closed allowlists, the
    reference projection (forward/project.py) drops every member they do not
    list, and no account name or identifier survives a projection of the
    fixtures (full documents from Linux, macOS and Windows, with the 1.0.6
    additions) or of the contract schema examples."""
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        print("check_schemas: jsonschema is required for the forward schemas", file=sys.stderr)
        return False
    import importlib.util

    spec = importlib.util.spec_from_file_location("defenseclaw_forward_project", MDM_CONTRACT_DIR / "forward" / "project.py")
    if spec is None or spec.loader is None:
        print("check_schemas: forward/project.py is missing", file=sys.stderr)
        return False
    forward_project = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(forward_project)
    forward_dir = MDM_CONTRACT_DIR / "forward"
    ok = True
    present = {path.name for path in forward_dir.glob("*.schema.json")}
    if present != set(MDM_FORWARD_SCHEMAS):
        print(f"check_schemas: forward schema drift present={sorted(present)} listed={sorted(MDM_FORWARD_SCHEMAS)}", file=sys.stderr)
        ok = False
    guide = (MDM_CONTRACT_DIR / MANAGEMENT_CONTRACT_GUIDE).read_text(encoding="utf-8")
    fixtures = sorted((forward_dir / "fixtures").glob("*.json"))
    for name in sorted(present & set(MDM_FORWARD_SCHEMAS)):
        schema = load_json(forward_dir / name)
        if not ensure_valid_meta(schema, forward_dir / name):
            ok = False
            continue
        if not schema.get("$id", "").startswith(MDM_CONTRACT_ID_PREFIX + "management/forward/"):
            print(f"check_schemas: forward/{name}: $id is not under management/forward/", file=sys.stderr)
            ok = False
        if name not in guide:
            print(f"check_schemas: {MANAGEMENT_CONTRACT_GUIDE} does not name forward/{name}", file=sys.stderr)
            ok = False
        for error in _forward_schema_rule_errors(schema, f"forward/{name}"):
            print(f"check_schemas: {error}", file=sys.stderr)
            ok = False
        validator = jsonschema.Draft202012Validator(schema)
        documents = []
        prefix = name.removesuffix("-forward.schema.json") + "."
        documents += [(f"fixture {path.name}", load_json(path)) for path in fixtures if path.name.startswith(prefix)]
        source = MDM_FORWARD_SCHEMAS[name]
        if source:
            for i, example in enumerate(load_json(MDM_CONTRACT_DIR / source).get("examples", [])):
                documents.append((f"{source} example {i}", example))
        if not documents:
            print(f"check_schemas: forward/{name}: no fixture projects through it", file=sys.stderr)
            ok = False
        for label, document in documents:
            projected = forward_project.project(document, schema)
            problems = [e.message for e in validator.iter_errors(projected)]
            text = json.dumps(projected)
            leak = MDM_FORWARD_LEAKS.search(text)
            if problems or leak or ("ok" in document and "ok" not in projected):
                print(f"check_schemas: forward/{name} {label}: projection problems={problems[:3]} leak={leak.group(0) if leak else None}", file=sys.stderr)
                ok = False
            if forward_project.project(projected, schema) != projected:
                print(f"check_schemas: forward/{name} {label}: projection is not idempotent", file=sys.stderr)
                ok = False
        # A member a later release adds is dropped, never an error.
        extra = forward_project.project({"added_in_a_later_release": {"user": "x"}}, schema)
        if extra != {}:
            print(f"check_schemas: forward/{name}: an unknown member was not dropped: {extra}", file=sys.stderr)
            ok = False
    if ok:
        print(f"check_schemas: management forward schemas OK ({len(present)} schemas, {len(fixtures)} fixtures)")
    return ok


def main() -> int:
    if not SCHEMA_DIR.is_dir():
        print(f"check_schemas: schema dir not found: {SCHEMA_DIR}", file=sys.stderr)
        return 2

    ok = True
    if not check_public_schema_inventory():
        ok = False
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

    hook_path = SCHEMA_DIR / "hook-audit-envelope.json"
    if hook_path.exists():
        if not check_hook_audit_envelope(load_json(hook_path)):
            ok = False
    else:
        print("check_schemas: hook-audit-envelope.json missing", file=sys.stderr)
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

    for name in RUNTIME_SPAN_SCHEMA_NAMES:
        span_path = SCHEMA_DIR / "otel" / name
        if not span_path.exists():
            print(f"check_schemas: schemas/otel/{name} missing", file=sys.stderr)
            ok = False
            continue
        if not check_runtime_span_schema(load_json(span_path), name):
            ok = False

    galileo_path = SCHEMA_DIR / "otel" / "galileo-export-profile.schema.json"
    runtime_paths = {
        name: SCHEMA_DIR / "otel" / name
        for name in (
            "runtime-llm-span.schema.json",
            "runtime-agent-span.schema.json",
            "runtime-tool-span.schema.json",
        )
    }
    if galileo_path.exists() and all(path.exists() for path in runtime_paths.values()):
        runtime_docs = {name: load_json(path) for name, path in runtime_paths.items()}
        if not check_galileo_export_profile(load_json(galileo_path), runtime_docs):
            ok = False
    else:
        print("check_schemas: Galileo export profile or runtime span schema missing", file=sys.stderr)
        ok = False

    if not check_management_contract():
        ok = False
    if not check_forward_schemas():
        ok = False

    # Cross-artifact drift checks are meaningful only for the repository's
    # canonical schema tree. Unit tests deliberately point SCHEMA_DIR at a
    # tampered copy to exercise schema validation; rerunning the unrelated
    # reference/Unicode/registry generators in those subprocesses used to add
    # more than 30 seconds per case and checked the real tree, not the supplied
    # one. The canonical `make check-schemas` path still executes every gate.
    canonical_schema_dir = (ROOT / "schemas").resolve()
    if SCHEMA_DIR.resolve() == canonical_schema_dir:
        if not check_schema_mirrors():
            ok = False

        if not check_cli_embed_mirrors():
            ok = False

        if not check_observability_v8_reference():
            ok = False

        if not check_observability_redaction_unicode():
            ok = False

        if not check_observability_redaction_catalog():
            ok = False

        if not check_telemetry_registry():
            ok = False

        if not check_acp_inventory_instances():
            ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
