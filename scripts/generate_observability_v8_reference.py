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

"""Generate the schema-owned DefenseClaw v8 observability reference.

The JSON Schema owns the accepted field names, destination variants, defaults,
and constraints. This generator owns presentation only: a comprehensive source
example and a Markdown rendering of the schema field catalog. CI validates the
example against the schema, proves that it exercises every source-field path
and destination kind, and rejects drift in the documentation. Python-wheel
copies are disposable build staging created by ``make _bundle-data``.

Run ``python scripts/generate_observability_v8_reference.py --write`` after a
reviewed schema change. Run with ``--check`` (the default) in CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas/config/v8/defenseclaw-config.schema.json"
REFERENCE_DIR = ROOT / "schemas/config/v8/reference"
CANONICAL_YAML = REFERENCE_DIR / "observability.yaml"
CANONICAL_MARKDOWN = REFERENCE_DIR / "observability.md"
PYTHON_DATA_DIR = ROOT / "cli/defenseclaw/_data/config/v8"

BUCKETS = (
    "compliance.activity",
    "security.finding",
    "guardrail.evaluation",
    "enforcement.action",
    "model.io",
    "tool.activity",
    "asset.scan",
    "asset.lifecycle",
    "network.egress",
    "agent.lifecycle",
    "ai.discovery",
    "telemetry.ingest",
    "platform.health",
    "diagnostic",
)

YAML_HEADER = """\
# DEFENSECLAW CONFIGURATION v8 — OBSERVABILITY REFERENCE
#
# GENERATED FILE. DO NOT EDIT.
# Canonical schema: schemas/config/v8/defenseclaw-config.schema.json
# Generator: scripts/generate_observability_v8_reference.py
#
# This is the complete source-config surface, not a recommended production
# file. Start from a preset or minimal config and copy only deliberate overrides.
#
# ┌──────────────────────────────────────────────────────────────────────────┐
# │ DATA FLOW                                                                │
# │                                                                          │
# │ producer -> bucket/signal -> collection gate                             │
# │                                  │                                       │
# │                                  ├-> automatic unredacted SQLite logs     │
# │                                  └-> each optional destination            │
# │                                        omitted policy = all capabilities │
# │                                        concise send, or advanced routes  │
# │                                          ├-> drop                        │
# │                                          └-> redact -> sign -> deliver   │
# └──────────────────────────────────────────────────────────────────────────┘
#
# Defaults are intentionally full-fidelity: all buckets collect logs, traces,
# and metrics; enabled destinations export every signal they support; and the
# default redaction profile is none. Explicit send/routes replace the generated
# destination default. Collection is evaluated before routing and sampling.
#
# Built-in redaction: none, sensitive, content, strict, legacy-v7.
# Route selectors: different fields AND; values inside one field OR.
# Route evaluation: first match wins independently per destination and signal.
# Secrets are references (for example token_env or {env: NAME}), never literals.
#
# Useful commands:
#   defenseclaw config validate
#   defenseclaw config show --effective --section observability
#   defenseclaw config reference observability
#   defenseclaw observability plan

"""

YAML_ANNOTATIONS = {
    "config_version: 8": ("# Selects the strict v8 configuration contract; unknown keys are errors.",),
    "  bucket_catalog_version: 1": (
        "  # Optional in source. Version 8 currently resolves catalog 1; pin it only",
        "  # when deliberately binding the file to this reviewed bucket taxonomy.",
    ),
    "  resource:": (
        "  # OpenTelemetry resource attributes shared by emitted signals. Keep values",
        "  # bounded and non-secret; credentials belong in environment references.",
    ),
    "  trace_policy:": (
        "  # Process-wide trace sampling, semantic-convention profile, compatibility",
        "  # aliases, and hard payload limits. Bucket collection runs before sampling.",
    ),
    "    sampler: parentbased_traceidratio": (
        "    # Samplers: always_on/off, traceidratio, or their parentbased variants.",
    ),
    "    sampler_arg: '0.10'": ("    # Ratio in [0,1], required only by ratio samplers.",),
    "    semantic_profile: defenseclaw-genai-rich-v1": (
        "    # Immutable registry profile combining OTel GenAI portability with",
        "    # DefenseClaw lifecycle, guardrail, evidence, and security attributes.",
    ),
    "    compatibility_aliases: true": (
        "    # Temporarily emit documented legacy aliases from the same redacted value.",
    ),
    "    limits:": ("    # Hard per-span/event/message limits; truncation stays deterministic.",),
    "  metric_policy:": ("  # Process-wide metric reader interval and aggregation temporality.",),
    "    export_interval_seconds: 60": ("    # Positive reader interval; destination export does not override it.",),
    "    temporality: delta": ("    # delta or cumulative; choose for backend aggregation expectations.",),
    "  defaults:": (
        "  # Optional global bucket override. Omit it to inherit versioned catalog",
        "  # defaults (all signals collected, no redaction in catalog v1).",
    ),
    "    collect:": ("    # Signal construction gate. false avoids normal producer/runtime cost.",),
    "    redaction_profile: none": ("    # Source default is intentionally unredacted; buckets may override it.",),
    "  buckets:": (
        "  # All 14 catalog buckets are expanded here for discoverability. Normal source",
        "  # files should list only deliberate collection or redaction overrides.",
    ),
    "  redaction_profiles:": (
        "  # Custom profiles extend exactly one built-in redacting profile.",
        "  # Detector groups: pii, credentials, secrets.",
        "  # Field modes: preserve, detect, whole, hash, remove.",
    ),
    "      extends: sensitive": ("      # Inheritance is single-level: sensitive, content, or strict.",),
    "      detectors:": ("      # Detector groups run only where a field class uses detect.",),
    "      field_classes:": ("      # Per-class handling redacts only sensitive substrings when set to detect.",),
    "  connectors:": (
        "  # Notification-only connector compatibility. This is not telemetry routing;",
        "  # the removed v7 connectors.*.audit_sinks key is intentionally unavailable.",
    ),
    "      webhooks:": (
        "      # Present empty list suppresses inherited global webhooks; entries retain",
        "      # the existing WebhookConfig notification contract.",
    ),
    "        secret_env: DEFENSECLAW_WEBHOOK_SECRET": (
        "        # Credential lookup by environment-variable name, never inline value.",
    ),
    "  local:": (
        "  # SQLite is mandatory, generated when omitted, and cannot be disabled or",
        "  # filtered. retention_days: 0 retains forever and raises a capacity warning.",
    ),
    "    path: ~/.defenseclaw/audit.db": (
        "    # Main immutable audit/evidence store; defaults below the data directory.",
    ),
    "    judge_bodies_path: ~/.defenseclaw/judge_bodies.db": (
        "    # Separate forensic judge-body store; must not alias any configured file.",
    ),
    "    retention_days: 90": ("    # Applies to local event/evidence/judge history; zero means retain forever.",),
    "  destinations:": (
        "  # Optional exports. Presence defaults enabled:true. Every example is disabled",
        "  # so this exhaustive reference is safe to inspect without exporting data.",
    ),
    "  - name: local-jsonl": ("  # JSONL: logs only. Ordered routes demonstrate first-match drop/send behavior.",),
    "    rotation:": (
        "    # Size/age rotation with optional gzip compression; zero backups/age disables",
        "    # that pruning dimension without disabling the destination.",
    ),
    "  - name: operator-console": ("  # Console: logs only. Concise send replaces the generated all-logs policy.",),
    "  - name: prometheus": ("  # Prometheus: metrics only, exposed through the configured pull endpoint.",),
    "  - name: splunk-production": (
        "  # Splunk HEC: logs only. Private/CGNAT collectors require reviewed opt-in;",
        "  # metadata, link-local, and other prohibited ranges remain blocked.",
    ),
    "    token_env: SPLUNK_HEC_TOKEN": ("    # Required HEC token environment-variable name.",),
    "  - name: http-archive": ("  # Generic HTTP JSONL: logs only. Header/auth values use environment references.",),
    "    bearer_env: ARCHIVE_BEARER_TOKEN": ("    # Optional bearer token environment-variable name.",),
    "  - name: general-otel": ("  # General OTLP: logs, traces, and metrics with per-signal endpoint overrides.",),
    "    protocol: http/protobuf": (
        "    # grpc, grpc/protobuf, http, or http/protobuf; HTTP means OTLP protobuf,",
        "    # never arbitrary JSON.",
    ),
    "    signal_overrides:": ("    # Empty endpoint inherits the destination endpoint; path remains per signal.",),
    "  - name: galileo": (
        "  # Galileo is the OTLP adapter's trace-only rich-v2 preset; its batch-delay",
        "  # override is 1000 ms while the general OTLP default remains 5000 ms.",
    ),
    "    enabled: false": (
        "    # Presence normally defaults true. Disabled examples retain policy without",
        "    # initializing transports or resolving their secrets.",
    ),
    "    headers:": ("    # Header values may be bounded literal metadata or {env: NAME} secrets.",),
    "    tls:": ("    # TLS verification defaults on. A CA path is read-only and may be shared.",),
    "    timeout_ms: 10000": ("    # Positive per-export timeout in milliseconds.",),
    "    network_safety:": (
        "    # Private and CGNAT destinations require separate explicit opt-ins. DNS is",
        "    # rechecked at connect time; metadata/link-local targets are always blocked.",
    ),
    "    batch:": (
        "    # Queue count/bytes are always bounded. Push destinations additionally",
        "    # bound encoded request count/bytes and delay; batch count <= queue count.",
    ),
    "    routes:": ("    # Advanced ordered rules. First match wins for each destination and signal.",),
    "    send:": ("    # Concise policy: exact signals + buckets + optional redaction profile.",),
    "      selector:": ("      # Selector fields AND together; values within one field OR together.",),
    "      action: drop": ("      # drop terminates routing and cannot specify a redaction profile.",),
    "      action: send": ("      # send applies the route profile, or the bucket profile when omitted.",),
}


def _collect_all() -> dict[str, bool]:
    return {"logs": True, "traces": True, "metrics": True}


def _reference_document() -> dict[str, Any]:
    """Return one exhaustive, valid source document.

    Values are illustrative and disabled destinations avoid accidental export
    if an operator runs the reference unchanged. Defaults and accepted values
    remain schema-owned; coverage checks below prevent this presentation data
    from silently omitting a newly added field.
    """

    bucket_policies = {bucket: {"collect": _collect_all(), "redaction_profile": "none"} for bucket in BUCKETS}
    return {
        "config_version": 8,
        "observability": {
            "bucket_catalog_version": 1,
            "resource": {
                "attributes": {
                    "service.name": "defenseclaw-gateway",
                    "deployment.environment": "production",
                }
            },
            "trace_policy": {
                "sampler": "parentbased_traceidratio",
                "sampler_arg": "0.10",
                "semantic_profile": "defenseclaw-genai-rich-v1",
                "compatibility_aliases": True,
                "limits": {
                    "max_attributes_per_span": 128,
                    "max_events_per_span": 64,
                    "max_links_per_span": 32,
                    "max_attributes_per_event": 32,
                    "max_attribute_value_bytes": 16384,
                    "max_projected_span_bytes": 262144,
                    "max_stacktrace_bytes": 32768,
                    "max_message_items": 128,
                },
            },
            "metric_policy": {
                "export_interval_seconds": 60,
                "temporality": "delta",
            },
            "defaults": {
                "collect": _collect_all(),
                "redaction_profile": "none",
            },
            "buckets": bucket_policies,
            "redaction_profiles": {
                "soc": {
                    "extends": "sensitive",
                    "detectors": ["pii", "credentials", "secrets"],
                    "field_classes": {
                        "metadata": "preserve",
                        "identifier": "preserve",
                        "content": "detect",
                        "reason": "detect",
                        "evidence": "detect",
                        "error": "detect",
                        "path": "hash",
                        "credential": "remove",
                    },
                }
            },
            "connectors": {
                "codex": {
                    "webhooks": [
                        {
                            "name": "soc-generic",
                            "url": "https://hooks.example.test/defenseclaw",
                            "type": "generic",
                            "secret_env": "DEFENSECLAW_WEBHOOK_SECRET",
                            "room_id": "soc",
                            "min_severity": "HIGH",
                            "events": ["block", "scan", "guardrail", "drift", "health"],
                            "timeout_seconds": 10,
                            "cooldown_seconds": 60,
                            "enabled": False,
                        }
                    ]
                }
            },
            "local": {
                "path": "~/.defenseclaw/audit.db",
                "judge_bodies_path": "~/.defenseclaw/judge_bodies.db",
                "retention_days": 90,
            },
            "destinations": [
                {
                    "name": "local-jsonl",
                    "kind": "jsonl",
                    "enabled": False,
                    "path": "~/.defenseclaw/gateway.jsonl",
                    "rotation": {
                        "max_size_mb": 50,
                        "max_backups": 5,
                        "max_age_days": 30,
                        "compress": True,
                    },
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67108864,
                    },
                    "routes": [
                        {
                            "name": "omit-diagnostics",
                            "signals": ["logs"],
                            "selector": {"buckets": ["diagnostic"]},
                            "action": "drop",
                        },
                        {
                            "name": "reviewed-security",
                            "signals": ["logs"],
                            "selector": {
                                "buckets": ["security.finding", "guardrail.evaluation"],
                                "sources": ["ai_defense", "codeguard"],
                                "connectors": ["codex", "openclaw"],
                                "actions": ["block", "quarantine"],
                                "event_names": ["finding.observed"],
                                "min_severity": "HIGH",
                            },
                            "action": "send",
                            "redaction_profile": "soc",
                        },
                    ],
                },
                {
                    "name": "operator-console",
                    "kind": "console",
                    "enabled": False,
                    "batch": {
                        "max_queue_size": 1024,
                        "max_queue_bytes": 33554432,
                    },
                    "send": {
                        "signals": ["logs"],
                        "buckets": ["compliance.activity", "platform.health"],
                        "redaction_profile": "strict",
                    },
                },
                {
                    "name": "prometheus",
                    "kind": "prometheus",
                    "enabled": False,
                    "listen": "127.0.0.1:9464",
                    "path": "/metrics",
                    "send": {
                        "signals": ["metrics"],
                        "buckets": ["security.finding", "guardrail.evaluation"],
                    },
                },
                {
                    "name": "splunk-production",
                    "kind": "splunk_hec",
                    "enabled": False,
                    "endpoint": "https://splunk.example.test:8088/services/collector/event",
                    "token_env": "SPLUNK_HEC_TOKEN",
                    "index": "main",
                    "source": "defenseclaw",
                    "sourcetype": "defenseclaw:event",
                    "sourcetype_overrides": {
                        "llm-judge-response": "defenseclaw:judge",
                        "guardrail-verdict": "defenseclaw:verdict",
                    },
                    "tls": {"insecure_skip_verify": False, "ca_cert": ""},
                    "timeout_ms": 10000,
                    "network_safety": {
                        "allow_private_networks": False,
                        "allow_cgnat": False,
                    },
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67108864,
                        "max_export_batch_size": 256,
                        "max_export_batch_bytes": 8388608,
                        "scheduled_delay_ms": 1000,
                    },
                    "routes": [
                        {
                            "name": "security",
                            "signals": ["logs"],
                            "selector": {
                                "buckets": ["security.finding", "enforcement.action"],
                                "min_severity": "HIGH",
                            },
                            "action": "send",
                            "redaction_profile": "soc",
                        }
                    ],
                },
                {
                    "name": "http-archive",
                    "kind": "http_jsonl",
                    "enabled": False,
                    "endpoint": "https://archive.example.test/defenseclaw",
                    "method": "POST",
                    "bearer_env": "ARCHIVE_BEARER_TOKEN",
                    "headers": {"X-Tenant": {"env": "ARCHIVE_TENANT"}},
                    "tls": {"insecure_skip_verify": False, "ca_cert": ""},
                    "timeout_ms": 10000,
                    "network_safety": {
                        "allow_private_networks": False,
                        "allow_cgnat": False,
                    },
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67108864,
                        "max_export_batch_size": 100,
                        "max_export_batch_bytes": 8388608,
                        "scheduled_delay_ms": 1000,
                    },
                    "send": {
                        "signals": ["logs"],
                        "buckets": ["compliance.activity"],
                        "redaction_profile": "strict",
                    },
                },
                {
                    "name": "general-otel",
                    "kind": "otlp",
                    "enabled": False,
                    "protocol": "http/protobuf",
                    "endpoint": "https://otel.example.test",
                    "headers": {
                        "Authorization": {"env": "OTEL_AUTHORIZATION"},
                        "X-Deployment": "production",
                    },
                    "logger_name": "defenseclaw.audit",
                    "tls": {"insecure": False, "ca_cert": "/etc/defenseclaw/otel-ca.pem"},
                    "timeout_ms": 10000,
                    "network_safety": {
                        "allow_private_networks": False,
                        "allow_cgnat": False,
                    },
                    "signal_overrides": {
                        "logs": {"endpoint": "", "path": "/v1/logs"},
                        "traces": {"endpoint": "", "path": "/v1/traces"},
                        "metrics": {"endpoint": "", "path": "/v1/metrics"},
                    },
                    "batch": {
                        "max_queue_size": 4096,
                        "max_queue_bytes": 134217728,
                        "max_export_batch_size": 512,
                        "max_export_batch_bytes": 16777216,
                        "scheduled_delay_ms": 5000,
                    },
                    "routes": [
                        {
                            "name": "operational-logs",
                            "signals": ["logs"],
                            "selector": {"buckets": ["compliance.activity", "platform.health"]},
                            "action": "send",
                            "redaction_profile": "strict",
                        },
                        {
                            "name": "runtime-signals",
                            "signals": ["traces", "metrics"],
                            "selector": {"buckets": ["model.io", "tool.activity", "agent.lifecycle"]},
                            "action": "send",
                            "redaction_profile": "sensitive",
                        },
                    ],
                },
                {
                    "name": "galileo",
                    "kind": "otlp",
                    "preset": "galileo",
                    "enabled": False,
                    "protocol": "http/protobuf",
                    "endpoint": "https://api.galileo.ai/otel/traces",
                    "headers": {
                        "Galileo-API-Key": {"env": "GALILEO_API_KEY"},
                        "project": "defenseclaw",
                        "logstream": "production",
                    },
                    "network_safety": {
                        "allow_private_networks": False,
                        "allow_cgnat": False,
                    },
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67108864,
                        "max_export_batch_size": 512,
                        "max_export_batch_bytes": 8388608,
                        "scheduled_delay_ms": 1000,
                    },
                    "send": {
                        "signals": ["traces"],
                        "buckets": [
                            "agent.lifecycle",
                            "model.io",
                            "tool.activity",
                            "guardrail.evaluation",
                        ],
                        "redaction_profile": "sensitive",
                    },
                },
            ],
        },
    }


def _resolve(schema: Mapping[str, Any], node: Mapping[str, Any]) -> Mapping[str, Any]:
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return node
    if not ref.startswith("#/"):
        raise ValueError(f"external reference is not supported: {ref}")
    target: Any = schema
    for part in ref[2:].split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    if not isinstance(target, Mapping):
        raise TypeError(f"schema reference {ref} does not resolve to an object")
    return target


def _schema_type(schema: Mapping[str, Any], node: Mapping[str, Any]) -> str:
    node = _resolve(schema, node)
    if "const" in node:
        return "constant"
    if "oneOf" in node:
        return "one of"
    value = node.get("type", "")
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return str(value or "constraint")


def _allowed(node: Mapping[str, Any]) -> str:
    if "const" in node:
        return json.dumps(node["const"], separators=(",", ":"))
    enum = node.get("enum")
    if isinstance(enum, list):
        return ", ".join(str(value) for value in enum)
    return ""


def _format_default(node: Mapping[str, Any]) -> str:
    if "default" not in node:
        return ""
    return json.dumps(node["default"], separators=(",", ":"))


def _field_rows(
    schema: Mapping[str, Any],
    node: Mapping[str, Any],
    prefix: str,
    seen: set[tuple[str, str]],
) -> list[tuple[str, str, str, str, str]]:
    """Return recursive field rows, retaining per-variant destination details."""

    node = _resolve(schema, node)
    rows: list[tuple[str, str, str, str, str]] = []
    one_of = node.get("oneOf")
    if isinstance(one_of, list):
        for variant in one_of:
            if isinstance(variant, Mapping):
                rows.extend(_field_rows(schema, variant, prefix, seen))
        return rows

    properties = node.get("properties")
    if isinstance(properties, Mapping):
        required = set(node.get("required", []))
        for name, child in properties.items():
            if not isinstance(child, Mapping):
                continue
            child_resolved = _resolve(schema, child)
            path = f"{prefix}.{name}" if prefix else str(name)
            key = (path, _schema_type(schema, child))
            if key not in seen:
                seen.add(key)
                description = str(child.get("description") or child_resolved.get("description") or "")
                if name in required:
                    description = f"Required. {description}".strip()
                rows.append(
                    (
                        path,
                        _schema_type(schema, child),
                        _format_default(child_resolved),
                        _allowed(child_resolved),
                        description,
                    )
                )
            rows.extend(_field_rows(schema, child, path, seen))

    additional = node.get("additionalProperties")
    if isinstance(additional, Mapping):
        path = f"{prefix}.<name>"
        key = (path, _schema_type(schema, additional))
        if key not in seen:
            seen.add(key)
            rows.append((path, _schema_type(schema, additional), "", "", "User-named entry."))
        rows.extend(_field_rows(schema, additional, path, seen))

    items = node.get("items")
    if isinstance(items, Mapping):
        rows.extend(_field_rows(schema, items, f"{prefix}[]", seen))
    return rows


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _destination_variants(schema: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    destination = _resolve(schema, schema["$defs"]["destination"])
    variants = []
    for variant in destination.get("oneOf", []):
        resolved = _resolve(schema, variant)
        kind = _resolve(schema, resolved["properties"]["kind"])["const"]
        variants.append((str(kind), resolved))
    return variants


def _render_markdown(schema: Mapping[str, Any]) -> str:
    observability = _resolve(schema, schema["$defs"]["observability"])
    rows = _field_rows(schema, observability, "observability", set())
    variants = _destination_variants(schema)
    lines = [
        "# DefenseClaw v8 observability configuration reference",
        "",
        "<!-- GENERATED FILE. DO NOT EDIT. -->",
        "",
        "This reference is generated from `schemas/config/v8/defenseclaw-config.schema.json`.",
        "The JSON Schema is the source of truth; this document and the adjacent exhaustive",
        "YAML are presentation artifacts checked for drift in CI.",
        "",
        "```text",
        "producer -> bucket/signal -> collect -> sample -> route -> redact -> export",
        "                                  \\-> mandatory local SQLite audit floor",
        "```",
        "",
        "An enabled destination with neither `send` nor `routes` receives every bucket and",
        "every signal its kind supports, unredacted. Configure `send` for one concise policy",
        "or ordered `routes` for selector-specific policy. Collection gates run first.",
        "",
        "## Destination kinds",
        "",
        "| Kind | Supported signals | Source fields |",
        "|---|---|---|",
    ]
    signal_support = {
        "jsonl": "logs",
        "console": "logs",
        "prometheus": "metrics",
        "splunk_hec": "logs",
        "http_jsonl": "logs",
        "otlp": "logs, traces, metrics (Galileo preset: traces)",
    }
    for kind, variant in variants:
        fields = ", ".join(f"`{name}`" for name in variant.get("properties", {}))
        lines.append(f"| `{kind}` | {signal_support[kind]} | {fields} |")

    lines.extend(
        [
            "",
            "## Complete source field catalog",
            "",
            "`<name>` denotes a user-selected map key; `[]` denotes an array item.",
            "Constraints that span fields are enforced by the compiler in addition to JSON Schema.",
            "",
            "| Source path | Type | Default | Allowed / constant | Description |",
            "|---|---|---|---|---|",
        ]
    )
    for path, value_type, default, allowed, description in rows:
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_escape_cell(path)}`",
                    _escape_cell(value_type),
                    f"`{_escape_cell(default)}`" if default else "",
                    f"`{_escape_cell(allowed)}`" if allowed else "",
                    _escape_cell(description),
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Exhaustive YAML",
            "",
            "See [`observability.yaml`](./observability.yaml). It intentionally disables every",
            "optional destination while demonstrating all destination kinds, selectors, secret",
            "references, redaction controls, and local-retention controls.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_yaml(document: Mapping[str, Any]) -> str:
    body = yaml.safe_dump(
        dict(document),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    )
    annotated: list[str] = []
    for line in body.splitlines():
        annotated.extend(YAML_ANNOTATIONS.get(line, ()))
        annotated.append(line)
    return YAML_HEADER + "\n".join(annotated) + "\n"


def _schema_paths(schema: Mapping[str, Any], node: Mapping[str, Any], prefix: str) -> set[str]:
    """Return structural source paths declared by a schema node."""

    node = _resolve(schema, node)
    paths: set[str] = set()
    one_of = node.get("oneOf")
    if isinstance(one_of, list):
        for variant in one_of:
            if isinstance(variant, Mapping):
                paths.update(_schema_paths(schema, variant, prefix))
        return paths
    properties = node.get("properties")
    if isinstance(properties, Mapping):
        for name, child in properties.items():
            if not isinstance(child, Mapping):
                continue
            path = f"{prefix}.{name}" if prefix else str(name)
            paths.add(path)
            paths.update(_schema_paths(schema, child, path))
    additional = node.get("additionalProperties")
    if isinstance(additional, Mapping):
        path = f"{prefix}.*"
        paths.add(path)
        paths.update(_schema_paths(schema, additional, path))
    items = node.get("items")
    if isinstance(items, Mapping):
        paths.update(_schema_paths(schema, items, f"{prefix}[]"))
    return paths


def _document_paths(value: Any, prefix: str = "") -> set[str]:
    """Return document paths, normalizing schema-defined user map keys."""

    paths: set[str] = set()
    if isinstance(value, Mapping):
        dynamic_parents = {
            "observability.resource.attributes",
            "observability.buckets",
            "observability.redaction_profiles",
            "observability.connectors",
        }
        dynamic_suffixes = (".headers", ".sourcetype_overrides")
        for name, child in value.items():
            rendered = "*" if prefix in dynamic_parents or prefix.endswith(dynamic_suffixes) else str(name)
            path = f"{prefix}.{rendered}" if prefix else rendered
            paths.add(path)
            paths.update(_document_paths(child, path))
    elif isinstance(value, list) and value:
        item_prefix = f"{prefix}[]"
        for child in value:
            paths.update(_document_paths(child, item_prefix))
    return paths


def _validate_reference(schema: Mapping[str, Any], document: Mapping[str, Any]) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - dependency declaration guards this
        raise RuntimeError("jsonschema is required to generate the v8 reference") from exc

    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ValueError(f"generated YAML violates canonical schema at {path}: {first.message}")
    observability_schema = _resolve(schema, schema["$defs"]["observability"])
    expected_paths = _schema_paths(schema, observability_schema, "observability")
    actual_paths = _document_paths(document)
    missing = sorted(expected_paths - actual_paths)
    if missing:
        raise ValueError("reference does not exercise schema source fields: " + ", ".join(missing))

    expected_kinds = {kind for kind, _ in _destination_variants(schema)}
    actual_kinds = {
        str(item.get("kind")) for item in document["observability"]["destinations"] if isinstance(item, Mapping)
    }
    if actual_kinds != expected_kinds:
        raise ValueError(
            "reference destination-kind drift: "
            f"missing={sorted(expected_kinds - actual_kinds)} "
            f"extra={sorted(actual_kinds - expected_kinds)}"
        )


def _outputs(schema_bytes: bytes) -> dict[Path, bytes]:
    schema = json.loads(schema_bytes)
    document = _reference_document()
    _validate_reference(schema, document)
    yaml_bytes = _render_yaml(document).encode()
    markdown_bytes = _render_markdown(schema).encode()
    return {
        CANONICAL_YAML: yaml_bytes,
        CANONICAL_MARKDOWN: markdown_bytes,
    }


def _write(outputs: Mapping[Path, bytes]) -> None:
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        print(f"generate_observability_v8_reference: wrote {path.relative_to(ROOT)}")


def _check(outputs: Mapping[Path, bytes]) -> bool:
    ok = True
    for path, expected in outputs.items():
        try:
            actual = path.read_bytes()
        except FileNotFoundError:
            print(
                f"generate_observability_v8_reference: missing {path.relative_to(ROOT)}; run with --write",
                file=sys.stderr,
            )
            ok = False
            continue
        # Git may materialize these generated UTF-8 text references with CRLF
        # when core.autocrlf=true. Compare their canonical LF representation so
        # Windows checkouts do not report drift while all content remains
        # covered by the deterministic generator.
        if actual.replace(b"\r\n", b"\n") != expected.replace(b"\r\n", b"\n"):
            print(
                f"generate_observability_v8_reference: drift in {path.relative_to(ROOT)}; run with --write",
                file=sys.stderr,
            )
            ok = False
        else:
            print(f"generate_observability_v8_reference: {path.relative_to(ROOT)} OK")
    return ok


def generate(*, write: bool) -> bool:
    outputs = _outputs(SCHEMA_PATH.read_bytes())
    if write:
        _write(outputs)
        return True
    return _check(outputs)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="regenerate all checked-in artifacts")
    mode.add_argument("--check", action="store_true", help="check artifacts (default)")
    args = parser.parse_args(argv)
    try:
        return 0 if generate(write=args.write) else 1
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        print(f"generate_observability_v8_reference: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
