"""Focused provenance and failure-atomicity tests for the telemetry compiler."""

from __future__ import annotations

import copy
import dataclasses
import functools
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"
UPDATER = ROOT / "scripts/update_telemetry_registry_upstream.py"
OUTPUT_DRIVER = ROOT / "cli/tests/support/telemetry_registry_manifest_driver.py"

DEPENDENCIES = (
    (
        "otel_core",
        "https://github.com/open-telemetry/semantic-conventions",
        "v1.42.0",
        "otel-semconv-v1.42.0",
        "ae3a98640194ed405c4c797281502e4d3bd258b3",
        "otel-core.normalized.json",
        "service.name",
    ),
    (
        "otel_genai",
        "https://github.com/open-telemetry/semantic-conventions-genai",
        "test",
        "otel-genai-b028dceecdad117461a785c3af35315e7184e813",
        "b028dceecdad117461a785c3af35315e7184e813",
        "otel-genai.normalized.json",
        "gen_ai.operation.name",
    ),
    (
        "openinference",
        "https://github.com/Arize-ai/openinference",
        "0.1.30",
        "openinference-semantic-conventions-v0.1.30",
        "789d41974c08a9a13147977f28ef4142a07e2106",
        "openinference.normalized.json",
        "openinference.span.kind",
    ),
)

# Test-only review lock. Runtime validation derives this order from the registry source.
_CANONICAL_OUTCOME_ORDER = (
    "allowed",
    "applied",
    "approved",
    "attempted",
    "blocked",
    "cancelled",
    "completed",
    "denied",
    "failed",
    "no_change",
    "partial",
    "quarantined",
    "redacted",
    "rejected",
    "released",
    "revoked",
    "skipped",
    "terminated",
    "timed_out",
    "validated",
)
_CANONICAL_AGENT_PHASES = (
    "session",
    "planning",
    "model",
    "tool",
    "approval",
    "waiting",
    "responding",
    "maintenance",
    "completed",
    "failed",
    "interrupted",
    "observed",
)

_SPAN_NAME_REQUIRED_CORRECTIONS = (
    ("span.admin.operation", "defenseclaw.admin.operation"),
    ("span.agent.invoke", "defenseclaw.agent.type"),
    ("span.asset.transition", "defenseclaw.asset.transition"),
    ("span.destination.export", "defenseclaw.destination.id"),
    ("span.enforcement.apply", "defenseclaw.enforcement.effective_action"),
    ("span.guardrail.apply", "defenseclaw.guardrail.name"),
    ("span.guardrail.apply", "defenseclaw.guardrail.target_type"),
    ("span.guardrail.judge", "gen_ai.request.model"),
    ("span.guardrail.phase", "defenseclaw.guardrail.phase"),
    ("span.model.chat", "gen_ai.request.model"),
    ("span.model.embeddings", "gen_ai.request.model"),
    ("span.network.request", "http.request.method"),
    ("span.retrieval.search", "defenseclaw.retrieval.source.id"),
    ("span.telemetry.normalize", "defenseclaw.telemetry.signal"),
    ("span.telemetry.receive", "http.request.method"),
    ("span.tool.execute", "gen_ai.tool.name"),
)

_ALL_SPAN_NAME_FIELDS = tuple(
    sorted(
        (
            *_SPAN_NAME_REQUIRED_CORRECTIONS,
            ("span.agent.transition", "defenseclaw.agent.lifecycle.event"),
            ("span.finding.enrich", "defenseclaw.source"),
            ("span.workflow.run", "defenseclaw.workflow.name"),
        )
    )
)


@pytest.fixture(scope="module")
def real_span_name_contract() -> tuple[ModuleType, Any, Any, Any, Any]:
    module = _load_generator_module("telemetry_registry_span_name_required_contract")
    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    local_attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    extensions = {extension.ref: extension for domain in ir.domains for extension in domain.attribute_extensions}
    upstream = {
        attribute.id: (dependency.id, attribute)
        for dependency in ir.dependencies
        for attribute in dependency.snapshot.attributes
    }
    return module, groups, local_attributes, extensions, upstream


# Test-only review lock. Runtime consumers resolve these rules from registry.yaml.
_MANDATORY_RULE_CATALOG_V1 = (
    ("always", "constant", True),
    ("control_plane_mutation", "builder_fact", "control_plane_mutation"),
    ("approval_resolution", "builder_fact", "approval_resolution"),
    ("alert_mutation", "builder_fact", "alert_mutation"),
    (
        "protected_boundary_auth_failure",
        "builder_fact",
        "protected_boundary_auth_failure",
    ),
    ("enforced_outcome", "builder_fact", "enforced_outcome"),
    ("enforcement_state_change", "builder_fact", "enforcement_state_change"),
    ("schema_validation_failure", "builder_fact", "schema_validation_failure"),
    ("sqlite_failure", "builder_fact", "sqlite_failure"),
    (
        "exporter_initialization_failure",
        "builder_fact",
        "exporter_initialization_failure",
    ),
    ("durable_health_transition", "builder_fact", "durable_health_transition"),
    ("destination_test_activity", "builder_fact", "destination_test_activity"),
    ("managed_aid_fail_open", "builder_fact", "managed_aid_fail_open"),
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _grouped_outcome_contract_matrix(
    contracts: list[tuple[str, str, tuple[str, ...]]],
) -> tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]:
    grouped: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for family_id, requirement, outcomes in contracts:
        grouped.setdefault((requirement, outcomes), []).append(family_id)
    return tuple(
        (requirement, outcomes, tuple(sorted(family_ids)))
        for (requirement, outcomes), family_ids in sorted(grouped.items())
    )


def _outcome_contract_digest(
    contracts: list[tuple[str, str, tuple[str, ...]]],
) -> str:
    matrix = _grouped_outcome_contract_matrix(contracts)
    return _sha256(json.dumps(matrix, separators=(",", ":")).encode())


def _write_yaml(path: Path, value: Any) -> None:
    if isinstance(value, dict) and isinstance(value.get("groups"), list):
        for group in value["groups"]:
            if isinstance(group, dict):
                group.setdefault("introduced_in", "telemetry-registry-v1")
    _write_yaml_raw(path, value)


def _write_yaml_raw(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


@functools.lru_cache(maxsize=1)


def _snapshot(
    dependency_id: str,
    repository: str,
    revision: str,
    attribute: str,
) -> bytes:
    del attribute
    source_path = "model/registry.yaml"
    source_files = [{"path": source_path, "sha256": "a" * 64}]
    if dependency_id == "otel_core":
        identifiers = {"service.version"}
    elif dependency_id == "otel_genai":
        identifiers = {
            "gen_ai.operation.name",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.tool.call.arguments",
            "gen_ai.tool.call.result",
        }
    else:
        identifiers = set()
    attributes = []
    for index, identifier in enumerate(sorted(identifiers)):
        structured_any = identifier in {
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.tool.call.arguments",
            "gen_ai.tool.call.result",
        }
        allowed_types = [] if structured_any else ["string"]
        attributes.append(
            {
                "id": identifier,
                "allowed_types": allowed_types,
                "shape": "any_value" if structured_any else "attribute",
                "stability": "development",
                "stability_source": "upstream",
                "source_pointer": f"{source_path}#/attributes/{index}",
                "enum": [],
                "deprecated": False,
            }
        )
    if dependency_id == "openinference":
        source_files = [
            {
                "path": "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
                "sha256": "a" * 64,
            },
            {"path": "spec/semantic_conventions.md", "sha256": "d" * 64},
        ]
        identifiers = {
            "openinference.span.kind",
            "input.value",
            "input.mime_type",
            "output.value",
            "output.mime_type",
            "metadata",
            "openinference.project.name",
        }
        attributes = [
            {
                "id": identifier,
                "allowed_types": ["string"],
                "shape": "attribute",
                "stability": "stable",
                "stability_source": "released_package_policy",
                "source_pointer": (
                    "python/openinference-semantic-conventions/src/openinference/semconv/"
                    f"resource/__init__.py#L{index + 1}"
                    if identifier == "openinference.project.name"
                    else f"spec/semantic_conventions.md#L{index + 1}"
                ),
                "enum": [],
                "deprecated": False,
            }
            for index, identifier in enumerate(sorted(identifiers))
        ]
    value = {
        "format_version": 2,
        "format": "defenseclaw-selected-semconv-v1",
        "dependency_id": dependency_id,
        "repository": repository,
        "revision": revision,
        "source_archive": {
            "url": f"{repository}/archive/{revision}.tar.gz",
            "sha256": "b" * 64,
        },
        "source_tree_sha256": "c" * 64,
        "full_normalized_inventory_sha256": "d" * 64,
        "selection": {
            "policy": (
                "runtime-profile-vocabulary-v1"
                if dependency_id == "openinference"
                else "authored-extension-closure-v1"
            ),
            "attribute_ids_sha256": _sha256(
                json.dumps(sorted(identifiers), separators=(",", ":")).encode()
            ),
        },
        "source_files": source_files,
        "attributes": attributes,
    }
    return (json.dumps(value, indent=2) + "\n").encode()


def _domain_sources() -> dict[str, dict[str, Any]]:
    domains = {
        "genai.yaml": {
            "schema_version": 1,
            "domain": "genai",
            "attributes": [
                {
                    "id": "defenseclaw.test.name",
                    "type": "string",
                    "brief": "A fixture-owned attribute.",
                    "examples": ["fixture"],
                    "stability": "development",
                    "owner": "defenseclaw",
                    "field_class": "metadata",
                    "sensitivity": "safe",
                    "cardinality": "low",
                    "normalization": {"id": "bounded-v1"},
                    "introduced_in": "telemetry-registry-v1",
                },
                {
                    "id": "defenseclaw.test.high",
                    "type": "string",
                    "brief": "A reviewed high-cardinality fixture attribute.",
                    "examples": ["fixture-high"],
                    "stability": "development",
                    "owner": "defenseclaw",
                    "field_class": "identifier",
                    "sensitivity": "internal",
                    "cardinality": "high",
                    "normalization": {"id": "bounded-v1"},
                    "introduced_in": "telemetry-registry-v1",
                },
            ],
            "attribute_extensions": [
                {
                    "ref": "gen_ai.operation.name",
                    "field_class": "metadata",
                    "sensitivity": "safe",
                    "cardinality": "low",
                    "normalization": {
                        "id": "enum-v1",
                        "overrides": {"enum": ["chat"]},
                    },
                }
            ],
            "groups": [
                {
                    "id": "span.model.chat",
                    "type": "span",
                    "brief": "A model chat call.",
                    "stability": "stable",
                    "extends": ["span.core"],
                    "attributes": [
                        {
                            "ref": "gen_ai.operation.name",
                            "requirement_level": "required",
                        }
                    ],
                    "span": {
                        "name_pattern": "chat {gen_ai.operation.name}",
                        "kinds": ["CLIENT"],
                        "status_rule": "technical_error_only",
                    },
                    "x-defenseclaw": {
                        "bucket": "model.io",
                        "family_schema_version": 1,
                        "outcome_requirement": "optional",
                        "allowed_outcomes": ["completed"],
                        "events": ["guardrail.decision"],
                        "route_selector": True,
                    },
                }
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
        "security.yaml": {
            "schema_version": 1,
            "domain": "security",
            "attributes": [],
            "attribute_extensions": [],
            "groups": [
                {
                    "id": "event.guardrail.decision",
                    "type": "span_event",
                    "brief": "A bounded guardrail decision.",
                    "stability": "stable",
                }
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
        "operations.yaml": {
            "schema_version": 1,
            "domain": "operations",
            "attributes": [],
            "attribute_extensions": [],
            "groups": [
                {
                    "id": "body.fixture",
                    "type": "body_group",
                    "brief": "A generated log body fixture.",
                    "stability": "development",
                },
                {
                    "id": "diagnostic.message",
                    "type": "log",
                    "brief": "A diagnostic message.",
                    "stability": "stable",
                    "extends": ["body.fixture"],
                    "log": {"event_name": "diagnostic.message"},
                    "x-defenseclaw": {
                        "bucket": "diagnostic",
                        "family_schema_version": 1,
                        "outcome_requirement": "forbidden",
                        "allowed_outcomes": [],
                    },
                },
            ],
            "producer_identity_sets": [],
            "producer_mappings": [],
        },
    }
    canonical_genai = yaml.safe_load((ROOT / "schemas/telemetry/v8/genai.yaml").read_text(encoding="utf-8"))
    structured_refs = (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    )
    for reference in structured_refs:
        domains["genai.yaml"]["attribute_extensions"].append(
            copy.deepcopy(next(item for item in canonical_genai["attribute_extensions"] if item["ref"] == reference))
        )
        domains["genai.yaml"]["groups"][0]["attributes"].append({"ref": reference, "requirement_level": "optional"})
    for attribute_id in (
        "defenseclaw.bucket",
        "defenseclaw.outcome",
        "defenseclaw.span.family",
        "defenseclaw.span.family_schema_version",
        "defenseclaw.source",
        "defenseclaw.connector.source",
        "defenseclaw.config.generation",
        "defenseclaw.run.id",
        "defenseclaw.operation.id",
        "defenseclaw.semantic_event.id",
        "defenseclaw.logical_event.id",
        "defenseclaw.connector.instance.id",
        "defenseclaw.agent.phase",
        "defenseclaw.agent.phase.previous",
        "defenseclaw.agent.phase.from",
        "defenseclaw.agent.phase.to",
        "defenseclaw.agent.phase.code",
        "defenseclaw.trace.schema_version",
        "defenseclaw.semantic_profile",
        "defenseclaw.link.relation",
    ):
        attribute = copy.deepcopy(next(item for item in canonical_genai["attributes"] if item["id"] == attribute_id))
        if attribute_id in {
            "defenseclaw.agent.phase",
            "defenseclaw.agent.phase.previous",
            "defenseclaw.agent.phase.from",
            "defenseclaw.agent.phase.to",
        }:
            attribute["normalization"] = {
                "id": "enum-v1",
                "overrides": {"enum": list(_CANONICAL_AGENT_PHASES)},
            }
        domains["genai.yaml"]["attributes"].append(attribute)
    for group_id in ("scope.core", "link.core", "span.core"):
        domains["genai.yaml"]["groups"].append(
            copy.deepcopy(next(item for item in canonical_genai["groups"] if item["id"] == group_id))
        )
    operations = domains["operations.yaml"]
    canonical_operations = yaml.safe_load((ROOT / "schemas/telemetry/v8/operations.yaml").read_text(encoding="utf-8"))
    for attribute_id in (
        "defenseclaw.inventory.connector.identifiers",
        "defenseclaw.inventory.connector.metadata",
        "defenseclaw.inventory.connector.content",
        "defenseclaw.inventory.mcp.identifiers",
        "defenseclaw.inventory.mcp.metadata",
        "defenseclaw.inventory.agent.identifiers",
        "defenseclaw.inventory.agent.metadata",
    ):
        operations["attributes"].append(
            copy.deepcopy(
                next(item for item in canonical_operations["attributes"] if item["id"] == attribute_id)
            )
        )
    operations["attribute_extensions"].append(
        copy.deepcopy(
            next(item for item in canonical_operations["attribute_extensions"] if item["ref"] == "service.version")
        )
    )
    for index in range(80):
        operations["groups"].append(
            {
                "id": f"fixture.log.{index}",
                "type": "log",
                "brief": "A generated canonical fixture log.",
                "stability": "development",
                "extends": ["body.fixture"],
                "log": {"event_name": f"fixture.event.{index}"},
                "x-defenseclaw": {
                    "bucket": "diagnostic",
                    "family_schema_version": 1,
                    "outcome_requirement": "forbidden",
                    "allowed_outcomes": [],
                },
            }
        )
    for event_name in (
        "compact_end",
        "compact_start",
        "event",
        "hook_decision",
        "session_end",
        "session_start",
        "subagent_start",
        "subagent_stop",
        "tool_end",
        "tool_start",
        "turn_end",
        "turn_start",
    ):
        operations["groups"].append(
            {
                "id": f"fixture.compat.{event_name}",
                "type": "log",
                "brief": "A generated compatibility fixture log.",
                "stability": "development",
                "extends": ["body.fixture"],
                "log": {"event_name": event_name},
                "x-defenseclaw": {
                    "bucket": "agent.lifecycle",
                    "family_schema_version": 1,
                    "outcome_requirement": "forbidden",
                    "allowed_outcomes": [],
                },
            }
        )
    for index in range(24):
        operations["groups"].append(
            {
                "id": f"span.fixture.{index}",
                "type": "span",
                "brief": "A generated span fixture.",
                "stability": "development",
                "extends": ["span.core"],
                "span": {
                    "name_pattern": f"fixture.span.{index}",
                    "kinds": ["INTERNAL"],
                    "status_rule": "technical_error_only",
                },
                "x-defenseclaw": {
                    "bucket": "diagnostic",
                    "family_schema_version": 1,
                    "outcome_requirement": "optional",
                    "allowed_outcomes": ["completed"],
                },
            }
        )
    inventory = yaml.safe_load(
        (ROOT / "docs/design/observability-v8/current-state-inventory.yaml").read_text(encoding="utf-8")
    )
    metric_items = inventory["classes"]["emitted_metrics"]["items"]
    for instrument_name, contract in metric_items.items():
        metric: dict[str, Any] = {
            "instrument_name": instrument_name,
            "instrument_type": contract["type"],
            "value_type": "int64",
            "unit": contract["unit"],
            "description": "Generated metric fixture.",
            "temporality": "delta",
        }
        metric["empty_labels_reason"] = "Fixture producer emits no instrument labels."
        group: dict[str, Any] = {
            "id": f"metric.{instrument_name}",
            "type": "metric",
            "brief": "Generated metric fixture.",
            "stability": "development",
            "metric": metric,
            "x-defenseclaw": {
                "bucket": "diagnostic",
                "family_schema_version": 1,
            },
        }
        if instrument_name in {"gen_ai.client.token.usage", "gen_ai.client.operation.duration"}:
            group["attributes"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
            metric.pop("empty_labels_reason")
        operations["groups"].append(group)
    for producer, section, source in (
        ("gateway_event", "gateway_event_types", "gateway"),
        ("audit_action", "audit_actions", "audit"),
    ):
        for key in inventory["classes"][section]["items"].values():
            operations["producer_mappings"].append(
                {
                    "producer": producer,
                    "key": key,
                    "source": source,
                    "event_name_policy": "fixed",
                    "default_identity": {
                        "event_name": "diagnostic.message",
                        "bucket": "diagnostic",
                        "family": "diagnostic.message",
                    },
                    "severity_policy": "canonical_or_info",
                }
            )
    operations["groups"].insert(
        0,
        {
            "id": "resource.core",
            "type": "resource",
            "brief": "A fixture resource contract.",
            "stability": "stable",
            "attributes": [{"ref": "service.version", "requirement_level": "required"}],
        },
    )
    for domain in domains.values():
        for group in domain["groups"]:
            group["introduced_in"] = "telemetry-registry-v1"
            if group["type"] in {"log", "span", "metric"}:
                profiles = ["local-observability-v1"]
                if group["id"] == "span.model.chat":
                    profiles.insert(0, "galileo-rich-v2")
                group.setdefault("x-defenseclaw", {})["compatibility_profiles"] = profiles
    return domains


def _fixture_inbound_bindings() -> dict[str, Any]:
    """Return a closed synthetic inbound catalog using only fixture families."""

    def predicate(
        location: str,
        key: str,
        operator: str,
        *,
        values: list[str | int] | None = None,
        value_type: str = "string",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "location": location,
            "key": key,
            "operator": operator,
            "value_type": value_type,
        }
        if values is not None:
            result["values"] = values
        return result

    def binding(
        binding_id: str,
        signal: str,
        sources: list[str],
        mode: str,
        expansion: dict[str, Any],
        predicates: list[dict[str, Any]],
        *,
        aliases: list[str] | None = None,
        derived_targets: list[dict[str, str]] | None = None,
        native: bool = False,
        strategy: str = "fixture-mapping-v1",
        unit_rule: dict[str, Any] | None = None,
        source_projection_plan: str | None = None,
    ) -> dict[str, Any]:
        mapping: dict[str, Any] = {"strategy": strategy, "alias_sets": aliases or []}
        if unit_rule is not None:
            mapping["unit_rule"] = unit_rule
        if source_projection_plan is not None:
            mapping["source_projection_plan"] = source_projection_plan
        return {
            "id": binding_id,
            "signal": signal,
            "sources": sources,
            "mode": mode,
            "expansion": expansion,
            "discriminator": {"kind": f"fixture-{signal}-v1", "predicates": predicates},
            "mapping": mapping,
            "derived_targets": derived_targets or [],
            "time_rule": "fixture-time-v1",
            "outcome_rule": "forbidden",
            "native_round_trip": native,
        }

    alias_specs = (
        ("conversation-id-v1", "gen_ai.conversation.id", ["conversation.id"]),
        ("codex-conversation-id-v1", "gen_ai.conversation.id", ["conversation.id"]),
        ("request-id-v1", "defenseclaw.request.id", ["request.id"]),
        ("turn-id-v1", "defenseclaw.turn.id", ["turn.id"]),
        ("codex-turn-id-v1", "defenseclaw.turn.id", ["turn.id"]),
        ("claudecode-turn-id-v1", "defenseclaw.turn.id", ["prompt.id"]),
        ("provider-v1", "gen_ai.provider.name", ["provider"]),
        ("request-model-v1", "gen_ai.request.model", ["model"]),
        ("codex-tool-name-v1", "gen_ai.tool.name", ["tool_name"]),
        ("codex-tool-call-id-v1", "gen_ai.tool.call.id", ["call_id"]),
        ("codex-tool-arguments-v1", "gen_ai.tool.call.arguments", ["arguments"]),
        ("codex-tool-result-v1", "gen_ai.tool.call.result", ["output"]),
        ("input-content-v1", "gen_ai.input.messages", ["prompt"]),
        ("output-content-v1", "gen_ai.output.messages", ["response"]),
        ("input-tokens-v1", "gen_ai.usage.input_tokens", ["input_tokens"]),
        ("output-tokens-v1", "gen_ai.usage.output_tokens", ["output_tokens"]),
        ("cached-input-tokens-v1", "$derived_cached_input_tokens", ["cached_input_tokens"]),
        ("log-duration-seconds-v1", "$derived_duration_seconds", ["duration_seconds"]),
    )
    aliases = [
        {
            "id": alias_id,
            "target": target,
            "value_type": (
                "double"
                if alias_id == "log-duration-seconds-v1"
                else "structured"
                if alias_id in {"codex-tool-arguments-v1", "codex-tool-result-v1"}
                else "string"
            ),
            "normalization": (
                "structured-genai-v1"
                if alias_id in {"codex-tool-arguments-v1", "codex-tool-result-v1"}
                else "bounded-v1"
            ),
            "sources": sources,
        }
        for alias_id, target, sources in alias_specs
    ]
    binding_classes = [
        binding(
            "otlp.native.log.v8",
            "logs",
            ["any_authenticated"],
            "import",
            {"kind": "all_signal_families"},
            [
                predicate("leaf_attribute", "defenseclaw.event.name", "equals_target_event"),
                predicate(
                    "leaf_attribute",
                    "defenseclaw.telemetry.forward.instance_id",
                    "present",
                ),
                predicate("log_body", "$body", "projected_record_json"),
            ],
            native=True,
        ),
        binding(
            "otlp.native.span.v8",
            "traces",
            ["any_authenticated"],
            "import",
            {"kind": "all_signal_families"},
            [
                predicate("scope_name", "$scope_name", "equals_contract"),
                predicate("leaf_attribute", "defenseclaw.span.family", "equals_target_family"),
                predicate(
                    "leaf_attribute",
                    "defenseclaw.telemetry.forward.instance_id",
                    "present",
                ),
            ],
            native=True,
        ),
        binding(
            "otlp.native.metric.v8",
            "metrics",
            ["any_authenticated"],
            "import",
            {"kind": "reversible_metric_families", "instrument_types": ["counter", "gauge", "updowncounter"]},
            [
                predicate("scope_name", "$scope_name", "equals_contract"),
                predicate(
                    "resource_attribute",
                    "defenseclaw.telemetry.forward.instance_id",
                    "present",
                ),
                predicate("instrument_name", "$instrument_name", "equals_target_instrument"),
                predicate("metric_point", "$point_shape", "reversible_target_shape"),
            ],
            native=True,
            strategy="generated-reverse-metric-v1",
            unit_rule={"kind": "target-unit-equality-v1"},
        ),
        binding(
            "otlp.genai.span.operation.v1",
            "traces",
            ["any_authenticated"],
            "import_and_derive",
            {
                "kind": "cases",
                "cases": [
                    {
                        "id_suffix": suffix,
                        "primary_family": family,
                        "operation": operation,
                        "required_key": "defenseclaw.test.name",
                    }
                    for suffix, family, operation in (
                        ("invoke-agent", "span.fixture.0", "invoke_agent"),
                        ("chat", "span.model.chat", "chat"),
                        ("embeddings", "span.fixture.1", "embeddings"),
                        ("execute-tool", "span.fixture.2", "execute_tool"),
                        ("retrieval", "span.fixture.3", "retrieval"),
                        ("invoke-workflow", "span.fixture.4", "invoke_workflow"),
                    )
                ],
            },
            [
                predicate("leaf_attribute", "gen_ai.operation.name", "equals_expansion_operation"),
                predicate("leaf_attribute", "$expansion_required_key", "present"),
                predicate("span", "$ended", "valid_ended_span", value_type="structural"),
            ],
            aliases=["conversation-id-v1", "provider-v1", "request-model-v1"],
        ),
        binding(
            "otlp.codex.turn_span.v1",
            "traces",
            ["codex"],
            "import_and_derive",
            {"kind": "singleton", "primary_family": "span.model.chat"},
            [
                predicate("leaf_attribute", "defenseclaw.span.family", "absent"),
                predicate("leaf_attribute", "gen_ai.operation.name", "absent"),
                predicate("leaf_attribute", "thread.id", "present"),
                predicate("leaf_attribute", "turn.id", "present"),
                predicate("leaf_attribute", "model", "present"),
                predicate("span", "$span_name", "equals", values=["session_task.turn"]),
                predicate("span", "$ended", "valid_ended_span", value_type="structural"),
            ],
            aliases=[
                "conversation-id-v1",
                "request-id-v1",
                "turn-id-v1",
                "provider-v1",
                "request-model-v1",
                "input-tokens-v1",
                "output-tokens-v1",
                "cached-input-tokens-v1",
            ],
            derived_targets=[
                {"family": "metric.gen_ai.client.operation.duration", "strategy": "elapsed-time-v1"},
            ],
        ),
        binding(
            "otlp.codex.user_prompt.v1",
            "logs",
            ["codex"],
            "import",
            {"kind": "singleton", "primary_family": "diagnostic.message"},
            [predicate("leaf_attribute", "event.name", "equals", values=["codex.user_prompt"])],
            aliases=["conversation-id-v1", "input-content-v1"],
        ),
        binding(
            "otlp.codex.tool_result.v1",
            "logs",
            ["codex"],
            "import",
            {"kind": "singleton", "primary_family": "fixture.log.2"},
            [
                predicate("leaf_attribute", "event.name", "equals", values=["codex.tool_result"]),
                predicate("leaf_attribute", "call_id", "present"),
                predicate("leaf_attribute", "tool_name", "present"),
            ],
            aliases=[
                "codex-conversation-id-v1",
                "request-id-v1",
                "codex-turn-id-v1",
                "codex-tool-name-v1",
                "codex-tool-call-id-v1",
                "codex-tool-arguments-v1",
                "codex-tool-result-v1",
            ],
        ),
        binding(
            "otlp.claudecode.user_prompt.v1",
            "logs",
            ["claudecode"],
            "import",
            {"kind": "singleton", "primary_family": "fixture.log.0"},
            [predicate("leaf_attribute", "event.name", "equals", values=["claude_code.user_prompt"])],
            aliases=["conversation-id-v1", "input-content-v1"],
        ),
        binding(
            "otlp.codex.response_completed.v1",
            "logs",
            ["codex"],
            "import_and_derive",
            {"kind": "singleton", "primary_family": "fixture.log.1"},
            [
                predicate("leaf_attribute", "event.name", "equals", values=["codex.sse_event"]),
                predicate("leaf_attribute", "event.kind", "equals", values=["response.completed"]),
                predicate("leaf_attribute", "input_token_count", "present"),
                predicate("leaf_attribute", "output_token_count", "present"),
            ],
            aliases=[
                "conversation-id-v1",
                "output-content-v1",
                "input-tokens-v1",
                "output-tokens-v1",
                "cached-input-tokens-v1",
            ],
            derived_targets=[
                {"family": "metric.defenseclaw.agent.token.usage", "strategy": "codex-token-fields-v1"},
            ],
        ),
        binding(
            "otlp.claudecode.token_usage.v1",
            "metrics",
            ["claudecode"],
            "derive",
            {"kind": "singleton", "primary_family": "metric.gen_ai.client.token.usage"},
            [
                predicate(
                    "instrument_name",
                    "$instrument_name",
                    "equals",
                    values=["claude_code.token.usage"],
                )
            ],
            aliases=[],
            strategy="claude-token-usage-v1",
            source_projection_plan="genai-token-metric-v1",
            unit_rule={
                "kind": "scale-table-v1",
                "accepted": [
                    {"source_unit": "", "scale": 1},
                    {"source_unit": "{token}", "scale": 1},
                    {"source_unit": "token", "scale": 1},
                    {"source_unit": "tokens", "scale": 1},
                ],
            },
        ),
        binding(
            "otlp.codex.token_usage.v1",
            "metrics",
            ["codex"],
            "derive",
            {"kind": "singleton", "primary_family": "metric.gen_ai.client.token.usage"},
            [
                predicate(
                    "instrument_name",
                    "$instrument_name",
                    "equals",
                    values=["codex.turn.token_usage"],
                ),
                predicate(
                    "metric_point_attribute",
                    "token_type",
                    "one_of",
                    values=["input", "cached_input", "output"],
                ),
                predicate("metric_point", "$point_shape", "one_of", values=["histogram"]),
            ],
            aliases=[],
            strategy="claude-token-usage-v1",
            source_projection_plan="genai-token-metric-v1",
            unit_rule={
                "kind": "scale-table-v1",
                "accepted": [
                    {"source_unit": "", "scale": 1},
                    {"source_unit": "{token}", "scale": 1},
                    {"source_unit": "token", "scale": 1},
                    {"source_unit": "tokens", "scale": 1},
                ],
            },
        ),
        binding(
            "otlp.genai.duration.metric.v1",
            "metrics",
            ["any_authenticated"],
            "derive",
            {
                "kind": "source_cases",
                "primary_family": "metric.gen_ai.client.operation.duration",
                "cases": [
                    {"id_suffix": suffix, "instrument_name": instrument}
                    for suffix, instrument in (
                        ("gen-ai-client", "gen_ai.client.operation.duration"),
                        ("gen-ai", "gen_ai.operation.duration"),
                        ("llm", "llm.operation.duration"),
                        ("claude-code", "claude_code.operation.duration"),
                        ("codex", "codex.operation.duration"),
                    )
                ],
            },
            [predicate("instrument_name", "$instrument_name", "equals_expansion_instrument")],
            aliases=[],
            strategy="duration-metric-v1",
            source_projection_plan="genai-duration-metric-v1",
            unit_rule={
                "kind": "scale-table-v1",
                "accepted": [
                    {"source_unit": unit, "scale": scale}
                    for unit, scale in (
                        ("", 1),
                        ("s", 1),
                        ("second", 1),
                        ("seconds", 1),
                        ("ms", 0.001),
                        ("millisecond", 0.001),
                        ("milliseconds", 0.001),
                        ("us", 0.000001),
                        ("microsecond", 0.000001),
                        ("microseconds", 0.000001),
                        ("ns", 0.000000001),
                        ("nanosecond", 0.000000001),
                        ("nanoseconds", 0.000000001),
                    )
                ],
            },
        ),
    ]
    assert [item["id"] for item in aliases] == [item[0] for item in alias_specs]
    assert [item["id"] for item in binding_classes] == [
        "otlp.native.log.v8",
        "otlp.native.span.v8",
        "otlp.native.metric.v8",
        "otlp.genai.span.operation.v1",
        "otlp.codex.turn_span.v1",
        "otlp.codex.user_prompt.v1",
        "otlp.codex.tool_result.v1",
        "otlp.claudecode.user_prompt.v1",
        "otlp.codex.response_completed.v1",
        "otlp.claudecode.token_usage.v1",
        "otlp.codex.token_usage.v1",
        "otlp.genai.duration.metric.v1",
    ]
    canonical_inbound = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))[
        "inbound_bindings"
    ]
    fixture_projection_plans = copy.deepcopy(canonical_inbound["source_projection_plans"])
    fixture_projection_plans[0]["field_rules"] = [
        {
            "target": "defenseclaw.test.name",
            "disposition": "project",
            "requirement": "required",
            "normalization": "genai-operation-label-v1",
            "source_groups": [{"placement": "fixed", "keys": ["chat"]}],
        }
    ]
    fixture_projection_plans[1]["field_rules"] = [
        {
            "target": "defenseclaw.test.name",
            "disposition": "project",
            "requirement": "required",
            "normalization": "genai-provider-label-v1",
            "source_groups": [{"placement": "authenticated_source", "keys": ["$authenticated_source"]}],
        }
    ]
    return {
        "version": 1,
        "max_forward_hops": 4,
        "unknown_fields": "drop_and_count",
        "semantic_resource_instance_key": "defenseclaw.instance.id",
        "forward_instance_key": "defenseclaw.telemetry.forward.instance_id",
        "forward_destination_key": "defenseclaw.telemetry.forward.destination",
        "forward_hop_count_key": "defenseclaw.telemetry.forward.hop_count",
        "record_id_key": "defenseclaw.record.id",
        "scope_name": "defenseclaw.telemetry",
        "scope_schema_url": "https://defenseclaw.io/schemas/telemetry/v8",
        "resource_schema_url": "https://opentelemetry.io/schemas/1.42.0",
        "alias_sets": aliases,
        "source_normalizers": copy.deepcopy(canonical_inbound["source_normalizers"]),
        "source_projection_plans": fixture_projection_plans,
        "binding_classes": binding_classes,
        "derivation_attachments": [
            {
                "id": "otlp.genai.duration.span.v1",
                "parent_class": "otlp.genai.span.operation.v1",
                "family": "metric.gen_ai.client.operation.duration",
                "strategy": "elapsed-time-v1",
            }
        ],
        "fixture_policy": {
            "encodings": ["json", "protobuf"],
            "classes": ["positive", "negative", "single_fault"],
            "protobuf_representation": "canonical_protojson",
        },
    }


def _fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    (root / ".git").mkdir(parents=True)
    (root / "internal/observability").mkdir(parents=True)
    telemetry = root / "schemas/telemetry/v8"
    upstream = telemetry / "upstream"
    upstream.mkdir(parents=True)
    compatibility_schema_source = ROOT / "schemas/telemetry/v8/compatibility/v7-exporter-selection.schema.json"
    compatibility_schema_target = telemetry / "compatibility/v7-exporter-selection.schema.json"
    compatibility_schema_target.parent.mkdir(parents=True)
    compatibility_schema_target.write_bytes(compatibility_schema_source.read_bytes())
    inventory_source = ROOT / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory_target = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory_target.parent.mkdir(parents=True)
    inventory = yaml.safe_load(inventory_source.read_text(encoding="utf-8"))
    registry_source = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    for instrument_name, contract in inventory["classes"]["emitted_metrics"]["items"].items():
        contract["labels"] = []
        contract["callsites"] = ["internal/telemetry/metrics.go:1"]
        contract["dropped_by_current_global_v8_gate"] = []
        contract["empty_labels_reason"] = "Fixture producer emits no instrument labels."
    for instrument_name in ("gen_ai.client.token.usage", "gen_ai.client.operation.duration"):
        contract = inventory["classes"]["emitted_metrics"]["items"][instrument_name]
        contract["labels"] = ["defenseclaw.test.name"]
        contract.pop("empty_labels_reason")
    fixture_selection = inventory["classes"]["v7_exporter_selection"]
    fixture_selection["collection"] = {
        "always": {
            "logs": {"derive_buckets_from": "local_log_producers"},
            "traces": [],
            "metrics": [],
        },
        "otel.logs": {
            "logs": {"derive_buckets_from": "catalog_v1"},
            "traces": [],
            "metrics": [],
        },
        "otel.traces": {
            "logs": [],
            "traces": {"derive_buckets_from": "catalog_v1"},
            "metrics": [],
        },
        "otel.metrics": {
            "logs": [],
            "traces": [],
            "metrics": {"derive_buckets_from": "emitted_metrics"},
        },
    }
    fixture_selection["exporters"]["generic_otlp"] = {
        "logs": {"derive_buckets_from": "catalog_v1"},
        "traces": {"derive_event_names_from": "span_families"},
        "metrics": {"derive_buckets_from": "emitted_metrics"},
    }
    fixture_selection["exporters"]["galileo"] = {
        "traces": [{"event_names": ["span.model.chat"]}],
    }
    fixture_selection["exporters"]["local_observability"] = {
        "logs": {"derive_buckets_from": "catalog_v1"},
        "traces": {"derive_event_names_from": "span_families"},
        "metrics": {"derive_buckets_from": "emitted_metrics"},
    }
    fixture_selection["features"] = {
        "otel_individual_findings": [{"event_names": ["diagnostic.message"]}],
    }
    fixture_selection["span_filter_operations"] = {
        "chat": {"required_attributes": [], "selectors": [{"event_names": ["span.model.chat"]}]},
    }
    _write_yaml(inventory_target, inventory)
    lock_dependencies: list[dict[str, Any]] = []
    for dependency_id, repository, version, profile, revision, filename, attribute in DEPENDENCIES:
        payload = _snapshot(dependency_id, repository, revision, attribute)
        (upstream / filename).write_bytes(payload)
        lock_dependencies.append(
            {
                "id": dependency_id,
                "repository": repository,
                "version": version,
                "profile_id": profile,
                "revision": revision,
                "snapshot": {
                    "path": f"schemas/telemetry/v8/upstream/{filename}",
                    "format": "defenseclaw-selected-semconv-v1",
                    "sha256": _sha256(payload),
                },
            }
        )
        if dependency_id == "otel_genai":
            structural_inputs = []
            for upstream_path, relative_path, digest in (
                (
                    "model/gen-ai/gen-ai-input-messages.json",
                    "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
                    "model/gen-ai/gen-ai-input-messages.json",
                    "034fcd8c87f1e013f3a5a5018503210e2bee4d2499c361823b96e906d40a50ad",
                ),
                (
                    "model/gen-ai/gen-ai-output-messages.json",
                    "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
                    "model/gen-ai/gen-ai-output-messages.json",
                    "a825a6c0cc1b7b22fdbfb9488d8dc3a318be3897ef6d3dbae01a10297bb6e569",
                ),
                (
                    "model/gen-ai/gen-ai-tool-call-arguments.json",
                    "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
                    "model/gen-ai/gen-ai-tool-call-arguments.json",
                    "73607a8e8d9e84393475ef460108c59dbb9e1d2ddc0d0177fce6f735a62367ea",
                ),
                (
                    "model/gen-ai/gen-ai-tool-call-result.json",
                    "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
                    "model/gen-ai/gen-ai-tool-call-result.json",
                    "44eb4a93b05eea7da14489f1d253814c6429772d1fe869f8f6fc1749d7593412",
                ),
            ):
                source = ROOT / relative_path
                target = root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
                assert _sha256(target.read_bytes()) == digest
                structural_inputs.append({"upstream_path": upstream_path, "path": relative_path, "sha256": digest})
            lock_dependencies[-1]["structural_inputs"] = structural_inputs
    _write_yaml(
        telemetry / "semconv.lock.yaml",
        {"schema_version": 1, "dependencies": lock_dependencies},
    )
    metric_profile = copy.deepcopy(registry_source["metric_compatibility_profiles"])
    _write_yaml(
        telemetry / "registry.yaml",
        {
            "schema_version": 1,
            "registry_version": 1,
            "bucket_catalog_version": 1,
            "imports": ["genai.yaml", "security.yaml", "operations.yaml"],
            "dependency_lock": "schemas/telemetry/v8/semconv.lock.yaml",
            "examples": "examples.yaml",
            "inbound_bindings": _fixture_inbound_bindings(),
            "semantic_profiles": [
                {
                    "id": "defenseclaw-genai-rich-v1",
                    "trace_schema_version": "defenseclaw-trace-v1",
                    "gen_ai_semconv_profile": DEPENDENCIES[1][3],
                    "openinference_profile": DEPENDENCIES[2][3],
                    "galileo_compatibility_profile": "galileo-rich-v2",
                }
            ],
            "normalizers": registry_source["normalizers"],
            "conditions": registry_source["conditions"],
            "mandatory_rule_catalog": registry_source["mandatory_rule_catalog"],
            "structured_types": registry_source["structured_types"],
            "structured_bindings": registry_source["structured_bindings"],
            "go_symbol_policy": registry_source["go_symbol_policy"],
            "value_catalogs": registry_source["value_catalogs"],
            "structural_contract": registry_source["structural_contract"],
            "metric_defaults": registry_source["metric_defaults"],
            "metric_compatibility_profiles": metric_profile,
        },
    )
    for name, value in _domain_sources().items():
        _write_yaml(telemetry / name, value)
    _write_yaml(
        telemetry / "examples.yaml",
        {
            "schema_version": 1,
            "examples": [
                {
                    "id": "valid-model-chat",
                    "valid": True,
                    "signal": "traces",
                    "family": "span.model.chat",
                    "description": "Small valid model trace.",
                    "builder_context": {
                        "inheritance": {"mode": "explicit"},
                        "occurrence": {
                            "timestamp": "2026-07-03T12:00:00Z",
                            "record_id": "fixture-record-1",
                        },
                        "condition_facts": {
                            "connector_known": False,
                            "operation_terminal": False,
                        },
                        "mandatory_facts": {},
                    },
                    "record": {
                        "schema_version": 1,
                        "bucket_catalog_version": 1,
                        "timestamp": "2026-07-03T12:00:00Z",
                        "record_id": "fixture-record-1",
                        "bucket": "model.io",
                        "signal": "traces",
                        "event_name": "span.model.chat",
                        "span_name": "chat chat",
                        "source": "gateway",
                        "correlation": {
                            "trace_id": "0123456789abcdef0123456789abcdef",
                            "span_id": "0123456789abcdef",
                        },
                        "provenance": {
                            "producer": "defenseclaw",
                            "binary_version": "8.0.0",
                            "registry_schema_version": 1,
                            "config_generation": 1,
                        },
                        "body": {
                            "kind": "CLIENT",
                            "start_time_unix_nano": 1,
                            "end_time_unix_nano": 2,
                            "flags": 256,
                            "attributes": {
                                "defenseclaw.bucket": "model.io",
                                "defenseclaw.span.family": "span.model.chat",
                                "defenseclaw.span.family_schema_version": 1,
                                "defenseclaw.source": "gateway",
                                "defenseclaw.config.generation": 1,
                                "gen_ai.operation.name": "chat",
                            },
                            "status": {"code": "OK"},
                            "resource": {
                                "schema_url": "https://opentelemetry.io/schemas/1.42.0",
                                "attributes": {"service.version": "8.0.0"},
                            },
                            "scope": {
                                "name": "defenseclaw.telemetry",
                                "version": "8.0.0",
                                "schema_url": "https://defenseclaw.io/schemas/telemetry/v8",
                                "attributes": {
                                    "defenseclaw.trace.schema_version": "defenseclaw-trace-v1",
                                    "defenseclaw.semantic_profile": "defenseclaw-genai-rich-v1",
                                },
                            },
                        },
                        "field_classes": {
                            "/kind": "metadata",
                            "/start_time_unix_nano": "metadata",
                            "/end_time_unix_nano": "metadata",
                            "/flags": "metadata",
                            "/attributes/defenseclaw.bucket": "metadata",
                            "/attributes/defenseclaw.span.family": "identifier",
                            "/attributes/defenseclaw.span.family_schema_version": "metadata",
                            "/attributes/defenseclaw.source": "identifier",
                            "/attributes/defenseclaw.config.generation": "metadata",
                            "/attributes/gen_ai.operation.name": "metadata",
                            "/status/code": "metadata",
                            "/resource/schema_url": "metadata",
                            "/resource/attributes/service.version": "metadata",
                            "/scope/name": "metadata",
                            "/scope/version": "metadata",
                            "/scope/schema_url": "metadata",
                            "/scope/attributes/defenseclaw.trace.schema_version": "metadata",
                            "/scope/attributes/defenseclaw.semantic_profile": "metadata",
                        },
                    },
                }
            ],
        },
    )
    return root


def _materialize_trace_attribute(root: Path, attribute: str, value: Any, field_class: str) -> None:
    """Keep the checked example valid when a test makes a trace attribute required."""
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    record["body"]["attributes"][attribute] = value
    record["field_classes"][f"/attributes/{attribute}"] = field_class
    _write_yaml(examples_path, examples)


def _run(root: Path, mode: str, *, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(OUTPUT_DRIVER), mode, "--root", str(root)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
    )


def _load_generator_module(name: str):
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_sibling_module_loader_rejects_foreign_preload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_generator_module("telemetry_registry_foreign_sibling_preload")
    name = "telemetry_go_output_coordinator"
    foreign = tmp_path / f"{name}.py"
    foreign.write_text("# stale foreign module\n", encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, foreign)
    assert spec is not None and spec.loader is not None
    existing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(existing)
    monkeypatch.setitem(sys.modules, name, existing)

    with pytest.raises(RuntimeError, match="foreign provenance"):
        module._load_sibling_module(name)


@pytest.mark.parametrize("unsafe", ["same-file-spoof", "missing-file", "directory", "missing-attribute"])
def test_sibling_module_loader_rejects_unsafe_preload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe: str,
) -> None:
    module = _load_generator_module(f"telemetry_registry_unsafe_sibling_preload_{unsafe}")
    name = "telemetry_go_output_coordinator"
    if unsafe == "same-file-spoof":
        existing = SimpleNamespace(__file__=str(GENERATOR.with_name(f"{name}.py").resolve()))
    elif unsafe == "missing-file":
        missing = tmp_path / "missing.py"
        existing = ModuleType(name)
        existing.__file__ = str(missing)
        existing.__spec__ = importlib.util.spec_from_file_location(name, missing)
    elif unsafe == "directory":
        directory = tmp_path / "not-a-module"
        directory.mkdir()
        existing = ModuleType(name)
        existing.__file__ = str(directory)
        existing.__spec__ = importlib.util.spec_from_file_location(name, directory)
    else:
        existing = ModuleType(name)
    monkeypatch.setitem(sys.modules, name, existing)

    with pytest.raises(RuntimeError, match="unsafe"):
        module._load_sibling_module(name)


def test_sibling_module_loader_reuses_same_file_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_generator_module("telemetry_registry_same_sibling_preload")
    name = "telemetry_go_output_coordinator"
    monkeypatch.delitem(sys.modules, name, raising=False)
    existing = module._load_sibling_module(name)

    assert isinstance(existing, ModuleType)
    assert module._load_sibling_module(name) is existing


@pytest.mark.parametrize("mode", ["package", "spec", "direct"])
def test_candidate_loader_uses_one_fresh_process_module_identity(mode: str) -> None:
    generator = GENERATOR.resolve()
    if mode == "package":
        cwd = ROOT
        load = "import scripts.generate_telemetry_registry as generator"
        prefix = "scripts."
    elif mode == "spec":
        cwd = ROOT / "cli/tests"
        load = f"""
import importlib.util
spec = importlib.util.spec_from_file_location("fresh_telemetry_generator", {str(generator)!r})
assert spec is not None and spec.loader is not None
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)
"""
        prefix = ""
    else:
        cwd = ROOT / "scripts"
        load = "import generate_telemetry_registry as generator"
        prefix = ""
    code = f"""
import sys
{load}
portable, go_renderer, coordinator = generator._load_candidate_renderers()
prefix = {prefix!r}
canonical = sys.modules[prefix + "telemetry_canonical_record"]
api = sys.modules[prefix + "telemetry_go_api_plan"]
fixtures = sys.modules[prefix + "telemetry_go_fixture_plan"]
producer = sys.modules[prefix + "telemetry_go_producer_plan"]
assert api.canonical_record_json is canonical.canonical_record_json
assert fixtures.canonical_record_json is canonical.canonical_record_json
assert portable.compile_go_api_plan is api.compile_go_api_plan
assert go_renderer.compile_go_fixture_plan is fixtures.compile_go_fixture_plan
assert go_renderer.compile_go_producer_plan is producer.compile_go_producer_plan
assert coordinator is sys.modules[prefix + "telemetry_go_output_coordinator"]
assert go_renderer.RenderedGoOutput is coordinator.RenderedGoOutput
assert go_renderer.GoFileDeclarationInventory is coordinator.GoFileDeclarationInventory
assert go_renderer.GoDeclarationKey is coordinator.GoDeclarationKey
assert "defenseclaw_telemetry_go_api_plan" not in sys.modules
opposite = "" if prefix else "scripts."
for leaf in (
    "telemetry_canonical_record",
    "telemetry_go_api_plan",
    "telemetry_go_fixture_plan",
    "telemetry_go_output_coordinator",
    "telemetry_go_producer_plan",
    "render_telemetry_registry_candidates",
    "render_telemetry_go",
):
    assert opposite + leaf not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("direction", ["package-then-direct", "direct-then-package", "package-then-renderer"])
def test_candidate_loader_reuses_first_valid_supported_namespace(direction: str) -> None:
    generator = GENERATOR.resolve()
    renderer = GENERATOR.with_name("render_telemetry_registry_candidates.py").resolve()
    if direction == "package-then-direct":
        setup = "import scripts.generate_telemetry_registry"
        action = f"""
spec = importlib.util.spec_from_file_location("mixed_direct_generator", {str(generator)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
"""
        assertion = (
            "assert module.runtime_assets is "
            "sys.modules['scripts.generate_telemetry_registry'].runtime_assets"
        )
    elif direction == "direct-then-package":
        setup = f"""
spec = importlib.util.spec_from_file_location("mixed_direct_generator", {str(generator)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
"""
        action = 'package_module = importlib.import_module("scripts.generate_telemetry_registry")'
        assertion = "assert package_module.runtime_assets is module.runtime_assets"
    else:
        setup = """
import scripts.telemetry_canonical_record
import scripts.telemetry_go_api_plan
"""
        action = f"""
spec = importlib.util.spec_from_file_location("mixed_direct_renderer", {str(renderer)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
"""
        assertion = (
            "assert module.compile_go_api_plan is sys.modules['scripts.telemetry_go_api_plan'].compile_go_api_plan"
        )
    code = f"""
import importlib
import importlib.util
import sys
{setup}
{action}
{assertion}
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("surface", ["file", "origin"])
def test_generator_loader_rejects_malformed_opposite_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    module = _load_generator_module(f"telemetry_registry_malformed_opposite_{surface}")
    leaf = "telemetry_go_api_plan"
    path = GENERATOR.with_name(f"{leaf}.py").resolve()
    # Force this load through the opposite supported namespace. A valid direct
    # identity may already exist when the entire CLI suite runs, in which case
    # the loader correctly reuses it without consulting the opposite identity.
    monkeypatch.delitem(sys.modules, leaf, raising=False)
    opposite = ModuleType(f"scripts.{leaf}")
    if surface == "file":
        opposite.__file__ = str(path)
        opposite.__spec__ = None
    else:
        opposite.__file__ = str(tmp_path / "missing.py")
        opposite.__spec__ = importlib.util.spec_from_file_location(f"scripts.{leaf}", path)
    monkeypatch.setitem(sys.modules, f"scripts.{leaf}", opposite)

    with pytest.raises(RuntimeError, match="unsafe"):
        module._load_sibling_module(leaf)


@pytest.mark.parametrize("surface", ["file", "origin"])
def test_candidate_direct_loader_rejects_malformed_opposite_identity(
    tmp_path: Path,
    surface: str,
) -> None:
    renderer = GENERATOR.with_name("render_telemetry_registry_candidates.py").resolve()
    canonical = GENERATOR.with_name("telemetry_canonical_record.py").resolve()
    malformed = (
        f"opposite.__file__ = {str(canonical)!r}\nopposite.__spec__ = None"
        if surface == "file"
        else (
            f"opposite.__file__ = {str(tmp_path / 'missing.py')!r}\n"
            f"opposite.__spec__ = importlib.util.spec_from_file_location("
            f"'scripts.telemetry_canonical_record', {str(canonical)!r})"
        )
    )
    code = f"""
import importlib.util
import sys
from types import ModuleType
opposite = ModuleType("scripts.telemetry_canonical_record")
{malformed}
sys.modules[opposite.__name__] = opposite
spec = importlib.util.spec_from_file_location("malformed_opposite_renderer", {str(renderer)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
except RuntimeError as exc:
    assert "foreign provenance" in str(exc)
else:
    raise AssertionError("candidate renderer accepted a malformed opposite identity")
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT / "cli/tests",
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


def _load_updater_module(name: str):
    if "generate_telemetry_registry" not in sys.modules:
        _load_generator_module("generate_telemetry_registry")
    spec = importlib.util.spec_from_file_location(name, UPDATER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _install_synthetic_candidate_renderers(
    module: ModuleType,
    ir: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    build_error: Exception | None = None,
) -> tuple[object, list[tuple[str, object]]]:
    class CandidateRenderError(ValueError):
        pass

    class GoRenderError(RuntimeError):
        pass

    class GoOutputPreflightError(RuntimeError):
        pass

    index = object()
    calls: list[tuple[str, object]] = []

    def build(view: object) -> object:
        calls.append(("build", view))
        if build_error is not None:
            raise build_error
        return index

    portable_paths = {
        *module.PORTABLE_STATIC_OUTPUT_PATHS,
        *(
            f"schemas/telemetry/generated/examples/{'valid' if example.valid else 'invalid'}/{example.id}.json"
            for example in ir.examples
        ),
        *(f"schemas/telemetry/generated/otlp-fixtures/cases/{example.id}.json" for example in ir.examples),
    }

    def portable_artifact(path: str) -> Any:
        if path == "schemas/telemetry/generated/compatibility/v7-exporter-selection.json":
            document = module._v7_exporter_selection_document(
                ir.v7_exporter_selection,
                schema_version=ir.schema_version,
                registry_version=ir.registry_version,
                materialized_view_sha256=ir.materialized_view.typed_canonical_json_sha256,
            )
            payload = (json.dumps(document, sort_keys=True) + "\n").encode()
        else:
            payload = b'{"x-defenseclaw-generated":true}\n'
        return SimpleNamespace(
            path=path,
            payload=payload,
            ownership_marker=b'"x-defenseclaw-generated"',
            mode=0o644,
        )

    def render_portable(observed: object) -> dict[str, Any]:
        calls.append(("portable", observed))
        return {path: portable_artifact(path) for path in portable_paths}

    portable = SimpleNamespace(
        CANDIDATE_AUTHORITY=module.GO_CANDIDATE_AUTHORITY,
        CandidateRenderError=CandidateRenderError,
        build_candidate_render_index=build,
        render_candidate_artifacts_from_index=render_portable,
    )
    go_render = SimpleNamespace(
        outputs=("rendered-go-inventory",),
        declaration_inventory=("declaration-inventory",),
        expected_declaration_keys=("declaration-key",),
        materialized_view_sha256=ir.materialized_view.typed_canonical_json_sha256,
        candidate_render_index_sha256="2" * 64,
        go_symbol_table_sha256="3" * 64,
    )

    def render_go(observed: object) -> Any:
        calls.append(("go", observed))
        return go_render

    go_renderer = SimpleNamespace(GoRenderError=GoRenderError, render_go_candidate=render_go)
    go_outputs = tuple(
        SimpleNamespace(
            path=path,
            payload=(b"// Code generated by DefenseClaw telemetry registry; DO NOT EDIT.\npackage observability\n"),
            marker=b"// Code generated by DefenseClaw telemetry registry; DO NOT EDIT.",
            mode=0o644,
        )
        for path in module.GO_CANDIDATE_OUTPUT_PATHS
    )
    metadata = SimpleNamespace(
        format_version=1,
        materialized_view_sha256=ir.materialized_view.typed_canonical_json_sha256,
        candidate_render_index_sha256="2" * 64,
        go_symbol_table_sha256="3" * 64,
        declaration_inventory_sha256="4" * 64,
        output_inventory_sha256="5" * 64,
        manifest_sha256="6" * 64,
    )

    def preflight(*args: Any, **kwargs: Any) -> Any:
        calls.append(("preflight", args[0]))
        assert args[0] is go_render.outputs
        assert args[1] is go_render.declaration_inventory
        assert kwargs["expected_declaration_keys"] is go_render.expected_declaration_keys
        return SimpleNamespace(outputs=go_outputs, metadata=metadata)

    coordinator = SimpleNamespace(
        EXACT_GO_OUTPUT_PATHS=module.GO_CANDIDATE_OUTPUT_PATHS,
        GoOutputPreflightError=GoOutputPreflightError,
        preflight_go_outputs=preflight,
    )
    monkeypatch.setattr(module, "_load_candidate_renderers", lambda: (portable, go_renderer, coordinator))
    return index, calls


def test_render_outputs_builds_one_index_and_fans_out_the_same_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_single_candidate_index")
    ir = module.compile_registry(root)
    index, calls = _install_synthetic_candidate_renderers(module, ir, monkeypatch)

    outputs = module.render_outputs(ir)

    assert [name for name, _ in calls] == ["build", "portable", "go", "preflight"]
    assert calls[1][1] is index
    assert calls[2][1] is index
    expected_portable = module._expected_portable_output_paths(ir)
    assert set(outputs) == {
        *(Path(path) for path in expected_portable if module._is_repository_output(path)),
        *(Path(path) for path in module.GO_CANDIDATE_OUTPUT_PATHS),
    }


def test_unexpected_renderer_failure_is_bounded_and_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_bounded_renderer_error")
    ir = module.compile_registry(root)
    secret = "/private/secret/customer-source-value"
    _install_synthetic_candidate_renderers(module, ir, monkeypatch, build_error=RuntimeError(secret))

    with pytest.raises(module.RegistryError) as raised:
        module.render_outputs(ir)

    assert str(raised.value) == "candidate telemetry rendering failed: unexpected candidate renderer failure"
    assert secret not in str(raised.value)


@pytest.fixture(scope="module")
def real_candidate_outputs() -> tuple[ModuleType, dict[Path, bytes]]:
    module = _load_generator_module("telemetry_registry_real_candidate_outputs")
    outputs = module.render_outputs(module.compile_registry(ROOT))
    return module, outputs


def test_real_candidate_outputs_map_to_one_exact_physical_inventory(
    real_candidate_outputs: tuple[ModuleType, dict[Path, bytes]],
) -> None:
    module, outputs = real_candidate_outputs
    physical = module._physical_outputs(outputs)

    assert set(physical) == module.REPOSITORY_PHYSICAL_OUTPUT_PATHS
    assert {path.as_posix() for path in outputs} == {
        *module.runtime_assets.LOGICAL_TO_ENCODED,
        *module.GO_CANDIDATE_OUTPUT_PATHS,
    }
    for logical, encoded in module.runtime_assets.LOGICAL_TO_ENCODED.items():
        assert module.runtime_assets.decode_canonical_gzip(physical[encoded]) == outputs[Path(logical)]
    for path in module.GO_CANDIDATE_OUTPUT_PATHS:
        assert physical[path] == outputs[Path(path)]


def test_real_candidate_direct_write_check_and_retired_cleanup(
    tmp_path: Path,
    real_candidate_outputs: tuple[ModuleType, dict[Path, bytes]],
) -> None:
    module, outputs = real_candidate_outputs
    root = tmp_path / "repository"
    root.mkdir()
    for relative in module.RETIRED_REPOSITORY_OUTPUT_PATHS:
        retired = root / relative
        retired.parent.mkdir(parents=True, exist_ok=True)
        retired.write_text("retired\n", encoding="utf-8")
    module.write_outputs(root, outputs)

    module.check_outputs(root, outputs)
    assert all(not (root / relative).exists() for relative in module.RETIRED_REPOSITORY_OUTPUT_PATHS)
    for relative, payload in module._physical_outputs(outputs).items():
        assert (root / relative).read_bytes() == payload


def test_unowned_internal_generated_go_is_rejected_by_check_and_write(
    tmp_path: Path,
    real_candidate_outputs: tuple[ModuleType, dict[Path, bytes]],
) -> None:
    module, outputs = real_candidate_outputs
    root = tmp_path / "repository"
    root.mkdir()
    module.write_outputs(root, outputs)
    extra = root / "internal/observability/zz_generated_telemetry_unowned.go"
    extra.write_text(
        "// Code generated by DefenseClaw telemetry registry; DO NOT EDIT.\npackage observability\n",
        encoding="utf-8",
    )
    with pytest.raises(module.RegistryError, match="extra=internal/observability/zz_generated_telemetry_unowned.go"):
        module.check_outputs(root, outputs)
    with pytest.raises(module.RegistryError, match="generated output drift: extra="):
        module.write_outputs(root, outputs)
    assert extra.is_file()


def _explicit_builder_context(
    record: Mapping[str, Any],
    *,
    condition_facts: Mapping[str, bool] | None = None,
    mandatory_facts: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    return {
        "inheritance": {"mode": "explicit"},
        "occurrence": {
            "timestamp": record["timestamp"],
            "record_id": record["record_id"],
        },
        "condition_facts": dict(condition_facts or {}),
        "mandatory_facts": dict(mandatory_facts or {}),
    }


def _exact_base_builder_context(base_example: str) -> dict[str, Any]:
    return {
        "inheritance": {
            "mode": "exact_base",
            "base_example": base_example,
        }
    }


def _mutate_snapshot(root: Path, dependency_id: str, mutate: Any) -> None:
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    dependency = next(item for item in lock["dependencies"] if item["id"] == dependency_id)
    snapshot_path = root / dependency["snapshot"]["path"]
    snapshot = json.loads(snapshot_path.read_bytes())
    mutate(snapshot)
    snapshot["attributes"].sort(key=lambda item: item["id"])
    snapshot["selection"]["attribute_ids_sha256"] = _sha256(
        json.dumps(
            [item["id"] for item in snapshot["attributes"]],
            separators=(",", ":"),
        ).encode()
    )
    payload = (json.dumps(snapshot, indent=2) + "\n").encode()
    snapshot_path.write_bytes(payload)
    dependency["snapshot"]["sha256"] = _sha256(payload)
    _write_yaml(lock_path, lock)


def test_write_check_is_deterministic_and_offline(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_direct_writer_determinism")
    first = _run(root, "--write")
    assert first.returncode == 0, first.stderr
    first_bytes = {
        relative: (root / relative).read_bytes()
        for relative in module.REPOSITORY_PHYSICAL_OUTPUT_PATHS
    }

    offline = dict(os.environ)
    offline.update(
        {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
    )
    checked = _run(root, "--check", environment=offline)
    assert checked.returncode == 0, checked.stderr
    second = _run(root, "--write", environment=offline)
    assert second.returncode == 0, second.stderr
    assert first_bytes == {
        relative: (root / relative).read_bytes()
        for relative in module.REPOSITORY_PHYSICAL_OUTPUT_PATHS
    }
    for logical, encoded in module.runtime_assets.LOGICAL_TO_ENCODED.items():
        decoded = module.runtime_assets.decode_canonical_gzip(first_bytes[encoded])
        document = json.loads(decoded)
        assert document["artifact"] == logical
        assert len(document["materialized_view_sha256"]) == 64


def test_snapshot_tampering_fails_without_partial_output(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    assert _run(root, "--write").returncode == 0
    module = _load_generator_module("telemetry_registry_snapshot_no_partial_output")
    before = {
        relative: (root / relative).read_bytes()
        for relative in module.REPOSITORY_PHYSICAL_OUTPUT_PATHS
    }
    snapshot = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    snapshot.write_bytes(snapshot.read_bytes() + b" ")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "snapshot digest mismatch" in result.stderr
    assert before == {
        relative: (root / relative).read_bytes()
        for relative in module.REPOSITORY_PHYSICAL_OUTPUT_PATHS
    }


def test_selected_otel_ownership_must_not_overlap(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.operation.name")
        target["id"] = "service.version"

    _mutate_snapshot(root, "otel_genai", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "duplicate selected ownership" in result.stderr


def test_selected_otel_inventory_must_equal_authored_extensions(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.operation.name")
        target["id"] = "gen_ai.unused"

    _mutate_snapshot(root, "otel_genai", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "selected OTel semantic-convention attributes differ" in result.stderr


def test_openinference_snapshot_is_exact_runtime_vocabulary(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        target = next(item for item in snapshot["attributes"] if item["id"] == "input.value")
        target["id"] = "session.id"

    _mutate_snapshot(root, "openinference", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "OpenInference runtime vocabulary mismatch" in result.stderr


def test_absent_selected_attribute_cannot_satisfy_authored_extension(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["attributes"][0]["ref"] = "gen_ai.legacy.000"
    document["attribute_extensions"][0]["ref"] = "gen_ai.legacy.000"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "selected OTel semantic-convention attributes differ" in result.stderr


def test_openinference_source_tuple_tamper_fails_with_recomputed_digest(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)

    def mutate(snapshot: dict[str, Any]) -> None:
        snapshot["source_files"][0]["path"] = "python/instrumentation/decoy.py"

    _mutate_snapshot(root, "openinference", mutate)
    result = _run(root, "--write")

    assert result.returncode == 1
    assert "non-authoritative OpenInference source" in result.stderr


def test_unknown_attribute_reference_fails_closed(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["attributes"][0]["ref"] = "gen_ai.unknown"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown attribute reference" in result.stderr
    assert not (root / "schemas/telemetry/generated").exists()


def test_producer_identity_must_match_canonical_family(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["producer_mappings"][0]["default_identity"]["bucket"] = "platform.health"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "family bucket mismatch" in result.stderr


def test_only_legacy_audit_identity_may_be_compatibility_only(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    identity = document["producer_mappings"][0]["default_identity"]
    identity.pop("family")
    identity["compatibility_only"] = True
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "must use legacy.audit.*" in result.stderr


def test_semantic_profile_tuple_is_immutable(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["semantic_profiles"][0]["galileo_compatibility_profile"] = "galileo-rich-v3"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "profile tuple does not match" in result.stderr


def test_upstream_attribute_extension_is_required_exactly_once(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    expected_missing = sorted(extension["ref"] for extension in document["attribute_extensions"])
    document["attribute_extensions"] = []
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert (
        "selected OTel semantic-convention attributes differ from authored extension closure "
        f"missing={expected_missing!r} extra=[]"
    ) in result.stderr


@pytest.mark.parametrize(
    ("field_class", "cardinality", "expected"),
    [
        ("metadata", "high", "high-cardinality label attribute defenseclaw.test.name is forbidden"),
        ("content", "bounded", "unsafe label attribute defenseclaw.test.name"),
        ("credential", "low", "unsafe label attribute defenseclaw.test.name"),
    ],
)
def test_metric_labels_reject_high_cardinality_or_sensitive_classes(
    tmp_path: Path,
    field_class: str,
    cardinality: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    genai_path = root / "schemas/telemetry/v8/genai.yaml"
    genai = yaml.safe_load(genai_path.read_text(encoding="utf-8"))
    genai["attributes"][0]["field_class"] = field_class
    genai["attributes"][0]["cardinality"] = cardinality
    _write_yaml(genai_path, genai)
    operations_path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(operations_path.read_text(encoding="utf-8"))
    metric_group = next(
        group
        for group in operations["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric_group["attributes"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
    metric_group["metric"].pop("empty_labels_reason")
    _write_yaml(operations_path, operations)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    contract = inventory["classes"]["emitted_metrics"]["items"]["defenseclaw.activity.diff_entries"]
    contract["labels"] = ["defenseclaw.test.name"]
    contract.pop("empty_labels_reason")
    _write_yaml(inventory_path, inventory)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_non_upstream_genai_name_requires_projection_alias_lifecycle(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    alias = copy.deepcopy(document["attributes"][0])
    alias.update(
        {
            "id": "gen_ai.test.legacy",
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
        }
    )
    document["attributes"].append(alias)
    _write_yaml(path, document)
    result = _run(root, "--write")
    assert result.returncode == 1
    assert "must be a projection-only alias" in result.stderr

    alias.update(
        {
            "projection_only": True,
            "alias_of": "defenseclaw.test.name",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
            "legacy_bindings": [{"source": "fixture", "disposition": "compatibility_alias"}],
        }
    )
    document["attributes"][-1] = alias
    _write_yaml(path, document)
    result = _run(root, "--write")
    assert result.returncode == 0, result.stderr


def test_span_events_use_public_names_not_internal_group_ids(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["x-defenseclaw"]["events"] = ["event.guardrail.decision"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "public names without event. prefix" in result.stderr


@pytest.mark.parametrize(
    "example_id",
    [
        pytest.param("Uppercase", id="uppercase"),
        pytest.param("a/b", id="slash"),
        pytest.param("a/../b", id="traversal"),
        pytest.param("a:b", id="colon"),
        pytest.param("\u00e9xample", id="non-ascii-nfc"),
        pytest.param("a" * 129, id="overlength"),
    ],
)
def test_compiler_rejects_nonportable_example_ids(tmp_path: Path, example_id: str) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["examples"][0]["id"] = example_id
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "examples[0].id: invalid string syntax" in result.stderr


@pytest.mark.parametrize(
    "example_id",
    [
        pytest.param("con", id="console"),
        pytest.param("prn", id="printer"),
        pytest.param("aux", id="auxiliary"),
        pytest.param("nul", id="null-device"),
        pytest.param("com1", id="serial-lower-bound"),
        pytest.param("com9", id="serial-upper-bound"),
        pytest.param("lpt1", id="parallel-lower-bound"),
        pytest.param("lpt9", id="parallel-upper-bound"),
    ],
)
def test_compiler_rejects_platform_reserved_example_ids(tmp_path: Path, example_id: str) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["examples"][0]["id"] = example_id
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "examples[0].id: platform-reserved example id" in result.stderr


def test_compiler_rejects_exact_example_id_collisions(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["examples"].append(copy.deepcopy(document["examples"][0]))
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "examples[1].id: duplicate example" in result.stderr


def test_invalid_top_level_example_requires_derived_mutation(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["examples"].append(
        {
            "id": "legacy-audit-invalid",
            "valid": False,
            "signal": "logs",
            "description": "Producer-only compatibility identity is not a family.",
            "builder_context": {},
            "record": {"event_name": "legacy.audit.scan"},
            "expected_error": "unknown_family",
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "base_example, and mutation" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("op", "remove"),
            "value: required for add/replace and forbidden for remove",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].pop("value"),
            "value: required for add/replace and forbidden for remove",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "record/event_name"),
            "must be an RFC6901 pointer",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "/description"),
            "root must be signal, family, or record",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "/builder_context/inheritance/mode"),
            "root must be signal, family, or record",
        ),
        (
            lambda invalid: invalid["mutation"]["changes"][0].__setitem__("path", "/record/event_name~2invalid"),
            "invalid RFC6901 escape",
        ),
        (
            lambda invalid: invalid["record"].__setitem__("event_name", "another.invalid.name"),
            "derived vector does not equal checked-in invalid example",
        ),
        (
            lambda invalid: invalid.__setitem__("base_example", "not.an.earlier.valid.example"),
            "must reference an earlier valid example",
        ),
    ],
)
def test_invalid_example_mutation_grammar_is_mechanical_and_exact(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["event_name"] = "invalid.event.name"
    invalid = {
        "id": "model-chat-invalid-event-name",
        "valid": False,
        "signal": "traces",
        "family": "span.model.chat",
        "description": "A mechanically derived invalid event-name vector.",
        "record": invalid_record,
        "expected_error": "family_event_name_mismatch",
        "base_example": valid["id"],
        "builder_context": {
            "inheritance": {"mode": "exact_base", "base_example": valid["id"]},
        },
        "mutation": {
            "kind": "family_event_name_mismatch",
            "changes": [
                {
                    "op": "replace",
                    "path": "/record/event_name",
                    "value": "invalid.event.name",
                }
            ],
        },
    }
    mutation(invalid)
    document["examples"].append(invalid)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_direct_upstream_bytes_type_compiles_losslessly(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    attribute = "gen_ai.fixture.bytes"

    def mutate(snapshot: dict[str, Any]) -> None:
        target = copy.deepcopy(
            next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.operation.name")
        )
        target["id"] = attribute
        target["allowed_types"] = ["bytes"]
        snapshot["attributes"].append(target)

    _mutate_snapshot(root, "otel_genai", mutate)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["attribute_extensions"].append(
        {
            "ref": attribute,
            "field_class": "metadata",
            "sensitivity": "safe",
            "cardinality": "low",
            "normalization": {"id": "bounded-v1"},
        }
    )
    domain["groups"][0]["attributes"].append({"ref": attribute, "requirement_level": "optional"})
    _write_yaml(domain_path, domain)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_metric_string_label_rejects_disallowed_normalizer(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["attributes"][0]["normalization"] = {"id": "digest-v1"}
    _write_yaml(domain_path, domain)
    operations_path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(operations_path.read_text(encoding="utf-8"))
    metric_group = next(
        group
        for group in operations["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric_group["attributes"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
    metric_group["metric"].pop("empty_labels_reason")
    _write_yaml(operations_path, operations)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    contract = inventory["classes"]["emitted_metrics"]["items"]["defenseclaw.activity.diff_entries"]
    contract["labels"] = ["defenseclaw.test.name"]
    contract.pop("empty_labels_reason")
    _write_yaml(inventory_path, inventory)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "uses unbounded normalizer digest-v1" in result.stderr


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("instrument_type", "summary", "instrument_type: unsupported value"),
        ("value_type", "float32", "value_type: unsupported value"),
        ("temporality", "sometimes", "temporality: unsupported value"),
    ],
)
def test_metric_vocabulary_is_closed(
    tmp_path: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    metric_group = next(group for group in document["groups"] if group["type"] == "metric")
    metric_group["metric"][field] = value
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("instrument_type", "gauge", "instrument_type 'gauge' differs from legacy inventory"),
        ("unit", "widgets", "unit 'widgets' differs from legacy inventory"),
    ],
)
def test_metric_type_and_unit_match_legacy_inventory(
    tmp_path: Path,
    field: str,
    value: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    metric_group = next(
        group
        for group in document["groups"]
        if group.get("metric", {}).get("instrument_name") == "defenseclaw.activity.diff_entries"
    )
    metric_group["metric"][field] = value
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_generated_only_metric_does_not_require_legacy_inventory_duplication(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    source = next(group for group in document["groups"] if group["type"] == "metric")
    additive = copy.deepcopy(source)
    additive["id"] = "metric.defenseclaw.additive"
    additive["metric"]["instrument_name"] = "defenseclaw.additive"
    document["groups"].append(additive)
    _write_yaml(path, document)

    module = _load_generator_module("telemetry_registry_generated_only_metric")
    ir = module.compile_registry(root)

    instruments = {group.instrument_name for domain in ir.domains for group in domain.groups if group.type == "metric"}
    assert "defenseclaw.additive" in instruments
    inventory = yaml.safe_load(
        (root / "docs/design/observability-v8/current-state-inventory.yaml").read_text(encoding="utf-8"),
    )
    assert "defenseclaw.additive" not in inventory["classes"]["emitted_metrics"]["items"]


@pytest.mark.parametrize(
    ("instrument", "boundaries", "expected"),
    [
        ("defenseclaw.activity.total", [1, 2], "allowed only for histograms"),
        ("gen_ai.client.operation.duration", [1, 1], "strictly ascending"),
        ("gen_ai.client.operation.duration", [1, float("nan")], "expected finite number"),
        ("gen_ai.client.operation.duration", [True, 2], "expected finite number"),
    ],
)
def test_metric_boundaries_are_histogram_only_finite_and_ascending(
    tmp_path: Path,
    instrument: str,
    boundaries: list[object],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    for domain_name in ("genai", "security", "operations"):
        path = root / f"schemas/telemetry/v8/{domain_name}.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = next(
            (group for group in document["groups"] if group.get("metric", {}).get("instrument_name") == instrument),
            None,
        )
        if target is not None:
            target["metric"]["boundaries"] = boundaries
            _write_yaml(path, document)
            break
    else:
        raise AssertionError(f"fixture metric missing: {instrument}")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("field_type", "normalization"),
    [
        ("boolean[]", {"id": "identity-v1"}),
        (
            "int64[]",
            {"id": "numeric-range-v1", "overrides": {"min": 0, "max": 10}},
        ),
    ],
)
def test_numeric_and_boolean_arrays_require_explicit_max_items(
    tmp_path: Path,
    field_type: str,
    normalization: dict[str, Any],
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = copy.deepcopy(document["attributes"][0])
    attribute.update(
        {
            "id": "defenseclaw.test.array",
            "type": field_type,
            "examples": [[]],
            "normalization": normalization,
        }
    )
    document["attributes"].append(attribute)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "arrays require an explicit max_items bound" in result.stderr

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attributes"][-1]["normalization"].setdefault("overrides", {})["max_items"] = 16
    _write_yaml(path, document)
    result = _run(root, "--write")
    assert result.returncode == 0, result.stderr


def test_scalar_normalization_rejects_min_items(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = next(
        item
        for item in document["attributes"]
        if item["type"] == "string" and item["normalization"]["id"] == "bounded-v1"
    )
    attribute["normalization"].setdefault("overrides", {})["min_items"] = 2
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "min_items requires an array or structured value" in result.stderr


def test_polymorphic_json_normalization_rejects_min_items_above_one() -> None:
    module = _load_generator_module("telemetry_registry_polymorphic_min_items")
    normalization = module.NormalizationIR(
        "structured-content-v1",
        {"min_items": 2},
        {
            "min_items": 2,
            "max_items": 256,
            "max_utf8_bytes": 65536,
            "max_item_utf8_bytes": 4096,
            "max_depth": 8,
            "max_properties": 256,
        },
        None,
    )

    with pytest.raises(module.RegistryError, match="unsupported for polymorphic JSON"):
        module._validate_normalization_compatibility(
            normalization,
            ("canonical_json",),
            "any_value",
            "test.normalization",
        )


@pytest.mark.parametrize(
    ("constraints", "expected"),
    [
        ({"pattern": "text"}, "pattern constraint is incompatible"),
        ({"min_items": 2}, "min_items greater than one is unsupported"),
    ],
)
def test_any_value_per_use_constraints_reject_scalar_unsafe_rules(
    tmp_path: Path,
    constraints: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module(f"telemetry_registry_any_value_{next(iter(constraints))}")
    ir = module.compile_registry(root)
    group = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = module.AttributeUseIR("test.any_value", "attributes", "optional", None, constraints)
    group = dataclasses.replace(group, attribute_uses=(use,))
    normalization = module.NormalizationIR(
        "structured-content-v1",
        {},
        {
            "max_items": 256,
            "max_utf8_bytes": 65536,
            "max_item_utf8_bytes": 4096,
            "max_depth": 8,
            "max_properties": 256,
        },
        None,
    )
    extension = module.AttributeExtensionIR(
        "test.any_value",
        "content",
        "sensitive",
        "high",
        normalization,
    )
    snapshot = module.SnapshotAttribute(
        "test.any_value",
        (),
        "any_value",
        "development",
        "fixture",
        "fixture#test.any_value",
        (),
        False,
    )

    with pytest.raises(module.RegistryError, match=expected):
        module._validate_attribute_use_constraints(
            {group.id: group},
            {},
            {extension.ref: extension},
            {snapshot.id: ("otel_genai", snapshot)},
        )


def test_normalization_enum_members_match_attribute_type(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = next(item for item in document["attributes"] if item["normalization"]["id"] == "enum-v1")
    attribute["normalization"]["overrides"]["enum"] = [1]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "member type is incompatible with attribute types" in result.stderr


@pytest.mark.parametrize(
    ("constraints", "expected"),
    [
        ({"pattern": "(?=chat)"}, "outside the portable RE2 subset"),
        ({"min": 1}, "numeric constraint is incompatible"),
        ({"max_utf8_bytes": 8192}, "max_utf8_bytes weakens normalization"),
        ({"enum": [True]}, "constraint enum type is incompatible"),
    ],
)
def test_per_use_constraints_are_typed_portable_and_restrictive(
    tmp_path: Path,
    constraints: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["attributes"][0]["constraints"] = constraints
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param(r"a++", id="possessive-plus"),
        pytest.param(r"a*+", id="possessive-star"),
        pytest.param(r"a?+", id="possessive-optional"),
        pytest.param(r"a{1}+", id="possessive-exact-count"),
        pytest.param(r"a{1,2}+", id="possessive-count-range"),
        pytest.param(r"a{,3}", id="python-missing-lower-bound"),
        pytest.param(r"a{1001}", id="go-repetition-exact-limit"),
        pytest.param(r"a{1,1001}", id="go-repetition-upper-limit"),
        pytest.param(r"\d+", id="unicode-digit"),
        pytest.param(r"\D+", id="inverse-unicode-digit"),
        pytest.param(r"\w+", id="unicode-word"),
        pytest.param(r"\W+", id="inverse-unicode-word"),
        pytest.param(r"\s+", id="unicode-space"),
        pytest.param(r"\S+", id="inverse-unicode-space"),
        pytest.param(r"\u0061", id="python-unicode-codepoint"),
        pytest.param(r"\U00000061", id="python-long-unicode-codepoint"),
        pytest.param(r"\N{LATIN SMALL LETTER A}", id="python-unicode-name"),
        pytest.param(r"\_", id="python-escaped-non-metachar"),
    ],
)
def test_portable_pattern_rejects_python_re2_semantic_divergences(pattern: str) -> None:
    module = _load_generator_module(f"telemetry_registry_portable_pattern_{pattern.encode().hex()}")

    with pytest.raises(module.RegistryError, match="outside the portable RE2 subset"):
        module._validate_portable_pattern(pattern, "test.pattern")


def test_portable_pattern_accepts_shared_hex_escape_and_repetition_limit() -> None:
    module = _load_generator_module("telemetry_registry_portable_pattern_shared_boundary")
    pattern = r"\x61{0,1000}"

    assert module._validate_portable_pattern(pattern, "test.pattern") == pattern


def test_per_use_pattern_cannot_replace_the_attribute_normalization_pattern(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attribute_extensions"][0]["normalization"] = {"id": "identifier-v1"}
    document["groups"][0]["attributes"][0]["constraints"] = {"pattern": "^chat$"}
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "nonrepresentable pattern intersection for gen_ai.operation.name" in result.stderr


def test_per_use_constraints_are_preserved_in_compiler_ir(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    constraints = {"enum": ["chat"], "max_utf8_bytes": 64, "pattern": "^chat$"}
    document["groups"][0]["attributes"][0]["constraints"] = constraints
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_generator_test")

    ir = module.compile_registry(root)
    group = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")

    assert dict(group.attribute_uses[0].constraints) == {
        "enum": ("chat",),
        "max_utf8_bytes": 64,
        "pattern": "^chat$",
    }




def test_mapping_bearing_ir_classes_are_explicitly_equality_only() -> None:
    module = _load_generator_module("telemetry_registry_hash_contract_test")
    equality_only = (
        module.NormalizerIR,
        module.NormalizationIR,
        module.LegacyBindingIR,
        module.AttributeIR,
        module.AttributeExtensionIR,
        module.MetricCompatibilityProfileIR,
        module.AttributeUseIR,
        module.AttributeUseOriginIR,
        module.ResolvedAttributeUseIR,
        module.GroupIR,
        module.DomainIR,
        module.ExampleIR,
        module.RegistryIR,
    )

    assert all(cls.__hash__ is None for cls in equality_only)


def test_unknown_upstream_owner_mapping_fails_with_registry_error() -> None:
    module = _load_generator_module("telemetry_registry_owner_error_test")

    with pytest.raises(module.RegistryError, match="no public attribute-owner mapping"):
        module._public_upstream_owner("unknown_dependency")


@pytest.mark.parametrize(
    "surface",
    [
        "attribute",
        "normalization",
        "attribute_extension",
        "attribute_use",
        "span",
        "metric",
        "x_defenseclaw",
        "producer_mapping",
        "producer_identity",
        "compatibility",
        "example",
    ],
)
def test_compiler_ir_source_surfaces_reject_unknown_keys(
    tmp_path: Path,
    surface: str,
) -> None:
    root = _fixture_root(tmp_path)
    if surface in {
        "attribute",
        "normalization",
        "attribute_extension",
        "attribute_use",
        "span",
    }:
        path = root / "schemas/telemetry/v8/genai.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = {
            "attribute": document["attributes"][0],
            "normalization": document["attributes"][0]["normalization"],
            "attribute_extension": document["attribute_extensions"][0],
            "attribute_use": document["groups"][0]["attributes"][0],
            "span": document["groups"][0]["span"],
        }[surface]
    elif surface in {"metric", "x_defenseclaw", "producer_mapping", "producer_identity", "compatibility"}:
        path = root / "schemas/telemetry/v8/operations.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        metric = next(group for group in document["groups"] if group["type"] == "metric")
        mapping = document["producer_mappings"][0]
        if surface == "compatibility":
            mapping["compatibility"] = {"unexpected": "value"}
            target = None
        else:
            target = {
                "metric": metric["metric"],
                "x_defenseclaw": metric["x-defenseclaw"],
                "producer_mapping": mapping,
                "producer_identity": mapping["default_identity"],
            }[surface]
    else:
        path = root / "schemas/telemetry/v8/examples.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = document["examples"][0]
    if target is not None:
        target["unexpected"] = "value"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown keys ['unexpected']" in result.stderr


@pytest.mark.parametrize(
    ("surface", "value", "expected"),
    [
        ("allowed_outcomes", ["invented"], "unknown outcome"),
        ("link_relations", ["parent_of"], "unknown relation"),
        ("compatibility_profiles", ["unknown-v1"], "unknown profile"),
        ("span_kinds", ["client"], "unsupported OTel span kind"),
    ],
)
def test_group_runtime_vocabularies_are_closed(
    tmp_path: Path,
    surface: str,
    value: list[str],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if surface == "span_kinds":
        document["groups"][0]["span"]["kinds"] = value
    else:
        document["groups"][0]["x-defenseclaw"][surface] = value
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("requirement_level", "include_clause", "expected"),
    [
        ("conditional", False, "required for conditional fields"),
        ("required", True, "allowed only for conditional or optional fields"),
        ("recommended", True, "allowed only for conditional or optional fields"),
    ],
)
def test_attribute_use_conditional_clause_is_exactly_coupled_to_level(
    tmp_path: Path,
    requirement_level: str,
    include_clause: bool,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    use = document["groups"][0]["attributes"][0]
    use["requirement_level"] = requirement_level
    if include_clause:
        use["conditional"] = "only for the fixture condition"
    else:
        use.pop("conditional", None)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing_requirement", "require outcome_requirement and allowed_outcomes"),
        ("missing_allowed", "require outcome_requirement and allowed_outcomes"),
        ("forbidden_nonempty", "forbidden outcome requires an empty"),
        ("required_empty", "required/optional outcome requires nonempty"),
        ("out_of_order", "must follow defenseclaw.outcome order"),
        ("globally_broad", "globally broad allowed_outcomes is forbidden"),
    ],
)
def test_log_span_outcome_contract_is_exact(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    extension = document["groups"][0]["x-defenseclaw"]
    vocabulary = next(attribute for attribute in document["attributes"] if attribute["id"] == "defenseclaw.outcome")[
        "normalization"
    ]["overrides"]["enum"]
    if mutation == "missing_requirement":
        extension.pop("outcome_requirement")
    elif mutation == "missing_allowed":
        extension.pop("allowed_outcomes")
    elif mutation == "forbidden_nonempty":
        extension["outcome_requirement"] = "forbidden"
        extension["allowed_outcomes"] = ["completed"]
    elif mutation == "required_empty":
        extension["outcome_requirement"] = "required"
        extension["allowed_outcomes"] = []
    elif mutation == "out_of_order":
        extension["allowed_outcomes"] = ["completed", "allowed"]
    else:
        extension["allowed_outcomes"] = list(vocabulary)
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize("key", ["outcome_requirement", "allowed_outcomes"])
def test_metric_forbids_envelope_outcome_contract(tmp_path: Path, key: str) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    metric = next(group for group in document["groups"] if group["type"] == "metric")
    metric["x-defenseclaw"][key] = "optional" if key == "outcome_requirement" else ["completed"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "outcome contract is allowed only on logs/spans" in result.stderr


def test_allowed_outcome_order_is_derived_from_canonical_source(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    outcome = next(attribute for attribute in document["attributes"] if attribute["id"] == "defenseclaw.outcome")
    vocabulary = outcome["normalization"]["overrides"]["enum"]
    vocabulary.remove("completed")
    vocabulary.insert(0, "completed")
    document["groups"][0]["x-defenseclaw"]["allowed_outcomes"] = [
        "completed",
        "allowed",
    ]
    _write_yaml(path, document)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    structural_outcome = next(
        field for field in registry["structural_contract"]["envelope"]["fields"] if field["name"] == "outcome"
    )
    structural_outcome["normalization"]["overrides"]["enum"] = list(vocabulary)
    _write_yaml(registry_path, registry)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_real_family_outcome_contract_matrix_is_complete() -> None:
    module = _load_generator_module("telemetry_registry_real_outcome_contract_test")
    ir = module.compile_registry(ROOT)
    attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    outcome_order = attributes["defenseclaw.outcome"].normalization.effective_constraints["enum"]
    families = [group for domain in ir.domains for group in domain.groups if group.type in {"log", "span"}]

    assert outcome_order == _CANONICAL_OUTCOME_ORDER
    assert families
    assert len(families) == len({group.id for group in families})
    assert all(group.outcome_requirement is not None for group in families)
    assert all(group.allowed_outcomes is not None for group in families)

    contracts = [(group.id, group.outcome_requirement, group.allowed_outcomes) for group in families]
    matrix = _grouped_outcome_contract_matrix(contracts)
    family_counts = {
        requirement: sum(
            len(family_ids) for matrix_requirement, _, family_ids in matrix if matrix_requirement == requirement
        )
        for requirement in {item[0] for item in matrix}
    }

    assert matrix
    assert sum(family_counts.values()) == len(families)
    assert set(family_counts) <= {"forbidden", "required"}
    assert len(_outcome_contract_digest(contracts)) == 64


def test_real_family_outcome_contract_digest_detects_single_family_drift() -> None:
    module = _load_generator_module("telemetry_registry_outcome_drift_lock_test")
    ir = module.compile_registry(ROOT)
    contracts = [
        (group.id, group.outcome_requirement, group.allowed_outcomes)
        for domain in ir.domains
        for group in domain.groups
        if group.type in {"log", "span"}
    ]
    required_index = next(index for index, (_, requirement, _) in enumerate(contracts) if requirement == "required")
    multi_outcome_index = next(index for index, (_, _, outcomes) in enumerate(contracts) if len(outcomes) > 1)

    broadened = list(contracts)
    family_id, requirement, _ = broadened[required_index]
    broadened[required_index] = (family_id, requirement, _CANONICAL_OUTCOME_ORDER[:-1])

    requirement_drift = list(contracts)
    family_id, _, outcomes = requirement_drift[required_index]
    requirement_drift[required_index] = (family_id, "optional", outcomes)

    subset_drift = list(contracts)
    family_id, requirement, outcomes = subset_drift[multi_outcome_index]
    subset_drift[multi_outcome_index] = (family_id, requirement, outcomes[:-1])

    baseline = _outcome_contract_digest(contracts)
    assert {
        _outcome_contract_digest(broadened),
        _outcome_contract_digest(requirement_drift),
        _outcome_contract_digest(subset_drift),
    }.isdisjoint({baseline})


def test_group_resolution_deduplicates_diamond_origins_and_strengthens(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"].extend(
        [
            {
                "id": "diamond.base",
                "type": "attribute_group",
                "brief": "Diamond base.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "optional",
                        "constraints": {"max_utf8_bytes": 128},
                    }
                ],
            },
            {
                "id": "diamond.left",
                "type": "attribute_group",
                "brief": "Diamond left.",
                "stability": "development",
                "extends": ["diamond.base"],
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "recommended",
                        "constraints": {"max_utf8_bytes": 64},
                    }
                ],
            },
            {
                "id": "diamond.right",
                "type": "attribute_group",
                "brief": "Diamond right.",
                "stability": "development",
                "extends": ["diamond.base"],
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "required",
                        "constraints": {"max_utf8_bytes": 96},
                    }
                ],
            },
        ]
    )
    document["groups"][0]["extends"] = ["span.core", "diamond.left", "diamond.right"]
    _write_yaml(path, document)
    _materialize_trace_attribute(root, "defenseclaw.test.name", "fixture", "metadata")
    module = _load_generator_module("telemetry_registry_diamond_test")

    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.name")

    assert use.role == "attributes"
    assert use.requirement_level == "required"
    assert dict(use.constraints) == {"max_utf8_bytes": 64}
    assert tuple(origin.group_id for origin in use.origins) == (
        "diamond.base",
        "diamond.left",
        "diamond.right",
    )
    assert len(ir.group_resolution_order) == len(set(ir.group_resolution_order))
    position = {group_id: index for index, group_id in enumerate(ir.group_resolution_order)}
    assert position["diamond.base"] < position["diamond.left"] < position["span.model.chat"]
    assert position["diamond.base"] < position["diamond.right"] < position["span.model.chat"]
    assert ir.resolved_group_uses[span.id] == span.resolved_uses


def test_body_group_transposes_direct_and_inherited_uses_for_logs(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    body = next(group for group in document["groups"] if group["id"] == "body.fixture")
    document["groups"].append(
        {
            "id": "body.source",
            "type": "attribute_group",
            "brief": "Body source.",
            "stability": "development",
            "attributes": [{"ref": "defenseclaw.test.name", "requirement_level": "optional"}],
        }
    )
    body["extends"] = ["body.source"]
    body["body_fields"] = [{"ref": "defenseclaw.test.name", "requirement_level": "required"}]
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_body_transpose_test")

    ir = module.compile_registry(root)
    log = next(group for domain in ir.domains for group in domain.groups if group.id == "diagnostic.message")
    use = next(item for item in log.resolved_uses if item.ref == "defenseclaw.test.name")

    assert use.role == "body_fields"
    assert use.requirement_level == "required"
    assert tuple((origin.group_id, origin.role) for origin in use.origins) == (
        ("body.source", "attributes"),
        ("body.fixture", "body_fields"),
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("span_body_parent", "incompatible body_group parent"),
        ("attribute_body_direct", "body_fields are not allowed for attribute_group"),
        ("log_no_parent", "log must extend exactly one body_group"),
        ("log_two_parents", "log must extend exactly one body_group"),
        ("log_attribute_parent", "incompatible attribute_group parent"),
    ],
)
def test_group_resolution_rejects_role_and_log_parent_ambiguity(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    if mutation == "span_body_parent":
        path = root / "schemas/telemetry/v8/genai.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["groups"][0]["extends"] = ["span.core", "body.fixture"]
    else:
        path = root / "schemas/telemetry/v8/operations.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        log = next(group for group in document["groups"] if group["id"] == "diagnostic.message")
        if mutation == "attribute_body_direct":
            document["groups"].append(
                {
                    "id": "invalid.attribute.role",
                    "type": "attribute_group",
                    "brief": "Invalid role.",
                    "stability": "development",
                    "body_fields": [{"ref": "defenseclaw.test.name", "requirement_level": "optional"}],
                }
            )
        elif mutation == "log_no_parent":
            log["extends"] = []
        elif mutation == "log_two_parents":
            document["groups"].append(
                {
                    "id": "body.fixture.two",
                    "type": "body_group",
                    "brief": "Second body.",
                    "stability": "development",
                }
            )
            log["extends"] = ["body.fixture", "body.fixture.two"]
        else:
            document["groups"].append(
                {
                    "id": "attribute.fixture.parent",
                    "type": "attribute_group",
                    "brief": "Attribute parent.",
                    "stability": "development",
                }
            )
            log["extends"] = ["attribute.fixture.parent"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_group_resolution_rejects_cycles_even_when_unreferenced(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"].extend(
        [
            {
                "id": "cycle.one",
                "type": "attribute_group",
                "brief": "Cycle one.",
                "stability": "development",
                "extends": ["cycle.two"],
            },
            {
                "id": "cycle.two",
                "type": "attribute_group",
                "brief": "Cycle two.",
                "stability": "development",
                "extends": ["cycle.one"],
            },
        ]
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "inheritance cycle" in result.stderr


@pytest.mark.parametrize(
    ("requirements", "conditionals", "expected_level", "expected_conditional", "error"),
    [
        (("optional", "recommended"), (None, None), "recommended", None, None),
        (
            ("conditional", "conditional"),
            ("connector-known-v1", "connector-known-v1"),
            "conditional",
            "connector-known-v1",
            None,
        ),
        (
            ("conditional", "conditional", "required"),
            ("connector-known-v1", "operation-terminal-v1", None),
            "required",
            None,
            None,
        ),
        (
            ("conditional", "conditional"),
            ("connector-known-v1", "operation-terminal-v1"),
            None,
            None,
            "conflicting dominant conditional",
        ),
    ],
)
def test_requirement_lattice_and_conditional_clause_merge(
    tmp_path: Path,
    requirements: tuple[str, ...],
    conditionals: tuple[str | None, ...],
    expected_level: str | None,
    expected_conditional: str | None,
    error: str | None,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    parents: list[str] = []
    for index, (requirement, conditional) in enumerate(zip(requirements, conditionals, strict=True)):
        group_id = f"lattice.{index}"
        use: dict[str, Any] = {
            "ref": "defenseclaw.test.name",
            "requirement_level": requirement,
        }
        if conditional is not None:
            use["conditional"] = conditional
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Lattice parent.",
                "stability": "development",
                "attributes": [use],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)
    if error is not None:
        result = _run(root, "--write")
        assert result.returncode == 1
        assert error in result.stderr
        return
    if expected_level == "required":
        _materialize_trace_attribute(root, "defenseclaw.test.name", "fixture", "metadata")
    module = _load_generator_module(f"telemetry_registry_lattice_{len(requirements)}")
    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.name")
    assert use.requirement_level == expected_level
    assert use.conditional == expected_conditional


def test_constraint_intersection_is_restrictive_and_deterministic(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"].extend(
        [
            {
                "id": "constraints.left",
                "type": "attribute_group",
                "brief": "Constraint left.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "optional",
                        "constraints": {
                            "enum": ["alpha", "beta", "gamma"],
                            "pattern": "^[a-z]+$",
                            "max_utf8_bytes": 128,
                        },
                    }
                ],
            },
            {
                "id": "constraints.right",
                "type": "attribute_group",
                "brief": "Constraint right.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "recommended",
                        "constraints": {
                            "enum": ["gamma", "beta"],
                            "pattern": "^[a-z]+$",
                            "max_utf8_bytes": 64,
                        },
                    }
                ],
            },
        ]
    )
    document["groups"][0]["extends"] = ["span.core", "constraints.left", "constraints.right"]
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_constraint_merge_test")

    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.name")

    assert dict(use.constraints) == {
        "enum": ("beta", "gamma"),
        "pattern": "^[a-z]+$",
        "max_utf8_bytes": 64,
    }


def test_structured_constraint_intersection_uses_lower_depth_and_property_limits(
    tmp_path: Path,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attributes"].append(
        {
            "id": "defenseclaw.test.object",
            "type": "object",
            "brief": "Structured merge fixture.",
            "examples": [{"fixture": "value"}],
            "stability": "development",
            "owner": "defenseclaw",
            "field_class": "metadata",
            "sensitivity": "safe",
            "cardinality": "bounded",
            "normalization": {"id": "structured-content-v1"},
            "introduced_in": "telemetry-registry-v1",
        }
    )
    parents = []
    for index, constraints in enumerate(
        (
            {"max_depth": 7, "max_properties": 100},
            {"max_depth": 4, "max_properties": 60},
        )
    ):
        group_id = f"structured.constraints.{index}"
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Structured constraints.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.object",
                        "requirement_level": "optional",
                        "constraints": constraints,
                    }
                ],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)
    module = _load_generator_module("telemetry_registry_structured_constraint_test")

    ir = module.compile_registry(root)
    span = next(group for domain in ir.domains for group in domain.groups if group.id == "span.model.chat")
    use = next(item for item in span.resolved_uses if item.ref == "defenseclaw.test.object")

    assert dict(use.constraints) == {"max_depth": 4, "max_properties": 60}


def test_enum_intersection_preserves_bool_int_and_float_type_identity() -> None:
    module = _load_generator_module("telemetry_registry_enum_type_identity_test")

    def origin(group_id: str, values: list[bool | int | float]) -> Any:
        return module.AttributeUseOriginIR(
            group_id,
            "attributes",
            "optional",
            None,
            module._freeze_mapping({"enum": values}),
        )

    merged = module._intersect_use_constraints(
        "enum.identity",
        "defenseclaw.test.scalar",
        (
            origin("enum.left", [True, 1, 1.0]),
            origin("enum.right", [1.0, 1, True]),
        ),
    )

    assert merged["enum"] == (True, 1, 1.0)
    assert tuple(type(value) for value in merged["enum"]) == (bool, int, float)
    for left, right in ((True, 1), (1, 1.0), (True, 1.0)):
        with pytest.raises(module.RegistryError, match="empty enum intersection"):
            module._intersect_use_constraints(
                "enum.noncollision",
                "defenseclaw.test.scalar",
                (origin("enum.left", [left]), origin("enum.right", [right])),
            )


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ({"enum": ["alpha"]}, {"enum": ["beta"]}, "empty enum intersection"),
        ({"pattern": "^alpha$"}, {"pattern": "^beta$"}, "nonrepresentable pattern"),
    ],
)
def test_constraint_intersection_rejects_empty_or_nonrepresentable(
    tmp_path: Path,
    left: dict[str, Any],
    right: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    parents = []
    for index, constraints in enumerate((left, right)):
        group_id = f"invalid.constraints.{index}"
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Invalid constraints.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.name",
                        "requirement_level": "optional",
                        "constraints": constraints,
                    }
                ],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_constraint_intersection_rejects_inconsistent_numeric_range(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["attributes"].append(
        {
            "id": "defenseclaw.test.number",
            "type": "int64",
            "brief": "Numeric merge fixture.",
            "examples": [50],
            "stability": "development",
            "owner": "defenseclaw",
            "field_class": "metadata",
            "sensitivity": "safe",
            "cardinality": "bounded",
            "normalization": {
                "id": "numeric-range-v1",
                "overrides": {"min": 0, "max": 100},
            },
            "introduced_in": "telemetry-registry-v1",
        }
    )
    document["groups"].extend(
        [
            {
                "id": "range.minimum",
                "type": "attribute_group",
                "brief": "Range minimum.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.number",
                        "requirement_level": "optional",
                        "constraints": {"min": 80},
                    }
                ],
            },
            {
                "id": "range.maximum",
                "type": "attribute_group",
                "brief": "Range maximum.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.number",
                        "requirement_level": "optional",
                        "constraints": {"max": 40},
                    }
                ],
            },
        ]
    )
    document["groups"][0]["extends"] = ["span.core", "range.minimum", "range.maximum"]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "inconsistent min/max intersection" in result.stderr


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            {"min_items": 5},
            {"max_items": 3},
            "inconsistent min_items/max_items intersection",
        ),
        (
            {"max_utf8_bytes": 10},
            {"max_item_utf8_bytes": 20},
            "incompatible UTF-8 bounds",
        ),
    ],
)
def test_constraint_intersection_rejects_inconsistent_collection_bounds(
    tmp_path: Path,
    left: dict[str, Any],
    right: dict[str, Any],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = copy.deepcopy(document["attributes"][0])
    attribute.update(
        {
            "id": "defenseclaw.test.names",
            "type": "string[]",
            "examples": [["fixture"]],
        }
    )
    document["attributes"].append(attribute)
    parents = []
    for index, constraints in enumerate((left, right)):
        group_id = f"invalid.collection.constraints.{index}"
        document["groups"].append(
            {
                "id": group_id,
                "type": "attribute_group",
                "brief": "Invalid collection constraints.",
                "stability": "development",
                "attributes": [
                    {
                        "ref": "defenseclaw.test.names",
                        "requirement_level": "optional",
                        "constraints": constraints,
                    }
                ],
            }
        )
        parents.append(group_id)
    document["groups"][0]["extends"] = ["span.core", *parents]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_real_registry_resolves_once_with_zero_ambiguity() -> None:
    module = _load_generator_module("telemetry_registry_real_resolution_test")

    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    positions = {group_id: index for index, group_id in enumerate(ir.group_resolution_order)}
    materialized_order = ir.materialized_view.facts["fields"]["group_resolution_order"]

    assert len(ir.group_resolution_order) == len(groups) == len(ir.resolved_group_uses)
    assert len(set(ir.group_resolution_order)) == len(groups)
    assert materialized_order == ir.group_resolution_order
    for group in groups.values():
        assert group.resolved_uses == ir.resolved_group_uses[group.id]
        assert len({use.ref for use in group.resolved_uses}) == len(group.resolved_uses)
        assert all(positions[parent] < positions[group.id] for parent in group.extends)
        if group.type == "log":
            assert len(group.extends) == 1
            assert groups[group.extends[0]].type == "body_group"
            assert all(use.role == "body_fields" for use in group.resolved_uses)
        elif group.type in {"span", "resource", "metric", "span_event"}:
            assert all(use.role == "attributes" for use in group.resolved_uses)


def test_span_name_placeholder_rejects_high_cardinality_attribute(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["attribute_extensions"][0]["cardinality"] = "high"
    _write_yaml(domain_path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unsafe name placeholder gen_ai.operation.name" in result.stderr


def test_real_span_name_programs_are_compiled_once_and_materialized_exactly() -> None:
    module = _load_generator_module("telemetry_registry_real_span_name_parts")

    ir = module.compile_registry(ROOT)
    spans = {group.id: group for domain in ir.domains for group in domain.groups if group.type == "span"}
    expected = {
        "span.agent.invoke": (("literal", "invoke_agent "), ("field", "defenseclaw.agent.type")),
        "span.workflow.run": (("literal", "workflow "), ("field", "defenseclaw.workflow.name")),
        "span.model.chat": (("literal", "chat "), ("field", "gen_ai.request.model")),
        "span.model.embeddings": (("literal", "embeddings "), ("field", "gen_ai.request.model")),
        "span.tool.execute": (("literal", "execute_tool "), ("field", "gen_ai.tool.name")),
        "span.retrieval.search": (
            ("literal", "retrieve "),
            ("field", "defenseclaw.retrieval.source.id"),
        ),
        "span.guardrail.apply": (
            ("literal", "apply_guardrail "),
            ("field", "defenseclaw.guardrail.name"),
            ("literal", " "),
            ("field", "defenseclaw.guardrail.target_type"),
        ),
        "span.guardrail.phase": (
            ("literal", "guardrail."),
            ("field", "defenseclaw.guardrail.phase"),
        ),
        "span.guardrail.judge": (("literal", "chat "), ("field", "gen_ai.request.model")),
        "span.enforcement.apply": (
            ("literal", "enforcement "),
            ("field", "defenseclaw.enforcement.effective_action"),
        ),
        "span.approval.resolve": (("literal", "exec.approval"),),
        "span.finding.enrich": (
            ("literal", "finding.enrich "),
            ("field", "defenseclaw.source"),
        ),
        "span.agent.transition": (
            ("literal", "agent.transition "),
            ("field", "defenseclaw.agent.lifecycle.event"),
        ),
        "span.asset.scan": (("literal", "asset.scan"),),
        "span.asset.scan.phase": (("literal", "asset.scan.phase"),),
        "span.asset.transition": (
            ("literal", "asset.transition "),
            ("field", "defenseclaw.asset.transition"),
        ),
        "span.network.request": (("field", "http.request.method"), ("literal", " outbound")),
        "span.ai.discovery": (("literal", "defenseclaw.ai.discovery"),),
        "span.ai.discovery.detector": (("literal", "defenseclaw.ai.discovery.detector"),),
        "span.telemetry.receive": (("field", "http.request.method"), ("literal", " telemetry")),
        "span.telemetry.normalize": (
            ("literal", "telemetry.normalize "),
            ("field", "defenseclaw.telemetry.signal"),
        ),
        "span.destination.export": (
            ("literal", "telemetry.export "),
            ("field", "defenseclaw.destination.id"),
        ),
        "span.config.reload": (("literal", "config.reload"),),
        "span.admin.operation": (("field", "defenseclaw.admin.operation"),),
        "span.diagnostic.canary": (("literal", "defenseclaw.telemetry.canary"),),
    }

    assert len(spans) == len(expected) == 25
    actual_name_fields: list[tuple[str, str]] = []
    for group_id, expected_parts in expected.items():
        group = spans[group_id]
        assert group.span_name_pattern
        assert group.span_name_parts is not None
        assert (
            tuple((part.kind, part.literal if part.kind == "literal" else part.field) for part in group.span_name_parts)
            == expected_parts
        )
        assert all(part.literal or part.field for part in group.span_name_parts)
        assert all(
            left.kind != "literal" or right.kind != "literal"
            for left, right in zip(group.span_name_parts, group.span_name_parts[1:])
        )
        materialized = module._materialize_registry_fact(group)
        materialized_parts = materialized["fields"]["span_name_parts"]
        assert tuple(item["$type"] for item in materialized_parts) == ("SpanNamePartIR",) * len(expected_parts)
        uses = {use.ref: use for use in group.resolved_uses}
        for part in group.span_name_parts:
            if part.kind != "field":
                continue
            assert part.field is not None
            actual_name_fields.append((group_id, part.field))
            use = uses[part.field]
            assert use.role == "attributes"
            assert use.requirement_level == "required"
            assert use.conditional is None

    assert tuple(sorted(actual_name_fields)) == _ALL_SPAN_NAME_FIELDS
    for group_id, field_id in _SPAN_NAME_REQUIRED_CORRECTIONS:
        direct = next(use for use in spans[group_id].attribute_uses if use.ref == field_id)
        assert direct.role == "attributes"
        assert direct.requirement_level == "required"
        assert direct.conditional is None


@pytest.mark.parametrize(("family_id", "field_id"), _SPAN_NAME_REQUIRED_CORRECTIONS)
def test_every_pre_release_span_name_required_correction_fails_closed_if_weakened(
    family_id: str,
    field_id: str,
    real_span_name_contract: tuple[ModuleType, Any, Any, Any, Any],
) -> None:
    module, canonical_groups, local_attributes, extensions, upstream = real_span_name_contract
    groups = dict(canonical_groups)
    group = canonical_groups[family_id]
    groups[family_id] = dataclasses.replace(
        group,
        resolved_uses=tuple(
            dataclasses.replace(use, requirement_level="recommended", conditional=None) if use.ref == field_id else use
            for use in group.resolved_uses
        ),
    )

    with pytest.raises(module.RegistryError, match="must resolve as an unconditional required string attribute"):
        module._validate_span_name_patterns(groups, local_attributes, extensions, upstream)


@pytest.mark.parametrize(
    ("role", "conditional"),
    (("body_fields", None), ("attributes", "technical-failure-v1")),
)
def test_span_name_placeholder_must_remain_an_unconditional_attribute(
    role: str,
    conditional: str | None,
    real_span_name_contract: tuple[ModuleType, Any, Any, Any, Any],
) -> None:
    module, canonical_groups, local_attributes, extensions, upstream = real_span_name_contract
    groups = dict(canonical_groups)
    group = canonical_groups["span.model.chat"]
    groups[group.id] = dataclasses.replace(
        group,
        resolved_uses=tuple(
            dataclasses.replace(use, role=role, conditional=conditional) if use.ref == "gen_ai.request.model" else use
            for use in group.resolved_uses
        ),
    )

    with pytest.raises(module.RegistryError, match="must resolve as an unconditional required string attribute"):
        module._validate_span_name_patterns(groups, local_attributes, extensions, upstream)


def test_span_name_placeholder_must_be_string_only_after_resolution(
    real_span_name_contract: tuple[ModuleType, Any, Any, Any, Any],
) -> None:
    module, groups, local_attributes, extensions, canonical_upstream = real_span_name_contract
    upstream = dict(canonical_upstream)
    owner, model = upstream["gen_ai.request.model"]
    upstream["gen_ai.request.model"] = (owner, dataclasses.replace(model, allowed_types=("int64",)))

    with pytest.raises(module.RegistryError, match="must resolve as an unconditional required string attribute"):
        module._validate_span_name_patterns(groups, local_attributes, extensions, upstream)


def test_local_span_name_placeholder_must_be_string_only_after_resolution(
    real_span_name_contract: tuple[ModuleType, Any, Any, Any, Any],
) -> None:
    module, groups, canonical_local_attributes, extensions, upstream = real_span_name_contract
    local_attributes = dict(canonical_local_attributes)
    operation = local_attributes["defenseclaw.admin.operation"]
    local_attributes[operation.id] = dataclasses.replace(operation, field_type="int64")

    with pytest.raises(module.RegistryError, match="must resolve as an unconditional required string attribute"):
        module._validate_span_name_patterns(groups, local_attributes, extensions, upstream)


@pytest.mark.parametrize(
    "pattern",
    [
        "chat {gen_ai.operation.name!r}",
        "chat {gen_ai.operation.name:>10}",
        "chat {}",
        "chat {",
        "chat {not canonical}",
    ],
)
def test_span_name_program_rejects_invalid_or_transformed_parts(pattern: str) -> None:
    module = _load_generator_module("telemetry_registry_invalid_span_name_parts")

    assert module._compile_span_name_parts(pattern) is None


@pytest.mark.parametrize(
    ("kind", "literal", "field"),
    [
        ("literal", None, None),
        ("literal", "", None),
        ("literal", "collision", "defenseclaw.source"),
        ("field", None, None),
        ("field", "collision", "defenseclaw.source"),
        ("field", None, ""),
        ("unknown", "value", None),
    ],
)
def test_span_name_part_exact_arms_reject_empty_noop_and_collisions(
    kind: str,
    literal: str | None,
    field: str | None,
) -> None:
    module = _load_generator_module("telemetry_registry_invalid_span_name_arm")

    with pytest.raises(ValueError, match="exactly one nonempty literal or canonical field arm"):
        module.SpanNamePartIR(kind, literal, field)


def test_span_name_program_coalesces_escaped_literals_without_empty_parts() -> None:
    module = _load_generator_module("telemetry_registry_escaped_span_name_parts")

    parts = module._compile_span_name_parts("chat {{literal}} {gen_ai.operation.name}")

    assert parts == (
        module.SpanNamePartIR("literal", "chat {literal} ", None),
        module.SpanNamePartIR("field", None, "gen_ai.operation.name"),
    )
    assert module._materialized_span_name(parts, {"gen_ai.operation.name": "chat"}) == "chat {literal} chat"


def test_span_name_validation_and_materialization_share_escaped_brace_parsing(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["groups"][0]["span"]["name_pattern"] = "chat {{literal}} {gen_ai.operation.name}"
    _write_yaml(domain_path, domain)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    examples["examples"][0]["record"]["span_name"] = "chat {literal} chat"
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_valid_example_field_class_map_is_complete_and_exact(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    examples["examples"][0]["record"]["field_classes"] = {}
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "field_classes: coverage mismatch" in result.stderr
    assert "/attributes/gen_ai.operation.name" in result.stderr


def test_real_registry_has_nonempty_unique_authoritative_signal_families() -> None:
    groups: list[dict[str, Any]] = []
    for domain in ("genai", "security", "operations"):
        document = yaml.safe_load((ROOT / f"schemas/telemetry/v8/{domain}.yaml").read_text(encoding="utf-8"))
        groups.extend(document["groups"])

    signal_groups = [group for group in groups if group["type"] in {"log", "span", "metric"}]
    assert {group["type"] for group in signal_groups} == {"log", "span", "metric"}
    ids = [group["id"] for group in signal_groups]
    assert len(ids) == len(set(ids))


def test_named_producer_identity_set_resolves_to_explicit_contexts(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapping = document["producer_mappings"][0]
    identity = mapping.pop("default_identity")
    mapping["event_name_policy"] = "context_required"
    mapping["allowed_context_identity_set"] = "diagnostic-context"
    document["producer_identity_sets"] = [{"id": "diagnostic-context", "identities": [identity]}]
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("unknown", "unknown set"),
        ("empty", "expected nonempty sequence"),
        ("duplicate", "duplicate identity"),
        ("unreferenced", "unreferenced producer identity sets"),
        ("fixed_ref", "not allowed for fixed policy"),
    ],
)
def test_named_producer_identity_sets_reject_ambiguous_shapes(
    tmp_path: Path,
    mode: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapping = document["producer_mappings"][0]
    identity = dict(mapping["default_identity"])
    identities = [] if mode == "empty" else [identity]
    if mode == "duplicate":
        identities.append(dict(identity))
    if mode != "unknown":
        document["producer_identity_sets"] = [{"id": "diagnostic-context", "identities": identities}]
    if mode == "unknown":
        mapping.pop("default_identity")
        mapping["event_name_policy"] = "context_required"
        mapping["allowed_context_identity_set"] = "missing-context"
    elif mode == "fixed_ref":
        mapping["allowed_context_identity_set"] = "diagnostic-context"
    elif mode != "unreferenced":
        mapping.pop("default_identity")
        mapping["event_name_policy"] = "context_required"
        mapping["allowed_context_identity_set"] = "diagnostic-context"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ("\nschema_version: 1\n", "duplicate YAML key"),
        ("\nunknown_key: true\n", "unknown keys"),
        ("\nbase: &base {value: 1}\nmerged: {<<: *base}\n", "anchors and aliases"),
        ("\ntagged: !defenseclaw value\n", "explicit YAML tags"),
    ],
)
def test_strict_yaml_rejects_ambiguous_or_unknown_input(
    tmp_path: Path,
    suffix: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    registry = root / "schemas/telemetry/v8/registry.yaml"
    registry.write_text(registry.read_text(encoding="utf-8") + suffix, encoding="utf-8")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr
    assert not (root / "schemas/telemetry/generated").exists()


def test_strict_yaml_rejects_invalid_utf8(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    registry = root / "schemas/telemetry/v8/registry.yaml"
    registry.write_bytes(registry.read_bytes() + b"\xff")

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "invalid UTF-8" in result.stderr


def test_check_preserves_unowned_and_detects_stale_outputs(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    assert _run(root, "--write").returncode == 0
    module = _load_generator_module("telemetry_registry_direct_check_drift")
    extra_relative = "schemas/telemetry/runtime/unowned.json.gz"
    extra = root / extra_relative
    extra.write_bytes(b"unowned")
    result = _run(root, "--check")
    assert result.returncode == 1
    assert f"extra={extra_relative}" in result.stderr
    assert extra.is_file()
    result = _run(root, "--write")
    assert result.returncode == 1
    assert "generated output drift: extra=" in result.stderr
    assert extra.is_file()
    assert _run(root, "--check").returncode == 1
    extra.unlink()
    assert _run(root, "--check").returncode == 0
    physical_relative = module.runtime_assets.LOGICAL_TO_ENCODED[
        "schemas/telemetry/generated/catalog.json"
    ]
    physical = root / physical_relative
    physical.write_bytes(physical.read_bytes() + b" ")
    result = _run(root, "--check")
    assert result.returncode == 1
    assert f"stale={physical_relative}" in result.stderr
    assert physical.is_file()

    assert _run(root, "--write").returncode == 0
    physical.unlink()
    result = _run(root, "--check")
    assert result.returncode == 1
    assert f"missing={physical_relative}" in result.stderr
    assert not physical.exists()


def _upstream_archive(path: Path, *, malformed_yaml: bool = False) -> None:
    source = (
        b"attributes:\n  - key: [unterminated\n"
        if malformed_yaml
        else b"""\
file_format: definition/2
attributes:
  - key: gen_ai.operation.name
    type: string
    brief: Operation name.
    stability: development
  - key: gen_ai.input.messages
    type: any
    brief: Input messages.
    stability: development
  - key: gen_ai.output.messages
    type: any
    brief: Output messages.
    stability: development
  - key: gen_ai.tool.call.arguments
    type: any
    brief: Tool-call arguments.
    stability: development
  - key: gen_ai.tool.call.result
    type: any
    brief: Tool-call result.
    stability: development
  - key: gen_ai.test.attribute
    type: string
    brief: Test attribute.
    stability: development
  - key: gen_ai.test.any_value
    type: any
    brief: Structured any value.
    stability: development
  - key: gen_ai.test.bytes
    type: bytes
    brief: Opaque bytes value.
    stability: development
"""
    )
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("semantic-conventions-genai/model/gen-ai/registry.yaml")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))
        for filename in (
            "gen-ai-input-messages.json",
            "gen-ai-output-messages.json",
            "gen-ai-tool-call-arguments.json",
            "gen-ai-tool-call-result.json",
        ):
            payload = (
                ROOT / "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
                f"model/gen-ai/{filename}"
            ).read_bytes()
            info = tarfile.TarInfo(f"semantic-conventions-genai/model/gen-ai/{filename}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def _full_genai_upstream_archive(path: Path) -> None:
    snapshot = json.loads(
        (
            ROOT / "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813.normalized.json"
        ).read_bytes()
    )
    reverse_types = {
        "string": "string",
        "boolean": "boolean",
        "int64": "int64",
        "double": "double",
        "string[]": "string[]",
    }
    attributes: list[dict[str, Any]] = []
    for item in snapshot["attributes"]:
        if item["enum"]:
            field_type: Any = {"members": [{"value": value} for value in item["enum"]]}
        elif item["shape"] == "any_value":
            field_type = "any"
        else:
            assert len(item["allowed_types"]) == 1
            field_type = reverse_types[item["allowed_types"][0]]
        attributes.append(
            {
                "id": item["id"],
                "type": field_type,
                "stability": item["stability"],
                "deprecated": item["deprecated"],
            }
        )
    source = yaml.safe_dump(
        {"file_format": "definition/2", "attributes": attributes},
        sort_keys=False,
    ).encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("semantic-conventions-genai/model/gen-ai/registry.yaml")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))
        for filename in (
            "gen-ai-input-messages.json",
            "gen-ai-output-messages.json",
            "gen-ai-tool-call-arguments.json",
            "gen-ai-tool-call-result.json",
        ):
            payload = (
                ROOT / "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
                f"model/gen-ai/{filename}"
            ).read_bytes()
            info = tarfile.TarInfo(f"semantic-conventions-genai/model/gen-ai/{filename}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def _full_core_upstream_archive(path: Path) -> None:
    snapshot = json.loads((ROOT / "schemas/telemetry/v8/upstream/otel-core-v1.42.0.normalized.json").read_bytes())
    attributes: list[dict[str, Any]] = []
    for item in snapshot["attributes"]:
        if item["enum"]:
            field_type: Any = {"members": [{"value": value} for value in item["enum"]]}
        elif item["shape"] == "any_value":
            field_type = "any"
        else:
            assert len(item["allowed_types"]) == 1
            field_type = item["allowed_types"][0]
        attributes.append(
            {
                "id": item["id"],
                "type": field_type,
                "stability": item["stability"],
                "deprecated": item["deprecated"],
            }
        )
    source = yaml.safe_dump(
        {"file_format": "definition/2", "attributes": attributes},
        sort_keys=False,
    ).encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("semantic-conventions/model/registry.yaml")
        info.size = len(source)
        archive.addfile(info, io.BytesIO(source))


def _openinference_archive(
    path: Path,
    *,
    version_value: str = "0.1.30",
    unknown_type: bool = False,
    malformed_header: bool = False,
    constants_mismatch: bool = False,
    reverse_members: bool = False,
) -> None:
    resource = b'class ResourceAttributes:\n    PROJECT_NAME = "openinference.project.name"\n'
    version = f'__version__ = "{version_value}"\n'.encode()
    typed = {
        "input.value": "String",
        "input.mime_type": "String",
        "output.value": "String",
        "output.mime_type": "String",
        "openinference.span.kind": "String",
        "llm.token_count.total": "Integer",
        "llm.cost.total": "Float",
        "tag.tags": "List of strings",
        "embedding.vector": "List of floats",
        "message_content.image": "Image Object",
        "llm.tools": "List of objects<sup>†</sup>",
        "metadata": "JSON String",
        "document.id": "String/Integer",
    }
    for index in range(77):
        typed[f"fixture.attribute.{index:03d}"] = "String"
    typed["session.id"] = "String"
    typed["user.id"] = "String"
    assert len(typed) == 92
    constants_only = {
        "completion.text",
        "llm.cost.completion_details",
        "llm.cost.prompt_details",
        "llm.token_count.prompt_details",
        "llm.token_count.prompt_details.cache_input",
        "prompt.text",
    }
    trace_identifiers = set(typed) | constants_only
    if constants_mismatch:
        trace_identifiers.remove("openinference.span.kind")
    trace_lines = ["class SpanAttributes:"]
    for index, identifier in enumerate(sorted(trace_identifiers)):
        trace_lines.append(f'    ATTRIBUTE_{index} = "{identifier}"')
    trace = ("\n".join(trace_lines) + "\n").encode()
    table_only = {
        "exception.escaped": "Boolean",
        "exception.message": "String",
        "exception.stacktrace": "String",
        "exception.type": "String",
    }
    table_rows = [
        "## Reserved Attributes",
        "",
        (
            "| Name | Type | Example | Description |"
            if malformed_header
            else "| Attribute | Type | Example | Description |"
        ),
        "| --- | --- | --- | --- |",
    ]
    for identifier, type_name in sorted({**typed, **table_only}.items()):
        if unknown_type and identifier == "input.value":
            type_name = "Opaque Mystery"
        table_rows.append(f"| `{identifier}` | {type_name} | `value` | Fixture. |")
    table_rows.extend(["", "## Next Section", ""])
    specification = "\n".join(table_rows).encode()
    foreign = b"""\
class InstrumentationAliases:
    FOREIGN = "gen_ai.operation.name"
"""
    files = {
        "openinference/python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py": resource,
        "openinference/python/openinference-semantic-conventions/src/openinference/semconv/trace/__init__.py": trace,
        "openinference/python/openinference-semantic-conventions/src/openinference/semconv/version.py": version,
        "openinference/spec/semantic_conventions.md": specification,
        "openinference/python/instrumentation/example.py": foreign,
    }
    archive_items = list(files.items())
    if reverse_members:
        archive_items.reverse()
    with tarfile.open(path, "w:gz") as archive:
        for name, source in archive_items:
            info = tarfile.TarInfo(name)
            info.size = len(source)
            archive.addfile(info, io.BytesIO(source))


def test_explicit_updater_derives_snapshot_from_local_pinned_archive(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "genai.tar.gz"
    _upstream_archive(archive)
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--archive",
            f"otel_genai={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    snapshot_path = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    snapshot = json.loads(snapshot_path.read_bytes())
    assert [item["id"] for item in snapshot["attributes"]] == [
        "gen_ai.input.messages",
        "gen_ai.operation.name",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ]
    any_value = next(item for item in snapshot["attributes"] if item["id"] == "gen_ai.input.messages")
    assert any_value["allowed_types"] == []
    assert any_value["shape"] == "any_value"
    assert not any(item["id"].startswith("gen_ai.test.") for item in snapshot["attributes"])
    assert snapshot["format_version"] == 2
    assert snapshot["format"] == "defenseclaw-selected-semconv-v1"
    assert snapshot["source_archive"]["sha256"] == _sha256(archive.read_bytes())
    assert re.fullmatch(r"[0-9a-f]{64}", snapshot["source_tree_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", snapshot["full_normalized_inventory_sha256"])
    lock = yaml.safe_load((root / "schemas/telemetry/v8/semconv.lock.yaml").read_text(encoding="utf-8"))
    dependency = next(item for item in lock["dependencies"] if item["id"] == "otel_genai")
    assert dependency["snapshot"]["sha256"] == _sha256(snapshot_path.read_bytes())
    assert [item["upstream_path"] for item in dependency["structural_inputs"]] == [
        "model/gen-ai/gen-ai-input-messages.json",
        "model/gen-ai/gen-ai-output-messages.json",
        "model/gen-ai/gen-ai-tool-call-arguments.json",
        "model/gen-ai/gen-ai-tool-call-result.json",
    ]
    for item in dependency["structural_inputs"]:
        target = root / item["path"]
        assert target.read_bytes()
        assert item["sha256"] == _sha256(target.read_bytes())


def test_full_genai_updater_refresh_compiles_end_to_end(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "full-genai.tar.gz"
    _full_genai_upstream_archive(archive)
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--archive",
            f"otel_genai={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    compiler = _load_generator_module("telemetry_registry_full_genai_refresh_compile")
    ir = compiler.compile_registry(root)

    genai = next(item for item in ir.dependencies if item.id == "otel_genai")
    assert {item.id for item in genai.snapshot.attributes} == {
        "gen_ai.operation.name",
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    }
    assert len(genai.structural_inputs) == 4


def test_updater_rejects_malformed_yaml_with_source_context(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "malformed-genai.tar.gz"
    _upstream_archive(archive, malformed_yaml=True)

    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--archive",
            f"otel_genai={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert "model/gen-ai/registry.yaml: parse failure" in result.stderr


def test_checked_in_otel_any_values_preserve_any_value_shape() -> None:
    snapshot = json.loads(
        (
            ROOT
            / "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813.normalized.json"
        ).read_bytes()
    )
    for identifier in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ):
        attribute = next(item for item in snapshot["attributes"] if item["id"] == identifier)
        assert attribute["allowed_types"] == []
        assert attribute["shape"] == "any_value"


def test_checked_in_upstream_privacy_extensions_are_explicit() -> None:
    extensions: dict[str, dict[str, Any]] = {}
    for domain in ("genai", "security", "operations"):
        document = yaml.safe_load((ROOT / f"schemas/telemetry/v8/{domain}.yaml").read_text(encoding="utf-8"))
        for extension in document["attribute_extensions"]:
            assert extension["ref"] not in extensions
            extensions[extension["ref"]] = extension
    for reference in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ):
        assert extensions[reference]["field_class"] == "content"
        assert extensions[reference]["sensitivity"] == "sensitive"
        assert extensions[reference]["cardinality"] == "high"
    assert extensions["exception.message"]["field_class"] == "error"
    assert extensions["exception.message"]["sensitivity"] == "sensitive"
    assert extensions["url.full"]["field_class"] == "path"
    assert extensions["url.full"]["sensitivity"] == "sensitive"


def test_openinference_updater_uses_only_authoritative_semconv_package(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "openinference.tar.gz"
    _openinference_archive(archive)
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "openinference",
            "--archive",
            f"openinference={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    snapshot_path = root / "schemas/telemetry/v8/upstream/openinference.normalized.json"
    snapshot = json.loads(snapshot_path.read_bytes())
    assert [item["path"] for item in snapshot["source_files"]] == [
        "python/openinference-semantic-conventions/src/openinference/semconv/resource/__init__.py",
        "spec/semantic_conventions.md",
    ]
    identifiers = {item["id"] for item in snapshot["attributes"]}
    assert identifiers == {
        "openinference.span.kind",
        "input.value",
        "input.mime_type",
        "output.value",
        "output.mime_type",
        "metadata",
        "openinference.project.name",
    }
    assert not any(identifier.startswith("gen_ai.") for identifier in identifiers)
    attributes = {item["id"]: item for item in snapshot["attributes"]}
    assert "metadata" in attributes
    assert "openinference.project.name" in attributes
    assert not any(identifier.startswith("exception.") for identifier in attributes)


def test_openinference_updater_rejects_package_version_mismatch(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "openinference.tar.gz"
    _openinference_archive(archive, version_value="0.1.31")

    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "openinference",
            "--archive",
            f"openinference={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert "package version does not match lock" in result.stderr


@pytest.mark.parametrize(
    ("option", "expected"),
    [
        ("unknown_type", "unsupported Reserved Attributes type"),
        ("malformed_header", "expected one Reserved Attributes table"),
        ("constants_mismatch", "selected attributes are absent upstream"),
    ],
)
def test_openinference_updater_rejects_malformed_authority(
    tmp_path: Path,
    option: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "openinference.tar.gz"
    _openinference_archive(archive, **{option: True})
    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "openinference",
            "--archive",
            f"openinference={archive}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert expected in result.stderr


def test_openinference_archive_member_order_does_not_change_snapshot(tmp_path: Path) -> None:
    snapshots: list[dict[str, Any]] = []
    for index, reverse in enumerate((False, True)):
        root = _fixture_root(tmp_path / str(index))
        archive = tmp_path / f"openinference-{index}.tar.gz"
        _openinference_archive(archive, reverse_members=reverse)
        result = subprocess.run(
            [
                sys.executable,
                str(UPDATER),
                "--write",
                "--root",
                str(root),
                "--dependency",
                "openinference",
                "--archive",
                f"openinference={archive}",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        snapshots.append(
            json.loads((root / "schemas/telemetry/v8/upstream/openinference.normalized.json").read_bytes())
        )

    # The raw archive attestation intentionally differs when archive bytes do,
    # while extraction, normalization, selection, and rendered provenance stay
    # deterministic.
    assert snapshots[0]["source_archive"]["sha256"] != snapshots[1]["source_archive"]["sha256"]
    snapshots[0]["source_archive"]["sha256"] = "<raw-archive>"
    snapshots[1]["source_archive"]["sha256"] = "<raw-archive>"
    assert snapshots[0] == snapshots[1]


def test_updater_validation_failure_preserves_all_existing_bytes(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    archive = tmp_path / "genai.tar.gz"
    _upstream_archive(archive)
    invalid = tmp_path / "invalid-openinference.tar.gz"
    invalid.write_bytes(b"not a tar archive")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    snapshot_path = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    before = {lock_path: lock_path.read_bytes(), snapshot_path: snapshot_path.read_bytes()}

    result = subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--write",
            "--root",
            str(root),
            "--dependency",
            "otel_genai",
            "--dependency",
            "openinference",
            "--archive",
            f"otel_genai={archive}",
            "--archive",
            f"openinference={invalid}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1
    assert {path: path.read_bytes() for path in before} == before


def test_structural_contract_ir_is_closed_lossless_and_runtime_bound() -> None:
    module = _load_generator_module("telemetry_registry_structural_contract")

    ir = module.compile_registry(ROOT)

    contract = ir.structural_contract
    assert contract.id == "defenseclaw.canonical-record"
    assert contract.version == 1
    assert contract.additional_properties is False
    assert contract.runtime_binding.record == "internal/observability.Record"
    assert contract.runtime_binding.schema_derived_constructor == ("internal/observability.newSchemaDerivedRecord")
    assert contract.runtime_binding.schema_derived_log_constructor == (
        "internal/observability.newSchemaDerivedLogRecord"
    )
    assert dict(contract.limits.values) == {
        "record_id_utf8_bytes": 512,
        "correlation_id_utf8_bytes": 512,
        "span_name_utf8_bytes": 512,
        "binary_version_utf8_bytes": 256,
        "provenance_hex_ascii_bytes": 128,
        "stable_token_ascii_bytes": 128,
        "payload_depth": 32,
        "payload_members": 8192,
        "payload_encoded_bytes": 1048576,
        "record_encoded_bytes": 4194304,
    }
    assert tuple(field.name for field in contract.trace_body.fields) == (
        "kind",
        "start_time_unix_nano",
        "end_time_unix_nano",
        "parent_span_id",
        "trace_state",
        "flags",
        "status",
        "resource",
        "scope",
        "attributes",
        "dropped_attributes_count",
        "events",
        "dropped_events_count",
        "links",
        "dropped_links_count",
    )
    trace_fields = {field.name: field for field in contract.trace_body.fields}
    assert trace_fields["start_time_unix_nano"].field_type == "uint64"
    assert trace_fields["start_time_unix_nano"].otlp_target == "startTimeUnixNano"
    assert trace_fields["trace_state"].semantic_format == "w3c-tracestate-v1"
    assert trace_fields["trace_state"].otlp_target == "traceState"
    assert trace_fields["flags"].field_type == "uint32"
    assert trace_fields["flags"].otlp_target == "flags"
    assert trace_fields["attributes"].semantic_ref == "registry.family_attributes"
    assert trace_fields["resource"].otlp_target is None
    assert trace_fields["scope"].otlp_target is None
    assert contract.trace_relations[0].left == "start_time_unix_nano"
    assert contract.trace_relations[0].right == "end_time_unix_nano"
    assert {
        (
            "target_attribute" if item.target_attribute is not None else "target_field",
            item.target_attribute if item.target_attribute is not None else item.target_field,
            item.source,
            item.equality,
            item.presence,
        )
        for item in contract.trace_derivations
    } == {
        (
            "target_attribute",
            "defenseclaw.bucket",
            "envelope.bucket",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.span.family",
            "family.id",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.span.family_schema_version",
            "family.family_schema_version",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.source",
            "envelope.source",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.config.generation",
            "provenance.config_generation",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.outcome",
            "envelope.outcome",
            "typed-json-exact",
            "when-registered-and-source-present",
        ),
        (
            "target_attribute",
            "service.version",
            "provenance.binary_version",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_field",
            "trace_scope.version",
            "provenance.binary_version",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.trace.schema_version",
            "semantic_profile.trace_schema_version",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.semantic_profile",
            "semantic_profile.id",
            "typed-json-exact",
            "when-registered",
        ),
        (
            "target_attribute",
            "defenseclaw.link.relation",
            "link.relation",
            "typed-json-exact",
            "when-registered",
        ),
    }
    assert len(contract.trace_derivations) == 11
    scope_fields = {field.name: field for field in contract.trace_scope.fields}
    assert scope_fields["name"].const == "defenseclaw.telemetry"
    assert scope_fields["schema_url"].const == "https://defenseclaw.io/schemas/telemetry/v8"
    assert scope_fields["version"].const_present is False
    resource_fields = {field.name: field for field in contract.trace_resource.fields}
    assert resource_fields["schema_url"].const_present is False
    assert {field.name for field in contract.trace_body.fields}.isdisjoint(
        {"trace_id", "span_id", "name", "traceId", "spanId"}
    )
    assert tuple(field.name for field in contract.metric_instrument_data.fields) == (
        "value",
        "attributes",
    )
    assert contract.metric_instrument_data.fields[0].field_type == "metric_number"
    assert contract.metric_instrument_data.fields[0].semantic_ref == "registry.metric_value"
    assert tuple(field.name for field in contract.provenance_import.fields) == (
        "protocol",
        "binding_id",
        "mode",
        "derivation",
        "source_aggregate_count",
        "authenticated_source",
        "upstream_instance_id",
        "upstream_record_id",
        "upstream_service_name",
        "upstream_redaction_profile",
        "ingress_hop_count",
        "last_hop_instance_id",
        "last_hop_destination",
    )
    provenance_fields = {field.name: field for field in contract.provenance.fields}
    assert provenance_fields["import"].object_ref == "provenance_import"
    assert provenance_fields["import"].required is False
    assert dict(provenance_fields["import"].normalization.effective_constraints) == {
        "max_utf8_bytes": 8192,
        "max_item_utf8_bytes": 512,
        "max_items": 13,
        "max_depth": 1,
        "max_properties": 13,
    }
    import_fields = {field.name: field for field in contract.provenance_import.fields}
    assert import_fields["protocol"].const == "otlp"
    assert import_fields["mode"].enum == ("import", "derive", "import_and_derive")
    assert import_fields["derivation"].enum == (
        "field_value",
        "elapsed_time",
        "cumulative_delta",
        "arithmetic_mean",
    )
    assert dict(import_fields["source_aggregate_count"].normalization.effective_constraints) == {
        "min": 1,
        "max": 2**64 - 1,
    }
    assert dict(import_fields["ingress_hop_count"].normalization.effective_constraints) == {
        "min": 0,
        "max": 4,
    }
    assert import_fields["upstream_record_id"].normalization.effective_constraints["pattern"] == (
        "^([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|[a-z0-9][a-z0-9_.-]{0,127})$"
    )
    assert contract.provenance_import_rules.derivation_required_modes == (
        "derive",
        "import_and_derive",
    )
    assert contract.provenance_import_rules.source_aggregate_count_required_derivations == ("arithmetic_mean",)
    assert contract.provenance_import_rules.exact_validation_owner == (
        "internal/observability.ImportProvenance.Validate"
    )
    assert contract.provenance_import_rules.json_schema_runtime_only == (
        "valid_utf8",
        "utf8_byte_length",
    )
    assert [(arm.signal, arm.payload_field) for arm in contract.signal_arms] == [
        ("logs", "body"),
        ("traces", "body"),
        ("metrics", "instrument_data"),
    ]
    assert tuple(condition.id for condition in ir.conditions) == (
        "connector-known-v1",
        "operation-terminal-v1",
        "technical-failure-v1",
        "guardrail-terminal-decision-available-v1",
        "security-severity-available-v1",
        "judge-output-parse-failed-v1",
        "admin-principal-known-v1",
        "agent-reported-cost-available-v1",
        "telemetry-canary-enabled-v1",
        "destination-test-failed-v1",
    )
    assert sum(condition.enforcement.kind == "builder_fact" for condition in ir.conditions) == 8
    attribute_conditions = tuple(
        condition for condition in ir.conditions if condition.enforcement.kind == "boolean_attribute"
    )
    assert tuple(condition.id for condition in attribute_conditions) == (
        "agent-reported-cost-available-v1",
        "telemetry-canary-enabled-v1",
    )
    attribute_condition = attribute_conditions[0]
    assert attribute_condition.id == "agent-reported-cost-available-v1"
    assert attribute_condition.enforcement.fact is None
    assert attribute_condition.enforcement.attribute == "defenseclaw.agent.reported_cost.present"
    assert {condition.false_requirement for condition in ir.conditions} == {"forbidden", "optional"}
    phase_catalog = ir.value_catalogs[0]
    assert phase_catalog.id == "agent-phase-v1"
    assert phase_catalog.kind == "string-int64-bijection"
    assert phase_catalog.value_attributes == (
        "defenseclaw.agent.phase",
        "defenseclaw.agent.phase.previous",
        "defenseclaw.agent.phase.from",
        "defenseclaw.agent.phase.to",
    )
    assert phase_catalog.paired_value_attribute == "defenseclaw.agent.phase"
    assert tuple((entry.value, entry.code) for entry in phase_catalog.entries) == tuple(
        (phase, index) for index, phase in enumerate(_CANONICAL_AGENT_PHASES, 1)
    )
    assert phase_catalog.compatibility.code == 0
    assert phase_catalog.compatibility.value == "unknown"
    assert phase_catalog.compatibility.canonical_emittable is False
    assert dict(contract.canonical_to_otlp.object_contexts)["trace_link"].endswith("links[]")
    assert dict(contract.canonical_to_otlp.field_context_overrides) == {
        "trace_resource.schema_url": "ResourceSpans",
        "trace_scope.schema_url": "ResourceSpans.scopeSpans[]",
    }
    assert ("uint32", "intValue") in contract.canonical_to_otlp.any_value_mapping
    assert contract.canonical_to_otlp.any_value_mapping[-1] == ("object", "kvlistValue")
    with pytest.raises(TypeError):
        contract.limits.values["payload_depth"] = 8


def test_provenance_import_contract_enforces_exact_runtime_only_and_cross_field_rules() -> None:
    module = _load_generator_module("telemetry_registry_provenance_import_rules")
    contract = module.compile_registry(ROOT).structural_contract
    fields = {field.name: field for field in contract.provenance_import.fields}
    rules = contract.provenance_import_rules
    valid = {
        "protocol": "otlp",
        "binding_id": "otlp.genai.span.operation.v1.chat",
        "mode": "import_and_derive",
        "derivation": "arithmetic_mean",
        "source_aggregate_count": 4,
        "authenticated_source": "codex",
        "upstream_instance_id": "upstream-instance-1",
        "upstream_record_id": "123E4567-E89B-12D3-A456-426614174000",
        "upstream_service_name": "upstream-service",
        "upstream_redaction_profile": "sensitive",
        "ingress_hop_count": 4,
        "last_hop_instance_id": "forwarder-instance-1",
        "last_hop_destination": "otlp-primary",
    }

    errors = module._ExampleErrorCollector([])
    lookup = {"provenance_import": contract.provenance_import}
    assert module._validate_structural_object_value(valid, contract.provenance_import, lookup, errors)
    assert module._provenance_import_rules_accept(valid, rules)

    valid_variants = (
        {**valid, "mode": "import", "derivation": None, "source_aggregate_count": None},
        {**valid, "mode": "derive", "derivation": "field_value", "source_aggregate_count": None},
        {**valid, "upstream_record_id": "record.stable-01"},
    )
    for candidate in valid_variants:
        candidate = {key: value for key, value in candidate.items() if value is not None}
        candidate_errors = module._ExampleErrorCollector([])
        assert module._validate_structural_object_value(
            candidate,
            contract.provenance_import,
            lookup,
            candidate_errors,
        )
        assert module._provenance_import_rules_accept(candidate, rules)

    invalid_cross_field = (
        {**valid, "mode": "import"},
        {key: value for key, value in valid.items() if key != "derivation"},
        {key: value for key, value in valid.items() if key != "source_aggregate_count"},
        {**valid, "derivation": "elapsed_time"},
        {**valid, "binding_id": ""},
    )
    assert all(not module._provenance_import_rules_accept(candidate, rules) for candidate in invalid_cross_field)

    assert not module._structural_value_accepts("é" * 257, fields["binding_id"])
    assert not module._structural_value_accepts("\udcff", fields["binding_id"])
    assert module._structural_value_accepts(
        "123E4567-E89B-12D3-A456-426614174000",
        fields["upstream_record_id"],
    )
    assert not module._structural_value_accepts("UPSTREAM-RECORD", fields["upstream_record_id"])


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda contract: contract["provenance_import"]["rules"].__setitem__(
                "derivation_required_modes", ["derive"]
            ),
            "differs from the canonical provenance import rules",
        ),
        (
            lambda contract: contract["provenance_import"]["fields"][1]["normalization"]["overrides"].__setitem__(
                "max_utf8_bytes", 511
            ),
            "provenance import field binding_id differs from the canonical contract",
        ),
        (
            lambda contract: contract["provenance_import"]["rules"].__setitem__("unknown", True),
            "unknown keys ['unknown']",
        ),
    ],
)
def test_provenance_import_registry_contract_fails_closed(
    mutation: Any,
    expected: str,
) -> None:
    module = _load_generator_module(
        "telemetry_registry_provenance_import_drift_" + hashlib.sha256(expected.encode()).hexdigest()[:8]
    )
    ir = module.compile_registry(ROOT)
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    raw = registry["structural_contract"]["provenance_import"]
    mutation(registry["structural_contract"])
    normalizers = {normalizer.id: normalizer for normalizer in ir.normalizers}
    provenance_import = module._parse_structural_object(
        {"additional_properties": raw["additional_properties"], "fields": raw["fields"]},
        "registry.structural_contract.provenance_import",
        "provenance_import",
        normalizers,
    )

    with pytest.raises(module.RegistryError, match=re.escape(expected)):
        module._parse_provenance_import_rules(
            raw["rules"],
            "registry.structural_contract.provenance_import.rules",
            provenance_import,
        )


def test_family_schema_version_materializes_as_uint32_with_exact_otlp_projection() -> None:
    module = _load_generator_module("telemetry_registry_family_schema_version_uint32")

    ir = module.compile_registry(ROOT)
    attribute = next(
        attribute
        for domain in ir.domains
        for attribute in domain.attributes
        if attribute.id == "defenseclaw.span.family_schema_version"
    )
    assert attribute.field_type == "uint32"
    assert dict(attribute.normalization.effective_constraints) == {
        "min": 1,
        "max": 2**32 - 1,
    }
    assert module._attribute_type_accepts(2**32 - 1, attribute.field_type)
    assert not module._attribute_type_accepts(2**32, attribute.field_type)

    materialized_domains = ir.materialized_view.facts["fields"]["domains"]
    materialized_genai = next(domain for domain in materialized_domains if domain["fields"]["domain"] == "genai")
    materialized_attribute = next(
        candidate
        for candidate in materialized_genai["fields"]["attributes"]
        if candidate["fields"]["id"] == "defenseclaw.span.family_schema_version"
    )
    assert materialized_attribute["fields"]["field_type"] == "uint32"
    assert ("uint32", "intValue") in ir.structural_contract.canonical_to_otlp.any_value_mapping
    assert 2**32 - 1 <= 2**63 - 1


@pytest.mark.parametrize(
    ("value", "accepted"),
    (
        ("", True),
        ("vendor=value", True),
        ("tenant@system=value", True),
        ("a=1,b=two words", True),
        ("Vendor=value", False),
        ("vendor=value,vendor=duplicate", False),
        ("vendor=value, other=value", False),
        ("vendor=value ", False),
        ("vendor=value=extra", False),
    ),
)
def test_w3c_tracestate_semantic_format_is_closed(value: str, accepted: bool) -> None:
    module = _load_generator_module("telemetry_registry_w3c_tracestate")
    assert module._w3c_tracestate_accepts(value) is accepted


def test_family_schema_version_above_uint32_is_rejected_before_rendering(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["groups"][0]["x-defenseclaw"]["family_schema_version"] = 2**32
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "x-defenseclaw.family_schema_version: expected integer in [1, 4294967295]" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda registry: registry["structural_contract"]["trace"]["body"]["fields"][1].__setitem__(
                "name", "startTimeUnixNano"
            ),
            "canonical structural names must be snake_case",
        ),
        (
            lambda registry: next(
                field
                for field in registry["structural_contract"]["correlation"]["fields"]
                if field["name"] == "trace_id"
            )["otlp"].__setitem__("target", "wrongTraceId"),
            "typed OTLP mapping mismatch",
        ),
    ],
)
def test_structural_contract_drift_fails_closed(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry)
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda contract: contract["canonical_to_otlp"]["field_context_overrides"].__setitem__(
                "trace_resource.schema_url", "ResourceSpans.resource"
            ),
            "field_context_overrides: differs from OTLP field placement",
        ),
        (
            lambda contract: contract["canonical_to_otlp"]["span_kind_mapping"][4].__setitem__("otlp", 4),
            "span_kind_mapping: differs from OTLP v1",
        ),
        (
            lambda contract: contract["canonical_to_otlp"]["any_value_mapping"][0].__setitem__(
                "otlp_arm", "stringValue"
            ),
            "any_value_mapping: differs from OTLP AnyValue v1",
        ),
    ],
)
def test_otlp_protocol_representation_is_closed(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["structural_contract"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("field_path", "mutation", "expected"),
    [
        (
            ("envelope", "outcome"),
            lambda field: field.__setitem__("field_class", "identifier"),
            "semantic attribute mismatch",
        ),
        (
            ("correlation", "trace_id"),
            lambda field: field["normalization"]["overrides"].__setitem__("max_utf8_bytes", 31),
            "semantic-format mismatch",
        ),
    ],
)
def test_structural_semantic_bindings_reject_local_drift(
    tmp_path: Path,
    field_path: tuple[str, str],
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    object_name, field_name = field_path
    fields = registry["structural_contract"][object_name]["fields"]
    mutation(next(field for field in fields if field["name"] == field_name))
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_runtime_limits_are_source_owned_not_mirrored_in_compiler(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    registry["structural_contract"]["limits"]["payload_depth"] = 31
    _write_yaml(path, registry)
    module = _load_generator_module("telemetry_registry_source_owned_limits")

    ir = module.compile_registry(root)

    assert ir.structural_contract.limits.values["payload_depth"] == 31


def test_conditional_use_requires_registered_stable_condition_id(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    span_core = next(group for group in domain["groups"] if group["id"] == "span.core")
    connector = next(item for item in span_core["attributes"] if item["ref"] == "defenseclaw.connector.source")
    connector["conditional"] = "connector known"
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown condition ID" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda conditions: conditions[1]["enforcement"].__setitem__("fact", conditions[0]["enforcement"]["fact"]),
            "duplicate builder fact",
        ),
        (
            lambda conditions: conditions[0].__setitem__("false_requirement", "required"),
            "false_requirement: unsupported value",
        ),
    ],
)
def test_condition_builder_facts_and_false_semantics_are_closed(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["conditions"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_mandatory_rule_catalog_v1_is_exact_and_materialized(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_mandatory_catalog_exact")

    ir = module.compile_registry(root)
    catalog = ir.mandatory_rule_catalog
    observed = tuple(
        (
            rule.id,
            rule.enforcement.kind,
            rule.enforcement.value if rule.enforcement.kind == "constant" else rule.enforcement.fact,
        )
        for rule in catalog.rules
    )

    assert catalog.version == 1
    assert observed == _MANDATORY_RULE_CATALOG_V1
    materialized = ir.materialized_view.facts["fields"]["mandatory_rule_catalog"]
    assert materialized["$type"] == "MandatoryRuleCatalogIR"
    assert tuple(rule["fields"]["id"] for rule in materialized["fields"]["rules"]) == tuple(
        rule_id for rule_id, _, _ in _MANDATORY_RULE_CATALOG_V1
    )
    assert ir.examples[0].builder_context.inheritance.mode == "explicit"
    assert ir.examples[0].builder_context.occurrence is not None
    assert ir.examples[0].builder_context.occurrence.record_id == "fixture-record-1"
    assert ir.examples[0].builder_context.mandatory_facts == ()
    assert (
        ir.materialized_view.facts["fields"]["examples"][0]["fields"]["builder_context"]["$type"] == "BuilderContextIR"
    )
    with pytest.raises(AttributeError):
        setattr(catalog, "version", 2)
    with pytest.raises(AttributeError):
        setattr(ir.examples[0].builder_context, "condition_facts", ())

    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    reordered_catalog = module.replace(catalog, rules=tuple(reversed(catalog.rules)))
    reordered_values = dict(registry_values, mandatory_rule_catalog=reordered_catalog)
    assert (
        module._build_materialized_registry_view(reordered_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )
    first_fact = ir.examples[0].builder_context.condition_facts[0]
    changed_context = module.replace(
        ir.examples[0].builder_context,
        condition_facts=(
            module.replace(first_fact, value=not first_fact.value),
            *ir.examples[0].builder_context.condition_facts[1:],
        ),
    )
    changed_example = module.replace(ir.examples[0], builder_context=changed_context)
    changed_values = dict(registry_values, examples=(changed_example, *ir.examples[1:]))
    assert (
        module._build_materialized_registry_view(changed_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda catalog: catalog.__setitem__("version", 2),
            "mandatory_rule_catalog.version: unsupported version",
        ),
        (
            lambda catalog: catalog["rules"].pop(),
            "does not match the exact required inventory",
        ),
        (
            lambda catalog: catalog["rules"].reverse(),
            "does not match the exact required inventory",
        ),
        (
            lambda catalog: catalog["rules"].append(
                {
                    "id": "extra_rule",
                    "enforcement": {"kind": "builder_fact", "fact": "extra_rule"},
                }
            ),
            "does not match the exact required inventory",
        ),
        (
            lambda catalog: catalog["rules"][0]["enforcement"].__setitem__("value", False),
            "constant rule must be true",
        ),
        (
            lambda catalog: catalog["rules"][1].__setitem__("id", "always"),
            "duplicate rule ID",
        ),
        (
            lambda catalog: catalog["rules"][2]["enforcement"].__setitem__(
                "fact", catalog["rules"][1]["enforcement"]["fact"]
            ),
            "duplicate builder fact",
        ),
        (
            lambda catalog: catalog["rules"][1]["enforcement"].__setitem__("value", True),
            "unknown keys ['value']",
        ),
        (
            lambda catalog: catalog["rules"][1]["enforcement"].__setitem__("kind", "computed"),
            "enforcement.kind: unsupported value",
        ),
    ],
)
def test_mandatory_rule_catalog_v1_rejects_every_inventory_drift(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["mandatory_rule_catalog"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("surface", "expected"),
    [
        ("log", "mandatory_floor: unknown rule"),
        ("span", "mandatory_floor: allowed only for log families"),
        ("producer", "mandatory_rules: unknown rule"),
        ("legacy_boolean", "unknown keys ['mandatory']"),
    ],
)
def test_mandatory_rule_references_are_catalog_backed_and_signal_closed(
    tmp_path: Path,
    surface: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    if surface == "span":
        path = root / "schemas/telemetry/v8/genai.yaml"
        domain = yaml.safe_load(path.read_text(encoding="utf-8"))
        domain["groups"][0]["x-defenseclaw"]["mandatory_floor"] = ["always"]
    else:
        path = root / "schemas/telemetry/v8/operations.yaml"
        domain = yaml.safe_load(path.read_text(encoding="utf-8"))
        if surface == "log":
            log = next(group for group in domain["groups"] if group["id"] == "diagnostic.message")
            log["x-defenseclaw"]["mandatory_floor"] = ["unknown_rule"]
        elif surface == "producer":
            domain["producer_mappings"][0]["mandatory_rules"] = ["unknown_rule"]
        else:
            domain["producer_mappings"][0]["mandatory"] = True
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_builder_context_occurrence_condition_and_boolean_contract_is_exact(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_builder_context_exact")
    ir = module.compile_registry(root)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    conditions = {condition.id: condition for condition in ir.conditions}
    mandatory_rules = {rule.id: rule for rule in ir.mandatory_rule_catalog.rules}
    family = groups["span.model.chat"]
    source = yaml.safe_load((root / "schemas/telemetry/v8/examples.yaml").read_text(encoding="utf-8"))
    valid = source["examples"][0]
    record = valid["record"]
    base_context = valid["builder_context"]

    cases: tuple[tuple[str, Any, str], ...] = (
        (
            "timestamp mismatch",
            lambda context, _: context["occurrence"].__setitem__("timestamp", "2026-07-03T12:00:01Z"),
            "must equal the record timestamp and record_id",
        ),
        (
            "record ID mismatch",
            lambda context, _: context["occurrence"].__setitem__("record_id", "another-record"),
            "must equal the record timestamp and record_id",
        ),
        (
            "missing fact",
            lambda context, _: context["condition_facts"].pop("connector_known"),
            "coverage mismatch missing=['connector_known']",
        ),
        (
            "extra fact",
            lambda context, _: context["condition_facts"].__setitem__("unregistered", False),
            "extra=['unregistered']",
        ),
        (
            "condition ID instead of enforcement fact",
            lambda context, _: context["condition_facts"].__setitem__(
                "connector-known-v1", context["condition_facts"].pop("connector_known")
            ),
            "missing=['connector_known']",
        ),
        (
            "non-boolean fact",
            lambda context, _: context["condition_facts"].__setitem__("connector_known", 1),
            "condition_facts.connector_known: expected boolean",
        ),
        (
            "true fact lacks field",
            lambda context, _: context["condition_facts"].__setitem__("connector_known", True),
            "true requires defenseclaw.connector.source",
        ),
        (
            "false-forbidden fact has field",
            lambda context, changed_record: (
                changed_record["body"]["attributes"].__setitem__("defenseclaw.connector.source", "fixture"),
                changed_record["field_classes"].__setitem__("/attributes/defenseclaw.connector.source", "identifier"),
            ),
            "false forbids defenseclaw.connector.source",
        ),
    )
    for case_name, mutate, expected in cases:
        context = copy.deepcopy(base_context)
        changed_record = copy.deepcopy(record)
        mutate(context, changed_record)
        with pytest.raises(module.RegistryError) as raised:
            module._parse_explicit_builder_context(
                context,
                f"examples.{case_name}.builder_context",
                signal="traces",
                family=family,
                record=changed_record,
                groups=groups,
                conditions=conditions,
                mandatory_rules=mandatory_rules,
            )
        assert expected in str(raised.value)


def test_builder_condition_fact_coverage_includes_every_trace_container(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_builder_context_trace_coverage")
    ir = module.compile_registry(root)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    conditions = {condition.id: condition for condition in ir.conditions}
    mandatory_rules = {rule.id: rule for rule in ir.mandatory_rule_catalog.rules}
    family = groups["span.model.chat"]
    source = yaml.safe_load((root / "schemas/telemetry/v8/examples.yaml").read_text(encoding="utf-8"))
    record = copy.deepcopy(source["examples"][0]["record"])
    record["body"]["events"] = [{"name": "guardrail.decision", "attributes": {}}]
    record["body"]["links"] = [{"attributes": {}}]

    placements = (
        ("span.model.chat", "defenseclaw.connector.source", "connector-known-v1"),
        ("resource.core", "defenseclaw.outcome", "operation-terminal-v1"),
        ("scope.core", "defenseclaw.outcome", "technical-failure-v1"),
        (
            "event.guardrail.decision",
            "defenseclaw.outcome",
            "guardrail-terminal-decision-available-v1",
        ),
        ("link.core", "defenseclaw.outcome", "security-severity-available-v1"),
    )
    changed_groups = dict(groups)
    for group_id, ref, condition_id in placements:
        use = module.ResolvedAttributeUseIR(
            ref,
            "attributes",
            "conditional",
            condition_id,
            {},
            (),
        )
        changed_groups[group_id] = module.replace(groups[group_id], resolved_uses=(use,))
    family = changed_groups["span.model.chat"]

    contexts = module._example_condition_use_contexts(
        "traces",
        family,
        record,
        changed_groups,
    )
    assert tuple(use.conditional for use, _ in contexts) == tuple(condition_id for _, _, condition_id in placements)
    facts = {conditions[condition_id].enforcement.fact: False for _, _, condition_id in placements}
    context = _explicit_builder_context(record, condition_facts=facts)
    parsed = module._parse_explicit_builder_context(
        context,
        "examples.trace.builder_context",
        signal="traces",
        family=family,
        record=record,
        groups=changed_groups,
        conditions=conditions,
        mandatory_rules=mandatory_rules,
    )
    assert {fact.fact for fact in parsed.condition_facts} == set(facts)
    for fact in facts:
        missing = copy.deepcopy(context)
        missing["condition_facts"].pop(fact)
        with pytest.raises(module.RegistryError, match=f"missing=\\['{fact}'\\]"):
            module._parse_explicit_builder_context(
                missing,
                "examples.trace.builder_context",
                signal="traces",
                family=family,
                record=record,
                groups=changed_groups,
                conditions=conditions,
                mandatory_rules=mandatory_rules,
            )


def test_mandatory_builder_facts_use_or_semantics_and_exact_wire_value(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_mandatory_builder_or")
    ir = module.compile_registry(root)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    conditions = {condition.id: condition for condition in ir.conditions}
    rules = {rule.id: rule for rule in ir.mandatory_rule_catalog.rules}
    log_family = groups["diagnostic.message"]
    record: dict[str, Any] = {
        "timestamp": "2026-07-03T12:00:00Z",
        "record_id": "mandatory-record",
        "body": {},
        "mandatory": False,
    }

    def parse(rule_ids: tuple[str, ...], facts: Mapping[str, Any], wire_value: bool) -> Any:
        changed_record = dict(record, mandatory=wire_value)
        family = module.replace(log_family, mandatory_floor=rule_ids)
        return module._parse_explicit_builder_context(
            _explicit_builder_context(changed_record, mandatory_facts=facts),
            "examples.log.builder_context",
            signal="logs",
            family=family,
            record=changed_record,
            groups=groups,
            conditions=conditions,
            mandatory_rules=rules,
        )

    builder_rules = tuple(rule for rule in ir.mandatory_rule_catalog.rules if rule.id != "always")
    all_rule_ids = tuple(rule.id for rule in builder_rules)
    all_false = {rule.enforcement.fact: False for rule in builder_rules}
    parse(all_rule_ids, all_false, False)
    for selected in builder_rules:
        assert selected.enforcement.fact is not None
        facts = dict(all_false)
        facts[selected.enforcement.fact] = True
        parsed = parse(all_rule_ids, facts, True)
        assert dict((fact.fact, fact.value) for fact in parsed.mandatory_facts) == dict(sorted(facts.items()))
        parse(("always", selected.id), {selected.enforcement.fact: False}, True)

    parse(("always",), {}, True)
    with pytest.raises(module.RegistryError, match="coverage mismatch missing=\\['control_plane_mutation'\\]"):
        parse(("control_plane_mutation",), {}, False)
    with pytest.raises(module.RegistryError, match="extra=\\['unregistered'\\]"):
        parse(("control_plane_mutation",), {"control_plane_mutation": False, "unregistered": False}, False)
    with pytest.raises(module.RegistryError, match="expected boolean"):
        parse(("control_plane_mutation",), {"control_plane_mutation": 1}, False)
    with pytest.raises(module.RegistryError, match="derived mandatory does not equal record.mandatory"):
        parse(("control_plane_mutation",), {"control_plane_mutation": True}, False)


def test_asset_state_log_families_preserve_enforcement_state_change_floor() -> None:
    module = _load_generator_module("telemetry_registry_asset_state_mandatory_floor")
    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    asset_state_families = (
        "log.asset.activated",
        "log.asset.admitted",
        "log.asset.disabled",
        "log.asset.discovered",
        "log.asset.quarantined",
        "log.asset.registered",
        "log.asset.released",
        "log.asset.removed",
        "log.asset.updated",
    )

    assert {family_id: groups[family_id].mandatory_floor for family_id in asset_state_families} == {
        family_id: ("enforcement_state_change",) for family_id in asset_state_families
    }


def test_operations_families_preserve_lossless_control_plane_discovery_and_ingest_facts() -> None:
    module = _load_generator_module("telemetry_registry_operations_lossless_facts")
    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}

    def uses(family_id: str) -> dict[str, Any]:
        return {use.ref: use for use in groups[family_id].resolved_uses}

    admin_fields = {
        "defenseclaw.admin.actor_ref",
        "defenseclaw.admin.origin",
        "defenseclaw.admin.target_ref",
        "defenseclaw.admin.before_summary",
        "defenseclaw.admin.after_summary",
        "defenseclaw.admin.reason",
        "defenseclaw.admin.revision",
        "defenseclaw.admin.current_revision",
        "defenseclaw.admin.change_count",
        "defenseclaw.admin.change_set_hash",
    }
    assert admin_fields <= set(uses("operation.admin"))
    assert admin_fields <= set(uses("body.compliance.activity"))
    assert admin_fields <= set(uses("span.admin.operation"))
    for field_id in ("defenseclaw.admin.before_summary", "defenseclaw.admin.after_summary"):
        attribute = attributes[field_id]
        assert attribute.field_class == "metadata"
        assert attribute.sensitivity == "internal"
        assert attribute.normalization.id == "bounded-v1"
        assert attribute.normalization.effective_constraints["max_utf8_bytes"] == 2048
    assert attributes["defenseclaw.admin.target_ref"].field_class == "identifier"
    assert attributes["defenseclaw.admin.reason"].field_class == "metadata"

    asset_fields = {
        "defenseclaw.asset.id",
        "defenseclaw.asset.type",
        "defenseclaw.asset.target_ref",
        "defenseclaw.asset.target_path",
        "defenseclaw.asset.transition",
        "defenseclaw.asset.transition_reason",
        "defenseclaw.asset.transition_code",
        "defenseclaw.asset.transition_initiator",
        "defenseclaw.asset.previous_state",
        "defenseclaw.asset.resulting_state",
        "defenseclaw.asset.install_action",
        "defenseclaw.asset.file_action",
        "defenseclaw.asset.runtime_action",
    }
    for family_id in (
        "span.asset.transition",
        "log.asset.activated",
        "log.asset.admitted",
        "log.asset.disabled",
        "log.asset.discovered",
        "log.asset.quarantined",
        "log.asset.registered",
        "log.asset.released",
        "log.asset.removed",
        "log.asset.updated",
    ):
        family_uses = uses(family_id)
        assert asset_fields <= set(family_uses)
        assert family_uses["defenseclaw.asset.id"].requirement_level == "required"
        assert family_uses["defenseclaw.asset.type"].requirement_level == "recommended"
        assert groups[family_id].compatibility_profiles == ("local-observability-v1",)
    assert attributes["defenseclaw.asset.target_path"].field_class == "path"
    assert groups["span.asset.scan"].extends == ("span.core", "security.scan", "error.core")
    assert groups["span.asset.scan.phase"].extends == ("span.core", "security.scan", "error.core")
    assert groups["span.network.request"].extends == (
        "span.core",
        "transport.http",
        "security.network.egress",
        "error.core",
    )

    ai_run_fields = {
        "defenseclaw.ai.discovery.scan_id",
        "defenseclaw.ai.discovery.source",
        "defenseclaw.ai.discovery.privacy_mode",
        "defenseclaw.ai.discovery.result",
        "defenseclaw.ai.discovery.duration_ms",
        "defenseclaw.ai.discovery.signals_total",
        "defenseclaw.ai.discovery.active_signals",
        "defenseclaw.ai.discovery.new_signals",
        "defenseclaw.ai.discovery.changed_signals",
        "defenseclaw.ai.discovery.gone_signals",
        "defenseclaw.ai.discovery.files_scanned",
        "defenseclaw.ai.discovery.dedupe_suppressed",
        "defenseclaw.ai.discovery.errors",
    }
    assert ai_run_fields <= set(uses("span.ai.discovery"))
    assert ai_run_fields <= set(uses("log.ai.discovery.completed"))
    assert groups["log.ai.discovery.completed"].allowed_outcomes == ("completed", "partial")
    detector_fields = {
        "defenseclaw.ai.discovery.detector",
        "defenseclaw.ai.discovery.duration_ms",
        "defenseclaw.ai.discovery.signals_total",
        "defenseclaw.ai.discovery.files_scanned",
    }
    assert detector_fields <= set(uses("span.ai.discovery.detector"))
    component_fields = {
        "defenseclaw.ai.component.vendor",
        "defenseclaw.ai.component.product",
        "defenseclaw.ai.component.identity_score",
        "defenseclaw.ai.component.identity_band",
        "defenseclaw.ai.component.presence_score",
        "defenseclaw.ai.component.presence_band",
        "defenseclaw.ai.component.install_count",
        "defenseclaw.ai.component.workspace_count",
        "defenseclaw.ai.component.detector_count",
        "defenseclaw.ai.component.policy_version",
    }
    for family_id in (
        "log.ai_component.changed",
        "log.ai_component.confidence.changed",
        "log.ai_component.discovered",
        "log.ai_component.removed",
    ):
        assert component_fields <= set(uses(family_id))
        assert groups[family_id].compatibility_profiles == ("local-observability-v1",)

    agent_summary = {
        "defenseclaw.agent.discovery.source",
        "defenseclaw.agent.discovery.cache_hit",
        "defenseclaw.agent.discovery.result",
        "defenseclaw.agent.discovery.duration_ms",
        "defenseclaw.agent.discovery.agents_total",
        "defenseclaw.agent.discovery.installed_total",
    }
    for family_id, allowed_outcomes in (
        ("log.agent.discovery.completed", ("completed",)),
        ("log.agent.discovery.rejected", ("rejected",)),
    ):
        assert agent_summary == set(uses(family_id))
        assert groups[family_id].bucket == "agent.lifecycle"
        assert groups[family_id].allowed_outcomes == allowed_outcomes
    completed_uses = uses("log.agent.discovery.completed")
    assert all(completed_uses[field_id].requirement_level == "required" for field_id in agent_summary)
    rejected_uses = uses("log.agent.discovery.rejected")
    assert rejected_uses["defenseclaw.agent.discovery.source"].requirement_level == "required"
    assert rejected_uses["defenseclaw.agent.discovery.result"].requirement_level == "required"
    assert all(
        rejected_uses[field_id].requirement_level == "recommended"
        for field_id in agent_summary - {"defenseclaw.agent.discovery.source", "defenseclaw.agent.discovery.result"}
    )
    assert set(uses("log.agent.discovery.signal")) == {
        "defenseclaw.agent.discovery.connector",
        "defenseclaw.agent.discovery.installed",
        "defenseclaw.agent.discovery.has_config",
        "defenseclaw.agent.discovery.has_binary",
        "defenseclaw.agent.discovery.probe_status",
    }
    assert groups["log.agent.discovery.signal"].outcome_requirement == "forbidden"

    telemetry_fields = {
        "defenseclaw.telemetry.signal",
        "defenseclaw.telemetry.payload_format",
        "defenseclaw.telemetry.record_count",
        "defenseclaw.telemetry.resource_count",
        "defenseclaw.telemetry.wire_bytes",
        "defenseclaw.telemetry.normalized_bytes",
        "defenseclaw.telemetry.latency_ms",
        "defenseclaw.telemetry.rejection_reason_class",
    }
    for family_id in (
        "span.telemetry.receive",
        "span.telemetry.normalize",
        "log.telemetry.batch.accepted",
        "log.telemetry.batch.normalized",
        "log.telemetry.batch.rejected",
    ):
        assert telemetry_fields <= set(uses(family_id))
        assert groups[family_id].compatibility_profiles == ("local-observability-v1",)
    assert uses("body.telemetry.ingest")["defenseclaw.telemetry.byte_count"].requirement_level == "required"
    assert attributes["defenseclaw.telemetry.rejection_reason_class"].field_class == "metadata"
    assert attributes["defenseclaw.telemetry.rejection_reason_class"].sensitivity == "internal"


def test_trace_and_metric_builder_contexts_forbid_mandatory_facts(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_non_log_mandatory_facts")
    ir = module.compile_registry(root)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    conditions = {condition.id: condition for condition in ir.conditions}
    rules = {rule.id: rule for rule in ir.mandatory_rule_catalog.rules}
    source = yaml.safe_load((root / "schemas/telemetry/v8/examples.yaml").read_text(encoding="utf-8"))
    trace = source["examples"][0]
    trace_context = copy.deepcopy(trace["builder_context"])
    trace_context["mandatory_facts"] = {"control_plane_mutation": False}
    metric_family = next(group for group in groups.values() if group.type == "metric")
    metric_record = {
        "timestamp": "2026-07-03T12:00:02Z",
        "record_id": "metric-record",
        "instrument_data": {"attributes": {}},
    }

    with pytest.raises(module.RegistryError, match="extra=\\['control_plane_mutation'\\]"):
        module._parse_explicit_builder_context(
            trace_context,
            "examples.trace.builder_context",
            signal="traces",
            family=groups["span.model.chat"],
            record=trace["record"],
            groups=groups,
            conditions=conditions,
            mandatory_rules=rules,
        )
    parsed = module._parse_explicit_builder_context(
        _explicit_builder_context(metric_record),
        "examples.metric.builder_context",
        signal="metrics",
        family=metric_family,
        record=metric_record,
        groups=groups,
        conditions=conditions,
        mandatory_rules=rules,
    )
    assert parsed.mandatory_facts == ()
    with pytest.raises(module.RegistryError, match="extra=\\['control_plane_mutation'\\]"):
        module._parse_explicit_builder_context(
            _explicit_builder_context(
                metric_record,
                mandatory_facts={"control_plane_mutation": False},
            ),
            "examples.metric.builder_context",
            signal="metrics",
            family=metric_family,
            record=metric_record,
            groups=groups,
            conditions=conditions,
            mandatory_rules=rules,
        )


def test_invalid_example_builder_context_is_exact_base_only(tmp_path: Path) -> None:
    module = _load_generator_module("telemetry_registry_builder_context_inheritance")
    parsed = module._parse_inherited_builder_context(
        _exact_base_builder_context("model.chat.valid"),
        "examples.invalid.builder_context",
        "model.chat.valid",
    )
    assert parsed.inheritance.mode == "exact_base"
    assert parsed.inheritance.base_example == "model.chat.valid"
    assert parsed.occurrence is None
    assert parsed.condition_facts == ()
    assert parsed.mandatory_facts == ()

    cases = (
        (
            _exact_base_builder_context("other.valid"),
            "must equal example base_example",
        ),
        (
            {"inheritance": {"mode": "explicit", "base_example": "model.chat.valid"}},
            "invalid example requires exact_base",
        ),
        (
            {
                **_exact_base_builder_context("model.chat.valid"),
                "condition_facts": {},
            },
            "unknown keys ['condition_facts']",
        ),
    )
    for value, expected in cases:
        with pytest.raises(module.RegistryError) as raised:
            module._parse_inherited_builder_context(
                value,
                "examples.invalid.builder_context",
                "model.chat.valid",
            )
        assert expected in str(raised.value)


def test_signal_family_requires_explicit_lifecycle(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"][0].pop("introduced_in")
    _write_yaml_raw(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "introduced_in: required for every group" in result.stderr


@pytest.mark.parametrize(
    "attribute_id",
    [
        "defenseclaw.agent.phase",
        "defenseclaw.agent.phase.previous",
        "defenseclaw.agent.phase.from",
        "defenseclaw.agent.phase.to",
    ],
)
def test_phase_value_catalog_binds_every_value_attribute_enum(
    tmp_path: Path,
    attribute_id: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    phase = next(item for item in domain["attributes"] if item["id"] == attribute_id)
    phase["normalization"]["overrides"]["enum"].append("invented")
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "must use the exact catalog enum" in result.stderr


def test_phase_value_catalog_binds_code_range(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    phase_code = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.agent.phase.code")
    phase_code["normalization"]["overrides"]["min"] = 0
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "code attribute must use the exact catalog range" in result.stderr


def test_nonstring_paired_phase_value_reports_validation_instead_of_type_error(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    domain["groups"][0]["attributes"].extend(
        [
            {"ref": "defenseclaw.agent.phase", "requirement_level": "optional"},
            {"ref": "defenseclaw.agent.phase.code", "requirement_level": "optional"},
        ]
    )
    _write_yaml(domain_path, domain)
    path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    record["body"]["attributes"]["defenseclaw.agent.phase"] = []
    record["body"]["attributes"]["defenseclaw.agent.phase.code"] = 2
    record["field_classes"]["/attributes/defenseclaw.agent.phase"] = "metadata"
    record["field_classes"]["/attributes/defenseclaw.agent.phase.code"] = "metadata"
    _write_yaml(path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "dynamic_attribute_value_invalid" in result.stderr
    assert "unhashable type" not in result.stderr


def test_removed_group_cannot_remain_route_selectable(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    group = domain["groups"][0]
    group.update(
        {
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    _write_yaml(path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "removed group cannot remain route-selectable" in result.stderr


@pytest.mark.parametrize(
    ("value", "constraints"),
    [
        ({"outer": {"inner": "value"}}, {"max_depth": 0}),
        ({"outer": {"inner": "value"}}, {"max_properties": 1}),
        ({"outer": [1, 2]}, {"max_items": 2}),
        ({"outer": "four"}, {"max_item_utf8_bytes": 3}),
        ({"outer": "value"}, {"max_utf8_bytes": 8}),
        ({"outer": float("nan")}, {}),
    ],
)
def test_recursive_normalization_rejects_every_structured_bound(
    value: Any,
    constraints: dict[str, Any],
) -> None:
    module = _load_generator_module("telemetry_registry_recursive_normalization")

    assert module._constraints_accept(value, constraints) is False


# Produced by internal/observability.NewValue (marshalMinimalJSON) and kept here
# as cross-language byte-accounting goldens for the registry compiler.
_GO_CANONICAL_JSON_GOLDENS = (
    ("float-1e-6", {"n": 1e-6}, '{"n":1e-6}'),
    ("float-1e-7", {"n": 1e-7}, '{"n":1e-7}'),
    ("float-1e20", {"n": 1e20}, '{"n":1e20}'),
    ("float-1e21", {"n": 1e21}, '{"n":1e21}'),
    ("negative-zero", {"n": -0.0}, '{"n":0}'),
    ("int-million", {"n": 1_000_000}, '{"n":1e6}'),
    ("int-max", {"n": 2**63 - 1}, '{"n":9223372036854775807}'),
    ("html-line-separators", {"text": "<>&\u2028\u2029"}, '{"text":"<>&\u2028\u2029"}'),
    (
        "nested-key-and-string-escapes",
        {
            "z/key": ["line\n", 'quote"', "slash\\"],
            "a~key": {"control": "\b\f\r\t\u0001"},
        },
        '{"a~key":{"control":"\\b\\f\\r\\t\\u0001"},"z/key":["line\\n","quote\\"","slash\\\\"]}',
    ),
)


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    _GO_CANONICAL_JSON_GOLDENS,
    ids=[item[0] for item in _GO_CANONICAL_JSON_GOLDENS],
)
def test_structured_byte_budget_matches_go_canonical_json_at_n_and_n_plus_one(
    name: str,
    value: Any,
    expected: str,
) -> None:
    del name
    module = _load_generator_module("telemetry_registry_go_canonical_json")
    expected_bytes = expected.encode("utf-8")

    assert module._canonical_json_bytes(value) == expected_bytes
    assert module._constraints_accept(value, {"max_utf8_bytes": len(expected_bytes)}) is True
    assert module._constraints_accept(value, {"max_utf8_bytes": len(expected_bytes) - 1}) is False


def test_array_types_validate_every_item_and_finite_numbers() -> None:
    module = _load_generator_module("telemetry_registry_array_item_types")

    assert module._attribute_type_accepts(["one", "two"], "string[]") is True
    assert module._attribute_type_accepts(["one", 2], "string[]") is False
    assert module._attribute_type_accepts([1, 2**63], "int64[]") is False
    assert module._attribute_type_accepts([1.0, float("inf")], "double[]") is False


@pytest.mark.parametrize("owner", ["local", "upstream"])
def test_materialized_examples_enforce_declared_dynamic_attribute_types(
    tmp_path: Path,
    owner: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    group = domain["groups"][0]
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    if owner == "local":
        attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
        attribute["type"] = "string[]"
        attribute["examples"] = [["fixture"]]
        attribute["normalization"] = {
            "id": "bounded-v1",
            "overrides": {"max_utf8_bytes": 128, "max_item_utf8_bytes": 64, "max_items": 4},
        }
        reference = "defenseclaw.test.name"
        value = ["valid", 7]
    else:
        reference = "gen_ai.operation.name"
        value = 7
    if not any(item["ref"] == reference for item in group["attributes"]):
        group["attributes"].append({"ref": reference, "requirement_level": "required"})
    record["body"]["attributes"][reference] = value
    for pointer in _load_generator_module("telemetry_registry_type_pointer")._json_leaf_pointers(
        value,
        f"/attributes/{reference}",
    ):
        record["field_classes"][pointer] = "metadata"
    _write_yaml(path, domain)
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "dynamic_attribute_value_invalid" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda attribute: attribute.__setitem__("examples", [7]),
            "value does not match declared attribute type",
        ),
        (
            lambda attribute: attribute.__setitem__("examples", [None]),
            "value does not match declared attribute type",
        ),
        (
            lambda attribute: attribute.update(
                {
                    "examples": ["12345"],
                    "normalization": {
                        "id": "bounded-v1",
                        "overrides": {"max_utf8_bytes": 4},
                    },
                }
            ),
            "value violates declared normalization",
        ),
        (
            lambda attribute: attribute.update(
                {
                    "type": "string[]",
                    "examples": [["valid", 7]],
                    "normalization": {
                        "id": "bounded-v1",
                        "overrides": {
                            "max_utf8_bytes": 128,
                            "max_item_utf8_bytes": 64,
                            "max_items": 4,
                        },
                    },
                }
            ),
            "value does not match declared attribute type",
        ),
        (
            lambda attribute: attribute.update(
                {
                    "type": "object",
                    "examples": [{"nested": {"deeper": {}}}],
                    "normalization": {
                        "id": "structured-content-v1",
                        "overrides": {
                            "max_utf8_bytes": 128,
                            "max_item_utf8_bytes": 64,
                            "max_items": 4,
                            "max_depth": 1,
                            "max_properties": 4,
                        },
                    },
                }
            ),
            "value violates declared normalization",
        ),
    ],
)
def test_local_attribute_examples_are_executable_typed_metadata(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
    mutation(attribute)
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_field_class_derivation_matches_go_leaf_and_rfc6901_rules(tmp_path: Path) -> None:
    module = _load_generator_module("telemetry_registry_recursive_field_classes")
    value = {"a/b": {"~x": [None, "value"]}, "empty": {}}
    assert module._json_leaf_pointers(value) == (
        "/a~1b/~0x/0",
        "/a~1b/~0x/1",
        "/empty",
    )

    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
    attribute["type"] = "object"
    attribute["examples"] = [{}]
    attribute["normalization"] = {
        "id": "structured-content-v1",
        "overrides": {
            "max_utf8_bytes": 1024,
            "max_item_utf8_bytes": 64,
            "max_items": 16,
            "max_depth": 4,
            "max_properties": 8,
        },
    }
    domain["groups"][0]["attributes"].append({"ref": "defenseclaw.test.name", "requirement_level": "required"})
    _write_yaml(domain_path, domain)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    record = examples["examples"][0]["record"]
    record["body"]["attributes"]["defenseclaw.test.name"] = value
    prefix = "/attributes/defenseclaw.test.name"
    for pointer in module._json_leaf_pointers(value, prefix):
        record["field_classes"][pointer] = "metadata"
    _write_yaml(examples_path, examples)

    accepted = _run(root, "--write")
    assert accepted.returncode == 0, accepted.stderr

    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    classes = examples["examples"][0]["record"]["field_classes"]
    for pointer in tuple(classes):
        if pointer.startswith(prefix):
            classes.pop(pointer)
    classes[prefix] = "metadata"
    _write_yaml(examples_path, examples)
    rejected = _run(root, "--write")
    assert rejected.returncode == 1
    assert "coverage mismatch" in rejected.stderr


def test_every_pseudo_semantic_ref_is_required_exactly_once(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    event_name = next(
        field for field in registry["structural_contract"]["envelope"]["fields"] if field["name"] == "event_name"
    )
    event_name.pop("semantic_ref")
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "missing pseudo semantic_ref" in result.stderr


def test_invalid_mutation_projection_uses_typed_json_equality(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["body"]["start_time_unix_nano"] = 1.0
    document["examples"].append(
        {
            "id": "model-chat-typed-projection-invalid",
            "valid": False,
            "signal": "traces",
            "family": "span.model.chat",
            "description": "Integer and double JSON values are not projection-equal.",
            "record": invalid_record,
            "expected_error": "structural_field_value_invalid",
            "base_example": valid["id"],
            "builder_context": {
                "inheritance": {"mode": "exact_base", "base_example": valid["id"]},
            },
            "mutation": {
                "kind": "structural_field_value_invalid",
                "changes": [
                    {
                        "op": "replace",
                        "path": "/record/body/start_time_unix_nano",
                        "value": 1,
                    }
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "derived vector does not equal" in result.stderr


def test_invalid_example_must_have_exactly_one_stable_error(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["bucket"] = "diagnostic"
    invalid_record["event_name"] = "invalid.event.name"
    invalid_record["field_classes"]["/kind"] = "content"
    document["examples"].append(
        {
            "id": "model-chat-two-errors-invalid",
            "valid": False,
            "signal": "traces",
            "family": "span.model.chat",
            "description": "Two independent errors cannot masquerade as one negative vector.",
            "record": invalid_record,
            "expected_error": "family_event_name_mismatch",
            "base_example": valid["id"],
            "builder_context": {
                "inheritance": {"mode": "exact_base", "base_example": valid["id"]},
            },
            "mutation": {
                "kind": "family_event_name_mismatch",
                "changes": [
                    {"op": "replace", "path": "/record/bucket", "value": "diagnostic"},
                    {
                        "op": "replace",
                        "path": "/record/event_name",
                        "value": "invalid.event.name",
                    },
                    {
                        "op": "replace",
                        "path": "/record/field_classes/~1kind",
                        "value": "content",
                    },
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "expected only 'family_event_name_mismatch'" in result.stderr
    assert "family_bucket_mismatch" in result.stderr
    assert "field_class_classification_mismatch" in result.stderr


def test_invalid_example_does_not_swallow_noncoverage_field_class_errors(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    invalid_record = copy.deepcopy(valid["record"])
    invalid_record["field_classes"] = []
    document["examples"].append(
        {
            "id": "model-chat-field-class-shape-invalid",
            "valid": False,
            "signal": "traces",
            "family": "span.model.chat",
            "description": "A malformed classification container is not a coverage-only negative vector.",
            "record": invalid_record,
            "expected_error": "field_class_coverage_mismatch",
            "base_example": valid["id"],
            "builder_context": {
                "inheritance": {"mode": "exact_base", "base_example": valid["id"]},
            },
            "mutation": {
                "kind": "field_class_coverage_mismatch",
                "changes": [
                    {
                        "op": "replace",
                        "path": "/record/field_classes",
                        "value": [],
                    }
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "field_classes: expected mapping" in result.stderr


def test_signal_root_mutation_is_replayed_as_part_of_the_typed_vector(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/examples.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    valid = document["examples"][0]
    log_record = {
        "schema_version": 1,
        "bucket_catalog_version": 1,
        "timestamp": "2026-07-03T12:00:00Z",
        "record_id": "fixture-log-invalid-signal",
        "bucket": "diagnostic",
        "signal": "traces",
        "event_name": "diagnostic.message",
        "source": "gateway",
        "correlation": {},
        "provenance": {
            "producer": "defenseclaw",
            "binary_version": "8.0.0",
            "registry_schema_version": 1,
            "config_generation": 1,
        },
        "body": {},
        "mandatory": False,
        "field_classes": {"": "metadata"},
    }
    document["examples"].append(
        {
            "id": "diagnostic-signal-root-invalid",
            "valid": False,
            "signal": "logs",
            "family": "diagnostic.message",
            "description": "The vector signal discriminator is replayed, not ignored.",
            "record": log_record,
            "expected_error": "example_signal_mismatch",
            "base_example": valid["id"],
            "builder_context": {
                "inheritance": {"mode": "exact_base", "base_example": valid["id"]},
            },
            "mutation": {
                "kind": "example_signal_mismatch",
                "changes": [
                    {"op": "replace", "path": "/signal", "value": "logs"},
                    {"op": "replace", "path": "/family", "value": "diagnostic.message"},
                    {"op": "replace", "path": "/record", "value": copy.deepcopy(log_record)},
                ],
            },
        }
    )
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda group: group.__setitem__("introduced_in", "v1"), "expected telemetry-registry-vN"),
        (
            lambda group: group.update(
                {
                    "stability": "deprecated",
                    "deprecated_in": "telemetry-registry-v1",
                    "removed_in": "telemetry-registry-v1",
                }
            ),
            "removed_in: must follow deprecated_in",
        ),
    ],
)
def test_lifecycle_versions_are_semantic_and_strictly_ordered(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(domain["groups"][0])
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


def test_future_removal_remains_active_until_its_registry_version(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"][0].update(
        {
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    _write_yaml(path, domain)

    result = _run(root, "--write")

    assert result.returncode == 0, result.stderr


def test_removed_non_signal_group_without_route_selector_is_historical_only(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    domain["groups"].append(
        {
            "id": "historical.attributes",
            "type": "attribute_group",
            "brief": "A removed non-signal group.",
            "stability": "deprecated",
            "introduced_in": "telemetry-registry-v1",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
            "attributes": [],
        }
    )
    _write_yaml(path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)
    module = _load_generator_module("telemetry_registry_historical_non_signal")

    ir = module.compile_registry(root)

    assert all(
        group.id != "historical.attributes" for compiled_domain in ir.domains for group in compiled_domain.groups
    )


def test_active_group_cannot_reference_removed_attribute(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(path.read_text(encoding="utf-8"))
    attribute = next(item for item in domain["attributes"] if item["id"] == "defenseclaw.test.name")
    attribute.update(
        {
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    domain["groups"][0]["attributes"].append({"ref": "defenseclaw.test.name", "requirement_level": "optional"})
    _write_yaml(path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "unknown attribute reference" in result.stderr


def test_removed_family_cannot_be_used_by_current_examples(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    domain_path = root / "schemas/telemetry/v8/genai.yaml"
    domain = yaml.safe_load(domain_path.read_text(encoding="utf-8"))
    retired = copy.deepcopy(domain["groups"][0])
    retired.update(
        {
            "id": "span.retired.fixture",
            "stability": "deprecated",
            "deprecated_in": "telemetry-registry-v1",
            "removed_in": "telemetry-registry-v2",
        }
    )
    retired["x-defenseclaw"]["route_selector"] = False
    domain["groups"].append(retired)
    _write_yaml(domain_path, domain)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = 2
    _write_yaml(registry_path, registry)
    examples_path = root / "schemas/telemetry/v8/examples.yaml"
    examples = yaml.safe_load(examples_path.read_text(encoding="utf-8"))
    retired_example = copy.deepcopy(examples["examples"][0])
    retired_example["id"] = "retired-family-current-invalid"
    retired_example["family"] = "span.retired.fixture"
    examples["examples"].append(retired_example)
    _write_yaml(examples_path, examples)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert "family: unknown family" in result.stderr


def test_normalizer_bounds_are_source_owned_not_literal_cloned(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    bounded = next(item for item in registry["normalizers"] if item["id"] == "bounded-v1")
    bounded["default_constraints"]["max_utf8_bytes"] = 4095
    _write_yaml(path, registry)
    module = _load_generator_module("telemetry_registry_source_owned_normalizer")

    ir = module.compile_registry(root)

    compiled = next(item for item in ir.normalizers if item.id == "bounded-v1")
    assert compiled.default_constraints["max_utf8_bytes"] == 4095


def test_materialized_registry_view_is_complete_recursive_and_immutable(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_view")

    ir = module.compile_registry(root)
    view = ir.materialized_view

    assert view.format == "defenseclaw-materialized-registry-view-v1"
    assert len(view.typed_canonical_json_sha256) == 64
    typed_bytes = module._canonical_json_bytes(module._typed_materialized_node(view.facts))
    assert (
        view.typed_canonical_json_sha256
        == hashlib.sha256(module.MATERIALIZED_VIEW_DIGEST_DOMAIN + typed_bytes).hexdigest()
    )
    registry_field_names = {
        field.name for field in module.dataclass_fields(module.RegistryIR) if field.name != "materialized_view"
    }
    assert set(view.facts["fields"]) == registry_field_names
    assert view.facts["$type"] == "RegistryIR"
    assert view.facts["fields"]["structural_contract"]["$type"] == "StructuralContractIR"
    assert view.facts["fields"]["examples"][0]["$type"] == "ExampleIR"

    observed_keys: set[str] = set()

    def assert_frozen(value: Any) -> None:
        assert not isinstance(value, (dict, list, set))
        assert not module.is_dataclass(value)
        if isinstance(value, Mapping):
            observed_keys.update(value)
            for child in value.values():
                assert_frozen(child)
        elif isinstance(value, tuple):
            for child in value:
                assert_frozen(child)

    assert_frozen(view.facts)
    assert {"field_class", "sensitivity", "introduced_in", "canonical_to_otlp"} <= observed_keys
    with pytest.raises(TypeError):
        view.facts["new"] = "mutable"
    with pytest.raises(TypeError):
        view.facts["fields"]["schema_version"] = 2

    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    reversed_values = dict(reversed(tuple(registry_values.items())))
    rebuilt = module._build_materialized_registry_view(reversed_values)
    assert rebuilt.facts == view.facts
    assert rebuilt.typed_canonical_json_sha256 == view.typed_canonical_json_sha256


def test_materialized_digest_is_typed_and_hash_seed_deterministic(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_digest")
    typed_values = {
        module._canonical_json_bytes(module._typed_materialized_node({"value": value})) for value in (b"1", "1", 1, 1.0)
    }
    assert len(typed_values) == 4
    assert module._freeze_json(b"\x00\xff") == b"\x00\xff"
    assert module._typed_materialized_node(b"\x00\xff") == ("bytes", "00ff")
    assert module._materialize_registry_fact(b"\x00\xff") == b"\x00\xff"

    observed: list[str] = []
    for seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        result = _run(root, "--write", environment=environment)
        assert result.returncode == 0, result.stderr
        catalog = module.runtime_assets.LOGICAL_TO_ENCODED[
            "schemas/telemetry/generated/catalog.json"
        ]
        payload = module.runtime_assets.decode_canonical_gzip((root / catalog).read_bytes())
        observed.append(json.loads(payload)["materialized_view_sha256"])
    assert len(set(observed)) == 1


def test_real_registry_materialized_digest_is_hash_seed_deterministic() -> None:
    probe = """
import importlib.util
import sys
from pathlib import Path

generator = Path(sys.argv[1])
root = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("telemetry_registry_real_seed_probe", generator)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load telemetry registry generator")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
print(module.compile_registry(root).materialized_view.typed_canonical_json_sha256)
"""
    observed: list[str] = []
    for seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", probe, str(GENERATOR), str(ROOT)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        observed.append(result.stdout.strip())
    assert len(set(observed)) == 1
    assert len(observed[0]) == 64


def test_materialized_digest_preserves_ordered_registry_sequences(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_ordered_sequences")
    ir = module.compile_registry(root)
    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    ordered_fields = (
        "imports",
        "input_digests",
        "dependencies",
        "normalizers",
        "conditions",
        "domains",
        "group_resolution_order",
        "upstream_attribute_ownership",
    )

    for field_name in ordered_fields:
        original = registry_values[field_name]
        assert isinstance(original, tuple) and len(original) > 1
        reordered = dict(registry_values)
        reordered[field_name] = tuple(reversed(original))
        rebuilt = module._build_materialized_registry_view(reordered)
        assert rebuilt.typed_canonical_json_sha256 != ir.materialized_view.typed_canonical_json_sha256

    second_example = module.replace(ir.examples[0], id="model-chat-valid-second")
    first_examples = dict(registry_values, examples=(ir.examples[0], second_example))
    second_examples = dict(registry_values, examples=(second_example, ir.examples[0]))
    assert (
        module._build_materialized_registry_view(first_examples).typed_canonical_json_sha256
        != module._build_materialized_registry_view(second_examples).typed_canonical_json_sha256
    )


def test_materialized_digest_preserves_nested_fields_uses_arms_and_changes(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_nested_order")
    ir = module.compile_registry(root)
    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }

    envelope = ir.structural_contract.envelope
    reordered_contract = module.replace(
        ir.structural_contract,
        envelope=module.replace(envelope, fields=tuple(reversed(envelope.fields))),
    )
    fields_values = dict(registry_values, structural_contract=reordered_contract)
    assert (
        module._build_materialized_registry_view(fields_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    reordered_contract = module.replace(
        ir.structural_contract,
        signal_arms=tuple(reversed(ir.structural_contract.signal_arms)),
    )
    arms_values = dict(registry_values, structural_contract=reordered_contract)
    assert (
        module._build_materialized_registry_view(arms_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    domain_index, domain, group_index, group = next(
        (domain_index, domain, group_index, group)
        for domain_index, domain in enumerate(ir.domains)
        for group_index, group in enumerate(domain.groups)
        if len(group.attribute_uses) > 1
    )
    changed_groups = list(domain.groups)
    changed_groups[group_index] = module.replace(group, attribute_uses=tuple(reversed(group.attribute_uses)))
    changed_domains = list(ir.domains)
    changed_domains[domain_index] = module.replace(domain, groups=tuple(changed_groups))
    uses_values = dict(registry_values, domains=tuple(changed_domains))
    assert (
        module._build_materialized_registry_view(uses_values).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    changes = (
        module.ExampleMutationChangeIR("replace", "/record/bucket", True, "model.io"),
        module.ExampleMutationChangeIR("remove", "/record/outcome", False, None),
    )
    first_example = module.replace(
        ir.examples[0],
        mutation=module.ExampleMutationIR("single_fault", changes),
    )
    second_example = module.replace(
        first_example,
        mutation=module.ExampleMutationIR("single_fault", tuple(reversed(changes))),
    )
    first_values = dict(registry_values, examples=(first_example, *ir.examples[1:]))
    second_values = dict(registry_values, examples=(second_example, *ir.examples[1:]))
    assert (
        module._build_materialized_registry_view(first_values).typed_canonical_json_sha256
        != module._build_materialized_registry_view(second_values).typed_canonical_json_sha256
    )


def test_materialized_digest_canonicalizes_declared_set_fields_only(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_materialized_declared_sets")
    ir = module.compile_registry(root)
    registry_values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    normalizer_index, normalizer = next(
        (index, item) for index, item in enumerate(ir.normalizers) if len(item.allowed_overrides) > 1
    )
    changed_normalizers = list(ir.normalizers)
    changed_normalizers[normalizer_index] = module.replace(
        normalizer,
        allowed_overrides=tuple(reversed(normalizer.allowed_overrides)),
    )
    reordered = dict(registry_values, normalizers=tuple(changed_normalizers))
    assert (
        module._build_materialized_registry_view(reordered).typed_canonical_json_sha256
        == ir.materialized_view.typed_canonical_json_sha256
    )
    changed_normalizers[normalizer_index] = module.replace(
        normalizer,
        allowed_overrides=normalizer.allowed_overrides[:-1],
    )
    membership_changed = dict(registry_values, normalizers=tuple(changed_normalizers))
    assert (
        module._build_materialized_registry_view(membership_changed).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )

    snapshot = module.SnapshotAttribute(
        "fixture",
        ("string", "int64"),
        "attribute",
        "stable",
        "upstream",
        "fixture#/attribute",
        (),
        False,
    )
    reversed_snapshot = module.replace(snapshot, allowed_types=tuple(reversed(snapshot.allowed_types)))
    assert module._materialize_registry_fact(snapshot) == module._materialize_registry_fact(reversed_snapshot)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda contract: contract["trace"]["derivations"].pop(),
            "trace.derivations: binding inventory mismatch",
        ),
        (
            lambda contract: contract["trace"]["derivations"][0].__setitem__("equality", "string-coercion"),
            "trace.derivations: binding inventory mismatch",
        ),
        (
            lambda contract: contract["trace"]["derivations"][0].__setitem__("target_field", "trace_scope.version"),
            "expected exactly one of target_attribute or target_field",
        ),
        (
            lambda contract: contract["trace"]["derivations"][0].pop("target_attribute"),
            "expected exactly one of target_attribute or target_field",
        ),
        (
            lambda contract: contract.__setitem__("derivations", contract["trace"].pop("derivations")),
            "registry.structural_contract: unknown keys ['derivations']",
        ),
    ],
)
def test_trace_derivations_are_complete_exact_and_trace_scoped(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutation(registry["structural_contract"])
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda scope, _resource: scope["schema_url"].pop("const"),
            "instrumentation-scope schema URL mismatch",
        ),
        (
            lambda scope, _resource: scope["schema_url"].__setitem__("const", "https://example.invalid/telemetry/v8"),
            "instrumentation-scope schema URL mismatch",
        ),
        (
            lambda _scope, resource: resource["schema_url"].__setitem__(
                "const", "https://opentelemetry.io/schemas/1.42.0"
            ),
            "resource schema URL must remain producer input",
        ),
    ],
)
def test_trace_scope_constants_and_resource_schema_url_input_are_exact(
    tmp_path: Path,
    mutation: Any,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    trace = registry["structural_contract"]["trace"]
    scope = {field["name"]: field for field in trace["scope"]["fields"]}
    resource = {field["name"]: field for field in trace["resource"]["fields"]}
    mutation(scope, resource)
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("object_name", "field_name", "expected"),
    [
        ("envelope", "bucket", "structural contract envelope: missing field bucket"),
        (
            "provenance",
            "config_generation",
            "structural contract provenance: missing field config_generation",
        ),
        (
            "provenance",
            "binary_version",
            "structural contract provenance: missing field binary_version",
        ),
    ],
)
def test_trace_derivation_source_field_lookup_fails_with_safe_registry_error(
    tmp_path: Path,
    object_name: str,
    field_name: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module(f"telemetry_registry_missing_derivation_source_{object_name}")
    ir = module.compile_registry(root)
    object_ir = getattr(ir.structural_contract, object_name)
    broken_object = module.replace(
        object_ir,
        fields=tuple(field for field in object_ir.fields if field.name != field_name),
    )
    broken_contract = module.replace(ir.structural_contract, **{object_name: broken_object})
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    upstream_attributes = {
        attribute.id: (dependency.id, attribute)
        for dependency in ir.dependencies
        for attribute in dependency.snapshot.attributes
    }

    with pytest.raises(module.RegistryError, match=expected):
        module._validate_structural_contract_bindings(
            broken_contract,
            ir.schema_version,
            ir.bucket_catalog_version,
            ir.semantic_profiles,
            groups,
            attributes,
            upstream_attributes,
        )


@pytest.mark.parametrize("mutation", ["unavailable", "source_type_mismatch"])
def test_trace_derivation_target_must_be_available_and_source_typed(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    target = next(
        attribute for attribute in document["attributes"] if attribute["id"] == "defenseclaw.span.family_schema_version"
    )
    if mutation == "unavailable":
        target["projection_only"] = True
        target["legacy_bindings"] = [
            {
                "source": "fixture",
                "disposition": "generated_compatibility_alias",
            }
        ]
        expected = "trace derivation trace-family-schema-version-equality-v1: target attribute is unavailable"
    else:
        target["type"] = "int64"
        target["normalization"]["overrides"]["max"] = 2**63 - 1
        expected = "trace derivation trace-family-schema-version-equality-v1: source/target type mismatch"
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize("mutation", ["wrong_condition", "wrong_requirement"])
def test_span_outcome_derivation_requires_exact_source_presence_semantics(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    span_core = next(group for group in document["groups"] if group["id"] == "span.core")
    outcome = next(use for use in span_core["attributes"] if use["ref"] == "defenseclaw.outcome")
    if mutation == "wrong_condition":
        outcome["conditional"] = "connector-known-v1"
    else:
        outcome["requirement_level"] = "optional"
        outcome.pop("conditional")
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert (
        "trace derivation target defenseclaw.outcome must resolve with exact "
        "operation-terminal-v1 source-presence semantics"
    ) in result.stderr


def test_span_forbidden_outcome_cannot_retain_inherited_outcome_derivation(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/genai.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    span = next(group for group in document["groups"] if group["type"] == "span")
    span["x-defenseclaw"]["outcome_requirement"] = "forbidden"
    span["x-defenseclaw"]["allowed_outcomes"] = []
    _write_yaml(path, document)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert ("forbidden outcome cannot resolve trace derivation target defenseclaw.outcome") in result.stderr


def test_unexampled_span_must_resolve_every_registered_trace_derivation(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(path.read_text(encoding="utf-8"))
    span = next(item for item in operations["groups"] if item["id"] == "span.fixture.0")
    span["extends"].remove("span.core")
    _write_yaml(path, operations)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert (
        "group span.fixture.0: trace derivation target defenseclaw.bucket must resolve as an unconditional "
        "required attribute"
    ) in result.stderr


def _structural_lock_rows(root: Path) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    dependency = next(item for item in lock["dependencies"] if item["id"] == "otel_genai")
    return lock_path, lock, dependency["structural_inputs"]


def test_checked_in_structured_catalog_bindings_dispositions_and_privacy_are_exact() -> None:
    module = _load_generator_module("telemetry_registry_structured_exact")
    ir = module.compile_registry(ROOT)

    assert tuple(item.id for item in ir.structured_types) == module.EXPECTED_STRUCTURED_TYPE_IDS
    assert (
        tuple(
            (item.attribute, item.structured_type, item.public_encoding, item.canonical_wire_encoding)
            for item in ir.structured_bindings
        )
        == module.EXPECTED_STRUCTURED_BINDINGS
    )
    assert len(ir.structured_property_dispositions) == 109
    assert [len(dependency.structural_inputs) for dependency in ir.dependencies] == [0, 4, 0]
    structural_digest_paths = {item.path for item in ir.input_digests if "/model/gen-ai/" in item.path}
    assert structural_digest_paths == {item[1] for item in module.EXPECTED_STRUCTURAL_INPUTS}

    by_id = {item.id: item for item in ir.structured_types}
    canonical = by_id["gen_ai.canonical_json"].canonical_json
    assert canonical is not None
    assert canonical.limits == module.CanonicalJSONLimitsIR(8, 256, 256, 4096, 256, 32768, 65536)
    assert canonical.object_member_id == "entry"
    assert canonical.duplicate_name_policy == "reject"
    assert canonical.post_redaction_name_collision_policy == "reject"
    union = by_id["gen_ai.message_part"]
    assert tuple((item.tag, item.structured_ref) for item in union.variants or ()) == (
        module.EXPECTED_MESSAGE_PART_VARIANTS
    )
    assert union.dynamic_variant is not None and union.dynamic_variant.arm_id == "generic"
    assert by_id["gen_ai.generic_part"].effective_reserved_names == ("type",)

    union_dispositions = [
        item
        for item in ir.structured_property_dispositions
        if item.structured_type == "gen_ai.message_part" and item.member_name == "type"
    ]
    assert len(union_dispositions) == 22
    assert {item.arm_id for item in union_dispositions} == {
        *(tag for tag, _ in module.EXPECTED_MESSAGE_PART_VARIANTS),
        "generic",
    }
    assert all(item.target_structured_type is not None for item in union_dispositions)
    blob_dynamic_surfaces = {
        (item.input_path, item.json_pointer)
        for item in ir.structured_property_dispositions
        if item.disposition == "dynamic_members" and item.json_pointer.endswith("BlobPart")
    }
    assert blob_dynamic_surfaces == {
        ("model/gen-ai/gen-ai-input-messages.json", "#/$defs/BlobPart"),
        ("model/gen-ai/gen-ai-output-messages.json", "#/$defs/BlobPart"),
    }
    nullable = {
        (item.structured_type, item.member_name)
        for item in ir.structured_property_dispositions
        if item.disposition == "nullable_optional_omission"
    }
    assert nullable == {
        (type_id, field_name)
        for type_id, fields in module.STRUCTURED_NULLABLE_OPTIONALS.items()
        for field_name in fields
    }
    chat = by_id["gen_ai.chat_message"]
    chat_fields = {field.name: field for field in chat.fields or ()}
    assert chat_fields["role"].scalar is not None
    assert chat_fields["role"].scalar.known_values == ("system", "user", "assistant", "tool")
    assert chat_fields["name"].scalar is not None
    assert chat_fields["name"].scalar.sensitivity == "sensitive"
    assert chat_fields["name"].scalar.normalization.effective_constraints["max_utf8_bytes"] == 512
    uri = next(field for field in by_id["gen_ai.uri_part"].fields or () if field.name == "uri")
    assert uri.scalar is not None
    assert uri.scalar.field_class == "path"
    assert uri.scalar.normalization.effective_constraints["max_utf8_bytes"] == 8192
    blob_content = next(field for field in by_id["gen_ai.blob_part"].fields or () if field.name == "content")
    assert blob_content.scalar is not None
    assert blob_content.scalar.encoding_annotation == "json-base64-bytes-v1"
    with pytest.raises(TypeError):
        canonical.object_name.normalization.effective_constraints["max_utf8_bytes"] = 1  # type: ignore[index]


def test_updater_and_compiler_structural_pins_and_profiles_have_exact_parity() -> None:
    compiler = _load_generator_module("telemetry_registry_pin_parity_compiler")
    updater = _load_updater_module("telemetry_registry_pin_parity_updater")
    ir = compiler.compile_registry(ROOT)
    dependencies = {item.id: item for item in ir.dependencies}
    genai = dependencies["otel_genai"]

    assert tuple((upstream, digest) for upstream, _path, digest in compiler.EXPECTED_STRUCTURAL_INPUTS) == (
        updater.OTEL_GENAI_STRUCTURAL_INPUTS
    )
    assert tuple(
        updater._structural_input_local_path(genai.revision, upstream)
        for upstream, _digest in updater.OTEL_GENAI_STRUCTURAL_INPUTS
    ) == tuple(path for _upstream, path, _digest in compiler.EXPECTED_STRUCTURAL_INPUTS)
    assert {dependency_id: item.profile_id for dependency_id, item in dependencies.items()} == (
        updater.EXPECTED_PROFILE_IDS
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("unknown-ref", "unknown structured_ref"),
        ("cycle", "only gen_ai.canonical_json may self-reference"),
        ("discriminator-collision", "discriminator collides"),
        ("canonical-limit", "canonical JSON contract differs"),
        ("dynamic-policy", "dynamic member contract differs"),
        ("extra-binding", "structured binding inventory/order mismatch"),
        ("reordered-types", "structured type inventory/order mismatch"),
    ],
)
def test_structured_registry_grammar_and_graph_fail_closed(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in registry["structured_types"]}
    if mutation == "unknown-ref":
        by_id["gen_ai.input_messages"]["items"]["structured_ref"] = "gen_ai.missing"
    elif mutation == "cycle":
        by_id["gen_ai.chat_message"]["fields"][1]["structured_ref"] = "gen_ai.chat_message"
    elif mutation == "discriminator-collision":
        by_id["gen_ai.text_part"]["fields"].append(
            {
                "name": "type",
                "required": True,
                "type": "string",
                "field_class": "identifier",
                "sensitivity": "internal",
                "normalization": {"id": "bounded-v1", "overrides": {"max_utf8_bytes": 256}},
            }
        )
    elif mutation == "canonical-limit":
        by_id["gen_ai.canonical_json"]["limits"]["max_depth"] = 9
    elif mutation == "dynamic-policy":
        by_id["gen_ai.generic_part"]["dynamic_members"]["duplicate_name_policy"] = "last_wins"
    elif mutation == "extra-binding":
        registry["structured_bindings"].append(copy.deepcopy(registry["structured_bindings"][0]))
    else:
        registry["structured_types"][0], registry["structured_types"][1] = (
            registry["structured_types"][1],
            registry["structured_types"][0],
        )
    _write_yaml(path, registry)

    result = _run(root, "--check")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize("mutation", ["missing", "extra", "reordered", "digest", "source"])
def test_structural_input_lock_and_source_inventory_fail_closed(tmp_path: Path, mutation: str) -> None:
    root = _fixture_root(tmp_path)
    lock_path, lock, rows = _structural_lock_rows(root)
    if mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append(copy.deepcopy(rows[-1]))
    elif mutation == "reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif mutation == "digest":
        rows[0]["sha256"] = "0" * 64
    else:
        (root / rows[0]["path"]).write_bytes((root / rows[0]["path"]).read_bytes() + b" ")
    _write_yaml(lock_path, lock)

    result = _run(root, "--check")

    assert result.returncode == 1
    assert "structural" in result.stderr


@pytest.mark.parametrize("mutation", ["duplicate", "trailing", "utf8", "nonfinite", "nesting"])
def test_structural_input_json_parser_is_strict(tmp_path: Path, mutation: str) -> None:
    root = _fixture_root(tmp_path)
    lock_path, lock, rows = _structural_lock_rows(root)
    row = rows[2]
    if mutation == "duplicate":
        payload = b'{"type":"object","type":"object","additionalProperties":true}'
    elif mutation == "trailing":
        payload = b'{"type":"object","additionalProperties":true} trailing'
    elif mutation == "utf8":
        payload = b'{"type":"object","additionalProperties":true,"x":"\xff"}'
    elif mutation == "nonfinite":
        payload = b'{"type":"object","additionalProperties":true,"x":NaN}'
    else:
        payload = b'{"type":"object","additionalProperties":true,"x":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
    (root / row["path"]).write_bytes(payload)
    row["sha256"] = _sha256(payload)
    _write_yaml(lock_path, lock)

    result = _run(root, "--check")

    assert result.returncode == 1
    assert any(
        marker in result.stderr
        for marker in ("duplicate JSON key", "invalid JSON", "invalid UTF-8", "non-finite", "nesting")
    )


def test_strict_json_nesting_scan_ignores_string_content_and_bounds_containers(tmp_path: Path) -> None:
    module = _load_generator_module("telemetry_registry_json_nesting_scanner")
    path = tmp_path / "authored.json"
    string_value = 'escaped backslash and quote: \\" ' + "[{" * 300
    accepted = json.dumps({"value": string_value}).encode("utf-8")

    assert module._parse_json_strict_bytes(path, accepted) == {"value": string_value}

    rejected = b'{"value":' + b"[" * 256 + b"0" + b"]" * 256 + b"}"
    with pytest.raises(module.RegistryError, match="JSON nesting exceeds the parser limit"):
        module._parse_json_strict_bytes(path, rejected)


def test_structural_inputs_are_parsed_from_the_exact_hashed_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    _, _, rows = _structural_lock_rows(root)
    module = _load_generator_module("telemetry_registry_structural_single_read")
    original_read = module._read_utf8
    reads = 0

    def counted(path: Path) -> tuple[bytes, str]:
        nonlocal reads
        reads += 1
        return original_read(path)

    monkeypatch.setattr(module, "_read_utf8", counted)
    monkeypatch.setattr(
        module,
        "load_json_strict",
        lambda _path: pytest.fail("structural parser reopened a hashed input"),
    )

    parsed, documents, digests = module._parse_structural_inputs(
        root,
        rows,
        "fixture.structural_inputs",
    )

    assert reads == 4
    assert len(parsed) == len(documents) == len(digests) == 4


@pytest.mark.parametrize(
    "mutation",
    [
        "dynamic-name-pattern",
        "dynamic-name-bound",
        "canonical-name-pattern",
        "canonical-name-bound",
        "content-extra-bound",
        "content-weakened-bound",
    ],
)
def test_authored_structured_type_contract_digest_rejects_unreviewed_semantics(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in registry["structured_types"]}
    if mutation.startswith("dynamic-name"):
        overrides = by_id["gen_ai.tool_call_arguments"]["dynamic_members"]["name"]["normalization"]["overrides"]
        if mutation.endswith("pattern"):
            overrides["pattern"] = "^x+$"
        else:
            overrides["max_utf8_bytes"] = 255
    elif mutation.startswith("canonical-name"):
        overrides = by_id["gen_ai.canonical_json"]["object"]["members"]["name"]["normalization"]["overrides"]
        if mutation.endswith("pattern"):
            overrides["pattern"] = "^x+$"
        else:
            overrides["max_utf8_bytes"] = 255
    else:
        content = next(field for field in by_id["gen_ai.text_part"]["fields"] if field["name"] == "content")
        content["normalization"]["overrides"] = (
            {"max_utf8_bytes": 32768} if mutation == "content-extra-bound" else {"max_depth": 7}
        )
    _write_yaml(path, registry)

    result = _run(root, "--check")

    assert result.returncode == 1
    assert "registry.structured_types" in result.stderr
    assert "contract" in result.stderr


def test_authored_structured_type_digest_ignores_only_normalization_notes(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    text_part = next(item for item in registry["structured_types"] if item["id"] == "gen_ai.text_part")
    content = next(field for field in text_part["fields"] if field["name"] == "content")
    content["normalization"]["notes"] = "Reviewer-only explanatory prose."
    _write_yaml(path, registry)
    module = _load_generator_module("telemetry_registry_structured_note_projection")

    ir = module.compile_registry(root)

    parsed_text = next(item for item in ir.structured_types if item.id == "gen_ai.text_part")
    parsed_content = next(field for field in parsed_text.fields or () if field.name == "content")
    assert parsed_content.scalar is not None
    assert parsed_content.scalar.normalization.notes == "Reviewer-only explanatory prose."


@pytest.mark.parametrize(
    "mutation",
    [
        "root",
        "definition",
        "fixed-property",
        "array-items",
        "union-branch",
        "enum-extra-integer",
        "enum-extra-null",
        "enum-unknown-ref",
        "nullable-default",
        "blob-explicit-open",
        "explicit-open-removed",
        "blob-format-removed",
        "text-format-added",
    ],
)
def test_structural_source_schema_rejects_unmodeled_keyword_surfaces(mutation: str) -> None:
    module = _load_generator_module(f"telemetry_registry_structural_keyword_{mutation}")
    ir = module.compile_registry(ROOT)
    source = (
        ROOT / "schemas/telemetry/v8/upstream/otel-genai-b028dceecdad117461a785c3af35315e7184e813/"
        "model/gen-ai/gen-ai-input-messages.json"
    )
    document = module.load_json_strict(source)
    if mutation == "root":
        document["allOf"] = []
    elif mutation == "definition":
        document["$defs"]["TextPart"]["propertyNames"] = {"pattern": "^x+$"}
    elif mutation == "fixed-property":
        document["$defs"]["TextPart"]["properties"]["content"]["pattern"] = "^x+$"
    elif mutation == "array-items":
        document["$defs"]["ChatMessage"]["properties"]["parts"]["items"]["minItems"] = 1
    elif mutation == "union-branch":
        document["$defs"]["ChatMessage"]["properties"]["parts"]["items"]["anyOf"][0]["title"] = "Unmodeled"
    elif mutation == "nullable-default":
        document["$defs"]["ChatMessage"]["properties"]["name"]["default"] = "not-null"
    elif mutation == "blob-explicit-open":
        document["$defs"]["BlobPart"]["additionalProperties"] = True
    elif mutation == "explicit-open-removed":
        document["$defs"]["TextPart"].pop("additionalProperties")
    elif mutation == "blob-format-removed":
        document["$defs"]["BlobPart"]["properties"]["content"].pop("format")
    elif mutation == "text-format-added":
        document["$defs"]["TextPart"]["properties"]["content"]["format"] = "binary"
    else:
        role_branches = document["$defs"]["ChatMessage"]["properties"]["role"]["anyOf"]
        if mutation == "enum-extra-integer":
            role_branches.append({"type": "integer"})
        elif mutation == "enum-extra-null":
            role_branches.append({"type": "null"})
        else:
            role_branches[0]["$ref"] = "#/$defs/UnknownRole"

    with pytest.raises(module.RegistryError):
        module._validate_message_structural_input(
            "model/gen-ai/gen-ai-input-messages.json",
            document,
            {item.id: item for item in ir.structured_types},
        )


def test_every_hashed_authored_input_is_read_once_for_parse_and_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    _, _, structural_rows = _structural_lock_rows(root)
    relative_paths = (
        "schemas/telemetry/v8/registry.yaml",
        "schemas/telemetry/v8/semconv.lock.yaml",
        "schemas/telemetry/v8/genai.yaml",
        "schemas/telemetry/v8/security.yaml",
        "schemas/telemetry/v8/operations.yaml",
        "schemas/telemetry/v8/examples.yaml",
        "schemas/telemetry/v8/compatibility/v7-exporter-selection.schema.json",
        "docs/design/observability-v8/current-state-inventory.yaml",
        *(f"schemas/telemetry/v8/upstream/{dependency[5]}" for dependency in DEPENDENCIES),
        *(row["path"] for row in structural_rows),
    )
    monitored = {root / relative for relative in relative_paths}
    reads = {path.resolve(): 0 for path in monitored}
    module = _load_generator_module("telemetry_registry_all_inputs_single_read")
    original_read = module._read_utf8

    def counted(path: Path) -> tuple[bytes, str]:
        resolved = path.resolve()
        if resolved in reads:
            reads[resolved] += 1
        return original_read(path)

    monkeypatch.setattr(module, "_read_utf8", counted)
    monkeypatch.setattr(
        module,
        "load_yaml_strict",
        lambda _path: pytest.fail("compiler reopened a hashed YAML input"),
    )
    monkeypatch.setattr(
        module,
        "load_json_strict",
        lambda _path: pytest.fail("compiler reopened a hashed JSON input"),
    )

    module.compile_registry(root)

    assert {path.relative_to(root).as_posix(): count for path, count in reads.items()} == {
        relative: 1 for relative in relative_paths
    }


def test_v7_exporter_selection_is_derived_from_exhaustive_producer_mappings() -> None:
    module = _load_generator_module("telemetry_registry_v7_exporter_selection")
    ir = module.compile_registry(ROOT)
    selection = ir.v7_exporter_selection

    gateway_events = selection["exporters"]["gateway_jsonl"]["logs"][0]["event_names"]
    console_events = selection["exporters"]["gateway_console"]["logs"][0]["event_names"]
    audit_actions = selection["exporters"]["audit_sink"]["logs"][0]["actions"]
    assert gateway_events == console_events == tuple(sorted(gateway_events))
    assert gateway_events and audit_actions == tuple(sorted(audit_actions))
    assert {
        "guardrail.evaluation.completed",
        "finding.observed",
        "legacy.audit.config.update",
        "model.request",
        "tool.invocation.requested",
    }.issubset(gateway_events)
    assert {
        "api-auth-failure",
        "config-update",
        "gateway-agent-start",
        "guardrail-verdict",
        "scan",
    }.issubset(audit_actions)
    assert ir.v7_exporter_selection_schema_path in {digest.path for digest in ir.input_digests}

    metric_groups = [group for domain in ir.domains for group in domain.groups if group.type == "metric"]
    log_groups = [group for domain in ir.domains for group in domain.groups if group.type == "log"]
    span_groups = [group for domain in ir.domains for group in domain.groups if group.type == "span"]
    metric_buckets = tuple(
        bucket for bucket in module.EXPECTED_BUCKET_ORDER if any(group.bucket == bucket for group in metric_groups)
    )
    assert metric_groups and log_groups and span_groups
    assert len(metric_buckets) == 14
    assert selection["collection"]["always"]["logs"] == tuple(module.EXPECTED_BUCKET_ORDER)
    assert selection["collection"]["otel.logs"]["logs"] == tuple(module.EXPECTED_BUCKET_ORDER)
    assert selection["collection"]["otel.traces"]["traces"] == tuple(module.EXPECTED_BUCKET_ORDER)
    assert selection["collection"]["otel.metrics"]["metrics"] == metric_buckets
    expected_span_names = tuple(sorted(group.id for group in span_groups))
    for exporter in ("generic_otlp", "local_observability"):
        assert selection["exporters"][exporter]["logs"] == ({"buckets": tuple(module.EXPECTED_BUCKET_ORDER)},)
        assert selection["exporters"][exporter]["traces"] == ({"event_names": expected_span_names},)
    assert selection["exporters"]["generic_otlp"]["metrics"] == ({"buckets": metric_buckets},)
    assert selection["exporters"]["local_observability"]["metrics"] == ({"buckets": metric_buckets},)


def test_v7_exporter_selection_derivation_tracks_mapping_identity_changes(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    operations_path = root / "schemas/telemetry/v8/operations.yaml"
    operations = yaml.safe_load(operations_path.read_text(encoding="utf-8"))
    mapping = next(item for item in operations["producer_mappings"] if item["producer"] == "gateway_event")
    mapping["default_identity"] = {
        "event_name": "fixture.event.0",
        "bucket": "diagnostic",
        "family": "fixture.log.0",
    }
    _write_yaml(operations_path, operations)

    module = _load_generator_module("telemetry_registry_v7_derivation_change")
    ir = module.compile_registry(root)
    gateway_events = ir.v7_exporter_selection["exporters"]["gateway_jsonl"]["logs"][0]["event_names"]
    assert gateway_events == ("diagnostic.message", "fixture.event.0")


def test_v7_exporter_selection_rejects_hand_maintained_gateway_selector(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    inventory_path = root / "docs/design/observability-v8/current-state-inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    inventory["classes"]["v7_exporter_selection"]["exporters"]["gateway_jsonl"]["logs"] = [{"buckets": ["diagnostic"]}]
    _write_yaml(inventory_path, inventory)

    module = _load_generator_module("telemetry_registry_v7_manual_selector")
    with pytest.raises(module.RegistryError, match="expected the closed derive_event_names_from declaration"):
        module.compile_registry(root)


def test_structured_facts_participate_in_materialized_digest() -> None:
    module = _load_generator_module("telemetry_registry_structured_digest")
    ir = module.compile_registry(ROOT)
    values = {
        field.name: getattr(ir, field.name)
        for field in module.dataclass_fields(module.RegistryIR)
        if field.name != "materialized_view"
    }
    canonical = ir.structured_types[0]
    assert canonical.canonical_json is not None
    changed_limits = module.replace(canonical.canonical_json.limits, max_depth=7)
    changed_contract = module.replace(canonical.canonical_json, limits=changed_limits)
    changed_type = module.replace(canonical, canonical_json=changed_contract)

    assert (
        module._build_materialized_registry_view(
            dict(values, structured_types=(changed_type, *ir.structured_types[1:]))
        ).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )
    assert (
        module._build_materialized_registry_view(
            dict(values, structured_bindings=tuple(reversed(ir.structured_bindings)))
        ).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )
    assert (
        module._build_materialized_registry_view(
            dict(values, structured_property_dispositions=tuple(reversed(ir.structured_property_dispositions)))
        ).typed_canonical_json_sha256
        != ir.materialized_view.typed_canonical_json_sha256
    )
















def test_updater_mid_publish_failure_restores_prior_bytes_and_inodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_mid_publish_rollback")
    paths = (
        root / "schemas/telemetry/v8/upstream/rollback-a.json",
        root / "schemas/telemetry/v8/upstream/rollback-b.json",
        root / "schemas/telemetry/v8/semconv.lock.yaml",
    )
    paths[0].write_bytes(b"old-a\n")
    paths[1].write_bytes(b"old-b\n")
    before = {path: (path.read_bytes(), path.stat().st_ino) for path in paths}
    rendered = {
        "schemas/telemetry/v8/upstream/rollback-a.json": b"new-a\n",
        "schemas/telemetry/v8/upstream/rollback-b.json": b"new-b\n",
        "schemas/telemetry/v8/semconv.lock.yaml": b"new-lock\n",
    }
    original_link = module.os.link
    calls = 0

    def fail_once(*args: Any, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("injected publication failure")
        original_link(*args, **kwargs)

    monkeypatch.setattr(module.os, "link", fail_once)

    with pytest.raises(
        module.RegistryError,
        match="telemetry upstream publication failed and was rolled back",
    ) as exc_info:
        module._install_rendered(root, rendered, "schemas/telemetry/v8/semconv.lock.yaml")

    assert isinstance(exc_info.value.__cause__, OSError)
    assert str(exc_info.value.__cause__) == "injected publication failure"
    for path, (payload, inode) in before.items():
        assert path.read_bytes() == payload
        assert path.stat().st_ino == inode
    assert not tuple(root.glob(".telemetry-upstream-update-*"))


def test_updater_transaction_directory_substitution_blocks_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_transaction_substitution")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    output_path = root / "schemas/telemetry/v8/upstream/substitution.json"
    original_remove = module._remove_tree_at
    replacement_name: str | None = None

    def substitute(parent_descriptor: int, name: str, identity: tuple[int, int]) -> None:
        nonlocal replacement_name
        replacement_name = name
        module.os.rename(
            name,
            f"{name}.original",
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        module.os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        original_remove(parent_descriptor, name, identity)

    monkeypatch.setattr(module, "_remove_tree_at", substitute)

    with pytest.raises(
        module.RegistryError,
        match="telemetry upstream update committed; transaction cleanup failed",
    ) as exc_info:
        module._install_rendered(
            root,
            {
                "schemas/telemetry/v8/upstream/substitution.json": b"new\n",
                "schemas/telemetry/v8/semconv.lock.yaml": b"new-lock\n",
            },
            "schemas/telemetry/v8/semconv.lock.yaml",
        )

    assert isinstance(exc_info.value.__cause__, module.RegistryError)
    assert "transaction directory was replaced" in str(exc_info.value.__cause__)
    assert output_path.read_bytes() == b"new\n"
    assert lock_path.read_bytes() == b"new-lock\n"
    assert replacement_name is not None
    assert (root / replacement_name).is_dir()
    assert (root / f"{replacement_name}.original").is_dir()


def test_updater_post_commit_cleanup_fsync_failure_reports_live_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_cleanup_fsync")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    output_path = root / "schemas/telemetry/v8/upstream/cleanup-fsync.json"
    original_remove = module._remove_tree_at
    original_fsync = module.os.fsync
    injected = False

    def fail_cleanup_fsync(parent_descriptor: int, name: str, identity: tuple[int, int]) -> None:
        nonlocal injected

        def fail_once(descriptor: int) -> None:
            nonlocal injected
            if not injected:
                injected = True
                raise OSError("injected transaction cleanup fsync failure")
            original_fsync(descriptor)

        monkeypatch.setattr(module.os, "fsync", fail_once)
        try:
            original_remove(parent_descriptor, name, identity)
        finally:
            monkeypatch.setattr(module.os, "fsync", original_fsync)

    monkeypatch.setattr(module, "_remove_tree_at", fail_cleanup_fsync)

    with pytest.raises(
        module.RegistryError,
        match="telemetry upstream update committed; transaction cleanup failed",
    ) as exc_info:
        module._install_rendered(
            root,
            {
                "schemas/telemetry/v8/upstream/cleanup-fsync.json": b"new\n",
                "schemas/telemetry/v8/semconv.lock.yaml": b"new-lock\n",
            },
            "schemas/telemetry/v8/semconv.lock.yaml",
        )

    assert injected is True
    assert isinstance(exc_info.value.__cause__, OSError)
    assert str(exc_info.value.__cause__) == "injected transaction cleanup fsync failure"
    assert output_path.read_bytes() == b"new\n"
    assert lock_path.read_bytes() == b"new-lock\n"
    assert tuple(root.glob(".telemetry-upstream-update-*"))


def test_updater_failure_removes_newly_created_parent_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_created_parent_rollback")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"

    def fail_stage(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("injected staging failure")

    monkeypatch.setattr(module, "_write_staged_file", fail_stage)

    with pytest.raises(
        module.RegistryError,
        match="telemetry upstream publication failed and was rolled back",
    ) as exc_info:
        module._install_rendered(
            root,
            {
                "schemas/telemetry/v8/upstream/new-parent/nested/value.json": b"new\n",
                "schemas/telemetry/v8/semconv.lock.yaml": lock_path.read_bytes(),
            },
            "schemas/telemetry/v8/semconv.lock.yaml",
        )

    assert isinstance(exc_info.value.__cause__, OSError)
    assert str(exc_info.value.__cause__) == "injected staging failure"
    assert not (root / "schemas/telemetry/v8/upstream/new-parent").exists()
    assert not tuple(root.glob(".telemetry-upstream-update-*"))


@pytest.mark.parametrize(
    "mutation",
    [
        "schema-version-bool",
        "dependency-scalar",
        "version-too-long",
        "profile-malformed",
        "profile-retargeted",
        "snapshot-shape",
        "snapshot-path-type",
        "snapshot-path-noncanonical",
        "snapshot-path-too-long",
        "snapshot-path-surrogate",
        "snapshot-format",
        "snapshot-digest-type",
        "snapshot-digest-noncanonical",
        "duplicate-snapshot-path",
        "snapshot-structural-collision",
    ],
)
def test_updater_lock_validation_rejects_compiler_incompatible_inputs(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module(f"telemetry_updater_lock_contract_{mutation}")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    dependencies = lock["dependencies"]
    target = dependencies[0]
    if mutation == "schema-version-bool":
        lock["schema_version"] = True
    elif mutation == "dependency-scalar":
        target["repository"] = 7
    elif mutation == "version-too-long":
        target["version"] = "v" * 4097
    elif mutation == "profile-malformed":
        target["profile_id"] = "invalid profile!"
    elif mutation == "profile-retargeted":
        target["profile_id"] = "valid-but-wrong-profile"
    elif mutation == "snapshot-shape":
        target["snapshot"] = "not-a-mapping"
    elif mutation == "snapshot-path-type":
        target["snapshot"]["path"] = 7
    elif mutation == "snapshot-path-noncanonical":
        target["snapshot"]["path"] = "schemas/telemetry/v8/upstream/../escape.json"
    elif mutation == "snapshot-path-too-long":
        target["snapshot"]["path"] = "schemas/telemetry/v8/upstream/" + "x" * 4097
    elif mutation == "snapshot-path-surrogate":
        target["snapshot"]["path"] = "schemas/telemetry/v8/upstream/\ud800.json"
    elif mutation == "snapshot-format":
        target["snapshot"]["format"] = 7
    elif mutation == "snapshot-digest-type":
        target["snapshot"]["sha256"] = 7
    elif mutation == "snapshot-digest-noncanonical":
        target["snapshot"]["sha256"] = "A" * 64
    elif mutation == "duplicate-snapshot-path":
        dependencies[1]["snapshot"]["path"] = target["snapshot"]["path"]
    else:
        target["snapshot"]["path"] = dependencies[1]["structural_inputs"][0]["path"]
    _write_yaml(lock_path, lock)

    with pytest.raises(module.RegistryError):
        module._load_lock(lock_path)


@pytest.mark.parametrize(
    ("phase", "swap_on_upstream_validation"),
    [
        ("before-snapshot", 1),
        ("before-lock", 2),
        ("after-lock", 3),
    ],
)
def test_updater_namespace_swap_cannot_publish_through_detached_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    swap_on_upstream_validation: int,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module(f"telemetry_updater_namespace_swap_{phase}")
    upstream = root / "schemas/telemetry/v8/upstream"
    displaced = root / "schemas/telemetry/v8/upstream.displaced"
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    before_lock = (lock_path.read_bytes(), lock_path.stat().st_ino)
    original_validate = module._validate_parent_binding
    swapped = False
    upstream_validations = 0

    def swap_before_validation(root_descriptor: int, state: dict[str, Any]) -> None:
        nonlocal swapped, upstream_validations
        if state["parent_parts"] == ("schemas", "telemetry", "v8", "upstream"):
            upstream_validations += 1
            if not swapped and upstream_validations == swap_on_upstream_validation:
                upstream.rename(displaced)
                upstream.mkdir()
                swapped = True
        original_validate(root_descriptor, state)

    monkeypatch.setattr(module, "_validate_parent_binding", swap_before_validation)

    with pytest.raises(
        module.RegistryError,
        match="telemetry upstream publication failed and was rolled back",
    ) as exc_info:
        module._install_rendered(
            root,
            {
                "schemas/telemetry/v8/upstream/namespace-swap.json": b"new\n",
                "schemas/telemetry/v8/semconv.lock.yaml": lock_path.read_bytes(),
            },
            "schemas/telemetry/v8/semconv.lock.yaml",
        )

    assert swapped is True
    assert isinstance(exc_info.value.__cause__, module.RegistryError)
    assert "canonical namespace" in str(exc_info.value.__cause__)
    assert not (upstream / "namespace-swap.json").exists()
    assert not (displaced / "namespace-swap.json").exists()
    assert lock_path.read_bytes() == before_lock[0]
    assert lock_path.stat().st_ino == before_lock[1]
    assert not tuple(root.glob(".telemetry-upstream-update-*"))


@pytest.mark.parametrize("phase", ["before-lock", "after-lock"])
@pytest.mark.parametrize("tamper", ["replace-inode", "in-place-bytes"])
def test_updater_installed_target_tampering_never_commits_a_new_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    tamper: str,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module(f"telemetry_updater_target_tamper_{phase}_{tamper}")
    target_path = root / "schemas/telemetry/v8/upstream/tamper.json"
    target_path.write_bytes(b"old-snapshot\n")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    before_target = (target_path.read_bytes(), target_path.stat().st_ino)
    before_lock = (lock_path.read_bytes(), lock_path.stat().st_ino)
    original_validate = module._validate_installed_target
    target_validations = 0
    tampered = False

    def tamper_before_validation(root_descriptor: int, state: dict[str, Any]) -> None:
        nonlocal target_validations, tampered
        if state["relative"] == "schemas/telemetry/v8/upstream/tamper.json":
            target_validations += 1
            target_phase = 1 if phase == "before-lock" else 2
            if not tampered and target_validations == target_phase:
                if tamper == "replace-inode":
                    replacement = target_path.with_suffix(".replacement")
                    replacement.write_bytes(b"foreign-replacement\n")
                    replacement.replace(target_path)
                else:
                    target_path.write_bytes(b"foreign-in-place\n")
                tampered = True
        original_validate(root_descriptor, state)

    monkeypatch.setattr(module, "_validate_installed_target", tamper_before_validation)

    expected = (
        "telemetry upstream rollback failed; transaction evidence was preserved"
        if tamper == "replace-inode"
        else "telemetry upstream publication failed and was rolled back"
    )
    with pytest.raises(module.RegistryError, match=expected):
        module._install_rendered(
            root,
            {
                "schemas/telemetry/v8/upstream/tamper.json": b"new-snapshot\n",
                "schemas/telemetry/v8/semconv.lock.yaml": b"new-lock\n",
            },
            "schemas/telemetry/v8/semconv.lock.yaml",
        )

    assert tampered is True
    assert lock_path.read_bytes() == before_lock[0]
    assert lock_path.stat().st_ino == before_lock[1]
    if tamper == "replace-inode":
        assert target_path.read_bytes() == b"foreign-replacement\n"
        assert target_path.stat().st_ino != before_target[1]
        assert tuple(root.glob(".telemetry-upstream-update-*"))
    else:
        assert target_path.read_bytes() == before_target[0]
        assert target_path.stat().st_ino == before_target[1]
        assert not tuple(root.glob(".telemetry-upstream-update-*"))


def test_updater_structural_json_nesting_matches_compiler_boundary() -> None:
    module = _load_updater_module("telemetry_updater_structural_nesting")
    path = "model/gen-ai/fixture.json"
    depth_256 = b'{"value":' + b"[" * 255 + b"0" + b"]" * 255 + b"}"
    depth_257 = b'{"value":' + b"[" * 256 + b"0" + b"]" * 256 + b"}"
    string_value = 'escaped backslash and quote: \\" ' + "[{" * 300

    module._validate_structural_json(path, depth_256)
    module._validate_structural_json(path, json.dumps({"value": string_value}).encode("utf-8"))
    with pytest.raises(module.RegistryError, match="JSON nesting exceeds the parser limit"):
        module._validate_structural_json(path, depth_257)


@pytest.mark.parametrize("mutation", ["same-inode", "replacement-inode"])
def test_updater_lock_cas_preserves_external_stale_lock_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module(f"telemetry_updater_stale_lock_{mutation}")
    archive = tmp_path / "genai.tar.gz"
    _upstream_archive(archive)
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    snapshot_path = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    before_snapshot = (snapshot_path.read_bytes(), snapshot_path.stat().st_ino)
    original_install = module._install_rendered
    external_payload = f"external-{mutation}\n".encode()

    def mutate_then_install(*args: Any, **kwargs: Any) -> None:
        if mutation == "same-inode":
            lock_path.write_bytes(external_payload)
        else:
            replacement = lock_path.with_suffix(".replacement")
            replacement.write_bytes(external_payload)
            replacement.replace(lock_path)
        original_install(*args, **kwargs)

    monkeypatch.setattr(module, "_install_rendered", mutate_then_install)

    with pytest.raises(module.RegistryError, match="telemetry upstream publication failed and was rolled back"):
        module.update(root, ("otel_genai",), {"otel_genai": archive})

    assert lock_path.read_bytes() == external_payload
    assert snapshot_path.read_bytes() == before_snapshot[0]
    assert snapshot_path.stat().st_ino == before_snapshot[1]
    assert not tuple(root.glob(".telemetry-upstream-update-*"))


def test_updater_unselected_reference_digest_drift_rolls_back_selected_subset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_unselected_digest_drift")
    archive = tmp_path / "genai.tar.gz"
    _upstream_archive(archive)
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    selected_path = root / "schemas/telemetry/v8/upstream/otel-genai.normalized.json"
    unselected_path = root / "schemas/telemetry/v8/upstream/otel-core.normalized.json"
    before_lock = (lock_path.read_bytes(), lock_path.stat().st_ino)
    before_selected = (selected_path.read_bytes(), selected_path.stat().st_ino)
    original_install = module._install_rendered

    def drift_then_install(*args: Any, **kwargs: Any) -> None:
        unselected_path.write_bytes(b"external-unselected-drift\n")
        original_install(*args, **kwargs)

    monkeypatch.setattr(module, "_install_rendered", drift_then_install)

    with pytest.raises(module.RegistryError, match="telemetry upstream publication failed and was rolled back"):
        module.update(root, ("otel_genai",), {"otel_genai": archive})

    assert unselected_path.read_bytes() == b"external-unselected-drift\n"
    assert selected_path.read_bytes() == before_selected[0]
    assert selected_path.stat().st_ino == before_selected[1]
    assert lock_path.read_bytes() == before_lock[0]
    assert lock_path.stat().st_ino == before_lock[1]
    assert not tuple(root.glob(".telemetry-upstream-update-*"))


def test_updater_concurrent_subset_refreshes_are_serialized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_concurrent_subset")
    lock_path = root / "schemas/telemetry/v8/semconv.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    before_subset_digests = {
        item["id"]: item["snapshot"]["sha256"]
        for item in lock["dependencies"]
        if item["id"] in {"otel_core", "openinference"}
    }
    core_archive = tmp_path / "core.tar.gz"
    openinference_archive = tmp_path / "openinference.tar.gz"
    _full_core_upstream_archive(core_archive)
    _openinference_archive(openinference_archive)
    original_archive_files = module._archive_files
    guard = threading.Lock()
    start = threading.Barrier(2)
    active = 0
    maximum_active = 0

    def observed_archive_files(payload: bytes) -> dict[str, bytes]:
        nonlocal active, maximum_active
        with guard:
            active += 1
            maximum_active = max(maximum_active, active)
        try:
            time.sleep(0.05)
            return original_archive_files(payload)
        finally:
            with guard:
                active -= 1

    def refresh(dependency: str, archive: Path) -> None:
        start.wait(timeout=5)
        module.update(root, (dependency,), {dependency: archive})

    monkeypatch.setattr(module, "_archive_files", observed_archive_files)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(refresh, "otel_core", core_archive),
            executor.submit(refresh, "openinference", openinference_archive),
        ]
        for future in futures:
            future.result(timeout=30)

    assert maximum_active == 1
    assert not tuple(root.glob(".telemetry-upstream-update-*"))
    refreshed_lock, dependencies = module._load_lock(lock_path)
    assert refreshed_lock["schema_version"] == 1
    for dependency in dependencies:
        snapshot_path = root / dependency["snapshot"]["path"]
        assert _sha256(snapshot_path.read_bytes()) == dependency["snapshot"]["sha256"]
    refreshed_digests = {
        item["id"]: item["snapshot"]["sha256"] for item in dependencies if item["id"] in {"otel_core", "openinference"}
    }
    assert set(refreshed_digests) == set(before_subset_digests)
    assert all(refreshed_digests[key] != before_subset_digests[key] for key in refreshed_digests)
    compiler = _load_generator_module("telemetry_registry_concurrent_subset_compile")
    compiler.compile_registry(root)


def test_updater_candidate_reference_rejects_sparse_oversized_file(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_sparse_reference")
    relative = "schemas/telemetry/v8/upstream/oversized-reference.json"
    target = root / relative
    with target.open("wb") as stream:
        stream.truncate(module.MAX_EXPANDED_BYTES + 1)

    with module._directory_descriptor(root) as root_descriptor:
        with pytest.raises(module.RegistryError, match="exceeds the read limit"):
            module._validate_candidate_references(root_descriptor, ((relative, "0" * 64),))


def test_core_runtime_span_context_cost_and_compatibility_contracts_are_exact() -> None:
    module = _load_generator_module("telemetry_registry_runtime_span_contract_completion")
    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    local_attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    extensions = {extension.ref: extension for domain in ir.domains for extension in domain.attribute_extensions}

    target_ids = (
        "span.agent.transition",
        "span.agent.invoke",
        "span.workflow.run",
        "span.model.chat",
        "span.tool.execute",
    )
    shared_context = {
        "defenseclaw.request.id",
        "defenseclaw.turn.id",
        "user.id",
        "defenseclaw.user.name",
        "defenseclaw.policy.id",
        "defenseclaw.policy.version",
        "defenseclaw.destination.app",
    }
    for family_id in target_ids:
        uses = {use.ref: use for use in groups[family_id].resolved_uses}
        assert shared_context <= set(uses)
        assert all(uses[reference].requirement_level == "recommended" for reference in shared_context)
        assert uses["defenseclaw.agent.reported_cost.present"].requirement_level == "required"
        cost = uses["defenseclaw.agent.reported_cost.usd"]
        assert cost.requirement_level == "conditional"
        assert cost.conditional == "agent-reported-cost-available-v1"
        assert "llm.cost.total" not in uses

    canary_fields = {
        "defenseclaw.telemetry.canary",
        "defenseclaw.telemetry.canary.operation",
        "defenseclaw.telemetry.canary.destination",
    }
    for family_id in ("span.agent.invoke", "span.model.chat"):
        uses = {use.ref: use for use in groups[family_id].resolved_uses}
        assert canary_fields <= set(uses)
        assert uses["defenseclaw.telemetry.canary"].requirement_level == "optional"
        assert uses["defenseclaw.telemetry.canary.operation"].requirement_level == "conditional"
        assert uses["defenseclaw.telemetry.canary.destination"].requirement_level == "optional"
        assert uses["defenseclaw.telemetry.canary.operation"].conditional == "telemetry-canary-enabled-v1"
        assert uses["defenseclaw.telemetry.canary.destination"].conditional == "telemetry-canary-enabled-v1"
    assert canary_fields.isdisjoint(use.ref for use in groups["span.diagnostic.canary"].resolved_uses)

    lifecycle_capable = ("span.agent.transition", "span.agent.invoke", "span.workflow.run")
    model_identity = {
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "gen_ai.response.model",
        "gen_ai.response.id",
        "defenseclaw.model.request.id",
        "defenseclaw.model.response.id",
    }
    tool_identity = {
        "defenseclaw.tool.id",
        "gen_ai.tool.name",
        "gen_ai.tool.type",
        "gen_ai.tool.call.id",
        "defenseclaw.tool.provider",
        "defenseclaw.tool.skill_key",
    }
    for family_id in lifecycle_capable:
        uses = {use.ref: use for use in groups[family_id].resolved_uses}
        assert model_identity | tool_identity <= set(uses)
        assert all(uses[reference].requirement_level == "recommended" for reference in model_identity | tool_identity)

    model_uses = {use.ref: use for use in groups["span.model.chat"].resolved_uses}
    assert model_identity <= set(model_uses)
    assert model_uses["gen_ai.request.model"].requirement_level == "required"
    tool_uses = {use.ref: use for use in groups["span.tool.execute"].resolved_uses}
    assert tool_identity <= set(tool_uses)
    assert tool_uses["gen_ai.tool.name"].requirement_level == "required"

    assert local_attributes["defenseclaw.agent.reported_cost.present"].field_class == "metadata"
    assert local_attributes["defenseclaw.agent.reported_cost.usd"].field_class == "metadata"
    assert local_attributes["defenseclaw.tool.id"].field_class == "identifier"
    assert local_attributes["defenseclaw.policy.id"].field_class == "identifier"
    assert local_attributes["defenseclaw.destination.app"].field_class == "identifier"
    assert extensions["user.id"].field_class == "identifier"
    assert extensions["user.id"].sensitivity == "sensitive"

    condition = next(item for item in ir.conditions if item.id == "agent-reported-cost-available-v1")
    assert condition.enforcement.kind == "boolean_attribute"
    assert condition.enforcement.fact is None
    assert condition.enforcement.attribute == "defenseclaw.agent.reported_cost.present"
    assert condition.false_requirement == "forbidden"
    transition = groups["span.agent.transition"]
    assert transition.compatibility_profiles == ("local-observability-v1",)
    ineligible = next(binding for binding in transition.legacy_bindings or () if binding.source == "galileo-rich-v2")
    assert ineligible.disposition == "explicitly_ineligible"
    assert ineligible.details["fabrication"] == "forbidden"
    assert "gen_ai.operation.name=invoke_agent" in ineligible.details["missing_required_semantics"]
    approval = groups["span.approval.resolve"]
    assert approval.compatibility_profiles == ("local-observability-v1",)
    approval_ineligible = next(
        binding for binding in approval.legacy_bindings or () if binding.source == "galileo-rich-v2"
    )
    assert approval_ineligible.disposition == "explicitly_ineligible"
    assert approval_ineligible.details == {
        "reason": "Galileo has no approval shape for native approval resolution spans.",
        "unsupported_shape": "approval",
        "fabrication": "forbidden",
    }
    assert {
        family_id for family_id, family in groups.items() if "galileo-rich-v2" in (family.compatibility_profiles or ())
    } == {
        "span.agent.invoke",
        "span.guardrail.judge",
        "span.model.chat",
        "span.retrieval.search",
        "span.tool.execute",
        "span.workflow.run",
    }


@pytest.mark.parametrize(
    ("enforcement", "expected"),
    (
        ({"kind": "boolean_attribute"}, "boolean_attribute requires only attribute"),
        (
            {"kind": "boolean_attribute", "attribute": "defenseclaw.agent.reported_cost.present", "fact": "x"},
            "boolean_attribute requires only attribute",
        ),
        (
            {"kind": "builder_fact", "fact": "x", "attribute": "defenseclaw.agent.reported_cost.present"},
            "builder_fact requires only fact",
        ),
    ),
)
def test_condition_enforcement_arms_are_shape_closed(
    tmp_path: Path,
    enforcement: dict[str, str],
    expected: str,
) -> None:
    root = _fixture_root(tmp_path)
    path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    registry["conditions"][-1]["enforcement"] = enforcement
    _write_yaml(path, registry)

    result = _run(root, "--write")

    assert result.returncode == 1
    assert expected in result.stderr


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("missing", "requires unconditional boolean source"),
        ("conditioned", "requires unconditional boolean source"),
        ("not_boolean", "must be a boolean attribute"),
    ),
)
def test_boolean_attribute_conditions_fail_closed_at_compile_time(mode: str, expected: str) -> None:
    module = _load_generator_module(f"telemetry_registry_boolean_condition_{mode}")
    ir = module.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    local_attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    upstream_attributes = {
        attribute.id: (dependency.id, attribute)
        for dependency in ir.dependencies
        for attribute in dependency.snapshot.attributes
    }
    condition = next(item for item in ir.conditions if item.id == "agent-reported-cost-available-v1")
    cost_group = groups["cost.agent.reported"]
    present = next(use for use in cost_group.resolved_uses if use.ref == "defenseclaw.agent.reported_cost.present")
    amount = next(use for use in cost_group.resolved_uses if use.ref == "defenseclaw.agent.reported_cost.usd")
    if mode == "missing":
        changed = module.replace(cost_group, resolved_uses=(amount,))
    elif mode == "conditioned":
        changed = module.replace(
            cost_group,
            resolved_uses=(
                module.replace(
                    present,
                    requirement_level="optional",
                    conditional="agent-reported-cost-available-v1",
                ),
                amount,
            ),
        )
    else:
        string_source = module.replace(present, ref="defenseclaw.agent.type")
        changed_condition = module.replace(
            condition,
            enforcement=module.ConditionEnforcementIR("boolean_attribute", None, "defenseclaw.agent.type"),
        )
        changed = module.replace(cost_group, resolved_uses=(string_source, amount))
        condition = changed_condition

    with pytest.raises(module.RegistryError, match=expected):
        module._validate_condition_references(
            {changed.id: changed},
            tuple(condition if item.id == condition.id else item for item in ir.conditions),
            local_attributes,
            upstream_attributes,
        )


def test_updater_transaction_bootstrap_failure_removes_exact_created_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _fixture_root(tmp_path)
    module = _load_updater_module("telemetry_updater_bootstrap_cleanup")
    original_fsync = module.os.fsync
    injected = False

    def fail_first_fsync(descriptor: int) -> None:
        nonlocal injected
        if not injected:
            injected = True
            raise OSError("injected bootstrap failure")
        original_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", fail_first_fsync)

    with module._directory_descriptor(root) as root_descriptor:
        with pytest.raises(module.RegistryError, match="cannot initialize telemetry upstream transaction directory"):
            module._create_transaction_directory(root_descriptor)

    assert injected is True
    assert not tuple(root.glob(".telemetry-upstream-update-*"))


@pytest.fixture(scope="module")
def canonical_go_symbol_compilation() -> tuple[Any, Any]:
    module = _load_generator_module("telemetry_registry_go_symbol_canonical")
    return module, module.compile_registry(ROOT)


def test_inbound_otlp_ir_expands_closed_match_target_and_echo_inventories(
    canonical_go_symbol_compilation: tuple[Any, Any],
) -> None:
    _module, ir = canonical_go_symbol_compilation
    inbound = ir.inbound_bindings

    assert inbound.binding_classes
    assert inbound.match_descriptors and inbound.target_descriptors
    assert inbound.native_markers and inbound.echo_recognizers and inbound.import_contexts
    assert inbound.semantic_resource_instance_key == "defenseclaw.instance.id"
    assert inbound.forward_instance_key == "defenseclaw.telemetry.forward.instance_id"
    assert inbound.semantic_resource_instance_key != inbound.forward_instance_key
    assert inbound.scope_schema_url == "https://defenseclaw.io/schemas/telemetry/v8"
    assert inbound.resource_schema_url == "https://opentelemetry.io/schemas/1.42.0"
    assert inbound.shape_policy["native_malformed_external_fallback"] == "forbidden"
    assert {item["signal"] for item in inbound.native_markers} == {"logs", "traces", "metrics"}
    assert {item["shape"] for item in inbound.match_descriptors} == {"native_exact", "external"}
    assert {item["family"] for item in inbound.echo_recognizers} == {
        group.id for domain in ir.domains for group in domain.groups if group.type in {"log", "span", "metric"}
    }
    assert all("mandatory" not in item and "floor" not in item for item in inbound.import_contexts)
    unit_rules = [
        item["mapping"]["source_unit_rule"]
        for item in inbound.match_descriptors
        if item["mapping"]["source_unit_rule"]["kind"] != "none"
    ]
    assert unit_rules
    for rule in unit_rules:
        assert rule["kind"] in {"scale-table-v1", "target-unit-equality-v1"}
        assert rule["target_unit"]
        assert rule["accepted"]
        assert len({item["source_unit"] for item in rule["accepted"]}) == len(rule["accepted"])
        assert all(item["scale"] > 0 for item in rule["accepted"])


def test_inbound_otlp_duration_aliases_have_unique_matches_and_one_target_rows(
    canonical_go_symbol_compilation: tuple[Any, Any],
) -> None:
    _module, ir = canonical_go_symbol_compilation
    inbound = ir.inbound_bindings
    matches = {
        item["id"]: item for item in inbound.match_descriptors if item["class_id"] == "otlp.genai.duration.metric.v1"
    }
    assert set(matches) == {
        "otlp.genai.duration.metric.v1.gen-ai-client",
        "otlp.genai.duration.metric.v1.gen-ai",
        "otlp.genai.duration.metric.v1.llm",
        "otlp.genai.duration.metric.v1.claude-code",
        "otlp.genai.duration.metric.v1.codex",
    }
    assert all(len(item["target_ids"]) == 1 for item in matches.values())
    assert {
        next(
            predicate["values"][0]
            for predicate in item["discriminator"]["predicates"]
            if predicate["location"] == "instrument_name"
        )
        for item in matches.values()
    } == {
        "gen_ai.client.operation.duration",
        "gen_ai.operation.duration",
        "llm.operation.duration",
        "claude_code.operation.duration",
        "codex.operation.duration",
    }
    duration_rule = {
        "kind": "scale-table-v1",
        "target_unit": "s",
        "accepted": tuple(
            {"source_unit": unit, "scale": scale}
            for unit, scale in (
                ("", 1.0),
                ("s", 1.0),
                ("second", 1.0),
                ("seconds", 1.0),
                ("ms", 0.001),
                ("millisecond", 0.001),
                ("milliseconds", 0.001),
                ("us", 0.000001),
                ("microsecond", 0.000001),
                ("microseconds", 0.000001),
                ("ns", 0.000000001),
                ("nanosecond", 0.000000001),
                ("nanoseconds", 0.000000001),
            )
        ),
    }
    assert all(item["mapping"]["source_unit_rule"] == duration_rule for item in matches.values())
    targets = {item["id"]: item for item in inbound.target_descriptors}
    assert all(
        targets[item["target_ids"][0]]["instrument_unit"] == "s"
        and targets[item["target_ids"][0]]["source_unit_rule"] == duration_rule
        for item in matches.values()
    )

    token = next(item for item in inbound.match_descriptors if item["class_id"] == "otlp.claudecode.token_usage.v1")
    assert token["mapping"]["source_unit_rule"] == {
        "kind": "scale-table-v1",
        "target_unit": "{token}",
        "accepted": (
            {"source_unit": "", "scale": 1.0},
            {"source_unit": "{token}", "scale": 1.0},
            {"source_unit": "token", "scale": 1.0},
            {"source_unit": "tokens", "scale": 1.0},
        ),
    }
    for native in (item for item in inbound.match_descriptors if item["class_id"] == "otlp.native.metric.v8"):
        target = targets[native["target_ids"][0]]
        assert native["mapping"]["source_unit_rule"] == {
            "kind": "target-unit-equality-v1",
            "target_unit": target["instrument_unit"],
            "accepted": ({"source_unit": target["instrument_unit"], "scale": 1.0},),
        }
    native_matches = [item for item in inbound.match_descriptors if item["class_id"] == "otlp.native.metric.v8"]
    native_families = [targets[item["target_ids"][0]]["family"] for item in native_matches]
    assert native_matches
    assert len(native_families) == len(set(native_families))


@pytest.mark.parametrize(
    ("class_id", "mutate", "message"),
    [
        (
            "otlp.genai.duration.metric.v1",
            lambda mapping: mapping["unit_rule"]["accepted"].append({"source_unit": "minute", "scale": 60}),
            "canonical source-unit table/order mismatch",
        ),
        (
            "otlp.genai.duration.metric.v1",
            lambda mapping: mapping["unit_rule"]["accepted"][4].__setitem__("scale", 1),
            "canonical source-unit table/order mismatch",
        ),
        (
            "otlp.claudecode.token_usage.v1",
            lambda mapping: mapping["unit_rule"]["accepted"][2].__setitem__("source_unit", "Token"),
            "canonical source-unit table/order mismatch",
        ),
        (
            "otlp.native.metric.v8",
            lambda mapping: mapping["unit_rule"].__setitem__("kind", "scale-table-v1"),
            "reverse metrics require target-unit-equality-v1",
        ),
    ],
)
def test_inbound_source_unit_grammar_rejects_any_table_drift(
    canonical_go_symbol_compilation: tuple[Any, Any],
    class_id: str,
    mutate: Any,
    message: str,
) -> None:
    module, ir = canonical_go_symbol_compilation
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    binding = next(item for item in registry["inbound_bindings"]["binding_classes"] if item["id"] == class_id)
    mutate(binding["mapping"])
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    with pytest.raises(module.RegistryError, match=message):
        module._parse_inbound_otlp(registry["inbound_bindings"], groups=groups)


def test_inbound_metric_source_projection_contract_is_closed_and_complete(
    canonical_go_symbol_compilation: tuple[Any, Any],
) -> None:
    module, ir = canonical_go_symbol_compilation
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    inbound = module._parse_inbound_otlp(
        registry["inbound_bindings"],
        groups={group.id: group for domain in ir.domains for group in domain.groups},
    )
    assert tuple(item["id"] for item in inbound.source_normalizers) == (
        "bounded-label-v1",
        "identifier-label-v1",
        "genai-provider-label-v1",
        "genai-model-label-v1",
        "genai-operation-label-v1",
        "token-type-label-v1",
    )
    assert tuple(item["id"] for item in inbound.source_projection_plans) == (
        "genai-token-metric-v1",
        "genai-duration-metric-v1",
    )
    token, duration = inbound.source_projection_plans
    assert tuple(rule["target"] for rule in token["field_rules"]) == (
        "gen_ai.operation.name",
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "gen_ai.token.type",
    )
    assert token["field_rules"][1]["source_groups"] == (
        {"placement": "metric_point_attribute", "keys": ("gen_ai.provider.name",)},
        {"placement": "authenticated_source", "keys": ("$authenticated_source",)},
        {"placement": "resource_attribute", "keys": ("service.name",)},
    )
    assert token["field_rules"][2]["requirement"] == "required"
    assert token["field_rules"][2]["source_groups"][-1] == {"placement": "fixed", "keys": ("unknown",)}
    assert tuple(item["id"] for item in token["cumulative_series"]["components"]) == (
        "authenticated_source",
        "resource_service_name",
        "resource_service_instance_id",
        "instrument_name",
        "normalized_model",
        "token_type",
        "normalized_conversation",
    )
    assert token["cumulative_series"]["framing"] == "length-prefixed-presence-v1"
    assert token["cumulative_series"]["normalization_stage"] == "before_framing"
    assert token["cumulative_series"]["reset_epoch"] == {
        "role": "reset_only",
        "identity": False,
        "placement": "metric_point_start_time",
        "key": "$start_time_unix_nano",
        "normalization": "unsigned-epoch-nanos-v1",
    }
    assert duration["cumulative_series"] is None
    assert duration["field_rules"][0]["source_groups"] == (
        {"placement": "metric_point_attribute", "keys": ("gen_ai.operation.name",)},
        {"placement": "fixed", "keys": ("chat",)},
    )
    assert tuple(
        match["id"] for match in inbound.match_descriptors if match["mapping"]["source_projection_plan"] is not None
    ) == (
        "otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage",
        "otlp.codex.token_usage.v1.metric.gen_ai.client.token.usage",
        "otlp.genai.duration.metric.v1.claude-code",
        "otlp.genai.duration.metric.v1.codex",
        "otlp.genai.duration.metric.v1.gen-ai",
        "otlp.genai.duration.metric.v1.gen-ai-client",
        "otlp.genai.duration.metric.v1.llm",
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("duplicate_normalizer", "duplicate source normalizer|inventory/order mismatch"),
        ("colliding_normalizer_input", "colliding exact-map input"),
        ("duplicate_plan", "duplicate source projection plan|inventory/order mismatch"),
        ("unused_plan", "required for claude-token-usage-v1|declarations must each be referenced exactly once"),
        ("unknown_plan", "unknown plan"),
        ("missing_field", "cover target fields exactly"),
        ("duplicate_field", "duplicate field disposition"),
        ("unknown_normalizer", "unsupported source normalization"),
        ("duplicate_source", "colliding source declaration|duplicate source key|duplicate value"),
        ("unknown_placement", "unknown source placement"),
        ("component_order", "canonical series identity/order mismatch"),
        ("start_time_identity", "start time is reset metadata only"),
        ("aliases_and_plan", "cannot both own fields"),
        (
            "plan_family",
            "cover target fields exactly|target family does not match expanded primary|projection.*incomplete",
        ),
    ),
)
def test_inbound_metric_source_projection_rejects_every_contract_drift(
    canonical_go_symbol_compilation: tuple[Any, Any],
    mutation: str,
    message: str,
) -> None:
    module, ir = canonical_go_symbol_compilation
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    inbound = registry["inbound_bindings"]
    normalizers = inbound["source_normalizers"]
    plans = inbound["source_projection_plans"]
    token_class = next(item for item in inbound["binding_classes"] if item["id"] == "otlp.claudecode.token_usage.v1")
    if mutation == "duplicate_normalizer":
        normalizers[1]["id"] = normalizers[0]["id"]
    elif mutation == "colliding_normalizer_input":
        operation = next(item for item in normalizers if item["id"] == "genai-operation-label-v1")
        operation["rules"][1]["inputs"].append(operation["rules"][0]["inputs"][0])
    elif mutation == "duplicate_plan":
        plans[1]["id"] = plans[0]["id"]
    elif mutation == "unused_plan":
        token_class["mapping"]["source_projection_plan"] = "genai-duration-metric-v1"
    elif mutation == "unknown_plan":
        token_class["mapping"]["source_projection_plan"] = "future-plan-v1"
    elif mutation == "missing_field":
        plans[0]["field_rules"].pop()
    elif mutation == "duplicate_field":
        plans[0]["field_rules"][1]["target"] = plans[0]["field_rules"][0]["target"]
    elif mutation == "unknown_normalizer":
        plans[0]["field_rules"][1]["normalization"] = "future-normalizer-v1"
    elif mutation == "duplicate_source":
        group = plans[0]["field_rules"][2]["source_groups"][0]
        group["keys"].append(group["keys"][0])
    elif mutation == "unknown_placement":
        plans[0]["field_rules"][1]["source_groups"][0]["placement"] = "scope_attribute"
    elif mutation == "component_order":
        components = plans[0]["cumulative_series"]["components"]
        components[0], components[1] = components[1], components[0]
    elif mutation == "start_time_identity":
        plans[0]["cumulative_series"]["reset_epoch"]["identity"] = True
    elif mutation == "aliases_and_plan":
        token_class["mapping"]["alias_sets"] = ["request-model-v1"]
    elif mutation == "plan_family":
        plans[0]["target_family"] = "metric.gen_ai.client.operation.duration"
    else:
        raise AssertionError(mutation)
    with pytest.raises(module.RegistryError, match=message):
        module._parse_inbound_otlp(
            inbound,
            groups={group.id: group for domain in ir.domains for group in domain.groups},
        )


def test_go_symbol_policy_tokenization_is_exact_and_strict() -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_policy")
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    policy, overrides = module._parse_go_symbol_contract(registry["go_symbol_policy"], None)

    assert overrides == ()
    assert policy.separators == (".", "-", "/", "_")
    assert tuple(policy.brand_spellings.items()) == (
        ("defenseclaw", "DefenseClaw"),
        ("opentelemetry", "OpenTelemetry"),
        ("otel", "OTel"),
    )
    assert (
        module._go_public_name(
            policy,
            "defenseclaw/opentelemetry-otel.ai_utf8",
            "test",
        )
        == "DefenseClawOpenTelemetryOTelAIUTF8"
    )
    assert module._go_public_name(policy, "gen_ai.canonical_json", "test") == "GenAICanonicalJSON"
    for source, message in (
        ("a..b", "empty Go symbol token"),
        ("a-é", "ASCII letters and digits"),
        ("1thing", "leading-digit Go symbol result"),
        ("a:b", "ASCII letters and digits"),
    ):
        with pytest.raises(module.RegistryError, match=message):
            module._go_public_name(policy, source, "test")


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "extra",
        "type",
        "value",
        "separator_order",
        "duplicate_separator",
        "initialism_order",
        "duplicate_initialism",
        "brand_value",
        "brand_extra",
    ),
)
def test_go_symbol_policy_rejects_every_noncanonical_shape(mutation: str) -> None:
    module = _load_generator_module(f"telemetry_registry_go_symbol_policy_{mutation}")
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    policy = copy.deepcopy(registry["go_symbol_policy"])
    if mutation == "missing":
        del policy["package"]
    elif mutation == "extra":
        policy["future"] = True
    elif mutation == "type":
        policy["version"] = "1"
    elif mutation == "value":
        policy["package"] = "telemetry"
    elif mutation == "separator_order":
        policy["separators"] = list(reversed(policy["separators"]))
    elif mutation == "duplicate_separator":
        policy["separators"].append(".")
    elif mutation == "initialism_order":
        policy["initialisms"] = list(reversed(policy["initialisms"]))
    elif mutation == "duplicate_initialism":
        policy["initialisms"].append("AI")
    elif mutation == "brand_value":
        policy["brand_spellings"]["otel"] = "Otel"
    elif mutation == "brand_extra":
        policy["brand_spellings"]["genai"] = "GenAI"
    with pytest.raises(module.RegistryError):
        module._parse_go_symbol_contract(policy, None)


def test_go_symbol_overrides_absent_and_empty_are_equivalent(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_go_symbol_empty_overrides")
    absent = module.compile_registry(root)
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["go_symbol_overrides"] = []
    _write_yaml(registry_path, registry)
    explicit_empty = module.compile_registry(root)

    assert absent.go_symbol_overrides == explicit_empty.go_symbol_overrides == ()
    assert absent.go_symbol_table == explicit_empty.go_symbol_table
    with pytest.raises(dataclasses.FrozenInstanceError):
        absent.go_symbol_table.rows[0].symbol = "Changed"


def test_go_symbol_override_rules_reject_policy_equivalence_and_shape_evasion(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    module = _load_generator_module("telemetry_registry_go_symbol_overrides")
    registry_path = root / "schemas/telemetry/v8/registry.yaml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    registry["go_symbol_overrides"] = [
        {
            "kind": "attribute",
            "source_id": "defenseclaw.test.name",
            "symbol": "TelemetryAttributeDefenseClawTestName",
            "reason": "synthetic policy-equivalent override",
        }
    ]
    _write_yaml(registry_path, registry)
    with pytest.raises(module.RegistryError, match="policy-equivalent override"):
        module.compile_registry(root)

    assert module._go_override_has_required_shape(
        "family_input",
        "LogDefenseClawAuditInput",
        "LogDefenseClawAuditV2Input",
    )
    assert not module._go_override_has_required_shape(
        "family_input",
        "LogDefenseClawAuditInput",
        "SpanDefenseClawAuditV2Input",
    )
    assert not module._go_override_has_required_shape(
        "family_input",
        "LogDefenseClawAuditInput",
        "LogDefenseclawAuditV2Input",
    )
    assert not module._go_override_has_required_shape(
        "family_builder",
        "BuildMetricOTelRequests",
        "BuildLogOTelRequestsV2",
    )


def test_go_symbol_override_parser_covers_all_kinds_and_compound_source_grammar() -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_override_kinds")
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    compound = {
        "structured_member",
        "structured_arm",
        "structured_member_input",
        "structured_member_constructor",
        "span_event_input",
        "span_event_constructor",
        "span_link_input",
        "span_link_constructor",
    }
    overrides = [
        {
            "kind": kind,
            "source_id": f"owner.{index}#member.{index}" if kind in compound else f"source.{index}",
            "symbol": f"ReviewedOverride{index}",
            "reason": f"reviewed collision {index}",
        }
        for index, kind in enumerate(module.GO_SYMBOL_KIND_ORDER)
    ]
    _, parsed = module._parse_go_symbol_contract(registry["go_symbol_policy"], overrides)
    assert tuple(item.kind for item in parsed) == module.GO_SYMBOL_KIND_ORDER


@pytest.mark.parametrize(
    ("kind", "source_id"),
    (
        ("attribute", "owner#member"),
        ("structured_member", "owner"),
        ("structured_member", "owner#member#extra"),
        ("structured_member", "owner#"),
        ("span_event_input", "#event"),
        ("span_link_constructor", "owner##relation"),
        ("attribute", "owner..member"),
        ("structured_member", "owner/#member"),
    ),
)
def test_go_symbol_override_parser_rejects_malformed_source_ids(kind: str, source_id: str) -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_override_malformed")
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    override = [{"kind": kind, "source_id": source_id, "symbol": "ReviewedSymbol", "reason": "reviewed"}]
    with pytest.raises(module.RegistryError):
        module._parse_go_symbol_contract(registry["go_symbol_policy"], override)


def test_go_symbol_override_parser_rejects_unknown_duplicate_unused_and_empty_reason() -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_override_failures")
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text(encoding="utf-8"))
    policy = registry["go_symbol_policy"]
    with pytest.raises(module.RegistryError, match="unknown Go symbol kind"):
        module._parse_go_symbol_contract(
            policy,
            [{"kind": "future", "source_id": "source", "symbol": "Reviewed", "reason": "reviewed"}],
        )
    duplicate = {
        "kind": "attribute",
        "source_id": "source",
        "symbol": "TelemetryAttributeSourceV2",
        "reason": "reviewed",
    }
    with pytest.raises(module.RegistryError, match="duplicate kind/source_id"):
        module._parse_go_symbol_contract(policy, [duplicate, dict(duplicate)])
    with pytest.raises(module.RegistryError, match="nonempty bounded string"):
        module._parse_go_symbol_contract(
            policy,
            [{"kind": "attribute", "source_id": "source", "symbol": "Reviewed", "reason": ""}],
        )
    candidate = module.GoSymbolIR("attribute", "source", "TelemetryAttributeSource", "exported_const")
    unused = module.GoSymbolOverrideIR("attribute", "other", "TelemetryAttributeOtherV2", "reviewed")
    with pytest.raises(module.RegistryError, match="unused override"):
        module._apply_go_symbol_overrides((candidate,), (unused,))


def test_go_symbol_collision_only_override_resolves_exactly_one_collision() -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_collision_override")
    candidates = (
        module.GoSymbolIR("attribute", "source.a", "TelemetryAttributeThing", "exported_const"),
        module.GoSymbolIR("attribute", "source.b", "TelemetryAttributeThing", "exported_const"),
    )
    override = module.GoSymbolOverrideIR(
        "attribute",
        "source.b",
        "TelemetryAttributeThingB",
        "reviewed collision disambiguator",
    )
    rows = module._apply_go_symbol_overrides(candidates, (override,))
    assert tuple(row.symbol for row in rows) == ("TelemetryAttributeThing", "TelemetryAttributeThingB")

    post_collision = candidates + (
        module.GoSymbolIR("attribute", "source.c", "TelemetryAttributeThingB", "exported_const"),
    )
    with pytest.raises(module.RegistryError, match="Go symbol collision"):
        module._apply_go_symbol_overrides(post_collision, (override,))

    noncollision = (module.GoSymbolIR("attribute", "source.only", "TelemetryAttributeOnly", "exported_const"),)
    arbitrary = module.GoSymbolOverrideIR(
        "attribute",
        "source.only",
        "TelemetryAttributeOnlyV2",
        "not backed by a collision",
    )
    with pytest.raises(module.RegistryError, match="no reviewed default collision"):
        module._apply_go_symbol_overrides(noncollision, (arbitrary,))


def test_go_symbol_row_validation_rejects_literal_cross_kind_collision() -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_cross_kind_collision")
    rows = (
        module.GoSymbolIR("attribute", "source.attribute", "TelemetryCollision", "exported_const"),
        module.GoSymbolIR("family", "source.family", "TelemetryCollision", "exported_const"),
    )
    with pytest.raises(module.RegistryError, match="Go symbol collision"):
        module._validate_go_symbol_rows(rows)

    signal_stripped_families = (
        module.GoSymbolIR("family", "log.shared", "TelemetryFamilyShared", "exported_const"),
        module.GoSymbolIR("family", "span.shared", "TelemetryFamilyShared", "exported_const"),
    )
    with pytest.raises(module.RegistryError, match="Go symbol collision"):
        module._validate_go_symbol_rows(signal_stripped_families)


@pytest.mark.parametrize(
    ("symbol", "message"),
    (
        ("type", "reserved identifier collision"),
        ("Éxported", "invalid or leading-digit identifier"),
        ("1Exported", "invalid or leading-digit identifier"),
    ),
)
def test_go_symbol_row_validation_rejects_reserved_nonascii_and_leading_digit(
    symbol: str,
    message: str,
) -> None:
    module = _load_generator_module("telemetry_registry_go_symbol_row_validation")
    row = module.GoSymbolIR("attribute", "source", symbol, "exported_const")
    with pytest.raises(module.RegistryError, match=message):
        module._validate_go_symbol_rows((row,))


def test_canonical_go_symbol_table_is_deterministic_unique_and_semantically_named(
    canonical_go_symbol_compilation: tuple[Any, Any],
) -> None:
    module, ir = canonical_go_symbol_compilation
    table = ir.go_symbol_table
    assert table.rows
    assert dict(table.kind_counts) == Counter(row.kind for row in table.rows)
    assert dict(table.declaration_form_counts) == Counter(row.declaration_form for row in table.rows)
    rank = {kind: index for index, kind in enumerate(module.GO_SYMBOL_KIND_ORDER)}
    assert list(table.rows) == sorted(
        table.rows,
        key=lambda row: (rank[row.kind], row.source_id.encode("ascii")),
    )
    assert len({(row.kind, row.source_id) for row in table.rows}) == len(table.rows)
    assert len({row.symbol for row in table.rows}) == len(table.rows)

    rows = {(row.kind, row.source_id): row for row in table.rows}
    assert rows[("family", "span.model.chat")].symbol == "TelemetryFamilyModelChat"
    assert rows[("span_event", "model.retry")].symbol == "TelemetrySpanEventModelRetry"
    assert rows[("structured_type", "gen_ai.canonical_json")].symbol == ("TelemetryStructuredGenAICanonicalJSON")
    assert rows[("structured_type", "gen_ai.canonical_json")].declaration_form == "exported_type"
    assert rows[("structured_member", "gen_ai.canonical_json#entry")].declaration_form == "exported_const"
    assert rows[("structured_arm", "gen_ai.canonical_json#finite_double")].declaration_form == "exported_type"
    assert rows[("structured_member_input", "gen_ai.canonical_json#entry")].symbol == (
        "GenAICanonicalJSONEntryMemberInput"
    )
    assert rows[("structured_member_constructor", "gen_ai.canonical_json#entry")].symbol == (
        "NewGenAICanonicalJSONEntryMember"
    )
    assert rows[("family_input", "span.model.chat")].symbol == "SpanModelChatInput"
    assert rows[("family_builder", "span.model.chat")].symbol == "BuildSpanModelChat"
    assert rows[("attribute", "defenseclaw.agent.reported_cost.present")].symbol == (
        "TelemetryAttributeDefenseClawAgentReportedCostPresent"
    )
    assert rows[("condition", "agent-reported-cost-available-v1")].symbol == (
        "TelemetryConditionAgentReportedCostAvailableV1"
    )
    assert ("condition_fact", "agent_reported_cost_available") not in rows
    assert rows[("span_event_input", "span.model.chat#model.retry")].symbol == ("SpanModelChatModelRetryEventInput")
    assert rows[("span_link_constructor", "span.model.chat#caused_by")].symbol == ("NewSpanModelChatCausedByLink")

    payload = json.dumps(
        [[row.kind, row.source_id, row.symbol, row.declaration_form] for row in table.rows],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(b"DefenseClaw GoSymbolTableIR v1\x00" + payload).hexdigest() == table.table_sha256


def test_go_symbol_file_domain_ownership_is_complete(
    canonical_go_symbol_compilation: tuple[Any, Any],
) -> None:
    _, ir = canonical_go_symbol_compilation
    family_domains = {
        group.id: domain.domain
        for domain in ir.domains
        for group in domain.groups
        if group.type in {"log", "span", "metric"}
    }
    ownership = {"ids": 0, "genai": 0, "security": 0, "operations": 0}
    for row in ir.go_symbol_table.rows:
        if row.declaration_form == "exported_const":
            ownership["ids"] += 1
        elif row.kind.startswith("structured_"):
            ownership["genai"] += 1
        elif row.source_id == "resource.core" and row.kind.startswith("resource_attributes_"):
            ownership["operations"] += 1
        else:
            family_id = row.source_id.split("#", 1)[0]
            ownership[family_domains[family_id]] += 1
    assert sum(ownership.values()) == len(ir.go_symbol_table.rows)
    assert all(count > 0 for count in ownership.values())


def test_go_symbol_policy_and_table_are_materialized_and_row_order_is_digest_significant(
    canonical_go_symbol_compilation: tuple[Any, Any],
) -> None:
    module, ir = canonical_go_symbol_compilation
    facts = ir.materialized_view.facts["fields"]
    assert facts["go_symbol_policy"]["$type"] == "GoSymbolPolicyIR"
    assert facts["go_symbol_overrides"] == ()
    assert facts["go_symbol_table"]["$type"] == "GoSymbolTableIR"
    reversed_rows = tuple(reversed(ir.go_symbol_table.rows))
    assert module._go_symbol_table_digest(reversed_rows) != ir.go_symbol_table.table_sha256
