# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import defenseclaw.observability.v8_migration as migration_module
import pytest
import yaml
from defenseclaw.observability.presets import GALILEO
from defenseclaw.observability.schema_resources import v7_exporter_selection_bytes
from defenseclaw.observability.v8_compatibility import V7CompatibilitySelection
from defenseclaw.observability.v8_config import BUCKETS, load_validate_v8
from defenseclaw.observability.v8_migration import (
    V8MigrationDependencyError,
    V8MigrationError,
    convert_v7_observability_to_v8,
)

_GENERATED_COMPATIBILITY = json.loads(v7_exporter_selection_bytes())
_TYPED_COMPATIBILITY = V7CompatibilitySelection.from_mapping(_GENERATED_COMPATIBILITY)
_ALL_BUCKETS = list(BUCKETS)
_TEST_DATA_DIR = str(Path(Path.cwd().anchor) / "var" / "lib" / "defenseclaw")
_FRESH_080_DEFAULT_OTEL_CONFIG = """config_version: 7
otel:
  enabled: false
  endpoint: ""
  protocol: grpc
  headers: {}
  tls: {ca_cert: "", insecure: false}
  batch:
    max_queue_size: 2048
    max_export_batch_size: 512
    scheduled_delay_ms: 5000
  traces:
    enabled: true
    sampler: always_on
    sampler_arg: "1.0"
    endpoint: ""
    protocol: ""
    url_path: ""
  logs:
    enabled: true
    emit_individual_findings: false
    endpoint: ""
    protocol: ""
    url_path: ""
  metrics:
    enabled: true
    export_interval_s: 60
    endpoint: ""
    protocol: ""
    url_path: ""
  resource:
    attributes: {}
"""
_FRESH_080_NAMED_OTEL_CONFIG = """config_version: 7
otel:
  enabled: false
  traces:
    sampler: always_on
    sampler_arg: "1.0"
  logs:
    emit_individual_findings: false
  destinations:
    - name: generic-otlp
      preset: generic-otlp
      enabled: false
      endpoint: ""
      protocol: grpc
      tls: {ca_cert: "", insecure: false}
      batch:
        max_queue_size: 2048
        max_export_batch_size: 512
        scheduled_delay_ms: 5000
      traces: {enabled: true, endpoint: "", protocol: "", url_path: ""}
      logs: {enabled: true, endpoint: "", protocol: "", url_path: ""}
      metrics: {enabled: true, endpoint: "", protocol: "", url_path: "", export_interval_s: 60}
  resource:
    attributes: {}
"""
_ALL_SPAN_EVENT_NAMES = [
    "span.admin.operation",
    "span.agent.invoke",
    "span.agent.transition",
    "span.ai.discovery",
    "span.ai.discovery.detector",
    "span.approval.resolve",
    "span.asset.scan",
    "span.asset.scan.phase",
    "span.asset.transition",
    "span.config.reload",
    "span.destination.export",
    "span.diagnostic.canary",
    "span.enforcement.apply",
    "span.finding.enrich",
    "span.guardrail.apply",
    "span.guardrail.judge",
    "span.guardrail.phase",
    "span.model.chat",
    "span.model.embeddings",
    "span.network.request",
    "span.retrieval.search",
    "span.telemetry.normalize",
    "span.telemetry.receive",
    "span.tool.execute",
    "span.workflow.run",
]


def _convert(source: str | bytes, environment: Mapping[str, str] | None = None, **kwargs: object):
    kwargs.setdefault("effective_data_dir", _TEST_DATA_DIR)
    kwargs.setdefault("compatibility_selection", _TYPED_COMPATIBILITY)
    return convert_v7_observability_to_v8(source, environment or {}, **kwargs)


def _document(result: object) -> dict[str, object]:
    candidate = result.candidate  # type: ignore[attr-defined]
    document = yaml.safe_load(candidate)
    assert isinstance(document, dict)
    return document


def _destination(document: Mapping[str, object], name: str) -> dict[str, object]:
    observability = document["observability"]
    assert isinstance(observability, dict)
    destinations = observability["destinations"]
    assert isinstance(destinations, list)
    return next(item for item in destinations if isinstance(item, dict) and item.get("name") == name)


def _galileo_span_filter_yaml() -> str:
    value = {
        "span_filter": {
            "operations": [
                {"name": name, "require_attributes": list(attributes)}
                for name, attributes in GALILEO.span_filter_operations
            ]
        }
    }
    return "\n".join("      " + line for line in yaml.safe_dump(value, sort_keys=False).rstrip().splitlines())


def test_already_valid_v8_is_an_exact_noop() -> None:
    source = b"# exact bytes\r\nconfig_version: 8\r\nobservability: {}\r\n"

    result = convert_v7_observability_to_v8(
        source,
        {"DEFENSECLAW_DISABLE_REDACTION": "1"},
        compatibility_selection=None,
    )

    assert result.candidate == source
    assert result.changed is False
    assert result.already_v8 is True
    assert result.effective_data_dir is None
    assert result.source_sha256 == hashlib.sha256(source).hexdigest()
    assert result.candidate_sha256 == result.source_sha256
    assert result.source_sha256 not in repr(result)
    assert result.candidate_sha256 not in repr(result)
    assert result.environment_edits == ()


def test_private_upstream_allowlist_is_preserved_only_when_explicit() -> None:
    explicit = _convert(
        """config_version: 7
guardrail:
  enabled: true
  allow_private_upstreams:
    - 10.20.30.40
    - fd12:3456::8
"""
    )
    explicit_guardrail = _document(explicit)["guardrail"]
    assert explicit_guardrail["allow_private_upstreams"] == ["10.20.30.40", "fd12:3456::8"]
    load_validate_v8(explicit.candidate)

    absent = _convert("config_version: 7\nguardrail: {enabled: true}\n")
    absent_guardrail = _document(absent)["guardrail"]
    assert "allow_private_upstreams" not in absent_guardrail


def test_private_upstream_environment_is_runtime_only_and_not_materialized() -> None:
    result = _convert(
        "config_version: 7\nguardrail: {enabled: true}\n",
        {"DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS": "10.20.30.40,fd12:3456::8"},
    )
    document = _document(result)
    assert "allow_private_upstreams" not in document["guardrail"]
    assert "DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS" not in result.candidate.decode()
    assert "DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS" not in {
        dependency.name for dependency in result.environment_dependencies
    }
    assert result.environment_edits == ()


def test_v7_loads_packaged_compatibility_and_fails_closed_when_it_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = convert_v7_observability_to_v8(
        "config_version: 7\n",
        {},
        effective_data_dir=_TEST_DATA_DIR,
    )
    assert result.summary.destination_version == 8

    monkeypatch.setattr(
        migration_module,
        "load_packaged_v7_compatibility_selection",
        lambda: (_ for _ in ()).throw(FileNotFoundError("missing package resource")),
    )
    with pytest.raises(V8MigrationDependencyError) as unavailable:
        convert_v7_observability_to_v8(
            "config_version: 7\n",
            {},
            effective_data_dir=_TEST_DATA_DIR,
        )
    assert unavailable.value.code == "compatibility_selection_unavailable"

    malformed = dict(_GENERATED_COMPATIBILITY, schema_version=2)
    with pytest.raises(V8MigrationDependencyError) as invalid:
        convert_v7_observability_to_v8(
            "config_version: 7\n",
            {},
            effective_data_dir=_TEST_DATA_DIR,
            compatibility_selection=malformed,
        )
    assert invalid.value.code == "compatibility_selection_invalid"


def test_no_otel_upgrade_keeps_every_v7_local_log_bucket_collected() -> None:
    result = _convert("config_version: 7\n")
    observability = _document(result)["observability"]

    assert observability["defaults"] == {
        "collect": {"logs": False, "traces": False, "metrics": False},
        "redaction_profile": "legacy-v7",
    }
    assert set(observability["buckets"]) == set(BUCKETS)
    assert all(policy == {"collect": {"logs": True}} for policy in observability["buckets"].values())
    assert all(
        route["signals"] == ["logs"]
        for destination_name in ("gateway-jsonl", "gateway-console")
        for route in _destination({"observability": observability}, destination_name)["routes"]
    )
    load_validate_v8(result.candidate)


def test_published_v7_claw_custody_field_survives_v8_validation() -> None:
    result = _convert(
        """config_version: 7
claw:
  mode: codex
  home_dir: ~/.codex
  config_file: ~/.codex/config.toml
  workspace_dir: ''
  openclaw_home_original: ''
otel:
  enabled: false
  destinations: []
"""
    )

    document = _document(result)
    assert document["claw"] == {
        "mode": "codex",
        "home_dir": "~/.codex",
        "config_file": "~/.codex/config.toml",
        "workspace_dir": "",
        "openclaw_home_original": "",
    }
    load_validate_v8(result.candidate)


def test_v6_flat_otel_converts_directly_to_v8_without_intermediate_writer() -> None:
    result = _convert(
        """config_version: 6
otel:
  enabled: true
  endpoint: 127.0.0.1:4317
  protocol: grpc
  traces: {enabled: true}
  metrics: {enabled: true}
  logs: {enabled: true}
"""
    )
    document = _document(result)
    names = {destination["name"] for destination in document["observability"]["destinations"]}

    assert result.summary.source_version == 6
    assert result.summary.destination_version == 8
    assert "local-observability" in names
    load_validate_v8(result.candidate)


def test_representative_mapping_is_valid_deterministic_and_idempotent() -> None:
    source = """# ┌──── OBSERVABILITY GUIDE ────┐
# collect -> route -> redact -> deliver
config_version: 7
data_dir: ~/.defenseclaw
audit_db: ~/.defenseclaw/audit.db
judge_bodies_db: ~/.defenseclaw/judge.db
guardrail:
  enabled: true
otel:
  enabled: true
  traces: {sampler: parentbased_traceidratio, sampler_arg: '0.25'}
  logs: {emit_individual_findings: false}
  metrics: {export_interval_s: 60, temporality: delta}
  resource:
    attributes: {service.name: defenseclaw, deployment.environment: test}
  destinations:
    - name: local-observability
      preset: local-otlp
      enabled: true
      protocol: grpc
      endpoint: 127.0.0.1:4317
      tls: {insecure: true}
      batch: {max_queue_size: 4096, max_export_batch_size: 512, scheduled_delay_ms: 2500}
      traces: {enabled: true}
      logs: {enabled: true}
      metrics: {enabled: true, export_interval_s: 60, temporality: delta}
privacy: {disable_redaction: false}
ai_discovery: {enabled: true, emit_otel: false}
# keep this comment with the unrelated section
notifications: {enabled: true}
"""

    first = _convert(source)
    second = _convert(source)
    document = _document(first)
    observability = document["observability"]
    assert isinstance(observability, dict)

    assert first.candidate == second.candidate
    assert first.candidate_sha256 == second.candidate_sha256
    assert first.summary.otlp_destinations == 1
    assert first.summary.local_observability == "partial"
    assert observability["local"] == {
        "path": "~/.defenseclaw/audit.db",
        "judge_bodies_path": "~/.defenseclaw/judge.db",
    }
    assert observability["trace_policy"] == {
        "sampler": "parentbased_traceidratio",
        "sampler_arg": "0.25",
    }
    assert observability["metric_policy"] == {
        "export_interval_seconds": 60,
        "temporality": "delta",
    }
    assert observability["resource"] == {
        "attributes": {
            "service.name": "defenseclaw",
            "deployment.environment.name": "test",
        }
    }
    assert first.summary.resource_migrations == (
        "environment_canonicalized",
        "service_name_preserved",
    )
    assert observability["defaults"] == {
        "collect": {"logs": False, "traces": False, "metrics": False},
        "redaction_profile": "legacy-v7",
    }
    assert observability["buckets"]["compliance.activity"] == {
        "collect": {"logs": True, "traces": True, "metrics": True}
    }
    assert observability["buckets"]["model.io"] == {"collect": {"logs": True, "traces": True, "metrics": True}}
    assert observability["buckets"]["ai.discovery"] == {"collect": {"logs": True}}
    local = _destination(document, "local-observability")
    assert local["network_safety"] == {"allow_private_networks": True}
    assert {route["signals"][0] for route in local["routes"]} == {"logs", "traces", "metrics"}
    drop_route = next(route for route in local["routes"] if route["name"] == "legacy-individual-findings-disabled-1")
    assert drop_route["selector"]["event_names"] == ["finding.observed"]
    log_route = next(route for route in local["routes"] if route["name"] == "legacy-local-observability-logs-1")
    assert "security.finding" in log_route["selector"]["buckets"]
    assert log_route["selector"]["buckets"] == _ALL_BUCKETS
    assert local["routes"][0] == {
        "name": "legacy-ai-discovery-disabled",
        "signals": ["logs", "traces", "metrics"],
        "selector": {"buckets": ["ai.discovery"]},
        "action": "drop",
    }
    assert any(route.get("selector", {}).get("buckets") == list(BUCKETS) for route in local["routes"])
    metric_route = next(route for route in local["routes"] if route["signals"] == ["metrics"])
    assert "redaction_profile" not in metric_route
    rendered = first.candidate.decode()
    assert rendered.startswith("# ┌──── OBSERVABILITY GUIDE ────┐")
    assert "# keep this comment with the unrelated section" in rendered
    assert "notifications: {enabled: true}" in rendered
    assert rendered.index("data_dir:") < rendered.index("observability:") < rendered.index("guardrail:")
    load_validate_v8(first.candidate)

    retry = _convert(first.candidate)
    assert retry.already_v8 is True
    assert retry.changed is False
    assert retry.candidate == first.candidate


def test_complete_local_observability_selection_reports_full_dashboard_coverage() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: local-observability
      preset: local-otlp
      enabled: true
      endpoint: 127.0.0.1:4317
      protocol: grpc
      traces: {enabled: true}
      logs: {enabled: true}
      metrics: {enabled: true}
"""
    )

    assert result.summary.local_observability == "full"
    assert "partial_dashboard_capability:local-observability" not in result.warnings


@pytest.mark.parametrize("sampler", [None, "", "always_on", "traceidratio", "parentbased_always_off", "future"])
def test_v7_always_sample_vocabulary_maps_semantically(sampler: str | None) -> None:
    sampler_line = "" if sampler is None else f"  traces: {{sampler: '{sampler}', sampler_arg: '0.01'}}\n"
    result = _convert(
        "config_version: 7\notel:\n"
        "  enabled: true\n"
        f"{sampler_line}"
        "  destinations:\n"
        "    - {name: traces, enabled: true, endpoint: 'https://collector.example.test', "
        "protocol: grpc, traces: {enabled: true}}\n"
    )

    assert _document(result)["observability"]["trace_policy"] == {"sampler": "always_on"}


@pytest.mark.parametrize(
    ("argument", "expected"),
    [(None, "1.0"), ("not-a-number", "1.0"), ("2.5", "1.0"), ("-0.5", "0.0"), ("0.25", "0.25")],
)
def test_v7_parentbased_ratio_argument_is_normalized(argument: str | None, expected: str) -> None:
    argument_field = "" if argument is None else f", sampler_arg: '{argument}'"
    result = _convert(
        f"config_version: 7\notel:\n  traces: {{sampler: parentbased_traceidratio{argument_field}}}\n  enabled: false\n"
    )

    assert _document(result)["observability"]["trace_policy"] == {
        "sampler": "parentbased_traceidratio",
        "sampler_arg": expected,
    }


def test_v7_always_off_ignores_legacy_sampler_argument() -> None:
    result = _convert("config_version: 7\notel: {enabled: false, traces: {sampler: always_off, sampler_arg: '1.0'}}\n")

    assert _document(result)["observability"]["trace_policy"] == {"sampler": "always_off"}


def test_missing_or_zero_version_is_supported_only_when_unambiguous() -> None:
    absent = _convert("audit_db: /tmp/audit.db\n")
    zero = _convert("config_version: 0\naudit_db: /tmp/audit.db\n")

    assert _document(absent)["config_version"] == 8
    assert _document(zero)["config_version"] == 8

    with pytest.raises(V8MigrationError) as captured:
        _convert("observability:\n  defaults: {redaction_profile: none}\n")
    assert captured.value.code == "ambiguous_unversioned_source"


@pytest.mark.parametrize("version", [5, 6])
def test_current_loader_normalized_versions_convert_directly(version: int) -> None:
    result = _convert(f"config_version: {version}\notel: {{enabled: false}}\n")

    assert _document(result)["config_version"] == 8
    assert result.summary.source_version == version


@pytest.mark.parametrize("version", [1, 2, 3, 4])
def test_historical_versions_require_in_memory_prenormalization(version: int) -> None:
    canary = "must-not-appear-in-historical-diagnostic"
    with pytest.raises(V8MigrationDependencyError) as captured:
        _convert(f"config_version: {version}\nunknown: {canary}\n")

    assert captured.value.code == "historical_prenormalization_required"
    assert "in memory" in captured.value.action
    assert "intermediate release" in captured.value.action
    assert canary not in str(captured.value)
    assert "none" not in str(captured.value)


def test_absent_or_relative_data_dir_requires_explicit_absolute_effective_value() -> None:
    with pytest.raises(V8MigrationDependencyError) as captured:
        convert_v7_observability_to_v8("config_version: 7\n", {}, compatibility_selection=_TYPED_COMPATIBILITY)
    assert captured.value.code == "effective_data_dir_required"

    effective_dir = Path(Path.cwd().anchor) / "srv" / "defenseclaw"
    result = convert_v7_observability_to_v8(
        "config_version: 7\ndata_dir: ~/.defenseclaw\n",
        {},
        effective_data_dir=str(effective_dir),
        compatibility_selection=_TYPED_COMPATIBILITY,
    )
    jsonl = _destination(_document(result), "gateway-jsonl")
    assert result.effective_data_dir == str(effective_dir)
    assert jsonl["path"] == str(effective_dir / "gateway.jsonl")
    assert not str(jsonl["path"]).startswith("~")
    observability = _document(result)["observability"]
    assert observability["local"] == {
        "path": str(effective_dir / "audit.db"),
        "judge_bodies_path": str(effective_dir / "judge_bodies.db"),
    }

    normalized_dir = effective_dir.parent / "defenseclaw-v8"
    normalized = convert_v7_observability_to_v8(
        "config_version: 7\n",
        {},
        effective_data_dir=str(effective_dir / ".." / normalized_dir.name),
        compatibility_selection=_TYPED_COMPATIBILITY,
    )
    assert normalized.effective_data_dir == str(normalized_dir)


@pytest.mark.parametrize(
    "field",
    [
        "audit_db: false",
        "audit_db: 0",
        "audit_db: ''",
        "judge_bodies_db: false",
        "judge_bodies_db: 0",
        "judge_bodies_db: ''",
    ],
)
def test_present_malformed_legacy_storage_paths_never_fall_back_to_defaults(field: str) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(f"config_version: 7\n{field}\n")
    assert captured.value.code == "unsupported_type"


def test_invalid_v8_is_never_reinterpreted_as_v7() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert("config_version: 8\nobservability: {unknown: true}\n")

    assert captured.value.code == "unsupported_version"
    assert "repair the invalid v8 source" in str(captured.value)


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        ({}, None),
        ({"DEFENSECLAW_PERSIST_JUDGE": "garbage"}, None),
        ({"DEFENSECLAW_PERSIST_JUDGE": "0"}, False),
        ({"DEFENSECLAW_PERSIST_JUDGE": " FALSE "}, False),
        ({"DEFENSECLAW_PERSIST_JUDGE": "off"}, False),
    ],
)
def test_judge_body_environment_precedence(environment: Mapping[str, str], expected: bool | None) -> None:
    result = _convert("config_version: 7\nguardrail: {enabled: true}\n", environment)
    guardrail = _document(result)["guardrail"]
    assert isinstance(guardrail, dict)
    assert guardrail.get("retain_judge_bodies") is expected

    explicit_false = _convert(
        "config_version: 7\nguardrail: {enabled: true, retain_judge_bodies: false}\n",
        {"DEFENSECLAW_PERSIST_JUDGE": "1"},
    )
    assert _document(explicit_false)["guardrail"]["retain_judge_bodies"] is False

    forced_false = _convert(
        "config_version: 7\nguardrail:\n  enabled: true\n  retain_judge_bodies: true # preserve comment\n",
        {"DEFENSECLAW_PERSIST_JUDGE": "no"},
    )
    assert "retain_judge_bodies: false # preserve comment" in forced_false.candidate.decode()


@pytest.mark.parametrize("value", ["1", "true", " YES ", "on", "enabled"])
def test_jsonl_disable_is_materialized_without_ambient_reads(value: str) -> None:
    result = _convert("config_version: 7\n", {"DEFENSECLAW_JSONL_DISABLE": value})
    jsonl = _destination(_document(result), "gateway-jsonl")

    assert jsonl["enabled"] is False
    assert "environment_decision:DEFENSECLAW_JSONL_DISABLE" in result.warnings


def test_unredacted_intent_omits_legacy_profile_and_routes_none() -> None:
    result = _convert(
        "config_version: 7\nprivacy: {disable_redaction: false}\n",
        {"DEFENSECLAW_DISABLE_REDACTION": "true"},
    )
    observability = _document(result)["observability"]
    assert isinstance(observability, dict)

    assert observability["defaults"] == {"collect": {"logs": False, "traces": False, "metrics": False}}
    assert result.summary.redaction_intent == "unredacted"
    assert "environment_decision:DEFENSECLAW_DISABLE_REDACTION" in result.warnings
    console = _destination(_document(result), "gateway-console")
    assert all(route["redaction_profile"] == "none" for route in console["routes"])


@pytest.mark.parametrize("value", ["enable", "enabled", "garbage", "0", "false", "no", "off"])
def test_redaction_environment_uses_exact_v7_truthy_vocabulary(value: str) -> None:
    result = _convert("config_version: 7\n", {"DEFENSECLAW_DISABLE_REDACTION": value})

    observability = _document(result)["observability"]
    assert observability["defaults"]["redaction_profile"] == "legacy-v7"
    assert "environment_decision:DEFENSECLAW_DISABLE_REDACTION" not in result.warnings


def test_inline_and_interpolated_secrets_become_protected_environment_edits() -> None:
    canary_token = "splunk-secret-canary"
    canary_header = "Bearer otlp-secret-canary"
    source = f"""config_version: 7
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token: {canary_token}
  - name: audit-otlp
    kind: otlp_logs
    enabled: true
    otlp_logs:
      endpoint: https://collector.example.test
      protocol: http
      headers:
        Authorization: Bearer ${{SOURCE_TOKEN}}
        project: safe-project
"""

    result = _convert(source, {"SOURCE_TOKEN": "otlp-secret-canary"})
    candidate = result.candidate.decode()
    document = _document(result)

    assert canary_token not in candidate
    assert canary_header not in candidate
    assert "safe-project" not in candidate
    assert canary_token not in repr(result)
    assert canary_header not in repr(result)
    assert result.source_sha256 not in repr(result)
    assert result.candidate_sha256 not in repr(result)
    assert all(canary_token not in line and canary_header not in line for line in result.summary.lines())
    assert len(result.environment_edits) == 3
    assert {edit.value for edit in result.environment_edits} == {canary_token, canary_header, "safe-project"}
    assert all(edit.backup_required and edit.rollback_with_config for edit in result.environment_edits)
    assert {reference.path for edit in result.environment_edits for reference in edit.references} == {
        ("token_env",),
        ("headers", "Authorization", "env"),
        ("headers", "project", "env"),
    }
    splunk = _destination(document, "splunk")
    assert str(splunk["token_env"]).startswith("DEFENSECLAW_MIGRATED_")
    otlp = _destination(document, "audit-otlp")
    assert set(otlp["headers"]["project"]) == {"env"}
    assert set(otlp["headers"]["Authorization"]) == {"env"}
    load_validate_v8(result.candidate)


def test_exact_missing_header_environment_reference_materializes_v7_empty_value() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers: {Authorization: '${REMOTE_TOKEN}'}
      traces: {enabled: true}
"""
    result = _convert(source, {})
    remote = _destination(_document(result), "remote")

    assert remote["headers"]["Authorization"] == ""
    assert result.environment_edits == ()
    assert "unresolved_legacy_header_materialized_empty" in result.warnings
    load_validate_v8(result.candidate)


def test_every_non_reference_header_is_promoted_without_name_heuristics() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers:
        project: project-canary
        logstream: logstream-canary
        X-Custom: custom-canary
        Authorization: '${EXISTING_TOKEN}'
      traces: {enabled: true}
"""

    result = _convert(source, {"EXISTING_TOKEN": "existing-secret"})
    destination = _destination(_document(result), "remote")

    assert {edit.value for edit in result.environment_edits} == {
        "project-canary",
        "logstream-canary",
        "custom-canary",
    }
    assert all(
        value not in result.candidate.decode() for value in ("project-canary", "logstream-canary", "custom-canary")
    )
    assert destination["headers"]["Authorization"] == {"env": "EXISTING_TOKEN"}
    assert all(set(destination["headers"][name]) == {"env"} for name in ("project", "logstream", "X-Custom"))


def test_interpolated_missing_header_reference_matches_v7_empty_expansion() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers: {Authorization: 'Bearer ${MISSING_TOKEN}'}
      traces: {enabled: true}
"""

    result = _convert(source)
    remote = _destination(_document(result), "remote")
    edit = result.environment_edits[0]

    assert remote["headers"]["Authorization"] == {"env": edit.name}
    assert edit.value == "Bearer "
    assert "MISSING_TOKEN" not in result.candidate.decode()


def test_dollar_name_header_expansion_matches_go_os_expand() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers: {Authorization: 'Bearer $TOKEN'}
      traces: {enabled: true}
"""
    result = _convert(source, {"TOKEN": "expanded-secret"})
    remote = _destination(_document(result), "remote")
    edit = result.environment_edits[0]

    assert remote["headers"]["Authorization"] == {"env": edit.name}
    assert edit.value == "Bearer expanded-secret"
    assert "expanded-secret" not in result.candidate.decode()


def test_explicit_otel_environment_transport_is_materialized_with_precedence() -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "http://127.0.0.1:4318/v1/traces",
            "DEFENSECLAW_OTEL_TRACES_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://lower-precedence.example.test",
            "OTEL_RESOURCE_ATTRIBUTES": "service.name=ignored,deployment.environment=ignored",
        },
    )
    document = _document(result)
    remote = _destination(document, "local-observability")

    assert remote["protocol"] == "http/protobuf"
    assert remote["signal_overrides"] == {"traces": {"endpoint": "http://127.0.0.1:4318", "path": "/v1/traces"}}
    assert remote["network_safety"] == {"allow_private_networks": True}
    observability = document["observability"]
    assert isinstance(observability, dict)
    assert "resource" not in observability
    assert "environment_decision:OTEL_RESOURCE_ATTRIBUTES" not in result.warnings


def test_legacy_resource_preset_markers_are_consumed_and_real_attributes_survive() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      defenseclaw.preset: generic-otlp
      defenseclaw.preset_name: Generic OTLP
      service.name: defenseclaw
      deployment.environment: staging
"""
    )
    observability = _document(result)["observability"]
    attributes = observability["resource"]["attributes"]
    assert attributes == {
        "service.name": "defenseclaw",
        "deployment.environment.name": "staging",
    }
    assert result.summary.resource_migrations == (
        "environment_canonicalized",
        "preset_display_name_removed",
        "preset_identity_consumed",
        "service_name_preserved",
    )
    assert "resource_migration:preset_identity_consumed" in result.warnings
    assert "resource_migration:preset_display_name_removed" in result.warnings


def test_v7_resource_null_and_scalar_values_preserve_go_yaml_node_lexemes() -> None:
    null_result = _convert("config_version: 7\notel: {enabled: false, resource: {attributes: null}}\n")
    scalar_result = _convert(
        """config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      answer: 42
      enabled: true
      boolean_alias: yes
      hexadecimal: 0x10
      yes: no
      ratio: 0.25
      nullable: null
"""
    )

    assert "resource" not in _document(null_result)["observability"]
    assert _document(scalar_result)["observability"]["resource"]["attributes"] == {
        "answer": "42",
        "enabled": "true",
        "boolean_alias": "yes",
        "hexadecimal": "0x10",
        "yes": "no",
        "ratio": "0.25",
    }


def test_otel_service_name_environment_has_runtime_precedence_and_is_materialized() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: false
  resource:
    attributes: {service.name: configured-name, deployment.environment: test}
""",
        {
            "OTEL_RESOURCE_ATTRIBUTES": "service.name=resource-env-name,service.namespace=security",
            "OTEL_SERVICE_NAME": "service-env-name",
        },
    )
    attributes = _document(result)["observability"]["resource"]["attributes"]
    assert attributes == {
        "service.name": "service-env-name",
        "deployment.environment.name": "test",
    }
    assert "environment_decision:OTEL_SERVICE_NAME" in result.warnings
    assert "resource_migration:service_name_preserved" in result.warnings


def test_equal_canonical_and_legacy_resource_environments_collapse_exactly() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      deployment.environment.name: production
      deployment.environment: production
      organization.unit: security
"""
    )

    assert _document(result)["observability"]["resource"]["attributes"] == {
        "deployment.environment.name": "production",
        "organization.unit": "security",
    }
    assert "resource_migration:environment_aliases_coalesced" in result.warnings
    assert "environment_aliases_coalesced" in result.summary.resource_migrations


def test_configurable_registered_tenant_and_workspace_resource_keys_survive() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      tenant.id: tenant-a
      workspace.id: workspace-a
"""
    )
    assert _document(result)["observability"]["resource"]["attributes"] == {
        "tenant.id": "tenant-a",
        "workspace.id": "workspace-a",
    }


def test_conflicting_canonical_and_legacy_resource_environments_fail_value_free() -> None:
    canonical_canary = "canonical-environment-canary"
    legacy_canary = "legacy-environment-canary"
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            f"""config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      deployment.environment.name: {canonical_canary}
      deployment.environment: {legacy_canary}
"""
        )

    assert captured.value.code == "conflicting_resource_environment"
    assert canonical_canary not in str(captured.value)
    assert legacy_canary not in str(captured.value)
    assert captured.value.__cause__ is None


def test_preset_markers_never_leak_into_resource_output_or_diagnostics() -> None:
    preset_canary = "preset-identity-canary"
    display_canary = "preset-display-canary"
    result = _convert(
        f"""config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      defenseclaw.preset: {preset_canary}
      defenseclaw.preset_name: {display_canary}
      custom.label: retained
"""
    )

    assert _document(result)["observability"]["resource"]["attributes"] == {"custom.label": "retained"}
    assert preset_canary not in result.candidate.decode()
    assert display_canary not in result.candidate.decode()
    assert all(preset_canary not in warning and display_canary not in warning for warning in result.warnings)
    assert all(preset_canary not in line and display_canary not in line for line in result.summary.lines())


@pytest.mark.parametrize("name", ["service.version", "telemetry.sdk.name", "deployment.mode"])
def test_unsupported_reserved_resource_attributes_fail_instead_of_becoming_custom(name: str) -> None:
    value_canary = "reserved-value-canary"
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            f"""config_version: 7
otel:
  enabled: false
  resource:
    attributes:
      {name}: {value_canary}
"""
        )

    assert captured.value.code == "unsupported_reserved_resource_attribute"
    assert captured.value.path == f"$.otel.resource.attributes.{name}"
    assert value_canary not in str(captured.value)


@pytest.mark.parametrize(
    ("preset", "endpoint", "expected_name", "expected_preset"),
    [
        ("galileo", "https://api.galileo.ai/otel/traces", "galileo", "galileo"),
        ("local-otlp", "127.0.0.1:4317", "local-observability", None),
        ("generic-otlp", "127.0.0.1:4317", "local-observability", None),
    ],
)
def test_flat_preset_identity_and_loopback_local_inference_survive(
    preset: str, endpoint: str, expected_name: str, expected_preset: str | None
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  endpoint: {endpoint}
  protocol: {"http" if preset == "galileo" else "grpc"}
  resource:
    attributes:
      defenseclaw.preset: {preset}
  traces: {{enabled: true}}
"""
    )
    destination = _destination(_document(result), expected_name)
    assert destination.get("preset") == expected_preset
    assert "resource" not in _document(result)["observability"]
    assert "resource_migration:preset_identity_consumed" in result.warnings
    if expected_name == "local-observability":
        assert destination["network_safety"] == {"allow_private_networks": True}


@pytest.mark.parametrize(("value", "enabled"), [("true", True), ("1", True), ("0", False), ("false", False)])
def test_otel_enabled_and_tls_environment_inputs_are_materialized(value: str, enabled: bool) -> None:
    endpoint = "http://collector.example.test" if enabled else "https://collector.example.test"
    result = _convert(
        "config_version: 7\notel: {enabled: false}\n",
        {
            "DEFENSECLAW_OTEL_ENABLED": value,
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": endpoint,
            "OPENCLAW_OTEL_TLS_INSECURE": value,
        },
    )
    destination = _destination(_document(result), "generic-otlp")

    assert destination.get("enabled") is (None if enabled else False)
    assert destination["tls"]["insecure"] is enabled
    assert "environment_decision:DEFENSECLAW_OTEL_ENABLED" in result.warnings
    assert "environment_decision:DEFENSECLAW_OTEL_TLS_INSECURE" in result.warnings


@pytest.mark.parametrize(
    ("value", "enabled"),
    [
        ("1", True),
        ("t", True),
        ("T", True),
        ("TRUE", True),
        ("true", True),
        ("True", True),
        ("0", False),
        ("f", False),
        ("F", False),
        ("FALSE", False),
        ("false", False),
        ("False", False),
    ],
)
def test_otel_enabled_environment_uses_exact_go_boolean_vocabulary(value: str, enabled: bool) -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {
            "DEFENSECLAW_OTEL_ENABLED": value,
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "https://collector.example.test",
        },
    )

    destination = _destination(_document(result), "generic-otlp")
    assert destination.get("enabled") is (None if enabled else False)
    assert "environment_decision:DEFENSECLAW_OTEL_ENABLED" in result.warnings


@pytest.mark.parametrize("value", ["yes", "on", "enable", "enabled", "no", "off", "garbage", " true "])
def test_invalid_nonempty_otel_enabled_environment_fails_value_safely(value: str) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            "config_version: 7\notel: {enabled: true}\n",
            {
                "DEFENSECLAW_OTEL_ENABLED": value,
                "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "https://collector.example.test",
            },
        )

    assert captured.value.code == "invalid_environment_boolean"
    assert captured.value.action == "use the exact Go boolean vocabulary without surrounding whitespace"
    assert captured.value.__cause__ is None


def test_empty_otel_enabled_environment_is_effectively_unset() -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {
            "DEFENSECLAW_OTEL_ENABLED": "",
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "https://collector.example.test",
        },
    )

    assert _destination(_document(result), "generic-otlp").get("enabled") is None
    assert "environment_decision:DEFENSECLAW_OTEL_ENABLED" not in result.warnings


@pytest.mark.parametrize(("value", "expected"), [("yes", True), ("on", True), ("no", False), ("off", False)])
def test_otel_tls_environment_keeps_its_distinct_v7_vocabulary(value: str, expected: bool) -> None:
    endpoint = "http://collector.example.test" if expected else "https://collector.example.test"
    result = _convert(
        "config_version: 7\notel: {enabled: false}\n",
        {
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": endpoint,
            "OPENCLAW_OTEL_TLS_INSECURE": value,
        },
    )

    assert _destination(_document(result), "generic-otlp")["tls"]["insecure"] is expected


@pytest.mark.parametrize("alias", ["DEFENSECLAW_OTEL_TLS_INSECURE", "OPENCLAW_OTEL_TLS_INSECURE"])
def test_both_legacy_tls_insecure_aliases_are_materialized(alias: str) -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "http://collector.example.test",
            alias: "true",
        },
    )
    assert _destination(_document(result), "generic-otlp")["tls"]["insecure"] is True


def test_plaintext_flat_otel_endpoint_materializes_v8_tls_mode() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  protocol: http
  endpoint: http://127.0.0.1:4318
  traces: {enabled: true}
  logs: {enabled: true}
  metrics: {enabled: true}
"""
    )

    destination = _destination(_document(result), "local-observability")
    assert destination["protocol"] == "http/protobuf"
    assert destination["endpoint"] == "http://127.0.0.1:4318"
    assert destination["tls"] == {"insecure": True}
    assert destination["network_safety"] == {"allow_private_networks": True}
    load_validate_v8(result.candidate)


@pytest.mark.parametrize(
    ("source", "placement"),
    [
        (
            """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: http://collector.example.test:4318
      logs: {enabled: true}
""",
            "destination",
        ),
        (
            """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      logs: {enabled: true, endpoint: http://collector.example.test:4318}
""",
            "signal_override",
        ),
    ],
)
def test_plaintext_named_otel_endpoints_materialize_v8_tls_mode(source: str, placement: str) -> None:
    result = _convert(source)
    destination = _destination(_document(result), "backend")

    assert destination["tls"] == {"insecure": True}
    if placement == "destination":
        assert destination["endpoint"] == "http://collector.example.test:4318"
        assert "signal_overrides" not in destination
    else:
        assert "endpoint" not in destination
        assert destination["signal_overrides"] == {"logs": {"endpoint": "http://collector.example.test:4318"}}
    load_validate_v8(result.candidate)


def test_mixed_secure_and_plaintext_signal_endpoints_split_by_tls_mode() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: https://collector.example.test:4318
      traces: {enabled: true}
      logs: {enabled: true, endpoint: http://logs.example.test:4318}
"""
    )
    document = _document(result)
    secure = _destination(document, "backend")
    plaintext = _destination(document, "backend-logs")

    assert secure["endpoint"] == "https://collector.example.test:4318"
    assert "tls" not in secure
    assert {tuple(route["signals"]) for route in secure["routes"]} == {("traces",)}
    assert plaintext["signal_overrides"] == {"logs": {"endpoint": "http://logs.example.test:4318"}}
    assert plaintext["tls"] == {"insecure": True}
    assert {tuple(route["signals"]) for route in plaintext["routes"]} == {("logs",)}
    load_validate_v8(result.candidate)


@pytest.mark.parametrize(
    ("endpoint", "configured_insecure", "expected_endpoint", "expected_insecure"),
    [
        ("https://collector.example.test:4318", True, "http://collector.example.test:4318", True),
        ("http://collector.example.test:4318", False, "http://collector.example.test:4318", True),
        ("collector.example.test:4317", False, "collector.example.test:4317", False),
    ],
)
def test_legacy_endpoint_transport_precedence_is_preserved(
    endpoint: str,
    configured_insecure: bool,
    expected_endpoint: str,
    expected_insecure: bool,
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: {"grpc" if "://" not in endpoint else "http"}
      endpoint: {endpoint}
      tls: {{insecure: {str(configured_insecure).lower()}}}
      traces: {{enabled: true}}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["endpoint"] == expected_endpoint
    assert destination["tls"]["insecure"] is expected_insecure
    load_validate_v8(result.candidate)


def test_plaintext_otel_with_ca_cert_fails_at_exact_v7_path() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            """config_version: 7
otel:
  enabled: true
  protocol: http
  endpoint: http://collector.example.test:4318
  tls: {ca_cert: /tmp/collector-ca.pem}
  traces: {enabled: true}
"""
        )

    assert captured.value.code == "conflicting_v7_otel_tls"
    assert captured.value.path == "$.otel.tls.ca_cert"


def test_grpc_ca_credentials_override_plaintext_url_hint() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
      endpoint: http://collector.example.test:4317
      tls: {ca_cert: /tmp/collector-ca.pem}
      traces: {enabled: true}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["endpoint"] == "https://collector.example.test:4317"
    assert destination["tls"] == {"ca_cert": "/tmp/collector-ca.pem"}
    load_validate_v8(result.candidate)


def test_grpc_explicit_plaintext_omits_ca_ignored_by_v7_runtime() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
      endpoint: https://collector.example.test:4317
      tls: {insecure: true, ca_cert: /tmp/collector-ca.pem}
      traces: {enabled: true}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["endpoint"] == "http://collector.example.test:4317"
    assert destination["tls"] == {"insecure": True}
    assert "legacy_plaintext_otlp_ca_ignored:backend" in result.warnings
    load_validate_v8(result.candidate)


def test_disabled_plaintext_http_destination_drops_inapplicable_ca_without_blocking_upgrade() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: false
      protocol: http
      endpoint: http://collector.example.test:4318
      tls: {ca_cert: /tmp/collector-ca.pem}
      logs: {enabled: true}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["enabled"] is False
    assert destination["tls"] == {"insecure": True}
    assert "legacy_plaintext_otlp_ca_ignored:backend" in result.warnings
    load_validate_v8(result.candidate)


@pytest.mark.parametrize(
    ("signal", "expected_path"),
    [
        ("traces: {enabled: true}", "/base/tenant%3Fscope%23fragment"),
        ("traces: {enabled: true, url_path: v1/custom}", "/v1/custom"),
        (
            "traces: {enabled: true, url_path: '/base%2Ftenant?scope#fragment'}",
            "/base%252Ftenant%3Fscope%23fragment",
        ),
    ],
)
def test_http_endpoint_paths_materialize_v7_effective_path_without_query_or_fragment(
    signal: str,
    expected_path: str,
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: https://collector.example.test:4318/base%2Ftenant%3Fscope%23fragment?ignored=yes#fragment
      {signal}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["endpoint"] == "https://collector.example.test:4318"
    assert destination["signal_overrides"] == {"traces": {"path": expected_path}}
    load_validate_v8(result.candidate)


def test_http_endpoint_literal_spaces_preserve_v7_wire_path() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: 'https://collector.example.test:4318/tenant name?ignored=hello world#note here'
      traces: {enabled: true}
"""
    )

    destination = _destination(_document(result), "backend")
    assert destination["endpoint"] == "https://collector.example.test:4318"
    assert destination["signal_overrides"] == {"traces": {"path": "/tenant%20name"}}
    load_validate_v8(result.candidate)


def test_http_endpoint_path_with_malformed_percent_escape_fails_closed() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: https://collector.example.test:4318/base%ZZtenant
      traces: {enabled: true}
"""
        )

    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == "$.otel.destinations[0].endpoint"


def test_signal_endpoint_path_with_malformed_percent_escape_has_exact_source_path() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: https://collector.example.test:4318
      traces:
        enabled: true
        endpoint: https://traces.example.test:4318/base%ZZtenant
"""
        )

    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == "$.otel.destinations[0].traces.endpoint"


@pytest.mark.parametrize(
    ("signal", "legacy_path", "expected_path"),
    [
        ("traces", ".", None),
        ("metrics", "   ", None),
        ("traces", "  /tenant  ", "/tenant"),
        ("metrics", "tenant  ", "/tenant"),
        ("logs", ".", "/."),
        ("logs", "   ", "/%20%20%20"),
        ("logs", "  /tenant  ", "/%20%20/tenant%20%20"),
    ],
)
def test_explicit_http_paths_preserve_each_v7_exporter_cleaning_contract(
    signal: str,
    legacy_path: str,
    expected_path: str | None,
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: https://collector.example.test:4318
      {signal}:
        enabled: true
        url_path: {legacy_path!r}
"""
    )
    destination = _destination(_document(result), "backend")

    if expected_path is None:
        assert "signal_overrides" not in destination
    else:
        assert destination["signal_overrides"] == {signal: {"path": expected_path}}
    load_validate_v8(result.candidate)


@pytest.mark.parametrize(
    ("signal", "expected_path"),
    [
        ("traces", "/tenant"),
        ("metrics", "/tenant"),
        ("logs", "/tenant%20%20"),
    ],
)
def test_endpoint_http_paths_preserve_each_v7_exporter_cleaning_contract(
    signal: str,
    expected_path: str,
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
      endpoint: https://collector.example.test:4318/tenant%20%20
      {signal}: {{enabled: true}}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["signal_overrides"] == {signal: {"path": expected_path}}
    load_validate_v8(result.candidate)


def test_grpc_endpoint_and_signal_paths_ignored_by_v7_are_removed() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
      endpoint: https://collector.example.test:4317/ignored?query=yes#fragment
      traces: {enabled: true, url_path: /also-ignored}
"""
    )
    destination = _destination(_document(result), "backend")

    assert destination["endpoint"] == "https://collector.example.test:4317"
    assert "signal_overrides" not in destination
    assert "legacy_grpc_path_ignored:backend:traces" in result.warnings
    load_validate_v8(result.candidate)


@pytest.mark.parametrize(
    ("protocol", "expected_endpoint", "expected_tls", "expected_overrides"),
    [
        ("http", "https://collector.example.test:4318", None, {"traces": {"path": "/legacy"}}),
        ("grpc", "http://collector.example.test:4318", {"insecure": True}, None),
    ],
)
def test_nonstandard_scheme_and_ignored_invalid_query_preserve_v7_wire_behavior(
    protocol: str,
    expected_endpoint: str,
    expected_tls: dict[str, bool] | None,
    expected_overrides: dict[str, dict[str, str]] | None,
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: {protocol}
      endpoint: 'ftp://collector.example.test:4318/legacy?ignored=%ZZ#fragment'
      traces: {{enabled: true}}
"""
    )

    destination = _destination(_document(result), "backend")
    assert destination["endpoint"] == expected_endpoint
    assert destination.get("tls") == expected_tls
    assert destination.get("signal_overrides") == expected_overrides
    if protocol == "grpc":
        assert "legacy_grpc_path_ignored:backend:traces" in result.warnings
    load_validate_v8(result.candidate)


def test_relative_legacy_otel_ca_cert_fails_with_exact_remediation() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
      endpoint: collector.example.test:4317
      tls: {ca_cert: relative/collector-ca.pem}
      traces: {enabled: true}
"""
        )

    assert captured.value.code == "relative_v7_otel_ca_cert"
    assert captured.value.path == "$.otel.destinations[0].tls.ca_cert"


def test_grpc_ca_keeps_mixed_endpoint_schemes_in_one_secure_transport_group() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
      endpoint: https://collector.example.test:4317
      tls: {ca_cert: /tmp/collector-ca.pem}
      traces: {enabled: true}
      logs: {enabled: true, endpoint: http://logs.example.test:4317}
"""
    )
    document = _document(result)
    destinations = [item for item in document["observability"]["destinations"] if item["kind"] == "otlp"]
    destination = _destination(document, "backend")

    assert len(destinations) == 1
    assert destination["endpoint"] == "https://collector.example.test:4317"
    assert destination["signal_overrides"] == {"logs": {"endpoint": "https://logs.example.test:4317"}}
    assert destination["tls"] == {"ca_cert": "/tmp/collector-ca.pem"}
    load_validate_v8(result.candidate)


def test_otel_exporter_header_environment_is_not_invented_for_v7() -> None:
    canary = "custom-header-secret-canary"
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {
            "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "https://collector.example.test",
            "OTEL_EXPORTER_OTLP_HEADERS": f"X-Custom={canary},project=sensitive-project",
        },
    )
    destination = _destination(_document(result), "generic-otlp")

    assert canary not in result.candidate.decode()
    assert "sensitive-project" not in result.candidate.decode()
    assert "headers" not in destination
    assert result.environment_edits == ()
    assert "environment_decision:OTEL_EXPORTER_OTLP_HEADERS" not in result.warnings


def test_preexisting_protected_environment_names_are_reused_or_collision_suffixed() -> None:
    source = """config_version: 7
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token: current-secret
"""
    first = _convert(source)
    first_edit = first.environment_edits[0]
    same = _convert(source, {first_edit.name: first_edit.value})
    different = _convert(source, {first_edit.name: "preexisting-different-secret"})
    same_destination = _destination(_document(same), "splunk")
    different_destination = _destination(_document(different), "splunk")

    assert len(same.environment_edits) == 1
    assert same.environment_edits[0].name == first_edit.name
    assert same.environment_edits[0].value == first_edit.value
    assert same_destination["token_env"] == first_edit.name
    assert len(different.environment_edits) == 1
    assert different.environment_edits[0].name != first_edit.name
    assert different_destination["token_env"] == different.environment_edits[0].name
    assert "current-secret" not in repr(different)
    assert "preexisting-different-secret" not in repr(different)


def test_conversion_binds_only_consulted_environment_inputs_without_values() -> None:
    canary = "environment-dependency-secret-canary"
    result = _convert(
        "config_version: 7\n",
        {
            "DEFENSECLAW_JSONL_DISABLE": "true",
            "DEFENSECLAW_DISABLE_REDACTION": canary,
            "UNRELATED_ENVIRONMENT_CANARY": "must-not-be-bound",
        },
    )

    dependencies = {dependency.name: dependency for dependency in result.environment_dependencies}
    assert "DEFENSECLAW_JSONL_DISABLE" in dependencies
    assert "DEFENSECLAW_DISABLE_REDACTION" in dependencies
    assert "UNRELATED_ENVIRONMENT_CANARY" not in dependencies
    assert dependencies["DEFENSECLAW_DISABLE_REDACTION"].value_sha256 == hashlib.sha256(canary.encode()).hexdigest()
    assert canary not in repr(result)
    assert canary not in repr(result.environment_dependencies)


@pytest.mark.parametrize(
    ("kind", "block_name", "environment_field", "inline_field"),
    [
        ("splunk_hec", "splunk_hec", "token_env", "token"),
        ("http_jsonl", "http_jsonl", "bearer_env", "bearer_token"),
    ],
)
def test_legacy_credential_environment_fallback_preserves_effective_inline_value(
    kind: str, block_name: str, environment_field: str, inline_field: str
) -> None:
    endpoint_field = "endpoint" if kind == "splunk_hec" else "url"
    source = f"""config_version: 7
audit_sinks:
  - name: fallback
    kind: {kind}
    enabled: true
    {block_name}:
      {endpoint_field}: https://collector.example.test
      {environment_field}: EXISTING_REFERENCE
      {inline_field}: inline-fallback-canary
"""

    missing = _convert(source)
    available = _convert(source, {"EXISTING_REFERENCE": "environment-value-canary"})
    missing_destination = _destination(_document(missing), "fallback")
    available_destination = _destination(_document(available), "fallback")

    assert missing_destination[environment_field] != "EXISTING_REFERENCE"
    assert {edit.value for edit in missing.environment_edits} == {"inline-fallback-canary"}
    assert {reference.path for edit in missing.environment_edits for reference in edit.references} == {
        (environment_field,)
    }
    assert available_destination[environment_field] == "EXISTING_REFERENCE"
    assert available.environment_edits == ()
    assert "inline-fallback-canary" not in missing.candidate.decode()
    assert "environment-value-canary" not in available.candidate.decode()


@pytest.mark.parametrize(
    ("kind", "block_name", "endpoint_field"),
    [
        ("splunk_hec", "splunk_hec", "endpoint"),
        ("http_jsonl", "http_jsonl", "url"),
    ],
)
def test_legacy_verify_tls_false_is_preserved_without_new_flag(
    kind: str,
    block_name: str,
    endpoint_field: str,
) -> None:
    credential_line = "      token_env: SPLUNK_TOKEN" if kind == "splunk_hec" else ""
    result = _convert(
        f"""config_version: 7
audit_sinks:
  - name: legacy-tls
    kind: {kind}
    enabled: true
    {block_name}:
      {endpoint_field}: https://collector.example.test
{credential_line}
      verify_tls: false
""",
        {"SPLUNK_TOKEN": "test-splunk-token"} if kind == "splunk_hec" else {},
    )

    destination = _destination(_document(result), "legacy-tls")
    assert destination["tls"] == {"insecure_skip_verify": True}
    load_validate_v8(result.candidate)


@pytest.mark.parametrize(
    ("kind", "block_name", "endpoint_field"),
    [
        ("splunk_hec", "splunk_hec", "endpoint"),
        ("http_jsonl", "http_jsonl", "url"),
    ],
)
def test_explicit_skip_verify_false_overrides_legacy_verify_tls_false(
    kind: str,
    block_name: str,
    endpoint_field: str,
) -> None:
    credential_line = "      token_env: SPLUNK_TOKEN" if kind == "splunk_hec" else ""
    result = _convert(
        f"""config_version: 7
audit_sinks:
  - name: explicit-tls
    kind: {kind}
    enabled: true
    {block_name}:
      {endpoint_field}: https://collector.example.test
{credential_line}
      verify_tls: false
      insecure_skip_verify: false
""",
        {"SPLUNK_TOKEN": "test-splunk-token"} if kind == "splunk_hec" else {},
    )

    destination = _destination(_document(result), "explicit-tls")
    assert "tls" not in destination
    load_validate_v8(result.candidate)


def test_named_destination_inherits_global_batch_per_field() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  batch: {max_queue_size: 4096, max_export_batch_size: 512, scheduled_delay_ms: 5000}
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      batch: {scheduled_delay_ms: 250}
      traces: {enabled: true}
"""
    )
    remote = _destination(_document(result), "remote")
    assert remote["batch"] == {
        "max_queue_size": 4096,
        "max_export_batch_size": 512,
        "scheduled_delay_ms": 250,
    }


@pytest.mark.parametrize("inherited_value", [0, -1])
def test_nonpositive_destination_batch_fields_inherit_effective_global_values(inherited_value: int) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  batch: {{max_queue_size: 4096, max_export_batch_size: 256, scheduled_delay_ms: 2500}}
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      batch:
        max_queue_size: {inherited_value}
        max_export_batch_size: {inherited_value}
        scheduled_delay_ms: {inherited_value}
      traces: {{enabled: true}}
"""
    )

    assert _destination(_document(result), "remote")["batch"] == {
        "max_queue_size": 4096,
        "max_export_batch_size": 256,
        "scheduled_delay_ms": 2500,
    }


@pytest.mark.parametrize(
    ("alias", "signal"),
    [
        ("DEFENSECLAW_OTEL_ENDPOINT", None),
        ("OPENCLAW_OTEL_ENDPOINT", None),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", None),
        ("DEFENSECLAW_OTEL_LOGS_ENDPOINT", "logs"),
        ("OPENCLAW_OTEL_LOGS_ENDPOINT", "logs"),
        ("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "logs"),
        ("DEFENSECLAW_OTEL_TRACES_ENDPOINT", "traces"),
        ("OPENCLAW_OTEL_TRACES_ENDPOINT", "traces"),
        ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "traces"),
        ("DEFENSECLAW_OTEL_METRICS_ENDPOINT", "metrics"),
        ("OPENCLAW_OTEL_METRICS_ENDPOINT", "metrics"),
        ("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "metrics"),
    ],
)
def test_every_legacy_otel_endpoint_alias_has_a_materialized_disposition(alias: str, signal: str | None) -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {alias: "https://collector.example.test/otlp"},
    )
    destination = _destination(_document(result), "generic-otlp")
    if signal is None:
        assert destination["endpoint"] == "https://collector.example.test"
    else:
        assert destination["signal_overrides"][signal]["endpoint"] == "https://collector.example.test"
    assert f"legacy_grpc_path_ignored:generic-otlp:{signal or 'logs'}" in result.warnings
    assert any(warning.startswith("environment_decision:OTEL") for warning in result.warnings)


@pytest.mark.parametrize(
    ("alias", "signal"),
    [
        ("DEFENSECLAW_OTEL_PROTOCOL", None),
        ("OPENCLAW_OTEL_PROTOCOL", None),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", None),
        ("DEFENSECLAW_OTEL_LOGS_PROTOCOL", "logs"),
        ("OPENCLAW_OTEL_LOGS_PROTOCOL", "logs"),
        ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "logs"),
        ("DEFENSECLAW_OTEL_TRACES_PROTOCOL", "traces"),
        ("OPENCLAW_OTEL_TRACES_PROTOCOL", "traces"),
        ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "traces"),
        ("DEFENSECLAW_OTEL_METRICS_PROTOCOL", "metrics"),
        ("OPENCLAW_OTEL_METRICS_PROTOCOL", "metrics"),
        ("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "metrics"),
    ],
)
def test_every_legacy_otel_protocol_alias_has_a_materialized_disposition(alias: str, signal: str | None) -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true, endpoint: 'https://collector.example.test'}\n",
        {alias: "http/protobuf"},
    )
    observability = _document(result)["observability"]
    assert isinstance(observability, dict)
    otlp = [destination for destination in observability["destinations"] if destination["kind"] == "otlp"]
    assert any(destination["protocol"] == "http/protobuf" for destination in otlp)
    assert any(warning.startswith("environment_decision:OTEL") for warning in result.warnings)


def test_otel_alias_precedence_prefers_yaml_then_defenseclaw_then_openclaw_then_standard() -> None:
    environment = {
        "DEFENSECLAW_OTEL_ENDPOINT": "https://defenseclaw.example.test",
        "OPENCLAW_OTEL_ENDPOINT": "https://openclaw.example.test",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://standard.example.test",
    }
    from_yaml = _convert(
        "config_version: 7\notel: {enabled: true, endpoint: 'https://yaml.example.test'}\n",
        environment,
    )
    assert _destination(_document(from_yaml), "generic-otlp")["endpoint"] == "https://yaml.example.test"

    from_aliases = _convert("config_version: 7\notel: {enabled: true}\n", environment)
    assert _destination(_document(from_aliases), "generic-otlp")["endpoint"] == ("https://defenseclaw.example.test")


def test_otel_alias_dependency_tracking_stops_after_first_effective_value() -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {"DEFENSECLAW_OTEL_ENDPOINT": "https://collector.example.test"},
    )
    dependencies = {dependency.name for dependency in result.environment_dependencies}

    assert "DEFENSECLAW_OTEL_ENDPOINT" in dependencies
    assert "OPENCLAW_OTEL_ENDPOINT" not in dependencies
    assert "OTEL_EXPORTER_OTLP_ENDPOINT" not in dependencies


def test_per_signal_protocol_conflict_splits_stable_destinations() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {enabled: true, protocol: grpc}
      logs: {enabled: true, protocol: http/protobuf, endpoint: https://logs.example.test/v1/logs}
      metrics: {enabled: false}
"""
    first = _convert(source)
    second = _convert(source)
    observability = _document(first)["observability"]
    assert isinstance(observability, dict)
    names = [item["name"] for item in observability["destinations"]]

    assert "backend" in names
    assert "backend-logs" in names
    assert first.candidate == second.candidate


def test_split_local_protocols_keep_dashboard_trace_profile_on_reserved_name() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: local-observability
      preset: local-otlp
      enabled: true
      endpoint: http://127.0.0.1:4318
      protocol: http
      traces: {enabled: true, protocol: grpc, endpoint: '127.0.0.1:4317'}
      logs: {enabled: true}
      metrics: {enabled: true}
"""
    )
    document = _document(result)
    trace_destination = _destination(document, "local-observability")
    log_metric_destination = _destination(document, "local-observability-logs-metrics")

    assert result.summary.local_observability == "full"
    assert trace_destination["protocol"] == "grpc"
    assert trace_destination["signal_overrides"] == {"traces": {"endpoint": "127.0.0.1:4317"}}
    assert trace_destination["routes"] == [
        {
            "name": "legacy-local-observability-traces-1",
            "signals": ["traces"],
            "selector": {"event_names": _ALL_SPAN_EVENT_NAMES},
            "redaction_profile": "legacy-v7",
        }
    ]
    assert log_metric_destination["protocol"] == "http/protobuf"
    assert log_metric_destination["routes"] == [
        {
            "name": "legacy-individual-findings-disabled-1",
            "signals": ["logs"],
            "selector": {"event_names": ["finding.observed"]},
            "action": "drop",
        },
        {
            "name": "legacy-local-observability-logs-1",
            "signals": ["logs"],
            "selector": {"buckets": _ALL_BUCKETS},
            "redaction_profile": "legacy-v7",
        },
        {
            "name": "legacy-local-observability-metrics-1",
            "signals": ["metrics"],
            "selector": {"buckets": _ALL_BUCKETS},
        },
    ]
    assert all(
        "*" not in values
        for destination in (trace_destination, log_metric_destination)
        for route in destination["routes"]
        for values in route["selector"].values()
    )
    load_validate_v8(result.candidate)


def test_flat_signal_protocol_becomes_v7_destination_fallback() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  endpoint: https://collector.example.test
  traces: {protocol: http/protobuf}
"""
    )

    otlp = [
        destination
        for destination in _document(result)["observability"]["destinations"]
        if destination["kind"] == "otlp"
    ]
    assert len(otlp) == 1
    assert otlp[0]["name"] == "generic-otlp"
    assert otlp[0]["protocol"] == "http/protobuf"
    assert {tuple(route["signals"]) for route in otlp[0]["routes"]} == {
        ("logs",),
        ("traces",),
        ("metrics",),
    }


def test_flat_signal_protocol_from_environment_becomes_v7_destination_fallback() -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true, endpoint: 'https://collector.example.test'}\n",
        {"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf"},
    )

    destination = _destination(_document(result), "generic-otlp")
    assert destination["protocol"] == "http/protobuf"
    assert "environment_decision:OTEL_TRACES_PROTOCOL" in result.warnings


def test_flat_protocol_fallback_uses_v7_trace_log_metric_precedence() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  endpoint: https://collector.example.test
  logs: {enabled: true, protocol: http/protobuf}
  traces: {enabled: true, protocol: grpc}
  metrics: {enabled: true}
"""
    )
    document = _document(result)
    inherited = _destination(document, "generic-otlp")
    logs = _destination(document, "generic-otlp-logs")

    assert inherited["protocol"] == "grpc"
    assert {tuple(route["signals"]) for route in inherited["routes"]} == {("traces",), ("metrics",)}
    assert logs["protocol"] == "http/protobuf"
    assert {tuple(route["signals"]) for route in logs["routes"]} == {("logs",)}


@pytest.mark.parametrize("reserved", ["gateway-jsonl", "gateway-console", "local-sqlite"])
def test_migrated_destinations_cannot_steal_reserved_v8_names(reserved: str) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: {reserved}
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {{enabled: true}}
"""
    )
    names = [destination["name"] for destination in _document(result)["observability"]["destinations"]]

    assert len(names) == len(set(names))
    assert f"{reserved}-2" in names
    load_validate_v8(result.candidate)


def test_flat_destination_avoids_explicit_generic_name_like_v7() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  endpoint: https://flat.example.test
  traces: {enabled: true}
  destinations:
    - name: generic-otlp
      enabled: true
      endpoint: https://named.example.test
      protocol: grpc
      traces: {enabled: true}
"""
    )
    destinations = _document(result)["observability"]["destinations"]
    endpoints = {destination.get("endpoint"): destination["name"] for destination in destinations}

    assert endpoints["https://named.example.test"] == "generic-otlp"
    assert endpoints["https://flat.example.test"] == "generic-otlp-2"


def test_exact_trimmed_duplicate_v7_destination_names_are_rejected() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: dup
      enabled: true
      endpoint: https://one.example.test
      protocol: grpc
      traces: {enabled: true}
    - name: ' dup '
      enabled: true
      endpoint: https://two.example.test
      protocol: grpc
      traces: {enabled: true}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)

    assert captured.value.code == "duplicate_destination_name"


def test_flat_environment_precedence_trims_and_skips_whitespace_values() -> None:
    result = _convert(
        "config_version: 7\notel: {enabled: true}\n",
        {
            "DEFENSECLAW_OTEL_ENDPOINT": "   ",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "  https://collector.example.test  ",
        },
    )

    assert _destination(_document(result), "generic-otlp")["endpoint"] == "https://collector.example.test"


def test_legacy_destination_names_are_deterministically_normalized_and_collision_safe() -> None:
    long_name = "Very Long Destination " + "X" * 100
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: 'TEAM OTLP'
      enabled: true
      endpoint: https://one.example.test
      protocol: grpc
      traces: {{enabled: true}}
    - name: 'team-otlp'
      enabled: true
      endpoint: https://two.example.test
      protocol: grpc
      traces: {{enabled: true}}
    - name: 'Télémétrie 東京'
      enabled: true
      endpoint: https://three.example.test
      protocol: grpc
      traces: {{enabled: true}}
    - name: '{long_name}'
      enabled: true
      endpoint: https://four.example.test
      protocol: grpc
      traces: {{enabled: true}}
"""
    first = _convert(source)
    second = _convert(source)
    observability = _document(first)["observability"]
    names = [destination["name"] for destination in observability["destinations"] if destination["kind"] == "otlp"]

    assert names[0] == "team-otlp"
    assert names[1] == "team-otlp-2"
    assert names[2] == "t-l-m-trie"
    assert len(names[3]) <= 64
    assert all(_name == _name.lower() and " " not in _name for _name in names)
    assert first.candidate == second.candidate
    assert any(warning.startswith("destination_name_normalized:") for warning in first.warnings)


def test_legacy_http_json_protocol_maps_to_protobuf_with_warning() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: legacy-http
      enabled: true
      endpoint: https://collector.example.test
      protocol: http/json
      traces: {enabled: true}
"""
    )
    destination = _destination(_document(result), "legacy-http")
    assert destination["protocol"] == "http/protobuf"
    assert "protocol_compatibility:http/json_to_http/protobuf" in result.warnings


@pytest.mark.parametrize(
    "source",
    [
        'config_version: 7\nprivacy: {disable_redaction: "false"}\n',
        'config_version: 7\notel: {enabled: "false"}\n',
        'config_version: 7\notel: {enabled: true, tls: {insecure: "true"}}\n',
        'config_version: 7\naudit_sinks: [{name: x, kind: http_jsonl, enabled: "false", http_jsonl: {url: https://x.example}}]\n',
        'config_version: 7\naudit_sinks: [{name: x, kind: http_jsonl, enabled: true, http_jsonl: {url: https://x.example, insecure_skip_verify: "false"}}]\n',
    ],
)
def test_quoted_owned_booleans_are_rejected_not_truthiness_coerced(source: str) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "unsupported_type"


@pytest.mark.parametrize(
    "source",
    [
        "config_version: 7\notel: {enabled: true}\n",
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: invalid
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {enabled: false}
      logs: {enabled: false}
      metrics: {enabled: false}
""",
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: missing-endpoint
      enabled: true
      protocol: grpc
      traces: {enabled: true}
""",
    ],
)
def test_invalid_enabled_v7_otel_shapes_are_rejected_not_broadened_or_dropped(source: str) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_v7_otel"


def test_disabled_destination_without_signals_is_preserved_as_explicit_drop_routes() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: false
  destinations:
    - name: dormant
      enabled: false
      endpoint: https://collector.example.test
      protocol: grpc
"""
    )
    dormant = _destination(_document(result), "dormant")

    assert dormant["enabled"] is False
    assert dormant["routes"] == [
        {
            "name": "legacy-disabled-no-signals",
            "signals": ["logs", "traces", "metrics"],
            "selector": {},
            "action": "drop",
        }
    ]


@pytest.mark.parametrize(
    "source",
    (_FRESH_080_DEFAULT_OTEL_CONFIG, _FRESH_080_NAMED_OTEL_CONFIG),
    ids=("flat-quickstart", "named-release-installer"),
)
def test_fresh_080_disabled_otel_placeholder_migrates_without_inventing_endpoint(source: str) -> None:
    result = _convert(source)
    assert all(
        destination.get("name") != "generic-otlp"
        for destination in _document(result)["observability"].get("destinations", [])
    )
    assert "legacy_unconfigured_generic_otlp_placeholder_omitted" in result.warnings
    load_validate_v8(result.candidate)


def test_custom_disabled_endpointless_otel_destination_still_fails_closed() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            """config_version: 7
otel:
  enabled: false
  destinations:
    - name: operator-destination
      preset: generic-otlp
      enabled: false
      protocol: grpc
      traces: {enabled: true}
      logs: {enabled: true}
      metrics: {enabled: true}
"""
        )

    assert captured.value.code == "candidate_validation_failed"


@pytest.mark.parametrize(
    ("original", "replacement"),
    (
        ("  headers: {}", "  headers: {X-Operator: custom}"),
        ("    sampler: always_on", "    sampler: parentbased_traceidratio"),
        ("    export_interval_s: 60", "    export_interval_s: 30"),
    ),
)
def test_fresh_placeholder_with_operator_changes_is_not_silently_omitted(
    original: str,
    replacement: str,
) -> None:
    source = _FRESH_080_DEFAULT_OTEL_CONFIG.replace(original, replacement)
    with pytest.raises(V8MigrationError):
        _convert(source)


def test_fresh_placeholder_with_environment_endpoint_preserves_effective_transport() -> None:
    result = _convert(
        _FRESH_080_DEFAULT_OTEL_CONFIG,
        {"OTEL_EXPORTER_OTLP_ENDPOINT": "collector.example.test:4317"},
    )
    destination = _destination(_document(result), "generic-otlp")

    assert destination["endpoint"] == "collector.example.test:4317"
    assert "legacy_unconfigured_generic_otlp_placeholder_omitted" not in result.warnings
    load_validate_v8(result.candidate)


def test_named_release_placeholder_with_operator_field_is_not_silently_omitted() -> None:
    source = _FRESH_080_NAMED_OTEL_CONFIG.replace(
        "      tls: {ca_cert: \"\", insecure: false}",
        "      headers: {}\n      tls: {ca_cert: \"\", insecure: false}",
    )
    with pytest.raises(V8MigrationError):
        _convert(source)


@pytest.mark.parametrize(
    ("source", "original", "replacement"),
    (
        (_FRESH_080_DEFAULT_OTEL_CONFIG, "  enabled: false", "  enabled: 0"),
        (
            _FRESH_080_DEFAULT_OTEL_CONFIG,
            '    sampler_arg: "1.0"',
            "    sampler_arg: 1.0",
        ),
        (
            _FRESH_080_DEFAULT_OTEL_CONFIG,
            "    export_interval_s: 60",
            "    export_interval_s: 60.0",
        ),
        (_FRESH_080_NAMED_OTEL_CONFIG, "      enabled: false", "      enabled: 0"),
        (
            _FRESH_080_NAMED_OTEL_CONFIG,
            "export_interval_s: 60}",
            "export_interval_s: 60.0}",
        ),
    ),
    ids=(
        "flat-bool-to-int",
        "flat-string-to-float",
        "flat-int-to-float",
        "named-bool-to-int",
        "named-int-to-float",
    ),
)
def test_historical_placeholder_scalar_types_must_match_exactly(
    source: str,
    original: str,
    replacement: str,
) -> None:
    altered = source.replace(original, replacement, 1)
    assert altered != source
    with pytest.raises(V8MigrationError):
        _convert(altered)


def test_named_release_placeholder_with_master_enabled_still_fails_closed() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            _FRESH_080_NAMED_OTEL_CONFIG,
            {"DEFENSECLAW_OTEL_ENABLED": "true"},
        )

    assert captured.value.code == "invalid_v7_otel"


def test_disabled_destination_without_any_transport_fails_instead_of_disappearing() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            """config_version: 7
otel:
  enabled: false
  destinations:
    - {name: dormant, enabled: false}
"""
        )

    assert captured.value.code == "dormant_otel_not_representable"


def test_metric_only_send_and_protocol_split_metric_group_have_no_redaction_profile() -> None:
    metric_only = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: metrics
      enabled: true
      endpoint: https://metrics.example.test
      protocol: grpc
      metrics: {enabled: true}
"""
    )
    metric_destination = _destination(_document(metric_only), "metrics")
    assert metric_destination["routes"] == [
        {
            "name": "legacy-generic-otlp-metrics-1",
            "signals": ["metrics"],
            "selector": {"buckets": _ALL_BUCKETS},
        }
    ]
    assert all("redaction_profile" not in route for route in metric_destination["routes"])
    load_validate_v8(metric_only.candidate)

    split = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: split
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {enabled: true, protocol: grpc}
      metrics: {enabled: true, protocol: http/protobuf, endpoint: https://metrics.example.test/v1/metrics}
"""
    )
    metric_group = _destination(_document(split), "split-metrics")
    assert {tuple(route["signals"]) for route in metric_group["routes"]} == {("metrics",)}
    assert all("redaction_profile" not in route for route in metric_group["routes"])
    load_validate_v8(split.candidate)


def test_individual_finding_toggle_uses_generated_event_family_not_whole_bucket() -> None:
    template = """config_version: 7
otel:
  enabled: true
  logs: {emit_individual_findings: %s}
  destinations:
    - name: logs
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      logs: {enabled: true}
"""
    disabled = _destination(_document(_convert(template % "false")), "logs")
    assert disabled["routes"][0] == {
        "name": "legacy-individual-findings-disabled-1",
        "signals": ["logs"],
        "selector": {"event_names": ["finding.observed"]},
        "action": "drop",
    }
    send_route = next(route for route in disabled["routes"] if route["name"] == "legacy-generic-otlp-logs-1")
    assert "security.finding" in send_route["selector"]["buckets"]

    enabled = _destination(_document(_convert(template % "true")), "logs")
    assert all(route["action"] != "drop" for route in enabled["routes"] if "action" in route)
    assert enabled["routes"] == [
        {
            "name": "legacy-generic-otlp-logs-1",
            "signals": ["logs"],
            "selector": {"buckets": _ALL_BUCKETS},
            "redaction_profile": "legacy-v7",
        }
    ]


def test_conflicting_metric_policy_fails_before_candidate() -> None:
    source = """config_version: 7
otel:
  enabled: true
  metrics: {export_interval_s: 60, temporality: delta}
  destinations:
    - name: one
      enabled: true
      endpoint: https://one.example.test
      protocol: grpc
      metrics: {enabled: true, export_interval_s: 30, temporality: delta}
    - name: two
      enabled: true
      endpoint: https://two.example.test
      protocol: grpc
      metrics: {enabled: true, export_interval_s: 60, temporality: delta}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "conflicting_metric_policy"
    assert "one" in captured.value.path
    assert captured.value.action == "align policies or keep only one metric-export destination"


def test_flat_and_named_metric_policy_conflict_fails_before_candidate() -> None:
    source = """config_version: 7
otel:
  enabled: true
  endpoint: https://flat.example.test
  metrics: {export_interval_s: 60, temporality: delta}
  destinations:
    - name: named
      enabled: true
      endpoint: https://named.example.test
      protocol: grpc
      metrics: {enabled: true, export_interval_s: 30, temporality: delta}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)

    assert captured.value.code == "conflicting_metric_policy"
    assert "$.otel.metrics.export_interval_s" in captured.value.path
    assert "named" in captured.value.path


def test_single_metric_destination_override_becomes_process_policy() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  metrics: {export_interval_s: 60, temporality: delta}
  destinations:
    - name: one
      enabled: true
      endpoint: https://one.example.test
      protocol: grpc
      metrics: {enabled: true, export_interval_s: 30, temporality: cumulative}
"""
    )

    assert _document(result)["observability"]["metric_policy"] == {
        "export_interval_seconds": 30,
        "temporality": "cumulative",
    }


def test_disabled_metric_destination_does_not_create_effective_policy_conflict() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  metrics: {export_interval_s: 60, temporality: delta}
  destinations:
    - name: active
      enabled: true
      endpoint: https://active.example.test
      protocol: grpc
      metrics: {enabled: true, export_interval_s: 60, temporality: delta}
    - name: dormant
      enabled: false
      endpoint: https://dormant.example.test
      protocol: grpc
      metrics: {enabled: true, export_interval_s: 5, temporality: cumulative}
"""
    )

    assert _document(result)["observability"]["metric_policy"] == {
        "export_interval_seconds": 60,
        "temporality": "delta",
    }


def test_galileo_inherited_delay_changes_but_explicit_delay_is_preserved() -> None:
    base = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      protocol: http
      endpoint: https://api.galileo.ai/otel/traces
      headers:
        Galileo-API-Key: '${GALILEO_API_KEY}'
      __BATCH__
      traces: {enabled: true}
__SPAN_FILTER__
"""
    base = base.replace("__SPAN_FILTER__", _galileo_span_filter_yaml())
    inherited = _convert(base.replace("__BATCH__", ""))
    explicit = _convert(base.replace("__BATCH__", "batch: {scheduled_delay_ms: 5000}"))

    inherited_galileo = _destination(_document(inherited), "galileo")
    explicit_galileo = _destination(_document(explicit), "galileo")
    assert inherited_galileo["batch"]["scheduled_delay_ms"] == 1000
    assert "galileo_preset_delay_changed:5000_to_1000" in inherited.warnings
    assert explicit_galileo["batch"]["scheduled_delay_ms"] == 5000
    assert "galileo_preset_delay_changed:5000_to_1000" not in explicit.warnings


def test_required_attribute_span_filters_use_exact_generated_compatibility_selection() -> None:
    operation_filter = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {enabled: true}
      span_filter:
        operations:
          - name: chat
            require_attributes: [tenant.export_allowed]
"""
    top_level_filter = operation_filter.replace(
        "operations:\n          - name: chat\n            require_attributes: [tenant.export_allowed]",
        "require_operation: chat\n        require_attributes: [tenant.export_allowed]",
    )

    for source in (operation_filter, top_level_filter):
        result = _convert(source)
        destination = _destination(_document(result), "remote")
        assert destination["routes"] == [
            {
                "name": "legacy-generic-otlp-traces-1",
                "signals": ["traces"],
                "selector": {"event_names": ["span.model.chat"]},
                "redaction_profile": "legacy-v7",
            }
        ]
        assert "span_filter_translated_from_generated_compatibility_selection" in result.warnings

    exact = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      endpoint: https://api.galileo.ai/otel/traces
      protocol: http
      traces: {enabled: true}
__SPAN_FILTER__
""".replace("__SPAN_FILTER__", _galileo_span_filter_yaml())
    exact_destination = _destination(_document(_convert(exact)), "galileo")
    assert exact_destination["routes"] == [
        {
            "name": "legacy-generic-otlp-traces-1",
            "signals": ["traces"],
            "selector": {
                "event_names": [
                    "span.agent.invoke",
                    "span.model.chat",
                    "span.tool.execute",
                ]
            },
            "redaction_profile": "legacy-v7",
        }
    ]


def test_generic_otel_emit_disable_and_redaction_goldens_are_exact() -> None:
    template = """config_version: 7
privacy: {disable_redaction: __DISABLED__}
ai_discovery: {enabled: true, emit_otel: false}
otel:
  enabled: true
  logs: {emit_individual_findings: false}
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      logs: {enabled: true}
      traces: {enabled: true}
      metrics: {enabled: true}
"""
    expected_routes = [
        {
            "name": "legacy-ai-discovery-disabled",
            "signals": ["logs", "traces", "metrics"],
            "selector": {"buckets": ["ai.discovery"]},
            "action": "drop",
        },
        {
            "name": "legacy-individual-findings-disabled-1",
            "signals": ["logs"],
            "selector": {"event_names": ["finding.observed"]},
            "action": "drop",
        },
        {
            "name": "legacy-generic-otlp-logs-1",
            "signals": ["logs"],
            "selector": {"buckets": _ALL_BUCKETS},
            "redaction_profile": "legacy-v7",
        },
        {
            "name": "legacy-generic-otlp-traces-1",
            "signals": ["traces"],
            "selector": {"event_names": _ALL_SPAN_EVENT_NAMES},
            "redaction_profile": "legacy-v7",
        },
        {
            "name": "legacy-generic-otlp-metrics-1",
            "signals": ["metrics"],
            "selector": {"buckets": _ALL_BUCKETS},
        },
    ]

    redacted = _convert(template.replace("__DISABLED__", "false"))
    redacted_document = _document(redacted)
    assert _destination(redacted_document, "remote")["routes"] == expected_routes
    assert redacted_document["observability"]["defaults"]["redaction_profile"] == "legacy-v7"
    assert redacted_document["observability"]["buckets"]["ai.discovery"] == {"collect": {"logs": True}}

    unredacted = _convert(template.replace("__DISABLED__", "true"))
    unredacted_document = _document(unredacted)
    unredacted_routes = _destination(unredacted_document, "remote")["routes"]
    assert unredacted_document["observability"]["defaults"] == {
        "collect": {"logs": False, "traces": False, "metrics": False}
    }
    assert unredacted_routes == [
        ({**route, "redaction_profile": "none"} if route.get("redaction_profile") == "legacy-v7" else route)
        for route in expected_routes
    ]
    for route in (*expected_routes, *unredacted_routes):
        if route.get("action", "send") == "send":
            assert route["selector"]
            assert all("*" not in values for values in route["selector"].values())
    load_validate_v8(redacted.candidate)
    load_validate_v8(unredacted.candidate)


def test_span_filter_predicates_use_v7_whitespace_normalization() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {enabled: true}
      span_filter:
        require_operation: ' chat '
        require_attributes: [' tenant.export_allowed ']
"""
    )

    assert _destination(_document(result), "remote")["routes"][0]["selector"] == {"event_names": ["span.model.chat"]}


@pytest.mark.parametrize(
    "span_filter",
    [
        "{require_operation: chat, operations: [{name: chat}]}",
        "{operations: [{name: chat}, {name: ' chat '}]}",
        "{require_operation: chat, require_attributes: [tenant.export_allowed, ' tenant.export_allowed ']}",
    ],
)
def test_invalid_v7_span_filter_ambiguity_is_not_silently_repaired(span_filter: str) -> None:
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {{enabled: true}}
      span_filter: {span_filter}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)

    assert captured.value.code == "unsupported_span_filter"


@pytest.mark.parametrize(
    "span_filter",
    ["{}", "{operations: []}", "{require_operation: '   ', require_attributes: []}"],
)
def test_disabled_legacy_span_filter_uses_normal_exporter_selection(span_filter: str) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {{enabled: true}}
      span_filter: {span_filter}
"""
    )
    destination = _destination(_document(result), "remote")

    assert destination["routes"][0]["selector"] == {"event_names": _ALL_SPAN_EVENT_NAMES}
    assert "span_filter_translated_from_generated_compatibility_selection" not in result.warnings


def test_galileo_operation_names_with_stricter_attributes_are_not_elided() -> None:
    value = {
        "span_filter": {
            "operations": [
                {"name": name, "require_attributes": list(attributes)}
                for name, attributes in GALILEO.span_filter_operations
            ]
        }
    }
    value["span_filter"]["operations"][0]["require_attributes"].append("tenant.export_allowed")
    filter_yaml = "\n".join("      " + line for line in yaml.safe_dump(value, sort_keys=False).rstrip().splitlines())
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      endpoint: https://api.galileo.ai/otel/traces
      protocol: http
      traces: {enabled: true}
__SPAN_FILTER__
""".replace("__SPAN_FILTER__", filter_yaml)

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "span_filter_mapping_incomplete"


def test_galileo_non_trace_signals_split_to_generic_sibling_without_loss() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  logs: {emit_individual_findings: true}
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      endpoint: https://api.galileo.ai/otel/traces
      protocol: http
      traces: {enabled: true}
      logs: {enabled: true}
      metrics: {enabled: true}
"""
    )
    document = _document(result)
    traces = _destination(document, "galileo")
    other = _destination(document, "galileo-logs-metrics")

    assert traces["preset"] == "galileo"
    assert {tuple(route["signals"]) for route in traces["routes"]} == {("traces",)}
    assert traces["batch"]["scheduled_delay_ms"] == 1000
    assert "preset" not in other
    assert {tuple(route["signals"]) for route in other["routes"]} == {("logs",), ("metrics",)}
    assert all("redaction_profile" not in route for route in other["routes"] if route["signals"] == ["metrics"])
    assert other["batch"]["scheduled_delay_ms"] == 5000


@pytest.mark.parametrize(
    ("destination_protocol", "trace_protocol", "expected_path"),
    [
        ("grpc", "", "$.otel.destinations[0].protocol"),
        ("http", "protocol: grpc", "$.otel.destinations[0].traces.protocol"),
    ],
)
def test_galileo_trace_protocol_fails_at_the_exact_legacy_source_field(
    destination_protocol: str,
    trace_protocol: str,
    expected_path: str,
) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(
            f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      endpoint: https://api.galileo.ai/otel/traces
      protocol: {destination_protocol}
      traces: {{enabled: true, {trace_protocol}}}
"""
        )

    assert captured.value.code == "unsupported_galileo_protocol"
    assert captured.value.path == expected_path
    assert "http or http/protobuf" in captured.value.action


def test_galileo_without_traces_remains_generic_instead_of_inventing_trace_export() -> None:
    result = _convert(
        """config_version: 7
otel:
  enabled: true
  logs: {emit_individual_findings: true}
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      endpoint: https://collector.example.test/v1/logs
      protocol: http
      logs: {enabled: true}
"""
    )
    destination = _destination(_document(result), "galileo")

    assert "preset" not in destination
    assert {tuple(route["signals"]) for route in destination["routes"]} == {("logs",)}


def test_custom_span_filter_consumes_generated_compatibility_selection() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: custom
      enabled: true
      protocol: grpc
      endpoint: https://collector.example.test
      traces: {enabled: true}
      span_filter: {require_operation: retrieve}
"""

    packaged = _convert(source, compatibility_selection=None)

    result = _convert(source)
    assert packaged.candidate == result.candidate
    custom = _destination(_document(result), "custom")
    assert custom["routes"] == [
        {
            "name": "legacy-generic-otlp-traces-1",
            "signals": ["traces"],
            "selector": {"event_names": ["span.retrieval.search"]},
            "redaction_profile": "legacy-v7",
        }
    ]


def test_connector_audit_overrides_become_ordered_routes_and_webhooks_survive() -> None:
    aliased = """config_version: 7
audit_sinks:
  - &not_allowed
    name: global-http
    kind: http_jsonl
    enabled: true
    http_jsonl: {url: https://events.example.test}
webhooks: [*not_allowed]
"""
    with pytest.raises(V8MigrationError) as captured:
        _convert(aliased)
    assert captured.value.code == "invalid_yaml"

    source = """config_version: 7
audit_sinks:
  - name: global-http
    kind: http_jsonl
    enabled: true
    http_jsonl: {url: https://events.example.test}
observability:
  connectors:
    codex:
      audit_sinks: []
      webhooks:
        - name: incident
          url: https://notifications.example.test
          type: generic
          events: [scan]
"""
    result = _convert(source)
    document = _document(result)
    destination = _destination(document, "global-http")

    assert destination["routes"][0] == {
        "name": "legacy-connector-suppress",
        "signals": ["logs"],
        "selector": {"connectors": ["codex"]},
        "action": "drop",
    }
    observability = document["observability"]
    assert isinstance(observability, dict)
    assert observability["connectors"]["codex"]["webhooks"][0]["name"] == "incident"


def test_connector_audit_override_preserves_replacement_and_duplicate_multiplicity() -> None:
    result = _convert(
        """config_version: 7
audit_sinks:
  - name: dup
    kind: http_jsonl
    enabled: true
    http_jsonl: {url: https://one.example.test}
  - name: dup
    kind: http_jsonl
    enabled: true
    http_jsonl: {url: https://two.example.test}
observability:
  connectors:
    codex:
      audit_sinks:
        - name: dup
          kind: http_jsonl
          enabled: true
          http_jsonl: {url: https://one.example.test}
        - name: dup
          kind: http_jsonl
          enabled: true
          http_jsonl: {url: https://one.example.test}
"""
    )
    destinations = {
        destination["name"]: destination for destination in _document(result)["observability"]["destinations"]
    }

    for name in ("dup", "dup-2"):
        assert destinations[name]["routes"][0] == {
            "name": "legacy-connector-suppress",
            "signals": ["logs"],
            "selector": {"connectors": ["codex"]},
            "action": "drop",
        }
    assert destinations["codex-dup"]["routes"][0]["selector"]["connectors"] == ["codex"]
    assert destinations["codex-dup-2"]["routes"][0]["selector"]["connectors"] == ["codex"]


@pytest.mark.parametrize(
    ("legacy_name", "canonical"),
    [("CoDeX", "codex"), ("open-hands", "openhands"), ("open_hands", "openhands")],
)
def test_connector_names_use_current_case_and_openhands_normalization(legacy_name: str, canonical: str) -> None:
    result = _convert(
        f"""config_version: 7
observability:
  connectors:
    {legacy_name}:
      webhooks:
        - name: incident
          type: generic
          enabled: false
          url: https://notifications.example.test
      audit_sinks: []
"""
    )
    observability = _document(result)["observability"]

    assert list(observability["connectors"]) == [canonical]


@pytest.mark.parametrize(
    ("first", "second"),
    [("Codex", "codex"), ("open-hands", "open_hands"), ("OpenHands", "open_hands")],
)
def test_connector_alias_collisions_fail_before_candidate(first: str, second: str) -> None:
    source = f"""config_version: 7
observability:
  connectors:
    {first}: {{audit_sinks: []}}
    {second}: {{audit_sinks: []}}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)

    assert captured.value.code == "duplicate_connector_alias"


def test_sink_specific_adapter_fields_and_selector_intent_survive() -> None:
    source = """config_version: 7
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    batch_size: 100
    flush_interval_s: 2
    timeout_s: 9
    min_severity: high
    actions: [scan]
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token_env: SPLUNK_TOKEN
      sourcetype: defenseclaw:audit
      sourcetype_overrides: {scan: 'defenseclaw:scan'}
  - name: log-scope
    kind: otlp_logs
    enabled: true
    otlp_logs:
      endpoint: https://collector.example.test
      protocol: grpc
      logger_name: defenseclaw.audit
"""
    result = _convert(source)
    document = _document(result)
    splunk = _destination(document, "splunk")
    scope = _destination(document, "log-scope")

    assert splunk["sourcetype_overrides"] == {
        "llm-judge-response": "defenseclaw:judge",
        "guardrail-verdict": "defenseclaw:verdict",
        "scan": "defenseclaw:scan",
    }
    assert splunk["timeout_ms"] == 9000
    assert splunk["batch"] == {
        "max_export_batch_size": 100,
        "max_queue_size": 10000,
        "scheduled_delay_ms": 2000,
    }
    assert splunk["routes"][0]["selector"]["min_severity"] == "HIGH"
    assert splunk["routes"][0]["selector"]["actions"] == ["scan"]
    assert scope["logger_name"] == "defenseclaw.audit"
    load_validate_v8(result.candidate)


def test_generated_audit_route_preserves_lifecycle_security_and_activity_actions_without_broadening() -> None:
    source = """config_version: 7
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    actions: [gateway-agent-start, guardrail-verdict, config-update, scan, api-auth-failure]
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token_env: SPLUNK_TOKEN
"""

    result = _convert(source)
    selector = _destination(_document(result), "splunk")["routes"][0]["selector"]
    assert selector == {
        "actions": [
            "api-auth-failure",
            "config-update",
            "gateway-agent-start",
            "guardrail-verdict",
            "scan",
        ]
    }


def test_unfiltered_audit_sink_preserves_only_the_four_v7_native_gateway_event_families() -> None:
    result = _convert(
        """config_version: 7
audit_sinks:
  - name: archive
    kind: http_jsonl
    enabled: true
    http_jsonl: {url: https://collector.example.test}
"""
    )
    routes = _destination(_document(result), "archive")["routes"]
    assert routes[0] == {
        "name": "legacy-audit-logs-1",
        "signals": ["logs"],
        "selector": {
            "event_names": [
                "guardrail.evaluation.completed",
                "legacy.audit.gateway.chat.error",
                "legacy.audit.gateway.session.message",
                "legacy.audit.gateway.tool.call",
                "legacy.audit.gateway.tool.call.blocked",
                "legacy.audit.gateway.tool.result",
                "legacy.audit.tool.call",
                "legacy.audit.tool.result",
                "model.call.failed",
                "model.request",
                "model.response",
                "model.stream.completed",
                "tool.invocation.blocked",
                "tool.invocation.completed",
                "tool.invocation.failed",
                "tool.invocation.requested",
                "tool.invocation.started",
                "tool_end",
                "tool_start",
            ]
        },
        "redaction_profile": "legacy-v7",
    }
    action_selector = routes[1]["selector"]["actions"]
    assert len(action_selector) == 188
    assert {"config-update", "gateway-agent-start", "guardrail-verdict", "scan"}.issubset(action_selector)
    assert "judge" not in routes[0]["selector"]["event_names"]
    assert "diagnostic.message" not in routes[0]["selector"]["event_names"]


def test_whitespace_only_audit_actions_preserve_v7_match_nothing_behavior() -> None:
    result = _convert(
        """config_version: 7
audit_sinks:
  - name: archive
    kind: http_jsonl
    enabled: true
    actions: ['   ']
    http_jsonl: {url: https://collector.example.test}
"""
    )

    assert _destination(_document(result), "archive")["routes"] == [
        {
            "name": "legacy-empty-action-filter",
            "signals": ["logs"],
            "selector": {},
            "action": "drop",
        }
    ]
    load_validate_v8(result.candidate)


def test_whitespace_audit_action_is_ignored_when_valid_actions_remain() -> None:
    result = _convert(
        """config_version: 7
audit_sinks:
  - name: archive
    kind: http_jsonl
    enabled: true
    actions: ['   ', ' Scan ']
    http_jsonl: {url: https://collector.example.test}
"""
    )

    assert _destination(_document(result), "archive")["routes"][0]["selector"]["actions"] == ["scan"]


@pytest.mark.parametrize(
    ("configured", "expected"),
    [("MED", "MEDIUM"), ("NONE", "INFO"), ("nonsense", "INFO"), (" info ", "INFO")],
)
def test_audit_min_severity_uses_v7_rank_normalization(configured: str, expected: str) -> None:
    result = _convert(
        f"""config_version: 7
audit_sinks:
  - name: archive
    kind: http_jsonl
    enabled: true
    min_severity: '{configured}'
    actions: [' Scan ']
    http_jsonl: {{url: https://collector.example.test}}
"""
    )
    selector = _destination(_document(result), "archive")["routes"][0]["selector"]

    assert selector["actions"] == ["scan"]
    assert selector["min_severity"] == expected
    load_validate_v8(result.candidate)


def test_active_unresolved_optional_bearer_is_omitted_like_v7() -> None:
    result = _convert(
        """config_version: 7
audit_sinks:
  - name: optional
    kind: http_jsonl
    enabled: true
    http_jsonl:
      url: https://collector.example.test
      bearer_env: OPTIONAL_TOKEN
"""
    )
    destination = _destination(_document(result), "optional")

    assert "bearer_env" not in destination
    assert "unresolved_optional_bearer_omitted" in result.warnings
    load_validate_v8(result.candidate)


def test_active_whitespace_only_optional_bearer_fails_before_candidate() -> None:
    source = """config_version: 7
audit_sinks:
  - name: optional
    kind: http_jsonl
    enabled: true
    http_jsonl:
      url: https://collector.example.test
      bearer_env: OPTIONAL_TOKEN
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source, {"OPTIONAL_TOKEN": "   "})

    assert captured.value.code == "unrepresentable_optional_bearer"


@pytest.mark.parametrize(
    "credential",
    ["bearer_token: '   '", "bearer_env: OPTIONAL_TOKEN\n      bearer_token: '   '"],
)
def test_active_whitespace_only_inline_bearer_fails_before_candidate(credential: str) -> None:
    source = f"""config_version: 7
audit_sinks:
  - name: optional
    kind: http_jsonl
    enabled: true
    http_jsonl:
      url: https://collector.example.test
      {credential}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)

    assert captured.value.code == "unrepresentable_optional_bearer"
    assert captured.value.__cause__ is None


def test_audit_sink_effective_defaults_and_partial_overrides_are_materialized() -> None:
    source = """config_version: 7
audit_sinks:
  - name: splunk-defaults
    kind: splunk_hec
    enabled: true
    batch_size: 200
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token_env: SPLUNK_TOKEN
      sourcetype_overrides: {guardrail-verdict: 'corp:verdict'}
  - name: http-defaults
    kind: http_jsonl
    enabled: true
    http_jsonl: {url: https://events.example.test}
  - name: otlp-defaults
    kind: otlp_logs
    enabled: true
    otlp_logs: {endpoint: https://collector.example.test}
"""
    document = _document(_convert(source))
    splunk = _destination(document, "splunk-defaults")
    http = _destination(document, "http-defaults")
    otlp = _destination(document, "otlp-defaults")

    assert splunk["source"] == "defenseclaw"
    assert splunk["sourcetype"] == "_json"
    assert splunk["sourcetype_overrides"] == {
        "llm-judge-response": "defenseclaw:judge",
        "guardrail-verdict": "corp:verdict",
    }
    assert splunk["timeout_ms"] == 10000
    assert splunk["batch"] == {
        "max_export_batch_size": 200,
        "max_queue_size": 20000,
        "scheduled_delay_ms": 5000,
    }
    assert http["timeout_ms"] == 10000
    assert http["batch"] == {
        "max_export_batch_size": 1,
        "max_queue_size": 10000,
        "scheduled_delay_ms": 5000,
    }
    assert otlp["logger_name"] == "defenseclaw.audit"
    assert otlp["timeout_ms"] == 10000
    assert otlp["batch"] == {
        "max_export_batch_size": 512,
        "max_queue_size": 2048,
        "scheduled_delay_ms": 5000,
    }


def test_crlf_comments_ascii_order_and_unrelated_scalar_style_survive() -> None:
    source = (
        "# ┌── keep ──┐\r\n"
        "config_version: 7\r\n"
        "environment: 'quoted-value' # inline\r\n"
        "otel: {enabled: false}\r\n"
        "# this belongs to guardrail\r\n"
        "guardrail: {enabled: false}\r\n"
    )
    result = _convert(source)
    candidate = result.candidate.decode()

    assert candidate.count("\n") == candidate.count("\r\n")
    assert candidate.startswith("# ┌── keep ──┐\r\nconfig_version: 8\r\n")
    assert "environment: 'quoted-value' # inline\r\n" in candidate
    assert "# this belongs to guardrail\r\n" in candidate
    assert candidate.index("environment:") < candidate.index("observability:") < candidate.index("guardrail:")


def test_comments_inside_every_reformatted_owned_section_survive_as_comment_tokens() -> None:
    source = """config_version: 7
audit_db: /var/lib/defenseclaw/audit.db # audit-path-comment
judge_bodies_db: /var/lib/defenseclaw/judge.db # judge-path-comment
otel: # otel-root-comment
  # ┌── nested otel guide ──┐
  enabled: false # otel-enabled-comment
  resource:
    attributes:
      service.name: '# quoted-hash-not-comment'
      deployment.environment: staging # environment-alias-comment
      defenseclaw.preset: generic-otlp # consumed-preset-comment
audit_sinks: # sinks-root-comment
  [] # sinks-empty-comment
observability: # connector-root-comment
  connectors:
    codex:
      # webhook-comment
      webhooks: []
privacy: # privacy-root-comment
  disable_redaction: false # privacy-value-comment
ai_discovery: # discovery-root-comment
  enabled: true
  emit_otel: false # discovery-routing-comment
"""
    result = _convert(source)
    candidate = result.candidate.decode()

    expected_comments = (
        "# audit-path-comment",
        "# judge-path-comment",
        "# otel-root-comment",
        "# ┌── nested otel guide ──┐",
        "# otel-enabled-comment",
        "# environment-alias-comment",
        "# consumed-preset-comment",
        "# sinks-root-comment",
        "# sinks-empty-comment",
        "# connector-root-comment",
        "# webhook-comment",
        "# privacy-root-comment",
        "# privacy-value-comment",
        "# discovery-root-comment",
        "# discovery-routing-comment",
    )
    for comment in expected_comments:
        assert comment in candidate
    assert candidate.count("# quoted-hash-not-comment") == 1
    assert _document(result)["observability"]["resource"]["attributes"] == {
        "service.name": "# quoted-hash-not-comment",
        "deployment.environment.name": "staging",
    }
    load_validate_v8(result.candidate)


def test_preserved_comments_scrub_migrated_secrets_and_exclude_block_scalar_hashes() -> None:
    token_canary = "inline-token-canary"
    block_canary = "block-header-canary"
    source = f"""config_version: 7
# before owned root repeats {token_canary}
audit_sinks:
  # standalone repeats {token_canary}
  - name: splunk
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token: {token_canary} # inline repeats {token_canary}
  - name: audit-otlp
    kind: otlp_logs
    enabled: true
    otlp_logs:
      endpoint: https://collector.example.test
      headers:
        Authorization: |
          Bearer {block_canary} # scalar-content-not-comment
      # real header comment survives
"""
    result = _convert(source)
    candidate = result.candidate.decode()

    assert token_canary not in candidate
    assert block_canary not in candidate
    assert "# scalar-content-not-comment" not in candidate
    assert "# standalone repeats [REDACTED]" in candidate
    assert "# before owned root repeats [REDACTED]" in candidate
    assert "# inline repeats [REDACTED]" in candidate
    assert "# real header comment survives" in candidate


def test_preserved_comments_scrub_resolved_credentials_and_unused_inline_fallbacks() -> None:
    credentials = {
        "SPLUNK_TOKEN": "resolved-splunk-comment-canary",
        "HTTP_TOKEN": "resolved-http-comment-canary",
        "HEADER_TOKEN": "resolved-header-comment-canary",
    }
    unused_splunk = "unused-splunk-comment-canary"
    unused_http = "unused-http-comment-canary"
    source = f"""config_version: 7
# resolved {credentials["SPLUNK_TOKEN"]} {credentials["HTTP_TOKEN"]} {credentials["HEADER_TOKEN"]}
# unused fallbacks {unused_splunk} {unused_http}
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token_env: SPLUNK_TOKEN
      token: {unused_splunk}
  - name: http
    kind: http_jsonl
    enabled: true
    http_jsonl:
      url: https://events.example.test
      bearer_env: HTTP_TOKEN
      bearer_token: {unused_http}
  - name: otlp
    kind: otlp_logs
    enabled: true
    otlp_logs:
      endpoint: https://collector.example.test
      headers:
        Authorization: '${{HEADER_TOKEN}}'
"""

    result = _convert(source, credentials)
    candidate = result.candidate.decode()
    document = _document(result)

    for secret in (*credentials.values(), unused_splunk, unused_http):
        assert secret not in candidate
    assert candidate.count("[REDACTED]") >= 5
    assert _destination(document, "splunk")["token_env"] == "SPLUNK_TOKEN"
    assert _destination(document, "http")["bearer_env"] == "HTTP_TOKEN"
    assert _destination(document, "otlp")["headers"]["Authorization"] == {"env": "HEADER_TOKEN"}
    assert result.environment_edits == ()
    load_validate_v8(result.candidate)


def test_interpolated_secret_components_are_scrubbed_from_preserved_comments() -> None:
    component = "component-secret-canary"
    source = f"""config_version: 7
otel:
  enabled: true
  # standalone component {component}
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers:
        Authorization: 'Bearer ${{SOURCE_TOKEN}}' # inline component {component}
      traces: {{enabled: true}}
"""
    result = _convert(source, {"SOURCE_TOKEN": component})
    candidate = result.candidate.decode()

    assert component not in candidate
    assert "# standalone component [REDACTED]" in candidate
    assert "# inline component [REDACTED]" in candidate


def test_many_secret_literals_and_comments_use_bounded_multi_literal_scrubbing() -> None:
    headers = "\n".join(f"        X-Token-{index}: secret-{index:03d}" for index in range(128))
    comments = "\n".join(f"  # comment secret-{index:03d}" for index in range(128))
    source = f"""config_version: 7
otel:
  enabled: true
{comments}
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers:
{headers}
      traces: {{enabled: true}}
"""
    result = _convert(source)

    assert len(result.environment_edits) == 128
    assert "secret-000" not in result.candidate.decode()
    assert result.candidate.decode().count("# comment [REDACTED]") == 128


def test_sensitive_literal_limits_fail_before_scrubber_allocation() -> None:
    oversized = "sensitive-canary-" + "x" * (256 * 1024)
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      headers: {{X-Custom: '{oversized}'}}
      traces: {{enabled: true}}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "sensitive_data_too_large"
    assert "sensitive-canary" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_sensitive_literal_count_is_bounded_before_scrubber_allocation() -> None:
    destinations = [
        {
            "name": f"remote-{destination_index}",
            "enabled": True,
            "endpoint": "https://collector.example.test",
            "protocol": "grpc",
            "headers": {
                f"X-Custom-{header_index}": f"value-{destination_index}-{header_index}" for header_index in range(820)
            },
            "traces": {"enabled": True},
        }
        for destination_index in range(5)
    ]
    source = yaml.safe_dump(
        {"config_version": 7, "otel": {"enabled": True, "destinations": destinations}},
        sort_keys=False,
    )

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "sensitive_data_too_large"


def test_explicit_environment_entry_and_value_limits_are_value_safe() -> None:
    too_many = {f"SAFE_NAME_{index}": "x" for index in range(4097)}
    with pytest.raises(V8MigrationError) as captured_entries:
        _convert("config_version: 7\n", too_many)
    assert captured_entries.value.code == "environment_too_large"

    canary = "environment-value-canary-" + "x" * (256 * 1024)
    with pytest.raises(V8MigrationError) as captured_value:
        _convert("config_version: 7\n", {"OVERSIZED_VALUE": canary})
    assert captured_value.value.code == "environment_value_too_large"
    assert "environment-value-canary" not in str(captured_value.value)
    assert captured_value.value.__cause__ is None


def test_malformed_yaml_diagnostic_suppresses_secret_bearing_parser_cause() -> None:
    canary = "malformed-secret-canary"
    with pytest.raises(V8MigrationError) as captured:
        _convert(f'config_version: 7\notel: {{headers: {{Authorization: "{canary}}}}}\n')

    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "source",
    [
        "config_version: 7\notel: {enabled: true, future_knob: true}\n",
        "config_version: 7\naudit_sinks: [{name: x, kind: future, enabled: true}]\n",
        "config_version: 7\nprivacy: {disable_redaction: false, future_knob: true}\n",
        "config_version: 7\nconfig_version: 7\n",
    ],
)
def test_unsupported_or_unsafe_v7_shapes_fail_instead_of_guessing(source: str) -> None:
    with pytest.raises(V8MigrationError):
        _convert(source)


@pytest.mark.parametrize(
    "nested",
    [
        "batch: {future_knob: 1}",
        "tls: {future_knob: true}",
        "resource: {future_knob: {}}",
    ],
)
def test_unknown_nested_otel_fields_fail_before_candidate(nested: str) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(f"config_version: 7\notel:\n  enabled: false\n  {nested}\n")
    assert captured.value.code == "unsupported_v7_shape"

    destination_nested = (
        "config_version: 7\notel:\n  enabled: true\n  destinations:\n"
        "    - name: remote\n      enabled: true\n      endpoint: https://collector.example.test\n"
        "      protocol: grpc\n      traces: {enabled: true}\n"
        f"      {nested}\n"
    )
    with pytest.raises(V8MigrationError):
        _convert(destination_nested)


def test_unknown_span_filter_operation_field_fails_before_family_lookup() -> None:
    source = """config_version: 7
otel:
  enabled: true
  destinations:
    - name: remote
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      traces: {enabled: true}
      span_filter:
        operations:
          - {name: chat, future_knob: true}
"""
    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "unsupported_v7_shape"


def test_deep_yaml_nesting_is_rejected_without_runtime_recursion_leak() -> None:
    deeply_nested = "config_version: 7\nunknown: " + "[" * 2000 + "0" + "]" * 2000 + "\n"
    with pytest.raises(V8MigrationError) as captured:
        _convert(deeply_nested)
    assert captured.value.code in {"source_too_complex", "invalid_yaml"}


def test_invalid_unicode_text_has_value_safe_utf8_error() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert("config_version: 7\n# \ud800\n")

    assert captured.value.code == "invalid_utf8"
    assert captured.value.__cause__ is None


def test_yaml_node_limit_is_enforced_before_container_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    source = "config_version: 7\nunknown:\n" + "  - x\n" * 65_536
    constructed = False

    def fail_if_constructed(*args: object, **kwargs: object) -> object:
        nonlocal constructed
        constructed = True
        raise AssertionError("YAML construction must not run after structural preflight rejection")

    monkeypatch.setattr(migration_module.yaml, "load", fail_if_constructed)
    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "source_too_complex"
    assert constructed is False


def test_yaml_mapping_entry_limit_is_enforced_before_container_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "config_version: 7\nunknown:\n" + "".join(f"  key_{index}: x\n" for index in range(1_025))
    constructed = False

    def fail_if_constructed(*args: object, **kwargs: object) -> object:
        nonlocal constructed
        constructed = True
        raise AssertionError("YAML construction must not run after mapping preflight rejection")

    monkeypatch.setattr(migration_module.yaml, "load", fail_if_constructed)
    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "source_too_complex"
    assert constructed is False


def test_nonscalar_resource_attribute_container_has_value_safe_error() -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert("config_version: 7\notel:\n  resource:\n    attributes: [not, a, mapping]\n")
    assert captured.value.code == "unsupported_type"
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("endpoint", "expected_name", "expected_safety"),
    [
        ("collector.localhost:4317", "local-observability", {"allow_private_networks": True}),
        ("[::ffff:100.64.0.1]:4317", "generic-otlp", {"allow_cgnat": True}),
    ],
)
def test_migrator_and_validator_share_private_endpoint_classification(
    endpoint: str, expected_name: str, expected_safety: dict[str, bool]
) -> None:
    result = _convert(
        f"""config_version: 7
otel:
  enabled: true
  endpoint: '{endpoint}'
  protocol: grpc
  traces: {{enabled: true}}
"""
    )

    destination = _destination(_document(result), expected_name)
    assert destination["network_safety"] == expected_safety
    load_validate_v8(result.candidate)


def test_malformed_endpoint_diagnostic_is_value_safe() -> None:
    canary = "malformed-host-canary"
    source = f"""config_version: 7
otel:
  enabled: true
  endpoint: http://[{canary}]
  traces: {{enabled: true}}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("placement", "expected_path"),
    [
        ("destination", "$.otel.destinations[0].endpoint"),
        ("signal", "$.otel.destinations[0].traces.endpoint"),
    ],
)
def test_named_malformed_endpoint_diagnostic_is_value_safe(placement: str, expected_path: str) -> None:
    canary = "malformed-named-host-canary"
    if placement == "destination":
        endpoint_block = f"      endpoint: http://[{canary}]\n      traces: {{enabled: true}}"
    else:
        endpoint_block = f"      traces: {{enabled: true, endpoint: 'http://[{canary}]'}}"
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: http
{endpoint_block}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == expected_path
    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("placement", "expected_path"),
    [
        ("destination", "$.otel.destinations[0].endpoint"),
        ("signal", "$.otel.destinations[0].traces.endpoint"),
    ],
)
def test_flat_destination_does_not_shift_named_source_diagnostic_path(
    placement: str,
    expected_path: str,
) -> None:
    canary = "mixed-flat-named-malformed-canary"
    if placement == "destination":
        endpoint_block = f"      endpoint: http://[{canary}]\n      traces: {{enabled: true}}"
    else:
        endpoint_block = f"      traces: {{enabled: true, endpoint: 'http://[{canary}]'}}"
    source = f"""config_version: 7
otel:
  enabled: true
  protocol: grpc
  endpoint: 127.0.0.1:4317
  traces: {{enabled: true}}
  destinations:
    - name: backend
      enabled: true
      protocol: http
{endpoint_block}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == expected_path
    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("endpoint", "placement", "expected_path"),
    [
        ("[malformed-grpc-host:4317", "destination", "$.otel.destinations[0].endpoint"),
        ("collector.example.test:not-a-port", "signal", "$.otel.destinations[0].traces.endpoint"),
    ],
)
def test_named_malformed_grpc_authority_has_exact_source_path(
    endpoint: str, placement: str, expected_path: str
) -> None:
    if placement == "destination":
        endpoint_block = f"      endpoint: '{endpoint}'\n      traces: {{enabled: true}}"
    else:
        endpoint_block = f"      traces: {{enabled: true, endpoint: '{endpoint}'}}"
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
{endpoint_block}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == expected_path
    assert endpoint not in str(captured.value)
    assert endpoint not in repr(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("protocol", "endpoint"),
    [
        ("grpc", "collector.example.test"),
        ("grpc", "collector.example.test:0"),
        ("grpc", "bad host.example.test:4317"),
        ("grpc", "collector.example.test:4317/path"),
        ("grpc", "collector.example.test:4317?tenant=review"),
        ("grpc", " collector.example.test:4317 "),
        ("grpc", "https://collector.example.test:4317/%ZZ"),
        ("http", "https://bad host.example.test:4318"),
        ("http", " https://collector.example.test:4318"),
        ("http", "https://-bad.example.test:4318"),
        ("http", "https://collector.example.test:0"),
        ("http", "https://collector.example.test:4318/%ZZ"),
    ],
)
def test_named_unrepresentable_endpoint_fails_before_candidate_construction(protocol: str, endpoint: str) -> None:
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: {protocol}
      endpoint: '{endpoint}'
      traces: {{enabled: true}}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == "$.otel.destinations[0].endpoint"
    assert endpoint not in str(captured.value)
    assert endpoint not in repr(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "global_endpoint",
    [
        "",
        "  endpoint: 127.0.0.1:4317\n",
        "  endpoint: collector.example.test:4317\n",
    ],
)
def test_flat_signal_malformed_endpoint_has_exact_source_path(global_endpoint: str) -> None:
    source = f"""config_version: 7
otel:
  enabled: true
{global_endpoint}  protocol: grpc
  traces: {{enabled: true, endpoint: 'traces.example.test:not-a-port'}}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == "$.otel.traces.endpoint"
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("source", "expected_path"),
    [
        (
            """config_version: 7
otel:
  enabled: true
  protocol: grpc
  traces: {enabled: true}
""",
            "$.otel.traces.endpoint",
        ),
        (
            """config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
      traces: {enabled: true}
""",
            "$.otel.destinations[0].traces.endpoint",
        ),
    ],
)
def test_missing_enabled_signal_endpoint_has_exact_source_path(source: str, expected_path: str) -> None:
    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_v7_otel"
    assert captured.value.path == expected_path
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("endpoint", "placement", "expected_path"),
    [
        ("review-user:review-secret@collector.example.test:4317", "destination", "$.otel.destinations[0].endpoint"),
        (
            "https://review-user:review-secret@collector.example.test:4317",
            "signal",
            "$.otel.destinations[0].traces.endpoint",
        ),
    ],
)
def test_named_endpoint_userinfo_is_rejected_at_exact_source_path(
    endpoint: str, placement: str, expected_path: str
) -> None:
    if placement == "destination":
        endpoint_block = f"      endpoint: '{endpoint}'\n      traces: {{enabled: true}}"
    else:
        endpoint_block = f"      traces: {{enabled: true, endpoint: '{endpoint}'}}"
    source = f"""config_version: 7
otel:
  enabled: true
  destinations:
    - name: backend
      enabled: true
      protocol: grpc
{endpoint_block}
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "invalid_endpoint"
    assert captured.value.path == expected_path
    assert "review-secret" not in str(captured.value)
    assert "review-secret" not in repr(captured.value)
    assert captured.value.__cause__ is None


def test_malformed_url_like_resource_attribute_remains_arbitrary_text() -> None:
    value = "http://[malformed-resource-note]"
    result = _convert(
        f"""config_version: 7
otel:
  resource:
    attributes:
      custom.note: '{value}'
"""
    )

    document = _document(result)
    assert document["observability"]["resource"]["attributes"]["custom.note"] == value
    load_validate_v8(result.candidate)


def test_malformed_url_like_resource_userinfo_is_rejected_value_safely() -> None:
    canary = "review-user:review-secret"
    source = f"""config_version: 7
otel:
  resource:
    attributes:
      custom.note: 'http://{canary}@[malformed-resource-note]'
"""

    with pytest.raises(V8MigrationError) as captured:
        _convert(source)
    assert captured.value.code == "candidate_validation_failed"
    assert canary not in str(captured.value)
    assert canary not in repr(captured.value)
    assert captured.value.__cause__ is None


def test_diagnostics_warnings_and_summary_never_contain_source_values() -> None:
    canary = "never-render-this-secret"
    source = f"""config_version: 7
audit_sinks:
  - name: splunk
    kind: splunk_hec
    enabled: true
    splunk_hec:
      endpoint: https://splunk.example.test/services/collector
      token: {canary}
"""
    result = _convert(source)

    assert canary not in repr(result)
    assert canary not in " ".join(result.warnings)
    assert canary not in " ".join(result.summary.lines())
    assert canary not in result.candidate.decode()
