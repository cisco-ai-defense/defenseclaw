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

import json
from pathlib import Path
from typing import Any

import pytest
from defenseclaw.observability.v8_config import (
    BUCKETS,
    DESTINATION_BATCH_MODES,
    DESTINATION_CAPABILITIES,
    MAX_MAPPING_ENTRIES,
    MAX_RESOURCE_ATTRIBUTES,
    MAX_RESOURCE_TOTAL_BYTES,
    MAX_YAML_DEPTH,
    MAX_YAML_NODES,
    PUSH_BATCH_BOUNDS,
    PUSH_BATCH_DEFAULTS,
    QUEUE_BOUNDS,
    QUEUE_DEFAULTS,
    V8ConfigError,
    _parse_source,
    _shape,
    load_validate_v8,
    observability_v8_parity_contract,
    validate_v8_source,
)

ROOT = Path(__file__).resolve().parents[2]


def test_minimal_source_and_parity_contract_are_deterministic() -> None:
    validated = load_validate_v8("config_version: 8\nobservability: {}\n")

    assert validated.source == {"config_version": 8, "observability": {}}
    assert validated.masked == validated.source
    assert json.loads(validated.masked_json()) == validated.masked
    assert validated.digest() == load_validate_v8("observability: {}\nconfig_version: 8\n").digest()

    contract = validated.parity_contract
    assert contract == observability_v8_parity_contract()
    assert contract["buckets"] == list(BUCKETS)
    assert contract["catalog_defaults"]["collect"] == {
        "logs": True,
        "traces": True,
        "metrics": True,
    }
    assert contract["catalog_defaults"]["redaction_profile"] == "none"
    assert contract["destination_capabilities"] == {
        name: list(signals) for name, signals in DESTINATION_CAPABILITIES.items()
    }
    assert contract["destination_batch_modes"] == DESTINATION_BATCH_MODES
    assert contract["galileo_capabilities"] == ["traces"]
    assert contract["queue_defaults"] == QUEUE_DEFAULTS
    assert contract["push_batch_defaults"] == PUSH_BATCH_DEFAULTS
    assert contract["queue_bounds"] == {name: list(bounds) for name, bounds in QUEUE_BOUNDS.items()}
    assert contract["push_batch_bounds"] == {name: list(bounds) for name, bounds in PUSH_BATCH_BOUNDS.items()}
    assert contract["profiles"] == ["none", "sensitive", "content", "strict", "legacy-v7"]


def test_extreme_yaml_depth_is_rejected_before_recursion_escapes() -> None:
    source = "config_version: 8\nobservability:\n  future: " + "[" * 5_000 + "]" * 5_000 + "\n"
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)
    assert captured.value.keyword in {"max-depth", "yaml"}
    assert captured.value.__cause__ is None


def test_extreme_mapping_depth_is_rejected_without_recursion_escape() -> None:
    nested: dict[str, Any] = {}
    current = nested
    for _ in range(2_000):
        child: dict[str, Any] = {}
        current["x"] = child
        current = child
    source: dict[str, Any] = {"config_version": 8, "observability": nested}
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)
    assert captured.value.keyword == "max-depth"
    assert captured.value.__cause__ is None


def test_reference_source_validates_against_canonical_schema() -> None:
    reference = ROOT / "schemas" / "config" / "v8" / "reference" / "observability.yaml"
    validated = load_validate_v8(reference.read_bytes(), source_name=str(reference))

    assert validated.source["config_version"] == 8
    assert len(validated.source["observability"]["destinations"]) == 7


def test_batch_source_round_trip_masking_and_independent_byte_domains() -> None:
    source = {
        "config_version": 8,
        "observability": {
            "destinations": [
                {
                    "name": "jsonl",
                    "kind": "jsonl",
                    "path": "/tmp/defenseclaw.jsonl",
                    "batch": {"max_queue_size": 1, "max_queue_bytes": 4_198_400},
                },
                {
                    "name": "archive",
                    "kind": "http_jsonl",
                    "endpoint": "https://archive.example.test/events?access_token=secret-canary",
                    "batch": {
                        "max_queue_size": 512,
                        "max_queue_bytes": 4_198_400,
                        "max_export_batch_size": 512,
                        "max_export_batch_bytes": 4_263_936,
                        "scheduled_delay_ms": 1,
                    },
                },
            ]
        },
    }
    validated = load_validate_v8(source)
    masked = validated.masked

    assert masked["observability"]["destinations"][0]["batch"] == source["observability"]["destinations"][0]["batch"]
    assert masked["observability"]["destinations"][1]["batch"] == source["observability"]["destinations"][1]["batch"]
    assert "secret-canary" not in validated.masked_json()
    assert "max_export_batch_bytes" in validated.masked_json()


@pytest.mark.parametrize(
    "destination",
    [
        {
            "name": "jsonl",
            "kind": "jsonl",
            "path": "/tmp/defenseclaw.jsonl",
            "batch": {"scheduled_delay_ms": 1_000},
        },
        {
            "name": "metrics",
            "kind": "prometheus",
            "listen": "127.0.0.1:9464",
            "path": "/metrics",
            "batch": dict(QUEUE_DEFAULTS),
        },
        {"name": "console", "kind": "console", "batch": {"max_queue_size": 65_537}},
        {"name": "console", "kind": "console", "batch": {"max_queue_bytes": 4_198_399}},
        {
            "name": "archive",
            "kind": "http_jsonl",
            "endpoint": "https://archive.example.test/events",
            "batch": {"max_export_batch_size": 8_193},
        },
        {
            "name": "archive",
            "kind": "http_jsonl",
            "endpoint": "https://archive.example.test/events",
            "batch": {"max_export_batch_bytes": 67_108_865},
        },
        {
            "name": "archive",
            "kind": "http_jsonl",
            "endpoint": "https://archive.example.test/events",
            "batch": {"scheduled_delay_ms": 600_001},
        },
    ],
)
def test_batch_kind_and_boundary_validation(destination: dict[str, Any]) -> None:
    with pytest.raises(V8ConfigError):
        load_validate_v8({"config_version": 8, "observability": {"destinations": [destination]}})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("defenseclaw.claw.home_dir", "opaque"),
        ("service.note", "/Users/operator/private"),
        ("service.note", r"C:\Users\operator\private"),
        ("service.note", r"\\server\share\private"),
        ("service.note", "file:///var/lib/defenseclaw"),
    ],
)
def test_resource_attributes_reject_filesystem_paths(name: str, value: str) -> None:
    source = {
        "config_version": 8,
        "observability": {"resource": {"attributes": {name: value}}},
    }
    with pytest.raises(V8ConfigError, match="filesystem and home-directory paths"):
        load_validate_v8(source)


@pytest.mark.parametrize(
    "legacy",
    [
        "otel: {}",
        "audit_sinks: []",
        "judge_bodies_db: /tmp/judge.db",
        "privacy: {disable_redaction: true}",
        "ai_discovery: {emit_otel: false}",
        "observability: {connectors: {codex: {audit_sinks: []}}}",
    ],
)
def test_exact_v8_rejects_legacy_fields(legacy: str) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(f"config_version: 8\n{legacy}\n")

    assert captured.value.keyword in {"additionalProperties", "oneOf"}
    assert "run defenseclaw upgrade" in str(captured.value)


@pytest.mark.parametrize("version", [7, 9, "8", 8.0, True])
def test_exact_v8_rejects_other_version_values(version: object) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8({"config_version": version})

    assert captured.value.path == "$.config_version"
    assert captured.value.keyword == "exact-version"


def test_private_upstream_allowlist_is_optional_unique_and_source_preserving() -> None:
    minimal = load_validate_v8({"config_version": 8, "guardrail": {}, "observability": {}})
    assert "allow_private_upstreams" not in minimal.source["guardrail"]

    values = [" 10.20.30.40 ", "fd12:3456::8", "8.8.8.8", "100.64.0.8"]
    validated = load_validate_v8(
        {
            "config_version": 8,
            "guardrail": {"allow_private_upstreams": values},
            "observability": {},
        }
    )
    assert validated.source["guardrail"]["allow_private_upstreams"] == values

    with pytest.raises(V8ConfigError) as duplicate:
        load_validate_v8(
            {
                "config_version": 8,
                "guardrail": {"allow_private_upstreams": ["10.20.30.40", "10.20.30.40"]},
                "observability": {},
            }
        )
    assert duplicate.value.keyword == "uniqueItems"


@pytest.mark.parametrize(
    "value",
    [
        "10.20.30.40",
        "172.16.0.8",
        "192.168.1.8",
        "fd12:3456::8",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "100.64.0.8",
        "::ffff:10.20.30.40",
        "  10.20.30.40  ",
        "   ",
    ],
)
def test_private_upstream_allowlist_accepts_go_valid_literal_classes(value: str) -> None:
    validated = load_validate_v8(
        {
            "config_version": 8,
            "guardrail": {"allow_private_upstreams": [value]},
            "observability": {},
        }
    )
    assert validated.source["guardrail"]["allow_private_upstreams"] == [value]


@pytest.mark.parametrize(
    "value",
    [
        "10.20.30.0/24",
        "not-an-ip",
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "169.254.10.20",
        "fe80::8",
        "::ffff:169.254.10.20",
        "224.0.0.8",
        "ff02::8",
        "0.0.0.0",
        "::",
        "::ffff:0.0.0.0",
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "2001:4860:4860::8888%eth0",
    ],
)
def test_private_upstream_allowlist_rejects_go_hard_denied_or_nonliteral_values(value: str) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(
            {
                "config_version": 8,
                "guardrail": {"allow_private_upstreams": [value]},
                "observability": {},
            }
        )
    assert captured.value.path == "$.guardrail.allow_private_upstreams[0]"
    assert captured.value.keyword == "semantic"


@pytest.mark.parametrize(
    "source",
    [
        "config_version: 8\nconfig_version: 8\n",
        "config_version: &version 8\nother: *version\n",
        "config_version: 8\nbase: &base {enabled: true}\nobservability:\n  <<: *base\n",
    ],
)
def test_yaml_duplicates_aliases_and_merge_keys_are_rejected(source: str) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)

    assert captured.value.keyword == "yaml"
    assert "duplicate keys, aliases, merge keys" in str(captured.value)


def test_yaml_rejects_non_string_keys_and_non_finite_numbers() -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8("config_version: 8\n1: value\n")
    assert captured.value.keyword == "yaml"

    for value in (".nan", ".inf", "-.inf"):
        with pytest.raises(V8ConfigError) as captured:
            load_validate_v8(f"config_version: 8\nllm:\n  timeout: {value}\n")
        assert captured.value.keyword == "finite-number"

    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8("config_version: 8\nenvironment: !unsafe value\n")
    assert captured.value.keyword == "yaml"


def test_timestamp_and_binary_scalars_project_as_source_text_like_go() -> None:
    timestamp = load_validate_v8("config_version: 8\nenvironment: 2026-07-02\n")
    binary = load_validate_v8("config_version: 8\nenvironment: !!binary Zm9v\n")

    assert timestamp.source["environment"] == "2026-07-02"
    assert binary.source["environment"] == "Zm9v"


def test_yaml_node_depth_and_mapping_boundaries_match_go_preflight() -> None:
    at_node_limit = {"config_version": 8, "unknown": [0] * (MAX_YAML_NODES - 5)}
    over_node_limit = {"config_version": 8, "unknown": [0] * (MAX_YAML_NODES - 4)}
    assert _shape(at_node_limit) == (MAX_YAML_NODES, 2)
    assert _shape(over_node_limit) == (MAX_YAML_NODES + 1, 2)
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(over_node_limit)
    assert captured.value.keyword == "max-nodes"

    value: object = "leaf"
    for index in range(MAX_YAML_DEPTH - 1):
        value = {f"level_{index}": value}
    at_depth_limit = {"config_version": 8, "unknown": value}
    assert _shape(at_depth_limit)[1] == MAX_YAML_DEPTH
    value = {"one_too_deep": value}
    over_depth_limit = {"config_version": 8, "unknown": value}
    assert _shape(over_depth_limit)[1] == MAX_YAML_DEPTH + 1
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(over_depth_limit)
    assert captured.value.keyword == "max-depth"

    entries = {f"entry_{index}": "value" for index in range(MAX_MAPPING_ENTRIES)}
    _parse_source({"config_version": 8, "preflight": entries}, "config.yaml")
    entries["one_too_many"] = "value"
    with pytest.raises(V8ConfigError) as captured:
        _parse_source({"config_version": 8, "preflight": entries}, "config.yaml")
    assert captured.value.keyword == "max-mapping-entries"


def test_resource_attribute_count_and_utf8_byte_boundaries() -> None:
    attributes = {f"custom.attribute_{index:02d}": "value" for index in range(MAX_RESOURCE_ATTRIBUTES)}
    load_validate_v8({"config_version": 8, "observability": {"resource": {"attributes": attributes}}})
    attributes["custom.one_too_many"] = "value"
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8({"config_version": 8, "observability": {"resource": {"attributes": attributes}}})
    assert captured.value.keyword == "maxProperties"
    assert captured.value.path == "$.observability.resource.attributes"

    valid_multibyte = "é" * 512
    load_validate_v8(
        {
            "config_version": 8,
            "observability": {"resource": {"attributes": {"custom.label": valid_multibyte}}},
        }
    )
    invalid_multibyte = valid_multibyte + "é"
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(
            {
                "config_version": 8,
                "observability": {"resource": {"attributes": {"custom.label": invalid_multibyte}}},
            }
        )
    assert "1 through 1024 UTF-8 bytes" in str(captured.value)
    assert invalid_multibyte not in str(captured.value)

    valid_key = "A" + ("a" * 127)
    load_validate_v8(
        {
            "config_version": 8,
            "observability": {"resource": {"attributes": {valid_key: "value"}}},
        }
    )
    with pytest.raises(V8ConfigError):
        load_validate_v8(
            {
                "config_version": 8,
                "observability": {"resource": {"attributes": {valid_key + "a": "value"}}},
            }
        )


@pytest.mark.parametrize(
    "source",
    [
        "config_version: 8\nenvironment: \ud800\n",
        'config_version: 8\nenvironment: "\\uD800"\n',
        {"config_version": 8, "environment": {"nested": "\ud800"}},
        {"config_version": 8, "\ud800": "value"},
    ],
)
def test_invalid_unicode_surrogates_are_bounded_validation_errors(source: str | dict[str, object]) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)

    assert captured.value.keyword == "utf-8"
    assert "valid UTF-8" in str(captured.value)
    assert "\ud800" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_resource_attribute_aggregate_boundary() -> None:
    attributes = {f"a{index:03d}": "v" * 1020 for index in range(16)}
    assert (
        sum(len(name.encode()) + len(value.encode()) for name, value in attributes.items()) == MAX_RESOURCE_TOTAL_BYTES
    )
    load_validate_v8({"config_version": 8, "observability": {"resource": {"attributes": attributes}}})
    attributes["a000"] += "v"
    with pytest.raises(V8ConfigError, match="within 16384 UTF-8 bytes"):
        load_validate_v8({"config_version": 8, "observability": {"resource": {"attributes": attributes}}})


@pytest.mark.parametrize(
    ("attributes", "message"),
    [
        ({"custom.label": ""}, "canonical v8 schema"),
        ({"custom.label": " \u00a0 "}, "nonblank"),
        ({"custom.label": "line\nvalue"}, "control characters"),
        ({"custom.label": "\ud800"}, "valid UTF-8"),
        ({"custom/label": "value"}, "canonical v8 schema"),
        ({"defenseclaw.instance.id": "value"}, "process-owned"),
        ({"defenseclaw.preset": "generic-otlp"}, "process-owned"),
        (
            {"deployment.environment.name": "canonical", "deployment.environment": "legacy"},
            "conflicting canonical and legacy alias spellings",
        ),
        ({"e\u0301": "first", "\u00e9": "second"}, "collide after NFC normalization"),
    ],
)
def test_resource_attribute_shape_ownership_and_collisions(attributes: dict[str, str], message: str) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8({"config_version": 8, "observability": {"resource": {"attributes": attributes}}})
    assert message in str(captured.value)


def test_registered_resource_core_is_not_misclassified_as_custom() -> None:
    for attributes in (
        {"service.name": "defenseclaw-gateway"},
        {"tenant.id": "tenant-a", "workspace.id": "workspace-a"},
        {"deployment.environment": "production"},
        {
            "deployment.environment.name": "production",
            "deployment.environment": "production",
        },
    ):
        load_validate_v8({"config_version": 8, "observability": {"resource": {"attributes": attributes}}})


def test_schema_diagnostics_do_not_render_values() -> None:
    canary = "super-secret-schema-canary"
    source = f"""config_version: 8
observability:
  unknown_field: {canary}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source, source_name="redacted.yaml")

    rendered = str(captured.value)
    assert canary not in rendered
    assert "redacted.yaml" in rendered
    assert captured.value.path == "$.observability"


def test_semantic_diagnostics_do_not_render_resource_credentials() -> None:
    canary = "Bearer super-secret-semantic-canary"
    source = {
        "config_version": 8,
        "observability": {"resource": {"attributes": {"service.note": canary}}},
    }
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)

    assert canary not in str(captured.value)
    assert captured.value.path == "$.observability.resource.attributes.service.note"


def test_masked_source_hides_inline_secrets_and_static_headers() -> None:
    source = """config_version: 8
llm:
  api_key: inline-llm-secret
  api_key_env: DEFENSECLAW_LLM_KEY
  extra_headers:
    Authorization: bearer-extra-header-secret
gateway:
  token: inline-gateway-token
  token_env: DEFENSECLAW_GATEWAY_TOKEN
observability:
  destinations:
    - name: otel
      kind: otlp
      endpoint: https://collector.example.test/v1/traces/path-secret-canary?access_token=query-secret#fragment-secret
      headers:
        Authorization: inline-header-secret
        X-Reference: {env: OTEL_HEADER_VALUE}
"""
    validated = load_validate_v8(source)
    masked = validated.masked
    destination = masked["observability"]["destinations"][0]

    assert masked["llm"]["api_key"] == "[REDACTED]"
    assert masked["llm"]["api_key_env"] == "DEFENSECLAW_LLM_KEY"
    assert masked["llm"]["extra_headers"]["Authorization"] == "[REDACTED]"
    assert masked["gateway"]["token"] == "[REDACTED]"
    assert masked["gateway"]["token_env"] == "DEFENSECLAW_GATEWAY_TOKEN"
    assert destination["headers"]["Authorization"] == "[REDACTED]"
    assert destination["headers"]["X-Reference"] == {"env": "OTEL_HEADER_VALUE"}
    assert destination["endpoint"] == "https://collector.example.test/[REDACTED]?[REDACTED]#[REDACTED]"
    rendered = validated.masked_json()
    assert "inline-llm-secret" not in rendered
    assert "inline-gateway-token" not in rendered
    assert "inline-header-secret" not in rendered
    assert "bearer-extra-header-secret" not in rendered
    assert "query-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "path-secret-canary" not in rendered


def test_returned_source_and_masked_views_are_detached() -> None:
    validated = load_validate_v8("config_version: 8\nobservability: {}\n")
    source = validated.source
    masked = validated.masked
    source["observability"]["mutated"] = True
    masked["observability"]["mutated"] = True

    assert validated.source == {"config_version": 8, "observability": {}}
    assert validated.masked == {"config_version": 8, "observability": {}}


def test_override_only_otlp_is_valid_but_missing_or_partial_endpoint_is_not() -> None:
    valid = """config_version: 8
observability:
  destinations:
    - name: traces
      kind: otlp
      protocol: http/protobuf
      signal_overrides:
        traces: {endpoint: https://traces.example.test/v1/traces}
      send:
        signals: [traces]
        buckets: [agent.lifecycle]
"""
    load_validate_v8(valid)

    missing = """config_version: 8
observability:
  destinations:
    - name: traces
      kind: otlp
      send: {signals: [traces], buckets: [agent.lifecycle]}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(missing)
    assert captured.value.path.endswith("signal_overrides.traces.endpoint")

    partial = """config_version: 8
observability:
  destinations:
    - name: mixed
      kind: otlp
      protocol: http/protobuf
      signal_overrides:
        traces: {endpoint: https://traces.example.test/v1/traces}
      send: {signals: [logs, traces], buckets: ['*']}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(partial)
    assert captured.value.path.endswith("signal_overrides.logs.endpoint")


def test_grpc_otlp_rejects_signal_path_override() -> None:
    source = """config_version: 8
observability:
  destinations:
    - name: logs
      kind: otlp
      protocol: grpc
      endpoint: collector.example.test:4317
      signal_overrides:
        logs: {path: /custom/logs}
      send: {signals: [logs], buckets: ['*']}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)
    assert captured.value.path.endswith("signal_overrides.logs.path")


def test_legacy_v7_profile_and_adapter_compatibility_fields_validate() -> None:
    source = """config_version: 8
observability:
  defaults: {redaction_profile: legacy-v7}
  destinations:
    - name: splunk
      kind: splunk_hec
      endpoint: https://splunk.example.test/services/collector/event
      token_env: SPLUNK_HEC_TOKEN
      sourcetype_overrides:
        llm-judge-response: defenseclaw:judge
        guardrail-verdict: defenseclaw:verdict
    - name: otel-logs
      kind: otlp
      endpoint: https://otel.example.test
      logger_name: defenseclaw.audit
      send: {signals: [logs], buckets: ['*']}
"""
    validated = load_validate_v8(source)

    assert validated.source["observability"]["defaults"]["redaction_profile"] == "legacy-v7"
    assert validated.source["observability"]["destinations"][1]["logger_name"] == "defenseclaw.audit"


@pytest.mark.parametrize(
    "profile",
    [
        "redaction_profiles: {legacy-v7: {extends: strict}}",
        "redaction_profiles: {compat: {extends: legacy-v7}}",
    ],
)
def test_legacy_v7_is_reserved_and_not_extendable(profile: str) -> None:
    with pytest.raises(V8ConfigError):
        load_validate_v8(f"config_version: 8\nobservability:\n  {profile}\n")


def test_logger_name_requires_selected_logs_and_is_otlp_only() -> None:
    no_logs = """config_version: 8
observability:
  destinations:
    - name: traces
      kind: otlp
      endpoint: https://otel.example.test
      logger_name: defenseclaw.audit
      send: {signals: [traces], buckets: ['*']}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(no_logs)
    assert captured.value.path.endswith("logger_name")

    wrong_kind = """config_version: 8
observability:
  destinations:
    - name: archive
      kind: http_jsonl
      endpoint: https://archive.example.test
      logger_name: defenseclaw.audit
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(wrong_kind)
    assert captured.value.keyword == "oneOf"


def test_compatibility_adapter_fields_enforce_utf8_byte_bounds() -> None:
    sourcetype = "é" * 129
    source = {
        "config_version": 8,
        "observability": {
            "destinations": [
                {
                    "name": "splunk",
                    "kind": "splunk_hec",
                    "endpoint": "https://splunk.example.test/services/collector/event",
                    "token_env": "SPLUNK_HEC_TOKEN",
                    "sourcetype_overrides": {"guardrail-verdict": sourcetype},
                }
            ]
        },
    }
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)
    assert captured.value.path.endswith("sourcetype_overrides.guardrail-verdict")

    source["observability"]["destinations"] = [
        {
            "name": "otel",
            "kind": "otlp",
            "endpoint": "https://otel.example.test",
            "logger_name": sourcetype,
        }
    ]
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)
    assert captured.value.path.endswith("logger_name")


@pytest.mark.parametrize(
    "endpoint,safety,valid",
    [
        ("https://collector.example.test/v1/logs", "", True),
        ("https://127.0.0.1:4318/v1/logs", "", False),
        (
            "https://127.0.0.1:4318/v1/logs",
            "network_safety: {allow_private_networks: true}",
            True,
        ),
        ("https://collector.localhost:4318/v1/logs", "", False),
        (
            "https://collector.localhost:4318/v1/logs",
            "network_safety: {allow_private_networks: true}",
            True,
        ),
        ("https://[::ffff:127.0.0.1]:4318/v1/logs", "", False),
        (
            "https://[::ffff:127.0.0.1]:4318/v1/logs",
            "network_safety: {allow_private_networks: true}",
            True,
        ),
        ("https://169.254.169.254/latest", "network_safety: {allow_private_networks: true}", False),
        ("https://[fd00:ec2::254]/latest", "network_safety: {allow_private_networks: true}", False),
        ("https://user:password@collector.example.test/v1/logs", "", False),
    ],
)
def test_push_endpoint_source_validation(endpoint: str, safety: str, valid: bool) -> None:
    source = f"""config_version: 8
observability:
  destinations:
    - name: archive
      kind: http_jsonl
      endpoint: {endpoint}
      {safety}
"""
    if valid:
        load_validate_v8(source)
    else:
        with pytest.raises(V8ConfigError):
            load_validate_v8(source)


@pytest.mark.parametrize(
    "listen",
    [
        "user@127.0.0.1:9464",
        "127.0.0.1:9464/metrics",
        "127.0.0.1:9464?query",
        "127.0.0.1:9464#fragment",
    ],
)
def test_prometheus_listener_rejects_url_components(listen: str) -> None:
    source = {
        "config_version": 8,
        "observability": {
            "destinations": [
                {
                    "name": "metrics",
                    "kind": "prometheus",
                    "listen": listen,
                    "path": "/metrics",
                }
            ]
        },
    }

    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)

    assert captured.value.path.endswith(".listen")


def test_duplicate_destination_and_route_names_are_rejected() -> None:
    duplicate_destination = """config_version: 8
observability:
  destinations:
    - {name: console, kind: console}
    - {name: console, kind: console}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(duplicate_destination)
    assert captured.value.path.endswith("destinations[1].name")

    duplicate_route = """config_version: 8
observability:
  destinations:
    - name: console
      kind: console
      routes:
        - {name: same, signals: [logs], selector: {}}
        - {name: same, signals: [logs], selector: {}}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(duplicate_route)
    assert captured.value.path.endswith("routes[1].name")


def test_profile_strength_and_trace_family_minimums_match_go() -> None:
    weak_profile = """config_version: 8
observability:
  redaction_profiles:
    weak:
      extends: sensitive
      field_classes: {content: preserve}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(weak_profile)
    assert captured.value.path.endswith("field_classes.content")

    low_limit = """config_version: 8
observability:
  trace_policy:
    limits: {max_attributes_per_span: 31}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(low_limit)
    assert captured.value.path.endswith("limits.max_attributes_per_span")


def test_unknown_profile_references_are_rejected_after_schema_validation() -> None:
    source = """config_version: 8
observability:
  buckets:
    model.io: {redaction_profile: undefined-profile}
"""
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(source)

    assert captured.value.path.endswith("buckets.model.io.redaction_profile")


def test_validate_v8_source_returns_masked_detached_source() -> None:
    source = "config_version: 8\nllm: {api_key: internal-only}\n"
    parsed = validate_v8_source(source)

    assert parsed["llm"]["api_key"] == "[REDACTED]"
    parsed["config_version"] = 7
    assert validate_v8_source(source)["config_version"] == 8
