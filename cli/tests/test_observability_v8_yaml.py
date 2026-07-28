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

import pytest
import yaml
from defenseclaw.observability.v8_yaml import (
    V8YAMLMutation,
    V8YAMLMutationError,
    prepare_v8_yaml_write,
)


def test_extreme_yaml_depth_is_rejected_before_recursion_escapes() -> None:
    source = "config_version: 8\nobservability:\n  future: " + "[" * 5_000 + "]" * 5_000 + "\n"
    with pytest.raises(V8YAMLMutationError) as captured:
        prepare_v8_yaml_write(source, [])
    assert captured.value.code == "source_too_complex"
    assert captured.value.__cause__ is None


def test_noop_is_byte_identical_with_comments_ascii_unicode_and_quotes() -> None:
    source = (
        "# ┌── OBSERVABILITY: collect → route ──┐\n"
        "config_version: 8\n"
        "name: café 🛡️ # before\n"
        "observability:\n"
        "  # keep inside\n"
        "  local: {path: '/tmp/audit.db', retention_days: 90} # inline\n"
        'after: "quoted" # after\n'
    ).encode()

    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 90)],
    )

    assert prepared.candidate == source
    assert prepared.changed is False
    assert prepared.expected_sha256 == hashlib.sha256(source).hexdigest()
    assert prepared.candidate_sha256 == prepared.expected_sha256


def test_block_scalar_patch_preserves_all_unrelated_text_and_quote_style() -> None:
    source = """# header
# ┌──── knobs ────┐
config_version: 8
before: keep # before observability
observability:
  # local explanation
  local:
    path: '/old path' # path comment
    retention_days: 90 # retained
  # route explanation
  destinations:
    - name: otel # destination name
      kind: otlp
      endpoint: "https://old.example.test" # endpoint comment
      routes:
        - name: findings # first route comment
          signals: [logs]
          selector: {buckets: [security.finding]}
after: keep # after observability
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(("observability", "local", "path"), "/new path"),
            V8YAMLMutation.set(("observability", "destinations", 0, "endpoint"), "https://new.example.test"),
        ],
    )
    candidate = prepared.candidate.decode()

    assert "path: '/new path' # path comment" in candidate
    assert 'endpoint: "https://new.example.test" # endpoint comment' in candidate
    for preserved in (
        "# header",
        "# ┌──── knobs ────┐",
        "before: keep # before observability",
        "# local explanation",
        "retention_days: 90 # retained",
        "# route explanation",
        "name: otel # destination name",
        "name: findings # first route comment",
        "selector: {buckets: [security.finding]}",
        "after: keep # after observability",
    ):
        assert preserved in candidate
    assert list(yaml.safe_load(candidate)) == ["config_version", "before", "observability", "after"]


def test_control_characters_are_safely_escaped_in_existing_quotes() -> None:
    source = 'config_version: 8\nobservability: {local: {path: "old"}}\n'
    value = "line one\nline two\t\u0001"
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "local", "path"), value)],
    )

    assert yaml.safe_load(prepared.candidate)["observability"]["local"]["path"] == value
    assert b"\\n" in prepared.candidate
    assert b"\\u0001" in prepared.candidate


def test_flow_style_patch_insert_and_delete_stays_flow_style() -> None:
    source = "config_version: 8\nobservability: {local: {path: '/old', retention_days: 90}, metric_policy: {temporality: delta}}\n"
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(("observability", "local", "path"), "/new"),
            V8YAMLMutation.set(("observability", "local", "judge_bodies_path"), "/judge.db"),
            V8YAMLMutation.delete(("observability", "local", "retention_days")),
        ],
    )
    candidate = prepared.candidate.decode()

    assert "local: {path: '/new', judge_bodies_path: /judge.db}" in candidate
    assert "metric_policy: {temporality: delta}" in candidate
    assert yaml.safe_load(candidate)["observability"]["local"] == {
        "path": "/new",
        "judge_bodies_path": "/judge.db",
    }


@pytest.mark.parametrize(
    "source",
    [
        (
            "config_version: 8\n"
            "observability: {local: {path: /audit.db,}, "
            "destinations: [{name: terminal, kind: console},]}\n"
        ),
        (
            "config_version: 8\n"
            "observability: {local: {path: /audit.db, # keep local note\n }, "
            "destinations: [{name: terminal, kind: console}, # keep destination note\n ]}\n"
        ),
    ],
)
def test_flow_insertions_reuse_existing_trailing_comma(source: str) -> None:
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(("observability", "local", "retention_days"), 30),
            V8YAMLMutation.set(
                ("observability", "destinations", 1),
                {"name": "archive", "kind": "jsonl", "path": "/tmp/archive.jsonl"},
            ),
        ],
    )
    candidate = prepared.candidate.decode()

    assert ",," not in candidate
    parsed = yaml.safe_load(candidate)["observability"]
    assert parsed["local"]["retention_days"] == 30
    assert [destination["name"] for destination in parsed["destinations"]] == [
        "terminal",
        "archive",
    ]


def test_insertion_builds_only_missing_observability_ancestors() -> None:
    source = "# existing header\nconfig_version: 8\nunrelated: {order: preserved}\n"
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "buckets", "model.io", "collect", "logs"), False)],
    )
    candidate = prepared.candidate.decode()

    assert candidate.startswith(source)
    assert "# existing header" in candidate
    assert yaml.safe_load(candidate)["observability"] == {"buckets": {"model.io": {"collect": {"logs": False}}}}


def test_block_deletion_does_not_touch_neighbor_comments_or_order() -> None:
    source = """config_version: 8
observability:
  local:
    path: /audit.db # remove with field
    # retention belongs to the next key
    retention_days: 90
  metric_policy:
    temporality: delta
"""
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.delete(("observability", "local", "path"))],
    )
    candidate = prepared.candidate.decode()

    assert "path:" not in candidate
    assert "# retention belongs to the next key" in candidate
    assert candidate.index("local:") < candidate.index("metric_policy:")
    assert yaml.safe_load(candidate)["observability"]["local"] == {"retention_days": 90}


def test_block_insertion_uses_parent_indent_and_preserves_following_sibling() -> None:
    source = """config_version: 8
observability:
  local:
    path: /audit.db
  metric_policy: # following sibling
    temporality: delta
"""
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.set(("observability", "local", "judge_bodies_path"), "/judge.db")],
    )
    candidate = prepared.candidate.decode()

    assert "    judge_bodies_path: /judge.db\n  metric_policy: # following sibling" in candidate
    assert yaml.safe_load(candidate)["observability"]["local"]["judge_bodies_path"] == "/judge.db"


def test_block_sequence_replacement_keeps_existing_indent() -> None:
    source = """config_version: 8
observability:
  redaction_profiles:
    soc:
      extends: sensitive
      detectors:
        - pii
        - credentials
      # comment belongs to following field
      field_classes: # following field
        content: detect
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.set(
                ("observability", "redaction_profiles", "soc", "detectors"),
                ["pii", "credentials", "secrets"],
            )
        ],
    )
    candidate = prepared.candidate.decode()

    assert (
        "      detectors:\n        - pii\n        - credentials\n        - secrets\n"
        "      # comment belongs to following field\n      field_classes:" in candidate
    )
    assert yaml.safe_load(candidate)["observability"]["redaction_profiles"]["soc"]["detectors"] == [
        "pii",
        "credentials",
        "secrets",
    ]


def test_deleting_last_block_entries_leaves_typed_empty_containers() -> None:
    source = """config_version: 8
observability:
  buckets:
    model.io:
      collect: {logs: false}
  destinations:
    - name: only
      kind: console
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.delete(("observability", "buckets", "model.io")),
            V8YAMLMutation.delete(("observability", "destinations", 0)),
        ],
    )

    observability = yaml.safe_load(prepared.candidate)["observability"]
    assert observability["buckets"] == {}
    assert observability["destinations"] == []
    assert "buckets:\n    {}" in prepared.candidate.decode()
    assert "destinations:\n    []" in prepared.candidate.decode()


def test_destination_append_and_delete_preserve_other_item_comments() -> None:
    source = """config_version: 8
observability:
  destinations:
    - name: first # keep first comment
      kind: console
    - name: removed # removed comment
      kind: console
  # comment belongs to local
  local:
    retention_days: 90 # keep after list
"""
    prepared = prepare_v8_yaml_write(
        source,
        [
            V8YAMLMutation.delete(("observability", "destinations", 1)),
            V8YAMLMutation.set(
                ("observability", "destinations", 1),
                {"name": "archive", "kind": "jsonl", "path": "/tmp/日本語.jsonl"},
            ),
        ],
    )
    candidate = prepared.candidate.decode()
    destinations = yaml.safe_load(candidate)["observability"]["destinations"]

    assert [item["name"] for item in destinations] == ["first", "archive"]
    assert "# keep first comment" in candidate
    assert "# removed comment" not in candidate
    assert "\n    - name: archive\n" in candidate
    assert "  # comment belongs to local\n  local:" in candidate
    assert "retention_days: 90 # keep after list" in candidate
    assert "/tmp/日本語.jsonl" in candidate


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_newline_mode_is_preserved_for_insertions(newline: str) -> None:
    source = newline.join(
        [
            "config_version: 8",
            "observability:",
            "  local:",
            "    path: /audit.db",
            "  metric_policy:",
            "    temporality: delta",
            "",
        ]
    )
    prepared = prepare_v8_yaml_write(
        source.encode(),
        [V8YAMLMutation.set(("observability", "local", "retention_days"), 0)],
    )
    candidate = prepared.candidate.decode()

    assert prepared.newline == newline
    if newline == "\r\n":
        assert "\n" not in candidate.replace("\r\n", "")
    assert yaml.safe_load(candidate)["observability"]["local"]["retention_days"] == 0


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("config_version: 8\nobservability: {}\nobservability: {}\n", "duplicate_mapping_key"),
        ("config_version: 8\nbase: &base {local: {}}\nobservability: *base\n", "yaml_alias_forbidden"),
        ("config_version: 8\nbase: &base {local: {}}\nobservability:\n  <<: *base\n", "yaml_alias_forbidden"),
        ("config_version: 8\nobservability: [unterminated\n", "invalid_yaml"),
    ],
)
def test_unsafe_or_invalid_yaml_is_rejected_without_echoing_values(source: str, code: str) -> None:
    hidden = "DO-NOT-ECHO-SECRET"
    source += f"# {hidden}\n"
    with pytest.raises(V8YAMLMutationError) as caught:
        prepare_v8_yaml_write(source, [])

    assert caught.value.code == code
    assert hidden not in str(caught.value)


def test_merge_key_without_alias_is_rejected() -> None:
    source = "config_version: 8\nobservability:\n  <<: {local: {}}\n"
    with pytest.raises(V8YAMLMutationError, match="merge keys") as caught:
        prepare_v8_yaml_write(source, [])
    assert caught.value.code == "yaml_merge_forbidden"


def test_non_v8_and_unsupported_paths_fail_without_mutation_values_in_error() -> None:
    with pytest.raises(V8YAMLMutationError) as wrong_version:
        prepare_v8_yaml_write("config_version: 7\nobservability: {}\n", [])
    assert wrong_version.value.code == "not_v8_configuration"

    hidden = "DO-NOT-ECHO-SECRET"
    with pytest.raises(V8YAMLMutationError) as unsupported:
        prepare_v8_yaml_write(
            "config_version: 8\nobservability: {}\n",
            [V8YAMLMutation.set(("observability", "unknown"), hidden)],
        )
    assert unsupported.value.code == "unsupported_mutation_path"
    assert hidden not in str(unsupported.value)


def test_prepared_write_is_deterministic_and_repr_is_content_safe() -> None:
    source = "config_version: 8\nobservability: {}\nsecret_elsewhere: do-not-print\n"
    mutation = V8YAMLMutation.set(("observability", "local", "retention_days"), 30)
    first = prepare_v8_yaml_write(source, [mutation], source_name="config.yaml")
    second = prepare_v8_yaml_write(source, [mutation], source_name="config.yaml")

    assert first == second
    assert first.changed is True
    assert first.expected_sha256 == hashlib.sha256(source.encode()).hexdigest()
    assert first.candidate_sha256 == hashlib.sha256(first.candidate).hexdigest()
    assert "do-not-print" not in repr(first)
    assert "30" not in repr(mutation)


def test_sequence_insertion_must_be_contiguous() -> None:
    source = "config_version: 8\nobservability: {destinations: []}\n"
    with pytest.raises(V8YAMLMutationError) as caught:
        prepare_v8_yaml_write(
            source,
            [V8YAMLMutation.set(("observability", "destinations", 2), {"name": "later", "kind": "console"})],
        )
    assert caught.value.code == "unreachable_mutation_path"


def test_destination_signal_override_can_be_removed_as_one_policy_unit() -> None:
    source = """config_version: 8
observability:
  destinations:
    - name: collector
      kind: otlp
      endpoint: collector.example.test:4317
      signal_overrides:
        traces: {path: /v1/traces}
        logs: {path: /v1/logs}
      send: {signals: [logs], buckets: ['*'], redaction_profile: none}
"""
    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.delete(("observability", "destinations", 0, "signal_overrides", "traces"))],
    )
    destination = yaml.safe_load(prepared.candidate)["observability"]["destinations"][0]
    assert destination["signal_overrides"] == {"logs": {"path": "/v1/logs"}}


def test_destination_send_can_be_removed_without_touching_comments_or_sibling_policy() -> None:
    source = """config_version: 8
observability:
  destinations:
    - name: galileo
      kind: otlp
      preset: galileo
      endpoint: https://api.galileo.ai/otel/traces
      protocol: http/protobuf
      # Keep the operator's batching note.
      batch: {scheduled_delay_ms: 1000}
      headers:
        Galileo-API-Key: {env: GALILEO_API_KEY}
        project: project
        logstream: stream
      send: {signals: [traces], buckets: ['*'], redaction_profile: none}
"""

    prepared = prepare_v8_yaml_write(
        source,
        [V8YAMLMutation.delete(("observability", "destinations", 0, "send"))],
    )

    rendered = prepared.candidate.decode("utf-8")
    destination = yaml.safe_load(rendered)["observability"]["destinations"][0]
    assert "send" not in destination
    assert destination["batch"] == {"scheduled_delay_ms": 1000}
    assert destination["headers"]["project"] == "project"
    assert "# Keep the operator's batching note." in rendered


def test_candidate_exceeding_source_limit_is_rejected() -> None:
    source = "config_version: 8\nobservability: {}\n"
    oversized = "x" * 4_194_304
    with pytest.raises(V8YAMLMutationError) as caught:
        prepare_v8_yaml_write(
            source,
            [V8YAMLMutation.set(("observability", "local", "path"), oversized)],
        )

    assert caught.value.code == "source_too_large"
    assert oversized[:100] not in str(caught.value)


@pytest.mark.parametrize(
    ("source", "mutation", "expected"),
    [
        (
            "config_version: 8\nobservability: {local: {path: /audit.db, # keep note\n retention_days: 90}}\n",
            V8YAMLMutation.delete(("observability", "local", "retention_days")),
            {"path": "/audit.db"},
        ),
        (
            "config_version: 8\n"
            "observability: {destinations: [{name: one, kind: console}, # keep note\n"
            " {name: two, kind: console}]}\n",
            V8YAMLMutation.delete(("observability", "destinations", 1)),
            [{"name": "one", "kind": "console"}],
        ),
    ],
)
def test_flow_delete_after_commented_separator_preserves_valid_yaml(
    source: str,
    mutation: V8YAMLMutation,
    expected: object,
) -> None:
    prepared = prepare_v8_yaml_write(source, [mutation])
    candidate = prepared.candidate.decode()

    assert "# keep note" in candidate
    parsed = yaml.safe_load(candidate)["observability"]
    actual = parsed["local"] if "local" in parsed else parsed["destinations"]
    assert actual == expected
