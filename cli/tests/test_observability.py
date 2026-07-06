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

"""Tests for the observability preset registry, writer, and CLI.

Covers:
* Shape of every preset (id/target/secret metadata consistent).
* Writer round-trip for each preset kind — YAML merges, secrets land in
  .env, preset identity stamps are applied to otel.resource.attributes.
* audit_sinks preservation across writes (the bug that motivated the
  writer living outside of Config.save()).
* CLI flag matrix for `defenseclaw setup observability add` across the
  three probe paths (otel / splunk_hec / http_jsonl).
* Migration idempotency — running `migrate-splunk --apply` twice on the
  same legacy config must not duplicate audit_sinks entries.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_observability import observability as observability_cmd
from defenseclaw.context import AppContext
from defenseclaw.observability import (
    PRESETS,
    apply_preset,
    list_destinations,
    migrate_flat_otel,
    preset_choices,
    remove_destination,
    resolve_preset,
    set_destination_enabled,
)
from defenseclaw.observability.display import redact_endpoint_for_display
from defenseclaw.observability.presets import Preset
from defenseclaw.tui.panels.setup import OBSERVABILITY_PRESETS

# ---------------------------------------------------------------------------
# flat OTel migration
# ---------------------------------------------------------------------------


def test_flat_otel_migration_is_previewable_applied_once_and_idempotent() -> None:
    _, tmp = _make_tmp_ctx()
    cfg_path = os.path.join(tmp, "config.yaml")
    with open(cfg_path, "w") as handle:
        handle.write(
            "otel:\n"
            "  enabled: true\n"
            "  protocol: grpc\n"
            "  endpoint: 127.0.0.1:4317\n"
            "  traces: {enabled: true}\n"
        )

    preview = migrate_flat_otel(tmp)
    assert preview.yaml_changes
    assert "destinations" not in _read_yaml(tmp)["otel"]

    applied = migrate_flat_otel(tmp, dry_run=False)
    assert applied.name == "local-observability"
    otel = _read_yaml(tmp)["otel"]
    assert otel["destinations"][0]["endpoint"] == "127.0.0.1:4317"
    assert "endpoint" not in otel
    assert os.path.exists(cfg_path + ".pre-observability-migration.bak")

    repeated = migrate_flat_otel(tmp, dry_run=False)
    assert repeated.yaml_changes == []


def test_flat_otel_migration_advances_only_explicit_v6_schema_stamp() -> None:
    _, tmp = _make_tmp_ctx()
    cfg_path = os.path.join(tmp, "config.yaml")
    with open(cfg_path, "w") as handle:
        handle.write(
            "config_version: 6\n"
            "otel:\n"
            "  enabled: true\n"
            "  endpoint: 127.0.0.1:4317\n"
        )

    migrate_flat_otel(tmp, dry_run=False)
    assert _read_yaml(tmp)["config_version"] == 7

    # A missing stamp may represent any historical schema. Preserve it so the
    # Go loader still runs unrelated pre-v6 compatibility migrations.
    with open(cfg_path, "w") as handle:
        handle.write(
            "otel:\n"
            "  enabled: true\n"
            "  endpoint: 127.0.0.1:4317\n"
        )
    migrate_flat_otel(tmp, dry_run=False)
    assert "config_version" not in _read_yaml(tmp)


def test_flat_otel_global_endpoint_enables_all_signals() -> None:
    _, tmp = _make_tmp_ctx()
    with open(os.path.join(tmp, "config.yaml"), "w") as handle:
        handle.write("otel:\n  enabled: true\n  endpoint: 127.0.0.1:4317\n")

    migrate_flat_otel(tmp, dry_run=False)
    destination = _read_yaml(tmp)["otel"]["destinations"][0]
    assert all(destination[signal]["enabled"] for signal in ("traces", "metrics", "logs"))


def test_observability_endpoint_display_redacts_credentials() -> None:
    endpoint = "https://alice:secret@collector.example.test/token/path?api_key=secret#fragment"
    assert redact_endpoint_for_display(endpoint) == "https://collector.example.test/token/path"
    assert redact_endpoint_for_display(endpoint, hide_path=True) == "https://collector.example.test/…"


def test_flat_otel_signal_environment_migrates_only_matching_signal() -> None:
    _, tmp = _make_tmp_ctx()
    with open(os.path.join(tmp, "config.yaml"), "w") as handle:
        handle.write("otel:\n  enabled: true\n")
    environment = {
        "DEFENSECLAW_OTEL_ENDPOINT": "",
        "DEFENSECLAW_OTEL_TRACES_ENDPOINT": "",
        "DEFENSECLAW_OTEL_LOGS_ENDPOINT": "http://127.0.0.1:4318/v1/logs",
        "DEFENSECLAW_OTEL_LOGS_PROTOCOL": "http/protobuf",
        "DEFENSECLAW_OTEL_METRICS_ENDPOINT": "",
    }
    with patch.dict(os.environ, environment, clear=False):
        migrate_flat_otel(tmp, dry_run=False)
    destination = _read_yaml(tmp)["otel"]["destinations"][0]
    assert destination["logs"] == {
        "enabled": True,
        "endpoint": "http://127.0.0.1:4318/v1/logs",
        "protocol": "http/protobuf",
    }
    assert destination["traces"].get("enabled") is not True
    assert destination["metrics"].get("enabled") is not True


def _make_tmp_ctx() -> tuple[AppContext, str]:
    """Build a minimal AppContext pointing at a fresh temp data dir.

    We bypass ``helpers.make_temp_config`` because the observability
    tests only need ``cfg.data_dir`` — wiring the full config ties the
    tests to unrelated dataclass fields that churn over time.
    """
    tmp = tempfile.mkdtemp(prefix="dclaw-obs-test-")
    # Minimal config.yaml so writer's _load_yaml returns a dict.
    cfg_path = os.path.join(tmp, "config.yaml")
    with open(cfg_path, "w") as f:
        f.write("claw:\n  mode: openclaw\n")
    # Lazy import to avoid a circular: cmd_setup_observability depends
    # on config which depends on... etc. Loading the real cfg via
    # config.load() is more faithful than hand-building one.
    from defenseclaw import config as cfg_mod

    os.environ["DEFENSECLAW_HOME"] = tmp
    app = AppContext()
    app.cfg = cfg_mod.load()
    return app, tmp


def _read_yaml(tmp: str) -> dict:
    with open(os.path.join(tmp, "config.yaml")) as f:
        return yaml.safe_load(f) or {}


def _read_dotenv(tmp: str) -> dict[str, str]:
    """Best-effort .env reader. Returns {} if the file is missing."""
    path = os.path.join(tmp, ".env")
    out: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out


class _FakeHTTPResponse:
    def __init__(self, status: int = 200, reason: str = "OK") -> None:
        self.status = status
        self.reason = reason

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


# ---------------------------------------------------------------------------
# Preset registry shape
# ---------------------------------------------------------------------------


class PresetRegistryTests(unittest.TestCase):
    """Lightweight sanity checks on the declarative preset list.

    These stop us from shipping a preset that the writer can't
    consume (e.g. target=audit_sinks without sink_kind, or a secret
    prompt without a token_env).
    """

    EXPECTED_PRESET_IDS = {
        "splunk-o11y",
        "splunk-hec",
        "splunk-enterprise",
        "datadog",
        "honeycomb",
        "newrelic",
        "grafana-cloud",
        "galileo",
        "local-otlp",
        "otlp",
        "webhook",
    }

    def test_expected_presets_present(self) -> None:
        self.assertEqual(set(PRESETS.keys()), self.EXPECTED_PRESET_IDS)
        self.assertEqual(set(preset_choices()), self.EXPECTED_PRESET_IDS)

    def test_resolve_preset_accepts_canonical_id(self) -> None:
        # The Click choice handler uses case_sensitive=False, so the
        # upper-case path goes through Click's normalizer before
        # landing here. Confirm the canonical (lower-case) id works
        # and that an unknown id raises a helpful error.
        self.assertIs(resolve_preset("datadog"), PRESETS["datadog"])
        with self.assertRaisesRegex(ValueError, "unknown preset"):
            resolve_preset("not-a-real-preset")

    def test_preset_invariants(self) -> None:
        for pid, preset in PRESETS.items():
            with self.subTest(preset=pid):
                self.assertIsInstance(preset, Preset)
                self.assertIn(preset.target, ("otel", "audit_sinks"))
                if preset.target == "otel":
                    # OTel presets must declare at least one default
                    # signal — otherwise the writer would produce an
                    # exporter that exports nothing.
                    self.assertTrue(preset.default_signals, preset.id)
                else:
                    # Audit-sink presets must name their kind so the
                    # writer can map to the right Go-side struct.
                    self.assertIn(preset.sink_kind, ("splunk_hec", "otlp_logs", "http_jsonl"))

    def test_tui_preset_list_matches_python(self) -> None:
        """The current Python TUI preset menu must mirror the registry."""
        tui_ids = tuple(preset_id for preset_id, _label in OBSERVABILITY_PRESETS)
        self.assertEqual(tui_ids, tuple(preset_choices()))


# ---------------------------------------------------------------------------
# Writer round-trip — one test per *target* class
# ---------------------------------------------------------------------------


class WriterOTelPresetTests(unittest.TestCase):
    """apply_preset() for target=otel presets."""

    def tearDown(self) -> None:
        os.environ.pop("DEFENSECLAW_HOME", None)

    def test_protocol_precedence_and_persistence(self) -> None:
        cases = (
            ("grpc", "http", "http"),
            ("http", "grpc", "grpc"),
            ("http", None, "http"),
            ("", None, "grpc"),
        )
        for preset_protocol, explicit_protocol, expected in cases:
            with self.subTest(
                preset_protocol=preset_protocol,
                explicit_protocol=explicit_protocol,
            ):
                _, tmp = _make_tmp_ctx()
                preset_id = "protocol-precedence"
                preset = Preset(
                    id=preset_id,
                    display_name="Protocol precedence",
                    target="otel",
                    description="test preset",
                    otel_protocol=preset_protocol,
                    endpoint_template="{endpoint}",
                    signal_url_paths={
                        "traces": "/v1/traces",
                        "metrics": "/v1/metrics",
                        "logs": "/v1/logs",
                    },
                    prompts=(
                        ("endpoint", "collector.example.test:4317", "endpoint", ""),
                        ("protocol", "grpc", "protocol", "grpc"),
                    ),
                )
                inputs = {"endpoint": "collector.example.test:4317"}
                if explicit_protocol is not None:
                    inputs["protocol"] = explicit_protocol
                with patch.dict(PRESETS, {preset_id: preset}):
                    apply_preset(preset_id, inputs, tmp)

                destination = _read_yaml(tmp)["otel"]["destinations"][0]
                self.assertEqual(destination["protocol"], expected)
                for signal in ("traces", "metrics", "logs"):
                    self.assertEqual(destination[signal]["protocol"], expected)
                    self.assertEqual(destination[signal]["url_path"], f"/v1/{signal}")
                self.assertEqual(list_destinations(tmp)[0].protocol, expected)

    def test_protocol_boundary_normalizes_case_and_rejects_invalid_without_write(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "otlp",
            {"endpoint": "collector.example.test:4317", "protocol": " HTTP "},
            tmp,
            name="collector",
        )
        self.assertEqual(list_destinations(tmp)[0].protocol, "http")
        before = _read_yaml(tmp)

        for invalid in ("http/protobuf", "udp", "   "):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "must be grpc or http"):
                    apply_preset(
                        "otlp",
                        {"endpoint": "replacement.example.test:4317", "protocol": invalid},
                        tmp,
                        name="collector",
                    )
                self.assertEqual(_read_yaml(tmp), before)

        with self.assertRaisesRegex(ValueError, "must be grpc or http"):
            apply_preset(
                "otlp",
                {"endpoint": "replacement.example.test:4317", "protocol": "udp"},
                tmp,
                name="audit-copy",
                target_override="audit_sinks",
            )
        self.assertEqual(_read_yaml(tmp), before)

        secret_preset = Preset(
            id="invalid-protocol-secret",
            display_name="Invalid protocol secret",
            target="otel",
            description="test preset",
            otel_protocol="grpc",
            endpoint_template="{endpoint}",
            token_env="TEST_OTLP_TOKEN",
            prompts=(("endpoint", "collector.example.test:4317", "endpoint", ""),),
        )
        with patch.dict(PRESETS, {secret_preset.id: secret_preset}):
            with self.assertRaisesRegex(ValueError, "must be grpc or http"):
                apply_preset(
                    secret_preset.id,
                    {"endpoint": "replacement.example.test:4317", "protocol": "udp"},
                    tmp,
                    name="collector",
                    secret_value="test-value",
                )
        self.assertEqual(_read_yaml(tmp), before)
        self.assertFalse(os.path.exists(os.path.join(tmp, ".env")))

        apply_preset(
            "otlp",
            {"endpoint": "collector.example.test:4317", "protocol": ""},
            tmp,
            name="collector",
        )
        self.assertEqual(list_destinations(tmp)[0].protocol, "grpc")

    def test_datadog_roundtrip_creates_named_destination(self) -> None:
        _, tmp = _make_tmp_ctx()
        result = apply_preset(
            "datadog",
            {"site": "us5"},
            tmp,
            signals=("traces", "metrics"),
            secret_value="dd-key-abc",
        )

        self.assertFalse(result.dry_run)
        self.assertEqual(result.target, "otel")

        doc = _read_yaml(tmp)
        otel = doc.get("otel") or {}
        self.assertTrue(otel.get("enabled"))
        destinations = otel.get("destinations") or []
        self.assertEqual(len(destinations), 1)
        datadog = destinations[0]
        self.assertEqual(datadog.get("name"), "datadog")
        self.assertEqual(datadog.get("preset"), "datadog")
        self.assertIn("datadoghq.com", str(datadog.get("endpoint", "")))
        self.assertTrue((datadog.get("traces") or {}).get("enabled"))
        self.assertTrue((datadog.get("metrics") or {}).get("enabled"))
        self.assertFalse((datadog.get("logs") or {}).get("enabled"))

        dotenv = _read_dotenv(tmp)
        self.assertEqual(dotenv.get(PRESETS["datadog"].token_env), "dd-key-abc")

    def test_local_otlp_marks_collector_transport_insecure(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "local-otlp",
            {"endpoint": "127.0.0.1:4317"},
            tmp,
        )

        doc = _read_yaml(tmp)
        otel = doc.get("otel") or {}
        local = (otel.get("destinations") or [])[0]
        self.assertTrue((local.get("tls") or {}).get("insecure"))
        self.assertEqual(local.get("protocol"), "grpc")
        self.assertEqual(local.get("endpoint"), "127.0.0.1:4317")

    def test_local_and_galileo_coexist_with_secret_reference(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset("local-otlp", {"endpoint": "127.0.0.1:4317"}, tmp)
        apply_preset(
            "galileo",
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "defenseclaw-tests",
                "logstream": "default",
            },
            tmp,
            secret_value="galileo-test-key",
        )

        doc = _read_yaml(tmp)
        destinations = (doc.get("otel") or {}).get("destinations") or []
        self.assertEqual([d.get("name") for d in destinations], ["local-observability", "galileo"])
        galileo = destinations[1]
        self.assertEqual(galileo.get("endpoint"), "https://api.galileo.ai/otel/traces")
        self.assertNotIn("url_path", galileo.get("traces") or {})
        self.assertTrue((galileo.get("traces") or {}).get("enabled"))
        self.assertFalse((galileo.get("metrics") or {}).get("enabled"))
        self.assertFalse((galileo.get("logs") or {}).get("enabled"))
        self.assertEqual(galileo["headers"]["Galileo-API-Key"], "${GALILEO_API_KEY}")
        self.assertEqual(galileo["headers"]["project"], "defenseclaw-tests")
        self.assertEqual(galileo["headers"]["logstream"], "default")
        self.assertEqual(
            galileo["span_filter"],
            {
                "operations": [
                    {
                        "name": "chat",
                        "require_attributes": [
                            "gen_ai.operation.name",
                            "gen_ai.provider.name",
                            "gen_ai.request.model",
                            "gen_ai.input.messages",
                            "gen_ai.output.messages",
                        ],
                    },
                    {
                        "name": "invoke_agent",
                        "require_attributes": [
                            "gen_ai.operation.name",
                            "gen_ai.agent.name",
                            "gen_ai.provider.name",
                            "openinference.span.kind",
                            "gen_ai.input.messages",
                            "gen_ai.output.messages",
                        ],
                    },
                    {
                        "name": "execute_tool",
                        "require_attributes": [
                            "gen_ai.operation.name",
                            "gen_ai.tool.name",
                            "openinference.span.kind",
                            "gen_ai.tool.call.arguments",
                            "gen_ai.tool.call.result",
                            "gen_ai.input.messages",
                            "gen_ai.output.messages",
                        ],
                    },
                ],
            },
        )
        self.assertEqual(_read_dotenv(tmp)["GALILEO_API_KEY"], "galileo-test-key")

    def test_adding_disabled_route_does_not_disable_existing_routes(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset("local-otlp", {"endpoint": "127.0.0.1:4317"}, tmp)
        apply_preset(
            "galileo",
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "defenseclaw-tests",
                "logstream": "default",
            },
            tmp,
            enabled=False,
            secret_value="galileo-test-key",
        )

        otel = _read_yaml(tmp)["otel"]
        self.assertTrue(otel["enabled"])
        destinations = {item["name"]: item for item in otel["destinations"]}
        self.assertTrue(destinations["local-observability"]["enabled"])
        self.assertFalse(destinations["galileo"]["enabled"])

    def test_adding_galileo_migrates_legacy_flat_exporter_without_loss(self) -> None:
        _, tmp = _make_tmp_ctx()
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            handle.write(
                textwrap.dedent(
                    """
                    otel:
                      enabled: true
                      protocol: grpc
                      endpoint: 127.0.0.1:4317
                      tls: {insecure: true}
                      traces: {enabled: true, sampler: always_on, sampler_arg: "1.0"}
                      metrics: {enabled: true, export_interval_s: 30}
                      logs: {enabled: true, emit_individual_findings: true}
                      resource:
                        attributes:
                          defenseclaw.preset: local-otlp
                          service.name: defenseclaw
                    """
                )
            )

        result = apply_preset(
            "galileo",
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "defenseclaw-tests",
                "logstream": "default",
            },
            tmp,
            secret_value="galileo-test-key",
        )

        assert any("migrated flat OTel exporter" in warning for warning in result.warnings)
        otel = _read_yaml(tmp)["otel"]
        assert [d["name"] for d in otel["destinations"]] == ["local-otlp", "galileo"]
        migrated = otel["destinations"][0]
        assert migrated["endpoint"] == "127.0.0.1:4317"
        assert migrated["tls"]["insecure"] is True
        assert migrated["traces"]["enabled"] is True
        assert migrated["metrics"]["enabled"] is True
        assert migrated["logs"]["enabled"] is True
        assert otel["traces"]["sampler"] == "always_on"
        assert otel["logs"]["emit_individual_findings"] is True
        backup = os.path.join(tmp, "config.yaml.pre-observability-migration.bak")
        assert os.path.exists(backup)
        with open(backup) as handle:
            backup_doc = yaml.safe_load(handle) or {}
        assert "destinations" not in (backup_doc.get("otel") or {})

    def test_adding_galileo_migrates_environment_backed_flat_exporter(self) -> None:
        _, tmp = _make_tmp_ctx()
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            handle.write("otel:\n  enabled: true\n")
        with patch.dict(
            os.environ,
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
                "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            },
            clear=False,
        ):
            apply_preset(
                "galileo",
                {
                    "endpoint": "https://api.galileo.ai/otel/traces",
                    "project": "defenseclaw-tests",
                    "logstream": "default",
                },
                tmp,
                secret_value="galileo-test-key",
            )

        destinations = _read_yaml(tmp)["otel"]["destinations"]
        assert [item["name"] for item in destinations] == ["generic-otlp", "galileo"]
        assert destinations[0]["endpoint"] == "http://127.0.0.1:4318"
        assert destinations[0]["protocol"] == "http/protobuf"
        assert all(destinations[0][signal]["enabled"] for signal in ("traces", "metrics", "logs"))

    def test_adding_galileo_migrates_defenseclaw_env_backed_flat_exporter(self) -> None:
        _, tmp = _make_tmp_ctx()
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            handle.write("otel:\n  enabled: true\n")
        with patch.dict(
            os.environ,
            {
                "DEFENSECLAW_OTEL_ENDPOINT": "http://127.0.0.1:4318",
                "DEFENSECLAW_OTEL_PROTOCOL": "http/protobuf",
                "DEFENSECLAW_OTEL_TLS_INSECURE": "true",
            },
            clear=False,
        ):
            apply_preset(
                "galileo",
                {
                    "endpoint": "https://api.galileo.ai/otel/traces",
                    "project": "defenseclaw-tests",
                    "logstream": "default",
                },
                tmp,
                secret_value="galileo-test-key",
            )

        destinations = _read_yaml(tmp)["otel"]["destinations"]
        assert [item["name"] for item in destinations] == ["generic-otlp", "galileo"]
        assert destinations[0]["endpoint"] == "http://127.0.0.1:4318"
        assert destinations[0]["protocol"] == "http/protobuf"
        assert destinations[0]["tls"]["insecure"] is True
        assert all(destinations[0][signal]["enabled"] for signal in ("traces", "metrics", "logs"))

    def test_rerun_repairs_mixed_flat_and_named_destination_shape(self) -> None:
        _, tmp = _make_tmp_ctx()
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            handle.write(
                textwrap.dedent(
                    """
                    otel:
                      enabled: true
                      protocol: grpc
                      headers: {X-Local-Metadata: preserved}
                      traces:
                        enabled: true
                        sampler: always_on
                        endpoint: 127.0.0.1:4317
                      metrics: {enabled: true, endpoint: 127.0.0.1:4317}
                      logs: {enabled: true, endpoint: 127.0.0.1:4317}
                      destinations:
                        - name: galileo
                          preset: galileo
                          enabled: true
                          protocol: http
                          endpoint: https://api.galileo.ai/otel/traces
                          traces: {enabled: true}
                          metrics: {enabled: false}
                          logs: {enabled: false}
                    """
                )
            )

        result = apply_preset(
            "galileo",
            {"endpoint": "https://api.galileo.ai/otel/traces", "project": "p", "logstream": "l"},
            tmp,
            secret_value="key",
        )
        assert any("migrated flat OTel exporter" in warning for warning in result.warnings)
        otel = _read_yaml(tmp)["otel"]
        assert [item["name"] for item in otel["destinations"]] == [
            "local-observability",
            "galileo",
        ]
        assert otel["destinations"][0]["preset"] == "local-otlp"
        assert otel["destinations"][0]["headers"] == {"X-Local-Metadata": "preserved"}
        assert otel["destinations"][0]["traces"]["endpoint"] == "127.0.0.1:4317"
        assert "endpoint" not in otel["traces"]
        assert "headers" not in otel

    def test_updating_galileo_preserves_operator_owned_fields(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "galileo",
            {"endpoint": "https://api.galileo.ai/otel/traces", "project": "p", "logstream": "l"},
            tmp,
            secret_value="key",
        )
        raw = _read_yaml(tmp)
        destination = raw["otel"]["destinations"][0]
        destination["tls"] = {"ca_cert": "/etc/galileo-ca.pem"}
        destination["batch"] = {"scheduled_delay_ms": 250}
        destination["headers"]["X-Tenant-Region"] = "east"
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            yaml.safe_dump(raw, handle)

        apply_preset(
            "galileo",
            {"endpoint": "https://api.galileo.ai/otel/traces", "project": "p2", "logstream": "l2"},
            tmp,
        )
        updated = _read_yaml(tmp)["otel"]["destinations"][0]
        assert updated["tls"] == {"ca_cert": "/etc/galileo-ca.pem"}
        assert updated["batch"] == {"scheduled_delay_ms": 250}
        assert updated["headers"]["X-Tenant-Region"] == "east"
        assert updated["headers"]["project"] == "p2"

    def test_updating_galileo_upgrades_legacy_batch_delay_to_realtime_default(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "galileo",
            {"endpoint": "https://api.galileo.ai/otel/traces", "project": "p", "logstream": "l"},
            tmp,
            secret_value="key",
        )
        raw = _read_yaml(tmp)
        raw["otel"]["destinations"][0]["batch"] = {
            "max_export_batch_size": 512,
            "scheduled_delay_ms": 5000,
            "max_queue_size": 2048,
        }
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            yaml.safe_dump(raw, handle)

        apply_preset(
            "galileo",
            {"endpoint": "https://api.galileo.ai/otel/traces", "project": "p", "logstream": "l"},
            tmp,
        )
        batch = _read_yaml(tmp)["otel"]["destinations"][0]["batch"]
        assert batch == {
            "max_export_batch_size": 512,
            "scheduled_delay_ms": 1000,
            "max_queue_size": 2048,
        }

    def test_shared_galileo_writer_rejects_environment_header_expansion(self) -> None:
        _, tmp = _make_tmp_ctx()
        with self.assertRaisesRegex(ValueError, "must not contain"):
            apply_preset(
                "galileo",
                {
                    "endpoint": "https://api.galileo.ai/otel/traces",
                    "project": "${HOME}",
                    "logstream": "default",
                },
                tmp,
                secret_value="key",
            )

    def test_removing_final_named_destination_disables_root_otel(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "galileo",
            {"endpoint": "https://api.galileo.ai/otel/traces", "project": "p", "logstream": "l"},
            tmp,
            secret_value="key",
        )
        remove_destination("galileo", tmp)
        otel = _read_yaml(tmp)["otel"]
        assert otel["destinations"] == []
        assert otel["enabled"] is False

    def test_dry_run_does_not_write(self) -> None:
        _, tmp = _make_tmp_ctx()
        before = _read_yaml(tmp)
        result = apply_preset(
            "honeycomb",
            {"dataset": "defenseclaw"},
            tmp,
            secret_value="hc-key",
            dry_run=True,
        )
        self.assertTrue(result.dry_run)
        after = _read_yaml(tmp)
        # No mutation beyond what was already there.
        self.assertEqual(before, after)
        self.assertEqual(_read_dotenv(tmp), {})

    def test_dry_run_does_not_take_config_write_lock(self) -> None:
        _, tmp = _make_tmp_ctx()
        with patch("defenseclaw.observability.writer.locked_config_yaml", side_effect=AssertionError("locked")):
            result = apply_preset(
                "honeycomb",
                {"dataset": "defenseclaw"},
                tmp,
                secret_value="hc-key",
                dry_run=True,
            )
        self.assertTrue(result.dry_run)


class WriterAuditSinksPresetTests(unittest.TestCase):
    """apply_preset() for target=audit_sinks presets."""

    def tearDown(self) -> None:
        os.environ.pop("DEFENSECLAW_HOME", None)

    def test_splunk_hec_preserves_existing_sinks(self) -> None:
        """Regression: Config.save() drops audit_sinks because they are
        not modelled as dataclass fields. The writer must edit the
        YAML in place so pre-existing sinks survive a second write.
        """
        _, tmp = _make_tmp_ctx()
        cfg_path = os.path.join(tmp, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                textwrap.dedent(
                    """\
                    claw:
                      mode: openclaw
                    audit_sinks:
                      - name: existing-webhook
                        kind: http_jsonl
                        enabled: true
                        http_jsonl:
                          url: https://example.com/hook
                          method: POST
                    """
                )
            )

        apply_preset(
            "splunk-hec",
            {"host": "splunk.example.com", "port": "8088"},
            tmp,
            secret_value="hec-token",
            name="splunk-hec-prod",
        )

        doc = _read_yaml(tmp)
        sinks = doc.get("audit_sinks") or []
        names = {s["name"] for s in sinks}
        self.assertIn("existing-webhook", names, "existing sink dropped by writer")
        self.assertIn("splunk-hec-prod", names)

    def test_splunk_enterprise_uses_endpoint_token_env_and_tls_verify(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "splunk-enterprise",
            {
                "endpoint": "https://splunk.example.com:8088/services/collector/event",
                "index": "defenseclaw",
            },
            tmp,
            secret_value="hec-token",
        )

        doc = _read_yaml(tmp)
        sinks = doc.get("audit_sinks") or []
        self.assertEqual(len(sinks), 1)
        sink = sinks[0]
        self.assertEqual(sink.get("kind"), "splunk_hec")
        self.assertEqual(sink.get("name"), "splunk-enterprise-splunk-example-com")
        hec = sink.get("splunk_hec") or {}
        self.assertEqual(
            hec.get("endpoint"),
            "https://splunk.example.com:8088/services/collector/event",
        )
        self.assertEqual(hec.get("token_env"), "DEFENSECLAW_SPLUNK_HEC_TOKEN")
        self.assertEqual(hec.get("index"), "defenseclaw")
        # production preset must NOT carry insecure_skip_verify;
        # the Go sink's secure default (TLS verification ON) wins.
        self.assertNotIn("insecure_skip_verify", hec)
        # And the legacy verify_tls field is no longer emitted by the
        # writer — operators with a real cert do not need any opt-out.
        self.assertNotIn("verify_tls", hec)
        self.assertEqual(_read_dotenv(tmp).get("DEFENSECLAW_SPLUNK_HEC_TOKEN"), "hec-token")

    def test_set_destination_enabled_roundtrip(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "webhook",
            {"url": "https://example.com/webhook"},
            tmp,
            name="generic-webhook",
        )
        set_destination_enabled("generic-webhook", False, tmp)
        dests = list_destinations(tmp)
        by_name = {d.name: d for d in dests}
        self.assertFalse(by_name["generic-webhook"].enabled)

    def test_set_destination_enabled_supports_legacy_flat_otel(self) -> None:
        _, tmp = _make_tmp_ctx()
        with open(os.path.join(tmp, "config.yaml"), "w") as handle:
            handle.write("otel:\n  enabled: true\n  endpoint: 127.0.0.1:4317\n")
        result = set_destination_enabled("otel", False, tmp)
        self.assertEqual(result.target, "otel")
        self.assertFalse(_read_yaml(tmp)["otel"]["enabled"])

    def test_remove_destination(self) -> None:
        _, tmp = _make_tmp_ctx()
        apply_preset(
            "webhook",
            {"url": "https://example.com/webhook"},
            tmp,
            name="generic-webhook",
        )
        remove_destination("generic-webhook", tmp)
        names = {d.name for d in list_destinations(tmp)}
        self.assertNotIn("generic-webhook", names)

    def test_otlp_preset_target_override_audit_sinks(self) -> None:
        """The generic ``otlp`` preset declares target=otel and
        sink_kind=None. ``target_override="audit_sinks"`` must mint a
        valid ``otlp_logs`` audit sink — the writer is responsible for
        coercing the missing sink_kind. Drives the same path that
        ``defenseclaw setup local-observability`` uses to add a
        loopback ``otlp_logs`` sink alongside the OTel exporter.
        """
        _, tmp = _make_tmp_ctx()
        result = apply_preset(
            "otlp",
            {"endpoint": "127.0.0.1:4317", "protocol": "grpc", "insecure": "true"},
            tmp,
            name="local-otlp-logs",
            target_override="audit_sinks",
        )
        self.assertEqual(result.target, "audit_sinks")

        doc = _read_yaml(tmp)
        sinks = doc.get("audit_sinks") or []
        self.assertEqual(len(sinks), 1)
        sink = sinks[0]
        self.assertEqual(sink.get("name"), "local-otlp-logs")
        self.assertEqual(sink.get("kind"), "otlp_logs")
        self.assertTrue(sink.get("enabled"))
        block = sink.get("otlp_logs") or {}
        # ``_strip_scheme`` keeps host:port intact (no leading ``http://``).
        self.assertEqual(block.get("endpoint"), "127.0.0.1:4317")
        self.assertEqual(block.get("protocol"), "grpc")
        self.assertTrue(block.get("insecure"))

        # And re-applying with the same name must update in place
        # rather than appending a duplicate — the writer's shallow
        # merge contract is what makes ``setup local-observability up``
        # idempotent across re-invocations.
        apply_preset(
            "otlp",
            {"endpoint": "127.0.0.1:4317", "protocol": "grpc", "insecure": "true"},
            tmp,
            name="local-otlp-logs",
            target_override="audit_sinks",
        )
        doc = _read_yaml(tmp)
        self.assertEqual(len(doc.get("audit_sinks") or []), 1)


# ---------------------------------------------------------------------------
# CLI flag matrix — exercise the three probe paths end-to-end
# ---------------------------------------------------------------------------


class ObservabilityCLITests(unittest.TestCase):
    """Drive `defenseclaw setup observability` through Click's runner.

    We hit one preset per target class (otel / splunk_hec / http_jsonl)
    to prove the flag wiring — exhaustive per-preset tests would just
    re-exercise the writer, which is already covered above.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dclaw-obs-cli-")
        os.environ["DEFENSECLAW_HOME"] = self.tmp
        with open(os.path.join(self.tmp, "config.yaml"), "w") as f:
            f.write("claw:\n  mode: openclaw\n")

        from defenseclaw import config as cfg_mod

        self.app = AppContext()
        self.app.cfg = cfg_mod.load()
        self.runner = CliRunner()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("DEFENSECLAW_HOME", None)

    def _invoke(self, args: list[str]):
        return self.runner.invoke(observability_cmd, args, obj=self.app, catch_exceptions=False)

    def test_add_datadog_non_interactive(self) -> None:
        result = self._invoke(
            [
                "add",
                "datadog",
                "--non-interactive",
                "--token",
                "dd-key-abc",
                "--site",
                "us5",
                "--signals",
                "traces,metrics",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Redaction: ON (redacted telemetry)", result.output)
        self.assertIn("defenseclaw setup redaction off --yes", result.output)
        doc = _read_yaml(self.tmp)
        self.assertTrue(doc.get("otel", {}).get("enabled"))
        self.assertIn("ADD otel:datadog", result.output)

        updated = self._invoke(
            [
                "add",
                "datadog",
                "--non-interactive",
                "--token",
                "dd-key-abc",
                "--site",
                "us5",
                "--signals",
                "traces",
            ]
        )
        self.assertEqual(updated.exit_code, 0, updated.output)
        self.assertIn("UPDATE otel:datadog", updated.output)
        self.assertIn("overwriting existing OTel destination", updated.output)

    def test_list_identifies_target_kind_and_signals(self) -> None:
        result = self._invoke(
            [
                "add",
                "otlp",
                "--non-interactive",
                "--name",
                "tempo",
                "--endpoint",
                "127.0.0.1:4317",
                "--signals",
                "traces",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)

        listed = self._invoke(["list"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        for heading in ("TARGET", "KIND", "PROTOCOL", "SIGNALS"):
            self.assertIn(heading, listed.output)
        self.assertIn("tempo", listed.output)
        self.assertIn("otel", listed.output)
        self.assertIn("traces", listed.output)

    def test_otlp_protocol_cli_roundtrip_list_probe_and_remove(self) -> None:
        for protocol in ("http", "grpc"):
            with self.subTest(protocol=protocol):
                name = f"collector-{protocol}"
                added = self._invoke(
                    [
                        "add",
                        "otlp",
                        "--non-interactive",
                        "--name",
                        name,
                        "--endpoint",
                        "127.0.0.1:4318",
                        "--protocol",
                        protocol,
                    ]
                )
                self.assertEqual(added.exit_code, 0, added.output)

                destination = _read_yaml(self.tmp)["otel"]["destinations"][0]
                self.assertEqual(destination["protocol"], protocol)
                for signal in ("traces", "metrics", "logs"):
                    self.assertEqual(destination[signal]["protocol"], protocol)

                listed_json = self._invoke(["list", "--json"])
                self.assertEqual(listed_json.exit_code, 0, listed_json.output)
                payload = json.loads(listed_json.output)
                self.assertEqual(payload[0]["protocol"], protocol)

                listed_human = self._invoke(["list"])
                self.assertEqual(listed_human.exit_code, 0, listed_human.output)
                self.assertIn("PROTOCOL", listed_human.output)
                self.assertIn(protocol, listed_human.output)

                with patch("socket.create_connection", return_value=MagicMock()):
                    probed = self._invoke(["test", name])
                self.assertEqual(probed.exit_code, 0, probed.output)
                self.assertEqual(probed.output.count(f"({protocol})"), 3)

                removed = self._invoke(["remove", name, "--yes"])
                self.assertEqual(removed.exit_code, 0, removed.output)
                self.assertEqual(list_destinations(self.tmp), [])

    def test_add_reports_raw_redaction_status_without_prompting(self) -> None:
        self.app.cfg.privacy.disable_redaction = True
        result = self._invoke(
            [
                "add",
                "otlp",
                "--non-interactive",
                "--target",
                "audit_sinks",
                "--endpoint",
                "collector.example.com:4317",
                "--protocol",
                "grpc",
                "--name",
                "lab-otlp",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Redaction: OFF (RAW telemetry; privacy.disable_redaction=true)", result.output)
        self.assertIn("defenseclaw setup redaction on", result.output)
        self.assertNotIn("Disable redaction?", result.output)

    def test_add_splunk_hec_then_disable(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup_observability.local_splunk_stack_supported",
            return_value=True,
        ):
            r1 = self._invoke(
                [
                    "add",
                    "splunk-hec",
                    "--non-interactive",
                    "--host",
                    "localhost",
                    "--port",
                    "8088",
                    "--token",
                    "hec-token",
                    "--name",
                    "splunk-hec-local",
                ]
            )
        self.assertEqual(r1.exit_code, 0, r1.output)

        with patch(
            "defenseclaw.commands.cmd_setup_observability.local_splunk_stack_supported",
            return_value=True,
        ):
            r2 = self._invoke(["disable", "splunk-hec-local"])
        self.assertEqual(r2.exit_code, 0, r2.output)

        dests = list_destinations(self.tmp)
        hec = next(d for d in dests if d.name == "splunk-hec-local")
        self.assertFalse(hec.enabled)

    def test_add_splunk_enterprise_non_interactive(self) -> None:
        result = self._invoke(
            [
                "add",
                "splunk-enterprise",
                "--non-interactive",
                "--endpoint",
                "https://splunk.example.com:8088/services/collector/event",
                "--token",
                "hec-token",
                "--index",
                "defenseclaw",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)

        dests = list_destinations(self.tmp)
        hec = next(d for d in dests if d.name == "splunk-enterprise-splunk-example-com")
        self.assertTrue(hec.enabled)
        self.assertEqual(hec.preset_id, "splunk-enterprise")
        self.assertEqual(_read_dotenv(self.tmp).get("DEFENSECLAW_SPLUNK_HEC_TOKEN"), "hec-token")

    def _add_enterprise_sink(self) -> None:
        result = self._invoke(
            [
                "add",
                "splunk-enterprise",
                "--non-interactive",
                "--endpoint",
                "https://splunk.example.com:8088/services/collector/event",
                "--token",
                "hec-token",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)

    def test_splunk_enterprise_probe_success(self) -> None:
        self._add_enterprise_sink()
        with patch("urllib.request.OpenerDirector.open", return_value=_FakeHTTPResponse(200, "OK")):
            result = self._invoke(["test", "splunk-enterprise-splunk-example-com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Splunk Enterprise (HEC)", result.output)
        self.assertIn("HEC responded 200 OK", result.output)

    def test_splunk_enterprise_probe_auth_failure(self) -> None:
        self._add_enterprise_sink()
        err = urllib.error.HTTPError(
            "https://splunk.example.com:8088/services/collector/event",
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )
        with patch("urllib.request.OpenerDirector.open", side_effect=err):
            result = self._invoke(["test", "splunk-enterprise-splunk-example-com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("HTTP 401 Unauthorized", result.output)
        self.assertIn("check token/index permissions", result.output)

    def test_splunk_enterprise_probe_forbidden(self) -> None:
        self._add_enterprise_sink()
        err = urllib.error.HTTPError(
            "https://splunk.example.com:8088/services/collector/event",
            403,
            "Forbidden",
            hdrs=None,
            fp=None,
        )
        with patch("urllib.request.OpenerDirector.open", side_effect=err):
            result = self._invoke(["test", "splunk-enterprise-splunk-example-com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("HTTP 403 Forbidden", result.output)
        self.assertIn("check token/index permissions", result.output)

    def test_splunk_enterprise_probe_unreachable(self) -> None:
        self._add_enterprise_sink()
        with patch("urllib.request.OpenerDirector.open", side_effect=OSError("network down")):
            result = self._invoke(["test", "splunk-enterprise-splunk-example-com"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("network down", result.output)

    def test_add_webhook_dry_run_does_not_persist(self) -> None:
        result = self._invoke(
            [
                "add",
                "webhook",
                "--non-interactive",
                "--url",
                "https://example.com/hook",
                "--dry-run",
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        # list_destinations() always surfaces the otel: block (enabled
        # or not) — a dry-run webhook must not land in audit_sinks.
        dests = list_destinations(self.tmp)
        sink_names = [d.name for d in dests if d.target == "audit_sinks"]
        self.assertEqual(sink_names, [])

    def test_list_is_stable_for_empty_config(self) -> None:
        result = self._invoke(["list"])
        self.assertEqual(result.exit_code, 0, result.output)


# ---------------------------------------------------------------------------
# migrate-splunk idempotency
# ---------------------------------------------------------------------------


class MigrateSplunkTests(unittest.TestCase):
    """`setup observability migrate-splunk --apply` twice must be a no-op
    the second time — that's the definition of idempotent."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dclaw-migrate-")
        os.environ["DEFENSECLAW_HOME"] = self.tmp
        # Seed a config.yaml with a legacy top-level `splunk:` block —
        # the shape produced by pre-observability `setup splunk
        # --logs`.
        with open(os.path.join(self.tmp, "config.yaml"), "w") as f:
            f.write(
                textwrap.dedent(
                    """\
                    claw:
                      mode: openclaw
                    splunk:
                      enabled: true
                      hec_endpoint: https://splunk.example.com:8088/services/collector/event
                      hec_token_env: DEFENSECLAW_SPLUNK_HEC_TOKEN
                      index: defenseclaw
                      source: defenseclaw
                      sourcetype: _json
                    """
                )
            )
        from defenseclaw import config as cfg_mod

        self.app = AppContext()
        self.app.cfg = cfg_mod.load()
        self.runner = CliRunner()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("DEFENSECLAW_HOME", None)

    def test_migrate_is_idempotent(self) -> None:
        r1 = self.runner.invoke(
            observability_cmd,
            ["migrate-splunk", "--apply"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(r1.exit_code, 0, r1.output)

        dests_after_first = list_destinations(self.tmp)
        hec_names_first = sorted(d.name for d in dests_after_first if d.kind == "splunk_hec")
        self.assertEqual(len(hec_names_first), 1, "expected exactly one HEC sink after migration")

        # Second apply — must not duplicate the sink.
        r2 = self.runner.invoke(
            observability_cmd,
            ["migrate-splunk", "--apply"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(r2.exit_code, 0, r2.output)

        dests_after_second = list_destinations(self.tmp)
        hec_names_second = sorted(d.name for d in dests_after_second if d.kind == "splunk_hec")
        self.assertEqual(hec_names_first, hec_names_second)

    def test_managed_migrate_apply_is_rejected_without_modifying_config(self) -> None:
        cfg_path = os.path.join(self.tmp, "config.yaml")
        with open(cfg_path) as f:
            raw = yaml.safe_load(f)
        raw["deployment_mode"] = "managed_enterprise"
        with open(cfg_path, "w") as f:
            yaml.safe_dump(raw, f, sort_keys=False)
        with open(cfg_path, "rb") as f:
            before = f.read()

        with patch("defenseclaw.config._is_admin_process", return_value=False):
            result = self.runner.invoke(
                observability_cmd,
                ["migrate-splunk", "--apply"],
                obj=self.app,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIsInstance(result.exception, PermissionError)
        with open(cfg_path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_managed_duplicate_cleanup_is_rejected_without_modifying_config(self) -> None:
        cfg_path = os.path.join(self.tmp, "config.yaml")
        with open(cfg_path) as f:
            raw = yaml.safe_load(f)
        raw["deployment_mode"] = "managed_enterprise"
        raw["audit_sinks"] = [
            {
                "name": "existing-splunk",
                "kind": "splunk_hec",
                "enabled": True,
                "splunk_hec": {
                    "endpoint": "https://splunk.example.com:8088/services/collector/event",
                },
            }
        ]
        with open(cfg_path, "w") as f:
            yaml.safe_dump(raw, f, sort_keys=False)
        with open(cfg_path, "rb") as f:
            before = f.read()

        with patch("defenseclaw.config._is_admin_process", return_value=False):
            result = self.runner.invoke(
                observability_cmd,
                ["migrate-splunk", "--apply"],
                obj=self.app,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIsInstance(result.exception, PermissionError)
        with open(cfg_path, "rb") as f:
            self.assertEqual(f.read(), before)


if __name__ == "__main__":
    unittest.main()
