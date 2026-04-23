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

import os
import sys
import tempfile
import textwrap
import unittest

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_setup_observability import observability as observability_cmd
from defenseclaw.context import AppContext
from defenseclaw.observability import (
    PRESETS,
    apply_preset,
    list_destinations,
    preset_choices,
    remove_destination,
    resolve_preset,
    set_destination_enabled,
)
from defenseclaw.observability.presets import Preset


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
        "datadog",
        "honeycomb",
        "newrelic",
        "grafana-cloud",
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
        """Guardrail: TUI's observabilityPresets slice must mirror
        ``preset_choices()`` ordering. The TUI is a separate Go codebase
        so we grep its source rather than import it.
        """
        go_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "internal", "tui", "setup.go"
        )
        if not os.path.exists(go_file):
            self.skipTest(f"{go_file} not found; running outside repo")
        with open(go_file) as f:
            source = f.read()
        for pid in self.EXPECTED_PRESET_IDS:
            self.assertIn(
                f'"{pid}"',
                source,
                f"preset id '{pid}' missing from internal/tui/setup.go — "
                "observabilityPresets drifted from presets.py",
            )


# ---------------------------------------------------------------------------
# Writer round-trip — one test per *target* class
# ---------------------------------------------------------------------------


class WriterOTelPresetTests(unittest.TestCase):
    """apply_preset() for target=otel presets."""

    def tearDown(self) -> None:
        os.environ.pop("DEFENSECLAW_HOME", None)

    def test_datadog_roundtrip_stamps_preset_identity(self) -> None:
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
        # Datadog's endpoint_template must have been substituted.
        self.assertIn("datadoghq.com", str(otel.get("traces", {}).get("endpoint", "")))

        attrs = (otel.get("resource") or {}).get("attributes") or {}
        self.assertEqual(attrs.get("defenseclaw.preset"), "datadog")
        self.assertEqual(
            attrs.get("defenseclaw.preset_name"),
            PRESETS["datadog"].display_name,
        )

        dotenv = _read_dotenv(tmp)
        self.assertEqual(dotenv.get(PRESETS["datadog"].token_env), "dd-key-abc")

    def test_local_otlp_roundtrip_enables_plaintext_grpc(self) -> None:
        _, tmp = _make_tmp_ctx()
        result = apply_preset(
            "local-otlp",
            {"endpoint": "127.0.0.1:4317"},
            tmp,
            signals=("traces", "metrics", "logs"),
        )

        self.assertFalse(result.dry_run)
        doc = _read_yaml(tmp)
        otel = doc.get("otel") or {}
        self.assertTrue((otel.get("tls") or {}).get("insecure"))
        self.assertEqual((otel.get("metrics") or {}).get("endpoint"), "127.0.0.1:4317")

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
        return self.runner.invoke(
            observability_cmd, args, obj=self.app, catch_exceptions=False
        )

    def test_add_datadog_non_interactive(self) -> None:
        result = self._invoke([
            "add", "datadog",
            "--non-interactive",
            "--token", "dd-key-abc",
            "--site", "us5",
            "--signals", "traces,metrics",
        ])
        self.assertEqual(result.exit_code, 0, result.output)
        doc = _read_yaml(self.tmp)
        self.assertTrue(doc.get("otel", {}).get("enabled"))

    def test_add_splunk_hec_then_disable(self) -> None:
        r1 = self._invoke([
            "add", "splunk-hec",
            "--non-interactive",
            "--host", "localhost", "--port", "8088",
            "--token", "hec-token",
            "--name", "splunk-hec-local",
        ])
        self.assertEqual(r1.exit_code, 0, r1.output)

        r2 = self._invoke(["disable", "splunk-hec-local"])
        self.assertEqual(r2.exit_code, 0, r2.output)

        dests = list_destinations(self.tmp)
        hec = next(d for d in dests if d.name == "splunk-hec-local")
        self.assertFalse(hec.enabled)

    def test_add_webhook_dry_run_does_not_persist(self) -> None:
        result = self._invoke([
            "add", "webhook",
            "--non-interactive",
            "--url", "https://example.com/hook",
            "--dry-run",
        ])
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


if __name__ == "__main__":
    unittest.main()
