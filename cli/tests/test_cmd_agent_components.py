# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw agent components`` and ``agent confidence``.

These commands are the operator-facing surface for the new two-axis
Bayesian confidence engine + per-component locations + history work
(plan: dedup-evidence-confidence). Coverage focuses on:

* The components listing renders Identity/Presence/Detectors columns
  only when the rollup payload carries them (back-compat with v1
  sidecars that don't have the engine wired).
* ``--min-identity`` / ``--min-presence`` filter rows server-agnostically.
* ``components show NAME`` / ``components history NAME`` resolve a
  component name via the rollup, fail cleanly on ambiguity, and pass
  the resolved (ecosystem, name) to the per-component endpoints.
* ``confidence explain NAME`` renders the per-evidence factor
  breakdown using both axes' factor slices.
* ``confidence policy {show, default, validate}`` round-trip the
  policy endpoints; ``validate`` exits non-zero on a bad file.
* ``agent usage --detail`` surfaces the new evidence records when
  ``signal.evidence[]`` is populated, and falls back cleanly otherwise.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_agent
from defenseclaw.context import AppContext


def _make_ctx(*, token: str = "secret-token") -> AppContext:
    cfg = SimpleNamespace(
        gateway=SimpleNamespace(host="127.0.0.1", port=18789, token=token),
    )

    def active_connector():
        return "openclaw"

    cfg.active_connector = active_connector
    cfg.save = MagicMock()

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    app.logger.log_action = MagicMock()
    return app


def _resolve_target_stub(app, *, gateway_host=None, gateway_port=None, gateway_token_env=None):
    return ("127.0.0.1", 18970, "secret-token")


# Reusable rollup fixtures. All tests build their FakeClient on top
# of these so the assertions on filter/show/history stay decoupled
# from how the listing happens to be wired today.
_ROLLUP_TWO_AXIS = {
    "components": [
        {
            "ecosystem": "pypi",
            "name": "openai",
            "framework": "",
            "vendor": "openai",
            "versions": ["1.45.0"],
            "install_count": 3,
            "workspace_count": 2,
            "detectors": ["package_manifest", "process"],
            "identity_score": 0.96,
            "identity_band": "very_high",
            "presence_score": 0.91,
            "presence_band": "very_high",
            "identity_factors": [
                {
                    "detector": "package_manifest",
                    "evidence_id": "pyproject.toml#openai",
                    "match_kind": "exact",
                    "quality": 1.0,
                    "specificity": 0.85,
                    "lr": 30.0,
                    "logit_delta": 3.4,
                },
            ],
            "presence_factors": [
                {
                    "detector": "process",
                    "evidence_id": "pid=1234",
                    "match_kind": "exact",
                    "quality": 1.0,
                    "specificity": 1.0,
                    "lr": 250.0,
                    "logit_delta": 5.5,
                },
            ],
            "last_seen": "2026-05-05T12:00:00Z",
            "last_active_at": "2026-05-05T12:00:00Z",
        },
        {
            "ecosystem": "npm",
            "name": "openai",
            "framework": "",
            "vendor": "openai",
            "versions": ["4.40.0"],
            "install_count": 1,
            "workspace_count": 1,
            "detectors": ["package_manifest"],
            "identity_score": 0.55,
            "identity_band": "low",
            "presence_score": 0.20,
            "presence_band": "very_low",
            "last_seen": "2026-05-05T11:00:00Z",
        },
        {
            "ecosystem": "pypi",
            "name": "anthropic",
            "framework": "",
            "vendor": "anthropic",
            "versions": ["0.30.0"],
            "install_count": 1,
            "workspace_count": 1,
            "detectors": ["package_manifest"],
            "identity_score": 0.85,
            "identity_band": "high",
            "presence_score": 0.40,
            "presence_band": "low",
            "last_seen": "2026-05-04T08:00:00Z",
        },
    ]
}

_ROLLUP_LEGACY = {
    "components": [
        {
            "ecosystem": "pypi",
            "name": "legacy",
            "version": "1.0.0",
            "framework": "",
            "vendor": "old",
            "workspaces": 1,
            "installs": 1,
            "last_seen": "2026-05-01T08:00:00Z",
        },
    ]
}


# ---------------------------------------------------------------------------
# Helper-level tests (no Click runner). These exercise the formatting
# and resolver utilities so a regression in `_format_confidence` shows
# up here, not in the higher-level table tests where the failure
# mode is harder to read.
# ---------------------------------------------------------------------------


class FormatHelperTests(unittest.TestCase):
    def test_format_confidence_combines_band_and_score(self):
        self.assertEqual(cmd_agent._format_confidence(0.965, "very_high"), "very_high (96%)")
        self.assertEqual(cmd_agent._format_confidence(0.50, "medium"), "medium (50%)")

    def test_format_confidence_handles_missing_inputs(self):
        self.assertEqual(cmd_agent._format_confidence(None, None), "")
        self.assertEqual(cmd_agent._format_confidence(None, "high"), "high")
        self.assertEqual(cmd_agent._format_confidence(0.5, None), "50%")
        # Bad numeric inputs do not crash — that protects the listing
        # table from a single malformed row taking the whole render down.
        self.assertEqual(cmd_agent._format_confidence("nope", "high"), "high")

    def test_format_logit_delta_signs_correctly(self):
        self.assertEqual(cmd_agent._format_logit_delta(12.345), "+12.3pp")
        self.assertEqual(cmd_agent._format_logit_delta(-3.14), "-3.1pp")
        self.assertEqual(cmd_agent._format_logit_delta(0.0), "+0.0pp")
        self.assertEqual(cmd_agent._format_logit_delta(None), "")

    def test_format_versions_handles_list_and_scalar(self):
        self.assertEqual(cmd_agent._format_versions(["1.0", "2.0"]), "1.0, 2.0")
        # Truncation past three keeps the column scannable on terminals
        # narrower than 200 cols.
        self.assertEqual(
            cmd_agent._format_versions(["1.0", "2.0", "3.0", "4.0"]),
            "1.0, 2.0, 3.0 (+1 more)",
        )
        self.assertEqual(cmd_agent._format_versions("scalar"), "scalar")
        self.assertEqual(cmd_agent._format_versions(""), "")

    def test_format_detectors_dedups_and_sorts(self):
        self.assertEqual(
            cmd_agent._format_detectors(["b", "a", "a", " c "]),
            "a, b, c",
        )
        self.assertEqual(
            cmd_agent._format_detectors(["a", "b", "c", "d", "e", "f"], limit=3),
            "a, b, c (+3 more)",
        )

    def test_format_evidence_records_renders_quality_and_match_kind(self):
        rec = [
            {"basename": "pyproject.toml", "quality": 1.0, "match_kind": "exact"},
            {"basename": "pkg.json", "quality": 0.6, "match_kind": "substring"},
        ]
        out = cmd_agent._format_evidence_records(rec)
        # exact + quality=1.0 collapses to bare basename — reduces noise
        # in the common case.
        self.assertIn("pyproject.toml", out)
        # Non-exact match kind and non-1.0 quality must surface.
        self.assertIn("substring", out)
        self.assertIn("q=0.6", out)

    def test_format_evidence_records_handles_path_hash_only(self):
        rec = [{"path_hash": "sha256:abcdef0123456789"}]
        out = cmd_agent._format_evidence_records(rec)
        self.assertTrue(out.startswith("sha256:abcdef"))


class FilterComponentsTests(unittest.TestCase):
    def test_min_identity_filters_low_band(self):
        rows = cmd_agent._filter_components(
            _ROLLUP_TWO_AXIS["components"], min_identity=0.8)
        names = sorted({r["name"] for r in rows})
        # openai npm row has identity_score=0.55 → filtered out.
        self.assertEqual(names, ["anthropic", "openai"])
        ids = [(r["ecosystem"], r["name"]) for r in rows]
        self.assertNotIn(("npm", "openai"), ids)

    def test_min_presence_filters_low_presence(self):
        rows = cmd_agent._filter_components(
            _ROLLUP_TWO_AXIS["components"], min_presence=0.5)
        # Only the pypi/openai row clears the bar; everything else has
        # presence < 0.5.
        self.assertEqual([(r["ecosystem"], r["name"]) for r in rows],
                         [("pypi", "openai")])

    def test_ecosystem_and_name_substring(self):
        rows = cmd_agent._filter_components(
            _ROLLUP_TWO_AXIS["components"],
            ecosystems=("pypi",),
            names=("opena",),
        )
        self.assertEqual([r["name"] for r in rows], ["openai"])
        self.assertEqual(rows[0]["ecosystem"], "pypi")


class ResolveComponentTests(unittest.TestCase):
    def _make_client(self, rollup):
        client = MagicMock()
        client.ai_usage_components.return_value = rollup
        return client

    def test_unique_match_returns_component(self):
        client = self._make_client(_ROLLUP_TWO_AXIS)
        comp, err = cmd_agent._resolve_component(
            client, name="anthropic", ecosystem=None)
        self.assertIsNone(err)
        self.assertEqual(comp["ecosystem"], "pypi")

    def test_ambiguous_name_demands_ecosystem(self):
        client = self._make_client(_ROLLUP_TWO_AXIS)
        comp, err = cmd_agent._resolve_component(
            client, name="openai", ecosystem=None)
        self.assertEqual(comp, {})
        self.assertIn("ambiguous", err)
        # The error must list both ecosystems so the operator can copy
        # one into --ecosystem without re-querying.
        self.assertIn("npm", err)
        self.assertIn("pypi", err)

    def test_ambiguous_resolved_with_ecosystem(self):
        client = self._make_client(_ROLLUP_TWO_AXIS)
        comp, err = cmd_agent._resolve_component(
            client, name="openai", ecosystem="npm")
        self.assertIsNone(err)
        self.assertEqual(comp["ecosystem"], "npm")

    def test_missing_component(self):
        client = self._make_client(_ROLLUP_TWO_AXIS)
        comp, err = cmd_agent._resolve_component(
            client, name="not-real", ecosystem=None)
        self.assertEqual(comp, {})
        self.assertIn("not found", err)

    def test_request_failures_surface_as_errors(self):
        client = MagicMock()
        client.ai_usage_components.side_effect = requests.ConnectionError("refused")
        comp, err = cmd_agent._resolve_component(
            client, name="anything", ecosystem=None)
        self.assertEqual(comp, {})
        self.assertIn("sidecar unavailable", err)


# ---------------------------------------------------------------------------
# CLI-level tests (Click runner). These exercise the wiring end-to-end
# through the click context so a regression in decorator order or
# subgroup propagation surfaces here.
# ---------------------------------------------------------------------------


class _FakeClient:
    """Minimal fake the listing/show/history tests use.

    Tests over-write attributes (e.g. ``components_payload``) per case
    so a single fixture covers happy paths and error injection.
    """

    components_payload: dict = _ROLLUP_TWO_AXIS
    locations_payload: dict = {
        "enabled": True, "ecosystem": "pypi", "name": "openai",
        "locations": [
            {
                "detector": "package_manifest",
                "state": "active",
                "basename": "pyproject.toml",
                "workspace_hash": "wh-abcdef0123456789",
                "quality": 1.0,
                "match_kind": "exact",
                "last_seen": "2026-05-05T12:00:00Z",
            },
            {
                "detector": "process",
                "state": "active",
                "basename": "python3",
                "workspace_hash": "wh-9876543210fedcba",
                "quality": 1.0,
                "match_kind": "exact",
                "last_seen": "2026-05-05T12:00:00Z",
            },
        ],
    }
    # Mirror the actual sidecar wire shape (see
    # ``ComponentHistoryRow`` in internal/inventory/store.go):
    # the timestamp is JSON-tagged ``scanned_at`` (NOT
    # ``computed_at``) and ``detectors`` is a comma-separated TEXT
    # field, not a list. Earlier fixtures used ``computed_at`` +
    # list which masked the F6/F7 renderer bugs entirely. Pin the
    # production shape here so any future drift is caught at unit
    # test time rather than in the field.
    history_payload: dict = {
        "enabled": True, "ecosystem": "pypi", "name": "openai",
        "history": [
            {
                "scan_id": "scan-2",
                "scanned_at": "2026-05-05T12:00:00Z",
                "identity_score": 0.96, "identity_band": "very_high",
                "presence_score": 0.91, "presence_band": "very_high",
                "detectors": "package_manifest,process",
                "policy_version": 1,
            },
            {
                "scan_id": "scan-1",
                "scanned_at": "2026-05-05T08:00:00Z",
                "identity_score": 0.94, "identity_band": "high",
                "presence_score": 0.20, "presence_band": "very_low",
                "detectors": "package_manifest",
                "policy_version": 1,
            },
        ],
    }
    policy_payload: dict = {
        "source": "merged",
        "enabled": True,
        "policy": {
            "version": 1,
            "priors": {"identity": "signature", "presence": 0.05},
            "half_life_hours": 168,
            "detectors": {"process": {"identity_lr": 8, "presence_lr": 250}},
            "penalties": {},
            "bands": [
                {"min": 0.95, "label": "very_high"},
                {"min": 0.80, "label": "high"},
                {"min": 0.60, "label": "medium"},
                {"min": 0.30, "label": "low"},
                {"min": 0.0, "label": "very_low"},
            ],
        },
    }
    validate_payload: dict = {"valid": True, "version": 1, "policy": {}}

    def __init__(self, **_kwargs):
        pass

    def scan_ai_usage(self):
        return self.components_payload

    def ai_usage(self):
        return {
            "enabled": True,
            "summary": {
                "active_signals": 2, "new_signals": 0,
                "changed_signals": 0, "gone_signals": 0,
                "scanned_at": "2026-05-05T12:00:00Z",
                "files_scanned": 12,
            },
            "signals": [],
        }

    def ai_usage_components(self):
        return self.components_payload

    def ai_usage_component_locations(self, ecosystem, name):
        # Test the resolver actually passes the resolved fields through.
        self.last_locations_call = (ecosystem, name)
        return self.locations_payload

    def ai_usage_component_history(self, ecosystem, name):
        self.last_history_call = (ecosystem, name)
        return self.history_payload

    def ai_usage_confidence_policy(self, *, source="merged"):
        self.last_policy_source = source
        # Echo the source back so `policy default` can be distinguished
        # from `policy show` in the rendered output.
        out = dict(self.policy_payload)
        out["source"] = source
        return out

    def ai_usage_validate_confidence_policy(self, yaml_text):
        self.last_validate_payload = yaml_text
        return self.validate_payload


class ComponentsListingTests(unittest.TestCase):
    def test_renders_identity_presence_columns_for_v2_payload(self):
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(cmd_agent.components_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Header must include the two new columns when scores are present.
        self.assertIn("Identity", result.output)
        self.assertIn("Presence", result.output)
        # Footer points operators at the new drill-down commands.
        self.assertIn("agent components show NAME", result.output)
        self.assertIn("agent confidence explain NAME", result.output)

    def test_v1_payload_omits_confidence_columns(self):
        runner = CliRunner()
        app = _make_ctx()

        class LegacyClient(_FakeClient):
            components_payload = _ROLLUP_LEGACY

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", LegacyClient):
            result = runner.invoke(cmd_agent.components_cmd, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Older sidecars don't ship identity/presence; confirm we
        # gracefully drop the column rather than rendering an empty one.
        self.assertNotIn("Identity", result.output)
        self.assertNotIn("Presence", result.output)
        self.assertIn("legacy", result.output)

    def test_min_identity_filter_drops_rows(self):
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["--min-identity", "0.9", "--json"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.output)
        names = {(c["ecosystem"], c["name"]) for c in payload["components"]}
        # Only pypi/openai (identity=0.96) clears 0.9; the other two are
        # below the threshold.
        self.assertEqual(names, {("pypi", "openai")})

    def test_listing_does_not_crash_on_unreachable_sidecar(self):
        runner = CliRunner()
        app = _make_ctx()

        class BrokenClient(_FakeClient):
            def ai_usage_components(self):
                raise requests.ConnectionError("connection refused")

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", BrokenClient):
            result = runner.invoke(cmd_agent.components_cmd, [], obj=app)
        # Non-zero exit is the contract — operator scripts can pipeline
        # `defenseclaw agent components || alert ...`.
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("sidecar unavailable", result.output)


class ComponentsShowTests(unittest.TestCase):
    def test_show_resolves_and_calls_locations_endpoint(self):
        runner = CliRunner()
        app = _make_ctx()
        instance: dict = {}

        class CapturingClient(_FakeClient):
            def __init__(self, **_kwargs):
                super().__init__()
                instance["client"] = self

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", CapturingClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["show", "openai", "--ecosystem", "pypi"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(instance["client"].last_locations_call, ("pypi", "openai"))
        self.assertIn("pyproject.toml", result.output)
        self.assertIn("python3", result.output)
        # The privacy footer is the operator's signal that they can
        # surface raw paths if they need them.
        self.assertIn("raw paths hidden", result.output)

    def test_show_ambiguous_name_fails_cleanly(self):
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["show", "openai"],   # no --ecosystem; openai exists in pypi+npm
                obj=app,
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("ambiguous", result.output)
        self.assertIn("--ecosystem", result.output)

    def test_show_emits_raw_path_column_when_present(self):
        runner = CliRunner()
        app = _make_ctx()

        class RawClient(_FakeClient):
            locations_payload = {
                "enabled": True, "ecosystem": "pypi", "name": "openai",
                "locations": [
                    {
                        "detector": "package_manifest",
                        "state": "active",
                        "basename": "pyproject.toml",
                        "raw_path": "/Users/op/proj/pyproject.toml",
                        "quality": 1.0, "match_kind": "exact",
                    },
                ],
            }

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", RawClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["show", "openai", "--ecosystem", "pypi"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Raw path", result.output)
        self.assertIn("/Users/op/proj/pyproject.toml", result.output)
        # When raw paths are present the privacy hint must NOT appear,
        # otherwise it's just visual noise.
        self.assertNotIn("raw paths hidden", result.output)


class ComponentsHistoryTests(unittest.TestCase):
    def test_history_renders_table(self):
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["history", "openai", "--ecosystem", "pypi"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Confidence history", result.output)
        # Both snapshots from the fixture must appear.
        self.assertIn("2026-05-05T12:00:00Z", result.output)
        self.assertIn("2026-05-05T08:00:00Z", result.output)

    def test_history_json_round_trips_payload(self):
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["history", "openai", "--ecosystem", "pypi", "--json"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.output)
        self.assertEqual(len(payload["history"]["history"]), 2)

    def test_history_renders_detectors_split_not_per_character(self):
        # Regression test for F7. Pre-fix, `_format_detectors` was
        # passed the comma-separated string from the wire and
        # iterated character-by-character, producing nonsense output
        # like ",.aceginprstu". Pin the human-readable rendering
        # and assert no character-soup leaks through.
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["history", "openai", "--ecosystem", "pypi"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Both detectors render in full from the comma-separated
        # field — only possible if the renderer split on "," first.
        self.assertIn("package_manifest", result.output)
        self.assertIn("process", result.output)

    def test_history_renders_scanned_at_column(self):
        # Regression test for F6. Pre-fix, the renderer read the
        # non-existent `computed_at` field and the column was
        # always blank in production. The header label changed too
        # ("Computed at" → "Scanned at") to match the wire field.
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.components_cmd,
                ["history", "openai", "--ecosystem", "pypi"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Scanned at", result.output)
        # Make sure the timestamp from the wire actually reaches
        # the renderer (this is what permanently failed pre-fix).
        self.assertIn("2026-05-05T12:00:00Z", result.output)


class HistoryHelpersTests(unittest.TestCase):
    """Direct tests for the `_history_row_*` shape adapters added
    to fix F6/F7. Pinned at the helper layer so a regression shows
    up here with a clear failure rather than as a column-rendering
    weirdness in the integration tests above.
    """

    def test_timestamp_prefers_scanned_at(self):
        row = {"scanned_at": "2026-05-05T12:00:00Z",
               "computed_at": "2026-05-04T12:00:00Z"}
        self.assertEqual(cmd_agent._history_row_timestamp(row), "2026-05-05T12:00:00Z")

    def test_timestamp_falls_back_to_computed_at(self):
        # Older test stubs (and any v1 sidecar payload that ever
        # shipped with computed_at) still render correctly.
        row = {"computed_at": "2026-05-04T12:00:00Z"}
        self.assertEqual(cmd_agent._history_row_timestamp(row), "2026-05-04T12:00:00Z")

    def test_timestamp_missing_returns_empty(self):
        self.assertEqual(cmd_agent._history_row_timestamp({}), "")

    def test_detectors_splits_comma_separated_string(self):
        row = {"detectors": "binary,process , package_manifest"}
        # Whitespace around segments must be stripped so the column
        # doesn't show " process".
        self.assertEqual(
            cmd_agent._history_row_detectors(row),
            ["binary", "process", "package_manifest"],
        )

    def test_detectors_passes_through_lists(self):
        row = {"detectors": ["binary", "process"]}
        self.assertEqual(cmd_agent._history_row_detectors(row), ["binary", "process"])

    def test_detectors_handles_missing_or_unknown_type(self):
        self.assertEqual(cmd_agent._history_row_detectors({}), [])
        self.assertEqual(cmd_agent._history_row_detectors({"detectors": None}), [])
        # Defensive: weird types don't crash the renderer.
        self.assertEqual(cmd_agent._history_row_detectors({"detectors": 42}), [])


class ConfidenceExplainTests(unittest.TestCase):
    def test_explain_renders_both_factor_tables(self):
        runner = CliRunner()
        app = _make_ctx()
        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", _FakeClient):
            result = runner.invoke(
                cmd_agent.confidence_explain,
                ["openai", "--ecosystem", "pypi"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Identity factors", result.output)
        self.assertIn("Presence factors", result.output)
        # The percentage-point shift column is the operator's
        # one-line explanation per evidence; it must render.
        self.assertIn("pp", result.output)


class ConfidencePolicyTests(unittest.TestCase):
    def test_policy_show_uses_merged_source(self):
        runner = CliRunner()
        app = _make_ctx()
        instance: dict = {}

        class CapturingClient(_FakeClient):
            def __init__(self, **_kwargs):
                super().__init__()
                instance["client"] = self

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", CapturingClient):
            result = runner.invoke(
                cmd_agent.confidence_policy_show, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(instance["client"].last_policy_source, "merged")
        # Default rendering is YAML with a provenance header.
        self.assertIn("source=merged", result.output)
        self.assertIn("version: 1", result.output)

    def test_policy_default_uses_default_source(self):
        runner = CliRunner()
        app = _make_ctx()
        instance: dict = {}

        class CapturingClient(_FakeClient):
            def __init__(self, **_kwargs):
                super().__init__()
                instance["client"] = self

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", CapturingClient):
            result = runner.invoke(
                cmd_agent.confidence_policy_default, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(instance["client"].last_policy_source, "default")

    def test_policy_validate_passes_through_yaml_and_exits_zero_on_valid(self):
        runner = CliRunner()
        app = _make_ctx()

        instance: dict = {}

        class CapturingClient(_FakeClient):
            def __init__(self, **_kwargs):
                super().__init__()
                instance["client"] = self

        with runner.isolated_filesystem():
            with open("policy.yaml", "w", encoding="utf-8") as fh:
                fh.write("version: 1\n")
            with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                       side_effect=_resolve_target_stub), \
                    patch("defenseclaw.commands.cmd_agent.OrchestratorClient", CapturingClient):
                result = runner.invoke(
                    cmd_agent.confidence_policy_validate,
                    ["policy.yaml"],
                    obj=app,
                )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("OK:", result.output)
        # Body must be the file contents — guard against accidental
        # filename-only POSTs.
        self.assertEqual(instance["client"].last_validate_payload, "version: 1\n")

    def test_policy_validate_exits_non_zero_on_invalid(self):
        runner = CliRunner()
        app = _make_ctx()

        class FailingValidateClient(_FakeClient):
            validate_payload = {"valid": False, "error": "unknown detector \"nope\""}

        with runner.isolated_filesystem():
            with open("policy.yaml", "w", encoding="utf-8") as fh:
                fh.write("detectors:\n  nope: { identity_lr: 1, presence_lr: 1 }\n")
            with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                       side_effect=_resolve_target_stub), \
                    patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FailingValidateClient):
                result = runner.invoke(
                    cmd_agent.confidence_policy_validate,
                    ["policy.yaml"],
                    obj=app,
                )
        # Non-zero exit so `&&` chains in operator scripts halt on
        # validation failure.
        self.assertEqual(result.exit_code, 1)
        # The diagnostic must reach the operator (we route the
        # invalid line to stderr but click captures both streams).
        self.assertIn("INVALID", result.output)
        self.assertIn("nope", result.output)


class UsageDetailEvidenceTests(unittest.TestCase):
    def test_detail_renders_rich_evidence_when_present(self):
        runner = CliRunner()
        app = _make_ctx()

        class RichEvidenceClient(_FakeClient):
            def ai_usage(self):
                return {
                    "enabled": True,
                    "summary": {
                        "active_signals": 1, "new_signals": 0,
                        "changed_signals": 0, "gone_signals": 0,
                        "scanned_at": "2026-05-05T12:00:00Z",
                        "files_scanned": 1,
                    },
                    "signals": [
                        {
                            "state": "active",
                            "category": "sdk",
                            "product": "OpenAI Python",
                            "vendor": "openai",
                            "detector": "package_manifest",
                            "identity_score": 0.96, "identity_band": "very_high",
                            "presence_score": 0.20, "presence_band": "very_low",
                            "evidence": [
                                {
                                    "basename": "pyproject.toml",
                                    "quality": 0.6,
                                    "match_kind": "substring",
                                },
                            ],
                            "basenames": ["pyproject.toml"],
                        },
                    ],
                }

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", RichEvidenceClient):
            result = runner.invoke(
                cmd_agent.usage,
                ["--detail"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # The new evidence-records formatter (Phase-2 rich payload)
        # must surface the quality + match_kind that the legacy
        # basename-only formatter would have stripped.
        self.assertIn("substring", result.output)
        self.assertIn("q=0.6", result.output)
        # Identity / Presence columns must light up too.
        self.assertIn("Identity", result.output)


if __name__ == "__main__":
    unittest.main()
