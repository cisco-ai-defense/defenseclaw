# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw status`` multi-connector "Agents" roster.

``_print_agents`` is config-derived (``active_connectors()`` +
``GuardrailConfig.effective_mode``) so it renders whether or not the sidecar
is running. The standalone ``Connectors:`` row was folded into a single
``Agents`` section. These tests pin:

* One line per connector with its effective mode under a single ``Agents``
  header, for ANY connector count — a single-connector install renders the
  same section (one row), not a separate legacy ``Agent:`` block.
* Called with no bound health snapshot (config-only), the roster lists
  connectors + mode without live counters.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands import cmd_status
from defenseclaw.commands.cmd_status import _print_agents
from defenseclaw.commands.cmd_status import status as status_cmd
from defenseclaw.config import AIDiscoveryConfig, ApplicationProtectionConfig, GuardrailConfig

from tests.helpers import cleanup_app, make_app_context


def _cfg(actives, *, modes=None, disabled=None):
    modes = modes or {}
    disabled = set(disabled or ())
    cfg = MagicMock()
    cfg.active_connectors.return_value = list(actives)
    cfg.guardrail.effective_mode.side_effect = lambda c: modes.get(c, "observe")
    cfg.guardrail.effective_enabled.side_effect = lambda c: c not in disabled
    cfg.application_protection = ApplicationProtectionConfig()
    cfg.ai_discovery = AIDiscoveryConfig()
    cfg.data_dir = ""
    return cfg


def _render(cfg) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # No bound health snapshot → config-only roster.
        _print_agents(cfg)
    return buf.getvalue()


class TestPrintAgentsRoster(unittest.TestCase):
    def test_single_connector_uses_same_roster(self):
        # Uniform UX: a single-connector install renders the SAME "Agents"
        # section as a fan-out install (one row), not a special "Agent:" block.
        out = _render(_cfg(["codex"], modes={"codex": "action"}))
        self.assertIn("Agents", out)
        self.assertIn("1 active", out)
        self.assertIn("Codex (codex)", out)
        self.assertIn("mode=action", out)

    def test_roster_reports_effective_fail_mode_and_provenance(self):
        report = {
            "effective": "open",
            "provenance": "process-env",
        }
        with patch.object(cmd_status, "_effective_status_fail_mode", return_value=report):
            out = _render(_cfg(["codex"], modes={"codex": "action"}))

        self.assertIn("fail-mode=open", out)
        self.assertIn("provenance=process-env", out)

    def test_zero_connectors_shows_no_active(self):
        out = _render(_cfg([]))
        self.assertIn("Agents", out)
        self.assertIn("no active connector", out)

    def test_multi_lists_each_connector_with_mode(self):
        out = _render(_cfg(["codex", "cursor"], modes={"codex": "observe", "cursor": "action"}))
        # The section is now labeled "Agents", not "Connectors".
        self.assertIn("Agents", out)
        self.assertNotIn("Connectors", out)
        self.assertIn("2 active", out)
        self.assertIn("Codex (codex)", out)
        self.assertIn("mode=observe", out)
        self.assertIn("Cursor (cursor)", out)
        self.assertIn("mode=action", out)

    def test_blank_connector_names_filtered(self):
        out = _render(_cfg(["codex", "", "cursor"]))
        # The empty entry is dropped, leaving two real connectors.
        self.assertIn("2 active", out)

    def test_effective_mode_exception_falls_back_to_placeholder(self):
        cfg = _cfg(["codex", "cursor"])
        cfg.guardrail.effective_mode.side_effect = RuntimeError("boom")
        out = _render(cfg)
        # The helper must not raise; it renders a placeholder mode.
        self.assertIn("mode=?", out)

    def test_disabled_connector_marked_and_excluded_from_active_count(self):
        # ``guardrail disable --connector codex`` sets enabled=false; the roster
        # must (a) count only the still-enforcing connector as active and report
        # the disabled one separately, and (b) mark it DISABLED rather than
        # letting it read like a connector the sidecar merely hasn't surfaced.
        out = _render(
            _cfg(
                ["codex", "cursor"],
                modes={"codex": "action", "cursor": "action"},
                disabled={"codex"},
            )
        )
        self.assertIn("1 active", out)
        self.assertIn("1 disabled", out)
        self.assertIn("DISABLED", out)
        self.assertIn("Codex (codex)", out)


def _render_live(cfg, health: dict) -> str:
    """Render the real connector parsing path against bound health."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_status._print_agents(cfg, health=health)
    return buf.getvalue()


@contextlib.contextmanager
def _owned_status_endpoint(
    runtime_data_dir: str,
    health: dict,
    expected_token: str,
    *,
    runtime_pid: object = 4242,
):
    """Serve a disposable loopback status/health endpoint owned by this test."""
    seen_paths: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            seen_paths.append(self.path)
            if self.path == "/status":
                if self.headers.get("Authorization") == f"Bearer {expected_token}":
                    payload = {
                        "runtime": {"pid": runtime_pid, "data_dir": runtime_data_dir},
                        "health": health,
                    }
                    status = 200
                else:
                    payload = {"error": "unauthorized"}
                    status = 401
            elif self.path == "/health":
                payload = health
                status = 200
            else:
                payload = {"error": "not found"}
                status = 404
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, seen_paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class TestPrintAgentsLiveCounters(unittest.TestCase):
    """With bound ``connectors[]`` health present, every active agent renders its
    own live counters — there is no privileged "primary" tally."""

    def test_cursor_disclosure_has_enabled_disabled_and_config_live_parity(self):
        disclosure = "priority-conflict-detection=unavailable (none inferred)"
        live_health = {
            "connectors": [
                {"name": "codex", "state": "running"},
                {"name": "cursor", "state": "running"},
            ]
        }

        for enabled in (True, False):
            for health in (None, live_health):
                with self.subTest(enabled=enabled, live=health is not None):
                    disabled = set() if enabled else {"cursor"}
                    cfg = _cfg(["codex", "cursor"], disabled=disabled)
                    out = _render(cfg) if health is None else _render_live(cfg, health)
                    cursor_row = next(line for line in out.splitlines() if "Cursor (cursor)" in line)
                    codex_row = next(line for line in out.splitlines() if "Codex (codex)" in line)

                    self.assertIn(disclosure, cursor_row)
                    self.assertNotIn("priority-conflict-detection", codex_row)
                    if enabled:
                        self.assertNotIn("DISABLED", cursor_row)
                        if health is not None:
                            self.assertIn("RUNNING", cursor_row)
                    else:
                        self.assertIn("DISABLED", cursor_row)
                        self.assertNotIn("RUNNING", cursor_row)

    def test_each_connector_renders_its_own_counters(self):
        health = {
            "connectors": [
                {"name": "codex", "state": "running", "requests": 5, "tool_blocks": 2},
                {"name": "cursor", "state": "running", "requests": 9, "tool_blocks": 1},
            ]
        }
        cfg = _cfg(["codex", "cursor"], modes={"codex": "observe", "cursor": "action"})
        out = _render_live(cfg, health)
        # Distinct per-connector tallies (not a single shared/global number).
        self.assertIn("requests: 5", out)
        self.assertIn("requests: 9", out)
        self.assertIn("tool blocks: 2", out)
        self.assertIn("tool blocks: 1", out)

    def test_connector_without_health_entry_falls_back_to_config_line(self):
        # Only codex has a live entry; cursor must still appear (config-only).
        health = {"connectors": [{"name": "codex", "state": "running", "requests": 3}]}
        cfg = _cfg(["codex", "cursor"])
        out = _render_live(cfg, health)
        self.assertIn("requests: 3", out)
        self.assertIn("Cursor (cursor)", out)

    def test_old_gateway_singular_connector_is_folded_in(self):
        # Pre-multi gateway reports only the singular `connector`; it still gets
        # counters via the fallback in _fetch_health_connectors.
        health = {"connector": {"name": "codex", "state": "running", "requests": 7}}
        cfg = _cfg(["codex", "cursor"])
        out = _render_live(cfg, health)
        self.assertIn("requests: 7", out)

    def test_automatic_connector_from_health_is_listed_with_source(self):
        health = {
            "connectors": [
                {"name": "codex", "state": "running", "source": "automatic", "requests": 2},
            ]
        }
        cfg = _cfg([])
        out = _render_live(cfg, health)
        self.assertIn("Agents", out)
        self.assertIn("Codex (codex)", out)
        self.assertIn("source=automatic", out)
        self.assertIn("requests: 2", out)

    def test_omnigent_running_adapter_is_degraded_when_effective_policy_is_unverified(self):
        health = {"connectors": [{"name": "omnigent", "state": "running", "requests": 0}]}
        cfg = _cfg(["omnigent"], modes={"omnigent": "action"})
        with patch(
            "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
            return_value=("warn", "server record is stale; effective policy config is unverified"),
        ):
            out = _render_live(cfg, health)

        self.assertIn("DEGRADED", out)
        self.assertNotIn("RUNNING", out)
        self.assertIn("effective policy config is unverified", out)

    def test_omnigent_verified_native_degraded_policy_remains_running(self):
        health = {"connectors": [{"name": "omnigent", "state": "running", "requests": 0}]}
        cfg = _cfg(["omnigent"], modes={"omnigent": "action"})
        with patch(
            "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
            return_value=("pass", "live effective config verified through --config"),
        ):
            out = _render_live(cfg, health)

        self.assertIn("RUNNING", out)
        self.assertNotIn("DEGRADED", out)
        self.assertIn("live effective config verified", out)

    def test_opencode_running_requires_fresh_current_generation_heartbeat(self):
        now = datetime.now(timezone.utc)
        health = {
            "started_at": (now - timedelta(hours=1)).isoformat(),
            "connectors": [
                {
                    "name": "opencode",
                    "state": "running",
                    "source": "manual",
                    "load_heartbeat_at": (now - timedelta(minutes=1)).isoformat(),
                }
            ],
        }
        out = _render_live(_cfg(["opencode"]), health)

        self.assertIn("RUNNING", out)
        self.assertIn("authenticated load heartbeat is fresh", out)

    def test_opencode_stale_heartbeat_is_degraded_without_guessing_pure(self):
        now = datetime.now(timezone.utc)
        health = {
            "started_at": (now - timedelta(hours=1)).isoformat(),
            "connectors": [
                {
                    "name": "opencode",
                    "state": "running",
                    "source": "manual",
                    "load_heartbeat_at": (now - timedelta(minutes=16)).isoformat(),
                }
            ],
        }
        out = _render_live(_cfg(["opencode"]), health)

        self.assertIn("DEGRADED", out)
        self.assertNotIn("RUNNING", out)
        self.assertIn("stale", out)
        self.assertNotIn("--pure", out)

    def test_opencode_noncanonical_registration_sources_are_degraded(self):
        now = datetime.now(timezone.utc)
        for source in ("MANUAL", "Automatic", " manual", "automatic ", 7):
            health = {
                "started_at": (now - timedelta(hours=1)).isoformat(),
                "connectors": [
                    {
                        "name": "opencode",
                        "state": "running",
                        "source": source,
                        "load_heartbeat_at": (now - timedelta(minutes=1)).isoformat(),
                    }
                ],
            }
            with self.subTest(source=source):
                out = _render_live(_cfg(["opencode"]), health)
                self.assertIn("DEGRADED", out)
                self.assertNotIn("RUNNING", out)
                self.assertIn("manual or automatic OpenCode registration", out)

    def test_opencode_gateway_unavailable_is_explicitly_degraded(self):
        out = _render(_cfg(["opencode"]))

        self.assertIn("DEGRADED", out)
        self.assertIn("authenticated gateway status is unavailable", out)
        self.assertNotIn("--pure", out)


class TestOpenCodeRuntimeTruth(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
        self.started = self.now - timedelta(hours=1)

    def _state(
        self,
        heartbeat: object,
        *,
        state: str = "running",
        source: object = "manual",
    ) -> tuple[str, str]:
        return cmd_status._opencode_runtime_truth(
            {
                "name": "opencode",
                "state": state,
                "source": source,
                "load_heartbeat_at": heartbeat,
            },
            gateway_started_at=self.started.isoformat(),
            now=self.now,
        )

    def test_manual_and_automatic_registration_with_fresh_heartbeat_are_healthy(self):
        for source in ("manual", "automatic"):
            with self.subTest(source=source):
                state, detail = self._state(self.now.isoformat(), source=source)
                self.assertEqual(state, "running")
                self.assertIn("authenticated load heartbeat is fresh", detail)

    def test_source_must_be_an_exact_gateway_registration_literal(self):
        for source in (
            "",
            "discovered",
            "operator",
            "MANUAL",
            "Automatic",
            " manual",
            "manual ",
            "\tautomatic",
            "automatic\n",
            7,
            None,
        ):
            with self.subTest(source=source):
                state, detail = self._state(self.now.isoformat(), source=source)
                self.assertEqual(state, "degraded")
                self.assertIn("manual or automatic OpenCode registration", detail)

    def test_missing_malformed_and_stale_are_unverified(self):
        for heartbeat, reason in (
            ("", "no authenticated load heartbeat"),
            ("not-a-timestamp", "malformed"),
            ((self.now - timedelta(minutes=16)).isoformat(), "stale"),
        ):
            with self.subTest(heartbeat=heartbeat):
                state, detail = self._state(heartbeat)
                self.assertEqual(state, "degraded")
                self.assertIn(reason, detail)
                self.assertNotIn("pure", detail.lower())

    def test_heartbeat_must_belong_to_current_gateway_generation(self):
        state, detail = self._state((self.started - timedelta(seconds=1)).isoformat())

        self.assertEqual(state, "degraded")
        self.assertIn("predates the current gateway generation", detail)

    def test_heartbeat_freshness_and_clock_skew_boundaries_are_inclusive(self):
        # The plugin has no periodic timer: after exactly fifteen idle minutes
        # the last authenticated load remains within the operator-evidence
        # window, then becomes unverified immediately beyond that boundary.
        state, _detail = self._state((self.now - timedelta(minutes=15)).isoformat())
        self.assertEqual(state, "running")
        state, detail = self._state((self.now - timedelta(minutes=15, microseconds=1)).isoformat())
        self.assertEqual(state, "degraded")
        self.assertIn("stale", detail)

        state, _detail = self._state((self.now + timedelta(minutes=5)).isoformat())
        self.assertEqual(state, "running")
        state, detail = self._state((self.now + timedelta(minutes=5, microseconds=1)).isoformat())
        self.assertEqual(state, "degraded")
        self.assertIn("ahead of the local clock", detail)

    def test_terminal_client_states_remain_terminal_not_pure_or_drifted(self):
        for terminal in ("stopped", "offline", "down", "disabled"):
            with self.subTest(state=terminal):
                state, detail = self._state("", state=terminal, source="")
                self.assertEqual(state, terminal)
                self.assertIn(f"reports {terminal}", detail)
                self.assertNotIn("pure", detail.lower())
                self.assertNotIn("drift", detail.lower())

    def test_gateway_unavailable_overrides_cached_running_state(self):
        state, detail = cmd_status._opencode_runtime_truth(
            {
                "name": "opencode",
                "state": "running",
                "source": "manual",
                "load_heartbeat_at": self.now.isoformat(),
            },
            gateway_started_at=self.started.isoformat(),
            gateway_available=False,
            now=self.now,
        )

        self.assertEqual(state, "degraded")
        self.assertIn("gateway status is unavailable", detail)


class TestOmnigentJsonReadinessParity(unittest.TestCase):
    def test_manual_plural_roster_degrades_stale_pid_and_preserves_opencode_truth(self):
        now = datetime.now(timezone.utc)
        health = {
            "started_at": (now - timedelta(hours=1)).isoformat(),
            "connectors": [
                {"name": "omnigent", "state": "running", "source": "manual"},
                {
                    "name": "opencode",
                    "state": "running",
                    "source": "manual",
                    "load_heartbeat_at": now.isoformat(),
                },
            ],
        }
        cfg = _cfg(["omnigent", "opencode"])
        detail = "server record is stale; effective policy config is unverified"
        with patch(
            "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
            return_value=("warn", detail),
        ) as readiness:
            rows = cmd_status._connector_roster(cfg, health=health)

        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["omnigent"]["state"], "degraded")
        self.assertEqual(by_name["omnigent"]["readiness_detail"], detail)
        self.assertEqual(by_name["omnigent"]["source"], "manual")
        self.assertEqual(by_name["opencode"]["state"], "running")
        self.assertIn("authenticated load heartbeat is fresh", by_name["opencode"]["runtime_detail"])
        readiness.assert_called_once_with(cfg)

    def test_automatic_singular_roster_degrades_live_config_mismatch(self):
        health = {
            "connector": {
                "name": "omnigent",
                "state": "running",
                "source": "automatic",
            }
        }
        cfg = _cfg([])
        detail = "live --config selects C:\\other\\config.yaml, not managed C:\\managed\\config.yaml"
        with patch(
            "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
            return_value=("fail", detail),
        ):
            rows = cmd_status._connector_roster(cfg, health=health)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "omnigent")
        self.assertEqual(rows[0]["source"], "automatic")
        self.assertEqual(rows[0]["state"], "degraded")
        self.assertEqual(rows[0]["readiness_detail"], detail)

    def test_verified_runtime_remains_running_in_json_roster(self):
        health = {"connectors": [{"name": "omnigent", "state": "running"}]}
        cfg = _cfg(["omnigent"])
        detail = "live effective config verified through --config"
        with patch(
            "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
            return_value=("pass", detail),
        ):
            rows = cmd_status._connector_roster(cfg, health=health)

        self.assertEqual(rows[0]["state"], "running")
        self.assertEqual(rows[0]["readiness_detail"], detail)

    def test_unavailable_readiness_is_degraded_without_failing_status(self):
        with patch(
            "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
            side_effect=OSError("evidence unavailable"),
        ):
            state, detail = cmd_status._omnigent_effective_runtime_state(
                _cfg(["omnigent"]),
                "running",
            )

        self.assertEqual(state, "degraded")
        self.assertIn("policy readiness unavailable", detail)


class TestStatusRuntimeProcessIdentity(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = MagicMock()
        self.cfg.data_dir = os.path.abspath("D:/status-runtime-fixture")

    def _fetch(self, runtime_pid: object, *, trusted_pid: int = 4242) -> dict | None:
        health = {"started_at": "2026-08-04T11:00:00Z", "connectors": []}
        client = MagicMock()
        client.status.return_value = {
            "runtime": {"pid": runtime_pid, "data_dir": self.cfg.data_dir},
            "health": health,
        }
        with patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=MagicMock(trusted=True, pid=trusted_pid, detail=""),
        ):
            return cmd_status._fetch_runtime_bound_health(client, self.cfg)

    def test_correct_verified_listener_pid_accepts_authenticated_health(self):
        self.assertIsNotNone(self._fetch(4242))

    def test_noncanonical_wrong_and_foreign_same_home_pid_are_unavailable(self):
        for runtime_pid in (
            4242.9,
            4242.0,
            True,
            None,
            {},
            [],
            "not-a-pid",
            0,
            -1,
            "4242",
            "004242",
            "+4242",
            " 4242 ",
            4241,
            9999,
        ):
            with self.subTest(runtime_pid=runtime_pid):
                self.assertIsNone(self._fetch(runtime_pid))

    def test_unverified_listener_is_rejected_before_authenticated_request(self):
        client = MagicMock()
        with patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=MagicMock(trusted=False, pid=0, detail="foreign listener"),
        ):
            self.assertIsNone(cmd_status._fetch_runtime_bound_health(client, self.cfg))
        client.status.assert_not_called()


class TestApplicationProtectionStatus(unittest.TestCase):
    def test_loads_persisted_state_when_sidecar_down(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "application_protection_state.json")
            with open(state_path, "w") as f:
                json.dump(
                    {
                        "enabled": True,
                        "discovered": [{"connector": "codex", "confidence": 0.93}],
                        "active": [{"connector": "codex", "source": "automatic"}],
                        "skipped": [{"connector": "openclaw", "reason": "proxy_connector_setup_only"}],
                        "last_activation_errors": {"cursor": "setup failed"},
                    },
                    f,
                )
            cfg = _cfg([])
            cfg.data_dir = td
            cfg.guardrail = GuardrailConfig()
            cfg.application_protection = ApplicationProtectionConfig()

            state = cmd_status._application_protection_status(cfg)
            self.assertTrue(state["enabled"])
            self.assertEqual(state["active"][0]["connector"], "codex")
            self.assertEqual(state["skipped"][0]["reason"], "proxy_connector_setup_only")
            self.assertEqual(state["last_activation_errors"]["cursor"], "setup failed")
            self.assertEqual(state["guardrail_mode"], "observe")
            self.assertEqual(state["asset_policy_mode"], "observe")
            self.assertFalse(state["require_trusted_binary_paths"])

    def test_live_health_details_override_persisted_state(self):
        cfg = _cfg([])
        cfg.guardrail = GuardrailConfig()
        cfg.application_protection = ApplicationProtectionConfig()
        health = {
            "application_protection": {
                "state": "running",
                "details": {
                    "enabled": True,
                    "active": [{"connector": "cursor", "source": "automatic"}],
                    "skipped": [{"connector": "openclaw", "reason": "proxy_connector_setup_only"}],
                    "last_errors": {"codex": "activation failed"},
                    "guardrail_mode": "action",
                    "asset_policy_mode": "action",
                    "require_trusted_binary_paths": True,
                    "trusted_binary_prefixes": ["/opt/tools"],
                },
            }
        }
        state = cmd_status._application_protection_status(cfg, health=health)
        self.assertEqual(state["health_state"], "running")
        self.assertEqual(state["active"][0]["connector"], "cursor")
        self.assertEqual(state["last_activation_errors"]["codex"], "activation failed")
        self.assertEqual(state["guardrail_mode"], "action")
        self.assertEqual(state["asset_policy_mode"], "action")
        self.assertTrue(state["require_trusted_binary_paths"])
        self.assertEqual(state["trusted_binary_prefixes"], ["/opt/tools"])


class TestHookGuardianStatus(unittest.TestCase):
    def test_loads_persisted_guardian_state(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "hook_guardian_state.json")
            with open(state_path, "w") as f:
                json.dump(
                    {
                        "version": 1,
                        "updated_at": "2026-06-23T12:00:00Z",
                        "manifest": "/etc/defenseclaw/hook-guardian/targets.yaml",
                        "ok": False,
                        "target_count": 2,
                        "success_count": 1,
                        "failure_count": 1,
                        "results": [
                            {"user": "alice", "connector": "codex", "ok": True},
                            {
                                "user": "bob",
                                "connector": "claudecode",
                                "ok": False,
                                "error": "hook config file missing",
                            },
                        ],
                    },
                    f,
                )
            cfg = _cfg([])
            cfg.data_dir = td

            state = cmd_status._hook_guardian_status(cfg)
            self.assertTrue(state["configured"])
            self.assertFalse(state["ok"])
            self.assertEqual(state["success_count"], 1)
            self.assertEqual(state["failure_count"], 1)
            self.assertEqual(state["results"][1]["connector"], "claudecode")

    def test_unconfigured_guardian_state_is_explicit(self):
        import shutil
        import tempfile

        cfg = _cfg([])
        cfg.data_dir = tempfile.mkdtemp()
        try:
            state = cmd_status._hook_guardian_status(cfg)
            self.assertFalse(state["configured"])
            self.assertTrue(state["state_file"].endswith("hook_guardian_state.json"))
        finally:
            shutil.rmtree(cfg.data_dir, ignore_errors=True)


class TestStatusDbErrorSurfacing(unittest.TestCase):
    """SU-05: an audit-DB read error must surface in the Enforcement + Activity
    sections, never silently drop them."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke(self):
        runner = CliRunner()
        with patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None):
            return runner.invoke(status_cmd, [], obj=self.app, catch_exceptions=False)

    def test_db_error_surfaces_and_stays_exit_zero(self):
        self.app.store.get_counts = MagicMock(side_effect=RuntimeError("disk I/O error"))
        result = self._invoke()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # Section headers still render, with a visible error instead of nothing.
        self.assertIn("Enforcement", result.output)
        self.assertIn("Activity", result.output)
        self.assertIn("unavailable", result.output)
        self.assertIn("disk I/O error", result.output)

    def test_healthy_db_shows_counts(self):
        result = self._invoke()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Enforcement", result.output)
        self.assertIn("Blocked skills", result.output)
        self.assertNotIn("disk I/O error", result.output)


class TestStatusJson(unittest.TestCase):
    """SU-13: ``status --json`` emits a machine-readable document."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # Keep unit status tests config-only; runtime provenance has a dedicated
        # disposable-state test in test_fail_mode_runtime.py.
        self.app.cfg.data_dir = ""
        from defenseclaw.config import PerConnectorGuardrailConfig

        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        gc.connectors = {
            "codex": PerConnectorGuardrailConfig(mode="action"),
            "hermes": PerConnectorGuardrailConfig(mode="observe"),
        }

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke_json(self):
        runner = CliRunner()
        with patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None):
            return runner.invoke(status_cmd, ["--json"], obj=self.app, catch_exceptions=False)

    def test_json_is_valid_and_has_core_keys(self):
        managed_config = os.path.join(self.tmp_dir, "managed-config.yaml")
        self.app.cfg.deployment_mode = "managed_enterprise"
        with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": managed_config}):
            result = self._invoke_json()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        doc = json.loads(result.output)
        for key in (
            "environment",
            "scanners",
            "enforcement",
            "activity",
            "connectors",
            "sidecar",
            "native_otlp_delivery",
        ):
            self.assertIn(key, doc)
        self.assertFalse(doc["sidecar"]["running"])
        self.assertEqual(doc["application_protection"]["guardrail_mode"], "observe")
        self.assertFalse(doc["application_protection"]["require_trusted_binary_paths"])
        self.assertEqual(doc["deployment_mode"], "managed_enterprise")
        self.assertEqual(doc["config"], managed_config)
        delivery = json.dumps(doc["native_otlp_delivery"], sort_keys=True)
        self.assertNotIn(self.tmp_dir, delivery)
        self.assertNotIn("token", delivery.lower())

    def test_json_roster_has_per_connector_mode(self):
        result = self._invoke_json()
        doc = json.loads(result.output)
        by_name = {c["name"]: c for c in doc["connectors"]}
        self.assertEqual(by_name["codex"]["mode"], "action")
        self.assertEqual(by_name["hermes"]["mode"], "observe")
        self.assertTrue(by_name["codex"]["enabled"])

    def test_json_cursor_disclosure_has_enabled_disabled_parity(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        expected = {
            "status": "unavailable",
            "conflict_inferred": False,
        }
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                self.app.cfg.guardrail.connectors["cursor"] = PerConnectorGuardrailConfig(
                    mode="action",
                    enabled=enabled,
                )
                result = self._invoke_json()
                self.assertEqual(result.exit_code, 0, msg=result.output)
                by_name = {row["name"]: row for row in json.loads(result.output)["connectors"]}

                self.assertEqual(by_name["cursor"]["enabled"], enabled)
                self.assertEqual(by_name["cursor"]["priority_conflict_detection"], expected)
                self.assertNotIn("priority_conflict_detection", by_name["codex"])
                self.assertNotIn("priority_conflict_detection", by_name["hermes"])

    def test_json_roster_reports_canonical_fail_mode_projection(self):
        report = {
            "effective": "closed",
            "provenance": "windows-sidecar",
            "configured": "open",
            "desired": "open",
            "runtime": "closed",
            "current": False,
            "drift": ["windows-sidecar-closed"],
            "sources": [],
        }
        with patch.object(cmd_status, "_effective_status_fail_mode", return_value=report):
            result = self._invoke_json()

        doc = json.loads(result.output)
        by_name = {c["name"]: c for c in doc["connectors"]}
        self.assertEqual(by_name["codex"]["fail_mode"], report)

    def test_json_db_error_is_explicit_null_not_dropped(self):
        self.app.store.get_counts = MagicMock(side_effect=RuntimeError("locked"))
        result = self._invoke_json()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        doc = json.loads(result.output)
        self.assertIsNone(doc["enforcement"])
        self.assertIsNone(doc["activity"])
        self.assertEqual(doc["audit_db_error"], "locked")


class TestStatusProfileIdentity(unittest.TestCase):
    def test_status_ignores_foreign_loopback_health_and_accepts_matching_profile(self):
        with tempfile.TemporaryDirectory(prefix="win-aud-078-") as root:
            isolated_home = Path(root) / "isolated-home"
            ambient_home = Path(root) / "ambient-home"
            isolated_home.mkdir()
            ambient_home.mkdir()
            app, app_tmp, db_path = make_app_context(str(isolated_home))
            runner = CliRunner()
            isolated_config = isolated_home / "config.yaml"
            owned_token = f"owned-endpoint-{os.getpid()}-{id(app)}"
            env = {
                "DEFENSECLAW_HOME": str(isolated_home),
                "DEFENSECLAW_CONFIG": str(isolated_config),
                "DEFENSECLAW_GATEWAY_TOKEN": owned_token,
                "OPENCLAW_GATEWAY_TOKEN": "",
            }
            foreign_marker = "foreign-profile-only"
            foreign_state_file = ambient_home / "application_protection_state.json"
            foreign_health = {
                "connectors": [{"name": foreign_marker, "state": "running", "requests": 99}],
                "application_protection": {
                    "state": "running",
                    "details": {
                        "active": [{"connector": foreign_marker, "source": "automatic"}],
                        "state_file": str(foreign_state_file),
                    },
                },
            }

            listener_patch = patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                return_value=MagicMock(trusted=True, pid=4242, detail=""),
            )
            listener_patch.start()
            try:
                with _owned_status_endpoint(str(ambient_home), foreign_health, owned_token) as (port, seen):
                    app.cfg.gateway.api_port = port
                    with patch.dict(os.environ, env, clear=False):
                        human = runner.invoke(status_cmd, [], obj=app, catch_exceptions=False)
                        result = runner.invoke(status_cmd, ["--json"], obj=app, catch_exceptions=False)
                self.assertEqual(human.exit_code, 0, msg=human.output)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(seen, ["/status", "/status"])
                self.assertIn("not running", human.output)
                self.assertNotIn(foreign_marker, human.output)
                self.assertNotIn(str(ambient_home), human.output)
                doc = json.loads(result.output)
                rendered = json.dumps(doc)
                self.assertFalse(doc["sidecar"]["running"])
                self.assertNotIn(foreign_marker, rendered)
                self.assertNotIn(str(ambient_home), rendered)
                self.assertEqual(
                    os.path.normcase(doc["application_protection"]["state_file"]),
                    os.path.normcase(str(isolated_home / "application_protection_state.json")),
                )

                matching_marker = "matching-profile-only"
                matching_health = {
                    "connectors": [{"name": matching_marker, "state": "running", "requests": 7}],
                    "application_protection": {
                        "state": "running",
                        "details": {
                            "active": [{"connector": matching_marker, "source": "automatic"}],
                            "state_file": str(isolated_home / "application_protection_state.json"),
                        },
                    },
                }
                with _owned_status_endpoint(str(isolated_home), matching_health, owned_token) as (port, seen):
                    app.cfg.gateway.api_port = port
                    with patch.dict(os.environ, env, clear=False):
                        result = runner.invoke(status_cmd, ["--json"], obj=app, catch_exceptions=False)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(seen, ["/status"])
                doc = json.loads(result.output)
                self.assertTrue(doc["sidecar"]["running"])
                self.assertIn(matching_marker, json.dumps(doc))
            finally:
                listener_patch.stop()
                cleanup_app(app, db_path, app_tmp)


if __name__ == "__main__":
    unittest.main()
