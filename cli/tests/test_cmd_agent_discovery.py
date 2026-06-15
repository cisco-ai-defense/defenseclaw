# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw agent discovery {enable,disable,status,setup,scan}``.

These commands are the one-shot wrapper around ``ai_discovery.enabled``
+ gateway restart + initial scan. Coverage focuses on:

* Idempotency (already-enabled / already-disabled short-circuits).
* No restart unless the operator explicitly opted in (or accepted the
  default), and never on save failure.
* Drift detection between on-disk config and the live sidecar's
  ``GET /api/v1/ai-usage`` response.
* The post-enable scan is best-effort — connection failures must not
  abort the command, otherwise a flaky restart races into a hard CLI
  failure for the operator.
"""

from __future__ import annotations

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


def _make_ctx(*, enabled: bool = False, connector: str = "openclaw",
              mode: str = "enhanced", token: str = "secret-token") -> AppContext:
    """Build a minimal AppContext that the discovery commands can drive.

    Mirrors ``cli/tests/test_cmd_guardrail.make_ctx`` so the two test
    suites share fixtures shape and a reviewer reading both can see the
    parity between ``guardrail enable/disable`` and ``agent discovery
    enable/disable``.
    """
    ai_cfg = SimpleNamespace(
        enabled=enabled,
        mode=mode,
        scan_interval_min=5,
        process_interval_s=60,
        scan_roots=["~"],
        signature_packs=[],
        disabled_signature_ids=[],
        include_shell_history=True,
        include_package_manifests=True,
        include_env_var_names=True,
        include_network_domains=True,
        max_files_per_scan=1000,
        max_file_bytes=512 * 1024,
        emit_otel=True,
        allow_workspace_signatures=False,
        store_raw_local_paths=False,
    )
    cfg = SimpleNamespace(
        ai_discovery=ai_cfg,
        guardrail=SimpleNamespace(connector=connector),
        claw=SimpleNamespace(mode=connector),
        data_dir="/tmp/dc",
        gateway=SimpleNamespace(host="127.0.0.1", port=18789, token=token),
        llm=SimpleNamespace(model="", api_key_env=""),
    )

    def active_connector():
        return connector

    cfg.active_connector = active_connector
    cfg.save = MagicMock()

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    app.logger.log_action = MagicMock()
    return app


def _resolve_target_stub(app, *, gateway_host=None, gateway_port=None, gateway_token_env=None):
    return ("127.0.0.1", 18970, "secret-token")


class ResolveConnectorTests(unittest.TestCase):
    def test_uses_active_connector_method(self):
        cfg = SimpleNamespace()
        cfg.active_connector = lambda: "Codex"
        self.assertEqual(cmd_agent._resolve_connector_for_restart(cfg), "codex")

    def test_falls_back_to_guardrail_connector(self):
        cfg = SimpleNamespace(
            guardrail=SimpleNamespace(connector="claudecode"),
            active_connector=lambda: "",
        )
        self.assertEqual(cmd_agent._resolve_connector_for_restart(cfg), "claudecode")

    def test_falls_back_to_claw_mode(self):
        cfg = SimpleNamespace(
            claw=SimpleNamespace(mode="zeptoclaw"),
            guardrail=SimpleNamespace(connector=""),
            active_connector=lambda: "",
        )
        self.assertEqual(cmd_agent._resolve_connector_for_restart(cfg), "zeptoclaw")

    def test_method_exception_falls_back(self):
        cfg = SimpleNamespace(
            guardrail=SimpleNamespace(connector="hermes"),
            active_connector=lambda: (_ for _ in ()).throw(RuntimeError("x")),
        )
        self.assertEqual(cmd_agent._resolve_connector_for_restart(cfg), "hermes")


class NormalizeScanRootsTests(unittest.TestCase):
    def test_splits_on_commas_and_strips(self):
        self.assertEqual(
            cmd_agent._normalize_scan_roots("~,  /workspace, ~/projects "),
            ["~", "/workspace", "~/projects"],
        )

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(cmd_agent._normalize_scan_roots(""), [])
        self.assertEqual(cmd_agent._normalize_scan_roots(",,,"), [])


class DiscoveryEnableTests(unittest.TestCase):
    def test_already_enabled_short_circuits(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(cmd_agent.discovery_enable, ["--yes", "--no-scan"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already enabled", result.output)
        # Idempotent path must not bounce the gateway or rewrite YAML —
        # otherwise re-running the wizard would cause needless sidecar
        # downtime.
        restart_mock.assert_not_called()
        app.cfg.save.assert_not_called()

    def test_persists_and_restarts(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False, connector="codex")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.ai_discovery.enabled)
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        # Restart MUST propagate the active connector — otherwise the
        # gateway tears down the wrong adapter on its way back up. This
        # is the same invariant the guardrail enable/disable tests
        # enforce.
        self.assertEqual(restart_mock.call_args.kwargs.get("connector"), "codex")
        # --no-scan suppresses the post-enable scan; with --no-scan we
        # must not even attempt the network call.
        scan_mock.assert_not_called()
        app.logger.log_action.assert_called_once()

    def test_no_restart_implies_no_scan(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-restart"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(app.cfg.ai_discovery.enabled)
        # Without a restart the sidecar never picks up the new config,
        # so triggering a scan would only hit the stale process and
        # report enabled=false. The command must auto-suppress the scan
        # rather than firing a misleading network call.
        restart_mock.assert_not_called()
        scan_mock.assert_not_called()
        self.assertIn("--no-restart implies --no-scan", result.output)

    def test_save_failure_aborts_without_restart(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        app.cfg.save.side_effect = OSError("disk full")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(cmd_agent.discovery_enable, ["--yes"], obj=app)
        self.assertNotEqual(result.exit_code, 0)
        # If config save fails the on-disk flag stays unset; bouncing
        # the sidecar would either no-op or run with stale config —
        # either way the operator would be confused. Stay silent.
        restart_mock.assert_not_called()
        scan_mock.assert_not_called()

    def test_declined_aborts_without_changes(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        result = runner.invoke(cmd_agent.discovery_enable, [], input="n\n", obj=app)
        self.assertNotEqual(result.exit_code, 0)
        self.assertFalse(app.cfg.ai_discovery.enabled)
        app.cfg.save.assert_not_called()

    def test_mode_override_is_persisted(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False, mode="enhanced")
        with patch("defenseclaw.commands.cmd_setup._restart_services"), \
                patch.object(cmd_agent, "_trigger_post_enable_scan"):
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan", "--mode", "passive"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.ai_discovery.mode, "passive")

    def test_scan_roots_override_is_normalized(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        with patch("defenseclaw.commands.cmd_setup._restart_services"), \
                patch.object(cmd_agent, "_trigger_post_enable_scan"):
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan", "--scan-roots", " ~ , /workspace ,, ~/proj "],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(
            app.cfg.ai_discovery.scan_roots,
            ["~", "/workspace", "~/proj"],
        )


class DiscoveryDisableTests(unittest.TestCase):
    def test_already_disabled_short_circuits(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(cmd_agent.discovery_disable, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already disabled", result.output)
        restart_mock.assert_not_called()
        app.cfg.save.assert_not_called()

    def test_persists_and_restarts(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True, connector="claudecode")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(cmd_agent.discovery_disable, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.ai_discovery.enabled)
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        self.assertEqual(restart_mock.call_args.kwargs.get("connector"), "claudecode")

    def test_no_restart_skips_gateway_call(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_agent.discovery_disable,
                ["--yes", "--no-restart"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.ai_discovery.enabled)
        restart_mock.assert_not_called()

    def test_save_failure_aborts_without_restart(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        app.cfg.save.side_effect = OSError("read-only")
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(cmd_agent.discovery_disable, ["--yes"], obj=app)
        self.assertNotEqual(result.exit_code, 0)
        restart_mock.assert_not_called()


class DiscoveryStatusTests(unittest.TestCase):
    def test_json_includes_drift_when_sidecar_disagrees(self):
        import json

        runner = CliRunner()
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def ai_usage(self):
                # Sidecar booted before the operator flipped the flag —
                # this is the exact "configured-on, sidecar-stale" case
                # that produces the HTTP 503 from `agent usage --refresh`.
                return {"enabled": False, "summary": {}}

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(
                cmd_agent.discovery_status,
                ["--json"],
                obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["on_disk"]["enabled"])
        self.assertTrue(payload["live"]["reachable"])
        self.assertFalse(payload["live"]["enabled"])
        self.assertTrue(payload["drift"])

    def test_table_warns_on_drift(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def ai_usage(self):
                return {"enabled": False, "summary": {}}

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(
                cmd_agent.discovery_status,
                [],
                obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Drift", result.output)

    def test_table_handles_unreachable_sidecar(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def ai_usage(self):
                raise requests.ConnectionError("connection refused")

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(
                cmd_agent.discovery_status,
                [],
                obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("sidecar unavailable", result.output)
        # Unreachable means we cannot detect drift — the warning must
        # NOT fire (it would be noise when the operator already knows
        # the sidecar is down).
        self.assertNotIn("Drift:", result.output)


class TriggerPostEnableScanTests(unittest.TestCase):
    def test_success_prints_summary(self):
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                return {
                    "enabled": True,
                    "summary": {"active_signals": 3, "new_signals": 1, "files_scanned": 12},
                    "signals": [],
                }

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient), \
                patch("defenseclaw.commands.cmd_agent.time.sleep"):
            runner = CliRunner()
            with runner.isolation() as (out, _err, _input):
                cmd_agent._trigger_post_enable_scan(
                    app,
                    gateway_host=None,
                    gateway_port=None,
                    gateway_token_env=None,
                )
                output = out.getvalue().decode()

        self.assertIn("Initial scan complete", output)
        self.assertIn("active=3", output)

    def test_503_triggers_retry_then_warns(self):
        app = _make_ctx(enabled=True)
        attempts = {"n": 0}

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                # Every call fails with 503 — sidecar is mid-restart and
                # never finishes binding. We expect the helper to retry
                # the configured number of times, then surface a single
                # warning instead of crashing the enable flow.
                attempts["n"] += 1
                resp = MagicMock(status_code=503)
                exc = requests.HTTPError("boot")
                exc.response = resp
                raise exc

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient), \
                patch("defenseclaw.commands.cmd_agent.time.sleep"):
            runner = CliRunner()
            with runner.isolation() as (out, _err, _input):
                cmd_agent._trigger_post_enable_scan(
                    app,
                    gateway_host=None,
                    gateway_port=None,
                    gateway_token_env=None,
                )
                output = out.getvalue().decode()

        # Four delays configured → expect at least 2 attempts (the helper
        # retries on 503). The exact count is an implementation detail
        # but we MUST never silently swallow without warning.
        self.assertGreaterEqual(attempts["n"], 2)
        self.assertIn("Could not run an initial scan", output)


class RequireLoadedConfigTests(unittest.TestCase):
    """Regression coverage for the pre-init / lazy-load path.

    The ``agent`` Click group is in :data:`defenseclaw.main.SKIP_LOAD_COMMANDS`,
    so ``app.cfg`` arrives as ``None`` for every ``agent ...`` subcommand
    until something explicitly loads it. Without :func:`_require_loaded_config`
    we used to crash with ``AttributeError: 'NoneType' object has no
    attribute 'ai_discovery'`` — an awful UX for a one-shot toggle.
    """

    def test_returns_existing_cfg_when_already_loaded(self):
        app = _make_ctx(enabled=False)
        original = app.cfg
        self.assertIs(cmd_agent._require_loaded_config(app), original)

    def test_lazy_loads_cfg_when_app_cfg_is_none(self):
        app = AppContext()
        self.assertIsNone(app.cfg)
        sentinel = SimpleNamespace(name="loaded")
        with patch("defenseclaw.config.load", return_value=sentinel) as load_mock:
            result = cmd_agent._require_loaded_config(app)
        load_mock.assert_called_once()
        # Lazy-load also caches on the AppContext so subsequent calls
        # within the same invocation share the same Config instance —
        # otherwise discovery_enable would load twice and the second
        # load could observe a freshly-saved file mid-flow.
        self.assertIs(result, sentinel)
        self.assertIs(app.cfg, sentinel)

    def test_load_failure_raises_clickexception_not_attributeerror(self):
        app = AppContext()
        with patch(
            "defenseclaw.config.load",
            side_effect=RuntimeError("config.yaml is malformed"),
        ):
            with self.assertRaises(click_exception_type()) as ctx:
                cmd_agent._require_loaded_config(app)
        # We deliberately surface a friendly remediation pointing at
        # ``defenseclaw init`` instead of letting the raw RuntimeError
        # bubble up — the operator's mental model for "I can't run a
        # subcommand" should always be "init or doctor", never
        # "decode this stack trace".
        self.assertIn("defenseclaw init", str(ctx.exception.message))


class DiscoveryEnableLazyConfigTests(unittest.TestCase):
    """End-to-end verification that ``discovery enable`` survives the
    pre-init path. Mirrors the user-reported traceback at
    ``cli/defenseclaw/commands/cmd_agent.py:224 ad = cfg.ai_discovery
    AttributeError: 'NoneType' object has no attribute 'ai_discovery'``.
    """

    def test_enable_lazy_loads_when_app_cfg_is_none(self):
        runner = CliRunner()
        app = AppContext()
        self.assertIsNone(app.cfg)
        loaded = _make_ctx(enabled=False).cfg

        with patch("defenseclaw.config.load", return_value=loaded), \
                patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan"],
                obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(loaded.ai_discovery.enabled)
        loaded.save.assert_called_once()
        restart_mock.assert_called_once()
        scan_mock.assert_not_called()

    def test_enable_with_unloadable_config_fails_with_helpful_error(self):
        runner = CliRunner()
        app = AppContext()
        with patch(
            "defenseclaw.config.load",
            side_effect=RuntimeError("yaml: line 5: mapping values are not allowed here"),
        ):
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes"],
                obj=app,
                catch_exceptions=False,
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("defenseclaw init", result.output)
        # Must NOT leak the raw YAML parse error trace — the original
        # bug surfaced as a NoneType AttributeError, which is even
        # less actionable.
        self.assertNotIn("Traceback", result.output)


def click_exception_type():
    import click as _click

    return _click.ClickException


class CommandRegistrationTests(unittest.TestCase):
    def test_discovery_group_registered_under_agent(self):
        names = set(cmd_agent.agent.commands.keys())
        self.assertIn("discovery", names)
        self.assertIn("usage", names)
        self.assertIn("discover", names)

    def test_discovery_group_exposes_subcommands(self):
        names = set(cmd_agent.discovery.commands.keys())
        self.assertEqual(names, {"enable", "disable", "status", "setup", "scan"})


class DiscoveryHelperTests(unittest.TestCase):
    """Direct coverage of the shared mutation pipeline.

    The ``enable`` CLI flag handler and the ``setup`` wizard both feed
    ``_build_discovery_overrides`` → ``_preview_discovery_changes`` →
    ``_apply_discovery_settings``. Pinning the helpers here lets us
    rewrite either CLI surface without losing protection against
    silently-clobbered fields or no-op detection regressions.
    """

    def test_build_skips_none_fields(self):
        out = cmd_agent._build_discovery_overrides(
            mode="passive",
            include_shell_history=False,
        )
        self.assertEqual(
            out,
            {"mode": "passive", "include_shell_history": False},
        )

    def test_build_normalizes_string_scan_roots(self):
        out = cmd_agent._build_discovery_overrides(
            scan_roots=" ~ , /workspace ,, ~/proj ",
        )
        self.assertEqual(out["scan_roots"], ["~", "/workspace", "~/proj"])

    def test_build_passes_through_list_scan_roots(self):
        # The wizard already pre-normalizes via ``_normalize_scan_roots``,
        # so passing a list must not double-normalize (would otherwise
        # crash on .split since lists don't have .split).
        out = cmd_agent._build_discovery_overrides(
            scan_roots=["~", "/etc"],
        )
        self.assertEqual(out["scan_roots"], ["~", "/etc"])

    def test_preview_skips_no_op_overrides(self):
        ad = SimpleNamespace(mode="enhanced", scan_interval_min=5, scan_roots=["~"])
        diff = cmd_agent._preview_discovery_changes(
            ad,
            {"mode": "enhanced", "scan_interval_min": 10, "scan_roots": ["~"]},
        )
        # mode + scan_roots are unchanged; only scan_interval_min must
        # appear. This is the contract that makes "press Enter on
        # everything in setup" produce a no-op.
        self.assertEqual(diff, [("scan_interval_min", 5, 10)])

    def test_apply_writes_in_place(self):
        ad = SimpleNamespace(
            mode="enhanced",
            scan_interval_min=5,
            include_shell_history=True,
            enabled=False,
        )
        cmd_agent._apply_discovery_settings(
            ad,
            {
                "mode": "passive",
                "scan_interval_min": 10,
                "include_shell_history": False,
                # 'enabled' is intentionally part of the override map
                # to prove the applier ignores it — only the
                # enable/disable command itself flips that field.
                "enabled": True,
            },
        )
        self.assertEqual(ad.mode, "passive")
        self.assertEqual(ad.scan_interval_min, 10)
        self.assertFalse(ad.include_shell_history)
        self.assertFalse(ad.enabled)


class DiscoveryEnableFlagsTests(unittest.TestCase):
    """Coverage for the new scriptable flags on ``discovery enable``."""

    def test_persists_advanced_flags(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        with patch("defenseclaw.commands.cmd_setup._restart_services"), \
                patch.object(cmd_agent, "_trigger_post_enable_scan"):
            result = runner.invoke(
                cmd_agent.discovery_enable,
                [
                    "--yes",
                    "--no-scan",
                    "--scan-interval-min", "10",
                    "--process-interval-s", "120",
                    "--max-files-per-scan", "500",
                    "--max-file-bytes", "262144",
                    "--no-include-shell-history",
                    "--no-emit-otel",
                    "--allow-workspace-signatures",
                ],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        ad = app.cfg.ai_discovery
        self.assertEqual(ad.scan_interval_min, 10)
        self.assertEqual(ad.process_interval_s, 120)
        self.assertEqual(ad.max_files_per_scan, 500)
        self.assertEqual(ad.max_file_bytes, 262144)
        self.assertFalse(ad.include_shell_history)
        self.assertFalse(ad.emit_otel)
        self.assertTrue(ad.allow_workspace_signatures)

    def test_rejects_out_of_range_scan_interval(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock:
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan", "--scan-interval-min", "0"],
                obj=app,
            )
        # Click's IntRange should reject 0 (min is 1) before we ever
        # touch the config — keeps a misconfiguration from clobbering
        # ai_discovery.scan_interval_min on disk.
        self.assertNotEqual(result.exit_code, 0)
        restart_mock.assert_not_called()
        app.cfg.save.assert_not_called()

    def test_already_enabled_with_flags_applies_changes(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan", "--scan-interval-min", "15"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # When flags carry actual diffs the command MUST persist the
        # update and bounce the gateway — otherwise an already-enabled
        # install can never tune cadence without disabling first.
        self.assertEqual(app.cfg.ai_discovery.scan_interval_min, 15)
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        scan_mock.assert_not_called()
        # Update path uses the dedicated audit action so SIEMs can
        # tell "discovery toggled" from "discovery tuned".
        details = app.logger.log_action.call_args.args
        self.assertEqual(details[0], "ai_discovery-update")

    def test_already_enabled_without_diff_short_circuits(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        # Same value as already in config → no diff → no save/restart.
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_enable,
                ["--yes", "--no-scan", "--scan-interval-min", "5"],
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already enabled", result.output)
        app.cfg.save.assert_not_called()
        restart_mock.assert_not_called()
        scan_mock.assert_not_called()


class DiscoverySetupTests(unittest.TestCase):
    """Coverage for the interactive ``discovery setup`` wizard.

    We feed ``stdin`` line-by-line so the prompt sequence is part of
    the test contract — re-ordering wizard prompts therefore requires
    updating this script in lock-step, which is the desired tradeoff
    (UX changes get test review).
    """

    # The prompt sequence is:
    #  1. enable?       (y/N confirm; default depends on cfg)
    #  2. mode          (choice; default cfg.mode)
    #  3. scan_interval (int; default cfg.scan_interval_min)
    #  4. process_int   (int)
    #  5. scan_roots    (string)
    #  6. max_files     (int)
    #  7. max_file_bytes(int)
    #  8. shell_history (y/N)
    #  9. package_man   (y/N)
    # 10. env_var_names (y/N)
    # 11. network_doms  (y/N)
    # 12. emit_otel     (y/N)
    # 13. allow_workspace_signatures (y/N)
    # 14. store_raw_local_paths      (y/N)
    # 15. final confirm "Save and apply?"  (only when --yes absent and there's a diff)

    def _all_defaults(self) -> str:
        # 14 prompts before the final confirm; --yes elides the final
        # one. Empty lines mean "accept default".
        return "\n" * 14

    def test_all_defaults_no_op(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_setup,
                ["--yes"],
                input=self._all_defaults(),
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("No changes", result.output)
        # No save/restart when nothing actually changed.
        app.cfg.save.assert_not_called()
        restart_mock.assert_not_called()
        scan_mock.assert_not_called()

    def test_changes_scan_interval_only(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        # Sequence: enable=Y, mode=Enter, interval=15, then 12 more Enters.
        stdin = "y\n\n15\n" + "\n" * 11
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_setup,
                ["--yes", "--no-scan"],
                input=stdin,
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.ai_discovery.scan_interval_min, 15)
        # All the unchanged knobs must remain untouched — proves the
        # diff-only applier doesn't clobber default-yes booleans.
        self.assertTrue(app.cfg.ai_discovery.include_shell_history)
        self.assertTrue(app.cfg.ai_discovery.emit_otel)
        self.assertEqual(app.cfg.ai_discovery.scan_roots, ["~"])
        app.cfg.save.assert_called_once()
        restart_mock.assert_called_once()
        scan_mock.assert_not_called()

    def test_empty_scan_roots_falls_back_to_previous(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        # enable=Y, mode=Enter, interval=Enter, process=Enter, roots=",",
        # then 10 more Enters. The wizard MUST detect the empty
        # post-normalization list and revert.
        stdin = "y\n\n\n\n,\n" + "\n" * 9
        with patch("defenseclaw.commands.cmd_setup._restart_services"), \
                patch.object(cmd_agent, "_trigger_post_enable_scan"):
            result = runner.invoke(
                cmd_agent.discovery_setup,
                ["--yes", "--no-scan"],
                input=stdin,
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(app.cfg.ai_discovery.scan_roots, ["~"])
        self.assertIn("Empty scan roots", result.output)

    def test_disable_via_setup_skips_post_save_scan(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        # First answer flips enabled → false; the rest accept defaults.
        stdin = "n\n" + "\n" * 13
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_setup,
                ["--yes"],
                input=stdin,
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertFalse(app.cfg.ai_discovery.enabled)
        # Discovery is being turned off — the wizard MUST NOT POST
        # /api/v1/ai-usage/scan; that would either 503 or scan against
        # a disabled service.
        scan_mock.assert_not_called()
        # The gateway still needs a restart so the running service
        # actually stops.
        restart_mock.assert_called_once()

    def test_no_restart_implies_no_scan(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)
        # All defaults except scan_interval=15 to force a real diff.
        stdin = "y\n\n15\n" + "\n" * 11
        with patch("defenseclaw.commands.cmd_setup._restart_services") as restart_mock, \
                patch.object(cmd_agent, "_trigger_post_enable_scan") as scan_mock:
            result = runner.invoke(
                cmd_agent.discovery_setup,
                ["--yes", "--no-restart"],
                input=stdin,
                obj=app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart_mock.assert_not_called()
        scan_mock.assert_not_called()
        self.assertIn("--no-restart implies --no-scan", result.output)


class DiscoveryScanTests(unittest.TestCase):
    """Coverage for the standalone ``discovery scan`` command."""

    def test_success_renders_summary(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                return {
                    "summary": {
                        "active_signals": 4,
                        "new_signals": 1,
                        "changed_signals": 2,
                        "files_scanned": 12,
                    },
                }

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(cmd_agent.discovery_scan, [], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("active=4", result.output)
        self.assertIn("new=1", result.output)
        self.assertIn("changed=2", result.output)
        self.assertIn("files=12", result.output)

    def test_503_surfaces_actionable_hint(self):
        runner = CliRunner()
        app = _make_ctx(enabled=False)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                resp = MagicMock()
                resp.status_code = 503
                err = requests.HTTPError(response=resp)
                raise err

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(cmd_agent.discovery_scan, [], obj=app)
        self.assertNotEqual(result.exit_code, 0)
        # The 503 from /api/v1/ai-usage/scan is the canonical "you
        # haven't enabled discovery yet" signal. Calling out the next
        # step explicitly is the whole point of having a scan
        # subcommand separate from `agent usage --refresh`.
        self.assertIn("agent discovery enable", result.output)

    def test_json_passthrough(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                return {"enabled": True, "summary": {"active_signals": 0}}

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(cmd_agent.discovery_scan, ["--json"], obj=app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # `--json` must emit a parseable object for piping into jq.
        import json as _json

        payload = _json.loads(result.output)
        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["summary"]["active_signals"], 0)

    def test_connection_error_propagates(self):
        runner = CliRunner()
        app = _make_ctx(enabled=True)

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                raise requests.ConnectionError("connection refused")

        with patch("defenseclaw.commands.cmd_agent._resolve_gateway_target",
                   side_effect=_resolve_target_stub), \
                patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            result = runner.invoke(cmd_agent.discovery_scan, [], obj=app)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("sidecar unavailable", result.output)


if __name__ == "__main__":
    unittest.main()
