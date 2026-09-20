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

"""Unit tests for canonical-v8 local-observability CLI helpers.

Native Docker ownership, port, and process contracts live beside the
``LocalStackController`` implementation in ``test_local_observability_controller``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from defenseclaw.context import AppContext
from defenseclaw.observability.local_stack import (
    CONTRACT,
    GRAFANA_ACCESS_NO_PASSWORD,
    GRAFANA_ACCESS_PASSWORD,
    LocalStackError,
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup_local_observability import (
    _apply_local_otlp_config,
    _print_stack_summary,
    _refresh_and_maybe_restart_local_observability,
)
from defenseclaw.commands.redaction_status import redaction_status_hint

ROOT = Path(__file__).resolve().parents[2]
LOCAL_BRIDGE = ROOT / "bundles/local_observability_stack/bin/openclaw-observability-bridge"


class TestBridgeReadinessContract(unittest.TestCase):
    def test_up_waits_for_every_query_and_ingest_service(self):
        text = LOCAL_BRIDGE.read_text(encoding="utf-8")
        for marker in (
            'collector_ok="false"',
            "http://127.0.0.1:13133/",
            "http://127.0.0.1:3000/api/health",
            "http://127.0.0.1:9090/-/ready",
            "http://127.0.0.1:3200/ready",
            "http://127.0.0.1:3100/ready",
        ):
            self.assertIn(marker, text)

    @unittest.skipIf(os.name == "nt", "the compatibility bridge is POSIX-only")
    def test_installed_bridge_resolves_sibling_managed_venv(self):
        with tempfile.TemporaryDirectory() as root:
            data_dir = Path(root) / ".defenseclaw"
            stack = data_dir / "observability-stack"
            bridge = stack / "bin" / "openclaw-observability-bridge"
            controller = data_dir / ".venv" / "bin" / "defenseclaw-observability"
            log = Path(root) / "controller.log"
            bridge.parent.mkdir(parents=True)
            controller.parent.mkdir(parents=True)
            shutil.copy2(LOCAL_BRIDGE, bridge)
            controller.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$CONTROLLER_LOG"\n',
                encoding="utf-8",
            )
            bridge.chmod(0o755)
            controller.chmod(0o755)
            environment = {
                "PATH": "/usr/bin:/bin",
                "CONTROLLER_LOG": str(log),
            }

            for arguments in (("url",), ("up", "--no-wait"), ("down",)):
                completed = subprocess.run(
                    [str(bridge), *arguments],
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(invocations), 3)
            self.assertIn(f"--stack-dir {stack}", invocations[0])
            self.assertTrue(invocations[0].startswith("url "))
            self.assertIn("up ", invocations[1])
            self.assertIn("--no-wait", invocations[1])
            self.assertTrue(invocations[2].startswith("down "))

    @unittest.skipIf(os.name == "nt", "the compatibility bridge is POSIX-only")
    def test_source_bridge_retains_repo_venv_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root) / "checkout"
            bridge = repo / "bundles/local_observability_stack/bin/openclaw-observability-bridge"
            controller = repo / ".venv/bin/defenseclaw-observability"
            log = Path(root) / "source.log"
            bridge.parent.mkdir(parents=True)
            controller.parent.mkdir(parents=True)
            shutil.copy2(LOCAL_BRIDGE, bridge)
            controller.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$CONTROLLER_LOG"\n',
                encoding="utf-8",
            )
            bridge.chmod(0o755)
            controller.chmod(0o755)

            completed = subprocess.run(
                [str(bridge), "url"],
                env={"PATH": "/usr/bin:/bin", "CONTROLLER_LOG": str(log)},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(log.read_text(encoding="utf-8").startswith("url "))

    @unittest.skipIf(os.name == "nt", "the compatibility bridge is POSIX-only")
    def test_explicit_controller_override_has_precedence(self):
        with tempfile.TemporaryDirectory() as root:
            stack = Path(root) / "observability-stack"
            bridge = stack / "bin/openclaw-observability-bridge"
            override = Path(root) / "custom-controller"
            log = Path(root) / "custom.log"
            bridge.parent.mkdir(parents=True)
            shutil.copy2(LOCAL_BRIDGE, bridge)
            override.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$CONTROLLER_LOG"\n',
                encoding="utf-8",
            )
            bridge.chmod(0o755)
            override.chmod(0o755)

            completed = subprocess.run(
                [str(bridge), "down"],
                env={
                    "PATH": "/usr/bin:/bin",
                    "CONTROLLER_LOG": str(log),
                    "DEFENSECLAW_OBSERVABILITY_BIN": str(override),
                },
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(log.read_text(encoding="utf-8").startswith("down "))


class TestManagedNoWaitSecurityGate(unittest.TestCase):
    def test_password_flags_propagate_exact_selected_mode(self):
        from defenseclaw.commands.cmd_setup_local_observability import local_observability

        app = AppContext()
        app.cfg = SimpleNamespace(data_dir="/tmp/defenseclaw-test")
        for flag, expected in (
            ("--password", GRAFANA_ACCESS_PASSWORD),
            ("--no-password", GRAFANA_ACCESS_NO_PASSWORD),
        ):
            controller = MagicMock()
            controller.grafana_password_file = Path(
                "/canonical/observability-stack/.grafana-admin-password"
            )
            controller.preflight.return_value = {}
            controller.up.return_value = SimpleNamespace(
                contract=dict(CONTRACT),
                readiness_verified=False,
                grafana_access_mode=expected,
            )
            with patch(
                "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
                return_value=controller,
            ):
                result = CliRunner().invoke(
                    local_observability,
                    [
                        "up",
                        "--no-refresh-bundle",
                        "--no-wait",
                        "--no-config",
                        flag,
                    ],
                    obj=app,
                )

            self.assertEqual(result.exit_code, 0, result.output)
            controller.up.assert_called_once_with(
                timeout=180,
                wait=False,
                grafana_access_mode=expected,
            )
            if expected == GRAFANA_ACCESS_NO_PASSWORD:
                self.assertIn("anonymous Admin", result.output)
                self.assertIn("every local process", result.output)
            else:
                self.assertIn(str(controller.grafana_password_file), result.output)

    def test_exact_no_refresh_no_wait_route_propagates_security_failure(self):
        from defenseclaw.commands.cmd_setup_local_observability import local_observability

        app = AppContext()
        app.cfg = SimpleNamespace(data_dir="/tmp/defenseclaw-test")
        controller = MagicMock()
        controller.preflight.return_value = {}
        controller.up.side_effect = LocalStackError(
            "insecure effective Grafana Compose config: anonymous access must be disabled"
        )
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
            return_value=controller,
        ):
            result = CliRunner().invoke(
                local_observability,
                ["up", "--no-refresh-bundle", "--no-wait", "--no-config"],
                obj=app,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("insecure effective Grafana", result.output)
        controller.up.assert_called_once_with(
            timeout=180,
            wait=False,
            grafana_access_mode=None,
        )

    def test_refresh_failure_cannot_restart_an_insecure_legacy_stack(self):
        controller = MagicMock()
        controller.is_running.return_value = True
        controller.up.side_effect = LocalStackError(
            "insecure effective Grafana Compose config: anonymous access must be disabled"
        )
        refresh_result = SimpleNamespace(
            skipped_reason=None,
            errors=["injected copy failure"],
            refreshed=False,
            refreshed_paths=[],
            preserved_paths=[],
            was_running=False,
            stopped=False,
        )
        with (
            patch(
                "defenseclaw.commands.cmd_setup_local_observability.refresh_local_observability_stack",
                return_value=refresh_result,
            ),
            patch("defenseclaw.commands.cmd_setup_local_observability.click.echo") as echo,
            self.assertRaises(SystemExit),
        ):
            _refresh_and_maybe_restart_local_observability(
                "/tmp/defenseclaw-test",
                refresh_config=True,
                controller=controller,
            )

        controller.down.assert_called_once_with()
        controller.up.assert_called_once_with(timeout=180, wait=False)
        rendered = "\n".join(str(call.args[0]) for call in echo.call_args_list if call.args)
        self.assertNotIn("successfully restarted", rendered.lower())


class TestStackSummary(unittest.TestCase):
    def test_grafana_access_reports_managed_private_credential(self):
        output: list[str] = []
        with (
            patch(
                "defenseclaw.commands.cmd_setup_local_observability.click.echo",
                side_effect=lambda value="", **_kwargs: output.append(str(value)),
            ),
            patch(
                "defenseclaw.commands.cmd_setup_local_observability.ux.bold",
                side_effect=lambda value: value,
            ),
            patch("defenseclaw.commands.cmd_setup_local_observability.ux.section"),
            patch("defenseclaw.commands.cmd_setup_local_observability.ux.subhead"),
            patch("defenseclaw.commands.cmd_setup_local_observability.print_redaction_status_hint"),
        ):
            _print_stack_summary(
                {},
                logs_enabled=False,
                grafana_password_file="/resolved/stack/.grafana-admin-password",
            )

        rendered = "\n".join(output)
        self.assertIn("user: admin", rendered)
        self.assertIn("/resolved/stack/.grafana-admin-password", rendered)
        self.assertNotIn("anonymous Admin", rendered)
        self.assertNotIn("admin / admin", rendered)
        self.assertIn("hot-reloads", rendered)
        self.assertNotIn("defenseclaw-gateway restart", rendered)

    def test_no_password_summary_is_explicit_and_warns(self):
        output: list[str] = []
        with (
            patch(
                "defenseclaw.commands.cmd_setup_local_observability.click.echo",
                side_effect=lambda value="", **_kwargs: output.append(str(value)),
            ),
            patch(
                "defenseclaw.commands.cmd_setup_local_observability.ux.bold",
                side_effect=lambda value: value,
            ),
            patch("defenseclaw.commands.cmd_setup_local_observability.ux.section"),
            patch("defenseclaw.commands.cmd_setup_local_observability.ux.subhead"),
            patch("defenseclaw.commands.cmd_setup_local_observability.print_redaction_status_hint"),
        ):
            _print_stack_summary(
                {},
                logs_enabled=False,
                grafana_access_mode=GRAFANA_ACCESS_NO_PASSWORD,
            )

        rendered = "\n".join(output)
        self.assertIn("anonymous Admin; no password", rendered)
        self.assertIn("every local process", rendered)
        self.assertNotIn(".grafana-admin-password", rendered)


class TestV8LocalDestinationWriter(unittest.TestCase):
    def test_local_stack_uses_one_unified_v8_destination(self):
        app = SimpleNamespace(cfg=SimpleNamespace(data_dir="/tmp/defenseclaw-v8"))
        with (
            patch(
                "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
                return_value=object(),
            ),
            patch(
                "defenseclaw.commands.cmd_setup_observability._add_v8_destination",
                return_value=(SimpleNamespace(changed=True), []),
            ) as add,
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._reload_cfg_from_data_dir",
            ) as reload_cfg,
        ):
            result = _apply_local_otlp_config(
                app,
                endpoint="127.0.0.1:4317",
                protocol="grpc",
                signals=("traces", "metrics", "logs"),
                service_name="defenseclaw",
            )

        self.assertIsNone(result)
        args, kwargs = add.call_args
        self.assertEqual(args[0], "/tmp/defenseclaw-v8")
        self.assertEqual(args[1].id, "local-otlp")
        self.assertEqual(args[2]["endpoint"], "127.0.0.1:4317")
        self.assertEqual(kwargs["name"], "local-observability")
        self.assertEqual(kwargs["signals"], ("traces", "metrics", "logs"))
        self.assertIsNone(kwargs["target"])
        self.assertEqual(len(kwargs["extra_mutations"]), 1)
        self.assertEqual(
            kwargs["extra_mutations"][0].path,
            ("observability", "resource", "attributes", "service.name"),
        )
        reload_cfg.assert_called_once_with(app)

    def test_v8_redaction_summary_uses_destination_policy(self):
        cfg = SimpleNamespace(_source_config_version=8)
        status, label, command = redaction_status_hint(cfg)
        self.assertEqual(status, "PER DESTINATION (defaults are unredacted)")
        self.assertIn("destination redaction", label)
        self.assertEqual(command, "defenseclaw setup redaction status")


if __name__ == "__main__":
    unittest.main()
