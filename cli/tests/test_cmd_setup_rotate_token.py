"""Tests for ``defenseclaw setup rotate-token`` (plan B5 / S0.5).

Locks the contract that:
  * the dotenv file is rewritten atomically with mode 0o600
  * unrelated entries (OPENAI_API_KEY, etc.) survive rotation
  * a duplicate DEFENSECLAW_GATEWAY_TOKEN line is collapsed (never two)
  * the hook-script refresh is delegated to a full gateway restart, whose
    boot loop re-runs Setup for EVERY active connector and re-bakes the
    rotated token into each connector's hook ``.token`` file (the token is
    a single shared secret, so rotation is inherently global)
"""

from __future__ import annotations

import os
import re
import unittest
from types import SimpleNamespace
from unittest import mock

import click
from click.testing import CliRunner
from defenseclaw.audit_actions import ACTION_SETUP_GATEWAY
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import _rotate_token_atomic_write
from defenseclaw.context import AppContext
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.permissions import assert_owner_only_file


class RotateTokenFileWriteTests(unittest.TestCase):
    def test_creates_file_with_mode_0600(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            _rotate_token_atomic_write(dotenv, "deadbeef" * 8)

            self.assertTrue(os.path.exists(dotenv))
            assert_owner_only_file(dotenv)

            with open(dotenv) as fh:
                body = fh.read()
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=deadbeef" + "deadbeef" * 7, body)

    def test_preserves_unrelated_entries(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "w") as fh:
                fh.write("OPENAI_API_KEY=sk-xxx\nANTHROPIC_API_KEY=anth-xxx\n")
            _rotate_token_atomic_write(dotenv, "feed1234" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            self.assertIn("OPENAI_API_KEY=sk-xxx", body)
            self.assertIn("ANTHROPIC_API_KEY=anth-xxx", body)
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=feed1234" + "feed1234" * 7, body)

    def test_collapses_duplicate_token_lines(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "w") as fh:
                fh.write("DEFENSECLAW_GATEWAY_TOKEN=old-token-1\n"
                         "DEFENSECLAW_GATEWAY_TOKEN=old-token-2\n"
                         "OPENAI_API_KEY=sk-xxx\n")
            _rotate_token_atomic_write(dotenv, "newtoken" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            tokens = re.findall(r"^DEFENSECLAW_GATEWAY_TOKEN=", body, re.MULTILINE)
            self.assertEqual(len(tokens), 1, f"expected exactly one token line, body=\n{body}")
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=newtoken" + "newtoken" * 7, body)
            self.assertIn("OPENAI_API_KEY=sk-xxx", body)

    def test_atomic_via_replace(self) -> None:
        """A failure mid-write must NOT leave the original .env truncated.
        We simulate this by failing the shared durable-replacement primitive;
        the original contents must remain intact.
        """
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            original = "OPENAI_API_KEY=sk-original-do-not-truncate\n"
            with open(dotenv, "w") as fh:
                fh.write(original)

            with mock.patch(
                "defenseclaw.file_permissions.replace_file_durable",
                side_effect=OSError("simulated rename failure"),
            ):
                with self.assertRaises(OSError):
                    _rotate_token_atomic_write(dotenv, "ignored" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            self.assertEqual(body, original,
                             "atomic-write contract violated: original .env was modified before rename succeeded")


def _make_rotate_ctx(td: str, connectors: list[str]):
    """Minimal AppContext for driving rotate_token_cmd."""
    app = AppContext()
    app.cfg = SimpleNamespace(
        data_dir=td,
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        guardrail=SimpleNamespace(connector=(connectors[0] if connectors else "")),
        active_connector=lambda: (connectors[0] if connectors else "openclaw"),
        active_connectors=lambda: list(connectors),
    )
    return app


class RotateTokenCommandFlowTests(unittest.TestCase):
    """`setup rotate-token` rewrites .env then refreshes ALL active connectors
    via a single gateway restart (the shared token must stay in lockstep)."""

    def test_restart_refreshes_every_active_connector(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(cmd_setup, "_restart_services") as restart,
            ):
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd, ["--yes"], obj=app
                )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            restart.assert_called_once()
            # The whole active set is forwarded so the boot loop re-bakes the
            # token into every connector — not just the primary.
            self.assertEqual(
                restart.call_args.kwargs.get("connectors"),
                ["claudecode", "codex"],
            )
            # .env actually rotated on disk.
            with open(os.path.join(td, ".env")) as fh:
                self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=", fh.read())

    def test_rotation_audit_contains_metadata_but_never_token_material(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            app.logger = mock.MagicMock()
            events: list[str] = []
            app.logger.log_action.side_effect = lambda *_args: events.append("audit")

            def record_restart(*_args, **_kwargs) -> None:
                self.assertEqual(os.environ.get("DEFENSECLAW_GATEWAY_TOKEN"), "a" * 64)
                events.append("restart")

            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(
                    cmd_setup,
                    "_restart_services",
                    side_effect=record_restart,
                ),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="a" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual(events, ["restart", "audit"])
            app.logger.log_action.assert_called_once_with(
                ACTION_SETUP_GATEWAY,
                "config",
                "action=rotate-token active_connectors=2 restart=true",
            )
            self.assertNotIn("a" * 64, app.logger.log_action.call_args.args[2])

    def test_default_rotation_attempts_restart_before_audit_failure(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            app.logger = mock.MagicMock()
            app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(cmd_setup, "_restart_services") as restart,
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            restart.assert_called_once()
            with open(os.path.join(td, ".env")) as fh:
                self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=", fh.read())

    def test_no_restart_skips_gateway_bounce(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            with mock.patch.object(cmd_setup, "_restart_services") as restart:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd, ["--yes", "--no-restart"], obj=app
                )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            restart.assert_not_called()
            self.assertIn("--no-restart", result.output)
            # Token is still rotated even when the refresh is deferred.
            with open(os.path.join(td, ".env")) as fh:
                self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=", fh.read())

    def test_no_restart_allows_explicit_offline_audit_staging(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            app.logger = mock.MagicMock()
            app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
            with mock.patch.object(cmd_setup, "_restart_services") as restart:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd, ["--yes", "--no-restart"], obj=app
                )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            restart.assert_not_called()
            self.assertIn("canonical setup audit event was not recorded", result.output)

    def test_inactive_openclaw_hint_is_ignored_for_codex_only_roster(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            with mock.patch.object(cmd_setup, "_restart_services") as restart:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd,
                    ["--yes", "--connector", "openclaw"],
                    obj=app,
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart.assert_called_once()
        self.assertEqual(restart.call_args.kwargs["connector"], "codex")
        self.assertEqual(restart.call_args.kwargs["connectors"], ["codex"])
        self.assertIn("Ignoring inactive connector restart hint 'openclaw'", result.output)

    def test_repeat_rotation_refreshes_each_multi_connector_roster_once(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claude-code", "codex", "codex"])
            with mock.patch.object(cmd_setup, "_restart_services") as restart:
                results = [
                    CliRunner().invoke(
                        cmd_setup.rotate_token_cmd,
                        ["--yes", "--connector", "openclaw"],
                        obj=app,
                    )
                    for _ in range(2)
                ]

            with open(os.path.join(td, ".env")) as fh:
                token_lines = [
                    line
                    for line in fh.read().splitlines()
                    if line.startswith("DEFENSECLAW_GATEWAY_TOKEN=")
                ]

        self.assertTrue(all(result.exit_code == 0 for result in results))
        self.assertEqual(restart.call_count, 2)
        for call in restart.call_args_list:
            self.assertEqual(call.kwargs["connector"], "claudecode")
            self.assertEqual(call.kwargs["connectors"], ["claudecode", "codex"])
        self.assertEqual(len(token_lines), 1)

    def test_empty_authoritative_roster_never_uses_openclaw_hint(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, [])
            with mock.patch.object(cmd_setup, "_restart_services") as restart:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd,
                    ["--yes", "--connector", "openclaw"],
                    obj=app,
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart.assert_not_called()
        self.assertIn("active connector roster: none", result.output)
        self.assertIn("no active connector configured", result.output)

    def test_restart_failure_propagates_after_token_write(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            with mock.patch.object(
                cmd_setup,
                "_restart_services",
                side_effect=click.ClickException("simulated restart failure"),
            ) as restart:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd,
                    ["--yes"],
                    obj=app,
                )
            token_written = os.path.exists(os.path.join(td, ".env"))

        self.assertNotEqual(result.exit_code, 0)
        restart.assert_called_once()
        self.assertTrue(token_written)
        self.assertIn("simulated restart failure", result.output)
        self.assertNotIn("Hook scripts refreshed", result.output)


if __name__ == "__main__":
    unittest.main()
