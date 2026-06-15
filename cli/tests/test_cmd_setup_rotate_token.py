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
import stat
import unittest
from types import SimpleNamespace
from unittest import mock

from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import _rotate_token_atomic_write
from defenseclaw.context import AppContext


class RotateTokenFileWriteTests(unittest.TestCase):
    def test_creates_file_with_mode_0600(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            _rotate_token_atomic_write(dotenv, "deadbeef" * 8)

            self.assertTrue(os.path.exists(dotenv))
            mode = stat.S_IMODE(os.stat(dotenv).st_mode)
            self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")

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
        We simulate this by patching os.replace to fail; the original
        contents must remain intact.
        """
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            original = "OPENAI_API_KEY=sk-original-do-not-truncate\n"
            with open(dotenv, "w") as fh:
                fh.write(original)

            with mock.patch("defenseclaw.commands.cmd_setup.os.replace",
                            side_effect=OSError("simulated rename failure")):
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
            with mock.patch.object(cmd_setup, "_restart_services") as restart:
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


if __name__ == "__main__":
    unittest.main()
