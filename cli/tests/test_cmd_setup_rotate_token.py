"""Tests for ``defenseclaw setup rotate-token`` (plan B5 / S0.5).

Locks the contract that:
  * the dotenv file is rewritten atomically with mode 0o600
  * unrelated entries survive rotation byte-for-byte
  * a duplicate DEFENSECLAW_GATEWAY_TOKEN line is collapsed (never two)
  * the hook-script refresh is delegated to a verified gateway generation
    change, whose boot loop re-runs Setup for EVERY active connector and re-bakes the
    rotated token into each connector's hook ``.token`` file (the token is
    a single shared secret, so rotation is inherently global)
"""

from __future__ import annotations

import os
import re
import subprocess
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
                fh.write("UNRELATED_ONE=alpha\nUNRELATED_TWO=beta\n")
            _rotate_token_atomic_write(dotenv, "feed1234" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            self.assertIn("UNRELATED_ONE=alpha", body)
            self.assertIn("UNRELATED_TWO=beta", body)
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=feed1234" + "feed1234" * 7, body)

    def test_collapses_duplicate_token_lines(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "w") as fh:
                fh.write(
                    "DEFENSECLAW_GATEWAY_TOKEN=old-token-1\n"
                    "DEFENSECLAW_GATEWAY_TOKEN=old-token-2\n"
                    "UNRELATED_ONE=alpha\n"
                )
            _rotate_token_atomic_write(dotenv, "newtoken" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            tokens = re.findall(r"^DEFENSECLAW_GATEWAY_TOKEN=", body, re.MULTILINE)
            self.assertEqual(len(tokens), 1, f"expected exactly one token line, body=\n{body}")
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=newtoken" + "newtoken" * 7, body)
            self.assertIn("UNRELATED_ONE=alpha", body)

    @unittest.skipUnless(os.name == "nt", "Windows dotenv keys are case-insensitive")
    def test_collapses_case_insensitive_token_lines_on_windows(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "wb") as fh:
                fh.write(b"defenseclaw_gateway_token=old\r\nUNRELATED_ONE=alpha\r\n")

            _rotate_token_atomic_write(dotenv, "c" * 64)

            with open(dotenv, "rb") as fh:
                body = fh.read()
            self.assertEqual(body.lower().count(b"defenseclaw_gateway_token="), 1)
            self.assertIn(b"UNRELATED_ONE=alpha\r\n", body)

    def test_preserves_unrelated_bytes_and_crlf(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            original = (
                b"# keep spacing exactly\r\nUNRELATED = value with spaces  \r\nDEFENSECLAW_GATEWAY_TOKEN=old\r\n\r\n"
            )
            with open(dotenv, "wb") as fh:
                fh.write(original)

            _rotate_token_atomic_write(dotenv, "b" * 64)

            with open(dotenv, "rb") as fh:
                body = fh.read()
            self.assertEqual(
                body,
                b"# keep spacing exactly\r\n"
                b"UNRELATED = value with spaces  \r\n"
                b"\r\n"
                b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64 + b"\r\n",
            )

    def test_atomic_via_replace(self) -> None:
        """A failure mid-write must NOT leave the original .env truncated.
        We simulate this by failing the shared durable-replacement primitive;
        the original contents must remain intact.
        """
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            original = "UNRELATED_ONE=original-do-not-truncate\n"
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
            self.assertEqual(
                body, original, "atomic-write contract violated: original .env was modified before rename succeeded"
            )


def _make_rotate_ctx(td: str, connectors: list[str]):
    """Minimal AppContext for driving rotate_token_cmd."""
    app = AppContext()
    app.cfg = SimpleNamespace(
        data_dir=td,
        gateway=SimpleNamespace(host="127.0.0.1", port=18789, token_env=""),
        guardrail=SimpleNamespace(connector=(connectors[0] if connectors else "")),
        active_connector=lambda: connectors[0] if connectors else "openclaw",
        active_connectors=lambda: list(connectors),
    )
    return app


class RotateTokenCommandFlowTests(unittest.TestCase):
    """The command crosses one verified stop(A)/commit(B)/start(B) boundary."""

    def setUp(self) -> None:
        # Keep every fixture isolated from an inherited gateway credential.
        self._gateway_env = {
            name: os.environ.get(name) for name in ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN")
        }
        self.addCleanup(self._restore_gateway_env)

    def _restore_gateway_env(self) -> None:
        for name, value in self._gateway_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_transaction_stops_a_commits_b_then_starts_b(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "wb") as fh:
                fh.write(b"KEEP=exact\r\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\r\n")
            events: list[tuple[str, bytes]] = []

            def lifecycle(_data_dir: str, action: str, *, cleanup: bool = False) -> None:
                self.assertFalse(cleanup)
                with open(dotenv, "rb") as fh:
                    events.append((action, fh.read()))

            with (
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual([action for action, _ in events], ["stop", "start"])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64, events[0][1])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[1][1])
            with open(dotenv, "rb") as fh:
                body = fh.read()
            self.assertIn(b"KEEP=exact\r\n", body)
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, body)

    def test_stop_timeout_after_pid_exit_restores_ready_a_without_committing_b(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = os.path.join(td, ".env")
            original = b"KEEP=exact\r\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\r\n"
            with open(dotenv, "wb") as fh:
                fh.write(original)
            events: list[tuple[str, bool]] = []

            def lifecycle(_data_dir: str, action: str, *, cleanup: bool = False) -> None:
                events.append((action, cleanup))
                if events == [("stop", False)]:
                    raise click.ClickException("fixture stop timeout")

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", side_effect=[True, False]),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(events, [("stop", False), ("start", False)])
            with open(dotenv, "rb") as fh:
                self.assertEqual(fh.read(), original)
            self.assertNotIn("b" * 64, result.output)

    def test_rotation_audit_contains_metadata_but_never_token_material(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            app.logger = mock.MagicMock()
            events: list[str] = []
            app.logger.log_action.side_effect = lambda *_args: events.append("audit")

            def record_lifecycle(_data_dir: str, action: str, *, cleanup: bool = False) -> None:
                self.assertFalse(cleanup)
                if action == "start":
                    self.assertEqual(os.environ.get("DEFENSECLAW_GATEWAY_TOKEN"), "a" * 64)
                events.append(action)

            with (
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(
                    cmd_setup,
                    "_run_rotate_token_lifecycle",
                    side_effect=record_lifecycle,
                ),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="a" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual(events, ["stop", "start", "audit"])
            app.logger.log_action.assert_called_once_with(
                ACTION_SETUP_GATEWAY,
                "config",
                "action=rotate-token active_connectors=2 restart=true",
            )
            self.assertNotIn("a" * 64, app.logger.log_action.call_args.args[2])

    def test_audit_failure_stops_b_restores_exact_a_and_restarts_a(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            app.logger = mock.MagicMock()
            app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
            dotenv = os.path.join(td, ".env")
            original = b"# exact snapshot\r\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\r\n\r\n"
            with open(dotenv, "wb") as fh:
                fh.write(original)
            events: list[tuple[str, bool, bytes]] = []

            def lifecycle(_data_dir: str, action: str, *, cleanup: bool = False) -> None:
                with open(dotenv, "rb") as fh:
                    events.append((action, cleanup, fh.read()))

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(
                [(action, cleanup) for action, cleanup, _ in events],
                [("stop", False), ("start", False), ("stop", True), ("start", False)],
            )
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[1][2])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[2][2])
            self.assertEqual(events[3][2], original)
            with open(dotenv, "rb") as fh:
                self.assertEqual(fh.read(), original)
            self.assertNotIn("b" * 64, result.output)

    def test_no_restart_is_rejected_before_any_mutation(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            lifecycle = mock.Mock()
            with mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", lifecycle):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes", "--no-restart"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            lifecycle.assert_not_called()
            self.assertIn("--no-restart", result.output)
            self.assertFalse(os.path.exists(os.path.join(td, ".env")))

    def test_custom_token_environment_is_rejected_before_stop(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            app.cfg.gateway.token_env = "EXTERNAL_GATEWAY_TOKEN"
            lifecycle = mock.Mock()
            with mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", lifecycle):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            lifecycle.assert_not_called()
            self.assertIn("externally managed", result.output)

    def test_inactive_openclaw_hint_is_ignored_for_codex_only_roster(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            with mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle") as lifecycle:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd,
                    ["--yes", "--connector", "openclaw"],
                    obj=app,
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(
            [call.args[1] for call in lifecycle.call_args_list],
            ["stop", "start"],
        )
        self.assertIn("Ignoring inactive connector restart hint 'openclaw'", result.output)

    def test_repeat_rotation_refreshes_each_multi_connector_roster_once(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claude-code", "codex", "codex"])
            with mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle") as lifecycle:
                results = [
                    CliRunner().invoke(
                        cmd_setup.rotate_token_cmd,
                        ["--yes", "--connector", "openclaw"],
                        obj=app,
                    )
                    for _ in range(2)
                ]

            with open(os.path.join(td, ".env")) as fh:
                token_lines = [line for line in fh.read().splitlines() if line.startswith("DEFENSECLAW_GATEWAY_TOKEN=")]

        self.assertTrue(all(result.exit_code == 0 for result in results))
        self.assertEqual(
            [call.args[1] for call in lifecycle.call_args_list],
            ["stop", "start", "stop", "start"],
        )
        self.assertEqual(len(token_lines), 1)

    def test_empty_authoritative_roster_never_uses_openclaw_hint(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, [])
            with mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle") as lifecycle:
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd,
                    ["--yes", "--connector", "openclaw"],
                    obj=app,
                )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(
            [call.args[1] for call in lifecycle.call_args_list],
            ["stop", "start"],
        )
        self.assertIn("active connector roster: none", result.output)

    def test_fixture_preserves_unrelated_hook_and_otlp_state(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            hooks = os.path.join(td, "hooks")
            os.makedirs(hooks)
            fixtures = {
                os.path.join(hooks, "hook_contract_lock.json"): b'{"fixture":"unchanged"}\n',
                os.path.join(hooks, ".otlp-codex.token"): b"independent-otlp-fixture\n",
                os.path.join(td, "otlp-state.json"): b'{"cursor":7}\n',
            }
            for path, body in fixtures.items():
                with open(path, "wb") as fh:
                    fh.write(body)

            with mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle"):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            self.assertEqual(result.exit_code, 0, msg=result.output)
            for path, expected in fixtures.items():
                with open(path, "rb") as fh:
                    self.assertEqual(fh.read(), expected)

    def test_failed_first_rotation_restores_absent_dotenv(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            events: list[tuple[str, bool]] = []

            def lifecycle(_data_dir: str, action: str, *, cleanup: bool = False) -> None:
                events.append((action, cleanup))
                if events == [("stop", False), ("start", False)]:
                    raise click.ClickException("fixture start failure")

            with mock.patch.object(
                cmd_setup,
                "_run_rotate_token_lifecycle",
                side_effect=lifecycle,
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(events, [("stop", False), ("start", False), ("stop", True)])
            self.assertFalse(os.path.lexists(os.path.join(td, ".env")))

    def test_lifecycle_timeout_is_bounded_and_never_replays_secret_output(self) -> None:
        secret = "sensitive-fixture-value-" + "x" * 32
        timeout = subprocess.TimeoutExpired(
            cmd=["gateway-fixture", "start"],
            timeout=cmd_setup._TOKEN_ROTATION_LIFECYCLE_TIMEOUT_SECONDS,
            output=secret,
            stderr=secret,
        )
        with (
            mock.patch.object(cmd_setup, "_gateway_lifecycle_executable", return_value="gateway-fixture"),
            mock.patch.object(cmd_setup.subprocess, "run", side_effect=timeout) as run,
        ):
            with self.assertRaises(click.ClickException) as raised:
                cmd_setup._run_rotate_token_lifecycle("D:\\fixture-data", "start")

        argv = run.call_args.args[0]
        self.assertEqual(argv, ["gateway-fixture", "start", "--rotation-transaction"])
        self.assertNotIn(secret, " ".join(argv))
        self.assertNotIn(secret, str(raised.exception))
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            cmd_setup._TOKEN_ROTATION_LIFECYCLE_TIMEOUT_SECONDS,
        )

        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(cmd_setup, "_gateway_lifecycle_executable", return_value="gateway-fixture"),
            mock.patch.object(cmd_setup.subprocess, "run", return_value=completed) as cleanup_run,
        ):
            cmd_setup._run_rotate_token_lifecycle("D:\\fixture-data", "stop", cleanup=True)
        self.assertEqual(
            cleanup_run.call_args.args[0],
            ["gateway-fixture", "stop", "--rotation-transaction", "--rotation-cleanup"],
        )

    def test_start_b_failure_restores_exact_snapshot_and_ready_a(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = os.path.join(td, ".env")
            original = b"KEEP=unchanged\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n"
            with open(dotenv, "wb") as fh:
                fh.write(original)
            events: list[tuple[str, bool]] = []

            def lifecycle(_data_dir: str, action: str, *, cleanup: bool = False) -> None:
                events.append((action, cleanup))
                if events == [("stop", False), ("start", False)]:
                    raise click.ClickException("fixture failure that must stay redacted")

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(
                    cmd_setup.rotate_token_cmd,
                    ["--yes"],
                    obj=app,
                )
            with open(dotenv, "rb") as fh:
                restored = fh.read()

        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(
            events,
            [("stop", False), ("start", False), ("stop", True), ("start", False)],
        )
        self.assertEqual(restored, original)
        self.assertNotIn("b" * 64, result.output)
        self.assertNotIn("Hook scripts refreshed", result.output)


if __name__ == "__main__":
    unittest.main()
