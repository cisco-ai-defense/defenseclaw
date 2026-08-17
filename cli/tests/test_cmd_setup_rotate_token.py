"""Tests for ``defenseclaw setup rotate-token`` (plan B5 / S0.5).

Locks the contract that:
  * the dotenv file is rewritten atomically with mode 0o600
  * unrelated entries survive rotation byte-for-byte
  * a duplicate DEFENSECLAW_GATEWAY_TOKEN line is collapsed (never two)
  * every enabled owner and safely discovered persisted sidecar receives a distinct scoped hook credential
  * the gateway boot loop refreshes affected hooks/plugins and proves scoped
    authentication before generation B is committed
  * every credential sidecar is restored byte-for-byte if any phase fails
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import click
from click.testing import CliRunner
from defenseclaw.audit_actions import ACTION_SETUP_GATEWAY
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import _rotate_token_atomic_write
from defenseclaw.config import CONFIG_PATH_ENV
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

    @unittest.skipUnless(os.name == "nt", "validates the gateway-managed Windows token DACL")
    def test_discovers_go_managed_hook_token_acl(self) -> None:
        from tempfile import TemporaryDirectory

        from defenseclaw import file_permissions, windows_acl

        with TemporaryDirectory() as td:
            hooks = Path(td, "hooks")
            hooks.mkdir()
            token = hooks / ".hook-codex.token"
            token.write_bytes(b"1" * 64 + b"\n")
            for path, ace in (
                (hooks, "*S-1-5-32-544:(OI)(CI)F"),
                (token, "*S-1-5-32-544:F"),
            ):
                file_permissions._set_windows_owner_only_acl(os.fspath(path), set_owner=True)
                subprocess.run(
                    ["icacls", os.fspath(path), "/grant", ace],
                    check=True,
                    capture_output=True,
                    text=True,
                )

            self.assertEqual(cmd_setup._rotate_token_persisted_hook_scopes(td), ["codex"])
            snapshot = cmd_setup._rotate_token_hook_snapshot_locked(td, "codex")
            hooks_acl = windows_acl.capture_path(os.fspath(hooks), directory=True)
            token_acl = windows_acl.capture_path(os.fspath(token))

            file_permissions.atomic_write_private_bytes(
                token,
                b"2" * 64 + b"\n",
                windows_managed_custody=True,
            )
            cmd_setup._rotate_token_restore_hook_snapshot_locked(snapshot)

            self.assertEqual(token.read_bytes(), b"1" * 64 + b"\n")
            self.assertEqual(windows_acl.capture_path(os.fspath(hooks), directory=True), hooks_acl)
            self.assertEqual(windows_acl.capture_path(os.fspath(token)), token_acl)
            self.assertEqual(windows_acl.capture_path(os.fspath(token)), snapshot.windows_security)

            subprocess.run(
                ["icacls", os.fspath(token), "/inheritance:e"],
                check=True,
                capture_output=True,
                text=True,
            )
            with self.assertRaisesRegex(click.ClickException, "ACL is not private"):
                cmd_setup._rotate_token_hook_snapshot_locked(td, "codex")

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

    def test_renderer_removes_exact_legacy_key_but_preserves_prefixed_keys(self) -> None:
        secret = "replacement-token-that-must-stay-redacted"
        snapshot = cmd_setup._RotateTokenDotenvSnapshot(
            existed=True,
            body=(
                b"OPENCLAW_GATEWAY_TOKEN=exposed-a\r\n"
                b"OPENCLAW_GATEWAY_TOKEN_SUFFIX=keep-legacy-prefix\r\n"
                b"XOPENCLAW_GATEWAY_TOKEN=keep-leading-prefix\r\n"
                b"DEFENSECLAW_GATEWAY_TOKEN=exposed-b\r\n"
                b"DEFENSE"
                b"CLAW_GATEWAY_TOKEN_BACKUP=keep-canonical-prefix\r\n"
            ),
            mode=0o644,
        )

        body = cmd_setup._rotate_token_render(snapshot, secret)

        self.assertNotIn(b"OPENCLAW_GATEWAY_TOKEN=exposed-a", body)
        self.assertNotIn(b"DEFENSECLAW_GATEWAY_TOKEN=exposed-b", body)
        self.assertIn(
            b"OPENCLAW_GATEWAY_TOKEN_SUFFIX=keep-legacy-prefix\r\n",
            body,
        )
        self.assertIn(b"XOPENCLAW_GATEWAY_TOKEN=keep-leading-prefix\r\n", body)
        self.assertIn(
            b"DEFENSE" + b"CLAW_GATEWAY_TOKEN_BACKUP=keep-canonical-prefix\r\n",
            body,
        )
        self.assertEqual(body.count(b"DEFENSECLAW_GATEWAY_TOKEN="), 1)
        self.assertTrue(body.endswith(f"DEFENSECLAW_GATEWAY_TOKEN={secret}\r\n".encode()))

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
    primary = connectors[0] if connectors else "''"
    config_lines = ["claw:", f"  mode: {primary}", "guardrail:"]
    config_lines.append(f"  connector: {primary}")
    if connectors:
        config_lines.append("  connectors:")
        for connector in dict.fromkeys(connectors):
            config_lines.extend((f"    {connector}:", "      enabled: true"))
    Path(td, "config.yaml").write_text("\n".join(config_lines) + "\n", encoding="utf-8")

    hooks_dir = Path(td, "hooks")
    hooks_dir.mkdir(mode=0o700)
    for index, raw in enumerate(dict.fromkeys(connectors), start=1):
        connector = cmd_setup.normalize_connector(raw)
        token_path = hooks_dir / f".hook-{connector}.token"
        cmd_setup.atomic_write_private_bytes(token_path, f"{index:064x}\n".encode("ascii"))

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

    def test_rotation_shared_publish_lock_basename_matches_go_contract(self) -> None:
        go_source = (
            Path(__file__).resolve().parents[2] / "internal" / "gateway" / "connector" / "hook_api_token.go"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'hookAPITokenPublishLockBaseName = ".hook-api-token-publish"',
            go_source,
        )
        self.assertEqual(
            cmd_setup._TOKEN_ROTATION_HOOK_PUBLISH_LOCK_BASE_NAME,
            ".hook-api-token-publish",
        )

    def test_shared_publish_lock_is_outermost_and_blocks_lifecycle_and_mutation(self) -> None:
        from tempfile import TemporaryDirectory

        from defenseclaw.file_lock import locked_file_update as real_locked_file_update

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = Path(td, ".env")
            dotenv_a = b"DEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n"
            cmd_setup.atomic_write_private_bytes(dotenv, dotenv_a)
            sidecar = Path(td, "hooks", ".hook-codex.token")
            sidecar_a = sidecar.read_bytes()
            config_file = Path(td, "config.yaml")
            shared_lock_base = Path(
                td,
                cmd_setup._TOKEN_ROTATION_HOOK_PUBLISH_LOCK_BASE_NAME,
            )
            holder_ready = Path(td, "python-publish-lock-ready")
            holder_release = Path(td, "python-publish-lock-release")
            holder_script = """
import pathlib
import sys
import time
from defenseclaw.file_lock import locked_file_update

lock_base, ready_name, release_name = sys.argv[1:]
ready = pathlib.Path(ready_name)
release = pathlib.Path(release_name)
with locked_file_update(lock_base):
    ready.write_bytes(b"ready")
    deadline = time.monotonic() + 15
    while not release.exists():
        if time.monotonic() >= deadline:
            raise SystemExit("timed out waiting for release")
        time.sleep(0.01)
"""
            holder = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    holder_script,
                    os.fspath(shared_lock_base),
                    os.fspath(holder_ready),
                    os.fspath(holder_release),
                ],
                cwd=Path(__file__).resolve().parents[2],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            worker: threading.Thread | None = None
            worker_done = threading.Event()
            worker_errors: list[BaseException] = []
            shared_lock_attempted = threading.Event()
            lifecycle_events: list[str] = []

            def observed_locked_file_update(path: str, *args, **kwargs):
                if os.path.abspath(path) == os.path.abspath(shared_lock_base):
                    shared_lock_attempted.set()
                return real_locked_file_update(path, *args, **kwargs)

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del token, config_file, connector_state, cleanup
                lifecycle_events.append(action)

            def rotate() -> None:
                try:
                    cmd_setup._rotate_token_transaction(
                        app,
                        os.fspath(dotenv),
                        "b" * 64,
                        "fixture shared publication lock",
                        scoped_connectors=("codex",),
                    )
                except BaseException as exc:
                    worker_errors.append(exc)
                finally:
                    worker_done.set()

            try:
                deadline = time.monotonic() + 5
                while not holder_ready.exists():
                    if holder.poll() is not None:
                        output = holder.stdout.read() if holder.stdout is not None else ""
                        self.fail(f"shared-lock holder exited before readiness: {output}")
                    if time.monotonic() >= deadline:
                        self.fail("timed out waiting for shared-lock holder readiness")
                    time.sleep(0.01)

                with (
                    mock.patch.object(
                        cmd_setup,
                        "locked_file_update",
                        side_effect=observed_locked_file_update,
                    ),
                    mock.patch.object(cmd_setup, "load_config", return_value=app.cfg),
                    mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                    mock.patch.object(cmd_setup.secrets, "token_bytes", return_value=b"\x42" * 32),
                ):
                    worker = threading.Thread(target=rotate, name="rotate-token-shared-lock")
                    worker.start()
                    self.assertTrue(
                        shared_lock_attempted.wait(timeout=5),
                        "rotation never attempted the shared Go publication lock",
                    )
                    self.assertFalse(worker_done.wait(timeout=0.15))
                    self.assertEqual(lifecycle_events, [])
                    self.assertEqual(dotenv.read_bytes(), dotenv_a)
                    self.assertEqual(sidecar.read_bytes(), sidecar_a)

                    # The shared lock must precede every narrower transaction
                    # lock. If rotation took any of these first, the bounded
                    # non-blocking probes would fail here.
                    for path in (config_file, dotenv, sidecar):
                        with real_locked_file_update(os.fspath(path), timeout_seconds=0.05):
                            pass

                    holder_release.write_bytes(b"release")
                    worker.join(timeout=30)
                    self.assertFalse(worker.is_alive(), "rotation did not finish after the shared lock was released")
            finally:
                try:
                    holder_release.write_bytes(b"release")
                except OSError:
                    pass
                if holder.poll() is None:
                    try:
                        holder.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        holder.kill()
                        holder.wait(timeout=5)
                if worker is not None and worker.is_alive():
                    worker.join(timeout=5)

            holder_output = holder.stdout.read() if holder.stdout is not None else ""
            self.assertEqual(holder.returncode, 0, msg=holder_output)
            self.assertEqual(worker_errors, [])
            self.assertEqual(lifecycle_events, ["stop", "start"])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, dotenv.read_bytes())
            self.assertNotEqual(sidecar.read_bytes(), sidecar_a)

    def test_lifecycle_executable_never_returns_a_bare_name(self) -> None:
        canonical = os.path.realpath(sys.executable)
        with (
            mock.patch(
                "defenseclaw.gateway.packaged_windows_install_root",
                return_value=None,
            ),
            mock.patch(
                "defenseclaw.commands.cmd_setup.shutil.which",
                return_value="defenseclaw-gateway",
            ),
            mock.patch(
                "defenseclaw.gateway.canonical_install_path",
                return_value=canonical,
            ),
            mock.patch(
                "defenseclaw.commands.cmd_setup._trusted_gateway_lifecycle_executable",
                side_effect=lambda path: path,
            ) as trust,
        ):
            executable = cmd_setup._gateway_lifecycle_executable()

        self.assertIsNotNone(executable)
        self.assertTrue(os.path.isabs(executable))
        self.assertNotEqual(executable, "defenseclaw-gateway")
        self.assertEqual(os.path.normcase(executable or ""), os.path.normcase(canonical))
        trust.assert_called_once_with(str(Path(canonical).resolve()))

    def test_lifecycle_executable_uses_only_absolute_non_current_path_entries(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            current = os.path.join(td, "current")
            allowed = os.path.join(td, "allowed")
            os.makedirs(current)
            os.makedirs(allowed)
            raw_search_path = os.pathsep.join(("", os.curdir, current, "relative-bin", allowed, allowed))
            previous = os.getcwd()
            try:
                os.chdir(current)
                with (
                    mock.patch(
                        "defenseclaw.gateway.packaged_windows_install_root",
                        return_value=None,
                    ),
                    mock.patch(
                        "defenseclaw.commands.cmd_setup.shutil.which",
                        return_value=None,
                    ) as which,
                    mock.patch(
                        "defenseclaw.gateway.canonical_install_path",
                        return_value=os.path.join(td, "missing"),
                    ),
                ):
                    self.assertIsNone(
                        cmd_setup._gateway_lifecycle_executable(
                            search_path=raw_search_path,
                        )
                    )
            finally:
                os.chdir(previous)

        which.assert_called_once_with(
            "defenseclaw-gateway",
            path=os.path.abspath(allowed),
        )

    def test_packaged_lifecycle_does_not_fall_back_when_sibling_is_missing(self) -> None:
        with (
            mock.patch(
                "defenseclaw.gateway.packaged_windows_install_root",
                return_value="C:\\Program Files\\DefenseClaw",
            ),
            mock.patch(
                "defenseclaw.gateway.packaged_windows_gateway_path",
                return_value=None,
            ),
            mock.patch("defenseclaw.gateway.resolve_gateway_binary") as resolve,
        ):
            executable = cmd_setup._gateway_lifecycle_executable()

        self.assertIsNone(executable)
        resolve.assert_not_called()

    def test_connector_state_serializes_exact_dual_and_mixed_postures(self) -> None:
        cases = {
            "dual": {
                "claudecode": ("action", "closed", True),
                "codex": ("action", "closed", True),
            },
            "mixed": {
                "claudecode": ("observe", "open", True),
                "codex": ("action", "closed", True),
            },
        }
        for name, policies in cases.items():
            with self.subTest(name=name):
                guardrail = SimpleNamespace(
                    effective_mode=lambda connector: policies[connector][0],
                    effective_hook_fail_mode=lambda connector: policies[connector][1],
                    effective_enabled=lambda connector: policies[connector][2],
                )
                cfg = SimpleNamespace(
                    guardrail=guardrail,
                    active_connectors=lambda: ["codex", "claude-code"],
                )
                payload = json.loads(cmd_setup._rotate_token_connector_state(cfg))
                self.assertEqual(payload["version"], 1)
                self.assertEqual(
                    payload["connectors"],
                    [
                        {
                            "name": connector,
                            "mode": policy[0],
                            "hook_fail_mode": policy[1],
                            "enabled": policy[2],
                        }
                        for connector, policy in sorted(policies.items())
                    ],
                )

    def test_scoped_generation_retries_every_prior_fingerprint(self) -> None:
        prior_values = {
            "claudecode": (1).to_bytes(32, "big").hex(),
            "codex": (2).to_bytes(32, "big").hex(),
        }
        prior_fingerprints = {
            connector: cmd_setup._rotate_token_hook_fingerprint(value) for connector, value in prior_values.items()
        }
        replacements = {
            "claudecode": (b"\x21" * 32).hex(),
            "codex": (b"\x42" * 32).hex(),
        }

        with mock.patch.object(
            cmd_setup.secrets,
            "token_bytes",
            side_effect=[
                (1).to_bytes(32, "big"),
                b"\x21" * 32,
                (2).to_bytes(32, "big"),
                b"\x42" * 32,
            ],
        ):
            generated = cmd_setup._rotate_token_new_hook_values(
                ["claudecode", "codex"],
                "b" * 64,
                prior_fingerprints,
            )

        self.assertEqual(generated, replacements)
        generated_fingerprints = {cmd_setup._rotate_token_hook_fingerprint(value) for value in generated.values()}
        self.assertTrue(generated_fingerprints.isdisjoint(prior_fingerprints.values()))

    def test_transaction_stops_a_commits_b_then_starts_b(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "wb") as fh:
                fh.write(b"KEEP=exact\r\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\r\n")
            events: list[tuple[str, str, bytes]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                self.assertFalse(cleanup)
                self.assertEqual(config_file, os.path.abspath(os.path.join(td, "config.yaml")))
                with open(dotenv, "rb") as fh:
                    events.append((action, token, fh.read()))

            with (
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual([action for action, _, _ in events], ["stop", "start"])
            self.assertEqual([token for _, token, _ in events], ["a" * 64, "b" * 64])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64, events[0][2])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[1][2])
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
            events: list[tuple[str, bool, str]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                events.append((action, cleanup, token))
                if len(events) == 1:
                    raise click.ClickException("fixture stop timeout")

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", side_effect=[True, False]),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(events, [("stop", False, "a" * 64), ("start", False, "a" * 64)])
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

            def record_lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                self.assertFalse(cleanup)
                if action == "start":
                    self.assertEqual(token, "a" * 64)
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
                "action=rotate-token active_connectors=2 scoped_hook_tokens=2 restart=true",
            )
            self.assertNotIn("a" * 64, app.logger.log_action.call_args.args[2])

    def test_success_rotates_distinct_multi_connector_sidecars_and_passes_only_fingerprints(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            hook_paths = {
                connector: Path(td, "hooks", f".hook-{connector}.token") for connector in ("claudecode", "codex")
            }
            old_values = {connector: path.read_text(encoding="ascii").strip() for connector, path in hook_paths.items()}
            scoped_values = {
                "claudecode": (b"\x21" * 32).hex(),
                "codex": (b"\x42" * 32).hex(),
            }
            start_states: list[dict[str, object]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del token, config_file, cleanup
                if action != "start":
                    return
                self.assertIsNotNone(connector_state)
                state = json.loads(str(connector_state))
                start_states.append(state)
                fingerprints = state["hook_token_fingerprints"]
                self.assertEqual(
                    fingerprints,
                    {
                        connector: cmd_setup._rotate_token_hook_fingerprint(path.read_text(encoding="ascii").strip())
                        for connector, path in hook_paths.items()
                    },
                )
                serialized = json.dumps(state, sort_keys=True)
                for value in scoped_values.values():
                    self.assertNotIn(value, serialized)

            with (
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(
                    cmd_setup.secrets,
                    "token_bytes",
                    side_effect=[b"\x21" * 32, b"\x42" * 32],
                ),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            new_values = {connector: path.read_text(encoding="ascii").strip() for connector, path in hook_paths.items()}

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(new_values, scoped_values)
        self.assertEqual(len(set(new_values.values())), 2)
        self.assertTrue(all(new_values[name] != old_values[name] for name in new_values))
        self.assertTrue(all(value != "b" * 64 for value in new_values.values()))
        self.assertEqual(len(start_states), 1)
        for value in (*old_values.values(), *new_values.values()):
            self.assertNotIn(value, result.output)

    def test_disabled_persisted_connector_sidecar_is_revoked(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            app.cfg.guardrail.effective_enabled = lambda _connector: False
            Path(td, "config.yaml").write_text(
                "claw:\n  mode: codex\nguardrail:\n"
                "  connector: codex\n  connectors:\n    codex:\n      enabled: false\n",
                encoding="utf-8",
            )
            sidecar = Path(td, "hooks", ".hook-codex.token")
            old_value = sidecar.read_text(encoding="ascii").strip()
            states: list[dict[str, object]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del token, config_file, cleanup
                if action == "start":
                    states.append(json.loads(str(connector_state)))

            with (
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(cmd_setup.secrets, "token_bytes", return_value=b"\x42" * 32),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            new_value = sidecar.read_text(encoding="ascii").strip()

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotEqual(new_value, old_value)
        self.assertEqual(new_value, (b"\x42" * 32).hex())
        self.assertEqual(states[0]["connectors"][0]["enabled"], False)
        self.assertEqual(
            states[0]["hook_token_fingerprints"]["codex"],
            cmd_setup._rotate_token_hook_fingerprint(new_value),
        )

    def test_unconfigured_orphan_sidecar_rotates_with_disjoint_readiness_state(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            orphan = Path(td, "hooks", ".hook-opencode.token")
            old_orphan = "3" * 64
            cmd_setup.atomic_write_private_bytes(orphan, (old_orphan + "\n").encode("ascii"))
            states: list[dict[str, object]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del token, config_file, cleanup
                if action == "start":
                    states.append(json.loads(str(connector_state)))

            with (
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(
                    cmd_setup.secrets,
                    "token_bytes",
                    side_effect=[b"\x21" * 32, b"\x42" * 32],
                ),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            codex_value = Path(td, "hooks", ".hook-codex.token").read_text(encoding="ascii").strip()
            orphan_value = orphan.read_text(encoding="ascii").strip()

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertNotEqual(orphan_value, old_orphan)
        self.assertFalse(
            cmd_setup.secrets.compare_digest(old_orphan, orphan_value),
            "the old orphan credential still authenticates after successful rotation",
        )
        self.assertEqual(len(states), 1)
        self.assertEqual(
            states[0]["hook_token_fingerprints"],
            {"codex": cmd_setup._rotate_token_hook_fingerprint(codex_value)},
        )
        self.assertEqual(
            states[0]["orphan_hook_token_fingerprints"],
            {"opencode": cmd_setup._rotate_token_hook_fingerprint(orphan_value)},
        )
        self.assertNotIn("opencode", states[0]["hook_token_fingerprints"])
        self.assertNotIn("opencode", result.output)

    def test_failed_b_restores_exact_orphan_and_recovery_state_omits_unverifiable_orphans(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = Path(td, ".env")
            cmd_setup.atomic_write_private_bytes(
                dotenv,
                b"DEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n",
            )
            orphan = Path(td, "hooks", ".hook-thirdparty.token")
            original_orphan = b"3" * 64 + b"\r\n"
            cmd_setup.atomic_write_private_bytes(orphan, original_orphan)
            if os.name != "nt":
                orphan.chmod(0o400)
            original_mode = orphan.stat().st_mode & 0o777
            starts: list[dict[str, object]] = []
            events: list[tuple[str, bool]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del config_file
                events.append((action, cleanup))
                if action == "start":
                    starts.append(json.loads(str(connector_state)))
                    if token == "b" * 64:
                        raise click.ClickException("fixture B readiness failure")

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(
                    cmd_setup.secrets,
                    "token_bytes",
                    side_effect=[b"\x21" * 32, b"\x42" * 32],
                ),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            restored_orphan = orphan.read_bytes()
            restored_mode = orphan.stat().st_mode & 0o777

        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(events, [("stop", False), ("start", False), ("stop", True), ("start", False)])
        self.assertEqual(restored_orphan, original_orphan)
        self.assertEqual(restored_mode, original_mode)
        self.assertIn("thirdparty", starts[0]["orphan_hook_token_fingerprints"])
        self.assertNotIn("orphan_hook_token_fingerprints", starts[1])
        self.assertNotIn("thirdparty", result.output)

    def test_orphan_discovery_rejects_noncanonical_linked_and_oversized_sidecars(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            _make_rotate_ctx(td, [])
            hooks = Path(td, "hooks")

            noncanonical = hooks / ".hook-Codex.token"
            cmd_setup.atomic_write_private_bytes(noncanonical, ("1" * 64 + "\n").encode("ascii"))
            with self.assertRaisesRegex(click.ClickException, "non-canonical"):
                cmd_setup._rotate_token_persisted_hook_scopes(td)
            noncanonical.unlink()

            noncanonical = hooks / ".HOOK-codex.TOKEN"
            cmd_setup.atomic_write_private_bytes(noncanonical, ("1" * 64 + "\n").encode("ascii"))
            with self.assertRaisesRegex(click.ClickException, "non-canonical"):
                cmd_setup._rotate_token_persisted_hook_scopes(td)
            noncanonical.unlink()

            target = Path(td, "outside-token")
            cmd_setup.atomic_write_private_bytes(target, ("2" * 64 + "\n").encode("ascii"))
            linked = hooks / ".hook-linked.token"
            try:
                linked.symlink_to(target)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaisesRegex(click.ClickException, "unsafe"):
                    cmd_setup._rotate_token_persisted_hook_scopes(td)
                linked.unlink()

            oversized = hooks / ".hook-oversized.token"
            cmd_setup.atomic_write_private_bytes(oversized, b"a" * 4097)
            with self.assertRaisesRegex(click.ClickException, "oversized"):
                cmd_setup._rotate_token_hook_snapshot_locked(td, "oversized")

    def test_orphan_discovery_has_a_bounded_roster(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            _make_rotate_ctx(td, [])
            for name in ("one", "two"):
                cmd_setup.atomic_write_private_bytes(
                    Path(td, "hooks", f".hook-{name}.token"),
                    ("1" * 64 + "\n").encode("ascii"),
                )
            with (
                mock.patch.object(cmd_setup, "_TOKEN_ROTATION_MAX_HOOK_SIDECARS", 1),
                self.assertRaisesRegex(click.ClickException, "roster is too large"),
            ):
                cmd_setup._rotate_token_persisted_hook_scopes(td)

    def test_second_sidecar_write_failure_restores_every_exact_snapshot_and_ready_a(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            dotenv = Path(td, ".env")
            original_dotenv = b"KEEP=exact\r\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\r\n"
            dotenv.write_bytes(original_dotenv)
            paths = [Path(td, "hooks", f".hook-{name}.token") for name in ("claudecode", "codex")]
            if os.name != "nt":
                paths[0].chmod(0o400)
            originals = {path: path.read_bytes() for path in paths}
            original_modes = {path: path.stat().st_mode & 0o777 for path in paths}
            real_write = cmd_setup.atomic_write_private_bytes
            injected = False
            hook_write_custody_modes: list[bool] = []
            events: list[tuple[str, bool, str]] = []

            def fail_second_sidecar(path: str | os.PathLike[str], data: bytes, *args, **kwargs) -> None:
                nonlocal injected
                if ".hook-" in os.path.basename(os.fspath(path)):
                    hook_write_custody_modes.append(kwargs.get("windows_managed_custody", False))
                if (
                    not injected
                    and os.fspath(path).endswith(".hook-codex.token")
                    and data == (b"\x42" * 32).hex().encode() + b"\n"
                ):
                    injected = True
                    raise OSError("simulated scoped publish failure")
                real_write(path, data, *args, **kwargs)

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del config_file, connector_state
                events.append((action, cleanup, token))

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup, "atomic_write_private_bytes", side_effect=fail_second_sidecar),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(
                    cmd_setup.secrets,
                    "token_bytes",
                    side_effect=[b"\x21" * 32, b"\x42" * 32],
                ),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            restored_dotenv = dotenv.read_bytes()
            restored_sidecars = {path: path.read_bytes() for path in paths}
            restored_modes = {path: path.stat().st_mode & 0o777 for path in paths}

        self.assertNotEqual(result.exit_code, 0)
        self.assertTrue(injected)
        self.assertEqual(
            events,
            [
                ("stop", False, "a" * 64),
                ("stop", True, "b" * 64),
                ("start", False, "a" * 64),
            ],
        )
        self.assertEqual(restored_dotenv, original_dotenv)
        self.assertEqual(restored_sidecars, originals)
        self.assertEqual(restored_modes, original_modes)
        self.assertTrue(hook_write_custody_modes)
        self.assertTrue(all(hook_write_custody_modes))
        for secret in ((b"\x21" * 32).hex(), (b"\x42" * 32).hex()):
            self.assertNotIn(secret, result.output)

    def test_restore_failure_chains_first_error_and_attempts_every_restore(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = Path(td, ".env")
            dotenv.write_bytes(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n")
            primary_error = RuntimeError("simulated gateway B failure")
            hook_restore_error = OSError("specific hook restore failure")
            dotenv_restore_error = OSError("specific dotenv restore failure")

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del config_file, connector_state, cleanup
                if action == "start" and token == "b" * 64:
                    raise primary_error

            hook_restore = mock.Mock(side_effect=hook_restore_error)
            dotenv_restore = mock.Mock(side_effect=dotenv_restore_error)
            with (
                mock.patch.object(cmd_setup, "load_config", return_value=app.cfg),
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(
                    cmd_setup,
                    "_rotate_token_restore_hook_snapshots_locked",
                    hook_restore,
                ),
                mock.patch.object(cmd_setup, "_rotate_token_restore_locked", dotenv_restore),
                self.assertRaises(click.ClickException) as raised,
            ):
                cmd_setup._rotate_token_transaction(
                    app,
                    os.fspath(dotenv),
                    "b" * 64,
                    "fixture rollback failure",
                )

        hook_restore.assert_called_once()
        dotenv_restore.assert_called_once()
        self.assertIs(raised.exception.__cause__, hook_restore_error)
        self.assertEqual(str(raised.exception.__cause__), "specific hook restore failure")
        self.assertIs(hook_restore_error.__context__, primary_error)
        self.assertIn("credential snapshots could not all be restored", str(raised.exception))

    def test_readiness_sidecar_mismatch_rolls_back_all_scoped_credentials(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["claudecode", "codex"])
            paths = [Path(td, "hooks", f".hook-{name}.token") for name in ("claudecode", "codex")]
            originals = {path: path.read_bytes() for path in paths}
            events: list[tuple[str, bool]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del config_file, connector_state
                events.append((action, cleanup))
                if action == "start" and token == "b" * 64:
                    paths[1].write_bytes((b"\x63" * 32).hex().encode("ascii") + b"\n")
                    paths[1].chmod(0o600)

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(
                    cmd_setup.secrets,
                    "token_bytes",
                    side_effect=[b"\x21" * 32, b"\x42" * 32],
                ),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            restored = {path: path.read_bytes() for path in paths}

        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(events, [("stop", False), ("start", False), ("stop", True), ("start", False)])
        self.assertEqual(restored, originals)
        self.assertNotIn((b"\x63" * 32).hex(), result.output)

    def test_stopped_missing_sidecar_is_minted_but_failure_restores_absence(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            sidecar = Path(td, "hooks", ".hook-codex.token")
            sidecar.unlink()
            events: list[tuple[str, bool]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                del token, config_file, connector_state
                events.append((action, cleanup))
                if action == "start":
                    raise click.ClickException("simulated readiness failure")

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=False),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
                mock.patch.object(cmd_setup.secrets, "token_bytes", return_value=b"\x42" * 32),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

            exists_after = sidecar.exists()

        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(events, [("stop", False), ("start", False), ("stop", True)])
        self.assertFalse(exists_after)

    def test_running_missing_sidecar_refuses_before_stop(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            Path(td, "hooks", ".hook-codex.token").unlink()
            lifecycle = mock.Mock()
            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", lifecycle),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)

        self.assertNotEqual(result.exit_code, 0)
        lifecycle.assert_not_called()
        self.assertIn("missing its scoped hook credential", result.output)

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
            events: list[tuple[str, bool, str, bytes]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                with open(dotenv, "rb") as fh:
                    events.append((action, cleanup, token, fh.read()))

            with (
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                mock.patch.object(cmd_setup.secrets, "token_hex", return_value="b" * 64),
            ):
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            self.assertEqual(
                [(action, cleanup) for action, cleanup, _, _ in events],
                [("stop", False), ("start", False), ("stop", True), ("start", False)],
            )
            self.assertEqual([token for _, _, token, _ in events], ["a" * 64, "b" * 64, "b" * 64, "a" * 64])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[1][3])
            self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[2][3])
            self.assertEqual(events[3][3], original)
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
            os.makedirs(hooks, exist_ok=True)
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

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
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
                cmd_setup._run_rotate_token_lifecycle(
                    "D:\\fixture-data",
                    "start",
                    token="explicit-a-value",
                    config_file="D:\\fixture-data\\config.yaml",
                    connector_state='{"connectors":[],"version":1}',
                )

        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            [
                "gateway-fixture",
                "start",
                "--rotation-transaction",
                "--rotation-connector-state",
                '{"connectors":[],"version":1}',
            ],
        )
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
            cmd_setup._run_rotate_token_lifecycle(
                "D:\\fixture-data",
                "stop",
                token="explicit-b-value",
                config_file="D:\\fixture-data\\config.yaml",
                cleanup=True,
            )
        self.assertEqual(
            cleanup_run.call_args.args[0],
            ["gateway-fixture", "stop", "--rotation-transaction", "--rotation-cleanup"],
        )

    def test_lifecycle_child_environment_is_bounded_and_uses_explicit_transaction_inputs(self) -> None:
        data_dir = "D:\\fixture-data"
        config_file = "D:\\authoritative-config\\config.yaml"
        explicit_token = "explicit-a-value"
        ambient = {
            "PATH": "D:\\fixture-bin",
            "SystemRoot": "D:\\fixture-windows",
            "USERPROFILE": "D:\\foreign-user-profile",
            "CODEX_HOME": "D:\\authoritative-codex-home",
            "CLAUDE_CONFIG_DIR": "D:\\authoritative-claude-home",
            "DEFENSECLAW_TRUSTED_BIN_PREFIXES": "D:\\trusted-python",
            "DEFENSECLAW_INSTALL_ROOT": "D:\\ambient-install-root",
            "UNRELATED_SENTINEL": "sentinel-value",
            "UNRELATED_SECRET": "private-fixture-value",
            cmd_setup._GATEWAY_TOKEN_ENV: "ambient-gateway-value",
            cmd_setup._LEGACY_GATEWAY_TOKEN_ENV: "ambient-legacy-value",
            cmd_setup._DEFENSECLAW_HOME_ENV: "D:\\ambient-home",
            cmd_setup._DEFENSECLAW_DATA_DIR_ENV: "D:\\ambient-data",
        }
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.dict(os.environ, ambient, clear=True),
            mock.patch.object(cmd_setup, "_gateway_lifecycle_executable", return_value="gateway-fixture"),
            mock.patch.object(cmd_setup.subprocess, "run", return_value=completed) as run,
        ):
            cmd_setup._run_rotate_token_lifecycle(
                data_dir,
                "stop",
                token=explicit_token,
                config_file=config_file,
            )

        argv = run.call_args.args[0]
        child_env = run.call_args.kwargs["env"]
        self.assertNotIn(explicit_token, " ".join(argv))
        self.assertEqual(child_env["PATH"], ambient["PATH"])
        self.assertEqual(child_env["SystemRoot"], ambient["SystemRoot"])
        self.assertEqual(child_env["USERPROFILE"], ambient["USERPROFILE"])
        self.assertEqual(child_env["CODEX_HOME"], ambient["CODEX_HOME"])
        self.assertEqual(child_env["CLAUDE_CONFIG_DIR"], ambient["CLAUDE_CONFIG_DIR"])
        self.assertEqual(
            child_env["DEFENSECLAW_TRUSTED_BIN_PREFIXES"],
            ambient["DEFENSECLAW_TRUSTED_BIN_PREFIXES"],
        )
        self.assertEqual(child_env[cmd_setup._DEFENSECLAW_HOME_ENV], os.path.abspath(data_dir))
        self.assertEqual(child_env[cmd_setup._DEFENSECLAW_DATA_DIR_ENV], os.path.abspath(data_dir))
        self.assertEqual(child_env[CONFIG_PATH_ENV], os.path.abspath(config_file))
        self.assertEqual(child_env[cmd_setup._GATEWAY_TOKEN_ENV], explicit_token)
        self.assertNotIn("UNRELATED_SENTINEL", child_env)
        self.assertNotIn("UNRELATED_SECRET", child_env)
        self.assertNotIn("DEFENSECLAW_INSTALL_ROOT", child_env)
        self.assertNotIn(cmd_setup._LEGACY_GATEWAY_TOKEN_ENV, child_env)
        self.assertEqual(
            set(child_env),
            {
                "PATH",
                "SystemRoot",
                "USERPROFILE",
                "CODEX_HOME",
                "CLAUDE_CONFIG_DIR",
                "DEFENSECLAW_TRUSTED_BIN_PREFIXES",
                CONFIG_PATH_ENV,
                cmd_setup._DEFENSECLAW_HOME_ENV,
                cmd_setup._DEFENSECLAW_DATA_DIR_ENV,
                cmd_setup._GATEWAY_TOKEN_ENV,
            },
        )

    def test_start_b_failure_restores_exact_snapshot_and_ready_a(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = os.path.join(td, ".env")
            original = b"KEEP=unchanged\nDEFENSECLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n"
            with open(dotenv, "wb") as fh:
                fh.write(original)
            connector_token_state = os.path.join(td, "connector-token-state")

            def connector_bytes(token: str) -> bytes:
                return b"connector-token=" + token.encode("ascii") + b"\r\n"

            original_connector = connector_bytes("a" * 64)
            with open(connector_token_state, "wb") as fh:
                fh.write(original_connector)
            config_file = os.path.join(td, "config.yaml")
            original_config = b"claw:\n  mode: codex\nguardrail:\n  connector: codex\n  mode: action\n"
            with open(config_file, "wb") as fh:
                fh.write(original_config)
            events: list[tuple[str, bool, str, bytes, bytes]] = []
            start_connector_states: list[str] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                self.assertEqual(config_file, os.path.abspath(os.path.join(td, "config.yaml")))
                # Model the gateway's connector refresh before readiness. A
                # rejected B start has already persisted B into connector
                # state; restarting A must deterministically restore A.
                if action == "start":
                    self.assertIsNotNone(connector_state)
                    start_connector_states.append(str(connector_state))
                    if token == "a" * 64 and events:
                        with open(config_file, "rb") as fh:
                            self.assertEqual(fh.read(), original_config)
                    with open(connector_token_state, "wb") as fh:
                        fh.write(connector_bytes(token))
                    if token == "b" * 64:
                        with open(config_file, "wb") as fh:
                            fh.write(b"guardrail:\n  mode: observe\n")
                with open(dotenv, "rb") as fh:
                    dotenv_state = fh.read()
                with open(connector_token_state, "rb") as fh:
                    persisted_connector_state = fh.read()
                events.append(
                    (action, cleanup, token, dotenv_state, persisted_connector_state),
                )
                if [(event[0], event[1]) for event in events] == [
                    ("stop", False),
                    ("start", False),
                ]:
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
            with open(connector_token_state, "rb") as fh:
                restored_connector = fh.read()
            with open(config_file, "rb") as fh:
                restored_config = fh.read()

        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(
            [(action, cleanup) for action, cleanup, *_ in events],
            [("stop", False), ("start", False), ("stop", True), ("start", False)],
        )
        self.assertEqual(
            [token for _, _, token, _, _ in events],
            ["a" * 64, "b" * 64, "b" * 64, "a" * 64],
        )
        self.assertEqual(events[0][3], original)
        self.assertIn(b"DEFENSECLAW_GATEWAY_TOKEN=" + b"b" * 64, events[1][3])
        self.assertEqual(events[1][4], connector_bytes("b" * 64))
        self.assertEqual(events[2][4], connector_bytes("b" * 64))
        self.assertEqual(events[3][3], original)
        self.assertEqual(events[3][4], original_connector)
        self.assertEqual(len(start_connector_states), 2)
        state_b, state_a = (json.loads(value) for value in start_connector_states)
        self.assertEqual(state_b["connectors"], state_a["connectors"])
        self.assertNotEqual(
            state_b["hook_token_fingerprints"]["codex"],
            state_a["hook_token_fingerprints"]["codex"],
        )
        self.assertEqual(
            state_a["hook_token_fingerprints"]["codex"],
            cmd_setup._rotate_token_hook_fingerprint(f"{1:064x}"),
        )
        self.assertEqual(restored, original)
        self.assertEqual(restored_connector, original_connector)
        self.assertEqual(restored_config, original_config)
        self.assertNotIn("b" * 64, result.output)
        self.assertNotIn("Hook scripts refreshed", result.output)

    def test_exposure_transaction_failure_never_restarts_compromised_a(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            dotenv = os.path.join(td, ".env")
            old_token = "a" * 64
            new_token = "b" * 64
            original = b"KEEP=exact\r\n" + b"DEFENSECLAW_GATEWAY_TOKEN=" + old_token.encode() + b"\r\n"
            with open(dotenv, "wb") as fh:
                fh.write(original)
            events: list[tuple[str, bool, str]] = []

            def lifecycle(
                _data_dir: str,
                action: str,
                *,
                token: str,
                config_file: str,
                connector_state: str | None = None,
                cleanup: bool = False,
            ) -> None:
                events.append((action, cleanup, token))
                if action == "start":
                    raise click.ClickException("gateway B activation failed")

            with (
                mock.patch.object(cmd_setup, "load_config", return_value=app.cfg),
                mock.patch.object(cmd_setup, "_is_pid_alive", return_value=True),
                mock.patch.object(
                    cmd_setup,
                    "_run_rotate_token_lifecycle",
                    side_effect=lifecycle,
                ),
                self.assertRaises(click.ClickException),
            ):
                cmd_setup._rotate_token_transaction(
                    app,
                    dotenv,
                    new_token,
                    "action=doctor-exposure-rotation restart=true",
                    recover_previous_runtime=False,
                )

            with open(dotenv, "rb") as fh:
                restored = fh.read()

        self.assertEqual(
            events,
            [
                ("stop", False, old_token),
                ("start", False, new_token),
                ("stop", True, new_token),
            ],
        )
        self.assertEqual(restored, original)
        self.assertNotIn(("start", False, old_token), events)


if __name__ == "__main__":
    unittest.main()
