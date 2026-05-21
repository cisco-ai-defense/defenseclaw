"""Doctor coverage for sidecar-vs-dotenv gateway-token drift.

Failure mode this closes: the sidecar caches its auth token at boot
(from env / dotenv). If anything later rewrites
``~/.defenseclaw/.env`` — Phase 4 migration, ``EnsureGatewayToken``
re-firing, manual ``defenseclaw keys set``, an install script — the
running sidecar keeps using the OLD token while the CLI reads the
NEW one. Every ``defenseclaw agent usage`` call returns HTTP 401
with no root-cause hint.

This file covers:

* ``_read_pid_from_file`` — tolerates legacy plain-int format AND
  current JSON envelope; treats unreadable / dead PIDs as 0.
* ``_read_process_env_var`` — smoke-tested only (its OS internals
  are platform-specific; ``ps eww`` / ``/proc/<pid>/environ`` show
  the kernel snapshot at process start, NOT live ``putenv``
  modifications, so ``patch.dict(os.environ)`` can't drive it
  meaningfully from the same process).
* ``_check_gateway_token_drift`` — emits ``pass`` when tokens match,
  ``fail`` when they drift, ``skip`` when introspection can't
  decide. Driven via patching ``_read_process_env_var``.
* ``_fix_gateway_token_drift`` — invokes ``defenseclaw-gateway
  restart`` only when drift is confirmed AND operator confirms;
  silently skips when there's nothing to fix.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _DoctorResult,
    _check_gateway_token_drift,
    _fix_gateway_token_drift,
    _read_pid_from_file,
    _read_process_env_var,
)


def _make_cfg(data_dir: str) -> SimpleNamespace:
    return SimpleNamespace(data_dir=data_dir, save=MagicMock())


def _seed_dotenv(data_dir: str, token: str = "deadbeef" * 8) -> None:
    """Write a minimal .env with the given DEFENSECLAW_GATEWAY_TOKEN."""
    with open(os.path.join(data_dir, ".env"), "w") as f:
        f.write(f"DEFENSECLAW_GATEWAY_TOKEN={token}\n")
    os.chmod(os.path.join(data_dir, ".env"), 0o600)


def _seed_pidfile(data_dir: str, pid: int, *, json_envelope: bool = True) -> None:
    """Write gateway.pid with the given PID, in JSON or legacy format."""
    path = os.path.join(data_dir, "gateway.pid")
    if json_envelope:
        with open(path, "w") as f:
            json.dump({"pid": pid, "executable": "/x/y/defenseclaw-gateway"}, f)
    else:
        with open(path, "w") as f:
            f.write(str(pid))


class ReadPidFromFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-drift-pid-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_returns_zero_when_pidfile_missing(self):
        self.assertEqual(_read_pid_from_file(os.path.join(self.tmp, "gateway.pid")), 0)

    def test_parses_legacy_plain_integer_format(self):
        my_pid = os.getpid()  # guaranteed alive
        _seed_pidfile(self.tmp, my_pid, json_envelope=False)
        self.assertEqual(
            _read_pid_from_file(os.path.join(self.tmp, "gateway.pid")),
            my_pid,
        )

    def test_parses_current_json_envelope_format(self):
        my_pid = os.getpid()
        _seed_pidfile(self.tmp, my_pid, json_envelope=True)
        self.assertEqual(
            _read_pid_from_file(os.path.join(self.tmp, "gateway.pid")),
            my_pid,
        )

    def test_returns_zero_for_dead_pid(self):
        # Pick something extremely unlikely to be a real process.
        _seed_pidfile(self.tmp, 999999, json_envelope=True)
        self.assertEqual(_read_pid_from_file(os.path.join(self.tmp, "gateway.pid")), 0)

    def test_returns_zero_for_malformed_pidfile(self):
        path = os.path.join(self.tmp, "gateway.pid")
        with open(path, "w") as f:
            f.write("{not even json")
        self.assertEqual(_read_pid_from_file(path), 0)

    def test_returns_zero_for_negative_pid(self):
        path = os.path.join(self.tmp, "gateway.pid")
        with open(path, "w") as f:
            f.write("-7")
        self.assertEqual(_read_pid_from_file(path), 0)


class ReadProcessEnvVarTests(unittest.TestCase):
    """Smoke-only — see module docstring for why we don't unit-test
    the OS internals here.
    """

    def test_returns_none_for_invalid_pid(self):
        self.assertIsNone(_read_process_env_var(0, "ANYVAR"))
        self.assertIsNone(_read_process_env_var(-1, "ANYVAR"))

    def test_returns_none_for_empty_var_name(self):
        self.assertIsNone(_read_process_env_var(os.getpid(), ""))

    def test_invocation_against_dead_pid_returns_none_or_empty(self):
        """Against a definitely-dead PID, /proc lookup misses and ``ps``
        returns nonzero — we expect ``None`` (not a crash).
        """
        # ps may or may not exist on every CI runner; tolerate both.
        result = _read_process_env_var(999999, "ANYTHING")
        # Two acceptable outcomes: None (couldn't introspect) or ""
        # (introspected and definitively absent). Both are NOT-drift.
        self.assertIn(result, (None, ""))


class CheckGatewayTokenDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-drift-check-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_op_when_no_pidfile(self):
        """No sidecar running → nothing to compare. Other checks
        handle the "sidecar down" case; this one stays silent.
        """
        _seed_dotenv(self.tmp, "abc123")
        r = _DoctorResult()
        _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.passed + r.failed + r.warned, 0)

    def test_no_op_when_dotenv_missing(self):
        """No .env to read → nothing to compare against."""
        _seed_pidfile(self.tmp, os.getpid())
        r = _DoctorResult()
        _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.passed + r.failed + r.warned, 0)

    def test_no_op_when_dotenv_lacks_gateway_token(self):
        """.env exists but has no DEFENSECLAW_GATEWAY_TOKEN → no
        comparison possible. _check_sidecar would have surfaced
        the missing-token state separately.
        """
        _seed_pidfile(self.tmp, os.getpid())
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("DEFENSECLAW_LLM_KEY=something-else\n")
        r = _DoctorResult()
        _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.passed + r.failed + r.warned, 0)

    def test_pass_when_process_and_dotenv_tokens_match(self):
        """The happy path — sidecar's in-memory token matches the
        token currently in .env. Should pass quietly so the operator
        sees the green check.
        """
        token = "match" * 10
        _seed_dotenv(self.tmp, token)
        _seed_pidfile(self.tmp, os.getpid())
        with patch(
            "defenseclaw.commands.cmd_doctor._read_process_env_var",
            return_value=token,
        ):
            r = _DoctorResult()
            _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.passed, 1)
        self.assertEqual(r.failed, 0)

    def test_fail_when_process_token_differs_from_dotenv(self):
        """The exact bug repro: sidecar holds OLD token, .env has
        NEW token. Must FAIL (not warn) and explain the remediation.
        """
        _seed_dotenv(self.tmp, "new-token-from-rewrite")
        _seed_pidfile(self.tmp, os.getpid())
        with patch(
            "defenseclaw.commands.cmd_doctor._read_process_env_var",
            return_value="old-cached-token",
        ):
            r = _DoctorResult()
            _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.failed, 1)
        fail_msg = next(c for c in r.checks if c["status"] == "fail")["detail"]
        # Must surface the actionable next step.
        self.assertIn("restart", fail_msg.lower())
        # Must NOT leak full tokens into the message.
        self.assertNotIn("old-cached-token", fail_msg)
        self.assertNotIn("new-token-from-rewrite", fail_msg)
        # Should show truncated prefixes so the operator can verify.
        self.assertIn("old-cach", fail_msg)
        self.assertIn("new-toke", fail_msg)

    def test_skip_when_process_env_unreadable(self):
        """Sidecar's env can't be introspected (permissions /
        process raced away). Must emit ``skip`` (not warn), because
        "can't tell" isn't drift.
        """
        _seed_dotenv(self.tmp, "abc123")
        _seed_pidfile(self.tmp, os.getpid())
        with patch(
            "defenseclaw.commands.cmd_doctor._read_process_env_var",
            return_value=None,
        ):
            r = _DoctorResult()
            _check_gateway_token_drift(self.cfg, r)
        # No fail / no warn; one skip recorded.
        self.assertEqual(r.failed, 0)
        self.assertEqual(r.warned, 0)
        skip_records = [c for c in r.checks if c["status"] == "skip"]
        self.assertEqual(len(skip_records), 1)

    def test_skip_when_sidecar_has_no_token_var_in_env(self):
        """Sidecar started without DEFENSECLAW_GATEWAY_TOKEN in env
        (e.g. older binary that reads dotenv directly). Comparing
        meaningless; skip rather than false-flag drift.
        """
        _seed_dotenv(self.tmp, "abc123")
        _seed_pidfile(self.tmp, os.getpid())
        with patch(
            "defenseclaw.commands.cmd_doctor._read_process_env_var",
            return_value="",
        ):
            r = _DoctorResult()
            _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.failed, 0)
        skip_records = [c for c in r.checks if c["status"] == "skip"]
        self.assertEqual(len(skip_records), 1)

    def test_handles_quoted_dotenv_value(self):
        """YAML/dotenv editors sometimes quote values. Comparison
        must strip quotes the same way config._load_dotenv_into_os
        does — otherwise we'd false-flag drift on cosmetic differences.
        """
        token = "quoted-token-abc123"
        path = os.path.join(self.tmp, ".env")
        with open(path, "w") as f:
            f.write(f'DEFENSECLAW_GATEWAY_TOKEN="{token}"\n')
        os.chmod(path, 0o600)
        _seed_pidfile(self.tmp, os.getpid())
        with patch(
            "defenseclaw.commands.cmd_doctor._read_process_env_var",
            return_value=token,
        ):
            r = _DoctorResult()
            _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.passed, 1)


class FixGatewayTokenDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-drift-fix-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_skip_when_no_pidfile(self):
        result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "skip")

    def test_skip_when_no_dotenv(self):
        _seed_pidfile(self.tmp, os.getpid())
        result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "skip")

    def test_skip_when_no_drift(self):
        token = "same" * 10
        _seed_dotenv(self.tmp, token)
        _seed_pidfile(self.tmp, os.getpid())
        with patch(
            "defenseclaw.commands.cmd_doctor._read_process_env_var",
            return_value=token,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "skip")
        self.assertIn("already matches", result[1])

    def test_skip_when_gateway_binary_missing(self):
        """If defenseclaw-gateway isn't on PATH we can't auto-restart
        — return ``warn`` so the operator knows to restart manually.
        """
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, os.getpid())
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="old-tok",
            ),
            patch("defenseclaw.commands.cmd_doctor.shutil.which", return_value=None),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "warn")
        self.assertIn("restart the sidecar manually", result[1])

    def test_pass_invokes_gateway_restart(self):
        """When drift is confirmed and operator says yes, invoke
        ``defenseclaw-gateway restart``. Mock the subprocess so the
        test doesn't actually try to bounce anything.
        """
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, os.getpid())
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="restarted", stderr="",
            ),
        )
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="old-tok",
            ),
            patch(
                "defenseclaw.commands.cmd_doctor.shutil.which",
                return_value="/usr/local/bin/defenseclaw-gateway",
            ),
            patch("defenseclaw.commands.cmd_doctor.subprocess.run", mock_run),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "pass")
        mock_run.assert_called_once()
        # Verify we called the restart subcommand.
        cmd = mock_run.call_args[0][0]
        self.assertIn("restart", cmd)

    def test_fail_when_restart_returncode_nonzero(self):
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, os.getpid())
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="port in use\n",
            ),
        )
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="old-tok",
            ),
            patch(
                "defenseclaw.commands.cmd_doctor.shutil.which",
                return_value="/usr/local/bin/defenseclaw-gateway",
            ),
            patch("defenseclaw.commands.cmd_doctor.subprocess.run", mock_run),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "fail")
        self.assertIn("port in use", result[1])

    def test_fail_when_restart_times_out(self):
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, os.getpid())
        mock_run = MagicMock(
            side_effect=subprocess.TimeoutExpired(cmd="gw restart", timeout=30),
        )
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="old-tok",
            ),
            patch(
                "defenseclaw.commands.cmd_doctor.shutil.which",
                return_value="/usr/local/bin/defenseclaw-gateway",
            ),
            patch("defenseclaw.commands.cmd_doctor.subprocess.run", mock_run),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "fail")
        self.assertIn("timed out", result[1])

    def test_skip_when_user_declines(self):
        """Operator must explicitly confirm before we bounce a live
        sidecar (in-flight requests interrupted).
        """
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, os.getpid())
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="old-tok",
            ),
            patch(
                "defenseclaw.commands.cmd_doctor.shutil.which",
                return_value="/usr/local/bin/defenseclaw-gateway",
            ),
            patch("defenseclaw.commands.cmd_doctor.click.confirm", return_value=False),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=False)
        self.assertEqual(result[0], "skip")
        self.assertIn("declined", result[1])


if __name__ == "__main__":
    unittest.main()
