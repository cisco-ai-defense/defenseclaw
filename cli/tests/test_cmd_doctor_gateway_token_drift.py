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
* ``_fix_gateway_token_drift`` — invokes the managed, readiness-aware
  lifecycle only when drift is confirmed AND operator confirms; silently
  skips when there's nothing to fix.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _check_gateway_token_drift,
    _DoctorResult,
    _fix_gateway_token_drift,
    _gateway_process_trust,
    _GatewayTrust,
    _read_pid_from_file,
    _read_process_env_var,
)
from defenseclaw.doctor_gateway import PIDRecord, ProcessEvidence


def _make_cfg(data_dir: str) -> SimpleNamespace:
    with open(os.path.join(data_dir, "config.yaml"), "w", encoding="utf-8") as fh:
        fh.write("config_version: 8\n")
    gateway = SimpleNamespace(
        api_bind="",
        api_port=18_970,
        token_env="",
        resolved_token=lambda: "",
    )
    return SimpleNamespace(data_dir=data_dir, gateway=gateway, save=MagicMock())


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
            json.dump(
                {
                    "pid": pid,
                    "executable": os.path.join(data_dir, "bin", "defenseclaw-gateway"),
                    "start_identity": "start-1",
                    "data_dir": data_dir,
                },
                f,
            )
    else:
        with open(path, "w") as f:
            f.write(str(pid))


def _trusted_process(
    cfg: SimpleNamespace,
    *,
    pid: int,
    start_identity: str = "start-1",
) -> _GatewayTrust:
    """Build trust from the same rich identity current gateways persist."""
    executable = os.path.join(cfg.data_dir, "bin", "defenseclaw-gateway")
    record = PIDRecord(
        "ok",
        pid=pid,
        executable=executable,
        start_identity=start_identity,
        data_dir=cfg.data_dir,
    )
    process = ProcessEvidence(
        "ok",
        pid=pid,
        executable=executable,
        start_identity=start_identity,
    )
    trust = _gateway_process_trust(
        cfg,
        record,
        process,
        platform_name="linux",
    )
    if not trust.trusted:
        raise AssertionError(f"test fixture did not establish process trust: {trust.code}")
    return trust


def _listener_unavailable(process_trust: _GatewayTrust) -> _GatewayTrust:
    """Preserve rich process evidence while modelling listener uncertainty."""
    return _GatewayTrust(
        "unavailable",
        "listener ownership unavailable",
        process_trust.pid,
        home_bound=process_trust.home_bound,
        record=process_trust.record,
        process=process_trust.process,
    )


def _status_body(cfg: SimpleNamespace, pid: int) -> str:
    return json.dumps({"runtime": {"pid": pid, "data_dir": cfg.data_dir}})


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
        self.process_trust = _trusted_process(self.cfg, pid=os.getpid())

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
        with patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=self.process_trust,
        ):
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
        with patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=self.process_trust,
        ):
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
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value=token,
            ),
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
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="old-cached-token",
            ),
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
        # Prefixes and hashes are credentials too; diagnostics must expose none.
        self.assertNotIn("old-cach", fail_msg)
        self.assertNotIn("new-toke", fail_msg)

    def test_skip_when_process_env_unreadable(self):
        """Sidecar's env can't be introspected (permissions /
        process raced away). Must emit ``skip`` (not warn), because
        "can't tell" isn't drift.
        """
        _seed_dotenv(self.tmp, "abc123")
        _seed_pidfile(self.tmp, os.getpid())
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value=None,
            ),
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
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value="",
            ),
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
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value=token,
            ),
        ):
            r = _DoctorResult()
            _check_gateway_token_drift(self.cfg, r)
        self.assertEqual(r.passed, 1)


class FixGatewayTokenDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-drift-fix-")
        self.cfg = _make_cfg(self.tmp)
        self.pid = os.getpid()
        self.process_trust = _trusted_process(self.cfg, pid=self.pid)
        self.replacement_trust = _trusted_process(
            self.cfg,
            pid=self.pid + 1,
            start_identity="start-2",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_skip_when_no_pidfile(self):
        result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "skip")

    def test_skip_when_no_dotenv(self):
        _seed_pidfile(self.tmp, self.pid)
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            ) as listener,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "skip")
        listener.assert_not_called()

    def test_skip_when_no_drift(self):
        token = "same" * 10
        _seed_dotenv(self.tmp, token)
        _seed_pidfile(self.tmp, self.pid)
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                return_value=_listener_unavailable(self.process_trust),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._read_process_env_var",
                return_value=token,
            ),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "skip")
        self.assertIn("already matches", result[1])

    def test_fail_when_managed_restart_is_unavailable(self):
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, self.pid)
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                return_value=(401, ""),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
                return_value=(False, "binary not found"),
            ),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "fail")
        self.assertIn("readiness verification failed", result[1])

    def test_pass_invokes_gateway_restart(self):
        """Confirmed drift uses the managed, readiness-aware lifecycle."""
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, self.pid)
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                side_effect=[self.process_trust, self.replacement_trust],
            ) as listener,
            patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                side_effect=[
                    (401, ""),
                    (200, _status_body(self.cfg, self.replacement_trust.pid)),
                ],
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
                return_value=(True, ""),
            ) as repair,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "pass")
        repair.assert_called_once_with(self.cfg, start_if_stopped=False)
        self.assertEqual(listener.call_count, 2)

    def test_fail_when_managed_restart_returns_false(self):
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, self.pid)
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                return_value=(401, ""),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
                return_value=(False, "managed lifecycle did not reach verified readiness"),
            ),
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)
        self.assertEqual(result[0], "fail")
        self.assertIn("readiness verification failed", result[1])

    def test_skip_when_user_declines(self):
        """Operator must explicitly confirm before we bounce a live
        sidecar (in-flight requests interrupted).
        """
        _seed_dotenv(self.tmp, "new-tok")
        _seed_pidfile(self.tmp, self.pid)
        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
                return_value=self.process_trust,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                return_value=(401, ""),
            ),
            patch(
                "defenseclaw.commands.cmd_doctor.click.confirm",
                return_value=False,
            ),
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            ) as repair,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=False)
        self.assertEqual(result[0], "skip")
        self.assertIn("declined", result[1])
        repair.assert_not_called()

    def test_fail_closed_for_malformed_pid_record(self):
        trust = _gateway_process_trust(
            self.cfg,
            PIDRecord("malformed", reason="PID file is not a safe regular file"),
            None,
            platform_name="linux",
        )

        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=trust,
            ),
            patch("defenseclaw.commands.cmd_doctor._http_probe") as probe,
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            ) as repair,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)

        self.assertEqual(result[0], "fail")
        self.assertIn("PID file is invalid", result[1])
        probe.assert_not_called()
        repair.assert_not_called()

    def test_fail_closed_for_legacy_pid_record(self):
        trust = _gateway_process_trust(
            self.cfg,
            PIDRecord("ok", pid=self.pid, data_dir=self.tmp),
            ProcessEvidence(
                "ok",
                pid=self.pid,
                executable=os.path.join(self.tmp, "bin", "defenseclaw-gateway"),
                start_identity="start-1",
            ),
            platform_name="linux",
        )

        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=trust,
            ),
            patch("defenseclaw.commands.cmd_doctor._http_probe") as probe,
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            ) as repair,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)

        self.assertEqual(trust.code, "legacy_identity")
        self.assertEqual(result[0], "fail")
        self.assertIn("legacy PID record", result[1])
        probe.assert_not_called()
        repair.assert_not_called()

    def test_fail_closed_for_unbound_pid_record(self):
        executable = os.path.join(self.tmp, "bin", "defenseclaw-gateway.exe")
        trust = _gateway_process_trust(
            self.cfg,
            PIDRecord(
                "ok",
                pid=self.pid,
                executable=executable,
                start_identity="start-1",
            ),
            ProcessEvidence(
                "ok",
                pid=self.pid,
                executable=executable,
                start_identity="start-1",
            ),
            platform_name="win32",
        )

        with (
            patch(
                "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
                return_value=trust,
            ),
            patch("defenseclaw.commands.cmd_doctor._http_probe") as probe,
            patch(
                "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            ) as repair,
        ):
            result = _fix_gateway_token_drift(self.cfg, assume_yes=True)

        self.assertEqual(trust.code, "unbound_home")
        self.assertEqual(result[0], "fail")
        self.assertIn("not bound", result[1])
        probe.assert_not_called()
        repair.assert_not_called()


if __name__ == "__main__":
    unittest.main()
