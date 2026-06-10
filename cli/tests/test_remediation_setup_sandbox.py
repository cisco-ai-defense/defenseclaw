# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Remediation regression tests for Avarice findings in the setup / init /
sandbox lifecycle.

One focused test per finding, each asserting the *fixed* (fail-closed)
behavior so a regression to the original vulnerable code re-fails the test:

* F-0101 / F-0121 — gateway PID identity must match the gateway binary name
  exactly (no generic ``defenseclaw`` prefix acceptance).
* F-0721 — a spoofed ``gateway.pid`` pointing at a live but unrelated process
  must not be treated as the running gateway.
* F-0142 / F-0143 — a failed gateway restart must propagate (fail closed),
  not be swallowed.
* F-0161 — privileged sandbox chown must refuse a ``.openclaw`` symlink whose
  realpath diverges from the pinned original home.
* F-0162 — sandbox-init idempotency fast-path must refuse a swapped
  ``.openclaw`` symlink.
* F-0163 — systemd/script install must copy only known filenames and refuse
  tampered (symlink / foreign-owned / group-writable) sources.
* F-0165 — generated ``pre-sandbox.sh`` tamper-guard must ``exit 1`` (fail
  closed) on a symlink mismatch.
* F-0166 — sandbox disable must restore the saved prior ``route_localnet``
  value instead of clobbering host state with 0.
* F-0122 — first-run init must create operator-private directories 0700.
"""

import os
import re
import stat
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Minimal config doubles for the sandbox launcher / chown helpers.
# ---------------------------------------------------------------------------
class _Claw:
    def __init__(self, openclaw_home_original: str = ""):
        self.openclaw_home_original = openclaw_home_original


class _Openshell:
    def __init__(self):
        self.host_networking = True


class _Guardrail:
    def __init__(self):
        self.port = 4000
        self.enabled = True


class _Gateway:
    def __init__(self):
        self.api_port = 18790
        self.port = 18789


class _Cfg:
    """Concrete (non-MagicMock) config so ``int(cfg.gateway.port)`` etc. work
    inside the launcher generator."""

    def __init__(self, data_dir: str = "", openclaw_home_original: str = ""):
        self.data_dir = data_dir
        self.gateway = _Gateway()
        self.guardrail = _Guardrail()
        self.openshell = _Openshell()
        self.claw = _Claw(openclaw_home_original)


def _patch_no_sudo():
    return patch(
        "defenseclaw.commands.cmd_init_sandbox._needs_sudo", return_value=False
    )


class TestGatewayPidIdentity(unittest.TestCase):
    """F-0101 / F-0121 / F-0721: gateway PID identity must be an *exact*
    binary-name match and must fail closed for foreign processes."""

    @patch("defenseclaw.process_liveness.process_argv0_basename")
    def test_f0101_bootstrap_rejects_lookalike_name(self, mock_argv0):
        from defenseclaw.bootstrap import _pid_looks_like_gateway

        # The original bug accepted any argv0 starting with "defenseclaw".
        mock_argv0.return_value = "defenseclaw-not-gateway"
        self.assertFalse(_pid_looks_like_gateway(4242))

        # The real gateway binary name is still accepted.
        mock_argv0.return_value = "defenseclaw-gateway"
        self.assertTrue(_pid_looks_like_gateway(4242))

    @patch("defenseclaw.process_liveness.process_argv0_basename")
    def test_f0121_init_rejects_lookalike_name(self, mock_argv0):
        from defenseclaw.commands.cmd_init import _pid_looks_like_gateway

        mock_argv0.return_value = "defenseclaw-not-gateway"
        self.assertFalse(_pid_looks_like_gateway(4242))

        mock_argv0.return_value = "defenseclaw-gateway"
        self.assertTrue(_pid_looks_like_gateway(4242))

    @patch("defenseclaw.process_liveness.process_argv0_basename")
    def test_f0721_spoofed_pidfile_foreign_process_rejected(self, mock_argv0):
        from defenseclaw.commands.cmd_setup import (
            _gateway_pid_file_identifies_gateway,
        )
        from defenseclaw.process_liveness import process_is_gateway

        # A spoofed gateway.pid points at a live but unrelated process.
        mock_argv0.return_value = "sleep"
        self.assertFalse(process_is_gateway(1234))

        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, "gateway.pid")
            with open(pid_file, "w") as fh:
                fh.write("1234")
            self.assertFalse(_gateway_pid_file_identifies_gateway(pid_file))

            # Same PID, but now it really is the gateway → accepted.
            mock_argv0.return_value = "defenseclaw-gateway"
            self.assertTrue(_gateway_pid_file_identifies_gateway(pid_file))


class TestRestartFailsClosed(unittest.TestCase):
    """F-0142 / F-0143: restart failures must propagate, not be swallowed."""

    @patch("defenseclaw.commands.cmd_setup.subprocess.run", side_effect=FileNotFoundError)
    def test_f0142_restart_defense_gateway_returns_false_on_failure(self, _mock_run):
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway

        with tempfile.TemporaryDirectory() as tmp:
            # No gateway.pid → start path; binary missing → must report failure
            # (the original code returned None and callers read it as success).
            self.assertIs(_restart_defense_gateway(tmp), False)

    def test_f0143_restart_services_fails_closed_when_gateway_down(self):
        from defenseclaw.commands import cmd_setup

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cmd_setup, "_restart_defense_gateway", return_value=False), \
                 patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=False) as mock_oc, \
                 patch.object(cmd_setup, "_check_openclaw_gateway"):
                with self.assertRaises(click.ClickException):
                    cmd_setup._restart_services(tmp, connector="openclaw")
                # The OpenClaw gateway restart helper must also have been
                # consulted (F-0143) and reported failure.
                mock_oc.assert_called_once()

    @patch("defenseclaw.commands.cmd_setup.subprocess.run", side_effect=FileNotFoundError)
    def test_f0143_restart_openclaw_gateway_returns_false_on_failure(self, _mock_run):
        from defenseclaw.commands.cmd_setup import _restart_openclaw_gateway

        self.assertIs(_restart_openclaw_gateway(), False)


class TestSandboxChownPin(unittest.TestCase):
    """F-0161: privileged chown must refuse a divergent symlink target."""

    def test_f0161_refuses_divergent_openclaw_target(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _assert_oc_target_is_pinned_home,
        )

        with tempfile.TemporaryDirectory() as tmp:
            pinned = os.path.join(tmp, "real-openclaw")
            evil = os.path.join(tmp, "evil")
            os.makedirs(pinned)
            os.makedirs(evil)
            cfg = _Cfg(openclaw_home_original=pinned)

            # Symlink swapped to an attacker tree → fail closed.
            with self.assertRaises(SystemExit):
                _assert_oc_target_is_pinned_home(evil, cfg)

            # Legitimate target equal to the pinned home → no raise.
            _assert_oc_target_is_pinned_home(pinned, cfg)


class TestSandboxInitIdempotentPin(unittest.TestCase):
    """F-0162: idempotency fast-path must refuse a swapped .openclaw symlink."""

    def test_f0162_refuses_swapped_symlink(self):
        from defenseclaw.commands.cmd_init_sandbox import (
            OPENCLAW_OWNERSHIP_BACKUP,
            _integrate_openclaw_home,
        )

        with tempfile.TemporaryDirectory() as tmp:
            data_dir = os.path.join(tmp, "data")
            sandbox_home = os.path.join(tmp, "sandbox")
            pinned = os.path.join(tmp, "real-openclaw")
            evil = os.path.join(tmp, "evil")
            for d in (data_dir, sandbox_home, pinned, evil):
                os.makedirs(d)

            # Idempotency preconditions: ownership backup present + symlink set.
            with open(os.path.join(data_dir, OPENCLAW_OWNERSHIP_BACKUP), "w") as fh:
                fh.write("{}")
            os.symlink(evil, os.path.join(sandbox_home, ".openclaw"))

            cfg = MagicMock()
            cfg.data_dir = data_dir
            cfg.claw.openclaw_home_original = pinned

            # Swapped symlink (evil != pinned) → fail closed.
            self.assertFalse(_integrate_openclaw_home(cfg, sandbox_home))


class TestSystemdInstallValidation(unittest.TestCase):
    """F-0163: install only known filenames, refusing tampered sources."""

    def test_f0163_source_trust_predicate(self):
        from defenseclaw.commands.cmd_setup_sandbox import _install_source_is_trusted

        with tempfile.TemporaryDirectory() as tmp:
            good = os.path.join(tmp, "openshell-sandbox.service")
            with open(good, "w") as fh:
                fh.write("[Unit]\n")
            os.chmod(good, 0o644)
            self.assertTrue(_install_source_is_trusted(good))

            # A symlink is never a trusted source.
            link = os.path.join(tmp, "link.service")
            os.symlink(good, link)
            self.assertFalse(_install_source_is_trusted(link))

            # Group/other-writable regular file is rejected (tamperable).
            ww = os.path.join(tmp, "ww.service")
            with open(ww, "w") as fh:
                fh.write("x")
            os.chmod(ww, 0o666)
            self.assertFalse(_install_source_is_trusted(ww))

    @patch("defenseclaw.commands.cmd_setup_sandbox.subprocess.run")
    def test_f0163_install_refuses_tampered_unit_before_copy(self, mock_run):
        from defenseclaw.commands.cmd_setup_sandbox import _install_systemd_units

        with tempfile.TemporaryDirectory() as tmp:
            systemd = os.path.join(tmp, "systemd")
            os.makedirs(systemd)
            # Plant a symlink in place of a known unit name. A privileged copy
            # that followed it would smuggle an attacker file into
            # /etc/systemd/system; install must refuse and run no privileged cp.
            payload = os.path.join(tmp, "payload.service")
            with open(payload, "w") as fh:
                fh.write("[Service]\nExecStart=/bin/true\n")
            os.symlink(payload, os.path.join(systemd, "openshell-sandbox.service"))

            self.assertFalse(_install_systemd_units(tmp))
            mock_run.assert_not_called()


class TestPreSandboxFailsClosed(unittest.TestCase):
    """F-0165: generated pre-sandbox tamper-guard must exit 1 on mismatch."""

    def test_f0165_pre_sandbox_exits_nonzero_on_symlink_mismatch(self):
        from defenseclaw.commands.cmd_setup_sandbox import _generate_launcher_scripts

        with tempfile.TemporaryDirectory() as tmp, _patch_no_sudo():
            sandbox_home = os.path.join(tmp, "sandbox")
            os.makedirs(sandbox_home)
            cfg = _Cfg(data_dir=tmp, openclaw_home_original=os.path.join(tmp, "oc"))
            _generate_launcher_scripts(
                tmp, sandbox_home, "10.200.0.1", "10.200.0.2", cfg
            )
            with open(os.path.join(tmp, "scripts", "pre-sandbox.sh")) as fh:
                content = fh.read()

            # Each tamper-guard branch must fail closed.
            codes = re.findall(
                r"refusing privileged repair[\s\S]*?\n\s*exit (\d)", content
            )
            self.assertTrue(codes, "no tamper-guard branches found in pre-sandbox.sh")
            self.assertTrue(
                all(code == "1" for code in codes),
                f"tamper-guard branch fails open (exit codes={codes})",
            )


class TestRouteLocalnetRestore(unittest.TestCase):
    """F-0166: disable must restore the saved route_localnet, not force 0."""

    @patch("defenseclaw.commands.cmd_setup_sandbox.subprocess.run")
    @patch("defenseclaw.commands.cmd_setup_sandbox._sudo_prefix", return_value=[])
    def test_f0166_restores_saved_value(self, _mock_sudo, mock_run):
        from defenseclaw.commands.cmd_setup_sandbox import _restore_route_localnet

        with tempfile.TemporaryDirectory() as tmp:
            # Host originally had route_localnet=1; setup recorded it.
            with open(os.path.join(tmp, "saved.route_localnet"), "w") as fh:
                fh.write("1\n")

            _restore_route_localnet(tmp)

            sysctl_calls = [
                c.args[0] for c in mock_run.call_args_list
                if c.args and "sysctl" in c.args[0]
            ]
            self.assertEqual(len(sysctl_calls), 1)
            # Restored to the saved value (1), never clobbered to 0.
            self.assertIn("net.ipv4.conf.all.route_localnet=1", sysctl_calls[0])
            self.assertNotIn("net.ipv4.conf.all.route_localnet=0", sysctl_calls[0])
            # Saved-state file consumed so a later run can't restore stale data.
            self.assertFalse(os.path.exists(os.path.join(tmp, "saved.route_localnet")))


class TestInitDirPermissions(unittest.TestCase):
    """F-0122: first-run init must create operator-private dirs 0700."""

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_f0122_data_dirs_are_0700(
        self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which
    ):
        from pathlib import Path

        from defenseclaw.commands.cmd_init import init_cmd
        from defenseclaw.context import AppContext

        with tempfile.TemporaryDirectory() as tmp:
            mock_path.return_value = Path(tmp)
            # A permissive umask is the dangerous case: bare os.makedirs would
            # leave these 0755 (world-readable audit state).
            old_umask = os.umask(0o022)
            try:
                result = CliRunner().invoke(
                    init_cmd, ["--skip-install"], obj=AppContext()
                )
            finally:
                os.umask(old_umask)

            self.assertEqual(result.exit_code, 0, result.output)

            for sub in ("quarantine", "plugins"):
                path = os.path.join(tmp, sub)
                self.assertTrue(os.path.isdir(path), f"{sub} not created")
                mode = stat.S_IMODE(os.stat(path).st_mode)
                self.assertEqual(
                    mode, 0o700, f"{sub} is {oct(mode)}, expected 0o700"
                )


if __name__ == "__main__":
    unittest.main()
