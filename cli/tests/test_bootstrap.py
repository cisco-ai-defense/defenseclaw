# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw.bootstrap``.

``bootstrap_env`` powers both ``init`` and ``quickstart``, so these
tests pin its idempotency + reporting contract. We run it twice per case
to catch any accidental re-seeding regressions.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.bootstrap import BootstrapReport, bootstrap_env
from defenseclaw.config import (
    Config,
    GatewayConfig,
    GuardrailConfig,
    OpenShellConfig,
)


def _cfg_for(tmp: str) -> Config:
    return Config(
        data_dir=tmp,
        audit_db=os.path.join(tmp, "audit.db"),
        quarantine_dir=os.path.join(tmp, "quarantine"),
        plugin_dir=os.path.join(tmp, "plugins"),
        policy_dir=os.path.join(tmp, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )


class BootstrapEnvTests(unittest.TestCase):
    # Every test needs ``DEFENSECLAW_HOME`` pointed at a tempdir so
    # ``config_path()`` doesn't resolve to the developer's real
    # ``~/.defenseclaw/config.yaml``. Without this, ``is_new_config``
    # becomes a function of the host machine rather than the code
    # under test, and the idempotency contract can't be exercised on
    # a fresh CI runner.
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._prev_home = os.environ.get("DEFENSECLAW_HOME")
        os.environ["DEFENSECLAW_HOME"] = self._tmp.name
        self.addCleanup(self._restore_home)

    def _restore_home(self) -> None:
        if self._prev_home is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = self._prev_home

    def test_first_run_creates_directories(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        report = bootstrap_env(cfg)

        self.assertIsInstance(report, BootstrapReport)
        self.assertEqual(report.errors, [], msg=report.errors)
        for d in (cfg.data_dir, cfg.quarantine_dir, cfg.plugin_dir, cfg.policy_dir):
            self.assertTrue(os.path.isdir(d), f"expected {d} to be created")

    def test_creates_audit_db_file(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        bootstrap_env(cfg)
        self.assertTrue(os.path.isfile(cfg.audit_db))

    def test_idempotent(self):
        """Running bootstrap twice must not error or duplicate side effects."""
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        first = bootstrap_env(cfg)
        self.assertEqual(first.errors, [])
        self.assertTrue(first.is_new_config)

        # ``init`` / ``quickstart`` persist the config after
        # ``bootstrap_env`` returns; simulate that here so the
        # ``is_new_config`` flag on the second run reflects reality.
        from defenseclaw.config import config_path
        cfg_file = str(config_path())
        os.makedirs(os.path.dirname(cfg_file), exist_ok=True)
        with open(cfg_file, "w", encoding="utf-8") as fh:
            fh.write("# seeded by test\n")

        second = bootstrap_env(cfg)
        self.assertEqual(second.errors, [])
        self.assertFalse(second.is_new_config)

    def test_reports_data_paths(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        report = bootstrap_env(cfg)
        self.assertEqual(report.data_dir, cfg.data_dir)
        self.assertEqual(report.audit_db, cfg.audit_db)


# ---------------------------------------------------------------------------
# _apply_first_run_choices: hook_fail_mode plumbing
#
# These pin the contract that callers (cmd_init, cmd_quickstart) rely on:
#
#   * Empty string in FirstRunOptions.hook_fail_mode = "leave whatever
#     was already in cfg.guardrail.hook_fail_mode alone." This is critical
#     for upgrade flows where the operator already chose "closed" via
#     `defenseclaw guardrail fail-mode` and then re-runs init for some
#     unrelated reason.
#
#   * "closed" persists exactly as "closed".
#
#   * Anything else (typo, stray uppercase, leading whitespace, garbage)
#     normalizes to "open". Failing-open on an unrecognized value is
#     strictly safer than failing-closed and bricking the agent.
#
# Mirrors normalizeHookFailMode in internal/gateway/connector/subprocess.go
# and _normalize_hook_fail_mode in cli/defenseclaw/config.py.
# ---------------------------------------------------------------------------

class ApplyFirstRunChoicesHookFailModeTests(unittest.TestCase):
    def setUp(self):
        from defenseclaw.config import default_config
        self.cfg = default_config()

    def _apply(self, hook_fail_mode: str) -> None:
        from defenseclaw.bootstrap import (
            FirstRunOptions,
            _apply_first_run_choices,
        )

        opts = FirstRunOptions(connector="codex", profile="observe", hook_fail_mode=hook_fail_mode)
        _apply_first_run_choices(self.cfg, opts, "codex", "observe", "local")

    def test_empty_string_preserves_existing_choice(self):
        self.cfg.guardrail.hook_fail_mode = "closed"
        self._apply("")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "closed",
                         "empty options.hook_fail_mode must NEVER overwrite an existing operator choice")

    def test_closed_persists(self):
        self._apply("closed")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "closed")

    def test_uppercase_closed_normalizes(self):
        self._apply("CLOSED")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "closed")

    def test_open_persists(self):
        self.cfg.guardrail.hook_fail_mode = "closed"  # seed with non-default
        self._apply("open")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "open",
                         "explicit 'open' must be honored even when starting from 'closed'")

    def test_typo_normalizes_to_open(self):
        self.cfg.guardrail.hook_fail_mode = "closed"  # seed with non-default
        self._apply("klosed")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "open",
                         "typo must NEVER silently put the agent in a stricter posture than the operator typed")


# ---------------------------------------------------------------------------
# _apply_first_run_choices: HITL (Human-In-the-Loop) plumbing
#
# These pin the contract that ``defenseclaw init`` / ``quickstart`` rely
# on when surfacing the HITL question to operators:
#
#   * ``human_approval=None`` MUST be a no-op. An operator who ran
#     ``defenseclaw setup guardrail`` last week and enabled HITL must
#     not have it silently disabled by a re-run of init that doesn't
#     pass the flag.
#
#   * Explicit True/False sets ``cfg.guardrail.hilt.enabled`` exactly.
#
#   * ``hilt_min_severity=""`` preserves the existing severity floor.
#     A valid value normalizes to uppercase. An invalid value (typo,
#     unknown severity name) falls back to ``"HIGH"`` — falling back
#     to a *stricter* posture is safer than silently demoting the
#     operator into a permissive one.
#
#   * Enabling HITL with no min_severity set anywhere backfills
#     ``"HIGH"``. An empty floor would let every finding skip the
#     prompt, defeating the entire feature.
#
# Mirrors _apply_guardrail_extra_options in cmd_setup.py and the
# default in HILTConfig (HIGH). When this contract slips, the init
# UX promises a feature it never delivers.
# ---------------------------------------------------------------------------


class ApplyFirstRunChoicesHITLTests(unittest.TestCase):
    def setUp(self):
        from defenseclaw.config import default_config
        self.cfg = default_config()

    def _apply(
        self,
        *,
        human_approval: bool | None = None,
        hilt_min_severity: str = "",
    ) -> None:
        from defenseclaw.bootstrap import (
            FirstRunOptions,
            _apply_first_run_choices,
        )

        opts = FirstRunOptions(
            connector="codex",
            profile="action",
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
        )
        _apply_first_run_choices(self.cfg, opts, "codex", "action", "local")

    def test_none_preserves_existing_enabled(self):
        self.cfg.guardrail.hilt.enabled = True
        self._apply(human_approval=None)
        self.assertTrue(self.cfg.guardrail.hilt.enabled,
                        "human_approval=None must NEVER silently flip an "
                        "operator's prior 'enabled' choice")

    def test_none_preserves_existing_disabled(self):
        self.cfg.guardrail.hilt.enabled = False
        self._apply(human_approval=None)
        self.assertFalse(self.cfg.guardrail.hilt.enabled)

    def test_true_enables(self):
        self.cfg.guardrail.hilt.enabled = False
        self._apply(human_approval=True)
        self.assertTrue(self.cfg.guardrail.hilt.enabled)

    def test_false_disables(self):
        self.cfg.guardrail.hilt.enabled = True
        self._apply(human_approval=False)
        self.assertFalse(self.cfg.guardrail.hilt.enabled)

    def test_min_severity_empty_preserves(self):
        self.cfg.guardrail.hilt.min_severity = "MEDIUM"
        self._apply(hilt_min_severity="")
        self.assertEqual(self.cfg.guardrail.hilt.min_severity, "MEDIUM",
                         "empty hilt_min_severity must preserve the existing "
                         "severity floor — used by callers who only want to "
                         "flip the toggle without overriding the threshold")

    def test_min_severity_normalizes_uppercase(self):
        self._apply(hilt_min_severity="medium")
        self.assertEqual(self.cfg.guardrail.hilt.min_severity, "MEDIUM",
                         "lowercase severity must normalize so config stays "
                         "consistent with the canonical HIGH/MEDIUM/LOW/"
                         "CRITICAL set used by the gateway")

    def test_min_severity_invalid_falls_back_to_high(self):
        self.cfg.guardrail.hilt.min_severity = "MEDIUM"  # seed non-default
        self._apply(hilt_min_severity="kritical")
        self.assertEqual(self.cfg.guardrail.hilt.min_severity, "HIGH",
                         "typo must fall back to the strictest practical "
                         "floor (HIGH) — falling back to a permissive value "
                         "would silently weaken the operator's intent")

    def test_enable_with_empty_severity_backfills_high(self):
        self.cfg.guardrail.hilt.enabled = False
        self.cfg.guardrail.hilt.min_severity = ""  # simulate round-tripped older config
        self._apply(human_approval=True, hilt_min_severity="")
        self.assertTrue(self.cfg.guardrail.hilt.enabled)
        self.assertEqual(self.cfg.guardrail.hilt.min_severity, "HIGH",
                         "enabling HITL with no severity floor must backfill "
                         "HIGH — an empty floor lets every finding skip the "
                         "prompt, which would defeat the feature entirely")

    def test_enable_with_explicit_severity_persists_both(self):
        self._apply(human_approval=True, hilt_min_severity="LOW")
        self.assertTrue(self.cfg.guardrail.hilt.enabled)
        self.assertEqual(self.cfg.guardrail.hilt.min_severity, "LOW")

    def test_disable_with_severity_still_persists_severity(self):
        # Operator wants to record a severity-floor preference for
        # "later" without enabling HITL right now. The bootstrap
        # layer must persist the severity exactly as supplied so the
        # operator can flip ``human_approval=True`` later via
        # ``defenseclaw setup guardrail`` and have the floor already
        # set without a second prompt.
        self._apply(human_approval=False, hilt_min_severity="MEDIUM")
        self.assertFalse(self.cfg.guardrail.hilt.enabled)
        self.assertEqual(self.cfg.guardrail.hilt.min_severity, "MEDIUM")


# ---------------------------------------------------------------------------
# _start_gateway_structured: connector-drift restart
#
# Pins the bug fix where ``defenseclaw init`` / ``quickstart`` would write
# the new connector to ``config.yaml`` but then short-circuit on
# ``Sidecar already running`` and leave the live gateway serving the
# previous connector. Without this, ``defenseclaw status`` reports the
# *old* connector for hours after a successful init — see the operator
# transcript at terminals/1.txt:228-318.
#
# The drift signal is ``<data_dir>/active_connector.json`` (written by
# ``connector_state.go::SaveActiveConnector`` after a successful
# ``Connector.Setup``). When that file's connector name doesn't match
# ``cfg.active_connector()`` we MUST restart so the sidecar re-reads
# config.yaml and runs the right ``Connector.Setup`` for the new
# adapter. When it matches, restarting would be pure disruption and we
# keep the legacy "already running" no-op.
#
# When the file is absent (older sidecar binary, fresh post-uninstall
# install) we conservatively keep the legacy behavior — see
# _running_connector_from_state_file's I-don't-know sentinel rule.
# ---------------------------------------------------------------------------


class StartGatewayStructuredDriftTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._prev_home = os.environ.get("DEFENSECLAW_HOME")
        os.environ["DEFENSECLAW_HOME"] = self._tmp.name
        self.addCleanup(self._restore_home)

        self.data_dir = os.path.join(self._tmp.name, "dchome")
        os.makedirs(self.data_dir, exist_ok=True)
        self.cfg = _cfg_for(self.data_dir)

    def _restore_home(self) -> None:
        if self._prev_home is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = self._prev_home

    def _write_active_connector(self, name: str) -> None:
        import json
        with open(os.path.join(self.data_dir, "active_connector.json"),
                  "w", encoding="utf-8") as fh:
            json.dump({"name": name}, fh)

    def _write_pid_file(self) -> None:
        # Use the current process's pid: ``_pid_file_running`` does
        # ``os.kill(pid, 0)`` so it must point at a real, owned-by-us
        # process. Using ``os.getpid()`` keeps the test hermetic.
        import json
        with open(os.path.join(self.data_dir, "gateway.pid"),
                  "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"pid": os.getpid()}))

    def _patch_subprocess(self, recorder: list, returncode: int = 0):
        """Return a context manager that intercepts ``subprocess.run`` and
        ``shutil.which`` calls inside ``_start_gateway_structured``.

        Every captured invocation lands in ``recorder`` so test
        assertions can verify both the command verb and the call
        count without relying on subprocess timing or a real
        gateway binary on PATH.
        """
        import subprocess
        from contextlib import ExitStack
        from unittest.mock import patch

        class _FakeCompleted:
            def __init__(self, rc: int) -> None:
                self.returncode = rc
                self.stdout = ""
                self.stderr = ""

        def fake_run(cmd, *args, **kwargs):
            recorder.append(tuple(cmd))
            return _FakeCompleted(returncode)

        stack = ExitStack()
        stack.enter_context(patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"))
        stack.enter_context(patch.object(subprocess, "run", side_effect=fake_run))
        return stack

    def test_already_running_no_drift_does_not_restart(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        self.cfg.guardrail.connector = "openclaw"
        self._write_pid_file()
        self._write_active_connector("openclaw")

        recorder: list = []
        with self._patch_subprocess(recorder):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.detail, "already running")
        self.assertEqual(recorder, [],
                         "no subprocess invocation expected when the live "
                         "connector matches cfg.active_connector()")

    def test_drift_triggers_restart_with_descriptive_detail(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        # Operator just ran ``init`` and switched from codex →
        # openclaw; gateway is still running with the codex
        # connector it picked at last boot.
        self.cfg.guardrail.connector = "openclaw"
        self.cfg.claw.mode = "openclaw"
        self._write_pid_file()
        self._write_active_connector("codex")

        recorder: list = []
        with self._patch_subprocess(recorder, returncode=0):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "pass")
        self.assertIn("restarted", result.detail)
        self.assertIn("codex", result.detail)
        self.assertIn("openclaw", result.detail)
        self.assertEqual(len(recorder), 1,
                         "exactly one subprocess invocation expected on drift")
        self.assertEqual(recorder[0][1], "restart",
                         "must call `defenseclaw-gateway restart`, not `start`")

    def test_drift_restart_failure_surfaces_warn_with_remediation(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        self.cfg.guardrail.connector = "openclaw"
        self._write_pid_file()
        self._write_active_connector("codex")

        recorder: list = []
        with self._patch_subprocess(recorder, returncode=1):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "warn")
        self.assertIn("drift detected", result.detail,
                      "warn detail must call out drift so the operator "
                      "knows the on-disk config doesn't match runtime")
        self.assertEqual(result.next_command, "defenseclaw-gateway restart")

    def test_no_active_connector_file_keeps_legacy_already_running(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        # No active_connector.json: this is what we'd see against an
        # older sidecar binary that pre-dates connector_state.go, or
        # after a fresh data_dir wipe. We can't tell whether there's
        # drift, so we MUST NOT restart — bouncing the sidecar on
        # every init would silently disrupt in-flight sessions.
        self.cfg.guardrail.connector = "openclaw"
        self._write_pid_file()

        recorder: list = []
        with self._patch_subprocess(recorder):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.detail, "already running")
        self.assertEqual(recorder, [],
                         "missing active_connector.json must NEVER trigger a "
                         "restart; legacy 'already running' behavior wins")

    def test_not_running_calls_start_not_restart(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        # No pid file → not running. Existing behavior: spawn `start`.
        # This test pins that the drift-detection path doesn't
        # accidentally short-circuit the not-running case.
        recorder: list = []
        with self._patch_subprocess(recorder, returncode=0):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.detail, "started")
        self.assertEqual(len(recorder), 1)
        self.assertEqual(recorder[0][1], "start")


# ---------------------------------------------------------------------------
# _running_connector_from_state_file: the I-don't-know sentinel
#
# Centralized helper so callers can't accidentally treat "file missing"
# the same as "file says different connector". Both are common during
# upgrades (fresh install hasn't booted yet vs. real connector switch)
# and conflating them would either trigger spurious restarts or skip
# necessary ones. These tests pin each expected return value.
# ---------------------------------------------------------------------------


class RunningConnectorFromStateFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _write(self, contents: str) -> None:
        with open(os.path.join(self._tmp.name, "active_connector.json"),
                  "w", encoding="utf-8") as fh:
            fh.write(contents)

    def test_missing_file_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file
        self.assertIsNone(_running_connector_from_state_file(self._tmp.name))

    def test_empty_name_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file
        self._write('{"name": ""}')
        self.assertIsNone(_running_connector_from_state_file(self._tmp.name),
                          "empty string must be treated as I-don't-know, not "
                          "as a real connector name")

    def test_malformed_json_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file
        self._write("{not json}")
        self.assertIsNone(_running_connector_from_state_file(self._tmp.name))

    def test_normalizes_case_and_whitespace(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file
        self._write('{"name": "  CODEX  "}')
        self.assertEqual(_running_connector_from_state_file(self._tmp.name), "codex",
                         "must match Config.active_connector() normalization "
                         "rule (strip + lowercase) so drift detection isn't "
                         "fooled by case differences")

    def test_non_dict_payload_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file
        self._write('"openclaw"')
        self.assertIsNone(_running_connector_from_state_file(self._tmp.name))


if __name__ == "__main__":
    unittest.main()
