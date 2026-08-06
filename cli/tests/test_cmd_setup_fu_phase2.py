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

"""FU-SETUP Phase-2 tests: the interactive UX cluster + per-connector
guardrail write-surface for ``setup`` (cmd_setup.py only).

Covers:

* B3 / E4d — per-connector guardrail write-surface from the setup path
  (block-message / fail-mode / human-approval+hilt / judge), in addition
  to the mode + rule-pack that already landed per-connector.
* SU-06 — interactive observe/action prompt in the hook setup flow.
* SU-07 — interactive judge-enable prompt in the hook setup flow.
* SU-08 — the untrusted-binary-prefix remediation prompt now fires in
  observe mode too (previously action-mode only).
* SU-09 — one standard "connector not detected locally" message.
* SU-10 — hook setup commands expose the judge/HILT/block-message/fail-mode
  options (parity with the proxy factory) + a hook/proxy help epilog.
* SU-11 — bare ``setup`` is repurposed to an interactive multi-connector
  picker + scripting flags (``-c/--connector`` / ``--detected`` / ``--all``).
* ND-3 — legacy ``setup mode`` is removed; use ``setup <connector> --mode``.
* J3 — opt-in per-direction detection-strategy flags on ``setup guardrail``
  (OFF by default).
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import stat
import sys
import threading
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import FunctionType, SimpleNamespace
from unittest.mock import MagicMock, patch

import click
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.logger import CanonicalObservabilityUnavailableError

from tests.helpers import cleanup_app, make_app_context, record_test_setup_agent_selections


def _invoke(args, app, catch=False):
    runner = CliRunner()
    return runner.invoke(setup_group, args, obj=app, catch_exceptions=catch)


def _click_result_exception_diagnostics(result) -> str:
    """Render the complete exception graph without following arbitrary objects."""

    diagnostics = [result.output, repr(result.exc_info)]
    if result.exc_info is not None:
        diagnostics.append("".join(traceback.format_exception(*result.exc_info)))
    pending = [result.exception]
    seen: set[int] = set()
    while pending:
        exc = pending.pop()
        if exc is None or id(exc) in seen:
            continue
        seen.add(id(exc))
        diagnostics.extend((str(exc), repr(exc)))
        pending.extend(
            (
                getattr(exc, "__cause__", None),
                getattr(exc, "__context__", None),
            )
        )
    return "\n".join(diagnostics)


def _click_result_reaches_marker(result, marker: str) -> bool:
    """Check bounded exception reachability, including traceback-owned state."""

    diagnostics = [result.output, repr(result.exc_info)]
    if result.exc_info is not None:
        diagnostics.append("".join(traceback.format_exception(*result.exc_info)))
    pending = [result.exception]
    seen_exceptions: set[int] = set()
    seen_functions: set[int] = set()

    def append_repr(value) -> None:
        try:
            diagnostics.append(repr(value))
        except BaseException:
            diagnostics.append("<repr unavailable>")

    def inspect_closure(function: FunctionType) -> None:
        if id(function) in seen_functions:
            return
        seen_functions.add(id(function))
        for cell in function.__closure__ or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            append_repr(value)
            if isinstance(value, FunctionType):
                inspect_closure(value)

    while pending:
        exc = pending.pop()
        if exc is None or id(exc) in seen_exceptions:
            continue
        seen_exceptions.add(id(exc))
        diagnostics.extend((str(exc), repr(exc)))
        pending.extend((exc.__cause__, exc.__context__))
        current_tb = exc.__traceback__
        while current_tb is not None:
            for value in current_tb.tb_frame.f_locals.values():
                append_repr(value)
                if isinstance(value, FunctionType):
                    inspect_closure(value)
            current_tb = current_tb.tb_next
    return any(marker in diagnostic for diagnostic in diagnostics)


@pytest.mark.parametrize(
    ("host_os", "expected_hook", "other_hook"),
    (
        ("windows", "windsurf-hook.ps1 on Windows", "windsurf-hook.sh"),
        ("linux", "windsurf-hook.sh on non-Windows", "windsurf-hook.ps1"),
    ),
)
def test_windsurf_mutation_notice_names_platform_hook(
    host_os: str,
    expected_hook: str,
    other_hook: str,
) -> None:
    runner = CliRunner()
    with (
        patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value=host_os),
        runner.isolation() as (stdout, _stderr, _input),
    ):
        cmd_setup._print_connector_mutation_notice("windsurf")

    notice = stdout.getvalue().decode()
    assert expected_hook in notice
    assert other_hook not in notice


@contextlib.contextmanager
def _stub_side_effects():
    """Stub the heavyweight setup side effects so commands run in CI."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            )
        )
        yield


@contextlib.contextmanager
def _guardrail_judge_secret_wizard(
    lock_path: Path,
    env_name: str,
    secret_value: str,
    *,
    abort_at: str | None = None,
    events: list[str] | None = None,
):
    """Drive the real interactive judge flow using disposable marker values."""

    recorded_events = events if events is not None else []
    runtime_reads = 0

    def capture_runtime(*_args, **_kwargs):
        nonlocal runtime_reads
        runtime_reads += 1
        return cmd_setup._SetupAppliedRuntimeEvidence(
            lifecycle="running",
            generation=f"generation-{runtime_reads}",
            invariants=(),
        )

    def select(data_dir, connectors):
        records = record_test_setup_agent_selections(data_dir, connectors)
        atomic_write_private_bytes(str(lock_path), b"fresh lock marker\n")
        return records

    def prompt(label, *_args, **_kwargs):
        if "Select mode" in label:
            return "2"
        if "Select engine" in label:
            return "1"
        if "API base URL" in label:
            return "http://127.0.0.1:1/v1"
        if "Model (" in label:
            return "disposable-model-marker"
        if "API key env var name" in label:
            return env_name
        if env_name in label:
            return secret_value
        if "Fallback model" in label:
            recorded_events.append("fallback-model")
            if abort_at == "fallback":
                raise click.Abort()
            return ""
        raise AssertionError(f"unexpected prompt: {label}")

    def confirm(label, *_args, **_kwargs):
        if "Enable guardrail?" in label:
            return True
        if "Configure fallback models?" in label:
            recorded_events.append("fallback-choice")
            return abort_at == "fallback"
        if "shared LLM key" in label:
            return False
        if "Configure advanced options?" in label:
            recorded_events.append("advanced-choice")
            if abort_at == "advanced":
                raise click.Abort()
            return False
        raise AssertionError(f"unexpected confirmation: {label}")

    def enable_judge(gc, *_args, **_kwargs):
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["opencode"]

    with (
        patch(
            "defenseclaw.commands.cmd_setup.platform_support.host_os",
            return_value="windows",
        ),
        patch(
            "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
            side_effect=capture_runtime,
        ),
        patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=select,
        ) as selected,
        patch(
            "defenseclaw.commands.cmd_setup._configure_hilt_interactive",
            return_value=None,
        ),
        patch(
            "defenseclaw.commands.cmd_setup._prompt_guardrail_judge_enablement",
            side_effect=enable_judge,
        ),
        patch(
            "defenseclaw.commands.cmd_setup.click.prompt",
            side_effect=prompt,
        ),
        patch(
            "defenseclaw.commands.cmd_setup.click.confirm",
            side_effect=confirm,
        ),
    ):
        yield selected


class _BaseSetup(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        # Lightweight save shim: tests assert on the in-memory config object.
        self.app.cfg.save = lambda: atomic_write_private_bytes(  # type: ignore[assignment]
            self.cfg_path, b"x\n"
        )

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _seed_map(self, *connectors):
        gc = self.app.cfg.guardrail
        gc.connectors = {c: PerConnectorGuardrailConfig() for c in connectors}
        gc.connector = sorted(connectors)[0]
        self.app.cfg.claw.mode = sorted(connectors)[0]


# ---------------------------------------------------------------------------
# B3 / E4d — per-connector guardrail write-surface
# ---------------------------------------------------------------------------
class TestPerConnectorWriteSurface(_BaseSetup):
    def test_amp_version_admission_precedes_rule_pack_conflict(self):
        events: list[str] = []

        def admit(*_args, **_kwargs):
            events.append("version")
            return True

        with (
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="windows",
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=admit,
            ) as version_check,
            patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections") as protected_selection,
        ):
            with self.assertRaisesRegex(click.UsageError, "mutually exclusive"):
                cmd_setup._apply_hook_connector_setup(
                    self.app,
                    connector="amp",
                    restart=False,
                    rule_pack="strict",
                    rule_pack_dir=self.tmp_dir,
                )

        self.assertEqual(events, ["version"])
        version_check.assert_called_once()
        protected_selection.assert_not_called()

    def test_forged_name_set_cannot_bypass_exact_opencode_selection(self):
        receipt = os.path.join(self.tmp_dir, "agent_selection.json")
        prior = b'{"prior":"receipt"}\n'
        atomic_write_private_bytes(receipt, prior)
        forbidden = AssertionError("generic discovery cannot authorize native-Windows OpenCode")

        with (
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="windows",
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException("fresh exact selection required"),
            ) as select_exact,
        ):
            with self.assertRaisesRegex(click.ClickException, "fresh exact selection required"):
                cmd_setup._apply_hook_connector_setup(
                    self.app,
                    connector="opencode",
                    restart=False,
                    _protected_selection=frozenset({"opencode"}),  # type: ignore[arg-type]
                )

        generic.assert_not_called()
        select_exact.assert_called_once()
        self.assertEqual(Path(receipt).read_bytes(), prior)

    def test_tampered_concrete_opencode_proof_forces_fresh_selection(self):
        with patch(
            "defenseclaw.commands.cmd_setup.platform_support.host_os",
            return_value="windows",
        ):
            snapshot = cmd_setup._capture_setup_config_snapshot(self.app.cfg)
            records, errors = record_test_setup_agent_selections(
                self.tmp_dir,
                ("opencode",),
            )
            self.assertEqual(errors, {})
            proof = cmd_setup._validate_setup_agent_selection_receipt(
                self.tmp_dir,
                ("opencode",),
                records,
                prior_generation=snapshot.agent_selection_generation,
            )
            receipt = Path(self.tmp_dir, "agent_selection.json")
            tampered = receipt.read_bytes() + b" "
            atomic_write_private_bytes(str(receipt), tampered)
            with patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException("tampered proof requires reselection"),
            ) as select_exact:
                with self.assertRaisesRegex(click.ClickException, "requires reselection"):
                    cmd_setup._apply_hook_connector_setup(
                        self.app,
                        connector="opencode",
                        restart=False,
                        _protected_selection=proof,
                    )

        select_exact.assert_called_once()
        self.assertEqual(receipt.read_bytes(), tampered)

    def test_prior_transaction_concrete_proof_cannot_authorize_single_setup(self):
        with patch(
            "defenseclaw.commands.cmd_setup.platform_support.host_os",
            return_value="windows",
        ):
            prior_transaction = cmd_setup._capture_setup_config_snapshot(self.app.cfg)
            records, errors = record_test_setup_agent_selections(
                self.tmp_dir,
                ("opencode",),
            )
            self.assertEqual(errors, {})
            old_proof = cmd_setup._validate_setup_agent_selection_receipt(
                self.tmp_dir,
                ("opencode",),
                records,
                prior_generation=prior_transaction.agent_selection_generation,
            )
            receipt = Path(self.tmp_dir, "agent_selection.json")
            prior_receipt = receipt.read_bytes()
            with patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException("new transaction must select again"),
            ) as select_exact:
                with self.assertRaisesRegex(click.ClickException, "select again"):
                    cmd_setup._apply_hook_connector_setup(
                        self.app,
                        connector="opencode",
                        restart=False,
                        _protected_selection=old_proof,
                    )

        select_exact.assert_called_once()
        self.assertEqual(receipt.read_bytes(), prior_receipt)

    def test_additive_setup_selects_complete_roster_before_first_gateway_start(self):
        self._seed_map("amp", "claudecode", "codex", "cursor")

        with (
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="windows",
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._windows_runtime_rollback",
                return_value=False,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException("selection captured"),
            ) as selected,
            self.assertRaisesRegex(click.ClickException, "selection captured"),
        ):
            cmd_setup._apply_hook_connector_setup(
                self.app,
                connector="codex",
                restart=True,
                write_mode="add",
            )

        selected.assert_called_once()
        self.assertEqual(
            selected.call_args.args[1],
            ("amp", "claudecode", "codex", "cursor"),
        )

    def test_stale_concrete_opencode_receipt_is_not_transaction_proof(self):
        with patch(
            "defenseclaw.commands.cmd_setup.platform_support.host_os",
            return_value="windows",
        ):
            records, errors = record_test_setup_agent_selections(
                self.tmp_dir,
                ("opencode",),
            )
            self.assertEqual(errors, {})
            receipt = Path(self.tmp_dir, "agent_selection.json")
            payload = json.loads(receipt.read_bytes())
            selected = datetime.now(timezone.utc) - timedelta(minutes=16)
            expires = selected + timedelta(minutes=15)
            selected_at = selected.isoformat(timespec="seconds").replace("+00:00", "Z")
            expires_at = expires.isoformat(timespec="seconds").replace("+00:00", "Z")
            payload["updated_at"] = selected_at
            payload["selections"]["opencode"]["selected_at"] = selected_at
            payload["selections"]["opencode"]["expires_at"] = expires_at
            atomic_write_private_bytes(
                str(receipt),
                (json.dumps(payload, sort_keys=True) + "\n").encode(),
            )

            with self.assertRaisesRegex(OSError, "not fresh|stale"):
                cmd_setup._validate_setup_agent_selection_receipt(
                    self.tmp_dir,
                    ("opencode",),
                    records,
                )

    def test_all_fields_land_per_connector_and_peer_untouched(self):
        self._seed_map("codex", "hermes")
        with _stub_side_effects():
            res = _invoke(
                [
                    "hermes", "--yes", "--no-restart", "--mode", "action",
                    "--block-message", "custom-hermes",
                    "--fail-mode", "closed",
                    "--human-approval", "--hilt-min-severity", "CRITICAL",
                    "--enable-judge",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        h = gc.connectors["hermes"]
        self.assertEqual(h.mode, "action")
        self.assertEqual(h.block_message, "custom-hermes")
        self.assertEqual(h.hook_fail_mode, "closed")
        self.assertIsNotNone(h.hilt)
        self.assertTrue(h.hilt.enabled)
        self.assertEqual(h.hilt.min_severity, "CRITICAL")
        # Judge enablement is global + gated; strategy bumped off regex_only.
        self.assertTrue(gc.judge.enabled)
        self.assertNotEqual(gc.detection_strategy, "regex_only")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")
        self.assertEqual(gc.judge.hook_connectors, ["hermes"])
        # Peer left completely untouched (inherits global).
        codex = gc.connectors["codex"]
        self.assertEqual(codex.mode, "")
        self.assertEqual(codex.block_message, "")
        self.assertEqual(codex.hook_fail_mode, "")
        self.assertIsNone(codex.hilt)

    def test_sole_connector_writes_global_fields(self):
        # Clean config -> replace shape -> global fields (effective_* falls back).
        with _stub_side_effects():
            res = _invoke(
                ["codex", "--yes", "--no-restart", "--block-message", "g", "--fail-mode", "closed"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.block_message, "g")
        self.assertEqual(gc.hook_fail_mode, "closed")

    def test_setup_guardrail_connector_flag_writes_existing_override_fields(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.mode = "observe"
        gc.block_message = ""
        with _stub_side_effects():
            res = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--no-restart",
                    "--no-verify",
                    "--connector",
                    "codex",
                    "--mode",
                    "action",
                    "--block-message",
                    "codex-only",
                    "--human-approval",
                    "--hilt-min-severity",
                    "CRITICAL",
                    "--rule-pack",
                    "strict",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.block_message, "")
        self.assertFalse(gc.hilt.enabled)

        codex = gc.connectors["codex"]
        hermes = gc.connectors["hermes"]
        self.assertEqual(codex.mode, "action")
        self.assertEqual(codex.block_message, "codex-only")
        self.assertTrue(codex.rule_pack_dir.endswith(os.path.join("policies", "guardrail", "strict")))
        self.assertIsNotNone(codex.hilt)
        self.assertTrue(codex.hilt.enabled)
        self.assertEqual(codex.hilt.min_severity, "CRITICAL")
        self.assertEqual(hermes.mode, "")
        self.assertEqual(hermes.block_message, "")
        self.assertEqual(hermes.rule_pack_dir, "")
        self.assertIsNone(hermes.hilt)

    def test_setup_guardrail_unscoped_mode_updates_all_active_overrides(self):
        self._seed_map("claudecode", "hermes", "opencode", "openhands")
        gc = self.app.cfg.guardrail
        gc.mode = "action"
        for connector in gc.connectors:
            gc.connectors[connector].mode = "action"

        with _stub_side_effects():
            res = _invoke(
                [
                    "guardrail",
                    "--yes",
                    "--no-restart",
                    "--no-verify",
                    "--mode",
                    "observe",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.mode, "observe")
        for connector in ("claudecode", "hermes", "opencode", "openhands"):
            self.assertEqual(gc.connectors[connector].mode, "observe")
            self.assertEqual(gc.effective_mode(connector), "observe")

    def test_setup_guardrail_unscoped_block_message_updates_all_active_overrides(self):
        self._seed_map("geminicli", "hermes")
        gc = self.app.cfg.guardrail
        gc.block_message = "Global block"
        gc.connectors["geminicli"].block_message = "Gemini scoped block"

        with _stub_side_effects():
            res = _invoke(
                [
                    "guardrail",
                    "--yes",
                    "--no-restart",
                    "--no-verify",
                    "--block-message",
                    "Global block 2",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.block_message, "Global block 2")
        for connector in ("geminicli", "hermes"):
            self.assertEqual(gc.connectors[connector].block_message, "Global block 2")
            self.assertEqual(gc.effective_block_message(connector), "Global block 2")

    def test_setup_guardrail_unscoped_without_mode_preserves_active_overrides(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.mode = "observe"
        gc.connectors["codex"].mode = "action"
        gc.connectors["hermes"].mode = "observe"

        with _stub_side_effects():
            res = _invoke(
                ["guardrail", "--yes", "--no-restart", "--no-verify"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.connectors["codex"].mode, "action")
        self.assertEqual(gc.connectors["hermes"].mode, "observe")

    def test_omitting_judge_flags_preserves_existing_action_judge(self):
        # SU-02/J1 preserve-don't-clobber: an action-mode re-run without judge
        # flags keeps the connector's existing judge selection.
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]
        gc.detection_strategy = "regex_judge"
        gc.connectors["hermes"].block_message = "keep-me"
        with _stub_side_effects():
            res = _invoke(["hermes", "--yes", "--no-restart", "--mode", "action"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.connectors["hermes"].block_message, "keep-me")

    def test_enable_judge_adds_connector_to_existing_narrow_gate(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex"]
        gc.detection_strategy = "regex_judge"
        with _stub_side_effects():
            res = _invoke(
                ["hermes", "--yes", "--no-restart", "--mode", "action", "--enable-judge"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, ["codex", "hermes"])

    def test_no_enable_judge_opts_connector_out_of_concrete_gate(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex", "hermes"]
        with _stub_side_effects():
            res = _invoke(["hermes", "--yes", "--no-restart", "--no-enable-judge"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertNotIn("hermes", gc.judge.hook_connectors)
        self.assertIn("codex", gc.judge.hook_connectors)

    def test_direct_action_missing_connector_falls_back_to_observe(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"copilot": signal})
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["copilot"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"
        saved_judge_states: list[tuple[bool, list[str], str]] = []

        def capture_save():
            saved_judge_states.append(
                (
                    bool(gc.judge.enabled),
                    list(gc.judge.hook_connectors or []),
                    gc.detection_strategy,
                )
            )

        self.app.cfg.save = capture_save  # type: ignore[assignment]

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
            stack.enter_context(
                patch("defenseclaw.commands.cmd_setup.agent_discovery.discover_agents", return_value=disc)
            )
            res = _invoke(
                ["copilot", "--yes", "--no-restart", "--mode", "action"],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("GitHub Copilot CLI: connector was not detected locally", res.output)
        self.assertIn("GitHub Copilot CLI: requested action mode was refused", res.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "copilot")
        self.assertEqual(self.app.cfg.guardrail.mode, "observe")
        self.assertEqual(saved_judge_states[-1], (False, [], "regex_only"))
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])

    def test_direct_hermes_unsupported_version_downgrades_after_one_discovery(self):
        signal = SimpleNamespace(
            version="Hermes Agent v0.17.0",
            installed=True,
            error="",
            binary_path=r"C:\Users\tester\AppData\Local\hermes\hermes-agent\venv\Scripts\hermes.exe",
        )
        disc = SimpleNamespace(agents={"hermes": signal})

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
            discover = stack.enter_context(
                patch("defenseclaw.commands.cmd_setup.agent_discovery.discover_agents", return_value=disc)
            )
            res = _invoke(
                ["hermes", "--yes", "--no-restart", "--mode", "action"],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        discover.assert_called_once_with(
            use_cache=False,
            refresh=True,
            data_dir=self.app.cfg.data_dir,
            persist_cache=True,
        )
        self.assertEqual(res.output.count("detected-but-unsupported-version"), 1)
        self.assertIn("installed version Hermes Agent v0.17.0", res.output)
        self.assertIn("hermes-hooks-v1 requires >=0.19.0", res.output)
        self.assertIn("requested action mode was refused; configuring observe mode instead", res.output)
        self.assertNotIn("connector was not detected locally", res.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "hermes")
        self.assertEqual(self.app.cfg.guardrail.mode, "observe")

    def test_windows_omnigent_admission_scan_does_not_publish_unrelated_discovery(self):
        signal = SimpleNamespace(
            version="omnigent 0.7.0",
            installed=True,
            error="",
            binary_path=r"C:\Users\tester\.local\bin\omnigent.exe",
        )
        disc = SimpleNamespace(agents={"omnigent": signal})

        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=disc,
            ) as discover,
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="windows",
            ),
        ):
            accepted = cmd_setup._check_connector_version_supported_for_setup(
                "omnigent",
                mode="action",
                emit=False,
                data_dir=self.app.cfg.data_dir,
            )

        self.assertTrue(accepted)
        discover.assert_called_once_with(
            use_cache=False,
            refresh=True,
            data_dir=self.app.cfg.data_dir,
            persist_cache=False,
        )

    def test_windows_opencode_admission_scan_preserves_prior_connector_discovery(self):
        signal = SimpleNamespace(
            version="opencode 1.18.11",
            installed=True,
            error="",
            binary_path=(
                r"D:\fixture\WinGet\Packages\SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe"
                r"\opencode.exe"
            ),
        )
        disc = SimpleNamespace(agents={"opencode": signal})

        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=disc,
            ) as discover,
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="windows",
            ),
        ):
            accepted = cmd_setup._check_connector_version_supported_for_setup(
                "opencode",
                mode="action",
                emit=False,
                data_dir=self.app.cfg.data_dir,
            )

        self.assertTrue(accepted)
        discover.assert_called_once_with(
            use_cache=False,
            refresh=True,
            data_dir=self.app.cfg.data_dir,
            persist_cache=False,
        )

    def test_windows_opencode_single_setup_selects_exact_image_before_state_and_generic(self):
        original_save = self.app.cfg.save
        for mode in ("observe", "action"):
            with self.subTest(mode=mode):
                events: list[str] = []

                def save():
                    events.append("save")
                    original_save()

                self.app.cfg.save = save  # type: ignore[assignment]

                def select(_data_dir, connectors):
                    events.append("select")
                    self.assertEqual(tuple(connectors), ("opencode",))
                    return record_test_setup_agent_selections(_data_dir, connectors)

                forbidden = AssertionError("generic OpenCode discovery cannot authorize setup")
                with (
                    patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
                    patch(
                        "defenseclaw.agent_selection.record_setup_agent_selections",
                        side_effect=select,
                    ) as selected,
                    patch(
                        "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                        side_effect=forbidden,
                    ) as generic,
                    patch(
                        "defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack",
                        return_value=None,
                    ),
                ):
                    result = _invoke(
                        ["opencode", "--yes", "--no-restart", "--mode", mode],
                        self.app,
                        catch=True,
                    )

                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(events[0], "select")
                selected.assert_called_once()
                generic.assert_not_called()

    def test_windows_opencode_single_failure_preserves_config_receipt_lock_and_roster(self):
        self._seed_map("codex", "hermes")
        data_dir = self.app.cfg.data_dir
        config_path = self.cfg_path
        receipt_path = os.path.join(data_dir, "agent_selection.json")
        lock_path = os.path.join(data_dir, "hook_contract_lock.json")
        prior_config = b"prior config bytes\n"
        prior_receipt = b'{"prior":"selection"}\n'
        prior_lock = b'{"prior":"lock"}\n'
        atomic_write_private_bytes(config_path, prior_config)
        atomic_write_private_bytes(receipt_path, prior_receipt)
        atomic_write_private_bytes(lock_path, prior_lock)
        prior_roster = tuple(self.app.cfg.active_connectors())
        forbidden = AssertionError("exact selection failure must precede mutation")
        self.app.cfg.save = MagicMock(side_effect=forbidden)  # type: ignore[assignment]

        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException(
                    "exact SST OpenCode 1.18.12 is outside the validated contract; PATH 1.18.11 is irrelevant"
                ),
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch("defenseclaw.commands.cmd_setup._add_trusted_bin_prefix", side_effect=forbidden) as trust,
            patch("defenseclaw.commands.cmd_setup._restart_services", side_effect=forbidden) as restart,
        ):
            result = _invoke(
                ["opencode", "--yes", "--no-restart", "--mode", "action"],
                self.app,
                catch=True,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("exact SST OpenCode 1.18.12", result.output)
        generic.assert_not_called()
        trust.assert_not_called()
        restart.assert_not_called()
        self.app.cfg.save.assert_not_called()
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior_roster)
        for path, payload in (
            (config_path, prior_config),
            (receipt_path, prior_receipt),
            (lock_path, prior_lock),
        ):
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), payload)

    def test_windows_opencode_guardrail_selects_before_generic_and_config_save(self):
        self._seed_map("opencode")
        self.app.cfg.guardrail.enabled = True
        events: list[str] = []
        original_save = self.app.cfg.save

        def save():
            events.append("save")
            original_save()

        def select(_data_dir, connectors):
            events.append("select")
            self.assertEqual(tuple(connectors), ("opencode",))
            return record_test_setup_agent_selections(_data_dir, connectors)

        self.app.cfg.save = save  # type: ignore[assignment]
        forbidden = AssertionError("guardrail must not consult generic OpenCode discovery")
        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection.record_setup_agent_selections",
                side_effect=select,
            ) as selected,
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa", return_value=None),
        ):
            result = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--connector",
                    "opencode",
                    "--mode",
                    "action",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
                catch=True,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(events[0], "select")
        selected.assert_called_once()
        generic.assert_not_called()

    def test_windows_opencode_unscoped_guardrail_selects_complete_roster_once(self):
        pristine = copy.deepcopy(self.app.cfg)
        for requested_mode in ("observe", "action"):
            with self.subTest(requested_mode=requested_mode):
                self.app.cfg = copy.deepcopy(pristine)
                self._seed_map("amp", "opencode")
                gc = self.app.cfg.guardrail
                gc.enabled = True
                gc.connectors["amp"].mode = "observe"
                gc.connectors["opencode"].mode = "observe"
                events: list[str] = []
                for name in ("config.yaml", "agent_selection.json", "hook_contract_lock.json"):
                    Path(self.tmp_dir, name).unlink(missing_ok=True)

                def save():
                    events.append("save")
                    atomic_write_private_bytes(self.cfg_path, b"saved config marker\n")

                def select(data_dir, connectors):
                    events.append("select")
                    self.assertEqual(tuple(connectors), ("amp", "opencode"))
                    self.assertEqual(gc.effective_mode("amp"), "observe")
                    self.assertEqual(gc.effective_mode("opencode"), "observe")
                    return record_test_setup_agent_selections(data_dir, connectors)

                def generic(connector, **_kwargs):
                    events.append(f"generic:{connector}")
                    self.assertEqual(events[0], "select")
                    return True

                def execute(*_args, **_kwargs):
                    events.append("execute")
                    self.app.cfg.save()
                    return True, []

                self.app.cfg.save = save  # type: ignore[assignment]
                revalidate = cmd_setup._revalidate_setup_agent_selections
                with (
                    patch(
                        "defenseclaw.commands.cmd_setup.platform_support.host_os",
                        return_value="windows",
                    ),
                    patch(
                        "defenseclaw.agent_selection.record_setup_agent_selections",
                        side_effect=select,
                    ) as selected,
                    patch(
                        "defenseclaw.commands.cmd_setup._revalidate_setup_agent_selections",
                        wraps=revalidate,
                    ) as proof_check,
                    patch(
                        "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                        side_effect=generic,
                    ) as generic_check,
                    patch(
                        "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                        side_effect=execute,
                    ),
                ):
                    result = _invoke(
                        [
                            "guardrail",
                            "--non-interactive",
                            "--mode",
                            requested_mode,
                            "--no-restart",
                            "--no-verify",
                        ],
                        self.app,
                        catch=True,
                    )

                self.assertEqual(result.exit_code, 0, msg=result.output)
                selected.assert_called_once()
                proof_check.assert_called_once()
                generic_check.assert_called_once()
                self.assertEqual(generic_check.call_args.args[0], "amp")
                self.assertEqual(events[0], "select")
                self.assertLess(events.index("generic:amp"), events.index("save"))
                self.assertEqual(gc.effective_mode("amp"), requested_mode)
                self.assertEqual(gc.effective_mode("opencode"), requested_mode)

    def test_windows_opencode_unscoped_guardrail_refusal_restores_complete_roster(self):
        pristine = copy.deepcopy(self.app.cfg)
        for requested_mode in ("observe", "action"):
            with self.subTest(requested_mode=requested_mode):
                self.app.cfg = copy.deepcopy(pristine)
                self._seed_map("amp", "opencode")
                gc = self.app.cfg.guardrail
                gc.enabled = True
                gc.connectors["amp"].mode = "observe"
                gc.connectors["opencode"].mode = "observe"
                prior_gc = copy.deepcopy(gc)
                config_path = Path(self.cfg_path)
                receipt_path = Path(self.tmp_dir, "agent_selection.json")
                lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                prior_config = b"complete-roster config marker\n"
                prior_receipt = b'{"prior":"complete-roster-receipt-marker"}\n'
                prior_lock = b'{"prior":"complete-roster-lock-marker"}\n'
                atomic_write_private_bytes(str(config_path), prior_config)
                atomic_write_private_bytes(str(receipt_path), prior_receipt)
                atomic_write_private_bytes(str(lock_path), prior_lock)
                forbidden = AssertionError("exact refusal must precede complete-roster mutation")
                self.app.cfg.save = MagicMock(side_effect=forbidden)  # type: ignore[assignment]

                def refuse(_data_dir, connectors, **_kwargs):
                    self.assertEqual(tuple(connectors), ("amp", "opencode"))
                    self.assertEqual(gc, prior_gc)
                    atomic_write_private_bytes(str(receipt_path), b"partial receipt marker\n")
                    atomic_write_private_bytes(str(lock_path), b"partial lock marker\n")
                    raise click.ClickException("exact complete-roster OpenCode selection refused")

                with (
                    patch(
                        "defenseclaw.commands.cmd_setup.platform_support.host_os",
                        return_value="windows",
                    ),
                    patch(
                        "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                        side_effect=refuse,
                    ) as selected,
                    patch(
                        "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                        side_effect=forbidden,
                    ) as generic,
                    patch(
                        "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                        side_effect=forbidden,
                    ) as execute,
                ):
                    result = _invoke(
                        [
                            "guardrail",
                            "--non-interactive",
                            "--mode",
                            requested_mode,
                            "--no-restart",
                            "--no-verify",
                        ],
                        self.app,
                        catch=True,
                    )

                self.assertNotEqual(result.exit_code, 0)
                self.assertIn("exact complete-roster OpenCode selection refused", result.output)
                selected.assert_called_once()
                generic.assert_not_called()
                execute.assert_not_called()
                self.app.cfg.save.assert_not_called()
                self.assertEqual(self.app.cfg.guardrail, prior_gc)
                self.assertEqual(config_path.read_bytes(), prior_config)
                self.assertEqual(receipt_path.read_bytes(), prior_receipt)
                self.assertEqual(lock_path.read_bytes(), prior_lock)

    def test_windows_opencode_explicit_guardrail_selection_remains_scoped(self):
        self._seed_map("amp", "opencode")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        selected_targets: list[tuple[str, ...]] = []

        def select(data_dir, connectors):
            selected_targets.append(tuple(connectors))
            return record_test_setup_agent_selections(data_dir, connectors)

        def execute(*_args, **_kwargs):
            return True, []

        revalidate = cmd_setup._revalidate_setup_agent_selections
        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection.record_setup_agent_selections",
                side_effect=select,
            ) as selected,
            patch(
                "defenseclaw.commands.cmd_setup._revalidate_setup_agent_selections",
                wraps=revalidate,
            ) as proof_check,
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=AssertionError("scoped OpenCode must not use generic discovery"),
            ) as generic,
            patch(
                "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                side_effect=execute,
            ),
        ):
            result = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--connector",
                    "opencode",
                    "--mode",
                    "action",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
                catch=True,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(selected_targets, [("opencode",)])
        selected.assert_called_once()
        proof_check.assert_called_once()
        generic.assert_not_called()

    def test_windows_opencode_interactive_cancel_restores_selection_authority(self):
        pristine = copy.deepcopy(self.app.cfg)
        for cancellation in ("decline", "abort"):
            for prior_exists in (False, True):
                with self.subTest(cancellation=cancellation, prior_exists=prior_exists):
                    self.app.cfg = copy.deepcopy(pristine)
                    gc = self.app.cfg.guardrail
                    gc.connector = "amp"
                    gc.enabled = True
                    gc.mode = "observe"
                    prior_gc = copy.deepcopy(gc)
                    receipt_path = Path(self.tmp_dir, "agent_selection.json")
                    lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                    secret_path = Path(self.tmp_dir, ".env")
                    for path in (receipt_path, lock_path, secret_path):
                        path.unlink(missing_ok=True)
                    prior_receipt = b'{"prior":"interactive-receipt-marker"}\n'
                    prior_lock = b'{"prior":"interactive-lock-marker"}\n'
                    secret_marker = b"disposable secret-file marker\n"
                    if prior_exists:
                        atomic_write_private_bytes(str(receipt_path), prior_receipt)
                        atomic_write_private_bytes(str(lock_path), prior_lock)
                    atomic_write_private_bytes(str(secret_path), secret_marker)

                    def select(data_dir, connectors):
                        self.assertEqual(tuple(connectors), ("opencode",))
                        records = record_test_setup_agent_selections(data_dir, connectors)
                        atomic_write_private_bytes(str(lock_path), b"fresh lock marker\n")
                        return records

                    prompt_effect = (
                        AssertionError("decline must return before later prompts")
                        if cancellation == "decline"
                        else click.Abort()
                    )
                    with (
                        patch(
                            "defenseclaw.commands.cmd_setup.platform_support.host_os",
                            return_value="windows",
                        ),
                        patch(
                            "defenseclaw.agent_selection.record_setup_agent_selections",
                            side_effect=select,
                        ) as selected,
                        patch(
                            "defenseclaw.commands.cmd_setup.click.confirm",
                            return_value=cancellation != "decline",
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup.click.prompt",
                            side_effect=prompt_effect,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._prompt_and_save_secret",
                            side_effect=AssertionError("cancellation must not write a secret"),
                        ) as secret_write,
                        patch(
                            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                            side_effect=AssertionError("cancellation must precede version validation"),
                        ) as generic,
                    ):
                        result = _invoke(
                            [
                                "guardrail",
                                "--connector",
                                "opencode",
                                "--no-restart",
                                "--no-verify",
                            ],
                            self.app,
                            catch=True,
                        )

                    self.assertEqual(result.exit_code, 0 if cancellation == "decline" else 1)
                    selected.assert_called_once()
                    secret_write.assert_not_called()
                    generic.assert_not_called()
                    self.assertEqual(self.app.cfg.guardrail, prior_gc)
                    self.assertEqual(secret_path.read_bytes(), secret_marker)
                    if prior_exists:
                        self.assertEqual(receipt_path.read_bytes(), prior_receipt)
                        self.assertEqual(lock_path.read_bytes(), prior_lock)
                    else:
                        self.assertFalse(os.path.lexists(receipt_path))
                        self.assertFalse(os.path.lexists(lock_path))

    def test_windows_opencode_judge_secret_abort_never_publishes_pending_value(self):
        pristine = copy.deepcopy(self.app.cfg)
        env_name = "DISPOSABLE_JUDGE_ENV"
        other_env_name = "DISPOSABLE_UNRELATED_ENV"
        secret_value = "disposable judge marker value"
        prior_env_value = "disposable prior process marker"
        other_env_value = "disposable unrelated process marker"
        for abort_at in ("fallback", "advanced"):
            for prior_exists in (False, True):
                with self.subTest(abort_at=abort_at, prior_exists=prior_exists):
                    self.app.cfg = copy.deepcopy(pristine)
                    gc = self.app.cfg.guardrail
                    gc.connector = "amp"
                    gc.enabled = True
                    gc.mode = "action"
                    gc.judge.enabled = False
                    prior_gc = copy.deepcopy(gc)
                    config_path = Path(self.cfg_path)
                    hint_path = Path(self.tmp_dir, "picked_connector")
                    receipt_path = Path(self.tmp_dir, "agent_selection.json")
                    lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                    dotenv_path = Path(self.tmp_dir, ".env")
                    hilt_path = Path(self.app.cfg.policy_dir, "rego", "data.json")
                    hilt_path.parent.mkdir(parents=True, exist_ok=True)
                    for path in (
                        config_path,
                        hint_path,
                        receipt_path,
                        lock_path,
                        dotenv_path,
                        hilt_path,
                    ):
                        path.unlink(missing_ok=True)
                    prior_files = {
                        config_path: b"disposable prior config marker\n",
                        hint_path: b"amp\n",
                        receipt_path: b'{"prior":"judge-receipt-marker"}\n',
                        lock_path: b'{"prior":"judge-lock-marker"}\n',
                        hilt_path: b'{"prior":"hilt-marker"}\n',
                    }
                    prior_dotenv = (
                        b"UNRELATED_MARKER=preserved\nDISPOSABLE_JUDGE_ENV=disposable prior file marker\n"
                        if prior_exists
                        else None
                    )
                    for path, body in prior_files.items():
                        atomic_write_private_bytes(str(path), body)
                    if prior_dotenv is not None:
                        atomic_write_private_bytes(str(dotenv_path), prior_dotenv)
                    save = MagicMock(side_effect=AssertionError("Abort must precede config save"))
                    self.app.cfg.save = save  # type: ignore[assignment]
                    log_action = MagicMock(side_effect=AssertionError("Abort must precede setup audit"))

                    with patch.dict(os.environ, {}, clear=False):
                        if prior_exists:
                            os.environ[env_name] = prior_env_value
                        else:
                            os.environ.pop(env_name, None)
                        os.environ[other_env_name] = other_env_value
                        with (
                            _guardrail_judge_secret_wizard(
                                lock_path,
                                env_name,
                                secret_value,
                                abort_at=abort_at,
                            ) as selected,
                            patch.object(self.app.logger, "log_action", log_action),
                            patch(
                                "defenseclaw.commands.cmd_setup._save_secret_to_dotenv",
                                side_effect=AssertionError("a cancellable prompt remains before secret publication"),
                            ) as secret_writer,
                        ):
                            result = _invoke(
                                [
                                    "guardrail",
                                    "--connector",
                                    "opencode",
                                    "--no-restart",
                                    "--no-verify",
                                ],
                                self.app,
                                catch=True,
                            )

                        self.assertEqual(result.exit_code, 1)
                        selected.assert_called_once()
                        secret_writer.assert_not_called()
                        save.assert_not_called()
                        log_action.assert_not_called()
                        self.assertEqual(self.app.cfg.guardrail, prior_gc)
                        for path, body in prior_files.items():
                            self.assertEqual(path.read_bytes(), body)
                        if prior_dotenv is None:
                            self.assertFalse(os.path.lexists(dotenv_path))
                        else:
                            self.assertEqual(dotenv_path.read_bytes(), prior_dotenv)
                        if prior_exists:
                            self.assertEqual(os.environ.get(env_name), prior_env_value)
                        else:
                            self.assertNotIn(env_name, os.environ)
                        self.assertEqual(os.environ.get(other_env_name), other_env_value)
                        diagnostics = _click_result_exception_diagnostics(result)
                        self.assertNotIn(secret_value, diagnostics)

    def test_windows_opencode_judge_secret_success_publishes_once_after_prompts(self):
        env_name = "DISPOSABLE_JUDGE_ENV"
        other_env_name = "DISPOSABLE_UNRELATED_ENV"
        secret_value = "disposable judge marker value"
        other_env_value = "disposable unrelated process marker"
        gc = self.app.cfg.guardrail
        gc.connector = "amp"
        gc.enabled = True
        gc.mode = "action"
        gc.judge.enabled = False
        lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
        dotenv_path = Path(self.tmp_dir, ".env")
        prior_dotenv = b"UNRELATED_MARKER=preserved\n"
        atomic_write_private_bytes(str(lock_path), b'{"prior":"lock-marker"}\n')
        atomic_write_private_bytes(str(dotenv_path), prior_dotenv)
        events: list[str] = []
        save_secret_batch = cmd_setup._save_secrets_to_dotenv_locked
        version_check = cmd_setup._check_guardrail_setup_connector_versions

        def publish(*args, **kwargs):
            events.append("publish")
            self.assertIn("advanced-choice", events)
            return save_secret_batch(*args, **kwargs)

        def validate(*args, **kwargs):
            events.append("validate")
            return version_check(*args, **kwargs)

        def execute(*_args, **_kwargs):
            events.append("execute")
            return True, []

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(env_name, None)
            os.environ[other_env_name] = other_env_value
            with (
                _guardrail_judge_secret_wizard(
                    lock_path,
                    env_name,
                    secret_value,
                    events=events,
                ) as selected,
                patch(
                    "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                    side_effect=publish,
                ) as secret_writer,
                patch(
                    "defenseclaw.commands.cmd_setup._check_guardrail_setup_connector_versions",
                    side_effect=validate,
                ) as validated,
                patch(
                    "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                    side_effect=execute,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._log_setup_action",
                    return_value=None,
                ) as log_action,
            ):
                result = _invoke(
                    [
                        "guardrail",
                        "--connector",
                        "opencode",
                        "--no-restart",
                        "--no-verify",
                    ],
                    self.app,
                    catch=True,
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            selected.assert_called_once()
            secret_writer.assert_called_once()
            validated.assert_called_once()
            log_action.assert_called_once()
            self.assertLess(events.index("advanced-choice"), events.index("publish"))
            self.assertLess(events.index("publish"), events.index("validate"))
            self.assertLess(events.index("validate"), events.index("execute"))
            dotenv_body = dotenv_path.read_bytes()
            self.assertIn(prior_dotenv, dotenv_body)
            self.assertEqual(dotenv_body.count((env_name + "=").encode()), 1)
            self.assertEqual(os.environ.get(env_name), secret_value)
            self.assertEqual(os.environ.get(other_env_name), other_env_value)
            self.assertNotIn(secret_value, result.output)
            self.assertNotIn(secret_value, repr(log_action.call_args))

    def test_windows_opencode_judge_secret_late_failure_restores_exact_state(self):
        pristine = copy.deepcopy(self.app.cfg)
        env_name = "DISPOSABLE_JUDGE_ENV"
        other_env_name = "DISPOSABLE_UNRELATED_ENV"
        secret_value = "disposable judge marker value"
        prior_env_value = "disposable prior process marker"
        other_env_value = "disposable unrelated process marker"
        for failure_phase in ("validation", "setup", "readiness"):
            for prior_exists in (False, True):
                with self.subTest(
                    failure_phase=failure_phase,
                    prior_exists=prior_exists,
                ):
                    self.app.cfg = copy.deepcopy(pristine)
                    gc = self.app.cfg.guardrail
                    gc.connector = "amp"
                    gc.enabled = True
                    gc.mode = "action"
                    gc.judge.enabled = False
                    prior_gc = copy.deepcopy(gc)
                    config_path = Path(self.cfg_path)
                    hint_path = Path(self.tmp_dir, "picked_connector")
                    receipt_path = Path(self.tmp_dir, "agent_selection.json")
                    lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                    dotenv_path = Path(self.tmp_dir, ".env")
                    hilt_path = Path(self.app.cfg.policy_dir, "rego", "data.json")
                    for path in (
                        config_path,
                        hint_path,
                        receipt_path,
                        lock_path,
                        dotenv_path,
                        hilt_path,
                    ):
                        path.unlink(missing_ok=True)
                    prior_files = {
                        config_path: b"disposable prior config marker\n",
                        hint_path: b"amp\n",
                        receipt_path: b'{"prior":"late-receipt-marker"}\n',
                        lock_path: b'{"prior":"late-lock-marker"}\n',
                    }
                    prior_dotenv = (
                        b"UNRELATED_MARKER=preserved\nDISPOSABLE_JUDGE_ENV=disposable prior file marker\n"
                        if prior_exists
                        else None
                    )
                    for path, body in prior_files.items():
                        atomic_write_private_bytes(str(path), body)
                    if prior_dotenv is not None:
                        atomic_write_private_bytes(str(dotenv_path), prior_dotenv)
                    events: list[str] = []
                    save_secret_batch = cmd_setup._save_secrets_to_dotenv_locked

                    def publish(*args, **kwargs):
                        events.append("publish")
                        return save_secret_batch(*args, **kwargs)

                    if failure_phase == "validation":
                        version_kwargs = {"side_effect": RuntimeError(secret_value)}
                        execute_kwargs = {"side_effect": AssertionError("validation failure must precede setup")}
                        restart_kwargs = {"side_effect": AssertionError("validation failure must precede readiness")}
                    elif failure_phase == "setup":
                        version_kwargs = {"return_value": True}
                        execute_kwargs = {"side_effect": RuntimeError(secret_value)}
                        restart_kwargs = {"side_effect": AssertionError("setup failure must precede readiness")}
                    else:
                        version_kwargs = {"return_value": True}
                        execute_kwargs = {"return_value": (True, [])}
                        restart_kwargs = {
                            "side_effect": [
                                RuntimeError(secret_value),
                                None,
                            ]
                        }

                    args = [
                        "guardrail",
                        "--connector",
                        "opencode",
                        "--no-verify",
                    ]
                    if failure_phase != "readiness":
                        args.append("--no-restart")

                    with patch.dict(os.environ, {}, clear=False):
                        if prior_exists:
                            os.environ[env_name] = prior_env_value
                        else:
                            os.environ.pop(env_name, None)
                        os.environ[other_env_name] = other_env_value
                        with (
                            _guardrail_judge_secret_wizard(
                                lock_path,
                                env_name,
                                secret_value,
                                events=events,
                            ) as selected,
                            patch(
                                "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                                side_effect=publish,
                            ) as secret_writer,
                            patch(
                                "defenseclaw.commands.cmd_setup._check_guardrail_setup_connector_versions",
                                **version_kwargs,
                            ),
                            patch(
                                "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                                **execute_kwargs,
                            ),
                            patch(
                                "defenseclaw.commands.cmd_setup._restart_services",
                                **restart_kwargs,
                            ),
                            patch(
                                "defenseclaw.commands.cmd_setup._log_setup_action",
                                side_effect=AssertionError("failed setup must not publish an audit success"),
                            ) as log_action,
                        ):
                            result = _invoke(args, self.app, catch=True)

                        self.assertNotEqual(result.exit_code, 0)
                        selected.assert_called_once()
                        secret_writer.assert_called_once()
                        log_action.assert_not_called()
                        self.assertIn("publish", events)
                        self.assertEqual(self.app.cfg.guardrail, prior_gc)
                        for path, body in prior_files.items():
                            self.assertEqual(path.read_bytes(), body)
                        self.assertFalse(os.path.lexists(hilt_path))
                        if prior_dotenv is None:
                            self.assertFalse(os.path.lexists(dotenv_path))
                        else:
                            self.assertEqual(dotenv_path.read_bytes(), prior_dotenv)
                        if prior_exists:
                            self.assertEqual(os.environ.get(env_name), prior_env_value)
                        else:
                            self.assertNotIn(env_name, os.environ)
                        self.assertEqual(os.environ.get(other_env_name), other_env_value)
                        diagnostics = _click_result_exception_diagnostics(result)
                        self.assertNotIn(secret_value, diagnostics)
                        self.assertNotIn(secret_value, repr(log_action.call_args_list))

    def test_guardrail_secret_holders_do_not_repr_sensitive_marker(self):
        secret_value = "disposable judge marker value"
        pending = cmd_setup._PendingGuardrailSecret(
            "DISPOSABLE_JUDGE_ENV",
            secret_value,
        )
        dotenv_snapshot = cmd_setup._RotateTokenDotenvSnapshot(
            existed=True,
            body=("DISPOSABLE_JUDGE_ENV=" + secret_value + "\n").encode(),
            mode=0o600,
        )
        key_transaction = cmd_setup._GuardrailSecretKeyTransaction(
            env_name="DISPOSABLE_JUDGE_ENV",
            dotenv_before_existed=True,
            dotenv_before_value=secret_value.encode(),
            dotenv_published_value=secret_value.encode(),
            dotenv_changed=True,
            process_before_existed=True,
            process_before_value=secret_value,
            process_published_value=secret_value,
            process_changed=True,
        )
        transaction = cmd_setup._GuardrailSecretTransaction(
            dotenv_path=str(Path(self.tmp_dir, ".env")),
            dotenv_before=dotenv_snapshot,
            dotenv_after=dotenv_snapshot,
            dotenv_after_sha256=cmd_setup._guardrail_dotenv_snapshot_sha256(dotenv_snapshot),
            dotenv_after_authoritative=True,
            keys=(key_transaction,),
        )
        rollback_status = cmd_setup._guardrail_secret_rollback_status("dotenv-owned-key-conflict")
        failure = cmd_setup._GuardrailSecretFailure("disposable-safe-code")

        for diagnostic in (
            repr(pending),
            repr(dotenv_snapshot),
            repr(key_transaction),
            repr(transaction),
            repr(rollback_status),
            repr(failure),
        ):
            self.assertNotIn(secret_value, diagnostic)

    def test_pending_guardrail_secret_prompt_hides_input_and_defers_writer(self):
        env_name = "DISPOSABLE_JUDGE_ENV"
        secret_value = "disposable judge marker value"
        pending: list[cmd_setup._PendingGuardrailSecret] = []
        with (
            patch.dict(os.environ, {}, clear=False),
            patch(
                "defenseclaw.commands.cmd_setup.click.prompt",
                return_value=secret_value,
            ) as prompted,
            patch(
                "defenseclaw.commands.cmd_setup._save_secret_to_dotenv",
                side_effect=AssertionError("pending prompt must not publish"),
            ) as secret_writer,
        ):
            os.environ.pop(env_name, None)
            cmd_setup._prompt_and_save_secret(
                env_name,
                "",
                self.tmp_dir,
                _pending_secrets=pending,
            )

        prompted.assert_called_once()
        self.assertTrue(prompted.call_args.kwargs["hide_input"])
        secret_writer.assert_not_called()
        self.assertEqual(len(pending), 1)
        self.assertNotIn(secret_value, repr(pending))
        cmd_setup._clear_pending_guardrail_secrets(pending)

    def test_guardrail_secret_batch_blocks_unrelated_writer_until_atomic_publish(self):
        owned_name = "DISPOSABLE_BATCH_OWNED_ENV"
        unrelated_name = "DISPOSABLE_BATCH_UNRELATED_ENV"
        owned_value = "disposable batch owned marker"
        unrelated_value = "disposable batch unrelated marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        prior_body = b"BASE_MARKER=preserved\n"
        atomic_write_private_bytes(str(dotenv_path), prior_body)
        render_started = threading.Event()
        unrelated_attempted = threading.Event()
        unrelated_finished = threading.Event()
        thread_failures: list[str] = []
        original_render = cmd_setup._dotenv_upsert_render

        def blocking_render(snapshot, key, value):
            if key == owned_name and not render_started.is_set():
                render_started.set()
                self.assertTrue(unrelated_attempted.wait(5))
                self.assertFalse(unrelated_finished.is_set())
            return original_render(snapshot, key, value)

        def unrelated_writer():
            if not render_started.wait(5):
                thread_failures.append("publication did not reach the locked render")
                return
            unrelated_attempted.set()
            try:
                cmd_setup._save_secret_to_dotenv(
                    unrelated_name,
                    unrelated_value,
                    self.tmp_dir,
                )
            except BaseException:
                thread_failures.append("unrelated locked writer failed")
            finally:
                unrelated_finished.set()

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(owned_name, None)
            os.environ.pop(unrelated_name, None)
            writer_thread = threading.Thread(target=unrelated_writer, daemon=True)
            writer_thread.start()
            try:
                with patch(
                    "defenseclaw.commands.cmd_setup._dotenv_upsert_render",
                    side_effect=blocking_render,
                ):
                    transaction = cmd_setup._publish_pending_guardrail_secrets(
                        [
                            cmd_setup._PendingGuardrailSecret(
                                owned_name,
                                owned_value,
                            )
                        ],
                        self.tmp_dir,
                    )
            finally:
                writer_thread.join(5)

            self.assertFalse(writer_thread.is_alive())
            self.assertEqual(thread_failures, [])
            self.assertIsNotNone(transaction)
            published_body = dotenv_path.read_bytes()
            self.assertIn((owned_name + "=").encode(), published_body)
            self.assertIn((unrelated_name + "=").encode(), published_body)
            rollback_status = cmd_setup._restore_guardrail_secret_transaction(transaction)
            self.assertTrue(rollback_status.complete)
            restored_body = dotenv_path.read_bytes()
            self.assertNotIn((owned_name + "=").encode(), restored_body)
            self.assertIn((unrelated_name + "=").encode(), restored_body)
            self.assertNotIn(owned_name, os.environ)
            self.assertEqual(os.environ.get(unrelated_name), unrelated_value)

    def test_guardrail_secret_failed_writer_captures_post_state_before_unlock(self):
        owned_name = "DISPOSABLE_FAILED_WRITE_OWNED_ENV"
        unrelated_name = "DISPOSABLE_FAILED_WRITE_UNRELATED_ENV"
        owned_value = "disposable failed write owned marker"
        unrelated_value = "disposable failed write unrelated marker"
        failure_marker = "disposable failed write exception marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        prior_body = b"BASE_MARKER=preserved\n"
        atomic_write_private_bytes(str(dotenv_path), prior_body)
        owned_written = threading.Event()
        unrelated_attempted = threading.Event()
        unrelated_finished = threading.Event()
        thread_failures: list[str] = []
        main_thread = threading.get_ident()
        main_lock_entries = 0
        original_lock = cmd_setup.locked_file_update
        original_batch_writer = cmd_setup._save_secrets_to_dotenv_locked

        @contextlib.contextmanager
        def ordered_lock(path):
            nonlocal main_lock_entries
            if threading.get_ident() == main_thread:
                main_lock_entries += 1
                if main_lock_entries > 1 and not unrelated_finished.wait(5):
                    raise AssertionError("unrelated writer did not finish before rollback")
            with original_lock(path):
                yield

        def fail_after_owned_write(path, snapshot, updates):
            original_batch_writer(path, snapshot, updates)
            if threading.get_ident() != main_thread:
                return
            owned_written.set()
            self.assertTrue(unrelated_attempted.wait(5))
            self.assertFalse(unrelated_finished.is_set())
            raise RuntimeError(failure_marker)

        def unrelated_writer():
            if not owned_written.wait(5):
                thread_failures.append("owned writer did not publish")
                return
            unrelated_attempted.set()
            try:
                cmd_setup._save_secret_to_dotenv(
                    unrelated_name,
                    unrelated_value,
                    self.tmp_dir,
                )
            except BaseException:
                thread_failures.append("unrelated locked writer failed")
            finally:
                unrelated_finished.set()

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(owned_name, None)
            os.environ.pop(unrelated_name, None)
            writer_thread = threading.Thread(target=unrelated_writer, daemon=True)
            writer_thread.start()
            try:
                with (
                    patch(
                        "defenseclaw.commands.cmd_setup.locked_file_update",
                        side_effect=ordered_lock,
                    ),
                    patch(
                        "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                        side_effect=fail_after_owned_write,
                    ),
                    self.assertRaises(cmd_setup._GuardrailSecretFailure) as raised,
                ):
                    cmd_setup._publish_pending_guardrail_secrets(
                        [cmd_setup._PendingGuardrailSecret(owned_name, owned_value)],
                        self.tmp_dir,
                    )
            finally:
                writer_thread.join(5)

            self.assertFalse(writer_thread.is_alive())
            self.assertEqual(thread_failures, [])
            current_body = dotenv_path.read_bytes()
            self.assertIn(prior_body.rstrip(), current_body)
            self.assertNotIn((owned_name + "=").encode(), current_body)
            self.assertIn((unrelated_name + "=").encode(), current_body)
            self.assertNotIn(owned_name, os.environ)
            self.assertEqual(os.environ.get(unrelated_name), unrelated_value)
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
            diagnostics = "".join(
                traceback.format_exception(
                    type(raised.exception),
                    raised.exception,
                    raised.exception.__traceback__,
                )
            )
            self.assertNotIn(failure_marker, diagnostics)
            self.assertNotIn(failure_marker, repr(raised.exception))

    def test_guardrail_secret_non_authoritative_post_snapshot_cannot_restore_file(self):
        owned_name = "DISPOSABLE_NONAUTHORITATIVE_OWNED_ENV"
        owned_value = "disposable nonauthoritative owned marker"
        failure_marker = "disposable nonauthoritative exception marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        prior_body = b"BASE_MARKER=preserved\n"
        atomic_write_private_bytes(str(dotenv_path), prior_body)
        snapshot_calls = 0
        original_snapshot = cmd_setup._rotate_token_snapshot_locked
        original_batch_writer = cmd_setup._save_secrets_to_dotenv_locked

        def fail_authoritative_snapshot(path):
            nonlocal snapshot_calls
            snapshot_calls += 1
            if snapshot_calls == 2:
                raise RuntimeError(failure_marker)
            return original_snapshot(path)

        def fail_after_owned_write(path, snapshot, updates):
            original_batch_writer(path, snapshot, updates)
            raise RuntimeError(failure_marker)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(owned_name, None)
            with (
                patch(
                    "defenseclaw.commands.cmd_setup._rotate_token_snapshot_locked",
                    side_effect=fail_authoritative_snapshot,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                    side_effect=fail_after_owned_write,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._rotate_token_restore_locked",
                    side_effect=AssertionError("a later snapshot cannot authorize exact restore"),
                ) as exact_restore,
                self.assertRaises(cmd_setup._GuardrailSecretFailure) as raised,
            ):
                cmd_setup._publish_pending_guardrail_secrets(
                    [cmd_setup._PendingGuardrailSecret(owned_name, owned_value)],
                    self.tmp_dir,
                )

            exact_restore.assert_not_called()
            self.assertGreaterEqual(snapshot_calls, 4)
            self.assertEqual(dotenv_path.read_bytes(), prior_body)
            self.assertNotIn(owned_name, os.environ)
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
            diagnostics = "".join(
                traceback.format_exception(
                    type(raised.exception),
                    raised.exception,
                    raised.exception.__traceback__,
                )
            )
            self.assertNotIn(failure_marker, diagnostics)
            self.assertNotIn(failure_marker, repr(raised.exception))

    def test_guardrail_secret_publication_reports_secret_and_setup_rollback_status(self):
        pristine = copy.deepcopy(self.app.cfg)
        env_name = "DISPOSABLE_PUBLIC_STATUS_ENV"
        secret_value = "disposable public status marker"
        original_snapshot = cmd_setup._rotate_token_snapshot_locked
        original_batch_writer = cmd_setup._save_secrets_to_dotenv_locked
        original_setup_restore = cmd_setup._restore_setup_config_snapshot
        expected_codes = {
            False: "publication-failed-secret-rollback-incomplete",
            True: "publication-failed-setup-and-secret-rollback-incomplete",
        }

        for setup_rollback_fails, expected_code in expected_codes.items():
            with self.subTest(setup_rollback_fails=setup_rollback_fails):
                self.app.cfg = copy.deepcopy(pristine)
                gc = self.app.cfg.guardrail
                gc.connector = "amp"
                gc.enabled = True
                gc.mode = "action"
                gc.judge.enabled = False
                prior_gc = copy.deepcopy(gc)
                config_path = Path(self.cfg_path)
                receipt_path = Path(self.tmp_dir, "agent_selection.json")
                lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                dotenv_path = Path(self.tmp_dir, ".env")
                for path in (config_path, receipt_path, lock_path, dotenv_path):
                    path.unlink(missing_ok=True)
                prior_files = {
                    config_path: b"disposable public status prior config\n",
                    receipt_path: b'{"prior":"public-status-receipt-marker"}\n',
                    lock_path: b'{"prior":"public-status-lock-marker"}\n',
                }
                for path, body in prior_files.items():
                    atomic_write_private_bytes(str(path), body)
                snapshot_calls = 0

                def fail_post_snapshots(path):
                    nonlocal snapshot_calls
                    snapshot_calls += 1
                    if snapshot_calls > 1:
                        raise RuntimeError(secret_value)
                    return original_snapshot(path)

                def fail_after_owned_write(path, snapshot, updates):
                    original_batch_writer(path, snapshot, updates)
                    raise RuntimeError(secret_value)

                def restore_then_maybe_fail(*args, **kwargs):
                    original_setup_restore(*args, **kwargs)
                    if setup_rollback_fails:
                        raise RuntimeError(secret_value)

                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop(env_name, None)
                    with (
                        _guardrail_judge_secret_wizard(
                            lock_path,
                            env_name,
                            secret_value,
                        ) as selected,
                        patch(
                            "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                            side_effect=fail_after_owned_write,
                        ) as secret_writer,
                        patch(
                            "defenseclaw.commands.cmd_setup._rotate_token_snapshot_locked",
                            side_effect=fail_post_snapshots,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._restore_setup_config_snapshot",
                            side_effect=restore_then_maybe_fail,
                        ) as setup_restore,
                        patch(
                            "defenseclaw.commands.cmd_setup._check_guardrail_setup_connector_versions",
                            side_effect=AssertionError("publication failure must precede validation"),
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                            side_effect=AssertionError("publication failure must precede setup"),
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._log_setup_action",
                            side_effect=AssertionError("failed publication must not audit success"),
                        ) as log_action,
                    ):
                        result = _invoke(
                            [
                                "guardrail",
                                "--connector",
                                "opencode",
                                "--no-restart",
                                "--no-verify",
                            ],
                            self.app,
                            catch=True,
                        )

                    self.assertNotEqual(result.exit_code, 0)
                    selected.assert_called_once()
                    secret_writer.assert_called_once()
                    setup_restore.assert_called_once()
                    log_action.assert_not_called()
                    self.assertEqual(snapshot_calls, 3)
                    self.assertEqual(self.app.cfg.guardrail, prior_gc)
                    for path, body in prior_files.items():
                        self.assertEqual(path.read_bytes(), body)
                    self.assertIn((env_name + "=").encode(), dotenv_path.read_bytes())
                    self.assertNotIn(env_name, os.environ)
                    self.assertIn(expected_code, result.output)
                    self.assertFalse(_click_result_reaches_marker(result, secret_value))
                    self.assertNotIn(secret_value, repr(log_action.call_args_list))

    def test_guardrail_secret_rollback_preserves_unrelated_post_publish_updates(self):
        owned_name = "DISPOSABLE_ROLLBACK_OWNED_ENV"
        unrelated_name = "DISPOSABLE_ROLLBACK_UNRELATED_ENV"
        prior_file_value = b"disposable prior file marker"
        prior_process_value = "disposable prior process marker"
        unrelated_value = "disposable unrelated update marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        prior_body = b"BASE_MARKER=preserved\n" + owned_name.encode() + b"=" + prior_file_value + b"\n"
        atomic_write_private_bytes(str(dotenv_path), prior_body)

        with patch.dict(os.environ, {}, clear=False):
            os.environ[owned_name] = prior_process_value
            os.environ.pop(unrelated_name, None)
            transaction = cmd_setup._publish_pending_guardrail_secrets(
                [
                    cmd_setup._PendingGuardrailSecret(
                        owned_name,
                        "disposable published update marker",
                    )
                ],
                self.tmp_dir,
            )
            self.assertIsNotNone(transaction)
            cmd_setup._save_secret_to_dotenv(
                unrelated_name,
                unrelated_value,
                self.tmp_dir,
            )
            rollback_status = cmd_setup._restore_guardrail_secret_transaction(transaction)

            self.assertTrue(rollback_status.complete)
            restored_body = dotenv_path.read_bytes()
            self.assertIn(owned_name.encode() + b"=" + prior_file_value, restored_body)
            self.assertIn((unrelated_name + "=").encode(), restored_body)
            self.assertEqual(os.environ.get(owned_name), prior_process_value)
            self.assertEqual(os.environ.get(unrelated_name), unrelated_value)

    def test_guardrail_secret_partial_multi_key_publication_rolls_back_changed_keys(self):
        first_name = "DISPOSABLE_PARTIAL_FIRST_ENV"
        second_name = "DISPOSABLE_PARTIAL_SECOND_ENV"
        first_prior = "disposable first prior process marker"
        failure_marker = "disposable partial failure marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        prior_body = b"UNRELATED_MARKER=preserved\n"
        atomic_write_private_bytes(str(dotenv_path), prior_body)
        prior_mode = stat.S_IMODE(dotenv_path.stat().st_mode)
        original_setter = cmd_setup._set_guardrail_secret_process_value

        def partial_setter(env_name, value):
            if env_name == second_name:
                raise RuntimeError(failure_marker)
            original_setter(env_name, value)

        pending = [
            cmd_setup._PendingGuardrailSecret(
                first_name,
                "disposable first published marker",
            ),
            cmd_setup._PendingGuardrailSecret(
                second_name,
                "disposable second published marker",
            ),
        ]
        with patch.dict(os.environ, {}, clear=False):
            os.environ[first_name] = first_prior
            os.environ.pop(second_name, None)
            with (
                patch(
                    "defenseclaw.commands.cmd_setup._set_guardrail_secret_process_value",
                    side_effect=partial_setter,
                ),
                patch(
                    "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                    wraps=cmd_setup._save_secrets_to_dotenv_locked,
                ) as batch_writer,
                self.assertRaises(cmd_setup._GuardrailSecretFailure) as raised,
            ):
                cmd_setup._publish_pending_guardrail_secrets(
                    pending,
                    self.tmp_dir,
                )

            batch_writer.assert_called_once()
            self.assertEqual(pending, [])
            self.assertEqual(dotenv_path.read_bytes(), prior_body)
            self.assertEqual(stat.S_IMODE(dotenv_path.stat().st_mode), prior_mode)
            self.assertEqual(os.environ.get(first_name), first_prior)
            self.assertNotIn(second_name, os.environ)
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
            self.assertNotIn(failure_marker, repr(raised.exception))

    def test_guardrail_secret_same_owned_key_conflict_is_preserved_and_reported(self):
        env_name = "DISPOSABLE_CONFLICT_ENV"
        prior_file_value = "disposable conflict prior file marker"
        prior_process_value = "disposable conflict prior process marker"
        concurrent_value = "disposable conflict concurrent marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        atomic_write_private_bytes(
            str(dotenv_path),
            (f"UNRELATED_MARKER=preserved\n{env_name}={prior_file_value}\n").encode(),
        )

        with patch.dict(os.environ, {}, clear=False):
            os.environ[env_name] = prior_process_value
            transaction = cmd_setup._publish_pending_guardrail_secrets(
                [
                    cmd_setup._PendingGuardrailSecret(
                        env_name,
                        "disposable conflict published marker",
                    )
                ],
                self.tmp_dir,
            )
            self.assertIsNotNone(transaction)
            cmd_setup._save_secret_to_dotenv(
                env_name,
                concurrent_value,
                self.tmp_dir,
            )
            rollback_status = cmd_setup._restore_guardrail_secret_transaction(transaction)

            self.assertFalse(rollback_status.complete)
            self.assertIn("dotenv-owned-key-conflict", rollback_status.codes)
            self.assertIn("process-owned-key-conflict", rollback_status.codes)
            current_body = dotenv_path.read_bytes()
            self.assertIn((env_name + "=" + concurrent_value).encode(), current_body)
            self.assertIn(b"UNRELATED_MARKER=preserved", current_body)
            self.assertEqual(os.environ.get(env_name), concurrent_value)
            self.assertNotIn(concurrent_value, repr(rollback_status))
            self.assertNotIn(concurrent_value, repr(transaction))

    def test_guardrail_secret_no_interleave_restores_exact_file_mode_and_process(self):
        env_name = "DISPOSABLE_EXACT_ROLLBACK_ENV"
        prior_process_value = "disposable exact prior process marker"
        dotenv_path = Path(self.tmp_dir, ".env")
        for prior_exists in (False, True):
            with self.subTest(prior_exists=prior_exists):
                dotenv_path.unlink(missing_ok=True)
                prior_body = (
                    b"UNRELATED_MARKER=preserved\nDISPOSABLE_EXACT_ROLLBACK_ENV=disposable exact prior file marker\n"
                    if prior_exists
                    else None
                )
                if prior_body is not None:
                    atomic_write_private_bytes(str(dotenv_path), prior_body)
                    prior_mode = stat.S_IMODE(dotenv_path.stat().st_mode)
                else:
                    prior_mode = None
                with patch.dict(os.environ, {}, clear=False):
                    if prior_exists:
                        os.environ[env_name] = prior_process_value
                    else:
                        os.environ.pop(env_name, None)
                    with patch(
                        "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                        wraps=cmd_setup._save_secrets_to_dotenv_locked,
                    ) as batch_writer:
                        transaction = cmd_setup._publish_pending_guardrail_secrets(
                            [
                                cmd_setup._PendingGuardrailSecret(
                                    env_name,
                                    "disposable exact published marker",
                                )
                            ],
                            self.tmp_dir,
                        )
                    batch_writer.assert_called_once()
                    self.assertIsNotNone(transaction)
                    self.assertEqual(
                        transaction.dotenv_after_sha256,
                        cmd_setup._guardrail_dotenv_snapshot_sha256(transaction.dotenv_after),
                    )
                    self.assertEqual(len(transaction.keys), 1)
                    self.assertTrue(transaction.keys[0].dotenv_changed)
                    self.assertTrue(transaction.keys[0].process_changed)
                    rollback_status = cmd_setup._restore_guardrail_secret_transaction(transaction)
                    self.assertTrue(rollback_status.complete)
                    if prior_body is None:
                        self.assertFalse(os.path.lexists(dotenv_path))
                        self.assertNotIn(env_name, os.environ)
                    else:
                        self.assertEqual(dotenv_path.read_bytes(), prior_body)
                        self.assertEqual(
                            stat.S_IMODE(dotenv_path.stat().st_mode),
                            prior_mode,
                        )
                        self.assertEqual(
                            os.environ.get(env_name),
                            prior_process_value,
                        )

    def test_windows_opencode_secret_exception_graph_is_redacted_for_writer_save_and_rollback(self):
        pristine = copy.deepcopy(self.app.cfg)
        env_name = "DISPOSABLE_CHAIN_ENV"
        secret_value = "disposable exception chain marker"
        prior_process_value = "disposable chain prior process marker"
        for failure_phase in ("writer", "save", "rollback"):
            with self.subTest(failure_phase=failure_phase):
                self.app.cfg = copy.deepcopy(pristine)
                gc = self.app.cfg.guardrail
                gc.connector = "amp"
                gc.enabled = True
                gc.mode = "action"
                gc.judge.enabled = False
                prior_gc = copy.deepcopy(gc)
                config_path = Path(self.cfg_path)
                hint_path = Path(self.tmp_dir, "picked_connector")
                receipt_path = Path(self.tmp_dir, "agent_selection.json")
                lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                dotenv_path = Path(self.tmp_dir, ".env")
                for path in (
                    config_path,
                    hint_path,
                    receipt_path,
                    lock_path,
                    dotenv_path,
                ):
                    path.unlink(missing_ok=True)
                prior_files = {
                    config_path: b"disposable chain prior config marker\n",
                    hint_path: b"amp\n",
                    receipt_path: b'{"prior":"chain-receipt-marker"}\n',
                    lock_path: b'{"prior":"chain-lock-marker"}\n',
                }
                prior_dotenv = b"UNRELATED_MARKER=preserved\nDISPOSABLE_CHAIN_ENV=disposable chain prior file marker\n"
                for path, body in prior_files.items():
                    atomic_write_private_bytes(str(path), body)
                atomic_write_private_bytes(str(dotenv_path), prior_dotenv)
                original_batch_writer = cmd_setup._save_secrets_to_dotenv_locked
                original_restore = cmd_setup._restore_setup_config_snapshot

                if failure_phase == "writer":
                    batch_effect = RuntimeError(secret_value)
                    version_kwargs = {"side_effect": AssertionError("writer failure must precede validation")}
                    execute_kwargs = {"side_effect": AssertionError("writer failure must precede setup")}
                    restore_effect = original_restore
                elif failure_phase == "save":
                    batch_effect = original_batch_writer
                    version_kwargs = {"return_value": True}

                    def fail_during_save(*_args, **_kwargs):
                        self.app.cfg.save()
                        return True, []

                    execute_kwargs = {"side_effect": fail_during_save}
                    restore_effect = original_restore
                else:
                    batch_effect = original_batch_writer
                    version_kwargs = {"side_effect": RuntimeError(secret_value)}
                    execute_kwargs = {"side_effect": AssertionError("rollback test must fail during validation")}

                    def restore_then_fail(*args, **kwargs):
                        original_restore(*args, **kwargs)
                        raise RuntimeError(secret_value)

                    restore_effect = restore_then_fail

                save = MagicMock(side_effect=RuntimeError(secret_value))
                if failure_phase == "save":
                    self.app.cfg.save = save  # type: ignore[assignment]
                log_action = MagicMock(side_effect=AssertionError("failed setup must not audit success"))
                with patch.dict(os.environ, {}, clear=False):
                    os.environ[env_name] = prior_process_value
                    with (
                        _guardrail_judge_secret_wizard(
                            lock_path,
                            env_name,
                            secret_value,
                        ) as selected,
                        patch(
                            "defenseclaw.commands.cmd_setup._save_secrets_to_dotenv_locked",
                            side_effect=batch_effect,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._check_guardrail_setup_connector_versions",
                            **version_kwargs,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                            **execute_kwargs,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._restore_setup_config_snapshot",
                            side_effect=restore_effect,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._log_setup_action",
                            log_action,
                        ),
                    ):
                        result = _invoke(
                            [
                                "guardrail",
                                "--connector",
                                "opencode",
                                "--no-restart",
                                "--no-verify",
                            ],
                            self.app,
                            catch=True,
                        )

                    self.assertNotEqual(result.exit_code, 0)
                    selected.assert_called_once()
                    self.assertEqual(self.app.cfg.guardrail, prior_gc)
                    for path, body in prior_files.items():
                        self.assertEqual(path.read_bytes(), body)
                    self.assertEqual(dotenv_path.read_bytes(), prior_dotenv)
                    self.assertEqual(os.environ.get(env_name), prior_process_value)
                    diagnostics = _click_result_exception_diagnostics(result)
                    self.assertNotIn(secret_value, diagnostics)
                    self.assertNotIn(secret_value, repr(log_action.call_args_list))
                    self.assertNotIn(secret_value, repr(save.call_args_list))

    def test_windows_opencode_late_failure_preserves_unrelated_concurrent_secret_state(self):
        pristine = copy.deepcopy(self.app.cfg)
        owned_name = "DISPOSABLE_LATE_OWNED_ENV"
        unrelated_name = "DISPOSABLE_LATE_UNRELATED_ENV"
        owned_value = "disposable late owned marker"
        unrelated_value = "disposable late unrelated marker"
        for failure_phase in ("validation", "setup", "readiness"):
            with self.subTest(failure_phase=failure_phase):
                self.app.cfg = copy.deepcopy(pristine)
                gc = self.app.cfg.guardrail
                gc.connector = "amp"
                gc.enabled = True
                gc.mode = "action"
                gc.judge.enabled = False
                prior_gc = copy.deepcopy(gc)
                config_path = Path(self.cfg_path)
                receipt_path = Path(self.tmp_dir, "agent_selection.json")
                lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                dotenv_path = Path(self.tmp_dir, ".env")
                for path in (config_path, receipt_path, lock_path, dotenv_path):
                    path.unlink(missing_ok=True)
                prior_files = {
                    config_path: b"disposable concurrent prior config marker\n",
                    receipt_path: b'{"prior":"concurrent-receipt-marker"}\n',
                    lock_path: b'{"prior":"concurrent-lock-marker"}\n',
                }
                prior_dotenv = b"BASE_MARKER=preserved\n"
                for path, body in prior_files.items():
                    atomic_write_private_bytes(str(path), body)
                atomic_write_private_bytes(str(dotenv_path), prior_dotenv)
                failure_count = 0

                def inject_unrelated_update():
                    cmd_setup._save_secret_to_dotenv(
                        unrelated_name,
                        unrelated_value,
                        self.tmp_dir,
                    )
                    self.assertIn(
                        (unrelated_name + "=").encode(),
                        dotenv_path.read_bytes(),
                    )

                def fail_validation(*_args, **_kwargs):
                    inject_unrelated_update()
                    raise RuntimeError(owned_value)

                def fail_setup(*_args, **_kwargs):
                    inject_unrelated_update()
                    raise RuntimeError(owned_value)

                def fail_readiness(*_args, **_kwargs):
                    nonlocal failure_count
                    failure_count += 1
                    if failure_count == 1:
                        inject_unrelated_update()
                        raise RuntimeError(owned_value)
                    return None

                version_kwargs = (
                    {"side_effect": fail_validation} if failure_phase == "validation" else {"return_value": True}
                )
                execute_kwargs = (
                    {"side_effect": fail_setup} if failure_phase == "setup" else {"return_value": (True, [])}
                )
                restart_kwargs = (
                    {"side_effect": fail_readiness} if failure_phase == "readiness" else {"return_value": None}
                )
                original_secret_restore = cmd_setup._restore_guardrail_secret_transaction

                def restore_secret_with_concurrency_assertions(transaction):
                    self.assertIn(
                        (unrelated_name + "=").encode(),
                        dotenv_path.read_bytes(),
                    )
                    self.assertNotEqual(
                        dotenv_path.read_bytes(),
                        transaction.dotenv_after.body,
                    )
                    status = original_secret_restore(transaction)
                    self.assertIn(
                        (unrelated_name + "=").encode(),
                        dotenv_path.read_bytes(),
                    )
                    return status

                args = [
                    "guardrail",
                    "--connector",
                    "opencode",
                    "--no-verify",
                ]
                if failure_phase != "readiness":
                    args.append("--no-restart")

                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop(owned_name, None)
                    os.environ.pop(unrelated_name, None)
                    with (
                        _guardrail_judge_secret_wizard(
                            lock_path,
                            owned_name,
                            owned_value,
                        ) as selected,
                        patch(
                            "defenseclaw.commands.cmd_setup._check_guardrail_setup_connector_versions",
                            **version_kwargs,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
                            **execute_kwargs,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._restart_services",
                            **restart_kwargs,
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._restore_guardrail_secret_transaction",
                            side_effect=restore_secret_with_concurrency_assertions,
                        ) as secret_restore,
                        patch(
                            "defenseclaw.commands.cmd_setup._log_setup_action",
                            side_effect=AssertionError("failed setup must not audit success"),
                        ) as log_action,
                    ):
                        result = _invoke(args, self.app, catch=True)

                    self.assertNotEqual(result.exit_code, 0)
                    selected.assert_called_once()
                    secret_restore.assert_called_once()
                    log_action.assert_not_called()
                    self.assertEqual(self.app.cfg.guardrail, prior_gc)
                    for path, body in prior_files.items():
                        self.assertEqual(path.read_bytes(), body)
                    current_body = dotenv_path.read_bytes()
                    self.assertIn(prior_dotenv, current_body)
                    self.assertNotIn((owned_name + "=").encode(), current_body)
                    self.assertIn((unrelated_name + "=").encode(), current_body)
                    self.assertNotIn(owned_name, os.environ)
                    self.assertEqual(os.environ.get(unrelated_name), unrelated_value)
                    diagnostics = _click_result_exception_diagnostics(result)
                    self.assertNotIn(owned_value, diagnostics)
                    self.assertNotIn(owned_value, repr(log_action.call_args_list))

    def test_windows_opencode_guardrail_selection_observes_pristine_explicit_state(self):
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.connector = "amp"
        gc.mode = "observe"
        gc.scanner_mode = "both"
        gc.hilt.enabled = False
        gc.judge.enabled = False
        prior_gc = copy.deepcopy(gc)
        config_path = Path(self.cfg_path)
        secret_path = Path(self.tmp_dir, ".env")
        prior_config = b"disposable prior config marker\n"
        prior_secret = b"disposable secret-file marker\n"
        atomic_write_private_bytes(str(config_path), prior_config)
        atomic_write_private_bytes(str(secret_path), prior_secret)

        def select(data_dir, connectors):
            self.assertEqual(tuple(connectors), ("opencode",))
            self.assertEqual(gc, prior_gc)
            self.assertEqual(config_path.read_bytes(), prior_config)
            self.assertEqual(secret_path.read_bytes(), prior_secret)
            return record_test_setup_agent_selections(data_dir, connectors)

        revalidate = cmd_setup._revalidate_setup_agent_selections
        forbidden = AssertionError("generic OpenCode discovery cannot authorize guardrail setup")
        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection.record_setup_agent_selections",
                side_effect=select,
            ) as selected,
            patch(
                "defenseclaw.commands.cmd_setup._revalidate_setup_agent_selections",
                wraps=revalidate,
            ) as proof_check,
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa", return_value=None),
        ):
            result = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--connector",
                    "opencode",
                    "--mode",
                    "action",
                    "--scanner-mode",
                    "local",
                    "--human-approval",
                    "--judge-model",
                    "disposable-model-marker",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
                catch=True,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        selected.assert_called_once()
        proof_check.assert_called_once()
        generic.assert_not_called()
        self.assertEqual(secret_path.read_bytes(), prior_secret)

    def test_windows_opencode_guardrail_refusal_preserves_explicit_configured_and_picked_state(self):
        original_cfg = copy.deepcopy(self.app.cfg)
        cases = ("explicit", "configured", "picked")
        for target_case in cases:
            for mode in ("observe", "action"):
                with self.subTest(target_case=target_case, mode=mode):
                    self.app.cfg = copy.deepcopy(original_cfg)
                    gc = self.app.cfg.guardrail
                    gc.enabled = True
                    gc.connector = "opencode" if target_case == "configured" else "openclaw"
                    gc.mode = "observe"
                    gc.scanner_mode = "both"
                    gc.hilt.enabled = False
                    gc.judge.enabled = False
                    prior_gc = copy.deepcopy(gc)
                    config_path = Path(self.tmp_dir, "config.yaml")
                    secret_path = Path(self.tmp_dir, ".env")
                    receipt_path = Path(self.tmp_dir, "agent_selection.json")
                    lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
                    hint_path = Path(self.tmp_dir, "picked_connector")
                    prior_files = {
                        config_path: b"disposable prior config marker\n",
                        secret_path: b"disposable secret-file marker\n",
                        receipt_path: b'{"prior":"guardrail-receipt"}\n',
                        lock_path: b'{"prior":"guardrail-lock"}\n',
                        hint_path: (b"opencode\n" if target_case == "picked" else b"openclaw\n"),
                    }
                    for path, body in prior_files.items():
                        atomic_write_private_bytes(str(path), body)
                    forbidden = AssertionError("selection refusal must precede guardrail mutation")
                    save = MagicMock(side_effect=forbidden)
                    self.app.cfg.save = save  # type: ignore[assignment]

                    def refuse(_data_dir, connectors, **_kwargs):
                        self.assertEqual(tuple(connectors), ("opencode",))
                        self.assertEqual(gc, prior_gc)
                        self.assertEqual(config_path.read_bytes(), prior_files[config_path])
                        self.assertEqual(secret_path.read_bytes(), prior_files[secret_path])
                        self.assertEqual(hint_path.read_bytes(), prior_files[hint_path])
                        atomic_write_private_bytes(str(receipt_path), b"partial receipt\n")
                        atomic_write_private_bytes(str(lock_path), b"partial lock\n")
                        raise click.ClickException("exact SST image refused before mutation")

                    args = [
                        "guardrail",
                        "--non-interactive",
                        "--mode",
                        mode,
                        "--scanner-mode",
                        "local",
                        "--human-approval",
                        "--judge-model",
                        "disposable-model-marker",
                        "--no-restart",
                        "--no-verify",
                    ]
                    if target_case == "explicit":
                        args[2:2] = ["--connector", "opencode"]
                    with (
                        patch(
                            "defenseclaw.commands.cmd_setup.platform_support.host_os",
                            return_value="windows",
                        ),
                        patch(
                            "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                            side_effect=refuse,
                        ) as selected,
                        patch(
                            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                            side_effect=forbidden,
                        ) as generic,
                        patch(
                            "defenseclaw.commands.cmd_setup._prompt_and_save_secret",
                            side_effect=forbidden,
                        ) as secret_write,
                        patch(
                            "defenseclaw.commands.cmd_setup._restart_services",
                            side_effect=forbidden,
                        ) as restart,
                    ):
                        result = _invoke(args, self.app, catch=True)

                    self.assertNotEqual(result.exit_code, 0)
                    self.assertIn("exact SST image refused", result.output)
                    selected.assert_called_once()
                    generic.assert_not_called()
                    secret_write.assert_not_called()
                    restart.assert_not_called()
                    save.assert_not_called()
                    self.assertEqual(gc, prior_gc)
                    for path, body in prior_files.items():
                        self.assertEqual(path.read_bytes(), body)

    def test_windows_opencode_interactive_refusal_precedes_judge_secret_path(self):
        gc = self.app.cfg.guardrail
        gc.enabled = False
        gc.connector = "openclaw"
        gc.mode = "observe"
        gc.scanner_mode = "both"
        gc.hilt.enabled = False
        gc.judge.enabled = False
        prior_gc = copy.deepcopy(gc)
        config_path = Path(self.cfg_path)
        secret_path = Path(self.tmp_dir, ".env")
        receipt_path = Path(self.tmp_dir, "agent_selection.json")
        lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
        prior_files = {
            config_path: b"disposable prior config marker\n",
            secret_path: b"disposable secret-file marker\n",
            receipt_path: b'{"prior":"interactive-receipt"}\n',
            lock_path: b'{"prior":"interactive-lock"}\n',
        }
        for path, body in prior_files.items():
            atomic_write_private_bytes(str(path), body)
        forbidden = AssertionError("exact selection refusal must precede interactive policy prompts")

        def refuse(_data_dir, connectors, **_kwargs):
            self.assertEqual(tuple(connectors), ("opencode",))
            self.assertEqual(gc, prior_gc)
            self.assertEqual(config_path.read_bytes(), prior_files[config_path])
            self.assertEqual(secret_path.read_bytes(), prior_files[secret_path])
            atomic_write_private_bytes(str(receipt_path), b"partial receipt\n")
            atomic_write_private_bytes(str(lock_path), b"partial lock\n")
            raise click.ClickException("interactive exact SST selection refused")

        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.commands.cmd_setup._select_connector_interactive",
                return_value="opencode",
            ) as connector_choice,
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=refuse,
            ) as selected,
            patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=forbidden) as confirm,
            patch(
                "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                side_effect=forbidden,
            ) as judge_config,
            patch(
                "defenseclaw.commands.cmd_setup._prompt_and_save_secret",
                side_effect=forbidden,
            ) as secret_write,
        ):
            result = _invoke(
                ["guardrail", "--no-restart", "--no-verify"],
                self.app,
                catch=True,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("interactive exact SST selection refused", result.output)
        connector_choice.assert_called_once()
        selected.assert_called_once()
        confirm.assert_not_called()
        judge_config.assert_not_called()
        secret_write.assert_not_called()
        self.assertEqual(self.app.cfg.guardrail, prior_gc)
        for path, body in prior_files.items():
            self.assertEqual(path.read_bytes(), body)

    def test_windows_opencode_refusal_preserves_absent_config_and_secret_files(self):
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.connector = "opencode"
        gc.mode = "observe"
        prior_gc = copy.deepcopy(gc)
        config_path = Path(self.cfg_path)
        secret_path = Path(self.tmp_dir, ".env")
        receipt_path = Path(self.tmp_dir, "agent_selection.json")
        lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
        self.assertFalse(os.path.lexists(config_path))
        self.assertFalse(os.path.lexists(secret_path))

        def refuse(_data_dir, connectors, **_kwargs):
            self.assertEqual(tuple(connectors), ("opencode",))
            self.assertEqual(gc, prior_gc)
            self.assertFalse(os.path.lexists(config_path))
            self.assertFalse(os.path.lexists(secret_path))
            atomic_write_private_bytes(str(receipt_path), b"partial receipt\n")
            atomic_write_private_bytes(str(lock_path), b"partial lock\n")
            raise click.ClickException("absent-file exact SST selection refused")

        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=refuse,
            ),
        ):
            result = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--mode",
                    "action",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
                catch=True,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(gc, prior_gc)
        for path in (config_path, secret_path, receipt_path, lock_path):
            self.assertFalse(os.path.lexists(path))

    def test_windows_opencode_guardrail_tampered_proof_refuses_without_late_reselection(self):
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.connector = "opencode"
        gc.mode = "observe"
        prior_gc = copy.deepcopy(gc)
        config_path = Path(self.cfg_path)
        receipt_path = Path(self.tmp_dir, "agent_selection.json")
        lock_path = Path(self.tmp_dir, "hook_contract_lock.json")
        prior_files = {
            config_path: b"disposable prior config marker\n",
            receipt_path: b'{"prior":"guardrail-receipt"}\n',
            lock_path: b'{"prior":"guardrail-lock"}\n',
        }
        for path, body in prior_files.items():
            atomic_write_private_bytes(str(path), body)
        apply_options = cmd_setup._apply_guardrail_extra_options

        def apply_then_tamper(*args, **kwargs):
            apply_options(*args, **kwargs)
            atomic_write_private_bytes(
                str(receipt_path),
                receipt_path.read_bytes() + b" ",
            )

        forbidden = AssertionError("tampered proof must refuse before config save")
        save = MagicMock(side_effect=forbidden)
        self.app.cfg.save = save  # type: ignore[assignment]
        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection.record_setup_agent_selections",
                side_effect=record_test_setup_agent_selections,
            ) as selected,
            patch(
                "defenseclaw.commands.cmd_setup._apply_guardrail_extra_options",
                side_effect=apply_then_tamper,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa", return_value=None),
        ):
            result = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--mode",
                    "action",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
                catch=True,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("selection changed before mutation", result.output)
        selected.assert_called_once()
        generic.assert_not_called()
        save.assert_not_called()
        self.assertEqual(self.app.cfg.guardrail, prior_gc)
        for path, body in prior_files.items():
            self.assertEqual(path.read_bytes(), body)

    def test_windows_opencode_guardrail_failure_restores_prior_in_memory_and_files(self):
        self._seed_map("codex", "opencode")
        self.app.cfg.guardrail.enabled = True
        self.app.cfg.guardrail.connectors["opencode"].mode = "observe"
        data_dir = self.app.cfg.data_dir
        receipt_path = os.path.join(data_dir, "agent_selection.json")
        lock_path = os.path.join(data_dir, "hook_contract_lock.json")
        prior_config = b"prior guardrail config\n"
        prior_receipt = b'{"prior":"guardrail-selection"}\n'
        prior_lock = b'{"prior":"guardrail-lock"}\n'
        atomic_write_private_bytes(self.cfg_path, prior_config)
        atomic_write_private_bytes(receipt_path, prior_receipt)
        atomic_write_private_bytes(lock_path, prior_lock)
        prior_roster = tuple(self.app.cfg.active_connectors())
        prior_mode = self.app.cfg.guardrail.effective_mode("opencode")
        forbidden = AssertionError("guardrail selection failure must precede mutation")
        save = MagicMock(side_effect=forbidden)
        self.app.cfg.save = save  # type: ignore[assignment]

        with (
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException("exact SST OpenCode image is missing"),
            ),
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch("defenseclaw.commands.cmd_setup._add_trusted_bin_prefix", side_effect=forbidden) as trust,
            patch("defenseclaw.commands.cmd_setup._restart_services", side_effect=forbidden) as restart,
        ):
            result = _invoke(
                [
                    "guardrail",
                    "--non-interactive",
                    "--connector",
                    "opencode",
                    "--mode",
                    "action",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
                catch=True,
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("exact SST OpenCode image is missing", result.output)
        generic.assert_not_called()
        trust.assert_not_called()
        restart.assert_not_called()
        save.assert_not_called()
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior_roster)
        self.assertEqual(self.app.cfg.guardrail.effective_mode("opencode"), prior_mode)
        for path, payload in (
            (self.cfg_path, prior_config),
            (receipt_path, prior_receipt),
            (lock_path, prior_lock),
        ):
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), payload)

    def test_windows_amp_admission_scan_preserves_prior_copilot_discovery(self):
        signal = SimpleNamespace(
            version="0.0.1785875347-gbc402f",
            installed=True,
            error="",
            binary_path=r"C:\fixture\npm\amp.exe",
        )
        disc = SimpleNamespace(agents={"amp": signal})

        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=disc,
            ) as discover,
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="windows",
            ),
        ):
            accepted = cmd_setup._check_connector_version_supported_for_setup(
                "amp",
                mode="action",
                emit=False,
                data_dir=self.app.cfg.data_dir,
            )

        self.assertTrue(accepted)
        discover.assert_called_once_with(
            use_cache=False,
            refresh=True,
            data_dir=self.app.cfg.data_dir,
            persist_cache=False,
        )

    def test_guardrail_action_fallback_prunes_only_refused_connector_from_judge(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.connectors["codex"].mode = "action"
        gc.connectors["hermes"].mode = "action"
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex", "hermes"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        def version_gate(connector, **_kwargs):
            return connector != "hermes"

        with patch(
            "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
            side_effect=version_gate,
        ):
            ok = cmd_setup._check_guardrail_setup_connector_versions(
                self.app,
                gc,
                explicit_connector=None,
                allow_prompt=False,
            )

        self.assertTrue(ok)
        self.assertEqual(gc.effective_mode("codex"), "action")
        self.assertEqual(gc.effective_mode("hermes"), "observe")
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, ["codex"])


# ---------------------------------------------------------------------------
# SU-06 / SU-07 — interactive mode + judge prompts
# ---------------------------------------------------------------------------
class TestInteractiveModeJudgePrompts(_BaseSetup):
    def test_guardrail_multi_selectors_stay_key_driven_without_vt(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "observe"
        for connector in gc.connectors.values():
            connector.mode = "observe"

        # Action picker: Windows Down, Space, Enter selects Hermes.
        # Judge picker: Enter accepts the empty default.
        keys = iter(["\xe0P", " ", "\r", "\r"])
        confirms = iter([True, False])  # enable guardrail, advanced options
        emitted: list[str] = []

        def record_echo(message: object | None = None, **_kwargs: object) -> None:
            if message is None:
                emitted.append("")
                return
            if not isinstance(message, str):
                raise TypeError(f"unexpected echo message type: {type(message).__name__}")
            emitted.append(message)

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._supports_terminal_redraw", return_value=False), \
                patch("defenseclaw.commands.cmd_setup.click.getchar", side_effect=lambda: next(keys)), \
                patch("defenseclaw.commands.cmd_setup.click.echo", side_effect=record_echo), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=lambda *a, **k: next(confirms)), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch("defenseclaw.commands.cmd_setup._prompt_hook_fail_mode", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._configure_hilt_interactive", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt:
            cmd_setup._interactive_guardrail_setup(self.app, gc)

        self.assertEqual(gc.connectors["codex"].mode, "observe")
        self.assertEqual(gc.connectors["hermes"].mode, "action")
        self.assertFalse(gc.judge.enabled)
        self.assertNotIn("comma-separated", "".join(emitted))
        self.assertTrue(any("Current 2/2: [x] Hermes" in line for line in emitted))
        model_prompt.assert_not_called()

    def test_mode_prompt_selects_action(self):
        # Clean config, interactive: "Configure now?" + judge confirms -> True,
        # mode prompt -> "2" (action).
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="2"), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config"):
            res = _invoke(["codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        # Sole connector (replace shape) -> global mode.
        self.assertEqual(self.app.cfg.guardrail.mode, "action")

    def test_judge_prompt_enables_judge(self):
        confirms = iter([True, True, True])
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=lambda *a, **k: next(confirms)), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="2"), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt:
            res = _invoke(["codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["codex"])
        model_prompt.assert_called_once()

    def test_observe_mode_skips_judge_prompt_and_removes_connector_from_gate(self):
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        confirms = iter([True])
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=lambda *a, **k: next(confirms)), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_enable_judge",
                    side_effect=AssertionError("observe mode should not ask for judge"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                    side_effect=AssertionError("observe mode should not configure judge model"),
                ):
            res = _invoke(["codex", "--no-restart"], self.app)

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertEqual(gc.detection_strategy, "regex_only")

    def test_scoped_guardrail_setup_preserves_unscoped_judge_gate(self):
        targets = ["antigravity", "claudecode", "hermes", "openhands"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "observe"
        for connector in targets:
            gc.connectors[connector].mode = "observe"
        gc.judge.enabled = True
        gc.judge.hook_connectors = list(targets)
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        confirms = iter([True, False])

        def confirm(*_args, **kwargs):
            try:
                return next(confirms)
            except StopIteration:
                return kwargs.get("default", False)

        def accept_defaults(_options, *, default_selected=None, **_kwargs):
            return list(default_selected or [])

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=confirm), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "action"},
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_hook_fail_mode", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._configure_hilt_interactive", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._prompt_checkbox_selection", side_effect=accept_defaults), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt, \
                patch("defenseclaw.commands.cmd_setup._print_connector_info", return_value=None):
            cmd_setup._interactive_guardrail_setup(self.app, gc, agent_name="hermes")

        self.assertEqual(gc.connectors["hermes"].mode, "action")
        self.assertEqual(gc.connectors["antigravity"].mode, "observe")
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, sorted(targets))
        model_prompt.assert_called_once()

    def test_multi_guardrail_setup_action_defaults_ignore_stale_global_mode(self):
        targets = ["antigravity", "claudecode", "geminicli", "hermes", "opencode", "openhands", "windsurf"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "action"
        for connector in targets:
            gc.connectors[connector].mode = "observe"
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["antigravity", "claudecode", "hermes", "openhands"]
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        default_selections: list[list[str]] = []
        confirms = iter([True, False, False])

        def confirm(*_args, **kwargs):
            try:
                return next(confirms)
            except StopIteration:
                return kwargs.get("default", False)

        def checkbox(_options, *, default_selected=None, title="", **_kwargs):
            if title == "Select connector(s) for action enforcement.":
                default_selections.append(list(default_selected or []))
                return []
            return list(default_selected or [])

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", side_effect=confirm), \
                patch("defenseclaw.commands.cmd_setup.click.prompt", return_value="1"), \
                patch("defenseclaw.commands.cmd_setup._prompt_checkbox_selection", side_effect=checkbox), \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config", return_value=None), \
                patch("defenseclaw.commands.cmd_setup._print_connector_info", return_value=None):
            cmd_setup._interactive_guardrail_setup(self.app, gc)

        self.assertEqual(default_selections, [[]])
        for connector in targets:
            self.assertEqual(gc.connectors[connector].mode, "observe")
            self.assertEqual(gc.effective_mode(connector), "observe")
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertEqual(gc.detection_strategy, "regex_only")

    def test_non_interactive_does_not_prompt(self):
        # --yes path: no prompts fire (would error on EOF if they did).
        with _stub_side_effects():
            res = _invoke(["codex", "--yes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        # Default observe, judge untouched (off).
        self.assertEqual(self.app.cfg.guardrail.mode, "observe")
        self.assertFalse(self.app.cfg.guardrail.judge.enabled)


# ---------------------------------------------------------------------------
# SU-08 — trusted-prefix prompt in observe mode
# ---------------------------------------------------------------------------
class TestTrustedPrefixObservePrompt(unittest.TestCase):
    def _run(self, mode):
        signal = SimpleNamespace(
            version="",
            installed=True,
            error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR,
            binary_path="/tmp/fake/hermes-bin",
        )
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="unversioned")
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.sys.stdin, "isatty", return_value=True), \
                patch.object(cmd_setup.sys.stdout, "isatty", return_value=True), \
                patch.object(cmd_setup, "_add_trusted_bin_prefix", return_value=True) as add_mock, \
                patch.object(cmd_setup.click, "confirm", return_value=True) as confirm_mock:
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode=mode)
        return ok, add_mock, confirm_mock

    def test_observe_mode_offers_trusted_prefix_prompt(self):
        ok, add_mock, confirm_mock = self._run("observe")
        # Observe continues regardless, and the prompt fired (the SU-08 fix).
        self.assertTrue(ok)
        self.assertTrue(confirm_mock.called)
        self.assertTrue(add_mock.called)

    def test_action_mode_still_offers_prompt(self):
        _ok, add_mock, confirm_mock = self._run("action")
        self.assertTrue(confirm_mock.called)
        self.assertTrue(add_mock.called)

    def test_noninteractive_observe_suppresses_prompt_but_emits_remediation(self):
        signal = SimpleNamespace(
            version="",
            installed=True,
            error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR,
            binary_path="/tmp/fake/hermes-bin",
        )
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="unversioned")
        hints = []
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.sys.stdin, "isatty", return_value=True), \
                patch.object(cmd_setup.sys.stdout, "isatty", return_value=True), \
                patch.object(cmd_setup, "_add_trusted_bin_prefix", return_value=True) as add_mock, \
                patch.object(cmd_setup.click, "confirm", side_effect=AssertionError("prompted")), \
                patch.object(cmd_setup.ux, "subhead", side_effect=lambda message: hints.append(message)):
            ok = cmd_setup._check_connector_version_supported_for_setup(
                "hermes",
                mode="observe",
                _allow_prompt=False,
            )
        self.assertTrue(ok)
        add_mock.assert_not_called()
        self.assertIn("trusted-paths add", " ".join(hints))


# ---------------------------------------------------------------------------
# SU-09 — single standard not-detected message
# ---------------------------------------------------------------------------
class TestNotDetectedMessage(unittest.TestCase):
    def test_helper_is_single_source(self):
        msg = cmd_setup._connector_not_detected_message("Hermes")
        self.assertIn("not detected locally", msg)
        self.assertIn("Hermes", msg)

    def test_check_emits_helper_message_when_not_installed(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="")
        captured = []
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.ux, "warn", side_effect=lambda m: captured.append(m)):
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode="observe")
        self.assertTrue(ok)
        self.assertIn(cmd_setup._connector_not_detected_message("Hermes"), captured)

    def test_check_refuses_action_when_not_installed(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"hermes": signal})
        captured = []
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup.ux, "err", side_effect=lambda m: captured.append(m)):
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode="action")
        self.assertFalse(ok)
        self.assertIn(
            "Hermes: connector was not detected locally; refusing action-mode hook setup.",
            captured,
        )

    def test_contract_drift_override_allows_action_when_not_installed(self):
        signal = SimpleNamespace(version="", installed=False, error="", binary_path="")
        disc = SimpleNamespace(agents={"hermes": signal})
        contract = SimpleNamespace(status=cmd_setup.STATUS_UNVERSIONED, contract=None, reason="")
        captured = []
        with patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"}), \
                patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch.object(cmd_setup, "resolve_connector_contract", return_value=contract), \
                patch.object(cmd_setup.ux, "warn", side_effect=lambda m: captured.append(m)):
            ok = cmd_setup._check_connector_version_supported_for_setup("hermes", mode="action")
        self.assertTrue(ok)
        self.assertIn(cmd_setup._connector_not_detected_message("Hermes"), captured)


# ---------------------------------------------------------------------------
# SU-10 — option parity / help epilog
# ---------------------------------------------------------------------------
class TestHelpParity(unittest.TestCase):
    def _help(self, args):
        return CliRunner().invoke(setup_group, args, catch_exceptions=False).output

    def test_codex_help_exposes_judge_hilt_block_fail_options(self):
        out = self._help(["codex", "--help"])
        for opt in ("--enable-judge", "--judge-hook-connectors", "--human-approval", "--hilt-min-severity", "--block-message", "--fail-mode"):
            self.assertIn(opt, out, msg=f"{opt} missing from `setup codex --help`")

    def test_factory_connector_help_exposes_options(self):
        out = self._help(["hermes", "--help"])
        self.assertIn("--enable-judge", out)
        self.assertIn("--block-message", out)

    def test_help_epilog_mentions_proxy_distinction(self):
        out = self._help(["codex", "--help"])
        self.assertIn("proxy", out.lower())

    def test_codex_help_reports_exact_versioned_event_tiers(self):
        out = self._help(["codex", "--help"])
        self.assertIn("0.133-0.144", out)
        self.assertIn("eleven from 0.145", out)
        self.assertIn("SessionEnd", out)
        self.assertNotIn("ten on 0.133+", out)


# ---------------------------------------------------------------------------
# SU-11 — bare `setup` picker + scripting flags
# ---------------------------------------------------------------------------
class TestBareSetupBatch(_BaseSetup):
    def test_detected_connectors_require_installed_application_signal(self):
        disc = SimpleNamespace(
            agents={
                "hermes": SimpleNamespace(installed=False, configured=True),
                "cursor": SimpleNamespace(installed=True, configured=False),
            }
        )
        with patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc) as discover:
            detected = cmd_setup._detect_installed_connectors()

        self.assertEqual(detected, ["cursor"])
        discover.assert_called_once_with(use_cache=False)

    def test_scripting_flags_configure_multiple(self):
        with _stub_side_effects():
            res = _invoke(["-c", "hermes", "-c", "codex", "--mode", "action", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"hermes", "codex"})
        self.assertEqual(gc.connectors["hermes"].mode, "action")

    def test_batch_no_restart_allows_explicit_offline_staging(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with _stub_side_effects():
            res = _invoke(["-c", "codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("canonical setup audit event was not recorded", res.output)

    def test_batch_default_restart_does_not_inherit_internal_offline_mode(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with _stub_side_effects(), self.assertRaises(CanonicalObservabilityUnavailableError):
            _invoke(["-c", "codex"], self.app)

    def test_detected_filters_to_hook_connectors(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._detect_installed_connectors", return_value=["hermes", "openclaw"]):
            res = _invoke(["--detected", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"hermes"})

    def test_all_selects_every_hook_connector(self):
        with _stub_side_effects():
            res = _invoke(["--all", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        expected = cmd_setup.platform_support.supported_connectors(
            cmd_setup._HOOK_ENFORCED_CONNECTORS
        )
        self.assertEqual(set(self.app.cfg.guardrail.connectors), set(expected))

    def test_invalid_connector_flag_errors(self):
        with _stub_side_effects():
            res = _invoke(["-c", "not-a-real-connector", "--no-restart"], self.app, catch=True)
        self.assertNotEqual(res.exit_code, 0)

    def test_bare_non_tty_prints_help(self):
        with _stub_side_effects(), patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=False):
            res = _invoke([], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("Configure DefenseClaw components", res.output)
        self.assertEqual(self.app.cfg.guardrail.connectors, {})

    def test_picker_applies_selection(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch("defenseclaw.commands.cmd_setup._detect_installed_connectors", return_value=["hermes"]), \
                patch("defenseclaw.commands.cmd_setup._supports_terminal_redraw", return_value=False), \
                patch("defenseclaw.commands.cmd_setup.click.getchar", return_value="\n"):
            res = _invoke(["--yes"], self.app)
        # --yes => no mode/judge prompts, but bare setup still needs the
        # connector picker. Enter accepts the detected default selection.
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertNotIn("comma-separated", res.output)
        self.assertEqual(len(self.app.cfg.guardrail.connectors), 1)
        self.assertIn("hermes", self.app.cfg.guardrail.connectors)

    def test_picker_preselects_active_not_detected_inactive_connectors(self):
        self._seed_map("hermes", "windsurf")
        captured = {}

        def choose(options, *, default_selected, title, empty_ok):
            captured["options"] = options
            captured["default_selected"] = default_selected
            return default_selected

        with patch(
            "defenseclaw.commands.cmd_setup._detect_installed_connectors",
            return_value=["cursor"],
        ), patch(
            "defenseclaw.commands.cmd_setup._prompt_checkbox_selection",
            side_effect=choose,
        ), patch("defenseclaw.commands.cmd_setup.ux.subhead") as subhead:
            selected = cmd_setup._run_setup_picker(self.app)

        self.assertEqual(set(selected), {"hermes", "windsurf"})
        cursor_option = next(option for option in captured["options"] if "Cursor" in option)
        self.assertNotIn(cursor_option, captured["default_selected"])
        subhead.assert_any_call(
            "Active connectors are pre-selected. Detected inactive connectors remain unchecked."
        )

    def test_batch_prompts_trusted_prefix_before_judge_picker(self):
        signal = SimpleNamespace(
            version="",
            installed=True,
            error=cmd_setup.agent_discovery.UNTRUSTED_PREFIX_ERROR,
            binary_path="/tmp/fake/hermes-bin",
        )
        disc = SimpleNamespace(agents={"hermes": signal})

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "action"},
                ), \
                patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc), \
                patch("defenseclaw.commands.cmd_setup._add_trusted_bin_prefix") as add_mock, \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=lambda targets, gc: self.assertTrue(add_mock.called) or set(),
                ):
            res = _invoke(["-c", "hermes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        add_mock.assert_called_once()

    def test_batch_action_refusal_downgrades_saved_mode_to_observe(self):
        def version_gate(connector, *, mode="observe", **_kwargs):
            return (mode or "").strip().lower() != "action"

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"geminicli": "action", "windsurf": "action"},
                )
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}))
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    return_value=set(),
                )
            )
            stack.enter_context(
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    side_effect=version_gate,
                )
            )
            res = _invoke(
                ["-c", "geminicli", "-c", "windsurf", "--no-restart"],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("Gemini CLI: requested action mode was refused", res.output)
        self.assertIn("Devin Desktop — legacy Cascade: requested action mode was refused", res.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.effective_mode("geminicli"), "observe")
        self.assertEqual(gc.effective_mode("windsurf"), "observe")
        self.assertEqual(gc.connectors["geminicli"].mode, "observe")
        self.assertEqual(gc.connectors["windsurf"].mode, "observe")

    def test_interactive_batch_selects_judge_connectors_without_strategy_prompt(self):
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]

        def choose_codex(targets, gc_arg):
            self.assertEqual(targets, ["codex"])
            cmd_setup._merge_batch_judge_selection(gc_arg, targets, {"codex"})
            return {"codex"}

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "observe", "codex": "action"},
                ) as mode_picker, \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                    side_effect=AssertionError("bare setup should not ask for scan strategy"),
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=choose_codex,
                ) as judge_picker, \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=False) as confirm_mock, \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                    side_effect=AssertionError("model prompt should be skipped when declined"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_connector_mode",
                    side_effect=AssertionError("per-connector mode prompt should not run"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_enable_judge",
                    side_effect=AssertionError("per-connector judge prompt should not run"),
                ):
            res = _invoke(["-c", "hermes", "-c", "codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        mode_picker.assert_called_once()
        judge_picker.assert_called_once()
        confirm_mock.assert_called_once()
        self.assertEqual(gc.connectors["hermes"].mode, "observe")
        self.assertEqual(gc.connectors["codex"].mode, "action")
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")
        self.assertEqual(gc.judge.hook_connectors, ["codex"])

    def test_batch_judge_selection_drops_unselected_existing_connectors(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "observe"},
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=AssertionError("judge picker should be skipped without action connectors"),
                ) as judge_picker, \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=False):
            res = _invoke(["-c", "hermes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        judge_picker.assert_not_called()
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertNotIn("codex", gc.judge.hook_connectors)

    def test_scoped_judge_selection_preserves_outside_existing_gate(self):
        targets = ["antigravity", "claudecode", "hermes", "openhands"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = list(targets)
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        cmd_setup._merge_batch_judge_selection(
            gc,
            ["hermes"],
            {"hermes"},
            preserve_outside_targets=True,
        )

        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, sorted(targets))
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")

    def test_scoped_judge_selection_removes_only_unchecked_target(self):
        targets = ["antigravity", "claudecode", "hermes", "openhands"]
        self._seed_map(*targets)
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = list(targets)
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        cmd_setup._merge_batch_judge_selection(
            gc,
            ["hermes"],
            set(),
            preserve_outside_targets=True,
        )

        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, ["antigravity", "claudecode", "openhands"])
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")

    def test_scoped_judge_selection_preserves_wildcard_when_target_checked(self):
        self._seed_map("antigravity", "claudecode", "hermes", "openhands")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["*"]

        cmd_setup._merge_batch_judge_selection(
            gc,
            ["hermes"],
            {"hermes"},
            preserve_outside_targets=True,
        )

        self.assertEqual(gc.judge.hook_connectors, ["*"])

    def test_batch_setup_reconciles_active_connectors_to_selected_set(self):
        self._seed_map("codex", "hermes")
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["codex", "hermes"]

        with _stub_side_effects():
            res = _invoke(
                ["-c", "hermes", "--yes", "--no-restart", "--mode", "action"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(sorted(gc.connectors), ["hermes"])
        self.assertEqual(gc.connector, "hermes")
        self.assertEqual(self.app.cfg.claw.mode, "hermes")
        self.assertEqual(gc.judge.hook_connectors, ["hermes"])

    def test_batch_setup_does_not_seed_unselected_legacy_single_connector(self):
        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        self.app.cfg.claw.mode = "codex"
        gc.connectors = {}

        with _stub_side_effects():
            res = _invoke(["-c", "hermes", "--yes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(sorted(gc.connectors), ["hermes"])
        self.assertNotIn("codex", gc.connectors)
        self.assertEqual(gc.connector, "hermes")

    def test_empty_batch_judge_selection_skips_model_and_uses_regex_only(self):
        gc = self.app.cfg.guardrail
        gc.judge.enabled = True
        gc.judge.hook_connectors = ["hermes"]

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "observe", "codex": "observe"},
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                    side_effect=AssertionError("bare setup should not ask for scan strategy"),
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=AssertionError("judge picker should be skipped without action connectors"),
                ) as judge_picker, \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_judge_model_config",
                    side_effect=AssertionError("judge model prompt should not run with no judge connectors"),
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup.click.confirm",
                    side_effect=AssertionError("judge model confirm should not run with no judge connectors"),
                ):
            res = _invoke(["-c", "hermes", "-c", "codex", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        judge_picker.assert_not_called()
        self.assertFalse(gc.judge.enabled)
        self.assertEqual(gc.detection_strategy, "regex_only")
        self.assertEqual(gc.detection_strategy_completion, "regex_only")
        self.assertEqual(gc.judge.hook_connectors, [])

    def test_batch_judge_selection_can_configure_model(self):
        def choose_hermes(targets, gc_arg):
            cmd_setup._merge_batch_judge_selection(gc_arg, targets, {"hermes"})
            return {"hermes"}

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup._is_interactive", return_value=True), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_connector_modes",
                    return_value={"hermes": "action"},
                ), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_scan_strategy",
                    side_effect=AssertionError("bare setup should not ask for scan strategy"),
                ), \
                patch("defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes", return_value={}), \
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_judge_connectors",
                    side_effect=choose_hermes,
                ), \
                patch("defenseclaw.commands.cmd_setup.click.confirm", return_value=True) as confirm_mock, \
                patch("defenseclaw.commands.cmd_setup._prompt_judge_model_config") as model_prompt:
            res = _invoke(["-c", "hermes", "--no-restart"], self.app)
        self.assertEqual(res.exit_code, 0, msg=res.output)
        confirm_mock.assert_called_once()
        model_prompt.assert_called_once()
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["hermes"])

    def test_flags_ignored_with_subcommand_warns(self):
        with _stub_side_effects(), patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=(), retention_days=0, plan_digest="test"),
        ):
            res = _invoke(["-c", "hermes", "observability", "list"], self.app)
        self.assertIn("are ignored when a setup", res.output)


# ---------------------------------------------------------------------------
# ND-3 — setup mode removal
# ---------------------------------------------------------------------------
class TestSetupModeHelp(unittest.TestCase):
    def test_mode_subcommand_is_removed(self):
        res = CliRunner().invoke(setup_group, ["mode", "--help"])
        self.assertNotEqual(res.exit_code, 0)
        self.assertIn("No such command 'mode'", res.output)

    def test_setup_help_keeps_enforcement_mode_flag(self):
        out = CliRunner().invoke(setup_group, ["--help"], catch_exceptions=False).output
        self.assertIn("--mode [observe|action]", out)
        self.assertNotIn("setup mode", out)


# ---------------------------------------------------------------------------
# J3 — per-direction detection-strategy flags (opt-in, off by default)
# ---------------------------------------------------------------------------
class TestJ3PerDirectionStrategy(_BaseSetup):
    def test_help_exposes_per_direction_flags(self):
        out = CliRunner().invoke(setup_group, ["guardrail", "--help"], catch_exceptions=False).output
        for opt in ("--detection-strategy-prompt", "--detection-strategy-completion", "--detection-strategy-tool-call"):
            self.assertIn(opt, out)

    def test_completion_flag_writes_field(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify",
                    "--detection-strategy-completion", "regex_judge",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_judge")

    def test_judge_strategy_flag_enables_judge_with_all_hook_coverage(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify",
                    "--mode", "action",
                    "--detection-strategy", "regex_judge",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["*"])

    def test_scoped_mode_update_preserves_empty_judge_gate(self):
        self._seed_map("antigravity", "hermes", "opencode")
        gc = self.app.cfg.guardrail
        gc.enabled = True
        gc.mode = "observe"
        gc.connectors["antigravity"].mode = "observe"
        gc.connectors["hermes"].mode = "action"
        gc.connectors["opencode"].mode = "action"
        gc.judge.enabled = True
        gc.judge.hook_connectors = []
        gc.detection_strategy = "regex_judge"
        gc.detection_strategy_completion = "regex_judge"

        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "hermes",
                    "--mode", "observe", "--no-restart", "--no-verify",
                ],
                self.app,
            )

        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertEqual(gc.effective_mode("antigravity"), "observe")
        self.assertEqual(gc.effective_mode("hermes"), "observe")
        self.assertEqual(gc.effective_mode("opencode"), "action")
        self.assertEqual(sorted(gc.connectors), ["antigravity", "hermes", "opencode"])
        self.assertTrue(gc.judge.enabled)
        self.assertEqual(gc.judge.hook_connectors, [])
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")

    def test_explicit_completion_regex_only_preserved_when_judge_enabled(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                [
                    "guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify",
                    "--mode", "action",
                    "--detection-strategy", "regex_judge",
                    "--detection-strategy-completion", "regex_only",
                ],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(self.app.cfg.guardrail.judge.enabled)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_completion, "regex_only")
        self.assertEqual(self.app.cfg.guardrail.judge.hook_connectors, ["*"])

    def test_off_by_default_tool_call_unset(self):
        with _stub_side_effects(), \
                patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
            res = _invoke(
                ["guardrail", "--non-interactive", "--connector", "codex", "--no-restart", "--no-verify"],
                self.app,
            )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        # Never written unless the operator opts in.
        self.assertEqual(self.app.cfg.guardrail.detection_strategy_tool_call, "")


if __name__ == "__main__":
    unittest.main()
