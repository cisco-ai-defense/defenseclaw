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

"""WU7 tests: additive multi-connector ``setup`` behavior.

``setup <connector>`` can now ADD a hook connector to
``guardrail.connectors`` alongside the existing one(s) instead of always
overwriting ``guardrail.connector``. These tests pin the WU7 decisions:

* D1 — three-choice interactive prompt (Add / Replace / Cancel) when
  another HOOK connector is already configured.
* D2 — adding seeds the map with both the existing and new connector and
  keeps ``guardrail.connector`` / ``claw.mode`` pointing at the sorted-
  first primary as a backward-compat mirror.
* D3 — the ``--yes`` non-interactive default is ADD (backward-incompatible);
  ``--replace`` forces overwrite.
* D4 — only hook-enforced connectors are additive peers; an existing
  proxy connector (openclaw/zeptoclaw) is replaced, never added to.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shlex
import sys
import unittest
from dataclasses import replace
from unittest.mock import MagicMock, patch

import click
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host
from defenseclaw.agent_selection import SetupAgentSelection
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_doctor import _omnigent_setup_repair_command
from defenseclaw.commands.cmd_setup import (
    _configured_connector_set,
    _print_observability_summary,
    _write_connector_identity,
)
from defenseclaw.commands.cmd_setup import (
    setup as setup_group,
)
from defenseclaw.config import HILTConfig, PerConnectorGuardrailConfig, load
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError

from tests.helpers import cleanup_app, make_app_context, record_test_setup_agent_selections


def _invoke(args, app):
    runner = CliRunner()
    return runner.invoke(setup_group, args, obj=app, catch_exceptions=False)


@contextlib.contextmanager
def _setup_patches(prompt=None):
    """Stub the heavyweight side effects so the command runs in CI.

    When *prompt* is given, the interactive three-choice ``click.prompt`` is
    patched to return it ("a"/"r"/"c").
    """
    with contextlib.ExitStack() as stack:
        runtime_captures = 0

        def capture_runtime(*_args, **_kwargs):
            nonlocal runtime_captures
            runtime_captures += 1
            return cmd_setup._SetupAppliedRuntimeEvidence(
                lifecycle="running",
                generation="generation-before" if runtime_captures == 1 else "generation-after",
                invariants=(),
            )

        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                side_effect=capture_runtime,
            )
        )
        restart = stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            )
        )
        if prompt is not None:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup.click.prompt", return_value=prompt))
        yield restart


class TestAdditiveSetupCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        self.app.cfg.save = lambda: atomic_write_private_bytes(  # type: ignore[assignment]
            self.cfg_path, b"x\n"
        )

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _seed_single(self, connector):
        self.app.cfg.claw.mode = connector
        self.app.cfg.guardrail.connector = connector
        self.app.cfg.guardrail.connectors = {}

    def _seed_map(self, *connectors):
        self.app.cfg.guardrail.connectors = {c: PerConnectorGuardrailConfig() for c in connectors}
        self.app.cfg.guardrail.connector = sorted(connectors)[0]
        self.app.cfg.claw.mode = sorted(connectors)[0]

    # D3: --yes defaults to ADD when another hook connector is configured.
    def test_yes_adds_alongside_existing_hook_connector(self):
        self._seed_single("codex")
        with _setup_patches():
            result = _invoke(["cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"codex", "cursor"})
        # Primary mirror is the sorted-first connector (D2).
        self.assertEqual(gc.connector, "codex")
        self.assertEqual(self.app.cfg.claw.mode, "codex")
        self.assertEqual(self.app.cfg.active_connectors(), ["codex", "cursor"])

    def test_cursor_action_preserves_peer_connector_modes(self):
        self.app.cfg.guardrail.connectors = {
            "claudecode": PerConnectorGuardrailConfig(mode="action", hook_fail_mode="closed"),
            "codex": PerConnectorGuardrailConfig(mode="observe", hook_fail_mode="open"),
        }
        self.app.cfg.guardrail.connector = "claudecode"
        self.app.cfg.claw.mode = "claudecode"

        with _setup_patches():
            result = _invoke(
                ["cursor", "--yes", "--mode", "action", "--no-human-approval", "--no-restart"],
                self.app,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"claudecode", "codex", "cursor"})
        self.assertEqual(gc.connectors["claudecode"].mode, "action")
        self.assertEqual(gc.connectors["claudecode"].hook_fail_mode, "closed")
        self.assertEqual(gc.connectors["codex"].mode, "observe")
        self.assertEqual(gc.connectors["codex"].hook_fail_mode, "open")
        self.assertEqual(gc.connectors["cursor"].mode, "action")
        self.assertEqual(gc.connectors["cursor"].hook_fail_mode, "closed")
        self.assertFalse(gc.connectors["cursor"].hilt.enabled)
        self.assertIn("cursor hook failures=closed (failClosed=true)", result.output)

    def test_later_setup_revalidates_every_active_connector_before_success(self):
        self._seed_single("codex")
        with _setup_patches() as restart:
            result = _invoke(["cursor", "--yes"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart.assert_called_once_with(
            self.app.cfg.data_dir,
            self.app.cfg.gateway.host,
            self.app.cfg.gateway.port,
            connector="cursor",
            connectors=["codex", "cursor"],
            wait_for_connector_ready=True,
        )

    def test_bare_batch_restart_waits_for_every_active_connector(self):
        self._seed_map("codex", "cursor")
        with (
            _setup_patches() as restart,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=False),
        ):
            result = _invoke(["-c", "codex", "-c", "cursor", "--yes"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart.assert_called_once_with(
            self.app.cfg.data_dir,
            self.app.cfg.gateway.host,
            self.app.cfg.gateway.port,
            connector="codex",
            connectors=["codex", "cursor"],
            wait_for_connector_ready=True,
            start_if_stopped=True,
        )

    def test_bare_batch_cannot_report_success_when_readiness_gate_fails(self):
        self._seed_map("codex", "cursor")
        with (
            _setup_patches() as restart,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=False),
        ):
            restart.side_effect = click.ClickException("connector runtime readiness failed")
            result = _invoke(["-c", "codex", "-c", "cursor", "--yes"], self.app)
        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("connector runtime readiness failed", result.output)

    def test_bare_batch_readiness_failure_restores_prior_single_active_roster(self):
        self._seed_single("claudecode")
        prior = tuple(self.app.cfg.active_connectors())
        with (
            _setup_patches() as restart,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=False),
        ):
            restart.side_effect = [click.ClickException("connector runtime readiness failed"), None]
            result = _invoke(["-c", "codex", "-c", "opencode", "--yes"], self.app)

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("restored the prior connector configuration and runtime", result.output)
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior)
        self.assertEqual(self.app.cfg.guardrail.connector, "claudecode")
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(restart.call_args_list[1].kwargs["connectors"], ["claudecode"])

    def test_replace_readiness_failure_restores_prior_connector_set(self):
        self._seed_map("claudecode", "codex")
        prior = tuple(self.app.cfg.active_connectors())
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=cmd_setup._SetupAppliedRuntimeEvidence(
                lifecycle="running",
                generation="snapshot-before",
                invariants=(),
            ),
        )
        with (
            _setup_patches() as restart,
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_config_snapshot",
                return_value=snapshot,
            ),
        ):
            restart.side_effect = [click.ClickException("replacement readiness failed"), None]
            result = _invoke(["cursor", "--yes", "--replace"], self.app)

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("restored the prior connector configuration and runtime", result.output)
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior)
        self.assertEqual(restart.call_count, 2)

    def test_later_opencode_failure_restores_exact_merged_selection_and_prior_runtime(self):
        self._seed_single("codex")
        data_dir = self.app.cfg.data_dir
        selection_path = os.path.join(data_dir, "agent_selection.json")
        lock_path = os.path.join(data_dir, "hook_contract_lock.json")
        runtime_path = os.path.join(data_dir, "hooks", "prior-posture.json")
        prior_selection = (
            b'{"schema_version":1,"selections":{'
            b'"codex":{"executable":"prior-codex"},'
            b'"hermes":{"executable":"prior-hermes"}}}\n'
        )
        prior_lock = b'{"version":2,"connectors":{"codex":{"hook_fail_mode":"open"}}}\n'
        prior_runtime = b'{"connector":"codex","hook_fail_mode":"open"}\n'
        atomic_write_private_bytes(selection_path, prior_selection)
        atomic_write_private_bytes(lock_path, prior_lock)
        atomic_write_private_bytes(runtime_path, prior_runtime)

        def _record(data_dir_arg, connectors):
            self.assertEqual(tuple(connectors), ("codex", "opencode"))
            return record_test_setup_agent_selections(data_dir_arg, connectors)

        restart_attempt = 0

        def _restart(*_args, **kwargs):
            nonlocal restart_attempt
            restart_attempt += 1
            if restart_attempt == 1:
                self.assertIn("opencode", kwargs["connectors"])
                atomic_write_private_bytes(
                    lock_path,
                    b'{"version":2,"connectors":{"codex":{"hook_fail_mode":"closed"},"opencode":{}}}\n',
                )
                atomic_write_private_bytes(
                    runtime_path,
                    b'{"connector":"codex","hook_fail_mode":"closed","opencode":"applied"}\n',
                )
                raise click.ClickException("OpenCode active roster publication failed")
            self.assertEqual(kwargs["connectors"], ["codex"])
            atomic_write_private_bytes(lock_path, prior_lock)
            atomic_write_private_bytes(runtime_path, prior_runtime)

        with (
            _setup_patches() as restart,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=False),
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch("defenseclaw.agent_selection.record_setup_agent_selections", side_effect=_record),
        ):
            restart.side_effect = _restart
            result = _invoke(["-c", "codex", "-c", "opencode", "--yes"], self.app)

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("restored the prior connector configuration and runtime", result.output)
        self.assertEqual(tuple(self.app.cfg.active_connectors()), ("codex",))
        with open(selection_path, "rb") as handle:
            self.assertEqual(handle.read(), prior_selection)
        with open(lock_path, "rb") as handle:
            self.assertEqual(handle.read(), prior_lock)
        with open(runtime_path, "rb") as handle:
            self.assertEqual(handle.read(), prior_runtime)
        self.assertEqual(restart.call_count, 2)

    def test_windows_opencode_batch_selects_before_trust_prompt_and_ignores_generic_decoy(self):
        events: list[str] = []
        original_save = self.app.cfg.save

        def save():
            events.append("save")
            original_save()

        def select(_data_dir, connectors):
            events.append("select-exact-1.18.11")
            self.assertEqual(tuple(connectors), ("opencode",))
            return record_test_setup_agent_selections(_data_dir, connectors)

        def prompt(_app, connector_modes):
            events.append("generic-trust-prompt")
            self.assertEqual(connector_modes, {"opencode": "action"})
            return {}

        self.app.cfg.save = save  # type: ignore[assignment]
        ctx = click.Context(setup_group, obj=self.app)
        forbidden = AssertionError("PATH/configured OpenCode 1.18.12 cannot authorize the exact image")
        with (
            ctx,
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection.record_setup_agent_selections",
                side_effect=select,
            ) as selected,
            patch(
                "defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes",
                side_effect=prompt,
            ) as trusted,
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa", return_value=None),
        ):
            cmd_setup._apply_setup_batch(
                ctx,
                self.app,
                ["opencode"],
                mode="action",
                restart=False,
                prompt_per_connector=False,
                connector_modes={"opencode": "action"},
                allow_trusted_path_prompt=True,
            )

        self.assertEqual(events[0], "select-exact-1.18.11")
        self.assertLess(events.index("select-exact-1.18.11"), events.index("generic-trust-prompt"))
        self.assertLess(events.index("select-exact-1.18.11"), events.index("save"))
        selected.assert_called_once()
        trusted.assert_called_once()
        generic.assert_not_called()
        self.assertEqual(self.app.cfg.guardrail.effective_mode("opencode"), "action")

    def test_windows_opencode_batch_exact_failure_precedes_all_generic_and_state_mutation(self):
        self._seed_map("codex", "hermes")
        data_dir = self.app.cfg.data_dir
        config_path = self.cfg_path
        receipt_path = os.path.join(data_dir, "agent_selection.json")
        lock_path = os.path.join(data_dir, "hook_contract_lock.json")
        prior_config = b"prior batch config\n"
        prior_receipt = b'{"prior":"batch-selection"}\n'
        prior_lock = b'{"prior":"batch-lock"}\n'
        atomic_write_private_bytes(config_path, prior_config)
        atomic_write_private_bytes(receipt_path, prior_receipt)
        atomic_write_private_bytes(lock_path, prior_lock)
        prior_roster = tuple(self.app.cfg.active_connectors())
        forbidden = AssertionError("exact selection failure must stop the batch")
        save = MagicMock(side_effect=forbidden)
        self.app.cfg.save = save  # type: ignore[assignment]
        ctx = click.Context(setup_group, obj=self.app)

        with (
            ctx,
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                side_effect=click.ClickException(
                    "exact SST OpenCode 1.18.12 rejected; PATH OpenCode 1.18.11 is not authority"
                ),
            ),
            patch(
                "defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes",
                side_effect=forbidden,
            ) as trusted,
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=forbidden,
            ) as generic,
            patch(
                "defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa",
                return_value=None,
            ) as hilt_sync,
            self.assertRaisesRegex(click.ClickException, "exact SST OpenCode 1.18.12"),
        ):
            cmd_setup._apply_setup_batch(
                ctx,
                self.app,
                ["opencode"],
                mode="observe",
                restart=False,
                prompt_per_connector=False,
                connector_modes={"opencode": "observe"},
                allow_trusted_path_prompt=True,
            )

        trusted.assert_not_called()
        generic.assert_not_called()
        hilt_sync.assert_not_called()
        save.assert_not_called()
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior_roster)
        for path, payload in (
            (config_path, prior_config),
            (receipt_path, prior_receipt),
            (lock_path, prior_lock),
        ):
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), payload)

    def test_windows_opencode_batch_tampered_proof_reselects_complete_roster(self):
        self._seed_single("amp")
        data_dir = self.app.cfg.data_dir
        receipt_path = os.path.join(data_dir, "agent_selection.json")
        with patch(
            "defenseclaw.commands.cmd_setup.platform_support.host_os",
            return_value="windows",
        ):
            before_selection = cmd_setup._capture_setup_config_snapshot(self.app.cfg)
            records, errors = record_test_setup_agent_selections(
                data_dir,
                ("amp", "opencode"),
            )
            self.assertEqual(errors, {})
            proof = cmd_setup._validate_setup_agent_selection_receipt(
                data_dir,
                ("amp", "opencode"),
                records,
                prior_generation=before_selection.agent_selection_generation,
            )
            with open(receipt_path, "rb") as handle:
                tampered = handle.read() + b" "
            atomic_write_private_bytes(receipt_path, tampered)
            ctx = click.Context(setup_group, obj=self.app)
            forbidden = AssertionError("tampered proof must fail before generic discovery")
            with (
                ctx,
                patch(
                    "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
                    side_effect=click.ClickException("fresh complete roster required"),
                ) as reselect,
                patch(
                    "defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes",
                    side_effect=forbidden,
                ) as trusted,
                patch(
                    "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                    side_effect=forbidden,
                ) as generic,
                self.assertRaisesRegex(click.ClickException, "complete roster required"),
            ):
                cmd_setup._apply_setup_batch(
                    ctx,
                    self.app,
                    ["amp", "opencode"],
                    mode="observe",
                    restart=False,
                    prompt_per_connector=False,
                    connector_modes={"amp": "observe", "opencode": "action"},
                    allow_trusted_path_prompt=True,
                    _protected_selection=proof,
                )

        reselect.assert_called_once()
        self.assertEqual(reselect.call_args.args[1], ("amp", "opencode"))
        trusted.assert_not_called()
        generic.assert_not_called()
        with open(receipt_path, "rb") as handle:
            self.assertEqual(handle.read(), tampered)

    def test_windows_opencode_batch_prompt_abort_restores_exact_prior_state(self):
        self._seed_map("codex", "hermes")
        data_dir = self.app.cfg.data_dir
        config_path = self.cfg_path
        receipt_path = os.path.join(data_dir, "agent_selection.json")
        lock_path = os.path.join(data_dir, "hook_contract_lock.json")
        prior_config = b"prior prompt config\n"
        prior_receipt = b'{"prior":"prompt-selection"}\n'
        prior_lock = b'{"prior":"prompt-lock"}\n'
        atomic_write_private_bytes(config_path, prior_config)
        atomic_write_private_bytes(receipt_path, prior_receipt)
        atomic_write_private_bytes(lock_path, prior_lock)
        prior_roster = tuple(self.app.cfg.active_connectors())

        def select(_data_dir, _connectors):
            return record_test_setup_agent_selections(_data_dir, _connectors)

        def abort_prompt(_app, _connector_modes):
            self.app.cfg.guardrail.mode = "action"
            self.app.cfg.save()
            raise click.Abort()

        ctx = click.Context(setup_group, obj=self.app)
        with (
            ctx,
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection.record_setup_agent_selections",
                side_effect=select,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._prompt_batch_trusted_prefixes",
                side_effect=abort_prompt,
            ),
            self.assertRaises(click.Abort),
        ):
            cmd_setup._apply_setup_batch(
                ctx,
                self.app,
                ["opencode"],
                mode="observe",
                restart=False,
                prompt_per_connector=False,
                connector_modes={"opencode": "observe"},
                allow_trusted_path_prompt=True,
            )

        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior_roster)
        for path, payload in (
            (config_path, prior_config),
            (receipt_path, prior_receipt),
            (lock_path, prior_lock),
        ):
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), payload)

    def test_direct_opencode_rollback_restores_exact_prior_persistence_before_prior_readiness(self):
        # Exercise the real v8 config merge writer. A mocked ``save`` cannot
        # reproduce the rollback defect where the restored object's modeled
        # baseline matches its prior-four state while config.yaml still holds
        # the newly staged five-connector generation.
        del self.app.cfg.save
        prior_connectors = ("claudecode", "codex", "cursor", "omnigent")
        self._seed_map(*prior_connectors)
        self.app.cfg.guardrail.connectors["cursor"].mode = "action"
        self.app.cfg.guardrail.connectors["cursor"].hook_fail_mode = "closed"
        self.app.cfg.save()

        data_dir = self.app.cfg.data_dir
        config_path = os.path.join(data_dir, "config.yaml")
        hint_path = os.path.join(data_dir, "picked_connector")
        selection_path = os.path.join(data_dir, "agent_selection.json")
        prior_hint = b"cursor\n"
        prior_selection = (
            b'{"schema_version":1,"selections":{'
            b'"claudecode":{"executable":"prior-claude"},'
            b'"codex":{"executable":"prior-codex"},'
            b'"omnigent":{"executable":"prior-omnigent"}}}\n'
        )
        atomic_write_private_bytes(hint_path, prior_hint)
        atomic_write_private_bytes(selection_path, prior_selection)
        with open(config_path, "rb") as handle:
            prior_config = handle.read()

        restart_attempt = 0

        def _restart(*_args, **kwargs):
            nonlocal restart_attempt
            restart_attempt += 1
            if restart_attempt == 1:
                self.assertEqual(set(kwargs["connectors"]), {*prior_connectors, "opencode"})
                self.assertIn("opencode", load(data_dir=data_dir).active_connectors())
                raise click.ClickException("requested five-connector readiness failed")
            self.assertEqual(set(kwargs["connectors"]), set(prior_connectors))
            self.assertEqual(tuple(load(data_dir=data_dir).active_connectors()), prior_connectors)
            with open(config_path, "rb") as handle:
                self.assertEqual(handle.read(), prior_config)
            with open(hint_path, "rb") as handle:
                self.assertEqual(handle.read(), prior_hint)
            with open(selection_path, "rb") as handle:
                self.assertEqual(handle.read(), prior_selection)
            raise click.ClickException("prior four-connector readiness failed")

        with _setup_patches() as restart:
            restart.side_effect = _restart
            result = _invoke(
                ["opencode", "--yes", "--mode", "action", "--no-human-approval"],
                self.app,
            )

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("rollback was incomplete", result.output)
        self.assertIn("prior four-connector readiness failed", result.output)
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior_connectors)
        with open(config_path, "rb") as handle:
            self.assertEqual(handle.read(), prior_config)
        with open(hint_path, "rb") as handle:
            self.assertEqual(handle.read(), prior_hint)
        with open(selection_path, "rb") as handle:
            self.assertEqual(handle.read(), prior_selection)
        self.assertEqual(restart.call_count, 2)

    def test_successful_batch_records_complete_codex_and_hermes_selection_receipt(self):
        self._seed_single("codex")
        selection_path = os.path.join(self.app.cfg.data_dir, "agent_selection.json")
        atomic_write_private_bytes(
            selection_path,
            b'{"schema_version":1,"selections":{"omnigent":{"executable":"stale"}}}\n',
        )
        selected = {
            "codex": SetupAgentSelection(
                connector="codex",
                executable=os.path.abspath(os.path.join(self.tmp_dir, "codex.exe")),
                raw_version="codex 0.144.3",
                normalized_version="0.144.3",
                sha256="a" * 64,
            ),
            "hermes": SetupAgentSelection(
                connector="hermes",
                executable=os.path.abspath(os.path.join(self.tmp_dir, "hermes.exe")),
                raw_version="Hermes Agent v0.20.0",
                normalized_version="0.20.0",
                sha256="b" * 64,
            ),
        }

        with (
            _setup_patches(),
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch(
                "defenseclaw.agent_selection._SUPPORTED_CONNECTORS",
                frozenset({"codex", "claudecode", "hermes", "omnigent"}),
            ),
            patch(
                "defenseclaw.agent_selection._select_agent_executable",
                side_effect=lambda _data_dir, connector: selected[connector],
            ) as select,
        ):
            result = _invoke(
                ["-c", "codex", "-c", "hermes", "--yes", "--no-restart"],
                self.app,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual([call.args[1] for call in select.call_args_list], ["codex", "hermes"])
        with open(selection_path, encoding="utf-8") as handle:
            receipt = json.load(handle)
        self.assertEqual(set(receipt["selections"]), {"codex", "hermes"})
        self.assertEqual(receipt["selections"]["codex"]["executable"], selected["codex"].executable)
        self.assertEqual(receipt["selections"]["hermes"]["executable"], selected["hermes"].executable)
        self.assertNotIn("omnigent", receipt["selections"])

    def test_bare_batch_unsupported_target_never_reconciles_prior_roster(self):
        self._seed_map("codex", "cursor")
        prior = tuple(self.app.cfg.active_connectors())
        with (
            _setup_patches() as restart,
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                side_effect=lambda connector, **_kwargs: connector != "opencode",
            ),
        ):
            result = _invoke(["-c", "codex", "-c", "opencode", "--yes"], self.app)

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("prior roster was not changed", result.output)
        self.assertEqual(tuple(self.app.cfg.active_connectors()), prior)
        self.assertNotIn("opencode", self.app.cfg.active_connectors())
        restart.assert_not_called()

    def test_bare_batch_no_restart_remains_offline_staging(self):
        self._seed_map("codex", "cursor")
        with (
            _setup_patches() as restart,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=False),
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway") as generic,
        ):
            result = _invoke(
                ["-c", "codex", "-c", "cursor", "--yes", "--no-restart"],
                self.app,
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("--no-restart", result.output)
        restart.assert_not_called()
        generic.assert_not_called()

    def test_unrelated_setup_callback_keeps_generic_restart_policy(self):
        self._seed_map("codex", "cursor")
        ctx = click.Context(setup_group, obj=self.app)
        ctx.meta[cmd_setup._SETUP_CFG_MTIME_KEY] = None
        with open(self.cfg_path, "w", encoding="utf-8") as config_file:
            config_file.write("unrelated: true\n")
        with (
            ctx,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=True),
            patch("defenseclaw.commands.cmd_setup._restart_services") as readiness,
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True) as generic,
        ):
            cmd_setup._auto_restart_sidecar_after_setup()
        readiness.assert_not_called()
        generic.assert_called_once_with(self.app.cfg.data_dir, start_if_stopped=False)

    # D3: --replace forces overwrite even non-interactively.
    def test_replace_flag_overwrites_multi_set(self):
        self._seed_map("codex", "cursor")
        with _setup_patches():
            result = _invoke(["windsurf", "--replace", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.connector, "windsurf")
        self.assertEqual(self.app.cfg.claw.mode, "windsurf")

    # D1: interactive three-choice prompt — Add.
    def test_interactive_add_choice(self):
        self._seed_single("codex")
        with _setup_patches(prompt="a"):
            result = _invoke(["cursor", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"codex", "cursor"})

    # D1: interactive three-choice prompt — Replace.
    def test_interactive_replace_choice(self):
        self._seed_single("codex")
        with _setup_patches(prompt="r"):
            result = _invoke(["cursor", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connectors, {})
        self.assertEqual(self.app.cfg.guardrail.connector, "cursor")

    # D1: interactive three-choice prompt — Cancel leaves state untouched.
    def test_interactive_cancel_choice_is_noop(self):
        self._seed_single("codex")
        with _setup_patches(prompt="c"):
            result = _invoke(["cursor", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Aborted", result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")
        self.assertEqual(self.app.cfg.guardrail.connectors, {})

    # D4: an existing PROXY connector is replaced, never added to.
    def test_proxy_existing_is_replaced_not_added(self):
        self._seed_single("openclaw")
        with _setup_patches():
            result = _invoke(["codex", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.connector, "codex")
        self.assertEqual(self.app.cfg.claw.mode, "codex")

    # First connector on a clean config: replace shape, no map.
    def test_first_connector_uses_replace_shape(self):
        self.app.cfg.guardrail.connector = ""
        self.app.cfg.guardrail.connectors = {}
        with _setup_patches():
            result = _invoke(["codex", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connectors, {})
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")

    def test_no_restart_suppresses_parent_auto_restart_for_hook_alias(self):
        self._seed_map("antigravity", "codex", "hermes", "opencode")
        with (
            _setup_patches() as restart,
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=True),
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway") as bounce,
        ):
            result = _invoke(["hermes", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        restart.assert_not_called()
        bounce.assert_not_called()

    def test_no_restart_allows_explicit_offline_connector_staging(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with _setup_patches():
            result = _invoke(["codex", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")
        self.assertIn("canonical setup audit event was not recorded", result.output)

    def test_offline_exception_is_not_suppressed_when_restart_was_requested(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with _setup_patches(), self.assertRaises(CanonicalObservabilityUnavailableError):
            _invoke(["codex", "--yes"], self.app)

    def test_no_restart_keeps_server_admission_rejection_fail_closed(self):
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityError("rejected")
        with _setup_patches(), self.assertRaises(CanonicalObservabilityError):
            _invoke(["codex", "--yes", "--no-restart"], self.app)


class TestWriteConnectorIdentityUnit(unittest.TestCase):
    """Direct unit tests for the write-mode writer (no Click layer)."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_add_seeds_existing_and_keeps_primary_mirror(self):
        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        gc.connectors = {}
        _write_connector_identity(self.app.cfg, "cursor", "add")
        self.assertEqual(set(gc.connectors), {"codex", "cursor"})
        self.assertEqual(gc.connector, "codex")  # sorted-first primary
        self.assertEqual(self.app.cfg.claw.mode, "codex")

    def test_add_is_idempotent_and_preserves_overrides(self):
        gc = self.app.cfg.guardrail
        gc.connectors = {"codex": PerConnectorGuardrailConfig(mode="action")}
        gc.connector = "codex"
        _write_connector_identity(self.app.cfg, "codex", "add")
        # Existing override block must not be clobbered.
        self.assertEqual(gc.connectors["codex"].mode, "action")

    def test_replace_clears_map(self):
        gc = self.app.cfg.guardrail
        gc.connectors = {"codex": PerConnectorGuardrailConfig(), "cursor": PerConnectorGuardrailConfig()}
        gc.connector = "codex"
        _write_connector_identity(self.app.cfg, "windsurf", "replace")
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.connector, "windsurf")
        self.assertEqual(self.app.cfg.claw.mode, "windsurf")

    def test_add_does_not_seed_proxy_predecessor(self):
        gc = self.app.cfg.guardrail
        gc.connector = "openclaw"  # proxy — must not become a multi peer
        gc.connectors = {}
        _write_connector_identity(self.app.cfg, "codex", "add")
        self.assertNotIn("openclaw", gc.connectors)
        self.assertIn("codex", gc.connectors)


class TestObservabilitySummaryDisplay(unittest.TestCase):
    """The post-setup summary must show all connectors as peers, never a
    misleading '(primary: X)' callout on a multi-connector install."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _seed_map(self, *connectors):
        self.app.cfg.guardrail.connectors = {
            c: PerConnectorGuardrailConfig() for c in connectors
        }
        self.app.cfg.guardrail.connector = sorted(connectors)[0]
        self.app.cfg.claw.mode = sorted(connectors)[0]

    def _capture_summary(self, connector, *, os_name=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_observability_summary(connector, self.app.cfg, mode="observe", os_name=os_name)
        return buf.getvalue()

    def test_multi_connector_summary_lists_all_peers_without_primary(self):
        self._seed_map("antigravity", "claudecode", "codex")
        out = self._capture_summary("codex")
        # roster row names every connector...
        self.assertIn("antigravity", out)
        self.assertIn("claudecode", out)
        self.assertIn("codex", out)
        self.assertIn("connectors:", out)
        self.assertIn("codex mode:", out)
        self.assertNotIn("guardrail.mode:", out)
        # ...and no '(primary: ...)' callout leaks the back-compat pointer.
        self.assertNotIn("primary:", out)

    def test_single_connector_summary_uses_connector_mode_label(self):
        self._seed_map("cursor")
        out = self._capture_summary("cursor")
        self.assertIn("active connector:", out)
        self.assertIn("cursor mode:", out)
        self.assertNotIn("claw.mode:", out)
        self.assertNotIn("guardrail.mode:", out)
        self.assertNotIn("connectors:", out)
        self.assertNotIn("primary:", out)

    def test_windows_summary_uses_canonical_tui_and_cli_filtering(self):
        self._seed_map("claudecode")

        out = self._capture_summary("claudecode", os_name="nt")

        self.assertIn("Watch decisions live: defenseclaw tui", out)
        self.assertIn("defenseclaw alerts --limit 25 --connector claudecode", out)
        self.assertNotIn("gateway.jsonl", out)
        self.assertNotIn("tail -f", out)
        self.assertNotIn("| jq", out)
        self.assertNotIn("Bash", out)
        self.assertNotIn("WSL", out)

    def test_posix_summary_uses_canonical_tui_and_alerts(self):
        self._seed_map("claudecode")

        out = self._capture_summary("claudecode", os_name="posix")

        self.assertIn("Watch decisions live: defenseclaw tui", out)
        self.assertIn("defenseclaw alerts --limit 25", out)
        self.assertIn("jq 'select(.connector == \"claudecode\")'", out)
        self.assertNotIn("gateway.jsonl", out)
        self.assertNotIn("Get-Content -LiteralPath", out)

    def test_hermes_action_summary_reports_fail_open_posture(self):
        self._seed_map("hermes")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_observability_summary(
                "hermes",
                self.app.cfg,
                mode="action",
                os_name="nt",
            )
        out = buf.getvalue()

        self.assertIn("pre_tool deny; pre_verify continue", out)
        self.assertIn("hook failure posture:", out)
        self.assertIn("upstream fail-open", out)
        self.assertIn("native ask/approve:", out)
        self.assertIn("unsupported", out)
        self.assertIn("native OTel:", out)
        self.assertIn("hook-derived audit only", out)


class TestConfiguredConnectorSet(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_map_keys_win_when_populated(self):
        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        gc.connectors = {"cursor": PerConnectorGuardrailConfig(), "codex": PerConnectorGuardrailConfig()}
        self.assertEqual(_configured_connector_set(gc), ["codex", "cursor"])

    def test_falls_back_to_singular(self):
        gc = self.app.cfg.guardrail
        gc.connector = "codex"
        gc.connectors = {}
        self.assertEqual(_configured_connector_set(gc), ["codex"])

    def test_empty_when_unconfigured(self):
        gc = self.app.cfg.guardrail
        gc.connector = ""
        gc.connectors = {}
        self.assertEqual(_configured_connector_set(gc), [])


class TestRemoveConnector(unittest.TestCase):
    """WU8 tests: ``setup remove <connector>`` (inverse of setup-add).

    Pins the WU8 decisions:
    * D2=A — removing the last connector is refused unless ``--force``,
      which fully unconfigures enforcement.
    * D3=A — teardown is delegated to a gateway restart (no per-connector
      teardown plumbing); ``--no-restart`` defers it and is honored.
    * Mutation shape mirrors setup-add: the connector map remains authoritative
      when one peer survives, while singular fields mirror that survivor.
    """

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _seed_map(self, *connectors):
        self.app.cfg.guardrail.connectors = {c: PerConnectorGuardrailConfig() for c in connectors}
        self.app.cfg.guardrail.connector = sorted(connectors)[0]
        self.app.cfg.claw.mode = sorted(connectors)[0]

    def _seed_single(self, connector):
        self.app.cfg.claw.mode = connector
        self.app.cfg.guardrail.connector = connector
        self.app.cfg.guardrail.connectors = {}

    @contextlib.contextmanager
    def _no_restart_bounce(self):
        runtime = cmd_setup._SetupAppliedRuntimeEvidence(
            lifecycle="running",
            generation="generation-before",
            invariants=(),
        )
        with (
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True) as bounce,
            patch("defenseclaw.commands.cmd_setup._capture_setup_applied_runtime", return_value=runtime),
        ):
            yield bounce

    # Removing one of three leaves a still-multi set; map retained, primary repointed.
    def test_remove_from_multi_keeps_map(self):
        self._seed_map("codex", "cursor", "windsurf")
        with self._no_restart_bounce():
            result = _invoke(["remove", "windsurf", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"codex", "cursor"})
        self.assertEqual(gc.connector, "codex")
        self.assertEqual(self.app.cfg.claw.mode, "codex")

    # Removing the next-to-last retains its map entry so overrides stay lossless.
    def test_remove_retains_one_entry_map(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce():
            result = _invoke(["remove", "cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"codex"})
        self.assertEqual(gc.connector, "codex")
        self.assertEqual(self.app.cfg.claw.mode, "codex")

    # D2=A: removing the last connector without --force is refused, no-op.
    def test_remove_last_without_force_refused(self):
        self._seed_single("codex")
        with self._no_restart_bounce():
            result = _invoke(["remove", "codex", "--yes", "--no-restart"], self.app)
        self.assertNotEqual(result.exit_code, 0)
        # State untouched.
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")

    # D2=A: --force --yes fully unconfigures the last connector.
    def test_remove_last_with_force_unconfigures(self):
        self._seed_single("codex")
        with self._no_restart_bounce():
            result = _invoke(["remove", "codex", "--force", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors, {})
        self.assertEqual(gc.connector, "")
        self.assertEqual(self.app.cfg.claw.mode, "")

    # Removing a connector that isn't configured is refused.
    def test_remove_unknown_refused(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce():
            result = _invoke(["remove", "not-a-connector", "--yes", "--no-restart"], self.app)
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"codex", "cursor"})

    def test_remove_known_absent_is_idempotent(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce():
            result = _invoke(["remove", "windsurf", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("already absent", result.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"codex", "cursor"})

    # Connector name match is case-insensitive.
    def test_remove_case_insensitive(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce():
            result = _invoke(["remove", "Cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")

    def test_remove_connector_alias(self):
        self._seed_map("claudecode", "codex")
        with self._no_restart_bounce():
            result = _invoke(["remove", "claude-code", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")
        self.assertNotIn("claudecode", self.app.cfg.guardrail.connectors)

    def _effective_policy(self, connector):
        gc = self.app.cfg.guardrail
        hilt = gc.effective_hilt(connector)
        gate = [str(name).strip() for name in gc.judge.hook_connectors]
        return {
            "enabled": gc.effective_enabled(connector),
            "mode": gc.effective_mode(connector),
            "rule_pack_dir": gc.effective_rule_pack_dir(connector),
            "hook_fail_mode": gc.effective_hook_fail_mode(connector),
            "hilt_enabled": hilt.enabled,
            "hilt_min_severity": hilt.min_severity,
            "block_message": gc.effective_block_message(connector),
            "judge_gate": bool(gc.judge.enabled) and ("*" in gate or connector in gate),
        }

    def test_remove_preserves_each_survivor_policy_round_trip_and_is_idempotent(self):
        policies = {
            "codex": PerConnectorGuardrailConfig(
                enabled=False,
                mode="action",
                rule_pack_dir="codex-pack",
                hook_fail_mode="closed",
                hilt=HILTConfig(enabled=True, min_severity="LOW"),
                block_message="codex-block",
            ),
            "claudecode": PerConnectorGuardrailConfig(
                enabled=False,
                mode="action",
                rule_pack_dir="claude-pack",
                hook_fail_mode="closed",
                hilt=HILTConfig(enabled=True, min_severity="MEDIUM"),
                block_message="claude-block",
            ),
        }
        cases = (("claudecode", "codex"), ("codex", "claudecode"))

        for removed, survivor in cases:
            with self.subTest(removed=removed, survivor=survivor):
                gc = self.app.cfg.guardrail
                gc.enabled = True
                gc.mode = "observe"
                gc.rule_pack_dir = "global-pack"
                gc.hook_fail_mode = "open"
                gc.hilt = HILTConfig(enabled=False, min_severity="HIGH")
                gc.block_message = "global-block"
                gc.connectors = copy.deepcopy(policies)
                gc.connector = "claudecode"
                self.app.cfg.claw.mode = "claudecode"
                gc.judge.enabled = True
                gc.judge.hook_connectors = ["codex", "claudecode"]

                expected_entry = copy.deepcopy(gc.connectors[survivor])
                expected_policy = self._effective_policy(survivor)
                with self._no_restart_bounce():
                    result = _invoke(["remove", removed, "--yes", "--no-restart"], self.app)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(set(gc.connectors), {survivor})
                self.assertEqual(gc.connectors[survivor], expected_entry)
                self.assertEqual(self._effective_policy(survivor), expected_policy)
                self.assertEqual(self.app.cfg.active_connectors(), [survivor])
                self.assertEqual(gc.connector, survivor)
                self.assertEqual(self.app.cfg.claw.mode, survivor)

                with patch.dict(
                    os.environ,
                    {"DEFENSECLAW_HOME": self.tmp_dir, "DEFENSECLAW_CONFIG": self.cfg_path},
                ):
                    reloaded = load()
                self.assertEqual(set(reloaded.guardrail.connectors), {survivor})
                self.assertEqual(reloaded.guardrail.connectors[survivor], expected_entry)
                self.assertEqual(reloaded.guardrail.connector, survivor)
                self.assertEqual(reloaded.claw.mode, survivor)

                saved = open(self.cfg_path, "rb").read()
                with self._no_restart_bounce():
                    repeated = _invoke(["remove", removed, "--yes", "--no-restart"], self.app)
                self.assertEqual(repeated.exit_code, 0, msg=repeated.output)
                self.assertIn("already absent", repeated.output)
                self.assertEqual(open(self.cfg_path, "rb").read(), saved)
                self.assertEqual(self._effective_policy(survivor), expected_policy)

    # D3=A: --restart bounces the gateway so boot-time set-diff teardown runs.
    def test_remove_restart_bounces_gateway(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce() as bounce:
            result = _invoke(["remove", "cursor", "--yes"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        bounce.assert_called_once()

    def test_remove_restart_failure_restores_prior_roster(self):
        self._seed_map("codex", "cursor")
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=cmd_setup._SetupAppliedRuntimeEvidence(
                lifecycle="running",
                generation="generation-before",
                invariants=(),
            ),
        )
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_config_snapshot",
                return_value=snapshot,
            ),
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="windows"),
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=False),
            patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle"),
            patch("defenseclaw.commands.cmd_setup._verify_restored_setup_runtime", return_value=[]),
        ):
            result = _invoke(["remove", "cursor", "--yes"], self.app)

        self.assertNotEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("restored the prior connector configuration and runtime", result.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"codex", "cursor"})

    # D3=A: --no-restart does NOT bounce and warns teardown is deferred.
    def test_remove_no_restart_defers_teardown(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce() as bounce:
            result = _invoke(["remove", "cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        bounce.assert_not_called()
        self.assertIn("--no-restart", result.output)

    def test_remove_no_restart_allows_explicit_offline_staging(self):
        self._seed_map("codex", "cursor")
        self.app.logger = MagicMock()
        self.app.logger.log_action.side_effect = CanonicalObservabilityUnavailableError("offline")
        with self._no_restart_bounce():
            result = _invoke(["remove", "cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")
        self.assertIn("canonical setup audit event was not recorded", result.output)

    # Declining the confirmation prompt is a no-op.
    def test_remove_declined_is_noop(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce(), patch(
            "defenseclaw.commands.cmd_setup.click.confirm", return_value=False
        ):
            result = _invoke(["remove", "cursor", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Aborted", result.output)
        self.assertEqual(set(self.app.cfg.guardrail.connectors), {"codex", "cursor"})


class TestSetupAppliedRuntimeRollback(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    @staticmethod
    def _evidence(*, lifecycle="running", generation="before", invariants=(), registration_locations=()):
        return cmd_setup._SetupAppliedRuntimeEvidence(
            lifecycle=lifecycle,
            generation=generation,
            invariants=tuple(invariants),
            registration_locations=tuple(registration_locations),
        )

    @staticmethod
    def _lock_body(entries):
        return (json.dumps({"version": 2, "connectors": entries}, sort_keys=True) + "\n").encode()

    def _snapshot_with_registration_lock(self, entries):
        names = sorted(entries)
        self.app.cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig() for name in names}
        self.app.cfg.guardrail.connector = names[0]
        self.app.cfg.claw.mode = names[0]
        lock_body = self._lock_body(entries)
        lock_path = os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json")
        atomic_write_private_bytes(lock_path, lock_body)
        locations = []
        for connector in sorted(entries):
            locations.extend(cmd_setup._capture_setup_registration_locations(connector, entries[connector]))
        runtime = self._evidence(
            invariants=(
                ("connector", "codex", "health-presence", "present"),
                ("watchdog", "runtime", "custody-health", "healthy"),
            ),
            registration_locations=locations,
        )
        return replace(cmd_setup._capture_setup_config_snapshot(self.app.cfg), applied_runtime=runtime), lock_body

    @staticmethod
    def _post_runtime(snapshot, required_registration_locations=()):
        locations = {
            cmd_setup._setup_registration_location_key(location): location
            for location in snapshot.applied_runtime.registration_locations
        }
        for required in required_registration_locations:
            normalized, identity, fingerprint = cmd_setup._capture_setup_runtime_location(required.path, required.role)
            current = replace(
                required,
                path=normalized,
                identity=identity,
                fingerprint=fingerprint,
            )
            locations[cmd_setup._setup_registration_location_key(current)] = current
        return replace(
            snapshot.applied_runtime,
            generation="after",
            registration_locations=tuple(locations[key] for key in sorted(locations)),
        )

    @staticmethod
    def _bounded_invariant_pair(mismatches, *, matching=0):
        expected = []
        actual = []
        for index in range(mismatches + matching):
            key = ("connector", "codex", f"bounded-evidence-{index:03}")
            expected.append((*key, "expected"))
            actual.append((*key, "actual" if index < mismatches else "expected"))
        return tuple(expected), tuple(actual)

    def _bounded_location_pair(self, mismatches, *, matching=0):
        expected = []
        actual = []
        for index in range(mismatches + matching):
            path = os.path.abspath(os.path.join(self.tmp_dir, "bounded-locations", f"{index:03}.json"))
            prior = cmd_setup._SetupRegistrationLocationEvidence(
                connector="codex",
                role="hook registration",
                identity=f"{index:064x}",
                fingerprint="present:1:" + ("a" * 64),
                path=path,
            )
            expected.append(prior)
            actual.append(replace(prior, fingerprint="missing") if index < mismatches else prior)
        return tuple(expected), tuple(actual)

    def test_manifest_comparison_is_symmetric_for_absent_and_present_runtime(self):
        stopped = self._evidence(
            lifecycle="stopped",
            generation=None,
            invariants=(
                ("connector", "codex", "health-presence", "missing"),
                ("connector", "codex", "hook-registration-a1", "missing"),
                ("watchdog", "runtime", "posture", "stopped"),
                ("watchdog", "runtime", "health-state", "missing"),
            ),
        )
        running = self._evidence(
            generation="after",
            invariants=(
                ("connector", "codex", "health-presence", "present"),
                ("connector", "codex", "hook-registration-a1", "present:9:digest"),
                ("connector", "codex", "receipt-b2", "present:7:digest"),
                ("watchdog", "runtime", "posture", "healthy"),
                ("watchdog", "runtime", "health-state", "running"),
            ),
        )

        stopped_to_running = cmd_setup._setup_runtime_manifest_mismatches(stopped, running)
        running_to_stopped = cmd_setup._setup_runtime_manifest_mismatches(running, stopped)

        self.assertIn("gateway lifecycle changed (stopped -> running)", stopped_to_running)
        self.assertIn("gateway generation was unexpectedly present", stopped_to_running)
        self.assertIn("connector codex: health presence changed", stopped_to_running)
        self.assertIn("watchdog: health state changed", stopped_to_running)
        self.assertIn("connector codex: unexpected receipt b2 is present", stopped_to_running)
        self.assertIn("gateway lifecycle changed (running -> stopped)", running_to_stopped)
        self.assertIn("prior running gateway generation is missing", running_to_stopped)
        self.assertIn("connector codex: receipt b2 is missing", running_to_stopped)

    def test_manifest_comparison_rejects_unchanged_running_generation(self):
        before = self._evidence(generation="same")
        after = self._evidence(generation="same")

        self.assertEqual(
            cmd_setup._setup_runtime_manifest_mismatches(before, after),
            ["restored gateway generation did not advance"],
        )

    def test_manifest_reports_omitted_peer_mode_digest_tombstone_and_watchdog(self):
        before = self._evidence(
            invariants=(
                ("connector", "codex", "guardrail-mode", "observe"),
                ("connector", "codex", "lock-identity", "prior-digest"),
                ("connector", "cursor", "health-presence", "present"),
                ("connector", "cursor", "roster-active", "present"),
                ("watchdog", "runtime", "posture", "healthy"),
            )
        )
        after = self._evidence(
            generation="after",
            invariants=(
                ("connector", "codex", "guardrail-mode", "action"),
                ("connector", "codex", "lock-identity", "changed-digest"),
                ("connector", "cursor", "roster-inactive", "present"),
                ("watchdog", "runtime", "posture", "degraded"),
            ),
        )

        failures = cmd_setup._setup_runtime_manifest_mismatches(before, after)

        self.assertIn("connector codex: guardrail mode changed", failures)
        self.assertIn("connector codex: lock identity changed", failures)
        self.assertIn("connector cursor: health presence is missing", failures)
        self.assertIn("connector cursor: roster active is missing", failures)
        self.assertIn("connector cursor: unexpected roster inactive is present", failures)
        self.assertIn("watchdog: posture changed", failures)

    def test_exactly_64_invariant_mismatches_keep_every_real_row(self):
        expected_invariants, actual_invariants = self._bounded_invariant_pair(64, matching=1)

        failures = cmd_setup._setup_runtime_manifest_mismatches(
            self._evidence(generation="before", invariants=expected_invariants),
            self._evidence(generation="after", invariants=actual_invariants),
        )

        self.assertEqual(len(failures), cmd_setup._SETUP_ROLLBACK_MAX_FAILURES)
        self.assertTrue(all(failure.endswith(" changed") for failure in failures))
        self.assertNotIn("additional runtime mismatches", "\n".join(failures))

    def test_exactly_64_location_mismatches_keep_every_real_row(self):
        expected_locations, actual_locations = self._bounded_location_pair(64, matching=1)

        failures = cmd_setup._setup_runtime_manifest_mismatches(
            self._evidence(generation="before", registration_locations=expected_locations),
            self._evidence(generation="after", registration_locations=actual_locations),
        )

        self.assertEqual(len(failures), cmd_setup._SETUP_ROLLBACK_MAX_FAILURES)
        self.assertTrue(all(failure.endswith(" changed") for failure in failures))
        self.assertNotIn("additional runtime mismatches", "\n".join(failures))

    def test_exactly_64_mixed_mismatches_have_no_omitted_marker(self):
        expected_invariants, actual_invariants = self._bounded_invariant_pair(31, matching=1)
        expected_locations, actual_locations = self._bounded_location_pair(31, matching=1)

        failures = cmd_setup._setup_runtime_manifest_mismatches(
            self._evidence(
                lifecycle="running",
                generation="before",
                invariants=expected_invariants,
                registration_locations=expected_locations,
            ),
            self._evidence(
                lifecycle="stopped",
                generation=None,
                invariants=actual_invariants,
                registration_locations=actual_locations,
            ),
        )

        self.assertEqual(len(failures), cmd_setup._SETUP_ROLLBACK_MAX_FAILURES)
        self.assertNotIn("additional runtime mismatches", "\n".join(failures))

    def test_more_than_64_mismatches_emit_one_truthful_bounded_marker(self):
        invariant_expected, invariant_actual = self._bounded_invariant_pair(65, matching=1)
        location_expected, location_actual = self._bounded_location_pair(65, matching=1)
        mixed_invariant_expected, mixed_invariant_actual = self._bounded_invariant_pair(32, matching=1)
        mixed_location_expected, mixed_location_actual = self._bounded_location_pair(31, matching=1)
        cases = (
            (
                "invariants",
                self._evidence(generation="before", invariants=invariant_expected),
                self._evidence(generation="after", invariants=invariant_actual),
            ),
            (
                "locations",
                self._evidence(generation="before", registration_locations=location_expected),
                self._evidence(generation="after", registration_locations=location_actual),
            ),
            (
                "mixed",
                self._evidence(
                    lifecycle="running",
                    generation="before",
                    invariants=mixed_invariant_expected,
                    registration_locations=mixed_location_expected,
                ),
                self._evidence(
                    lifecycle="stopped",
                    generation=None,
                    invariants=mixed_invariant_actual,
                    registration_locations=mixed_location_actual,
                ),
            ),
        )

        for label, expected, actual in cases:
            with self.subTest(label=label):
                failures = cmd_setup._setup_runtime_manifest_mismatches(expected, actual)
                self.assertEqual(len(failures), cmd_setup._SETUP_ROLLBACK_MAX_FAILURES)
                self.assertEqual(
                    failures[-1],
                    "additional runtime mismatches were omitted at the bounded reporting limit",
                )
                self.assertEqual(
                    sum("additional runtime mismatches" in failure for failure in failures),
                    1,
                )

    def test_registration_identity_prefix_collisions_remain_distinct(self):
        shared_prefix = "abcdef123456"
        first = cmd_setup._SetupRegistrationLocationEvidence(
            connector="codex",
            role="hook registration",
            identity=shared_prefix + ("0" * 52),
            fingerprint="present:5:first",
            path=os.path.abspath(os.path.join(self.tmp_dir, "registrations", "first.json")),
        )
        second = cmd_setup._SetupRegistrationLocationEvidence(
            connector="codex",
            role="hook registration",
            identity=shared_prefix + ("1" * 52),
            fingerprint="present:6:second",
            path=os.path.abspath(os.path.join(self.tmp_dir, "registrations", "second.json")),
        )
        locations = (first, second)

        self.assertEqual(len(cmd_setup._setup_registration_location_map(locations)), 2)
        digest = cmd_setup._setup_registration_fingerprint(locations)
        self.assertNotEqual(
            digest,
            cmd_setup._setup_registration_fingerprint((replace(first, fingerprint="missing"), second)),
        )
        self.assertNotEqual(
            digest,
            cmd_setup._setup_registration_fingerprint((first, replace(second, fingerprint="missing"))),
        )
        for changed in (
            (replace(first, fingerprint="missing"), second),
            (first, replace(second, fingerprint="missing")),
        ):
            failures = cmd_setup._setup_runtime_manifest_mismatches(
                self._evidence(generation="before", registration_locations=locations),
                self._evidence(generation="after", registration_locations=changed),
            )
            self.assertEqual(len([failure for failure in failures if failure.endswith(" changed")]), 1)
        with self.assertRaisesRegex(OSError, "duplicate full identity"):
            cmd_setup._setup_registration_fingerprint((first, first))

    def test_runtime_capture_retries_until_two_consecutive_manifests_match(self):
        first = self._evidence(generation="first")
        stable = self._evidence(generation="stable")
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=[first, stable, stable],
            ) as capture,
            patch("defenseclaw.commands.cmd_setup.time.sleep"),
        ):
            result = cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        self.assertEqual(result, stable)
        self.assertEqual(capture.call_count, 3)

    def test_runtime_capture_waits_for_post_teardown_evidence_to_stabilize(self):
        stable = self._evidence(generation="stable")
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=[OSError("private transient"), OSError("private transient"), stable, stable],
            ) as capture,
            patch("defenseclaw.commands.cmd_setup.time.sleep") as pause,
        ):
            result = cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        self.assertEqual(result, stable)
        self.assertEqual(capture.call_count, 4)
        self.assertEqual(pause.call_count, 3)
        pause.assert_called_with(cmd_setup._SETUP_RUNTIME_SNAPSHOT_RETRY_SECONDS)

    def test_runtime_capture_keeps_complete_sample_across_transient_read_error(self):
        stable = self._evidence(generation="stable")
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=[stable, OSError("private transient"), stable],
            ) as capture,
            patch("defenseclaw.commands.cmd_setup.time.sleep") as pause,
        ):
            result = cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        self.assertEqual(result, stable)
        self.assertEqual(capture.call_count, 3)
        self.assertEqual(pause.call_count, 2)

    def test_runtime_capture_replaces_complete_sample_after_observed_change(self):
        first = self._evidence(generation="first")
        stable = self._evidence(generation="stable")
        with patch(
            "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
            side_effect=[first, OSError("private transient"), stable, stable],
        ) as capture:
            result = cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        self.assertEqual(result, stable)
        self.assertEqual(capture.call_count, 4)

    def test_runtime_capture_rejects_generation_race_without_leaking_details(self):
        private_detail = os.path.join(self.tmp_dir, "secret-profile", "gateway.json")
        evidence = [
            self._evidence(generation=private_detail + "-one"),
            self._evidence(generation=private_detail + "-two"),
            self._evidence(generation=private_detail + "-three"),
        ]
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=evidence,
            ),
            self.assertRaises(OSError) as raised,
        ):
            cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        message = str(raised.exception)
        self.assertIn("did not stabilize", message)
        self.assertIn("[diff=generation]", message)
        self.assertNotIn(private_detail, message)
        self.assertNotIn("secret-profile", message)

    def test_runtime_capture_reports_changed_invariant_name_without_values(self):
        private_first = os.path.join(self.tmp_dir, "secret-profile", "first")
        private_second = os.path.join(self.tmp_dir, "secret-profile", "second")
        first = self._evidence(
            invariants=(("watchdog", "runtime", "custody-health", private_first),),
        )
        second = self._evidence(
            invariants=(("watchdog", "runtime", "custody-health", private_second),),
        )
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=[first, second, first],
            ),
            patch("defenseclaw.commands.cmd_setup.time.sleep"),
            self.assertRaises(OSError) as raised,
        ):
            cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        message = str(raised.exception)
        self.assertIn("[diff=watchdog.runtime.custody-health]", message)
        self.assertNotIn(private_first, message)
        self.assertNotIn(private_second, message)
        self.assertNotIn("secret-profile", message)

    def test_runtime_capture_reports_redacted_local_error_site(self):
        private_detail = os.path.join(self.tmp_dir, "secret-profile", "gateway-boundary")
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_gateway_boundary",
                side_effect=OSError(private_detail),
            ),
            patch("defenseclaw.commands.cmd_setup.time.sleep"),
            self.assertRaises(OSError) as raised,
        ):
            cmd_setup._capture_setup_applied_runtime(self.app.cfg)

        message = str(raised.exception)
        self.assertRegex(
            message,
            r"\[site=_capture_setup_applied_runtime_once:\d+;error=[0-9a-f]{12}\]",
        )
        self.assertNotIn(private_detail, message)
        self.assertNotIn("secret-profile", message)

    def test_runtime_capture_has_start_end_generation_fence(self):
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_gateway_boundary",
                side_effect=[
                    ("running", {}, "generation-before"),
                    ("running", {}, "generation-after"),
                ],
            ),
            patch(
                "defenseclaw.commands.cmd_setup._capture_protected_setup_file",
                return_value=(False, b"", None),
            ),
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_watchdog_fingerprint",
                return_value="watchdog-fingerprint",
            ),
            self.assertRaisesRegex(OSError, "generation changed"),
        ):
            cmd_setup._capture_setup_applied_runtime_once(self.app.cfg)

    def test_watchdog_fingerprint_accepts_repairable_invalid_stopped_record(self):
        evidence = MagicMock()
        evidence.watchdog_pid_record.return_value = MagicMock(
            status="malformed", reason="private malformed record detail", executable=""
        )
        evidence.watchdog_ownership.return_value = MagicMock(status="missing", source="stable")
        with patch("defenseclaw.doctor_gateway.GatewayEvidence", return_value=evidence):
            fingerprint = cmd_setup._capture_setup_watchdog_fingerprint(self.app.cfg)

        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")

    def test_watchdog_fingerprint_does_not_reread_validated_runtime_publications(self):
        evidence = MagicMock()
        evidence.watchdog_pid_record.side_effect = OSError("private concurrent PID publication")
        evidence.watchdog_ownership.side_effect = OSError("private concurrent ownership publication")
        health = MagicMock(status="fresh", state="healthy")
        with (
            patch("defenseclaw.doctor_gateway.GatewayEvidence", return_value=evidence),
            patch(
                "defenseclaw.commands.cmd_doctor._inspect_windows_watchdog_runtime",
                return_value=("running", "validated exact runtime", health),
            ),
        ):
            fingerprint = cmd_setup._capture_setup_watchdog_fingerprint(self.app.cfg)

        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
        evidence.watchdog_pid_record.assert_not_called()
        evidence.watchdog_ownership.assert_not_called()

    def test_watchdog_fingerprint_excludes_atomically_republished_health_hint(self):
        evidence = MagicMock()
        health_samples = (
            MagicMock(status="unavailable", state=""),
            MagicMock(status="ok", state="healthy"),
        )
        with (
            patch("defenseclaw.doctor_gateway.GatewayEvidence", return_value=evidence),
            patch(
                "defenseclaw.commands.cmd_doctor._inspect_windows_watchdog_runtime",
                side_effect=[("running", "validated exact runtime", health) for health in health_samples],
            ),
        ):
            fingerprints = tuple(cmd_setup._capture_setup_watchdog_fingerprint(self.app.cfg) for _ in health_samples)

        self.assertEqual(fingerprints[0], fingerprints[1])

    def test_watchdog_fingerprint_excludes_safe_teardown_liveness_posture(self):
        evidence = MagicMock()
        safe_samples = (
            ("running", "validated owned runtime", MagicMock(status="ok", state="healthy")),
            ("stale", "owned process exited", None),
            ("invalid", "retiring canonical publication", None),
            ("stopped", "owned teardown complete", None),
        )
        with (
            patch("defenseclaw.doctor_gateway.GatewayEvidence", return_value=evidence),
            patch(
                "defenseclaw.commands.cmd_doctor._inspect_windows_watchdog_runtime",
                side_effect=safe_samples,
            ),
        ):
            fingerprints = tuple(cmd_setup._capture_setup_watchdog_fingerprint(self.app.cfg) for _ in safe_samples)

        self.assertEqual(len(set(fingerprints)), 1)

    def test_watchdog_fingerprint_rejects_unsafe_custody(self):
        with patch(
            "defenseclaw.commands.cmd_doctor._inspect_windows_watchdog_runtime",
            return_value=("unsafe", "private custody detail", None),
        ):
            with self.assertRaisesRegex(OSError, "watchdog custody evidence is unavailable") as raised:
                cmd_setup._capture_setup_watchdog_fingerprint(self.app.cfg)

        self.assertNotIn("private custody detail", str(raised.exception))

    def test_final_success_proves_complete_registration_union_in_both_fenced_samples(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        failed_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "failed-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        snapshot, _prior_lock = self._snapshot_with_registration_lock(
            {"codex": {"locations": {"hook_config_paths": [prior_path]}}}
        )
        atomic_write_private_bytes(failed_path, b"failed-generation-b\n")
        normalized, identity, fingerprint = cmd_setup._capture_setup_runtime_location(failed_path, "hook registration")
        failed = cmd_setup._SetupRegistrationLocationEvidence(
            connector="codex",
            role="hook registration",
            identity=identity,
            fingerprint=fingerprint,
            path=normalized,
        )
        os.remove(failed_path)
        complete = self._post_runtime(snapshot, (failed,))

        with patch(
            "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
            return_value=complete,
        ) as capture:
            failures = cmd_setup._verify_restored_setup_runtime(self.app.cfg, snapshot, (failed,))

        self.assertEqual(failures, [])
        self.assertEqual(capture.call_count, 2)
        self.assertTrue(all(call.args == (self.app.cfg, (failed,)) for call in capture.call_args_list))
        self.assertEqual(
            complete.registration_locations,
            cmd_setup._expected_setup_registration_locations(snapshot, (failed,)),
        )

    def test_snapshot_authority_fence_retries_generation_change(self):
        baseline = cmd_setup._capture_setup_config_snapshot(self.app.cfg)
        changed = replace(baseline, config_generation=(1, 2, 3, 4))
        runtime = self._evidence()
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_desired_snapshot_once",
                side_effect=[baseline, changed, baseline, baseline],
            ) as desired,
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                return_value=runtime,
            ) as applied,
        ):
            snapshot = cmd_setup._capture_setup_config_snapshot(self.app.cfg, capture_runtime=True)

        self.assertEqual(snapshot.applied_runtime, runtime)
        self.assertEqual(desired.call_count, 4)
        self.assertEqual(applied.call_count, 2)

    def test_snapshot_fails_before_mutation_when_authority_never_stabilizes(self):
        baseline = cmd_setup._capture_setup_config_snapshot(self.app.cfg)
        changed = replace(baseline, config_generation=(1, 2, 3, 4))
        runtime = self._evidence()
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_desired_snapshot_once",
                side_effect=[baseline, changed] * cmd_setup._SETUP_RUNTIME_SNAPSHOT_ATTEMPTS,
            ) as desired,
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                return_value=runtime,
            ) as applied,
            self.assertRaisesRegex(OSError, "authority changed"),
        ):
            cmd_setup._capture_setup_config_snapshot(self.app.cfg, capture_runtime=True)

        self.assertEqual(desired.call_count, 2 * cmd_setup._SETUP_RUNTIME_SNAPSHOT_ATTEMPTS)
        self.assertEqual(applied.call_count, cmd_setup._SETUP_RUNTIME_SNAPSHOT_ATTEMPTS)

    def test_rollback_aggregates_restore_persistence_and_runtime_failures(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(),
        )
        private_detail = os.path.join(self.tmp_dir, "secret-profile", "config.yaml")
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restore_setup_config_snapshot",
                side_effect=OSError(private_detail),
            ),
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_persistence",
                side_effect=[["config.yaml differs"], ["agent_selection.json differs"]],
            ) as persistence,
            patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle") as lifecycle,
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_runtime",
                return_value=["connector codex: health presence changed"],
            ) as runtime,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app,
                snapshot,
                OSError(private_detail),
            )

        message = str(raised.exception)
        self.assertIn("restore prior desired authority", message)
        self.assertIn("config.yaml differs", message)
        self.assertIn("runtime reconciliation was skipped", message)
        self.assertIn("agent_selection.json differs", message)
        self.assertIn("connector codex: health presence changed", message)
        self.assertNotIn(private_detail, message)
        self.assertNotIn("secret-profile", message)
        self.assertEqual(persistence.call_count, 2)
        lifecycle.assert_not_called()
        runtime.assert_called_once()

    def test_restart_failure_does_not_skip_persistence_or_runtime_verification(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(),
        )
        private_detail = os.path.join(self.tmp_dir, "private-identity", "gateway.lock")
        with (
            patch("defenseclaw.commands.cmd_setup._restore_setup_config_snapshot"),
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_persistence",
                side_effect=[[], ["picked_connector differs"]],
            ) as persistence,
            patch(
                "defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle",
                side_effect=OSError(private_detail),
            ),
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_runtime",
                return_value=["watchdog: posture changed"],
            ) as runtime,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(self.app, snapshot, RuntimeError("failed"))

        message = str(raised.exception)
        self.assertIn("restore prior gateway lifecycle", message)
        self.assertIn("picked_connector differs", message)
        self.assertIn("watchdog: posture changed", message)
        self.assertNotIn(private_detail, message)
        self.assertNotIn("private-identity", message)
        self.assertEqual(persistence.call_count, 2)
        runtime.assert_called_once()

    def test_persistence_exception_does_not_skip_remaining_verification(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(),
        )
        private_detail = os.path.join(self.tmp_dir, "private-profile", "receipt.json")
        with (
            patch("defenseclaw.commands.cmd_setup._restore_setup_config_snapshot"),
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_persistence",
                side_effect=[OSError(private_detail), ["config.yaml differs"]],
            ) as persistence,
            patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle") as lifecycle,
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_runtime",
                return_value=["connector cursor: roster active is missing"],
            ) as runtime,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(self.app, snapshot, RuntimeError("failed"))

        message = str(raised.exception)
        self.assertIn("pre-reconciliation persistence verification unavailable", message)
        self.assertIn("runtime reconciliation was skipped", message)
        self.assertIn("config.yaml differs", message)
        self.assertIn("connector cursor: roster active is missing", message)
        self.assertNotIn(private_detail, message)
        self.assertNotIn("private-profile", message)
        self.assertEqual(persistence.call_count, 2)
        lifecycle.assert_not_called()
        runtime.assert_called_once()

    def test_runtime_artifact_capture_redacts_private_path_errors(self):
        private_detail = os.path.abspath(os.path.join(self.tmp_dir, "secret-profile", "registration.json"))
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_protected_setup_file",
                side_effect=OSError(private_detail),
            ),
            self.assertRaises(OSError) as raised,
        ):
            cmd_setup._capture_setup_runtime_file(private_detail, "hook registration")

        message = str(raised.exception)
        self.assertIn("hook registration evidence", message)
        self.assertNotIn(private_detail, message)
        self.assertNotIn("secret-profile", message)

    def test_protected_snapshot_open_error_redacts_private_path(self):
        private_detail = os.path.abspath(os.path.join(self.tmp_dir, "private-profile", "config.yaml"))
        with (
            patch(
                "defenseclaw.commands.cmd_setup.open_regular_file_no_follow",
                side_effect=OSError(private_detail),
            ),
            self.assertRaises(OSError) as raised,
        ):
            cmd_setup._capture_protected_setup_file(private_detail, 4096, "config.yaml")

        self.assertIn("config.yaml rollback source is unavailable", str(raised.exception))
        self.assertNotIn(private_detail, str(raised.exception))
        self.assertNotIn("private-profile", str(raised.exception))

    def test_name_stable_failed_registration_path_cannot_report_exact_success(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        failed_path = os.path.abspath(os.path.join(self.tmp_dir, "private-profile", "failed-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        prior_entry = {"locations": {"hook_config_paths": [prior_path]}}
        snapshot, prior_lock = self._snapshot_with_registration_lock({"codex": prior_entry})
        failed_entry = {"locations": {"hook_config_paths": [failed_path]}}
        atomic_write_private_bytes(failed_path, b"failed-generation-b\n")
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body({"codex": failed_entry}),
        )
        _normalized, failed_identity, _fingerprint = cmd_setup._capture_setup_runtime_location(
            failed_path, "hook registration"
        )

        with (
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
            patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle"),
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                side_effect=lambda _cfg, required=(): self._post_runtime(snapshot, required),
            ),
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app, snapshot, click.ClickException("readiness failed")
            )

        message = str(raised.exception)
        self.assertIn("rollback was incomplete", message)
        self.assertIn("failed hook registration", message)
        self.assertIn(failed_identity[:12], message)
        self.assertNotIn(failed_path, message)
        self.assertNotIn("private-profile", message)
        self.assertLess(len(message), 2048)
        self.assertEqual(open(failed_path, "rb").read(), b"failed-generation-b\n")
        self.assertEqual(
            open(os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"), "rb").read(),
            prior_lock,
        )

    def test_name_stable_reconciliation_removes_failed_path_and_restores_exact_runtime(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        failed_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "failed-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        snapshot, prior_lock = self._snapshot_with_registration_lock(
            {"codex": {"locations": {"hook_config_paths": [prior_path]}}}
        )
        atomic_write_private_bytes(failed_path, b"failed-generation-b\n")
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body({"codex": {"locations": {"hook_config_paths": [failed_path]}}}),
        )

        def reconcile(_app, _snapshot):
            os.remove(failed_path)

        with (
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
            patch(
                "defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle",
                side_effect=reconcile,
            ) as lifecycle,
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                side_effect=lambda _cfg, required=(): self._post_runtime(snapshot, required),
            ) as runtime,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app, snapshot, click.ClickException("readiness failed")
            )

        self.assertIn("restored the prior connector configuration and runtime", str(raised.exception))
        self.assertFalse(os.path.exists(failed_path))
        self.assertEqual(open(prior_path, "rb").read(), b"prior-a\n")
        self.assertEqual(
            open(os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"), "rb").read(),
            prior_lock,
        )
        lifecycle.assert_called_once_with(self.app, snapshot)
        runtime.assert_called_once()
        self.assertEqual(runtime.call_args.args[0], self.app.cfg)
        self.assertEqual(len(runtime.call_args.args[1]), 1)

    def test_failed_location_reappearing_during_final_capture_is_incomplete(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        failed_path = os.path.abspath(os.path.join(self.tmp_dir, "private-race", "failed-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        snapshot, _prior_lock = self._snapshot_with_registration_lock(
            {"codex": {"locations": {"hook_config_paths": [prior_path]}}}
        )
        atomic_write_private_bytes(failed_path, b"failed-generation-b\n")
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body({"codex": {"locations": {"hook_config_paths": [failed_path]}}}),
        )
        samples = 0

        def reconcile(_app, _snapshot):
            os.remove(failed_path)

        def capture_final(_cfg, required):
            nonlocal samples
            samples += 1
            if samples == 2:
                atomic_write_private_bytes(failed_path, b"reappeared-b\n")
            return self._post_runtime(snapshot, required)

        with (
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
            patch(
                "defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle",
                side_effect=reconcile,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=capture_final,
            ) as capture,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app, snapshot, click.ClickException("readiness failed")
            )

        message = str(raised.exception)
        self.assertIn("rollback was incomplete", message)
        self.assertIn("failed hook registration", message)
        self.assertNotIn("restored the prior connector configuration and runtime", message)
        self.assertNotIn(failed_path, message)
        self.assertNotIn("private-race", message)
        self.assertEqual(capture.call_count, 3)

    def test_failed_location_oscillation_between_final_samples_is_incomplete(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        failed_path = os.path.abspath(os.path.join(self.tmp_dir, "private-oscillation", "failed-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        snapshot, _prior_lock = self._snapshot_with_registration_lock(
            {"codex": {"locations": {"hook_config_paths": [prior_path]}}}
        )
        atomic_write_private_bytes(failed_path, b"failed-generation-b\n")
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body({"codex": {"locations": {"hook_config_paths": [failed_path]}}}),
        )
        samples = 0

        def reconcile(_app, _snapshot):
            os.remove(failed_path)

        def capture_final(_cfg, required):
            nonlocal samples
            samples += 1
            if samples % 2:
                atomic_write_private_bytes(failed_path, b"oscillating-b\n")
            else:
                os.remove(failed_path)
            return self._post_runtime(snapshot, required)

        with (
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
            patch(
                "defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle",
                side_effect=reconcile,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime_once",
                side_effect=capture_final,
            ) as capture,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app, snapshot, click.ClickException("readiness failed")
            )

        message = str(raised.exception)
        self.assertIn("rollback was incomplete", message)
        self.assertIn("applied runtime verification unavailable", message)
        self.assertNotIn("restored the prior connector configuration and runtime", message)
        self.assertNotIn(failed_path, message)
        self.assertNotIn("private-oscillation", message)
        self.assertEqual(capture.call_count, cmd_setup._SETUP_RUNTIME_SNAPSHOT_ATTEMPTS)

    def test_multi_connector_name_stable_failed_location_union_is_verified(self):
        codex_a = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "codex-a.json"))
        codex_b = os.path.abspath(os.path.join(self.tmp_dir, "private-multi", "codex-b.json"))
        cursor_a = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "cursor-a.json"))
        atomic_write_private_bytes(codex_a, b"codex-a\n")
        atomic_write_private_bytes(cursor_a, b"cursor-a\n")
        prior_entries = {
            "codex": {"locations": {"hook_config_paths": [codex_a]}},
            "cursor": {"locations": {"hook_config_paths": [cursor_a]}},
        }
        snapshot, _prior_lock = self._snapshot_with_registration_lock(prior_entries)
        atomic_write_private_bytes(codex_b, b"codex-b-failed\n")
        failed_entries = {
            "codex": {"locations": {"hook_config_paths": [codex_b]}},
            "cursor": {"locations": {"hook_config_paths": [cursor_a]}},
        }
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body(failed_entries),
        )

        with (
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
            patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle"),
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                side_effect=lambda _cfg, required=(): self._post_runtime(snapshot, required),
            ),
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app, snapshot, click.ClickException("multi readiness failed")
            )

        message = str(raised.exception)
        self.assertIn("connector codex: failed hook registration", message)
        self.assertNotIn("connector cursor: failed hook registration", message)
        self.assertNotIn(codex_b, message)
        self.assertNotIn("private-multi", message)
        self.assertEqual(open(cursor_a, "rb").read(), b"cursor-a\n")

    def test_failed_location_with_proven_prior_fingerprint_is_restored_not_deleted(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        reused_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "existing-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        prior_reused = b"operator-existing-b\n"
        atomic_write_private_bytes(reused_path, prior_reused)
        prior_entry = {
            "locations": {
                "hook_config_paths": [prior_path],
                "telemetry_config_paths": [reused_path],
            }
        }
        snapshot, prior_lock = self._snapshot_with_registration_lock({"codex": prior_entry})
        atomic_write_private_bytes(reused_path, b"failed-owned-b\n")
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body({"codex": {"locations": {"hook_config_paths": [reused_path]}}}),
        )

        def reconcile(_app, _snapshot):
            atomic_write_private_bytes(reused_path, prior_reused)

        with (
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
            patch(
                "defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle",
                side_effect=reconcile,
            ),
            patch(
                "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                side_effect=lambda _cfg, required=(): self._post_runtime(snapshot, required),
            ),
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(
                self.app, snapshot, click.ClickException("readiness failed")
            )

        self.assertIn("restored the prior connector configuration and runtime", str(raised.exception))
        self.assertEqual(open(reused_path, "rb").read(), prior_reused)
        self.assertEqual(
            open(os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"), "rb").read(),
            prior_lock,
        )

    def test_untrusted_failed_location_evidence_is_incomplete_redacted_and_never_scanned(self):
        prior_path = os.path.abspath(os.path.join(self.tmp_dir, "registrations", "prior-a.json"))
        failed_path = os.path.abspath(os.path.join(self.tmp_dir, "secret-location", "failed-b.json"))
        atomic_write_private_bytes(prior_path, b"prior-a\n")
        snapshot, _prior_lock = self._snapshot_with_registration_lock(
            {"codex": {"locations": {"hook_config_paths": [prior_path]}}}
        )
        failed_lock = self._lock_body({"codex": {"locations": {"hook_config_paths": [failed_path]}}})

        for label, error in (
            ("tampered", ValueError(failed_path)),
            ("untrusted", PermissionError(failed_path)),
            ("unreadable", OSError(failed_path)),
        ):
            with self.subTest(label=label):
                atomic_write_private_bytes(
                    os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
                    failed_lock,
                )
                with (
                    patch(
                        "defenseclaw.commands.cmd_setup._capture_setup_lock_registration_locations_once",
                        side_effect=error,
                    ) as capture,
                    patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa"),
                    patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle"),
                    patch(
                        "defenseclaw.commands.cmd_setup._capture_setup_applied_runtime",
                        side_effect=lambda _cfg, required=(): self._post_runtime(snapshot, required),
                    ),
                    patch(
                        "defenseclaw.commands.cmd_setup.os.walk", side_effect=AssertionError("wildcard scan")
                    ) as walk,
                    self.assertRaises(click.ClickException) as raised,
                ):
                    cmd_setup._rollback_failed_connector_application(
                        self.app, snapshot, click.ClickException("readiness failed")
                    )

                message = str(raised.exception)
                self.assertIn("failed-generation registration evidence unavailable", message)
                self.assertIn("rollback was incomplete", message)
                self.assertNotIn(failed_path, message)
                self.assertNotIn("secret-location", message)
                self.assertLess(len(message), 2048)
                self.assertEqual(capture.call_count, cmd_setup._SETUP_RUNTIME_SNAPSHOT_ATTEMPTS)
                walk.assert_not_called()

    def test_failed_lock_relative_location_is_rejected_without_scan_or_identity_exposure(self):
        private_identity = os.path.join("secret-location", "failed-b.json")
        atomic_write_private_bytes(
            os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json"),
            self._lock_body({"codex": {"locations": {"hook_config_paths": [private_identity]}}}),
        )
        with (
            patch("defenseclaw.commands.cmd_setup.os.walk", side_effect=AssertionError("wildcard scan")) as walk,
            self.assertRaises(OSError) as raised,
        ):
            cmd_setup._capture_failed_setup_registration_locations(self.app.cfg)

        message = str(raised.exception)
        self.assertIn("failed-generation registration evidence did not stabilize", message)
        self.assertNotIn(private_identity, message)
        self.assertNotIn("secret-location", message)
        walk.assert_not_called()

    def test_failed_lock_absence_is_fenced_against_late_publication(self):
        published = self._lock_body({"codex": {"locations": {"hook_config_paths": []}}})
        with (
            patch(
                "defenseclaw.commands.cmd_setup._capture_protected_setup_file",
                side_effect=[(False, b"", None), (True, published, (1, 2, len(published), 3))],
            ),
            self.assertRaisesRegex(OSError, "hook contract changed"),
        ):
            cmd_setup._capture_setup_lock_registration_locations_once(self.app.cfg)

    def test_restore_prior_stopped_lifecycle_reconciles_then_stops_failed_setup_gateway(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(lifecycle="stopped", generation=None),
        )
        trust = MagicMock(trusted=True)
        with (
            patch("defenseclaw.commands.cmd_setup._restart_restored_connector_runtime") as reconcile,
            patch("defenseclaw.commands.cmd_doctor._trusted_gateway_listener", return_value=trust),
            patch("defenseclaw.commands.cmd_setup._stop_defense_gateway_native", return_value=True) as stop,
        ):
            cmd_setup._restore_prior_setup_lifecycle(self.app, snapshot)

        reconcile.assert_called_once_with(self.app)
        stop.assert_called_once_with(self.app.cfg.data_dir)

    def test_restore_prior_stopped_lifecycle_requires_trusted_reconciled_gateway(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(lifecycle="stopped", generation=None),
        )
        trust = MagicMock(trusted=False, code="foreign_process")
        with (
            patch("defenseclaw.commands.cmd_setup._restart_restored_connector_runtime") as reconcile,
            patch("defenseclaw.commands.cmd_doctor._trusted_gateway_listener", return_value=trust),
            patch("defenseclaw.commands.cmd_setup._stop_defense_gateway_native") as stop,
            self.assertRaisesRegex(OSError, "restored gateway cleanup is unavailable"),
        ):
            cmd_setup._restore_prior_setup_lifecycle(self.app, snapshot)

        reconcile.assert_called_once_with(self.app)
        stop.assert_not_called()

    def test_restore_prior_stopped_lifecycle_stops_after_readiness_failure(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(lifecycle="stopped", generation=None),
        )
        readiness_error = RuntimeError("readiness failed after process start")
        trust = MagicMock(trusted=True)
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_restored_connector_runtime",
                side_effect=readiness_error,
            ),
            patch("defenseclaw.commands.cmd_doctor._trusted_gateway_listener", return_value=trust),
            patch("defenseclaw.commands.cmd_setup._stop_defense_gateway_native", return_value=True) as stop,
            self.assertRaises(RuntimeError) as raised,
        ):
            cmd_setup._restore_prior_setup_lifecycle(self.app, snapshot)

        self.assertIs(raised.exception, readiness_error)
        stop.assert_called_once_with(self.app.cfg.data_dir)

    def test_restore_prior_stopped_lifecycle_reports_untrusted_cleanup_after_readiness_failure(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(lifecycle="stopped", generation=None),
        )
        readiness_error = RuntimeError("readiness failed after process start")
        trust = MagicMock(trusted=False, code="foreign_process")
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_restored_connector_runtime",
                side_effect=readiness_error,
            ),
            patch("defenseclaw.commands.cmd_doctor._trusted_gateway_listener", return_value=trust),
            patch("defenseclaw.commands.cmd_setup._stop_defense_gateway_native") as stop,
            self.assertRaisesRegex(OSError, "restart failed.*cleanup incomplete") as raised,
        ):
            cmd_setup._restore_prior_setup_lifecycle(self.app, snapshot)

        self.assertIs(raised.exception.__cause__, readiness_error)
        self.assertIn(cmd_setup._setup_runtime_ref("foreign_process"), str(raised.exception))
        stop.assert_not_called()

    def test_restore_prior_stopped_lifecycle_aggregates_stop_failure_after_readiness_failure(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(lifecycle="stopped", generation=None),
        )
        readiness_error = RuntimeError("readiness failed after process start")
        trust = MagicMock(trusted=True)
        with (
            patch(
                "defenseclaw.commands.cmd_setup._restart_restored_connector_runtime",
                side_effect=readiness_error,
            ),
            patch("defenseclaw.commands.cmd_doctor._trusted_gateway_listener", return_value=trust),
            patch("defenseclaw.commands.cmd_setup._stop_defense_gateway_native", return_value=False) as stop,
            self.assertRaisesRegex(OSError, "restart failed.*did not stop") as raised,
        ):
            cmd_setup._restore_prior_setup_lifecycle(self.app, snapshot)

        self.assertIs(raised.exception.__cause__, readiness_error)
        stop.assert_called_once_with(self.app.cfg.data_dir)

    def test_successful_rollback_reports_exact_restoration(self):
        snapshot = replace(
            cmd_setup._capture_setup_config_snapshot(self.app.cfg),
            applied_runtime=self._evidence(),
        )
        with (
            patch("defenseclaw.commands.cmd_setup._restore_setup_config_snapshot"),
            patch(
                "defenseclaw.commands.cmd_setup._verify_restored_setup_persistence",
                side_effect=[[], []],
            ) as persistence,
            patch("defenseclaw.commands.cmd_setup._restore_prior_setup_lifecycle") as lifecycle,
            patch("defenseclaw.commands.cmd_setup._verify_restored_setup_runtime", return_value=[]) as runtime,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(self.app, snapshot, RuntimeError("failed"))

        self.assertIn("restored the prior connector configuration and runtime", str(raised.exception))
        self.assertEqual(persistence.call_count, 2)
        lifecycle.assert_called_once_with(self.app, snapshot)
        runtime.assert_called_once_with(self.app.cfg, snapshot, ())


class TestPerConnectorModeAndPreserve(unittest.TestCase):
    """SU-01 (per-connector mode write) + SU-02/ND-1 (preserve judge/strategy,
    keep the documented detection_strategy default) for the hook setup path."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        # Start from a clean, unconfigured guardrail block.
        self.app.cfg.guardrail.connector = ""
        self.app.cfg.guardrail.connectors = {}

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _setup(self, *args):
        with _setup_patches():
            return _invoke([*args, "--yes", "--no-restart"], self.app)

    # --- SU-01: per-connector mode ------------------------------------
    def test_sequential_codex_claude_action_closed_preserves_promoted_codex_posture(self):
        first = self._setup("codex", "--mode", "action", "--fail-mode", "closed")
        self.assertEqual(first.exit_code, 0, msg=first.output)

        second = self._setup("claude-code", "--mode", "action", "--fail-mode", "closed")
        self.assertEqual(second.exit_code, 0, msg=second.output)

        gc = self.app.cfg.guardrail
        self.assertEqual(set(gc.connectors), {"codex", "claudecode"})
        for connector in ("codex", "claudecode"):
            with self.subTest(connector=connector):
                self.assertEqual(gc.connectors[connector].mode, "action")
                self.assertEqual(gc.connectors[connector].hook_fail_mode, "closed")
                self.assertEqual(gc.effective_mode(connector), "action")
                self.assertEqual(gc.effective_hook_fail_mode(connector), "closed")

    def test_omnigent_doctor_repair_command_preserves_roster_peers_lock_and_posture(self):
        gc = self.app.cfg.guardrail
        gc.mode = "observe"
        gc.hook_fail_mode = "closed"
        gc.connector = "claudecode"
        self.app.cfg.claw.mode = "claudecode"
        gc.connectors = {
            "claudecode": PerConnectorGuardrailConfig(mode="action", hook_fail_mode="closed"),
            "codex": PerConnectorGuardrailConfig(mode="observe", hook_fail_mode="open"),
            "cursor": PerConnectorGuardrailConfig(mode="observe", hook_fail_mode="open"),
            "omnigent": PerConnectorGuardrailConfig(
                mode="action",
                hook_fail_mode="closed",
                hilt=HILTConfig(enabled=True, min_severity="LOW"),
            ),
        }
        peer_posture = copy.deepcopy({name: gc.connectors[name] for name in ("claudecode", "codex", "cursor")})
        lock_path = os.path.join(self.app.cfg.data_dir, "hook_contract_lock.json")
        lock_body = (
            b'{"version":2,"connectors":{"claudecode":{"compatibility_status":"known"},'
            b'"codex":{"compatibility_status":"known"},'
            b'"cursor":{"compatibility_status":"known"},'
            b'"omnigent":{"compatibility_status":"known"}}}\n'
        )
        atomic_write_private_bytes(lock_path, lock_body)

        command = _omnigent_setup_repair_command(self.app.cfg)
        argv = shlex.split(command, posix=True)
        self.assertEqual(argv[:3], ["defenseclaw", "setup", "omnigent"])
        with _setup_patches(), patch(
            "defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections",
            return_value=None,
        ):
            result = _invoke(argv[2:], self.app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(set(gc.connectors), {"claudecode", "codex", "cursor", "omnigent"})
        self.assertEqual(
            {name: gc.connectors[name] for name in ("claudecode", "codex", "cursor")},
            peer_posture,
        )
        self.assertEqual(gc.effective_mode("omnigent"), "action")
        self.assertEqual(gc.effective_hook_fail_mode("omnigent"), "closed")
        self.assertTrue(gc.effective_hilt("omnigent").enabled)
        self.assertEqual(gc.effective_hilt("omnigent").min_severity, "LOW")
        with open(lock_path, "rb") as lock_file:
            self.assertEqual(lock_file.read(), lock_body)

    def test_toggling_one_connector_mode_lands_per_connector(self):
        # Configure two hook connectors (codex seeded into the map), then flip
        # codex to action. The action mode must land on codex's OWN override
        # block, not the shared global field, and the peer must be untouched.
        self.assertEqual(self._setup("codex", "--mode", "observe").exit_code, 0)
        self.assertEqual(self._setup("hermes", "--mode", "observe").exit_code, 0)
        r = self._setup("codex", "--mode", "action")
        self.assertEqual(r.exit_code, 0, msg=r.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors["codex"].mode, "action")  # written per-connector
        self.assertEqual(gc.mode, "observe")  # global field NOT flipped to action
        self.assertEqual(gc.effective_mode("codex"), "action")
        self.assertEqual(gc.effective_mode("hermes"), "observe")

    def test_connector_setup_tui_unchanged_rerun_preserves_both_connectors(self):
        from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, build_wizard_args

        cases = (
            (
                "codex",
                "action",
                ("setup", "codex", "--yes", "--mode", "action"),
            ),
            (
                "claudecode",
                "observe",
                ("setup", "claude-code", "--yes", "--mode", "observe"),
            ),
        )
        for connector, effective_mode, expected_argv in cases:
            with self.subTest(connector=connector):
                gc = self.app.cfg.guardrail
                gc.enabled = True
                gc.mode = "observe"
                gc.rule_pack_dir = "global-pack"
                gc.hook_fail_mode = "open"
                gc.hilt = HILTConfig(enabled=False, min_severity="HIGH")
                gc.block_message = "global-block"
                gc.connector = "claudecode"
                self.app.cfg.claw.mode = "claudecode"
                gc.connectors = {
                    "codex": PerConnectorGuardrailConfig(
                        enabled=False,
                        mode="action",
                        rule_pack_dir="codex-pack",
                        hook_fail_mode="closed",
                        hilt=HILTConfig(enabled=True, min_severity="LOW"),
                        block_message="codex-block",
                    ),
                    "claudecode": PerConnectorGuardrailConfig(
                        enabled=True,
                        mode="observe",
                        rule_pack_dir="claude-pack",
                        hook_fail_mode="open",
                        hilt=HILTConfig(enabled=False, min_severity="MEDIUM"),
                        block_message="claude-block",
                    ),
                }
                gc.judge.enabled = True
                gc.judge.hook_connectors = ["codex"]
                gc.detection_strategy = "regex_judge"
                gc.detection_strategy_completion = "regex_judge"
                before_policies = copy.deepcopy(gc.connectors)
                before_gate = list(gc.judge.hook_connectors)

                model = SetupPanelModel(cfg=self.app.cfg, os_name="windows")
                model.open_wizard_form(SetupWizard.CONNECTOR_SETUP)
                for index, field in enumerate(model.form_fields):
                    if field.label == "Connector":
                        model.form_fields[index] = field.with_value(connector)
                        break
                model.recompute_dependent_fields()
                argv = build_wizard_args(SetupWizard.CONNECTOR_SETUP, model.form_fields)

                self.assertEqual(argv, expected_argv)
                self.assertNotIn("--replace", argv)
                with _setup_patches():
                    result = _invoke(list(argv[1:]), self.app)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertEqual(set(gc.connectors), {"codex", "claudecode"})
                self.assertEqual(gc.effective_mode(connector), effective_mode)
                self.assertEqual(gc.connectors, before_policies)
                self.assertEqual(gc.judge.hook_connectors, before_gate)
                self.assertEqual(gc.connector, "claudecode")
                self.assertEqual(self.app.cfg.claw.mode, "claudecode")

                with patch.dict(
                    os.environ,
                    {
                        "DEFENSECLAW_HOME": self.tmp_dir,
                        "DEFENSECLAW_CONFIG": os.path.join(self.tmp_dir, "config.yaml"),
                    },
                ):
                    reloaded = load()
                self.assertEqual(reloaded.guardrail.connectors, before_policies)
                self.assertEqual(reloaded.guardrail.judge.hook_connectors, before_gate)

    def test_pdf_repro_peer_mode_not_flipped(self):
        # PDF repro: `setup hermes --mode action` then `setup codex` (default
        # observe). The bug wrote the global mode, so configuring codex flipped
        # hermes back to observe. hermes must remain action.
        self.assertEqual(self._setup("hermes", "--mode", "action").exit_code, 0)
        self.assertEqual(self._setup("codex").exit_code, 0)  # default observe, ADD
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.effective_mode("hermes"), "action")
        self.assertEqual(gc.effective_mode("codex"), "observe")

    # --- SU-02: preserve operator's judge + strategy ------------------
    def test_rerun_preserves_enabled_judge_and_strategy(self):
        gc = self.app.cfg.guardrail
        gc.connector = "hermes"
        gc.connectors = {}
        gc.detection_strategy = "judge_first"
        gc.detection_strategy_completion = "regex_judge"
        gc.judge.enabled = True
        r = self._setup("hermes")
        self.assertEqual(r.exit_code, 0, msg=r.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.detection_strategy, "judge_first")  # not re-pinned
        self.assertEqual(gc.detection_strategy_completion, "regex_judge")  # preserved
        self.assertTrue(gc.judge.enabled)  # not silently disabled

    def test_fresh_setup_keeps_documented_regex_judge_default(self):
        # ND-1: a fresh hook setup no longer clobbers the documented
        # detection_strategy default (regex_judge) down to regex_only, and does
        # not force-toggle the judge.
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        r = self._setup("hermes")
        self.assertEqual(r.exit_code, 0, msg=r.output)
        self.assertEqual(self.app.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertFalse(self.app.cfg.guardrail.judge.enabled)


if __name__ == "__main__":
    unittest.main()
