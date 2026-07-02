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
import io
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import (
    _configured_connector_set,
    _print_observability_summary,
    _write_connector_identity,
)
from defenseclaw.commands.cmd_setup import (
    setup as setup_group,
)
from defenseclaw.config import PerConnectorGuardrailConfig

from tests.helpers import cleanup_app, make_app_context


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
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._restart_services", return_value=None))
        stack.enter_context(patch("defenseclaw.commands.cmd_setup._maybe_bring_up_local_stack", return_value=None))
        stack.enter_context(
            patch(
                "defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup",
                return_value=True,
            )
        )
        if prompt is not None:
            stack.enter_context(patch("defenseclaw.commands.cmd_setup.click.prompt", return_value=prompt))
        yield


class TestAdditiveSetupCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        self.app.cfg.save = lambda: open(self.cfg_path, "w").write("x\n")  # type: ignore[assignment]

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
            _setup_patches(),
            patch("defenseclaw.commands.cmd_setup._is_pid_alive", return_value=True),
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway") as bounce,
        ):
            result = _invoke(["hermes", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        bounce.assert_not_called()


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

    def test_windows_summary_uses_native_powershell_and_cli_filtering(self):
        self._seed_map("claudecode")

        out = self._capture_summary("claudecode", os_name="nt")

        self.assertIn("Get-Content -LiteralPath", out)
        self.assertIn("-Wait", out)
        self.assertIn("ConvertFrom-Json", out)
        self.assertIn("defenseclaw alerts --limit 25 --connector claudecode", out)
        self.assertNotIn("tail -f", out)
        self.assertNotIn("| jq", out)
        self.assertNotIn("Bash", out)
        self.assertNotIn("WSL", out)

    def test_posix_summary_retains_unix_guidance(self):
        self._seed_map("claudecode")

        out = self._capture_summary("claudecode", os_name="posix")

        self.assertIn("tail -f ~/.defenseclaw/gateway.jsonl | jq", out)
        self.assertIn("jq 'select(.connector == \"claudecode\")'", out)
        self.assertNotIn("Get-Content -LiteralPath", out)


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
    * Mutation shape mirrors setup-add: multi stays multi, the next-to-last
      removal collapses back to the legacy singular shape.
    """

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        self.app.cfg.save = lambda: open(self.cfg_path, "w").write("x\n")  # type: ignore[assignment]

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
        with patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=None) as bounce:
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

    # Removing the next-to-last collapses back to the legacy singular shape.
    def test_remove_collapses_to_singular(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce():
            result = _invoke(["remove", "cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        gc = self.app.cfg.guardrail
        self.assertEqual(gc.connectors, {})
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
            result = _invoke(["remove", "windsurf", "--yes", "--no-restart"], self.app)
        self.assertNotEqual(result.exit_code, 0)
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

    # D3=A: --restart bounces the gateway so boot-time set-diff teardown runs.
    def test_remove_restart_bounces_gateway(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce() as bounce:
            result = _invoke(["remove", "cursor", "--yes"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        bounce.assert_called_once()

    # D3=A: --no-restart does NOT bounce and warns teardown is deferred.
    def test_remove_no_restart_defers_teardown(self):
        self._seed_map("codex", "cursor")
        with self._no_restart_bounce() as bounce:
            result = _invoke(["remove", "cursor", "--yes", "--no-restart"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        bounce.assert_not_called()
        self.assertIn("--no-restart", result.output)

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
