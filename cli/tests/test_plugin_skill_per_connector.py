# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Per-connector plugin/skill policy CLI (P-A, SK-4).

Covers: independent allow@one-peer + block@another-peer resolution, global
applies where no override, the new PolicyEngine ``*_for_connector`` round-trips,
runtime honoring at the admission gate, and the per-connector display maps.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_plugin import _build_plugin_actions_map, plugin
from defenseclaw.commands.cmd_skill import _build_actions_map, skill
from defenseclaw.enforce import PolicyEngine
from defenseclaw.enforce.admission import evaluate_admission

from tests.helpers import cleanup_app, make_app_context


class PolicyEngineForConnectorTests(unittest.TestCase):
    """The new disable/enable/quarantine/clear_quarantine _for_connector methods."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.pe = PolicyEngine(self.app.store)

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_disable_enable_for_connector_independent_of_global(self):
        self.pe.disable_for_connector("plugin", "p", "codex", "bad on codex")
        # codex-scoped row exists; the global row does not.
        self.assertTrue(self.app.store.has_action("plugin", "p", "runtime", "disable", "codex"))
        self.assertFalse(self.app.store.has_action("plugin", "p", "runtime", "disable"))
        # enable for codex clears only the codex row.
        self.pe.enable_for_connector("plugin", "p", "codex")
        self.assertFalse(self.app.store.has_action("plugin", "p", "runtime", "disable", "codex"))

    def test_quarantine_clear_for_connector(self):
        self.pe.quarantine_for_connector("skill", "s", "hermes", "quar")
        self.assertTrue(self.pe.is_quarantined_for_connector("skill", "s", "hermes"))
        self.assertFalse(self.pe.is_quarantined("skill", "s"))  # not global
        self.pe.clear_quarantine_for_connector("skill", "s", "hermes")
        self.assertFalse(self.pe.is_quarantined_for_connector("skill", "s", "hermes"))

    def test_global_quarantine_covers_every_connector(self):
        self.pe.quarantine("plugin", "p", "global quar")
        # most-specific-wins: no codex row, so the global one applies.
        self.assertTrue(self.pe.is_quarantined_for_connector("plugin", "p", "codex"))

    def test_connector_install_action_overrides_global_install_action(self):
        self.pe.block("plugin", "p", "global block")
        self.pe.allow_for_connector("plugin", "p", "codex", "scoped allow")
        self.assertFalse(self.pe.is_blocked_for_connector("plugin", "p", "codex"))
        self.assertTrue(self.pe.is_allowed_for_connector("plugin", "p", "codex"))
        self.assertTrue(self.pe.is_blocked_for_connector("plugin", "p", "hermes"))

        self.pe.allow("skill", "s", "global allow")
        self.pe.block_for_connector("skill", "s", "codex", "scoped block")
        self.assertTrue(self.pe.is_blocked_for_connector("skill", "s", "codex"))
        self.assertFalse(self.pe.is_allowed_for_connector("skill", "s", "codex"))
        self.assertTrue(self.pe.is_allowed_for_connector("skill", "s", "hermes"))


class PluginPerConnectorCLITests(unittest.TestCase):
    """plugin block/allow --connector resolve independently per peer."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.runner = CliRunner()
        self.pe = PolicyEngine(self.app.store)

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args):
        return self.runner.invoke(plugin, args, obj=self.app, catch_exceptions=False)

    def test_allow_one_peer_block_another_resolve_independently(self):
        r1 = self.invoke(["allow", "tool", "--connector", "hermes"])
        self.assertEqual(r1.exit_code, 0, r1.output)
        r2 = self.invoke(["block", "tool", "--connector", "codex"])
        self.assertEqual(r2.exit_code, 0, r2.output)

        self.assertTrue(self.pe.is_allowed_for_connector("plugin", "tool", "hermes"))
        self.assertFalse(self.pe.is_blocked_for_connector("plugin", "tool", "hermes"))
        self.assertTrue(self.pe.is_blocked_for_connector("plugin", "tool", "codex"))
        self.assertFalse(self.pe.is_allowed_for_connector("plugin", "tool", "codex"))
        # Neither wrote a global entry.
        self.assertFalse(self.pe.is_blocked("plugin", "tool"))
        self.assertFalse(self.pe.is_allowed("plugin", "tool"))

    def test_bare_block_is_global(self):
        r = self.invoke(["block", "p"])
        self.assertEqual(r.exit_code, 0, r.output)
        self.assertTrue(self.pe.is_blocked("plugin", "p"))
        # global block covers an arbitrary peer (most-specific-wins fallback).
        self.assertTrue(self.pe.is_blocked_for_connector("plugin", "p", "anything"))

    def test_block_already_blocked_for_connector_is_idempotent(self):
        self.invoke(["block", "p", "--connector", "codex"])
        r = self.invoke(["block", "p", "--connector", "codex"])
        self.assertEqual(r.exit_code, 0, r.output)
        self.assertIn("Already blocked for codex", r.output)

    def test_actions_map_per_connector_override(self):
        # global allow, codex block — codex view must show the block.
        self.invoke(["allow", "p"])
        self.invoke(["block", "p", "--connector", "codex"])
        codex_map = _build_plugin_actions_map(self.app.store, "codex")
        self.assertEqual(codex_map["p"].actions.install, "block")
        # a peer with no override sees the global allow.
        hermes_map = _build_plugin_actions_map(self.app.store, "hermes")
        self.assertEqual(hermes_map["p"].actions.install, "allow")


class SkillPerConnectorCLITests(unittest.TestCase):
    """skill block/allow/unblock --connector."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.active_connectors = lambda: ["codex", "hermes"]  # type: ignore[method-assign]
        self.runner = CliRunner()
        self.pe = PolicyEngine(self.app.store)

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def invoke(self, args):
        return self.runner.invoke(skill, args, obj=self.app, catch_exceptions=False)

    def test_block_allow_independent_per_peer(self):
        self.invoke(["allow", "s", "--connector", "hermes"])
        self.invoke(["block", "s", "--connector", "codex"])
        self.assertTrue(self.pe.is_allowed_for_connector("skill", "s", "hermes"))
        self.assertTrue(self.pe.is_blocked_for_connector("skill", "s", "codex"))
        self.assertFalse(self.pe.is_blocked("skill", "s"))

    def test_connector_unblock_keeps_global_block(self):
        self.invoke(["block", "s"])  # global
        self.invoke(["block", "s", "--connector", "codex"])  # peer
        r = self.invoke(["unblock", "s", "--connector", "codex"])
        self.assertEqual(r.exit_code, 0, r.output)
        # codex row cleared, global block still in force.
        self.assertFalse(self.app.store.has_action("skill", "s", "install", "block", "codex"))
        self.assertTrue(self.pe.is_blocked("skill", "s"))

    def test_unblock_no_state_for_connector(self):
        r = self.invoke(["unblock", "s", "--connector", "codex"])
        self.assertEqual(r.exit_code, 0, r.output)
        self.assertIn("no enforcement state to clear for codex", r.output)

    def test_actions_map_per_connector(self):
        self.invoke(["block", "s", "--connector", "codex"])
        codex_map = _build_actions_map(self.app.store, "codex")
        self.assertIn("s", codex_map)
        self.assertEqual(codex_map["s"].actions.install, "block")
        # global view (no connector) does not see the codex-only row.
        global_map = _build_actions_map(self.app.store)
        self.assertNotIn("s", global_map)


class AdmissionHonorsPerConnectorTests(unittest.TestCase):
    """Runtime honoring: the admission gate respects a per-connector block."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.pe = PolicyEngine(self.app.store)

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_per_connector_block_blocks_only_that_peer(self):
        self.pe.block_for_connector("plugin", "p", "codex", "blocked on codex")
        blocked = evaluate_admission(
            self.pe, policy_dir=self.app.cfg.policy_dir,
            target_type="plugin", name="p", connector="codex",
        )
        self.assertEqual(blocked.verdict, "blocked")
        # hermes has no block → not blocked (scan required, no result yet).
        other = evaluate_admission(
            self.pe, policy_dir=self.app.cfg.policy_dir,
            target_type="plugin", name="p", connector="hermes",
        )
        self.assertNotEqual(other.verdict, "blocked")

    def test_global_block_blocks_every_peer(self):
        self.pe.block("skill", "s", "global block")
        for c in ("codex", "hermes", "openclaw"):
            d = evaluate_admission(
                self.pe, policy_dir=self.app.cfg.policy_dir,
                target_type="skill", name="s", connector=c,
            )
            self.assertEqual(d.verdict, "blocked", c)


if __name__ == "__main__":
    unittest.main()
