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

"""WU1 mirror tests: per-connector guardrail overrides, resolvers,
validation, and the active_connectors() shim — kept in lockstep with
``internal/config`` (config.go / claw.go)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (  # noqa: E402
    ClawConfig,
    Config,
    GuardrailConfig,
    HILTConfig,
    PerConnectorGuardrailConfig,
    _merge_guardrail,
    load,
)


class TestActiveConnectors(unittest.TestCase):
    def test_plural_map_wins_sorted(self):
        cfg = Config(
            guardrail=GuardrailConfig(
                connector="claudecode",
                connectors={
                    "codex": PerConnectorGuardrailConfig(),
                    "antigravity": PerConnectorGuardrailConfig(),
                },
            )
        )
        self.assertEqual(cfg.active_connectors(), ["antigravity", "codex"])
        # active_connector() keeps its original precedence and is NOT
        # influenced by the connectors map: the singular guardrail.connector
        # field still wins, so legacy single-connector callers are untouched.
        self.assertEqual(cfg.active_connector(), "claudecode")

    def test_singular_when_no_map(self):
        cfg = Config(guardrail=GuardrailConfig(connector="codex"))
        self.assertEqual(cfg.active_connectors(), ["codex"])

    def test_claw_mode_fallback(self):
        cfg = Config()
        cfg.claw.mode = "zeptoclaw"
        self.assertEqual(cfg.active_connectors(), ["zeptoclaw"])

    def test_unconfigured_returns_empty(self):
        # Nothing configured (every connector marker empty, as persisted by
        # `setup remove` when the last connector is dropped): active_connectors
        # must NOT fabricate a phantom ["openclaw"]. It returns [] so fan-out
        # callers (status/aibom/list resolver) render a "no connector
        # configured" empty state instead of operating against ~/.openclaw.
        cfg = Config()
        cfg.claw.mode = ""
        self.assertFalse(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connectors(), [])

    def test_explicit_openclaw_still_lists(self):
        # A real openclaw install pins the marker (claw.mode / guardrail
        # .connector == "openclaw"), so it stays distinguishable from the
        # unconfigured case and still lists.
        cfg = Config()
        cfg.claw.mode = "openclaw"
        self.assertTrue(cfg.has_connector_configured())
        self.assertEqual(cfg.active_connectors(), ["openclaw"])
        cfg2 = Config(guardrail=GuardrailConfig(connector="openclaw"))
        cfg2.claw.mode = ""
        self.assertTrue(cfg2.has_connector_configured())
        self.assertEqual(cfg2.active_connectors(), ["openclaw"])

    def test_has_connector_configured_signals(self):
        # The predicate is True for any non-empty marker and False only when
        # all three are empty.
        self.assertFalse(
            Config(claw=ClawConfig(mode="")).has_connector_configured()
        )
        self.assertTrue(
            Config(claw=ClawConfig(mode="codex")).has_connector_configured()
        )
        self.assertTrue(
            Config(
                guardrail=GuardrailConfig(connector="codex"),
                claw=ClawConfig(mode=""),
            ).has_connector_configured()
        )
        self.assertTrue(
            Config(
                guardrail=GuardrailConfig(
                    connectors={"codex": PerConnectorGuardrailConfig()},
                ),
                claw=ClawConfig(mode=""),
            ).has_connector_configured()
        )

    def test_whitespace_keys_dropped(self):
        cfg = Config(
            guardrail=GuardrailConfig(
                connector="codex",
                connectors={"   ": PerConnectorGuardrailConfig()},
            )
        )
        self.assertEqual(cfg.active_connectors(), ["codex"])

    def test_alias_keys_deduped(self):
        # Two keys that normalize to the same connector must not make the
        # boot loop iterate that connector twice.
        cfg = Config(
            guardrail=GuardrailConfig(
                connector="codex",
                connectors={
                    "open-hands": PerConnectorGuardrailConfig(),
                    "openhands": PerConnectorGuardrailConfig(),
                },
            )
        )
        self.assertEqual(cfg.active_connectors(), ["openhands"])


class TestEffectiveResolvers(unittest.TestCase):
    def _cfg(self) -> GuardrailConfig:
        return GuardrailConfig(
            mode="observe",
            hook_fail_mode="open",
            block_message="global-msg",
            rule_pack_dir="/global/rules",
            hilt=HILTConfig(enabled=False, min_severity="HIGH"),
            connectors={
                "codex": PerConnectorGuardrailConfig(
                    mode="action",
                    hook_fail_mode="closed",
                    block_message="codex-msg",
                    rule_pack_dir="/codex/rules",
                    hilt=HILTConfig(enabled=True, min_severity="LOW"),
                ),
                "empty": PerConnectorGuardrailConfig(),
            },
        )

    def test_per_connector_override_wins(self):
        g = self._cfg()
        self.assertEqual(g.effective_mode("codex"), "action")
        self.assertEqual(g.effective_hook_fail_mode("codex"), "closed")
        self.assertEqual(g.effective_block_message("codex"), "codex-msg")
        self.assertEqual(g.effective_rule_pack_dir("codex"), "/codex/rules")
        self.assertTrue(g.effective_hilt("codex").enabled)
        self.assertEqual(g.effective_hilt("codex").min_severity, "LOW")

    def test_empty_block_inherits_global(self):
        g = self._cfg()
        self.assertEqual(g.effective_mode("empty"), "observe")
        self.assertEqual(g.effective_hook_fail_mode("empty"), "open")
        self.assertEqual(g.effective_block_message("empty"), "global-msg")
        self.assertEqual(g.effective_rule_pack_dir("empty"), "/global/rules")
        self.assertFalse(g.effective_hilt("empty").enabled)
        self.assertEqual(g.effective_hilt("empty").min_severity, "HIGH")

    def test_unknown_and_empty_connector_use_global(self):
        g = self._cfg()
        self.assertEqual(g.effective_mode("nope"), "observe")
        self.assertEqual(g.effective_hook_fail_mode(""), "open")

    def test_safe_fallbacks_when_unset(self):
        g = GuardrailConfig(mode="", hook_fail_mode="", rule_pack_dir="")
        self.assertEqual(g.effective_mode(""), "observe")
        self.assertEqual(g.effective_hook_fail_mode(""), "open")
        self.assertEqual(g.effective_block_message(""), "")
        self.assertEqual(g.effective_rule_pack_dir(""), "")

    def test_explicit_connector_fail_mode_wins_in_observe(self):
        g = GuardrailConfig(
            mode="observe",
            hook_fail_mode="closed",
            connectors={
                "codex": PerConnectorGuardrailConfig(hook_fail_mode="closed"),
                "claudecode": PerConnectorGuardrailConfig(),
            },
        )
        self.assertEqual(g.effective_hook_fail_mode("codex"), "closed")
        self.assertEqual(g.effective_hook_fail_mode("claudecode"), "open")

    def test_empty_map_equals_absent(self):
        with_empty = GuardrailConfig(mode="action", connectors={})
        absent = GuardrailConfig(mode="action")
        self.assertEqual(
            with_empty.effective_mode("codex"), absent.effective_mode("codex")
        )
        self.assertEqual(with_empty.effective_mode("codex"), "action")

    def test_connector_override_name_insensitive(self):
        # Mirrors Go TestConnectorOverride_NameInsensitive: a per-connector
        # override is honored even when the configured key differs from the
        # requested (registry-canonical) name only by case or a hyphen/
        # underscore alias. Otherwise an operator who hand-writes "OpenHands"
        # or "open-hands" would silently get the global policy.
        g = GuardrailConfig(
            mode="observe",
            block_message="global-msg",
            connectors={
                "Codex": PerConnectorGuardrailConfig(
                    mode="action", block_message="codex-msg"
                ),
                "open-hands": PerConnectorGuardrailConfig(
                    mode="action", enabled=False
                ),
            },
        )
        # Case-insensitive key.
        self.assertEqual(g.effective_mode("codex"), "action")
        self.assertEqual(g.effective_block_message("codex"), "codex-msg")
        # Alias key: canonical "openhands" resolves "open-hands".
        self.assertEqual(g.effective_mode("openhands"), "action")
        self.assertFalse(g.effective_enabled("openhands"))
        # Genuinely-absent connector still falls through to the global.
        self.assertEqual(g.effective_mode("windsurf"), "observe")

    def test_effective_enabled(self):
        # Mirrors Go EffectiveEnabled: default True; False only on an
        # explicit per-connector enabled=false override.
        g = GuardrailConfig(
            mode="action",
            connectors={
                "codex": PerConnectorGuardrailConfig(enabled=False),
                "claudecode": PerConnectorGuardrailConfig(enabled=True),
                "cursor": PerConnectorGuardrailConfig(),  # unset → default
            },
        )
        self.assertFalse(g.effective_enabled("codex"))
        self.assertTrue(g.effective_enabled("claudecode"))
        self.assertTrue(g.effective_enabled("cursor"))
        # Unknown / empty / single-connector all default True.
        self.assertTrue(g.effective_enabled("windsurf"))
        self.assertTrue(g.effective_enabled(""))
        self.assertTrue(GuardrailConfig(connector="codex").effective_enabled("codex"))


class TestGuardrailValidate(unittest.TestCase):
    def test_empty_ok(self):
        GuardrailConfig().validate()  # no raise

    def test_valid_global(self):
        GuardrailConfig(
            mode="action",
            hook_fail_mode="closed",
            hilt=HILTConfig(min_severity="LOW"),
        ).validate()

    def test_global_fields_not_validated(self):
        # Global fields predate multi-connector support and were never
        # gated by load(); validate() only checks the new connectors map,
        # so odd global values must pass rather than reject a config that
        # loads fine today.
        GuardrailConfig(
            mode="blarg",
            hook_fail_mode="halfopen",
            hilt=HILTConfig(min_severity="SPICY"),
        ).validate()

    def test_bad_connector_fail_mode_named(self):
        with self.assertRaises(ValueError) as ctx:
            GuardrailConfig(
                connectors={
                    "codex": PerConnectorGuardrailConfig(hook_fail_mode="halfopen")
                }
            ).validate()
        msg = str(ctx.exception)
        self.assertIn("guardrail.connectors['codex']", msg)
        self.assertIn("invalid hook_fail_mode", msg)

    def test_bad_connector_mode_named(self):
        with self.assertRaises(ValueError) as ctx:
            GuardrailConfig(
                connectors={"codex": PerConnectorGuardrailConfig(mode="blarg")}
            ).validate()
        msg = str(ctx.exception)
        self.assertIn("guardrail.connectors['codex']", msg)
        self.assertIn("invalid guardrail mode", msg)

    def test_empty_connector_name(self):
        with self.assertRaises(ValueError) as ctx:
            GuardrailConfig(
                connectors={"  ": PerConnectorGuardrailConfig()}
            ).validate()
        self.assertIn("empty connector name is not allowed", str(ctx.exception))

    def test_valid_connector(self):
        GuardrailConfig(
            connectors={
                "codex": PerConnectorGuardrailConfig(
                    mode="action",
                    hook_fail_mode="open",
                    hilt=HILTConfig(min_severity="CRITICAL"),
                )
            }
        ).validate()

    def test_duplicate_normalized_alias_keys_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            GuardrailConfig(
                connectors={
                    "openhands": PerConnectorGuardrailConfig(mode="action"),
                    "open-hands": PerConnectorGuardrailConfig(mode="observe"),
                }
            ).validate()
        self.assertIn("refer to the same connector", str(ctx.exception))


class TestMergeConnectors(unittest.TestCase):
    def test_absent_yields_empty(self):
        gc = _merge_guardrail({}, "/tmp")
        self.assertEqual(gc.connectors, {})

    def test_parses_connectors_with_inherit_hilt(self):
        gc = _merge_guardrail(
            {
                "mode": "observe",
                "connectors": {
                    "codex": {"mode": "action", "hook_fail_mode": "closed"},
                    "antigravity": {
                        "hilt": {"enabled": True, "min_severity": "low"}
                    },
                },
            },
            "/tmp",
        )
        self.assertEqual(set(gc.connectors), {"codex", "antigravity"})
        self.assertEqual(gc.connectors["codex"].mode, "action")
        # codex has no hilt block -> inherit (None)
        self.assertIsNone(gc.connectors["codex"].hilt)
        # antigravity has an explicit hilt block (min_severity upper-cased)
        self.assertIsNotNone(gc.connectors["antigravity"].hilt)
        self.assertEqual(gc.connectors["antigravity"].hilt.min_severity, "LOW")

    def test_hitl_alias_in_connector(self):
        gc = _merge_guardrail(
            {"connectors": {"codex": {"hitl": {"enabled": True}}}},
            "/tmp",
        )
        self.assertIsNotNone(gc.connectors["codex"].hilt)
        self.assertTrue(gc.connectors["codex"].hilt.enabled)


class TestLoadAndRoundTrip(unittest.TestCase):
    def test_load_rejects_invalid_connector_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / ".defenseclaw"
            data_dir.mkdir()
            (data_dir / "config.yaml").write_text(
                "guardrail:\n"
                "  enabled: true\n"
                "  connectors:\n"
                "    codex:\n"
                "      mode: blarg\n",
                encoding="utf-8",
            )
            with patch("defenseclaw.config.default_data_path", return_value=data_dir):
                with self.assertRaises(ValueError) as ctx:
                    load()
            self.assertIn("invalid guardrail mode", str(ctx.exception))

    def test_load_resolves_plural_connectors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / ".defenseclaw"
            data_dir.mkdir()
            (data_dir / "config.yaml").write_text(
                "guardrail:\n"
                "  enabled: true\n"
                "  connectors:\n"
                "    codex: {}\n"
                "    antigravity: {}\n",
                encoding="utf-8",
            )
            with patch("defenseclaw.config.default_data_path", return_value=data_dir):
                cfg = load()
            self.assertEqual(cfg.active_connectors(), ["antigravity", "codex"])

    def test_empty_connectors_stripped_on_save(self):
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="macos",
            )
            cfg.save()
            with open(os.path.join(tmpdir, "config.yaml")) as f:
                raw = yaml.safe_load(f)
            guardrail = raw.get("guardrail") or {}
            self.assertNotIn(
                "connectors", guardrail, "empty connectors map must be stripped"
            )

    def test_per_connector_enabled_round_trips(self):
        # An explicit enabled=false persists and reloads; an unset (None)
        # enabled must NOT serialize as `enabled: null` (Go omitempty parity).
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="macos",
                guardrail=GuardrailConfig(
                    enabled=True,
                    connectors={
                        "codex": PerConnectorGuardrailConfig(enabled=False),
                        "claudecode": PerConnectorGuardrailConfig(),  # unset
                    },
                ),
            )
            cfg.save()
            with open(os.path.join(tmpdir, "config.yaml")) as f:
                raw = yaml.safe_load(f)
            conns = raw["guardrail"]["connectors"]
            self.assertIs(conns["codex"]["enabled"], False)
            # Unset pointer must be omitted, never written as null.
            self.assertNotIn("enabled", conns["claudecode"])

            with patch("defenseclaw.config.default_data_path", return_value=Path(tmpdir)):
                reloaded = load()
            self.assertFalse(reloaded.guardrail.effective_enabled("codex"))
            self.assertTrue(reloaded.guardrail.effective_enabled("claudecode"))

    def _write_three_connector_config(self, tmpdir: str) -> None:
        """Seed a config.yaml on disk with three connectors so the
        load → mutate → save → reload cycle exercises the authoritative
        merge (which is where the removal-persistence bug lived)."""
        import yaml

        raw = {
            "config_version": 8,
            "observability": {},
            "guardrail": {
                "enabled": True,
                "connector": "antigravity",
                "connectors": {
                    "antigravity": {},
                    "claudecode": {},
                    "codex": {},
                },
            },
            "claw": {"mode": "antigravity"},
        }
        with open(os.path.join(tmpdir, "config.yaml"), "w") as f:
            yaml.safe_dump(raw, f, sort_keys=False)

    def test_connector_removal_persists_across_reload(self):
        # Regression: deleting a connector from guardrail.connectors and
        # saving must REMOVE it from disk. Before guardrail.connectors was
        # made authoritative, the non-authoritative merge rescued the
        # deleted key from the prior file, so `setup remove` silently
        # failed to persist and every reload resurrected all connectors.
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_three_connector_config(tmpdir)
            with patch("defenseclaw.config.default_data_path", return_value=Path(tmpdir)):
                cfg = load()
            self.assertEqual(set(cfg.guardrail.connectors), {"antigravity", "claudecode", "codex"})

            # Drop one connector and persist via the REAL save path.
            del cfg.guardrail.connectors["codex"]
            cfg.guardrail.connector = "antigravity"
            cfg.data_dir = tmpdir
            cfg.save()

            with open(os.path.join(tmpdir, "config.yaml")) as f:
                raw = yaml.safe_load(f)
            self.assertEqual(
                set(raw["guardrail"]["connectors"]),
                {"antigravity", "claudecode"},
                "removed connector must not be rescued from the prior file",
            )

            with patch("defenseclaw.config.default_data_path", return_value=Path(tmpdir)):
                reloaded = load()
            self.assertEqual(
                set(reloaded.guardrail.connectors), {"antigravity", "claudecode"}
            )
            self.assertNotIn("codex", reloaded.guardrail.connectors)

    def test_collapse_to_single_clears_connectors_on_disk(self):
        # Regression: collapsing the last multi-connector entry back to the
        # singular shape (connectors -> {}) must clear the on-disk map.
        # Popping the empty key let the parent guardrail merge rescue the
        # stale connectors, so the collapse never persisted.
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_three_connector_config(tmpdir)
            with patch("defenseclaw.config.default_data_path", return_value=Path(tmpdir)):
                cfg = load()

            # Collapse to the legacy singular shape.
            cfg.guardrail.connectors = {}
            cfg.guardrail.connector = "antigravity"
            cfg.claw.mode = "antigravity"
            cfg.data_dir = tmpdir
            cfg.save()

            with open(os.path.join(tmpdir, "config.yaml")) as f:
                raw = yaml.safe_load(f)
            # An explicit empty map (or absent) is fine; a stale populated
            # map is the regression.
            self.assertFalse(
                raw["guardrail"].get("connectors"),
                "collapsed connectors map must not retain stale entries on disk",
            )

            with patch("defenseclaw.config.default_data_path", return_value=Path(tmpdir)):
                reloaded = load()
            self.assertEqual(reloaded.guardrail.connectors, {})
            self.assertEqual(reloaded.guardrail.connector, "antigravity")


class TestDirResolversConnectorOverride(unittest.TestCase):
    """WU13 L1: skill_dirs/plugin_dirs/mcp_servers accept an optional
    connector override (default = active connector) and forward it to the
    connector-parameterized resolvers in connector_paths."""

    def test_skill_dirs_override_forwarded(self):
        cfg = Config(guardrail=GuardrailConfig(connector="codex"))
        with patch("defenseclaw.connector_paths.skill_dirs", return_value=["/x"]) as m:
            cfg.skill_dirs("cursor")
            cfg.skill_dirs()  # default → active connector
        self.assertEqual(m.call_args_list[0].args[0], "cursor")
        self.assertEqual(m.call_args_list[1].args[0], "codex")

    def test_plugin_dirs_override_forwarded(self):
        cfg = Config(guardrail=GuardrailConfig(connector="codex"))
        with patch("defenseclaw.connector_paths.plugin_dirs", return_value=["/x"]) as m:
            cfg.plugin_dirs("cursor")
            cfg.plugin_dirs()
        self.assertEqual(m.call_args_list[0].args[0], "cursor")
        self.assertEqual(m.call_args_list[1].args[0], "codex")

    def test_mcp_servers_override_forwarded(self):
        cfg = Config(guardrail=GuardrailConfig(connector="codex"))
        with patch("defenseclaw.connector_paths.mcp_servers", return_value=[]) as m:
            cfg.mcp_servers("cursor")
            cfg.mcp_servers()
        self.assertEqual(m.call_args_list[0].args[0], "cursor")
        self.assertEqual(m.call_args_list[1].args[0], "codex")


class TestResolveListConnector(unittest.TestCase):
    """WU13 L1: the shared ``--connector`` resolver validates against the
    configured active set and never silently falls back on a typo."""

    def _app(self, connector="claudecode", connectors=None):
        gc = GuardrailConfig(connector=connector)
        if connectors:
            gc.connectors = {
                name: PerConnectorGuardrailConfig() for name in connectors
            }
        cfg = Config(guardrail=gc)

        class _App:
            pass

        app = _App()
        app.cfg = cfg
        return app

    def test_empty_returns_active(self):
        from defenseclaw.commands import resolve_list_connector

        app = self._app(connector="codex")
        self.assertEqual(resolve_list_connector(app, ""), "codex")

    def test_valid_override_case_insensitive(self):
        from defenseclaw.commands import resolve_list_connector

        app = self._app(connector="claudecode", connectors=["codex", "cursor"])
        self.assertEqual(resolve_list_connector(app, "CURSOR"), "cursor")

    def test_valid_override_accepts_alias(self):
        from defenseclaw.commands import resolve_list_connector

        # "open-hands" is a documented alias of the registry-canonical
        # "openhands"; passing the alias must resolve the configured peer
        # rather than raising "not configured".
        app = self._app(connector="claudecode", connectors=["openhands", "codex"])
        self.assertEqual(resolve_list_connector(app, "open-hands"), "openhands")

    def test_unknown_connector_raises(self):
        import click
        from defenseclaw.commands import resolve_list_connector

        app = self._app(connector="claudecode", connectors=["codex"])
        with self.assertRaises(click.UsageError) as cm:
            resolve_list_connector(app, "nope")
        message = str(cm.exception)
        self.assertIn("Configured connectors: codex", message)
        self.assertNotIn("Active connectors:", message)


if __name__ == "__main__":
    unittest.main()
