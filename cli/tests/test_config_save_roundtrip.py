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

"""Regression tests for exact-v8 ``Config.save()`` persistence.

The Python CLI applies modeled deltas over the latest on-disk document so the
canonical observability graph and future Go-owned fields survive ordinary
setup commands. Writes remain schema-validated, permission-safe, and atomic.
"""

import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import config as config_module  # noqa: E402
from defenseclaw.config import (  # noqa: E402
    Config,
    ConfigVersionError,
    _load_existing_config_yaml,
    default_config,
    load,
    prepare_fresh_v8_config,
)


class TestConfigVersionPreflight(unittest.TestCase):
    def test_invalid_utf8_is_normalized_to_config_version_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "wb") as stream:
                stream.write(b"config_version: 7\ninvalid: \xff\n")
            with self.assertRaisesRegex(config_module.ConfigVersionError, "not valid UTF-8"):
                config_module.source_config_version(path=path)


def _make_cfg(tmpdir: str, **overrides) -> Config:
    """Build a Config with the minimum required path fields for tests."""
    cfg = prepare_fresh_v8_config(default_config())
    cfg.data_dir = tmpdir
    cfg.audit_db = os.path.join(tmpdir, "audit.db")
    cfg.quarantine_dir = os.path.join(tmpdir, "quarantine")
    cfg.plugin_dir = os.path.join(tmpdir, "plugins")
    cfg.policy_dir = os.path.join(tmpdir, "policies")
    cfg.environment = "macos"
    for name, value in overrides.items():
        setattr(cfg, name, value)
    return cfg


@unittest.skipIf(os.name == "nt", "POSIX mode preservation; native Windows DACL preservation has dedicated coverage")
class TestConfigSavePreservesFileMode(unittest.TestCase):
    """P1 security regression: ``Config.save()`` must NOT widen the
    file mode of an existing config.yaml. The pre-fix path opened
    a temp via ``open(tmp, 'w')`` (umask-honoring, typically 0644)
    and ``os.replace``d it onto a 0600 live file, silently
    downgrading the mode to 0644 — exposing gateway / OTLP
    credentials carried in the file (e.g. ``gateway.token`` and named
    destination authorization headers)."""

    def test_save_preserves_existing_0600_mode(self):
        """A 0600 config.yaml stays 0600 across save."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)
            os.chmod(cfg_path, 0o600)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            mode = os.stat(cfg_path).st_mode & 0o777
        self.assertEqual(
            mode,
            0o600,
            msg=(
                f"Config.save widened mode to {mode:o}; pre-fix umask-honoring "
                "open() leaked secrets to group/other readers"
            ),
        )

    def test_save_first_create_is_0600(self):
        """A first-save (no pre-existing file) lands at 0600 — the
        explicit O_EXCL + 0o600 mode in os.open ensures the umask
        cannot widen the new file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            self.assertFalse(os.path.exists(cfg_path))

            cfg = _make_cfg(tmpdir)
            cfg.save()

            self.assertTrue(os.path.exists(cfg_path))
            mode = os.stat(cfg_path).st_mode & 0o777
        self.assertEqual(
            mode,
            0o600,
            msg=(f"First-save mode = {mode:o} (want 0o600). Process umask must not widen the new file."),
        )

    def test_save_does_not_widen_stricter_existing_mode(self):
        """A 0400 (read-only) config.yaml is not widened to 0600.
        Some operators ship 0400 by policy; save must narrow on
        existing-mode mirror, never widen."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)
            os.chmod(cfg_path, 0o400)
            # Make parent dir writable so os.replace can rename.
            os.chmod(tmpdir, 0o700)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            mode = os.stat(cfg_path).st_mode & 0o777
        # 0o400 is the stricter case — `target_mode = existing & 0o600 = 0o400`
        # so the live file lands at 0o400.
        self.assertEqual(
            mode,
            0o400,
            msg=(f"Config.save widened 0o400 to {mode:o}; mode mirror was supposed to narrow-only, not widen."),
        )

    def test_save_strips_world_readable_bits_on_legacy_0644(self):
        """If a pre-fix install left the file at 0644 (the bug we're
        fixing), the next save with this code MUST narrow it back to
        0600. This is the upgrade path: an operator running a fixed
        sidecar should see their leaky 0644 file fixed on the next
        ``defenseclaw setup`` invocation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.safe_dump({"data_dir": tmpdir, "environment": "macos"}, f)
            os.chmod(cfg_path, 0o644)

            cfg = _make_cfg(tmpdir)
            cfg.save()

            mode = os.stat(cfg_path).st_mode & 0o777
        # existing & 0o600 = 0o600, so the live file should narrow
        # from 0o644 to 0o600.
        self.assertEqual(
            mode,
            0o600,
            msg=(
                f"Save did not narrow legacy 0o644 to 0o600; got {mode:o}. "
                "Upgrade path leaves credentials world-readable."
            ),
        )


class TestConfigSaveResilience(unittest.TestCase):
    """``cfg.save()`` must succeed on a fresh install, a missing file,
    and a partially-corrupt existing file."""

    def test_first_save_with_no_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            self.assertFalse(os.path.exists(cfg_path))

            cfg = _make_cfg(tmpdir)
            cfg.save()

            self.assertTrue(os.path.exists(cfg_path))
            with open(cfg_path) as f:
                after = yaml.safe_load(f)
            self.assertEqual(after["data_dir"], tmpdir)
            self.assertNotIn("audit_sinks", after)  # nothing to preserve


class TestConfigSaveV8HardCutover(unittest.TestCase):
    def test_fresh_programmatic_config_creates_v8_without_legacy_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = default_config()
                cfg.data_dir = tmpdir
                cfg.guardrail.mode = "action"
                cfg.save()

            with open(os.path.join(tmpdir, "config.yaml"), encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)

            self.assertEqual(persisted["config_version"], 9)
            self.assertEqual(persisted["guardrail"]["mode"], "action")
            self.assertEqual(persisted["observability"], {})
            for removed in ("audit_sinks", "otel", "privacy", "splunk"):
                self.assertNotIn(removed, persisted)

    def test_unversioned_programmatic_config_cannot_overwrite_existing_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.yaml")
            with open(config_path, "w", encoding="utf-8") as stream:
                stream.write("guardrail:\n  mode: observe\n")
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = default_config()
                cfg.data_dir = tmpdir
                with self.assertRaisesRegex(ConfigVersionError, "older DefenseClaw"):
                    cfg.save()

    def test_fresh_v8_save_emits_only_canonical_observability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = prepare_fresh_v8_config(default_config())
                cfg.data_dir = tmpdir
                cfg.save()

            with open(os.path.join(tmpdir, "config.yaml"), encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)

            self.assertEqual(persisted["config_version"], 9)
            self.assertEqual(persisted["observability"], {})
            for removed in ("audit_sinks", "otel", "privacy", "splunk"):
                self.assertNotIn(removed, persisted)
            self.assertNotIn("emit_otel", persisted.get("ai_discovery", {}))
            self.assertFalse(
                persisted.get("ai_discovery", {}).get(
                    "lookup_model_provenance_online",
                    False,
                )
            )

    def test_fresh_v8_preparation_rejects_loaded_configs(self):
        cfg = default_config()
        cfg._source_config_version = 7
        with self.assertRaisesRegex(ValueError, "unversioned default"):
            prepare_fresh_v8_config(cfg)

    def test_ai_discovery_block_without_enabled_loads_disabled_and_enable_persists(self):
        # Go defaults ai_discovery.enabled to false; a block holding only a
        # privacy toggle must load as disabled so enabling it writes the flag.
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.yaml")
            with open(config_path, "w", encoding="utf-8") as stream:
                yaml.safe_dump(
                    {
                        "config_version": 8,
                        "observability": {},
                        "gateway": {"token_env": "DEFENSECLAW_GATEWAY_TOKEN"},
                        "ai_discovery": {"include_user_principal": True},
                    },
                    stream,
                    sort_keys=False,
                )
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = load()
                self.assertFalse(cfg.ai_discovery.enabled)
                cfg.ai_discovery.enabled = True
                cfg.save()

            with open(config_path, encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)

            self.assertIs(persisted["ai_discovery"]["enabled"], True)
            self.assertIs(persisted["ai_discovery"]["include_user_principal"], True)

    def test_loaded_v8_can_enable_ai_discovery_without_restoring_v7_routing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.yaml")
            with open(config_path, "w", encoding="utf-8") as stream:
                yaml.safe_dump(
                    {
                        "config_version": 8,
                        "observability": {},
                        "gateway": {"token_env": "DEFENSECLAW_GATEWAY_TOKEN"},
                    },
                    stream,
                    sort_keys=False,
                )
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = load()
                cfg.ai_discovery.enabled = True
                cfg.ai_discovery.mode = cfg.ai_discovery.mode or "enhanced"
                cfg.ai_discovery.include_shell_history = True
                cfg.ai_discovery.include_package_manifests = True
                cfg.ai_discovery.include_env_var_names = True
                cfg.ai_discovery.include_network_domains = True
                cfg.ai_discovery.lookup_model_provenance_online = True
                cfg.save()

            with open(config_path, encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)

            self.assertTrue(persisted["ai_discovery"]["enabled"])
            self.assertTrue(
                persisted["ai_discovery"]["lookup_model_provenance_online"]
            )
            self.assertNotIn("emit_otel", persisted["ai_discovery"])

    def test_loaded_v8_save_preserves_graph_and_uses_local_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            observability = {
                "local": {"path": "history/custom.db", "retention_days": 45},
                "destinations": [
                    {
                        "name": "collector",
                        "kind": "otlp",
                        "protocol": "http/protobuf",
                        "endpoint": "https://collector.example.test",
                    },
                ],
            }
            with open(cfg_path, "w", encoding="utf-8") as stream:
                yaml.safe_dump(
                    {
                        "config_version": 8,
                        "data_dir": tmpdir,
                        "observability": observability,
                    },
                    stream,
                    sort_keys=False,
                )
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = load()
                self.assertEqual(cfg.audit_db, os.path.join(tmpdir, "history", "custom.db"))
                cfg.claw.mode = "codex"
                cfg.save()

            with open(cfg_path, encoding="utf-8") as stream:
                after = yaml.safe_load(stream)
            self.assertEqual(after["config_version"], 8)
            self.assertEqual(after["observability"], observability)
            self.assertEqual(after["claw"], {"mode": "codex"})
            for removed in ("audit_db", "audit_sinks", "otel", "privacy", "splunk"):
                self.assertNotIn(removed, after)

    def test_v8_save_preserves_concurrent_observability_edit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            original = {"config_version": 8, "data_dir": tmpdir, "observability": {}}
            with open(cfg_path, "w", encoding="utf-8") as stream:
                yaml.safe_dump(original, stream, sort_keys=False)
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = load()
                concurrent = {
                    "destinations": [
                        {"name": "console", "kind": "console"},
                    ],
                }
                with open(cfg_path, "w", encoding="utf-8") as stream:
                    yaml.safe_dump({**original, "observability": concurrent}, stream, sort_keys=False)
                cfg.claw.mode = "codex"
                cfg.save()

            with open(cfg_path, encoding="utf-8") as stream:
                after = yaml.safe_load(stream)
            self.assertEqual(after["observability"], concurrent)
            self.assertEqual(after["claw"], {"mode": "codex"})


class TestGatewayFleetModeRoundTrip(unittest.TestCase):
    def test_explicit_fleet_modes_survive_load_and_noop_save_exactly(self):
        for mode in ("enabled", "disabled", "auto"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmpdir:
                config_path = os.path.join(tmpdir, "config.yaml")
                original = {
                    "config_version": 8,
                    "data_dir": tmpdir,
                    "environment": "linux",
                    "claw": {"mode": "codex"},
                    "gateway": {
                        "fleet_mode": mode,
                        "host": "fleet.example.test",
                        "port": 18_790,
                        "api_bind": "127.0.0.2",
                        "api_port": 18_971,
                    },
                    "observability": {
                        "local": {
                            "path": "history/custom.db",
                            "retention_days": 23,
                        },
                    },
                }
                with open(config_path, "w", encoding="utf-8") as stream:
                    yaml.safe_dump(original, stream, sort_keys=False)

                with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                    os.environ.pop("DEFENSECLAW_CONFIG", None)
                    cfg = load()
                    self.assertEqual(cfg.gateway.fleet_mode, mode)
                    cfg.save()
                    reloaded = load()

                with open(config_path, encoding="utf-8") as stream:
                    persisted = yaml.safe_load(stream)
                self.assertEqual(reloaded.gateway.fleet_mode, mode)
                self.assertEqual(persisted, original)

    def test_absent_fleet_mode_keeps_auto_semantics_without_being_inserted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.yaml")
            original = {
                "config_version": 8,
                "data_dir": tmpdir,
                "environment": "macos",
                "claw": {"mode": "codex"},
                "gateway": {
                    "host": "127.0.0.1",
                    "port": 18_789,
                    "api_bind": "127.0.0.1",
                    "api_port": 18_970,
                    "watcher": {"enabled": False},
                },
                "observability": {
                    "local": {
                        "path": "history/unchanged.db",
                        "retention_days": 17,
                    },
                },
            }
            with open(config_path, "w", encoding="utf-8") as stream:
                yaml.safe_dump(original, stream, sort_keys=False)

            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                os.environ.pop("DEFENSECLAW_CONFIG", None)
                cfg = load()
                self.assertEqual(cfg.gateway.fleet_mode, "")
                self.assertEqual(cfg.gateway.fleet_mode or "auto", "auto")
                cfg.save()
                reloaded = load()

            with open(config_path, encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)
            self.assertEqual(reloaded.gateway.fleet_mode or "auto", "auto")
            self.assertNotIn("fleet_mode", persisted["gateway"])
            self.assertEqual(persisted, original)



class TestConfigVersion9KeysRoundTrip(unittest.TestCase):
    def test_v9_keys_load_and_survive_an_unrelated_save(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.yaml")
            original = {
                "config_version": 8,
                "data_dir": tmpdir,
                "environment": "linux",
                "claw": {"mode": "codex"},
                "admission": {
                    "skill": {
                        "scan_on_install": False,
                        "actions": {"high": "block", "low": {"install": "none", "file": "none", "runtime": "disable"}},
                    }
                },
                "guardrail": {
                    "rule_pack": "strict",
                    "rules": {"severity_overrides": {"SEC-AWS-SECRET": "HIGH"}},
                    "connectors": {"codex": {"rules": {"disable": ["CMD-GIT-PUSH-FORCE"]}}},
                },
                "asset_policy": {"tool": {"denied": [{"name": "shell", "connector": "codex"}]}},
                "llm_providers": {"custom": [{"name": "gw", "domains": ["llm.example.internal"]}]},
                "update": {"check": False},
                "observability": {},
            }
            with open(config_path, "w", encoding="utf-8") as stream:
                yaml.safe_dump(original, stream, sort_keys=False)

            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                os.environ.pop("DEFENSECLAW_CONFIG", None)
                cfg = load()
                self.assertIs(cfg.admission.skill.scan_on_install, False)
                self.assertEqual(cfg.admission.skill.actions["high"], "block")
                self.assertEqual(cfg.guardrail.rules.severity_overrides, {"SEC-AWS-SECRET": "HIGH"})
                self.assertEqual(cfg.guardrail.connectors["codex"].rules.disable, ["CMD-GIT-PUSH-FORCE"])
                self.assertEqual(cfg.asset_policy.tool.denied[0].connector, "codex")
                self.assertEqual(cfg.llm_providers.custom[0].domains, ["llm.example.internal"])
                self.assertIs(cfg.update.check, False)
                cfg.guardrail.rules.disable = ["ENT-DATA-EMPLOYEE-ID"]
                cfg.save()

            with open(config_path, encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)
            original["guardrail"]["rules"]["disable"] = ["ENT-DATA-EMPLOYEE-ID"]
            self.assertEqual(persisted, original)

class TestConfigSaveResilienceContinued(unittest.TestCase):
    def test_corrupt_or_non_mapping_yaml_refuses_the_save(self):
        """A save over a file that no longer parses kept only the changed
        fields and dropped every other setting (GAP-0370): it is refused,
        naming the line, and the file is left as it was."""
        from defenseclaw.config_writer import ConfigUnparseableError

        for broken, words in (
            ("config_version: 9\ngateway:\n  api_port: 19020\nbroken: [unclosed\n", "not valid YAML (line"),
            ("- not\n- a\n- mapping\n", "not a mapping"),
        ):
            with tempfile.TemporaryDirectory() as tmpdir:
                cfg_path = os.path.join(tmpdir, "config.yaml")
                with open(cfg_path, "w") as f:
                    f.write(broken)
                cfg = _make_cfg(tmpdir)
                with self.assertRaises(ConfigUnparseableError) as refused:
                    cfg.save()
                self.assertIn(words, str(refused.exception))
                with open(cfg_path) as f:
                    self.assertEqual(f.read(), broken)


def test_bom_crlf_config_loads_and_saves_with_the_windows_locale(tmp_path, monkeypatch):
    """GAP-0386: Notepad and PowerShell 5 start config.yaml with a UTF-8 BOM.
    Read with the Windows locale encoding the mark became a prefix on the
    first key, and a save wrote that unknown key back (refused). A BOM and
    CRLF file loads and saves like any other."""
    import builtins

    from defenseclaw import config as config_module
    from defenseclaw.config import PerConnectorGuardrailConfig

    real_open = builtins.open

    def windows_open(file, mode="r", *args, encoding=None, **kwargs):
        if "b" not in mode and encoding is None:
            encoding = "cp1252"
        return real_open(file, mode, *args, encoding=encoding, **kwargs)

    monkeypatch.setattr(config_module, "open", windows_open, raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    cfg = _make_cfg(str(tmp_path))
    cfg.guardrail.connectors = {"opencode": PerConnectorGuardrailConfig()}
    cfg.save()
    path = tmp_path / "config.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes().replace(b"\n", b"\r\n"))

    loaded = config_module.load()
    loaded.guardrail.connectors["opencode"].mode = "action"
    loaded.save()

    saved = yaml.safe_load(path.read_bytes())
    assert loaded.data_dir == str(tmp_path) and not any(str(key).startswith("\u00ef") for key in saved)
    assert saved["guardrail"]["connectors"]["opencode"]["mode"] == "action"


class TestConfigSaveAtomicity(unittest.TestCase):
    """The save must be atomic via tmp + rename so a crash mid-write
    cannot leave a half-written ``config.yaml`` that bricks the gateway."""

    def test_save_leaves_no_tmp_file_behind(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = _make_cfg(tmpdir)
            cfg.save()
            self.assertFalse(
                os.path.exists(os.path.join(tmpdir, "config.yaml.tmp")),
            )

    def test_save_atomically_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write("config_version: 8\nobservability: {}\n")
            inode_before = os.stat(cfg_path).st_ino

            cfg = _make_cfg(tmpdir)
            cfg.save()

            self.assertTrue(os.path.exists(cfg_path))
            # On POSIX, os.replace from a tmp file changes the inode.
            # On filesystems without inode semantics this is a no-op but
            # the existence-check above still proves the write completed.
            inode_after = os.stat(cfg_path).st_ino
            self.assertNotEqual(
                inode_before,
                inode_after,
                msg="config.yaml inode unchanged — save was not atomic",
            )


class TestMergeHelpers(unittest.TestCase):
    """Unit tests for the live v8 save primitives."""

    def test_load_existing_returns_empty_on_missing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(
                _load_existing_config_yaml(os.path.join(tmpdir, "nope.yaml")),
                {},
            )

    def test_load_existing_emits_warning_on_corrupt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "bad.yaml")
            with open(path, "w") as f:
                f.write("a: [unclosed")
            with self.assertLogs("defenseclaw.config", level="WARNING") as logs:
                self.assertEqual(_load_existing_config_yaml(path), {})
            self.assertTrue(any("failed to parse" in m for m in logs.output))


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
