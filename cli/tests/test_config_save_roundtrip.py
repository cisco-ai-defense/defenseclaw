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
            with self.assertRaisesRegex(config_module.ConfigVersionError, "schema version"):
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
            mode, 0o600,
            msg=(f"Config.save widened mode to {mode:o}; pre-fix umask-honoring "
                 "open() leaked secrets to group/other readers"),
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
            mode, 0o600,
            msg=(f"First-save mode = {mode:o} (want 0o600). Process umask "
                 "must not widen the new file."),
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
            mode, 0o400,
            msg=(f"Config.save widened 0o400 to {mode:o}; mode mirror was "
                 "supposed to narrow-only, not widen."),
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
            mode, 0o600,
            msg=(f"Save did not narrow legacy 0o644 to 0o600; got {mode:o}. "
                 "Upgrade path leaves credentials world-readable."),
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

            self.assertEqual(persisted["config_version"], 8)
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
                with self.assertRaisesRegex(ConfigVersionError, "schema v8"):
                    cfg.save()

    def test_fresh_v8_save_emits_only_canonical_observability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
                cfg = prepare_fresh_v8_config(default_config())
                cfg.data_dir = tmpdir
                cfg.save()

            with open(os.path.join(tmpdir, "config.yaml"), encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)

            self.assertEqual(persisted["config_version"], 8)
            self.assertEqual(persisted["observability"], {})
            for removed in ("audit_sinks", "otel", "privacy", "splunk"):
                self.assertNotIn(removed, persisted)
            self.assertNotIn("emit_otel", persisted.get("ai_discovery", {}))

    def test_fresh_v8_preparation_rejects_loaded_configs(self):
        cfg = default_config()
        cfg._source_config_version = 7
        with self.assertRaisesRegex(ValueError, "unversioned default"):
            prepare_fresh_v8_config(cfg)

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
                cfg.save()

            with open(config_path, encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)

            self.assertTrue(persisted["ai_discovery"]["enabled"])
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


class TestConfigSaveResilienceContinued(unittest.TestCase):

    def test_corrupt_yaml_falls_back_to_dataclass_only(self):
        """Operator with a half-edited YAML must still be able to recover
        by re-running setup. We log a warning but do NOT raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            # Write something yaml.safe_load can't parse.
            with open(cfg_path, "w") as f:
                f.write("config_version: 8\nobservability: [unclosed_list\n - {bad: yaml")

            cfg = _make_cfg(tmpdir)
            with self.assertLogs("defenseclaw.config", level="WARNING") as logs:
                cfg.save()
            self.assertTrue(
                any("failed to parse" in m for m in logs.output),
                msg=f"expected parse-failure warning, got {logs.output!r}",
            )

            # The malformed source is unrecoverable, but the fallback produces
            # a well-formed, schema-v8 document that setup can repair further.
            with open(cfg_path) as f:
                after = yaml.safe_load(f)
            self.assertEqual(after["data_dir"], tmpdir)

    def test_non_mapping_yaml_falls_back(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            # Top-level YAML list — invalid for our schema.
            with open(cfg_path, "w") as f:
                f.write("- not\n- a\n- mapping\n")

            cfg = _make_cfg(tmpdir)
            with self.assertLogs("defenseclaw.config", level="WARNING"):
                cfg.save()

            with open(cfg_path) as f:
                after = yaml.safe_load(f)
            self.assertIsInstance(after, dict)
            self.assertEqual(after["data_dir"], tmpdir)


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
                inode_before, inode_after,
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
