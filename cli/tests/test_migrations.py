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

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw.migrations import (
    _LEGACY_FLAT_REGO_FILENAMES,
    MigrationContext,
    _migrate_0_3_0,
    _migrate_0_3_0_from_pristine,
    _migrate_0_3_0_surgical,
    _migrate_0_4_0,
    _migrate_0_5_0,
    _parse_dotenv,
    run_migrations,
)


def _write_json(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _read_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _ctx(openclaw_home: str, data_dir: str | None = None) -> MigrationContext:
    """Helper for building a migration context in tests."""
    return MigrationContext(
        openclaw_home=openclaw_home,
        data_dir=data_dir or tempfile.mkdtemp(prefix="dclaw-mig-data-"),
    )


class TestMigrate030FromPristine(unittest.TestCase):
    """Tests for the pristine-backup restore path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-")
        self.oc_json = os.path.join(self.tmp, "openclaw.json")
        self.pristine = os.path.join(self.tmp, "openclaw.json.pristine")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_restores_from_pristine_and_registers_plugin(self):
        pristine_cfg = {
            "models": {"providers": {"openai": {"key": "sk-test"}}},
            "agents": {"defaults": {"model": {"primary": "claude-sonnet-4-20250514"}}},
        }
        _write_json(self.pristine, pristine_cfg)

        current_cfg = {
            "models": {
                "providers": {
                    "openai": {"key": "sk-test"},
                    "defenseclaw": {"url": "http://localhost:8080"},
                    "litellm": {"url": "http://localhost:8081"},
                }
            },
            "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-sonnet-4-20250514"}}},
        }
        _write_json(self.oc_json, current_cfg)

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        result = _read_json(self.oc_json)
        self.assertNotIn("defenseclaw", result.get("models", {}).get("providers", {}))
        self.assertNotIn("litellm", result.get("models", {}).get("providers", {}))
        self.assertEqual(
            result["agents"]["defaults"]["model"]["primary"], "claude-sonnet-4-20250514"
        )
        self.assertIn("defenseclaw", result["plugins"]["allow"])
        self.assertEqual(result["plugins"]["entries"]["defenseclaw"]["enabled"], True)
        install_path = os.path.join(self.tmp, "extensions", "defenseclaw")
        self.assertIn(install_path, result["plugins"]["load"]["paths"])

    def test_creates_pre_migration_backup(self):
        _write_json(self.pristine, {"plugins": {}})
        _write_json(self.oc_json, {"old": True})

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        backup = self.oc_json + ".pre-0.3.0-migration"
        self.assertTrue(os.path.isfile(backup))
        self.assertEqual(_read_json(backup), {"old": True})

    def test_preserves_existing_plugin_entries(self):
        pristine_cfg = {
            "plugins": {
                "allow": ["other-plugin"],
                "entries": {"other-plugin": {"enabled": True}},
                "load": {"paths": ["/some/path"]},
            }
        }
        _write_json(self.pristine, pristine_cfg)
        _write_json(self.oc_json, {})

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        result = _read_json(self.oc_json)
        self.assertIn("other-plugin", result["plugins"]["allow"])
        self.assertIn("defenseclaw", result["plugins"]["allow"])
        self.assertIn("other-plugin", result["plugins"]["entries"])

    def test_falls_back_to_surgical_on_corrupted_pristine(self):
        with open(self.pristine, "w") as f:
            f.write("not valid json{{{")

        current_cfg = {
            "models": {
                "providers": {"defenseclaw": {"url": "http://localhost:8080"}}
            },
        }
        _write_json(self.oc_json, current_cfg)

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        result = _read_json(self.oc_json)
        self.assertNotIn("defenseclaw", result.get("models", {}).get("providers", {}))


class TestMigrate030Surgical(unittest.TestCase):
    """Tests for the surgical fallback path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-")
        self.oc_json = os.path.join(self.tmp, "openclaw.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_removes_defenseclaw_and_litellm_providers(self):
        cfg = {
            "models": {
                "providers": {
                    "openai": {"key": "sk-test"},
                    "defenseclaw": {"url": "http://localhost:8080"},
                    "litellm": {"url": "http://localhost:8081"},
                }
            },
        }
        _write_json(self.oc_json, cfg)

        _migrate_0_3_0_surgical(self.oc_json)

        result = _read_json(self.oc_json)
        providers = result["models"]["providers"]
        self.assertNotIn("defenseclaw", providers)
        self.assertNotIn("litellm", providers)
        self.assertIn("openai", providers)

    def test_restores_model_primary_defenseclaw_prefix(self):
        cfg = {
            "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-sonnet-4-20250514"}}},
        }
        _write_json(self.oc_json, cfg)

        _migrate_0_3_0_surgical(self.oc_json)

        result = _read_json(self.oc_json)
        self.assertEqual(
            result["agents"]["defaults"]["model"]["primary"], "claude-sonnet-4-20250514"
        )

    def test_restores_model_primary_litellm_prefix(self):
        cfg = {
            "agents": {"defaults": {"model": {"primary": "litellm/gpt-4o"}}},
        }
        _write_json(self.oc_json, cfg)

        _migrate_0_3_0_surgical(self.oc_json)

        result = _read_json(self.oc_json)
        self.assertEqual(result["agents"]["defaults"]["model"]["primary"], "gpt-4o")

    def test_noop_when_no_legacy_entries(self):
        cfg = {
            "models": {"providers": {"openai": {"key": "sk-test"}}},
            "agents": {"defaults": {"model": {"primary": "claude-sonnet-4-20250514"}}},
        }
        _write_json(self.oc_json, cfg)
        mtime_before = os.path.getmtime(self.oc_json)

        _migrate_0_3_0_surgical(self.oc_json)

        mtime_after = os.path.getmtime(self.oc_json)
        self.assertEqual(mtime_before, mtime_after)

    def test_noop_when_file_missing(self):
        _migrate_0_3_0_surgical(os.path.join(self.tmp, "nonexistent.json"))

    def test_noop_when_file_is_invalid_json(self):
        with open(self.oc_json, "w") as f:
            f.write("{bad json")
        _migrate_0_3_0_surgical(self.oc_json)


class TestMigrate030Dispatch(unittest.TestCase):
    """Tests for the top-level _migrate_0_3_0 dispatch logic."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-")
        self.oc_home = self.tmp
        self.oc_json = os.path.join(self.oc_home, "openclaw.json")
        self.data_dir = os.path.join(self.tmp, ".defenseclaw")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_noop_when_no_openclaw_json(self):
        _migrate_0_3_0(_ctx(self.oc_home, self.data_dir))

    @patch("defenseclaw.guardrail.pristine_backup_path")
    @patch("defenseclaw.migrations._migrate_0_3_0_from_pristine")
    def test_uses_pristine_when_available(self, mock_from_pristine, mock_pristine_path):
        _write_json(self.oc_json, {})
        mock_pristine_path.return_value = "/some/pristine/backup"

        _migrate_0_3_0(_ctx(self.oc_home, self.data_dir))

        mock_from_pristine.assert_called_once_with(self.oc_json, "/some/pristine/backup")

    @patch("defenseclaw.guardrail.pristine_backup_path")
    @patch("defenseclaw.migrations._migrate_0_3_0_surgical")
    def test_falls_back_to_surgical_when_no_pristine(self, mock_surgical, mock_pristine_path):
        _write_json(self.oc_json, {})
        mock_pristine_path.return_value = None

        _migrate_0_3_0(_ctx(self.oc_home, self.data_dir))

        mock_surgical.assert_called_once_with(self.oc_json)


class TestRunMigrations(unittest.TestCase):
    """Tests for the run_migrations orchestrator."""

    def test_applies_migrations_in_range(self):
        # 0.2.0 → 0.3.0 picks up the 0.3.0 migration only.
        with tempfile.TemporaryDirectory() as data_dir:
            count = run_migrations("0.2.0", "0.3.0", tempfile.mkdtemp(), data_dir)
        self.assertEqual(count, 1)

    def test_applies_same_version_migrations(self):
        with tempfile.TemporaryDirectory() as data_dir:
            count = run_migrations("0.3.0", "0.3.0", tempfile.mkdtemp(), data_dir)
        self.assertEqual(count, 1)

    def test_same_version_runs_only_exact_migration(self):
        calls: list[str] = []

        def record(version: str):
            def _inner(_ctx: MigrationContext) -> None:
                calls.append(version)

            return _inner

        migrations = [
            ("0.3.0", "old restore migration", record("0.3.0")),
            ("0.4.0", "same-version repair migration", record("0.4.0")),
        ]
        with patch("defenseclaw.migrations.MIGRATIONS", migrations):
            with tempfile.TemporaryDirectory() as data_dir:
                count = run_migrations("0.4.0", "0.4.0", tempfile.mkdtemp(), data_dir)

        self.assertEqual(count, 1)
        self.assertEqual(calls, ["0.4.0"])

    def test_applies_connector_v3_migration_in_range(self):
        # 0.3.x → 0.4.0 picks up the connector-v3 migration only.
        with tempfile.TemporaryDirectory() as data_dir:
            count = run_migrations("0.3.0", "0.4.0", tempfile.mkdtemp(), data_dir)
        # Only _migrate_0_4_0 is in (0.3.0, 0.4.0]; _migrate_0_3_0 is
        # NOT re-run (already applied at the prior version).
        self.assertEqual(count, 1)

    def test_applies_both_migrations_when_jumping(self):
        # 0.2.0 → 0.4.0 picks up both 0.3.0 and 0.4.0.
        with tempfile.TemporaryDirectory() as data_dir:
            count = run_migrations("0.2.0", "0.4.0", tempfile.mkdtemp(), data_dir)
        self.assertEqual(count, 2)

    def test_skips_future_migrations(self):
        with tempfile.TemporaryDirectory() as data_dir:
            count = run_migrations("0.1.0", "0.2.0", tempfile.mkdtemp(), data_dir)
        self.assertEqual(count, 0)

    def test_migration_failure_does_not_abort_run(self):
        """A raised exception in one migration must not skip the next.

        Cursor-model semantics: ``count`` reports SUCCEEDED migrations
        (the number reported in ``cmd_upgrade``'s "Applied N
        migration(s)" line). A failed migration does NOT increment
        the counter and is NOT marked applied in the cursor — so the
        next upgrade replays only the one that failed, while the
        siblings stay marked.
        """
        calls: list[str] = []

        def fail(_ctx: MigrationContext) -> None:
            calls.append("0.3.0")
            raise RuntimeError("boom")

        def succeed(_ctx: MigrationContext) -> None:
            calls.append("0.4.0")

        migrations = [
            ("0.3.0", "failing migration", fail),
            ("0.4.0", "next migration", succeed),
        ]
        with patch("defenseclaw.migrations.MIGRATIONS", migrations):
            with tempfile.TemporaryDirectory() as data_dir:
                count = run_migrations("0.2.0", "0.4.0", tempfile.mkdtemp(), data_dir)
                # Cursor records 0.4.0 as applied (succeeded) but not
                # 0.3.0 (failed); a re-run will retry 0.3.0 only.
                cursor = _read_json(os.path.join(data_dir, ".migration_state.json"))
                self.assertEqual(cursor["applied"], ["0.4.0"])
        self.assertEqual(count, 1)
        self.assertEqual(calls, ["0.3.0", "0.4.0"])

    def test_partial_failure_only_replays_failed_migration_on_rerun(self):
        """End-to-end proof of the cursor's main job.

        Run 1: A fails, B succeeds. Cursor records only B.
        Run 2: cursor present; B is skipped, A retried (this time
               succeeds). Cursor records both.
        """
        attempts: dict[str, int] = {"0.3.0": 0, "0.4.0": 0}

        def flaky(_ctx: MigrationContext) -> None:
            attempts["0.3.0"] += 1
            if attempts["0.3.0"] == 1:
                raise RuntimeError("transient")

        def stable(_ctx: MigrationContext) -> None:
            attempts["0.4.0"] += 1

        migrations = [
            ("0.3.0", "flaky", flaky),
            ("0.4.0", "stable", stable),
        ]
        with patch("defenseclaw.migrations.MIGRATIONS", migrations):
            with tempfile.TemporaryDirectory() as data_dir:
                run_migrations("0.2.0", "0.4.0", tempfile.mkdtemp(), data_dir)
                run_migrations("0.4.0", "0.4.0", tempfile.mkdtemp(), data_dir)
        # 0.3.0 retried; 0.4.0 ran exactly once (cursor protected it).
        # Same-version reapply on the second run targets only ver==to
        # which is 0.4.0 — but the cursor already says applied AND
        # same-version-reapply bypasses for ver==to, so 0.4.0 runs a
        # second time. That's the documented escape-hatch behavior;
        # the assertion below pins it.
        self.assertEqual(attempts["0.3.0"], 2)  # failed, then succeeded
        self.assertEqual(attempts["0.4.0"], 2)  # ran in run1; same-version reapply re-fired in run2

    def test_corrupt_cursor_treated_as_missing(self):
        """A garbage cursor file must not crash the upgrade flow."""
        with tempfile.TemporaryDirectory() as data_dir:
            cursor_path = os.path.join(data_dir, ".migration_state.json")
            with open(cursor_path, "w") as f:
                f.write("{not valid json")
            count = run_migrations("0.2.0", "0.3.0", tempfile.mkdtemp(), data_dir)
            # Bootstrapped from from_version=0.2.0 → no pre-marks → 0.3.0 ran.
            self.assertEqual(count, 1)
            # A fresh, well-formed cursor exists post-run.
            cursor = _read_json(cursor_path)
            self.assertIn("0.3.0", cursor["applied"])

    def test_data_dir_defaults_to_env_then_home(self):
        """When data_dir is not passed, env override is honored.

        Uses a real temp dir for the env override (the legacy test
        relied on ``/nonexistent/dclaw`` short-circuiting; with the
        cursor model the loader needs a writable dir to persist
        state).
        """
        with tempfile.TemporaryDirectory() as env_dir, \
             patch.dict(os.environ, {"DEFENSECLAW_HOME": env_dir}):
            count = run_migrations("0.3.0", "0.4.0", tempfile.mkdtemp())
            self.assertTrue(
                os.path.exists(os.path.join(env_dir, ".migration_state.json")),
                "run_migrations should persist the cursor under $DEFENSECLAW_HOME",
            )
        self.assertEqual(count, 1)


# ---------------------------------------------------------------------------
# 0.4.0 — connector architecture v3 (PR #194)
# ---------------------------------------------------------------------------


class TestMigrate040TokenBootstrap(unittest.TestCase):
    """The first-boot token must exist after migration so the new
    fail-closed empty-token check doesn't lock pre-v3 installs out of
    /api/v1/inspect/* and connector hook endpoints."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-040-")
        self.data_dir = os.path.join(self.tmp, "data")
        self.oc_home = os.path.join(self.tmp, "openclaw")
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.oc_home, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_synthesises_token_when_env_missing(self):
        ctx = _ctx(self.oc_home, self.data_dir)
        _migrate_0_4_0(ctx)

        env_path = os.path.join(self.data_dir, ".env")
        self.assertTrue(os.path.isfile(env_path))
        kv = _parse_dotenv(env_path)
        token = kv.get("DEFENSECLAW_GATEWAY_TOKEN", "")
        # 32 bytes hex == 64 chars
        self.assertEqual(len(token), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in token))
        # File mode is 0o600.
        mode = stat.S_IMODE(os.stat(env_path).st_mode)
        self.assertEqual(mode, 0o600)
        # Change log contains the bootstrap entry.
        self.assertTrue(
            any("DEFENSECLAW_GATEWAY_TOKEN" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_preserves_existing_token(self):
        env_path = os.path.join(self.data_dir, ".env")
        with open(env_path, "w") as f:
            f.write("DEFENSECLAW_GATEWAY_TOKEN=my-existing-token\n")

        ctx = _ctx(self.oc_home, self.data_dir)
        _migrate_0_4_0(ctx)

        kv = _parse_dotenv(env_path)
        self.assertEqual(kv["DEFENSECLAW_GATEWAY_TOKEN"], "my-existing-token")
        # No change recorded for the bootstrap step.
        self.assertFalse(
            any("generated first-boot DEFENSECLAW_GATEWAY_TOKEN" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_renames_legacy_openclaw_token_var(self):
        """Operators on 0.2.x had OPENCLAW_GATEWAY_TOKEN; we promote to
        the new canonical name without rotating the secret value."""
        env_path = os.path.join(self.data_dir, ".env")
        with open(env_path, "w") as f:
            f.write("OPENCLAW_GATEWAY_TOKEN=legacy-secret-123\n")

        ctx = _ctx(self.oc_home, self.data_dir)
        _migrate_0_4_0(ctx)

        kv = _parse_dotenv(env_path)
        self.assertEqual(kv.get("DEFENSECLAW_GATEWAY_TOKEN"), "legacy-secret-123")
        self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", kv)
        self.assertTrue(
            any("renamed legacy OPENCLAW_GATEWAY_TOKEN" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_token_bootstrap_preserves_comments_and_unrelated_lines(self):
        env_path = os.path.join(self.data_dir, ".env")
        with open(env_path, "w") as f:
            f.write("# operator note\n")
            f.write("OPENCLAW_GATEWAY_TOKEN=legacy-secret-123\n")
            f.write("\n")
            f.write("export CUSTOM_SETTING=keep-me\n")
            f.write("not dotenv syntax but intentional\n")

        ctx = _ctx(self.oc_home, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(env_path) as f:
            text = f.read()
        self.assertIn("# operator note\n", text)
        self.assertIn("export CUSTOM_SETTING=keep-me\n", text)
        self.assertIn("not dotenv syntax but intentional\n", text)
        self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=legacy-secret-123\n", text)
        self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", text)

    def test_idempotent(self):
        ctx1 = _ctx(self.oc_home, self.data_dir)
        _migrate_0_4_0(ctx1)
        env_path = os.path.join(self.data_dir, ".env")
        token_before = _parse_dotenv(env_path)["DEFENSECLAW_GATEWAY_TOKEN"]

        # Re-run — token must not rotate.
        ctx2 = _ctx(self.oc_home, self.data_dir)
        _migrate_0_4_0(ctx2)

        token_after = _parse_dotenv(env_path)["DEFENSECLAW_GATEWAY_TOKEN"]
        self.assertEqual(token_before, token_after)


class TestMigrate040PermsTighten(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-040-perms-")
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_tightens_loose_perms_on_secret_files(self):
        device_key = os.path.join(self.data_dir, "device.key")
        with open(device_key, "w") as f:
            f.write("secretkey")
        os.chmod(device_key, 0o644)

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        mode = stat.S_IMODE(os.stat(device_key).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertTrue(
            any("tightened perms on device.key" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_noop_when_already_0o600(self):
        device_key = os.path.join(self.data_dir, "device.key")
        with open(device_key, "w") as f:
            f.write("secretkey")
        os.chmod(device_key, 0o600)

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        self.assertFalse(
            any("device.key" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_tightens_managed_connector_backup_perms(self):
        managed = os.path.join(
            self.data_dir,
            "connector_backups",
            "codex",
            "config.toml.json",
        )
        os.makedirs(os.path.dirname(managed), exist_ok=True)
        with open(managed, "w") as f:
            f.write("{}")
        os.chmod(managed, 0o644)

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        mode = stat.S_IMODE(os.stat(managed).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertTrue(
            any("connector_backups/codex/config.toml.json" in c for c in ctx.changes),
            msg=ctx.changes,
        )


class TestMigrate040LegacyCodexEnvCleanup(unittest.TestCase):
    """S8.1 / F31 — legacy global-OPENAI_BASE_URL env override files
    must be removed during upgrade."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-040-codex-")
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_removes_codex_env_sh(self):
        legacy = os.path.join(self.data_dir, "codex_env.sh")
        with open(legacy, "w") as f:
            f.write("export OPENAI_BASE_URL=http://localhost:4000\n")

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        self.assertFalse(os.path.isfile(legacy))
        self.assertTrue(
            any("codex_env.sh" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_removes_codex_dotenv(self):
        legacy = os.path.join(self.data_dir, "codex.env")
        with open(legacy, "w") as f:
            f.write("OPENAI_BASE_URL=http://localhost:4000\n")

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        self.assertFalse(os.path.isfile(legacy))

    def test_idempotent(self):
        ctx1 = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx1)
        ctx2 = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx2)
        # Re-run does not re-remove anything (file already gone).
        self.assertFalse(
            any("codex_env" in c for c in ctx2.changes),
            msg=ctx2.changes,
        )


class TestMigrate040ClawModeNormalize(unittest.TestCase):
    """S3.1 / F9 — legacy 'nemoclaw' / 'opencode' enum values must be
    rewritten to canonical names that pass OTel schema validation."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-040-mode-")
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_rewrites_nemoclaw_to_openclaw(self):
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write("claw:\n  mode: nemoclaw\n  home_dir: ~/.openclaw\n")

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(cfg_path) as f:
            text = f.read()
        self.assertIn("mode: openclaw", text)
        self.assertNotIn("nemoclaw", text)
        self.assertTrue(
            any("nemoclaw" in c for c in ctx.changes),
            msg=ctx.changes,
        )

    def test_rewrites_opencode_to_openclaw(self):
        # opencode was a forward-looking placeholder that never
        # shipped; fall back to openclaw rather than invent a Codex
        # opt-in for the operator.
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write("claw:\n  mode: opencode\n")

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(cfg_path) as f:
            text = f.read()
        self.assertIn("mode: openclaw", text)
        self.assertNotIn("opencode", text)

    def test_does_not_touch_canonical_modes(self):
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        original = "claw:\n  mode: openclaw\n  home_dir: ~/.openclaw\n"
        with open(cfg_path, "w") as f:
            f.write(original)

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(cfg_path) as f:
            self.assertEqual(f.read(), original)

    def test_rewrites_legacy_value_with_trailing_comment(self):
        """Hand-edited configs frequently carry a YAML inline comment
        next to ``mode:``. The original regex only matched a bare
        value followed by whitespace, so a comment on the same line
        would silently skip the rewrite and leave the operator on
        a value that fails OTel schema validation."""
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "claw:\n"
                "  mode: nemoclaw  # legacy enum, retired in 0.4.0\n"
                "  home_dir: ~/.openclaw\n"
            )

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(cfg_path) as f:
            text = f.read()
        # The value flipped, the comment survived, and the line
        # ordering didn't shift.
        self.assertIn("mode: openclaw  # legacy enum, retired in 0.4.0", text)
        self.assertNotIn("nemoclaw", text)


class TestMigrate040SeedActiveConnector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-040-seed-")
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_seeds_openclaw_when_no_config(self):
        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        state_path = os.path.join(self.data_dir, "active_connector.json")
        self.assertTrue(os.path.isfile(state_path))
        with open(state_path) as f:
            state = json.load(f)
        self.assertEqual(state["name"], "openclaw")

    def test_respects_explicit_guardrail_connector(self):
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "claw:\n  mode: openclaw\n"
                "guardrail:\n  enabled: true\n  connector: codex\n"
            )

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        state_path = os.path.join(self.data_dir, "active_connector.json")
        with open(state_path) as f:
            state = json.load(f)
        self.assertEqual(state["name"], "codex")

    def test_does_not_overwrite_existing_marker(self):
        state_path = os.path.join(self.data_dir, "active_connector.json")
        with open(state_path, "w") as f:
            json.dump({"name": "claudecode"}, f)
        os.chmod(state_path, 0o600)

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(state_path) as f:
            state = json.load(f)
        self.assertEqual(state["name"], "claudecode")


class TestMigrate040NoTouchOnEmptyDataDir(unittest.TestCase):
    def test_short_circuits_when_data_dir_missing(self):
        """Operators on a fresh install (no ~/.defenseclaw) must not
        crash the migration — the new sidecar will bootstrap on first
        boot via the same firstboot.go path."""
        with tempfile.TemporaryDirectory() as tmp:
            ctx = MigrationContext(
                openclaw_home=tmp,
                data_dir=os.path.join(tmp, "does-not-exist"),
            )
            _migrate_0_4_0(ctx)
        self.assertEqual(ctx.changes, [])


class TestMigrate040SeedHookFailMode(unittest.TestCase):
    """Migration 0.4.0 surfaces ``guardrail.hook_fail_mode`` in
    pre-existing config.yaml so operators discover the new knob.

    The runtime default is "open" (matches the Go-side
    EffectiveHookFailMode + viper default) and so is the seeded
    value. The migration MUST NOT overwrite an explicit operator
    choice — including a "closed" choice we'd ourselves recommend
    against — because operators have explicit override authority over
    a no-touch upgrade migration.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-040-failmode-")
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _read_yaml(self) -> dict:
        import yaml
        with open(os.path.join(self.data_dir, "config.yaml")) as f:
            return yaml.safe_load(f) or {}

    def test_seeds_open_when_field_missing(self):
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "claw:\n  mode: openclaw\n"
                "guardrail:\n  enabled: true\n  mode: observe\n"
            )

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        data = self._read_yaml()
        self.assertEqual(data["guardrail"]["hook_fail_mode"], "open")
        self.assertTrue(any("hook_fail_mode" in c for c in ctx.changes))

    def test_does_not_overwrite_explicit_open(self):
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "claw:\n  mode: openclaw\n"
                "guardrail:\n  enabled: true\n"
                "  hook_fail_mode: open\n"
            )

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        data = self._read_yaml()
        self.assertEqual(data["guardrail"]["hook_fail_mode"], "open")
        self.assertFalse(any("hook_fail_mode" in c for c in ctx.changes))

    def test_does_not_overwrite_explicit_closed(self):
        """Operator's explicit 'closed' is sacred — we never silently
        flip a strict-policy install back to fail-open just because
        we think the new default is friendlier."""
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "claw:\n  mode: openclaw\n"
                "guardrail:\n  enabled: true\n"
                "  hook_fail_mode: closed\n"
            )

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        data = self._read_yaml()
        self.assertEqual(data["guardrail"]["hook_fail_mode"], "closed")
        self.assertFalse(any("hook_fail_mode" in c for c in ctx.changes))

    def test_preserves_comments_and_blank_lines(self):
        """Surgical insert MUST NOT round-trip the file through PyYAML.

        The previous implementation called ``yaml.safe_load`` +
        ``yaml.dump`` on the full document, which silently stripped
        every comment, blank line, and the operator's chosen key
        order. That is unacceptable in a no-touch migration that
        promises to leave operator curation intact.
        """
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        original = (
            "# DefenseClaw config — hand-edited 2026-04-01\n"
            "# DO NOT FORGET to rotate the gateway token before prod.\n"
            "\n"
            "claw:\n"
            "  mode: openclaw  # forwarded to OpenClaw 1.7+\n"
            "\n"
            "guardrail:\n"
            "  # Threshold tuned during the Q2 incident response review.\n"
            "  enabled: true\n"
            "  mode: action\n"
            "  block_message: \"Blocked by DefenseClaw — see #sec-help\"\n"
        )
        with open(cfg_path, "w") as f:
            f.write(original)

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(cfg_path) as f:
            new = f.read()

        # All five comments survived byte-for-byte.
        self.assertIn("# DefenseClaw config — hand-edited 2026-04-01", new)
        self.assertIn("# DO NOT FORGET to rotate the gateway token", new)
        self.assertIn("# forwarded to OpenClaw 1.7+", new)
        self.assertIn("# Threshold tuned during the Q2 incident response review.", new)

        # The blank line before ``guardrail:`` survived, as did the
        # operator's order (mode before block_message). PyYAML's
        # default emit alphabetises and squashes blanks; finding the
        # original ordering proves the rewrite stayed surgical.
        self.assertIn("\n\nclaw:", new)
        self.assertIn("\n\nguardrail:", new)
        self.assertLess(new.index("mode: action"), new.index("block_message"))

        # And the whole point of the migration: the new key landed
        # under guardrail with the right indentation.
        self.assertIn("  hook_fail_mode: open\n", new)
        # Sanity: the value parses correctly even with comments.
        data = self._read_yaml()
        self.assertEqual(data["guardrail"]["hook_fail_mode"], "open")

    def test_handles_four_space_indent(self):
        """Operators who use four-space YAML indent get the seeded
        line at the same indent — surgical insert mirrors the
        operator's chosen indentation rather than hard-coding two
        spaces. Without this the inserted line would render at a
        different indent and confuse PyYAML on the next save."""
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "claw:\n    mode: openclaw\n"
                "guardrail:\n    enabled: true\n    mode: observe\n"
            )

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        with open(cfg_path) as f:
            new = f.read()
        self.assertIn("    hook_fail_mode: open\n", new)
        data = self._read_yaml()
        self.assertEqual(data["guardrail"]["hook_fail_mode"], "open")

    def test_no_op_when_no_guardrail_block(self):
        """Pre-v3 configs that never opted into guardrail don't get
        a freshly-fabricated guardrail block — the operator is on
        the no-guardrail path and that's fine."""
        cfg_path = os.path.join(self.data_dir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write("claw:\n  mode: openclaw\n")

        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)

        data = self._read_yaml()
        self.assertNotIn("guardrail", data)
        self.assertFalse(any("hook_fail_mode" in c for c in ctx.changes))

    def test_no_op_when_no_config_yaml(self):
        ctx = _ctx(self.tmp, self.data_dir)
        _migrate_0_4_0(ctx)
        self.assertFalse(
            os.path.isfile(os.path.join(self.data_dir, "config.yaml"))
        )
        self.assertFalse(any("hook_fail_mode" in c for c in ctx.changes))


class TestGuardrailConfigHookFailModeRoundTrip(unittest.TestCase):
    """The Python config dataclass MUST round-trip
    ``guardrail.hook_fail_mode`` through load/save without dropping
    or mutating it. The Go sidecar reads the same YAML and must see
    a stable value, so any silent rewrite during a Python save would
    silently change the agent's policy posture.
    """

    def test_loader_normalizes_typos_to_open(self):
        from defenseclaw.config import _merge_guardrail
        gc = _merge_guardrail({"hook_fail_mode": "OpEn"}, "/tmp")
        self.assertEqual(gc.hook_fail_mode, "open")

        gc = _merge_guardrail({"hook_fail_mode": "klosed"}, "/tmp")
        # Anything other than the canonical "closed" sentinel falls
        # back to "open" — silently fail-open is strictly safer than
        # silently fail-closed. Mirrors normalizeHookFailMode in
        # internal/gateway/connector/subprocess.go.
        self.assertEqual(gc.hook_fail_mode, "open")

    def test_loader_accepts_explicit_closed(self):
        from defenseclaw.config import _merge_guardrail
        gc = _merge_guardrail({"hook_fail_mode": "closed"}, "/tmp")
        self.assertEqual(gc.hook_fail_mode, "closed")

    def test_default_is_open_when_missing(self):
        from defenseclaw.config import _merge_guardrail
        gc = _merge_guardrail({"enabled": True}, "/tmp")
        self.assertEqual(gc.hook_fail_mode, "open")


class TestMigrate050PurgeLegacyFlatPolicyBundle(unittest.TestCase):
    """0.5.0 deletes the stale flat-layout policy bundle that silently
    overrode the canonical nested layout in older installs.

    Regression context: the Go loader (``resolveRegoDir`` in
    ``internal/policy/engine.go``) used to prefer ``<dir>/`` over
    ``<dir>/rego/`` when both contained .rego files. Older installers
    wrote the bundle flat at ``<dir>/`` (≤0.3.x) and never deleted it
    on upgrade, so operators carried both copies around. The flat copy
    predated the HILT confirm branch, so prompt-stage HIGH findings
    came back as ``alert`` instead of ``confirm`` and the HILT dialog
    never appeared until tool-call time.

    The Go loader was changed to prefer the nested layout. This
    migration completes the cleanup on disk so the residue does not
    silently outlive the loader fix.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-policies-")
        self.policies = os.path.join(self.tmp, "policies")
        self.nested = os.path.join(self.policies, "rego")
        os.makedirs(self.nested, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _ctx(self) -> MigrationContext:
        return MigrationContext(
            openclaw_home=self.tmp, data_dir=self.tmp,
        )

    def _seed_canonical_bundle(self):
        # A single canonical .rego is enough — mirrors hasRegoFiles in
        # the Go loader.
        for name in ("guardrail.rego", "admission.rego"):
            with open(os.path.join(self.nested, name), "w") as f:
                f.write("package defenseclaw.placeholder\n")
        with open(os.path.join(self.nested, "data.json"), "w") as f:
            json.dump({"guardrail": {"layer": "nested"}}, f)

    def _seed_flat_bundle(self):
        for name in _LEGACY_FLAT_REGO_FILENAMES:
            with open(os.path.join(self.policies, name), "w") as f:
                f.write("package defenseclaw.legacy\n")
        with open(os.path.join(self.policies, "data.json"), "w") as f:
            json.dump({"guardrail": {"layer": "flat"}}, f)

    def test_removes_only_known_legacy_files_when_canonical_exists(self):
        self._seed_canonical_bundle()
        self._seed_flat_bundle()

        # Operator-curated custom rule that we MUST NOT delete. Any
        # *.rego at the flat path that is not on the legacy list is
        # treated as operator content.
        custom = os.path.join(self.policies, "custom_rules.rego")
        with open(custom, "w") as f:
            f.write("package operator.custom\n")

        ctx = self._ctx()
        _migrate_0_5_0(ctx)

        # Every legacy filename is gone.
        for name in _LEGACY_FLAT_REGO_FILENAMES:
            self.assertFalse(
                os.path.isfile(os.path.join(self.policies, name)),
                f"{name} should have been removed from the flat layout",
            )

        # Custom operator rules survive.
        self.assertTrue(
            os.path.isfile(custom),
            "operator-authored custom rule MUST be preserved during migration",
        )

        # The canonical bundle is untouched.
        self.assertTrue(os.path.isfile(os.path.join(self.nested, "guardrail.rego")))
        self.assertTrue(os.path.isfile(os.path.join(self.nested, "data.json")))

        # Flat data.json contents (``{"layer": "flat"}``) DIFFER from the
        # canonical (``{"layer": "nested"}``) — the migration must
        # preserve the operator-visible variant rather than silently
        # deleting it. The non-destructive contract: rename to
        # ``data.json.pre-0.5.0`` so any operator hand-edits land in an
        # obvious sidecar file. The original flat path is gone (so the
        # filesystem matches the post-fix loader's view) but the bytes
        # are still on disk.
        self.assertFalse(os.path.isfile(os.path.join(self.policies, "data.json")))
        backup = os.path.join(self.policies, "data.json.pre-0.5.0")
        self.assertTrue(
            os.path.isfile(backup),
            "differing flat data.json must be renamed (not deleted) "
            "so operator edits aren't silently lost",
        )
        with open(backup) as f:
            self.assertEqual(json.load(f), {"guardrail": {"layer": "flat"}})

        # ctx.changes records exactly what we did.
        joined = "\n".join(ctx.changes)
        self.assertIn("removed legacy flat-layout policy bundle", joined)
        self.assertIn("preserved operator-edited", joined)

    def test_removes_flat_data_json_when_byte_identical_to_nested(self):
        # When the flat copy is byte-identical to the canonical nested
        # copy it carries no operator edits — pure residue. Delete it
        # outright so we don't leave a confusing ``.pre-0.5.0`` file
        # on a clean upgrade.
        self._seed_canonical_bundle()
        # Identical bytes: write the same payload to both paths.
        identical = {"guardrail": {"layer": "nested"}}
        with open(os.path.join(self.nested, "data.json"), "w") as f:
            json.dump(identical, f)
        with open(os.path.join(self.policies, "data.json"), "w") as f:
            json.dump(identical, f)

        ctx = self._ctx()
        _migrate_0_5_0(ctx)

        self.assertFalse(os.path.isfile(os.path.join(self.policies, "data.json")))
        self.assertFalse(
            os.path.exists(os.path.join(self.policies, "data.json.pre-0.5.0")),
            "no backup should be written when the flat copy is residue",
        )
        joined = "\n".join(ctx.changes)
        self.assertIn("removed duplicate", joined)
        self.assertNotIn("preserved operator-edited", joined)

    def test_symlinked_flat_data_json_is_left_alone(self):
        # Operators sometimes symlink ``policies/data.json`` to the
        # canonical nested copy on purpose. Removing or renaming a
        # symlink could break that pattern; the migration must skip
        # symlinks even when they would resolve to identical bytes.
        self._seed_canonical_bundle()
        nested_data = os.path.join(self.nested, "data.json")
        flat_data = os.path.join(self.policies, "data.json")
        try:
            os.symlink(nested_data, flat_data)
        except (OSError, NotImplementedError):
            self.skipTest("filesystem does not support symlinks")

        ctx = self._ctx()
        _migrate_0_5_0(ctx)

        self.assertTrue(os.path.islink(flat_data), "symlink must be preserved")
        self.assertEqual(
            os.readlink(flat_data), nested_data,
            "symlink target must be unchanged",
        )

    def test_existing_backup_does_not_clobber_prior_preservation(self):
        # An operator who runs ``defenseclaw upgrade`` twice in a row
        # against a partially-migrated install must not have their
        # earlier ``.pre-0.5.0`` backup overwritten by the second pass.
        # The migration should pick a fresh suffix instead.
        self._seed_canonical_bundle()
        # Differing flat copy.
        with open(os.path.join(self.policies, "data.json"), "w") as f:
            json.dump({"guardrail": {"layer": "flat-second-pass"}}, f)
        # Pre-existing backup from a prior partial upgrade.
        old_backup = os.path.join(self.policies, "data.json.pre-0.5.0")
        with open(old_backup, "w") as f:
            json.dump({"guardrail": {"layer": "flat-first-pass"}}, f)

        ctx = self._ctx()
        _migrate_0_5_0(ctx)

        # Original backup is unchanged.
        with open(old_backup) as f:
            self.assertEqual(
                json.load(f), {"guardrail": {"layer": "flat-first-pass"}},
                "prior backup must not be clobbered",
            )
        # Second-pass content lands in a numbered suffix.
        suffixed = os.path.join(self.policies, "data.json.pre-0.5.0.1")
        self.assertTrue(
            os.path.isfile(suffixed),
            "differing flat data.json must rename to a fresh suffix when "
            "the base backup name is taken",
        )
        with open(suffixed) as f:
            self.assertEqual(json.load(f), {"guardrail": {"layer": "flat-second-pass"}})

    def test_no_op_when_canonical_layout_missing(self):
        # Operator removed the canonical bundle (or stayed on flat
        # intentionally). We MUST NOT delete the flat bundle — that
        # would leave the gateway with no policy at all.
        shutil.rmtree(self.nested)
        self._seed_flat_bundle()

        ctx = self._ctx()
        _migrate_0_5_0(ctx)

        for name in _LEGACY_FLAT_REGO_FILENAMES:
            self.assertTrue(
                os.path.isfile(os.path.join(self.policies, name)),
                f"flat {name} must survive when no canonical layout exists",
            )
        self.assertTrue(os.path.isfile(os.path.join(self.policies, "data.json")))
        self.assertEqual(ctx.changes, [])

    def test_no_op_when_canonical_dir_has_no_rego_files(self):
        # Empty rego/ directory: hasRegoFiles in the loader would also
        # fall back to the flat layout, so deleting the flat copy here
        # would brick the policy load.
        with open(os.path.join(self.nested, "data.json"), "w") as f:
            json.dump({"guardrail": {}}, f)
        self._seed_flat_bundle()

        ctx = self._ctx()
        _migrate_0_5_0(ctx)

        for name in _LEGACY_FLAT_REGO_FILENAMES:
            self.assertTrue(
                os.path.isfile(os.path.join(self.policies, name)),
                f"flat {name} must survive when canonical rego/ has no .rego files",
            )

    def test_idempotent_on_clean_install(self):
        # Fresh canonical-only install. Re-running the migration MUST
        # be a silent no-op (no warnings, no ctx.changes entries).
        self._seed_canonical_bundle()

        ctx = self._ctx()
        _migrate_0_5_0(ctx)
        self.assertEqual(ctx.changes, [])

        ctx2 = self._ctx()
        _migrate_0_5_0(ctx2)
        self.assertEqual(ctx2.changes, [])

    def test_no_op_when_data_dir_lacks_policies_dir(self):
        # ``defenseclaw setup`` was never run on this host. The migration
        # must not crash on the missing parent directory.
        bare = tempfile.mkdtemp(prefix="dclaw-mig-bare-")
        try:
            ctx = MigrationContext(openclaw_home=bare, data_dir=bare)
            _migrate_0_5_0(ctx)  # no exception
            self.assertEqual(ctx.changes, [])
        finally:
            shutil.rmtree(bare)


class TestRunMigrations050(unittest.TestCase):
    """End-to-end coverage of run_migrations for the 0.5.0 entry."""

    def test_050_runs_when_target_includes_it(self):
        with tempfile.TemporaryDirectory() as data_dir:
            policies = os.path.join(data_dir, "policies")
            nested = os.path.join(policies, "rego")
            os.makedirs(nested, exist_ok=True)
            with open(os.path.join(nested, "guardrail.rego"), "w") as f:
                f.write("package defenseclaw.placeholder\n")
            stale = os.path.join(policies, "guardrail.rego")
            with open(stale, "w") as f:
                f.write("package defenseclaw.legacy\n")

            count = run_migrations("0.4.0", "0.5.0", tempfile.mkdtemp(), data_dir)

            self.assertEqual(count, 1)
            self.assertFalse(os.path.isfile(stale))

    def test_050_skipped_when_target_below(self):
        with tempfile.TemporaryDirectory() as data_dir:
            policies = os.path.join(data_dir, "policies")
            nested = os.path.join(policies, "rego")
            os.makedirs(nested, exist_ok=True)
            with open(os.path.join(nested, "guardrail.rego"), "w") as f:
                f.write("package defenseclaw.placeholder\n")
            stale = os.path.join(policies, "guardrail.rego")
            with open(stale, "w") as f:
                f.write("package defenseclaw.legacy\n")

            # Targeting 0.4.0 only runs 0.3.0 + 0.4.0 — not 0.5.0.
            run_migrations("0.2.0", "0.4.0", tempfile.mkdtemp(), data_dir)

            # Stale file remains because 0.5.0 wasn't in range.
            self.assertTrue(os.path.isfile(stale))


if __name__ == "__main__":
    unittest.main()
