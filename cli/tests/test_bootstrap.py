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

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.bootstrap import BootstrapReport, _connector_readiness, bootstrap_env
from defenseclaw.config import (
    Config,
    GatewayConfig,
    GuardrailConfig,
    HILTConfig,
    OpenShellConfig,
    PerConnectorGuardrailConfig,
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
        default_broker = patch(
            "defenseclaw.credential_protection.credential_protection_default_enabled",
            return_value=False,
        )
        default_broker.start()
        self.addCleanup(default_broker.stop)
        self._prev_home = os.environ.get("DEFENSECLAW_HOME")
        os.environ["DEFENSECLAW_HOME"] = self._tmp.name
        self.addCleanup(self._restore_home)
        # bootstrap_env may adopt a token from a connector config reachable on
        # the test host and intentionally publish it into this process. Keep
        # that production behavior inside each test so a Linux validator with
        # OpenClaw installed cannot leak the token into later Doctor tests.
        self._gateway_token_env = patch.dict(
            os.environ,
            {"DEFENSECLAW_GATEWAY_TOKEN": "", "OPENCLAW_GATEWAY_TOKEN": ""},
        )
        self._gateway_token_env.start()
        self.addCleanup(self._gateway_token_env.stop)

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

    def test_first_run_uses_private_directory_creation_for_owned_state(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        created: list[str] = []

        def record_private_directory(path):
            created.append(os.path.abspath(os.fspath(path)))
            os.makedirs(path, exist_ok=True)

        with patch(
            "defenseclaw.file_permissions.make_private_directory",
            side_effect=record_private_directory,
        ):
            report = bootstrap_env(cfg)

        self.assertEqual(report.errors, [], msg=report.errors)
        for expected in (cfg.data_dir, cfg.quarantine_dir, cfg.plugin_dir, cfg.policy_dir):
            self.assertIn(os.path.abspath(expected), created)

    def test_windows_zero_link_count_accepts_regular_recovery_file(self):
        from types import SimpleNamespace

        from defenseclaw import bootstrap

        with (
            patch(
                "defenseclaw.file_permissions.open_regular_file_no_follow",
                return_value=17,
            ),
            patch.object(bootstrap.os, "name", "nt"),
            patch.object(
                bootstrap.os,
                "fstat",
                return_value=SimpleNamespace(st_nlink=0, st_size=6),
            ),
            patch.object(bootstrap.os, "read", side_effect=[b"config", b""]),
            patch.object(bootstrap.os, "close") as close,
        ):
            raw = bootstrap._read_bounded_regular_file(
                "config.yaml",
                1024,
                private=False,
            )

        self.assertEqual(raw, b"config")
        close.assert_called_once_with(17)

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

    def test_hermes_readiness_honors_hermes_home(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        hermes_home = os.path.join(self._tmp.name, "hermes-home")
        os.makedirs(hermes_home)
        with open(os.path.join(hermes_home, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write("hooks: {}\n")

        with patch.dict(os.environ, {"HERMES_HOME": hermes_home}):
            result = _connector_readiness(cfg, "hermes")

        self.assertEqual(result.status, "pass")
        self.assertIn("Hermes config found", result.detail)

    def test_omnigent_readiness_honors_config_home(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        config_home = os.path.join(self._tmp.name, "omnigent-config")
        os.makedirs(config_home)
        with open(os.path.join(config_home, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write("policy_modules: [defenseclaw_omnigent_policy]\npolicies: {defenseclaw_guardrail: {}}\n")
        with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": config_home}):
            result = _connector_readiness(cfg, "omnigent")

        self.assertEqual(result.status, "pass")
        self.assertIn("custom policy", result.detail)
        self.assertIn(config_home, result.detail)

    def test_omnigent_readiness_rejects_partial_registration(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        config_home = os.path.join(self._tmp.name, "partial-omnigent-config")
        os.makedirs(config_home)
        with open(os.path.join(config_home, "config.yaml"), "w", encoding="utf-8") as fh:
            fh.write("policy_modules: [defenseclaw_omnigent_policy]\n")
        with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": config_home}):
            result = _connector_readiness(cfg, "omnigent")

        self.assertEqual(result.status, "warn")

    def test_omnigent_readiness_treats_malformed_utf8_as_unconfigured(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        config_home = os.path.join(self._tmp.name, "malformed-omnigent-config")
        os.makedirs(config_home)
        with open(os.path.join(config_home, "config.yaml"), "wb") as fh:
            fh.write(b"\xff\xfe\x00")
        with patch.dict(os.environ, {"OMNIGENT_CONFIG_HOME": config_home}):
            result = _connector_readiness(cfg, "omnigent")

        self.assertEqual(result.status, "warn")

    def test_amp_readiness_uses_global_plugin_with_or_without_workspace(self):
        plugin = Path(self._tmp.name) / "amp-home" / "plugins" / "defenseclaw.ts"
        plugin.parent.mkdir(parents=True)
        plugin.write_text(
            "// DefenseClaw\nconst endpoint = '/api/v1/amp/hook';\n",
            encoding="utf-8",
        )

        for workspace in ("", os.path.join(self._tmp.name, "workspace")):
            with self.subTest(workspace=workspace or "<none>"):
                cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
                cfg.claw.workspace_dir = workspace
                with patch(
                    "defenseclaw.bootstrap.amp_policy_plugin_path",
                    return_value=str(plugin),
                ):
                    result = _connector_readiness(cfg, "amp")

                self.assertEqual(result.status, "pass")
                self.assertIn(str(plugin), result.detail)


class FreshMigrationCursorTests(unittest.TestCase):
    """Fresh v8 publication seeds one non-clobbering migration cursor."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _pending_config(self, label: str):
        from defenseclaw.bootstrap import (
            _record_fresh_migration_retry,
            fresh_migration_pending_path,
        )
        from defenseclaw.config import default_config, prepare_fresh_v8_config

        data_dir = os.path.join(self._tmp.name, label)
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
            cfg = default_config()
            prepare_fresh_v8_config(cfg)
            cfg.save()
            _record_fresh_migration_retry(cfg)
        return cfg, fresh_migration_pending_path(data_dir)

    def _run_first_run(self, data_dir: str):
        from defenseclaw.bootstrap import (
            FirstRunOptions,
            StepResult,
            run_first_run,
        )

        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch(
                "defenseclaw.bootstrap._quiet_guardrail_setup",
                return_value=StepResult("Guardrail", "pass", "test"),
            ),
        ):
            return run_first_run(
                FirstRunOptions(
                    connector="codex",
                    profile="observe",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                )
            )

    def test_successful_fresh_first_run_bootstraps_registry_through_0_8_5(self):
        from defenseclaw import __version__, migration_state
        from defenseclaw.migrations import MIGRATIONS, _ver_tuple

        data_dir = os.path.join(self._tmp.name, "fresh")
        report = self._run_first_run(data_dir)

        self.assertNotEqual(report.status, "needs_attention")
        state = migration_state.load(data_dir)
        self.assertIsNotNone(state)
        assert state is not None
        expected = [
            version
            for version, _description, _migration in MIGRATIONS
            if _ver_tuple(version) <= _ver_tuple(__version__)
        ]
        self.assertEqual(state.applied, expected)
        self.assertEqual(state.package_version, __version__)
        self.assertEqual(state.applied_at["0.8.5"], migration_state.BOOTSTRAP_SENTINEL)
        self.assertTrue(all(state.applied_at[version] == migration_state.BOOTSTRAP_SENTINEL for version in expected))

    def test_fresh_first_run_skips_broker_without_staged_release_module(self):
        import yaml

        data_dir = os.path.join(self._tmp.name, "source-default")
        with patch("defenseclaw.bootstrap._setup_credential_protection_structured") as setup_broker:
            report = self._run_first_run(data_dir)

        setup_broker.assert_not_called()
        with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as stream:
            raw = yaml.safe_load(stream)
        self.assertNotIn("credential_protection", raw)
        credential_step = next(step for step in report.setup if step.name == "Credential broker")
        self.assertEqual(credential_step.status, "skip")
        self.assertIn("release artifacts are not installed", credential_step.detail)

    def test_fresh_broker_failure_keeps_persisted_config_disabled(self):
        import yaml
        from defenseclaw.bootstrap import FirstRunOptions, StepResult, run_first_run

        data_dir = os.path.join(self._tmp.name, "broker-failure")

        def fail_setup(cfg, *, already_enabled=None, removed_connectors=()):
            with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as stream:
                initial = yaml.safe_load(stream)
            self.assertNotIn("credential_protection", initial)
            self.assertTrue(cfg.credential_protection.enabled)
            self.assertFalse(already_enabled)
            self.assertEqual(list(removed_connectors), [])
            return StepResult(
                "Credential broker",
                "fail",
                "supported s-gw runtime unavailable",
                "defenseclaw setup credential-protection --yes",
            )

        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch(
                "defenseclaw.credential_protection.credential_protection_default_enabled",
                return_value=True,
            ),
            patch(
                "defenseclaw.bootstrap._setup_credential_protection_structured",
                side_effect=fail_setup,
            ),
        ):
            report = run_first_run(
                FirstRunOptions(
                    connector="none",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                )
            )

        self.assertEqual(report.status, "needs_attention")
        with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as stream:
            persisted = yaml.safe_load(stream)
        self.assertNotIn("credential_protection", persisted)

    def test_fresh_manual_broker_registration_stays_disabled_and_withholds_gateway(self):
        import yaml
        from defenseclaw.bootstrap import FirstRunOptions, StepResult, run_first_run

        data_dir = os.path.join(self._tmp.name, "broker-manual")
        manual = StepResult(
            "Credential broker",
            "warn",
            "s-gw ready; MCP zeptoclaw=manual",
            "defenseclaw credential-protection status",
        )
        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch(
                "defenseclaw.credential_protection.credential_protection_default_enabled",
                return_value=True,
            ),
            patch(
                "defenseclaw.bootstrap._setup_credential_protection_structured",
                return_value=manual,
            ),
            patch("defenseclaw.bootstrap._start_gateway_structured") as start_gateway,
        ):
            report = run_first_run(
                FirstRunOptions(
                    connector="none",
                    skip_install=True,
                    start_gateway=True,
                    verify=False,
                )
            )

        self.assertEqual(report.status, "partial")
        start_gateway.assert_not_called()
        sidecar = next(step for step in report.setup if step.name == "Sidecar")
        self.assertEqual(sidecar.status, "skip")
        self.assertIn("credential-protection setup did not complete", sidecar.detail)
        with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as stream:
            persisted = yaml.safe_load(stream)
        self.assertNotIn("credential_protection", persisted)

    def test_no_connector_first_run_creates_canonical_config_and_cursor_without_connector_setup(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import FirstRunOptions, run_first_run

        data_dir = os.path.join(self._tmp.name, "none")
        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch("defenseclaw.bootstrap._quiet_guardrail_setup") as connector_setup,
        ):
            report = run_first_run(
                FirstRunOptions(
                    connector="none",
                    profile="observe",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                )
            )

        self.assertNotEqual(report.status, "needs_attention")
        self.assertTrue(os.path.isfile(os.path.join(data_dir, "config.yaml")))
        self.assertIsNotNone(migration_state.load(data_dir))
        connector_setup.assert_not_called()
        self.assertTrue(any(step.name == "Guardrail" and step.status == "skip" for step in report.setup))

    def test_no_connector_first_run_preserves_existing_connector_selection(self):
        from defenseclaw.bootstrap import FirstRunOptions, run_first_run
        from defenseclaw.config import default_config, load, prepare_fresh_v8_config

        data_dir = os.path.join(self._tmp.name, "none-existing")
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
            cfg = default_config()
            prepare_fresh_v8_config(cfg)
            cfg.claw.mode = "claudecode"
            cfg.guardrail.connector = "claudecode"
            cfg.guardrail.mode = "action"
            cfg.save()

            report = run_first_run(
                FirstRunOptions(
                    connector="none",
                    profile="observe",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                )
            )
            preserved = load()

        self.assertNotEqual(report.status, "needs_attention")
        self.assertEqual(preserved.claw.mode, "claudecode")
        self.assertEqual(preserved.guardrail.connector, "claudecode")
        self.assertEqual(preserved.guardrail.mode, "action")

    def test_no_connector_first_run_preserves_unloadable_existing_config(self):
        from defenseclaw.bootstrap import FirstRunOptions, run_first_run

        data_dir = os.path.join(self._tmp.name, "none-unloadable")
        config_path = os.path.join(data_dir, "config.yaml")
        os.makedirs(data_dir)
        original = b"config_version: 8\noperator_extension: preserve-me\n"
        with open(config_path, "wb") as stream:
            stream.write(original)

        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch("defenseclaw.config.load", side_effect=OSError("injected load failure")),
        ):
            report = run_first_run(
                FirstRunOptions(
                    connector="none",
                    profile="observe",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                )
            )

        self.assertEqual(report.status, "needs_attention")
        with open(config_path, "rb") as stream:
            self.assertEqual(stream.read(), original)

    def test_connector_first_run_preserves_unloadable_existing_config(self):
        from defenseclaw.bootstrap import FirstRunOptions, run_first_run

        data_dir = os.path.join(self._tmp.name, "connector-unloadable")
        config_path = os.path.join(data_dir, "config.yaml")
        os.makedirs(data_dir)
        original = b"config_version: 8\noperator_extension: preserve-me\n"
        with open(config_path, "wb") as stream:
            stream.write(original)

        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch("defenseclaw.config.load", side_effect=OSError("injected load failure")),
            patch("defenseclaw.bootstrap._quiet_guardrail_setup") as connector_setup,
            patch("defenseclaw.bootstrap._setup_credential_protection_structured") as credential_setup,
        ):
            report = run_first_run(
                FirstRunOptions(
                    connector="codex",
                    profile="observe",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                    credential_protection=True,
                )
            )

        self.assertEqual(report.status, "needs_attention")
        self.assertIn("could not be loaded", report.setup[0].detail)
        self.assertEqual(Path(config_path).read_bytes(), original)
        connector_setup.assert_not_called()
        credential_setup.assert_not_called()

    def test_rerun_preserves_bootstrapped_cursor_byte_for_byte(self):
        from defenseclaw import migration_state

        data_dir = os.path.join(self._tmp.name, "rerun")
        self._run_first_run(data_dir)
        cursor_path = migration_state.state_path(data_dir)
        with open(cursor_path, "rb") as stream:
            original = stream.read()

        self._run_first_run(data_dir)

        with open(cursor_path, "rb") as stream:
            self.assertEqual(stream.read(), original)

    def test_existing_valid_future_unknown_and_corrupt_cursors_are_preserved(self):
        from defenseclaw import migration_state

        payloads = {
            "valid": b'{"schema":1,"package_version":"operator","applied":["0.8.0"]}\n',
            "future": b'{"schema":999,"opaque":{"keep":true}}\n',
            "unknown": b'{"schema":"next","opaque":{"keep":true}}\n',
            "corrupt": b'{"schema":',
        }
        for label, payload in payloads.items():
            with self.subTest(label=label):
                data_dir = os.path.join(self._tmp.name, label)
                os.makedirs(data_dir)
                cursor_path = migration_state.state_path(data_dir)
                with open(cursor_path, "wb") as stream:
                    stream.write(payload)

                self._run_first_run(data_dir)

                with open(cursor_path, "rb") as stream:
                    self.assertEqual(stream.read(), payload)

    def test_final_config_save_failure_does_not_create_cursor(self):
        from defenseclaw import migration_state
        from defenseclaw.config import Config

        data_dir = os.path.join(self._tmp.name, "save-failure")
        original_save = Config.save
        save_calls = 0

        def fail_final_save(cfg):
            nonlocal save_calls
            save_calls += 1
            if save_calls == 1:
                return original_save(cfg)
            raise OSError("injected final config save failure")

        with patch.object(Config, "save", new=fail_final_save):
            report = self._run_first_run(data_dir)

        self.assertTrue(os.path.isfile(os.path.join(data_dir, "config.yaml")))
        self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))
        self.assertTrue(any(step.name == "Config Save" and step.status == "fail" for step in report.setup))

    def test_unmarked_existing_v8_config_never_infers_a_fresh_cursor(self):
        from defenseclaw import migration_state
        from defenseclaw.config import default_config, prepare_fresh_v8_config

        data_dir = os.path.join(self._tmp.name, "unmarked-existing")
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
            cfg = default_config()
            prepare_fresh_v8_config(cfg)
            cfg.save()

        report = self._run_first_run(data_dir)

        self.assertNotEqual(report.status, "needs_attention")
        self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))

    def test_later_setup_exception_does_not_create_cursor(self):
        import sqlite3

        from defenseclaw import migration_state
        from defenseclaw.bootstrap import FirstRunOptions, run_first_run
        from defenseclaw.db import Store

        data_dir = os.path.join(self._tmp.name, "setup-failure")
        stores = []

        def track_store(path):
            store = Store(path)
            stores.append(store)
            return store

        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}),
            patch("defenseclaw.db.Store", side_effect=track_store),
            patch("defenseclaw.logger.Logger.no_runtime") as no_runtime,
            patch(
                "defenseclaw.bootstrap._quiet_guardrail_setup",
                side_effect=RuntimeError("injected setup failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "injected setup failure"),
        ):
            run_first_run(
                FirstRunOptions(
                    connector="codex",
                    profile="observe",
                    skip_install=True,
                    start_gateway=False,
                    verify=False,
                )
            )

        self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))
        no_runtime.return_value.close.assert_called_once_with()
        self.assertTrue(stores)
        for store in stores:
            with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
                store.db.execute("SELECT 1")

    def test_version_mismatched_pending_marker_refuses_inference(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            _record_fresh_migration_retry,
            fresh_migration_pending_path,
        )
        from defenseclaw.config import default_config, prepare_fresh_v8_config

        data_dir = os.path.join(self._tmp.name, "version-mismatch")
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
            cfg = default_config()
            prepare_fresh_v8_config(cfg)
            cfg.save()
            _record_fresh_migration_retry(cfg)
        marker = fresh_migration_pending_path(data_dir)
        with open(marker, encoding="utf-8") as stream:
            payload = json.load(stream)
        payload["package_version"] = "0.0.1"
        with open(marker, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
        os.chmod(marker, 0o600)

        report = self._run_first_run(data_dir)

        self.assertEqual(report.status, "needs_attention")
        self.assertTrue(any("pending from DefenseClaw 0.0.1" in step.detail for step in report.setup))
        self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))
        self.assertTrue(os.path.isfile(marker))

    def test_pending_marker_readback_distinguishes_disappearance_from_change(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            _record_fresh_migration_retry,
            fresh_migration_pending_path,
        )
        from defenseclaw.config import default_config, prepare_fresh_v8_config

        for label, persisted, message in (
            ("disappeared", None, "evidence disappeared during publication"),
            ("changed", {}, "evidence changed during publication"),
        ):
            with self.subTest(label=label):
                data_dir = os.path.join(self._tmp.name, f"marker-readback-{label}")
                with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
                    cfg = default_config()
                    prepare_fresh_v8_config(cfg)
                    cfg.save()
                    with (
                        patch(
                            "defenseclaw.bootstrap._load_fresh_migration_pending",
                            return_value=persisted,
                        ),
                        self.assertRaisesRegex(FreshMigrationStateError, message),
                    ):
                        _record_fresh_migration_retry(cfg)

                self.assertTrue(os.path.isfile(fresh_migration_pending_path(data_dir)))
                self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))

    @unittest.skipIf(os.name == "nt", "POSIX marker mode and symlink checks")
    def test_unsafe_pending_marker_is_never_retry_authority(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import fresh_migration_pending_path

        for label in ("malformed", "public", "symlink"):
            with self.subTest(label=label):
                data_dir = os.path.join(self._tmp.name, f"unsafe-{label}")
                os.makedirs(data_dir)
                marker = fresh_migration_pending_path(data_dir)
                if label == "symlink":
                    target = os.path.join(self._tmp.name, "attacker-marker")
                    with open(target, "w", encoding="utf-8") as stream:
                        stream.write("{}\n")
                    os.symlink(target, marker)
                else:
                    with open(marker, "w", encoding="utf-8") as stream:
                        stream.write("{broken\n" if label == "malformed" else "{}\n")
                    os.chmod(marker, 0o644 if label == "public" else 0o600)

                report = self._run_first_run(data_dir)

                self.assertEqual(report.status, "needs_attention")
                self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))
                self.assertTrue(os.path.lexists(marker))

    def test_pending_marker_never_overwrites_a_corrupt_cursor(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            _record_fresh_migration_retry,
            fresh_migration_pending_path,
        )
        from defenseclaw.config import default_config, prepare_fresh_v8_config

        data_dir = os.path.join(self._tmp.name, "corrupt-existing-cursor")
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
            cfg = default_config()
            prepare_fresh_v8_config(cfg)
            cfg.save()
            _record_fresh_migration_retry(cfg)
        cursor = migration_state.state_path(data_dir)
        with open(cursor, "wb") as stream:
            stream.write(b'{"schema":')
        os.chmod(cursor, 0o600)

        report = self._run_first_run(data_dir)

        self.assertEqual(report.status, "needs_attention")
        with open(cursor, "rb") as stream:
            self.assertEqual(stream.read(), b'{"schema":')
        self.assertTrue(os.path.isfile(fresh_migration_pending_path(data_dir)))

    def test_cursor_publication_failure_is_repaired_on_rerun(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import _fresh_migration_pending_path

        data_dir = os.path.join(self._tmp.name, "cursor-retry")
        with patch.object(
            migration_state,
            "save_if_absent",
            side_effect=OSError("injected cursor publication failure"),
        ):
            first_report = self._run_first_run(data_dir)

        self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))
        self.assertTrue(os.path.isfile(_fresh_migration_pending_path(data_dir)))
        self.assertTrue(
            any(
                step.name == "Migration State" and step.status == "fail" and step.next_command == "defenseclaw init"
                for step in first_report.setup
            )
        )

        second_report = self._run_first_run(data_dir)

        self.assertIsNotNone(migration_state.load(data_dir))
        self.assertFalse(os.path.lexists(_fresh_migration_pending_path(data_dir)))
        self.assertTrue(
            any(
                step.name == "Migration State"
                and step.status == "pass"
                and "recovered pending fresh cursor" in step.detail
                for step in second_report.setup
            )
        )

    def test_fresh_cursor_readback_failure_is_actionable_and_retains_marker(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            finalize_first_run_config,
            fresh_migration_pending_path,
        )
        from defenseclaw.config import default_config, prepare_fresh_v8_config

        data_dir = os.path.join(self._tmp.name, "cursor-readback-failure")
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": data_dir}):
            cfg = default_config()
            prepare_fresh_v8_config(cfg)
            with (
                patch.object(
                    migration_state,
                    "load",
                    side_effect=OSError("injected cursor readback failure"),
                ),
                self.assertRaisesRegex(
                    FreshMigrationStateError,
                    "published but could not be read back",
                ),
            ):
                finalize_first_run_config(cfg, was_config_absent=True)

        self.assertTrue(os.path.isfile(migration_state.state_path(data_dir)))
        self.assertTrue(os.path.isfile(fresh_migration_pending_path(data_dir)))

    def test_cursor_retry_refuses_config_changed_after_failed_publication(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import _fresh_migration_pending_path

        data_dir = os.path.join(self._tmp.name, "cursor-retry-tampered")
        with patch.object(
            migration_state,
            "save_if_absent",
            side_effect=OSError("injected cursor publication failure"),
        ):
            self._run_first_run(data_dir)

        config_path = os.path.join(data_dir, "config.yaml")
        with open(config_path, "a", encoding="utf-8") as stream:
            stream.write("# operator change\n")
        changed = Path(config_path).read_bytes()

        report = self._run_first_run(data_dir)

        self.assertEqual(report.status, "needs_attention")
        self.assertEqual(Path(config_path).read_bytes(), changed)
        self.assertFalse(os.path.lexists(migration_state.state_path(data_dir)))
        self.assertTrue(os.path.isfile(_fresh_migration_pending_path(data_dir)))

    def test_pending_cursor_repair_reports_missing_evidence_without_inference(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            repair_pending_first_run_config,
        )

        cfg, marker = self._pending_config("repair-missing-evidence")
        with (
            patch(
                "defenseclaw.bootstrap._load_fresh_migration_pending",
                return_value=None,
            ),
            self.assertRaisesRegex(
                FreshMigrationStateError,
                "evidence disappeared before cursor publication",
            ),
        ):
            repair_pending_first_run_config(cfg)

        self.assertTrue(os.path.isfile(marker))
        self.assertFalse(os.path.lexists(migration_state.state_path(cfg.data_dir)))

    def test_pending_cursor_repair_reports_save_failure_and_retains_marker(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            repair_pending_first_run_config,
        )

        cfg, marker = self._pending_config("repair-save-failure")
        with (
            patch.object(
                migration_state,
                "save_if_absent",
                side_effect=OSError("injected cursor save failure"),
            ),
            self.assertRaisesRegex(
                FreshMigrationStateError,
                "could not publish the pending fresh migration cursor",
            ),
        ):
            repair_pending_first_run_config(cfg)

        self.assertTrue(os.path.isfile(marker))
        self.assertFalse(os.path.lexists(migration_state.state_path(cfg.data_dir)))

    def test_pending_cursor_repair_wraps_lock_failure_and_retains_marker(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            repair_pending_first_run_config,
        )

        cfg, marker = self._pending_config("repair-lock-failure")
        with (
            patch(
                "defenseclaw.file_lock.locked_file_update",
                side_effect=OSError("injected lock failure"),
            ),
            self.assertRaisesRegex(
                FreshMigrationStateError,
                "could not complete the pending fresh migration cursor",
            ),
        ):
            repair_pending_first_run_config(cfg)

        self.assertTrue(os.path.isfile(marker))
        self.assertFalse(os.path.lexists(migration_state.state_path(cfg.data_dir)))

    def test_pending_cursor_repair_reports_mismatch_and_retains_marker(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            repair_pending_first_run_config,
        )

        cfg, marker = self._pending_config("repair-mismatch")
        with (
            patch.object(migration_state, "save_if_absent", return_value=False),
            patch.object(migration_state, "load", return_value=None),
            self.assertRaisesRegex(
                FreshMigrationStateError,
                "cursor does not match the pending fresh installation",
            ),
        ):
            repair_pending_first_run_config(cfg)

        self.assertTrue(os.path.isfile(marker))
        self.assertFalse(os.path.lexists(migration_state.state_path(cfg.data_dir)))

    def test_pending_cursor_repair_reports_marker_cleanup_after_cursor_success(self):
        from defenseclaw import migration_state
        from defenseclaw.bootstrap import (
            FreshMigrationStateError,
            repair_pending_first_run_config,
        )

        cfg, marker = self._pending_config("repair-marker-cleanup")
        with (
            patch(
                "defenseclaw.file_permissions.delete_file_durable",
                side_effect=OSError("injected durable delete failure"),
            ),
            self.assertRaisesRegex(
                FreshMigrationStateError,
                "cursor is complete, but its retry marker could not be cleared",
            ),
        ):
            repair_pending_first_run_config(cfg)

        self.assertTrue(os.path.isfile(marker))
        self.assertIsNotNone(migration_state.load(cfg.data_dir))


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
        self.assertEqual(
            self.cfg.guardrail.hook_fail_mode,
            "closed",
            "empty options.hook_fail_mode must NEVER overwrite an existing operator choice",
        )

    def test_closed_persists(self):
        self._apply("closed")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "closed")

    def test_uppercase_closed_normalizes(self):
        self._apply("CLOSED")
        self.assertEqual(self.cfg.guardrail.hook_fail_mode, "closed")

    def test_open_persists(self):
        self.cfg.guardrail.hook_fail_mode = "closed"  # seed with non-default
        self._apply("open")
        self.assertEqual(
            self.cfg.guardrail.hook_fail_mode,
            "open",
            "explicit 'open' must be honored even when starting from 'closed'",
        )

    def test_typo_normalizes_to_open(self):
        self.cfg.guardrail.hook_fail_mode = "closed"  # seed with non-default
        self._apply("klosed")
        self.assertEqual(
            self.cfg.guardrail.hook_fail_mode,
            "open",
            "typo must NEVER silently put the agent in a stricter posture than the operator typed",
        )


# ---------------------------------------------------------------------------
# _apply_first_run_choices: judge setup
#
# ``init`` and ``quickstart`` expose a single "enable judge" choice. When
# selected, that choice must be effective for hook connectors without asking
# for a second coverage list.
# ---------------------------------------------------------------------------


class ApplyFirstRunChoicesJudgeTests(unittest.TestCase):
    def setUp(self):
        from defenseclaw.config import default_config

        self.cfg = default_config()

    def _apply(self, *, with_judge: bool) -> None:
        from defenseclaw.bootstrap import (
            FirstRunOptions,
            _apply_first_run_choices,
        )

        opts = FirstRunOptions(connector="codex", profile="observe", with_judge=with_judge)
        _apply_first_run_choices(self.cfg, opts, "codex", "observe", "local")

    def test_with_judge_enables_all_hook_coverage(self):
        self._apply(with_judge=True)
        self.assertTrue(self.cfg.guardrail.judge.enabled)
        self.assertEqual(self.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.cfg.guardrail.judge.hook_connectors, ["*"])

    def test_with_judge_bumps_regex_only_strategy(self):
        self.cfg.guardrail.detection_strategy = "regex_only"
        self._apply(with_judge=True)
        self.assertEqual(self.cfg.guardrail.detection_strategy, "regex_judge")
        self.assertEqual(self.cfg.guardrail.judge.hook_connectors, ["*"])

    def test_first_run_choice_clears_stale_multi_connector_map(self):
        self.cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(),
            "hermes": PerConnectorGuardrailConfig(),
        }
        self._apply(with_judge=False)
        self.assertEqual(sorted(self.cfg.guardrail.connectors), ["codex"])
        self.assertNotIn("hermes", self.cfg.guardrail.connectors)
        self.assertEqual(self.cfg.active_connectors(), ["codex"])


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
        connector: str = "codex",
        human_approval: bool | None = None,
        hilt_min_severity: str = "",
    ) -> None:
        from defenseclaw.bootstrap import (
            FirstRunOptions,
            _apply_first_run_choices,
        )

        opts = FirstRunOptions(
            connector=connector,
            profile="action",
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
        )
        _apply_first_run_choices(self.cfg, opts, connector, "action", "local")

    def test_none_preserves_existing_enabled(self):
        self.cfg.guardrail.hilt.enabled = True
        self._apply(human_approval=None)
        self.assertTrue(
            self.cfg.guardrail.hilt.enabled,
            "human_approval=None must NEVER silently flip an operator's prior 'enabled' choice",
        )

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
        self.assertEqual(
            self.cfg.guardrail.hilt.min_severity,
            "MEDIUM",
            "empty hilt_min_severity must preserve the existing "
            "severity floor — used by callers who only want to "
            "flip the toggle without overriding the threshold",
        )

    def test_min_severity_normalizes_uppercase(self):
        self._apply(hilt_min_severity="medium")
        self.assertEqual(
            self.cfg.guardrail.hilt.min_severity,
            "MEDIUM",
            "lowercase severity must normalize so config stays "
            "consistent with the canonical HIGH/MEDIUM/LOW/"
            "CRITICAL set used by the gateway",
        )

    def test_min_severity_invalid_falls_back_to_high(self):
        self.cfg.guardrail.hilt.min_severity = "MEDIUM"  # seed non-default
        self._apply(hilt_min_severity="kritical")
        self.assertEqual(
            self.cfg.guardrail.hilt.min_severity,
            "HIGH",
            "typo must fall back to the strictest practical "
            "floor (HIGH) — falling back to a permissive value "
            "would silently weaken the operator's intent",
        )

    def test_enable_with_empty_severity_backfills_high(self):
        self.cfg.guardrail.hilt.enabled = False
        self.cfg.guardrail.hilt.min_severity = ""  # simulate round-tripped older config
        self._apply(human_approval=True, hilt_min_severity="")
        self.assertTrue(self.cfg.guardrail.hilt.enabled)
        self.assertEqual(
            self.cfg.guardrail.hilt.min_severity,
            "HIGH",
            "enabling HITL with no severity floor must backfill "
            "HIGH — an empty floor lets every finding skip the "
            "prompt, which would defeat the feature entirely",
        )

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

    def test_explicit_choice_updates_selected_connector_hilt_override(self):
        self.cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(hilt=HILTConfig(enabled=True, min_severity="LOW")),
            "hermes": PerConnectorGuardrailConfig(hilt=HILTConfig(enabled=False, min_severity="HIGH")),
        }
        self.cfg.guardrail.hilt.enabled = False

        self._apply(connector="hermes", human_approval=True)

        self.assertEqual(sorted(self.cfg.guardrail.connectors), ["hermes"])
        hermes_hilt = self.cfg.guardrail.connectors["hermes"].hilt
        self.assertIsNotNone(hermes_hilt)
        self.assertTrue(hermes_hilt.enabled)
        self.assertEqual(hermes_hilt.min_severity, "HIGH")
        self.assertTrue(self.cfg.guardrail.effective_hilt("hermes").enabled)

    def test_explicit_false_updates_selected_connector_hilt_override(self):
        self.cfg.guardrail.connectors = {
            "hermes": PerConnectorGuardrailConfig(hilt=HILTConfig(enabled=True, min_severity="MEDIUM")),
        }

        self._apply(connector="hermes", human_approval=False)

        hermes_hilt = self.cfg.guardrail.connectors["hermes"].hilt
        self.assertIsNotNone(hermes_hilt)
        self.assertFalse(hermes_hilt.enabled)
        self.assertEqual(hermes_hilt.min_severity, "MEDIUM")


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

        with open(os.path.join(self.data_dir, "active_connector.json"), "w", encoding="utf-8") as fh:
            json.dump({"name": name}, fh)

    def _write_pid_file(self) -> None:
        # Use the current process's pid: ``_pid_file_running`` does
        # ``os.kill(pid, 0)`` so it must point at a real, owned-by-us
        # process. Using ``os.getpid()`` keeps the test hermetic.
        import json

        with open(os.path.join(self.data_dir, "gateway.pid"), "w", encoding="utf-8") as fh:
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
        # _pid_file_running now also checks
        # /proc/<pid>/cmdline against known gateway binary names.
        # Tests use os.getpid() (the python test runner) which won't
        # match — stub the cmdline check to keep the test focused on
        # drift detection, not on the new spoof guard. The spoof
        # guard has its own dedicated tests.
        stack.enter_context(
            patch(
                "defenseclaw.bootstrap._pid_looks_like_gateway",
                return_value=True,
            )
        )
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
        self.assertEqual(
            recorder, [], "no subprocess invocation expected when the live connector matches cfg.active_connector()"
        )

    def test_credential_service_restarts_running_same_connector(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        self.cfg.guardrail.connector = "openclaw"
        self._write_pid_file()
        self._write_active_connector("openclaw")

        recorder: list = []
        with self._patch_subprocess(recorder):
            result = _start_gateway_structured(
                self.cfg,
                restart_if_running=True,
            )

        self.assertEqual(result.status, "pass")
        self.assertIn("credential-protection service", result.detail)
        self.assertEqual(recorder, [("/usr/bin/defenseclaw-gateway", "restart")])

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
        self.assertEqual(len(recorder), 1, "exactly one subprocess invocation expected on drift")
        self.assertEqual(recorder[0][1], "restart", "must call `defenseclaw-gateway restart`, not `start`")

    def test_drift_restart_failure_surfaces_warn_with_remediation(self):
        from defenseclaw.bootstrap import _start_gateway_structured

        self.cfg.guardrail.connector = "openclaw"
        self._write_pid_file()
        self._write_active_connector("codex")

        recorder: list = []
        with self._patch_subprocess(recorder, returncode=1):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "warn")
        self.assertIn(
            "drift detected",
            result.detail,
            "warn detail must call out drift so the operator knows the on-disk config doesn't match runtime",
        )
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
        self.assertEqual(
            recorder,
            [],
            "missing active_connector.json must NEVER trigger a restart; legacy 'already running' behavior wins",
        )

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

    def test_windows_live_unrelated_reused_pid_does_not_suppress_start(self):
        import subprocess

        from defenseclaw.bootstrap import _start_gateway_structured

        self._write_pid_file()
        completed = subprocess.CompletedProcess(
            args=["defenseclaw-gateway", "start"],
            returncode=0,
            stdout="",
            stderr="",
        )
        with (
            patch.object(os, "name", "nt"),
            patch(
                "defenseclaw.bootstrap.shutil.which",
                return_value=r"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe",
            ),
            patch(
                "defenseclaw.bootstrap.subprocess.run",
                return_value=completed,
            ) as run,
            patch(
                "defenseclaw.process_liveness.read_pid_file",
                return_value=os.getpid(),
            ),
            patch(
                "defenseclaw.process_liveness.pid_alive",
                return_value=True,
            ),
            patch(
                "defenseclaw.process_liveness.process_is_gateway",
                return_value=False,
            ) as process_is_gateway,
        ):
            result = _start_gateway_structured(self.cfg)

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.detail, "started")
        process_is_gateway.assert_called_once_with(os.getpid())
        run.assert_called_once_with(
            [
                r"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe",
                "start",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_windows_verified_gateway_still_counts_as_running(self):
        from defenseclaw.bootstrap import _pid_file_running

        self._write_pid_file()
        with (
            patch.object(os, "name", "nt"),
            patch(
                "defenseclaw.process_liveness.read_pid_file",
                return_value=os.getpid(),
            ),
            patch(
                "defenseclaw.process_liveness.pid_alive",
                return_value=True,
            ),
            patch(
                "defenseclaw.process_liveness.process_is_gateway",
                return_value=True,
            ) as process_is_gateway,
        ):
            self.assertTrue(
                _pid_file_running(os.path.join(self.data_dir, "gateway.pid")),
            )

        process_is_gateway.assert_called_once_with(os.getpid())


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
        with open(os.path.join(self._tmp.name, "active_connector.json"), "w", encoding="utf-8") as fh:
            fh.write(contents)

    def test_missing_file_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file

        self.assertIsNone(_running_connector_from_state_file(self._tmp.name))

    def test_empty_name_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file

        self._write('{"name": ""}')
        self.assertIsNone(
            _running_connector_from_state_file(self._tmp.name),
            "empty string must be treated as I-don't-know, not as a real connector name",
        )

    def test_malformed_json_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file

        self._write("{not json}")
        self.assertIsNone(_running_connector_from_state_file(self._tmp.name))

    def test_normalizes_case_and_whitespace(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file

        self._write('{"name": "  CODEX  "}')
        self.assertEqual(
            _running_connector_from_state_file(self._tmp.name),
            "codex",
            "must match Config.active_connector() normalization "
            "rule (strip + lowercase) so drift detection isn't "
            "fooled by case differences",
        )

    def test_non_dict_payload_returns_none(self):
        from defenseclaw.bootstrap import _running_connector_from_state_file

        self._write('"openclaw"')
        self.assertIsNone(_running_connector_from_state_file(self._tmp.name))


class ApplyGatewayDefaultsTokenGateTests(unittest.TestCase):
    """SU-03 / ND-2: the OpenClaw gateway token must only be adopted when
    openclaw is a genuinely active connector — never leaked onto a hook-only
    install that merely has a stray ``openclaw.json`` reachable on disk."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._prev_home = os.environ.get("DEFENSECLAW_HOME")
        os.environ["DEFENSECLAW_HOME"] = self._tmp.name
        self.addCleanup(self._restore_home)
        self._gateway_token_env = patch.dict(
            os.environ,
            {"DEFENSECLAW_GATEWAY_TOKEN": "", "OPENCLAW_GATEWAY_TOKEN": ""},
        )
        self._gateway_token_env.start()
        self.addCleanup(self._gateway_token_env.stop)

    def _restore_home(self) -> None:
        if self._prev_home is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = self._prev_home

    def _stray_openclaw_json(self, token: str) -> str:
        import json

        path = os.path.join(self._tmp.name, "openclaw.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"gateway": {"model": "local", "port": 19000, "auth": {"token": token}}},
                fh,
            )
        return path

    def test_hook_only_install_does_not_pin_openclaw_token(self):
        from defenseclaw.bootstrap import _apply_gateway_defaults

        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        os.makedirs(cfg.data_dir, exist_ok=True)
        # Hook-only: codex is the active connector, openclaw is NOT.
        cfg.claw.mode = "codex"
        cfg.guardrail.connector = "codex"
        cfg.claw.config_file = self._stray_openclaw_json("stray-proxy-secret")

        _apply_gateway_defaults(cfg, is_new_config=True)

        self.assertEqual(cfg.gateway.token_env, "DEFENSECLAW_GATEWAY_TOKEN")
        # The stray proxy secret must never be copied into the dotenv.
        env_path = os.path.join(cfg.data_dir, ".env")
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8") as fh:
                self.assertNotIn("stray-proxy-secret", fh.read())

    def test_openclaw_install_still_pins_openclaw_token(self):
        from defenseclaw.bootstrap import _apply_gateway_defaults

        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        os.makedirs(cfg.data_dir, exist_ok=True)
        cfg.claw.mode = "openclaw"
        cfg.guardrail.connector = "openclaw"
        cfg.claw.config_file = self._stray_openclaw_json("legit-openclaw-secret")

        _apply_gateway_defaults(cfg, is_new_config=True)

        self.assertEqual(cfg.gateway.token_env, "OPENCLAW_GATEWAY_TOKEN")


if __name__ == "__main__":
    unittest.main()
