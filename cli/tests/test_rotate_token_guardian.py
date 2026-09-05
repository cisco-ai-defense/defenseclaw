"""Unit tests for the #735 guardian rotation coordinator helpers."""

from __future__ import annotations

import json
import os
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import click
from defenseclaw.rotate_token_guardian import (
    GUARDIAN_AUTH_DIR_ENV,
    GUARDIAN_MANIFEST_ENV,
    GuardianRotationPlan,
    GuardianRotationTarget,
    assert_current_attestations,
    assert_guardian_control_plane_path,
    assert_guardian_idle,
    bind_guardian_roster,
    default_guardian_manifest_path,
    expected_fingerprints_payload,
    guardian_manifest_digest,
    parse_guardian_rotate_response,
    require_guardian_participant,
)


def _plan(manifest: str = "/etc/defenseclaw/hook-guardian/targets.yaml") -> GuardianRotationPlan:
    digest = ""
    if os.path.isfile(manifest):
        digest = guardian_manifest_digest(os.path.abspath(manifest))
    return GuardianRotationPlan(
        operation_id="a" * 32,
        generation="b" * 32,
        manifest=manifest,
        targets=(
            GuardianRotationTarget("alice", "/home/alice", "", "codex", ""),
            GuardianRotationTarget("bob", "/home/bob", "", "codex", ""),
            GuardianRotationTarget("alice", "/home/alice", "", "claudecode", ""),
        ),
        manifest_sha256=digest,
    )


def _in_tree_auth_dir(td: str) -> Path:
    auth = Path(td, "hook-guardian")
    auth.mkdir(exist_ok=True)
    os.environ[GUARDIAN_AUTH_DIR_ENV] = str(auth)
    return auth


def _write_test_manifest(path: Path) -> str:
    path.write_text("version: 1\ntargets: []\n", encoding="utf-8")
    return str(path.resolve())


def _passthrough_control_plane(path: str, label: str, *, directory: bool = False) -> os.stat_result:
    info = os.lstat(path)
    if directory and not stat.S_ISDIR(info.st_mode):
        raise click.ClickException(f"{label} is not a trusted directory.")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise click.ClickException(f"{label} is not a trusted regular file.")
    return info


def _clear_guardian_env() -> None:
    for name in (GUARDIAN_AUTH_DIR_ENV, GUARDIAN_MANIFEST_ENV):
        os.environ.pop(name, None)


class RequireGuardianParticipantTests(unittest.TestCase):
    def setUp(self) -> None:
        self._guardian_env = {
            name: os.environ.get(name) for name in (GUARDIAN_AUTH_DIR_ENV, GUARDIAN_MANIFEST_ENV)
        }
        _clear_guardian_env()
        custody = mock.patch(
            "defenseclaw.rotate_token_guardian.assert_guardian_control_plane_path",
            side_effect=_passthrough_control_plane,
        )
        custody.start()
        self.addCleanup(custody.stop)
        self.addCleanup(self._restore_guardian_env)

    def _restore_guardian_env(self) -> None:
        for name, value in self._guardian_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class DefaultManifestTests(RequireGuardianParticipantTests):
    def test_uses_packaged_macos_layout(self) -> None:
        self.assertEqual(
            default_guardian_manifest_path("darwin"),
            "/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml",
        )

    def test_uses_linux_etc_layout(self) -> None:
        self.assertEqual(
            default_guardian_manifest_path("linux"),
            "/etc/defenseclaw/hook-guardian/targets.yaml",
        )


class IdleJournalTests(RequireGuardianParticipantTests):
    def test_retires_terminal_journal(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            journal = _in_tree_auth_dir(td) / "rotation-transaction.json"
            journal.write_text(json.dumps({"phase": "committed", "operation_id": "c" * 32}), encoding="utf-8")
            assert_guardian_idle(td)
            self.assertFalse(journal.exists())

    def test_refuses_in_progress_journal(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            journal = _in_tree_auth_dir(td) / "rotation-transaction.json"
            journal.write_text(json.dumps({"phase": "prepared", "operation_id": "c" * 32}), encoding="utf-8")
            with self.assertRaises(click.ClickException) as raised:
                assert_guardian_idle(td)
            self.assertIn("already in progress", str(raised.exception))
            self.assertTrue(journal.exists())

    def test_refuses_unknown_journal_phase(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            journal = _in_tree_auth_dir(td) / "rotation-transaction.json"
            journal.write_text(json.dumps({"phase": "unknown", "operation_id": "c" * 32}), encoding="utf-8")
            with self.assertRaises(click.ClickException) as raised:
                assert_guardian_idle(td)
            self.assertIn("unexpected phase", str(raised.exception))
            self.assertTrue(journal.exists())


class RequireGuardianParticipantBehaviorTests(RequireGuardianParticipantTests):
    def test_unmanaged_does_not_join(self) -> None:
        self.assertFalse(require_guardian_participant(SimpleNamespace(deployment_mode="unmanaged_byod")))
        self.assertFalse(require_guardian_participant(SimpleNamespace(deployment_mode="")))

    def test_windows_managed_is_refused(self) -> None:
        with mock.patch("defenseclaw.rotate_token_guardian.os.name", "nt"):
            with self.assertRaises(click.ClickException) as raised:
                require_guardian_participant(SimpleNamespace(deployment_mode="managed_enterprise"))
        self.assertIn("native guardian adapter", str(raised.exception))

    @unittest.skipIf(os.name == "nt", "POSIX managed participant")
    def test_posix_managed_joins(self) -> None:
        self.assertTrue(require_guardian_participant(SimpleNamespace(deployment_mode="managed_enterprise")))


class BindGuardianRosterTests(RequireGuardianParticipantTests):
    def test_binds_enabled_multi_user_roster(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = Path(td, "targets.yaml")
            manifest.write_text(
                "\n".join(
                    [
                        "version: 1",
                        "targets:",
                        "  - user: alice",
                        "    user_home: /home/alice",
                        "    connector: Codex",
                        "  - user: bob",
                        "    user_home: /home/bob",
                        "    connector: codex",
                        "  - user: alice",
                        "    user_home: /home/alice",
                        "    connector: claudecode",
                        "    enabled: false",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            plan = bind_guardian_roster(
                manifest_path=str(manifest),
                requested_scopes={"codex", "claudecode"},
                operation_id="a" * 32,
                generation="b" * 32,
            )
            self.assertIsNotNone(plan)
            assert plan is not None
            self.assertEqual(plan.manifest_sha256, guardian_manifest_digest(str(manifest.resolve())))
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual([target.connector for target in plan.targets], ["codex", "codex"])
        self.assertEqual({target.user for target in plan.targets}, {"alice", "bob"})

    def test_missing_service_scope_fails_closed(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = Path(td, "targets.yaml")
            manifest.write_text(
                "version: 1\ntargets:\n  - user: alice\n    user_home: /home/alice\n    connector: gemini\n",
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                bind_guardian_roster(
                    manifest_path=str(manifest),
                    requested_scopes={"codex"},
                    operation_id="a" * 32,
                    generation="b" * 32,
                )
        self.assertIn("not in the service rotation roster", str(raised.exception))

    def test_rotatable_but_unrequested_scope_fails_closed(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = Path(td, "targets.yaml")
            manifest.write_text(
                "version: 1\ntargets:\n  - user: alice\n    user_home: /home/alice\n    connector: gemini\n",
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                bind_guardian_roster(
                    manifest_path=str(manifest),
                    requested_scopes={"codex", "claudecode"},
                    operation_id="a" * 32,
                    generation="b" * 32,
                )
        self.assertIn("not in the service rotation roster", str(raised.exception))

    def test_rejects_non_boolean_enabled_flag(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = Path(td, "targets.yaml")
            manifest.write_text(
                "version: 1\ntargets:\n  - user: alice\n    user_home: /home/alice\n"
                "    connector: codex\n    enabled: 0\n",
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                bind_guardian_roster(
                    manifest_path=str(manifest),
                    requested_scopes={"codex"},
                    operation_id="a" * 32,
                    generation="b" * 32,
                )
        self.assertIn("enabled flag must be a boolean", str(raised.exception))

    def test_empty_roster_does_not_join(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = Path(td, "targets.yaml")
            manifest.write_text("version: 1\ntargets: []\n", encoding="utf-8")
            self.assertIsNone(
                bind_guardian_roster(
                    manifest_path=str(manifest),
                    requested_scopes={"codex"},
                    operation_id="a" * 32,
                    generation="b" * 32,
                )
            )

    def test_rejects_invalid_rotation_identity(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = Path(td, "targets.yaml")
            manifest.write_text(
                "version: 1\ntargets:\n  - user: alice\n    user_home: /home/alice\n    connector: codex\n",
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                bind_guardian_roster(
                    manifest_path=str(manifest),
                    requested_scopes={"codex"},
                    operation_id="not-a-valid-generation-id",
                    generation="b" * 32,
                )
        self.assertIn("identity is invalid", str(raised.exception))


class CurrentAttestationTests(RequireGuardianParticipantTests):
    def test_rejects_aggregate_count_without_per_target_proof(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = _write_test_manifest(Path(td, "targets.yaml"))
            plan = _plan(manifest)
            digest = guardian_manifest_digest(manifest)
            auth = _in_tree_auth_dir(td)
            (auth / "protected_targets.json").write_text(
                json.dumps(
                    {
                        "current": {
                            "ok": True,
                            "generation": "b" * 32,
                            "manifest_sha256": digest,
                            "target_count": 3,
                            "success_count": 3,
                            "attestations": [
                                {
                                    "user": "alice",
                                    "user_home": "/home/alice",
                                    "connector": "codex",
                                    "ok": True,
                                    "generation": "b" * 32,
                                    "token_fingerprint": "c" * 64,
                                    "manifest_sha256": digest,
                                }
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                assert_current_attestations(td, plan, {"codex": "c" * 64, "claudecode": "c" * 64})
        self.assertIn("per-target readiness", str(raised.exception))

    def test_rejects_attestation_bound_to_a_different_manifest(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = _write_test_manifest(Path(td, "targets.yaml"))
            plan = _plan(manifest)
            auth = _in_tree_auth_dir(td)
            (auth / "protected_targets.json").write_text(
                json.dumps(
                    {
                        "current": {
                            "ok": True,
                            "generation": "b" * 32,
                            "manifest_sha256": "d" * 64,
                            "target_count": 3,
                            "success_count": 3,
                            "attestations": [
                                {
                                    "user": target.user,
                                    "user_home": target.user_home,
                                    "connector": target.connector,
                                    "ok": True,
                                    "generation": "b" * 32,
                                    "token_fingerprint": "c" * 64,
                                    "manifest_sha256": "d" * 64,
                                }
                                for target in plan.targets
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                assert_current_attestations(td, plan, {"codex": "c" * 64, "claudecode": "c" * 64})
        self.assertIn("not bound to the selected manifest", str(raised.exception))

    def test_rejects_row_attested_against_a_different_manifest(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = _write_test_manifest(Path(td, "targets.yaml"))
            plan = _plan(manifest)
            digest = guardian_manifest_digest(manifest)
            auth = _in_tree_auth_dir(td)
            (auth / "protected_targets.json").write_text(
                json.dumps(
                    {
                        "current": {
                            "ok": True,
                            "generation": "b" * 32,
                            "manifest_sha256": digest,
                            "target_count": 3,
                            "success_count": 3,
                            "attestations": [
                                {
                                    "user": target.user,
                                    "user_home": target.user_home,
                                    "connector": target.connector,
                                    "ok": True,
                                    "generation": "b" * 32,
                                    "token_fingerprint": "c" * 64,
                                    "manifest_sha256": digest if target.connector == "codex" else "d" * 64,
                                }
                                for target in plan.targets
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                assert_current_attestations(td, plan, {"codex": "c" * 64, "claudecode": "c" * 64})
        self.assertIn("attested a different manifest", str(raised.exception))

    def test_rejects_coerced_readiness_counts(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            manifest = _write_test_manifest(Path(td, "targets.yaml"))
            plan = _plan(manifest)
            digest = guardian_manifest_digest(manifest)
            auth = _in_tree_auth_dir(td)
            (auth / "protected_targets.json").write_text(
                json.dumps(
                    {
                        "current": {
                            "ok": True,
                            "generation": "b" * 32,
                            "manifest_sha256": digest,
                            "target_count": "3",
                            "success_count": "3",
                            "attestations": [
                                {
                                    "user": target.user,
                                    "user_home": target.user_home,
                                    "connector": target.connector,
                                    "ok": True,
                                    "generation": "b" * 32,
                                    "token_fingerprint": "c" * 64,
                                    "manifest_sha256": digest,
                                }
                                for target in plan.targets
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(click.ClickException) as raised:
                assert_current_attestations(td, plan, {"codex": "c" * 64, "claudecode": "c" * 64})
        self.assertIn("malformed", str(raised.exception))


class GuardianResponseTests(RequireGuardianParticipantTests):
    def test_accepts_exact_identity_and_roster_count(self) -> None:
        parse_guardian_rotate_response(
            json.dumps(
                {
                    "ok": True,
                    "action": "prepare",
                    "operation_id": "a" * 32,
                    "generation": "b" * 32,
                    "phase": "prepared",
                    "targets": 3,
                }
            ),
            action="prepare",
            plan=_plan(),
        )

    def test_rejects_mixed_generation_or_extra_failure(self) -> None:
        with self.assertRaises(click.ClickException):
            parse_guardian_rotate_response(
                json.dumps(
                    {
                        "ok": True,
                        "action": "prepare",
                        "operation_id": "a" * 32,
                        "generation": "c" * 32,
                        "phase": "prepared",
                        "targets": 3,
                    }
                ),
                action="prepare",
                plan=_plan(),
            )

    def test_rejects_bool_target_count(self) -> None:
        with self.assertRaises(click.ClickException):
            parse_guardian_rotate_response(
                json.dumps(
                    {
                        "ok": True,
                        "action": "prepare",
                        "operation_id": "a" * 32,
                        "generation": "b" * 32,
                        "phase": "prepared",
                        "targets": True,
                    }
                ),
                action="prepare",
                plan=_plan(),
            )

    def test_accepts_idle_rollback_when_prepare_never_published(self) -> None:
        parse_guardian_rotate_response(
            json.dumps(
                {
                    "ok": True,
                    "action": "rollback",
                    "operation_id": "",
                    "generation": "",
                    "phase": "",
                    "targets": 0,
                }
            ),
            action="rollback",
            plan=_plan(),
        )

    def test_expected_fingerprints_never_include_raw_values(self) -> None:
        payload = expected_fingerprints_payload(_plan(), {"codex": "c" * 64, "claudecode": "e" * 64})
        blob = json.dumps(payload)
        self.assertIn("token_fingerprint", blob)
        self.assertNotIn("token=", blob)
        self.assertEqual(len(payload["targets"]), 3)


class ControlPlaneCustodyTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "uid-0 custody is a POSIX administrator check")
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root-owned fixtures cannot prove the non-root rejection")
    def test_rejects_non_root_owner(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            path = Path(td, "targets.yaml")
            path.write_text("version: 1\ntargets: []\n", encoding="utf-8")
            with self.assertRaises(click.ClickException) as raised:
                assert_guardian_control_plane_path(str(path.resolve()), "guardian manifest")
        self.assertIn("administrator-owned", str(raised.exception))

    def test_rejects_symlink(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            real = Path(td, "real.yaml")
            real.write_text("version: 1\ntargets: []\n", encoding="utf-8")
            link = Path(td, "targets.yaml")
            link.symlink_to(real)
            self.assertTrue(stat.S_ISLNK(os.lstat(str(link)).st_mode))
            with self.assertRaises(click.ClickException) as raised:
                assert_guardian_control_plane_path(str(link), "guardian manifest")
        self.assertIn("not a trusted regular path", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
