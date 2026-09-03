"""Unit tests for the #735 guardian rotation coordinator helpers."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import click

from defenseclaw.rotate_token_guardian import (
    GuardianRotationPlan,
    GuardianRotationTarget,
    assert_current_attestations,
    bind_guardian_roster,
    expected_fingerprints_payload,
    parse_guardian_rotate_response,
    require_guardian_participant,
)


def _plan() -> GuardianRotationPlan:
    return GuardianRotationPlan(
        operation_id="a" * 32,
        generation="b" * 32,
        manifest="/etc/defenseclaw/hook-guardian/targets.yaml",
        targets=(
            GuardianRotationTarget("alice", "/home/alice", "", "codex", ""),
            GuardianRotationTarget("bob", "/home/bob", "", "codex", ""),
            GuardianRotationTarget("alice", "/home/alice", "", "claudecode", ""),
        ),
    )


class RequireGuardianParticipantTests(unittest.TestCase):
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


class BindGuardianRosterTests(unittest.TestCase):
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
                rotatable_scopes={"codex", "claudecode"},
                operation_id="a" * 32,
                generation="b" * 32,
            )
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
                    rotatable_scopes={"codex"},
                    operation_id="a" * 32,
                    generation="b" * 32,
                )
        self.assertIn("not in the service rotation roster", str(raised.exception))


class CurrentAttestationTests(unittest.TestCase):
    def test_rejects_aggregate_count_without_per_target_proof(self) -> None:
        from tempfile import TemporaryDirectory

        plan = _plan()
        with TemporaryDirectory() as td:
            auth = Path(f"{td}-hook-guardian")
            auth.mkdir()
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
                                    "user": "alice",
                                    "user_home": "/home/alice",
                                    "connector": "codex",
                                    "ok": True,
                                    "generation": "b" * 32,
                                    "token_fingerprint": "c" * 64,
                                    "manifest_sha256": "d" * 64,
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


class GuardianResponseTests(unittest.TestCase):
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

    def test_expected_fingerprints_never_include_raw_values(self) -> None:
        payload = expected_fingerprints_payload(_plan(), {"codex": "c" * 64, "claudecode": "e" * 64})
        blob = json.dumps(payload)
        self.assertIn("token_fingerprint", blob)
        self.assertNotIn("token=", blob)
        self.assertEqual(len(payload["targets"]), 3)


if __name__ == "__main__":
    unittest.main()
