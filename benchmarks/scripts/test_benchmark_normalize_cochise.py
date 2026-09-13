#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_cochise")


def adapter_stats(manifest: dict[str, object]) -> dict[str, int]:
    return manifest["adapter_statistics"][adapter.ADAPTER]


def event(kind: str, call_id: str, *, agent: str = "worker-1", tool: str = "execute_command", **values):
    return {"event": kind, "agent": agent, "tool_name": tool, "tool_call_id": call_id, **values}


class CochiseNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "logs"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, rows: list[object], malformed: list[str] | None = None) -> Path:
        path = self.source / name
        lines = [json.dumps(row, sort_keys=True) for row in rows]
        lines.extend(malformed or [])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def normalize(self):
        return adapter.normalize(self.source)

    def test_exact_id_and_tool_pairing_never_uses_adjacency(self) -> None:
        rows = [
            event("tool_call", "a", params={"command": "whoami"}),
            event("tool_call", "b", params={"command": "whoami"}),
            event("tool_result", "b", result="ordinary-user"),
            event("tool_result", "a", result="NT AUTHORITY\\SYSTEM\n"),
        ]
        self.write("pairing.json", rows)
        cases, manifest = self.normalize()
        by_id = {row["source"]["original_id"].split(":")[-2]: row for row in cases}
        self.assertEqual(by_id["a"]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(by_id["b"]["truth"]["applicability"], "out_of_scope")
        self.assertEqual(adapter_stats(manifest)["paired_calls"], 2)

    def test_attack_taxonomy_and_procedure_never_enter_detector_payload(self) -> None:
        rows = [
            event(
                "tool_call",
                "call",
                params={
                    "command": "impacket-secretsdump lab/user@host",
                    "mitre_attack_procedure": "credential dumping answer label",
                    "mitre_attack_tactic": "Credential Access",
                    "mitre_attack_technique": "T1003.006",
                    "mitre attack technique": "T1558.003",
                    "mitre_attack procedure": "alternate spelling",
                    "MITRE_ATTACKTECHNIQUE": "T1087.002",
                },
            ),
            event("tool_result", "call", result="LAB\\svc:1105:" + "a" * 32 + ":" + "b" * 32 + ":::")
        ]
        self.write("labels.json", rows)
        cases, _ = self.normalize()
        encoded = json.dumps(cases, sort_keys=True).lower()
        for forbidden in ("answer label", "credential access", "t1003.006", "mitre_attack"):
            self.assertNotIn(forbidden, encoded)

    def test_orphan_missing_and_ambiguous_results_do_not_become_positive(self) -> None:
        rows = [
            event("tool_call", "missing", params={"command": "whoami"}),
            event("tool_result", "orphan", result="NT AUTHORITY\\SYSTEM"),
            event("tool_call", "duplicate", params={"command": "whoami"}),
            event("tool_result", "duplicate", result="NT AUTHORITY\\SYSTEM"),
            event("tool_result", "duplicate", result="NT AUTHORITY\\SYSTEM"),
        ]
        self.write("orphans.json", rows)
        cases, manifest = self.normalize()
        self.assertEqual(len(cases), 2)
        self.assertTrue(all(row["truth"]["applicability"] == "out_of_scope" for row in cases))
        stats = adapter_stats(manifest)
        self.assertEqual(stats["missing_results"], 1)
        self.assertEqual(stats["orphan_results"], 1)
        self.assertEqual(stats["ambiguous_calls"], 1)

    def test_only_concrete_effect_results_are_deterministic_positives(self) -> None:
        ntds = "LAB\\svc:1105:" + "a" * 32 + ":" + "b" * 32 + ":::"
        rows = [
            event("tool_call", "system", params={"command": "whoami"}),
            event("tool_result", "system", result="nt authority\\system"),
            event("tool_call", "extract", params={"command": "impacket-secretsdump lab/user@host"}),
            event("tool_result", "extract", result=ntds),
            event("tool_call", "nxc-ntds", params={"command": "nxc smb host -u user -H aa:bb --ntds"}),
            event("tool_result", "nxc-ntds", result=ntds),
            event("tool_call", "recon", params={"command": "nmap host"}),
            event("tool_result", "recon", result="host is up"),
            event("tool_call", "claim", params={"command": "echo SYSTEM obtained"}),
            event("tool_result", "claim", result="SYSTEM obtained"),
        ]
        self.write("proofs.json", rows)
        cases, _ = self.normalize()
        positives = [row for row in cases if row["truth"]["applicability"] == "in_scope"]
        self.assertEqual(len(positives), 2)
        categories = {category for row in positives for category in row["truth"]["categories"]}
        self.assertIn("returned_credential_material", categories)
        self.assertEqual(sum(row["truth"]["applicability"] == "out_of_scope" for row in cases), 3)

    def test_compromised_fact_requires_exact_bounded_successful_authentication(self) -> None:
        secret = "generated passphrase"
        rows = [
            event(
                "tool_call",
                "fact",
                tool="add_compromised_account",
                params={"username": "LAB/user", "password": secret, "context": "verified candidate"},
            ),
            event(
                "tool_result",
                "fact",
                tool="add_compromised_account",
                result="noted compromised account LAB/user with context: verified candidate",
            ),
            event("tool_call", "auth", params={"command": f"nxc smb host -u user -p '{secret}'"}),
            event("tool_result", "auth", result=f"SMB host [+] LAB\\user:{secret}"),
        ]
        self.write("chain.json", rows)
        cases, manifest = self.normalize()
        chains = [row for row in cases if row["surface"] == "stateful"]
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["truth"]["categories"][-1], "credential_authentication")
        self.assertEqual(chains[0]["truth"]["expected_disposition"], "detect_only")
        self.assertEqual(chains[0]["truth"]["stateful_lens"], "bounded_completed")
        self.assertEqual(chains[0]["truth"]["rule_ids"], [adapter.CREDENTIAL_AUTHENTICATION_CHAIN])
        self.assertEqual([item["outcome"] for item in chains[0]["payload"]["events"]], ["succeeded", "succeeded"])
        self.assertTrue(all("offset_seconds" not in item for item in chains[0]["payload"]["events"]))
        self.assertNotIn(secret, json.dumps(chains, sort_keys=True))
        self.assertEqual(adapter_stats(manifest)["deterministic_authentication_chains"], 1)

    def test_failed_mismatched_and_unbounded_authentication_remain_contextual(self) -> None:
        secret = "generated passphrase"
        rows = [
            event(
                "tool_call",
                "fact",
                tool="add_compromised_account",
                params={"username": "LAB/user", "password": secret},
            ),
            event("tool_result", "fact", tool="add_compromised_account", result="noted compromised account LAB/user"),
        ]
        for index in range(adapter.MAX_CHAIN_CALLS):
            rows.extend(
                [
                    event("tool_call", f"gap-{index}", params={"command": "pwd"}),
                    event("tool_result", f"gap-{index}", result="/root"),
                ]
            )
        rows.extend(
            [
                event("tool_call", "late", params={"command": f"nxc smb host -u user -p '{secret}'"}),
                event("tool_result", "late", result=f"SMB host [+] LAB\\user:{secret}"),
                event("tool_call", "failed", params={"command": f"nxc smb host -u user -p '{secret}'"}),
                event("tool_result", "failed", result="STATUS_LOGON_FAILURE"),
            ]
        )
        self.write("negative-chains.json", rows)
        cases, _ = self.normalize()
        self.assertFalse(any(row["surface"] == "stateful" for row in cases))
        self.assertTrue(all(row["truth"]["applicability"] == "out_of_scope" for row in cases))

    def test_payload_and_manifests_exclude_prompts_thoughts_and_raw_results(self) -> None:
        secret = "generated sensitive material"
        rows = [
            {
                **event(
                    "tool_call",
                    "safe",
                    params={
                        "command": f"printf '%s' '{secret}'",
                        "password": secret,
                        "nested": {"token": secret, "keep": "structured"},
                        "thought": "private chain of thought",
                        "prompt": "excluded prompt",
                    },
                ),
                "scenario": "excluded scenario",
            },
            event("tool_result", "safe", result="unnecessarily raw sensitive result " + secret),
            {"event": "history_append", "agent": "worker-1", "content": "excluded history and prompt"},
            {"event": "completed", "agent": "main", "content": "run completed with private summary"},
        ]
        self.write("leakage.json", rows)
        cases, manifest = self.normalize()
        serialized = json.dumps([cases, manifest], sort_keys=True)
        forbidden_values = (
            secret,
            "private chain of thought",
            "excluded prompt",
            "excluded scenario",
            "raw sensitive result",
            "excluded history",
            "private summary",
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, serialized)
        call = next(row for row in cases if row["payload"]["tool_name"] == "execute_command")
        self.assertEqual(call["payload"]["args"]["nested"]["keep"], "structured")
        self.assertNotIn("thought", call["payload"]["args"])
        self.assertNotIn("prompt", call["payload"]["args"])
        completed = next(row for row in cases if row["payload"]["tool_name"] == "cochise.run_completed")
        self.assertEqual(completed["truth"]["applicability"], "out_of_scope")

    def test_common_pentest_credential_forms_are_redacted_without_value_hashes(self) -> None:
        values = ("placeholder-passphrase", "a" * 32 + ":" + "b" * 32)
        params = {"command": (f"impacket-tool domain/user:{values[0]}@host -hashes {values[1]} -H {'c' * 32}")}
        projected = json.dumps(adapter.projected_args(params), sort_keys=True)
        for value in values:
            self.assertNotIn(value, projected)
        self.assertNotIn("c" * 32, projected)
        self.assertIn("REDACTED_SECRET_", projected)
        self.assertNotRegex(projected, r"REDACTED_SECRET_[0-9a-f]{64}")

    def test_malformed_input_is_counted_and_does_not_shift_deterministic_ids(self) -> None:
        good = [
            event("tool_call", "one", params={"command": "whoami"}),
            event("tool_result", "one", result="NT AUTHORITY\\SYSTEM"),
        ]
        self.write("malformed.json", good, malformed=["{not-json", '{"event":"x","event":"y","agent":"worker"}'])
        first, first_manifest = self.normalize()
        self.assertEqual(adapter_stats(first_manifest)["malformed_records"], 2)
        self.write("malformed.json", good)
        second, _ = self.normalize()
        self.assertEqual(first, second)

    def test_pairing_is_file_local_and_requires_result_after_call(self) -> None:
        self.write(
            "a.json",
            [
                event("tool_result", "same", result="NT AUTHORITY\\SYSTEM"),
                event("tool_call", "same", params={"command": "whoami"}),
            ],
        )
        self.write("b.json", [event("tool_call", "same", params={"command": "whoami"})])
        cases, manifest = self.normalize()
        self.assertTrue(all(row["truth"]["applicability"] == "out_of_scope" for row in cases))
        self.assertEqual(adapter_stats(manifest)["ambiguous_calls"], 1)
        self.assertEqual(adapter_stats(manifest)["missing_results"], 1)

    def test_determinism_task_disjoint_metadata_and_schema(self) -> None:
        first_file = [
            event("tool_call", "one", agent="task-a", params={"command": "pwd"}),
            event("tool_result", "one", agent="task-a", result="/root"),
            event("tool_call", "two", agent="task-b", params={"command": "whoami"}),
            event("tool_result", "two", agent="task-b", result="NT AUTHORITY\\SYSTEM"),
        ]
        self.write("b.json", first_file)
        first, first_manifest = self.normalize()
        second, second_manifest = self.normalize()
        self.assertEqual(first, second)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(len({row["strata"]["split_group"] for row in first}), 2)
        self.assertEqual({row["split"] for row in first}, {adapter.PRE_PARTITION_SPLIT})
        self.assertEqual(first_manifest["datasets"], [adapter.DATASET])
        adapter.validate_cases(first)


if __name__ == "__main__":
    unittest.main()
