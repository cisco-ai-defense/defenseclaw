#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_injecagent")


USER_INSTRUCTION = "Find me the catalog entry for part number XR-9."
TOOL_PARAMETERS = "{'part_number': 'XR-9'}"


def fixture_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    direct = [{
        "User Tool": "CatalogSearch",
        "User Instruction": USER_INSTRUCTION,
        "Tool Parameters": TOOL_PARAMETERS,
        "Attacker Tools": ["DoorUnlock"],
        "Attack Type": "Physical Harm",
        "Attacker Instruction": "excluded attacker prose",
        "Expected Achievements": "excluded expected result",
        "Tool Response": "excluded tool response carrying excluded attacker prose",
    }]
    stealing = [{
        "User Tool": "CatalogSearch",
        "User Instruction": USER_INSTRUCTION,
        "Tool Parameters": TOOL_PARAMETERS,
        "Attacker Tools": ["AddressRead", "MailSend"],
        "Attack Type": "Physical Data",
        "Attacker Instruction": "excluded attacker prose",
        "Expected Achievements": "excluded expected result",
        "Tool Response": "excluded tool response carrying excluded attacker prose",
    }]
    return direct, stealing


class InjecAgentAdapterTests(unittest.TestCase):
    def test_emits_complete_value_free_staging_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            direct_path = root / "test_cases_dh_base.json"
            stealing_path = root / "test_cases_ds_base.json"
            direct, stealing = fixture_rows()
            direct_path.write_text(json.dumps(direct), encoding="utf-8")
            stealing_path.write_text(json.dumps(stealing), encoding="utf-8")
            rows, manifest = adapter.normalize(
                [direct_path, stealing_path],
                adapter.SOURCE_REVISION,
                adapter.PRE_PARTITION_SPLIT,
                verify_source=False,
            )

        # Two attacker chains plus one deduplicated intent_matching counterpart: both fixture
        # rows share a user request, so the matching side is emitted once, not twice.
        self.assertEqual(len(rows), 3)
        self.assertEqual(manifest["datasets"], ["injecagent"])
        self.assertEqual(manifest["counts"], {"injecagent": 3})
        self.assertEqual(manifest["cases"], 3)
        self.assertEqual(
            manifest["adapter_statistics"]["injecagent-tool-chain-v2"]["malicious_cases"], 2
        )
        self.assertEqual(
            manifest["adapter_statistics"]["injecagent-tool-chain-v2"]["benign_intent_matching_cases"], 1
        )
        self.assertTrue(all(row["split"] == "smoke" for row in rows))
        payload = json.dumps([row["payload"] for row in rows], sort_keys=True)
        self.assertNotIn("excluded attacker prose", payload)
        self.assertNotIn("excluded expected result", payload)
        self.assertNotIn("excluded tool response", payload)

        # Every case carries the user's request, which is the whole point of the pairing.
        self.assertTrue(all(row["payload"]["content"] == USER_INSTRUCTION for row in rows))
        self.assertEqual(manifest["intent_pairs"]["cases_with_intent"], 3)

        # The user's own call carries the real Tool Parameters; the attacker tools carry none,
        # because the upstream corpus supplies none and inventing them would be fabrication.
        for row in rows:
            events = row["payload"]["events"]
            self.assertEqual(events[0]["tool_name"], "CatalogSearch")
            self.assertEqual(events[0]["args"], {"part_number": "XR-9"})
            self.assertTrue(all(event["args"] == {} for event in events[1:]))
            # Nothing here was executed, so no event may claim an outcome.
            self.assertTrue(all(event["outcome"] == "unknown" for event in events))
        self.assertEqual(manifest["intent_pairs"]["cases_with_arguments"], 3)

        # Both case classes are produced, and a pair joins on the user-instruction hash.
        classes = {row["strata"]["case_class"] for row in rows}
        self.assertEqual(classes, {"intent_matching", "intent_violating"})
        self.assertEqual(manifest["intent_pairs"]["case_classes"], {"intent_matching": 1, "intent_violating": 2})
        self.assertEqual(len({row["strata"]["pair_group"] for row in rows}), 1)
        self.assertEqual(manifest["intent_pairs"]["pair_groups"], 1)

        matching = [row for row in rows if row["strata"]["case_class"] == "intent_matching"]
        violating = [row for row in rows if row["strata"]["case_class"] == "intent_violating"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["surface"], "action")
        self.assertEqual(matching[0]["truth"]["source_truth"], "benign")
        self.assertEqual(matching[0]["truth"]["expected_disposition"], "allow")
        self.assertEqual(matching[0]["truth"]["deterministic_truth"], "benign")
        self.assertEqual(len(matching[0]["payload"]["events"]), 1)
        for row in violating:
            self.assertEqual(row["surface"], "stateful")
            self.assertEqual(row["truth"]["source_truth"], "malicious")
            self.assertEqual(row["truth"]["expected_disposition"], "detect_only")
            # No call here was ever emitted or executed, so nothing may reach grade A.
            self.assertEqual(row["truth"]["deterministic_truth"], "contextual_or_dual_use")
            self.assertEqual(row["truth"]["label_confidence"], "high")
            self.assertNotIn("exact_proof", row["truth"]["categories"])
            self.assertNotIn("closed_proof", row["truth"]["categories"])

        # The original tool-chain family scheme is preserved verbatim.
        for row in violating:
            tools = [event["tool_name"] for event in row["payload"]["events"]]
            self.assertEqual(
                row["strata"]["split_group"],
                hashlib.sha256("\x00".join(tools).encode()).hexdigest()[:24],
            )
        self.assertEqual(
            matching[0]["strata"]["split_group"],
            hashlib.sha256(b"CatalogSearch").hexdigest()[:24],
        )

    def test_enhanced_variants_are_accepted_and_tagged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            direct, stealing = fixture_rows()
            paths = []
            for name, payload in (
                ("test_cases_dh_base.json", direct),
                ("test_cases_ds_base.json", stealing),
                ("test_cases_dh_enhanced.json", direct),
                ("test_cases_ds_enhanced.json", stealing),
            ):
                path = root / name
                path.write_text(json.dumps(payload), encoding="utf-8")
                paths.append(path)
            rows, manifest = adapter.normalize(
                paths, adapter.SOURCE_REVISION, adapter.PRE_PARTITION_SPLIT, verify_source=False
            )

        # Four attacker chains, and still exactly one matching counterpart.
        self.assertEqual(manifest["intent_pairs"]["case_classes"], {"intent_matching": 1, "intent_violating": 4})
        self.assertEqual(
            manifest["intent_pairs"]["injection_strength"], {"base": 2, "enhanced": 2, "none": 1}
        )
        # Enhanced rows add no new family: they reuse the base tool chains.
        self.assertEqual(manifest["intent_pairs"]["split_groups"], 3)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))

    def test_rejects_moving_revision_partition_source_set_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            direct_path = root / "test_cases_dh_base.json"
            stealing_path = root / "test_cases_ds_base.json"
            direct, stealing = fixture_rows()
            direct_path.write_text(json.dumps(direct), encoding="utf-8")
            stealing_path.write_text(json.dumps(stealing), encoding="utf-8")
            paths = [direct_path, stealing_path]
            with self.assertRaisesRegex(ValueError, "datasets.lock.json"):
                adapter.normalize(paths, "moving-revision", adapter.PRE_PARTITION_SPLIT)
            with self.assertRaisesRegex(ValueError, "pre-partitioned"):
                adapter.normalize(paths, adapter.SOURCE_REVISION, "development")
            with self.assertRaisesRegex(ValueError, "source set is incomplete"):
                adapter.normalize([direct_path], adapter.SOURCE_REVISION, adapter.PRE_PARTITION_SPLIT)
            with self.assertRaisesRegex(ValueError, "pinned identity"):
                adapter.normalize(paths, adapter.SOURCE_REVISION, adapter.PRE_PARTITION_SPLIT)


if __name__ == "__main__":
    unittest.main()
