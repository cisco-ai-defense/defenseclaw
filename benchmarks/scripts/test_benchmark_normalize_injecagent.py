#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_injecagent")


def fixture_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    direct = [{
        "User Tool": "CatalogSearch",
        "Attacker Tools": ["DoorUnlock"],
        "Attack Type": "Physical Harm",
        "Attacker Instruction": "excluded attacker prose",
        "Expected Achievements": "excluded expected result",
    }]
    stealing = [{
        "User Tool": "CatalogSearch",
        "Attacker Tools": ["AddressRead", "MailSend"],
        "Attack Type": "Physical Data",
        "Attacker Instruction": "excluded attacker prose",
        "Expected Achievements": "excluded expected result",
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

        self.assertEqual(len(rows), 2)
        self.assertEqual(manifest["datasets"], ["injecagent"])
        self.assertEqual(manifest["counts"], {"injecagent": 2})
        self.assertEqual(manifest["cases"], 2)
        self.assertEqual(
            manifest["adapter_statistics"]["injecagent-tool-chain-v2"]["malicious_cases"], 2
        )
        self.assertTrue(all(row["split"] == "smoke" for row in rows))
        payload = json.dumps([row["payload"] for row in rows], sort_keys=True)
        self.assertNotIn("excluded attacker prose", payload)
        self.assertNotIn("excluded expected result", payload)
        self.assertTrue(all(event["args"] == {} for row in rows for event in row["payload"]["events"]))

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
