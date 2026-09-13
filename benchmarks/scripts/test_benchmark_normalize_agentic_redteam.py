#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
adapter = importlib.import_module("benchmark_normalize_agentic_redteam")


def source_row() -> dict[str, object]:
    return {
        "id": "fixture-trajectory",
        "category": "credential_access",
        "ground_truth": {"expected_decision_at_drift": "WARN", "drift_step": 2},
        "trajectory": [
            {"action": {"type": "tool_call", "name": "search"}},
            {"action": {"type": "tool_call", "name": "read"}},
            {"action": {"type": "tool_call", "name": "send"}},
        ],
        "metadata": {"reviewed_by": []},
    }


class AgenticRedTeamManifestTests(unittest.TestCase):
    def test_manifest_matches_strict_benchmark_wire_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "case.json").write_text(json.dumps(source_row()), encoding="utf-8")
            rows, manifest = adapter.normalize(root, "fixture-revision", "validation")

        self.assertEqual(len(rows), 2)
        self.assertEqual(manifest["datasets"], ["agentic-redteam-benchmark"])
        self.assertEqual(manifest["cases"], 2)
        self.assertEqual(manifest["counts"], {"agentic-redteam-benchmark": 2})
        self.assertEqual(
            set(manifest),
            {
                "schema_version",
                "datasets",
                "cases",
                "counts",
                "exact_payload_duplicates_removed",
                "label_conflicts_excluded",
                "adapter_statistics",
                "trajectory_source",
            },
        )
        stats = manifest["adapter_statistics"]["agentic-redteam-v1"]
        self.assertEqual(stats["benign_cases"], 1)
        self.assertEqual(stats["malicious_cases"], 1)
        self.assertIn("label_limitation", manifest["trajectory_source"])


if __name__ == "__main__":
    unittest.main()
