#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

adapter = importlib.import_module("benchmark_normalize_socbed")


def adapter_stats(manifest: dict[str, object]) -> dict[str, int]:
    return manifest["adapter_statistics"][adapter.ADAPTER]


def console_line(timestamp: str, event: str, attack: str, **attributes: str) -> str:
    fields = [f'event="{event}"', f'attack="{attack}"']
    fields.extend(f'{key}="{value}"' for key, value in attributes.items())
    message = "Run attack" if event == "run_attack" else "Attack succeeded"
    return f"{timestamp} tbfconsole INFO [{' '.join(fields)}] {message}"


def process_row(
    timestamp: str,
    identity: str,
    executable: str,
    argv: list[str],
    *,
    parent: str | None = None,
    command: str | None = None,
) -> dict[str, object]:
    process: dict[str, object] = {
        "entity_id": identity,
        "executable": executable,
        "name": executable.replace("/", "\\").rsplit("\\", 1)[-1],
        "args": argv,
        "command_line": command or " ".join(argv),
        "working_directory": "C:\\Users\\operator",
        "hash": {"sha256": "a" * 64},
    }
    if parent:
        process["parent"] = {"entity_id": parent}
    return {
        "@timestamp": timestamp,
        "event": {"code": 1, "type": ["start", "process_start"]},
        "host": {"name": "CLIENT1.lab.invalid"},
        "process": process,
    }


class SocbedNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.run = self.source / "host1_bestpractice"
        self.run.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_run(self, console: list[str], telemetry: list[object], ordinal: str = "01") -> None:
        (self.run / f"attackconsole_{ordinal}.log").write_text("\n".join(console) + "\n", encoding="utf-8")
        (self.run / f"winlogbeat_{ordinal}.jsonl").write_text(
            "\n".join(json.dumps(row, sort_keys=True) for row in telemetry) + "\n", encoding="utf-8"
        )

    def normalize(self):
        return adapter.normalize(self.source)

    def test_exact_executed_artifact_is_positive_and_context_is_not_benign(self) -> None:
        console = [
            console_line(
                "2021-06-18T15:09:49+02:00",
                "run_attack",
                "misc_execute_malware",
                file="C:\\Windows\\payload.exe",
                rhost="192.0.2.10",
            ),
            console_line(
                "2021-06-18T15:09:51+02:00",
                "attack_succeeded",
                "misc_execute_malware",
                file="C:\\Windows\\payload.exe",
                rhost="192.0.2.10",
            ),
        ]
        telemetry = [
            process_row("2021-06-18T13:09:49.200Z", "parent", "C:\\Windows\\cmd.exe", ["cmd", "/c"]),
            process_row(
                "2021-06-18T13:09:49.400Z",
                "payload",
                "C:\\Windows\\payload.exe",
                ["C:\\Windows\\payload.exe"],
                parent="parent",
            ),
        ]
        self.write_run(console, telemetry)
        cases, manifest = self.normalize()
        actions = [row for row in cases if row["surface"] == "action"]
        positives = [row for row in actions if row["truth"]["applicability"] == "in_scope"]
        self.assertEqual(len(positives), 1)
        self.assertIn("executed_artifact", positives[0]["truth"]["categories"])
        self.assertEqual(
            [row["truth"]["source_truth"] for row in actions if row["truth"]["applicability"] == "out_of_scope"],
            ["unknown"],
        )
        self.assertEqual(adapter_stats(manifest)["deterministic_atomic_cases"], 1)

    def test_autorun_requires_exact_reg_identity_value_name_and_path(self) -> None:
        attributes = {"data": "payload.exe", "name": "Example Startup", "rhost": "192.0.2.10"}
        console = [
            console_line("2021-06-18T15:06:49+02:00", "run_attack", "misc_set_autostart", **attributes),
            console_line("2021-06-18T15:06:50+02:00", "attack_succeeded", "misc_set_autostart", **attributes),
        ]
        exact = [
            "REG",
            "ADD",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "/v",
            "Example Startup",
            "/d",
            "payload.exe",
            "/f",
        ]
        telemetry = [
            process_row(
                "2021-06-18T13:06:49.300Z",
                "reg-exact",
                "C:\\Windows\\System32\\reg.exe",
                exact,
            ),
            process_row(
                "2021-06-18T13:06:49.400Z",
                "reg-wrong",
                "C:\\Windows\\System32\\reg.exe",
                [*exact[:-3], "other.exe", "/f"],
            ),
        ]
        self.write_run(console, telemetry)
        cases, _ = self.normalize()
        positives = [row for row in cases if row["truth"]["applicability"] == "in_scope"]
        self.assertEqual(len(positives), 1)
        self.assertIn("autorun_registry_write", positives[0]["truth"]["categories"])

    def test_success_pair_must_be_exact_ordered_and_bounded(self) -> None:
        telemetry = [process_row("2021-06-18T13:00:01Z", "p", "C:\\Windows\\payload.exe", ["payload.exe"])]
        cases = [
            [
                console_line(
                    "2021-06-18T15:00:00+02:00", "attack_succeeded", "misc_execute_malware", file="payload.exe"
                ),
                console_line("2021-06-18T15:00:01+02:00", "run_attack", "misc_execute_malware", file="payload.exe"),
            ],
            [
                console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="payload.exe"),
                console_line("2021-06-18T15:00:01+02:00", "attack_succeeded", "misc_set_autostart", file="payload.exe"),
            ],
            [
                console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="payload.exe"),
                console_line(
                    "2021-06-18T15:06:00+02:00", "attack_succeeded", "misc_execute_malware", file="payload.exe"
                ),
            ],
        ]
        for index, console in enumerate(cases, 1):
            self.write_run(console, telemetry, f"{index:02d}")
        rows, manifest = self.normalize()
        self.assertEqual(rows, [])
        stats = adapter_stats(manifest)
        self.assertGreaterEqual(stats["ambiguous_attack_pairs"], 2)
        self.assertGreaterEqual(stats["orphan_attack_successes"], 1)

    def test_stateful_window_uses_only_exact_parent_lineage_and_is_bounded(self) -> None:
        console = [
            console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="C:\\payload.exe"),
            console_line(
                "2021-06-18T15:00:10+02:00", "attack_succeeded", "misc_execute_malware", file="C:\\payload.exe"
            ),
        ]
        telemetry = []
        parent = None
        for index in range(11):
            identity = f"process-{index}"
            executable = "C:\\payload.exe" if index == 10 else f"C:\\Windows\\step-{index}.exe"
            telemetry.append(
                process_row(
                    f"2021-06-18T13:00:{index:02d}Z",
                    identity,
                    executable,
                    [executable],
                    parent=parent,
                )
            )
            parent = identity
        telemetry.append(process_row("2021-06-18T13:00:09.500Z", "nearby", "C:\\Windows\\nearby.exe", ["nearby"]))
        self.write_run(console, telemetry)
        rows, _ = self.normalize()
        stateful = [row for row in rows if row["surface"] == "stateful"]
        self.assertEqual(len(stateful), 1)
        self.assertEqual(len(stateful[0]["payload"]["events"]), adapter.MAX_EVENTS)
        refs = [event["args"]["process_ref"] for event in stateful[0]["payload"]["events"]]
        self.assertNotIn(adapter.digest("socbed-process", "nearby")[:24], refs)
        for earlier, later in zip(stateful[0]["payload"]["events"], stateful[0]["payload"]["events"][1:]):
            self.assertEqual(later["args"]["parent_process_ref"], earlier["args"]["process_ref"])

    def test_payload_redacts_targets_and_credentials_and_excludes_attack_labels(self) -> None:
        console = [
            console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="C:\\payload.exe"),
            console_line(
                "2021-06-18T15:00:02+02:00", "attack_succeeded", "misc_execute_malware", file="C:\\payload.exe"
            ),
        ]
        telemetry = [
            process_row(
                "2021-06-18T13:00:01Z",
                "payload",
                "C:\\payload.exe",
                ["C:\\payload.exe", "--password", "do-not-emit", "http://192.0.2.2/a"],
            )
        ]
        self.write_run(console, telemetry)
        rows, manifest = self.normalize()
        payloads = json.dumps([row["payload"] for row in rows], sort_keys=True)
        self.assertNotIn("do-not-emit", payloads)
        self.assertNotIn("192.0.2.2", payloads)
        self.assertNotIn("misc_execute_malware", payloads)
        self.assertNotIn("attack_succeeded", payloads)
        self.assertNotIn("misc_execute_malware", json.dumps(manifest, sort_keys=True))

    def test_failed_and_outside_interval_telemetry_never_becomes_benign(self) -> None:
        console = [
            console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="C:\\payload.exe")
        ]
        telemetry = [process_row("2021-06-18T13:00:01Z", "payload", "C:\\payload.exe", ["C:\\payload.exe"])]
        self.write_run(console, telemetry)
        rows, _ = self.normalize()
        self.assertEqual(rows, [])
        console.append(
            console_line(
                "2021-06-18T15:00:02+02:00", "attack_succeeded", "misc_execute_malware", file="C:\\payload.exe"
            )
        )
        telemetry.append(process_row("2021-06-18T13:10:00Z", "outside", "C:\\outside.exe", ["outside.exe"]))
        self.write_run(console, telemetry)
        rows, _ = self.normalize()
        self.assertFalse(any(row["truth"]["source_truth"] == "benign" for row in rows))
        self.assertFalse(any("outside.exe" in json.dumps(row["payload"]) for row in rows))

    def test_zip_streaming_determinism_manifest_schema_and_duplicate_exclusion(self) -> None:
        console = [
            console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="C:\\payload.exe"),
            console_line(
                "2021-06-18T15:00:02+02:00", "attack_succeeded", "misc_execute_malware", file="C:\\payload.exe"
            ),
        ]
        row = process_row("2021-06-18T13:00:01Z", "payload", "C:\\payload.exe", ["C:\\payload.exe"])
        self.write_run(console, [row, row])
        archive = self.root / "dataset.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            for path in sorted(self.source.rglob("*")):
                if path.is_file():
                    handle.write(path, path.relative_to(self.source).as_posix())
        first, first_manifest = adapter.normalize(archive)
        second, second_manifest = adapter.normalize(archive)
        self.assertEqual(first, second)
        self.assertEqual(first_manifest, second_manifest)
        self.assertGreaterEqual(adapter_stats(first_manifest)["exact_payload_duplicates_removed"], 1)
        self.assertEqual(first_manifest["datasets"], [adapter.DATASET])
        self.assertEqual(first_manifest["cases"], len(first))
        self.assertEqual(
            first_manifest["output_sha256"],
            adapter.hashlib.sha256(b"".join(adapter.canonical_json(row) for row in first)).hexdigest(),
        )
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            pass
        else:
            adapter.validate_cases(first)

    def test_malformed_duplicate_json_and_missing_pair_are_quarantined(self) -> None:
        console = [
            console_line("2021-06-18T15:00:00+02:00", "run_attack", "misc_execute_malware", file="C:\\payload.exe"),
            console_line(
                "2021-06-18T15:00:02+02:00", "attack_succeeded", "misc_execute_malware", file="C:\\payload.exe"
            ),
        ]
        self.write_run(console, [])
        telemetry = self.run / "winlogbeat_01.jsonl"
        telemetry.write_text('{"event":{"code":1},"event":{"code":1}}\n{not-json\n', encoding="utf-8")
        rows, manifest = self.normalize()
        self.assertEqual(rows, [])
        self.assertEqual(adapter_stats(manifest)["malformed_telemetry_lines"], 2)

    def test_archive_traversal_and_unpinned_revision_are_rejected(self) -> None:
        archive = self.root / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../host/attackconsole_01.log", "ignored")
            handle.writestr("../host/winlogbeat_01.jsonl", "{}\n")
        with self.assertRaisesRegex(ValueError, "unsafe source member"):
            adapter.normalize(archive)
        with self.assertRaisesRegex(ValueError, "pinned source revision"):
            adapter.normalize(self.source, revision="moving-branch")


if __name__ == "__main__":
    unittest.main()
