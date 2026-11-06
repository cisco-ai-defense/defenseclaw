# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The public D1 subset admits reviewed synthetic inputs only."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.check_d1_shapes import check, synthetic_operands

CORPUS = Path(__file__).resolve().parents[1] / "internal/gateway/testdata/d1-shapes.jsonl"
NEARBY_COMMANDS = (
    "ssh sample-host-17",
    "chown sampleacct7 $HOME/proj/item.txt",
    "cat /srv/sample/item.txt",
    "git clone ssh://sample-host-17/repo",
    "git clone git@sample-host-17:repo",
    "git remote add origin sample-host-17:repo",
    "git config user.name sampleacct7",
    "git -c user.email=sampleacct7@example.invalid status",
)


def write_rows(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class D1ShapeScrubTest(unittest.TestCase):
    def test_synthetic_git_host_and_account_twins_are_allowed(self):
        for command in (
            "git clone ssh://git@example.invalid/repo",
            "git clone git@example.invalid:repo",
            "git remote add origin example.invalid:repo",
            "git config user.name testuser",
            "git -c user.email=testuser@example.invalid status",
        ):
            with self.subTest(command=command):
                self.assertTrue(synthetic_operands({"command": command}))

    def test_reviewed_public_subset_passes_scrub(self):
        self.assertEqual(check(CORPUS), [])

    def test_nearby_unreviewed_operands_fail_on_reviewed_manifest(self):
        source = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()][:250]
        with TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "d1.jsonl"
            for command in NEARBY_COMMANDS:
                with self.subTest(command=command):
                    rows = [dict(row) for row in source]
                    for row in rows:
                        if row["kind"] == "shell":
                            row["command"] = command
                    write_rows(corpus, rows)
                    self.assertTrue(check(corpus))

    def test_nearby_unreviewed_operands_fail_with_updated_manifest(self):
        from scripts.check_d1_shapes import payload_digest

        source = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()]
        with TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "d1.jsonl"
            manifest = Path(temporary) / "approved.tsv"
            for command in NEARBY_COMMANDS:
                with self.subTest(command=command):
                    rows = [dict(row) for row in source]
                    rows[29]["command"] = command
                    write_rows(corpus, rows)
                    manifest.write_text(
                        "".join(f"{row['id']}\t{payload_digest(row)}\n" for row in rows), encoding="utf-8"
                    )
                    self.assertTrue(any("unapproved host" in error for error in check(corpus, manifest)))

    def test_payload_change_requires_manifest_review(self):
        rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()]
        rows[29]["command"] = "git status --short"
        with TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "d1.jsonl"
            write_rows(corpus, rows)
            self.assertTrue(any("unapproved public payload" in error for error in check(corpus)))


if __name__ == "__main__":
    unittest.main()
