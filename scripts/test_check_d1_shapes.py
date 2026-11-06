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
    "git clone -q sample-host-17:repo",
    "git remote add origin sample-host-17:repo",
    "git remote set-url origin sample-host-17:repo",
    "git config user.name sampleacct7",
    "git -c user.email=sampleacct7@example.invalid status",
    "GIT_AUTHOR_NAME=sampleacct7 git status",
    "curl testbed:80",
    "curl --user testbed testbed:80",
    "curl --proxy=testbed https://example.invalid/resource",
    "curl --url=testbed",
    "curl -xtestbed https://example.invalid/resource",
    "wget testbed",
    "curl αβγ",
    "curl --user αβγ example.invalid",
    "nc testbed 80",
    "nc -z testbed 80",
    "netcat testbed 80",
    "telnet testbed 80",
    "curl -H 'Host: testbed' https://example.invalid/resource",
    "curl -H $'\\110\\157\\163\\164:testbed' https://example.invalid/resource",
    "nc -l -c 'nc testbed 80'",
    "curl -H '$(printf Host): testbed' https://example.invalid/resource",
    "curl -HHost:testbed https://example.invalid/resource",
    "curl --proxy-header='X-Forwarded-Host: testbed' https://example.invalid/resource",
    "wget -H testbed",
    "nc -stestbed example.invalid 80",
)


def write_rows(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class D1ShapeScrubTest(unittest.TestCase):
    def test_synthetic_git_host_and_account_twins_are_allowed(self):
        for command in (
            "git clone ssh://git@example.invalid/repo",
            "git clone git@example.invalid:repo",
            "git clone -q example.invalid:repo",
            "git remote add origin example.invalid:repo",
            "git remote set-url origin example.invalid:repo",
            "git config user.name testuser",
            "git -c user.email=testuser@example.invalid status",
            "GIT_AUTHOR_NAME=testuser git status",
        ):
            with self.subTest(command=command):
                self.assertTrue(synthetic_operands({"command": command}))

    def test_synthetic_network_twins_are_allowed(self):
        for command in (
            "curl -fsSL https://example.invalid/resource",
            "curl --user testuser example.invalid:80",
            "curl --proxy=example.invalid https://example.invalid/resource",
            "curl --url=example.invalid",
            "curl -xexample.invalid https://example.invalid/resource",
            "wget -O sample https://example.invalid/resource",
            "nc example.invalid 80",
            "nc -z example.invalid 80",
            "netcat example.invalid 80",
            "telnet example.invalid 80",
            "curl -H 'Host: example.invalid' https://example.invalid/resource",
            "nc -l -c 'nc example.invalid 80'",
            "curl -HHost:example.invalid https://example.invalid/resource",
            "curl --proxy-header='X-Forwarded-Host: example.invalid' https://example.invalid/resource",
            "wget -H example.invalid",
            "nc -sexample.invalid example.invalid 80",
        ):
            with self.subTest(command=command):
                self.assertTrue(synthetic_operands({"command": command}))

    def test_identifiers_in_tool_arguments_are_checked(self):
        self.assertFalse(synthetic_operands({"args": {"content": "git clone sample-host-17:repo"}}))
        self.assertTrue(synthetic_operands({"args": {"content": "git clone example.invalid:repo"}}))

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

    def test_new_literal_requires_review_even_with_updated_manifest(self):
        from scripts.check_d1_shapes import payload_digest

        rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()]
        rows[29]["command"] = "printf novelhostlabel"
        with TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "d1.jsonl"
            manifest = Path(temporary) / "approved.tsv"
            write_rows(corpus, rows)
            manifest.write_text("".join(f"{row['id']}\t{payload_digest(row)}\n" for row in rows), encoding="utf-8")
            self.assertIn("unreviewed public vocabulary", check(corpus, manifest))

    def test_new_tool_argument_name_requires_review(self):
        from scripts.check_d1_shapes import payload_digest

        rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()]
        rows[0]["args"]["novelhostlabel"] = "sample"
        with TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "d1.jsonl"
            manifest = Path(temporary) / "approved.tsv"
            write_rows(corpus, rows)
            manifest.write_text("".join(f"{row['id']}\t{payload_digest(row)}\n" for row in rows), encoding="utf-8")
            self.assertIn("unreviewed public vocabulary", check(corpus, manifest))

    def test_tool_metadata_requires_review_with_updated_manifest(self):
        from scripts.check_d1_shapes import payload_digest

        rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()]
        rows[29]["tool_name"] = "curl testbed"
        with TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "d1.jsonl"
            manifest = Path(temporary) / "approved.tsv"
            write_rows(corpus, rows)
            manifest.write_text("".join(f"{row['id']}\t{payload_digest(row)}\n" for row in rows), encoding="utf-8")
            self.assertIn("line 30: unapproved public tool", check(corpus, manifest))


if __name__ == "__main__":
    unittest.main()
