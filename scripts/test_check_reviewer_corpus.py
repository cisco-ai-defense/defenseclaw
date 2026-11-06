# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
import unittest

from scripts.check_reviewer_corpus import collect, verdict_key


class ReviewerCorpusTest(unittest.TestCase):
    def test_keeps_verdict_and_drops_command_text(self):
        key = verdict_key("TestRVCdvarCorpus/cc", "RVROW|01|codex|false|B|allow|-|echo sample")
        self.assertEqual(key, "TestRVCdvarCorpus\tRVROW|01|codex|false|B|allow|-")

    def test_empty_run_is_error(self):
        with self.assertRaisesRegex(ValueError, "no reviewer corpus"):
            collect([json.dumps({"Action": "output", "Output": "PASS\\n"})])

    def test_windows_verdict_is_recorded(self):
        self.assertEqual(
            verdict_key(
                "TestRVWL2Comment", "    reviewer_test.go:12: CMT codex/per-user sample action=block ids=[RULE]"
            ),
            "TestRVWL2Comment\tCMT codex/per-user sample|block|[RULE]",
        )


if __name__ == "__main__":
    unittest.main()
