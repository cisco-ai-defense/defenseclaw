# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""A well-formed judge answer from any model is accepted (GAP-2609)."""

import copy
import unittest

from defenseclaw.scanner import _skill_judge_compat as compat
from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

_IDS = {"SRC:0e95f5a3666031d6", "DET:74cb22b1b5bfd75b"}


def _luna_answer() -> dict:
    """The answer GPT-5.6 Luna gave for the risky skill: no aisubtech key."""
    return {
        "findings": [{
            "severity": "CRITICAL",
            "verdict": "TRUE_POSITIVE",
            "category": "data_exfiltration",
            "confidence": "HIGH",
            "evidence_ids": sorted(_IDS),
            "aitech": "AITech-8.2",
            "title": "Reads cloud credentials and sends them out",
            "description": "run.py reads ~/.aws/credentials",
            "location": "run.py:3",
            "evidence": "open(os.path.expanduser(\"~/.aws/credentials\"))",
            "remediation": "Remove the credential read",
        }],
        "overall_assessment": "Exfiltrates credentials",
        "verdict": "MALICIOUS",
        "primary_threats": ["data_exfiltration"],
    }


class SkillJudgeCompatTest(unittest.TestCase):
    def setUp(self):
        self._original = LLMAnalyzer._repair_optional_taxonomy
        self.addCleanup(setattr, LLMAnalyzer, "_repair_optional_taxonomy", self._original)
        # Start from the pinned scanner's own method, whatever an earlier test
        # in this process installed (r106 CI GAP-0055).
        pinned = self._original
        while getattr(pinned, compat._MARKER, False):
            pinned = pinned.__wrapped__
        LLMAnalyzer._repair_optional_taxonomy = pinned
        self.analyzer = object.__new__(LLMAnalyzer)
        self.analyzer._allowed_evidence_ids = set(_IDS)
        self.analyzer.taxonomy_repairs = 0

    def _check(self, answer: dict) -> dict:
        self.analyzer._repair_optional_taxonomy(answer)
        self.analyzer._validate_primary_contract(answer)
        return answer

    def test_pinned_scanner_rejects_missing_nullable_field_without_fix(self):
        with self.assertRaisesRegex(ValueError, "missing or unexpected fields"):
            self._check(_luna_answer())

    def test_missing_nullable_fields_default_to_none(self):
        self.assertTrue(compat.install())
        answer = _luna_answer()
        for key in ("location", "evidence", "remediation"):
            del answer["findings"][0][key]
        finding = self._check(answer)["findings"][0]
        for key in compat.FINDING_NULLABLE:
            self.assertIsNone(finding[key])
        self.assertEqual(finding["severity"], "CRITICAL")

    def test_unknown_fields_are_ignored(self):
        compat.install()
        answer = _luna_answer()
        answer["findings"][0]["line"] = 3
        answer["model_notes"] = "extra"
        checked = self._check(answer)
        self.assertNotIn("line", checked["findings"][0])
        self.assertNotIn("model_notes", checked)

    def test_missing_required_field_still_fails(self):
        compat.install()
        for key in sorted(compat.FINDING_REQUIRED):
            answer = _luna_answer()
            del answer["findings"][0][key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self._check(answer)
        answer = _luna_answer()
        del answer["primary_threats"]
        with self.assertRaisesRegex(ValueError, "top-level"):
            self._check(answer)

    def test_malformed_answers_still_fail(self):
        compat.install()
        cases = {
            "invented evidence id": ("evidence_ids", ["DET:ffffffffffffffff"]),
            "too short evidence id": ("evidence_ids", ["DET:74cb22b1"]),
            "evidence id without kind": ("evidence_ids", ["74cb22b1b5bfd75"]),
            "bad aitech": ("aitech", "AITech-99"),
            "bad severity": ("severity", "SEVERE"),
        }
        for name, (key, value) in cases.items():
            answer = _luna_answer()
            answer["findings"][0][key] = value
            with self.subTest(name), self.assertRaises(ValueError):
                self._check(answer)
        answer = _luna_answer()
        answer["findings"].append("not a finding")
        with self.assertRaisesRegex(ValueError, "missing or unexpected fields"):
            self._check(answer)

    def test_cut_evidence_id_maps_to_the_one_id_it_starts(self):
        answer = _luna_answer()
        answer["findings"][0]["aisubtech"] = None
        answer["findings"][0]["evidence_ids"] = ["SRC:0e95f5a3666031d6", "DET:74cb22b1b5bfd75"]
        with self.assertRaisesRegex(ValueError, "unknown evidence IDs"):
            self._check(copy.deepcopy(answer))
        compat.install()
        checked = self._check(answer)
        self.assertEqual(checked["findings"][0]["evidence_ids"], ["SRC:0e95f5a3666031d6", "DET:74cb22b1b5bfd75b"])

    def test_cut_evidence_id_next_to_its_full_id_is_dropped(self):
        compat.install()
        answer = _luna_answer()
        answer["findings"][0]["evidence_ids"] = ["DET:74cb22b1b5bfd75b", "DET:74cb22b1b5bfd75"]
        checked = self._check(answer)
        self.assertEqual(checked["findings"][0]["evidence_ids"], ["DET:74cb22b1b5bfd75b"])

    def test_ambiguous_cut_evidence_id_still_fails(self):
        compat.install()
        self.analyzer._allowed_evidence_ids = set(_IDS) | {"DET:74cb22b1b5bfd75c"}
        answer = _luna_answer()
        answer["findings"][0]["evidence_ids"] = ["DET:74cb22b1b5bfd75"]
        with self.assertRaisesRegex(ValueError, "unknown evidence IDs"):
            self._check(answer)

    def test_complete_answer_is_unchanged_and_install_is_idempotent(self):
        self.assertTrue(compat.install())
        patched = LLMAnalyzer._repair_optional_taxonomy
        self.assertTrue(compat.install())
        self.assertIs(LLMAnalyzer._repair_optional_taxonomy, patched)
        answer = _luna_answer()
        answer["findings"][0]["aisubtech"] = None
        before = copy.deepcopy(answer)
        self.assertEqual(self._check(answer), before)


if __name__ == "__main__":
    unittest.main()
