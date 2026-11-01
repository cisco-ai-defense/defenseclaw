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

"""Accept a well-formed skill judge answer from any supported model (GAP-2609).

The pinned skill-scanner checks each judge finding against an exact key set.
Some judge models (GPT-5.6 Luna on Bedrock) leave out a key whose value may
be null (``aisubtech`` most often) or add a key of their own. The scanner then
rejects the whole answer with "Primary finding has missing or unexpected
fields" and the scan fails, although every required field is present.

Before the scanner validates an answer, :func:`normalize_primary_answer`
fills a missing nullable field with ``None`` and drops keys the contract does
not define. The same model also cuts the last character off a 16-digit
evidence id now and then (``DET:74cb22b1b5bfd75`` for ``DET:74cb22b1b5bfd75b``);
:func:`repair_truncated_evidence_ids` maps such an id back when it is the
start of exactly one evidence id the scanner gave the model. Nothing else
changes: a missing or invalid required field, an invented or ambiguous
evidence id or a bad verdict still fails the answer, so a malformed answer
still fails the scan, and a judge failure is never turned into a clean result.
"""

from __future__ import annotations

import functools
import importlib.metadata
import logging
import sys
from typing import Any

_log = logging.getLogger(__name__)

# The skill-scanner primary answer contract (llm_analyzer._validate_primary_contract).
PRIMARY_TOP_LEVEL = frozenset({"findings", "overall_assessment", "verdict", "primary_threats"})
FINDING_REQUIRED = frozenset({
    "severity", "verdict", "category", "confidence", "evidence_ids", "aitech", "title", "description",
})
FINDING_NULLABLE = ("aisubtech", "location", "evidence", "remediation")
FINDING_KEYS = FINDING_REQUIRED | frozenset(FINDING_NULLABLE)

# A cut evidence id keeps at least this many of its 16 digits, so it still
# names one evidence item; a shorter one is left for the scanner to reject.
_MIN_EVIDENCE_ID_DIGITS = 12

_MARKER = "_defenseclaw_judge_compat"


def normalize_primary_answer(answer: Any) -> int:
    """Default missing nullable finding fields and drop unknown keys, in place.

    Returns the number of keys added or removed. Required keys are never
    added, so the scanner still rejects an answer that lacks one.
    """
    if not isinstance(answer, dict):
        return 0
    changes = 0
    for key in [k for k in answer if k not in PRIMARY_TOP_LEVEL]:
        del answer[key]
        changes += 1
    findings = answer.get("findings")
    if not isinstance(findings, list):
        return changes
    for item in findings:
        if not isinstance(item, dict):
            continue
        for key in [k for k in item if k not in FINDING_KEYS]:
            del item[key]
            changes += 1
        for key in FINDING_NULLABLE:
            if key not in item:
                item[key] = None
                changes += 1
    return changes


def _full_evidence_id(evidence_id: str, known: set[str]) -> str:
    """The one known id *evidence_id* is the start of, or *evidence_id* itself."""
    if evidence_id in known:
        return evidence_id
    kind, sep, digits = evidence_id.partition(":")
    if not (kind and sep and len(digits) >= _MIN_EVIDENCE_ID_DIGITS):
        return evidence_id
    candidates = [k for k in known if k.startswith(evidence_id)]
    return candidates[0] if len(candidates) == 1 else evidence_id


def repair_truncated_evidence_ids(answer: Any, allowed: Any) -> int:
    """Map a cut evidence id back to the one known id it starts, in place.

    Only an id the scanner does not know is touched, and only when it has the
    kind prefix (``DET:``, ``SRC:``), at least ``_MIN_EVIDENCE_ID_DIGITS``
    digits and starts exactly one known id. An invented, ambiguous or short id
    is kept as written, so the scanner still rejects the answer. Returns the
    number of ids mapped.
    """
    if not isinstance(answer, dict) or not isinstance(answer.get("findings"), list):
        return 0
    known = {i for i in (allowed or ()) if isinstance(i, str)}
    repairs = 0
    for item in answer["findings"]:
        ids = item.get("evidence_ids") if isinstance(item, dict) else None
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            continue
        mapped: list[str] = []
        item_repairs = 0
        for evidence_id in ids:
            full = _full_evidence_id(evidence_id, known)
            if full != evidence_id:
                item_repairs += 1
                if full in mapped or full in ids:
                    continue  # the finding already cites the full id
            mapped.append(full)
        if item_repairs:
            item["evidence_ids"] = mapped
            repairs += item_repairs
    return repairs


def install() -> bool:
    """Normalize every primary judge answer before skill-scanner validates it.

    Idempotent. Returns False, and changes nothing, when the scanner does not
    have the hook this relies on (a scanner version with another contract).
    """
    try:
        from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer
    except ImportError:
        return False
    original = getattr(LLMAnalyzer, "_repair_optional_taxonomy", None)
    if original is None or not hasattr(LLMAnalyzer, "_validate_primary_contract"):
        _log.debug("skill-scanner has no primary-answer hook; judge answers are checked as shipped")
        return False
    if getattr(original, _MARKER, False):
        return True

    # __wrapped__ keeps the scanner's own method reachable (tests check it).
    @functools.wraps(original)
    def _repair_optional_taxonomy(self: Any, analysis_result: dict[str, Any]) -> None:
        changes = normalize_primary_answer(analysis_result)
        if changes:
            _log.debug("normalized %d optional or unknown field(s) in the skill judge answer", changes)
        repaired = repair_truncated_evidence_ids(analysis_result, getattr(self, "_allowed_evidence_ids", ()))
        if repaired:
            _log.debug("mapped %d cut evidence id(s) in the skill judge answer to the id each one starts", repaired)
        original(self, analysis_result)

    setattr(_repair_optional_taxonomy, _MARKER, True)
    LLMAnalyzer._repair_optional_taxonomy = _repair_optional_taxonomy  # type: ignore[method-assign]
    return True


def main() -> Any:
    """Run the skill-scanner command line with the judge-answer fix installed.

    The scanner runtimes start this instead of the bare skill-scanner console
    script: ``sys.argv`` is the skill-scanner command line.
    """
    install()
    matches = [e for e in importlib.metadata.entry_points(group="console_scripts") if e.name == "skill-scanner"]
    if len(matches) != 1:
        print("defenseclaw: the skill-scanner command is not installed", file=sys.stderr)
        return 1
    sys.argv = ["skill-scanner", *sys.argv[1:]]
    return matches[0].load()()
