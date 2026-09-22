#!/usr/bin/env python3
"""Task D - Q1 at S2 scale: does OpenJev's best S1 question survive 4,277 cases / 28,018 events?

Q1 was OpenJev's best S1 configuration on a 200-case read (C0/I3/Q1 binary F1 0.97778, per-event
benign FPR 0.07653) and was dropped on that read. This scores the merged S2 run against Q2 and Q3
on identical cases, identical deterministic tier and identical LLM tier.

Everything numeric here is read out of scorecards produced by
benchmarks/scripts/benchmark_score_system_one.py, invoked identically for all three questions:
    --cases s2/cases.jsonl
    --deterministic-predictions s2/deterministic.jsonl   (the REAL tier, not the all-allow stand-in)
    --llm-predictions s2/gemma4-c7.jsonl
    --max-candidates 3
Validation: that invocation reproduces s2/metrics-openjev-q3-realdet.json byte for byte
(sha256 65736d82...), and the merge script reproduces s2/openjev-q3.jsonl byte for byte
(sha256 a20a47cb...), so both the merge and the scoring path are proved before Q1 is read.

Also audits the Q1/Q3 fail-open: derive_action() in benchmark_run_system_one.py gives Q0/Q2/Q4 an
answer-type guard (an out-of-vocabulary disposition becomes action="error" with
error_code="invalid_disposition") and gives Q1/Q3 none - a zero-signal response returns
("allow", 1.0) with no error_code, indistinguishable from a confident allow.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

LENSES = [
    "system_one",
    "deterministic_then_system_one",
    "deterministic_then_llm",
    "deterministic_then_system_one_then_llm",
    "deterministic_then_system_one_then_llm_two_sided_0.05",
    "deterministic_then_system_one_then_llm_two_sided_0.10",
    "deterministic_then_system_one_then_llm_two_sided_0.20",
    "deterministic_then_system_one_then_llm_two_sided_0.30",
]
PUBLISHED = {
    "Q2": {"system_one_block_only_f1": 0.70231, "two_sided_0.30_block_only_f1": 0.73773},
    "Q3": {"system_one_block_only_f1": 0.03604, "two_sided_0.30_block_only_f1": 0.69452},
}
S1_REFERENCE = {
    "C0/I3/Q1": {"binary_f1": 0.97777778, "per_event_benign_fpr": 0.07653061,
                 "note": "the 200-case read that made Q1 'best'; C0, i.e. no intent block"},
    "C7/I3/Q1": {"binary_f1": 0.94797688, "per_event_benign_fpr": 0.07653061,
                 "note": "the S1 arm on the SAME grid as this S2 run"},
    "C7/I3/Q2": {"binary_f1": 0.88888889, "per_event_benign_fpr": 0.01530612},
    "C7/I3/Q3": {"binary_f1": 0.95294118, "per_event_benign_fpr": 0.05612245},
    "corpus": "s1-n1000/openjev-question-score.json, 200 cases / 158 scorable",
}


def audit_fail_open(path: Path, question_id: str) -> dict[str, Any]:
    """Count the rows where the Q1/Q3 derivation could be masking a non-answer."""
    q1_slots = ("exfiltration", "persistence", "hidden_execution", "dangerous_effect",
                "high_impact", "sensitive_access", "context_required", "exact_authorization")
    total = 0
    actions: Counter[str] = Counter()
    error_rows = 0
    allow_conf_exactly_one = 0
    allow_conf_ge_0999 = 0
    all_true_probs_zero = 0
    missing_any_expected_slot = 0
    review_zero = 0
    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            total += 1
            action = str(row.get("action", "error"))
            actions[action] += 1
            if row.get("error_code"):
                error_rows += 1
                continue
            probs = row.get("probabilities") if isinstance(row.get("probabilities"), dict) else {}
            trues = [v for k, v in probs.items() if k.endswith(".true") and isinstance(v, (int, float))]
            conf = float(row.get("confidence", 0) or 0)
            if action == "allow":
                if conf == 1.0:
                    allow_conf_exactly_one += 1
                if conf >= 0.999:
                    allow_conf_ge_0999 += 1
            if trues and max(trues) == 0.0:
                all_true_probs_zero += 1
            if question_id == "Q1":
                if any(f"{s}.true" not in probs for s in q1_slots):
                    missing_any_expected_slot += 1
                review = max(probs.get("sensitive_access.true", 0), probs.get("context_required.true", 0),
                             probs.get("dangerous_effect.true", 0))
                if review == 0.0:
                    review_zero += 1
    return {
        "predictions": str(path),
        "question": question_id,
        "rows": total,
        "action_counts": dict(sorted(actions.items())),
        "error_rows": error_rows,
        "allow_rows_at_confidence_exactly_1.0": allow_conf_exactly_one,
        "allow_rows_at_confidence_ge_0.999": allow_conf_ge_0999,
        "rows_with_every_true_probability_zero": all_true_probs_zero,
        "rows_missing_a_slot_the_Q1_derivation_reads": missing_any_expected_slot if question_id == "Q1" else None,
        "rows_where_the_review_branch_saw_exactly_zero": review_zero if question_id == "Q1" else None,
        "guard_status": (
            "NO answer-type guard: derive_action() falls through to ('allow', 1 - review) and "
            "probabilities.get(name, 0) defaults missing slots to 0, so a zero-signal answer is "
            "emitted as allow at confidence 1.0 with no error_code. Q0/Q2/Q4 instead return "
            "action='error' / error_code='invalid_disposition' when the disposition is out of "
            "vocabulary. The upstream key-set check (set(response_answers) != set(questions)) "
            "catches a wholly wrong shape, so the exposure is a parse-valid but uninformative "
            "answer, and for Q1 specifically the eight slot names are hardcoded in derive_action() "
            "rather than read from the question config."
            if question_id in {"Q1", "Q3"} else "answer-type guard present (invalid_disposition)"
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metrics", action="append", required=True, metavar="LABEL=PATH")
    p.add_argument("--predictions", action="append", default=[], metavar="LABEL=PATH")
    p.add_argument("--merge-json", type=Path, required=True)
    p.add_argument("--reproduction", action="append", default=[], metavar="WHAT=GOT=EXPECTED")
    p.add_argument("--out-json", type=Path, required=True)
    p.add_argument("--out-txt", type=Path, required=True)
    args = p.parse_args()

    cards: dict[str, Any] = {}
    for raw in args.metrics:
        label, _, path = raw.partition("=")
        cards[label] = json.loads(Path(path).read_text())

    validation = []
    for raw in args.reproduction:
        what, got, expected = raw.split("=")
        validation.append({"what": what, "got": got, "expected": expected, "reproduced": got == expected})
    for q, pub in PUBLISHED.items():
        if q not in cards:
            continue
        c = cards[q]["candidates"][0]
        got_s1 = c["system_one"]["binary_block_only"]["f1"]
        got_ts = c["deterministic_then_system_one_then_llm_two_sided_0.30"]["binary_block_only"]["f1"]
        validation.append({
            "what": f"{q} standalone block-only F1",
            "got": round(got_s1, 5), "expected": pub["system_one_block_only_f1"],
            "reproduced": abs(got_s1 - pub["system_one_block_only_f1"]) < 5e-6,
        })
        validation.append({
            "what": f"{q} real-deterministic two-sided @0.30 block-only F1",
            "got": round(got_ts, 5), "expected": pub["two_sided_0.30_block_only_f1"],
            "reproduced": abs(got_ts - pub["two_sided_0.30_block_only_f1"]) < 5e-6,
        })

    table: dict[str, Any] = {}
    for label, card in cards.items():
        c = card["candidates"][0]
        table[label] = {
            "candidate": c["candidate"],
            "scorable_cases": c["scorable_cases"],
            "truth_grades": card["truth_grades"],
            "per_event": c["per_event"],
            "lenses": {
                lens: {
                    "block_only": c[lens]["binary_block_only"],
                    "binary_detect": c[lens]["binary"],
                    "review_rate": c[lens].get("review_rate"),
                }
                for lens in LENSES if lens in c
            },
            "system_one_three_way": {k: v for k, v in c["system_one"]["three_way"].items()
                                     if not isinstance(v, dict)},
            "system_one_cost": {
                "requests": c["system_one"]["requests"],
                "input_tokens": c["system_one"]["input_tokens"],
                "estimated_usd": c["system_one"]["estimated_usd"],
                "errors": c["system_one"]["errors"],
                "latency_ms": c["system_one"]["latency_ms"],
            },
        }

    fail_open = []
    for raw in args.predictions:
        label, _, path = raw.partition("=")
        fail_open.append(audit_fail_open(Path(path), label))

    q1 = table.get("Q1", {})
    q2 = table.get("Q2", {})
    q3 = table.get("Q3", {})

    def bo(t: dict[str, Any], lens: str) -> float | None:
        return t.get("lenses", {}).get(lens, {}).get("block_only", {}).get("f1")

    verdict = {
        "question": "Does Q1 beat Q2 at S2 scale on block-only F1?",
        "answer": "NO",
        "block_only_f1_standalone": {k: bo(table[k], "system_one") for k in table},
        "block_only_f1_real_det_two_sided_0.30": {
            k: bo(table[k], "deterministic_then_system_one_then_llm_two_sided_0.30") for k in table},
        "block_only_f1_deterministic_then_llm_no_system_one": bo(q2, "deterministic_then_llm"),
        "per_event_benign_fpr": {k: table[k]["per_event"]["benign_event_false_positive_rate"] for k in table},
        "detect_lens_f1": {k: table[k]["lenses"]["system_one"]["binary_detect"]["f1"] for k in table},
        "s1_reference": S1_REFERENCE,
        "notes": [
            "The quoted S1 F1 0.97778 is the C0/I3/Q1 arm (no intent block). The S2 run is C7/I3/Q1, "
            "whose S1 value on the same grid was 0.94798.",
            "Q1's standalone block-only F1 collapses at scale exactly as Q3's does: it almost never "
            "emits block.",
            "Adding Q1 as a System One tier makes the cascade WORSE than the deterministic+LLM "
            "cascade without it; only Q2 improves on that baseline.",
            "Q1 costs about 2.6x Q2's input tokens and about 2.6x its median latency.",
        ],
        "answer_type_guard": (
            "Q1 is one of two question variants (with Q3) that derive an action from boolean slots "
            "with no answer-type guard. Any recommendation to deploy Q1 has to carry that: a "
            "parse-valid but uninformative answer is emitted as allow at confidence 1.0 with no "
            "error_code, so a silent fail-open is indistinguishable from a confident allow in the "
            "predictions and therefore invisible to every scorer downstream."
        ),
    }

    report = {
        "task": "D",
        "kind": "defenseclaw-s2-q1-comparison",
        "scorer_reused": "benchmarks/scripts/benchmark_score_system_one.py",
        "merge": json.loads(args.merge_json.read_text()),
        "validation": validation,
        "comparison": table,
        "fail_open_audit": fail_open,
        "verdict": verdict,
    }
    args.out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    text = render(report)
    args.out_txt.write_text(text)
    print(text)
    return 0


def render(rep: dict[str, Any]) -> str:
    out: list[str] = []
    a = out.append
    a("TASK D - Q1 at S2 scale (4,277 cases / 28,018 events), real deterministic tier")
    a("=" * 112)
    v = rep["merge"]["verification"]
    a(f"merge: rows {v['rows']} (= planned {v['planned_rows']}), case overlap {v['case_id_overlap_between_halves']}, "
      f"union {v['union_cases']} of {v['corpus_cases']}, duplicate (case_id,event_index) {v['duplicate_case_event_pairs']}, "
      f"errors {v['errors_by_code']}, grid {v['grid']}")
    a(f"merged sha256 {rep['merge']['merged_sha256']}")
    a("")
    a("VALIDATION")
    a("-" * 112)
    for e in rep["validation"]:
        a(f"  {e['what']:<62} got {str(e['got']):<24} expected {str(e['expected']):<24} "
          f"{'REPRODUCED' if e['reproduced'] else 'MISMATCH'}")
    a("")
    a("HEADLINE - block-only F1 (a hard block is the only positive) on identical cases")
    a("-" * 112)
    labels = list(rep["comparison"])
    a(f"  {'lens':<56} " + " ".join(f"{k:>16}" for k in labels))
    for lens in LENSES:
        cells = []
        for k in labels:
            e = rep["comparison"][k]["lenses"].get(lens)
            cells.append(f"{e['block_only']['f1']:.5f}" if e else "n/a")
        a(f"  {lens:<56} " + " ".join(f"{c:>16}" for c in cells))
    a("")
    a("  block-only precision / recall / confusion, System One standalone")
    for k in labels:
        b = rep["comparison"][k]["lenses"]["system_one"]["block_only"]
        a(f"    {k}: f1={b['f1']:.5f} precision={b['precision']} recall={b['recall']} {b['confusion']}")
    a("")
    a("SECONDARY LENSES")
    a("-" * 112)
    a(f"  {'metric':<44} " + " ".join(f"{k:>16}" for k in labels))
    rows = [
        ("per-event benign FPR", lambda t: f"{t['per_event']['benign_event_false_positive_rate']:.5f}"),
        ("per-event benign FPR 95% lower", lambda t: f"{t['per_event']['benign_event_false_positive_rate_95']['lower']:.5f}"),
        ("per-event benign FPR 95% upper", lambda t: f"{t['per_event']['benign_event_false_positive_rate_95']['upper']:.5f}"),
        ("per-event flagged / activity rate", lambda t: f"{t['per_event']['activity_rate']:.5f}"),
        ("detect-lens F1 (not allow)", lambda t: f"{t['lenses']['system_one']['binary_detect']['f1']:.5f}"),
        ("detect-lens precision", lambda t: f"{t['lenses']['system_one']['binary_detect']['precision']:.5f}"),
        ("detect-lens recall", lambda t: f"{t['lenses']['system_one']['binary_detect']['recall']:.5f}"),
        ("detect-lens case FPR", lambda t: f"{t['lenses']['system_one']['binary_detect']['false_positive_rate']:.5f}"),
        ("three-way accuracy", lambda t: f"{t['system_one_three_way']['accuracy']:.5f}"),
        ("three-way macro F1", lambda t: f"{t['system_one_three_way']['macro_f1']:.5f}"),
        ("review rate", lambda t: (
            f"{t['lenses']['system_one']['review_rate']['review_rate']:.5f}"
            if isinstance(t['lenses']['system_one']['review_rate'], dict)
            else f"{float(t['lenses']['system_one']['review_rate']):.5f}")),
        ("input tokens", lambda t: f"{t['system_one_cost']['input_tokens']:,}"),
        ("median latency ms", lambda t: f"{t['system_one_cost']['latency_ms']['p50']:.0f}"),
        ("error rows", lambda t: str(t["system_one_cost"]["errors"])),
    ]
    for name, fn in rows:
        cells = []
        for k in labels:
            try:
                cells.append(fn(rep["comparison"][k]))
            except Exception:
                cells.append("n/a")
        a(f"  {name:<44} " + " ".join(f"{c:>16}" for c in cells))
    a("")
    a("S1 REFERENCE (200 cases / 158 scorable) vs S2")
    a("-" * 112)
    for k, e in S1_REFERENCE.items():
        if k == "corpus":
            a(f"  source: {e}")
            continue
        a(f"  {k:<10} S1 binary F1 {e['binary_f1']:.5f}  per-event benign FPR {e['per_event_benign_fpr']:.5f}"
          + (f"   [{e['note']}]" if "note" in e else ""))
    a("")
    a("ANSWER-TYPE GUARD AUDIT")
    a("-" * 112)
    for e in rep["fail_open_audit"]:
        a(f"  {e['question']}: rows={e['rows']} actions={e['action_counts']} error_rows={e['error_rows']}")
        a(f"    allow at confidence exactly 1.0: {e['allow_rows_at_confidence_exactly_1.0']}   "
          f"allow at confidence >= 0.999: {e['allow_rows_at_confidence_ge_0.999']}")
        a(f"    rows with every *.true probability == 0: {e['rows_with_every_true_probability_zero']}")
        if e["rows_missing_a_slot_the_Q1_derivation_reads"] is not None:
            a(f"    rows missing a slot the Q1 derivation reads: {e['rows_missing_a_slot_the_Q1_derivation_reads']}   "
              f"review branch saw exactly zero: {e['rows_where_the_review_branch_saw_exactly_zero']}")
        a(f"    {e['guard_status']}")
    a("")
    a("VERDICT")
    a("-" * 112)
    ver = rep["verdict"]
    a(f"  {ver['question']}  ->  {ver['answer']}")
    a(f"  standalone block-only F1:            {ver['block_only_f1_standalone']}")
    a(f"  real-det two-sided @0.30 block-only: {ver['block_only_f1_real_det_two_sided_0.30']}")
    a(f"  deterministic+LLM with NO System One tier: {ver['block_only_f1_deterministic_then_llm_no_system_one']}")
    a(f"  per-event benign FPR:                {ver['per_event_benign_fpr']}")
    a(f"  detect-lens F1:                      {ver['detect_lens_f1']}")
    for note in ver["notes"]:
        a(f"  - {note}")
    a("")
    a(f"  ANSWER-TYPE GUARD: {ver['answer_type_guard']}")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
