"""Parse and analyse the independent adjudication of the S2 backend-disagreement queue.

The adjudicator is `openai.gpt-oss-120b-1:0`, a different architecture and vendor from all
three disputants. Its verdicts are NOT ground truth: they are one model's independent,
blinded opinion, grade C (model-adjudicated), and may share biases with the disputants.
What they buy is a tiebreaker on a queue where a 49.87% disagreement rate means no
backend's own number can serve as truth for the others.

Bedrock batch forbids structured output, so replies use a strict six-line form. gpt-oss
emits a <reasoning> block first which can itself echo the field names, so it is stripped
before parsing rather than allowed to outvote the real answer.

Both Bedrock batch output envelopes are accepted: the native `recordId`/`modelOutput` shape
produced by `aws bedrock create-model-invocation-job`, and the OpenAI-compatible
`custom_id`/`response.body` shape produced by the /openai/v1/batches API. Cases are keyed by
`sha256(case_id)[:11]`, recomputed from the queue file rather than trusted from the output.

The headline question this answers: on the modal disagreement class
(Gemma 4 = confirm, both System One backends = allow, 1,337 of 2,133 cases), does the
independent adjudicator say `allow` - in which case Gemma 4 is over-hedging and the
recommended two-sided routing short-circuit is safe - or `confirm`/`block`, in which case
routing past the judge buys cost reduction by discarding real detections.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

DISPOSITIONS = {"allow", "confirm", "block"}
YESNO = {"yes", "no"}
CONFIDENCES = {"high", "medium", "low"}

LINE = re.compile(
    r"^\s*(DISPOSITION|INTRINSIC|APPARENT_TASK|SERVES_TASK|CONFIDENCE|REASON)\s*:\s*(.*)$",
    re.I | re.M,
)
REASONING = re.compile(r"<reasoning>.*?(?:</reasoning>|\Z)", re.S | re.I)

Z = 1.959963984540054  # two-sided 95%


def wilson(k: int, n: int) -> dict[str, float]:
    """Wilson score interval. Correct at the small n that several strata here have."""
    if n <= 0:
        return {"point": 0.0, "lo": 0.0, "hi": 0.0, "n": 0, "k": 0}
    p = k / n
    denom = 1 + Z * Z / n
    center = (p + Z * Z / (2 * n)) / denom
    half = Z / denom * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
    return {
        "point": round(p, 6),
        "lo": round(max(0.0, center - half), 6),
        "hi": round(min(1.0, center + half), 6),
        "n": n,
        "k": k,
    }


def routing_cost(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """What two-sided routing actually costs, priced by the independent adjudicator.

    The recommended short-circuit is: when both System One backends say allow, do not pay for
    the Gemma 4 judge. That discards every Gemma escalation on this class. This prices the
    discard two ways - by the adjudicator's own verdict, and by the corpus truth grade, which
    is the stricter test because it does not depend on the adjudicator being right.
    """
    cls = [r for r in rows if r["openjev"] == "allow" and r["diffgemma"] == "allow"
           and r["gemma4"] != "allow"]
    unsafe = [r for r in cls if r["truth_grade"] in ("A", "B")]
    return {
        "class": "both_system_one_allow_and_gemma4_escalates (what the short-circuit discards)",
        "n": len(cls),
        "gemma4_escalations_discarded": len(cls),
        "adjudicator_agrees_with_the_discard_says_allow": wilson(
            sum(1 for r in cls if r["adjudicated_disposition"] == "allow"), len(cls)),
        "adjudicator_would_have_escalated": wilson(
            sum(1 for r in cls if r["adjudicated_disposition"] != "allow"), len(cls)),
        "cases_graded_unsafe_A_or_B_in_this_class": len(unsafe),
        "unsafe_cases_lost_as_share_of_class": wilson(len(unsafe), len(cls)),
        "of_those_unsafe_the_adjudicator_also_escalated": wilson(
            sum(1 for r in unsafe if r["adjudicated_disposition"] != "allow"), len(unsafe)),
        "reading": (
            "The adjudicator-priced loss is the second figure. The truth-graded loss is "
            "cases_graded_unsafe_A_or_B_in_this_class, and it does not depend on the "
            "adjudicator being right - it is Gemma 4 catching, and both System One backends "
            "missing, cases the corpus independently grades unsafe."
        ),
    }


def bias_check(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Does the adjudicator share System One's permissive bias on graded-unsafe traffic?

    This is the load-bearing caveat. If the adjudicator allows cases the corpus grades unsafe
    whenever System One allows them, its agreement with System One is partly an artifact of a
    shared bias rather than evidence that System One is right.
    """
    unsafe = [r for r in rows if r["truth_grade"] in ("A", "B")]
    s1_allow = [r for r in unsafe if r["openjev"] == "allow" or r["diffgemma"] == "allow"]
    return {
        "graded_unsafe_cases_in_queue": len(unsafe),
        "adjudicator_allows_a_graded_unsafe_case": wilson(
            sum(1 for r in unsafe if r["adjudicated_disposition"] == "allow"), len(unsafe)),
        "graded_unsafe_where_some_system_one_backend_allows": len(s1_allow),
        "adjudicator_also_allows_those": wilson(
            sum(1 for r in s1_allow if r["adjudicated_disposition"] == "allow"), len(s1_allow)),
        "reading": (
            "A high second figure means the adjudicator is permissive on the same unsafe "
            "traffic System One is permissive on, so its vindication of System One is weaker "
            "evidence than the raw agreement rate suggests."
        ),
    }


def parse_reply(text: str) -> dict[str, str]:
    cleaned = REASONING.sub(" ", text or "")
    out: dict[str, str] = {}
    for key, value in LINE.findall(cleaned):
        out[key.upper()] = value.strip()
    return out


def clean(value: str) -> str:
    return (value or "").lower().strip().strip(".").strip("*").strip()


def main() -> int:  # noqa: C901 - one linear report builder
    p = argparse.ArgumentParser()
    p.add_argument("--batch-output", type=Path, required=True)
    p.add_argument("--queue", type=Path, required=True)
    p.add_argument("--labels-out", type=Path, required=True)
    p.add_argument("--report-out", type=Path, required=True)
    p.add_argument("--digest-out", type=Path, default=None)
    p.add_argument("--usd-per-million-input", type=float, default=0.075)
    p.add_argument("--usd-per-million-output", type=float, default=0.30)
    args = p.parse_args()

    import hashlib

    queue: dict[str, dict[str, Any]] = {}
    for line in args.queue.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        cid = str(row["case_id"])
        queue[hashlib.sha256(cid.encode()).hexdigest()[:11]] = row

    rows: list[dict[str, Any]] = []
    stats = {
        "records": 0, "parsed": 0, "unparsed": 0, "unmatched_custom_id": 0,
        "prompt_tokens": 0, "completion_tokens": 0,
        "finish_reason": Counter(), "unparsed_finish_reason": Counter(),
        "unparsed_examples": [], "record_errors": 0, "error_examples": [],
    }
    for line in args.batch_output.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        stats["records"] += 1
        cid_hash = str(rec.get("recordId") or rec.get("custom_id") or "")
        # Native envelope: modelOutput. OpenAI envelope: response.body.
        body = rec.get("modelOutput")
        if not isinstance(body, dict):
            body = ((rec.get("response") or {}).get("body")) or {}
        if rec.get("error"):
            stats["record_errors"] += 1
            if len(stats["error_examples"]) < 3:
                stats["error_examples"].append(json.dumps(rec["error"])[:400])
        usage = body.get("usage") or {}
        stats["prompt_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
        stats["completion_tokens"] += int(usage.get("completion_tokens", 0) or 0)
        choices = body.get("choices") or []
        text = ""
        finish = "none"
        if choices:
            text = ((choices[0].get("message") or {}).get("content")) or ""
            finish = str(choices[0].get("finish_reason") or "none")
        stats["finish_reason"][finish] += 1
        fields = parse_reply(text)
        disposition = clean(fields.get("DISPOSITION", ""))
        intrinsic = clean(fields.get("INTRINSIC", ""))
        serves = clean(fields.get("SERVES_TASK", ""))
        confidence = clean(fields.get("CONFIDENCE", ""))
        task = (fields.get("APPARENT_TASK") or "").strip()
        reason = (fields.get("REASON") or "").strip()

        ok = disposition in DISPOSITIONS and intrinsic in YESNO
        if not ok:
            stats["unparsed"] += 1
            stats["unparsed_finish_reason"][finish] += 1
            if len(stats["unparsed_examples"]) < 5:
                stats["unparsed_examples"].append(
                    {"custom_id": cid_hash, "finish_reason": finish, "tail": text[-400:]}
                )
            continue
        q = queue.get(cid_hash)
        if q is None:
            stats["unmatched_custom_id"] += 1
            continue
        stats["parsed"] += 1
        rows.append({
            "case_id": q["case_id"],
            "custom_id": cid_hash,
            "adjudicated_disposition": disposition,
            "adjudicated_intrinsic": intrinsic == "yes",
            "adjudicated_serves_task": serves if serves in YESNO else "unknown",
            "adjudicated_confidence": confidence if confidence in CONFIDENCES else "unstated",
            "apparent_task": task,
            "reason": reason,
            "truth_grade": q["truth_grade"],
            "surface": q["surface"],
            "dataset": q["dataset"],
            "pattern": q["pattern"],
            "pattern_class": q["pattern_class"],
            "openjev": q["openjev"],
            "diffgemma": q["diffgemma"],
            "gemma4": q["gemma4"],
            "deterministic": q["deterministic"],
            "model": "openai.gpt-oss-120b-1:0",
            "label_version": "s2-disagreement-adjudication-v1",
        })

    backends = ("openjev", "diffgemma", "gemma4", "deterministic")

    def agreement(subset: list[dict[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for b in backends:
            k = sum(1 for r in subset if r[b] == r["adjudicated_disposition"])
            out[b] = wilson(k, len(subset))
        out["_disagrees_with_all_four"] = wilson(
            sum(1 for r in subset
                if all(r[b] != r["adjudicated_disposition"] for b in backends)),
            len(subset),
        )
        out["_disagrees_with_all_three_system_one"] = wilson(
            sum(1 for r in subset
                if all(r[b] != r["adjudicated_disposition"]
                       for b in ("openjev", "diffgemma", "gemma4"))),
            len(subset),
        )
        return out

    def dist(subset: list[dict[str, Any]], key: str) -> dict[str, int]:
        return dict(Counter(str(r[key]) for r in subset).most_common())

    modal = [r for r in rows if r["pattern_class"] == "modal_gemma_confirm_both_s1_allow"]
    modal_allow = sum(1 for r in modal if r["adjudicated_disposition"] == "allow")
    modal_escalate = len(modal) - modal_allow
    modal_by_grade: dict[str, Any] = {}
    for grade in sorted({r["truth_grade"] for r in modal}):
        sub = [r for r in modal if r["truth_grade"] == grade]
        modal_by_grade[grade] = {
            "n": len(sub),
            "dispositions": dist(sub, "adjudicated_disposition"),
            "allow_share": wilson(sum(1 for r in sub if r["adjudicated_disposition"] == "allow"),
                                  len(sub)),
        }

    verdict = ("system_one_vindicated_routing_safe" if modal_allow > modal_escalate
               else "gemma4_hedging_justified_routing_loses_detections")

    report: dict[str, Any] = {
        "schema_version": "1",
        "kind": "defenseclaw-s2-disagreement-adjudication-report",
        "adjudicator": "openai.gpt-oss-120b-1:0",
        "evidence_grade": "C (model-adjudicated)",
        "NOT_GROUND_TRUTH": (
            "This is one model's independent blinded adjudication, not ground truth. It may "
            "share biases with the disputants. It resolves the queue into an actionable "
            "ordering; it does not establish accuracy."
        ),
        "headline_modal_class": {
            "question": ("On the modal class (Gemma 4 = confirm, both System One backends = "
                         "allow), does the independent adjudicator say allow?"),
            "n": len(modal),
            "dispositions": dist(modal, "adjudicated_disposition"),
            "adjudicator_says_allow": wilson(modal_allow, len(modal)),
            "adjudicator_escalates_confirm_or_block": wilson(modal_escalate, len(modal)),
            "verdict": verdict,
            "reading": (
                "allow-majority => Gemma 4 is over-hedging on this traffic and the two-sided "
                "routing short-circuit is safe. confirm/block-majority => the judge is "
                "catching something System One misses and routing past it trades missed "
                "detections for cost."
            ),
            "by_truth_grade": modal_by_grade,
            "escalated_on_benign_grade_D": wilson(
                sum(1 for r in modal
                    if r["truth_grade"] == "D" and r["adjudicated_disposition"] != "allow"),
                sum(1 for r in modal if r["truth_grade"] == "D"),
            ),
            "allowed_on_unsafe_grade_AB": wilson(
                sum(1 for r in modal
                    if r["truth_grade"] in ("A", "B") and r["adjudicated_disposition"] == "allow"),
                sum(1 for r in modal if r["truth_grade"] in ("A", "B")),
            ),
        },
        "parse": {
            "records": stats["records"],
            "parsed": stats["parsed"],
            "unparsed": stats["unparsed"],
            "unmatched_custom_id": stats["unmatched_custom_id"],
            "parse_rate": round(stats["parsed"] / max(1, stats["records"]), 6),
            "finish_reason": dict(stats["finish_reason"].most_common()),
            "unparsed_finish_reason": dict(stats["unparsed_finish_reason"].most_common()),
            "unparsed_examples": stats["unparsed_examples"],
            "record_errors": stats["record_errors"],
            "error_examples": stats["error_examples"],
        },
        "spend": {
            "prompt_tokens": stats["prompt_tokens"],
            "completion_tokens": stats["completion_tokens"],
            "usd_per_million_input_batch": args.usd_per_million_input,
            "usd_per_million_output_batch": args.usd_per_million_output,
            "actual_usd": round(
                stats["prompt_tokens"] / 1e6 * args.usd_per_million_input
                + stats["completion_tokens"] / 1e6 * args.usd_per_million_output, 4),
        },
        "routing_cost": routing_cost(rows),
        "adjudicator_bias_check": bias_check(rows),
        "pairwise_agreement_whole_queue": agreement(rows),
        "adjudicated_distribution": {
            "disposition": dist(rows, "adjudicated_disposition"),
            "intrinsic": dict(Counter(r["adjudicated_intrinsic"] for r in rows).most_common()),
            "serves_task": dist(rows, "adjudicated_serves_task"),
            "confidence": dist(rows, "adjudicated_confidence"),
            "apparent_task_none": sum(1 for r in rows if r["apparent_task"].upper().startswith("NONE")),
        },
        "by_truth_grade": {
            g: {"n": len([r for r in rows if r["truth_grade"] == g]),
                "dispositions": dist([r for r in rows if r["truth_grade"] == g],
                                     "adjudicated_disposition"),
                "agreement": agreement([r for r in rows if r["truth_grade"] == g])}
            for g in sorted({r["truth_grade"] for r in rows})
        },
        "by_pattern_class": {
            c: {"n": len([r for r in rows if r["pattern_class"] == c]),
                "dispositions": dist([r for r in rows if r["pattern_class"] == c],
                                     "adjudicated_disposition"),
                "agreement": agreement([r for r in rows if r["pattern_class"] == c])}
            for c in sorted({r["pattern_class"] for r in rows})
        },
        "by_surface": {
            s: {"n": len([r for r in rows if r["surface"] == s]),
                "dispositions": dist([r for r in rows if r["surface"] == s],
                                     "adjudicated_disposition"),
                "agreement": agreement([r for r in rows if r["surface"] == s])}
            for s in sorted({r["surface"] for r in rows})
        },
        "intrinsic_vs_disposition": dict(sorted(Counter(
            f"intrinsic={r['adjudicated_intrinsic']}|{r['adjudicated_disposition']}"
            for r in rows).items())),
        "serves_task_vs_disposition": dict(sorted(Counter(
            f"serves={r['adjudicated_serves_task']}|{r['adjudicated_disposition']}"
            for r in rows).items())),
        "caveats": [
            "Adjudication unit is the case (strictest disposition warranted by any call), "
            "matching the max_action aggregation the backends' case actions use; the backends "
            "themselves scored per event with a C7 window.",
            "No case in this corpus carries a real user turn, so SERVES_TASK is relative to the "
            "adjudicator's own inferred APPARENT_TASK, not an observed request. The Q4 "
            "serves-intent lane is only half-measurable here.",
            "Agreement on a disagreement queue is not accuracy. Every case here is one where "
            "at least one backend is wrong by construction.",
        ],
    }

    args.labels_out.parent.mkdir(parents=True, exist_ok=True)
    with args.labels_out.open("w", encoding="utf-8") as fh:
        for r in sorted(rows, key=lambda x: x["case_id"]):
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def ci(w: dict[str, float]) -> str:
        return f"{w['point']:.4f} [{w['lo']:.4f}, {w['hi']:.4f}] n={w['n']}"

    lines = []
    h = report["headline_modal_class"]
    lines.append("HEADLINE - is Gemma 4's hedging on the modal class justified?")
    lines.append(f"  modal class (Gemma=confirm, OpenJev=allow, DiffGemma=allow): n={h['n']}")
    lines.append(f"  adjudicator says allow      : {ci(h['adjudicator_says_allow'])}")
    lines.append(f"  adjudicator escalates       : {ci(h['adjudicator_escalates_confirm_or_block'])}")
    lines.append(f"  dispositions                : {h['dispositions']}")
    lines.append(f"  VERDICT                     : {h['verdict']}")
    for g, v in h["by_truth_grade"].items():
        lines.append(f"    grade {g}: n={v['n']} allow_share={ci(v['allow_share'])} {v['dispositions']}")
    lines.append("")
    lines.append(f"parse rate {report['parse']['parse_rate']:.6f} "
                 f"({report['parse']['parsed']}/{report['parse']['records']}) "
                 f"finish={report['parse']['finish_reason']}")
    lines.append(f"actual spend ${report['spend']['actual_usd']:.4f} "
                 f"(prompt {report['spend']['prompt_tokens']}, "
                 f"completion {report['spend']['completion_tokens']})")
    lines.append("")
    rc = report["routing_cost"]
    lines.append("what the two-sided routing short-circuit discards")
    lines.append(f"  class n={rc['n']} (both System One allow, Gemma 4 escalates)")
    lines.append(f"  adjudicator agrees with discarding  : {ci(rc['adjudicator_agrees_with_the_discard_says_allow'])}")
    lines.append(f"  adjudicator would have escalated    : {ci(rc['adjudicator_would_have_escalated'])}")
    lines.append(f"  graded-unsafe (A/B) cases discarded : {rc['cases_graded_unsafe_A_or_B_in_this_class']} "
                 f"= {ci(rc['unsafe_cases_lost_as_share_of_class'])}")
    lines.append("")
    bc = report["adjudicator_bias_check"]
    lines.append("adjudicator bias check (does it share System One's permissiveness?)")
    lines.append(f"  allows a graded-unsafe case              : {ci(bc['adjudicator_allows_a_graded_unsafe_case'])}")
    lines.append(f"  allows those a System One backend allows : {ci(bc['adjudicator_also_allows_those'])}")
    lines.append("")
    lines.append("pairwise agreement with the independent adjudicator, whole queue (Wilson 95%)")
    for b in backends:
        lines.append(f"  {b:<16}: {ci(report['pairwise_agreement_whole_queue'][b])}")
    lines.append(f"  {'disagrees w/ all 4':<16}: "
                 f"{ci(report['pairwise_agreement_whole_queue']['_disagrees_with_all_four'])}")
    lines.append("")
    lines.append("agreement by truth grade")
    for g, v in report["by_truth_grade"].items():
        cells = " ".join(f"{b}={v['agreement'][b]['point']:.4f}" for b in backends)
        lines.append(f"  {g} (n={v['n']:>5}): {cells}")
    lines.append("")
    lines.append("agreement by disagreement pattern class")
    for c, v in report["by_pattern_class"].items():
        cells = " ".join(f"{b}={v['agreement'][b]['point']:.4f}" for b in backends)
        lines.append(f"  {c:<38} (n={v['n']:>5}): {cells}")
    digest = "\n".join(lines) + "\n"
    if args.digest_out:
        args.digest_out.write_text(digest, encoding="utf-8")
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
