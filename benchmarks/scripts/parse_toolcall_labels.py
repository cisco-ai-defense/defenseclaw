"""Parse the gpt-oss-120b batch output into tool-call security labels.

The four-line reply form is parsed deterministically (batch inference forbids structured
output). INTRINSIC is the field that matters most for architecture: it separates calls that
are harmful regardless of the request from ones whose harm depends on user intent - the two
halves of DefenseClaw's definition of malicious.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

CATEGORIES = {
    "destructive", "exfiltration", "persistence", "privilege_escalation",
    "credential_access", "recon", "benign",
}
SEVERITIES = {"none", "low", "medium", "high"}

LINE = re.compile(r"^\s*(INTENT|CATEGORY|SEVERITY|INTRINSIC)\s*:\s*(.*)$", re.I | re.M)
# gpt-oss emits a <reasoning> block first; it can itself mention the field names, so strip it
# before parsing rather than letting reasoning text win over the real answer.
REASONING = re.compile(r"<reasoning>.*?(?:</reasoning>|\Z)", re.S | re.I)


def parse_reply(text: str) -> dict[str, str]:
    cleaned = REASONING.sub(" ", text or "")
    out: dict[str, str] = {}
    for key, value in LINE.findall(cleaned):
        out[key.upper()] = value.strip()
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--batch-output", type=Path, required=True)
    p.add_argument("--labels-out", type=Path, required=True)
    p.add_argument("--report-out", type=Path, required=True)
    args = p.parse_args()

    rows = []
    stats = {
        "records": 0, "parsed": 0, "unparsed": 0,
        "category": Counter(), "severity": Counter(), "intrinsic": Counter(),
        "intent_none": 0, "intent_present": 0,
        "by_class": Counter(), "category_by_class": Counter(),
        "prompt_tokens": 0, "completion_tokens": 0,
    }

    with args.batch_output.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            stats["records"] += 1
            custom_id = rec.get("custom_id") or ""
            record_class = custom_id.split(":", 1)[0] if ":" in custom_id else "unknown"
            body = ((rec.get("response") or {}).get("body")) or {}
            usage = body.get("usage") or {}
            stats["prompt_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
            stats["completion_tokens"] += int(usage.get("completion_tokens", 0) or 0)
            choices = body.get("choices") or []
            text = ""
            if choices:
                text = ((choices[0].get("message") or {}).get("content")) or ""
            fields = parse_reply(text)

            category = (fields.get("CATEGORY") or "").lower().strip().strip(".")
            severity = (fields.get("SEVERITY") or "").lower().strip().strip(".")
            intrinsic = (fields.get("INTRINSIC") or "").lower().strip().strip(".")
            intent = (fields.get("INTENT") or "").strip()

            ok = category in CATEGORIES and severity in SEVERITIES and intrinsic in {"yes", "no"}
            if not ok:
                stats["unparsed"] += 1
                continue
            stats["parsed"] += 1
            stats["category"][category] += 1
            stats["severity"][severity] += 1
            stats["intrinsic"][intrinsic] += 1
            stats["by_class"][record_class] += 1
            stats["category_by_class"][f"{record_class}:{category}"] += 1
            if intent.upper() == "NONE" or not intent:
                stats["intent_none"] += 1
                intent = ""
            else:
                stats["intent_present"] += 1

            rows.append({
                "custom_id": custom_id,
                "record_class": record_class,
                "intent": intent,
                "category": category,
                "severity": severity,
                "intrinsic": intrinsic == "yes",
                "model": "openai.gpt-oss-120b-1:0",
                "label_version": "toolcall-security-intent-v1",
            })

    args.labels_out.parent.mkdir(parents=True, exist_ok=True)
    with args.labels_out.open("w", encoding="utf-8") as out:
        for r in rows:
            out.write(json.dumps(r, sort_keys=True) + "\n")

    report = {
        "schema_version": "1",
        "kind": "defenseclaw-toolcall-label-report",
        "model": "openai.gpt-oss-120b-1:0",
        "records": stats["records"],
        "parsed": stats["parsed"],
        "unparsed": stats["unparsed"],
        "parse_rate": round(stats["parsed"] / max(1, stats["records"]), 6),
        "prompt_tokens": stats["prompt_tokens"],
        "completion_tokens": stats["completion_tokens"],
        "intent_present": stats["intent_present"],
        "intent_none": stats["intent_none"],
        "category": dict(stats["category"].most_common()),
        "severity": dict(stats["severity"].most_common()),
        "intrinsic": dict(stats["intrinsic"].most_common()),
        "by_class": dict(stats["by_class"].most_common()),
        "category_by_class": dict(sorted(stats["category_by_class"].items())),
    }
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in
                      ("records", "parsed", "unparsed", "parse_rate", "intent_present",
                       "intent_none", "category", "severity", "intrinsic", "by_class")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
