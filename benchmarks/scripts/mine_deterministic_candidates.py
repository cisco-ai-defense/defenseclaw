"""Mine candidate deterministic rules from System One predictions.

Deterministic-only measured recall 0.02273 at FPR 0.00000 on the S1 screen: it catches almost
nothing but never false-positives. Anything promoted into deterministic runs at ZERO runtime
model cost, so the cases System One blocks confidently and deterministic allows are the
highest-value target in the whole integration.

Emits a value-free, ranked review queue. Per the plan, rules stay human-authored: this
produces candidates and evidence, never executable rules.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from benchmark_inventory_system_one_sources import read_jsonl, truth_grade
except ModuleNotFoundError:
    from benchmarks.scripts.benchmark_inventory_system_one_sources import read_jsonl, truth_grade

# Coarse, auditable shape extraction. Deliberately not a parser: the point is to cluster
# similar commands so a human can see which families of call are worth an exact proof.
TOKEN = re.compile(r"[A-Za-z0-9_./-]+")
SIGNALS = (
    ("pipe_to_shell", re.compile(r"\|\s*(bash|sh|zsh)\b")),
    ("curl_or_wget", re.compile(r"\b(curl|wget)\b")),
    ("rm_recursive", re.compile(r"\brm\b[^|;]*-[a-zA-Z]*r")),
    ("chmod_permissive", re.compile(r"\bchmod\s+(777|a\+[rwx]+)")),
    ("credential_path", re.compile(r"(id_rsa|authorized_keys|\.aws/credentials|/etc/shadow|\.npmrc|\.netrc)")),
    ("passwd_or_useradd", re.compile(r"\b(passwd|useradd|usermod|chpasswd)\b")),
    ("dev_tcp", re.compile(r"/dev/tcp/")),
    ("base64_decode", re.compile(r"\bbase64\b[^|;]*-{1,2}d")),
    ("crontab_or_systemd", re.compile(r"\b(crontab|systemctl|launchctl)\b")),
    ("nohup_background", re.compile(r"\b(nohup|setsid)\b")),
    ("sudo", re.compile(r"\bsudo\b")),
    ("history_tamper", re.compile(r"(HISTFILE|history\s+-c|\.bash_history)")),
)


def command_text(case: dict[str, Any], event_index: int) -> str:
    payload = case.get("payload") if isinstance(case.get("payload"), dict) else {}
    events = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
    if event_index < 0 or event_index >= len(events):
        return ""
    ev = events[event_index] if isinstance(events[event_index], dict) else {}
    args = ev.get("args")
    if args in (None, {}, ""):
        args = ev.get("command") or ev.get("argv") or ""
    return args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)


def shape(text: str) -> tuple[str, list[str]]:
    hits = [name for name, rx in SIGNALS if rx.search(text)]
    head = ""
    m = TOKEN.search(text or "")
    if m:
        head = Path(m.group(0)).name[:40]
    return head, hits


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--system-one-predictions", action="append", type=Path, required=True)
    p.add_argument("--deterministic-predictions", type=Path)
    p.add_argument("--block-threshold", type=float, default=0.75)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--top", type=int, default=40)
    args = p.parse_args()

    cases = {str(r["id"]): r for r in read_jsonl(args.cases)}
    det_allowed: set[str] = set()
    if args.deterministic_predictions:
        for row in read_jsonl(args.deterministic_predictions):
            if str(row.get("action", "allow")) == "allow":
                det_allowed.add(str(row.get("case_id", "")))
    else:
        det_allowed = set(cases)

    clusters: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = defaultdict(
        lambda: {"events": 0, "grades": Counter(), "examples": [], "max_conf": 0.0, "cases": set()}
    )
    considered = missed = 0

    for path in args.system_one_predictions:
        for row in read_jsonl(path):
            if row.get("error_code"):
                continue
            action = str(row.get("action", ""))
            if action != "block":
                continue
            conf = float(row.get("confidence", 0) or 0)
            if conf < args.block_threshold:
                continue
            case_id = str(row.get("case_id", ""))
            considered += 1
            if case_id not in det_allowed or case_id not in cases:
                continue
            missed += 1
            case = cases[case_id]
            text = command_text(case, int(row.get("event_index", -1)))
            if not text.strip():
                continue
            head, hits = shape(text)
            key = (head, tuple(hits))
            c = clusters[key]
            c["events"] += 1
            c["grades"][truth_grade(case)] += 1
            c["max_conf"] = max(c["max_conf"], conf)
            c["cases"].add(case_id)
            if len(c["examples"]) < 3:
                # bounded, value-free excerpt: shape evidence only
                c["examples"].append(text[:160])

    ranked = sorted(
        (
            {
                "head_token": head,
                "signals": list(hits),
                "events": c["events"],
                "distinct_cases": len(c["cases"]),
                "truth_grades": dict(sorted(c["grades"].items())),
                "max_confidence": round(c["max_conf"], 6),
                "example_excerpts": c["examples"],
                "priority": round(c["events"] * c["max_conf"], 3),
            }
            for (head, hits), c in clusters.items()
        ),
        key=lambda r: -r["priority"],
    )

    report = {
        "schema_version": "1",
        "kind": "defenseclaw-deterministic-candidate-queue",
        "block_threshold": args.block_threshold,
        "confident_blocks_considered": considered,
        "confident_blocks_deterministic_missed": missed,
        "clusters": len(ranked),
        "note": (
            "Candidates only. Rules remain human-authored and must follow the existing exact-proof "
            "workflow; nothing here is an executable rule."
        ),
        "top_clusters": ranked[: args.top],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in
                      ("confident_blocks_considered", "confident_blocks_deterministic_missed", "clusters")},
                     sort_keys=True))
    for r in ranked[:12]:
        print(f"  prio {r['priority']:>9.1f}  events {r['events']:>5}  cases {r['distinct_cases']:>5}  "
              f"{r['head_token'][:24]:24} {','.join(r['signals'])[:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
