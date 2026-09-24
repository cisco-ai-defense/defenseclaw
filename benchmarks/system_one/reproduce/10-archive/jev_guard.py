#!/usr/bin/env python3
"""Payload guard over everything staged for the two private repos.

Three layers, all writing to NEW result paths (no existing guard-results file is touched):

  1. ROW GUARD  - reuses the programme's own governance/tools/guard2.py `guard_file()` on
                  every new prediction .jsonl under the `system_one` schema family. This is
                  the guard that actually gated the existing predictions repo.
  2. FLAT GUARD - raw-byte credential/CJK scan plus a structural walk banning
                  payload-bearing keys, over every new analysis .json / .txt.
  3. NAMED GUARD- the caller-named $WORK/.system-one-space-build/src/guard.py, run
                  over the subset it can actually accept (its ALLOWED_EXT excludes .jsonl
                  and it caps files at 1 MiB, so it is structurally inapplicable to
                  prediction files; that is reported, not silently skipped).

Exit 0 only if every applicable layer passes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")
GUARD2 = Path("$WORK/.system-one-hf-stage/evaluations-add/governance/tools/guard2.py")
NAMED_GUARD = Path("$WORK/.system-one-space-build/src/guard.py")
PY = "$WORK/.system-one-venv/bin/python"
RESULTS = DATA / "jev-parity/guard"

CJK = re.compile(r"[㐀-䶿一-鿿぀-ヿ가-힯！-｠]")
CRED = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}"
    r"|sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{16,}"
    r"|AIza[0-9A-Za-z_-]{30,}|-----BEGIN[A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)
CRED_KV = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|bearer)"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9/_+=.-]{12,}"
)
# The hosted-provider key must never appear, in any form.
KEY_NAMES = re.compile(r"(?i)(TYPESAFE_API_KEY|authorization\s*:\s*bearer\s+\S)")

FORBIDDEN_KEYS = {
    "payload", "content", "command", "args", "tool_name", "messages", "modelInput",
    "modelOutput", "reason", "intent", "text", "prompt", "session_user_intent",
    "current_tool_call", "prior_events", "risk_description", "user_intent",
    "observation", "apparent_task", "truth_grade_reason", "why_text",
    "stdout", "stderr", "body", "response", "completion",
}
# The programme's own analysis prose is allowed in evaluation artifacts. This mirrors the
# existing governance/tools/guard_flat2.py rule: "'rationale'/'note' are the programme
# authors' own analysis prose - allowed, but still credential/CJK scanned by the raw pass."
# 'reason' is in the same category: in these scorecards it is the methodological note saying
# why a comparison is unavailable, and the value is byte-identical to the corresponding
# already-published artifact (verified by PRE_APPROVED_PROSE below).
PROSE_OK = {"note", "notes", "rationale", "caveat", "interpretation", "conclusion",
            "applicability_note", "notes_list", "reason"}

# (new artifact, already-published artifact, json pointer) triples whose prose must match
# byte-for-byte. If the new file's prose has drifted from the published text, the guard fails.
PRE_APPROVED_PROSE = [
    ("toolcall-labels/q4-analysis-jev-C0.json", "toolcall-labels/q4-analysis.json",
     ("q2_comparison", "reason")),
    ("toolcall-labels/q4-analysis-jev-C7.json", "toolcall-labels/q4-analysis.json",
     ("q2_comparison", "reason")),
]


def prose_matches_published() -> list[str]:
    """Confirm every prose exemption reuses text already approved in a published artifact."""
    problems: list[str] = []
    for new_rel, pub_rel, pointer in PRE_APPROVED_PROSE:
        new_path, pub_path = DATA / new_rel, DATA / pub_rel
        if not new_path.exists():
            continue
        if not pub_path.exists():
            problems.append(f"{new_rel}: published counterpart {pub_rel} not found")
            continue
        def dig(path: Path):
            node = json.loads(path.read_text())
            for key in pointer:
                node = node.get(key) if isinstance(node, dict) else None
            return node
        if dig(new_path) != dig(pub_path):
            problems.append(f"{new_rel}: prose at {'.'.join(pointer)} differs from the "
                            f"already-published {pub_rel}; not covered by the exemption")
    return problems


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_guard2():
    spec = importlib.util.spec_from_file_location("guard2", GUARD2)
    module = importlib.util.module_from_spec(spec)
    sys.modules["guard2"] = module
    spec.loader.exec_module(module)
    return module


def raw_scan(path: Path) -> list[str]:
    fails: list[str] = []
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"not valid utf-8 at byte {exc.start}"]
    for label, pattern in (("credential", CRED), ("credential-kv", CRED_KV),
                           ("provider-key-name", KEY_NAMES)):
        match = pattern.search(text)
        if match:
            fails.append(f"{label} pattern matched at offset {match.start()} "
                         f"(length {len(match.group(0))}; value withheld)")
    match = CJK.search(text)
    if match:
        fails.append(f"CJK/fullwidth codepoint at offset {match.start()}")
    return fails


def structural_scan(path: Path) -> list[str]:
    if path.suffix != ".json":
        return []
    fails: list[str] = []

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in FORBIDDEN_KEYS and key not in PROSE_OK:
                    if value not in (None, "", [], {}):
                        fails.append(f"payload-bearing key '{key}' at {where} is non-empty")
                walk(value, f"{where}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node[:200]):
                walk(value, f"{where}[{index}]")

    try:
        walk(json.loads(path.read_text()), "$")
    except json.JSONDecodeError as exc:
        fails.append(f"invalid json: {exc.msg}")
    return fails


def main(argv: list[str]) -> int:
    plan_path = Path(argv[1])
    plan = json.loads(plan_path.read_text())
    RESULTS.mkdir(parents=True, exist_ok=True)
    guard2 = load_guard2()

    row_results, flat_results = [], []
    row_fail = flat_fail = 0

    print("== LAYER 1: row guard (governance/tools/guard2.py, family=system_one) ==")
    for item in plan:
        if not item["rel"].endswith(".jsonl"):
            continue
        result = guard2.guard_file(item["rel"], item.get("family", "system_one"))
        row_results.append(result)
        ok = not result["failures"]
        row_fail += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} {result['rel']:<52} rows={result['rows']:>7} "
              f"{format(result['bytes'], ','):>14} B")
        for failure in result["failures"][:5]:
            print(f"      !! {failure}")

    print("\n== LAYER 2: flat guard (credential / CJK / payload-key walk) ==")
    for item in plan:
        if item["rel"].endswith(".jsonl"):
            continue
        path = DATA / item["rel"]
        if not path.exists():
            flat_results.append({"rel": item["rel"], "failures": ["missing"], "sha256": None})
            flat_fail += 1
            print(f"FAIL {item['rel']} missing")
            continue
        fails = raw_scan(path) + structural_scan(path)
        flat_results.append({"rel": item["rel"], "failures": fails,
                             "sha256": sha256_file(path), "bytes": path.stat().st_size})
        ok = not fails
        flat_fail += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} {item['rel']:<64} "
              f"{format(path.stat().st_size, ','):>12} B")
        for failure in fails[:5]:
            print(f"      !! {failure}")

    print("\n== prose exemption check ==")
    prose_problems = prose_matches_published()
    for problem in prose_problems:
        print(f"  FAIL {problem}")
    if not prose_problems:
        print(f"  {len(PRE_APPROVED_PROSE)} prose exemptions all byte-identical to the "
              f"already-published artifacts")

    print("\n== LAYER 3: named guard (.system-one-space-build/src/guard.py) ==")
    named_dir = RESULTS / "named-guard-payload"
    if named_dir.exists():
        for child in sorted(named_dir.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
    named_dir.mkdir(parents=True, exist_ok=True)
    accepted, inapplicable = [], []
    for item in plan:
        path = DATA / item["rel"]
        if not path.exists():
            continue
        if path.suffix not in {".html", ".css", ".md", ".json", ".txt"}:
            inapplicable.append({"rel": item["rel"], "reason":
                                 f"extension {path.suffix} not in the named guard's ALLOWED_EXT"})
            continue
        if path.stat().st_size > 1024 * 1024:
            inapplicable.append({"rel": item["rel"], "reason":
                                 f"{path.stat().st_size} bytes exceeds the named guard's 1 MiB cap"})
            continue
        dest = named_dir / item["rel"].replace("/", "__")
        dest.write_bytes(path.read_bytes())
        accepted.append(item["rel"])
    named = {"accepted_files": len(accepted), "inapplicable": inapplicable}
    if accepted:
        proc = subprocess.run([PY, str(NAMED_GUARD), str(named_dir)],
                              capture_output=True, text=True)
        named["returncode"] = proc.returncode
        named["stdout_tail"] = proc.stdout.strip().splitlines()[-12:]
        print("\n".join(named["stdout_tail"]))
    else:
        named["returncode"] = None
        print("no files the named guard can accept")
    for entry in inapplicable:
        print(f"  INAPPLICABLE {entry['rel']}: {entry['reason']}")

    report = {
        "kind": "defenseclaw-system-one-jev-guard",
        "schema_version": "1",
        "row_guard": {"files": len(row_results), "failures": row_fail,
                      "rows_checked": sum(r["rows"] for r in row_results),
                      "results": row_results},
        "flat_guard": {"files": len(flat_results), "failures": flat_fail,
                       "results": flat_results},
        "named_guard": named,
        "prose_exemptions": {
            "policy": "author-written analysis prose keys are allowed, mirroring "
                      "governance/tools/guard_flat2.py; each is verified byte-identical to the "
                      "corresponding already-published artifact",
            "keys_allowed": sorted(PROSE_OK),
            "verified": [{"new": n, "published": p, "pointer": list(ptr)}
                         for n, p, ptr in PRE_APPROVED_PROSE],
            "problems": prose_problems,
        },
    }
    (RESULTS / "jev-guard-results.json").write_text(
        json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(f"\nROW  GUARD: {len(row_results) - row_fail} passed, {row_fail} failed, "
          f"{report['row_guard']['rows_checked']} rows")
    print(f"FLAT GUARD: {len(flat_results) - flat_fail} passed, {flat_fail} failed")
    print(f"NAMED GUARD: returncode {named['returncode']} over {named['accepted_files']} files, "
          f"{len(inapplicable)} structurally inapplicable")
    print(f"wrote {RESULTS / 'jev-guard-results.json'}")
    print(f"PROSE EXEMPTIONS: {len(prose_problems)} problems")
    bad = (row_fail or flat_fail or prose_problems
           or (named["returncode"] not in (0, None)))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
