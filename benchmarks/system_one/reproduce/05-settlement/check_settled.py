"""Settled-file discipline, applied independently of the other agent's in-flight scorecards.

A stage arm is quotable only when its meta records complete: true AND the on-disk sha256 equals
meta.prediction_sha256 (or the merge manifest's merged_sha256 / a pinned published digest).
Copied from build_parity.is_settled so the rule is identical.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")

ATTESTED = {
    str(DATA / "s3/openjev-full.jsonl"): "cbe2db0fd78ae35e8c9fd7f0b14bdfa5248553bd2ea5702ad3c763e004dd40cd",
}

ARMS = {
    "s2": {
        "jev": [DATA / "s2/jev-C7.jsonl"],
        "openjev": [DATA / "s2/openjev-final.jsonl"],
        "diffusiongemma": [DATA / "s2/diffgemma-q2.jsonl"],
        "gemma4": [DATA / "s2/gemma4-c7.jsonl"],
    },
    "s3": {
        "jev": [DATA / "s3/jev-C7.jsonl"],
        "openjev": [DATA / "s3/openjev-full.jsonl"],
        "diffusiongemma": [DATA / "s3/diffgemma-q2.jsonl"],
        "gemma4": [DATA / "s3/gemma4-c7.jsonl"],
    },
    "intent-real": {
        "jev-C0": [DATA / "intent-real/jev-C0.jsonl"],
        "jev-C7": [DATA / "intent-real/jev-C7.jsonl"],
        "openjev-C0": [DATA / "intent-real/openjev-C0.jsonl"],
        "openjev-C7": [DATA / "intent-real/openjev-C7.jsonl"],
        "diffgemma-C0": [DATA / "intent-real/diffgemma-C0.jsonl"],
        "diffgemma-C7": [DATA / "intent-real/diffgemma-C7.jsonl"],
        "gemma4-C0": [DATA / "intent-real/gemma4-C0.jsonl"],
        "gemma4-C7": [DATA / "intent-real/gemma4-C7.jsonl"],
    },
    "toolcall-labels": {
        "jev-q4-C7": [DATA / "toolcall-labels/jev-q4-C7.jsonl"],
        "openjev-q4-C7": [DATA / "toolcall-labels/openjev-q4-C7.jsonl"],
        "diffgemma-q4-C7": [DATA / "toolcall-labels/diffgemma-q4-C7.jsonl"],
    },
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_settled(path: Path) -> tuple[bool, str, str | None]:
    if not path.exists():
        return False, "file does not exist", None
    meta_path = Path(str(path) + ".meta.json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        if meta.get("complete") is not True:
            return False, "meta complete is not true (in flight or failed)", None
        digest = sha256_file(path)
        if digest != meta.get("prediction_sha256"):
            return False, "on-disk sha256 != meta.prediction_sha256", digest
        return True, "meta", digest
    merge_path = Path(str(path).removesuffix(".jsonl") + ".merge.json")
    if merge_path.exists():
        merge = json.loads(merge_path.read_text())
        if not merge.get("verification", {}).get("coverage_complete"):
            return False, "merge manifest not coverage_complete", None
        digest = sha256_file(path)
        if digest != merge.get("merged_sha256"):
            return False, "on-disk sha256 != merge manifest merged_sha256", digest
        return True, "merge-manifest", digest
    if str(path) in ATTESTED:
        digest = sha256_file(path)
        if digest == ATTESTED[str(path)]:
            return True, "published-scorecard-sha256", digest
        return False, "on-disk sha256 != pinned published digest", digest
    return False, "no .meta.json and no .merge.json attestation", None


out: dict = {}
for stage, arms in ARMS.items():
    out[stage] = {}
    for arm, paths in arms.items():
        entries = []
        for p in paths:
            ok, why, digest = is_settled(p)
            entries.append({"path": str(p), "settled": ok, "attestation": why, "sha256": digest})
        out[stage][arm] = {"settled": all(e["settled"] for e in entries), "files": entries}

Path("$WORK/.system-one-data/outputs/secjudge/settled-inputs.json").write_text(
    json.dumps(out, indent=2, sort_keys=True) + "\n"
)
for stage, arms in out.items():
    for arm, v in arms.items():
        flag = "SETTLED " if v["settled"] else "NOT-SETTLED"
        why = "" if v["settled"] else " <- " + "; ".join(e["attestation"] for e in v["files"] if not e["settled"])
        print(f"{flag}  {stage:<16} {arm}{why}")
