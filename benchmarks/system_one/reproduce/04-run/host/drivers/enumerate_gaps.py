#!/usr/bin/env python3
"""Enumerate every (stage, corpus, context, instruction, question) arm that OpenJev or
DiffusionGemma completed and hosted Jev has not, so the parity gap set is derived from the
metas on disk rather than from a hand-written list.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

DATA = Path("$WORK/.system-one-data/outputs")

MODEL_FAMILY = {
    "openjev": "openjev",
    "diffusiongemma": "diffusiongemma",
    "jev-1.13.0": "jev",
}

# Stages with no hosted equivalent / mock harnesses.
SKIP_STAGES = {"fault-injection", "cache", "gpu-host-evidence", "deterministic-real", "repeat"}


def family(model: str | None) -> str | None:
    if not model:
        return None
    if model in MODEL_FAMILY:
        return MODEL_FAMILY[model]
    if model.startswith("diffusiongemma"):
        return "diffusiongemma"
    if model.startswith("jev"):
        return "jev"
    if model.startswith("openjev"):
        return "openjev"
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    arms: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    corpora: dict[str, set[str]] = defaultdict(set)
    skipped_incomplete: list[str] = []

    for meta_path in sorted(DATA.glob("*/*.jsonl.meta.json")) + sorted(DATA.glob("*/*/*.jsonl.meta.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        fam = family(meta.get("model"))
        if fam is None:
            continue
        stage = meta_path.relative_to(DATA).parts[0]
        if stage in SKIP_STAGES:
            continue
        ctx = meta.get("contexts")
        ins = meta.get("instructions")
        qst = meta.get("questions")
        if not (ctx and ins and qst):
            continue
        if len(ctx) != 1 or len(ins) != 1 or len(qst) != 1:
            # multi-variant screening sweeps are not single arms
            continue
        pred = Path(str(meta_path).removesuffix(".meta.json"))
        if meta.get("complete") is not True:
            skipped_incomplete.append(str(pred.relative_to(DATA)))
            continue
        # Normalised arm key. Three things are deliberately NOT part of the key:
        #  * instruction_format - DiffusionGemma requires "string" where Jev/OpenJev use
        #    "structured"; that is a per-model prompt-encoding requirement, not a different arm.
        #  * cases_sha256 - OpenJev sharded some large runs (s2 cases.h0/h1, s3 cases.shard*),
        #    so a sharded run of the same corpus would otherwise look like a different corpus.
        #  * shard/half suffixes in the filename.
        # Without this normalisation the same logical arm appears as a gap once per encoding and
        # once per shard, which is how the coverage diff gets misread.
        key = (stage, ctx[0], ins[0], qst[0])
        arms[key][fam].append({
            "path": str(pred.relative_to(DATA)),
            "requests": meta.get("requests"),
            "cases": meta.get("cases"),
            "cases_sha256": meta.get("cases_sha256") or "",
            "instruction_format": meta.get("instruction_format"),
            "tokens_per_request": round(meta["actual_input_tokens"] / meta["requests"], 1)
            if meta.get("actual_input_tokens") and meta.get("requests") else None,
        })
        corpora[meta.get("cases_sha256")].add(stage)

    # map cases_sha256 -> an actual cases file on disk
    cases_by_sha: dict[str, str] = {}
    for candidate in sorted(DATA.glob("*/cases*.jsonl")) + sorted(DATA.glob("*/*/cases*.jsonl")):
        try:
            cases_by_sha.setdefault(sha256_file(candidate), str(candidate))
        except Exception:
            continue

    gaps = []
    have = []
    for key in sorted(arms, key=lambda k: (k[0], k[4], k[2], k[3])):
        stage, ctx, ins, qst = key
        fams = arms[key]
        row = {
            "stage": stage,
            "grid": f"{ctx}/{ins}/{qst}",
            "context": ctx, "instruction": ins, "question": qst,
            "instruction_formats_seen": sorted({a.get("instruction_format") or "unset"
                                                for arms_list in fams.values()
                                                for a in arms_list}),
            "corpora_seen": sorted({a["cases_sha256"][:12] for arms_list in fams.values()
                                    for a in arms_list}),
            "openjev": [a["path"] for a in fams.get("openjev", [])],
            "diffusiongemma": [a["path"] for a in fams.get("diffusiongemma", [])],
            "jev": [a["path"] for a in fams.get("jev", [])],
            "requests": (fams.get("openjev") or fams.get("diffusiongemma") or fams.get("jev"))[0]["requests"],
            "openjev_tok_per_req": fams["openjev"][0]["tokens_per_request"] if fams.get("openjev") else None,
        }
        if row["jev"]:
            have.append(row)
        elif row["openjev"] or row["diffusiongemma"]:
            gaps.append(row)

    print("=" * 108)
    print("JEV PARITY GAPS - arms OpenJev or DiffusionGemma completed that hosted Jev does not have")
    print("=" * 108)
    print("Arm identity is normalised over instruction_format and over shard/half corpus")
    print("splits, because neither makes a different arm. See the source comment for why.")
    print()
    print(f"{'stage':<18}{'grid':<12}{'requests':>9}  {'oj tok/req':>10}  "
          f"{'has OJ':>6} {'has DG':>6}  formats seen")
    total_req = 0
    for row in gaps:
        total_req += row["requests"] or 0
        print(f"{row['stage']:<18}{row['grid']:<12}"
              f"{str(row['requests']):>9}  {str(row['openjev_tok_per_req']):>10}  "
              f"{('yes' if row['openjev'] else '-'):>6} {('yes' if row['diffusiongemma'] else '-'):>6}  "
              f"{','.join(row['instruction_formats_seen'])}")
    print(f"\n{len(gaps)} TRUE gap arms, {total_req} requests total")
    if not gaps:
        print("Jev has an arm for every (stage, context, instruction, question) combination that")
        print("OpenJev or DiffusionGemma completed. Parity is closed.")
    est_042 = total_req * 900 * 0.042 / 1e6
    est_049 = total_req * 900 * 0.04906 / 1e6
    print(f"rough estimate at 900 tok/req: ${est_042:.2f} (at $0.042/M) / ${est_049:.2f} (at $0.04906/M)")

    print("\n" + "=" * 108)
    print("ALREADY AT PARITY (Jev arm exists)")
    print("=" * 108)
    for row in have:
        print(f"{row['stage']:<18}{row['grid']:<12}{str(row['requests']):>9}  "
              f"jev={row['jev']} oj={'yes' if row['openjev'] else '-'} "
              f"dg={'yes' if row['diffusiongemma'] else '-'}")

    if skipped_incomplete:
        print("\nskipped (meta not complete): " + ", ".join(skipped_incomplete))

    out = DATA / "jev-parity/parity-gap-enumeration.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "kind": "defenseclaw-system-one-parity-gap-enumeration",
        "schema_version": "1",
        "skipped_stages": sorted(SKIP_STAGES),
        "skipped_incomplete": skipped_incomplete,
        "normalisation": {
            "keyed_on": ["stage", "context", "instruction", "question"],
            "deliberately_ignored": {
                "instruction_format": ("DiffusionGemma requires string-format instructions where "
                                       "Jev and OpenJev use structured; a per-model prompt encoding "
                                       "is not a different arm"),
                "cases_sha256": ("OpenJev sharded some large runs (s2 cases.h0/h1, "
                                 "s3 cases.shard0/1/2a/2b/2c); a sharded run of the same corpus is "
                                 "not a different arm"),
            },
        },
        "gaps": gaps,
        "at_parity": have,
        "gap_request_total": total_req,
    }, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
