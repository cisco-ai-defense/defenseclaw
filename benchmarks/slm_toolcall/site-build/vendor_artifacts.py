#!/usr/bin/env python3
"""Vendor a scoring artifact into the public repository, dropping out-of-scope blocks.

Some scoring artifacts cover both programmes: the same run that scored the cohort also scored a
System One board arm, and its output carries both. Those board results belong on the System One
Space and may not be published here, so an artifact that mixes them cannot be vendored as it is.

This script copies an artifact and removes named top-level blocks and named keys, then records
exactly what was removed, the parent file's sha256, and a scope scan of the result. The filtering
is a script rather than a hand edit so the next reader can re-run it and get the same bytes.

Nothing in-scope is rewritten: every value that survives is byte-identical to the parent's.

Usage:
  vendor_artifacts.py --check     verify the vendored copies match what this script would write
  vendor_artifacts.py             write them
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.path.abspath(os.path.join(HERE, "..", "artifacts"))
SRC = os.environ.get("SLM_ARTIFACT_SRC", "/home/ubuntu/s3-escalation-2026-09-24/out")

# the name tokens that may not reach the public repository through a vendored artifact
FORBIDDEN = ("open-jev", "openjev", "open jev", "jevify", "jev 1.13", "zefancai",
             "kev-9b", "decider-2b", "bespoke-nimble", "secjudge", "diffusiongemma")

# Copied verbatim: their only forbidden-token hit is the artifact's own scope_rule string, which
# states which families are excluded. A rule naming what it excludes is not a publication of it.
VERBATIM = ["s3-stats.json"]

# Filtered: these carry a System One board arm's own scores alongside the cohort's.
FILTERED = {
    "cohort-length-controlled-ranking.json": {
        "out": "cohort-length-controlled-ranking.json",
        "drop_top_level": [],
        "drop_keys_under": {},
        "scrub_strings_at": ["provenance.scope_rule"],
        "why": "the artifact's own scope_rule names the excluded families one by one. The rule is "
               "kept as a statement; the family names are not reproduced here.",
    },
    "cohort-scores.json": {
        "out": "cohort-scores.json",
        "drop_top_level": [],
        "drop_keys_under": {"arms": ["open-jev-qwen-2b-merged"]},
        "anonymise_keys_under": {"parity_gate": "reference"},
        "drop_keys_in_each": {"parity_gate": ["published_block_only_f1",
                                              "shipped_block_only_f1_recomputed",
                                              "published_confusion",
                                              "shipped_block_only_confusion_recomputed",
                                              "auc_P_block_published",
                                              "auc_P_block_recomputed_defA"]},
        "why": "this stage-0 scorecard file covered one Jev-family arm and named three System One "
               "board references with their scores. The arm is removed; the equivalence gate's "
               "references are reduced to the properties of the check, which is what this Space "
               "publishes, with their identities and scores left to the System One Space.",
    },
    "final-comparisons.json": {
        "out": "final-comparisons.json",
        "drop_top_level": [],
        "drop_keys_under": {
            "headline_comparisons": [
                "anchor_shipped_minus_block_everything",
                "deberta_ORACLE_ceiling_as_fraction_of_openjev_shipped",
                "deberta_ORACLE_reaches_openjev_shipped",
                "deberta_shipped_as_fraction_of_openjev",
                "deberta_shipped_beats_anchor",
                "deberta_shipped_minus_anchor_shipped",
                "openjev_published_rounded",
                "openjev_shipped_minus_deberta_ORACLE_ceiling",
                "openjev_shipped_minus_deberta_shipped",
                "openjev_shipped_recomputed"],
            "length_controlled_auc": [
                "anchor P(block) defA==defB",
                "anchor P(block)-P(confirm) defA [FLAGGED VARIABLE]",
                "anchor P(block)-P(confirm) defB [FLAGGED VARIABLE]",
                "anchor risk = 1-P(allow) defA==defB"],
        },
        "why": "every comparison against a Jev-family arm, and every ranking row belonging to one, "
               "is out of scope on this Space. The trivial baselines, the chance band and the "
               "in-scope rows are kept byte-identical.",
    },
    "s3-scores.json": {
        "out": "s3-scores-in-scope.json",
        "drop_top_level": ["task2_bespoke_nimble_9b_s3"],
        "drop_keys_under": {"comparison": ["bespoke-nimble-9b"]},
        "scrub_strings_at": ["provenance.scope_rule"],
        "why": "the run that scored the six cohort arms on the held-out corpus also scored one "
               "System One board arm. That arm's results belong on the System One Space, so its "
               "block and its comparison entry are removed here.",
    },
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scope_hits(obj) -> list[str]:
    """Every path at which a forbidden token survives, key or value."""
    out: list[str] = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if any(t in str(k).lower() for t in FORBIDDEN):
                    out.append(f"{path}.{k} [key]")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        else:
            s = str(node).lower()
            for t in FORBIDDEN:
                if t in s:
                    out.append(f"{path} [value: {t}]")
                    break

    walk(obj)
    return out


def dig_set(doc, dotted: str, value) -> bool:
    cur = doc
    parts = dotted.split(".")
    for p in parts[:-1]:
        if not isinstance(cur, dict) or p not in cur:
            return False
        cur = cur[p]
    if isinstance(cur, dict) and parts[-1] in cur:
        cur[parts[-1]] = value
        return True
    return False


def build_filtered(name: str, spec: dict) -> tuple[str, bytes, dict]:
    src = os.path.join(SRC, name)
    with open(src, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    # The manifest records WHAT SHAPE was removed and how much, never the names, because a
    # removal note that names an out-of-scope arm republishes it.
    removed = []
    for top in spec["drop_top_level"]:
        if top in doc:
            doc.pop(top)
            removed.append(f"one top-level block covering an out-of-scope arm")
    for parent, keys in spec.get("drop_keys_under", {}).items():
        n = 0
        for k in keys:
            if isinstance(doc.get(parent), dict) and k in doc[parent]:
                doc[parent].pop(k)
                n += 1
        if n:
            removed.append(f"{n} key(s) under {parent!r} naming or quoting an out-of-scope arm")
    for parent, prefix in spec.get("anonymise_keys_under", {}).items():
        if isinstance(doc.get(parent), dict):
            items = sorted(doc[parent].items())
            doc[parent] = {f"{prefix}_{i + 1}": v for i, (_k, v) in enumerate(items)}
            removed.append(f"{len(items)} key(s) under {parent!r} replaced with "
                           f"{prefix}_N, so the references are counted and not identified")
    for parent, keys in spec.get("drop_keys_in_each", {}).items():
        if isinstance(doc.get(parent), dict):
            n = 0
            for _k, v in doc[parent].items():
                if isinstance(v, dict):
                    for kk in keys:
                        if kk in v:
                            v.pop(kk)
                            n += 1
            if n:
                removed.append(f"{n} score field(s) inside {parent!r}, so what survives is "
                               f"whether the check passed and by how little")
    for dotted in spec.get("scrub_strings_at", []):
        if dig_set(doc, dotted,
                   "recorded in the parent artifact; the families it names are out of scope on "
                   "this Space and the string is replaced here rather than reproduced"):
            removed.append(f"{dotted} [string replaced]")
    note = {
        "vendored_by": "benchmarks/slm_toolcall/site-build/vendor_artifacts.py",
        "parent_file": name,
        "parent_sha256": sha256_file(src),
        "blocks_removed": removed,
        "why": spec["why"],
        "every_surviving_value_is_byte_identical_to_the_parent": True,
    }
    doc["_vendoring"] = note
    hits = scope_hits(doc)
    body = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()
    return spec["out"], body, {"hits": hits, "note": note}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    changed, problems = [], []

    for name in VERBATIM:
        src = os.path.join(SRC, name)
        if not os.path.exists(src):
            print(f"note: {name} not at {SRC}; the vendored copy is left as it is")
            continue
        body = open(src, "rb").read()
        hits = scope_hits(json.loads(body))
        allowed = [h for h in hits if h.endswith("scope_rule [value: open-jev]")
                   or "scope_rule" in h]
        if [h for h in hits if h not in allowed]:
            problems.append(f"{name}: forbidden tokens outside the scope_rule string: "
                            f"{[h for h in hits if h not in allowed]}")
            continue
        print(f"{name}: verbatim, {len(hits)} scope hit(s), all inside the artifact's own "
              f"scope_rule statement")
        dst = os.path.join(ARTIFACTS, name)
        if not os.path.exists(dst) or open(dst, "rb").read() != body:
            changed.append(dst)
            if not args.check:
                open(dst, "wb").write(body)

    for name, spec in FILTERED.items():
        src = os.path.join(SRC, name)
        if not os.path.exists(src):
            print(f"note: {name} not at {SRC}; the vendored copy is left as it is")
            continue
        out, body, info = build_filtered(name, spec)
        if info["hits"]:
            problems.append(f"{name}: {len(info['hits'])} forbidden token(s) survive the filter: "
                            f"{info['hits'][:5]}")
            continue
        print(f"{name} -> {out}: removed {info['note']['blocks_removed']}, 0 scope hits remain")
        dst = os.path.join(ARTIFACTS, out)
        if not os.path.exists(dst) or open(dst, "rb").read() != body:
            changed.append(dst)
            if not args.check:
                open(dst, "wb").write(body)

    if problems:
        print("\nABORT: an artifact could not be vendored within scope:")
        for p in problems:
            print("  " + p)
        return 1
    verb = "would write" if args.check else "wrote"
    print(f"\n{verb} {len(changed)} file(s)" if changed else "\nnothing to do; copies are current")
    for c in changed:
        print("  " + os.path.relpath(c, os.path.dirname(ARTIFACTS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
