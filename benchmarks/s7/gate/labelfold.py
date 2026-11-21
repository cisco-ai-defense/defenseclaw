#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (the checked-in benchmark tooling has always been long-line)
"""Label overlays folded into a label set, with a check that a set holds them (rel-1-0-10 GAP-0455, GAP-0122, GAP-0123, GAP-0020).

A label set is a jsonl file of {"id", "source_truth", ...} rows that `s7gate.py score --labels` applies over the corpus files (benign / malicious / excluded).
Hand reviews are kept as small overlay files under benchmarks/s7/gate/labels/ (one per gap, rows by case id with the reviewer's reason) so a review does not live
only on one box. This module never reads or prints case text: it works on ids, verdicts and reasons.

  fold-labels  --base SET.jsonl --overlay F [--overlay F ...] --out DIR --version vX [--name labels-v3]
      writes DIR/<name>.jsonl and DIR/<name>.manifest.json: the base rows, with each overlay row replacing the base row of the same id (appended when the id is new).
      Refuses (exit 4) a malformed row, an unknown verdict, two overlays that disagree on one id, and an --out that already holds <name>.jsonl (a label set is never
      rewritten in place: switching one mid-A/B changes every compare, so a new version is a new file).
  check-labels --labels SET.jsonl --overlay F [--overlay F ...]
      exit 0 when every overlay row is in the set with the same verdict; exit 1 and the ids that are missing or differ otherwise.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import sys

VERDICTS = ("benign", "malicious", "excluded", "sensitive")
OVERLAY_RULE = "H-HAND-OVERLAY"


class LabelError(Exception):
    """A label or overlay file the tool refuses to use; the message names the file and line, never a value."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def read_rows(path, what="label", need_truth=True):
    """Rows of a jsonl label file. Every row must be an object with a string id; source_truth must be a known verdict, and may only be absent in a label
    set (need_truth=False): the dev label sets hold disposition-only rows (a rule that changes expected_disposition and leaves the verdict alone)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        raise LabelError(f"{what} file {path}: cannot read: {e.strerror or e}") from e
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        line = data.count(b"\n", 0, e.start) + 1
        raise LabelError(f"{what} file {path} line {line}: not UTF-8") from e
    rows = []
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_no_duplicate_keys)
        except ValueError as e:
            raise LabelError(
                f"{what} file {path} line {n}: not JSON or a duplicated key ({e.__class__.__name__})"
            ) from e
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            raise LabelError(f"{what} file {path} line {n}: a row needs a string id")
        if row.get("source_truth") not in VERDICTS and (need_truth or "source_truth" in row):
            raise LabelError(f"{what} file {path} line {n}: source_truth must be one of {', '.join(VERDICTS)}")
        rows.append(row)
    if not rows:
        # an empty or truncated file must not read as "nothing to fold" or "every row present" (GAP-1583)
        raise LabelError(f"{what} file {path}: no rows")
    return rows


def _no_duplicate_keys(pairs):
    """json object hook: a key given twice in one row is an error, not a silent last-value-wins (GAP-1583)."""
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicated key {k!r}")
        d[k] = v
    return d


def load_overlays(paths):
    """id -> (row, overlay file) over all overlay files. The same id with two different verdicts is an error."""
    if not paths:
        raise LabelError("no --overlay given")
    merged = {}
    for p in paths:
        for row in read_rows(p, "overlay"):
            old = merged.get(row["id"])
            if old and old[0]["source_truth"] != row["source_truth"]:
                raise LabelError(f"overlay files {old[1]} and {p} disagree on the verdict of case {row['id']}")
            merged[row["id"]] = (row, p)
    return merged


def fold(base_rows, overlay):
    """(rows, stats): base rows in order, an overlay row replacing the base row of its id, new ids appended in id order."""
    out, seen = [], set()
    changed = same = 0
    for row in base_rows:
        hit = overlay.get(row["id"])
        if hit is None:
            out.append(row)
            continue
        new, src = hit
        if row.get("source_truth") == new["source_truth"]:
            same += 1
        else:
            changed += 1
        merged = dict(row)
        merged.update({k: v for k, v in new.items() if k in ("corpus", "source_truth", "why", "expected_disposition")})
        merged.update(rule=OVERLAY_RULE, src="hand", hand_file=os.path.basename(src))
        out.append(merged)
        seen.add(row["id"])
    added = 0
    for cid in sorted(set(overlay) - seen):
        new, src = overlay[cid]
        row = {k: v for k, v in new.items() if k in ("id", "corpus", "source_truth", "why", "expected_disposition")}
        row.update(rule=OVERLAY_RULE, src="hand", hand_file=os.path.basename(src))
        out.append(row)
        added += 1
    return out, dict(changed=changed, same=same, added=added)


def write_set(out_dir, name, version, rows, base_path, overlay_paths, stats):
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        raise LabelError(f"--out {out_dir}: cannot create: {e.strerror or e}") from e
    lp, mp = os.path.join(out_dir, name + ".jsonl"), os.path.join(out_dir, name + ".manifest.json")
    if os.path.exists(lp) or os.path.exists(mp):
        raise LabelError(
            f"{lp} or its manifest already exists: a label set is never rewritten in place; give the new set another --name"
        )
    body = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in rows).encode()
    manifest = {
        "version": version,
        "labels_sha256": hashlib.sha256(body).hexdigest(),
        "rows": len(rows),
        "rows_by_truth": dict(collections.Counter(r.get("source_truth", "-") for r in rows)),
        "base": {"file": os.path.basename(base_path), "sha256": sha256_file(base_path)},
        "overlays": [{"file": os.path.basename(p), "sha256": sha256_file(p)} for p in overlay_paths],
        "fold": stats,
    }
    # both files are written in full first; the manifest is put in place before the label set, so a failure leaves at
    # most a manifest with no set (which resolve_labels and write_set refuse), never a set without its manifest
    pairs = ((mp, (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()), (lp, body))
    try:
        for path, data in pairs:
            with open(path + ".tmp", "wb") as f:
                f.write(data)
        for path, _ in pairs:
            os.replace(path + ".tmp", path)
    except OSError as e:
        for path, _ in pairs:
            if os.path.exists(path + ".tmp"):
                os.remove(path + ".tmp")
        raise LabelError(f"--out {out_dir}: cannot write the label set: {e.strerror or e}") from e
    return manifest


def check(label_rows, overlay):
    """[(id, state)] for every overlay row the label set lacks (missing) or holds with another verdict (differs)."""
    have = {r["id"]: r["source_truth"] for r in label_rows if "source_truth" in r}
    bad = []
    for cid, (row, _src) in sorted(overlay.items()):
        if cid not in have:
            bad.append((cid, "missing"))
        elif have[cid] != row["source_truth"]:
            bad.append((cid, f"differs: set {have[cid]}, overlay {row['source_truth']}"))
    return bad


def cmd_fold(a):
    try:
        overlay = load_overlays(a.overlay)
        rows, stats = fold(read_rows(a.base, "base label", need_truth=False), overlay)
        m = write_set(a.out, a.name, a.version, rows, a.base, a.overlay, stats)
    except LabelError as e:
        print(f"s7gate: fold-labels: {e}", file=sys.stderr)
        sys.exit(4)
    print(
        f"fold-labels: {a.name} {a.version}: {m['rows']} rows (changed {stats['changed']}, already the same {stats['same']}, added {stats['added']}) sha256 {m['labels_sha256'][:16]}"
    )


def cmd_check(a):
    try:
        bad = check(read_rows(a.labels, "label", need_truth=False), load_overlays(a.overlay))
    except LabelError as e:
        print(f"s7gate: check-labels: {e}", file=sys.stderr)
        sys.exit(4)
    for cid, state in bad:
        print(f"{cid}: {state}")
    print(f"check-labels: {'FAIL' if bad else 'ok'}: {len(bad)} overlay rows not in {os.path.basename(a.labels)}")
    sys.exit(1 if bad else 0)


def add_parsers(sub):
    pf = sub.add_parser("fold-labels")
    pf.add_argument("--base", required=True)
    pf.add_argument("--overlay", action="append", default=[])
    pf.add_argument("--out", required=True)
    pf.add_argument("--version", required=True)
    pf.add_argument("--name", default="labels-v3")
    pc = sub.add_parser("check-labels")
    pc.add_argument("--labels", required=True)
    pc.add_argument("--overlay", action="append", default=[])
