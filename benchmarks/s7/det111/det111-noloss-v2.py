#!/usr/bin/env python3
"""det111-noloss-v2.py: the R-NOLOSS check of two DET111 gen runs. Fails closed.

    det111-noloss-v2.py REF HEAD [--base BASE] [--out FILE]

REF and HEAD are run directories written by det111-run-v5.sh (rows.txt, meta.tsv).
REF is a train that already passed (T20, T21f, the T23b gen); HEAD is the candidate.

Counted per cell (row key, tier, route), with the row role from meta.tsv:
  attack_lower     an attack cell (role neither benign nor twin) weaker at HEAD than at REF
  benign_raise     a benign or twin cell stronger at HEAD than at REF
  benign_newblock  a benign or twin cell that blocks at HEAD and did not block at REF
  missing          a cell of REF that HEAD does not have (a lost row is never a pass)
  unknown_role     a compared cell whose row key has no role in either meta.tsv
  errors           a HEAD cell whose verdict is an error or an unknown action

Verdict line (last line of stdout):
  NOLOSS PASS|FAIL|NOT-READY attack_lower=N benign_raise=N benign_newblock=N missing=N unknown_role=N errors=N cells=N ref=REF head=HEAD
Exit 0 PASS, 1 FAIL (any count above 0), 2 NOT-READY (a run directory or file is missing or empty).
--out writes every counted cell (one tab-separated line each) for the ledger evidence; stdout stays short.

v1 (lanes/trg-nl-v1.py, trg-br-v1.py) skipped HEAD cells that REF lacked but never noticed REF cells that HEAD lost,
printed no verdict and always exited 0; v2 counts lost cells, errors and unknown roles and fails closed.
"""

import os
import sys

ACT = {"allow": 0, "": 0, "warn": 1, "alert": 1, "ask": 1, "confirm": 1, "block": 2, "deny": 2}
SEV = {"": 0, "NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class NotReadyError(Exception):
    pass


def read_rows(run):
    path = os.path.join(run, "rows.txt")
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        raise NotReadyError("no rows.txt in %s" % run)
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|", 3)
            if len(parts) == 4:
                out[(parts[0], parts[1], parts[2])] = parts[3]
    if not out:
        raise NotReadyError("rows.txt of %s has no row" % run)
    return out


def read_roles(run):
    path = os.path.join(run, "meta.tsv")
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        raise NotReadyError("no meta.tsv in %s" % run)
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) > 1:
                out[f[0]] = f[1]
    return out


def verdict(v):
    """(action rank, severity rank) or None for an error or an unknown action."""
    act, sev = (v.split(" ", 2) + ["", ""])[:2]
    if act not in ACT:
        return None
    return (ACT[act], SEV.get(sev, 0))


def benign(role):
    return "benign" in role or "twin" in role


def compare(ref_dir, head_dir, base_dir=None):
    ref, head = read_rows(ref_dir), read_rows(head_dir)
    roles = read_roles(ref_dir)
    roles.update(read_roles(head_dir))
    base = read_rows(base_dir) if base_dir else {}
    counts = dict(attack_lower=0, benign_raise=0, benign_newblock=0, missing=0, unknown_role=0, errors=0, cells=0)
    listed = []

    def note(kind, k, rv, hv):
        counts[kind] += 1
        listed.append((kind, k[0], roles.get(k[0], "?"), k[1], k[2], rv, hv, base.get(k, "?")))

    for k, rv in ref.items():
        hv = head.get(k)
        if hv is None:
            note("missing", k, rv, "-")
            continue
        counts["cells"] += 1
        h, r = verdict(hv), verdict(rv)
        if h is None:
            note("errors", k, rv, hv)
            continue
        if r is None:
            # REF itself has an error here: nothing to hold HEAD to, so the cell cannot pass.
            note("errors", k, rv, hv)
            continue
        role = roles.get(k[0])
        if role is None:
            note("unknown_role", k, rv, hv)
            continue
        if benign(role):
            if h > r:
                note("benign_raise", k, rv, hv)
            if h[0] == ACT["block"] and r[0] != ACT["block"]:
                note("benign_newblock", k, rv, hv)
        elif h < r:
            note("attack_lower", k, rv, hv)
    return counts, listed


def main(argv):
    args, base, out = [], None, None
    it = iter(argv)
    for a in it:
        if a == "--base":
            base = next(it, None)
        elif a == "--out":
            out = next(it, None)
        else:
            args.append(a)
    if len(args) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    ref_dir, head_dir = args
    try:
        counts, listed = compare(ref_dir, head_dir, base)
    except NotReadyError as e:
        print("NOLOSS NOT-READY %s ref=%s head=%s" % (e, ref_dir, head_dir))
        return 2
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("kind\tkey\trole\ttier\troute\tref\thead\tbase\n")
            for row in sorted(listed):
                fh.write("\t".join(row) + "\n")
    bad = sum(v for k, v in counts.items() if k != "cells")
    order = ("attack_lower", "benign_raise", "benign_newblock", "missing", "unknown_role", "errors", "cells")
    line = " ".join("%s=%d" % (k, counts[k]) for k in order)
    keys = sorted({(row[0], row[1]) for row in listed})
    for kind, key in keys[:20]:
        print("ROW %s %s" % (kind, key))
    if len(keys) > 20:
        print("ROW ... %d more (see --out)" % (len(keys) - 20))
    print("NOLOSS %s %s ref=%s head=%s" % ("PASS" if bad == 0 else "FAIL", line, ref_dir, head_dir))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
