#!/usr/bin/env python3
"""Task 1: repeatability across three deliberate repeats of the same corpus."""
import json
import sys
from collections import Counter
from pathlib import Path

OUT = Path("$WORK/.system-one-data/outputs/repeat")
BACKENDS = ["openjev", "diffgemma", "jev"]


def load(path):
    """Return (ok_map, err_count, total_rows). ok_map: (case_id, event_index) -> action."""
    ok, errs, total, dupes = {}, 0, 0, 0
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            total += 1
            if r.get("error_code"):
                errs += 1
                continue
            key = (str(r.get("case_id", "")), int(r.get("event_index", -1)))
            if key in ok:
                dupes += 1
            ok[key] = str(r.get("action", ""))
    return ok, errs, total, dupes


def analyze(backend):
    paths = [OUT / f"{backend}-r{n}.jsonl" for n in (1, 2, 3)]
    missing = [p.name for p in paths if not p.exists()]
    if missing:
        return {"backend": backend, "status": "MISSING", "missing": missing}

    runs, errs, totals, dupes = [], [], [], []
    for p in paths:
        o, e, t, d = load(p)
        runs.append(o)
        errs.append(e)
        totals.append(t)
        dupes.append(d)

    keysets = [set(r) for r in runs]
    common = keysets[0] & keysets[1] & keysets[2]
    union = keysets[0] | keysets[1] | keysets[2]

    flips = []
    pattern = Counter()
    nonallow_total = 0
    nonallow_flips = 0
    for k in sorted(common):
        a = tuple(r[k] for r in runs)
        distinct = set(a)
        is_nonallow = distinct != {"allow"}
        if is_nonallow:
            nonallow_total += 1
        if len(distinct) > 1:
            flips.append((k, a))
            pattern["->".join(a)] += 1
            if is_nonallow:
                nonallow_flips += 1

    # alternative non-allow restriction: r1 decision was not allow
    r1_nonallow = [k for k in common if runs[0][k] != "allow"]
    r1_nonallow_flips = sum(1 for k in r1_nonallow if len({r[k] for r in runs}) > 1)

    # majority (>=2 of 3) non-allow restriction -- avoids the tautology of
    # "any run produced non-allow", which every allow<->non-allow flip satisfies
    maj_nonallow = [
        k for k in common if sum(1 for r in runs if r[k] != "allow") >= 2
    ]
    maj_nonallow_flips = sum(1 for k in maj_nonallow if len({r[k] for r in runs}) > 1)

    # unanimous-non-allow: all three runs non-allow (flips only among confirm/block)
    unan_nonallow = [k for k in common if all(r[k] != "allow" for r in runs)]
    unan_nonallow_flips = sum(1 for k in unan_nonallow if len({r[k] for r in runs}) > 1)

    return {
        "backend": backend,
        "status": "OK",
        "rows_per_run": totals,
        "errors_per_run": errs,
        "dupe_keys_per_run": dupes,
        "identities_union": len(union),
        "identities_common_clean": len(common),
        "dropped": len(union) - len(common),
        "flips": len(flips),
        "flip_rate": (len(flips) / len(common)) if common else None,
        "nonallow_identities": nonallow_total,
        "nonallow_flips": nonallow_flips,
        "nonallow_flip_rate": (nonallow_flips / nonallow_total) if nonallow_total else None,
        "r1_nonallow_identities": len(r1_nonallow),
        "r1_nonallow_flips": r1_nonallow_flips,
        "r1_nonallow_flip_rate": (r1_nonallow_flips / len(r1_nonallow)) if r1_nonallow else None,
        "majority_nonallow_identities": len(maj_nonallow),
        "majority_nonallow_flips": maj_nonallow_flips,
        "majority_nonallow_flip_rate": (maj_nonallow_flips / len(maj_nonallow)) if maj_nonallow else None,
        "unanimous_nonallow_identities": len(unan_nonallow),
        "unanimous_nonallow_flips": unan_nonallow_flips,
        "unanimous_nonallow_flip_rate": (unan_nonallow_flips / len(unan_nonallow)) if unan_nonallow else None,
        "action_dist_r1": dict(Counter(runs[0][k] for k in common).most_common()),
        "flip_patterns": dict(pattern.most_common(30)),
        "flip_examples": [{"case_id": k[0], "event_index": k[1], "actions": list(a)} for k, a in flips[:15]],
        "pairwise_disagreements": {
            "r1_vs_r2": sum(1 for k in common if runs[0][k] != runs[1][k]),
            "r1_vs_r3": sum(1 for k in common if runs[0][k] != runs[2][k]),
            "r2_vs_r3": sum(1 for k in common if runs[1][k] != runs[2][k]),
        },
    }


def main():
    wanted = sys.argv[1:] or BACKENDS
    results = [analyze(b) for b in wanted]
    print(json.dumps(results, indent=2, sort_keys=False))


if __name__ == "__main__":
    main()
