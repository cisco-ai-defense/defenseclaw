#!/usr/bin/env python3
"""Default-vs-default control for Gemma 4: is the flex/default delta just tier noise?

Compares the new flex-run's `default` arm against the pre-existing
s1-gemma4-screen-c7 run, which used the identical config (C7 / I3 / Q0,
service_tier=default, same 200-case corpus, same cases_sha256).
"""
import json
from collections import Counter
from pathlib import Path

NEW = Path("$WORK/.system-one-data/outputs/flex")
OLD = Path("$WORK/.system-one-data/outputs/s1-n1000")

ARMS = {
    "default_new": NEW / "gemma4-default.jsonl",
    "flex_new": NEW / "gemma4-flex.jsonl",
    "default_old": OLD / "gemma4-screen-c7.jsonl",
}


def rows(p):
    out = []
    with p.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def emap(p):
    ep = p.with_suffix(p.suffix + ".events.jsonl")
    m = {}
    for r in rows(ep):
        if r.get("error_code"):
            continue
        m[(str(r.get("case_id", "")), int(r.get("event_index", -1)))] = str(r.get("action", ""))
    return m


def cmap(p):
    return {str(r.get("case_id", "")): str(r.get("action", "")) for r in rows(p)}


def compare(a_name, b_name, a, b):
    common = set(a) & set(b)
    dis = [k for k in common if a[k] != b[k]]
    return {
        "pair": f"{a_name} vs {b_name}",
        "n_common": len(common),
        "disagreements": len(dis),
        "agreement_rate": round((len(common) - len(dis)) / len(common), 6) if common else None,
        "transitions": dict(Counter(f"{a[k]}->{b[k]}" for k in dis).most_common()),
    }


def main():
    missing = {n: str(p) for n, p in ARMS.items() if not p.exists()}
    if missing:
        print(json.dumps({"status": "MISSING", "missing": missing}, indent=2))
        return

    # confirm the control really used the same config
    cfg = {}
    for n, p in ARMS.items():
        mp = p.with_suffix(p.suffix + ".meta.json")
        if mp.exists():
            m = json.loads(mp.read_text())
            cfg[n] = {
                k: m.get(k)
                for k in ("context", "instruction", "question", "service_tier",
                          "model", "cases_sha256", "prompt_tokens", "completion_tokens",
                          "provider_calls", "errors", "prediction_sha256")
            }

    ev = {n: emap(p) for n, p in ARMS.items()}
    ca = {n: cmap(p) for n, p in ARMS.items()}

    report = {
        "config_check": cfg,
        "per_event": [
            compare("default_new", "flex_new", ev["default_new"], ev["flex_new"]),
            compare("default_old", "default_new", ev["default_old"], ev["default_new"]),
            compare("default_old", "flex_new", ev["default_old"], ev["flex_new"]),
        ],
        "per_case": [
            compare("default_new", "flex_new", ca["default_new"], ca["flex_new"]),
            compare("default_old", "default_new", ca["default_old"], ca["default_new"]),
            compare("default_old", "flex_new", ca["default_old"], ca["flex_new"]),
        ],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
