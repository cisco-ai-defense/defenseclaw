"""Settled-file check for exactly the files this phase quotes.

Same rule as .secjudge-work/check_settled.py: meta complete: true AND the on-disk
sha256 equals meta.prediction_sha256.
"""

import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


def check(path):
    path = Path(path)
    if not path.exists():
        return {"path": str(path), "settled": False, "reason": "missing"}
    meta = path.with_suffix(path.suffix + ".meta.json")
    if not meta.exists():
        return {"path": str(path), "settled": False, "reason": "no meta"}
    m = json.loads(meta.read_text())
    digest = sha256_file(path)
    return {"path": str(path), "settled": bool(m.get("complete")) and m.get("prediction_sha256") == digest,
            "complete": m.get("complete"), "meta_prediction_sha256": m.get("prediction_sha256"),
            "on_disk_sha256": digest, "requests": m.get("requests"), "cases": m.get("cases"),
            "cases_sha256": m.get("cases_sha256"), "model": m.get("model"),
            "model_revision": m.get("model_revision"),
            "contexts": m.get("contexts"), "instructions": m.get("instructions"), "questions": m.get("questions")}


if __name__ == "__main__":
    out = [check(p) for p in sys.argv[1:]]
    print(json.dumps(out, indent=2))
    print("ALL SETTLED:", all(r["settled"] for r in out))
