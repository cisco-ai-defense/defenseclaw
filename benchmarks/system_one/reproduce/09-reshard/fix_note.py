"""Correct one provenance claim in the settled meta, and re-verify the body digest.

The generated note said shard0's driver was "stopped at a case boundary it had passed".
That is not what happened: I never signalled PID 92139. It was lost when the Lightning
studio stopped at ~00:15Z and the body was frozen from then on. Editing meta.json does not
touch the prediction body, so prediction_sha256 stays valid -- re-checked below regardless.
"""
import hashlib, json
from pathlib import Path

S = Path("/teamspace/studios/this_studio/sysone/runs/nimble-s3/settled")
body, meta_p = S / "bespoke-nimble-9b.jsonl", S / "bespoke-nimble-9b.jsonl.meta.json"

def sha256_file(p):
    d = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            d.update(b)
    return d.hexdigest()

before = sha256_file(body)
m = json.loads(meta_p.read_text())
m["merge"]["shard0"]["note"] = (
    "Produced by the original live driver PID 92139 at the canonical serving conditions. "
    "That driver was NOT stopped deliberately: it was lost when the Lightning studio stopped "
    "at ~00:15Z, and the body was frozen at 23096 rows from then on. The first 22535 rows are "
    "a prefix of the full 100001-request plan, revalidated row-by-row with the runner's own "
    "validate_resume_prefix (ordered plan identity, prediction schema, and request_sha256 "
    "recomputed from the rebuilt canonical request). The 561 rows beyond the boundary are "
    "discarded here because chunk shard 52 covers that range instead.")
m["merge"]["shard0"]["driver_end"] = "lost with the studio stop at ~00:15Z, not signalled"
meta_p.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")

after = sha256_file(body)
declared = json.loads(meta_p.read_text())["prediction_sha256"]
print(json.dumps({"body_digest_before_meta_edit": before,
                  "body_digest_after_meta_edit": after,
                  "body_unchanged": before == after,
                  "declared_in_meta": declared,
                  "declared_matches_disk": declared == after}, indent=1))
