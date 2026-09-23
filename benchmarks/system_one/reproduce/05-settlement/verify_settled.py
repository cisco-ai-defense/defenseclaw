"""Verify each merged s2 prediction file is settled per the publication rule:
meta complete:true AND on-disk sha256 == prediction_sha256."""
import hashlib
import json
import pathlib
import sys

TARGETS = [
    ("open-jev-qwen-9b", "$WORK/.system-one-data/outputs/openjev-qwen/s2/open-jev-qwen-9b.jsonl"),
    ("open-jev-qwen-2b", "$WORK/.system-one-data/outputs/openjev-qwen/s2/open-jev-qwen-2b.jsonl"),
    ("bespoke-nimble-9b", "$WORK/.system-one-data/outputs/nimble/s2/bespoke-nimble-9b.jsonl"),
]

bad = []
for name, path in TARGETS:
    predictions = pathlib.Path(path)
    meta_path = pathlib.Path(path + ".meta.json")
    if not meta_path.exists():
        print(f"{name:20s} NO META")
        bad.append(name)
        continue
    meta = json.loads(meta_path.read_text())
    digest = hashlib.sha256()
    with predictions.open("rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            digest.update(block)
    disk = digest.hexdigest()
    match = disk == meta.get("prediction_sha256")
    settled = meta.get("complete") is True and match
    print(f"{name:20s} complete={meta.get('complete')} rows={meta.get('requests')} "
          f"sha_match={match} SETTLED={settled}")
    print(f"{'':20s} repo_id={meta.get('repo_id')}  base={meta.get('base_model')}"
          f"@{(meta.get('base_revision') or '')[:12]}")
    print(f"{'':20s} adapter_revision={meta.get('adapter_revision')}  "
          f"adapter_sha256={(meta.get('adapter_sha256') or '')[:12]}  T={meta.get('temperature')}")
    print(f"{'':20s} grid={meta.get('grid')}  errors={meta.get('errors_by_code')}  "
          f"model_revision={(meta.get('model_revision') or '')[:16]}")
    if not settled:
        bad.append(name)

print()
print("ALL SETTLED" if not bad else f"NOT SETTLED: {bad}")
sys.exit(1 if bad else 0)
