"""Post-chunk gate: meta must be complete and pinned to the canonical cell, and the body
must contain zero error rows.

The 2B wreckage shows why the error check matters: a driver that trips the 200M input-token
cap keeps writing rows with route="error", and a chunk could in principle come back
complete:true while being unusable. Chunks here are ~1.5k requests (~4.2M tokens) so the cap
cannot bind, but the gate is cheap and catches any provider/parse failure too.
"""
import json, sys

meta_path, pred_path, want = sys.argv[1], sys.argv[2], int(sys.argv[3])
m = json.load(open(meta_path))
if m.get("complete") is not True:
    sys.exit(f"meta complete is not true: {m.get('complete')}")
if m["requests"] != want:
    sys.exit(f"meta requests {m['requests']} != expected {want}")
if m["model"] != "bespoke-nimble-9b":
    sys.exit(f"model {m['model']}")
if m["model_revision"] != "93ec5d6ff1a9cd31d6cc0e0c58d312465d36de7c":
    sys.exit(f"revision {m['model_revision']}")
if (m["contexts"], m["instructions"], m["questions"], m["instruction_format"]) != \
   (["C7"], ["I3"], ["Q2"], "structured"):
    sys.exit(f"grid {m['contexts']} {m['instructions']} {m['questions']} {m['instruction_format']}")

rows = err = tok = 0
codes = {}
for line in open(pred_path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    r = json.loads(line)
    rows += 1
    tok += int(r.get("input_tokens", 0))
    if r.get("error_code") or r.get("route") == "error":
        err += 1
        codes[r.get("error_code", "?")] = codes.get(r.get("error_code", "?"), 0) + 1
if rows != want:
    sys.exit(f"body has {rows} rows, expected {want}")
print(json.dumps({"rows": rows, "error_rows": err, "error_codes": codes,
                  "actual_input_tokens": m["actual_input_tokens"], "summed_row_tokens": tok}))
if err:
    sys.exit(f"{err} error rows: {codes}")
