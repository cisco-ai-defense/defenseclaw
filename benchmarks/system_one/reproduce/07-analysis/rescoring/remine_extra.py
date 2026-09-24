"""Second pass: every OTHER settled artifact pinned to the same 4,277-case core corpus.
Reuses remine.py's arithmetic unchanged. ZERO GPU, read-only on all inputs."""
import json, sys
from pathlib import Path
sys.path.insert(0, "/home/ubuntu/rescoring-remine")
import remine as R

DATA = R.DATA
EXTRA = [
    ("Jev 1.13.0 @Q0", None, DATA/"s2/jev-q0-C7.jsonl", None, None, None),
    ("Jev 1.13.0 @Q1", None, DATA/"s2/jev-q1-C7.jsonl", None, None, None),
    ("Jev 1.13.0 @Q3", None, DATA/"s2/jev-q3-C7.jsonl", None, None, None),
    ("Jev 1.13.0 @Q4", None, DATA/"s2/jev-q4-C7.jsonl", None, None, None),
    ("DiffusionGemma @Q3", None, DATA/"s2/diffgemma-final.jsonl", None, None, None),
    ("deterministic rule tier", None, DATA/"s2/deterministic.jsonl", None, None, None),
    ("secjudge C7-isattack", None, DATA/"secjudge/predictions/secjudge-s2-C7-isattack.jsonl", None, None, None),
    ("secjudge C7-t05-50", None, DATA/"secjudge/predictions/secjudge-s2-C7-t05-50.jsonl", None, None, None),
    ("secjudge C7-t10-90", None, DATA/"secjudge/predictions/secjudge-s2-C7-t10-90.jsonl", None, None, None),
    ("secjudge C7-t20-75", None, DATA/"secjudge/predictions/secjudge-s2-C7-t20-75.jsonl", None, None, None),
    ("secjudge C0-sev", None, DATA/"secjudge/predictions/secjudge-s2-C0-sev.jsonl", None, None, None),
    ("secjudge C0-isattack", None, DATA/"secjudge/predictions/secjudge-s2-C0-isattack.jsonl", None, None, None),
    ("secjudge C0-t05-50", None, DATA/"secjudge/predictions/secjudge-s2-C0-t05-50.jsonl", None, None, None),
    ("secjudge C0-t10-90", None, DATA/"secjudge/predictions/secjudge-s2-C0-t10-90.jsonl", None, None, None),
    ("secjudge C0-t20-75", None, DATA/"secjudge/predictions/secjudge-s2-C0-t20-75.jsonl", None, None, None),
    ("open-jev-qwen-27b (h200 dup path)", None, DATA/"openjev-qwen/s2/h200/open-jev-qwen-27b.jsonl", None, None, None),
]
# metas whose prediction body is absent -> list as unusable, do not score
ORPHAN_METAS = [
    DATA/"secjudge/s2/secjudge.jsonl",
    DATA/"openjev-qwen/validation/guard/named-guard-payload/nimble__s2__bespoke-nimble-9b.jsonl",
    DATA/"openjev-qwen/validation/guard/named-guard-payload/openjev-qwen__s2__open-jev-qwen-2b.jsonl",
    DATA/"openjev-qwen/validation/guard/named-guard-payload/openjev-qwen__s2__open-jev-qwen-9b.jsonl",
]
R.ARMS = EXTRA
orig = R.main
def main():
    out = Path(sys.argv[sys.argv.index("--out")+1])
    orig()
    rep = json.loads((out/"remine-full.json").read_text())
    orph = []
    for p in ORPHAN_METAS:
        mp = Path(str(p)+".meta.json")
        m = json.loads(mp.read_text()) if mp.exists() else {}
        orph.append({"declared_prediction_path": str(p), "prediction_body_on_disk": p.exists(),
                     "meta_path": str(mp), "meta_complete": m.get("complete"),
                     "meta_prediction_sha256": m.get("prediction_sha256"),
                     "meta_predictions_field": m.get("predictions"),
                     "meta_cases": m.get("cases"), "meta_cases_sha256": m.get("cases_sha256"),
                     "verdict": "UNUSABLE: meta exists but the prediction body it names is not at this path"})
    rep["orphan_metas"] = orph
    (out/"remine-full.json").write_text(json.dumps(rep, indent=2, sort_keys=True)+"\n")
    for o in orph:
        print("ORPHAN META:", o["declared_prediction_path"], "-> meta.predictions =", o["meta_predictions_field"])
main()
