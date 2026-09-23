"""int8 dynamic-quantization equivalence check, as requested, with a documented delta distribution.

Rule applied: if quantization changes a single disposition, we either abandon it or report every
affected case. A benchmark number produced by a quantized model, compared against other models'
full-precision numbers, is not a fair comparison unless equivalence is shown.

Measures on a stratified s2 sample: fp32 vs int8 dynamic (qint8 on nn.Linear), reporting
raw_score / calibrated_score delta distributions, severity and is_attack agreement, and the
resulting `sev` disposition changes, plus wall-clock for both.
"""

from __future__ import annotations

import json
import os
import random
import statistics
import sys
import time
from pathlib import Path

REPO = "$WORK/defenseclaw-system-one"
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + "/benchmarks/scripts")
sys.path.insert(0, "$WORK/.system-one-data/outputs/secjudge/code")
MODEL_DIR = "$WORK/.system-one-data/models/secjudge-snapshot"
sys.path.insert(0, MODEL_DIR)

import safetensors.torch  # noqa: E402
import torch  # noqa: E402
import torch.nn as nn  # noqa: E402
from transformers import AutoConfig, AutoTokenizer  # noqa: E402

from benchmark_inventory_system_one_sources import read_jsonl, truth_grade  # noqa: E402
from secjudge_model import IsotonicCalibrator, SecJudgeForSequenceClassification  # noqa: E402
from secjudge_serialize import case_decisions  # noqa: E402

THREADS = int(os.environ.get("SJ_THREADS", "4"))
N = int(os.environ.get("SJ_N", "400"))
torch.set_num_threads(THREADS)
torch.set_grad_enabled(False)


def build():
    cfg = AutoConfig.from_pretrained(MODEL_DIR)
    cfg.calibration_temperatures = json.load(open(MODEL_DIR + "/secjudge_config.json"))["calibration_temperatures"]
    m = SecJudgeForSequenceClassification(cfg)
    r = m.classifier.load_state_dict(safetensors.torch.load_file(MODEL_DIR + "/model.safetensors"), strict=False)
    assert not r.missing_keys and not r.unexpected_keys
    m.calibrator = IsotonicCalibrator.load(MODEL_DIR + "/isotonic_calibrator.pt")
    m.eval()
    return m


tok = AutoTokenizer.from_pretrained(MODEL_DIR)
fp32 = build()
int8 = torch.ao.quantization.quantize_dynamic(build(), {nn.Linear}, dtype=torch.qint8)

# stratified sample of real s2 C0 texts
rng = random.Random(741983)
cases = list(read_jsonl(Path("$WORK/.system-one-data/outputs/s2/cases.jsonl")))
unsafe = [c for c in cases if truth_grade(c) in ("A", "B")]
benign = [c for c in cases if truth_grade(c) == "D"]
rng.shuffle(unsafe)
rng.shuffle(benign)
texts: list[tuple[str, str]] = []
for c in unsafe[:60] + benign[:120]:
    for _ei, _v, text, _m in case_decisions(c, ["C0"]):
        texts.append((str(c["id"]), text))
        if len(texts) >= N:
            break
    if len(texts) >= N:
        break
lens = [len(tok(t, truncation=True, max_length=512)["input_ids"]) for _, t in texts]
order = sorted(range(len(texts)), key=lambda i: lens[i])
texts = [texts[i] for i in order]


def run(model, label):
    out = []
    t0 = time.perf_counter()
    for i in range(0, len(texts), 8):
        chunk = texts[i : i + 8]
        enc = tok([t for _, t in chunk], truncation=True, max_length=512, padding=True, return_tensors="pt")
        o = model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"])
        for j, (cid, _t) in enumerate(chunk):
            out.append(
                {
                    "case_id": cid,
                    "raw": float(o.raw_attack_score[j]),
                    "cal": float(o.calibrated_score[j]),
                    "sev": o.severity[j],
                    "atk": bool(o.is_attack[j]),
                }
            )
    return out, time.perf_counter() - t0


a, t_a = run(fp32, "fp32")
b, t_b = run(int8, "int8")


def disp(sev):
    return "allow" if sev in ("NONE", "LOW") else "confirm" if sev == "MEDIUM" else "block"


draw = [abs(x["raw"] - y["raw"]) for x, y in zip(a, b)]
dcal = [abs(x["cal"] - y["cal"]) for x, y in zip(a, b)]
sev_dis = [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x["sev"] != y["sev"]]
atk_dis = [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x["atk"] != y["atk"]]
disp_dis = [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if disp(x["sev"]) != disp(y["sev"])]


def q(vals, p):
    v = sorted(vals)
    return round(v[min(len(v) - 1, int(p * len(v)))], 6)


res = {
    "kind": "secjudge-int8-equivalence",
    "n": len(a),
    "threads": THREADS,
    "fp32_seconds": round(t_a, 2),
    "int8_seconds": round(t_b, 2),
    "speedup": round(t_a / t_b, 3) if t_b else None,
    "raw_score_delta": {
        "max": round(max(draw), 6),
        "mean": round(statistics.fmean(draw), 8),
        "p50": q(draw, 0.5),
        "p95": q(draw, 0.95),
        "p99": q(draw, 0.99),
    },
    "calibrated_score_delta": {
        "max": round(max(dcal), 6),
        "mean": round(statistics.fmean(dcal), 8),
        "p50": q(dcal, 0.5),
        "p95": q(dcal, 0.95),
        "p99": q(dcal, 0.99),
    },
    "severity_agreement": round(1 - len(sev_dis) / len(a), 6),
    "is_attack_agreement": round(1 - len(atk_dis) / len(a), 6),
    "three_way_disposition_agreement": round(1 - len(disp_dis) / len(a), 6),
    "severity_disagreements": len(sev_dis),
    "is_attack_disagreements": len(atk_dis),
    "disposition_disagreements": len(disp_dis),
    "disposition_disagreement_examples": [
        {
            "case_id": x["case_id"],
            "fp32": {"sev": x["sev"], "cal": round(x["cal"], 4), "raw": round(x["raw"], 4), "disp": disp(x["sev"])},
            "int8": {"sev": y["sev"], "cal": round(y["cal"], 4), "raw": round(y["raw"], 4), "disp": disp(y["sev"])},
        }
        for _i, x, y in disp_dis[:40]
    ],
}
res["verdict"] = (
    "REJECT int8 for reported numbers"
    if res["disposition_disagreements"] > 0
    else "int8 equivalent on this sample"
)
Path("$WORK/.system-one-data/outputs/secjudge/int8-equivalence.json").write_text(
    json.dumps(res, indent=2, sort_keys=True) + "\n"
)
print(json.dumps({k: v for k, v in res.items() if k != "disposition_disagreement_examples"}, indent=2, sort_keys=True))
