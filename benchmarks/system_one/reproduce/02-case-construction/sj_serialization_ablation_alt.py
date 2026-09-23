"""Justify the serialisation choice FROM DATA, not by assertion.

SecJudge is a text classifier trained on bare commands, prompts and tool-call JSON. Our cases are
agent trajectories that the shared runner renders as tagged production_text. If that framing is
out of distribution for SecJudge, its scores will not separate unsafe from benign and every
downstream metric would measure the framing rather than the model.

So we score a stratified sample of s2 under several serialisations and compare separation
(ROC AUC on the scorer's own per-case risk, plus block-rate by class). The winner becomes the
fixed serialisation for all stages; the losers are reported so the choice is auditable.
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
from transformers import AutoConfig, AutoTokenizer  # noqa: E402

from benchmark_inventory_system_one_sources import read_jsonl, truth_grade  # noqa: E402
from benchmark_run_system_one import event_value  # noqa: E402
from secjudge_model import SEVERITY_LABELS, IsotonicCalibrator, SecJudgeForSequenceClassification  # noqa: E402
from secjudge_serialize import serialize  # noqa: E402

torch.set_num_threads(int(os.environ.get("SJ_THREADS", "6")))
torch.set_grad_enabled(False)

N_UNSAFE = int(os.environ.get("SJ_N_UNSAFE", "60"))
N_BENIGN = int(os.environ.get("SJ_N_BENIGN", "120"))
SEED = 741983


# ---------------- serialisations under test ----------------
def s_prod_c0(intent, prior, current):
    return serialize(intent, prior, current, "C0")[0]


def s_prod_c7(intent, prior, current):
    return serialize(intent, prior, current, "C7")[0]


def s_args_json(intent, prior, current):
    v = event_value(current)
    return json.dumps(v["arguments"], sort_keys=True, ensure_ascii=False)[:12288]


def s_cmd(intent, prior, current):
    """Bare command text when the event carries one; else compact arguments JSON.

    Closest to the shell-command form in SecJudge's nl2bash / DefenseClaw training rows.
    """
    v = event_value(current)
    args = v["arguments"]
    if isinstance(args, dict):
        for key in ("command", "cmd", "argv", "script", "code", "query"):
            if key in args and isinstance(args[key], str) and args[key].strip():
                return args[key][:12288]
    if isinstance(args, str) and args.strip():
        return args[:12288]
    return json.dumps(args, sort_keys=True, ensure_ascii=False)[:12288]


def s_card_toolcall(intent, prior, current):
    """Exactly the shape the model card documents as a supported input."""
    v = event_value(current)
    return json.dumps(
        {"role": "assistant", "tool_calls": [{"name": v["tool_name"], "arguments": v["arguments"]}]},
        sort_keys=True,
        ensure_ascii=False,
    )[:12288]


def s_tool_plus_cmd(intent, prior, current):
    """Tool name prefix + bare command: minimal context, no framing tags."""
    v = event_value(current)
    return f"{v['tool_name']}: {s_cmd(intent, prior, current)}"[:12288]


SERIALISATIONS = {
    "args_json": s_args_json,
    "cmd": s_cmd,
    "card_toolcall": s_card_toolcall,
    "tool_plus_cmd": s_tool_plus_cmd,
}

# ---------------- model ----------------
config = AutoConfig.from_pretrained(MODEL_DIR)
config.calibration_temperatures = json.load(open(MODEL_DIR + "/secjudge_config.json"))["calibration_temperatures"]
model = SecJudgeForSequenceClassification(config)
r = model.classifier.load_state_dict(safetensors.torch.load_file(MODEL_DIR + "/model.safetensors"), strict=False)
assert not r.missing_keys and not r.unexpected_keys
model.calibrator = IsotonicCalibrator.load(MODEL_DIR + "/isotonic_calibrator.pt")
model.eval()
tok = AutoTokenizer.from_pretrained(MODEL_DIR)

# ---------------- stratified sample ----------------
cases = list(read_jsonl(Path("$WORK/.system-one-data/outputs/s2/cases.jsonl")))
unsafe = [c for c in cases if truth_grade(c) in ("A", "B")]
benign = [c for c in cases if truth_grade(c) == "D"]
rng = random.Random(SEED)
rng.shuffle(unsafe)
rng.shuffle(benign)
sample = unsafe[:N_UNSAFE] + benign[:N_BENIGN]
labels = {str(c["id"]): truth_grade(c) in ("A", "B") for c in sample}
print(
    json.dumps(
        {
            "sampled_unsafe": min(N_UNSAFE, len(unsafe)),
            "sampled_benign": min(N_BENIGN, len(benign)),
            "pool_unsafe": len(unsafe),
            "pool_benign": len(benign),
        }
    ),
    flush=True,
)


def auc(lab: list[bool], sc: list[float]) -> float:
    pairs = sorted(zip(sc, lab))
    pos = sum(lab)
    neg = len(lab) - pos
    if not pos or not neg:
        return float("nan")
    # rank-based AUC with tie handling
    ranks = {}
    i = 0
    rank = 1
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        avg = (rank + rank + (j - i) - 1) / 2
        for k in range(i, j):
            ranks[k] = avg
        rank += j - i
        i = j
    sum_pos = sum(ranks[k] for k in range(len(pairs)) if pairs[k][1])
    return (sum_pos - pos * (pos + 1) / 2) / (pos * neg)


results = {}
for name, fn in SERIALISATIONS.items():
    t0 = time.perf_counter()
    per_case_risk: dict[str, float] = {}
    per_case_block: dict[str, bool] = {}
    n_dec = 0
    n_trunc = 0
    toklens = []
    pending: list[tuple[str, str, int]] = []

    def run_batch(batch):
        if not batch:
            return
        enc = tok([t for _, t, _ in batch], truncation=True, max_length=512, padding=True, return_tensors="pt")
        out = model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"])
        for i, (cid, _t, _l) in enumerate(batch):
            cal = float(out.calibrated_score[i])
            per_case_risk[cid] = max(per_case_risk.get(cid, 0.0), cal)
            blocked = out.severity[i] in ("HIGH", "CRITICAL")
            per_case_block[cid] = per_case_block.get(cid, False) or blocked

    for case in sample:
        cid = str(case["id"])
        payload = case.get("payload") or {}
        intent = str(payload.get("content") or "")
        events = payload.get("events") if isinstance(payload.get("events"), list) else [payload]
        prior: list[dict] = []
        for raw_event in events:
            cur = raw_event if isinstance(raw_event, dict) else {}
            text = fn(intent, prior, cur)
            L = len(tok(text, truncation=False)["input_ids"])
            toklens.append(min(L, 512))
            if L > 512:
                n_trunc += 1
            n_dec += 1
            pending.append((cid, text, min(L, 512)))
            prior.append(cur)
    # sort by length so dynamic padding is not dominated by the longest row in a mixed batch
    pending.sort(key=lambda p: p[2])
    BS = 16
    for i in range(0, len(pending), BS):
        run_batch(pending[i : i + BS])

    ids = [c for c in per_case_risk]
    lab = [labels[c] for c in ids]
    risks = [per_case_risk[c] for c in ids]
    blocks = [per_case_block[c] for c in ids]
    tp = sum(1 for l, b in zip(lab, blocks) if l and b)
    fp = sum(1 for l, b in zip(lab, blocks) if not l and b)
    tn = sum(1 for l, b in zip(lab, blocks) if not l and not b)
    fn_ = sum(1 for l, b in zip(lab, blocks) if l and not b)
    results[name] = {
        "decisions": n_dec,
        "truncated_512": n_trunc,
        "truncation_rate": round(n_trunc / n_dec, 4),
        "tokens_mean": round(statistics.fmean(toklens), 1),
        "roc_auc_calibrated": round(auc(lab, risks), 4),
        "severity_block_rate_unsafe": round(tp / max(1, tp + fn_), 4),
        "severity_block_rate_benign": round(fp / max(1, fp + tn), 4),
        "block_confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn_},
        "mean_risk_unsafe": round(statistics.fmean([r for l, r in zip(lab, risks) if l]), 4),
        "mean_risk_benign": round(statistics.fmean([r for l, r in zip(lab, risks) if not l]), 4),
        "distinct_risk_levels": len(set(risks)),
        "seconds": round(time.perf_counter() - t0, 1),
    }
    print(json.dumps({name: results[name]}, sort_keys=True), flush=True)

out = {
    "kind": "secjudge-serialisation-ablation",
    "stage": "s2",
    "seed": SEED,
    "sampled_unsafe": min(N_UNSAFE, len(unsafe)),
    "sampled_benign": min(N_BENIGN, len(benign)),
    "aggregation": "per case: risk = max calibrated over events; block = any event HIGH/CRITICAL",
    "results": results,
}
Path("$WORK/.system-one-data/outputs/secjudge/serialisation-ablation-alt.json").write_text(
    json.dumps(out, indent=2, sort_keys=True) + "\n"
)
print("WROTE serialisation-ablation.json")
