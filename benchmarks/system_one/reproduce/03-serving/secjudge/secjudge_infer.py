"""SecJudge CPU inference over a stage corpus.

Writes a RAW score sidecar (one row per decision) rather than prediction JSONL directly, so the
5-class -> 3-way mapping and the raw_score threshold family can be re-derived without re-running
the 395M-param forward pass.

Sharding: --shard i --shards n partitions by case index, so n processes can run concurrently.
Batching: rows are sorted by token length inside a window and padded dynamically, which on CPU
is far cheaper than the shipped load_secjudge()'s unconditional padding="max_length".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

REPO = "$WORK/defenseclaw-system-one"
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + "/benchmarks/scripts")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = "$WORK/.system-one-data/models/secjudge-snapshot"
sys.path.insert(0, MODEL_DIR)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--stage", required=True)
    ap.add_argument("--variants", default="C7")
    ap.add_argument("--out", required=True)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--max-length", type=int, default=512)
    ap.add_argument("--char-slice", type=int, default=0, help="0=off; 512 reproduces load_secjudge()")
    ap.add_argument("--batch-window", type=int, default=256, help="rows sorted by length within this window")
    ap.add_argument("--batch-tokens", type=int, default=8192, help="max padded tokens per batch")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--limit-cases", type=int, default=0)
    ap.add_argument("--no-cache", action="store_true", help="disable the exact dedup cache (for audits)")
    ap.add_argument("--serialisation", default="production_text", choices=["production_text", "cmd"])
    ap.add_argument("--progress-every", type=int, default=2000)
    args = ap.parse_args()

    import torch

    torch.set_num_threads(args.threads)
    torch.set_grad_enabled(False)

    import safetensors.torch
    from transformers import AutoConfig, AutoTokenizer

    from benchmark_inventory_system_one_sources import read_jsonl, truth_grade
    from secjudge_model import SEVERITY_LABELS, IsotonicCalibrator, SecJudgeForSequenceClassification
    from secjudge_serialize import case_decisions

    # ---- load model (local snapshot; a bare repo-id would silently random-init) ----
    config = AutoConfig.from_pretrained(MODEL_DIR)
    sj_cfg = json.load(open(os.path.join(MODEL_DIR, "secjudge_config.json")))
    config.calibration_temperatures = sj_cfg.get("calibration_temperatures", [1.2] * 5)
    model = SecJudgeForSequenceClassification(config)
    sd = safetensors.torch.load_file(os.path.join(MODEL_DIR, "model.safetensors"))
    res = model.classifier.load_state_dict(sd, strict=False)
    if res.missing_keys or res.unexpected_keys:
        raise RuntimeError(f"weight load mismatch: missing={res.missing_keys[:5]} unexpected={res.unexpected_keys[:5]}")
    model.calibrator = IsotonicCalibrator.load(os.path.join(MODEL_DIR, "isotonic_calibrator.pt"))
    model.eval()
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)

    variants = args.variants.split(",")
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    n_decisions = 0
    n_cases = 0
    padded_tokens = 0
    n_cached = 0
    # Identical serialised text under a deterministic fp32 forward pass gives an identical
    # result, so this cache is exact rather than an approximation.
    cache: dict[str, dict] = {}

    def emit(handle, b: dict, payload: dict, duration_ms: float) -> None:
        nonlocal n_decisions
        handle.write(
            json.dumps(
                {
                    "case_id": b["case_id"],
                    "event_index": b["event_index"],
                    "context_variant": b["variant"],
                    "grade": b["grade"],
                    "n_tokens_untruncated": b["n_tokens_untruncated"],
                    "n_tokens_used": min(b["n_tokens_untruncated"], args.max_length),
                    "n_chars": b["n_chars"],
                    "truncated_at_max_length": b["n_tokens_untruncated"] > args.max_length,
                    "context_truncated_by_runner": b["ctx_trunc"],
                    "severity": payload["severity"],
                    "is_attack": payload["is_attack"],
                    "raw_score": payload["raw_score"],
                    "calibrated_score": payload["calibrated_score"],
                    "severity_probabilities": payload["severity_probabilities"],
                    "duration_ms": round(duration_ms, 4),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        n_decisions += 1

    def flush(batch, handle):
        nonlocal padded_tokens
        if not batch:
            return
        texts = [b["text"] for b in batch]
        enc = tok(
            texts,
            truncation=True,
            max_length=args.max_length,
            padding=True,
            return_tensors="pt",
        )
        padded_tokens += int(enc["input_ids"].numel())
        t0 = time.perf_counter()
        out = model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"])
        dt = (time.perf_counter() - t0) * 1000.0
        probs = out.severity_probs
        raw = out.raw_attack_score
        cal = out.calibrated_score
        per_row_ms = dt / len(batch)
        for i, b in enumerate(batch):
            payload = {
                "severity": out.severity[i],
                "is_attack": bool(out.is_attack[i]),
                "raw_score": round(float(raw[i]), 6),
                "calibrated_score": round(float(cal[i]), 6),
                "severity_probabilities": {SEVERITY_LABELS[j]: round(float(probs[i][j]), 6) for j in range(5)},
            }
            cache[b["text_sha"]] = payload
            emit(handle, b, payload, per_row_ms)
        batch.clear()

    with out_path.open("w", encoding="utf-8") as handle:
        window: list[dict] = []
        for case_index, case in enumerate(read_jsonl(Path(args.cases))):
            if args.shards > 1 and case_index % args.shards != args.shard:
                continue
            if args.limit_cases and n_cases >= args.limit_cases:
                break
            n_cases += 1
            grade = truth_grade(case)
            case_id = str(case.get("id"))
            for event_index, variant, text, meta in case_decisions(case, variants, args.serialisation):
                t = text[: args.char_slice] if args.char_slice else text
                n_untrunc = len(tok(t, truncation=False, add_special_tokens=True)["input_ids"])
                text_sha = hashlib.sha256(t.encode()).hexdigest()
                row = {
                    "case_id": case_id,
                    "event_index": event_index,
                    "variant": variant,
                    "grade": grade,
                    "text": t,
                    "text_sha": text_sha,
                    "n_tokens_untruncated": n_untrunc,
                    "n_chars": len(t),
                    "ctx_trunc": bool(meta["truncated"]),
                }
                hit = None if args.no_cache else cache.get(text_sha)
                if hit is not None:
                    emit(handle, row, hit, 0.0)
                    n_cached += 1
                else:
                    window.append(row)
            if len(window) >= args.batch_window:
                window.sort(key=lambda b: min(b["n_tokens_untruncated"], args.max_length))
                batch: list[dict] = []
                for row in window:
                    L = min(row["n_tokens_untruncated"], args.max_length)
                    if batch and (len(batch) + 1) * max(L, batch[0]["_L"]) > args.batch_tokens:
                        flush(batch, handle)
                    row["_L"] = L
                    if not batch:
                        batch = [row]
                    else:
                        batch.append(row)
                flush(batch, handle)
                window = []
                if n_decisions and n_decisions % args.progress_every < args.batch_window:
                    el = time.perf_counter() - started
                    print(
                        json.dumps(
                            {
                                "shard": args.shard,
                                "cases": n_cases,
                                "decisions": n_decisions,
                                "elapsed_s": round(el, 1),
                                "rate_per_s": round(n_decisions / el, 2),
                            }
                        ),
                        flush=True,
                    )
        if window:
            window.sort(key=lambda b: min(b["n_tokens_untruncated"], args.max_length))
            batch = []
            for row in window:
                L = min(row["n_tokens_untruncated"], args.max_length)
                if batch and (len(batch) + 1) * max(L, batch[0]["_L"]) > args.batch_tokens:
                    flush(batch, handle)
                row["_L"] = L
                if not batch:
                    batch = [row]
                else:
                    batch.append(row)
            flush(batch, handle)
        handle.flush()
        os.fsync(handle.fileno())

    elapsed = time.perf_counter() - started
    meta = {
        "kind": "secjudge-raw-shard",
        "stage": args.stage,
        "cases_path": args.cases,
        "shard": args.shard,
        "shards": args.shards,
        "variants": variants,
        "serialisation": args.serialisation,
        "max_length": args.max_length,
        "char_slice": args.char_slice,
        "threads": args.threads,
        "cases": n_cases,
        "decisions": n_decisions,
        "cache_hits": n_cached,
        "forward_passes": n_decisions - n_cached,
        "padded_tokens": padded_tokens,
        "wall_clock_s": round(elapsed, 2),
        "decisions_per_s": round(n_decisions / elapsed, 3) if elapsed else None,
        "model_dir": MODEL_DIR,
        "model_revision": "28e810afc9113d5b3ec60401940657108f51f1bb",
        "complete": True,
    }
    Path(str(out_path) + ".meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    print(json.dumps(meta, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
