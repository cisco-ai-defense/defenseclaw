#!/usr/bin/env python3
"""Serve Mapika/decider-2b on the DefenseClaw System One /v1/systemone contract.

Deliberately avoids decider.serve's defaults, which would make the numbers incomparable:
  * DECIDER_FP8 defaults to "1" there -> would serve fp8, not bf16.
  * DECIDER_COMPILE defaults to "1" and Engine(use_graphs=True) -> torch.compile + CUDA graphs.
  * the schema cache and eng.score_shared both reuse a prefix across the rows of a request.
This shim uses decider's OWN semantic code (prompt.build, systemone.plan_rows/assemble,
DecisionModel.slot_logits, softmax(logits / T)) so the readout is the shipped one, but loads
bf16 + eager, caps GPU memory hard, asserts zero offload, and never reuses a prefix.

Probabilities are emitted at full float precision: decider.systemone.format_answer rounds to
4 dp, which would quantise the ranking variable far below the other arms on this board
(they carry full precision). The argmax and every decision are identical either way.
"""
import argparse, json, os, sys, threading, time, hashlib
from contextlib import contextmanager

import torch
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@contextmanager
def forced_loader(attn, dtype):
    """Force attn_implementation and dtype at load; record what was actually passed."""
    from transformers import AutoModelForCausalLM
    original = AutoModelForCausalLM.from_pretrained
    captured = {}

    def wrapper(*a, **kw):
        kw["attn_implementation"] = attn
        kw["dtype"] = dtype
        captured.update({"attn_implementation": attn, "dtype": str(dtype)})
        return original(*a, **kw)

    AutoModelForCausalLM.from_pretrained = staticmethod(wrapper)
    try:
        yield captured
    finally:
        AutoModelForCausalLM.from_pretrained = original


def placement_report(model):
    """Every parameter and buffer must live on a real CUDA device. cpu/meta/disk means offload."""
    counts = {}
    offenders = []
    dtypes = {}
    buffer_dtypes = {}
    params = dict(model.named_parameters())
    for name, tensor in list(model.named_parameters()) + list(model.named_buffers()):
        kind = tensor.device.type
        counts[kind] = counts.get(kind, 0) + 1
        if kind != "cuda":
            offenders.append(f"{name}:{kind}")
        if tensor.is_floating_point():
            if name in params:
                dtypes[str(tensor.dtype)] = dtypes.get(str(tensor.dtype), 0) + 1
            else:
                buffer_dtypes[str(tensor.dtype)] = buffer_dtypes.get(str(tensor.dtype), 0) + 1
    hooked = []
    for name, module in model.named_modules():
        hook = getattr(module, "_hf_hook", None)
        if hook is not None and getattr(hook, "offload", False):
            hooked.append(name or "<root>")
    return {
        "devices": counts,
        "parameter_float_dtypes": dtypes,
        "buffer_float_dtypes": buffer_dtypes,
        "tensors_not_on_cuda": offenders[:20],
        "n_tensors_not_on_cuda": len(offenders),
        "modules_with_offload_hook": hooked,
        "zero_offload": not offenders and not hooked,
    }


class Shim:
    def __init__(self, args):
        sys.path.insert(0, args.model_path)
        from decider.model import DecisionModel, collate
        from decider.prompt import build, MAX_OPTIONS
        from decider.infer import Example, Q
        from decider import systemone as S1

        self.collate, self.build, self.Example, self.Q, self.S1 = collate, build, Example, Q, S1
        self.MAX_OPTIONS = MAX_OPTIONS

        # full-precision answers: assemble() looks format_answer up as a module global
        original_format = S1.format_answer
        S1.format_answer = lambda rq, p, nd=17: original_format(rq, p, nd)

        cfg = json.load(open(os.path.join(args.model_path, "decider_config.json")))
        self.cfg = cfg
        self.T = float(cfg.get("temperature", 1.0))
        self.isolated = bool(cfg.get("isolated_levels", False))
        self.neutralize_none = bool(cfg.get("neutralize_none", True))
        if self.neutralize_none:
            raise SystemExit("ABORT: neutralize_none is true for this checkpoint; shim does not implement it")
        self.model_name = "decider-" + str(cfg.get("version", "dev"))

        total = torch.cuda.get_device_properties(0).total_memory
        cap = int(args.max_memory_gib * (1 << 30))
        if cap >= total:
            raise SystemExit(f"ABORT: cap {cap} >= card total {total}; refusing to take whatever is free")
        torch.cuda.set_per_process_memory_fraction(cap / total, 0)
        self.cap_bytes, self.total_bytes = cap, total

        with forced_loader(args.attn, torch.bfloat16) as captured:
            self.m = DecisionModel(args.model_path, dtype=torch.bfloat16, grad_ckpt=False).to("cuda:0").eval()
        self.load_kwargs = dict(captured)

        self.m.lm.config.use_cache = False
        self.placement = placement_report(self.m)
        live_attn = getattr(self.m.lm.config, "_attn_implementation", None)
        self.live_attn = live_attn
        if live_attn != args.attn:
            raise SystemExit(f"ABORT: attn_implementation is {live_attn!r}, expected {args.attn!r}")
        if not self.placement["zero_offload"]:
            raise SystemExit("ABORT: offload detected: " + json.dumps(self.placement))
        # Weights must be bf16 (this is what rules out the fp8 path). Non-persistent RoPE
        # inv_freq buffers are fp32 by design in transformers and are reported, not policed.
        bad = [d for d in self.placement["parameter_float_dtypes"] if d != "torch.bfloat16"]
        if bad:
            raise SystemExit(f"ABORT: non-bf16 parameter dtypes present {bad}")
        self.attn_budget = int(args.attn_budget_elems)
        self.max_rows = int(getattr(args, "max_rows_per_forward", 0) or 0)
        self.lock = threading.Lock()
        self.stats = dict(requests=0, rows=0, forwards=0, prefix_reuse=0, schema_cache_hits=0, errors=0)

    @torch.no_grad()
    def systemone(self, state, questions):
        S1 = self.S1
        rqs = {k: S1.render_question(v) for k, v in questions.items()}
        flat, index = S1.plan_rows(rqs, self.isolated)
        ctx = S1.render_state(state)
        # one row per question (and per isolated Score level); every row carries its own copy of
        # the state, so no prefix is shared or cached across rows.
        items = [
            self.build(
                self.Example(ctx, [self.Q(r["question"], list(r["options"]), 0)]),
                self.m.tok, _NoShuffle(), max_options=self.MAX_OPTIONS,
                max_ctx_tokens=32768, layout="state_first",
            )
            for r in flat
        ]
        # Eager attention materialises a fp32 [B, heads, T, T] score matrix (32*B*T^2 bytes here:
        # 8 heads, 6 full-attention layers of 24). Sub-batch the rows so that stays inside the
        # cap on the longest prompts. Rows are independent and right-padded, so the grouping does
        # not change any probability -- verified by --isolation-check.
        chunks, cur = [], []
        for it in items:
            t = ((len(it["ids"]) + 63) // 64) * 64
            if cur and ((self.max_rows and len(cur) >= self.max_rows)
                        or (len(cur) + 1) * t * t > self.attn_budget):
                chunks.append(cur); cur = []
            cur.append(it)
        if cur:
            chunks.append(cur)
        parts = []
        for chunk in chunks:
            b = self.collate(chunk, self.m.tok.pad_token_id)
            with self.lock:
                logits = self.m.slot_logits(
                    b["input_ids"].to("cuda:0"), b["attention_mask"].to("cuda:0"),
                    b["slot_idx"].to("cuda:0"), b["slot_batch"].to("cuda:0"), b["nopts"].to("cuda:0"),
                )
                parts.append(torch.softmax(logits / self.T, -1).cpu())
                self.stats["forwards"] += 1
        probs = torch.cat(parts, 0)
        self.stats["requests"] += 1
        self.stats["rows"] += len(items)
        answers = S1.assemble(rqs, index, [probs[i].tolist() for i in range(len(flat))])
        return {
            "model": self.model_name,
            "answers": answers,
            "usage": {"input_tokens": S1.unique_tokens(items), "output_tokens": 0},
        }


class _NoShuffle:
    def shuffle(self, x): pass
    def sample(self, xs, k): return xs[:k]


class S1Req(BaseModel):
    state: object
    questions: dict
    model: str | None = None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model-path", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--repo-id", required=True)
    p.add_argument("--repo-revision", required=True)
    p.add_argument("--attn", default="eager")
    p.add_argument("--max-memory-gib", type=float, required=True)
    p.add_argument("--max-rows-per-forward", type=int, default=0,
                   help="hard cap on rows per forward; 1 makes every answer independent of batch "
                        "grouping (bf16 kernels vary by batch shape) and removes all padding")
    p.add_argument("--attn-budget-elems", type=float, default=24e6,
                   help="cap on B*T^2 per forward; bounds the eager fp32 attention matrix")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--provenance-out")
    p.add_argument("--selftest")
    p.add_argument("--selftest-limit", type=int, default=0)
    p.add_argument("--selftest-out")
    args = p.parse_args()

    shim = Shim(args)
    prov = {
        "name": args.name, "repo_id": args.repo_id, "repo_revision": args.repo_revision,
        "model_path": args.model_path, "load_kwargs": shim.load_kwargs,
        "attn_implementation_live": shim.live_attn,
        "dtype": "bfloat16",
        "prefix_cache": False,
        "prefix_cache_mechanisms_disabled": [
            "decider.serve schema cache (SCHEMA_FIRST) not used",
            "decider.engine.score_shared not used",
            "CUDA graphs not used (no Engine)",
            "torch.compile not used",
            "fp8 not used",
            "layout=state_first, one full-state row per question, config.use_cache=False",
        ],
        "temperature_applied": shim.T,
        "temperature_source": "decider_config.json:temperature",
        "isolated_levels": shim.isolated,
        "max_memory_gib_cap": args.max_memory_gib,
        "attn_budget_elems": args.attn_budget_elems,
        "max_rows_per_forward": args.max_rows_per_forward,
        "card_total_bytes": shim.total_bytes,
        "cap_bytes": shim.cap_bytes,
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "placement": shim.placement,
        "torch": torch.__version__,
        "decider_config": shim.cfg,
        "probabilities_precision": "full float (format_answer nd=17)",
    }
    import transformers
    prov["transformers"] = transformers.__version__
    prov["weights_sha256"] = sha256_file(os.path.join(args.model_path, "model.safetensors"))
    prov["peak_alloc_gib_after_load"] = round(torch.cuda.max_memory_allocated(0) / 2 ** 30, 3)
    print("[provenance] " + json.dumps(prov, indent=2), flush=True)
    if args.provenance_out:
        with open(args.provenance_out, "w") as fh:
            json.dump(prov, fh, indent=2, sort_keys=True)

    if args.selftest:
        rows = [json.loads(l) for l in open(args.selftest) if l.strip()]
        if args.selftest_limit:
            rows = rows[: args.selftest_limit]
        out, t0 = [], time.time()
        for r in rows:
            s = time.time()
            res = shim.systemone(r["state"], r["questions"])
            out.append({"case_id": r.get("case_id"), "event_index": r.get("event_index"),
                        "ms": round((time.time() - s) * 1000, 2), "answers": res["answers"],
                        "usage": res["usage"]})
        el = time.time() - t0
        rep = {"n": len(out), "elapsed_s": round(el, 2),
               "rows_per_s": round(len(out) / el, 4) if el else None,
               "peak_alloc_gib": round(torch.cuda.max_memory_allocated(0) / 2 ** 30, 3),
               "peak_reserved_gib": round(torch.cuda.max_memory_reserved(0) / 2 ** 30, 3),
               "cap_gib": args.max_memory_gib, "stats": shim.stats,
               "placement": shim.placement, "attn_live": shim.live_attn,
               "temperature": shim.T, "results": out}
        print(json.dumps({k: v for k, v in rep.items() if k != "results"}, indent=2), flush=True)
        if args.selftest_out:
            with open(args.selftest_out, "w") as fh:
                json.dump(rep, fh, indent=2)
        return 0

    app = FastAPI(title=args.name)

    @app.post("/v1/systemone")
    async def systemone(r: S1Req):
        try:
            return shim.systemone(r.state, r.questions)
        except ValueError as e:
            shim.stats["errors"] += 1
            raise HTTPException(422, str(e))

    @app.get("/health")
    async def health():
        return {"ok": True, "model": args.name}

    @app.get("/stats")
    async def stats():
        return dict(shim.stats,
                    peak_alloc_gib=round(torch.cuda.max_memory_allocated(0) / 2 ** 30, 3),
                    peak_reserved_gib=round(torch.cuda.max_memory_reserved(0) / 2 ** 30, 3),
                    cap_gib=args.max_memory_gib, attn_live=shim.live_attn,
                    zero_offload=shim.placement["zero_offload"], temperature=shim.T)

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
