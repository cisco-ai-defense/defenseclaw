#!/usr/bin/env python3
"""Serve jaredpalmer/kev-9b on the DefenseClaw System One /v1/systemone contract.

kev.serve's own request path is reused verbatim (kev.api.to_record/to_answers, Server.answer,
DecisionModel.probs), so the readout is the shipped one. What this shim controls:

  * placement: kev's loader takes a single `device` and would put 9.7B on one card. The backbone
    is merged on CPU in fp32 (the shipped default: exact), cast to bf16, then dispatched across
    two cards with a hard per-card cap. Zero cpu/meta/disk offload is asserted before serving.
  * KEV_DTYPE/KEV_ATTN/KEV_PREFIX_CACHE are pinned to bf16 / eager / off and asserted live.
  * probabilities at full float precision (kev.api.round_prob rounds to 4 dp, which would
    quantise the ranking variable far below the other arms on this board).
"""
import argparse, json, os, sys, hashlib, time

# must be set before kev.serve is imported: it reads these at module scope
os.environ.setdefault("KEV_PREFIX_CACHE", "0")     # 0 disables the state-prefix cache entirely
os.environ.setdefault("KEV_DATE_FACTS", "0")      # preprocessing is reported separately upstream; not enabled
os.environ.pop("KEV_API_KEY", None)

import torch


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def placement_report(module):
    counts, offenders, pdt, bdt = {}, [], {}, {}
    params = dict(module.named_parameters())
    for name, t in list(module.named_parameters()) + list(module.named_buffers()):
        counts[t.device.type] = counts.get(t.device.type, 0) + 1
        if t.device.type != "cuda":
            offenders.append(f"{name}:{t.device.type}")
        if t.is_floating_point():
            (pdt if name in params else bdt)[str(t.dtype)] = \
                (pdt if name in params else bdt).get(str(t.dtype), 0) + 1
    hooks = []
    for name, sub in module.named_modules():
        h = getattr(sub, "_hf_hook", None)
        if h is not None and getattr(h, "offload", False):
            hooks.append(name or "<root>")
    by_dev = {}
    for name, t in module.named_parameters():
        by_dev[str(t.device)] = by_dev.get(str(t.device), 0) + t.numel() * t.element_size()
    return {"devices": counts, "parameter_float_dtypes": pdt, "buffer_float_dtypes": bdt,
            "tensors_not_on_cuda": offenders[:20], "n_tensors_not_on_cuda": len(offenders),
            "modules_with_offload_hook": hooks, "zero_offload": not offenders and not hooks,
            "param_bytes_per_device": {k: round(v / 2 ** 30, 3) for k, v in sorted(by_dev.items())}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--kev-src", required=True)
    p.add_argument("--adapter-path", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--repo-id", required=True)
    p.add_argument("--repo-revision", required=True)
    p.add_argument("--attn", default="eager")
    p.add_argument("--max-memory-gib", type=float, required=True,
                   help="hard allocator cap PER CARD (weights + activations)")
    p.add_argument("--rows-per-forward", type=int, default=1,
                   help="causal rows per forward pass; 1 removes padding and makes each answer "
                        "independent of batch grouping")
    p.add_argument("--weights-budget-gib", type=float, required=True,
                   help="per-card budget offered to infer_auto_device_map for WEIGHTS only; must "
                        "leave the difference to --max-memory-gib free for activations")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--release-slack-gib", type=float, default=2.0)
    p.add_argument("--provenance-out")
    p.add_argument("--selftest")
    p.add_argument("--selftest-limit", type=int, default=0)
    p.add_argument("--selftest-out")
    args = p.parse_args()

    sys.path.insert(0, args.kev_src)
    n_cards = torch.cuda.device_count()
    if n_cards < 2:
        raise SystemExit(f"ABORT: need 2 visible cards to shard 9.7B, see {n_cards}")
    cap = int(args.max_memory_gib * (1 << 30))
    for i in range(n_cards):
        total = torch.cuda.get_device_properties(i).total_memory
        if cap >= total:
            raise SystemExit(f"ABORT: cap >= card {i} total; refusing to take whatever is free")
        torch.cuda.set_per_process_memory_fraction(cap / total, i)

    if args.weights_budget_gib >= args.max_memory_gib:
        raise SystemExit("ABORT: weights budget must leave headroom under the allocator cap")

    from kev.checkpoint import read_meta
    from kev.model import DecisionModel, load_tokenizer
    from peft import PeftModel

    meta = read_meta(args.adapter_path)
    tok = load_tokenizer(meta.base, revision=meta.base_revision)

    t0 = time.perf_counter()
    # fp32 on CPU -> merge (exact) -> bf16. Never materialises fp32 on a card.
    m = DecisionModel(meta.base, tok, "cpu", lora=None, revision=meta.base_revision,
                      head_dim=meta.head_dim, option_isolation=meta.option_isolation,
                      dtype=torch.float32, attn=args.attn)
    m.lm = PeftModel.from_pretrained(m.lm, args.adapter_path, torch_device="cpu").to("cpu")
    merged = True
    m.lm = m.lm.merge_and_unload()
    m.lm = m.lm.to(torch.bfloat16)
    m.head.load_state_dict(meta.head)
    m.eval()
    m.head.temperature = meta.temperature

    from accelerate import dispatch_model, infer_auto_device_map
    from accelerate.hooks import AlignDevicesHook, add_hook_to_module
    no_split = getattr(m.lm, "_no_split_modules", None) or []
    # max_memory budgets WEIGHTS only; accelerate will happily fill the allocator cap with
    # parameters and leave nothing for the eager attention transient. Keep the two separate.
    dmap = infer_auto_device_map(
        m.lm, max_memory={i: f"{args.weights_budget_gib}GiB" for i in range(n_cards)},
        dtype=torch.bfloat16, no_split_module_classes=list(no_split))
    bad = {k: v for k, v in dmap.items() if v in ("cpu", "disk") or v == "meta"}
    if bad:
        raise SystemExit("ABORT: device_map would offload to cpu/disk: " + json.dumps(bad, indent=2))
    m.lm = dispatch_model(m.lm, device_map=dmap)
    add_hook_to_module(m.lm, AlignDevicesHook(io_same_device=True), append=True)
    m.head.to("cuda:0")
    m.device = "cuda:0"
    load_s = round(time.perf_counter() - t0, 1)

    placement = placement_report(m.lm)
    hp = placement_report(m.head)
    if not placement["zero_offload"] or not hp["zero_offload"]:
        raise SystemExit("ABORT: offload detected: " + json.dumps({"backbone": placement, "head": hp}, indent=2))
    badp = [d for d in placement["parameter_float_dtypes"] if d != "torch.bfloat16"]
    if badp:
        raise SystemExit(f"ABORT: non-bf16 backbone parameter dtypes {badp}")
    live_attn = getattr(m.lm.config, "_attn_implementation", None)
    if live_attn != args.attn:
        raise SystemExit(f"ABORT: attn_implementation is {live_attn!r}, expected {args.attn!r}")
    if float(m.head.temperature) != float(meta.temperature):
        raise SystemExit("ABORT: head temperature not the checkpoint's fitted value")

    # One causal row per forward. kev builds one row per question and batches them; the eager
    # attention transient scales with that batch, and (as measured on decider-2b) bf16 kernels
    # give slightly different reductions per batch shape. Rows are independent by construction
    # (DecisionModel.forward_rows_batch docstring), so chunking changes no probability and with
    # a chunk of 1 there is no padding at all.
    if args.rows_per_forward:
        _orig_rows_hidden = m._rows_hidden
        _ch = int(args.rows_per_forward)

        def _chunked_rows_hidden(rows, *a, **kw):
            out = []
            for i in range(0, len(rows), _ch):
                out.extend(_orig_rows_hidden(rows[i:i + _ch], *a, **kw))
            return out
        m._rows_hidden = _chunked_rows_hidden

    import kev.serve as KS
    import kev.api as KA
    if KS.PREFIX_CACHE_SIZE != 0:
        raise SystemExit(f"ABORT: prefix cache size {KS.PREFIX_CACHE_SIZE}, expected 0")
    if KS.DATE_FACTS:
        raise SystemExit("ABORT: KEV_DATE_FACTS is on")
    KA.round_prob = lambda x: float(x)          # full precision, as the rest of this board records

    from kev.checkpoint import Checkpoint
    ckpt = Checkpoint(args.adapter_path)
    server = KS.Server(checkpoint=ckpt, tok=tok, model=m, device="cuda:0")
    KS.app.state.server = server

    inner = server.probs

    def probs_then_release(rec):
        try:
            return inner(rec)
        finally:
            slack = max(torch.cuda.memory_reserved(i) - torch.cuda.memory_allocated(i)
                        for i in range(n_cards))
            if slack > args.release_slack_gib * 2 ** 30:
                torch.cuda.empty_cache()
    server.probs = probs_then_release

    prov = {
        "weights_budget_gib_per_card": args.weights_budget_gib,
        "rows_per_forward": args.rows_per_forward,
        "name": args.name, "repo_id": args.repo_id, "repo_revision": args.repo_revision,
        "base_model": meta.base, "base_revision": meta.base_revision,
        "architecture": f"LoRA r{meta.lora} (alpha {2 * meta.lora}) on attention/MLP/DeltaNet projections + pointer head (head_dim {meta.head_dim})",
        "lora_merged_into_base": merged, "merge_precision": "fp32 on CPU, then cast to bf16",
        "dtype": "bfloat16", "attn_implementation_live": live_attn,
        "prefix_cache": False, "prefix_cache_size": KS.PREFIX_CACHE_SIZE,
        "date_facts_preprocessor": KS.DATE_FACTS,
        "temperature_applied": float(m.head.temperature),
        "temperature_source": "head.pt:temperature (fitted by scripts/calibrate_checkpoint.py)",
        "max_memory_gib_cap_per_card": args.max_memory_gib,
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "device_map_devices": sorted({str(v) for v in dmap.values()}),
        "placement_backbone": placement, "placement_head": hp,
        "load_seconds": load_s, "torch": torch.__version__,
        "adapter_sha256": sha256_file(os.path.join(args.adapter_path, "adapter_model.safetensors")),
        "head_sha256": sha256_file(os.path.join(args.adapter_path, "head.pt")),
        "hybrid_backbone": bool(m.hybrid),
        "option_isolation": bool(meta.option_isolation),
        "probabilities_precision": "full float (kev.api.round_prob patched to identity)",
        "peak_alloc_gib_after_load": {i: round(torch.cuda.max_memory_allocated(i) / 2 ** 30, 3) for i in range(n_cards)},
    }
    import transformers, peft
    prov["transformers"], prov["peft"] = transformers.__version__, peft.__version__
    prov["checkpoint_sha256"] = hashlib.sha256(
        (prov["adapter_sha256"] + prov["head_sha256"]).encode()).hexdigest()
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
            req = KA.SystemOneRequest(model=args.name, state=r["state"], questions=r["questions"])
            res = server.answer(req)
            out.append({"case_id": r.get("case_id"), "event_index": r.get("event_index"),
                        "ms": round((time.time() - s) * 1000, 2), "answers": res["answers"],
                        "usage": res["usage"]})
        el = time.time() - t0
        rep = {"n": len(out), "elapsed_s": round(el, 2),
               "rows_per_s": round(len(out) / el, 4) if el else None,
               "peak_alloc_gib": {i: round(torch.cuda.max_memory_allocated(i) / 2 ** 30, 3) for i in range(n_cards)},
               "peak_reserved_gib": {i: round(torch.cuda.max_memory_reserved(i) / 2 ** 30, 3) for i in range(n_cards)},
               "cap_gib_per_card": args.max_memory_gib,
               "prefix_hits": server.prefix_hits, "prefix_misses": server.prefix_misses,
               "attn_live": live_attn, "temperature": float(m.head.temperature),
               "zero_offload": placement["zero_offload"],
               "param_bytes_per_device": placement["param_bytes_per_device"], "results": out}
        print(json.dumps({k: v for k, v in rep.items() if k != "results"}, indent=2), flush=True)
        if args.selftest_out:
            with open(args.selftest_out, "w") as fh:
                json.dump(rep, fh, indent=2)
        return 0

    @KS.app.get("/stats")
    async def stats():
        return {"prefix_cache_size": KS.PREFIX_CACHE_SIZE,
                "prefix_hits": server.prefix_hits, "prefix_misses": server.prefix_misses,
                "attn_live": live_attn, "temperature": float(m.head.temperature),
                "zero_offload": placement["zero_offload"],
                "cap_gib_per_card": args.max_memory_gib,
                "peak_reserved_gib": {i: round(torch.cuda.max_memory_reserved(i) / 2 ** 30, 3) for i in range(n_cards)}}

    @KS.app.get("/health")
    async def health():
        return {"ok": True, "model": args.name}

    import uvicorn
    uvicorn.run(KS.app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
