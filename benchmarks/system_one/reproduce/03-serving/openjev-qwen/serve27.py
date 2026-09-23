"""Serve an Open-Jev checkpoint whose base model does not fit on one card.

Open-Jev's own loader (`jev.serving.load_predictor` -> `jev.model.DecisionModel.load`)
is used unchanged. Three things are added at the serving layer, because the 27B needs
them and a 2B/9B did not:

  1. the base model is placed across several GPUs, since the resident language-model
     backbone is 47.73 GiB against 44.4 GiB of usable L40S memory;
  2. attention runs on the `eager` path instead of the `sdpa` path hardcoded in
     `jev/model.py`, because only the eager path is covered by this programme's
     numeric-agreement gates;
  3. the `io_same_device` behaviour is re-attached to the backbone. `dispatch_model`
     puts that hook on the root `Qwen3_5ForConditionalGeneration`, but
     `DecisionModel.__init__` keeps only `full.model.language_model` and drops the
     root, so without this the last hidden state comes back on the last card while
     the scalar head and the index tensors live on the first one.

(1) and (2) are injected by wrapping `AutoModelForImageTextToText.from_pretrained` for
the duration of the load and restoring it afterwards; no Open-Jev file is edited.

`--selftest` loads, asserts placement, runs real request bodies and writes per-candidate
logits, then exits without binding a port. That is how the eager/sdpa agreement check and
the capacity measurement are taken.
"""

import argparse
import collections
import contextlib
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, "$WORK/sysone/Open-Jev")

EXPECTED_SHA256 = {
    "adapter/adapter_model.safetensors":
        "1c857224bd3609c6a71eacf7f71dd021115fcc0f791936b1fc332e915b548a81",
    "head.pt":
        "76e382f122abfa4e0c467d860a8d142d2fb6d2a98dc0ef9e19870bfc6eb296b4",
    "temperature.json":
        "185c0b85539d195d02a2d4949295f0400fc208d9eb7ac4e5e6c97ebd339a235f",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_checkpoint(checkpoint):
    """Re-verify the staged artifacts and abort on any mismatch."""
    checkpoint = Path(checkpoint)
    observed = {}
    mismatched = []
    for relative, expected in sorted(EXPECTED_SHA256.items()):
        target = checkpoint / relative
        if not target.is_file():
            mismatched.append(f"{relative}: MISSING")
            continue
        actual = sha256_file(target)
        observed[relative] = actual
        if actual != expected:
            mismatched.append(f"{relative}: expected {expected} got {actual}")
    if mismatched:
        raise SystemExit("ABORT: checkpoint checksum mismatch:\n  " + "\n  ".join(mismatched))
    print(json.dumps({"checksums_verified": observed}, indent=2, sort_keys=True), flush=True)
    return observed


@contextlib.contextmanager
def patched_loader(attn_implementation, device_map, max_memory):
    """Force eager attention and a multi-GPU placement onto Open-Jev's own load call."""
    from transformers import AutoModelForImageTextToText

    original = AutoModelForImageTextToText.from_pretrained
    captured = {}

    def wrapper(*args, **kwargs):
        kwargs["attn_implementation"] = attn_implementation
        kwargs["device_map"] = device_map
        if max_memory:
            kwargs["max_memory"] = max_memory
        captured["kwargs"] = {key: value for key, value in kwargs.items()
                              if key not in ("state_dict", "config")}
        return original(*args, **kwargs)

    AutoModelForImageTextToText.from_pretrained = wrapper
    try:
        yield captured
    finally:
        AutoModelForImageTextToText.from_pretrained = original


def attach_io_same_device(module):
    """Make the backbone return its output on the device its input arrived on."""
    from accelerate.hooks import AlignDevicesHook, add_hook_to_module

    add_hook_to_module(module, AlignDevicesHook(io_same_device=True), append=True)
    return type(module).__name__


def placement_report(model):
    """Authoritative placement audit: where the tensors actually are, right now."""
    import torch

    counts = collections.Counter()
    by_device_bytes = collections.Counter()
    offloaded_hooks = []
    for name, tensor in list(model.backbone.named_parameters()) + list(model.backbone.named_buffers()):
        device = str(tensor.device)
        counts[device] += 1
        by_device_bytes[device] += tensor.numel() * tensor.element_size()
    for name, submodule in model.backbone.named_modules():
        hook = getattr(submodule, "_hf_hook", None)
        if hook is not None and getattr(hook, "offload", False):
            offloaded_hooks.append(name or "<root>")

    head_devices = sorted({str(p.device) for p in model.head.parameters()})
    bad = sorted(device for device in counts if device.startswith(("cpu", "meta", "disk")))
    report = {
        "tensors_by_device": dict(sorted(counts.items())),
        "gib_by_device": {device: round(nbytes / 2 ** 30, 3)
                          for device, nbytes in sorted(by_device_bytes.items())},
        "head_devices": head_devices,
        "modules_with_offload_hook": offloaded_hooks,
        "cpu_or_meta_devices": bad,
        "layers_offloaded_to_cpu": counts.get("cpu", 0) + counts.get("meta", 0),
        "zero_offload": not bad and not offloaded_hooks,
    }
    report["cuda_memory"] = {}
    for index in range(torch.cuda.device_count()):
        free, total = torch.cuda.mem_get_info(index)
        report["cuda_memory"][f"cuda:{index}"] = {
            "allocated_gib": round(torch.cuda.memory_allocated(index) / 2 ** 30, 3),
            "reserved_gib": round(torch.cuda.memory_reserved(index) / 2 ** 30, 3),
            "free_mib": round(free / 2 ** 20),
            "total_mib": round(total / 2 ** 20),
        }
    return report


def build(args):
    import torch
    from jev.serving import load_predictor

    verify_checkpoint(args.checkpoint)

    visible = os.environ.get("CUDA_VISIBLE_DEVICES", "<unset>")
    count = torch.cuda.device_count()
    max_memory = None
    if args.max_memory_per_card:
        max_memory = {index: args.max_memory_per_card for index in range(count)}

    started = time.perf_counter()
    with patched_loader(args.attn, args.device_map, max_memory) as captured:
        predictor = load_predictor(checkpoint=args.checkpoint, device=args.device,
                                   max_length=args.max_length, batch_size=args.batch_size,
                                   prefix_cache=args.prefix_cache)
    load_seconds = time.perf_counter() - started

    model = predictor.scorer.model
    hooked = attach_io_same_device(model.backbone)
    # `DecisionModel.__init__` loads the full conditional-generation model and then drops
    # the vision tower, lm_head and mtp head; return those blocks to the device so a
    # neighbouring shard is not crowded by cached-but-unused segments.
    torch.cuda.empty_cache()

    # Eager attention materialises a (candidates, heads, tokens, tokens) score matrix and
    # upcasts it to float32 for the softmax. At the corpus's longest prompt that is a
    # ~7.5 GiB transient, and the caching allocator does not hand those blocks back
    # between requests, so reserved memory ratchets up and a later long prompt OOMs even
    # though no single request is too large. Release cached blocks once a request has left
    # a large unused reservation behind. Bounded, deterministic, and a function only of
    # allocator state -- not of which request happened to arrive.
    inner_predict = predictor.predict

    def predict_then_release(request):
        try:
            return inner_predict(request)
        finally:
            slack = max((torch.cuda.memory_reserved(index) - torch.cuda.memory_allocated(index))
                        for index in range(torch.cuda.device_count()))
            if slack > args.release_slack_gib * 2 ** 30:
                torch.cuda.empty_cache()

    predictor.predict = predict_then_release

    placement = placement_report(model)
    if not placement["zero_offload"]:
        raise SystemExit("ABORT: non-GPU placement detected: " + json.dumps(placement, indent=2))

    canonical = predictor.model_name
    predictor.model_name = args.name
    predictor.provenance.update(
        repo_id=args.repo_id, display_name=args.name, canonical_base_model=canonical,
        repo_revision=args.repo_revision, adapter_revision=args.repo_revision,
        attn_implementation=args.attn, dtype="bfloat16",
        device_map=args.device_map, max_memory_per_card=args.max_memory_per_card,
        cuda_visible_devices=visible, cuda_device_count=count,
        prefix_cache=bool(args.prefix_cache), io_same_device_hook_on=hooked,
        load_seconds=round(load_seconds, 1),
    )
    return predictor, model, placement, captured.get("kwargs", {})


def run_selftest(args, predictor, model, placement, load_kwargs):
    import torch

    rows = [json.loads(line) for line in open(args.selftest, encoding="utf-8") if line.strip()]
    if args.selftest_limit:
        rows = rows[:args.selftest_limit]

    results = []
    for index, row in enumerate(rows):
        for device in range(torch.cuda.device_count()):
            torch.cuda.reset_peak_memory_stats(device)
        started = time.perf_counter()
        response = predictor.predict({"state": row["state"], "questions": row["questions"]})
        elapsed = time.perf_counter() - started
        peak = {f"cuda:{d}": round(torch.cuda.max_memory_allocated(d) / 2 ** 30, 3)
                for d in range(torch.cuda.device_count())}
        results.append({
            "case_id": row.get("case_id"), "event_index": row.get("event_index"),
            "seconds": round(elapsed, 4),
            "input_tokens": response["usage"]["input_tokens"],
            "candidate_sequences": response["metadata"]["candidate_sequences"],
            "answers": response.get("answers"),
            "probabilities": response.get("probabilities"),
            "peak_allocated_gib": peak,
        })
        print(f"  [{index + 1}/{len(rows)}] {elapsed:7.3f}s "
              f"tok={response['usage']['input_tokens']:6d} "
              f"cand={response['metadata']['candidate_sequences']} peak={peak}", flush=True)

    latencies = sorted(r["seconds"] for r in results)
    # Rate must be projected against the corpus length distribution, not against whatever
    # this sample happened to contain: the corpus p50 is 494 tokens per candidate while its
    # longest is 3,464, so a tail-weighted sample overstates wall clock several-fold.
    per_token = [r["seconds"] / max(r["input_tokens"], 1) for r in results]
    summary = {
        "attn_implementation": args.attn,
        "seconds_per_input_token": {
            "mean": round(sum(per_token) / len(per_token), 8),
            "min": round(min(per_token), 8), "max": round(max(per_token), 8),
        },
        "input_tokens": {
            "mean": round(sum(r["input_tokens"] for r in results) / len(results), 1),
            "min": min(r["input_tokens"] for r in results),
            "max": max(r["input_tokens"] for r in results),
        },
        "checkpoint": args.checkpoint,
        "requests": len(results),
        "temperature": predictor.temperature,
        "method": predictor.method,
        "max_length": model.max_length,
        "batch_size": predictor.batch_size,
        "prefix_cache": bool(args.prefix_cache),
        "load_kwargs": {k: str(v) for k, v in load_kwargs.items()},
        "placement": placement,
        "latency_seconds": {
            "min": latencies[0], "p50": latencies[len(latencies) // 2],
            "max": latencies[-1],
            "mean": round(sum(latencies) / len(latencies), 4),
        },
        "single_shard_rows_per_min": round(60.0 / (sum(latencies) / len(latencies)), 2),
        "candidate_sequences_observed": sorted({r["candidate_sequences"] for r in results}),
        "results": results,
    }
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2, sort_keys=True),
          flush=True)
    if args.selftest_out:
        Path(args.selftest_out).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("wrote", args.selftest_out, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--repo-revision")
    parser.add_argument("--device", default="cuda:0",
                        help="device for inputs, the scalar head and index tensors")
    parser.add_argument("--device-map", default="balanced")
    parser.add_argument("--max-memory-per-card", default="30GiB",
                        help="per-card cap so a shard cannot crowd its neighbour")
    parser.add_argument("--attn", default="eager", choices=["eager", "sdpa"])
    parser.add_argument("--max-length", type=int)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--release-slack-gib", type=float, default=2.0,
                        help="release cached CUDA blocks once reserved-but-unused exceeds this")
    parser.add_argument("--prefix-cache", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8821)
    parser.add_argument("--provenance-out")
    parser.add_argument("--selftest", help="jsonl of {state, questions}; load, measure, exit")
    parser.add_argument("--selftest-limit", type=int, default=0)
    parser.add_argument("--selftest-out")
    args = parser.parse_args()

    predictor, model, placement, load_kwargs = build(args)

    startup = {"model": predictor.model_name, "method": predictor.method,
               "temperature": predictor.temperature, "max_length": model.max_length,
               "batch_size": predictor.batch_size, "placement": placement,
               "load_kwargs": {k: str(v) for k, v in load_kwargs.items()},
               **predictor.provenance}

    if args.selftest:
        print(json.dumps({"startup": {k: v for k, v in startup.items() if k != "placement"}},
                         indent=2, sort_keys=True), flush=True)
        print(json.dumps({"placement": placement}, indent=2, sort_keys=True), flush=True)
        run_selftest(args, predictor, model, placement, load_kwargs)
        return

    from jev.server import make_server

    server = make_server(predictor, args.host, args.port)
    startup["url"] = f"http://{args.host}:{server.server_port}"
    print(json.dumps(startup, indent=2, sort_keys=True), flush=True)
    if args.provenance_out:
        Path(args.provenance_out).write_text(
            json.dumps(startup, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
