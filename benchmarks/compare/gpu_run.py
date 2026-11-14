#!/usr/bin/env python3
"""Open-weight guard models on one GPU with vLLM (each model card's recommended serving), bf16, greedy decoding.

  python3 gpu_run.py --model llama-guard-4|granite-guardian-3.3|qwen3guard-8b --sets a,b --sides holdout [--out ~/s7c/compare/raw]
  python3 gpu_run.py --model ... --latency ~/s7c/compare/latency-sample.jsonl [--out-lat ~/s7c/compare/latency]

Placements (each model card's own; a surface the card does not document is not applicable):
  llama-guard-4         prompt classification (user turn); response classification of the agent turn = the tool call, with the
                        user's task as the user turn. All S1-S14 categories. unsafe -> block. score = P("unsafe") at the label.
  granite-guardian-3.3  non-thinking mode. Prompt: criteria jailbreak and harm (the default criteria); agent turn (tool call):
                        harm. "yes" -> block. score = P(yes) / (P(yes) + P(no)) at the score token (the card's logprob recipe).
  qwen3guard-8b         Qwen3Guard-Gen-8B. Prompt moderation of the user turn; response moderation of the agent turn (tool call).
                        Unsafe -> block, Controversial -> alert (its three-level label). score = P(Unsafe) at the label.
Tool output has no role in any of the three templates: not applicable. Rows are written in run.py's raw format, so
materialize.py, the scorer and aggregate.py treat them like every other tool. Batched generation for the runs (all distinct
inputs at once; vLLM schedules them), one request at a time for the latency figure, batched for throughput.
"""
import argparse, hashlib, json, math, os, socket, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caseview  # noqa: E402

MODELS = {"llama-guard-4": "meta-llama/Llama-Guard-4-12B", "granite-guardian-3.3": "ibm-granite/granite-guardian-3.3-8b", "qwen3guard-8b": "Qwen/Qwen3Guard-Gen-8B"}
MAX_CALL_CHARS = 8000
MAX_PROMPT_CHARS = 32000


RENDER = os.environ.get("CMP_CALL_RENDER", "text")   # text: "Tool call: X / Arguments: {...}"; json: Llama's tool-call JSON {"name", "parameters"}


def call_str(ev):
    a = ev["args"]
    if RENDER == "json":
        return json.dumps({"name": ev["tool"], "parameters": a}, ensure_ascii=False)[:MAX_CALL_CHARS]
    s = json.dumps(a, ensure_ascii=False) if not isinstance(a, str) else a
    return f"Tool call: {ev['tool']}\nArguments: {s}"[:MAX_CALL_CHARS]


MAX_TOKENS_IN = 16384 - 64


def requests_for(model, ev, tok, cap=None):
    """-> list of (scanner, prompt text) for one event; [] when the model has no placement for it. A rendered prompt over the
    model length is rendered again with the text cut to half until it fits (rows say truncated); a request is never dropped."""
    cap = cap or MAX_PROMPT_CHARS
    out = _requests(model, ev, tok, cap)
    if any(len(tok(p, add_special_tokens=False).input_ids) > MAX_TOKENS_IN for _, p in out) and cap > 500:
        return [(scn + "", p) for scn, p in requests_for(model, ev, tok, cap // 2)]
    return out


def _requests(model, ev, tok, MAX_PROMPT_CHARS):
    MAX_CALL_CHARS_ = min(MAX_CALL_CHARS, MAX_PROMPT_CHARS)
    out = []
    if ev["kind"] == "prompt":
        u = (ev["text"] or "")[:MAX_PROMPT_CHARS]
        if model == "llama-guard-4":
            out.append(("lg4", tok.apply_chat_template([{"role": "user", "content": [{"type": "text", "text": u}]}], tokenize=False, add_generation_prompt=True)))
        elif model == "granite-guardian-3.3":
            for c in ("jailbreak", "harm"):
                out.append((f"gg_{c}", tok.apply_chat_template([{"role": "user", "content": u}], guardian_config={"criteria_id": c}, think=False, tokenize=False, add_generation_prompt=True)))
        else:
            out.append(("qg", tok.apply_chat_template([{"role": "user", "content": u}], tokenize=False)))
    elif ev["kind"] == "call":
        task = ev.get("task") or "(no user message is available)"
        c = call_str(ev)[:MAX_CALL_CHARS_]
        if model == "llama-guard-4":
            out.append(("lg4", tok.apply_chat_template([{"role": "user", "content": [{"type": "text", "text": task[:MAX_PROMPT_CHARS]}]},
                                                         {"role": "assistant", "content": [{"type": "text", "text": c}]}], tokenize=False, add_generation_prompt=True)))
        elif model == "granite-guardian-3.3":
            out.append(("gg_harm", tok.apply_chat_template([{"role": "user", "content": task[:MAX_PROMPT_CHARS]}, {"role": "assistant", "content": c}],
                                                           guardian_config={"criteria_id": "harm"}, think=False, tokenize=False, add_generation_prompt=True)))
        else:
            out.append(("qg", tok.apply_chat_template([{"role": "user", "content": task[:MAX_PROMPT_CHARS]}, {"role": "assistant", "content": c}], tokenize=False)))
    return out


def label_prob(output, words):
    """At the first generated position whose token is one of `words` (case-insensitive, stripped), the probabilities of each word
    from that position's top logprobs. -> (word, {word: p})."""
    for i, tid in enumerate(output.token_ids):
        lp = output.logprobs[i] if output.logprobs else None
        if not lp:
            continue
        cand = lp.get(tid)
        t = (cand.decoded_token if cand else "").strip().lower()
        if t in words:
            ps = {}
            for x in lp.values():
                w = (x.decoded_token or "").strip().lower()
                if w in words:
                    ps[w] = ps.get(w, 0.0) + math.exp(x.logprob)
            return t, ps
    return None, {}


def parse(model, scanner, out):
    text = out.text.strip()
    if model == "llama-guard-4":
        w, ps = label_prob(out, {"safe", "unsafe"})
        lab = text.split()[0].lower() if text else ""
        return dict(score=ps.get("unsafe", 1.0 if lab == "unsafe" else 0.0), decision="block" if lab == "unsafe" else "allow", categories=text.split("\n", 1)[1].strip() if "\n" in text else "")
    if model == "granite-guardian-3.3":
        w, ps = label_prob(out, {"yes", "no"})
        import re
        m = re.findall(r"<score>(.*?)</score>", text, re.S)
        lab = (m[-1].strip().lower() if m else (w or ""))
        y, n = ps.get("yes", 0.0), ps.get("no", 0.0)
        return dict(score=y / (y + n) if y + n else (1.0 if lab == "yes" else 0.0), decision="block" if lab == "yes" else "allow")
    import re
    m = re.search(r"Safety: (Safe|Unsafe|Controversial)", text)
    lab = m.group(1) if m else ""
    w, ps = label_prob(out, {"safe", "unsafe", "controversial"})
    cats = re.findall(r"Categories: (.*)", text)
    return dict(score=ps.get("unsafe", 1.0 if lab == "Unsafe" else 0.0), score_controversial=ps.get("controversial"),
                decision={"Unsafe": "block", "Controversial": "alert"}.get(lab, "allow"), label=lab, categories=cats[0].strip() if cats else "")


LOCAL = {"llama-guard-4": os.path.expanduser("~/cmp/models/Llama-Guard-4-12B")}   # gated weights copied from the downloading host (revision 87acb4b9)


def load_llm(model, max_len):
    # greedy decoding needs no top-k/top-p kernel; vLLM's FlashInfer sampler would JIT-compile one (and its link step fails on the
    # Deep Learning AMI's CUDA 13 toolkit), so the PyTorch sampler is used. The scores and labels do not depend on the sampler.
    os.environ.setdefault("VLLM_USE_FLASHINFER_SAMPLER", "0")
    from vllm import LLM
    from transformers import AutoTokenizer
    path = LOCAL.get(model) if os.path.isdir(LOCAL.get(model, "")) else MODELS[model]
    tok = AutoTokenizer.from_pretrained(path)
    kw = dict(model=path, served_model_name=MODELS[model], dtype="bfloat16", max_model_len=max_len, gpu_memory_utilization=0.90, seed=0, enable_prefix_caching=True)
    if model == "llama-guard-4":
        kw["limit_mm_per_prompt"] = {"image": 0}
    return LLM(**kw), tok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, choices=sorted(MODELS)); ap.add_argument("--sets", default="")
    ap.add_argument("--sides", default="holdout"); ap.add_argument("--sets-dir", default=os.path.expanduser("~/s7c/compare/sets"))
    ap.add_argument("--out", default=os.path.expanduser("~/s7c/compare/raw")); ap.add_argument("--max-len", type=int, default=16384)
    ap.add_argument("--latency", default=""); ap.add_argument("--out-lat", default=os.path.expanduser("~/s7c/compare/latency"))
    a = ap.parse_args()
    from vllm import SamplingParams
    import vllm, torch
    llm, tok = load_llm(a.model, a.max_len)
    sp = SamplingParams(temperature=0.0, max_tokens=24, logprobs=20)
    ver = dict(model=MODELS[a.model], vllm=vllm.__version__, torch=torch.__version__, gpu=torch.cuda.get_device_name(0), host=socket.gethostname(),
               max_model_len=a.max_len, sampling="greedy, max_tokens 24, logprobs 20", dtype="bfloat16")
    try:
        from huggingface_hub import HfApi
        ver["model_revision"] = "87acb4b94e930c3d679e6e7ee9d57e2feab9ea71" if a.model == "llama-guard-4" else HfApi().model_info(MODELS[a.model]).sha
    except Exception:
        pass
    name = a.model + ("-" + RENDER if RENDER != "text" else "")
    od = os.path.join(a.out, name); os.makedirs(od, exist_ok=True)
    json.dump(dict(ver, name=name, call_render=RENDER, scans=["prompt", "tool-call (agent turn)"]), open(os.path.join(od, "VERSION.json"), "w"), indent=1)
    if a.latency:
        sample = [json.loads(l) for l in open(a.latency)]
        reqs = [(r, q) for r in sample for q in requests_for(a.model, r["ev"], tok)]
        prompts = [p for _, (_, p) in reqs]
        llm.generate(prompts[:10], sp, use_tqdm=False)
        per_event = {}
        for (r, (scn, p)) in reqs:      # one request in flight: the inline latency of one guardrail call
            t = time.perf_counter(); llm.generate([p], sp, use_tqdm=False); ms = (time.perf_counter() - t) * 1000
            k = (r["set"], r["case"], r["idx"]); per_event.setdefault(k, [r["ev"]["kind"], 0.0]); per_event[k][1] += ms
        lat = {}
        for kind, ms in per_event.values():
            lat.setdefault(kind, []).append(ms); lat.setdefault("all", []).append(ms)
        pct = lambda xs, q: sorted(xs)[min(len(xs) - 1, int(q * len(xs)))]
        single = {k: dict(n=len(v), p50=pct(v, .5), p95=pct(v, .95), p99=pct(v, .99), mean=sum(v) / len(v)) for k, v in lat.items()}
        t = time.perf_counter(); outs = llm.generate(prompts * 4, sp, use_tqdm=False); dt = time.perf_counter() - t
        thr = dict(requests=len(prompts) * 4, seconds=dt, requests_per_s=len(prompts) * 4 / dt, events_per_s=len(per_event) * 4 / dt, note="batched, all requests submitted at once")
        os.makedirs(a.out_lat, exist_ok=True)
        json.dump(dict(name=a.model, version=ver, single_stream_ms=single, throughput=thr, sample=a.latency, sample_events=len(per_event)),
                  open(os.path.join(a.out_lat, a.model + ".json"), "w"), indent=1)
        print(json.dumps(dict(single=single.get("all"), throughput=thr)))
        return
    for s in a.sets.split(","):
        for side in a.sides.split(","):
            t0 = time.time()
            rows, uniq = [], {}
            for l in open(os.path.join(a.sets_dir, f"{s}.{side}.cases.jsonl")):
                c = json.loads(l)
                for i, ev in enumerate(caseview.events(c)):
                    rq = requests_for(a.model, ev, tok)
                    keys = []
                    for scn, p in rq:
                        h = hashlib.sha256(p.encode()).hexdigest(); uniq[h] = p; keys.append((scn, h))
                    rows.append((c["id"], i, ev["kind"], keys))
            hs = list(uniq)
            outs = llm.generate([uniq[h] for h in hs], sp, use_tqdm=False) if hs else []
            res = {h: o.outputs[0] for h, o in zip(hs, outs)}
            ntok = {h: len(o.prompt_token_ids) for h, o in zip(hs, outs)}
            dt = time.time() - t0
            with open(os.path.join(od, f"{s}.{side}.jsonl"), "w") as f:
                for cid, i, kind, keys in rows:
                    sc = {}
                    for scn, h in keys:
                        r = parse(a.model, scn, res[h]); r.update(applicable=True, cached=False, tokens=ntok[h])
                        sc[scn] = r
                    if not keys:
                        sc["none"] = dict(applicable=False, decision="allow", score=None)
                    f.write(json.dumps(dict(case=cid, idx=i, kind=kind, scanners=sc, ms=None)) + "\n")
            print(f"[{a.model}] {s}.{side}: {len(rows)} events, {len(hs)} distinct requests, {dt:.0f}s", flush=True)


if __name__ == "__main__":
    main()
