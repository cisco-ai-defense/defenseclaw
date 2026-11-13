"""Meta Llama Guard 4 12B (content-safety classifier, MLCommons hazard taxonomy S1-S14, all categories on, the model card's
default chat template) on the two placements its model card documents: prompt classification (the user turn) and response
classification (the agent turn; here the tool call the agent emits, with the user's task as the preceding user turn when the
dataset has one). Tool output has no Llama Guard role and is not applicable.

Recorded per event: lg4 score = P(first generated token is "unsafe"), decision = the generated label (unsafe -> block),
categories. Options: device=auto|cpu|cuda, dtype=bfloat16
"""
import json, os

NAME = "llama-guard-4"
CACHE_VERSION = 1
MODEL = "meta-llama/Llama-Guard-4-12B"
MAX_CALL_CHARS = 8000
cached = None


def version(opts):
    import importlib.metadata as md
    from huggingface_hub import HfApi
    try:
        rev = HfApi().model_info(MODEL).sha
    except Exception:
        rev = None
    return dict(packages={p: md.version(p) for p in ("transformers", "torch", "accelerate")}, model=MODEL, model_revision=rev,
                device=opts.get("device", "auto"), dtype=opts.get("dtype", "bfloat16"), scans=["prompt", "tool-call (as the agent turn)"],
                categories="S1-S14 (model default)", max_call_chars=MAX_CALL_CHARS)


def setup(opts):
    import torch
    from transformers import AutoProcessor, Llama4ForConditionalGeneration
    dev = opts.get("device", "auto")
    if dev == "auto":
        dev = "cuda" if torch.cuda.is_available() else "cpu"
    dt = getattr(torch, opts.get("dtype", "bfloat16"))
    proc = AutoProcessor.from_pretrained(MODEL)
    model = Llama4ForConditionalGeneration.from_pretrained(MODEL, torch_dtype=dt, device_map=dev)
    model.eval()
    tok = proc.tokenizer
    ids = {w: tok.encode(w, add_special_tokens=False) for w in ("safe", "unsafe")}
    return dict(proc=proc, model=model, dev=dev, ids=ids, torch=torch)


def _classify(st, messages):
    torch = st["torch"]; proc = st["proc"]; model = st["model"]
    inputs = proc.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt", return_dict=True).to(st["dev"])
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=10, do_sample=False, output_scores=True, return_dict_in_generate=True)
    gen = out.sequences[0, inputs["input_ids"].shape[-1]:]
    text = proc.tokenizer.decode(gen, skip_special_tokens=True).strip()
    score = None
    first_u, first_s = st["ids"]["unsafe"][0], st["ids"]["safe"][0]
    for step, tid in enumerate(gen.tolist()):
        if tid in (first_u, first_s):
            p = torch.softmax(out.scores[step][0].float(), dim=-1)
            score = float(p[first_u])
            break
    label = text.split()[0].lower() if text else ""
    cats = text.split("\n", 1)[1].strip() if "\n" in text else ""
    return dict(score=score if score is not None else (1.0 if label == "unsafe" else 0.0), decision="block" if label == "unsafe" else "allow",
                categories=cats, tokens=int(inputs["input_ids"].shape[-1]))


def _call_str(ev):
    a = ev["args"]
    s = json.dumps(a, ensure_ascii=False) if not isinstance(a, str) else a
    return f"Tool call: {ev['tool']}\nArguments: {s}"[:MAX_CALL_CHARS]


def scan(st, ev):
    if ev["kind"] == "prompt":
        msgs = [{"role": "user", "content": [{"type": "text", "text": ev["text"] or ""}]}]
        return {"lg4": cached("lg4", ["prompt", ev["text"]], lambda: _classify(st, msgs))}
    if ev["kind"] == "call":
        task = ev.get("task") or "(no user message is available)"
        call = _call_str(ev)
        msgs = [{"role": "user", "content": [{"type": "text", "text": task}]}, {"role": "assistant", "content": [{"type": "text", "text": call}]}]
        return {"lg4": cached("lg4", ["call", task, call], lambda: _classify(st, msgs))}
    return {"lg4": dict(applicable=False, decision="allow", score=None)}
