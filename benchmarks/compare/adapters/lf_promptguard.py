"""Meta LlamaFirewall PromptGuard scanner (Llama Prompt Guard 2, 86M or 22M), as LlamaFirewall configures it for agents:
PromptGuard on user input (Role.USER) and on tool output (Role.TOOL). It does not inspect tool calls (that is AlignmentCheck).

Scanners recorded per event:
  pg           LlamaFirewall's own PromptGuardScanner score (its code: whitespace pre-processing, first 512 tokens), default block >= 0.9
  pg_chunked   the same model over every 512-token segment, max score: the model card's advice for long inputs ("split into
               segments and scan each"), up to MAX_CHUNKS segments (the row says when a text was longer)
On a tool-call event the call's own tool output (when the dataset has it) is scanned as Role.TOOL and recorded as pg@result.
Options: variant=86m|22m
"""
import asyncio, os

NAME = "llamafirewall-promptguard"
CACHE_VERSION = 1
MAX_CHUNKS = 16
MODELS = {"86m": "meta-llama/Llama-Prompt-Guard-2-86M", "22m": "meta-llama/Llama-Prompt-Guard-2-22M"}
cached = None   # set by run.py


def version(opts):
    import importlib.metadata as md
    from huggingface_hub import HfApi
    m = MODELS[opts.get("variant", "86m")]
    return dict(packages={p: md.version(p) for p in ("llamafirewall", "torch", "transformers")}, model=m,
                model_revision=HfApi().model_info(m).sha, default_threshold=0.9, scans=["prompt", "tool-result", "tool-call:result"])


def setup(opts):
    from llamafirewall.scanners.prompt_guard_scanner import PromptGuardScanner
    from llamafirewall.scanners import promptguard_utils as pu
    m = MODELS[opts.get("variant", "86m")]
    orig = pu.PromptGuard._load_model_and_tokenizer

    def load(self, model_name=m):  # LlamaFirewall loads 86M by default; the 22M variant is the same class with the other model id
        return orig(self, model_name=model_name)
    pu.PromptGuard._load_model_and_tokenizer = load
    sc = PromptGuardScanner()
    return dict(sc=sc, pg=sc.pg, loop=asyncio.new_event_loop(), model=m)


def _lib_score(st, text):
    from llamafirewall import UserMessage
    r = st["loop"].run_until_complete(st["sc"].scan(UserMessage(content=text)))
    return dict(score=float(r.score), decision="block" if r.decision.value == "block" else "allow")


def _chunked(st, text):
    import torch
    pg = st["pg"]; tok = pg.tokenizer
    ids = tok(text, add_special_tokens=False)["input_ids"]
    seg = 510
    parts = [ids[i:i + seg] for i in range(0, max(1, len(ids)), seg)]
    truncated = len(parts) > MAX_CHUNKS
    parts = parts[:MAX_CHUNKS]
    texts = [tok.decode(p) for p in parts] or [""]
    best = 0.0
    for t in texts:
        best = max(best, float(pg.get_jailbreak_score(text=t)))
    return dict(score=best, decision="block" if best >= 0.9 else "allow", chunks=len(texts), truncated=truncated)


def _scan_text(st, text, suffix=""):
    out = {}
    out["pg" + suffix] = cached("pg", text, lambda: _lib_score(st, text))
    out["pg_chunked" + suffix] = cached("pg_chunked", text, lambda: _chunked(st, text))
    return out


def scan(st, ev):
    if ev["kind"] in ("prompt", "result"):
        return _scan_text(st, ev["text"] or "")
    out = {"pg": dict(applicable=False, decision="allow", score=None)}
    if ev.get("result"):
        out.update(_scan_text(st, ev["result"], "@result"))
    return out
