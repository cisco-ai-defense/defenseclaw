"""ProtectAI LLM Guard input scanners on the text that enters the model: the user prompt and tool output.
LLM Guard has no tool-call scanner (its output scanners check chat text), so tool calls are not applicable.

Scanners recorded per text:
  pi        PromptInjection, deberta-v3-base-prompt-injection-v2 at LLM Guard's pinned revision, ONNX on CPU (LLM Guard's
            recommended CPU setup), MatchType FULL (the default: first 512 tokens); score = LLM Guard's own injection score
            (rounded to 2 places as its code does), default flag when score > 0.92
  pi_chunks the same with MatchType CHUNKS (LLM Guard's option for long inputs), max score
  invisible InvisibleText (Unicode tag / private-use / format characters)
  secrets   Secrets (detect-secrets plugins, LLM Guard's set)
On a tool-call event the call's own tool output is scanned and recorded with the suffix @result.
"""
import os

NAME = "llm-guard"
CACHE_VERSION = 1
cached = None


def version(opts):
    import importlib.metadata as md
    from llm_guard.input_scanners.prompt_injection import V2_MODEL
    return dict(packages={p: md.version(p) for p in ("llm-guard", "transformers", "onnxruntime", "detect-secrets") if _has(p)}, model=V2_MODEL.path,
                model_revision=V2_MODEL.revision, onnx=True, default_threshold=0.92, scans=["prompt", "tool-result", "tool-call:result"])


def _has(p):
    import importlib.metadata as md
    try:
        md.version(p); return True
    except md.PackageNotFoundError:
        return False


def setup(opts):
    from llm_guard.util import configure_logger
    configure_logger("ERROR")
    from llm_guard.input_scanners import InvisibleText, PromptInjection, Secrets
    from llm_guard.input_scanners.prompt_injection import MatchType
    onnx = opts.get("onnx", "1") == "1"
    return dict(full=PromptInjection(threshold=0.92, match_type=MatchType.FULL, use_onnx=onnx),
                chunks=PromptInjection(threshold=0.92, match_type=MatchType.CHUNKS, use_onnx=onnx),
                inv=InvisibleText(), sec=Secrets())


def _pi(sc, text):
    if not text.strip():
        return dict(score=0.0, decision="allow")
    best = 0.0
    for r in sc._pipeline(sc._match_type.get_inputs(text)):
        s = round(r["score"] if r["label"] == "INJECTION" else 1 - r["score"], 2)
        best = max(best, s)
    return dict(score=best, decision="block" if best > 0.92 else "allow")


def _flag(sc, text):
    _, valid, risk = sc.scan(text)
    return dict(score=float(risk), decision="allow" if valid else "block")


def _scan_text(st, text, suf=""):
    return {"pi" + suf: cached("pi", text, lambda: _pi(st["full"], text)),
            "pi_chunks" + suf: cached("pi_chunks", text, lambda: _pi(st["chunks"], text)),
            "invisible" + suf: cached("invisible", text, lambda: _flag(st["inv"], text)),
            "secrets" + suf: cached("secrets", text, lambda: _flag(st["sec"], text))}


def scan(st, ev):
    if ev["kind"] in ("prompt", "result"):
        return _scan_text(st, ev["text"] or "")
    out = {"pi": dict(applicable=False, decision="allow", score=None)}
    if ev.get("result"):
        out.update(_scan_text(st, ev["result"], "@result"))
    return out
