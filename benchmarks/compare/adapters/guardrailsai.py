"""Guardrails AI with its hub validators (installed from PyPI: guardrails-ai-detect-jailbreak, guardrails-ai-secrets-present; the
Guardrails Hub monorepo packages, no hub token needed), run in-process (use_local) through Guard().use(...).validate().

  jailbreak   DetectJailbreak (known-attack embeddings + prompt-saturation detector + RoBERTa classifier, max of the three),
              default threshold 0.81, on the user prompt; jailbreak@result records it on tool output too (configs say when used)
  secrets     SecretsPresent (detect-secrets) on the user prompt, on tool-call arguments (its README: secrets in generated code)
              and on tool output
A validation failure with on_fail=exception is a block. Guardrails AI has no tool-call semantics beyond validating the
argument text, so tool calls get SecretsPresent only.
"""
import json, os

NAME = "guardrails-ai"
CACHE_VERSION = 1
cached = None


def version(opts):
    import importlib.metadata as md
    return dict(packages={p: md.version(p) for p in ("guardrails-ai", "guardrails-ai-detect-jailbreak", "guardrails-ai-secrets-present", "torch", "transformers")},
                jailbreak_default_threshold=0.81, scans=["prompt", "tool-result", "tool-call"])


def setup(opts):
    from guardrails_ai.detect_jailbreak import DetectJailbreak
    from guardrails_ai.secrets_present import SecretsPresent
    jb = DetectJailbreak(threshold=0.81, device="cpu", on_fail="exception", use_local=True)
    sp = SecretsPresent(on_fail="exception", use_local=True)
    return dict(jb=jb, sp=sp)


def _jb(st, text):
    s = float(st["jb"].predict_jailbreak([text or " "])[0])
    return dict(score=s, decision="block" if s >= 0.81 else "allow")


def _sp(st, text):
    from guardrails.classes.validation.validation_result import FailResult
    v = text if "\n" in text else text + "\n"     # the validator appends the newline itself and warns; same input
    r = st["sp"].validate(v, {})
    bad = isinstance(r, FailResult)
    return dict(score=1.0 if bad else 0.0, decision="block" if bad else "allow")


def scan(st, ev):
    if ev["kind"] == "prompt":
        t = ev["text"] or ""
        return {"jailbreak": cached("jb", t, lambda: _jb(st, t)), "secrets": cached("sp", t, lambda: _sp(st, t))}
    if ev["kind"] == "result":
        t = ev["text"] or ""
        return {"jailbreak": cached("jb", t, lambda: _jb(st, t)), "secrets": cached("sp", t, lambda: _sp(st, t))}
    a = ev["args"]
    t = ev.get("command") or (json.dumps(a, ensure_ascii=False, indent=1) if not isinstance(a, str) else a)
    out = {"secrets": cached("sp", t, lambda: _sp(st, t))}
    if ev.get("result"):
        r = ev["result"]
        out["jailbreak@result"] = cached("jb", r, lambda: _jb(st, r))
        out["secrets@result"] = cached("sp", r, lambda: _sp(st, r))
    return out
