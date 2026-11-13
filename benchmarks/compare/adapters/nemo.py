"""NVIDIA NeMo Guardrails: the rails its docs list for jailbreak protection and agentic security, called through the library's
own check functions and actions with a RailsConfig built from the documented YAML (no main LLM is needed for these rails).

  prompt (input rails):  jailbreak detection heuristics (GPT-2 large perplexity: length/perplexity >= 89.79, prefix/suffix
                         perplexity >= 1845.65, the documented defaults), jailbreak detection model (NemoGuard JailbreakDetect:
                         Snowflake arctic-embed-m-long + random forest, local ONNX), context bloat detection (source input)
  tool output:           context bloat detection (source retrieval, the docs' placement for text the agent did not author);
                         jb_model@result records the JailbreakDetect model on tool output as well (an extension, configs say)
  tool call:             injection detection (YARA rules code, sqli, template, xss, action reject) on the call's arguments,
                         the docs' placement "if the LLM output is used as an argument to downstream functions"
Tool call validation / tool result validation (IORails) are structural schema checks against declared tools; the datasets
carry no tool schemas, so they are not run. Self check input/output need an application-written policy prompt: not run.
"""
import asyncio, json, os

NAME = "nemo-guardrails"
CACHE_VERSION = 1
cached = None
YAML = """
rails:
  config:
    injection_detection:
      injections: [code, sqli, template, xss]
      action: reject
    context_bloat_detection:
      action: reject
    jailbreak_detection:
      length_per_perplexity_threshold: 89.79
      prefix_suffix_perplexity_threshold: 1845.65
  input:
    flows: [jailbreak detection heuristics, jailbreak detection model, context bloat detection on input]
  output:
    flows: [injection detection]
"""


def version(opts):
    import importlib.metadata as md
    return dict(packages={p: md.version(p) for p in ("nemoguardrails", "yara-python", "onnxruntime", "transformers", "torch")}, yaml=YAML,
                models=["nvidia/NemoGuard-JailbreakDetect (snowflake.onnx)", "Snowflake/snowflake-arctic-embed-m-long", "gpt2-large"],
                scans=["prompt", "tool-result", "tool-call"])


def setup(opts):
    from nemoguardrails import RailsConfig
    cfg = None
    for y in (YAML, YAML.replace(", context bloat detection on input", "")):
        try:
            cfg = RailsConfig.from_content(yaml_content=y); break
        except Exception:
            continue
    # NemoGuard JailbreakDetect's embedder (Snowflake arctic-embed-m-long, remote code) reads `safe_serialization`, while NeMo
    # passes `use_safetensors=True`; with current transformers its loader then looks for a .bin the repo does not ship. Pass
    # both, so the documented model loads as NeMo intends (the weights are the same safetensors file).
    import transformers
    _orig = transformers.AutoModel.from_pretrained.__func__

    def _fp(cls, name, *a, **kw):
        if "snowflake-arctic-embed" in str(name):
            kw.setdefault("safe_serialization", True)
        return _orig(cls, name, *a, **kw)
    transformers.AutoModel.from_pretrained = classmethod(_fp)
    from nemoguardrails.library.jailbreak_detection.model_based.checks import initialize_model
    clf = initialize_model()
    return dict(cfg=cfg, clf=clf, loop=asyncio.new_event_loop(), heur=None)


def _heur(st, text):
    if st["heur"] is None:
        from nemoguardrails.library.jailbreak_detection.heuristics import checks
        st["heur"] = checks
    h = st["heur"]
    lp = h.check_jailbreak_length_per_perplexity(text, 89.79)
    ps = h.check_jailbreak_prefix_suffix_perplexity(text, 1845.65)
    hit = bool(lp.get("jailbreak")) or bool(ps.get("jailbreak"))
    return dict(score=1.0 if hit else 0.0, decision="block" if hit else "allow", lp=bool(lp.get("jailbreak")), ps=bool(ps.get("jailbreak")))


def _model(st, text):
    cls, sc = st["clf"](text)
    p = sc if cls else 1.0 + sc       # library score: +P(class 1) when flagged, -P(class 0) otherwise -> P(jailbreak)
    return dict(score=float(p), decision="block" if cls else "allow")


def _blocked(r):
    """RailOutcome.decision is a RailDecision (ALLOW, BLOCK, TRANSFORM); reject actions give BLOCK."""
    return "BLOCK" in str(getattr(r, "decision", "")).upper()


def _bloat(st, text, source):
    from nemoguardrails.library.context_bloat_detection.actions import context_bloat_detection
    r = st["loop"].run_until_complete(context_bloat_detection(source, text, st["cfg"]))
    blocked = _blocked(r)
    return dict(score=1.0 if blocked else 0.0, decision="block" if blocked else "allow", reason=str((getattr(r, "metadata", {}) or {}).get("reason", ""))[:60])


def _inj(st, text):
    from nemoguardrails.library.injection_detection.actions import injection_detection
    r = st["loop"].run_until_complete(injection_detection(text, st["cfg"]))
    md = getattr(r, "metadata", {}) or {}
    blocked = _blocked(r)
    return dict(score=1.0 if blocked else 0.0, decision="block" if blocked else "allow", detections=md.get("detections", []))


def _call_text(ev):
    if ev.get("command"):
        return ev["command"]
    a = ev["args"]
    if isinstance(a, dict):   # the argument values, as a downstream function would receive them
        return "\n".join(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False) for v in a.values())
    return str(a)


def scan(st, ev):
    if ev["kind"] == "prompt":
        t = ev["text"] or ""
        return {"jb_heur": cached("jb_heur", t, lambda: _heur(st, t)), "jb_model": cached("jb_model", t, lambda: _model(st, t)),
                "bloat": cached("bloat_in", t, lambda: _bloat(st, t, "input"))}
    if ev["kind"] == "result":
        t = ev["text"] or ""
        return {"bloat": cached("bloat_ret", t, lambda: _bloat(st, t, "retrieval")), "jb_model": cached("jb_model", t, lambda: _model(st, t))}
    t = _call_text(ev)
    out = {"injection": cached("injection", t, lambda: _inj(st, t))}
    if ev.get("result"):
        r = ev["result"]
        out["bloat@result"] = cached("bloat_ret", r, lambda: _bloat(st, r, "retrieval"))
        out["jb_model@result"] = cached("jb_model", r, lambda: _model(st, r))
    return out
