"""Meta LlamaFirewall AlignmentCheck (experimental scanner) on every tool call, with the model LlamaFirewall uses by default
(Llama-4-Maverick-17B-128E-Instruct, there via Together; here Amazon Bedrock through llmshim.py, same weights family).

The scanner is LlamaFirewall's own AlignmentCheckScanner: its system prompt, its trace format, its output schema and its
decisions. Trace = the user's task (Role.USER), then every earlier call (Role.ASSISTANT, the JSON action format of
LlamaFirewall's AlignmentCheck examples: thought / action / action_input) and its tool output (Role.TOOL) when the dataset
has it, then the current call. A case without a user task cannot be checked (LlamaFirewall returns ALLOW with status ERROR,
"No trace provided"): recorded as not applicable. Its positive decision is HUMAN_IN_THE_LOOP_REQUIRED (LlamaFirewall never
returns BLOCK for this scanner); mapped to alert. An LLM or parse failure is LlamaFirewall's error default (conclusion True).
Options: base_url (default http://127.0.0.1:18431/v1), model (default llama4-maverick)
"""
import asyncio, json, os

NAME = "llamafirewall-alignmentcheck"
CACHE_VERSION = 1
cached = None
MAX_RESULT_CHARS = 4000   # per earlier tool output in the trace (Maverick context is large; this bounds cost, recorded in VERSION)
MAX_HISTORY = 12          # earlier calls kept (the most recent ones)


def version(opts):
    import importlib.metadata as md
    return dict(packages={p: md.version(p) for p in ("llamafirewall", "openai")}, model=opts.get("model", "llama4-maverick"),
                bedrock_model="us.meta.llama4-maverick-17b-instruct-v1:0", llamafirewall_default_model="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8 (Together)",
                max_result_chars=MAX_RESULT_CHARS, max_history=MAX_HISTORY, scans=["tool-call"], native_positive="human_in_the_loop_required -> alert")


def setup(opts):
    os.environ.setdefault("S7CMP_SHIM_KEY", "local-shim")
    os.environ.setdefault("TOGETHER_API_KEY", "unused")   # the constructor insists on it; the client is replaced below (Bedrock via llmshim)
    from llamafirewall.scanners.experimental.alignmentcheck_scanner import AlignmentCheckScanner
    from llamafirewall.utils.base_llm import LLMClient
    sc = AlignmentCheckScanner()
    sc.llm = LLMClient(model_name=opts.get("model", "llama4-maverick"), api_base_url=opts.get("base_url", "http://127.0.0.1:18431/v1"), api_key_env_var="S7CMP_SHIM_KEY")
    return dict(sc=sc, loop=asyncio.new_event_loop())


def _action(tool, args):
    return json.dumps({"thought": "", "action": tool, "action_input": args}, ensure_ascii=False, default=str)


def _run(st, ev):
    from llamafirewall import AssistantMessage, ToolMessage, UserMessage
    trace = [UserMessage(content=ev["task"])]
    for h in ev["history"][-MAX_HISTORY:]:
        trace.append(AssistantMessage(content=_action(h["tool"], h["args"])))
        if h.get("result"):
            trace.append(ToolMessage(content=h["result"][:MAX_RESULT_CHARS]))
    import time
    for attempt in range(4):
        r = st["loop"].run_until_complete(st["sc"].scan(AssistantMessage(content=_action(ev["tool"], ev["args"])), trace))
        if "Error occurred during evaluation" not in (r.reason or ""):
            break
        time.sleep(2 ** attempt)
    else:
        # LlamaFirewall's own error default is conclusion True (human in the loop). Not cached; materialize applies that default.
        return dict(score=1.0, decision="error", native="alert", err="LLM call or parse failed 4 times")
    d = r.decision.value
    return dict(score=float(r.score), decision="alert" if d == "human_in_the_loop_required" else ("block" if d == "block" else "allow"),
                status=r.status.value)


def scan(st, ev):
    if ev["kind"] != "call":
        return {"alignmentcheck": dict(applicable=False, decision="allow", score=None)}
    if not ev.get("task"):
        return {"alignmentcheck": dict(applicable=False, decision="allow", score=None, reason="no user task in the case")}
    payload = [ev["task"], [(h["tool"], h["args"], (h.get("result") or "")[:MAX_RESULT_CHARS]) for h in ev["history"][-MAX_HISTORY:]], ev["tool"], ev["args"]]
    return {"alignmentcheck": cached("alignmentcheck", payload, lambda: _run(st, ev))}
