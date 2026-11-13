"""One normalized view of a case-v1 row, shared by every adapter (stdlib only).

A case is a list of events. Each event is what an inline guardrail would see at that point of an agent run:
  kind      "prompt" (a user turn), "call" (a tool call before it runs) or "result" (a tool result before the model reads it)
  task      the user's request when the dataset carries it (payload.user_intent, else payload.content on tool-call corpora)
  history   the earlier events of the same case: [{"tool", "args", "result"}]
  tool, args, command   the call (tool name, argument object, shell command if any)
  text      the prompt text (kind prompt) or the tool result text (kind result)
  result    for a call: the result the call returned, when the dataset carries it (scanned as the next tool output)
Every tool gets exactly the same view; an adapter only changes how it renders it for its own API.

One decision row per event index is written, as the DefenseClaw harness does (s7gate.py counts rows per case), so a case is
flagged when any of its events is flagged.
"""
import json

SHELL_KEYS = ("command", "cmd", "script", "code", "commands")
CODE_TOOLS = {"python_interpreter", "execute_ipython_cell", "run_python", "python"}
EXT_LANG = {"py": "python", "js": "javascript", "ts": "typescript", "sh": "bash", "java": "java", "c": "c", "cpp": "cpp", "go": "go",
            "rs": "rust", "php": "php", "rb": "ruby", "cs": "csharp", "ps1": "powershell"}


def _result_text(r):
    if r is None:
        return None
    if isinstance(r, dict):
        if "text" in r:
            return r.get("text")
        return json.dumps(r, ensure_ascii=False)
    if isinstance(r, str):
        return r
    return json.dumps(r, ensure_ascii=False)


def _command(ev):
    if ev.get("command"):
        return ev["command"]
    a = ev.get("args")
    if isinstance(a, dict):
        for k in SHELL_KEYS:
            v = a.get(k)
            if isinstance(v, str) and v.strip():
                return v
            if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                return " ".join(v)
    return None


def surface(case):
    gs = (case.get("strata") or {}).get("guardrail_surface")
    if gs == "prompt":
        return "prompt"
    if gs == "tool-result":
        return "tool-result"
    return "tool-call"


def events(case):
    """-> list of event dicts (see module doc). The number of events equals the rows the DefenseClaw harness writes for the case."""
    p = case["payload"]
    s = surface(case)
    if s == "prompt":
        return [dict(kind="prompt", task=None, history=[], tool=None, args=None, command=None, text=p.get("content") or "", result=None)]
    task = p.get("user_intent") or p.get("prompt") or p.get("content") or None
    if s == "tool-result":
        return [dict(kind="result", task=task, history=[], tool=p.get("tool_name"), args=p.get("args"), command=_command(p),
                     text=_result_text(p.get("result") if "result" in p else p.get("event_result")) or "", result=None)]
    evs = p.get("events") or [p]
    out, hist = [], []
    for e in evs:
        res = _result_text(e.get("tool_result") if "tool_result" in e else e.get("event_result"))
        out.append(dict(kind="call", task=task, history=list(hist), tool=e.get("tool_name") or "",
                        args=e.get("args") if e.get("args") is not None else {}, command=_command(e), text=None, result=res))
        hist.append({"tool": e.get("tool_name") or "", "args": e.get("args"), "result": res})
    return out


def call_text(ev, max_chars=None):
    """A tool call as one string (tool name + JSON arguments), for text-only scanners."""
    a = ev["args"]
    s = f"{ev['tool']}({a})" if isinstance(a, str) else f"{ev['tool']}({json.dumps(a, ensure_ascii=False, sort_keys=True)})"
    return s[:max_chars] if max_chars else s


def code_of(ev):
    """(language, code) the call would run or write, for code scanners; None when the call carries no code."""
    if ev.get("command"):
        return ("python" if (ev["tool"] or "").lower() in CODE_TOOLS else "bash", ev["command"])
    a = ev["args"] if isinstance(ev["args"], dict) else {}
    for k in ("content", "file_text", "new_string", "code", "text"):
        v = a.get(k)
        if isinstance(v, str) and v.strip():
            path = str(a.get("file_path") or a.get("path") or a.get("filePath") or "")
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            lang = EXT_LANG.get(ext)
            return (lang, v) if lang else None
    return None
