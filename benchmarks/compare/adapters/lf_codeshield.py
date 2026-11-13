"""Meta LlamaFirewall CodeShield scanner (CodeShield insecure-code detector: regex + semgrep rules) on the code a tool call runs
or writes (shell commands, interpreter code, file writes with a code extension), as LlamaFirewall's CODING_ASSISTANT use case
does for assistant output. CodeShield's own scanner runs every supported language over the text; its decision is BLOCK on any
issue. Calls that carry no code are not applicable.
"""
import asyncio, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import caseview  # noqa: E402

NAME = "llamafirewall-codeshield"
CACHE_VERSION = 1
cached = None


def version(opts):
    import importlib.metadata as md
    return dict(packages={p: md.version(p) for p in ("llamafirewall", "codeshield", "semgrep")}, scans=["tool-call:code"])


def setup(opts):
    from llamafirewall.scanners.code_shield_scanner import CodeShieldScanner
    return dict(sc=CodeShieldScanner(), loop=asyncio.new_event_loop())


def _run(st, code):
    from llamafirewall import AssistantMessage
    r = st["loop"].run_until_complete(st["sc"].scan(AssistantMessage(content=code)))
    return dict(score=float(r.score), decision="block" if r.decision.value == "block" else "allow", issues=(r.reason or "").count("\n- "))


def scan(st, ev):
    if ev["kind"] != "call":
        return {"codeshield": dict(applicable=False, decision="allow", score=None)}
    c = caseview.code_of(ev)
    if not c:
        return {"codeshield": dict(applicable=False, decision="allow", score=None)}
    return {"codeshield": cached("codeshield", c[1], lambda: _run(st, c[1]))}
