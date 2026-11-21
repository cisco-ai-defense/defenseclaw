#!/usr/bin/env python3
"""Tests for s7gate.py judge cost and prompt attribution (lane s7-benchfix3, rel-1-0-10:GAP-0649, GAP-0650, and the P4 label).

  python3 -I test_s7gate_judgecost.py [path/to/s7gate.py]     (default: s7gate.py beside this file); exit 0 = all pass

GAP-0649: the judge USD was priced on the calls that came back with usage only; the tokens of cut and failed calls were dropped. Now both are
reported side by side: answered-only (as before) and all-sent (every request that went to a model). A cut or failed call carries no usage, so the harness
records the size of each request (req_chars) and the scorer prices an unanswered call at that size (output counted as 0, a lower bound); the s7proxy log
of the run gives the exact figure for the whole run.
GAP-0650: in a tool-call run with -prompt-from-content the opening UserPromptSubmit's judge calls are the prompt's own line (prompt_judge_calls,
prompt_lat_us on the idx 0 row), not the first tool call's.
Synthetic rows only.
"""

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "s7gate.py")
sys.argv = [GATE]
spec = importlib.util.spec_from_loader("s7gate_t", importlib.machinery.SourceFileLoader("s7gate_t", GATE))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
fails = []
M = "gemma-4-31b"
PI, PO = g.JUDGE_PRICE[M]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else ": " + detail))
    if not cond:
        fails.append(name)


def near(a, b, tol=1e-9):
    return abs(a - b) <= tol


def ok(intok=1000, outtok=100, chars=3000, ms=900):
    return {"latency_ms": ms, "parsed": True, "in_tok": intok, "out_tok": outtok, "req_chars": chars}


def cut(chars=3300, ms=3400, intok=0, outtok=0):
    c = {"latency_ms": ms, "err": "context deadline exceeded", "parsed": False, "cancelled": True, "req_chars": chars}
    if intok:
        c["in_tok"] = intok
    if outtok:
        c["out_tok"] = outtok
    return c


def refused():
    return {"latency_ms": 2, "err": "OpenAI returned 503: cache-only: miss refused", "parsed": False, "req_chars": 3000}


def http_err():
    return {"latency_ms": 30, "err": "OpenAI returned 429: slow down", "parsed": False, "req_chars": 3000}


def reset():
    return {"latency_ms": 50, "err": "connection reset by peer", "parsed": False, "req_chars": 2400}


# 1. call classes
check("class answered", g.judge_call_class(ok()) == "answered")
check("class cut by deadline", g.judge_call_class(cut()) == "cut")
check("class cut by a provider-side deadline", g.judge_call_class({"err": "context deadline exceeded"}) == "cut")
check("class cut by cancel text", g.judge_call_class({"err": "context canceled"}) == "cut")
check("class refused", g.judge_call_class(refused()) == "refused")
check("class rejected http", g.judge_call_class(http_err()) == "rejected")
check("class failed in transport", g.judge_call_class(reset()) == "failed")

# 2. judge_cost: answered-only vs all-sent
calls = [ok(), ok(1200, 120, 3600), ok(800, 80, 2400), cut(3300), reset(), refused(), http_err()]
c = g.judge_cost(calls, M)
cpt = (3000 + 3600 + 2400) / (1000 + 1200 + 800)  # 3.0 chars per token, from the answered calls
est = 3300 / cpt + 2400 / cpt
check(
    "counts by class",
    (c["calls"], c["answered"], c["cut"], c["failed_in_transport"], c["refused_not_sent"], c["rejected_http"])
    == (7, 3, 1, 1, 1, 1),
    str(c),
)
check(
    "answered-only tokens and USD",
    c["answered_in_tok"] == 3000
    and c["answered_out_tok"] == 300
    and near(c["usd_answered"], (3000 * PI + 300 * PO) / 1e6),
    str(c),
)
a = c["all_sent"]
check("all-sent counts the cut and the failed, not the refused or the HTTP error", a["calls"] == 5, str(a))
check(
    "all-sent input = answered usage + request-size estimate",
    a["in_tok"] == round(3000 + est) and a["in_tok_estimated"] == round(est),
    str(a),
)
check("all-sent output is the answered output (unanswered counted as 0)", a["out_tok"] == 300, str(a))
check(
    "all-sent USD above answered-only",
    a["usd"] > c["usd_answered"] and near(a["usd"], ((3000 + est) * PI + 300 * PO) / 1e6),
    str(a),
)
check("all-sent says how it is priced", "lower bound" in a["basis"] and "refused" in a["basis"], a["basis"])
# a recorded usage on a cut call (the proxy or a newer harness) is used as is, never re-estimated
c2 = g.judge_cost([ok(), cut(3300, intok=1100, outtok=900)], M)
check(
    "a cut call with recorded usage is priced exactly",
    c2["all_sent"]["in_tok"] == 2100 and c2["all_sent"]["out_tok"] == 1000 and c2["all_sent"]["in_tok_estimated"] == 0,
    str(c2["all_sent"]),
)
# a run from before the harness recorded sizes: the call cannot be priced and says so
c3 = g.judge_cost([ok(), {"err": "context deadline exceeded", "cancelled": True, "latency_ms": 3400}], M)
check(
    "a sent call with no size and no usage is counted, not priced",
    c3["all_sent"]["unpriced_calls"] == 1 and c3["all_sent"]["in_tok"] == 1000,
    str(c3["all_sent"]),
)
check(
    "no answered call to calibrate: the fallback ratio is used",
    near(g.judge_cost([cut(3000)], M)["all_sent"]["chars_per_token"], g.FALLBACK_CHARS_PER_TOKEN),
)


# 3. judge_stats keeps the old figures and adds the all-sent ones
def row(case, idx, n, calls=None, lat=5000, **kw):
    r = {
        "case": case,
        "idx": idx,
        "n": n,
        "mapped": "shell",
        "status": 200,
        "action": "allow",
        "raw_action": "allow",
        "lat_us": lat,
    }
    if calls:
        r["judge_calls"] = calls
    r.update(kw)
    return r


with tempfile.TemporaryDirectory() as d:
    rows = [
        row("a", 0, 2, [ok(), cut()], 9000),
        row("a", 1, 2, [ok(900, 70, 2700)]),
        row("b", 0, 1, [ok(), reset()], 9000),
    ]
    with open(os.path.join(d, "alice-default.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    pred = g.load_decisions(d, "default")
    js = g.judge_stats(pred, ["a", "b"], M)
    check("old keys unchanged: counts", js["judge_calls"] == 5, str(js["judge_calls"]))
    check(
        "old keys unchanged: answered-only USD",
        near(js["usd"], ((1000 + 900 + 1000) * PI + (100 + 70 + 100) * PO) / 1e6) and js["answered"] == 3,
        str((js["usd"], js["answered"])),
    )
    check(
        "all-sent beside it, per 1k tool calls",
        js["all_sent"]["usd"] > js["usd"]
        and near(js["all_sent"]["usd_per_1k_tool_calls"], js["all_sent"]["usd"] / 3 * 1000),
        str(js["all_sent"]),
    )
    check(
        "answered tokens exposed for run totals",
        js["answered_in_tok"] == 2900 and js["answered_out_tok"] == 270,
        str((js["answered_in_tok"], js["answered_out_tok"])),
    )
    line = g.judge_line(M, js)
    check("summary line shows both costs", "answered-only" in line and "all-sent" in line, line)

    # 4. P4: the 3.4 s share is labelled as the tool-call window
    check(
        "hook share is labelled with its window",
        "tool-call answer window" in js["hook_over_window_basis"] and "3400" in js["hook_over_window_basis"],
        js["hook_over_window_basis"],
    )
    check("summary line labels the share", "over 3.4 s (the tool-call window)" in line, line)
    pj = g.prompt_from_content_of({"harness_args": "-strategy,regex_judge,-prompt-from-content"})
    check(
        "prompt-from-content is read from the run's harness args",
        pj is True
        and g.prompt_from_content_of({"harness_args": "-strategy,regex_judge"}) is False
        and g.prompt_from_content_of(None) is False,
    )

    # 5. GAP-0650: the opening prompt is its own line
    rows = [
        row("a", 0, 2, [ok(900, 60, 2700)], 9000, prompt_judge_calls=[ok(), ok(), cut()], prompt_lat_us=4_200_000),
        row("a", 1, 2, None),
        row("b", 0, 1, None, 9000, prompt_judge_calls=[ok(), ok(1100, 90, 3300), ok()], prompt_lat_us=1_100_000),
        row("c", 0, 1, [ok(700, 50, 2100)], 9000),
    ]  # c: no opening prompt
    with open(os.path.join(d, "alice-default.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    pred = g.load_decisions(d, "default")
    check(
        "prompt calls are kept apart from the tool calls",
        len(pred["a"]["jc"]) == 1
        and len(pred["a"]["pjc"]) == 3
        and pred["a"]["prompted"] == 1
        and pred["c"]["pjc"] == [],
        str({k: (len(v["jc"]), len(v["pjc"]), v["prompted"]) for k, v in pred.items()}),
    )
    check("prompt latency is not a tool-call latency", pred["a"]["hook_ms"] == [5.0], str(pred["a"]["hook_ms"]))
    js = g.judge_stats(pred, ["a", "b", "c"], M, True)
    check(
        "per tool call counts the tool calls' own requests only",
        js["judge_calls"] == 2 and near(js["per_tool_call"], 2 / 4),
        str((js["judge_calls"], js["per_tool_call"])),
    )
    pc = js.get("prompt_cost")
    check(
        "prompt cost has its own line",
        pc and pc["sessions"] == 2 and pc["judge_calls"] == 6 and near(pc["per_session"], 3.0),
        str(pc),
    )
    check(
        "prompt cost: answered-only and all-sent side by side",
        pc
        and pc["usd_all_sent"] > pc["usd_answered"]
        and near(pc["usd_per_1k_sessions_all_sent"], pc["usd_all_sent"] / 2 * 1000),
        str(pc),
    )
    check("prompt hook latency of its own", pc and pc["hook_p50_ms"] in (1100.0, 4200.0), str(pc and pc["hook_p50_ms"]))
    check("a run with separated prompts is not flagged legacy", "prompt_calls_in_idx0_rows_legacy" not in js)
    check("summary line carries the prompt line", "prompt cost own line" in g.judge_line(M, js), g.judge_line(M, js))

    # 6. a run made before the harness separated the prompt: said so, and the rate with idx 0 left out is given
    rows = [
        row("x", 0, 3, [ok(), ok(), ok(), ok(950, 80, 2850)], 9000),
        row("x", 1, 3, [ok(600, 40, 1800)]),
        row("x", 2, 3, None),
        row("y", 0, 2, [ok(), ok(), ok()], 9000),
        row("y", 1, 2, None),
    ]
    with open(os.path.join(d, "alice-default.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    pred = g.load_decisions(d, "default")
    js = g.judge_stats(pred, ["x", "y"], M, True)
    check(
        "legacy run flagged",
        js.get("prompt_calls_in_idx0_rows_legacy") is True and "GAP-0650" in js["legacy_note"],
        str(js.get("legacy_note")),
    )
    check(
        "legacy: idx 0 rows and their calls counted",
        js["idx0_rows"] == 2 and js["idx0_judge_calls"] == 7 and js["judge_calls_after_idx0"] == 1,
        str((js["idx0_rows"], js["idx0_judge_calls"], js["judge_calls_after_idx0"])),
    )
    check(
        "legacy: the per-call rate after idx 0 is exact",
        near(js["per_call_after_idx0"], 1 / 3),
        str(js["per_call_after_idx0"]),
    )
    check("legacy: summary says so", "inside the idx-0 rows" in g.judge_line(M, js), g.judge_line(M, js))
    js2 = g.judge_stats(pred, ["x", "y"], M, False)
    check("not flagged when the run had no -prompt-from-content", "prompt_calls_in_idx0_rows_legacy" not in js2)

# 7. the proxy log: exact run-level tokens, refused and aborted lines apart
with tempfile.TemporaryDirectory() as d:
    lines = [
        {"ts": 1, "kind": "judge", "model": "gemma-4-31b", "cache_hit": True, "in_tok": 1000, "out_tok": 100},
        {"ts": 2, "kind": "judge", "model": "gemma-4-31b", "cache_hit": False, "in_tok": 1500, "out_tok": 1024},
        {"ts": 3, "kind": "judge", "model": "gemma-4-31b", "key": "k", "cache_miss_refused": True},
        {"ts": 4, "error": "BrokenPipeError: [Errno 32] Broken pipe", "path": "/v1/chat/completions"},
        {"ts": 5, "error": "ValueError: boom", "path": "/v1/chat/completions"},
    ]
    pp = os.path.join(d, "calls.jsonl")
    open(pp, "w").write("\n".join(json.dumps(x) for x in lines) + "\nnot json\n")
    px = g.proxy_totals(pp, M)
    check(
        "proxy totals",
        px["requests"] == 2
        and px["cache_hits"] == 1
        and px["in_tok"] == 2500
        and px["out_tok"] == 1124
        and px["refused_not_sent"] == 1
        and px["client_abort_records"] == 1
        and px["other_error_records"] == 1,
        str(px),
    )
    check("proxy USD at the list price", near(px["usd"], (2500 * PI + 1124 * PO) / 1e6), str(px))
    # run-level report: answered-only, all-sent by the harness record, all-sent by the proxy, side by side, written to judge_cost.json
    js = g.judge_stats(
        {"a": dict(n=1, jc=[ok(), cut()], hook_ms=[], untimed_prompt=0, pjc=[], prompted=0, prompt_ms=[], jc0=0, n0=0)},
        ["a"],
        M,
    )
    lines2 = g.judge_cost_report(d, [("corp", "default", js)], pp, M)
    rep = json.load(open(os.path.join(d, "judge_cost.json")))
    check(
        "report has the three figures",
        rep["answered_only"]["usd"] > 0
        and rep["all_sent_harness"]["usd"] > rep["answered_only"]["usd"]
        and rep["all_sent_proxy"]["requests"] == 2,
        json.dumps(rep)[:400],
    )
    check(
        "report lines name all three",
        "answered-only" in lines2[0]
        and "all-sent by the harness record" in lines2[0]
        and "all-sent by the proxy log" in lines2[0],
        lines2[0],
    )
    check("no cells, no report", g.judge_cost_report(d, [], pp, M) == [])

print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
