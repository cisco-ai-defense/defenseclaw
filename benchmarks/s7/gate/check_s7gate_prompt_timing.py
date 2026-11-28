#!/usr/bin/env python3
"""Tests for s7gate.py prompt-row latency and judge calls (lane s7-benchfix2, rel-1-0-10:GAP-0613).

  python3 -I test_s7gate_prompt_timing.py [path/to/s7gate.py]     (default: s7gate.py beside this file); exit 0 = all pass

A prompt-surface row is one call (idx 0). Before GAP-0613 the harness wrote it with lat_us 0 and no judge_calls, and s7gate would have dropped
it from the hook-latency list anyway (idx 0 = "first call carries harness start-up"). Now a timed prompt row counts like a tool call: its hook
latency is in hook_p50/p95, its judge requests are in the judge stats (count, latency, tokens, USD). A row without timing is counted apart.
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
spec = importlib.util.spec_from_loader("s7gate_t", importlib.machinery.SourceFileLoader("s7gate_t", GATE))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else ": " + detail))
    if not cond:
        fails.append(name)


def prompt_row(cid, lat_us, calls, action="alert"):
    r = {
        "case": cid,
        "idx": 0,
        "n": 1,
        "src_tool": "__prompt__",
        "tool": "UserPromptSubmit",
        "mapped": "prompt",
        "status": 200,
        "action": action,
        "raw_action": action,
        "sev": "HIGH",
        "lat_us": lat_us,
        "extra": {"scored_via": "hook"},
    }
    if calls:
        r["judge_calls"] = calls
    return r


def jc(ms, intok=800, outtok=60, err=""):
    c = {"latency_ms": ms, "parsed": not err, "in_tok": intok, "out_tok": outtok}
    if err:
        c["err"] = err
        c["cancelled"] = "cancel" in err
    return c


with tempfile.TemporaryDirectory() as d:
    rows = [
        prompt_row("a", 1_500_000, [jc(1200)]),
        prompt_row("b", 900_000, [jc(800), jc(40, err="context canceled")]),
        prompt_row("c", 3_900_000, [jc(2900, 1000, 80)]),
        prompt_row("d", 0, None, "allow"),  # d: written before GAP-0613
        prompt_row("e", 8_000, None, "allow"),
    ]  # e: rules only, timed
    with open(os.path.join(d, "alice-default.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    pred = g.load_decisions(d, "default")
    check(
        "prompt rows are scored via the hook",
        all(pred[i].get("via") == "hook" for i in "abcde"),
        str({i: pred[i].get("via") for i in "abcde"}),
    )
    check(
        "timed prompt rows count in hook_ms",
        sorted(x for i in "abce" for x in pred[i]["hook_ms"]) == [8.0, 900.0, 1500.0, 3900.0],
        str({i: pred[i]["hook_ms"] for i in "abcde"}),
    )
    check("an untimed prompt row is not a 0 ms call", pred["d"]["hook_ms"] == [] and pred["d"]["untimed_prompt"] == 1)
    check("judge calls are taken from prompt rows", [len(pred[i]["jc"]) for i in "abcde"] == [1, 2, 1, 0, 0])
    js = g.judge_stats(pred, list("abcde"), "gemma-4-31b")
    check("judge stats exist for prompt rows", js is not None)
    check(
        "hook p50/p95 are the prompt hook latencies",
        js and js["hook_p50_ms"] == 1500.0 and js["hook_p95_ms"] == 3900.0,
        str(js and (js["hook_p50_ms"], js["hook_p95_ms"])),
    )
    check(
        "hook over the answer window counted",
        js and abs(js["hook_over_window"] - 1 / 4) < 1e-9,
        str(js and js["hook_over_window"]),
    )
    check(
        "judge count, cut and answered",
        js and js["judge_calls"] == 4 and js["cut_at_window"] == 1 and js["answered"] == 3,
        str(js),
    )
    check(
        "tokens and USD come from the calls",
        js and js["in_tok_avg"] == (800 + 800 + 1000) / 3 and js["usd"] > 0,
        str(js and (js["in_tok_avg"], js["usd"])),
    )
    check(
        "per call rate uses the prompt rows",
        js and abs(js["per_tool_call"] - 4 / 5) < 1e-9,
        str(js and js["per_tool_call"]),
    )
    check(
        "the untimed prompt row is reported",
        js and js["prompt_rows_untimed"] == 1,
        str(js and js.get("prompt_rows_untimed")),
    )
    # tool-call rows keep the old rule: idx 0 carries harness start-up and is left out.
    with open(os.path.join(d, "alice-default.jsonl"), "w") as f:
        for i in range(3):
            f.write(
                json.dumps(
                    {
                        "case": "t",
                        "idx": i,
                        "n": 3,
                        "mapped": "shell",
                        "status": 200,
                        "action": "allow",
                        "raw_action": "allow",
                        "lat_us": 5000 * (i + 1),
                    }
                )
                + "\n"
            )
    tp = g.load_decisions(d, "default")
    check("tool-call rows still skip idx 0", tp["t"]["hook_ms"] == [10.0, 15.0], str(tp["t"]["hook_ms"]))
    check("tool-call rows have no untimed prompts", tp["t"]["untimed_prompt"] == 0)
print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
