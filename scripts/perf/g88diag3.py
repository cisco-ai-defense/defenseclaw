"""GAP-0088 diagnosis 3 (diagnostic branch only, never merged).

100 idle Claude Code calls right after the provision step, as dcperf does.
Mode plain: no tracing; mode strace: the guard leg runs under strace -f -ttt
(execve, connect, sendto/write, recvfrom/read, exit_group), and the trace of
every call over 110 ms is kept. After the calls the gateway's own time per
call (connector-hook elapsed_ms) is read from the audit store and matched to
the calls in order.
"""
import json, os, sqlite3, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dcperf as dp


def timed_call(inst, env, argvs, data, trace):
    t0 = time.perf_counter()
    procs = []
    for i, a in enumerate(argvs):
        if trace and i == 0:
            a = ["strace", "-f", "-ttt", "-qq", "-e",
                 "trace=execve,connect,sendto,write,recvfrom,read,exit_group,wait4", "-s", "0", "-o", trace] + a
        procs.append(subprocess.Popen(a, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=env, cwd=str(inst.work)))
    ends = [0.0] * len(procs)

    def talk(i):
        procs[i].communicate(data, timeout=60)
        ends[i] = (time.perf_counter() - t0) * 1000

    th = [threading.Thread(target=talk, args=(i,)) for i in range(len(procs))]
    [t.start() for t in th]
    [t.join() for t in th]
    return [round(e, 1) for e in ends]


def summarize_trace(path, start):
    """Key moments of the guard leg in ms since the call started."""
    marks = []
    for line in Path(path).read_text(errors="replace").splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, ts, rest = parts
        try:
            t = (float(ts) - start) * 1000
        except ValueError:
            continue
        name = rest.split("(", 1)[0]
        if name in ("execve", "connect", "exit_group") or (name in ("sendto", "write", "recvfrom", "read") and "= -1 EAGAIN" not in rest):
            if name in ("read", "write") and not any(k in rest for k in ("(3,", "(4,", "(5,", "(6,", "(7,", "(8,")):
                continue
            marks.append([round(t, 1), pid, name, rest[len(name):len(name) + 60]])
    return marks[:80]


def main():
    home, out, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    inst = dp.Install(home.resolve())
    env = inst.env()
    argvs = dp.registered_hooks(inst, "claudecode")
    session = f"g88-{time.monotonic_ns()}"
    calls = []
    for k in range(103):
        data = dp.hook_payload("claudecode", inst.work, session)
        trace = None
        if mode == "strace":
            trace = tempfile.mktemp(prefix="g88-trace-")
        wall = time.time()
        at = time.monotonic() - dp.RUN_STARTED
        legs = timed_call(inst, env, argvs, data, trace)
        rec = dict(k=k, at_s=round(at, 3), wall=wall, legs=legs)
        if trace:
            if max(legs) > 110:
                rec["trace"] = summarize_trace(trace, wall)
            os.unlink(trace)
        calls.append(rec)
    db = sqlite3.connect(f"file:{inst.dc / 'audit.db'}?mode=ro", uri=True)
    rows = db.execute("SELECT timestamp, structured_json FROM audit_events WHERE action = ? ORDER BY timestamp", ("connector-hook",)).fetchall()
    gw = []
    for ts, sj in rows:
        try:
            d = json.loads(sj or "{}")
        except ValueError:
            continue
        if d.get("event") == "PreToolUse":
            gw.append([ts, d.get("elapsed_ms")])
    for c, g in zip(calls, gw[-len(calls):]):
        c["gw_ts"], c["gw_ms"] = g
    ms = sorted(max(c["legs"]) for c in calls[3:])
    print(mode, "p50/p95/max", ms[len(ms) // 2], ms[int(len(ms) * 0.95)], ms[-1], "gateway rows", len(gw), flush=True)
    for c in calls[3:]:
        if max(c["legs"]) > 110:
            print("slow", c["k"], c["at_s"], c["legs"], "gw_ms", c.get("gw_ms"), flush=True)
            for m in c.get("trace", [])[:40]:
                print("    ", m, flush=True)
    out.write_text(json.dumps(dict(mode=mode, calls=calls)))


main()
