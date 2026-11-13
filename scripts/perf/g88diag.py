"""GAP-0088 diagnosis (diagnostic branch only, not for merge): Claude Code and
Codex idle PreToolUse calls right after the gateway start and again 30 s
later, with the time of each handler and, every 100 ms, the busiest
processes of the runner."""
import json, os, sys, threading, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dcperf as dp

HZ = os.sysconf("SC_CLK_TCK")

def proc_ticks():
    out = {}
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            s = open(f"/proc/{p}/stat").read()
            name = s[s.index("(") + 1:s.rindex(")")]
            f = s[s.rindex(")") + 2:].split()
            out[int(p)] = (name, int(f[11]) + int(f[12]))
        except (OSError, ValueError):
            pass
    return out

class Sampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True); self.rows = []; self.stop = False
    def run(self):
        prev = proc_ticks(); t0 = time.monotonic()
        while not self.stop:
            time.sleep(0.1)
            cur = proc_ticks(); at = time.monotonic() - dp.RUN_STARTED
            d = []
            for pid, (name, t) in cur.items():
                was = prev.get(pid)
                dt = t - (was[1] if was and was[0] == name else 0)
                if dt > 0:
                    d.append((dt, name, pid))
            d.sort(reverse=True)
            self.rows.append([round(at, 2), os.getloadavg()[0], [[round(x[0] * 1000 / HZ), x[1], x[2]] for x in d[:6]]])
            prev = cur

def timed_call(inst, env, argvs, connector, session):
    data = dp.hook_payload(connector, inst.work, session)
    import subprocess
    t0 = time.perf_counter()
    procs = [subprocess.Popen(a, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(inst.work)) for a in argvs]
    ends = [0.0] * len(procs); outs = [b""] * len(procs)
    def talk(i):
        outs[i] = procs[i].communicate(data, timeout=60)[0]; ends[i] = (time.perf_counter() - t0) * 1000
    th = [threading.Thread(target=talk, args=(i,)) for i in range(len(procs))]
    [t.start() for t in th]; [t.join() for t in th]
    return [round(e, 1) for e in ends], [p.returncode for p in procs], [o[:200].decode(errors="replace") for o in outs]

def phase(inst, connector, n=100):
    env = inst.env(); argvs = dp.registered_hooks(inst, connector)
    session = f"g88-{connector}-{time.monotonic_ns()}"
    for _ in range(3):
        timed_call(inst, env, argvs, connector, session)
    calls = []
    for i in range(n):
        at = time.monotonic() - dp.RUN_STARTED
        ends, rcs, outs = timed_call(inst, env, argvs, connector, session)
        rec = dict(i=i, at_s=round(at, 3), legs=ends, rc=rcs)
        if max(ends) > 120:
            rec["out"] = outs
        calls.append(rec)
    ms = sorted(max(c["legs"]) for c in calls)
    return dict(connector=connector, handlers=[a[0].rsplit("/", 1)[-1] + " " + (a[1] if len(a) > 1 else "") for a in argvs],
                p50=ms[len(ms) // 2], p95=ms[int(len(ms) * 0.95)], max=ms[-1], calls=calls)

def main():
    home = Path(sys.argv[1]); out = Path(sys.argv[2])
    inst = dp.Install(home.resolve())
    s = Sampler(); s.start()
    res = dict(host=dp.host_facts() if hasattr(dp, "host_facts") else {}, phases=[])
    for name, conn, wait in (("cc-now", "claudecode", 0), ("cx-now", "codex", 0), ("cc-30s", "claudecode", 30), ("cx-30s", "codex", 0), ("cc-again", "claudecode", 0)):
        time.sleep(wait)
        p = phase(inst, conn); p["name"] = name; res["phases"].append(p)
        print(name, p["handlers"], "p50/p95/max", p["p50"], p["p95"], p["max"], flush=True)
        for c in p["calls"]:
            if max(c["legs"]) > 120:
                print("   slow", c["i"], c["at_s"], c["legs"], flush=True)
    s.stop = True; time.sleep(0.2)
    res["samples"] = s.rows
    out.write_text(json.dumps(res))
    try:
        log = (inst.dc / "gateway.log").read_text(errors="replace").splitlines()
        print("gateway.log tail:"); print("\n".join(log[-60:]))
    except OSError:
        pass

main()
