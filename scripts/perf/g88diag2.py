"""GAP-0088 diagnosis 2 (diagnostic branch only, never merged).

Mode (argv 3): now = measure right after the provision step, as dcperf does;
sync = sync(1) first, so the just-installed files are on disk; wait20 = sleep
20 s first, so the gateway start-up work and the runner's own start-up are
over. Each mode runs 100 idle Claude Code calls, then 100 Codex calls. Every
100 ms a sampler records the CPU of every process, and the kernel's Dirty and
Writeback page counts; each call records its handler legs.
"""
import json, os, subprocess, sys, threading, time
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


def meminfo():
    m = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":", 1)
        if k in ("Dirty", "Writeback"):
            m[k] = int(v.split()[0])
    return m


def iostat():
    busy = 0
    for line in open("/proc/diskstats"):
        f = line.split()
        if len(f) > 12 and not f[2].startswith(("loop", "ram")) and not f[2][-1].isdigit():
            busy += int(f[12])
    return busy


class Sampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.rows = []
        self.stop = False

    def run(self):
        prev = proc_ticks()
        io0 = iostat()
        while not self.stop:
            time.sleep(0.1)
            cur = proc_ticks()
            io1 = iostat()
            at = time.monotonic() - dp.RUN_STARTED
            d = []
            for pid, (name, t) in cur.items():
                was = prev.get(pid)
                if was is None or was[0] != name:
                    continue
                if t > was[1]:
                    d.append((t - was[1], name))
            d.sort(reverse=True)
            m = meminfo()
            self.rows.append([round(at, 2), m.get("Dirty", 0), m.get("Writeback", 0), io1 - io0,
                              [[round(x[0] * 1000 / HZ), x[1]] for x in d[:5]]])
            prev, io0 = cur, io1


def timed_call(inst, env, argvs, connector, session):
    data = dp.hook_payload(connector, inst.work, session)
    t0 = time.perf_counter()
    procs = [subprocess.Popen(a, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env, cwd=str(inst.work)) for a in argvs]
    ends = [0.0] * len(procs)

    def talk(i):
        procs[i].communicate(data, timeout=60)
        ends[i] = (time.perf_counter() - t0) * 1000

    th = [threading.Thread(target=talk, args=(i,)) for i in range(len(procs))]
    [t.start() for t in th]
    [t.join() for t in th]
    return [round(e, 1) for e in ends]


def phase(inst, connector, n=100):
    env = inst.env()
    argvs = dp.registered_hooks(inst, connector)
    session = f"g88-{connector}-{time.monotonic_ns()}"
    for _ in range(3):
        timed_call(inst, env, argvs, connector, session)
    calls = []
    for _ in range(n):
        at = time.monotonic() - dp.RUN_STARTED
        calls.append([round(at, 3), timed_call(inst, env, argvs, connector, session)])
    ms = sorted(max(c[1]) for c in calls)
    return dict(connector=connector, p50=ms[len(ms) // 2], p95=ms[int(len(ms) * 0.95)], max=ms[-1], calls=calls)


def main():
    home, out, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    inst = dp.Install(home.resolve())
    s = Sampler()
    s.start()
    t = time.monotonic()
    if mode == "sync":
        subprocess.run(["sync"], check=False)
    elif mode == "wait20":
        time.sleep(20)
    prep = round(time.monotonic() - t, 2)
    res = dict(mode=mode, prep_s=prep, phases=[])
    for conn in ("claudecode", "codex"):
        p = phase(inst, conn)
        res["phases"].append(p)
        slow = [c for c in p["calls"] if max(c[1]) > 120]
        print(mode, conn, "p50/p95/max", p["p50"], p["p95"], p["max"], "slow", len(slow),
              [(c[0], c[1]) for c in slow[:10]], flush=True)
    s.stop = True
    time.sleep(0.2)
    res["samples"] = s.rows
    out.write_text(json.dumps(res))
    print("prep", prep, "s")


main()
