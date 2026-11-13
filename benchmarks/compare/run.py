#!/usr/bin/env python3
"""Run one competitor adapter over the comparison sets and record every scanner's raw output per event.

  python3 run.py --adapter adapters.llamafirewall_pg --sets agentdojo,mcptox --sides holdout,tune \
      --sets-dir ~/s7c/compare/sets --out ~/s7c/compare/raw --workers 16 --threads 4 [--opt key=value ...] [--limit N]

Output: <out>/<adapter NAME>/<set>.<side>.jsonl, one row per event:
  {"case", "idx", "kind", "scanners": {name: {"score", "decision", "applicable", "err", "ms", "cached"}}, "ms"}
and <out>/<NAME>/VERSION.json (package versions, model ids and revisions, options, host, CPU/GPU).
Rows are appended and a rerun skips cases already complete, so a run can be resumed. Decisions are NOT thresholded here:
materialize.py turns raw rows into decision files for a given configuration (default or tuned thresholds).

A shared answer cache (<out>/<NAME>/cache.sqlite, keyed by sha256 of scanner + exact input) makes repeated identical inputs
free (sliding windows repeat the same calls and results); a cache hit keeps the latency of the original computation and is
marked cached, and latency figures come from latency.py, never from cached rows.
"""
import argparse, hashlib, importlib, json, multiprocessing as mp, os, platform, socket, sqlite3, sys, time, traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import caseview  # noqa: E402

_A = None      # adapter module (per worker)
_S = None      # adapter state (per worker)
_DB = None
_OPTS = {}


class Cache:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=120, isolation_level=None)
        self.db.execute("pragma journal_mode=wal")
        self.db.execute("pragma busy_timeout=120000")
        self.db.execute("create table if not exists c (k text primary key, v text)")

    def get(self, k):
        r = self.db.execute("select v from c where k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else None

    def put(self, k, v):
        for _ in range(20):
            try:
                self.db.execute("insert or replace into c values (?,?)", (k, json.dumps(v)))
                return
            except sqlite3.OperationalError:
                time.sleep(0.5)


def cached(scanner, payload, fn):
    """Run fn() once per (adapter version, scanner, exact payload); payload must be JSON-serialisable."""
    k = hashlib.sha256(json.dumps([_A.NAME, getattr(_A, "CACHE_VERSION", 1), scanner, payload], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    hit = _DB.get(k) if _DB else None
    if hit is not None:
        hit = dict(hit); hit["cached"] = True
        return hit
    t = time.perf_counter()
    try:
        res = fn()
        res = dict(res)
    except Exception as e:  # an adapter error is recorded, never silently turned into an allow
        res = dict(score=None, decision="error", err=f"{type(e).__name__}: {str(e)[:300]}")
    res.setdefault("ms", (time.perf_counter() - t) * 1000)
    res.setdefault("applicable", True)
    if _DB and res.get("decision") != "error":
        _DB.put(k, res)
    res["cached"] = False
    return res


def limit_onnx_threads(threads):
    """ONNX Runtime ignores OMP_NUM_THREADS and starts one intra-op thread per core in every session; with many worker processes
    that oversubscribes the box. Give every session the worker's thread budget (a resource limit only: same model, same scores)."""
    try:
        import onnxruntime as ort
    except Exception:
        return
    orig = ort.InferenceSession.__init__

    def init(self, path_or_bytes, sess_options=None, *a, **kw):
        so = sess_options or ort.SessionOptions()
        if not so.intra_op_num_threads:
            so.intra_op_num_threads = threads
        if not so.inter_op_num_threads:
            so.inter_op_num_threads = 1
        return orig(self, path_or_bytes, so, *a, **kw)
    ort.InferenceSession.__init__ = init


def init_worker(adapter, opts, cache_path, threads):
    global _A, _S, _DB, _OPTS
    os.environ.setdefault("OMP_NUM_THREADS", str(threads))
    os.environ.setdefault("MKL_NUM_THREADS", str(threads))
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    try:
        import torch
        torch.set_num_threads(threads)
    except Exception:
        pass
    limit_onnx_threads(threads)
    _OPTS = opts
    _A = importlib.import_module(adapter)
    _A.cached = cached
    try:
        _S = _A.setup(opts)
    except Exception as e:   # a Pool initializer that raises is respawned forever: record the error, fail every case instead
        global _INIT_ERR
        _INIT_ERR = f"adapter setup failed: {type(e).__name__}: {e}\n{traceback.format_exc()[-1500:]}"
        print(_INIT_ERR, file=sys.stderr, flush=True)
    _DB = Cache(cache_path) if cache_path else None


_INIT_ERR = None


def do_case(line):
    case = json.loads(line)
    if _INIT_ERR:
        return case["id"], None, _INIT_ERR
    rows = []
    try:
        evs = caseview.events(case)
        for i, ev in enumerate(evs):
            t = time.perf_counter()
            sc = _A.scan(_S, ev)
            rows.append(dict(case=case["id"], idx=i, kind=ev["kind"], scanners=sc, ms=(time.perf_counter() - t) * 1000))
    except Exception as e:
        return case["id"], None, f"{type(e).__name__}: {e}\n{traceback.format_exc()[-1500:]}"
    return case["id"], rows, None


def host_info():
    info = dict(host=socket.gethostname(), python=platform.python_version(), cpu=platform.processor() or platform.machine(), cpus=os.cpu_count())
    try:
        info["cpu_model"] = [l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")][0]
    except Exception:
        pass
    try:
        import torch
        info["torch"] = torch.__version__
        info["cuda"] = torch.cuda.is_available()
        if torch.cuda.is_available():
            info["gpu"] = torch.cuda.get_device_name(0)
    except Exception:
        pass
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--sets", required=True)
    ap.add_argument("--sides", default="holdout,tune")
    ap.add_argument("--sets-dir", default=os.path.expanduser("~/s7c/compare/sets"))
    ap.add_argument("--out", default=os.path.expanduser("~/s7c/compare/raw"))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--opt", action="append", default=[], help="adapter option key=value")
    ap.add_argument("--limit", type=int, default=0, help="first N cases per file (smoke tests)")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--redo-errors", action="store_true", help="run again every case with a scanner error (errors are never cached)")
    a = ap.parse_args()
    opts = dict(o.split("=", 1) for o in a.opt)
    mod = importlib.import_module(a.adapter)
    name = mod.NAME + (("-" + opts["variant"]) if opts.get("variant") else "")
    od = os.path.join(a.out, name)
    os.makedirs(od, exist_ok=True)
    cache_path = None if a.no_cache else os.path.join(od, "cache.sqlite")
    ver = dict(adapter=a.adapter, name=name, options=opts, started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), host=host_info())
    try:
        ver.update(mod.version(opts))
    except Exception as e:
        ver["version_error"] = str(e)[:200]
    json.dump(ver, open(os.path.join(od, "VERSION.json"), "w"), indent=1)
    ctx = mp.get_context("spawn")
    with ctx.Pool(a.workers, initializer=init_worker, initargs=(a.adapter, opts, cache_path, a.threads)) as pool:
        for s in a.sets.split(","):
            for side in a.sides.split(","):
                src = os.path.join(a.sets_dir, f"{s}.{side}.cases.jsonl")
                dst = os.path.join(od, f"{s}.{side}.jsonl")
                done = set()
                bad = set()
                if os.path.exists(dst):
                    nev = {}
                    for l in open(dst):
                        try:
                            r = json.loads(l)
                        except ValueError:
                            continue
                        if a.redo_errors and any(v.get("decision") == "error" for v in r["scanners"].values()):
                            bad.add(r["case"])
                        nev.setdefault(r["case"], set()).add(r["idx"])
                    want = {}
                    for l in open(src):
                        c = json.loads(l)
                        want[c["id"]] = len(caseview.events(c))
                    done = {c for c, ix in nev.items() if len(ix) >= want.get(c, 1 << 30)} - bad
                    if bad:   # drop the old rows of the cases run again, so each event has one row
                        keep = [l for l in open(dst) if json.loads(l)["case"] not in bad]
                        open(dst, "w").writelines(keep)
                lines = [l for l in open(src) if json.loads(l)["id"] not in done]
                if a.limit:
                    lines = lines[: a.limit]
                t0 = time.time(); n = 0; errs = 0
                with open(dst, "a") as f:
                    for cid, rows, err in pool.imap_unordered(do_case, lines, chunksize=4):
                        n += 1
                        if err:
                            errs += 1
                            print(f"[{name}] {s}.{side} case {cid} failed: {err[:400]}", file=sys.stderr, flush=True)
                            continue
                        for r in rows:
                            f.write(json.dumps(r) + "\n")
                        if n % 200 == 0:
                            f.flush()
                            print(f"[{name}] {s}.{side} {n}/{len(lines)} cases {time.time() - t0:.0f}s", flush=True)
                if errs and errs == n:
                    sys.exit(f"[{name}] {s}.{side}: every case failed; stopping")
                print(f"[{name}] {s}.{side} DONE {n} cases ({len(done)} already done), {errs} failed, {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
