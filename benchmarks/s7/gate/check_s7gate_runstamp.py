#!/usr/bin/env python3
"""Tests for the run stamp in s7gate.py RUN.json (lane s7-benchfix3, rel-1-0-10 S7 P4): every run records its host, its code commit and a build stamp.

  python3 -I test_s7gate_runstamp.py [path/to/s7gate.py]     (default: s7gate.py beside this file); exit 0 = all pass

The Sunday benchmark runs are tied to a commit through RUN.json, so a run that cannot say which code it ran is refused when --require-stamp or
S7_REQUIRE_STAMP=1 is set (s7-gate sets it for a worktree run), and is marked unstamped otherwise. Synthetic corpora and a fake harness binary only.
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "s7gate.py")
sys.argv = [GATE]
spec = importlib.util.spec_from_loader("s7gate_t", importlib.machinery.SourceFileLoader("s7gate_t", GATE))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
fails = []
SHA = "0123456789abcdef0123456789abcdef01234567"
ENVKEYS = ("S7_CODE_COMMIT", "S7_CODE_DIRTY", "S7_CODE_REF", "S7_RUN_HOST", "S7_REQUIRE_STAMP")


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else ": " + detail))
    if not cond:
        fails.append(name)


def clean_env(**kw):
    for k in ENVKEYS:
        os.environ.pop(k, None)
    os.environ.update(kw)


# the part of a Go binary the stamp reads: the build-info marker, the version, and the vcs.* / -tags settings
GOBIN = (
    b"\x7fELF-ish\x00"
    + b"\xff Go buildinf:\x08\x02"
    + b"\x07go1.26.4"
    + b"\x00" * 8
    + b"build\t-tags=s7bench\nbuild\tvcs.revision="
    + SHA.encode()
    + b"\nbuild\tvcs.time=2026-11-14T17:00:00Z\nbuild\tvcs.modified=false\n"
)

with tempfile.TemporaryDirectory() as d:
    gobin = os.path.join(d, "s7bench-go")
    open(gobin, "wb").write(GOBIN)
    plain = os.path.join(d, "s7bench-plain")
    open(plain, "wb").write(b"#!/bin/sh\nexit 0\n")

    clean_env()
    s = g.run_stamp(gobin)
    check(
        "commit and build info read from the binary's own stamp",
        s["code_commit"] == SHA and s["code_commit_source"] == "binary vcs stamp" and s["stamped"],
        str(s),
    )
    check(
        "build stamp: sha256, size, go version, tags",
        s["build"]["bin_sha256"] == hashlib.sha256(GOBIN).hexdigest()
        and s["build"]["bin_bytes"] == len(GOBIN)
        and s["build"]["go_version"] == "go1.26.4"
        and s["build"]["tags"] == "s7bench"
        and s["build"]["vcs_time"] == "2026-11-14T17:00:00Z",
        str(s["build"]),
    )
    check(
        "host falls back to this machine's name",
        s["host"] == s["hostname"] and s["host"] != "",
        str((s["host"], s["hostname"])),
    )
    check("dirty comes from vcs.modified", s["code_dirty"] is False, str(s["code_dirty"]))

    clean_env(
        S7_CODE_COMMIT="f" * 40, S7_RUN_HOST="dc-bench-x", S7_CODE_DIRTY="1", S7_CODE_REF="s7/some-branch@fffffffffffff"
    )
    s = g.run_stamp(gobin)
    check(
        "S7_CODE_COMMIT wins over the binary's stamp",
        s["code_commit"] == "f" * 40 and s["code_commit_source"] == "S7_CODE_COMMIT",
        str(s),
    )
    check("host is S7_RUN_HOST when set", s["host"] == "dc-bench-x" and s["hostname"] != "", str(s))
    check(
        "dirty and ref come from the environment",
        s["code_dirty"] is True and s["code_ref"] == "s7/some-branch@fffffffffffff",
        str(s),
    )

    clean_env()
    s = g.run_stamp(plain)
    check(
        "no commit anywhere: unstamped, source none",
        s["code_commit"] == ""
        and s["code_commit_source"] == "none"
        and s["stamped"] is False
        and s["code_dirty"] is None,
        str(s),
    )
    check("an unreadable binary is recorded, not fatal", "error" in g.run_stamp(os.path.join(d, "missing"))["build"])

    # end to end: a run through the CLI with a fake harness
    FAKE = '#!/usr/bin/env python3\nimport json, sys\na = sys.argv[1:]\nids = {l.strip() for l in open(a[a.index("-ids") + 1]) if l.strip()}\nwith open(a[a.index("-out") + 1], "w") as o:\n    for line in open(a[a.index("-corpus") + 1]):\n        c = json.loads(line)\n        if c["id"] in ids: o.write(json.dumps({"case": c["id"], "idx": 0, "action": "allow", "raw_action": "allow", "status": 200}) + "\\n")\n'
    fake = os.path.join(d, "fake-s7bench")
    open(fake, "w").write(FAKE)
    os.chmod(fake, 0o755)
    home = os.path.join(d, "home")
    os.makedirs(os.path.join(home, "s7c", "corpora"))
    cp = os.path.join(home, "s7c", "corpora", "t.cases.jsonl")
    with open(cp, "w") as f:
        for i in range(2):
            f.write(
                json.dumps(
                    {
                        "id": "t-%d" % i,
                        "surface": "action",
                        "source": {"dataset": "synthetic/s7bf3"},
                        "strata": {"platform": "linux", "provider": "claudecode"},
                        "truth": {"source_truth": "benign", "applicability": "in_scope"},
                        "payload": {"events": [{"tool_name": "Bash", "tool_input": {"command": "ls"}}]},
                    }
                )
                + "\n"
            )

    def gate(*args, **env):
        e = {k: v for k, v in os.environ.items() if k not in ENVKEYS}
        e.update(HOME=home, **env)
        return subprocess.run(
            [sys.executable, "-I", GATE] + list(args), env=e, capture_output=True, text=True, timeout=300
        )

    r = gate("register-corpus", cp, "--version", "t1")
    check("register corpus", r.returncode == 0, r.stderr[-300:])
    cj = os.path.join(home, "corpora.json")
    json.dump({"t": {"files": [cp]}}, open(cj, "w"))
    scr = os.path.join(home, "scr")
    os.makedirs(scr)

    def common(label):
        return [
            "--bin",
            fake,
            "--policy-dir",
            home,
            "--corpora",
            cj,
            "--out",
            os.path.join(home, "gate", label),
            "--packs",
            "default",
            "--parallel",
            "1",
            "--scratch-dir",
            scr,
            "--min-free-gb",
            "1",
        ]

    r = gate("run", *common("stamped"), S7_CODE_COMMIT=SHA, S7_RUN_HOST="dc-bench-x", S7_CODE_REF="s7/x@0123456789")
    run = json.load(open(os.path.join(home, "gate", "stamped", "RUN.json")))
    check(
        "a stamped run completes",
        r.returncode == 0 and run["complete"] is True,
        "rc %d %s" % (r.returncode, r.stdout[-300:] + r.stderr[-300:]),
    )
    check(
        "RUN.json records host, commit, ref and build",
        run["host"] == "dc-bench-x"
        and run["code_commit"] == SHA
        and run["code_ref"] == "s7/x@0123456789"
        and run["stamped"] is True
        and run["build"]["bin_sha256"] == hashlib.sha256(FAKE.encode()).hexdigest()
        and run["hostname"],
        json.dumps(run)[:500],
    )
    check(
        "the run says its stamp on stdout", "run stamp: host=dc-bench-x code_commit=" + SHA in r.stdout, r.stdout[:300]
    )

    r = gate("run", *common("unstamped"))
    run = json.load(open(os.path.join(home, "gate", "unstamped", "RUN.json")))
    check(
        "no commit: the run goes on but is marked unstamped, with a warning",
        r.returncode == 0
        and run["stamped"] is False
        and run["code_commit"] == ""
        and run["host"]
        and "WARNING: no code commit" in r.stdout,
        "rc %d %s" % (r.returncode, r.stdout[:300]),
    )

    r = gate("run", *common("req1"), "--require-stamp")
    check(
        "--require-stamp refuses a run with no commit (exit 6, nothing written)",
        r.returncode == 6 and not os.path.exists(os.path.join(home, "gate", "req1", "RUN.json")),
        "rc %d %s" % (r.returncode, r.stderr[-200:]),
    )
    r = gate("run", *common("req2"), S7_REQUIRE_STAMP="1")
    check("S7_REQUIRE_STAMP=1 refuses it too", r.returncode == 6, "rc %d" % r.returncode)
    r = gate("run", *common("req3"), "--require-stamp", S7_CODE_COMMIT=SHA)
    check(
        "--require-stamp lets a stamped run through",
        r.returncode == 0,
        "rc %d %s" % (r.returncode, r.stdout[-200:] + r.stderr[-200:]),
    )

    a = gate(
        "audit", "--gate-dir", os.path.join(home, "gate"), "--corpora", cj, "--json", os.path.join(home, "audit.json")
    )
    rows = (
        [json.loads(l) for l in open(os.path.join(home, "audit.json")) if l.strip()]
        if os.path.exists(os.path.join(home, "audit.json"))
        else []
    )
    by = {x["label"]: x for x in rows}
    check(
        "audit rows carry host, commit and whether the run is stamped",
        by.get("stamped", {}).get("run_commit") == SHA
        and by["stamped"]["run_stamped"] is True
        and by["unstamped"]["run_stamped"] is False
        and by["stamped"]["run_host"] == "dc-bench-x",
        json.dumps(rows)[:400] + a.stdout[-200:],
    )

print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
