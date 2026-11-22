#!/usr/bin/env python3
"""s7gate: run the rules-only DefenseClaw hook benchmark on every corpus x pack, score it, and compare two runs.

  s7gate.py run     --bin s7bench --policy-dir DIR --corpora corpora.json --out OUT [--packs default,permissive,strict] [--gomaxprocs 8] [--only name,...]
  s7gate.py score   --corpora corpora.json --out OUT [--reviews reviews.jsonl]          writes OUT/scores/<corpus>-<pack>.json and OUT/SUMMARY.md
  s7gate.py compare --base OUTBASE --cand OUTCAND                                      per-corpus rate deltas + per-rule diffs; exit 1 if a gate rate worsens
  s7gate.py all     (run + score)                                                      the one command used for before/after; a missing or changed label set refuses (exit 1)
  s7gate.py register-corpus FILE --version ID   record the sha256 of a corpus file as a registered version
  s7gate.py verify-corpora --corpora C [--only a,b]   exit 1 when a corpus file is missing, unregistered or changed in place
  s7gate.py push-labels --src DIR --dest DIR [--name labels-v3]   copy a label set to <dest>/current.*, verified by sha256; any failure exits 4
  s7gate.py fold-labels --base SET --overlay F [--overlay F ...] --out DIR --version V   a NEW label set = base + hand-review overlays; exit 4 on bad input
  s7gate.py check-labels --labels SET --overlay F [--overlay F ...]   exit 1 and the case ids when the set lacks an overlay row; exit 4 on bad input

One scorer (rel-1-0-10 GAP-1581): this file is the scorer s7-gate deploys to the bench boxes (with holdout.py, surface.py, s7session.py and
labelfold.py beside it; the frozen holdout-split-v1.json is data and stays on the dev host, S7_HOLDOUT_SPLIT names another file). Exit codes
are per subcommand: run/score/all/audit 4 = incomplete run; push-labels/fold-labels/check-labels 4 = bad input; 1 = a missing label set, or one that changed during the run;
compare 1 = a gate rate worsened, 3 = no verdict (label sets or fixture roots differ, a side unlabelled without --allow-unlabelled, a cell
incomplete). Corpus registry root $S7_CORPORA_ROOT (default ~/s7c/corpora); default label set $S7_LABELS_DEFAULT (default
~/s7c/labels/current.jsonl); fixture root $S7_FIXTURE_ROOT (default ~/s7c/fx), one per box and label-free (GAP-0495, GAP-0736).
  s7gate.py split   --corpora C                                                         cases per side of the frozen holdout split per corpus, checked against the freeze manifest
  s7gate.py audit   --gate-dir DIR --corpora C [--judge-corpora J] [--box NAME] [--json FILE] [--only-label a,b]   completeness of every run dir under DIR (no scoring)

RUN.json "complete" covers every shard of the run dir, not only those the last --resume/--only invocation ran; a shard whose harness refused its
arguments (an unsupported -surface value in that harness build) says so in its reasons (s7-hookscorerev 2026-11-14).
Completeness (rel-1-0-10:GAP-0170): a harness shard (corpus x group x pack) is complete only when its exit status was 0 (not a signal, not the scratch cap),
no FATAL / kill line is in its .err, and every case of its ids file has all its events decided (rows per case == events in the case); in-scope cases are
those the scorer counts (after exclusions). A corpus x pack with any incomplete shard is INCOMPLETE: the scorer writes scores/<corpus>-<pack>.json with
status "incomplete" and the missing counts and NO rates; trend rows and TREND.md show it as incomplete; compare exits 3. run/all exit 4 when any shard is incomplete.

corpora.json: {"name": {"files": ["/abs/a.cases.jsonl", ...], "meta": ["/abs/a.meta.jsonl", ...]}}   (corpus paths /home/alice and /Users/alice are rewritten to <fixture root>/home/alice and .../Users/alice, the same path for every run on the box; real scratch homes with decoy files; HOME points there; no sudo)
Truth is read from case-v1: benign = source_truth benign and in_scope; attack = malicious/sensitive and in_scope; everything else is excluded.
A corpus entry may carry "ids" (a file of case ids, one per line): only those cases are run and scored, and the "meta" weights
({"id", "weight"} per line, population / sampled) then give precision, FPR and F1 at corpus prevalence ("weighted" in each cell).
--harness-args passes extra s7bench flags (the rules+judge configuration: -strategy regex_judge -judge-model ... -judge-url ...);
judge request stats (calls per tool call, answered, cut at the window, parse failures, latency p50/p95, tokens, USD per 1k tool calls)
are scored whenever the decisions carry judge_calls. Writes no corpus text to stdout.
Judge cost is reported two ways side by side (rel-1-0-10:GAP-0649): answered-only (the calls that came back with usage, as before) and all-sent
(every request that went to a model: answered, cut at the window, failed in transport; not a request the cache-only proxy refused, not an HTTP
error status). A cut or failed call has no usage in its answer; the harness records the size of every request (req_chars), the scorer prices an
unanswered call at that size with the run's own chars-per-token and counts its output as 0 (a lower bound), and --judge-proxy-log PATH (the s7proxy
log of the run) gives the exact all-sent tokens for the whole run (judge_cost.json). In a tool-call run the opening UserPromptSubmit's judge calls
are the prompt's own line (judge.prompt_cost; rel-1-0-10:GAP-0650), not the first tool call's. Every RUN.json records the host, the code commit and a
build stamp of the binary (host, code_commit, code_commit_source, code_dirty, build{bin_sha256, go_version, vcs_*}); with --require-stamp
(or S7_REQUIRE_STAMP=1) a run with no code commit is refused.
"""

import argparse
import collections
import glob
import hashlib
import json
import math
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import holdout as HOLD  # noqa: E402, N812  the frozen holdout split (rel-1-0-10 S7 L2); see holdout.py
from surface import case_surface  # noqa: E402

PACKS = ["default", "permissive", "strict"]
# The harness drives the claudecode connector with Claude Code tool names (benchmarks/cmd/s7bench mapTool). Other connectors' native tools are
# sent as unknown MCP calls, so no file-path or patch rule can see them. Cases that use them are reported, not scored, unless --include-unsupported.
UNSUPPORTED_TOOLS = {
    "apply_patch",
    "powershell",
    "pwsh",
    "applypatch",
    "patch",
    "str_replace_editor",
    "replace",
    "fs_write",
    "fs_append",
}
HOMES = {"linux": "/home/alice", "macos": "/Users/alice"}


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return p, (c - h) / d, (c + h) / d


# USD per 1M tokens (input, output), AWS Pricing API us-east-1, Mantle on demand. Only the judge model the gate runs.
JUDGE_PRICE = {"gemma-4-31b": (0.14, 0.40)}
WINDOW_MS = 3400


def sample_ids(cfg):
    if not cfg.get("ids"):
        return None
    return {l.strip() for l in open(cfg["ids"]) if l.strip()}


def read_cases(cfg, name=None):
    """yield (id, truth dict) for a corpus entry, streaming (only the "ids" sample when the entry has one). With the corpus name, each case also carries its
    side of the frozen holdout split (split = "tune" | "holdout")."""
    keep = sample_ids(cfg)
    hcfg = HOLD.load() if name else None
    for f in cfg["files"]:
        with open(f) as fh:
            for line in fh:
                r = json.loads(line)
                if keep is not None and r["id"] not in keep:
                    continue
                t = r["truth"]
                s = r.get("strata", {})
                pl = r["payload"]
                evs = pl.get("events") or [pl]
                dial = collections.Counter(e.get("dialect") for e in evs).most_common(1)[0][0] or "none"
                tools = sorted({e.get("tool_name") or "" for e in evs})
                yield (
                    r["id"],
                    dict(
                        state=(
                            "benign"
                            if (t.get("source_truth") == "benign" and t.get("applicability", "in_scope") == "in_scope")
                            else "attack"
                            if (
                                t.get("source_truth") in ("malicious", "sensitive")
                                and t.get("applicability", "in_scope") == "in_scope"
                            )
                            else "excluded"
                        ),
                        blockpos=t.get("expected_disposition") == "block",
                        platform=s.get("platform") or "unknown",
                        dialect=dial,
                        provider=s.get("provider") or "unknown",
                        campaign=s.get("campaign") or "unknown",
                        domain=s.get("domain") or "unknown",
                        surface=r["surface"],
                        tsurface=case_surface(r),
                        dataset=r["source"]["dataset"].split("/")[-1],
                        cats=t.get("categories") or [],
                        tool=tools[0] if len(tools) == 1 else "multi",
                        label_source=t.get("label_source", ""),
                        nev=len(evs),
                        split=HOLD.split_of(name, r, hcfg) if name else HOLD.TUNE,
                        supported=True,
                    ),
                )


FIXTURE_FILES = {
    ".ssh/authorized_keys": "# decoy s7gate fixture\n",
    ".ssh/known_hosts": "",
    ".ssh/config": "",
    ".ssh/id_ed25519": "decoy\n",
    ".netrc": "decoy\n",
    ".aws/credentials": "[default]\n",
    ".claude/settings.json": "{}\n",
    ".codex/config.toml": "",
    ".defenseclaw/config.yaml": "{}\n",
    ".bashrc": "",
    ".gitconfig": "",
}


# The fixture root is the home the corpus paths are rewritten to, and a call's text carries it (HOME, cwd, paths in the command). A root under the run directory
# made the call length depend on the run LABEL: a case at 4090 bytes under one label was 4099 under a longer one and crossed the 4096-byte reading bound
# (shellparse nestedBodyMinCommand, ACTION-COMPOUND-LIMIT) on both rel and head, so two runs with labels of different length decided one call differently
# (rel-1-0-10:GAP-0666, GAP-0648, GAP-0684). The root is now FX_BASE/<12 hex of sha256 of the run directory>: one fixed length, unique per run.
# Parent of the per-run fixture trees the scorer made before one root per box (GAP-0666 scheme); gc_fixtures removes the
# trees whose run directory is gone. Kept until no run directory of that scorer is left on the bench boxes (1.0.12).
FX_HASH_LEN = 12  # hex digits of a per-run tree name (the per-run scheme, GAP-0666)


def fx_base():
    return os.path.abspath(os.path.expanduser(os.environ.get("S7_FX_BASE") or "~/s7c/fx"))


def fixture_root(out=None):
    """The scratch fixture root of every run on this box: $S7_FIXTURE_ROOT, else ~/s7c/fx. It does not depend on the
    run label or the output directory: the corpus rewrite puts this path into every case, and a content regex that
    reads the label text in it decided one benign case differently between two runs of the same code (rel-1-0-10
    GAP-0495, GAP-0736); a path built from the label (or a hash of OUT) also changes the call bytes between runs.
    A run directory made by an older scorer (OUT/fx a directory, or a link to a per-run tree) keeps its tree, so a
    --resume of that run stays consistent with its already rewritten corpus; compare refuses it against a new run."""
    if out:
        legacy = os.path.join(os.path.abspath(out), "fx")
        if os.path.islink(legacy):
            return os.path.realpath(legacy)
        if os.path.isdir(legacy):
            print(
                f"[s7gate] WARNING {legacy} is a pre-labelfix fixture directory: the call bytes of this run depend on "
                "its label (GAP-0666)",
                flush=True,
            )
            return legacy
    return os.path.abspath(os.path.expanduser(os.environ.get("S7_FIXTURE_ROOT") or "~/s7c/fx"))


def _per_run_tree(root):
    name = os.path.basename(root.rstrip("/"))
    return len(name) == FX_HASH_LEN and all(c in "0123456789abcdef" for c in name)


def run_fixture_root(d):
    """(root, scheme) of the fixture tree a run directory's corpora were rewritten under. RUN.json fixture_root (this
    scorer): scheme 'box' (one label-free root per box), or 'per-run' for a --resume of an older run (its
    fx_base()/<12 hex> tree). Else OUT/fx of the run, or of the run it was rescored from (a deployed-scorer run: a
    link to its per-run tree, or a pre-labelfix directory): 'per-run'. (None, None) when none is there. Per-run trees
    have paths of one length (GAP-0666) and compare with each other; a per-run tree against the box root does not
    (13 bytes shorter per path), nor do two different box roots (GAP-0495)."""
    try:
        run = json.load(open(os.path.join(d, "RUN.json")))
    except (OSError, ValueError):
        run = {}
    root = run.get("fixture_root")
    if root:
        return root, "per-run" if _per_run_tree(root) else "box"
    for r in (d, run.get("rescored_from")):
        if r and os.path.lexists(os.path.join(r, "fx")):
            return os.path.realpath(os.path.join(r, "fx")), "per-run"
    return None, None


def _read_owner(d):
    try:
        with open(os.path.join(d, ".owner")) as f:
            return f.read().strip()
    except OSError:
        return None


def gc_fixtures():
    """Remove FX_BASE/<hash> trees whose run directory is gone (rm -rf gate/<label>, clean-stale, --overwrite)."""
    base = fx_base()
    try:
        names = os.listdir(base)
    except OSError:
        return
    for h in names:
        d = os.path.join(base, h)
        owner = _read_owner(d)
        if owner is None:
            continue
        if not os.path.exists(owner):
            shutil.rmtree(d, ignore_errors=True)


def make_fixture(out):
    """Real (scratch) home directories for the corpus accounts, so protected-file and link checks resolve against a
    filesystem like a live host. Every run on the box shares them (fixture_root); the files are only created, never
    changed, so a concurrent run reads the same bytes."""
    gc_fixtures()
    fx = fixture_root(out)
    for home in ("home/alice", "Users/alice"):
        for rel, body in FIXTURE_FILES.items():
            p = os.path.join(fx, home, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if not os.path.exists(p):
                with open(p, "w") as f:
                    f.write(body)
        os.chmod(os.path.join(fx, home, ".ssh"), 0o700)
    return fx


def rewrite_corpus(src, dst, fx):
    """Copy a corpus with /home/alice and /Users/alice moved under the scratch fixture root (the root ends in .../home/alice, so rules that
    look for /home/<user>/.ssh still match, and the filesystem checks find real files)."""
    if os.path.exists(dst) and os.path.getmtime(dst) >= os.path.getmtime(src):
        return
    tmp = dst + ".tmp"
    with open(src) as i, open(tmp, "w") as o:
        for line in i:
            o.write(line.replace("/home/alice", fx + "/home/alice").replace("/Users/alice", fx + "/Users/alice"))
    os.replace(tmp, dst)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Completeness. One shard = one harness invocation set: corpus x group (alice, alice-st, macos, macos-st) x pack. Its output is
# decisions/<corpus>/<group>-<pack>.jsonl (or .<i>.jsonl per corpus file), its exit code <...>.jsonl.rc, its success marker <...>.jsonl.ok.
DEFAULT_SCRATCH_CAP_MB = 0  # 0: pick by where the scratch is (see resolve_scratch). Was 2048 in the harness: it killed healthy runs on dc-s7-bench (GAP-0170)
_UNUSED = 32768  # per harness process; a runaway backstop, never a normal limit (see cmd_run). The audit WAL guard in the harness is untouched.
MIN_FREE_TMPFS_GB = 24  # the same, when the scratch dir is on tmpfs (it is RAM)
MIN_FREE_GB = 100  # a shard is not started while the scratch volume has less free space than this


def shard_files(prefix):
    """Output files of one shard. prefix = <dir>/<group>-<pack><chunk tag> (no .jsonl): the file itself, or one file per corpus file (.0, .1 ...)."""
    return glob.glob(prefix + ".jsonl") + glob.glob(prefix + ".[0-9]*.jsonl")


def shard_id(idfile):
    """ids.<group>[.cNNN].txt -> (group, chunk tag)."""
    stem = os.path.basename(idfile)[4:-4]
    m = re.match(r"^(.*?)(\.c\d{3})?$", stem)
    return m.group(1), m.group(2) or ""


HARNESS_ARG_REFUSAL = re.compile(
    r"^(-[A-Za-z][\w-]* must be |flag provided but not defined: |invalid (boolean )?value .* for flag )"
)


def err_evidence(prefix):
    """A harness that was killed leaves a line in its .err: the scratch cap (FATAL ... over the ... cap) or a signal (removing scratch dir and exiting)."""
    p = prefix + ".err"
    try:
        with open(p, "rb") as f:
            f.seek(0, 2)
            n = f.tell()
            f.seek(max(0, n - 2_000_000))
            txt = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    for line in txt.splitlines():
        if HARNESS_ARG_REFUSAL.match(line):
            # the harness build does not take an argument this corpus passes (corpora.json harness_args), e.g. a -surface value from a branch that
            # is not in this harness lineage: every case of the shard is undecided, and the reason says so (s7-hookscorerev, sr7 response-owner)
            return "harness refused its arguments (unsupported in this harness build): " + line.strip()[:120]
        if line.startswith("[s7bench] FATAL"):
            return line.split("FATAL:", 1)[-1].strip()[:140]
        if line.startswith("[s7bench]") and "removing scratch dir" in line and "FATAL" not in line:
            return "killed by a signal (" + line.split("]", 1)[1].split(":", 1)[0].strip() + ")"
    return None


def shard_status(d, g, pack, truth, tag=""):
    """Completeness of one shard. truth: case id -> dict with state and nev (events), or None when the corpus definition is unknown (every case in scope, events not checked).
    Returns counts (all cases and in-scope cases) and the reasons it is incomplete; reasons == [] means complete."""
    idf = f"{d}/ids.{g}{tag}.txt"
    prefix = f"{d}/{g}-{pack}{tag}"
    ids = [l.strip() for l in open(idf) if l.strip()] if os.path.exists(idf) else []
    rows = collections.Counter()
    for f in shard_files(prefix):
        with open(f) as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rows[json.loads(line)["case"]] += 1
                except (ValueError, KeyError):
                    rows["\0bad-row"] += 1  # a torn last line of a killed run
    full = lambda c: c in rows and (truth is None or truth.get(c) is None or rows[c] == truth[c]["nev"])
    scope = [c for c in ids if truth is None or truth.get(c) is None or truth[c]["state"] != "excluded"]
    decided = sum(1 for c in ids if full(c))
    in_scope_decided = sum(1 for c in scope if full(c))
    partial = sum(1 for c in ids if c in rows and not full(c))
    base = prefix + ".jsonl"
    rc = None
    try:
        rc = int(open(base + ".rc").read().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    ok = os.path.exists(base + ".ok")
    reasons = []
    if not ids:
        reasons.append("no ids file")
    if len(scope) - in_scope_decided:
        reasons.append(
            f"{len(scope) - in_scope_decided} of {len(scope)} in-scope cases not fully decided"
            + (f" ({partial} partly)" if partial else "")
        )
    if rc not in (None, 0):
        reasons.append(f"harness exit status {rc}" + (" (killed by signal %d)" % -rc if rc < 0 else ""))
    ev = err_evidence(prefix)
    if ev:
        reasons.append("harness killed: " + ev)
    if rc is None and not ok:
        reasons.append("no completion marker (not finished or killed)")
    return dict(
        shard=f"{g}{tag}",
        pack=pack,
        expected_total=len(ids),
        decided_total=decided,
        expected_in_scope=len(scope),
        decided_in_scope=in_scope_decided,
        missing_total=len(ids) - decided,
        missing_in_scope=len(scope) - in_scope_decided,
        partial_cases=partial,
        rc=rc,
        ok_marker=ok,
        reasons=reasons,
        complete=not reasons,
    )


def run_completeness(out, packs, truths):
    """Incomplete shards of the whole run dir OUT for packs: every ids file of every corpus under OUT/decisions, not only the shards the last
    invocation ran. truths: corpus -> case truth for the corpora this invocation read; a corpus it did not read (a --resume or --only subset) is
    complete only by its shards' own completion markers (.ok with complete true, written only for a shard that exited 0 and decided every case)."""
    bad = []
    for d in sorted(glob.glob(os.path.join(out, "decisions", "*", ""))):
        d = d.rstrip("/")
        name = os.path.basename(d)
        for idf in sorted(glob.glob(d + "/ids.*.txt")):
            g, tag = shard_id(idf)
            for pack in packs:
                if name not in truths:
                    try:
                        if json.load(open(f"{d}/{g}-{pack}{tag}.jsonl.ok")).get("complete"):
                            continue
                    except (OSError, ValueError):
                        pass
                st = shard_status(d, g, pack, truths.get(name), tag)
                if not st["complete"]:
                    bad.append(dict(st, shard=f"{name}/{st['shard']}"))
    return bad


def corpus_pack_status(d, name, pack, truth):
    shards = [
        shard_status(d, *shard_id(f)[:1], pack, truth, shard_id(f)[1]) for f in sorted(glob.glob(d + "/ids.*.txt"))
    ]
    row = dict(corpus=name, pack=pack, shards=len(shards), complete=bool(shards) and all(x["complete"] for x in shards))
    for k in (
        "expected_total",
        "decided_total",
        "expected_in_scope",
        "decided_in_scope",
        "missing_total",
        "missing_in_scope",
        "partial_cases",
    ):
        row[k] = sum(x[k] for x in shards)
    row["status"] = "complete" if row["complete"] else "incomplete"
    row["incomplete_shards"] = [
        dict(
            shard=x["shard"],
            expected_in_scope=x["expected_in_scope"],
            decided_in_scope=x["decided_in_scope"],
            missing_in_scope=x["missing_in_scope"],
            rc=x["rc"],
            reasons=x["reasons"],
        )
        for x in shards
        if not x["complete"]
    ]
    return row


def packs_present(d, run):
    """The packs this run was asked for (RUN.json when it was written), else the packs that have any output."""
    if run and run.get("packs"):
        return [p for p in PACKS if p in run["packs"]]
    return [p for p in PACKS if glob.glob(f"{d}/*-{p}.jsonl*") or glob.glob(f"{d}/*-{p}.[0-9c]*.jsonl*")]


def supports_fixture_fs(binary, cache={}):
    """Whether the harness binary was built with the fixturefs seam (hook-call path reads of /tmp, /var/tmp, /dev/shm go to the run's fixture tree, not the live box).
    Without it a glob like /tmp/x-*.log is expanded against the live /tmp and a verdict depends on the box and the minute (rel-1-0-10:GAP-0271)."""
    if binary not in cache:
        needle = b"S7_FIXTURE_FS_ROOT"
        hit = False
        try:
            with open(binary, "rb") as f:
                tail = b""
                while True:
                    chunk = f.read(8 << 20)
                    if not chunk:
                        break
                    if needle in tail + chunk:
                        hit = True
                        break
                    tail = chunk[-len(needle) :]
        except OSError:
            pass
        cache[binary] = hit
    return cache[binary]


def supports_flag(binary, flag, cache={}):
    """Whether the harness binary knows a flag (older baseline binaries have no -scratch-cap-mb)."""
    key = (
        binary,
        flag,
    )  # per flag: a cache by binary alone answered every flag with the first one's result (17:24Z -corpus-name rc=2)
    if key not in cache:
        try:
            r = subprocess.run([binary, "-h"], capture_output=True, text=True, timeout=30)
            cache[key] = ("-" + flag) in (r.stdout + r.stderr)
        except (OSError, subprocess.TimeoutExpired):
            cache[key] = False
    return cache[key]


def resolve_scratch(arg, cap_mb):
    """Where the harness puts audit.db + WAL, and the kill line for one process.

    Root cause of the GAP-0170 kills: the harness audit store syncs every write (synchronous=FULL) and its WAL guard needs synced checkpoints to restart the
    log. On dc-s7-bench the root volume answers an fdatasync in ~107 ms (p50, measured with 40 harness processes running; dc-build-1: 6 ms), so the guard never
    gets the log restarted and the WAL grows ~0.3 MiB per decision until the 2 GiB cap fires. The verdicts do not depend on the disk, so the scratch goes to tmpfs
    (no sync cost, the WAL stays near the guard's 256 MiB bound) when it has room; the cap there is a RAM backstop."""
    if arg == "auto":
        shm = "/dev/shm"
        arg = shm if os.path.isdir(shm) and os.access(shm, os.W_OK) and free_gb(shm) >= 40 else tempfile.gettempdir()
    on_tmpfs = False
    try:
        for line in open("/proc/mounts"):
            f = line.split()
            if f[1] == os.path.realpath(arg) or os.path.realpath(arg).startswith(f[1].rstrip("/") + "/"):
                on_tmpfs = f[2] == "tmpfs"
    except OSError:
        pass
    return arg, on_tmpfs, (cap_mb or (4096 if on_tmpfs else 32768))


def free_gb(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize / 2**30


# ---- registered corpus versions (rel-1-0-10, 2026-11-13 corpus-mutation incident) -------------------------------------------------------------------------------
# A corpus file is NEVER rewritten in place. ~/s7c/corpora/VERSIONS.json ("files": {key: {sha256, version, registered}}) says which bytes each registered file has; a run refuses to
# start when a corpus file it would read is missing, is not registered, or does not have the registered sha256. New content (a redacted variant, a rebuilt corpus) is a NEW file with a
# NEW version id, registered with `s7-gate register-corpus <file> --version <id>` (a path that is already registered with other bytes is refused).
def corpora_root():
    return os.path.abspath(os.path.expanduser(os.environ.get("S7_CORPORA_ROOT") or "~/s7c/corpora"))


def _vpath():
    return os.path.join(corpora_root(), "VERSIONS.json")


def _vkey(path):
    p, root = os.path.abspath(os.path.expanduser(path)), corpora_root()
    return os.path.relpath(p, root) if p.startswith(root + os.sep) else p


def _registry():
    try:
        return json.load(open(_vpath())).get("files", {})
    except (OSError, ValueError):
        return {}


def _file_sha(path):
    """sha256 of a corpus file, cached by path, size and mtime under the registry root."""
    st = os.stat(path)
    ck = f"{path}|{st.st_size}|{st.st_mtime_ns}"
    cp = os.path.join(corpora_root(), ".shacache.json")
    try:
        cache = json.load(open(cp))
    except (OSError, ValueError):
        cache = {}
    if ck in cache:
        return cache[ck]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    cache = {k: v for k, v in cache.items() if not k.startswith(path + "|")}
    cache[ck] = h.hexdigest()
    try:
        json.dump(cache, open(cp + ".tmp", "w"))
        os.replace(cp + ".tmp", cp)
    except OSError:
        pass
    return cache[ck]


def verify_corpora(cfgs, only=None):
    reg = _registry()
    bad = []
    for name, cfg in cfgs.items():
        if only and name not in only:
            continue
        for f in list(cfg.get("files", [])) + list(cfg.get("meta", [])):
            f = os.path.expanduser(f)
            if not os.path.exists(f):
                bad.append(f"{name}: {f} is missing")
                continue
            k = _vkey(f)
            if k not in reg:
                bad.append(
                    f"{name}: {k} is not a registered corpus version (register it: s7-gate register-corpus {f} --version <id>)"
                )
                continue
            s = _file_sha(f)
            if s != reg[k]["sha256"]:
                bad.append(
                    f"{name}: {k} has sha256 {s[:16]}, the registered version {reg[k].get('version')} has {reg[k]['sha256'][:16]}: the corpus was changed in place"
                )
    return bad


def file_sha256(path):
    """sha256 of any file, not cached (label sets, copies)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def refuse_corpus_overwrite(out, inputs=()):
    """For any tool that writes a corpus or a redacted copy of one: exit unless OUT is a new file, not one of its inputs
    and not a registered corpus version."""
    o = os.path.abspath(os.path.expanduser(out))
    for i in inputs:
        if i and os.path.abspath(os.path.expanduser(i)) == o:
            raise SystemExit(
                f"s7gate: output {out} is also an input: a corpus is never rewritten in place; "
                "write the new content to a new file"
            )
    if _vkey(o) in _registry():
        raise SystemExit(
            f"s7gate: {out} is a registered corpus version; write the new content to a new file "
            "and register it under a new version id"
        )


def cmd_verify_corpora(a):
    bad = verify_corpora(json.load(open(a.corpora)), set(a.only.split(",")) if a.only else None)
    print("\n".join(bad) if bad else "all corpus files match their registered versions")
    sys.exit(1 if bad else 0)


def cmd_register_corpus(a):
    f = os.path.expanduser(a.file)
    if not os.path.isfile(f):
        print(f"s7gate: {a.file} is not a file", file=sys.stderr)
        sys.exit(2)
    k = _vkey(f)
    s = _file_sha(f)
    vp = _vpath()
    try:
        d = json.load(open(vp))
    except (OSError, ValueError):
        d = {"schema": 1}
    d.setdefault("files", {})
    if k in d["files"] and d["files"][k]["sha256"] != s:
        print(
            f"s7gate: {k} is registered as version {d['files'][k].get('version')} with other bytes: a registered corpus is never rewritten; write the new content to a new file and register that under a new version id",
            file=sys.stderr,
        )
        sys.exit(2)
    d["files"][k] = {
        "sha256": s,
        "version": a.version,
        "size": os.path.getsize(f),
        "registered": time.strftime("%FT%TZ", time.gmtime()),
    }
    os.makedirs(os.path.dirname(vp), exist_ok=True)
    json.dump(d, open(vp + ".tmp", "w"), indent=1, sort_keys=True)
    os.replace(vp + ".tmp", vp)
    print(f"registered {k} version {a.version} sha256 {s[:16]}")


def cmd_run(a):
    cfgs = json.load(open(a.corpora))
    _only = set(a.only.split(",")) if a.only else None
    _bad = verify_corpora(cfgs, _only)
    if _bad:
        print(
            "[s7gate] REFUSED: a corpus file does not match its registered version (GAP-0222 pass-2 incident, 2026-11-13):\n  "
            + "\n  ".join(_bad[:20]),
            file=sys.stderr,
        )
        sys.exit(5)
    dm_key = ""
    if getattr(a, "dm_key_file", ""):
        dm_key = open(a.dm_key_file).read().strip()  # never printed, never put on a command line
    only = set(a.only.split(",")) if a.only else None
    packs = a.packs.split(",")
    stamp = run_stamp(a.bin)
    print(
        f"[s7gate] run stamp: host={stamp['host']} code_commit={stamp['code_commit'] or 'NONE'} ({stamp['code_commit_source']}) dirty={stamp['code_dirty']} bin_sha256={stamp['build'].get('bin_sha256', '?')[:16]} go={stamp['build'].get('go_version', '?')}",
        flush=True,
    )
    if not stamp["stamped"]:
        print(
            "[s7gate] WARNING: no code commit for this run (no S7_CODE_COMMIT and no vcs.revision in the binary): RUN.json will say unstamped and the run cannot be tied to a commit",
            flush=True,
        )
        if getattr(a, "require_stamp", False) or os.environ.get("S7_REQUIRE_STAMP") == "1":
            print(
                "[s7gate] REFUSED: --require-stamp / S7_REQUIRE_STAMP=1 and the run has no code commit", file=sys.stderr
            )
            sys.exit(6)
    os.makedirs(a.out, exist_ok=True)
    fx = make_fixture(a.out)
    jobs = []
    truths = {}
    scratch_root, on_tmpfs, cap_mb = resolve_scratch(a.scratch_dir, a.scratch_cap_mb)
    min_free = a.min_free_gb or (MIN_FREE_TMPFS_GB if on_tmpfs else MIN_FREE_GB)
    os.makedirs(scratch_root, exist_ok=True)
    for name, cfg in cfgs.items():
        if only and name not in only:
            continue
        groups = collections.defaultdict(list)
        truths[name] = {}
        for cid, tr in read_cases(cfg):
            truths[name][cid] = dict(state=tr["state"], nev=tr["nev"])
            g = ("macos" if tr["platform"] == "macos" else "alice") + ("-st" if tr["surface"] == "stateful" else "")
            groups[g].append(cid)
        d = f"{a.out}/decisions/{name}"
        os.makedirs(d, exist_ok=True)
        rwdir = f"{a.out}/corpus-rw/{name}"
        os.makedirs(rwdir, exist_ok=True)
        rwfiles = []
        for k, f in enumerate(cfg["files"]):
            dst = f"{rwdir}/{k}.jsonl"
            rewrite_corpus(f, dst, fx)
            rwfiles.append(dst)
        for g, ids in groups.items():
            # Every case is self-contained (a stateful case carries its own event window), so a group can be cut into chunks of --chunk
            # cases, one harness process each. The audit WAL of a process grows with its case count (about 0.35 MiB per case when the
            # checkpoint cannot restart the log under box load), so chunking bounds the scratch per process; outputs sit beside each other
            # as <group>-<pack>.c<k>.jsonl and the scorer globs them all.
            n = a.chunk if a.chunk and a.chunk > 0 else max(len(ids), 1)
            parts = [ids[i : i + n] for i in range(0, len(ids), n)] or [ids]
            for k, part in enumerate(parts):
                tag = "" if len(parts) == 1 else f".c{k:03d}"
                idf = f"{d}/ids.{g}{tag}.txt"
                open(idf, "w").write("\n".join(part) + "\n")
                for pack in packs:
                    jobs.append(
                        (name, g, pack, rwfiles, idf, f"{d}/{g}-{pack}{tag}.jsonl", list(cfg.get("harness_args") or []))
                    )
    # Packs are the outer order: the strict run of a group then starts after its default run, so a judge request the two packs share
    # is a cache hit at the proxy instead of two paid calls made at the same time.
    jobs.sort(key=lambda j: packs.index(j[2]))
    print(f"[s7gate] {len(jobs)} harness runs", flush=True)
    running = []

    def start(j):
        name, g, pack, files, idf, out, hargs = j
        env = dict(os.environ, GOMAXPROCS=str(a.gomaxprocs))
        fxr = fx  # the fixed-length fixture root (make_fixture), not a path built from the run label
        home = fxr + (HOMES["macos"] if g.startswith("macos") else HOMES["linux"])
        # lean (default): -det=false everywhere (verdict-neutral, -23% CPU); -post=false only for single-call action cases, where no later
        # decision exists for a PostToolUse to influence. Stateful windows keep their PostToolUse so sequence rules see the same history.
        lean = (
            []
            if (a.full_fidelity or getattr(a, "effects_rules", ""))
            else (["-det=false"] if g.endswith("-st") else ["-det=false", "-post=false"])
        )
        # HOME is only a string here (/home/alice, /Users/alice): nothing is created there. The harness reads its device key from
        # DEFENSECLAW_HOME, which points into the run's own output directory.
        dch = os.path.join(a.out, "dchome")
        os.makedirs(dch, exist_ok=True)
        keyf = os.path.join(dch, "device.key")
        if not os.path.exists(keyf):
            import base64

            with open(keyf, "w") as kf:
                kf.write(
                    "-----BEGIN ED25519 PRIVATE KEY-----\n"
                    + base64.b64encode(os.urandom(32)).decode()
                    + "\n-----END ED25519 PRIVATE KEY-----\n"
                )
            os.chmod(keyf, 0o600)
        env["DEFENSECLAW_HOME"] = dch
        if dm_key:
            env["DEFENSECLAW_DECISION_MODEL_KEY"] = dm_key
        else:
            env.pop("DEFENSECLAW_DECISION_MODEL_KEY", None)
        env.pop("S7_FIXTURE_FS_ROOT", None)
        if supports_fixture_fs(a.bin) and not os.environ.get("S7_LIVE_FS"):
            env["S7_FIXTURE_FS_ROOT"] = os.path.join(
                fxr, "rootfs"
            )  # hermetic: the mutable system roots are read from the run's fixture tree
        # The scratch cap is a runaway backstop, not a limit the run may hit: the harness's default (2 GiB) killed healthy runs on a loaded box where the audit
        # WAL checkpoints lag (rel-1-0-10:GAP-0170). The WAL guard inside the harness is unchanged; this only raises the kill line.
        capf = ["-scratch-cap-mb", str(cap_mb)] if supports_flag(a.bin, "scratch-cap-mb") else []
        capf += (
            ["-corpus-name", name] if supports_flag(a.bin, "corpus-name") else []
        )  # the harness checks -dm-allow-corpus against it
        env["TMPDIR"] = (
            scratch_root  # the harness makes its scratch dir with os.MkdirTemp("", ...): TMPDIR moves it, with any harness build
        )
        cmds = []
        for i, f in enumerate(files):
            o = out if len(files) == 1 else out.replace(".jsonl", f".{i}.jsonl")
            cmds.append(
                [
                    "nice",
                    "-n",
                    "15",
                    "env",
                    "HOME=" + home,
                    "DEFENSECLAW_HOME=" + dch,
                    "GOMAXPROCS=" + str(a.gomaxprocs),
                    a.bin,
                    "-corpus",
                    f,
                    "-ids",
                    idf,
                    "-out",
                    o,
                    "-policy-dir",
                    a.policy_dir,
                    "-pack",
                    pack,
                    "-workers",
                    str(a.workers),
                ]
                + capf
                + lean
                + (
                    [
                        ("-cascade-effects" if supports_flag(a.bin, "cascade-effects") else "-effects-rules"),
                        a.effects_rules,
                    ]
                    if getattr(a, "effects_rules", "")
                    else []
                )
                + (["-connector", a.connector] if a.connector else [])
                + (a.harness_args.replace(",", " ").split() if a.harness_args else [])
                + hargs
            )  # corpora.json "harness_args" per corpus (s7-surfaces)
        for stale in shard_files(out[: -len(".jsonl")]) + [out + ".rc", out + ".ok"]:
            try:
                os.remove(stale)  # a rerun of a shard never mixes with the rows or the marker of an earlier attempt
            except OSError:
                pass
        logf = open(out.replace(".jsonl", ".err"), "w")
        sh = " && ".join(" ".join(map(str, c)) for c in cmds)
        # pipefail: the shard's exit status is the harness's, not grep's. grep -v exits 1 when it prints nothing, which is not a failure.
        return subprocess.Popen(
            [
                "bash",
                "-c",
                "set -o pipefail; { "
                + sh
                + "; } 2>&1 | { grep -v 'applying migration\\|notification suppressed' || [ $? -eq 1 ]; }",
            ],
            env=env,
            stdout=logf,
            stderr=subprocess.STDOUT,
        ), j

    def shard_tag(j):  # the chunk tag of a job, from its ids file (ids.<group>.cNNN.txt)
        return shard_id(j[4])[1]

    def trusted_done(j):
        """A shard marked .ok is kept on resume only when the marker proves completeness; a legacy marker (written by a pipeline that hid the exit status) is re-verified."""
        mk = j[5] + ".ok"
        if not os.path.exists(mk):
            return False
        try:
            return bool(json.load(open(mk)).get("complete"))
        except (ValueError, OSError):
            st = shard_status(os.path.dirname(j[5]), j[1], j[2], truths[j[0]], shard_tag(j))
            return st["complete"]

    pending = [j for j in jobs if not trusted_done(j)]
    t0 = time.time()
    bad = []
    low_since = None
    print(
        f"[s7gate] resume: {len(jobs) - len(pending)} runs already done, {len(pending)} to run; scratch in {scratch_root}{' (tmpfs)' if on_tmpfs else ''}, cap {cap_mb} MiB per harness process, start only with >= {min_free} GiB free there",
        flush=True,
    )
    while pending or running:
        # Disk safety belongs here, before a shard starts, not in a kill line that silently cuts a run short: wait for space instead of starting a shard on a nearly full volume.
        if pending and len(running) < a.parallel and free_gb(scratch_root) < min_free:
            low_since = low_since or time.time()
            if int(time.time() - low_since) % 300 < 2:
                print(
                    f"[s7gate] waiting for disk: {free_gb(scratch_root):.0f} GiB free in {scratch_root}, need {min_free}",
                    flush=True,
                )
            if not running and time.time() - low_since > a.disk_wait_min * 60:
                print(
                    f"[s7gate] FATAL: less than {min_free} GiB free for {a.disk_wait_min} min with nothing running; {len(pending)} shards not run (the run is INCOMPLETE)",
                    flush=True,
                )
                for j in pending:
                    bad.append(dict(shard=f"{j[0]}/{j[1]}", pack=j[2], reasons=["not started: no free disk"]))
                pending = []
                break
        else:
            low_since = None
            while pending and len(running) < a.parallel:
                running.append(start(pending.pop(0)))
        for p, j in list(running):
            if p.poll() is not None:
                running.remove((p, j))
                name, g, pack, out = j[0], j[1], j[2], j[5]
                open(out + ".rc", "w").write(f"{p.returncode}\n")  # negative: killed by that signal
                st = shard_status(os.path.dirname(out), g, pack, truths[name], shard_tag(j))
                if p.returncode == 0 and st["complete"]:
                    json.dump(
                        dict(
                            complete=True,
                            rc=0,
                            **{
                                k: st[k]
                                for k in ("expected_total", "decided_total", "expected_in_scope", "decided_in_scope")
                            },
                        ),
                        open(out + ".ok", "w"),
                    )
                else:
                    bad.append(st)
                print(
                    f"[s7gate] {name} {g} {pack} rc={p.returncode} {time.time() - t0:.0f}s load={open('/proc/loadavg').read().split()[0]}"
                    + (
                        ""
                        if st["complete"] and p.returncode == 0
                        else f" INCOMPLETE ({'; '.join(st['reasons']) or 'exit status ' + str(p.returncode)}; decided {st['decided_in_scope']} of {st['expected_in_scope']} in-scope)"
                    ),
                    flush=True,
                )
        time.sleep(2)
    # The run's completeness is the run dir's, not this invocation's (s7-hookscorerev): a --resume / --only subset that finishes cleanly must not
    # mark the run complete while shards outside it are still incomplete.
    prev = {}
    try:
        prev = json.load(open(f"{a.out}/RUN.json"))
    except (OSError, ValueError):
        pass
    run_packs = [p for p in PACKS if p in set(packs) | set(prev.get("packs") or [])] + [
        p for p in packs if p not in PACKS
    ]
    seen = set()
    allbad = []
    for x in run_completeness(a.out, run_packs, truths) + [
        dict(x, shard=x.get("shard")) for x in bad if "not started" in "".join(x.get("reasons") or [])
    ]:
        k = (x.get("shard"), x.get("pack"))
        if k not in seen:
            seen.add(k)
            allbad.append(x)
    if allbad and not bad:
        print(
            f"[s7gate] INCOMPLETE: this invocation's shards finished, but {len(allbad)} shards of the run dir are not complete (outside this --resume/--only set): "
            + "; ".join(f"{x['shard']} {x['pack']}: {', '.join(x['reasons'])}" for x in allbad[:6]),
            flush=True,
        )
    bad = allbad
    json.dump(
        {
            "bin": a.bin,
            "policy_dir": a.policy_dir,
            "packs": run_packs,
            "harness_args": a.harness_args or "",
            "finished": time.strftime("%FT%TZ", time.gmtime()),
            **stamp,
            "split_version": HOLD.load()["version"],
            "split_sha256": HOLD.sha256(),
            "scratch_cap_mb": cap_mb,
            "scratch_dir": scratch_root,
            "scratch_tmpfs": on_tmpfs,
            "fixture_fs": "hermetic" if supports_fixture_fs(a.bin) and not os.environ.get("S7_LIVE_FS") else "live",
            "fixture_root": fixture_root(a.out),
            "complete": not bad,
            "incomplete_shards": [
                dict(
                    shard=x.get("shard"),
                    pack=x.get("pack"),
                    reasons=x.get("reasons"),
                    missing_in_scope=x.get("missing_in_scope"),
                )
                for x in bad
            ],
        },
        open(f"{a.out}/RUN.json", "w"),
    )
    if getattr(a, "dm_key_file", ""):
        try:
            os.remove(a.dm_key_file)
        except OSError:
            pass
    if bad:
        print(
            f"[s7gate] INCOMPLETE: {len(bad)} of {len(jobs)} shards did not finish cleanly; rerun with --resume (only those shards run again)",
            flush=True,
        )
    return not bad


def load_decisions(dirp, pack, col="rules"):
    pred = {}
    import glob

    for f in glob.glob(f"{dirp}/*-{pack}*.jsonl"):
        if os.path.basename(f).startswith("ids."):
            continue
        for line in open(f):
            r = json.loads(line)
            p = pred.setdefault(
                r["case"],
                dict(
                    fb=0,
                    unsup=False,
                    block=False,
                    alert=False,
                    n=0,
                    err=0,
                    evb=0,
                    eva=0,
                    rules=set(),
                    blockrules=set(),
                    cause=None,
                    ex=[],
                    jc=[],
                    hook_ms=[],
                    untimed_prompt=0,
                    pjc=[],
                    prompted=0,
                    prompt_ms=[],
                    jc0=0,
                    n0=0,
                ),
            )
            p["n"] += 1
            p["err"] += 1 if r.get("err") else 0
            p["jc"].extend(r.get("judge_calls") or [])
            # The opening UserPromptSubmit of a tool-call session has its own fields on the idx 0 row (rel-1-0-10:GAP-0650): its judge requests and its
            # hook latency. A row written before that carries neither, and its judge_calls then hold the prompt's requests and the first tool call's.
            p["pjc"].extend(r.get("prompt_judge_calls") or [])
            if r.get("prompt_lat_us", 0) > 0:
                p["prompted"] += 1
                p["prompt_ms"].append(r["prompt_lat_us"] / 1000)
            if r.get("mapped") != "prompt" and r.get("idx", 0) == 0:
                p["n0"] += 1
                p["jc0"] += len(r.get("judge_calls") or [])
            if r.get("mapped") == "prompt":
                # A prompt row is one call, idx 0, so the tool-call rule (idx > 0, the first call of a session carries harness start-up) would drop every
                # one of them (rel-1-0-10:GAP-0613). Its latency is the UserPromptSubmit hook call's, timed by the harness; a row written before that
                # (lat_us 0) was never timed and is counted apart, never as a 0 ms call.
                if r.get("lat_us", 0) > 0:
                    p["hook_ms"].append(r["lat_us"] / 1000)
                else:
                    p["untimed_prompt"] += 1
            elif r.get("idx", 0) > 0:
                p["hook_ms"].append(r.get("lat_us", 0) / 1000)  # the first call of a session carries harness start-up
            if (r.get("extra") or {}).get("connector_fallback"):
                p["fb"] += 1
            if r.get("mapped") == "mcp" and (r.get("src_tool") or "").lower() in UNSUPPORTED_TOOLS:
                p["unsup"] = True  # legacy harness: a native tool reached the hook as an unknown MCP call
            act, ract = r.get("action"), r.get("raw_action")
            rfind, rrules = r.get("findings") or [], r.get("rule_ids") or []
            if r.get("mapped") == "prompt":
                # prompt surface (rel-1-0-10:GAP-0554): what a coding agent gets is the UserPromptSubmit hook answer, and every column except
                # "inspect" scores it. A run made with the fixed harness writes it as the action (extra.scored_via hook; the proxy text inspection in
                # extra.inspect_*). A run made before the fix wrote the text inspection as the action and the hook answer in extra.hook_*: it is
                # re-scored from extra.hook_* (s7-hookscorerev: the default column was "as written", so an old record re-scored without
                # --effects-column hook still scored InspectText). An old hook answer with no action (no JSON or not HTTP 200) is an error row.
                # Column "inspect" scores the text inspection of either kind of run (diagnostic only).
                ex = r.get("extra") or {}
                old = "hook_action" in ex and ex.get("scored_via") != "hook"
                if col == "inspect":
                    if "inspect_action" in ex:
                        act = ract = ex["inspect_action"]
                        rfind, rrules = [f for f in (ex.get("inspect_findings") or "").split(",") if f], []
                    p["via"] = "inspect"
                elif old:
                    act, ract = ex["hook_action"], ex.get("hook_raw_action") or ex["hook_action"]
                    rfind, rrules = [f for f in (ex.get("hook_findings") or "").split(",") if f], []
                    if not act or (r.get("status") not in (None, 200)):
                        p["err"] += 0 if r.get("err") else 1
                    p["via"] = "hook (old record, extra.hook_*)"
                else:
                    p["via"] = "hook"
            b = act == "block"
            al = b or ract in ("block", "alert", "confirm") or act in ("alert", "confirm")
            if col in ("restricted", "full"):
                e = (r.get("det") or {}).get("effect" if col == "restricted" else "effect_full") or {}
                ea = e.get("action")
                b = b or ea == "block"
                al = al or ea in ("block", "alert")
            p["block"] |= b
            p["alert"] |= al
            p["evb"] += b
            p["eva"] += al
            rid = set(rrules) | {f.split(":", 1)[0] for f in rfind if not f.startswith("codeguard:")}
            if al:
                p["rules"] |= rid
            if b:
                p["blockrules"] |= rid
            # miss-cause evidence, kept for the first event only
            if p["cause"] is None or (not al and p["cause"] is not None):
                det = r.get("det") or {}
                dfs = det.get("findings") or []
                p["cause"] = (
                    r.get("mapped"),
                    det.get("parse"),
                    tuple(sorted({f.get("disp") for f in dfs})),
                    tuple(sorted({f.get("sev") for f in dfs if f.get("disp") == "enforceable"})),
                    r.get("sev"),
                    al,
                )
    return pred


def miss_cause(p):
    if p["block"]:
        return None
    mapped, parse, disps, sevs, sev, alerted = p["cause"] or (None,) * 6
    if mapped == "shell" and parse is None and not disps:
        return "not recorded: lean run keeps no parse status (see the full-fidelity attack-only run)"
    if alerted:
        if "detect_only" in disps and "enforceable" not in disps:
            return "alert only: finding is detection-only (parser/proof cannot enforce)"
        if sevs and "CRITICAL" not in sevs:
            return "alert only: enforceable finding below block_at (HIGH/MEDIUM)"
        if "enforceable" in disps:
            return "alert only: enforceable CRITICAL not blocked (check)"
        return "alert only: other"
    if mapped != "shell":
        return "miss: no shell surface (file/MCP/app tool; harm is in the semantics or the sequence)"
    if parse in ("partial", "unknown", "unsupported", "", None):
        return "miss: shell parse partial/unknown and no fallback rule"
    if disps:
        return "miss: findings only audit/advisory"
    return "miss: shell parsed, no rule covers the effect"


def cell(tp, fp, fn, tn):
    P = tp / (tp + fp) if tp + fp else float("nan")
    R = tp / (tp + fn) if tp + fn else float("nan")
    F = 2 * P * R / (P + R) if P == P and R == R and P + R else 0.0
    return dict(
        pos=tp + fn,
        neg=fp + tn,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=P,
        recall=R,
        fpr=fp / (fp + tn) if fp + tn else float("nan"),
        f1=F,
        recall_ci=wilson(int(tp), int(tp + fn))[1:],
        fpr_ci=wilson(int(fp), int(fp + tn))[1:],
    )


def wcell(rows):
    """rows: (attack, flagged, weight). Precision, recall, FPR, F1 at corpus prevalence."""
    tp = sum(w for y, yh, w in rows if y and yh)
    fp = sum(w for y, yh, w in rows if not y and yh)
    fn = sum(w for y, yh, w in rows if y and not yh)
    tn = sum(w for y, yh, w in rows if not y and not yh)
    P = tp / (tp + fp) if tp + fp else float("nan")
    R = tp / (tp + fn) if tp + fn else float("nan")
    return dict(
        precision=P,
        recall=R,
        fpr=fp / (fp + tn) if fp + tn else float("nan"),
        f1=2 * tp / (2 * tp + fp + fn) if tp else 0.0,
    )


def wboot(rows, n=500):
    """95% label-stratified case bootstrap of wcell (seeded), so the sample design is kept."""
    if not rows:
        return {}
    rnd = random.Random(741983)
    pos = [r for r in rows if r[0]]
    neg = [r for r in rows if not r[0]]
    acc = collections.defaultdict(list)
    for _ in range(n):
        m = wcell([pos[rnd.randrange(len(pos))] for _ in pos] + [neg[rnd.randrange(len(neg))] for _ in neg])
        for k, v in m.items():
            if v == v:
                acc[k].append(v)
    q = lambda v, x: sorted(v)[min(len(v) - 1, int(x * len(v)))]
    return {k: [q(v, 0.025), q(v, 0.975)] for k, v in acc.items() if v}


def pctl(xs, x):
    return sorted(xs)[min(len(xs) - 1, int(x * len(xs)))] if xs else None


FALLBACK_CHARS_PER_TOKEN = 3.0  # s7proxy's own cap-reservation ratio; used only when a run has no answered call with a request size to calibrate on
ALL_SENT_BASIS = (
    "every request sent to a model: answered calls at the usage they returned; a cut or failed call at the usage the harness recorded for it, "
    "else its input from the request size (chars per token taken from this run's answered calls) and its output as 0, so the figure is a lower bound; "
    "a request the cache-only proxy refused and a provider HTTP error status are not priced"
)


def judge_call_class(c):
    """answered | cut | failed | refused | rejected. cut and failed requests were sent; refused (the cache-only replay proxy turned a miss away) and
    rejected (the provider answered with an HTTP 4xx/5xx status, which is not billed) were not."""
    err = c.get("err") or ""
    if not err:
        return "answered"
    if "cache-only" in err:
        return "refused"
    if c.get("cancelled") or "cancel" in err or "deadline" in err:
        return "cut"
    if re.search(r"returned [45]\d\d\b", err):
        return "rejected"
    return "failed"


def judge_cost(calls, model):
    """What a set of judge calls cost, answered-only and all-sent (rel-1-0-10:GAP-0649). Tokens are exact where a call recorded usage."""
    cls = [(judge_call_class(c), c) for c in calls]
    ans = [c for k, c in cls if k == "answered"]
    sent = [c for k, c in cls if k in ("answered", "cut", "failed")]
    cal = [c for c in ans if c.get("req_chars") and c.get("in_tok")]
    cpt = sum(c["req_chars"] for c in cal) / sum(c["in_tok"] for c in cal) if cal else FALLBACK_CHARS_PER_TOKEN
    pi, po = JUDGE_PRICE.get(model, (float("nan"), float("nan")))
    a_in = sum(c.get("in_tok") or 0 for c in ans)
    a_out = sum(c.get("out_tok") or 0 for c in ans)
    s_in = s_out = est = 0.0
    unpriced = 0
    for c in sent:
        i, o = c.get("in_tok") or 0, c.get("out_tok") or 0
        if i or o:
            s_in += i
            s_out += o
        elif c.get("req_chars"):
            e = c["req_chars"] / cpt
            s_in += e
            est += e
        else:
            unpriced += 1
    cnt = collections.Counter(k for k, _ in cls)
    return dict(
        calls=len(calls),
        answered=cnt["answered"],
        cut=cnt["cut"],
        failed_in_transport=cnt["failed"],
        refused_not_sent=cnt["refused"],
        rejected_http=cnt["rejected"],
        sent=len(sent),
        answered_in_tok=a_in,
        answered_out_tok=a_out,
        usd_answered=(a_in * pi + a_out * po) / 1e6,
        all_sent=dict(
            calls=len(sent),
            in_tok=round(s_in),
            out_tok=round(s_out),
            in_tok_estimated=round(est),
            unpriced_calls=unpriced,
            chars_per_token=cpt,
            usd=(s_in * pi + s_out * po) / 1e6,
            basis=ALL_SENT_BASIS,
        ),
    )


def judge_stats(pred, ids, model, prompt_from_content=False):
    calls = [c for i in ids for c in pred[i]["jc"]]
    pcalls = [c for i in ids for c in pred[i].get("pjc", [])]
    tool_calls = sum(pred[i]["n"] for i in ids)
    if not calls and not pcalls:
        return None
    cut = [c for c in calls if c.get("cancelled") or "cancel" in (c.get("err") or "")]
    failed = [c for c in calls if c.get("err") and c not in cut]
    ans = [c for c in calls if not c.get("err")]
    lat = [c["latency_ms"] for c in ans]
    hook = [x for i in ids for x in pred[i]["hook_ms"]]
    tin = sum(c.get("in_tok") or 0 for c in ans)
    tout = sum(c.get("out_tok") or 0 for c in ans)
    pi, po = JUDGE_PRICE.get(model, (float("nan"), float("nan")))
    usd = (tin * pi + tout * po) / 1e6
    jcst = judge_cost(calls, model)
    asd = dict(jcst["all_sent"])
    asd["usd_per_1k_tool_calls"] = asd["usd"] / max(1, tool_calls) * 1000
    n0 = sum(pred[i].get("n0", 0) for i in ids)
    jc0 = sum(pred[i].get("jc0", 0) for i in ids)
    prompted = sum(pred[i].get("prompted", 0) for i in ids)
    out = dict(
        model=model,
        tool_calls=tool_calls,
        judge_calls=len(calls),
        per_tool_call=len(calls) / max(1, tool_calls),
        answered=len(ans),
        parse_failed=sum(1 for c in ans if not c.get("parsed")),
        failed=len(failed),
        cut_at_window=len(cut),
        cut_share=len(cut) / max(1, len(calls)),
        p50_ms=pctl(lat, 0.5),
        p95_ms=pctl(lat, 0.95),
        p99_ms=pctl(lat, 0.99),
        hook_p50_ms=pctl(hook, 0.5),
        hook_p95_ms=pctl(hook, 0.95),
        hook_over_window=sum(1 for x in hook if x > WINDOW_MS) / max(1, len(hook)),
        hook_over_window_basis=f"share of hook calls over {WINDOW_MS} ms, the tool-call answer window; a prompt hook call is measured against the same figure and has no window of its own in the product",
        in_tok_avg=tin / max(1, len(ans)),
        out_tok_avg=tout / max(1, len(ans)),
        usd=usd,
        usd_per_1k_tool_calls=usd / max(1, tool_calls) * 1000,
        usd_basis="answered-only (the calls that came back with usage)",
        answered_in_tok=tin,
        answered_out_tok=tout,
        all_sent=asd,
        idx0_rows=n0,
        idx0_judge_calls=jc0,
        judge_calls_after_idx0=len(calls) - jc0,
        per_call_after_idx0=(len(calls) - jc0) / max(1, tool_calls - n0),
        prompt_rows_untimed=sum(pred[i]["untimed_prompt"] for i in ids),
    )
    if pcalls or prompted:
        pc = judge_cost(pcalls, model)
        pms = [x for i in ids for x in pred[i].get("prompt_ms", [])]
        out["prompt_cost"] = dict(
            sessions=prompted,
            judge_calls=len(pcalls),
            per_session=len(pcalls) / max(1, prompted),
            usd_answered=pc["usd_answered"],
            usd_all_sent=pc["all_sent"]["usd"],
            usd_per_1k_sessions_answered=pc["usd_answered"] / max(1, prompted) * 1000,
            usd_per_1k_sessions_all_sent=pc["all_sent"]["usd"] / max(1, prompted) * 1000,
            hook_p50_ms=pctl(pms, 0.5),
            hook_p95_ms=pctl(pms, 0.95),
            detail=pc,
            note="the opening UserPromptSubmit of each tool-call session, charged to the prompt (rel-1-0-10:GAP-0650); judge_calls above and per_tool_call hold the tool calls' own requests",
        )
    elif prompt_from_content and jc0:
        # A run made before GAP-0650: the opening prompt's requests sit in the idx 0 rows' judge_calls and the rows cannot be told apart.
        out["prompt_calls_in_idx0_rows_legacy"] = True
        out["legacy_note"] = (
            f"made with -prompt-from-content before the harness separated the opening prompt (GAP-0650): its judge calls are inside the {n0} idx-0 rows ({jc0} calls, "
            f"{jc0 / max(1, n0):.2f} per row against {out['per_call_after_idx0']:.3f} per later tool call), so per_tool_call and the USD per 1k tool calls charge the prompt to the first tool call; "
            "per_call_after_idx0 is the tool-call rate with those rows left out"
        )
    return out


def judge_line(model, js):
    """The judge part of a SUMMARY cell line: answered-only and all-sent cost side by side, hook latency labelled with its window, the prompt's own line."""
    s = (
        f" | judge {model}: {js['per_tool_call']:.2f}/call, p50 {js['p50_ms']} p95 {js['p95_ms']} ms, cut {js['cut_share']:.3f}, parse-fail {js['parse_failed']}, "
        f"USD/1k calls answered-only {js['usd_per_1k_tool_calls']:.3f}, all-sent {js['all_sent']['usd_per_1k_tool_calls']:.3f}"
    )
    if js["all_sent"]["unpriced_calls"]:
        s += f" ({js['all_sent']['unpriced_calls']} sent calls carry no size or usage and are not priced)"
    if js.get("hook_p50_ms") is not None:
        s += f", hook p50 {js['hook_p50_ms']:.0f} p95 {js['hook_p95_ms']:.0f} ms, {100 * js['hook_over_window']:.1f}% over {WINDOW_MS / 1000:g} s (the tool-call window)"
    pc = js.get("prompt_cost")
    if pc:
        s += f", prompt cost own line: {pc['judge_calls']} calls over {pc['sessions']} sessions ({pc['per_session']:.2f}/session), USD/1k sessions answered-only {pc['usd_per_1k_sessions_answered']:.3f}, all-sent {pc['usd_per_1k_sessions_all_sent']:.3f}"
    if js.get("prompt_calls_in_idx0_rows_legacy"):
        s += f", NOTE: UserPromptSubmit judge calls are inside the idx-0 rows (run made before GAP-0650); {js['per_call_after_idx0']:.3f}/call after idx 0"
    if js.get("prompt_rows_untimed"):
        s += f", {js['prompt_rows_untimed']} prompt rows carry no timing (written before GAP-0613: re-run for latency)"
    return s


def proxy_totals(path, model):
    """Run-level totals of an s7proxy log (one run's): every judge request the proxy took, exact tokens, priced at the list price. Cache hits count, as in
    the answered figure (a hit is a request the product sent). A refused miss was never sent to a model; a client-abort record is a request whose caller had
    gone (its tokens are on the request's own line)."""
    n = hits = refused = aborted = other = 0
    tin = tout = 0
    for l in open(path):
        try:
            r = json.loads(l)
        except ValueError:
            continue
        if r.get("cache_miss_refused"):
            refused += 1
        elif "in_tok" in r:
            n += 1
            hits += 1 if r.get("cache_hit") else 0
            tin += r.get("in_tok") or 0
            tout += r.get("out_tok") or 0
        elif r.get("error"):
            if "BrokenPipe" in r["error"] or "ConnectionReset" in r["error"]:
                aborted += 1
            else:
                other += 1
    pi, po = JUDGE_PRICE.get(model, (float("nan"), float("nan")))
    return dict(
        path=os.path.basename(path),
        requests=n,
        cache_hits=hits,
        live_requests=n - hits,
        in_tok=tin,
        out_tok=tout,
        usd=(tin * pi + tout * po) / 1e6,
        refused_not_sent=refused,
        client_abort_records=aborted,
        other_error_records=other,
    )


def judge_cost_report(out, jcells, proxy_path, model):
    """Run-level judge cost over the scored cells, answered-only and all-sent side by side (+ the proxy log's exact all-sent when given). Writes OUT/judge_cost.json."""
    if not jcells:
        return []
    T = collections.Counter()
    for _, _, js in jcells:
        T["tool_calls"] += js["tool_calls"]
        T["judge_calls"] += js["judge_calls"]
        T["a_in"] += js["answered_in_tok"]
        T["a_out"] += js["answered_out_tok"]
        T["usd_a"] += js["usd"]
        T["s_in"] += js["all_sent"]["in_tok"]
        T["s_out"] += js["all_sent"]["out_tok"]
        T["s_est"] += js["all_sent"]["in_tok_estimated"]
        T["usd_s"] += js["all_sent"]["usd"]
        T["unpriced"] += js["all_sent"]["unpriced_calls"]
        pc = js.get("prompt_cost")
        if pc:
            T["p_sessions"] += pc["sessions"]
            T["p_calls"] += pc["judge_calls"]
            T["p_usd_a"] += pc["usd_answered"]
            T["p_usd_s"] += pc["usd_all_sent"]
        if js.get("prompt_calls_in_idx0_rows_legacy"):
            T["legacy_cells"] += 1
    tc = max(1, T["tool_calls"])
    rep = dict(
        model=model,
        cells=len(jcells),
        rows=T["tool_calls"],
        judge_calls=T["judge_calls"],
        answered_only=dict(
            in_tok=T["a_in"], out_tok=T["a_out"], usd=T["usd_a"], usd_per_1k_rows=T["usd_a"] / tc * 1000
        ),
        all_sent_harness=dict(
            in_tok=T["s_in"],
            out_tok=T["s_out"],
            in_tok_estimated=T["s_est"],
            unpriced_calls=T["unpriced"],
            usd=T["usd_s"],
            usd_per_1k_rows=T["usd_s"] / tc * 1000,
            basis=ALL_SENT_BASIS,
        ),
        prompt_cost=dict(
            sessions=T["p_sessions"], judge_calls=T["p_calls"], usd_answered=T["p_usd_a"], usd_all_sent=T["p_usd_s"]
        )
        if T["p_sessions"]
        else None,
        legacy_cells_prompt_in_idx0=T["legacy_cells"],
    )
    lines = [
        f"- judge cost over {len(jcells)} scored cells ({T['tool_calls']} rows, {T['judge_calls']} judge calls), USD {model}: answered-only {T['usd_a']:.4f} ({T['usd_a'] / tc * 1000:.3f}/1k rows), "
        f"all-sent by the harness record {T['usd_s']:.4f} ({T['usd_s'] / tc * 1000:.3f}/1k rows; {T['s_est']:.0f} input tokens estimated from request size, output of unanswered calls counted as 0)"
    ]
    if proxy_path:
        px = proxy_totals(proxy_path, model)
        rep["all_sent_proxy"] = px
        lines[-1] += (
            f"; all-sent by the proxy log {px['usd']:.4f} ({px['requests']} requests, {px['in_tok']} in / {px['out_tok']} out tokens, exact, whole run: {px['usd'] / tc * 1000:.3f}/1k rows; {px['refused_not_sent']} refused, {px['client_abort_records']} client-abort records)"
        )
    if T["p_sessions"]:
        lines.append(
            f"- tool-call prompt cost (own line, GAP-0650): {T['p_calls']} judge calls over {T['p_sessions']} sessions, USD answered-only {T['p_usd_a']:.4f}, all-sent {T['p_usd_s']:.4f}"
        )
    if T["legacy_cells"]:
        lines.append(
            f"- {T['legacy_cells']} cells were run before the harness separated the opening prompt (GAP-0650): their judge calls include the prompt's, charged to idx 0"
        )
    json.dump(rep, open(f"{out}/judge_cost.json", "w"), indent=1)
    return lines


def prompt_from_content_of(run):
    return "-prompt-from-content" in ((run or {}).get("harness_args") or "").replace(",", " ").split()


def run_stamp(binpath):
    """Host, code commit and build stamp of a run, recorded in RUN.json (the Sunday runs depend on it). The commit is S7_CODE_COMMIT when s7-gate set it (a
    worktree run), else the binary's own vcs.revision; with neither the run is unstamped and says so. The build stamp is read from the binary itself:
    sha256, size, mtime, the Go version and the vcs.* / tags build settings that Go embeds."""
    bp = os.path.expanduser(binpath)
    build = dict(bin=binpath)
    try:
        data = open(bp, "rb").read()
        build.update(
            bin_sha256=hashlib.sha256(data).hexdigest(),
            bin_bytes=len(data),
            bin_mtime=time.strftime("%FT%TZ", time.gmtime(os.path.getmtime(bp))),
        )
        k = data.find(b"\xff Go buildinf:")
        m = re.search(rb"go1\.\d+(?:\.\d+)?", data[k : k + 256]) if k >= 0 else None
        if m:
            build["go_version"] = m.group(0).decode()
        for key, pat in (
            ("vcs_revision", rb"vcs\.revision=([0-9a-f]{40})"),
            ("vcs_time", rb"vcs\.time=(\d{4}-\d\d-\d\dT[0-9:]+Z)"),
            ("vcs_modified", rb"vcs\.modified=(true|false)"),
            ("tags", rb"-tags=([A-Za-z0-9_,]+)"),
        ):
            m = re.search(pat, data)
            if m:
                build[key] = m.group(1).decode()
    except OSError as e:
        build["error"] = f"{type(e).__name__}: cannot read the binary"
    commit, how = os.environ.get("S7_CODE_COMMIT", "").strip(), "S7_CODE_COMMIT"
    if not commit and build.get("vcs_revision"):
        commit, how = build["vcs_revision"], "binary vcs stamp"
    if not commit:
        how = "none"
    dirty = os.environ.get("S7_CODE_DIRTY", "").strip().lower()
    dirty = (
        dirty in ("1", "true", "yes")
        if dirty
        else (build.get("vcs_modified") == "true" if build.get("vcs_modified") else None)
    )
    return dict(
        host=os.environ.get("S7_RUN_HOST", "").strip() or socket.gethostname(),
        hostname=socket.gethostname(),
        code_commit=commit,
        code_commit_source=how,
        code_ref=os.environ.get("S7_CODE_REF", ""),
        code_dirty=dirty,
        stamped=bool(commit),
        build=build,
    )


def judge_model_of(run):
    ha = (run or {}).get("harness_args") or ""
    t = ha.replace(",", " ").split()
    return t[t.index("-judge-model") + 1].split("#")[0] if "-judge-model" in t else None


def split_headline(sel, truth, pred, weights, sampled):
    """The numbers every report quotes, on the cases of one side of the frozen split (tune or holdout): block and alert cells, recall on the expected-block cases,
    event false rates, rates at corpus prevalence for a sampled corpus, and the same cells per tool surface. No rule names and no case ids: this is what a lane may report."""
    out = dict(
        cases=len(sel),
        benign=sum(1 for i in sel if truth[i]["state"] == "benign"),
        attack=sum(1 for i in sel if truth[i]["state"] == "attack"),
    )
    for key in ("block", "alert"):
        c = collections.Counter((truth[i]["state"] == "attack", pred[i][key]) for i in sel)
        out[key] = cell(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])
        if sampled and sel:
            rows = [(truth[i]["state"] == "attack", pred[i][key], weights.get(i, 1)) for i in sel]
            out[key]["weighted"] = wcell(rows)
            out[key]["weighted_ci"] = wboot(rows)
    tp = sum(1 for i in sel if truth[i]["state"] == "attack" and truth[i]["blockpos"] and pred[i]["block"])
    fn = sum(1 for i in sel if truth[i]["state"] == "attack" and truth[i]["blockpos"] and not pred[i]["block"])
    fpb = sum(1 for i in sel if truth[i]["state"] == "benign" and pred[i]["block"])
    tnb = out["benign"] - fpb
    out["block_on_expected_block"] = cell(tp, fpb, fn, tnb)
    bev = sum(pred[i]["n"] for i in sel if truth[i]["state"] == "benign")
    out["event_fpr_block"] = sum(pred[i]["evb"] for i in sel if truth[i]["state"] == "benign") / max(1, bev)
    out["event_fpr_alert"] = sum(pred[i]["eva"] for i in sel if truth[i]["state"] == "benign") / max(1, bev)
    by = collections.defaultdict(list)
    for i in sel:
        by[truth[i]["tsurface"]].append(i)
    out["surfaces"] = {}
    for sname, ss in by.items():
        gg = {
            "cases": len(ss),
            "benign": sum(1 for i in ss if truth[i]["state"] == "benign"),
            "attack": sum(1 for i in ss if truth[i]["state"] == "attack"),
        }
        for key in ("block", "alert"):
            c = collections.Counter((truth[i]["state"] == "attack", pred[i][key]) for i in ss)
            gg[key] = cell(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])
        out["surfaces"][sname] = gg
    return out


def split_line(h):
    """One compact SUMMARY line for one side of the split."""
    if not h["cases"]:
        return "none"
    b, al = h["block"], h["alert"]
    f = lambda x: "nan" if x != x else f"{x:.4f}"
    return (
        f"benign {b['neg']}, attack {b['pos']} | block recall {f(b['recall'])} {tuple(round(x, 3) for x in b['recall_ci'])}, alert recall {f(al['recall'])} | "
        f"false-block {f(b['fpr'])} {tuple(round(x, 5) for x in b['fpr_ci'])} ({b['fp']}), false-alert {f(al['fpr'])} {tuple(round(x, 5) for x in al['fpr_ci'])} ({al['fp']}) | F1 block {f(b['f1'])} alert {f(al['f1'])}"
    )


# --- labels v3 (s7-relabel lane): the default label set the scorer applies on top of the corpus files -----------------------------------
def default_labels():
    return os.path.expanduser(os.environ.get("S7_LABELS_DEFAULT") or "~/s7c/labels/current.jsonl")


def resolve_labels(a):
    """(path, info) of the overlay the scorer applies. --reviews (explicit, as before) wins; else --labels PATH; else $S7_LABELS; else
    ~/s7c/labels/current.jsonl when it exists. --labels none switches the default off. info records what was applied (sha256, rows, version)."""
    ex = getattr(a, "reviews", None)
    lab = getattr(a, "labels", "") or os.environ.get("S7_LABELS", "")
    if ex:
        path = ex
    elif lab == "none":
        return None, None
    else:
        path = lab or default_labels()
    if not path or not os.path.exists(path):
        # review F6: never fall back silently. A score without its label set cannot be compared with one that has it.
        raise SystemExit(
            f"s7gate: label file {path or '(none)'} not found. The default is {default_labels()} (copied by `s7gate.py push-labels` or s7-gate push_labels); pass --labels none to score the corpus files as they stand, on purpose."
        )
    raw = open(path, "rb").read()
    a._label_bytes = raw
    man = path[: -len(".jsonl")] + ".manifest.json" if path.endswith(".jsonl") else ""
    ver = ""
    if man and os.path.exists(man):
        try:
            ver = json.load(open(man)).get("version", "")
        except Exception:
            ver = ""
    return path, dict(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        rows=sum(1 for l in raw.splitlines() if l.strip()),
        version=ver,
        explicit=bool(ex),
    )


def stamp_run_labels(out, info, droot=None):
    """Record the label set in OUT/RUN.json (a rescore into a new OUT copies the run it scored first)."""
    rp = os.path.join(out, "RUN.json")
    try:
        run = (
            json.load(open(rp))
            if os.path.exists(rp)
            else (
                json.load(open(os.path.join(droot, "RUN.json")))
                if droot and os.path.exists(os.path.join(droot, "RUN.json"))
                else {}
            )
        )
    except Exception:
        run = {}
    run["labels"] = info
    if droot and droot != out:
        run["rescored_from"] = droot
    tmp = rp + ".tmp"
    json.dump(run, open(tmp, "w"))
    os.replace(tmp, rp)


def push_labels(src, dest, name="labels-v3"):
    """Copy SRC/<name>.jsonl and SRC/<name>.manifest.json to DEST/current.jsonl and DEST/current.manifest.json, each
    through a temp file, and check the sha256 of every copy. Every failure (missing source, unwritable destination, a
    copy that does not match) exits 4 with the step that failed: nothing is hidden, nothing is partial."""
    for ext in (".jsonl", ".manifest.json"):
        sp = os.path.join(src, name + ext)
        if not os.path.isfile(sp):
            raise SystemExit(f"s7gate: push-labels: {sp} is missing; the scorer would refuse to score")
    try:
        os.makedirs(dest, exist_ok=True)
    except OSError as e:
        raise SystemExit(f"s7gate: push-labels: cannot create {dest}: {e}") from e
    for ext, dst in ((".jsonl", "current.jsonl"), (".manifest.json", "current.manifest.json")):
        sp, dp = os.path.join(src, name + ext), os.path.join(dest, dst)
        try:
            shutil.copyfile(sp, dp + ".tmp")
            os.replace(dp + ".tmp", dp)
        except OSError as e:
            raise SystemExit(f"s7gate: push-labels: copy {sp} -> {dp} failed: {e}") from e
        if file_sha256(sp) != file_sha256(dp):
            raise SystemExit(f"s7gate: push-labels: {dp} does not match {sp} after the copy")
    print(f"push-labels: {name} -> {dest}/current.* sha256 {file_sha256(os.path.join(dest, 'current.jsonl'))[:16]}")


def cmd_push_labels(a):
    try:
        push_labels(a.src, a.dest, a.name)
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
            sys.exit(4)
        raise


def top_counts(counter, n=None):
    """counter.most_common(n) with ties broken by key: Counter keeps insertion order for equal counts, and the scorer's
    insertion order is not stable between processes, so two scorings of one run listed equal-count rules in different
    orders (and could cut a different rule at n)."""
    items = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return [list(kv) for kv in (items if n is None else items[:n])]


def cmd_score(a):
    cfgs = json.load(open(a.corpora))
    droot = getattr(a, "decisions_from", "") or a.out
    col = getattr(a, "effects_column", "rules") or "rules"
    reviews = {}
    tags = {}
    dispo = {}
    pinned = getattr(a, "resolved_labels", None)
    lab_path, lab_info = resolve_labels(a)  # read again now: the bytes parsed below are the bytes hashed here
    if pinned and pinned[1] and (lab_info or {}).get("sha256") != pinned[1]["sha256"]:
        raise SystemExit(
            f"s7gate: label file {lab_path} changed during the run (sha256 {pinned[1]['sha256'][:16]} at the start, "
            f"{(lab_info or {}).get('sha256', 'none')[:16]} now; s7-gate push_labels replaces current.jsonl): no score is "
            f"written. Rescore the run under one label set: s7gate.py score --decisions-from {a.out} --out <new> "
            "--labels <file>"
        )
    if lab_path:
        for l in a._label_bytes.decode("utf-8").split("\n"):
            l = l.rstrip("\r")
            if not l:
                continue
            if l.startswith("{"):
                r = json.loads(l)
                if r.get("source_truth"):
                    reviews[r["id"]] = r["source_truth"]
                if r.get("expected_disposition"):
                    dispo[r["id"]] = r["expected_disposition"]
            else:
                i_, _, tg = l.partition("\t")
                tags[i_] = tg or "reviewed"
    os.makedirs(f"{a.out}/scores", exist_ok=True)
    run = json.load(open(droot + "/RUN.json")) if os.path.exists(droot + "/RUN.json") else None
    jmodel = judge_model_of(run)
    md = [
        "# s7gate summary",
        f"run: {run or '?'}",
        f"effects_column: {col}",
        f"labels: {lab_info['version'] or 'overlay'} sha256 {lab_info['sha256'][:16]} ({lab_info['rows']} rows, {lab_info['path']})"
        if lab_info
        else "labels: none (corpus files as they stand)",
        "@@STATUS@@",
        "",
    ]
    comp_rows = []
    stamp_run_labels(a.out, lab_info, droot)
    jcells = []
    pfc = prompt_from_content_of(run)
    layers_val = "rules+effects" if col != "rules" else ("rules+judge" if jmodel else "rules")
    hcfg = HOLD.load()
    diag_all = getattr(a, "diagnostics_scope", "tune") == "all"
    md[2:2] = [
        f"split: {hcfg['version']} sha256 {HOLD.sha256()} ({hcfg['percent']}% of each corpus is holdout; tuned regression suites: {', '.join(hcfg['tuned_corpora'])}); diagnostics (rule lists, miss causes, case ids) are from the {'tune and holdout cases (--diagnostics-scope all)' if diag_all else 'tune side only'}"
    ]
    for name, cfg in cfgs.items():
        d = f"{droot}/decisions/{name}"
        if not os.path.isdir(d):
            continue
        if cfg.get("session"):
            # session mode (lane s7-chainbench): one verdict per whole session, see s7session.py
            import s7session

            truth = dict(read_cases(cfg, name))
            for pack in packs_present(d, run):
                cs = corpus_pack_status(d, name, pack, truth)
                comp_rows.append(cs)
                if not cs["complete"]:
                    res = dict(
                        corpus=name,
                        pack=pack,
                        status="incomplete",
                        session=True,
                        layers=layers_val,
                        scorer="s7-gate session",
                        **{
                            k: cs[k]
                            for k in (
                                "expected_total",
                                "decided_total",
                                "expected_in_scope",
                                "decided_in_scope",
                                "missing_total",
                                "missing_in_scope",
                                "partial_cases",
                                "incomplete_shards",
                            )
                        },
                    )
                    json.dump(res, open(f"{a.out}/scores/{name}-{pack}.json", "w"), indent=1, default=list)
                    md.append(
                        f"- {name} / {pack}: INCOMPLETE, no rates: {cs['decided_in_scope']} of {cs['expected_in_scope']} in-scope sessions decided, {cs['missing_in_scope']} missing"
                    )
                    print(md[-1], flush=True)
                    continue
                res, srows = s7session.score_corpus(name, cfg, d, pack, truth, run)
                res.update(
                    layers=layers_val,
                    judge_model=jmodel,
                    labels=lab_info,
                    session=True,
                    split_version=hcfg["version"],
                    split_sha256=HOLD.sha256(),
                    completeness={
                        k: cs[k]
                        for k in ("expected_total", "decided_total", "expected_in_scope", "decided_in_scope", "shards")
                    },
                )
                js = (
                    judge_stats(
                        {i: p_ for i, p_ in load_decisions(d, pack, col).items()},
                        [i for i in truth if truth[i]["state"] != "excluded"],
                        jmodel,
                        pfc,
                    )
                    if jmodel
                    else None
                )
                if js:
                    res["judge"] = js
                    jcells.append((name, pack, js))
                json.dump(res, open(f"{a.out}/scores/{name}-{pack}.json", "w"), indent=1, default=list)
                with open(f"{a.out}/scores/{name}-{pack}.sessions.jsonl", "w") as sf:
                    for r_ in srows:
                        sf.write(json.dumps(r_) + "\n")
                md.extend(s7session.summary_lines(res))
                print(md[-1], flush=True)
            continue
        truth = dict(read_cases(cfg, name))
        weights = {}
        for mf in cfg.get("meta", []):
            if os.path.exists(mf):
                for l in open(mf):
                    m = json.loads(l)
                    weights[m["id"]] = m.get("weight", 1)
        for cid, tr in truth.items():
            if cid in reviews:
                tr["state"] = {"benign": "benign", "malicious": "attack"}.get(reviews[cid], "excluded")
            if cid in dispo:
                tr["blockpos"] = dispo[cid] == "block"
        for pack in packs_present(d, run):
            # Completeness first: a corpus x pack with any shard that died, was killed or left cases undecided gets no rates, only the missing counts.
            cs = corpus_pack_status(d, name, pack, truth)
            comp_rows.append(cs)
            if not cs["complete"]:
                res = dict(
                    corpus=name,
                    pack=pack,
                    status="incomplete",
                    sampled=bool(cfg.get("ids")),
                    layers=layers_val,
                    tier=col,
                    scorer="s7-gate",
                    judge_model=jmodel,
                    **{
                        k: cs[k]
                        for k in (
                            "expected_total",
                            "decided_total",
                            "expected_in_scope",
                            "decided_in_scope",
                            "missing_total",
                            "missing_in_scope",
                            "partial_cases",
                            "incomplete_shards",
                        )
                    },
                )
                json.dump(res, open(f"{a.out}/scores/{name}-{pack}.json", "w"), indent=1, default=list)
                md.append(
                    f"- {name} / {pack}: INCOMPLETE, no rates: {cs['decided_in_scope']} of {cs['expected_in_scope']} in-scope cases decided, {cs['missing_in_scope']} missing"
                    + "; "
                    + "; ".join(f"{x['shard']}: {'; '.join(x['reasons'])}" for x in cs["incomplete_shards"])
                )
                print(md[-1], flush=True)
                continue
            pred = load_decisions(d, pack, col)
            if not pred:
                continue
            unsupported = sum(1 for i in truth if i in pred and truth[i]["state"] != "excluded" and pred[i]["unsup"])
            pvia = collections.Counter(pred[i]["via"] for i in pred if pred[i].get("via"))
            ids = [
                i
                for i in truth
                if i in pred and truth[i]["state"] != "excluded" and (a.include_unsupported or not pred[i]["unsup"])
            ]
            res = dict(
                corpus=name,
                pack=pack,
                layers=layers_val,
                tier=col,
                scorer="s7-gate",
                cases_in_corpus=len(truth),
                scored=len(ids),
                excluded=sum(1 for i in truth if truth[i]["state"] == "excluded"),
                unsupported_tool_cases_not_scored=0 if a.include_unsupported else unsupported,
                missing_decisions=sum(1 for i in truth if i not in pred),
                errors=sum(pred[i]["err"] for i in ids),
                connector_fallback_decisions=sum(pred[i]["fb"] for i in ids),
            )
            for key in ("block", "alert"):
                tp = fp = fn = tn = 0
                for i in ids:
                    y = truth[i]["state"] == "attack"
                    yh = pred[i][key]
                    if y and yh:
                        tp += 1
                    elif y:
                        fn += 1
                    elif yh:
                        fp += 1
                    else:
                        tn += 1
                res[key] = cell(tp, fp, fn, tn)
                wfp = sum(weights.get(i, 1) for i in ids if truth[i]["state"] == "benign" and pred[i][key])
                wn = sum(weights.get(i, 1) for i in ids if truth[i]["state"] == "benign")
                res[key]["fpr_weighted"] = wfp / wn if wn else float("nan")
                res[key]["benign_weight"] = wn
                if cfg.get("ids"):
                    rows = [(truth[i]["state"] == "attack", pred[i][key], weights.get(i, 1)) for i in ids]
                    res[key]["weighted"] = wcell(rows)
                    res[key]["weighted_ci"] = wboot(rows)
            if pvia:
                res["prompt_scored_via"] = dict(pvia)  # rel-1-0-10:GAP-0554: cases per source of the prompt verdict
            res["split_version"] = hcfg["version"]
            res["split_sha256"] = HOLD.sha256()
            res["diagnostics_scope"] = "all" if diag_all else "tune"
            res["tuned_corpus"] = name in hcfg["tuned_corpora"]
            tune_ids = [i for i in ids if truth[i]["split"] == HOLD.TUNE]
            hold_ids = [i for i in ids if truth[i]["split"] == HOLD.HOLDOUT]
            diag_ids = ids if diag_all else tune_ids
            diag_set = set(diag_ids)
            res["split"] = {
                HOLD.TUNE: split_headline(tune_ids, truth, pred, weights, bool(cfg.get("ids"))),
                HOLD.HOLDOUT: split_headline(hold_ids, truth, pred, weights, bool(cfg.get("ids"))),
            }
            res["labels"] = lab_info
            res["status"] = "complete"
            res["completeness"] = {
                k: cs[k] for k in ("expected_total", "decided_total", "expected_in_scope", "decided_in_scope", "shards")
            }
            res["sampled"] = bool(cfg.get("ids"))
            res["layers"] = "rules+judge" if jmodel else "rules"
            res["judge_model"] = jmodel
            js = judge_stats(pred, ids, jmodel, pfc) if jmodel else None
            if js:
                res["judge"] = js
                jcells.append((name, pack, js))
            bev = sum(pred[i]["n"] for i in ids if truth[i]["state"] == "benign")
            res["event_fpr_block"] = sum(pred[i]["evb"] for i in ids if truth[i]["state"] == "benign") / max(1, bev)
            res["event_fpr_alert"] = sum(pred[i]["eva"] for i in ids if truth[i]["state"] == "benign") / max(1, bev)
            # block recall against the cases whose label itself says block (detect-only attacks cannot be blocked by definition)
            tp = fn = 0
            for i in ids:
                if truth[i]["state"] == "attack" and truth[i]["blockpos"]:
                    if pred[i]["block"]:
                        tp += 1
                    else:
                        fn += 1
            fpb = sum(1 for i in ids if truth[i]["state"] == "benign" and pred[i]["block"])
            tnb = sum(1 for i in ids if truth[i]["state"] == "benign") - fpb
            res["block_on_expected_block"] = cell(tp, fpb, fn, tnb)
            groups = {}
            for dim in ("platform", "dialect", "provider", "campaign", "domain", "surface", "dataset", "tool"):
                by = collections.defaultdict(list)
                for i in ids:
                    by[truth[i][dim]].append(i)
                groups[dim] = {}
                for v, sel in by.items():
                    if len(sel) < 5:
                        continue
                    gg = {}
                    for key in ("block", "alert"):
                        c = collections.Counter((truth[i]["state"] == "attack", pred[i][key]) for i in sel)
                        gg[key] = cell(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])
                    groups[dim][v] = gg
            cats = collections.defaultdict(list)
            for i in ids:
                for c in truth[i]["cats"]:
                    cats[c].append(i)
            groups["category"] = {}
            for v, sel in cats.items():
                if len(sel) < 5:
                    continue
                gg = {}
                for key in ("block", "alert"):
                    c = collections.Counter((truth[i]["state"] == "attack", pred[i][key]) for i in sel)
                    gg[key] = cell(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])
                groups["category"][v] = gg
            res["groups"] = groups
            sp = [i for i in ids if truth[i]["state"] == "benign" and tags.get(i) == "self-protection-expected"]
            if tags:
                nb = res["block"]["neg"]
                res["selfprot"] = {
                    "tagged_benign": len(sp),
                    "blocked": sum(1 for i in sp if pred[i]["block"]),
                    "alerted": sum(1 for i in sp if pred[i]["alert"]),
                    "false_block_excl_selfprot": res["block"]["fp"] - sum(1 for i in sp if pred[i]["block"]),
                    "false_alert_excl_selfprot": res["alert"]["fp"] - sum(1 for i in sp if pred[i]["alert"]),
                    "benign": nb,
                }
            surf = {}
            by = collections.defaultdict(list)
            for i in ids:
                by[truth[i]["tsurface"]].append(i)
            for sname, sel in by.items():
                gg = {
                    "cases": len(sel),
                    "calls": sum(pred[i]["n"] for i in sel),
                    "benign": sum(1 for i in sel if truth[i]["state"] == "benign"),
                    "attack": sum(1 for i in sel if truth[i]["state"] == "attack"),
                }
                for key in ("block", "alert"):
                    c = collections.Counter((truth[i]["state"] == "attack", pred[i][key]) for i in sel)
                    gg[key] = cell(c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])
                fpr_rules = collections.Counter()
                for i in sel:
                    if truth[i]["state"] == "benign" and i in diag_set:
                        for rr in pred[i]["rules"]:
                            fpr_rules[rr] += 1
                gg["fp_rules"] = top_counts(fpr_rules, 6)
                gg["miss_causes"] = top_counts(
                    collections.Counter(
                        c2
                        for c2 in (miss_cause(pred[i]) for i in sel if truth[i]["state"] == "attack" and i in diag_set)
                        if c2
                    ),
                    4,
                )
                surf[sname] = gg
            res["surfaces"] = surf
            rb = collections.Counter()
            rbb = collections.Counter()
            ra = collections.Counter()
            for i in diag_ids:
                if truth[i]["state"] == "benign":
                    for r in pred[i]["rules"]:
                        rb[r] += 1
                    for r in pred[i]["blockrules"]:
                        rbb[r] += 1
                else:
                    for r in pred[i]["rules"]:
                        ra[r] += 1
            res["benign_alert_rules"] = top_counts(rb, 60)
            res["benign_block_rules"] = top_counts(rbb, 60)
            res["attack_rules"] = top_counts(ra, 40)
            res["miss_causes"] = top_counts(
                collections.Counter(
                    c for c in (miss_cause(pred[i]) for i in diag_ids if truth[i]["state"] == "attack") if c
                )
            )
            res["benign_hit_ids"] = {
                "block": [i for i in diag_ids if truth[i]["state"] == "benign" and pred[i]["block"]][:400],
                "alert": [
                    i for i in diag_ids if truth[i]["state"] == "benign" and pred[i]["alert"] and not pred[i]["block"]
                ][:400],
            }
            json.dump(res, open(f"{a.out}/scores/{name}-{pack}.json", "w"), indent=1, default=list)
            b, al = res["block"], res["alert"]
            f = lambda x: "nan" if x != x else f"{x:.4f}"
            bb = res["block_on_expected_block"]
            md.append(
                f"- {name} / {pack}: benign {b['neg']}, attack {b['pos']} (expected-block {bb['pos']}), excluded {res['excluded']}, tool-unsupported-not-scored {res['unsupported_tool_cases_not_scored']}, errors {res['errors']}, connector-fallback {res['connector_fallback_decisions']} | block recall {f(b['recall'])} (on expected-block only {f(bb['recall'])}) {tuple(round(x, 3) for x in b['recall_ci'])}, alert recall {f(al['recall'])} | "
                f"false-block {f(b['fpr'])} {tuple(round(x, 5) for x in b['fpr_ci'])} ({b['fp']}), false-alert {f(al['fpr'])} {tuple(round(x, 5) for x in al['fpr_ci'])} ({al['fp']}) | F1 block {f(b['f1'])} alert {f(al['f1'])}"
                + (
                    f" | at prevalence: block P {f(b['weighted']['precision'])} F1 {f(b['weighted']['f1'])} FPR {f(b['weighted']['fpr'])}, alert P {f(al['weighted']['precision'])} F1 {f(al['weighted']['f1'])} FPR {f(al['weighted']['fpr'])}"
                    if "weighted" in b
                    else ""
                )
                + (judge_line(jmodel, js) if js else "")
            )
            print(md[-1], flush=True)
            for side in (HOLD.TUNE, HOLD.HOLDOUT):
                md.append(
                    f"    [{side}] "
                    + (
                        "tuned regression suite: no holdout"
                        if side == HOLD.HOLDOUT and res["tuned_corpus"]
                        else split_line(res["split"][side])
                    )
                )
                print(md[-1], flush=True)
    md.extend(judge_cost_report(a.out, jcells, getattr(a, "judge_proxy_log", ""), jmodel))
    nbad = sum(1 for r in comp_rows if not r["complete"])
    md[md.index("@@STATUS@@")] = (
        f"STATUS: INCOMPLETE ({nbad} of {len(comp_rows)} corpus x pack cells have undecided cases or a shard that did not exit cleanly; no rates are given for them)"
        if nbad
        else f"STATUS: COMPLETE ({len(comp_rows)} corpus x pack cells, every in-scope case decided, every shard exit status 0)"
    )
    open(f"{a.out}/SUMMARY.md", "w").write("\n".join(md) + "\n")
    json.dump(
        dict(
            label=os.path.basename(os.path.normpath(a.out)),
            t=time.strftime("%FT%TZ", time.gmtime()),
            complete=not nbad,
            rows=comp_rows,
        ),
        open(f"{a.out}/COMPLETENESS.json", "w"),
        indent=1,
    )
    return not nbad


def cmd_compare(a):
    import glob

    bad = 0
    lines = []
    inc = 0
    hbad = []
    labdiff = 0

    def _fsmode(d):
        try:
            return json.load(open(f"{d}/RUN.json")).get("fixture_fs", "live")
        except (OSError, ValueError):
            return "live"

    (fx0, k0), (fx1, k1) = run_fixture_root(a.base), run_fixture_root(a.cand)
    fxs, kinds = [fx0, fx1], [k0, k1]
    # A side with no recorded root and no OUT/fx is a run of the per-run-tree scorer (this scorer always records one), e.g.
    # a cross-host copy (s7-gate compare --allow-cross-host copies scores and RUN.json, not fx): treat it as per-run, so
    # against the box root it gets no verdict; two such sides are old-vs-old and compare with a warning.
    missing = [n for n, x in (("base", fxs[0]), ("candidate", fxs[1])) if not x]
    kinds = [k or "per-run" for k in kinds]
    if missing:
        lines.append(
            f"WARNING the {' and '.join(missing)} side records no fixture root and has no OUT/fx (a run of the older "
            "per-run-tree scorer, or a cross-host copy): read as a per-run tree (GAP-0495)"
        )
    if kinds[0] != kinds[1] or (kinds[0] == "box" and fxs[0] != fxs[1]):
        print(
            f"GATE: FIXTURE ROOTS DIFFER (base {fxs[0]} [{kinds[0]}], candidate {fxs[1]} [{kinds[1]}]): the corpora "
            "were rewritten to paths of different length or text (GAP-0666, GAP-0495); rerun one side (no verdict)"
        )
        sys.exit(3)
    fb, fc = _fsmode(a.base), _fsmode(a.cand)
    if fb != fc:
        lines.append(
            f"WARNING fixture file system differs (base {fb}, candidate {fc}): a call that globs or checks /tmp, /var/tmp or /dev/shm is decided against the live box in a live run, so cases such as persistence.ssh_authorized_keys_command on a glob can flip for that reason alone (rel-1-0-10:GAP-0271); compare against a baseline built with the same seam"
        )
    elif fb == "live":
        lines.append(
            "NOTE both runs read the live file system for /tmp, /var/tmp and /dev/shm (no fixturefs seam in the binary): globs over a busy /tmp can flip with box state (GAP-0271)"
        )
    for bf in sorted(glob.glob(f"{a.base}/scores/*.json")):
        cf = bf.replace(a.base, a.cand)
        if not os.path.exists(cf):
            lines.append(f"MISSING in candidate: {os.path.basename(bf)}")
            bad += 1
            continue
        b, c = json.load(open(bf)), json.load(open(cf))
        if b.get("status") == "incomplete" or c.get("status") == "incomplete":
            # No numbers on a partial run: the pair cannot be compared and the gate is not passed.
            side = " and ".join(n for n, x in (("base", b), ("candidate", c)) if x.get("status") == "incomplete")
            lines.append(
                f"{os.path.basename(bf)[:-5]}: INCOMPLETE ({side}): "
                + ", ".join(
                    f"{n} {x['decided_in_scope']} of {x['expected_in_scope']} in-scope cases decided"
                    for n, x in (("base", b), ("candidate", c))
                    if x.get("status") == "incomplete"
                )
            )
            inc += 1
            continue
        lb, lc = (
            (b.get("labels") or {}).get("sha256"),
            (c.get("labels") or {}).get("sha256"),
        )  # labels v3 (s7-relabel): scores under different label sets are not comparable
        if lb and lc and lb != lc:
            lines.append(
                f"{os.path.basename(bf)[:-5]}: LABELS DIFFER (base {lb[:12]}, candidate {lc[:12]}): the rates are not comparable; rescore one side with the other's labels (s7gate.py score --decisions-from <run> --out <new> --labels <file>)"
            )
            labdiff += 1
            continue
        if not (lb and lc):
            missing = " and ".join(n for n, x in (("base", lb), ("candidate", lc)) if not x)
            if not getattr(a, "allow_unlabelled", False):
                lines.append(
                    f"{os.path.basename(bf)[:-5]}: LABELS MISSING on the {missing} side: it was scored without a "
                    "recorded label set (an old run, --labels none, or a box without the label file); rescore it "
                    "with --labels <file>, or pass --allow-unlabelled on purpose"
                )
                labdiff += 1
                continue
            lines.append(
                f"{os.path.basename(bf)[:-5]}: WARNING no recorded label set on the {missing} side "
                "(--allow-unlabelled): the rates may not be comparable"
            )
        row = [os.path.basename(bf)[:-5]]
        for key in ("block", "alert"):
            for m, worse_if in (("fpr", "up"), ("f1", "down"), ("recall", "down")):
                x, y = b[key][m], c[key][m]
                if x != x or y != y:
                    continue
                d = y - x
                flag = ""
                if m in ("fpr", "f1") and ((worse_if == "up" and d > 1e-12) or (worse_if == "down" and d < -1e-12)):
                    flag = " REGRESSED"
                    bad += 1
                row.append(f"{key}.{m} {x:.5f}->{y:.5f} ({d:+.5f}){flag}")
        lines.append("; ".join(row))
        for side in (
            "tune",
            "holdout",
        ):  # S7 L2: both sides of the frozen split are always shown; the holdout verdict is the one a claim may use
            bs, cs = (b.get("split") or {}).get(side), (c.get("split") or {}).get(side)
            if not bs or not cs or not bs["cases"] or not cs["cases"]:
                continue
            sp = []
            for key in ("block", "alert"):
                for m, worse_if in (("fpr", "up"), ("f1", "down"), ("recall", "down")):
                    x, y = bs[key][m], cs[key][m]
                    if x != x or y != y:
                        continue
                    d = y - x
                    flag = ""
                    if (
                        side == "holdout"
                        and m in ("fpr", "f1")
                        and ((worse_if == "up" and d > 1e-12) or (worse_if == "down" and d < -1e-12))
                    ):
                        flag = " REGRESSED"
                        hbad.append(row[0])
                    sp.append(f"{key}.{m} {x:.5f}->{y:.5f} ({d:+.5f}){flag}")
            lines.append(f"   [{side}] " + "; ".join(sp))
        rb = dict(b["benign_alert_rules"])
        rc = dict(c["benign_alert_rules"])
        diffs = sorted(((rc.get(r, 0) - rb.get(r, 0), r) for r in set(rb) | set(rc)), key=lambda t: -abs(t[0]))
        lines.append("   per-rule benign-alert diff: " + ", ".join(f"{r} {d:+d}" for d, r in diffs[:12] if d))
    print("\n".join(lines))
    if labdiff:
        print(
            f"GATE: LABELS DIFFER OR MISSING ({labdiff} corpus x pack cells scored under different label sets, or one side has none; no verdict)"
        )
        sys.exit(3)
    if inc:
        print(
            f"GATE: INCOMPLETE ({inc} corpus x pack cells have an incomplete run on one side; rerun the shard(s), no verdict)"
            + ("; also FAIL: a rate rose or F1 fell on the complete cells" if bad else "")
        )
        sys.exit(3)
    print(
        "GATE (holdout side only, informational; the verdict below stays on all cases):",
        f"FAIL on {len(set(hbad))} cell(s): " + ", ".join(sorted(set(hbad))[:8]) if hbad else "PASS",
    )
    print("GATE:", "FAIL (false-block/alert rate rose or F1 fell)" if bad else "PASS")
    sys.exit(1 if bad else 0)


def running_labels(gate_dir):
    """Labels with a live runner or harness process (their folders are not finished, so not 'incomplete')."""
    live = set()
    root = os.path.realpath(gate_dir).rstrip("/") + "/"
    for d in glob.glob("/proc/[0-9]*"):
        try:
            cmd = open(d + "/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "s7gate.py" not in cmd and "s7bench" not in cmd:
            continue
        for m in re.finditer(re.escape(root) + r"([A-Za-z0-9._-]+)", cmd):
            live.add(m.group(1))
    return live


def cmd_audit(a):
    """Completeness of every run directory under --gate-dir (no scoring). One JSON row per label x corpus x pack, plus a per-label summary on stdout."""
    corp_cache = {}

    def truth_of(cpath, name):
        key = (cpath, name)
        if key not in corp_cache:
            cfgs = json.load(open(cpath)) if cpath and os.path.exists(cpath) else {}
            corp_cache[key] = (
                {cid: dict(state=tr["state"], nev=tr["nev"]) for cid, tr in read_cases(cfgs[name])}
                if name in cfgs
                else None
            )
        return corp_cache[key]

    labels = sorted(x for x in os.listdir(a.gate_dir) if os.path.isdir(f"{a.gate_dir}/{x}/decisions"))
    if a.only_label:
        labels = [x for x in labels if x in set(a.only_label.split(","))]
    out = []
    live = running_labels(a.gate_dir)
    for lab in labels:
        base = f"{a.gate_dir}/{lab}"
        run = json.load(open(base + "/RUN.json")) if os.path.exists(base + "/RUN.json") else None
        cpath = a.judge_corpora if (lab.endswith(".judge") or lab.endswith(".jrules")) else a.corpora
        for name in sorted(os.listdir(base + "/decisions")):
            d = f"{base}/decisions/{name}"
            if not os.path.isdir(d):
                continue
            truth = truth_of(cpath, name)
            if truth is None and cpath != a.corpora:
                truth = truth_of(a.corpora, name)  # a corpus the judge-sample file does not define
            if truth is None and os.path.exists(a.corpora_full or "/nonexistent"):
                truth = truth_of(a.corpora_full, name)
            for pack in packs_present(d, run):
                r = corpus_pack_status(d, name, pack, truth)
                if not r["complete"] and lab in live:
                    r["status"] = "running"
                    r["running"] = True  # a live run is not incomplete yet
                r.update(
                    label=lab,
                    box=a.box,
                    run_json=bool(run),
                    run_finished=(run or {}).get("finished"),
                    run_host=(run or {}).get("host"),
                    run_commit=(run or {}).get("code_commit"),
                    run_stamped=bool((run or {}).get("code_commit")),
                    corpus_def="known" if truth is not None else "unknown (all ids in scope, events unchecked)",
                )
                out.append(r)
    if a.json:
        with open(a.json, "w") as f:
            for r in out:
                f.write(json.dumps(r, sort_keys=True, default=list) + "\n")
    byl = collections.defaultdict(lambda: [0, 0, 0])
    for r in out:
        byl[r["label"]][0 if r["complete"] else (2 if r.get("running") else 1)] += 1
    for lab, v in sorted(byl.items()):
        print(f"{lab}: {v[0]} complete, {v[1]} incomplete" + (f", {v[2]} still running" if len(v) > 2 else ""))
    return not any(not r["complete"] and not r.get("running") for r in out)


def cmd_census(a):
    """Cases per connector and per tool name, as the harness sent them: (strata.provider, tool in the case, tool sent, mapped class) -> decisions."""
    cfgs = json.load(open(a.corpora))
    tot = collections.Counter()
    for name, cfg in cfgs.items():
        d = f"{a.out}/decisions/{name}"
        if not os.path.isdir(d):
            continue
        prov = {}
        for f in cfg["files"]:
            for line in open(f):
                r = json.loads(line)
                prov[r["id"]] = r["strata"].get("provider") or "unknown"
        import glob

        pk = a.pack
        for f in glob.glob(f"{d}/*-{pk}*.jsonl"):
            for line in open(f):
                r = json.loads(line)
                tot[
                    (
                        name,
                        prov.get(r["case"], "?"),
                        r.get("connector") or "claudecode(legacy)",
                        r.get("src_tool"),
                        r.get("tool"),
                        r.get("mapped"),
                    )
                ] += 1
    rows = collections.Counter()
    for (corp, prov, conn, src, tool, mapped), n in tot.items():
        rows[(prov, conn, src, tool, mapped)] += n
    print("provider -> connector handler | case tool -> tool sent | mapped class | decisions")
    for k, n in sorted(rows.items(), key=lambda kv: -kv[1])[: a.top]:
        print(f"{k[0]} -> {k[1]} | {k[2]} -> {k[3]} | {k[4]} | {n}")
    byc = collections.Counter()
    bym = collections.Counter()
    for (prov, conn, src, tool, mapped), n in rows.items():
        byc[conn] += n
        bym[mapped] += n
    print("decisions per connector handler:", dict(byc))
    print("decisions per mapped class:", dict(bym))


def cmd_coverage(a):
    """Cases per tool surface x label for every corpus (counts only). Weighted columns use the meta sidecar weights when given."""
    cfgs = json.load(open(a.corpora))
    table = {}
    for name, cfg in cfgs.items():
        cnt = collections.defaultdict(collections.Counter)
        for f in cfg["files"]:
            for line in open(f):
                r = json.loads(line)
                t = r["truth"]
                state = t["source_truth"] if t.get("applicability", "in_scope") == "in_scope" else "excluded"
                state = {"malicious": "attack", "sensitive": "attack"}.get(state, state)
                cnt[case_surface(r)][state] += 1
        table[name] = {k: dict(v) for k, v in cnt.items()}
    json.dump(table, open(a.out, "w"), indent=1)
    surfaces = sorted({s for t in table.values() for s in t})
    print("surface | " + " | ".join(table) + " | TOTAL benign / attack")
    for s in surfaces:
        row = []
        tb = ta = 0
        for n, t in table.items():
            c = t.get(s, {})
            b, at = c.get("benign", 0), c.get("attack", 0)
            tb += b
            ta += at
            row.append(f"{b}/{at}")
        print(f"{s} | " + " | ".join(row) + f" | {tb} / {ta}")


def cmd_split(a):
    """Cases and groups per side of the frozen split for every corpus of --corpora, against the manifest written at freeze (holdout-split-v1.manifest.json). Exit 1 on drift."""
    cfgs = json.load(open(a.corpora))
    hcfg = HOLD.load()
    man_f = HOLD.FILE.replace(".json", ".manifest.json")
    man = json.load(open(man_f)) if os.path.exists(man_f) else {}
    print(
        f"split {hcfg['version']} sha256 {HOLD.sha256()} frozen {hcfg['frozen']}, {hcfg['percent']}% holdout, tuned corpora {', '.join(hcfg['tuned_corpora'])}"
    )
    drift = 0
    for name, cfg in cfgs.items():
        n = collections.Counter()
        g = {HOLD.TUNE: set(), HOLD.HOLDOUT: set()}
        for f in cfg["files"]:
            for line in open(f):
                r = json.loads(line)
                sp = HOLD.split_of(name, r, hcfg)
                n[sp] += 1
                g[sp].add(HOLD.group_key(r))
        tot = n[HOLD.TUNE] + n[HOLD.HOLDOUT]
        m = man.get(name)
        note = (
            "not in the manifest (a corpus added after the freeze: split by the same rule)"
            if m is None
            else (
                "matches the manifest"
                if (m["cases"], m["holdout"]) == (tot, n[HOLD.HOLDOUT])
                else "DRIFT: the corpus changed since the freeze (manifest %d cases, %d holdout)"
                % (m["cases"], m["holdout"])
            )
        )
        drift += 1 if m is not None and "DRIFT" in note else 0
        print(
            f"{name}: {tot} cases, tune {n[HOLD.TUNE]} ({len(g[HOLD.TUNE])} groups), holdout {n[HOLD.HOLDOUT]} ({len(g[HOLD.HOLDOUT])} groups) = {n[HOLD.HOLDOUT] / max(1, tot):.1%} | {note}"
        )
    return not drift


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    pv = sub.add_parser("coverage")
    pv.add_argument("--corpora", required=True)
    pv.add_argument("--out", required=True)
    pc = sub.add_parser("census")
    pc.add_argument("--corpora", required=True)
    pc.add_argument("--out", required=True)
    pc.add_argument("--pack", default="default")
    pc.add_argument("--top", type=int, default=40)
    pa = sub.add_parser("audit")
    pa.add_argument("--gate-dir", required=True)
    pa.add_argument("--corpora", required=True)
    pa.add_argument("--judge-corpora", default="")
    pa.add_argument("--corpora-full", default="")
    pa.add_argument("--box", default="")
    pa.add_argument("--json")
    pa.add_argument("--only-label", default="")
    ps = sub.add_parser("split")
    ps.add_argument("--corpora", required=True)
    pr = sub.add_parser("register-corpus")
    pr.add_argument("file")
    pr.add_argument("--version", required=True)
    pvc = sub.add_parser("verify-corpora")
    pvc.add_argument("--corpora", required=True)
    pvc.add_argument("--only", default="")
    ppl = sub.add_parser("push-labels")
    ppl.add_argument("--src", required=True)
    ppl.add_argument("--dest", default=os.path.dirname(default_labels()))
    ppl.add_argument("--name", default="labels-v3")
    try:
        import labelfold  # only fold-labels / check-labels need it; a box without labelfold.py runs everything else
    except ImportError:
        labelfold = None
    if labelfold:
        labelfold.add_parsers(sub)
    elif len(sys.argv) > 1 and sys.argv[1] in ("fold-labels", "check-labels"):
        print(f"s7gate: {sys.argv[1]} needs labelfold.py beside s7gate.py (copy it with the scorer)", file=sys.stderr)
        sys.exit(4)
    for n in ("run", "score", "compare", "all"):
        p = sub.add_parser(n)
        if n in ("run", "all"):
            p.add_argument(
                "--require-stamp",
                action="store_true",
                help="refuse a run with no code commit (no S7_CODE_COMMIT and no vcs.revision in the binary); also S7_REQUIRE_STAMP=1",
            )
            p.add_argument("--bin", required=True)
            p.add_argument("--policy-dir", required=True)
            p.add_argument("--packs", default=",".join(PACKS))
            p.add_argument("--gomaxprocs", type=int, default=8)
            p.add_argument("--workers", type=int, default=24)
            p.add_argument("--parallel", type=int, default=1)
            p.add_argument("--chunk", type=int, default=2500)
            p.add_argument("--only")
            p.add_argument(
                "--dm-key-file",
                default="",
                help="file (on this box) with the bearer key of the external decision model endpoint; read into DEFENSECLAW_DECISION_MODEL_KEY of the harness processes only and deleted when the run ends",
            )
            p.add_argument(
                "--connector",
                default="",
                help="pass -connector to the harness (auto = each case to its own connector's hook handler); needs a harness built from s7/bench-connectors",
            )
            p.add_argument(
                "--full-fidelity",
                action="store_true",
                help="also record the det block and send PostToolUse for action cases (needed for miss-cause analysis; ~1.5x CPU)",
            )
            p.add_argument(
                "--harness-args",
                default="",
                help="extra s7bench flags, comma or space separated (the rules+judge configuration)",
            )
            p.add_argument(
                "--cascade-effects",
                "--effects-rules",
                dest="effects_rules",
                default="",
                help="pass the effects lane value (guardrail.cascade.lanes.effects, e.g. shadow) to the harness as -cascade-effects (-effects-rules for a harness built before the rename) and record det, so the effect shadow columns are emitted; --effects-rules is the old spelling, kept as an alias",
            )
            p.add_argument(
                "--scratch-cap-mb",
                type=int,
                default=DEFAULT_SCRATCH_CAP_MB,
                help="harness -scratch-cap-mb: the runaway backstop on one process's scratch dir (0: leave the harness default). Default %(default)s MiB",
            )
            p.add_argument(
                "--min-free-gb",
                type=int,
                default=0,
                help="do not start a shard while the scratch volume has less free space (GiB); 0: %d on disk, %d on tmpfs"
                % (MIN_FREE_GB, MIN_FREE_TMPFS_GB),
            )
            p.add_argument(
                "--scratch-dir",
                default="auto",
                help="parent of every harness process's scratch dir (audit.db + WAL): auto (default) = /dev/shm when it has room, else the system temp dir; or a path. See rel-1-0-10:GAP-0170 root cause",
            )
            p.add_argument("--disk-wait-min", type=int, default=120)
        if n in ("run", "score", "all"):
            p.add_argument("--corpora", required=True)
            p.add_argument("--out", required=True)
        if n in ("score", "all"):
            p.add_argument(
                "--diagnostics-scope",
                default="tune",
                choices=["tune", "all"],
                help="which cases the rule lists, miss causes and case ids come from: the tune side of the frozen split (default) or both sides (an explicit, recorded choice)",
            )
            p.add_argument("--reviews")
            p.add_argument(
                "--labels",
                default="",
                help="label overlay to apply (default: $S7_LABELS, else ~/s7c/labels/current.jsonl = labels v3); none = corpus files as they stand. --reviews overrides",
            )
            p.add_argument("--include-unsupported", action="store_true")
            p.add_argument(
                "--effects-column",
                default="rules",
                choices=["rules", "restricted", "full", "inspect", "hook"],
                help="score the effect shadow decision column merged with today (default rules); on the prompt surface every column but inspect scores the UserPromptSubmit hook answer, for old records too (extra.hook_*), and inspect = the proxy text inspection, diagnostic only (GAP-0554)",
            )
            p.add_argument(
                "--decisions-from",
                default="",
                help="read decisions/RUN.json from this run dir instead of --out (re-score one run as several columns)",
            )
            p.add_argument(
                "--judge-proxy-log",
                default="",
                help="the s7proxy log of this run (one run's): its exact tokens give the run-level all-sent judge cost next to the answered-only figure (rel-1-0-10:GAP-0649); written to OUT/judge_cost.json",
            )
        if n == "compare":
            p.add_argument("--base", required=True)
            p.add_argument("--cand", required=True)
            p.add_argument(
                "--allow-unlabelled",
                action="store_true",
                help="compare a run that records no label set (pre-v3) with one that does; the rates may not be comparable",
            )
    a = ap.parse_args()
    if a.cmd == "run":
        sys.exit(0 if cmd_run(a) else 4)
    elif a.cmd == "score":
        sys.exit(0 if cmd_score(a) else 4)
    elif a.cmd == "compare":
        cmd_compare(a)
    elif a.cmd == "split":
        sys.exit(0 if cmd_split(a) else 1)
    elif a.cmd == "register-corpus":
        cmd_register_corpus(a)
    elif a.cmd == "verify-corpora":
        cmd_verify_corpora(a)
    elif a.cmd == "push-labels":
        cmd_push_labels(a)
    elif a.cmd == "fold-labels":
        labelfold.cmd_fold(a)
    elif a.cmd == "check-labels":
        labelfold.cmd_check(a)
    elif a.cmd == "census":
        cmd_census(a)
    elif a.cmd == "coverage":
        cmd_coverage(a)
    elif a.cmd == "audit":
        sys.exit(0 if cmd_audit(a) else 4)
    else:
        # GAP-1580: a missing label set refuses before the harness runs (exit 1), not after the whole run; cmd_score
        # refuses again if the file changed while the run went on (s7-gate push_labels replaces current.jsonl)
        a.resolved_labels = resolve_labels(a)
        ran = cmd_run(a)
        scored = cmd_score(a)
        sys.exit(
            0 if ran and scored else 4
        )  # 4: the run is INCOMPLETE (scores for the complete cells exist; the others carry status incomplete and no rates)


if __name__ == "__main__":
    main()
