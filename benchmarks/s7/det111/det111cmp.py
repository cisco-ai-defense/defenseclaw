#!/usr/bin/env python3
"""det111cmp.py: compare and check DET111 probe runs. Fails closed.

A run is a directory written by det111-run-v1.sh (rows.txt, meta.tsv, stamp.txt):
  rows.txt  key|tier|route|<action> <severity> <rule ids>
  meta.tsv  key role gen variant seed pair gap tool dialect windows truth cwdshift cwd command  (tab separated, \\t \\n escaped)

  det111cmp.py props RUN [--out FILE]            generator properties inside one run
  det111cmp.py cmp HEAD BASE [--allow GAP,..]    head against base: weaker / stronger rows, per tier
  det111cmp.py seeds RUN                         corpus case ids that alert or block in some tier (seed list)
  det111cmp.py all HEAD BASE                     props on both, cmp, one verdict line
  det111cmp.py expect RUN CASES...               measured 1.0.10 verdict against the expectations the gap rows carry

Exit code: 0 = PASS, 1 = FAIL (a property or a weaker/raised row), 2 = NOT-READY (missing or unreadable rows).
The final line is  DET111CMP PASS|FAIL|NOT-READY <counts>  .
"""

import collections
import os
import sys

ACT = {"allow": 0, "": 0, "warn": 1, "alert": 1, "ask": 1, "confirm": 1, "block": 2, "deny": 2}
SEV = {"": 0, "NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Cells the owner ruled (CONTRACT.md 2026-11-21): rows of these gaps may be weaker, and are listed, never silent.
# Allowed by (gap, tiers, kind): GAP-1611/1698 the managed default only, action block -> alert; GAP-0851/0962 severity only, same action.
# Strict and managed-strict are never excused. Variants, twins and benign rows are never excused (they only inherit the gap id).
OWNER_RULED = {
    "GAP-1611": {"tiers": ("managed",), "kind": "block-to-alert"},
    "GAP-1698": {"tiers": ("managed",), "kind": "block-to-alert"},
    "GAP-0851": {"tiers": ("default", "permissive", "strict", "managed", "managed-strict"), "kind": "severity-only"},
    "GAP-0962": {"tiers": ("default", "permissive", "strict", "managed", "managed-strict"), "kind": "severity-only"},
}
OWNER_ROLES = ("corpus", "seed")


def owner_ruled(gap, role, tier, b, h):
    r = OWNER_RULED.get(gap)
    if not r or role not in OWNER_ROLES or tier not in r["tiers"]:
        return False
    if r["kind"] == "block-to-alert":
        return b[0] == "block" and norm_action(h[0]) == "alert"
    if r["kind"] == "severity-only":
        return norm_action(h[0]) == norm_action(b[0]) and SEV.get(h[1], 0) < SEV.get(b[1], 0)
    return False


TIERS = ["default", "permissive", "strict", "managed", "managed-strict"]


def parse_verdict(v):
    parts = (v.split(" ", 2) + ["", ""])[:3]
    act, sev, rules = parts
    rs = frozenset(r for r in rules.strip().split(",") if r)
    return act, sev, rs


def rank(v):
    act, sev, _ = v
    return (ACT.get(act, -1), SEV.get(sev, 0))


def stamp_fields(text):
    out = {}
    for tok in text.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


class Run:
    def __init__(self, d):
        self.dir = d
        self.rows = {}  # key -> {(tier, route): verdict}
        self.errors = 0
        self.nlines = 0
        self.dups = 0
        self.bad = []
        rp = os.path.join(d, "rows.txt")
        mp = os.path.join(d, "meta.tsv")
        for p in (rp, mp):
            if not os.path.exists(p):
                self.bad.append("missing " + p)
        if self.bad:
            self.meta = {}
            return
        self.nlines = 0
        self.dups = 0
        for ln in open(rp, errors="replace"):
            ln = ln.rstrip("\n")
            f = ln.split("|", 3)
            if len(f) != 4:
                self.bad.append("unparsable row line: " + ln[:80])
                continue
            k, tier, route, v = f
            self.nlines += 1
            if v.startswith("error"):
                self.errors += 1
            if (tier, route) in self.rows.get(k, {}):
                self.dups += 1
            self.rows.setdefault(k, {})[(tier, route)] = parse_verdict(v)
        self.meta = {}
        for ln in open(mp, errors="replace"):
            f = ln.rstrip("\n").split("\t")
            f += [""] * (14 - len(f))
            self.meta[f[0]] = dict(
                zip(
                    (
                        "key",
                        "role",
                        "gen",
                        "variant",
                        "seed",
                        "pair",
                        "gap",
                        "tool",
                        "dialect",
                        "windows",
                        "truth",
                        "cwdshift",
                        "cwd",
                        "cmd",
                    ),
                    f,
                )
            )
        for k in self.meta:
            if k not in self.rows:
                self.bad.append("no verdict lines for row " + k)
                break
        sp = os.path.join(d, "stamp.txt")
        self.stamp = open(sp).read().strip() if os.path.exists(sp) else ""
        self.sf = stamp_fields(self.stamp)
        if not self.stamp:
            self.bad.append("missing stamp.txt in " + d)
        if not self.rows:
            self.bad.append("empty run " + d)
        if self.sf.get("dirty", "1") != "0":
            self.bad.append("run %s was made from a dirty tree (dirty=%s)" % (d, self.sf.get("dirty", "?")))
        if self.sf.get("rows") and int(self.sf["rows"]) != len(self.meta):
            self.bad.append("run %s: stamp rows=%s but meta has %d" % (d, self.sf["rows"], len(self.meta)))
        if self.sf.get("lines") and int(self.sf["lines"]) != self.nlines:
            self.bad.append("run %s: stamp lines=%s but rows.txt has %d" % (d, self.sf["lines"], self.nlines))
        if self.errors:
            self.bad.append("run %s has %d error verdicts" % (d, self.errors))
        if self.dups:
            self.bad.append("run %s has %d duplicate verdict lines" % (d, self.dups))


def stronger(a, b):
    return rank(a) > rank(b)


def sv_is_noise(sv, role):
    # variant: a seed that alerts only by a parser artifact; twin: a twin-seed that is not allow (not benign here)
    if role == "variant":
        return noise(sv)
    if role == "twin-variant":
        return rank(sv) > (0, 0)
    return False


def noise(v):
    """A verdict whose only findings are parser artifacts (ACTION-*) says nothing about the effect."""
    return bool(v[2]) and all(r.startswith("ACTION-") for r in v[2])


def props(run, out=None):
    """Generator properties inside one run. Returns (per-generator counters, failures, missing)."""
    G = collections.defaultdict(lambda: collections.Counter())
    fails = []
    missing = []
    byname = collections.defaultdict(collections.Counter)
    seedfail = collections.defaultdict(set)
    for k, m in run.meta.items():
        role = m["role"]
        if role not in ("variant", "twin-variant", "benign-variant"):
            continue
        seedk = m["seed"]
        seedrows = run.rows.get(seedk)
        mine = run.rows.get(k, {})
        gen = m["gen"]
        if seedrows is None:
            missing.append((k, "seed row " + seedk))
            continue
        for cell, sv in seedrows.items():
            if cell not in mine:
                missing.append((k, "%s/%s" % cell))
                continue
            v = mine[cell]
            src = "td" if "/td/" in k else "corpus"
            c = G[(gen, role)]
            if role != "benign-variant" and sv_is_noise(sv, role):
                c["cells-seed-noise"] += 1
                continue
            if cell[1] == "llm" and m["cwdshift"] == "true":
                c["cells-skipped-llm-cwd"] += 1  # the LLM tool-call route carries no working folder
                continue
            if role == "variant" and m["variant"] in MAYBE_VARIANTS:
                c["cells-maybe"] += 1
                continue
            if role == "variant":
                if rank(sv)[0] == 0 and rank(sv)[1] == 0:
                    c["cells-seed-allow"] += 1  # nothing to be weaker than
                    continue
                c["cells"] += 1
                bad = None
                if rank(v) < rank(sv):
                    bad = "weak"
                elif not sv[2] <= v[2] and rank(v)[0] <= rank(sv)[0]:
                    bad = "rule"
                if bad:
                    c["fail-" + bad] += 1
                    c["src-%s-%s" % (src, bad)] += 1
                    seedfail[(gen, role)].add(seedk)
                    fails.append((gen, role, m["variant"], k, cell, bad, sv, v))
                    byname[(gen, role)][m["variant"]] += 1
                if rank(v) > rank(sv):
                    c["raised"] += 1
            else:  # twin-variant or benign-variant: never stronger than its benign seed
                c["cells"] += 1
                if stronger(v, sv):
                    c["fail-raise"] += 1
                    c["src-%s-raise" % src] += 1
                    seedfail[(gen, role)].add(seedk)
                    if v[0] != "allow" and ACT.get(v[0], 0) > ACT.get(sv[0], 0) and v[0] == "block":
                        c["fail-newblock"] += 1
                    fails.append((gen, role, m["variant"], k, cell, "raise", sv, v))
                    byname[(gen, role)][m["variant"]] += 1
    # variants (rows) failing: any cell
    failing_rows = collections.defaultdict(set)
    for gen, role, var, k, cell, kind, sv, v in fails:
        failing_rows[(gen, role)].add(k)
    totals = collections.defaultdict(lambda: collections.Counter())
    for k, m in run.meta.items():
        if m["role"] in ("variant", "twin-variant", "benign-variant"):
            totals[(m["gen"], m["role"])]["rows"] += 1
    return G, fails, missing, failing_rows, totals, byname, seedfail


def report_props(run, out=None):
    G, fails, missing, failing_rows, totals, byname, seedfail = props(run)
    lines = []
    for key in sorted(set(G) | set(totals)):
        gen, role = key
        c = G[key]
        lines.append(
            "PROPS gen=%s role=%s rows=%d failing_rows=%d seeds_failing=%d cells=%d weak=%d rule=%d raise=%d newblock=%d seed_allow_cells=%d seed_noise_cells=%d raised_tp=%d td_fail=%d corpus_fail=%d"
            % (
                gen,
                role,
                totals[key]["rows"],
                len(failing_rows.get(key, ())),
                len(seedfail.get(key, ())),
                c["cells"],
                c["fail-weak"],
                c["fail-rule"],
                c["fail-raise"],
                c["fail-newblock"],
                c["cells-seed-allow"],
                c["cells-seed-noise"],
                c["raised"],
                c["src-td-weak"] + c["src-td-rule"] + c["src-td-raise"],
                c["src-corpus-weak"] + c["src-corpus-rule"] + c["src-corpus-raise"],
            )
        )
    for key, cnt in sorted(byname.items()):
        for name, n in cnt.most_common(12):
            lines.append("  %s/%s %s: %d cells" % (key[0], key[1], name, n))
    if out:
        with open(out, "w") as f:
            for gen, role, var, k, cell, kind, sv, v in sorted(fails):
                f.write(
                    "%s\t%s\t%s\t%s\t%s/%s\t%s\t%s %s %s\t%s %s %s\t%s\n"
                    % (
                        gen,
                        role,
                        var,
                        k,
                        cell[0],
                        cell[1],
                        kind,
                        sv[0],
                        sv[1],
                        ",".join(sorted(sv[2])),
                        v[0],
                        v[1],
                        ",".join(sorted(v[2])),
                        run.meta[k]["cmd"],
                    )
                )
    return lines, fails, missing, failing_rows


def cmp_runs(head, base, allow=None):
    notes = []
    missing = []
    hk, bk = set(head.rows), set(base.rows)
    for k in sorted(bk - hk):
        missing.append("row only in base: " + k)
    for k in sorted(hk - bk):
        missing.append("row only in head: " + k)
    stats = collections.defaultdict(collections.Counter)
    weaker = []
    benign_raise = []
    for k in sorted(hk & bk):
        m = head.meta.get(k) or base.meta.get(k) or {}
        role = m.get("role", "")
        truth = m.get("truth", "")
        benign = role in ("twin-seed", "twin-variant", "benign-seed", "benign-variant") or (
            role == "corpus" and truth == "allow"
        )
        gap = m.get("gap", "")
        hv, bv = head.rows[k], base.rows[k]
        for cell in sorted(set(hv) | set(bv)):
            if cell not in hv or cell not in bv:
                missing.append("cell only on one side: %s %s/%s" % (k, cell[0], cell[1]))
                continue
            h, b = hv[cell], bv[cell]
            tier = cell[0]
            st = stats[tier]
            st["cells"] += 1
            if rank(h) < rank(b):
                kind = "action" if rank(h)[0] < rank(b)[0] else "severity"
                if benign:
                    st["benign-lower"] += 1
                elif owner_ruled(gap, role, tier, b, h):
                    st["weaker-owner-ruled"] += 1
                    notes.append("owner-ruled weaker: %s %s/%s %s -> %s" % (k, cell[0], cell[1], b[:2], h[:2]))
                else:
                    st["weaker-" + kind] += 1
                    weaker.append((k, cell, b, h, kind))
            elif rank(h) > rank(b):
                if benign:
                    st["benign-raise"] += 1
                    if h[0] == "block" and b[0] != "block":
                        st["benign-newblock"] += 1
                    benign_raise.append((k, cell, b, h))
                else:
                    st["stronger"] += 1
            elif h[2] != b[2] and not benign and rank(b)[0] > 0:
                st["rules-changed"] += 1
    return stats, weaker, benign_raise, missing, notes


# Spellings that name the active home only when passwd agrees with HOME (~login, ~other/../login): scored apart, not as failures.
MAYBE_VARIANTS = ("tilde-login", "tilde-other-dotdot", "cd-tilde-login")
ALERTISH = {"alert", "warn", "ask", "confirm"}


def norm_action(a):
    if a in ALERTISH:
        return "alert"
    if a == "deny":
        return "block"
    return a


ROUTE_ORDER = (
    "hook-cc",
    "hook-cc:prompt",
    "hook-cc:tool-result",
    "hook-cc:stateful",
    "hook-codex:stateful",
    "hook-codex",
    "inspect-oc",
)


def pick_route(cells, tier):
    for r in ROUTE_ORDER:
        if (tier, r) in cells:
            return r
    for t, r in sorted(cells):
        if t == tier and r.startswith("as-is"):
            return r
    return None


def load_expect(files):
    """Expectations of the gap rows: categories exp:<tier>=<action> and tier:<tier>=<action>, tiers-from-seed (the seed's
    measured verdict), tiers-baseline (the row is a seed: its measured verdict is the expectation), expect:no-rule=<id>,
    and expected_profile_actions. Returns {id: dict}."""
    import json

    out = {}
    for f in files:
        for ln in open(f, errors="replace"):
            r = json.loads(ln)
            t = r.get("truth", {})
            cats = t.get("categories", [])
            e = {
                "exp": {},
                "mode": "none",
                "seed": "",
                "basis": [],
                "gap": "",
                "norule": [],
                "role": "",
                "file": os.path.basename(f),
            }
            for ct in cats:
                if ct.startswith(("exp:", "tier:")) and "=" in ct:
                    k, v = ct.split(":", 1)[1].split("=", 1)
                    e["exp"][k] = v
                elif ct == "tiers-from-seed":
                    e["mode"] = "from-seed"
                elif ct == "tiers-baseline":
                    e["mode"] = "baseline"
                elif ct.startswith("seed:"):
                    e["seed"] = ct[5:]
                elif ct.startswith("role:"):
                    e["role"] = ct[5:]
                elif ct.startswith("basis:"):
                    e["basis"].append(ct[6:])
                elif ct.startswith("gap:"):
                    e["gap"] = ct[4:].upper()
                elif ct.startswith("expect:no-rule="):
                    e["norule"].append(ct.split("=", 1)[1])
            for k, v in (t.get("expected_profile_actions") or {}).items():
                e["exp"].setdefault(k, v)
            if e["exp"] and e["mode"] == "none":
                e["mode"] = "explicit"
            if e["mode"] == "none" and (e["role"] == "twin" or r["id"].endswith("/twin")):
                # a benign twin (same spelling, non-protected target) is expected to be allowed in every tier
                e["exp"] = {t: "allow" for t in TIERS}
                e["mode"] = "explicit"
                e["basis"].append("twin-default-allow")
            out[r["id"]] = e
    return out


_EXPECT = {}


def load_expect_cache(files):
    key = tuple(files)
    if key not in _EXPECT:
        _EXPECT[key] = load_expect(files)
    return _EXPECT[key]


def expect_cmd(run, files):
    ex = load_expect(files)
    mism, noexp, checked, inferred = [], [], 0, 0
    for cid, e in sorted(ex.items()):
        k = "corpus/" + cid
        if k not in run.rows:
            continue  # skipped row (listed in skipped.txt)
        cells = run.rows[k]
        if e["mode"] == "none" and not e["norule"] and e["gap"]:
            noexp.append(cid)
            continue
        for tier in TIERS:
            route = pick_route(cells, tier)
            if route is None:
                continue
            m = cells[(tier, route)]
            if e["mode"] == "from-seed" and e["seed"]:
                sk = "corpus/" + e["seed"]
                if sk in run.rows and (tier, route) in run.rows[sk]:
                    sv = run.rows[sk][(tier, route)]
                    # the expectation is the seed's measured verdict: the variant must be at least as strong
                    if rank(m) < rank(sv):
                        mism.append(
                            (cid, tier, "seed:" + sv[0] + " " + sv[1], m[0] + " " + m[1], route, ",".join(e["basis"]))
                        )
                    checked += 1
                continue
            if e["mode"] == "baseline":
                continue
            if tier in e["exp"]:
                checked += 1
                if norm_action(e["exp"][tier]) != norm_action(m[0]):
                    mism.append((cid, tier, e["exp"][tier], m[0] + " " + m[1], route, ",".join(e["basis"])))
                    if any("infer" in b for b in e["basis"]):
                        inferred += 1
            for nr in e["norule"]:
                checked += 1
                if nr in m[2]:
                    mism.append(
                        (cid, tier, "no-rule " + nr, m[0] + " " + ",".join(sorted(m[2])), route, ",".join(e["basis"]))
                    )
    return mism, noexp, checked, inferred


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    allow = None
    args = [a for a in argv[2:] if a != "--self-test"]
    out = None
    if "--out" in args:
        i = args.index("--out")
        out = args[i + 1]
        del args[i : i + 2]
    if "--allow" in args:
        print(
            "DET111CMP NOT-READY --allow is refused: the owner-ruled cells are fixed in OWNER_RULED (gap, tier, kind)"
        )
        return 2
    if cmd == "expect":
        run = Run(args[0])
        if run.bad:
            print("DET111CMP NOT-READY " + "; ".join(run.bad[:3]))
            return 2
        mism, noexp, checked, inferred = expect_cmd(run, args[1:])
        for m in mism:
            print(
                "EXPECT-MISMATCH id=%s tier=%s expected=%s measured=%s route=%s basis=%s role=%s"
                % (m + (load_expect_cache(args[1:])[m[0]]["role"] or m[0].rsplit("/", 1)[-1],))
            )
        for n in noexp:
            print("NO-EXPECTATION id=%s" % n)
        exm = load_expect(args[1:])
        byrole = collections.Counter((exm[m[0]]["role"] or m[0].rsplit("/", 1)[-1]) for m in mism)
        print("  by role: " + " ".join("%s=%d" % kv for kv in sorted(byrole.items())))
        by = collections.Counter(exm[m[0]]["gap"] or "?" for m in mism)
        for g, n in sorted(by.items()):
            print("  gap %s: %d cells" % (g, n))
        verdict = "NOT-READY" if noexp else ("FAIL" if mism else "PASS")
        print(
            "DET111CMP %s expect checked=%d mismatches=%d inferred_mismatches=%d rows_without_expectation=%d"
            % (verdict, checked, len(mism), inferred, len(noexp))
        )
        return {"PASS": 0, "FAIL": 1, "NOT-READY": 2}[verdict]
    if cmd == "seeds":
        run = Run(args[0])
        if run.bad:
            print("DET111CMP NOT-READY " + "; ".join(run.bad[:3]))
            return 2
        ids = []
        for k, m in run.meta.items():
            if m["role"] == "corpus" and any(rank(v) > (0, 0) for v in run.rows.get(k, {}).values()):
                ids.append(k[len("corpus/") :])
        print("\n".join(sorted(ids)))
        return 0
    if cmd == "props":
        run = Run(args[0])
        if run.bad:
            print("DET111CMP NOT-READY " + "; ".join(run.bad[:3]))
            return 2
        lines, fails, missing, fr = report_props(run, out)
        print("\n".join(lines))
        if missing or run.errors:
            print("DET111CMP NOT-READY props missing=%d errors=%d" % (len(missing), run.errors))
            return 2
        nf = len(fr and set().union(*fr.values()) or ())
        print("DET111CMP %s props failing_rows=%d" % ("FAIL" if nf else "PASS", nf))
        return 1 if nf else 0
    if cmd in ("cmp", "all"):
        head, base = Run(args[0]), Run(args[1])
        bad = head.bad + base.bad
        if base.sf.get("base_identical") != "1" and "--self-test" not in argv:
            bad.append(
                "base run %s is not the a64bfdb931 product code (stamp base_identical=%s)"
                % (base.dir, base.sf.get("base_identical", "?"))
            )
        if base.stamp and head.stamp and base.sf.get("sha") == head.sf.get("sha") and "--self-test" not in argv:
            bad.append(
                "head and base are the same commit %s (use --self-test to check the harness)" % head.sf.get("sha")
            )
        if bad:
            print("DET111CMP NOT-READY " + "; ".join(bad[:3]))
            return 2
        pf = 0
        failsets = {}
        if cmd == "all":
            for name, r in (("head", head), ("base", base)):
                lines, fails, missing, fr = report_props(r, (out or "props") + "-" + name + ".tsv")
                print("== props " + name)
                print("\n".join(lines))
                if missing:
                    print("DET111CMP NOT-READY props missing=%d (%s)" % (len(missing), name))
                    return 2
                failsets[name] = set().union(*fr.values()) if fr else set()
            pf = len(failsets["head"] - failsets["base"])
            print(
                "PROPS-SUMMARY failing_rows head=%d base=%d new_in_head=%d fixed_in_head=%d"
                % (len(failsets["head"]), len(failsets["base"]), pf, len(failsets["base"] - failsets["head"]))
            )
        stats, weaker, braise, missing, notes = cmp_runs(head, base, allow)
        for t in TIERS + sorted(set(stats) - set(TIERS)):
            if t in stats:
                c = stats[t]
                print(
                    "CMP tier=%s cells=%d weaker_action=%d weaker_severity=%d owner_ruled=%d stronger=%d benign_raise=%d benign_newblock=%d benign_lower=%d rules_changed=%d"
                    % (
                        t,
                        c["cells"],
                        c["weaker-action"],
                        c["weaker-severity"],
                        c["weaker-owner-ruled"],
                        c["stronger"],
                        c["benign-raise"],
                        c["benign-newblock"],
                        c["benign-lower"],
                        c["rules-changed"],
                    )
                )
        for n in notes[:20]:
            print("  " + n)
        for k, cell, b, h, kind in weaker[:40]:
            print("  WEAKER[%s] %s %s/%s %s -> %s" % (kind, k, cell[0], cell[1], " ".join(b[:2]), " ".join(h[:2])))
        for k, cell, b, h in braise[:40]:
            print("  BENIGN-RAISE %s %s/%s %s -> %s" % (k, cell[0], cell[1], " ".join(b[:2]), " ".join(h[:2])))
        if missing:
            for m in missing[:10]:
                print("  MISSING " + m)
            print("DET111CMP NOT-READY missing=%d" % len(missing))
            return 2
        tot = collections.Counter()
        for c in stats.values():
            tot.update(c)
        nw = tot["weaker-action"] + tot["weaker-severity"]
        counts = "weaker=%d benign_raise=%d benign_newblock=%d stronger=%d owner_ruled=%d props_new_failing_rows=%d" % (
            nw,
            tot["benign-raise"],
            tot["benign-newblock"],
            tot["stronger"],
            tot["weaker-owner-ruled"],
            pf,
        )
        verdict = "PASS" if nw == 0 and tot["benign-raise"] == 0 and (cmd == "cmp" or pf == 0) else "FAIL"
        print(
            "DET111CMP %s %s head=%s base=%s"
            % (
                verdict,
                counts,
                head.stamp.split()[0] if head.stamp else "?",
                base.stamp.split()[0] if base.stamp else "?",
            )
        )
        return 0 if verdict == "PASS" else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
