#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""s7-gate dataset adapters for benchmarks/datasets.lock.json (DET111 DATA-A).

One deterministic pipeline per locked set, run on a bench box (never on dev or a laptop):

  fetch      pinned revision into <root>/data/sources/<id> (git: benchmark_prepare.py; HF: snapshot at the locked
             revision; Zenodo: files checked against the record md5). Nothing from a dataset is ever executed.
  normalize  the existing benchmark_normalize_*.py adapter -> case-v1 rows (<root>/norm/<slug>.jsonl)
  convert    case-v1 rows -> an s7-gate corpus <root>/corpora/<slug>-<ver>.cases.jsonl, under the public-eval truth
             contract: attack = in_scope + deterministic_malicious, benign = in_scope + benign; contextual,
             out-of-scope and unresolved rows are abstain and are dropped (counted), never kept as benign.
             Rows are sorted by id, ids are unique, a corpus file is never rewritten (new content = new version).
  register   one entry per corpus in a corpora json for `s7-gate run --corpora`.

No step needs the network except fetch. Row text is never printed: reports carry ids and counts only.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from registry import REGISTRY, VERSION  # noqa: E402

REPO = HERE.parents[2]
LOCK = REPO / "benchmarks/datasets.lock.json"
SCRIPTS = REPO / "benchmarks/scripts"


def lock_entry(dataset_id: str) -> dict:
    for item in json.loads(LOCK.read_text(encoding="utf-8"))["datasets"]:
        if item["id"] == dataset_id:
            return item
    raise SystemExit(f"{dataset_id}: not in {LOCK}")


def src_dir(root: Path, dataset_id: str) -> Path:
    return root / "data/sources" / REGISTRY.get(dataset_id, {}).get("dir", dataset_id)


def norm_path(root: Path, dataset_id: str) -> Path:
    reg = REGISTRY[dataset_id]
    return root / "norm" / f"{reg.get('norm_slug', reg['slug'])}.jsonl"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(base: Path) -> tuple[str, int, int]:
    """sha256 over (relative path, file sha256) of every data file below base, sorted; skips cache metadata."""
    h = hashlib.sha256()
    n = size = 0
    for p in sorted(x for x in base.rglob("*") if x.is_file()):
        rel = p.relative_to(base).as_posix()
        if rel.startswith(".cache/") or rel == ".defenseclaw-source.json":
            continue
        h.update(rel.encode() + b"\0" + sha256_file(p).encode() + b"\n")
        n += 1
        size += p.stat().st_size
    return h.hexdigest(), n, size


def fetch(root: Path, dataset_id: str, max_bytes: int, token_file: str | None) -> None:
    ent = lock_entry(dataset_id)
    reg = REGISTRY[dataset_id]
    if reg.get("skip"):
        raise SystemExit(f"{dataset_id}: skipped: {reg['skip']}")
    dest = src_dir(root, dataset_id)
    meta = dest / ".defenseclaw-source.json"
    if meta.is_file():
        print(f"{dataset_id}: already fetched")
        return
    kind = reg["fetch"]
    url, rev = ent["source_url"], ent["revision"]
    inc = reg.get("include") or ent.get("include_paths") or []
    if kind == "prepare":
        lock = LOCK
        if reg.get("include_from"):
            # the adapter audits an exact file list: fetch only those paths (never a whole repository)
            import re  # noqa: PLC0415

            text = (SCRIPTS / reg["include_from"]).read_text(encoding="utf-8")
            paths = sorted(set(re.findall(r'"(datasets/[A-Za-z0-9_./-]+\.(?:log|json|yml|zip))"', text)))
            doc = json.loads(LOCK.read_text(encoding="utf-8"))
            for item in doc["datasets"]:
                if item["id"] == dataset_id:
                    item["include_paths"] = paths
                    item["fetch"] = "git"  # the lock says manual (no include list); the pinned git blobs are what we need
            lock = root / "data" / f"lock-{reg['slug']}.json"
            lock.parent.mkdir(parents=True, exist_ok=True)
            lock.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        cmd = [sys.executable, "-I", str(SCRIPTS / "benchmark_prepare.py"), "--lock", str(lock), "--data-dir", str(root / "data"),
               "--datasets", dataset_id]
        subprocess.run(cmd, check=True)
        return
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "hf":
        from huggingface_hub import HfApi, snapshot_download  # noqa: PLC0415

        token = Path(token_file).read_text().strip() if token_file else None
        repo = url.split("huggingface.co/datasets/")[1].strip("/")
        info = HfApi().dataset_info(repo, revision=rev, files_metadata=True, token=token)
        if info.sha != rev:
            raise SystemExit(f"{dataset_id}: resolved {info.sha}, lock says {rev}")
        pats = None
        if inc:
            pats = []
            for p in inc:
                pats += [p, p.rstrip("/") + "/**"]
        sel = [s for s in info.siblings if pats is None or any(_match(s.rfilename, q) for q in pats)]
        total = sum(s.size or 0 for s in sel)
        if total > max_bytes:
            raise SystemExit(f"{dataset_id}: selected {total} bytes exceeds --max-bytes {max_bytes}")
        snapshot_download(repo, repo_type="dataset", revision=rev, local_dir=str(dest), allow_patterns=pats, token=token)
    elif kind == "zenodo":
        rid = url.rstrip("/").split("/")[-1].split(".")[-1]
        with urllib.request.urlopen(f"https://zenodo.org/api/records/{rid}", timeout=60) as r:
            rec = json.load(r)
        for f in sorted(rec["files"], key=lambda x: x["key"]):
            if inc and f["key"] not in inc:
                continue
            if f["size"] > max_bytes:
                raise SystemExit(f"{dataset_id}: {f['key']} exceeds --max-bytes")
            target = dest / f["key"]
            target.parent.mkdir(parents=True, exist_ok=True)
            md5 = hashlib.md5()
            with urllib.request.urlopen(f["links"]["self"], timeout=300) as r, target.open("wb") as o:
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    md5.update(chunk)
                    o.write(chunk)
            want = f["checksum"].split(":", 1)[-1]
            if md5.hexdigest() != want:
                target.unlink()
                raise SystemExit(f"{dataset_id}: md5 mismatch for {f['key']}")
    else:
        raise SystemExit(f"{dataset_id}: unknown fetch kind {kind}")
    digest, n, size = tree_digest(dest)
    meta.write_text(json.dumps({"id": dataset_id, "source_url": url, "revision": rev, "files": n, "bytes": size,
                                "tree_sha256": digest}, indent=2, sort_keys=True) + "\n")
    print(f"{dataset_id}: fetched {n} files {size} bytes tree {digest[:12]}")


def _match(path: str, pat: str) -> bool:
    from fnmatch import fnmatchcase  # noqa: PLC0415

    return fnmatchcase(path, pat) or path == pat or path.startswith(pat.rstrip("*").rstrip("/") + "/")


def safe_extract_zip(archive: Path, dest: Path, max_files: int = 5000, max_bytes: int = 1 << 30) -> None:
    """Extract an untrusted zip as inert files: no absolute or parent paths, no symlinks, bounded count and size."""
    dest.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if len(infos) > max_files or sum(i.file_size for i in infos) > max_bytes:
            raise SystemExit(f"{archive.name}: archive exceeds the extraction bounds ({len(infos)} entries)")
        for i in infos:
            parts = Path(i.filename).parts
            if Path(i.filename).is_absolute() or ".." in parts or ((i.external_attr >> 16) & 0o170000) == 0o120000:
                raise SystemExit(f"{archive.name}: unsafe entry refused")
            target = dest.joinpath(*parts)
            if i.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as r, target.open("wb") as o:
                o.write(r.read())


def normalize(root: Path, dataset_id: str) -> Path:
    reg = REGISTRY[dataset_id]
    ent = lock_entry(dataset_id)
    out = norm_path(root, dataset_id)
    man = out.with_suffix(".manifest.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        print(f"{dataset_id}: normalized already: {out}")
        return out
    ext = root / "data/extracted" / reg.get("dir", dataset_id)
    if reg.get("extract") and not ext.exists():
        safe_extract_zip(src_dir(root, dataset_id) / reg["extract"], ext)
    sub = {"archive": str(src_dir(root, dataset_id) / reg.get("extract", "-")), "ext": str(ext),
           "src": str(src_dir(root, dataset_id)), "srcroot": str(root / "data/sources"), "rev": ent["revision"], "out": str(out), "manifest": str(man),
           "lock": str(LOCK), "id": dataset_id, "data": str(root / "data")}
    argv = [sys.executable, "-s", str(SCRIPTS / reg["norm"][0])] + [a.format(**sub) for a in reg["norm"][1:]]
    tmp = out.with_suffix(".jsonl.partial")
    argv = [tmp.as_posix() if a == out.as_posix() else a for a in argv]
    print(f"{dataset_id}: normalize {reg['norm'][0]}")
    subprocess.run(argv, check=True, cwd=REPO)  # adapters default to repo-relative schema paths
    os.replace(tmp, out)
    return out


def overlay_path(root: Path, dataset_id: str) -> Path:
    return norm_path(root, dataset_id).with_suffix(".labeled.jsonl")


def merge_truth(rows: list[dict], truth_by_id: dict[str, dict], annotated: set[str]) -> tuple[list[dict], int]:
    """Rows without a per-command annotation take the truth block of a published truth file (same id); returns (rows, n taken)."""
    n = 0
    out = []
    for r in rows:
        t = truth_by_id.get(r["id"])
        if t is not None and r["id"] not in annotated:
            r = dict(r)
            nt = dict(t)
            nt.setdefault("label_source", "published_truth_file")
            r["truth"] = nt
            n += 1
        out.append(r)
    return out, n


def _load(path: Path) -> list[dict]:
    with opener(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def overlay(root: Path, dataset_id: str, labels_dir: Path) -> Path:
    """Apply the published per-command labels (gpt-oss proposals, digest-checked by benchmark_apply_labels.py) to a normalized
    set; ids without an annotation take the published truth file, every other row is excluded as unlabeled (abstain)."""
    reg = REGISTRY[dataset_id]
    ov = reg["overlay"]
    src = norm_path(root, dataset_id)
    dst = overlay_path(root, dataset_id)
    if dst.exists():
        print(f"{dataset_id}: overlay already: {dst}")
        return dst
    prefix = ov["prefix"]
    rows = [r for r in _load(src) if r["id"].startswith(prefix)]
    ids = {r["id"] for r in rows}
    ann: dict[str, dict] = {}
    by_digest: dict[str, list[str]] = {}
    if ov.get("join_digest"):
        # the published labels were made with an older adapter revision (different row ids): join on the command digest
        sys.path.insert(0, str(SCRIPTS))
        from benchmark_label_bedrock import extract_command  # noqa: PLC0415

        for r in rows:
            cmd = extract_command(r)
            if cmd is not None:
                by_digest.setdefault(hashlib.sha256(cmd.encode()).hexdigest(), []).append(r["id"])
    for name in ov["labels"]:
        for a in _load(labels_dir / name):
            targets = [a["id"]] if a["id"] in ids else by_digest.get(a.get("input_sha256", ""), []) if a["id"].startswith(prefix) else []
            for tid in targets:
                if tid in ann:
                    if a["id"] == tid and ann[tid]["id"] == tid:
                        raise SystemExit(f"{dataset_id}: id annotated twice across label files: {tid}")
                    if ann[tid]["label"] != a["label"]:
                        raise SystemExit(f"{dataset_id}: conflicting annotations for one command digest: {tid}")
                    continue
                ann[tid] = dict(a, id=tid)
    truth: dict[str, dict] = {}
    for name in ov.get("truth", []):
        for a in _load(labels_dir / name):
            if a["id"] in ids and a["id"] not in ann:
                truth[a["id"]] = a["truth"]
    work = dst.parent / f".{dst.name}.work"
    work.mkdir(parents=True, exist_ok=True)
    flt, base = work / "labels.jsonl", work / "applied.jsonl"
    with flt.open("w", encoding="utf-8", newline="\n") as o:
        for rid in sorted(ann):
            o.write(json.dumps(ann[rid], sort_keys=True, separators=(",", ":")) + "\n")
    subprocess.run([sys.executable, "-s", str(SCRIPTS / "benchmark_apply_labels.py"), "--corpus", str(src), "--labels", str(flt),
                    "--output", str(base)] + list(ov.get("apply_flags", [])), check=True)
    merged, taken = merge_truth(_load(base), truth, set(ann))
    tmp = dst.with_suffix(".partial")
    with tmp.open("w", encoding="utf-8", newline="\n") as o:
        for r in merged:
            o.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
    os.replace(tmp, dst)
    print(f"{dataset_id}: overlay annotations {len(ann)} truth-file rows {taken} rows {len(merged)}")
    return dst


def opener(p: Path):
    return gzip.open(p, "rt", encoding="utf-8") if p.suffix == ".gz" else p.open("r", encoding="utf-8")


def convert(root: Path, dataset_id: str, version: str, benign_modulus: int, cdir: Path) -> dict:
    reg = REGISTRY[dataset_id]
    src = overlay_path(root, dataset_id) if reg.get("overlay") else norm_path(root, dataset_id)
    match = reg.get("match")
    dst = cdir / f"{reg['slug']}-{version}.cases.jsonl"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        raise SystemExit(f"refusing to rewrite {dst}: a new corpus is a new version")
    rows: dict[str, tuple[str, str]] = {}
    srcmal: dict[str, str] = {}
    st = dict(rows_source=0, abstain=0, sensitive=0, dup=0, det_attack=0, det_benign=0, label_only_attack=0, label_only_benign=0)
    with opener(src) as f:
        for ln in f:
            if not ln.strip():
                continue
            r = json.loads(ln)
            if match and (r.get("source") or {}).get("dataset") != match:
                continue
            st["rows_source"] += 1
            t = r.get("truth") or {}
            app, det, srct = t.get("applicability", "in_scope"), t.get("deterministic_truth"), t.get("source_truth")
            if r["id"] in rows:
                st["dup"] += 1
                continue
            # truth rule: a source-malicious row without deterministic proof (contextual, unresolved, out of scope, or no
            # deterministic_truth at all) is never an attack row of the contract corpus
            if app != "in_scope" or det in ("contextual_or_dual_use", "unresolved") or (det is None and srct == "malicious"):
                if srct == "malicious":
                    # source says malicious but the contract has no deterministic proof: kept apart as a source-label
                    # attack set (<slug>-srcmal), reported separately, never mixed into the contract corpus
                    t2 = dict(t)
                    t2.update(applicability="in_scope", source_truth="malicious", label_grade="source-label")
                    r2 = dict(r)
                    r2["truth"] = t2
                    sm = reg.get("srcmal_modulus", 1)
                    if sm <= 1 or int(hashlib.sha256(r["id"].encode()).hexdigest()[:8], 16) % sm == 0:
                        srcmal[r["id"]] = json.dumps(r2, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
                st["abstain"] += 1
                continue
            if det == "deterministic_malicious":
                new, kind = "malicious", "det"
            elif det == "benign":
                new, kind = "benign", "det"
            elif det is None and srct == "sensitive":
                st["sensitive"] += 1
                continue
            elif det is None and srct == "benign":
                new, kind = "benign", "label_only"
            else:
                st["abstain"] += 1
                continue
            if new == "benign" and benign_modulus > 1 and int(hashlib.sha256(r["id"].encode()).hexdigest()[:8], 16) % benign_modulus:
                st["abstain"] += 1  # deterministic benign sampling; counted as dropped
                continue
            t["source_truth"] = new
            r["truth"] = t
            rows[r["id"]] = (json.dumps(r, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n", new)
            key = ("det_" if kind == "det" else "label_only_") + ("attack" if new == "malicious" else "benign")
            st[key] += 1
    for rid in list(srcmal):
        if rid in rows:
            del srcmal[rid]
    st["srcmal"] = len(srcmal)
    if srcmal:
        sdst = cdir / f"{reg['slug']}-srcmal-{version}.cases.jsonl"
        if sdst.exists():
            raise SystemExit(f"refusing to rewrite {sdst}: a new corpus is a new version")
        with sdst.open("w", encoding="utf-8", newline="\n") as o:
            for rid in sorted(srcmal):
                o.write(srcmal[rid])
        st["srcmal_sha256"] = sha256_file(sdst)
    att = st["det_attack"] + st["label_only_attack"]
    ben = st["det_benign"] + st["label_only_benign"]
    st.update(id=dataset_id, slug=reg["slug"], version=version, rows_kept=len(rows), attack=att, benign=ben, file=str(dst), sha256="-")
    if not rows:
        print(f"{dataset_id}: 0 rows kept: not registered ({st['rows_source']} source rows, {st['abstain']} abstain)")
        return st
    tmp = dst.with_suffix(".tmp")
    h = hashlib.sha256()
    with tmp.open("w", encoding="utf-8", newline="\n") as o:
        for rid in sorted(rows):
            o.write(rows[rid][0])
            h.update(rows[rid][0].encode())
    os.replace(tmp, dst)
    st["sha256"] = h.hexdigest()
    print(f"{dataset_id}: kept {len(rows)} attack {att} benign {ben} abstain {st['abstain']} sensitive {st['sensitive']} sha {st['sha256'][:12]}")
    return st


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["fetch", "normalize", "overlay", "convert", "build", "list", "corpora-json"])
    ap.add_argument("ids", nargs="*", help="locked dataset ids (default: every registered, non-skipped set for `list`)")
    ap.add_argument("--root", default=os.path.expanduser("~/s7c/dsets"))
    ap.add_argument("--version", default=VERSION)
    ap.add_argument("--max-bytes", type=int, default=12 << 30)
    ap.add_argument("--benign-modulus", type=int, default=1, help="keep 1 in N benign rows (sha256 of the id); attacks are never sampled")
    ap.add_argument("--corpus-dir", help="where corpora are written (default <root>/corpora); must be under ~/s7c to be registered")
    ap.add_argument("--labels-dir", default=os.path.expanduser("~/s7c/hf/bench/data"), help="published label files (overlay)")
    ap.add_argument("--hf-token-file")
    ap.add_argument("--report", help="append one TSV line per converted set")
    a = ap.parse_args()
    root = Path(a.root)
    if a.step == "list":
        for k, v in REGISTRY.items():
            print(k, v["slug"], "SKIP: " + v["skip"] if v.get("skip") else v["fetch"])
        return 0
    if a.step == "corpora-json":
        # one s7-gate corpora file from the converted sets listed in --report (rows with a corpus file on disk)
        cdir = Path(a.corpus_dir) if a.corpus_dir else root / "corpora"
        out = {}
        for ln in Path(a.report).read_text().splitlines():
            f = ln.split("\t")
            if len(f) < 17 or f[4] == "0":
                continue
            for name, path in ((f[1], cdir / f"{f[1]}-{a.version}.cases.jsonl"), (f[1] + "-srcmal", cdir / f"{f[1]}-srcmal-{a.version}.cases.jsonl")):
                if path.is_file():
                    out[name] = {"files": [str(path)]}
        print(json.dumps(dict(sorted(out.items())), indent=1))
        return 0
    rc = 0
    for dataset_id in a.ids:
        if dataset_id not in REGISTRY:
            print(f"{dataset_id}: not registered", file=sys.stderr)
            rc = 1
            continue
        try:
            if a.step in ("fetch", "build"):
                fetch(root, dataset_id, a.max_bytes, a.hf_token_file)
            if a.step in ("normalize", "build"):
                normalize(root, dataset_id)
            if a.step in ("overlay", "build") and REGISTRY[dataset_id].get("overlay"):
                overlay(root, dataset_id, Path(a.labels_dir))
            if a.step in ("convert", "build"):
                st = convert(root, dataset_id, a.version, REGISTRY[dataset_id].get("benign_modulus", a.benign_modulus), Path(a.corpus_dir) if a.corpus_dir else root / "corpora")
                if a.report:
                    with open(a.report, "a") as o:
                        o.write("\t".join(str(st.get(k, "")) for k in ("id", "slug", "version", "rows_source", "rows_kept", "attack", "benign", "det_attack", "det_benign", "label_only_attack", "label_only_benign", "abstain", "sensitive", "dup", "srcmal", "sha256", "file")) + "\n")
        except (subprocess.CalledProcessError, SystemExit) as exc:
            print(f"{dataset_id}: FAILED: {exc}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
