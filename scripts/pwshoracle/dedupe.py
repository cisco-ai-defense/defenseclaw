#!/usr/bin/env python3
"""Dedupe the oracle input corpora. Usage: dedupe.py OUTDIR  (reads oracle-work/pub/*.b64, rec/go.b64 given by --rec, priv/windows-shell.b64)
Writes OUTDIR/pub.b64 (public rows, one base64 script per line), OUTDIR/pub.ids (row id + source labels),
OUTDIR/priv.b64 and OUTDIR/priv.ids. Row id of a public row = pw-<sha1[:10]> of the script bytes; private rows get priv-<n>."""
import sys, os, glob, hashlib, base64, argparse
ap = argparse.ArgumentParser()
ap.add_argument('outdir'); ap.add_argument('--pub', default='oracle-work/pub'); ap.add_argument('--rec', action='append', default=[])
ap.add_argument('--priv', default='oracle-work/priv/windows-shell.b64')
a = ap.parse_args()
os.makedirs(a.outdir, exist_ok=True)
def rows(path):
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                yield ln
seen = {}   # sha -> index
pub = []    # (id, b64, labels)
def add(b64, label, store, seen):
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return
    h = hashlib.sha1(raw).hexdigest()
    if h in seen:
        store[seen[h]][2].add(label); return
    seen[h] = len(store)
    store.append(('pw-' + h[:10], b64, {label}))
for p in sorted(glob.glob(a.pub + '/*.b64')):
    lab = os.path.basename(p)[:-4]
    for r in rows(p): add(r, lab, pub, seen)
for p in a.rec:
    lab = 'gotest'
    for r in rows(p): add(r, lab, pub, seen)
priv = []; pseen = {}
if os.path.exists(a.priv):
    for r in rows(a.priv):
        try: raw = base64.b64decode(r)
        except Exception: continue
        h = hashlib.sha1(raw).hexdigest()
        if h in seen or h in pseen: continue   # public wins
        pseen[h] = len(priv); priv.append(('priv-%d' % len(priv), r, {'windows-shell'}))
for name, st in (('pub', pub), ('priv', priv)):
    with open('%s/%s.b64' % (a.outdir, name), 'w') as fb, open('%s/%s.ids' % (a.outdir, name), 'w') as fi:
        for rid, b64, labs in st:
            fb.write(b64 + '\n'); fi.write(rid + '\t' + ','.join(sorted(labs)) + '\n')
    print(name, len(st), 'rows')
