#!/usr/bin/env python3
"""diff51.py FIXTUREDIR SAMPLE_IDS ORACLE51.jsonl ID... : source and first AST difference of the given sample rows (public)."""
import sys, json, gzip, base64
F, sids, o51 = sys.argv[1:4]; want = set(sys.argv[4:])
sel = [l.rstrip('\n').split('\t') for l in open(sids)]
rows = gzip.open(F + '/pub.b64.gz', 'rt').read().split('\n')
need = {int(a): b for a, b in sel if b in want}
o7 = {}
with gzip.open(F + '/pub.oracle.jsonl.gz', 'rt') as f:
    for i, ln in enumerate(f):
        if i in need: o7[i] = json.loads(ln)
r51 = [json.loads(l) for l in open(o51)]
for n, (a, b) in enumerate(sel):
    a = int(a)
    if a not in need: continue
    print('=== ' + b); print(base64.b64decode(rows[a]).decode('utf8', 'replace')[:300])
    x, y = o7[a], r51[n]
    print(' 7.6.6 err', x['err'][:3], ' 5.1 err', y['err'][:3])
    for k in range(max(len(x['ast']), len(y['ast']))):
        p = x['ast'][k] if k < len(x['ast']) else None; q = y['ast'][k] if k < len(y['ast']) else None
        if p != q and not (p and q and p[:4] == q[:4] and all(p[4].get(z) == q[4].get(z) for z in set(p[4]) & set(q[4]))):
            print('  first AST diff @%d: 7=%s  5.1=%s' % (k, p, q)); break
