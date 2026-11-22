#!/usr/bin/env python3
"""raw.py RUNDIR ID : print the oracle AST (depth type start end props) of a public row"""
import sys, json
W, rid = sys.argv[1:3]
ids = [l.split('\t')[0] for l in open(W + '/pub.ids')]; i = ids.index(rid)
for n, ln in enumerate(open(W + '/pub.oracle.jsonl')):
    if n == i:
        r = json.loads(ln)
        for a in r['ast']: print('  ' * a[0], a[1], a[2], a[3], a[4])
        print('TOK', [(t[0], t[2], t[3], t[4]) for t in r['tok']][:30]); break
