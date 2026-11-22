#!/usr/bin/env python3
"""cmp51.py FIXTUREDIR SAMPLE_IDS ORACLE51.jsonl : compare Windows PowerShell 5.1 and pwsh 7.6.6 on the sample rows.
SAMPLE_IDS lines: <row index in pub>\t<row id>. Prints classes with counts and 10 sample row ids."""
import sys, json, gzip
from collections import defaultdict
F, sids, o51 = sys.argv[1:4]
sel = [l.rstrip('\n').split('\t') for l in open(sids)]
want = {int(a): b for a, b in sel}
o7 = {}
with gzip.open(F + '/pub.oracle.jsonl.gz', 'rt') as f:
    for i, ln in enumerate(f):
        if i in want: o7[i] = json.loads(ln)
r51 = [json.loads(l) for l in open(o51)]
cls = defaultdict(list)
def key(a, common=None):
    p = a[4] if common is None else {k: v for k, v in a[4].items() if k in common}
    return (a[1], a[2], a[3], json.dumps(p, sort_keys=True))
for n, (idx, rid) in enumerate((int(a), b) for a, b in sel):
    a, b = o7[idx], r51[n]
    if b.get('crash') or a.get('crash'): cls['crash in the dumper'].append(rid); continue
    found = False
    ea, eb = [e[0] for e in a['err']], [e[0] for e in b['err']]
    if bool(ea) != bool(eb):
        cls['errors on one side only (%s)' % ('5.1 errors, 7 clean' if eb else '7 errors, 5.1 clean')].append(rid); found = True
    elif ea != eb:
        cls['both error, different error ids'].append(rid); found = True
    ta = [x[0] for x in a['ast']]; tb = [x[0] for x in b['ast']]
    sa = [(x[1]) for x in a['ast']]; sb = [(x[1]) for x in b['ast']]
    if sa != sb:
        # first differing node type
        d = next((k for k in range(min(len(sa), len(sb))) if sa[k] != sb[k]), min(len(sa), len(sb)))
        x = sa[d] if d < len(sa) else 'end'; y = sb[d] if d < len(sb) else 'end'
        cls['AST node types differ: 7 has %s where 5.1 has %s' % (x, y)].append(rid); found = True
    else:
        ka = []; kb = []
        for x, y in zip(a['ast'], b['ast']):   # props present only in 7 (PipelineAst.Background, ...) are not differences
            com = set(x[4]) & set(y[4]); ka.append(key(x, com)); kb.append(key(y, com))
        if ka != kb:
            d = next(k for k in range(len(ka)) if ka[k] != kb[k])
            cls['same node types, differing extent or property (%s)' % a['ast'][d][1]].append(rid); found = True
    tk = lambda r: [(t[0], t[2], t[3], t[4]) for t in r['tok']]
    if tk(a) != tk(b) and not found:
        cls['only the token stream differs'].append(rid); found = True
    if not found: cls['identical (AST, errors, tokens)'].append(rid)
print('rows compared: %d (5.1 = %s)' % (len(sel), open(o51 + '.version').read() if False else '5.1'))
print('| class | rows | sample row ids |\n|---|---|---|')
for k, rs in sorted(cls.items(), key=lambda kv: -len(kv[1])):
    print('| %s | %d | %s |' % (k, len(rs), ', '.join(rs[:10])))
