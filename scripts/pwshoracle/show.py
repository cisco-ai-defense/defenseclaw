#!/usr/bin/env python3
"""Print source and both views for public row ids. Usage: show.py RUNDIR ID [ID...]  (public rows only)"""
import sys, json, base64
W = sys.argv[1]; want = set(sys.argv[2:])
ids = [l.split('\t') for l in open(W + '/pub.ids')]
idx = {r[0]: i for i, r in enumerate(ids) if r[0] in want}
need = set(idx.values())
def pick(path):
    out = {}
    with open(path) as f:
        for i, ln in enumerate(f):
            if i in need: out[i] = ln.rstrip('\n')
    return out
src = pick(W + '/pub.b64'); ov = pick(W + '/pub.oview.jsonl'); uv = pick(W + '/pub.uview.jsonl')
for rid, i in idx.items():
    print('=== ' + rid + ' [' + ids[i][1].strip() + ']')
    print(base64.b64decode(src[i]).decode('utf8', 'replace')[:700])
    o = json.loads(ov[i]); u = json.loads(uv[i])
    print('-- oracle err:', o.get('err'), ' ours diag:', u.get('diag'))
    def fmt(c):
        def e(x):
            if x[0] == 'param': return '-%s%s' % (x[1], (':' + e(x[3])) if x[2] else '')
            return '%s<%s>' % (x[0], x[1] if x[1] is not None else '')
        return '@%d %s%s %s%s' % (c['s'], c['op'], e(c['name']), ' '.join(e(x) for x in c['el']), ('  RD' + json.dumps(c['rd'])) if c['rd'] else '')
    for c in o['cmds'][:12]: print('  O', fmt(c)[:300])
    for c in u['cmds'][:12]: print('  U', fmt(c)[:300])
