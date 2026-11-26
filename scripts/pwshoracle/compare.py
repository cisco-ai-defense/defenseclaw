#!/usr/bin/env python3
"""Compare the oracle view (oracle_view.py) with the psparse view (psview) row by row.
Usage: compare.py ORACLE_VIEW OURS_VIEW IDS OUT_PREFIX [--public]
Writes OUT_PREFIX.rows.tsv (row id, classes) and OUT_PREFIX.report.md (class, rows, instances, 10 sample row ids).
With --public the samples are printed; without it (private rows) only counts."""
import sys, json, re
from collections import defaultdict, Counter
ov_p, ours_p, ids_p, out = sys.argv[1:5]
public = '--public' in sys.argv
ids = [l.split('\t')[0] for l in open(ids_p)]
def tail(v):
    return (v or '').split(':')[-1].lower()
def norm_kind(k):
    return k
def e_key(e):
    return (e[0], e[1] if e[0] not in ('num',) and not e[0].startswith('other:') else None)
def redir_ours(r):
    op, merge, tgt = r
    m = re.match(r'^(\d|\*)?(>>|>|<)', op)
    stream = (m.group(1) or '1') if m else '?'
    if merge:
        return ['merge', stream, merge]
    return ['file', stream, '>>' in op, tgt]
def nk(k):
    return 'dqx' if k == 'barex' else k
def shape(e):
    k = nk(e[0])
    if k == 'param': return 'param'
    v = e[1] if isinstance(e[1], str) else ''
    if k in ('bare', 'sq', 'dq') and v.startswith('-'): return k + '(dash-word)'
    if k in ('bare',) and '#' in v: return k + '(has #)'
    return k
def cls_add(cl, row, key, n=1):
    cl[key][0].add(row); cl[key][1] += n
classes = defaultdict(lambda: [set(), 0])
rowcls = {}
ov = open(ov_p); ou = open(ours_p)
nrows = 0
for ol, ul in zip(ov, ou):
    o = json.loads(ol); u = json.loads(ul)
    rid = ids[o['i']]
    if o.get('bad') or u.get('empty'):
        continue
    nrows += 1
    cl = defaultdict(lambda: [set(), 0]); rc = set()
    stratum = 'E' if o['err'] else 'V'   # E: the real parser reports errors (the script would not run); V: valid script
    def add(k, n=1):
        k = '[%s] %s' % (stratum, k)
        cls_add(cl, rid, k, n); rc.add(k)
    diag = u.get('diag') or []
    if any(d.startswith('PANIC') for d in diag): add('ours-panic')
    oc, uc = o['cmds'], u['cmds']
    # align
    uidx = {}
    for j, c in enumerate(uc): uidx.setdefault(c['s'], []).append(j)
    used = set(); pairs = []; left = []
    for i, c in enumerate(oc):
        js = [j for j in uidx.get(c['s'], []) if j not in used]
        if js:
            used.add(js[0]); pairs.append((i, js[0], False))
        else: left.append(i)
    for i in left[:]:
        for j, c in enumerate(uc):
            if j in used: continue
            if oc[i]['name'][1] is not None and c['name'][1] is not None and oc[i]['name'][1].lower() == str(c['name'][1]).lower():
                used.add(j); pairs.append((i, j, True)); left.remove(i); break
    fl = 'ours flagged a diagnostic' if diag else 'ours silent'
    for i in left:
        n = oc[i]['name']
        add('cmd-missed-by-ours, %s%s' % (fl, '' if n[1] is not None else ' (dynamic name)'))
    for j in range(len(uc)):
        if j not in used: add('cmd-extra-in-ours, %s' % fl)
    for i, j, shifted in pairs:
        a, b = oc[i], uc[j]
        if shifted: add('cmd-span-origin-differs (nested string/sub-expression offsets)')
        if a['op'] != b['op']: add('invocation-op-differs (%s vs %s)' % (a['op'] or '-', b['op'] or '-'))
        an, bn = a['name'], b['name']
        if nk(an[0]) != nk(bn[0]):
            add('name-kind: oracle %s vs ours %s' % (an[0], bn[0]))
        elif an[0] not in ('num', 'barex', 'dqx', 'hdqx') and not an[0].startswith('other:'):
            av, bv = (tail(an[1]), tail(bn[1])) if an[0] == 'var' else (an[1], bn[1])
            if av != bv: add('name-value-differs (%s)' % an[0])
        ael, bel = a['el'], b['el']
        if len(ael) != len(bel):
            # signature = first differing element
            sig = '?'
            for k in range(min(len(ael), len(bel)) + 1):
                x = ael[k] if k < len(ael) else None; y = bel[k] if k < len(bel) else None
                if x is None or y is None or nk(x[0]) != nk(y[0]) or (nk(x[0]) in ('bare', 'sq', 'dq', 'param') and x[1] != y[1]):
                    sig = 'oracle %s vs ours %s' % (shape(x) if x else 'end', shape(y) if y else 'end'); break
            add('arg-count (%s): %s' % ('oracle fewer' if len(ael) < len(bel) else 'oracle more', sig))
        else:
            for x, y in zip(ael, bel):
                if nk(x[0]) != nk(y[0]):
                    add('arg-kind: oracle %s vs ours %s' % (shape(x), shape(y)))
                elif x[0] == 'param':
                    if x[1] != y[1]: add('param-name-differs')
                    elif x[2] != y[2]: add('param-colon-form-differs')
                    elif nk(x[3][0]) != nk(y[3][0]): add('param-colon-value-kind: oracle %s vs ours %s' % (x[3][0], y[3][0]))
                elif x[0] == 'var':
                    if tail(x[1]) != tail(y[1]): add('arg-var-name-differs')
                elif x[0] not in ('num', 'barex', 'dqx', 'hdqx') and not x[0].startswith('other:'):
                    if x[1] != y[1]: add('arg-value-differs (%s)' % x[0])
        ar = [(r[0], r[1]) + ((r[2],) if r[0] == 'file' else (r[2],)) for r in a['rd']]
        br = [redir_ours(r) for r in b['rd']]
        ar2 = [(r[0], r[1], r[2] if r[0] == 'merge' else (r[2], r[3][0], r[3][1] if r[3][0] in ('bare', 'sq', 'dq', 'hsq', 'hdq') else None)) for r in a['rd']]
        def rn(r):
            if r[0] == 'merge': return ('merge', r[1], r[2])
            t = r[3]
            return ('file', r[1], r[2], t[0], t[1] if t[0] in ('bare', 'sq', 'dq', 'hsq', 'hdq') else None)
        ar3 = [(r[0], r[1], r[2]) if r[0] == 'merge' else rn(r) for r in a['rd']]
        br3 = [(r[0], r[1], r[2]) if r[0] == 'merge' else rn(r) for r in br]
        if ar3 != br3:
            if len(ar3) != len(br3): add('redirection-count: oracle %s ours' % ('more than' if len(ar3) > len(br3) else 'fewer than'))
            else: add('redirection-differs')
    if o['sbs'] != u['sbs']: add('scriptblock-count-differs (oracle %s ours)' % ('more' if o['sbs'] > u['sbs'] else 'fewer'))
    op = sorted(x for x in o['pipes'] if x >= 2); up = sorted(x for x in u['pipes'] if x >= 2)
    if op != up: add('pipeline-size-differs (oracle %s ours)' % ('more elements' if sum(op) > sum(up) else 'fewer elements' if sum(op) < sum(up) else 'regrouped'))
    ochain = o.get('chains', 0)
    if ochain != 0 and not any('&&' in str(x) for x in []): pass
    oe = bool(o['err']); ue = any(d in ('ps_unterminated', 'ps_unbalanced', 'ps_unknown_token', 'ps_incomplete_expr') for d in diag)
    if oe and not ue: add('parse-error: oracle errors, ours silent')
    if ue and not oe: add('parse-error: ours flags, oracle clean')
    for k, (rs, n) in cl.items():
        classes[k][0] |= rs; classes[k][1] += n
    if rc: rowcls[rid] = sorted(rc)
with open(out + '.rows.tsv', 'w') as f:
    for rid, cs in rowcls.items(): f.write(rid + '\t' + ' | '.join(cs) + '\n')
with open(out + '.report.md', 'w') as f:
    f.write('rows compared: %d; rows with any disagreement: %d\n\n' % (nrows, len(rowcls)))
    f.write('| class | rows | instances | sample row ids |\n|---|---|---|---|\n')
    for k, (rs, n) in sorted(classes.items(), key=lambda kv: -len(kv[1][0])):
        s = ', '.join(sorted(rs)[:10]) if public else '(private rows: counts only)'
        f.write('| %s | %d | %d | %s |\n' % (k, len(rs), n, s))
print(open(out + '.report.md').read())
