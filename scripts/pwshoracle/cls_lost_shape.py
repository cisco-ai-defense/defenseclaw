# cls2.py W IDS ROWIDS : for each row, the lost effects (kind@prog) and the pwsh oracle element shape of that command. Derived data only.
import sys, json, collections
w, idsp, rp = sys.argv[1:4]
ids = [l.split('\t')[0] for l in open(idsp)]
idx = {r: i for i, r in enumerate(ids)}
def rd(p):
    out = {}
    for l in open(p):
        f = l.rstrip('\n').split('\t')
        out[int(f[0])] = set(x.strip() for x in (f[1] if len(f) > 1 else '').split(' | ') if x.strip())
    return out
old, new = rd(w + '/prog.old.tsv'), rd(w + '/prog.new.tsv')
ov = open(w + '/pub.oview.jsonl').read().split('\n')
def leaf(n):
    n = (n or '').lower().replace('/', '\\').split('\\')[-1]
    return n[:-4] if n.endswith('.exe') else n
def red(e):
    k, rest = e.split(':', 1)
    path, tail = rest.rsplit('(', 1)
    return '%s(%s)%s' % (k, 'P' if path else '-', '(' + tail.split(')')[0] + ')@' + e.rsplit('@', 1)[-1])
sig = collections.Counter(); ex = {}
for r in [l.strip() for l in open(rp) if l.strip()]:
    i = idx[r]; o = json.loads(ov[i])
    for e in sorted(old[i] - new[i]):
        prog = leaf(e.rsplit('@', 1)[-1])
        shapes = ['/'.join((el[0] if isinstance(el, list) else str(el)) for el in c.get('el', [])) for c in o.get('cmds', []) if leaf(c.get('cn')) == prog]
        nk = sorted(set(red(x) for x in new[i] if leaf(x.rsplit('@', 1)[-1]) == prog))
        s = '%s | pwsh els=%s | port same-prog=%s' % (red(e), shapes[:2], nk[:3])
        sig[s] += 1; ex.setdefault(s, r)
for s, c in sig.most_common(40):
    print(c, ex[s], s[:330])
