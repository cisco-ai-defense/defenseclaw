# cls.py W IDS WEAKER : classify rows that lose an effect (old psparse reader -> port)
# against the pwsh oracle command view. Counts + ids only.
import sys, json, collections
w, idsp, weakp = sys.argv[1:4]
ids = [l.split('\t')[0] for l in open(idsp)]
idx = {r: i for i, r in enumerate(ids)}
weak = [l.strip() for l in open(weakp) if l.strip()]
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
cls = collections.Counter(); rows = collections.defaultdict(list); sub = collections.Counter()
for r in weak:
    i = idx[r]
    lost = old[i] - new[i]
    o = json.loads(ov[i]) if ov[i] else {}
    ocmds = set(leaf(c.get('cn')) for c in o.get('cmds', []))
    newprogs = set(e.rsplit('@', 1)[-1] for e in new[i])
    worst = 'a'
    for e in lost:
        kind = e.split(':', 1)[0]
        prog = leaf(e.rsplit('@', 1)[-1])
        if prog and prog not in ocmds:
            c = 'a:prog-not-in-pwsh'
        elif prog in newprogs and any(x.split(':', 1)[0] == kind and leaf(x.rsplit('@', 1)[-1]) == prog for x in new[i]):
            c = 'r:same-kind-prog-other-target'
        elif prog in newprogs:
            c = 'r:prog-kept-kind-lost'
        else:
            c = 'b?:pwsh-has-prog-port-lost-it'
        sub[c] += 1
        if c.startswith('b') or (c.startswith('r') and worst == 'a'):
            worst = c
    cls[worst] += 1; rows[worst].append(r)
print('rows by worst class:', dict(cls))
print('lost effects by class:', dict(sub))
for k, v in rows.items():
    open(w + "/cls." + k.replace("?", "q").replace(":", ".") + ".ids", "w").write('\n'.join(v) + '\n')
