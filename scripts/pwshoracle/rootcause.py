#!/usr/bin/env python3
"""Group the per-row disagreement classes (compare.py rows.tsv) into root causes.
Usage: rootcause.py RUNDIR SET(pub|priv)   writes RUNDIR/SET.rootcause.md; for pub prints 10 sample row ids per cause."""
import sys, re, json, base64
from collections import defaultdict
W, SET = sys.argv[1], sys.argv[2]
ids = [l.split('\t')[0] for l in open('%s/%s.ids' % (W, SET))]
src = {}
with open('%s/%s.b64' % (W, SET)) as f:
    for i, ln in enumerate(f): src[ids[i]] = base64.b64decode(ln.strip()).decode('utf8', 'replace')
rows = {}
for ln in open('%s/%s.rows.tsv' % (W, SET)):
    rid, cs = ln.rstrip('\n').split('\t'); rows[rid] = cs.split(' | ')
nested = lambda s: max(s.count('$(@"'), s.count('@('), s.count('$(('), 0) > 40 or s.count('(') > 120 or s.count('{') > 120
def causes(rid, cs):
    s = src[rid]; out = set()
    st = cs[0][1]  # V or E
    base = [c[4:] for c in cs]
    joined = ' || '.join(base)
    if re.search(r'(^|\n)\s*\*{3} ', s) : out.add('apply_patch envelope: a leading `***` word is dropped from the command (ours reads "Begin" as the command)')
    if nested(s): out.add('deep nesting beyond our depth/size bound (ours stops, the real parser keeps reading)')
    if re.search(r'[^\s;|&(){}\[\],=#$"\'`]#', s) or re.search(r'["\']#', s): out.add('"#" inside or right after a word: real parser keeps it in the word, ours starts a comment')
    if re.search(r'(^|[\s=(;|{])#', s) and ('cmd-extra' in joined) : out.add('"#" after an operator ("=#", "(#"): real parser starts a comment, ours reads "#" as a command name')
    if re.search(r'(^|\s)-[A-Za-z]+[\'"]', s) or re.search(r'(^|\s)-[A-Za-z]+\$', s):
        if any(k in joined for k in ('dash-word', 'vs ours param', 'oracle param vs ours param', 'arg-value-differs', 'param-colon')): out.add('parameter token fused with an adjacent quote or variable (-Version\'2\'): one bareword in the real parser, ours splits it into a parameter and a string')
    if 'oracle param vs ours param' in joined or 'param-name-differs' in joined: out.add('parameter name runs through "-", "/" or other punctuation (-nop-ExecutionPolicy, -ep/c): real parser reads one name, ours cuts it')
    if 'param-colon' in joined or re.search(r'-\w+:(\s|$)', s): out.add('-Name: with a space after the colon: real parser takes the next token as the value even if it starts with "-", ours treats it as a new parameter')
    if re.search(r"'[^'\n]*''", s) and ('arg-value-differs (bare)' in joined or 'name-value-differs' in joined): out.add('adjacent quoted pieces glued into one word: ours mis-decodes the doubled quote or drops inner quotes')
    if 'name-kind: oracle bare vs ours other:ErrorExpr' in joined or 'ErrorExpr' in joined: out.add('ours produces an error node where the real parser sees a command or script block')
    if 'scriptblock-count' in joined: out.add('script block counted differently (class/switch/trap bodies and condition blocks)')
    if 'redirection' in joined: out.add('redirection differs (shell-style "<", "<<<", fused "2>&1"-like tokens)')
    if 'pipeline-size' in joined: out.add('pipeline grouping differs')
    if 'oracle errors, ours silent' in joined: out.add('real parser reports a parse error that ours accepts (the script would not run)')
    if 'ours flags, oracle clean' in joined: out.add('ours flags a diagnostic on a script the real parser accepts')
    if 'cmd-span-origin' in joined: out.add('(not a disagreement) spans inside expandable strings are relative to the string')
    if 'dqx' in joined or 'bare vs ours dqx' in joined: out.add('(representation) bare expandable word is a dqx string in ours')
    if re.search(r'(^|[\n;|(])\s*[=\]?]', s) and ('cmd-missed' in joined or 'cmd-extra' in joined or 'name-' in joined or 'arg-count' in joined): out.add('command word that starts with an operator character ("=", "]", "?"): real parser reads it as a command name, ours splits or drops it')
    if '--%' in s and ('param' in joined or 'arg-' in joined): out.add('a quoted or later "--%" word: ours reads the words after it as parameters, the real parser AST omits them or keeps them as one word')
    if re.search(r'(^|\s)--(\s|$)', s) and 'arg-' in joined: out.add('"--" end-of-parameters word: real parser makes it a parameter, ours a string')
    if re.search(r'<#', s) and 'cmd-missed' in joined: out.add('"<#" block comment start right after an operator ("=<# x #>"): ours reads "<" as a redirection and loses the rest of the line')
    if not out and ('arg-value-differs' in joined or 'name-value' in joined): out.add('fused word value differs: ours drops inner quotes or a doubled quote of a word built from several quoted pieces')
    if not out and any(x in joined for x in ('param', 'dash-word', 'arg-count', 'arg-kind')): out.add('word glued from adjacent pieces (a word touching a quote or a "-" word, 2-of, 0x10-of): one word in the real parser, ours splits it')
    if not out: out.add('UNASSIGNED')
    return [('[%s] ' % st) + o for o in sorted(out)]
agg = defaultdict(list)
for rid, cs in rows.items():
    for c in causes(rid, cs): agg[c].append(rid)
with open('%s/%s.rootcause.md' % (W, SET), 'w') as f:
    f.write('| root cause | rows | sample row ids |\n|---|---|---|\n')
    for k, rs in sorted(agg.items(), key=lambda kv: -len(kv[1])):
        f.write('| %s | %d | %s |\n' % (k, len(rs), ', '.join(sorted(rs)[:10]) if SET == 'pub' else '(private)'))
print(open('%s/%s.rootcause.md' % (W, SET)).read())
