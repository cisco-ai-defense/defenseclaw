#!/usr/bin/env python3
"""Build the reading view (commands, arguments, string kinds, script blocks, pipelines,
redirections) from the dumper's output (pwsh_oracle_dump.ps1 JSONL). Same shape as psview prints
for internal/psparse. Usage: oracle_view.py oracle.jsonl [row-index-base] > view.jsonl"""
import sys, json
SKIND = {'BareWord': 'bare', 'SingleQuoted': 'sq', 'DoubleQuoted': 'dq',
         'SingleQuotedHereString': 'hsq', 'DoubleQuotedHereString': 'hdq'}
OTHER = {'SubExpressionAst': 'SubExpr', 'ParenExpressionAst': 'Paren', 'ArrayExpressionAst': 'ArrayExpr',
         'HashtableAst': 'Hashtable', 'ScriptBlockExpressionAst': 'ScriptBlockExpr', 'MemberExpressionAst': 'Member',
         'InvokeMemberExpressionAst': 'Invoke', 'IndexExpressionAst': 'Index', 'ConvertExpressionAst': 'Convert',
         'UnaryExpressionAst': 'Unary', 'BinaryExpressionAst': 'Binary', 'ArrayLiteralAst': 'ArrayLit',
         'TypeExpressionAst': 'TypeExpr', 'ErrorExpressionAst': 'ErrorExpr'}
STREAM = {'Output': '1', 'Error': '2', 'Warning': '3', 'Verbose': '4', 'Debug': '5', 'Information': '6', 'All': '*'}

def expr(n):
    t, p = n[1], n[4]
    if t == 'StringConstantExpressionAst':
        return [SKIND.get(p.get('StringConstantType'), 'str?'), p.get('Value'), True]
    if t == 'ExpandableStringExpressionAst':
        k = SKIND.get(p.get('StringConstantType'), 'dq')
        return [k + 'x', p.get('Value'), False]
    if t == 'ConstantExpressionAst':
        return ['num', p.get('Value'), True]
    if t == 'VariableExpressionAst':
        return ['var', p.get('VariablePath'), False]
    return ['other:' + OTHER.get(t, t), None, False]

def build(rec):
    ast = rec['ast']
    cmds, pipes, chains, sbs = [], [], 0, 0
    nmax = len(ast)
    def kids(i):
        d = ast[i][0]; out = []; j = i + 1
        while j < nmax and ast[j][0] > d:
            if ast[j][0] == d + 1: out.append(j)
            j += 1
        return out
    for i, n in enumerate(ast):
        t = n[1]
        if t == 'ScriptBlockExpressionAst': sbs += 1
        elif t == 'PipelineChainAst': chains += 1
        elif t == 'PipelineAst':
            pipes.append(len(kids(i)))
        elif t == 'CommandAst':
            p = n[4]
            ks = kids(i); els = []; rd = []; name = ['none', None, False]; first = True
            for k in ks:
                kt = ast[k][1]
                if kt == 'FileRedirectionAst':
                    kk = kids(k)
                    rd.append(['file', STREAM.get(ast[k][4].get('FromStream'), '?'), ast[k][4].get('Append') == 'true',
                               expr(ast[kk[0]]) if kk else ['none', None, False]])
                elif kt == 'MergingRedirectionAst':
                    rd.append(['merge', STREAM.get(ast[k][4].get('FromStream'), '?'), STREAM.get(ast[k][4].get('ToStream'), '?')])
                elif kt == 'CommandParameterAst':
                    kk = kids(k)
                    e = ['param', ast[k][4].get('ParameterName'), bool(kk), expr(ast[kk[0]]) if kk else ['none', None, False]]
                    if first: name = e
                    else: els.append(e)
                    first = False
                else:
                    e = expr(ast[k])
                    if first: name = e
                    else: els.append(e)
                    first = False
            cmds.append({'s': n[2], 'op': {'Ampersand': '&', 'Dot': '.'}.get(p.get('InvocationOperator'), ''),
                         'name': name, 'el': els, 'rd': rd, 'cn': p.get('CommandName')})
    return {'i': rec['i'], 'cmds': cmds, 'sbs': sbs, 'pipes': pipes, 'chains': chains,
            'err': [e[0] for e in rec['err']]}

base = int(sys.argv[2]) if len(sys.argv) > 2 else 0
for ln in open(sys.argv[1]):
    rec = json.loads(ln)
    rec['i'] += base
    if rec.get('empty') or rec.get('crash'):
        print(json.dumps({'i': rec['i'], 'bad': True})); continue
    print(json.dumps(build(rec), separators=(',', ':')))
