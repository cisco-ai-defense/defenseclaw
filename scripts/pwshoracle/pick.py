#!/usr/bin/env python3
"""pick.py RUNDIR OUT ID... : write the base64 sources of the given public row ids to OUT (one per line, in the order given)"""
import sys
W, out = sys.argv[1], sys.argv[2]; want = sys.argv[3:]
ids = [l.split('\t')[0] for l in open(W + '/pub.ids')]; pos = {r: i for i, r in enumerate(ids)}
lines = open(W + '/pub.b64').read().split('\n')
open(out, 'w').write('\n'.join(lines[pos[r]] for r in want) + '\n')
