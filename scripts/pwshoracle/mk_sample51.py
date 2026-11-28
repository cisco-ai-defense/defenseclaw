#!/usr/bin/env python3
"""mk_sample51.py FIXTUREDIR OUT.b64 OUT.ids : the 5.1 sample = every public row of the targeted corpora (not the go-test recorder) plus
the first rows of the recorder up to 500, skipping scripts over 20 KB."""
import sys, gzip, base64
F, out, outids = sys.argv[1:4]
rows = gzip.open(F + '/pub.b64.gz', 'rt').read().split('\n')
ids = [l.rstrip('\n').split('\t') for l in open(F + '/pub.ids')]
sel = []
for i, (rid, labs) in enumerate(ids):
    if labs != 'gotest' and len(rows[i]) < 27000: sel.append(i)
for i, (rid, labs) in enumerate(ids):
    if len(sel) >= 500: break
    if labs == 'gotest' and len(rows[i]) < 27000: sel.append(i)
sel = sel[:500]
open(out, 'w').write('\n'.join(rows[i] for i in sel) + '\n')
open(outids, 'w').write('\n'.join('%d\t%s' % (i, ids[i][0]) for i in sel) + '\n')
print(len(sel), 'rows')
