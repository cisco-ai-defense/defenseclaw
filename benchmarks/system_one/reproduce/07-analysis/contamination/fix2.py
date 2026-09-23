W = "$WORK/.system-one-data/outputs/secjudge/contamination/work"
p = W + "/emit3.py"; s = open(p).read()
old = 'A("(training %s -> %s distinct, corpus %s -> %s distinct). Identical texts have identical signatures, so this")'
assert old in s, "not found"
new = ('A("(training %s -> %s distinct, corpus %s -> %s distinct). Identical texts have identical signatures, so this" % (\n'
       '    format(545633, ","), format(434473, ","), format(330666, ","), format(213777, ",")))')
s = s.replace(old, new)
assert '% (\n' in s
open(p, "w").write(s)
print("patched emit3 placeholder")
