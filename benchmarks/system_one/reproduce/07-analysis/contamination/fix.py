import re
W = "$WORK/.system-one-data/outputs/secjudge/contamination/work"

# --- fix emit3.py: unfilled placeholder + real max-char figure ---
p = W + "/emit3.py"; s = open(p).read()
old = 'A("Both sides are collapsed on the sha256 of the normalised text first")\nA("(training %s -> %s distinct, corpus %s -> %s distinct). Identical texts have identical signatures, so this")'
if old not in s:
    old2 = '''A("(training %s -> %s distinct, corpus %s -> %s distinct). Identical texts have identical signatures, so this")'''
    assert old2 in s, "placeholder line not found"
    s = s.replace(old2, '''A("(training %s -> %s distinct, corpus %s -> %s distinct). Identical texts have identical signatures, so this" % (
    format(545633, ","), format(434473, ","), format(330666, ","), format(213777, ",")))''')
maxchars = 'max((v or {}).get("max_unique_shingles", 0) + 4 for v in mh.values())'
if maxchars in s:
    s = s.replace(maxchars,
        'max([cds[x]["max_norm_chars"] for x in STAGES] + [v["max_norm_chars"] for v in (tds or {}).get("groups", {}).values()])')
# add the card-sum discrepancy and the length-stratified command pass to methodology
anchor = 'A("## 7. What each number means")'
assert anchor in s
ins = '''A("### Length-stratified command pass")
A("")
A("The same bare-string pass was re-run requiring BOTH strings to be at least 40 and at least 80 normalised")
A("characters (`MIN_LEN` env var, outputs `work/command_overlap_min40.json` and `_min80.json`). Candidate")
A("pruning in that pass requires `|A n B| >= max(3, 0.5*min(|A|,|B|))`, which cannot discard a pair with")
A("J>=0.5 because J>=0.5 implies `|A n B| >= (|A|+|B|)/3 >= (2/3)*min(|A|,|B|)`. The strata exist because")
A("with no length floor the exact collisions are dominated by ubiquitous commands (`env`, `df -h`,")
A("`crontab -l`, `rm -rf /`) that carry no evidential weight.")
A("")
'''
s = s.replace(anchor, ins + anchor)
open(p, "w").write(s); print("emit3 patched")

# --- fix emit.py: record the card's own arithmetic discrepancy ---
p = W + "/emit.py"; s = open(p).read()
anchor = '    "card_totals": {"sources": 11, "samples": 15266},'
assert anchor in s
s = s.replace(anchor, '''    "card_totals": {"sources": 11, "samples_stated_by_card": 15266,
                    "samples_summed_from_card_table": 15795,
                    "discrepancy": 529,
                    "note": "the card states 15,266 samples but its own per-source table sums to 15,795 "
                            "(4100+5900+1400+190+490+870+770+680+840+330+225). We report both; percentages "
                            "below use the tabulated 15,795 unless stated otherwise."},''')
old = '"fraction_of_15266_training_samples_whose_source_pool_we_could_obtain": round((5900+1400+870+680+840+330+225)/15266, 4),'
assert old in s
s = s.replace(old, '''"fraction_of_tabulated_15795_samples_whose_source_pool_we_could_obtain": round(10245/15795, 4),
        "fraction_of_stated_15266_samples_whose_source_pool_we_could_obtain": round(10245/15266, 4),''')
open(p, "w").write(s); print("emit patched")
