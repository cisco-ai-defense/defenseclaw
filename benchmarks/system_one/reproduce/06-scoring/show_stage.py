import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
d = json.loads(p.read_text())
print(f"== {p.name}  cases={d['case_count']}  grades={d['truth_grades']}")
print(f"   cases_sha256={d['cases_sha256'][:16]}")
for k, v in d["prediction_sha256"].items():
    print(f"   pred {Path(k).name} sha={v[:16]}")
print()


def n(v, nd=4):
    return "-" if v is None else f"{v:.{nd}f}"


hdr = f"{'arm':<26}{'n':>7}{'blkF1':>8}{'blkP':>8}{'blkR':>8}{'blkFPR':>9}{'anyF1':>8}{'anyP':>8}{'anyR':>8}{'anyFPR':>9}{'3way':>8}{'conf%':>8}"
print(hdr)
print("-" * len(hdr))
for c in d["candidates"]:
    so = c["system_one"]
    bo, bi, tw = so["binary_block_only"], so["binary"], so["three_way"]
    arm = c["candidate"].split("/")[0].replace("secjudge-28e810afc911", "sj")
    print(
        f"{arm:<26}{c['scorable_cases']:>7,}{n(bo['f1']):>8}{n(bo['precision']):>8}{n(bo['recall']):>8}"
        f"{n(bo['false_positive_rate']):>9}{n(bi['f1']):>8}{n(bi['precision']):>8}{n(bi['recall']):>8}"
        f"{n(bi['false_positive_rate']):>9}{n(tw['accuracy']):>8}{n(so.get('review_rate')):>8}"
    )

print()
print("CASCADE (real deterministic tier):")
h2 = f"{'arm':<22}{'composition':<44}{'blkF1':>8}{'blkFPR':>9}{'anyF1':>8}{'anyFPR':>9}{'3way':>8}{'llm%':>8}"
print(h2)
print("-" * len(h2))
for c in d["candidates"]:
    arm = c["candidate"].split("/")[0].replace("secjudge-28e810afc911", "sj")
    for comp in [
        "deterministic_then_system_one",
        "deterministic_then_llm",
        "deterministic_then_system_one_then_llm",
        "deterministic_then_system_one_then_llm_two_sided_0.05",
        "deterministic_then_system_one_then_llm_two_sided_0.10",
        "deterministic_then_system_one_then_llm_two_sided_0.20",
        "deterministic_then_system_one_then_llm_two_sided_0.30",
    ]:
        if comp not in c:
            continue
        v = c[comp]
        bo, bi, tw = v["binary_block_only"], v["binary"], v["three_way"]
        print(
            f"{arm:<22}{comp.replace('deterministic_then_', 'det+'):<44}{n(bo['f1']):>8}"
            f"{n(bo['false_positive_rate']):>9}{n(bi['f1']):>8}{n(bi['false_positive_rate']):>9}"
            f"{n(tw['accuracy']):>8}{n(v.get('llm_invocation_rate')):>8}"
        )
