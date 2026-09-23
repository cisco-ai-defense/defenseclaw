import json
from pathlib import Path

SJ = Path("$WORK/.system-one-data/outputs/secjudge")
rows = []
for f in sorted((SJ / "scores").glob("incumbent-*.json")):
    d = json.loads(f.read_text())
    name = f.stem.removeprefix("incumbent-")
    for c in d["candidates"]:
        so = c["system_one"]
        bo, bi, tw = so["binary_block_only"], so["binary"], so["three_way"]
        det = c.get("deterministic_then_system_one", {})
        dbo = det.get("binary_block_only", {}) if det else {}
        rows.append(
            {
                "arm": name,
                "candidate": c["candidate"],
                "n": c["scorable_cases"],
                "block_f1": bo.get("f1"),
                "block_p": bo.get("precision"),
                "block_r": bo.get("recall"),
                "block_fpr": bo.get("false_positive_rate"),
                "any_f1": bi.get("f1"),
                "any_p": bi.get("precision"),
                "any_r": bi.get("recall"),
                "any_fpr": bi.get("false_positive_rate"),
                "three_way_acc": tw.get("accuracy"),
                "confirm_rate": so.get("review_rate"),
                "det_then_s1_block_f1": dbo.get("f1"),
                "det_then_s1_block_fpr": dbo.get("false_positive_rate"),
                "scorecard": str(f),
            }
        )

(SJ / "incumbent-metrics.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")


def n(v, nd=4):
    return "-" if v is None else f"{v:.{nd}f}"


hdr = (
    f"{'arm':<30}{'n':>7}{'blkF1':>8}{'blkP':>8}{'blkR':>8}{'blkFPR':>9}"
    f"{'anyF1':>8}{'anyP':>8}{'anyR':>8}{'anyFPR':>9}{'3way':>8}{'det+s1F1':>10}"
)
print(hdr)
print("-" * len(hdr))
for r in rows:
    print(
        f"{r['arm']:<30}{r['n']:>7,}{n(r['block_f1']):>8}{n(r['block_p']):>8}{n(r['block_r']):>8}"
        f"{n(r['block_fpr']):>9}{n(r['any_f1']):>8}{n(r['any_p']):>8}{n(r['any_r']):>8}"
        f"{n(r['any_fpr']):>9}{n(r['three_way_acc']):>8}{n(r['det_then_s1_block_f1']):>10}"
    )
print()
print(f"wrote {SJ / 'incumbent-metrics.json'}")
