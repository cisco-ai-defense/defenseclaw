import json
import pathlib

SJ = pathlib.Path("$WORK/.system-one-data/outputs/secjudge")
alt = json.load(open(SJ / "serialisation-ablation-alt.json"))

prod = None
for line in open(SJ / "logs/ablation-run1-prodC0.log"):
    line = line.strip()
    if line.startswith('{"prod_C0"'):
        prod = json.loads(line)["prod_C0"]

combined = dict(alt)
combined["results"] = {}
if prod:
    combined["results"]["prod_C0_PARITY"] = prod
combined["results"].update(alt["results"])
combined["note"] = (
    "Same stratified s2 sample (60 unsafe grade-A/B, 120 benign grade-D, seed 741983) and the same "
    "per-case aggregation as the shared scorer (risk = max calibrated over events; block = any "
    "event HIGH/CRITICAL). prod_C0_PARITY is the parity-faithful serialisation used for the "
    "headline numbers. prod_C7 was not run here because the full s2 and intent-real C7 stages "
    "measure it directly at full corpus scale."
)
combined["winner_by_auc"] = max(combined["results"], key=lambda k: combined["results"][k]["roc_auc_calibrated"])
(SJ / "serialisation-ablation.json").write_text(json.dumps(combined, indent=2, sort_keys=True) + "\n")

print("winner by AUC:", combined["winner_by_auc"])
hdr = f"{'serialisation':<20}{'AUC':>8}{'blk_unsafe':>12}{'blk_benign':>12}{'levels':>8}{'tokens':>9}"
print(hdr)
for k, v in combined["results"].items():
    print(
        f"{k:<20}{v['roc_auc_calibrated']:>8.4f}{v['severity_block_rate_unsafe']:>12.4f}"
        f"{v['severity_block_rate_benign']:>12.4f}{v['distinct_risk_levels']:>8}{v['tokens_mean']:>9.1f}"
    )
