"""Compare candidate-logit dumps from g2d_logits.py across devices and attention kernels."""

import json
import math
import sys
from pathlib import Path


def load(path):
    d = json.load(open(path))
    return d, {(r["case_id"], r["event_index"]): r for r in d["rows"]}


def main():
    dumps = [load(p) for p in sys.argv[1:-1]]
    names = [f"{d['device']}/{d['attn']}/{d['dtype']}" for d, _ in dumps]
    keys = sorted(set.intersection(*[set(rows) for _, rows in dumps]),
                  key=lambda k: dumps[0][1][k]["tokens"])
    print("dumps:", names)
    print("shared prompts:", len(keys))
    out = {"dumps": [{"name": n, **{k: v for k, v in d.items() if k != "rows"}} for n, (d, _) in zip(names, dumps)],
           "pairs": {}}
    for i in range(len(dumps)):
        for j in range(i + 1, len(dumps)):
            worst = {"max_abs_label_probability_diff": 0.0, "max_abs_candidate_logit_diff": 0.0,
                     "argmax_disagreements": 0, "per_prompt": []}
            for key in keys:
                a, b = dumps[i][1][key], dumps[j][1][key]
                pa, pb = a["label_probabilities"], b["label_probabilities"]
                la, lb = a["candidate_logits"], b["candidate_logits"]
                dp = max(abs(x - y) for x, y in zip(pa, pb))
                dl = max(abs(x - y) for x, y in zip(la, lb))
                agree = max(range(len(pa)), key=pa.__getitem__) == max(range(len(pb)), key=pb.__getitem__)
                worst["max_abs_label_probability_diff"] = max(worst["max_abs_label_probability_diff"], dp)
                worst["max_abs_candidate_logit_diff"] = max(worst["max_abs_candidate_logit_diff"], dl)
                worst["argmax_disagreements"] += not agree
                worst["per_prompt"].append({"tokens": a["tokens"], "label_prob_diff": dp,
                                            "logit_diff": dl, "argmax_agrees": agree})
            name = f"{names[i]} vs {names[j]}"
            out["pairs"][name] = worst
            print("%-52s labelprob=%.6g logit=%.6g argmaxX=%d" % (
                name, worst["max_abs_label_probability_diff"],
                worst["max_abs_candidate_logit_diff"], worst["argmax_disagreements"]))
    # entropy of each dump's distributions, to show whether the prompts are saturated
    for name, (d, rows) in zip(names, dumps):
        ent = []
        for r in d["rows"]:
            p = r["label_probabilities"]
            ent.append(-sum(x * math.log(max(x, 1e-15)) for x in p) / math.log(len(p)))
        out.setdefault("normalized_entropy", {})[name] = {
            "min": min(ent), "median": sorted(ent)[len(ent) // 2], "max": max(ent)}
        print("%-52s normalized entropy min=%.4f med=%.4f max=%.4f" % (
            name, min(ent), sorted(ent)[len(ent) // 2], max(ent)))
    Path(sys.argv[-1]).write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
