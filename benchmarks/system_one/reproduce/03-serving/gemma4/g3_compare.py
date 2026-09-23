"""G3: does the readout follow option content or option position?

Compares two runs of the same checkpoint on the same 324 rows, one with the dataset's
option order and one with every Choice's options reversed. Under reversal a
content-driven reader keeps the same answer KEY while its letter changes; a
position-driven reader keeps the same LETTER while its key changes. Score levels and
Noul are not permuted (their prompts assert an ordering), so those rows double as a
determinism check: they must be identical.
"""

import json
import sys
from collections import Counter
from pathlib import Path


def load(path):
    rows = [json.loads(l) for l in (Path(path) / "rows.jsonl").read_text().splitlines() if l.strip()]
    return {r["id"]: r for r in rows}, json.loads((Path(path) / "settings.json").read_text())


def main():
    base_dir, permuted_dir = sys.argv[1], sys.argv[2]
    base, base_settings = load(base_dir)
    perm, perm_settings = load(permuted_dir)
    if base_settings["repo"] != perm_settings["repo"]:
        raise SystemExit("runs are of different checkpoints")
    if base_settings["permute"] != "none" or perm_settings["permute"] == "none":
        raise SystemExit("expected an unpermuted run then a permuted run")
    if set(base) != set(perm):
        raise SystemExit("runs cover different rows")

    out = {"repo": base_settings["repo"], "revision": base_settings.get("revision"),
           "base_run": base_dir, "permuted_run": permuted_dir,
           "permutation": perm_settings["permute"], "rows": len(base), "by_kind": {}}
    for kind in ("choice", "noul", "score", "all"):
        ids = [i for i in base if kind == "all" or base[i]["kind"] == kind]
        if not ids:
            continue
        same_key = sum(json.dumps(base[i]["prediction"]) == json.dumps(perm[i]["prediction"]) for i in ids)
        same_letter = sum(base[i]["selected_letter"] == perm[i]["selected_letter"] for i in ids)
        identical = sum(base[i]["probabilities"] == perm[i]["probabilities"] for i in ids)
        out["by_kind"][kind] = {
            "count": len(ids),
            "accuracy_original_order": sum(base[i]["correct"] for i in ids) / len(ids),
            "accuracy_reversed_order": sum(perm[i]["correct"] for i in ids) / len(ids),
            "correct_original": sum(base[i]["correct"] for i in ids),
            "correct_reversed": sum(perm[i]["correct"] for i in ids),
            "same_predicted_key_rate": same_key / len(ids),
            "same_predicted_letter_rate": same_letter / len(ids),
            "identical_distribution_rate": identical / len(ids),
            "both_correct": sum(base[i]["correct"] and perm[i]["correct"] for i in ids),
            "neither_correct": sum((not base[i]["correct"]) and (not perm[i]["correct"]) for i in ids),
            "only_original_correct": sum(base[i]["correct"] and not perm[i]["correct"] for i in ids),
            "only_reversed_correct": sum((not base[i]["correct"]) and perm[i]["correct"] for i in ids),
        }
    out["letter_histogram_original"] = dict(sorted(Counter(
        base[i]["selected_letter"] for i in base if base[i]["kind"] == "choice").items()))
    out["letter_histogram_reversed"] = dict(sorted(Counter(
        perm[i]["selected_letter"] for i in perm if perm[i]["kind"] == "choice").items()))
    # How often does the reader pick the first presented option?
    for label, table in (("original", base), ("reversed", perm)):
        choice_ids = [i for i in table if table[i]["kind"] == "choice"]
        out[f"first_option_rate_{label}"] = sum(table[i]["selected_letter"] == "A" for i in choice_ids) / len(choice_ids)
    choice_ids = [i for i in base if base[i]["kind"] == "choice"]
    out["verdict"] = {
        "content_following_rate": out["by_kind"]["choice"]["same_predicted_key_rate"],
        "position_following_rate": out["by_kind"]["choice"]["same_predicted_letter_rate"],
        "unpermuted_kinds_bit_identical": all(
            base[i]["probabilities"] == perm[i]["probabilities"] for i in base if base[i]["kind"] != "choice"),
        "choice_accuracy_delta": (out["by_kind"]["choice"]["accuracy_reversed_order"]
                                  - out["by_kind"]["choice"]["accuracy_original_order"]),
        "choice_rows": len(choice_ids),
    }
    print(json.dumps(out, indent=2))
    Path(sys.argv[3]).write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
