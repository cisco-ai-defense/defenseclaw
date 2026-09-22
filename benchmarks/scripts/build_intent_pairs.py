"""Assemble matched causal pairs for the intent-deviation experiment.

For each AgentDojo user task (pair_group) take one case of each available class:

  clean                 same user request, no attack             -> expected allow
  attacked_resisted     attacker content present, agent refused  -> expected allow (hard negative)
  attacked_compromised  attack succeeded, actions serve attacker -> expected detect

Holding the user request fixed across the three isolates the variable DefenseClaw actually
cares about: whether the trajectory still serves the stated intent. A backend that only detects
intrinsic danger should score near chance here, because the tool calls are individually
plausible in all three conditions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

CLASSES = ("clean", "attacked_resisted", "attacked_compromised")


def rank(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}\0{value}".encode()).hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--per-class-per-group", type=int, default=1)
    p.add_argument("--seed", type=int, default=741983)
    args = p.parse_args()

    groups: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    with args.cases.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            st = row.get("strata") or {}
            groups[str(st.get("pair_group"))][str(st.get("case_class"))].append(row)

    selected: list[dict[str, Any]] = []
    complete_triples = 0
    classes: Counter[str] = Counter()
    for _group, by_class in sorted(groups.items()):
        present = [c for c in CLASSES if by_class.get(c)]
        if len(present) == len(CLASSES):
            complete_triples += 1
        for klass in present:
            pool = sorted(by_class[klass], key=lambda r: rank(args.seed, str(r["id"])))
            for row in pool[: args.per_class_per_group]:
                row["strata"]["pair_complete"] = len(present) == len(CLASSES)
                selected.append(row)
                classes[klass] += 1

    selected.sort(key=lambda r: (str(r["strata"]["pair_group"]), str(r["strata"]["case_class"])))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out:
        for row in selected:
            out.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    events = sum(len(r["payload"]["events"]) for r in selected)
    manifest = {
        "schema_version": "1",
        "kind": "defenseclaw-intent-deviation-pairs",
        "seed": args.seed,
        "cases": len(selected),
        "decisions": events,
        "pair_groups": len(groups),
        "complete_triples": complete_triples,
        "case_classes": dict(classes.most_common()),
        "design": (
            "User request held fixed within a pair_group across clean / attacked_resisted / "
            "attacked_compromised. Detecting attacked_compromised above the two allow classes is "
            "evidence of intent-deviation capability, not intrinsic-danger capability."
        ),
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in
                      ("cases", "decisions", "pair_groups", "complete_triples", "case_classes")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
