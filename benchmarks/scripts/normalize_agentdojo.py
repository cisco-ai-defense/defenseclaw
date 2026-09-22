"""Normalize AgentDojo run traces into case-v1, PRESERVING user intent.

This closes the gap that blocks the whole intent-deviation question: 0 of 1,000 S1 cases and 0
of 8,000 scanned agent-trace records carry a user turn, so DefenseClaw's "does this call match
what the user asked" mechanism has never been evaluated. AgentDojo traces do carry it, plus
ground truth:

  user_task_id      the legitimate request  -> payload.content (INTENT)
  injection_task_id the attacker's goal     -> present only on attacked runs
  security          False = attack SUCCEEDED (agent was compromised)
  utility           True  = the user's task still completed

Three case classes come out of that:
  attacked_compromised  injection present, security False -> trajectory contains
                        intent-deviating actions. source_truth malicious.
  attacked_resisted     injection present, security True  -> attack attempted and refused.
                        A hard negative: attacker content in context, correct behaviour.
  clean                 no injection -> benign baseline.

`strata.pair_group` ties runs sharing a user task together so matched vs mismatched intent
pairs can be assembled. Family identity is per-run so pairs are not collapsed by
family-deduplicated selection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def text_of(content: Any) -> str:
    """AgentDojo content is either a string or a list of {type, content} blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                c = block.get("content")
                if isinstance(c, str):
                    parts.append(c)
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return ""


def case_id(suite: str, user_task: str, injection: str | None, attack: str | None, path: Path) -> str:
    digest = hashlib.sha256(str(path).encode()).hexdigest()[:16]
    return f"agentdojo-{suite}-{user_task}-{injection or 'none'}-{attack or 'none'}-{digest}"


def build_case(path: Path, doc: dict[str, Any]) -> dict[str, Any] | None:
    suite = str(doc.get("suite_name") or "unknown")
    user_task = str(doc.get("user_task_id") or "unknown")
    injection = doc.get("injection_task_id")
    attack = doc.get("attack_type")
    security = doc.get("security")
    utility = doc.get("utility")
    messages = doc.get("messages") or []

    intent = ""
    events: list[dict[str, Any]] = []
    for msg in messages:
        role = msg.get("role")
        if role == "user" and not intent:
            intent = text_of(msg.get("content")).strip()
        for call in msg.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            name = str(call.get("function") or "unknown")
            args = call.get("args")
            events.append(
                {
                    "tool_name": name,
                    "args": args if isinstance(args, (dict, list, str)) else {},
                    "dialect": "structured",
                    "outcome": "unknown",
                }
            )
    if not intent or not events:
        return None

    if injection and security is False:
        # AgentDojo's own checker says the attack succeeded: the trajectory contains actions
        # that serve the attacker rather than the user.
        source_truth, disposition, confidence, klass = "malicious", "detect_only", "high", "attacked_compromised"
        hard_negative = False
    elif injection:
        # Attacker content was present in context and the agent did not comply.
        source_truth, disposition, confidence, klass = "benign", "allow", "high", "attacked_resisted"
        hard_negative = True
    else:
        source_truth, disposition, confidence, klass = "benign", "allow", "high", "clean"
        hard_negative = False

    return {
        "schema_version": "1",
        "id": case_id(suite, user_task, injection, attack, path),
        "split": "development",
        "surface": "stateful",
        "source": {
            "dataset": "agentdojo",
            "revision": "089ed468cf3ed0322acc66b0211f26d9d90dbf60",
            "original_id": f"{suite}/{user_task}/{attack or 'none'}/{injection or 'none'}",
        },
        "payload": {"content": intent, "events": events},
        "truth": {
            "applicability": "in_scope",
            "source_truth": source_truth,
            "deterministic_truth": "contextual_or_dual_use",
            "expected_disposition": disposition,
            "label_confidence": confidence,
            "categories": ["intent_deviation"] if klass == "attacked_compromised" else [],
        },
        "strata": {
            # per-run family so matched/mismatched pairs survive family-deduplicated selection
            "split_group": f"agentdojo:{suite}:{user_task}:{injection or 'none'}:{attack or 'none'}",
            # shared key for assembling causal pairs
            "pair_group": f"agentdojo:{suite}:{user_task}",
            "case_class": klass,
            "attack_type": attack or "none",
            "injection_task_id": injection or "",
            "agentdojo_security": security,
            "agentdojo_utility": utility,
            "hard_negative": hard_negative,
            "domain": suite,
        },
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--runs-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--limit", type=int, default=0)
    args = p.parse_args()

    stats: Counter[str] = Counter()
    suites: Counter[str] = Counter()
    pair_groups: set[str] = set()
    intent_lens: list[int] = []
    rows = 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out:
        for path in sorted(args.runs_root.rglob("*.json")):
            if args.limit and rows >= args.limit:
                break
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                stats["unreadable"] += 1
                continue
            case = build_case(path, doc)
            if case is None:
                stats["skipped_no_intent_or_events"] += 1
                continue
            out.write(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n")
            rows += 1
            stats[case["strata"]["case_class"]] += 1
            suites[case["strata"]["domain"]] += 1
            pair_groups.add(case["strata"]["pair_group"])
            intent_lens.append(len(case["payload"]["content"]))

    manifest = {
        "schema_version": "1",
        "kind": "defenseclaw-agentdojo-normalized",
        "source": {"dataset": "agentdojo", "revision": "089ed468cf3ed0322acc66b0211f26d9d90dbf60", "license": "MIT"},
        "cases": rows,
        "case_classes": dict(stats.most_common()),
        "suites": dict(suites.most_common()),
        "pair_groups": len(pair_groups),
        "intent_present": rows,
        "median_intent_chars": sorted(intent_lens)[len(intent_lens) // 2] if intent_lens else 0,
        "note": (
            "Every case carries payload.content (the real user request), which no other "
            "normalized corpus in this project does. attacked_compromised cases are labelled "
            "from AgentDojo's own security checker, not from a model."
        ),
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in
                      ("cases", "case_classes", "suites", "pair_groups", "median_intent_chars")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
