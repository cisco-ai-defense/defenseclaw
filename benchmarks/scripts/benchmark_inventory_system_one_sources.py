from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line, object_pairs_hook=strict_object)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected object")
            yield row


def family_id(row: dict[str, Any]) -> str:
    strata = row.get("strata") if isinstance(row.get("strata"), dict) else {}
    source = row.get("source") if isinstance(row.get("source"), dict) else {}
    for value in (strata.get("split_group"), strata.get("trajectory_id"), source.get("original_id"), row.get("id")):
        if isinstance(value, str) and value:
            return value
    return "missing"


def truth_grade(row: dict[str, Any]) -> str:
    truth = row.get("truth") if isinstance(row.get("truth"), dict) else {}
    categories = set(truth.get("categories") or [])
    source_truth = truth.get("source_truth")
    deterministic = truth.get("deterministic_truth")
    expected = truth.get("expected_disposition")
    confidence = truth.get("label_confidence")
    applicability = truth.get("applicability")
    if applicability == "out_of_scope" or source_truth == "unknown" and not deterministic:
        return "E"
    if deterministic == "deterministic_malicious" or "exact_proof" in categories or "closed_proof" in categories:
        return "A"
    if source_truth in {"malicious", "sensitive"} and row.get("surface") == "stateful" and confidence == "high":
        return "B"
    if expected == "allow" and (source_truth == "benign" or deterministic == "benign"):
        return "D"
    if source_truth in {"malicious", "sensitive"} or deterministic == "contextual_or_dual_use":
        return "C"
    return "E"


def inspect_cases(path: Path) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    datasets: Counter[str] = Counter()
    families: set[str] = set()
    ids: set[str] = set()
    duplicates = 0
    source_revisions: dict[str, set[str]] = defaultdict(set)
    for row in read_jsonl(path):
        case_id = row.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"{path}: case missing id")
        if case_id in ids:
            duplicates += 1
        ids.add(case_id)
        source = row.get("source") if isinstance(row.get("source"), dict) else {}
        truth = row.get("truth") if isinstance(row.get("truth"), dict) else {}
        strata = row.get("strata") if isinstance(row.get("strata"), dict) else {}
        dataset = str(source.get("dataset", "missing"))
        datasets[dataset] += 1
        source_revisions[dataset].add(str(source.get("revision", "missing")))
        families.add(family_id(row))
        for key, value in {
            "grade": truth_grade(row),
            "split": row.get("split", "missing"),
            "surface": row.get("surface", "missing"),
            "source_truth": truth.get("source_truth", "missing"),
            "deterministic_truth": truth.get("deterministic_truth", "missing"),
            "disposition": truth.get("expected_disposition", "missing"),
            "confidence": truth.get("label_confidence", "missing"),
            "applicability": truth.get("applicability", "missing"),
            "hard_negative": bool(strata.get("hard_negative", False)),
            "intent": bool((row.get("payload") or {}).get("content"))
            if isinstance(row.get("payload"), dict)
            else False,
        }.items():
            counts[f"{key}:{value}"] += 1
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "cases": len(ids),
        "families": len(families),
        "duplicate_ids": duplicates,
        "datasets": dict(sorted(datasets.items())),
        "source_revisions": {key: sorted(value) for key, value in sorted(source_revisions.items())},
        "counts": dict(sorted(counts.items())),
    }


def build_catalog(inputs: list[Path], manifests: list[Path]) -> dict[str, Any]:
    corpora = [inspect_cases(path) for path in inputs]
    manifest_rows = []
    for path in manifests:
        value = read_json(path)
        manifest_rows.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "content_sha256": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            }
        )
    all_ids: dict[str, list[str]] = defaultdict(list)
    all_families: dict[str, list[str]] = defaultdict(list)
    for path in inputs:
        for row in read_jsonl(path):
            all_ids[str(row["id"])].append(str(path))
            all_families[family_id(row)].append(str(path))
    overlaps = {
        "duplicate_case_ids": sum(len(set(paths)) > 1 for paths in all_ids.values()),
        "cross_corpus_families": sum(len(set(paths)) > 1 for paths in all_families.values() if paths),
    }
    total_counts: Counter[str] = Counter()
    for corpus in corpora:
        total_counts.update(corpus["counts"])
    return {
        "schema_version": "1",
        "kind": "defenseclaw-system-one-source-catalog",
        "corpora": corpora,
        "manifests": manifest_rows,
        "totals": dict(sorted(total_counts.items())),
        "overlaps": overlaps,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", type=Path, default=[])
    parser.add_argument("--manifest", action="append", type=Path, default=[])
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input:
        raise ValueError("at least one --input is required")
    catalog = build_catalog(args.input, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"output": str(args.output), "corpora": len(catalog["corpora"]), "totals": catalog["totals"]},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
