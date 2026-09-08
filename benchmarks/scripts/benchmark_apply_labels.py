# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Apply provisional gpt-oss labels without erasing source provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

if __package__:
    from .benchmark_error_analysis import load_jsonl, sha256_file
    from .benchmark_label_bedrock import (
        MODEL_ID,
        LEGACY_MODEL_ID,
        MANUAL_MODEL_ID,
        MANUAL_PROMPT_VERSION,
        SUPPORTED_PROMPT_VERSIONS,
        extract_command,
        normalize_label,
    )
else:
    from benchmark_error_analysis import load_jsonl, sha256_file
    from benchmark_label_bedrock import (
        MANUAL_MODEL_ID,
        MANUAL_PROMPT_VERSION,
        MODEL_ID,
        LEGACY_MODEL_ID,
        SUPPORTED_PROMPT_VERSIONS,
        extract_command,
        normalize_label,
    )

LABEL_SOURCE_BY_PROMPT = {
    "deterministic-command-gpt-oss-20b-v1": "bedrock_gpt_oss_20b_v1",
    "deterministic-command-gpt-oss-20b-v2": "bedrock_gpt_oss_20b_v2",
    "deterministic-command-block-review-gpt-oss-20b-v3": "bedrock_gpt_oss_20b_v3",
    "deterministic-command-proof-review-gpt-oss-20b-v4": "bedrock_gpt_oss_20b_v4",
    "deterministic-command-gpt-oss-120b-v1": "bedrock_gpt_oss_120b_v1",
    "deterministic-command-block-review-gpt-oss-120b-v1": "bedrock_gpt_oss_120b_block_v1",
    "deterministic-command-proof-review-gpt-oss-120b-v1": "bedrock_gpt_oss_120b_proof_v1",
    "explicit-command-proof-review-v1": "explicit_proof_review_v1",
}


def index_annotations(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        case_id = str(row.get("id", ""))
        if not case_id or case_id in indexed:
            raise ValueError(f"missing or duplicate annotation ID {case_id!r}")
        indexed[case_id] = row
    return indexed


def verified_label(annotation: dict[str, Any], source_row: dict[str, Any]) -> dict[str, str]:
    case_id = str(source_row["id"])
    if annotation.get("prompt_version") not in SUPPORTED_PROMPT_VERSIONS:
        raise ValueError(f"{case_id}: unexpected prompt version")
    prompt_version = str(annotation.get("prompt_version", ""))
    if prompt_version == MANUAL_PROMPT_VERSION:
        expected_model_id = MANUAL_MODEL_ID
    elif "gpt-oss-20b" in prompt_version:
        expected_model_id = LEGACY_MODEL_ID
    else:
        expected_model_id = MODEL_ID
    if annotation.get("model_id") != expected_model_id:
        raise ValueError(f"{case_id}: unexpected model ID")
    command = extract_command(source_row)
    if command is None:
        raise ValueError(f"{case_id}: source case has no command")
    expected_digest = hashlib.sha256(command.encode()).hexdigest()
    if annotation.get("input_sha256") != expected_digest:
        raise ValueError(f"{case_id}: annotation input digest does not match corpus")
    label = annotation.get("label")
    if not isinstance(label, dict):
        raise ValueError(f"{case_id}: annotation has no label")
    normalized = normalize_label({"id": case_id, **label}, case_id, prompt_version)
    if normalized != label:
        raise ValueError(f"{case_id}: annotation label is not canonical")
    return normalized


def write_corpus(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def exclude_unadjudicated(row: dict[str, Any], reason: str) -> None:
    truth = row["truth"]
    if truth.get("applicability") == "in_scope":
        truth["applicability"] = "out_of_scope"
        truth["exclusion_reason"] = reason


def include_adjudicated(row: dict[str, Any]) -> None:
    """Restore only rows provisionally excluded pending model adjudication."""
    truth = row["truth"]
    if truth.get("exclusion_reason") not in {
        "pending_gpt_oss_20b_review",
        "pending_gpt_oss_120b_review",
    }:
        return
    truth["applicability"] = "in_scope"
    truth.pop("exclusion_reason", None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-review", action="store_true")
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument(
        "--preserve-benign-source-truth",
        action="store_true",
        help="keep in-scope public benign rows as benchmark negatives instead of applying model labels",
    )
    parser.add_argument(
        "--retain-unlabeled-source-truth",
        action="store_true",
        help="exploratory only: score missing/review rows using broad source labels",
    )
    args = parser.parse_args()

    corpus = load_jsonl(args.corpus)
    annotations = index_annotations(load_jsonl(args.labels))
    corpus_ids = {str(row["id"]) for row in corpus}
    unknown = sorted(set(annotations) - corpus_ids)
    if unknown:
        parser.error(f"labels reference {len(unknown)} unknown corpus case IDs")
    applied = 0
    review_required = 0
    missing = 0
    output_rows: list[dict[str, Any]] = []
    for source_row in corpus:
        row = json.loads(json.dumps(source_row))
        if (
            args.preserve_benign_source_truth
            and row["truth"].get("applicability") == "in_scope"
            and row["truth"].get("source_truth") == "benign"
        ):
            truth = row["truth"]
            truth["deterministic_truth"] = "benign"
            truth["label_confidence"] = "high"
            truth["label_source"] = "public_benign_source"
            truth["expected_disposition"] = "allow"
            applied += 1
            output_rows.append(row)
            continue
        annotation = annotations.get(str(row["id"]))
        if annotation is None:
            missing += 1
            if not args.retain_unlabeled_source_truth:
                exclude_unadjudicated(row, "missing_deterministic_label")
            output_rows.append(row)
            continue
        label = verified_label(annotation, row)
        if label.get("verdict") == "invalid":
            review_required += 1
            if not args.retain_unlabeled_source_truth:
                exclude_unadjudicated(row, "invalid_or_noncommand_label")
            output_rows.append(row)
            continue
        if annotation.get("review_required") and not args.include_review:
            review_required += 1
            if not args.retain_unlabeled_source_truth:
                exclude_unadjudicated(row, "review_required_deterministic_label")
            output_rows.append(row)
            continue
        truth = row["truth"]
        include_adjudicated(row)
        truth["deterministic_truth"] = label["verdict"]
        truth["label_confidence"] = label["confidence"]
        truth["label_source"] = LABEL_SOURCE_BY_PROMPT[str(annotation["prompt_version"])]
        truth["expected_disposition"] = label["disposition"]
        category = f"adjudicated-{label['category']}"
        truth["categories"] = sorted(set((truth.get("categories") or []) + [category]))
        applied += 1
        output_rows.append(row)
    if args.require_all and (missing or review_required):
        parser.error(f"labels incomplete: missing={missing}, review_required={review_required}")
    write_corpus(args.output, output_rows)
    manifest = {
        "schema_version": "1",
        "source_corpus_sha256": sha256_file(args.corpus),
        "labels_sha256": sha256_file(args.labels),
        "output_sha256": sha256_file(args.output),
        "case_count": len(corpus),
        "applied_count": applied,
        "missing_count": missing,
        "review_required_count": review_required,
        "include_review": args.include_review,
        "preserve_benign_source_truth": args.preserve_benign_source_truth,
        "retain_unlabeled_source_truth": args.retain_unlabeled_source_truth,
        "classification_sha256": hashlib.sha256(
            "\n".join(
                f"{row['id']}\t{row['truth'].get('deterministic_truth', '')}\t{row['truth']['expected_disposition']}"
                for row in output_rows
            ).encode()
        ).hexdigest(),
    }
    args.output.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(corpus)} rows: applied={applied}, missing={missing}, review_required={review_required}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
