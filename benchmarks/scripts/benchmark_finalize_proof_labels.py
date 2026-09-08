# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Turn a digest-bound explicit proof review into final command-label overrides."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

if __package__:
    from .benchmark_error_analysis import load_jsonl, sha256_file
    from .benchmark_label_bedrock import (
        MANUAL_MODEL_ID,
        MANUAL_PROMPT_VERSION,
        MODEL_ID,
        PROMPT_VERSION_120B_PROOF,
        PROOF_BLOCK_CATEGORIES,
        extract_command,
        normalize_label,
    )
else:
    from benchmark_error_analysis import load_jsonl, sha256_file
    from benchmark_label_bedrock import (
        MANUAL_MODEL_ID,
        MANUAL_PROMPT_VERSION,
        MODEL_ID,
        PROMPT_VERSION_120B_PROOF,
        PROOF_BLOCK_CATEGORIES,
        extract_command,
        normalize_label,
    )


def annotation(case_id: str, command: str, label: dict[str, str], review_required: bool) -> dict[str, Any]:
    canonical = normalize_label({"id": case_id, **label}, case_id, MANUAL_PROMPT_VERSION)
    return {
        "schema_version": "1",
        "id": case_id,
        "prompt_version": MANUAL_PROMPT_VERSION,
        "input_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "model_id": MANUAL_MODEL_ID,
        "label": canonical,
        "review_required": review_required,
    }


def literal_machine_witness(command: str, category: str) -> tuple[bool, str]:
    """Conservatively verify proof classes the local text can establish.

    This is intentionally narrower than the model rubric. Privacy reduction
    removes external-destination and artifact lineage, so those categories
    cannot become publication positives from model assertion alone.
    """
    value = command.casefold()
    reverse_shell = bool(
        re.search(r"\b(?:ba|z|k|c)?sh\b[^\n]{0,200}/dev/(?:tcp|udp)/[^\s;/]+/[0-9]{1,5}", value)
        or re.search(r"\bsocat\b[^\n]{0,300}\btcp-connect:[^\s]+[^\n]{0,300}\bexec:[^\n]{0,80}\bsh\b", value)
        or (
            re.search(r"\b(?:nc|ncat|netcat)\b[^\n]{0,240}(?:\s-e\s|\s--exec(?:=|\s))[^\n]{0,80}\bsh\b", value)
            and not re.search(r"(?:^|\s)-(?:[^\s]*l[^\s]*)(?:\s|$)|\s--listen(?:\s|$)", value)
        )
    )
    bind_shell = bool(
        re.search(
            r"\b(?:nc|ncat|netcat)\b[^\n]{0,240}(?:(?:^|\s)-[^\s]*l[^\s]*(?:\s|$)|\s--listen(?:\s|$))"
            r"[^\n]{0,240}(?:\s-e\s|\s--exec(?:=|\s))[^\n]{0,80}\bsh\b",
            value,
        )
        or re.search(r"\bsocat\b[^\n]{0,300}\btcp-listen:[^\s]+[^\n]{0,300}\bexec:[^\n]{0,80}\bsh\b", value)
    )
    broad_wipe = bool(
        re.search(r"\brm\b[^\n;&|]{0,160}(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)[^\n;&|]{0,160}(?:\s|^)(?:/|~|\$home)(?:[/\\*\s]|$)", value)
        or re.search(r"\bfind\s+(?:/|~|\$home)(?:\s|/)[^\n;&|]{0,240}\s-delete(?:\s|$)", value)
        or re.search(r"\bmkfs(?:\.[a-z0-9]+)?\b[^\n;&|]{0,200}\s/dev/(?:sd|hd|vd|xvd|nvme|mmcblk)[a-z0-9]*", value)
        or re.search(r"\bdd\b[^\n;&|]{0,240}\bof=/dev/(?:sd|hd|vd|xvd|nvme|mmcblk)[a-z0-9]*", value)
    )

    if category == "reverse_shell":
        return reverse_shell, "reverse_shell_literal" if reverse_shell else "reverse_shell_witness_absent"
    if category == "bind_shell":
        return bind_shell, "bind_shell_literal" if bind_shell else "bind_shell_witness_absent"
    if category == "broad_destructive_wipe":
        return broad_wipe, "broad_wipe_literal" if broad_wipe else "broad_wipe_witness_absent"
    if category == "defense_disable_plus_attack":
        defense_disable = bool(
            re.search(r"\b(?:disable|stop|uninstall|remove)\b[^\n;&|]{0,120}\b(?:antivirus|defender|edr|falcon|firewall|security|sentinel)\b", value)
        )
        attack = reverse_shell or bind_shell or broad_wipe
        accepted = defense_disable and attack
        return accepted, "defense_disable_attack_literal" if accepted else "compound_attack_witness_absent"
    if category == "remote_payload_execute_cleanup":
        return False, "requires_exact_artifact_lineage"
    if category == "sensitive_exfiltration":
        return False, "requires_sensitive_dataflow_and_external_scope"
    return False, "unsupported_proof_category"


def finalize(corpus_path: Path, labels_path: Path, review_path: Path, output_path: Path) -> int:
    corpus_rows = load_jsonl(corpus_path)
    corpus = {str(row.get("id", "")): row for row in corpus_rows}
    if "" in corpus or len(corpus) != len(corpus_rows):
        raise ValueError("corpus has missing or duplicate IDs")

    source_labels = load_jsonl(labels_path)
    candidates = {
        str(row["id"]): row
        for row in source_labels
        if row.get("label", {}).get("verdict") == "deterministic_malicious"
    }
    review = json.loads(review_path.read_text(encoding="utf-8"))
    if review.get("schema_version") != "1" or review.get("protocol") != MANUAL_PROMPT_VERSION:
        raise ValueError("unsupported explicit proof review format")
    if review.get("candidate_labels_sha256") != sha256_file(labels_path):
        raise ValueError("review is not bound to the supplied candidate-label file")
    if review.get("default_decision") != "contextual_or_dual_use":
        raise ValueError("proof review must default rejected candidates to contextual")
    if review.get("reviewed_candidate_count") != len(candidates):
        raise ValueError("reviewed candidate count does not match candidate-label file")

    accepted_rows = review.get("accepted", [])
    if not isinstance(accepted_rows, list):
        raise ValueError("accepted must be a list")
    accepted: dict[str, str] = {}
    for item in accepted_rows:
        case_id = str(item.get("id", ""))
        category = str(item.get("category", ""))
        if case_id in accepted or case_id not in candidates:
            raise ValueError(f"accepted case is duplicate or not a candidate: {case_id!r}")
        if category not in PROOF_BLOCK_CATEGORIES:
            raise ValueError(f"accepted case has invalid proof category: {case_id!r}")
        accepted[case_id] = category

    unresolved_rows = review.get("unresolved", [])
    if not isinstance(unresolved_rows, list):
        raise ValueError("unresolved must be a list")
    unresolved: dict[str, str] = {}
    for item in unresolved_rows:
        case_id = str(item.get("id", ""))
        reason = str(item.get("reason_code", "unresolved_proof_review"))
        if case_id in unresolved or case_id in candidates or case_id not in corpus:
            raise ValueError(f"unresolved case is duplicate, reviewed, or unknown: {case_id!r}")
        unresolved[case_id] = reason

    output: list[dict[str, Any]] = []
    for case_id in sorted(candidates):
        command = extract_command(corpus[case_id])
        if command is None:
            raise ValueError(f"candidate {case_id!r} has no command")
        if case_id in accepted:
            label = {
                "verdict": "deterministic_malicious",
                "disposition": "block",
                "confidence": "high",
                "category": accepted[case_id],
                "reason_code": "literal_proof_present",
            }
        else:
            label = {
                "verdict": "contextual_or_dual_use",
                "disposition": "detect_only",
                "confidence": "high",
                "category": "no_deterministic_proof",
                "reason_code": "explicit_proof_rejected",
            }
        output.append(annotation(case_id, command, label, False))

    for case_id, reason_code in sorted(unresolved.items()):
        command = extract_command(corpus[case_id])
        if command is None:
            raise ValueError(f"unresolved case {case_id!r} has no command")
        output.append(
            annotation(
                case_id,
                command,
                {
                    "verdict": "invalid",
                    "disposition": "allow",
                    "confidence": "low",
                    "category": "unresolved",
                    "reason_code": reason_code,
                },
                True,
            )
        )

    output.sort(key=lambda row: row["id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in output:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest = {
        "schema_version": "1",
        "prompt_version": MANUAL_PROMPT_VERSION,
        "model_id": MANUAL_MODEL_ID,
        "source_corpus_sha256": sha256_file(corpus_path),
        "candidate_labels_sha256": sha256_file(labels_path),
        "review_sha256": sha256_file(review_path),
        "labels_sha256": sha256_file(output_path),
        "label_count": len(output),
        "accepted_count": len(accepted),
        "rejected_count": len(candidates) - len(accepted),
        "review_required_count": len(unresolved),
        "errors": [],
    }
    output_path.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"finalized {len(candidates)} reviewed candidates: accepted={len(accepted)}, "
        f"rejected={len(candidates) - len(accepted)}, unresolved={len(unresolved)}"
    )
    return 0


def finalize_model_proof(
    corpus_path: Path,
    labels_path: Path,
    proof_labels_path: Path,
    output_path: Path,
) -> int:
    corpus_rows = load_jsonl(corpus_path)
    corpus = {str(row.get("id", "")): row for row in corpus_rows}
    if "" in corpus or len(corpus) != len(corpus_rows):
        raise ValueError("corpus has missing or duplicate IDs")

    source_labels = load_jsonl(labels_path)
    candidates = {
        str(row["id"]): row
        for row in source_labels
        if row.get("label", {}).get("verdict") == "deterministic_malicious"
    }
    proof_manifest_path = proof_labels_path.with_suffix(".manifest.json")
    prepare_manifest_path = proof_labels_path.parent / "prepare-manifest.json"
    if not proof_manifest_path.is_file() or not prepare_manifest_path.is_file():
        raise ValueError("proof bundle is missing labels or prepare manifest")
    proof_manifest = json.loads(proof_manifest_path.read_text(encoding="utf-8"))
    prepare_manifest = json.loads(prepare_manifest_path.read_text(encoding="utf-8"))
    if proof_manifest.get("labels_sha256") != sha256_file(proof_labels_path):
        raise ValueError("proof labels digest does not match its manifest")
    if proof_manifest.get("model_id") != MODEL_ID or proof_manifest.get("prompt_version") != PROMPT_VERSION_120B_PROOF:
        raise ValueError("proof labels are not from the required GPT-OSS 120B proof profile")
    if prepare_manifest.get("selection_labels_sha256") != sha256_file(labels_path):
        raise ValueError("proof selection is not bound to the supplied base labels")
    if prepare_manifest.get("selection_case_count") != len(candidates):
        raise ValueError("proof selection candidate count differs from base labels")

    proof_rows = load_jsonl(proof_labels_path)
    proof = {str(row.get("id", "")): row for row in proof_rows}
    if "" in proof or len(proof) != len(proof_rows):
        raise ValueError("proof labels have missing or duplicate IDs")
    missing = sorted(set(candidates) - set(proof))
    if missing:
        raise ValueError(f"proof labels are missing {len(missing)} selected candidates")

    output: list[dict[str, Any]] = []
    model_accepted_count = 0
    witness_rejected_count = 0
    for case_id in sorted(candidates):
        command = extract_command(corpus.get(case_id, {}))
        if command is None:
            raise ValueError(f"candidate {case_id!r} has no command")
        row = proof[case_id]
        if row.get("input_sha256") != hashlib.sha256(command.encode()).hexdigest():
            raise ValueError(f"proof input digest differs for candidate {case_id!r}")
        label = row.get("label")
        if not isinstance(label, dict):
            raise ValueError(f"proof label is malformed for candidate {case_id!r}")
        canonical = normalize_label({"id": case_id, **label}, case_id, PROMPT_VERSION_120B_PROOF)
        if canonical["verdict"] == "deterministic_malicious":
            model_accepted_count += 1
            witnessed, witness_code = literal_machine_witness(command, canonical["category"])
            if not witnessed:
                witness_rejected_count += 1
                canonical = normalize_label(
                    {
                        "id": case_id,
                        "verdict": "contextual_or_dual_use",
                        "disposition": "detect_only",
                        "confidence": "high",
                        "category": "machine_witness_rejected",
                        "reason_code": witness_code,
                    },
                    case_id,
                    PROMPT_VERSION_120B_PROOF,
                )
        output.append(
            {
                "schema_version": "1",
                "id": case_id,
                "prompt_version": PROMPT_VERSION_120B_PROOF,
                "input_sha256": row["input_sha256"],
                "model_id": MODEL_ID,
                "label": canonical,
                "review_required": bool(row.get("review_required")),
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in output:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest = {
        "schema_version": "1",
        "prompt_version": PROMPT_VERSION_120B_PROOF,
        "model_id": MODEL_ID,
        "source_corpus_sha256": sha256_file(corpus_path),
        "candidate_labels_sha256": sha256_file(labels_path),
        "proof_labels_sha256": sha256_file(proof_labels_path),
        "labels_sha256": sha256_file(output_path),
        "label_count": len(output),
        "accepted_count": sum(row["label"]["verdict"] == "deterministic_malicious" for row in output),
        "rejected_count": sum(row["label"]["verdict"] != "deterministic_malicious" for row in output),
        "model_accepted_count": model_accepted_count,
        "machine_witness_rejected_count": witness_rejected_count,
        "machine_witness_version": "literal-command-proof-v1",
        "review_required_count": sum(bool(row["review_required"]) for row in output),
        "errors": [],
    }
    output_path.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"finalized {len(output)} GPT-OSS 120B proof candidates: "
        f"accepted={manifest['accepted_count']}, rejected={manifest['rejected_count']}, "
        f"review_required={manifest['review_required_count']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--review", type=Path)
    source.add_argument("--proof-labels", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.proof_labels is not None:
        return finalize_model_proof(args.corpus, args.labels, args.proof_labels, args.output)
    return finalize(args.corpus, args.labels, args.review, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
