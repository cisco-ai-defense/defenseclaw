#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned MCP-Atlas reference trajectories as benign stateful cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET = "ScaleAI/MCP-Atlas"
SOURCE_URL = "https://huggingface.co/datasets/ScaleAI/MCP-Atlas"
SOURCE_REVISION = "8c563b55d7c967755f474299848049834d624617"
SOURCE_LICENSE = "CC-BY-4.0"

# Closed chain catalog evaluated by this benign completed-trajectory control.
# A match for any listed identity is a false positive for the trajectory.
CHAIN_RULE_IDS = [
    "chain.cloud_iam_principal_create_then_admin_attach_same_principal",
    "chain.download_decode_execute_same_artifact",
    "chain.download_then_execute_same_artifact",
    "chain.endpoint_security_control_request_then_completed_same_process",
    "chain.firewall_trust_expansion_then_destination_use",
    "chain.guardrails_off_then_egress",
    "chain.kubernetes_privileged_cronjob_patch_then_create_job",
    "chain.kubernetes_privileged_host_root_write_apply_exec",
    "chain.permission_denied_then_runtime_bypass",
    "chain.privilege_discovery_then_elevation",
    "chain.reverse_shell_payload_write_then_persistence_install_same_artifact",
    "chain.secret_manager_read_then_egress",
    "chain.secret_read_then_egress",
    "chain.secretsdump_then_psexec_same_target_principal",
    "chain.sensitive_egress_artifact_then_execute",
    "chain.sensitive_read_value_then_external_literal_transmit",
    "chain.sql_command_udf_create_then_invoke_same_function",
    "chain.sqlserver_xp_cmdshell_enable_then_invoke",
    "chain.wireless_capture_then_deauth_same_bssid",
    "chain.workload_identity_then_lateral_execution",
]
SOURCE_FILE = "MCP-Atlas.parquet"
SOURCE_BYTES = 15_638_757
SOURCE_SHA256 = "2d7bc052f14cbcb3b8294293481053f7111d256f9c9deaa96f3ff632d19958d0"
ADAPTER = "mcp-atlas-reference-trajectories-v1"

MAX_SOURCE_BYTES = 20 * 1024 * 1024
MAX_TRAJECTORY_BYTES = 2 * 1024 * 1024
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_EVENTS = 8
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_json(value: str) -> Any:
    return json.loads(value, object_pairs_hook=reject_duplicate_keys)


def english_prompt(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(re.search(r"[A-Za-z]", value))
        and NON_ENGLISH_SCRIPT.search(value) is None
    )


def tool_result_outcomes(messages: list[Any]) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for message in messages:
        if not isinstance(message, Mapping) or message.get("role") != "tool":
            continue
        call_id = message.get("tool_call_id")
        if not isinstance(call_id, str) or not call_id or call_id in outcomes:
            continue
        failed = message.get("is_error") is True or message.get("error") not in (None, "", False)
        outcomes[call_id] = "failed" if failed else "succeeded"
    return outcomes


def trajectory_events(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > MAX_TRAJECTORY_BYTES:
        return []
    try:
        messages = exact_json(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(messages, list):
        return []
    outcomes = tool_result_outcomes(messages)
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for message in messages:
        if not isinstance(message, Mapping) or message.get("role") != "assistant":
            continue
        calls = message.get("tool_calls")
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, Mapping) or call.get("type") != "function":
                return []
            call_id = call.get("id")
            function = call.get("function")
            if (
                not isinstance(call_id, str)
                or not call_id
                or call_id in seen_ids
                or not isinstance(function, Mapping)
            ):
                return []
            name = function.get("name")
            arguments = function.get("arguments")
            if (
                not isinstance(name, str)
                or SAFE_TOOL.fullmatch(name) is None
                or not isinstance(arguments, str)
                or len(arguments.encode("utf-8")) > MAX_ARGUMENT_BYTES
            ):
                return []
            try:
                args = exact_json(arguments)
            except (json.JSONDecodeError, ValueError):
                return []
            if not isinstance(args, dict) or call_id not in outcomes:
                return []
            seen_ids.add(call_id)
            events.append(
                {
                    "args": args,
                    "dialect": "none",
                    "offset_seconds": len(events),
                    "outcome": outcomes[call_id],
                    "tool_name": name,
                }
            )
            if len(events) > MAX_EVENTS:
                return []
    return events


def split_for(task: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(task.encode("utf-8")).digest()[:2], "big") % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def normalize_rows(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_tasks: set[str] = set()
    for row in rows:
        counts["source_rows"] += 1
        task = row.get("TASK")
        if not isinstance(task, str) or not re.fullmatch(r"[a-f0-9]{24}", task) or task in seen_tasks:
            counts["invalid_or_duplicate_task"] += 1
            continue
        if not english_prompt(row.get("PROMPT")):
            counts["non_english"] += 1
            continue
        events = trajectory_events(row.get("TRAJECTORY"))
        if not events:
            counts["invalid_or_unpaired_trajectory"] += 1
            continue
        seen_tasks.add(task)
        split = split_for(task)
        cases.append(
            {
                "id": f"mcp-atlas/{task}",
                "payload": {"direction": "tool_call", "events": events},
                "schema_version": SCHEMA_VERSION,
                "source": {
                    "dataset": DATASET,
                    "license": SOURCE_LICENSE,
                    "original_id": task,
                    "redistribution": "download-only",
                    "revision": SOURCE_REVISION,
                },
                "split": split,
                "strata": {
                    "campaign": "reference_mcp_workflow",
                    "domain": "benign_mcp",
                    "ecosystem": "mcp",
                    "hard_negative": True,
                    "language": "en",
                    "platform": "cross-platform",
                    "split_group": task,
                    "trajectory_id": task,
                    "sequence_index": 0,
                    "call_index": 0,
                },
                "surface": "stateful",
                "truth": {
                    "applicability": "in_scope",
                    "categories": ["benign", "paired_reference_trajectory", "real_mcp_arguments"],
                    "deterministic_truth": "benign",
                    "expected_disposition": "allow",
                    "label_confidence": "high",
                    "label_source": "source:mcp_atlas_reference_trajectory",
                    "rule_ids": CHAIN_RULE_IDS,
                    "source_truth": "benign",
                    "stateful_lens": "bounded_completed",
                },
            }
        )
        counts[split] += 1
        counts["events"] += len(events)
    cases.sort(key=lambda case: case["id"])
    counts["accepted"] = len(cases)
    return cases, counts


def parquet_rows(path: Path) -> Iterable[Mapping[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read MCP-Atlas Parquet") from exc
    table = parquet.read_table(path, columns=["TASK", "PROMPT", "TRAJECTORY"])
    yield from table.to_pylist()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or args.input.is_symlink():
        fail("input must be a regular non-symlink file")
    size = args.input.stat().st_size
    if size != SOURCE_BYTES or size > MAX_SOURCE_BYTES or sha256_file(args.input) != SOURCE_SHA256:
        fail("pinned MCP-Atlas source identity mismatch")
    cases, counts = normalize_rows(parquet_rows(args.input))
    body = "".join(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n" for case in cases)
    atomic_write(args.output, body)
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))},
        "cases": len(cases),
        "counts": {DATASET: len(cases)},
        "datasets": [DATASET],
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "output_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": size,
            "dataset": DATASET,
            "license": SOURCE_LICENSE,
            "path": SOURCE_FILE,
            "redistribution": "download-only",
            "revision": SOURCE_REVISION,
            "sha256": SOURCE_SHA256,
        },
    }
    atomic_write(args.manifest, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"adapter": ADAPTER, "cases": len(cases), "counts": dict(sorted(counts.items()))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
