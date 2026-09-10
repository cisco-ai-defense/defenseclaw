#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned public benchmark sources into DefenseClaw case JSONL.

This adapter is intentionally data-only: it reads source files, emits inert
records, and never imports or executes code from a downloaded repository.
Hostile payloads remain in the ignored benchmark data directory. Publication
artifacts contain case IDs and aggregate results, not these normalized rows.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

SCHEMA_VERSION = "1"
SUPPORTED = (
    "atomic-red-team",
    "gretel-pii-en-v1",
    "nemotron-pii",
    "nl2bash",
    "nl2bash-pii-negative",
    "shell-attack-evolution",
    "tldr",
)
ATOMIC_COMMAND = re.compile(r"^(?P<indent>\s*)command:\s*(?P<value>.*)$")
TLDR_COMMAND = re.compile(r"^\s*`(?P<command>.+)`\s*$")
PLACEHOLDER = re.compile(r"\{\{[^{}]+\}\}")
SHELL_PLACEHOLDER = re.compile(r"#\{[^{}]+\}")
URL_VALUE = re.compile(r"\b(?:https?|ftp)://[^\s|;&]+", re.IGNORECASE)
IPV4_VALUE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
UUID_VALUE = re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.IGNORECASE)
LONG_HEX_VALUE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
NUMBER_VALUE = re.compile(r"\b\d+\b")
QUOTED_VALUE = re.compile(r"""(?s)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')""")
POWERSHELL_COMMAND = re.compile(
    r"(?im)(?:^|[\s;&|])(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b|"
    r"\$[A-Za-z_][A-Za-z0-9_]*\s*=|\b(?:New|Get|Set|Remove|Invoke|Start|Stop)-[A-Za-z]+\b|"
    r"\[(?:System|Security|Microsoft)\.[A-Za-z.]++\]"
)
CMD_COMMAND = re.compile(
    r"(?im)(?:^|[\s;&|])(?:cmd(?:\.exe)?\s+/c|reg(?:\.exe)?\s+(?:add|delete|query)|"
    r"wmic\b|schtasks\b|netsh\b|rundll32(?:\.exe)?\b|certutil(?:\.exe)?\b|"
    r"bitsadmin(?:\.exe)?\b|sc(?:\.exe)?\s+(?:create|delete|config|start|stop)|"
    r"takeown(?:\.exe)?\b|icacls(?:\.exe)?\b)"
)
ADAPTER_STATISTICS: dict[str, dict[str, int]] = {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="benchmarks/datasets.lock.json")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--datasets", required=True, help="comma-separated prepared dataset IDs")
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", help="normalization manifest; defaults next to --output")
    parser.add_argument("--split", choices=("development", "validation", "test"), default="test")
    parser.add_argument("--max-cases-per-dataset", type=int, default=0)
    return parser.parse_args()


def read_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_lock(path: Path) -> dict[str, dict[str, object]]:
    raw = read_json(path)
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported dataset lock schema")
    out: dict[str, dict[str, object]] = {}
    datasets = raw.get("datasets")
    if not isinstance(datasets, list):
        raise ValueError("dataset lock requires datasets")
    for item in datasets:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("dataset lock contains an invalid entry")
        dataset_id = str(item["id"])
        if dataset_id in out:
            raise ValueError(f"duplicate dataset ID {dataset_id!r}")
        out[dataset_id] = item
    return out


def verify_source(root: Path, locked: dict[str, object]) -> None:
    metadata_path = root / ".defenseclaw-source.json"
    metadata = read_json(metadata_path)
    if not isinstance(metadata, dict):
        raise ValueError(f"invalid source metadata: {metadata_path}")
    for field in ("id", "source_url", "revision", "license", "license_status"):
        if metadata.get(field) != locked.get(field):
            raise ValueError(f"{locked['id']}: prepared source {field} does not match lock")
    if metadata.get("include_paths", []) != locked.get("include_paths", []):
        raise ValueError(f"{locked['id']}: prepared source include_paths does not match lock")


def stable_id(dataset: str, original_id: str, content: str) -> str:
    digest = hashlib.sha256((dataset + "\x00" + original_id + "\x00" + content).encode("utf-8")).hexdigest()[:24]
    return f"{dataset}/{digest}"


def split_group_id(dataset: str, material: str) -> str:
    return hashlib.sha256((dataset + "\x00" + material).encode("utf-8")).hexdigest()[:24]


def command_family(command: str) -> str:
    """Return a deterministic value-scrubbed command-family fingerprint input."""
    family = command.casefold()
    family = SHELL_PLACEHOLDER.sub("<placeholder>", family)
    family = PLACEHOLDER.sub("<placeholder>", family)
    family = family.replace("bench_value", "<placeholder>")
    family = URL_VALUE.sub("<url>", family)
    family = IPV4_VALUE.sub("<ip>", family)
    family = UUID_VALUE.sub("<uuid>", family)
    family = LONG_HEX_VALUE.sub("<hex>", family)
    family = QUOTED_VALUE.sub("<quoted>", family)
    family = NUMBER_VALUE.sub("<number>", family)
    return " ".join(family.split())


def infer_command_context(command: str, platform_hint: str = "") -> tuple[str, str]:
    """Infer only high-confidence Windows dialect markers; default to POSIX."""
    platform = platform_hint.casefold()
    if POWERSHELL_COMMAND.search(command):
        return "windows", "powershell"
    if CMD_COMMAND.search(command):
        return "windows", "cmd"
    if platform in {"windows", "win32"}:
        return "windows", "cmd"
    return platform_hint or "linux", "posix"


def make_case(
    locked: dict[str, object],
    original_id: str,
    command: str,
    split: str,
    source_truth: str,
    disposition: str,
    categories: list[str],
    *,
    platform: str = "linux",
    dialect: str = "",
    hard_negative: bool = False,
    label_priority: int = 50,
    split_group: str = "",
) -> dict[str, object]:
    dataset_id = str(locked["id"])
    group_material = split_group or original_id
    inferred_platform, inferred_dialect = infer_command_context(command, platform)
    if dialect:
        inferred_dialect = dialect
    cwd = r"C:\repo" if inferred_platform == "windows" else "/repo"
    active_home = r"C:\Users\alice" if inferred_platform == "windows" else "/home/alice"
    return {
        "_label_priority": label_priority,
        "schema_version": SCHEMA_VERSION,
        "id": stable_id(dataset_id, original_id, command),
        "source": {
            "dataset": dataset_id,
            "revision": str(locked["revision"]),
            "original_id": original_id,
            "license": str(locked["license"]),
            "redistribution": str(locked["redistribution"]),
        },
        "split": split,
        "surface": "action",
        "payload": {
            "tool_name": "shell",
            "command": command,
            "dialect": inferred_dialect,
            "cwd": cwd,
            "active_home": active_home,
        },
        "truth": {
            "source_truth": source_truth,
            "applicability": "in_scope",
            "expected_disposition": disposition,
            "categories": categories,
        },
        "strata": {
            "platform": inferred_platform,
            "dialect": inferred_dialect,
            "hard_negative": hard_negative,
            "split_group": split_group_id(dataset_id, group_material),
        },
    }


def make_text_case(
    locked: dict[str, object],
    original_id: str,
    content: str,
    split: str,
    source_truth: str,
    disposition: str,
    categories: list[str],
    *,
    spans: list[dict[str, object]] | None = None,
    domain: str = "",
    document_type: str = "",
    hard_negative: bool = False,
    split_group: str = "",
    direction: str = "completion",
) -> dict[str, object]:
    dataset_id = str(locked["id"])
    group_material = split_group or original_id
    truth: dict[str, object] = {
        "source_truth": source_truth,
        "applicability": "in_scope",
        "expected_disposition": disposition,
        "categories": categories,
    }
    if spans:
        truth["spans"] = spans
    strata: dict[str, object] = {
        "hard_negative": hard_negative,
        "split_group": split_group_id(dataset_id, group_material),
    }
    if domain:
        strata["domain"] = domain
    if document_type:
        strata["document_type"] = document_type
    return {
        "schema_version": SCHEMA_VERSION,
        "id": stable_id(dataset_id, original_id, content),
        "source": {
            "dataset": dataset_id,
            "revision": str(locked["revision"]),
            "original_id": original_id,
            "license": str(locked["license"]),
            "redistribution": str(locked["redistribution"]),
        },
        "split": split,
        "surface": "text",
        "payload": {"direction": direction, "content": content},
        "truth": truth,
        "strata": strata,
    }


def byte_offset(text: str, character_offset: int) -> int:
    if character_offset < 0 or character_offset > len(text):
        raise ValueError("annotation character offset is outside the source text")
    return len(text[:character_offset].encode("utf-8"))


def parquet_rows(path: Path, columns: list[str]) -> Iterator[dict[str, object]]:
    try:
        import pyarrow.parquet as parquet  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ValueError(
            "PII adapters require pyarrow==25.0.1; run with "
            "`uv run --isolated --no-project --with pyarrow==25.0.1 python "
            "benchmarks/scripts/benchmark_normalize.py ...`"
        ) from exc
    source = parquet.ParquetFile(path)
    missing = sorted(set(columns) - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"{path}: missing parquet columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=256, columns=columns):
        values = batch.to_pydict()
        for row in range(batch.num_rows):
            yield {column: values[column][row] for column in columns}


def normalize_command(command: str) -> str:
    return command.replace("\x00", "").strip()


def adapt_nl2bash(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    commands = root / "data" / "bash" / "all.cm"
    descriptions = root / "data" / "bash" / "all.nl"
    with (
        commands.open("r", encoding="utf-8") as command_file,
        descriptions.open("r", encoding="utf-8") as description_file,
    ):
        command_lines = command_file.readlines()
        description_lines = description_file.readlines()
    if len(command_lines) != len(description_lines):
        raise ValueError("nl2bash: command and description row counts differ")
    for index, (command, description) in enumerate(zip(command_lines, description_lines, strict=True), start=1):
        command = normalize_command(command)
        if not command:
            continue
        # NL2Bash is a corpus of commands used in practice, not an attack
        # corpus. Treating every row as allow is deliberately conservative:
        # any finding or block is visible in the benign FPR denominator.
        yield make_case(
            locked,
            f"data/bash/all.cm:{index}",
            command,
            split,
            "benign",
            "allow",
            ["benign-command", "nl2bash"],
            hard_negative=True,
            split_group=command_family(command),
        )


def adapt_nl2bash_pii_negative(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    commands = root / "data" / "bash" / "all.cm"
    descriptions = root / "data" / "bash" / "all.nl"
    with (
        commands.open("r", encoding="utf-8") as command_file,
        descriptions.open("r", encoding="utf-8") as description_file,
    ):
        command_lines = command_file.readlines()
        description_lines = description_file.readlines()
    if len(command_lines) != len(description_lines):
        raise ValueError("nl2bash-pii-negative: command and description row counts differ")
    for index, (command, description) in enumerate(zip(command_lines, description_lines, strict=True), start=1):
        command = normalize_command(command)
        description = description.replace("\x00", "").strip()
        if not command or not description:
            continue
        yield make_text_case(
            locked,
            f"data/bash/all.nl:{index}",
            description,
            split,
            "benign",
            "allow",
            ["pii", "pii-negative", "pii-hard-negative", "natural-language-instruction", "nl2bash"],
            hard_negative=True,
            split_group=command_family(command),
            direction="prompt",
        )


def adapt_tldr(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    page_roots = sorted(path for path in root.iterdir() if path.is_dir() and path.name.startswith("pages"))
    if not page_roots:
        raise ValueError("tldr: no pages directories found")
    for page_root in page_roots:
        for path in sorted(page_root.rglob("*.md")):
            relative = path.relative_to(root).as_posix()
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    match = TLDR_COMMAND.match(line.rstrip("\n"))
                    if not match:
                        continue
                    command = normalize_command(PLACEHOLDER.sub("BENCH_VALUE", match.group("command")))
                    if not command:
                        continue
                    page_relative = path.relative_to(page_root)
                    platform = page_relative.parts[0] if len(page_relative.parts) > 1 else "common"
                    yield make_case(
                        locked,
                        f"{relative}:{line_number}",
                        command,
                        split,
                        "benign",
                        "allow",
                        ["benign-command", "documentation-example", "tldr"],
                        platform=platform,
                        hard_negative=True,
                        split_group=relative,
                    )


def atomic_commands(path: Path) -> Iterator[tuple[int, str]]:
    """Extract command scalar values without loading or executing YAML tags."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    index = 0
    while index < len(lines):
        match = ATOMIC_COMMAND.match(lines[index])
        if not match:
            index += 1
            continue
        value = match.group("value").strip()
        start_line = index + 1
        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            base_indent = len(match.group("indent"))
            block: list[str] = []
            index += 1
            while index < len(lines):
                line = lines[index]
                stripped = line.lstrip(" ")
                indent = len(line) - len(stripped)
                if stripped and indent <= base_indent:
                    break
                if stripped:
                    block.append(stripped if value.startswith(">") else line[base_indent + 2 :])
                else:
                    block.append("")
                index += 1
            separator = " " if value.startswith(">") else "\n"
            command = separator.join(block)
        else:
            # Reject complex YAML nodes, aliases, and tagged values. They are
            # recorded as exclusions in the manifest instead of guessed.
            if not value or value[0] in "[{&*!":
                index += 1
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            command = value
            index += 1
        command = normalize_command(command)
        if command:
            yield start_line, command


def adapt_atomic(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    atomics = root / "atomics"
    if not atomics.is_dir():
        raise ValueError("atomic-red-team: atomics directory is missing")
    for path in sorted(atomics.glob("T*/T*.yaml")):
        relative = path.relative_to(root).as_posix()
        technique = path.stem
        for line_number, command in atomic_commands(path):
            yield make_case(
                locked,
                f"{relative}:{line_number}",
                command,
                split,
                "malicious",
                "detect_only",
                ["attack-emulation", "atomic-red-team", technique],
                split_group=technique,
            )


def jsonl_rows(path: Path) -> Iterator[tuple[int, dict[str, object]]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            yield line_number, value


def adapt_shell_attack(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    # Prefer the independently annotated replay subset. The source's Vi harm
    # index is mapped conservatively: only 3-4 is block truth; 0-2 remains a
    # malicious detection-positive but blocking-negative example.
    curated = root / "request_response" / "curated.jsonl"
    for line_number, row in jsonl_rows(curated):
        command = normalize_command(str(row.get("command", "")))
        if not command:
            continue
        severity = row.get("severity_vi")
        disposition = "block" if isinstance(severity, int) and severity >= 3 else "detect_only"
        period = str(row.get("period", "unknown"))
        original_id = f"request_response/curated.jsonl:{line_number}"
        session_id = row.get("session_id")
        turn_index = row.get("turn_index")
        if isinstance(session_id, str) and isinstance(turn_index, int):
            original_id = f"curated:{session_id}:{turn_index}"
        group_material = (
            f"session:{session_id}" if isinstance(session_id, str) and session_id else command_family(command)
        )
        yield make_case(
            locked,
            original_id,
            command,
            split,
            "malicious",
            disposition,
            ["honeypot-attack", "shell-attack", f"harm-vi-{severity}", f"period-{period}"],
            label_priority=100,
            split_group=group_material,
        )

    for path in sorted((root / "commands").glob("*.jsonl")):
        relative = path.relative_to(root).as_posix()
        for line_number, row in jsonl_rows(path):
            command = normalize_command(str(row.get("command", "")))
            if not command:
                continue
            period = str(row.get("period", path.stem))
            command_pattern = row.get("command_pattern")
            group_material = (
                f"pattern:{command_pattern}"
                if isinstance(command_pattern, str) and command_pattern.strip()
                else command_family(command)
            )
            yield make_case(
                locked,
                f"{relative}:{line_number}",
                command,
                split,
                "malicious",
                "detect_only",
                ["honeypot-attack", "shell-attack", f"period-{period}"],
                label_priority=10,
                split_group=group_material,
            )


def entity_label(raw: object) -> str:
    if isinstance(raw, (list, tuple)):
        values = sorted({str(item).strip() for item in raw if str(item).strip()})
    else:
        value = str(raw).strip()
        values = [value] if value else []
    label = "/".join(values) or "pii"
    if len(label) > 120:
        raise ValueError("PII annotation label exceeds the benchmark schema bound")
    return label


def gretel_entity_spans(text: str, raw_entities: object) -> list[dict[str, object]]:
    if not isinstance(raw_entities, str):
        raise ValueError("gretel-pii-en-v1: entities must be a Python-literal string")
    try:
        entities = ast.literal_eval(raw_entities)
    except (SyntaxError, ValueError) as exc:
        raise ValueError("gretel-pii-en-v1: invalid entities literal") from exc
    if not isinstance(entities, list):
        raise ValueError("gretel-pii-en-v1: entities must decode to a list")
    spans: set[tuple[int, int, str]] = set()
    for annotation in entities:
        if not isinstance(annotation, dict) or not isinstance(annotation.get("entity"), str):
            raise ValueError("gretel-pii-en-v1: invalid entity annotation")
        entity = annotation["entity"]
        if not entity:
            raise ValueError("gretel-pii-en-v1: empty entity annotation")
        label = entity_label(annotation.get("types", []))
        start = text.find(entity)
        if start < 0:
            raise ValueError("gretel-pii-en-v1: annotated entity is absent from text")
        while start >= 0:
            end = start + len(entity)
            spans.add((byte_offset(text, start), byte_offset(text, end), label))
            start = text.find(entity, start + 1)
    return [{"start": start, "end": end, "label": label} for start, end, label in sorted(spans)]


def adapt_gretel_pii(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    path = root / "data" / "test-00000-of-00001.parquet"
    columns = ["uid", "domain", "document_type", "document_description", "entities", "text"]
    for row_number, row in enumerate(parquet_rows(path, columns), start=1):
        text = row["text"]
        if not isinstance(text, str) or not text:
            raise ValueError(f"gretel-pii-en-v1: row {row_number} has no text")
        uid = str(row["uid"] or f"row-{row_number}")
        domain = str(row["domain"] or "")
        document_type = str(row["document_type"] or "")
        spans = gretel_entity_spans(text, row["entities"])
        if not spans:
            raise ValueError(f"gretel-pii-en-v1: row {row_number} has no entity annotations")
        labels = sorted({str(span["label"]) for span in spans})
        yield make_text_case(
            locked,
            f"{uid}:text",
            text,
            split,
            "sensitive",
            "detect_only",
            ["pii", "pii-positive", "gretel-pii", *[f"pii-type:{label}" for label in labels]],
            spans=spans,
            domain=domain,
            document_type=document_type,
            split_group=uid,
        )

        # The source defines this field as a structural overview rather than
        # document content. Keep it as a source-provided PII-context hard
        # negative only when it contains none of that row's labeled values.
        description = row["document_description"]
        if isinstance(description, str) and description.strip():
            description = description.strip()
            entities = ast.literal_eval(str(row["entities"]))
            entity_overlap = any(
                isinstance(item, dict) and isinstance(item.get("entity"), str) and item["entity"] in description
                for item in entities
            )
            if not entity_overlap:
                yield make_text_case(
                    locked,
                    f"{uid}:document-description",
                    description,
                    split,
                    "benign",
                    "allow",
                    ["pii", "pii-context-negative", "gretel-pii"],
                    domain=domain,
                    document_type=document_type,
                    hard_negative=True,
                    split_group=uid,
                )


def nemotron_annotations(raw_spans: object) -> list[dict[str, object]]:
    if raw_spans is None:
        return []
    if isinstance(raw_spans, str):
        try:
            raw_spans = ast.literal_eval(raw_spans)
        except (SyntaxError, ValueError) as exc:
            raise ValueError("nemotron-pii: invalid spans literal") from exc
    if not isinstance(raw_spans, list):
        raise ValueError("nemotron-pii: spans must be a list")
    if any(not isinstance(annotation, dict) for annotation in raw_spans):
        raise ValueError("nemotron-pii: invalid span annotation")
    return raw_spans


def nemotron_spans(text: str, raw_spans: object) -> tuple[list[dict[str, object]], int]:
    annotations = nemotron_annotations(raw_spans)
    spans: set[tuple[int, int, str]] = set()
    rejected = 0
    for annotation in annotations:
        start = annotation.get("start")
        end = annotation.get("end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start or end > len(text):
            rejected += 1
            continue
        annotated_text = annotation.get("text")
        if annotated_text is None or text[start:end] != str(annotated_text):
            rejected += 1
            continue
        label = entity_label(annotation.get("label", "pii"))
        spans.add((byte_offset(text, start), byte_offset(text, end), label))
    return (
        [{"start": start, "end": end, "label": label} for start, end, label in sorted(spans)],
        rejected,
    )


def adapt_nemotron_pii(root: Path, locked: dict[str, object], split: str) -> Iterator[dict[str, object]]:
    path = root / "data" / "test-00000-of-00001.parquet"
    columns = ["uid", "domain", "document_type", "document_description", "text", "spans"]
    for row_number, row in enumerate(parquet_rows(path, columns), start=1):
        text = row["text"]
        if not isinstance(text, str) or not text:
            raise ValueError(f"nemotron-pii: row {row_number} has no text")
        uid = str(row["uid"] or f"row-{row_number}")
        spans, rejected = nemotron_spans(text, row["spans"])
        if rejected:
            statistics = ADAPTER_STATISTICS.setdefault("nemotron-pii", {})
            statistics["rows_excluded_annotation_mismatch"] = statistics.get("rows_excluded_annotation_mismatch", 0) + 1
            statistics["annotations_excluded"] = statistics.get("annotations_excluded", 0) + rejected
            continue
        sensitive = bool(spans)
        labels = sorted({str(span["label"]) for span in spans})
        yield make_text_case(
            locked,
            f"{uid}:text",
            text,
            split,
            "sensitive" if sensitive else "benign",
            "detect_only" if sensitive else "allow",
            [
                "pii",
                "pii-positive" if sensitive else "pii-negative",
                "nemotron-pii",
                *[f"pii-type:{label}" for label in labels],
            ],
            spans=spans,
            domain=str(row["domain"] or ""),
            document_type=str(row["document_type"] or ""),
            hard_negative=not sensitive,
            split_group=uid,
        )

        description = row["document_description"]
        if isinstance(description, str) and description.strip():
            description = description.strip()
            description_folded = description.casefold()
            value_overlap = any(
                isinstance(annotation.get("text"), str)
                and bool(annotation["text"])
                and str(annotation["text"]).casefold() in description_folded
                for annotation in nemotron_annotations(row["spans"])
            )
            if not value_overlap:
                statistics = ADAPTER_STATISTICS.setdefault("nemotron-pii", {})
                statistics["description_negatives_included"] = (
                    statistics.get("description_negatives_included", 0) + 1
                )
                yield make_text_case(
                    locked,
                    f"{uid}:document-description:{row_number}",
                    description,
                    split,
                    "benign",
                    "allow",
                    ["pii", "pii-context-negative", "nemotron-pii"],
                    domain=str(row["domain"] or ""),
                    document_type=str(row["document_type"] or ""),
                    hard_negative=True,
                    split_group=uid,
                    direction="prompt",
                )
            else:
                statistics = ADAPTER_STATISTICS.setdefault("nemotron-pii", {})
                statistics["descriptions_excluded_value_overlap"] = (
                    statistics.get("descriptions_excluded_value_overlap", 0) + 1
                )


ADAPTERS = {
    "atomic-red-team": adapt_atomic,
    "gretel-pii-en-v1": adapt_gretel_pii,
    "nemotron-pii": adapt_nemotron_pii,
    "nl2bash": adapt_nl2bash,
    "nl2bash-pii-negative": adapt_nl2bash_pii_negative,
    "shell-attack-evolution": adapt_shell_attack,
    "tldr": adapt_tldr,
}


def write_outputs(
    output: Path,
    manifest_path: Path,
    selected: list[str],
    rows: Iterable[dict[str, object]],
    counts: dict[str, int],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    digest = hashlib.sha256()
    all_rows = sorted(rows, key=lambda row: str(row["id"]))
    seen_ids: set[str] = set()
    by_payload: dict[str, list[dict[str, object]]] = {}
    for row in all_rows:
        case_id = str(row["id"])
        if case_id in seen_ids:
            raise ValueError(f"duplicate normalized case ID {case_id}")
        seen_ids.add(case_id)
        surface = str(row["surface"])
        payload = row["payload"]
        if not isinstance(payload, dict):
            raise ValueError(f"{case_id}: payload is not an object")
        if surface == "action":
            identity = {"surface": surface, "command": payload.get("command", "")}
        elif surface == "text":
            identity = {
                "surface": surface,
                "direction": payload.get("direction", ""),
                "content": payload.get("content", ""),
            }
        else:
            identity = {"surface": surface, "payload": payload}
        payload_key = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        by_payload.setdefault(payload_key, []).append(row)

    normalized: list[dict[str, object]] = []
    duplicates = 0
    conflicts = 0
    for payload_key in sorted(by_payload):
        group = by_payload[payload_key]
        duplicates += len(group) - 1
        by_dataset: dict[str, list[dict[str, object]]] = {}
        for row in group:
            dataset_id = str(row["source"]["dataset"])  # type: ignore[index]
            by_dataset.setdefault(dataset_id, []).append(row)
        representatives: list[dict[str, object]] = []
        has_internal_conflict = False
        for dataset_id in sorted(by_dataset):
            source_rows = by_dataset[dataset_id]
            highest_priority = max(int(row.get("_label_priority", 50)) for row in source_rows)
            preferred = [row for row in source_rows if int(row.get("_label_priority", 50)) == highest_priority]
            preferred_labels = {
                (
                    str(row["truth"]["source_truth"]),  # type: ignore[index]
                    str(row["truth"]["expected_disposition"]),  # type: ignore[index]
                )
                for row in preferred
            }
            if len(preferred_labels) > 1:
                has_internal_conflict = True
            representatives.append(preferred[0])
        labels = {
            (
                str(row["truth"]["source_truth"]),  # type: ignore[index]
                str(row["truth"]["expected_disposition"]),  # type: ignore[index]
            )
            for row in representatives
        }
        canonical = representatives[0]
        if has_internal_conflict or len(labels) > 1:
            conflicts += 1
            truth = canonical["truth"]
            assert isinstance(truth, dict)
            truth["source_truth"] = "unknown"
            truth["applicability"] = "out_of_scope"
            truth["expected_disposition"] = "detect_only"
            truth["exclusion_reason"] = "exact payload has conflicting public-source labels"
            categories = truth.get("categories", [])
            if not isinstance(categories, list):
                categories = []
            truth["categories"] = sorted({str(item) for item in categories} | {"cross-source-label-conflict"})
        canonical.pop("_label_priority", None)
        normalized.append(canonical)

    normalized.sort(key=lambda row: str(row["id"]))
    with temporary.open("x", encoding="utf-8", newline="\n") as handle:
        for row in normalized:
            encoded = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
            handle.write(encoded.decode())
            digest.update(encoded)
            dataset_id = str(row["source"]["dataset"])  # type: ignore[index]
            counts[dataset_id] = counts.get(dataset_id, 0) + 1
    temporary.replace(output)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": sorted(selected),
        "cases": len(normalized),
        "counts": dict(sorted(counts.items())),
        "exact_payload_duplicates_removed": duplicates,
        "label_conflicts_excluded": conflicts,
        "adapter_statistics": {
            dataset: dict(sorted(statistics.items())) for dataset, statistics in sorted(ADAPTER_STATISTICS.items())
        },
        "output_sha256": digest.hexdigest(),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    ADAPTER_STATISTICS.clear()
    if args.max_cases_per_dataset < 0:
        raise ValueError("--max-cases-per-dataset must be non-negative")
    selected = [item.strip() for item in args.datasets.split(",") if item.strip()]
    if not selected:
        raise ValueError("--datasets must select at least one dataset")
    if len(selected) != len(set(selected)):
        raise ValueError("--datasets contains a duplicate ID")
    selected.sort()
    unsupported = sorted(set(selected) - set(SUPPORTED))
    if unsupported:
        raise ValueError(f"no normalizer for: {', '.join(unsupported)}")

    locked = load_lock(Path(args.lock))
    data_root = Path(args.data_dir).expanduser().resolve()
    streams: list[Iterable[dict[str, object]]] = []
    for dataset_id in selected:
        if dataset_id not in locked:
            raise ValueError(f"dataset {dataset_id!r} is absent from the lock")
        entry = locked[dataset_id]
        if entry.get("enabled") is not True or entry.get("license_status") != "approved":
            raise ValueError(f"{dataset_id}: dataset is not enabled and license-approved")
        source = (data_root / "sources" / dataset_id).resolve()
        if data_root != source and data_root not in source.parents:
            raise ValueError(f"{dataset_id}: source path escapes the data directory")
        verify_source(source, entry)
        stream = ADAPTERS[dataset_id](source, entry, args.split)
        if args.max_cases_per_dataset:
            limit = args.max_cases_per_dataset

            def bounded(rows: Iterable[dict[str, object]], maximum: int = limit) -> Iterator[dict[str, object]]:
                for index, row in enumerate(rows):
                    if index >= maximum:
                        break
                    yield row

            stream = bounded(stream)
        streams.append(stream)

    def combined() -> Iterator[dict[str, object]]:
        for stream in streams:
            yield from stream

    output = Path(args.output)
    manifest = Path(args.manifest) if args.manifest else output.with_suffix(".manifest.json")
    counts: dict[str, int] = {}
    write_outputs(output, manifest, selected, combined(), counts)
    print(f"normalized {sum(counts.values())} cases from {len(selected)} datasets -> {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"benchmark-normalize: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
