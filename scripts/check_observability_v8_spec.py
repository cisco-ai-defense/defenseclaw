#!/usr/bin/env python3
"""Validate the tracked observability-v8 specification package."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE = ROOT / "docs" / "design" / "observability-v8"
DECISION_LOG = "08-decisions-and-exclusions.md"
TRACEABILITY = "13-decision-traceability.md"
DECISION_ROW = re.compile(r"^\| ((?:D|S|P)-\d{3}) \| (.+) \|$")
TRACE_ROW = re.compile(r"^\| ((?:D|S|P)-\d{3}) \| (.+) \| (.+) \|$")
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class SpecError(ValueError):
    """Raised when the specification package is malformed."""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecError(f"cannot read {path}: {exc}") from exc


def _non_fenced_lines(text: str) -> tuple[list[str], bool]:
    """Return CommonMark-style content lines and whether all fences close."""
    lines: list[str] = []
    fence_char = ""
    fence_length = 0
    for line in text.splitlines():
        candidate = line.lstrip(" ")
        indent = len(line) - len(candidate)
        marker_char = candidate[:1]
        marker_length = 0
        if indent <= 3 and marker_char in {"`", "~"}:
            marker_length = len(candidate) - len(candidate.lstrip(marker_char))
        if not fence_char:
            if marker_length >= 3:
                fence_char = marker_char
                fence_length = marker_length
                continue
            lines.append(line)
            continue
        if (
            marker_char == fence_char
            and marker_length >= fence_length
            and not candidate[marker_length:].strip()
        ):
            fence_char = ""
            fence_length = 0
    return lines, not fence_char


def _decision_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    duplicates: list[str] = []
    lines, _ = _non_fenced_lines(_read(path))
    for line in lines:
        match = DECISION_ROW.match(line)
        if not match:
            continue
        decision_id, text = match.groups()
        if decision_id in rows:
            duplicates.append(decision_id)
        rows[decision_id] = text.strip()
    if duplicates:
        raise SpecError(f"{path.name}: duplicate decision rows: {sorted(set(duplicates))}")
    if not rows:
        raise SpecError(f"{path.name}: no decision rows found")
    return rows


def _trace_rows(path: Path) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    duplicates: list[str] = []
    lines, _ = _non_fenced_lines(_read(path))
    for line in lines:
        match = TRACE_ROW.match(line)
        if not match:
            continue
        decision_id, contract, verification = match.groups()
        if decision_id in rows:
            duplicates.append(decision_id)
        rows[decision_id] = (contract.strip(), verification.strip())
    if duplicates:
        raise SpecError(f"{path.name}: duplicate traceability rows: {sorted(set(duplicates))}")
    if not rows:
        raise SpecError(f"{path.name}: no traceability rows found")
    return rows


def _check_contiguous(ids: set[str]) -> list[str]:
    errors: list[str] = []
    by_prefix: dict[str, list[int]] = {"D": [], "S": [], "P": []}
    for decision_id in ids:
        prefix, number = decision_id.split("-", 1)
        by_prefix[prefix].append(int(number))
    for prefix, numbers in by_prefix.items():
        if not numbers:
            errors.append(f"decision family {prefix} has no rows")
            continue
        expected = set(range(1, max(numbers) + 1))
        missing = sorted(expected - set(numbers))
        if missing:
            errors.append(f"decision family {prefix} has gaps: {missing}")
    return errors


def _check_markdown(package: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(package.glob("*.md")):
        text = _read(path)
        lines, balanced = _non_fenced_lines(text)
        if not balanced:
            errors.append(f"{path.name}: unbalanced fenced code blocks")
        for target in MARKDOWN_LINK.findall("\n".join(lines)):
            target = target.strip().split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                errors.append(f"{path.name}: missing linked path {target!r}")
    return errors


def _check_yaml(package: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(package.glob("*.yaml")):
        try:
            yaml.safe_load(_read(path))
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: invalid YAML: {exc}")
    return errors


def check_package(package: Path) -> tuple[Counter[str], list[str]]:
    if not package.is_dir():
        raise SpecError(f"package directory does not exist: {package}")
    decisions = _decision_rows(package / DECISION_LOG)
    traceability = _trace_rows(package / TRACEABILITY)
    errors = _check_contiguous(set(decisions))

    missing_trace = sorted(set(decisions) - set(traceability))
    extra_trace = sorted(set(traceability) - set(decisions))
    if missing_trace:
        errors.append(f"decisions missing traceability rows: {missing_trace}")
    if extra_trace:
        errors.append(f"traceability rows without decisions: {extra_trace}")

    for decision_id, (contract, verification) in traceability.items():
        if not contract or contract == "—":
            errors.append(f"{decision_id}: normative contract is empty")
        if not verification or verification == "—":
            errors.append(f"{decision_id}: required verification is empty")

    errors.extend(_check_markdown(package))
    errors.extend(_check_yaml(package))
    counts = Counter(decision_id[0] for decision_id in decisions)
    counts["total"] = len(decisions)
    return counts, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    args = parser.parse_args()
    try:
        counts, errors = check_package(args.package.resolve())
    except SpecError as exc:
        print(f"observability-v8 spec invalid: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"observability-v8 spec drift: {error}", file=sys.stderr)
        return 1
    print(
        "observability-v8 spec valid: "
        f"D={counts['D']} S={counts['S']} P={counts['P']} total={counts['total']}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
