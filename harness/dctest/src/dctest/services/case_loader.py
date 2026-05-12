"""Load YAML-defined test cases shipped with the package."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path

import yaml

from dctest.exceptions import CaseNotFoundError
from dctest.models import TestCase
from dctest.prompt_loader import case_path


def _walk_yaml_files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob("*.yaml")):
        if p.is_file():
            yield p


def load_all_cases() -> list[TestCase]:
    """Return every TestCase defined under ``cases/`` in stable id order."""
    root = case_path()
    cases: list[TestCase] = []
    seen_ids: set[str] = set()
    if not root.exists():
        return []
    for path in _walk_yaml_files(root):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in data.get("cases", []):
            case = TestCase.model_validate(raw)
            if case.id in seen_ids:
                raise ValueError(f"Duplicate case id {case.id!r} (also in {path})")
            seen_ids.add(case.id)
            cases.append(case)
    cases.sort(key=lambda c: c.id)
    return cases


def get_case(case_id: str) -> TestCase:
    for c in load_all_cases():
        if c.id == case_id:
            return c
    raise CaseNotFoundError(case_id)


def filter_cases(
    cases: list[TestCase],
    *,
    glob: str | None = None,
    surface: str | None = None,
    feature: str | None = None,
    tag: str | None = None,
) -> list[TestCase]:
    out = list(cases)
    if glob:
        out = [c for c in out if fnmatch.fnmatchcase(c.id, glob)]
    if surface:
        out = [c for c in out if c.surface == surface]
    if feature:
        out = [c for c in out if c.feature.startswith(feature)]
    if tag:
        out = [c for c in out if tag in c.tags]
    return out
