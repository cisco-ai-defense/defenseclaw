# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("benchmark_normalize_ossf_malicious_packages.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_ossf_malicious_packages", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def report(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.7.4",
        "id": "MAL-2026-1234",
        "summary": "excluded narrative",
        "details": "excluded package behavior and secret-like prose",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "example-package"},
                "versions": ["1.2.3", "4.5.6"],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
                "database_specific": {"indicators": {"package_contents": "excluded"}},
            }
        ],
        "references": [{"type": "PACKAGE", "url": "https://packages.example.invalid/value"}],
        "credits": [{"name": "excluded contact", "contact": ["person@example.invalid"]}],
    }
    value.update(overrides)
    return value


def test_projection_is_value_free_and_has_no_command_authority() -> None:
    facts = MODULE.project_report(report(), "osv/malicious/npm/example-package/MAL-2026-1234.json")[0]
    assert facts == {
        "report_id": "MAL-2026-1234",
        "affected_index": 0,
        "action": "reported_malicious",
        "ecosystem": "npm",
        "package_name": "example-package",
        "explicit_version_count": 2,
        "range_count": 1,
        "range_event_count": 2,
        "has_explicit_versions": True,
        "has_ranges": True,
    }
    case = MODULE.make_case(MODULE.SOURCE_REVISION, facts)
    rendered = MODULE.canonical_json(case)
    for excluded in (
        "1.2.3",
        "4.5.6",
        "9.9.9",
        "excluded narrative",
        "package_contents",
        "person@example.invalid",
        "packages.example.invalid",
    ):
        assert excluded not in rendered
    assert case["surface"] == "plugin"
    assert case["payload"]["tool_name"] == "package.registry.report"
    assert case["truth"]["applicability"] == "out_of_scope"
    assert case["truth"]["expected_disposition"] == "detect_only"
    assert case["truth"]["deterministic_truth"] == "contextual_or_dual_use"
    assert "rule_ids" not in case["truth"]
    assert "command" not in case["payload"]


def test_withdrawn_report_cannot_become_positive() -> None:
    with pytest.raises(MODULE.ProjectionError, match="active_report_marked_withdrawn"):
        MODULE.project_report(
            report(withdrawn="2026-01-01T00:00:00Z"),
            "osv/malicious/npm/example-package/MAL-2026-1234.json",
        )


def test_git_range_uses_only_pinned_source_hierarchy_for_identity() -> None:
    value = report(
        affected=[
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://excluded.example.invalid/repository.git",
                        "events": [{"introduced": "0"}],
                    }
                ]
            }
        ]
    )
    facts = MODULE.project_report(
        value,
        "osv/malicious/git/github.com/example/repository/MAL-2026-1234.json",
    )[0]
    assert facts["ecosystem"] == "Git"
    assert facts["package_name"] == "github.com/example/repository"
    assert "excluded.example.invalid" not in MODULE.canonical_json(facts)


def test_report_id_must_match_path() -> None:
    with pytest.raises(MODULE.ProjectionError, match="report_id_path_mismatch"):
        MODULE.project_report(report(), "osv/malicious/npm/example-package/MAL-2026-9999.json")


def test_duplicate_json_keys_and_nonfinite_values_are_rejected() -> None:
    with pytest.raises(MODULE.ProjectionError, match="duplicate_json_key"):
        json.loads('{"id":"one","id":"two"}', object_pairs_hook=MODULE.strict_object)
    with pytest.raises(MODULE.ProjectionError, match="non_finite_json"):
        json.loads('{"value":NaN}', parse_constant=MODULE.reject_nonfinite)


def test_version_strings_are_validated_but_only_counts_are_projected() -> None:
    invalid = report(
        affected=[
            {
                "package": {"ecosystem": "PyPI", "name": "example"},
                "versions": [""],
            }
        ]
    )
    with pytest.raises(MODULE.ProjectionError, match="invalid_version"):
        MODULE.project_report(invalid, "osv/malicious/pypi/example/MAL-2026-1234.json")


def test_revision_and_real_source_fingerprints_are_enforced() -> None:
    with pytest.raises(ValueError, match="pinned revision"):
        MODULE.verify_source(Path("."), "main")
    source = Path(
        "/workspace/benchmark-data/sources/ossf-malicious-packages/"
        "de3a859ea74ab1a4701902937140ae4f496c6a28"
    )
    if not source.exists():
        pytest.skip("pinned OSSF source fixture is not present")
    resolved, entries = MODULE.verify_source(source, MODULE.SOURCE_REVISION)
    assert resolved == source.resolve()
    assert len(entries) > 200_000
