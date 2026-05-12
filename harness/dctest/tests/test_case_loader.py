"""Case loader sanity: every shipped YAML parses and ids are unique."""

from __future__ import annotations

from dctest.services.case_loader import filter_cases, load_all_cases


def test_load_all_cases_non_empty():
    cases = load_all_cases()
    assert cases, "expected at least one shipped case"


def test_case_ids_unique():
    cases = load_all_cases()
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"


def test_filter_by_surface_and_glob():
    cases = load_all_cases()
    cli_cases = filter_cases(cases, surface="python-cli")
    assert cli_cases
    glob_cases = filter_cases(cases, glob="cli-py.skill.*")
    assert all(c.id.startswith("cli-py.skill.") for c in glob_cases)


def test_every_case_has_expected_or_must_not():
    cases = load_all_cases()
    for c in cases:
        # A case must declare an exit-code expectation OR an output expectation.
        assert (
            c.expected_exit_code is not None
            or c.expected_substrings
            or c.must_not_contain
        ), f"case {c.id} has no expectations declared"
