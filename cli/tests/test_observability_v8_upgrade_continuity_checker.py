# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "scripts" / "check_observability_v8_upgrade_continuity.py"
SPEC = importlib.util.spec_from_file_location("upgrade_continuity_checker", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def _series(values: dict[str, float]) -> list[dict[str, object]]:
    return [
        {
            "metric": {"connector": "codex", "gen_ai_agent_type": role},
            "value": [1_700_000_000, str(value)],
        }
        for role, value in values.items()
    ]


def _series_pairs(values: list[tuple[str, float]]) -> list[dict[str, object]]:
    return [
        {
            "metric": {"connector": "codex", "gen_ai_agent_type": role},
            "value": [1_700_000_000, str(value)],
        }
        for role, value in values
    ]


def test_metric_continuity_uses_bounded_roles_and_straddles_cutover(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def vector(query: str, *, timeout_seconds: float) -> list[dict[str, object]]:
        queries.append(query)
        assert timeout_seconds == 60
        values = {"root": 99.0, "direct": 98.0, "nested": 97.0}
        if query.startswith("max_over_time"):
            values = {"root": 101.0, "direct": 102.0, "nested": 103.0}
        return _series(values)

    monkeypatch.setattr(checker.dashboards, "_prometheus_vector", vector)
    checker._assert_metrics(100.0, 2)

    assert len(queries) == 2
    assert all("gen_ai_agent_id" not in query for query in queries)
    assert all('gen_ai_agent_type=~"root|direct|nested"' in query for query in queries)
    assert queries[0].startswith("min_over_time(")
    assert queries[1].startswith("max_over_time(")
    assert all(query.endswith("[2h])") for query in queries)


@pytest.mark.parametrize(
    ("minimum", "maximum", "message"),
    [
        (
            {"root": 99.0, "direct": 98.0},
            {"root": 101.0, "direct": 102.0},
            "lost lifecycle role series",
        ),
        (
            {"root": 100.0, "direct": 98.0, "nested": 97.0},
            {"root": 101.0, "direct": 102.0, "nested": 103.0},
            "missing_pre=['root']",
        ),
        (
            {"root": 99.0, "direct": 98.0, "nested": 97.0},
            {"root": 100.0, "direct": 102.0, "nested": 103.0},
            "missing_post=['root']",
        ),
    ],
)
def test_metric_continuity_rejects_missing_or_one_sided_history(
    monkeypatch: pytest.MonkeyPatch,
    minimum: dict[str, float],
    maximum: dict[str, float],
    message: str,
) -> None:
    calls = iter((_series(minimum), _series(maximum)))
    monkeypatch.setattr(
        checker.dashboards,
        "_prometheus_vector",
        lambda *_args, **_kwargs: next(calls),
    )

    with pytest.raises(checker.ContinuityError, match=message.replace("[", r"\[").replace("]", r"\]")):
        checker._assert_metrics(100.0, 2)


@pytest.mark.parametrize("cutover", [0.0, -1.0, float("nan"), float("inf"), float("-inf")])
def test_metric_continuity_rejects_invalid_cutover_before_querying(
    monkeypatch: pytest.MonkeyPatch,
    cutover: float,
) -> None:
    def unexpected_query(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise AssertionError("invalid cutover reached Prometheus")

    monkeypatch.setattr(checker.dashboards, "_prometheus_vector", unexpected_query)

    with pytest.raises(checker.ContinuityError, match="finite positive epoch"):
        checker._assert_metrics(cutover, 2)


@pytest.mark.parametrize("metric_value", [0.0, -1.0, float("nan"), float("inf"), float("-inf")])
def test_metric_continuity_rejects_invalid_metric_values(
    monkeypatch: pytest.MonkeyPatch,
    metric_value: float,
) -> None:
    calls = iter(
        (
            _series({"root": metric_value, "direct": 98.0, "nested": 97.0}),
            _series({"root": 101.0, "direct": 102.0, "nested": 103.0}),
        ),
    )
    monkeypatch.setattr(
        checker.dashboards,
        "_prometheus_vector",
        lambda *_args, **_kwargs: next(calls),
    )

    with pytest.raises(checker.ContinuityError, match="non-finite or non-positive"):
        checker._assert_metrics(100.0, 2)


@pytest.mark.parametrize("reverse", [False, True])
def test_metric_continuity_aggregates_duplicate_role_series_deterministically(
    monkeypatch: pytest.MonkeyPatch,
    reverse: bool,
) -> None:
    minimum = [
        ("root", 101.0),
        ("root", 99.0),
        ("direct", 98.0),
        ("nested", 97.0),
    ]
    maximum = [
        ("root", 99.0),
        ("root", 103.0),
        ("direct", 102.0),
        ("nested", 104.0),
    ]
    if reverse:
        minimum.reverse()
        maximum.reverse()
    calls = iter((_series_pairs(minimum), _series_pairs(maximum)))
    monkeypatch.setattr(
        checker.dashboards,
        "_prometheus_vector",
        lambda *_args, **_kwargs: next(calls),
    )

    checker._assert_metrics(100.0, 2)
