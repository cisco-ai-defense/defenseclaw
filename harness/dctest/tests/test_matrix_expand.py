"""Matrix expansion and selection round-trip."""

from __future__ import annotations

from dctest.services.matrix import (
    expand_matrix,
    load_connectors,
    load_providers,
    load_roles,
    load_selection,
    serialize_selection,
)


def test_required_only_filters_optional_connectors():
    cells = expand_matrix(required_only=True)
    optional_ids = {c["id"] for c in load_connectors() if c.get("tier") == "optional"}
    assert optional_ids
    assert all(c.connector not in optional_ids for c in cells)


def test_filter_provider_narrows_cells():
    cells = expand_matrix(filters=["provider=anthropic-claude-sonnet"], required_only=True)
    assert cells
    assert {c.provider.id for c in cells} == {"anthropic-claude-sonnet"}


def test_mixed_role_picks_different_judge_provider():
    cells = expand_matrix(filters=["role=guardrail+judge-mixed"], required_only=True)
    assert cells
    for c in cells:
        assert c.judge_provider is not None
        assert c.judge_provider.id != c.provider.id


def test_full_profiles_produces_3x3():
    cells_sampled = expand_matrix(required_only=True)
    cells_full = expand_matrix(required_only=True, full_profiles=True)
    assert len(cells_full) > len(cells_sampled)


def test_selection_round_trip(tmp_path):
    cells = expand_matrix(
        filters=["provider=anthropic-claude-sonnet", "connector=codex"], required_only=True
    )
    out = tmp_path / "sel.yaml"
    serialize_selection(cells, out)
    reloaded = load_selection(out)
    assert [c.id for c in reloaded] == [c.id for c in cells]


def test_load_providers_and_roles_non_empty():
    assert load_providers()
    assert load_roles()
