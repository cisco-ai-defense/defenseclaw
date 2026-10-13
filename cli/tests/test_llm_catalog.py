# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``scripts/check_llm_catalog.py``.

Two layers, both hermetic (no network, no wall clock):

* The PR gate: the real catalog against the LiteLLM registry snapshot
  bundled in the locked ``litellm`` wheel, as of ``GATE_AS_OF`` — the same
  assertion ``make check-llm-catalog`` enforces. Live drift against the
  upstream registry and today's date is the scheduled radar's job
  (``make check-llm-catalog-live``), never a PR's.
* Deterministic unit tests for the resolver / deprecation logic using a
  synthetic ``model_cost`` so behaviour is pinned regardless of which
  LiteLLM version happens to be installed.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_llm_catalog.py"
CATALOG = ROOT / "bundles" / "llm" / "model_catalog.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_llm_catalog", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mod = _load_module()


# ---------------------------------------------------------------------------
# PR gate: the shipped catalog must be current in the pinned registry.
# ---------------------------------------------------------------------------


def test_shipped_catalog_has_no_stale_ids() -> None:
    registry = mod.load_bundled_registry()
    if registry is None:
        pytest.skip("litellm is not installed")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    problems = mod.check_catalog(catalog, registry, mod.GATE_AS_OF)
    assert problems == [], "stale model ids in model_catalog.json: " + "; ".join(
        f"[{p}] {m} — {why}" for p, m, why in problems
    )


def test_every_non_local_provider_is_mapped() -> None:
    """Guard against a new cloud provider silently bypassing the gate.

    Local providers are intentionally unmapped (skipped); every other
    provider in the catalog must have a LiteLLM mapping so its models are
    actually validated.
    """
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    unmapped = [
        p["name"]
        for p in catalog["providers"]
        if p.get("kind") not in mod.LOCAL_KINDS and p["name"] not in mod.PROVIDER_LL_MAP
    ]
    assert unmapped == [], f"unmapped non-local providers: {unmapped}"


# ---------------------------------------------------------------------------
# Deterministic unit tests with a synthetic registry.
# ---------------------------------------------------------------------------

_TODAY = date(2026, 5, 29)

_FAKE_COST = {
    "claude-opus-4-8": {"litellm_provider": "anthropic", "mode": "chat"},
    "anthropic/claude-sonnet-4-20250514": {
        "litellm_provider": "anthropic",
        "mode": "chat",
        "deprecation_date": "2026-05-14",  # before _TODAY
    },
    "gemini/gemini-9-flash": {
        "litellm_provider": "gemini",
        "mode": "chat",
        "deprecation_date": "2099-01-01",  # future: still valid
    },
    "us.anthropic.claude-sonnet-4-6": {"litellm_provider": "bedrock", "mode": "chat"},
    "openrouter/z-ai/glm-5": {"litellm_provider": "openrouter", "mode": "chat"},
}


def test_resolve_prefers_provider_prefixed_entry() -> None:
    assert mod.resolve(_FAKE_COST, "openrouter", "z-ai/glm-5") == "openrouter/z-ai/glm-5"


def test_resolve_falls_back_to_bare_id() -> None:
    assert mod.resolve(_FAKE_COST, "anthropic", "claude-opus-4-8") == "claude-opus-4-8"


def test_resolve_strips_bedrock_region_prefix() -> None:
    # Registry only has the us. form; a differently-prefixed id still resolves
    # via the region-stripped fallback shapes.
    assert mod.resolve(_FAKE_COST, "bedrock", "us.anthropic.claude-sonnet-4-6") == (
        "us.anthropic.claude-sonnet-4-6"
    )


def test_resolve_unknown_returns_none() -> None:
    assert mod.resolve(_FAKE_COST, "openai", "gpt-does-not-exist") is None


def test_check_flags_unknown_and_deprecated_but_not_future() -> None:
    catalog = {
        "providers": [
            {
                "name": "anthropic",
                "kind": "cloud",
                "models": ["claude-opus-4-8", "claude-sonnet-4-20250514", "ghost-model"],
            },
            {"name": "gemini", "kind": "cloud", "models": ["gemini-9-flash"]},
        ]
    }
    problems = mod.check_catalog(catalog, _FAKE_COST, _TODAY)
    flagged = {(p, m): why for p, m, why in problems}
    assert ("anthropic", "ghost-model") in flagged
    assert "deprecated" in flagged[("anthropic", "claude-sonnet-4-20250514")]
    # Valid + future-deprecation models are not flagged.
    assert ("anthropic", "claude-opus-4-8") not in flagged
    assert ("gemini", "gemini-9-flash") not in flagged


def test_local_providers_are_skipped() -> None:
    catalog = {
        "providers": [
            {"name": "ollama", "kind": "local", "models": ["llama3.3", "nonsense-tag"]},
        ]
    }
    assert mod.check_catalog(catalog, _FAKE_COST, _TODAY) == []


def test_unmapped_provider_is_skipped_not_failed() -> None:
    catalog = {
        "providers": [
            {"name": "brand-new-provider", "kind": "cloud", "models": ["whatever"]},
        ]
    }
    assert mod.check_catalog(catalog, _FAKE_COST, _TODAY) == []


def test_gate_is_pinned_to_gate_as_of_not_the_wall_clock(monkeypatch, tmp_path) -> None:
    """A deprecation date passing must not fail the PR gate on unrelated PRs."""
    catalog = tmp_path / "model_catalog.json"
    catalog.write_text(
        json.dumps({"providers": [{"name": "gemini", "kind": "cloud", "models": ["gemini-9-flash"]}]}),
        encoding="utf-8",
    )

    class _AfterDeprecation(date):
        @classmethod
        def today(cls) -> date:
            return date(2100, 1, 1)  # past gemini-9-flash's 2099-01-01

    monkeypatch.setattr(mod, "CATALOG", catalog)
    monkeypatch.setattr(mod, "load_bundled_registry", lambda: _FAKE_COST)
    monkeypatch.setattr(mod, "date", _AfterDeprecation)
    assert mod.main([]) == 0


def test_live_mode_fails_when_litellm_used_its_bundled_fallback(monkeypatch, capsys) -> None:
    """The radar must not pass against the bundled snapshot when upstream failed."""
    import sys
    import types

    litellm = types.ModuleType("litellm")
    litellm.model_cost = _FAKE_COST
    core = types.ModuleType("litellm.litellm_core_utils")
    cost_map = types.ModuleType("litellm.litellm_core_utils.get_model_cost_map")
    cost_map.get_model_cost_map_source_info = lambda: {"source": "local", "fallback_reason": "fetch failed"}
    monkeypatch.setitem(sys.modules, "litellm", litellm)
    monkeypatch.setitem(sys.modules, "litellm.litellm_core_utils", core)
    monkeypatch.setitem(sys.modules, "litellm.litellm_core_utils.get_model_cost_map", cost_map)
    assert mod.main(["--live"]) == 2
    assert "upstream not used: fetch failed" in capsys.readouterr().err


def test_live_mode_fails_when_litellm_cannot_report_its_registry_source(monkeypatch, capsys) -> None:
    """Without source info the radar cannot rule out the bundled snapshot."""
    import sys
    import types

    litellm = types.ModuleType("litellm")
    litellm.model_cost = _FAKE_COST
    monkeypatch.setitem(sys.modules, "litellm", litellm)
    monkeypatch.setitem(sys.modules, "litellm.litellm_core_utils", types.ModuleType("litellm.litellm_core_utils"))
    monkeypatch.setitem(
        sys.modules,
        "litellm.litellm_core_utils.get_model_cost_map",
        types.ModuleType("litellm.litellm_core_utils.get_model_cost_map"),
    )
    assert mod.main(["--live"]) == 2
    assert "cannot confirm litellm used the upstream registry" in capsys.readouterr().err


def test_corrupt_bundled_snapshot_reports_the_registry_unavailable(monkeypatch, tmp_path, capsys) -> None:
    """A truncated snapshot exits 2 with the message, not a traceback."""
    (tmp_path / mod.BUNDLED_REGISTRY).write_text('{"gpt-4": {', encoding="utf-8")
    spec = importlib.util.spec_from_loader("litellm", loader=None, is_package=True)
    spec.submodule_search_locations = [str(tmp_path)]
    monkeypatch.setattr(mod.importlib.util, "find_spec", lambda name: spec)
    assert mod.main([]) == 2
    assert "litellm registry unavailable" in capsys.readouterr().err
