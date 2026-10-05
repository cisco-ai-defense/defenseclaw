#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Fail CI when ``bundles/llm/model_catalog.json`` lists model ids that
LiteLLM's bundled registry no longer recognises or has marked deprecated.

The catalog is a hand-curated convenience layer for the ``defenseclaw
setup llm`` picker: it carries provider/auth/region metadata that LiteLLM
does not model, so it cannot be auto-generated. This check keeps the one
field that *does* go stale — the suggested ``models`` list — honest, by
cross-referencing each id against ``litellm.model_cost``.

Validation rules:

* Cloud/regional providers: every suggested model id must resolve to a
  ``litellm.model_cost`` entry, and that entry must not carry a
  ``deprecation_date`` on or before today.
* Local providers (``kind == "local"``: ollama/vllm/lm_studio): skipped.
  LiteLLM does not track self-hosted model tags, so requiring registry
  presence there would be all false positives.
* Providers with no LiteLLM mapping are skipped (not failed) so adding a
  new provider to the catalog never hard-breaks this gate before the
  mapping is taught here.

Two modes, so the per-PR gate cannot go red on a date or an upstream edit:

* Default (``make check-llm-catalog``, the required PR gate): hermetic.
  The registry is the snapshot bundled inside the installed ``litellm``
  wheel (``model_prices_and_context_window_backup.json``, pinned through
  ``uv.lock``), and deprecations are judged as of ``GATE_AS_OF``. The
  result changes only when the catalog, the LiteLLM pin or
  ``GATE_AS_OF`` changes. It needs no network and does not import
  ``litellm``.
* ``--live`` (``make check-llm-catalog-live``, the scheduled
  ``LLM Catalog Radar`` workflow): ``litellm.model_cost`` as loaded at
  import, which by default is LiteLLM's upstream registry, judged as of
  today. It reports drift as it happens; refresh the catalog (and bump
  ``GATE_AS_OF``) when it fails.

Runtime dispatch is handled by the Bifrost SDK, not LiteLLM — this check
validates ids, it does not drive routing.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "bundles" / "llm" / "model_catalog.json"

# Catalog provider name -> LiteLLM provider key (litellm.models_by_provider).
PROVIDER_LL_MAP: dict[str, str] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "bedrock": "bedrock",
    "vertex_ai": "vertex_ai",
    "azure": "azure",
    "gemini": "gemini",
    "groq": "groq",
    "mistral": "mistral",
    "deepseek": "deepseek",
    "openrouter": "openrouter",
}

# Bedrock catalog ids carry a regional inference-profile prefix that the
# pricing key may or may not include; strip it before falling back.
BEDROCK_REGION_PREFIXES = ("us.", "eu.", "apac.", "global.", "au.", "jp.", "us-gov.")

# kind values treated as self-hosted; their model lists are not validated.
LOCAL_KINDS = {"local"}

# Date the hermetic PR gate judges deprecations against. Never date.today():
# a wall-clock date turns every deprecation date in the registry into a
# failure on unrelated PRs the day it passes. Bump it when refreshing the
# catalog after the live radar reports drift.
GATE_AS_OF = date(2026, 10, 1)

BUNDLED_REGISTRY = "model_prices_and_context_window_backup.json"


def load_bundled_registry() -> dict | None:
    """Return the registry snapshot bundled in the installed ``litellm``.

    Reads the JSON file directly, without importing ``litellm`` (its import
    fetches the upstream registry over the network by default). Returns
    ``None`` when ``litellm`` is not installed or ships no snapshot.
    """
    spec = importlib.util.find_spec("litellm")
    if spec is None or not spec.submodule_search_locations:
        return None
    path = Path(next(iter(spec.submodule_search_locations))) / BUNDLED_REGISTRY
    if not path.is_file():
        return None
    registry = json.loads(path.read_text(encoding="utf-8"))
    # LiteLLM exposes each entry's ``aliases`` as extra top-level keys.
    for entry in list(registry.values()):
        if isinstance(entry, dict) and isinstance(entry.get("aliases"), list):
            for alias in entry["aliases"]:
                registry.setdefault(str(alias), entry)
    return registry


def resolve(model_cost: dict, provider_ll: str, model: str) -> str | None:
    """Return the ``model_cost`` key a catalog id maps to, or ``None``.

    Tries the provider-prefixed form first (so an OpenRouter
    ``deepseek/deepseek-v3.2`` resolves to the OpenRouter entry, not the
    native DeepSeek one), then the bare id, then Bedrock region-stripped
    variants.
    """
    candidates = [f"{provider_ll}/{model}", model]
    if provider_ll == "bedrock":
        base = model
        for prefix in BEDROCK_REGION_PREFIXES:
            if model.startswith(prefix):
                base = model[len(prefix):]
                break
        candidates += [base, f"bedrock/{base}", f"bedrock/{model}"]
    for cand in candidates:
        entry = model_cost.get(cand)
        if isinstance(entry, dict):
            return cand
    return None


def check_catalog(
    catalog: dict,
    model_cost: dict,
    today: date,
) -> list[tuple[str, str, str]]:
    """Return ``(provider, model, reason)`` tuples for every stale id.

    An empty list means the catalog is clean.
    """
    problems: list[tuple[str, str, str]] = []
    for provider in catalog.get("providers", []):
        name = str(provider.get("name", ""))
        if str(provider.get("kind", "")) in LOCAL_KINDS:
            continue
        provider_ll = PROVIDER_LL_MAP.get(name)
        if provider_ll is None:
            continue
        for model in provider.get("models", []) or []:
            key = resolve(model_cost, provider_ll, str(model))
            if key is None:
                problems.append((name, str(model), "not found in litellm registry"))
                continue
            dep = model_cost[key].get("deprecation_date")
            if not dep:
                continue
            try:
                if date.fromisoformat(str(dep)) <= today:
                    problems.append((name, str(model), f"deprecated {dep}"))
            except ValueError:
                # Unparseable date: treat as a soft signal, not a failure.
                continue
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--live",
        action="store_true",
        help="check against LiteLLM's live registry and today's date (scheduled radar)",
    )
    args = parser.parse_args(argv)

    if args.live:
        try:
            import litellm  # noqa: PLC0415
        except ImportError:
            litellm = None
        model_cost = getattr(litellm, "model_cost", None)
        today = date.today()
        source = f"live litellm registry as of {today.isoformat()}"
        try:
            from litellm.litellm_core_utils.get_model_cost_map import (  # noqa: PLC0415
                get_model_cost_map_source_info,
            )

            info = get_model_cost_map_source_info()
        except (ImportError, AttributeError):
            # Without source info the radar cannot tell the upstream registry
            # from the bundled snapshot, so it fails rather than pass unchecked.
            print(
                "check_llm_catalog: error: cannot confirm litellm used the upstream registry "
                "(get_model_cost_map_source_info is unavailable)",
                file=sys.stderr,
            )
            return 2
        if info.get("source") == "local":
            # The upstream fetch failed or was disabled.
            reason = info.get("fallback_reason") or "LITELLM_LOCAL_MODEL_COST_MAP is set"
            source = f"bundled litellm registry as of {today.isoformat()}; upstream not used: {reason}"
            # The radar exists to check upstream drift, so it fails rather
            # than pass against the bundled snapshot.
            print(f"check_llm_catalog: error: {source}", file=sys.stderr)
            return 2
    else:
        model_cost = load_bundled_registry()
        today = GATE_AS_OF
        source = f"bundled litellm registry as of {today.isoformat()}"
    if not model_cost:
        print(
            "check_llm_catalog: litellm registry unavailable — install the cli extra "
            "(litellm is the registry this check reads).",
            file=sys.stderr,
        )
        return 2

    if not CATALOG.exists():
        print(f"check_llm_catalog: {CATALOG} not found", file=sys.stderr)
        return 2

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    problems = check_catalog(catalog, model_cost, today)

    if problems:
        print(
            f"check_llm_catalog: stale model ids in bundles/llm/model_catalog.json ({source})",
            file=sys.stderr,
        )
        for provider, model, reason in problems:
            print(f"  [{provider}] {model} — {reason}", file=sys.stderr)
        print(
            "\nRefresh the suggested ids (LiteLLM lists current ones via "
            "litellm.models_by_provider[<provider>]).",
            file=sys.stderr,
        )
        return 1

    print(f"check_llm_catalog: all catalog model ids are current ({source}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
