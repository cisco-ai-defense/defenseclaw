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

LiteLLM's registry is bundled data, so this check needs no network and no
credentials; its freshness is pinned to the ``litellm==`` version in
``pyproject.toml``. Runtime dispatch is handled by the Bifrost SDK, not
LiteLLM — this check validates ids, it does not drive routing.

Run via ``make check-llm-catalog``.
"""

from __future__ import annotations

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


def main() -> int:
    try:
        import litellm  # noqa: PLC0415
    except ImportError:
        print(
            "check_llm_catalog: litellm not importable — install the cli extra "
            "(litellm is the registry this check reads).",
            file=sys.stderr,
        )
        return 2

    if not CATALOG.exists():
        print(f"check_llm_catalog: {CATALOG} not found", file=sys.stderr)
        return 2

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    problems = check_catalog(catalog, litellm.model_cost, date.today())

    if problems:
        print("check_llm_catalog: stale model ids in bundles/llm/model_catalog.json", file=sys.stderr)
        for provider, model, reason in problems:
            print(f"  [{provider}] {model} — {reason}", file=sys.stderr)
        print(
            "\nRefresh the suggested ids (LiteLLM lists current ones via "
            "litellm.models_by_provider[<provider>]).",
            file=sys.stderr,
        )
        return 1

    print("check_llm_catalog: all catalog model ids are current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
