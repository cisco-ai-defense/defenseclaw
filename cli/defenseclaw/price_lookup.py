# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The price-table lookup of observability.pricing, as the gateway does it.

The gateway prices a call with internal/modelusage/cost.go (PriceTable.lookup,
modelKeys, Compute). The CLI asks the same question (does this routing alias
have a price, so do its calls count toward budgets?) and must get the same
answer: before rel-1-0-10 GAP-1108 it compared the model string as written, so
doctor warned that bedrock/us.anthropic.claude-haiku-4-5-... had no price while
the gateway priced its calls with bedrock/claude-haiku-4-5*.

Both sides are checked against one set of cases,
internal/modelusage/testdata/price_lookup_cases.json.
"""

from __future__ import annotations

from typing import Any

# Bedrock cross-region inference-profile prefixes, then model vendor prefixes,
# in the order the gateway tries them (internal/modelusage/cost.go modelKeys).
_REGION_PREFIXES = ("us-gov.", "global.", "apac.", "us.", "eu.", "jp.", "au.", "ca.")
_VENDOR_PREFIXES = ("anthropic.", "openai.", "google.", "meta.", "mistral.", "amazon.", "cohere.")

FALLBACK_ENTRY = "fallback"


def _text(value: Any) -> str:
    # A missing value is "", as an unset Go string; anything else as written.
    return "" if value is None else str(value)


def model_keys(model: str) -> list[str]:
    """The lower-cased forms of a model id to try: as sent, with a Bedrock
    inference-profile ARN reduced to its id and the region prefix removed, and
    without the vendor prefix."""
    m = _text(model).strip().lower()
    if not m:
        return []
    if m.startswith("arn:") and "/" in m:
        m = m[m.rfind("/") + 1 :]
    keys = [m]
    for prefix in _REGION_PREFIXES:
        if m.startswith(prefix):
            m = m[len(prefix) :]
            keys.append(m)
            break
    for prefix in _VENDOR_PREFIXES:
        if m.startswith(prefix):
            keys.append(m[len(prefix) :])
            break
    return keys


def _has_rates(rates: Any) -> bool:
    # An entry without both rates prices nothing (the gateway skips it).
    if not isinstance(rates, dict):
        return False
    return rates.get("input_per_mtok") is not None and rates.get("output_per_mtok") is not None


def _entries(pricing: dict[str, Any]) -> list[tuple[str, str, bool, str]]:
    """(provider, model, prefix, key): exact entries first, then prefixes by
    descending length, then by key, like NewPriceTable."""
    models = pricing.get("models")
    out = []
    for entry in models if isinstance(models, list) else []:
        if not _has_rates(entry):
            continue
        provider = _text(entry.get("provider")).strip().lower()
        model = _text(entry.get("model")).strip().lower()
        prefix = model.endswith("*")
        out.append((provider, model[:-1] if prefix else model, prefix, f"{provider}/{model}"))
    out.sort(key=lambda e: (e[2], -len(e[1]), e[3]))
    return out


def price_entry(pricing: Any, provider: str, model: str) -> str | None:
    """The price-table key that prices provider/model (``fallback`` when only
    the unknown_model fallback does), or None when its calls have no cost."""
    if not isinstance(pricing, dict):
        return None
    provider = _text(provider).strip().lower()
    entries = _entries(pricing)
    for cand in model_keys(model):
        for wild in (False, True):
            for e_provider, e_model, prefix, key in entries:
                if wild != (e_provider == "*") or (not wild and e_provider != provider):
                    continue
                if (prefix and cand.startswith(e_model)) or (not prefix and cand == e_model):
                    return key
    if pricing.get("unknown_model") == "fallback" and _has_rates(pricing.get("fallback")):
        return FALLBACK_ENTRY
    return None
