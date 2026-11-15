# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The note shown when routing runs with tokenomics off (rel-1-0-10 GAP-0932).

Tokenomics (per-call usage and cost) is off by default, and that stays: it is
a product choice, not a routing side effect. The Savings, Spend per user and
Budget spend panels of the routing dashboard, and budgets themselves, need it,
so every place that turns routing or a budget on says so and gives the command.
"""

from __future__ import annotations

from typing import Any

ENABLE_COMMAND = "defenseclaw setup tokenomics --enable"


def _note(*, budgets: bool) -> str:
    what = "the Savings, Spend per user and Budget spend panels of the routing dashboard stay blank" + (
        " and budgets cannot count spend" if budgets else ""
    )
    return f"Tokenomics (per-call usage and cost) is off, so {what}. Turn it on: {ENABLE_COMMAND}"


def note_from_doc(doc: dict[str, Any], *, routing_on: bool = False, budgets_set: bool = False) -> str:
    """The note for a raw config document, or "" when tokenomics is on or neither
    routing nor a budget is on. routing_on and budgets_set say the caller just
    turned that on, before the document shows it."""
    routing = doc.get("routing") if isinstance(doc.get("routing"), dict) else {}
    admin = routing.get("admin") if isinstance(routing.get("admin"), dict) else {}
    budgets = budgets_set or bool(admin.get("budgets"))
    if not (routing_on or routing.get("enabled") or budgets):
        return ""
    obs = doc.get("observability") if isinstance(doc.get("observability"), dict) else {}
    tok = obs.get("tokenomics") if isinstance(obs.get("tokenomics"), dict) else {}
    if tok.get("enabled"):
        return ""
    return _note(budgets=budgets)


def note_from_cfg(cfg: Any) -> str:
    """The note for a loaded Config, or "" when routing is off or tokenomics is on."""
    routing = getattr(cfg, "routing", None)
    if routing is None:
        return ""
    admin = getattr(routing, "admin", None)
    budgets = bool(admin.get("budgets") if isinstance(admin, dict) else getattr(admin, "budgets", None))
    if not (bool(getattr(routing, "enabled", False)) or budgets):
        return ""
    if bool(getattr(getattr(getattr(cfg, "observability", None), "tokenomics", None), "enabled", False)):
        return ""
    return _note(budgets=budgets)
