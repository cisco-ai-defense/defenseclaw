# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The note shown when routing runs with tokenomics off (rel-1-0-10 GAP-0932).

Tokenomics (per-call usage and cost) is off by default, and that stays: it is
a product choice, not a routing side effect. The Savings, Spend per user and
Budget spend panels of the routing dashboard, and budgets themselves, need it,
so every place that turns routing or a budget on says so and gives the command.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ENABLE_COMMAND = "defenseclaw setup tokenomics --enable"


@dataclass(frozen=True)
class TokenomicsNote:
    """What is missing, as fields; text is what the CLI prints."""

    # panels: tokenomics is off, so the dashboard panels stay blank.
    # budgets: budgets are set and cannot count spend (tokenomics, or its local
    # store, is off).
    panels: bool
    budgets: bool
    detail: str

    @property
    def text(self) -> str:
        return f"{self.detail}. Turn it on: {ENABLE_COMMAND}"


def _build(*, routing_on: bool, budgets_set: bool, tokenomics_on: bool, store_on: bool) -> TokenomicsNote | None:
    panels = routing_on and not tokenomics_on
    budgets = budgets_set and not (tokenomics_on and store_on)
    if not (panels or budgets):
        return None
    if panels:
        text = (
            "Tokenomics (per-call usage and cost) is off, so the Savings, Spend per user and "
            "Budget spend panels of the routing dashboard stay blank"
        )
        if budgets_set:
            text += " and budgets cannot count spend"
    else:
        text = "Budgets are set but the local usage store is off, so budgets cannot count spend"
    return TokenomicsNote(panels=panels, budgets=budgets, detail=text)


def note_from_doc(doc: dict[str, Any], *, routing_on: bool = False, budgets_set: bool = False) -> TokenomicsNote | None:
    """The note for a raw config document, or None. routing_on and budgets_set say
    the caller just turned that on, before the document shows it."""
    routing = doc.get("routing") if isinstance(doc.get("routing"), dict) else {}
    admin = routing.get("admin") if isinstance(routing.get("admin"), dict) else {}
    obs = doc.get("observability") if isinstance(doc.get("observability"), dict) else {}
    tok = obs.get("tokenomics") if isinstance(obs.get("tokenomics"), dict) else {}
    store = tok.get("local_store") if isinstance(tok.get("local_store"), dict) else {}
    return _build(
        routing_on=routing_on or bool(routing.get("enabled")),
        budgets_set=budgets_set or bool(admin.get("budgets")),
        tokenomics_on=bool(tok.get("enabled")),
        store_on=bool(store.get("enabled")),
    )


def note_from_cfg(cfg: Any) -> TokenomicsNote | None:
    """The note for a loaded Config, or None."""
    routing = getattr(cfg, "routing", None)
    if routing is None:
        return None
    admin = getattr(routing, "admin", None)
    budgets = admin.get("budgets") if isinstance(admin, dict) else getattr(admin, "budgets", None)
    tok = getattr(getattr(cfg, "observability", None), "tokenomics", None)
    return _build(
        routing_on=bool(getattr(routing, "enabled", False)),
        budgets_set=bool(budgets),
        tokenomics_on=bool(getattr(tok, "enabled", False)),
        store_on=bool(getattr(tok, "local_store_enabled", False)),
    )
