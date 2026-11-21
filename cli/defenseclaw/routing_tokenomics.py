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
COST_FIX = (
    "set observability.tokenomics.cost.compute to true and leave observability.tokenomics.roles "
    "empty or include agent"
)


@dataclass(frozen=True)
class TokenomicsNote:
    """What is missing, as fields; text is what the CLI prints."""

    # panels: tokenomics is off, so the dashboard panels stay blank.
    # budgets: budgets are set and cannot count spend (the gateway records no
    # computed cost of agent calls: config.BudgetFeedReady is false).
    panels: bool
    budgets: bool
    detail: str
    # remedy is the fix: the enable command, or the cost/roles keys when
    # tokenomics is on but agent call cost is not computed.
    remedy: str = ENABLE_COMMAND

    @property
    def text(self) -> str:
        if self.remedy == ENABLE_COMMAND:
            return f"{self.detail}. Turn it on: {ENABLE_COMMAND}"
        return f"{self.detail}: {self.remedy}"


def budget_feed_ready(*, tokenomics_on: bool, cost_compute: bool, roles: Any) -> bool:
    """config.BudgetFeedReady: budgets count only agent calls recorded with a
    computed cost (tokenomics on, cost.compute on, roles empty or with agent).
    The local usage store is not needed: budget spend has its own ledger."""
    roles = [str(r) for r in roles] if isinstance(roles, (list, tuple)) else []
    return tokenomics_on and cost_compute and (not roles or "agent" in roles)


def _build(*, routing_on: bool, budgets_set: bool, tokenomics_on: bool, feed_ready: bool) -> TokenomicsNote | None:
    panels = routing_on and not tokenomics_on
    budgets = budgets_set and not feed_ready
    if not (panels or budgets):
        return None
    if panels:
        text = (
            "Tokenomics (per-call usage and cost) is off, so the Savings, Spend per user and "
            "Budget spend panels of the routing dashboard stay blank"
        )
        if budgets_set:
            text += " and budgets cannot count spend"
        return TokenomicsNote(panels=True, budgets=budgets, detail=text)
    if not tokenomics_on:
        detail = "Tokenomics (per-call usage and cost) is off, so budgets cannot count spend"
        return TokenomicsNote(panels=False, budgets=True, detail=detail)
    return TokenomicsNote(
        panels=False,
        budgets=True,
        detail="Budgets are set but the cost of agent calls is not computed, so budgets cannot count spend",
        remedy=COST_FIX,
    )


def _compute(value: Any) -> bool:
    # cost.compute defaults to true (config.TokenomicsConfig.ComputesCost).
    return value if isinstance(value, bool) else True


def note_from_doc(doc: dict[str, Any], *, routing_on: bool = False, budgets_set: bool = False) -> TokenomicsNote | None:
    """The note for a raw config document, or None. routing_on and budgets_set say
    the caller just turned that on, before the document shows it."""
    routing = doc.get("routing") if isinstance(doc.get("routing"), dict) else {}
    admin = routing.get("admin") if isinstance(routing.get("admin"), dict) else {}
    obs = doc.get("observability") if isinstance(doc.get("observability"), dict) else {}
    tok = obs.get("tokenomics") if isinstance(obs.get("tokenomics"), dict) else {}
    cost = tok.get("cost") if isinstance(tok.get("cost"), dict) else {}
    tokenomics_on = bool(tok.get("enabled"))
    return _build(
        routing_on=routing_on or bool(routing.get("enabled")),
        budgets_set=budgets_set or bool(admin.get("budgets")),
        tokenomics_on=tokenomics_on,
        feed_ready=budget_feed_ready(
            tokenomics_on=tokenomics_on, cost_compute=_compute(cost.get("compute")), roles=tok.get("roles")
        ),
    )


def note_from_cfg(cfg: Any) -> TokenomicsNote | None:
    """The note for a loaded Config, or None."""
    routing = getattr(cfg, "routing", None)
    if routing is None:
        return None
    admin = getattr(routing, "admin", None)
    budgets = admin.get("budgets") if isinstance(admin, dict) else getattr(admin, "budgets", None)
    tok = getattr(getattr(cfg, "observability", None), "tokenomics", None)
    tokenomics_on = bool(getattr(tok, "enabled", False))
    return _build(
        routing_on=bool(getattr(routing, "enabled", False)),
        budgets_set=bool(budgets),
        tokenomics_on=tokenomics_on,
        feed_ready=budget_feed_ready(
            tokenomics_on=tokenomics_on,
            cost_compute=bool(getattr(tok, "cost_compute", True)),
            roles=getattr(tok, "roles", None),
        ),
    )
