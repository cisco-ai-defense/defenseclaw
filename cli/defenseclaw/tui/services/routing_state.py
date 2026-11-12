# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Model routing panel state (pure: no I/O, no Textual).

The app loads ``defenseclaw routing status --json`` and
``defenseclaw routing usage --json`` in workers and hands the stdout here.
Every change is a ``defenseclaw routing ...`` command the app previews and
runs; config.yaml is never written by the TUI.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any

VIEW_ROUTING = "routing"
VIEW_USAGE = "usage"
USAGE_PERIODS = (("d", "day", "24h"), ("w", "week", "7d"), ("m", "month", "30d"))


@dataclass(frozen=True)
class RoutingCommandIntent:
    """A CLI command the app previews and runs."""

    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "routing"
    risk: str = "mutation"
    hint: str = ""
    consequence: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


@dataclass(frozen=True)
class RoutingPanelAction:
    """What a key asks the app to do: none, move, view, refresh, intent or prompt."""

    kind: str
    intent: RoutingCommandIntent | None = None
    # For kind "prompt": which text the app asks for (model or test).
    prompt: str = ""
    hint: str = ""


@dataclass(frozen=True)
class RoutingRow:
    kind: str  # model | rule | budget
    name: str
    detail: str
    marks: str = ""


def parse_model_entry(text: str) -> tuple[str, str, str] | None:
    """``ALIAS PROVIDER MODEL`` (or ``ALIAS PROVIDER/MODEL``) -> parts, else None."""
    try:
        parts = shlex.split(text)
    except ValueError:
        return None
    if len(parts) == 2 and "/" in parts[1]:
        provider, _, model = parts[1].partition("/")
        parts = [parts[0], provider, model]
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


@dataclass
class RoutingPanelModel:
    view: str = VIEW_ROUTING
    cursor: int = 0
    status: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    period: str = "week"
    error: str = ""
    loaded: bool = False

    # ------------------------------------------------------------ data in

    def apply_status_json(self, stdout: str | bytes) -> None:
        data = _json_object(stdout)
        if data is None:
            self.set_error("routing status did not answer with JSON; run defenseclaw routing status")
            return
        self.status, self.error, self.loaded = data, "", True
        self.cursor = min(self.cursor, max(0, len(self.rows()) - 1))

    def apply_usage_json(self, stdout: str | bytes) -> None:
        data = _json_object(stdout)
        self.usage = data if data is not None else {"rows": [], "error": "usage did not answer with JSON"}

    def set_error(self, message: str) -> None:
        self.error, self.loaded = message, True

    # ------------------------------------------------------------ rows

    @property
    def managed(self) -> bool:
        return bool(self.status.get("managed"))

    @property
    def enabled(self) -> bool:
        return bool(self.status.get("enabled"))

    def rows(self) -> list[RoutingRow]:
        out: list[RoutingRow] = []
        for m in self.status.get("models") or []:
            if not isinstance(m, dict):
                continue
            marks = " ".join(x for x in ("default" if m.get("default") else "", "locked" if m.get("locked") else "") if x)
            out.append(RoutingRow("model", str(m.get("alias", "")), f"{m.get('provider', '')}/{m.get('model', '')}", marks))
        effective = self.status.get("effective") or {}
        for r in self.status.get("rule_list") or effective.get("rules") or []:
            if isinstance(r, dict):
                out.append(RoutingRow("rule", str(r.get("id", "")), _rule_text(r)))
        for b in effective.get("budgets") or self.status.get("budget_list") or []:
            if isinstance(b, dict):
                out.append(RoutingRow("budget", str(b.get("id", "")), _budget_text(b), "used up" if b.get("exceeded") else ""))
        return out

    def usage_rows(self) -> list[dict[str, Any]]:
        rows = self.usage.get("rows") if isinstance(self.usage, dict) else None
        return [r for r in rows or [] if isinstance(r, dict)]

    def data_table_columns(self, compact: bool) -> tuple[str, ...]:
        if self.view == VIEW_USAGE:
            return ("Model", "Calls", "Cost") if compact else ("Model", "Calls", "Input", "Output", "Cost")
        return ("Kind", "Name", "Details") if compact else ("Kind", "Name", "Details", "Marks")

    def data_table_rows(self, compact: bool) -> list[tuple[str, ...]]:
        if self.view == VIEW_USAGE:
            rows = []
            for r in self.usage_rows():
                cost = r.get("cost_usd")
                cost_text = f"{cost:.4f}" if isinstance(cost, (int, float)) else "unknown"
                key, calls = str(r.get("key", "-")), str(r.get("calls", 0))
                rows.append((key, calls, cost_text) if compact else
                            (key, calls, str(r.get("input_tokens", 0)), str(r.get("output_tokens", 0)), cost_text))
            return rows
        if compact:
            return [(r.kind, r.name, (r.detail + (f" ({r.marks})" if r.marks else ""))[:48]) for r in self.rows()]
        return [(r.kind, r.name, r.detail, r.marks) for r in self.rows()]

    def total_count(self) -> int:
        return len(self.status.get("models") or [])

    def summary_line(self) -> str:
        """The one line above the table."""
        if self.error:
            return self.error
        if not self.loaded:
            return "Loading routing status..."
        if self.view == VIEW_USAGE:
            scope = "everyone" if (self.usage or {}).get("scope") == "all" else "yours"
            return f"Usage for the last {self.period} ({scope})."
        state = "on" if self.enabled else "off"
        health = str((self.status.get("health") or {}).get("state") or "unknown")
        text = f"Routing {state} · classifier {self.status.get('classifier', '?')} · {health}"
        if self.managed:
            text += " · set by your administrator"
        return text

    def warnings(self) -> list[str]:
        return [str(w) for w in self.status.get("warnings") or []]

    def empty_state(self) -> str:
        if self.view == VIEW_USAGE:
            return "No recorded model calls yet. Usage needs observability.tokenomics turned on."
        if self.managed:
            return "Routing is set by your administrator; nothing is shared with you yet."
        return "No models yet. Press a to add one, or run defenseclaw routing setup."

    def selected(self) -> RoutingRow | None:
        rows = self.rows()
        return rows[self.cursor] if 0 <= self.cursor < len(rows) else None

    # ------------------------------------------------------------ keys

    def keys(self) -> tuple[tuple[str, str], ...]:
        """The keys of the current view (hint bar, ? help and handle_key agree)."""
        if self.view == VIEW_USAGE:
            return (("d", "day"), ("w", "week"), ("m", "month"), ("u", "back"), ("r", "refresh"))
        keys: list[tuple[str, str]] = [("t", "test a prompt"), ("u", "usage"), ("p", "prices")]
        if not self.managed:
            keys = [("a", "add model"), ("d", "delete"), ("e", "on/off"), *keys]
        return (*keys, ("r", "refresh"))

    def handle_key(self, key: str) -> RoutingPanelAction:
        allowed = {k for k, _ in self.keys()} | {"up", "down", "k", "j"}
        if key not in allowed:
            return RoutingPanelAction("none")
        if key in ("up", "k", "down", "j"):
            count = len(self.usage_rows()) if self.view == VIEW_USAGE else len(self.rows())
            step = -1 if key in ("up", "k") else 1
            self.cursor = max(0, min(self.cursor + step, max(0, count - 1)))
            return RoutingPanelAction("move")
        if key == "r":
            return RoutingPanelAction("refresh")
        if key == "u":
            self.view, self.cursor = (VIEW_ROUTING if self.view == VIEW_USAGE else VIEW_USAGE), 0
            return RoutingPanelAction("view")
        if self.view == VIEW_USAGE:
            for letter, period, _since in USAGE_PERIODS:
                if key == letter:
                    self.period = period
                    return RoutingPanelAction("refresh")
            return RoutingPanelAction("none")
        if key == "t":
            return RoutingPanelAction("prompt", prompt="test")
        if key == "a":
            return RoutingPanelAction("prompt", prompt="model")
        if key == "p":
            return RoutingPanelAction("intent", RoutingCommandIntent(
                "routing pricing show", ("routing", "pricing", "show"), risk="read-only", hint="Show the model price table."))
        if key == "e":
            verb = "disable" if self.enabled else "enable"
            return RoutingPanelAction("intent", RoutingCommandIntent(
                f"routing {verb}", ("routing", verb), hint=f"Turn model routing {'off' if self.enabled else 'on'}."))
        if key == "d":
            return self._delete_action()
        return RoutingPanelAction("none")

    def _delete_action(self) -> RoutingPanelAction:
        row = self.selected()
        if row is None:
            return RoutingPanelAction("none", hint="Pick a model, rule or budget first.")
        group = {"model": "models", "rule": "rules", "budget": "budgets"}[row.kind]
        return RoutingPanelAction("intent", RoutingCommandIntent(
            f"routing {group} remove {row.name}", ("routing", group, "remove", "--", row.name), risk="destructive",
            hint=f"Remove the {row.kind} {row.name} from config.yaml.",
            consequence=f"Removes the {row.kind} {row.name} from config.yaml; the gateway stops using it at the next reload."))

    # ------------------------------------------------------------ prompts

    def intent_for_prompt(self, prompt: str, text: str) -> RoutingCommandIntent | None:
        text = text.strip()
        if not text:
            return None
        if prompt == "test":
            return RoutingCommandIntent(f"routing test {text[:40]}", ("routing", "test", "--", text), risk="read-only",
                                        hint="Dry run: no model is called.")
        if prompt == "model":
            parts = parse_model_entry(text)
            if parts is None:
                return None
            alias, provider, model = parts
            return RoutingCommandIntent(f"routing models add {alias}",
                                        ("routing", "models", "add", "--provider", provider, "--model", model, "--", alias),
                                        hint=f"Add the model alias {alias} ({provider}/{model}).")
        return None

    def usage_since(self) -> str:
        return next(since for _k, period, since in USAGE_PERIODS if period == self.period)


def routing_keys_hint(model: RoutingPanelModel) -> str:
    return " · ".join(f"{k} {label}" for k, label in model.keys())


def overview_tile(status: dict[str, Any]) -> str:
    """The overview line: on/off, models, and a used-up budget if any."""
    if not status:
        return "Routing: unknown"
    if not status.get("enabled"):
        return "Routing: off"
    text = f"Routing: on · {len(status.get('models') or [])} model(s)"
    budgets = (status.get("effective") or {}).get("budgets") or []
    used = [b for b in budgets if isinstance(b, dict) and b.get("exceeded")]
    if used:
        text += f" · budget {used[0].get('id')} used up"
    return text


def _json_object(stdout: str | bytes) -> dict[str, Any] | None:
    try:
        data = json.loads(stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else stdout)
    except (ValueError, AttributeError):
        return None
    return data if isinstance(data, dict) else None


def _rule_text(rule: dict[str, Any]) -> str:
    match = rule.get("match") or {}
    parts = [f"{k}={','.join(map(str, v)) if isinstance(v, list) else v}" for k, v in match.items()]
    if rule.get("action") == "deny":
        action = "deny"
    else:
        action = " ".join(x for x in (f"allow {','.join(rule.get('allow') or [])}" if rule.get("allow") else "",
                                      f"default {rule['default']}" if rule.get("default") else "") if x)
    return f"{' '.join(parts) or '-'} -> {action}"


def _budget_text(budget: dict[str, Any]) -> str:
    spent = budget.get("spent_usd")
    used = f"{spent:.2f}" if isinstance(spent, (int, float)) else (
        f"{budget['percent_used']:.0f}%" if isinstance(budget.get("percent_used"), (int, float)) else "?")
    return f"{used}/{budget.get('limit_usd')} USD per {budget.get('period')} -> {budget.get('on_exceed')}"


def routing_keys_hint_for(panel_view: str) -> str:
    """Hint bar line for a panel view name (routing, usage, with -managed)."""
    view, _, managed = panel_view.partition("-")
    model = RoutingPanelModel(view=view if view in (VIEW_ROUTING, VIEW_USAGE) else VIEW_ROUTING,
                              status={"managed": managed == "managed"})
    return routing_keys_hint(model)


def routing_help_rows(managed: bool) -> list[tuple[str, str]]:
    """The ? sheet rows: every key handle_key takes, in both views."""
    rows = [(k, label) for k, label in RoutingPanelModel(status={"managed": managed}).keys()]
    rows += [(f"{k} (usage)", label) for k, label in RoutingPanelModel(view=VIEW_USAGE, status={"managed": managed}).keys()]
    return [("j/k", "move"), *rows, ("M", "open this panel")]
