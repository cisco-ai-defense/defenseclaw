# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""How the Setup panel groups, names and rates its tasks and config sections.

``SetupWizard`` values are stable ids (tests, intents and saved state use
them), so the display order lives here instead: ``WIZARD_GROUPS`` lists the
task groups the nav shows, each with its tasks in table order.
``group_tasks`` / ``task_row`` map between a group's table rows and tasks.

``task_status`` rates one task from the config and the readiness checks
(the Status column), and ``task_problems`` picks the readiness checks a
task's detail should mention.

The config editor's sections get the same treatment: ``section_groups``
sorts them into a handful of groups for the nav and the ``g`` section list,
and ``field_entries`` / ``filter_field_entries`` back the ``/`` field
finder. All of this is pure so it is unit-tested without Textual.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from defenseclaw.tui.panels.setup import WIZARD_NAMES, SetupWizard
from defenseclaw.tui.services.setup_state import (
    ConfigSection,
    ReadinessCheck,
    get_config_value,
    validate_config_field,
)
from defenseclaw.tui.services.setup_state import (
    _active_connector_names as active_connector_names,
)

# (group title, ((wizard, friendly label), ...)). Every SetupWizard member
# appears exactly once; test_setup_catalog.py enforces it. Labels are read
# under their group's title, so they can stay short.
WIZARD_GROUPS: tuple[tuple[str, tuple[tuple[SetupWizard, str], ...]], ...] = (
    (
        "Get protected",
        (
            (SetupWizard.CONNECTOR_SETUP, "Protect an agent"),
            (SetupWizard.CREDENTIALS, "API keys & secrets"),
            (SetupWizard.LLM, "LLM for scanners & judge"),
        ),
    ),
    (
        "Guardrail & scanning",
        (
            (SetupWizard.GUARDRAIL, "Guardrail"),
            (SetupWizard.GUARDRAIL_ACTIONS, "On/off, fail mode, approvals"),
            (SetupWizard.SKILL_SCANNER, "Skill scanner"),
            (SetupWizard.MCP_SCANNER, "MCP scanner"),
            (SetupWizard.REDACTION, "Redaction"),
            (SetupWizard.TRUSTED_PATHS, "Trusted agent binaries"),
            (SetupWizard.REGISTRIES, "Approved catalogs"),
            (SetupWizard.ACP_GUARD, "Editor agents (ACP)"),
            (SetupWizard.SANDBOX, "Sandboxes (OpenShell)"),
        ),
    ),
    (
        "Alerts & telemetry",
        (
            (SetupWizard.NOTIFICATIONS_ROUTING, "What notifies you"),
            (SetupWizard.WEBHOOKS, "Chat & paging webhooks"),
            (SetupWizard.OBSERVABILITY, "Export telemetry"),
            (SetupWizard.SPLUNK, "Splunk"),
            (SetupWizard.SPLUNK_DASHBOARDS, "Splunk dashboards"),
            (SetupWizard.LOCAL_OBSERVABILITY, "Local observability stack"),
        ),
    ),
    (
        "Gateway & advanced",
        (
            (SetupWizard.GATEWAY, "Gateway"),
            (SetupWizard.TOKEN_ROTATION, "Rotate gateway tokens"),
            (SetupWizard.CUSTOM_PROVIDERS, "Custom LLM providers"),
            (SetupWizard.AI_DISCOVERY, "AI usage discovery"),
        ),
    ),
)

GROUP_TITLES: tuple[str, ...] = tuple(title for title, _items in WIZARD_GROUPS)
_LABELS: dict[SetupWizard, str] = {wizard: label for _title, items in WIZARD_GROUPS for wizard, label in items}
_GROUP_OF: dict[SetupWizard, str] = {wizard: title for title, items in WIZARD_GROUPS for wizard, _label in items}
_TASKS: dict[str, tuple[SetupWizard, ...]] = {
    title: tuple(wizard for wizard, _label in items) for title, items in WIZARD_GROUPS
}
_ORDER: tuple[SetupWizard, ...] = tuple(wizard for title in GROUP_TITLES for wizard in _TASKS[title])


def wizard_label(wizard: SetupWizard | int) -> str:
    """Plain name for a wizard (falls back to the historical name)."""

    wizard = SetupWizard(wizard)
    return _LABELS.get(wizard) or WIZARD_NAMES[int(wizard)]


def wizard_group(wizard: SetupWizard | int) -> str:
    return _GROUP_OF.get(SetupWizard(wizard), "")


def display_order() -> tuple[SetupWizard, ...]:
    """Every task, group by group, in table order."""

    return _ORDER


def group_tasks(group: str) -> tuple[SetupWizard, ...]:
    """The tasks of ``group`` in table order (empty for an unknown group)."""

    return _TASKS.get(group, ())


def task_row(wizard: SetupWizard | int) -> int:
    """Row of ``wizard`` in its group's table."""

    wizard = SetupWizard(wizard)
    return _TASKS[_GROUP_OF[wizard]].index(wizard)


def task_at(group: str, row: int) -> SetupWizard | None:
    """Task on ``row`` of ``group``'s table; None when out of range."""

    tasks = group_tasks(group)
    return tasks[row] if 0 <= row < len(tasks) else None


def step_wizard(wizard: SetupWizard | int, delta: int, *, wrap: bool = False) -> SetupWizard:
    """Next/previous task in display order, across group boundaries."""

    index = _ORDER.index(SetupWizard(wizard)) + delta
    if wrap:
        return _ORDER[index % len(_ORDER)]
    return _ORDER[max(0, min(index, len(_ORDER) - 1))]


def step_group(wizard: SetupWizard | int, delta: int) -> SetupWizard:
    """First task of the group ``delta`` groups away (wrapping)."""

    index = GROUP_TITLES.index(wizard_group(wizard)) + delta
    return _TASKS[GROUP_TITLES[index % len(GROUP_TITLES)]][0]


# --- task status ----------------------------------------------------------

TaskState = Literal["ok", "attention", "off", "na"]
TASK_GLYPHS: dict[str, str] = {"ok": "✓", "attention": "!", "off": "○", "na": "–"}
_DEFAULT_TEXT: dict[str, str] = {"ok": "set up", "attention": "needs attention", "off": "not set up", "na": "n/a"}


@dataclass(frozen=True)
class TaskStatus:
    """One task's Status cell: ✓ set up, ! needs attention, ○ not set up, – n/a.

    ``text`` is a short state such as ``on · observe`` or ``2 missing``.
    """

    state: TaskState
    text: str = ""

    @property
    def glyph(self) -> str:
        return TASK_GLYPHS[self.state]

    @property
    def label(self) -> str:
        return f"{self.glyph} {self.text or _DEFAULT_TEXT[self.state]}"


@dataclass(frozen=True)
class TaskProblem:
    """A readiness check that needs attention, as one task's detail tells it.

    ``owned`` checks decide the task's own status; the others are about
    something the task depends on (``why`` says what).
    """

    check: ReadinessCheck
    owned: bool = True
    why: str = ""

    @property
    def fix(self) -> str:
        fix = self.check.fix
        if fix is None:
            return ""
        return " ".join((fix.binary, *fix.args))


def _check_name(check: ReadinessCheck) -> str:
    # "Active Connector: codex" is one row per connector.
    return check.title.split(":", 1)[0].strip()


# Which task owns each readiness check (its fix belongs to that task).
_READINESS_OWNERS: dict[str, tuple[SetupWizard, ...]] = {
    "Active Connector": (SetupWizard.CONNECTOR_SETUP,),
    "Gateway / API Health": (SetupWizard.GATEWAY,),
    "Guardrail": (SetupWizard.GUARDRAIL,),
    "Required Credentials": (SetupWizard.CREDENTIALS,),
    "LLM Config": (SetupWizard.LLM,),
    "Regional Provider": (SetupWizard.LLM,),
    "Custom-provider Overlay": (SetupWizard.CUSTOM_PROVIDERS,),
    "Scanner Availability": (SetupWizard.SKILL_SCANNER, SetupWizard.MCP_SCANNER),
    "Observability v8": (SetupWizard.OBSERVABILITY,),
    "Registry / Asset Policy": (SetupWizard.REGISTRIES,),
    "Restart Pending": (SetupWizard.GATEWAY,),
}
# Checks a task depends on without owning them: (check, task) -> why.
_READINESS_RELATED: dict[tuple[str, SetupWizard], str] = {
    ("LLM Config", SetupWizard.GUARDRAIL): "the judge uses it",
    ("Regional Provider", SetupWizard.GUARDRAIL): "the judge uses it",
    ("LLM Config", SetupWizard.SKILL_SCANNER): "LLM analysis uses it",
    ("Required Credentials", SetupWizard.LLM): "the model needs its API key",
    ("Gateway / API Health", SetupWizard.GUARDRAIL): "the guardrail runs in the gateway",
    ("Gateway / API Health", SetupWizard.GUARDRAIL_ACTIONS): "the guardrail runs in the gateway",
}


def _related_applies(name: str, wizard: SetupWizard, cfg: object | Mapping[str, Any] | None) -> bool:
    if wizard == SetupWizard.GUARDRAIL and name in {"LLM Config", "Regional Provider"}:
        strategy = _text(cfg, "guardrail.detection_strategy") or "regex_judge"
        return _flag(cfg, "guardrail.enabled") and (strategy != "regex_only" or _flag(cfg, "guardrail.judge.enabled"))
    if wizard == SetupWizard.SKILL_SCANNER:
        return _flag(cfg, "scanners.skill_scanner.use_llm")
    if wizard in {SetupWizard.GUARDRAIL, SetupWizard.GUARDRAIL_ACTIONS}:
        return _flag(cfg, "guardrail.enabled")
    return True


def task_problems(
    wizard: SetupWizard | int,
    readiness: Sequence[ReadinessCheck] = (),
    cfg: object | Mapping[str, Any] | None = None,
) -> tuple[TaskProblem, ...]:
    """Readiness checks that need attention and matter to ``wizard``.

    The task's own checks come first, then the ones it depends on.
    """

    wizard = SetupWizard(wizard)
    owned: list[TaskProblem] = []
    related: list[TaskProblem] = []
    for check in readiness:
        if check.status == "pass":
            continue
        name = _check_name(check)
        if wizard in _READINESS_OWNERS.get(name, ()):
            owned.append(TaskProblem(check))
        elif (why := _READINESS_RELATED.get((name, wizard))) and _related_applies(name, wizard, cfg):
            related.append(TaskProblem(check, owned=False, why=why))
    return (*owned, *related)


def _value(cfg: object | Mapping[str, Any] | None, path: str, default: Any = None) -> Any:
    try:
        return get_config_value(cfg, path, default)
    except Exception:  # noqa: BLE001 - a config quirk must not break the Status column.
        return default


def _text(cfg: object | Mapping[str, Any] | None, path: str) -> str:
    value = _value(cfg, path, "")
    return str(value).strip() if value is not None else ""


def _flag(cfg: object | Mapping[str, Any] | None, path: str, default: bool = False) -> bool:
    value = _value(cfg, path, default)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _items(cfg: object | Mapping[str, Any] | None, path: str) -> list[Any]:
    value = _value(cfg, path, None)
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _enabled(entry: Any, default: bool = True) -> bool:
    value = entry.get("enabled", default) if isinstance(entry, Mapping) else getattr(entry, "enabled", default)
    return default if value is None else bool(value)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _short(value: str, width: int = 20) -> str:
    return value if len(value) <= width else value[: width - 1] + "…"


def _destinations(observability: Any) -> list[Any] | None:
    """Enabled destinations the operator added; None when the plan isn't known."""

    if observability is None:
        return None
    return [
        destination
        for destination in getattr(observability, "destinations", ()) or ()
        if getattr(destination, "enabled", False) and not getattr(destination, "generated", False)
    ]


def _connector_status(cfg: Any, owned: bool) -> TaskStatus:
    names = active_connector_names(cfg)
    if not names:
        return TaskStatus("attention" if owned else "off", "no agent yet")
    return TaskStatus("ok", names[0] if len(names) == 1 else _plural(len(names), "agent"))


def _credentials_status(credentials: Any, problems: Sequence[TaskProblem]) -> TaskStatus:
    rows = tuple(getattr(credentials, "rows", ()) or ())
    if getattr(credentials, "error", ""):
        return TaskStatus("attention", "couldn't list keys")
    missing = getattr(credentials, "missing_required", ()) if rows else ()
    if missing:
        return TaskStatus("attention", f"{len(missing)} missing")
    if problems:
        return TaskStatus("attention", "keys missing")
    if rows:
        return TaskStatus("ok", "none missing")
    return TaskStatus("off", "not checked yet")


def _llm_status(cfg: Any, problems: Sequence[TaskProblem]) -> TaskStatus:
    provider = _text(cfg, "llm.provider")
    model = _text(cfg, "llm.model")
    instance = _text(cfg, "llm.instance_name")
    if problems:
        return TaskStatus("attention", "no region" if provider and (model or instance) else "not set")
    if not provider and not model:
        return TaskStatus("off", "not needed (judge off)" if not _flag(cfg, "guardrail.judge.enabled") else "not set")
    if model and "/" not in model and provider:
        model = f"{provider}/{model}"
    return TaskStatus("ok", _short(model or f"{provider} via {instance}"))


def _gateway_status(cfg: Any, problems: Sequence[TaskProblem]) -> TaskStatus:
    names = {_check_name(problem.check) for problem in problems}
    if "Gateway / API Health" in names:
        return TaskStatus("attention", "not running")
    if "Restart Pending" in names:
        return TaskStatus("attention", "restart queued")
    # The sidecar API listener, not gateway.host/port (the OpenClaw
    # gateway uplink, 18789 by default) (GAP-1160).
    host = _text(cfg, "gateway.api_bind") or "127.0.0.1"
    port = _text(cfg, "gateway.api_port")
    return TaskStatus("ok", _short(f"{host}:{port}" if port else host))


def _observability_status(observability: Any, error: str) -> TaskStatus:
    destinations = _destinations(observability)
    if destinations is None:
        if error:
            return TaskStatus("attention", "config unreadable")
        return TaskStatus("off", "local only")
    if not destinations:
        return TaskStatus("off", "local only")
    return TaskStatus("ok", _plural(len(destinations), "destination"))


def _splunk_status(cfg: Any, observability: Any) -> TaskStatus:
    destinations = _destinations(observability)
    if destinations is not None:
        splunk = [
            d
            for d in destinations
            if getattr(d, "kind", "") == "splunk_hec" or str(getattr(d, "preset", "")).startswith("splunk")
        ]
        return TaskStatus("ok", _plural(len(splunk), "destination")) if splunk else TaskStatus("off")
    return TaskStatus("ok", "HEC on") if _flag(cfg, "splunk.enabled") else TaskStatus("off")


def _has_preset(observability: Any, preset: str) -> bool:
    return any(str(getattr(d, "preset", "")) == preset for d in _destinations(observability) or ())


def task_status(
    wizard: SetupWizard | int,
    cfg: object | Mapping[str, Any] | None,
    readiness: Sequence[ReadinessCheck] = (),
    *,
    credentials: Any = None,
    observability: Any = None,
    observability_error: str = "",
    available: bool = True,
) -> TaskStatus:
    """Rate one Setup task for the Status column.

    ``cfg`` is the loaded config (a ``Config``, a mapping, or None);
    ``readiness`` the Setup readiness checks; a failing check the task owns
    makes it need attention. ``credentials`` is the ``keys list`` snapshot,
    ``observability`` the canonical plan status (both optional), and
    ``available`` False for a task this OS can't run.
    """

    wizard = SetupWizard(wizard)
    if not available:
        return TaskStatus("na", "not on this OS")
    problems = tuple(problem for problem in task_problems(wizard, readiness, cfg) if problem.owned)
    guardrail_on = _flag(cfg, "guardrail.enabled")
    if wizard == SetupWizard.CONNECTOR_SETUP:
        return _connector_status(cfg, bool(problems))
    if wizard == SetupWizard.CREDENTIALS:
        return _credentials_status(credentials, problems)
    if wizard == SetupWizard.LLM:
        return _llm_status(cfg, problems)
    if wizard == SetupWizard.GUARDRAIL:
        if not guardrail_on:
            return TaskStatus("attention" if problems else "off", "off")
        return TaskStatus("ok", f"on · {_text(cfg, 'guardrail.mode') or 'observe'}")
    if wizard == SetupWizard.GUARDRAIL_ACTIONS:
        if not guardrail_on:
            return TaskStatus("off", "guardrail off")
        return TaskStatus("ok", f"fail {_text(cfg, 'guardrail.hook_fail_mode') or 'closed'}")
    if wizard in {SetupWizard.SKILL_SCANNER, SetupWizard.MCP_SCANNER}:
        scanner = "skill_scanner" if wizard == SetupWizard.SKILL_SCANNER else "mcp_scanner"
        if problems:
            return TaskStatus("attention", "not configured")
        if not _text(cfg, f"scanners.{scanner}.binary"):
            return TaskStatus("off")
        if wizard == SetupWizard.SKILL_SCANNER:
            policy = _text(cfg, "scanners.skill_scanner.policy") or "permissive"
            return TaskStatus("ok", f"{policy} · LLM" if _flag(cfg, "scanners.skill_scanner.use_llm") else policy)
        return TaskStatus("ok", _short(f"{_text(cfg, 'scanners.mcp_scanner.analyzers') or 'auto'} analyzers"))
    if wizard == SetupWizard.REDACTION:
        if _flag(cfg, "privacy.disable_redaction"):
            return TaskStatus("attention", "turned off")
        return TaskStatus("ok", "on")
    if wizard == SetupWizard.TRUSTED_PATHS:
        added = len(_items(cfg, "ai_discovery.trusted_binary_prefixes"))
        return TaskStatus("ok", f"defaults + {added}" if added else "defaults")
    if wizard == SetupWizard.REGISTRIES:
        if problems:
            return TaskStatus("attention", "catalog required")
        sources = [source for source in _items(cfg, "registries.sources") if _enabled(source)]
        return TaskStatus("ok", _plural(len(sources), "catalog")) if sources else TaskStatus("off", "none added")
    if wizard == SetupWizard.ACP_GUARD:
        if not _flag(cfg, "acp.enabled"):
            return TaskStatus("off")
        return TaskStatus("ok", f"on · {_text(cfg, 'acp.mode') or 'observe'}")
    if wizard == SetupWizard.SANDBOX:
        if not _flag(cfg, "openshell.enabled"):
            return TaskStatus("off")
        return TaskStatus("ok", _short(f"on · {_text(cfg, 'openshell.profile') or 'pack default'}"))
    if wizard == SetupWizard.NOTIFICATIONS_ROUTING:
        return TaskStatus("ok", "on") if _flag(cfg, "notifications.enabled") else TaskStatus("off", "off")
    if wizard == SetupWizard.WEBHOOKS:
        hooks = [hook for hook in _items(cfg, "webhooks") if _enabled(hook, default=False)]
        return TaskStatus("ok", _plural(len(hooks), "webhook")) if hooks else TaskStatus("off", "none")
    if wizard == SetupWizard.OBSERVABILITY:
        return _observability_status(observability, observability_error)
    if wizard == SetupWizard.SPLUNK:
        return _splunk_status(cfg, observability)
    if wizard == SetupWizard.SPLUNK_DASHBOARDS:
        if _has_preset(observability, "splunk-o11y"):
            return TaskStatus("na", "on demand")
        return TaskStatus("off", "needs Splunk O11y")
    if wizard == SetupWizard.LOCAL_OBSERVABILITY:
        return TaskStatus("ok", "wired up") if _has_preset(observability, "local-otlp") else TaskStatus("off")
    if wizard == SetupWizard.GATEWAY:
        return _gateway_status(cfg, problems)
    if wizard == SetupWizard.TOKEN_ROTATION:
        return TaskStatus("na", "on demand")
    if wizard == SetupWizard.CUSTOM_PROVIDERS:
        instance = _text(cfg, "llm.instance_name")
        return TaskStatus("ok", _short(f"using {instance}")) if instance else TaskStatus("off", "none")
    if wizard == SetupWizard.AI_DISCOVERY:
        if not _flag(cfg, "ai_discovery.enabled"):
            return TaskStatus("off", "off")
        return TaskStatus("ok", f"on · {_text(cfg, 'ai_discovery.mode') or 'enhanced'}")
    return TaskStatus("na")


def setup_detail_pairs(model: object) -> tuple[tuple[str, str], ...]:
    """What ``i`` shows on the wizard list: the selected task, then readiness.

    ``model`` is a SetupPanelModel. Checks that need attention come first,
    each with the command that fixes it when there is one.
    """

    info = model.active_wizard_info()  # type: ignore[attr-defined]
    pairs: list[tuple[str, str]] = [
        ("Task", f"{wizard_label(info.wizard)} ({wizard_group(info.wizard)})"),
        ("What it does", info.description),
        ("How it works", info.how_to),
        ("Command", " ".join(info.argv)),
    ]
    if info.status == "unsupported":
        pairs.append(("Unavailable", model.wizard_unavailable_reason(info.wizard)))  # type: ignore[attr-defined]
    checks = tuple(getattr(model, "readiness_checks", ()) or ())
    ranked = sorted(checks, key=lambda check: {"fail": 0, "warn": 1}.get(check.status, 2))
    for check in ranked:
        value = f"{check.status.upper()} · {check.detail}"
        fix = getattr(check, "fix", None)
        if fix is not None and check.status != "pass":
            value += f" · fix: {getattr(fix, 'binary', 'defenseclaw')} {' '.join(fix.args)}"
        pairs.append((check.title, value))
    snapshot = getattr(model, "credential_snapshot", None)
    if getattr(snapshot, "error", ""):
        pairs.append(("API keys", f"Could not list keys: {snapshot.error}"))
    elif not getattr(snapshot, "rows", ()):
        pairs.append(("API keys", "Not loaded yet; press r on the task list to load them."))
    return tuple(pairs)


# --- config sections -------------------------------------------------------

SECTION_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Core", ("General", "Agent", "Claw", "Gateway", "Gateway Watcher", "Gateway Watchdog")),
    (
        "Protection",
        (
            "Guardrail",
            "Scanners",
            "Asset Policy",
            "Skill Actions",
            "MCP Actions",
            "Plugin Actions",
            "Cisco AI Defense",
            "Firewall",
            "Trusted Paths",
            "OpenShell Sandboxes",
            "Watch",
        ),
    ),
    ("Hooks (read-only)", ("Agent Hooks", "Connector Hooks")),
    ("Observability", ("Observability", "Webhooks", "Notifications", "AI Discovery")),
    ("Legacy", ("Inspect LLM (legacy - read-only)",)),
)
_DEFAULT_SECTION_GROUP = "Core"
_LEGACY_GROUP = "Legacy"


def section_group(name: str) -> str:
    for title, names in SECTION_GROUPS:
        if name in names:
            return title
    if "legacy" in name.lower():
        return _LEGACY_GROUP
    return _DEFAULT_SECTION_GROUP


def section_order(sections: Sequence[ConfigSection]) -> tuple[int, ...]:
    """Section indices in grouped order (Core first, Legacy last)."""

    group_rank = {title: rank for rank, (title, _names) in enumerate(SECTION_GROUPS)}
    name_rank = {name: rank for _title, names in SECTION_GROUPS for rank, name in enumerate(names)}
    return tuple(
        sorted(
            range(len(sections)),
            key=lambda index: (
                group_rank.get(section_group(sections[index].name), 0),
                name_rank.get(sections[index].name, len(name_rank) + index),
                index,
            ),
        )
    )


def step_section(sections: Sequence[ConfigSection], current: int, delta: int) -> int:
    """Next/previous section index in grouped order, wrapping around."""

    order = section_order(sections)
    if not order:
        return 0
    position = order.index(current) if current in order else 0
    return order[(position + delta) % len(order)]


def section_position(sections: Sequence[ConfigSection], current: int) -> tuple[int, int]:
    """1-based position of ``current`` in grouped order, and the total."""

    order = section_order(sections)
    if current not in order:
        return (0, len(order))
    return (order.index(current) + 1, len(order))


@dataclass(frozen=True)
class SectionCounts:
    changed: int = 0
    errors: int = 0


def section_counts(section: ConfigSection) -> SectionCounts:
    changed = 0
    errors = 0
    for field in section.fields:
        if field.kind == "header":
            continue
        if field.value != field.original:
            changed += 1
        if validate_config_field(field).severity == "error":
            errors += 1
    return SectionCounts(changed, errors)


@dataclass(frozen=True)
class PickerRow:
    """One row of a Setup picker: a selectable entry or a group header."""

    row_id: str
    label: str
    detail: str = ""
    selectable: bool = True
    search_text: str = ""


def section_picker_rows(sections: Sequence[ConfigSection], active: int = -1) -> tuple[PickerRow, ...]:
    """Grouped section list for ``g``; row ids are section indices."""

    rows: list[PickerRow] = []
    group = None
    for index in section_order(sections):
        section = sections[index]
        title = section_group(section.name)
        if title != group:
            rows.append(PickerRow(f"group:{title}", title, selectable=False))
            group = title
        counts = section_counts(section)
        facts = []
        if counts.changed:
            facts.append(f"{counts.changed} changed")
        if counts.errors:
            facts.append(f"{counts.errors} to fix")
        if index == active:
            facts.append("open")
        rows.append(
            PickerRow(
                str(index),
                section.name,
                " · ".join(facts),
                search_text=section.name.lower(),
            )
        )
    return tuple(rows)


@dataclass(frozen=True)
class FieldEntry:
    section_index: int
    line: int
    section: str
    label: str
    key: str

    @property
    def row_id(self) -> str:
        return f"{self.section_index}:{self.line}"


def field_entries(sections: Sequence[ConfigSection]) -> tuple[FieldEntry, ...]:
    """Every real field across all sections (separator rows left out)."""

    entries: list[FieldEntry] = []
    for index in section_order(sections):
        section = sections[index]
        for line, field in enumerate(section.fields):
            if field.kind == "header" and not field.key and not field.value:
                continue
            entries.append(FieldEntry(index, line, section.name, field.label, field.key))
    return tuple(entries)


def filter_field_entries(query: str, entries: Sequence[FieldEntry]) -> tuple[FieldEntry, ...]:
    """Entries whose key or label contains every word of ``query``.

    Ranked: exact key, key prefix, label prefix, then anything else, keeping
    the section order within a rank.
    """

    words = query.strip().lower().split()
    if not words:
        return tuple(entries)
    ranked: list[tuple[int, int, FieldEntry]] = []
    for position, entry in enumerate(entries):
        key = entry.key.lower()
        label = entry.label.lower()
        haystack = f"{key} {label} {entry.section.lower()}"
        if not all(word in haystack for word in words):
            continue
        whole = " ".join(words)
        if key == whole:
            rank = 0
        elif key.startswith(whole) or key.rsplit(".", 1)[-1].startswith(whole):
            rank = 1
        elif label.startswith(whole):
            rank = 2
        else:
            rank = 3
        ranked.append((rank, position, entry))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return tuple(entry for _rank, _position, entry in ranked)


def field_picker_rows(entries: Sequence[FieldEntry]) -> tuple[PickerRow, ...]:
    return tuple(
        PickerRow(
            entry.row_id,
            entry.label,
            f"{entry.section} · {entry.key}" if entry.key else entry.section,
        )
        for entry in entries
    )


__all__ = [
    "GROUP_TITLES",
    "SECTION_GROUPS",
    "TASK_GLYPHS",
    "WIZARD_GROUPS",
    "FieldEntry",
    "PickerRow",
    "SectionCounts",
    "TaskProblem",
    "TaskStatus",
    "display_order",
    "field_entries",
    "field_picker_rows",
    "filter_field_entries",
    "group_tasks",
    "section_counts",
    "section_group",
    "section_order",
    "section_picker_rows",
    "section_position",
    "setup_detail_pairs",
    "step_group",
    "step_section",
    "step_wizard",
    "task_at",
    "task_problems",
    "task_row",
    "task_status",
    "wizard_group",
    "wizard_label",
]
