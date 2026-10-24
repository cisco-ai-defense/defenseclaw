# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""The hook fields that keep each connector's tool calls guarded.

Each agent runs the DefenseClaw hook before a tool call only while the hook
entry Setup wrote keeps the fields in this table: the event, a match-all
matcher, the ``command`` type, the timeout and, where the agent has one, the
enabled flag. A hook entry that is still there but was edited (Antigravity
``enabled: false`` or matcher ``run_command``, Copilot ``type: prompt`` or
``timeoutSec: 1``) let the call run unchecked while doctor on Linux and macOS
passed it (rel-1-0-4 GAP-0538).

Doctor (every OS), status, quickstart, setup readiness, ``guardrail
fail-mode`` and the Windows registration validators read this one table.
cli/tests/test_hook_guard_matrix.py checks it against the files Setup writes
(internal/gateway/connector/testdata/hook_registration_every_connector.json)
and edits each field in turn.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

# Layouts of the agent hook files.
FLAT = "flat"  # hooks.<event>: [handler]
GROUPED = "grouped"  # hooks.<event>: [{matcher, hooks: [handler]}]; Devin's project file is the event map
ANTIGRAVITY = "antigravity"  # defenseclaw-antigravity-<event>: {enabled, <event>: [{matcher, hooks: [handler]}]}
KIRO = "kiro"  # hooks: [{trigger, matcher, enabled, timeout, action: handler}]


@dataclass(frozen=True)
class ToolGuardHook:
    """The hook entry fields one connector needs to inspect a tool call before it runs."""

    layout: str
    # The events that run before a tool call and can block it.
    events: tuple[str, ...]
    timeout: int
    timeout_key: str = "timeout"
    # The matcher values that select every tool (None: the matcher may be
    # left out); empty when the agent has no matcher.
    matchers: tuple[str | None, ...] = ()
    # Whether the handler carries ``type`` (Hermes entries have none).
    typed: bool = True
    # Whether a managed install publishes the hooks through a machine policy
    # layer, whose own timeout the enterprise policy reconcile checks
    # (internal/enterprisepolicy claude.go, codex.go, copilot.go, cursor.go).
    # Per-user-route connectors keep user-writable files on managed hosts too.
    machine_policy: bool = False


TOOL_GUARD_HOOKS: dict[str, ToolGuardHook] = {
    "antigravity": ToolGuardHook(ANTIGRAVITY, ("PreToolUse",), 30, matchers=("*",)),
    "claudecode": ToolGuardHook(GROUPED, ("PreToolUse",), 30, matchers=(None, "", "*"), machine_policy=True),
    "codex": ToolGuardHook(GROUPED, ("PreToolUse",), 30, matchers=("*",), machine_policy=True),
    "copilot": ToolGuardHook(FLAT, ("preToolUse",), 30, timeout_key="timeoutSec", machine_policy=True),
    "cursor": ToolGuardHook(
        FLAT,
        ("preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"),
        30,
        machine_policy=True,
    ),
    "devin": ToolGuardHook(GROUPED, ("PreToolUse",), 10, matchers=(None, "")),
    "hermes": ToolGuardHook(FLAT, ("pre_tool_call",), 30, matchers=(".*",), typed=False),
    "kiro": ToolGuardHook(KIRO, ("PreToolUse",), 30, matchers=(".*",)),
}

# Claude Code runs an async hook, or one with an ``if`` condition, without
# waiting for it, or only for some calls.
_NON_BLOCKING_FLAGS = ("async", "asyncRewake", "async_rewake")


@dataclass(frozen=True)
class _Entry:
    """One registered handler with the fields that decide whether it runs, read from its layout."""

    handler: dict[str, Any]
    matcher: tuple[bool, Any]  # (present, value)
    timeout: Any
    type: Any
    enabled: Any
    containers: tuple[dict[str, Any], ...]


def antigravity_hook_key(event: str) -> str:
    return f"defenseclaw-antigravity-{event.lower()}"


def _entries(spec: ToolGuardHook, document: dict[str, Any], event: str) -> Iterator[_Entry]:
    if spec.layout == ANTIGRAVITY:
        container = document.get(antigravity_hook_key(event))
        if not isinstance(container, dict):
            return
        groups = container.get(event)
        enabled = container.get("enabled", True)
        holders: tuple[dict[str, Any], ...] = (container,)
    elif spec.layout == KIRO:
        hooks = document.get("hooks")
        for item in hooks if isinstance(hooks, list) else ():
            action = item.get("action") if isinstance(item, dict) else None
            if isinstance(action, dict) and item.get("trigger") == event:
                yield _Entry(
                    action,
                    ("matcher" in item, item.get("matcher")),
                    item.get("timeout"),
                    action.get("type"),
                    item.get("enabled", True),
                    (item,),
                )
        return
    else:
        hooks = document.get("hooks")
        if spec.layout == GROUPED and not isinstance(hooks, dict):
            hooks = document  # Devin's project hooks.v1.json
        if not isinstance(hooks, dict):
            return
        groups = hooks.get(event)
        enabled = True
        holders = ()
    for group in groups if isinstance(groups, list) else ():
        if not isinstance(group, dict):
            continue
        if spec.layout == FLAT:
            yield _Entry(
                group,
                ("matcher" in group, group.get("matcher")),
                group.get(spec.timeout_key),
                group.get("type"),
                enabled,
                holders,
            )
            continue
        handlers = group.get("hooks")
        for handler in handlers if isinstance(handlers, list) else ():
            if isinstance(handler, dict):
                yield _Entry(
                    handler,
                    ("matcher" in group, group.get("matcher")),
                    handler.get(spec.timeout_key),
                    handler.get("type"),
                    enabled,
                    (*holders, group),
                )


def _entry_problem(spec: ToolGuardHook, entry: _Entry, *, managed: bool) -> str:
    """Why *entry* does not run before every tool call, or "".

    On a *managed* install the timeout of a machine-policy connector is the
    one the enterprise policy publishes and checks, so it is not compared
    here; every other field is.
    """

    if type(entry.enabled) is not bool or not entry.enabled:
        return f"is disabled (enabled: {entry.enabled!r})"
    if spec.typed and entry.type != "command":
        return f"has type {entry.type!r}, not 'command'"
    if spec.matchers:
        present, matcher = entry.matcher
        if (matcher if present else None) not in spec.matchers:
            return f"matcher {matcher!r} does not select every tool (setup registers {spec.matchers[-1]!r})"
    if not (managed and spec.machine_policy) and (type(entry.timeout) is not int or entry.timeout != spec.timeout):
        return (
            f"{spec.timeout_key} is {entry.timeout!r}, not the {spec.timeout} seconds setup registers, "
            "and the agent runs the call when the hook does not answer in time"
        )
    for container in (*entry.containers, entry.handler):
        for flag in _NON_BLOCKING_FLAGS:
            if container.get(flag) is True:
                return f"sets {flag}: true, so the agent does not wait for it"
        condition = container.get("if", "")
        if not isinstance(condition, str) or condition:
            return f"has an if condition ({condition!r}), so it runs only for some calls"
    return ""


def unguarded_tool_events(
    connector: str,
    document: Any,
    owns: Callable[[dict[str, Any]], bool],
    *,
    managed: bool = False,
) -> list[tuple[str, str]]:
    """The tool-guard events of *connector* that *document* leaves unguarded.

    Each item is ``(event, why)``; ``why`` is "" when the document has no
    DefenseClaw handler for the event at all. *owns* tells whether a decoded
    handler runs DefenseClaw. Callers pass only documents that register
    DefenseClaw hooks; the unregistered-file check reports the others.
    *managed* is a managed_enterprise install (see _entry_problem).
    """

    spec = TOOL_GUARD_HOOKS.get(connector)
    if spec is None or not isinstance(document, dict):
        return []
    found: list[tuple[str, str]] = []
    for event in spec.events:
        owned = [entry for entry in _entries(spec, document, event) if owns(entry.handler)]
        if not owned:
            found.append((event, ""))
            continue
        problems = [_entry_problem(spec, entry, managed=managed) for entry in owned]
        if all(problems):
            found.append((event, problems[0]))
    return found
