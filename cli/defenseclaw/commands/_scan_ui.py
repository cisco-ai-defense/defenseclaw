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

"""Shared UI helpers for ``defenseclaw <component> scan`` commands.

The scan commands (``defenseclaw plugin scan``, ``defenseclaw skill
scan``, ``defenseclaw mcp scan``, ``defenseclaw scan --all``) all
share the same UX shape: announce *what* is being scanned and *for*
what (so users see "Scanning 3 plugins for malware, prompt
injection, secrets" instead of an opaque "Scanning..."), then print
either a per-target verdict line or a JSON document. Today each
command rolls its own preamble, scan-table, and summary; small drift
between them confuses operators who are paging through several at
once.

This module is the canonical home for those helpers. S6.1
introduces the data structures and primitives; S6.2 / S6.3 / S6.4
will replace the per-command UX with calls into this module.

Public surface:

* :class:`ScanContext` — bundles the per-invocation context every
  helper needs (component label, active connector, paths, scan
  categories, --json flag, click context). Built by
  :meth:`ScanContext.for_plugin` / :meth:`ScanContext.for_skill` /
  :meth:`ScanContext.for_mcp`.
* :func:`render_preamble` — prints the "Scanning N <component>s on
  <connector>" banner, with concrete bullet points for the scan
  categories.
* :func:`render_per_target_status` — prints a single result line.
* :func:`render_summary` — prints the final tally (clean / blocked /
  errored / total).
* :func:`render_json_payload` — emits a stable JSON shape; locked
  by snapshot tests in S6.6.

All helpers tolerate ``ctx.as_json`` and emit nothing in JSON mode
except the final document — per
:doc:`docs/cli-ux-contract` (the JSON shape is the
machine-readable contract; humans see the table only on the human
output path).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import click

# ---------------------------------------------------------------------------
# Component / category definitions
# ---------------------------------------------------------------------------

# Stable component IDs mirroring the inventory categories from S4.3.
COMPONENT_PLUGIN = "plugin"
COMPONENT_SKILL = "skill"
COMPONENT_MCP = "mcp"

# Human labels and pluralization. Kept in one place so the wording
# stays consistent across `scan`, `aibom`, `doctor`, and the help
# text.
_COMPONENT_LABELS: dict[str, tuple[str, str]] = {
    COMPONENT_PLUGIN: ("plugin", "plugins"),
    COMPONENT_SKILL: ("skill", "skills"),
    COMPONENT_MCP: ("MCP server", "MCP servers"),
}

# Default per-component scan categories — the bullet list under the
# preamble. Concrete enough to set expectations, abstract enough that
# we don't have to re-version every time a scanner adds a check.
_DEFAULT_CATEGORIES: dict[str, tuple[str, ...]] = {
    COMPONENT_PLUGIN: (
        "malicious code patterns",
        "prompt injection attempts",
        "hardcoded secrets",
        "supply-chain risk indicators",
    ),
    COMPONENT_SKILL: (
        "prompt injection in SKILL.md",
        "malicious shell / Python invocations",
        "untrusted bundled bins",
        "policy violations",
    ),
    COMPONENT_MCP: (
        "untrusted command paths",
        "outbound URL allow-listing",
        "tool-name spoofing",
        "auth-token handling",
    ),
}


# ---------------------------------------------------------------------------
# Verdict states
# ---------------------------------------------------------------------------

VERDICT_CLEAN = "clean"
VERDICT_BLOCKED = "blocked"
VERDICT_QUARANTINED = "quarantined"
VERDICT_ERROR = "error"
VERDICT_SKIPPED = "skipped"

_VERDICT_GLYPH: dict[str, str] = {
    VERDICT_CLEAN: "ok",
    VERDICT_BLOCKED: "BLOCKED",
    VERDICT_QUARANTINED: "QUARANTINED",
    VERDICT_ERROR: "ERROR",
    VERDICT_SKIPPED: "skip",
}


# ---------------------------------------------------------------------------
# ScanContext
# ---------------------------------------------------------------------------


@dataclass
class ScanContext:
    """Per-invocation context passed to every render helper.

    Built once at the top of a scan command via the convenience
    constructors below, then threaded through. Keeping a dataclass
    (instead of separate positional args) means we can add new
    fields — e.g. ``severity_threshold``, ``offline``, ``policy_id``
    — without breaking call sites.

    Attributes
    ----------
    component
        One of :data:`COMPONENT_PLUGIN`, :data:`COMPONENT_SKILL`,
        :data:`COMPONENT_MCP`.
    connector
        The active connector name (e.g. ``"openclaw"``,
        ``"codex"``). Lowercase, never empty — defaults to
        ``"openclaw"`` when unset, mirroring
        ``Config.active_connector``.
    paths
        The directories or files being scanned. Used for the
        preamble (``Scanning N plugins under ~/.codex/extensions``)
        and the JSON ``targets[]`` array.
    categories
        The scan categories listed under the preamble bullet
        points. Defaults to the per-component list in
        :data:`_DEFAULT_CATEGORIES`.
    as_json
        When True, no human output is emitted before the final JSON
        document. Mirrors the ``--json`` flag wired into every scan
        command.
    click_ctx
        Optional click context, used to short-circuit on
        ``--quiet`` / ``--no-color`` flags. May be None in unit
        tests.
    """

    component: str
    connector: str
    paths: list[str] = field(default_factory=list)
    categories: tuple[str, ...] = ()
    as_json: bool = False
    click_ctx: click.Context | None = None

    def __post_init__(self) -> None:
        # Normalize. Operators routinely paste connector names with
        # weird casing or trailing whitespace.
        self.connector = (self.connector or "openclaw").strip().lower() or "openclaw"
        if not self.categories:
            self.categories = _DEFAULT_CATEGORIES.get(self.component, ())

    # -- convenience constructors -------------------------------------

    @classmethod
    def for_plugin(cls, *, connector: str, paths: Iterable[str], as_json: bool = False) -> ScanContext:
        return cls(
            component=COMPONENT_PLUGIN,
            connector=connector,
            paths=list(paths),
            as_json=as_json,
        )

    @classmethod
    def for_skill(cls, *, connector: str, paths: Iterable[str], as_json: bool = False) -> ScanContext:
        return cls(
            component=COMPONENT_SKILL,
            connector=connector,
            paths=list(paths),
            as_json=as_json,
        )

    @classmethod
    def for_mcp(cls, *, connector: str, paths: Iterable[str], as_json: bool = False) -> ScanContext:
        return cls(
            component=COMPONENT_MCP,
            connector=connector,
            paths=list(paths),
            as_json=as_json,
        )

    # -- helpers ------------------------------------------------------

    def label(self, *, plural: bool = False) -> str:
        """Return the human-readable component label, optionally pluralized."""
        sing, plur = _COMPONENT_LABELS.get(self.component, (self.component, self.component + "s"))
        return plur if plural else sing


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------


def render_preamble(ctx: ScanContext, target_count: int) -> None:
    """Print the "Scanning N <components> on <connector> for ..." banner.

    Skipped entirely when ``ctx.as_json`` is True — JSON callers
    care only about the final document.
    """
    if ctx.as_json:
        return
    label = ctx.label(plural=target_count != 1)
    click.echo()
    click.echo(
        f"  Scanning {target_count} {label} on {ctx.connector} for:"
    )
    for cat in ctx.categories:
        click.echo(f"    - {cat}")
    if ctx.paths:
        click.echo()
        if len(ctx.paths) == 1:
            click.echo(f"  Source: {ctx.paths[0]}")
        else:
            click.echo("  Sources:")
            for p in ctx.paths:
                click.echo(f"    - {p}")
    click.echo()


def render_per_target_status(
    ctx: ScanContext,
    *,
    target: str,
    verdict: str,
    detail: str = "",
    findings: int = 0,
) -> None:
    """Print one ``<glyph> <target> [<finding count>] <detail>`` line.

    No-ops in JSON mode.
    """
    if ctx.as_json:
        return
    glyph = _VERDICT_GLYPH.get(verdict, "?")
    finding_part = ""
    if findings > 0:
        finding_part = f" ({findings} finding{'s' if findings != 1 else ''})"
    detail_part = f" — {detail}" if detail else ""
    click.echo(f"    [{glyph}] {target}{finding_part}{detail_part}")


def render_summary(
    ctx: ScanContext,
    *,
    clean: int,
    blocked: int,
    errored: int,
    total: int,
    duration_ms: int | None = None,
) -> None:
    """Print the final tally line.

    No-ops in JSON mode (the JSON document carries the same numbers
    in its ``summary`` block).
    """
    if ctx.as_json:
        return
    click.echo()
    parts = [
        f"  Summary: {total} {ctx.label(plural=total != 1)} scanned",
        f"clean={clean}",
        f"blocked={blocked}",
    ]
    if errored:
        parts.append(f"errored={errored}")
    if duration_ms is not None and duration_ms >= 0:
        parts.append(f"in {duration_ms}ms")
    click.echo(", ".join(parts))


# ---------------------------------------------------------------------------
# JSON payload
# ---------------------------------------------------------------------------


def render_json_payload(
    ctx: ScanContext,
    *,
    results: list[dict[str, Any]],
    clean: int,
    blocked: int,
    errored: int,
    duration_ms: int | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Build the canonical JSON payload for a scan command.

    The shape is locked here — call sites must not invent their own
    keys. S6.6 will add a snapshot test that hashes this payload
    schema (without values) so any drift produces a CI failure.

    Returns the serialized string; caller is responsible for echo /
    write. We don't emit directly so unit tests can inspect the
    structure without parsing ``capsys`` output.
    """
    payload: dict[str, Any] = {
        "version": 1,
        "component": ctx.component,
        "connector": ctx.connector,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "paths": list(ctx.paths),
        "categories": list(ctx.categories),
        "results": results,
        "summary": {
            "total": len(results),
            "clean": clean,
            "blocked": blocked,
            "errored": errored,
        },
    }
    if duration_ms is not None and duration_ms >= 0:
        payload["summary"]["duration_ms"] = duration_ms
    if extra:
        # Allow callers to attach component-specific extras (e.g.
        # plugin scanner's "checked_for_signatures": True). Never
        # let them clobber the locked top-level keys.
        for k, v in extra.items():
            if k not in payload:
                payload[k] = v
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Helpers consumed by unit tests / cmd_doctor (S6.5)
# ---------------------------------------------------------------------------


def categories_for(component: str) -> tuple[str, ...]:
    """Return the default category bullet list for *component*.

    Useful for ``defenseclaw doctor`` (S6.5) which lists the
    categories each scanner advertises so operators see what they
    get before running anything.
    """
    return _DEFAULT_CATEGORIES.get(component, ())


def supported_components() -> tuple[str, ...]:
    """Return the stable list of scan components."""
    return (COMPONENT_PLUGIN, COMPONENT_SKILL, COMPONENT_MCP)
