# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 12: Ctrl+K command palette for the Playground modal.

The web Creator paints a similar mini-launcher: type a few letters,
the matched action runs (jump to section, toggle a flag, run lint,
emit YAML, etc.). Headless logic lives here so we can unit-test the
fuzzy filter without spinning up Textual.

Design contract:

* ``COMMANDS`` is a static catalogue keyed by ``id``. Each entry has
  a human ``label``, a short ``hint``, optional ``aliases`` (matched
  alongside the label), and a ``kind`` that the dispatch shim uses
  to route the action.
* ``filter_commands`` accepts a query string and returns ranked
  matches. Substring matches win over fuzzy character-skip matches;
  ties broken by alphabetical label so the catalogue order stays
  predictable.
* The match score is intentionally simple - we don't need
  fzf-quality scoring for ~30 commands; deterministic and fast is
  more important.

The dispatcher (``run_command``) lives in ``screens/playground.py``
and calls back into ``PlaygroundModel`` for state mutations. Here we
keep things free of Textual / model imports so the catalogue stays
trivially testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

CommandKind = Literal[
    "jump",  # jump to a section ("target" = section id)
    "toggle",  # toggle a known modal pane ("target" = "test" / "diff")
    "save",  # ctrl+s save
    "cancel",  # esc / cancel
    "lint",  # run rego lint and pin output
    "emit-yaml",  # copy generated YAML to last_message
    "emit-script",  # copy install script to last_message
    "diff",  # focus diff panel
]


@dataclass(frozen=True, slots=True)
class Command:
    """One palette entry."""

    id: str
    label: str
    hint: str
    kind: CommandKind
    target: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)


COMMANDS: tuple[Command, ...] = (
    # --- section navigation ------------------------------------------
    Command(
        id="jump.basics",
        label="Go to Basics",
        hint="name, description, basedOn",
        kind="jump",
        target="basics",
        aliases=("name", "description"),
    ),
    Command(
        id="jump.severity-matrix",
        label="Go to Severity matrix",
        hint="skill_actions + scanner overrides",
        kind="jump",
        target="severity-matrix",
        aliases=("severity", "matrix", "scanner"),
    ),
    Command(
        id="jump.admission",
        label="Go to Admission",
        hint="scan_on_install, allow-list",
        kind="jump",
        target="admission",
        aliases=("admit", "allow-list", "scan"),
    ),
    Command(
        id="jump.guardrail",
        label="Go to Guardrail",
        hint="block/alert thresholds, HILT, trust level",
        kind="jump",
        target="guardrail",
        aliases=("hilt", "trust"),
    ),
    Command(
        id="jump.rules",
        label="Go to Rule pack",
        hint="rule files + per-rule editing",
        kind="jump",
        target="rules",
        aliases=("rule", "pack"),
    ),
    Command(
        id="jump.suppressions",
        label="Go to Suppressions",
        hint="pre-judge, finding, tool",
        kind="jump",
        target="suppressions",
        aliases=("suppress", "exception"),
    ),
    Command(
        id="jump.sensitive-tools",
        label="Go to Sensitive tools",
        hint="result inspection, judge gating",
        kind="jump",
        target="sensitive-tools",
        aliases=("tool", "exec"),
    ),
    Command(
        id="jump.judges",
        label="Go to LLM judges",
        hint="prompts and category gating",
        kind="jump",
        target="judges",
        aliases=("judge", "prompt"),
    ),
    Command(
        id="jump.correlator",
        label="Go to Correlator",
        hint="Layer-5 session patterns",
        kind="jump",
        target="correlator",
        aliases=("correlation", "session"),
    ),
    Command(
        id="jump.firewall",
        label="Go to Firewall",
        hint="default action, blocked dests",
        kind="jump",
        target="firewall",
        aliases=("egress", "network"),
    ),
    Command(
        id="jump.webhooks",
        label="Go to Webhooks",
        hint="alert destinations",
        kind="jump",
        target="webhooks",
        aliases=("alert", "slack", "discord"),
    ),
    Command(
        id="jump.watch",
        label="Go to Watch",
        hint="rescan cadence",
        kind="jump",
        target="watch",
        aliases=("rescan", "interval"),
    ),
    Command(
        id="jump.enforcement",
        label="Go to Enforcement",
        hint="max delay, dry-run",
        kind="jump",
        target="enforcement",
        aliases=("enforce", "delay"),
    ),
    Command(
        id="jump.audit",
        label="Go to Audit",
        hint="log, retention",
        kind="jump",
        target="audit",
        aliases=("log", "retention"),
    ),
    Command(
        id="jump.scanners",
        label="Go to Scanner profiles",
        hint="codeguard, plugin, skill profile names",
        kind="jump",
        target="scanners",
        aliases=("profile", "scan-profile"),
    ),
    Command(
        id="jump.cisco-ai-defense",
        label="Go to Cisco AI Defense",
        hint="optional cloud lane",
        kind="jump",
        target="cisco-ai-defense",
        aliases=("aid", "ai defense", "cisco"),
    ),
    Command(
        id="jump.custom-rego",
        label="Go to Custom Rego",
        hint="hand-authored snippets",
        kind="jump",
        target="custom-rego",
        aliases=("rego", "opa"),
    ),
    Command(
        id="jump.review",
        label="Go to Review & save",
        hint="generated YAML + data.json",
        kind="jump",
        target="review",
        aliases=("save", "preview", "yaml"),
    ),
    # --- panels / actions --------------------------------------------
    Command(
        id="toggle.test",
        label="Toggle live test pane",
        hint="bundled scenarios",
        kind="toggle",
        target="test",
        aliases=("test", "scenarios", "opa"),
    ),
    Command(
        id="toggle.diff",
        label="Toggle diff vs preset",
        hint="dotted-path overrides",
        kind="toggle",
        target="diff",
        aliases=("diff", "delta"),
    ),
    Command(
        id="lint.rego",
        label="Run Rego lint",
        hint="custom-rego section structural checks",
        kind="lint",
        aliases=("lint", "rego-lint", "check"),
    ),
    Command(
        id="emit.yaml",
        label="Emit gateway YAML",
        hint="copy preview into status line",
        kind="emit-yaml",
        aliases=("emit", "yaml"),
    ),
    Command(
        id="emit.script",
        label="Emit install bash script",
        hint="copy heredoc-script preview",
        kind="emit-script",
        aliases=("install", "script", "bash"),
    ),
    Command(
        id="diff.focus",
        label="Show diff vs preset (force on)",
        hint="render the diff panel",
        kind="diff",
        aliases=("show diff",),
    ),
    Command(
        id="action.save",
        label="Save policy",
        hint="ctrl+s",
        kind="save",
        aliases=("save", "commit"),
    ),
    Command(
        id="action.cancel",
        label="Cancel and close playground",
        hint="esc",
        kind="cancel",
        aliases=("close", "exit", "esc"),
    ),
)


def _haystacks(cmd: Command) -> tuple[str, ...]:
    """Return all the strings a query is matched against for ``cmd``.
    """

    return (cmd.label.lower(), cmd.hint.lower(), *(a.lower() for a in cmd.aliases))


def _score(query: str, cmd: Command) -> int:
    """Return a non-negative match score; 0 means "no match".

    Higher = better. The score is:

    * ``0`` when the query matches nothing.
    * Substring hit on the label adds 100.
    * Substring hit on any alias / hint adds 50.
    * Subsequence (fuzzy) hit on the label adds 25.
    * Prefix hit on the label adds 25 (combined with substring or
      subsequence).
    """

    if not query:
        return 1  # treat empty query as "show everything" with stable order

    q = query.lower().strip()
    if not q:
        return 1

    score = 0
    label = cmd.label.lower()
    if q in label:
        score += 100
        if label.startswith(q):
            score += 25
    if any(q in h for h in _haystacks(cmd) if h != label):
        score += 50

    # Subsequence ("ggu" matches "guardrail")
    if score == 0:
        i = 0
        for ch in label:
            if i < len(q) and ch == q[i]:
                i += 1
        if i == len(q):
            score += 25

    return score


def filter_commands(query: str) -> list[Command]:
    """Return commands whose match score is positive, sorted by:

    1. Score descending.
    2. Command id ascending (stable, human-readable order).
    """

    scored = [(cmd, _score(query, cmd)) for cmd in COMMANDS]
    scored = [(cmd, score) for cmd, score in scored if score > 0]
    scored.sort(key=lambda pair: (-pair[1], pair[0].id))
    return [cmd for cmd, _ in scored]


def find_command(command_id: str) -> Command | None:
    """Look up a command by id. Returns ``None`` for unknown ids."""

    for cmd in COMMANDS:
        if cmd.id == command_id:
            return cmd
    return None
