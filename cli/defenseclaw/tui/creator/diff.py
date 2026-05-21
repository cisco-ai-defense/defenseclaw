# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 6 patch: dotted-path policy diff against the source preset.

Mirrors ``docs-site/components/policy-creator/lib/diff.ts`` line for
line. The Review section in the Quick Start wizard and the ``Review``
section in the Playground modal both render this output as a ``+/-/~``
ASCII patch alongside the live test pane, so the operator can always
see exactly which knobs they have moved away from the bundled preset.

The diff is intentionally narrow: we only enumerate the high-signal
fields the wizard exposes. A generic deep-diff of the full ``Policy``
would either be too noisy (every default tuple shows up as "changed")
or too brittle (renaming a sub-field requires re-keying the diff
table). Keeping the field list explicit also makes the test surface
finite and easy to enumerate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.types import Policy

DiffKind = Literal["added", "removed", "changed"]


@dataclass(frozen=True, slots=True)
class DiffEntry:
    """One human-readable difference between policy and its preset.

    ``path`` is dotted (``guardrail.block_threshold``), ``kind`` carries
    the verb the renderer should use, and ``description`` is a short
    pre-formatted "before -> after" string. The Review pane prepends
    ``+ ``, ``- ``, or ``~ `` based on ``kind``.
    """

    kind: DiffKind
    path: str
    description: str


_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SKILL_ACTION_AXES: tuple[str, ...] = ("runtime", "file", "install")
_SUPPRESSION_LAYERS: tuple[str, ...] = (
    "pre_judge_strips",
    "finding_suppressions",
    "tool_suppressions",
)


def _arrow(before: object, after: object) -> str:
    """Format a "before -> after" cell. Booleans rendered as
    ``true``/``false`` to match the YAML emit (and the docs-site UI),
    not Python's ``True``/``False``."""

    def _fmt(value: object) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    return f"{_fmt(before)} -> {_fmt(after)}"


def diff_against_base(policy: Policy) -> list[DiffEntry]:
    """Return the entries that differ from the bundled ``basedOn``
    preset. Empty list means the policy is byte-identical to the
    preset (modulo defaults the operator never touched).

    Mirrors ``diffAgainstBase`` in ``diff.ts``. The ordering matches
    the TS implementation so the Review pane stays diffable across
    backends if a curious operator shells the same policy through
    both UIs.
    """

    base = load_preset(policy.basedOn)
    out: list[DiffEntry] = []

    if policy.admission.scan_on_install != base.admission.scan_on_install:
        out.append(
            DiffEntry(
                kind="changed",
                path="admission.scan_on_install",
                description=_arrow(
                    base.admission.scan_on_install,
                    policy.admission.scan_on_install,
                ),
            )
        )
    if policy.admission.allow_list_bypass_scan != base.admission.allow_list_bypass_scan:
        out.append(
            DiffEntry(
                kind="changed",
                path="admission.allow_list_bypass_scan",
                description=_arrow(
                    base.admission.allow_list_bypass_scan,
                    policy.admission.allow_list_bypass_scan,
                ),
            )
        )

    for sev in _SEVERITIES:
        bs = base.skill_actions.get(sev)
        ps = policy.skill_actions.get(sev)
        for axis in _SKILL_ACTION_AXES:
            before = getattr(bs, axis)
            after = getattr(ps, axis)
            if before != after:
                out.append(
                    DiffEntry(
                        kind="changed",
                        path=f"skill_actions.{sev}.{axis}",
                        description=_arrow(before, after),
                    )
                )

    for scanner in policy.scanner_overrides:
        if scanner not in base.scanner_overrides or not base.scanner_overrides[scanner]:
            out.append(
                DiffEntry(
                    kind="added",
                    path=f"scanner_overrides.{scanner}",
                    description="new override section",
                )
            )

    if len(policy.first_party_allow_list) != len(base.first_party_allow_list):
        out.append(
            DiffEntry(
                kind="changed",
                path="first_party_allow_list",
                description=(
                    f"{len(base.first_party_allow_list)} -> "
                    f"{len(policy.first_party_allow_list)} entries"
                ),
            )
        )

    if policy.guardrail.block_threshold != base.guardrail.block_threshold:
        out.append(
            DiffEntry(
                kind="changed",
                path="guardrail.block_threshold",
                description=_arrow(
                    base.guardrail.block_threshold,
                    policy.guardrail.block_threshold,
                ),
            )
        )
    if policy.guardrail.alert_threshold != base.guardrail.alert_threshold:
        out.append(
            DiffEntry(
                kind="changed",
                path="guardrail.alert_threshold",
                description=_arrow(
                    base.guardrail.alert_threshold,
                    policy.guardrail.alert_threshold,
                ),
            )
        )
    if policy.guardrail.hilt.enabled != base.guardrail.hilt.enabled:
        out.append(
            DiffEntry(
                kind="changed",
                path="guardrail.hilt.enabled",
                description=_arrow(
                    base.guardrail.hilt.enabled,
                    policy.guardrail.hilt.enabled,
                ),
            )
        )

    base_rule_count = sum(len(f.rules) for f in base.rule_pack.files)
    rule_count = sum(len(f.rules) for f in policy.rule_pack.files)
    if base_rule_count != rule_count:
        out.append(
            DiffEntry(
                kind="changed",
                path="rule_pack",
                description=f"{base_rule_count} -> {rule_count} rules",
            )
        )

    for layer in _SUPPRESSION_LAYERS:
        before = len(getattr(base.suppressions, layer))
        after = len(getattr(policy.suppressions, layer))
        if before != after:
            out.append(
                DiffEntry(
                    kind="changed",
                    path=f"suppressions.{layer}",
                    description=f"{before} -> {after}",
                )
            )

    if policy.firewall.default_action != base.firewall.default_action:
        out.append(
            DiffEntry(
                kind="changed",
                path="firewall.default_action",
                description=_arrow(
                    base.firewall.default_action,
                    policy.firewall.default_action,
                ),
            )
        )
    if len(policy.firewall.allowed_domains) != len(base.firewall.allowed_domains):
        out.append(
            DiffEntry(
                kind="changed",
                path="firewall.allowed_domains",
                description=(
                    f"{len(base.firewall.allowed_domains)} -> "
                    f"{len(policy.firewall.allowed_domains)} entries"
                ),
            )
        )

    if len(policy.webhooks) != len(base.webhooks):
        out.append(
            DiffEntry(
                kind="changed",
                path="webhooks",
                description=(
                    f"{len(base.webhooks)} -> {len(policy.webhooks)} entries"
                ),
            )
        )

    if policy.audit.retention_days != base.audit.retention_days:
        out.append(
            DiffEntry(
                kind="changed",
                path="audit.retention_days",
                description=_arrow(
                    base.audit.retention_days,
                    policy.audit.retention_days,
                ),
            )
        )

    if policy.custom_rego:
        suffix = "" if len(policy.custom_rego) == 1 else "s"
        out.append(
            DiffEntry(
                kind="added",
                path="custom_rego",
                description=(
                    f"{len(policy.custom_rego)} custom Rego snippet{suffix}"
                ),
            )
        )

    return out


def render_diff_lines(entries: list[DiffEntry]) -> list[str]:
    """Render the diff list as ``+ /- /~ `` ASCII patch lines.

    Each entry yields one line of the form
    ``<marker> <path> <description>``. Used by the Review pane to
    feed ``Static`` widgets without forcing each section to ship its
    own renderer.
    """

    markers: dict[DiffKind, str] = {"added": "+", "removed": "-", "changed": "~"}
    return [
        f"{markers[entry.kind]} {entry.path}: {entry.description}"
        for entry in entries
    ]
