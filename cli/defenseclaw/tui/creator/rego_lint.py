# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 12: lightweight Rego linter for the Playground custom-rego pane.

We deliberately avoid invoking the ``opa`` CLI for routine keystroke
linting - subprocess-per-edit would freeze a textual TextArea. The
linter here implements a small set of structural checks that catch
the mistakes operators actually make when authoring custom rules:

* missing or duplicated ``package`` directive
* package path that conflicts with the standard ``data.defenseclaw``
  namespace required by the gateway loader
* unbalanced curly braces
* unbalanced parentheses or square brackets
* dangling ``import`` declaration without an identifier
* a ``deny`` / ``allow`` rule body that never references ``input``
  (almost always a bug in the wizard era - the sandbox skeleton does
  reference ``input``)

When the user hits Ctrl+P, the model exposes
``opa_eval.evaluate_inline_rego`` which actually runs the snippet
through ``opa eval``. The lint here is the cheap fast-path; it never
returns "false negatives loud enough to block save". Every issue is
either ``warning`` (advisory, save still allowed) or ``error``
(structural problem that would make the gateway loader reject the
file - we do block save on these).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

LintSeverity = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class LintIssue:
    """A single rego-lint finding."""

    severity: LintSeverity
    line: int  # 1-indexed; 0 means "whole file"
    message: str
    code: str

    def render(self) -> str:
        # Severity prefix is wrapped in escaped square brackets via
        # ``\\[`` so that any caller piping the string through Rich's
        # markup parser keeps the literal ``[ERROR]`` / ``[WARNING]``
        # tokens visible. Plain stdout printers see a backslash, but
        # the TUI is the only consumer and it strips the backslash.
        prefix = self.severity.upper()
        if self.line:
            return f"\\[{prefix}] line {self.line}: {self.message} ({self.code})"
        return f"\\[{prefix}] {self.message} ({self.code})"


_PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*$")
_IMPORT_RE = re.compile(r"^\s*import\b\s*(.*)$")
_RULE_HEAD_RE = re.compile(r"^\s*(deny|allow|warn|violation)\b")


def lint_rego(source: str) -> list[LintIssue]:
    """Return a list of lint issues, in source order.

    The function is deterministic: identical inputs always produce
    identical outputs. Empty / whitespace-only input returns an empty
    list (nothing to lint, no need to nag the operator while they're
    typing the first character).
    """

    if not source.strip():
        return []

    issues: list[LintIssue] = []
    lines = source.splitlines()

    # --- structural balance -----------------------------------------
    open_braces = source.count("{")
    close_braces = source.count("}")
    if open_braces != close_braces:
        issues.append(
            LintIssue(
                severity="error",
                line=0,
                message=(
                    f"unbalanced curly braces: {open_braces} '{{' vs "
                    f"{close_braces} '}}'"
                ),
                code="REGO_BRACE_MISMATCH",
            )
        )
    open_parens = source.count("(")
    close_parens = source.count(")")
    if open_parens != close_parens:
        issues.append(
            LintIssue(
                severity="error",
                line=0,
                message=(
                    f"unbalanced parentheses: {open_parens} '(' vs "
                    f"{close_parens} ')'"
                ),
                code="REGO_PAREN_MISMATCH",
            )
        )
    open_brackets = source.count("[")
    close_brackets = source.count("]")
    if open_brackets != close_brackets:
        issues.append(
            LintIssue(
                severity="error",
                line=0,
                message=(
                    f"unbalanced square brackets: {open_brackets} '[' vs "
                    f"{close_brackets} ']'"
                ),
                code="REGO_BRACKET_MISMATCH",
            )
        )

    # --- package / imports ------------------------------------------
    package_lines: list[tuple[int, str]] = []
    references_input = False
    declares_rule = False

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        m = _PACKAGE_RE.match(line)
        if m:
            package_lines.append((idx, m.group(1)))
            continue

        m = _IMPORT_RE.match(line)
        if m:
            ident = m.group(1).strip().rstrip(",")
            if not ident:
                issues.append(
                    LintIssue(
                        severity="error",
                        line=idx,
                        message="import declaration without an identifier",
                        code="REGO_IMPORT_EMPTY",
                    )
                )
            continue

        if _RULE_HEAD_RE.match(line):
            declares_rule = True

        if "input" in line:
            references_input = True

    if not package_lines:
        issues.append(
            LintIssue(
                severity="error",
                line=0,
                message="missing ``package`` directive",
                code="REGO_PACKAGE_MISSING",
            )
        )
    elif len(package_lines) > 1:
        # Report the second occurrence; the first is fine.
        dup_line, _ = package_lines[1]
        issues.append(
            LintIssue(
                severity="error",
                line=dup_line,
                message="duplicate ``package`` directive",
                code="REGO_PACKAGE_DUPLICATE",
            )
        )
    else:
        line_no, pkg = package_lines[0]
        if not pkg.startswith("defenseclaw."):
            issues.append(
                LintIssue(
                    severity="warning",
                    line=line_no,
                    message=(
                        "package should start with ``defenseclaw.`` so the "
                        "gateway loader picks it up"
                    ),
                    code="REGO_PACKAGE_NAMESPACE",
                )
            )

    if declares_rule and not references_input:
        issues.append(
            LintIssue(
                severity="warning",
                line=0,
                message=(
                    "rule body never references ``input`` - rules without an "
                    "input check almost always misbehave"
                ),
                code="REGO_RULE_NO_INPUT",
            )
        )

    return issues


def has_blocking_errors(issues: list[LintIssue]) -> bool:
    """Return True when any issue would prevent save.

    ``error`` is blocking; ``warning`` and ``info`` are not.
    """

    return any(i.severity == "error" for i in issues)


def render_issues(issues: list[LintIssue]) -> list[str]:
    """Return one string per issue, in source order, ready for
    direct insertion into a Rich text renderer.
    """

    return [issue.render() for issue in issues]
