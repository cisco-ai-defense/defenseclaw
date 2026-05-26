# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Phase 12 Rego linter."""

from __future__ import annotations

from defenseclaw.tui.creator.rego_lint import (
    LintIssue,
    has_blocking_errors,
    lint_rego,
    render_issues,
)


def _codes(issues: list[LintIssue]) -> list[str]:
    return [issue.code for issue in issues]


def test_empty_input_returns_no_issues():
    assert lint_rego("") == []
    assert lint_rego("   \n  \n") == []


def test_well_formed_snippet_passes_with_no_blocking_errors():
    src = """
    package defenseclaw.custom.demo

    deny[msg] {
        input.request.kind == "Pod"
        msg := "rejected"
    }
    """
    issues = lint_rego(src)
    assert not has_blocking_errors(issues)


def test_missing_package_directive_is_error():
    src = """
    deny[msg] {
        input.x == 1
        msg := "x"
    }
    """
    codes = _codes(lint_rego(src))
    assert "REGO_PACKAGE_MISSING" in codes


def test_duplicate_package_is_error():
    src = """
package defenseclaw.custom.a

package defenseclaw.custom.b

deny[msg] {
    input.x
    msg := "y"
}
"""
    codes = _codes(lint_rego(src))
    assert "REGO_PACKAGE_DUPLICATE" in codes


def test_non_defenseclaw_package_is_warning_not_error():
    src = """
package foo.bar

deny[msg] {
    input.x
    msg := "y"
}
"""
    issues = lint_rego(src)
    codes = _codes(issues)
    assert "REGO_PACKAGE_NAMESPACE" in codes
    assert not has_blocking_errors(issues)


def test_unbalanced_braces_is_error():
    src = """
package defenseclaw.custom.demo

deny[msg] {
    input.x == 1
"""
    codes = _codes(lint_rego(src))
    assert "REGO_BRACE_MISMATCH" in codes


def test_unbalanced_parens_is_error():
    src = """
package defenseclaw.custom.demo

deny[msg] {
    not startswith(input.x, "foo"
    msg := "x"
}
"""
    codes = _codes(lint_rego(src))
    assert "REGO_PAREN_MISMATCH" in codes


def test_unbalanced_brackets_is_error():
    src = """
package defenseclaw.custom.demo

deny[msg {
    input.x
    msg := "x"
}
"""
    codes = _codes(lint_rego(src))
    assert "REGO_BRACKET_MISMATCH" in codes


def test_empty_import_is_error():
    src = """
package defenseclaw.custom.demo

import

deny[msg] {
    input.x
    msg := "x"
}
"""
    codes = _codes(lint_rego(src))
    assert "REGO_IMPORT_EMPTY" in codes


def test_rule_without_input_reference_is_warning():
    src = """
package defenseclaw.custom.demo

deny[msg] {
    msg := "always"
}
"""
    issues = lint_rego(src)
    codes = _codes(issues)
    assert "REGO_RULE_NO_INPUT" in codes
    assert not has_blocking_errors(issues)


def test_render_issues_includes_line_numbers():
    src = """
package foo.bar
"""
    issues = lint_rego(src)
    rendered = render_issues(issues)
    assert any("line" in r for r in rendered)


def test_render_issues_escapes_severity_bracket_for_rich():
    """Render output is consumed by Rich; the severity prefix must be
    escaped so ``[ERROR]`` survives the markup parser.
    """

    src = "package foo.bar\n"
    rendered = render_issues(lint_rego(src))
    assert all(r.startswith("\\[") for r in rendered)


def test_has_blocking_errors_is_false_when_only_warnings():
    issues = lint_rego(
        "package foo.bar\n\ndeny[msg] { msg := \"x\" }\n"
    )
    assert not has_blocking_errors(issues)


def test_has_blocking_errors_is_true_when_error_present():
    issues = lint_rego(
        "package defenseclaw.custom.demo\n\ndeny[msg] {\n    input.x\n"
    )
    assert has_blocking_errors(issues)
