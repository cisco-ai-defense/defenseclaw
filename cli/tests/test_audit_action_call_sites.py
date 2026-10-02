# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Every audit action a call site emits must be in the registry.

The gateway admits only registered actions (internal/audit/actions.go) and
answers anything else with HTTP 400, which made commands such as
``registry approve``, ``plugin unblock``, ``mcp unset`` and
``guardrail judge add`` crash with CanonicalObservabilityError after they had
already applied the change.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

from defenseclaw.audit_actions import is_known_action

ROOT = Path(__file__).resolve().parents[2]
PY_ROOT = ROOT / "cli" / "defenseclaw"

# f-string action names whose every expansion is registered.
_ALLOWED_DYNAMIC = {("commands/cmd_guardrail.py", "f'guardrail-{verb}'")}


def _discovery_module():
    path = ROOT / "scripts" / "discover_unregistered_audit_actions.py"
    spec = importlib.util.spec_from_file_location("discover_unregistered_audit_actions", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_literal_audit_actions_at_call_sites_are_registered() -> None:
    discovery = _discovery_module()
    emitted = discovery.discover_go_actions() | discovery.discover_python_actions()
    assert sorted(a for a in emitted if not is_known_action(a)) == []


def test_python_call_sites_do_not_build_unregistered_action_names() -> None:
    dynamic = set()
    for path in sorted(PY_ROOT.rglob("*.py")):
        rel = path.relative_to(PY_ROOT).as_posix()
        if rel.startswith("tests/"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in {"log_action", "log_activity"}:
                continue
            args = node.args[:1] if node.func.attr == "log_action" else []
            args += [kw.value for kw in node.keywords if kw.arg == "action"]
            for arg in args:
                if isinstance(arg, ast.JoinedStr):
                    dynamic.add((rel, ast.unparse(arg)))
    assert dynamic - _ALLOWED_DYNAMIC == set()
