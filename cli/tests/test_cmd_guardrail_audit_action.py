# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Guardrail changes must be audited with an action the gateway admits."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from defenseclaw.audit_actions import is_known_action
from defenseclaw.commands import cmd_guardrail


def test_guardrail_changes_use_a_registered_audit_action() -> None:
    # The gateway answers unregistered action names with HTTP 400, which
    # silently dropped every use-pack / protection / mode / level audit event.
    app = SimpleNamespace(logger=MagicMock())
    for operation in ("guardrail-use-pack", "guardrail-protection", "guardrail-mode", "guardrail-block-at"):
        cmd_guardrail._log_guardrail_change(app, operation, "scope=codex")  # noqa: SLF001
        action, target, details = app.logger.log_action.call_args.args
        assert is_known_action(action), action
        assert (target, details) == ("config", f"{operation} scope=codex")
