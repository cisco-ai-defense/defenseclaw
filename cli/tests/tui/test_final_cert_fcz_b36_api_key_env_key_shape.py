# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup --api-key-env: the CLI refuses what the TUI redacts as a key (final-cert batch 36, GAP-2581)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import _looks_like_secret
from defenseclaw.tui.services.setup_state import looks_like_secret_value

# Fake key-shaped values (GAP-2594: real key shapes, not bare prefixes).
_KEY_SHAPED = (
    "AKIAFAKEB36EXAMPLE0123",
    "ASIAFAKEB36EXAMPLE0123",
    "AIzaFAKEB36" + "0" * 30,
    "eyJGQUtFQjM2.e30",
    "ghs_FAKEB36",
)


@pytest.mark.parametrize("value", [*_KEY_SHAPED, "CISCO_AI_DEFENSE_API_KEY", "ANTHROPIC_API_KEY", "MY_KEY"])
def test_cli_and_tui_agree_on_key_shape(value: str) -> None:
    assert _looks_like_secret(value) == looks_like_secret_value(value)


def test_setup_mcp_scanner_refuses_key_prefixed_values_and_saves_nothing() -> None:
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    for value in _KEY_SHAPED:
        app, tmp_dir, db_path = make_app_context()
        try:
            argv = ["mcp-scanner", "--non-interactive", "--no-verify", "--api-key-env", value]
            result = CliRunner().invoke(setup, argv, obj=app)
            assert result.exit_code == 2, result.output
            assert "keys set CISCO_AI_DEFENSE_API_KEY" in result.output
            assert value not in result.output
            assert app.cfg.cisco_ai_defense.api_key_env != value
        finally:
            cleanup_app(app, db_path, tmp_dir)
