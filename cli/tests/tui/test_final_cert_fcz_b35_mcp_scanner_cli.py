# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup mcp-scanner: --api-key-env name check and summary alignment (final-cert batch 35)."""

from __future__ import annotations

from click.testing import CliRunner
from defenseclaw.tui.command_line import infer_command_risk
from defenseclaw.tui.screens.command_preview import mask_argv

_PASTED_KEY = "AIzaSyFakeB35KeyValue0123456789abcdefg"


def _run(argv: list[str]):
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        result = CliRunner().invoke(setup, ["mcp-scanner", "--non-interactive", "--no-verify", *argv], obj=app)
        return result, app.cfg.cisco_ai_defense.api_key_env
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_api_key_env_refuses_a_pasted_key_and_saves_nothing() -> None:
    # GAP-2569: a letters-and-digits key was saved as the env var name.
    for value in (_PASTED_KEY, "sk-fake-0123456789abcdef"):
        result, saved = _run(["--api-endpoint", "https://aid.example", "--api-key-env", value])
        assert result.exit_code == 2, result.output
        assert "NAME of the variable" in result.output and "keys set" in result.output
        assert value not in result.output
        assert saved != value
    result, saved = _run(["--api-endpoint", "https://aid.example", "--api-key-env", "AID_KEY"])
    assert result.exit_code == 0, result.output
    assert saved == "AID_KEY"


def test_pasted_key_in_api_key_env_stays_redacted_in_the_tui() -> None:
    args = ("setup", "mcp-scanner", "--non-interactive", "--api-key-env", _PASTED_KEY)
    assert mask_argv(("defenseclaw", *args))[-1] == "<redacted>"
    assert infer_command_risk("setup", args) == "secret"
    named = ("setup", "mcp-scanner", "--non-interactive", "--api-key-env", "CISCO_AI_DEFENSE_API_KEY")
    assert mask_argv(("defenseclaw", *named)) == ("defenseclaw", *named)


def test_summary_values_share_one_column() -> None:
    # GAP-2568: only the key was padded, so section length shifted the value.
    argv = ["--analyzers", "yara,api", "--llm-provider", "openai", "--llm-model", "gpt-x"]
    argv += ["--api-endpoint", "https://aid.example", "--api-key-env", "AID_KEY", "--api-timeout-ms", "7250"]
    result, _ = _run(argv)
    assert result.exit_code == 0, result.output
    rows = [line for line in result.output.splitlines() if line.startswith("    ") and "." in line.split()[0]]
    rows = [line for line in rows if line.split()[0].endswith(":")]
    labels = {line.split()[0] for line in rows}
    assert {"scanners.mcp_scanner.analyzers:", "llm.provider:", "cisco_ai_defense.endpoint:"} <= labels
    columns = {line.index(line.split()[1], len("    ") + len(line.split()[0])) for line in rows}
    assert len(columns) == 1, result.output
