# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Security-remediation regression tests for the DefenseClaw TUI.

One test per finding fixed in the ``cli/defenseclaw/tui`` package:

* F-0481 - setup wizard command preview must not render secret values.
* F-0801 - credentials wizard must feed the secret over stdin, not argv.
* F-0482 - command preview must redact ``--env KEY=VALUE`` values.
* F-0803 - MCP set form must route env secrets through the child env, not argv.
* F-0521 - plugin action menu must target ``row.id`` (not ``display_name``).
* F-0781 - audit export must be written owner-only (0600).
* F-0782 - activity output save must be written owner-only (0600).
"""

from __future__ import annotations

import json
import sys
from unittest.mock import patch

import pytest
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.executor import CommandExecutor
from defenseclaw.tui.panels.audit import AuditPanelModel
from defenseclaw.tui.panels.setup import (
    CredentialRow,
    SetupPanelModel,
    SetupWizard,
    WizardFormField,
    mask_wizard_secret_values,
)
from defenseclaw.tui.screens.command_preview import mask_argv
from defenseclaw.tui.screens.mcp_set_form import MCPSetFormValues
from defenseclaw.tui.services.catalog_state import (
    parse_plugin_list_json,
    plugin_action_intent,
    plugin_direct_scan_intent,
)

from tests.permissions import assert_owner_only_file


def _set_wizard_field(model: SetupPanelModel, label: str, value: str) -> None:
    for index, field in enumerate(model.form_fields):
        if field.label == label:
            model.form_fields[index] = field.with_value(value)
            return
    raise AssertionError(f"missing wizard field: {label}")


def _write_capture_shim(directory, capture, body: str):
    """Drop an executable ``defenseclaw`` shim that records how it was run."""

    shim = directory / "defenseclaw"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        f"{body}\n",
        encoding="utf-8",
    )
    shim.chmod(0o700)
    _ = capture  # capture path is referenced by the shim body.
    return shim


# ---------------------------------------------------------------------------
# F-0481: setup wizard command preview must mask secret field values.
# ---------------------------------------------------------------------------
def test_f0481_wizard_command_preview_masks_secret_values() -> None:
    marker = "MARKER_SECRET_1234567890"
    model = SetupPanelModel()
    model.open_wizard_form(SetupWizard.CREDENTIALS)
    _set_wizard_field(model, "Action", "set")
    _set_wizard_field(model, "Env Name", "DEFENSECLAW_TEST_KEY")
    _set_wizard_field(model, "Secret Value", marker)

    preview = model.wizard_command_preview()
    assert marker not in preview

    # The masking helper redacts a password value wherever it appears as an
    # argv token, including the ``--flag value`` and ``--flag=value`` forms.
    fields = (WizardFormField(label="API Key", kind="password", flag="--api-key", value=marker),)
    assert mask_wizard_secret_values(fields, ("setup", "llm", "--api-key", marker)) == (
        "setup",
        "llm",
        "--api-key",
        "<redacted>",
    )
    assert mask_wizard_secret_values(fields, ("setup", "llm", f"--api-key={marker}")) == (
        "setup",
        "llm",
        "--api-key=<redacted>",
    )


# ---------------------------------------------------------------------------
# F-0801: credentials wizard secret travels via stdin, never argv.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_f0801_credentials_secret_fed_via_stdin_not_argv(tmp_path) -> None:
    secret = "sk-f0801-secret-zzz"
    model = SetupPanelModel({})
    model.set_credential_snapshot((CredentialRow(env_name="OPENAI_API_KEY", requirement="required"),))
    model.credential_action("s")
    _set_wizard_field(model, "Secret Value", secret)

    action = model.submit_wizard_form()
    assert action.intent is not None
    assert action.intent.args == ("keys", "set", "OPENAI_API_KEY")
    assert secret not in action.intent.args
    assert "--value" not in action.intent.args
    assert action.intent.secret_stdin == secret + "\n"

    capture = tmp_path / "capture.json"
    shim = _write_capture_shim(
        tmp_path,
        capture,
        "data = sys.stdin.readline()\n"
        f"open({str(capture)!r}, 'w', encoding='utf-8')"
        ".write(json.dumps({'argv': sys.argv, 'stdin': data}))",
    )

    resolved = (sys.executable, str(shim), *action.intent.args)
    with patch(
        "defenseclaw.tui.executor.resolve_subprocess_argv",
        return_value=resolved,
    ) as resolver:
        async for _event in CommandExecutor(use_pty=False).run(
            action.intent.binary,
            action.intent.args,
            stdin_input=action.intent.secret_stdin,
        ):
            pass
    resolver.assert_called_once_with(action.intent.binary, action.intent.args)

    payload = json.loads(capture.read_text(encoding="utf-8"))
    assert secret not in payload["argv"]
    assert payload["stdin"].strip() == secret


# ---------------------------------------------------------------------------
# F-0482: command preview redacts --env KEY=VALUE values.
# ---------------------------------------------------------------------------
def test_f0482_mask_argv_redacts_env_pair_values() -> None:
    secret = "MARKER_SECRET_1234567890"

    masked = mask_argv(
        ("defenseclaw", "mcp", "set", "srv", "--command", "node", "--env", f"API_TOKEN={secret}")
    )
    assert secret not in " ".join(masked)
    assert "API_TOKEN=<redacted>" in masked

    masked_inline = mask_argv(("defenseclaw", "mcp", "set", "srv", f"--env=API_TOKEN={secret}"))
    assert secret not in " ".join(masked_inline)
    assert masked_inline[-1] == "--env=API_TOKEN=<redacted>"


# ---------------------------------------------------------------------------
# F-0803: MCP set form routes env secrets through the child environment.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_f0803_mcp_env_secret_via_environment_not_argv(tmp_path) -> None:
    secret = "F0803_secret_value"
    result = MCPSetFormValues(name="srv", command="uvx", env=f"API_KEY={secret}").build_result()

    assert "--env" not in result.argv
    assert all(secret not in arg for arg in result.argv)
    assert result.env == (("API_KEY", secret),)

    capture = tmp_path / "capture.json"
    shim = _write_capture_shim(
        tmp_path,
        capture,
        f"open({str(capture)!r}, 'w', encoding='utf-8')"
        ".write(json.dumps({'argv': sys.argv, 'api_key': os.environ.get('API_KEY', '')}))",
    )

    resolved = (sys.executable, str(shim), *result.argv)
    with patch(
        "defenseclaw.tui.executor.resolve_subprocess_argv",
        return_value=resolved,
    ) as resolver:
        async for _event in CommandExecutor(use_pty=False).run(
            result.binary,
            result.argv,
            env_overrides=dict(result.env),
        ):
            pass
    resolver.assert_called_once_with(result.binary, result.argv)

    payload = json.loads(capture.read_text(encoding="utf-8"))
    assert all(secret not in arg for arg in payload["argv"])
    assert payload["api_key"] == secret


# ---------------------------------------------------------------------------
# F-0521: plugin action menu targets row.id, not the spoofable display name.
# ---------------------------------------------------------------------------
def test_f0521_plugin_action_menu_targets_row_id() -> None:
    row = parse_plugin_list_json(
        json.dumps(
            [{"id": "evil-id", "name": "victim-plugin", "enabled": True, "status": "enabled"}]
        )
    )[0]
    assert row.id == "evil-id"
    assert row.display_name == "victim-plugin"

    assert plugin_direct_scan_intent(row).args == ("plugin", "scan", "evil-id")
    for key in ("b", "a", "q", "x"):
        intent = plugin_action_intent(key, row, origin="action-menu")
        assert intent is not None
        assert intent.args[2] == "evil-id"
        assert intent.args[2] != row.display_name


# ---------------------------------------------------------------------------
# F-0781: audit export is written owner-only (0600).
# ---------------------------------------------------------------------------
def test_f0781_audit_export_is_owner_only(tmp_path) -> None:
    audit = AuditPanelModel()
    audit.set_events(
        [Event(id="event-1", action="scan", target="skill://alpha", severity="HIGH", details="token")]
    )
    app = DefenseClawTUI(data_dir=tmp_path, audit_model=audit)

    target = app._export_audit(None)  # noqa: SLF001 - direct sync export
    assert target.exists()
    assert_owner_only_file(target)


# ---------------------------------------------------------------------------
# F-0782: saved activity output is written owner-only (0600).
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_f0782_activity_save_is_owner_only(tmp_path) -> None:
    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.data_dir = tmp_path
        app.activity_model.add_entry("defenseclaw doctor")
        app.activity_model.append_output("OPENAI_API_KEY=sk-should-be-private")
        app.activity_model.finish_entry(0)
        await pilot.pause()
        app._save_activity_output_interactive()  # noqa: SLF001 - sync write

    saved = list(tmp_path.glob("defenseclaw-activity-*-defenseclaw-doctor.txt"))
    assert len(saved) == 1
    assert_owner_only_file(saved[0])
