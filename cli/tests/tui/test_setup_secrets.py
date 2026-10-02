# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Credentials wizard's secret reaches ``keys set`` on stdin, and only there."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.executor import CommandEvent, CommandExecutor
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard
from defenseclaw.tui.screens.command_preview import build_command_preview
from defenseclaw.tui.services.setup_state import CredentialRow

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import screen_text, snapshot_app  # noqa: E402

SECRET = "sk-test-0123456789"


def _credentials_set_intent(secret: str = SECRET) -> Any:
    model = SetupPanelModel({})
    model.set_credential_snapshot((CredentialRow(env_name="OPENAI_API_KEY", requirement="required"),))
    model.credential_action("s")
    assert model.active_wizard == SetupWizard.CREDENTIALS
    index = next(i for i, field in enumerate(model.form_fields) if field.label == "Secret Value")
    model.form_fields[index] = model.form_fields[index].with_value(secret)
    action = model.submit_wizard_form()
    assert action.intent is not None
    return action.intent


def test_set_intent_reads_the_secret_from_stdin() -> None:
    intent = _credentials_set_intent()
    assert intent.args == ("keys", "set", "OPENAI_API_KEY", "--value-stdin")
    assert intent.secret_stdin == SECRET + "\n"
    assert all(SECRET not in arg for arg in intent.args)


def test_preview_names_hidden_inputs_without_values() -> None:
    preview = build_command_preview(
        ParsedCommand(
            binary="defenseclaw",
            args=("keys", "set", "OPENAI_API_KEY", "--value-stdin"),
            display_name="setup Credentials",
            category="setup",
            stdin_input=SECRET + "\n",
            env_overrides=(("API_TOKEN", "tok-secret-value"),),
        )
    )
    assert preview.hidden_inputs == (
        "Secret: sent on stdin (hidden)",
        "Environment: API_TOKEN=<hidden>",
    )
    rendered = " ".join((preview.masked_display, *preview.hidden_inputs))
    assert SECRET not in rendered
    assert "tok-secret-value" not in rendered


async def test_credentials_set_sends_secret_on_stdin_only(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    calls: list[tuple[str, tuple[str, ...], dict[str, Any]]] = []

    async def fake_run(binary: str, args: tuple[str, ...], **kwargs: Any):
        calls.append((binary, tuple(args), kwargs))
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("output", "saved OPENAI_API_KEY")
        yield CommandEvent("done", exit_code=0, duration=0.01)

    async def confirm(_screen: Any) -> bool:
        return True

    async def no_credential_reload() -> None:
        return None

    async with app.run_test(size=(80, 24)) as pilot:
        app.executor.run = fake_run  # type: ignore[method-assign]
        app.push_screen_wait = confirm  # type: ignore[method-assign]
        app._load_setup_credentials = no_credential_reload  # type: ignore[method-assign]
        exit_code = await app._confirm_and_run_intent(_credentials_set_intent())
        await pilot.pause()

        assert exit_code == 0
        assert len(calls) == 1
        binary, args, kwargs = calls[0]
        assert (binary, args) == ("defenseclaw", ("keys", "set", "OPENAI_API_KEY", "--value-stdin"))
        assert kwargs["stdin_input"] == SECRET + "\n"
        assert all(SECRET not in arg for arg in args)
        assert SECRET not in app.activity_model.render_text(height=200)
        assert SECRET not in screen_text(app)


@pytest.mark.allow_subprocess
async def test_executor_closes_stdin_after_the_secret() -> None:
    # The child reads to EOF; without the close it would wait forever.
    script = "import sys; data = sys.stdin.read(); print('bytes', len(data))"
    events = [
        event
        async for event in CommandExecutor(use_pty=False).run(sys.executable, ("-c", script), stdin_input=SECRET + "\n")
    ]
    assert events[-1].kind == "done"
    assert events[-1].exit_code == 0
    output = "".join(event.text for event in events if event.kind == "output")
    assert f"bytes {len(SECRET) + 1}" in output
    assert SECRET not in output
