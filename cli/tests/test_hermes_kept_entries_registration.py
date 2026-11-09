# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A Hermes hook entry Setup keeps for the user is not a second DefenseClaw handler, and setup says it kept it."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from defenseclaw.doctor_hooks import _HERMES_REQUIRED_HOOKS, hermes_kept_hook_note, unix_hermes_hook_problem

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the Unix Hermes registration")


def _registration(tmp_path: Path, extra: dict[str, list[dict]] | None = None):
    script = tmp_path / "hooks" / "hermes-hook.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    command = str(script)
    hooks = {
        event: [{"command": command, "timeout": 30, **({"matcher": matcher} if matcher else {})}]
        for event, matcher in _HERMES_REQUIRED_HOOKS.items()
    }
    for event, entries in (extra or {}).items():
        hooks[event] = [*entries, *hooks.get(event, [])]
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({"hooks": hooks}), encoding="utf-8")
    approvals = [{"event": event, "command": command} for event in _HERMES_REQUIRED_HOOKS]
    (tmp_path / "shell-hooks-allowlist.json").write_text(json.dumps({"approvals": approvals}), encoding="utf-8")
    return config, script, command


@pytest.mark.parametrize("suffix", [" ", "  ", "\t"])
def test_a_padded_copy_of_the_command_is_kept_not_counted(tmp_path, suffix):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": command + suffix, "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert unix_hermes_hook_problem(str(config), str(script), check_approvals=False) == ("", "")


def test_a_padded_copy_on_another_event_is_kept_not_counted(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["some_future_event"] = [{"command": command + " ", "timeout": 30}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert unix_hermes_hook_problem(str(config), str(script), check_approvals=False) == ("", "")


def test_two_current_commands_are_still_two_handlers(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].append({"command": command, "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "pre_tool_call has 2 DefenseClaw handlers" in problem


def test_a_registration_with_only_a_padded_command_is_reported(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"] = [{"command": command + " ", "timeout": 30, "matcher": ".*"}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "pre_tool_call has 0 DefenseClaw handlers" in problem


def test_setup_says_which_events_kept_an_entry(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": command + " ", "timeout": 30})
    document["hooks"]["post_tool_call"].insert(0, {"command": str(script) + ".off", "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    note = hermes_kept_hook_note(str(tmp_path), str(config))

    assert note.startswith("hermes setup: kept hook entries in ")
    assert "(events: post_tool_call, pre_tool_call)" in note


def test_setup_says_nothing_when_every_entry_is_its_own(tmp_path):
    config, _script, _command = _registration(tmp_path)

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""
    assert hermes_kept_hook_note(str(tmp_path), str(tmp_path / "missing.yaml")) == ""


def test_the_restart_step_of_a_hermes_setup_prints_the_kept_entry_notice(tmp_path, monkeypatch):
    from defenseclaw.commands import cmd_setup

    config, _script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": command + " ", "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *a, **k: True)
    monkeypatch.setattr(cmd_setup.connector_paths, "hermes_config_path", lambda: str(config))
    warned: list[str] = []
    monkeypatch.setattr(cmd_setup.ux, "warn", lambda text, *a, **k: warned.append(str(text)))

    cmd_setup._restart_services(str(tmp_path), connector="hermes", teardown=True, notice_connectors=["hermes"])
    cmd_setup._restart_services(str(tmp_path), connector="hermes")
    assert warned == [], "a teardown or a global change does not repeat the notice"

    cmd_setup._restart_services(str(tmp_path), connector="hermes", notice_connectors=["hermes"])
    assert len(warned) == 1 and "kept hook entries" in warned[0] and "pre_tool_call" in warned[0], warned


@pytest.mark.parametrize("event", ["pre_tool_call", "some_future_event"])
def test_a_double_quoted_copy_of_the_command_is_kept_beside_the_setup_written_entry(tmp_path, event):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"][event] = [{"command": chr(34) + command + chr(34), "timeout": 30}, *document["hooks"].get(event, [])]
    for required in _HERMES_REQUIRED_HOOKS:
        document["hooks"][required] = [
            {**entry, "command": "\x27" + command + "\x27"} if entry["command"] == command else entry
            for entry in document["hooks"][required]
        ]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert unix_hermes_hook_problem(str(config), str(script), check_approvals=False) == ("", "")


def test_an_extra_event_with_the_setup_written_single_quoted_command_is_still_reported(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["some_future_event"] = [{"command": "\x27" + command + "\x27", "timeout": 30}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "some_future_event" in problem


def test_a_users_own_hook_is_kept_without_a_notice(tmp_path):
    config, script, _command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": str(tmp_path / "user-hook.sh"), "timeout": 30})
    document["hooks"]["post_tool_call"].insert(0, {"command": "/opt/tools/audit --event post_tool_call", "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert unix_hermes_hook_problem(str(config), str(script), check_approvals=False) == ("", "")
    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


def test_the_notice_lists_a_copy_of_a_defenseclaw_hook_and_not_the_users_hook_beside_it(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": str(tmp_path / "user-hook.sh"), "timeout": 30})
    document["hooks"]["post_tool_call"].insert(0, {"command": command + " ", "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    note = hermes_kept_hook_note(str(tmp_path), str(config))

    assert "(events: post_tool_call)" in note
    assert "pre_tool_call" not in note


@pytest.mark.parametrize(
    "command",
    [
        "~/.defenseclaw/hooks/hookX",
        "$HOME/.defenseclaw/hooks/hookX --event pre_tool_call",
        "bash /somewhere/else/hermes-hook.sh",
        "echo hermes-hook.sh",
    ],
)
def test_an_entry_that_names_a_defenseclaw_hook_is_listed(tmp_path, command):
    config, _script, _command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": command, "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert "(events: pre_tool_call)" in hermes_kept_hook_note(str(tmp_path), str(config))
