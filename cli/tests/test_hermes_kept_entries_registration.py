# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A Hermes hook entry Setup keeps for the user is not a second DefenseClaw handler, a plain spelling of Setup's own command is, and setup says what it kept."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from defenseclaw.doctor_hooks import _HERMES_REQUIRED_HOOKS, hermes_kept_hook_note, unix_hermes_hook_problem
from defenseclaw.hook_integrity import HERMES_HOME_RECORD_FILE, hermes_command_hash, hermes_command_written

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


def _spellings(command: str) -> dict[str, str]:
    """Plain spellings of Setup's command: the same script run through another quoting, blanks or plain arguments."""
    return {
        "trailing blank": command + " ",
        "two blanks": command + "  ",
        "trailing tab": command + "\t",
        "leading blank": " " + command,
        "single quoted": chr(39) + command + chr(39),
        "single quoted, blank after": chr(39) + command + chr(39) + " ",
        "single quoted, blank inside": chr(39) + command + " " + chr(39),
        "double quoted": chr(34) + command + chr(34),
        "with an argument": command + " --extra-arg",
        "quoted, with an argument": chr(39) + command + chr(39) + " --extra-arg",
    }


@pytest.mark.parametrize("name", list(_spellings("x")))
def test_a_spelling_of_the_command_is_the_same_entry_and_a_second_handler_beside_it(tmp_path, name):
    # Setup replaces such an entry, so a registration that holds one beside the entry Setup added is not
    # healthy: the hook would run twice (GAP-0873).
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": _spellings(command)[name], "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "pre_tool_call has 2 DefenseClaw handlers" in problem


@pytest.mark.parametrize("name", list(_spellings("x")))
def test_a_spelling_of_the_command_on_another_event_is_a_defenseclaw_handler(tmp_path, name):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["some_future_event"] = [{"command": _spellings(command)[name], "timeout": 30}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "some_future_event" in problem


# A command that runs the script and something else, or reaches it some other way, is the user's.
_NOT_A_SPELLING = [
    "{c} && echo done",
    "{c}; echo done",
    "{c} | tee /tmp/out",
    "{c} > /tmp/out",
    "{c} $(id)",
    "{c} `id`",
    "{c} $HOME",
    "{c} 'quoted arg'",
    "{c}.off",
    "{c}x",
    "sudo {c}",
    "echo {c}",
    "bash {c}x",
    chr(39) + "{c}" + chr(39) + "x",
    chr(34) + "{c}$HOME" + chr(34),
    chr(39) + "{c}",
    "",
]


@pytest.mark.parametrize("template", _NOT_A_SPELLING)
def test_a_command_that_does_more_than_run_the_script_is_not_a_spelling_of_it(tmp_path, template):
    _config, script, command = _registration(tmp_path)

    assert not hermes_command_written(template.format(c=command), {str(script)})


@pytest.mark.parametrize("template", [t for t in _NOT_A_SPELLING if t])
def test_a_command_that_does_more_than_run_the_script_beside_the_entry_is_not_a_second_handler(tmp_path, template):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].insert(0, {"command": template.format(c=command), "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert unix_hermes_hook_problem(str(config), str(script), check_approvals=False) == ("", "")


def test_two_current_commands_are_still_two_handlers(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"].append({"command": command, "timeout": 30})
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "pre_tool_call has 2 DefenseClaw handlers" in problem


def test_a_registration_with_only_a_padded_command_is_one_handler(tmp_path):
    # The shell runs the script a trailing blank leaves alone, and the approval is read for the same command.
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"] = [{"command": command + " ", "timeout": 30, "matcher": ".*"}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert unix_hermes_hook_problem(str(config), str(script)) == ("", "")


def test_a_registration_with_only_a_command_with_an_argument_is_reported(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["pre_tool_call"] = [{"command": command + " --extra-arg", "timeout": 30, "matcher": ".*"}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "pre_tool_call command does not run" in problem


def _record_setup(tmp_path: Path, kept: dict[str, list[str]] | None = None) -> None:
    """Write the Hermes home record Setup makes: per event, the commands it wrote and the commands it kept."""

    hooks = {
        event: {"wrote": [hermes_command_hash(event)], **({"kept": [hermes_command_hash(c) for c in kept[event]]} if event in (kept or {}) else {})}
        for event in _HERMES_REQUIRED_HOOKS
    }
    record = {"home": str(tmp_path), "set_up_at": "2026-11-09T00:00:00Z", "hooks": hooks}
    (tmp_path / HERMES_HOME_RECORD_FILE).write_text(json.dumps(record), encoding="utf-8")


def _add_entry(config: Path, event: str, command: str, *, first: bool = True) -> None:
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    entry = {"command": command, "timeout": 30}
    document["hooks"][event] = [entry, *document["hooks"][event]] if first else [*document["hooks"][event], entry]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")


def test_setup_says_which_events_kept_an_entry(tmp_path):
    config, script, command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", str(script) + ".bak")
    _add_entry(config, "post_tool_call", str(script) + ".off")
    _record_setup(tmp_path, {"pre_tool_call": [str(script) + ".bak"], "post_tool_call": [str(script) + ".off"]})

    note = hermes_kept_hook_note(str(tmp_path), str(config))

    assert note.startswith("hermes setup: kept hook entries in ")
    assert "(events: post_tool_call, pre_tool_call)" in note


def test_setup_says_nothing_when_every_entry_is_its_own(tmp_path):
    config, _script, _command = _registration(tmp_path)
    _record_setup(tmp_path)

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""
    assert hermes_kept_hook_note(str(tmp_path), str(tmp_path / "missing.yaml")) == ""


def test_the_restart_step_of_a_hermes_setup_prints_the_kept_entry_notice(tmp_path, monkeypatch):
    from defenseclaw.commands import cmd_setup

    config, script, _command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", str(script) + ".bak")
    _record_setup(tmp_path, {"pre_tool_call": [str(script) + ".bak"]})
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
def test_a_double_quoted_copy_of_the_command_is_a_defenseclaw_handler_beside_the_setup_written_entry(tmp_path, event):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"][event] = [{"command": chr(34) + command + chr(34), "timeout": 30}, *document["hooks"].get(event, [])]
    for required in _HERMES_REQUIRED_HOOKS:
        document["hooks"][required] = [
            {**entry, "command": chr(39) + command + chr(39)} if entry["command"] == command else entry
            for entry in document["hooks"][required]
        ]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and event in problem


def test_an_extra_event_with_the_setup_written_single_quoted_command_is_still_reported(tmp_path):
    config, script, command = _registration(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["hooks"]["some_future_event"] = [{"command": chr(39) + command + chr(39), "timeout": 30}]
    config.write_text(yaml.safe_dump(document), encoding="utf-8")

    state, problem = unix_hermes_hook_problem(str(config), str(script), check_approvals=False)

    assert state == "stale" and "some_future_event" in problem


def test_a_users_own_hook_is_kept_without_a_notice(tmp_path):
    config, script, _command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", str(tmp_path / "user-hook.sh"))
    _add_entry(config, "post_tool_call", "/opt/tools/audit --event post_tool_call")
    _record_setup(tmp_path)

    assert unix_hermes_hook_problem(str(config), str(script), check_approvals=False) == ("", "")
    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


def test_the_notice_lists_a_copy_of_a_defenseclaw_hook_and_not_the_users_hook_beside_it(tmp_path):
    config, script, command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", str(tmp_path / "user-hook.sh"))
    _add_entry(config, "post_tool_call", command + ".off")
    _record_setup(tmp_path, {"post_tool_call": [command + ".off"]})

    note = hermes_kept_hook_note(str(tmp_path), str(config))

    assert "(events: post_tool_call)" in note
    assert "pre_tool_call" not in note


_NAMES_A_HOOK = [
    "~/.defenseclaw/hooks/hookX",
    "$HOME/.defenseclaw/hooks/hookX --event pre_tool_call",
    "bash /somewhere/else/hermes-hook.sh",
    "echo hermes-hook.sh",
    "bash /somewhere/else/hermes-hook.sh.off --event pre_tool_call",
    "sh -c \"$HOME/.defenseclaw/hooks/hookX --event pre_tool_call\"",
    "printf %s " + chr(39) + "hermes-hook.sh" + chr(39) + " >/dev/null",
    "true # hermes-hook.sh",
    "true # ~/.defenseclaw/hooks/hermes-hook.sh",
    "echo hook --connector hermes",
    "bash /opt/tools/audit.sh",
]


@pytest.mark.parametrize("command", _NAMES_A_HOOK)
def test_an_entry_the_setup_record_names_is_listed_whatever_the_command_says(tmp_path, command):
    config, _script, _command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", command)
    _record_setup(tmp_path, {"pre_tool_call": [command]})

    assert "(events: pre_tool_call)" in hermes_kept_hook_note(str(tmp_path), str(config))


@pytest.mark.parametrize("command", _NAMES_A_HOOK)
def test_a_user_hook_that_only_names_a_defenseclaw_hook_gets_no_notice(tmp_path, command):
    config, _script, _command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", command)
    _add_entry(config, "post_tool_call", command, first=False)
    _record_setup(tmp_path)

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


@pytest.mark.parametrize("command", _NAMES_A_HOOK)
def test_an_entry_gets_no_notice_when_there_is_no_setup_record(tmp_path, command):
    config, _script, _command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", command)

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


@pytest.mark.parametrize(
    "record",
    [b"", b"not json", b"[]", b"{}", b"{\"hooks\": []}", b"{\"hooks\": {\"pre_tool_call\": {\"kept\": \"x\"}}}"],
)
def test_a_setup_record_that_cannot_be_read_lists_nothing(tmp_path, record):
    config, _script, command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", command + ".off")
    (tmp_path / HERMES_HOME_RECORD_FILE).write_bytes(record)

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


def test_a_setup_record_that_is_a_link_is_not_followed(tmp_path):
    config, _script, command = _registration(tmp_path)
    _add_entry(config, "pre_tool_call", command + ".off")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _record_setup(elsewhere, {"pre_tool_call": [command + ".off"]})
    (tmp_path / HERMES_HOME_RECORD_FILE).symlink_to(elsewhere / HERMES_HOME_RECORD_FILE)

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


def test_an_entry_the_record_names_is_not_listed_once_it_is_gone_from_the_file(tmp_path):
    config, _script, command = _registration(tmp_path)
    _record_setup(tmp_path, {"pre_tool_call": [command + ".off"]})

    assert hermes_kept_hook_note(str(tmp_path), str(config)) == ""


def test_a_command_is_named_by_the_sha256_the_gateway_writes():
    assert hermes_command_hash("/opt/tools/audit --old") == "043eaf7fcdff435feeb38ee9f79e6c7e49f6125e8663f452f1d4a264ea1c7b91"
