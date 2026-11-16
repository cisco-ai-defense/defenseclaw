"""Unix Hermes doctor must check the hook registration Hermes executes."""

import json
import os
from pathlib import Path

import pytest
import yaml
from defenseclaw.doctor_hooks import _HERMES_REQUIRED_HOOKS, unix_hermes_hook_problem

# unix_hermes_hook_problem serves Linux and macOS only: doctor sends a Windows
# Hermes registration to _check_windows_native_hooks (GAP-2321). It parses the
# command with POSIX shlex, which a Windows path does not survive.
pytestmark = pytest.mark.skipif(os.name == "nt", reason="Unix Hermes hook matrix; Windows uses the native hook check")


def test_unix_hermes_doctor_rejects_skipped_or_unusable_hooks(tmp_path: Path) -> None:
    script = tmp_path / "hooks" / "hermes-hook.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    config = tmp_path / "config.yaml"
    allowlist = tmp_path / "shell-hooks-allowlist.json"
    command = str(script)
    hooks = {
        event: [{"command": command, "timeout": 30, **({"matcher": matcher} if matcher is not None else {})}]
        for event, matcher in _HERMES_REQUIRED_HOOKS.items()
    }
    allowlist.write_text(
        json.dumps({"approvals": [{"event": event, "command": command} for event in hooks]}),
        encoding="utf-8",
    )

    def check() -> tuple[str, str]:
        config.write_text(yaml.safe_dump({"hooks": hooks}), encoding="utf-8")
        return unix_hermes_hook_problem(str(config), str(script))

    assert check() == ("", "")
    for field, value in [
        ("matcher", "terminal"),
        ("timeout", 1),
        ("command", "/tmp/other/hermes-hook.sh"),
    ]:
        original = hooks["pre_tool_call"][0].copy()
        hooks["pre_tool_call"][0][field] = value
        state, problem = check()
        assert state == "stale", (field, state, problem)
        assert field in problem or field == "command"
        hooks["pre_tool_call"][0] = original
    del hooks["pre_tool_call"]
    assert check()[0] == "missing"


def test_unix_hermes_doctor_requires_exact_approval_pair(tmp_path: Path) -> None:
    script = tmp_path / "hermes-hook.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "hooks": {
                    event: [{"command": str(script), "timeout": 30, **({"matcher": matcher} if matcher else {})}]
                    for event, matcher in _HERMES_REQUIRED_HOOKS.items()
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "shell-hooks-allowlist.json").write_text('{"approvals":[]}', encoding="utf-8")
    state, problem = unix_hermes_hook_problem(str(config), str(script))
    assert state == "stale"
    assert "approval" in problem
