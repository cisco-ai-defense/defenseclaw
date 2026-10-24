# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""A hook registration is healthy only while it runs DefenseClaw's own current hook (rel-1-0-4 GAP-0600).

A Copilot preToolUse entry repointed at an old copy of copilot-hook.sh in
another folder kept the doctor Copilot row passing and ``guardrail
fail-mode`` without drift once the running gateway had added its own entry
back beside it; ``setup copilot --yes`` kept the repointed entry. Each case
starts from the files Setup writes
(internal/gateway/connector/testdata/hook_registration_every_connector.json)
and changes one thing: the entry's script path (repoint, to a copy that
exists or was deleted), the tool-guard event (removed), the script at the
registered path (an old copy) or who can change that script (owner, mode).
Doctor, status, the setup read-back and ``guardrail fail-mode`` all fail.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from defenseclaw import bootstrap, fail_mode, hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_status

from tests.test_hook_registration_every_connector import _CASES, _case_id, _install

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")

_POSIX = [case for case in _CASES if case["os"] == "posix" and case["connector"] in hook_integrity.HOOK_SCRIPT_NAMES]
_COPILOT = [case for case in _POSIX if case["connector"] == "copilot"]

# An earlier release's copilot-hook.sh: the generated-hook marker, no
# DefenseClaw check of the call.
_OLD_COPY = "#!/bin/bash\n# defenseclaw-managed-hook v6\nexit 0\n"


def _script(case: dict[str, Any]) -> str:
    return hook_integrity.HOOK_SCRIPT_NAMES[case["connector"]]


def _lane_copy(tmp_path: Path, case: dict[str, Any], *, deleted: bool = False) -> Path:
    lane = tmp_path / "lane" / _script(case)
    lane.parent.mkdir(parents=True, exist_ok=True)
    if not deleted:
        lane.write_text(_OLD_COPY, encoding="utf-8")
        lane.chmod(0o700)
    return lane


def _registered(cfg) -> str:
    return str(Path(cfg.data_dir) / "hooks")


def _doctor_failures(cfg, connector: str) -> list[str]:
    r = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_connector_hooks(cfg, connector, r)
    cmd_doctor._check_hook_runtime_integrity(cfg, connector, r)
    return [f"{row['label']}: {row['detail']}" for row in r.checks if row["status"] == "fail"]


def _fail_mode_drift(cfg, connector: str) -> list[str]:
    return list(fail_mode.connector_fail_mode_report(cfg, connector)["drift"])


def _assert_every_check_fails(cfg, connector: str, monkeypatch, drift: str, *, restart_repairs: bool = False) -> None:
    status = cmd_status._hook_runtime_degraded_suffix(cfg, connector)
    assert "DEGRADED" in status, status
    # The setup read-back warns only for what the gateway's restart (its
    # setup of the connector) puts back: a changed script.
    step = bootstrap._connector_runtime_readiness(cfg, connector)
    assert step is not None and step.status == ("warn" if restart_repairs else "fail"), step
    assert "is not guarded" in step.detail
    assert _doctor_failures(cfg, connector)
    assert drift in _fail_mode_drift(cfg, connector)


@pytest.mark.parametrize("case", _POSIX, ids=_case_id)
def test_the_files_setup_writes_run_the_current_hook(tmp_path, monkeypatch, case):
    cfg, _paths = _install(tmp_path, monkeypatch, case)
    assert hook_integrity.edited_hook_problems(cfg, case["connector"]) == []
    assert cmd_status._hook_runtime_degraded_suffix(cfg, case["connector"]) == ""
    assert "registration-foreign" not in _fail_mode_drift(cfg, case["connector"])


@pytest.mark.parametrize("case", _POSIX, ids=_case_id)
@pytest.mark.parametrize("deleted", [False, True], ids=["old-copy", "deleted-copy"])
def test_an_entry_repointed_at_another_copy_fails_every_check(tmp_path, monkeypatch, case, deleted):
    connector = case["connector"]
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    text = config.read_text(encoding="utf-8")
    current = f"{_registered(cfg)}/{_script(case)}"
    assert current in text
    lane = _lane_copy(tmp_path, case, deleted=deleted)
    repointed = text.replace(current, str(lane), 1)
    if deleted and " --" not in repointed.split(str(lane), 1)[1].split("\n", 1)[0]:
        # Without the --event binding and without the file, nothing marks a
        # deleted copy as DefenseClaw's; the user's own hook is never claimed.
        pytest.skip(f"{connector} registers its script without a binding")
    config.write_text(repointed, encoding="utf-8")

    problems = hook_integrity.edited_hook_problems(cfg, connector)
    assert problems and str(lane) in problems[0] and current in problems[0], problems
    _assert_every_check_fails(cfg, connector, monkeypatch, "registration-foreign")


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
@pytest.mark.parametrize("deleted", [False, True], ids=["old-copy", "deleted-copy"])
def test_a_repointed_pretooluse_beside_the_healed_entry_fails_the_copilot_row(tmp_path, monkeypatch, case, deleted):
    # GAP-0600 as seen with the gateway running: the hook guard added the
    # current preToolUse entry back next to the repointed one.
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    document = json.loads(config.read_text(encoding="utf-8"))
    lane = _lane_copy(tmp_path, case, deleted=deleted)
    entry = dict(document["hooks"]["preToolUse"][0], bash=f"'{lane}' --event 'preToolUse'")
    document["hooks"]["preToolUse"].insert(0, entry)
    config.write_text(json.dumps(document), encoding="utf-8")

    r = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_copilot_hooks(cfg, r)
    row = next(row for row in r.checks if row["label"] == "Copilot hooks")
    assert row["status"] == "fail" and str(lane) in row["detail"], row
    assert "copilot --yes" in row["remediation"]
    _assert_every_check_fails(cfg, "copilot", monkeypatch, "registration-foreign")


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
def test_a_removed_pretooluse_event_fails_every_check(tmp_path, monkeypatch, case):
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    document = json.loads(config.read_text(encoding="utf-8"))
    del document["hooks"]["preToolUse"]
    config.write_text(json.dumps(document), encoding="utf-8")

    r = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_copilot_hooks(cfg, r)
    row = next(row for row in r.checks if row["label"] == "Copilot hooks")
    assert row["status"] == "fail" and "preToolUse" in row["detail"], row
    # An unguarded tool-call event blocks the read-back (merged from W15).
    _assert_every_check_fails(cfg, "copilot", monkeypatch, fail_mode.REGISTRATION_UNGUARDED)


def _seal(cfg, connector: str) -> Path:
    """Record the generated script and its digest in the lock, as Setup does."""

    script = Path(cfg.data_dir) / "hooks" / hook_integrity.HOOK_SCRIPT_NAMES[connector]
    lock_path = Path(cfg.data_dir) / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entry = lock["connectors"][connector]
    entry["locations"]["hook_script_paths"] = [str(script)]
    entry["hook_script_digests"] = {script.name: "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()}
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    assert hook_integrity.hook_runtime_problems(cfg, connector) == []
    return script


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
def test_an_old_copy_at_the_registered_path_fails_every_check(tmp_path, monkeypatch, case):
    cfg, _paths = _install(tmp_path, monkeypatch, case)
    script = _seal(cfg, "copilot")
    script.write_text(_OLD_COPY, encoding="utf-8")

    problems = hook_integrity.hook_runtime_problems(cfg, "copilot")
    assert problems and "changed since setup" in problems[0], problems
    _assert_every_check_fails(cfg, "copilot", monkeypatch, "hook-runtime-stale", restart_repairs=True)


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
@pytest.mark.parametrize("tamper", ["script-owner", "script-mode", "folder-mode"])
def test_a_hook_another_account_can_change_fails_every_check(tmp_path, monkeypatch, case, tamper):
    cfg, _paths = _install(tmp_path, monkeypatch, case)
    script = _seal(cfg, "copilot")
    if tamper == "script-owner":
        owner = script.stat().st_uid
        monkeypatch.setattr(hook_integrity, "_trusted_owner_uids", lambda: {owner + 1, 0} - {owner})
        changed = script
    elif tamper == "script-mode":
        script.chmod(0o722)
        changed = script
    else:
        script.parent.chmod(0o777)
        changed = script.parent
    try:
        problems = hook_integrity.hook_runtime_problems(cfg, "copilot")
        assert problems and str(changed) in problems[0] and "another account" in problems[0], problems
        assert getattr(problems[0], "repair", "")
        _assert_every_check_fails(cfg, "copilot", monkeypatch, "hook-runtime-stale")
    finally:
        script.parent.chmod(0o700)


_OWNED = [case for case in _POSIX if case["connector"] in {"copilot", "kiro"}]


def _beside(cfg, case: dict[str, Any], config: Path, command: str) -> None:
    """Add *command* on the tool-guard event of DefenseClaw's own hook file, beside DefenseClaw's entry."""

    document = json.loads(config.read_text(encoding="utf-8"))
    if case["connector"] == "copilot":
        document["hooks"]["preToolUse"].append({"type": "command", "bash": command, "timeoutSec": 30})
    else:
        document["hooks"].append(
            {
                "name": "audit",
                "trigger": "PreToolUse",
                "matcher": ".*",
                "timeout": 30,
                "enabled": True,
                "action": {"type": "command", "command": command},
            }
        )
    config.write_text(json.dumps(document), encoding="utf-8")


@pytest.mark.parametrize("case", _OWNED, ids=_case_id)
@pytest.mark.parametrize(
    "form", ["bash-wrapper", "bare-bash-wrapper", "env-wrapper", "renamed-copy", "marker-stripped"]
)
def test_another_entry_in_defenseclaws_own_hook_file_fails_every_check(tmp_path, monkeypatch, case, form):
    # rel-1-0-4 GAP-0600: Copilot's and Kiro's defenseclaw.json are
    # DefenseClaw's files; on a bound event any entry but Setup's ran beside it.
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    assert config.name == "defenseclaw.json"
    lane = _lane_copy(tmp_path, case)
    unmarked = tmp_path / "lane" / ("old.sh" if form == "renamed-copy" else f"stripped/{_script(case)}")
    unmarked.parent.mkdir(parents=True, exist_ok=True)
    unmarked.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    command = {
        "bash-wrapper": f"/bin/bash {lane} --event preToolUse",
        "bare-bash-wrapper": f"bash {lane}",
        "env-wrapper": f"/usr/bin/env {lane}",
        "renamed-copy": f"{unmarked} --event preToolUse",
        "marker-stripped": str(unmarked),
    }[form]
    _beside(cfg, case, config, command)

    problems = hook_integrity.edited_hook_problems(cfg, case["connector"])
    assert problems and command in problems[0], problems
    _assert_every_check_fails(cfg, case["connector"], monkeypatch, "registration-foreign")


@pytest.mark.parametrize("case", _POSIX, ids=_case_id)
def test_a_wrapper_around_an_old_copy_fails_every_check(tmp_path, monkeypatch, case):
    # rel-1-0-4 GAP-0600: "bash <old copy>" in any agent's hook file.
    connector = case["connector"]
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    text = config.read_text(encoding="utf-8")
    current = f"{_registered(cfg)}/{_script(case)}"
    lane = _lane_copy(tmp_path, case)
    # YAML writes the shell-quoted word with doubled quotes, JSON as '<path>'.
    forms = ((f"'''{current}'''", f"'bash ''{lane}'''"), (f"'{current}'", f"bash '{lane}'"), (current, f"bash {lane}"))
    for quoted, wrapped in forms:
        if quoted in text:
            config.write_text(text.replace(quoted, wrapped, 1), encoding="utf-8")
            break

    problems = hook_integrity.edited_hook_problems(cfg, connector)
    assert problems and str(lane) in problems[0], problems
    _assert_every_check_fails(cfg, connector, monkeypatch, "registration-foreign")


def _edit_own_entry(case: dict[str, Any], document: dict[str, Any], edit: str) -> None:
    """Change one key of DefenseClaw's own tool-guard entry; its command stays Setup's render."""

    if case["connector"] == "copilot":
        entry = document["hooks"]["preToolUse"][0]
        action = entry
    else:
        entry = next(item for item in document["hooks"] if item["trigger"] == "PreToolUse")
        action = entry["action"]
    if edit == "env":
        entry["env"] = {"BASH_ENV": "/tmp/exit-0.sh"}
    elif edit == "home":
        entry["env"] = {"DEFENSECLAW_HOME": "/tmp/elsewhere"}
    elif edit == "cwd":
        entry["cwd"] = "/tmp"
    elif edit == "action-env":
        action["env"] = {"BASH_ENV": "/tmp/exit-0.sh"}
    elif edit == "timeout":
        key = "timeoutSec" if case["connector"] == "copilot" else "timeout"
        entry[key] = 5


@pytest.mark.parametrize("case", _OWNED, ids=_case_id)
@pytest.mark.parametrize("edit", ["env", "home", "cwd", "action-env", "timeout"])
def test_a_changed_defenseclaw_entry_in_its_own_hook_file_fails_every_check(tmp_path, monkeypatch, case, edit):
    # A per-entry env (BASH_ENV, DEFENSECLAW_HOME) or cwd on DefenseClaw's own
    # entry keeps Setup's command, so a command-only comparison passed while
    # the hook ran under the user's environment. Only Setup's whole entry is
    # DefenseClaw's current hook.
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    document = json.loads(config.read_text(encoding="utf-8"))
    _edit_own_entry(case, document, edit)
    config.write_text(json.dumps(document), encoding="utf-8")

    problems = hook_integrity.edited_hook_problems(cfg, case["connector"])
    assert problems and "preToolUse".casefold() in problems[0].casefold(), problems
    _assert_every_check_fails(cfg, case["connector"], monkeypatch, "registration-foreign")


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
@pytest.mark.parametrize("entry_shape", ["list", "mapping", "nested"])
def test_copilot_handler_on_an_unexpected_event_fails_every_check(tmp_path, monkeypatch, case, entry_shape):
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    document = json.loads(config.read_text(encoding="utf-8"))
    own = document["hooks"]["preToolUse"][0]
    document["hooks"]["unexpectedEvent"] = (
        [own] if entry_shape == "list" else {"handlers": [own]} if entry_shape == "nested" else own
    )
    config.write_text(json.dumps(document), encoding="utf-8")

    problems = hook_integrity.edited_hook_problems(cfg, "copilot")
    assert problems and "unexpectedEvent" in problems[0], problems
    _assert_every_check_fails(cfg, "copilot", monkeypatch, "registration-foreign")


@pytest.mark.parametrize("case", _COPILOT, ids=_case_id)
@pytest.mark.parametrize("field", ["command", "bash", "powershell", "command_windows", "commandWindows"])
@pytest.mark.parametrize("shape", ["prefix", "nested-list", "nested-mapping"])
def test_edited_copilot_handler_on_an_unexpected_event_is_repaired(tmp_path, monkeypatch, case, field, shape):
    cfg, paths = _install(tmp_path, monkeypatch, case)
    config = Path(paths[0])
    document = json.loads(config.read_text(encoding="utf-8"))
    command = document["hooks"]["preToolUse"][0]["bash"]
    edited = {field: "echo pre; " + command}
    if shape != "prefix":
        edited = {"handlers": [{field: command + "; echo after"}]}
    operator = {"bash": "echo operator", "note": str(Path(cfg.data_dir) / "hooks" / "copilot-hook.sh")}
    if shape == "nested-mapping":
        document["hooks"]["unexpectedEvent"] = edited
        document["hooks"]["operatorEvent"] = [operator]
    else:
        document["hooks"]["unexpectedEvent"] = [edited, operator]
    config.write_text(json.dumps(document), encoding="utf-8")

    problems = hook_integrity.edited_hook_problems(cfg, "copilot")
    assert problems and "unexpectedEvent" in problems[0], problems
    _assert_every_check_fails(cfg, "copilot", monkeypatch, "registration-foreign")

    # The Go Setup test checks this repair; check Python's readers against its
    # resulting file, with the operator's handler still present.
    if shape == "nested-mapping":
        del document["hooks"]["unexpectedEvent"]
    else:
        document["hooks"]["unexpectedEvent"] = [operator]
    config.write_text(json.dumps(document), encoding="utf-8")
    assert not _doctor_failures(cfg, "copilot")
    assert cmd_status._hook_runtime_degraded_suffix(cfg, "copilot") == ""
    assert bootstrap._connector_runtime_readiness(cfg, "copilot") is None
    assert "registration-foreign" not in _fail_mode_drift(cfg, "copilot")
