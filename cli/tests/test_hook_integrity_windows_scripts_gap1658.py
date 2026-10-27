"""GAP-1658: on Windows an edited generated hook file (the .ps1 adapters too)
fails the Hook runtime files row, so doctor --fix re-renders it."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from defenseclaw import hook_integrity
from defenseclaw.commands.cmd_doctor import _check_hook_runtime_integrity, _DoctorResult


def _install(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    adapter = hooks / "copilot-hook.ps1"
    adapter.write_bytes(b"param()\r\n& $launcher hook --connector copilot\r\n")
    script = hooks / "copilot-hook.sh"
    script.write_bytes(b"#!/bin/sh\nexit 2\n")
    digests = {p.name: "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() for p in (adapter, script)}
    lock = {
        "version": 2,
        "connectors": {
            "copilot": {
                "locations": {"hook_script_paths": [str(adapter), str(script)]},
                "hook_script_digests": digests,
            }
        },
    }
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    return SimpleNamespace(data_dir=str(tmp_path), deployment_mode=""), adapter


def test_windows_edited_adapter_fails_hook_runtime_files(tmp_path, monkeypatch):
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    cfg, adapter = _install(tmp_path)
    assert hook_integrity.hook_runtime_problems(cfg, "copilot") == []

    adapter.write_bytes(adapter.read_bytes() + b"exit 0\r\n")
    problems = hook_integrity.hook_runtime_problems(cfg, "copilot")
    assert len(problems) == 1 and "changed since setup" in problems[0] and "copilot-hook.ps1" in problems[0]

    r = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "copilot", r)
    row = next(row for row in r.checks if row.get("label") == "Hook runtime files")
    assert row["status"] == "fail" and "doctor --fix" in row["detail"]


def test_windows_missing_token_and_mode_are_not_reported(tmp_path, monkeypatch):
    # The POSIX owner, mode and token checks do not apply to Windows hooks.
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    cfg, _ = _install(tmp_path)
    (tmp_path / "hooks" / "copilot-hook.sh").chmod(0o600)
    assert hook_integrity.hook_runtime_problems(cfg, "copilot") == []


def test_windows_unreadable_adapter_is_not_reported_as_edited(tmp_path, monkeypatch):
    """GAP-1942: a hook file Defender holds or a deny ACE hides read as "changed
    since setup (an edit ...)"; it is "cannot be read", as on POSIX (GAP-0403)."""
    from defenseclaw import fail_mode

    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    cfg, _ = _install(tmp_path)
    monkeypatch.setattr(fail_mode, "_sha256_regular_file", lambda _path: "")
    monkeypatch.setattr(hook_integrity, "_opens_for_read", lambda _path: False)
    problems = hook_integrity.hook_runtime_problems(cfg, "copilot")
    assert len(problems) == 1 and "cannot be read" in problems[0] and "changed since setup" not in problems[0], problems


def test_windows_link_in_place_of_adapter_is_drift_that_doctor_fix_renders(tmp_path, monkeypatch):
    """GAP-2022: a symlink in place of copilot-hook.ps1 (no regular file to digest)
    read as "cannot be read", so doctor --fix skipped it. It is drift."""
    from defenseclaw.commands import cmd_doctor

    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    cfg, adapter = _install(tmp_path)
    other = tmp_path / "other.ps1"
    other.write_bytes(b"exit 0\\r\\n")
    adapter.unlink()
    adapter.symlink_to(other)
    problems = hook_integrity.hook_runtime_problems(cfg, "copilot")
    assert len(problems) == 1 and "changed since setup" in problems[0], problems
    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda _cfg: ["copilot"])
    assert cmd_doctor._drifted_hook_connectors(cfg) == ["copilot"]


def test_windows_oversized_adapter_is_drift_not_unreadable(tmp_path, monkeypatch):
    """GAP-2022: a readable file the digest helper refuses (oversized, or changed
    during the read) is drift, not "cannot be read"."""
    from defenseclaw import fail_mode

    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    cfg, _ = _install(tmp_path)
    monkeypatch.setattr(fail_mode, "_sha256_regular_file", lambda _path: "")
    monkeypatch.setattr(hook_integrity, "_opens_for_read", lambda _path: True)
    problems = hook_integrity.hook_runtime_problems(cfg, "copilot")
    assert len(problems) == 1 and "changed since setup" in problems[0], problems
