"""GAP-0015: doctor's Hermes host probe when ps cannot list processes."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from defenseclaw.commands import cmd_doctor


def _proc(root: Path, pid: str, uid: str, argv: list[str]) -> None:
    d = root / pid
    d.mkdir(parents=True)
    (d / "status").write_text(f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")


def _failing_ps(*_args, **_kwargs):
    return subprocess.CompletedProcess(args=["ps"], returncode=1, stdout="", stderr="Unable to get system boot time")


@pytest.mark.skipif(os.name == "nt", reason="Unix /proc probe")
def test_a_failing_ps_falls_back_to_this_accounts_proc_entries(tmp_path, monkeypatch):
    uid = str(os.getuid())
    _proc(tmp_path, str(os.getpid()), uid, ["python3", "-m", "defenseclaw"])
    _proc(tmp_path, "4242", uid, ["/bin/bash", "-l"])
    _proc(tmp_path, "4343", str(int(uid) + 1), ["hermes"])  # another account's host does not count
    monkeypatch.setattr(cmd_doctor.subprocess, "run", _failing_ps)
    monkeypatch.setattr(
        cmd_doctor,
        "_hermes_host_running_from_proc",
        lambda root=str(tmp_path), f=cmd_doctor._hermes_host_running_from_proc: f(root),
    )
    assert cmd_doctor._hermes_host_running() is False
    _proc(tmp_path, "4444", uid, ["/home/u/.local/bin/hermes", "chat"])
    assert cmd_doctor._hermes_host_running() is True


@pytest.mark.skipif(os.name == "nt", reason="Unix /proc probe")
def test_an_unreadable_or_foreign_proc_stays_unknown(tmp_path):
    assert cmd_doctor._hermes_host_running_from_proc(str(tmp_path / "missing")) is None
    _proc(tmp_path, "4242", str(os.getuid()), ["/bin/bash"])
    # This process is not in the listing: that /proc is not this namespace's.
    assert cmd_doctor._hermes_host_running_from_proc(str(tmp_path)) is None
