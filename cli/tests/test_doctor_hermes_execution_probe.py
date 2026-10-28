# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Hermes health requires a runnable command read from the agent registration."""

import contextlib
import hashlib
import json
import os
import shutil
import sys
import time
import tracemalloc
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from defenseclaw import fail_mode
from defenseclaw.commands import cmd_doctor
from defenseclaw.doctor_hooks import _HERMES_REQUIRED_HOOKS, WindowsHookCheck

# What the gateway seals for Hermes on Unix, in its order: the shared
# inspect-*.sh runtime, Hermes' own script and the _hardening.sh it sources
# (connector.hookRuntimeArtifactPaths). Go pins the same list in
# TestHookContractLockSealsEachConnectorScriptBesideTheSharedRuntime; change
# both together. A lock naming hermes-hook.sh alone is not what any release
# writes, so every check below reads the real layout (GAP-0833).
_GATEWAY_HERMES_LOCKED_SCRIPTS = (
    "inspect-tool.sh",
    "inspect-request.sh",
    "inspect-response.sh",
    "inspect-tool-response.sh",
    "hermes-hook.sh",
    "_hardening.sh",
)


def _registered_unix_hermes(tmp_path, monkeypatch):
    """Register a sealed Unix Hermes hook; return it and a reseal-and-check call."""
    data_dir = tmp_path / "dc"
    hooks_dir = data_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    script = hooks_dir / "hermes-hook.sh"
    script.write_text("#!/bin/sh\nprintf 'defenseclaw-execution-probe-ok\\n'\n", encoding="utf-8")
    script.chmod(0o700)
    command = "'" + str(script) + "'"
    config = tmp_path / "hermes" / "config.yaml"
    config.parent.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(config.parent))
    hooks = {
        event: [{"command": command, "timeout": 30, **({"matcher": matcher} if matcher else {})}]
        for event, matcher in _HERMES_REQUIRED_HOOKS.items()
    }
    config.write_text(yaml.safe_dump({"hooks": hooks, "hooks_auto_accept": False}), encoding="utf-8")
    allowlist = config.with_name("shell-hooks-allowlist.json")
    allowlist.write_text(json.dumps({"approvals": [
        {"event": event, "command": command, "defenseclaw_managed": True}
        for event in _HERMES_REQUIRED_HOOKS
    ]}), encoding="utf-8")
    lock_path = data_dir / "hook_contract_lock.json"

    def seal():
        lock_path.write_text(json.dumps({"connectors": {"hermes": {"hook_script_digests": {
            "hermes-hook.sh": "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest(),
        }, "locations": {
            "hook_config_paths": [str(config)],
            "hook_script_paths": [str(hooks_dir / name) for name in _GATEWAY_HERMES_LOCKED_SCRIPTS],
        }}}}), encoding="utf-8")

    seal()
    cfg = SimpleNamespace(data_dir=str(data_dir))
    monkeypatch.setattr(cmd_doctor, "_hermes_host_running", lambda: False)

    def check(*, reseal: bool = True):
        if reseal:
            seal()
        result = cmd_doctor._DoctorResult()
        cmd_doctor._check_hook_health(cfg, "hermes", result)
        return result.checks[-1]

    return script, check


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_uses_current_home_after_move(tmp_path, monkeypatch):
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    assert check()["status"] == "pass"
    new_home = tmp_path / "new-hermes-home"
    new_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(new_home))
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert str(new_home / "config.yaml") in row["detail"]


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_rejects_old_lock_path_with_valid_new_home(tmp_path, monkeypatch):
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    old_home = tmp_path / "hermes"
    new_home = tmp_path / "new-hermes-home"
    new_home.mkdir()
    for name in ("config.yaml", "shell-hooks-allowlist.json"):
        (new_home / name).write_bytes((old_home / name).read_bytes())
    monkeypatch.setenv("HERMES_HOME", str(new_home))
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "lock" in row["detail"]


def test_windows_hermes_doctor_rejects_old_lock_path_before_runtime_check(tmp_path, monkeypatch):
    _script, _check = _registered_unix_hermes(tmp_path, monkeypatch)
    new_home = tmp_path / "new-hermes-home"
    new_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(new_home))
    monkeypatch.setattr(cmd_doctor, "hermes_profile_unsupported_reason", lambda _path: None)
    called = []
    monkeypatch.setattr(cmd_doctor, "_check_windows_native_hooks", lambda *_args, **_kwargs: called.append(True))
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_hermes_hooks(SimpleNamespace(data_dir=str(tmp_path / "dc")), result, platform_name="nt")
    assert result.checks[-1]["status"] == "fail"
    assert str(new_home / "config.yaml") in result.checks[-1]["detail"]
    assert not called


def test_windows_hermes_fail_mode_rejects_old_lock_path(tmp_path, monkeypatch):
    from defenseclaw import doctor_hooks

    current = str(tmp_path / "new-home" / "config.yaml")
    old = str(tmp_path / "old-home" / "config.yaml")
    monkeypatch.setattr(fail_mode, "_is_windows", lambda: True)
    monkeypatch.setattr(fail_mode, "hermes_config_path", lambda: current)
    monkeypatch.setattr(fail_mode, "_registration_hook_config_paths", lambda *_args: (old,))
    calls = []
    monkeypatch.setattr(doctor_hooks, "validate_windows_hook_registration", lambda **_kwargs: calls.append(True))
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))
    assert fail_mode._native_deny_registration_freshness(cfg, "hermes") == "registration-config-binding-stale"
    assert not calls


def _rewrite_locked_scripts(tmp_path, paths):
    lock_path = tmp_path / "dc" / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["connectors"]["hermes"]["locations"]["hook_script_paths"] = paths
    lock_path.write_text(json.dumps(lock), encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_and_fail_mode_accept_the_lock_the_gateway_writes(tmp_path, monkeypatch):
    """GAP-0833: every setup and upgrade sealed this layout and doctor failed it."""
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    row = check()
    assert row["status"] == "pass", row
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))
    assert fail_mode._unix_registration_freshness(cfg, "hermes") is None


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
@pytest.mark.parametrize("case", ["missing", "other-install", "also-other-install", "twice", "dotdot"])
def test_hermes_doctor_probes_only_one_hook_sealed_at_this_install(tmp_path, monkeypatch, case):
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    assert check()["status"] == "pass"
    hooks = script.parent
    shared = [str(hooks / name) for name in _GATEWAY_HERMES_LOCKED_SCRIPTS if name != script.name]
    other = tmp_path / "old-dc" / "hooks" / script.name
    other.parent.mkdir(parents=True)
    other.write_bytes(script.read_bytes())
    other.chmod(0o700)
    paths = {
        "missing": shared,
        "other-install": [*shared, str(other)],
        "also-other-install": [*shared, str(script), str(other)],
        "twice": [*shared, str(script), str(script)],
        "dotdot": [*shared, str(hooks / ".." / "hooks" / script.name)],
    }[case]
    _rewrite_locked_scripts(tmp_path, paths)
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "no exact sealed hook script" in row["detail"]
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))
    assert fail_mode._unix_registration_freshness(cfg, "hermes") == "registration-command-stale"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_upgrade_from_1_0_2_layout_passes_once_the_gateway_reseals(tmp_path, monkeypatch):
    """A 1.0.2 per-user install upgraded in place (GAP-0833).

    1.0.2 registered the same command and approvals and sealed the same lock
    layout (a v1 lock: digests in the entry). Its hook has no execution-probe
    branch, so until the new gateway renders and reseals it, doctor fails and
    names the probe, not a lock-shape mismatch. After the reseal (a v2 lock
    with the shared digests at the root) doctor passes and fail-mode reports
    no stale registration.
    """
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    hooks = script.parent
    lock_path = tmp_path / "dc" / "hook_contract_lock.json"
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))

    def digest(path):
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def write_lock(version, hook_body):
        for name in _GATEWAY_HERMES_LOCKED_SCRIPTS:
            if name != script.name:
                (hooks / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.write_text(hook_body, encoding="utf-8")
        script.chmod(0o700)
        everything = {name: digest(hooks / name) for name in _GATEWAY_HERMES_LOCKED_SCRIPTS}
        entry = {
            "hook_script_digests": everything if version == 1 else {script.name: everything[script.name]},
            "locations": {
                "hook_config_paths": [str(tmp_path / "hermes" / "config.yaml")],
                "hook_script_paths": [str(hooks / name) for name in _GATEWAY_HERMES_LOCKED_SCRIPTS],
            },
        }
        lock = {"connectors": {"hermes": entry}}
        if version == 2:
            lock["version"] = 2
            lock["shared_hook_script_digests"] = {
                name: value for name, value in everything.items() if name != script.name
            }
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

    # As found after the binary swap: 1.0.2's hook and lock.
    write_lock(1, "#!/bin/sh\n# defenseclaw-managed-hook v5\nexit 0\n")
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "execution probe failed" in row["detail"]
    assert fail_mode._unix_registration_freshness(cfg, "hermes") == "registration-command-stale"

    # The new gateway's Setup renders the hook and reseals the lock.
    write_lock(2, "#!/bin/sh\n# defenseclaw-managed-hook v6\n" + _PROOF)
    row = check(reseal=False)
    assert row["status"] == "pass", row
    assert fail_mode._unix_registration_freshness(cfg, "hermes") is None


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_requires_approval_for_every_event(tmp_path, monkeypatch):
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    assert check()["status"] == "pass"
    allowlist = tmp_path / "hermes" / "shell-hooks-allowlist.json"
    document = json.loads(allowlist.read_text(encoding="utf-8"))
    document["approvals"] = document["approvals"][1:]
    allowlist.write_text(json.dumps(document), encoding="utf-8")
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "approval" in row["detail"]


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_fails_for_malformed_approval_and_lock(tmp_path, monkeypatch):
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    allowlist = tmp_path / "hermes" / "shell-hooks-allowlist.json"
    allowlist.write_text(json.dumps({"approvals": [{"event": ["pre_tool_call"], "command": "hook"}]}), encoding="utf-8")
    assert check(reseal=False)["status"] == "fail"
    lock_path = tmp_path / "dc" / "hook_contract_lock.json"
    lock_path.write_text("[]", encoding="utf-8")
    assert check(reseal=False)["status"] == "fail"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_rejects_lock_with_hidden_invalid_path(tmp_path, monkeypatch):
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    lock_path = tmp_path / "dc" / "hook_contract_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["connectors"]["hermes"]["locations"]["hook_config_paths"].append(None)
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "lock" in row["detail"]
    assert fail_mode._registration_hook_config_paths(SimpleNamespace(data_dir=str(tmp_path / "dc")), "hermes") == ()


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_names_setup_for_missing_current_registration(tmp_path, monkeypatch):
    _script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    (tmp_path / "hermes" / "config.yaml").unlink()
    row = check(reseal=False)
    assert row["status"] == "fail"
    assert "active hook registration is missing" in row["detail"]
    assert "setup hermes --yes --restart" in row["remediation"]


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_fail_mode_rejects_stale_open_command(tmp_path, monkeypatch):
    script, _check = _registered_unix_hermes(tmp_path, monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    stale = script.with_name(script.name + ".old")
    stale.write_text("#!/bin/sh\nFAIL_MODE=\"open\"\n", encoding="utf-8")
    stale.chmod(0o700)
    config = tmp_path / "hermes" / "config.yaml"
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    for entries in document["hooks"].values():
        entries[0]["command"] = "'" + str(stale) + "'"
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))
    assert fail_mode._unix_registration_freshness(cfg, "hermes") == "registration-command-stale"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_fail_mode_rejects_unresolvable_current_home(tmp_path, monkeypatch):
    def unresolvable_home():
        raise ValueError("bad home")

    monkeypatch.setattr(fail_mode, "hermes_config_path", unresolvable_home)
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))
    assert fail_mode._unix_registration_freshness(cfg, "hermes") == "registration-config-binding-stale"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_requires_registered_executable_probe(tmp_path, monkeypatch):
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    assert check()["status"] == "pass"
    script.chmod(0o600)
    row = check(reseal=False)
    assert row["status"] == "fail", row
    assert "executable" in row["detail"]
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    row = check()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]
    script.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    script.chmod(0o700)
    row = check()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]


@pytest.mark.skipif(os.name == "nt", reason="Unix stub for the Windows probe helper")
def test_windows_hermes_probe_requires_active_runtime_response(tmp_path):
    target = tmp_path / "hook"
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o700)
    assert not cmd_doctor._hermes_windows_execution_probe(check).healthy
    target.write_text("#!/bin/sh\nprintf 'defenseclaw-execution-probe-ok\\n'\n", encoding="utf-8")
    assert cmd_doctor._hermes_windows_execution_probe(check).healthy


_PROOF = "printf 'defenseclaw-execution-probe-ok\\n'\n"
_OVERSIZED_OUTPUTS = {
    "proof-then-64MiB": _PROOF + "head -c 67108864 /dev/zero\n",
    "64MiB-then-proof": "set -e\nhead -c 67108864 /dev/zero\n" + _PROOF,
    "endless-stream": _PROOF + "exec yes\n",
}


def _probe_stub(tmp_path, body: str):
    target = tmp_path / "hook"
    target.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    target.chmod(0o700)
    return target


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
@pytest.mark.parametrize("body", list(_OVERSIZED_OUTPUTS.values()), ids=list(_OVERSIZED_OUTPUTS))
def test_hermes_execution_probe_caps_captured_output(tmp_path, monkeypatch, body):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", 20.0)
    target = _probe_stub(tmp_path, body)
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    tracemalloc.start()
    start = time.monotonic()
    try:
        healthy = cmd_doctor._hermes_windows_execution_probe(check).healthy
        returncode, stdout = cmd_doctor._run_hermes_execution_probe([str(target)])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert not healthy
    assert returncode is None
    assert len(stdout) <= len(b"defenseclaw-execution-probe-ok\n")
    assert peak < 4 << 20, f"Doctor kept {peak} bytes of probe output"
    assert time.monotonic() - start < 10, "an output overflow must end the probe before its timeout"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
def test_hermes_unix_doctor_probe_caps_registered_hook_output(tmp_path, monkeypatch):
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    script.write_text("#!/bin/sh\n" + _OVERSIZED_OUTPUTS["proof-then-64MiB"], encoding="utf-8")
    script.chmod(0o700)
    tracemalloc.start()
    try:
        row = check()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert row["status"] == "fail", row
    assert "probe" in row["detail"]
    assert peak < 16 << 20, f"Doctor kept {peak} bytes of probe output"


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
@pytest.mark.parametrize(
    ("body", "timeout", "proved"),
    [
        (_PROOF + "sleep 20 &\nexit 0\n", 20.0, None),
        ("sleep 20 &\nsleep 20\n", 0.3, False),
        ("trap '' TERM\n" + _PROOF + "sleep 20 &\nsleep 20\n", 0.3, False),
    ],
    ids=["exits-descendant-holds-stdout", "hangs-descendant-holds-stdout", "hangs-after-proof"],
)
def test_hermes_execution_probe_bounds_inherited_stdout(tmp_path, monkeypatch, body, timeout, proved):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target = _probe_stub(tmp_path, body)
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    start = time.monotonic()
    healthy = cmd_doctor._hermes_windows_execution_probe(check).healthy
    assert time.monotonic() - start < 2, "the probe waited on stdout a descendant inherited"
    if proved is not None:
        assert healthy is proved


# r104 W5b: a probed launcher that exits after the proof must not leave what
# it started running, one more for each Doctor run.
def _process_gone(pid: int, wait: float = 3.0) -> bool:
    deadline = time.monotonic() + wait
    while True:
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            if not handle:
                return True
            try:
                remaining = max(0, int((deadline - time.monotonic()) * 1000))
                return kernel32.WaitForSingleObject(handle, remaining) == 0
            finally:
                kernel32.CloseHandle(handle)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
                if stat.read().rsplit(")", 1)[1].split()[0] == "Z":
                    return True
        except (OSError, IndexError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _kill_quietly(pid: int) -> None:
    import signal

    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


def _read_pid(path) -> int:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, ValueError):
            return int(path.read_text(encoding="utf-8").strip())
        time.sleep(0.02)
    raise AssertionError(f"probe never wrote {path}")


# The child writes its pid as the test sees it ($! counts in the probe's PID
# namespace on Linux), then runs as sleep.
_CHILD = '( read -r p _ < /proc/self/stat; echo $p > "$PIDFILE"; exec sleep 60 )'
_WAIT_CHILD = 'while [ ! -s "$PIDFILE" ]; do sleep 0.01; done\n'
_DESCENDANT_CASES = {
    # body, timeout: what the hook leaves behind and how the probe ends
    "exits-child-holds-stdout": (_PROOF + _CHILD + " &\n" + _WAIT_CHILD + "exit 0\n", 20.0),
    "exits-child-detached-from-stdout": (_PROOF + _CHILD + " >/dev/null 2>&1 &\n" + _WAIT_CHILD + "exit 0\n", 20.0),
    "exits-grandchild": (_PROOF + "( " + _CHILD + " & )\n" + _WAIT_CHILD + "exit 0\n", 20.0),
    "times-out": (_CHILD + " &\nwait\n", 0.5),
    "overflows": (_PROOF + _CHILD + " &\n" + _WAIT_CHILD + "exec yes\n", 20.0),
}


def _descendant_stub(tmp_path, body: str):
    pid_file = tmp_path / "descendant.pid"
    target = _probe_stub(tmp_path, f"PIDFILE='{pid_file}'\n" + body)
    return target, pid_file


@pytest.mark.skipif(os.name == "nt", reason="Unix shell stub")
@pytest.mark.parametrize("case", list(_DESCENDANT_CASES), ids=list(_DESCENDANT_CASES))
def test_hermes_execution_probe_ends_what_the_hook_started(tmp_path, monkeypatch, case):
    body, timeout = _DESCENDANT_CASES[case]
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target, pid_file = _descendant_stub(tmp_path, body)
    cmd_doctor._run_hermes_execution_probe([str(target)])
    if not _LINUX:
        try:
            assert not pid_file.exists(), "forkless probe started a descendant"
        finally:
            if pid_file.exists():
                _kill_quietly(_read_pid(pid_file))
        return
    descendant = _read_pid(pid_file)
    try:
        assert _process_gone(descendant), f"probe left descendant {descendant} running"
    finally:
        _kill_quietly(descendant)


class _ProxyModule(types.ModuleType):
    """``base`` with some attributes replaced, for one module's view only."""

    def __init__(self, base, **overrides):
        super().__init__(base.__name__)
        self._base = base
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._base, name)


class _EmulatedWindowsJob:
    """A kill-on-close job emulated by the probe's own POSIX session."""

    def __init__(self, pid: int, *, allow_breakaway: bool = True, fail: str = "") -> None:
        if fail == "create":
            raise OSError("CreateJobObjectW failed")
        self.pid = pid
        self.allow_breakaway = allow_breakaway
        self.fail = fail
        self.terminated = 0
        self.closed = False

    def terminate_sync(self, *, exit_code: int = 130, timeout: float = 2.0) -> bool:
        self.terminated += 1
        if self.fail == "terminate":
            raise OSError("TerminateJobObject failed")
        if self.fail == "stall":
            return False
        import signal

        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.pid, signal.SIGKILL)
        return self.fail != "linger"

    def close(self) -> None:
        if self.fail == "stall":
            _kill_quietly(self.pid)
        self.closed = True


@pytest.mark.skipif(os.name == "nt", reason="emulates an unresponsive Windows job on POSIX")
def test_windows_hermes_probe_has_hard_deadline_if_job_cannot_end(tmp_path, monkeypatch):
    target = _probe_stub(tmp_path, "exec sleep 60\n")
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", 0.2)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TREE_REAP", 0.2)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.2)
    _launches, jobs = _emulate_windows_probe(monkeypatch, fail="stall")
    start = time.monotonic()
    returncode, _stdout = cmd_doctor._run_hermes_execution_probe([str(target)])
    assert returncode is None
    assert time.monotonic() - start < 2.0
    assert jobs[0].closed


def _emulate_windows_probe(monkeypatch, *, fail: str = ""):
    """Run the probe's Windows branch on POSIX; return the Popen kwargs and jobs."""
    import subprocess

    real_popen = subprocess.Popen
    launches: list[dict] = []
    jobs: list[_EmulatedWindowsJob] = []

    def popen(argv, **kwargs):
        launches.append(dict(kwargs))
        return real_popen(
            argv, stdin=kwargs["stdin"], stdout=kwargs["stdout"], stderr=kwargs["stderr"], start_new_session=True,
        )

    def job(pid, *, allow_breakaway=True):
        created = _EmulatedWindowsJob(pid, allow_breakaway=allow_breakaway, fail=fail)
        jobs.append(created)
        return created

    monkeypatch.setattr(cmd_doctor, "os", _ProxyModule(os, name="nt"))
    monkeypatch.setattr(cmd_doctor, "subprocess", _ProxyModule(subprocess, Popen=popen))
    monkeypatch.setattr("defenseclaw.tui.windows_process.WindowsJob", job)
    return launches, jobs


@pytest.mark.skipif(os.name == "nt", reason="emulates the Windows branch on a POSIX shell stub")
@pytest.mark.parametrize("case", list(_DESCENDANT_CASES), ids=list(_DESCENDANT_CASES))
def test_windows_hermes_doctor_probe_ends_its_job(tmp_path, monkeypatch, case):
    body, timeout = _DESCENDANT_CASES[case]
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target, pid_file = _descendant_stub(tmp_path, body)
    launches, jobs = _emulate_windows_probe(monkeypatch)
    check = WindowsHookCheck("healthy", "registered", '"hook" hook --connector hermes', str(target))
    healthy = cmd_doctor._hermes_windows_execution_probe(check).healthy
    descendant = _read_pid(pid_file)
    try:
        assert _process_gone(descendant), f"Windows Doctor probe left descendant {descendant} running"
    finally:
        _kill_quietly(descendant)
    assert healthy is case.startswith("exits"), case
    (launch,) = launches
    assert launch["creationflags"] & 0x00000004, "the launcher must start suspended, before the job owns it"
    assert launch["creationflags"] & 0x08000000, "the probe must not open a console window"
    (job,) = jobs
    assert job.allow_breakaway is False
    assert job.terminated >= 1
    assert job.closed


@pytest.mark.skipif(os.name == "nt", reason="emulates the Windows branch on a POSIX shell stub")
@pytest.mark.parametrize("fail", ["create", "terminate", "linger"])
def test_windows_hermes_doctor_probe_fails_closed_without_job_cleanup(tmp_path, monkeypatch, fail):
    # The hard deadline, not the probe's own bound, ends this run.
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", 3.0)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    root_pid_file = tmp_path / "root.pid"
    target = _probe_stub(tmp_path, f"echo $$ > '{root_pid_file}'\n" + _PROOF + "exec sleep 60\n")
    _emulate_windows_probe(monkeypatch, fail=fail)
    start = time.monotonic()
    returncode, _ = cmd_doctor._run_hermes_execution_probe([str(target)])
    assert returncode is None, "a probe whose job could not be ended must not pass"
    assert time.monotonic() - start < 10
    if root_pid_file.exists():
        root = _read_pid(root_pid_file)
        try:
            assert _process_gone(root), f"uncontained probe root {root} still runs"
        finally:
            _kill_quietly(root)


@pytest.mark.skipif(os.name != "nt", reason="real Windows Job Object")
def test_windows_hermes_doctor_probe_ends_child_of_exited_launcher(tmp_path):
    import sys

    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess, sys\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        # Raw bytes, as the hook executable writes them: text-mode stdout on
        # Windows would end the line with CRLF, one byte past the bounded proof.
        "sys.stdout.buffer.write(b'defenseclaw-execution-probe-ok\\n')\n"
    )
    returncode, stdout = cmd_doctor._run_hermes_execution_probe([sys.executable, "-c", code])
    child = _read_pid(pid_file)
    assert _process_gone(child), f"Windows Doctor probe left child {child} running"
    assert returncode == 0
    assert stdout == b"defenseclaw-execution-probe-ok\n"


# r104 W5b: a sealed, approved hook can start a child out of the probe's
# session (a new session, its own process group, a double fork) and redirect
# its streams. Doctor killed only the probe's session and passed while the
# child kept running.
_ESCAPE_SESSION = "perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die' "
_ESCAPE_GROUP = "perl -e 'setpgrp(0, 0) or die; exec @ARGV or die' "
# The child writes its pid as the test sees it: $$ counts in the probe's PID
# namespace on Linux.
_ESCAPED_CHILD = "sh -c 'read -r p _ < /proc/self/stat; echo $p > \"$0\"; exec sleep 60' \"$PIDFILE\" </dev/null >/dev/null 2>&1"
_ESCAPED_CHILD_FDS_CLOSED = (
    "sh -c 'read -r p _ < /proc/self/stat; echo $p > \"$0\"; exec sleep 60 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-' "
    "\"$PIDFILE\" </dev/null >/dev/null 2>&1"
)
_WAIT_PID = 'while [ ! -s "$PIDFILE" ]; do sleep 0.01; done\n'
_ESCAPE_CASES = {
    # body, timeout, whether the proof holds once the child is ended
    "new-session": (_PROOF + _ESCAPE_SESSION + _ESCAPED_CHILD + " &\n" + _WAIT_PID + "exit 0\n", 20.0, True),
    "double-fork-into-new-session": (
        _PROOF + "( " + _ESCAPE_SESSION + _ESCAPED_CHILD + " & )\n" + _WAIT_PID + "exit 0\n", 20.0, True,
    ),
    "own-process-group": (_PROOF + _ESCAPE_GROUP + _ESCAPED_CHILD + " &\n" + _WAIT_PID + "exit 0\n", 20.0, True),
    "new-session-descriptors-closed": (
        _PROOF + _ESCAPE_SESSION + _ESCAPED_CHILD_FDS_CLOSED + " &\n" + _WAIT_PID + "exit 0\n", 20.0, True,
    ),
    "new-session-then-times-out": (_ESCAPE_SESSION + _ESCAPED_CHILD + " &\n" + _WAIT_PID + "sleep 60\n", 0.5, False),
    "new-session-then-overflows": (
        _PROOF + _ESCAPE_SESSION + _ESCAPED_CHILD + " &\n" + _WAIT_PID + "exec yes\n", 20.0, False,
    ),
    "new-session-then-fails": (_PROOF + _ESCAPE_SESSION + _ESCAPED_CHILD + " &\n" + _WAIT_PID + "exit 1\n", 20.0, False),
}
_LINUX = sys.platform.startswith("linux")
_needs_perl = pytest.mark.skipif(os.name == "nt" or not shutil.which("perl"), reason="Unix shell stub with perl")


def _probe_escape(tmp_path, monkeypatch, body: str, timeout: float = 20.0):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", timeout)
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    target, pid_file = _descendant_stub(tmp_path, body)
    returncode, stdout = cmd_doctor._run_hermes_execution_probe([str(target)])
    return returncode, stdout, _read_pid(pid_file)


@_needs_perl
@pytest.mark.parametrize("case", list(_ESCAPE_CASES), ids=list(_ESCAPE_CASES))
def test_hermes_execution_probe_ends_descendants_that_leave_its_session(tmp_path, monkeypatch, case):
    body, timeout, proves = _ESCAPE_CASES[case]
    if not _LINUX:
        # The macOS launcher disallows all forks. The child cannot reach its
        # PID write, regardless of its new session or closed descriptors.
        monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", min(timeout, 1.0))
        target, pid_file = _descendant_stub(tmp_path, body)
        cmd_doctor._run_hermes_execution_probe([str(target)])
        try:
            assert not pid_file.exists(), "the forkless probe started a child"
        finally:
            if pid_file.exists():
                _kill_quietly(_read_pid(pid_file))
        return
    returncode, stdout, descendant = _probe_escape(tmp_path, monkeypatch, body, timeout)
    try:
        assert _process_gone(descendant, wait=0.2), f"probe left descendant {descendant} running"
        proved = returncode == 0 and stdout == cmd_doctor._HERMES_EXECUTION_PROBE_RESPONSE
        assert proved is proves, (returncode, stdout)
    finally:
        _kill_quietly(descendant)


@_needs_perl
def test_hermes_forkless_probe_preserves_a_simple_proof(tmp_path, monkeypatch):
    """Exercise the macOS launcher on a non-root POSIX host."""
    monkeypatch.setattr(cmd_doctor, "_HERMES_PROBE_UNIX_CONTAINMENT", "forkless")
    target = _probe_stub(tmp_path, _PROOF)
    assert cmd_doctor._run_hermes_execution_probe([str(target)]) == (
        0, cmd_doctor._HERMES_EXECUTION_PROBE_RESPONSE,
    )


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_forkless_probe_reaches_the_installed_hook_template(tmp_path, monkeypatch):
    """The real hook's early proof must work with forks forbidden."""
    source = Path(__file__).resolve().parents[2] / "internal/gateway/connector/hooks"
    hook = tmp_path / "hermes-hook.sh"
    helper = tmp_path / "_hardening.sh"
    template = (source / hook.name).read_text(encoding="utf-8")
    # The Go renderer removes this host-only guard. The probe exits before
    # the later template branches are parsed by bash.
    template = template.replace("{{if not .Sandbox}}", "", 1).replace("{{end}}# Windows", "# Windows", 1)
    hook.write_text(template, encoding="utf-8")
    shutil.copyfile(source / helper.name, helper)
    hook.chmod(0o700)
    monkeypatch.setattr(cmd_doctor, "_HERMES_PROBE_UNIX_CONTAINMENT", "forkless")
    args = [str(hook), "--defenseclaw-execution-probe", "--forkless"]
    assert cmd_doctor._run_hermes_execution_probe(args) == (
        0, cmd_doctor._HERMES_EXECUTION_PROBE_RESPONSE,
    )
    helper.write_text("exit 7\n", encoding="utf-8")
    assert cmd_doctor._run_hermes_execution_probe(args)[0] != 0


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_forkless_probe_ignores_inherited_bash_startup(tmp_path, monkeypatch):
    hook = tmp_path / "hermes-hook.sh"
    hook.write_text("#!/bin/bash\nprintf 'ordinary\\n'\nexit 9\n", encoding="utf-8")
    hook.chmod(0o700)
    startup = tmp_path / "startup.sh"
    startup.write_text(_PROOF + "exit 0\n", encoding="utf-8")
    monkeypatch.setenv("BASH_ENV", str(startup))
    monkeypatch.setenv(
        "BASH_FUNC_printf%%",
        "() { builtin printf 'defenseclaw-execution-probe-ok\\n'; exit 0; }",
    )
    monkeypatch.setattr(cmd_doctor, "_HERMES_PROBE_UNIX_CONTAINMENT", "forkless")
    assert cmd_doctor._run_hermes_execution_probe([str(hook)]) == (9, b"ordinary\n")


@pytest.mark.skipif(os.name == "nt", reason="Unix shell hook")
def test_hermes_doctor_adds_forkless_arg_only_for_darwin(tmp_path, monkeypatch):
    hook, _check = _registered_unix_hermes(tmp_path, monkeypatch)
    seen = []

    def probe(argv):
        seen.append(argv)
        return 0, cmd_doctor._HERMES_EXECUTION_PROBE_RESPONSE

    monkeypatch.setattr(cmd_doctor, "_run_hermes_execution_probe", probe)
    cfg = SimpleNamespace(data_dir=str(tmp_path / "dc"))
    config = str(tmp_path / "hermes" / "config.yaml")
    assert not cmd_doctor._hermes_registered_execution_problem(cfg, config)
    assert seen == [[str(hook), "--defenseclaw-execution-probe"]]
    seen.clear()
    monkeypatch.setattr(cmd_doctor, "sys", _ProxyModule(sys, platform="darwin"))
    assert not cmd_doctor._hermes_registered_execution_problem(cfg, config)
    assert seen == [[str(hook), "--defenseclaw-execution-probe", "--forkless"]]


@_needs_perl
def test_hermes_forkless_probe_cannot_leave_a_closed_fd_child(tmp_path, monkeypatch):
    """The old lifeline passed after a detached child closed its descriptors."""
    monkeypatch.setattr(cmd_doctor, "_HERMES_PROBE_UNIX_CONTAINMENT", "forkless")
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_TIMEOUT", 1.0)
    body = _PROOF + _ESCAPE_SESSION + _ESCAPED_CHILD_FDS_CLOSED + " &\nsleep 0.2\nexit 0\n"
    target, pid_file = _descendant_stub(tmp_path, body)
    cmd_doctor._run_hermes_execution_probe([str(target)])
    try:
        assert not pid_file.exists(), "the probe started a child that closed every inherited descriptor"
    finally:
        if pid_file.exists():
            _kill_quietly(_read_pid(pid_file))


@pytest.mark.skipif(not _LINUX, reason="Linux probe supervisor")
def test_hermes_probe_supervisor_fails_closed_without_a_namespace(tmp_path, monkeypatch):
    # A kernel or sandbox that refuses the namespaces (here: an unshare flag
    # it rejects) never runs the hook.
    supervisor = cmd_doctor._HERMES_PROBE_SUPERVISOR
    assert "CLONE_NEWUSER, CLONE_NEWPID = 0x10000000, 0x20000000" in supervisor
    monkeypatch.setattr(cmd_doctor, "_HERMES_PROBE_SUPERVISOR", supervisor.replace(
        "CLONE_NEWUSER, CLONE_NEWPID = 0x10000000, 0x20000000", "CLONE_NEWUSER, CLONE_NEWPID = 0x10000000, 0x1",
    ))
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    ran = tmp_path / "ran"
    returncode, _stdout = cmd_doctor._run_hermes_execution_probe(
        [str(_probe_stub(tmp_path, f": > '{ran}'\n" + _PROOF))],
    )
    assert returncode is None
    assert not ran.exists(), "the hook ran outside a namespace of its own"


@pytest.mark.skipif(not _LINUX or not shutil.which("perl"), reason="Linux probe supervisor")
def test_hermes_probe_ends_the_tree_when_its_supervisor_is_killed(tmp_path, monkeypatch):
    # Killed from outside, however it dies, the supervisor takes the
    # namespace with it, and the probe cannot pass.
    import signal
    import threading

    chain = tmp_path / "supervisors"
    body = _ESCAPE_CASES["new-session"][0].replace("exit 0\n", (
        'read -r _ _ _ a _ < /proc/self/stat; list=""\n'
        'while [ "${a:-0}" -gt 1 ]; do\n'
        '  case "$(tr \'\\0\' \' \' < /proc/$a/cmdline)" in *"def reap_all"*) list="$list $a" ;; esac\n'
        '  read -r _ _ _ a _ < /proc/$a/stat || break\n'
        "done\n"
        f"echo $list > '{chain}.tmp' && mv '{chain}.tmp' '{chain}'\n"
        "sleep 60\n"
    ))
    result = {}
    probe = threading.Thread(target=lambda: result.update(zip(
        ("returncode", "stdout", "descendant"), _probe_escape(tmp_path, monkeypatch, body),
    )))
    probe.start()
    deadline = time.monotonic() + 10
    while not chain.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    supervisors = chain.read_text(encoding="utf-8").split()
    assert supervisors, "the hook found no supervisor ancestor"
    os.kill(int(supervisors[-1]), signal.SIGKILL)
    probe.join(15)
    assert not probe.is_alive(), "Doctor still waits after its probe supervisor died"
    try:
        assert result["returncode"] is None, "a probe whose supervisor died must not pass"
        assert _process_gone(result["descendant"]), f"Doctor left descendant {result['descendant']} after supervisor death"
    finally:
        _kill_quietly(result["descendant"])


# r104 W5b review: a hook that SIGKILLed the subreaper custodian, its
# grandparent, took the runner and itself down, and the kernel handed its
# setsid child to init, which kept running while Doctor returned. Every
# supervisor ancestor, by the pids the test sees, outermost first, killed
# together; only ever the probe's supervisors, never the test runner.
_KILL_SUPERVISORS = """read -r _ _ _ a _ < /proc/self/stat; list=""
while [ "${a:-0}" -gt 1 ]; do
  case "$(tr '\\0' ' ' < /proc/$a/cmdline)" in *"def reap_all"*) list="$a $list" ;; esac
  read -r _ _ _ a _ < /proc/$a/stat || break
done
[ -n "$list" ] || exit 7
kill -9 $list
sleep 1
"""


@pytest.mark.skipif(not _LINUX or not shutil.which("perl"), reason="Linux probe supervisor")
def test_hermes_probe_hook_cannot_end_its_supervisors(tmp_path, monkeypatch):
    body = _ESCAPE_CASES["new-session"][0].replace("exit 0\n", _KILL_SUPERVISORS + "exit 0\n")
    returncode, stdout, descendant = _probe_escape(tmp_path, monkeypatch, body)
    try:
        assert returncode != 7, "the hook found no supervisor ancestor"
        assert _process_gone(descendant, wait=0.2), f"Doctor left descendant {descendant} after the hook killed its supervisors"
    finally:
        _kill_quietly(descendant)


@pytest.mark.skipif(not _LINUX, reason="Linux probe supervisor")
@pytest.mark.parametrize(("body", "want"), [("exit 0\n", 0), ("exit 3\n", 3), ("kill -TERM $$\n", 143)])
def test_hermes_probe_supervisor_keeps_the_hook_exit_status(tmp_path, monkeypatch, body, want):
    monkeypatch.setattr(cmd_doctor, "_HERMES_EXECUTION_PROBE_PIPE_WAIT", 0.5)
    returncode, _stdout = cmd_doctor._run_hermes_execution_probe([str(_probe_stub(tmp_path, body))])
    assert returncode == want


@_needs_perl
def test_hermes_doctor_ends_hook_child_in_new_session(tmp_path, monkeypatch):
    script, check = _registered_unix_hermes(tmp_path, monkeypatch)
    pid_file = tmp_path / "escaped.pid"
    script.write_text(
        f"#!/bin/sh\nPIDFILE='{pid_file}'\n" + _ESCAPE_CASES["new-session"][0], encoding="utf-8",
    )
    script.chmod(0o700)
    row = check()
    if not _LINUX:
        try:
            assert not pid_file.exists(), "Doctor started a child outside its session"
            assert row["status"] == "fail", row
        finally:
            if pid_file.exists():
                _kill_quietly(_read_pid(pid_file))
        return
    descendant = _read_pid(pid_file)
    try:
        assert _process_gone(descendant, wait=0.2), f"Doctor left hook child {descendant} running"
        assert row["status"] == "pass", row
    finally:
        _kill_quietly(descendant)
