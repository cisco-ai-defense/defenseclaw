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

"""until the 0.8 bridge retires: a DefenseClaw Setup 0.8.x install left beside this one.

DefenseClaw Setup (DefenseClawSetup-x64.exe) was the per-user Windows
installer of 0.8.7-0.8.10. install.ps1 imports such an install when it
upgrades, unless that install keeps its data in another folder than the
upgrade (DEFENSECLAW_HOME); then it leaves it alone. ``defenseclaw
uninstall`` removes what is left of it: it stops the programs that run from
its folder, removes its program folder, its cached Setup, its Apps &
Features entry, its sign-in start and its user Path entry, and turns its hook
launcher off. It never runs a program of that install (those Setups were
unsigned), touches only the current user's own install, and keeps its data
folder.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass

_LOCAL_APP_DATA_FOLDER_ID = "f1b32785-6fba-4fcf-9d55-7b8e7f157091"
_MAX_STATE_BYTES = 256 * 1024
_MAX_HOOK_STATE_BYTES = 64 * 1024
_VERSION = re.compile(r"0\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\Z")
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw"
_STOP_WAIT_MS = 10_000


@dataclass(frozen=True)
class LegacySetupInstall:
    """The current user's DefenseClaw Setup 0.8.x install."""

    root: str
    version: str
    data_root: str
    cache: str
    hook_state: str
    # problem is why it is left in place ("" when it can be removed).
    problem: str = ""


def local_app_data() -> str:
    """The current user's LocalAppData Known Folder ("" when it cannot be read)."""
    from defenseclaw.doctor_hooks import _windows_known_folder_path

    try:
        return _windows_known_folder_path(_LOCAL_APP_DATA_FOLDER_ID) or ""
    except Exception:  # noqa: BLE001 - no Known Folder means nothing to find.
        return ""


def find(platform_name: str) -> LegacySetupInstall | None:
    """Return the current user's DefenseClaw Setup 0.8.x install, or None."""
    if platform_name != "win32":
        return None
    local = local_app_data()
    if not local:
        return None
    root = os.path.join(local, "Programs", "DefenseClaw")
    state_path = os.path.join(root, "installer", "install-state.json")
    if not os.path.lexists(state_path):
        return None
    cache = os.path.join(local, "DefenseClaw", "InstallerCache")
    hook_state = os.path.join(local, "DefenseClaw", "HookRuntime", "hook-runtime-state.json")
    try:
        state = _read_state(state_path)
    except OSError as exc:
        return LegacySetupInstall(root, "", "", cache, hook_state, problem=str(exc))
    if not isinstance(state, dict) or state.get("install_kind") != "native-windows-exe":
        return None
    version = state.get("version")
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        # Only the released 0.8.x Setups: a newer per-user Setup was never published.
        return None
    data_root = state.get("data_root") if isinstance(state.get("data_root"), str) else ""
    problem = ""
    install_root = state.get("install_root")
    if state.get("install_scope") != "user":
        problem = "its install state does not describe a per-user install"
    elif not isinstance(install_root, str) or not _same_path(install_root, root):
        problem = f"its install state names another program folder ({install_root})"
    elif _inside(os.path.abspath(sys.executable), root):
        problem = "this command runs from that install"
    else:
        problem = _ownership_problem(root)
    return LegacySetupInstall(root, version, data_root, cache, hook_state, problem=problem)


def plan_lines(install: LegacySetupInstall, data_dir: str) -> list[str]:
    """What the uninstall does with *install*, one line each."""
    name = f"DefenseClaw Setup {install.version}" if install.version else "DefenseClaw Setup"
    if install.problem:
        return [f"{name} at {install.root} stays: {install.problem}"]
    lines = [
        f"{name} at {install.root}: its programs stop, and its program folder, cached Setup, "
        "Apps & Features entry, sign-in start and user Path entry go; its hook launcher is turned off"
    ]
    if install.data_root and not _same_path(install.data_root, data_dir) and os.path.isdir(install.data_root):
        lines.append(f"kept: its data folder {install.data_root} (delete it yourself if you no longer need it)")
    return lines


def remove(install: LegacySetupInstall, *, edit_user_path) -> tuple[list[str], list[str]]:
    """Remove *install*; return (what was removed, what could not be).

    Every step runs, so one that fails leaves the others done. *edit_user_path*
    removes one folder from the user Path and returns whether it changed.
    """
    done: list[str] = []
    problems: list[str] = []
    if install.problem:
        return done, [f"{install.root}: {install.problem}"]
    # Off first: the launcher can start the old gateway again, and so can its sign-in start.
    try:
        if _turn_hook_launcher_off(install.hook_state, install.root):
            done.append(f"turned the DefenseClaw Setup hook launcher off ({install.hook_state} removed)")
    except OSError as exc:
        problems.append(f"could not turn the DefenseClaw Setup hook launcher off ({install.hook_state}): {exc}")
    try:
        for name in _remove_run_values(install.root, install.cache):
            done.append(f"removed its sign-in start (HKCU\\{_RUN_KEY}\\{name})")
    except OSError as exc:
        problems.append(f"could not read or change HKCU\\{_RUN_KEY}: {exc}")
    try:
        stopped = _stop_processes_under(install.root)
        if stopped:
            done.append(f"stopped {stopped} DefenseClaw Setup program(s) running from {install.root}")
    except OSError as exc:
        problems.append(f"could not stop the programs running from {install.root}: {exc}")
    try:
        if _remove_uninstall_entry(install.root):
            done.append(f"removed its Apps & Features entry (HKCU\\{_UNINSTALL_KEY})")
    except OSError as exc:
        problems.append(f"could not remove HKCU\\{_UNINSTALL_KEY}: {exc}")
    bin_dir = os.path.join(install.root, "bin")
    try:
        if edit_user_path(bin_dir):
            done.append(f"removed {bin_dir} from your user Path (new terminals get the change)")
    except OSError as exc:
        problems.append(f"could not remove {bin_dir} from your user Path: {exc}")
    for path in (install.root, install.cache):
        try:
            if _remove_tree(path):
                done.append(f"removed {path}")
        except OSError as exc:
            problems.append(f"could not remove {path}: {exc}")
    return done, problems


def _read_state(path: str) -> object:
    from defenseclaw.file_permissions import open_regular_file_no_follow

    fd = open_regular_file_no_follow(path)
    try:
        size = os.fstat(fd).st_size
        if size <= 0 or size > _MAX_STATE_BYTES:
            raise OSError(f"{path} is outside the {_MAX_STATE_BYTES}-byte bound")
        raw = os.read(fd, size + 1)
    finally:
        os.close(fd)
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        raise OSError(f"{path} is not valid JSON: {exc}") from exc


def _ownership_problem(root: str) -> str:
    """Why *root* is not this account's own folder ("" when it is)."""
    from defenseclaw.file_permissions import _windows_acl_snapshot, _windows_current_user_sid

    if _is_reparse(root):
        return "its program folder is a link"
    try:
        owner, _null_dacl, _entries = _windows_acl_snapshot(root)
        current = _windows_current_user_sid()
    except OSError as exc:
        return f"its owner could not be read ({exc})"
    if owner != current:
        return f"its program folder belongs to another account ({owner or 'unknown'})"
    return ""


def _turn_hook_launcher_off(hook_state: str, root: str) -> bool:
    """Remove the HookRuntime state that runs this install's hook.

    The launcher treats missing state as disabled, so agent hooks the old
    Setup wrote do nothing from then on. A state install.ps1 published (it
    delegates to this install's copy of the hook) is not this install's.
    """
    if not os.path.lexists(hook_state):
        return False
    if _is_reparse(hook_state) or not stat.S_ISREG(os.lstat(hook_state).st_mode):
        raise OSError("it is not a regular file")
    if os.path.getsize(hook_state) > _MAX_HOOK_STATE_BYTES:
        raise OSError(f"it is larger than {_MAX_HOOK_STATE_BYTES} bytes")
    with open(hook_state, encoding="utf-8-sig") as handle:
        try:
            hook = json.load(handle).get("hook_path")
        except (ValueError, AttributeError):
            hook = None
    if not isinstance(hook, str) or not _inside(os.path.abspath(hook), root):
        return False
    os.unlink(hook_state)
    return True


def _remove_run_values(root: str, cache: str) -> list[str]:
    import winreg

    prefixes = tuple(os.path.normcase(os.path.join(os.path.abspath(path), "")) for path in (root, cache))
    removed: list[str] = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        return removed
    with key:
        names: list[str] = []
        index = 0
        while True:
            try:
                name, value, _kind = winreg.EnumValue(key, index)
            except OSError:
                break
            index += 1
            command = os.path.normcase(winreg.ExpandEnvironmentStrings(value)) if isinstance(value, str) else ""
            if any(prefix in command for prefix in prefixes):
                names.append(name)
        for name in names:
            winreg.DeleteValue(key, name)
            removed.append(name)
    return removed


def _remove_uninstall_entry(root: str) -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _UNINSTALL_KEY) as key:
            location, _kind = winreg.QueryValueEx(key, "InstallLocation")
    except FileNotFoundError:
        return False
    if not isinstance(location, str) or not _same_path(location, root):
        return False
    _delete_key_tree(winreg.HKEY_CURRENT_USER, _UNINSTALL_KEY)
    return True


def _delete_key_tree(hive, path: str) -> None:
    import winreg

    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
        children: list[str] = []
        index = 0
        while True:
            try:
                children.append(winreg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    for child in children:
        _delete_key_tree(hive, path + "\\" + child)
    winreg.DeleteKey(hive, path)


def _remove_tree(path: str) -> bool:
    if not os.path.lexists(path):
        return False
    if _is_reparse(path):
        # A link is removed, never followed.
        if os.path.isdir(path):
            os.rmdir(path)
        else:
            os.unlink(path)
        return True
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)
    return True


def _stop_processes_under(root: str) -> int:
    """Stop the processes whose program is inside *root* (exact PIDs)."""
    import ctypes
    from ctypes import wintypes

    from defenseclaw.commands.windows_uninstall_helper import _kernel32, _ProcessEntry

    kernel32 = _kernel32()
    kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateProcess.restype = wintypes.BOOL
    prefix = os.path.normcase(os.path.join(os.path.abspath(root), ""))
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    pids: list[int] = []
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            pids.append(int(entry.th32ProcessID))
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    stopped = 0
    own = os.getpid()
    # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    access = 0x0001 | 0x1000 | 0x00100000
    for pid in pids:
        if pid in (0, 4, own):
            continue
        handle = kernel32.OpenProcess(access, False, pid)
        if not handle:
            continue
        try:
            size = wintypes.DWORD(32768)
            image = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                continue
            if not os.path.normcase(os.path.abspath(image.value)).startswith(prefix):
                continue
            if not kernel32.TerminateProcess(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            kernel32.WaitForSingleObject(handle, _STOP_WAIT_MS)
            stopped += 1
        finally:
            kernel32.CloseHandle(handle)
    return stopped


def _is_reparse(path: str) -> bool:
    if os.path.islink(path):
        return True
    with contextlib.suppress(OSError):
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)).rstrip("\\/") == os.path.normcase(os.path.abspath(right)).rstrip(
        "\\/"
    )


def _inside(path: str, root: str) -> bool:
    return os.path.normcase(path).startswith(os.path.normcase(os.path.join(os.path.abspath(root), "")))
