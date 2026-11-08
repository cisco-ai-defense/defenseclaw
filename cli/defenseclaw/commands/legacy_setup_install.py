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

import errno
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass

from defenseclaw.link_guard import Problem, dangling_link_problem, is_reparse, link_problem

_LOCAL_APP_DATA_FOLDER_ID = "f1b32785-6fba-4fcf-9d55-7b8e7f157091"
_MAX_STATE_BYTES = 256 * 1024
_MAX_HOOK_STATE_BYTES = 64 * 1024
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_VERSION = re.compile(r"0\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\Z")
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw"
_STOP_WAIT_MS = 10_000
# A folder an elevated token creates belongs to this group, not to the user
# (Windows Server, a "Run as administrator" install, UAC off).
_ADMINISTRATORS_SID = "S-1-5-32-544"


@dataclass(frozen=True)
class LegacySetupInstall:
    """The current user's DefenseClaw Setup 0.8.x install."""

    root: str
    version: str
    data_root: str
    cache: str
    hook_state: str
    # problem is why it is left in place ("" when it can be removed);
    # problem_step is what the user does about that reason.
    problem: str = ""
    problem_step: str = ""


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
    cache = os.path.join(local, "DefenseClaw", "InstallerCache")
    hook_state = os.path.join(local, "DefenseClaw", "HookRuntime", "hook-runtime-state.json")
    if not os.path.lexists(state_path):
        # A link whose target cannot be found hides the state, so there is nothing to find through it: say so
        # instead of nothing, with the step that removes only the link. A link at the Setup folder is always
        # named; one further up only when Setup 0.8.x left its entries (registry, hook launcher state), so a
        # stray link on a profile that never had Setup is not a reason to exit 1.
        dangling = dangling_link_problem(root, above=_setup_registered(root, cache) or os.path.lexists(hook_state))
        if dangling:
            return LegacySetupInstall(
                root, "", "", cache, hook_state, problem=str(dangling), problem_step=dangling.step
            )
        return None
    # A link at or above the program folder is named before anything is read: the
    # state is never opened through it, and nothing is removed through it.
    linked = link_problem(root, setup=True)
    if linked:
        return LegacySetupInstall(root, "", "", cache, hook_state, problem=str(linked), problem_step=linked.step)
    try:
        state = _read_state(state_path)
    except OSError as exc:
        # A link made since the check above is still named, not "delete it yourself".
        linked = link_problem(root, setup=True)
        return LegacySetupInstall(
            root,
            "",
            "",
            cache,
            hook_state,
            problem=str(linked or exc),
            problem_step=linked.step
            if linked
            else (
                f"Uninstall DefenseClaw Setup from Apps & Features, or delete {root} yourself "
                "(ask an administrator if your account cannot)."
            ),
        )
    if not isinstance(state, dict) or state.get("install_kind") != "native-windows-exe":
        return None
    version = state.get("version")
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        # Only the released 0.8.x Setups: a newer per-user Setup was never published.
        return None
    data_root = state.get("data_root") if isinstance(state.get("data_root"), str) else ""
    problem = step = ""
    install_root = state.get("install_root")
    if state.get("install_scope") != "user":
        problem = "its install state does not describe a per-user install"
        step = f"Uninstall it with its own uninstaller (Apps & Features), or ask an administrator to remove {root}."
    elif not isinstance(install_root, str) or not _same_path(install_root, root):
        # The folder comes from a file the user can edit: name it, never advise deleting it.
        named = "".join(ch for ch in str(install_root) if ch.isprintable())[:260]
        problem = f"its install state names another program folder ({named})"
        step = (
            f"Uninstall DefenseClaw Setup from Apps & Features. Its install state names {named}: "
            "ask an administrator to check that folder. DefenseClaw does not remove it."
        )
    elif _inside(os.path.abspath(sys.executable), root):
        problem = "this command runs from that install"
        step = (
            f"Run the uninstall with a defenseclaw outside {root} (where.exe defenseclaw lists the "
            "ones on your Path), or uninstall DefenseClaw Setup from Apps & Features."
        )
    else:
        problem = _ownership_problem(root)
        step = getattr(problem, "step", "")
    return LegacySetupInstall(root, version, data_root, cache, hook_state, problem=problem, problem_step=step)


def hook_entries(install: LegacySetupInstall, config_files: list[str]) -> list[str]:
    """The files among *config_files* that start a program of *install*.

    A DefenseClaw Setup 0.8.x install registers its own hook launcher in the
    agent's settings, and this release registers another one beside it. The
    two commands then disagree and the registration check fails after the
    sidecar has started (GAP-0101). Only a hook that runs from the program
    folder or the hook runtime folder of this account's own 0.8.x install
    counts; a hook of any other product, or of a copy of DefenseClaw in
    another folder, does not.
    """
    prefixes = tuple(
        _slashes(folder).rstrip("\\") + "\\"
        for folder in (install.root, os.path.dirname(install.hook_state))
        if folder
    )
    found: list[str] = []
    for path in config_files:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read(_MAX_CONFIG_BYTES)
        except OSError:
            continue
        # JSON escapes each backslash; settings written by hand may use slashes.
        commands = _slashes(_hook_command_text(text).replace("\\\\", "\\"))
        if any(prefix in commands for prefix in prefixes):
            found.append(path)
    return found


def _hook_command_text(text: str) -> str:
    """The part of an agent's settings file where a hook command can be.

    JSON: the strings under a ``hooks`` key. Any other format (TOML, or JSON
    with comments): the lines that set a ``command``. An allow-list rule or a
    note that mentions the Setup folder is not a registration (L2).
    """
    try:
        data = json.loads(text)
    except ValueError:
        return "\n".join(line for line in text.splitlines() if "command" in line.lower())
    found: list[str] = []

    def walk(node: object, in_hooks: bool) -> None:
        if isinstance(node, str):
            if in_hooks:
                found.append(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                walk(value, in_hooks or key == "hooks")
        elif isinstance(node, list):
            for value in node:
                walk(value, in_hooks)

    walk(data, False)
    return "\n".join(found)


def hook_refusal(install: LegacySetupInstall, files: list[str], rerun: str) -> str:
    """Why init stops before it changes anything, naming the older install and the next step."""
    name = f"DefenseClaw Setup {install.version}" if install.version else "DefenseClaw Setup"
    return (
        f"{name} at {install.root} still has hooks registered in {', '.join(files)}. "
        "This release's hooks would sit beside them and the two disagree, so init changes nothing. "
        "No command removes only that install: `defenseclaw uninstall` removes DefenseClaw Setup 0.8.x "
        "(your data folder is kept) and also stops this release's gateway and removes the hooks of the "
        f"connectors it has configured. Run it, then run `{rerun}` again to set them up."
    )


def _slashes(value: str) -> str:
    return value.replace("/", "\\").lower()


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
        lines.append(
            f"kept: its data folder {install.data_root} (delete it yourself if you no longer need it; "
            "the Enterprise Setup does not install on this computer while it is there)"
        )
    return lines


def remove(install: LegacySetupInstall, *, edit_user_path) -> tuple[list[str], list[str]]:
    """Remove *install*; return (what was removed, what could not be).

    Every step runs, so one that fails leaves the others done. *edit_user_path*
    removes one folder from the user Path and returns whether it changed.
    """
    done: list[str] = []
    problems: list[str] = []
    if install.problem:
        return done, [Problem(f"{install.root}: {install.problem}", install.problem_step)]
    # Off first: the launcher can start the old gateway again, and so can its sign-in start.
    launcher_link = link_problem(install.hook_state, include_self=False, setup=True)
    try:
        if launcher_link:
            problems.append(
                Problem(
                    f"could not turn the DefenseClaw Setup hook launcher off ({install.hook_state}): {launcher_link}",
                    launcher_link.step,
                )
            )
        elif _turn_hook_launcher_off(install.hook_state, install.root):
            done.append(f"turned the DefenseClaw Setup hook launcher off ({install.hook_state} removed)")
    except OSError as exc:
        problems.append(
            Problem(
                f"could not turn the DefenseClaw Setup hook launcher off ({install.hook_state}): {exc}",
                _path_step(exc, install.hook_state),
            )
        )
    try:
        for name in _remove_run_values(install.root, install.cache):
            done.append(f"removed its sign-in start (HKCU\\{_RUN_KEY}\\{name})")
    except OSError as exc:
        problems.append(
            Problem(
                f"could not read or change HKCU\\{_RUN_KEY}: {exc}",
                f"Delete the DefenseClaw Setup values under HKCU\\{_RUN_KEY} yourself "
                "(Task Manager > Startup apps, or regedit), then run the command again.",
            )
        )
    try:
        stopped = _stop_processes_under(install.root)
        if stopped:
            done.append(f"stopped {stopped} DefenseClaw Setup program(s) running from {install.root}")
    except OSError as exc:
        problems.append(
            Problem(
                f"could not stop the programs running from {install.root}: {exc}",
                f"End the DefenseClaw programs running from {install.root} in Task Manager "
                "(or sign out and back in), then run the command again.",
            )
        )
    try:
        if _remove_uninstall_entry(install.root):
            done.append(f"removed its Apps & Features entry (HKCU\\{_UNINSTALL_KEY})")
    except OSError as exc:
        problems.append(
            Problem(
                f"could not remove HKCU\\{_UNINSTALL_KEY}: {exc}",
                f"Uninstall DefenseClaw Setup from Apps & Features, or delete HKCU\\{_UNINSTALL_KEY} "
                "in regedit, then run the command again.",
            )
        )
    bin_dir = os.path.join(install.root, "bin")
    try:
        if edit_user_path(bin_dir):
            done.append(f"removed {bin_dir} from your user Path (new terminals get the change)")
    except OSError as exc:
        problems.append(
            Problem(
                f"could not remove {bin_dir} from your user Path: {exc}",
                f"Remove {bin_dir} from your user Path yourself (Settings > System > About > "
                "Advanced system settings > Environment Variables), then run the command again.",
            )
        )
    for path in (install.root, install.cache):
        linked = link_problem(path, include_self=False, setup=True)
        if linked:
            problems.append(Problem(f"could not remove {path}: {linked}", linked.step))
            continue
        try:
            if _remove_tree(path):
                done.append(f"removed {path}")
        except OSError as exc:
            problems.append(Problem(f"could not remove {path}: {exc}", _path_step(exc, path)))
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
    """Why *root* is not this account's own folder, with the step for it as ``.step`` ("" when it is)."""
    from defenseclaw.commands.windows_uninstall_helper import _validate_root
    from defenseclaw.file_permissions import _windows_acl_snapshot, _windows_current_user_sid

    linked = link_problem(root, setup=True)
    if linked:
        return linked
    try:
        _validate_root(root, "its program folder")
    except ValueError as exc:
        return Problem(str(exc), f"Ask an administrator to check {root}, then run the command again.")
    try:
        owner, _null_dacl, _entries = _windows_acl_snapshot(root)
        current = _windows_current_user_sid()
    except OSError as exc:
        return Problem(
            f"its owner could not be read ({exc})",
            f"Ask an administrator to remove {root}, or to give your account access to it, then run the command again.",
        )
    # The user's own account, or Administrators: an elevated install is owned by
    # the group. The folder is still the user's own Known Folder path with no
    # link above it, and removing it takes no authority this account lacks.
    if owner not in (current, _ADMINISTRATORS_SID):
        who = _account_label(owner)
        return Problem(
            f"its program folder belongs to another account ({who}); "
            "sign in as that account to uninstall it, or delete the folder yourself",
            f"Ask an administrator, or the account that owns it ({who}), to remove {root}.",
        )
    return ""


def _account_label(sid: str) -> str:
    """The account name and SID of *sid* ("unknown" when empty, the SID alone when the name cannot be read)."""
    if not sid:
        return "unknown"
    try:
        from defenseclaw.inventory.claw_inventory import _windows_account_name_for_sid

        name = _windows_account_name_for_sid(sid)
    except Exception:  # noqa: BLE001 - the name is best effort; the SID still names the owner.
        return sid
    return f"{name}, {sid}" if name else sid


def _path_step(error: BaseException, path: str) -> str:
    """What to do about *path*, from why its removal failed (held, denied or other)."""
    from defenseclaw.commands import windows_uninstall_helper as helper

    # A link on the way to *path* is the reason, whatever the error said.
    linked = link_problem(path, setup=True)
    if linked:
        return linked.step
    winerror = getattr(error, "winerror", None)
    code = getattr(error, "errno", None)
    # The error names the file inside *path* that it could not remove.
    named = getattr(error, "filename", None)
    where = named if isinstance(named, str) and named else path
    if winerror in (helper._ERROR_SHARING_VIOLATION, helper._ERROR_LOCK_VIOLATION, helper._ERROR_DIR_NOT_EMPTY) or (
        winerror is None and code in (errno.EBUSY, errno.ENOTEMPTY)
    ):
        return f"Close the program that holds {where}, then run the command again."
    if winerror == helper._ERROR_ACCESS_DENIED or (winerror is None and code in (errno.EACCES, errno.EPERM)):
        return (
            f"Your account cannot remove {where}: ask an administrator to remove it (or to give your "
            "account full control of it), then run the command again."
        )
    return f"Remove {path} yourself, then run the command again."


def _turn_hook_launcher_off(hook_state: str, root: str) -> bool:
    """Remove the HookRuntime state that runs this install's hook.

    The launcher treats missing state as disabled, so agent hooks the old
    Setup wrote do nothing from then on. A state install.ps1 published (it
    delegates to this install's copy of the hook) is not this install's.
    """
    if not os.path.lexists(hook_state):
        return False
    if is_reparse(hook_state) or not stat.S_ISREG(os.lstat(hook_state).st_mode):
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


def _setup_registered(root: str, cache: str) -> bool:
    """Whether DefenseClaw Setup 0.8.x left its entries for *root* in this account registry (read only).

    Its Apps & Features entry names the program folder, and its sign-in start runs a program in the
    program folder or the cache.
    """
    try:
        import winreg
    except ImportError:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _UNINSTALL_KEY) as key:
            location, _kind = winreg.QueryValueEx(key, "InstallLocation")
        if isinstance(location, str) and _same_path(location, root):
            return True
    except OSError:
        pass
    prefixes = tuple(os.path.normcase(os.path.join(os.path.abspath(path), "")) for path in (root, cache))
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_QUERY_VALUE)
    except OSError:
        return False
    with key:
        index = 0
        while True:
            try:
                _name, value, _kind = winreg.EnumValue(key, index)
            except OSError:
                return False
            index += 1
            command = os.path.normcase(winreg.ExpandEnvironmentStrings(value)) if isinstance(value, str) else ""
            if _starts_in(command, prefixes):
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
            if _starts_in(command, prefixes):
                names.append(name)
        for name in names:
            winreg.DeleteValue(key, name)
            removed.append(name)
    return removed


def _starts_in(command: str, prefixes: tuple[str, ...]) -> bool:
    """Whether the program *command* runs is inside one of the folders *prefixes*.

    Both are normcased; each prefix ends with a path separator, so a sibling
    folder whose name only starts the same way does not match, and neither
    does another program that merely passes such a path as an argument.
    """
    program = command.lstrip()
    if program.startswith('"'):
        program = program[1:]
    return program.startswith(prefixes)


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
    if is_reparse(path):
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
    failures: list[str] = []
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
                failures.append(f"PID {pid} ({ctypes.WinError(ctypes.get_last_error()).strerror})")
                continue
            kernel32.WaitForSingleObject(handle, _STOP_WAIT_MS)
            stopped += 1
        finally:
            kernel32.CloseHandle(handle)
    if failures:
        raise OSError(f"stopped {stopped}, could not stop {', '.join(failures)}")
    return stopped


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)).rstrip("\\/") == os.path.normcase(os.path.abspath(right)).rstrip(
        "\\/"
    )


def _inside(path: str, root: str) -> bool:
    return os.path.normcase(path).startswith(os.path.normcase(os.path.join(os.path.abspath(root), "")))
