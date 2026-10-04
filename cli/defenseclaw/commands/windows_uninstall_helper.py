"""Standalone Windows deferred cleanup helper.

The CLI copies this standard-library-only file outside the managed virtual
environment before starting it. All paths arrive as JSON data. The only
shell text is the cmd.exe line that removes the folders holding this
helper's own Python once it exits (interpreter_dirs); those paths are
validated first and must hold no cmd.exe metacharacter.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import stat
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

_ALLOWED_BINARIES = {
    "defenseclaw.cmd",
    # The installer's copy of the venv's launcher (GAP-2237).
    "defenseclaw.exe",
    "defenseclaw",
    "defenseclaw-gateway.exe",
    "defenseclaw-acp.exe",
    "defenseclaw-hook.exe",
    "skill-scanner.cmd",
    "mcp-scanner.cmd",
    "defenseclaw-hook-state.json",
    # uv, when the installer put it there (see cmd_uninstall._UV_RECORD).
    "defenseclaw-uv.sha256",
    "uv.exe",
    "uvx.exe",
    "uvw.exe",
}
# A copy of an owned binary that a source install renamed aside while it ran
# (install_publish; GAP-1929).
_RETIRED_COPY_RE = re.compile(r"\.(?P<name>.+)\.source-install-old-[0-9a-f]+", re.IGNORECASE)
_OWNERSHIP_MARKERS = {"config.yaml", "audit.db", ".env", "policies", "quarantine", ".venv"}
_LAUNCHER_UNWIND_GRACE_SECONDS = 1.0
# scripts/install.ps1 holds this folder in the data dir while it installs; it
# and "installer" and ".venv" are what a new install writes there (GAP-2149).
_INSTALL_LOCK = ".install.lock"
_NEW_INSTALL_ENTRIES = (_INSTALL_LOCK, "installer", ".venv")
_LAUNCHER_WAIT_SECONDS = 15.0
# An interactive cmd.exe that ran the shim stays open; do not wait long on it.
_SHIM_SHELL_WAIT_SECONDS = 5.0
_MAX_LAUNCHER_DEPTH = 4
# cmd.exe would interpret these in a path (paths cannot hold a quote anyway).
_CMD_METACHARACTERS = set('"%!^&|<>()')


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ProcessEntry))
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ProcessEntry))
    kernel32.Process32NextW.restype = wintypes.BOOL
    return kernel32


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _is_reparse(path: str) -> bool:
    if os.path.islink(path):
        return True
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _validate_root(path: str, label: str) -> str:
    root = _norm(path)
    if not os.path.isabs(path) or Path(root).anchor == root:
        raise ValueError(f"unsafe {label}: {path}")
    if os.path.lexists(root) and _is_reparse(root):
        raise ValueError(f"{label} is a symlink or reparse point: {path}")
    candidate = Path(root)
    while str(candidate) != candidate.anchor:
        if os.path.lexists(candidate) and _is_reparse(str(candidate)):
            raise ValueError(f"reparse-point ancestor for {label}: {candidate}")
        candidate = candidate.parent
    return root


def _validate_plan(plan: dict[str, object]) -> tuple[str, str, list[str]]:
    install_root = _validate_root(str(plan["install_root"]), "install root")
    data_dir = _validate_root(str(plan["data_dir"]), "data root")
    managed_venv = _norm(str(plan["managed_venv"]))
    if managed_venv != _norm(os.path.join(data_dir, ".venv")):
        raise ValueError("managed runtime is not the exact data-root .venv")
    if os.path.lexists(managed_venv) and _is_reparse(managed_venv):
        raise ValueError("managed runtime is a symlink or reparse point")
    protected_paths = {_norm(str(path)) for path in plan.get("protected_paths", [])}
    if data_dir in protected_paths:
        raise ValueError(f"refusing protected data root: {data_dir}")
    try:
        common = os.path.commonpath((data_dir, install_root))
        overlap = common in {data_dir, install_root}
    except ValueError:
        overlap = False
    if overlap:
        raise ValueError("data root overlaps the binary install root")
    if (
        bool(plan.get("remove_data_dir"))
        and os.path.isdir(data_dir)
        and not any(
            os.path.exists(os.path.join(data_dir, marker)) and not _is_reparse(os.path.join(data_dir, marker))
            for marker in _OWNERSHIP_MARKERS
        )
    ):
        raise ValueError("data root has no DefenseClaw ownership marker")
    targets: list[str] = []
    for raw in plan.get("binary_targets", []):
        target = _norm(str(raw))
        name = os.path.basename(target).lower()
        retired = _RETIRED_COPY_RE.fullmatch(name)
        owned = name in _ALLOWED_BINARIES or (retired is not None and retired.group("name") in _ALLOWED_BINARIES)
        if not owned or os.path.dirname(target) != install_root:
            raise ValueError(f"binary target is not product-owned: {raw}")
        if os.path.lexists(target) and _is_reparse(target):
            raise ValueError(f"binary target is a symlink or reparse point: {raw}")
        targets.append(target)
    existing = [target for target in targets if os.path.lexists(target)]
    if existing:
        shim = os.path.join(install_root, "defenseclaw.cmd")
        if not os.path.isfile(shim) or _is_reparse(shim):
            raise ValueError("installer-owned defenseclaw.cmd shim is missing")
        with open(shim, encoding="utf-8-sig", errors="strict") as stream:
            contents = stream.read(16_385)
        if len(contents) > 16_384:
            raise ValueError("Windows CLI shim is oversized")
        expected_cli = os.path.join(managed_venv, "Scripts", "defenseclaw.exe")
        if f'"{expected_cli}" %*'.lower() not in contents.lower():
            raise ValueError("Windows CLI shim targets an unrelated runtime")
    targets.sort(key=lambda target: os.path.basename(target).lower() == "defenseclaw.cmd")
    return install_root, data_dir, targets


def _open_parent(plan: dict[str, object]) -> int:
    process_id = int(plan["parent_pid"])
    expected_image = _norm(str(plan["parent_executable"]))
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, process_id)
    if not handle:
        raise OSError(ctypes.get_last_error(), "could not open uninstall parent process")
    size = wintypes.DWORD(32768)
    image = ctypes.create_unicode_buffer(size.value)
    if not kernel32.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
        kernel32.CloseHandle(handle)
        raise OSError(ctypes.get_last_error(), "could not identify uninstall parent process")
    if _norm(image.value) != expected_image:
        kernel32.CloseHandle(handle)
        raise ValueError(
            f"uninstall parent process identity changed: expected {expected_image}, got {_norm(image.value)}"
        )
    return handle


def _parent_pids(kernel32) -> dict[int, int]:
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        return {}
    parents: dict[int, int] = {}
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return parents


def _open_launchers(plan: dict[str, object]) -> list[tuple[int, float]]:
    """Open the managed-runtime launchers waiting on the uninstall CLI.

    defenseclaw.cmd runs Scripts/defenseclaw.exe, which can start the venv's
    python.exe launcher, which starts the base interpreter. cmd.exe reads the
    rest of the shim only after the outermost launcher returns, and that can
    be well after the base interpreter exits. Deleting the shim earlier ends a
    successful uninstall with "The batch file cannot be found" and exit 1.
    Ancestors whose image lives in the managed runtime's Scripts folder are
    opened, then the cmd.exe running the shim (a shorter wait, since an
    interactive prompt stays open); the walk stops at any other process.
    PowerShell and cmd.exe start the installer's defenseclaw.exe instead of
    the shim (GAP-2237): it is opened too, and the walk ends there, since no
    batch file is read after it.
    Each entry is (handle, seconds to wait at most).
    """
    kernel32 = _kernel32()
    scripts = _norm(os.path.join(str(plan["managed_venv"]), "Scripts")) + os.sep
    cli_launcher = _norm(os.path.join(str(plan["install_root"]), "defenseclaw.exe"))
    parents = _parent_pids(kernel32)
    handles: list[tuple[int, float]] = []
    process_id = parents.get(int(plan["parent_pid"]), 0)
    for _ in range(_MAX_LAUNCHER_DEPTH):
        if not process_id:
            break
        handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, process_id)
        if not handle:
            break
        size = wintypes.DWORD(32768)
        image = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
            kernel32.CloseHandle(handle)
            break
        if _norm(image.value).startswith(scripts):
            handles.append((handle, _LAUNCHER_WAIT_SECONDS))
            process_id = parents.get(process_id, 0)
            continue
        if _norm(image.value) == cli_launcher:
            handles.append((handle, _LAUNCHER_WAIT_SECONDS))
            break
        if handles and os.path.basename(_norm(image.value)) == "cmd.exe":
            handles.append((handle, _SHIM_SHELL_WAIT_SECONDS))
        else:
            kernel32.CloseHandle(handle)
        break
    return handles


def _interpreter_dirs(plan: dict[str, object], data_dir: str) -> list[str]:
    """Validate the folders that hold this helper's own Python.

    Each is the data dir's .uv folder or a uv "python" folder, holds
    sys.executable, is reached through no link or junction, and has no
    cmd.exe metacharacter.
    """
    executable = _norm(os.path.realpath(sys.executable))
    dirs: list[str] = []
    for raw in plan.get("interpreter_dirs", []) or []:
        path = _validate_root(str(raw), "interpreter folder")
        name = os.path.basename(path)
        allowed = path == _norm(os.path.join(data_dir, ".uv")) or (
            name == "python" and os.path.basename(os.path.dirname(path)) == "uv"
        )
        holds = _contains(path, executable)
        if not allowed or not holds or _CMD_METACHARACTERS & set(path) or not os.path.isdir(path):
            raise ValueError(f"interpreter folder is not the helper's uv Python: {raw}")
        dirs.append(path)
    return dirs


_EMPTY_DIR_RD_TRIES = 30
_LOCK_CLOCK_SLACK_SECONDS = 0.5


class _SupersededError(Exception):
    """A new install started in the data dir; the cleanup must not touch it."""


def _superseded_detail(data_dir: str) -> str:
    return (
        f"a new DefenseClaw install started in {data_dir} before this cleanup finished, so the cleanup "
        "stopped and left that folder and its launchers to the new install; nothing needs to be removed by hand"
    )


def _check_not_superseded(data_dir: str, since: float) -> None:
    """Stop before deleting anything once an installer holds its lock in data_dir (GAP-2149).

    A lock older than this helper is a leftover, not a new install. NTFS
    stamps file times from the coarse system clock (one ~16 ms tick behind
    time.time()), so a lock taken just after the helper started can look a
    little older; _LOCK_CLOCK_SLACK_SECONDS absorbs that.
    """
    try:
        changed = os.lstat(os.path.join(data_dir, _INSTALL_LOCK)).st_mtime
    except OSError:
        return
    if changed >= since - _LOCK_CLOCK_SLACK_SECONDS:
        raise _SupersededError(_superseded_detail(data_dir))


def _result_step(status_path: str, gone: list[str], data_dir: str = "") -> str:
    """cmd.exe step that writes the uninstall result once the after-exit removal ran.

    It says failed with the first folder in gone that is still there, else
    succeeded (GAP-1960). By then the helper had emptied data_dir, so an
    installer's entry in it means a new install now owns it: superseded, not
    "remove it by hand" (GAP-2149).
    """
    step = f'(echo {{"status": "succeeded"}}>"{status_path}")'
    for path in reversed(gone):
        detail = json.dumps(f"could not remove {path}; remove it by hand")
        step = f'(if exist "{path}" (echo {{"status": "failed", "detail": {detail}}}>"{status_path}") else {step})'
    if data_dir:
        detail = json.dumps(_superseded_detail(data_dir))
        for name in reversed(_NEW_INSTALL_ENTRIES):
            marker = os.path.join(data_dir, name)
            step = (
                f'(if exist "{marker}" (echo {{"status": "superseded", "detail": {detail}}}>"{status_path}") '
                f"else {step})"
            )
    return step


def _remove_after_exit(
    dirs: list[str],
    empty_dirs: list[str],
    *,
    status_path: str = "",
    gone: list[str] | None = None,
    data_dir: str = "",
) -> bool:
    """Start cmd.exe to remove dirs (and then empty_dirs, if empty) after this process exits.

    rd /s does not follow junctions, and rd without /s removes only an
    empty folder. With status_path, cmd.exe then writes the result there:
    failed if a dir, its renamed copy or a folder in gone is still there.
    Returns whether it will write that result.
    """
    if not dirs:
        return False
    must_go: list[str] = []
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    cmd = os.path.join(system_root, "System32", "cmd.exe")
    steps = ["ping -n 4 127.0.0.1 >nul"]
    for path in dirs:
        # Rename first, then delete the renamed folder: the rename is instant,
        # so a reinstall that recreates the folder while rd still runs keeps
        # its new files (GAP-1647). Retry the rename once; if it still fails,
        # fall back to removing the folder in place as before.
        tombstone_name = f"{os.path.basename(path)}.dc-removed-{os.urandom(4).hex()}"
        tombstone = os.path.join(os.path.dirname(path), tombstone_name)
        must_go.extend((path, tombstone))
        rename = f'ren "{path}" "{tombstone_name}" 2>nul'
        steps.append(
            f"({rename} || (ping -n 5 127.0.0.1 >nul & {rename}))"
            # Parenthesize the if: cmd would run a trailing "& next step" only
            # in the else branch.
            f' & (if exist "{tombstone}" (rd /s /q "{tombstone}") else (rd /s /q "{path}"))'
        )
    # Retry the empty-folder rd: Defender or another reader can hold a deleted
    # file open, so the tombstone stays delete-pending for a few seconds and the
    # first rd sees a non-empty folder (GAP-1728). rd without /s still keeps a
    # folder that has real content.
    steps.extend(
        f'(for /l %i in (1,1,{_EMPTY_DIR_RD_TRIES}) do if exist "{path}" '
        f'(rd "{path}" 2>nul || ping -n 3 127.0.0.1 >nul))'
        for path in empty_dirs
        if not _CMD_METACHARACTERS & set(path)
    )
    must_go.extend(gone or [])
    writes_result = bool(status_path) and not _CMD_METACHARACTERS & set(status_path + "".join(must_go) + data_dir)
    if writes_result:
        steps.append(_result_step(status_path, must_go, data_dir))
    command = " & ".join(steps)
    flags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    subprocess.Popen(
        f'"{cmd}" /d /q /s /c "{command}"',
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
        cwd=system_root,
    )
    return writes_result


def _remove_tree(path: str, *, marker_names: set[str] | None = None, skip: set[str] | None = None) -> None:
    """Remove a tree without traversing a reparse-point entry.

    The paths in skip (normalized) stay, and so does each folder above them.
    """
    if _is_reparse(path):
        raise ValueError(f"refusing reparse-point data root: {path}")
    with os.scandir(path) as entries:
        children = list(entries)
    marker_names = marker_names or set()
    skip = skip or set()
    if _norm(path) in skip:
        return
    for marker_pass in (False, True):
        for entry in children:
            if (entry.name in marker_names) != marker_pass:
                continue
            if _norm(entry.path) in skip:
                continue
            if _is_reparse(entry.path):
                if entry.is_dir(follow_symlinks=False):
                    os.rmdir(entry.path)
                else:
                    os.unlink(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                _remove_tree(entry.path, skip=skip)
            else:
                os.unlink(entry.path)
    if any(_contains(_norm(path), kept) for kept in skip):
        return
    os.rmdir(path)


def _contains(parent: str, child: str) -> bool:
    try:
        return os.path.commonpath((parent, child)) == parent
    except ValueError:
        return False


def _retry(action, description: str) -> None:
    last_error: Exception | None = None
    for _ in range(80):
        try:
            action()
            return
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            last_error = exc
            time.sleep(0.125)
    raise OSError(f"{description} failed after waiting for file release: {last_error}") from last_error


def _data_left_detail(plan: dict[str, object], data_dir: str, error: OSError) -> str:
    """Say what is left of a data folder that could not go and what to do (GAP-2055)."""
    held = getattr(error.__cause__, "filename", "") or ""
    shim = os.path.join(str(plan["install_root"]), "defenseclaw.cmd")
    flags = " --binaries" if plan.get("remove_empty_install_root") else ""
    # PowerShell (the Windows Terminal default) needs the & call operator
    # before a quoted command path; Command Prompt rejects it (GAP-2082).
    rerun = (
        f'run & "{shim}" uninstall --all{flags} --yes again in PowerShell (in Command Prompt, leave out the &)'
        if os.path.isfile(shim)
        else "remove it by hand"
    )
    if held:
        detail = f"could not remove {data_dir}: {held} is in use by another program. Close that program, then {rerun}."
    else:
        detail = f"could not remove {data_dir}: {error.__cause__ or error}. To finish, {rerun}."
    try:
        left = sorted(os.listdir(data_dir))
    except OSError:
        left = []
    names = ", ".join(f"{name} (holds API keys)" if name == ".env" else name for name in left)
    return f"{detail} Still there: {names}." if names else detail


def _remove_earlier_results(status_path: str) -> None:
    """Remove the result files earlier uninstall runs left beside this one.

    Each run's result stays for the operator to read; only the newest is
    kept, so repeated uninstalls do not pile them up in TEMP.
    """
    folder, current = os.path.split(status_path)
    try:
        with os.scandir(folder) as entries:
            for entry in entries:
                name = entry.name
                if (
                    name == current
                    or not name.startswith("defenseclaw-uninstall-result-")
                    or not name.endswith(".json")
                    or not entry.is_file(follow_symlinks=False)
                    or _is_reparse(entry.path)
                ):
                    continue
                try:
                    os.unlink(entry.path)
                except OSError:
                    pass
    except OSError:
        pass


def _write_json(path: str, payload: dict[str, object]) -> None:
    temporary = f"{path}.tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True)
    os.replace(temporary, path)


def main() -> int:
    if sys.platform != "win32" or len(sys.argv) != 2:
        return 2
    manifest_path = os.path.abspath(sys.argv[1])
    status_path = ""
    ready_path = ""
    handle = 0
    launchers: list[tuple[int, float]] = []
    after_exit: list[str] = []
    after_exit_empty: list[str] = []
    gone: list[str] = []
    deferred = False
    started_at = time.time()
    try:
        with open(manifest_path, encoding="utf-8") as stream:
            plan = json.load(stream)
        status_path = os.path.abspath(str(plan["status_path"]))
        ready_path = os.path.abspath(str(plan["ready_path"]))
        _, data_dir, targets = _validate_plan(plan)
        interpreter_dirs = _interpreter_dirs(plan, data_dir)
        handle = _open_parent(plan)
        try:
            launchers = _open_launchers(plan)
        except OSError:
            launchers = []
        # The CLI prints this path once it sees ready, so it exists from then
        # on and is the only result file in TEMP (GAP-2054).
        _write_json(
            status_path,
            {
                "status": "scheduled",
                "detail": "cleanup starts when the uninstall command exits; "
                "this file says succeeded or failed when it finishes",
            },
        )
        _remove_earlier_results(status_path)
        _write_json(ready_path, {"status": "ready"})

        kernel32 = _kernel32()
        if kernel32.WaitForSingleObject(handle, 120_000) != 0:
            raise TimeoutError("uninstall parent did not exit within 120 seconds")
        # Bounded: a launcher or shell that outlives its wait does not block
        # cleanup.
        started = time.monotonic()
        for launcher, limit in launchers:
            remaining = max(0, int((started + limit - time.monotonic()) * 1000))
            kernel32.WaitForSingleObject(launcher, remaining)

        # cmd.exe resumes the shim just after its launcher child exits. Leave a
        # bounded unwind window before removing launcher files; all paths are
        # revalidated again below before any deletion occurs.
        time.sleep(_LAUNCHER_UNWIND_GRACE_SECONDS)

        install_root, data_dir, targets = _validate_plan(plan)
        if bool(plan.get("remove_data_dir")) and os.path.lexists(data_dir):

            def remove_data() -> None:
                _validate_plan(plan)
                _check_not_superseded(data_dir, started_at)
                _remove_tree(data_dir, marker_names=_OWNERSHIP_MARKERS, skip=set(interpreter_dirs))

            # Data first: if it cannot go, the launchers stay, so the
            # uninstall can run again (GAP-2055).
            try:
                _retry(remove_data, f"remove {data_dir}")
            except OSError as exc:
                raise OSError(_data_left_detail(plan, data_dir, exc)) from exc
        # The data dir is gone (or only the helper's .uv is left in it), so
        # the ownership-marker check no longer applies.
        targets_plan = {**plan, "remove_data_dir": False}
        for target in targets:

            def remove_target(target=target):
                _validate_plan(targets_plan)
                _check_not_superseded(data_dir, started_at)
                os.unlink(target)

            _retry(remove_target, f"remove {target}")
        if bool(plan.get("remove_empty_install_root")) and targets:
            # rmdir removes only an empty folder: one other tools use stays.
            try:
                os.rmdir(install_root)
            except OSError:
                pass
        after_exit = interpreter_dirs
        after_exit_empty = [data_dir] if bool(plan.get("remove_data_dir")) else []
        after_exit_empty.extend(
            os.path.dirname(path) for path in interpreter_dirs if os.path.basename(path) == "python"
        )
        gone = [data_dir] if bool(plan.get("remove_data_dir")) else []
        if after_exit:
            # The folders that hold this Python go after it exits; cmd.exe
            # rewrites this file once that ran (GAP-1960).
            _write_json(
                status_path,
                {
                    "status": "removing",
                    "detail": "the last folders are removed after the helper exits; "
                    "this file says succeeded or failed when that finishes",
                },
            )
            deferred = True
        else:
            _write_json(status_path, {"status": "succeeded"})
        return 0
    except _SupersededError as exc:
        try:
            _write_json(status_path, {"status": "superseded", "detail": str(exc)})
        except OSError:
            pass
        return 0
    except Exception as exc:  # noqa: BLE001 - helper result boundary.
        payload = {"status": "failed", "detail": str(exc)}
        destination = status_path or f"{manifest_path}.failed.json"
        try:
            _write_json(destination, payload)
            if ready_path and not os.path.exists(ready_path):
                _write_json(ready_path, payload)
        except OSError:
            pass
        return 1
    finally:
        if handle:
            _kernel32().CloseHandle(handle)
        for launcher, _limit in launchers:
            _kernel32().CloseHandle(launcher)
        try:
            os.unlink(manifest_path)
        except OSError:
            pass
        if ready_path:
            try:
                os.unlink(ready_path)
            except OSError:
                pass
        try:
            os.unlink(__file__)
            os.rmdir(os.path.dirname(__file__))
        except OSError:
            pass
        result: dict[str, object] = {"status": "succeeded"}
        try:
            if _remove_after_exit(
                after_exit,
                after_exit_empty,
                status_path=status_path if deferred else "",
                gone=gone,
                data_dir=data_dir if gone else "",
            ):
                result = {}
        except OSError as exc:
            result = {"status": "failed", "detail": f"could not start the final removal: {exc}"}
        if deferred and result:
            try:
                _write_json(status_path, result)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
