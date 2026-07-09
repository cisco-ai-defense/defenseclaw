"""Standalone Windows deferred cleanup helper.

The CLI copies this standard-library-only file outside the managed virtual
environment before starting it. All paths arrive as JSON data; none are
interpolated into shell text.
"""

from __future__ import annotations

import ctypes
import json
import os
import stat
import sys
import time
from ctypes import wintypes
from pathlib import Path

_ALLOWED_BINARIES = {
    "defenseclaw.cmd",
    "defenseclaw-gateway.exe",
    "defenseclaw-hook.exe",
}
_OWNERSHIP_MARKERS = {"config.yaml", "audit.db", ".env", "policies", "quarantine", ".venv"}


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
        if name not in _ALLOWED_BINARIES or os.path.dirname(target) != install_root:
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


def _remove_tree(path: str, *, marker_names: set[str] | None = None) -> None:
    """Remove a tree without traversing a reparse-point entry."""
    if _is_reparse(path):
        raise ValueError(f"refusing reparse-point data root: {path}")
    with os.scandir(path) as entries:
        children = list(entries)
    marker_names = marker_names or set()
    for marker_pass in (False, True):
        for entry in children:
            if (entry.name in marker_names) != marker_pass:
                continue
            if _is_reparse(entry.path):
                if entry.is_dir(follow_symlinks=False):
                    os.rmdir(entry.path)
                else:
                    os.unlink(entry.path)
            elif entry.is_dir(follow_symlinks=False):
                _remove_tree(entry.path)
            else:
                os.unlink(entry.path)
    os.rmdir(path)


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
    raise OSError(f"{description} failed after waiting for file release: {last_error}")


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
    try:
        with open(manifest_path, encoding="utf-8") as stream:
            plan = json.load(stream)
        status_path = os.path.abspath(str(plan["status_path"]))
        ready_path = os.path.abspath(str(plan["ready_path"]))
        _, data_dir, targets = _validate_plan(plan)
        handle = _open_parent(plan)
        _write_json(ready_path, {"status": "ready"})

        kernel32 = _kernel32()
        if kernel32.WaitForSingleObject(handle, 120_000) != 0:
            raise TimeoutError("uninstall parent did not exit within 120 seconds")

        _, data_dir, targets = _validate_plan(plan)
        for target in targets:

            def remove_target(target=target):
                _validate_plan(plan)
                os.unlink(target)

            _retry(remove_target, f"remove {target}")
        if bool(plan.get("remove_data_dir")) and os.path.lexists(data_dir):

            def remove_data() -> None:
                _validate_plan(plan)
                _remove_tree(data_dir, marker_names=_OWNERSHIP_MARKERS)

            _retry(remove_data, f"remove {data_dir}")
        _write_json(status_path, {"status": "succeeded"})
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


if __name__ == "__main__":
    raise SystemExit(main())
