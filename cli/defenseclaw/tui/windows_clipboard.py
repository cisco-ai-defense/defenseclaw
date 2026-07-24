"""Bounded, resource-safe access to the native Windows clipboard."""

from __future__ import annotations

import ctypes
import time
from collections.abc import Callable
from ctypes import wintypes
from typing import Protocol

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
MAX_CLIPBOARD_BYTES = 16 * 1024 * 1024
HWND_MESSAGE = -3


class ClipboardError(RuntimeError):
    """A concise, operator-safe clipboard failure."""


class ClipboardAPI(Protocol):
    """Injectable native boundary used by hermetic unit tests."""

    def create_owner(self) -> int: ...

    def destroy_owner(self, owner: int) -> None: ...

    def open(self, owner: int | None = None) -> bool: ...

    def close(self) -> None: ...

    def empty(self) -> bool: ...

    def allocate_unicode(self, payload: bytes) -> int: ...

    def free(self, handle: int) -> None: ...

    def set_unicode(self, handle: int) -> bool: ...

    def read_unicode(self) -> str: ...


class Win32ClipboardAPI:
    """Thin ctypes wrapper around user32/kernel32 clipboard primitives."""

    def __init__(self) -> None:
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        self._open = self._user32.OpenClipboard
        self._open.argtypes = [wintypes.HWND]
        self._open.restype = wintypes.BOOL
        self._close = self._user32.CloseClipboard
        self._close.argtypes = []
        self._close.restype = wintypes.BOOL
        self._empty = self._user32.EmptyClipboard
        self._empty.argtypes = []
        self._empty.restype = wintypes.BOOL
        self._set = self._user32.SetClipboardData
        self._set.argtypes = [wintypes.UINT, wintypes.HANDLE]
        self._set.restype = wintypes.HANDLE
        self._get = self._user32.GetClipboardData
        self._get.argtypes = [wintypes.UINT]
        self._get.restype = wintypes.HANDLE
        self._create_window = self._user32.CreateWindowExW
        self._create_window.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.INT,
            wintypes.INT,
            wintypes.INT,
            wintypes.INT,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        self._create_window.restype = wintypes.HWND
        self._destroy_window = self._user32.DestroyWindow
        self._destroy_window.argtypes = [wintypes.HWND]
        self._destroy_window.restype = wintypes.BOOL

        self._alloc = self._kernel32.GlobalAlloc
        self._alloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        self._alloc.restype = wintypes.HGLOBAL
        self._lock = self._kernel32.GlobalLock
        self._lock.argtypes = [wintypes.HGLOBAL]
        self._lock.restype = wintypes.LPVOID
        self._unlock = self._kernel32.GlobalUnlock
        self._unlock.argtypes = [wintypes.HGLOBAL]
        self._unlock.restype = wintypes.BOOL
        self._free = self._kernel32.GlobalFree
        self._free.argtypes = [wintypes.HGLOBAL]
        self._free.restype = wintypes.HGLOBAL
        self._get_module_handle = self._kernel32.GetModuleHandleW
        self._get_module_handle.argtypes = [wintypes.LPCWSTR]
        self._get_module_handle.restype = wintypes.HINSTANCE

    def create_owner(self) -> int:
        """Create a nonvisible HWND that can legally own clipboard data."""
        module = self._get_module_handle(None)
        owner = self._create_window(
            0,
            "STATIC",
            "DefenseClawClipboardOwner",
            0,
            0,
            0,
            0,
            0,
            wintypes.HWND(HWND_MESSAGE),
            None,
            module,
            None,
        )
        if not owner:
            raise ClipboardError("clipboard owner creation failed")
        return int(owner)

    def destroy_owner(self, owner: int) -> None:
        if not self._destroy_window(owner):
            raise ClipboardError("clipboard owner cleanup failed")

    def open(self, owner: int | None = None) -> bool:
        return bool(self._open(owner))

    def close(self) -> None:
        if not self._close():
            raise ClipboardError("clipboard close failed")

    def empty(self) -> bool:
        return bool(self._empty())

    def allocate_unicode(self, payload: bytes) -> int:
        handle = self._alloc(GMEM_MOVEABLE, len(payload))
        if not handle:
            raise ClipboardError("clipboard allocation failed")
        pointer = self._lock(handle)
        if not pointer:
            self.free(int(handle))
            raise ClipboardError("clipboard memory lock failed")
        unlock_attempted = False
        try:
            ctypes.memmove(pointer, payload, len(payload))
            unlock_attempted = True
            self._unlock_checked(handle)
        except BaseException:
            if not unlock_attempted:
                try:
                    self._unlock_checked(handle)
                except ClipboardError:
                    pass
            self.free(int(handle))
            raise
        return int(handle)

    def free(self, handle: int) -> None:
        if self._free(handle):
            raise ClipboardError("clipboard free failed")

    def set_unicode(self, handle: int) -> bool:
        return bool(self._set(CF_UNICODETEXT, handle))

    def read_unicode(self) -> str:
        handle = self._get(CF_UNICODETEXT)
        if not handle:
            raise ClipboardError("clipboard read-back failed")
        pointer = self._lock(handle)
        if not pointer:
            raise ClipboardError("clipboard read-back lock failed")
        try:
            return ctypes.wstring_at(pointer)
        finally:
            self._unlock_checked(handle)

    def _unlock_checked(self, handle: int) -> None:
        # GlobalUnlock returns zero both on a successful final unlock and on
        # failure. Last-error is the only way to distinguish the two cases.
        ctypes.set_last_error(0)
        if not self._unlock(handle) and ctypes.get_last_error():
            raise ClipboardError("clipboard memory unlock failed")


def copy_windows_clipboard(
    text: str,
    *,
    api: ClipboardAPI | None = None,
    timeout: float = 0.5,
    retry_interval: float = 0.025,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Write and verify Unicode text, retrying only the busy open operation.

    ``SetClipboardData`` transfers ownership of the allocation to Windows on
    success. Before that point every failure frees it, and every successful
    open is paired with ``CloseClipboard``.
    """
    payload = text.encode("utf-16-le") + b"\x00\x00"
    if len(payload) > MAX_CLIPBOARD_BYTES:
        raise ClipboardError("clipboard content exceeds 16 MiB limit")
    if timeout < 0 or retry_interval <= 0:
        raise ValueError("invalid clipboard retry bounds")

    native = api or Win32ClipboardAPI()
    owner = native.create_owner()
    opened = False
    handle = 0
    transferred = False
    operation_error: BaseException | None = None
    try:
        deadline = monotonic() + timeout
        while not native.open(owner):
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise ClipboardError("clipboard unavailable")
            sleep(min(retry_interval, remaining))
        opened = True
        if not native.empty():
            raise ClipboardError("clipboard access denied")
        handle = native.allocate_unicode(payload)
        if not native.set_unicode(handle):
            raise ClipboardError("clipboard write failed")
        transferred = True
        if native.read_unicode() != text:
            raise ClipboardError("clipboard verification failed")
    except BaseException as exc:
        operation_error = exc

    free_error: BaseException | None = None
    if handle and not transferred:
        try:
            native.free(handle)
        except BaseException as exc:
            free_error = exc

    close_error: BaseException | None = None
    if opened:
        try:
            native.close()
        except BaseException as exc:
            close_error = exc

    owner_error: BaseException | None = None
    try:
        native.destroy_owner(owner)
    except BaseException as exc:
        owner_error = exc

    # A failed free means ownership was neither transferred nor reclaimed and
    # is therefore the most actionable cleanup failure. Otherwise preserve the
    # operation error, followed by close/owner cleanup errors after success.
    error = free_error or operation_error or close_error or owner_error
    if error is not None:
        raise error
