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


class ClipboardError(RuntimeError):
    """A concise, operator-safe clipboard failure."""


class ClipboardAPI(Protocol):
    """Injectable native boundary used by hermetic unit tests."""

    def open(self) -> bool: ...

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

    def open(self) -> bool:
        return bool(self._open(None))

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
            self._free(handle)
            raise ClipboardError("clipboard memory lock failed")
        try:
            ctypes.memmove(pointer, payload, len(payload))
        except BaseException:
            self._unlock(handle)
            self._free(handle)
            raise
        else:
            # A zero return is also the documented successful final unlock.
            self._unlock(handle)
        return int(handle)

    def free(self, handle: int) -> None:
        self._free(handle)

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
            self._unlock(handle)


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
    deadline = monotonic() + timeout
    while not native.open():
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ClipboardError("clipboard unavailable")
        sleep(min(retry_interval, remaining))

    handle = 0
    transferred = False
    primary_error: BaseException | None = None
    try:
        if not native.empty():
            raise ClipboardError("clipboard access denied")
        handle = native.allocate_unicode(payload)
        if not native.set_unicode(handle):
            raise ClipboardError("clipboard write failed")
        transferred = True
        if native.read_unicode() != text:
            raise ClipboardError("clipboard verification failed")
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if handle and not transferred:
            native.free(handle)
        try:
            native.close()
        except ClipboardError:
            if primary_error is None:
                raise
