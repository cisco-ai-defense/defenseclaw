"""Hermetic coverage for native Windows clipboard ownership and retries."""

from __future__ import annotations

import ctypes
import os
import time
from dataclasses import dataclass, field

import pytest
from defenseclaw.tui.windows_clipboard import (
    CF_UNICODETEXT,
    MAX_CLIPBOARD_BYTES,
    ClipboardError,
    Win32ClipboardAPI,
    copy_windows_clipboard,
)


@dataclass
class FakeClipboardAPI:
    opens_before_success: int = 0
    empty_ok: bool = True
    set_ok: bool = True
    read_override: str | None = None
    close_error: bool = False
    open_calls: int = 0
    close_calls: int = 0
    free_calls: list[int] = field(default_factory=list)
    allocated_payload: bytes = b""
    stored_text: str = ""

    def open(self) -> bool:
        self.open_calls += 1
        return self.open_calls > self.opens_before_success

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error:
            raise ClipboardError("clipboard close failed")

    def empty(self) -> bool:
        return self.empty_ok

    def allocate_unicode(self, payload: bytes) -> int:
        self.allocated_payload = payload
        self.stored_text = payload[:-2].decode("utf-16-le")
        return 41

    def free(self, handle: int) -> None:
        self.free_calls.append(handle)

    def set_unicode(self, handle: int) -> bool:
        assert handle == 41
        return self.set_ok

    def read_unicode(self) -> str:
        return self.stored_text if self.read_override is None else self.read_override


@pytest.mark.parametrize(
    "text",
    [
        "",
        "café 🛡️ 你好",
        "first line\r\nsecond line\nthird line",
        "x" * (1024 * 1024),
    ],
    ids=["empty", "unicode", "multiline", "large"],
)
def test_native_unicode_write_and_read_back(text: str) -> None:
    api = FakeClipboardAPI()

    copy_windows_clipboard(text, api=api)

    assert api.stored_text == text
    assert api.allocated_payload.endswith(b"\x00\x00")
    assert api.close_calls == 1
    assert api.free_calls == []  # successful SetClipboardData transfers ownership


def test_busy_clipboard_retries_with_bounded_sleep() -> None:
    api = FakeClipboardAPI(opens_before_success=2)
    clock = iter([0.0, 0.1, 0.2, 0.3])
    sleeps: list[float] = []

    copy_windows_clipboard(
        "retry",
        api=api,
        timeout=0.5,
        retry_interval=0.1,
        monotonic=lambda: next(clock),
        sleep=sleeps.append,
    )

    assert api.open_calls == 3
    assert sleeps == [0.1, 0.1]
    assert api.close_calls == 1


def test_busy_clipboard_timeout_has_no_allocation_or_close() -> None:
    api = FakeClipboardAPI(opens_before_success=99)
    clock = iter([0.0, 0.2, 0.5])

    with pytest.raises(ClipboardError, match="unavailable"):
        copy_windows_clipboard(
            "blocked",
            api=api,
            timeout=0.5,
            retry_interval=0.2,
            monotonic=lambda: next(clock),
            sleep=lambda _: None,
        )

    assert api.allocated_payload == b""
    assert api.close_calls == 0


def test_access_denied_closes_without_allocating() -> None:
    api = FakeClipboardAPI(empty_ok=False)

    with pytest.raises(ClipboardError, match="access denied"):
        copy_windows_clipboard("secret", api=api)

    assert api.allocated_payload == b""
    assert api.close_calls == 1


def test_failed_set_frees_allocation_and_closes() -> None:
    api = FakeClipboardAPI(set_ok=False)

    with pytest.raises(ClipboardError, match="write failed"):
        copy_windows_clipboard("secret", api=api)

    assert api.free_calls == [41]
    assert api.close_calls == 1


def test_read_back_mismatch_closes_after_ownership_transfer() -> None:
    api = FakeClipboardAPI(read_override="corrupt")

    with pytest.raises(ClipboardError, match="verification failed"):
        copy_windows_clipboard("expected", api=api)

    assert api.free_calls == []
    assert api.close_calls == 1


def test_close_failure_is_reported_after_successful_write() -> None:
    api = FakeClipboardAPI(close_error=True)

    with pytest.raises(ClipboardError, match="close failed"):
        copy_windows_clipboard("payload", api=api)

    assert api.close_calls == 1


def test_oversize_content_has_no_native_side_effect() -> None:
    api = FakeClipboardAPI()
    # ASCII UTF-16 consumes two bytes per character, plus its terminator.
    text = "x" * (MAX_CLIPBOARD_BYTES // 2)

    with pytest.raises(ClipboardError, match="exceeds"):
        copy_windows_clipboard(text, api=api)

    assert api.open_calls == 0
    assert api.allocated_payload == b""


def _open_native_clipboard(api: Win32ClipboardAPI, timeout: float = 1.0) -> None:
    deadline = time.monotonic() + timeout
    while not api.open():
        if time.monotonic() >= deadline:
            pytest.skip("native clipboard stayed busy; preserving operator clipboard state")
        time.sleep(0.025)


@pytest.mark.skipif(os.name != "nt", reason="native Windows clipboard round trip")
def test_native_win32_round_trip_restores_clipboard_state() -> None:
    """Use the real Win32 boundary without destroying an operator clipboard.

    Arbitrary clipboard formats cannot be reconstructed from a generic memory
    handle. Refuse to mutate when anything except Unicode text is present; an
    empty or text-only clipboard can be restored losslessly in ``finally``.
    """

    api = Win32ClipboardAPI()
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_formats = user32.EnumClipboardFormats
    enum_formats.argtypes = [ctypes.c_uint]
    enum_formats.restype = ctypes.c_uint

    _open_native_clipboard(api)
    formats: list[int] = []
    current = 0
    try:
        while current := int(enum_formats(current)):
            formats.append(current)
        unsupported = [value for value in formats if value != CF_UNICODETEXT]
        if unsupported:
            pytest.skip("native clipboard has non-text formats that cannot be restored losslessly")
        original = api.read_unicode() if CF_UNICODETEXT in formats else None
    finally:
        api.close()

    payload = "DefenseClaw clipboard café\r\n第二行 🛡️"
    try:
        copy_windows_clipboard(payload)
        _open_native_clipboard(api)
        try:
            assert api.read_unicode() == payload
        finally:
            api.close()
    finally:
        if original is None:
            _open_native_clipboard(api)
            try:
                assert api.empty()
            finally:
                api.close()
        else:
            copy_windows_clipboard(original)
