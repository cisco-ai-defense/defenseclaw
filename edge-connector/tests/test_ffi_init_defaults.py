"""FFI adapters must not claim an accepted OTA policy on blank flash."""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import generic_hook
import picoclaw_hook


@pytest.mark.parametrize("adapter", ["generic", "picoclaw"])
@pytest.mark.parametrize("configured,want", [(None, 0), ("7", 7)])
def test_ffi_initial_policy_version(monkeypatch, adapter, configured, want):
    if configured is None:
        monkeypatch.delenv("DCLAW_POLICY_VERSION", raising=False)
    else:
        monkeypatch.setenv("DCLAW_POLICY_VERSION", configured)

    module = generic_hook if adapter == "generic" else picoclaw_hook
    info_type = module._DclawDeviceInfo if adapter == "generic" else module.DclawDeviceInfo
    seen = []
    lib = MagicMock()

    def init(info_pointer):
        seen.append(ctypes.cast(info_pointer, ctypes.POINTER(info_type)).contents.policy_version)
        return 0

    lib.dclaw_init.side_effect = init
    with patch.object(module.ctypes, "CDLL", return_value=lib):
        if adapter == "generic":
            module._FFIBackend("/synthetic/libdclaw_core.so")
        else:
            module.DclawEngine("/synthetic/libdclaw_core.so").init()
    assert seen == [want]
