"""Tests for the generic Edge Connector adapter (generic_hook.py).

Run:
    cd edge-connector
    python -m pytest tests/test_generic_hook.py -v
"""
from __future__ import annotations

import json
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the tools directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from generic_hook import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_WARN,
    CAP_EXEC_SHELL,
    CAP_NET_FETCH,
    CAP_READ_FS,
    CAP_SENSOR_READ,
    CAP_WRITE_FS,
    DEFAULT_TOOL_CAP_MAP,
    EdgeConnector,
    Verdict,
    _FFIBackend,
    _SocketBackend,
)


# -----------------------------------------------------------------------
# Verdict dataclass
# -----------------------------------------------------------------------
class TestVerdict:
    def test_from_raw_allow(self):
        v = Verdict.from_raw(ACTION_ALLOW, 0x01, severity=0, cached=False)
        assert v.action == ACTION_ALLOW
        assert v.blocked is False
        assert v.reason == "POLICY_TABLE"
        assert v.cached is False

    def test_from_raw_block(self):
        v = Verdict.from_raw(ACTION_BLOCK, 0x05, severity=3, cached=True)
        assert v.blocked is True
        assert v.reason == "RATE_LIMIT"
        assert v.severity == 3
        assert v.cached is True

    def test_from_raw_warn(self):
        v = Verdict.from_raw(ACTION_WARN, 0x02)
        assert v.blocked is False
        assert v.action == ACTION_WARN
        assert v.reason == "CAP_SEQUENCE"

    def test_from_raw_unknown_reason(self):
        v = Verdict.from_raw(ACTION_BLOCK, 0xFF)
        assert v.reason == "UNKNOWN(0xff)"

    def test_allow_factory(self):
        v = Verdict.allow()
        assert v.blocked is False
        assert v.reason == "ALLOW"

    def test_error_factory(self):
        v = Verdict.error("ENGINE_ERROR: timeout")
        assert v.blocked is True
        assert v.reason == "ENGINE_ERROR: timeout"

    def test_verdict_is_frozen(self):
        v = Verdict.allow()
        with pytest.raises(AttributeError):
            v.blocked = True  # type: ignore[misc]


# -----------------------------------------------------------------------
# Tool-to-capability mapping
# -----------------------------------------------------------------------
class TestToolCapMapping:
    def test_known_tools_mapped(self):
        assert DEFAULT_TOOL_CAP_MAP["exec"] == CAP_EXEC_SHELL
        assert DEFAULT_TOOL_CAP_MAP["read_file"] == CAP_READ_FS
        assert DEFAULT_TOOL_CAP_MAP["web_search"] == CAP_NET_FETCH
        assert DEFAULT_TOOL_CAP_MAP["write_file"] == CAP_WRITE_FS
        assert DEFAULT_TOOL_CAP_MAP["get_sensors"] == CAP_SENSOR_READ

    def test_custom_map_override(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
        ec.tool_cap_map["my_custom_tool"] = CAP_WRITE_FS
        assert ec._resolve_capability("my_custom_tool") == CAP_WRITE_FS

    def test_unknown_tool_defaults_to_sensor_read(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
        assert ec._resolve_capability("check_weather") == CAP_SENSOR_READ

    def test_dangerous_keyword_escalation(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
        assert ec._resolve_capability("run_dangerous") == CAP_EXEC_SHELL
        assert ec._resolve_capability("delete_everything") == CAP_EXEC_SHELL
        assert ec._resolve_capability("rm_old_files") == CAP_EXEC_SHELL


# -----------------------------------------------------------------------
# Destination extraction
# -----------------------------------------------------------------------
class TestDestinationExtraction:
    def test_extract_url(self):
        dest = EdgeConnector._extract_destination(
            "fetch", {"url": "https://evil.com/payload"}
        )
        assert dest == "evil.com"

    def test_extract_href(self):
        dest = EdgeConnector._extract_destination(
            "fetch", {"href": "http://example.org/path"}
        )
        assert dest == "example.org"

    def test_no_url(self):
        dest = EdgeConnector._extract_destination("fetch", {"query": "hello"})
        assert dest == ""

    def test_empty_arguments(self):
        dest = EdgeConnector._extract_destination("fetch", {})
        assert dest == ""


# -----------------------------------------------------------------------
# Evaluate with mock FFI backend
# -----------------------------------------------------------------------
class TestEvaluateWithMockFFI:
    def _make_connector(self, verdict: Verdict) -> EdgeConnector:
        """Create an EdgeConnector with a mock FFI backend."""
        ec = EdgeConnector.__new__(EdgeConnector)
        ec._fail_open = False
        ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
        ec._session_id = 1
        mock_backend = MagicMock()
        mock_backend.evaluate.return_value = verdict
        ec._backend = mock_backend
        return ec

    def test_allow_verdict(self):
        ec = self._make_connector(Verdict.allow())
        v = ec.evaluate(tool_name="read_file", arguments={"path": "/etc/hosts"})
        assert v.blocked is False

    def test_block_verdict(self):
        ec = self._make_connector(
            Verdict.from_raw(ACTION_BLOCK, 0x07)  # CLOUD_TIMEOUT
        )
        v = ec.evaluate(tool_name="exec", arguments={"command": "whoami"})
        assert v.blocked is True
        assert v.reason == "CLOUD_TIMEOUT"

    def test_arguments_serialized_as_content(self):
        ec = self._make_connector(Verdict.allow())
        args = {"command": "ls -la"}
        ec.evaluate(tool_name="bash", arguments=args)
        call_kwargs = ec._backend.evaluate.call_args
        content_arg = call_kwargs.kwargs.get("content") or call_kwargs[1].get("content")
        # Fall back to positional
        if content_arg is None:
            content_arg = call_kwargs[0][4] if len(call_kwargs[0]) > 4 else None
        assert content_arg is not None

    def test_explicit_content_takes_precedence(self):
        ec = self._make_connector(Verdict.allow())
        ec.evaluate(
            tool_name="bash",
            arguments={"command": "ls"},
            content="custom content payload",
        )
        call_args = ec._backend.evaluate.call_args
        # Check that "custom content payload" was passed
        all_args = list(call_args[0]) + list(call_args[1].values())
        assert any("custom content payload" in str(a) for a in all_args)


# -----------------------------------------------------------------------
# Fallback to socket when FFI unavailable
# -----------------------------------------------------------------------
class TestFallbackBehavior:
    @patch("generic_hook._FFIBackend.__init__", side_effect=OSError("no .so"))
    @patch("generic_hook.Path.exists", return_value=False)
    def test_fail_open_returns_allow(self, mock_exists, mock_ffi):
        ec = EdgeConnector(fail_open=True)
        v = ec.evaluate(tool_name="anything")
        assert v.blocked is False

    @patch("generic_hook._FFIBackend.__init__", side_effect=OSError("no .so"))
    @patch("generic_hook.Path.exists", return_value=False)
    def test_fail_closed_raises(self, mock_exists, mock_ffi):
        with pytest.raises(ConnectionError):
            EdgeConnector(fail_open=False)

    def test_backend_error_fail_open(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        ec._fail_open = True
        ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
        ec._session_id = 1
        mock_backend = MagicMock()
        mock_backend.evaluate.side_effect = RuntimeError("engine crash")
        ec._backend = mock_backend

        v = ec.evaluate(tool_name="exec", arguments={"cmd": "ls"})
        assert v.blocked is False  # fail-open

    def test_backend_error_fail_closed(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        ec._fail_open = False
        ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
        ec._session_id = 1
        mock_backend = MagicMock()
        mock_backend.evaluate.side_effect = RuntimeError("engine crash")
        ec._backend = mock_backend

        v = ec.evaluate(tool_name="exec", arguments={"cmd": "ls"})
        assert v.blocked is True
        assert "ENGINE_ERROR" in v.reason


# -----------------------------------------------------------------------
# Shutdown
# -----------------------------------------------------------------------
class TestShutdown:
    def test_shutdown_calls_backend(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        mock_backend = MagicMock()
        ec._backend = mock_backend
        ec.shutdown()
        mock_backend.shutdown.assert_called_once()
        assert ec._backend is None

    def test_shutdown_no_backend(self):
        ec = EdgeConnector.__new__(EdgeConnector)
        ec._backend = None
        ec.shutdown()  # should not raise
