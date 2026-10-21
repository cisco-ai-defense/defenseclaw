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

import threading

from generic_hook import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_ESCALATE,
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


def _bare_connector(**overrides) -> EdgeConnector:
    """Create an EdgeConnector via __new__ with all required attributes."""
    ec = EdgeConnector.__new__(EdgeConnector)
    ec._fail_open = overrides.get("fail_open", False)
    ec.tool_cap_map = dict(DEFAULT_TOOL_CAP_MAP)
    ec._session_id = 1
    ec._backend_lock = threading.Lock()
    ec._fail_open_count = 0
    ec._fail_open_start = None
    ec._FAIL_OPEN_MAX_DURATION = 300
    ec._FAIL_OPEN_MAX_COUNT = 1000
    ec._allow_ffi = overrides.get("allow_ffi", False)
    ec._socket_path = overrides.get("socket_path", "/nonexistent/dclaw.sock")
    ec._lib_path = "/nonexistent/libdclaw_core.so"
    ec._backend = overrides.get("backend", None)
    return ec


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

    @pytest.mark.parametrize("action", [ACTION_ESCALATE, 4, 99, -1])
    def test_from_raw_non_permitting_actions_block(self, action):
        assert Verdict.from_raw(action, 0x06).blocked is True

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
        ec = _bare_connector()
        ec.tool_cap_map["my_custom_tool"] = CAP_WRITE_FS
        assert ec._resolve_capability("my_custom_tool") == CAP_WRITE_FS

    def test_unknown_tool_defaults_to_sensor_read(self):
        ec = _bare_connector()
        assert ec._resolve_capability("check_weather") == CAP_SENSOR_READ

    def test_dangerous_keyword_escalation(self):
        ec = _bare_connector()
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

    @pytest.mark.parametrize("url,want", [
        ("http://[2606:4700:4700::1111]/x", "[2606:4700:4700::1111]"),
        ("https://[2606:4700:4700::1111]:8443/x", "[2606:4700:4700::1111]"),
        ("https://1.1.1.1/x", "1.1.1.1"),
    ])
    def test_ip_literals_keep_engine_form(self, url, want):
        assert EdgeConnector._extract_destination("fetch", {"url": url}) == want

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
        mock_backend = MagicMock()
        mock_backend.evaluate.return_value = verdict
        return _bare_connector(backend=mock_backend)

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
# Chunked evaluation
# -----------------------------------------------------------------------
class TestChunkedEvaluation:
    @pytest.mark.parametrize("late_action", [ACTION_ESCALATE, 7, -1])
    def test_non_permitting_chunk_verdict_denies(self, late_action):
        backend = MagicMock()
        backend.evaluate.side_effect = [
            Verdict.allow(),
            Verdict.from_raw(late_action, 0x06),
            Verdict.allow(),
            Verdict.allow(),
        ]
        ec = _bare_connector(backend=backend)
        v = ec.evaluate(tool_name="read_file", content="x" * 9000)
        assert backend.evaluate.call_count == 2
        assert v.blocked is True
        assert v.action == late_action

    @staticmethod
    def _sent_contents(content: str) -> list[str]:
        backend = MagicMock()
        backend.evaluate.return_value = Verdict.allow()
        ec = _bare_connector(backend=backend)
        assert ec.evaluate(tool_name="read_file", content=content).blocked is False
        return [c.kwargs["content"] for c in backend.evaluate.call_args_list]

    @staticmethod
    def _escaped_len(text: str) -> int:
        return len(json.dumps(text)) - 2

    @pytest.mark.parametrize("content", [
        # Under 4095 raw bytes, but over the limit once quotes are escaped.
        ("a" * 2 + '"') * 1066 + "b" * 2,
        # Exactly at the old raw-byte limit; the daemon's in-place decoder
        # truncates beyond 4092 bytes.
        "x" * 4094,
        # Multi-byte characters are \uXXXX-escaped on the wire.
        "\u00e9" * 3000,
        "\U0001F600" * 1000 + "tail",
        "line\n" * 2000,
    ])
    def test_chunks_fit_daemon_limit_after_json_escaping(self, content):
        sent = self._sent_contents(content)
        assert len(sent) > 1
        limit = EdgeConnector._CONTENT_ESCAPED_MAX
        assert limit <= 4092
        for chunk in sent:
            assert self._escaped_len(chunk) <= limit
            assert "\ufffd" not in chunk
        # Windows overlap and together cover the whole content.
        rebuilt = sent[0]
        for prev, chunk in zip(sent, sent[1:]):
            overlap = min(EdgeConnector._CONTENT_OVERLAP, len(prev) // 2)
            assert chunk[:overlap] == prev[len(prev) - overlap:]
            rebuilt += chunk[overlap:]
        assert rebuilt == content

    def test_content_within_limit_is_sent_whole(self):
        content = '"' * 2046  # 4092 escaped characters
        assert self._sent_contents(content) == [content]

    def test_warn_chunk_is_kept(self):
        backend = MagicMock()
        backend.evaluate.side_effect = [
            Verdict.allow(), Verdict.from_raw(ACTION_WARN, 0x08), Verdict.allow(),
        ]
        ec = _bare_connector(backend=backend)
        v = ec.evaluate(tool_name="read_file", content="x" * 9000)
        assert v.action == ACTION_WARN
        assert v.blocked is False


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
        mock_backend = MagicMock()
        mock_backend.evaluate.side_effect = RuntimeError("engine crash")
        ec = _bare_connector(fail_open=True, backend=mock_backend)

        v = ec.evaluate(tool_name="exec", arguments={"cmd": "ls"})
        assert v.blocked is False  # fail-open

    def test_backend_error_fail_closed(self):
        mock_backend = MagicMock()
        mock_backend.evaluate.side_effect = RuntimeError("engine crash")
        ec = _bare_connector(fail_open=False, backend=mock_backend)

        v = ec.evaluate(tool_name="exec", arguments={"cmd": "ls"})
        assert v.blocked is True
        assert "ENGINE_ERROR" in v.reason


# -----------------------------------------------------------------------
# No silent switch from the daemon to an in-process engine
# -----------------------------------------------------------------------
class TestNoSilentFFIFallback:
    @patch("generic_hook._FFIBackend.__init__", return_value=None)
    @patch("generic_hook.Path.exists", return_value=False)
    def test_missing_socket_fails_closed_without_opt_in(self, _exists, ffi, monkeypatch):
        monkeypatch.delenv("DCLAW_ALLOW_FFI", raising=False)
        with pytest.raises(ConnectionError):
            EdgeConnector(fail_open=False)
        ffi.assert_not_called()

    @patch("generic_hook._FFIBackend.__init__", return_value=None)
    @patch("generic_hook.Path.exists", return_value=False)
    def test_missing_socket_uses_ffi_with_opt_in(self, _exists, ffi, monkeypatch):
        monkeypatch.setenv("DCLAW_ALLOW_FFI", "1")
        ec = EdgeConnector(fail_open=False)
        ffi.assert_called_once()
        assert isinstance(ec._backend, _FFIBackend)

    @patch("generic_hook._FFIBackend.__init__", return_value=None)
    def test_socket_error_fails_closed_without_opt_in(self, ffi):
        backend = _SocketBackend("/nonexistent/dclaw.sock")
        ec = _bare_connector(backend=backend)
        v = ec.evaluate(tool_name="read_file", arguments={"path": "/tmp/x"})
        assert v.blocked is True
        assert "ENGINE_ERROR" in v.reason
        ffi.assert_not_called()
        assert ec._backend is backend

    @patch("generic_hook._FFIBackend.evaluate", return_value=Verdict.allow())
    @patch("generic_hook._FFIBackend.__init__", return_value=None)
    def test_socket_error_falls_back_with_opt_in(self, ffi, _evaluate):
        backend = _SocketBackend("/nonexistent/dclaw.sock")
        ec = _bare_connector(backend=backend, allow_ffi=True)
        # Skip the liveness probe so the socket error happens inside evaluate().
        with patch.object(EdgeConnector, "_check_backend", lambda self: None):
            v = ec.evaluate(tool_name="read_file", arguments={"path": "/tmp/x"})
        ffi.assert_called_once()
        assert isinstance(ec._backend, _FFIBackend)
        assert v.blocked is False

    @patch("generic_hook._FFIBackend.__init__", return_value=None)
    def test_dead_socket_check_keeps_socket_without_opt_in(self, ffi):
        backend = _SocketBackend("/nonexistent/dclaw.sock")
        ec = _bare_connector(backend=backend)
        ec._check_backend()
        assert ec._backend is backend
        ffi.assert_not_called()

    def test_session_id_override_reaches_backend(self):
        backend = MagicMock()
        backend.evaluate.return_value = Verdict.allow()
        ec = _bare_connector(backend=backend)
        ec.evaluate(tool_name="read_file", arguments={"a": 1}, session_id=42)
        assert backend.evaluate.call_args.kwargs["session_id"] == 42


# -----------------------------------------------------------------------
# Shutdown
# -----------------------------------------------------------------------
class TestShutdown:
    def test_shutdown_calls_backend(self):
        mock_backend = MagicMock()
        ec = _bare_connector(backend=mock_backend)
        ec.shutdown()
        mock_backend.shutdown.assert_called_once()
        assert ec._backend is None

    def test_shutdown_no_backend(self):
        ec = _bare_connector()
        ec.shutdown()  # should not raise


# -----------------------------------------------------------------------
# DCLAW_PRODUCTION parsing matches the Go fleet (productionFlagSet)
# -----------------------------------------------------------------------
_PRODUCTION_VALUES = [
    (None, False), ("", False), ("  ", False), ("0", False), ("false", False),
    ("FALSE", False), ("no", False), ("off", False), (" Off ", False),
    ("1", True), ("true", True), (" TRUE ", True), ("yes", True),
    ("on", True), ("ON", True), ("enabled", True),
]


class TestProductionFlag:
    @pytest.mark.parametrize("raw,expected", _PRODUCTION_VALUES)
    def test_production_flag_set_matches_go(self, raw, expected):
        from generic_hook import production_flag_set
        assert production_flag_set(raw) is expected

    @pytest.mark.parametrize("raw,expected", [v for v in _PRODUCTION_VALUES if v[0] is not None])
    def test_is_production_reads_env(self, raw, expected, monkeypatch):
        from generic_hook import is_production
        monkeypatch.setenv("DCLAW_PRODUCTION", raw)
        assert is_production() is expected

    @pytest.mark.parametrize("raw,warns", [("on", True), (" TRUE ", True),
                                           ("0", False), ("off", False)])
    def test_check_http_production_uses_shared_parser(self, raw, warns, monkeypatch):
        import warnings
        from generic_hook import check_http_production
        monkeypatch.setenv("DCLAW_PRODUCTION", raw)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            check_http_production("http://1.1.1.1/mcp")
        assert bool(caught) is warns

    @pytest.mark.parametrize("module,cls,kwargs", [
        ("defenseclaw_ha", "HomeAssistantAdapter", {"host": "1.1.1.1"}),
        ("defenseclaw_bubbaloop", "BubbaloopAdapter", {"host": "1.1.1.1"}),
        ("defenseclaw_espclaw", "ESPClawAdapter", {"host": "1.1.1.1"}),
    ])
    @pytest.mark.parametrize("raw,rejects", [("on", True), (" TRUE ", True),
                                             ("0", False), ("off", False)])
    def test_integrations_use_shared_parser(self, module, cls, kwargs, raw, rejects,
                                            monkeypatch):
        import importlib
        import warnings
        integrations = Path(__file__).resolve().parent.parent / "integrations"
        for sub in ("homeassistant", "bubbaloop", "espclaw"):
            path = str(integrations / sub)
            if path not in sys.path:
                sys.path.insert(0, path)
        adapter_cls = getattr(importlib.import_module(module), cls)
        monkeypatch.setenv("DCLAW_EDGE_SCHEME", "http")
        monkeypatch.delenv("DCLAW_ESPCLAW_ALLOW_HTTP", raising=False)
        monkeypatch.setenv("DCLAW_PRODUCTION", raw)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if rejects:
                with pytest.raises(ValueError, match="production"):
                    adapter_cls(connector=MagicMock(), **kwargs)
            else:
                adapter_cls(connector=MagicMock(), **kwargs)
