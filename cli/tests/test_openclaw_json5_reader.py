# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""openclaw.json is read as JSON5 by every DefenseClaw reader, like OpenClaw and the sidecar do."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw import openclaw_json5
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway
from defenseclaw.connector_paths import _read_openclaw_json, openclaw_gateway_token
from defenseclaw.openclaw_guardrail import detect_current_model
from defenseclaw.openclaw_plugin_config import (
    UNREADABLE_CONFIG,
    openclaw_plugin_config_issue,
    openclaw_plugin_config_unreadable,
)

MANIFEST = Path(__file__).resolve().parents[2] / "extensions" / "defenseclaw" / "openclaw.plugin.json"

# The file shape a user (or OpenClaw itself) writes: every JSON5 feature the
# product accepts, with a gateway token and a hexadecimal port.
JSON5_FILE = """\
// OpenClaw reads this file as JSON5
/* block comment */
{
  gateway: {
    mode: 'local',
    port: 0x7077,
    auth: { mode: 'token', token: 'json5-file-token', },
  },
  agents: { defaults: { model: { primary: 'anthropic/claude-sonnet', }, }, },
  plugins: { entries: { defenseclaw: { enabled: true, }, }, },
}
"""


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("{ // note\n gateway: {auth: {mode: 'token', token: 'it\\'s \"x\"',},}, /* c */ list: [1, 2,],}\n",
         {"gateway": {"auth": {"mode": "token", "token": "it's \"x\""}}, "list": [1, 2]}),
        ('{"a":{"b":"x // not a comment","c":[true,null]}}', {"a": {"b": "x // not a comment", "c": [True, None]}}),
        ("{ // it's fine\n a: 1 }", {"a": 1}),
        ("{a: 'one \\\ntwo'}", {"a": "one two"}),
        ("{a: true, b: null, $c_1: false}", {"a": True, "b": None, "$c_1": False}),
        ("{a: 0x4971, b: -0X10, c: 0xFFFFFFFFFFFFFFFFFF}", {"a": 18801, "b": -16, "c": 4722366482869645213695}),
        ("{a: +1, b: .5, c: 5., d: -.5e2, e: 1E+3, f: +.0}", {"a": 1, "b": 0.5, "c": 5.0, "d": -50.0, "e": 1000.0, "f": 0.0}),
        ("{a: Infinity, b: -Infinity, c: +NaN, d: [NaN]}", {"a": None, "b": None, "c": None, "d": [None]}),
        ("{a: '\\x41\\0\\v\\q\\u0042'}", {"a": "A\x00\x0bqB"}),
        ('{b: "tab\traw"}', {"b": "tab\traw"}),
        ("\ufeff{a: 1}", {"a": 1}),
        ("{\u00a0a\x0b:\x0c1,\u2028b: 2}", {"a": 1, "b": 2}),
        ("{k\u00e9y: 1, \u00fcber_2: {x: 0x1}}", {"k\u00e9y": 1, "\u00fcber_2": {"x": 1}}),
        ("{a /* c */ : 1, b // c\n : 2}", {"a": 1, "b": 2}),
        ('{Infinity1: "NaN", x0x1: "0x10 +1 .5"}', {"Infinity1": "NaN", "x0x1": "0x10 +1 .5"}),
        ("{a: 1, // c\rb: 2}", {"a": 1, "b": 2}),
        ("{a: 1, // c\u2028b: 2}", {"a": 1, "b": 2}),
        ("{a: 1, // c\u2029b: 2}", {"a": 1, "b": 2}),
        ("{a // c\u2028: 1, b: 2}", {"a": 1, "b": 2}),
        ("{g\\u0061teway: 1, \\u0062: {\\u0063\\u0064: 2}, e\\u00e9: 3, a\\u0030: 4, \\u0024x: 5, true: 6, 'q': 'g\\u0061'}",
         {"gateway": 1, "b": {"cd": 2}, "e\u00e9": 3, "a0": 4, "$x": 5, "true": 6, "q": "ga"}),
    ],
)
def test_loads_reads_what_openclaw_accepts(text: str, want: object) -> None:
    assert openclaw_json5.loads(text) == want


@pytest.mark.parametrize(
    "text",
    [
        "{a: 'open", "{a: 1", "{a: -}", "{a: 0x}", "{a: +}", "{a: .}", "{a: '\\1'}", "{a: '\\x4'}", "{a: '\\00'}",
        "{a: 'raw\nnewline'}", "{a: 1 2}", "{a: Infinityx}",
        "{a: 1}/*", "{a: 1} /* open", "/*", "{a: /* open 1}", "{a /* open : 1}",
        "{g\\u006teway: 1}", "{g\\u0020a: 1}", "{\\u0031a: 1}", "{a: tr\\u0075e}", "{a: 1}\\u0061", "{\\u00: 1}", "{a\\: 1}",
        "", "   ", "{a: 1,, b: 2}",
    ],
)
def test_loads_leaves_invalid_input_invalid(text: str) -> None:
    with pytest.raises(openclaw_json5.OpenClawConfigSyntaxError):
        openclaw_json5.loads(text)


def test_syntax_error_names_the_line_and_column_in_the_original_text() -> None:
    text = "// header comment\n{\n  gateway: {\n    port: 18789,\n    auth: { token: 'x' mode: 'token' },\n  },\n}\n"
    with pytest.raises(openclaw_json5.OpenClawConfigSyntaxError) as caught:
        openclaw_json5.loads(text)
    assert caught.value.line == 5
    assert 20 <= caught.value.column <= 40, caught.value
    assert "line 5" in str(caught.value)


@pytest.mark.parametrize(
    ("terminator", "line"),
    [("\n", 3), ("\r", 3), ("\r\n", 3), ("\u2028", 3), ("\u2029", 3), ("\x0b", 2), ("\x0c", 2), ("\x85", 2)],
)
def test_syntax_error_counts_exactly_the_json5_line_terminators(terminator: str, line: int) -> None:
    text = f"// first{terminator}// second\n{{ a: \"bad\nstring\" }}"
    with pytest.raises(openclaw_json5.OpenClawConfigSyntaxError) as caught:
        openclaw_json5.loads(text)
    assert (caught.value.line, caught.value.column) == (line, 10)


def test_oversized_json5_error_counts_json5_line_terminators() -> None:
    text = '{"a": 1,\r b: 2}' + " " * openclaw_json5.MAX_JSON5_CHARS
    with pytest.raises(openclaw_json5.OpenClawConfigSyntaxError) as raised:
        openclaw_json5.loads(text)
    assert (raised.value.line, raised.value.column) == (2, 2)


def test_syntax_error_never_quotes_the_file_text() -> None:
    secret = "s3cret-token-value"
    with pytest.raises(openclaw_json5.OpenClawConfigSyntaxError) as caught:
        openclaw_json5.loads(f"{{gateway: {{auth: {{token: '{secret}' oops}}}}}}")
    assert secret not in str(caught.value)


def _installed(tmp_path: Path, text: str) -> Path:
    manifest = tmp_path / "extensions" / "defenseclaw" / "openclaw.plugin.json"
    manifest.parent.mkdir(parents=True)
    shutil.copyfile(MANIFEST, manifest)
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(text, encoding="utf-8")
    return config_file


def test_json5_openclaw_json_passes_the_plugin_config_check(tmp_path: Path) -> None:
    config_file = _installed(tmp_path, JSON5_FILE)
    assert openclaw_plugin_config_issue(str(config_file), str(tmp_path)) is None


def test_json5_plugin_config_is_still_checked_against_the_manifest(tmp_path: Path) -> None:
    text = "{plugins: {entries: {defenseclaw: {config: {level: 3, operatorNote: 'note',},},},},}"
    config_file = _installed(tmp_path, text)
    assert "schema rejects" in openclaw_plugin_config_issue(str(config_file), str(tmp_path))


def test_broken_openclaw_json_still_fails_with_the_parse_location(tmp_path: Path) -> None:
    config_file = _installed(tmp_path, "{\n  gateway: {\n    port: 18789\n    mode: 'local'\n  },\n}\n")
    issue = openclaw_plugin_config_issue(str(config_file), str(tmp_path))
    assert issue is not None
    assert issue.startswith(UNREADABLE_CONFIG)
    assert "line 4" in issue
    assert openclaw_plugin_config_unreadable(issue)
    assert not openclaw_plugin_config_unreadable("plugins.entries.defenseclaw.config has values the installed plugin schema rejects")
    assert not openclaw_plugin_config_unreadable(None)


def test_non_utf8_openclaw_json_is_unreadable(tmp_path: Path) -> None:
    config_file = _installed(tmp_path, "{}")
    config_file.write_bytes(b"{a: '\xff\xfe'}")
    issue = openclaw_plugin_config_issue(str(config_file), str(tmp_path))
    assert openclaw_plugin_config_unreadable(issue)


def _doctor_result(config_file: Path) -> cmd_doctor._DoctorResult:
    cfg = SimpleNamespace(
        guardrail=SimpleNamespace(enabled=True),
        claw=SimpleNamespace(home_dir=str(config_file.parent), config_file=str(config_file)),
    )
    result = cmd_doctor._DoctorResult(quiet=True)
    with (
        patch.object(cmd_doctor, "_guardrail_proxy_intentionally_closed", return_value=False),
        patch.object(cmd_doctor, "_doctor_active_connectors", return_value=["openclaw"]),
        patch.object(cmd_doctor, "_connector_enabled", return_value=True),
    ):
        cmd_doctor._check_proxy_interception(cfg, result, live_health={"uptime_ms": 2000})
    return result


def test_doctor_interception_row_does_not_fail_on_a_json5_file(tmp_path: Path) -> None:
    result = _doctor_result(_installed(tmp_path, JSON5_FILE))
    assert result.failed == 0
    assert all(UNREADABLE_CONFIG not in check["detail"] for check in result.checks)


def test_doctor_interception_row_fails_on_a_syntax_error_with_the_location(tmp_path: Path) -> None:
    result = _doctor_result(_installed(tmp_path, "{\n  a: 1\n  b: 2\n}\n"))
    assert result.failed == 1
    check = result.checks[0]
    assert check["label"] == "OpenClaw interception"
    assert UNREADABLE_CONFIG in check["detail"]
    assert "line 3" in check["detail"]
    assert "defenseclaw setup openclaw" not in check["remediation"]
    assert "syntax" in check["remediation"]


def test_shared_reader_returns_the_json5_document_and_its_token(tmp_path: Path) -> None:
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(JSON5_FILE, encoding="utf-8")
    document = _read_openclaw_json(str(config_file))
    assert document is not None
    assert document["gateway"]["port"] == 0x7077
    assert openclaw_gateway_token(document).value == "json5-file-token"


def test_shared_reader_returns_none_for_a_file_it_cannot_read(tmp_path: Path) -> None:
    config_file = tmp_path / "openclaw.json"
    assert _read_openclaw_json(str(config_file)) is None
    config_file.write_text("{gateway: {port: }", encoding="utf-8")
    assert _read_openclaw_json(str(config_file)) is None


def test_init_resolves_the_gateway_from_a_json5_file(tmp_path: Path) -> None:
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(JSON5_FILE, encoding="utf-8")
    resolved = _resolve_openclaw_gateway(str(config_file))
    assert resolved["port"] == 0x7077
    assert resolved["token"] == "json5-file-token"


def test_model_detection_reads_a_json5_file(tmp_path: Path) -> None:
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(JSON5_FILE, encoding="utf-8")
    assert detect_current_model(str(config_file)) == ("anthropic/claude-sonnet", "anthropic")
    config_file.write_text(json.dumps({"agents": {"defaults": {"model": {"primary": "openai/gpt"}}}}), encoding="utf-8")
    assert detect_current_model(str(config_file)) == ("openai/gpt", "openai")


def test_large_strict_json_is_still_read(tmp_path: Path) -> None:
    # A valid JSON file stays readable at any size; only the JSON5 rewrite has a cap.
    pad = " " * (openclaw_json5.MAX_JSON5_CHARS + 1)
    text = "{\"gateway\": {\"auth\": {\"token\": \"big-file-token\"}}}" + pad
    assert openclaw_json5.loads(text)["gateway"]["auth"]["token"] == "big-file-token"
    config_file = _installed(tmp_path, text)
    assert openclaw_plugin_config_issue(str(config_file), str(tmp_path)) is None
    assert _doctor_result(config_file).failed == 0


def test_oversized_json5_fails_with_a_location_not_a_crash() -> None:
    text = "{a: 1, // c\n}" + " " * openclaw_json5.MAX_JSON5_CHARS
    with pytest.raises(openclaw_json5.OpenClawConfigSyntaxError) as raised:
        openclaw_json5.loads(text)
    assert "too large to read as JSON5" in str(raised.value)
    assert raised.value.line == 1


@pytest.mark.parametrize("mcp_value", ["null", "[]", "\x27off\x27", "42"])
def test_mcp_listing_survives_a_wrong_shaped_mcp_value(tmp_path: Path, mcp_value: str) -> None:
    from defenseclaw.connector_paths import _read_mcp_servers_from_openclaw_json

    config_file = tmp_path / "openclaw.json"
    config_file.write_text("{ // c\n  mcp: " + mcp_value + ",\n}\n", encoding="utf-8")
    sink: list = []
    assert _read_mcp_servers_from_openclaw_json(str(config_file), diagnostic_sink=sink) == []
    strict = {"null": None, "[]": [], "\x27off\x27": "off", "42": 42}[mcp_value]
    config_file.write_text(json.dumps({"mcp": strict}), encoding="utf-8")
    assert _read_mcp_servers_from_openclaw_json(str(config_file), diagnostic_sink=sink) == []


def test_mcp_listing_reads_servers_from_a_json5_file(tmp_path: Path) -> None:
    from defenseclaw.connector_paths import _read_mcp_servers_from_openclaw_json

    config_file = tmp_path / "openclaw.json"
    config_file.write_text("{\n  // c\n  mcp: { servers: { demo: { command: \x27npx\x27, }, }, },\n}\n", encoding="utf-8")
    entries = _read_mcp_servers_from_openclaw_json(str(config_file))
    assert [(e.name, e.command) for e in entries] == [("demo", "npx")]
