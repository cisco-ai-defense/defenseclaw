"""GAP-0209: an MCP scan whose analyzers did not inspect every tool has no verdict.

The upstream scanner logs an analyzer that raised and returns the tool with
no findings from it, which read as a clean verdict. Every scan path fails
instead, so the gateway blocks the server as not scanned (fail closed).
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.config import MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner import mcp

_SDK_LOGGER = "mcpscanner.core.scanner"


def _tool_result(name: str, analyzers: list[str]) -> SimpleNamespace:
    return SimpleNamespace(tool_name=name, analyzers=analyzers, findings=[], status="completed")


class _CustomRules:
    name = "yara"


def test_failed_yara_analysis_has_no_verdict() -> None:
    errors = [(_SDK_LOGGER, 'YARA analysis failed on description: tool="ignore all rules", error="boom"')]
    with pytest.raises(mcp.MCPScanIncompleteError, match="the YARA analyzer failed") as caught:
        mcp._raise_if_analysis_incomplete("decoy", errors, [_tool_result("ping", ["yara"])], SimpleNamespace())
    # The message never copies the logged text (server-controlled tool names).
    assert "ignore all rules" not in str(caught.value)
    assert "boom" not in str(caught.value)


@pytest.mark.parametrize(
    "message",
    [
        'API analysis failed on description: tool="t", error="x"',
        'Readiness analysis failed: tool="t", error="x"',
        'Custom analyzer "yara" failed: tool="t", error="x"',
    ],
)
def test_any_failed_analyzer_has_no_verdict(message: str) -> None:
    with pytest.raises(mcp.MCPScanIncompleteError):
        mcp._raise_if_analysis_incomplete("decoy", [(_SDK_LOGGER, message)], [], SimpleNamespace())


def test_custom_rules_that_did_not_run_have_no_verdict() -> None:
    # The SDK lists the selected analyzers as enum members, then the name of
    # each custom analyzer that ran; the bundled rules share the "yara" value.
    import enum

    class Selected(str, enum.Enum):
        YARA = "yara"

    scanner = SimpleNamespace(get_custom_analyzers=lambda: [_CustomRules()])
    with pytest.raises(mcp.MCPScanIncompleteError, match="DefenseClaw YARA rules did not run"):
        mcp._raise_if_analysis_incomplete("decoy", [], [_tool_result("ping", [Selected.YARA])], scanner)
    mcp._raise_if_analysis_incomplete("decoy", [], [_tool_result("ping", [Selected.YARA, "yara"])], scanner)


def test_complete_scan_and_llm_skip_keep_their_verdict() -> None:
    # The LLM analyzer keeps degrading with a warning, as before.
    errors = [(_SDK_LOGGER, 'LLM analysis failed: tool="ping", error="unreachable"')]
    mcp._raise_if_analysis_incomplete("benign", errors, [_tool_result("ping", ["yara"])], SimpleNamespace())


def test_windows_scan_with_a_failed_analyzer_fails_instead_of_clean() -> None:
    # The managed Windows path (#1164 relay included) dropped the captured
    # analyzer errors once tools/list had answered.
    wrapper = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    plan = mcp._StdioLaunchPlan("resolved", (), {}, "npx")

    async def scan(*_args, **_kwargs):
        logging.getLogger(_SDK_LOGGER).error('YARA analysis failed on description: tool="ping", error="boom"')
        return [_tool_result("ping", ["yara"])], 0

    with (
        patch.object(mcp.os, "name", "nt"),
        patch.object(mcp, "_windows_stdio_launch_plan", return_value=plan),
        patch.object(mcp, "_scan_windows_stdio_tools", scan),
        pytest.raises(mcp.MCPScanIncompleteError, match="'decoy' is incomplete"),
    ):
        wrapper._scan_local(SimpleNamespace(), MCPServerEntry(name="decoy", command="npx", args=["pkg"]), [])


def test_windows_scan_that_inspected_every_tool_returns_its_findings() -> None:
    wrapper = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    plan = mcp._StdioLaunchPlan("resolved", (), {}, "npx")
    finding = SimpleNamespace(severity="HIGH", summary="s")

    async def scan(*_args, **_kwargs):
        return [SimpleNamespace(tool_name="ping", analyzers=["yara"], findings=[finding])], 0

    with (
        patch.object(mcp.os, "name", "nt"),
        patch.object(mcp, "_windows_stdio_launch_plan", return_value=plan),
        patch.object(mcp, "_scan_windows_stdio_tools", scan),
    ):
        found = wrapper._scan_local(SimpleNamespace(), MCPServerEntry(name="ok", command="npx", args=["pkg"]), [])
    assert found == [finding]


def test_local_scan_with_a_failed_analyzer_fails_instead_of_clean() -> None:
    wrapper = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))

    async def scan_file(**_kwargs):
        logging.getLogger(_SDK_LOGGER).error('YARA analysis failed on parameters: tool="ping", error="boom"')
        return [_tool_result("ping", ["yara"])]

    scanner = SimpleNamespace(scan_mcp_config_file=scan_file)
    with patch.object(mcp.os, "name", "posix"), pytest.raises(mcp.MCPScanIncompleteError):
        wrapper._scan_local(scanner, MCPServerEntry(name="decoy", command="npx", args=["pkg"]), [])


def test_remote_scan_with_a_failed_analyzer_fails_instead_of_clean() -> None:
    wrapper = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))

    def uncaptured(_scanner, _target, _analyzers):
        logging.getLogger(_SDK_LOGGER).error('YARA analysis failed on description: tool="ping", error="boom"')
        return []

    with patch.object(wrapper, "_scan_remote_uncaptured", uncaptured), pytest.raises(mcp.MCPScanIncompleteError):
        wrapper._scan_remote(SimpleNamespace(), "https://mcp.example.com/mcp", [])


def test_missing_bundled_rules_fail_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp, "bundled_mcp_yara_rules_dir", lambda: None)
    with pytest.raises(mcp.MCPScanIncompleteError, match="bundled DefenseClaw MCP YARA rules are missing"):
        mcp._supplemental_yara_analyzers(lambda **_kw: object())


def test_unloadable_bundled_rules_fail_the_scan() -> None:
    def broken(**_kwargs):
        raise ValueError("syntax error in rule")

    with pytest.raises(mcp.MCPScanIncompleteError, match="could not be loaded"):
        mcp._supplemental_yara_analyzers(broken)


def test_the_real_sdk_reports_custom_rule_names_the_check_expects() -> None:
    # The structural check reads ToolScanResult.analyzers; pin that the
    # pinned SDK lists a custom analyzer that ran by its name.
    pytest.importorskip("mcpscanner")
    from mcpscanner import Config, Scanner
    from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
    from mcpscanner.core.models import AnalyzerEnum

    rules = mcp._supplemental_yara_analyzers(YaraAnalyzer)
    scanner = Scanner(Config(), custom_analyzers=rules)
    tool = SimpleNamespace(
        name="ping",
        description="Returns a harmless ping response.",
        model_dump_json=lambda **_kwargs: '{"name": "ping", "description": "Returns a harmless ping response."}',
    )
    result = asyncio.run(scanner._analyze_tool(tool, [AnalyzerEnum.YARA]))
    # 4.8 folds a custom name equal to a built-in value into the built-in
    # entry, so the bundled pack must carry its own name to be seen.
    assert [r.name for r in rules] == ["DefenseClaw YARA"]
    assert all(getattr(r, "name", "") in [str(getattr(a, "value", a)) for a in result.analyzers] for r in rules)
    mcp._raise_if_analysis_incomplete("benign", [], [result], scanner)


@pytest.mark.parametrize(
    ("message", "label"),
    [
        # MCP Scanner 4.8 log lines (enum value or custom analyzer name).
        ("api analysis failed on description: TimeoutError", "Cisco AI Defense API analyzer"),
        ("yara analysis failed on description: Error", "YARA analyzer"),
        ("readiness analysis failed on description: ValueError", "readiness analyzer"),
        ("DefenseClaw YARA analysis failed on description: Error", "DefenseClaw YARA rules"),
        ("DefenseClaw YARA extra analysis failed on prompt: Error", "DefenseClaw YARA rules"),
    ],
)
def test_scanner_4_8_failure_logs_have_no_verdict(message: str, label: str) -> None:
    with pytest.raises(mcp.MCPScanIncompleteError, match=label):
        mcp._raise_if_analysis_incomplete("decoy", [(_SDK_LOGGER, message)], [], SimpleNamespace())


def test_llm_failure_logs_of_both_scanner_lines_degrade() -> None:
    assert mcp._is_llm_failure_log("LLM analysis failed: tool=x")
    assert mcp._is_llm_failure_log("llm analysis failed on description: APIConnectionError")
    mcp._raise_if_analysis_incomplete(
        "benign", [(_SDK_LOGGER, "llm analysis failed on description: APIConnectionError")], [], SimpleNamespace()
    )


def test_defenseclaw_yara_findings_keep_the_yara_scanner_label() -> None:
    finding = SimpleNamespace(severity="HIGH", analyzer="DefenseClaw YARA", summary="x", details={})
    result = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))._convert([finding], "t", 0.1)
    assert [f.scanner for f in result.findings] == ["mcp-scanner/YARA"]
