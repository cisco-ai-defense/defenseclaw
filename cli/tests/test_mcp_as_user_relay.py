"""#1164: an enrolled user's MCP server on managed Windows starts as the user.

The managed scanner runtime starts the gateway's relay in place of the
server; the hook enumerator starts the published definition as the user.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from defenseclaw.config import MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner import mcp


def _relay(tmp_path: Path) -> tuple[str, ...]:
    gateway = tmp_path / "defenseclaw-gateway.exe"
    gateway.write_text("fixture", encoding="utf-8")
    return (os.fspath(gateway), "enterprise", "windows", "mcp-relay", "--request", "abc")


def test_relay_plan_starts_the_relay_not_the_server(tmp_path: Path) -> None:
    relay = _relay(tmp_path)
    entry = MCPServerEntry(name="notes", command="npx", args=["-y", ".", "--config", r".\srv.json"],
                           env={"NOTES_TOKEN": "x"})
    plan = mcp._as_user_relay_plan(entry, relay)
    assert plan.command == relay[0]
    assert plan.args == relay[1:]
    assert plan.launcher == "npx"
    assert plan.cwd is None
    # The server's env goes nowhere near the relay; the enumerator applies it.
    assert "NOTES_TOKEN" not in plan.env
    uvx = mcp._as_user_relay_plan(MCPServerEntry(name="t", command="uvx", args=["mcp-server-time"]), relay)
    assert uvx.launcher == "uvx"


@pytest.mark.parametrize(
    "command,args",
    [
        ("node", ["server.js"]),
        ("cmd.exe", ["/c", "calc"]),
    ],
)
def test_relay_plan_refuses_other_launchers(tmp_path: Path, command: str, args: list[str]) -> None:
    with pytest.raises(mcp.MCPStdioLaunchError, match="only through npx or uvx"):
        mcp._as_user_relay_plan(MCPServerEntry(name="s", command=command, args=args), _relay(tmp_path))


def test_relay_plan_refuses_npx_metacharacters(tmp_path: Path) -> None:
    with pytest.raises(mcp.MCPStdioLaunchError, match="metacharacter"):
        mcp._as_user_relay_plan(MCPServerEntry(name="s", command="npx", args=["pkg&calc"]), _relay(tmp_path))


def test_relay_plan_needs_an_installed_relay(tmp_path: Path) -> None:
    entry = MCPServerEntry(name="s", command="npx", args=["pkg"])
    for relay in [(), ("relative.exe",), (os.fspath(tmp_path / "missing.exe"),)]:
        with pytest.raises(mcp.MCPStdioLaunchError, match="not an installed executable"):
            mcp._as_user_relay_plan(entry, relay)


def test_scanner_wrapper_has_no_relay_by_default() -> None:
    assert mcp.MCPScannerWrapper(MCPScannerConfig()).stdio_relay == ()


def test_relay_startup_failure_names_the_relay_and_the_os_error(tmp_path: Path) -> None:
    # GAP-0114: a failed start of the relay read "Windows npx wrapper startup
    # failed" with no cause; it names the relay and the system error.
    plan = mcp._as_user_relay_plan(MCPServerEntry(name="s", command="npx", args=["pkg"]), _relay(tmp_path))
    message = str(mcp._classify_windows_stdio_error(PermissionError(13, "Access is denied"), plan, [], 0, 7))
    assert "MCP as-user relay startup failed" in message
    assert "npx wrapper" not in message
    assert "PermissionError errno 13: Access is denied" in message


def test_no_writable_temporary_folder_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-0114: under the managed gateway token Python found no writable
    # temporary folder, and the scan said the npx wrapper failed to start.
    import asyncio
    from types import SimpleNamespace

    def refuse(*_args, **_kwargs):
        raise FileNotFoundError(2, "No usable temporary directory found")

    monkeypatch.setattr(mcp.tempfile, "TemporaryFile", refuse)
    scanner = SimpleNamespace(_validate_analyzer_requirements=lambda _a: None, _analyze_tool=lambda *_a: None)
    plan = mcp._StdioLaunchPlan("resolved", (), {}, "npx")
    with pytest.raises(mcp.MCPStdioLaunchError, match="no writable temporary folder") as caught:
        asyncio.run(mcp._scan_windows_stdio_tools(scanner, plan, ["fixture"]))
    assert "No usable temporary directory found" in str(caught.value)
