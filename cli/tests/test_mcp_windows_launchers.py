"""WIN-AUD-064 regression coverage for native Windows MCP launchers."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
from defenseclaw.commands import cmd_mcp
from defenseclaw.config import MCPScannerConfig, MCPServerEntry
from defenseclaw.inventory import agent_discovery
from defenseclaw.scanner import mcp

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_launchers"
PYTHON_FIXTURE = FIXTURES / "python" / "defenseclaw_mcp_launcher_fixture.py"
HOST_LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
HOST_UVX = shutil.which("uvx.exe") if os.name == "nt" else None
HOST_NPX = shutil.which("npx.cmd") if os.name == "nt" else None
HOST_UV = shutil.which("uv.exe") if os.name == "nt" else None
HOST_POWERSHELL = shutil.which("powershell.exe") if os.name == "nt" else None


def _touch(path: Path, content: str = "fixture") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return os.fspath(path)


def _which_map(monkeypatch: pytest.MonkeyPatch, values: dict[str, str | None]) -> None:
    monkeypatch.setattr(
        mcp.shutil,
        "which",
        lambda command, **_kwargs: values.get(command.lower()),
    )


def _trusted(monkeypatch: pytest.MonkeyPatch, trusted_paths: set[str]) -> None:
    trusted = {os.path.normcase(os.path.realpath(path)) for path in trusted_paths}
    monkeypatch.setattr(
        agent_discovery,
        "_is_trusted_binary_path",
        lambda path, *_args, **_kwargs: os.path.normcase(os.path.realpath(path)) in trusted,
    )


def test_mcp_set_recovers_json_argv_stripped_by_windows_batch_launcher() -> None:
    raw = (
        r"[--offline,--from,C:\\Users\\operator\\Temp\\fixture package,"
        r"defenseclaw-mcp-launcher-fixture]"
    )

    assert cmd_mcp._parse_args(raw) == [
        "--offline",
        "--from",
        r"C:\Users\operator\Temp\fixture package",
        "defenseclaw-mcp-launcher-fixture",
    ]


def test_mcp_set_rejects_ambiguous_batch_mangled_json_argv() -> None:
    with pytest.raises(click.BadParameter, match="malformed JSON array"):
        cmd_mcp._parse_args('[--from,"ambiguous]')


def test_trusted_npx_cmd_uses_narrow_system_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    npx = _touch(tmp_path / "Program Files" / "nodejs" / "npx.cmd")
    command_processor = _touch(tmp_path / "Windows" / "System32" / "cmd.exe")
    env = {
        "PATH": os.fspath(Path(npx).parent),
        "SYSTEMROOT": os.fspath(tmp_path / "Windows"),
    }
    monkeypatch.setattr(mcp, "_safe_subprocess_env", lambda _operator: dict(env))
    _which_map(monkeypatch, {"npx": npx, "npx.cmd": npx})
    _trusted(monkeypatch, {npx, command_processor})

    plan = mcp._windows_stdio_launch_plan(
        MCPServerEntry(
            name="fixture",
            command="npx",
            args=["--yes", "package with spaces"],
        )
    )

    assert plan.command == os.path.realpath(command_processor)
    assert plan.args == (
        "/d",
        "/s",
        "/v:off",
        "/c",
        "call",
        os.path.realpath(npx),
        "--yes",
        "package with spaces",
    )
    assert plan.launcher == "npx"


@pytest.mark.parametrize("argument", ["pkg&whoami", "pkg|whoami", "pkg>out", "%PATH%", "!PATH!", 'pkg"arg'])
def test_npx_rejects_cmd_metacharacters(
    argument: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    npx = _touch(tmp_path / "nodejs" / "npx.cmd")
    command_processor = _touch(tmp_path / "Windows" / "System32" / "cmd.exe")
    monkeypatch.setattr(
        mcp,
        "_safe_subprocess_env",
        lambda _operator: {
            "PATH": os.fspath(Path(npx).parent),
            "SYSTEMROOT": os.fspath(tmp_path / "Windows"),
        },
    )
    _which_map(monkeypatch, {"npx": npx, "npx.cmd": npx})
    _trusted(monkeypatch, {npx, command_processor})

    with pytest.raises(mcp.MCPStdioLaunchError, match="metacharacter"):
        mcp._windows_stdio_launch_plan(MCPServerEntry(name="fixture", command="npx", args=[argument]))


def test_npx_rejects_unsupported_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    npx = _touch(tmp_path / "trusted" / "npx.cmd")
    shadow = _touch(tmp_path / "shadow" / "npx.exe")
    env = {"PATH": os.pathsep.join((os.fspath(Path(shadow).parent), os.fspath(Path(npx).parent)))}
    _which_map(monkeypatch, {"npx": shadow, "npx.cmd": npx})
    _trusted(monkeypatch, {npx})

    with pytest.raises(mcp.MCPStdioLaunchError, match="shadowed"):
        mcp._resolve_trusted_windows_launcher("npx", ".cmd", env)


def test_untrusted_launcher_path_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    npx = _touch(tmp_path / "user-writable" / "npx.cmd")
    _which_map(monkeypatch, {"npx": npx, "npx.cmd": npx})
    _trusted(monkeypatch, set())

    with pytest.raises(mcp.MCPStdioLaunchError, match="untrusted Windows path"):
        mcp._resolve_trusted_windows_launcher("npx", ".cmd", {"PATH": os.fspath(Path(npx).parent)})


@pytest.mark.parametrize(
    "command",
    ["npx.cmd", "npx.bat", "npx.ps1", r"C:\tools\npx"],
)
def test_unsupported_npx_spellings_remain_outside_allowlist(command: str) -> None:
    error = mcp._stdio_scan_command_error(command, ["package"])
    assert error is not None
    assert "allowlisted stdio launcher" in error


def test_uvx_resolves_to_trusted_exe_and_keeps_literal_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uvx = _touch(tmp_path / "uv" / "uvx.exe")
    args = ["--from", "package with spaces", "literal&argument"]
    monkeypatch.setattr(
        mcp,
        "_safe_subprocess_env",
        lambda _operator: {"PATH": os.fspath(Path(uvx).parent)},
    )
    _which_map(monkeypatch, {"uvx": uvx, "uvx.exe": uvx})
    _trusted(monkeypatch, {uvx})

    plan = mcp._windows_stdio_launch_plan(MCPServerEntry(name="fixture", command="uvx", args=args))

    assert plan.command == os.path.realpath(uvx)
    assert plan.args == tuple(args)
    assert plan.launcher == "uvx"


def test_missing_uvx_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    _which_map(monkeypatch, {"uvx": None, "uvx.exe": None})
    with pytest.raises(mcp.MCPStdioLaunchError, match="not found as native 'uvx.exe'"):
        mcp._resolve_trusted_windows_launcher("uvx", ".exe", {"PATH": "missing"})


def test_trusted_node_repl_remains_a_direct_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node_repl = _touch(tmp_path / "node_repl.exe")
    monkeypatch.setattr(mcp, "_is_trusted_codex_node_repl", lambda _path: True)
    monkeypatch.setattr(mcp, "_safe_subprocess_env", lambda _operator: {"PATH": "safe"})

    plan = mcp._windows_stdio_launch_plan(MCPServerEntry(name="node_repl", command=node_repl, args=[]))

    assert plan.command == os.path.realpath(node_repl)
    assert plan.args == ()
    assert plan.launcher == "node_repl.exe"


class _RecordingScanner:
    DEFAULT_ANALYZERS = ("fixture",)

    def __init__(self) -> None:
        self.tools: list[str] = []

    def _validate_analyzer_requirements(self, analyzers: list[str]) -> None:
        assert analyzers == ["fixture"]

    async def _analyze_tool(self, tool, _analyzers: list[str]):
        self.tools.append(tool.name)
        return SimpleNamespace(tool_name=tool.name, findings=[])


def _build_python_fixture_wheel(source: Path, dist: Path) -> Path:
    dist.mkdir(parents=True)
    subprocess.run(
        [os.fspath(HOST_UV), "build", "--wheel", "--out-dir", os.fspath(dist), os.fspath(source)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return next(dist.glob("defenseclaw_mcp_launcher_fixture-*.whl"))


def _python_plan(env: dict[str, str]) -> mcp._StdioLaunchPlan:
    return mcp._StdioLaunchPlan(
        command=sys.executable,
        args=(os.fspath(PYTHON_FIXTURE),),
        env=env,
        launcher="uvx",
    )


@pytest.mark.allow_subprocess
@pytest.mark.skipif(os.name != "nt", reason="native Windows stdio adapter")
def test_complete_lifecycle_enumerates_benign_and_malicious_tools_and_scrubs_env(
    tmp_path: Path,
) -> None:
    report = tmp_path / "env-report.json"
    parent_secret = "must-not-reach-fixture"
    operator_env = {
        "MCP_FIXTURE_REQUIRED": "present",
        "MCP_FIXTURE_ENV_REPORT": os.fspath(report),
    }
    with patch.dict(
        os.environ,
        {"WIN_AUD_064_TEST_API_KEY": parent_secret},
        clear=False,
    ):
        env = mcp._safe_subprocess_env(operator_env)
        scanner = _RecordingScanner()
        results, _stderr_size = asyncio.run(mcp._scan_windows_stdio_tools(scanner, _python_plan(env), ["fixture"]))

    assert [result.tool_name for result in results] == ["benign_echo", "malicious_shell"]
    assert scanner.tools == ["benign_echo", "malicious_shell"]
    assert json.loads(report.read_text(encoding="utf-8")) == {
        "requiredPresent": True,
        "secretAbsent": True,
    }
    assert parent_secret not in json.dumps(env)


@pytest.mark.allow_subprocess
@pytest.mark.skipif(os.name != "nt", reason="native Windows stdio adapter")
def test_lifecycle_trace_reaches_tools_list_and_analyzer_handoff(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    trace = tmp_path / "protocol.jsonl"
    env = mcp._safe_subprocess_env({"MCP_FIXTURE_TRACE": os.fspath(trace)})
    caplog.set_level(logging.DEBUG, logger=mcp.__name__)

    scanner = _RecordingScanner()
    results, _stderr_size = asyncio.run(mcp._scan_windows_stdio_tools(scanner, _python_plan(env), ["fixture"]))

    stages = [
        record.getMessage().split("stage=", 1)[1].split()[0]
        for record in caplog.records
        if "Windows MCP stdio lifecycle stage=" in record.getMessage()
    ]
    assert stages == [
        "transport-opening",
        "process-created-job-assigned-resumed",
        "process-context-entered",
        "transport-opened",
        "initialize-sent",
        "initialize-responded-initialized-sent",
        "tools-list-sent",
        "tools-list-responded",
        "session-closed",
        "process-context-exited",
        "job-containment-closed",
        "transport-closed",
        "analyzer-handoff",
        "analyzer-completed",
    ]
    protocol = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in protocol] == [
        "process_started",
        "initialize_received",
        "initialize_responded",
        "initialized_received",
        "tools_list_received",
        "tools_list_responded",
    ]
    assert protocol[-1]["tools"] == ["benign_echo", "malicious_shell"]
    assert [result.tool_name for result in results] == ["benign_echo", "malicious_shell"]


@pytest.mark.allow_subprocess
@pytest.mark.skipif(os.name != "nt", reason="native Windows stdio adapter")
def test_yara_verdicts_keep_clean_and_malicious_tool_semantics() -> None:
    from mcpscanner import Config, Scanner
    from mcpscanner.core.models import AnalyzerEnum

    scanner = Scanner(Config())
    results, _stderr_size = asyncio.run(
        mcp._scan_windows_stdio_tools(
            scanner,
            _python_plan(mcp._safe_subprocess_env(None)),
            [AnalyzerEnum.YARA],
        )
    )
    by_name = {result.tool_name: result for result in results}

    assert set(by_name) == {"benign_echo", "malicious_shell"}
    assert by_name["benign_echo"].findings == []
    assert by_name["malicious_shell"].findings


@pytest.mark.allow_subprocess
@pytest.mark.skipif(not HOST_NPX, reason="native npx.cmd is unavailable")
def test_native_npx_cmd_acceptance_with_quoted_local_package(
    tmp_path: Path,
) -> None:
    package = tmp_path / "fixture package with spaces"
    shutil.copytree(FIXTURES / "node", package)
    entry = MCPServerEntry(
        name="native-npx",
        command="npx",
        args=[
            "--yes",
            "--offline",
            f"--package={package}",
            "defenseclaw-mcp-launcher-fixture",
        ],
        env={},
    )
    plan = mcp._windows_stdio_launch_plan(entry)
    scanner = _RecordingScanner()
    results, _stderr_size = asyncio.run(mcp._scan_windows_stdio_tools(scanner, plan, ["fixture"]))

    assert Path(plan.args[5]).name.lower() == "npx.cmd"
    assert [result.tool_name for result in results] == ["benign_echo", "malicious_shell"]


@pytest.mark.allow_subprocess
@pytest.mark.skipif(
    not (HOST_UVX and HOST_UV and HOST_LOCALAPPDATA),
    reason="native uvx.exe/uv.exe is unavailable",
)
def test_native_uvx_exe_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The suite redirects Windows identity roots, while setup-uv may install
    # the real executable in a hosted toolcache instead of LOCALAPPDATA.
    # Opt that exact parent into the production trust gate; owner/DACL checks
    # still apply to the executable and its chain through this narrow prefix.
    monkeypatch.setenv("LOCALAPPDATA", HOST_LOCALAPPDATA)
    monkeypatch.setenv("DEFENSECLAW_TRUSTED_BIN_PREFIXES", os.fspath(Path(HOST_UVX).parent))
    fixture_wheel = _build_python_fixture_wheel(FIXTURES / "python", tmp_path / "fixture wheel")
    entry = MCPServerEntry(
        name="native-uvx",
        command="uvx",
        args=[
            "--offline",
            "--from",
            os.fspath(fixture_wheel),
            "defenseclaw-mcp-launcher-fixture",
        ],
        env={},
    )
    plan = mcp._windows_stdio_launch_plan(entry)
    scanner = _RecordingScanner()
    results, _stderr_size = asyncio.run(mcp._scan_windows_stdio_tools(scanner, plan, ["fixture"]))

    assert Path(plan.command).name.lower() == "uvx.exe"
    assert [result.tool_name for result in results] == ["benign_echo", "malicious_shell"]


def _run_public_installed_cli(
    bin_dir: Path,
    env: dict[str, str],
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    child_env = dict(env)
    child_env["WIN_AUD_064_CLI_ARGV"] = json.dumps(args)
    completed = subprocess.run(
        [
            os.fspath(HOST_POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ("$forward = ConvertFrom-Json $env:WIN_AUD_064_CLI_ARGV; & defenseclaw @forward; exit $LASTEXITCODE"),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=child_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"installed CLI failed ({completed.returncode}):\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return completed


def _read_fixture_trace(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.allow_subprocess
@pytest.mark.skipif(
    not (os.name == "nt" and HOST_NPX and HOST_UVX and HOST_UV and HOST_POWERSHELL),
    reason="native npx, uvx, uv, and Windows PowerShell are required",
)
def test_installed_cli_batch_entrypoint_scans_npx_and_uvx_for_both_connectors(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    """Exercise the wheel and public .cmd entrypoint, not an internal adapter."""

    repo = Path(__file__).resolve().parents[2]
    dist = tmp_path / "dist"
    venv = tmp_path / "installed-venv"
    subprocess.run(
        [os.fspath(HOST_UV), "build", "--wheel", "--out-dir", os.fspath(dist)],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    subprocess.run(
        [
            os.fspath(HOST_UV),
            "venv",
            "--python",
            sys.executable,
            os.fspath(venv),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    python = venv / "Scripts" / "python.exe"
    wheel = next(dist.glob("defenseclaw-*.whl"))
    subprocess.run(
        [
            os.fspath(HOST_UV),
            "pip",
            "install",
            "--python",
            os.fspath(python),
            "--no-deps",
            os.fspath(wheel),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    # Keep this deterministic and offline: the wheel under test is installed
    # in the fresh venv, while its already-pinned dependencies are imported
    # from the repository venv.  Added .pth directories do not recursively
    # process the editable-install .pth, so DefenseClaw itself still comes
    # from the built wheel (verified below).
    dependency_site = next(
        Path(item) for item in sys.path if item.lower().endswith("site-packages") and Path(item).is_dir()
    )
    installed_site = venv / "Lib" / "site-packages"
    (installed_site / "win-aud-064-dependencies.pth").write_text(
        "\n".join(
            (
                os.fspath(dependency_site),
                os.fspath(dependency_site / "win32"),
                os.fspath(dependency_site / "win32" / "lib"),
                os.fspath(dependency_site / "Pythonwin"),
                "import pywin32_bootstrap",
            )
        ),
        encoding="utf-8",
    )
    probe = subprocess.run(
        [python, "-c", "import defenseclaw; print(defenseclaw.__file__)"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=True,
    )
    assert os.path.normcase(probe.stdout.strip()).startswith(os.path.normcase(os.fspath(installed_site)))

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cli_exe = venv / "Scripts" / "defenseclaw.exe"
    (bin_dir / "defenseclaw.cmd").write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        'set "PYTHONPATH="\r\n'
        'set "PYTHONHOME="\r\n'
        f'"{cli_exe}" %*\r\n'
        'set "defenseclawExit=%errorlevel%"\r\n'
        "endlocal & exit /b %defenseclawExit%\r\n",
        encoding="ascii",
    )
    # The installed CLI validates v8 through its release-paired Go helper.
    # Keep this wheel-focused test independent of any older gateway installed
    # on the host while preserving the exact versioned helper wire contract.
    gateway = bin_dir / "defenseclaw-gateway.cmd"
    gateway.write_text(
        "@echo off\r\n"
        'if /I "%~1 %~2"=="config-v8 validate" (\r\n'
        '  echo {"wire_version":2,"kind":"validation","config_version":8,'
        '"source":"fixture","data_dir":"fixture","gateway_api_port":18970,'
        '"plan_digest":"fixture","network_validation":"offline","valid":true}\r\n'
        "  exit /b 0\r\n"
        ")\r\n"
        'if /I "%~1"=="--version" (\r\n'
        "  echo defenseclaw-gateway 0.0.0-test\r\n"
        "  exit /b 0\r\n"
        ")\r\n"
        "exit /b 64\r\n",
        encoding="ascii",
    )

    admitted: list[dict] = []

    class GatewayHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if (
                self.path != "/api/v1/observability/cli"
                or self.headers.get("Authorization") != "Bearer fixture-gateway-token"
            ):
                self.send_response(401)
                self.end_headers()
                return
            admitted.append(json.loads(body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    gateway_server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()

    def stop_gateway() -> None:
        gateway_server.shutdown()
        gateway_server.server_close()
        gateway_thread.join(timeout=2)

    request.addfinalizer(stop_gateway)

    profile = tmp_path / "profile"
    dc_home = profile / ".defenseclaw"
    dc_home.mkdir(parents=True)
    config = dc_home / "config.yaml"
    config.write_text(
        "config_version: 8\n"
        "guardrail:\n"
        "  enabled: true\n"
        "  connector: codex\n"
        "  connectors:\n"
        "    codex:\n"
        "      mode: observe\n"
        "    claudecode:\n"
        "      mode: observe\n"
        "scanners:\n"
        "  mcp_scanner:\n"
        "    analyzers: yara\n"
        "gateway:\n"
        "  api_bind: 127.0.0.1\n"
        f"  api_port: {gateway_server.server_port}\n"
        "  token_env: DEFENSECLAW_GATEWAY_TOKEN\n"
        "observability: {}\n",
        encoding="utf-8",
    )
    fixture_root = tmp_path / "fixture packages with spaces"
    node_fixture = fixture_root / "node fixture with spaces"
    python_fixture = fixture_root / "python fixture with spaces"
    shutil.copytree(FIXTURES / "node", node_fixture)
    shutil.copytree(FIXTURES / "python", python_fixture)
    python_fixture_wheel = _build_python_fixture_wheel(
        python_fixture,
        fixture_root / "python wheel dist with spaces",
    )

    traces = tmp_path / "traces"
    traces.mkdir()
    npx_trace = traces / "npx.jsonl"
    uvx_trace = traces / "uvx.jsonl"
    npx_report = traces / "npx-env.json"
    uvx_report = traces / "uvx-env.json"
    npx_args = [
        "--yes",
        "--offline",
        f"--package={node_fixture}",
        "defenseclaw-mcp-launcher-fixture",
    ]
    uvx_args = [
        "--offline",
        "--from",
        os.fspath(python_fixture_wheel),
        "defenseclaw-mcp-launcher-fixture",
    ]
    env = dict(os.environ)
    env.update(
        {
            "PATH": os.pathsep.join((os.fspath(bin_dir), env["PATH"])),
            "HOME": os.fspath(profile),
            "USERPROFILE": os.fspath(profile),
            "APPDATA": os.fspath(profile / "AppData" / "Roaming"),
            "LOCALAPPDATA": HOST_LOCALAPPDATA,
            "DEFENSECLAW_TRUSTED_BIN_PREFIXES": os.fspath(Path(HOST_UVX).parent),
            "DEFENSECLAW_HOME": os.fspath(dc_home),
            "DEFENSECLAW_CONFIG": os.fspath(config),
            "DEFENSECLAW_GATEWAY_BIN": os.fspath(gateway),
            "DEFENSECLAW_GATEWAY_TOKEN": "fixture-gateway-token",
            "PYTHONPATH": os.fspath(tmp_path / "hostile-python-path"),
            "PYTHONHOME": os.fspath(tmp_path / "hostile-python-home"),
            "WIN_AUD_064_TEST_API_KEY": "must-not-reach-fixture",
        }
    )

    registrations = (
        (
            "installed-npx",
            "npx",
            npx_args,
            npx_trace,
            npx_report,
        ),
        (
            "installed-uvx",
            "uvx",
            uvx_args,
            uvx_trace,
            uvx_report,
        ),
    )
    for name, command, args, trace, report in registrations:
        _run_public_installed_cli(
            bin_dir,
            env,
            "mcp",
            "set",
            name,
            "--command",
            command,
            "--args",
            json.dumps(args, separators=(",", ":")),
            "--transport",
            "stdio",
            "--env",
            "MCP_FIXTURE_REQUIRED=present",
            "--env",
            f"MCP_FIXTURE_TRACE={trace}",
            "--env",
            f"MCP_FIXTURE_ENV_REPORT={report}",
            "--skip-scan",
        )

    listed = json.loads(_run_public_installed_cli(bin_dir, env, "mcp", "list", "--connector", "codex", "--json").stdout)
    by_name = {entry["name"]: entry for entry in listed["mcp_servers"]}
    assert by_name["installed-npx"]["args"] == npx_args
    assert by_name["installed-uvx"]["args"] == uvx_args

    for connector in ("codex", "claudecode"):
        for name, _command, _args, _trace, _report in registrations:
            payload = json.loads(
                _run_public_installed_cli(
                    bin_dir,
                    env,
                    "mcp",
                    "scan",
                    name,
                    "--connector",
                    connector,
                    "--analyzers",
                    "yara",
                    "--json",
                ).stdout
            )
            assert payload.get("error") is None
            assert payload["connector"] == connector
            assert {finding["location"] for finding in payload["findings"]} == {"tool:malicious_shell"}

    all_payload = json.loads(
        _run_public_installed_cli(bin_dir, env, "mcp", "scan", "--all", "--analyzers", "yara", "--json").stdout
    )
    assert len(all_payload) == 4
    assert {item["connector"] for item in all_payload} == {"codex", "claudecode"}
    assert all(not item.get("error") for item in all_payload)

    for trace in (npx_trace, uvx_trace):
        responses = [event for event in _read_fixture_trace(trace) if event["event"] == "tools_list_responded"]
        assert len(responses) == 4
        assert all(response["tools"] == ["benign_echo", "malicious_shell"] for response in responses)
    for report in (npx_report, uvx_report):
        assert json.loads(report.read_text(encoding="utf-8")) == {
            "requiredPresent": True,
            "secretAbsent": True,
        }

    install_trace = traces / "install-time.jsonl"
    _run_public_installed_cli(
        bin_dir,
        env,
        "mcp",
        "set",
        "installed-clean",
        "--command",
        "uvx",
        "--args",
        json.dumps(uvx_args, separators=(",", ":")),
        "--transport",
        "stdio",
        "--env",
        "MCP_FIXTURE_MODE=benign_only",
        "--env",
        f"MCP_FIXTURE_TRACE={install_trace}",
        "--connector",
        "codex",
    )
    install_responses = [
        event for event in _read_fixture_trace(install_trace) if event["event"] == "tools_list_responded"
    ]
    assert install_responses == [{"event": "tools_list_responded", "tools": ["benign_echo"]}]
    assert admitted


@pytest.mark.parametrize(
    ("exc", "errors", "launcher", "expected"),
    [
        (TimeoutError(), [], "uvx", "MCP stdio timeout"),
        (OSError(), [], "uvx", "launcher startup failed"),
        (OSError(), [], "npx", "Windows npx wrapper startup failed"),
        (ConnectionError("Connection closed"), [], "uvx", "exited before completing"),
        (ValueError("opaque"), [("mcp.client.stdio", "Failed to parse JSONRPC message")], "uvx", "protocol failure"),
    ],
)
def test_error_boundaries_are_distinct_and_stderr_safe(
    exc: BaseException,
    errors: list[tuple[str, str]],
    launcher: str,
    expected: str,
) -> None:
    plan = mcp._StdioLaunchPlan("resolved", (), {}, launcher)
    message = str(
        mcp._classify_windows_stdio_error(
            exc,
            plan,
            errors + [("fixture", "do-not-disclose-this-marker")],
            32,
            7,
        )
    )
    assert expected in message
    assert "Connection closed" not in message
    assert "do-not-disclose-this-marker" not in message
    assert "captured and withheld" in message


def test_windows_scan_preserves_cancellation() -> None:
    wrapper = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    plan = mcp._StdioLaunchPlan("resolved", (), {}, "uvx")

    async def cancel(*_args, **_kwargs):
        raise asyncio.CancelledError

    with (
        patch.object(mcp.os, "name", "nt"),
        patch.object(mcp, "_windows_stdio_launch_plan", return_value=plan),
        patch.object(mcp, "_scan_windows_stdio_tools", cancel),
        pytest.raises(asyncio.CancelledError),
    ):
        wrapper._scan_local(
            SimpleNamespace(),
            MCPServerEntry(name="fixture", command="uvx", args=["package"]),
            [],
        )


@pytest.mark.allow_subprocess
@pytest.mark.skipif(os.name != "nt", reason="native Windows stdio adapter")
def test_early_exit_is_reported_without_leaking_stderr_marker() -> None:
    marker = "private-stderr-marker"
    env = mcp._safe_subprocess_env({"MCP_FIXTURE_MODE": "early_exit", "MCP_FIXTURE_STDERR": marker})
    errors: list[tuple[str, str]] = []
    with pytest.raises(BaseException) as caught, mcp._capture_sdk_error_logs(errors):
        asyncio.run(
            mcp._scan_windows_stdio_tools(_RecordingScanner(), _python_plan(env), ["fixture"], timeout_seconds=5)
        )

    stderr_size = int(getattr(caught.value, "_defenseclaw_stderr_size", 0) or 0)
    message = str(mcp._classify_windows_stdio_error(caught.value, _python_plan(env), errors, stderr_size, 5))
    assert "exited before completing" in message
    assert marker not in message


@pytest.mark.allow_subprocess
@pytest.mark.skipif(os.name != "nt", reason="native Windows stdio adapter")
def test_protocol_error_is_distinguished_from_timeout() -> None:
    env = mcp._safe_subprocess_env({"MCP_FIXTURE_MODE": "protocol_error"})
    errors: list[tuple[str, str]] = []
    with pytest.raises(BaseException) as caught, mcp._capture_sdk_error_logs(errors):
        asyncio.run(
            mcp._scan_windows_stdio_tools(_RecordingScanner(), _python_plan(env), ["fixture"], timeout_seconds=0.5)
        )

    message = str(
        mcp._classify_windows_stdio_error(
            caught.value,
            _python_plan(env),
            errors,
            int(getattr(caught.value, "_defenseclaw_stderr_size", 0) or 0),
            0.5,
        )
    )
    assert "protocol failure" in message
    assert "timeout" not in message.lower()


@pytest.mark.allow_subprocess
@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object regression")
def test_timeout_cleans_up_process_tree_without_orphan(tmp_path: Path) -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_exit_code.restype = ctypes.c_int

    def pid_exists(pid: int) -> bool:
        handle = open_process(0x1000, 0, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            try:
                exit_code = ctypes.c_uint32()
                if get_exit_code(handle, ctypes.byref(exit_code)):
                    return exit_code.value == 259  # STILL_ACTIVE
                return True
            finally:
                close_handle(handle)
        # ERROR_INVALID_PARAMETER means the PID no longer exists. Access
        # denied still means a live process, so fail closed for the assertion.
        return ctypes.get_last_error() != 87

    child_pid_path = tmp_path / "child.pid"
    env = mcp._safe_subprocess_env(
        {
            "MCP_FIXTURE_MODE": "timeout",
            "MCP_FIXTURE_CHILD_PID": os.fspath(child_pid_path),
        }
    )
    with pytest.raises(BaseException):
        asyncio.run(
            mcp._scan_windows_stdio_tools(_RecordingScanner(), _python_plan(env), ["fixture"], timeout_seconds=1)
        )

    deadline = time.monotonic() + 5
    while not child_pid_path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert child_pid_path.exists()
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    while pid_exists(child_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not pid_exists(child_pid)


def test_non_windows_local_scan_preserves_existing_scanner_config_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict = {}

    class FakeScanner:
        async def scan_mcp_config_file(self, **kwargs):
            config_path = kwargs["config_path"]
            seen.update(json.loads(Path(config_path).read_text(encoding="utf-8")))
            return []

    wrapper = mcp.MCPScannerWrapper(MCPScannerConfig(analyzers="yara"))
    monkeypatch.setattr(mcp.os, "name", "posix")
    result = wrapper._scan_local(
        FakeScanner(),
        MCPServerEntry(name="fixture", command="npx", args=["package"], env={}),
        analyzers=[],
    )

    assert result == []
    assert seen["mcpServers"]["fixture"]["command"] == "npx"
    assert seen["mcpServers"]["fixture"]["args"] == ["package"]
