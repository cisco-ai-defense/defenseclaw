# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Claude Desktop's Claude Code engine counts as a Claude Code installation
(cowork-1-0-8 GAP-0036): an account with Claude Desktop and no claude CLI."""

from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path

import pytest
from defenseclaw import agent_selection
from defenseclaw.commands import cmd_setup
from defenseclaw.connector_contracts import resolve_connector_contract
from defenseclaw.doctor_health import HealthStatus, assess_connector_health
from defenseclaw.inventory import agent_discovery as ad
from defenseclaw.inventory import claude_desktop

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits")

# Measured build folders (IN-3p.md): macOS 91184d3d9ba3, Windows a33aa5518497.
_BUILD = {"darwin": "91184d3d9ba3", "windows": "a33aa5518497", "linux": "b1"}


def _folders(home: Path) -> dict[str, Path]:
    return {
        "home": home,
        "config": home / ".config",
        "appdata": home / "AppData" / "Roaming",
        "localappdata": home / "AppData" / "Local",
    }


@pytest.fixture
def host(monkeypatch, tmp_path):
    """A clean account; returns a function that picks the simulated OS."""
    home = tmp_path / "home"
    home.mkdir()
    folders = _folders(home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dc"))
    monkeypatch.setenv("APPDATA", str(folders["appdata"]))
    monkeypatch.setenv("LOCALAPPDATA", str(folders["localappdata"]))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(ad, "_which", lambda _name: "")

    def pick(platform: str) -> dict[str, Path]:
        monkeypatch.setattr(ad, "_is_windows_host", lambda: platform == "windows")
        if platform == "windows" and os.name != "nt":
            # The change time Windows gives is the one this system keeps (a
            # Windows host reads its own).
            monkeypatch.setattr(
                ad,
                "_windows_change_time",
                lambda path: os.lstat(path).st_ctime_ns // 100 + ad._WINDOWS_TICKS_AT_UNIX_EPOCH,
            )
        monkeypatch.setattr(ad, "_is_macos_host", lambda: platform == "darwin")
        # Windows file-version metadata of the fake claude.exe: the version of
        # the folder it sits in, unless a test says otherwise.
        monkeypatch.setattr(
            ad, "_windows_file_version_for_binary", lambda path, **_kw: (Path(path).parent.parent.name, "")
        )
        # No Windows CLI install roots on this account.
        monkeypatch.setattr(ad, "_windows_binary_candidates", lambda _connector, _name: ())
        return folders

    return pick


def _data_dir(folders: dict[str, Path], base: str, rel: str) -> Path:
    return folders[base].joinpath(*rel.replace("*", "pzs8sxrjxfjjc").split("/"))


def _engine(platform: str, data: Path, version: str, *, plist_version: str | None = None) -> Path:
    """One engine build in the measured layout of *platform*."""
    build = data / "claude-code" / version / _BUILD[platform]
    if platform == "darwin":
        contents = build / "claude.app" / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        (contents / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.anthropic.claude-code",
                    "CFBundleShortVersionString": plist_version or version,
                }
            )
        )
        exe = contents / "MacOS" / "claude"
    else:
        build.mkdir(parents=True)
        exe = build / ("claude.exe" if platform == "windows" else "claude")
    exe.write_bytes(b"engine")
    exe.chmod(0o755)
    return exe


def _probe(monkeypatch, answers: dict[str, str]):
    """Fake --version runs: argv[0] -> first stdout line; records each run."""
    runs: list[tuple[str, float]] = []

    def run(argv, **kwargs):
        runs.append((argv[0], kwargs["timeout"]))
        out = answers.get(argv[0])
        if out is None:
            return subprocess.CompletedProcess(argv, 1, b"", b"not expected")
        return subprocess.CompletedProcess(argv, 0, out.encode() + b"\n", b"")

    monkeypatch.setattr(ad, "_run_probe", run)
    return runs


def _scan(tmp_path: Path, *, probe: bool = True) -> ad.AgentSignal:
    return ad._scan_agent("claudecode", data_dir=tmp_path / "dc", include_workspace_config=False, probe=probe)


def _root_cases(*platforms: str):
    return [
        pytest.param(p, d, b, r, id=f"{p}-{d}-{r}", marks=() if p == "windows" else POSIX_ONLY)
        for p in platforms
        for d, b, r in claude_desktop.CLAUDE_DESKTOP_ROOTS[p]
    ]


@pytest.mark.parametrize(("platform", "deployment", "base", "rel"), _root_cases("darwin", "windows", "linux"))
def test_engine_in_every_data_root_is_claude_code(host, monkeypatch, tmp_path, platform, deployment, base, rel):
    """macOS 1p/3p, Windows Roaming/Claude-Data (MSIX)/LocalCache/Claude-3p, Linux 1p/3p."""
    folders = host(platform)
    exe = _engine(platform, _data_dir(folders, base, rel), "2.1.317")
    runs = _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})

    signal = _scan(tmp_path)

    assert signal.installed, signal.error
    assert signal.binary_path == str(exe)
    assert signal.version == "2.1.317 (Claude Code)"
    assert signal.source == ad.SOURCE_CLAUDE_DESKTOP
    # Run exactly as the claude CLI is: --version, the same timeout.
    assert runs == [(str(exe), ad.VERSION_TIMEOUT_SECONDS)]
    contract = resolve_connector_contract("claudecode", signal.version)
    assert contract.contract is not None and contract.contract.contract_id == "claudecode-hooks-v2"


@pytest.mark.parametrize(
    ("platform", "older", "newer"),
    [
        pytest.param(
            "darwin",
            ("home", "Library/Application Support/Claude"),
            ("home", "Library/Application Support/Claude-3p"),
            marks=POSIX_ONLY,
        ),
        pytest.param("windows", ("localappdata", "Claude-Data/claude_*"), ("localappdata", "Claude-3p")),
        pytest.param("linux", ("config", "Claude-3p"), ("config", "Claude"), marks=POSIX_ONLY),
    ],
)
def test_newest_engine_build_across_folders_wins(host, monkeypatch, tmp_path, platform, older, newer):
    folders = host(platform)
    old = _engine(platform, _data_dir(folders, *older), "2.1.309")
    new = _engine(platform, _data_dir(folders, *newer), "2.1.317")
    _engine(platform, _data_dir(folders, *older), "2.1.98")  # numeric, not string, order
    _probe(monkeypatch, {str(old): "2.1.309 (Claude Code)", str(new): "2.1.317 (Claude Code)"})

    signal = _scan(tmp_path)

    assert (signal.binary_path, signal.version) == (str(new), "2.1.317 (Claude Code)")
    assert ad._claude_desktop_engine_candidates()[:2] == (str(new), str(old))


@POSIX_ONLY
def test_same_version_in_both_folders_reads_the_3p_build(host, monkeypatch, tmp_path):
    """The Cowork Mac: Claude and Claude-3p both hold 2.1.317; Desktop runs 3p."""
    folders = host("darwin")
    first = _engine("darwin", _data_dir(folders, "home", "Library/Application Support/Claude"), "2.1.317")
    third = _engine("darwin", _data_dir(folders, "home", "Library/Application Support/Claude-3p"), "2.1.317")
    _probe(monkeypatch, {str(first): "2.1.317 (Claude Code)", str(third): "2.1.317 (Claude Code)"})

    assert _scan(tmp_path).binary_path == str(third)
    assert [b.deployment for b in claude_desktop.claude_desktop_engines("darwin")] == ["3p", "1p"]


@pytest.mark.parametrize(
    "platform", [pytest.param("darwin", marks=POSIX_ONLY), "windows", pytest.param("linux", marks=POSIX_ONLY)]
)
def test_claude_cli_wins_over_the_desktop_engine(host, monkeypatch, tmp_path, platform):
    folders = host(platform)
    base, rel = claude_desktop.CLAUDE_DESKTOP_ROOTS[platform][-1][1:]
    exe = _engine(platform, _data_dir(folders, base, rel), "2.1.317")
    cli = tmp_path / "bin" / ("claude.exe" if platform == "windows" else "claude")
    cli.parent.mkdir()
    cli.write_bytes(b"cli")
    cli.chmod(0o755)
    monkeypatch.setattr(ad, "_which", lambda name: str(cli) if name == "claude" else "")
    runs = _probe(monkeypatch, {str(cli): "2.1.200 (Claude Code)", str(exe): "2.1.317 (Claude Code)"})

    signal = _scan(tmp_path)

    assert (signal.binary_path, signal.version, signal.source) == (str(cli), "2.1.200 (Claude Code)", ad.SOURCE_CLI)
    assert [path for path, _ in runs] == [str(cli)]


@POSIX_ONLY
def test_cli_that_does_not_answer_falls_back_to_the_engine(host, monkeypatch, tmp_path):
    folders = host("darwin")
    exe = _engine("darwin", _data_dir(folders, "home", "Library/Application Support/Claude-3p"), "2.1.317")
    cli = tmp_path / "bin" / "claude"
    cli.parent.mkdir()
    cli.write_bytes(b"cli")
    cli.chmod(0o755)
    monkeypatch.setattr(ad, "_which", lambda name: str(cli) if name == "claude" else "")
    _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})  # the CLI exits 1

    signal = _scan(tmp_path)

    assert (signal.binary_path, signal.source) == (str(exe), ad.SOURCE_CLAUDE_DESKTOP)
    assert signal.skipped_binaries == (str(cli),)


@POSIX_ONLY
def test_macos_info_plist_must_name_the_folder_version(host, monkeypatch, tmp_path):
    """A build whose Info.plist names another version is passed over unrun."""
    folders = host("darwin")
    data = _data_dir(folders, "home", "Library/Application Support/Claude-3p")
    copied = _engine("darwin", data, "2.1.320", plist_version="2.1.98")
    good = _engine("darwin", data, "2.1.317")
    runs = _probe(monkeypatch, {str(copied): "2.1.320 (Claude Code)", str(good): "2.1.317 (Claude Code)"})

    signal = _scan(tmp_path)

    assert (signal.binary_path, signal.version) == (str(good), "2.1.317 (Claude Code)")
    assert [path for path, _ in runs] == [str(good)]


def test_windows_file_version_must_name_the_folder_version(host, monkeypatch, tmp_path):
    folders = host("windows")
    exe = _engine("windows", _data_dir(folders, "localappdata", "Claude-3p"), "2.1.317")
    monkeypatch.setattr(ad, "_windows_file_version_for_binary", lambda _p, **_kw: ("2.1.200.0", ""))
    runs = _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})

    signal = _scan(tmp_path)

    assert not signal.installed and not runs
    assert "its file version is '2.1.200.0'" in signal.error


@pytest.mark.parametrize("platform", [pytest.param("darwin", marks=POSIX_ONLY), "windows"])
def test_engine_must_report_its_folder_version(host, monkeypatch, tmp_path, platform):
    folders = host(platform)
    base, rel = claude_desktop.CLAUDE_DESKTOP_ROOTS[platform][-2 if platform == "windows" else -1][1:]
    exe = _engine(platform, _data_dir(folders, base, rel), "2.1.317")
    _probe(monkeypatch, {str(exe): "2.1.300 (Claude Code)"})

    signal = _scan(tmp_path)

    assert not signal.installed
    assert "reports version '2.1.300 (Claude Code)'" in signal.error


@POSIX_ONLY
@pytest.mark.parametrize("kind", ["not-executable", "symlink", "no-engine", "vm-copy"])
def test_linux_version_folder_without_a_real_engine_is_not_claude_code(host, monkeypatch, tmp_path, kind):
    folders = host("linux")
    data = _data_dir(folders, "config", "Claude-3p")
    if kind == "vm-copy":
        # The Cowork VM's copy is a sibling of claude-code, not a build.
        vm = data / "claude-code-vm" / "2.1.317" / "claude"
        vm.parent.mkdir(parents=True)
        vm.write_bytes(b"vm")
        vm.chmod(0o755)
    else:
        version = data / "claude-code" / "2.1.317"
        version.mkdir(parents=True)
        if kind == "not-executable":
            (version / "claude").write_bytes(b"x")
            (version / "claude").chmod(0o644)
        elif kind == "symlink":
            target = tmp_path / "elsewhere"
            target.write_bytes(b"x")
            target.chmod(0o755)
            (version / "claude").symlink_to(target)
    runs = _probe(monkeypatch, {})

    signal = _scan(tmp_path)

    assert not signal.installed and not signal.binary_path and not runs
    assert claude_desktop.claude_desktop_engines("linux") == []


@POSIX_ONLY
def test_linux_engine_directly_in_the_version_folder(host, monkeypatch, tmp_path):
    folders = host("linux")
    exe = _data_dir(folders, "config", "Claude") / "claude-code" / "2.1.317" / "claude"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"engine")
    exe.chmod(0o755)
    _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})

    assert _scan(tmp_path).binary_path == str(exe)


def test_unprobed_scan_counts_the_engine_without_running_it(host, monkeypatch, tmp_path):
    folders = host("windows")
    exe = _engine("windows", _data_dir(folders, "localappdata", "Claude-Data/claude_*"), "2.1.317")
    runs = _probe(monkeypatch, {})

    signal = _scan(tmp_path, probe=False)

    assert (signal.installed, signal.binary_path, signal.error) == (True, str(exe), ad.VERSION_NOT_PROBED)
    assert signal.source == ad.SOURCE_CLAUDE_DESKTOP and not runs


def test_cache_keeps_the_source(tmp_path):
    agents = {
        name: ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        for name in ad.DISCOVERABLE_CONNECTORS
    }
    agents["claudecode"] = ad.AgentSignal(
        name="claudecode",
        installed=True,
        config_path="",
        binary_path="/e/claude",
        version="2.1.317 (Claude Code)",
        error="",
        source=ad.SOURCE_CLAUDE_DESKTOP,
    )
    agents["codex"].source = "made-up"
    disc = ad.AgentDiscovery(scanned_at=ad._format_rfc3339(ad._now_utc()), agents=agents, cache_hit=False)
    assert ad._write_cache(disc, data_dir=tmp_path)

    cached = ad._read_cache(data_dir=tmp_path)

    assert cached is not None
    assert cached.agents["claudecode"].source == ad.SOURCE_CLAUDE_DESKTOP
    assert cached.agents["codex"].source == ""
    assert "(Claude Desktop engine)" in ad._render_plain_table(cached)


def test_doctor_counts_the_engine_as_the_claude_code_installation():
    signal = ad.AgentSignal(
        name="claudecode",
        installed=True,
        config_path="",
        binary_path="/e/claude",
        version="2.1.317 (Claude Code)",
        error="",
        source=ad.SOURCE_CLAUDE_DESKTOP,
    )
    disc = ad.AgentDiscovery(scanned_at="2026-11-04T06:00:00Z", agents={"claudecode": signal}, cache_hit=True)

    (finding,) = assess_connector_health(["claudecode"], disc)

    assert finding.status is HealthStatus.SUPPORTED
    assert finding.contract_id == "claudecode-hooks-v2"
    assert finding.installed_version == "2.1.317"


def test_setup_names_the_engine_and_does_not_say_not_installed(capsys, tmp_path):
    signal = ad.AgentSignal(
        name="claudecode",
        installed=True,
        config_path="",
        binary_path="/e/2.1.317/b/claude.app/Contents/MacOS/claude",
        version="2.1.317 (Claude Code)",
        error="",
        source=ad.SOURCE_CLAUDE_DESKTOP,
    )
    disc = ad.AgentDiscovery(scanned_at="2026-11-04T06:00:00Z", agents={"claudecode": signal}, cache_hit=False)

    assert cmd_setup._check_connector_version_supported_for_setup(
        "claudecode", data_dir=str(tmp_path), _discovery=disc, _allow_prompt=False
    )

    captured = capsys.readouterr()
    out = " ".join((captured.out + captured.err).split())
    assert "using Claude Desktop's Claude Code engine" in out and "no claude CLI was found" in out
    assert "not installed" not in out
    assert "claudecode-hooks-v2" in out


def test_windows_selection_takes_the_signed_engine_without_a_cli(host, monkeypatch, tmp_path):
    """GAP-0039: Windows setup binds the Authenticode-verified engine (the
    gateway's check) as Claude Code's executable on a Desktop-only account."""
    folders = host("windows")
    exe = _engine("windows", _data_dir(folders, "localappdata", "Claude-3p"), "2.1.317")
    _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})
    calls = []

    def gateway():
        calls.append(1)
        return {
            "version": "2.1.317",
            "engine_dir": str(exe.parent.parent.parent),
            "executable": str(exe),
            "sha256": agent_selection.stable_executable_sha256(str(exe)),
        }

    monkeypatch.setattr(agent_selection, "_verified_claude_desktop_engine", gateway)
    spec = ad._SPECS["claudecode"]
    assert str(exe) in ad._binary_candidates_for_agent("claudecode", spec)
    assert str(exe) not in agent_selection._setup_agent_candidates("claudecode", spec, str(tmp_path / "dc"))

    selection = agent_selection._select_agent_executable(str(tmp_path / "dc"), "claudecode")

    assert (selection.executable, selection.raw_version, selection.normalized_version) == (
        str(exe),
        "2.1.317 (Claude Code)",
        "2.1.317",
    )
    assert selection.sha256 == agent_selection.stable_executable_sha256(str(exe))
    assert len(calls) == 2  # checked before and after the hash


@pytest.mark.parametrize(
    ("swapped", "message"),
    [
        # The gateway verified a signed file, then a same-user process put
        # another file in its place before setup hashed it (and back again
        # before the second check would see it).
        ("first", "changed while setup checked it"),
        # Setup hashed the file and probed it, then the signed file was put
        # back for the gateway's second check.
        ("second", "changed while setup checked it"),
        # A gateway that reports no digest cannot bind the signature.
        ("missing", "does not report the hash of the Claude Desktop engine it verified; update DefenseClaw"),
    ],
)
def test_windows_selection_refuses_an_engine_hash_the_signature_check_did_not_take(
    host, monkeypatch, tmp_path, swapped, message
):
    """GAP-0039 review: the digest setup records must be the one the gateway
    took over the handle whose Authenticode signature verified, in both
    checks; a gateway digest of other bytes refuses the selection."""
    folders = host("windows")
    exe = _engine("windows", _data_dir(folders, "localappdata", "Claude-3p"), "2.1.317")
    _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})
    own = agent_selection.stable_executable_sha256(str(exe))
    other = "0" * 64
    answers = {
        "first": [other, own],
        "second": [own, other],
        "missing": ["", ""],
    }[swapped]

    def gateway():
        return {"version": "2.1.317", "engine_dir": "", "executable": str(exe), "sha256": answers.pop(0)}

    monkeypatch.setattr(agent_selection, "_verified_claude_desktop_engine", gateway)
    with pytest.raises(OSError, match=message):
        agent_selection._select_agent_executable(str(tmp_path / "dc"), "claudecode")


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (
            {"reason": "not_found", "unverified": "Claude Desktop engine 2.1.317: claude.exe is not signed"},
            "is not signed",
        ),
        ({"version": "2.1.317", "executable": "C:/elsewhere/claude.exe", "sha256": "0" * 64},
         "not one of this account's engine builds"),
        (OSError("this defenseclaw-gateway cannot check Claude Desktop's engine"), "cannot check"),
    ],
)
def test_windows_selection_refuses_an_engine_the_gateway_does_not_verify(host, monkeypatch, tmp_path, answer, message):
    folders = host("windows")
    _engine("windows", _data_dir(folders, "localappdata", "Claude-Data/claude_*"), "2.1.317")
    _probe(monkeypatch, {})

    def gateway():
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(agent_selection, "_verified_claude_desktop_engine", gateway)
    with pytest.raises(OSError, match=message):
        agent_selection._select_agent_executable(str(tmp_path / "dc"), "claudecode")


def test_windows_selection_without_any_claude_code_is_unchanged(host, monkeypatch, tmp_path):
    host("windows")
    monkeypatch.setattr(agent_selection, "_verified_claude_desktop_engine", lambda: pytest.fail("gateway asked"))
    with pytest.raises(OSError, match="no installed executable"):
        agent_selection._select_agent_executable(str(tmp_path / "dc"), "claudecode")


@POSIX_ONLY
def test_action_mode_setup_admits_a_desktop_only_account(host, monkeypatch, tmp_path):
    """GAP-0037: setup claude-code --mode action and guardrail mode action run
    this check. On a Desktop-only account it passes and records the engine's
    version where the gateway reads it (agent_discovery.json)."""
    import json

    folders = host("darwin")
    exe = _engine("darwin", _data_dir(folders, "home", "Library/Application Support/Claude-3p"), "2.1.317")
    _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})
    data_dir = tmp_path / "dc"
    data_dir.mkdir()

    assert cmd_setup._check_connector_version_supported_for_setup(
        "claudecode", mode="action", data_dir=str(data_dir), _allow_prompt=False
    )

    cached = json.loads((data_dir / "agent_discovery.json").read_text())["agents"]["claudecode"]
    assert (cached["installed"], cached["binary_path"], cached["version"], cached["source"]) == (
        True,
        str(exe),
        "2.1.317 (Claude Code)",
        ad.SOURCE_CLAUDE_DESKTOP,
    )


def test_action_mode_still_refuses_without_any_claude_code(host, monkeypatch, tmp_path, capsys):
    host("windows")
    _probe(monkeypatch, {})
    data_dir = tmp_path / "dc"
    data_dir.mkdir()

    assert not cmd_setup._check_connector_version_supported_for_setup(
        "claudecode", mode="action", data_dir=str(data_dir), _allow_prompt=False
    )
    captured = capsys.readouterr()
    assert "not detected locally" in captured.out + captured.err


def test_windows_setup_receipt_binds_the_engine(host, monkeypatch, tmp_path):
    """GAP-0039 end to end at the selection layer: the protected receipt
    Windows setup publishes names the engine, and setup's own receipt
    validation accepts it."""
    folders = host("windows")
    exe = _engine("windows", _data_dir(folders, "localappdata", "Claude-Data/claude_*"), "2.1.317")
    _probe(monkeypatch, {str(exe): "2.1.317 (Claude Code)"})
    monkeypatch.setattr(
        agent_selection,
        "_verified_claude_desktop_engine",
        lambda: {
            "version": "2.1.317",
            "engine_dir": "",
            "executable": str(exe),
            "sha256": agent_selection.stable_executable_sha256(str(exe)),
        },
    )
    data_dir = tmp_path / "dc"
    data_dir.mkdir()

    selections, errors = agent_selection.record_setup_agent_selections(str(data_dir), ["claudecode"])

    assert errors == {} and selections["claudecode"].executable == str(exe)
    verified = cmd_setup._validate_setup_agent_selection_receipt(str(data_dir), ("claudecode",), selections)
    assert verified.record_for("claudecode").executable == str(exe)


@pytest.mark.parametrize(
    ("stdout", "stderr", "message"),
    [
        ("", 'Error: unknown command "claude-desktop-engine" for "defenseclaw-gateway connector"',
         "older than this CLI and cannot check Claude Desktop's engine; update DefenseClaw"),
        ("", "Error: unknown flag: --json", "older than this CLI"),
        # cowork-1-0-8 GAP-0043: any other failure names what the gateway said.
        ("", "Error: failed to load config: open config.yaml: no such file or directory",
         r"could not check Claude Desktop's engine signature \(exit 1: failed to load config: open config.yaml"),
        ("", "", r"\(exit 1 and printed nothing\); run defenseclaw doctor"),
        ('{"version": "2.1.317", "executable": "C:/x/claude.exe"}', "", None),
    ],
)
def test_gateway_engine_check_reads_the_hidden_command(monkeypatch, stdout, stderr, message):
    from defenseclaw import pinned_exec

    seen = []

    def run(argv, **_kw):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0 if stdout else 1, stdout, stderr)

    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda **_kw: "/opt/dc/bin/defenseclaw-gateway")
    monkeypatch.setattr(pinned_exec, "run_pinned_executable", run)
    if message:
        with pytest.raises(OSError, match=message):
            agent_selection._verified_claude_desktop_engine()
    else:
        assert agent_selection._verified_claude_desktop_engine()["executable"] == "C:/x/claude.exe"
    assert seen == [["/opt/dc/bin/defenseclaw-gateway", "connector", "claude-desktop-engine", "--json"]]
