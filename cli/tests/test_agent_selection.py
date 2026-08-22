# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import agent_selection
from defenseclaw.commands import cmd_setup


def test_openhands_protected_selection_roster_is_darwin_only(monkeypatch) -> None:
    connectors = ("codex", "claudecode", "openhands", "amp")
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "linux")
    assert agent_selection.setup_agent_selection_connectors(connectors) == (
        "codex",
        "claudecode",
        "amp",
    )
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    assert agent_selection.setup_agent_selection_connectors(connectors) == (
        "codex",
        "claudecode",
        "openhands",
        "amp",
    )


def test_darwin_guardrail_preselects_only_protected_native_connectors(monkeypatch) -> None:
    monkeypatch.setattr(cmd_setup.platform_support, "host_os", lambda: "darwin")

    assert cmd_setup._guardrail_preselection_connectors(
        ("codex", "claude-code", "openhands", "amp", "codex")
    ) == ("codex", "claudecode", "openhands")


def test_darwin_setup_records_all_protected_native_connectors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    selected = agent_selection.SetupAgentSelection(
        connector="openhands",
        executable="/usr/local/bin/openhands",
        raw_version="OpenHands CLI 1.16.0",
        normalized_version="1.16.0",
        sha256="a" * 64,
    )
    captured: list[tuple[str, ...]] = []
    monkeypatch.setattr(cmd_setup.platform_support, "host_os", lambda: "darwin")
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")

    def record(_data_dir, connectors):
        captured.append(tuple(connectors))
        return {name: selected for name in connectors}, {}

    sentinel = object()
    monkeypatch.setattr(agent_selection, "record_setup_agent_selections", record)
    monkeypatch.setattr(cmd_setup, "_validate_setup_agent_selection_receipt", lambda *_args, **_kwargs: sentinel)

    result = cmd_setup._record_windows_setup_agent_selections(
        tmp_path,
        ("codex", "claudecode", "openhands", "amp"),
    )

    assert result is sentinel
    assert captured == [("codex", "claudecode", "openhands")]


@pytest.mark.skipif(os.name == "nt", reason="Darwin POSIX executable custody")
def test_darwin_openhands_selection_binds_stable_executable_and_full_chain(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    versions = home / ".local" / "share" / "openhands" / "versions"
    trusted = versions / "1.16.0"
    trusted.mkdir(parents=True, mode=0o700)
    executable = trusted / "openhands"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"OpenHands standalone fixture")
    executable.chmod(0o700)
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection.Path, "home", lambda: home)
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(versions),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(executable),),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("OpenHands CLI 1.16.0", ""),
    )

    selected = agent_selection._select_agent_executable(str(tmp_path / "state"), "openhands")

    assert selected.executable == str(executable)
    assert selected.sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()

    probes: list[str] = []
    monkeypatch.setattr(agent_selection.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(
        agent_selection,
        "_run_macos_identity_command",
        lambda _args: (0, "arm64\n"),
    )
    monkeypatch.setattr(
        agent_selection,
        "darwin_acl_write_error",
        lambda _path: "extended ACL grants additional write access",
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: (probes.append("version") or "OpenHands CLI 1.16.0", ""),
    )
    with pytest.raises(OSError, match="cannot select openhands executable"):
        agent_selection._select_agent_executable(str(tmp_path / "state"), "openhands")
    assert probes == []

    monkeypatch.setattr(agent_selection, "darwin_acl_write_error", lambda _path: None)
    trusted.chmod(0o777)
    assert not agent_selection.is_setup_trusted_binary(
        str(executable),
        str(tmp_path / "state"),
        connector="openhands",
    )


@pytest.mark.skipif(os.name == "nt", reason="Darwin POSIX executable custody")
def test_darwin_openhands_selection_rejects_identity_change_during_hash(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o700)
    executable = trusted / "openhands"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection, "_setup_agent_candidates", lambda *_args: (str(executable),))
    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("OpenHands CLI 1.16.0", ""),
    )

    def replace_during_hash(path: str) -> str:
        Path(path).write_text("#!/bin/sh\necho replaced\n", encoding="utf-8")
        return "b" * 64

    monkeypatch.setattr(agent_selection, "stable_executable_sha256", replace_during_hash)

    with pytest.raises(OSError, match="changed while hashing"):
        agent_selection._select_agent_executable(str(tmp_path / "state"), "openhands")


def test_macos_openhands_native_admission_requires_arm64_and_safe_acl(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "openhands"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"OpenHands standalone fixture")
    monkeypatch.setattr(agent_selection.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(agent_selection, "darwin_acl_write_error", lambda _path: None)
    monkeypatch.setattr(
        agent_selection,
        "_run_macos_identity_command",
        lambda _args: (0, "arm64\n"),
    )

    assert agent_selection._validate_macos_openhands_binary(str(executable)) is None

    monkeypatch.setattr(
        agent_selection,
        "darwin_acl_write_error",
        lambda _path: "extended ACL grants additional write access",
    )
    assert "unsafe file ACL" in agent_selection._validate_macos_openhands_binary(str(executable))

    monkeypatch.setattr(agent_selection, "darwin_acl_write_error", lambda _path: None)
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "x86_64")
    assert "only on macOS arm64" in agent_selection._validate_macos_openhands_binary(str(executable))

    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(
        agent_selection,
        "_run_macos_identity_command",
        lambda _args: (0, "x86_64\n"),
    )
    assert "does not contain" in agent_selection._validate_macos_openhands_binary(str(executable))


@pytest.mark.skipif(os.name == "nt", reason="Darwin POSIX symlink and custody semantics")
def test_darwin_openhands_standalone_selection_uses_exact_target_not_path_symlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    versions = home / ".local" / "share" / "openhands" / "versions"
    executable = versions / "1.16.0" / "openhands"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"OpenHands standalone fixture")
    executable.chmod(0o700)
    path_link = home / ".local" / "bin" / "openhands"
    path_link.parent.mkdir(parents=True)
    path_link.symlink_to(executable)

    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection.Path, "home", lambda: home)
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(versions),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(path_link),),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("OpenHands CLI 1.16.0", ""),
    )

    candidates = agent_selection._setup_agent_candidates(
        "openhands",
        agent_selection.agent_discovery._SPECS["openhands"],
        str(tmp_path / "state"),
    )
    selected = agent_selection._select_agent_executable(str(tmp_path / "state"), "openhands")

    assert candidates[:2] == (str(executable), str(path_link))
    assert agent_selection._stable_selection_identity(str(path_link)) is None
    assert selected.executable == str(executable)


@pytest.mark.skipif(os.name == "nt", reason="Darwin POSIX executable custody")
def test_darwin_openhands_target_requires_canonical_or_operator_approved_macho(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    versions = home / ".local" / "share" / "openhands" / "versions"
    executable = versions / "1.16.0" / "openhands"
    sibling = versions / "lookalike" / "openhands"
    uv_script = home / ".local" / "share" / "uv" / "tools" / "openhands" / "bin" / "openhands"
    approved = tmp_path / "operator-approved"
    approved_macho = approved / "openhands"
    for candidate in (executable, sibling, approved_macho):
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"\xcf\xfa\xed\xfe" + b"native fixture")
        candidate.chmod(0o700)
    uv_script.parent.mkdir(parents=True)
    uv_script.write_text("#!/bin/sh\n", encoding="utf-8")
    uv_script.chmod(0o700)

    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection.Path, "home", lambda: home)
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(versions),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, (str(approved), str(uv_script.parent))),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))

    assert agent_selection.is_setup_trusted_binary(
        str(executable),
        str(tmp_path / "state"),
        connector="openhands",
    )
    assert agent_selection.is_setup_trusted_binary(
        str(approved_macho),
        str(tmp_path / "state"),
        connector="openhands",
    )
    for decoy in (sibling, uv_script):
        assert not agent_selection.is_setup_trusted_binary(
            str(decoy),
            str(tmp_path / "state"),
            connector="openhands",
        )

    versions.chmod(0o777)
    assert not agent_selection.is_setup_trusted_binary(
        str(executable),
        str(tmp_path / "state"),
        connector="openhands",
    )


@pytest.mark.parametrize(
    ("connector", "raw_version"),
    (
        ("codex", "codex-cli 0.144.3"),
        ("claudecode", "2.1.220 (Claude Code)"),
    ),
)
def test_darwin_protected_selection_passes_connector_to_trust_gate_without_version_ceiling(
    connector: str,
    raw_version: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / ("codex" if connector == "codex" else "2.1.220")
    executable.write_bytes(b"native fixture")
    executable.chmod(0o700)
    calls: list[str] = []
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection, "_setup_agent_candidates", lambda *_args: (str(executable),))

    def trusted(_path: str, _data_dir: str, *, connector: str = "") -> bool:
        calls.append(connector)
        return True

    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", trusted)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: (raw_version, ""),
    )

    selected = agent_selection._select_agent_executable(str(tmp_path / "state"), connector)

    assert selected.raw_version == raw_version
    assert calls == [connector]


def test_macos_native_identity_requires_arm64_pinned_signer_and_no_quarantine(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"signed native image")
    executable.chmod(0o500)
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")

    def identity_command(args: list[str]) -> tuple[int, str]:
        if args[0] == "/usr/bin/codesign" and "-d" in args:
            return (
                0,
                "Identifier=codex\n"
                "Authority=Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)\n"
                "TeamIdentifier=2DC432GLL2\n",
            )
        if args[0] == "/usr/bin/lipo":
            return 0, "arm64\n"
        if args[0] == "/usr/bin/xattr":
            return 1, ""
        return 0, ""

    monkeypatch.setattr(agent_selection, "_run_macos_identity_command", identity_command)
    assert agent_selection._macos_codex_binary_is_trusted(str(executable))

    monkeypatch.setattr(
        agent_selection,
        "_run_macos_identity_command",
        lambda args: (
            (0, "Identifier=codex\nTeamIdentifier=ATTACKER\n")
            if args[0] == "/usr/bin/codesign" and "-d" in args
            else identity_command(args)
        ),
    )
    assert not agent_selection._macos_codex_binary_is_trusted(str(executable))


def test_macos_claudecode_identity_rejects_quarantine(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "2.1.220"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"signed Claude Code")
    executable.chmod(0o500)
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")

    def identity_command(args: list[str]) -> tuple[int, str]:
        if args[0] == "/usr/bin/codesign" and "-d" in args:
            return (
                0,
                "Identifier=com.anthropic.claude-code\n"
                "Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n"
                "TeamIdentifier=Q6L2SF6YDW\n",
            )
        if args[0] == "/usr/bin/lipo":
            return 0, "arm64\n"
        if args[0] == "/usr/bin/xattr":
            return 0, "0081;quarantined"
        return 0, ""

    monkeypatch.setattr(agent_selection, "_run_macos_identity_command", identity_command)
    assert "still quarantined" in (agent_selection._validate_macos_claudecode_binary(str(executable)) or "")

    monkeypatch.setattr(
        agent_selection,
        "_run_macos_identity_command",
        lambda args: (0, "") if args[0] == "/usr/bin/xattr" else identity_command(args),
    )
    assert "still quarantined" in (agent_selection._validate_macos_claudecode_binary(str(executable)) or "")


@pytest.mark.skipif(os.name == "nt", reason="Darwin POSIX executable custody")
def test_macos_claudecode_trust_requires_canonical_versions_target_and_safe_chain(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    versions = home / ".local" / "share" / "claude" / "versions"
    versions.mkdir(parents=True, mode=0o700)
    executable = versions / "2.1.220"
    executable.write_bytes(b"native Claude")
    executable.chmod(0o700)
    decoy_root = tmp_path / "trusted-decoy"
    decoy_root.mkdir(mode=0o700)
    decoy = decoy_root / "2.1.220"
    decoy.write_bytes(b"native decoy")
    decoy.chmod(0o700)
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection.Path, "home", lambda: home)
    monkeypatch.setattr(
        agent_selection,
        "_builtin_setup_trusted_prefixes",
        lambda: (str(versions), str(decoy_root)),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(agent_selection, "_validate_macos_claudecode_binary", lambda _path: None)

    assert agent_selection.is_setup_trusted_binary(
        str(executable),
        str(tmp_path / "state"),
        connector="claudecode",
    )
    assert not agent_selection.is_setup_trusted_binary(
        str(decoy),
        str(tmp_path / "state"),
        connector="claudecode",
    )
    versions.chmod(0o777)
    assert not agent_selection.is_setup_trusted_binary(
        str(executable),
        str(tmp_path / "state"),
        connector="claudecode",
    )


def test_macos_protected_candidates_include_exact_off_path_native_images(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    versions = home / ".local" / "share" / "claude" / "versions"
    versions.mkdir(parents=True)
    older = versions / "2.1.160"
    current = versions / "2.1.220"
    older.write_bytes(b"older")
    current.write_bytes(b"current")

    openhands_versions = home / ".local" / "share" / "openhands" / "versions"
    openhands_older = openhands_versions / "1.15.0" / "openhands"
    openhands_current = openhands_versions / "1.16.0" / "openhands"
    for candidate in (openhands_older, openhands_current):
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"\xcf\xfa\xed\xfe" + b"OpenHands standalone")

    npm_root = tmp_path / "npm"
    npm_codex = (
        npm_root
        / "node_modules"
        / "@openai"
        / "codex-darwin-arm64"
        / "vendor"
        / "aarch64-apple-darwin"
        / "bin"
        / "codex"
    )
    npm_codex.parent.mkdir(parents=True)
    npm_codex.write_bytes(b"npm native")
    standalone = (
        home / ".codex" / "packages" / "standalone" / "releases" / "0.144.3-aarch64-apple-darwin" / "bin" / "codex"
    )
    standalone.parent.mkdir(parents=True)
    standalone.write_bytes(b"standalone native")

    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(agent_selection.Path, "home", lambda: home)
    monkeypatch.setattr(
        agent_selection,
        "_builtin_setup_trusted_prefixes",
        lambda: (
            str(npm_root),
            str(versions),
            str(openhands_versions),
            str(home / ".codex" / "packages" / "standalone"),
        ),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (),
    )

    claude_candidates = agent_selection._setup_agent_candidates(
        "claudecode",
        agent_selection.agent_discovery._SPECS["claudecode"],
        str(tmp_path / "state"),
    )
    codex_candidates = agent_selection._setup_agent_candidates(
        "codex",
        agent_selection.agent_discovery._SPECS["codex"],
        str(tmp_path / "state"),
    )
    openhands_candidates = agent_selection._setup_agent_candidates(
        "openhands",
        agent_selection.agent_discovery._SPECS["openhands"],
        str(tmp_path / "state"),
    )

    assert claude_candidates[:2] == (str(current), str(older))
    assert openhands_candidates[:2] == (str(openhands_current), str(openhands_older))
    assert str(npm_codex) in codex_candidates
    assert str(standalone.resolve()) in codex_candidates


def test_macos_codex_native_candidates_accept_node_modules_as_trusted_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    node_modules = tmp_path / "homebrew" / "lib" / "node_modules"
    nested = (
        node_modules
        / "@openai"
        / "codex"
        / "node_modules"
        / "@openai"
        / "codex-darwin-arm64"
        / "vendor"
        / "aarch64-apple-darwin"
        / "bin"
        / "codex"
    )
    hoisted = (
        node_modules
        / "@openai"
        / "codex-darwin-arm64"
        / "vendor"
        / "aarch64-apple-darwin"
        / "bin"
        / "codex"
    )
    for executable in (nested, hoisted):
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"native codex")

    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")

    assert agent_selection._codex_macos_npm_native_candidates(str(node_modules)) == (
        str(nested),
        str(hoisted),
    )


def test_record_setup_agent_selection_writes_short_lived_protected_receipt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "trusted" / "codex.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"agent")
    selected = agent_selection.SetupAgentSelection(
        connector="codex",
        executable=str(executable),
        raw_version="codex-cli 0.144.3",
        normalized_version="0.144.3",
        sha256=hashlib.sha256(b"agent").hexdigest(),
    )
    monkeypatch.setattr(agent_selection, "_select_agent_executable", lambda *_args: selected)

    selections, errors = agent_selection.record_setup_agent_selections(tmp_path / "state", ["codex"])

    assert selections == {"codex": selected}
    assert errors == {}
    receipt = json.loads((tmp_path / "state" / agent_selection.SELECTION_FILENAME).read_text())
    assert receipt["schema_version"] == 1
    assert receipt["selections"]["codex"] == {
        "connector": "codex",
        "source": "setup-selected",
        "executable": str(executable),
        "raw_version": "codex-cli 0.144.3",
        "normalized_version": "0.144.3",
        "sha256": selected.sha256,
        "selected_at": receipt["selections"]["codex"]["selected_at"],
        "expires_at": receipt["selections"]["codex"]["expires_at"],
    }
    selected_at = datetime.fromisoformat(receipt["selections"]["codex"]["selected_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(receipt["selections"]["codex"]["expires_at"].replace("Z", "+00:00"))
    assert expires_at - selected_at == agent_selection.SELECTION_LIFETIME


def test_record_setup_agent_selection_accepts_omnigent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "trusted" / "omnigent.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"omnigent")
    selected = agent_selection.SetupAgentSelection(
        connector="omnigent",
        executable=str(executable),
        raw_version="omnigent 0.7.0",
        normalized_version="0.7.0",
        sha256=hashlib.sha256(b"omnigent").hexdigest(),
    )
    monkeypatch.setattr(agent_selection, "_select_agent_executable", lambda *_args: selected)

    selections, errors = agent_selection.record_setup_agent_selections(
        tmp_path / "state",
        ["omnigent"],
    )

    assert selections == {"omnigent": selected}
    assert errors == {}


def test_record_setup_agent_selection_accepts_opencode(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "trusted" / "opencode.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"official-opencode")
    selected = agent_selection.SetupAgentSelection(
        connector="opencode",
        executable=str(executable),
        raw_version="opencode 1.18.11",
        normalized_version="1.18.11",
        sha256=hashlib.sha256(b"official-opencode").hexdigest(),
    )
    monkeypatch.setattr(agent_selection, "_select_agent_executable", lambda *_args: selected)

    selections, errors = agent_selection.record_setup_agent_selections(
        tmp_path / "state",
        ["opencode"],
    )

    assert selections == {"opencode": selected}
    assert errors == {}


def test_record_setup_agent_selection_accepts_amp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "trusted" / "amp.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"official-amp-native")
    selected = agent_selection.SetupAgentSelection(
        connector="amp",
        executable=str(executable),
        raw_version="0.0.1785875347-gbc402f",
        normalized_version="0.0.1785875347",
        sha256=hashlib.sha256(b"official-amp-native").hexdigest(),
    )
    monkeypatch.setattr(agent_selection, "_select_agent_executable", lambda *_args: selected)

    selections, errors = agent_selection.record_setup_agent_selections(
        tmp_path / "state",
        ["amp"],
    )

    assert selections == {"amp": selected}
    assert errors == {}


@pytest.mark.skipif(os.name != "nt", reason="Windows native Amp selection authority")
def test_amp_setup_candidates_enumerate_only_native_amp_exe(tmp_path: Path, monkeypatch) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    native = trusted / "amp.exe"
    native.write_bytes(b"native Amp")
    rejected = tuple(trusted / name for name in ("amp.cmd", "amp.bat", "amp.com", "amp-helper.exe"))
    for path in rejected:
        path.write_bytes(b"not native Amp authority")
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(trusted),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: tuple(str(path) for path in (*rejected, native)),
    )

    candidates = agent_selection._setup_agent_candidates(
        "amp",
        agent_selection.agent_discovery._SPECS["amp"],
        str(tmp_path / "state"),
    )

    assert candidates == (str(native),)


@pytest.mark.skipif(os.name != "nt", reason="Windows native Amp selection authority")
@pytest.mark.parametrize("authority", ["env-only", "unsafe-acl", "reparse"])
def test_amp_selection_rejects_unsafe_prefix_authority(
    authority: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / authority
    root.mkdir()
    executable = root / "amp.exe"
    executable.write_bytes(b"untrusted Amp")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(executable),),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(
        agent_selection,
        "_builtin_setup_trusted_prefixes",
        (lambda: ()) if authority == "env-only" else (lambda: (str(root),)),
    )
    monkeypatch.setattr(
        agent_selection,
        "is_link_or_reparse",
        lambda path: authority == "reparse" and os.path.normcase(path) == os.path.normcase(str(executable)),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_windows_acl_chain_is_safe",
        lambda *_args: authority != "unsafe-acl",
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("0.0.1785875347-gbc402f", ""),
    )

    with pytest.raises(OSError, match="cannot select amp executable"):
        agent_selection._select_agent_executable(str(tmp_path / "state"), "amp")


@pytest.mark.parametrize("reported", ["not-an-amp-version", "amp 0.0.1"])
def test_amp_selection_rejects_fake_or_unsupported_version(
    reported: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "amp.exe"
    executable.write_bytes(b"Amp fixture")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(executable),),
    )
    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: (reported, ""),
    )

    with pytest.raises(OSError, match="cannot select amp executable"):
        agent_selection._select_agent_executable(str(tmp_path / "state"), "amp")


def test_windows_opencode_winget_root_accepts_exact_observed_package_id(monkeypatch) -> None:
    local = r"D:\fixture\AppData\Local"
    exact = os.path.abspath(
        os.path.join(
            local,
            "Microsoft",
            "WinGet",
            "Packages",
            "SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe",
        )
    )
    monkeypatch.setattr(agent_selection.os.path, "isdir", lambda path: path == exact)
    monkeypatch.setattr(agent_selection, "is_link_or_reparse", lambda _path: False)

    assert agent_selection._windows_opencode_winget_package_prefixes(local) == (exact,)


def test_windows_opencode_winget_root_rejects_lookalikes_and_reparse(monkeypatch) -> None:
    local = r"D:\fixture\AppData\Local"
    exact = os.path.abspath(
        os.path.join(
            local,
            "Microsoft",
            "WinGet",
            "Packages",
            "SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe",
        )
    )
    lookalikes = (
        exact + ".evil",
        exact.replace("SST.opencode_", "evil.SST.opencode_"),
        exact.replace("SST.opencode_", "AnomalyInnovations.opencode_"),
    )
    monkeypatch.setattr(
        agent_selection.os.path,
        "isdir",
        lambda path: path == exact or path in lookalikes,
    )
    monkeypatch.setattr(agent_selection, "is_link_or_reparse", lambda path: path == exact)

    assert agent_selection._windows_opencode_winget_package_prefixes(local) == ()


@pytest.mark.skipif(os.name != "nt", reason="Windows protected OpenCode selection authority")
def test_windows_opencode_setup_candidates_ignore_path_configured_and_winget_links(
    tmp_path: Path,
    monkeypatch,
) -> None:
    local = tmp_path / "token-local"
    exact = (
        local
        / "Microsoft"
        / "WinGet"
        / "Packages"
        / "SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe"
        / "opencode.exe"
    )
    exact.parent.mkdir(parents=True)
    exact.write_bytes(b"official SST OpenCode")
    for decoy in (
        tmp_path / "path" / "opencode.exe",
        tmp_path / "configured" / "opencode.exe",
        local / "Microsoft" / "WinGet" / "Links" / "opencode.exe",
    ):
        decoy.parent.mkdir(parents=True)
        decoy.write_bytes(b"lookalike")

    monkeypatch.setattr(agent_selection, "_windows_known_folder", lambda _identifier: str(local))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (_ for _ in ()).throw(AssertionError("PATH discovery must not authorize OpenCode setup")),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda *_args: (_ for _ in ()).throw(AssertionError("configured roots must not authorize OpenCode setup")),
    )
    monkeypatch.setattr(
        agent_selection,
        "_builtin_setup_trusted_prefixes",
        lambda: (_ for _ in ()).throw(AssertionError("generic roots must not authorize OpenCode setup")),
    )

    candidates = agent_selection._setup_agent_candidates(
        "opencode",
        agent_selection.agent_discovery._SPECS["opencode"],
        str(tmp_path / "state"),
    )

    assert candidates == (str(exact),)


@pytest.mark.skipif(os.name != "nt", reason="Windows protected OpenCode selection authority")
@pytest.mark.parametrize("authority", ["lookalike", "reparse-chain", "unsafe-acl"])
def test_windows_opencode_exact_image_rejects_lookalike_reparse_and_unsafe_acl(
    authority: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    local = tmp_path / "token-local"
    exact = (
        local
        / "Microsoft"
        / "WinGet"
        / "Packages"
        / "SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe"
        / "opencode.exe"
    )
    exact.parent.mkdir(parents=True)
    exact.write_bytes(b"official SST OpenCode")
    candidate = exact
    if authority == "lookalike":
        candidate = exact.parent.with_name(exact.parent.name + ".evil") / "opencode.exe"
        candidate.parent.mkdir()
        candidate.write_bytes(b"lookalike")

    monkeypatch.setattr(agent_selection, "_windows_known_folder", lambda _identifier: str(local))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_windows_path_chain_has_no_reparse_points",
        lambda *_args: authority != "reparse-chain",
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_windows_acl_chain_is_safe",
        lambda *_args: authority != "unsafe-acl",
    )

    assert not agent_selection._is_windows_opencode_setup_binary(str(candidate))


@pytest.mark.skipif(os.name != "nt", reason="Windows protected OpenCode selection authority")
@pytest.mark.parametrize(
    ("reported", "accepted"),
    [
        ("opencode 1.18.10", True),
        ("opencode 1.18.11", True),
        ("opencode 1.18.19", True),
        ("opencode 1.18.9", False),
        ("opencode 1.18.20", False),
    ],
)
def test_windows_opencode_selection_enforces_exact_validated_version_range(
    reported: str,
    accepted: bool,
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "opencode.exe"
    body = b"official SST OpenCode"
    executable.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    monkeypatch.setattr(agent_selection, "_setup_agent_candidates", lambda *_args: (str(executable),))
    monkeypatch.setattr(agent_selection, "_is_windows_opencode_setup_binary", lambda _path: True)
    monkeypatch.setattr(
        agent_selection,
        "_stable_windows_executable_version_and_sha256",
        lambda *_args: (reported, "", digest),
    )
    monkeypatch.setattr(
        agent_selection,
        "stable_executable_sha256",
        lambda *_args: (_ for _ in ()).throw(AssertionError("OpenCode must reuse its locked digest")),
    )

    if not accepted:
        with pytest.raises(OSError, match="outside the validated hook contract"):
            agent_selection._select_agent_executable(str(tmp_path / "state"), "opencode")
        return

    selected = agent_selection._select_agent_executable(str(tmp_path / "state"), "opencode")
    assert selected.raw_version == reported
    assert selected.normalized_version == reported.rsplit(" ", 1)[1]
    assert selected.sha256 == digest


@pytest.mark.skipif(os.name != "nt", reason="Windows protected OpenCode selection authority")
@pytest.mark.parametrize(("changed_call", "message"), [(2, "probing its version"), (3, "hashing")])
def test_windows_opencode_locked_probe_refuses_version_and_hash_identity_races(
    changed_call: int,
    message: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "opencode.exe"
    executable.write_bytes(b"official SST OpenCode")
    open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    monkeypatch.setattr(
        agent_selection.windows_acl,
        "open_regular_execution_fd",
        lambda path: os.open(path, open_flags),
    )
    monkeypatch.setattr(agent_selection, "is_link_or_reparse", lambda _path: False)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("opencode 1.18.11", ""),
    )
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        if calls != changed_call:
            return current
        return SimpleNamespace(
            st_mode=current.st_mode,
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_size=current.st_size + 1,
            st_mtime_ns=current.st_mtime_ns,
        )

    monkeypatch.setattr(agent_selection.os, "fstat", changing_fstat)

    with pytest.raises(OSError, match=message):
        agent_selection._stable_windows_executable_version_and_sha256(
            "opencode",
            str(executable),
            ("--version",),
            str(tmp_path / "state"),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows protected OpenCode selection authority")
def test_missing_exact_windows_opencode_image_preserves_receipt_and_skips_discovery_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    receipt = state / agent_selection.SELECTION_FILENAME
    prior = b'{"prior":"protected receipt"}\r\n'
    receipt.write_bytes(prior)
    monkeypatch.setattr(agent_selection, "_windows_known_folder", lambda _identifier: str(tmp_path / "missing"))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (_ for _ in ()).throw(AssertionError("generic discovery must not run")),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "discover_agents",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("shared discovery cache must not run")),
    )
    monkeypatch.setattr(
        agent_selection,
        "atomic_write_private_bytes",
        lambda *_args: (_ for _ in ()).throw(AssertionError("failed selection must not write a receipt")),
    )

    selections, errors = agent_selection.record_setup_agent_selections(state, ["opencode"])

    assert selections == {}
    assert "opencode" in errors
    assert receipt.read_bytes() == prior


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable fixture; Windows aliases are enumerated separately")
@pytest.mark.parametrize("alias", ["omnigent.exe", "omni.exe"])
def test_omnigent_official_alias_selection_records_real_version_and_digest(
    tmp_path: Path,
    monkeypatch,
    alias: str,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    executable = trusted / alias
    executable.write_text("#!/bin/sh\nprintf 'omnigent 0.7.0\\n'\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(trusted),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (),
    )

    selected = agent_selection._select_agent_executable(str(tmp_path / "state"), "omnigent")

    assert selected.executable == str(executable.resolve())
    assert selected.raw_version == "omnigent 0.7.0"
    assert selected.normalized_version == "0.7.0"
    assert selected.sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()


def test_omnigent_candidate_aliases_do_not_raise_or_accept_unlisted_names(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    expected = {str(trusted / "omnigent.exe"), str(trusted / "omni.exe")}
    for candidate in expected:
        Path(candidate).write_bytes(b"MZ")
    (trusted / "omnigent.cmd").write_text("@echo off\r\n", encoding="utf-8")
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(trusted),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (),
    )

    candidates = agent_selection._setup_agent_candidates(
        "omnigent",
        agent_selection.agent_discovery._SPECS["omnigent"],
        str(tmp_path / "state"),
    )

    assert set(candidates) == expected


@pytest.mark.skipif(os.name != "nt", reason="Windows updater-managed Hermes authority")
def test_hermes_setup_candidates_only_use_managed_venv_on_first_and_repeat(
    tmp_path: Path,
    monkeypatch,
) -> None:
    managed = tmp_path / "token-local" / "hermes" / "hermes-agent" / "venv" / "Scripts"
    executable = managed / "hermes.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"managed Hermes")
    decoy = tmp_path / "path" / "hermes.exe"
    decoy.parent.mkdir()
    decoy.write_bytes(b"PATH decoy")
    monkeypatch.setattr(agent_selection, "_windows_managed_hermes_prefixes", lambda: (str(managed),))
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(decoy), str(executable)),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, (str(decoy.parent),)),
    )

    first = agent_selection._setup_agent_candidates(
        "hermes",
        agent_selection.agent_discovery._SPECS["hermes"],
        str(tmp_path / "state"),
    )
    repeated = agent_selection._setup_agent_candidates(
        "hermes",
        agent_selection.agent_discovery._SPECS["hermes"],
        str(tmp_path / "state"),
    )

    assert first == (str(executable),)
    assert repeated == first


def test_explicit_selection_probes_candidates_instead_of_discovery_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "codex.exe"
    executable.write_bytes(b"trusted-codex")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(executable),),
    )
    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args, **_kwargs: True)
    probe_options: dict[str, object] = {}

    def probe_version(*_args, **kwargs):
        probe_options.update(kwargs)
        return "codex-cli 0.144.3", ""

    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        probe_version,
    )
    monkeypatch.setattr(
        agent_selection,
        "stable_executable_sha256",
        lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "discover_agents",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("cache/discovery must not authorize setup")),
    )

    selection = agent_selection._select_agent_executable(str(tmp_path), "codex")

    assert selection.executable == str(executable.resolve())
    assert selection.normalized_version == "0.144.3"
    assert selection.sha256 == hashlib.sha256(b"trusted-codex").hexdigest()
    assert probe_options["require_trusted_binary_paths"] is False


def test_setup_trust_rejects_path_admitted_only_by_environment_extension(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "env-only" / "codex.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"agent")
    monkeypatch.setattr(agent_selection, "is_link_or_reparse", lambda _path: False)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: ())
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(agent_selection.agent_discovery, "_is_trusted_binary_path", lambda *_args, **_kwargs: True)

    assert not agent_selection.is_setup_trusted_binary(str(executable), str(tmp_path / "state"))


@pytest.mark.skipif(os.name != "nt", reason="Windows native-image authority")
@pytest.mark.parametrize("suffix", [".cmd", ".bat", ".com"])
def test_setup_trust_rejects_non_native_windows_launchers(
    suffix: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    trusted = tmp_path / "trusted"
    executable = trusted / f"codex{suffix}"
    trusted.mkdir()
    executable.write_bytes(b"wrapper")
    monkeypatch.setattr(agent_selection, "is_link_or_reparse", lambda _path: False)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(trusted),))
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(agent_selection.agent_discovery, "_windows_acl_chain_is_safe", lambda *_args: True)

    assert not agent_selection.is_setup_trusted_binary(str(executable), str(tmp_path / "state"))


def test_selection_errors_preserve_last_valid_receipt_byte_for_byte(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "state"
    state.mkdir()
    receipt_path = state / agent_selection.SELECTION_FILENAME
    prior = b'{"prior":"exact-last-valid-receipt"}\r\n'
    receipt_path.write_bytes(prior)
    monkeypatch.setattr(
        agent_selection,
        "_select_agent_executable",
        lambda _data_dir, connector: (_ for _ in ()).throw(OSError(f"{connector} unavailable")),
    )

    selections, errors = agent_selection.record_setup_agent_selections(state, ["hermes"])

    assert selections == {}
    assert errors == {"hermes": "hermes unavailable"}
    assert receipt_path.read_bytes() == prior


@pytest.mark.skipif(os.name != "nt", reason="Windows known-folder API contract")
def test_builtin_setup_roots_ignore_poisoned_profile_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    trusted_local = tmp_path / "known-local"
    poisoned_local = tmp_path / "project-controlled"
    monkeypatch.setenv("LOCALAPPDATA", str(poisoned_local))
    known = {
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": str(trusted_local),
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": "",
        "5E6C858F-0E22-4760-9AFE-EA3317B67173": "",
        "6D809377-6AF0-444B-8957-A3773F02200E": "",
        "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": "",
    }
    monkeypatch.setattr(agent_selection, "_windows_known_folder", lambda identifier: known[identifier])
    monkeypatch.setattr(agent_selection, "_windows_system_directory", lambda: "")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_windows_configured_package_manager_bin_prefixes",
        lambda: (),
    )

    roots = agent_selection._builtin_setup_trusted_prefixes()

    assert any(str(trusted_local) in root for root in roots)
    assert all(str(poisoned_local) not in root for root in roots)


@pytest.mark.skipif(os.name != "nt", reason="Windows configured package-manager roots")
def test_builtin_setup_roots_include_validated_configured_manager_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configured = tmp_path / "LocalAppData" / "Programs" / "DevTools" / "node"
    configured.mkdir(parents=True)
    monkeypatch.setattr(agent_selection, "_windows_known_folder", lambda _identifier: "")
    monkeypatch.setattr(agent_selection, "_windows_system_directory", lambda: "")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_windows_configured_package_manager_bin_prefixes",
        lambda: (str(configured),),
    )

    roots = agent_selection._builtin_setup_trusted_prefixes()

    assert os.path.normcase(str(configured)) in {os.path.normcase(root) for root in roots}


def test_darwin_setup_roots_admit_only_exact_home_npm_global_layout(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    poisoned_prefix = tmp_path / "operator-controlled-prefix"
    monkeypatch.setenv("npm_config_prefix", str(poisoned_prefix))
    monkeypatch.setenv("NPM_CONFIG_PREFIX", str(poisoned_prefix))

    roots = set(agent_selection._darwin_setup_trusted_prefixes(home))
    exact = home / ".npm-global" / "lib" / "node_modules"

    assert os.fspath(exact) in roots
    assert os.fspath(home / ".npm-global-lookalike" / "lib" / "node_modules") not in roots
    assert os.fspath(home / ".npm-global" / "lib" / "node_modules-lookalike") not in roots
    assert os.fspath(poisoned_prefix / "lib" / "node_modules") not in roots


@pytest.mark.skipif(os.name == "nt", reason="Darwin POSIX executable custody")
def test_darwin_codex_selector_rejects_npm_root_lookalikes_and_env_prefix(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    exact_root = home / ".npm-global" / "lib" / "node_modules"
    lookalike_root = home / ".npm-global-lookalike" / "lib" / "node_modules"
    poisoned_root = tmp_path / "operator-controlled-prefix" / "lib" / "node_modules"

    def native(root: Path) -> Path:
        candidate = (
            root
            / "@openai"
            / "codex"
            / "node_modules"
            / "@openai"
            / "codex-darwin-arm64"
            / "vendor"
            / "aarch64-apple-darwin"
            / "bin"
            / "codex"
        )
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"signed fixture")
        candidate.chmod(0o700)
        return candidate

    exact = native(exact_root)
    lookalike = native(lookalike_root)
    poisoned = native(poisoned_root)
    monkeypatch.setenv("npm_config_prefix", str(poisoned_root.parents[1]))
    monkeypatch.setenv("NPM_CONFIG_PREFIX", str(poisoned_root.parents[1]))
    monkeypatch.setattr(agent_selection, "_HOST_PLATFORM", "darwin")
    monkeypatch.setattr(agent_selection.Path, "home", lambda: home)
    monkeypatch.setattr(agent_selection.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(agent_selection.agent_discovery, "_builtin_trusted_bin_prefixes", lambda: ())
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: tuple(roots))
    monkeypatch.setattr(agent_selection, "_macos_codex_binary_is_trusted", lambda _path: True)

    assert agent_selection.is_setup_trusted_binary(str(exact), str(tmp_path / "state"), connector="codex")
    assert not agent_selection.is_setup_trusted_binary(
        str(lookalike), str(tmp_path / "state"), connector="codex"
    )
    assert not agent_selection.is_setup_trusted_binary(
        str(poisoned), str(tmp_path / "state"), connector="codex"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows token-bound Known Folder contract")
def test_windows_known_folders_ignore_inherited_profile_environment(tmp_path: Path) -> None:
    identifiers = (
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091",  # LocalAppData
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D",  # RoamingAppData
        "5E6C858F-0E22-4760-9AFE-EA3317B67173",  # Profile
    )
    expected = [agent_selection._windows_known_folder(identifier) for identifier in identifiers]
    assert all(expected)

    foreign_profile = tmp_path / "foreign-profile"
    foreign_local = foreign_profile / "AppData" / "Local"
    foreign_roaming = foreign_profile / "AppData" / "Roaming"
    foreign_local.mkdir(parents=True)
    foreign_roaming.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(
        {
            "USERPROFILE": str(foreign_profile),
            "HOME": str(foreign_profile),
            "LOCALAPPDATA": str(foreign_local),
            "APPDATA": str(foreign_roaming),
        }
    )
    cli_root = str(Path(__file__).resolve().parents[1])
    environment["PYTHONPATH"] = os.pathsep.join(
        entry for entry in (cli_root, environment.get("PYTHONPATH", "")) if entry
    )
    code = (
        "import json; from defenseclaw import agent_selection; "
        f"print(json.dumps([agent_selection._windows_known_folder(value) for value in {identifiers!r}]))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    actual = json.loads(completed.stdout)

    assert [os.path.normcase(os.path.abspath(value)) for value in actual] == [
        os.path.normcase(os.path.abspath(value)) for value in expected
    ]


def test_setup_candidates_include_official_nested_npm_native_codex(
    tmp_path: Path,
    monkeypatch,
) -> None:
    npm_root = tmp_path / "npm"
    native = (
        npm_root
        / "node_modules"
        / "@openai"
        / "codex"
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native-codex")
    wrapper = npm_root / "codex.cmd"
    wrapper.write_text("@echo wrapper", encoding="utf-8")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(wrapper),),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(npm_root),))
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: list(roots))

    candidates = agent_selection._setup_agent_candidates(
        "codex",
        agent_selection.agent_discovery._SPECS["codex"],
        str(tmp_path / "state"),
    )

    assert candidates[0] == str(native)
    assert str(wrapper) in candidates


def test_setup_candidates_prefer_native_image_for_path_npm_wrapper_over_desktop(
    tmp_path: Path,
    monkeypatch,
) -> None:
    npm_root = tmp_path / "npm"
    native = (
        npm_root
        / "node_modules"
        / "@openai"
        / "codex"
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    native.parent.mkdir(parents=True)
    native.write_bytes(b"active-npm-codex")
    wrapper = npm_root / "codex.cmd"
    wrapper.write_text("@echo wrapper", encoding="utf-8")

    desktop = tmp_path / "OpenAI" / "Codex" / "bin" / "stale" / "codex.exe"
    desktop.parent.mkdir(parents=True)
    desktop.write_bytes(b"stale-desktop-codex")
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(wrapper), str(desktop)),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(
        agent_selection,
        "_builtin_setup_trusted_prefixes",
        lambda: (str(npm_root), str(desktop.parents[1])),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: list(roots))

    candidates = agent_selection._setup_agent_candidates(
        "codex",
        agent_selection.agent_discovery._SPECS["codex"],
        str(tmp_path / "state"),
    )

    assert candidates[0] == str(native)
    assert candidates.index(str(native)) < candidates.index(str(desktop))


def test_configured_devtools_npm_root_selects_upgraded_native_codex_despite_old_lock(
    tmp_path: Path,
    monkeypatch,
) -> None:
    npm_root = tmp_path / "LocalAppData" / "Programs" / "DevTools" / "node"
    package = npm_root / "node_modules" / "@openai" / "codex"
    entrypoint = package / "bin" / "codex.js"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("// current Codex", encoding="utf-8")
    native = (
        package
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    native.parent.mkdir(parents=True)
    native.write_bytes(b"current-native-codex")
    wrapper = npm_root / "codex.cmd"
    wrapper.write_text(
        '@node "%~dp0\\node_modules\\@openai\\codex\\bin\\codex.js" %*\n',
        encoding="utf-8",
    )
    data_dir = tmp_path / "state"
    data_dir.mkdir()
    (data_dir / "hook_contract_lock.json").write_text(
        json.dumps(
            {
                "version": 2,
                "connectors": {
                    "codex": {
                        "raw_agent_version": "codex-cli 0.144.0-alpha.4",
                        "normalized_agent_version": "0.144.0-alpha.4",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(wrapper),),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(npm_root),))
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: list(roots))
    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("codex-cli 0.144.3", ""),
    )

    selected = agent_selection._select_agent_executable(str(data_dir), "codex")

    assert selected.executable == str(native.resolve())
    assert selected.raw_version == "codex-cli 0.144.3"
    assert selected.normalized_version == "0.144.3"


def test_setup_candidates_follow_active_pnpm_package_not_stale_store_entry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pnpm_root = tmp_path / "pnpm"
    active_package = pnpm_root / "global" / "v11" / "active-hash" / "node_modules" / "@openai" / "codex"
    active_js = active_package / "bin" / "codex.js"
    active_js.parent.mkdir(parents=True)
    active_js.write_text("// active Codex", encoding="utf-8")
    native = (
        active_package.parents[1]
        / ".pnpm"
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    native.parent.mkdir(parents=True)
    native.write_bytes(b"active-pnpm-codex")
    stale = (
        pnpm_root
        / "global"
        / "v10"
        / "stale-hash"
        / "node_modules"
        / "@openai"
        / "codex"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale-pnpm-codex")
    stale_direct = (
        pnpm_root
        / "node_modules"
        / "@openai"
        / "codex"
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    stale_direct.parent.mkdir(parents=True)
    stale_direct.write_bytes(b"stale-direct-codex")
    wrapper = pnpm_root / "bin" / "codex.cmd"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(
        '@node "%~dp0\\..\\global\\v11\\active-hash\\node_modules\\@openai\\codex\\bin\\codex.js" %*\n',
        encoding="utf-8",
    )
    desktop = tmp_path / "OpenAI" / "Codex" / "bin" / "stale" / "codex.exe"
    desktop.parent.mkdir(parents=True)
    desktop.write_bytes(b"stale-desktop-codex")

    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_binary_candidates_for_agent",
        lambda *_args: (str(wrapper), str(desktop)),
    )
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(
        agent_selection,
        "_builtin_setup_trusted_prefixes",
        lambda: (str(pnpm_root), str(desktop.parents[1])),
    )
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: list(roots))

    candidates = agent_selection._setup_agent_candidates(
        "codex",
        agent_selection.agent_discovery._SPECS["codex"],
        str(tmp_path / "state"),
    )

    assert candidates[0] == str(native)
    assert str(stale) not in candidates
    assert str(stale_direct) not in candidates
    assert candidates.index(str(native)) < candidates.index(str(desktop))


def test_codex_wrapper_missing_js_target_rejects_leftover_native(tmp_path: Path) -> None:
    root = tmp_path / "pnpm"
    wrapper = root / "codex.cmd"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text(
        '@node "%~dp0\\global\\v11\\removed\\node_modules\\@openai\\codex\\bin\\codex.js" %*\n',
        encoding="utf-8",
    )
    leftover = (
        root
        / "global"
        / "v11"
        / "removed"
        / "node_modules"
        / ".pnpm"
        / "node_modules"
        / "@openai"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    leftover.parent.mkdir(parents=True)
    leftover.write_bytes(b"leftover-native")

    recognized, candidates = agent_selection._codex_wrapper_native_candidates(
        str(root),
        str(wrapper),
        agent_selection._CODEX_WINDOWS_PLATFORM_VARIANTS,
    )

    assert recognized
    assert candidates == ()


def test_setup_candidates_do_not_recursively_accept_lookalike_npm_codex(
    tmp_path: Path,
    monkeypatch,
) -> None:
    npm_root = tmp_path / "npm"
    lookalike = (
        npm_root
        / "node_modules"
        / "unrelated"
        / "codex-win32-x64"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "bin"
        / "codex.exe"
    )
    lookalike.parent.mkdir(parents=True)
    lookalike.write_bytes(b"lookalike")
    monkeypatch.setattr(agent_selection.agent_discovery, "_binary_candidates_for_agent", lambda *_args: ())
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_ai_discovery_trust_config",
        lambda _data_dir: (True, ()),
    )
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(npm_root),))
    monkeypatch.setattr(agent_selection.agent_discovery, "_expand_bin_prefixes", lambda roots: list(roots))

    candidates = agent_selection._setup_agent_candidates(
        "codex",
        agent_selection.agent_discovery._SPECS["codex"],
        str(tmp_path / "state"),
    )

    assert str(lookalike) not in candidates
