# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

import pytest
from defenseclaw import agent_selection


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
    monkeypatch.setattr(agent_selection, "is_setup_trusted_binary", lambda *_args: True)
    monkeypatch.setattr(
        agent_selection.agent_discovery,
        "_version_for_agent_binary",
        lambda *_args, **_kwargs: ("codex-cli 0.144.3", ""),
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


def test_selection_errors_are_persisted_as_no_executable_authority(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        agent_selection,
        "_select_agent_executable",
        lambda _data_dir, connector: (_ for _ in ()).throw(OSError(f"{connector} unavailable")),
    )

    selections, errors = agent_selection.record_setup_agent_selections(tmp_path / "state", ["codex"])

    assert selections == {}
    assert errors == {"codex": "codex unavailable"}
    receipt = json.loads((tmp_path / "state" / agent_selection.SELECTION_FILENAME).read_text())
    assert receipt["selections"] == {}


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

    roots = agent_selection._builtin_setup_trusted_prefixes()

    assert any(str(trusted_local) in root for root in roots)
    assert all(str(poisoned_local) not in root for root in roots)


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


def test_setup_candidates_follow_active_pnpm_package_not_stale_store_entry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pnpm_root = tmp_path / "pnpm"
    active_package = (
        pnpm_root
        / "global"
        / "v11"
        / "active-hash"
        / "node_modules"
        / "@openai"
        / "codex"
    )
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
