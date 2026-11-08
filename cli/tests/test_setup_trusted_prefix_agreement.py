# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""`setup trusted-paths` and agent selection answer from one predicate.

On a Windows account whose profile folder is relocated to a path with repeated
spaces, ``trusted-paths add <profile>\\.local\\bin`` printed "already trusted by
default" while ``init`` refused ``claude.exe`` in that folder as "not in a
built-in or operator-approved trusted prefix" (GAP-0866). The two answered from
different lists, and the refusal never said which check failed. Selection now
names the failed check, and ``trusted-paths`` takes "built-in" to mean the
prefixes setup itself admits. The tests use POSIX folders: the lists and the
reasons are platform-neutral.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import agent_selection
from defenseclaw.inventory import agent_discovery

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX folders stand in for the Windows profile layout")

PROFILE = "alpha  deep folder  with repeated  spaces 01"


def _folder(parent: Path, *names: str, mode: int = 0o755) -> Path:
    path = parent.joinpath(*names)
    path.mkdir(parents=True)
    path.chmod(mode)
    return path


def _agent(folder: Path) -> Path:
    agent = folder / "claude.exe"
    agent.write_bytes(b"synthetic agent")
    agent.chmod(0o755)
    return agent


def _add(runner: CliRunner, home: Path, directory: Path, setup_roots: tuple[str, ...], discovery_roots: tuple[str, ...]):
    from defenseclaw.main import cli

    environment = {
        "DEFENSECLAW_HOME": str(home),
        "DEFENSECLAW_CONFIG": str(home / "config.yaml"),
        "DEFENSECLAW_TRUSTED_BIN_PREFIXES": "",
    }
    with (
        patch.dict(os.environ, environment),
        patch.object(agent_selection, "_builtin_setup_trusted_prefixes", return_value=setup_roots),
        patch.object(agent_discovery, "_builtin_trusted_bin_prefixes", return_value=discovery_roots),
    ):
        result = runner.invoke(cli, ["setup", "trusted-paths", "add", str(directory), "--json"])
    return result, json.loads(result.output)


def test_add_admits_a_folder_only_the_discovery_list_calls_default() -> None:
    # The two lists name different profile roots (one from the account token,
    # one from the process environment): add must not say "already trusted" for
    # a folder setup would still refuse, and what it records must be admitted.
    runner = CliRunner()
    with runner.isolated_filesystem():
        cwd = Path.cwd()
        home = cwd / ".defenseclaw"
        token_bin = _folder(cwd, "token-profile", ".local", "bin")
        profile_bin = _folder(cwd, PROFILE, "r109ywd6", ".local", "bin")
        agent = _agent(profile_bin)

        before = agent_selection.setup_binary_trust_problem(str(agent), str(home))
        assert before == agent_selection.NOT_IN_TRUSTED_PREFIX

        result, payload = _add(runner, home, profile_bin, (str(token_bin),), (str(profile_bin),))

        assert result.exit_code == 0, result.output
        assert payload["ok"] is True
        assert "already trusted" not in payload["message"]
        assert agent_selection.setup_binary_trust_problem(str(agent), str(home)) == ""
        assert agent_selection.is_setup_trusted_binary(str(agent), str(home))


def test_add_keeps_saying_already_trusted_for_a_prefix_setup_admits() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        cwd = Path.cwd()
        profile_bin = _folder(cwd, PROFILE, "r109ywd6", ".local", "bin")

        result, payload = _add(runner, cwd / ".defenseclaw", profile_bin, (str(profile_bin),), (str(profile_bin),))

        assert result.exit_code == 0, result.output
        assert payload["ok"] is True
        assert "already trusted by default" in payload["message"]


def test_add_does_not_call_a_builtin_prefix_trusted_when_setup_refuses_its_permissions() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        cwd = Path.cwd()
        unsafe = _folder(cwd, PROFILE, "r109ywd6", ".local", "bin", mode=0o777)

        result, payload = _add(runner, cwd / ".defenseclaw", unsafe, (str(unsafe),), (str(unsafe),))

        assert result.exit_code == 1, result.output
        assert payload["ok"] is False
        assert "world-writable" in payload["message"]
        assert "already trusted" not in payload["message"]


def test_selection_names_the_failed_check_when_the_prefix_is_trusted_but_the_folder_is_not(
    tmp_path: Path, monkeypatch
) -> None:
    unsafe = _folder(tmp_path, PROFILE, "r109ywd6", ".local", "bin", mode=0o777)
    agent = _agent(unsafe)
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(unsafe),))
    monkeypatch.setattr(agent_selection.agent_discovery, "_binary_candidates_for_agent", lambda *_args: ())

    with pytest.raises(OSError) as raised:
        agent_selection._select_agent_executable(str(tmp_path / "state"), "claudecode")

    text = str(raised.value)
    assert os.path.realpath(agent) in text
    assert "world-writable" in text
    assert "trusted-paths add" not in text
    assert "not in a built-in or operator-approved trusted prefix" not in text


def test_selection_still_points_to_trusted_paths_for_a_folder_outside_every_prefix(
    tmp_path: Path, monkeypatch
) -> None:
    outside = _folder(tmp_path, PROFILE, "r109ywd6", ".local", "bin")
    agent = _agent(outside)
    elsewhere = _folder(tmp_path, "elsewhere")
    monkeypatch.setattr(agent_selection, "_builtin_setup_trusted_prefixes", lambda: (str(elsewhere),))
    monkeypatch.setattr(agent_selection.agent_discovery, "_binary_candidates_for_agent", lambda *_args: (str(agent),))

    with pytest.raises(OSError) as raised:
        agent_selection._select_agent_executable(str(tmp_path / "state"), "claudecode")

    text = str(raised.value)
    assert "is not in a built-in or operator-approved trusted prefix" in text
    assert f"defenseclaw setup trusted-paths add {os.path.realpath(outside)}" in text


def test_list_does_not_label_a_discovery_only_prefix_as_a_setup_default() -> None:
    from defenseclaw.main import cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        cwd = Path.cwd()
        setup_bin = _folder(cwd, "setup-root", "bin")
        discovery_bin = _folder(cwd, PROFILE, "discovery-root", "bin")
        home = cwd / ".defenseclaw"
        environment = {
            "DEFENSECLAW_HOME": str(home),
            "DEFENSECLAW_CONFIG": str(home / "config.yaml"),
            "DEFENSECLAW_TRUSTED_BIN_PREFIXES": "",
        }
        with (
            patch.dict(os.environ, environment),
            patch.object(agent_selection, "_builtin_setup_trusted_prefixes", return_value=(str(setup_bin),)),
            patch.object(
                agent_discovery,
                "_builtin_trusted_bin_prefixes",
                return_value=(str(setup_bin), str(discovery_bin)),
            ),
        ):
            result = runner.invoke(cli, ["setup", "trusted-paths", "list", "--json"])

        assert result.exit_code == 0, result.output
        sources = {row["resolved"]: row["source"] for row in json.loads(result.output)}
        assert sources[os.path.realpath(setup_bin)] == "default"
        assert sources[os.path.realpath(discovery_bin)] == "discovery default"


def test_acl_chain_error_names_the_folder_that_fails_and_agrees_with_the_boolean(tmp_path: Path) -> None:
    prefix = _folder(tmp_path, PROFILE, "r109ywd6", ".local", "bin")
    agent = _agent(prefix)
    unsafe_key = agent_discovery._path_key(str(prefix))

    def acl_error(path: str):
        return "ACL grants write access to untrusted principal S-1-5-21-1" if agent_discovery._path_key(path) == unsafe_key else None

    with patch.object(agent_discovery, "_windows_acl_write_error", side_effect=acl_error):
        reason = agent_discovery._windows_acl_chain_error(str(agent), str(prefix))
        safe = agent_discovery._windows_acl_chain_is_safe(str(agent), str(prefix))

    assert reason is not None and reason.startswith(f"{prefix}: ACL grants write access")
    assert safe is False
    with patch.object(agent_discovery, "_windows_acl_write_error", return_value=None):
        assert agent_discovery._windows_acl_chain_error(str(agent), str(prefix)) is None
        assert agent_discovery._windows_acl_chain_is_safe(str(agent), str(prefix)) is True
