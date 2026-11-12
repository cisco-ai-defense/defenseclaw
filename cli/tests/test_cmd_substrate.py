# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw substrate``: the generated Click stubs mirror the Go tree and exec it.

The Go command tree is pinned in internal/cli/testdata/substrate_commands.json
(TestSubstrateCommandManifest regenerates it) and cmd_substrate.py is generated
from it by scripts/gen_substrate_stubs.py. These tests hold the stubs to the
manifest in both directions and check that every stub hands its arguments to
``defenseclaw-gateway`` unchanged.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_substrate
from defenseclaw.commands.cmd_sandbox import GatewayCommand, GatewayOption
from defenseclaw.commands.cmd_substrate import substrate
from defenseclaw.context import AppContext

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "internal" / "cli" / "testdata" / "substrate_commands.json"
GENERATOR = REPO_ROOT / "scripts" / "gen_substrate_stubs.py"


def _manifest() -> dict[str, dict[str, Any]]:
    entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {entry["path"]: entry for entry in entries[1:]}


def _python_tree() -> dict[str, click.Command]:
    out: dict[str, click.Command] = {}

    def walk(node: click.Command, path: str) -> None:
        if not isinstance(node, click.Group):
            return
        for name, child in node.commands.items():
            child_path = f"{path} {name}"
            out[child_path] = child
            walk(child, child_path)

    walk(substrate, "substrate")
    return out


def _python_flags(command: click.Command) -> list[dict[str, str]]:
    flags = []
    for param in command.params:
        if not isinstance(param, click.Option):
            continue
        assert isinstance(param, GatewayOption), f"{command.name}: --{param.name} is not a GatewayOption"
        long_names = [opt[2:] for opt in param.opts if opt.startswith("--")]
        shorts = [opt[1:] for opt in param.opts if not opt.startswith("--")]
        entry = {"name": long_names[0], "type": param.go_type}
        if shorts:
            entry["shorthand"] = shorts[0]
        if param.go_default:
            entry["default"] = param.go_default
        flags.append(entry)
    return sorted(flags, key=lambda flag: flag["name"])


def _manifest_flags(entry: dict[str, Any]) -> list[dict[str, str]]:
    flags = []
    for flag in entry.get("flags") or []:
        item = {"name": flag["name"], "type": flag["type"]}
        if flag.get("shorthand"):
            item["shorthand"] = flag["shorthand"]
        if flag.get("default"):
            item["default"] = flag["default"]
        flags.append(item)
    return sorted(flags, key=lambda flag: flag["name"])


def test_manifest_exists_and_is_nonempty() -> None:
    assert MANIFEST.is_file(), (
        "regenerate it: DEFENSECLAW_UPDATE_GOLDEN=1 go test ./internal/cli -run TestSubstrateCommandManifest"
    )
    assert len(_manifest()) > 25


def test_the_generated_module_is_current() -> None:
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_every_go_command_has_a_python_stub() -> None:
    missing = sorted(set(_manifest()) - set(_python_tree()))
    assert not missing, f"Go substrate commands without a Python stub: {missing}"


def test_every_python_stub_exists_in_go() -> None:
    extra = sorted(set(_python_tree()) - set(_manifest()))
    assert not extra, f"Python substrate stubs the Go tree does not have: {extra}"


@pytest.mark.parametrize("path", sorted(_manifest()))
def test_stub_flags_match_the_go_flags(path: str) -> None:
    entry = _manifest()[path]
    if entry.get("passthrough"):
        assert _python_flags(_python_tree()[path]) == [], path
        return
    assert _python_flags(_python_tree()[path]) == _manifest_flags(entry), path


@pytest.mark.parametrize("path", sorted(_manifest()))
def test_groups_and_leaves_match(path: str) -> None:
    manifest = _manifest()
    has_children = any(other.startswith(path + " ") for other in manifest)
    command = _python_tree()[path]
    if has_children:
        assert isinstance(command, click.Group), path
    else:
        assert isinstance(command, GatewayCommand), path
        assert ("substrate", *command.gateway_path) == tuple(path.split()), path


def test_short_help_is_the_go_short_description() -> None:
    python = _python_tree()
    for path, entry in _manifest().items():
        assert python[path].short_help == entry["short"], path


def test_long_help_and_examples_are_the_go_ones() -> None:
    def words(text: str) -> str:
        return " ".join(text.split())

    for path, entry in _manifest().items():
        if entry.get("passthrough"):
            # The Go side prints this help (the stub forwards --help); check the declared text instead.
            assert words(entry["long"]) in words(_python_tree()[path].help or ""), path
            continue
        shown = CliRunner().invoke(substrate, [*path.split()[1:], "--help"], obj=AppContext())
        assert shown.exit_code == 0, (path, shown.output)
        if entry.get("long"):
            assert words(entry["long"]) in words(shown.output), path
        if entry.get("example"):
            assert words(entry["example"]) in words(shown.output), path


def test_bool_and_repeatable_flags_have_the_matching_click_shape() -> None:
    for path, command in _python_tree().items():
        for param in command.params:
            if not isinstance(param, GatewayOption):
                continue
            if param.go_type == "bool":
                assert param.is_flag, f"{path} --{param.name}"
            elif param.go_type in {"stringArray", "stringSlice", "intSlice"}:
                assert param.multiple, f"{path} --{param.name}"
            else:
                assert not param.is_flag and not param.multiple, f"{path} --{param.name}"


@pytest.fixture
def exec_capture(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_execv(path: str, argv: list[str]) -> None:
        calls.append([path, *argv])

    monkeypatch.setattr(cmd_substrate, "_execv", fake_execv)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    return calls


@pytest.mark.parametrize(
    "args",
    [
        ["login", "--admin-url", "https://admin.example.test:9443", "--issuer", "https://sso.example.test/r"],
        ["login", "--workload", "--workload-token-file", "/run/ci/token"],
        ["logout"],
        ["whoami", "--json"],
        ["run", "claude"],
        ["run", "claude", "--clone", "https://git.example.test/a.git", "--ref", "main", "--", "--model", "sonnet"],
        ["run", "codex", "--task", "fix the failing tests", "--detach", "--profile", "eng"],
        ["run", "claude", "--batch", "tasks.yaml", "--parallel", "5", "--secret", "NPM_TOKEN", "--secret", "GH"],
        ["run", "claude", "--unmask", ".env.example", "--exclude", "build/**", "--max-upload-mb", "200"],
        ["connect", "fix-tests-7f3a", "--transport", "longpoll"],
        ["list", "-o", "json", "--batch", "b1"],
        ["status"],
        ["status", "fix-tests-7f3a", "--json"],
        ["logs", "fix-tests-7f3a", "-f"],
        ["pull", "fix-tests-7f3a", "--branch", "agent/fix", "--yes"],
        ["pull", "fix-tests-7f3a", "--patch-out", "fix.patch", "--timeout", "5m"],
        ["checkpoint", "fix-tests-7f3a", "--every", "1h"],
        ["undo", "fix-tests-7f3a", "--to", "dc-checkpoint-2", "-y"],
        ["delete", "one", "two", "-y"],
        ["delete", "--batch", "b1", "--yes"],
        ["migrate", "old-agent"],
        ["approvals", "--json"],
        ["approve", "ask-1", "--always", "--reason", "known tool"],
        ["reject", "ask-2"],
        ["usage", "--batch", "b1", "-o", "json"],
        ["secrets", "list", "--mine"],
        ["secrets", "set", "NPM_TOKEN", "--from-env", "NPM_TOKEN"],
        ["secrets", "rm", "NPM_TOKEN", "-y"],
        ["secrets", "test", "NPM_TOKEN"],
        ["policy", "explain", "fix-tests-7f3a"],
        ["policy", "show", "--json"],
        ["policy", "test", "fix-tests-7f3a", "--host", "registry.example.test"],
        ["doctor", "--json"],
        ["verify", "--install-file", "install.yaml", "--json"],
        ["status", "--cluster", "--api", "--json"],
        ["setup", "--remove", "--dry-run"],
        ["bundle", "apply", "bundle.dcbundle", "--atespaces", "eng,ops"],
        ["bundle", "status"],
        ["template", "build", "--connector", "claude", "--from", "img:1", "--to", "reg/img:1", "--json"],
        ["template", "verify", "reg/img@sha256:abc", "--anchors", "trust.pem"],
    ],
)
def test_every_stub_forwards_its_arguments_unchanged(exec_capture: list[list[str]], args: list[str]) -> None:
    result = CliRunner().invoke(substrate, args, obj=AppContext())
    assert result.exit_code == 0, (args, result.output)
    assert exec_capture == [["/opt/dc/defenseclaw-gateway", "/opt/dc/defenseclaw-gateway", "substrate", *args]]


def test_a_missing_gateway_binary_is_a_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "")
    result = CliRunner().invoke(substrate, ["list"], obj=AppContext())
    assert result.exit_code != 0
    assert "defenseclaw-gateway" in result.output


def test_substrate_runs_without_a_defenseclaw_config() -> None:
    from defenseclaw import main as main_module

    assert "substrate" in main_module.SKIP_LOAD_COMMANDS
    assert "substrate" in main_module.ALLOW_MISSING_V8_PREFLIGHT
