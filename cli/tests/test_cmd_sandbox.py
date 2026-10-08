# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw sandbox``: the Click stubs mirror the Go tree and exec it.

The Go command tree is pinned in internal/cli/testdata/sandbox_commands.json
(TestSandboxCommandManifest regenerates it). These tests hold the Python stubs
to that manifest in both directions and check that every stub hands its
arguments to ``defenseclaw-gateway`` unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner
from defenseclaw import main as main_module
from defenseclaw.commands import cmd_sandbox
from defenseclaw.commands.cmd_sandbox import GatewayCommand, GatewayOption, sandbox
from defenseclaw.context import AppContext

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "internal" / "cli" / "testdata" / "sandbox_commands.json"


def _manifest() -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in json.loads(MANIFEST.read_text(encoding="utf-8"))}


def _python_tree() -> dict[str, click.Command]:
    out: dict[str, click.Command] = {}

    def walk(node: click.Command, path: str) -> None:
        if not isinstance(node, click.Group):
            return
        for name, child in node.commands.items():
            child_path = f"{path} {name}"
            out[child_path] = child
            walk(child, child_path)

    walk(sandbox, "sandbox")
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
        "regenerate it: DEFENSECLAW_UPDATE_GOLDEN=1 go test ./internal/cli -run TestSandboxCommandManifest"
    )
    assert len(_manifest()) > 20


def test_every_go_command_has_a_python_stub() -> None:
    python = _python_tree()
    missing = sorted(set(_manifest()) - set(python))
    assert not missing, f"Go sandbox commands without a Python stub: {missing}"


def test_every_python_stub_exists_in_go() -> None:
    extra = sorted(set(_python_tree()) - set(_manifest()))
    assert not extra, f"Python sandbox stubs the Go tree does not have: {extra}"


@pytest.mark.parametrize("path", sorted(_manifest()))
def test_stub_flags_match_the_go_flags(path: str) -> None:
    command = _python_tree()[path]
    assert _python_flags(command) == _manifest_flags(_manifest()[path]), path


@pytest.mark.parametrize("path", sorted(_manifest()))
def test_groups_and_leaves_match(path: str) -> None:
    manifest = _manifest()
    has_children = any(other.startswith(path + " ") for other in manifest)
    command = _python_tree()[path]
    if has_children:
        assert isinstance(command, click.Group), path
    else:
        assert isinstance(command, GatewayCommand), path
        assert ("sandbox", *command.gateway_path) == tuple(path.split()), path


def test_short_help_is_the_go_short_description() -> None:
    python = _python_tree()
    for path, entry in _manifest().items():
        assert python[path].short_help == entry["short"], path


def test_long_help_and_examples_are_the_go_ones() -> None:
    # GAP-0171: users read the stub's --help, so a Go Long text the stub lacks
    # is help nobody sees (unblock never said what it cannot lift). Click
    # rewraps, so compare the words.
    def words(text: str) -> str:
        return " ".join(text.split())

    stubs = {"sandbox " + " ".join(cmd.path): cmd for cmd in cmd_sandbox.SANDBOX_COMMANDS}
    for path, entry in _manifest().items():
        if entry.get("long"):
            assert words(stubs[path].long) == words(entry["long"]), path
        if entry.get("example"):
            assert words(stubs[path].example) == words(entry["example"]), path
    shown = CliRunner().invoke(sandbox, ["unblock", "--help"], obj=AppContext())
    assert shown.exit_code == 0, shown.output
    assert "It cannot lift a block-list entry" in words(shown.output)
    # GAP-0187: nor what the egress guard keeps closed.
    assert "Nor does it open a private network" in words(shown.output)


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

    monkeypatch.setattr(cmd_sandbox, "_execv", fake_execv)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "linux")
    return calls


@pytest.mark.parametrize(
    "args",
    [
        ["setup", "--non-interactive", "--harness", "claudecode", "--harness", "codex", "--no-wrappers"],
        ["setup", "--harness", "claudecode,codex", "-y"],
        ["doctor", "--json"],
        ["doctor", "-o", "json", "--fix", "-y"],
        ["run", "claude"],
        ["run", "claude", "--copy", "--name", "fix-tests", "--", "--model", "sonnet"],
        ["run", "codex", "--host-port", "5432,6379", "--host-port", "8080", "--context", "~/code/lib"],
        ["run", "claude", "-d", "-p", "fix the failing tests", "--credential", "STRIPE_API_KEY=api.stripe.com"],
        ["run", "claude", "--profile", "strict", "--unmask", ".env.example", "--llm", "none"],
        ["list", "-o", "json"],
        ["status"],
        ["status", "myapp-claude-7f3a", "--output", "json"],
        ["connect", "myapp", "--", "--resume"],
        ["connect", "myapp", "--shell"],
        ["exec", "myapp", "--", "ls", "-la"],
        ["exec", "myapp", "--workdir", "/work/app", "--tty", "--", "sh"],
        ["stop", "myapp"],
        ["start", "myapp", "--no-snapshot"],
        ["delete", "one", "two", "-y", "--keep-snapshot"],
        ["logs", "myapp", "-f", "-n", "50"],
        ["activity", "-f", "--since", "42", "--sandbox", "myapp"],
        ["undo", "myapp", "--preview"],
        ["undo", "myapp", "-y", "--restart", "--keep-refs"],
        ["review", "myapp", "--diff", "-o", "json"],
        ["approvals", "--watch"],
        ["approve", "myapp", "ask-1", "--always"],
        ["reject", "myapp", "ask-1", "--reason", "not needed"],
        ["unblock", "webhook.site", "--sandbox", "myapp"],
        ["unblock", "example.com", "--always"],
        ["pull", "myapp", "--apply"],
        ["pull", "myapp", "--patch-out", "work.patch", "--accept-sensitive"],
        ["policy", "show", "--sandbox", "myapp"],
        ["policy", "explain", "--harness", "codex", "--copy", "--unmask", "a", "--unmask", "b"],
        ["policy", "suggest", "-o", "json"],
        ["policy", "allow", "api.example.com", "cdn.example.com"],
        ["policy", "block", "paste.example.com"],
        ["pack", "list"],
        ["pack", "show", "balanced", "-o", "json"],
        ["pack", "validate", "./pack.yaml"],
        ["image", "build", "claudecode", "--force", "--verbose"],
        ["image", "list"],
        ["image", "prune", "--dry-run"],
        ["image", "rm", "claude", "kiro", "-y", "--dry-run"],
        ["enable", "claude", "--shell", "zsh"],
        ["disable", "codex", "--rc", "/tmp/rc"],
        ["teardown", "--dry-run", "--keep-images"],
        # pflag's bool flags take an explicit value too.
        ["run", "claude", "--copy=false", "--safe=true", "-y=true", "--", "--resume=false"],
        ["teardown", "--yes=1", "--dry-run=F", "--keep-images=True"],
        ["run", "claude", "--prompt", "--copy=false", "--detach=t"],
    ],
)
def test_stub_execs_the_gateway_with_the_same_argv(exec_capture: list[list[str]], args: list[str]) -> None:
    result = CliRunner().invoke(sandbox, args, obj=AppContext(), catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert exec_capture == [["/opt/dc/defenseclaw-gateway", "/opt/dc/defenseclaw-gateway", "sandbox", *args]]


def test_the_root_cli_forwards_through_the_stub(exec_capture: list[list[str]], monkeypatch) -> None:
    monkeypatch.setattr("defenseclaw.config.require_v8_config", lambda **_kwargs: None)
    result = CliRunner().invoke(main_module.cli, ["sandbox", "list", "-o", "json"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert exec_capture[-1][2:] == ["sandbox", "list", "-o", "json"]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["run"], "Missing argument"),
        (["run", "claude", "--model", "x"], "No such option"),
        (["stop"], "Missing argument"),
        (["image", "rm"], "Missing argument"),
        (["approve", "myapp"], "Missing argument"),
        (["run", "claude", "--host-port", "abc"], "is not a port"),
        (["activity", "--since", "-1"], "--since"),
        (["logs", "x", "-n", "many"], "not a valid integer"),
        # A value pflag refuses for a bool flag is refused here too.
        (["run", "claude", "--copy=maybe"], "does not take a value"),
    ],
)
def test_usage_errors_stop_before_the_gateway_runs(exec_capture, args: list[str], message: str) -> None:
    result = CliRunner().invoke(sandbox, args, obj=AppContext())
    assert result.exit_code == 2, result.output
    assert message in result.output
    assert exec_capture == []


def test_help_is_answered_by_the_stub(exec_capture) -> None:
    result = CliRunner().invoke(sandbox, ["run", "--help"], obj=AppContext())
    assert result.exit_code == 0
    assert "--copy" in result.output and "Arguments after -- go to the" in " ".join(result.output.split())
    assert exec_capture == []


def test_run_help_names_every_harness(exec_capture) -> None:
    # Manual test R2-73; internal/cli pins that this is the Go help text and
    # that it names every harness in the registry.
    result = CliRunner().invoke(sandbox, ["run", "--help"], obj=AppContext())
    assert result.exit_code == 0
    text = " ".join(result.output.split())
    # Certification AG-MAC-F8: Antigravity by the name image build, image
    # list and openshell.harnesses use, with its command accepted too.
    assert "The harness is claude, codex, copilot, opencode, kiro, hermes, openhands, omnigent or antigravity" in text
    assert "(its command, agy, works too; amp, cursor-agent and devin are not verified yet, so they do not run)" in text
    assert exec_capture == []


def test_help_says_how_a_mac_differs(exec_capture) -> None:
    # On macOS (OpenShell's MicroVM driver) every run works on a copy: --yes
    # leaves its changes in the sandbox, and review previews the pull.
    def help_text(*args: str) -> str:
        result = CliRunner().invoke(sandbox, [*args, "--help"], obj=AppContext())
        assert result.exit_code == 0, result.output
        return " ".join(result.output.split())

    run = help_text("run")
    assert "on macOS (the MicroVM driver) every run works on a copy" in run
    assert "(mount: keep the changes; copy: leave them in the sandbox for pull)" in run
    assert "(repeatable; mount mode only)" in run
    assert "copy: leave them in the sandbox for pull" in help_text("connect")
    assert 'previews what "sandbox pull" would bring back and applies nothing' in help_text("review")
    assert "on a Mac it switches the gateway to OpenShell's MicroVM driver" in help_text("setup")
    assert exec_capture == []


def test_windows_is_refused_with_a_clear_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "windows")

    def must_not_resolve() -> str:
        raise AssertionError("the gateway binary was resolved on Windows")

    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", must_not_resolve)
    monkeypatch.setattr(cmd_sandbox, "_execv", lambda *_: pytest.fail("exec on Windows"))
    result = CliRunner().invoke(sandbox, ["list"], obj=AppContext())
    assert result.exit_code == cmd_sandbox.UNSUPPORTED_EXIT_CODE
    assert "Linux and macOS only" in result.output


def test_a_missing_gateway_binary_is_a_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "linux")
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: None)
    result = CliRunner().invoke(sandbox, ["doctor"], obj=AppContext())
    assert result.exit_code == 1
    assert "defenseclaw-gateway is not installed" in result.output
    assert "Traceback" not in result.output


def test_an_unstartable_gateway_binary_is_a_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "linux")
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/nonexistent/defenseclaw-gateway")

    def failing_execv(_path: str, _argv: list[str]) -> None:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(cmd_sandbox, "_execv", failing_execv)
    result = CliRunner().invoke(sandbox, ["list"], obj=AppContext())
    assert result.exit_code == 1
    assert "could not start /nonexistent/defenseclaw-gateway: No such file or directory" in result.output


@pytest.mark.parametrize(
    ("argv", "env", "expected"),
    [
        (["sandbox", "teardown", "--yes"], {}, True),
        (["sandbox", "pack", "list"], {}, True),
        (["sandbox", "pack", "show", "strict"], {}, True),
        (["sandbox", "pack", "validate", "pack.yaml"], {}, True),
        (["sandbox", "pack"], {}, False),
        # GAP-0124: the CI mode the policy-packs page documents needs no install.
        (["sandbox", "policy", "test", "--pack", "balanced", "--fixture", "f.yaml"], {}, True),
        (["sandbox", "policy", "show"], {}, False),
        (["sandbox", "run", "claude"], {"DEFENSECLAW_SANDBOX_ID": "sb-1"}, True),
        (["sandbox", "run", "claude"], {}, False),
        (["sandbox", "list"], {}, False),
        (["status"], {}, False),
    ],
)
def test_config_optional_sandbox_commands_mirror_go(monkeypatch, argv, env, expected) -> None:
    monkeypatch.delenv("DEFENSECLAW_SANDBOX_ID", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main_module.sys, "argv", ["defenseclaw", *argv])
    ctx = click.Context(main_module.cli)
    ctx.invoked_subcommand = argv[0]
    assert main_module._is_config_optional_sandbox_command(ctx) is expected
