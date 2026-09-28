# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw sandbox — run coding agents in NVIDIA OpenShell sandboxes.

The commands are implemented by the Go ``defenseclaw-gateway sandbox`` tree
(internal/cli/sandbox.go). This module declares the same commands and flags as
Click stubs, so ``--help`` and the documentation check see the real grammar,
and each stub replaces this process with the gateway binary, forwarding the
arguments exactly as typed. The command tree is pinned in
internal/cli/testdata/sandbox_commands.json; cli/tests/test_cmd_sandbox.py
checks the stubs against it both ways.

``legacy-cleanup`` stays Python-native: it undoes a legacy openshell-sandbox
(0.0.x) install on hosts that may not have a current gateway binary yet.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, NoReturn

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

# The gateway refuses these platforms with exit status 3; the stub does the
# same without starting it.
UNSUPPORTED_PLATFORM_MESSAGE = "OpenShell sandboxes run on Linux and macOS only; Windows and WSL2 are not supported"
UNSUPPORTED_EXIT_CODE = 3

# Tests replace this to capture the argv instead of replacing the process.
_execv = os.execv


# --- Command declarations ----------------------------------------------------
#
# Each entry mirrors one cobra command. ``go_type`` is the pflag value type the
# manifest records; the Click option is shaped from it (bool flags, repeatable
# array/slice flags, integers). Help strings are the Go ones.


@dataclass(frozen=True)
class _Flag:
    name: str
    go_type: str
    help: str
    short: str = ""
    default: str = ""
    metavar: str = ""


@dataclass(frozen=True)
class _Arg:
    name: str
    required: bool = True
    many: bool = False


@dataclass(frozen=True)
class _Cmd:
    path: tuple[str, ...]
    short: str
    long: str = ""
    args: tuple[_Arg, ...] = ()
    flags: tuple[_Flag, ...] = ()
    example: str = ""


_OUTPUT = _Flag("output", "string", "output format: text or json", short="o", default="text", metavar="FORMAT")
_YES = _Flag("yes", "bool", "answer every question with its default", short="y")


def _policy_flags() -> tuple[_Flag, ...]:
    return (
        _OUTPUT,
        _Flag("sandbox", "string", "the policy of this sandbox", metavar="NAME"),
        _Flag("harness", "string", "resolve for this harness", metavar="HARNESS"),
        _Flag("pack", "string", "resolve with this pack", metavar="PACK"),
        _Flag("profile", "string", "resolve with this profile", metavar="PROFILE"),
        _Flag("copy", "bool", "resolve for a copy-mode run"),
        _Flag("safe", "bool", "resolve for a --safe run"),
        _Flag("unmask", "stringArray", "resolve with these --unmask globs", metavar="GLOB"),
    )


def _wrapper_flags() -> tuple[_Flag, ...]:
    return (
        _Flag("shell", "string", "bash, zsh or fish (default: $SHELL)", metavar="SHELL"),
        _Flag("rc", "string", "rc file to edit (default: the shell's)", metavar="PATH"),
    )


def _decide_flags() -> tuple[_Flag, ...]:
    return (
        _Flag("always", "bool", "keep the decision for future sandboxes"),
        _Flag("reason", "string", "note recorded with the decision", metavar="TEXT"),
    )


SANDBOX_COMMANDS: tuple[_Cmd, ...] = (
    _Cmd(
        ("setup",),
        "One-time setup: OpenShell, bind mounts, telemetry, harnesses, wrappers, images",
        long=(
            "Checks this machine, installs OpenShell with NVIDIA's installer when you agree, "
            "enables project-folder bind mounts on your local OpenShell gateway (backed up and "
            'restored by "sandbox teardown"), turns OpenShell\'s upstream telemetry off unless you '
            "keep it, records the harnesses, offers shell wrappers and builds the harness images."
        ),
        flags=(
            _Flag(
                "install-openshell",
                "bool",
                "install OpenShell with NVIDIA's pinned, sha256-verified installer (uses sudo)",
            ),
            _Flag("no-mounts", "bool", "leave bind mounts off; every run then works on a copy"),
            _Flag("wrappers", "bool", "make the harness commands run sandboxed without asking"),
            _Flag("no-wrappers", "bool", "do not offer the shell wrappers"),
            _Flag(
                "non-interactive",
                "bool",
                "never prompt: take the defaults and skip steps that need consent",
            ),
            _YES,
            _Flag(
                "harness",
                "stringSlice",
                "harness to set up, added to openshell.harnesses "
                "(repeatable; default: openshell.harnesses, else claude and codex)",
                metavar="HARNESS",
            ),
            _Flag("upstream-telemetry", "bool", "keep OpenShell's anonymous usage telemetry on"),
            _Flag("skip-images", "bool", "do not build the harness images now (the first run builds them)"),
            _Flag(
                "restart-gateway",
                "bool",
                "restart the OpenShell gateway to apply its configuration even while sandboxes run on it",
            ),
        ),
        example="defenseclaw sandbox setup\ndefenseclaw sandbox setup --non-interactive --harness claudecode",
    ),
    _Cmd(
        ("doctor",),
        "Check that this machine can run sandboxes",
        long=(
            "Checks the platform, Landlock, Docker, the OpenShell service, CLI, registration and "
            "version, bind mounts, telemetry, ports, the DefenseClaw daemon, harness images, shell "
            "wrappers and the organization policy. Exits 1 when a check fails (with --output json "
            'the result is printed and the exit status is 0; read "ok").'
        ),
        flags=(
            _OUTPUT,
            _Flag("json", "bool", "same as --output json"),
            _Flag("fix", "bool", "apply the fixes doctor can make as your user (asks first)"),
            _Flag("yes", "bool", "apply fixes without asking", short="y"),
        ),
    ),
    _Cmd(
        ("run",),
        "Run a harness in a sandbox on this folder",
        long=(
            "Runs the harness in a new sandbox on the current folder: live-mounted by default "
            "with a pre-session snapshot, or a copy with --copy. The harness is claude, codex, "
            "copilot, opencode, kiro, hermes, openhands, omnigent or agy (amp, cursor-agent and devin "
            "are not verified yet, so they do not run). Skip-permissions mode is on by default; "
            "--safe keeps the harness's own prompts. The harness gets your terminal; when it exits "
            "you get a summary, a review of changed files that can run code on your machine, and "
            "the choice to keep or undo the changes. Arguments after -- go to the harness."
        ),
        args=(_Arg("harness"), _Arg("harness_args", required=False, many=True)),
        flags=(
            _Flag(
                "name",
                "string",
                "sandbox name, at most 19 lowercase letters, digits and '-' (default <folder>-<random>)",
                metavar="NAME",
            ),
            _Flag(
                "copy",
                "bool",
                "work on a copy of the folder with secrets held back; bring changes back with pull",
            ),
            _Flag("safe", "bool", "keep the harness's own permission prompts (skip-permissions off)"),
            _Flag(
                "pack",
                "string",
                "sandbox policy pack (open, balanced, strict, or a custom pack)",
                metavar="PACK",
            ),
            _Flag("profile", "string", "network profile: open, balanced or strict", metavar="PROFILE"),
            _Flag("context", "stringArray", "extra folder mounted read-only (repeatable)", metavar="PATH"),
            _Flag(
                "unmask",
                "stringArray",
                "share a masked secret file or glob with the sandbox (repeatable)",
                metavar="GLOB",
            ),
            _Flag(
                "host-port",
                "intSlice",
                "open this localhost port on your machine to the sandbox (repeatable)",
                metavar="PORT",
            ),
            _Flag(
                "credential",
                "stringArray",
                "NAME=host[:port]: give the sandbox a placeholder for $NAME that works only against "
                "that host (repeatable)",
                metavar="NAME=HOST",
            ),
            _Flag(
                "github-write",
                "bool",
                "bind your GitHub token (GH_TOKEN or GITHUB_TOKEN) to api.github.com so gh can call the "
                "GitHub API (for example to open pull requests) with everything the token may do; git push "
                "over HTTPS is not covered",
            ),
            _Flag("no-mcp", "bool", "leave the harness's MCP servers behind"),
            _Flag(
                "detach",
                "bool",
                "run in the background (needs --prompt); follow with sandbox logs -f",
                short="d",
            ),
            _Flag("rm", "bool", "delete the sandbox when the session ends"),
            _Flag("prompt", "string", "run the harness headless with this prompt", short="p", metavar="TEXT"),
            _Flag(
                "env",
                "stringArray",
                "KEY=VALUE non-secret variable for the sandbox (repeatable)",
                metavar="KEY=VALUE",
            ),
            _Flag(
                "llm",
                "string",
                "model credential to share: auto, none, anthropic, claude-oauth, openai or bedrock",
                default="auto",
                metavar="SOURCE",
            ),
            _Flag(
                "bedrock-region",
                "string",
                "Amazon Bedrock region for --llm bedrock "
                "(default $AWS_REGION, then $AWS_DEFAULT_REGION, then us-east-1)",
                metavar="REGION",
            ),
            _Flag("no-snapshot", "bool", "skip the pre-session snapshot (and so undo)"),
            _Flag("no-build", "bool", "fail instead of building a missing harness image"),
            _Flag("new", "bool", "start a new sandbox even when one already holds this folder"),
            _Flag("refresh", "bool", "when resuming a copy-mode sandbox, copy the folder again"),
            _Flag("cpu", "string", "CPU limit, for example 2 or 500m", metavar="CPU"),
            _Flag("memory", "string", "memory limit, for example 4Gi", metavar="MEMORY"),
            _Flag("yes", "bool", "take the defaults at the end of the session (keep the changes)", short="y"),
        ),
        example=(
            "defenseclaw sandbox run claude\n"
            "defenseclaw sandbox run codex --copy --name fix-tests\n"
            'defenseclaw sandbox run claude --detach --prompt "fix the failing tests"\n'
            "defenseclaw sandbox run claude --credential STRIPE_API_KEY=api.stripe.com -- --model sonnet"
        ),
    ),
    _Cmd(("list",), "List sandboxes", flags=(_OUTPUT,)),
    _Cmd(
        ("status",),
        "Show the sandbox subsystem, or one sandbox in detail",
        args=(_Arg("name", required=False),),
        flags=(_OUTPUT,),
    ),
    _Cmd(
        ("connect",),
        "Resume a sandbox: start it if stopped and attach the harness",
        long="Harness arguments go after --.",
        args=(_Arg("name"), _Arg("harness_args", required=False, many=True)),
        flags=(
            _Flag("shell", "bool", "open a shell in the sandbox instead of the harness"),
            _Flag("refresh", "bool", "copy-mode: copy the folder into the sandbox again first"),
            _Flag("rm", "bool", "delete the sandbox when the session ends"),
            _Flag("yes", "bool", "take the defaults at the end of the session (keep the changes)", short="y"),
            _Flag("prompt", "string", "run the harness headless with this prompt", short="p", metavar="TEXT"),
        ),
    ),
    _Cmd(
        ("exec",),
        "Run a command in a sandbox",
        long="Usage: defenseclaw sandbox exec <name> -- <command> [args...]",
        args=(_Arg("name"), _Arg("command", required=False, many=True)),
        flags=(
            _Flag("workdir", "string", "working directory in the sandbox (default: the project)", metavar="DIR"),
            _Flag("tty", "bool", "allocate a terminal even when this one is not"),
            _Flag("no-tty", "bool", "never allocate a terminal"),
        ),
    ),
    _Cmd(
        ("stop",),
        "Stop a sandbox (it is kept for start or connect)",
        args=(_Arg("name"),),
        flags=(_Flag("yes", "bool", "stop without asking when a detached run is still going", short="y"),),
    ),
    _Cmd(
        ("start",),
        "Start a stopped sandbox for a new session",
        args=(_Arg("name"),),
        flags=(
            _Flag("no-snapshot", "bool", "keep the previous session's snapshot instead of taking a new one"),
            _Flag(
                "new-snapshot",
                "bool",
                "take a new snapshot even if the folder still has an earlier session's changes "
                "(undo no longer reverts them)",
            ),
        ),
    ),
    _Cmd(
        ("delete",),
        "Delete sandboxes with their providers, credentials and snapshots",
        args=(_Arg("names", many=True),),
        flags=(
            _Flag("yes", "bool", "do not ask", short="y"),
            _Flag("keep-snapshot", "bool", "keep the pre-session snapshot"),
        ),
    ),
    _Cmd(
        ("logs",),
        "Show the output of a sandbox's detached run",
        args=(_Arg("name"),),
        flags=(
            _Flag("follow", "bool", "keep following the output", short="f"),
            _Flag("lines", "int", "lines to show", short="n", default="200", metavar="N"),
        ),
    ),
    _Cmd(
        ("activity",),
        "Show the live activity feed: destinations, blocks, asks, tool blocks, findings",
        flags=(
            _OUTPUT,
            _Flag("sandbox", "string", "only this sandbox", metavar="NAME"),
            _Flag("follow", "bool", "keep following the feed", short="f"),
            _Flag("since", "uint64", "start after this event sequence number", default="0", metavar="SEQ"),
        ),
    ),
    _Cmd(
        ("undo",),
        "Restore the project folder to its pre-session snapshot",
        args=(_Arg("name"),),
        flags=(
            _OUTPUT,
            _Flag("yes", "bool", "do not ask after the preview", short="y"),
            _Flag("preview", "bool", "only show what undo would change"),
            _Flag("restart", "bool", "start the sandbox again afterwards"),
            _Flag("keep-refs", "bool", "leave branches and tags as the session left them"),
        ),
    ),
    _Cmd(
        ("review",),
        "Review the session's changes, flagging files that can run code on this machine",
        args=(_Arg("name"),),
        flags=(_OUTPUT, _Flag("diff", "bool", "print the unified diff too")),
    ),
    _Cmd(
        ("approvals",),
        "List the asks waiting for you (doors into your machine or network)",
        flags=(
            _OUTPUT,
            _Flag("sandbox", "string", "only this sandbox", metavar="NAME"),
            _Flag("watch", "bool", "keep watching for new asks"),
        ),
    ),
    _Cmd(("approve",), "Approve an ask", args=(_Arg("name"), _Arg("id")), flags=_decide_flags()),
    _Cmd(("reject",), "Reject an ask", args=(_Arg("name"), _Arg("id")), flags=_decide_flags()),
    _Cmd(
        ("unblock",),
        "Lift an egress block for one sandbox or for every sandbox",
        args=(_Arg("host"),),
        flags=(
            _Flag("sandbox", "string", "unblock for this sandbox only", metavar="NAME"),
            _Flag("always", "bool", "unblock for every sandbox from now on"),
        ),
    ),
    _Cmd(
        ("pull",),
        "Bring a copy-mode sandbox's work back (3-way apply, a branch, or a patch)",
        args=(_Arg("name"),),
        flags=(
            _OUTPUT,
            _Flag("apply", "bool", "merge the changes into your working tree (3-way)"),
            _Flag("branch", "bool", "put the changes on branch dc/<name>"),
            _Flag("branch-name", "string", "put the changes on this branch", metavar="BRANCH"),
            _Flag("patch-out", "string", "write the changes to this patch file", metavar="FILE"),
            _Flag("force", "bool", "override blocking review gates, an existing branch or patch file"),
            _Flag("accept-sensitive", "bool", "bring back changes that can run code on this machine"),
        ),
    ),
    _Cmd(("policy",), "Show, explain and adjust the sandbox policy"),
    _Cmd(("policy", "show"), "Show the effective sandbox policy", flags=_policy_flags()),
    _Cmd(
        ("policy", "explain"),
        "Show every resolved setting and where it comes from (pack, config, flag, organization)",
        flags=_policy_flags(),
    ),
    _Cmd(
        ("policy", "suggest"),
        "Suggest an egress allowlist from the destinations sandboxes reached",
        flags=(_OUTPUT, _Flag("sandbox", "string", "only this sandbox's destinations", metavar="NAME")),
    ),
    _Cmd(
        ("policy", "allow"),
        "Add hosts to openshell.egress.allow (used by the balanced and strict profiles)",
        args=(_Arg("hosts", many=True),),
    ),
    _Cmd(("policy", "block"), "Add hosts to openshell.egress.block", args=(_Arg("hosts", many=True),)),
    _Cmd(("pack",), "Inspect sandbox policy packs"),
    _Cmd(("pack", "list"), "List the built-in and custom packs with their sha256 digests", flags=(_OUTPUT,)),
    _Cmd(
        ("pack", "show"),
        "Print a pack and its sha256 digest (for openshell.admin.required_pack_digest)",
        args=(_Arg("pack"),),
        flags=(_OUTPUT,),
    ),
    _Cmd(("pack", "validate"), "Validate a pack file strictly", args=(_Arg("path"),)),
    _Cmd(("image",), "Build, list and prune the harness images"),
    _Cmd(
        ("image", "build"),
        "Build and hook-verify harness images (default: the configured harnesses)",
        args=(_Arg("harnesses", required=False, many=True),),
        flags=(
            _Flag("force", "bool", "rebuild even when a verified image is current"),
            _Flag("verbose", "bool", "stream the docker build output"),
        ),
    ),
    _Cmd(("image", "list"), "List the harness images", flags=(_OUTPUT,)),
    _Cmd(
        ("image", "prune"),
        "Remove superseded harness images",
        flags=(_Flag("dry-run", "bool", "only show what would be removed"),),
    ),
    _Cmd(
        ("enable",),
        "Make the harness command run sandboxed (a marked block in your shell rc)",
        args=(_Arg("harness"),),
        flags=_wrapper_flags(),
    ),
    _Cmd(
        ("disable",),
        "Stop the harness command from running sandboxed (removes the shell wrapper)",
        args=(_Arg("harness"),),
        flags=_wrapper_flags(),
    ),
    _Cmd(
        ("teardown",),
        "Remove every DefenseClaw sandbox, provider, profile, image, gateway change and wrapper",
        long=(
            "Deletes DefenseClaw's sandboxes, OpenShell providers and provider profiles and its harness "
            "images, restores the OpenShell gateway configuration that setup changed (when nobody changed "
            "it since), removes the shell wrappers and turns openshell.enabled off. OpenShell itself stays "
            'installed. "defenseclaw uninstall" runs it.'
        ),
        flags=(
            _Flag("yes", "bool", "do not ask", short="y"),
            _Flag("dry-run", "bool", "only show what would be removed"),
            _Flag("keep-images", "bool", "keep the harness images"),
        ),
    ),
)


# --- Click shaping -----------------------------------------------------------


class _PortList(click.ParamType):
    """A pflag intSlice value: one port or a comma-separated list."""

    name = "port[,port...]"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        text = str(value)
        parts = [part.strip() for part in text.split(",")]
        if not parts or any(not part.lstrip("-").isdigit() for part in parts):
            self.fail(f"{text!r} is not a port number (or a comma-separated list of them)", param, ctx)
        return text


class GatewayOption(click.Option):
    """A Click option that records the pflag type of the Go flag it mirrors."""

    def __init__(self, *args: Any, go_type: str, go_default: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.go_type = go_type
        self.go_default = go_default


class GatewayCommand(click.Command):
    """A Click stub that hands its command line to ``defenseclaw-gateway``.

    Click parses the arguments (so usage errors, ``--help`` and the docs check
    behave), then the callback forwards the arguments exactly as typed.
    """

    def __init__(self, *args: Any, gateway_path: tuple[str, ...], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.gateway_path = gateway_path

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        ctx.meta[_RAW_ARGS_KEY] = tuple(args)
        return super().parse_args(ctx, args)


_RAW_ARGS_KEY = "defenseclaw.sandbox.raw_args"


def _click_option(flag: _Flag) -> GatewayOption:
    decls = [f"--{flag.name}"]
    if flag.short:
        decls.append(f"-{flag.short}")
    kwargs: dict[str, Any] = {"help": flag.help}
    if flag.go_type == "bool":
        kwargs.update(is_flag=True, default=False)
    elif flag.go_type in {"stringArray", "stringSlice"}:
        kwargs.update(multiple=True, metavar=flag.metavar or None)
    elif flag.go_type == "intSlice":
        kwargs.update(multiple=True, type=_PortList(), metavar=flag.metavar or None)
    elif flag.go_type == "int":
        kwargs.update(type=click.INT, metavar=flag.metavar or None)
    elif flag.go_type == "uint64":
        kwargs.update(type=click.IntRange(min=0), metavar=flag.metavar or None)
    elif flag.go_type == "string":
        kwargs.update(type=click.STRING, metavar=flag.metavar or None)
    else:  # pragma: no cover - guarded by the manifest parity test
        raise ValueError(f"unsupported flag type {flag.go_type!r} for --{flag.name}")
    if flag.default and flag.go_type != "bool":
        kwargs.update(default=flag.default, show_default=True)
    # The pflag DefValue the manifest records: "false", "[]", or the literal.
    go_default = flag.default or {"bool": "false", "stringArray": "[]", "stringSlice": "[]", "intSlice": "[]"}.get(
        flag.go_type, ""
    )
    return GatewayOption(decls, go_type=flag.go_type, go_default=go_default, **kwargs)


def _click_argument(arg: _Arg) -> click.Argument:
    if arg.many:
        return click.Argument([arg.name], nargs=-1, required=arg.required)
    return click.Argument([arg.name], required=arg.required)


def _help_text(cmd: _Cmd) -> str:
    text = cmd.short + "."
    if cmd.long:
        text += "\n\n" + cmd.long
    if cmd.example:
        text += "\n\n\b\nExamples:\n" + "\n".join("  " + line for line in cmd.example.splitlines())
    return text


def _forward(ctx: click.Context, **_params: Any) -> NoReturn:
    command = ctx.command
    assert isinstance(command, GatewayCommand)
    raw = ctx.meta.get(_RAW_ARGS_KEY, ())
    exec_gateway(("sandbox", *command.gateway_path, *raw))


def exec_gateway(argv: Sequence[str]) -> NoReturn:
    """Replace this process with ``defenseclaw-gateway <argv>``."""
    from defenseclaw.gateway import resolve_gateway_binary
    from defenseclaw.platform_support import host_os

    if host_os() == "windows":
        click.echo(f"{ux._style('✗', fg='red', bold=True)} {UNSUPPORTED_PLATFORM_MESSAGE}", err=True)
        raise SystemExit(UNSUPPORTED_EXIT_CODE)
    binary = resolve_gateway_binary()
    if not binary:
        raise click.ClickException(
            "defenseclaw-gateway is not installed; run 'defenseclaw upgrade' (or 'make gateway-install' "
            "in a source checkout) and try again",
        )
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
    try:
        _execv(binary, [binary, *argv])
    except OSError as exc:
        raise click.ClickException(f"could not start {binary}: {exc.strerror or exc}") from exc
    raise SystemExit(0)  # only reached when a test replaces _execv


def _build_command(cmd: _Cmd) -> click.Command:
    params: list[click.Parameter] = [_click_argument(arg) for arg in cmd.args]
    params += [_click_option(flag) for flag in cmd.flags]
    return GatewayCommand(
        cmd.path[-1],
        params=params,
        callback=click.pass_context(_forward),
        help=_help_text(cmd),
        short_help=cmd.short,
        gateway_path=cmd.path,
        no_args_is_help=False,
    )


def _build_group(cmd: _Cmd) -> click.Group:
    return click.Group(cmd.path[-1], help=_help_text(cmd), short_help=cmd.short)


@click.group()
def sandbox() -> None:
    """Run coding agents in NVIDIA OpenShell sandboxes.

    Run Claude Code, Codex and other hooks-only harnesses inside an NVIDIA
    OpenShell sandbox: the agent sees only your project folder (live, with
    secret files masked, git internals read-only and a snapshot for undo),
    reaches the web through DefenseClaw's egress proxy, and every tool call
    still goes through DefenseClaw.

    Start with "defenseclaw sandbox setup", then run "defenseclaw sandbox run
    claude" in a project folder. Linux and macOS only.
    """


def _register(root: click.Group, commands: Sequence[_Cmd]) -> None:
    groups: dict[tuple[str, ...], click.Group] = {(): root}
    for cmd in commands:
        parent = groups[cmd.path[:-1]]
        is_group = any(other.path[:-1] == cmd.path for other in commands)
        node: click.Command = _build_group(cmd) if is_group else _build_command(cmd)
        parent.add_command(node)
        if is_group:
            assert isinstance(node, click.Group)
            groups[cmd.path] = node


_register(sandbox, SANDBOX_COMMANDS)


@sandbox.command("legacy-cleanup")
@click.option("--dry-run", is_flag=True, help="Print the cleanup plan and exact commands; change nothing.")
@click.option("--yes", "-y", is_flag=True, help="Apply the plan without asking for confirmation.")
@click.option(
    "--remove-user",
    is_flag=True,
    help=(
        "Also delete the 'sandbox' user and its home (userdel -r); refused while it has processes or "
        "until its ownership and ACLs are gone from the OpenClaw home."
    ),
)
@click.option(
    "--remove-binary",
    is_flag=True,
    help="Also remove /usr/local/bin/openshell-sandbox when it is a legacy 0.0.x build not owned by a package.",
)
@pass_ctx
def legacy_cleanup(app: AppContext, dry_run: bool, yes: bool, remove_user: bool, remove_binary: bool) -> None:
    """Undo a legacy openshell-sandbox (0.0.x) standalone install (Linux).

    Detects each legacy artifact, prints every step with the exact command it
    runs, and asks before changing anything unless --yes is given. Privileged
    commands run through sudo with binaries resolved only from root-owned
    system directories. Nothing after the systemd units step runs while any
    part of the legacy sandbox is still running. Progress is recorded in
    <data_dir>/legacy-sandbox-cleanup.json, so re-running only does what is
    left.

    \b
    Example:
      defenseclaw sandbox legacy-cleanup --dry-run
      defenseclaw sandbox legacy-cleanup
    """
    from defenseclaw import sandbox_legacy
    from defenseclaw.platform_support import host_os

    if host_os() == "windows":
        raise click.ClickException("sandbox legacy-cleanup is unsupported on native Windows")

    if not app.cfg:
        from defenseclaw.config import load, require_v8_config

        require_v8_config()
        app.cfg = load()
    cfg = app.cfg

    system = sandbox_legacy.System()
    if system.is_root():
        ux.warn(
            "running as root: cleanup reads the root user's DefenseClaw config; "
            "run it as the operator instead (it calls sudo itself)",
        )
    state = sandbox_legacy.detect(cfg, system=system, probe_binary=remove_binary)
    steps = sandbox_legacy.plan(
        state,
        cfg,
        remove_user=remove_user,
        remove_binary=remove_binary,
        system=system,
    )
    extra = sandbox_legacy.hints(state, remove_user=remove_user, remove_binary=remove_binary)

    ux.section("Legacy sandbox cleanup")
    if not steps:
        if not dry_run and sandbox_legacy.complete_idle_receipt(state, system):
            ux.ok("Nothing is left to clean up; the legacy cleanup is complete.")
        else:
            ux.ok("No legacy openshell-sandbox standalone install found; nothing to clean up.")
        for hint in extra:
            ux.subhead(hint, indent="  ")
        return

    result = sandbox_legacy.apply(steps, state, yes=yes, dry_run=dry_run, system=system)
    for hint in extra:
        ux.subhead(hint, indent="  ")
    if dry_run:
        return
    if result.failed:
        raise click.ClickException(
            f"{len(result.failed)} cleanup step(s) failed; fix the reported problem and re-run "
            "'defenseclaw sandbox legacy-cleanup' (completed steps are skipped)",
        )
    click.echo()
    for note in sandbox_legacy.review_notes(state):
        ux.warn(note)
    ux.section("Next steps")
    for index, (why, command) in enumerate(sandbox_legacy.NEXT_STEPS, 1):
        click.echo(f"    {index}. {why}:")
        click.echo(f"       {ux.accent(command)}")
