# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Audit helpers — operator activity logging for TUI and automation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_CONFIG_UPDATE, is_known_action
from defenseclaw.context import AppContext, pass_context
from defenseclaw.gateway import GATEWAY_NOT_FOUND_MESSAGE


@click.group("audit")
def audit() -> None:
    """Audit trail helpers: export, findings and gateway logs.

    \b
    Export the audit log, config changes included (action config-update):
        defenseclaw audit export [--connector X] [--since 1h]
    Report the current distinct skill/MCP/plugin/code scan findings (JSON):
        defenseclaw audit findings [--scanner NAME] [--since 30m]
    'export' and 'findings' run 'defenseclaw-gateway audit <command>' with the
    same options. Show the newest gateway or watchdog log lines:
        defenseclaw audit logs [--source watchdog] [-n 50] [--grep TEXT]
    """


# Replaced by tests; the real calls replace or wait for this process.
_execv = os.execv
_run = subprocess.run

_GATEWAY_MISSING = GATEWAY_NOT_FOUND_MESSAGE


def run_gateway(argv: Sequence[str]) -> NoReturn:
    """Run ``defenseclaw-gateway <argv>`` and exit with its status."""
    from defenseclaw.file_permissions import UnsafePathError
    from defenseclaw.gateway import resolve_trusted_gateway_binary

    try:
        binary = resolve_trusted_gateway_binary()
    except UnsafePathError as exc:
        raise click.ClickException(str(exc)) from exc
    if not binary:
        raise click.ClickException(_GATEWAY_MISSING)
    # Usage errors then name 'defenseclaw audit ...', the command the user
    # typed, instead of 'defenseclaw-gateway audit ...' (GAP-1644).
    os.environ["DEFENSECLAW_DELEGATED_FROM"] = "defenseclaw"
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
    try:
        if os.name == "nt":
            # Windows has no exec: os.execv starts a new process and exits
            # this one, so the console would get the prompt back early.
            raise SystemExit(_run([binary, *argv], check=False).returncode)
        _execv(binary, [binary, *argv])
    except OSError as exc:
        raise click.ClickException(f"could not start {binary}: {exc.strerror or exc}") from exc
    raise SystemExit(0)  # only reached when a test replaces _execv


@audit.command(
    "export",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    add_help_option=False,
)
@click.argument("gateway_args", nargs=-1, type=click.UNPROCESSED)
def audit_export(gateway_args: tuple[str, ...]) -> None:
    """Export the audit log as JSONL (runs 'defenseclaw-gateway audit export').

    Every argument goes to 'defenseclaw-gateway audit export'; see
    'defenseclaw audit export --help' for its options.
    """
    run_gateway(("audit", "export", *gateway_args))


@audit.command(
    "findings",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
    add_help_option=False,
)
@click.argument("gateway_args", nargs=-1, type=click.UNPROCESSED)
def audit_findings(gateway_args: tuple[str, ...]) -> None:
    """Report distinct current scan findings (runs 'defenseclaw-gateway audit findings').

    Every argument goes to 'defenseclaw-gateway audit findings'; see
    'defenseclaw audit findings --help' for its options.
    """
    run_gateway(("audit", "findings", *gateway_args))


_LOG_FILES = {"gateway": "gateway.log", "watchdog": "watchdog.log"}


@audit.command("logs")
@click.option(
    "--source",
    type=click.Choice(sorted(_LOG_FILES)),
    default="gateway",
    show_default=True,
    help="Which log to read.",
)
@click.option("-n", "--lines", "line_count", type=click.IntRange(1, 5000), default=50, show_default=True,
              help="Number of newest lines to show.")
@click.option("--grep", "pattern", default=None, help="Only lines containing this text (case-insensitive).")
@pass_context
def audit_logs(app: AppContext, source: str, line_count: int, pattern: str | None) -> None:
    """Show the newest lines of the gateway or watchdog log (as the TUI Logs panel does)."""
    path = Path(app.cfg.data_dir) / _LOG_FILES[source]
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            start = max(0, fh.tell() - 1024 * 1024)
            fh.seek(start)
            text = fh.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        raise click.ClickException(
            f"no {source} log yet at {path}; start the gateway with 'defenseclaw-gateway start'"
        ) from None
    except OSError as exc:
        raise click.ClickException(f"could not read {path}: {exc.strerror or exc}") from exc
    lines = text.splitlines()
    if start and lines:
        lines = lines[1:]  # drop the partial first line of the window
    if pattern:
        needle = pattern.lower()
        lines = [line for line in lines if needle in line.lower()]
        if not lines:
            # GAP-1494: an empty match used to print nothing at all.
            click.echo(
                f"No {source} log lines match {pattern!r} in {path} "
                "(searched the newest 1 MiB).",
                err=True,
            )
            return
    for line in lines[-line_count:]:
        click.echo(line)


# Internal helper (it used to back TUI config saves); hidden from --help.
@audit.command("log-activity", hidden=True)
@click.option(
    "--payload-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="JSON file with the change: action, target and before/after snapshots.",
)
@pass_context
def audit_log_activity(app: AppContext, payload_file: Path) -> None:
    """Record a config change from a JSON payload as an audit event (internal)."""
    raw = payload_file.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"invalid JSON payload: {exc}") from exc

    logger = getattr(app, "logger", None)
    if logger is None:
        raise click.ClickException("logger unavailable — run via defenseclaw with store loaded")

    # Reject unknown actions from the untrusted payload so bogus values
    # never reach audit_events / activity_events and break SIEM group-by
    # or downstream schema validation. Empty/missing action falls back
    # to the default, which is a registered constant.
    action = str(data.get("action") or ACTION_CONFIG_UPDATE)
    if not is_known_action(action):
        raise click.ClickException(
            f"unknown audit action {action!r}; "
            "add the constant to defenseclaw.audit_actions and internal/audit/actions.go first",
        )

    logger.log_activity(
        actor=str(data.get("actor") or "cli"),
        action=action,
        target_type=str(data.get("target_type") or "config"),
        target_id=str(data.get("target_id") or "config.yaml"),
        before=data.get("before"),
        after=data.get("after"),
        diff=data.get("diff"),
        version_from=str(data.get("version_from") or ""),
        version_to=str(data.get("version_to") or ""),
        severity=str(data.get("severity") or "INFO"),
    )
    click.echo(ux._style("activity logged", fg="green"), file=sys.stderr)
