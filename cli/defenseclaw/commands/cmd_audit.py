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


@click.group("audit")
def audit() -> None:
    """Audit trail helpers (export and activity logging).

    \b
    Export the audit log (incl. per-connector filtering):
        defenseclaw audit export [--connector X]
    It runs 'defenseclaw-gateway audit export' with the same options.
    'log-activity' records operator/config activity.
    """


# Replaced by tests; the real calls replace or wait for this process.
_execv = os.execv
_run = subprocess.run

_GATEWAY_MISSING = (
    "defenseclaw-gateway is not installed; run 'defenseclaw upgrade' (or 'make gateway-install' "
    "in a source checkout) and try again"
)


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


@audit.command("log-activity")
@click.option(
    "--payload-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="JSON payload written by the TUI on config save (before/after snapshots).",
)
@pass_context
def audit_log_activity(app: AppContext, payload_file: Path) -> None:
    """Record a config or operator mutation via Logger.log_activity."""
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
