# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw settings — TUI parity helpers for persisting configuration."""

from __future__ import annotations

import os

import click

from defenseclaw.audit_actions import ACTION_CONFIG_UPDATE
from defenseclaw.context import AppContext, pass_ctx


@click.group("settings")
def settings_cmd() -> None:
    """Operator settings (parity with the TUI setup panel save path)."""


@settings_cmd.command("save")
@pass_ctx
def settings_save(app: AppContext) -> None:
    """Write the current resolved configuration to disk and record an activity event."""
    cfg_path = os.path.join(app.cfg.data_dir, "config.yaml")
    before_txt = ""
    try:
        with open(cfg_path, encoding="utf-8") as f:
            before_txt = f.read()
    except OSError:
        before_txt = ""

    app.cfg.save()

    after_txt = ""
    try:
        with open(cfg_path, encoding="utf-8") as f:
            after_txt = f.read()
    except OSError:
        after_txt = ""

    before = {"config_path": cfg_path, "bytes": len(before_txt)}
    after = {"config_path": cfg_path, "bytes": len(after_txt)}
    diff: list[dict] = []
    if before_txt != after_txt:
        diff.append(
            {
                "path": "/config.yaml",
                "op": "replace",
                "before": f"<{len(before_txt)} bytes>",
                "after": f"<{len(after_txt)} bytes>",
            },
        )
    if app.logger:
        app.logger.log_activity(
            actor="cli:operator",
            action=ACTION_CONFIG_UPDATE,
            target_type="config",
            target_id="config.yaml",
            before=before,
            after=after,
            diff=diff,
        )
    click.echo(f"  ✓ Saved configuration to {cfg_path}")
