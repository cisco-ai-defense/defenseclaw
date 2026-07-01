# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw settings — TUI parity helpers for persisting configuration."""

from __future__ import annotations

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_CONFIG_UPDATE
from defenseclaw.config import config_path_for_data_dir
from defenseclaw.context import AppContext, pass_ctx


@click.group("settings")
def settings_cmd() -> None:
    """Operator settings (parity with the TUI setup panel save path)."""


@settings_cmd.command("save")
@pass_ctx
def settings_save(app: AppContext) -> None:
    """Write the current resolved configuration to disk and record an activity event."""
    cfg_path = str(config_path_for_data_dir(app.cfg.data_dir))
    before_txt = ""
    try:
        with open(cfg_path, encoding="utf-8") as f:
            before_txt = f.read()
    except OSError:
        before_txt = ""

    try:
        app.cfg.save()
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}")
        raise SystemExit(1) from exc

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
    ux.ok(f"Saved configuration to {cfg_path}")
