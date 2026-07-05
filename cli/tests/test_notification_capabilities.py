#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from copy import deepcopy
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.notification_capabilities import desktop_notification_capability

from tests.helpers import cleanup_app, make_app_context


def test_desktop_notification_capability_matrix() -> None:
    for system, supported, provider in (
        ("Darwin", True, "osascript"),
        ("Linux", True, "notify-send"),
        ("Windows", False, ""),
        ("Plan9", False, ""),
    ):
        capability = desktop_notification_capability(system)
        assert capability.supported is supported
        assert capability.provider == provider
        assert capability.effective_enabled(True) is supported
        assert capability.effective_enabled(False) is False


def _invoke(app, *args: str):
    with patch("defenseclaw.commands.cmd_setup._restart_services") as restart:
        result = CliRunner().invoke(setup_group, list(args), obj=app)
    return result, restart


def test_windows_status_reports_legacy_enabled_as_inactive_and_preserves_file() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = True
        app.cfg.save()
        before = open(app.cfg.config_path, "rb").read()

        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"):
            result, restart = _invoke(app, "notifications", "status")

        assert result.exit_code == 0, result.output
        assert "configured (notifications.enabled):" in result.output
        assert "ON" in result.output
        assert "native desktop delivery:" in result.output
        assert "INACTIVE" in result.output
        assert "UNSUPPORTED" in result.output
        assert "ACTIVE" not in result.output.replace("INACTIVE", "")
        assert open(app.cfg.config_path, "rb").read() == before
        assert app.cfg.notifications.enabled is True
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_status_reports_disabled_or_missing_default_as_inactive() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"):
            result, restart = _invoke(app, "notifications", "status")
        assert result.exit_code == 0, result.output
        assert "configured (notifications.enabled):" in result.output
        assert "OFF" in result.output
        assert "INACTIVE" in result.output
        assert "UNSUPPORTED" in result.output
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_enable_rejected_without_mutation_save_restart_or_audit() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        app.cfg.notifications.block_would_block = True
        app.cfg.save()
        before_bytes = open(app.cfg.config_path, "rb").read()
        before_notifications = deepcopy(app.cfg.notifications)
        before_webhooks = deepcopy(app.cfg.webhooks)

        with (
            patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"),
            patch.object(app.cfg, "save", wraps=app.cfg.save) as save,
            patch.object(app.logger, "log_action", wraps=app.logger.log_action) as log_action,
        ):
            result, restart = _invoke(app, "notifications", "on", "--yes")

        assert result.exit_code != 0
        assert "unsupported" in result.output.lower()
        assert app.cfg.notifications == before_notifications
        assert app.cfg.webhooks == before_webhooks
        assert open(app.cfg.config_path, "rb").read() == before_bytes
        save.assert_not_called()
        restart.assert_not_called()
        log_action.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_onboarding_enable_is_rejected_without_prompt_or_traceback() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"):
            result, restart = _invoke(app, "notifications", "--yes")
        assert result.exit_code != 0
        assert "unsupported" in result.output.lower()
        assert "Show desktop notifications" not in result.output
        assert "Traceback" not in result.output
        assert app.cfg.notifications.enabled is False
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_off_clears_only_legacy_master_switch() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = True
        app.cfg.notifications.block_would_block = True
        before_webhooks = deepcopy(app.cfg.webhooks)
        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"):
            result, restart = _invoke(app, "notifications", "off", "--no-restart")
        assert result.exit_code == 0, result.output
        assert app.cfg.notifications.enabled is False
        assert app.cfg.notifications.block_would_block is True
        assert app.cfg.webhooks == before_webhooks
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_supported_platform_enable_still_works() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Linux"):
            result, restart = _invoke(app, "notifications", "on", "--no-restart")
        assert result.exit_code == 0, result.output
        assert app.cfg.notifications.enabled is True
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_save_failure_rolls_back_in_memory_enable() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        with (
            patch("defenseclaw.notification_capabilities.platform.system", return_value="Linux"),
            patch.object(app.cfg, "save", side_effect=OSError("disk full")),
        ):
            result, restart = _invoke(app, "notifications", "on", "--no-restart")
        assert result.exit_code != 0
        assert "config save failed" in result.output
        assert app.cfg.notifications.enabled is False
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)
