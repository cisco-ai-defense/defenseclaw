#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from copy import deepcopy
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.notification_capabilities import desktop_notification_capability

from tests.helpers import cleanup_app, make_app_context


def test_desktop_notification_capability_matrix() -> None:
    for system, supported, provider in (
        ("Darwin", True, "osascript"),
        ("Linux", True, "notify-send"),
        ("Windows", True, "Shell_NotifyIconW"),
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


def _reload_windows_config(config_path: str, data_dir: str):
    with (
        patch.dict(
            os.environ,
            {"DEFENSECLAW_CONFIG": config_path, "DEFENSECLAW_HOME": data_dir},
        ),
        patch("defenseclaw.config.platform.system", return_value="Windows"),
    ):
        return config_module.load()


def test_windows_status_reports_enabled_as_active_and_preserves_file() -> None:
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
        assert "ACTIVE" in result.output
        assert "UNSUPPORTED" not in result.output
        assert open(app.cfg.config_path, "rb").read() == before
        assert app.cfg.notifications.enabled is True
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_status_reports_disabled_as_inactive() -> None:
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
        assert "UNSUPPORTED" not in result.output
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_enable_succeeds_without_restart() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"):
            app.cfg.save()
            before = open(app.cfg.config_path, "rb").read()
            result, restart = _invoke(app, "notifications", "on", "--no-restart")

        assert result.exit_code == 0, result.output
        assert app.cfg.notifications.enabled is True
        assert open(app.cfg.config_path, "rb").read() != before
        assert _reload_windows_config(app.cfg.config_path, tmp_dir).notifications.enabled is True
        restart.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_windows_onboarding_yes_enables_without_traceback() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.notifications.enabled = False
        with patch("defenseclaw.notification_capabilities.platform.system", return_value="Windows"):
            app.cfg.save()
            before = open(app.cfg.config_path, "rb").read()
            result, restart = _invoke(app, "notifications", "--yes", "--no-restart")
        assert result.exit_code == 0, result.output
        assert "Traceback" not in result.output
        assert app.cfg.notifications.enabled is True
        assert open(app.cfg.config_path, "rb").read() != before
        assert _reload_windows_config(app.cfg.config_path, tmp_dir).notifications.enabled is True
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
