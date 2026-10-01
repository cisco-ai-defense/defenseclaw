# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw status` reports the managed_enterprise profile."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from defenseclaw.commands import cmd_status


@pytest.fixture()
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(cmd_status, "config_path", lambda: path)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)
    return path


@pytest.mark.parametrize(
    ("config", "mode", "pin", "platform", "want"),
    [
        # An unmanaged install has no profile, whatever its config says.
        ("config_version: 8\nenterprise:\n  profile: standalone\n", "", "", None, {""}),
        ("config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n", "managed_enterprise", "", None, {"standalone"}),
        # The service pin wins over the config.
        ("config_version: 8\ndeployment_mode: managed_enterprise\n", "managed_enterprise", "Standalone", None, {"standalone"}),
        # Without either, the default follows the platform.
        ("config_version: 8\ndeployment_mode: managed_enterprise\n", "managed_enterprise", "", "linux", {"standalone"}),
        ("config_version: 8\ndeployment_mode: managed_enterprise\n", "managed_enterprise", "", "win32", {"secure_client"}),
        # A malformed config never raises.
        (": : not yaml [\n", "managed_enterprise", "", None, {"standalone", "secure_client"}),
    ],
)
def test_enterprise_profile_resolution(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, config: str, mode: str, pin: str, platform: str | None, want: set[str]
) -> None:
    config_file.write_text(config)
    if pin:
        monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", pin)
    if platform:
        monkeypatch.setattr("sys.platform", platform)
    assert cmd_status._enterprise_profile(SimpleNamespace(deployment_mode=mode)) in want


def _invoke_status(monkeypatch: pytest.MonkeyPatch, config_file: Path, *, profile_text: str, default: str, json_output: bool):
    """Run `defenseclaw status` for a managed_enterprise config with the given per-OS default profile."""

    from click.testing import CliRunner

    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.data_dir = ""
        app.cfg.deployment_mode = "managed_enterprise"
        config_file.write_text("config_version: 8\ndeployment_mode: managed_enterprise\n" + profile_text)
        monkeypatch.setattr(cmd_status, "_default_enterprise_profile", lambda: default)
        monkeypatch.setattr(cmd_status, "_fetch_runtime_bound_health", lambda *_args, **_kwargs: None)
        args = ["--json"] if json_output else []
        result = CliRunner().invoke(cmd_status.status, args, obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        return result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("pin", ["", "secure_client"])
def test_secure_client_status_is_unchanged(config_file: Path, monkeypatch: pytest.MonkeyPatch, pin: str) -> None:
    # A Secure Client config has no enterprise block (macOS and Windows
    # default to secure_client); status prints no Enterprise row and the JSON
    # document has no enterprise_profile key, as before profiles existed.
    if pin:
        monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", pin)
    text = _invoke_status(monkeypatch, config_file, profile_text="", default="secure_client", json_output=False)
    assert "Enterprise" not in text
    assert "managed by your organization" not in text
    import json

    document = json.loads(_invoke_status(monkeypatch, config_file, profile_text="", default="secure_client", json_output=True))
    assert "enterprise_profile" not in document
    assert list(document)[:3] == ["environment", "deployment_mode", "data_dir"]


def test_standalone_status_reports_the_profile(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = "enterprise:\n  profile: standalone\n"
    text = _invoke_status(monkeypatch, config_file, profile_text=profile, default="secure_client", json_output=False)
    assert "standalone (managed by your organization)" in text
    import json

    document = json.loads(_invoke_status(monkeypatch, config_file, profile_text=profile, default="secure_client", json_output=True))
    assert document["enterprise_profile"] == "standalone"
    assert list(document)[:3] == ["environment", "deployment_mode", "enterprise_profile"]
