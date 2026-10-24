# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Old first-run Cursor pins must not become outage choices on upgrade."""

import pytest
import yaml
from defenseclaw.config import load
from defenseclaw.migrations import migrate


@pytest.mark.parametrize("release", ["1.0.0", "1.0.1", "1.0.2", "1.0.3"])
@pytest.mark.parametrize(
    "mode,tier,pin,expected",
    [("observe", "strict", "open", "closed"), ("observe", "default", "open", "open")],
)
@pytest.mark.parametrize("shape", ["global", "connector"])
def test_upgrade_removes_setup_written_cursor_fail_mode(tmp_path, release, mode, tier, pin, expected, shape):
    guardrail = {"mode": mode, "rule_pack": tier}
    if shape == "global":
        guardrail.update({"connector": "cursor", "hook_fail_mode": pin})
    else:
        guardrail["connectors"] = {"cursor": {"hook_fail_mode": pin}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"config_version": 9, "guardrail": guardrail, "observability": {}}), encoding="utf-8")
    result = migrate(str(tmp_path), from_version=release)
    assert result.changed
    saved = yaml.safe_load(path.read_text(encoding="utf-8"))["guardrail"]
    if shape == "global":
        assert "hook_fail_mode" not in saved
    else:
        assert "hook_fail_mode" not in saved["connectors"]["cursor"]
    assert load(data_dir=str(tmp_path)).guardrail.effective_hook_fail_mode("cursor") == expected


@pytest.mark.parametrize("shape", ["global", "connector"])
def test_upgrade_keeps_an_action_mode_closed_cursor_value(tmp_path, shape):
    # No loosening on upgrade: 1.0.x action mode blocked Cursor outages.
    guardrail = {"mode": "action", "rule_pack": "default"}
    if shape == "global":
        guardrail.update({"connector": "cursor", "hook_fail_mode": "closed"})
    else:
        guardrail["connectors"] = {"cursor": {"hook_fail_mode": "closed"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"config_version": 9, "guardrail": guardrail, "observability": {}}), encoding="utf-8")
    migrate(str(tmp_path), from_version="1.0.3")
    assert load(data_dir=str(tmp_path)).guardrail.effective_hook_fail_mode("cursor") == "closed"


def test_upgrade_preserves_non_pin_user_choice(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "config_version: 9\nguardrail: {connector: cursor, mode: observe, rule_pack: strict, hook_fail_mode: closed}\nobservability: {}\n",
        encoding="utf-8",
    )
    migrate(str(tmp_path), from_version="1.0.3")
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["guardrail"]["hook_fail_mode"] == "closed"


@pytest.mark.parametrize("release", ["0.8.10", "1.0.3"])
def test_upgrade_leaves_managed_or_older_cursor_choice_alone(tmp_path, release):
    path = tmp_path / "config.yaml"
    path.write_text(
        "config_version: 9\ndeployment_mode: managed_enterprise\n"
        "enterprise: {profile: standalone}\n"
        "guardrail: {connector: cursor, mode: observe, rule_pack: strict, hook_fail_mode: open}\n"
        "observability: {}\n",
        encoding="utf-8",
    )
    migrate(str(tmp_path), from_version=release)
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["guardrail"]["hook_fail_mode"] == "open"


def test_pre_1_0_upgrade_does_not_drop_existing_cursor_choice(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "config_version: 9\nguardrail: {connector: cursor, mode: observe, rule_pack: strict, hook_fail_mode: open}\n"
        "observability: {}\n",
        encoding="utf-8",
    )
    migrate(str(tmp_path), from_version="0.8.10")
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["guardrail"]["hook_fail_mode"] == "open"
