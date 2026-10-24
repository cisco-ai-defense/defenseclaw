# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A saved Cursor fail mode survives an upgrade; an ambiguous 1.0.x open is named."""

import pytest
import yaml
from defenseclaw.config import load
from defenseclaw.migrations import migrate


@pytest.mark.parametrize("release", ["1.0.0", "1.0.1", "1.0.2", "1.0.3"])
@pytest.mark.parametrize("tier", ["strict", "default"])
@pytest.mark.parametrize("shape", ["global", "connector"])
def test_upgrade_keeps_a_cursor_open_it_cannot_attribute(tmp_path, capsys, release, tier, shape):
    # 1.0.x setup wrote open for an observe Cursor, and `guardrail fail-mode
    # open` or `config set` wrote the same bytes. The upgrade does not guess:
    # the value stays (1.0.x failed open here, strict included) and the
    # migration names the command that lets the policy tier decide.
    guardrail = {"mode": "observe", "rule_pack": tier}
    if shape == "global":
        guardrail.update({"connector": "cursor", "hook_fail_mode": "open"})
        key = "guardrail.hook_fail_mode"
    else:
        guardrail["connectors"] = {"cursor": {"hook_fail_mode": "open"}}
        key = "guardrail.connectors.cursor.hook_fail_mode"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"config_version": 9, "guardrail": guardrail, "observability": {}}), encoding="utf-8")
    result = migrate(str(tmp_path), from_version=release)
    assert not result.changed
    saved = yaml.safe_load(path.read_text(encoding="utf-8"))["guardrail"]
    assert (saved if shape == "global" else saved["connectors"]["cursor"])["hook_fail_mode"] == "open"
    assert load(data_dir=str(tmp_path)).guardrail.effective_hook_fail_mode("cursor") == "open"
    out = capsys.readouterr()
    assert f"defenseclaw config unset {key}" in out.out + out.err


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
