# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-connector notification compatibility under canonical v8 observability.

Covers the four safety/behaviour properties the feature must hold:

1. Webhook overrides round-trip without replacing the v8 routing graph.
2. Notification resolution falls back to the global list when unset.
3. A global-only v8 config retains the required empty observability mapping;
   clearing the last connector override propagates to disk.
4. ``setup webhook --connector`` writes only the notification compatibility
   child.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import config as cfg_mod  # noqa: E402
from defenseclaw.commands.cmd_setup_webhook import webhook  # noqa: E402
from defenseclaw.config import (  # noqa: E402
    Config,
    ObservabilityConfig,
    PerConnectorObservability,
    WebhookConfig,
)
from defenseclaw.context import AppContext  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bare_config(data_dir: str) -> Config:
    return Config(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, "audit.db"),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        environment="linux",
    )


def _read_yaml(data_dir: str) -> dict:
    with open(os.path.join(data_dir, "config.yaml")) as f:
        return yaml.safe_load(f) or {}


@pytest.fixture()
def ctx():
    """Fresh AppContext rooted at a temp DEFENSECLAW_HOME (restored after)."""
    prev = os.environ.get("DEFENSECLAW_HOME")
    tmp = tempfile.mkdtemp(prefix="dclaw-obs-conn-")
    with open(os.path.join(tmp, "config.yaml"), "w") as f:
        f.write("config_version: 8\nobservability: {}\nclaw:\n  mode: openclaw\n")
    os.environ["DEFENSECLAW_HOME"] = tmp
    app = AppContext()
    app.cfg = cfg_mod.load()
    try:
        yield app, tmp, CliRunner()
    finally:
        if prev is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = prev


# ---------------------------------------------------------------------------
# 1. Round-trip
# ---------------------------------------------------------------------------


def test_per_connector_observability_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        cfg = _bare_config(d)
        cfg.observability.connectors = {
            "codex": PerConnectorObservability(
                webhooks=[WebhookConfig(
                    name="cx-slack", type="slack",
                    url="https://hooks.slack.com/services/A/B/C", enabled=True,
                )],
            ),
            # hermes overrides webhooks only → must INHERIT global sinks.
            "hermes": PerConnectorObservability(
                webhooks=[WebhookConfig(
                    name="h-pd", type="pagerduty",
                    url="https://events.pagerduty.com/v2/enqueue",
                    secret_env="PD", enabled=True,
                )],
            ),
        }
        cfg.save()

        raw = _read_yaml(d)
        conns = raw["observability"]["connectors"]
        assert conns["codex"]["webhooks"][0]["name"] == "cx-slack"
        # webhook omitempty: cooldown_seconds absent.
        assert "cooldown_seconds" not in conns["codex"]["webhooks"][0]

        with patch("defenseclaw.config.default_data_path", return_value=Path(d)):
            loaded = cfg_mod.load()
        cx = loaded.observability.connectors["codex"]
        assert cx.webhooks[0].name == "cx-slack" and cx.webhooks[0].type == "slack"


def test_save_preserves_global_and_other_connectors():
    # Saving a NEW connector must not drop the global lists or a sibling.
    with tempfile.TemporaryDirectory() as d:
        cfg = _bare_config(d)
        cfg.webhooks = [WebhookConfig(
            name="global-slack", type="slack",
            url="https://hooks.slack.com/services/G/L/B", enabled=True,
        )]
        cfg.observability.connectors = {
            "codex": PerConnectorObservability(
                webhooks=[WebhookConfig(
                    name="cx", type="slack",
                    url="https://hooks.slack.com/services/C/X/1", enabled=True,
                )],
            ),
        }
        cfg.save()
        # add hermes via a fresh load + save (simulates a later session).
        with patch("defenseclaw.config.default_data_path", return_value=Path(d)):
            loaded = cfg_mod.load()
        loaded.observability.connectors["hermes"] = PerConnectorObservability(
            webhooks=[WebhookConfig(
                name="h", type="slack",
                url="https://hooks.slack.com/services/H/E/2", enabled=True,
            )],
        )
        loaded.save()

        raw = _read_yaml(d)
        assert [w["name"] for w in raw["webhooks"]] == ["global-slack"]
        assert set(raw["observability"]["connectors"]) == {"codex", "hermes"}


# ---------------------------------------------------------------------------
# 2. Notification resolution — override + global fallback (no silent drop)
# ---------------------------------------------------------------------------


def test_resolution_webhooks_override_and_fallback():
    gw = [WebhookConfig(name="global-wh")]
    cfg = _bare_config("/tmp/x")
    cfg.webhooks = gw
    cfg.observability.connectors = {
        "codex": PerConnectorObservability(
            webhooks=[WebhookConfig(name="cx-wh")],
        ),
    }
    assert cfg.effective_webhooks("codex")[0].name == "cx-wh"
    # unconfigured → global (no silent drop)
    assert cfg.effective_webhooks("hermes")[0].name == "global-wh"
    assert cfg.effective_webhooks("")[0].name == "global-wh"


# ---------------------------------------------------------------------------
# 3. Byte-stability + clear-persist + validate
# ---------------------------------------------------------------------------


def test_global_only_retains_required_observability_mapping():
    with tempfile.TemporaryDirectory() as d:
        cfg = _bare_config(d)
        cfg.save()
        raw = _read_yaml(d)
        assert raw["observability"] == {}


def test_clearing_last_connector_persists():
    with tempfile.TemporaryDirectory() as d:
        cfg = _bare_config(d)
        cfg.observability.connectors = {
            "codex": PerConnectorObservability(
                webhooks=[WebhookConfig(
                    name="cx", type="slack",
                    url="https://hooks.slack.com/services/C/X/1", enabled=True,
                )],
            ),
        }
        cfg.save()
        assert "observability" in _read_yaml(d)
        with patch("defenseclaw.config.default_data_path", return_value=Path(d)):
            loaded = cfg_mod.load()
        loaded.observability.connectors.clear()
        loaded.save()
        raw = _read_yaml(d)
        # authoritative atomic-replace clears the on-disk connectors.
        assert not raw.get("observability", {}).get("connectors")


def test_validate_rejects_empty_and_duplicate_connector_names():
    with pytest.raises(ValueError):
        ObservabilityConfig(connectors={"": PerConnectorObservability()}).validate()
    with pytest.raises(ValueError):
        ObservabilityConfig(connectors={
            "open-hands": PerConnectorObservability(webhooks=[]),
            "openhands": PerConnectorObservability(webhooks=[]),
        }).validate()


# ---------------------------------------------------------------------------
# 4. CLI — webhooks
# ---------------------------------------------------------------------------


def _inv(runner, cmd, args, app):
    return runner.invoke(cmd, args, obj=app, catch_exceptions=False)


def test_cli_webhook_add_connector_isolates_from_global(ctx):
    app, tmp, runner = ctx
    r = _inv(runner, webhook, [
        "add", "slack", "--non-interactive",
        "--url", "https://hooks.slack.com/services/G/L/B",
    ], app)
    assert r.exit_code == 0, r.output
    r = _inv(runner, webhook, [
        "add", "slack", "--non-interactive",
        "--url", "https://hooks.slack.com/services/C/X/1",
        "--connector", "codex", "--name", "cx-slack",
    ], app)
    assert r.exit_code == 0, r.output

    raw = _read_yaml(tmp)
    assert "cx-slack" not in [w["name"] for w in raw["webhooks"]]
    assert [w["name"] for w in raw["observability"]["connectors"]["codex"]["webhooks"]] == ["cx-slack"]


def test_cli_webhook_connector_validation_reused(ctx):
    # The writer's SSRF guard must still reject a private URL on the
    # per-connector path (validation reused from apply_webhook).
    app, _tmp, runner = ctx
    r = runner.invoke(webhook, [
        "add", "slack", "--non-interactive",
        "--url", "https://10.0.0.5/hook", "--connector", "codex",
    ], obj=app, catch_exceptions=False)
    assert r.exit_code != 0
    assert "private" in r.output.lower() or "ssrf" in r.output.lower()


def test_cli_webhook_list_disable_remove_connector(ctx):
    app, tmp, runner = ctx
    _inv(runner, webhook, [
        "add", "slack", "--non-interactive",
        "--url", "https://hooks.slack.com/services/C/X/1",
        "--connector", "codex", "--name", "cx-slack",
    ], app)
    r = _inv(runner, webhook, ["list", "--connector", "hermes"], app)
    assert "inherits the global" in r.output
    r = _inv(runner, webhook, ["disable", "cx-slack", "--connector", "codex"], app)
    assert r.exit_code == 0, r.output
    raw = _read_yaml(tmp)
    assert raw["observability"]["connectors"]["codex"]["webhooks"][0]["enabled"] is False
    r = _inv(runner, webhook, ["remove", "cx-slack", "--connector", "codex", "--yes"], app)
    assert r.exit_code == 0, r.output
    assert not _read_yaml(tmp).get("observability", {}).get("connectors")
