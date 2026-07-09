# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""D5b — per-connector observability (audit_sinks + webhooks).

Covers the four safety/behaviour properties the feature must hold:

1. Round-trip — per-connector sinks/webhooks survive a Config save/load
   cycle without dropping the global block or other connectors'.
2. Resolution — a connector's events resolve to its per-connector
   sinks/webhooks when set, falling back to the GLOBAL list when unset
   (no silent drop for an unconfigured connector).
3. Byte-stability — a global-only config omits the ``observability:`` key
   entirely; clearing the last per-connector override propagates to disk.
4. CLI — ``setup observability add --connector`` / ``setup webhook add
   --connector`` write under ``observability.connectors[<name>]`` and never
   pollute the global lists; bare (no --connector) stays back-compatible.
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
from defenseclaw.commands.cmd_setup_observability import observability  # noqa: E402
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
        f.write("claw:\n  mode: openclaw\n")
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
                audit_sinks=[{
                    "name": "cx-hec", "kind": "splunk_hec", "enabled": True,
                    "splunk_hec": {"endpoint": "https://h:8088/x", "token_env": "T"},
                }],
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
        assert conns["codex"]["audit_sinks"][0]["name"] == "cx-hec"
        assert conns["codex"]["webhooks"][0]["name"] == "cx-slack"
        # inherit-global dimension (None) is not serialized as null.
        assert "audit_sinks" not in conns["hermes"]
        # webhook omitempty: cooldown_seconds absent.
        assert "cooldown_seconds" not in conns["codex"]["webhooks"][0]

        with patch("defenseclaw.config.default_data_path", return_value=Path(d)):
            loaded = cfg_mod.load()
        cx = loaded.observability.connectors["codex"]
        assert cx.audit_sinks[0]["name"] == "cx-hec"
        assert cx.webhooks[0].name == "cx-slack" and cx.webhooks[0].type == "slack"
        assert loaded.observability.connectors["hermes"].audit_sinks is None


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
# 2. Resolution — override + global fallback (no silent drop)
# ---------------------------------------------------------------------------


def test_resolution_audit_sinks_override_and_fallback():
    obs = ObservabilityConfig(connectors={
        "codex": PerConnectorObservability(audit_sinks=[{"name": "cx-hec"}]),
        # hermes present but only overrides webhooks → sinks inherit global.
        "hermes": PerConnectorObservability(webhooks=[]),
    })
    g = [{"name": "global-hec"}]
    # override
    assert obs.effective_audit_sinks("codex", g)[0]["name"] == "cx-hec"
    # present connector w/ no sink override → global
    assert obs.effective_audit_sinks("hermes", g)[0]["name"] == "global-hec"
    # UNCONFIGURED connector → global (the no-silent-drop safety property)
    assert obs.effective_audit_sinks("unknown", g)[0]["name"] == "global-hec"
    # alias-insensitive lookup (open-hands == openhands)
    obs2 = ObservabilityConfig(connectors={
        "open-hands": PerConnectorObservability(audit_sinks=[{"name": "oh"}]),
    })
    assert obs2.effective_audit_sinks("openhands", g)[0]["name"] == "oh"


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


def test_explicit_empty_override_suppresses_global():
    # An explicit empty list is an override (suppress), distinct from None.
    obs = ObservabilityConfig(connectors={
        "codex": PerConnectorObservability(audit_sinks=[]),
    })
    assert obs.effective_audit_sinks("codex", [{"name": "g"}]) == []
    assert obs.effective_audit_sinks("other", [{"name": "g"}]) == [{"name": "g"}]


# ---------------------------------------------------------------------------
# 3. Byte-stability + clear-persist + validate
# ---------------------------------------------------------------------------


def test_global_only_omits_observability_key():
    with tempfile.TemporaryDirectory() as d:
        cfg = _bare_config(d)
        cfg.save()
        raw = _read_yaml(d)
        assert "observability" not in raw


def test_clearing_last_connector_persists():
    with tempfile.TemporaryDirectory() as d:
        cfg = _bare_config(d)
        cfg.observability.connectors = {
            "codex": PerConnectorObservability(audit_sinks=[{"name": "cx"}]),
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
            "open-hands": PerConnectorObservability(audit_sinks=[]),
            "openhands": PerConnectorObservability(audit_sinks=[]),
        }).validate()


# ---------------------------------------------------------------------------
# 4. CLI — observability
# ---------------------------------------------------------------------------


def _inv(runner, cmd, args, app):
    return runner.invoke(cmd, args, obj=app, catch_exceptions=False)


def test_cli_observability_add_connector_isolates_from_global(ctx):
    app, tmp, runner = ctx
    # global sink (back-compat)
    r = _inv(runner, observability, [
        "add", "splunk-hec", "--non-interactive",
        "--host", "localhost", "--port", "8088", "--token", "G",
    ], app)
    assert r.exit_code == 0, r.output
    # per-connector sink
    r = _inv(runner, observability, [
        "add", "splunk-enterprise", "--non-interactive",
        "--endpoint", "https://splunk.example.com:8088/services/collector/event",
        "--token", "C", "--connector", "codex", "--name", "cx-hec",
    ], app)
    assert r.exit_code == 0, r.output

    raw = _read_yaml(tmp)
    assert [s["name"] for s in raw["audit_sinks"]] == ["splunk-hec-localhost"]
    assert [s["name"] for s in raw["observability"]["connectors"]["codex"]["audit_sinks"]] == ["cx-hec"]
    # secret persisted to .env
    assert "C" in open(os.path.join(tmp, ".env")).read()


def test_cli_observability_connector_rejects_otel_preset(ctx):
    app, _tmp, runner = ctx
    r = _inv(runner, observability, [
        "add", "datadog", "--non-interactive", "--site", "us5",
        "--token", "X", "--connector", "codex",
    ], app)
    assert r.exit_code != 0
    assert "audit_sinks only" in r.output


def test_cli_observability_list_and_remove_connector(ctx):
    app, tmp, runner = ctx
    _inv(runner, observability, [
        "add", "splunk-hec", "--non-interactive", "--host", "h",
        "--port", "8088", "--token", "C", "--connector", "codex", "--name", "cx-hec",
    ], app)
    # unconfigured connector communicates inheritance, never silent-empty
    r = _inv(runner, observability, ["list", "--connector", "hermes"], app)
    assert "inherits the global" in r.output
    # configured connector lists its own sink
    r = _inv(runner, observability, ["list", "--connector", "codex"], app)
    assert "cx-hec" in r.output
    # remove + prune
    r = _inv(runner, observability, ["remove", "cx-hec", "--connector", "codex", "--yes"], app)
    assert r.exit_code == 0, r.output
    assert "observability" not in _read_yaml(tmp)


# ---------------------------------------------------------------------------
# 4. CLI — webhooks
# ---------------------------------------------------------------------------


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
    assert "observability" not in _read_yaml(tmp)
