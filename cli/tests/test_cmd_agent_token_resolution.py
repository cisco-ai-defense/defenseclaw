"""Regressions for `_resolve_gateway_target` token-precedence ladder.

Phase 2 of the gateway-token rebranding fix
(`DEFENSECLAW_GATEWAY_TOKEN` becomes canonical, `OPENCLAW_GATEWAY_TOKEN`
remains as a back-compat shim). These tests lock in:

* Operator-supplied `--gateway-token-env` wins absolutely (even over
  a populated DEFENSECLAW_/OPENCLAW_ var).
* Falls through to ``cfg.gateway.resolved_token()`` when the CLI
  flag is absent — keeps the per-call path symmetric with the
  config-object ladder validated in `test_config.py`.
* Last-resort env probe catches the no-config case (early-boot
  smoke tests, doctor pre-config) so the same dev-friendly behaviour
  works without a Config instance.
* DEFENSECLAW_ wins over OPENCLAW_ at every level — no scenario
  should silently route through the legacy var when the new one is
  present.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from defenseclaw.commands.cmd_agent import _resolve_gateway_target


_GATEWAY_VARS = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN", "MY_TOK")


def _clean_env(**overrides: str) -> dict[str, str]:
    """Build a baseline env without leaking the dev's local gateway vars."""
    env = {k: v for k, v in os.environ.items() if k not in _GATEWAY_VARS}
    env.update(overrides)
    return env


class _StubGateway:
    """Minimal stub matching the GatewayConfig surface we touch."""

    def __init__(self, *, host: str = "127.0.0.1", api_port: int = 18970, token_env: str = "", token: str = ""):
        self.host = host
        self.api_port = api_port
        self.token_env = token_env
        self.token = token

    def resolved_token(self) -> str:
        # Re-implement the production logic here so we can test the
        # resolver in isolation without pulling the whole Config
        # dataclass tree into the test fixture.
        if self.token_env:
            val = os.environ.get(self.token_env, "")
            if val:
                return val
        val = os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", "")
        if val:
            return val
        val = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
        if val:
            return val
        return self.token


class _StubAppContext:
    def __init__(self, gw: _StubGateway | None):
        if gw is None:
            self.cfg = None
        else:
            self.cfg = type("Cfg", (), {"gateway": gw})()


def test_cli_token_env_override_wins_absolutely():
    """`--gateway-token-env=MY_TOK` beats both DEFENSECLAW_ and OPENCLAW_."""
    env = _clean_env(
        MY_TOK="cli-override-tok",
        DEFENSECLAW_GATEWAY_TOKEN="dc-tok",
        OPENCLAW_GATEWAY_TOKEN="oc-tok",
    )
    with patch.dict(os.environ, env, clear=True):
        host, port, token = _resolve_gateway_target(
            _StubAppContext(_StubGateway()),
            gateway_host=None,
            gateway_port=None,
            gateway_token_env="MY_TOK",
        )
    assert token == "cli-override-tok"


def test_falls_through_to_defenseclaw_when_cli_override_unset():
    """No CLI override + DEFENSECLAW_GATEWAY_TOKEN present → use it.

    The user's bug-report case: cfg.gateway.token_env defaults to
    `OPENCLAW_GATEWAY_TOKEN` (legacy), that env var is unset, but the
    Go gateway wrote `DEFENSECLAW_GATEWAY_TOKEN` to the dotenv. The
    resolver must auto-pick that up instead of returning "".
    """
    env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="dc-tok")
    with patch.dict(os.environ, env, clear=True):
        host, port, token = _resolve_gateway_target(
            _StubAppContext(_StubGateway(token_env="OPENCLAW_GATEWAY_TOKEN")),
            gateway_host=None,
            gateway_port=None,
            gateway_token_env=None,
        )
    assert token == "dc-tok"


def test_defenseclaw_wins_over_openclaw_when_both_set():
    """Belt-and-suspenders: even with both vars set, prefer DEFENSECLAW_."""
    env = _clean_env(
        DEFENSECLAW_GATEWAY_TOKEN="dc-tok",
        OPENCLAW_GATEWAY_TOKEN="oc-tok",
    )
    with patch.dict(os.environ, env, clear=True):
        _, _, token = _resolve_gateway_target(
            _StubAppContext(_StubGateway()),
            gateway_host=None,
            gateway_port=None,
            gateway_token_env=None,
        )
    assert token == "dc-tok"


def test_legacy_openclaw_still_works_for_upgraders():
    """When DEFENSECLAW_ is absent, OPENCLAW_ still resolves."""
    env = _clean_env(OPENCLAW_GATEWAY_TOKEN="legacy-tok")
    with patch.dict(os.environ, env, clear=True):
        _, _, token = _resolve_gateway_target(
            _StubAppContext(_StubGateway()),
            gateway_host=None,
            gateway_port=None,
            gateway_token_env=None,
        )
    assert token == "legacy-tok"


def test_no_config_no_env_returns_empty():
    """No Config, no env vars → empty token. Callers raise the friendly error.

    Note: we patch ``defenseclaw.config.load`` because the resolver
    falls through to loading the real config when ``app.cfg is None``
    — and the dev's actual ``~/.defenseclaw/config.yaml`` would
    otherwise return a real token from their dotenv, making this
    assertion silently false.
    """
    env = _clean_env()
    with patch.dict(os.environ, env, clear=True), patch(
        "defenseclaw.config.load", side_effect=Exception("test: no config")
    ):
        host, port, token = _resolve_gateway_target(
            _StubAppContext(None),
            gateway_host=None,
            gateway_port=None,
            gateway_token_env=None,
        )
    assert token == ""
    # Defaults still flow through so callers get usable host/port.
    assert host == "127.0.0.1"
    assert port == 18970


def test_no_config_with_defenseclaw_env_uses_env():
    """Early-boot case (no Config yet): env var alone is enough.

    Mirrors the doctor pre-config codepath — without a loaded config
    the resolver still needs to pick up DEFENSECLAW_ from os.environ
    so token-dependent doctor checks can run.
    """
    env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="dc-tok-from-env")
    with patch.dict(os.environ, env, clear=True), patch(
        "defenseclaw.config.load", side_effect=Exception("test: no config")
    ):
        _, _, token = _resolve_gateway_target(
            _StubAppContext(None),
            gateway_host=None,
            gateway_port=None,
            gateway_token_env=None,
        )
    assert token == "dc-tok-from-env"


def test_fresh_install_defaults_use_defenseclaw_env_name():
    """Phase 3 contract: `_setup_gateway_defaults` writes the new env name.

    Locks in that a non-OpenClaw fresh install ends with
    ``cfg.gateway.token_env == "DEFENSECLAW_GATEWAY_TOKEN"`` (matches
    what the Go gateway writes on first boot), not the legacy
    ``OPENCLAW_GATEWAY_TOKEN`` default that bit the user.

    Mocks ``_resolve_gateway_for_connector`` to return no token so we
    hit the else-branch — the only branch that controls the default.
    """
    from unittest.mock import MagicMock

    from defenseclaw.commands.cmd_init import _setup_gateway_defaults

    cfg = MagicMock()
    cfg.guardrail.connector = "defenseclaw"
    cfg.gateway.host = ""
    cfg.gateway.port = 0
    cfg.gateway.token_env = ""  # Simulate fresh install — nothing set yet.
    cfg.gateway.api_port = 18970
    cfg.gateway.watcher.enabled = False
    cfg.gateway.watcher.skill.enabled = False
    cfg.gateway.watcher.skill.take_action = False
    cfg.gateway.watcher.plugin.enabled = False
    cfg.gateway.watcher.plugin.take_action = False
    cfg.gateway.watcher.plugin.dirs = []
    cfg.gateway.device_key_file = "/tmp/test-device.key"
    cfg.gateway.resolved_token.return_value = ""
    cfg.ai_discovery.enabled = False
    cfg.ai_discovery.mode = "off"
    cfg.plugin_dirs.return_value = []

    logger = MagicMock()

    with patch(
        "defenseclaw.commands.cmd_init._resolve_gateway_for_connector",
        return_value={"host": "127.0.0.1", "port": 18789, "token": ""},
    ), patch("defenseclaw.commands.cmd_init._ensure_device_key"):
        _setup_gateway_defaults(cfg, logger, is_new_config=True)

    assert cfg.gateway.token_env == "DEFENSECLAW_GATEWAY_TOKEN", (
        "Fresh install should default token_env to DEFENSECLAW_GATEWAY_TOKEN "
        "(matches the Go gateway's first-boot write). Got: "
        f"{cfg.gateway.token_env!r}"
    )


def test_operator_set_token_env_is_preserved_on_init():
    """`_setup_gateway_defaults` must not stomp an operator-pinned token_env.

    If the user has already run `defenseclaw setup gateway` and pinned
    a custom env var, re-running init must NOT silently rewrite it
    to the default. The `or` short-circuit in the else branch is the
    guard; this test makes the contract explicit.
    """
    from unittest.mock import MagicMock

    from defenseclaw.commands.cmd_init import _setup_gateway_defaults

    cfg = MagicMock()
    cfg.guardrail.connector = "defenseclaw"
    cfg.gateway.host = ""
    cfg.gateway.port = 0
    cfg.gateway.token_env = "MY_CUSTOM_TOKEN_ENV"  # Operator override.
    cfg.gateway.api_port = 18970
    cfg.gateway.watcher.enabled = False
    cfg.gateway.watcher.skill.enabled = False
    cfg.gateway.watcher.skill.take_action = False
    cfg.gateway.watcher.plugin.enabled = False
    cfg.gateway.watcher.plugin.take_action = False
    cfg.gateway.watcher.plugin.dirs = []
    cfg.gateway.device_key_file = "/tmp/test-device.key"
    cfg.gateway.resolved_token.return_value = ""
    cfg.ai_discovery.enabled = False
    cfg.ai_discovery.mode = "off"
    cfg.plugin_dirs.return_value = []

    logger = MagicMock()

    with patch(
        "defenseclaw.commands.cmd_init._resolve_gateway_for_connector",
        return_value={"host": "127.0.0.1", "port": 18789, "token": ""},
    ), patch("defenseclaw.commands.cmd_init._ensure_device_key"):
        _setup_gateway_defaults(cfg, logger, is_new_config=True)

    assert cfg.gateway.token_env == "MY_CUSTOM_TOKEN_ENV", (
        "Operator-pinned token_env must survive re-running init. "
        f"Got: {cfg.gateway.token_env!r}"
    )


def test_cli_host_port_override_wins_over_config():
    """Sanity: --gateway-host / --gateway-port still take precedence.

    Not strictly token-related, but documenting the contract while
    we're here — the resolver should let an operator override host
    or port without touching the token path.
    """
    env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="dc-tok")
    with patch.dict(os.environ, env, clear=True):
        host, port, token = _resolve_gateway_target(
            _StubAppContext(_StubGateway(host="10.0.0.1", api_port=9999)),
            gateway_host="192.168.1.42",
            gateway_port=12345,
            gateway_token_env=None,
        )
    assert host == "192.168.1.42"
    assert port == 12345
    assert token == "dc-tok"
