# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Upgrade from 1.0.8 / 1.0.9: the OpenClaw token stops being the DefenseClaw master (R-TOK).

Those releases saved the OpenClaw gateway.auth.token as OPENCLAW_GATEWAY_TOKEN
with gateway.token_env naming it, and setup openclaw copied it under both
gateway-token names. ``defenseclaw migrate`` (run by every upgrade) now keeps
OPENCLAW_GATEWAY_TOKEN for the OpenClaw connection, mints a separate
DEFENSECLAW_GATEWAY_TOKEN and repoints token_env.
"""

from __future__ import annotations

import json
import os
import re

import pytest
import yaml
from defenseclaw import config as config_module
from defenseclaw import credential_provenance
from defenseclaw.migrations import _GATEWAY_TOKEN_SPLIT_STEP_NAME, _gateway_token_split_pending, migrate

NAMES = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_DEPLOYMENT_MODE")
X = "openclaw-side-token-x"
MARKER = "# defenseclaw: adopted gateway token sha256=0000"
MINTED = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    credential_provenance._reset_for_tests()
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    yield
    for name in NAMES:
        os.environ.pop(name, None)
    credential_provenance._reset_for_tests()


def _install(tmp_path, dotenv: str, token_env: str = "OPENCLAW_GATEWAY_TOKEN", openclaw_token: str = X) -> None:
    oc = tmp_path / "openclaw.json"
    oc.write_text(json.dumps({"gateway": {"auth": {"token": openclaw_token}}}), encoding="utf-8")
    gateway = {"host": "127.0.0.1", "port": 18789, "api_port": 18970}
    if token_env:
        gateway["token_env"] = token_env
    doc = {
        "config_version": config_module.CURRENT_CONFIG_VERSION,
        "gateway": gateway,
        "claw": {"mode": "openclaw", "config_file": str(oc)},
        "guardrail": {"connector": "openclaw"},
        "observability": {},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    (tmp_path / ".env").write_text(dotenv, encoding="utf-8")
    (tmp_path / ".env").chmod(0o600)


def _dotenv(tmp_path) -> dict[str, str]:
    out = {}
    for line in (tmp_path / ".env").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.startswith("#"):
            out[key] = value
    return out


def _token_env(tmp_path) -> str:
    return yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["gateway"].get("token_env", "")


def _resolve(tmp_path) -> str:
    for name in NAMES:
        os.environ.pop(name, None)
    config_module._load_dotenv_into_os(str(tmp_path))
    return config_module.load(data_dir=str(tmp_path)).gateway.resolved_token()


def _pending(tmp_path) -> bool:
    return _gateway_token_split_pending(str(tmp_path / "config.yaml"), str(tmp_path))


CASES = {
    # setup gateway / init / bootstrap: only the OpenClaw name.
    "setup-gateway": (f"OPENCLAW_GATEWAY_TOKEN={X}\n", "OPENCLAW_GATEWAY_TOKEN"),
    # setup openclaw adoption: the OpenClaw token under both names, marked.
    "adoption": (f"DEFENSECLAW_GATEWAY_TOKEN={X}\nOPENCLAW_GATEWAY_TOKEN={X}\n{MARKER}\n", "OPENCLAW_GATEWAY_TOKEN"),
    "adoption-canonical-token-env": (f"DEFENSECLAW_GATEWAY_TOKEN={X}\nOPENCLAW_GATEWAY_TOKEN={X}\n", ""),
    # Only the master name left, holding the openclaw.json token.
    "master-equals-openclaw-json": (f"DEFENSECLAW_GATEWAY_TOKEN={X}\n", "DEFENSECLAW_GATEWAY_TOKEN"),
}


@pytest.mark.parametrize("release", ["1.0.8", "1.0.9"])
@pytest.mark.parametrize("name", sorted(CASES))
def test_upgrade_gives_the_gateway_a_token_of_its_own(tmp_path, name, release):
    dotenv, token_env = CASES[name]
    _install(tmp_path, dotenv, token_env)
    assert _pending(tmp_path)

    result = migrate(str(tmp_path), from_version=release)

    assert _GATEWAY_TOKEN_SPLIT_STEP_NAME in result.applied
    saved = _dotenv(tmp_path)
    if "OPENCLAW_GATEWAY_TOKEN=" in dotenv:
        assert saved["OPENCLAW_GATEWAY_TOKEN"] == X  # the gateway still connects to OpenClaw with it
    master = saved["DEFENSECLAW_GATEWAY_TOKEN"]
    assert MINTED.match(master) and master != X
    assert _token_env(tmp_path) == (token_env and "DEFENSECLAW_GATEWAY_TOKEN")
    assert _resolve(tmp_path) == master

    # Idempotent: a second migrate finds nothing to do and changes nothing.
    dotenv_before = (tmp_path / ".env").read_bytes()
    config_before = (tmp_path / "config.yaml").read_bytes()
    assert not _pending(tmp_path)
    again = migrate(str(tmp_path), from_version="1.0.10")
    assert _GATEWAY_TOKEN_SPLIT_STEP_NAME not in again.applied
    assert (tmp_path / ".env").read_bytes() == dotenv_before
    assert (tmp_path / "config.yaml").read_bytes() == config_before


def test_a_separate_master_needs_nothing(tmp_path):
    _install(
        tmp_path, f"DEFENSECLAW_GATEWAY_TOKEN=own-master\nOPENCLAW_GATEWAY_TOKEN={X}\n", "DEFENSECLAW_GATEWAY_TOKEN"
    )
    assert not _pending(tmp_path)
    before = (tmp_path / ".env").read_bytes()
    result = migrate(str(tmp_path), from_version="1.0.9")
    assert _GATEWAY_TOKEN_SPLIT_STEP_NAME not in result.applied
    assert (tmp_path / ".env").read_bytes() == before


def test_a_stale_token_env_alone_keeps_the_master(tmp_path):
    _install(tmp_path, f"DEFENSECLAW_GATEWAY_TOKEN=own-master\nOPENCLAW_GATEWAY_TOKEN={X}\n")
    assert _pending(tmp_path)
    migrate(str(tmp_path), from_version="1.0.9")
    assert _dotenv(tmp_path) == {"DEFENSECLAW_GATEWAY_TOKEN": "own-master", "OPENCLAW_GATEWAY_TOKEN": X}
    assert _token_env(tmp_path) == "DEFENSECLAW_GATEWAY_TOKEN"
    assert _resolve(tmp_path) == "own-master"


def test_a_hook_only_install_without_openclaw_needs_nothing(tmp_path):
    _install(tmp_path, "DEFENSECLAW_GATEWAY_TOKEN=own-master\n", "DEFENSECLAW_GATEWAY_TOKEN", openclaw_token="")
    assert not _pending(tmp_path)


def test_a_managed_install_is_left_to_the_gateway(tmp_path, monkeypatch):
    # The service owns a managed .env; the gateway mints its token at start.
    _install(tmp_path, f"OPENCLAW_GATEWAY_TOKEN={X}\n")
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    assert not _pending(tmp_path)
