# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Connector-aware test fixtures + helpers (plan E5).

Drop-in helpers for non-OpenClaw connector tests. Every helper
roots its work at a tmp_path so the developer's real ``~/.claude``
etc. is untouched. Each helper returns the absolute path of the
file it wrote so callers can assert on it.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from typing import Any, Iterator
from unittest.mock import patch

CONNECTORS = ("openclaw", "zeptoclaw", "claudecode", "codex")


def make_zeptoclaw_config(
    home: str,
    *,
    providers: dict[str, dict[str, str]] | None = None,
) -> str:
    """Write a minimal ``<home>/.zeptoclaw/config.json``.

    *providers* is a mapping ``{provider_name: {"api_base": ..., "api_key": ...}}``.
    """
    providers = providers or {
        "anthropic": {
            "api_base": "https://api.anthropic.com",
            "api_key": "sk-ant-fixture",
        }
    }
    zc_dir = os.path.join(home, ".zeptoclaw")
    os.makedirs(zc_dir, exist_ok=True)
    cfg_path = os.path.join(zc_dir, "config.json")
    body = {
        "providers": providers,
        "safety": {"allow_private_endpoints": False},
    }
    with open(cfg_path, "w") as fh:
        json.dump(body, fh, indent=2)
    return cfg_path


def make_claudecode_settings(
    home: str,
    *,
    hooks: list[dict[str, Any]] | None = None,
    mcp_servers: dict[str, Any] | None = None,
) -> str:
    """Write a minimal ``<home>/.claude/settings.json``."""
    cd = os.path.join(home, ".claude")
    os.makedirs(cd, exist_ok=True)
    body = {
        "hooks": hooks or [],
        "mcpServers": mcp_servers or {},
    }
    settings_path = os.path.join(cd, "settings.json")
    with open(settings_path, "w") as fh:
        json.dump(body, fh, indent=2)
    return settings_path


def make_codex_config(
    home: str,
    *,
    hooks_block: str = "",
    model_provider: str = "openai",
) -> str:
    """Write a minimal ``<home>/.codex/config.toml`` with optional hooks block."""
    cd = os.path.join(home, ".codex")
    os.makedirs(cd, exist_ok=True)
    body = ""
    if model_provider:
        body += f'model_provider = "{model_provider}"\n'
    if hooks_block:
        body += hooks_block + "\n"
    cfg_path = os.path.join(cd, "config.toml")
    with open(cfg_path, "w") as fh:
        fh.write(body)
    return cfg_path


def seed_skill_dir(home: str, connector_rel: str, name: str) -> str:
    """Create a ``<home>/<connector_rel>/skills/<name>`` skill dir."""
    skill_dir = os.path.join(home, connector_rel, "skills", name)
    os.makedirs(skill_dir, exist_ok=True)
    skill_md = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_md):
        with open(skill_md, "w") as fh:
            fh.write(f"# {name}\n\nfixture skill.\n")
    return skill_dir


def seed_plugin_dir(
    home: str,
    connector_rel: str,
    name: str,
    *,
    manifest_name: str = "plugin.json",
    manifest: dict[str, Any] | None = None,
) -> str:
    """Create a ``<home>/<connector_rel>/plugins/<name>`` host plugin dir."""
    plugin_dir = os.path.join(home, connector_rel, "plugins", name)
    os.makedirs(plugin_dir, exist_ok=True)
    body = manifest or {"id": name, "name": name, "version": "0.0.1"}
    with open(os.path.join(plugin_dir, manifest_name), "w") as fh:
        json.dump(body, fh)
    return plugin_dir


@contextlib.contextmanager
def with_connector(connector: str) -> Iterator[tuple[str, Any]]:
    """Context manager: tmpdir HOME + ``DEFENSECLAW_HOME`` + cfg w/ connector.

    Yields ``(home_dir, cfg)``. The cfg is whatever ``defenseclaw.config.load()``
    returns under the patched env, with ``cfg.guardrail.connector`` already
    pointed at *connector*.
    """
    if connector not in CONNECTORS:
        raise ValueError(
            f"unknown connector {connector!r}; expected one of {CONNECTORS}"
        )

    with tempfile.TemporaryDirectory(prefix=f"dc-fixture-{connector}-") as tmp:
        dc_home = os.path.join(tmp, ".defenseclaw")
        os.makedirs(dc_home, exist_ok=True)

        with patch.dict(
            os.environ,
            {"DEFENSECLAW_HOME": dc_home, "HOME": tmp},
            clear=False,
        ):
            from defenseclaw.config import load as load_config

            cfg = load_config()
            cfg.guardrail.connector = connector
            yield tmp, cfg
