# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Route-only mode helpers for hook connectors (S1 slice 5b).

``defenseclaw routing enable|disable|status --connector`` (S13 owns the
click group) call these. They read the agent configuration once to record
where its model calls go today, then write ``routing.route_only`` in
config.yaml through the shared writer. The gateway renders the agent side
from config.yaml on reload (no restart) and restores it on disable,
uninstall and rollback (DESIGN 7.5, 16.11, 17.5).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from defenseclaw import codex_toml
from defenseclaw.connector_paths import claude_config_dir, codex_home

ROUTE_ONLY_CONNECTORS = ("claudecode", "codex")
_SUPPORTED = ", ".join(ROUTE_ONLY_CONNECTORS)
_ROUTE_PREFIX = "/r/"


class RouteOnlyError(Exception):
    """A route-only change that cannot be made, with the reason to show."""


@dataclass
class Upstream:
    base_url: str
    api: str
    bedrock_auth: str = ""

    def to_config(self) -> dict[str, Any]:
        out: dict[str, Any] = {"base_url": self.base_url, "api": self.api}
        if self.bedrock_auth:
            out["bedrock"] = {"auth": self.bedrock_auth}
        return out


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _claude_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_"))}
    path = os.path.join(claude_config_dir(), "settings.json")
    try:
        with open(path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        return env
    block = settings.get("env") if isinstance(settings, dict) else None
    if isinstance(block, dict):
        env.update({str(k): str(v) for k, v in block.items()})
    return env


def detect_upstream(connector: str) -> Upstream | None:
    """Where the agent sends model calls today; None when it already points
    at a DefenseClaw route-only endpoint (keep the recorded upstream)."""
    if connector == "claudecode":
        env = _claude_env()
        if _truthy(env.get("CLAUDE_CODE_USE_BEDROCK")):
            base = env.get("ANTHROPIC_BEDROCK_BASE_URL", "").strip()
            if _ROUTE_PREFIX + "claudecode" in base:
                return None
            if not env.get("AWS_BEARER_TOKEN_BEDROCK"):
                raise RouteOnlyError(
                    "Claude Code on Bedrock needs a Bedrock API key (AWS_BEARER_TOKEN_BEDROCK) for route-only; "
                    "gateway signing is not available in this build"
                )
            region = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "us-east-1"
            return Upstream(base or f"https://bedrock-runtime.{region}.amazonaws.com", "invoke", "passthrough")
        base = env.get("ANTHROPIC_BASE_URL", "").strip()
        if _ROUTE_PREFIX + "claudecode" in base:
            return None
        return Upstream(base.rstrip("/") or "https://api.anthropic.com", "messages")
    if connector == "codex":
        path = os.path.join(codex_home(), "config.toml")
        try:
            with open(path, "rb") as fh:
                doc = codex_toml.loads(fh.read())
        except FileNotFoundError:
            doc = {}
        except (OSError, ValueError) as exc:
            raise RouteOnlyError(f"cannot read {path}: {exc}") from exc
        profile = doc.get("profile")
        profiles = doc.get("profiles") or {}
        if profile and isinstance(profiles.get(profile), dict) and profiles[profile].get("model_provider"):
            raise RouteOnlyError(f"the active Codex profile {profile!r} sets its own model_provider; route-only routes the top-level provider only")
        provider = str(doc.get("model_provider") or "openai")
        if provider == "defenseclaw_route":
            return None
        if provider == "openai":
            if _codex_chatgpt_login():
                return Upstream("https://chatgpt.com/backend-api/codex", "responses")
            return Upstream("https://api.openai.com/v1", "responses")
        table = (doc.get("model_providers") or {}).get(provider) or {}
        base = str(table.get("base_url") or "").strip()
        if not base:
            raise RouteOnlyError(f"Codex provider {provider!r} has no base_url to wrap")
        api = "chat" if str(table.get("wire_api") or "chat") == "chat" else "responses"
        return Upstream(base.rstrip("/"), api)
    raise RouteOnlyError(f"{connector} has no route-only support (supported: {_SUPPORTED})")


def _codex_chatgpt_login() -> bool:
    try:
        with open(os.path.join(codex_home(), "auth.json"), encoding="utf-8") as fh:
            auth = json.load(fh)
    except (OSError, ValueError):
        return False
    return isinstance(auth, dict) and bool(auth.get("tokens")) and not auth.get("OPENAI_API_KEY")


def _check_host(cfg: Any) -> None:
    mode = str(getattr(cfg, "deployment_mode", "") or "").strip()
    if mode == "managed_enterprise":
        raise RouteOnlyError("route-only on managed hosts comes from the signed policy bundle and is not available in this build")


def _route_only(cfg: Any) -> tuple[list[str], dict[str, Any]]:
    ro = getattr(cfg.routing, "route_only", None) or {}
    connectors = [str(c) for c in (ro.get("connectors") or [])]
    upstreams = {str(k): dict(v) for k, v in (ro.get("upstreams") or {}).items() if isinstance(v, dict)}
    return connectors, upstreams


def _store(cfg: Any, connectors: list[str], upstreams: dict[str, Any]) -> None:
    value: dict[str, Any] = {}
    if connectors:
        value["connectors"] = connectors
    if upstreams:
        value["upstreams"] = upstreams
    cfg.routing.route_only = value


def enable(cfg: Any, connector: str) -> dict[str, Any]:
    """Route connector through the gateway (routing and usage only).

    Writes routing.route_only.connectors and .upstreams.<connector> and saves
    config.yaml; the running gateway renders the agent config on reload.
    """
    _check_host(cfg)
    if connector not in ROUTE_ONLY_CONNECTORS:
        raise RouteOnlyError(f"{connector} has no route-only support (supported: {_SUPPORTED})")
    if not cfg.routing.enabled or not cfg.routing.models:
        raise RouteOnlyError("turn on semantic routing with at least one model first (routing.enabled and routing.models)")
    connectors, upstreams = _route_only(cfg)
    detected = detect_upstream(connector)
    if detected is None:
        if connector not in upstreams:
            raise RouteOnlyError(
                f"{connector} already points at a DefenseClaw route-only endpoint but config.yaml has no upstream for it; "
                "run disable, check the agent configuration, then enable again"
            )
    else:
        upstreams[connector] = detected.to_config()
    if connector not in connectors:
        connectors.append(connector)
    _store(cfg, connectors, upstreams)
    cfg.save()
    return {"connector": connector, "enabled": True, "upstream": upstreams[connector], "restart_agent": True}


def disable(cfg: Any, connector: str) -> dict[str, Any]:
    """Stop routing connector; the gateway restores the agent config.

    Works with the gateway stopped too: the next gateway start (or the
    connector teardown on uninstall) restores the agent values.
    """
    _check_host(cfg)
    connectors, upstreams = _route_only(cfg)
    was = connector in connectors
    connectors = [c for c in connectors if c != connector]
    upstreams.pop(connector, None)
    _store(cfg, connectors, upstreams)
    cfg.save()
    # The running gateway restores on reload; this also covers a gateway
    # that is stopped or down (DESIGN 7.4).
    restored = restore_agent_config(connector)
    return {"connector": connector, "enabled": False, "changed": was, "restart_agent": was, "agent_config_restored": restored}


def status(cfg: Any) -> list[dict[str, Any]]:
    """Route-only state per supported connector (for status, doctor, TUI)."""
    connectors, upstreams = _route_only(cfg)
    return [
        {
            "connector": name,
            "enabled": name in connectors and bool(cfg.routing.enabled),
            "listed": name in connectors,
            "upstream": upstreams.get(name),
        }
        for name in ROUTE_ONLY_CONNECTORS
    ]


def restore_agent_config(connector: str | None = None) -> bool:
    """Put back the agent model settings route-only replaced, with or without
    a running gateway (``defenseclaw-gateway connector route-restore``).

    Best effort: returns False when the gateway binary is missing or too old
    (it predates route-only, so nothing was rendered) or the restore failed.
    """
    import subprocess

    from defenseclaw.gateway import path_gateway

    gw = path_gateway(honor_override=False)
    if gw is None:
        return False
    args = [gw, "connector", "route-restore"] + (["--connector", connector] if connector else ["--all"])
    try:
        proc = subprocess.run(args, capture_output=True, encoding="utf-8", errors="replace", timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0
