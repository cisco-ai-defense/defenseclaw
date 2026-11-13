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

import configparser
import json
import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

from defenseclaw import codex_toml
from defenseclaw.connector_paths import claude_config_dir, codex_home

ROUTE_ONLY_CONNECTORS = ("claudecode", "codex")
# The route credential header and the Codex provider the gateway renders
# (internal/gateway/connector RouteOnlyHeader, codexRouteProviderID).
ROUTE_HEADER = "X-DC-Route-Auth"
CODEX_ROUTE_PROVIDER = "defenseclaw_route"
_SUPPORTED = ", ".join(ROUTE_ONLY_CONNECTORS)
_ROUTE_PREFIX = "/r/"


class RouteOnlyError(Exception):
    """A route-only change that cannot be made, with the reason to show."""


@dataclass
class Upstream:
    base_url: str
    api: str
    bedrock_auth: str = ""
    bedrock_profile: str = ""
    bedrock_region: str = ""

    def to_config(self) -> dict[str, Any]:
        out: dict[str, Any] = {"base_url": self.base_url, "api": self.api}
        if self.bedrock_auth:
            bedrock = {"auth": self.bedrock_auth, "profile": self.bedrock_profile, "region": self.bedrock_region}
            out["bedrock"] = {k: v for k, v in bedrock.items() if v}
        return out


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _claude_settings() -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    """The agent env (shell merged with settings.json env), the settings.json
    env block alone, and the settings document."""
    env = {k: v for k, v in os.environ.items() if k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_"))}
    path = os.path.join(claude_config_dir(), "settings.json")
    try:
        with open(path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (OSError, ValueError):
        return env, {}, {}
    if not isinstance(settings, dict):
        return env, {}, {}
    block = settings.get("env")
    own = {str(k): str(v) for k, v in block.items()} if isinstance(block, dict) else {}
    env.update(own)
    return env, own, settings


# Gateway signing sends the AWS credential only to an AWS Bedrock runtime
# host (the gateway refuses others, internal/gateway/routeonly_sigv4.go).
# Group 1 is the region the host names.
_BEDROCK_RUNTIME_HOST = re.compile(
    r"(?:^|\.)bedrock-runtime(?:-fips)?\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.(?:vpce\.)?amazonaws\.com(?:\.cn)?$"
)


def bedrock_signable(url: str) -> bool:
    """Whether the gateway would sign for url (Go bedrockSignableURL)."""
    parts = urllib.parse.urlsplit(str(url or "").strip())
    return parts.scheme == "https" and bool(_BEDROCK_RUNTIME_HOST.search((parts.hostname or "").lower()))


_SIGNING_OPTIONS = (
    "use a Bedrock API key (AWS_BEARER_TOKEN_BEDROCK) "
    "or name an AWS profile (AWS_PROFILE) in ~/.aws that the gateway can read"
)


def _aws_file(env: dict[str, str], own: dict[str, str], name: str, default: str) -> str:
    """The AWS shared file the agent reads. A path set only in settings.json
    env is seen by Claude Code and never by the gateway: refused."""
    path = (env.get(name) or "").strip()
    if path and own.get(name, "").strip() == path and os.environ.get(name, "").strip() != path:
        raise RouteOnlyError(
            f"Claude Code reads AWS profiles from {name}={path} (settings.json env), "
            "which the DefenseClaw gateway does not read; "
            f"move the profile to {default} or {_SIGNING_OPTIONS}"
        )
    return os.path.expanduser(path or default)


def _aws_profile_exists(env: dict[str, str], own: dict[str, str], profile: str) -> bool:
    config_file = _aws_file(env, own, "AWS_CONFIG_FILE", os.path.join("~", ".aws", "config"))
    creds_file = _aws_file(env, own, "AWS_SHARED_CREDENTIALS_FILE", os.path.join("~", ".aws", "credentials"))
    in_config = {f"profile {profile}"} | ({"default"} if profile == "default" else set())
    wanted = {config_file: in_config, creds_file: {profile}}
    for path, sections in wanted.items():
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error) as exc:
            raise RouteOnlyError(f"cannot read the AWS file {path}: {exc}") from exc
        if sections & {s.strip() for s in parser.sections()}:
            return True
    return False


def _claude_bedrock_upstream(env: dict[str, str], own: dict[str, str], settings: dict[str, Any], base: str) -> Upstream:
    """The route-only upstream of Claude Code on Bedrock (REVIEW-code-slice7 P2-2)."""
    region = (env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "us-east-1").strip()
    upstream = base.rstrip("/") or f"https://bedrock-runtime.{region}.amazonaws.com"
    if _truthy(env.get("CLAUDE_CODE_SKIP_BEDROCK_AUTH")):
        # The user already skips AWS auth (their own gateway signs): the
        # gateway passes the call through and adds no credential.
        return Upstream(upstream, "invoke", "passthrough", bedrock_region=region)
    if env.get("AWS_BEARER_TOKEN_BEDROCK"):
        # A Bedrock API key is not bound to the path: passed through.
        return Upstream(upstream, "invoke", "passthrough", bedrock_region=region)
    # IAM credentials: the agent skips its own AWS auth and the gateway signs
    # with the same profile (its SigV4 would name the loopback host).
    for key in ("awsCredentialExport", "awsAuthRefresh"):
        if settings.get(key):
            raise RouteOnlyError(
                f"Claude Code gets its AWS credentials from settings.json {key}, "
                f"which the DefenseClaw gateway cannot run; {_SIGNING_OPTIONS}"
            )
    profile = (env.get("AWS_PROFILE") or "").strip()
    if not profile and env.get("AWS_ACCESS_KEY_ID"):
        raise RouteOnlyError(
            "Claude Code signs Bedrock calls with AWS_ACCESS_KEY_ID from its environment, "
            f"which the DefenseClaw gateway does not have; {_SIGNING_OPTIONS}"
        )
    profile = profile or "default"
    if not bedrock_signable(upstream):
        raise RouteOnlyError(
            "gateway Bedrock signing sends AWS credentials only to an https "
            f"bedrock-runtime.<region>.amazonaws.com host, not {upstream}; {_SIGNING_OPTIONS}"
        )
    if not _aws_profile_exists(env, own, profile):
        raise RouteOnlyError(
            f"the AWS profile {profile!r} is not in the AWS config or credentials file; {_SIGNING_OPTIONS}"
        )
    return Upstream(upstream, "invoke", "profile", bedrock_profile=profile, bedrock_region=region)


def detect_upstream(connector: str) -> Upstream | None:
    """Where the agent sends model calls today; None when it already points
    at a DefenseClaw route-only endpoint (keep the recorded upstream)."""
    if connector == "claudecode":
        env, own, settings = _claude_settings()
        if _truthy(env.get("CLAUDE_CODE_USE_BEDROCK")):
            base = env.get("ANTHROPIC_BEDROCK_BASE_URL", "").strip()
            if _ROUTE_PREFIX + "claudecode" in base:
                return None
            return _claude_bedrock_upstream(env, own, settings, base)
        base = env.get("ANTHROPIC_BASE_URL", "").strip()
        if _ROUTE_PREFIX + "claudecode" in base:
            return None
        return Upstream(base.rstrip("/") or "https://api.anthropic.com", "messages")
    if connector == "codex":
        doc = codex_config()
        profile = doc.get("profile")
        profiles = doc.get("profiles") or {}
        if profile and isinstance(profiles.get(profile), dict) and profiles[profile].get("model_provider"):
            raise RouteOnlyError(
                f"the active Codex profile {profile!r} sets its own model_provider; route-only routes the top-level provider only"
            )
        provider = str(doc.get("model_provider") or "openai")
        if provider == CODEX_ROUTE_PROVIDER:
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


def codex_config() -> dict[str, Any]:
    """The Codex config.toml ({} when there is none)."""
    path = os.path.join(codex_home(), "config.toml")
    try:
        with open(path, "rb") as fh:
            return codex_toml.loads(fh.read())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise RouteOnlyError(f"cannot read {path}: {exc}") from exc


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
        # Managed hosts are configured by the bundle; the gateway validation
        # refuses a managed macOS or Windows bundle whose route-only upstream has no
        # gateway credential (custody, every call would answer 503) and
        # doctor fails such a host.
        raise RouteOnlyError(
            "route-only on managed hosts comes from the signed policy bundle (routing.route_only); "
            "on managed macOS and Windows the bundle also needs a gateway credential (routing.models[].credential) "
            "for each routed upstream, because the agent credential is not forwarded there"
        )


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
        raise RouteOnlyError(
            "turn on semantic routing with at least one model first (routing.enabled and routing.models)"
        )
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
    return {
        "connector": connector,
        "enabled": False,
        "changed": was,
        "restart_agent": was,
        "agent_config_restored": restored,
    }


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
