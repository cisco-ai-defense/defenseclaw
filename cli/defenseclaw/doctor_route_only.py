# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor and status rows for route-only mode (S1 DESIGN 7.2, 7.4, 17.1).

The gateway publishes per-connector readiness in /health
``routing.details.route_only``: listener mounted, custody (managed macOS and
Windows forward no agent credential), the gateway credential in use and the
Bedrock signing checks. These helpers turn it into rows. Without a running
gateway they check what can be checked offline (agent config, custody
coverage, AWS profile, region) and say that model calls fail until the
gateway starts. Shared by ``defenseclaw doctor`` and ``defenseclaw status``.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Any

from defenseclaw import routing_route_only as ro

# Gateway Bedrock signing modes (internal/gateway/routeonly_sigv4.go).
SIGNING_AUTH = ("profile", "instance_role", "iam_credentials")
PORT_HELD_MARK = ".route-port-held.json"
_DEFAULT_ORIGINS = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com"}
_REGION_HOST = re.compile(
    r"(?:^|\.)bedrock-runtime(?:-fips)?\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.(?:vpce\.)?amazonaws\.com(?:\.cn)?$"
)


@dataclass
class Row:
    tag: str  # pass, warn, fail, skip
    label: str
    detail: str
    fix: str = ""


def upstream_provider(api: str) -> str:
    """The provider a route-only upstream API talks to (Go RouteOnlyUpstreamProvider)."""
    if api == "messages":
        return "anthropic"
    if api in ("converse", "invoke"):
        return "bedrock"
    return "openai"


def origin(raw: str) -> str:
    parts = urllib.parse.urlsplit(str(raw or "").strip())
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def custody_covered(cfg: Any, upstream: dict[str, Any]) -> bool:
    """Whether the gateway holds its own credential for upstream: gateway
    Bedrock signing, or a routing.models[].credential of the same provider
    and origin (Go config routeOnlyCustodyCovered)."""
    bedrock = upstream.get("bedrock") or {}
    if isinstance(bedrock, dict) and bedrock.get("auth") in ("instance_role", "iam_credentials"):
        return True
    provider, want = upstream_provider(str(upstream.get("api") or "")), origin(upstream.get("base_url") or "")
    for model in getattr(cfg.routing, "models", None) or []:
        if not isinstance(model, dict) or str(model.get("provider") or "").lower() != provider:
            continue
        if not str(model.get("credential") or "").strip():
            continue
        got = origin(model.get("base_url") or "") or _DEFAULT_ORIGINS.get(provider, "")
        if got.lower() == want.lower():
            return True
    return False


def custody_host(profile: str, platform: str = sys.platform) -> bool:
    """Managed standalone macOS and Windows forward no agent credential."""
    return profile == "standalone" and (platform == "darwin" or platform.startswith("win"))


def custody_fix(upstream: dict[str, Any]) -> str:
    provider = upstream_provider(str(upstream.get("api") or ""))
    where = origin(upstream.get("base_url") or "")
    return f"set routing.models[].credential for {provider} (base_url {where}) in the policy bundle"


def _expected_base_url(cfg: Any, connector: str) -> str:
    port = int(getattr(getattr(cfg, "gateway", None), "api_port", 0) or 0)
    return f"http://127.0.0.1:{port}/r/{connector}"


def agent_config_row(cfg: Any, connector: str, upstream: dict[str, Any]) -> Row:
    """Whether the agent config DefenseClaw renders from config.yaml is in place (OSS)."""
    label = f"Route-only {connector} agent config"
    want = _expected_base_url(cfg, connector)
    fix = "restart the gateway to render it again from config.yaml: defenseclaw-gateway restart, then restart the agent"
    if connector == "claudecode":
        _env, own, _settings = ro._claude_settings()
        key = "ANTHROPIC_BEDROCK_BASE_URL" if upstream.get("api") in ("converse", "invoke") else "ANTHROPIC_BASE_URL"
        got = own.get(key, "").strip().rstrip("/")
        if got != want:
            shown = got or "unset"
            return Row("warn", label, f"settings.json env {key} is {shown}, not {want}", fix)
        if ro.ROUTE_HEADER not in own.get("ANTHROPIC_CUSTOM_HEADERS", ""):
            return Row("warn", label, f"settings.json env ANTHROPIC_CUSTOM_HEADERS has no {ro.ROUTE_HEADER} line", fix)
        return Row("pass", label, f"settings.json points at {want}")
    if connector == "codex":
        doc = ro.codex_config()
        table = (doc.get("model_providers") or {}).get(ro.CODEX_ROUTE_PROVIDER) or {}
        got = str(table.get("base_url") or "").strip().rstrip("/")
        if doc.get("model_provider") != ro.CODEX_ROUTE_PROVIDER or got != want:
            return Row("warn", label, f"config.toml model_provider is not {ro.CODEX_ROUTE_PROVIDER} at {want}", fix)
        return Row("pass", label, f"config.toml points at {want}")
    return Row("skip", label, "no route-only render for this connector")


def _host_region(base_url: str) -> str:
    match = _REGION_HOST.search((urllib.parse.urlsplit(base_url).hostname or "").lower())
    return match.group(1) if match else ""


def signing_rows(connector: str, upstream: dict[str, Any], live: dict[str, Any] | None) -> list[Row]:
    """Gateway Bedrock signing: signer, region, profile and credential rows.
    live is the signing block the gateway reports (None: gateway not running)."""
    bedrock = upstream.get("bedrock") or {}
    auth = str(bedrock.get("auth") or "")
    if auth not in SIGNING_AUTH:
        return []
    label = f"Route-only {connector} Bedrock"
    block = f"routing.route_only.upstreams.{connector}.bedrock"
    profile = str(bedrock.get("profile") or "default") if auth == "profile" else ""
    rows: list[Row] = []
    if live is None:
        host, region = _host_region(upstream.get("base_url") or ""), str(bedrock.get("region") or "")
        if host and region and host != region.lower():
            rows.append(
                Row(
                    "fail",
                    f"{label} region",
                    f"{block}.region {region} does not match the upstream host region {host}",
                    f"set {block}.region to {host} or remove it",
                )
            )
        elif not (host or region):
            rows.append(
                Row(
                    "fail",
                    f"{label} region",
                    "no region: the upstream host names none and the block sets none",
                    f"set {block}.region",
                )
            )
        else:
            rows.append(Row("pass", f"{label} region", host or region))
        if profile:
            try:
                found = ro._aws_profile_exists(dict(os.environ), {}, profile)
            except ro.RouteOnlyError as exc:
                rows.append(Row("fail", f"{label} profile", str(exc), "fix the AWS files of the gateway account"))
            else:
                tag = "pass" if found else "fail"
                detail = f"AWS profile {profile} " + (
                    "found" if found else "is not in the AWS config or credentials file of the gateway account"
                )
                rows.append(
                    Row(
                        tag,
                        f"{label} profile",
                        detail,
                        "" if found else f"create profile {profile} for this account, or change {block}.profile",
                    )
                )
        rows.append(Row("skip", f"{label} credential", "not checked: the gateway is not running"))
        return rows
    rows.append(
        _signing_row(
            f"{label} signer",
            bool(live.get("signer")),
            f"auth {auth}",
            str(live.get("signer_error") or ""),
            f"check {block}",
        )
    )
    region_ok = bool(live.get("region_ok"))
    rows.append(
        _signing_row(
            f"{label} region",
            region_ok,
            str(live.get("region") or ""),
            str(live.get("region_error") or ""),
            f"set {block}.region to the region of the upstream host",
        )
    )
    if profile:
        found = live.get("profile_found")
        if found is not None:
            rows.append(
                _signing_row(
                    f"{label} profile",
                    bool(found),
                    f"AWS profile {profile} found",
                    f"AWS profile {profile} is not in the AWS files of the gateway account",
                    f"create profile {profile} for the gateway account, or change {block}.profile",
                )
            )
    if live.get("signer"):
        rows.append(
            _signing_row(
                f"{label} credential",
                bool(live.get("credential")),
                "one AWS credential fetched within 2 s",
                str(live.get("credential_error") or "no credential"),
                "refresh the AWS credentials of the gateway account (for SSO: aws sso login)",
            )
        )
    return rows


def _signing_row(label: str, ok: bool, good: str, bad: str, fix: str) -> Row:
    return Row("pass", label, good) if ok else Row("fail", label, bad or "failed", fix)


def port_held_row(cfg: Any) -> Row | None:
    """The mark the Linux gateway leaves when another account held its API
    port (internal/gateway/api_port_held.go); gone once it owns the port again."""
    path = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "hooks", PORT_HELD_MARK)
    try:
        with open(path, encoding="utf-8") as fh:
            mark = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        mark = {}
    uid = mark.get("uid", "?") if isinstance(mark, dict) else "?"
    port = int(getattr(getattr(cfg, "gateway", None), "api_port", 0) or 0)
    return Row(
        "fail",
        "Route-only API port",
        f"another account (uid {uid}) held the gateway API port; route-only agents may have sent model calls to it",
        f"find it with: ss -ltnp sport = :{port}; stop it, then restart the gateway (it replaces the route credential "
        "and renders the agent configs again) and restart the agents",
    )


def shared_mac_row(connectors: list[str], users_dir: str = "/Users") -> Row | None:
    """OSS macOS has no port owner reader (DESIGN 17.1): warn on a Mac with
    more than one account."""
    try:
        names = [n for n in os.listdir(users_dir) if not n.startswith(".") and n not in ("Shared", "Guest")]
    except OSError:
        return None
    if len(names) < 2:
        return None
    first = connectors[0] if connectors else "<name>"
    return Row(
        "warn",
        "Route-only on a shared Mac",
        f"{len(names)} accounts on this Mac: while the gateway restarts another account can take its API port "
        "and receive the model credential the agents send",
        f"use route-only on single-user Macs, or run defenseclaw routing disable --connector {first}",
    )


_CREDENTIAL_TEXT = {
    "agent": "the agent credential is passed through",
    "gateway_held": "gateway-held key",
    "gateway_signing": "the gateway signs Bedrock calls",
}


def _live(health: dict | None) -> dict[str, dict[str, Any]] | None:
    """Readiness by connector from /health (None: no running gateway)."""
    if not isinstance(health, dict):
        return None
    routing = health.get("routing")
    details = routing.get("details") if isinstance(routing, dict) else None
    rows = details.get("route_only") if isinstance(details, dict) else None
    out: dict[str, dict[str, Any]] = {}
    for item in rows if isinstance(rows, list) else []:
        if isinstance(item, dict) and item.get("connector"):
            out[str(item["connector"])] = item
    return out


def route_only_rows(
    cfg: Any, health: dict | None, *, profile: str = "", platform: str = sys.platform, users_dir: str = "/Users"
) -> list[Row]:
    """Every route-only row: one state row per connector, its agent config
    (OSS), gateway Bedrock signing, a held API port and the shared Mac note."""
    connectors, upstreams = ro._route_only(cfg)
    if not connectors:
        return []
    names = ", ".join(connectors)
    if not getattr(cfg.routing, "enabled", False):
        return [
            Row(
                "warn",
                "Route-only",
                f"{names} listed in routing.route_only.connectors, but routing.enabled is false: not routed",
                "turn routing on, or run defenseclaw routing disable --connector <name>",
            )
        ]
    live = _live(health)
    managed = profile == "standalone"
    custody = custody_host(profile, platform)
    rows: list[Row] = []
    for name in connectors:
        up = upstreams.get(name) or {}
        label = f"Route-only {name}"
        state = live.get(name) if live is not None else None
        if not str(up.get("base_url") or "").strip():
            where = "in the policy bundle" if managed else f"by running defenseclaw routing enable --connector {name}"
            rows.append(Row("fail", label, f"routing.route_only.upstreams.{name} is not set", f"set it {where}"))
        elif live is None:
            if custody and not custody_covered(cfg, up):
                rows.append(
                    Row(
                        "fail",
                        label,
                        "this managed host forwards no agent credential and no gateway credential "
                        "covers the upstream: every model call answers 503",
                        custody_fix(up),
                    )
                )
            elif managed:
                rows.append(
                    Row(
                        "fail",
                        label,
                        f"the gateway is not running: {name} model calls fail until it is back",
                        "the guardian restarts it; ask an administrator if it stays down",
                    )
                )
            else:
                rows.append(
                    Row(
                        "fail",
                        label,
                        f"the gateway is not running: {name} model calls fail until it starts",
                        "start it with defenseclaw-gateway start, or restore direct model access: "
                        f"defenseclaw routing disable --connector {name}",
                    )
                )
        elif state is None:
            rows.append(
                Row(
                    "warn",
                    label,
                    f"the running gateway reports no route-only state for {name}",
                    "restart it so it runs this build: defenseclaw-gateway restart",
                )
            )
        elif state.get("ready"):
            text = _CREDENTIAL_TEXT.get(str(state.get("credential") or ""), str(state.get("credential") or ""))
            provider = state.get("provider") or upstream_provider(str(up.get("api") or ""))
            where = state.get("upstream") or origin(up.get("base_url") or "")
            rows.append(Row("pass", label, f"{provider} at {where}; {text}"))
        else:
            rows.append(
                Row(
                    "fail",
                    label,
                    str(state.get("problem") or "not ready"),
                    str(state.get("fix") or "run defenseclaw doctor"),
                )
            )
        if not managed and str(up.get("base_url") or "").strip():
            rows.append(agent_config_row(cfg, name, up))
        signing = state.get("signing") if isinstance(state, dict) else None
        rows.extend(signing_rows(name, up, signing if live is not None and isinstance(signing, dict) else None))
    held = port_held_row(cfg)
    if held is not None:
        rows.append(held)
    if platform == "darwin" and not managed:
        shared = shared_mac_row(connectors, users_dir)
        if shared is not None:
            rows.append(shared)
    return rows
