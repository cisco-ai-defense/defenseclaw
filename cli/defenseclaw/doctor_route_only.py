# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor and status rows for route-only mode (S1 DESIGN 7.2, 7.4, 16.2, 17.1).

The gateway publishes per-connector readiness in /health
``routing.details.route_only``: custody (managed macOS and Windows forward
no agent credential), the gateway credential in use and the Bedrock signing
checks. These helpers turn it into rows. Without the verified gateway of
this account they check what can be checked offline (agent config, custody
coverage, AWS profile, region) and say why live readiness is missing.
Shared by ``defenseclaw doctor`` and ``defenseclaw status``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Any

from defenseclaw import routing_route_only as ro

# Gateway Bedrock signing modes (internal/gateway/routeonly_sigv4.go).
SIGNING_AUTH = ("profile", "instance_role", "iam_credentials")
PORT_HELD_MARK = ".route-port-held.json"
_DEFAULT_ORIGINS = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com"}
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
# The gateway states route_only_rows knows besides a verified one ("").
GATEWAY_FOREGROUND, GATEWAY_FOREIGN, GATEWAY_UNVERIFIED = "foreground", "foreign", "unverified"


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


def restore_direct(connector: str) -> str:
    """How to give connector its direct model access back, gateway running or not."""
    return (
        f"remove {connector} from routing.route_only.connectors in config.yaml, then run "
        f"defenseclaw-gateway connector route-restore --connector {connector}"
    )


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


def _shown_url(raw: str) -> str:
    """A configured URL as doctor prints it: the loopback render in full,
    any other URL as its origin only (a corporate URL can carry a token)."""
    host = (urllib.parse.urlsplit(raw).hostname or "").lower()
    return raw if host in _LOOPBACK_HOSTS else (origin(raw) or "set")


def _active_connector(cfg: Any, connector: str) -> bool | None:
    """Whether connector is set up (the gateway renders only those); None if unknown."""
    active = getattr(cfg, "active_connectors", None)
    if not callable(active):
        return None
    try:
        return connector in active()
    except Exception:  # noqa: BLE001 - a doctor row must not stop on it
        return None


def _drift_fix(cfg: Any, connector: str, signing_failed: bool) -> str:
    """Why the gateway left the agent config alone, and the fix that clears the row."""
    if _active_connector(cfg, connector) is False:
        from defenseclaw.hook_integrity import setup_command

        return (
            f"{connector} is not a set-up connector, so the gateway renders nothing for it: "
            f"set it up with {setup_command(connector)}"
        )
    if signing_failed:
        return (
            f"the gateway renders it once Bedrock signing works: fix the failing Route-only {connector} "
            "Bedrock rows (the agent keeps its direct access until then)"
        )
    return (
        "restart the gateway to render it again from config.yaml: defenseclaw-gateway restart, then restart the agent"
    )


def agent_config_row(cfg: Any, connector: str, upstream: dict[str, Any], *, signing_failed: bool = False) -> Row:
    """Whether the agent config DefenseClaw renders from config.yaml is in place (OSS).
    A broken agent file gives a warn row for that connector only."""
    label = f"Route-only {connector} agent config"
    want = _expected_base_url(cfg, connector)
    try:
        if connector == "claudecode":
            _env, own, _settings = ro._claude_settings()
            key = (
                "ANTHROPIC_BEDROCK_BASE_URL" if upstream.get("api") in ("converse", "invoke") else "ANTHROPIC_BASE_URL"
            )
            got = own.get(key, "").strip().rstrip("/")
            if got != want:
                shown = _shown_url(got) if got else "unset"
                detail = f"settings.json env {key} is {shown}, not {want}"
                return Row("warn", label, detail, _drift_fix(cfg, connector, signing_failed))
            if ro.ROUTE_HEADER not in own.get("ANTHROPIC_CUSTOM_HEADERS", ""):
                detail = f"settings.json env ANTHROPIC_CUSTOM_HEADERS has no {ro.ROUTE_HEADER} line"
                return Row("warn", label, detail, _drift_fix(cfg, connector, signing_failed))
            return Row("pass", label, f"settings.json points at {want}")
        if connector == "codex":
            doc = ro.codex_config()
            table = (doc.get("model_providers") or {}).get(ro.CODEX_ROUTE_PROVIDER) or {}
            got = str(table.get("base_url") or "").strip().rstrip("/")
            if doc.get("model_provider") != ro.CODEX_ROUTE_PROVIDER or got != want:
                detail = f"config.toml model_provider is not {ro.CODEX_ROUTE_PROVIDER} at {want}"
                return Row("warn", label, detail, _drift_fix(cfg, connector, signing_failed))
            return Row("pass", label, f"config.toml points at {want}")
    except (ro.RouteOnlyError, OSError, ValueError, AttributeError, TypeError) as exc:
        text = " ".join(str(exc).split())[:200]
        return Row(
            "warn",
            label,
            f"could not read the {connector} agent config: {text}",
            "fix the file (or move it aside); the gateway renders it again from config.yaml",
        )
    return Row("skip", label, "no route-only render for this connector")


def _host_region(base_url: str) -> str:
    host = (urllib.parse.urlsplit(str(base_url or "").strip()).hostname or "").lower()
    match = ro._BEDROCK_RUNTIME_HOST.search(host)
    return match.group(1) if match else ""


def signing_rows(connector: str, upstream: dict[str, Any], live: dict[str, Any] | None) -> list[Row]:
    """Gateway Bedrock signing: signer, region, profile and credential rows.
    live is the signing block the gateway reports (None: no live state)."""
    bedrock = upstream.get("bedrock") or {}
    auth = str(bedrock.get("auth") or "")
    if auth not in SIGNING_AUTH:
        return []
    label = f"Route-only {connector} Bedrock"
    block = f"routing.route_only.upstreams.{connector}"
    profile = str(bedrock.get("profile") or "default") if auth == "profile" else ""
    rows: list[Row] = []
    if live is None:
        base_url = str(upstream.get("base_url") or "")
        if not ro.bedrock_signable(base_url):
            rows.append(
                Row(
                    "fail",
                    f"{label} signer",
                    f"the gateway signs only for an https bedrock-runtime AWS host, not {_shown_url(base_url)}",
                    f"point {block}.base_url at https://bedrock-runtime.<region>.amazonaws.com, "
                    f"or set {block}.bedrock.auth to passthrough",
                )
            )
        host, region = _host_region(base_url), str(bedrock.get("region") or "").strip()
        if host and region and host != region.lower():
            rows.append(
                Row(
                    "fail",
                    f"{label} region",
                    f"{block}.bedrock.region {region} does not match the upstream host region {host}",
                    f"set {block}.bedrock.region to {host} or remove it",
                )
            )
        elif not (host or region):
            rows.append(
                Row(
                    "fail",
                    f"{label} region",
                    "no region: the upstream host names none and the block sets none",
                    f"set {block}.bedrock.region",
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
                        ""
                        if found
                        else f"create profile {profile} for this account, or change {block}.bedrock.profile",
                    )
                )
        rows.append(Row("skip", f"{label} credential", "not checked: no live gateway state"))
        return rows
    region_ok = bool(live.get("region_ok"))
    if region_ok:
        # The gateway builds its signer only once the region is known.
        rows.append(
            _signing_row(
                f"{label} signer",
                bool(live.get("signer")),
                f"auth {auth}",
                str(live.get("signer_error") or ""),
                f"check {block}.bedrock",
            )
        )
    rows.append(
        _signing_row(
            f"{label} region",
            region_ok,
            str(live.get("region") or ""),
            str(live.get("region_error") or ""),
            f"set {block}.bedrock.region to the region of the upstream host",
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
                    f"create profile {profile} for the gateway account, or change {block}.bedrock.profile",
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


def _port_holder_command(port: int, platform: str) -> str:
    if platform.startswith("win"):
        return (
            f"Get-NetTCPConnection -LocalPort {port} -State Listen | Select-Object OwningProcess, "
            "then Get-Process -Id <pid> -IncludeUserName (PowerShell as an administrator)"
        )
    if platform == "darwin":
        return f"sudo lsof -nP -iTCP:{port} -sTCP:LISTEN"
    return f'sudo ss -ltnp "sport = :{port}"'


def port_held_row(cfg: Any, platform: str = sys.platform) -> Row | None:
    """The mark the OSS gateway leaves when another account held its API
    port (Linux names the uid, Windows does not; internal/gateway/api_port_held.go).
    Gone once the gateway owns the port again and replaced the route key."""
    path = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "hooks", PORT_HELD_MARK)
    try:
        with open(path, encoding="utf-8") as fh:
            mark = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        mark = {}
    uid = mark.get("uid") if isinstance(mark, dict) else None
    who = f"another account (uid {uid})" if isinstance(uid, int) else "another account"
    port = int(getattr(getattr(cfg, "gateway", None), "api_port", 0) or 0)
    return Row(
        "fail",
        "Route-only API port",
        f"{who} held the gateway API port; route-only agents may have sent model calls to it",
        f"find it with: {_port_holder_command(port, platform)}; stop it, then restart the gateway (it replaces "
        "the route credential and renders the agent configs again) and restart the agents",
    )


def mac_accounts() -> list[str] | None:
    """The user accounts of this Mac (uid >= 500, no _service accounts), from
    Directory Services; None when it cannot be read."""
    try:
        out = subprocess.run(
            ["dscl", ".", "-list", "/Users", "UniqueID"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    names = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= 500 and not parts[0].startswith("_"):
            names.append(parts[0])
    return names


def shared_mac_row(connectors: list[str], accounts: list[str] | None = None) -> Row | None:
    """OSS macOS has no port owner reader (DESIGN 17.1): warn on a Mac with
    more than one account."""
    names = mac_accounts() if accounts is None else accounts
    if names is None or len(names) < 2:
        return None
    first = connectors[0] if connectors else "<name>"
    return Row(
        "warn",
        "Route-only on a shared Mac",
        f"{len(names)} accounts on this Mac: while the gateway restarts another account can take its API port "
        "and receive the model credential the agents send",
        f"use route-only on single-user Macs, or restore direct model access: {restore_direct(first)}",
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


def _no_live_row(name: str, label: str, *, gateway: str, managed: bool, holder: str, holder_fix: str) -> Row:
    """The state row of a connector without the live readiness of this
    account verified gateway, by why it is missing."""
    if gateway == GATEWAY_FOREGROUND:
        return Row(
            "skip",
            label,
            "live readiness not checked: this account runs its gateway in the foreground, unverified "
            "(the offline checks follow)",
        )
    if gateway == GATEWAY_UNVERIFIED:
        return Row(
            "skip",
            label,
            "live readiness not checked: the listener on the API port is not verified as this account's gateway "
            "(see the Sidecar API row; the offline checks follow)",
        )
    if gateway == GATEWAY_FOREIGN:
        who = holder or "another process"
        fix = holder_fix or "see the Sidecar API row"
        if not managed:
            fix += f"; or restore direct model access: {restore_direct(name)}"
        return Row(
            "fail",
            label,
            f"the gateway API port is held by {who}, not by this account's gateway: {name} model calls go to it",
            fix,
        )
    if managed:
        return Row(
            "fail",
            label,
            f"the gateway is not running: {name} model calls fail until it is back",
            "the guardian restarts it; ask an administrator if it stays down",
        )
    return Row(
        "fail",
        label,
        f"the gateway is not running: {name} model calls fail until it starts",
        f"start it with defenseclaw-gateway start, or restore direct model access: {restore_direct(name)}",
    )


def route_only_rows(
    cfg: Any,
    health: dict | None,
    *,
    profile: str = "",
    platform: str = sys.platform,
    gateway: str = "",
    holder: str = "",
    holder_fix: str = "",
    accounts: list[str] | None = None,
) -> list[Row]:
    """Every route-only row: one state row per connector, its agent config
    (OSS), gateway Bedrock signing, a held API port and the shared Mac note.

    health is the /health of this account's verified gateway (None: not
    running). gateway says why there is none when the API port answers:
    GATEWAY_FOREGROUND (this account, started in the foreground),
    GATEWAY_FOREIGN (holder holds the port; holder_fix is the Sidecar API
    remediation) or GATEWAY_UNVERIFIED; its health is then not used.
    accounts lists the Mac accounts (None: read them)."""
    connectors, upstreams = ro._route_only(cfg)
    if not connectors:
        return []
    names = ", ".join(connectors)
    managed = profile == "standalone"
    if not getattr(cfg.routing, "enabled", False):
        fix = (
            "the policy bundle lists route-only connectors with routing off; update the bundle"
            if managed
            else "turn routing on (routing.enabled in config.yaml), or remove them from routing.route_only.connectors"
        )
        return [
            Row(
                "warn",
                "Route-only",
                f"{names} listed in routing.route_only.connectors, but routing.enabled is false: not routed",
                fix,
            )
        ]
    live = None if gateway else _live(health)
    custody = custody_host(profile, platform)
    renders = not managed and profile != "secure_client"
    rows: list[Row] = []
    for name in connectors:
        up = upstreams.get(name) or {}
        label = f"Route-only {name}"
        state = live.get(name) if live is not None else None
        if not str(up.get("base_url") or "").strip():
            where = "the policy bundle" if managed else "config.yaml"
            rows.append(
                Row(
                    "fail",
                    label,
                    f"routing.route_only.upstreams.{name} is not set",
                    f"set routing.route_only.upstreams.{name} (base_url and api) in {where}",
                )
            )
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
            else:
                rows.append(
                    _no_live_row(name, label, gateway=gateway, managed=managed, holder=holder, holder_fix=holder_fix)
                )
        elif state is None:
            rows.append(
                Row(
                    "warn",
                    label,
                    f"the running gateway reports no route-only state for {name}",
                    "restart it so it runs this build: defenseclaw-gateway restart; if it still reports none, "
                    "the route-only listener did not start (see the gateway log)",
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
        signing = state.get("signing") if isinstance(state, dict) else None
        signed = signing_rows(name, up, signing if live is not None and isinstance(signing, dict) else None)
        if renders and str(up.get("base_url") or "").strip():
            failed = any(row.tag == "fail" for row in signed)
            rows.append(agent_config_row(cfg, name, up, signing_failed=failed))
        rows.extend(signed)
    held = port_held_row(cfg, platform)
    if held is not None:
        rows.append(held)
    if platform == "darwin" and not managed:
        shared = shared_mac_row(connectors, accounts)
        if shared is not None:
            rows.append(shared)
    return rows
