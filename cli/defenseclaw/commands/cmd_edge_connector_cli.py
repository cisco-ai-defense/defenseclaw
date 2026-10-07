# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw edge-connector -- Manage edge devices, push policies, and monitor edge connector health."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import click
import requests as req_lib

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

_TOKEN_ENV = "DCLAW_FLEET_API_TOKEN"
_FLEET_PREFIX = "/api/v1/fleet"
_CONN_ERR = "Cannot reach the gateway. Is it running?"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_fleet_token() -> str:
    """Read DCLAW_FLEET_API_TOKEN from env or ~/.defenseclaw/.env."""
    token = os.environ.get(_TOKEN_ENV, "").strip()
    if token:
        return token
    env_path = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    if not env_path.is_file():
        return ""
    try:
        for line in env_path.read_text().splitlines():
            s = line.strip()
            for prefix in (f"{_TOKEN_ENV}=", f"export {_TOKEN_ENV}="):
                if s.startswith(prefix):
                    return s.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


class _Fleet:
    """Thin HTTP wrapper for /api/v1/fleet/* endpoints."""

    def __init__(self, session, base_url: str, timeout: int) -> None:
        self._s = session
        self._base = f"{base_url}{_FLEET_PREFIX}"
        self.timeout = timeout

    def get(self, path: str) -> req_lib.Response:
        return self._s.get(f"{self._base}{path}", timeout=self.timeout, allow_redirects=False)

    def post(self, path: str, body: dict | None = None) -> req_lib.Response:
        return self._s.post(f"{self._base}{path}", json=body or {}, timeout=self.timeout, allow_redirects=False)

    def delete(self, path: str) -> req_lib.Response:
        return self._s.delete(f"{self._base}{path}", timeout=self.timeout, allow_redirects=False)


def _client(app: AppContext) -> _Fleet:
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host
    cfg = app.cfg
    gw = getattr(cfg, "gateway", None)
    port = int(getattr(gw, "api_port", 0) or 0) if gw else 0
    if port <= 0:
        ux.err("Edge Connector API not available -- gateway API port is not configured.")
        ux.echo("  Run 'defenseclaw setup edge-connector' first.")
        raise SystemExit(1)
    resolver = getattr(gw, "resolved_token", None)
    try:
        token = resolver() if callable(resolver) else str(getattr(gw, "token", "") or "")
    except Exception:  # noqa: BLE001
        token = ""
    orch = OrchestratorClient(
        host=gateway_api_client_host(cfg), port=port,
        token=(_load_fleet_token() or token or "").strip(), timeout=10,
    )
    return _Fleet(orch._session, orch.base_url, orch.timeout)


def _check(resp: req_lib.Response, ctx: str) -> None:
    if 200 <= resp.status_code < 300:
        return
    if resp.status_code in (404, 503):
        ux.err(f"Edge Connector API not available ({resp.status_code}). Run 'defenseclaw setup edge-connector' first.")
        raise SystemExit(1)
    detail = ""
    try:
        b = resp.json()
        detail = str(b.get("error") or b.get("message") or "") if isinstance(b, dict) else ""
    except (ValueError, KeyError):
        pass
    ux.err(f"{ctx}: HTTP {resp.status_code}" + (f" -- {detail}" if detail else ""))
    raise SystemExit(1)


def _body(resp: req_lib.Response):
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
def edge_connector_group() -> None:
    """Manage edge connector devices, policies, and fleet health."""


@edge_connector_group.command("devices")
@click.option("--json", "as_json", is_flag=True, help="Emit device list as JSON.")
@pass_ctx
def devices(app: AppContext, as_json: bool) -> None:
    """List all registered fleet devices with their status."""
    c = _client(app)
    try:
        resp = c.get("/devices")
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, "Failed to list devices")
    raw = _body(resp)
    items = raw if isinstance(raw, list) else (raw.get("devices", []) if isinstance(raw, dict) else [])
    if as_json:
        click.echo(json.dumps(items, indent=2))
        return
    if not items:
        ux.echo("  No devices registered.")
        ux.echo(ux.dim("  Register a device: defenseclaw edge-connector register <device-id>"))
        return
    ux.echo(ux.bold(f"  {'DEVICE ID':<28s} {'STATUS':<12s} {'LAST SEEN'}"))
    ux.echo(f"  {'─' * 28} {'─' * 12} {'─' * 24}")
    for d in items:
        did = str(d.get("device_id") or d.get("id") or "?")
        st = str(d.get("status") or "unknown")
        ls = str(d.get("last_seen") or d.get("last_heartbeat") or "—")
        color = "green" if st.lower() in ("online", "active", "healthy") else "yellow"
        ux.echo(f"  {did:<28s} {ux._style(st, fg=color):<22s} {ls}")


def _compose_device_id(device_id: str, tenant_id: int, fleet_id: int) -> str:
    """Compose a full 64-bit device ID from short ID + tenant/fleet.

    If *device_id* is already a large integer (>= 2^32), it is assumed to be
    the composite ID and returned as-is.  Otherwise the same formula the Go
    manager uses is applied: ``(tenantID << 48) | (fleetID << 32) | deviceID``.
    """
    try:
        raw = int(device_id)
    except ValueError:
        return device_id  # non-numeric -- pass through and let the API decide
    if raw < (1 << 32):
        raw = (tenant_id << 48) | (fleet_id << 32) | raw
    return str(raw)


@edge_connector_group.command("device")
@click.argument("device_id")
@click.option("--tenant-id", default=1, type=int, help="Tenant ID for composing the full device ID (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Fleet ID for composing the full device ID (default 1).")
@click.option("--json", "as_json", is_flag=True, help="Emit device details as JSON.")
@pass_ctx
def device_detail(app: AppContext, device_id: str, tenant_id: int, fleet_id: int, as_json: bool) -> None:
    """Show detailed information for a single device."""
    full_id = _compose_device_id(device_id, tenant_id, fleet_id)
    c = _client(app)
    try:
        resp = c.get(f"/devices/{full_id}")
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    if resp.status_code == 404:
        ux.err(f"Device '{device_id}' not found (looked up as {full_id}).")
        raise SystemExit(1)
    _check(resp, f"Failed to get device '{device_id}'")
    data = _body(resp) or {}
    if as_json:
        click.echo(json.dumps(data, indent=2))
        return
    ux.echo(ux.bold(f"  Device: {full_id}"))
    for key in ("status", "last_seen", "last_heartbeat", "firmware", "policy_version",
                "ip_address", "hostname", "tags", "registered_at"):
        val = data.get(key)
        if val is not None:
            ux.echo(f"    {ux.dim(f'{key}:'.ljust(20))}{val}")


@edge_connector_group.command("register")
@click.argument("device_id", type=int)
@click.option("--tenant-id", default=1, type=int, help="Tenant ID (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Fleet ID (default 1).")
@click.option("--tags", default="", help="Comma-separated tags for the device.")
@click.option("--json", "as_json", is_flag=True, help="Emit result as JSON.")
@pass_ctx
def register(app: AppContext, device_id: int, tenant_id: int, fleet_id: int, tags: str, as_json: bool) -> None:
    """Manually register a device in the fleet."""
    c = _client(app)
    payload: dict = {"device_id": device_id, "tenant_id": tenant_id, "fleet_id": fleet_id}
    if tags:
        payload["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    try:
        resp = c.post("/devices", payload)
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, f"Failed to register device '{device_id}'")
    if as_json:
        click.echo(json.dumps(_body(resp) or {"status": "registered"}, indent=2))
        return
    ux.ok(f"Device '{device_id}' registered.")


@edge_connector_group.command("decommission")
@click.argument("device_id", type=int)
@click.option("--tenant-id", default=1, type=int, help="Tenant ID (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Fleet ID (default 1).")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Skip confirmation prompt.")
@pass_ctx
def decommission(app: AppContext, device_id: int, tenant_id: int, fleet_id: int, assume_yes: bool) -> None:
    """Decommission a single device from the fleet."""
    if not assume_yes and not click.confirm(f"Decommission device '{device_id}'? This cannot be undone"):
        ux.echo("Cancelled.")
        return
    c = _client(app)
    try:
        resp = c.post("/devices/decommission-batch", {
            "devices": [{"tenant_id": tenant_id, "fleet_id": fleet_id, "device_id": device_id}],
        })
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, f"Failed to decommission device '{device_id}'")
    data = _body(resp) or {}
    not_found = data.get("not_found", [])
    if not_found:
        ux.err(f"Device '{device_id}' not found.")
        raise SystemExit(1)
    ux.ok(f"Device '{device_id}' decommissioned.")


@edge_connector_group.command("decommission-batch")
@click.option(
    "--ids", required=True,
    help="Comma-separated device IDs (format: tenant:fleet:device or just device_id).",
)
@click.option("--tenant-id", default=1, type=int, help="Default tenant ID when using plain device IDs (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Default fleet ID when using plain device IDs (default 1).")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Skip confirmation prompt.")
@pass_ctx
def decommission_batch(app: AppContext, ids: str, tenant_id: int, fleet_id: int, assume_yes: bool) -> None:
    """Decommission multiple devices at once."""
    raw_ids = [d.strip() for d in ids.split(",") if d.strip()]
    if not raw_ids:
        ux.err("No device IDs provided.")
        raise SystemExit(1)
    devices = []
    for raw in raw_ids:
        parts = raw.split(":")
        try:
            if len(parts) == 3:
                devices.append({"tenant_id": int(parts[0]), "fleet_id": int(parts[1]), "device_id": int(parts[2])})
            else:
                devices.append({"tenant_id": tenant_id, "fleet_id": fleet_id, "device_id": int(raw)})
        except ValueError:
            raise click.UsageError(f"Invalid device ID '{raw}' -- expected an integer or tenant:fleet:device format.")
    if not assume_yes and not click.confirm(f"Decommission {len(devices)} device(s)? This cannot be undone"):
        ux.echo("Cancelled.")
        return
    c = _client(app)
    try:
        resp = c.post("/devices/decommission-batch", {"devices": devices})
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, "Failed to decommission devices")
    data = _body(resp) or {}
    decommissioned = data.get("decommissioned", 0)
    not_found_ids = data.get("not_found", [])
    if decommissioned > 0:
        ux.ok(f"{decommissioned} device(s) decommissioned.")
    for nf in not_found_ids:
        ux.warn(f"  Not found: {nf}")
    if decommissioned == 0 and not_found_ids:
        ux.err("No devices were decommissioned -- all IDs were not found.")
        raise SystemExit(1)


@edge_connector_group.command("health")
@click.option("--json", "as_json", is_flag=True, help="Emit health summary as JSON.")
@pass_ctx
def health(app: AppContext, as_json: bool) -> None:
    """Show edge connector health summary (online/offline counts)."""
    c = _client(app)
    try:
        resp = c.get("/health")
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, "Failed to fetch edge connector health")
    data = _body(resp) or {}
    if as_json:
        click.echo(json.dumps(data, indent=2))
        return
    fleet = data.get("fleet", data)  # API nests health under "fleet"; fall back to top-level
    online = int(fleet.get("online", 0))
    offline = int(fleet.get("offline", 0))
    total = int(fleet.get("total_devices", online + offline))
    ux.section("Edge Connector Health")
    ux.echo(f"  Total devices:   {total}")
    ux.echo(f"  Online:          {ux._style(str(online), fg='green')}")
    ux.echo(f"  Offline:         {ux._style(str(offline), fg='yellow') if offline else '0'}")
    if fleet.get("degraded"):
        ux.echo(f"  Degraded:        {fleet['degraded']}")
    if fleet.get("lockdown"):
        ux.echo(f"  Lockdown:        {fleet['lockdown']}")
    if data.get("last_check"):
        ux.echo(f"  Last check:      {data['last_check']}")


@edge_connector_group.command("command")
@click.argument("device_id")
@click.argument("cmd", type=click.Choice(["reboot", "policy-refresh", "diagnostics"]))
@click.option("--tenant-id", default=1, type=int, help="Tenant ID for composing the full device ID (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Fleet ID for composing the full device ID (default 1).")
@click.option("--json", "as_json", is_flag=True, help="Emit result as JSON.")
@pass_ctx
def send_command(app: AppContext, device_id: str, cmd: str, tenant_id: int, fleet_id: int, as_json: bool) -> None:
    """Send a command to a device (reboot, policy-refresh, diagnostics)."""
    full_id = _compose_device_id(device_id, tenant_id, fleet_id)
    c = _client(app)
    try:
        resp = c.post(f"/devices/{full_id}/command", {"command": cmd})
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    if resp.status_code == 404:
        ux.err(f"Device '{device_id}' not found (looked up as {full_id}).")
        raise SystemExit(1)
    _check(resp, f"Failed to send '{cmd}' to '{device_id}'")
    if as_json:
        click.echo(json.dumps(_body(resp) or {"status": "sent"}, indent=2))
        return
    ux.ok(f"Command '{cmd}' sent to device '{full_id}'.")


# ---------------------------------------------------------------------------
# edge connector policy (subgroup)
# ---------------------------------------------------------------------------

@edge_connector_group.group("policy")
def edge_connector_group_policy() -> None:
    """Manage fleet-wide policies -- push, list versions, emergency commands."""


@edge_connector_group_policy.command("push")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--tenant-id", default=None, type=int, help="Tenant ID (overrides YAML metadata; default 1).")
@click.option("--fleet-id", default=None, type=int, help="Fleet ID (overrides YAML metadata; default 1).")
@click.option("--json", "as_json", is_flag=True, help="Emit result as JSON.")
@pass_ctx
def policy_push(app: AppContext, file: str, tenant_id: int | None, fleet_id: int | None, as_json: bool) -> None:
    """Push a edge connector policy file (compile, sign, distribute)."""
    import yaml
    try:
        with open(file) as fh:
            raw_yaml = fh.read()
            data = yaml.safe_load(raw_yaml) or {}
    except Exception as exc:
        ux.err(f"Failed to read policy file: {exc}")
        raise SystemExit(1)
    meta = data.get("metadata", {}) or {}
    payload = {"policy_yaml": raw_yaml,
               "profile": str(meta.get("profile", "standard")),
               "tenant_id": tenant_id if tenant_id is not None else int(meta.get("tenant_id", 1)),
               "fleet_id": fleet_id if fleet_id is not None else int(meta.get("fleet_id", 1))}
    c = _client(app)
    try:
        resp = c.post("/policy/push", payload)
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, "Failed to push edge connector policy")
    result = _body(resp) or {}
    if as_json:
        click.echo(json.dumps(result, indent=2))
        return
    ux.ok(f"Edge Connector policy '{meta.get('name', os.path.basename(file))}' {result.get('status', 'distributed')}.")


@edge_connector_group_policy.command("versions")
@click.option("--tenant-id", default=1, type=int, help="Tenant ID (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Fleet ID (default 1).")
@click.option("--json", "as_json", is_flag=True, help="Emit versions as JSON.")
@pass_ctx
def policy_versions(app: AppContext, tenant_id: int, fleet_id: int, as_json: bool) -> None:
    """List edge connector policy versions."""
    c = _client(app)
    try:
        resp = c.get(f"/policy/versions?tenant_id={tenant_id}&fleet_id={fleet_id}")
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, "Failed to list policy versions")
    raw = _body(resp)
    items = raw if isinstance(raw, list) else (raw.get("versions", []) if isinstance(raw, dict) else [])
    if as_json:
        click.echo(json.dumps(items, indent=2))
        return
    if not items:
        ux.echo("  No policy versions found.")
        return
    ux.echo(ux.bold(f"  {'VERSION':<12s} {'STATUS':<12s} {'PUSHED AT'}"))
    ux.echo(f"  {'─' * 12} {'─' * 12} {'─' * 24}")
    for v in items:
        ux.echo(f"  {str(v.get('version') or v.get('id') or '?'):<12s} "
                f"{str(v.get('status') or 'unknown'):<12s} "
                f"{str(v.get('pushed_at') or v.get('created_at') or '—')}")


@edge_connector_group_policy.command("emergency")
@click.argument("cmd", type=click.Choice(["block-all", "enter-lockdown", "revoke-sessions", "force-sync"]))
@click.option("--tenant-id", default=1, type=int, help="Tenant ID (default 1).")
@click.option("--fleet-id", default=1, type=int, help="Fleet ID (default 1).")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Skip confirmation prompt.")
@pass_ctx
def policy_emergency(app: AppContext, cmd: str, tenant_id: int, fleet_id: int, assume_yes: bool) -> None:
    """Send an emergency fleet command (block-all, enter-lockdown, revoke-sessions, force-sync)."""
    if not assume_yes and not click.confirm(f"Send emergency command '{cmd}' to the entire fleet?"):
        ux.echo("Cancelled.")
        return
    # API expects uppercase underscore command names (e.g. FLUSH_CACHE)
    api_cmd = cmd.upper().replace("-", "_")
    c = _client(app)
    try:
        resp = c.post("/policy/emergency", {"command": api_cmd, "tenant_id": tenant_id, "fleet_id": fleet_id})
    except req_lib.ConnectionError:
        ux.err(_CONN_ERR)
        raise SystemExit(1)
    _check(resp, f"Failed to send emergency command '{cmd}'")
    data = _body(resp) or {}
    ux.ok(f"Emergency command '{cmd}' {data.get('status', 'sent')} (affected: {data.get('affected_devices', 'all')}).")


# ---------------------------------------------------------------------------
# Helpers for edge connector test
# ---------------------------------------------------------------------------


def _load_env_var(key: str) -> str:
    """Read a value from the environment or from ~/.defenseclaw/.env."""
    val = os.environ.get(key, "").strip()
    if val:
        return val
    env_path = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    if not env_path.is_file():
        return ""
    try:
        for line in env_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{key}="):
                return stripped.split("=", 1)[1].strip().strip("'\"")
            if stripped.startswith(f"export {key}="):
                return stripped.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return ""


def _check_broker(url: str) -> bool:
    """Try a TCP connect to the MQTT broker; return True on success."""
    try:
        p = urlparse(url)
        with socket.create_connection((p.hostname or "127.0.0.1", p.port or 1883), timeout=5):
            return True
    except (OSError, ValueError):
        return False


def _heartbeat_age(last_seen: str) -> str:
    """Human-readable age from an ISO timestamp."""
    from datetime import datetime, timezone
    try:
        ts = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        secs = int((datetime.now(timezone.utc) - ts).total_seconds())
        if secs < 60:
            return f"{secs}s ago"
        if secs < 3600:
            return f"{secs // 60}m ago"
        return f"{secs // 3600}h ago"
    except (ValueError, TypeError):
        return "unknown"


def _status_line(label: str, passed: bool, detail: str) -> None:
    """Print a fixed-width status line with colored marker."""
    padded = f"{label}:".ljust(12)
    if passed:
        ux.ok(f"{padded}{detail}")
    else:
        ux.err(f"{padded}{detail}")


# ---------------------------------------------------------------------------
# edge connector test
# ---------------------------------------------------------------------------


@edge_connector_group.command("test")
@click.option("--device-id", default=None, help="Specific device ID to verify.")
@click.option(
    "--broker-url", default=None,
    help="MQTT broker URL (reads DCLAW_MQTT_BROKER_URL from env if omitted).",
)
@click.option("--timeout", default=10, type=int, help="Per-check timeout in seconds.")
@click.option("--json", "as_json", is_flag=True, help="Emit test results as JSON.")
@pass_ctx
def test_fleet(
    app: AppContext,
    device_id: str | None,
    broker_url: str | None,
    timeout: int,
    as_json: bool,
) -> None:
    """Test the full edge-connector fleet pipeline.

    Checks:\n
      1. Gateway fleet API is reachable (GET /health)\n
      2. MQTT broker accepts TCP connections\n
      3. Devices registered and their count\n
      4. Last heartbeat age for online devices\n
      5. Policy distribution status\n

    Prints a colored summary of each component's health.
    """
    results: dict = {
        "gateway": {"status": "unknown"},
        "broker": {"status": "skipped"},
        "devices": {"status": "skipped"},
        "policy": {"status": "skipped"},
    }
    all_ok = True

    # 1. Gateway health ---------------------------------------------------
    c = _client(app)
    health_data: dict | None = None
    try:
        resp = c.get("/health")
        if 200 <= resp.status_code < 300:
            health_data = _body(resp) or {}
            results["gateway"] = {"status": "ok", **health_data}
        else:
            results["gateway"] = {"status": "error", "http_status": resp.status_code}
            all_ok = False
    except req_lib.ConnectionError:
        results["gateway"] = {"status": "unreachable"}
        all_ok = False
    except Exception as exc:  # noqa: BLE001
        results["gateway"] = {"status": "error", "detail": str(exc)}
        all_ok = False

    # 2. Broker reachable? ------------------------------------------------
    if broker_url is None:
        broker_url = (
            _load_env_var("DCLAW_MQTT_BROKER_URL")
            or _load_env_var("DCLAW_BROKER_URL")
            or ""
        )
    if broker_url:
        bok = _check_broker(broker_url)
        results["broker"] = {"status": "ok" if bok else "unreachable", "url": broker_url}
        if not bok:
            all_ok = False
    else:
        results["broker"] = {
            "status": "not_configured",
            "reason": "no broker URL (set DCLAW_MQTT_BROKER_URL or use --broker-url)",
        }
        all_ok = False

    # 3. Devices registered? ----------------------------------------------
    devices: list[dict] = []
    online = offline = 0
    if health_data is not None:
        try:
            dev_resp = c.get("/devices")
            if 200 <= dev_resp.status_code < 300:
                raw = _body(dev_resp)
                devices = (
                    raw if isinstance(raw, list)
                    else (raw.get("devices", []) if isinstance(raw, dict) else [])
                )
                for d in devices:
                    if str(d.get("status") or "offline").lower() in ("online", "active", "healthy"):
                        online += 1
                    else:
                        offline += 1
                results["devices"] = {
                    "status": "ok" if devices else "empty",
                    "online": online, "offline": offline, "total": len(devices),
                }
                if not devices:
                    all_ok = False
        except Exception:  # noqa: BLE001
            results["devices"] = {"status": "error", "detail": "could not query device list"}
            all_ok = False

    # 4. Heartbeat freshness ----------------------------------------------
    stale: list[str] = []
    if devices:
        for d in devices:
            ls = d.get("last_heartbeat") or d.get("last_seen")
            if ls and "h ago" in _heartbeat_age(str(ls)):
                stale.append(str(d.get("device_id") or d.get("id") or "?"))
        if stale:
            results["devices"]["stale_heartbeats"] = stale

    # Specific device check
    if device_id:
        try:
            dr = c.get(f"/devices/{device_id}")
            if dr.status_code == 404:
                results["device_check"] = {"status": "not_found", "device_id": device_id}
                all_ok = False
            elif 200 <= dr.status_code < 300:
                ds = str((_body(dr) or {}).get("status") or "unknown").lower()
                results["device_check"] = {
                    "status": "online" if ds in ("online", "active", "healthy") else ds,
                    "device_id": device_id,
                }
                if ds not in ("online", "active", "healthy"):
                    all_ok = False
        except Exception as exc:  # noqa: BLE001
            results["device_check"] = {"status": "error", "detail": str(exc)}
            all_ok = False

    # 5. Policy distribution status ---------------------------------------
    if health_data is not None:
        try:
            pr = c.get("/policy/status")
            if 200 <= pr.status_code < 300:
                pd = _body(pr) or {}
                ver = pd.get("version")
                if ver:
                    dist = int(pd.get("distributed_count", 0))
                    tot = len(devices) or int(pd.get("total_devices", 0))
                    results["policy"] = {
                        "status": "ok", "version": ver,
                        "distributed": dist, "total_devices": tot,
                    }
                else:
                    results["policy"] = {"status": "no_policy"}
                    all_ok = False
            elif pr.status_code == 404:
                results["policy"] = {"status": "no_policy"}
        except Exception:  # noqa: BLE001
            results["policy"] = {"status": "error"}

    # --- Output ----------------------------------------------------------
    if as_json:
        results["all_ok"] = all_ok
        click.echo(json.dumps(results, indent=2))
        if not all_ok:
            raise SystemExit(1)
        return

    ux.section("Edge Connector Pipeline Test")

    # Gateway
    gw = results["gateway"]
    if gw["status"] == "ok":
        _status_line("Gateway", True, "running (fleet API mounted)")
    else:
        _status_line("Gateway", False, f"not reachable ({gw.get('detail') or gw['status']})")

    # Broker
    br = results["broker"]
    if br["status"] == "ok":
        _status_line("Broker", True, f"reachable at {broker_url}")
    elif br["status"] == "not_configured":
        _status_line("Broker", False, "no broker URL configured (set DCLAW_MQTT_BROKER_URL)")
    else:
        _status_line("Broker", False, f"cannot connect to {broker_url}")

    # Devices
    dv = results.get("devices", {})
    if dv.get("status") == "ok":
        parts = []
        if online:
            parts.append(f"{online} online")
        if offline:
            parts.append(f"{offline} offline")
        _status_line("Devices", True, ", ".join(parts))
        if stale:
            ux.warn(f"  Stale heartbeats (>1h): device(s) {', '.join(stale)}")
    elif dv.get("status") == "empty":
        _status_line("Devices", False, "no devices registered")
    elif health_data is not None:
        _status_line("Devices", False, dv.get("detail", "could not query device list"))

    # Specific device
    dc = results.get("device_check")
    if dc:
        if dc["status"] in ("online", "active", "healthy"):
            ux.ok(f"  Device {device_id}: {dc['status']}")
        elif dc["status"] == "not_found":
            ux.err(f"  Device {device_id}: not found")
        else:
            ux.warn(f"  Device {device_id}: {dc['status']}")

    # Policy
    pol = results.get("policy", {})
    if pol.get("status") == "ok":
        v = pol.get("version", "?")
        d = pol.get("distributed", 0)
        t = pol.get("total_devices", 0)
        _status_line("Policy", True, f"v{v} distributed to {d}/{t} devices")
    elif pol.get("status") == "no_policy":
        _status_line("Policy", False, "no policy loaded (run: defenseclaw policy load <file>)")
    elif health_data is not None:
        _status_line("Policy", False, pol.get("detail", "could not query policy status"))

    # Summary
    ux.echo()
    if all_ok:
        ux.ok("All fleet pipeline checks passed.")
    else:
        ux.warn("Some checks failed. Review the output above.")
        raise SystemExit(1)
