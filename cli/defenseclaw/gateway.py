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

"""Gateway-related helpers shared by every Click command.

This module hosts two cohesive but independent responsibilities:

* :class:`OrchestratorClient` — the HTTP client the Python CLI uses to
  talk to the running sidecar at ``http://{host}:{api_port}``.  Mirrors
  the endpoints exposed in ``internal/gateway/api.go``.
* :func:`resolve_gateway_binary` — the single source of truth for where
  the Python CLI looks for the ``defenseclaw-gateway`` executable on
  disk.  See the helper's own docstring for the resolution order and
  the UX bug that prompted it.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from functools import lru_cache
from typing import Any
from urllib.parse import quote

import requests

PLUGIN_MUTATION_TIMEOUT = 90
ALERT_DISPOSITION_MIN_TIMEOUT_SECONDS = 30
ALERT_DISPOSITION_MAX_TIMEOUT_SECONDS = 300
ALERT_DISPOSITION_SECONDS_PER_TARGET = 1


def alert_disposition_timeout_seconds(target_count: int) -> int:
    """Return a read timeout that can finish sequential alert-review writes.

    Apply walks each matched alert through a protected-state CAS transaction
    on the audit database. A short client timeout expires before a few hundred
    writes on a large local store finish, and the CLI then reports a generic
    confirmation failure even though the gateway may still be applying.
    """
    count = max(int(target_count), 0)
    return min(
        ALERT_DISPOSITION_MAX_TIMEOUT_SECONDS,
        max(
            ALERT_DISPOSITION_MIN_TIMEOUT_SECONDS,
            ALERT_DISPOSITION_MIN_TIMEOUT_SECONDS + count * ALERT_DISPOSITION_SECONDS_PER_TARGET,
        ),
    )


def gateway_api_client_host(cfg: Any) -> str:
    """Return a connectable host for the configured sidecar API bind."""
    from defenseclaw.config import api_bind_host

    bind = api_bind_host(cfg)
    if bind in {"::", "[::]"}:
        # An unspecified IPv6 bind is reachable on the IPv6 loopback, which is
        # the exact target. But a host can have IPv6 disabled at the kernel or
        # image level while still running this gateway (hardened base images
        # and some container runtimes do), and on those hosts a ``::`` listener
        # is reached through the IPv4 loopback. Only claim ``::1`` when this
        # process can actually open an IPv6 socket; otherwise fall back to the
        # historical 127.0.0.1 rather than emitting an unconnectable host.
        return "::1" if _ipv6_loopback_available() else "127.0.0.1"
    if bind in {"", "0.0.0.0", "*"}:
        return "127.0.0.1"
    return bind


@lru_cache(maxsize=1)
def _ipv6_loopback_available() -> bool:
    """Return whether this process can bind the IPv6 loopback.

    Cached: the answer is a property of the running kernel and cannot change
    within one CLI invocation. Binding port 0 is a purely local operation --
    it sends no traffic and needs no privileges.
    """
    if not getattr(socket, "has_ipv6", False):
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


def _url_host(host: str) -> str:
    """Bracket a bare IPv6 literal for use in an HTTP authority."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _refuse_gateway_redirect(response: requests.Response, **_kwargs: Any) -> requests.Response:
    """Reject every management-channel redirect before callers parse a body."""
    if 300 <= response.status_code < 400:
        raise requests.HTTPError(
            f"gateway response redirect refused ({response.status_code})",
            response=response,
        )
    return response


# ---------------------------------------------------------------------------
# Sandbox API (/api/v1/sandbox/...)
# ---------------------------------------------------------------------------
#
# Mirrors the typed Go client in internal/openshell/sandboxapi. Every non-2xx
# answer carries {"code", "error", "detail", "violation"}; the codes are stable
# machine tokens and "error" is the sentence to show a person.

SANDBOX_API_PREFIX = "/api/v1/sandbox"
SANDBOX_ADMIN_MESSAGE = "blocked by your organization's DefenseClaw policy"
# Lifecycle calls can wait for OpenShell (start, stop, undo, review, delete).
SANDBOX_LIFECYCLE_TIMEOUT = 180
# Activity streams carry a keepalive every 15 seconds.
SANDBOX_STREAM_READ_TIMEOUT = 45

_SANDBOX_STATUS_CODES = {
    400: "invalid_request",
    401: "policy_violation",
    403: "policy_violation",
    404: "not_found",
    409: "conflict",
    502: "upstream_error",
    503: "unavailable",
}


class SandboxAPIError(Exception):
    """A refused or failed sandbox API call, with a message fit for people."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        detail: str = "",
        status: int = 0,
        violation: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message if not detail else f"{message}: {detail}")
        self.code = code
        self.message = message
        self.detail = detail
        self.status = status
        self.violation = dict(violation) if isinstance(violation, Mapping) else None

    @property
    def admin(self) -> bool:
        """Whether an openshell.admin constraint refused the request."""
        return self.code == "admin_violation" or bool(self.violation and self.violation.get("admin"))

    @property
    def unavailable(self) -> bool:
        return self.code in {"unavailable", "disabled"}

    def plain(self) -> str:
        """One line for a status bar or toast; never a stack trace."""
        if self.admin and SANDBOX_ADMIN_MESSAGE not in self.message:
            return f"{SANDBOX_ADMIN_MESSAGE}: {self.message}"
        return self.message


def _sandbox_error(resp: requests.Response) -> SandboxAPIError:
    body: Any = None
    try:
        body = resp.json()
    except ValueError:
        body = None
    code = ""
    message = ""
    detail = ""
    violation = None
    if isinstance(body, Mapping):
        code = str(body.get("code") or "")
        message = str(body.get("error") or "")
        detail = str(body.get("detail") or "")
        raw_violation = body.get("violation")
        violation = raw_violation if isinstance(raw_violation, Mapping) else None
    if not message:
        text = (resp.text or "").strip()
        message = text[:300] if text and not text.startswith("{") else (resp.reason or f"HTTP {resp.status_code}")
    if not code:
        code = _SANDBOX_STATUS_CODES.get(resp.status_code, "internal")
    return SandboxAPIError(code, message, detail=detail, status=resp.status_code, violation=violation)


def parse_sse_events(lines: Iterable[str | bytes]) -> Iterator[dict[str, Any]]:
    """Decode a text/event-stream of sandbox activity events.

    Mirrors ``sandboxapi.ReadEvents``: ``data:`` lines accumulate until a blank
    line dispatches them and comment lines (the keepalive) are skipped. A
    malformed event is skipped rather than ending the stream.
    """
    data: list[str] = []

    def dispatch() -> dict[str, Any] | None:
        if not data:
            return None
        raw = "\n".join(data)
        data.clear()
        try:
            event = json.loads(raw)
        except ValueError:
            return None
        return event if isinstance(event, dict) else None

    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        line = line.rstrip("\r\n")
        if line == "":
            event = dispatch()
            if event is not None:
                yield event
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            value = line[len("data:") :]
            data.append(value[1:] if value.startswith(" ") else value)
    event = dispatch()
    if event is not None:
        yield event


class SandboxActivityStream:
    """An open ``GET /api/v1/sandbox/activity?follow=true`` stream.

    Iterate for events; :meth:`close` (from any thread) ends the iteration.
    """

    def __init__(self, response: requests.Response) -> None:
        self._response = response
        self._closed = False

    def __iter__(self) -> Iterator[dict[str, Any]]:
        try:
            yield from parse_sse_events(self._response.iter_lines(decode_unicode=False))
        except (requests.RequestException, AttributeError, ValueError, OSError) as exc:
            if self._closed:
                return
            raise SandboxAPIError(
                "unavailable", "the activity stream from the DefenseClaw daemon broke off", detail=str(exc)
            ) from exc
        finally:
            self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True
        try:
            self._response.close()
        except Exception:  # noqa: BLE001 - closing a dead socket is best effort
            pass


class GatewayListenerNotOwnedError(requests.ConnectionError):
    """Another account holds this account's loopback API port: no token was sent."""


_LISTENER_OWNER_TTL_SECONDS = 5.0
_listener_owner_cache: dict[tuple[str, int], tuple[float, str]] = {}


def foreign_loopback_listener(host: str, port: int) -> str:
    """Explain a loopback API listener that belongs to another account, or "".

    GAP-1260: the per-user CLI sent this account's gateway token to whatever
    listened on the configured port, so an account that held it (or the old
    port after a move) collected the token. Like ``defenseclaw-gateway
    start``, this names the holder from the kernel's socket tables on Linux,
    or from ``lsof`` on macOS, which lists only this account's sockets. On
    Windows (GAP-1343) the holder is another account's when it is not the
    recorded gateway and this account may not open it. It returns ""
    whenever ownership is unknown, for a non-loopback host, and on a managed
    host, where the gateway is a service of another account by design.
    """
    import ipaddress
    import time

    if not 0 < int(port) <= 65535:
        return ""
    try:
        if not ipaddress.ip_address(str(host).strip("[]")).is_loopback:
            return ""
    except ValueError:
        if str(host).strip().lower() != "localhost":
            return ""
    from defenseclaw.upgrade_shim import _windows_managed_profile, managed_descriptor

    if managed_descriptor() or (os.name == "nt" and _windows_managed_profile()):
        return ""
    key = (str(host), int(port))
    now = time.monotonic()
    cached = _listener_owner_cache.get(key)
    if cached is not None and now - cached[0] < _LISTENER_OWNER_TTL_SECONDS:
        return cached[1]
    if os.name == "nt":
        problem = _windows_foreign_listener(str(host), int(port))
    else:
        problem = _foreign_loopback_listener_uncached(int(port))
    if problem:
        problem = (
            f"{_url_host(str(host))}:{port} is held by {problem}, not by this account's gateway, "
            "so the gateway token was not sent. Run `defenseclaw-gateway start` to see how to "
            "move this account's gateway to a free port"
        )
    _listener_owner_cache[key] = (now, problem)
    return problem


def _windows_foreign_listener(host: str, port: int) -> str:
    """Name another account's process listening on ``port`` on Windows, or "".

    The owner-PID table lists every account's listeners. The holder is this
    account's when it is the gateway recorded in gateway.pid, or a process
    this account may open; a standard account cannot open another account's
    process, so "denied" means another account holds the port.
    """
    from defenseclaw import doctor_gateway as evidence
    from defenseclaw.config import default_data_path

    host = "" if host.strip("[]").casefold() == "localhost" else host
    listener = evidence._windows_listener_evidence(port, host=host)
    if listener.status != "ok" or listener.pid <= 0:
        return ""
    record = evidence.read_pid_record(os.path.join(str(default_data_path()), "gateway.pid"))
    if record.status == "ok" and record.pid == listener.pid:
        return ""
    if evidence._windows_process_evidence(listener.pid).status != "denied":
        return ""
    return f"PID {listener.pid}, a process of another account"


def _foreign_loopback_listener_uncached(port: int, proc_net: str = "/proc/net") -> str:
    own_uid = os.getuid()
    if sys.platform.startswith("linux"):
        from defenseclaw.doctor_gateway import _linux_proc_net_endpoint

        owners: set[int] = set()
        for table in (os.path.join(proc_net, "tcp"), os.path.join(proc_net, "tcp6")):
            try:
                with open(table, encoding="ascii") as stream:
                    rows = stream.readlines()[1:]
            except (OSError, UnicodeError):
                continue
            for row in rows:
                fields = row.split()
                # State 0A is LISTEN; field 7 is the socket owner's uid.
                if len(fields) < 8 or fields[3] != "0A" or not fields[7].isdigit():
                    continue
                endpoint = _linux_proc_net_endpoint(fields[1])
                if endpoint is None or endpoint[1] != port:
                    continue
                if endpoint[0].is_loopback or endpoint[0].is_unspecified:
                    owners.add(int(fields[7]))
        if not owners or own_uid in owners:
            return ""
        uid = min(owners)
        try:
            import pwd

            return f"a process of another account (uid {uid}, {pwd.getpwuid(uid).pw_name})"
        except (ImportError, KeyError):
            return f"a process of another account (uid {uid})"
    if sys.platform == "darwin":
        import subprocess

        from defenseclaw.doctor_gateway import trusted_lsof_path

        lsof = trusted_lsof_path()
        if not lsof:
            return ""
        try:
            proc = subprocess.run(
                [lsof, "-nP", "-a", "-u", str(own_uid), f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if proc.stdout.strip() or proc.returncode not in (0, 1) or proc.stderr.strip():
            return ""
        # lsof lists only this account's sockets: a listener it does not show
        # that still accepts connections belongs to another account.
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            return ""
        return "a process of another account"
    return ""


class _GatewaySession(requests.Session):
    """A session that sends a bearer token only to this account's listener."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self._dc_target = (host, port)

    def send(self, request, **kwargs):  # type: ignore[override]
        if request.headers.get("Authorization") or request.headers.get("X-DC-Auth"):
            problem = foreign_loopback_listener(*self._dc_target)
            if problem:
                raise GatewayListenerNotOwnedError(problem, request=request)
        return super().send(request, **kwargs)


class OrchestratorClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 18970,
        timeout: int = 5,
        token: str = "",
        plugin_timeout: int | None = None,
    ) -> None:
        self.base_url = f"http://{_url_host(host)}:{port}"
        self.timeout = timeout
        self.plugin_timeout = max(timeout, plugin_timeout or PLUGIN_MUTATION_TIMEOUT)
        self._session = _GatewaySession(host, port)
        # This client talks to the operator-selected managed gateway, often on
        # loopback or a local standalone bridge address. Environment proxy
        # discovery can forward both gateway bearer headers to HTTP_PROXY and
        # let the proxy impersonate gateway responses. Keep the management
        # channel direct on every platform.
        self._session.trust_env = False
        # Requests dispatches response hooks before it follows redirects or
        # returns the response to a method. Coupled with allow_redirects=False
        # on every call below, this gives every present and future management
        # endpoint one consistent fail-closed redirect policy.
        self._session.hooks["response"].append(_refuse_gateway_redirect)
        self._session.headers["X-DefenseClaw-Client"] = "python-cli"
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"
            self._session.headers["X-DC-Auth"] = f"Bearer {token}"

    def health(self) -> dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}/health",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict[str, Any]:
        # No per-method redirect check: the session-level ``_refuse_gateway_redirect``
        # hook already raises before any method sees a 3xx response, so a local
        # copy here would be unreachable and would imply — wrongly — that
        # redirect safety is something each new endpoint must remember to add.
        resp = self._session.get(
            f"{self.base_url}/status",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def provider_registry(self) -> dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}/v1/config/providers",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or not isinstance(data.get("providers"), list):
            raise ValueError("sidecar returned a malformed provider registry")
        return data

    def reload_provider_registry(self) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/v1/config/providers/reload",
            json={},
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "ok":
            raise ValueError("sidecar returned a malformed provider reload response")
        return data

    def reload_policy(self) -> dict[str, Any]:
        """POST /policy/reload so the gateway recompiles OPA policy from disk.

        Raises ``requests.HTTPError`` when the gateway rejects the reload
        (e.g. the Rego/data.json no longer compiles) and ``ValueError`` on a
        malformed success body. Connection errors propagate unchanged so
        callers can tell "not running" from "rejected".
        """
        resp = self._session.post(
            f"{self.base_url}/policy/reload",
            json={},
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "reloaded":
            raise ValueError("gateway returned a malformed policy reload response")
        return data

    def acp_profiles(self) -> dict[str, Any]:
        """GET /v1/acp/profiles: the ACP policy the running gateway has loaded."""
        resp = self._session.get(
            f"{self.base_url}/v1/acp/profiles",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("gateway returned a malformed ACP profiles response")
        return data

    def emit_cli_observability(self, payload: Mapping[str, Any]) -> None:
        """Hand one raw Python-CLI fact to the canonical v8 runtime.

        Destination selection, redaction, SQLite persistence, and fanout all
        happen in the gateway. A non-204 response means admission was not
        confirmed and is intentionally surfaced to the caller.
        """
        resp = self._session.post(
            f"{self.base_url}/api/v1/observability/cli",
            json=dict(payload),
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        if resp.status_code != 204:
            raise requests.HTTPError("canonical observability admission was not acknowledged")

    def set_alert_disposition(
        self,
        *,
        operation_id: str,
        audit_db_identity: str,
        disposition: str,
        selector: Mapping[str, Any],
        preview: bool,
        selection_digest: str | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Preview or apply protected alert-review state through the CAS API."""

        payload: dict[str, Any] = {
            "operation_id": operation_id,
            "audit_db_identity": audit_db_identity,
            "disposition": disposition,
            "selector": dict(selector),
            "preview": preview,
        }
        if selection_digest:
            payload["selection_digest"] = selection_digest
        ids = selector.get("ids")
        id_count = len(ids) if isinstance(ids, (list, tuple)) else 0
        request_timeout = max(self.timeout, alert_disposition_timeout_seconds(id_count))
        if timeout is not None:
            request_timeout = max(request_timeout, int(timeout))
        resp = self._session.post(
            f"{self.base_url}/api/v1/alerts/disposition",
            json=payload,
            timeout=request_timeout,
            allow_redirects=False,
        )
        if resp.status_code not in {200, 409, 503}:
            resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("gateway returned a malformed alert disposition response")
        data["_http_status"] = resp.status_code
        return data

    def close(self) -> None:
        self._session.close()

    def disable_skill(self, skill_key: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/skill/disable",
            json={"skillKey": skill_key},
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def enable_skill(self, skill_key: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/skill/enable",
            json={"skillKey": skill_key},
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def patch_config(self, path: str, value: Any) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/config/patch",
            json={"path": path, "value": value},
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def list_skills(self) -> dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}/skills",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def get_tools_catalog(self) -> dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}/tools/catalog",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def disable_plugin(self, plugin_name: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/plugin/disable",
            json={"pluginName": plugin_name},
            timeout=self.plugin_timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def enable_plugin(self, plugin_name: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/plugin/enable",
            json={"pluginName": plugin_name},
            timeout=self.plugin_timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def scan_skill(self, target: str, name: str = "") -> dict[str, Any]:
        """Request a skill scan on the remote sidecar host.

        The sidecar runs the skill-scanner locally against the target path
        on that machine and returns the ScanResult JSON.
        """
        resp = self._session.post(
            f"{self.base_url}/v1/skill/scan",
            json={"target": target, "name": name},
            timeout=120,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def emit_agent_discovery(self, report: dict[str, Any]) -> dict[str, Any]:
        """Emit a sanitized agent-discovery report through the sidecar.

        The caller owns sanitizing local filesystem paths before invoking this
        method. The sidecar endpoint is token-authenticated and fans the report
        into gateway lifecycle telemetry plus OTel metrics/logs.
        """
        resp = self._session.post(
            f"{self.base_url}/api/v1/agents/discovery",
            json=report,
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_usage(self) -> dict[str, Any]:
        resp = self._session.get(
            f"{self.base_url}/api/v1/ai-usage",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def scan_ai_usage(self) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/api/v1/ai-usage/scan",
            json={},
            timeout=120,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_runtime(self) -> dict[str, Any]:
        """Fetch the most recent runtime-plane snapshot.

        The response carries coverage -- how much of the process and
        connection table this run could see -- alongside the findings, so a
        caller cannot render one without the other. A quiet host and a blind
        sensor look identical if you only read the findings.
        """
        resp = self._session.get(
            f"{self.base_url}/api/v1/ai-usage/runtime",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def scan_ai_runtime(self) -> dict[str, Any]:
        """Trigger one immediate runtime-plane poll and return its result."""
        resp = self._session.post(
            f"{self.base_url}/api/v1/ai-usage/runtime/scan",
            json={},
            timeout=120,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_usage_components(self) -> dict[str, Any]:
        """Fetch the deduped components rollup (one row per
        (ecosystem, name, version)).

        The sidecar exposes this view at ``GET /api/v1/ai-usage/components``;
        it folds across every detector + workspace so the CLI can render
        a true "what SDKs and versions are on this fleet" table without
        re-implementing the join.
        """
        resp = self._session.get(
            f"{self.base_url}/api/v1/ai-usage/components",
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_usage_component_locations(self, ecosystem: str, name: str) -> dict[str, Any]:
        """Fetch the locations detail for one component (the rows
        from ``ai_signals`` for the latest scan).

        Powered by ``GET /api/v1/ai-usage/components/{ecosystem}/{name}/locations``;
        when ``ai_discovery.store_raw_local_paths`` is set on the sidecar,
        each row may include a ``raw_path`` field, otherwise
        only basenames + path hashes are returned.

        ``ecosystem`` and ``name`` are URL-encoded with ``safe=""``
        so any character (including ``/``, ``?``, ``#``, ``%``,
        whitespace) round-trips intact through the path. The gateway
        parses the path via ``r.URL.EscapedPath()`` and
        ``url.PathUnescape``s each segment, so a percent-encoded
        slash inside a scoped npm name like ``@anthropic-ai/sdk``
        survives the split and the lookup hits the right row.
        """
        url = f"{self.base_url}/api/v1/ai-usage/components/{quote(ecosystem, safe='')}/{quote(name, safe='')}/locations"
        resp = self._session.get(
            url,
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_usage_component_history(self, ecosystem: str, name: str) -> dict[str, Any]:
        """Fetch up to 50 confidence snapshots for one component
        (most-recent-first) so ``agent components history`` can render
        the trend without recomputing scores.

        ``ecosystem`` and ``name`` are URL-encoded with ``safe=""``
        for the same reason as ``ai_usage_component_locations``.
        """
        url = f"{self.base_url}/api/v1/ai-usage/components/{quote(ecosystem, safe='')}/{quote(name, safe='')}/history"
        resp = self._session.get(
            url,
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_usage_confidence_policy(self, *, source: str = "merged") -> dict[str, Any]:
        """Fetch the active confidence policy.

        ``source`` is forwarded as a query parameter. ``merged``
        returns whatever the engine currently uses (default + any
        operator override deep-merged on top); ``default`` returns
        the embedded baseline so an operator can diff against their
        override.
        """
        resp = self._session.get(
            f"{self.base_url}/api/v1/ai-usage/confidence/policy",
            params={"source": source},
            timeout=self.timeout,
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def ai_usage_validate_confidence_policy(self, yaml_text: str) -> dict[str, Any]:
        """Dry-run a candidate policy YAML against the sidecar's
        loader + validator without writing anything to disk.

        The wire format is a JSON envelope ``{"yaml": "<raw YAML>"}``
        (not a raw YAML body) because the sidecar's CSRF gate rejects
        every non-OTLP POST that doesn't advertise
        ``application/json``. See the matching server comment in
        ``handleAIUsageConfidencePolicyValidate`` for context.

        Always returns 200 OK; the response carries a ``valid``
        boolean and (on failure) an ``error`` message so the CLI can
        exit non-zero with the same diagnostic the loader would
        print.
        """
        resp = self._session.post(
            f"{self.base_url}/api/v1/ai-usage/confidence/policy/validate",
            json={"yaml": yaml_text},
            timeout=self.timeout,
            allow_redirects=False,
        )
        if resp.status_code == 413:
            return {"valid": False, "error": "policy file exceeds size limit"}
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Sandbox API
    # ------------------------------------------------------------------

    def _sandbox_call(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | Sequence[tuple[str, str]] | None = None,
        body: Mapping[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        url = f"{self.base_url}{SANDBOX_API_PREFIX}{path}"
        payload: Any = None
        if method != "GET":
            payload = dict(body or {})
        try:
            resp = self._session.request(
                method,
                url,
                params=params,
                json=payload,
                timeout=timeout or self.timeout,
                allow_redirects=False,
            )
        except requests.HTTPError as exc:
            # The session hook refuses redirects before a body is parsed.
            raise SandboxAPIError(
                "internal", "the DefenseClaw daemon answered with a redirect", detail=str(exc)
            ) from exc
        except requests.ConnectTimeout as exc:
            # Nothing accepted the connection. Windows retries a refused
            # localhost connect for about two seconds, so a stopped daemon
            # shows up there as a connect timeout rather than a refusal.
            raise SandboxAPIError("unavailable", "the DefenseClaw daemon is not reachable", detail=str(exc)) from exc
        except requests.Timeout as exc:
            raise SandboxAPIError(
                "unavailable", "the DefenseClaw daemon did not answer in time", detail=str(exc)
            ) from exc
        except requests.RequestException as exc:
            raise SandboxAPIError("unavailable", "the DefenseClaw daemon is not reachable", detail=str(exc)) from exc
        if not 200 <= resp.status_code < 300:
            raise _sandbox_error(resp)
        try:
            return resp.json()
        except ValueError as exc:
            raise SandboxAPIError("internal", "the DefenseClaw daemon returned a malformed response") from exc

    @staticmethod
    def _sandbox_path(name: str, verb: str = "") -> str:
        path = "/sandboxes/" + quote(name, safe="")
        return f"{path}/{verb}" if verb else path

    @staticmethod
    def _sandbox_object(value: Any, what: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise SandboxAPIError("internal", f"the DefenseClaw daemon returned a malformed {what}")
        return value

    def _sandbox_list(self, value: Any, key: str, what: str) -> list[dict[str, Any]]:
        rows = self._sandbox_object(value, what).get(key)
        if not isinstance(rows, list):
            raise SandboxAPIError("internal", f"the DefenseClaw daemon returned a malformed {what}")
        return [row for row in rows if isinstance(row, dict)]

    def sandbox_status(self) -> dict[str, Any]:
        """``GET /api/v1/sandbox/status``: the sandbox subsystem as a whole."""
        return self._sandbox_object(self._sandbox_call("GET", "/status"), "sandbox status")

    def list_sandboxes(self) -> list[dict[str, Any]]:
        """``GET /api/v1/sandbox/sandboxes``: every DefenseClaw sandbox."""
        return self._sandbox_list(self._sandbox_call("GET", "/sandboxes"), "sandboxes", "sandbox list")

    def get_sandbox(self, name: str) -> dict[str, Any]:
        return self._sandbox_object(self._sandbox_call("GET", self._sandbox_path(name)), "sandbox")

    def stop_sandbox(self, name: str) -> dict[str, Any]:
        """Stop a sandbox; it is kept for a later start or connect."""
        result = self._sandbox_call("POST", self._sandbox_path(name, "stop"), timeout=SANDBOX_LIFECYCLE_TIMEOUT)
        return self._sandbox_object(result, "sandbox")

    def start_sandbox(self, name: str, *, no_snapshot: bool = False, new_snapshot: bool = False) -> dict[str, Any]:
        """Start a stopped sandbox (a new session).

        It takes a fresh snapshot unless ``no_snapshot``, or unless the folder
        still holds an earlier session's changes; ``new_snapshot`` takes one
        even then, and undo no longer reverts those changes.
        """
        body: dict[str, Any] = {}
        if no_snapshot:
            body["no_snapshot"] = True
        if new_snapshot:
            body["new_snapshot"] = True
        result = self._sandbox_call(
            "POST", self._sandbox_path(name, "start"), body=body, timeout=SANDBOX_LIFECYCLE_TIMEOUT
        )
        return self._sandbox_object(result, "sandbox")

    def delete_sandbox(self, name: str, *, keep_snapshot: bool = False) -> dict[str, Any]:
        """Delete a sandbox with its providers, binding and (unless kept) snapshot."""
        body = {"keep_snapshot": True} if keep_snapshot else {}
        result = self._sandbox_call("DELETE", self._sandbox_path(name), body=body, timeout=SANDBOX_LIFECYCLE_TIMEOUT)
        return self._sandbox_object(result, "delete result")

    def undo_sandbox(
        self,
        name: str,
        *,
        preview: bool = False,
        keep_refs: bool = False,
        stop: bool = False,
        restart: bool = False,
    ) -> dict[str, Any]:
        """Restore the project to its pre-session snapshot.

        Undo needs the sandbox stopped: ``stop`` stops a running one first and
        ``restart`` starts it again afterwards. ``preview`` changes nothing.
        """
        flags = (("preview", preview), ("keep_refs", keep_refs), ("stop", stop), ("restart", restart))
        body = {key: True for key, value in flags if value}
        result = self._sandbox_call(
            "POST", self._sandbox_path(name, "undo"), body=body, timeout=SANDBOX_LIFECYCLE_TIMEOUT
        )
        return self._sandbox_object(result, "undo result")

    def review_sandbox(self, name: str, *, diff: bool = False) -> dict[str, Any]:
        """The end-of-session review of a mounted project."""
        body = {"diff": True} if diff else {}
        result = self._sandbox_call(
            "POST", self._sandbox_path(name, "review"), body=body, timeout=SANDBOX_LIFECYCLE_TIMEOUT
        )
        return self._sandbox_object(result, "review")

    def accept_sandbox_changes(
        self, name: str, *, snapshot_created_at: str = "", session: int = 0
    ) -> dict[str, Any]:
        """Record that the user kept the changes on top of a stopped mounted sandbox's undo point.

        Its next start takes a new undo point, whoever starts it.
        ``snapshot_created_at`` names the undo point the changes were
        reviewed against (the sandbox's ``snapshot.created_at``); the daemon
        refuses with ``conflict`` when the sandbox has another one by now.
        ``session`` is the sandbox's ``session`` when they were reviewed; the
        daemon refuses with ``conflict`` when the sandbox was started again
        since.
        """
        body: dict[str, Any] = {"snapshot_created_at": snapshot_created_at} if snapshot_created_at else {}
        if session:
            body["session"] = session
        result = self._sandbox_call(
            "POST", self._sandbox_path(name, "accept"), body=body, timeout=SANDBOX_LIFECYCLE_TIMEOUT
        )
        return self._sandbox_object(result, "sandbox")

    def sandbox_run_log(self, name: str, *, lines: int = 0) -> dict[str, Any]:
        """The log of the sandbox's latest detached run, kept when the daemon last stopped it.

        ``state`` is ``exited`` (with ``exit``) or ``interrupted``, and
        ``log`` the end of the run's output (its last ``lines`` lines when
        given). ``not_found`` when no log was kept.
        """
        params = {"lines": str(lines)} if lines > 0 else None
        result = self._sandbox_call("GET", self._sandbox_path(name, "logs"), params=params)
        return self._sandbox_object(result, "run log")

    def sandbox_approvals(self, sandbox: str = "") -> list[dict[str, Any]]:
        """Pending asks, optionally for one sandbox."""
        params = {"sandbox": sandbox} if sandbox else None
        return self._sandbox_list(self._sandbox_call("GET", "/approvals", params=params), "approvals", "approval list")

    def decide_sandbox_approval(
        self,
        approval_id: str,
        *,
        approve: bool,
        always: bool = False,
        reason: str = "",
    ) -> dict[str, Any]:
        """Approve or reject one ask; ``always`` keeps the decision for future sandboxes."""
        body: dict[str, Any] = {"decision": "approve" if approve else "reject"}
        if always:
            body["always"] = True
        if reason:
            body["reason"] = reason
        result = self._sandbox_call("POST", "/approvals/" + quote(approval_id, safe=""), body=body, timeout=30)
        return self._sandbox_object(result, "approval result")

    def unblock_sandbox_egress(self, host: str, *, sandbox: str = "", always: bool = False) -> dict[str, Any]:
        """Lift an egress block for one sandbox, or with ``always`` for every sandbox."""
        body: dict[str, Any] = {"host": host}
        if sandbox:
            body["sandbox"] = sandbox
        if always:
            body["always"] = True
        result = self._sandbox_call("POST", "/egress/unblock", body=body, timeout=30)
        return self._sandbox_object(result, "unblock result")

    def sandbox_policy_explain(
        self,
        *,
        sandbox: str = "",
        harness: str = "",
        pack: str = "",
        profile: str = "",
        project: str = "",
        copy: bool = False,
        safe: bool = False,
        yolo: bool = False,
        unmask: Sequence[str] = (),
    ) -> dict[str, Any]:
        """The resolved sandbox posture with provenance (``sandbox policy explain``)."""
        texts = (("sandbox", sandbox), ("harness", harness), ("pack", pack), ("profile", profile), ("project", project))
        params: list[tuple[str, str]] = [(key, value) for key, value in texts if value]
        params += [(key, "true") for key, value in (("copy", copy), ("safe", safe), ("yolo", yolo)) if value]
        params += [("unmask", glob) for glob in unmask]
        result = self._sandbox_call("GET", "/policy/explain", params=params or None)
        return self._sandbox_object(result, "policy explanation")

    def sandbox_activity(self, *, since: int = 0, sandbox: str = "") -> list[dict[str, Any]]:
        """Buffered activity events after sequence number ``since``."""
        params: dict[str, str] = {}
        if since > 0:
            params["since"] = str(since)
        if sandbox:
            params["sandbox"] = sandbox
        result = self._sandbox_call("GET", "/activity", params=params or None)
        return self._sandbox_list(result, "events", "activity feed")

    def open_sandbox_activity_stream(
        self,
        *,
        since: int = 0,
        sandbox: str = "",
        read_timeout: float = SANDBOX_STREAM_READ_TIMEOUT,
    ) -> SandboxActivityStream:
        """Open the live activity feed (server-sent events), replaying after ``since``."""
        params: dict[str, str] = {"follow": "true"}
        if since > 0:
            params["since"] = str(since)
        if sandbox:
            params["sandbox"] = sandbox
        try:
            resp = self._session.get(
                f"{self.base_url}{SANDBOX_API_PREFIX}/activity",
                params=params,
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=(self.timeout, read_timeout),
                allow_redirects=False,
            )
        except requests.HTTPError as exc:
            raise SandboxAPIError(
                "internal", "the DefenseClaw daemon answered with a redirect", detail=str(exc)
            ) from exc
        except requests.RequestException as exc:
            raise SandboxAPIError("unavailable", "the DefenseClaw daemon is not reachable", detail=str(exc)) from exc
        if resp.status_code != 200:
            try:
                raise _sandbox_error(resp)
            finally:
                resp.close()
        return SandboxActivityStream(resp)

    def is_running(self) -> bool:
        try:
            self.health()
            return True
        except (requests.RequestException, ValueError):
            return False


# ---------------------------------------------------------------------------
# Binary resolver
# ---------------------------------------------------------------------------
#
# Every caller that needs to shell out to the Go sidecar used to write
# ``shutil.which("defenseclaw-gateway")`` inline and treat a ``None``
# result as "not installed".  That silently misbehaves right after
# ``make all``: the binary is installed at ``~/.local/bin/defenseclaw-
# gateway`` (the ``INSTALL_DIR`` in the ``Makefile``) but the user's
# current shell hasn't picked up the ``PATH`` entry that ``scripts/
# add-to-path.sh`` just appended to their rc file.  Opening a new shell
# (or ``source``ing the rc file) fixes it, but we should not make users
# debug that to run ``defenseclaw tui``.  The helper below centralises
# the lookup and adds a fallback to the canonical install path so the
# CLI stays usable in the very same shell that ran ``make all``.


GATEWAY_BIN_NAME = "defenseclaw-gateway"

_CANONICAL_INSTALL_DIR = os.path.join(os.path.expanduser("~"), ".local", "bin")


def canonical_install_path() -> str:
    """Return the canonical install path written by the installers.

    Exposed so error messages can reference the exact same path instead of
    each hard-coding the string.
    """
    name = GATEWAY_BIN_NAME + (".exe" if os.name == "nt" else "")
    return os.path.join(_CANONICAL_INSTALL_DIR, name)


def resolve_gateway_binary() -> str | None:
    """Return the first resolvable path to the gateway binary, or ``None``.

    Resolution order:

    1. The verified sibling from a native Windows installation.  The native
       launcher supplies ``DEFENSECLAW_INSTALL_ROOT`` only after validating
       install state; this helper additionally requires ``sys.executable`` to
       be that root's embedded Python runtime.  This path deliberately wins
       over the working directory, overrides, and ``PATH`` so an unrelated
       ``defenseclaw-gateway.exe`` cannot shadow the installed service.
    2. ``DEFENSECLAW_GATEWAY_BIN`` — explicit env override used by
       tests, packagers, and vendored distributions that drop the
       binary somewhere non-standard.  Returned verbatim (even when the
       file is missing) so the real ``exec`` error surfaces to the
       caller rather than a generic "not found" from here.
    3. ``shutil.which(GATEWAY_BIN_NAME)`` — honours ``PATH``.  The
       happy path for installed releases and for users whose shell has
       already sourced the updated rc file.
    4. :func:`canonical_install_path` — the ``~/.local/bin`` fallback
       that keeps ``defenseclaw tui`` working in the same shell that
       just ran ``make all``.

    ``None`` only if every option above fails to resolve to a runnable
    file on disk.  Callers own the user-facing error message.
    """
    packaged_root = packaged_windows_install_root()
    if packaged_root:
        # A corroborated package must fail closed when its sibling is missing;
        # never fall through to a working-directory/PATH shadow.
        return packaged_windows_gateway_path()

    override = os.environ.get("DEFENSECLAW_GATEWAY_BIN", "").strip()
    if override:
        return override

    via_path = shutil.which(GATEWAY_BIN_NAME)
    if via_path:
        return via_path

    canonical = canonical_install_path()
    if _is_runnable_file(canonical):
        return canonical

    return None


def resolve_trusted_gateway_binary() -> str | None:
    """Return :func:`resolve_gateway_binary` for helpers whose answer is trusted.

    The canonical config and rule-pack helpers run the gateway binary and act
    on what it prints, and Doctor runs them on every check. On Linux and
    macOS a binary found on ``PATH`` or in ``~/.local/bin`` must pass the
    custody check the gateway lifecycle uses: held only by root or this
    account, with no group- or world-writable file or parent directory. A
    path another account could replace was run as it was. An explicit
    ``DEFENSECLAW_GATEWAY_BIN`` (a ``.env`` cannot set it) and the verified
    Windows package sibling are used as they are.

    Raises :class:`defenseclaw.file_permissions.UnsafePathError` for a binary
    that fails the check.
    """

    binary = resolve_gateway_binary()
    if not binary or os.name == "nt" or os.environ.get("DEFENSECLAW_GATEWAY_BIN", "").strip():
        return binary
    from defenseclaw.file_permissions import UnsafePathError, trusted_posix_executable_path

    try:
        return trusted_posix_executable_path(binary)
    except UnsafePathError as exc:
        raise UnsafePathError(f"refusing to run {binary}: {exc}", code=exc.code) from exc


def packaged_windows_gateway_path() -> str | None:
    """Return the gateway sibling for a corroborated native Windows runtime.

    ``DEFENSECLAW_INSTALL_ROOT`` is not trusted by itself: developer shells and
    child processes may set arbitrary environment values.  A packaged CLI is
    recognized only when the current interpreter is the embedded Python at the
    same root and the sibling gateway is runnable.  Native setup can then use
    this absolute path for every lifecycle operation without Windows' current-
    directory executable search taking precedence over ``PATH``.
    """

    root = packaged_windows_install_root()
    if not root:
        return None

    candidate = os.path.join(root, "bin", "defenseclaw-gateway.exe")
    if _is_runnable_file(candidate):
        return os.path.abspath(candidate)
    return None


def packaged_windows_install_root() -> str | None:
    """Return a native install root corroborated by the running interpreter."""

    if os.name != "nt":
        return None

    install_root = os.environ.get("DEFENSECLAW_INSTALL_ROOT", "").strip()
    if not install_root or "\x00" in install_root or not os.path.isabs(install_root):
        return None

    root = os.path.abspath(install_root)
    expected_python = os.path.join(root, "runtime", "python", "python.exe")
    try:
        actual_python = os.path.normcase(os.path.realpath(sys.executable))
        packaged_python = os.path.normcase(os.path.realpath(expected_python))
    except OSError:
        return None
    if actual_python != packaged_python:
        return None
    return root


def _is_runnable_file(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    except OSError:
        return False
