"""Prerequisite checks: verify the host can execute the selected matrix.

This is intentionally read-only. It does NOT install or modify anything;
it produces a checklist with one entry per requirement and an overall
``ok`` boolean. The CLI prints the checklist and exits non-zero on
failures.
"""

from __future__ import annotations

import os
import shutil
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dctest.config import get_settings
from dctest.models import MatrixCell
from dctest.services.matrix import expand_matrix, load_selection

ServiceName = str  # one of "gateway", "sidecar", "observability", "webhook-target"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


def _which(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


def _env_present(name: str) -> bool:
    return bool(os.environ.get(name))


def _endpoint_reachable(url: str, *, timeout_s: float = 2.0) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def _http_ok(url: str, *, timeout_s: float = 2.0) -> bool:
    """Return True iff a GET to ``url`` answers with status < 500.

    A 404 is still "service is up"; only connection failures and 5xx are
    treated as the service being unavailable, since we just want to know
    whether anything is listening for the prereq probe.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:  # noqa: S310 - localhost
            return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


def probe_service(name: ServiceName) -> bool:
    """Return True iff the named service is reachable from the harness host.

    Knows about four service names that case YAMLs can list under
    ``requires_services``:

    - ``"gateway"`` — DefenseClaw gateway HTTP endpoint.
    - ``"sidecar"`` — running ``defenseclaw`` Python sidecar (we treat the
      console script being on PATH as the proxy here; full-process detection
      is out of scope).
    - ``"observability"`` — gateway metrics endpoint.
    - ``"webhook-target"`` — local webhook sink the gateway can post to.
    """
    settings = get_settings()
    if name == "gateway":
        return _http_ok(settings.gateway_health_url)
    if name == "observability":
        return _http_ok(settings.observability_health_url)
    if name == "webhook-target":
        return _http_ok(settings.webhook_target_url)
    if name == "sidecar":
        # Sidecar = python CLI installed. Refine later when we have a
        # real long-running sidecar process to ping.
        return shutil.which(settings.defenseclaw_bin) is not None
    return False


def probe_services(names: list[ServiceName]) -> dict[ServiceName, bool]:
    """Probe each service name; return a mapping of name -> ok."""
    return {n: probe_service(n) for n in names}


def _baseline_checks() -> list[Check]:
    settings = get_settings()
    return [
        Check(name="claude CLI on PATH", ok=_which(settings.claude_bin)),
        Check(name="codex CLI on PATH (optional)", ok=_which(settings.codex_bin)),
        Check(name="defenseclaw on PATH", ok=_which(settings.defenseclaw_bin)),
        Check(
            name="defenseclaw-gateway on PATH",
            ok=_which(settings.defenseclaw_gateway_bin),
        ),
        Check(name="git on PATH", ok=_which("git")),
        Check(name="docker on PATH (optional, for local-observability)", ok=_which("docker")),
    ]


def _cells_to_check(selection_path: Path | None) -> list[MatrixCell]:
    if selection_path:
        return load_selection(selection_path)
    return expand_matrix(required_only=True)


def run_doctor(selection_path: Path | None = None) -> Report:
    cells = _cells_to_check(selection_path)
    report = Report(checks=_baseline_checks())
    seen_envs: set[str] = set()
    seen_endpoints: set[str] = set()
    for cell in cells:
        for provider in [cell.provider, cell.judge_provider]:
            if provider is None:
                continue
            if provider.auth_env and provider.auth_env not in seen_envs:
                seen_envs.add(provider.auth_env)
                report.checks.append(
                    Check(
                        name=f"env {provider.auth_env} set (for provider {provider.id})",
                        ok=_env_present(provider.auth_env),
                    )
                )
            if provider.endpoint and provider.endpoint not in seen_endpoints:
                seen_endpoints.add(provider.endpoint)
                report.checks.append(
                    Check(
                        name=f"endpoint {provider.endpoint} reachable (provider {provider.id})",
                        ok=_endpoint_reachable(provider.endpoint),
                    )
                )
    return report
