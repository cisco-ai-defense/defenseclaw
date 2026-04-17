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

"""Config writer for ``webhooks[]`` notifier entries.

Sister module to ``defenseclaw.observability.writer`` — the ``webhooks:``
top-level list in ``config.yaml`` is consumed at runtime by
``internal/gateway/webhook.go`` for chat/incident notifiers
(Slack, PagerDuty, Webex, generic HMAC). This is a *different* surface
from ``audit_sinks[].http_jsonl`` (which forwards every audit event as
JSONL to a log collector); both write to the same YAML file but to
separate keys, so we use the same atomic tmp+rename pattern to keep the
Go gateway safe on reload.

All callers (CLI commands, TUI shell-outs, doctor probes) go through
``apply_webhook``, ``set_webhook_enabled``, ``remove_webhook`` rather
than hand-editing YAML.
"""

from __future__ import annotations

import copy
import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import yaml

# ---------------------------------------------------------------------------
# Constants mirrored with internal/gateway/webhook.go and internal/config
# ---------------------------------------------------------------------------

CONFIG_FILE_NAME = "config.yaml"

# Matches the Go dispatcher's channel-type switch
# (see NewWebhookDispatcher / setAuthHeaders).
VALID_TYPES: tuple[str, ...] = ("slack", "pagerduty", "webex", "generic")

# Severity rank -- mirrors audit.SeverityRank.
VALID_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Event categories -- mirrors categorizeAction() in webhook.go.
VALID_EVENT_CATEGORIES: tuple[str, ...] = (
    "block",
    "scan",
    "guardrail",
    "drift",
    "health",
)

# Default event allow-list when user leaves --events empty. Keeping this
# aligned with the runtime "all categories" behaviour (empty ep.events
# map matches everything) is intentional: the CLI writes the set the
# user explicitly opted into so filtering is visible at read-time.
DEFAULT_EVENTS: tuple[str, ...] = VALID_EVENT_CATEGORIES

# Defaults matching WebhookConfig in internal/config/config.go +
# cli/defenseclaw/config.py. These are written as *explicit* values so
# the YAML round-trips via _merge_webhooks without surprises.
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MIN_SEVERITY = "HIGH"

# Slug regex mirrors observability._NAME_RE — used for CLI-visible
# destination names (`setup webhook enable <name>`).
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class WebhookWriteResult:
    """Summary of an apply/remove/enable operation, rendered by the CLI."""

    name: str
    type: str
    yaml_changes: list[str]
    warnings: list[str]
    dry_run: bool


@dataclass
class WebhookView:
    """Unified view of a configured webhook (for ``list``/``show``).

    Mirrors the fields of ``WebhookConfig`` 1:1 so the CLI/TUI render
    layer doesn't need to know the YAML schema.
    """

    name: str
    type: str
    url: str
    secret_env: str
    room_id: str
    min_severity: str
    events: list[str]
    timeout_seconds: int
    # ``None`` preserves the "use runtime default" signal from Go
    # (``cooldown_seconds: *int`` where ``nil`` means ``300s`` and ``0``
    # means "disabled"); ``int`` is an explicit override.
    cooldown_seconds: int | None
    enabled: bool


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def apply_webhook(
    *,
    name: str | None,
    type_: str,
    url: str,
    data_dir: str,
    secret_env: str | None = None,
    room_id: str | None = None,
    min_severity: str | None = None,
    events: list[str] | tuple[str, ...] | None = None,
    timeout_seconds: int | None = None,
    cooldown_seconds: int | None = None,
    enabled: bool = True,
    dry_run: bool = False,
) -> WebhookWriteResult:
    """Insert/update a ``webhooks[]`` entry.

    ``name`` is optional — when omitted, the writer derives a slug from
    ``type + host`` (e.g. ``slack-hooks.slack.com``). Passing an
    existing name updates that entry in place (with a warning).

    ``cooldown_seconds=None`` preserves the Go dispatcher's default
    (``webhookDefaultCooldown = 300s``). Pass ``0`` to disable the
    cooldown and ``>0`` for an explicit override.
    """
    type_norm = (type_ or "").strip().lower()
    if type_norm not in VALID_TYPES:
        raise ValueError(
            f"invalid webhook type {type_!r}; choose one of: {', '.join(VALID_TYPES)}",
        )
    url = (url or "").strip()
    validate_webhook_url(url)
    _reject_inline_url_credentials(url)

    if not secret_env and type_norm in ("pagerduty", "webex"):
        raise ValueError(
            f"{type_norm}: --secret-env is required (routing key / bot token)",
        )
    if type_norm == "webex" and not (room_id or "").strip():
        raise ValueError("webex: --room-id is required")

    if secret_env is not None:
        _validate_env_var_name(secret_env)

    severity = (min_severity or DEFAULT_MIN_SEVERITY).upper()
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"invalid min_severity {min_severity!r}; "
            f"choose one of: {', '.join(VALID_SEVERITIES)}",
        )

    events_list = _normalize_events(events)
    timeout = int(timeout_seconds) if timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS
    if timeout <= 0:
        raise ValueError(f"timeout_seconds must be > 0 (got {timeout})")
    if cooldown_seconds is not None and cooldown_seconds < 0:
        raise ValueError(f"cooldown_seconds must be >= 0 (got {cooldown_seconds})")

    derived_name = _derive_name(name, type_norm, url)
    if not _NAME_RE.match(derived_name):
        raise ValueError(
            f"webhook name {derived_name!r} must match {_NAME_RE.pattern}",
        )

    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    raw = _load_yaml(cfg_path)
    before = copy.deepcopy(raw)

    warnings: list[str] = []
    webhooks = raw.setdefault("webhooks", [])
    if not isinstance(webhooks, list):
        warnings.append("webhooks: replaced non-list value")
        webhooks = []
        raw["webhooks"] = webhooks

    existing_idx = _find_index_by_name(webhooks, derived_name)
    matched_by_url_only = False
    if existing_idx < 0:
        # Fall back to matching by URL so users who wrote entries by
        # hand (no ``name`` key) still get in-place updates rather than
        # duplicate rows. When the caller did not pass ``name`` and the
        # matched entry has its own explicit name, preserve the
        # operator's chosen name rather than silently renaming it to
        # the type+host slug.
        existing_idx = _find_index_by_url(webhooks, url)
        if existing_idx >= 0 and name is None:
            matched = webhooks[existing_idx]
            if isinstance(matched, dict):
                prior_name = str(matched.get("name", "") or "")
                if prior_name and prior_name != derived_name:
                    warnings.append(
                        f"webhook matched by url — preserving existing "
                        f"name {prior_name!r} (pass --name to override)",
                    )
                    derived_name = prior_name
                    matched_by_url_only = True

    entry: dict[str, Any] = {
        "name": derived_name,
        "url": url,
        "type": type_norm,
        "min_severity": severity,
        "events": list(events_list),
        "timeout_seconds": timeout,
        "enabled": bool(enabled),
    }
    # Only emit cooldown_seconds when the user explicitly set it; a
    # missing key means "use the Go default" (nil pointer semantics).
    if cooldown_seconds is not None:
        entry["cooldown_seconds"] = int(cooldown_seconds)
    if secret_env:
        entry["secret_env"] = secret_env
    if room_id:
        entry["room_id"] = room_id

    if existing_idx >= 0:
        if not matched_by_url_only:
            warnings.append(
                f"webhook[{derived_name}] already existed — fields overwritten "
                "(other keys preserved)",
            )
        merged = dict(webhooks[existing_idx]) if isinstance(webhooks[existing_idx], dict) else {}
        # If caller did not supply cooldown_seconds but the prior entry
        # had one, preserve it — editing other fields should not reset
        # the cooldown.
        if cooldown_seconds is None and "cooldown_seconds" in merged:
            entry["cooldown_seconds"] = merged["cooldown_seconds"]
        merged.update(entry)
        webhooks[existing_idx] = merged
    else:
        webhooks.append(entry)

    yaml_changes = _summarize_diff(before, raw, derived_name)

    if not dry_run:
        _write_yaml(cfg_path, raw)

    return WebhookWriteResult(
        name=derived_name,
        type=type_norm,
        yaml_changes=yaml_changes,
        warnings=warnings,
        dry_run=dry_run,
    )


def list_webhooks(data_dir: str) -> list[WebhookView]:
    """Return every configured webhook entry in file order."""
    raw = _load_yaml(os.path.join(data_dir, CONFIG_FILE_NAME))
    out: list[WebhookView] = []
    for entry in raw.get("webhooks") or []:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url", "") or "")
        if not url:
            continue
        name = str(entry.get("name", "") or "") or _derive_name(
            None, str(entry.get("type", "generic") or "generic"), url,
        )
        cd_raw = entry.get("cooldown_seconds")
        cooldown: int | None
        if cd_raw is None:
            cooldown = None
        else:
            try:
                cooldown = int(cd_raw)
            except (TypeError, ValueError):
                cooldown = None
        out.append(WebhookView(
            name=name,
            type=str(entry.get("type", "generic") or "generic"),
            url=url,
            secret_env=str(entry.get("secret_env", "") or ""),
            room_id=str(entry.get("room_id", "") or ""),
            min_severity=str(entry.get("min_severity", "") or DEFAULT_MIN_SEVERITY).upper(),
            events=[str(e) for e in (entry.get("events") or [])],
            timeout_seconds=int(entry.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS) or DEFAULT_TIMEOUT_SECONDS),
            cooldown_seconds=cooldown,
            enabled=bool(entry.get("enabled", False)),
        ))
    return out


def set_webhook_enabled(name: str, enabled: bool, data_dir: str) -> WebhookWriteResult:
    """Flip the ``enabled`` flag on a named webhook."""
    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    raw = _load_yaml(cfg_path)
    webhooks = raw.get("webhooks")
    if not isinstance(webhooks, list):
        raise ValueError(f"no webhook named {name!r}")
    idx = _find_index_by_name(webhooks, name)
    if idx < 0:
        raise ValueError(f"no webhook named {name!r}")
    entry = webhooks[idx]
    if not isinstance(entry, dict):
        raise ValueError(f"webhook[{name}] has invalid shape")
    entry["enabled"] = bool(enabled)
    _write_yaml(cfg_path, raw)
    return WebhookWriteResult(
        name=name,
        type=str(entry.get("type", "") or ""),
        yaml_changes=[f"webhooks[{name}].enabled = {bool(enabled)}"],
        warnings=[],
        dry_run=False,
    )


def remove_webhook(name: str, data_dir: str) -> WebhookWriteResult:
    """Delete the webhook entry with ``name``."""
    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    raw = _load_yaml(cfg_path)
    webhooks = raw.get("webhooks")
    if not isinstance(webhooks, list):
        raise ValueError(f"no webhook named {name!r}")

    removed: dict[str, Any] | None = None
    new: list[Any] = []
    for entry in webhooks:
        if isinstance(entry, dict) and entry.get("name") == name:
            removed = entry
            continue
        new.append(entry)
    if removed is None:
        raise ValueError(f"no webhook named {name!r}")

    if new:
        raw["webhooks"] = new
    else:
        raw.pop("webhooks", None)

    _write_yaml(cfg_path, raw)
    return WebhookWriteResult(
        name=name,
        type=str(removed.get("type", "") or ""),
        yaml_changes=[f"webhooks[{name}] removed"],
        warnings=[],
        dry_run=False,
    )


# ---------------------------------------------------------------------------
# SSRF prevention — parity with internal/gateway/webhook.go::validateWebhookURL
# ---------------------------------------------------------------------------


_PRIVATE_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in net for net in _PRIVATE_CIDRS)


def validate_webhook_url(url: str) -> None:
    """Raise ``ValueError`` if ``url`` is unsafe for outbound delivery.

    Mirrors ``validateWebhookURL`` in ``internal/gateway/webhook.go``:
    blocks non-http(s) schemes, localhost, private/link-local ranges,
    and cloud metadata endpoints. Set
    ``DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1`` for local dev.
    """
    if not url:
        raise ValueError("webhook url is required")
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ValueError(f"invalid URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme {scheme!r} not allowed (must be http or https)")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("empty hostname")

    allow_local = os.environ.get("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST") == "1"

    if host.lower() == "localhost":
        if not allow_local:
            raise ValueError(
                "localhost not allowed (set DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST=1 for local dev)",
            )
        return

    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if _is_private_ip(literal_ip):
            if allow_local and literal_ip.is_loopback:
                return
            raise ValueError(f"IP {literal_ip} is private/reserved")
        return

    # Host is a DNS name. Match the Go behaviour: resolve and reject if
    # any public resolution points at private space. Tolerate resolution
    # failures (the Go side also allows them at config time).
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return
    for info in infos:
        addr = info[4][0]
        try:
            resolved = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_private_ip(resolved):
            if allow_local and resolved.is_loopback:
                continue
            raise ValueError(
                f"hostname {host!r} resolves to private IP {resolved}",
            )


# ---------------------------------------------------------------------------
# Internals — YAML I/O (atomic tmp+rename)
# ---------------------------------------------------------------------------


def _load_yaml(path: str) -> dict[str, Any]:
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"{path}: expected mapping at top level, got {type(data).__name__}",
        )
    return data


def _write_yaml(path: str, data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Internals — helpers
# ---------------------------------------------------------------------------


def _normalize_events(events: list[str] | tuple[str, ...] | None) -> list[str]:
    if events is None:
        return list(DEFAULT_EVENTS)
    seen: set[str] = set()
    out: list[str] = []
    for raw in events:
        evt = str(raw).strip().lower()
        if not evt:
            continue
        if evt not in VALID_EVENT_CATEGORIES:
            raise ValueError(
                f"unknown event category {evt!r}; "
                f"choose from: {', '.join(VALID_EVENT_CATEGORIES)}",
            )
        if evt in seen:
            continue
        seen.add(evt)
        out.append(evt)
    return out or list(DEFAULT_EVENTS)


def _slug(value: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out[:40] or "default"


def _derive_name(name: str | None, type_: str, url: str) -> str:
    if name:
        return name.strip().lower()
    host = "webhook"
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            host = parsed.hostname
    except ValueError:
        pass
    return f"{type_}-{_slug(host)}"


def _find_index_by_name(webhooks: list[Any], name: str) -> int:
    for i, entry in enumerate(webhooks):
        if isinstance(entry, dict) and entry.get("name") == name:
            return i
    return -1


def _find_index_by_url(webhooks: list[Any], url: str) -> int:
    for i, entry in enumerate(webhooks):
        if isinstance(entry, dict) and entry.get("url") == url:
            return i
    return -1


def _summarize_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    name: str,
) -> list[str]:
    lines: list[str] = []
    before_list = before.get("webhooks") or []
    after_list = after.get("webhooks") or []
    if len(before_list) != len(after_list):
        lines.append(f"webhooks: {len(before_list)} -> {len(after_list)} entries")
    for entry in after_list:
        if not isinstance(entry, dict):
            continue
        if entry.get("name") != name:
            continue
        lines.append(
            f"webhooks[{name}] type={entry.get('type')} "
            f"enabled={entry.get('enabled')} severity={entry.get('min_severity')}",
        )
        break
    return lines


_ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _reject_inline_url_credentials(url: str) -> None:
    """Reject URLs with inline ``user:pass@host`` authentication.

    Storing credentials inside the URL writes them to disk in
    plaintext as part of ``config.yaml``. HTTP auth belongs in
    ``secret_env`` (env var name) so the secret never hits the file.

    Note: for ``slack`` the URL itself is the secret (Slack's incoming-
    webhook scheme) — that case is expected and not blocked here.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return
    if parsed.username or parsed.password:
        raise ValueError(
            "webhook URL must not embed credentials (user:password@host); "
            "pass the secret via --secret-env instead",
        )


def _validate_env_var_name(value: str) -> None:
    """Reject inline secrets — only env var NAMES are allowed."""
    if not value:
        return
    if not _ENV_VAR_RE.match(value):
        raise ValueError(
            f"secret_env {value!r} does not look like an environment "
            "variable name (expected e.g. SLACK_WEBHOOK_SECRET); inline "
            "secrets are not accepted — store the value in "
            "~/.defenseclaw/.env instead",
        )
