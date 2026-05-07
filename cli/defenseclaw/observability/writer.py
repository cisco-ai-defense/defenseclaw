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

"""Config writer for observability presets.

This writer is intentionally YAML-level (not ``Config.save()``) because
``audit_sinks:`` is not modelled as a structured field on the Python
``Config`` dataclass — it is only mirrored *into* ``Config.splunk`` at
load time for the in-process Python HEC forwarder (see
``cli/defenseclaw/config.py::load``). A naïve ``cfg.save()`` would lose
every sink in the file.

The writer reads ``~/.defenseclaw/config.yaml`` as raw YAML, applies the
preset-specific diff, and writes it back. Secrets land in
``~/.defenseclaw/.env`` via ``_write_dotenv`` (mode 0600). All callers
(CLI, TUI shell-outs, future automation) should go through
``apply_preset``, ``set_destination_enabled``, and ``remove_destination``
rather than editing YAML by hand.

The Go gateway re-reads this same YAML on start / on SIGHUP, so any
write here is picked up after ``defenseclaw-gateway restart``.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from typing import Any

import yaml

from defenseclaw.observability.presets import Preset, Signal, resolve_preset

# ---------------------------------------------------------------------------
# Constants mirrored with internal/config/sinks.go and internal/telemetry
# ---------------------------------------------------------------------------

CONFIG_FILE_NAME = "config.yaml"
DOTENV_FILE_NAME = ".env"

# Identity attributes stamped into otel.resource.attributes so operators
# (and the Go gateway's telemetry/provider.go) can correlate a running
# exporter back to the preset that configured it.
_RESOURCE_PRESET_ID_KEY = "defenseclaw.preset"
_RESOURCE_PRESET_NAME_KEY = "defenseclaw.preset_name"

# Valid sink kinds — mirrors internal/config/sinks.go::AuditSinkKind.
_SINK_KIND_SPLUNK_HEC = "splunk_hec"
_SINK_KIND_OTLP_LOGS = "otlp_logs"
_SINK_KIND_HTTP_JSONL = "http_jsonl"

# Regex used to sanity-check that a destination name is safe to pass on
# the CLI / show in the TUI picker. Matches the Go-side Validate() which
# only requires non-empty but we additionally require a slug shape so
# ``enable``/``disable``/``remove`` commands have a clean arg surface.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass
class WriteResult:
    """Summary of a write operation, rendered by the CLI / TUI.

    Fields are intentionally flat and serialisable so the Go TUI may one
    day consume a ``--json`` variant of ``setup observability add``.
    """

    # Canonical name of the destination ("otel" for gateway OTel exporter
    # or the ``audit_sinks[].name`` for audit sinks).
    name: str
    target: str  # "otel" | "audit_sinks"
    preset_id: str
    # Human-readable one-liners used for CLI echo() output.
    yaml_changes: list[str]
    dotenv_changes: list[str]
    # Populated with warnings (e.g. "overwriting existing destination").
    warnings: list[str]
    # True iff the caller passed --dry-run (or the writer detected a
    # conflict and did not write).
    dry_run: bool


@dataclass
class Destination:
    """Unified view across ``otel:`` and ``audit_sinks:`` for the
    ``list`` command and the TUI observability picker."""

    name: str
    target: str  # "otel" | "audit_sinks"
    kind: str  # preset kind ("splunk_hec" etc.) or "otel"
    enabled: bool
    preset_id: str  # "" when not stamped by the writer
    endpoint: str
    # Per-signal enablement; populated for OTel only.
    signals: dict[str, bool]


# ---------------------------------------------------------------------------
# apply_preset — the single entry point for writes
# ---------------------------------------------------------------------------


def apply_preset(
    preset_id: str,
    inputs: dict[str, str],
    data_dir: str,
    *,
    name: str | None = None,
    enabled: bool = True,
    signals: tuple[Signal, ...] | None = None,
    secret_value: str | None = None,
    target_override: str | None = None,
    dry_run: bool = False,
) -> WriteResult:
    """Apply ``preset_id`` with ``inputs`` to ``config.yaml``.

    Parameters
    ----------
    preset_id:
        Canonical preset id as registered in
        ``observability.presets.PRESETS``.
    inputs:
        Prompt-answer map keyed by ``Preset.prompts[i].flag_name``
        (e.g. ``{"realm": "us1"}``). Missing keys fall back to the
        preset default. Extra keys are ignored — the writer is forgiving
        on purpose so non-interactive callers can supply a superset of
        flags without per-preset branching.
    data_dir:
        DefenseClaw data directory (normally ``~/.defenseclaw``).
    name:
        Override the auto-derived destination name. For ``target=otel``
        presets this is ignored because there is only one ``otel:``
        block; instead it is stamped into
        ``otel.resource.attributes.service.name``.
    enabled:
        ``audit_sinks[*].enabled`` / ``otel.enabled``. Callers typically
        use ``set_destination_enabled`` after initial creation.
    signals:
        OTel signals to enable when ``target=otel``. ``None`` means
        "use preset.default_signals".
    secret_value:
        If provided, written to ``~/.defenseclaw/.env`` under
        ``preset.token_env``. Must not be empty when the preset declares
        a ``token_env`` and no value already exists. Callers are
        responsible for prompting/redacting.
    target_override:
        For presets that support multiple targets (``otlp`` →
        ``otel`` | ``audit_sinks``), force one. Ignored for all other
        presets.
    dry_run:
        Compute and return the diff but do not touch disk.

    Raises
    ------
    ValueError
        On unknown preset / missing required inputs.
    """
    preset = resolve_preset(preset_id)
    effective_target = _resolve_target(preset, target_override)
    resolved_inputs = _resolve_inputs(preset, inputs)
    dest_name = _destination_name(preset, name, resolved_inputs)
    if effective_target == "audit_sinks" and not _NAME_RE.match(dest_name):
        raise ValueError(
            f"destination name {dest_name!r} must match {_NAME_RE.pattern}"
        )

    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    raw = _load_yaml(cfg_path)
    before = copy.deepcopy(raw)

    warnings: list[str] = []
    if effective_target == "otel":
        _apply_otel_preset(
            raw,
            preset,
            resolved_inputs,
            enabled=enabled,
            signals=signals or preset.default_signals,
            dest_name=dest_name,
            warnings=warnings,
        )
    else:
        _apply_audit_sink_preset(
            raw,
            preset,
            resolved_inputs,
            name=dest_name,
            enabled=enabled,
            warnings=warnings,
        )

    yaml_changes = _summarize_diff(before, raw, effective_target, dest_name)
    dotenv_changes = _apply_secret(
        data_dir, preset, secret_value, dry_run=dry_run,
    )

    if not dry_run:
        _write_yaml(cfg_path, raw)

    return WriteResult(
        name=dest_name,
        target=effective_target,
        preset_id=preset.id,
        yaml_changes=yaml_changes,
        dotenv_changes=dotenv_changes,
        warnings=warnings,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# list / enable / disable / remove
# ---------------------------------------------------------------------------


def list_destinations(data_dir: str) -> list[Destination]:
    """Return all configured observability destinations.

    Includes the gateway ``otel:`` block (as ``Destination(name="otel")``)
    and every entry in ``audit_sinks:``. Stable order: ``otel`` first,
    then audit sinks in file order (matching the Go Manager
    dispatch order).
    """
    raw = _load_yaml(os.path.join(data_dir, CONFIG_FILE_NAME))
    out: list[Destination] = []

    otel = raw.get("otel") or {}
    if isinstance(otel, dict):
        attrs = ((otel.get("resource") or {}).get("attributes") or {})
        out.append(
            Destination(
                name="otel",
                target="otel",
                kind="otel",
                enabled=bool(otel.get("enabled", False)),
                preset_id=str(attrs.get(_RESOURCE_PRESET_ID_KEY, "") or ""),
                endpoint=_derive_otel_endpoint(otel),
                signals={
                    "traces": bool((otel.get("traces") or {}).get("enabled", False)),
                    "metrics": bool((otel.get("metrics") or {}).get("enabled", False)),
                    "logs": bool((otel.get("logs") or {}).get("enabled", False)),
                },
            ),
        )

    for sink in raw.get("audit_sinks") or []:
        if not isinstance(sink, dict):
            continue
        kind = str(sink.get("kind", "") or "")
        name = str(sink.get("name", "") or "")
        if not name or not kind:
            continue
        out.append(
            Destination(
                name=name,
                target="audit_sinks",
                kind=kind,
                enabled=bool(sink.get("enabled", False)),
                preset_id=_sink_preset_id(sink),
                endpoint=_sink_endpoint(sink),
                signals={},
            ),
        )
    return out


def set_destination_enabled(
    name: str,
    enabled: bool,
    data_dir: str,
) -> WriteResult:
    """Flip the ``enabled`` flag on an existing destination.

    ``name == "otel"`` targets the top-level ``otel:`` block. Any other
    name must match an existing ``audit_sinks[].name``.
    """
    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    raw = _load_yaml(cfg_path)
    changes: list[str] = []
    target = "otel" if name == "otel" else "audit_sinks"

    if target == "otel":
        otel = raw.setdefault("otel", {})
        otel["enabled"] = bool(enabled)
        changes.append(f"otel.enabled = {bool(enabled)}")
    else:
        sink = _find_sink(raw, name)
        if sink is None:
            raise ValueError(f"no audit sink named {name!r}")
        sink["enabled"] = bool(enabled)
        changes.append(f"audit_sinks[{name}].enabled = {bool(enabled)}")

    _write_yaml(cfg_path, raw)
    return WriteResult(
        name=name,
        target=target,
        preset_id="",
        yaml_changes=changes,
        dotenv_changes=[],
        warnings=[],
        dry_run=False,
    )


def remove_destination(name: str, data_dir: str) -> WriteResult:
    """Delete an audit_sinks entry (``name == "otel"`` clears otel.enabled).

    The writer intentionally does *not* delete the gateway ``otel:`` block
    on ``remove otel`` — operators frequently toggle the exporter off
    while iterating, and re-enabling requires all fields to remain. Use
    ``disable otel`` explicitly to keep the config stable.
    """
    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    raw = _load_yaml(cfg_path)
    changes: list[str] = []

    if name == "otel":
        otel = raw.get("otel")
        if isinstance(otel, dict):
            otel["enabled"] = False
            changes.append("otel.enabled = False (use `remove` only to disable)")
        else:
            changes.append("otel block absent — nothing to do")
        _write_yaml(cfg_path, raw)
        return WriteResult(
            name=name, target="otel", preset_id="",
            yaml_changes=changes, dotenv_changes=[], warnings=[], dry_run=False,
        )

    sinks = raw.get("audit_sinks")
    if not isinstance(sinks, list):
        raise ValueError(f"no audit sink named {name!r}")
    new = [s for s in sinks if isinstance(s, dict) and s.get("name") != name]
    if len(new) == len(sinks):
        raise ValueError(f"no audit sink named {name!r}")
    if new:
        raw["audit_sinks"] = new
    else:
        raw.pop("audit_sinks", None)
    changes.append(f"audit_sinks[{name}] removed")

    _write_yaml(cfg_path, raw)
    return WriteResult(
        name=name, target="audit_sinks", preset_id="",
        yaml_changes=changes, dotenv_changes=[], warnings=[], dry_run=False,
    )


# ---------------------------------------------------------------------------
# Internals — YAML I/O
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
        raise RuntimeError(f"{path}: expected mapping at top level, got {type(data).__name__}")
    return data


def _write_yaml(path: str, data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Write to a temp file and rename so a crash mid-write cannot leave
    # a half-written config.yaml (which would brick the Go gateway on
    # next reload).
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Internals — OTel preset
# ---------------------------------------------------------------------------


def _apply_otel_preset(
    raw: dict[str, Any],
    preset: Preset,
    inputs: dict[str, str],
    *,
    enabled: bool,
    signals: tuple[Signal, ...],
    dest_name: str,
    warnings: list[str],
) -> None:
    otel = raw.setdefault("otel", {})
    if not isinstance(otel, dict):
        warnings.append("otel: replaced non-mapping value")
        otel = {}
        raw["otel"] = otel

    # Endpoint — strip scheme (matches the Go exporter's expectation
    # that endpoint is host[:port], with scheme implied by protocol +
    # insecure flag; see internal/telemetry/provider.go).
    endpoint = _render_template(preset.endpoint_template, inputs)
    endpoint_no_scheme = _strip_scheme(endpoint)

    otel["enabled"] = bool(enabled)
    if preset.otel_protocol:
        otel["protocol"] = preset.otel_protocol

    # Headers merge: preserve any pre-existing headers the user added
    # manually, but overwrite keys we manage (vendor-specific auth).
    existing_headers = otel.get("headers")
    if not isinstance(existing_headers, dict):
        existing_headers = {}
    for k, v in preset.otel_headers.items():
        existing_headers[k] = v
    # Honeycomb dataset lives in a separate header; stamp it at apply
    # time from inputs rather than at preset-decl time so per-environment
    # values work.
    if preset.id == "honeycomb" and inputs.get("dataset"):
        existing_headers["x-honeycomb-dataset"] = inputs["dataset"]
    if existing_headers:
        otel["headers"] = existing_headers
    if preset.otel_tls_insecure:
        tls = otel.setdefault("tls", {})
        if not isinstance(tls, dict):
            warnings.append("otel.tls: replaced non-mapping value")
            tls = {}
            otel["tls"] = tls
        tls["insecure"] = True

    signals_set = set(signals)
    for sig in ("traces", "metrics", "logs"):
        block = otel.setdefault(sig, {})
        if not isinstance(block, dict):
            block = {}
            otel[sig] = block
        block["enabled"] = sig in signals_set
        if sig in signals_set:
            block["endpoint"] = endpoint_no_scheme
            if preset.otel_protocol:
                block["protocol"] = preset.otel_protocol
            path = preset.signal_url_paths.get(sig, "")
            if path:
                block["url_path"] = path

    # Stamp identity attributes so operators can tell which preset
    # wrote the current config and the gateway telemetry panel can show
    # it at runtime.
    resource = otel.setdefault("resource", {})
    if not isinstance(resource, dict):
        resource = {}
        otel["resource"] = resource
    attrs = resource.setdefault("attributes", {})
    if not isinstance(attrs, dict):
        attrs = {}
        resource["attributes"] = attrs
    attrs[_RESOURCE_PRESET_ID_KEY] = preset.id
    attrs[_RESOURCE_PRESET_NAME_KEY] = preset.display_name
    attrs.setdefault("service.name", dest_name or "defenseclaw")


# ---------------------------------------------------------------------------
# Internals — audit_sinks preset
# ---------------------------------------------------------------------------


def _apply_audit_sink_preset(
    raw: dict[str, Any],
    preset: Preset,
    inputs: dict[str, str],
    *,
    name: str,
    enabled: bool,
    warnings: list[str],
) -> None:
    sinks = raw.setdefault("audit_sinks", [])
    if not isinstance(sinks, list):
        warnings.append("audit_sinks: replaced non-list value")
        sinks = []
        raw["audit_sinks"] = sinks

    entry = _build_sink_entry(preset, inputs, name=name, enabled=enabled)
    existing_idx = -1
    for i, s in enumerate(sinks):
        if isinstance(s, dict) and s.get("name") == name:
            existing_idx = i
            break
    if existing_idx >= 0:
        warnings.append(
            f"audit_sinks[{name}] already existed — fields overwritten (other "
            "keys preserved)",
        )
        # Shallow-merge: preserve operator-added keys (min_severity,
        # actions, batch_size, etc.) that the preset does not own.
        merged = dict(sinks[existing_idx])
        merged.update(entry)
        sinks[existing_idx] = merged
    else:
        sinks.append(entry)


def _build_sink_entry(
    preset: Preset,
    inputs: dict[str, str],
    *,
    name: str,
    enabled: bool,
) -> dict[str, Any]:
    kind = preset.sink_kind or ""
    # The generic ``otlp`` preset declares target=otel and sink_kind=None
    # because its primary mode is the gateway exporter. When a caller
    # supplies ``target_override="audit_sinks"``, ``_resolve_target``
    # routes us here without setting sink_kind on the (frozen) preset.
    # Coerce to ``otlp_logs`` — the only valid sink shape for this
    # preset — so the rest of the builder picks the right block. See
    # ``_resolve_target``'s "coerce to otlp_logs" comment for the
    # contract this completes.
    if not kind and preset.id == "otlp":
        kind = _SINK_KIND_OTLP_LOGS
    base: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "enabled": bool(enabled),
    }
    if kind == _SINK_KIND_SPLUNK_HEC:
        # Allow a fully-qualified ``endpoint`` override so callers like
        # the local-Splunk bridge can preserve the actual scheme it
        # bootstrapped with (free-mode docker compose returns ``http://``).
        # Falling back to ``https://{host}:{port}/...`` keeps the
        # zero-config default safe (TLS by default).
        explicit_endpoint = (inputs.get("endpoint") or "").strip()
        if explicit_endpoint:
            endpoint = explicit_endpoint
        else:
            host = inputs.get("host", "localhost")
            port = inputs.get("port", "8088")
            endpoint = f"https://{host}:{port}/services/collector/event"
        if not endpoint.lower().startswith(("http://", "https://")):
            raise ValueError(
                f"splunk HEC endpoint must start with http:// or https:// (got {endpoint!r})",
            )
        verify_tls_default = "true" if preset.id == "splunk-enterprise" else "false"
        base["splunk_hec"] = {
            "endpoint": endpoint,
            "token_env": preset.token_env,
            "index": inputs.get("index", "defenseclaw"),
            "source": inputs.get("source", "defenseclaw"),
            "sourcetype": inputs.get("sourcetype", "_json"),
            "verify_tls": _parse_bool(inputs.get("verify_tls", verify_tls_default)),
        }
    elif kind == _SINK_KIND_OTLP_LOGS:
        endpoint = inputs.get("endpoint", "").strip()
        protocol = (inputs.get("protocol") or preset.otel_protocol or "grpc").strip()
        if protocol not in ("grpc", "http"):
            raise ValueError(
                f"invalid protocol {protocol!r}; must be grpc or http",
            )
        block: dict[str, Any] = {
            "endpoint": _strip_scheme(endpoint),
            "protocol": protocol,
        }
        headers = dict(preset.otel_headers)
        if headers:
            block["headers"] = headers
        if inputs.get("insecure"):
            block["insecure"] = _parse_bool(inputs.get("insecure", "false"))
        # Allow an explicit url_path input to override per-signal paths
        # (logs-only case for HTTP protocol).
        if inputs.get("url_path"):
            block["url_path"] = inputs["url_path"]
        base["otlp_logs"] = block
    elif kind == _SINK_KIND_HTTP_JSONL:
        url = inputs.get("url", "").strip()
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(
                f"webhook url must start with http:// or https:// (got {url!r})",
            )
        method = (inputs.get("method") or "POST").upper()
        if method not in ("POST", "PUT", "PATCH"):
            raise ValueError(
                f"webhook method must be POST/PUT/PATCH (got {method!r})",
            )
        block = {
            "url": url,
            "method": method,
        }
        if preset.token_env:
            block["bearer_env"] = preset.token_env
        headers = dict(preset.otel_headers)  # usually empty for webhook
        if headers:
            block["headers"] = headers
        base["http_jsonl"] = block
    else:
        raise ValueError(f"preset {preset.id!r} has no sink_kind")

    # Stamp preset identity so list_destinations / doctor can attribute
    # a sink back to the preset that created it. We use a dotted prefix
    # under an ``actions`` shim — no, that conflicts with the Go
    # Actions filter; use a dedicated defenseclaw:<key> header in the
    # kind block where supported, otherwise skip silently. The Go side
    # ignores unknown keys so this is safe but mapstructure is strict.
    # Instead we keep this light: re-derive the preset id at list-time
    # from endpoint + kind signatures. See _sink_preset_id below.
    return base


# ---------------------------------------------------------------------------
# Internals — helpers
# ---------------------------------------------------------------------------


def _resolve_target(preset: Preset, override: str | None) -> str:
    if override:
        if override not in ("otel", "audit_sinks"):
            raise ValueError(
                f"invalid target {override!r}; must be otel or audit_sinks",
            )
        if preset.id != "otlp":
            # Only the generic OTLP preset supports target override.
            raise ValueError(
                f"preset {preset.id!r} does not support target override",
            )
        if override == "audit_sinks" and preset.sink_kind is None:
            # Caller asked for audit_sinks but preset has no sink kind
            # → coerce to otlp_logs (only valid combination).
            return "audit_sinks"
        return override
    return preset.target


def _resolve_inputs(preset: Preset, inputs: dict[str, str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for flag_name, _placeholder, _desc, default in preset.prompts:
        val = inputs.get(flag_name, "")
        if not val:
            val = default
        if not val:
            raise ValueError(
                f"preset {preset.id!r}: missing required input {flag_name!r} "
                "(no default provided)",
            )
        resolved[flag_name] = val
    # Pass-through extra keys (dataset, verify_tls, url_path) that are
    # not in prompts but used by specific presets.
    for k, v in inputs.items():
        if k not in resolved:
            resolved[k] = v
    return resolved


def _destination_name(
    preset: Preset, override: str | None, inputs: dict[str, str],
) -> str:
    if override:
        return override
    # Deterministic default names — short, human-readable, and unique
    # enough per-host that a user can pick them out of a list.
    if preset.id in ("splunk-hec", "splunk-enterprise"):
        host = inputs.get("host", "localhost")
        if preset.id == "splunk-enterprise":
            endpoint = inputs.get("endpoint", "")
            if "://" in endpoint:
                from urllib.parse import urlparse

                host = urlparse(endpoint).hostname or host
            elif endpoint:
                host = endpoint.split("/", 1)[0].split(":", 1)[0] or host
        return f"{preset.id}-{_slug(host)}"
    if preset.id == "webhook":
        url = inputs.get("url", "")
        host = url.split("/")[2] if "://" in url else "webhook"
        return f"webhook-{_slug(host)}"
    if preset.id == "otlp":
        endpoint = inputs.get("endpoint", "")
        host = endpoint.split("/")[0] if endpoint else "otlp"
        return f"otlp-{_slug(host)}"
    return preset.id


def _slug(value: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out[:40] or "default"


def _render_template(template: str, inputs: dict[str, str]) -> str:
    try:
        return template.format(**inputs)
    except KeyError as exc:
        raise ValueError(
            f"endpoint template {template!r} references unknown input {exc.args[0]!r}",
        ) from exc


def _strip_scheme(url: str) -> str:
    low = url.lower()
    for prefix in ("https://", "http://"):
        if low.startswith(prefix):
            return url[len(prefix):]
    return url


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def _summarize_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    target: str,
    name: str,
) -> list[str]:
    lines: list[str] = []
    if target == "otel":
        b = before.get("otel") or {}
        a = after.get("otel") or {}
        if b.get("enabled") != a.get("enabled"):
            lines.append(f"otel.enabled: {b.get('enabled')} -> {a.get('enabled')}")
        for sig in ("traces", "metrics", "logs"):
            bs = (b.get(sig) or {}).get("enabled")
            as_ = (a.get(sig) or {}).get("enabled")
            if bs != as_:
                lines.append(f"otel.{sig}.enabled: {bs} -> {as_}")
        if (b.get("headers") or {}) != (a.get("headers") or {}):
            # Redact values — show keys only.
            keys = sorted((a.get("headers") or {}).keys())
            lines.append(f"otel.headers: {', '.join(keys)} (values redacted)")
        lines.append(f"otel stamped with preset={name}")
        return lines

    bsinks = before.get("audit_sinks") or []
    asinks = after.get("audit_sinks") or []
    if len(bsinks) != len(asinks):
        lines.append(f"audit_sinks: {len(bsinks)} -> {len(asinks)} entries")
    for s in asinks:
        if isinstance(s, dict) and s.get("name") == name:
            lines.append(f"audit_sinks[{name}] kind={s.get('kind')} enabled={s.get('enabled')}")
            break
    return lines


def _apply_secret(
    data_dir: str,
    preset: Preset,
    secret_value: str | None,
    *,
    dry_run: bool,
) -> list[str]:
    if not preset.token_env:
        return []
    if not secret_value:
        # No new value — caller may have passed the secret through the
        # environment or dotenv already. Emit an advisory.
        dotenv = _load_dotenv(os.path.join(data_dir, DOTENV_FILE_NAME))
        if preset.token_env not in dotenv and not os.environ.get(preset.token_env):
            return [
                f"{preset.token_env}: not set — sink/exporter will fail until "
                "exported or added to ~/.defenseclaw/.env",
            ]
        return []
    if dry_run:
        return [f"{preset.token_env}: (would write to ~/.defenseclaw/.env)"]
    path = os.path.join(data_dir, DOTENV_FILE_NAME)
    existing = _load_dotenv(path)
    existing[preset.token_env] = secret_value
    _write_dotenv(path, existing)
    os.environ[preset.token_env] = secret_value
    return [f"{preset.token_env}: written to ~/.defenseclaw/.env"]


# ---------------------------------------------------------------------------
# Internals — destination introspection
# ---------------------------------------------------------------------------


def _find_sink(raw: dict[str, Any], name: str) -> dict[str, Any] | None:
    sinks = raw.get("audit_sinks")
    if not isinstance(sinks, list):
        return None
    for s in sinks:
        if isinstance(s, dict) and s.get("name") == name:
            return s
    return None


def _derive_otel_endpoint(otel: dict[str, Any]) -> str:
    # Prefer signal endpoints (where the Go exporter actually dials).
    for sig in ("traces", "metrics", "logs"):
        block = otel.get(sig) or {}
        if isinstance(block, dict):
            ep = block.get("endpoint")
            if ep:
                return str(ep)
    return str(otel.get("endpoint", "") or "")


def _sink_endpoint(sink: dict[str, Any]) -> str:
    kind = sink.get("kind", "")
    if kind == _SINK_KIND_SPLUNK_HEC:
        return str((sink.get("splunk_hec") or {}).get("endpoint", "") or "")
    if kind == _SINK_KIND_OTLP_LOGS:
        return str((sink.get("otlp_logs") or {}).get("endpoint", "") or "")
    if kind == _SINK_KIND_HTTP_JSONL:
        return str((sink.get("http_jsonl") or {}).get("url", "") or "")
    return ""


def _sink_preset_id(sink: dict[str, Any]) -> str:
    """Best-effort reverse lookup of the preset that created ``sink``.

    We don't persist the preset id (the Go-side schema is strict and
    rejects unknown keys), so we pattern-match on endpoint + kind.
    Returns ``""`` for unknown / hand-edited sinks.
    """
    kind = sink.get("kind", "")
    if kind == _SINK_KIND_SPLUNK_HEC:
        name = str(sink.get("name", "") or "")
        endpoint = str((sink.get("splunk_hec") or {}).get("endpoint", "") or "")
        if name.startswith("splunk-enterprise-") or _is_remote_splunk_endpoint(endpoint):
            return "splunk-enterprise"
        return "splunk-hec"
    if kind == _SINK_KIND_HTTP_JSONL:
        return "webhook"
    if kind == _SINK_KIND_OTLP_LOGS:
        ep = (sink.get("otlp_logs") or {}).get("endpoint", "") or ""
        low = ep.lower()
        if "datadoghq.com" in low:
            return "datadog"
        if "honeycomb.io" in low:
            return "honeycomb"
        if "nr-data.net" in low:
            return "newrelic"
        if "grafana.net" in low:
            return "grafana-cloud"
        if "splunkcloud.com" in low:
            return "splunk-o11y"
        return "otlp"
    return ""


def _is_remote_splunk_endpoint(endpoint: str) -> bool:
    if not endpoint:
        return False
    from urllib.parse import urlparse

    parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    host = (parsed.hostname or "").lower()
    return host not in ("", "localhost", "127.0.0.1", "::1")


# ---------------------------------------------------------------------------
# Internals — dotenv I/O (duplicated from cmd_setup so the writer has no
# dependency on the Click command layer; values must stay in sync).
# ---------------------------------------------------------------------------


def _load_dotenv(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                if k:
                    out[k] = v
    except FileNotFoundError:
        pass
    return out


def _write_dotenv(path: str, entries: dict[str, str]) -> None:
    lines = [f"{k}={v}\n" for k, v in sorted(entries.items())]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.writelines(lines)
