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
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import yaml

from defenseclaw.config import config_path_for_data_dir, locked_config_yaml, write_config_yaml_secure
from defenseclaw.observability.presets import Preset, Signal, resolve_preset
from defenseclaw.safety import sanitize_dotenv_value

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
_UUID_RE = re.compile(
    r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)

# Go's configuration schema version that introduced named OTel destinations.
# Only an explicitly stamped v6 file is advanced after the durable rewrite;
# missing/older stamps must remain untouched so the Go loader can still apply
# its unrelated v1-v6 in-memory compatibility migrations.
_NAMED_OTEL_CONFIG_VERSION = 7


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass
class WriteResult:
    """Summary of a write operation, rendered by the CLI / TUI.

    Fields are intentionally flat and serialisable so the Go TUI may one
    day consume a ``--json`` variant of ``setup observability add``.
    """

    # Canonical name of the named OTel destination or audit sink.
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
        Override the auto-derived destination name.
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
    if effective_target in {"audit_sinks", "otel"} and not _NAME_RE.match(dest_name):
        raise ValueError(f"destination name {dest_name!r} must match {_NAME_RE.pattern}")

    cfg_path = str(config_path_for_data_dir(data_dir))
    lock = nullcontext() if dry_run else locked_config_yaml(cfg_path)
    with lock:
        raw = _load_yaml(cfg_path)
        before = copy.deepcopy(raw)

        warnings: list[str] = []
        if effective_target == "otel":
            _apply_otel_preset(
                raw,
                preset,
                resolved_inputs,
                data_dir=data_dir,
                enabled=enabled,
                signals=signals or preset.default_signals,
                dest_name=dest_name,
                warnings=warnings,
            )
            if any(warning.startswith("migrated flat OTel exporter") for warning in warnings):
                _advance_named_otel_config_version(raw)
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
            data_dir,
            preset,
            secret_value,
            dry_run=dry_run,
        )

        if not dry_run:
            if any(warning.startswith("migrated flat OTel exporter") for warning in warnings):
                backup_path = cfg_path + ".pre-observability-migration.bak"
                if not os.path.exists(backup_path):
                    write_config_yaml_secure(backup_path, before)
                    warnings.append(f"saved pre-migration backup at {backup_path}")
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

    Includes every named ``otel.destinations[]`` route and every entry in
    ``audit_sinks:`` in file order.
    """
    raw = _load_yaml(str(config_path_for_data_dir(data_dir)))
    out: list[Destination] = []

    otel = raw.get("otel") or {}
    if isinstance(otel, dict):
        destinations = otel.get("destinations")
        if isinstance(destinations, list):
            for item in destinations:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                out.append(
                    Destination(
                        name=str(item["name"]),
                        target="otel",
                        kind="otel",
                        enabled=bool(otel.get("enabled", False) and item.get("enabled", False)),
                        preset_id=str(item.get("preset", "") or ""),
                        endpoint=_derive_otel_endpoint(item),
                        signals={
                            "traces": bool((item.get("traces") or {}).get("enabled", False)),
                            "metrics": bool((item.get("metrics") or {}).get("enabled", False)),
                            "logs": bool((item.get("logs") or {}).get("enabled", False)),
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


def migrate_flat_otel(data_dir: str, *, dry_run: bool = True) -> WriteResult:
    """Convert an old flat ``otel:`` exporter into one named destination."""

    cfg_path = os.path.join(data_dir, CONFIG_FILE_NAME)
    with locked_config_yaml(cfg_path):
        raw = _load_yaml(cfg_path)
        before = copy.deepcopy(raw)
        warnings: list[str] = []
        otel = raw.get("otel")
        if isinstance(otel, dict):
            _migrate_flat_otel_in_place(otel, warnings, data_dir=data_dir)
        migrated = any(warning.startswith("migrated flat OTel exporter") for warning in warnings)
        if not migrated:
            return WriteResult(
                name="",
                target="otel",
                preset_id="",
                yaml_changes=[],
                dotenv_changes=[],
                warnings=[],
                dry_run=dry_run,
            )
        _advance_named_otel_config_version(raw)
        destination = (raw.get("otel") or {}).get("destinations", [{}])[0]
        name = str(destination.get("name", "generic-otlp"))
        if not dry_run:
            backup_path = cfg_path + ".pre-observability-migration.bak"
            if not os.path.exists(backup_path):
                write_config_yaml_secure(backup_path, before)
                warnings.append(f"saved pre-migration backup at {backup_path}")
            _write_yaml(cfg_path, raw)
        return WriteResult(
            name=name,
            target="otel",
            preset_id=str(destination.get("preset", "generic-otlp")),
            yaml_changes=[f"flat otel exporter -> otel.destinations[{name}]"],
            dotenv_changes=[],
            warnings=warnings,
            dry_run=dry_run,
        )


def set_destination_enabled(
    name: str,
    enabled: bool,
    data_dir: str,
) -> WriteResult:
    """Flip the ``enabled`` flag on an existing destination.

    Named OTel destinations are matched before audit sinks.
    """
    cfg_path = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(cfg_path):
        raw = _load_yaml(cfg_path)
        changes: list[str] = []
        otel_destination = _find_otel_destination(raw, name)
        target = "otel" if otel_destination is not None else "audit_sinks"

        if otel_destination is not None:
            otel_destination["enabled"] = bool(enabled)
            otel = raw.setdefault("otel", {})
            if enabled:
                otel["enabled"] = True
            else:
                destinations = otel.get("destinations") or []
                otel["enabled"] = any(
                    isinstance(item, dict) and bool(item.get("enabled", False))
                    for item in destinations
                )
            changes.append(f"otel.destinations[{name}].enabled = {bool(enabled)}")
        elif name == "otel":
            otel = raw.get("otel")
            if not isinstance(otel, dict) or isinstance(otel.get("destinations"), list):
                raise ValueError(f"no destination named {name!r}")
            otel["enabled"] = bool(enabled)
            target = "otel"
            changes.append(f"otel.enabled = {bool(enabled)}")
        else:
            sink = _find_sink(raw, name)
            if sink is None:
                raise ValueError(f"no destination named {name!r}")
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
    """Delete one named OTel destination or audit sink."""
    cfg_path = str(config_path_for_data_dir(data_dir))
    with locked_config_yaml(cfg_path):
        raw = _load_yaml(cfg_path)
        changes: list[str] = []

        otel = raw.get("otel")
        if isinstance(otel, dict) and isinstance(otel.get("destinations"), list):
            destinations = otel["destinations"]
            kept = [item for item in destinations if not (isinstance(item, dict) and item.get("name") == name)]
            if len(kept) != len(destinations):
                otel["destinations"] = kept
                otel["enabled"] = any(isinstance(item, dict) and bool(item.get("enabled", False)) for item in kept)
                changes.append(f"otel.destinations[{name}] removed")
                _write_yaml(cfg_path, raw)
                return WriteResult(
                    name=name,
                    target="otel",
                    preset_id="",
                    yaml_changes=changes,
                    dotenv_changes=[],
                    warnings=[],
                    dry_run=False,
                )

        sinks = raw.get("audit_sinks")
        if not isinstance(sinks, list):
            raise ValueError(f"no destination named {name!r}")
        new = [s for s in sinks if isinstance(s, dict) and s.get("name") != name]
        if len(new) == len(sinks):
            raise ValueError(f"no destination named {name!r}")
        if new:
            raw["audit_sinks"] = new
        else:
            raw.pop("audit_sinks", None)
        changes.append(f"audit_sinks[{name}] removed")

        _write_yaml(cfg_path, raw)
    return WriteResult(
        name=name,
        target="audit_sinks",
        preset_id="",
        yaml_changes=changes,
        dotenv_changes=[],
        warnings=[],
        dry_run=False,
    )


def _find_otel_destination(raw: dict[str, Any], name: str) -> dict[str, Any] | None:
    otel = raw.get("otel")
    if not isinstance(otel, dict):
        return None
    destinations = otel.get("destinations")
    if not isinstance(destinations, list):
        return None
    return next(
        (item for item in destinations if isinstance(item, dict) and item.get("name") == name),
        None,
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
    write_config_yaml_secure(path, data)


def _advance_named_otel_config_version(raw: dict[str, Any]) -> None:
    """Advance only the exact v6 -> v7 schema transition.

    An absent stamp is historically equivalent to a much older config, not
    necessarily v6. Advancing it directly to v7 would make the Go loader skip
    unrelated LLM and connector migrations, so those files deliberately keep
    their original stamp while receiving the named OTel shape.
    """
    version = raw.get("config_version")
    if isinstance(version, bool):
        return
    try:
        parsed = int(version)
    except (TypeError, ValueError):
        return
    if parsed == _NAMED_OTEL_CONFIG_VERSION - 1:
        raw["config_version"] = _NAMED_OTEL_CONFIG_VERSION


# ---------------------------------------------------------------------------
# Internals — OTel preset
# ---------------------------------------------------------------------------


def _apply_otel_preset(
    raw: dict[str, Any],
    preset: Preset,
    inputs: dict[str, str],
    *,
    data_dir: str,
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

    # Convert an old flat exporter before adding a route so setup is a one-way,
    # lossless migration into the named destination model.
    _migrate_flat_otel_in_place(otel, warnings, data_dir=data_dir)

    endpoint = _render_template(preset.endpoint_template, inputs)

    headers: dict[str, str] = {}
    for k, v in preset.otel_headers.items():
        headers[k] = _render_header_template(v, inputs)
    if preset.id == "galileo":
        for field_name in ("project", "logstream"):
            _validate_literal_header_value(field_name, inputs.get(field_name, ""))
            if _UUID_RE.fullmatch(inputs.get(field_name, "")):
                headers[f"{field_name}id"] = headers.pop(field_name)
    # Honeycomb dataset lives in a separate header; stamp it at apply
    # time from inputs rather than at preset-decl time so per-environment
    # values work.
    if preset.id == "honeycomb" and inputs.get("dataset"):
        headers["x-honeycomb-dataset"] = inputs["dataset"]

    destination: dict[str, Any] = {
        "name": dest_name,
        "preset": preset.id,
        "enabled": bool(enabled),
        "protocol": preset.otel_protocol or inputs.get("protocol", "grpc"),
        "endpoint": endpoint,
    }
    if preset.id == "galileo":
        # Real-time is the Galileo default: completed operations leave the
        # process within one second, while retaining bounded async batching.
        destination["batch"] = {"scheduled_delay_ms": 1000}
    if headers:
        destination["headers"] = headers
    if preset.otel_tls_insecure:
        destination["tls"] = {"insecure": True}
    if preset.span_filter_operations:
        destination["span_filter"] = {
            "operations": [
                {"name": name, "require_attributes": list(attributes)}
                for name, attributes in preset.span_filter_operations
            ]
        }
    elif preset.span_filter_operation or preset.span_filter_required_attributes:
        destination["span_filter"] = {
            "require_operation": preset.span_filter_operation,
            "require_attributes": list(preset.span_filter_required_attributes),
        }

    signals_set = set(signals)
    for sig in ("traces", "metrics", "logs"):
        block: dict[str, Any] = {"enabled": sig in signals_set}
        path = preset.signal_url_paths.get(sig, "")
        if path:
            block["url_path"] = path
        destination[sig] = block

    destinations = otel.setdefault("destinations", [])
    if not isinstance(destinations, list):
        warnings.append("otel.destinations: replaced non-list value")
        destinations = []
        otel["destinations"] = destinations
    replaced = False
    for idx, existing in enumerate(destinations):
        if isinstance(existing, dict) and existing.get("name") == dest_name:
            # Presets own identity, endpoint, their declared headers/filter, and
            # signal enablement. Preserve operator-owned additions such as a
            # private CA, batch tuning, and non-preset headers.
            merged = copy.deepcopy(existing)
            merged.update(
                {
                    key: copy.deepcopy(value)
                    for key, value in destination.items()
                    if key not in {"headers", "tls", "batch"}
                }
            )
            if headers:
                merged_headers = copy.deepcopy(existing.get("headers") or {})
                if preset.id == "galileo":
                    # Routing names and IDs are mutually exclusive aliases.
                    # Remove the previous form when setup switches between
                    # name-based and ID-based routing.
                    for routing_header in ("project", "projectid", "logstream", "logstreamid"):
                        if routing_header not in headers:
                            merged_headers.pop(routing_header, None)
                merged_headers.update(headers)
                merged["headers"] = merged_headers
            if preset.otel_tls_insecure:
                merged_tls = copy.deepcopy(existing.get("tls") or {})
                merged_tls["insecure"] = True
                merged["tls"] = merged_tls
            if "batch" in destination:
                existing_batch = copy.deepcopy(existing.get("batch") or {})
                if preset.id == "galileo":
                    # 5000ms is the historical/global default, not an
                    # operator-tuned real-time value. Upgrade that historical
                    # value to Galileo's one-second default while preserving
                    # every non-default/custom batch field.
                    if existing_batch.get("scheduled_delay_ms") in (None, 5000):
                        existing_batch["scheduled_delay_ms"] = destination["batch"]["scheduled_delay_ms"]
                elif not existing_batch:
                    existing_batch = copy.deepcopy(destination["batch"])
                merged["batch"] = existing_batch
            destinations[idx] = merged
            warnings.append(
                f"overwriting existing OTel destination {dest_name!r} while preserving operator-owned fields"
            )
            replaced = True
            break
    if not replaced:
        destinations.append(destination)

    # The root switch controls the whole fan-out provider. It must reflect
    # the aggregate, not the destination currently being edited: adding one
    # disabled route beside an enabled local collector must not turn every
    # OTel route off.
    otel["enabled"] = any(isinstance(item, dict) and bool(item.get("enabled", False)) for item in destinations)

    # Resource identity is process-wide. Keep service identity here, but do
    # not stamp a vendor preset: different destinations now receive the same
    # resource and vendor-specific preset metadata belongs on each entry.
    resource = otel.setdefault("resource", {})
    if not isinstance(resource, dict):
        resource = {}
        otel["resource"] = resource
    attrs = resource.setdefault("attributes", {})
    if not isinstance(attrs, dict):
        attrs = {}
        resource["attributes"] = attrs
    attrs.pop(_RESOURCE_PRESET_ID_KEY, None)
    attrs.pop(_RESOURCE_PRESET_NAME_KEY, None)
    if inputs.get("service_name"):
        attrs["service.name"] = inputs["service_name"]
    else:
        attrs.setdefault("service.name", "defenseclaw")


def _migrate_flat_otel_in_place(
    otel: dict[str, Any],
    warnings: list[str],
    *,
    data_dir: str,
) -> None:
    """Move a configured flat exporter into ``otel.destinations[]``.

    The runtime accepts only named destinations. Migration preserves a flat
    exporter when setup mutates the file and ignores a bare disabled scaffold.
    """

    existing_destinations = otel.get("destinations")
    has_named_destinations = isinstance(existing_destinations, list)
    env_global_endpoint = _first_runtime_env(
        data_dir,
        "DEFENSECLAW_OTEL_ENDPOINT",
        "OPENCLAW_OTEL_ENDPOINT",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    )
    env_signal_endpoints = {
        sig: _first_runtime_env(
            data_dir,
            f"DEFENSECLAW_OTEL_{sig.upper()}_ENDPOINT",
            f"OPENCLAW_OTEL_{sig.upper()}_ENDPOINT",
            f"OTEL_EXPORTER_OTLP_{sig.upper()}_ENDPOINT",
        )
        for sig in ("traces", "metrics", "logs")
    }
    env_signal_protocols = {
        sig: _first_runtime_env(
            data_dir,
            f"DEFENSECLAW_OTEL_{sig.upper()}_PROTOCOL",
            f"OPENCLAW_OTEL_{sig.upper()}_PROTOCOL",
            f"OTEL_EXPORTER_OTLP_{sig.upper()}_PROTOCOL",
        )
        for sig in ("traces", "metrics", "logs")
    }
    env_endpoint = env_global_endpoint or next(
        (value for value in env_signal_endpoints.values() if value), ""
    )
    has_flat_transport = bool(
        otel.get("endpoint")
        or otel.get("headers")
        or any(
            isinstance(otel.get(sig), dict)
            and ((otel.get(sig) or {}).get("endpoint") or (otel.get(sig) or {}).get("url_path"))
            for sig in ("traces", "metrics", "logs")
        )
    )
    has_destination = bool(
        has_flat_transport
        or (
            not has_named_destinations
            and (
                any(
                    isinstance(otel.get(sig), dict) and (otel.get(sig) or {}).get("enabled") is True
                    for sig in ("traces", "metrics", "logs")
                )
                or (otel.get("enabled") is True and env_endpoint)
            )
        )
    )
    if not has_destination:
        return

    attrs = (otel.get("resource") or {}).get("attributes") or {}
    preset_id = str(attrs.get(_RESOURCE_PRESET_ID_KEY, "") or "generic-otlp")
    name = preset_id if _NAME_RE.match(preset_id) else "generic-otlp"
    configured_endpoints = [
        str(value)
        for value in [
            otel.get("endpoint"),
            *((otel.get(signal) or {}).get("endpoint") for signal in ("traces", "metrics", "logs")),
        ]
        if value
    ]
    if (
        preset_id == "generic-otlp"
        and configured_endpoints
        and all(_endpoint_is_loopback(value) for value in configured_endpoints)
    ):
        preset_id = "local-otlp"
        name = "local-observability"
    if has_named_destinations:
        existing_names = {str(item.get("name", "")) for item in existing_destinations if isinstance(item, dict)}
        base_name = name
        suffix = 2
        while name in existing_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
    destination: dict[str, Any] = {
        "name": name,
        "preset": preset_id,
        "enabled": bool(otel.get("enabled", False)),
        "protocol": str(
            otel.get("protocol", "")
            or _first_runtime_env(
                data_dir,
                "DEFENSECLAW_OTEL_PROTOCOL",
                "OPENCLAW_OTEL_PROTOCOL",
                "OTEL_EXPORTER_OTLP_PROTOCOL",
            )
            or next((value for value in env_signal_protocols.values() if value), "")
            or "grpc"
        ),
        "endpoint": str(otel.get("endpoint", "") or env_global_endpoint or ""),
    }
    for key in ("headers", "tls", "batch"):
        value = otel.get(key)
        if value:
            destination[key] = copy.deepcopy(value)
    if "tls" not in destination:
        legacy_tls_insecure = _first_runtime_env(
            data_dir,
            "DEFENSECLAW_OTEL_TLS_INSECURE",
            "OPENCLAW_OTEL_TLS_INSECURE",
        ).strip().lower()
        if legacy_tls_insecure in {"1", "true", "yes", "on"}:
            destination["tls"] = {"insecure": True}
        elif legacy_tls_insecure in {"0", "false", "no", "off"}:
            destination["tls"] = {"insecure": False}
    has_global_endpoint = bool(otel.get("endpoint") or env_global_endpoint)
    has_explicit_signal_enabled = any(
        isinstance(otel.get(sig), dict) and "enabled" in (otel.get(sig) or {})
        for sig in ("traces", "metrics", "logs")
    )
    for sig in ("traces", "metrics", "logs"):
        source = copy.deepcopy(otel.get(sig) or {})
        if not isinstance(source, dict):
            source = {}
        if not source.get("endpoint") and env_signal_endpoints[sig]:
            source["endpoint"] = env_signal_endpoints[sig]
        if not source.get("protocol") and env_signal_protocols[sig]:
            source["protocol"] = env_signal_protocols[sig]
        if "enabled" not in source and (
            source.get("endpoint")
            or source.get("url_path")
            or (has_global_endpoint and not has_explicit_signal_enabled)
        ):
            source["enabled"] = True
        if sig == "traces":
            source.pop("sampler", None)
            source.pop("sampler_arg", None)
        elif sig == "logs":
            source.pop("emit_individual_findings", None)
        destination[sig] = source

    if has_global_endpoint and not any(
        bool((destination.get(sig) or {}).get("enabled", False))
        for sig in ("traces", "metrics", "logs")
    ):
        for sig in ("traces", "metrics", "logs"):
            destination[sig]["enabled"] = True

    if has_named_destinations:
        otel["destinations"] = [destination, *existing_destinations]
    else:
        otel["destinations"] = [destination]
    for key in ("protocol", "endpoint", "headers", "tls", "batch"):
        otel.pop(key, None)
    traces = otel.get("traces") or {}
    otel["traces"] = {key: value for key, value in traces.items() if key in {"sampler", "sampler_arg"}}
    logs = otel.get("logs") or {}
    otel["logs"] = {key: value for key, value in logs.items() if key == "emit_individual_findings"}
    otel.pop("metrics", None)
    if isinstance(attrs, dict):
        attrs.pop(_RESOURCE_PRESET_ID_KEY, None)
        attrs.pop(_RESOURCE_PRESET_NAME_KEY, None)
    warnings.append(f"migrated flat OTel exporter to named destination {name!r}")


def _first_runtime_env(data_dir: str, *names: str) -> str:
    """Return the first process/.env value without copying secret headers."""

    dotenv: dict[str, str] = {}
    try:
        with open(os.path.join(data_dir, DOTENV_FILE_NAME)) as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                dotenv[key.strip()] = value.strip().strip("'\"")
    except OSError:
        pass
    for name in names:
        value = os.environ.get(name, "") or dotenv.get(name, "")
        if value:
            return value
    return ""


def _endpoint_is_loopback(value: str) -> bool:
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or "").strip("[]").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _validate_literal_header_value(name: str, value: str) -> None:
    value = str(value).strip()
    if not value:
        raise ValueError(f"Galileo {name} must not be empty")
    if len(value) > 512:
        raise ValueError(f"Galileo {name} must be 512 characters or fewer")
    if "$" in value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError(f"Galileo {name} must not contain '$' or control characters")


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
            f"audit_sinks[{name}] already existed — fields overwritten (other keys preserved)",
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
        # / TLS verification is now ON by default on the
        # Go sink. Presets that historically pointed at a self-signed
        # local HEC (the docker-compose ``splunk-hec`` flavour) opt
        # OUT explicitly via ``insecure_skip_verify=true``. Production
        # presets (``splunk-enterprise``) omit the flag entirely so the
        # secure default wins.
        insecure_default = preset.id != "splunk-enterprise"
        if "verify_tls" in inputs:
            # Legacy callers that still pass verify_tls=true|false
            # are mapped onto the new insecure_skip_verify field.
            insecure = not _parse_bool(inputs.get("verify_tls", "true"))
        else:
            insecure = _parse_bool(
                inputs.get(
                    "insecure_skip_verify",
                    "true" if insecure_default else "false",
                )
            )
        block: dict[str, Any] = {
            "endpoint": endpoint,
            "token_env": preset.token_env,
            "index": inputs.get("index", "defenseclaw"),
            "source": inputs.get("source", "defenseclaw"),
            "sourcetype": inputs.get("sourcetype", "_json"),
        }
        # Only emit the field when it diverges from the secure default
        # so production sinks don't carry a redundant negative knob.
        if insecure:
            block["insecure_skip_verify"] = True
        base["splunk_hec"] = block
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
                f"preset {preset.id!r}: missing required input {flag_name!r} (no default provided)",
            )
        resolved[flag_name] = val
    # Pass-through extra keys (dataset, verify_tls, url_path) that are
    # not in prompts but used by specific presets.
    for k, v in inputs.items():
        if k not in resolved:
            resolved[k] = v
    return resolved


def _destination_name(
    preset: Preset,
    override: str | None,
    inputs: dict[str, str],
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
    if preset.id == "local-otlp":
        return "local-observability"
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


def _render_header_template(template: str, inputs: dict[str, str]) -> str:
    """Render preset inputs while preserving ``${ENV_VAR}`` references."""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in inputs:
            raise ValueError(f"header template {template!r} references unknown input {key!r}")
        return inputs[key]

    return re.sub(r"(?<!\$)\{([a-zA-Z_][a-zA-Z0-9_]*)\}", replace, template)


def _strip_scheme(url: str) -> str:
    low = url.lower()
    for prefix in ("https://", "http://"):
        if low.startswith(prefix):
            return url[len(prefix) :]
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
        destination = next(
            (item for item in (a.get("destinations") or []) if isinstance(item, dict) and item.get("name") == name),
            {},
        )
        enabled_signals = [sig for sig in ("traces", "metrics", "logs") if (destination.get(sig) or {}).get("enabled")]
        lines.append(
            f"otel.destinations[{name}] preset={destination.get('preset', '')} "
            f"signals={','.join(enabled_signals) or 'none'}"
        )
        headers = destination.get("headers") or {}
        if headers:
            lines.append(f"otel.destinations[{name}].headers: {', '.join(sorted(headers))} (values redacted)")
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
                f"{preset.token_env}: not set — sink/exporter will fail until exported or added to ~/.defenseclaw/.env",
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
    lines = [f"{k}={sanitize_dotenv_value(v, key=k)}\n" for k, v in sorted(entries.items())]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # O_NOFOLLOW (where available) refuses to open through a symlink so a
    # pre-planted symlink cannot redirect the secret write elsewhere.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        # The 0o600 mode argument to os.open only applies when the file is
        # newly CREATED — POSIX preserves the existing mode on O_TRUNC. A
        # pre-existing group/world-readable dotenv would otherwise keep
        # its loose perms and expose the freshly written observability
        # token (F-0442), so explicitly tighten the descriptor to 0o600.
        try:
            os.fchmod(f.fileno(), 0o600)
        except (AttributeError, OSError):
            # os.fchmod is POSIX-only; fall back to a path-based chmod.
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        f.writelines(lines)
