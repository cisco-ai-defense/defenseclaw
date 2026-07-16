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

"""Read-only renderers for routes already compiled by the Go v8 planner."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

from defenseclaw import config as config_module
from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config
from defenseclaw.observability.custody_status import (
    ConnectorCustodyReport,
    inspect_connector_custody,
)
from defenseclaw.observability.destination_test import (
    DestinationTestError,
    canonical_local_compliance_recorder,
    run_destination_test,
)

_BUCKETS = (
    "compliance.activity",
    "security.finding",
    "guardrail.evaluation",
    "enforcement.action",
    "model.io",
    "tool.activity",
    "asset.scan",
    "asset.lifecycle",
    "network.egress",
    "agent.lifecycle",
    "ai.discovery",
    "telemetry.ingest",
    "platform.health",
    "diagnostic",
)
_SIGNALS = ("logs", "traces", "metrics")
_SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


@dataclass(frozen=True)
class _PlanFilters:
    connector: str = ""
    source: str = ""
    action: str = ""
    event_name: str = ""
    severity: str = ""


@click.group("observability")
def observability_cmd() -> None:
    """Inspect canonical observability collection and routing policy."""


@observability_cmd.group("destination")
def observability_destination() -> None:
    """Inspect or explicitly test one configured destination."""


@observability_destination.command("test")
@click.argument("name")
@click.option(
    "--write-probe",
    is_flag=True,
    help="Send one marked, content-free probe when the named adapter supports isolated writes.",
)
@click.option(
    "--timeout",
    type=click.FloatRange(min=0.1, max=60.0),
    default=5.0,
    show_default=True,
    help="DNS, connection, TLS, and protocol timeout in seconds.",
)
def observability_destination_test(name: str, write_probe: bool, timeout: float) -> None:
    """Test exactly NAME without ordinary collection, routing, or fan-out."""

    try:
        inspected = inspect_v8_config(
            "effective",
            config_path=str(config_module.config_path()),
        )
        result = run_destination_test(
            inspected.effective or {},
            name=name,
            data_dir=inspected.data_dir,
            timeout=timeout,
            write_probe=write_probe,
            compliance=canonical_local_compliance_recorder(
                config_path=inspected.source,
                data_dir=inspected.data_dir,
            ),
        )
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    except DestinationTestError as exc:
        raise click.ClickException(f"destination test failed ({exc.failure_class}): {exc.message}") from exc

    click.echo(f"destination: {result.destination}")
    click.echo(f"kind: {result.kind}")
    click.echo(f"mode: {result.mode}")
    click.echo(f"protocol: {result.protocol}")
    click.echo(f"endpoints tested: {result.endpoint_count}")
    click.echo(f"probe ID: {result.probe_id}")
    if result.mode == "write_probe":
        click.echo("write probe: accepted by the named destination")
    if result.authentication_verified:
        click.echo("authentication: configured credential accepted with the synthetic write probe")
    elif result.mode == "write_probe":
        click.echo("authentication: no credential configured")
    else:
        click.echo("authentication: resolved locally; not transmitted by the non-mutating handshake")
    click.echo("compliance activity: attempt and outcome recorded locally")


@observability_cmd.command("plan")
@click.option("--bucket", "buckets", multiple=True, type=click.Choice(_BUCKETS), help="Limit bucket rows.")
@click.option("--signal", "signals", multiple=True, type=click.Choice(_SIGNALS), help="Limit signal rows.")
@click.option("--connector", default="", help="Evaluate connector-constrained routes.")
@click.option("--source", default="", help="Evaluate source-constrained routes.")
@click.option("--action", default="", help="Evaluate action-constrained routes.")
@click.option("--event-name", default="", help="Evaluate event-name-constrained routes.")
@click.option(
    "--severity",
    type=click.Choice(tuple(_SEVERITY_RANK), case_sensitive=False),
    default=None,
    help="Evaluate minimum-severity route constraints.",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", show_default=True)
def observability_plan(
    buckets: tuple[str, ...],
    signals: tuple[str, ...],
    connector: str,
    source: str,
    action: str,
    event_name: str,
    severity: str | None,
    fmt: str,
) -> None:
    """Render collection and first-route outcomes from the compiled Go plan."""

    try:
        inspected = inspect_v8_config(
            "effective",
            config_path=str(config_module.config_path()),
        )
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    effective = inspected.effective or {}
    filters = _PlanFilters(
        connector=connector.strip(),
        source=source.strip(),
        action=action.strip(),
        event_name=event_name.strip(),
        severity=severity.upper() if severity else "",
    )
    rows = _plan_rows(
        effective,
        selected_buckets=set(buckets),
        selected_signals=set(signals),
        filters=filters,
    )
    delivery = _delivery_settings(effective)
    custody = inspect_connector_custody(
        _audit_db_path(effective, inspected.data_dir),
        inspected.data_dir,
    )
    if fmt == "json":
        click.echo(
            json.dumps(
                {
                    "basis": "canonical_go_compiled_routes",
                    "config_version": inspected.config_version,
                    "plan_digest": inspected.plan_digest,
                    "network_validation": inspected.network_validation,
                    "delivery": delivery,
                    "connector_export_custody": custody.as_json(),
                    "rows": rows,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        _render_plan_table(rows, inspected.plan_digest, delivery, custody)
    for warning in effective.get("warnings") or []:
        if isinstance(warning, dict):
            code = str(warning.get("code") or "warning")
            summary = str(warning.get("summary") or "configuration warning")
            click.echo(f"warning: {code}: {summary}", err=True)


def _plan_rows(
    effective: dict[str, Any],
    *,
    selected_buckets: set[str],
    selected_signals: set[str],
    filters: _PlanFilters,
) -> list[dict[str, Any]]:
    destinations = [item for item in effective.get("destinations") or [] if isinstance(item, dict)]
    rows: list[dict[str, Any]] = []
    for bucket_policy in effective.get("buckets") or []:
        if not isinstance(bucket_policy, dict):
            continue
        bucket = str(bucket_policy.get("bucket") or "")
        if selected_buckets and bucket not in selected_buckets:
            continue
        collect = bucket_policy.get("collect") if isinstance(bucket_policy.get("collect"), dict) else {}
        for signal in _SIGNALS:
            if selected_signals and signal not in selected_signals:
                continue
            collected = bool(collect.get(signal, False))
            for destination in destinations:
                rows.append(
                    _destination_row(
                        bucket,
                        signal,
                        collected,
                        str(bucket_policy.get("reload_applicability") or ""),
                        destination,
                        filters,
                    )
                )
    return rows


def _destination_row(
    bucket: str,
    signal: str,
    collected: bool,
    collection_reload: str,
    destination: dict[str, Any],
    filters: _PlanFilters,
) -> dict[str, Any]:
    name = str(destination.get("name") or "")
    result: dict[str, Any] = {
        "bucket": bucket,
        "signal": signal,
        "collected": collected,
        "destination": name,
        "decision": "unmatched",
        "route": None,
        "redaction_profile": None,
    }
    reload_applicability = destination.get("reload_applicability")
    if collection_reload or isinstance(reload_applicability, dict):
        reload_policy = reload_applicability if isinstance(reload_applicability, dict) else {}
        result["reload_applicability"] = {
            "collection": collection_reload or None,
            "routing": reload_policy.get("policy"),
            "transport": reload_policy.get("transport"),
        }
    if not destination.get("enabled", False):
        result["decision"] = "destination_disabled"
        return _annotate_compatibility(result, signal, destination, filters)
    if signal not in (destination.get("selected_signals") or []):
        result["decision"] = "signal_not_selected"
        return _annotate_compatibility(result, signal, destination, filters)
    if not collected:
        floor_route = _destination_floor_route(destination) if name == "local-sqlite" else None
        if signal == "logs" and floor_route is not None:
            # The effective plan deliberately identifies the floor route but
            # does not duplicate the event-level floor catalog.  Do not claim
            # an exact event match that the Python renderer cannot prove.
            result["decision"] = "conditional"
            result["potential_action"] = "floor_only"
            result["condition"] = "mandatory_floor_event_qualification"
            result["route"] = floor_route
        else:
            result["decision"] = "not_collected"
        return _annotate_compatibility(result, signal, destination, filters)

    for route in destination.get("routes") or []:
        if not isinstance(route, dict):
            continue
        match = _route_match(route, bucket, signal, filters)
        if match == "no":
            continue
        result["route"] = route.get("name") or None
        if match == "conditional":
            result["decision"] = "conditional"
            result["potential_action"] = route.get("action") or "send"
            return _annotate_compatibility(result, signal, destination, filters)
        action = str(route.get("action") or "send")
        result["decision"] = action
        if action == "send" and signal in {"logs", "traces"}:
            profiles = route.get("redaction_profile_by_bucket")
            if isinstance(profiles, dict):
                result["redaction_profile"] = profiles.get(bucket)
        return _annotate_compatibility(result, signal, destination, filters)
    return _annotate_compatibility(result, signal, destination, filters)


def _annotate_compatibility(
    result: dict[str, Any],
    signal: str,
    destination: dict[str, Any],
    filters: _PlanFilters,
) -> dict[str, Any]:
    """Render only Go-published family/profile facts for an exact span filter."""

    if signal != "traces" or not filters.event_name:
        return result
    profiles = destination.get("compatibility_profiles")
    if not isinstance(profiles, list):
        return result
    annotations: list[dict[str, Any]] = []
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("id"), str):
            continue
        eligible_families = profile.get("eligible_span_families")
        if not isinstance(eligible_families, list):
            continue
        matched_family = next(
            (
                family
                for family in eligible_families
                if isinstance(family, dict)
                and family.get("event_name") == filters.event_name
                and family.get("bucket") == result.get("bucket")
            ),
            None,
        )
        family_member = matched_family is not None
        profile_availability = str(profile.get("availability") or "unknown")
        binding_availability = (
            str(matched_family.get("availability") or "unknown") if isinstance(matched_family, dict) else None
        )
        decision = str(result.get("decision") or "unmatched")
        family_shape_available = (
            family_member and profile_availability == "available" and binding_availability == "available"
        )
        family_eligible = family_shape_available and decision == "send"
        if not family_member:
            eligibility = "family_not_in_profile"
        elif profile_availability != "available":
            eligibility = f"profile_{profile_availability}"
        elif binding_availability != "available":
            eligibility = f"family_binding_{binding_availability}"
        elif decision == "send":
            eligibility = "eligible"
        elif decision == "conditional":
            eligibility = "conditional_route"
        else:
            eligibility = "not_routed"
        annotations.append(
            {
                "profile": profile["id"],
                "profile_availability": profile_availability,
                "event_name": filters.event_name,
                "family_member": family_member,
                "family_binding_availability": binding_availability,
                "family_shape_available": family_shape_available,
                "family_eligible": family_eligible,
                "eligibility": eligibility,
            }
        )
    if annotations:
        result["compatibility"] = annotations
    return result


def _route_match(route: dict[str, Any], bucket: str, signal: str, filters: _PlanFilters) -> str:
    if signal not in (route.get("signals") or []):
        return "no"
    selector = route.get("selector") if isinstance(route.get("selector"), dict) else {}
    route_buckets = selector.get("buckets") or []
    if route_buckets and bucket not in route_buckets:
        return "no"

    conditional = False
    dimensions = (
        ("sources", filters.source),
        ("connectors", filters.connector),
        ("actions", filters.action),
        ("event_names", filters.event_name),
    )
    for field, provided in dimensions:
        expected = selector.get(field) or []
        if not expected or "*" in expected:
            continue
        if not provided:
            conditional = True
        elif provided not in expected:
            return "no"

    minimum = str(selector.get("min_severity") or "").upper()
    if minimum:
        if not filters.severity:
            conditional = True
        elif _SEVERITY_RANK.get(filters.severity, 0) < _SEVERITY_RANK.get(minimum, 0):
            return "no"
    return "conditional" if conditional else "match"


def _destination_floor_route(destination: dict[str, Any]) -> str | None:
    for route in destination.get("routes") or []:
        if isinstance(route, dict) and route.get("includes_mandatory_floor") is True:
            return str(route.get("name") or "") or None
    return None


def _delivery_settings(effective: dict[str, Any]) -> list[dict[str, Any]]:
    """Project compiled queue/batch values without deriving defaults in Python."""

    result: list[dict[str, Any]] = []
    for destination in effective.get("destinations") or []:
        if not isinstance(destination, dict):
            continue
        transport = destination.get("transport")
        if not isinstance(transport, dict):
            continue
        batch = transport.get("batch")
        if not isinstance(batch, dict):
            continue
        result.append(
            {
                "destination": str(destination.get("name") or ""),
                "kind": str(destination.get("kind") or ""),
                "max_queue_size": batch.get("max_queue_size"),
                "max_queue_bytes": batch.get("max_queue_bytes"),
                "max_export_batch_size": batch.get("max_export_batch_size"),
                "max_export_batch_bytes": batch.get("max_export_batch_bytes"),
                "scheduled_delay_ms": batch.get("scheduled_delay_ms"),
            }
        )
    return result


def _render_plan_table(
    rows: list[dict[str, Any]],
    digest: str,
    delivery: list[dict[str, Any]],
    custody: ConnectorCustodyReport | None = None,
) -> None:
    click.echo(f"Compiled Go plan digest: {digest}")
    headings = (
        "BUCKET",
        "SIGNAL",
        "COLLECT",
        "DESTINATION",
        "DECISION",
        "ROUTE",
        "REDACTION",
        "COMPATIBILITY",
        "RELOAD",
    )
    values = [
        (
            row["bucket"],
            row["signal"],
            "yes"
            if row["collected"]
            else (
                "floor?" if row["decision"] == "conditional" and row.get("potential_action") == "floor_only" else "no"
            ),
            row["destination"],
            row["decision"],
            row["route"] or "-",
            row["redaction_profile"] or "-",
            _table_compatibility(row),
            _table_reload(row),
        )
        for row in rows
    ]
    widths = [len(value) for value in headings]
    for row in values:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    click.echo("  ".join(value.ljust(widths[index]) for index, value in enumerate(headings)))
    for row in values:
        click.echo("  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))
    if any(row["decision"] == "conditional" for row in rows):
        click.echo("conditional = an earlier route constrains metadata not supplied by the current filters")
    if delivery:
        click.echo("Delivery limits (compiled defaults and source overrides):")
        delivery_headings = (
            "DESTINATION",
            "KIND",
            "QUEUE_RECORDS",
            "QUEUE_BYTES",
            "BATCH_RECORDS",
            "BATCH_BYTES",
            "DELAY_MS",
        )
        delivery_values = [
            (
                item["destination"],
                item["kind"],
                item["max_queue_size"],
                item["max_queue_bytes"],
                item["max_export_batch_size"] or "-",
                item["max_export_batch_bytes"] or "-",
                item["scheduled_delay_ms"] or "-",
            )
            for item in delivery
        ]
        delivery_widths = [len(value) for value in delivery_headings]
        for row in delivery_values:
            for index, value in enumerate(row):
                delivery_widths[index] = max(delivery_widths[index], len(str(value)))
        click.echo("  ".join(value.ljust(delivery_widths[index]) for index, value in enumerate(delivery_headings)))
        for row in delivery_values:
            click.echo("  ".join(str(value).ljust(delivery_widths[index]) for index, value in enumerate(row)))
    if custody is not None:
        _render_custody_table(custody)
    click.echo("Rows render canonical Go-compiled routes; Python does not compile routing policy.")


def _audit_db_path(effective: dict[str, Any], data_dir: str) -> str:
    local = effective.get("local")
    if isinstance(local, dict):
        path = local.get("path")
        if isinstance(path, str) and path.strip():
            candidate = Path(path).expanduser()
            if not candidate.is_absolute():
                candidate = Path(data_dir) / candidate
            return str(candidate)
    return str(Path(data_dir) / "audit.db")


def _render_custody_table(report: ConnectorCustodyReport) -> None:
    click.echo("Connector export custody (read-only correlation ledger):")
    if report.state != "available":
        click.echo(f"  unavailable: {report.reason}")
        return
    if not report.instances:
        click.echo("  no connector instances observed")
    for item in report.instances:
        identity = item.connector if item.default else f"{item.connector}/{item.connector_instance_id[:8]}"
        detail = (
            f"custody={item.custody}; profile={item.profile_version}; "
            f"managed_config={item.managed_config_state}; "
            f"normalized={item.normalized_batches}; drop_only={item.drop_only_batches}; "
            f"credentials={item.credential_state}"
        )
        click.echo(f"  {identity}: {detail}")
    if report.unattributed_authentication_failures:
        click.echo(
            "  unattributed: "
            f"authentication_failures={report.unattributed_authentication_failures}; "
            f"last={report.last_unattributed_authentication_failure or 'unknown'}"
        )
    if report.event_rows_truncated:
        click.echo("  warning: recent ingest evidence reached the bounded read limit")


def _table_compatibility(row: dict[str, Any]) -> str:
    annotations = row.get("compatibility")
    if not isinstance(annotations, list):
        return "-"
    values = [
        f"{item.get('profile')}:{item.get('eligibility')}"
        for item in annotations
        if isinstance(item, dict) and item.get("profile") and item.get("eligibility")
    ]
    return ",".join(values) or "-"


def _table_reload(row: dict[str, Any]) -> str:
    applicability = row.get("reload_applicability")
    if not isinstance(applicability, dict):
        return "-"
    values = [str(applicability.get(field) or "unknown") for field in ("collection", "routing", "transport")]
    if values[0] == values[1] == values[2]:
        return values[0]
    return f"collect={values[0]},route={values[1]},transport={values[2]}"
