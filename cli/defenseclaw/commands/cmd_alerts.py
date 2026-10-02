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

"""defenseclaw alerts — View and manage security alerts.

P3-#20 collapsed the legacy Textual TUI here in favour of the Go-based
panel shipped with ``defenseclaw tui`` (internal/tui/alerts.go). This
module now renders a plain, pipe-friendly table by default and supports
``--show N`` for scripted deep dives. The ``--tui`` flag is retained as
a no-op for backward compatibility with muscle memory and older docs;
it prints a deprecation notice and falls through to the table so
existing aliases/scripts keep working.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

import click
import requests

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.gateway import OrchestratorClient, alert_disposition_timeout_seconds
from defenseclaw.logger import _gateway_api_host

# ---------------------------------------------------------------------------
# Table view helpers
# ---------------------------------------------------------------------------

_OVERHEAD   = 19
_W_IDX      = 2
_W_SEV      = 8
_W_TIME     = 5
_W_ACTION   = 17
_W_TARGET   = 11
_W_FIXED    = _W_IDX + _W_SEV + _W_TIME + _W_ACTION + _W_TARGET  # = 43

_SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _ellipsis() -> str:
    # Piped or legacy-code-page output is written as ASCII, where the stream
    # turns "…" into "..." after Rich sized the column (WIN2-U3-13), so
    # truncate with the ASCII form there and size it correctly.
    return "…" if ux.unicode_output_enabled() else "..."


def _trunc(s: str, width: int) -> str:
    s = s.strip()
    if len(s) <= width:
        return s
    ell = _ellipsis()
    return s[: max(0, width - len(ell))] + ell


def _trunc_path(s: str, width: int) -> str:
    s = s.strip()
    if len(s) <= width:
        return s
    ell = _ellipsis()
    # Windows paths split on "\\" (GAP-1590).
    sep = "\\" if "\\" in s and "/" not in s else "/"
    parts = s.rstrip(sep).split(sep)
    for n in range(1, len(parts) + 1):
        candidate = sep.join(parts[-n:])
        if len(candidate) + len(ell) + 1 <= width:
            return ell + sep + candidate
    tail = parts[-1]
    if len(tail) + len(ell) + 1 <= width:
        return ell + sep + tail
    return ell + s[-max(1, width - len(ell)):]


_ABS_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|[/\\~])")


def _path_name(target: str) -> str:
    """The last part of a file system path (the skill or file name); other targets as is."""
    target = target.strip()
    if not _ABS_PATH.match(target):
        return target
    return re.split(r"[\\/]", target.rstrip("\\/"))[-1] or target


_DETAIL_KEY = re.compile(r"[A-Za-z_][\w.]*")


def _detail_tokens(raw: str) -> list[str]:
    """Split details on whitespace, keeping a "<redacted len=N sha=H>" placeholder whole."""
    tokens: list[str] = []
    for tok in raw.split():
        if tokens and tokens[-1].count("<") > tokens[-1].count(">"):
            tokens[-1] += " " + tok
        else:
            tokens.append(tok)
    return tokens


def _strip_details_json(raw: str) -> str:
    """Drop the trailing ``details_json=`` blob; it repeats the key=value fields."""
    if raw.startswith("details_json="):
        return ""
    return raw.split(" details_json=", 1)[0]


def _humanize_details(raw: str) -> str:
    raw = _strip_details_json(raw or "")
    if not raw:
        return ""
    tokens = _detail_tokens(raw)
    if not any("=" in t for t in tokens):
        return raw
    kv: dict[str, str] = {}
    plain: list[str] = []
    last = ""
    for tok in tokens:
        k, sep, v = tok.partition("=")
        if sep and _DETAIL_KEY.fullmatch(k):
            kv[k] = v
            last = k
        elif last:
            # A value with spaces runs on to the next key
            # ("reason=matched: RULE-ID:title", "agent_version_raw=2.1 (Agent)").
            kv[last] += " " + tok
        else:
            plain.append(tok)
    # would_block is the observe-mode "would have blocked"; false says nothing
    # and reads as a contradiction next to action=block.
    if kv.get("would_block") == "false":
        kv.pop("would_block")
    parts: list[str] = []
    if "host" in kv and "port" in kv:
        parts.append(f"{kv.pop('host')}:{kv.pop('port')}")
    elif "port" in kv:
        parts.append(f":{kv.pop('port')}")
    for key in ("mode", "environment", "status", "protocol", "scanner_mode"):
        if key in kv:
            parts.append(kv.pop(key))
    if "model" in kv:
        parts.append(kv.pop("model").split("/")[-1])
    for key in ("max_severity", "scanner", "findings"):
        kv.pop(key, None)
    for k, v in kv.items():
        parts.append(f"{k}={v}")
    parts.extend(plain)
    return " ".join(parts)


def _findings_json(findings: list[dict], width: int) -> str:
    suffix = _ellipsis()
    close = "]"
    parts: list[str] = []
    for f in findings:
        entry = json.dumps({"severity": f["severity"], "title": f["title"]}, separators=(",", ":"))
        candidate = "[" + ",".join(parts + [entry]) + close
        if len(candidate) > width:
            if parts:
                trunc = "[" + ",".join(parts) + "," + suffix
                if len(trunc) <= width:
                    return trunc
            full = json.dumps(
                [{"severity": f["severity"], "title": f["title"]} for f in findings],
                separators=(",", ":"),
            )
            return _trunc(full, width)
        parts.append(entry)
    return "[" + ",".join(parts) + close


def _kv(details: str) -> dict[str, str]:
    return dict(tok.split("=", 1) for tok in (details or "").split() if "=" in tok)


# When --connector is set, scan a generous window of recent alerts so the
# filter can surface up to --limit matches even when other connectors
# dominate the most-recent rows. Bounded so a huge audit DB stays responsive.
_CONNECTOR_SCAN_POOL = 2000


def _event_connector(event) -> str:
    """Connector attributed to an alert from its persisted provenance.

    First-class audit and structured fields take precedence; the legacy
    ``connector=`` detail token remains readable for historical rows.
    Gateway-global alerts carry no connector and return ""."""
    connector = str(getattr(event, "connector", "") or "").strip().lower()
    if connector:
        return connector
    structured = getattr(event, "structured", None)
    if isinstance(structured, dict):
        connector = str(structured.get("connector") or "").strip().lower()
        if connector:
            return connector
    return _kv(event.details or "").get("connector", "").lower()


def _hook_decision(hook_details: list[str], hook_event: str = "") -> str:
    """Decision of the connector-hook rows recorded for the same request.

    A post-tool finding (PostToolUse, ...) cannot block the call that already
    ran, so it is not labelled observe mode on an action-mode connector
    (GAP-1303)."""
    from defenseclaw.hook_metrics import detection_only_hook_label  # noqa: PLC0415

    decision = ""
    for raw in hook_details:
        kv = _kv(_strip_details_json(raw))
        action = kv.get("action", "").lower()
        if action == "block":
            return "blocked"
        # Observe mode records action=allow raw_action=block, with or without
        # would_block=true; both are "would block" (GAP-1213).
        observed_block = action == "allow" and kv.get("raw_action", "").lower() == "block"
        if kv.get("would_block", "").lower() == "true" or observed_block:
            # A post-tool or MessageDisplay finding cannot block, whatever
            # the connector's mode (GAP-1303, GAP-1531).
            decision = detection_only_hook_label(hook_event) or "would block (observe mode)"
        elif not decision and action:
            decision = action
    return decision


def _acp_route(hook_details: list[str]) -> str:
    """``ACP session/prompt (client zed)`` from the guardrail-verdict row of an ACP finding."""
    for raw in hook_details:
        kv = _kv(raw)
        if method := kv.get("acp_method", ""):
            client = kv.get("acp_client", "")
            return f"ACP {method} (client {client})" if client else f"ACP {method}"
    return ""


# The audit store replaces the title of every finding classed as a secret
# with this placeholder, including rules tagged "credential" whose pack title
# names no secret (GAP-1223).
_REDACTED_SECRET_TITLE = "Secret finding"
_RULE_FILE_LIMIT = 1024 * 1024


def _rule_pack_dirs() -> list[Path]:
    """Rule packs to read titles from: configured, seeded copies, then bundled."""
    dirs: list[Path] = []
    try:
        from defenseclaw import config as config_module  # noqa: PLC0415

        cfg = config_module.load()
        gc = cfg.guardrail
        if str(getattr(gc, "rule_pack_dir", "") or "").strip():
            dirs.append(Path(gc.rule_pack_dir).expanduser())
        policy_dir = str(getattr(cfg, "policy_dir", "") or "").strip()
        if policy_dir:
            seeded = Path(policy_dir).expanduser() / "guardrail"
            if seeded.is_dir():
                dirs.extend(sorted(p for p in seeded.iterdir() if p.is_dir()))
    except Exception:  # noqa: BLE001 - titles are a display nicety.
        pass
    from defenseclaw.paths import bundled_guardrail_profiles_dir  # noqa: PLC0415

    bundled = bundled_guardrail_profiles_dir()
    if bundled is not None:
        dirs.extend(sorted(p for p in bundled.iterdir() if p.is_dir()))
    return dirs


@functools.lru_cache(maxsize=1)
def _rule_pack_titles() -> dict[str, str]:
    """Rule id -> title from the local rule packs (static catalog text)."""
    import yaml  # noqa: PLC0415

    titles: dict[str, str] = {}
    for pack in _rule_pack_dirs():
        rules_dir = pack / "rules"
        try:
            files = sorted(rules_dir.glob("*.yaml")) if rules_dir.is_dir() else []
        except OSError:
            continue
        for path in files:
            try:
                if path.stat().st_size > _RULE_FILE_LIMIT:
                    continue
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - skip an unreadable or broken file.
                continue
            rules = data.get("rules") if isinstance(data, dict) else None
            for rule in rules if isinstance(rules, list) else []:
                if isinstance(rule, dict) and isinstance(rule.get("id"), str) and isinstance(rule.get("title"), str):
                    titles.setdefault(rule["id"].strip(), rule["title"].strip())
    return titles


def _finding_title(rule_id: str, title: str) -> str:
    """The pack's own title for a rule whose stored title was redacted."""
    if title == _REDACTED_SECRET_TITLE and rule_id:
        return _rule_pack_titles().get(rule_id, title) or title
    return title


def _finding_facts(
    e,
    hook_details: dict[str, list[str]],
    targets: dict[str, dict[str, str]] | None = None,
) -> dict[str, str] | None:
    """Readable facts for a canonical finding row (GAP-1080).

    The audit row behind a hook-rule finding has an empty target and only
    ``finding.observed`` as details; the rule, target and scanner live in its
    structured payload and the decision in the connector-hook row of the same
    request.
    """
    structured = getattr(e, "structured", None)
    if e.action not in ("scan-finding", "sandbox-finding") or not isinstance(structured, dict):
        return None
    rule_id = str(structured.get("defenseclaw.finding.rule_id") or "").strip()
    if not rule_id:
        return None
    title = _finding_title(rule_id, str(structured.get("defenseclaw.finding.title") or "").strip())
    # A skill or path scan finding keeps its path in the scan result (GAP-1590).
    scanned = (targets or {}).get(e.id, {})
    target = (
        e.target or str(structured.get("defenseclaw.finding.target_ref") or "").strip() or scanned.get("target", "")
    )
    if e.action == "sandbox-finding":
        # GAP-1303: a sandbox finding row has no target and only
        # ``finding.observed`` as details; name the sandbox (or the
        # destination) and the OpenShell disposition ("FINDING:BLOCKED ...").
        sandbox = str(structured.get("defenseclaw.sandbox.name") or "").strip()
        evidence = str(structured.get("defenseclaw.guardrail.evidence_summary") or "")
        disposition = re.match(r"FINDING:([A-Z_]+)\b", evidence.strip())
        return {
            "target": target or sandbox,
            "decision": disposition.group(1).lower().replace("_", " ") if disposition else "",
            "connector": _event_connector(e),
            "rule": f"{rule_id}: {title}" if title else rule_id,
            "sandbox": sandbox if sandbox != (target or sandbox) else "",
        }
    facts = {
        "target": target,
        "decision": _hook_decision(hook_details.get(e.id, []), target),
        "connector": _event_connector(e),
        "rule": f"{rule_id}: {title}" if title else rule_id,
        "scanner": str(structured.get("defenseclaw.scan.scanner") or "").strip(),
        "route": _acp_route(hook_details.get(e.id, [])),
        "path": scanned.get("path", "") if scanned.get("path", "") != target else "",
    }
    return facts


def _quarantine_facts(e, targets: dict[str, dict[str, str]]) -> dict[str, str] | None:
    """Name the skill or plugin of a quarantine row (GAP-1590).

    The ``enforcement.quarantine.applied`` row has no target; the
    ``asset.quarantined`` row of the same enforcement names the asset."""
    if e.action != "quarantine" or e.target:
        return None
    found = targets.get(e.id)
    if not found:
        return None
    return {"target": found.get("target", ""), "moved_to": found.get("path", "")}


def _alert_targets_for(store, alert_list: list) -> dict[str, dict[str, str]]:
    lookup = getattr(store, "alert_targets_for", None)
    ids = [
        e.id for e in alert_list
        if not (e.target or "").strip() and e.action in ("scan-finding", "quarantine") and getattr(e, "id", "")
    ]
    if lookup is None or not ids:
        return {}
    try:
        result = lookup(ids)
    except Exception:  # noqa: BLE001 - an older or locked audit DB only loses the target
        return {}
    return result if isinstance(result, dict) else {}


def _short_hook_target(target: str, connector: str) -> str:
    """``claudecode:PostToolUse`` -> ``PostToolUse``; Details already names the connector."""
    prefix = f"{connector}:" if connector else ""
    if prefix and target.lower().startswith(prefix.lower()) and len(target) > len(prefix):
        return target[len(prefix):]
    return target


def _finding_details(facts: dict[str, str]) -> str:
    return " ".join(
        f"{key}={facts[key]}" for key in ("decision", "connector", "rule", "scanner", "sandbox") if facts.get(key)
    )


def _hook_details_for(store, alert_list: list) -> dict[str, list[str]]:
    lookup = getattr(store, "hook_details_for_alerts", None)
    ids = [e.id for e in alert_list if e.action == "scan-finding" and getattr(e, "id", "")]
    if lookup is None or not ids:
        return {}
    try:
        result = lookup(ids)
    except Exception:  # an older or locked audit DB only loses the decision
        return {}
    return result if isinstance(result, dict) else {}


def _filter_by_connector(alert_list: list, connector: str | None) -> list:
    """Keep only alerts whose connector matches ``connector`` (substring,
    case-insensitive — same match rule as the TUI ``connector:`` token).

    An empty/None ``connector`` is a no-op so single-connector and unfiltered
    invocations behave exactly as before."""
    needle = (connector or "").strip().lower()
    if not needle:
        return alert_list
    return [e for e in alert_list if needle in _event_connector(e)]


def _render_table(alert_list: list, store, connector: str | None = None) -> None:
    """Plain Rich table — the single renderer since the Textual TUI
    was retired in P3-#20. Kept in a helper so the deprecated
    ``--tui`` flag can fall through here without duplicating the
    column/width logic."""
    from rich import box
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    console = Console()
    term_width = console.size.width
    # A wide terminal shows the whole hook event (UserPromptSubmit,
    # PostToolBatch); 11 columns cut it to "...ptSubmit" (GAP-1535).
    w_target = _W_TARGET if term_width < 100 else 18
    w_details = max(11, term_width - _OVERHEAD - _W_FIXED - (w_target - _W_TARGET))

    scope = f" — connector={connector}" if (connector or "").strip() else ""
    table = Table(
        title=f"Security Alerts (last {len(alert_list)}){scope}",
        caption=(
            "Run [bold]defenseclaw alerts --show #[/bold] for full details and the alert ID "
            "(for [bold]alerts acknowledge/dismiss --id[/bold]), "
            "or [bold]defenseclaw tui[/bold] for the interactive Alerts panel."
        ),
        show_lines=False,
        box=box.HEAVY_HEAD if ux.unicode_output_enabled() else box.ASCII,
    )
    table.add_column("#",         no_wrap=True)
    table.add_column("Severity",  style="bold", no_wrap=True)
    table.add_column("Time",      no_wrap=True)
    table.add_column("Action",    no_wrap=True)
    table.add_column("Target",    no_wrap=True)
    table.add_column("Details [--show #]", no_wrap=True)

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
    }

    hook_details = _hook_details_for(store, alert_list)
    targets = _alert_targets_for(store, alert_list)
    for idx, e in enumerate(alert_list, 1):
        sev_style = sev_styles.get(e.severity, "")
        sev_cell = f"[{sev_style}]{e.severity}[/{sev_style}]" if sev_style else e.severity
        ts     = e.timestamp.strftime("%H:%M") if e.timestamp else ""
        action = _trunc(e.action or "", _W_ACTION)
        target = _trunc_path(e.target or "", w_target)
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        facts = _finding_facts(e, hook_details, targets)
        quarantined = _quarantine_facts(e, targets)
        if facts is not None:
            short = _path_name(_short_hook_target(facts["target"], facts.get("connector", "")))
            target = _trunc_path(short, w_target)
            raw_details = _finding_details(facts)
        elif quarantined is not None:
            target = _trunc_path(quarantined["target"], w_target)
            raw_details = f"quarantined to {quarantined['moved_to']}" if quarantined["moved_to"] else "quarantined"
        elif e.action == "scan" and scanner_name and e.target:
            findings = store.get_findings_for_target(e.target, scanner_name)
            raw_details = _findings_json(findings, w_details) if findings else _humanize_details(e.details or "")
        else:
            raw_details = _humanize_details(e.details or "")
        details = _trunc(raw_details, w_details)
        table.add_row(
            escape(str(idx)), sev_cell, ts,
            escape(action), escape(target), escape(details),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# CLI command group (default = table view)
# ---------------------------------------------------------------------------

@click.group("alerts", invoke_without_command=True)
@click.option("-n", "--limit", default=25, help="Number of alerts to load")
@click.option("--show", "show_idx", default=None, type=int,
              help="Print full details for alert # and exit (non-interactive)")
@click.option(
    "--connector",
    "connector",
    default=None,
    help=(
        "Only show alerts from this connector (for example codex, claudecode, "
        "antigravity); the same match as the TUI's connector: search."
    ),
)
@click.option(
    "--tui/--no-tui",
    default=False,
    hidden=True,
    help="Retired: use 'defenseclaw tui' (Alerts panel). Prints a notice and shows the table.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the alerts as a JSON list.")
@click.pass_context
def alerts(
    ctx: click.Context,
    limit: int,
    show_idx: int | None,
    connector: str | None,
    tui: bool,
    as_json: bool,
) -> None:
    """View and manage security alerts."""
    if ctx.invoked_subcommand is not None:
        return
    app = ctx.find_object(AppContext)
    if app is None:
        raise click.ClickException("internal error: AppContext missing")
    if as_json:
        _alerts_json(app, limit, connector)
        return
    _alerts_default(app, limit, show_idx, tui, connector)


# Delivery failure codes (internal/observability/delivery) in plain words.
_DELIVERY_FAILURE_REASONS = {
    "http_authentication": "the destination rejected the credentials (HTTP 401/403); check the API key or token",
    "hec_ack_authentication": "the destination rejected the credentials; check the HEC token",
    "http_retryable": "the destination was busy or failing (HTTP 408, 429 or 5xx)",
    "hec_ack_retryable": "the destination was busy and asked for a retry",
    "http_rejected": "the destination rejected the data (HTTP 4xx)",
    "hec_ack_rejected": "the destination rejected the data",
    "resolution_failed": "the endpoint host name did not resolve; check the endpoint and DNS",
    "connection_failed": "could not connect to the endpoint; check the endpoint and the network",
    "request_timeout": "the export timed out",
    "request_canceled": "the export was canceled (usually a gateway restart)",
    "acknowledgement_lost": "the export was sent but no reply arrived",
    "transport_failed": "a network error interrupted the export",
    "endpoint_prohibited": "the endpoint is blocked by the egress policy",
    "queue_full": "the export queue was full, so records were dropped",
}


def _alert_next_step(event) -> str:
    """Return a next step for alerts whose details alone do not say what to do."""
    details = (event.details or "").strip()
    if event.action == "telemetry-destination":
        destination = details.split("/", 1)[0].strip()
        code = details.rsplit(":", 1)[1].strip() if ":" in details else ""
        reason = _DELIVERY_FAILURE_REASONS.get(code, "")
        lead = "the gateway retries on its own"
    elif event.action == "circuit_breaker_open":
        destination = details.split(" ", 1)[0].strip()
        reason = ""
        lead = "the gateway paused exports to this destination and retries on its own"
    else:
        return ""
    status_cmd = (
        "defenseclaw setup galileo status"
        if destination == "galileo"
        else "defenseclaw setup observability list"
    )
    selector = f"--id {event.id}" if event.id else "--severity HIGH"
    prefix = f"{reason[0].upper()}{reason[1:]}. " if reason else ""
    return (
        f"{prefix}Run '{status_cmd}' to see whether delivery has recovered ({lead}). "
        "This alert records the failure and stays listed after recovery; clear it "
        f"with 'defenseclaw alerts dismiss {selector}'."
    )


def _alerts_json(app: AppContext, limit: int, connector: str | None) -> None:
    """``alerts --json``: the same rows as the table, newest first."""
    import json  # noqa: PLC0415

    if not app.store:
        raise click.ClickException("No audit store available. Run 'defenseclaw init' first.")
    needle = (connector or "").strip()
    if needle:
        alert_list = _filter_by_connector(app.store.list_alerts(max(limit, _CONNECTOR_SCAN_POOL)), needle)[:limit]
    else:
        alert_list = app.store.list_alerts(limit)
    hook_details = _hook_details_for(app.store, alert_list)
    targets = _alert_targets_for(app.store, alert_list)
    rows = []
    for e in alert_list:
        row = {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "severity": e.severity,
            "action": e.action,
            "target": e.target,
            "actor": e.actor,
            "connector": _event_connector(e),
            "details": e.details,
        }
        # The same facts the table and --show print: a finding row's own
        # target and details are empty or only "finding.observed" (GAP-1615).
        facts = _finding_facts(e, hook_details, targets) or _quarantine_facts(e, targets) or {}
        if facts.get("target"):
            row["target"] = facts["target"]
        for key in ("decision", "route", "rule", "scanner", "sandbox", "path", "moved_to"):
            if facts.get(key):
                row[key] = facts[key]
        if "moved_to" in facts:
            row.setdefault("decision", "quarantined")
        rows.append(row)
    click.echo(json.dumps(rows, indent=2, sort_keys=True))


def _alerts_default(
    app: AppContext,
    limit: int,
    show_idx: int | None,
    tui: bool,
    connector: str | None = None,
) -> None:
    """View security alerts as a table (legacy ``defenseclaw alerts``)."""
    if not app.store:
        ux.warn("No audit store available. Run 'defenseclaw init' first.")
        return

    needle = (connector or "").strip()
    if needle:
        # Scan a wider window, then keep up to --limit matching the connector.
        pool = app.store.list_alerts(max(limit, _CONNECTOR_SCAN_POOL))
        alert_list = _filter_by_connector(pool, needle)[:limit]
    else:
        alert_list = app.store.list_alerts(limit)

    if not alert_list:
        if needle:
            ux.ok(
                f"No alerts from connector '{needle}' in the last "
                f"{max(limit, _CONNECTOR_SCAN_POOL)} events."
            )
        else:
            ux.ok("No alerts. All clear.")
        return

    if show_idx is not None:
        if show_idx < 1 or show_idx > len(alert_list):
            ux.err(f"alert #{show_idx} not found (1–{len(alert_list)})")
            raise SystemExit(1)
        e = alert_list[show_idx - 1]
        sev_fg = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "white",
        }.get(e.severity, "bright_black")
        def label(name: str) -> str:
            return ux._style(f"{name}:".ljust(10), fg="bright_black", bold=True)

        targets = _alert_targets_for(app.store, [e])
        facts = _finding_facts(e, _hook_details_for(app.store, [e]), targets)
        quarantined = _quarantine_facts(e, targets)
        click.echo(f"{ux.bold(f'Alert #{show_idx}')}")
        if e.id:
            click.echo(f"  {label('ID')} {e.id}")
        click.echo(f"  {label('Severity')} ", nl=False)
        click.echo(ux._style(e.severity, fg=sev_fg, bold=e.severity in ("CRITICAL", "HIGH")))
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else ""
        click.echo(f"  {label('Timestamp')} {ts}")
        click.echo(f"  {label('Action')} {e.action}")
        target = facts["target"] if facts else (quarantined["target"] if quarantined else e.target)
        if target:
            click.echo(f"  {label('Target')} {target}")
        if facts:
            for key, name in (("decision", "Decision"), ("route", "Route"), ("connector", "Connector"),
                              ("rule", "Rule"), ("scanner", "Scanner"), ("sandbox", "Sandbox"),
                              ("path", "Path")):
                if facts.get(key):
                    click.echo(f"  {label(name)} {facts[key]}")
        elif quarantined:
            click.echo(f"  {label('Decision')} quarantined")
            if quarantined["moved_to"]:
                click.echo(f"  {label('Moved to')} {quarantined['moved_to']}")
        elif e.details:
            if connector_name := _event_connector(e):
                click.echo(f"  {label('Connector')} {connector_name}")
            human = _humanize_details(e.details)
            if human:
                click.echo(f"  {label('Details')} {human}")
        kv_map = _kv(e.details or "")
        scanner_name = kv_map.get("scanner", "")
        if e.action == "scan" and scanner_name and e.target:
            findings = app.store.get_findings_for_target(e.target, scanner_name)
            if findings:
                click.echo(f"  {ux.bold('Findings:')}")
                for f in findings:
                    tag = f"[{f['severity']}]"
                    sev_tag_fg = {
                        "CRITICAL": "red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "cyan",
                        "INFO": "bright_black",
                    }.get(f["severity"], "white")
                    click.echo(f"    {ux._style(tag, fg=sev_tag_fg, bold=True)}", nl=False)
                    loc = f"  {f['location']}" if f["location"] else ""
                    click.echo(f" {f['title']}{loc}")
        hint = _alert_next_step(e)
        if hint:
            click.echo(f"  {ux._style('Next:', fg='bright_black', bold=True)}      {hint}")
        if e.id:
            click.echo(ux.dim(f"  Acknowledge: defenseclaw alerts acknowledge --id {e.id}"))
        return

    if tui:
        ux.warn(
            "`defenseclaw alerts --tui` has been retired. "
            "Launch `defenseclaw tui` and press 2 for the Alerts panel.",
        )

    _render_table(alert_list, app.store, connector=needle)


@alerts.command("acknowledge")
@click.option("--id", "alert_ids", multiple=True, help="Exact alert ID; repeat for multiple alerts.")
@click.option("--connector", default=None, help="Select active alerts from this exact connector.")
@click.option("--target", default=None, help="Select active alerts with this exact target.")
@click.option(
    "--severity",
    type=click.Choice(["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "INFO"]),
    default="all",
    show_default=True,
    help="Limit which severities are acknowledged.",
)
@click.option("--since", default=None, help="Select alerts at or after this RFC3339 timestamp.")
@click.option("--before", default=None, help="Select alerts before this RFC3339 timestamp.")
@click.option("--dry-run", is_flag=True, help="Preview the exact matched IDs without mutating them.")
@click.option(
    "-y",
    "--yes",
    is_flag=True,
    help="Confirm a mutation affecting more than one exact ID or a broad selector.",
)
@pass_ctx
def alerts_acknowledge(
    app: AppContext,
    alert_ids: tuple[str, ...],
    connector: str | None,
    target: str | None,
    severity: str,
    since: str | None,
    before: str | None,
    dry_run: bool,
    yes: bool,
) -> None:
    """Mark alerts as acknowledged (seen by an operator)."""
    n = _set_alert_disposition(
        app,
        "acknowledged",
        alert_ids=alert_ids,
        connector=connector,
        target=target,
        severity=severity,
        since=since,
        before=before,
        dry_run=dry_run,
        yes=yes,
    )
    if n is not None:
        ux.ok(f"Acknowledged {n} alert(s).")


@alerts.command("dismiss")
@click.option("--id", "alert_ids", multiple=True, help="Exact alert ID; repeat for multiple alerts.")
@click.option("--connector", default=None, help="Select active alerts from this exact connector.")
@click.option("--target", default=None, help="Select active alerts with this exact target.")
@click.option(
    "--severity",
    type=click.Choice(["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "INFO"]),
    default="all",
    show_default=True,
    help="Limit which severities are cleared from the active list.",
)
@click.option("--since", default=None, help="Select alerts at or after this RFC3339 timestamp.")
@click.option("--before", default=None, help="Select alerts before this RFC3339 timestamp.")
@click.option("--dry-run", is_flag=True, help="Preview the exact matched IDs without mutating them.")
@click.option(
    "-y",
    "--yes",
    is_flag=True,
    help="Confirm a mutation affecting more than one exact ID or a broad selector.",
)
@pass_ctx
def alerts_dismiss(
    app: AppContext,
    alert_ids: tuple[str, ...],
    connector: str | None,
    target: str | None,
    severity: str,
    since: str | None,
    before: str | None,
    dry_run: bool,
    yes: bool,
) -> None:
    """Dismiss alerts so they no longer show in the active alert list."""
    n = _set_alert_disposition(
        app,
        "dismissed",
        alert_ids=alert_ids,
        connector=connector,
        target=target,
        severity=severity,
        since=since,
        before=before,
        dry_run=dry_run,
        yes=yes,
    )
    if n is not None:
        ux.ok(f"Dismissed {n} alert(s) from the active list.")


_ALERT_DB_IDENTITY_DOMAIN = b"defenseclaw.alert-disposition.audit-db.v1\x00"


def _alert_audit_db_identity(path: str) -> str:
    if not path or not path.strip():
        raise click.ClickException("The resolved audit database path is unavailable.")
    normalized = os.path.realpath(os.path.abspath(path))
    normalized = os.path.normcase(os.path.normpath(normalized)).replace("\\", "/")
    digest = hashlib.sha256()
    digest.update(_ALERT_DB_IDENTITY_DOMAIN)
    digest.update(normalized.encode("utf-8"))
    return f"sha256:v1:{digest.hexdigest()}"


def _alert_selector(
    *,
    alert_ids: tuple[str, ...],
    connector: str | None,
    target: str | None,
    severity: str,
    since: str | None,
    before: str | None,
) -> dict[str, object]:
    normalized_ids = [alert_id.strip() for alert_id in alert_ids]
    if any(not alert_id for alert_id in normalized_ids):
        raise click.ClickException("Alert IDs must be non-empty.")
    ids = sorted(set(normalized_ids))
    broad_values = [connector, target, since, before]
    if ids:
        if any(value and value.strip() for value in broad_values) or severity != "all":
            raise click.ClickException("--id cannot be combined with connector, target, severity, or time selectors.")
        return {"ids": ids}
    selector: dict[str, object] = {}
    if connector and connector.strip():
        selector["connector"] = connector.strip()
    if target and target.strip():
        selector["target"] = target.strip()
    if severity != "all":
        selector["severity"] = severity
    if since and since.strip():
        selector["since"] = since.strip()
    if before and before.strip():
        selector["before"] = before.strip()
    return selector


def _response_count(response: dict[str, object], field: str) -> int:
    value = response.get(field, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise click.ClickException("Gateway returned a malformed alert disposition response.")
    return value


def _raise_alert_response_error(response: dict[str, object]) -> None:
    matched = _response_count(response, "matched")
    applied = _response_count(response, "applied")
    no_change = _response_count(response, "no_change")
    rejected = _response_count(response, "rejected")
    failed = _response_count(response, "failed")
    click.echo(
        f"Result: matched={matched} applied={applied} no_change={no_change} "
        f"rejected={rejected} failed={failed}",
        err=True,
    )
    failures = response.get("failures", [])
    if isinstance(failures, list):
        for failure in failures[:20]:
            if isinstance(failure, dict):
                alert_id = str(failure.get("id", ""))
                code = str(failure.get("code", "failed"))
                click.echo(f"  {alert_id}: {code}", err=True)
    message = str(response.get("error") or "Alert disposition was not fully applied.")
    raise click.ClickException(message)


def _alert_disposition_failure_message(exc: BaseException) -> str:
    if isinstance(exc, requests.Timeout):
        return (
            "Gateway timed out while confirming alert disposition. "
            "The audit database may still be applying the change; wait and retry."
        )
    if isinstance(exc, requests.ConnectionError):
        return "Gateway is unreachable; start it with 'defenseclaw-gateway start' and retry."
    if isinstance(exc, requests.HTTPError):
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status == 401:
            return "Gateway rejected authentication; run 'defenseclaw doctor' and retry."
        if status is not None:
            return f"Gateway rejected alert disposition (HTTP {status})."
        return "Gateway rejected alert disposition."
    return "Canonical alert disposition was not confirmed by the gateway."


def _set_alert_disposition(
    app: AppContext,
    disposition: str,
    *,
    alert_ids: tuple[str, ...] = (),
    connector: str | None = None,
    target: str | None = None,
    severity: str = "all",
    since: str | None = None,
    before: str | None = None,
    dry_run: bool = False,
    yes: bool = False,
) -> int | None:
    if app.cfg is None or getattr(app.cfg, "_source_config_version", None) != 8:
        raise click.ClickException("Configuration schema v8 is required — run 'defenseclaw migrate' first.")

    selector = _alert_selector(
        alert_ids=alert_ids,
        connector=connector,
        target=target,
        severity=severity,
        since=since,
        before=before,
    )
    audit_db_identity = _alert_audit_db_identity(app.cfg.audit_db)
    token = app.cfg.gateway.resolved_token()
    if not token:
        raise click.ClickException("Gateway authentication is unavailable; start or reconfigure the v8 gateway.")
    exact_ids = selector.get("ids")
    id_count = len(exact_ids) if isinstance(exact_ids, list) else 0
    client = OrchestratorClient(
        host=_gateway_api_host(app.cfg),
        port=int(app.cfg.gateway.api_port),
        timeout=alert_disposition_timeout_seconds(id_count),
        token=token,
    )
    operation_id = f"alert-review-{uuid.uuid4().hex}"
    try:
        preview = client.set_alert_disposition(
            operation_id=operation_id,
            audit_db_identity=audit_db_identity,
            disposition=disposition,
            selector=selector,
            preview=True,
        )
        if int(preview.get("_http_status", 0)) != 200:
            _raise_alert_response_error(preview)
        matched = _response_count(preview, "matched")
        selection_digest = preview.get("selection_digest")
        if not isinstance(selection_digest, str) or not selection_digest.startswith("sha256:v1:"):
            raise click.ClickException("Gateway returned a malformed alert selection preview.")
        # The selection digest and projection versions are the gateway's
        # concurrency check, not something to read; the IDs are listed only
        # for --dry-run, which promises them (GAP-1512).
        click.echo(f"Preview: {matched} alert(s) matched.")
        targets = preview.get("targets", [])
        if dry_run and isinstance(targets, list):
            for item in targets[:20]:
                if isinstance(item, dict):
                    click.echo(f"  {item.get('id', '')}")
            if len(targets) > 20:
                click.echo(f"  … and {len(targets) - 20} more")
        if dry_run:
            ux.ok("Dry run complete; no alerts were changed.")
            return None
        if matched == 0:
            return 0
        exact_ids = selector.get("ids", [])
        broad = not isinstance(exact_ids, list) or len(exact_ids) != 1
        if broad and not yes:
            click.confirm(f"Apply {disposition} to {matched} matched alert(s)?", abort=True)
        response = client.set_alert_disposition(
            operation_id=operation_id,
            audit_db_identity=audit_db_identity,
            disposition=disposition,
            selector=selector,
            preview=False,
            selection_digest=selection_digest,
            timeout=alert_disposition_timeout_seconds(matched),
        )
        if (
            int(response.get("_http_status", 0)) != 200
            or _response_count(response, "rejected") > 0
            or _response_count(response, "failed") > 0
        ):
            _raise_alert_response_error(response)
    except Exception as exc:
        if isinstance(exc, (click.ClickException, click.Abort)):
            raise
        raise click.ClickException(_alert_disposition_failure_message(exc)) from exc
    finally:
        client.close()
    return _response_count(response, "applied") + _response_count(response, "no_change")
