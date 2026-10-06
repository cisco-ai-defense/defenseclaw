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

"""defenseclaw policy — Create, list, show, activate, delete, validate, test, and edit security policies."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import NoReturn

import click
import yaml

from defenseclaw import policy_catalog, ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.paths import bundled_policies_dir, bundled_rego_dir

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RUNTIME_CHOICES = ["disable", "enable"]
FILE_CHOICES = ["quarantine", "none"]
INSTALL_CHOICES = ["block", "allow", "none"]

BUILTIN_POLICIES = {"default", "strict", "permissive"}


def _policies_dir(app: AppContext) -> str:
    return app.cfg.policy_dir


def _bundled_policies_dir() -> str:
    """Return path to the bundled policies/ directory (wheel _data/ or repo root)."""
    return str(bundled_policies_dir())


def _rego_dir() -> str:
    return str(bundled_rego_dir())


def _default_rego_dir(app: AppContext) -> str:
    """The Rego directory the gateway loads: <policy_dir>/rego when it exists.

    Falls back to the bundled copy (a fresh install before init). The bundled
    directory lives inside the package and is replaced on upgrade, so it is
    the wrong place to point users at for their own tests (GAP-1459).
    """
    policy_dir = getattr(getattr(app, "cfg", None), "policy_dir", "") or ""
    user_rego = os.path.join(policy_dir, "rego") if policy_dir else ""
    if user_rego and os.path.isdir(user_rego):
        return user_rego
    return _rego_dir()


def _ensure_policies_dir(app: AppContext) -> str:
    d = _policies_dir(app)
    os.makedirs(d, exist_ok=True)
    return d


def _load_policy(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _save_policy(path: str, data: dict) -> None:
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def _sanitize_policy_name(name: str) -> str:
    """Strip path components from a policy name to prevent traversal."""
    safe = os.path.basename(name)
    if not safe or safe != name or ".." in name:
        raise click.ClickException(
            f"invalid policy name {name!r} — must be a simple name without path separators"
        )
    return safe


def _find_policy_file(app: AppContext, name: str) -> str | None:
    """Find ``<name>.yaml`` (user dir, then bundled), whatever its content."""
    name = _sanitize_policy_name(name)
    user_dir = _policies_dir(app)
    candidate = os.path.join(user_dir, f"{name}.yaml")
    if os.path.isfile(candidate):
        return candidate

    bundled = _bundled_policies_dir()
    candidate = os.path.join(bundled, f"{name}.yaml")
    if os.path.isfile(candidate):
        return candidate

    return None


def _not_a_policy_error(name: str, data: object) -> None:
    """Explain why ``<name>.yaml`` can't be used as a named policy, then exit 1."""
    if isinstance(data, dict) and {"rules", "default_action", "allowlist"} & set(data):
        click.echo(
            f"error: '{name}' is the host egress-firewall template, not a security policy. "
            "List security policies with `defenseclaw policy list`.",
            err=True,
        )
    else:
        click.echo(
            f"error: '{name}.yaml' is not a DefenseClaw security policy "
            "(no admission, skill_actions or guardrail section). "
            "List security policies with `defenseclaw policy list`.",
            err=True,
        )
    raise SystemExit(1)


def _policy_not_found(app: AppContext, name: str) -> NoReturn:
    """Report an unknown policy name with the valid names, then exit 1 (GAP-1818)."""
    try:
        names = [p.name for p in policy_catalog.list_named_policies(_policies_dir(app))]
    except Exception:  # noqa: BLE001 - the hint is best effort
        names = []
    msg = f"Error: policy '{name}' not found."
    if names:
        msg += f" Available policies: {', '.join(names)}."
    msg += " Run `defenseclaw policy list` for details."
    click.echo(msg, err=True)
    raise SystemExit(1)


def _find_policy(app: AppContext, name: str) -> str | None:
    """Find a named security policy file by name (without .yaml extension).

    Returns ``None`` when no such file exists. A file that exists but is not
    a named policy (e.g. the bundled ``firewall-deny-default`` host-firewall
    template) exits 1 with a plain explanation instead of being treated as
    one.
    """
    path = _find_policy_file(app, name)
    if path is None:
        return None
    data = policy_catalog.load_policy_yaml(path)
    if data is None or not policy_catalog.is_named_policy(data):
        _not_a_policy_error(name, data)
    return path


@click.group()
def policy() -> None:
    """Manage DefenseClaw security policies — create, list, show, activate, validate, test, edit."""


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("name")
@click.option("--description", "-d", default="", help="Policy description")
@click.option("--from-preset", type=click.Choice(["default", "strict", "permissive"]),
              help="Start from a built-in preset and customize")
@click.option("--scan-on-install/--no-scan-on-install", "scan_on_install", default=None,
              help="Scan on install (default: true; with --from-preset, keep the preset's value)")
@click.option("--allow-list-bypass/--no-allow-list-bypass", "allow_list_bypass", default=None,
              help="Allow-listed items skip scan (default: true; with --from-preset, keep the preset's value)")
@click.option("--critical-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for CRITICAL findings")
@click.option("--high-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for HIGH findings")
@click.option("--medium-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for MEDIUM findings")
@click.option("--low-action", type=click.Choice(["block", "warn", "allow"]), default=None,
              help="Action for LOW findings")
@pass_ctx
def create(
    app: AppContext,
    name: str,
    description: str,
    from_preset: str | None,
    scan_on_install: bool | None,
    allow_list_bypass: bool | None,
    critical_action: str | None,
    high_action: str | None,
    medium_action: str | None,
    low_action: str | None,
) -> None:
    """Create a new security policy.

    Examples:\n
      defenseclaw policy create my-strict --from-preset strict\n
      defenseclaw policy create prod --critical-action block --high-action block --medium-action warn\n
      defenseclaw policy create dev --critical-action block --high-action warn --medium-action allow
    """
    name = _sanitize_policy_name(name)

    if name in BUILTIN_POLICIES:
        click.echo(f"error: cannot overwrite built-in policy '{name}'", err=True)
        raise SystemExit(1)

    policies_dir = _ensure_policies_dir(app)
    dest = os.path.join(policies_dir, f"{name}.yaml")

    if os.path.islink(dest):
        ux.echo(f"error: policy '{name}' is a symbolic link — refusing to write", err=True)
        raise SystemExit(1)

    real_dest = os.path.realpath(dest)
    real_dir = os.path.realpath(policies_dir)
    if not real_dest.startswith(real_dir + os.sep):
        click.echo("error: resolved path escapes policy directory", err=True)
        raise SystemExit(1)

    if os.path.exists(dest):
        click.echo(f"error: policy '{name}' already exists at {dest}", err=True)
        click.echo("  Delete it first or choose a different name.", err=True)
        raise SystemExit(1)

    if from_preset:
        preset_path = _find_policy(app, from_preset)
        if preset_path:
            data = _load_policy(preset_path)
        else:
            data = _default_policy_data()
    else:
        data = _default_policy_data()

    data["name"] = name
    if description:
        data["description"] = description
    elif "description" not in data:
        data["description"] = f"Custom policy: {name}"

    # Tri-state admission flags (OTHER-3): the boolean flags default to
    # None when the operator doesn't pass them. Only override when set,
    # so `create --from-preset P` keeps P's admission values instead of
    # silently resetting them to the CLI defaults. When a flag is omitted
    # and the loaded data (preset or _default_policy_data) doesn't carry
    # the key, fall back to the default-policy admission block — this
    # preserves the historical bare-`create` behaviour (scan_on_install
    # true / allow_list_bypass_scan true).
    admission = data.setdefault("admission", {})
    default_admission = _default_policy_data()["admission"]
    if scan_on_install is not None:
        admission["scan_on_install"] = scan_on_install
    elif "scan_on_install" not in admission:
        admission["scan_on_install"] = default_admission["scan_on_install"]
    if allow_list_bypass is not None:
        admission["allow_list_bypass_scan"] = allow_list_bypass
    elif "allow_list_bypass_scan" not in admission:
        admission["allow_list_bypass_scan"] = default_admission["allow_list_bypass_scan"]

    actions = data.setdefault("skill_actions", {})
    severity_overrides = {
        "critical": critical_action,
        "high": high_action,
        "medium": medium_action,
        "low": low_action,
    }

    for sev, action in severity_overrides.items():
        if action is not None:
            actions[sev] = _action_for_level(action)

    for sev in SEVERITIES:
        if sev not in actions:
            actions[sev] = _action_for_level("allow")

    _save_policy(dest, data)

    ux.ok(f"Policy '{name}' created at {dest}")
    click.echo(f"  {ux.dim('Activate with:')} defenseclaw policy activate {name}")

    _log_policy_action(app, "policy-create", name, f"path={dest}", done="Policy created")


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@policy.command("list")
@click.option("--json", "json_out", is_flag=True, help="Print the policies as JSON.")
@pass_ctx
def list_policies(app: AppContext, json_out: bool) -> None:
    """List all available policies (built-in and custom)."""
    policies = policy_catalog.list_named_policies(_policies_dir(app))
    active = policy_catalog.active_policy_name(_policies_dir(app))

    if json_out:
        click.echo(
            json.dumps(
                {"version": 1, "active": active, "policies": [p.to_json() for p in policies]},
                indent=2,
            )
        )
        return

    if not policies:
        ux.warn("No policies found.")
        return

    click.echo(f"{ux.bold('Available policies:')}")
    click.echo()
    for summary in policies:
        prefix = "  * " if summary.active else "    "
        label = ux.bold(summary.name)
        tag = ""
        if summary.builtin:
            tag += ux.dim(" [built-in, edited]" if summary.edited else " [built-in]")
        if summary.active:
            tag += ux._style(" [active]", fg="green")

        click.echo(f"{prefix}{label}{tag}")
        if summary.description:
            click.echo(f"      {ux.dim(summary.description)}")

    click.echo()
    click.echo(f"  {ux.dim('Activate a policy:')} defenseclaw policy activate <name>")
    click.echo(f"  {ux.dim('Show details:')}      defenseclaw policy show <name>")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("name")
@click.option("--json", "json_out", is_flag=True, help="Print the policy summary as JSON.")
@pass_ctx
def show(app: AppContext, name: str, json_out: bool) -> None:
    """Show details of a policy."""
    path = _find_policy(app, name)
    if not path:
        _policy_not_found(app, name)

    if json_out:
        summary = policy_catalog.get_policy(_sanitize_policy_name(name), _policies_dir(app))
        if summary is None:
            click.echo(f"error: policy '{name}' could not be read", err=True)
            raise SystemExit(1)
        click.echo(json.dumps({"version": 1, "policy": summary.to_json()}, indent=2))
        return

    data = _load_policy(path)
    pname = data.get("name", name)
    desc = data.get("description", "")
    admission = data.get("admission", {})

    click.echo(ux.bold(f"Policy: {pname}"))
    if desc:
        ux.subhead(desc, indent="  ")
    click.echo()

    click.echo(ux.bold("Admission:"))
    click.echo(
        f"  {ux._style('scan_on_install:', fg='bright_black', bold=True)}"
        f"        {admission.get('scan_on_install', True)}"
    )
    click.echo(
        f"  {ux._style('allow_list_bypass_scan:', fg='bright_black', bold=True)} "
        f"{admission.get('allow_list_bypass_scan', True)}"
    )
    click.echo()

    click.echo(ux.bold("Severity Actions:"))
    actions = data.get("skill_actions", {})
    for sev in SEVERITIES:
        action = actions.get(sev, {})
        file_a = action.get("file", "none")
        runtime_a = action.get("runtime", "enable")
        install_a = action.get("install", "none")

        if install_a == "block":
            color = "red"
        elif file_a == "quarantine":
            color = "red"
        elif runtime_a == "disable":
            color = "yellow"
        else:
            color = "green"

        click.echo(
            f"  {ux.bold(sev.upper().ljust(10))}  "
            + ux._style(
                f"install={install_a:5s}  file={file_a:10s}  runtime={runtime_a}",
                fg=color,
            )
        )

    overrides = data.get("scanner_overrides", {})
    if overrides:
        click.echo()
        click.echo("Scanner Overrides:")
        for scanner_type, sevs in overrides.items():
            if not sevs:
                continue
            click.echo(f"  {scanner_type}:")
            for sev_name, sev_action in sevs.items():
                file_a = sev_action.get("file", "none")
                runtime_a = sev_action.get("runtime", "enable")
                install_a = sev_action.get("install", "none")
                click.echo(
                    f"    {sev_name.upper():10s}  install={install_a:5s}  file={file_a:10s}  runtime={runtime_a}"
                )

    guardrail = data.get("guardrail", {})
    if guardrail:
        click.echo()
        click.echo("Guardrail:")
        click.echo(f"  block_threshold:    {_severity_rank_label(guardrail.get('block_threshold', 4))}")
        click.echo(f"  alert_threshold:    {_severity_rank_label(guardrail.get('alert_threshold', 2))}")
        click.echo(
            "  (these thresholds apply to LLM traffic through the guardrail proxy; "
            "tool-call blocking uses 'defenseclaw guardrail block-at')"
        )
        hilt = guardrail.get("hilt", {}) or {}
        click.echo(
            f"  hilt:               enabled={bool(hilt.get('enabled', False))} "
            f"min={hilt.get('min_severity', 'HIGH')}"
        )
        click.echo(f"  cisco_trust_level:  {guardrail.get('cisco_trust_level', 'full')}")
        patterns = guardrail.get("patterns", {})
        if patterns:
            click.echo("  patterns:")
            for cat, pats in patterns.items():
                click.echo(f"    {cat}: {len(pats)} pattern(s)")
        mappings = guardrail.get("severity_mappings", {})
        if mappings:
            click.echo("  severity_mappings:")
            for cat, sev in mappings.items():
                click.echo(f"    {cat}: {sev}")

    fw = data.get("firewall", {})
    if fw:
        click.echo()
        click.echo("Firewall:")
        click.echo(f"  default_action:        {fw.get('default_action', 'deny')}")
        click.echo(f"  blocked_destinations:  {len(fw.get('blocked_destinations', []))} entries")
        click.echo(f"  allowed_domains:       {len(fw.get('allowed_domains', []))} entries")
        click.echo(f"  allowed_ports:         {fw.get('allowed_ports', [])}")

    enforcement = data.get("enforcement", {})
    if enforcement:
        click.echo()
        click.echo("Enforcement:")
        click.echo(f"  max_enforcement_delay_seconds: {enforcement.get('max_enforcement_delay_seconds', 2)}")

    audit_cfg = data.get("audit", {})
    if audit_cfg:
        click.echo()
        click.echo("Audit:")
        click.echo(f"  retention_days: {audit_cfg.get('retention_days', 90)}")


# ---------------------------------------------------------------------------
# activate
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# load — load a policy from a YAML file (supports FleetPolicy kind)
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@pass_ctx
def load(app: AppContext, path: str) -> None:
    """Load a policy from a YAML file.

    For standard policies this is equivalent to ``policy activate`` on
    the named policy.  When the YAML has ``kind: FleetPolicy`` the file
    is pushed to the fleet API instead
    (POST /api/v1/fleet/policy/push).

    Examples:\n
      defenseclaw policy load my-policy.yaml\n
      defenseclaw policy load fleet-policy.yaml
    """
    data = _load_policy(path)

    kind = str(data.get("kind", "")).strip()
    if kind == "FleetPolicy":
        _load_fleet_policy(app, path, data)
        return

    # Standard policy: treat as activate. The file must contain a
    # ``name`` field so the catalog can register it.
    name = data.get("name") or data.get("metadata", {}).get("name", "")
    if not name:
        click.echo("error: policy YAML has no 'name' field; cannot activate.", err=True)
        raise SystemExit(1)

    # Copy the file into the user policy directory so activate can find it.
    dest = os.path.join(_ensure_policies_dir(app), f"{_sanitize_policy_name(name)}.yaml")
    _save_policy(dest, data)
    ux.ok(f"Policy '{name}' saved to {dest}")

    _activate_policy(app, name)
    ux.ok(f"Policy '{name}' activated.")
    _reload_and_report(app, name)


def _load_fleet_policy(app: AppContext, path: str, data: dict) -> None:
    """Push a FleetPolicy YAML to the fleet API."""
    import requests as req_lib

    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    cfg = app.cfg
    gateway = getattr(cfg, "gateway", None)
    port = int(getattr(gateway, "api_port", 0) or 0) if gateway is not None else 0
    if port <= 0:
        click.echo(
            "error: Fleet API not available. Use `defenseclaw setup edge-connector` first.",
            err=True,
        )
        raise SystemExit(1)

    resolver = getattr(gateway, "resolved_token", None)
    try:
        token = resolver() if callable(resolver) else str(getattr(gateway, "token", "") or "")
    except Exception:  # noqa: BLE001
        token = ""

    client = OrchestratorClient(
        host=gateway_api_client_host(cfg),
        port=port,
        token=(token or "").strip(),
        timeout=10,
    )

    metadata = data.get("metadata", {}) or {}
    tenant_id = int(metadata.get("tenant_id", 1))
    fleet_id = int(metadata.get("fleet_id", 1))

    payload = {
        "tenant_id": tenant_id,
        "fleet_id": fleet_id,
        "policy": data,
    }

    try:
        resp = client._session.post(
            f"{client.base_url}/api/v1/fleet/policy/push",
            json=payload,
            timeout=client.timeout,
            allow_redirects=False,
        )
        if resp.status_code in (404, 503):
            click.echo(
                "error: Fleet API not available. Use `defenseclaw setup edge-connector` first.",
                err=True,
            )
            raise SystemExit(1)
        resp.raise_for_status()
        result = resp.json() if resp.content else {}
    except req_lib.ConnectionError:
        click.echo(
            "error: Fleet API not available. Use `defenseclaw setup edge-connector` first.",
            err=True,
        )
        raise SystemExit(1)
    except req_lib.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        click.echo(f"error: Fleet API returned HTTP {status}.", err=True)
        raise SystemExit(1)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"error: failed to push fleet policy: {exc}", err=True)
        raise SystemExit(1)

    name = metadata.get("name", os.path.basename(path))
    status = result.get("status", "distributed")
    ux.ok(f"Fleet policy '{name}' {status} (tenant={tenant_id}, fleet={fleet_id}).")


@policy.command()
@click.argument("name")
@click.option(
    "--reload/--no-reload",
    "reload_gateway",
    default=True,
    show_default=True,
    help="Ask the running gateway to reload its policy after saving.",
)
@pass_ctx
def activate(app: AppContext, name: str, reload_gateway: bool) -> None:
    """Activate a policy — makes it the policy DefenseClaw enforces.

    By default the running gateway is then asked to reload its policy
    (POST /policy/reload) so the change takes effect immediately. If the
    gateway isn't running, it loads the policy when it next starts.
    """
    before = _restart_only_config(app.cfg)
    path = _activate_policy(app, name)
    ux.ok(f"Policy '{name}' activated.")
    # The policy's guardrail thresholds are not the tool-call block level
    # (GAP-1228).
    click.echo(
        "  Its guardrail thresholds govern LLM traffic through the proxy; tool-call "
        "blocking is unchanged (see 'defenseclaw guardrail status' and 'guardrail block-at')."
    )
    # A stopped gateway gets one note after the success lines, covering both
    # the skipped audit event and the reload on start (GAP-1718).
    audit_skipped = _log_policy_action(
        app, "policy-activate", name, f"source={path}", done="Policy saved", defer_stopped=reload_gateway
    )
    if not reload_gateway:
        return
    _reload_and_report(
        app, name, needs_restart=_restart_only_config(app.cfg) != before, audit_skipped=audit_skipped
    )


def _log_policy_action(
    app: AppContext, action: str, name: str, details: str, *, done: str, defer_stopped: bool = False
) -> bool:
    """Record a finished policy change; a stopped gateway only skips the audit event.

    The policy file is already written, so a stopped or refusing gateway prints
    one plain warning instead of a traceback and rc=1 (GAP-1651), like
    ``setup webhook`` and ``guardrail fail-mode``. With ``defer_stopped`` the
    stopped-gateway warning is left to the caller, which folds it into its
    own note; returns True when the audit event was skipped that way.
    """
    if not app.logger:
        return False
    from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError

    try:
        app.logger.log_action(action, name, details)
    except CanonicalObservabilityUnavailableError:
        if defer_stopped:
            return True
        ux.echo(
            f"  ⚠ {done}. The gateway isn't running, so the audit event was not recorded "
            "(start it with: defenseclaw-gateway start).",
            err=True,
        )
    except CanonicalObservabilityError as exc:
        ux.echo(f"  ⚠ {done}, but the gateway did not confirm the audit event ({exc}).", err=True)
    return False


def _restart_only_config(cfg) -> tuple[str, ...]:  # noqa: ANN001 - Config, imported lazily
    """The config.yaml sections a policy writes that the gateway cannot hot-reload.

    The gateway's config watcher refuses a change to ``skill_actions``,
    ``watch`` or (outside managed installs) ``cisco_ai_defense`` with
    "config reload requires gateway restart", so a policy change that
    touches them needs a restart to take effect.
    """
    return tuple(repr(getattr(cfg, section, None)) for section in ("skill_actions", "watch", "cisco_ai_defense"))


def _gateway_pid_alive(app: AppContext) -> bool:
    from defenseclaw.process_liveness import pid_file_alive

    try:
        return pid_file_alive(os.path.join(app.cfg.data_dir, "gateway.pid"))
    except Exception:  # noqa: BLE001 - an unreadable PID file means "not running".
        return False


_SEVERITY_RANK_NAMES = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


class _SeverityRank(click.ParamType):
    """A guardrail threshold: LOW, MEDIUM, HIGH, CRITICAL (any case) or 1-4 (GAP-1724)."""

    name = "LEVEL"

    def get_metavar(self, param, ctx=None) -> str:  # noqa: ARG002 - click API
        return "[LOW|MEDIUM|HIGH|CRITICAL|1-4]"

    def convert(self, value, param, ctx):
        if isinstance(value, int) and value in _SEVERITY_RANK_NAMES:
            return value
        text = str(value).strip()
        by_name = {label: rank for rank, label in _SEVERITY_RANK_NAMES.items()}
        if text.upper() in by_name:
            return by_name[text.upper()]
        if text.isdigit() and int(text) in _SEVERITY_RANK_NAMES:
            return int(text)
        self.fail(f"{value!r} is not a severity. Use LOW, MEDIUM, HIGH, CRITICAL or 1-4.", param, ctx)


_SEVERITY_RANK = _SeverityRank()


def _severity_rank_label(value: object) -> str:
    """'MEDIUM (2)' for a policy severity rank; the raw value when it is not a known rank (GAP-1228)."""

    try:
        rank = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value)
    name = _SEVERITY_RANK_NAMES.get(rank)
    return f"{name} ({rank})" if name else str(value)


def _reload_and_report(
    app: AppContext, name: str, *, needs_restart: bool = False, audit_skipped: bool = False
) -> None:
    """Ask the running gateway to reload its policy and say how that went.

    Shared by ``policy activate`` and ``policy edit``: reloaded → ok;
    gateway not running → the change is saved for its next start (exit 0);
    rejected → exit 1 pointing at ``defenseclaw policy validate``. When
    ``needs_restart`` (the change also touched config sections the gateway
    only reads at start) a running gateway is restarted instead.
    ``audit_skipped``: the caller's audit event found no gateway; say so here.
    """
    skipped_note = (
        "  ⚠ The gateway isn't running, so the audit event was not recorded "
        "(start it with: defenseclaw-gateway start)."
    )
    if needs_restart and _gateway_pid_alive(app):
        if audit_skipped:
            ux.echo(skipped_note, err=True)
        from defenseclaw.commands import cmd_setup

        if cmd_setup._restart_defense_gateway(app.cfg.data_dir, start_if_stopped=False):
            ux.ok("Restarted the gateway; it is enforcing the policy now.")
            return
        click.echo(
            f"error: policy '{name}' was saved, but the gateway restart failed. "
            "Run `defenseclaw-gateway restart`, then `defenseclaw doctor`.",
            err=True,
        )
        raise SystemExit(1)
    outcome, detail = _reload_gateway_policy(app)
    if outcome == "reloaded":
        ux.ok("Gateway reloaded the policy; it is enforcing it now.")
        return
    if outcome == "unreachable":
        ux.echo(
            "  ⚠ The gateway isn't running; it loads this policy when it starts "
            "(defenseclaw-gateway start)" + ("; the audit event was not recorded." if audit_skipped else ".")
        )
        return
    if audit_skipped:
        ux.echo(skipped_note, err=True)
    click.echo(
        f"error: policy '{name}' was saved, but the running gateway rejected the reload"
        + (f" ({detail})" if detail else "")
        + ". Run `defenseclaw policy validate` to find the problem, fix it, then activate again.",
        err=True,
    )
    raise SystemExit(1)


def _reload_gateway_policy(app: AppContext) -> tuple[str, str]:
    """POST /policy/reload to the running gateway.

    Returns ``(outcome, detail)`` where outcome is ``"reloaded"``,
    ``"unreachable"`` (nothing listening / timed out / no API port) or
    ``"rejected"`` (HTTP error or malformed response; *detail* says why).
    """
    import requests

    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    gateway = getattr(app.cfg, "gateway", None)
    port = int(getattr(gateway, "api_port", 0) or 0) if gateway is not None else 0
    if port <= 0:
        return "unreachable", ""
    resolver = getattr(gateway, "resolved_token", None)
    try:
        token = resolver() if callable(resolver) else str(getattr(gateway, "token", "") or "")
    except Exception:  # noqa: BLE001 — a token lookup failure is an auth problem, not a crash.
        token = ""
    client = OrchestratorClient(
        host=gateway_api_client_host(app.cfg),
        port=port,
        token=(token or "").strip(),
        timeout=5,
    )
    try:
        client.reload_policy()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status in (401, 403):
            return "rejected", "the gateway refused the request; check the gateway token"
        reason = ""
        if exc.response is not None:
            try:
                body = exc.response.json()
                if isinstance(body, dict):
                    reason = str(body.get("error") or "")
            except ValueError:
                reason = ""
        return "rejected", reason[:300] or f"HTTP {status}"
    except (requests.ConnectionError, requests.Timeout, OSError):
        return "unreachable", ""
    except ValueError:
        return "rejected", "the gateway sent an unexpected reply"
    return "reloaded", ""


def _skill_actions_from_policy(data: dict):  # noqa: ANN202 - SkillActionsConfig, imported lazily
    """The ``skill_actions`` block of a policy as the config.yaml section."""
    from defenseclaw.config import SeverityAction, SkillActionsConfig

    actions_raw = data.get("skill_actions", {})

    def _parse_action(raw: dict) -> SeverityAction:
        return SeverityAction(
            file=raw.get("file", "none"),
            runtime=raw.get("runtime", "enable"),
            install=raw.get("install", "none"),
        )

    return SkillActionsConfig(
        critical=_parse_action(actions_raw.get("critical", {})),
        high=_parse_action(actions_raw.get("high", {})),
        medium=_parse_action(actions_raw.get("medium", {})),
        low=_parse_action(actions_raw.get("low", {})),
        info=_parse_action(actions_raw.get("info", {})),
    )


def _activate_policy(app: AppContext, name: str) -> str:
    """Apply the named policy to config.yaml and sync OPA data.json.

    Returns the resolved source path. Raises ``SystemExit(1)`` when the
    policy can't be found. Shared by the ``activate`` command and the N1
    ``delete --force`` fallback, which re-activates ``default`` after
    removing the policy that was live so the gateway never keeps
    enforcing a deleted policy.
    """
    path = _find_policy(app, name)
    if not path:
        _policy_not_found(app, name)

    data = _load_policy(path)

    watch_raw = data.get("watch", {})
    app.cfg.skill_actions = _skill_actions_from_policy(data)
    if "rescan_enabled" in watch_raw:
        app.cfg.watch.rescan_enabled = bool(watch_raw["rescan_enabled"])
    if "rescan_interval_min" in watch_raw:
        app.cfg.watch.rescan_interval_min = int(watch_raw["rescan_interval_min"])

    # Apply Cisco AI Defense settings into config.yaml. The gateway reads
    # the AID lane from Config.CiscoAIDefense, not from data.json, so we
    # have to mutate ``app.cfg.cisco_ai_defense`` here. We deliberately
    # only touch the fields the policy YAML carries — if a field is
    # absent we keep whatever the operator set via ``defenseclaw setup``.
    aid_raw = data.get("cisco_ai_defense", {})
    if isinstance(aid_raw, dict) and aid_raw:
        if "endpoint" in aid_raw and isinstance(aid_raw["endpoint"], str):
            app.cfg.cisco_ai_defense.endpoint = aid_raw["endpoint"]
        if "api_key_env" in aid_raw and isinstance(aid_raw["api_key_env"], str):
            # We never accept a literal `api_key` from a policy YAML —
            # that would mean someone pasted a secret into a file the
            # docs site emits; force the operator through `api_key_env`.
            app.cfg.cisco_ai_defense.api_key_env = aid_raw["api_key_env"]

    # Webhooks are gateway config (notifier destinations), not policy data,
    # but the playground carries them through the policy YAML so the
    # wizard's output is one self-describing artifact. Activation only ADDS
    # the policy's webhooks whose name (or URL) isn't configured yet; it
    # never removes or rewrites the operator's own entries. The built-in
    # policies carry ``webhooks: []``, and replacing the list wholesale
    # silently deleted every webhook on each activate (GAP-1273).
    webhook_notes: list[str] = []
    if "webhooks" in data:
        wh_raw = data.get("webhooks")
        if isinstance(wh_raw, list) and wh_raw:
            from defenseclaw.config import WebhookConfig

            new_webhooks: list[WebhookConfig] = []
            for entry in wh_raw:
                if not isinstance(entry, dict):
                    continue
                # Construct via known fields only — anything else gets
                # dropped rather than silently passed through, which is
                # the right call for a structure that maps to a Go
                # struct on the gateway side.
                kwargs: dict = {}
                for fld in ("name", "url", "secret_env", "enabled"):
                    if fld in entry:
                        kwargs[fld] = entry[fld]
                try:
                    new_webhooks.append(WebhookConfig(**kwargs))
                except TypeError:
                    # If WebhookConfig grew new required fields and the
                    # YAML doesn't carry them, fall back to per-attribute
                    # set so the policy still activates.
                    wh = WebhookConfig()
                    for k, v in kwargs.items():
                        setattr(wh, k, v)
                    new_webhooks.append(wh)
            merged = list(app.cfg.webhooks or [])
            known = {str(getattr(w, "name", "") or "") for w in merged} - {""}
            known |= {str(getattr(w, "url", "") or "") for w in merged} - {""}
            existing = {(str(getattr(w, "name", "") or ""), str(getattr(w, "url", "") or "")) for w in merged}
            for wh in new_webhooks:
                label = str(getattr(wh, "name", "") or "") or str(getattr(wh, "url", "") or "")
                keys = {str(getattr(wh, "name", "") or ""), str(getattr(wh, "url", "") or "")} - {""}
                if keys and not keys & known:
                    merged.append(wh)
                    known |= keys
                    webhook_notes.append(f"Added webhook {label} from the policy")
                elif keys and (str(getattr(wh, "name", "") or ""), str(getattr(wh, "url", "") or "")) not in existing:
                    # GAP-1585: say why a policy webhook was not added.
                    webhook_notes.append(
                        f"Skipped webhook {label}: a webhook with that name or URL is already configured"
                    )
            app.cfg.webhooks = merged
    app.cfg.save()
    for note in webhook_notes:
        click.echo(f"  {note}")

    _sync_opa_data(app, data)
    return path


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("name")
@click.option("--force", is_flag=True,
              help="Delete even if active; re-activates 'default' afterward")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def delete(app: AppContext, name: str, force: bool, assume_yes: bool) -> None:
    """Delete a custom policy, or your edited copy of a built-in.

    The policy file is removed for good (no backup is kept). On a terminal
    you are asked to confirm first; pass --yes to skip the prompt.

    For a built-in policy (default, strict, permissive) only the user copy
    that ``policy edit`` saved is removed, which restores the built-in; an
    active built-in is re-activated from the restored version.

    The active policy is not deleted unless --force is given; activate
    another policy first, or pass --force to delete it and switch back to
    the built-in 'default' policy.
    """
    # Without the guard the gateway would keep enforcing a policy whose YAML
    # is gone and 'policy list' would still mark it [active].
    name = _sanitize_policy_name(name)

    user_dir = _policies_dir(app)
    path = os.path.join(user_dir, f"{name}.yaml")

    builtin = name in BUILTIN_POLICIES
    if builtin and (not os.path.lexists(path) or _is_bundled_path(path)):
        click.echo(
            f"error: cannot delete built-in policy '{name}' (it has no edited copy to remove)",
            err=True,
        )
        raise SystemExit(1)

    if os.path.islink(path):
        ux.echo(f"error: policy '{name}' is a symbolic link — refusing to delete", err=True)
        raise SystemExit(1)

    real_path = os.path.realpath(path)
    real_dir = os.path.realpath(user_dir)
    if not real_path.startswith(real_dir + os.sep):
        click.echo("error: resolved path escapes policy directory", err=True)
        raise SystemExit(1)

    if not os.path.isfile(real_path):
        click.echo(f"error: policy '{name}' not found in {user_dir}", err=True)
        raise SystemExit(1)

    is_active = name == _get_active_policy_name(app)
    if builtin:
        # GAP-1458: drop the user copy that shadowed the built-in.
        _confirm_policy_delete(f"your edited copy of built-in policy '{name}'", path, assume_yes)
        os.remove(real_path)
        ux.ok(f"Removed your edited copy of built-in policy '{name}'; the built-in version is back.")
        _log_policy_action(app, "policy-delete", name, "reverted edited built-in", done="Copy removed")
        if is_active:
            _reactivate_after_delete(app, name)
        return

    if is_active and not force:
        ux.echo(
            f"error: policy '{name}' is active — refusing to delete. "
            "Activate another policy first, or pass --force to delete it "
            "and re-activate 'default'.",
            err=True,
        )
        raise SystemExit(1)

    _confirm_policy_delete(f"policy '{name}'", path, assume_yes)
    os.remove(real_path)
    ux.ok(f"Policy '{name}' deleted.")
    _log_policy_action(app, "policy-delete", name, "", done="Policy deleted")

    # N1: the live data.json still names the just-deleted policy. Re-point
    # it at the default built-in so the gateway never keeps enforcing a
    # policy whose source is gone. Only reachable with --force (the guard
    # above blocks the implicit case).
    if is_active:
        ux.warn(f"'{name}' was the active policy — re-activating 'default'.")
        _reactivate_after_delete(app, "default")


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _confirm_policy_delete(label: str, path: str, assume_yes: bool) -> None:
    """Ask before removing a user-authored policy file (GAP-1887)."""
    if assume_yes or not _stdin_is_tty():
        return
    shown = path.replace(os.path.expanduser("~"), "~", 1)
    if not click.confirm(f"Delete {label} ({shown})? It cannot be undone", default=False):
        click.echo("Cancelled; nothing was deleted.")
        raise SystemExit(1)


def _reactivate_after_delete(app: AppContext, name: str) -> None:
    """Re-activate *name* and apply it to the running gateway like ``policy activate`` (GAP-1723)."""
    before = _restart_only_config(app.cfg)
    _activate_policy(app, name)
    _reload_and_report(app, name, needs_restart=_restart_only_config(app.cfg) != before)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@policy.command()
@click.option("--rego-dir", default=None,
              help="Path to rego directory (default: <policy_dir>/rego, e.g. "
                   "~/.defenseclaw/policies/rego; the bundled copy before init)")
@pass_ctx
def validate(app: AppContext, rego_dir: str | None) -> None:
    """Check the policy rule files (Rego modules and data.json) for errors.

    Checks:\n
      1. data.json is valid JSON with required top-level keys\n
      2. All severity levels in actions and scanner_overrides have valid fields\n
      3. Rego modules compile without errors ('opa' if installed, else defenseclaw-gateway)
    """
    rd = rego_dir or _default_rego_dir(app)
    errors: list[str] = []

    # 1. Validate data.json
    data_json_path = os.path.join(rd, "data.json")
    if not os.path.isfile(data_json_path):
        ux.err(f"FAIL: data.json not found at {data_json_path}")
        raise SystemExit(1)

    try:
        with open(data_json_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        ux.err(f"FAIL: data.json is not valid JSON: {exc}")
        raise SystemExit(1)

    required_keys = ["config", "actions", "severity_ranking"]
    for key in required_keys:
        if key not in data:
            errors.append(f"data.json missing required key: {key}")

    valid_runtimes = {"block", "allow"}
    valid_files = {"quarantine", "none"}
    valid_installs = {"block", "allow", "none"}

    actions = data.get("actions", {})
    for sev, action in actions.items():
        if not isinstance(action, dict):
            errors.append(f"actions.{sev}: expected object, got {type(action).__name__}")
            continue
        if action.get("runtime") not in valid_runtimes:
            errors.append(f"actions.{sev}.runtime: invalid value '{action.get('runtime')}' (expected {valid_runtimes})")
        if action.get("file") not in valid_files:
            errors.append(f"actions.{sev}.file: invalid value '{action.get('file')}' (expected {valid_files})")
        if "install" in action and action["install"] not in valid_installs:
            errors.append(f"actions.{sev}.install: invalid value '{action['install']}' (expected {valid_installs})")

    overrides = data.get("scanner_overrides", {})
    for scanner_type, sevs in overrides.items():
        if not isinstance(sevs, dict):
            errors.append(f"scanner_overrides.{scanner_type}: expected object")
            continue
        for sev, action in sevs.items():
            if not isinstance(action, dict):
                errors.append(f"scanner_overrides.{scanner_type}.{sev}: expected object")
                continue
            if action.get("runtime") not in valid_runtimes:
                errors.append(f"scanner_overrides.{scanner_type}.{sev}.runtime: invalid '{action.get('runtime')}'")
            if action.get("file") not in valid_files:
                errors.append(f"scanner_overrides.{scanner_type}.{sev}.file: invalid '{action.get('file')}'")
            if "install" in action and action["install"] not in valid_installs:
                errors.append(f"scanner_overrides.{scanner_type}.{sev}.install: invalid '{action['install']}'")

    if errors:
        ux.err("data.json validation errors:")
        for e in errors:
            click.echo(f"  - {e}")
    else:
        ux.ok("data.json: OK")

    # 2. Try to compile Rego
    rego_compiled = _try_rego_compile(rd)

    if errors or not rego_compiled:
        raise SystemExit(1)

    ux.ok("All validations passed.")


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

@policy.command("test")
@click.option("--rego-dir", default=None,
              help="Path to rego directory (default: <policy_dir>/rego, e.g. "
                   "~/.defenseclaw/policies/rego; the bundled copy before init)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose test output")
@pass_ctx
def test_rego(app: AppContext, rego_dir: str | None, verbose: bool) -> None:
    """Run OPA Rego unit tests.

    Uses the 'opa' binary when it is on PATH, otherwise the OPA test runner
    built into defenseclaw-gateway (no separate install needed).
    """
    rd = rego_dir or _default_rego_dir(app)

    if not os.path.isdir(rd):
        ux.err(f"error: rego directory not found: {rd}")
        raise SystemExit(1)

    if not _has_rego_tests(rd):
        # Installed policy directories ship no *_test.rego files, so this is
        # the normal answer there, not a failure (GAP-1091). The modules
        # must still compile, as 'opa test' requires (GAP-1392).
        if not _try_rego_compile(rd):
            raise SystemExit(1)
        click.echo(
            f"No Rego unit tests (*_test.rego) in {rd}; nothing to run. "
            "Add <module>_test.rego files next to your policies to test them."
        )
        return

    cmd = _rego_tool_cmd(["test", rd], ["policy", "test", "--rego-dir", rd])
    if cmd is None:
        ux.err("error: neither 'opa' nor 'defenseclaw-gateway' was found")
        ux.subhead(
            "Reinstall DefenseClaw, or install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa",
            indent="  ",
        )
        raise SystemExit(1)
    if verbose:
        cmd.append("-v")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        ux.err(f"error: {cmd[0]} not found")
        raise SystemExit(1)
    except subprocess.TimeoutExpired:
        ux.err("error: Rego tests timed out after 60s")
        raise SystemExit(1)

    if result.stdout:
        click.echo(result.stdout.rstrip())
    if result.stderr:
        click.echo(result.stderr.rstrip(), err=True)

    if result.returncode != 0:
        ux.err("Tests FAILED.")
        raise SystemExit(result.returncode)

    ux.ok("All Rego tests passed.")


# ---------------------------------------------------------------------------
# edit — structured editing of policy sections
# ---------------------------------------------------------------------------

@policy.group()
def edit() -> None:
    """Edit policy sections (guardrail, firewall, scanner, actions).

    Each edit changes the active policy unless --policy-name (-p) names
    another one; the result line names the policy it changed. Editing the
    active policy applies the change and, by default, asks the running
    gateway to reload it (``--no-reload`` to skip). Editing any other policy
    only saves the draft.
    """


_reload_option = click.option(
    "--reload/--no-reload",
    "reload_gateway",
    default=True,
    show_default=True,
    help="When the edited policy is the active one, ask the running gateway to reload it.",
)


@edit.command("actions")
@click.option("--severity", "-s", required=True, type=click.Choice(SEVERITIES),
              help="Severity level to configure")
@click.option("--runtime", type=click.Choice(RUNTIME_CHOICES), default=None,
              help="Turn a finding at this severity off (disable) or leave it running (enable)")
@click.option("--file", "file_action", type=click.Choice(FILE_CHOICES), default=None,
              help="Quarantine the files of a finding at this severity, or leave them (none)")
@click.option("--install", type=click.Choice(INSTALL_CHOICES), default=None,
              help="Block or allow installing an item with a finding at this severity (none: no rule)")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@_reload_option
@pass_ctx
def edit_actions(app: AppContext, severity: str, runtime: str | None, file_action: str | None,
                 install: str | None, policy_name: str | None, reload_gateway: bool) -> None:
    """Edit severity actions for the global policy."""
    path, data, name = _resolve_editable_policy(app, policy_name)

    actions = data.setdefault("skill_actions", {})
    entry = actions.setdefault(severity, {})

    changed = []
    if runtime is not None:
        entry["runtime"] = runtime
        changed.append(f"runtime={runtime}")
    if file_action is not None:
        entry["file"] = file_action
        changed.append(f"file={file_action}")
    if install is not None:
        entry["install"] = install
        changed.append(f"install={install}")

    if not changed:
        click.echo("No changes specified.")
        return

    synced = _save_and_maybe_sync(app, path, data, name)
    before = _restart_only_config(app.cfg)
    if synced:
        # CLI skill-action paths fall back to config.yaml's skill_actions,
        # which `policy activate` writes; an edit to the active policy
        # updates them the same way. A draft edit leaves them alone.
        app.cfg.skill_actions = _skill_actions_from_policy(data)
        app.cfg.save()
    ux.ok(f"Updated {severity.upper()} actions of {_edited_policy_label(app, name)}: {', '.join(changed)}")
    _reload_after_edit(
        app,
        name,
        synced=synced,
        reload_gateway=reload_gateway,
        needs_restart=_restart_only_config(app.cfg) != before,
    )


@edit.command("scanner")
@click.option("--type", "scanner_type", required=True, type=click.Choice(["skill", "mcp", "plugin"]),
              help="Scanner type to override")
@click.option("--severity", "-s", required=True, type=click.Choice(SEVERITIES),
              help="Severity level to configure")
@click.option("--runtime", type=click.Choice(RUNTIME_CHOICES), default=None,
              help="Turn a finding at this severity off (disable) or leave it running (enable)")
@click.option("--file", "file_action", type=click.Choice(FILE_CHOICES), default=None,
              help="Quarantine the files of a finding at this severity, or leave them (none)")
@click.option("--install", type=click.Choice(INSTALL_CHOICES), default=None,
              help="Block or allow installing an item with a finding at this severity (none: no rule)")
@click.option("--remove", is_flag=True, help="Remove this override (revert to global)")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@_reload_option
@pass_ctx
def edit_scanner(app: AppContext, scanner_type: str, severity: str, runtime: str | None,
                 file_action: str | None, install: str | None, remove: bool,
                 policy_name: str | None, reload_gateway: bool) -> None:
    """Edit per-scanner-type severity overrides."""
    path, data, name = _resolve_editable_policy(app, policy_name)

    overrides = data.setdefault("scanner_overrides", {})

    if remove:
        scanner_ovr = overrides.get(scanner_type, {})
        if severity in scanner_ovr:
            del scanner_ovr[severity]
            if not scanner_ovr:
                del overrides[scanner_type]
            synced = _save_and_maybe_sync(app, path, data, name)
            ux.ok(f"Removed {scanner_type}/{severity.upper()} override from {_edited_policy_label(app, name)}.")
            _reload_after_edit(app, name, synced=synced, reload_gateway=reload_gateway)
        else:
            click.echo(f"No override found for {scanner_type}/{severity.upper()}.")
        return

    scanner_ovr = overrides.setdefault(scanner_type, {})
    entry = scanner_ovr.setdefault(severity, {"runtime": "allow", "file": "none", "install": "none"})

    changed = []
    if runtime is not None:
        entry["runtime"] = runtime
        changed.append(f"runtime={runtime}")
    if file_action is not None:
        entry["file"] = file_action
        changed.append(f"file={file_action}")
    if install is not None:
        entry["install"] = install
        changed.append(f"install={install}")

    if not changed:
        click.echo("No changes specified. Use --runtime, --file, and/or --install.")
        return

    synced = _save_and_maybe_sync(app, path, data, name)
    ux.ok(
        f"Updated scanner override {scanner_type}/{severity.upper()} in {_edited_policy_label(app, name)}: "
        f"{', '.join(changed)}"
    )
    _reload_after_edit(app, name, synced=synced, reload_gateway=reload_gateway)


@edit.command("guardrail")
@click.option("--block-threshold", type=_SEVERITY_RANK, default=None,
              help="Lowest severity to block: LOW, MEDIUM, HIGH, CRITICAL (or 1-4)")
@click.option("--alert-threshold", type=_SEVERITY_RANK, default=None,
              help="Lowest severity to alert on: LOW, MEDIUM, HIGH, CRITICAL (or 1-4)")
@click.option("--cisco-trust-level", type=click.Choice(["full", "advisory", "none"]), default=None,
              help="How Cisco AI Defense verdicts count: full (can block), advisory (shown, never block), none")
@click.option("--add-pattern", nargs=2, multiple=True, metavar="CATEGORY PATTERN",
              help="Add a guardrail pattern (e.g. --add-pattern injection 'new pattern')")
@click.option("--remove-pattern", nargs=2, multiple=True, metavar="CATEGORY PATTERN",
              help="Remove a guardrail pattern")
@click.option("--set-severity-mapping", nargs=2, multiple=True, metavar="CATEGORY SEVERITY",
              help="Set severity mapping (e.g. --set-severity-mapping injection CRITICAL)")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@_reload_option
@pass_ctx
def edit_guardrail(app: AppContext, block_threshold: int | None, alert_threshold: int | None,
                   cisco_trust_level: str | None, add_pattern: tuple, remove_pattern: tuple,
                   set_severity_mapping: tuple, policy_name: str | None, reload_gateway: bool) -> None:
    """Edit guardrail thresholds, patterns, and severity mappings.

    Thresholds are severities: LOW, MEDIUM, HIGH or CRITICAL (or their
    ranks 1-4).
    They govern LLM traffic through the guardrail proxy only. Tool calls
    from hook connectors (Claude Code, Codex, ...) are blocked at the level
    set with 'defenseclaw guardrail block-at' / 'alert-at' instead.

    Edits the active policy unless --policy-name names another one.
    """
    path, data, name = _resolve_editable_policy(app, policy_name)

    guardrail = data.setdefault("guardrail", {})
    changed = []

    if block_threshold is not None:
        guardrail["block_threshold"] = block_threshold
        changed.append(f"block_threshold={_severity_rank_label(block_threshold)}")
    if alert_threshold is not None:
        guardrail["alert_threshold"] = alert_threshold
        changed.append(f"alert_threshold={_severity_rank_label(alert_threshold)}")
    if cisco_trust_level is not None:
        guardrail["cisco_trust_level"] = cisco_trust_level
        changed.append(f"cisco_trust_level={cisco_trust_level}")

    patterns = guardrail.setdefault("patterns", {})
    for category, pattern in add_pattern:
        cat_list = patterns.setdefault(category, [])
        if pattern not in cat_list:
            cat_list.append(pattern)
            changed.append(f"+pattern {category}:'{pattern}'")
        else:
            click.echo(f"  Pattern already exists in {category}: '{pattern}'")

    for category, pattern in remove_pattern:
        cat_list = patterns.get(category, [])
        if pattern in cat_list:
            cat_list.remove(pattern)
            changed.append(f"-pattern {category}:'{pattern}'")
        else:
            click.echo(f"  Pattern not found in {category}: '{pattern}'")

    mappings = guardrail.setdefault("severity_mappings", {})
    for category, severity in set_severity_mapping:
        mappings[category] = severity
        changed.append(f"mapping {category}={severity}")

    if not changed:
        click.echo("No changes specified.")
        return

    synced = _save_and_maybe_sync(app, path, data, name)
    ux.ok(f"Guardrail of {_edited_policy_label(app, name)} updated: {', '.join(changed)}")
    if block_threshold is not None or alert_threshold is not None:
        click.echo(
            "  Note: these thresholds apply to LLM traffic through the guardrail proxy. "
            "To change when hook tool calls are blocked, run "
            "'defenseclaw guardrail block-at LEVEL [--connector NAME]'."
        )
    _reload_after_edit(app, name, synced=synced, reload_gateway=reload_gateway)


@edit.command("firewall")
@click.option("--default-action", type=click.Choice(["allow", "deny"]), default=None,
              help="What happens to traffic no rule matches")
@click.option("--add-domain", multiple=True, help="Add an allowed domain")
@click.option("--remove-domain", multiple=True, help="Remove an allowed domain")
@click.option("--add-blocked", multiple=True, help="Add a blocked destination (IP/host)")
@click.option("--remove-blocked", multiple=True, help="Remove a blocked destination")
@click.option("--add-port", multiple=True, type=int, help="Add an allowed port")
@click.option("--remove-port", multiple=True, type=int, help="Remove an allowed port")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@_reload_option
@pass_ctx
def edit_firewall(app: AppContext, default_action: str | None, add_domain: tuple,
                  remove_domain: tuple, add_blocked: tuple, remove_blocked: tuple,
                  add_port: tuple, remove_port: tuple, policy_name: str | None, reload_gateway: bool) -> None:
    """Edit egress firewall rules (domains, ports, blocked destinations)."""
    path, data, name = _resolve_editable_policy(app, policy_name)

    fw = data.setdefault("firewall", {})
    changed = []

    if default_action is not None:
        fw["default_action"] = default_action
        changed.append(f"default_action={default_action}")

    domains = fw.setdefault("allowed_domains", [])
    for d in add_domain:
        if d not in domains:
            domains.append(d)
            changed.append(f"+domain {d}")
    for d in remove_domain:
        if d in domains:
            domains.remove(d)
            changed.append(f"-domain {d}")

    blocked = fw.setdefault("blocked_destinations", [])
    for b in add_blocked:
        if b not in blocked:
            blocked.append(b)
            changed.append(f"+blocked {b}")
    for b in remove_blocked:
        if b in blocked:
            blocked.remove(b)
            changed.append(f"-blocked {b}")

    ports = fw.setdefault("allowed_ports", [])
    for p in add_port:
        if p not in ports:
            ports.append(p)
            changed.append(f"+port {p}")
    for p in remove_port:
        if p in ports:
            ports.remove(p)
            changed.append(f"-port {p}")

    if not changed:
        click.echo("No changes specified.")
        return

    synced = _save_and_maybe_sync(app, path, data, name)
    ux.ok(f"Firewall of {_edited_policy_label(app, name)} updated: {', '.join(changed)}")
    _reload_after_edit(app, name, synced=synced, reload_gateway=reload_gateway)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _default_policy_data() -> dict:
    return {
        "name": "custom",
        "description": "Custom policy",
        "admission": {
            "scan_on_install": True,
            "allow_list_bypass_scan": True,
        },
        "skill_actions": {
            "critical": {"file": "quarantine", "runtime": "disable", "install": "block"},
            "high": {"file": "quarantine", "runtime": "disable", "install": "block"},
            "medium": {"file": "none", "runtime": "enable", "install": "none"},
            "low": {"file": "none", "runtime": "enable", "install": "none"},
            "info": {"file": "none", "runtime": "enable", "install": "none"},
        },
        "scanner_overrides": {},
        "guardrail": {
            "block_threshold": 4,
            "alert_threshold": 2,
            "hilt": {
                "enabled": False,
                "min_severity": "HIGH",
            },
            "cisco_trust_level": "full",
            "patterns": {},
            "severity_mappings": {},
        },
        "firewall": {
            "default_action": "deny",
            "blocked_destinations": ["169.254.169.254", "fd00:ec2::254"],
            "allowed_domains": [],
            "allowed_ports": [443, 80],
        },
        "enforcement": {
            "max_enforcement_delay_seconds": 2,
        },
        "audit": {
            "log_all_actions": True,
            "log_scan_results": True,
            "retention_days": 90,
        },
    }


def _action_for_level(level: str) -> dict:
    """Convert a simple action level (block/warn/allow) to a full action dict."""
    if level == "block":
        return {"file": "quarantine", "runtime": "disable", "install": "block"}
    elif level == "warn":
        return {"file": "none", "runtime": "enable", "install": "none"}
    else:
        return {"file": "none", "runtime": "enable", "install": "none"}


def _get_active_policy_name(app: AppContext) -> str | None:
    """Determine which policy is currently active by reading OPA data.json.

    Prefers the user policy_dir copy (where activation writes), falling
    back to the bundled repo-local copy.
    """
    user_data_json = os.path.join(app.cfg.policy_dir, "rego", "data.json")
    bundled_data_json = os.path.join(_bundled_policies_dir(), "rego", "data.json")

    for data_json in (user_data_json, bundled_data_json):
        if os.path.isfile(data_json):
            try:
                with open(data_json) as f:
                    data = json.load(f)
                return data.get("config", {}).get("policy_name")
            except (OSError, json.JSONDecodeError):
                continue
    return None


def _is_bundled_path(path: str) -> bool:
    """True when ``path`` resolves inside the bundled (wheel/repo) policies dir."""
    bundled = _bundled_policies_dir()
    try:
        real_path = os.path.realpath(path)
        real_bundled = os.path.realpath(bundled)
    except OSError:
        return False
    return real_path == real_bundled or real_path.startswith(real_bundled + os.sep)


def _user_policy_dest(app: AppContext, name: str) -> str:
    """Return the guarded user-dir destination path for a policy ``name``.

    Mirrors the symlink / path-escape guards used by ``create`` and
    ``delete`` so copy-on-write can never be tricked into writing outside
    the user policy directory.
    """
    name = _sanitize_policy_name(name)
    policies_dir = _ensure_policies_dir(app)
    dest = os.path.join(policies_dir, f"{name}.yaml")

    if os.path.islink(dest):
        ux.echo(f"error: policy '{name}' is a symbolic link — refusing to write", err=True)
        raise SystemExit(1)

    real_dest = os.path.realpath(dest)
    real_dir = os.path.realpath(policies_dir)
    if not real_dest.startswith(real_dir + os.sep):
        click.echo("error: resolved path escapes policy directory", err=True)
        raise SystemExit(1)
    return dest


def _resolve_editable_policy(app: AppContext, policy_name: str | None) -> tuple[str, dict, str]:
    """Resolve the policy to edit. Returns ``(path, data, name)``.

    ``path`` is always a writable location under the user policy dir:
    editing a built-in copies it out of the bundled wheel dir first
    (copy-on-write, OTHER-4) so we never write back into site-packages,
    which is lost on upgrade and may be read-only. ``name`` is the
    resolved policy name so callers can gate the live OPA sync on whether
    the edited policy is the active one (OTHER-2). Raises ``SystemExit(1)``
    when the policy can't be found.
    """
    if policy_name:
        name = _sanitize_policy_name(policy_name)
        path = _find_policy(app, name)
        if not path:
            _policy_not_found(app, policy_name)
    else:
        name = _get_active_policy_name(app)
        path = _find_policy(app, name) if name else None
        if not path:
            click.echo(
                "error: no active policy found. Activate one first: "
                "defenseclaw policy activate <name>",
                err=True,
            )
            raise SystemExit(1)

    data = _load_policy(path)

    # Copy-on-write (OTHER-4): editing a built-in must not mutate the
    # bundled copy in the wheel/repo. Redirect the write to the user
    # policy dir; the full policy data is saved there, shadowing the
    # built-in (list/show already prefer the user dir).
    if _is_bundled_path(path):
        dest = _user_policy_dest(app, name)
        click.echo(ux.dim(
            f"Editing built-in '{name}' as a user copy at {dest} "
            f"(defenseclaw policy delete {name} restores the built-in)"
        ))
        path = dest

    return path, data, name


def _save_and_maybe_sync(app: AppContext, path: str, data: dict, name: str) -> bool:
    """Persist the edited policy YAML, syncing the live OPA data.json only
    when the edited policy is the active one (OTHER-2).

    Editing a non-active draft must not overwrite the gateway's live
    data.json nor silently stamp the draft as active (a "tweak a draft"
    action becoming a live policy swap). When the edited policy isn't
    active we save the YAML and tell the operator how to apply it.
    Returns True when the live (active) copy was synced.
    """
    _save_policy(path, data)
    active = _get_active_policy_name(app)
    if active is not None and name == active:
        _sync_opa_data(app, data)
        return True
    click.echo(
        f"  {ux.dim('Saved draft. Activate with:')} "
        f"defenseclaw policy activate {name}"
    )
    return False


def _reload_after_edit(
    app: AppContext, name: str, *, synced: bool, reload_gateway: bool, needs_restart: bool = False
) -> None:
    """After editing the active policy, reload it like ``policy activate``."""
    if synced and reload_gateway:
        _reload_and_report(app, name, needs_restart=needs_restart)


def _edited_policy_label(app: AppContext, name: str) -> str:
    """"policy 'strict' (active)": the result line of an edit names the policy it changed (GAP-1667)."""
    state = "active" if name == _get_active_policy_name(app) else "draft"
    return f"policy '{name}' ({state})"


def _opa_runtime_action(runtime: str) -> str:
    """Map a policy ``runtime`` value to the OPA ``data.json`` vocabulary.

    Policy YAML may use either the enforcement vocabulary
    (``enable``/``disable``) or the OPA vocabulary (``allow``/``block``).
    Both ``disable`` and ``block`` mean "do not allow runtime execution"
    and must map to ``block``; ``enable``/``allow`` (and anything
    unrecognised) map to ``allow``. The previous
    ``"block" if runtime == "disable" else "allow"`` silently rewrote an
    existing ``runtime: block`` override to ``allow`` (F-0241), so a
    bundled override meant to block runtime execution was synced as an
    allow.
    """
    return "block" if str(runtime).strip().lower() in ("disable", "block") else "allow"


def _sync_opa_data(app: AppContext, policy_data: dict) -> None:
    """Sync OPA data.json with the activated policy settings.

    This performs a complete sync of all policy dimensions:
    - config (admission settings, enforcement)
    - actions (with install field)
    - scanner_overrides
    - guardrail (thresholds, HILT, patterns, severity_mappings)
    - firewall (domains, ports, blocked destinations)
    - audit (retention, logging flags)

    Writes to the user's policy_dir (where the gateway reads from).
    Falls back to the bundled repo-local copy as a seed source.
    """
    user_rego_dir = os.path.join(app.cfg.policy_dir, "rego")
    user_data_json = os.path.join(user_rego_dir, "data.json")
    bundled_data_json = os.path.join(_bundled_policies_dir(), "rego", "data.json")

    if os.path.isfile(user_data_json):
        data_json_path = user_data_json
    elif os.path.isfile(bundled_data_json):
        os.makedirs(user_rego_dir, exist_ok=True)
        import shutil
        shutil.copy2(bundled_data_json, user_data_json)
        data_json_path = user_data_json
    else:
        return

    try:
        with open(data_json_path) as f:
            opa_data = json.load(f)
    except OSError as exc:
        # silently returning on read failures hid
        # malformed/stale data.json from `policy activate`. The
        # caller has already updated config to the new policy
        # selection, so leaving sync skipped left the gateway
        # running with stale OPA data that would not match the
        # advertised activation. Surface the failure and let
        # activate exit non-zero.
        raise click.ClickException(
            f"failed to read OPA data file at {data_json_path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"OPA data file at {data_json_path} is not valid JSON: {exc}; "
            f"run `defenseclaw policy validate` and repair before activating"
        ) from exc

    # --- config section ---
    opa_data.setdefault("config", {})
    opa_data["config"]["policy_name"] = policy_data.get("name", "custom")

    admission = policy_data.get("admission", {})
    if "allow_list_bypass_scan" in admission:
        opa_data["config"]["allow_list_bypass_scan"] = admission["allow_list_bypass_scan"]
    if "scan_on_install" in admission:
        opa_data["config"]["scan_on_install"] = admission["scan_on_install"]

    enforcement = policy_data.get("enforcement", {})
    if "max_enforcement_delay_seconds" in enforcement:
        opa_data["config"]["max_enforcement_delay_seconds"] = enforcement["max_enforcement_delay_seconds"]

    # --- actions section (with install field) ---
    actions = policy_data.get("skill_actions", {})
    opa_actions = {}
    for sev in SEVERITIES:
        raw = actions.get(sev, {})
        runtime = raw.get("runtime", "enable")
        file_action = raw.get("file", "none")
        install_action = raw.get("install", "none")
        opa_runtime = _opa_runtime_action(runtime)
        opa_install = install_action if install_action in ("block", "allow", "none") else "none"
        opa_actions[sev.upper()] = {
            "runtime": opa_runtime,
            "file": file_action,
            "install": opa_install,
        }
    opa_data["actions"] = opa_actions

    # --- scanner_overrides section ---
    overrides = policy_data.get("scanner_overrides", {})
    opa_overrides: dict = {}
    for scanner_type, sevs in overrides.items():
        if not isinstance(sevs, dict):
            continue
        opa_scanner: dict = {}
        for sev, action in sevs.items():
            if not isinstance(action, dict):
                continue
            runtime = action.get("runtime", "enable")
            opa_runtime = _opa_runtime_action(runtime)
            opa_scanner[sev.upper()] = {
                "runtime": opa_runtime,
                "file": action.get("file", "none"),
                "install": action.get("install", "none"),
            }
        if opa_scanner:
            opa_overrides[scanner_type] = opa_scanner
    opa_data["scanner_overrides"] = opa_overrides

    # --- guardrail section ---
    guardrail = policy_data.get("guardrail", {})
    if guardrail:
        opa_data.setdefault("guardrail", {})
        for key in ("block_threshold", "alert_threshold", "cisco_trust_level",
                     "patterns", "severity_mappings", "hilt"):
            if key in guardrail:
                opa_data["guardrail"][key] = guardrail[key]

    # --- firewall section ---
    firewall = policy_data.get("firewall", {})
    if firewall:
        opa_data.setdefault("firewall", {})
        for key in ("default_action", "blocked_destinations", "allowed_domains", "allowed_ports"):
            if key in firewall:
                opa_data["firewall"][key] = firewall[key]

    # --- first_party_allow_list section ---
    yaml_fp = policy_data.get("first_party_allow_list", [])
    if yaml_fp:
        existing = {
            (e["target_type"], e["target_name"]): e
            for e in opa_data.get("first_party_allow_list", [])
            if "target_type" in e and "target_name" in e
        }
        merged = []
        for entry in yaml_fp:
            key = (entry.get("target_type", ""), entry.get("target_name", ""))
            base = existing.get(key, {})
            base.update(entry)
            if "source_path_contains" not in base:
                prev = existing.get(key, {})
                if "source_path_contains" in prev:
                    base["source_path_contains"] = prev["source_path_contains"]
            merged.append(base)
        opa_data["first_party_allow_list"] = merged

    # --- audit section ---
    audit_cfg = policy_data.get("audit", {})
    if audit_cfg:
        opa_data.setdefault("audit", {})
        for key in ("retention_days", "log_all_actions", "log_scan_results"):
            if key in audit_cfg:
                opa_data["audit"][key] = audit_cfg[key]

    with open(data_json_path, "w") as f:
        json.dump(opa_data, f, indent=2)
        f.write("\n")


def _has_rego_tests(rego_dir: str) -> bool:
    """True when rego_dir (recursively, like 'opa test') holds a *_test.rego."""
    for _root, _dirs, files in os.walk(rego_dir):
        if any(f.endswith("_test.rego") for f in files):
            return True
    return False


def _rego_tool_cmd(opa_args: list[str], gateway_args: list[str]) -> list[str] | None:
    """Return the argv for a Rego check: 'opa' when installed, else the gateway.

    defenseclaw-gateway embeds OPA (``policy validate`` / ``policy test``), so
    a standard install can validate and test Rego without a separate 'opa'
    binary (GAP-1091). Returns None when neither is available.
    """
    import shutil

    opa = shutil.which("opa")
    if opa:
        return [opa, *opa_args]
    from defenseclaw.gateway import resolve_gateway_binary

    gateway = resolve_gateway_binary()
    if gateway:
        return [gateway, *gateway_args]
    return None


def _try_rego_compile(rego_dir: str) -> bool:
    """Try to compile Rego modules. Returns True on success."""
    rego_files = [
        os.path.join(rego_dir, f) for f in os.listdir(rego_dir)
        if f.endswith(".rego") and not f.endswith("_test.rego")
    ]
    if not rego_files:
        ux.err("FAIL: no .rego files found")
        return False

    cmd = _rego_tool_cmd(["check", "--strict", *rego_files], ["policy", "validate", "--rego-dir", rego_dir])
    if cmd is None:
        # A missing checker must not turn into a clean "Rego compilation: OK"
        # verdict, so the default fails closed. Operators can opt out with
        # DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA=1.
        if os.environ.get("DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA", "").strip() == "1":
            ux.echo("  No Rego checker found — skipping Rego compilation (opt-in).")
            return True
        ux.err("FAIL: no Rego checker found (neither 'opa' nor 'defenseclaw-gateway').")
        click.echo("  Reinstall DefenseClaw, or install OPA for full validation.")
        click.echo(
            "  Set DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA=1 to bypass "
            "(NOT recommended for production)."
        )
        return False

    via = "opa" if os.path.basename(cmd[0]).startswith("opa") else "defenseclaw-gateway"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        ux.err(f"FAIL: {cmd[0]} not found")
        return False
    except subprocess.TimeoutExpired:
        ux.err("FAIL: Rego compilation timed out")
        return False
    if result.returncode == 0:
        ux.ok(f"Rego compilation: OK ({len(rego_files)} modules, {via})")
        return True
    ux.err("Rego compilation errors:")
    if result.stderr:
        click.echo(result.stderr.rstrip())
    if result.stdout:
        click.echo(result.stdout.rstrip())
    return False
