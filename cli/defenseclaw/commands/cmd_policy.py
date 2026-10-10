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
import tempfile
from typing import NoReturn

import click
import yaml

from defenseclaw import policy_catalog, ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.enforce import asset_lists
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
    """The Rego directory the gateway loads: <policy_dir>/rego.

    The bundled copy stands in only before init (no config.yaml yet). The
    bundled directory lives inside the package and is replaced on upgrade, so
    it is the wrong place to point users at for their own tests (GAP-1459),
    and after init it must not hide a policy directory that is gone, which
    defenseclaw-gateway policy validate reports (GAP-0889). Secure Client
    keeps the fallback of main (issue #1092).
    """
    cfg = getattr(app, "cfg", None)
    policy_dir = getattr(cfg, "policy_dir", "") or ""
    user_rego = os.path.join(policy_dir, "rego") if policy_dir else ""
    if user_rego and os.path.isdir(user_rego):
        return user_rego
    if user_rego and _initialized(cfg) and not asset_lists.is_secure_client(cfg):
        return user_rego
    return _rego_dir()


def _initialized(cfg) -> bool:
    """True once init has written config.yaml for this data directory."""
    from defenseclaw.config import config_path_for_data_dir

    return config_path_for_data_dir(getattr(cfg, "data_dir", None)).is_file()


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
        names = [p.name for p in policy_catalog.list_named_policies(_policies_dir(app), app.cfg)]
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
    policies = policy_catalog.list_named_policies(_policies_dir(app), app.cfg)
    active = policy_catalog.active_policy_name(_policies_dir(app), app.cfg)
    warnings = [] if asset_lists.is_secure_client(app.cfg) else policy_catalog.configured_hilt_warnings(app.cfg)

    if json_out:
        payload = {"version": 1, "active": active, "policies": [p.to_json() for p in policies]}
        if warnings:
            payload["warnings"] = warnings
        click.echo(
            json.dumps(
                payload,
                indent=2,
            )
        )
        return

    if not policies:
        ux.warn("No policies found.")
        return

    click.echo(f"{ux.bold('Available policies:')}")
    click.echo()
    for warning in warnings:
        ux.warn(warning)
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
    if not active and not asset_lists.is_secure_client(app.cfg):
        # Since config_version 9 a policy is active when config.yaml holds its
        # values; an edit made after `policy activate` matches none (GAP-0970).
        click.echo(ux.dim("  No policy is active: none matches the values config.yaml holds now (activating a policy"))
        click.echo(ux.dim("  writes its values there, and a later change to one of them leaves no policy matching)."))
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
        summary = policy_catalog.get_policy(_sanitize_policy_name(name), _policies_dir(app), app.cfg)
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
            "  (activation writes them to guardrail.block_at / alert_at)"
        )
        hilt = guardrail.get("hilt", {}) or {}
        click.echo(
            f"  hilt:               enabled={bool(hilt.get('enabled', False))} "
            f"min={hilt.get('min_severity', 'HIGH')}"
        )
        click.echo(f"  cisco_trust_level:  {guardrail.get('cisco_trust_level', 'full')}")

    fw = data.get("firewall", {})
    if fw:
        click.echo()
        click.echo("Firewall (stored in the preset; the gateway does not enforce it):")
        click.echo(f"  default_action:        {fw.get('default_action', 'deny')}")
        click.echo(f"  blocked_destinations:  {len(fw.get('blocked_destinations', []))} entries")
        click.echo(f"  allowed_domains:       {len(fw.get('allowed_domains', []))} entries")
        click.echo(f"  allowed_ports:         {fw.get('allowed_ports', [])}")

    audit_cfg = data.get("audit", {})
    if audit_cfg:
        click.echo()
        click.echo("Audit:")
        click.echo(f"  retention_days: {audit_cfg.get('retention_days', 90)}")


# ---------------------------------------------------------------------------
# activate
# ---------------------------------------------------------------------------

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
    secure_client = asset_lists.is_secure_client(app.cfg)
    before = _restart_only_config(app.cfg) if secure_client else ()
    levels_before = None if secure_client else _global_levels(app.cfg)
    path, restart_keys = _activate_policy(app, name)
    ux.ok(f"Policy '{name}' activated.")
    if secure_client:
        click.echo(
            "  Its guardrail thresholds govern LLM traffic through the proxy; tool-call "
            "blocking is unchanged (see 'defenseclaw guardrail status' and 'guardrail block-at')."
        )
    else:
        click.echo(
            "  Its guardrail levels apply to tool calls, prompts and LLM traffic on every connector "
            "without its own level (see 'defenseclaw guardrail status' and 'guardrail block-at')."
        )
        _report_level_changes(levels_before, app.cfg, name)
    # A stopped gateway gets one note after the success lines, covering both
    # the skipped audit event and the reload on start (GAP-1718).
    audit_skipped = _log_policy_action(
        app, "policy-activate", name, f"source={path}", done="Policy saved", defer_stopped=reload_gateway
    )
    if not reload_gateway:
        return
    # The gateway applies a preset hot from the new configuration generation
    # (spec section 4); only a key the writer reports as restart-required
    # restarts it (GAP-0056). Secure Client keeps the restart of main for
    # the sections its gateway reads at start (issue #1092).
    needs_restart = _restart_only_config(app.cfg) != before if secure_client else bool(restart_keys)
    _reload_and_report(app, name, needs_restart=needs_restart, audit_skipped=audit_skipped)


def _global_levels(cfg) -> dict[str, tuple[str, int]]:  # noqa: ANN001 - Config, imported lazily
    """guardrail.block_at and alert_at: the stored value and the effective rank of the global scope."""
    levels = policy_catalog.resolve_levels(
        policy_catalog.global_pack(cfg).path, (cfg.guardrail.block_at, cfg.guardrail.alert_at)
    )
    return {
        "block_at": (policy_catalog.level_value(cfg.guardrail.block_at), levels.block_rank),
        "alert_at": (policy_catalog.level_value(cfg.guardrail.alert_at), levels.alert_rank),
    }


def _report_level_changes(before: dict[str, tuple[str, int]], cfg, name: str) -> None:  # noqa: ANN001
    """Name each global guardrail level the activation changed, old and new.

    A preset writes its levels over the ones in config.yaml, including a level
    set with `guardrail block-at` / `alert-at`; one that now blocks or alerts on
    fewer severities is a warning with the command that sets it back
    (GAP-1020).
    """
    after = _global_levels(cfg)
    for key, command in (("block_at", "block-at"), ("alert_at", "alert-at")):
        (old_set, old_rank), (new_set, new_rank) = before[key], after[key]
        if old_rank == new_rank:
            continue
        old, new = policy_catalog.level_name(old_rank), policy_catalog.level_name(new_rank)
        if new_rank < old_rank:
            click.echo(f"  guardrail.{key}: {old} -> {new}")
            continue
        how = "cleared" if old_set and not new_set else "lowered"
        origin = f"guardrail.{key} {old_set} in config.yaml" if old_set else f"the rule pack's {old}"
        ux.warn(
            f"guardrail.{key}: {old} -> {new}: policy '{name}' {how} {origin}. "
            f"To keep {old}: defenseclaw guardrail {command} {old}"
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
    """The sections a policy writes that a Secure Client gateway reads at start.

    On Secure Client ``policy activate`` keeps the restart of main for a
    change to ``watch`` or ``cisco_ai_defense`` (issue #1092); every other
    gateway reloads them hot.
    """
    return tuple(repr(getattr(cfg, section, None)) for section in ("watch", "cisco_ai_defense"))


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


_RANK_NAMES = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


def _admission_triple(raw: dict) -> dict:
    """A policy action in config ``admission`` triple form. Policy YAML uses
    either runtime vocabulary (enable/disable or allow/block, F-0241)."""
    runtime = str(raw.get("runtime", "enable")).strip().lower()
    if runtime not in {"enable", "disable", "allow", "block"}:
        raise ValueError(f"invalid runtime action {runtime!r}; expected enable, disable, allow or block")
    return {
        "install": str(raw.get("install") or "none"),
        "file": str(raw.get("file") or "none"),
        "runtime": "disable" if runtime in ("disable", "block") else "enable",
    }


def _policy_bool(value: object, key: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _admission_from_policy(data: dict):  # noqa: ANN202 - AdmissionConfig, imported lazily
    """A named policy's admission settings as config ``admission:``.

    The policy's ``skill_actions`` applied to every asset type and its
    ``scanner_overrides.<type>`` refined one type, so they become
    ``admission.defaults.actions`` and ``admission.<type>.actions``.
    """
    from defenseclaw.config import AdmissionConfig, AdmissionFirstParty

    adm = AdmissionConfig()
    raw = data.get("admission") or {}
    if isinstance(raw, dict):
        if "scan_on_install" in raw:
            adm.defaults.scan_on_install = _policy_bool(raw["scan_on_install"], "admission.scan_on_install")
        if "allow_list_bypass_scan" in raw:
            adm.defaults.allow_list_bypass_scan = _policy_bool(
                raw["allow_list_bypass_scan"], "admission.allow_list_bypass_scan"
            )
    for sev, action in (data.get("skill_actions") or {}).items():
        if isinstance(action, dict) and str(sev).lower() in SEVERITIES:
            adm.defaults.actions[str(sev).lower()] = _admission_triple(action)
    for target_type, sevs in (data.get("scanner_overrides") or {}).items():
        holder = getattr(adm, str(target_type), None) if target_type in ("skill", "mcp", "plugin") else None
        if holder is None or not isinstance(sevs, dict):
            continue
        for sev, action in sevs.items():
            if isinstance(action, dict) and str(sev).lower() in SEVERITIES:
                holder.actions[str(sev).lower()] = _admission_triple(action)
    if "first_party_allow_list" in data:
        entries = data["first_party_allow_list"]
        if not isinstance(entries, list):
            raise ValueError("first_party_allow_list must be a list")
        # The preset's top-level list is complete when present. Keep an
        # explicit empty list so compilation cannot restore built-in entries.
        for target_type in ("skill", "mcp", "plugin"):
            getattr(adm, target_type).first_party_allow_list = []
    else:
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        holder = getattr(adm, str(entry.get("target_type", "")), None)
        name = str(entry.get("target_name", "") or "")
        paths = [str(p) for p in entry.get("source_path_contains") or [] if p]
        if holder is None or not name or not paths:
            continue
        if holder.first_party_allow_list is None:
            holder.first_party_allow_list = []
        holder.first_party_allow_list.append(
            AdmissionFirstParty(name=name, source_path_contains=paths, reason=str(entry.get("reason", "") or "")),
        )
    # The preset's actions are an explicit choice for skills too: without
    # admission.skill.actions the scanner gate would decide skills instead.
    for sev, action in adm.defaults.actions.items():
        adm.skill.actions.setdefault(sev, action)
    return adm


def _apply_policy_guardrail(cfg, data: dict) -> None:  # noqa: ANN001 - Config, imported lazily
    """A named policy's guardrail mode, thresholds and Cisco trust level as
    config keys. A threshold equal to the configured rule pack's posture
    default is left unset so that default applies; any other is written, so the
    preset's levels hold whichever pack is selected (as the v9 migration
    compares). A preset's ``hilt`` is not applied: HITL is the operator's
    setting (``defenseclaw guardrail hilt``), and activation keeps it."""
    from defenseclaw.policy_catalog import _PROFILE_RANKS, global_pack, pack_profile

    guardrail = data.get("guardrail") or {}
    if not isinstance(guardrail, dict):
        return
    pack_block, pack_alert = _PROFILE_RANKS[pack_profile(global_pack(cfg).path)]
    for key, attr, default in (
        ("block_threshold", "block_at", pack_block),
        ("alert_threshold", "alert_at", pack_alert),
    ):
        if key in guardrail:
            rank = int(guardrail[key])
            setattr(cfg.guardrail, attr, "" if rank == default else _RANK_NAMES.get(rank, ""))
    if "mode" in guardrail:
        mode = str(guardrail["mode"]).strip()
        if mode not in {"observe", "action"}:
            raise ValueError("guardrail.mode must be observe or action")
        cfg.guardrail.mode = mode
    if "cisco_trust_level" in guardrail:
        level = str(guardrail["cisco_trust_level"] or "")
        cfg.guardrail.cisco_trust_level = "" if level == "full" else level


def _activate_policy(app: AppContext, name: str) -> tuple[str, list[str]]:
    """Apply a named preset to config.yaml, and to v8 OPA data on Secure Client.

    A named policy is a preset: its admission, guardrail threshold, watch,
    Cisco AI Defense and webhook settings become config keys. Returns the
    resolved source path and the changed keys the writer reports as
    restart-required. Raises ``SystemExit(1)`` when the policy can't be
    found.
    """
    path = _find_policy(app, name)
    if not path:
        _policy_not_found(app, name)

    data = _load_policy(path)

    watch_raw = data.get("watch", {})
    secure_client = asset_lists.is_secure_client(app.cfg)
    opa_update = _prepare_opa_data(app, data) if secure_client else None
    if not secure_client:
        try:
            app.cfg.admission = _admission_from_policy(data)
            _apply_policy_guardrail(app.cfg, data)
        except (TypeError, ValueError) as exc:
            raise click.ClickException(f"invalid policy {name!r}: {exc}") from exc
    if "rescan_enabled" in watch_raw:
        app.cfg.watch.rescan_enabled = bool(watch_raw["rescan_enabled"])
    if "rescan_interval_min" in watch_raw:
        app.cfg.watch.rescan_interval_min = int(watch_raw["rescan_interval_min"])

    # Apply Cisco AI Defense settings into config.yaml (Config.CiscoAIDefense). We deliberately
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
    if opa_update is not None:
        # The writer validates and saves config first, under its lock. If the
        # OPA replacement fails, save_verified restores the prior config.
        result = app.cfg.save_verified(lambda _path: _write_opa_data(*opa_update))
    else:
        result = app.cfg.save()
    for note in webhook_notes:
        click.echo(f"  {note}")
    return path, list(getattr(result, "restart_required", None) or [])


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("name")
@click.option("--force", is_flag=True, help="On Secure Client, delete an active custom policy and activate default")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def delete(app: AppContext, name: str, force: bool, assume_yes: bool) -> None:
    """Delete a custom policy, or your edited copy of a built-in.

    The policy file is removed for good (no backup is kept). On a terminal
    you are asked to confirm first; pass --yes to skip the prompt.

    For a built-in policy (default, strict, permissive) only the user copy
    that ``policy edit`` saved is removed, which restores the built-in.

    On Secure Client, an active edited built-in is reactivated from the
    bundled copy. An active custom policy needs --force and then activates
    the built-in default. Other profiles keep the applied config preset.
    """
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

    secure_client = asset_lists.is_secure_client(app.cfg)
    is_active = secure_client and name == _get_active_policy_name(app)
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

    # A named policy is a preset: config.yaml keeps what an activation
    # applied, so deleting the file changes nothing that is enforced.
    _confirm_policy_delete(f"policy '{name}'", path, assume_yes)
    os.remove(real_path)
    ux.ok(f"Policy '{name}' deleted.")
    _log_policy_action(app, "policy-delete", name, "", done="Policy deleted")
    if is_active:
        ux.warn(f"'{name}' was the active policy — re-activating 'default'.")
        _reactivate_after_delete(app, "default")


def _reactivate_after_delete(app: AppContext, name: str) -> None:
    """Apply the replacement to Secure Client OPA data and reload the gateway."""
    before = _restart_only_config(app.cfg)
    _activate_policy(app, name)
    _reload_and_report(app, name, needs_restart=_restart_only_config(app.cfg) != before)


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


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@policy.command()
@click.option("--rego-dir", default=None,
              help="Path to rego directory (default: <policy_dir>/rego, e.g. "
                   "~/.defenseclaw/policies/rego; the bundled copy before init)")
@pass_ctx
def validate(app: AppContext, rego_dir: str | None) -> None:
    """Check policy rule files and Secure Client's legacy OPA data.

    On v9, the Rego modules read only their input: admission and block/allow
    policy come from config.yaml, which ``defenseclaw config`` validates.
    Rego compiles with defenseclaw-gateway, the loader the gateway runs, or
    with 'opa' when the gateway is not installed.
    """
    rd = rego_dir or _default_rego_dir(app)
    if asset_lists.is_secure_client(app.cfg) and not _validate_legacy_data(rd):
        raise SystemExit(1)
    if not os.path.isdir(rd):
        # As in defenseclaw-gateway policy validate: a policy directory
        # without rego/ is config-only mode, a missing one fails (GAP-0889).
        policy_dir = getattr(app.cfg, "policy_dir", "") or ""
        if rego_dir or not policy_dir or not os.path.isdir(policy_dir):
            ux.err(f"FAIL: read rego directory {rd}: no such directory")
            if not rego_dir:
                ux.subhead(
                    f"The policy directory {policy_dir or rd} is gone; restore it or run 'defenseclaw init'.",
                    indent="  ",
                )
            raise SystemExit(1)
        click.echo(f"No Rego directory at {rd}: the admission policy is compiled from config.yaml alone.")
        ux.ok("All validations passed.")
        return
    if not _try_rego_compile(rd, app.cfg):
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
        if not _try_rego_compile(rd, app.cfg):
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

    Without --policy-name (-p) an edit changes the live policy in config.yaml
    (``admission:`` and ``guardrail:``) and the gateway applies it. With
    --policy-name it saves a named policy (a preset) for a later
    ``policy activate``; the result line names what it changed.
    """


_reload_option = click.option(
    "--reload/--no-reload",
    "reload_gateway",
    default=True,
    show_default=True,
    help="After a live edit, ask the running gateway to reload.",
)

_policy_name_option = click.option(
    "--policy-name", "-p", default=None,
    help="Named policy (preset) to edit instead of the live config.yaml policy",
)


def _live_admission_triple(app: AppContext, holder_name: str, severity: str) -> tuple[dict, bool]:
    """The current live triple and its allowed verdict, from config or the compiled default."""
    from defenseclaw.enforce.admission import compile_admission

    holder = getattr(app.cfg.admission, holder_name)
    raw = holder.actions.get(severity)
    if isinstance(raw, dict):
        return dict(raw), False
    target = "tool" if holder_name == "defaults" else holder_name
    if isinstance(raw, str):
        from defenseclaw.enforce.admission import _SHORTHANDS

        action, allowed = _SHORTHANDS.get(raw, _SHORTHANDS["warn"])
    else:
        action, allowed = compile_admission(app.cfg, target).actions[severity.upper()]
    return {"install": action.install, "file": action.file, "runtime": action.runtime}, allowed


def _edit_live_actions(
    app: AppContext, holder_name: str, severity: str, runtime: str | None, file_action: str | None,
    install: str | None, reload_gateway: bool,
) -> None:
    triple, allowed = _live_admission_triple(app, holder_name, severity)
    original = dict(triple)
    changed = []
    for key, value in (("runtime", runtime), ("file", file_action), ("install", install)):
        if value is not None:
            triple[key] = value
            changed.append(f"{key}={value}")
    if not changed:
        click.echo("No changes specified. Use --runtime, --file, and/or --install.")
        return
    # A triple cannot express the distinct allowed verdict. Keep the allow
    # shorthand when the requested edit leaves its actions unchanged.
    value = "allow" if allowed and triple == original else triple
    getattr(app.cfg.admission, holder_name).actions[severity] = value
    updated = [f"admission.{holder_name}.actions.{severity}"]
    if holder_name == "defaults":
        # Skills resolve the scanner gate (scanners.skill_scanner
        # fail_on_severity / review_queue_min) before admission.defaults, and
        # the gate covers every severity, so the edit is also the skill's own.
        app.cfg.admission.skill.actions[severity] = dict(value) if isinstance(value, dict) else value
        updated.append(f"admission.skill.actions.{severity}")
    app.cfg.save()
    ux.ok(f"Updated {' and '.join(updated)}: {', '.join(changed)}")
    _reload_after_edit(app, "live", synced=True, reload_gateway=reload_gateway)


@edit.command("actions")
@click.option("--severity", "-s", required=True, type=click.Choice(SEVERITIES),
              help="Severity level to configure")
@click.option("--runtime", type=click.Choice(RUNTIME_CHOICES), default=None,
              help="Turn a finding at this severity off (disable) or leave it running (enable)")
@click.option("--file", "file_action", type=click.Choice(FILE_CHOICES), default=None,
              help="Quarantine the files of a finding at this severity, or leave them (none)")
@click.option("--install", type=click.Choice(INSTALL_CHOICES), default=None,
              help="Block or allow installing an item with a finding at this severity (none: no rule)")
@_policy_name_option
@_reload_option
@pass_ctx
def edit_actions(app: AppContext, severity: str, runtime: str | None, file_action: str | None,
                 install: str | None, policy_name: str | None, reload_gateway: bool) -> None:
    """Edit the severity actions of every asset type: admission.defaults,
    and admission.skill, whose scanner gate outranks the defaults."""
    if policy_name is None and not asset_lists.is_secure_client(app.cfg):
        _edit_live_actions(app, "defaults", severity, runtime, file_action, install, reload_gateway)
        return
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

    synced = _save_policy_edit(app, path, data, name)
    ux.ok(f"Updated {severity.upper()} actions of {_edited_policy_label(name)}: {', '.join(changed)}")
    _reload_after_edit(app, name, synced=synced, reload_gateway=reload_gateway)


@edit.command("scanner")
@click.option("--type", "scanner_type", required=True, type=click.Choice(["skill", "mcp", "plugin"]),
              help="Asset type to override")
@click.option("--severity", "-s", required=True, type=click.Choice(SEVERITIES),
              help="Severity level to configure")
@click.option("--runtime", type=click.Choice(RUNTIME_CHOICES), default=None,
              help="Turn a finding at this severity off (disable) or leave it running (enable)")
@click.option("--file", "file_action", type=click.Choice(FILE_CHOICES), default=None,
              help="Quarantine the files of a finding at this severity, or leave them (none)")
@click.option("--install", type=click.Choice(INSTALL_CHOICES), default=None,
              help="Block or allow installing an item with a finding at this severity (none: no rule)")
@click.option("--remove", is_flag=True, help="Remove this override (revert to the inherited action)")
@_policy_name_option
@_reload_option
@pass_ctx
def edit_scanner(app: AppContext, scanner_type: str, severity: str, runtime: str | None,
                 file_action: str | None, install: str | None, remove: bool,
                 policy_name: str | None, reload_gateway: bool) -> None:
    """Edit one asset type's severity actions (admission.<type>.actions)."""
    if policy_name is None and not asset_lists.is_secure_client(app.cfg):
        if remove:
            actions = getattr(app.cfg.admission, scanner_type).actions
            if severity not in actions:
                click.echo(f"No override found for {scanner_type}/{severity.upper()}.")
                return
            del actions[severity]
            app.cfg.save()
            ux.ok(f"Removed admission.{scanner_type}.actions.{severity}.")
            _reload_after_edit(app, "live", synced=True, reload_gateway=reload_gateway)
            return
        _edit_live_actions(app, scanner_type, severity, runtime, file_action, install, reload_gateway)
        return
    path, data, name = _resolve_editable_policy(app, policy_name)

    overrides = data.setdefault("scanner_overrides", {})

    if remove:
        scanner_ovr = overrides.get(scanner_type, {})
        if severity in scanner_ovr:
            del scanner_ovr[severity]
            if not scanner_ovr:
                del overrides[scanner_type]
            synced = _save_policy_edit(app, path, data, name)
            ux.ok(f"Removed {scanner_type}/{severity.upper()} override from {_edited_policy_label(name)}.")
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

    synced = _save_policy_edit(app, path, data, name)
    ux.ok(
        f"Updated scanner override {scanner_type}/{severity.upper()} in {_edited_policy_label(name)}: "
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
@_policy_name_option
@_reload_option
@pass_ctx
def edit_guardrail(app: AppContext, block_threshold: int | None, alert_threshold: int | None,
                   cisco_trust_level: str | None, policy_name: str | None, reload_gateway: bool) -> None:
    """Edit guardrail thresholds and the Cisco AI Defense trust level.

    Thresholds are severities: LOW, MEDIUM, HIGH or CRITICAL (or their
    ranks 1-4). A live edit writes guardrail.block_at / alert_at and
    guardrail.cisco_trust_level in config.yaml.
    """
    if policy_name is None and not asset_lists.is_secure_client(app.cfg):
        changed = []
        if block_threshold is not None:
            app.cfg.guardrail.block_at = _RANK_NAMES[block_threshold]
            changed.append(f"block_at={app.cfg.guardrail.block_at}")
        if alert_threshold is not None:
            app.cfg.guardrail.alert_at = _RANK_NAMES[alert_threshold]
            changed.append(f"alert_at={app.cfg.guardrail.alert_at}")
        if cisco_trust_level is not None:
            app.cfg.guardrail.cisco_trust_level = "" if cisco_trust_level == "full" else cisco_trust_level
            changed.append(f"cisco_trust_level={cisco_trust_level}")
        if not changed:
            click.echo("No changes specified.")
            return
        app.cfg.save()
        ux.ok(f"Guardrail updated: {', '.join(changed)}")
        _reload_after_edit(app, "live", synced=True, reload_gateway=reload_gateway)
        return
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

    if not changed:
        click.echo("No changes specified.")
        return

    synced = _save_policy_edit(app, path, data, name)
    ux.ok(f"Guardrail of {_edited_policy_label(name)} updated: {', '.join(changed)}")
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
@click.option("--policy-name", "-p", required=True, help="Named policy (preset) to edit")
@pass_ctx
def edit_firewall(app: AppContext, default_action: str | None, add_domain: tuple,
                  remove_domain: tuple, add_blocked: tuple, remove_blocked: tuple,
                  add_port: tuple, remove_port: tuple, policy_name: str) -> None:
    """Edit a named policy's egress firewall rules (domains, ports, blocked
    destinations). The gateway does not enforce them; OpenShell sandboxes use
    openshell: in config.yaml."""
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

    _save_policy_edit(app, path, data, name)
    ux.ok(f"Firewall of {_edited_policy_label(name)} updated: {', '.join(changed)}")


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
        },
        "firewall": {
            "default_action": "deny",
            "blocked_destinations": ["169.254.169.254", "fd00:ec2::254"],
            "allowed_domains": [],
            "allowed_ports": [443, 80],
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
    """Resolve the named policy to edit. Returns ``(path, data, name)``.

    ``path`` is always a writable location under the user policy dir:
    editing a built-in copies it out of the bundled wheel dir first
    (copy-on-write, OTHER-4) so we never write back into site-packages,
    which is lost on upgrade and may be read-only. Raises ``SystemExit(1)``
    when the policy can't be found.
    """
    if policy_name is None and asset_lists.is_secure_client(app.cfg):
        policy_name = _get_active_policy_name(app)
        if not policy_name:
            raise click.ClickException("Secure Client active policy not found in data.json")
    name = _sanitize_policy_name(policy_name)
    path = _find_policy(app, name)
    if not path:
        _policy_not_found(app, policy_name)

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


def _get_active_policy_name(app: AppContext) -> str | None:
    """Secure Client stores the live preset name in its v8 OPA data."""
    path = os.path.join(app.cfg.policy_dir, "rego", "data.json")
    try:
        with open(path) as f:
            data = json.load(f)
        return data.get("config", {}).get("policy_name")
    except (OSError, ValueError, AttributeError):
        return None


def _save_policy_edit(app: AppContext, path: str, data: dict, name: str) -> bool:
    """A Secure Client edit of its active preset must update the legacy OPA data."""
    if not asset_lists.is_secure_client(app.cfg):
        _save_draft(path, data, name)
        return False
    active = _get_active_policy_name(app)
    if active == name:
        # Check the target before saving the YAML, so a missing data file
        # cannot leave a seemingly applied edit behind.
        _sync_opa_data(app, data)
        _save_policy(path, data)
        return True
    _save_draft(path, data, name)
    return False


def _save_draft(path: str, data: dict, name: str) -> None:
    """Persist an edited named policy; activation applies it to config.yaml."""
    _save_policy(path, data)
    click.echo(
        f"  {ux.dim('Saved. Apply it with:')} "
        f"defenseclaw policy activate {name}"
    )


def _reload_after_edit(
    app: AppContext, name: str, *, synced: bool, reload_gateway: bool, needs_restart: bool = False
) -> None:
    """After a live edit, reload like ``policy activate``."""
    if synced and reload_gateway:
        _reload_and_report(app, name, needs_restart=needs_restart)


def _edited_policy_label(name: str) -> str:
    """"policy 'strict'": the result line of an edit names the policy it changed (GAP-1667)."""
    return f"policy '{name}'"


def _opa_runtime_action(runtime: str) -> str:
    """Map a policy ``runtime`` value to the OPA ``data.json`` vocabulary.

    Policy YAML may use either the enforcement vocabulary
    (``enable``/``disable``) or the OPA vocabulary (``allow``/``block``).
    Both ``disable`` and ``block`` mean "do not allow runtime execution"
    and must map to ``block``; ``enable``/``allow`` map to ``allow``.
    Unknown values are rejected before activation. The previous
    ``"block" if runtime == "disable" else "allow"`` silently rewrote an
    existing ``runtime: block`` override to ``allow`` (F-0241), so a
    bundled override meant to block runtime execution was synced as an
    allow.
    """
    value = str(runtime).strip().lower()
    if value not in {"disable", "block", "enable", "allow"}:
        raise click.ClickException(f"invalid runtime action {runtime!r}")
    return "block" if value in ("disable", "block") else "allow"


def _prepare_opa_data(app: AppContext, policy_data: dict) -> tuple[str, dict]:
    """Prepare OPA data.json from a named policy without changing the file.

    This performs a complete sync of all policy dimensions:
    - config (admission settings, enforcement)
    - actions (with install field)
    - scanner_overrides
    - guardrail (thresholds, HILT, patterns, severity_mappings)
    - firewall (domains, ports, blocked destinations)
    - audit (retention, logging flags)

    Writes to the Secure Client user's policy_dir, which the gateway reads.
    A missing file is an error because this branch no longer bundles v8 data.
    """
    user_rego_dir = os.path.join(app.cfg.policy_dir, "rego")
    user_data_json = os.path.join(user_rego_dir, "data.json")
    if os.path.isfile(user_data_json):
        data_json_path = user_data_json
    else:
        raise click.ClickException(
            f"Secure Client OPA data file not found at {user_data_json}; "
            "run `defenseclaw policy validate` and repair before activating"
        )

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

    if not isinstance(opa_data, dict):
        raise click.ClickException(f"OPA data file at {data_json_path} must contain an object")
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

    return data_json_path, opa_data


def _write_opa_data(path: str, data: dict) -> None:
    """Replace legacy OPA data atomically, preserving its file mode."""
    mode = os.stat(path).st_mode & 0o777
    fd, staged = tempfile.mkstemp(prefix=".data-", suffix=".json", dir=os.path.dirname(path))
    try:
        os.chmod(staged, mode)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def _sync_opa_data(app: AppContext, policy_data: dict) -> None:
    """Sync legacy OPA data for an active policy edit."""
    _write_opa_data(*_prepare_opa_data(app, policy_data))


def _validate_legacy_data(rego_dir: str) -> bool:
    """Validate the Secure Client v8 OPA data that its gateway still loads."""
    path = os.path.join(rego_dir, "data.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        ux.err(f"FAIL: data.json is missing or invalid at {path}: {exc}")
        return False
    if not isinstance(data, dict):
        ux.err("FAIL: data.json must contain an object")
        return False
    errors = [f"missing {key}" for key in ("config", "actions", "severity_ranking") if key not in data]
    for section in ("actions", "scanner_overrides"):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            errors.append(f"{section} must be an object")
            continue
        if section == "scanner_overrides":
            entries = {f"{kind}.{sev}": action for kind, group in entries.items()
                       for sev, action in (group.items() if isinstance(group, dict) else [("", group)])}
        for name, action in entries.items():
            if not isinstance(action, dict):
                errors.append(f"{section}.{name} must be an object")
                continue
            for field, choices in (
                ("runtime", {"block", "allow"}),
                ("file", {"quarantine", "none"}),
                ("install", {"block", "allow", "none"}),
            ):
                if field == "install" and field not in action:
                    continue
                if action.get(field) not in choices:
                    errors.append(f"{section}.{name}.{field} is invalid")
    if errors:
        for error in errors:
            ux.err(f"FAIL: data.json {error}")
        return False
    ux.ok("data.json: OK")
    return True


def _has_rego_tests(rego_dir: str) -> bool:
    """True when rego_dir (recursively, like 'opa test') holds a *_test.rego."""
    for _root, _dirs, files in os.walk(rego_dir):
        if any(f.endswith("_test.rego") for f in files):
            return True
    return False


def _rego_tool_cmd(opa_args: list[str], gateway_args: list[str], *, gateway_first: bool = False) -> list[str] | None:
    """Return the argv for a Rego check: 'opa' when installed, else the gateway.

    defenseclaw-gateway embeds OPA (``policy validate`` / ``policy test``), so
    a standard install can validate and test Rego without a separate 'opa'
    binary (GAP-1091). ``gateway_first`` picks the gateway whenever it is
    installed: its ``policy validate`` is the loader the gateway runs, which
    also refuses a module that reads data config_version 9 no longer
    provides (data.config, data.actions), where 'opa check' accepts any data
    reference. Returns None when neither is available.
    """
    import shutil

    from defenseclaw.gateway import resolve_gateway_binary

    opa = shutil.which("opa")
    gateway = resolve_gateway_binary() if gateway_first or not opa else None
    if gateway:
        return [gateway, *gateway_args]
    if opa:
        return [opa, *opa_args]
    return None


def _try_rego_compile(rego_dir: str, cfg=None) -> bool:
    """Try to compile Rego modules. Returns True on success.

    The gateway gives the verdict when it is installed, so a module the
    gateway refuses never passes here; a Secure Client host keeps the 'opa'
    first order of main (issue #1092).
    """
    rego_files = [
        os.path.join(rego_dir, f) for f in os.listdir(rego_dir)
        if f.endswith(".rego") and not f.endswith("_test.rego")
    ]
    if not rego_files:
        ux.err("FAIL: no .rego files found")
        return False

    cmd = _rego_tool_cmd(
        ["check", "--strict", *rego_files],
        ["policy", "validate", "--rego-dir", rego_dir],
        gateway_first=not asset_lists.is_secure_client(cfg),
    )
    if cmd is None:
        # A missing checker must not turn into a clean "Rego compilation: OK"
        # verdict, so the default fails closed. Operators can opt out with
        # DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA=1.
        from defenseclaw.envvars import lookup

        if (lookup("DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA") or "").strip() == "1":
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
