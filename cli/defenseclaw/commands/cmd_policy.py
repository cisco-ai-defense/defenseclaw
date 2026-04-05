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
from pathlib import Path

import click
import yaml

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


def _ensure_policies_dir(app: AppContext) -> str:
    d = _policies_dir(app)
    os.makedirs(d, exist_ok=True)
    return d


def _list_policy_files(app: AppContext) -> list[str]:
    """Return paths to all .yaml policy files (user dir + bundled)."""
    files: list[str] = []
    user_dir = _policies_dir(app)
    if os.path.isdir(user_dir):
        for name in os.listdir(user_dir):
            if name.endswith(".yaml") and not name.startswith("."):
                files.append(os.path.join(user_dir, name))

    bundled = _bundled_policies_dir()
    if os.path.isdir(bundled):
        seen = {os.path.basename(f) for f in files}
        for name in os.listdir(bundled):
            if name.endswith(".yaml") and not name.startswith(".") and name not in seen:
                files.append(os.path.join(bundled, name))

    return sorted(files)


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


def _find_policy(app: AppContext, name: str) -> str | None:
    """Find a policy file by name (without .yaml extension)."""
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


def _find_active_policy_path(app: AppContext) -> str | None:
    """Find the path to the currently active policy."""
    name = _get_active_policy_name(app)
    if name:
        return _find_policy(app, name)
    return None


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
@click.option("--scan-on-install/--no-scan-on-install", default=True,
              help="Scan on install (default: true)")
@click.option("--allow-list-bypass/--no-allow-list-bypass", default=True,
              help="Allow-listed items skip scan (default: true)")
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
    scan_on_install: bool,
    allow_list_bypass: bool,
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

    data.setdefault("admission", {})
    data["admission"]["scan_on_install"] = scan_on_install
    data["admission"]["allow_list_bypass_scan"] = allow_list_bypass

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

    click.secho(f"Policy '{name}' created at {dest}", fg="green")
    click.echo(f"  Activate with: defenseclaw policy activate {name}")

    if app.logger:
        app.logger.log_action("policy-create", name, f"path={dest}")


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@policy.command("list")
@pass_ctx
def list_policies(app: AppContext) -> None:
    """List all available policies (built-in and custom)."""
    files = _list_policy_files(app)

    if not files:
        click.echo("No policies found.")
        return

    active = _get_active_policy_name(app)

    click.echo("Available policies:")
    click.echo()
    for path in files:
        data = _load_policy(path)
        pname = data.get("name", Path(path).stem)
        desc = data.get("description", "")
        is_builtin = path.startswith(_bundled_policies_dir())
        is_active = pname == active

        prefix = "  * " if is_active else "    "
        label = click.style(pname, bold=True)
        tag = ""
        if is_builtin:
            tag = click.style(" [built-in]", dim=True)
        if is_active:
            tag += click.style(" [active]", fg="green")

        click.echo(f"{prefix}{label}{tag}")
        if desc:
            click.echo(f"      {desc}")

    click.echo()
    click.echo("  Activate a policy: defenseclaw policy activate <name>")
    click.echo("  Show details:      defenseclaw policy show <name>")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("name")
@pass_ctx
def show(app: AppContext, name: str) -> None:
    """Show details of a policy."""
    path = _find_policy(app, name)
    if not path:
        click.echo(f"error: policy '{name}' not found", err=True)
        raise SystemExit(1)

    data = _load_policy(path)
    pname = data.get("name", name)
    desc = data.get("description", "")

    click.secho(f"Policy: {pname}", bold=True)
    if desc:
        click.echo(f"  {desc}")
    click.echo()

    admission = data.get("admission", {})
    click.echo("Admission:")
    click.echo(f"  scan_on_install:        {admission.get('scan_on_install', True)}")
    click.echo(f"  allow_list_bypass_scan: {admission.get('allow_list_bypass_scan', True)}")
    click.echo()

    click.echo("Severity Actions:")
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

        click.echo(f"  {sev.upper():10s}  ", nl=False)
        click.secho(f"install={install_a:5s}  file={file_a:10s}  runtime={runtime_a}", fg=color)

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
        click.echo(f"  block_threshold:    {guardrail.get('block_threshold', 3)} (severity rank)")
        click.echo(f"  alert_threshold:    {guardrail.get('alert_threshold', 2)} (severity rank)")
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

@policy.command()
@click.argument("name")
@pass_ctx
def activate(app: AppContext, name: str) -> None:
    """Activate a policy — applies it to config.yaml and syncs OPA data.json."""
    path = _find_policy(app, name)
    if not path:
        click.echo(f"error: policy '{name}' not found", err=True)
        raise SystemExit(1)

    data = _load_policy(path)

    actions_raw = data.get("skill_actions", {})

    from defenseclaw.config import (
        SeverityAction,
        SkillActionsConfig,
    )

    def _parse_action(raw: dict) -> SeverityAction:
        return SeverityAction(
            file=raw.get("file", "none"),
            runtime=raw.get("runtime", "enable"),
            install=raw.get("install", "none"),
        )

    new_actions = SkillActionsConfig(
        critical=_parse_action(actions_raw.get("critical", {})),
        high=_parse_action(actions_raw.get("high", {})),
        medium=_parse_action(actions_raw.get("medium", {})),
        low=_parse_action(actions_raw.get("low", {})),
        info=_parse_action(actions_raw.get("info", {})),
    )

    app.cfg.skill_actions = new_actions
    app.cfg.save()
    click.echo(f"Config updated with policy '{name}'.")

    _sync_opa_data(app, data)

    click.secho(f"Policy '{name}' activated.", fg="green")
    if app.logger:
        app.logger.log_action("policy-activate", name, f"source={path}")


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@policy.command()
@click.argument("name")
@pass_ctx
def delete(app: AppContext, name: str) -> None:
    """Delete a custom policy."""
    if name in BUILTIN_POLICIES:
        click.echo(f"error: cannot delete built-in policy '{name}'", err=True)
        raise SystemExit(1)

    user_dir = _policies_dir(app)
    path = os.path.join(user_dir, f"{name}.yaml")
    if not os.path.isfile(path):
        click.echo(f"error: policy '{name}' not found in {user_dir}", err=True)
        raise SystemExit(1)

    os.remove(path)
    click.echo(f"Policy '{name}' deleted.")
    if app.logger:
        app.logger.log_action("policy-delete", name, "")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

@policy.command()
@click.option("--rego-dir", default=None, help="Path to rego directory (default: bundled policies/rego)")
@pass_ctx
def validate(app: AppContext, rego_dir: str | None) -> None:
    """Validate OPA Rego modules and data.json schema.

    Checks:\n
      1. data.json is valid JSON with required top-level keys\n
      2. All severity levels in actions and scanner_overrides have valid fields\n
      3. Rego modules compile without errors (requires 'opa' binary or Go daemon)
    """
    rd = rego_dir or _rego_dir()
    errors: list[str] = []

    # 1. Validate data.json
    data_json_path = os.path.join(rd, "data.json")
    if not os.path.isfile(data_json_path):
        click.secho(f"FAIL: data.json not found at {data_json_path}", fg="red")
        raise SystemExit(1)

    try:
        with open(data_json_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        click.secho(f"FAIL: data.json is not valid JSON: {exc}", fg="red")
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
        click.secho("data.json validation errors:", fg="red")
        for e in errors:
            click.echo(f"  - {e}")
    else:
        click.secho("data.json: OK", fg="green")

    # 2. Try to compile Rego
    rego_compiled = _try_rego_compile(rd)

    if errors or not rego_compiled:
        raise SystemExit(1)

    click.secho("All validations passed.", fg="green")


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

@policy.command("test")
@click.option("--rego-dir", default=None, help="Path to rego directory (default: bundled policies/rego)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose test output")
@pass_ctx
def test_rego(app: AppContext, rego_dir: str | None, verbose: bool) -> None:
    """Run OPA Rego unit tests.

    Requires 'opa' binary on PATH. Install: https://www.openpolicyagent.org/docs/latest/#running-opa
    """
    rd = rego_dir or _rego_dir()

    if not os.path.isdir(rd):
        click.secho(f"error: rego directory not found: {rd}", fg="red", err=True)
        raise SystemExit(1)

    cmd = ["opa", "test", rd]
    if verbose:
        cmd.append("-v")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        click.secho("error: 'opa' binary not found on PATH", fg="red", err=True)
        click.echo("  Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa", err=True)
        click.echo("  Or: brew install opa", err=True)
        raise SystemExit(1)
    except subprocess.TimeoutExpired:
        click.secho("error: opa test timed out after 60s", fg="red", err=True)
        raise SystemExit(1)

    if result.stdout:
        click.echo(result.stdout.rstrip())
    if result.stderr:
        click.echo(result.stderr.rstrip(), err=True)

    if result.returncode != 0:
        click.secho("Tests FAILED.", fg="red")
        raise SystemExit(result.returncode)

    click.secho("All Rego tests passed.", fg="green")


# ---------------------------------------------------------------------------
# edit — structured editing of policy sections
# ---------------------------------------------------------------------------

@policy.group()
def edit() -> None:
    """Edit policy sections (guardrail, firewall, scanner, actions)."""


@edit.command("actions")
@click.option("--severity", "-s", required=True, type=click.Choice(SEVERITIES),
              help="Severity level to configure")
@click.option("--runtime", type=click.Choice(RUNTIME_CHOICES), default=None)
@click.option("--file", "file_action", type=click.Choice(FILE_CHOICES), default=None)
@click.option("--install", type=click.Choice(INSTALL_CHOICES), default=None)
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@pass_ctx
def edit_actions(app: AppContext, severity: str, runtime: str | None, file_action: str | None,
                 install: str | None, policy_name: str | None) -> None:
    """Edit severity actions for the global policy."""
    path, data = _resolve_editable_policy(app, policy_name)

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

    _save_policy(path, data)
    _sync_opa_data(app, data)
    click.secho(f"Updated {severity.upper()}: {', '.join(changed)}", fg="green")


@edit.command("scanner")
@click.option("--type", "scanner_type", required=True, type=click.Choice(["skill", "mcp", "plugin"]),
              help="Scanner type to override")
@click.option("--severity", "-s", required=True, type=click.Choice(SEVERITIES),
              help="Severity level to configure")
@click.option("--runtime", type=click.Choice(RUNTIME_CHOICES), default=None)
@click.option("--file", "file_action", type=click.Choice(FILE_CHOICES), default=None)
@click.option("--install", type=click.Choice(INSTALL_CHOICES), default=None)
@click.option("--remove", is_flag=True, help="Remove this override (revert to global)")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@pass_ctx
def edit_scanner(app: AppContext, scanner_type: str, severity: str, runtime: str | None,
                 file_action: str | None, install: str | None, remove: bool,
                 policy_name: str | None) -> None:
    """Edit per-scanner-type severity overrides."""
    path, data = _resolve_editable_policy(app, policy_name)

    overrides = data.setdefault("scanner_overrides", {})

    if remove:
        scanner_ovr = overrides.get(scanner_type, {})
        if severity in scanner_ovr:
            del scanner_ovr[severity]
            if not scanner_ovr:
                del overrides[scanner_type]
            _save_policy(path, data)
            _sync_opa_data(app, data)
            click.secho(f"Removed {scanner_type}/{severity.upper()} override.", fg="green")
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

    _save_policy(path, data)
    _sync_opa_data(app, data)
    click.secho(f"Updated scanner override {scanner_type}/{severity.upper()}: {', '.join(changed)}", fg="green")


@edit.command("guardrail")
@click.option("--block-threshold", type=int, default=None,
              help="Minimum severity rank to block (1=LOW .. 4=CRITICAL)")
@click.option("--alert-threshold", type=int, default=None,
              help="Minimum severity rank to alert (1=LOW .. 4=CRITICAL)")
@click.option("--cisco-trust-level", type=click.Choice(["full", "advisory", "none"]), default=None)
@click.option("--add-pattern", nargs=2, multiple=True, metavar="CATEGORY PATTERN",
              help="Add a guardrail pattern (e.g. --add-pattern injection 'new pattern')")
@click.option("--remove-pattern", nargs=2, multiple=True, metavar="CATEGORY PATTERN",
              help="Remove a guardrail pattern")
@click.option("--set-severity-mapping", nargs=2, multiple=True, metavar="CATEGORY SEVERITY",
              help="Set severity mapping (e.g. --set-severity-mapping injection CRITICAL)")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@pass_ctx
def edit_guardrail(app: AppContext, block_threshold: int | None, alert_threshold: int | None,
                   cisco_trust_level: str | None, add_pattern: tuple, remove_pattern: tuple,
                   set_severity_mapping: tuple, policy_name: str | None) -> None:
    """Edit guardrail thresholds, patterns, and severity mappings."""
    path, data = _resolve_editable_policy(app, policy_name)

    guardrail = data.setdefault("guardrail", {})
    changed = []

    if block_threshold is not None:
        guardrail["block_threshold"] = block_threshold
        changed.append(f"block_threshold={block_threshold}")
    if alert_threshold is not None:
        guardrail["alert_threshold"] = alert_threshold
        changed.append(f"alert_threshold={alert_threshold}")
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

    _save_policy(path, data)
    _sync_opa_data(app, data)
    click.secho(f"Guardrail updated: {', '.join(changed)}", fg="green")


@edit.command("firewall")
@click.option("--default-action", type=click.Choice(["allow", "deny"]), default=None)
@click.option("--add-domain", multiple=True, help="Add an allowed domain")
@click.option("--remove-domain", multiple=True, help="Remove an allowed domain")
@click.option("--add-blocked", multiple=True, help="Add a blocked destination (IP/host)")
@click.option("--remove-blocked", multiple=True, help="Remove a blocked destination")
@click.option("--add-port", multiple=True, type=int, help="Add an allowed port")
@click.option("--remove-port", multiple=True, type=int, help="Remove an allowed port")
@click.option("--policy-name", "-p", default=None, help="Policy to edit (default: active policy)")
@pass_ctx
def edit_firewall(app: AppContext, default_action: str | None, add_domain: tuple,
                  remove_domain: tuple, add_blocked: tuple, remove_blocked: tuple,
                  add_port: tuple, remove_port: tuple, policy_name: str | None) -> None:
    """Edit egress firewall rules (domains, ports, blocked destinations)."""
    path, data = _resolve_editable_policy(app, policy_name)

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

    _save_policy(path, data)
    _sync_opa_data(app, data)
    click.secho(f"Firewall updated: {', '.join(changed)}", fg="green")


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
            "block_threshold": 3,
            "alert_threshold": 2,
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


def _resolve_editable_policy(app: AppContext, policy_name: str | None) -> tuple[str, dict]:
    """Resolve the policy to edit. Returns (path, data). Raises SystemExit if not found."""
    if policy_name:
        path = _find_policy(app, policy_name)
        if not path:
            click.echo(f"error: policy '{policy_name}' not found", err=True)
            raise SystemExit(1)
        if policy_name in BUILTIN_POLICIES and path.startswith(_bundled_policies_dir()):
            click.echo(f"warning: editing built-in policy '{policy_name}' in-place", err=True)
    else:
        path = _find_active_policy_path(app)
        if not path:
            click.echo(
                "error: no active policy found. Activate one first: defenseclaw policy activate <name>",
                err=True,
            )
            raise SystemExit(1)

    return path, _load_policy(path)


def _sync_opa_data(app: AppContext, policy_data: dict) -> None:
    """Sync OPA data.json with the activated policy settings.

    This performs a complete sync of all policy dimensions:
    - config (admission settings, enforcement)
    - actions (with install field)
    - scanner_overrides
    - guardrail (thresholds, patterns, severity_mappings)
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
    except (OSError, json.JSONDecodeError):
        return

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
        opa_runtime = "block" if runtime == "disable" else "allow"
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
            opa_runtime = "block" if runtime == "disable" else "allow"
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
                     "patterns", "severity_mappings"):
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

    click.echo(f"OPA data.json synced at {data_json_path}")


def _try_rego_compile(rego_dir: str) -> bool:
    """Try to compile Rego modules. Returns True on success."""
    # Try opa binary first
    try:
        rego_files = [
            os.path.join(rego_dir, f) for f in os.listdir(rego_dir)
            if f.endswith(".rego") and not f.endswith("_test.rego")
        ]
        if not rego_files:
            click.secho("FAIL: no .rego files found", fg="red")
            return False

        cmd = ["opa", "check", "--strict"] + rego_files
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            click.secho(f"Rego compilation: OK ({len(rego_files)} modules)", fg="green")
            return True
        else:
            click.secho("Rego compilation errors:", fg="red")
            if result.stderr:
                click.echo(result.stderr.rstrip())
            if result.stdout:
                click.echo(result.stdout.rstrip())
            return False
    except FileNotFoundError:
        click.echo("  'opa' binary not found — skipping Rego compilation check.")
        click.echo("  Install OPA for full validation: brew install opa")
        return True
    except subprocess.TimeoutExpired:
        click.secho("FAIL: opa check timed out", fg="red")
        return False
