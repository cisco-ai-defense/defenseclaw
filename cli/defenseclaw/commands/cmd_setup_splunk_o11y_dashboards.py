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

"""defenseclaw setup splunk dashboards — manage O11y dashboards.

This command is intentionally a thin Terraform driver. It copies the bundled
Terraform module into the user's DefenseClaw data directory, resolves the
Splunk Observability Cloud API URL from config or environment, and requires an
explicit Splunk O11y API token for Terraform via ``TF_VAR_*`` rather than
command-line arguments.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import click
import requests

from defenseclaw import ux
from defenseclaw.context import AppContext
from defenseclaw.paths import bundled_splunk_o11y_dashboards_terraform_dir

_DEFAULT_WORK_SUBDIR = "splunk-o11y-dashboards"

_DASHBOARD_SPECS = (
    ("executive", "Executive Agent Watch"),
    ("guardrail_inspection", "Guardrail and Inspection"),
    ("connector_ingest", "Connector and OTel Ingest"),
    ("security_policy", "Security and Policy"),
    ("token_economics", "DefenseClaw AI Agents Token Economics"),
    ("runtime_reliability", "Runtime and Reliability"),
    ("scanners_findings", "Scanners and Findings"),
)


@click.group(
    "dashboards",
    short_help="Create/update Splunk Observability Cloud dashboards.",
)
def splunk_o11y_dashboards() -> None:
    """Create or update DefenseClaw Splunk Observability Cloud dashboards.

    The command uses the Terraform bundle shipped with DefenseClaw and stores
    Terraform working files under ``~/.defenseclaw/splunk-o11y-dashboards`` by
    default. Re-running from the same state path updates the same O11y objects.
    """


def _dashboard_options(func):
    func = click.option(
        "--timeout",
        type=int,
        default=900,
        show_default=True,
        help="Timeout in seconds for each Terraform subprocess.",
    )(func)
    func = click.option(
        "--skip-validate",
        is_flag=True,
        help="Skip `terraform validate` after init.",
    )(func)
    func = click.option(
        "--skip-init",
        is_flag=True,
        help="Skip `terraform init` in the working directory.",
    )(func)
    func = click.option(
        "--plugin-dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
        default=None,
        envvar="DEFENSECLAW_TERRAFORM_PLUGIN_DIR",
        help="Optional Terraform provider plugin directory for offline/cached provider installs.",
    )(func)
    func = click.option(
        "--terraform-bin",
        default="terraform",
        show_default=True,
        envvar="TERRAFORM_BIN",
        help="Terraform executable to run.",
    )(func)
    func = click.option(
        "--state",
        "state_path",
        type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
        default=None,
        help="Terraform state file path. Defaults under the DefenseClaw data directory.",
    )(func)
    func = click.option(
        "--work-dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
        default=None,
        envvar="DEFENSECLAW_SPLUNK_O11Y_DASHBOARDS_WORK_DIR",
        help="Terraform working directory. Defaults under the DefenseClaw data directory.",
    )(func)
    func = click.option(
        "--detector-notification",
        "detector_notifications",
        multiple=True,
        help='Detector notification target, e.g. "Email,secops@example.com". Repeatable.',
    )(func)
    func = click.option(
        "--enable-detectors",
        is_flag=True,
        help="Create detector rules enabled. By default created detectors are disabled.",
    )(func)
    func = click.option(
        "--with-detectors/--dashboards-only",
        "with_detectors",
        default=False,
        show_default=True,
        help="Create Splunk detectors in addition to dashboards.",
    )(func)
    func = click.option(
        "--name-prefix",
        default="",
        envvar="DEFENSECLAW_O11Y_DASHBOARD_NAME_PREFIX",
        help="Label dashboard groups, dashboards, and detectors. Useful for smoke tests.",
    )(func)
    func = click.option(
        "--o11y-api-token",
        default=None,
        envvar="SFX_AUTH_TOKEN",
        help=(
            "Splunk O11y API access token. Prefer the SFX_AUTH_TOKEN "
            "environment variable so the secret never appears in shell "
            "history or process listings."
        ),
    )(func)
    func = click.option(
        "--api-url",
        default=None,
        envvar="SFX_API_URL",
        help="Splunk O11y API URL. Defaults from SFX_API_URL or the configured OTLP ingest realm.",
    )(func)
    return func


@splunk_o11y_dashboards.command("plan")
@_dashboard_options
@click.pass_context
def plan_cmd(
    ctx: click.Context,
    api_url: str | None,
    o11y_api_token: str | None,
    name_prefix: str,
    with_detectors: bool,
    enable_detectors: bool,
    detector_notifications: tuple[str, ...],
    work_dir: Path | None,
    state_path: Path | None,
    terraform_bin: str,
    plugin_dir: Path | None,
    skip_init: bool,
    skip_validate: bool,
    timeout: int,
) -> None:
    """Show Terraform changes for the O11y dashboard bundle."""
    prepared = _prepare_run(
        ctx.find_object(AppContext),
        api_url=api_url,
        o11y_api_token=o11y_api_token,
        name_prefix=name_prefix,
        with_detectors=with_detectors,
        enable_detectors=enable_detectors,
        detector_notifications=detector_notifications,
        work_dir=work_dir,
        state_path=state_path,
    )
    _run_init_validate(
        prepared,
        terraform_bin=terraform_bin,
        plugin_dir=plugin_dir,
        skip_init=skip_init,
        skip_validate=skip_validate,
        timeout=timeout,
    )
    _adopt_existing_resources(prepared, terraform_bin=terraform_bin, timeout=timeout)
    _run_terraform(
        terraform_bin,
        ["plan", "-input=false", f"-state={prepared.state_path}"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )


@splunk_o11y_dashboards.command("apply")
@_dashboard_options
@click.option(
    "--yes",
    is_flag=True,
    help="Apply without an additional confirmation prompt.",
)
@click.pass_context
def apply_cmd(
    ctx: click.Context,
    yes: bool,
    api_url: str | None,
    o11y_api_token: str | None,
    name_prefix: str,
    with_detectors: bool,
    enable_detectors: bool,
    detector_notifications: tuple[str, ...],
    work_dir: Path | None,
    state_path: Path | None,
    terraform_bin: str,
    plugin_dir: Path | None,
    skip_init: bool,
    skip_validate: bool,
    timeout: int,
) -> None:
    """Create or update the O11y dashboards."""
    apply_dashboards(
        ctx.find_object(AppContext),
        api_url=api_url,
        o11y_api_token=o11y_api_token,
        name_prefix=name_prefix,
        with_detectors=with_detectors,
        enable_detectors=enable_detectors,
        detector_notifications=detector_notifications,
        work_dir=work_dir,
        state_path=state_path,
        terraform_bin=terraform_bin,
        plugin_dir=plugin_dir,
        skip_init=skip_init,
        skip_validate=skip_validate,
        timeout=timeout,
        yes=yes,
    )


@splunk_o11y_dashboards.command("destroy")
@_dashboard_options
@click.option(
    "--yes",
    is_flag=True,
    help="Destroy without an additional confirmation prompt.",
)
@click.pass_context
def destroy_cmd(
    ctx: click.Context,
    yes: bool,
    api_url: str | None,
    o11y_api_token: str | None,
    name_prefix: str,
    with_detectors: bool,
    enable_detectors: bool,
    detector_notifications: tuple[str, ...],
    work_dir: Path | None,
    state_path: Path | None,
    terraform_bin: str,
    plugin_dir: Path | None,
    skip_init: bool,
    skip_validate: bool,
    timeout: int,
) -> None:
    """Destroy O11y objects managed by the selected Terraform state."""
    prepared = _prepare_run(
        ctx.find_object(AppContext),
        api_url=api_url,
        o11y_api_token=o11y_api_token,
        name_prefix=name_prefix,
        with_detectors=with_detectors,
        enable_detectors=enable_detectors,
        detector_notifications=detector_notifications,
        work_dir=work_dir,
        state_path=state_path,
    )
    _run_init_validate(
        prepared,
        terraform_bin=terraform_bin,
        plugin_dir=plugin_dir,
        skip_init=skip_init,
        skip_validate=skip_validate,
        timeout=timeout,
    )
    _run_terraform(
        terraform_bin,
        ["plan", "-destroy", "-input=false", f"-state={prepared.state_path}"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )
    if not yes:
        click.confirm("Destroy these Splunk Observability Cloud objects?", abort=True)
    _run_terraform(
        terraform_bin,
        ["destroy", "-input=false", "-auto-approve", f"-state={prepared.state_path}"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )


class _PreparedRun:
    def __init__(
        self,
        work_dir: Path,
        state_path: Path,
        env: dict[str, str],
        *,
        name_prefix: str,
        with_detectors: bool,
    ) -> None:
        self.work_dir = work_dir
        self.state_path = state_path
        self.env = env
        self.name_prefix = name_prefix
        self.with_detectors = with_detectors


def _prepare_run(
    app: AppContext | None,
    *,
    api_url: str | None,
    o11y_api_token: str | None,
    name_prefix: str,
    with_detectors: bool,
    enable_detectors: bool,
    detector_notifications: tuple[str, ...],
    work_dir: Path | None,
    state_path: Path | None,
) -> _PreparedRun:
    data_dir = _resolve_data_dir(app)
    resolved_work_dir = (work_dir or data_dir / _DEFAULT_WORK_SUBDIR / "terraform").expanduser()
    resolved_state_path = (state_path or data_dir / _DEFAULT_WORK_SUBDIR / "terraform.tfstate").expanduser()
    resolved_api_url = _resolve_api_url(api_url, app)
    resolved_o11y_api_token = _resolve_o11y_api_token(o11y_api_token)

    _sync_terraform_bundle(resolved_work_dir)
    resolved_state_path.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "TF_VAR_signalfx_auth_token": resolved_o11y_api_token,
            "TF_VAR_signalfx_api_url": resolved_api_url,
            "TF_VAR_name_prefix": name_prefix,
            "TF_VAR_create_detectors": _tf_bool(with_detectors),
            "TF_VAR_detectors_disabled": _tf_bool(not enable_detectors),
            "TF_VAR_detector_notifications": json.dumps(list(detector_notifications)),
        }
    )

    ux.section("Splunk O11y dashboards")
    click.echo(f"    Terraform dir: {resolved_work_dir}")
    click.echo(f"    State:         {resolved_state_path}")
    click.echo(f"    API URL:       {resolved_api_url}")
    click.echo(f"    Test label:    {name_prefix or '(none)'}")
    click.echo(f"    Detectors:     {_detector_summary(with_detectors, enable_detectors)}")
    click.echo("    Adoption:      automatic import of matching existing dashboards before apply")
    if not with_detectors:
        click.echo(f"    {ux.dim('Use --with-detectors to create Splunk detectors from bundled rules.')}")
    click.echo()

    return _PreparedRun(
        work_dir=resolved_work_dir,
        state_path=resolved_state_path,
        env=env,
        name_prefix=name_prefix,
        with_detectors=with_detectors,
    )


def apply_dashboards(
    app: AppContext | None,
    *,
    api_url: str | None,
    o11y_api_token: str | None,
    name_prefix: str,
    with_detectors: bool,
    enable_detectors: bool,
    detector_notifications: tuple[str, ...],
    work_dir: Path | None,
    state_path: Path | None,
    terraform_bin: str,
    plugin_dir: Path | None,
    skip_init: bool,
    skip_validate: bool,
    timeout: int,
    yes: bool,
) -> None:
    prepared = _prepare_run(
        app,
        api_url=api_url,
        o11y_api_token=o11y_api_token,
        name_prefix=name_prefix,
        with_detectors=with_detectors,
        enable_detectors=enable_detectors,
        detector_notifications=detector_notifications,
        work_dir=work_dir,
        state_path=state_path,
    )
    _run_init_validate(
        prepared,
        terraform_bin=terraform_bin,
        plugin_dir=plugin_dir,
        skip_init=skip_init,
        skip_validate=skip_validate,
        timeout=timeout,
    )
    _adopt_existing_resources(prepared, terraform_bin=terraform_bin, timeout=timeout)
    _run_terraform(
        terraform_bin,
        ["plan", "-input=false", f"-state={prepared.state_path}"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )
    if not yes:
        click.confirm("Apply these Splunk Observability Cloud changes?", abort=True)
    _run_terraform(
        terraform_bin,
        ["apply", "-input=false", "-auto-approve", f"-state={prepared.state_path}"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )
    _print_dashboard_outputs(prepared, terraform_bin=terraform_bin, timeout=timeout)


def _run_init_validate(
    prepared: _PreparedRun,
    *,
    terraform_bin: str,
    plugin_dir: Path | None,
    skip_init: bool,
    skip_validate: bool,
    timeout: int,
) -> None:
    if not skip_init:
        init_args = ["init", "-input=false"]
        if plugin_dir is not None:
            init_args.append(f"-plugin-dir={plugin_dir.expanduser()}")
        _run_terraform(terraform_bin, init_args, cwd=prepared.work_dir, env=prepared.env, timeout=timeout)
    if not skip_validate:
        _run_terraform(terraform_bin, ["validate"], cwd=prepared.work_dir, env=prepared.env, timeout=timeout)


@dataclass(frozen=True)
class _ImportTarget:
    address: str
    remote_id: str


def _terraform_state_list(terraform_bin: str, *, prepared: _PreparedRun, timeout: int) -> set[str]:
    result = _run_terraform(
        terraform_bin,
        ["state", "list", f"-state={prepared.state_path}"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    return {line.strip() for line in (result.stdout or "").splitlines() if line.strip()}


def _terraform_state_rm(terraform_bin: str, *, prepared: _PreparedRun, addresses: list[str], timeout: int) -> None:
    if not addresses:
        return
    _run_terraform(
        terraform_bin,
        ["state", "rm", f"-state={prepared.state_path}", *addresses],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )


def _terraform_console_json(terraform_bin: str, *, prepared: _PreparedRun, expr: str, timeout: int):
    display = f"{terraform_bin} console"
    click.echo(f"  {ux.dim('$')} {display}")
    try:
        result = subprocess.run(
            [terraform_bin, "console", "-no-color"],
            cwd=str(prepared.work_dir),
            env=prepared.env,
            text=True,
            input=expr + "\n",
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise click.ClickException(
            f"Terraform executable not found: {terraform_bin}. Install Terraform or pass --terraform-bin."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise click.ClickException(f"Terraform console timed out after {timeout}s: {display}") from exc
    except OSError as exc:
        raise click.ClickException(f"Could not execute Terraform console: {exc}") from exc

    if result.returncode != 0:
        _echo_captured_failure(result)
        raise click.ClickException(f"Terraform console failed with exit code {result.returncode}: {display}")

    raw = (result.stdout or "").strip()
    if not raw:
        return None
    try:
        decoded = json.loads(raw)
    except ValueError as exc:
        raise click.ClickException(f"Terraform console did not return JSON: {raw[:120]}") from exc
    if isinstance(decoded, str):
        try:
            return json.loads(decoded)
        except ValueError:
            return decoded
    return decoded


def _o11y_api_get_json(
    api_url: str,
    o11y_api_token: str,
    path: str,
    params: dict[str, object] | None = None,
) -> object:
    url = f"{api_url.rstrip('/')}/{path.lstrip('/')}"
    response = requests.get(
        url,
        headers={
            "X-SF-TOKEN": o11y_api_token,
            "Accept": "application/json",
        },
        params=params or {},
        timeout=30,
    )
    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        raise click.ClickException(f"Splunk O11y API request failed for {url}: {exc}") from exc
    try:
        return response.json()
    except ValueError as exc:
        raise click.ClickException(f"Splunk O11y API returned invalid JSON for {url}") from exc


def _extract_list_payload(payload: object) -> list[object]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("results", "dashboardGroups", "dashboards", "detectors", "charts", "items", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    for value in payload.values():
        if isinstance(value, list):
            return value
    return []


def _find_exact_named(items: list[object], expected_name: str, *, group_id: str | None = None) -> dict | None:
    matches: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("dashboardName") or item.get("title") or "").strip()
        if name != expected_name:
            continue
        if group_id:
            item_group = str(
                item.get("dashboardGroupId")
                or item.get("dashboardGroupID")
                or item.get("groupId")
                or item.get("dashboard_group_id")
                or ""
            ).strip()
            if item_group and item_group != group_id:
                continue
        matches.append(item)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise click.ClickException(f"Found multiple O11y resources named {expected_name!r}; cannot adopt safely.")
    return None


def _find_all_named(items: list[object], expected_name: str) -> list[dict]:
    matches: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("dashboardName") or item.get("title") or "").strip()
        if name == expected_name:
            matches.append(item)
    return matches


def _resource_id(item: object) -> str:
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        raise click.ClickException(f"Could not determine resource id from O11y object: {item!r}")
    for key in ("id", "dashboardId", "dashboard_id", "detectorId", "detector_id", "chartId", "chart_id", "groupId"):
        value = item.get(key)
        if value:
            return str(value)
    raise click.ClickException(f"Could not determine resource id from O11y object: {item!r}")


def _expected_dashboard_name(base: str, name_prefix: str) -> str:
    prefix = name_prefix.strip()
    return f"{base} ({prefix})" if prefix else base


def _expected_group_name(name_prefix: str) -> str:
    prefix = name_prefix.strip()
    return f"{prefix} DefenseClaw O11y".strip() if prefix else "DefenseClaw O11y"


def _dashboard_group_id(item: dict) -> str:
    for key in ("dashboardGroupId", "dashboardGroupID", "groupId", "dashboard_group_id"):
        value = item.get(key)
        if value:
            return str(value)
    return ""


def _terraform_import(
    terraform_bin: str,
    *,
    prepared: _PreparedRun,
    address: str,
    remote_id: str,
    timeout: int,
) -> None:
    _run_terraform(
        terraform_bin,
        ["import", "-input=false", f"-state={prepared.state_path}", address, remote_id],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
    )


def _dashboard_charts(detail: object) -> list[dict]:
    if not isinstance(detail, dict):
        return []
    for container in (detail, detail.get("dashboard"), detail.get("data")):
        if not isinstance(container, dict):
            continue
        for key in ("charts", "dashboardCharts", "elements", "items"):
            value = container.get(key)
            if isinstance(value, list):
                charts = [item if isinstance(item, dict) else {"id": str(item)} for item in value if item is not None]
                if charts:
                    return charts
    return []


def _adopt_existing_resources(
    prepared: _PreparedRun,
    *,
    terraform_bin: str,
    timeout: int,
) -> None:
    ux.section("Adopting existing Splunk O11y resources")
    console_data = _terraform_console_json(
        terraform_bin,
        prepared=prepared,
        expr=(
            "jsonencode({"
            "single = local.single_value_charts,"
            "time = local.time_charts,"
            "table = local.table_charts,"
            "layouts = local.dashboard_layouts,"
            "detectors = local.detectors"
            "})"
        ),
        timeout=timeout,
    )
    if not isinstance(console_data, dict):
        raise click.ClickException("Unexpected Terraform console output while loading the dashboard bundle metadata.")

    chart_maps = {
        "single": console_data.get("single") or {},
        "time": console_data.get("time") or {},
        "table": console_data.get("table") or {},
    }
    dashboard_layouts = console_data.get("layouts") or {}
    detector_defs = console_data.get("detectors") or {}

    if not isinstance(chart_maps["single"], dict) or not isinstance(chart_maps["time"], dict) or not isinstance(
        chart_maps["table"], dict
    ):
        raise click.ClickException("Unexpected Terraform console output for chart metadata.")
    if not isinstance(dashboard_layouts, dict) or not isinstance(detector_defs, dict):
        raise click.ClickException("Unexpected Terraform console output for dashboard or detector metadata.")

    state_addresses = _terraform_state_list(terraform_bin, prepared=prepared, timeout=timeout)
    o11y_api_token = str(prepared.env["TF_VAR_signalfx_auth_token"])
    api_url = str(prepared.env["TF_VAR_signalfx_api_url"])

    imported = 0
    resources: list[_ImportTarget] = []
    chart_addresses = [
        f'{resource_prefix}["{chart_key}"]'
        for chart_type, resource_prefix in (
            ("single", "signalfx_single_value_chart.single"),
            ("time", "signalfx_time_chart.time"),
            ("table", "signalfx_table_chart.table"),
        )
        for chart_key in (chart_maps.get(chart_type) or {}).keys()
        if f'{resource_prefix}["{chart_key}"]' in state_addresses
    ]
    bundle_addresses = {
        "signalfx_dashboard_group.defenseclaw_o11y",
        *{f"signalfx_dashboard.{dashboard_key}" for dashboard_key in dashboard_layouts.keys()},
        *{
            f'{resource_prefix}["{chart_key}"]'
            for chart_type, resource_prefix in (
                ("single", "signalfx_single_value_chart.single"),
                ("time", "signalfx_time_chart.time"),
                ("table", "signalfx_table_chart.table"),
            )
            for chart_key in (chart_maps.get(chart_type) or {}).keys()
        },
    }
    if prepared.with_detectors:
        bundle_addresses.update(
            {f'signalfx_detector.detector["{detector_key}"]' for detector_key in detector_defs.keys()}
        )

    group_name = _expected_group_name(prepared.name_prefix)
    dashboard_groups_payload = _extract_list_payload(
        _o11y_api_get_json(api_url, o11y_api_token, "/v2/dashboardgroup", params={"limit": 200, "offset": 0})
    )
    candidate_groups = _find_all_named(dashboard_groups_payload, group_name)
    dashboards_payload = _extract_list_payload(
        _o11y_api_get_json(api_url, o11y_api_token, "/v2/dashboard", params={"limit": 500, "offset": 0})
    )
    expected_dashboard_names = {
        dashboard_key: _expected_dashboard_name(base_name, prepared.name_prefix)
        for dashboard_key, base_name in _DASHBOARD_SPECS
    }
    dashboards_by_group: dict[str, dict[str, dict]] = {}
    for group_item in candidate_groups:
        group_id = _resource_id(group_item)
        group_dashboards: dict[str, dict] = {}
        for dashboard_key, dashboard_name in expected_dashboard_names.items():
            dashboard_item = _find_exact_named(dashboards_payload, dashboard_name, group_id=group_id)
            if dashboard_item is not None:
                group_dashboards[dashboard_key] = dashboard_item
        dashboards_by_group[group_id] = group_dashboards

    chosen_group: dict | None = None
    chosen_group_dashboards: dict[str, dict] = {}
    if candidate_groups:
        chosen_group = max(
            enumerate(candidate_groups),
            key=lambda pair: (len(dashboards_by_group.get(_resource_id(pair[1]), {})), pair[0]),
        )[1]
        chosen_group_dashboards = dashboards_by_group.get(_resource_id(chosen_group), {})
        top_score = len(chosen_group_dashboards)
        tied = [
            item
            for item in candidate_groups
            if len(dashboards_by_group.get(_resource_id(item), {})) == top_score
        ]
        if len(tied) > 1:
            tie_ids = ", ".join(f"{_resource_id(item)}" for item in tied)
            click.echo(
                f"  warning: multiple dashboard groups named {group_name!r} matched equally ({top_score} dashboards); "
                f"using the first candidate. IDs: {tie_ids}"
            )

    if chosen_group is not None and chosen_group_dashboards:
        group_id = _resource_id(chosen_group)
        click.echo(f"  Selected dashboard group {group_name!r} (id: {group_id}) for adoption.")
        resources.append(_ImportTarget("signalfx_dashboard_group.defenseclaw_o11y", group_id))
        for dashboard_key, dashboard_item in chosen_group_dashboards.items():
            resources.append(_ImportTarget(f"signalfx_dashboard.{dashboard_key}", _resource_id(dashboard_item)))
        if chart_addresses:
            _terraform_state_rm(terraform_bin, prepared=prepared, addresses=chart_addresses, timeout=timeout)
            for address in chart_addresses:
                state_addresses.discard(address)

    elif candidate_groups:
        bundle_state_addresses = sorted(address for address in bundle_addresses if address in state_addresses)
        if bundle_state_addresses:
            click.echo("  No matching dashboards were found in O11y; clearing stale bundle state before apply.")
            _terraform_state_rm(terraform_bin, prepared=prepared, addresses=bundle_state_addresses, timeout=timeout)
            for address in bundle_state_addresses:
                state_addresses.discard(address)
        click.echo(
            f"  Found {len(candidate_groups)} dashboard groups named {group_name!r}, "
            "but none contained matching dashboards."
        )
    else:
        bundle_state_addresses = sorted(address for address in bundle_addresses if address in state_addresses)
        if bundle_state_addresses:
            click.echo("  No existing dashboard group was found; clearing stale bundle state before apply.")
            _terraform_state_rm(terraform_bin, prepared=prepared, addresses=bundle_state_addresses, timeout=timeout)
            for address in bundle_state_addresses:
                state_addresses.discard(address)
        click.echo(f"  No existing dashboard group named {group_name!r} was found; nothing to adopt.")

    if prepared.with_detectors:
        detector_items = _extract_list_payload(
            _o11y_api_get_json(api_url, o11y_api_token, "/v2/detector", params={"limit": 500, "offset": 0})
        )
        for detector_key, detector_def in detector_defs.items():
            if not isinstance(detector_def, dict):
                continue
            detector_name = str(detector_def.get("name") or "").strip()
            if not detector_name:
                continue
            detector_item = _find_exact_named(detector_items, detector_name)
            if detector_item is None:
                continue
            detector_address = f'signalfx_detector.detector["{detector_key}"]'
            if detector_address in state_addresses:
                continue
            resources.append(_ImportTarget(detector_address, _resource_id(detector_item)))

    for resource in resources:
        if resource.address in state_addresses:
            continue
        _terraform_import(
            terraform_bin,
            prepared=prepared,
            address=resource.address,
            remote_id=resource.remote_id,
            timeout=timeout,
        )
        state_addresses.add(resource.address)
        imported += 1

    if imported:
        click.echo(f"  Imported {imported} existing resources into the selected Terraform state.")
    else:
        click.echo("  No matching existing resources needed import.")


def _run_terraform(
    terraform_bin: str,
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    capture_output: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    display = " ".join([terraform_bin, *args])
    click.echo(f"  {ux.dim('$')} {display}")
    try:
        result = subprocess.run(
            [terraform_bin, *args],
            cwd=str(cwd),
            env=env,
            text=True,
            capture_output=capture_output,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise click.ClickException(
            f"Terraform executable not found: {terraform_bin}. Install Terraform or pass --terraform-bin."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise click.ClickException(f"Terraform command timed out after {timeout}s: {display}") from exc
    except OSError as exc:
        raise click.ClickException(f"Could not execute Terraform: {exc}") from exc

    if check and result.returncode != 0:
        if capture_output:
            _echo_captured_failure(result)
        raise click.ClickException(f"Terraform command failed with exit code {result.returncode}: {display}")
    return result


def _print_dashboard_outputs(prepared: _PreparedRun, *, terraform_bin: str, timeout: int) -> None:
    result = _run_terraform(
        terraform_bin,
        ["output", "-json", f"-state={prepared.state_path}", "dashboard_urls"],
        cwd=prepared.work_dir,
        env=prepared.env,
        timeout=timeout,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        ux.warn("apply completed, but dashboard_urls output was not available")
        return
    try:
        urls = json.loads(result.stdout or "{}")
    except ValueError:
        ux.warn("apply completed, but dashboard_urls output was not valid JSON")
        return
    if not isinstance(urls, dict) or not urls:
        return

    ux.ok("Dashboard URLs")
    for name, url in sorted(urls.items()):
        click.echo(f"    {name}: {url}")


def _echo_captured_failure(result: subprocess.CompletedProcess[str]) -> None:
    output = (result.stderr or result.stdout or "").strip()
    for line in output.splitlines()[:20]:
        click.echo(f"    {line}", err=True)


def _sync_terraform_bundle(work_dir: Path) -> None:
    source_dir = bundled_splunk_o11y_dashboards_terraform_dir()
    if not source_dir.is_dir():
        raise click.ClickException(f"Bundled Splunk O11y Terraform directory not found: {source_dir}")
    work_dir.mkdir(parents=True, exist_ok=True)
    if source_dir.resolve() == work_dir.resolve():
        return
    for source_file in source_dir.glob("*.tf"):
        shutil.copy2(source_file, work_dir / source_file.name)


def _resolve_data_dir(app: AppContext | None) -> Path:
    if app is not None and app.cfg is not None and getattr(app.cfg, "data_dir", None):
        return Path(str(app.cfg.data_dir)).expanduser()
    return Path.home() / ".defenseclaw"


def _resolve_o11y_api_token(o11y_api_token: str | None) -> str:
    if o11y_api_token:
        return o11y_api_token
    raise click.ClickException(
        "Splunk O11y token not found. Set the SFX_AUTH_TOKEN environment "
        "variable (preferred) or pass --o11y-api-token."
    )


def _validate_api_url(api_url: str) -> str:
    """Validate an explicitly-supplied O11y API URL before attaching the token.

    ``_api_url_from_ingest_endpoint`` only ever derives ``https://api.<realm>.
    signalfx.com`` (or ``…observability.splunkcloud.com``) hosts, but an
    explicit ``--api-url`` / ``SFX_API_URL`` previously bypassed that
    allowlist, so the ``X-SF-TOKEN`` could be sent to an arbitrary host.
    Require the same https + Splunk O11y host shape so the token only ever
    reaches a legitimate Splunk O11y API endpoint (F-0187). Returns the
    normalised ``https://<host>`` form (path/query/port stripped) so no
    extra routing can be smuggled in.
    """
    parsed = urlsplit(api_url.strip())
    host = (parsed.hostname or "").lower()
    host_ok = bool(
        re.fullmatch(
            r"api\.[a-z0-9-]+\.(signalfx\.com|observability\.splunkcloud\.com)",
            host,
        )
    )
    if parsed.scheme != "https" or not host_ok or parsed.port not in (None, 443):
        raise click.ClickException(
            f"Refusing to send the Splunk O11y API token to {api_url!r}: "
            "--api-url / SFX_API_URL must be an https URL to a Splunk O11y API "
            "host (api.<realm>.signalfx.com or "
            "api.<realm>.observability.splunkcloud.com).",
        )
    return f"https://{host}"


def _resolve_api_url(api_url: str | None, app: AppContext | None) -> str:
    if api_url:
        return _validate_api_url(api_url)
    for endpoint in _configured_otel_endpoints(app):
        derived = _api_url_from_ingest_endpoint(endpoint)
        if derived:
            return derived
    raise click.ClickException(
        "Splunk O11y API URL not found. Set SFX_API_URL, pass --api-url, or configure Splunk O11y ingest first."
    )


def _configured_otel_endpoints(app: AppContext | None) -> list[str]:
    if app is None or app.cfg is None:
        return []
    otel = getattr(app.cfg, "otel", None)
    if otel is None:
        return []
    endpoints: list[str] = []
    for attr in ("endpoint",):
        value = getattr(otel, attr, "")
        if value:
            endpoints.append(str(value))
    for signal in ("metrics", "traces", "logs"):
        cfg = getattr(otel, signal, None)
        value = getattr(cfg, "endpoint", "") if cfg is not None else ""
        if value:
            endpoints.append(str(value))
    return endpoints


def _api_url_from_ingest_endpoint(endpoint: str) -> str | None:
    host = _hostname_from_endpoint(endpoint)
    if not host:
        return None
    if re.fullmatch(r"api\.[a-z0-9-]+\.(signalfx\.com|observability\.splunkcloud\.com)", host):
        return f"https://{host}"
    match = re.fullmatch(
        r"ingest\.([a-z0-9-]+)\.(signalfx\.com|observability\.splunkcloud\.com)",
        host,
    )
    if not match:
        return None
    realm = match.group(1)
    return f"https://api.{realm}.signalfx.com"


def _hostname_from_endpoint(endpoint: str) -> str:
    raw = endpoint.strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
    return host.lower().strip()


def _tf_bool(value: bool) -> str:
    return "true" if value else "false"


def _detector_summary(with_detectors: bool, enable_detectors: bool) -> str:
    if not with_detectors:
        return "not created"
    if enable_detectors:
        return "created enabled"
    return "created disabled"
