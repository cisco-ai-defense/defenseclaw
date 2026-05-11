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

"""defenseclaw setup splunk-o11y-dashboards — manage O11y dashboards.

This command is intentionally a thin Terraform driver. It copies the bundled
Terraform module into the user's DefenseClaw data directory, resolves the
Splunk Observability Cloud API URL/token from config or environment, and runs
Terraform with the token supplied through ``TF_VAR_*`` rather than command-line
arguments.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import click

from defenseclaw import ux
from defenseclaw.context import AppContext
from defenseclaw.paths import bundled_splunk_o11y_dashboards_terraform_dir

_DEFAULT_WORK_SUBDIR = "splunk-o11y-dashboards"


@click.group(
    "splunk-o11y-dashboards",
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
        "--auth-token",
        default=None,
        help="Splunk O11y API access token. Required unless provided explicitly.",
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
    auth_token: str | None,
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
        ctx,
        api_url=api_url,
        auth_token=auth_token,
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
    auth_token: str | None,
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
    prepared = _prepare_run(
        ctx,
        api_url=api_url,
        auth_token=auth_token,
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
    auth_token: str | None,
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
        ctx,
        api_url=api_url,
        auth_token=auth_token,
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
    def __init__(self, work_dir: Path, state_path: Path, env: dict[str, str]) -> None:
        self.work_dir = work_dir
        self.state_path = state_path
        self.env = env


def _prepare_run(
    ctx: click.Context,
    *,
    api_url: str | None,
    auth_token: str | None,
    name_prefix: str,
    with_detectors: bool,
    enable_detectors: bool,
    detector_notifications: tuple[str, ...],
    work_dir: Path | None,
    state_path: Path | None,
) -> _PreparedRun:
    app = ctx.find_object(AppContext)
    data_dir = _resolve_data_dir(app)
    resolved_work_dir = (work_dir or data_dir / _DEFAULT_WORK_SUBDIR / "terraform").expanduser()
    resolved_state_path = (state_path or data_dir / _DEFAULT_WORK_SUBDIR / "terraform.tfstate").expanduser()
    resolved_api_url = _resolve_api_url(api_url, app)
    resolved_auth_token = _resolve_auth_token(auth_token)

    _sync_terraform_bundle(resolved_work_dir)
    resolved_state_path.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "TF_VAR_signalfx_auth_token": resolved_auth_token,
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
    if not with_detectors:
        click.echo(f"    {ux.dim('Use --with-detectors to create Splunk detectors from bundled rules.')}")
    click.echo()

    return _PreparedRun(
        work_dir=resolved_work_dir,
        state_path=resolved_state_path,
        env=env,
    )


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


def _resolve_auth_token(auth_token: str | None) -> str:
    if auth_token:
        return auth_token
    raise click.ClickException(
        "Splunk O11y token not found. Pass --auth-token."
    )


def _resolve_api_url(api_url: str | None, app: AppContext | None) -> str:
    if api_url:
        return api_url
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
