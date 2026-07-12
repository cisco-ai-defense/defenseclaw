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

"""defenseclaw config — inspect and validate configuration.

Four subcommands:

* ``config validate`` — parse ``~/.defenseclaw/config.yaml`` and
  return a non-zero exit code on any error. Used both by the operator
  and by the auto-validate hook in ``main.py``.
* ``config show`` — render the resolved config as JSON or YAML with
  secrets masked.
* ``config reference`` — render schema-generated v8 reference material.
* ``config path`` — print the filesystem layout DefenseClaw uses.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import fields, is_dataclass
from pathlib import Path

import click
import yaml

from defenseclaw import config as config_module
from defenseclaw import ux
from defenseclaw.config_inspect import (
    ConfigInspectError,
    config_v8_reference,
    config_v8_schema,
    inspect_v8_config,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8
from defenseclaw.webhooks.writer import redact_webhook_url

# Field names here catch both the bare form (``api_key``) and the
# suffixed form (``virustotal_api_key``). We deliberately exclude any
# field ending in ``_env`` because those hold env-var *names* (e.g.
# ``JUDGE_API_KEY``), not the secret values themselves.
_SECRET_FIELDS = (
    "api_key",
    "token",
    "secret",
    "password",
    "hec_token",
    "private_key",
    "pepper",
)

_V8_VERSION_LINE = re.compile(
    rb"(?m)^config_version\s*:\s*"
    rb"(?:(?:!!int|tag:yaml\.org,2002:int)\s+)?"
    rb"(?:8|['\"]8['\"])\s*(?:#.*)?$"
)
_MAX_VERSION_PROBE_BYTES = 4 * 1024 * 1024 + 1
_V7_READ_ONLY_SUBCOMMANDS = frozenset({"validate", "show", "reference", "path"})


@click.group("config")
@click.pass_context
def config_cmd(ctx: click.Context) -> None:
    """Inspect and validate DefenseClaw configuration."""

    # The root command deliberately lets config recovery/inspection run while
    # a v7 source still exists.  Keep that exemption narrow and future-proof:
    # a newly-added mutating subcommand must never silently write the legacy
    # document just because the top-level ``config`` group bypasses runtime
    # initialization.
    subcommand = ctx.invoked_subcommand
    path = config_module.config_path()
    if (
        subcommand
        and subcommand not in _V7_READ_ONLY_SUBCOMMANDS
        and path.exists()
        and not _looks_like_v8_config(str(path))
    ):
        raise click.ClickException(
            "configuration schema v8 is required for config changes; "
            "run 'defenseclaw upgrade' first"
        )


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@config_cmd.command("validate")
@click.option("--quiet", is_flag=True, help="Exit 0/1 with no stdout output.")
def config_validate(quiet: bool) -> None:
    """Verify the config file parses and references valid enums."""
    result = validate_config()
    if quiet:
        raise SystemExit(0 if result.ok else 1)

    click.echo()
    click.echo(f"  {ux.bold('Config:')} {result.path}")
    if result.exists:
        ux.ok("file exists", indent="  ")
    else:
        ux.warn("file does not exist yet — run 'defenseclaw init' or 'defenseclaw quickstart'")

    if result.parse_error:
        ux.err(f"parse error: {result.parse_error}", indent="  ")
    elif result.ok:
        ux.ok("syntax OK", indent="  ")

    for issue in result.errors:
        ux.err(issue, indent="  ")
    for warning in result.warnings:
        ux.warn(warning, indent="  ")

    click.echo()
    if not result.ok:
        raise SystemExit(1)
    ux.ok("config is valid", indent="  ")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@config_cmd.command("show")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    default="yaml",
    show_default=True,
    help="Output format.",
)
@click.option("--source", is_flag=True, help="Display the masked source configuration.")
@click.option("--effective", is_flag=True, help="Display canonical resolved defaults and expansions.")
@click.option(
    "--provenance",
    is_flag=True,
    help="Include canonical Go provenance annotations for the effective configuration.",
)
@click.option(
    "--section",
    type=click.Choice(["observability"], case_sensitive=False),
    default=None,
    help="Limit output to one configuration section.",
)
@click.option(
    "--reveal",
    is_flag=True,
    help="Include resolved secret VALUES (masked). Off by default; env-var names are always shown.",
)
@pass_ctx
def config_show(
    app: AppContext,
    fmt: str,
    source: bool,
    effective: bool,
    provenance: bool,
    section: str | None,
    reveal: bool,
) -> None:
    """Render the resolved configuration (secrets masked)."""
    if source and effective:
        raise click.UsageError("--source and --effective are mutually exclusive")
    if source and provenance:
        raise click.UsageError("--provenance annotates the effective view and cannot be combined with --source")

    cfg_path = str(config_module.config_path())
    v8 = _looks_like_v8_config(cfg_path)
    if v8:
        if reveal:
            raise click.UsageError("--reveal is not supported for configuration v8 output")
        if source:
            try:
                raw = Path(cfg_path).read_bytes()
                data = load_validate_v8(raw, source_name=cfg_path).masked
            except OSError as exc:
                raise click.ClickException(f"cannot read configuration source: {exc}") from exc
            except (V8ConfigError, RuntimeError) as exc:
                raise click.ClickException(str(exc)) from exc
        else:
            try:
                result = inspect_v8_config("effective", config_path=cfg_path)
            except ConfigInspectError as exc:
                raise click.ClickException(str(exc)) from exc
            data = {"observability": result.effective or {}}
    else:
        if provenance:
            raise click.UsageError("--provenance requires a configuration v8 effective plan")
        # Preserve the pre-v8 view for installations that have not upgraded.
        cfg = app.cfg if app.cfg is not None else config_module.load()
        data = _config_to_masked_dict(cfg, reveal=reveal)

    if section:
        section_name = section.lower()
        data = {section_name: data.get(section_name, {})}
    if provenance:
        effective_observability = data.get("observability")
        if isinstance(effective_observability, dict):
            effective_observability = dict(effective_observability)
            annotations = effective_observability.pop("provenance", [])
            data["observability"] = effective_observability
        else:
            annotations = []
        data["_provenance"] = {
            "basis": "canonical_go_effective_plan",
            "annotations": annotations,
        }
    if fmt.lower() == "json":
        click.echo(json.dumps(data, indent=2, sort_keys=True))
    else:
        click.echo(yaml.safe_dump(data, sort_keys=True, default_flow_style=False).rstrip())


# ---------------------------------------------------------------------------
# reference
# ---------------------------------------------------------------------------


@config_cmd.command("reference")
@click.argument("section", type=click.Choice(["observability"], case_sensitive=False))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yaml", "json-schema", "markdown"], case_sensitive=False),
    default="yaml",
    show_default=True,
)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
def config_reference(section: str, fmt: str, output: Path | None) -> None:
    """Render a version-matched generated configuration reference."""

    try:
        rendered = (
            config_v8_schema() if fmt.lower() == "json-schema" else config_v8_reference(fmt, section=section.lower())
        )
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc

    if output is None:
        click.echo(rendered, nl=not rendered.endswith("\n"))
        return
    try:
        with click.open_file(str(output), mode="w", encoding="utf-8", atomic=True) as stream:
            stream.write(rendered)
    except OSError as exc:
        raise click.ClickException(f"cannot write reference output: {exc}") from exc


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------


@config_cmd.command("path")
@pass_ctx
def config_path(app: AppContext) -> None:
    """Print the filesystem locations DefenseClaw uses."""
    cfg_path = str(config_module.config_path())
    if app.cfg is not None:
        cfg = app.cfg
    elif _looks_like_v8_config(cfg_path):
        cfg = _v8_config_path_view(cfg_path)
    else:
        cfg = config_module.load()
    click.echo()
    rows = [
        ("config file", config_module.config_path()),
        ("data dir", cfg.data_dir),
        ("audit DB", cfg.audit_db),
        ("policy dir", cfg.policy_dir),
        ("plugin dir", cfg.plugin_dir),
        ("quarantine dir", cfg.quarantine_dir),
        ("dotenv", os.path.join(cfg.data_dir, ".env")),
        ("device key", cfg.gateway.device_key_file),
        ("OpenClaw config", cfg.claw.config_file),
        ("OpenClaw home", cfg.claw.home_dir),
    ]
    label_width = max(len(lbl) for lbl, _ in rows)
    for label, value in rows:
        exists = value and os.path.exists(str(value))
        marker = ux._style("✓", fg="green", bold=True) if exists else ux.dim("·")
        padded = (label + ":").ljust(label_width)
        click.echo(f"  {marker}  {ux._style(padded, fg='bright_black', bold=True)}{value}")
    click.echo()


# ---------------------------------------------------------------------------
# Public helpers (shared with main.py auto-validate)
# ---------------------------------------------------------------------------


class ValidationResult:
    """Plain container so this module has zero Click dependencies at import."""

    def __init__(self) -> None:
        self.path: str = ""
        self.exists: bool = False
        self.parse_error: str = ""
        self.errors: list[str] = []
        self.warnings: list[str] = []

    @property
    def ok(self) -> bool:
        return not self.parse_error and not self.errors


def validate_config() -> ValidationResult:
    """Parse config, return structured diagnostics (no I/O on success)."""
    res = ValidationResult()
    cfg_path = str(config_module.config_path())
    res.path = cfg_path
    res.exists = os.path.isfile(cfg_path)

    if not res.exists:
        # Missing config is a soft-fail: `init`/`quickstart` will create
        # it. We return ok=True here so the auto-validate hook doesn't
        # block `init` before the file even exists.
        return res

    if _looks_like_v8_config(cfg_path):
        try:
            inspected = inspect_v8_config("validate", config_path=cfg_path)
        except ConfigInspectError as exc:
            res.errors.append(str(exc))
            return res
        if inspected.valid is not True:
            res.errors.append("canonical v8 validator returned no validity decision")
        return res

    res.errors.append("Configuration schema v8 is required — run 'defenseclaw upgrade' first.")
    return res


def _looks_like_v8_config(path: str) -> bool:
    """Detect a root v8 declaration without constructing source values.

    ``yaml.compose`` understands valid YAML presentation variants (including
    explicit standard tags) while leaving scalar values unconstructed.  The
    narrow line probe is intentionally retained as a fallback so malformed v8
    input still reaches the canonical Go validator and its actionable errors.
    """

    try:
        with open(path, "rb") as stream:
            raw = stream.read(_MAX_VERSION_PROBE_BYTES)
    except OSError:
        return False
    try:
        root = yaml.compose(raw)
    except (yaml.YAMLError, RecursionError, OverflowError):
        root = None
    if isinstance(root, yaml.MappingNode):
        for key_node, value_node in root.value:
            if not isinstance(key_node, yaml.ScalarNode) or key_node.value != "config_version":
                continue
            if isinstance(value_node, yaml.ScalarNode):
                if value_node.value.strip() == "8":
                    return True
                if value_node.tag == "tag:yaml.org,2002:int":
                    try:
                        if yaml.safe_load(value_node.value) == 8:
                            return True
                    except yaml.YAMLError:
                        pass
    return _V8_VERSION_LINE.search(raw) is not None


def _v8_config_path_view(path: str):
    """Build the legacy path-display shape from a masked v8 source.

    ``config path`` is a recovery command and must not send an exact-v8 file
    through the v7 loader. Only non-secret filesystem fields used by the view
    are projected; observability policy remains owned by the Go compiler.
    """

    try:
        source = load_validate_v8(Path(path).read_bytes(), source_name=path).masked
    except OSError as exc:
        raise click.ClickException(f"cannot read configuration source: {exc}") from exc
    except (V8ConfigError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    cfg = config_module.default_config()
    data_dir = str(source.get("data_dir") or cfg.data_dir)
    cfg.data_dir = data_dir
    cfg.audit_db = str(
        ((source.get("observability") or {}).get("local") or {}).get("path") or os.path.join(data_dir, "audit.db")
    )
    cfg.policy_dir = str(source.get("policy_dir") or os.path.join(data_dir, "policies"))
    cfg.plugin_dir = str(source.get("plugin_dir") or os.path.join(data_dir, "plugins"))
    cfg.quarantine_dir = str(source.get("quarantine_dir") or os.path.join(data_dir, "quarantine"))

    gateway = source.get("gateway") or {}
    cfg.gateway.device_key_file = str(gateway.get("device_key_file") or os.path.join(data_dir, "device.key"))
    claw = source.get("claw") or {}
    if claw.get("config_file"):
        cfg.claw.config_file = str(claw["config_file"])
    if claw.get("home_dir"):
        cfg.claw.home_dir = str(claw["home_dir"])
    return cfg


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _config_to_masked_dict(cfg, *, reveal: bool) -> dict:
    """Convert a Config dataclass tree into a dict with secrets masked."""
    from defenseclaw.credentials import mask

    def _convert(value):
        if is_dataclass(value):
            return {f.name: _convert(getattr(value, f.name)) for f in fields(value) if not f.name.startswith("_")}
        if isinstance(value, dict):
            return {k: _convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_convert(v) for v in value]
        return value

    raw = _convert(cfg)

    def _walk(node, key_hint: str = "") -> None:
        if isinstance(node, dict):
            # Header maps (canonical OTLP/HTTP destination headers, …)
            # carry bearer/API tokens under non-secret-looking keys such
            # as ``Authorization`` and ``x-honeycomb-team``; redact every
            # header value so none slips through (F-0221).
            in_headers = key_hint.lower() == "headers"
            # Webhook entries store the bearer secret inside ``url``.
            in_webhook = key_hint.lower() == "webhooks"
            for k, v in list(node.items()):
                if _is_secret_field(k) and isinstance(v, str) and v:
                    node[k] = mask(v) if reveal else "***"
                elif in_headers and isinstance(v, str) and v:
                    node[k] = mask(v) if reveal else "***"
                elif in_webhook and k.lower() == "url" and isinstance(v, str) and v:
                    node[k] = v if reveal else redact_webhook_url(v)
                else:
                    _walk(v, k)
        elif isinstance(node, list):
            for item in node:
                _walk(item, key_hint)

    _walk(raw)
    return raw


def _is_secret_field(key: str) -> bool:
    lowered = key.lower()
    # Env-var *name* fields (e.g. ``api_key_env``, ``hec_token_env``)
    # are not secrets — they're identifiers pointing to a secret stored
    # elsewhere. Never redact them.
    if lowered.endswith("_env"):
        return False
    for name in _SECRET_FIELDS:
        if lowered == name or lowered.endswith("_" + name):
            return True
    return False
