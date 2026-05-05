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

Three subcommands:

* ``config validate`` — parse ``~/.defenseclaw/config.yaml`` and
  return a non-zero exit code on any error. Used both by the operator
  and by the auto-validate hook in ``main.py``.
* ``config show`` — render the resolved config as JSON or YAML with
  secrets masked.
* ``config path`` — print the filesystem layout DefenseClaw uses.
"""

from __future__ import annotations

import json
import os
from dataclasses import fields, is_dataclass

import click
import yaml

from defenseclaw import config as config_module
from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

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


@click.group("config")
def config_cmd() -> None:
    """Inspect and validate DefenseClaw configuration."""


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
@click.option(
    "--reveal",
    is_flag=True,
    help="Include resolved secret VALUES (masked). Off by default; env-var names are always shown.",
)
@pass_ctx
def config_show(app: AppContext, fmt: str, reveal: bool) -> None:
    """Render the resolved configuration (secrets masked)."""
    data = _config_to_masked_dict(app.cfg, reveal=reveal)
    if fmt.lower() == "json":
        click.echo(json.dumps(data, indent=2, sort_keys=True))
    else:
        click.echo(yaml.safe_dump(data, sort_keys=True, default_flow_style=False).rstrip())


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------

@config_cmd.command("path")
@pass_ctx
def config_path(app: AppContext) -> None:
    """Print the filesystem locations DefenseClaw uses."""
    cfg = app.cfg
    click.echo()
    rows = [
        ("config file",    config_module.config_path()),
        ("data dir",       cfg.data_dir),
        ("audit DB",       cfg.audit_db),
        ("policy dir",     cfg.policy_dir),
        ("plugin dir",     cfg.plugin_dir),
        ("quarantine dir", cfg.quarantine_dir),
        ("dotenv",         os.path.join(cfg.data_dir, ".env")),
        ("device key",     cfg.gateway.device_key_file),
        ("OpenClaw config", cfg.claw.config_file),
        ("OpenClaw home",  cfg.claw.home_dir),
    ]
    label_width = max(len(lbl) for lbl, _ in rows)
    for label, value in rows:
        exists = value and os.path.exists(str(value))
        marker = ux._style("✓", fg="green", bold=True) if exists else ux.dim("·")
        padded = (label + ":").ljust(label_width)
        click.echo(
            f"  {marker}  {ux._style(padded, fg='bright_black', bold=True)}{value}"
        )
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

    try:
        cfg = config_module.load()
    except yaml.YAMLError as exc:
        res.parse_error = f"YAML parse failed: {exc}"
        return res
    except Exception as exc:  # broad — we want to surface any config error
        res.parse_error = f"{type(exc).__name__}: {exc}"
        return res

    # --- semantic checks ---
    gc = getattr(cfg, "guardrail", None)
    if gc is not None:
        if gc.mode not in ("observe", "action"):
            res.errors.append(f"guardrail.mode must be 'observe' or 'action' (got '{gc.mode}')")
        if gc.scanner_mode not in ("local", "remote", "both"):
            res.errors.append(
                f"guardrail.scanner_mode must be 'local', 'remote', or 'both' (got '{gc.scanner_mode}')"
            )
        if gc.port <= 0 or gc.port > 65535:
            res.errors.append(f"guardrail.port out of range: {gc.port}")

    gw = getattr(cfg, "gateway", None)
    if gw is not None:
        if gw.port <= 0 or gw.port > 65535:
            res.errors.append(f"gateway.port out of range: {gw.port}")
        if gw.api_port <= 0 or gw.api_port > 65535:
            res.errors.append(f"gateway.api_port out of range: {gw.api_port}")
        if gw.port == gw.api_port:
            res.warnings.append(
                f"gateway.port ({gw.port}) equals gateway.api_port ({gw.api_port}) — one will fail to bind"
            )

    # Legacy plain-text secrets: already emitted as logger warnings on
    # load. We surface the same info in the validate report for
    # visibility.
    if getattr(cfg, "inspect_llm", None) and cfg.inspect_llm.api_key:
        res.warnings.append("inspect_llm.api_key is stored in plaintext; prefer api_key_env")
    if getattr(cfg, "cisco_ai_defense", None) and cfg.cisco_ai_defense.api_key:
        res.warnings.append("cisco_ai_defense.api_key is stored in plaintext; prefer api_key_env")
    if getattr(cfg, "scanners", None):
        ss = cfg.scanners.skill_scanner
        if ss.virustotal_api_key:
            res.warnings.append(
                "scanners.skill_scanner.virustotal_api_key is stored in plaintext; prefer virustotal_api_key_env"
            )
    if getattr(cfg, "splunk", None) and cfg.splunk.hec_token:
        res.warnings.append("splunk.hec_token is stored in plaintext; prefer hec_token_env")

    return res


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _config_to_masked_dict(cfg, *, reveal: bool) -> dict:
    """Convert a Config dataclass tree into a dict with secrets masked."""
    from defenseclaw.credentials import mask

    def _convert(value):
        if is_dataclass(value):
            return {f.name: _convert(getattr(value, f.name)) for f in fields(value)}
        if isinstance(value, dict):
            return {k: _convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_convert(v) for v in value]
        return value

    raw = _convert(cfg)

    def _walk(node, key_hint: str = "") -> None:
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if _is_secret_field(k) and isinstance(v, str) and v:
                    node[k] = mask(v) if reveal else "***"
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
