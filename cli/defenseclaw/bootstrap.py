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

"""Headless bootstrap helpers.

These are the idempotent, non-interactive pieces of ``defenseclaw init``:
directory creation, policy seeding, audit DB initialization, and gateway
default resolution. Factoring them out of ``cmd_init`` lets non-init flows
(``quickstart``, tests, migrations) rerun the setup without re-printing the
banner or prompting the user.

Design rule: *no click.echo in here*. Callers (``cmd_init``, ``quickstart``)
are responsible for rendering any UI. That keeps this module easy to test
and safe to call from background contexts.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from defenseclaw.config import Config
    from defenseclaw.logger import Logger


@dataclass
class BootstrapReport:
    """Structured result of a bootstrap run.

    Callers use this to drive per-step status lines without having to
    duplicate the underlying logic. Every field is a plain Python type
    so the report serializes cleanly to JSON for ``doctor`` and tests.
    """

    data_dir: str = ""
    config_file: str = ""
    audit_db: str = ""
    is_new_config: bool = False
    dirs_created: list[str] = field(default_factory=list)
    rego_seeded: str = ""       # destination path, "" if bundle missing
    guardrail_profiles_seeded: list[str] = field(default_factory=list)
    guardrail_profiles_preserved: list[str] = field(default_factory=list)
    splunk_bridge_dest: str = ""      # "" if bundle missing, otherwise dest path
    splunk_bridge_preserved: bool = False
    openclaw_token_detected: bool = False
    device_key_file: str = ""
    errors: list[str] = field(default_factory=list)


def bootstrap_env(cfg: Config, logger: Logger | None = None) -> BootstrapReport:
    """Initialize ``~/.defenseclaw/`` and related state.

    Safe to call repeatedly. Each step is idempotent:

    * directories — ``os.makedirs(exist_ok=True)``
    * policy seeding — skipped when destination already exists
    * audit DB — ``Store.init()`` runs ``CREATE TABLE IF NOT EXISTS``
    * gateway token — re-read from ``openclaw.json`` on every call

    Returns a :class:`BootstrapReport` describing what happened so the
    caller can render a user-facing summary. Never raises for
    recoverable failures — those are collected into ``report.errors``.
    """
    from defenseclaw.config import config_path
    from defenseclaw.db import Store

    report = BootstrapReport(
        data_dir=cfg.data_dir,
        config_file=config_path(),
        audit_db=cfg.audit_db,
    )
    report.is_new_config = not os.path.exists(report.config_file)

    # --- directories ---
    candidates = [cfg.data_dir, cfg.quarantine_dir, cfg.plugin_dir, cfg.policy_dir]
    data_real = os.path.realpath(cfg.data_dir) if cfg.data_dir else ""
    for d in candidates:
        if not d:
            continue
        try:
            os.makedirs(d, exist_ok=True)
            report.dirs_created.append(d)
        except OSError as exc:
            report.errors.append(f"mkdir {d}: {exc}")

    # Only mkdir skill dirs that sit *inside* our data dir — we don't
    # want bootstrap inadvertently creating OpenClaw's home directory
    # if the user wiped it intentionally.
    try:
        skill_dirs = list(cfg.skill_dirs())
    except Exception:  # pragma: no cover — defensive
        skill_dirs = []
    for d in skill_dirs:
        if not d or not data_real:
            continue
        if os.path.realpath(d).startswith(data_real + os.sep):
            try:
                os.makedirs(d, exist_ok=True)
                report.dirs_created.append(d)
            except OSError as exc:
                report.errors.append(f"mkdir {d}: {exc}")

    # --- policy seeding ---
    _seed_rego(cfg.policy_dir, report)
    _seed_guardrail_profiles(cfg.policy_dir, report)
    _seed_splunk_bridge(cfg.data_dir, report)

    # --- audit DB ---
    if cfg.audit_db:
        try:
            store = Store(cfg.audit_db)
            store.init()
            store.close()
        except Exception as exc:  # broad because sqlite/file errors all matter
            report.errors.append(f"audit_db init: {exc}")

    # --- gateway defaults (OpenClaw token detection) ---
    try:
        report.openclaw_token_detected = _apply_gateway_defaults(cfg, report.is_new_config)
    except Exception as exc:  # pragma: no cover — defensive
        report.errors.append(f"gateway defaults: {exc}")

    report.device_key_file = cfg.gateway.device_key_file

    if logger is not None:
        try:
            logger.log_action(
                "bootstrap",
                cfg.data_dir,
                f"new={report.is_new_config} errors={len(report.errors)}",
            )
        except Exception:  # pragma: no cover — logger shouldn't block bootstrap
            pass

    return report


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------

def _seed_rego(policy_dir: str, report: BootstrapReport) -> None:
    from defenseclaw.paths import bundled_rego_dir

    bundled = bundled_rego_dir()
    if not bundled or not bundled.is_dir() or not policy_dir:
        return

    dest = os.path.join(policy_dir, "rego")
    try:
        os.makedirs(dest, exist_ok=True)
    except OSError as exc:
        report.errors.append(f"mkdir {dest}: {exc}")
        return

    for src in bundled.iterdir():
        if src.suffix not in (".rego", ".json") or src.name.startswith("."):
            continue
        dst = os.path.join(dest, src.name)
        if os.path.exists(dst):
            continue
        try:
            shutil.copy2(str(src), dst)
        except OSError as exc:
            report.errors.append(f"seed rego {src.name}: {exc}")
    report.rego_seeded = dest


def _seed_guardrail_profiles(policy_dir: str, report: BootstrapReport) -> None:
    from defenseclaw.paths import bundled_guardrail_profiles_dir

    bundled = bundled_guardrail_profiles_dir()
    if bundled is None or not policy_dir:
        return

    dest_root = os.path.join(policy_dir, "guardrail")
    try:
        os.makedirs(dest_root, exist_ok=True)
    except OSError as exc:
        report.errors.append(f"mkdir {dest_root}: {exc}")
        return

    for profile in bundled.iterdir():
        if not profile.is_dir() or profile.name.startswith("."):
            continue
        dst = os.path.join(dest_root, profile.name)
        if os.path.isdir(dst):
            report.guardrail_profiles_preserved.append(profile.name)
            continue
        try:
            shutil.copytree(str(profile), dst)
            report.guardrail_profiles_seeded.append(profile.name)
        except OSError as exc:
            report.errors.append(f"seed guardrail profile {profile.name}: {exc}")


def _seed_splunk_bridge(data_dir: str, report: BootstrapReport) -> None:
    from defenseclaw.paths import bundled_splunk_bridge_dir

    bundled = bundled_splunk_bridge_dir()
    if not bundled or not bundled.is_dir() or not data_dir:
        return

    dest = os.path.join(data_dir, "splunk-bridge")
    if os.path.isdir(dest):
        report.splunk_bridge_dest = dest
        report.splunk_bridge_preserved = True
        return

    try:
        shutil.copytree(str(bundled), dest)
    except OSError as exc:
        report.errors.append(f"seed splunk-bridge: {exc}")
        return

    bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
    if os.path.isfile(bridge_bin):
        try:
            os.chmod(bridge_bin, 0o755)
        except OSError:
            pass
    report.splunk_bridge_dest = dest


def _apply_gateway_defaults(cfg: Config, is_new_config: bool) -> bool:
    """Sync gateway host/port/token from ``openclaw.json``.

    Returns True when an OPENCLAW_GATEWAY_TOKEN was detected and
    written to ``~/.defenseclaw/.env``. Mirrors the production logic
    in ``cmd_init._setup_gateway_defaults`` without the UI chatter.
    """
    from defenseclaw.commands.cmd_init import (
        _ensure_device_key,
        _resolve_openclaw_gateway,
    )
    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    oc_gw = _resolve_openclaw_gateway(cfg.claw.config_file)
    if is_new_config:
        cfg.gateway.host = oc_gw["host"]
        cfg.gateway.port = oc_gw["port"]

    token_configured = False
    token = oc_gw.get("token", "")
    if token:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", token, cfg.data_dir)
        cfg.gateway.token = ""
        cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        token_configured = True
    else:
        cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        token_configured = bool(cfg.gateway.resolved_token())

    if not cfg.gateway.device_key_file:
        cfg.gateway.device_key_file = os.path.join(cfg.data_dir, "device.key")
    _ensure_device_key(cfg.gateway.device_key_file)

    return token_configured
