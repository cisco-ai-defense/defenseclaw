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

import contextlib
import io
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from defenseclaw.config import Config
    from defenseclaw.logger import Logger


# Canonical HITL severity floors. Duplicated here (not imported from
# cmd_setup.py) so click options on cmd_init / cmd_quickstart can
# reference it without dragging the entire setup wizard module into
# the import graph for ``defenseclaw --help``. The list is small and
# changes rarely; if a fifth severity is ever added, both this and
# ``cmd_setup._HILT_MIN_SEVERITIES`` must move in lockstep.
HILT_MIN_SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "CRITICAL")


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


@dataclass
class StepResult:
    """One setup/readiness outcome rendered by CLI/TUI frontends."""

    name: str
    status: str
    detail: str = ""
    next_command: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "next_command": self.next_command,
        }


@dataclass
class FirstRunOptions:
    """Structured input for the guided first-run backend."""

    connector: str = "codex"
    profile: str = "observe"  # observe | action
    scanner_mode: str = "local"  # local | remote | both
    with_judge: bool = False
    skip_install: bool = False
    sandbox: bool = False
    start_gateway: bool = False
    verify: bool = True
    force: bool = False
    verbose: bool = False
    llm_provider: str = ""
    llm_model: str = ""
    llm_api_key: str = ""
    llm_api_key_env: str = "DEFENSECLAW_LLM_KEY"
    llm_base_url: str = ""
    cisco_endpoint: str = ""
    cisco_api_key: str = ""
    cisco_api_key_env: str = "CISCO_AI_DEFENSE_API_KEY"
    # hook_fail_mode controls what generated hooks
    # (codex-hook, claude-code-hook, inspect-*) do when the
    # gateway returns a *response-layer* failure (4xx, malformed
    # JSON, missing action). Empty string means "leave the
    # current cfg.guardrail.hook_fail_mode untouched" so callers
    # who don't care don't accidentally clobber an operator's
    # earlier choice. Transport-layer failures (gateway
    # unreachable / 5xx) ALWAYS allow unless
    # DEFENSECLAW_STRICT_AVAILABILITY=1, regardless of this
    # value — see _normalize_hook_fail_mode for the canonical
    # rule.
    hook_fail_mode: str = ""
    # human_approval is the operator's HITL (Human-In-the-Loop)
    # toggle. ``None`` means "leave whatever was loaded alone" —
    # critical for upgrade flows where the operator already
    # enabled HITL via ``defenseclaw setup guardrail`` and then
    # re-runs init for some unrelated reason. ``True`` /
    # ``False`` set ``cfg.guardrail.hilt.enabled`` explicitly.
    # NOTE: HITL only fires in action mode (the gateway short-
    # circuits in observe mode regardless of this flag); we
    # still persist the operator's choice in observe mode so it
    # takes effect the moment they later flip to action via
    # ``defenseclaw setup guardrail``. Mirrors the contract
    # documented in cmd_setup.py::_configure_hilt_interactive.
    human_approval: bool | None = None
    # hilt_min_severity is the lowest finding severity that
    # triggers a HITL prompt (HIGH / MEDIUM / LOW / CRITICAL).
    # Empty string means "leave the existing value alone" so
    # callers who want to flip HITL on without overriding the
    # severity floor can pass ``human_approval=True`` and an
    # empty severity. Invalid values normalize to ``"HIGH"`` —
    # falling back to a stricter posture is safer than silently
    # promoting a typo into a permissive setting.
    hilt_min_severity: str = ""


@dataclass
class FirstRunReport:
    """Full structured summary returned by ``run_first_run``."""

    status: str
    config_file: str
    data_dir: str
    connector: str
    profile: str
    setup: list[StepResult] = field(default_factory=list)
    readiness: list[StepResult] = field(default_factory=list)
    next_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "config_file": self.config_file,
            "data_dir": self.data_dir,
            "connector": self.connector,
            "profile": self.profile,
            "setup": [s.to_dict() for s in self.setup],
            "readiness": [s.to_dict() for s in self.readiness],
            "next_commands": self.next_commands,
        }


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


def run_first_run(options: FirstRunOptions) -> FirstRunReport:
    """Run the canonical first-run setup flow without rendering UI.

    This is the backend shared by ``defenseclaw init``, ``quickstart``,
    installer handoff, and the Go TUI. It mutates only DefenseClaw-owned
    files unless the selected connector setup later runs inside the
    gateway. Secrets supplied as flags are persisted to ``.env`` and the
    config stores only env-var names.
    """
    from defenseclaw import config as cfg_mod
    from defenseclaw.context import AppContext
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    setup: list[StepResult] = []
    connector = _normalize_connector(options.connector)
    profile = _normalize_profile(options.profile, connector)
    scanner_mode = _normalize_scanner_mode(options.scanner_mode)

    new_config = not os.path.exists(cfg_mod.config_path())
    try:
        cfg = cfg_mod.load()
    except Exception:
        cfg = cfg_mod.default_config()
        new_config = True

    cfg.environment = cfg_mod.detect_environment()
    _apply_first_run_choices(cfg, options, connector, profile, scanner_mode)

    try:
        cfg.save()
        setup.append(StepResult(
            "Config",
            "pass",
            "created defaults" if new_config else "preserved existing config",
        ))
    except OSError as exc:
        setup.append(StepResult("Config", "fail", str(exc), "defenseclaw config validate"))

    store = Store(cfg.audit_db)
    try:
        store.init()
    except Exception as exc:  # broad: sqlite/file errors need to surface
        setup.append(StepResult("Audit DB", "fail", str(exc), "defenseclaw doctor --fix"))
    logger = Logger(store, cfg.splunk)

    try:
        bootstrap = bootstrap_env(cfg, logger)
        if bootstrap.errors:
            setup.extend(StepResult("Bootstrap", "fail", e, "defenseclaw doctor --fix") for e in bootstrap.errors)
        else:
            setup.append(StepResult("Bootstrap", "pass", cfg.data_dir))
    finally:
        pass

    _persist_first_run_secrets(cfg, options, setup)

    if options.skip_install:
        setup.append(StepResult("Scanners", "skip", "--skip-install"))
    else:
        scanner_status = _scanner_availability(cfg)
        setup.extend(scanner_status)

    app = AppContext()
    app.cfg = cfg
    app.store = store
    app.logger = logger

    setup.append(_quiet_guardrail_setup(app, connector, verbose=options.verbose))

    if options.sandbox:
        setup.append(StepResult(
            "Sandbox",
            "warn",
            "sandbox bootstrap remains Linux-only; run the dedicated sandbox setup",
            "defenseclaw sandbox setup",
        ))

    if options.start_gateway:
        setup.append(_start_gateway_structured(cfg))
    else:
        setup.append(StepResult("Sidecar", "skip", "not started (--no-start-gateway)", "defenseclaw-gateway start"))

    try:
        cfg.save()
    except OSError as exc:
        setup.append(StepResult("Config Save", "fail", str(exc), "defenseclaw config validate"))

    readiness = targeted_readiness(cfg, options) if options.verify else [
        StepResult("Readiness", "skip", "--no-verify", "defenseclaw doctor")
    ]

    try:
        logger.close()
    finally:
        store.close()

    next_commands = _next_commands(setup, readiness, cfg, profile)
    status = _rollup_status(setup, readiness)
    return FirstRunReport(
        status=status,
        config_file=str(cfg_mod.config_path()),
        data_dir=cfg.data_dir,
        connector=connector,
        profile=profile,
        setup=setup,
        readiness=readiness,
        next_commands=next_commands,
    )


def targeted_readiness(cfg: Config, options: FirstRunOptions) -> list[StepResult]:
    """Run scoped readiness checks for the choices made during first run."""
    steps: list[StepResult] = []
    cfg_path = os.path.join(cfg.data_dir, "config.yaml")
    steps.append(StepResult(
        "Config file",
        "pass" if os.path.isfile(cfg_path) else "fail",
        cfg_path if os.path.isfile(cfg_path) else "missing",
        "defenseclaw init" if not os.path.isfile(cfg_path) else "",
    ))
    steps.append(StepResult(
        "Audit database",
        "pass" if os.path.isfile(cfg.audit_db) else "fail",
        cfg.audit_db,
        "defenseclaw doctor --fix" if not os.path.isfile(cfg.audit_db) else "",
    ))
    device_key = cfg.gateway.device_key_file
    steps.append(StepResult(
        "Device key",
        "pass" if device_key and os.path.isfile(device_key) else "fail",
        device_key or "(unset)",
        "defenseclaw doctor --fix" if not (device_key and os.path.isfile(device_key)) else "",
    ))

    for s in _scanner_availability(cfg):
        if s.status == "warn":
            s.detail += " — scans are unavailable until this binary is installed"
        steps.append(s)

    connector = _normalize_connector(options.connector)
    steps.append(_connector_readiness(cfg, connector))

    if options.start_gateway:
        pid_file = os.path.join(cfg.data_dir, "gateway.pid")
        running = _pid_file_running(pid_file)
        steps.append(StepResult(
            "Sidecar",
            "pass" if running else "warn",
            "running" if running else "not confirmed after start",
            "defenseclaw-gateway status" if not running else "",
        ))

    llm = cfg.resolve_llm("guardrail")
    if cfg.guardrail.enabled and llm.is_local_provider():
        if llm.base_url:
            steps.append(_tcpish_url_probe("Local LLM", llm.base_url, timeout=3.0))
        else:
            steps.append(StepResult("Local LLM", "warn", "local provider set without base_url"))
    elif cfg.guardrail.enabled and (llm.model or options.llm_api_key or llm.api_key):
        steps.append(_doctor_check("_check_llm_api_key", cfg, "LLM API key"))
    else:
        steps.append(StepResult("LLM API", "skip", "not configured"))

    if cfg.guardrail.enabled and cfg.guardrail.scanner_mode in ("remote", "both"):
        steps.append(_doctor_check("_check_cisco_ai_defense", cfg, "Cisco AI Defense"))
    else:
        steps.append(StepResult("Cisco AI Defense", "skip", "scanner_mode is local"))

    if shutil.which("defenseclaw-gateway") is None:
        steps.append(StepResult(
            "Gateway binary",
            "warn",
            "defenseclaw-gateway not on PATH",
            "make gateway-install",
        ))
    else:
        steps.append(StepResult("Gateway binary", "pass", "found on PATH"))

    return steps


def _normalize_connector(raw: str | None) -> str:
    from defenseclaw import connector_paths

    value = (raw or "").strip().lower()
    if value in {"claude", "claude-code", "claude_code"}:
        value = "claudecode"
    if value in {"none", ""}:
        value = "codex"
    try:
        return connector_paths.normalize(value)
    except Exception:
        return value or "openclaw"


def _normalize_profile(raw: str, connector: str) -> str:
    value = (raw or "").strip().lower()
    if value == "telemetry":
        return "observe"
    if value in {"observe", "action"}:
        return value
    return "observe"


def _normalize_scanner_mode(raw: str) -> str:
    value = (raw or "").strip().lower()
    return value if value in {"local", "remote", "both"} else "local"


def _apply_first_run_choices(
    cfg: Config,
    options: FirstRunOptions,
    connector: str,
    profile: str,
    scanner_mode: str,
) -> None:
    cfg.claw.mode = connector
    cfg.guardrail.connector = connector
    cfg.guardrail.scanner_mode = scanner_mode
    cfg.guardrail.mode = "action" if profile == "action" else "observe"
    cfg.guardrail.enabled = True
    cfg.guardrail.judge.enabled = bool(options.with_judge)
    cfg.guardrail.detection_strategy = cfg.guardrail.detection_strategy or "regex_judge"
    if connector == "codex":
        cfg.guardrail.codex_enforcement_enabled = profile == "action"
    if connector == "claudecode":
        cfg.guardrail.claudecode_enforcement_enabled = profile == "action"

    # Honor an explicit operator choice supplied via flag/prompt.
    # Empty string means "leave whatever was loaded alone" — usually
    # the canonical default ("open") seeded by _migrate_0_4_0 or by
    # default_config(). Anything other than the literal "closed"
    # sentinel is silently downgraded to "open" because failing-open
    # on a typo is strictly safer than failing-closed and bricking
    # the agent. Mirrors normalizeHookFailMode in
    # internal/gateway/connector/subprocess.go and
    # _normalize_hook_fail_mode in cli/defenseclaw/config.py.
    desired = (options.hook_fail_mode or "").strip().lower()
    if desired:
        cfg.guardrail.hook_fail_mode = "closed" if desired == "closed" else "open"

    # Human-In-the-Loop (HITL). ``None`` is the no-op sentinel so
    # init/quickstart reruns don't clobber an operator who already
    # enabled approvals via ``defenseclaw setup guardrail``.
    if options.human_approval is not None:
        cfg.guardrail.hilt.enabled = bool(options.human_approval)

    # Severity floor: empty string preserves; valid value normalizes
    # to uppercase; anything else falls back to ``"HIGH"``. Mirrors
    # _apply_guardrail_extra_options in cmd_setup.py so the init
    # path and the setup path can never disagree on which
    # severities trigger an approval prompt.
    severity = (options.hilt_min_severity or "").strip().upper()
    if severity:
        cfg.guardrail.hilt.min_severity = (
            severity if severity in HILT_MIN_SEVERITIES else "HIGH"
        )

    # Defensive: if we just enabled HITL but the existing
    # min_severity is empty (default_config seeds "HIGH" but
    # round-tripped configs from older versions may have lost
    # it), backfill the canonical "HIGH" floor. Critical for
    # making sure the prompt actually fires for *something* —
    # an empty floor would let every finding skip the prompt.
    if cfg.guardrail.hilt.enabled and not cfg.guardrail.hilt.min_severity:
        cfg.guardrail.hilt.min_severity = "HIGH"

    if options.llm_provider:
        cfg.llm.provider = options.llm_provider.strip()
    if options.llm_model:
        model = options.llm_model.strip()
        if options.llm_provider and "/" not in model:
            model = f"{options.llm_provider.strip()}/{model}"
        cfg.llm.model = model
    if options.llm_api_key_env:
        cfg.llm.api_key_env = options.llm_api_key_env.strip()
    if options.llm_base_url:
        cfg.llm.base_url = options.llm_base_url.strip()

    if options.cisco_endpoint:
        cfg.cisco_ai_defense.endpoint = options.cisco_endpoint.strip()
    if options.cisco_api_key_env:
        cfg.cisco_ai_defense.api_key_env = options.cisco_api_key_env.strip()


def _persist_first_run_secrets(cfg: Config, options: FirstRunOptions, steps: list[StepResult]) -> None:
    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    secrets = [
        ("LLM API key", options.llm_api_key_env, options.llm_api_key),
        ("Cisco AI Defense key", options.cisco_api_key_env, options.cisco_api_key),
    ]
    for label, env_name, value in secrets:
        env_name = (env_name or "").strip()
        value = value or ""
        if not value:
            continue
        if not _valid_env_name(env_name):
            steps.append(StepResult(label, "fail", f"invalid env var name: {env_name!r}"))
            continue
        try:
            _save_secret_to_dotenv(env_name, value, cfg.data_dir)
            steps.append(StepResult(label, "pass", f"saved to .env as {env_name}"))
        except Exception as exc:
            steps.append(StepResult(label, "fail", str(exc), f"defenseclaw keys set {env_name}"))


def _valid_env_name(value: str) -> bool:
    if not value:
        return False
    if not (value[0].isalpha() or value[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in value)


def _scanner_availability(cfg: Config) -> list[StepResult]:
    scanners = [
        ("Skill scanner", cfg.scanners.skill_scanner.binary, "defenseclaw setup skill-scanner"),
        ("MCP scanner", cfg.scanners.mcp_scanner.binary, "defenseclaw setup mcp-scanner"),
    ]
    out: list[StepResult] = []
    for label, binary, next_command in scanners:
        path = shutil.which(binary)
        if path:
            out.append(StepResult(label, "pass", path))
        else:
            out.append(StepResult(label, "warn", f"{binary!r} not on PATH", next_command))
    return out


def _quiet_guardrail_setup(app, connector: str, *, verbose: bool) -> StepResult:
    from defenseclaw.commands.cmd_setup import execute_guardrail_setup

    if connector == "openclaw":
        oc_path = os.path.expanduser(app.cfg.claw.config_file)
        if not os.path.isfile(oc_path):
            try:
                app.cfg.save()
            except OSError:
                pass
            return StepResult(
                "Guardrail",
                "warn",
                f"OpenClaw config not found at {app.cfg.claw.config_file}; saved config but skipped connector patch",
                "defenseclaw setup guardrail",
            )

    buf = io.StringIO()
    sink = contextlib.nullcontext() if verbose else contextlib.redirect_stdout(buf)
    try:
        with sink:
            ok, warnings = execute_guardrail_setup(app, save_config=True)
    except Exception as exc:
        detail = str(exc)
        if not verbose and buf.getvalue().strip():
            detail += " | " + buf.getvalue().strip().splitlines()[-1]
        return StepResult("Guardrail", "fail", detail, "defenseclaw setup guardrail")
    if ok and not warnings:
        return StepResult("Guardrail", "pass", f"{connector}, mode={app.cfg.guardrail.mode}")
    if ok:
        return StepResult("Guardrail", "warn", "; ".join(warnings), "defenseclaw doctor")
    return StepResult("Guardrail", "fail", "setup returned false", "defenseclaw setup guardrail")


def _running_connector_from_state_file(data_dir: str) -> str | None:
    """Return the connector name the running sidecar booted with, or None.

    The sidecar persists its active connector to
    ``<data_dir>/active_connector.json`` after a successful
    ``Connector.Setup`` (see ``internal/gateway/connector/
    connector_state.go::SaveActiveConnector``). Reading that file is
    the cheapest way to learn what the live gateway is actually
    serving without going over HTTP — useful when the gateway is
    healthy but configured to a stale connector because ``init``
    short-circuited on ``Sidecar already running`` instead of
    bouncing it.

    Returns:
        Lowercased, whitespace-trimmed connector name, OR ``None``
        when the file is absent / unreadable / malformed. ``None``
        is the "I don't know" sentinel — callers must treat it as
        "no drift detectable" rather than "drift detected", because
        an older sidecar binary that pre-dates connector_state.go
        won't have written this file at all and we'd rather risk a
        skipped restart than a spurious one that disrupts in-flight
        sessions.
    """
    path = os.path.join(data_dir, "active_connector.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, OSError, ValueError):
        return None
    name = data.get("name") if isinstance(data, dict) else None
    if not isinstance(name, str):
        return None
    name = name.strip().lower()
    return name or None


def _start_gateway_structured(cfg: Config) -> StepResult:
    """Start (or restart) the defenseclaw-gateway sidecar to match
    the on-disk config, returning a structured StepResult.

    Three regimes:

    1. **Not running** → spawn ``defenseclaw-gateway start``.
    2. **Running, configured connector matches the live one** →
       no-op, return ``"already running"``. The cheapest path and
       what most reruns of ``defenseclaw init`` end up doing.
    3. **Running, configured connector differs from the live one** →
       call ``defenseclaw-gateway restart``. This is the path the
       fail-mode/connector-switch UX bug used to short-circuit:
       operators who flipped ``cfg.claw.mode`` from ``codex`` to
       ``openclaw`` via ``init`` would see ``✓ Sidecar already
       running`` and ``defenseclaw status`` would keep reporting
       Codex because the sidecar reads its connector at boot only.

    Drift detection deliberately uses
    ``active_connector.json`` instead of ``/health`` — the file is
    written atomically by the sidecar after a successful
    ``Connector.Setup`` and works even when the gateway is up but
    not yet listening, or when network namespaces / firewalls block
    loopback HTTP. When the file is missing (older sidecar binary,
    fresh post-uninstall reinstall) we conservatively keep the
    legacy "already running" behavior — see
    :func:`_running_connector_from_state_file` for the I-don't-know
    sentinel rule.
    """
    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return StepResult("Sidecar", "warn", "defenseclaw-gateway not on PATH", "make gateway-install")
    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    if _pid_file_running(pid_file):
        # Compare what the live sidecar booted with against what
        # the just-saved config says it *should* be running. Drift
        # implies init/quickstart/migration changed the connector
        # while the gateway was up — restart so the new config
        # takes effect now instead of "next time the operator
        # bounces the daemon themselves".
        desired = cfg.active_connector()
        running = _running_connector_from_state_file(cfg.data_dir)
        if running is not None and running != desired:
            try:
                result = subprocess.run(
                    [gw, "restart"], capture_output=True, text=True, timeout=30,
                )
            except subprocess.TimeoutExpired:
                return StepResult(
                    "Sidecar", "warn",
                    f"connector drift detected ({running} → {desired}) but restart timed out",
                    "defenseclaw-gateway restart",
                )
            except OSError as exc:
                return StepResult(
                    "Sidecar", "warn",
                    f"connector drift detected ({running} → {desired}): {exc}",
                    "defenseclaw-gateway restart",
                )
            if result.returncode == 0:
                return StepResult(
                    "Sidecar", "pass",
                    f"restarted (was {running}, now {desired})",
                )
            detail = (result.stderr or result.stdout or "restart failed").strip().splitlines()
            return StepResult(
                "Sidecar", "warn",
                f"connector drift detected ({running} → {desired}) but restart failed: "
                f"{detail[0] if detail else 'restart failed'}",
                "defenseclaw-gateway restart",
            )
        return StepResult("Sidecar", "pass", "already running")
    try:
        result = subprocess.run([gw, "start"], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return StepResult("Sidecar", "warn", "start timed out", "defenseclaw-gateway status")
    except OSError as exc:
        return StepResult("Sidecar", "warn", str(exc), "defenseclaw-gateway status")
    if result.returncode == 0:
        return StepResult("Sidecar", "pass", "started")
    detail = (result.stderr or result.stdout or "start failed").strip().splitlines()
    return StepResult("Sidecar", "warn", detail[0] if detail else "start failed", "defenseclaw-gateway status")


def _pid_file_running(pid_file: str) -> bool:
    try:
        with open(pid_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
        try:
            pid = int(raw)
        except ValueError:
            pid = int(json.loads(raw)["pid"])
    except (FileNotFoundError, ValueError, KeyError, OSError, TypeError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _connector_readiness(cfg: Config, connector: str) -> StepResult:
    if connector == "openclaw":
        path = os.path.expanduser(cfg.claw.config_file)
        if os.path.isfile(path):
            return StepResult("Connector", "pass", f"OpenClaw config found: {cfg.claw.config_file}")
        return StepResult(
            "Connector",
            "warn",
            f"OpenClaw config missing: {cfg.claw.config_file}",
            "defenseclaw setup mode openclaw",
        )
    if connector == "codex":
        path = os.path.expanduser("~/.codex/config.toml")
        if os.path.isfile(path):
            return StepResult("Connector", "pass", "Codex config found")
        return StepResult("Connector", "warn", "Codex config not found yet", "defenseclaw setup codex")
    if connector == "claudecode":
        path = os.path.expanduser("~/.claude/settings.json")
        if os.path.isfile(path):
            return StepResult("Connector", "pass", "Claude Code settings found")
        return StepResult("Connector", "warn", "Claude Code settings not found yet", "defenseclaw setup claude-code")
    if connector == "zeptoclaw":
        path = os.path.expanduser("~/.zeptoclaw/config.json")
        if os.path.isfile(path):
            return StepResult("Connector", "pass", "ZeptoClaw config found")
        return StepResult("Connector", "warn", "ZeptoClaw config not found yet", "defenseclaw setup mode zeptoclaw")
    return StepResult("Connector", "warn", f"unknown connector {connector!r}")


def _doctor_check(fn_name: str, cfg: Config, label: str) -> StepResult:
    from defenseclaw.commands import cmd_doctor

    result = cmd_doctor._DoctorResult()
    previous = cmd_doctor._json_mode
    cmd_doctor._json_mode = True
    try:
        getattr(cmd_doctor, fn_name)(cfg, result)
    except Exception as exc:
        return StepResult(label, "warn", str(exc), "defenseclaw doctor")
    finally:
        cmd_doctor._json_mode = previous
    if result.failed:
        status = "fail"
    elif result.warned:
        status = "warn"
    elif result.passed:
        status = "pass"
    else:
        status = "skip"
    detail = ""
    for check in result.checks:
        if check.get("label") == label or not detail:
            detail = check.get("detail", "")
            if check.get("label") == label:
                break
    return StepResult(label, status, detail, "defenseclaw doctor" if status in {"fail", "warn"} else "")


def _tcpish_url_probe(label: str, raw_url: str, *, timeout: float) -> StepResult:
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    host = parsed.hostname
    port = parsed.port
    if not host:
        return StepResult(label, "warn", f"invalid URL: {raw_url}")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return StepResult(label, "pass", f"{host}:{port} reachable")
    except OSError as exc:
        return StepResult(label, "warn", f"{host}:{port} unreachable: {exc}", "defenseclaw doctor")


def _rollup_status(setup: list[StepResult], readiness: list[StepResult]) -> str:
    all_steps = setup + readiness
    if any(s.status == "fail" for s in all_steps):
        return "needs_attention"
    if any(s.status == "warn" for s in all_steps):
        return "partial"
    return "ready"


def _next_commands(
    setup: list[StepResult],
    readiness: list[StepResult],
    cfg: Config,
    profile: str,
) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()
    for step in setup + readiness:
        if step.next_command and step.next_command not in seen:
            commands.append(step.next_command)
            seen.add(step.next_command)
    if "defenseclaw doctor" not in seen:
        commands.append("defenseclaw doctor")
    if getattr(cfg, "data_dir", "") and "defenseclaw keys list" not in seen:
        commands.append("defenseclaw keys list")
    return commands


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
