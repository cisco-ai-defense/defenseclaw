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

"""defenseclaw init — Initialize DefenseClaw environment.

Mirrors internal/cli/init.go.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import click

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.paths import (
    bundled_guardrail_profiles_dir,
    bundled_local_observability_dir,
    bundled_rego_dir,
    bundled_splunk_bridge_dir,
)


@click.command("init")
@click.option("--skip-install", is_flag=True, help="Skip automatic scanner dependency installation")
@click.option("--enable-guardrail", is_flag=True, help="Configure LLM guardrail during init")
@click.option("--sandbox", is_flag=True, help="Set up sandbox mode (Linux only: creates sandbox user and directories)")
@pass_ctx
def init_cmd(app: AppContext, skip_install: bool, enable_guardrail: bool, sandbox: bool) -> None:
    """Initialize DefenseClaw environment.

    Creates ~/.defenseclaw/, default config, SQLite database,
    and installs scanner dependencies.

    Use --sandbox to set up openshell-sandbox standalone mode (Linux only).
    Use --enable-guardrail to configure the LLM guardrail inline.
    """
    import platform

    from defenseclaw.config import config_path, default_config, detect_environment, load
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    if sandbox and platform.system() != "Linux":
        click.echo("  ERROR: Sandbox mode requires Linux.", err=True)
        raise SystemExit(1)

    click.echo()
    click.echo("  ── Environment ───────────────────────────────────────")
    click.echo()

    from defenseclaw import __version__
    click.echo(f"  DefenseClaw:   v{__version__}")
    gw_version = _get_gateway_version()
    if gw_version:
        click.echo(f"  Gateway:       {gw_version}")
    else:
        click.echo("  Gateway:       not found")

    env = detect_environment()
    click.echo(f"  Platform:      {env}")

    cfg_file = config_path()
    is_new_config = not os.path.exists(cfg_file)
    if is_new_config:
        cfg = default_config()
        click.echo("  Config:        created new defaults")
    else:
        cfg = load()
        click.echo("  Config:        preserved existing")

    cfg.environment = env
    click.echo(f"  Claw mode:     {cfg.claw.mode}")
    click.echo(f"  Claw home:     {cfg.claw_home_dir()}")

    dirs = [
        cfg.data_dir, cfg.quarantine_dir,
        cfg.plugin_dir, cfg.policy_dir,
    ]

    data_dir_real = os.path.realpath(cfg.data_dir)
    for d in dirs:
        os.makedirs(d, exist_ok=True)

    external_dirs = list(cfg.skill_dirs())
    for d in external_dirs:
        d_real = os.path.realpath(d)
        if d_real.startswith(data_dir_real + os.sep):
            os.makedirs(d, exist_ok=True)
    click.echo("  Directories:   created")

    _seed_rego_policies(cfg.policy_dir)
    _seed_guardrail_profiles(cfg.policy_dir)
    _seed_splunk_bridge(cfg.data_dir)
    _seed_local_observability_stack(cfg.data_dir)

    cfg.save()
    click.echo(f"  Config file:   {cfg_file}")

    store = Store(cfg.audit_db)
    store.init()
    click.echo(f"  Audit DB:      {cfg.audit_db}")

    logger = Logger(store, cfg.splunk)
    logger.log_action("init", cfg.data_dir, f"environment={env}")

    click.echo()
    click.echo("  ── Scanners ──────────────────────────────────────────")
    click.echo()
    _install_scanners(cfg, logger, skip_install)
    _show_scanner_defaults(cfg)

    click.echo()
    click.echo("  ── Gateway ───────────────────────────────────────────")
    click.echo()
    _setup_gateway_defaults(cfg, logger, is_new_config=is_new_config)

    click.echo()
    click.echo("  ── Guardrail ─────────────────────────────────────────")
    click.echo()
    guardrail_ok = False
    if enable_guardrail:
        guardrail_ok = _setup_guardrail_inline(app, cfg, logger)
    else:
        _install_guardrail(cfg, logger, skip_install)
        click.echo()
        click.echo("  Run 'defenseclaw init --enable-guardrail' or")
        click.echo("  'defenseclaw setup guardrail' to enable the guardrail proxy.")

    click.echo()
    click.echo("  ── Skills ────────────────────────────────────────────")
    click.echo()
    if cfg.openshell.is_standalone():
        click.echo("  CodeGuard:     deferred (installed during sandbox setup)")
    else:
        _install_codeguard_skill(cfg, logger)

    cfg.save()

    # Sandbox setup (Linux only)
    if sandbox:
        already_configured = cfg.openshell.is_standalone()
        if already_configured:
            click.echo()
            click.echo("  ── Sandbox ───────────────────────────────────────────")
            click.echo()
            click.echo("  Sandbox:       already configured (openshell.mode=standalone)")
        else:
            click.echo()
            click.echo("  ── Sandbox ───────────────────────────────────────────")
            click.echo()
            from defenseclaw.commands.cmd_init_sandbox import _init_sandbox
            sandbox_ok = _init_sandbox(cfg, logger)

            if sandbox_ok:
                click.echo()
                click.echo("  ── Sandbox Networking ────────────────────────────────")
                click.echo()
                from defenseclaw.commands.cmd_setup_sandbox import setup_sandbox
                app.cfg = cfg
                ctx = click.Context(setup_sandbox, parent=click.get_current_context())
                ctx.invoke(setup_sandbox, sandbox_ip="10.200.0.2", host_ip="10.200.0.1",
                           sandbox_home=None, openclaw_port=18789, dns="8.8.8.8,1.1.1.1",
                           policy="default", no_auto_pair=False, disable=False,
                           non_interactive=True)

    sidecar_started = False
    if not sandbox:
        click.echo()
        click.echo("  ── Sidecar ───────────────────────────────────────────")
        click.echo()
        _start_gateway(cfg, logger)
        sidecar_started = True

        if guardrail_ok and sidecar_started:
            click.echo("  Restarting sidecar to apply guardrail config...")
            _restart_gateway_quiet()

    click.echo()
    click.echo("  ──────────────────────────────────────────────────────")
    click.echo()
    click.echo("  DefenseClaw initialized.")
    click.echo()
    click.echo("  Next steps:")
    if sandbox and not guardrail_ok:
        click.echo("    defenseclaw setup guardrail   Enable LLM traffic inspection")
    elif not guardrail_ok:
        click.echo("    defenseclaw setup guardrail   Enable LLM traffic inspection")
    if not sidecar_started and not sandbox:
        click.echo("    defenseclaw-gateway start     Start the sidecar")
    click.echo("    defenseclaw setup            Customize scanners and policies")
    click.echo("    defenseclaw doctor           Verify connectivity and credentials")
    click.echo("    defenseclaw skill scan all   Scan installed OpenClaw skills")
    click.echo("    defenseclaw mcp scan --all   Scan configured MCP servers")

    store.close()


def _seed_rego_policies(policy_dir: str) -> None:
    """Copy bundled Rego policies into the user's policy_dir if not already present."""
    bundled_rego = bundled_rego_dir()
    if not bundled_rego.is_dir():
        return

    dest_rego = os.path.join(policy_dir, "rego")
    os.makedirs(dest_rego, exist_ok=True)

    for src in bundled_rego.iterdir():
        if src.suffix in (".rego", ".json") and not src.name.startswith("."):
            dst = os.path.join(dest_rego, src.name)
            if not os.path.exists(dst):
                shutil.copy2(str(src), dst)

    click.echo(f"  Rego policies: {dest_rego}")


def _seed_guardrail_profiles(policy_dir: str) -> None:
    """Copy bundled guardrail rule-pack profiles (default/strict/permissive) into
    the user's policy_dir if not already present. Operators can then edit the
    YAML in place and `defenseclaw policy reload` will pick up the changes.
    """
    bundled = bundled_guardrail_profiles_dir()
    if bundled is None:
        return

    dest_root = os.path.join(policy_dir, "guardrail")
    os.makedirs(dest_root, exist_ok=True)

    seeded: list[str] = []
    preserved: list[str] = []
    for profile_dir in bundled.iterdir():
        if not profile_dir.is_dir() or profile_dir.name.startswith("."):
            continue
        dst = os.path.join(dest_root, profile_dir.name)
        if os.path.isdir(dst):
            preserved.append(profile_dir.name)
            continue
        shutil.copytree(str(profile_dir), dst)
        seeded.append(profile_dir.name)

    if seeded:
        click.echo(f"  Guardrail rule packs: seeded {', '.join(sorted(seeded))} in {dest_root}")
    if preserved:
        click.echo(f"  Guardrail rule packs: preserved existing ({', '.join(sorted(preserved))})")


def _seed_splunk_bridge(data_dir: str) -> None:
    """Copy vendored Splunk bridge runtime into ~/.defenseclaw/splunk-bridge/."""
    bundled = _resolve_splunk_bridge_bundle()
    if not bundled.is_dir():
        return

    dest = os.path.join(data_dir, "splunk-bridge")
    if os.path.isdir(dest):
        click.echo(f"  Splunk bridge: preserved existing ({dest})")
        return

    shutil.copytree(str(bundled), dest)
    bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
    if os.path.isfile(bridge_bin):
        os.chmod(bridge_bin, 0o755)
    click.echo(f"  Splunk bridge: seeded in {dest}")


def _resolve_splunk_bridge_bundle():
    """Resolve the vendored local Splunk runtime from package data or source tree."""
    return bundled_splunk_bridge_dir()


def _seed_local_observability_stack(data_dir: str) -> None:
    """Copy bundled Prom/Loki/Tempo/Grafana stack into ~/.defenseclaw/observability-stack/.

    Mirrors _seed_splunk_bridge so ``defenseclaw setup
    local-observability`` can drive a user-editable copy of the stack
    (dashboards, alert rules, prom config) without requiring the
    operator to unpack the wheel. Preserves an existing seeded copy so
    operator edits survive subsequent ``init`` runs.
    """
    bundled = bundled_local_observability_dir()
    if not bundled.is_dir():
        return

    dest = os.path.join(data_dir, "observability-stack")
    if os.path.isdir(dest):
        click.echo(f"  Observability stack: preserved existing ({dest})")
        return

    shutil.copytree(str(bundled), dest)
    bridge_bin = os.path.join(dest, "bin", "openclaw-observability-bridge")
    if os.path.isfile(bridge_bin):
        os.chmod(bridge_bin, 0o755)
    shim = os.path.join(dest, "run.sh")
    if os.path.isfile(shim):
        os.chmod(shim, 0o755)
    click.echo(f"  Observability stack: seeded in {dest}")


def _install_scanners(cfg, logger, skip: bool) -> None:
    if skip:
        click.echo("  Scanners:      skipped (--skip-install)")
        return

    _verify_scanner_sdk("skill-scanner", "skill_scanner")
    _verify_scanner_sdk("mcp-scanner", "mcpscanner", min_python=(3, 11))


def _verify_scanner_sdk(name: str, import_name: str, min_python: tuple[int, ...] | None = None) -> None:
    """Check that a scanner SDK is importable; report status."""
    import importlib
    import sys

    pad = max(14 - len(name), 1)
    label = name + ":" + " " * pad

    if min_python and sys.version_info < min_python:
        ver = ".".join(str(v) for v in min_python)
        click.echo(f"  {label}requires Python >={ver} (skipped)")
        return

    try:
        importlib.import_module(import_name)
        click.echo(f"  {label}available")
    except ImportError:
        click.echo(f"  {label}not installed")
        click.echo("                 install with: pip install defenseclaw")


def _show_scanner_defaults(cfg) -> None:
    """Display the default scanner configuration set during init."""
    sc = cfg.scanners.skill_scanner
    mc = cfg.scanners.mcp_scanner

    click.echo()
    click.echo(f"  skill-scanner: policy={sc.policy}, lenient={sc.lenient}")
    click.echo(f"  mcp-scanner:   analyzers={mc.analyzers}")
    click.echo()
    click.echo("  Run 'defenseclaw setup' to customize scanner settings.")


def _ensure_device_key(path: str) -> None:
    """Create the Ed25519 device key file if it doesn't exist.

    The Go gateway creates this on first start, but the guardrail setup
    needs it earlier to derive the proxy master key. Uses the same PEM
    format as internal/gateway/device.go.
    """
    if os.path.exists(path):
        return
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    os.makedirs(os.path.dirname(path), exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    import base64
    b64_seed = base64.b64encode(seed).decode()
    pem_data = (
        "-----BEGIN ED25519 PRIVATE KEY-----\n"
        f"{b64_seed}\n"
        "-----END ED25519 PRIVATE KEY-----\n"
    )
    # Create the file with 0o600 atomically so the key is never
    # world-readable, even for the brief window between open() and
    # the previous chmod(). ``O_EXCL`` ensures we don't overwrite a
    # concurrently-created key (idempotent early-exit already covered
    # the is-it-there case above).
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        # Another process won the race — trust its key and exit.
        return
    with os.fdopen(fd, "w") as f:
        f.write(pem_data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _resolve_openclaw_gateway(claw_config_file: str) -> dict[str, str | int]:
    """Read gateway host, port, and token from openclaw.json.

    Looks for gateway.port and gateway.auth.token when gateway.mode is 'local'.
    Always uses the shared gateway.auth.token — device-auth.json is a
    client-side cache used by the OpenClaw Node.js client, not by our Go gateway.
    """
    from defenseclaw.config import _read_openclaw_config

    result: dict[str, str | int] = {
        "host": "127.0.0.1",
        "port": 18789,
        "token": "",
    }

    oc = _read_openclaw_config(claw_config_file)
    if not oc:
        return result

    gw = oc.get("gateway", {})
    if not isinstance(gw, dict):
        return result

    mode = gw.get("mode", "local")
    if mode == "local":
        result["host"] = "127.0.0.1"
    else:
        result["host"] = gw.get("host", "127.0.0.1")

    if "port" in gw:
        try:
            result["port"] = int(gw["port"])
        except (ValueError, TypeError):
            pass

    auth = gw.get("auth", {})
    if isinstance(auth, dict):
        token = auth.get("token", "")
        if token:
            result["token"] = token

    return result


def _setup_gateway_defaults(cfg, logger, is_new_config: bool = True) -> None:
    """Resolve gateway settings from OpenClaw and display them.

    Only applies OpenClaw values (host/port/token) when creating a new config.
    Existing configs preserve user-customized gateway settings.
    """
    oc_gw = _resolve_openclaw_gateway(cfg.claw.config_file)
    token_configured = False
    if is_new_config:
        cfg.gateway.host = oc_gw["host"]
        cfg.gateway.port = oc_gw["port"]

    # Always re-sync the token from openclaw.json — it may have changed
    # after re-onboarding or OpenClaw restart.
    if oc_gw["token"]:
        from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", oc_gw["token"], cfg.data_dir)
        cfg.gateway.token = ""
        cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        token_configured = True
    else:
        cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        token_configured = bool(cfg.gateway.resolved_token())

    if not cfg.gateway.device_key_file:
        cfg.gateway.device_key_file = os.path.join(cfg.data_dir, "device.key")

    _ensure_device_key(cfg.gateway.device_key_file)

    click.echo(f"  OpenClaw:      {cfg.gateway.host}:{cfg.gateway.port}")
    token_status = "configured" if token_configured else "none (local)"
    click.echo(f"  Token:         {token_status}")
    click.echo(f"  API port:      {cfg.gateway.api_port}")
    click.echo(f"  Watcher:       enabled={cfg.gateway.watcher.enabled}")
    click.echo(f"  Skill watch:   enabled={cfg.gateway.watcher.skill.enabled}, "
               f"take_action={cfg.gateway.watcher.skill.take_action}")
    plugin_dirs = cfg.gateway.watcher.plugin.dirs or cfg.plugin_dirs()
    click.echo(f"  Plugin watch:  enabled={cfg.gateway.watcher.plugin.enabled}, "
               f"take_action={cfg.gateway.watcher.plugin.take_action}")
    click.echo(f"  Plugin dirs:   {', '.join(plugin_dirs)}")
    click.echo(f"  Device key:    {cfg.gateway.device_key_file}")
    click.echo()
    click.echo("  Run 'defenseclaw setup gateway' to customize.")

    logger.log_action("init-gateway", "config",
                       f"host={cfg.gateway.host} port={cfg.gateway.port}")


def _install_guardrail(cfg, logger, skip: bool) -> None:
    """Report guardrail proxy status (built into Go binary, no external deps)."""
    if skip:
        click.echo("  Guardrail:     skipped (--skip-install)")
        return

    click.echo("  Guardrail:     built into Go binary (no external dependencies)")
    logger.log_action("install-dep", "guardrail", "builtin")


def _ensure_uv() -> None:
    if shutil.which("uv"):
        return

    click.echo("  uv: not found, installing...", nl=False)
    try:
        subprocess.run(
            ["sh", "-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
            capture_output=True, check=True,
        )
        _add_uv_to_path()
        click.echo(" done")
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo(" failed")
        click.echo("    install uv manually: curl -LsSf https://astral.sh/uv/install.sh | sh")
        click.echo("    then re-run: defenseclaw init")


def _add_uv_to_path() -> None:
    home = os.path.expanduser("~")
    for extra in [f"{home}/.local/bin", f"{home}/.cargo/bin"]:
        if extra not in os.environ.get("PATH", ""):
            os.environ["PATH"] = extra + ":" + os.environ.get("PATH", "")


def _install_with_uv(pkg: str) -> bool:
    uv = shutil.which("uv")
    if not uv:
        return False
    try:
        result = subprocess.run(
            [uv, "tool", "install", "--python", "3.13", pkg],
            capture_output=True, text=True,
        )
        if result.returncode == 0 or "already installed" in result.stderr:
            return True
        return False
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _install_codeguard_skill(cfg, logger) -> None:
    """Install the CodeGuard proactive skill into the OpenClaw skills directory."""
    from defenseclaw.codeguard_skill import install_codeguard_skill

    click.echo("  CodeGuard:     installing...", nl=False)
    status = install_codeguard_skill(cfg)
    click.echo(f" {status}")
    logger.log_action("install-skill", "codeguard", f"status={status}")


def _setup_guardrail_inline(app, cfg, logger) -> bool:
    """Run the full interactive guardrail setup during init.

    Returns True if guardrail was successfully configured.
    """
    from defenseclaw.commands.cmd_setup import (
        _interactive_guardrail_setup,
        execute_guardrail_setup,
    )
    from defenseclaw.context import AppContext

    if not isinstance(app, AppContext):
        app = AppContext()
    app.cfg = cfg
    app.logger = logger

    gc = cfg.guardrail
    _interactive_guardrail_setup(app, gc)

    if not gc.enabled:
        click.echo("  Guardrail not enabled.")
        click.echo("  You can enable it later with 'defenseclaw setup guardrail'.")
        return False

    ok, warnings = execute_guardrail_setup(app, save_config=False)

    if warnings:
        click.echo()
        click.echo("  ── Warnings ──────────────────────────────────────────")
        for w in warnings:
            click.echo(f"  ⚠ {w}")

    if ok:
        click.echo()
        click.echo(f"  Guardrail:     mode={gc.mode}, model={gc.model_name}")
        click.echo("  To disable:    defenseclaw setup guardrail --disable")
        logger.log_action(
            "init-guardrail", "config",
            f"mode={gc.mode} scanner_mode={gc.scanner_mode} port={gc.port} model={gc.model}",
        )

    return ok


def _start_gateway(cfg, logger) -> None:
    """Start the defenseclaw-gateway sidecar and verify it is running."""
    gw_bin = shutil.which("defenseclaw-gateway")
    if not gw_bin:
        click.echo("  Sidecar:       not found (binary not installed)")
        click.echo("                 install with: make gateway-install")
        return

    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    if _is_sidecar_running(pid_file):
        pid = _read_pid(pid_file)
        click.echo(f"  Sidecar:       already running (PID {pid})")
        return

    started = False
    click.echo("  Sidecar:       starting...", nl=False)
    try:
        result = subprocess.run(
            ["defenseclaw-gateway", "start"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            click.echo(" ✓")
            pid = _read_pid(pid_file)
            if pid:
                click.echo(f"  PID:           {pid}")
            logger.log_action("init-sidecar", "start", f"pid={pid or 'unknown'}")
            started = True
        else:
            click.echo(" ✗")
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"                 {line}")
            click.echo("                 check: defenseclaw-gateway status")
    except FileNotFoundError:
        click.echo(" ✗ (binary not found)")
    except subprocess.TimeoutExpired:
        click.echo(" ✗ (timed out)")
        click.echo("                 check: defenseclaw-gateway status")

    if started:
        bind = "127.0.0.1"
        if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost"):
            bind = cfg.guardrail.host
        _check_sidecar_health(cfg.gateway.api_port, bind=bind)


def _get_gateway_version() -> str | None:
    """Try to get the gateway binary version."""
    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return None
    try:
        result = subprocess.run(
            [gw, "--version"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip().split()[-1] if result.stdout.strip() else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _restart_gateway_quiet() -> None:
    """Restart the gateway sidecar silently (used after guardrail setup during init)."""
    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return
    try:
        subprocess.run(
            [gw, "restart"], capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _is_sidecar_running(pid_file: str) -> bool:
    """Check if the gateway sidecar process is alive."""
    pid = _read_pid(pid_file)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _read_pid(pid_file: str) -> int | None:
    """Read PID from the sidecar's PID file."""
    try:
        with open(pid_file) as f:
            raw = f.read().strip()
        try:
            return int(raw)
        except ValueError:
            import json
            return json.loads(raw)["pid"]
    except (FileNotFoundError, ValueError, KeyError, OSError):
        return None


def _check_sidecar_health(api_port: int, retries: int = 3, bind: str = "127.0.0.1") -> dict | None:
    """Poll the sidecar REST API and return parsed health JSON (or None)."""
    import json as _json
    import time
    import urllib.error
    import urllib.request

    url = f"http://{bind}:{api_port}/health"
    for i in range(retries):
        time.sleep(1)
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="replace")
                    try:
                        health = _json.loads(body)
                    except (_json.JSONDecodeError, TypeError):
                        health = None
                    _print_health_summary(health)
                    return health
        except (urllib.error.URLError, OSError, ValueError):
            pass

    click.echo("  Health:        not responding")
    click.echo("                 check: defenseclaw-gateway status")
    return None


def _print_health_summary(health: dict | None) -> None:
    """Render a compact health summary from /health JSON."""
    if not health:
        click.echo("  Health:        ok ✓")
        return

    subsystems = ["gateway", "watcher", "guardrail", "api", "telemetry", "splunk", "sandbox"]
    parts = []
    for sub in subsystems:
        info = health.get(sub, {})
        if not info:
            continue
        state = info.get("state", info.get("status", "unknown"))
        if state.lower() in ("running", "healthy"):
            parts.append(f"{sub}:ok")
        elif state.lower() in ("disabled", "stopped"):
            parts.append(f"{sub}:off")
        else:
            parts.append(f"{sub}:{state}")

    if parts:
        click.echo(f"  Health:        {', '.join(parts)}")
    else:
        click.echo("  Health:        ok ✓")

