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
from defenseclaw.paths import bundled_rego_dir, bundled_splunk_bridge_dir


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
    from defenseclaw.config import config_path, default_config, detect_environment, load
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger
    import platform

    if sandbox and platform.system() != "Linux":
        click.echo("  ERROR: Sandbox mode requires Linux.", err=True)
        raise SystemExit(1)

    click.echo()
    click.echo("  ── Environment ───────────────────────────────────────")
    click.echo()

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
    _seed_splunk_bridge(cfg.data_dir)

    cfg.save()
    click.echo(f"  Config file:   {cfg_file}")

    store = Store(cfg.audit_db)
    store.init()
    click.echo(f"  Audit DB:      {cfg.audit_db}")

    logger = Logger(store)
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
            sandbox_ok = _init_sandbox(cfg, logger)

            if sandbox_ok:
                click.echo()
                click.echo("  ── Sandbox Networking ────────────────────────────────")
                click.echo()
                from defenseclaw.commands.cmd_setup import setup_sandbox
                app.cfg = cfg
                ctx = click.Context(setup_sandbox, parent=click.get_current_context())
                ctx.invoke(setup_sandbox, sandbox_ip="10.200.0.2", host_ip="10.200.0.1",
                           sandbox_home=None, openclaw_port=18789, dns="8.8.8.8,1.1.1.1",
                           policy="default", no_auto_pair=False, disable=False,
                           non_interactive=True)

    if not sandbox:
        click.echo()
        click.echo("  ── Sidecar ───────────────────────────────────────────")
        click.echo()
        _start_gateway(cfg, logger)

    click.echo()
    click.echo("  ──────────────────────────────────────────────────────")
    click.echo()
    click.echo("  DefenseClaw initialized.")
    click.echo()
    click.echo("  Next steps:")
    if sandbox:
        click.echo("    defenseclaw setup guardrail   Enable LLM traffic inspection")
    elif guardrail_ok:
        click.echo("    defenseclaw setup guardrail   Customize guardrail settings")
    else:
        click.echo("    defenseclaw setup guardrail   Enable LLM traffic inspection")
    click.echo("    defenseclaw setup            Customize scanners and policies")
    click.echo("    defenseclaw skill            Manage and scan OpenClaw skills")
    click.echo("    defenseclaw mcp              Manage and scan MCP servers")

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
    with open(path, "w") as f:
        os.chmod(path, 0o600)
        f.write(pem_data)


def _resolve_openclaw_gateway(claw_config_file: str) -> dict[str, str | int]:
    """Read gateway host, port, and token from openclaw.json.

    Looks for gateway.port and gateway.auth.token when gateway.model is 'local'.
    Returns a dict with resolved values; missing keys use safe defaults.
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

    model = gw.get("model", "local")
    if model == "local":
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
    token_configured = False
    if is_new_config:
        oc_gw = _resolve_openclaw_gateway(cfg.claw.config_file)
        cfg.gateway.host = oc_gw["host"]
        cfg.gateway.port = oc_gw["port"]
        if oc_gw["token"]:
            from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv
            _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", oc_gw["token"], cfg.data_dir)
            cfg.gateway.token = ""
            cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
            token_configured = True
        else:
            cfg.gateway.token = ""
            # Keep standard env indirection so ~/.defenseclaw/.env can supply the token
            # when OpenClaw enables gateway auth after init.
            cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
    else:
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
        _check_sidecar_health(cfg.gateway.api_port)


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


def _check_sidecar_health(api_port: int, retries: int = 3) -> None:
    """Briefly poll the sidecar REST API to confirm it started."""
    import time
    import urllib.error
    import urllib.request

    url = f"http://127.0.0.1:{api_port}/health"
    for i in range(retries):
        time.sleep(1)
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    click.echo("  Health:        ok ✓")
                    return
        except (urllib.error.URLError, OSError, ValueError):
            pass

    click.echo("  Health:        not responding")
    click.echo("                 check: defenseclaw-gateway status")


OPENCLAW_OWNERSHIP_BACKUP = "openclaw-ownership-backup.json"

_SANDBOX_SYSTEM_DEPS = ["iptables"]


def _ensure_iptables() -> None:
    """Install iptables if not present. Required by openshell-sandbox for bypass detection."""
    if shutil.which("iptables"):
        return
    click.echo("  iptables:      not found, installing...", nl=False)
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y", "-qq", "iptables"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and shutil.which("iptables"):
            click.echo(" done")
        else:
            click.echo(" failed")
            click.echo("                 install manually: apt-get install -y iptables")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        click.echo(" failed")
        click.echo("                 install manually: apt-get install -y iptables")


def _init_sandbox(cfg, logger) -> bool:
    """Initialize sandbox mode: create user, directories, integrate OpenClaw, and configure.

    Returns True if sandbox setup completed, False if aborted (e.g. user
    declined the OpenClaw ownership change).
    """
    sandbox_home = cfg.openshell.effective_sandbox_home()

    # 1. Check openshell-sandbox binary — auto-install if missing
    if shutil.which("openshell-sandbox"):
        click.echo("  openshell:     found on PATH")
    else:
        click.echo("  openshell:     not found, installing...", nl=False)
        if _install_openshell_sandbox(cfg):
            click.echo(" done")
        else:
            click.echo(" failed")
            click.echo("                 install manually: install-openshell-sandbox")

    # 1b. Ensure iptables is installed (runtime dep for openshell-sandbox)
    _ensure_iptables()

    # 2. Create sandbox system user (idempotent)
    _create_sandbox_user(sandbox_home)

    # 3. Integrate existing OpenClaw installation (detect, confirm, chown, symlink)
    openclaw_integrated = _integrate_openclaw_home(cfg, sandbox_home)

    if not openclaw_integrated:
        click.echo()
        click.echo("  Sandbox mode requires OpenClaw ownership transfer to proceed.")
        click.echo("  Re-run 'defenseclaw init --sandbox' when ready.")
        return False

    # 4. Create sandbox directories
    sandbox_dirs = [os.path.join(sandbox_home, ".defenseclaw")]
    all_exist = all(os.path.isdir(d) for d in sandbox_dirs)
    for d in sandbox_dirs:
        os.makedirs(d, exist_ok=True)
    if all_exist:
        click.echo(f"  Sandbox dirs:  exist at {sandbox_home}")
    else:
        click.echo(f"  Sandbox dirs:  created at {sandbox_home}")

    # 5. Install DefenseClaw plugin into sandbox
    target_plugin = os.path.join(sandbox_home, ".openclaw", "extensions", "defenseclaw", "dist", "index.js")
    if os.path.isfile(target_plugin):
        click.echo(f"  Plugin:        already installed")
    else:
        _install_plugin_to_sandbox(cfg, sandbox_home)

    # 6. Copy default OpenShell policy files
    rego_dst = os.path.join(cfg.data_dir, "openshell-policy.rego")
    if os.path.isfile(rego_dst):
        click.echo("  Policies:      already present")
    else:
        _copy_openshell_policies(cfg.data_dir)

    # 7. Fix ownership — files written after the initial chown (plugin, policies)
    #    need to be owned by sandbox too
    oc_target = os.path.join(sandbox_home, ".openclaw")
    if os.path.islink(oc_target):
        oc_target = os.readlink(oc_target)
    try:
        subprocess.run(
            ["chown", "-R", "sandbox:sandbox", oc_target],
            capture_output=True, check=False,
        )
    except FileNotFoundError:
        pass

    logger.log_action("init-sandbox", sandbox_home, f"version={cfg.openshell.effective_version()}")

    click.echo()
    click.echo(f"  Sandbox home:  {sandbox_home}")
    return True


def _detect_openclaw_home() -> "str | None":
    """Detect where the user's OpenClaw home directory is.

    Checks SUDO_USER's home first (since init is typically run with sudo),
    then the current user's home, then /root.
    """
    import pwd as _pwd

    candidates = []

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            pw = _pwd.getpwnam(sudo_user)
            candidates.append(os.path.join(pw.pw_dir, ".openclaw"))
        except KeyError:
            pass

    candidates.append(os.path.expanduser("~/.openclaw"))

    if os.path.exists("/root/.openclaw"):
        candidates.append("/root/.openclaw")

    seen = set()
    unique = []
    for c in candidates:
        resolved = os.path.realpath(c)
        if resolved not in seen:
            seen.add(resolved)
            unique.append(c)

    for path in unique:
        if os.path.isfile(os.path.join(path, "openclaw.json")):
            return path

    return None


def _save_ownership_backup(openclaw_home: str, data_dir: str) -> str:
    """Save ownership info of the OpenClaw home directory for undo.

    Records original uid/gid so chown -R can restore them later.
    Also records parent directories that may need o+x removed on undo.
    Returns the backup file path.
    """
    import json
    import stat as _stat

    backup_path = os.path.join(data_dir, OPENCLAW_OWNERSHIP_BACKUP)
    real_path = os.path.realpath(openclaw_home)
    st = os.stat(real_path)

    # Record parents that currently lack o+x so we can restore on undo
    parents_without_ox = []
    parent = os.path.dirname(real_path)
    while parent and parent != "/":
        try:
            pst = os.stat(parent)
            pmode = _stat.S_IMODE(pst.st_mode)
            if not (pmode & _stat.S_IXOTH):
                parents_without_ox.append({"path": parent, "original_mode": oct(pmode)})
        except OSError:
            break
        parent = os.path.dirname(parent)

    backup = {
        "openclaw_home": real_path,
        "original_uid": st.st_uid,
        "original_gid": st.st_gid,
        "original_mode": oct(_stat.S_IMODE(st.st_mode)),
        "parents_modified": parents_without_ox,
    }

    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with open(backup_path, "w") as f:
        json.dump(backup, f, indent=2)

    return backup_path


def _ensure_parent_traversal(target_path: str) -> None:
    """Ensure all parent directories of target_path have o+x (traverse) permission.

    Without this, symlinking into e.g. /root/.openclaw fails because /root/
    is typically mode 700. Adding o+x allows the sandbox user to traverse
    the directory without granting read or write access.
    """
    import stat as _stat

    parent = os.path.dirname(target_path)
    while parent and parent != "/":
        try:
            st = os.stat(parent)
            mode = _stat.S_IMODE(st.st_mode)
            if not (mode & _stat.S_IXOTH):
                new_mode = mode | _stat.S_IXOTH
                os.chmod(parent, new_mode)
                click.echo(f"  Traversal:     added o+x to {parent}")
        except OSError:
            break
        parent = os.path.dirname(parent)


def _install_acl_package() -> str | None:
    """Try to install the ``acl`` package, or prompt the user to do it.

    Returns the path to ``setfacl`` on success, ``None`` on failure.
    """
    pkg_mgr = shutil.which("apt-get") or shutil.which("dnf") or shutil.which("yum")
    if not pkg_mgr:
        click.echo("  ACL:           setfacl not found and no supported package manager detected")
        click.echo("                 Install the 'acl' package manually, then re-run this command")
        return None

    mgr_name = os.path.basename(pkg_mgr)
    if mgr_name == "apt-get":
        install_cmd = [pkg_mgr, "install", "-y", "acl"]
    else:
        install_cmd = [pkg_mgr, "install", "-y", "acl"]

    click.echo(f"  ACL:           setfacl not found — installing via {mgr_name}...")
    result = subprocess.run(install_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"  ACL:           install failed ({result.stderr.strip()[:120]})")
        click.echo(f"                 Install manually: {mgr_name} install acl")
        return None

    path = shutil.which("setfacl")
    if path:
        click.echo("  ACL:           acl package installed")
    else:
        click.echo("  ACL:           package installed but setfacl still not on PATH")
        click.echo("                 Check your installation or add it to PATH")
    return path


def _ensure_sandbox_acls(target_path: str, sandbox_user: str = "sandbox") -> bool:
    """Set POSIX ACLs so the sandbox user retains access regardless of file ownership.

    Uses ``setfacl`` to grant the sandbox user rwX on all existing files
    and sets *default* ACLs so newly-created files automatically inherit
    the same grant.  This eliminates the need to chase every individual
    file-write with an ``os.chown`` call — any process (including root)
    can create/modify files and the sandbox user still has access.

    Also grants the sandbox user ``rx`` on every parent directory up to
    ``/`` so symlinks into e.g. ``/root/.openclaw`` remain traversable.

    Returns True if setfacl succeeded.
    """
    if not os.path.isdir(target_path):
        return False

    setfacl = shutil.which("setfacl")
    if not setfacl:
        setfacl = _install_acl_package()
    if not setfacl:
        return False

    ok = True
    for args, desc in [
        (["-R", "-m", f"u:{sandbox_user}:rwX", target_path],
         "grant sandbox access on existing files"),
        (["-R", "-d", "-m", f"u:{sandbox_user}:rwX", target_path],
         "set default ACL for new files"),
        (["-R", "-m", "m::rwx", target_path],
         "fix ACL mask on existing files"),
        (["-R", "-d", "-m", "m::rwx", target_path],
         "fix default ACL mask for new files"),
    ]:
        result = subprocess.run(
            [setfacl] + args,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            click.echo(f"  ACL:           {desc} failed ({result.stderr.strip()})")
            ok = False

    # Parent traversal via ACL (more targeted than chmod o+x)
    parent = os.path.dirname(os.path.realpath(target_path))
    while parent and parent != "/":
        subprocess.run(
            [setfacl, "-m", f"u:{sandbox_user}:x", parent],
            capture_output=True,
        )
        parent = os.path.dirname(parent)

    if ok:
        click.echo(f"  ACL:           default ACLs set on {target_path}")
    return ok


def _integrate_openclaw_home(cfg, sandbox_home: str) -> bool:
    """Detect existing OpenClaw install and transfer ownership to sandbox user.

    Flow:
    1. If already configured (backup + symlink in place), skip (idempotent).
    2. Detect the OpenClaw home directory.
    3. Prompt user to confirm or modify the path.
    4. Warn about ownership change consequences.
    5. Save ownership backup for undo.
    6. chown -R to sandbox user.
    7. Symlink from sandbox_home/.openclaw to the original path.

    Returns True if integration succeeded (symlink created or already present).
    """
    import pwd as _pwd

    backup_path = os.path.join(cfg.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
    symlink_path = os.path.join(sandbox_home, ".openclaw")

    # Idempotency: backup exists and symlink is in place — already done.
    # Still ensure parent traversal since a reboot or container restart
    # could reset directory permissions.
    if os.path.isfile(backup_path) and os.path.islink(symlink_path):
        target = os.readlink(symlink_path)
        click.echo(f"  OpenClaw:      already configured at {target}")
        real_target = os.path.realpath(target)
        _ensure_parent_traversal(real_target)
        _ensure_sandbox_acls(real_target)
        return True

    detected = _detect_openclaw_home()

    if not detected:
        click.echo("  OpenClaw:      not found")
        click.echo("                 Install OpenClaw first, then re-run 'defenseclaw init --sandbox'")
        click.echo("                 Install: curl -fsSL https://openclaw.ai/install.sh | bash")
        return False

    click.echo(f"  OpenClaw:      detected at {detected}")
    click.echo()
    click.echo("  \u26a0 WARNING: Sandbox integration will change ownership of this directory")
    click.echo("    to the 'sandbox' user. OpenClaw will NOT be usable outside the sandbox")
    click.echo("    until reversed with 'defenseclaw setup sandbox --disable'.")
    click.echo()

    confirmed_path = click.prompt(
        "  Confirm OpenClaw home path",
        default=detected,
        type=str,
    )
    confirmed_path = os.path.expanduser(confirmed_path.strip())

    if not os.path.isdir(confirmed_path):
        click.echo(f"  OpenClaw:      path does not exist: {confirmed_path}")
        return False

    if not os.path.isfile(os.path.join(confirmed_path, "openclaw.json")):
        click.echo(f"  OpenClaw:      no openclaw.json found in {confirmed_path}")
        return False

    if not click.confirm("  Proceed with ownership change?", default=True):
        click.echo("  OpenClaw:      skipped (user declined)")
        return False

    # Save ownership backup
    try:
        _save_ownership_backup(confirmed_path, cfg.data_dir)
        click.echo(f"  Backup:        ownership saved to {backup_path}")
    except OSError as exc:
        click.echo(f"  Backup:        failed ({exc})")
        return False

    # Change ownership to sandbox user
    try:
        sandbox_pw = _pwd.getpwnam("sandbox")
        result = subprocess.run(
            ["chown", "-R", f"{sandbox_pw.pw_uid}:{sandbox_pw.pw_gid}", confirmed_path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            click.echo(f"  Ownership:     chown failed ({result.stderr.strip()})")
            return False
        click.echo("  Ownership:     changed to sandbox user")
    except (KeyError, FileNotFoundError) as exc:
        click.echo(f"  Ownership:     failed ({exc})")
        return False

    _ensure_sandbox_acls(confirmed_path)

    # Create symlink: sandbox_home/.openclaw -> confirmed_path
    if os.path.isdir(symlink_path) and not os.path.islink(symlink_path):
        shutil.rmtree(symlink_path)
    elif os.path.islink(symlink_path):
        os.remove(symlink_path)

    try:
        os.symlink(os.path.realpath(confirmed_path), symlink_path)
        click.echo(f"  Symlink:       {symlink_path} -> {confirmed_path}")
    except OSError as exc:
        click.echo(f"  Symlink:       failed ({exc})")
        return False

    # Ensure parent directories are traversable by the sandbox user.
    # /root/ is typically mode 700 which blocks the sandbox user from
    # following the symlink. Adding o+x grants traverse-only permission
    # (no read/write on the parent directory itself).
    _ensure_parent_traversal(os.path.realpath(confirmed_path))

    cfg.claw.openclaw_home_original = os.path.realpath(confirmed_path)

    return True


def _create_sandbox_user(sandbox_home: str) -> None:
    """Create the 'sandbox' system user if it doesn't exist."""
    import pwd
    try:
        pwd.getpwnam("sandbox")
        click.echo("  Sandbox user:  exists")
        return
    except KeyError:
        pass

    try:
        subprocess.run(
            ["groupadd", "-r", "sandbox"],
            capture_output=True, check=False,
        )
        result = subprocess.run(
            ["useradd", "-r", "-g", "sandbox", "-d", sandbox_home,
             "-m", "-s", "/bin/bash", "sandbox"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            click.echo("  Sandbox user:  created")
        else:
            click.echo(f"  Sandbox user:  failed ({result.stderr.strip()})")
            click.echo("                 create manually: useradd -r -g sandbox "
                        f"-d {sandbox_home} -m -s /bin/bash sandbox")
    except FileNotFoundError:
        click.echo("  Sandbox user:  useradd not found (create manually)")


def _find_plugin_source() -> "str | None":
    """Locate the built DefenseClaw plugin directory.

    Checks: data_dir staging, repo-relative, bundled _data/.
    """
    from pathlib import Path

    # 1. ~/.defenseclaw/extensions/defenseclaw (staging from make plugin-install)
    from defenseclaw.config import default_data_path
    staging = Path(str(default_data_path())) / "extensions" / "defenseclaw" / "dist" / "index.js"
    if staging.is_file():
        return str(staging.parent.parent)

    # 2. Repo-relative: walk up from cmd_init.py looking for extensions/defenseclaw/
    here = Path(__file__).resolve()
    for ancestor in [here.parent.parent.parent.parent,   # cli/defenseclaw/commands/ -> repo root
                     here.parent.parent.parent]:          # defenseclaw/commands/ -> editable install root
        candidate = ancestor / "extensions" / "defenseclaw"
        if (candidate / "dist" / "index.js").is_file():
            return str(candidate)

    # 3. Bundled _data/
    bundled = here.parent.parent / "_data" / "extensions" / "defenseclaw"
    if (bundled / "dist" / "index.js").is_file():
        return str(bundled)

    return None


def _install_plugin_to_sandbox(cfg, sandbox_home: str) -> None:
    """Install the DefenseClaw plugin into the sandbox user's OpenClaw extensions."""
    source_dir = _find_plugin_source()
    target_dir = os.path.join(sandbox_home, ".openclaw", "extensions", "defenseclaw")

    if not source_dir:
        click.echo("  Plugin:        not built (run 'make plugin-install' first)")
        return

    try:
        if os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        shutil.copytree(source_dir, target_dir)
        click.echo(f"  Plugin:        installed to {target_dir}")
    except OSError as exc:
        click.echo(f"  Plugin:        failed to install ({exc})")


def _find_openshell_policies_dir() -> "Path | None":
    """Locate the openshell policy templates directory.

    Checks repo-relative path first, then the bundled _data/ directory
    shipped inside the wheel.
    """
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    repo_policies = repo_root / "policies" / "openshell"
    if repo_policies.is_dir():
        return repo_policies

    bundled = Path(__file__).resolve().parent.parent / "_data" / "policies" / "openshell"
    if bundled.is_dir():
        return bundled

    return None


def _copy_openshell_policies(data_dir: str) -> None:
    """Copy default OpenShell policy files to the data directory."""
    policy_src = _find_openshell_policies_dir()

    if policy_src is None:
        click.echo("  Policies:      openshell templates not found")
        return

    for src_name, dst_name in [
        ("default.rego", "openshell-policy.rego"),
        ("default-data.yaml", "openshell-policy.yaml"),
    ]:
        src = policy_src / src_name
        dst = os.path.join(data_dir, dst_name)
        if src.is_file() and not os.path.exists(dst):
            shutil.copy2(str(src), dst)

    click.echo("  Policies:      openshell defaults copied")


def _find_installer_script() -> "str | None":
    """Locate install-openshell-sandbox.sh.

    Checks: system PATH, repo-relative scripts/, bundled _data/scripts/.
    """
    from pathlib import Path

    on_path = shutil.which("install-openshell-sandbox")
    if on_path:
        return on_path

    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    repo_script = repo_root / "scripts" / "install-openshell-sandbox.sh"
    if repo_script.is_file():
        return str(repo_script)

    bundled = Path(__file__).resolve().parent.parent / "_data" / "scripts" / "install-openshell-sandbox.sh"
    if bundled.is_file():
        return str(bundled)

    return None


def _install_openshell_sandbox(cfg) -> bool:
    """Run the install-openshell-sandbox script to fetch the binary.

    The install script has its own default version for the OCI image tag
    (openshell-sandbox versioning is independent of the openshell CLI).
    We only override OPENSHELL_VERSION if the user set sandbox_version
    explicitly in config.
    """
    script = _find_installer_script()
    if not script:
        return False

    env = os.environ.copy()
    sandbox_version = getattr(cfg.openshell, "sandbox_version", "")
    if sandbox_version:
        env["OPENSHELL_VERSION"] = sandbox_version

    cmd = ["bash", script, "--install-dir", "/usr/local/bin"]

    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            if stderr:
                click.echo()
                for line in stderr.splitlines()[-3:]:
                    click.echo(f"                 {line}")
            return False
        return shutil.which("openshell-sandbox") is not None
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
