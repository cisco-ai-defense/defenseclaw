"""Sandbox setup command — defenseclaw sandbox setup."""

from __future__ import annotations

import json as _json
import os
import shlex
import shutil
import subprocess

import click

from defenseclaw.context import AppContext, pass_ctx


def restore_sandbox_ownership_if_needed(cfg) -> None:
    """Restore sandbox ownership of .openclaw dir if running in standalone mode."""
    if not cfg.openshell.is_standalone():
        return
    sandbox_home = cfg.openshell.effective_sandbox_home()
    oc_target = os.path.realpath(os.path.join(sandbox_home, ".openclaw"))
    try:
        subprocess.run(
            ["chown", "-R", "sandbox:sandbox", oc_target],
            capture_output=True, check=False,
        )
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# setup sandbox
# ---------------------------------------------------------------------------

@click.command("setup")
@click.option("--sandbox-ip", default="10.200.0.2", help="Bridge IP of the sandbox (default: 10.200.0.2)")
@click.option("--host-ip", default="10.200.0.1", help="Bridge IP of the host (default: 10.200.0.1)")
@click.option("--sandbox-home", default=None, help="Sandbox user home directory (default: /home/sandbox)")
@click.option("--openclaw-port", type=int, default=18789, help="OpenClaw gateway port inside sandbox")
@click.option(
    "--policy",
    type=click.Choice(["default", "strict", "permissive"]),
    default="default",
    help="Network policy template",
)
@click.option("--dns", default="8.8.8.8,1.1.1.1", help="DNS nameservers (comma-separated, or 'host')")
@click.option("--no-auto-pair", is_flag=True, help="Disable automatic device pre-pairing")
@click.option("--disable", is_flag=True, help="Revert to host mode (no sandbox)")
@click.option("--non-interactive", is_flag=True, help="Skip confirmation prompts")
@pass_ctx
def setup_sandbox(
    app: AppContext,
    sandbox_ip: str,
    host_ip: str,
    sandbox_home: str | None,
    openclaw_port: int,
    policy: str,
    dns: str,
    no_auto_pair: bool,
    disable: bool,
    non_interactive: bool,
) -> None:
    """Configure DefenseClaw for openshell-sandbox standalone mode.

    Full orchestration: configures networking, generates systemd units,
    patches OpenClaw config, sets up device pairing, and installs policy.

    \b
    Example:
      defenseclaw sandbox setup --sandbox-ip 10.200.0.2 --host-ip 10.200.0.1
      defenseclaw sandbox setup --policy strict --no-auto-pair
      defenseclaw sandbox setup --disable
    """
    import platform

    from defenseclaw.commands.cmd_setup import (
        _detect_openclaw_gateway_token,
        _mask,
        _save_secret_to_dotenv,
    )

    if not app.cfg:
        from defenseclaw.config import load
        app.cfg = load()
    if not app.store:
        from defenseclaw.db import Store
        from defenseclaw.logger import Logger
        app.store = Store(app.cfg.audit_db)
        app.logger = Logger(app.store)

    if disable:
        _disable_sandbox(app)
        return

    if platform.system() != "Linux":
        click.echo("  ERROR: Sandbox mode requires Linux.", err=True)
        raise SystemExit(1)

    sandbox_home = sandbox_home or app.cfg.openshell.effective_sandbox_home()
    data_dir = app.cfg.data_dir

    click.echo()
    click.echo("  Configuring sandbox mode ...")

    # 1. Validate prerequisites
    _validate_sandbox_prerequisites(sandbox_home)

    # 2. Configure DefenseClaw
    app.cfg.openshell.mode = "standalone"
    app.cfg.openshell.sandbox_home = sandbox_home
    if no_auto_pair:
        app.cfg.openshell.auto_pair = False

    app.cfg.gateway.host = sandbox_ip
    app.cfg.gateway.port = openclaw_port
    app.cfg.guardrail.host = host_ip
    app.cfg.gateway.watcher.enabled = True
    app.cfg.gateway.watcher.skill.enabled = True
    app.cfg.gateway.watcher.skill.take_action = True

    app.cfg.claw.home_dir = os.path.join(sandbox_home, ".openclaw")
    app.cfg.claw.config_file = os.path.join(sandbox_home, ".openclaw", "openclaw.json")

    click.echo("    openshell.mode:       standalone")
    click.echo(f"    openshell.sandbox_home: {sandbox_home}")
    click.echo(f"    gateway.host:         {sandbox_ip}")
    click.echo(f"    guardrail.host:       {host_ip}")
    click.echo(f"    claw.home_dir:        {app.cfg.claw.home_dir}")

    # 3. Read gateway auth token from OpenClaw config (same as non-sandbox mode).
    #    OpenClaw owns the token — DefenseClaw never generates or injects one.
    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    detected_token = _detect_openclaw_gateway_token(oc_config)
    if detected_token:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected_token, data_dir)
        app.cfg.gateway.token = ""
        app.cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        click.echo(f"    gateway.token:        read from openclaw.json ({_mask(detected_token)})")
    else:
        click.echo("    gateway.token:        not found (sidecar will auto-detect on connect)")

    # 4. Install policy template
    _install_policy_template(data_dir, policy)
    click.echo(f"    policy template:      {policy}")

    # 5. Generate DNS resolv.conf
    _generate_resolv_conf(data_dir, dns)
    click.echo(f"    dns nameservers:      {dns}")

    # 6. Patch sandbox-side OpenClaw config (port + bind only, never the token)
    if os.path.isfile(oc_config):
        _patch_openclaw_gateway(oc_config, openclaw_port)
        click.echo(f"    openclaw.json:        patched (gateway.port={openclaw_port}, gateway.bind=lan)")

    # 7. Generate systemd unit files
    _generate_systemd_units(data_dir, sandbox_home, host_ip, sandbox_ip, app.cfg)
    click.echo(f"    systemd units:        generated in {data_dir}")

    # 8. Generate launcher scripts
    _generate_launcher_scripts(data_dir, sandbox_home, host_ip, app.cfg)
    click.echo(f"    launcher scripts:     generated in {data_dir}")

    # 9. Device pre-pairing
    if not no_auto_pair:
        paired = _pre_pair_device(data_dir, sandbox_home)
        if paired:
            click.echo("    device pairing:       pre-paired")
        else:
            click.echo("    device pairing:       skipped (device.key not found)")
    else:
        click.echo("    device pairing:       manual (--no-auto-pair)")

    # 10. Fix ownership and traversal — all files written above (openclaw.json
    #     patch, paired.json, policy templates) were created as root. Restore
    #     sandbox ownership so the OpenClaw process can read/write them.
    #     Also ensure parent directories (e.g. /root/) have o+x so the sandbox
    #     user can follow the symlink to the real OpenClaw home.
    oc_target = os.path.realpath(os.path.join(sandbox_home, ".openclaw"))
    try:
        subprocess.run(
            ["chown", "-R", "sandbox:sandbox", oc_target],
            capture_output=True, check=False,
        )
    except FileNotFoundError:
        pass

    from defenseclaw.commands.cmd_init_sandbox import _ensure_parent_traversal
    _ensure_parent_traversal(oc_target)

    # 11. Save config
    app.cfg.save()

    # 12. Install systemd units and launcher scripts (if systemd present)
    has_systemd = shutil.which("systemctl") is not None
    installed = _install_systemd_units(data_dir) if has_systemd else False

    # 13. Generate convenience run-sandbox.sh for non-systemd environments
    _generate_run_sandbox_script(data_dir, host_ip, app.cfg)

    click.echo()
    click.echo("  ── Summary ───────────────────────────────────────────")
    click.echo()
    click.echo("  Sandbox mode configured successfully.")
    click.echo()

    if installed:
        click.echo("  ✓ Systemd units installed and daemon reloaded")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Run 'defenseclaw setup guardrail' to configure LLM interception")
        click.echo(f"       (will set baseUrl to http://{host_ip}:{app.cfg.guardrail.port})")
        click.echo()
        click.echo("    2. Start the sandbox:")
        click.echo("       sudo systemctl start defenseclaw-sandbox.target")
    elif has_systemd:
        click.echo("  ⚠ Systemd units were generated but could not be installed automatically.")
        click.echo(f"    Files are at: {data_dir}/systemd/ and {data_dir}/scripts/")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Install systemd units manually (requires root):")
        click.echo(f"       sudo cp {data_dir}/systemd/*.service /etc/systemd/system/")
        click.echo(f"       sudo cp {data_dir}/systemd/*.target /etc/systemd/system/")
        click.echo("       sudo mkdir -p /usr/local/lib/defenseclaw")
        click.echo(f"       sudo cp {data_dir}/scripts/*.sh /usr/local/lib/defenseclaw/")
        click.echo("       sudo chmod +x /usr/local/lib/defenseclaw/*.sh")
        click.echo("       sudo systemctl daemon-reload")
        click.echo()
        click.echo("    2. Run 'defenseclaw setup guardrail' to configure LLM interception")
        click.echo(f"       (will set baseUrl to http://{host_ip}:{app.cfg.guardrail.port})")
        click.echo()
        click.echo("    3. Start the sandbox:")
        click.echo("       sudo systemctl start defenseclaw-sandbox.target")
    else:
        click.echo("  ℹ No systemd detected (container/minimal environment).")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Run 'defenseclaw setup guardrail' to configure LLM interception")
        click.echo(f"       (will set baseUrl to http://{host_ip}:{app.cfg.guardrail.port})")
        click.echo()
        click.echo("    2. Start the sandbox manually:")
        click.echo(f"       sudo {data_dir}/scripts/run-sandbox.sh")
        click.echo()
        click.echo("    To stop:")
        click.echo(f"       sudo {data_dir}/scripts/run-sandbox.sh stop")
    click.echo()


def _restore_openclaw_ownership(data_dir: str, sandbox_home: str) -> None:
    """Restore original ownership of the OpenClaw home directory from backup.

    Reads the backup file saved during init, runs chown -R to restore
    original uid:gid, removes the symlink from sandbox home, and
    deletes the backup file.
    """
    import json as _json_mod

    from defenseclaw.commands.cmd_init_sandbox import OPENCLAW_OWNERSHIP_BACKUP

    backup_path = os.path.join(data_dir, OPENCLAW_OWNERSHIP_BACKUP)
    if not os.path.isfile(backup_path):
        return

    try:
        with open(backup_path) as f:
            backup = _json_mod.load(f)
    except (OSError, _json_mod.JSONDecodeError) as exc:
        click.echo(f"  Ownership:     failed to read backup ({exc})")
        return

    openclaw_home = backup.get("openclaw_home", "")
    uid = backup.get("original_uid")
    gid = backup.get("original_gid")

    if not openclaw_home or uid is None or gid is None:
        click.echo("  Ownership:     invalid backup data")
        return

    # Restore ownership
    try:
        result = subprocess.run(
            ["chown", "-R", f"{uid}:{gid}", openclaw_home],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            click.echo(f"  Ownership:     restored to {uid}:{gid} on {openclaw_home}")
        else:
            click.echo(f"  Ownership:     restore failed ({result.stderr.strip()})")
    except FileNotFoundError:
        click.echo("  Ownership:     chown not found")

    # Restore parent directory permissions (remove o+x we added).
    # Validate each path is a true ancestor of openclaw_home and
    # the mode is sane to guard against tampered backup files.
    real_oc_home = os.path.realpath(openclaw_home)
    for entry in backup.get("parents_modified", []):
        ppath = entry.get("path", "")
        orig_mode = entry.get("original_mode", "")
        if not ppath or not orig_mode:
            continue
        real_ppath = os.path.realpath(ppath)
        if not real_oc_home.startswith(real_ppath + "/"):
            click.echo(f"  Traversal:     skipping non-ancestor {ppath}")
            continue
        try:
            mode_int = int(orig_mode, 8)
        except ValueError:
            click.echo(f"  Traversal:     skipping invalid mode {orig_mode!r}")
            continue
        if mode_int & 0o002:
            click.echo(f"  Traversal:     skipping world-writable mode {orig_mode}")
            continue
        try:
            os.chmod(real_ppath, mode_int)
            click.echo(f"  Traversal:     restored {ppath} to {orig_mode}")
        except OSError:
            pass

    # Remove symlink from sandbox home
    symlink_path = os.path.join(sandbox_home, ".openclaw")
    if os.path.islink(symlink_path):
        try:
            os.remove(symlink_path)
            click.echo(f"  Symlink:       removed {symlink_path}")
        except OSError as exc:
            click.echo(f"  Symlink:       remove failed ({exc})")

    # Remove backup file
    try:
        os.remove(backup_path)
    except OSError:
        pass


def _disable_sandbox(app: AppContext) -> None:
    """Revert to host mode: restore OpenClaw ownership, clean up symlink, reset config."""
    sandbox_home = app.cfg.openshell.effective_sandbox_home()

    # Restore gateway config in openclaw.json BEFORE removing the symlink
    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    if os.path.isfile(oc_config):
        _restore_openclaw_gateway(oc_config)

    # Restore original OpenClaw ownership and remove symlink
    _restore_openclaw_ownership(app.cfg.data_dir, sandbox_home)

    app.cfg.openshell.mode = ""
    app.cfg.gateway.host = "127.0.0.1"
    app.cfg.gateway.port = 18789
    app.cfg.guardrail.host = "localhost"
    app.cfg.gateway.watcher.enabled = False
    app.cfg.claw.home_dir = "~/.openclaw"
    app.cfg.claw.config_file = "~/.openclaw/openclaw.json"
    app.cfg.claw.openclaw_home_original = ""
    app.cfg.save()
    click.echo("  Sandbox mode disabled. Config reverted to host mode.")
    click.echo("  Re-run 'defenseclaw setup guardrail' to update openclaw.json baseUrl.")


def _validate_sandbox_prerequisites(sandbox_home: str) -> None:
    """Check that required prerequisites exist."""
    import pwd
    try:
        pwd.getpwnam("sandbox")
    except KeyError:
        click.echo("  WARNING: 'sandbox' user not found. Run 'defenseclaw sandbox init' first.", err=True)

    if not os.path.isdir(sandbox_home):
        click.echo(f"  WARNING: sandbox home {sandbox_home} does not exist.", err=True)


def _patch_openclaw_gateway(openclaw_config: str, port: int) -> bool:
    """Patch gateway port and bind into openclaw.json for sandbox mode.

    Only sets mode/port/bind — the auth token is owned by OpenClaw and
    never written by DefenseClaw.
    """
    try:
        st = os.stat(openclaw_config)
        with open(openclaw_config) as f:
            cfg = _json.load(f)
    except (OSError, _json.JSONDecodeError):
        return False

    gw = cfg.setdefault("gateway", {})
    gw["mode"] = "local"
    gw["port"] = port
    gw["bind"] = "lan"

    with open(openclaw_config, "w") as f:
        _json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    try:
        os.chown(openclaw_config, st.st_uid, st.st_gid)
    except OSError:
        pass
    return True


def _restore_openclaw_gateway(openclaw_config: str) -> bool:
    """Remove gateway.* fields from openclaw.json."""
    try:
        st = os.stat(openclaw_config)
        with open(openclaw_config) as f:
            cfg = _json.load(f)
    except (OSError, _json.JSONDecodeError):
        return False

    gw = cfg.get("gateway", {})
    for key in ("mode", "port", "bind", "token"):
        gw.pop(key, None)
    auth = gw.get("auth", {})
    auth.pop("token", None)

    with open(openclaw_config, "w") as f:
        _json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    try:
        os.chown(openclaw_config, st.st_uid, st.st_gid)
    except OSError:
        pass
    return True


def _install_policy_template(data_dir: str, policy_name: str) -> None:
    """Copy the selected policy template to the data dir."""
    policy_dir = os.path.join(data_dir, "policies")
    os.makedirs(policy_dir, exist_ok=True)

    repo_root = _find_repo_root()
    if not repo_root:
        click.echo("  WARNING: Could not find repo root. Policy templates not installed.", err=True)
        return

    rego_src = os.path.join(repo_root, "policies", "openshell", "default.rego")
    data_src = os.path.join(repo_root, "policies", "openshell", f"{policy_name}-data.yaml")

    for src, dst_name in [(rego_src, "openshell-policy.rego"), (data_src, "openshell-policy.yaml")]:
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(data_dir, dst_name))


def _generate_resolv_conf(data_dir: str, dns_arg: str) -> None:
    """Write sandbox-resolv.conf with configured nameservers."""
    import ipaddress as _ipaddress

    if dns_arg == "host":
        nameservers = _parse_host_resolv()
    else:
        nameservers = [ns.strip() for ns in dns_arg.split(",") if ns.strip()]

    validated: list[str] = []
    for ns in nameservers:
        try:
            _ipaddress.ip_address(ns)
            validated.append(ns)
        except ValueError:
            click.echo(f"  Warning: skipping invalid nameserver: {ns!r}")
    nameservers = validated or ["8.8.8.8", "1.1.1.1"]

    resolv_path = os.path.join(data_dir, "sandbox-resolv.conf")
    with open(resolv_path, "w") as f:
        for ns in nameservers:
            f.write(f"nameserver {ns}\n")


def _parse_host_resolv() -> list[str]:
    """Parse nameservers from host /etc/resolv.conf."""
    try:
        with open("/etc/resolv.conf") as f:
            return [
                line.split()[1]
                for line in f
                if line.strip().startswith("nameserver") and len(line.split()) >= 2
            ]
    except OSError:
        return []


def _generate_systemd_units(
    data_dir: str,
    sandbox_home: str,
    host_ip: str,
    sandbox_ip: str,
    cfg,
) -> None:
    """Generate systemd unit files for the sandbox and sidecar."""
    systemd_dir = os.path.join(data_dir, "systemd")
    os.makedirs(systemd_dir, exist_ok=True)

    sandbox_unit = """[Unit]
Description=OpenShell Sandbox (DefenseClaw-managed)
Documentation=https://github.com/defenseclaw/defenseclaw
After=network.target

[Service]
Type=exec
ExecStartPre=/usr/local/lib/defenseclaw/pre-sandbox.sh
ExecStart=/usr/local/lib/defenseclaw/start-sandbox.sh
ExecStartPost=/usr/local/lib/defenseclaw/post-sandbox.sh
ExecStopPost=/usr/local/lib/defenseclaw/cleanup-sandbox.sh

Restart=on-failure
RestartSec=5
RestartMaxDelaySec=60

StandardOutput=journal
StandardError=journal
SyslogIdentifier=openshell-sandbox

[Install]
WantedBy=defenseclaw-sandbox.target
"""

    sidecar_unit = f"""[Unit]
Description=DefenseClaw Gateway Sidecar
Documentation=https://github.com/defenseclaw/defenseclaw
After=openshell-sandbox.service
Wants=openshell-sandbox.service

[Service]
Type=exec
ExecStart=/usr/local/bin/defenseclaw-gateway run

Restart=on-failure
RestartSec=3
RestartMaxDelaySec=30

StandardOutput=journal
StandardError=journal
SyslogIdentifier=defenseclaw-gateway

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths="{data_dir}"
ReadOnlyPaths="{sandbox_home}/.openclaw"

[Install]
WantedBy=defenseclaw-sandbox.target
"""

    target_unit = """[Unit]
Description=DefenseClaw Sandbox (sandbox + sidecar)
Wants=openshell-sandbox.service defenseclaw-gateway.service

[Install]
WantedBy=multi-user.target
"""

    with open(os.path.join(systemd_dir, "openshell-sandbox.service"), "w") as f:
        f.write(sandbox_unit)
    with open(os.path.join(systemd_dir, "defenseclaw-gateway.service"), "w") as f:
        f.write(sidecar_unit)
    with open(os.path.join(systemd_dir, "defenseclaw-sandbox.target"), "w") as f:
        f.write(target_unit)


def _install_systemd_units(data_dir: str) -> bool:
    """Install generated systemd units and launcher scripts into system paths.

    Returns True if all steps succeeded.
    """
    import glob
    import shutil

    systemd_src = os.path.join(data_dir, "systemd")
    scripts_src = os.path.join(data_dir, "scripts")
    systemd_dst = "/etc/systemd/system"
    scripts_dst = "/usr/local/lib/defenseclaw"

    if not os.path.isdir(systemd_src):
        click.echo("    systemd install:     skipped (units not generated)")
        return False

    try:
        for f in glob.glob(os.path.join(systemd_src, "*.service")) + \
                 glob.glob(os.path.join(systemd_src, "*.target")):
            shutil.copy2(f, systemd_dst)

        os.makedirs(scripts_dst, exist_ok=True)
        if os.path.isdir(scripts_src):
            for f in glob.glob(os.path.join(scripts_src, "*.sh")):
                shutil.copy2(f, scripts_dst)
                os.chmod(os.path.join(scripts_dst, os.path.basename(f)), 0o755)

        import subprocess
        subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True, check=True,
        )
        click.echo("    systemd install:     units and scripts installed")
        return True
    except PermissionError:
        click.echo("    systemd install:     skipped (not root)")
        return False
    except FileNotFoundError:
        click.echo("    systemd install:     skipped (systemctl not found)")
        return False
    except subprocess.CalledProcessError as exc:
        click.echo(f"    systemd install:     daemon-reload failed ({exc})")
        return False


def _generate_launcher_scripts(
    data_dir: str,
    sandbox_home: str,
    host_ip: str,
    cfg,
) -> None:
    """Generate launcher shell scripts for the sandbox lifecycle."""
    scripts_dir = os.path.join(data_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)

    api_port = int(cfg.gateway.api_port)
    guardrail_port = int(cfg.guardrail.port)

    q_sandbox_home = shlex.quote(sandbox_home)
    q_data_dir = shlex.quote(data_dir)
    q_host_ip = shlex.quote(host_ip)

    pre_sandbox = f"""#!/bin/bash
set -euo pipefail

SANDBOX_HOME={q_sandbox_home}
OC_LINK="$SANDBOX_HOME/.openclaw"

# Resolve the real OpenClaw home (follows symlink)
if [ -L "$OC_LINK" ]; then
    OC_REAL=$(readlink "$OC_LINK")
else
    OC_REAL="$OC_LINK"
fi

# Ensure parent directories are traversable (o+x) so the sandbox user
# can follow the symlink. /root/ is typically 700 which blocks access.
dir=$(dirname "$OC_REAL")
while [ "$dir" != "/" ] && [ -n "$dir" ]; do
    perms=$(stat -c %a "$dir" 2>/dev/null || echo "")
    if [ -n "$perms" ]; then
        other_x=$((perms % 10))
        if [ $((other_x & 1)) -eq 0 ]; then
            chmod o+x "$dir"
            echo "Added o+x to $dir"
        fi
    fi
    dir=$(dirname "$dir")
done

# Fix ownership — ensure sandbox user owns everything under OpenClaw home
chown -R sandbox:sandbox "$OC_REAL" 2>/dev/null || true

# Also fix /home/sandbox/.openclaw (the actual home dir, not just symlink target).
# Node.js uses atomic writes (write-to-temp then rename) which bypass default
# ACLs entirely, and explicit open(path, 0600) resets the ACL mask to ---.
# Both patterns require a blanket fix-up on every startup.
_fix_acls() {{
    local target="$1"
    [ -d "$target" ] || return 0
    chown -R sandbox:sandbox "$target" 2>/dev/null || true
    setfacl -R -m u:sandbox:rwX "$target" 2>/dev/null || true
    setfacl -R -d -m u:sandbox:rwX "$target" 2>/dev/null || true
    setfacl -R -m m::rwx "$target" 2>/dev/null || true
    setfacl -R -d -m m::rwx "$target" 2>/dev/null || true
}}

if command -v setfacl >/dev/null 2>&1; then
    _fix_acls "$OC_REAL"
    # Sandbox home may differ from symlink target (e.g. /home/sandbox/.openclaw
    # is a real dir while OC_REAL points to /root/.openclaw).
    if [ "$SANDBOX_HOME/.openclaw" != "$OC_REAL" ] && [ -d "$SANDBOX_HOME/.openclaw" ]; then
        _fix_acls "$SANDBOX_HOME/.openclaw"
    fi
    # Parent traversal via ACL (targeted — doesn't open /root to all users)
    dir="$OC_REAL"
    while [ "$dir" != "/" ] && [ -n "$dir" ]; do
        dir=$(dirname "$dir")
        setfacl -m u:sandbox:rx "$dir" 2>/dev/null || true
    done
fi

for ns in $(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{{print $1}}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done

find "$SANDBOX_HOME/.openclaw/agents/" -name "*.lock" -delete 2>/dev/null || true

if [ -f "$SANDBOX_HOME/.openclaw/gateway.pid" ]; then
    pid=$(cat "$SANDBOX_HOME/.openclaw/gateway.pid")
    if ! (kill -0 "$pid" 2>/dev/null && \\
          grep -q openshell "/proc/$pid/cmdline" 2>/dev/null); then
        rm -f "$SANDBOX_HOME/.openclaw/gateway.pid"
        echo "Cleaned stale PID file (pid=$pid)"
    fi
fi
"""

    start_sandbox = f"""#!/bin/bash
set -euo pipefail

DEFENSECLAW_DIR={q_data_dir}
RESOLV_FILE="$DEFENSECLAW_DIR/sandbox-resolv.conf"
POLICY_REGO="$DEFENSECLAW_DIR/openshell-policy.rego"
POLICY_DATA="$DEFENSECLAW_DIR/openshell-policy.yaml"
SANDBOX_HOME={q_sandbox_home}

exec unshare --mount -- bash -c '
    mount --bind '"$RESOLV_FILE"' /etc/resolv.conf
    exec openshell-sandbox \\
        --policy-rules '"$POLICY_REGO"' \\
        --policy-data '"$POLICY_DATA"' \\
        --log-level info \\
        --timeout 0 \\
        -w '"$SANDBOX_HOME"' \\
        -- '"$SANDBOX_HOME"'/start-openclaw.sh
'
"""

    post_sandbox = f"""#!/bin/bash
set -euo pipefail

DEFENSECLAW_DIR={q_data_dir}
HOST_IP={q_host_ip}
API_PORT={api_port}
GUARDRAIL_PORT={guardrail_port}

# Wait for the veth pair to come up
for i in $(seq 1 30); do
    if ip addr show | grep -q "$HOST_IP"; then
        break
    fi
    sleep 1
done

if ! ip addr show | grep -q "$HOST_IP"; then
    echo "WARNING: veth pair not detected — openshell-sandbox manages networking internally" >&2
fi

# Attempt iptables injection into the sandbox namespace.
# openshell-sandbox creates namespaces programmatically and may not expose
# them in a way compatible with 'ip netns exec'. In that case, network
# policy is enforced by openshell-sandbox's built-in OPA proxy, which
# reads allowed endpoints from the policy data YAML.
NS=$(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{{print $1}}' | head -1)
if [ -z "$NS" ]; then
    echo "NOTE: sandbox namespace not accessible via ip netns — OPA proxy handles network policy"
    exit 0
fi

if ip netns exec "$NS" true 2>/dev/null; then
    for ns in $(grep '^nameserver' "$DEFENSECLAW_DIR/sandbox-resolv.conf" | awk '{{print $2}}'); do
        ip netns exec "$NS" iptables -I OUTPUT 1 -p udp -d "$ns" --dport 53 -j ACCEPT 2>/dev/null || true
    done

    ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" --dport "$API_PORT" -j ACCEPT 2>/dev/null || true
    ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" \\
        --dport "$GUARDRAIL_PORT" -j ACCEPT 2>/dev/null || true

    echo "Injected iptables rules into namespace $NS"
else
    echo "NOTE: cannot enter namespace $NS — OPA proxy handles network policy"
fi
"""

    cleanup_sandbox = """#!/bin/bash
for ns in $(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{print $1}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done
"""

    start_openclaw = f"""#!/bin/bash
set -euo pipefail

export NO_PROXY={q_host_ip}"${{NO_PROXY:+,$NO_PROXY}}"

exec openclaw gateway run
"""

    for name, content in [
        ("pre-sandbox.sh", pre_sandbox),
        ("start-sandbox.sh", start_sandbox),
        ("post-sandbox.sh", post_sandbox),
        ("cleanup-sandbox.sh", cleanup_sandbox),
    ]:
        path = os.path.join(scripts_dir, name)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)

    oc_script = os.path.join(sandbox_home, "start-openclaw.sh")
    try:
        with open(oc_script, "w") as f:
            f.write(start_openclaw)
        os.chmod(oc_script, 0o755)
    except OSError:
        click.echo(f"  WARNING: Could not write {oc_script}. Create it manually.", err=True)


def _generate_run_sandbox_script(data_dir: str, host_ip: str, cfg) -> None:
    """Generate a standalone run-sandbox.sh that starts everything without systemd."""
    scripts_dir = os.path.join(data_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)

    gateway_bin = shutil.which("defenseclaw-gateway") or "defenseclaw-gateway"
    api_bind = host_ip
    api_port = int(cfg.gateway.api_port)

    q_gateway_bin = shlex.quote(gateway_bin)
    q_api_bind = shlex.quote(api_bind)

    script = f"""#!/bin/bash
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$(dirname "$SCRIPTS_DIR")"
PIDFILE="$DATA_DIR/sandbox.pids"
ACL_FIXER_PID=""

# ---------------------------------------------------------------------------
# kill_tree PID — recursively kill a process and all its descendants.
# Walks children depth-first so leaves die before parents, preventing zombies
# from being reparented to PID 1.
# ---------------------------------------------------------------------------
kill_tree() {{
    local pid=$1 sig=${{2:-TERM}}
    local children
    children=$(ps -o pid= --ppid "$pid" 2>/dev/null || true)
    for child in $children; do
        kill_tree "$child" "$sig"
    done
    kill -"$sig" "$pid" 2>/dev/null || true
}}

stop_sandbox() {{
    echo "Stopping sandbox processes..."

    # 1. Kill the ACL fixer first (lightweight, no children)
    if [ -n "$ACL_FIXER_PID" ] && kill -0 "$ACL_FIXER_PID" 2>/dev/null; then
        kill "$ACL_FIXER_PID" 2>/dev/null || true
        wait "$ACL_FIXER_PID" 2>/dev/null || true
        echo "  stopped acl-fixer (pid $ACL_FIXER_PID)"
    fi

    # 2. Kill tracked processes and their entire process trees
    if [ -f "$PIDFILE" ]; then
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill_tree "$pid" TERM
                echo "  sent SIGTERM to $name tree (pid $pid)"
            fi
        done < "$PIDFILE"

        # Give processes 3 seconds to exit gracefully
        sleep 3

        # Escalate to SIGKILL for anything still alive
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill_tree "$pid" KILL
                echo "  sent SIGKILL to $name tree (pid $pid)"
            fi
        done < "$PIDFILE"

        # Reap all children to prevent zombies
        while read -r pid name; do
            wait "$pid" 2>/dev/null || true
        done < "$PIDFILE"

        rm -f "$PIDFILE"
    fi

    # 3. Kill any orphaned sandbox-related processes not tracked in the PID file.
    #    These can accumulate when previous runs used an older stop mechanism
    #    or when the script was killed without cleanup.
    _kill_strays() {{
        local pat="$1"
        local pids
        pids=$(pgrep -f "$pat" 2>/dev/null || true)
        for p in $pids; do
            # Don't kill ourselves or our parent
            [ "$p" = "$$" ] && continue
            [ "$p" = "$PPID" ] && continue
            kill "$p" 2>/dev/null && echo "  killed stray $pat (pid $p)"
        done
    }}
    _kill_strays openshell-sandbox
    _kill_strays defenseclaw-gateway
    _kill_strays "openclaw$"
    _kill_strays openclaw-gateway
    _kill_strays "dmesg --follow"

    # 4. Clean up network namespace and veth pairs
    "$SCRIPTS_DIR/cleanup-sandbox.sh" 2>/dev/null || true

    # 5. Reap any remaining background jobs (ACL fixer, etc.)
    wait 2>/dev/null || true

    echo "Sandbox stopped."
}}

if [ "${{1:-}}" = "stop" ]; then
    stop_sandbox
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run-sandbox.sh requires root" >&2
    exit 1
fi

trap 'stop_sandbox; exit 0' EXIT INT TERM

rm -f "$PIDFILE"

# 1. Clean stale state
echo "==> Cleaning stale state..."
"$SCRIPTS_DIR/pre-sandbox.sh"

# 2. Start openshell-sandbox in background
echo "==> Starting openshell-sandbox..."
"$SCRIPTS_DIR/start-sandbox.sh" &
SANDBOX_PID=$!
echo "$SANDBOX_PID openshell-sandbox" >> "$PIDFILE"
echo "  openshell-sandbox started (pid $SANDBOX_PID)"

# 3. Wait for sandbox namespace to appear
echo "==> Waiting for sandbox namespace..."
for i in $(seq 1 30); do
    if ! kill -0 "$SANDBOX_PID" 2>/dev/null; then
        echo "ERROR: openshell-sandbox exited prematurely" >&2
        wait "$SANDBOX_PID" 2>/dev/null
        exit 1
    fi
    if ip netns list 2>/dev/null | grep -qE 'sandbox|openshell'; then
        break
    fi
    sleep 1
done

if ! ip netns list 2>/dev/null | grep -qE 'sandbox|openshell'; then
    echo "ERROR: sandbox namespace not created after 30s" >&2
    exit 1
fi
echo "  namespace ready"

# 4. Inject iptables rules
echo "==> Injecting iptables rules..."
"$SCRIPTS_DIR/post-sandbox.sh"

# 5. Start defenseclaw-gateway
echo "==> Starting defenseclaw-gateway..."
{q_gateway_bin} &
GATEWAY_PID=$!
echo "$GATEWAY_PID defenseclaw-gateway" >> "$PIDFILE"
echo "  defenseclaw-gateway started (pid $GATEWAY_PID)"

sleep 2

# 6. Health check
if curl -sf "http://{q_api_bind}:{api_port}/health" -o /dev/null 2>/dev/null; then
    echo ""
    echo "==> Sandbox is running"
    echo "    sidecar health: http://{q_api_bind}:{api_port}/health"
    echo "    stop with:      $SCRIPTS_DIR/run-sandbox.sh stop"
    echo ""
else
    echo "WARNING: sidecar health check failed (http://{q_api_bind}:{api_port}/health)" >&2
fi

# 7. Background ACL fixer — OpenClaw uses atomic writes (write-to-temp then
# rename) which bypass POSIX default ACLs, and explicit open(path, 0600)
# resets the ACL mask to ---.  This loop periodically re-applies correct ACLs
# so the sandbox user can always read/write OpenClaw config and extensions.
_fix_sandbox_acls() {{
    while kill -0 "$SANDBOX_PID" 2>/dev/null; do
        sleep 5
        for d in /root/.openclaw /home/sandbox/.openclaw; do
            [ -d "$d" ] || continue
            setfacl -R -m u:sandbox:rwX "$d" 2>/dev/null || true
            setfacl -R -m m::rwx "$d" 2>/dev/null || true
        done
    done
}}
_fix_sandbox_acls &
ACL_FIXER_PID=$!

# Keep running until signalled
wait
"""

    path = os.path.join(scripts_dir, "run-sandbox.sh")
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)


def _extract_ed25519_pubkey(key_data: bytes) -> bytes | None:
    """Extract the Ed25519 public key from a device key file.

    Supports PEM-encoded seeds (as written by the Go gateway) and raw
    32/64-byte keys. Returns the 32-byte public key or None.
    """
    import base64

    # PEM format: -----BEGIN ED25519 PRIVATE KEY-----\n<base64 seed>\n-----END ...
    text = key_data.decode("utf-8", errors="replace")
    if "BEGIN ED25519 PRIVATE KEY" in text:
        lines = text.strip().splitlines()
        b64_lines = [line for line in lines if not line.startswith("-----")]
        try:
            seed = base64.b64decode("".join(b64_lines))
        except Exception:
            return None
        if len(seed) != 32:
            return None
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub_bytes = priv.public_key().public_bytes_raw()
        return pub_bytes

    # Raw binary: 64-byte key (seed + pub) or 32-byte pub
    if len(key_data) == 64:
        return key_data[32:]
    if len(key_data) == 32:
        return key_data
    return None


def _pre_pair_device(data_dir: str, sandbox_home: str) -> bool:
    """Pre-inject the sidecar's device key into OpenClaw's devices/paired.json."""
    import base64
    import hashlib
    import time

    device_key_file = os.path.join(data_dir, "device.key")
    if not os.path.isfile(device_key_file):
        return False

    try:
        with open(device_key_file, "rb") as f:
            key_data = f.read()
    except OSError:
        return False

    pub_key = _extract_ed25519_pubkey(key_data)
    if pub_key is None:
        return False

    pub_b64 = base64.urlsafe_b64encode(pub_key).decode().rstrip("=")
    device_id = hashlib.sha256(pub_key).hexdigest()

    devices_dir = os.path.join(sandbox_home, ".openclaw", "devices")
    paired_path = os.path.join(devices_dir, "paired.json")
    paired: dict = {}

    if os.path.isfile(paired_path):
        try:
            with open(paired_path) as f:
                paired = _json.load(f)
            if not isinstance(paired, dict):
                paired = {}
        except (OSError, _json.JSONDecodeError):
            paired = {}

    now_ms = int(time.time() * 1000)
    existing = paired.get(device_id, {})
    paired[device_id] = {
        "deviceId": device_id,
        "publicKey": pub_b64,
        "displayName": "defenseclaw-sidecar",
        "platform": "linux",
        "deviceFamily": existing.get("deviceFamily"),
        "clientId": "gateway-client",
        "clientMode": "backend",
        "role": "operator",
        "roles": ["operator"],
        "scopes": [
            "operator.read",
            "operator.write",
            "operator.admin",
            "operator.approvals",
        ],
        "approvedScopes": [
            "operator.read",
            "operator.write",
            "operator.admin",
            "operator.approvals",
        ],
        "tokens": existing.get("tokens", {}),
        "createdAtMs": existing.get("createdAtMs", now_ms),
        "approvedAtMs": now_ms,
    }

    os.makedirs(devices_dir, exist_ok=True)
    with open(paired_path, "w") as f:
        _json.dump(paired, f, indent=2)
        f.write("\n")

    # Ensure the sandbox user can read the paired device file
    try:
        import pwd as _pwd
        import shutil
        sandbox_uid = _pwd.getpwnam("sandbox").pw_uid
        sandbox_gid = _pwd.getpwnam("sandbox").pw_gid
        for d in [devices_dir, paired_path]:
            shutil.chown(d, sandbox_uid, sandbox_gid)
    except (KeyError, OSError):
        pass

    return True


def _find_repo_root() -> str | None:
    """Walk up from this file to find the repo root (contains policies/ dir)."""
    path = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.isdir(os.path.join(path, "policies")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return None
