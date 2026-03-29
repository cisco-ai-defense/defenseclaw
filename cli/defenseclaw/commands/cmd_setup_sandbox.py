"""Sandbox setup command — defenseclaw sandbox setup."""

from __future__ import annotations

import json as _json
import os
import shlex
import shutil
import subprocess

import click

from defenseclaw.commands.cmd_init_sandbox import (
    _ensure_sudo_cache,
    _fix_data_dir_ownership,
    _needs_sudo,
    _sudo_prefix,
    _sudo_write,
)
from defenseclaw.context import AppContext, pass_ctx


def _sudo_read_json(path: str) -> dict | None:
    """Read a JSON file that may require sudo (e.g. inside /home/sandbox/)."""
    try:
        if _needs_sudo():
            result = subprocess.run(
                [*_sudo_prefix(), "cat", path],
                capture_output=True, text=True, check=True,
            )
            return _json.loads(result.stdout)
        with open(path) as f:
            return _json.load(f)
    except (OSError, _json.JSONDecodeError, subprocess.CalledProcessError):
        return None


def restore_sandbox_ownership_if_needed(cfg) -> None:
    """Restore sandbox ownership of .openclaw dir if running in standalone mode."""
    if not cfg.openshell.is_standalone():
        return
    sandbox_home = cfg.openshell.effective_sandbox_home()
    oc_target = os.path.realpath(os.path.join(sandbox_home, ".openclaw"))
    try:
        subprocess.run(
            [*_sudo_prefix(), "chown", "-R", "sandbox:sandbox", oc_target],
            capture_output=True, check=False,
        )
    except FileNotFoundError:
        pass


def _find_openclaw_binary() -> str:
    """Locate the openclaw binary for use in generated launcher scripts.

    Checks system PATH first, then the invoking user's npm global prefix
    (which may not be on PATH, especially under sudo).
    """
    found = shutil.which("openclaw")
    if found:
        return found

    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
    if sudo_user:
        try:
            import pwd as _pwd
            pw = _pwd.getpwnam(sudo_user)
            result = subprocess.run(
                ["sudo", "-u", sudo_user, "npm", "config", "get", "prefix"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                prefix = result.stdout.strip()
                if prefix:
                    candidate = os.path.join(prefix, "bin", "openclaw")
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                        return candidate

            for bindir in [".local/bin", ".nvm/current/bin"]:
                candidate = os.path.join(pw.pw_dir, bindir, "openclaw")
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    return candidate
        except (KeyError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return "openclaw"


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
@click.option("--no-host-networking", is_flag=True,
              help="Skip host-side iptables rules (DNS, UI forwarding, MASQUERADE)")
@click.option("--no-guardrail", is_flag=True,
              help="Skip guardrail network setup (API_PORT + GUARDRAIL_PORT iptables)")
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
    no_host_networking: bool,
    no_guardrail: bool,
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
        _ensure_sudo_cache()
        _disable_sandbox(app)
        return

    if platform.system() != "Linux":
        click.echo("  ERROR: Sandbox mode requires Linux.", err=True)
        raise SystemExit(1)

    _ensure_sudo_cache()

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
    if no_host_networking:
        app.cfg.openshell.host_networking = False
    if no_guardrail:
        app.cfg.guardrail.enabled = False

    app.cfg.gateway.host = sandbox_ip
    app.cfg.gateway.port = openclaw_port
    if app.cfg.guardrail.enabled:
        app.cfg.guardrail.host = host_ip
    app.cfg.gateway.watcher.enabled = True
    app.cfg.gateway.watcher.skill.enabled = True
    app.cfg.gateway.watcher.skill.take_action = True

    app.cfg.claw.home_dir = os.path.join(sandbox_home, ".openclaw")
    app.cfg.claw.config_file = os.path.join(sandbox_home, ".openclaw", "openclaw.json")

    click.echo("    openshell.mode:       standalone")
    click.echo(f"    openshell.sandbox_home: {sandbox_home}")
    click.echo(f"    openshell.host_networking: {app.cfg.openshell.host_networking}")
    click.echo(f"    gateway.host:         {sandbox_ip}")
    if app.cfg.guardrail.enabled:
        click.echo(f"    guardrail.host:       {host_ip}")
    else:
        click.echo("    guardrail:            disabled (use 'defenseclaw setup guardrail' to enable)")
    click.echo(f"    claw.home_dir:        {app.cfg.claw.home_dir}")

    # 3. Read OpenClaw config (token resolution deferred to after pairing — step 9b).
    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    oc_json = _sudo_read_json(oc_config)

    # 4. Install policy template
    _install_policy_template(data_dir, policy)
    click.echo(f"    policy template:      {policy}")

    # 5. Generate DNS resolv.conf (only when host networking is active)
    if app.cfg.openshell.host_networking:
        _generate_resolv_conf(data_dir, dns)
        click.echo(f"    dns nameservers:      {dns}")
    else:
        click.echo("    dns:                  managed by openshell-sandbox (host networking disabled)")

    # 6. Patch sandbox-side OpenClaw config (port + bind + guardrail baseUrl)
    if oc_json is not None:
        _patch_openclaw_gateway(oc_config, openclaw_port, existing_cfg=oc_json, host_ip=host_ip)
        click.echo(f"    openclaw.json:        patched (gateway.port={openclaw_port}, gateway.bind=lan)")

    # 7. Generate systemd unit files
    _generate_systemd_units(data_dir, sandbox_home, host_ip, sandbox_ip, app.cfg)
    click.echo(f"    systemd units:        generated in {data_dir}")

    # 8. Generate launcher scripts
    _generate_launcher_scripts(data_dir, sandbox_home, host_ip, sandbox_ip, app.cfg)
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

    # 9b. Read the shared gateway.auth.token from openclaw.json.
    #     This is the canonical auth token — device-auth.json is a client-side
    #     cache used by the OpenClaw Node.js client, not by our Go gateway.
    detected_token = (oc_json or {}).get("gateway", {}).get("auth", {}).get("token", "")

    if detected_token:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected_token, data_dir)
        app.cfg.gateway.token = ""
        app.cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        click.echo(f"    gateway.token:        detected ({_mask(detected_token)})")
    else:
        click.echo("    gateway.token:        not found (sidecar will auto-detect on connect)")

    # 10a. Install CodeGuard skill into the sandbox-owned OpenClaw tree
    _install_codeguard_to_sandbox(app.cfg, sandbox_home)

    # 10b. Install guardrail plugin into the sandbox-owned OpenClaw extensions
    if app.cfg.guardrail.enabled:
        _install_guardrail_plugin_to_sandbox(sandbox_home)

    # 11. Fix ownership and traversal — all files written above (openclaw.json
    #     patch, paired.json, policy templates) were created as the invoking
    #     user.  Restore sandbox ownership so the OpenClaw process can
    #     read/write them.  Also ensure parent directories (e.g. /root/) have
    #     o+x so the sandbox user can follow the symlink to the real OpenClaw home.
    oc_target = os.path.realpath(os.path.join(sandbox_home, ".openclaw"))
    try:
        subprocess.run(
            [*_sudo_prefix(), "chown", "-R", "sandbox:sandbox", oc_target],
            capture_output=True, check=False,
        )
    except FileNotFoundError:
        pass

    from defenseclaw.commands.cmd_init_sandbox import _ensure_parent_traversal
    _ensure_parent_traversal(oc_target)

    # 12. Add invoking user to sandbox group so the gateway watcher can
    #     observe skill/extension directories owned by sandbox:sandbox.
    _add_user_to_sandbox_group()
    _grant_watcher_acls(sandbox_home, app.cfg)

    # 13. Save config
    app.cfg.save()

    # 14. Stop host-side OpenClaw — the sandbox will run its own instance.
    #     Leaving the host one running causes duplicate openclaw-gateway
    #     processes and token conflicts.
    _stop_host_openclaw()

    # 15. Install systemd units and launcher scripts (if systemd present)
    has_systemd = shutil.which("systemctl") is not None
    installed = _install_systemd_units(data_dir) if has_systemd else False

    # 16. Generate convenience run-sandbox.sh for non-systemd environments
    _generate_run_sandbox_script(data_dir, host_ip, app.cfg)

    # 17. Fix data_dir ownership — files written by root (systemd units,
    #     scripts, config) should be owned by the invoking user.
    _fix_data_dir_ownership(data_dir)

    click.echo()
    click.echo("  ── Summary ───────────────────────────────────────────")
    click.echo()
    click.echo("  Sandbox mode configured successfully.")
    click.echo()

    if installed:
        click.echo("  ✓ Systemd units installed and daemon reloaded")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Start the sandbox:")
        click.echo("       sudo systemctl start defenseclaw-sandbox.target")
        click.echo()
        click.echo("    2. (Re)start the gateway:")
        click.echo("       defenseclaw-gateway start")
        click.echo()
        click.echo("  Stop:")
        click.echo("       sudo systemctl stop defenseclaw-sandbox.target")
        click.echo()
        click.echo("  Logs:")
        click.echo("       sudo journalctl -u openshell-sandbox -f")
        click.echo(f"       {data_dir}/gateway.log")
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
        click.echo("    2. Start the sandbox:")
        click.echo("       sudo systemctl start defenseclaw-sandbox.target")
        click.echo()
        click.echo("    3. (Re)start the gateway:")
        click.echo("       defenseclaw-gateway start")
        click.echo()
        click.echo("  Stop:")
        click.echo("       sudo systemctl stop defenseclaw-sandbox.target")
        click.echo()
        click.echo("  Logs:")
        click.echo("       sudo journalctl -u openshell-sandbox -f")
        click.echo(f"       {data_dir}/gateway.log")
    else:
        click.echo("  ℹ No systemd detected (container/minimal environment).")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Start the sandbox manually:")
        click.echo(f"       sudo {data_dir}/scripts/run-sandbox.sh")
        click.echo()
        click.echo("  Stop:")
        click.echo(f"       sudo {data_dir}/scripts/run-sandbox.sh stop")
        click.echo()
        click.echo("  Logs:")
        click.echo(f"       {data_dir}/gateway.log")
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
            [*_sudo_prefix(), "chown", "-R", f"{uid}:{gid}", openclaw_home],
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
        result = subprocess.run(
            [*_sudo_prefix(), "chmod", oct(mode_int)[-4:], real_ppath],
            capture_output=True, check=False,
        )
        if result.returncode == 0:
            click.echo(f"  Traversal:     restored {ppath} to {orig_mode}")

    # Remove symlink from sandbox home
    symlink_path = os.path.join(sandbox_home, ".openclaw")
    if os.path.islink(symlink_path):
        result = subprocess.run(
            [*_sudo_prefix(), "rm", "-f", symlink_path],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            click.echo(f"  Symlink:       removed {symlink_path}")
        else:
            click.echo(f"  Symlink:       remove failed ({result.stderr.strip()})")

    # Remove backup file
    try:
        os.remove(backup_path)
    except OSError:
        pass


def _disable_sandbox(app: AppContext) -> None:
    """Revert to host mode: restore OpenClaw ownership, clean up symlink, reset config."""
    sandbox_home = app.cfg.openshell.effective_sandbox_home()

    # Capture current sandbox IPs/port before resetting config.
    # gateway.host may already be reset to 127.0.0.1 if --disable ran before,
    # so fall back to the well-known default sandbox IP.
    cfg_host = app.cfg.gateway.host
    sandbox_ip = cfg_host if cfg_host not in ("127.0.0.1", "localhost", "") else "10.200.0.2"
    openclaw_port = int(app.cfg.gateway.port)

    # 1. Stop and disable systemd units
    _disable_systemd_units()

    # 2. Remove iptables rules
    if app.cfg.openshell.host_networking:
        _remove_iptables_rules(sandbox_ip, openclaw_port)

    # 3. Restore gateway config in openclaw.json BEFORE removing the symlink
    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    oc_exists = subprocess.run(
        [*_sudo_prefix(), "test", "-f", oc_config], capture_output=True,
    ).returncode == 0
    if oc_exists:
        _restore_openclaw_gateway(oc_config)

    # 4. Restore original OpenClaw ownership and remove symlink
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


def _disable_systemd_units() -> None:
    """Stop and disable sandbox systemd units."""
    units = ["defenseclaw-sandbox.target", "openshell-sandbox.service"]
    for unit in units:
        subprocess.run(
            [*_sudo_prefix(), "systemctl", "stop", unit],
            capture_output=True, check=False,
        )
        subprocess.run(
            [*_sudo_prefix(), "systemctl", "disable", unit],
            capture_output=True, check=False,
        )
    subprocess.run(
        [*_sudo_prefix(), "systemctl", "daemon-reload"],
        capture_output=True, check=False,
    )
    click.echo("  Systemd:       sandbox units stopped and disabled")


def _remove_iptables_rules(sandbox_ip: str, openclaw_port: int) -> None:
    """Remove iptables NAT rules added during sandbox setup."""
    rules = [
        ["-t", "nat", "-D", "OUTPUT", "-d", "127.0.0.1",
         "-p", "tcp", "--dport", str(openclaw_port),
         "-j", "DNAT", "--to-destination", f"{sandbox_ip}:{openclaw_port}"],
        ["-t", "nat", "-D", "POSTROUTING", "-d", sandbox_ip,
         "-p", "tcp", "--dport", str(openclaw_port),
         "-j", "MASQUERADE"],
        ["-t", "nat", "-D", "POSTROUTING", "-s", "10.200.0.0/24",
         "-p", "udp", "--dport", "53",
         "-j", "MASQUERADE"],
    ]
    removed = 0
    for rule in rules:
        result = subprocess.run(
            [*_sudo_prefix(), "iptables", *rule],
            capture_output=True, check=False,
        )
        if result.returncode == 0:
            removed += 1
    subprocess.run(
        [*_sudo_prefix(), "sysctl", "-w", "net.ipv4.conf.all.route_localnet=0"],
        capture_output=True, check=False,
    )
    if removed > 0:
        click.echo(f"  iptables:      removed {removed} NAT rules")
    else:
        click.echo("  iptables:      clean (already removed by sandbox shutdown)")


def _validate_sandbox_prerequisites(sandbox_home: str) -> None:
    """Check that required prerequisites exist; abort if missing."""
    import pwd
    missing: list[str] = []
    try:
        pwd.getpwnam("sandbox")
    except KeyError:
        missing.append("'sandbox' user not found")

    if not os.path.isdir(sandbox_home):
        missing.append(f"sandbox home {sandbox_home} does not exist")

    if missing:
        detail = "\n  ".join(f"- {m}" for m in missing)
        raise click.ClickException(
            f"Sandbox not initialized. Run 'defenseclaw sandbox init' first.\n  {detail}"
        )


def _add_user_to_sandbox_group() -> None:
    """Add the invoking user to the sandbox group.

    This lets the gateway's file watcher (running as the invoking user)
    read skill/extension directories owned by sandbox:sandbox.
    """
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
    if not sudo_user or sudo_user in ("root", "sandbox"):
        return

    import grp
    try:
        members = grp.getgrnam("sandbox").gr_mem
    except KeyError:
        return

    if sudo_user in members:
        return

    result = subprocess.run(
        [*_sudo_prefix(), "usermod", "-aG", "sandbox", sudo_user],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        click.echo(f"    group membership:    {sudo_user} added to sandbox group")
        msg = click.style("(log out and back in for this to take effect)", fg="green")
        click.echo(f"                         {msg}")
    else:
        click.echo(f"    group membership:    failed ({result.stderr.strip()})", err=True)


def _grant_watcher_acls(sandbox_home: str, cfg) -> None:
    """Grant the invoking user read+execute ACLs on sandbox directories.

    The gateway watcher runs as the invoking user and needs to traverse
    sandbox-owned directories to watch for skill/plugin changes. Group
    membership alone requires a re-login; setfacl takes effect immediately.
    """
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
    if not sudo_user or sudo_user in ("root", "sandbox"):
        return

    if not shutil.which("setfacl"):
        return

    oc_home = os.path.join(sandbox_home, ".openclaw")
    dirs = [
        sandbox_home,
        oc_home,
        os.path.join(oc_home, "skills"),
        os.path.join(oc_home, "workspace"),
        os.path.join(oc_home, "workspace", "skills"),
        os.path.join(oc_home, "extensions"),
    ]
    # The gateway also needs to read openclaw.json for skill dir autodiscovery
    files = [
        os.path.join(oc_home, "openclaw.json"),
    ]

    granted = 0
    for d in dirs:
        if not os.path.isdir(d):
            continue
        result = subprocess.run(
            [*_sudo_prefix(), "setfacl", "-m", f"u:{sudo_user}:rx,m::rx", d],
            capture_output=True, check=False,
        )
        if result.returncode == 0:
            granted += 1
    for f in files:
        if not os.path.isfile(f):
            continue
        result = subprocess.run(
            [*_sudo_prefix(), "setfacl", "-m", f"u:{sudo_user}:r,m::r", f],
            capture_output=True, check=False,
        )
        if result.returncode == 0:
            granted += 1
    if granted:
        click.echo(f"    watcher ACLs:        granted read access on {granted} paths")


def _stop_host_openclaw() -> None:
    """Stop the host-side OpenClaw gateway before the sandbox starts its own.

    Only targets processes owned by the invoking user (SUDO_USER or USER),
    never the sandbox user's processes.
    """
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
    if not sudo_user or sudo_user in ("root", "sandbox"):
        return

    result = subprocess.run(
        ["pgrep", "-u", sudo_user, "-f", "openclaw-gateway"],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return

    openclaw_bin = _find_openclaw_binary()
    if not openclaw_bin:
        return

    # Always run as the original user — we're stopping *their* gateway,
    # and we may be running as root via sudo.
    run_as = ["sudo", "-u", sudo_user] if os.getuid() == 0 else []
    try:
        subprocess.run(
            [*run_as, openclaw_bin, "gateway", "stop"],
            capture_output=True, timeout=10,
        )
        click.echo("    host openclaw:       stopped (sandbox will run its own)")
    except subprocess.TimeoutExpired:
        click.echo("    host openclaw:       stop timed out (kill manually if needed)")


def _install_codeguard_to_sandbox(cfg, sandbox_home: str) -> None:
    """Install CodeGuard skill into the sandbox-owned OpenClaw skills directory.

    Uses sudo because ~/.openclaw/ is owned by sandbox:sandbox at this point.
    The caller is responsible for chowning the tree afterward.
    """
    from defenseclaw.paths import bundled_codeguard_dir

    source_dir = bundled_codeguard_dir()
    if not source_dir.is_dir() or not (source_dir / "SKILL.md").is_file():
        click.echo("    codeguard:           skipped (skill source not found)")
        return

    skill_dirs = cfg.skill_dirs()
    if not skill_dirs:
        click.echo("    codeguard:           skipped (no skill directories)")
        return

    target_dir = os.path.join(skill_dirs[0], "codeguard")
    subprocess.run(
        [*_sudo_prefix(), "mkdir", "-p", skill_dirs[0]],
        capture_output=True, check=False,
    )
    subprocess.run(
        [*_sudo_prefix(), "rm", "-rf", target_dir],
        capture_output=True, check=False,
    )
    subprocess.run(
        [*_sudo_prefix(), "cp", "-r", str(source_dir), target_dir],
        capture_output=True, check=False,
    )

    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    oc_json = _sudo_read_json(oc_config)
    if oc_json is not None:
        skills = oc_json.setdefault("skills", {})
        entries = skills.setdefault("entries", {})
        entries["codeguard"] = {"enabled": True}
        content = _json.dumps(oc_json, indent=2, ensure_ascii=False) + "\n"
        _sudo_write(content, oc_config)

    click.echo(f"    codeguard:           installed to {target_dir}")


def _install_guardrail_plugin_to_sandbox(sandbox_home: str) -> None:
    """Install the DefenseClaw guardrail plugin into the sandbox OpenClaw extensions.

    Copies the plugin files and registers it in openclaw.json so OpenClaw
    routes LLM traffic through the guardrail proxy.
    """
    from defenseclaw.paths import bundled_extensions_dir

    source_dir = bundled_extensions_dir()
    if not source_dir.is_dir() or not (source_dir / "package.json").is_file():
        click.echo("    guardrail plugin:    skipped (plugin source not found)")
        return

    oc_ext = os.path.join(sandbox_home, ".openclaw", "extensions", "defenseclaw")
    subprocess.run(
        [*_sudo_prefix(), "mkdir", "-p", os.path.dirname(oc_ext)],
        capture_output=True, check=False,
    )
    subprocess.run(
        [*_sudo_prefix(), "rm", "-rf", oc_ext],
        capture_output=True, check=False,
    )
    subprocess.run(
        [*_sudo_prefix(), "cp", "-r", str(source_dir), oc_ext],
        capture_output=True, check=False,
    )

    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    oc_json = _sudo_read_json(oc_config)
    if oc_json is not None:
        plugins = oc_json.setdefault("plugins", {})
        allow = plugins.setdefault("allow", [])
        if "defenseclaw" not in allow:
            allow.append("defenseclaw")
        content = _json.dumps(oc_json, indent=2, ensure_ascii=False) + "\n"
        _sudo_write(content, oc_config)

    click.echo(f"    guardrail plugin:    installed to {oc_ext}")


def _patch_openclaw_gateway(
    openclaw_config: str, port: int, *, existing_cfg: dict | None = None,
    host_ip: str = "10.200.0.1",
) -> bool:
    """Patch gateway port and bind into openclaw.json for sandbox mode.

    Only sets mode/port/bind — the auth token is owned by OpenClaw and
    never written by DefenseClaw.  Also rewrites the guardrail provider
    baseUrl from localhost → host_ip so the sandbox can reach the proxy.
    """
    if existing_cfg is not None:
        import copy
        cfg = copy.deepcopy(existing_cfg)
    else:
        cfg = _sudo_read_json(openclaw_config)
        if cfg is None:
            return False

    gw = cfg.setdefault("gateway", {})
    gw["mode"] = "local"
    gw["port"] = port
    gw["bind"] = "lan"

    dc_provider = cfg.get("models", {}).get("providers", {}).get("defenseclaw", {})
    if dc_provider and "baseUrl" in dc_provider:
        from urllib.parse import urlparse
        parsed = urlparse(dc_provider["baseUrl"])
        dc_provider["baseUrl"] = f"http://{host_ip}:{parsed.port or 4000}"

    content = _json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"

    if _needs_sudo():
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        subprocess.run([*_sudo_prefix(), "cp", tmp_path, openclaw_config],
                       capture_output=True, check=False)
        os.unlink(tmp_path)
    else:
        with open(openclaw_config, "w") as f:
            f.write(content)

    subprocess.run(
        [*_sudo_prefix(), "chown", "sandbox:sandbox", openclaw_config],
        capture_output=True, check=False,
    )
    return True


def _restore_openclaw_gateway(openclaw_config: str) -> bool:
    """Restore gateway defaults in openclaw.json after sandbox mode."""
    cfg = _sudo_read_json(openclaw_config)
    if cfg is None:
        return False

    gw = cfg.get("gateway", {})
    gw["mode"] = "local"
    gw["port"] = 18789
    gw["bind"] = "loopback"

    dc_provider = cfg.get("models", {}).get("providers", {}).get("defenseclaw", {})
    if dc_provider and "baseUrl" in dc_provider:
        from urllib.parse import urlparse
        parsed = urlparse(dc_provider["baseUrl"])
        dc_provider["baseUrl"] = f"http://localhost:{parsed.port or 4000}"

    content = _json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"

    if _needs_sudo():
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        subprocess.run([*_sudo_prefix(), "cp", tmp_path, openclaw_config],
                       capture_output=True, check=False)
        os.unlink(tmp_path)
    else:
        with open(openclaw_config, "w") as f:
            f.write(content)

    # Ownership is restored by _restore_openclaw_ownership, not here.
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

    target_unit = """[Unit]
Description=DefenseClaw Sandbox
Wants=openshell-sandbox.service

[Install]
WantedBy=multi-user.target
"""

    with open(os.path.join(systemd_dir, "openshell-sandbox.service"), "w") as f:
        f.write(sandbox_unit)
    with open(os.path.join(systemd_dir, "defenseclaw-sandbox.target"), "w") as f:
        f.write(target_unit)


def _install_systemd_units(data_dir: str) -> bool:
    """Install generated systemd units and launcher scripts into system paths.

    Returns True if all steps succeeded.
    """
    import glob

    systemd_src = os.path.join(data_dir, "systemd")
    scripts_src = os.path.join(data_dir, "scripts")
    systemd_dst = "/etc/systemd/system"
    scripts_dst = "/usr/local/lib/defenseclaw"

    if not os.path.isdir(systemd_src):
        click.echo("    systemd install:     skipped (units not generated)")
        return False

    sudo = _sudo_prefix()
    try:
        for f in glob.glob(os.path.join(systemd_src, "*.service")) + \
                 glob.glob(os.path.join(systemd_src, "*.target")):
            subprocess.run([*sudo, "cp", f, systemd_dst],
                           capture_output=True, check=True)

        subprocess.run([*sudo, "mkdir", "-p", scripts_dst],
                       capture_output=True, check=True)
        if os.path.isdir(scripts_src):
            for f in glob.glob(os.path.join(scripts_src, "*.sh")):
                subprocess.run([*sudo, "cp", f, scripts_dst],
                               capture_output=True, check=True)
                subprocess.run([*sudo, "chmod", "755",
                                os.path.join(scripts_dst, os.path.basename(f))],
                               capture_output=True, check=False)

        subprocess.run(
            [*sudo, "systemctl", "daemon-reload"],
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
    sandbox_ip: str,
    cfg,
) -> None:
    """Generate launcher shell scripts for the sandbox lifecycle.

    Reads ``cfg.openshell.host_networking`` and ``cfg.guardrail.enabled`` to
    conditionally include DNS plumbing, UI forwarding, and guardrail iptables rules.
    """
    scripts_dir = os.path.join(data_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)

    host_networking = cfg.openshell.host_networking
    guardrail_enabled = cfg.guardrail.enabled

    api_port = int(cfg.gateway.api_port)
    guardrail_port = int(cfg.guardrail.port)
    openclaw_port = int(cfg.gateway.port)

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

    # start-sandbox.sh: conditionally mount resolv.conf for DNS
    if host_networking:
        start_sandbox_body = """\
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
    else:
        start_sandbox_body = f"""\
exec openshell-sandbox \\
    --policy-rules "$POLICY_REGO" \\
    --policy-data "$POLICY_DATA" \\
    --log-level info \\
    --timeout 0 \\
    -w {q_sandbox_home} \\
    -- {q_sandbox_home}/start-openclaw.sh
"""

    start_sandbox = f"""#!/bin/bash
set -euo pipefail

DEFENSECLAW_DIR={q_data_dir}
RESOLV_FILE="$DEFENSECLAW_DIR/sandbox-resolv.conf"
POLICY_REGO="$DEFENSECLAW_DIR/openshell-policy.rego"
POLICY_DATA="$DEFENSECLAW_DIR/openshell-policy.yaml"
SANDBOX_HOME={q_sandbox_home}

{start_sandbox_body}"""

    # post-sandbox.sh: conditionally inject DNS and guardrail iptables rules
    needs_iptables = host_networking or guardrail_enabled

    if needs_iptables:
        iptables_rules = ""

        if host_networking:
            iptables_rules += """
for ns in $(grep '^nameserver' "$DEFENSECLAW_DIR/sandbox-resolv.conf" | awk '{print $2}'); do
    $NSENTER iptables -I OUTPUT 1 -p udp -d "$ns" --dport 53 -j ACCEPT 2>/dev/null || true
done
"""

        if guardrail_enabled:
            iptables_rules += """
$NSENTER iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" --dport "$API_PORT" -j ACCEPT 2>/dev/null || true
$NSENTER iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" \\
    --dport "$GUARDRAIL_PORT" -j ACCEPT 2>/dev/null || true
"""

        masquerade_block = ""
        if host_networking:
            masquerade_block = """
# MASQUERADE DNS on the HOST side so responses from external nameservers
# route back to the sandbox IP (10.200.0.x).  Scoped to UDP port 53 only —
# all other sandbox traffic goes through the OPA proxy.
iptables -t nat -C POSTROUTING -s 10.200.0.0/24 -p udp --dport 53 -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -p udp --dport 53 -j MASQUERADE 2>/dev/null || true

# Allow DNAT from localhost to non-loopback addresses (required for UI forwarding).
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true

# Forward localhost:OPENCLAW_PORT to the sandbox so the UI is accessible
# from the host without SSH tunneling. Only local processes can reach this
# (OUTPUT chain, not PREROUTING).
iptables -t nat -C OUTPUT -d 127.0.0.1 -p tcp --dport "$OPENCLAW_PORT" \\
    -j DNAT --to-destination "$SANDBOX_IP:$OPENCLAW_PORT" 2>/dev/null || \\
    iptables -t nat -A OUTPUT -d 127.0.0.1 -p tcp --dport "$OPENCLAW_PORT" \\
    -j DNAT --to-destination "$SANDBOX_IP:$OPENCLAW_PORT" 2>/dev/null || true
iptables -t nat -C POSTROUTING -d "$SANDBOX_IP" -p tcp --dport "$OPENCLAW_PORT" \\
    -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -d "$SANDBOX_IP" -p tcp --dport "$OPENCLAW_PORT" \\
    -j MASQUERADE 2>/dev/null || true
"""

        post_sandbox = f"""#!/bin/bash
set -euo pipefail

DEFENSECLAW_DIR={q_data_dir}
HOST_IP={q_host_ip}
SANDBOX_IP={shlex.quote(sandbox_ip)}
API_PORT={api_port}
GUARDRAIL_PORT={guardrail_port}
OPENCLAW_PORT={openclaw_port}

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

# Resolve a command prefix for running iptables in the sandbox network
# namespace.  Try 'ip netns exec' first (works on real Linux hosts where
# openshell-sandbox registers the namespace under /var/run/netns/).  Fall
# back to 'nsenter --target <pid> --net' which works even in Docker where
# the namespace bind-mount may not be visible.
NSENTER=""

NS=$(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{{print $1}}' | head -1)
if [ -n "$NS" ] && ip netns exec "$NS" true 2>/dev/null; then
    NSENTER="ip netns exec $NS"
else
    for pid in $(pgrep -f openshell-sandbox 2>/dev/null); do
        child=$(pgrep -P "$pid" 2>/dev/null | head -1)
        if [ -n "$child" ]; then
            NSENTER="nsenter --target $child --net"
            break
        fi
    done
fi

if [ -z "$NSENTER" ]; then
    echo "NOTE: sandbox namespace not accessible — OPA proxy handles network policy"
    exit 0
fi
{iptables_rules}
echo "Injected iptables rules via $NSENTER"
{masquerade_block}"""
    else:
        post_sandbox = """#!/bin/bash
# No iptables rules needed (DNS override and guardrail both disabled)
exit 0
"""

    cleanup_iptables = ""
    if host_networking:
        cleanup_iptables = f"""
# Remove UI port forwarding rules
iptables -t nat -D OUTPUT -d 127.0.0.1 -p tcp --dport {openclaw_port} \\
    -j DNAT --to-destination {sandbox_ip}:{openclaw_port} 2>/dev/null || true
iptables -t nat -D POSTROUTING -d {sandbox_ip} -p tcp --dport {openclaw_port} \\
    -j MASQUERADE 2>/dev/null || true

# Remove DNS MASQUERADE
iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -p udp --dport 53 -j MASQUERADE 2>/dev/null || true

# Restore route_localnet
sysctl -w net.ipv4.conf.all.route_localnet=0 >/dev/null 2>&1 || true
"""

    cleanup_sandbox = f"""#!/bin/bash
{cleanup_iptables}
for ns in $(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{{print $1}}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done
"""

    # start-openclaw.sh: conditionally include DNS wait loop
    if host_networking:
        dns_wait = """\

# Wait for DNS — iptables rules are injected by post-sandbox.sh after
# the network namespace is created, so DNS may not work immediately.
for i in $(seq 1 30); do
    python3 -c "import socket; socket.getaddrinfo('api.telegram.org', 443)" 2>/dev/null && break
    sleep 1
done
"""
    else:
        dns_wait = ""

    openclaw_bin = _find_openclaw_binary()
    q_openclaw_bin = shlex.quote(openclaw_bin)

    start_openclaw = f"""#!/bin/bash
set -euo pipefail

export HTTPS_PROXY=http://{q_host_ip}:3128
export HTTP_PROXY=http://{q_host_ip}:3128
export NO_PROXY={q_host_ip}"${{NO_PROXY:+,$NO_PROXY}}"
{dns_wait}
exec {q_openclaw_bin} gateway run
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
    if not _sudo_write(start_openclaw, oc_script, mode=0o755):
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

    sudo = _sudo_prefix()
    subprocess.run([*sudo, "mkdir", "-p", devices_dir],
                   capture_output=True, check=False)

    content = _json.dumps(paired, indent=2) + "\n"
    _sudo_write(content, paired_path)

    subprocess.run(
        [*sudo, "chown", "-R", "sandbox:sandbox", devices_dir],
        capture_output=True, check=False,
    )

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
