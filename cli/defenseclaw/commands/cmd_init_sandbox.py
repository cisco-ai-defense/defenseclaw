"""defenseclaw sandbox init — Initialize sandbox mode.

Requires ``defenseclaw init`` to have been run first.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import click

from defenseclaw.context import AppContext, pass_ctx

OPENCLAW_OWNERSHIP_BACKUP = "openclaw-ownership-backup.json"

_SANDBOX_SYSTEM_DEPS = ["iptables"]


@click.command("init")
@pass_ctx
def sandbox_init_cmd(app: AppContext) -> None:
    """Initialize openshell-sandbox standalone mode (Linux only).

    Creates the sandbox user, transfers OpenClaw ownership, installs
    the DefenseClaw plugin into the sandbox, and configures networking.

    \b
    Prerequisite:
      Run 'defenseclaw init' first to set up the base environment.

    \b
    Example:
      defenseclaw sandbox init
    """
    import platform

    from defenseclaw.config import config_path, load

    if platform.system() != "Linux":
        click.echo("  ERROR: Sandbox mode requires Linux.", err=True)
        raise SystemExit(1)

    if not os.path.exists(config_path()):
        click.echo("  ERROR: DefenseClaw is not initialized.", err=True)
        click.echo("         Run 'defenseclaw init' first.", err=True)
        raise SystemExit(1)

    cfg = app.cfg or load()
    app.cfg = cfg

    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    store = app.store or Store(cfg.audit_db)
    logger = app.logger or Logger(store)

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
            from defenseclaw.commands.cmd_setup_sandbox import setup_sandbox
            ctx = click.Context(setup_sandbox, parent=click.get_current_context())
            ctx.invoke(setup_sandbox, sandbox_ip="10.200.0.2", host_ip="10.200.0.1",
                       sandbox_home=None, openclaw_port=18789, dns="8.8.8.8,1.1.1.1",
                       policy="default", no_auto_pair=False, disable=False,
                       non_interactive=True)

    click.echo()
    click.echo("  ──────────────────────────────────────────────────────")
    click.echo()
    click.echo("  Next steps:")
    click.echo("    defenseclaw setup guardrail   Enable LLM traffic inspection")
    click.echo("    defenseclaw sandbox setup     Customize sandbox networking")
    click.echo()

    if not app.store:
        store.close()


# ---------------------------------------------------------------------------
# Sandbox helpers
# ---------------------------------------------------------------------------

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
        click.echo("  Re-run 'defenseclaw sandbox init' when ready.")
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
        click.echo("  Plugin:        already installed")
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
    oc_target = os.path.realpath(os.path.join(sandbox_home, ".openclaw"))
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


def _detect_openclaw_home() -> str | None:
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
        click.echo("                 Install OpenClaw first, then re-run 'defenseclaw sandbox init'")
        click.echo("                 Install: curl -fsSL https://openclaw.ai/install.sh | bash")
        return False

    click.echo(f"  OpenClaw:      detected at {detected}")
    click.echo()
    click.echo("  \u26a0 WARNING: Sandbox integration will change ownership of this directory")
    click.echo("    to the 'sandbox' user. OpenClaw will NOT be usable outside the sandbox")
    click.echo("    until reversed with 'defenseclaw sandbox setup --disable'.")
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

    try:
        _save_ownership_backup(confirmed_path, cfg.data_dir)
        click.echo(f"  Backup:        ownership saved to {backup_path}")
    except OSError as exc:
        click.echo(f"  Backup:        failed ({exc})")
        return False

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


def _find_plugin_source() -> str | None:
    """Locate the built DefenseClaw plugin directory.

    Checks: data_dir staging, repo-relative, bundled _data/.
    """
    from pathlib import Path

    from defenseclaw.config import default_data_path
    staging = Path(str(default_data_path())) / "extensions" / "defenseclaw" / "dist" / "index.js"
    if staging.is_file():
        return str(staging.parent.parent)

    here = Path(__file__).resolve()
    for ancestor in [here.parent.parent.parent.parent,
                     here.parent.parent.parent]:
        candidate = ancestor / "extensions" / "defenseclaw"
        if (candidate / "dist" / "index.js").is_file():
            return str(candidate)

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


def _find_openshell_policies_dir() -> Path | None:
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


def _find_installer_script() -> str | None:
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
