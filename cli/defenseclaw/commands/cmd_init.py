"""defenseclaw init — Initialize DefenseClaw environment.

Mirrors internal/cli/init.go.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command("init")
@click.option("--skip-install", is_flag=True, help="Skip automatic scanner dependency installation")
@pass_ctx
def init_cmd(app: AppContext, skip_install: bool) -> None:
    """Initialize DefenseClaw environment.

    Creates ~/.defenseclaw/, default config, SQLite database,
    and installs scanner dependencies.
    """
    from defenseclaw.config import config_path, default_config, detect_environment
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    env = detect_environment()
    click.echo(f"  Environment: {env}")

    defaults = default_config()
    click.echo(f"  Claw mode:   {defaults.claw.mode}")
    click.echo(f"  Claw home:   {defaults.claw_home_dir()}")

    dirs = [
        defaults.data_dir, defaults.quarantine_dir,
        defaults.plugin_dir, defaults.policy_dir,
    ]
    dirs.extend(defaults.skill_dirs())
    dirs.extend(defaults.mcp_dirs())

    for d in dirs:
        os.makedirs(d, exist_ok=True)
    click.echo("  Directories: created")

    defaults.save()
    click.echo(f"  Config: {config_path()}")

    store = Store(defaults.audit_db)
    store.init()
    click.echo(f"  Audit DB: {defaults.audit_db}")

    logger = Logger(store)
    logger.log_action("init", defaults.data_dir, f"environment={env}")

    click.echo()
    _install_scanners(defaults, logger, skip_install)

    click.echo()
    if shutil.which(defaults.openshell.binary):
        click.echo("  OpenShell: found")
    elif env == "macos":
        click.echo("  OpenShell: not available on macOS (sandbox enforcement will be skipped)")
    else:
        click.echo("  OpenShell: not found (sandbox enforcement will not be active)")

    click.echo("\nDefenseClaw initialized. Run 'defenseclaw scan' to start scanning.")

    store.close()


def _install_scanners(cfg, logger, skip: bool) -> None:
    if skip:
        click.echo("  Scanners: skipped (--skip-install)")
        return

    _ensure_uv()

    deps = [
        ("skill-scanner", cfg.scanners.skill_scanner.binary, "cisco-ai-skill-scanner"),
        ("mcp-scanner", cfg.scanners.mcp_scanner, "cisco-ai-mcp-scanner"),
        ("cisco-aibom", cfg.scanners.aibom, "cisco-aibom"),
    ]

    for name, binary, pkg in deps:
        if shutil.which(binary):
            click.echo(f"  {name}: already installed")
            continue

        click.echo(f"  {name}: installing...", nl=False)
        if _install_with_uv(pkg):
            click.echo(" done")
            logger.log_action("install-scanner", name, f"package={pkg}")
        else:
            click.echo(" failed")
            click.echo(f"    install manually: uv tool install {pkg}")


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
