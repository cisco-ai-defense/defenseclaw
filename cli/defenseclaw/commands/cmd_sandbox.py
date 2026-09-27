"""defenseclaw sandbox — sandbox lifecycle commands.

The legacy openshell-sandbox (0.0.x) standalone integration was removed. The
group currently carries only ``legacy-cleanup``, which undoes an old install;
NVIDIA OpenShell 0.1 support is being rebuilt.
"""

from __future__ import annotations

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx


@click.group()
def sandbox() -> None:
    """Manage DefenseClaw sandboxes.

    The legacy openshell-sandbox standalone mode was removed; OpenShell 0.1
    sandbox support is being rebuilt.

    \b
    Commands:
      legacy-cleanup   Undo a legacy openshell-sandbox (0.0.x) install
    """


@sandbox.command("legacy-cleanup")
@click.option("--dry-run", is_flag=True, help="Print the cleanup plan and exact commands; change nothing.")
@click.option("--yes", "-y", is_flag=True, help="Apply the plan without asking for confirmation.")
@click.option(
    "--remove-user",
    is_flag=True,
    help=(
        "Also delete the 'sandbox' user and its home (userdel -r); refused while it has processes or "
        "until its ownership and ACLs are gone from the OpenClaw home."
    ),
)
@click.option(
    "--remove-binary",
    is_flag=True,
    help="Also remove /usr/local/bin/openshell-sandbox when it is a legacy 0.0.x build not owned by a package.",
)
@pass_ctx
def legacy_cleanup(app: AppContext, dry_run: bool, yes: bool, remove_user: bool, remove_binary: bool) -> None:
    """Undo a legacy openshell-sandbox (0.0.x) standalone install (Linux).

    Detects each legacy artifact, prints every step with the exact command it
    runs, and asks before changing anything unless --yes is given. Privileged
    commands run through sudo with binaries resolved only from root-owned
    system directories. Nothing after the systemd units step runs while any
    part of the legacy sandbox is still running. Progress is recorded in
    <data_dir>/legacy-sandbox-cleanup.json, so re-running only does what is
    left.

    \b
    Example:
      defenseclaw sandbox legacy-cleanup --dry-run
      defenseclaw sandbox legacy-cleanup
    """
    from defenseclaw import sandbox_legacy
    from defenseclaw.platform_support import host_os

    if host_os() == "windows":
        raise click.ClickException("sandbox legacy-cleanup is unsupported on native Windows")

    if not app.cfg:
        from defenseclaw.config import load, require_v8_config

        require_v8_config()
        app.cfg = load()
    cfg = app.cfg

    system = sandbox_legacy.System()
    if system.is_root():
        ux.warn(
            "running as root: cleanup reads the root user's DefenseClaw config; "
            "run it as the operator instead (it calls sudo itself)",
        )
    state = sandbox_legacy.detect(cfg, system=system, probe_binary=remove_binary)
    steps = sandbox_legacy.plan(
        state, cfg, remove_user=remove_user, remove_binary=remove_binary, system=system,
    )
    extra = sandbox_legacy.hints(state, remove_user=remove_user, remove_binary=remove_binary)

    ux.section("Legacy sandbox cleanup")
    if not steps:
        if not dry_run and sandbox_legacy.complete_idle_receipt(state, system):
            ux.ok("Nothing is left to clean up; the legacy cleanup is complete.")
        else:
            ux.ok("No legacy openshell-sandbox standalone install found; nothing to clean up.")
        for hint in extra:
            ux.subhead(hint, indent="  ")
        return

    result = sandbox_legacy.apply(steps, state, yes=yes, dry_run=dry_run, system=system)
    for hint in extra:
        ux.subhead(hint, indent="  ")
    if dry_run:
        return
    if result.failed:
        raise click.ClickException(
            f"{len(result.failed)} cleanup step(s) failed; fix the reported problem and re-run "
            "'defenseclaw sandbox legacy-cleanup' (completed steps are skipped)",
        )
    click.echo()
    for note in sandbox_legacy.review_notes(state):
        ux.warn(note)
    ux.section("Next steps")
    for index, (why, command) in enumerate(sandbox_legacy.NEXT_STEPS, 1):
        click.echo(f"    {index}. {why}:")
        click.echo(f"       {ux.accent(command)}")
