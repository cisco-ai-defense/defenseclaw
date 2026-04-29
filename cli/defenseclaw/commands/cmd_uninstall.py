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

"""defenseclaw uninstall / reset — clean removal and config wipe.

Removes DefenseClaw artifacts from the system in a predictable,
scriptable way so operators aren't left with a mess after evaluating
the tool. ``reset`` is the "lose my data" button — it wipes
``~/.defenseclaw`` but keeps the binaries and the agent framework's
plugin in place so ``defenseclaw quickstart`` can reinstall cleanly.

Connector polymorphism (S7.3)
-----------------------------
Removal of the agent framework's defenseclaw artifacts is delegated to
``defenseclaw-gateway connector teardown`` — the canonical sentinel that
each connector adapter implements (S7.2). Uninstall fans that sentinel
out across every known connector, not just the active one, so switching
connectors cannot leave stale hooks or backups behind.

The Python side still owns OpenClaw-specific revert paths as a fallback
for very old gateway binaries (pre-S7.2) where the ``connector teardown``
subcommand is not available. The fallback only ever runs against
OpenClaw, never against the other adapters — calling
``restore_openclaw_config`` against a Codex install would corrupt it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

import click

from defenseclaw import config as config_module
from defenseclaw import connector_paths

# Connectors whose teardown the Python CLI knows how to perform locally
# without going through ``defenseclaw-gateway connector teardown``. This
# is the conservative fallback path used when the gateway binary is too
# old to expose the connector subcommand.
_PYTHON_FALLBACK_CONNECTORS: frozenset[str] = frozenset({"openclaw"})

# Connector names are normally sourced from connector_paths.KNOWN_CONNECTORS.
# The active connector may still be a plugin connector, so validate it before
# passing it to the gateway as a subprocess argument.
_CONNECTOR_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


@dataclass
class UninstallPlan:
    """Aggregated summary of what an uninstall/reset intends to do."""

    stop_gateway: bool = True
    remove_plugin: bool = True
    remove_data_dir: bool = False
    remove_binaries: bool = False
    data_dir: str = ""
    openclaw_config_file: str = ""
    openclaw_home: str = ""
    # connector is the active framework adapter. It is kept for display
    # and backwards-compatible direct test construction; connectors is
    # the ordered teardown set. When connectors is empty, helpers fall
    # back to the singleton active connector.
    connector: str = "openclaw"
    connectors: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# uninstall
# ---------------------------------------------------------------------------

@click.command("uninstall")
@click.option("--all", "wipe_data", is_flag=True, help="Also delete ~/.defenseclaw (audit log, config, secrets).")
@click.option(
    "--binaries",
    is_flag=True,
    help="Additionally remove the defenseclaw + defenseclaw-gateway binaries from ~/.local/bin.",
)
@click.option("--dry-run", is_flag=True, help="Show what would happen without touching the system.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def uninstall_cmd(
    wipe_data: bool,
    binaries: bool,
    dry_run: bool,
    yes: bool,
) -> None:
    """Uninstall DefenseClaw (reversibly by default)."""
    plan = _build_plan(
        wipe_data=wipe_data,
        binaries=binaries,
        remove_plugin=True,
    )
    _render_plan(plan, dry_run=dry_run)

    if dry_run:
        click.echo("  (dry-run — nothing modified)")
        return

    if not yes and not click.confirm("  Proceed?", default=False):
        click.echo("  Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

@click.command("reset")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def reset_cmd(yes: bool) -> None:
    """Wipe ~/.defenseclaw so 'defenseclaw quickstart' starts clean.

    Keeps binaries installed, but restores connector configs to their
    pre-DefenseClaw state. For a full uninstall use 'defenseclaw
    uninstall --all --binaries'.
    """
    plan = _build_plan(
        wipe_data=True,
        binaries=False,
        remove_plugin=True,
    )
    _render_plan(plan, dry_run=False)

    if not yes and not click.confirm(
        f"  This will DELETE {plan.data_dir}. Continue?", default=False
    ):
        click.echo("  Cancelled.")
        raise SystemExit(1)

    _execute_plan(plan)
    click.echo("  ✓ Reset complete. Run 'defenseclaw quickstart' to reinstall.")


# ---------------------------------------------------------------------------
# Planning + execution
# ---------------------------------------------------------------------------

def _resolve_active_connector(cfg) -> str:
    """Return the active connector for ``cfg``, lowercased.

    Mirrors :meth:`Config.active_connector` but tolerates older
    in-process configs that haven't been migrated yet — the same
    pattern used in :mod:`cmd_setup_sandbox`. We can't rely on
    ``Config.active_connector`` existing because ``_build_plan`` is
    called even when config loading raised.
    """
    if cfg is None:
        return "openclaw"
    if hasattr(cfg, "active_connector") and callable(cfg.active_connector):
        try:
            name = (cfg.active_connector() or "").strip().lower()
            if name:
                return name
        except Exception:
            pass
    if hasattr(cfg, "guardrail") and hasattr(cfg.guardrail, "connector"):
        name = (cfg.guardrail.connector or "").strip().lower()
        if name:
            return name
    return "openclaw"


def _build_plan(
    *,
    wipe_data: bool,
    binaries: bool,
    remove_plugin: bool,
) -> UninstallPlan:
    data_dir = str(config_module.default_data_path())

    # Best-effort config load to discover OpenClaw paths. A broken or
    # missing config is fine here — we fall back to sensible defaults
    # rather than blocking the uninstall.
    openclaw_config_file = ""
    openclaw_home = ""
    cfg = None
    try:
        cfg = config_module.load()
        openclaw_config_file = cfg.claw.config_file
        openclaw_home = cfg.claw.home_dir
    except Exception:
        openclaw_home = os.path.expanduser("~/.openclaw")
        openclaw_config_file = os.path.join(openclaw_home, "openclaw.json")

    connector = _resolve_active_connector(cfg)
    connectors = _planned_teardown_connectors(connector)

    return UninstallPlan(
        stop_gateway=True,
        remove_plugin=remove_plugin,
        remove_data_dir=wipe_data,
        remove_binaries=binaries,
        data_dir=data_dir,
        openclaw_config_file=openclaw_config_file,
        openclaw_home=openclaw_home,
        connector=connector,
        connectors=connectors,
    )


def _render_plan(plan: UninstallPlan, *, dry_run: bool) -> None:
    connectors = _connectors_to_teardown(plan)
    click.echo()
    click.echo("  ── Uninstall plan ────────────────────────────────────")
    click.echo()
    click.echo(f"  • active connector:    {plan.connector}")
    click.echo(f"  • stop sidecar:        {'yes' if plan.stop_gateway else 'no'}")
    if connectors:
        click.echo(
            "  • teardown connectors: "
            f"yes ({', '.join(connectors)} via gateway connector teardown)"
        )
    else:
        click.echo("  • teardown connectors: no")
    click.echo(
        f"  • revert openclaw.json: {'yes' if 'openclaw' in connectors else 'no'} "
        f"({plan.openclaw_config_file})"
    )
    click.echo(
        "  • remove OpenClaw plugin: "
        f"{'yes' if plan.remove_plugin and 'openclaw' in connectors else 'no'}"
    )
    click.echo(f"  • wipe {plan.data_dir}: {'yes' if plan.remove_data_dir else 'no'}")
    click.echo(f"  • remove binaries:     {'yes' if plan.remove_binaries else 'no'}")
    click.echo()


def _execute_plan(plan: UninstallPlan) -> None:
    connectors = _connectors_to_teardown(plan)
    if plan.stop_gateway:
        _stop_gateway()
    if connectors:
        _connector_teardown(plan)
    if plan.remove_plugin and "openclaw" in connectors:
        # Plugin removal is OpenClaw-specific. For other connectors the
        # gateway sentinel teardown above already removed the
        # connector's hook scripts and config patches, so there is
        # nothing additional to do here.
        _remove_plugin(plan)
    if plan.remove_data_dir:
        _remove_data_dir(plan.data_dir)
    if plan.remove_binaries:
        _remove_binaries()


def _stop_gateway() -> None:
    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        click.echo("  · sidecar not on PATH — nothing to stop")
        return
    try:
        subprocess.run([gw, "stop"], capture_output=True, text=True, timeout=15)
        click.echo("  ✓ sidecar stopped")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        click.echo(f"  ⚠ could not stop sidecar: {exc}")


def _gateway_supports_connector_teardown() -> bool:
    """Return True iff the local ``defenseclaw-gateway`` exposes the
    ``connector teardown`` subcommand introduced in S7.2.

    Older binaries print a usage error that includes ``unknown command``
    on stderr; the subprocess returncode is also non-zero. We detect
    by asking for ``--help`` on the ``connector`` subcommand — which is
    a non-destructive probe — and checking exit code + output.
    """
    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        return False
    try:
        proc = subprocess.run(
            [gw, "connector", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    combined = (proc.stdout or "") + (proc.stderr or "")
    return "teardown" in combined and "list-backups" in combined


def _planned_teardown_connectors(
    active_connector: str,
) -> tuple[str, ...]:
    """Return the ordered connector set for uninstall teardown.

    Built-ins come from the shared connector path registry so the Python
    CLI stays in lockstep with the other connector-aware commands. A
    safe active plugin connector is appended because it may not appear
    in the static built-in list.
    """
    names: list[str] = []
    for name in connector_paths.KNOWN_CONNECTORS:
        normalized = connector_paths.normalize(name)
        names.append(normalized)

    active = connector_paths.normalize(active_connector)
    if _is_safe_connector_name(active) and active not in names:
        names.append(active)
    return tuple(dict.fromkeys(names))


def _connectors_to_teardown(plan: UninstallPlan) -> tuple[str, ...]:
    """Return a de-duplicated, validated teardown list for *plan*."""
    candidates = plan.connectors or (plan.connector,)
    names: list[str] = []
    for candidate in candidates:
        name = connector_paths.normalize(candidate)
        if not _is_safe_connector_name(name):
            click.echo(f"  ⚠ skipping invalid connector name {candidate!r}")
            continue
        if name not in names:
            names.append(name)
    return tuple(names)


def _is_safe_connector_name(name: str) -> bool:
    return bool(_CONNECTOR_NAME_RE.fullmatch(name))


def _connector_teardown(plan: UninstallPlan) -> None:
    """Run planned connector teardowns via the canonical sentinel.

    For non-OpenClaw connectors the Python fallback path is **not** safe
    — calling ``restore_openclaw_config`` against a Codex install would
    corrupt it — so unsupported connectors get a clear warning while the
    uninstall continues with the rest of the plan.
    """
    connectors = _connectors_to_teardown(plan)
    if not connectors:
        click.echo("  · no connector teardown requested")
        return

    gateway_supported = _gateway_supports_connector_teardown()
    for connector in connectors:
        if gateway_supported:
            if _run_gateway_connector_teardown(connector):
                continue
            click.echo(
                f"  ⚠ gateway connector teardown for {connector} reported errors — "
                f"see output above"
            )
            if connector != "openclaw":
                continue

        if connector in _PYTHON_FALLBACK_CONNECTORS:
            _revert_openclaw_python(plan)
            continue

        click.echo(
            f"  ⚠ no Python fallback for connector '{connector}'.\n"
            f"     Upgrade defenseclaw-gateway to v0.7+ (introduces "
            f"'connector teardown') and re-run 'defenseclaw uninstall'."
        )


def _run_gateway_connector_teardown(connector: str) -> bool:
    """Invoke ``defenseclaw-gateway connector teardown --connector <name>``.

    Returns True on success (rc == 0), False on any error. stdout/stderr
    is forwarded to the operator so they can see exactly what each
    adapter restored.
    """
    connector = connector_paths.normalize(connector)
    if not _is_safe_connector_name(connector):
        click.echo(f"  ⚠ refusing invalid connector name {connector!r}")
        return False

    gw = shutil.which("defenseclaw-gateway")
    if gw is None:
        return False
    try:
        proc = subprocess.run(
            [gw, "connector", "teardown", "--connector", connector],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        click.echo(f"  ⚠ gateway connector teardown failed to launch: {exc}")
        return False
    if proc.stdout:
        for line in proc.stdout.splitlines():
            click.echo(f"  · {line}")
    if proc.stderr and proc.returncode != 0:
        for line in proc.stderr.splitlines():
            click.echo(f"  ⚠ {line}")
    if proc.returncode == 0:
        click.echo(f"  ✓ {connector} teardown via gateway sentinel")
        return True
    return False


def _revert_openclaw_python(plan: UninstallPlan) -> None:
    """OpenClaw-specific revert path used as a fallback when the gateway
    sentinel is unavailable. NOT safe for other connectors."""
    from defenseclaw.guardrail import (
        pristine_backup_path,
        restore_openclaw_config,
    )

    pristine = pristine_backup_path(plan.openclaw_config_file, plan.data_dir)
    target = _expand(plan.openclaw_config_file)
    if pristine:
        try:
            shutil.copy2(pristine, target)
            click.echo(f"  ✓ restored {target} from pristine backup ({os.path.basename(pristine)})")
            return
        except OSError as exc:
            click.echo(f"  ⚠ pristine restore failed: {exc} — falling back to config edit")

    # Fall back to the surgical restore — removes our plugin registration
    # without rolling the file back to its exact prior state.
    try:
        ok = restore_openclaw_config(plan.openclaw_config_file, original_model="")
        if ok:
            click.echo(f"  ✓ removed DefenseClaw entries from {plan.openclaw_config_file}")
        else:
            click.echo(f"  ⚠ could not revert {plan.openclaw_config_file} (missing or malformed)")
    except Exception as exc:
        click.echo(f"  ⚠ openclaw.json revert failed: {exc}")


def _remove_plugin(plan: UninstallPlan) -> None:
    from defenseclaw.guardrail import uninstall_openclaw_plugin

    result = uninstall_openclaw_plugin(plan.openclaw_home)
    if result == "cli":
        click.echo("  ✓ plugin uninstalled via openclaw CLI")
    elif result == "manual":
        click.echo("  ✓ plugin directory removed")
    elif result == "":
        click.echo("  · plugin was not installed")
    else:
        click.echo("  ⚠ plugin uninstall failed (check permissions)")


def _remove_data_dir(data_dir: str) -> None:
    # Safety guard: an empty / root-like path here would be catastrophic
    # because we're about to recursively delete. Bail out unless the
    # directory genuinely looks like a DefenseClaw data dir (i.e.
    # contains one of the files we ourselves write on init). This
    # protects operators who set ``DEFENSECLAW_HOME`` to somewhere weird
    # like ``/`` or ``$HOME`` against a catastrophic rm -rf.
    if not data_dir or not os.path.isdir(data_dir):
        click.echo(f"  · {data_dir} does not exist — skipping")
        return
    # Disallow top-level / root-ish paths outright.
    resolved = os.path.realpath(data_dir)
    if resolved in ("/", os.path.expanduser("~"), os.path.realpath(os.path.expanduser("~"))):
        click.echo(f"  ⚠ refusing to remove protected path {resolved}")
        return
    markers = ("config.yaml", "audit.db", ".env", "policies", "quarantine")
    if not any(os.path.exists(os.path.join(data_dir, m)) for m in markers):
        click.echo(
            f"  ⚠ {data_dir} does not look like a DefenseClaw data dir "
            "(no config.yaml / audit.db / policies) — skipping"
        )
        return
    try:
        shutil.rmtree(data_dir)
        click.echo(f"  ✓ removed {data_dir}")
    except OSError as exc:
        click.echo(f"  ⚠ failed to remove {data_dir}: {exc}")


def _remove_binaries() -> None:
    targets = [
        os.path.expanduser("~/.local/bin/defenseclaw-gateway"),
        os.path.expanduser("~/.local/bin/defenseclaw"),
        # Scanner entry points symlinked by `make cli-install`. Keep
        # this list in sync with the Makefile `cli-install` loop so a
        # fresh install / uninstall round-trip leaves no orphan links.
        os.path.expanduser("~/.local/bin/skill-scanner"),
        os.path.expanduser("~/.local/bin/skill-scanner-api"),
        os.path.expanduser("~/.local/bin/skill-scanner-pre-commit"),
        os.path.expanduser("~/.local/bin/mcp-scanner"),
        os.path.expanduser("~/.local/bin/mcp-scanner-api"),
        os.path.expanduser("~/.local/bin/litellm"),
    ]
    for path in targets:
        if not os.path.lexists(path):
            click.echo(f"  · {path} not installed")
            continue
        try:
            os.unlink(path)
            click.echo(f"  ✓ removed {path}")
        except OSError as exc:
            click.echo(f"  ⚠ failed to remove {path}: {exc}")

    # Clean up the pip-installed Python package symlink if operators
    # used ``pip install defenseclaw`` — we don't shell out to pip
    # because we can't be sure which environment they used.
    click.echo(
        "  · if you installed the Python CLI via pip, run "
        "'pip uninstall defenseclaw' manually"
    )


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return os.path.expanduser(p)
    return p
