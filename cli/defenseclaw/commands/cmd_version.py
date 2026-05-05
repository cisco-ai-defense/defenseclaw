# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw version`` — cross-component version inspector.

Where ``defenseclaw --version`` only speaks for the Python CLI, this
command surfaces the version of *every* DefenseClaw component the
operator has on their machine (CLI, gateway binary, OpenClaw plugin)
and warns when they drift.

Drift matters because the three components ship together: the gateway
speaks a sidecar REST API the CLI depends on, and the plugin's IPC
contract with the gateway changes from release to release. Running
mismatched builds is the single most common cause of silent
"guardrail not enforcing" reports in the field — so we make drift
explicit instead of waiting for it to manifest as a runtime error.

Exit codes:
    0 — all components in sync (or operator explicitly opted in with
        ``--json`` and is making the decision themselves)
    1 — drift detected. The summary table still prints on stdout so
        CI can diff it without parsing stderr.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

import click

from defenseclaw import __version__, ux
from defenseclaw.paths import bundled_extensions_dir


# Matches the semantic version format we ship (MAJOR.MINOR.PATCH plus
# optional ``-rc1`` / ``+meta`` suffixes). We compare by the (major,
# minor, patch) tuple only — build/prerelease metadata is surfaced but
# does not trigger a drift error, because hot-fix tags legitimately
# differ across components during rolling upgrades.
@dataclass(frozen=True)
class Component:
    name: str
    version: str
    origin: str              # where we discovered it (path, "builtin", …)
    detail: str = ""         # free-form extras (commit, build date, …)
    status: str = "ok"       # "ok" | "missing" | "error"


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def _cli_component() -> Component:
    """The Python CLI is definitional — its version is always known."""
    return Component(
        name="cli",
        version=__version__,
        origin="defenseclaw (python)",
        detail="",
        status="ok",
    )


def _gateway_component() -> Component:
    """Resolve the ``defenseclaw-gateway`` binary and interrogate it.

    We invoke ``--version`` rather than reading a build-info file so
    operators who swap the binary in place (a common dev loop) still
    see the real version. Short timeout because the gateway binary
    can also be a long-running daemon — ``--version`` short-circuits
    before Cobra touches any state, but a misconfigured shim could
    still hang.
    """
    bin_path = shutil.which("defenseclaw-gateway")
    if not bin_path:
        return Component(
            name="gateway",
            version="(not installed)",
            origin="PATH",
            status="missing",
        )

    try:
        out = subprocess.check_output(
            [bin_path, "--version"],
            stderr=subprocess.STDOUT,
            timeout=5,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return Component(
            name="gateway",
            version="(timeout)",
            origin=bin_path,
            status="error",
            detail="binary did not respond to --version within 5s",
        )
    except subprocess.CalledProcessError as exc:
        err_lines = (exc.output or "").strip().splitlines()
        return Component(
            name="gateway",
            version="(error)",
            origin=bin_path,
            status="error",
            detail=(err_lines[0][:200] if err_lines else f"exit {exc.returncode}"),
        )
    except OSError as exc:
        return Component(
            name="gateway",
            version="(error)",
            origin=bin_path,
            status="error",
            detail=str(exc),
        )

    # Cobra renders: "defenseclaw-gateway version 0.2.0 (commit=…, built=…)"
    stripped = (out or "").strip().splitlines()
    first = stripped[0] if stripped else ""
    version, detail = _parse_gateway_version(first)
    return Component(
        name="gateway",
        version=version or "(unknown)",
        origin=bin_path,
        detail=detail,
        status="ok" if version else "error",
    )


def _parse_gateway_version(line: str) -> tuple[str, str]:
    """Extract ``(version, detail)`` from the gateway's ``--version`` output.

    Returns ``("", raw_line)`` if we can't find a version token so the
    caller can still surface what the binary said.
    """
    # Format: "defenseclaw-gateway version X.Y.Z (commit=…, built=…)"
    marker = " version "
    idx = line.find(marker)
    if idx < 0:
        return "", line
    tail = line[idx + len(marker):].strip()
    # Split at first whitespace or '(' to isolate the version token.
    for sep in (" ", "("):
        cut = tail.find(sep)
        if cut >= 0:
            return tail[:cut].strip(), tail[cut:].strip()
    return tail, ""


def _plugin_component() -> Component:
    """Read the OpenClaw plugin's ``package.json`` if it's installed."""
    candidates: list[Path] = []
    # Installed location (what DefenseClaw ships to OpenClaw)
    openclaw_ext = Path.home() / ".openclaw" / "extensions" / "defenseclaw" / "package.json"
    candidates.append(openclaw_ext)

    # Dev-tree / source location (for operators running out of the repo)
    try:
        built = bundled_extensions_dir() / "package.json"
        candidates.append(built)
    except Exception:
        # paths helper can raise FileNotFoundError through ``_first_existing``;
        # that's fine, it just means we fall back to the installed location.
        pass

    for path in candidates:
        if not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return Component(
                name="plugin",
                version="(error)",
                origin=str(path),
                status="error",
                detail=str(exc),
            )
        version = str(data.get("version", "")).strip() or "(unknown)"
        return Component(
            name="plugin",
            version=version,
            origin=str(path.parent),
            status="ok" if version != "(unknown)" else "error",
        )

    return Component(
        name="plugin",
        version="(not installed)",
        origin="~/.openclaw/extensions/defenseclaw",
        status="missing",
    )


# ---------------------------------------------------------------------------
# Drift analysis
# ---------------------------------------------------------------------------

def _normalize(version: str) -> tuple[int, int, int] | None:
    """Extract the (major, minor, patch) triple from a version string.

    Returns ``None`` for non-semver strings (e.g. "(not installed)",
    "dev") so the drift check skips them rather than reporting every
    unbuilt dev component as drift.
    """
    if not version:
        return None
    # Strip leading 'v', isolate the numeric prefix up to the first '-' or '+'.
    head = version.lstrip("v")
    for sep in ("-", "+"):
        cut = head.find(sep)
        if cut >= 0:
            head = head[:cut]
            break
    parts = head.split(".")
    if len(parts) < 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _compute_drift(components: list[Component]) -> list[str]:
    """Return a list of human-readable drift warnings.

    Only compares components whose versions normalize successfully, so
    "(not installed)" and local dev builds don't produce false
    positives. We compare by (major, minor, patch) — suffix metadata is
    shown in ``detail`` but doesn't trigger drift on its own.
    """
    normalized = {
        c.name: (_normalize(c.version), c) for c in components
    }
    valid = {n: t for n, (t, _c) in normalized.items() if t is not None}
    if len(valid) < 2:
        return []

    # Pick the CLI's triple as the reference (it's the component the
    # user *invoked*, so "you're running an X cli against a Y gateway"
    # is the most actionable phrasing).
    reference = valid.get("cli") or next(iter(valid.values()))
    issues: list[str] = []
    for name, triple in valid.items():
        if triple != reference:
            cli_v = ".".join(str(x) for x in reference)
            other_v = ".".join(str(x) for x in triple)
            issues.append(
                f"{name} {other_v} differs from cli {cli_v} — "
                f"run 'defenseclaw upgrade' (or rebuild with 'make install') "
                f"to resync."
            )
    return issues


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _render_table(components: list[Component]) -> None:
    """Pretty-print a fixed-width table to stdout."""
    name_w    = max(len("COMPONENT"), *(len(c.name) for c in components))
    version_w = max(len("VERSION"),   *(len(c.version) for c in components))
    status_w  = max(len("STATUS"),    *(len(c.status) for c in components))

    click.echo(
        f"  {ux.bold('COMPONENT'.ljust(name_w))}  "
        f"{ux.bold('VERSION'.ljust(version_w))}  "
        f"{ux.bold('STATUS'.ljust(status_w))}  "
        f"{ux.bold('ORIGIN')}"
    )
    click.echo(
        f"  {ux.dim('─' * name_w)}  {ux.dim('─' * version_w)}  "
        f"{ux.dim('─' * status_w)}  {ux.dim('─' * 40)}"
    )
    for c in components:
        st_fg = {"ok": "green", "missing": "yellow", "error": "red"}.get(c.status, "white")
        click.echo(
            f"  {ux.bold(c.name.ljust(name_w))}  "
            f"{c.version.ljust(version_w)}  "
            f"{ux._style(c.status.ljust(status_w), fg=st_fg, bold=True)}  "
            f"{c.origin}"
        )
        if c.detail:
            click.echo(
                f"  {' ' * name_w}  {' ' * version_w}  {' ' * status_w}  "
                f"{ux.dim('↳')} {c.detail}"
            )


# ---------------------------------------------------------------------------
# Click entrypoint
# ---------------------------------------------------------------------------

@click.command("version")
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable report.")
@click.option(
    "--no-drift-exit",
    is_flag=True,
    help="Always exit 0, even if component versions disagree (useful in CI).",
)
def version_cmd(as_json: bool, no_drift_exit: bool) -> None:
    """Show DefenseClaw CLI / gateway / plugin versions and flag drift.

    This is the command to run first when a bug report says "the
    guardrail isn't blocking" — nine times out of ten the problem is a
    freshly rebuilt CLI talking to a stale gateway binary still living
    in the operator's PATH from ``make install`` weeks ago.
    """
    # Preserve discovery order (cli → gateway → plugin) so the table
    # reads top-down the way the request flows at runtime.
    components = [
        _cli_component(),
        _gateway_component(),
        _plugin_component(),
    ]
    drift = _compute_drift(components)

    if as_json:
        click.echo(json.dumps(
            {
                "components": [asdict(c) for c in components],
                "drift": drift,
                "ok": not drift,
            },
            indent=2,
        ))
    else:
        click.echo()
        click.echo(ux._style("  DefenseClaw versions", fg="cyan", bold=True))
        click.echo()
        _render_table(components)
        click.echo()
        if drift:
            click.echo(f"  {ux.bold('Drift detected:')}")
            for issue in drift:
                ux.warn(issue, indent="    ")
            click.echo()
        else:
            ux.ok("All components in sync.", indent="  ")
            click.echo()

    # Non-zero exit on drift so CI pipelines can gate deploys on a
    # clean `defenseclaw version`. Operators who explicitly don't
    # care (e.g. during a staged rollout) opt out via --no-drift-exit.
    if drift and not no_drift_exit and not as_json:
        raise SystemExit(1)
    # Also exit 1 if any component outright failed to report — that's
    # a "broken install" signal, not a "drift" signal.
    if any(c.status == "error" for c in components):
        raise SystemExit(1)
