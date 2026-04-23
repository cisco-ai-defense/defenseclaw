# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Go Cobra CLI introspection → MDX AUTOGEN blocks.

Shells out to ``cmd/docgen-go`` (a tiny Go binary that walks the Cobra
tree and emits JSON), then renders into ``docs-site/cli/gateway-cli.mdx``
and per-subcommand pages under ``docs-site/cli/commands-gateway/``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from . import mdx, splice


ROOT_PAGE = Path("docs-site/cli/gateway-cli.mdx")
# Gateway subcommand pages live alongside python commands with a suffix
# so Python and Go command namespaces never collide (e.g. both define
# `policy` and `audit`).
CMD_DIR = Path("docs-site/cli/commands-gateway")

GATEWAY_BIN_NAME = "defenseclaw-gateway"


def _dump_cobra_tree() -> dict:
    """Run cmd/docgen-go and return parsed JSON."""
    # Prefer compiled binary if present, otherwise go run.
    cwd = Path(".").resolve()
    pre_built = cwd / "bin" / "docgen-go"
    if pre_built.exists():
        cmd = [str(pre_built)]
    elif shutil.which("go"):
        cmd = ["go", "run", "./cmd/docgen-go"]
    else:
        raise RuntimeError("Neither ./bin/docgen-go nor `go` is available on PATH")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=str(cwd))
    if proc.returncode != 0:
        raise RuntimeError(
            f"docgen-go failed (rc={proc.returncode}):\n"
            f"stdout:\n{proc.stdout[:500]}\nstderr:\n{proc.stderr[:500]}"
        )
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _flag_rows(flags: List[dict]) -> List[List[str]]:
    rows: List[List[str]] = []
    for f in flags:
        if f.get("deprecated"):
            continue
        flag = "--" + f["name"]
        if f.get("shorthand"):
            flag = f"-{f['shorthand']}, {flag}"
        default = f.get("default") or ""
        default_s = mdx.md_code(default) if default and default not in ("", "false", "[]") else "—"
        usage = mdx.escape_pipe(f.get("usage", ""))
        rows.append([
            mdx.md_code(flag),
            mdx.md_code(f.get("type", "")),
            default_s,
            usage or "—",
        ])
    return rows


def _cmd_block(cmd: dict, level: int = 3) -> str:
    body: List[str] = []
    h = "#" * level
    body.append(f"{h} Synopsis")
    body.append("")
    body.append(mdx.code_fence("bash", cmd.get("use") or cmd.get("full_name", "")))
    body.append("")

    subs = cmd.get("subcommands") or []
    if subs:
        body.append(f"{h} Subcommands")
        body.append("")
        rows = []
        for sub in sorted(subs, key=lambda x: x["name"]):
            one = (sub.get("short") or (sub.get("long") or "").split("\n", 1)[0])[:200]
            rows.append([mdx.md_code(sub["name"]), mdx.escape_pipe(one)])
        body.append(mdx.render_table(["Subcommand", "Description"], rows))
        body.append("")

    long_text = cmd.get("long") or cmd.get("short") or ""
    if long_text.strip():
        body.append(f"{h} Description")
        body.append("")
        body.append(long_text.strip())
        body.append("")

    local = cmd.get("local_flags") or []
    if local:
        body.append(f"{h} Flags")
        body.append("")
        body.append(mdx.render_table(["Flag", "Type", "Default", "Description"], _flag_rows(local)))
        body.append("")

    persistent = cmd.get("persistent_flags") or []
    if persistent:
        body.append(f"{h} Persistent flags")
        body.append("")
        body.append(mdx.render_table(["Flag", "Type", "Default", "Description"], _flag_rows(persistent)))
        body.append("")

    if cmd.get("example"):
        body.append(f"{h} Example")
        body.append("")
        body.append(mdx.code_fence("bash", cmd["example"].strip()))
        body.append("")

    # Nested subcommands inline
    for sub in sorted(subs, key=lambda x: x["name"]):
        body.append(f"{h} `{sub['full_name']}`")
        body.append("")
        body.append(_cmd_block(sub, level=level + 1))
        body.append("")

    return "\n".join(body).rstrip() + "\n"


def _render_root_block(tree: dict) -> str:
    body: List[str] = []
    body.append("### Global synopsis")
    body.append("")
    body.append(mdx.code_fence("bash", f"{tree['name']} [flags] <command> [args]"))
    body.append("")
    body.append("### Description")
    body.append("")
    if tree.get("long"):
        body.append(tree["long"].strip())
        body.append("")
    body.append("### Commands")
    body.append("")
    rows = []
    for sub in sorted(tree.get("subcommands") or [], key=lambda x: x["name"]):
        one = (sub.get("short") or "")[:200]
        link = f"[{sub['name']}](/docs-site/cli/commands-gateway/{sub['name']})"
        rows.append([link, mdx.escape_pipe(one)])
    body.append(mdx.render_table(["Command", "Description"], rows))
    body.append("")
    body.append("### Persistent flags")
    body.append("")
    persistent = tree.get("persistent_flags") or []
    local = tree.get("local_flags") or []
    all_top = persistent + local
    if all_top:
        body.append(mdx.render_table(["Flag", "Type", "Default", "Description"], _flag_rows(all_top)))
    else:
        body.append("_None._")
    return "\n".join(body).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

def _root_template() -> str:
    return """---
title: "Gateway CLI"
description: "Reference for the Go defenseclaw-gateway sidecar daemon CLI."
order: 3
---

## Overview

`defenseclaw-gateway` is the Go sidecar daemon. It connects to the
OpenClaw gateway WebSocket, enforces policy on tool calls in real time,
runs the audit pipeline, and exposes the local REST API that the Python
CLI drives.

<Callout type="info">
  Python's `defenseclaw start / stop / status / tui / scan / audit` wrap
  this binary. Operators can also invoke `defenseclaw-gateway` directly
  (e.g. for systemd units). See [Python CLI](/docs-site/cli/python-cli)
  for the high-level surface.
</Callout>

## Reference

<!-- BEGIN AUTOGEN:cli_go:root -->
<!-- END AUTOGEN:cli_go:root -->

## Running as a daemon

- systemd: `scripts/systemd/defenseclaw-gateway.service` (generated by
  `defenseclaw start --install-service`).
- launchd (macOS): managed by `defenseclaw start` / `defenseclaw stop`.
- Docker / k8s: run the binary as PID 1; it handles graceful shutdown
  signals and flushes audit sinks before exit.

## Related

- [Python CLI](/docs-site/cli/python-cli)
- [Environment variables](/docs-site/reference/env-vars)
- [Gateway architecture](/docs-site/developer/architecture)

---

<!-- generated-from: internal/cli/root.go, internal/cli/daemon.go, internal/cli/sidecar.go, internal/cli/scan.go, internal/cli/policy.go, internal/cli/sandbox.go, internal/cli/audit_export.go, internal/cli/watchdog.go, internal/cli/tui_cmd.go, internal/cli/provenance_cmd.go -->
"""


def _cmd_template(cmd: dict) -> str:
    name = cmd["name"]
    short = (cmd.get("short") or cmd.get("long") or "").split("\n", 1)[0]
    if short and short[-1] not in ".!?":
        short = short + "."
    short_dq = short.replace('"', '\\"')
    # Find generated-from — every command maps to a file we know about.
    gf_guess = {
        "start": "internal/cli/daemon.go",
        "stop": "internal/cli/daemon.go",
        "restart": "internal/cli/daemon.go",
        "status": "internal/cli/sidecar.go",
        "scan": "internal/cli/scan.go",
        "policy": "internal/cli/policy.go",
        "sandbox": "internal/cli/sandbox.go",
        "audit": "internal/cli/audit_export.go",
        "watchdog": "internal/cli/watchdog.go",
        "tui": "internal/cli/tui_cmd.go",
        "provenance": "internal/cli/provenance_cmd.go",
    }.get(name, "internal/cli/root.go")
    return f"""---
title: "defenseclaw-gateway {name}"
description: "{short_dq}"
order: 10
---

## Overview

`defenseclaw-gateway {name}` — {short.rstrip('.') or 'Subcommand reference.'}.

## Reference

<!-- BEGIN AUTOGEN:cli_go:{name} -->
<!-- END AUTOGEN:cli_go:{name} -->

## Usage

_Concrete invocation recipes are added by the `cli-commands` subagents.
Pair this with the equivalent Python wrapper command under
[Python CLI](/docs-site/cli/python-cli) — most gateway operations are
also available one layer up._

## Related

- [Gateway CLI overview](/docs-site/cli/gateway-cli)
- [Python CLI](/docs-site/cli/python-cli)

---

<!-- generated-from: {gf_guess} -->
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> List[Tuple[str, bool]]:
    tree = _dump_cobra_tree()
    results: List[Tuple[str, bool]] = []

    splice.ensure_scaffold(ROOT_PAGE, _root_template())
    ch = splice.splice(ROOT_PAGE, "cli_go", "root", _render_root_block(tree))
    results.append((str(ROOT_PAGE), ch))

    CMD_DIR.mkdir(parents=True, exist_ok=True)
    for sub in tree.get("subcommands") or []:
        name = sub["name"]
        page = CMD_DIR / f"{name}.mdx"
        splice.ensure_scaffold(page, _cmd_template(sub))
        ch = splice.splice(page, "cli_go", name, _cmd_block(sub))
        results.append((str(page), ch))

    return results


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
