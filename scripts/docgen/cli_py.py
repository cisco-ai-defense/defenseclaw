# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Python Click CLI introspection → MDX AUTOGEN blocks.

Walks the root ``cli`` group in ``cli.defenseclaw.main``, emits:
  * one "root" block for ``docs-site/cli/python-cli.mdx`` (top-level summary)
  * one per-command block for ``docs-site/cli/commands/<cmd>.mdx``
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Iterable, List, Tuple

import click

from . import mdx, splice


ROOT_PAGE = Path("docs-site/cli/python-cli.mdx")
CMD_DIR = Path("docs-site/cli/commands")


# ---------------------------------------------------------------------------
# Introspection helpers
# ---------------------------------------------------------------------------

def _load_root() -> click.Group:
    mod = importlib.import_module("defenseclaw.main")
    root = getattr(mod, "cli")
    if not isinstance(root, click.Group):
        raise TypeError(f"defenseclaw.main.cli is not a click.Group (got {type(root).__name__})")
    return root


def _param_rows(cmd: click.Command) -> List[List[str]]:
    rows: List[List[str]] = []
    for p in cmd.params:
        if isinstance(p, click.Option):
            flags = ", ".join(p.opts + p.secondary_opts)
            default = p.default
            if default in (False, None) or repr(default).startswith("<Sentinel."):
                default_s = "—"
            elif default is True:
                default_s = "true"
            elif isinstance(default, (list, tuple)) and not default:
                default_s = "—"
            else:
                default_s = mdx.md_code(str(default))
            envvar = ""
            if getattr(p, "envvar", None):
                env = p.envvar if isinstance(p.envvar, str) else ", ".join(p.envvar)
                envvar = mdx.md_code(env)
            type_s = _type_name(p.type)
            required = "yes" if p.required else "no"
            help_s = mdx.escape_pipe(p.help or "")
            rows.append([
                mdx.md_code(flags),
                type_s,
                default_s,
                envvar or "—",
                required,
                help_s,
            ])
    return rows


def _arg_rows(cmd: click.Command) -> List[List[str]]:
    rows: List[List[str]] = []
    for p in cmd.params:
        if isinstance(p, click.Argument):
            nargs = p.nargs
            nargs_s = "variadic" if nargs == -1 else str(nargs)
            rows.append([
                mdx.md_code(p.name or ""),
                _type_name(p.type),
                nargs_s,
                "yes" if p.required else "no",
            ])
    return rows


def _type_name(t: click.ParamType) -> str:
    if isinstance(t, click.Choice):
        choices = ", ".join(f"`{c}`" for c in t.choices)
        return f"choice ({choices})"
    if isinstance(t, click.IntRange):
        bounds = []
        if t.min is not None:
            bounds.append(f"≥{t.min}")
        if t.max is not None:
            bounds.append(f"≤{t.max}")
        return "int " + " ".join(bounds) if bounds else "int"
    return t.name.lower() if getattr(t, "name", None) else type(t).__name__


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _render_help(cmd: click.Command) -> str:
    parts: List[str] = []
    summary = cmd.short_help or (cmd.help or "").split("\n\n", 1)[0].strip()
    if summary:
        parts.append(summary.rstrip("."))
    long_help = cmd.help or ""
    if long_help and long_help.strip() != summary:
        parts.append("")
        parts.append(_dedent_click_help(long_help))
    return "\n".join(parts).rstrip()


def _dedent_click_help(s: str) -> str:
    lines = s.splitlines()
    out: List[str] = []
    for ln in lines:
        out.append(ln.rstrip())
    while out and not out[0]:
        out.pop(0)
    while out and not out[-1]:
        out.pop()
    # Normalize leading indentation to zero.
    non_empty = [ln for ln in out if ln.strip()]
    if not non_empty:
        return ""
    indent = min(len(ln) - len(ln.lstrip()) for ln in non_empty)
    return "\n".join(ln[indent:] if ln.strip() else "" for ln in out)


def _render_cmd_block(name: str, cmd: click.Command, *, path_prefix: str = "defenseclaw") -> str:
    """Render a per-command AUTOGEN block body (without sentinels)."""
    full_name = f"{path_prefix} {name}".strip()
    body: List[str] = []
    body.append(f"### Synopsis")
    body.append("")
    body.append(mdx.code_fence("bash", f"{full_name} [OPTIONS]" +
                               ("" if not _has_args(cmd) else " " + " ".join(_arg_signature(cmd)))))
    body.append("")

    if isinstance(cmd, click.Group) and cmd.commands:
        body.append("### Subcommands")
        body.append("")
        body.append(mdx.render_table(
            ["Subcommand", "Description"],
            [[mdx.md_code(sub), mdx.escape_pipe((sub_cmd.short_help or (sub_cmd.help or "").strip().splitlines()[0] if sub_cmd.help else "")[:200])]
             for sub, sub_cmd in sorted(cmd.commands.items())],
        ))
        body.append("")

    help_text = _render_help(cmd)
    if help_text:
        body.append("### Description")
        body.append("")
        body.append(help_text)
        body.append("")

    arg_rows = _arg_rows(cmd)
    if arg_rows:
        body.append("### Arguments")
        body.append("")
        body.append(mdx.render_table(["Name", "Type", "Arity", "Required"], arg_rows))
        body.append("")

    param_rows = _param_rows(cmd)
    if param_rows:
        body.append("### Options")
        body.append("")
        body.append(mdx.render_table(
            ["Flag", "Type", "Default", "Env var", "Required", "Description"],
            param_rows,
        ))
        body.append("")

    # Recurse into subcommands for groups — append each subcommand block.
    if isinstance(cmd, click.Group):
        for sub, sub_cmd in sorted(cmd.commands.items()):
            body.append(f"### `{full_name} {sub}`")
            body.append("")
            body.append(_render_subcmd_inline(sub_cmd, full_name=f"{full_name} {sub}"))
            body.append("")

    return "\n".join(body).rstrip() + "\n"


def _render_subcmd_inline(cmd: click.Command, *, full_name: str, depth: int = 4) -> str:
    body: List[str] = []
    help_text = _render_help(cmd)
    if help_text:
        body.append(help_text)
        body.append("")
    if _has_args(cmd):
        body.append(mdx.code_fence("bash", f"{full_name} " + " ".join(_arg_signature(cmd))))
        body.append("")
    arg_rows = _arg_rows(cmd)
    if arg_rows:
        body.append("**Arguments**")
        body.append("")
        body.append(mdx.render_table(["Name", "Type", "Arity", "Required"], arg_rows))
        body.append("")
    param_rows = _param_rows(cmd)
    if param_rows:
        body.append("**Options**")
        body.append("")
        body.append(mdx.render_table(
            ["Flag", "Type", "Default", "Env var", "Required", "Description"],
            param_rows,
        ))
        body.append("")
    if isinstance(cmd, click.Group) and cmd.commands:
        body.append("**Subcommands**")
        body.append("")
        body.append(mdx.render_table(
            ["Subcommand", "Description"],
            [[mdx.md_code(sub), mdx.escape_pipe((sc.short_help or (sc.help or "").strip().splitlines()[0] if sc.help else "")[:200])]
             for sub, sc in sorted(cmd.commands.items())],
        ))
        body.append("")
        heading = "#" * min(depth, 6)
        for sub, sub_cmd in sorted(cmd.commands.items()):
            body.append(f"{heading} `{full_name} {sub}`")
            body.append("")
            body.append(_render_subcmd_inline(sub_cmd, full_name=f"{full_name} {sub}", depth=depth + 1))
            body.append("")
    return "\n".join(body).rstrip()


def _has_args(cmd: click.Command) -> bool:
    return any(isinstance(p, click.Argument) for p in cmd.params)


def _arg_signature(cmd: click.Command) -> List[str]:
    sig = []
    for p in cmd.params:
        if isinstance(p, click.Argument):
            name = (p.name or "").upper()
            if p.nargs == -1:
                sig.append(f"[{name}...]")
            elif p.required:
                sig.append(f"<{name}>")
            else:
                sig.append(f"[{name}]")
    return sig


def _render_root_block(root: click.Group) -> str:
    body: List[str] = []
    body.append("### Global synopsis")
    body.append("")
    body.append(mdx.code_fence("bash", "defenseclaw [--version] [--help] <command> [<args>]"))
    body.append("")
    body.append("### Commands")
    body.append("")
    rows: List[List[str]] = []
    for name, sub in sorted(root.commands.items()):
        one_line = ""
        if sub.help:
            one_line = sub.help.strip().splitlines()[0][:200]
        elif sub.short_help:
            one_line = sub.short_help[:200]
        link = f"[{name}](/docs-site/cli/commands/{name})"
        rows.append([link, mdx.escape_pipe(one_line)])
    body.append(mdx.render_table(["Command", "Description"], rows))
    body.append("")
    body.append("### Global options")
    body.append("")
    global_rows = _param_rows(root)
    if global_rows:
        body.append(mdx.render_table(
            ["Flag", "Type", "Default", "Env var", "Required", "Description"],
            global_rows,
        ))
    else:
        body.append("_No global options beyond `--version` / `--help`._")
    return "\n".join(body).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Templates for first-run file creation
# ---------------------------------------------------------------------------

def _root_template() -> str:
    return """---
title: "Python CLI"
description: "Reference for the defenseclaw Python Click CLI — global options and all top-level commands."
order: 2
---

## Overview

`defenseclaw` is the Python control-plane CLI. It provisions config, drives
scanners, manages policy, and wraps the gateway sidecar lifecycle. Run it
anywhere you have the Python package installed.

<Callout type="tip">
  The Go gateway daemon is a sibling binary — see [Gateway CLI](/docs-site/cli/gateway-cli).
  The two CLIs are covered together in the [CLI overview](/docs-site/cli/index).
</Callout>

## Reference

<!-- BEGIN AUTOGEN:cli_py:root -->
<!-- END AUTOGEN:cli_py:root -->

## Automation tips

See [Automation](/docs-site/cli/automation) for CI/CD patterns, exit code
handling, and JSON output conventions.

---

<!-- generated-from: cli/defenseclaw/main.py -->
"""


def _cmd_template(name: str, cmd: click.Command) -> str:
    summary = ""
    if cmd.help:
        summary = cmd.help.strip().splitlines()[0]
    elif cmd.short_help:
        summary = cmd.short_help
    summary_dq = summary.replace('"', '\\"')
    module_name = name.replace("-", "_")
    return f"""---
title: "defenseclaw {name}"
description: "{summary_dq}"
order: 10
---

## Overview

`defenseclaw {name}` — {summary.rstrip('.') or 'Subcommand reference.'}.

## Reference

<!-- BEGIN AUTOGEN:cli_py:{name} -->
<!-- END AUTOGEN:cli_py:{name} -->

## Usage

_This section is hand-written by the `cli-commands` subagents — concrete
invocation recipes, typical flags in context, and cross-links to related
pages go here._

## Related

- [Python CLI reference](/docs-site/cli/python-cli)
- [Exit codes](/docs-site/reference/exit-codes)
- [Environment variables](/docs-site/reference/env-vars)

---

<!-- generated-from: cli/defenseclaw/commands/cmd_{module_name}.py -->
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> List[Tuple[str, bool]]:
    """Generate all Python CLI blocks. Returns list of (path, changed)."""
    root = _load_root()
    results: List[Tuple[str, bool]] = []

    splice.ensure_scaffold(ROOT_PAGE, _root_template())
    ch = splice.splice(ROOT_PAGE, "cli_py", "root", _render_root_block(root))
    results.append((str(ROOT_PAGE), ch))

    CMD_DIR.mkdir(parents=True, exist_ok=True)
    for name, cmd in sorted(root.commands.items()):
        page = CMD_DIR / f"{name}.mdx"
        splice.ensure_scaffold(page, _cmd_template(name, cmd))
        block = _render_cmd_block(name, cmd)
        ch = splice.splice(page, "cli_py", name, block)
        results.append((str(page), ch))

    return results


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
