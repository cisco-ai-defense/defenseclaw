#!/usr/bin/env python3
"""Render docs/ENV-VARS.md and docs-site/.../env-vars.mdx from the
single source of truth at internal/envvars/registry.json.

The script preserves hand-written prose outside the AUTOGEN sentinels.
Each target file looks like::

    <hand-written intro and front-matter>

    {/* AUTOGEN-BEGIN: env-vars */}
    ...generated tables go here...
    {/* AUTOGEN-END: env-vars */}

    <hand-written footer (links, callouts)>

Run with no arguments to regenerate both files in place. Pass
``--check`` to fail the build if either file is out of date — this is
what the CI gate runs.
"""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from pathlib import Path

# Make `defenseclaw` importable when invoked from the repo root without
# an editable install. The registry-loader resolution at
# defenseclaw.envvars.load_registry walks up to find registry.json.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "cli"))

from defenseclaw.envvars import (  # noqa: E402  (sys.path manipulated above)
    ALLOWED_CATEGORIES,
    CATEGORY_CREDENTIAL,
    CATEGORY_DEBUG,
    CATEGORY_DISCOVERY,
    CATEGORY_HOOK_INTERNAL,
    CATEGORY_RUNTIME_PATH,
    CATEGORY_SECURITY_OPT_OUT,
    CATEGORY_SPLUNK_BRIDGE,
    CATEGORY_TELEMETRY,
    CATEGORY_TEST_FIXTURE,
    EnvVar,
    load_registry,
)

# Render order. Security-impacting categories first so they're visible
# above the fold; test fixtures last because operators almost never
# need them.
_CATEGORY_ORDER = (
    CATEGORY_SECURITY_OPT_OUT,
    CATEGORY_CREDENTIAL,
    CATEGORY_RUNTIME_PATH,
    CATEGORY_TELEMETRY,
    CATEGORY_DEBUG,
    CATEGORY_DISCOVERY,
    CATEGORY_HOOK_INTERNAL,
    CATEGORY_SPLUNK_BRIDGE,
    CATEGORY_TEST_FIXTURE,
)
assert set(_CATEGORY_ORDER) == ALLOWED_CATEGORIES, (
    "Category render order out of sync with ALLOWED_CATEGORIES"
)

_CATEGORY_TITLES = {
    CATEGORY_SECURITY_OPT_OUT: "Security opt-outs",
    CATEGORY_CREDENTIAL: "Credentials & secrets",
    CATEGORY_RUNTIME_PATH: "Paths & runtime layout",
    CATEGORY_TELEMETRY: "Telemetry (OTel)",
    CATEGORY_DEBUG: "Debug / verbose logging",
    CATEGORY_DISCOVERY: "Discovery & probes",
    CATEGORY_HOOK_INTERNAL: "Hook-internal (do not override)",
    CATEGORY_SPLUNK_BRIDGE: "Splunk-bridge bundle",
    CATEGORY_TEST_FIXTURE: "Test fixtures (test-only)",
}

_SENTINEL_BEGIN_MDX = "{/* AUTOGEN-BEGIN: env-vars */}"
_SENTINEL_END_MDX = "{/* AUTOGEN-END: env-vars */}"
_SENTINEL_BEGIN_MD = "<!-- AUTOGEN-BEGIN: env-vars -->"
_SENTINEL_END_MD = "<!-- AUTOGEN-END: env-vars -->"

_AUTOGEN_NOTE_MD = (
    "<!-- The block below is auto-generated from "
    "`internal/envvars/registry.json` via `scripts/gen_envvars_docs.py`. "
    "Edit the JSON, not this file. -->"
)
# MDX does not allow HTML comments inside JSX/MDX content; use a block comment.
_AUTOGEN_NOTE_MDX = (
    "{/* The block below is auto-generated from "
    "`internal/envvars/registry.json` via `scripts/gen_envvars_docs.py`. "
    "Edit the JSON, not this file. */}"
)


# ---------------------------------------------------------------------------
# Rendering helpers


def _escape_table_cell(text: str) -> str:
    """Escape a string so it survives a markdown table cell.

    Newlines collapse to spaces, pipes are escaped, runs of whitespace
    collapse to a single space. Markdown table cells can't carry block
    structure so we flatten aggressively.
    """
    s = text.replace("\n", " ").replace("|", "\\|")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _impact_badge(impact: str) -> str:
    return {
        "high": "**HIGH**",
        "medium": "**medium**",
        "low": "low",
        "none": "—",
    }.get(impact, impact)


def _accepted_values_cell(entry: EnvVar) -> str:
    if not entry.accepted_values:
        return "—"
    bits = []
    for v in entry.accepted_values:
        if v == "unset":
            bits.append("`unset`")
        else:
            bits.append(f"`{_escape_table_cell(v)}`")
    return ", ".join(bits)


def _mdx_default_needs_backticks(text: str) -> bool:
    """MDX interprets ``${...}`` / ``{ident}`` in table cells as JS and
    ``<token>`` as a JSX tag. Wrap such cells in a code span so literal
    placeholders like ``127.0.0.1:<api_port>`` or ``<data_dir>/...`` render
    verbatim instead of failing the MDX parse with an unclosed-tag error."""
    return bool(text) and any(c in text for c in ("$", "{", "<", ">"))


def _default_cell(entry: EnvVar, *, mdx: bool) -> str:
    d = entry.default or ""
    if not d or d.lower() == "unset" or d.lower().startswith("unset "):
        suffix = (
            f" {_escape_table_cell(d[len('unset'):]).strip()}"
            if len(d) > len("unset")
            else ""
        )
        combined = f"`unset`{suffix}"
        if mdx and suffix and _mdx_default_needs_backticks(suffix):
            return f"`{_escape_table_cell(d)}`"
        return combined
    rendered = _escape_table_cell(d)
    if mdx and _mdx_default_needs_backticks(rendered):
        return f"`{rendered}`"
    return rendered


def _consumer_cell(entry: EnvVar) -> str:
    parts = []
    for c in entry.consumers:
        parts.append(f"`{_escape_table_cell(c.location)}` — {_escape_table_cell(c.description)}")
    return "<br/>".join(parts)


def _security_note_cell(entry: EnvVar) -> str:
    if not entry.security_note:
        return "—"
    return _escape_table_cell(entry.security_note)


_SENTENCE_SPLIT = re.compile(r"\.\s+(?=[A-Z])")


def _first_sentence(text: str) -> str:
    """Return the first sentence of ``text`` without splitting at
    abbreviations like ``e.g.`` or ``Mr.``. We split only at a period
    followed by whitespace AND a capital letter, which is a fair-enough
    heuristic for the prose used in purpose fields.
    """
    parts = _SENTENCE_SPLIT.split(text, maxsplit=1)
    head = parts[0].rstrip()
    if not head.endswith("."):
        head += "."
    return head


def _render_table(category: str, *, mdx: bool) -> str:
    """Render one category's table. ``mdx=True`` emits JSX-safe
    ``<br/>`` line-breaks (required by MDX). ``mdx=False`` emits plain
    ``<br>`` for vanilla markdown."""
    reg = load_registry()
    entries = sorted(reg.by_category(category), key=lambda e: e.name)
    if not entries:
        return f"\n*(no entries in this category)*\n"

    br = "<br/>" if mdx else "<br>"

    lines: list[str] = []
    lines.append(
        "| Env var | Impact | Default | Accepted values | Purpose | Security concern | Consumers |"
    )
    lines.append(
        "| --- | --- | --- | --- | --- | --- | --- |"
    )
    for e in entries:
        name = f"`{e.name}`"
        if e.deprecated:
            name = f"~~`{e.name}`~~"
        purpose = _escape_table_cell(_first_sentence(e.purpose))
        if e.replacement_hint:
            purpose += (
                f" {br}**Fix:** "
                + _escape_table_cell(e.replacement_hint)
            )
        # Consumer cell built with <br/> placeholder; rewrite per-target.
        consumer_cell = _consumer_cell(e).replace("<br/>", br)
        row = (
            f"| {name} | {_impact_badge(e.security_impact)} | "
            f"{_default_cell(e, mdx=mdx)} | "
            f"{_accepted_values_cell(e)} | "
            f"{purpose} | "
            f"{_security_note_cell(e)} | "
            f"{consumer_cell} |"
        )
        lines.append(row)
    return "\n".join(lines)


def _render_block(*, mdx: bool) -> str:
    """Build the full auto-generated block (one section per category)."""
    chunks: list[str] = []
    chunks.append(_AUTOGEN_NOTE_MDX if mdx else _AUTOGEN_NOTE_MD)
    chunks.append("")
    for category in _CATEGORY_ORDER:
        title = _CATEGORY_TITLES[category]
        chunks.append(f"## {title}")
        chunks.append("")
        chunks.append(_render_table(category, mdx=mdx))
        chunks.append("")
    return "\n".join(chunks).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Sentinel-aware file write


def _replace_between(
    text: str,
    begin: str,
    end: str,
    payload: str,
) -> tuple[str, bool]:
    """Replace the region between ``begin`` and ``end`` with ``payload``.

    Returns ``(new_text, found)`` where ``found`` is ``True`` if the
    sentinels existed. If absent, the file is returned unchanged and
    the caller is responsible for falling back to a template.
    """
    pattern = re.compile(
        re.escape(begin) + r"(.*?)" + re.escape(end),
        re.DOTALL,
    )
    if not pattern.search(text):
        return text, False
    new_text = pattern.sub(
        f"{begin}\n{payload}\n{end}",
        text,
        count=1,
    )
    return new_text, True


# ---------------------------------------------------------------------------
# Default templates used when the target file doesn't yet exist

_DEFAULT_MD_TEMPLATE = textwrap.dedent(
    """\
    # DefenseClaw environment variables

    Canonical list of every `DEFENSECLAW_*` env var consumed by the
    codebase, generated from `internal/envvars/registry.json`.

    > **Edit policy:** Do not hand-edit the auto-generated block below.
    > Edit `internal/envvars/registry.json` and run
    > `python3 scripts/gen_envvars_docs.py` to regenerate.

    The CI gate at `cli/tests/test_envvars_codebase_coverage.py` fails
    if any callsite references a `DEFENSECLAW_*` var not declared in
    the registry — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
    workflow.

    Active overrides are also surfaced live by `defenseclaw doctor`
    (the "Security Overrides" section).

    {begin}
    {payload}
    {end}

    ## When in doubt

    Run `defenseclaw doctor`. It walks the same env-var resolution
    code paths as the running gateway and surfaces effective values
    plus any active opt-outs.
    """
)

_DEFAULT_MDX_TEMPLATE = textwrap.dedent(
    """\
    ---
    title: Environment variables
    description: Every environment variable DefenseClaw reads, grouped by category, with defaults, accepted values, and the file:line that consumes each one.
    keywords:
      - DefenseClaw env vars
      - DEFENSECLAW_LLM_KEY
      - DEFENSECLAW_HOME
      - DEFENSECLAW_DISABLE_REDACTION
      - DEFENSECLAW_OTEL_ENABLED
      - DefenseClaw configuration
    ---

    This is the canonical list of every environment variable DefenseClaw reads. The list is generated from [`internal/envvars/registry.json`](https://github.com/cisco-ai-defense/defenseclaw/blob/main/internal/envvars/registry.json); CI fails if any callsite references a `DEFENSECLAW_*` var not declared in the registry.

    <Callout title="See live what's active">
    `defenseclaw doctor` surfaces any **active security override** in real time. Operators with no overrides set see a single "none active" pass row; if you've left a debug toggle on, doctor flags it loudly.
    </Callout>

    {begin}
    {payload}
    {end}

    ## When in doubt

    Run `defenseclaw doctor`. The doctor walks the same env-var resolution code paths as the running gateway and surfaces effective values plus any active opt-outs.

    ```bash
    defenseclaw doctor
    defenseclaw keys list
    ```

    ## Reference

    - [`internal/envvars/registry.json`](https://github.com/cisco-ai-defense/defenseclaw/blob/main/internal/envvars/registry.json) — single source of truth.
    - [`cli/defenseclaw/envvars.py`](https://github.com/cisco-ai-defense/defenseclaw/blob/main/cli/defenseclaw/envvars.py) — Python loader.
    - [`internal/envvars/registry.go`](https://github.com/cisco-ai-defense/defenseclaw/blob/main/internal/envvars/registry.go) — Go loader.
    - [Reference → Keys](/docs/reference/keys) — credential resolution order.
    - [Reference → Redaction](/docs/reference/redaction) — `DEFENSECLAW_DISABLE_REDACTION` / `DEFENSECLAW_REVEAL_PII`.
    - [Reference → Fail modes](/docs/reference/fail-modes) — `DEFENSECLAW_FAIL_MODE` / `DEFENSECLAW_STRICT_AVAILABILITY`.
    """
)


# ---------------------------------------------------------------------------
# Public entry points


def render_mdx() -> str:
    """Return the full content of env-vars.mdx."""
    payload = _render_block(mdx=True)
    return _DEFAULT_MDX_TEMPLATE.format(
        begin=_SENTINEL_BEGIN_MDX,
        end=_SENTINEL_END_MDX,
        payload=payload,
    )


def render_md() -> str:
    """Return the full content of docs/ENV-VARS.md."""
    payload = _render_block(mdx=False)
    return _DEFAULT_MD_TEMPLATE.format(
        begin=_SENTINEL_BEGIN_MD,
        end=_SENTINEL_END_MD,
        payload=payload,
    )


def update_file(path: Path, payload: str, sentinel_begin: str, sentinel_end: str) -> str:
    """Update an existing file in place, preserving hand-written prose
    outside the sentinels. Returns the new contents."""
    if path.is_file():
        old = path.read_text(encoding="utf-8")
        new, found = _replace_between(old, sentinel_begin, sentinel_end, payload)
        if found:
            return new
    # Fall back to writing from the default template.
    if str(path).endswith(".mdx"):
        return render_mdx()
    return render_md()


_TARGET_MD = _REPO_ROOT / "docs" / "ENV-VARS.md"
_TARGET_MDX = _REPO_ROOT / "docs-site" / "content" / "docs" / "reference" / "env-vars.mdx"


def write_all() -> dict[str, bool]:
    """Regenerate both files. Returns ``{path: changed}``."""
    results: dict[str, bool] = {}

    payload_md = _render_block(mdx=False)
    new_md = update_file(_TARGET_MD, payload_md, _SENTINEL_BEGIN_MD, _SENTINEL_END_MD)
    old_md = _TARGET_MD.read_text(encoding="utf-8") if _TARGET_MD.is_file() else ""
    if new_md != old_md:
        _TARGET_MD.parent.mkdir(parents=True, exist_ok=True)
        _TARGET_MD.write_text(new_md, encoding="utf-8")
        results[str(_TARGET_MD)] = True
    else:
        results[str(_TARGET_MD)] = False

    payload_mdx = _render_block(mdx=True)
    new_mdx = update_file(_TARGET_MDX, payload_mdx, _SENTINEL_BEGIN_MDX, _SENTINEL_END_MDX)
    old_mdx = _TARGET_MDX.read_text(encoding="utf-8") if _TARGET_MDX.is_file() else ""
    if new_mdx != old_mdx:
        _TARGET_MDX.parent.mkdir(parents=True, exist_ok=True)
        _TARGET_MDX.write_text(new_mdx, encoding="utf-8")
        results[str(_TARGET_MDX)] = True
    else:
        results[str(_TARGET_MDX)] = False
    return results


def check_only() -> int:
    """Return 0 if both files are up to date; 1 otherwise. Used by CI."""
    payload_md = _render_block(mdx=False)
    payload_mdx = _render_block(mdx=True)

    drift = []
    for target, payload, begin, end in (
        (_TARGET_MD, payload_md, _SENTINEL_BEGIN_MD, _SENTINEL_END_MD),
        (_TARGET_MDX, payload_mdx, _SENTINEL_BEGIN_MDX, _SENTINEL_END_MDX),
    ):
        new = update_file(target, payload, begin, end)
        old = target.read_text(encoding="utf-8") if target.is_file() else ""
        if new != old:
            drift.append(str(target))
    if drift:
        print(
            "env-vars docs out of date — regenerate with "
            "`python3 scripts/gen_envvars_docs.py`. Out-of-date files: "
            + ", ".join(drift),
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if either target file is out of date; do not write.",
    )
    args = parser.parse_args()
    if args.check:
        return check_only()
    changed = write_all()
    for path, did_change in sorted(changed.items()):
        print(f"{'updated' if did_change else 'unchanged'}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
