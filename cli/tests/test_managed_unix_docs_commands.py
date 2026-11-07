# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""No doc tells an administrator to type a bare ``defenseclaw-gateway`` on managed Linux or macOS.

The standalone packages link only the users' sandbox launcher onto ``PATH``
(``/usr/bin/defenseclaw`` on Linux, ``/usr/local/bin/defenseclaw`` on macOS, see
``.goreleaser.yaml`` and ``scripts/build-macos-enterprise-pkg.sh``). The gateway
stays in ``/opt/defenseclaw/bin`` or ``/opt/cisco/defenseclaw/bin``, and sudo's
``secure_path`` leaves that folder out, so a bare ``defenseclaw-gateway`` is
"command not found" for root and for every user. A doc names the gateway by its
full path (cowork-1-0-8 GAP-0081):

    sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux status
    sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos status

The test reads the pages of ``docs-site/content`` the way
``test_managed_windows_docs_commands`` does (each fenced code line and each inline
code span), and two packaging files, and fails on:

* A bare ``defenseclaw-gateway enterprise``: that family exists only on a managed
  computer. ``reference/cli.mdx`` lists the family in the table rows of its
  "## Enterprise" section, under the sentence there that says to run it by the
  full path; only those rows are not flagged, and the test fails if the sentence
  is lost.
* A bare ``defenseclaw-gateway`` followed by an administrator command in a page of
  ``enterprise/`` (every page there is for a managed computer). ``windows.mdx`` is
  left to the Windows test.
* The few commands that sit in a page shared with the per-user install, listed in
  ``SHARED_PAGES`` with the pattern that must not come back.

A name after a path separator, a quote or a ``$`` is not bare, so the full paths,
``$PAYLOAD/defenseclaw-gateway`` and ``<dir>/defenseclaw-gateway`` pass.
"""

from __future__ import annotations

import re

import pytest

from tests.test_managed_windows_docs_commands import ROOT, SITE, _units

ENTERPRISE = SITE / "docs/enterprise"
CLI_REFERENCE = SITE / "docs/reference/cli.mdx"
CLI_REFERENCE_SENTENCE = "run it by its full path from the table below"
# Packaging files with a printed or commented administrator command.
PACKAGING_FILES = ("packaging/identity/ad/README.md", "packaging/identity/ad/sandbox-profiles.example.yaml")

_BARE = r"(?<![\\/\w.'\"$-])defenseclaw-gateway(?![\w.-])"
_ENTERPRISE_COMMAND = re.compile(_BARE + r"\s+enterprise\b")
_ADMIN_COMMAND = re.compile(
    _BARE
    + r"\s+(?:enterprise|config|status|audit|policy|rulepack|provenance|scan|connector|watchdog|start|stop|restart|doctor)\b"
)

# Pages of the per-user docs that also carry a managed Linux or macOS instruction.
SHARED_PAGES: dict[str, re.Pattern[str]] = {
    "docs-site/content/docs/policies/rules.mdx": re.compile(_BARE + r"\s+rulepack\b"),
    "docs-site/content/docs/policies/rulepack-validation.mdx": re.compile(_BARE + r"\s+rulepack\b"),
    "docs-site/content/docs/connectors/claudecode.mdx": re.compile(_BARE + r"\s+rulepack\b"),
    "docs-site/content/docs/guardrail/user-and-group-policies.mdx": re.compile(_BARE + r"\s+config\s+validate\b"),
    "docs-site/content/docs/tui.mdx": re.compile(_BARE + r"\s+status\b"),
}

# A bare name that is right: the command refuses there, so it is named, not run.
# Each entry is a path relative to the repository root and the start of the unit.
NAMED_NOT_RUN: dict[str, str] = {
    "docs-site/content/docs/enterprise/lifecycle.mdx": "defenseclaw-gateway start",
}


def _rel(path) -> str:
    return path.relative_to(ROOT).as_posix()


def _files():
    yield from sorted(SITE.rglob("*.mdx"))
    for rel in PACKAGING_FILES:
        yield ROOT / rel


def _line_of(text: str, number: int) -> str:
    return text.splitlines()[number - 1]


def _enterprise_section(text: str) -> range:
    """The line numbers of the "## Enterprise" section of reference/cli.mdx."""
    lines = text.splitlines()
    start = next(number for number, line in enumerate(lines, 1) if line == "## Enterprise")
    end = next((number for number, line in enumerate(lines[start:], start + 1) if line.startswith("## ")), len(lines) + 1)
    return range(start, end)


def _findings() -> list[tuple[str, int, str]]:
    found = []
    for path in _files():
        rel = _rel(path)
        text = path.read_text(encoding="utf-8")
        if rel.startswith("packaging/"):
            # A plain file: look at each line of text.
            lines = list(enumerate(text.splitlines(), 1))
        else:
            lines = [(number, unit) for number, unit, _ in _units(text)]
        section = _enterprise_section(text) if rel == _rel(CLI_REFERENCE) else range(0)
        for number, unit in lines:
            why = _bare_gateway(rel, unit, _line_of(text, number), number in section)
            if why:
                found.append((rel, number, f"{why}: {' '.join(unit.split())[:110]}"))
    return found


def _bare_gateway(rel: str, unit: str, line: str, in_cli_enterprise_section: bool = False) -> str | None:
    unit = " ".join(unit.split())
    if _ENTERPRISE_COMMAND.search(unit):
        if rel == _rel(CLI_REFERENCE) and in_cli_enterprise_section and line.lstrip().startswith("|"):
            return None
        return "bare defenseclaw-gateway enterprise"
    in_enterprise_page = rel.startswith("docs-site/content/docs/enterprise/")
    if in_enterprise_page and not rel.endswith("/windows.mdx") and _ADMIN_COMMAND.search(unit):
        if unit.startswith(NAMED_NOT_RUN.get(rel, "\0")):
            return None
        return "bare defenseclaw-gateway administrator command"
    pattern = SHARED_PAGES.get(rel)
    if pattern and pattern.search(unit):
        return "bare defenseclaw-gateway in a managed instruction"
    return None


def test_no_bare_managed_unix_gateway_command_in_the_docs() -> None:
    hits = _findings()
    assert not hits, (
        "defenseclaw-gateway is not on the PATH of a managed Linux or macOS host. Write "
        "/opt/defenseclaw/bin/defenseclaw-gateway (Linux) or /opt/cisco/defenseclaw/bin/defenseclaw-gateway (macOS):\n"
        + "\n".join(f"  {rel}:{number}: {why}" for rel, number, why in hits)
    )


def test_cli_reference_says_to_use_the_full_paths() -> None:
    text = " ".join(CLI_REFERENCE.read_text(encoding="utf-8").split())
    assert CLI_REFERENCE_SENTENCE in text, "reference/cli.mdx table rows name the bare gateway only under that sentence"
    assert (
        "/opt/defenseclaw/bin/defenseclaw-gateway" in text and "/opt/cisco/defenseclaw/bin/defenseclaw-gateway" in text
    )


def test_named_not_run_entries_are_not_stale() -> None:
    for rel, start in NAMED_NOT_RUN.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        used = [unit for _, unit, _ in _units(text) if " ".join(unit.split()).startswith(start)]
        assert used, f"NAMED_NOT_RUN entry {rel!r} no longer matches a unit, remove it"


def test_concepts_page_states_the_gateway_is_on_no_path() -> None:
    text = " ".join((ENTERPRISE / "concepts.mdx").read_text(encoding="utf-8").split())
    assert "do not put `defenseclaw-gateway` on the `PATH`" in text
    assert "`/usr/bin/defenseclaw` on Linux, `/usr/local/bin/defenseclaw` on macOS" in text


@pytest.mark.parametrize(
    "rel, unit, bare",
    [
        ("docs-site/content/docs/enterprise/linux.mdx", "defenseclaw-gateway enterprise linux status", True),
        ("docs-site/content/docs/enterprise/linux.mdx", "sudo defenseclaw-gateway enterprise linux status", True),
        ("docs-site/content/docs/get-started/install.mdx", "defenseclaw-gateway enterprise macos ensure --json", True),
        ("docs-site/content/docs/enterprise/operations.mdx", "defenseclaw-gateway config validate ./config.yaml", True),
        ("docs-site/content/docs/enterprise/sandboxes.mdx", "defenseclaw-gateway config validate FILE", True),
        ("docs-site/content/docs/policies/rules.mdx", "defenseclaw-gateway rulepack validate --dir PACK", True),
        (
            "docs-site/content/docs/enterprise/linux.mdx",
            "/opt/defenseclaw/bin/defenseclaw-gateway enterprise linux status",
            False,
        ),
        (
            "docs-site/content/docs/enterprise/macos.mdx",
            "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos status",
            False,
        ),
        (
            "docs-site/content/docs/enterprise/lifecycle.mdx",
            'sudo "$PAYLOAD/defenseclaw-gateway" enterprise linux ensure',
            False,
        ),
        (
            "docs-site/content/docs/edge-connector/install.mdx",
            "<dir>/defenseclaw-gateway enterprise linux install",
            False,
        ),
        ("docs-site/content/docs/enterprise/linux.mdx", "defenseclaw-gateway", False),
        ("docs-site/content/docs/enterprise/sandboxes.mdx", "defenseclaw-gateway sandbox-daemon", False),
        # The per-user install types it bare.
        ("docs-site/content/docs/get-started/install.mdx", "defenseclaw-gateway status", False),
        ("docs-site/content/docs/policies/rules.mdx", "defenseclaw-gateway restart", False),
        # Windows pages are the Windows test's.
        ("docs-site/content/docs/enterprise/windows.mdx", "defenseclaw-gateway status --json", False),
    ],
)
def test_matcher(rel: str, unit: str, bare: bool) -> None:
    assert bool(_bare_gateway(rel, unit, unit)) is bare


def test_cli_reference_table_rows_are_exempt_only_in_the_enterprise_section() -> None:
    row = "| `defenseclaw-gateway enterprise policy show` | Show each connector's route |"
    cli = _rel(CLI_REFERENCE)
    assert _bare_gateway(cli, row, row, True) is None
    assert _bare_gateway(cli, row, row, False)
    section = _enterprise_section(CLI_REFERENCE.read_text(encoding="utf-8"))
    assert len(section) > 50, "the Enterprise section of reference/cli.mdx is gone or empty"
