# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Retired connector names must not reappear in the tree.

Two connectors are gone: the pre-rename Devin Desktop connector (now covered by
``devin``) and Google's retired command-line connector (replaced by
Antigravity). Only these files may still name them:

* the old Desktop connector: the two legacy-migration modules and their tests;
* both connectors: ``CHANGELOG.md``, the "Renamed and removed connectors"
  section of the upgrade guide, and the enterprise manual test plan, whose
  migration rows configure the retired ids.

``openwiki/`` is generated and excluded. This test is scanned like any other
file, so it builds every retired name from fragments (and the old Desktop
strings from ``defenseclaw.legacy_connector``) instead of spelling them.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from defenseclaw import legacy_connector

ROOT = Path(__file__).resolve().parents[2]
THIS_FILE = Path(__file__).resolve().relative_to(ROOT).as_posix()

_DESKTOP_ID = legacy_connector.RETIRED_DESKTOP_ID
_DESKTOP_PUBLISHER = legacy_connector.INVENTORY_DOT_DIRS[1].lstrip(".")
_CASCADE_RESPONSE = "post_" + "cascade" + "_response"

_GEMINI = "gemini"
_CLI = "cli"

# Desktop patterns: allowed in the legacy modules and their tests.
DESKTOP_PATTERNS = (
    re.escape(_DESKTOP_ID),
    re.escape(_DESKTOP_PUBLISHER),
    re.escape(_CASCADE_RESPONSE),
    re.escape(_CASCADE_RESPONSE.replace("_", "")),
)
# Command-line connector patterns: allowed only in the changelog and the
# upgrade notes.
GEMINI_PATTERNS = (
    re.escape(_GEMINI + _CLI),
    _GEMINI + r"[-_ ]" + _CLI,
    re.escape((_GEMINI + "_" + _CLI + "_home").upper()),
    re.escape(("defenseclaw_" + _GEMINI + "_config_home").upper()),
    re.escape((_GEMINI + "_config_dir").upper()),
    re.escape("otlp-" + _GEMINI + _CLI),
    re.escape("OTLPScope" + _GEMINI.capitalize() + _CLI.upper()),
)

DESKTOP_RE = re.compile("|".join(DESKTOP_PATTERNS), re.IGNORECASE)
GEMINI_RE = re.compile("|".join(GEMINI_PATTERNS), re.IGNORECASE)
ANY_RE = re.compile("|".join(DESKTOP_PATTERNS + GEMINI_PATTERNS), re.IGNORECASE)
# The bare Google agent name listed next to hook connectors in prose, as in
# "Hermes / <name> / Copilot". Case-sensitive and limited to agent names that
# are not also model families, so provider lists and Antigravity's ~/.gemini
# paths do not match.
_HOOK_AGENTS = r"(?:Claude Code|Cursor|Devin|Hermes|Copilot|OpenCode|Amp|Kiro|OpenHands)"
_LISTED = _GEMINI.capitalize()
_LIST_SEP = r"\s*[/,]\s*"
GEMINI_LIST_RE = re.compile(rf"\b{_LISTED}{_LIST_SEP}{_HOOK_AGENTS}\b|\b{_HOOK_AGENTS}{_LIST_SEP}{_LISTED}\b")

# Files that may name the old Desktop connector (but not the command-line one).
DESKTOP_ONLY_FILES = frozenset(
    {
        "cli/defenseclaw/legacy_connector.py",
        "cli/tests/test_legacy_connector.py",
        "internal/legacyconnector/legacyconnector.go",
        "internal/legacyconnector/legacyconnector_test.go",
    }
)
# Files that may name either retired connector.
UNRESTRICTED_FILES = frozenset({"CHANGELOG.md", "docs/ENTERPRISE-TEST-PLAN.md"})
UPGRADE_GUIDE = "docs-site/content/docs/get-started/upgrade.mdx"
UPGRADE_SECTION = "## Renamed and removed connectors"
EXCLUDED_PREFIXES = ("openwiki/",)
MAX_SCAN_BYTES = 8 * 1024 * 1024


def _tracked_files() -> list[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("retired-name tripwire needs a git checkout")
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def _read_text(relative: str) -> str | None:
    path = ROOT / relative
    try:
        if not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _outside_upgrade_section(text: str) -> str:
    """Return the upgrade guide with its renamed/removed section blanked."""
    start = text.find(UPGRADE_SECTION)
    if start < 0:
        return text
    rest = text[start + len(UPGRADE_SECTION) :]
    following = re.search(r"^## ", rest, re.MULTILINE)
    end = start + len(UPGRADE_SECTION) + (following.start() if following else len(rest))
    return text[:start] + text[end:]


def _hits(text: str, pattern: re.Pattern[str]) -> list[str]:
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append(f"{number}: {line.strip()[:160]}")
    return hits


def _violations(relative: str, text: str) -> list[str]:
    """Return the retired names ``text`` may not contain at path ``relative``."""
    if relative.startswith(EXCLUDED_PREFIXES) or relative in UNRESTRICTED_FILES:
        return []
    if relative in DESKTOP_ONLY_FILES:
        hits = _hits(text, GEMINI_RE) + _hits(text, GEMINI_LIST_RE)
    else:
        if relative == UPGRADE_GUIDE:
            text = _outside_upgrade_section(text)
        hits = _hits(text, ANY_RE) + _hits(text, GEMINI_LIST_RE)
    return [f"{relative}:{hit}" for hit in hits]


def test_retired_connector_names_do_not_reappear() -> None:
    violations: list[str] = []
    for relative in _tracked_files():
        text = _read_text(relative)
        if text is not None:
            violations.extend(_violations(relative, text))
    assert not violations, (
        "retired connector names reappeared outside the allowlisted migration and "
        "upgrade-notes files:\n" + "\n".join(violations[:50])
    )


def test_tripwire_flags_reappearing_names() -> None:
    gemini_names = (
        _GEMINI + _CLI,
        _GEMINI + "-" + _CLI,
        _GEMINI.capitalize() + " " + _CLI.upper(),
        _GEMINI + "_" + _CLI + "_home",
        (_GEMINI + "_" + _CLI + "_home").upper(),
        _GEMINI + "_config_dir",
        "otlp-" + _GEMINI + _CLI,
        "OTLPScope" + _GEMINI.capitalize() + _CLI.upper(),
    )
    desktop_names = (_DESKTOP_ID, _DESKTOP_ID + "_user_home", _DESKTOP_PUBLISHER, _CASCADE_RESPONSE)
    ordinary = "cli/defenseclaw/example.py"
    for name in gemini_names:
        line = f'value = "{name}"\n'
        assert _violations(ordinary, line), name
        assert _violations(THIS_FILE, line), name
        for relative in DESKTOP_ONLY_FILES:
            assert _violations(relative, line), (relative, name)
        assert not _violations("CHANGELOG.md", line)
    for name in desktop_names:
        line = f'value = "{name}"\n'
        assert _violations(ordinary, line), name
        for relative in DESKTOP_ONLY_FILES:
            assert not _violations(relative, line), (relative, name)

    gemini = _GEMINI + _CLI
    guide = f"# Upgrade\n\n{UPGRADE_SECTION}\n\nRemove `{gemini}`.\n\n## Next\n\n"
    assert not _violations(UPGRADE_GUIDE, guide)
    assert _violations(UPGRADE_GUIDE, guide + f"Remove `{gemini}`.\n")


def test_gemini_list_pattern_matches_connector_lists_only() -> None:
    gemini = _GEMINI.capitalize()
    assert GEMINI_LIST_RE.search(f"Codex / Claude Code / Cursor / Devin / Hermes / {gemini} / Copilot")
    assert GEMINI_LIST_RE.search(f"{gemini}, Copilot")
    assert not GEMINI_LIST_RE.search(f"OpenAI, Anthropic, {gemini}, Bedrock")
    assert not GEMINI_LIST_RE.search("~/.gemini/config/hooks.json")


def test_allowlisted_files_still_exist() -> None:
    tracked = set(_tracked_files())
    for relative in DESKTOP_ONLY_FILES | UNRESTRICTED_FILES | {UPGRADE_GUIDE}:
        assert relative in tracked, f"allowlisted file is missing: {relative}"


def test_upgrade_guide_documents_both_changes() -> None:
    text = (ROOT / UPGRADE_GUIDE).read_text(encoding="utf-8")
    assert UPGRADE_SECTION in text
    section = text[text.index(UPGRADE_SECTION) :]
    assert DESKTOP_RE.search(section)
    assert GEMINI_RE.search(section)
