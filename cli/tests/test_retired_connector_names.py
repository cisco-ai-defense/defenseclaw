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
``devin``) and the Gemini CLI connector (replaced by Antigravity). Only these
files may still name them:

* the two legacy-migration modules and their tests, for the old Desktop ID;
* the two native Windows install-state compatibility lists, which let Setup
  and the uninstaller read state written by pre-release builds;
* ``CHANGELOG.md``;
* the "Renamed and removed connectors" section of the upgrade guide;
* this test.

``openwiki/`` is generated and excluded. The old Desktop strings are built from
``defenseclaw.legacy_connector`` so this file does not spell them itself.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from defenseclaw import legacy_connector

ROOT = Path(__file__).resolve().parents[2]

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
# Gemini CLI patterns: allowed nowhere except the upgrade notes.
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
ANY_RE = re.compile("|".join(DESKTOP_PATTERNS + GEMINI_PATTERNS), re.IGNORECASE)

# Files that may name the old Desktop connector (but not Gemini CLI).
DESKTOP_ONLY_FILES = frozenset(
    {
        "cli/defenseclaw/legacy_connector.py",
        "cli/tests/test_legacy_connector.py",
        "internal/legacyconnector/legacyconnector.go",
        "internal/legacyconnector/legacyconnector_test.go",
    }
)
# Files that may name any retired connector.
UNRESTRICTED_FILES = frozenset(
    {
        "CHANGELOG.md",
        "cli/defenseclaw/retired_install_state.py",
        "cli/tests/test_retired_connector_names.py",
        "cmd/defenseclaw-setup/retired_install_state.go",
    }
)
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


def test_retired_connector_names_do_not_reappear() -> None:
    violations: list[str] = []
    for relative in _tracked_files():
        if relative.startswith(EXCLUDED_PREFIXES) or relative in UNRESTRICTED_FILES:
            continue
        text = _read_text(relative)
        if text is None:
            continue
        if relative in DESKTOP_ONLY_FILES:
            gemini_only = re.compile("|".join(GEMINI_PATTERNS), re.IGNORECASE)
            for hit in _hits(text, gemini_only):
                violations.append(f"{relative}:{hit}")
            continue
        if relative == UPGRADE_GUIDE:
            text = _outside_upgrade_section(text)
        for hit in _hits(text, ANY_RE):
            violations.append(f"{relative}:{hit}")
    assert not violations, (
        "retired connector names reappeared outside the allowlisted migration and "
        "upgrade-notes files:\n" + "\n".join(violations[:50])
    )


def test_allowlisted_files_still_exist() -> None:
    tracked = set(_tracked_files())
    for relative in DESKTOP_ONLY_FILES | UNRESTRICTED_FILES | {UPGRADE_GUIDE}:
        assert relative in tracked, f"allowlisted file is missing: {relative}"


def test_upgrade_guide_documents_both_changes() -> None:
    text = (ROOT / UPGRADE_GUIDE).read_text(encoding="utf-8")
    assert UPGRADE_SECTION in text
    section = text[text.index(UPGRADE_SECTION) :]
    assert DESKTOP_RE.search(section)
    assert re.search("|".join(GEMINI_PATTERNS), section, re.IGNORECASE)
