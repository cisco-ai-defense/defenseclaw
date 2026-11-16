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

``openwiki/`` is generated and excluded. The upstream files of a vendored Go
module are excluded too: a ``third_party/<module>/`` folder that ships the
upstream ``LICENSE`` and is a ``replace`` target in the root ``go.mod``.
DefenseClaw patches some of those modules, so the files it wrote or changed in
them (``VENDORED_LOCAL_FILES``, the ones each module ``README.md`` names) stay
scanned, and so does every other ``third_party`` folder. This test is scanned like any other
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
_HOOK_AGENTS = r"(?:Claude Code|Cursor|Devin|Hermes|Copilot|OpenCode|Amp|Kiro)"
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
        # IDE inventory: legacy Desktop folders are reported as Devin Desktop,
        # and the page names the old product so admins can find it (GAP-0418).
        "docs-site/content/docs/ai-discovery.mdx",
    }
)
# Third-party VS Code extension ids the IDE inventory flags as AI extensions
# (GAP-0343). They name a vendor extension, not a DefenseClaw connector.
THIRD_PARTY_EXTENSION_IDS = ("google." + _GEMINI + "-" + _CLI + "-vscode-ide-companion",)
# Files that may name either retired connector.
UNRESTRICTED_FILES = frozenset({"CHANGELOG.md"})
# The full notes live in the appendix; the upgrade page keeps a short pointer
# section of the same name.
UPGRADE_GUIDE = "docs-site/content/docs/get-started/upgrade.mdx"
UPGRADE_GUIDES = frozenset({UPGRADE_GUIDE, "docs-site/content/docs/get-started/upgrade.mdx"})
UPGRADE_SECTION = "## Renamed and removed connectors"
# Released hook renders the upgrade tests run byte for byte, as they shipped.
EXCLUDED_PREFIXES = ("openwiki/", "internal/gateway/connector/testdata/released-hooks/")
MAX_SCAN_BYTES = 8 * 1024 * 1024
# Vendored upstream Go modules (go.mod replace targets with the upstream
# LICENSE, such as the Bifrost core copy of GAP-0564). Upstream code names
# vendor CLIs in its own user-agent tables; those are not DefenseClaw
# connectors and are not ours to edit. The files DefenseClaw wrote or changed
# in each module stay scanned. Each module README names exactly these files
# (test_vendored_local_files_match_module_readmes); a new vendored module needs
# an entry here (test_tree_scan_still_reads_our_code).
VENDORED_ROOT = "third_party/"
VENDORED_MARKER = "LICENSE"
VENDORED_README = "README.md"
VENDORED_LOCAL_FILES: dict[str, frozenset[str]] = {
    "bifrost-core": frozenset(
        {
            VENDORED_README,
            "providers/utils/proxy_conn.go",
            "providers/utils/roundtripper.go",
            "providers/utils/utils.go",
        }
    ),
    "fsnotify": frozenset({VENDORED_README, "backend_kqueue.go", "backend_windows.go"}),
}
_GO_MOD_REPLACE_RE = re.compile(r"=>\s*\./third_party/([^/\s]+)/?\s*$", re.MULTILINE)
_README_GO_FILE_RE = re.compile(r"[\w./-]+\.go\b")


def _tracked_files() -> list[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("retired-name tripwire needs a git checkout")
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def _go_mod_replace_targets(go_mod: str) -> frozenset[str]:
    """Return the ``third_party`` module folders ``go.mod`` replaces a module with."""
    return frozenset(_GO_MOD_REPLACE_RE.findall(go_mod))


def _root_replace_targets() -> frozenset[str]:
    return _go_mod_replace_targets((ROOT / "go.mod").read_text(encoding="utf-8"))


def _vendored_modules(tracked: list[str], replaced: frozenset[str]) -> frozenset[str]:
    """Return the vendored module names: an upstream LICENSE and a go.mod replace target."""
    modules = set()
    for relative in tracked:
        parts = relative.split("/")
        if len(parts) == 3 and relative.startswith(VENDORED_ROOT) and parts[2] == VENDORED_MARKER:
            if parts[1] in replaced:
                modules.add(parts[1])
    return frozenset(modules)


def _scanned_files(
    tracked: list[str],
    replaced: frozenset[str] | None = None,
    local_files: dict[str, frozenset[str]] | None = None,
) -> list[str]:
    """Return the tracked files the tripwire reads (vendored upstream code skipped)."""
    replaced = _root_replace_targets() if replaced is None else replaced
    local_files = VENDORED_LOCAL_FILES if local_files is None else local_files
    modules = _vendored_modules(tracked, replaced)
    scanned = []
    for relative in tracked:
        parts = relative.split("/", 2)
        if len(parts) == 3 and parts[0] + "/" == VENDORED_ROOT and parts[1] in modules:
            if parts[2] not in local_files.get(parts[1], frozenset({VENDORED_README})):
                continue
        scanned.append(relative)
    return scanned


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
    for extension_id in THIRD_PARTY_EXTENSION_IDS:
        text = text.replace(extension_id, "")
    if relative in DESKTOP_ONLY_FILES:
        hits = _hits(text, GEMINI_RE) + _hits(text, GEMINI_LIST_RE)
    else:
        if relative in UPGRADE_GUIDES:
            text = _outside_upgrade_section(text)
        hits = _hits(text, ANY_RE) + _hits(text, GEMINI_LIST_RE)
    return [f"{relative}:{hit}" for hit in hits]


def test_retired_connector_names_do_not_reappear() -> None:
    violations: list[str] = []
    for relative in _scanned_files(_tracked_files()):
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


def test_go_mod_replace_targets_are_parsed() -> None:
    go_mod = (
        "module example\n\n"
        "replace github.com/a/one => ./third_party/one\n"
        "replace github.com/b/two v1.2.3 => ./third_party/two/\n"
        "replace (\n\tgithub.com/c/three => ./third_party/three\n\tgithub.com/d/four => ../elsewhere/four\n)\n"
        "require github.com/e/five v1.0.0 // ./third_party/five is not a replace\n"
    )
    assert _go_mod_replace_targets(go_mod) == {"one", "two", "three"}


def test_only_vendored_upstream_code_is_skipped() -> None:
    tracked = [
        "third_party/upstream/LICENSE",
        "third_party/upstream/README.md",
        "third_party/upstream/schemas/useragents.go",
        "third_party/upstream/patched/local.go",
        "third_party/licensed-not-replaced/LICENSE",
        "third_party/licensed-not-replaced/api.go",
        "third_party/unlicensed/notes.go",
        "third_party/top-level.go",
        "internal/gateway/provider_bifrost.go",
        "cli/defenseclaw/example.py",
    ]
    replaced = frozenset({"upstream", "unlicensed"})
    local = {"upstream": frozenset({"README.md", "patched/local.go"})}
    assert _scanned_files(tracked, replaced, local) == [
        "third_party/upstream/README.md",
        "third_party/upstream/patched/local.go",
        "third_party/licensed-not-replaced/LICENSE",
        "third_party/licensed-not-replaced/api.go",
        "third_party/unlicensed/notes.go",
        "third_party/top-level.go",
        "internal/gateway/provider_bifrost.go",
        "cli/defenseclaw/example.py",
    ]
    # A patched file that names a retired connector is still reported.
    gemini = _GEMINI + _CLI
    assert _violations("third_party/upstream/patched/local.go", f'agent := "{gemini}"\n')


def test_tree_scan_still_reads_our_code() -> None:
    tracked = _tracked_files()
    tracked_set = set(tracked)
    modules = _vendored_modules(tracked, _root_replace_targets())
    assert modules == set(VENDORED_LOCAL_FILES), (
        "every vendored module (third_party/<module>/LICENSE and a go.mod replace) needs a "
        "VENDORED_LOCAL_FILES entry, and every entry a vendored module"
    )
    scanned = set(_scanned_files(tracked))
    for relative in (THIS_FILE, "cli/defenseclaw/legacy_connector.py", "internal/gateway/provider_bifrost.go"):
        assert relative in scanned, relative
    for module, local_files in VENDORED_LOCAL_FILES.items():
        for name in local_files:
            relative = f"{VENDORED_ROOT}{module}/{name}"
            assert relative in tracked_set, f"listed local file is not tracked: {relative}"
            assert relative in scanned, relative
    skipped = tracked_set - scanned
    assert skipped, "no vendored module found; drop the exclusion if third_party/ is gone"
    assert all(relative.split("/")[1] in modules for relative in skipped), sorted(skipped)[:5]


def test_vendored_local_files_match_module_readmes() -> None:
    for module, local_files in VENDORED_LOCAL_FILES.items():
        readme = (ROOT / VENDORED_ROOT / module / VENDORED_README).read_text(encoding="utf-8")
        listed = local_files - {VENDORED_README}
        named = set()
        for token in _README_GO_FILE_RE.findall(readme):
            # A README may name a listed file by its base name once its path is given.
            same_base = [path for path in listed if path.rsplit("/", 1)[-1] == token]
            named.add(same_base[0] if token not in listed and len(same_base) == 1 else token)
        assert named == listed, (module, sorted(named))


def test_allowlisted_files_still_exist() -> None:
    tracked = set(_tracked_files())
    for relative in DESKTOP_ONLY_FILES | UNRESTRICTED_FILES | UPGRADE_GUIDES:
        assert relative in tracked, f"allowlisted file is missing: {relative}"


def test_upgrade_guide_documents_both_changes() -> None:
    text = (ROOT / UPGRADE_GUIDE).read_text(encoding="utf-8")
    assert UPGRADE_SECTION in text
    section = text[text.index(UPGRADE_SECTION) :]
    assert DESKTOP_RE.search(section)
    assert GEMINI_RE.search(section)
