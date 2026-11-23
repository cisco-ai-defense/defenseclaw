"""rel-1-0-10:GAP-1749: every config/targets render in the Windows installer
bootstrap follows -EnterpriseProfile.

The -DeferredConfig placeholder (Setup /install without CONFIG= and MANIFEST=)
rendered its config without -ForProfile, so the standalone placeholder lacked
``enterprise.profile: standalone`` and the gateway's inspect-cowork refused it:
every standalone deferred install ended 1603.

The placeholder targets.yaml was then rendered with no profiles as a bare
``targets:`` key. That decodes as null, which the guardian manifest loader
refuses as a withdrawal of enrolled hooks, so the staged install still ended
1603 one stage later. It is now the explicit empty list ``targets: []``.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

INSTALLER = (
    Path(__file__).resolve().parents[2] / "packaging" / "windows" / "install-enterprise.ps1"
)
RENDERERS = ("Get-DefenseClawRenderedEnterpriseConfig", "Get-DefenseClawRenderedEnterpriseTargets")


def _command_at(text: str, start: int) -> str:
    """The PowerShell command that starts at ``start``: up to the first line end
    outside parentheses that is not a backtick continuation."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break  # the end of an enclosing (Get-... ) expression
            depth -= 1
        elif ch == "\n" and depth == 0 and not text[start:i].rstrip().endswith("`"):
            break
        i += 1
    return re.sub(r"\s+", " ", text[start:i].replace("`", " ")).strip()


def _render_calls() -> list[str]:
    text = INSTALLER.read_text(encoding="utf-8")
    calls = []
    for name in RENDERERS:
        for match in re.finditer(re.escape(name), text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            prefix = text[line_start : match.start()].strip()
            if prefix.startswith(("function", "#")):
                continue
            calls.append(_command_at(text, match.start()))
    return calls


def test_every_installer_render_call_passes_the_enterprise_profile() -> None:
    calls = _render_calls()
    # The deferred placeholder config and the -Mode/-Connector shorthand pair.
    # The deferred placeholder manifest is a literal (see below).
    assert len(calls) == 3, calls
    missing = [c for c in calls if "-ForProfile $EnterpriseProfile" not in c]
    assert missing == [], missing


def test_deferred_placeholder_config_follows_the_enterprise_profile() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    start = text.index("if ($DeferredConfig) {")
    end = text.index("$Config = $deferredConfigPath", start)
    at = text.index("Get-DefenseClawRenderedEnterpriseConfig", start)
    assert at < end
    assert "-ForProfile $EnterpriseProfile" in _command_at(text, at)


def test_deferred_placeholder_targets_are_an_explicit_empty_list() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    start = text.index("if ($DeferredConfig) {")
    end = text.index("$Manifest = $deferredManifestPath", start)
    block = text[start:end]
    match = re.search(
        r'WriteAllText\(\s*\$deferredManifestPath,\s*"((?:[^"`]|`.)*)",', block
    )
    # A renderer call with no profiles emits a bare `targets:` (null), which
    # the guardian refuses; only a literal explicit empty list loads.
    assert match, "the deferred placeholder manifest must be a literal explicit empty set"
    doc = yaml.safe_load(match.group(1).replace("`n", "\n"))
    assert doc == {"version": 1, "targets": []}, doc
