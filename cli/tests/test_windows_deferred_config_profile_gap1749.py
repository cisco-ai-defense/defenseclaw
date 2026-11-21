"""rel-1-0-10:GAP-1749: every config/targets render in the Windows installer
bootstrap follows -EnterpriseProfile.

The -DeferredConfig placeholder (Setup /install without CONFIG= and MANIFEST=)
rendered its config without -ForProfile, so the standalone placeholder lacked
``enterprise.profile: standalone`` and the gateway's inspect-cowork refused it:
every standalone deferred install ended 1603.
"""

from __future__ import annotations

import re
from pathlib import Path

INSTALLER = (
    Path(__file__).resolve().parents[2] / "packaging" / "windows" / "install-enterprise.ps1"
)
RENDERERS = ("Get-DefenseClawRenderedEnterpriseConfig", "Get-DefenseClawRenderedEnterpriseTargets")


def _logical_lines(text: str) -> list[str]:
    # Join PowerShell backtick line continuations into one logical line.
    return re.sub(r"`[ \t]*\r?\n[ \t]*", " ", text).splitlines()


def _render_calls() -> list[str]:
    calls = []
    for line in _logical_lines(INSTALLER.read_text(encoding="utf-8")):
        for name in RENDERERS:
            if name in line and not line.lstrip().startswith(("function ", "#")):
                calls.append(line.strip())
    return calls


def test_every_installer_render_call_passes_the_enterprise_profile() -> None:
    calls = _render_calls()
    # The deferred placeholder pair and the -Mode/-Connector shorthand pair.
    assert len(calls) >= 4, calls
    missing = [c for c in calls if "-ForProfile $EnterpriseProfile" not in c]
    assert missing == [], missing


def test_deferred_placeholder_config_follows_the_enterprise_profile() -> None:
    text = "\n".join(_logical_lines(INSTALLER.read_text(encoding="utf-8")))
    start = text.index("if ($DeferredConfig) {")
    block = text[start : text.index("$Config = $deferredConfigPath", start)]
    config_calls = [
        line for line in block.splitlines() if "Get-DefenseClawRenderedEnterpriseConfig" in line
    ]
    assert len(config_calls) == 1, config_calls
    assert "-ForProfile $EnterpriseProfile" in config_calls[0], config_calls[0]
