# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Regression checks for managed standalone deployment instructions."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site" / "content" / "docs"


@pytest.mark.parametrize(
    ("gap", "pages", "markers"),
    [
        ("0430", ("get-started/upgrade.mdx", "../../../CHANGELOG.md"), ("LOW and INFO skill findings", "review queue")),
        ("0553", ("enterprise/lifecycle.mdx",), ("mismatched pack", "restart alone")),
        ("0559", ("enterprise/configuration.mdx", "enterprise/machine-policy.mdx"), ("claudecode.enabled: false", "machine policy")),
        ("0564", ("enterprise/ai-defense-key.mdx",), ("/opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise secret status", "/opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise secret remove")),
        ("0565", ("enterprise/mdm/jamf.mdx", "enterprise/mdm/kandji.mdx", "enterprise/mdm/intune-macos.mdx", "enterprise/mdm/workspace-one.mdx"), ("uninstall removes this log",)),
        ("0568", ("enterprise/mdm/jamf.mdx", "enterprise/mdm/kandji.mdx", "enterprise/mdm/intune-macos.mdx", "enterprise/mdm/workspace-one.mdx"), ("stage-pack", "sha256:<digest>")),
        ("0585", ("enterprise/configuration.mdx", "reference/fail-modes.mdx"), ("hook_fail_mode: open", "fail-closed")),
        ("0586", ("enterprise/configuration.mdx", "policies/admission.mdx"), ("4 MiB", "65,536")),
        ("0630", ("enterprise/enrollment.mdx",), ("include_groups", "three consecutive enumerator cycles")),
        ("0637", ("enterprise/enrollment.mdx",), ("gateway journal", "Audit export")),
        ("0657", ("enterprise/mdm/linux-config-management.mdx",), ("rc -ne 75", "tries       => 1")),
        ("0658", ("enterprise/mdm/intune-linux.mdx", "enterprise/mdm/linux-config-management.mdx"), ("agent_sessions_restart_required", "restart agent sessions")),
        ("0659", ("enterprise/mdm/linux-config-management.mdx",), ("node['defenseclaw']['ai_defense_key']",)),
        ("0579", ("enterprise/configuration.mdx",), ("config migrate --config /etc/defenseclaw/config.yaml --ack",)),
        ("0523", ("enterprise/mdm/intune-linux.mdx",), ("cached retry", "exit `75`")),
        ("0537", ("enterprise/mdm/intune-linux.mdx",), ("pack-delivery", "After an uninstall with purge")),
        ("0518", ("enterprise/mdm/intune-macos.mdx",), ("cached recurring install", "checked in")),
        ("0563", ("enterprise/mdm/intune-macos.mdx", "enterprise/mdm/kandji.mdx"), ("HTTP 302", "direct HTTPS file URL")),
    ],
)
def test_deployment_guidance(gap: str, pages: tuple[str, ...], markers: tuple[str, ...]) -> None:
    for page in pages:
        text = (DOCS / page).read_text(encoding="utf-8")
        for marker in markers:
            assert marker.lower() in text.lower(), f"GAP-{gap}: {page} should mention {marker}"
