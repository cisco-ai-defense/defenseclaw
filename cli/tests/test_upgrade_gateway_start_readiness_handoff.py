# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the frozen-controller gateway readiness handoff."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_post_hard_cut_continuation_scopes_fresh_process_marker_to_frozen_controller() -> None:
    resolver = (ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    start = resolver.index("continue_post_hard_cut_upgrade() {")
    end = resolver.index("\nvalidate_tarball_members() {", start)
    continuation = resolver[start:end]

    marker = "DEFENSECLAW_UPGRADE_FRESH_PROCESS=1"
    controller = '"${DEFENSECLAW_VENV}/bin/defenseclaw" upgrade --yes --version "${final_version}"'
    assert continuation.count(marker) == 1
    assert continuation.count(controller) == 1
    assert f"export {marker}" not in continuation
    for staged_name in (
        "DEFENSECLAW_STAGED_UPGRADE",
        "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR",
        "DEFENSECLAW_STAGED_TARGET_CONTROLLER_VERSION",
    ):
        assert continuation.index(f"unset {staged_name}") < continuation.index(marker)
    assert continuation.index('STAGING_DIR=""') < continuation.index(marker)
    assert continuation.index(marker) < continuation.index(controller)
    assert (
        f"env -u UV_CONSTRAINT -u UV_OVERRIDE -u UV_EXCLUDE_NEWER \\\n        {marker} \\\n        {controller}"
    ) in continuation


def test_fresh_health_process_delegates_one_strict_versioned_readiness_budget() -> None:
    upgrade_source = (ROOT / "cli" / "defenseclaw" / "commands" / "cmd_upgrade.py").read_text(encoding="utf-8")
    gateway_source = (ROOT / "internal" / "cli" / "daemon.go").read_text(encoding="utf-8")

    assert 'os.environ.get(_UPGRADE_HANDOFF_ENV) == "1"' in upgrade_source
    assert "_poll_handoff_gateway_readiness(cfg, timeout_seconds, expected_version)" in upgrade_source
    assert '"upgrade-wait-ready"' in upgrade_source
    assert '"--expected-version"' in upgrade_source
    assert "timeout=readiness_timeout + 5" in upgrade_source

    assert 'Use:               "upgrade-wait-ready"' in gateway_source
    assert "Hidden:            true" in gateway_source
    assert "waitForUpgradeGatewayReadiness(" in gateway_source
    assert "waitForRunningDaemonReadinessWithVersion(" in gateway_source
    assert "inspectConfiguredListener(d, cfg, client)" in gateway_source
    assert "status.Provenance.BinaryVersion != requirements.expectedBinaryVersion" in gateway_source
    assert "ManagedProcessStartedAt(pid)" in gateway_source
