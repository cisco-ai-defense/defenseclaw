# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""PR change detection needs only the merge commit and its two parents."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("workflow_name", "expected_diff"),
    (
        ("connector-live-e2e.yml", "git diff --name-only HEAD^1 HEAD"),
        ("telemetry-registry.yml", 'git diff --quiet HEAD^1 HEAD^2 -- "${telemetry_paths[@]}"'),
        ("macos-app.yml", 'git diff --quiet --no-renames HEAD^1 HEAD -- "${macos_paths[@]}"'),
    ),
)
def test_pr_change_detection_uses_bounded_merge_checkout(workflow_name: str, expected_diff: str) -> None:
    workflow = yaml.load((ROOT / ".github/workflows" / workflow_name).read_text(), Loader=yaml.BaseLoader)
    changes = workflow["jobs"]["changes"]
    assert changes["timeout-minutes"] == "5"
    checkout = next(step for step in changes["steps"] if str(step.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == "2"
    assert checkout["with"]["persist-credentials"] == "false"
    assert expected_diff in str(changes["steps"])


def test_non_pr_change_detection_keeps_full_coverage() -> None:
    connector = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text()
    telemetry = (ROOT / ".github/workflows/telemetry-registry.yml").read_text()
    macos = (ROOT / ".github/workflows/macos-app.yml").read_text()
    assert 'if [ "${EVENT}" != "pull_request" ]; then' in connector
    assert 'echo "matrix=${full}" >> "$GITHUB_OUTPUT"' in connector
    assert 'if [[ "$EVENT_NAME" != "pull_request" ]]; then' in telemetry
    assert 'echo "telemetry=true" >> "$GITHUB_OUTPUT"' in telemetry
    assert "push|workflow_dispatch)" in macos
    assert 'echo "macos=true" >> "$GITHUB_OUTPUT"' in macos
