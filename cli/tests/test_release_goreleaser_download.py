# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GoReleaser is downloaded from its GitHub release and checked by sha256.

goreleaser-action resolved the version through goreleaser.com before it
downloaded anything, so an outage there failed the release with an empty
error (rel-1-0-1:CI-a). Both workflows now fetch the pinned tarball with curl
retries and refuse it unless its sha256 matches the pin.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

VERSION = "v2.15.4"
# goreleaser_Linux_x86_64.tar.gz in the v2.15.4 checksums.txt; that file's
# cosign bundle verifies against goreleaser's release workflow at the tag.
SHA256 = "aae00c71a4a6d55e08cce9273a1516bdce33c1e07cffb7e502fa6fec4377dede"
URL = "https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz"

# (workflow, job, name of the step that runs goreleaser, its command, its env)
GORELEASER_JOBS = (
    (
        "release.yaml",
        "build",
        "Build gateway archives and SBOMs",
        "args=(release --clean)",
        {"GITHUB_TOKEN": "${{ github.token }}"},
    ),
    (
        "ci.yml",
        "enterprise-install-assets",
        "Build the Linux packages with the release GoReleaser config",
        "goreleaser release --snapshot --clean --skip=sbom,sign,publish,validate",
        {"GORELEASER_CURRENT_TAG": "v9.9.9"},
    ),
)


def _steps(workflow: str, job: str) -> tuple[dict, list[dict]]:
    data = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    job_data = data["jobs"][job]
    return job_data, job_data["steps"]


def test_no_workflow_uses_goreleaser_action() -> None:
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        assert "goreleaser/goreleaser-action" not in path.read_text(encoding="utf-8"), path.name


def test_goreleaser_is_downloaded_with_retries_and_checked_by_sha256() -> None:
    for workflow, job, build_name, command, env in GORELEASER_JOBS:
        job_data, steps = _steps(workflow, job)
        # The pinned checksum is for the Linux x86_64 tarball.
        assert job_data["runs-on"] == "ubuntu-latest", (workflow, job)
        names = [step.get("name") for step in steps]
        install = steps[names.index("Install GoReleaser")]
        build = steps[names.index(build_name)]
        assert names.index("Install GoReleaser") < names.index(build_name), (workflow, job)

        assert install["env"] == {"GORELEASER_VERSION": VERSION, "GORELEASER_SHA256": SHA256}, (workflow, job)
        script = install["run"]
        assert "set -euo pipefail" in script
        assert 'uname -m)" == Linux/x86_64' in script
        curl = next(line for line in script.splitlines() if line.strip().startswith("curl "))
        assert "--retry 5" in curl and "-fsSL" in curl, (workflow, job, curl)
        assert URL in script
        assert 'echo "${GORELEASER_SHA256}  $dir/goreleaser.tar.gz" | sha256sum -c -' in script
        # Unpack and put on PATH only after the checksum passed (set -e).
        assert script.index("sha256sum -c") < script.index("tar -xzf") < script.index("$GITHUB_PATH")

        assert "uses" not in build, (workflow, job)
        assert build["env"] == env, (workflow, job)
        assert command in build["run"], (workflow, job)


def test_release_dry_run_still_skips_publish() -> None:
    _, steps = _steps("release.yaml", "build")
    build = next(step for step in steps if step.get("name") == "Build gateway archives and SBOMs")
    assert 'if [[ "$DRY_RUN" == true ]]; then args+=(--skip=publish); fi' in build["run"]
    assert 'goreleaser "${args[@]}"' in build["run"]
    workflow = yaml.safe_load((WORKFLOWS / "release.yaml").read_text(encoding="utf-8"))
    assert workflow["env"]["DRY_RUN"] == "${{ inputs.dry_run }}"


def test_both_workflows_pin_the_same_goreleaser() -> None:
    pins = set()
    for workflow, job, *_ in GORELEASER_JOBS:
        _, steps = _steps(workflow, job)
        install = next(step for step in steps if step.get("name") == "Install GoReleaser")
        pins.add((install["env"]["GORELEASER_VERSION"], install["env"]["GORELEASER_SHA256"]))
    assert pins == {(VERSION, SHA256)}
