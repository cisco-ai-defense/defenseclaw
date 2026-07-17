# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI_PATH = ROOT / ".github/workflows/ci.yml"
RELEASE_PATH = ROOT / ".github/workflows/release.yaml"
EXHAUSTIVE_PATH = ROOT / ".github/workflows/telemetry-registry.yml"

EXHAUSTIVE_TESTS = {
    "cli/tests/test_telemetry_registry_generator.py",
    "cli/tests/test_telemetry_registry_candidate_renderer.py",
}


def _workflow(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _render(value: object) -> str:
    return str(value)


def _pull_request_paths() -> set[str]:
    pull_request = _workflow(EXHAUSTIVE_PATH)["on"]["pull_request"]
    return set(pull_request["paths"])


def _matches_any(path: Path, patterns: set[str]) -> bool:
    relative = path.relative_to(ROOT).as_posix()
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)


def test_ordinary_ci_always_checks_real_registry_without_exhaustive_mutation_suites() -> None:
    workflow = _workflow(CI_PATH)
    jobs = workflow["jobs"]
    schema_steps = jobs["schema-parity"]["steps"]

    telemetry_steps = [step for step in schema_steps if step.get("run") == "make telemetry-check"]
    assert len(telemetry_steps) == 1
    assert "if" not in telemetry_steps[0]
    assert "python-telemetry-test" not in jobs

    regular = _render(jobs["python-test"])
    for test_file in EXHAUSTIVE_TESTS:
        assert f"--exclude {test_file}" in regular

    aggregate = jobs["python-lint-test"]
    assert set(aggregate["needs"]) == {"python-test", "python-lint"}
    rendered_aggregate = _render(aggregate)
    assert 'test "${#coverage_parts[@]}" -eq 4' in rendered_aggregate
    assert "PYTHON_TELEMETRY" not in rendered_aggregate
    assert "python-coverage-part-telemetry" not in CI_PATH.read_text(encoding="utf-8")


def test_exhaustive_registry_workflow_is_path_filtered_nightly_and_manual() -> None:
    workflow = _workflow(EXHAUSTIVE_PATH)
    triggers = workflow["on"]
    jobs = workflow["jobs"]
    text = EXHAUSTIVE_PATH.read_text(encoding="utf-8")

    assert set(triggers) == {"pull_request", "schedule", "workflow_dispatch"}
    assert triggers["schedule"] == [{"cron": "47 3 * * *"}]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "telemetry-registry-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }

    exhaustive = jobs["exhaustive"]
    cases = exhaustive["strategy"]["matrix"]["include"]
    assert {case["test_file"] for case in cases} == EXHAUSTIVE_TESTS
    assert exhaustive["timeout-minutes"] == "50"
    assert "--numprocesses=4" in _render(exhaustive)
    assert "--dist=worksteal" in _render(exhaustive)
    assert "--cov" not in text
    assert "coverage-py-telemetry" not in text
    assert "upload-artifact" not in text

    complete = jobs["complete"]
    assert complete["needs"] == "exhaustive"
    assert complete["if"] == "${{ always() }}"
    assert 'test "$EXHAUSTIVE_RESULT" = success' in _render(complete)


def test_exhaustive_path_filter_covers_every_registry_input_and_test_dependency() -> None:
    patterns = _pull_request_paths()
    required_patterns = {
        "schemas/telemetry/**",
        "scripts/generate_telemetry_registry.py",
        "scripts/update_telemetry_registry_upstream.py",
        "scripts/render_telemetry_*.py",
        "scripts/telemetry_*.py",
        "cli/tests/conftest.py",
        "cli/tests/test_telemetry_ci_strategy.py",
        "cli/tests/test_telemetry_registry_*.py",
        "cli/tests/support/telemetry_registry_manifest_driver.py",
        "docs/design/observability-v8/current-state-inventory.yaml",
        "internal/observability/zz_generated_telemetry_*.go",
        "Makefile",
        "pyproject.toml",
        "uv.lock",
        ".github/workflows/ci.yml",
        ".github/workflows/telemetry-registry.yml",
    }
    assert patterns == required_patterns

    concrete_inputs = {
        ROOT / "scripts/generate_telemetry_registry.py",
        ROOT / "scripts/update_telemetry_registry_upstream.py",
        ROOT / "cli/tests/conftest.py",
        ROOT / "cli/tests/support/telemetry_registry_manifest_driver.py",
        ROOT / "docs/design/observability-v8/current-state-inventory.yaml",
        ROOT / "Makefile",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
        CI_PATH,
        EXHAUSTIVE_PATH,
        *ROOT.glob("scripts/render_telemetry_*.py"),
        *ROOT.glob("scripts/telemetry_*.py"),
        *ROOT.glob("cli/tests/test_telemetry_registry_*.py"),
        *ROOT.glob("internal/observability/zz_generated_telemetry_*.go"),
        *ROOT.glob("schemas/telemetry/**/*"),
    }
    assert concrete_inputs
    uncovered = sorted(
        path.relative_to(ROOT).as_posix() for path in concrete_inputs if not _matches_any(path, patterns)
    )
    assert uncovered == []


def test_exhaustive_suites_cannot_drift_back_into_ordinary_ci_or_release() -> None:
    ci = _workflow(CI_PATH)
    release = _workflow(RELEASE_PATH)
    release_text = RELEASE_PATH.read_text(encoding="utf-8")
    exhaustive_text = EXHAUSTIVE_PATH.read_text(encoding="utf-8")

    for job_name, job in ci["jobs"].items():
        rendered = _render(job)
        if job_name == "python-test":
            for test_file in EXHAUSTIVE_TESTS:
                assert f"--exclude {test_file}" in rendered
            continue
        for test_file in EXHAUSTIVE_TESTS:
            assert test_file not in rendered, job_name

    for test_file in EXHAUSTIVE_TESTS:
        assert test_file not in release_text
        assert exhaustive_text.count(test_file) == 1
    assert "telemetry-registry.yml" not in release_text
    assert "uses: ./.github/workflows/telemetry-registry.yml" not in CI_PATH.read_text(encoding="utf-8")

    broad_make = re.compile(r"(?:^|[\n;&])\s*make\s+(?:test|cli-test|cli-test-cov)(?=\s|$)")
    broad_cli_path = re.compile(r"(?<![\w/])cli(?:/tests/?)?(?=\s|\\|;|&|$)")
    explicit_test_file = re.compile(r"(?:^|\s)[^\s\\;&*]+\.py(?=\s|\\|;|&|$)")
    for workflow_name, workflow in (("CI", ci), ("Release", release)):
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                run = step.get("run", "")
                assert not broad_make.search(run), (workflow_name, job_name, run)
                if "pytest" not in run:
                    continue
                if job_name == "python-test":
                    assert '"${test_files[@]}"' in run
                    for test_file in EXHAUSTIVE_TESTS:
                        assert f"--exclude {test_file}" in run
                    continue
                assert '"${test_files[@]}"' not in run, (workflow_name, job_name)
                assert not broad_cli_path.search(run), (workflow_name, job_name, run)
                assert "cli/tests/*" not in run, (workflow_name, job_name, run)
                assert explicit_test_file.search(run), (workflow_name, job_name, run)
