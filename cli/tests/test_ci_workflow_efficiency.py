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

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ci_shards_python_once_and_does_not_repeat_unified_corpus() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    exhaustive = (ROOT / ".github/workflows/telemetry-registry.yml").read_text(encoding="utf-8")

    assert "name: Python Test (shard ${{ matrix.shard }})" in workflow
    assert "shard: [0, 1, 2, 3, 4, 5, 6, 7]" in workflow
    assert "PYTHON_TEST_SHARDS: 8" in workflow
    assert "python3 scripts/python_test_shards.py" in workflow
    assert "--timings scripts/test-timings/python-linux.json" in workflow
    assert (ROOT / "scripts/test-timings/python-linux.json").is_file()
    for isolated in (
        "cli/tests/test_telemetry_registry_generator.py",
        "cli/tests/test_telemetry_registry_candidate_renderer.py",
    ):
        assert workflow.count(f"--exclude {isolated}") == 1
        assert exhaustive.count(f"test_file: {isolated}") == 1
    assert "name: Python Telemetry Test (${{ matrix.suite }})" not in workflow
    assert "--numprocesses=4" in exhaustive
    assert "--dist=worksteal" in exhaustive
    assert "name: Python Lint" in workflow
    assert "name: Python Lint & Test" in workflow
    assert "needs: [changes, python-test, python-lint]" in workflow
    assert workflow.count("run: make py-lint") == 1
    assert "pattern: python-coverage-part-*" in workflow
    assert 'test "${#coverage_parts[@]}" -eq 8' in workflow
    assert ".venv/bin/coverage combine" in workflow
    assert "run: make test" not in workflow

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert '"pytest-xdist==3.8.0"' in pyproject
    assert 'name = "pytest-xdist"' in lock


def test_windows_shards_never_carry_the_exhaustive_telemetry_suites() -> None:
    # A main run once put both mutation suites in one 16-minute Python shard;
    # they need about 45 serial minutes on a hosted Windows runner, so main
    # timed out (runs 40447361282, 41065202349). They get their own job.
    workflow_text = (ROOT / ".github/workflows/windows-native.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(workflow_text)["jobs"]
    exhaustive_files = (
        "cli/tests/test_telemetry_registry_generator.py",
        "cli/tests/test_telemetry_registry_candidate_renderer.py",
    )

    assert "WINDOWS_TELEMETRY_REGISTRY_MODE" not in workflow_text
    assert "$fullTelemetryRegistry" not in workflow_text

    shard_job = jobs["windows-python"]
    assert "env" not in shard_job or "WINDOWS_TELEMETRY_REGISTRY_MODE" not in shard_job["env"]
    shard_step = next(step for step in shard_job["steps"] if "python_test_shards.py" in step.get("run", ""))
    shard_run = shard_step["run"]
    assert "'scripts/python_test_shards.py', '--shard-count', '12'" in shard_run
    for test_file in exhaustive_files:
        assert f"'{test_file}'" in shard_run
    # Every run excludes both modules; no event re-admits them.
    exclude_loop = (
        "\nforeach ($telemetryFile in $exhaustiveTelemetryFiles) {\n"
        "  $shardSelectionArgs += @('--exclude', $telemetryFile)\n"
        "}\n"
    )
    assert exclude_loop in shard_run
    assert shard_run.count("$shardSelectionArgs += @('--exclude'") == 1
    # The native Windows updater paths stay on every run, pull requests included.
    assert "if ($shardIndex -eq 2) {" in shard_run
    for native_test in (
        "test_updater_help_imports_on_native_platform",
        "test_updater_mid_publish_failure_restores_prior_bytes_and_inodes",
        "test_updater_windows_failure_after_replace_restores_prior_file",
        "test_updater_post_commit_cleanup_fsync_failure_reports_live_commit",
        "test_updater_namespace_swap_cannot_publish_through_detached_parent",
        "test_updater_transaction_bootstrap_failure_removes_exact_created_inode",
    ):
        assert f"'cli/tests/test_telemetry_registry_generator.py::{native_test}'" in shard_run
    assert "$nativeTelemetryPytestArgs" in shard_run

    telemetry_job = jobs["windows-telemetry-registry"]
    assert telemetry_job["needs"] == "changes"
    assert telemetry_job["if"] == (
        "${{ !cancelled() && github.event_name != 'pull_request' && needs.changes.outputs.windows_python != 'false' }}"
    )
    assert telemetry_job["runs-on"] == "windows-latest"
    assert sorted(case["test_file"] for case in telemetry_job["strategy"]["matrix"]["include"]) == sorted(
        exhaustive_files
    )
    assert telemetry_job["strategy"]["fail-fast"] is False
    run_step = next(step for step in telemetry_job["steps"] if "$telemetryPytestArgs" in step.get("run", ""))
    run = run_step["run"]
    assert "$env:TELEMETRY_TEST_FILE" in run
    assert "'--numprocesses=4', '--dist=worksteal'" in run
    pytest_timeout = int(re.search(r"-TimeoutSeconds (\d+)", run).group(1))
    assert pytest_timeout < int(telemetry_job["timeout-minutes"]) * 60
    assert "windows-telemetry-registry" in jobs["windows-native-required"]["needs"]


def test_ci_preserves_make_test_context_without_repeating_test_work() -> None:
    workflow_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(workflow_text)["jobs"]

    aggregate = jobs["make-test"]
    assert aggregate["name"] == "make test (unified)"
    assert aggregate["needs"] == ["go-test", "python-lint-test"]
    assert aggregate["if"] == "${{ always() }}"
    assert aggregate["runs-on"] == "ubuntu-latest"
    assert len(aggregate["steps"]) == 1
    step = aggregate["steps"][0]
    assert set(step) == {"name", "env", "run"}
    assert step["name"] == "Require unified Go and Python test gates"
    assert step["env"] == {
        "GO_TEST_RESULT": "${{ needs.go-test.result }}",
        "PYTHON_TEST_RESULT": "${{ needs.python-lint-test.result }}",
    }
    assert step["run"].splitlines() == [
        "set -euo pipefail",
        'test "$GO_TEST_RESULT" = success',
        'test "$PYTHON_TEST_RESULT" = success',
    ]

    run_steps = [step["run"] for job in jobs.values() for step in job.get("steps", []) if "run" in step]
    assert all("make test" not in run for run in run_steps)


def test_ci_shards_slow_gateway_package_and_combines_go_coverage() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "name: Go Gateway Test (shard ${{ matrix.shard }})" in workflow
    assert "python3 scripts/go_test_shards.py" in workflow
    assert "name: Go Audit Test (shard ${{ matrix.shard }})" in workflow
    assert "--package-dir internal/audit" in workflow
    assert "name: Go Test (remaining packages / shard ${{ matrix.shard }})" in workflow
    assert "GO_PACKAGE_SHARD: ${{ matrix.shard }}" in workflow
    assert "GO_PACKAGE_SHARDS: 12" in workflow
    assert "GO_TEST_SHARDS: 24" in workflow
    assert "--exclude github.com/defenseclaw/defenseclaw/internal/audit" in workflow
    assert "--exclude github.com/defenseclaw/defenseclaw/internal/gateway" in workflow
    assert workflow.count("--timings scripts/test-timings/go-linux.json") == 3
    # 24 gateway + 4 audit + 12 remaining-package shards, one profile each.
    assert 'test "${#coverage_parts[@]}" -eq 40' in workflow
    # checkptr in the transpiled SQLite doubled the cost of every race shard.
    # A hang fails at go test's -timeout, well inside the job's budget, and
    # go_test_report.py names the test still running.
    race = "go test -json -race -gcflags=modernc.org/...=-d=checkptr=0 -count=1 -timeout 11m "
    assert workflow.count("go test -race") == 0
    assert workflow.count(race) == 3
    # The three Linux race jobs and the darwin connector parts.
    assert workflow.count("python3 scripts/go_test_report.py --timings") == 4
    assert workflow.count("label: macos-latest darwin connector ") == 4
    assert "--timings scripts/test-timings/go-darwin.json \\\n            --shard-count 4 \\" in workflow
    assert "name: go-test-timings-darwin-connector-${{ matrix.shard }}" in workflow
    assert "DC_TEST_NATIVE_GATEWAY" in workflow
    assert "needs: [changes, go-test-gateway, go-test-audit, go-test-other, go-pinned]" in workflow
    assert 'test "$AUDIT_RESULT" = success' in workflow
    assert "python3 scripts/merge_go_coverage.py" in workflow
    assert "go tool cover -func=coverage.out" in workflow
    assert "run: make go-test-cov" not in workflow

    sharder = (ROOT / "scripts/go_test_shards.py").read_text(encoding="utf-8")
    assert "Test|Fuzz|Example" in sharder


def test_release_validates_reviewed_macos_pin_without_freshness_block() -> None:
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")

    assert "python3 scripts/check-macos-upstream.py --offline" in workflow
    assert "Require latest stable macOS app source" not in workflow


def test_release_dispatch_version_is_stamped_without_a_version_only_pr() -> None:
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")

    assert workflow.count('scripts/stamp-version.sh "$VERSION"') >= 2
    first_stamp = workflow.index('scripts/stamp-version.sh "$VERSION"')
    identity_check = workflow.index("python3 scripts/source_release_identity.py check", first_stamp)
    extension_build = workflow.index("make extensions", identity_check)
    gateway_build = workflow.index("- name: Build gateway archives and SBOMs", extension_build)
    assert first_stamp < identity_check < extension_build < gateway_build

    macos_build = (ROOT / "scripts/build-macos-app-release.sh").read_text(encoding="utf-8")
    assert 'MARKETING_VERSION="${VERSION}"' in macos_build


def test_windows_standalone_setup_jobs_install_uv_first() -> None:
    # build-setup.sh builds the Python scanner runtime with uv (GAP-0132).
    for name in ("ci.yml", "release.yaml"):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))
        for job_id, job in workflow["jobs"].items():
            steps = [str(step.get("uses", "")) + str(step.get("run", "")) for step in job.get("steps", [])]
            builds = [i for i, step in enumerate(steps) if "standalone/build-setup.sh" in step]
            uv = [i for i, step in enumerate(steps) if step.startswith("astral-sh/setup-uv@")]
            assert not builds or (uv and uv[0] < builds[0]), f"{name}:{job_id} runs build-setup.sh without setup-uv"


def test_make_gateway_test_runs_the_gateway_race_suite_only_as_bounded_shards() -> None:
    # Race-enabled, ./internal/gateway runs for well over an hour as one test
    # binary, so a single-process run reaches any gate timeout while its
    # tests are still running (r103 GAP-0267). The canonical local gate runs
    # it only as timing-balanced shards, each with its own deadline.
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile[makefile.index("\ngateway-test:") :]
    target = target[: target.index("\n\n")]
    gateway_runs = [line for line in target.splitlines() if "./internal/gateway" in line]
    assert gateway_runs and all("-timeout $(GO_TEST_TIMEOUT)" in line for line in gateway_runs)
    assert "$(GO_SHARD_RUN) --package-dir internal/gateway --" in target
    assert "GO_SHARD_RUN = $(HOST_PYTHON) scripts/go_test_shards.py" in makefile


def _pull_request_jobs():
    for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        triggers = workflow.get(True) or workflow.get("on") or {}
        if "pull_request" not in triggers:
            continue
        for job_id, job in workflow["jobs"].items():
            yield path.name, job_id, job


# Jobs that never run on a pull request (they need a live agent login or a
# self-hosted runner) keep the longer budget of their live sessions.
LIVE_ONLY_JOBS = {
    ("connector-live-e2e.yml", "live-matrix"),
    ("connector-live-e2e.yml", "windows-live"),
    ("connector-live-e2e.yml", "windows-copilot-live"),
    ("connector-live-e2e.yml", "windows-antigravity-live"),
    ("connector-live-e2e.yml", "windows-antigravity-held-state"),
}


def test_every_pull_request_job_has_a_twenty_minute_budget() -> None:
    # A hung test or lane fails within the pull request's 20-minute budget
    # instead of holding the PR for the default six hours.
    for name, job_id, job in _pull_request_jobs():
        if (name, job_id) in LIVE_ONLY_JOBS:
            continue
        budget = job.get("timeout-minutes")
        assert isinstance(budget, int), f"{name}:{job_id} has no timeout-minutes"
        assert budget <= 20, f"{name}:{job_id} timeout-minutes {budget} is over 20"


def test_go_test_timeouts_stay_inside_the_job_budget() -> None:
    # go test's own -timeout must fire before the job's timeout-minutes so a
    # hung test prints Go's goroutine dump (the 1.0.4 gateway shard that hung
    # was cancelled by the job at 50 minutes, before go test's 45m).
    for name in ("ci.yml", "windows-native.yml"):
        text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        for minutes in re.findall(r"-timeout[ =](\d+)m", text):
            assert int(minutes) <= 14, f"{name}: go test -timeout {minutes}m leaves no room in a 20-minute job"


def test_every_go_cache_save_writes_the_entry_its_job_restores() -> None:
    # A job with its own Go cache entry (a release cross-compile) must save
    # under that entry; saving under "shared" would leave its own entry
    # unwritten and fill the test jobs' entry with an unrelated build.
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (workflow.get("jobs") or {}).items():
            steps = job.get("steps") or []
            restores = [s.get("with") or {} for s in steps if s.get("uses") == "./.github/actions/setup-go"]
            saves = [s.get("with") or {} for s in steps if s.get("uses") == "./.github/actions/go-cache-save"]
            for save in saves:
                assert len(restores) == 1, f"{path.name}:{job_id} saves a Go cache it does not restore once"
                for key, default in (("cache-name", "shared"), ("cache-files", "")):
                    restored, saved = restores[0].get(key, default), save.get(key, default)
                    assert saved == restored, (
                        f"{path.name}:{job_id} restores {key}={restored!r} but saves {key}={saved!r}"
                    )
