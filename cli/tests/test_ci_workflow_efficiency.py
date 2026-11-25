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

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
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
    assert "'scripts/python_test_shards.py', '--shard-count', '18'" in shard_run
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


def test_ci_shards_slow_gateway_package_and_combines_go_coverage(tmp_path, capsys) -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "name: Go Gateway Test (shard ${{ matrix.shard }})" in workflow
    assert "python3 scripts/go_test_shards.py" in workflow
    assert "name: Go Audit Test (shard ${{ matrix.shard }})" in workflow
    assert "--package-dir internal/audit" in workflow
    assert "name: Go Test (remaining packages / shard ${{ matrix.shard }})" in workflow
    assert "GO_PACKAGE_SHARD: ${{ matrix.shard }}" in workflow
    assert "GO_PACKAGE_SHARDS: 32" in workflow
    assert "GO_TEST_SHARDS: 140" in workflow
    assert "--exclude github.com/defenseclaw/defenseclaw/internal/audit" in workflow
    assert "--exclude github.com/defenseclaw/defenseclaw/internal/gateway" in workflow
    # The three Linux jobs, the Go Pinned Tests shards, and the six darwin
    # gateway parts, which weigh the unix and darwin tests by their macOS
    # times once go-darwin.json records internal/gateway and by their Linux
    # times until then.
    assert workflow.count("--timings scripts/test-timings/go-linux.json") == 5
    jobs = yaml.safe_load(workflow)["jobs"]
    parts = jobs["darwin-gateway"]["strategy"]["matrix"]["include"]
    assert parts == [{"part": shard + 1, "shard": shard} for shard in range(6)]
    assert '--shard-count 6 \\\n            --shard-index "$GO_TEST_SHARD")"' in workflow
    assert (
        "--timings scripts/test-timings/go-darwin.json \\\n            --timings scripts/test-timings/go-linux.json \\"
        in workflow
    )
    # One coverage profile per gateway, audit and remaining-package shard: the
    # count Combine Go coverage requires follows the shard counts (it stayed 52
    # when the remaining packages went from 12 to 16 shards and would have
    # failed the first run on which every shard passed).
    profiles = sum(
        len(jobs[name]["strategy"]["matrix"]["shard"]) for name in ("go-test-gateway", "go-test-audit", "go-test-other")
    )
    assert profiles == 177
    # The frozen-gateway job adds one more profile (it runs the three tests
    # that no longer run in the shards).
    profiles += 1
    assert f'test "${{#coverage_parts[@]}}" -eq {profiles}' in workflow
    # checkptr in the transpiled SQLite doubled the cost of every race shard.
    # A hang fails at go test's -timeout, well inside the job's budget, and
    # go_test_report.py names the test still running.
    race = "go test -json -race -gcflags=modernc.org/...=-d=checkptr=0 -count=1 -timeout 11m "
    assert workflow.count("go test -race") == 0
    assert workflow.count(race) == 0
    # A gateway and an audit shard's -timeout follow their planned seconds
    # (go_test_shards.py --timeout, test_linux_gateway_shard_timeouts_fit_the_job;
    # the audit shards had a flat 11m until rel-1-0-10:GAP-1216).
    planned = 'go test -json -race -gcflags=modernc.org/...=-d=checkptr=0 -count=1 -timeout "$test_timeout" '
    assert workflow.count(planned) == 2
    assert workflow.count('test_timeout="$("${plan[@]}" --timeout)"') == 2
    # The remaining-package shards run several go test runs in one step: they
    # share one deadline inside the step budget, and each run is stopped at
    # most 11 minutes in or when the deadline is up, whichever comes first.
    shared = 'go test -json -race -gcflags=modernc.org/...=-d=checkptr=0 -count=1 -timeout "$limit" '
    assert workflow.count(shared) == 1
    assert "deadline=$((SECONDS + 960))" in workflow
    assert 'echo "$((left < 660 ? left : 660))s"' in workflow
    # The three Linux race jobs, the darwin connector parts and the darwin
    # gateway parts.
    assert workflow.count("python3 scripts/go_test_report.py --timings") == 5
    assert workflow.count("label: macos-latest darwin connector ") == 4
    assert "--timings scripts/test-timings/go-darwin.json \\\n            --shard-count 4 \\" in workflow
    assert "name: go-test-timings-darwin-connector-${{ matrix.shard }}" in workflow
    assert "name: go-test-timings-darwin-gateway-${{ matrix.shard }}" in workflow
    # The darwin gateway parts share one test binary, cross-compiled on the
    # 16 GB Linux runner (the 8 GB compile ran paced for 26.6 minutes on the
    # 7 GB macOS runner, CI run 44948629340) with CGO_ENABLED=0, as release
    # builds darwin. go test -c runs go test's vet checks for the whole
    # package once; every part runs the binary through test2json the way go
    # test -json runs it, and keeps the check name of its old Unix Standalone
    # Lifecycle part.
    build = jobs["darwin-gateway-test-binary"]
    assert build["runs-on"] == "ubuntu-latest"
    step = next(s for s in build["steps"] if s.get("name") == "Build the internal/gateway test binary")
    assert step["env"] == {"CGO_ENABLED": "0", "GOOS": "darwin", "GOARCH": "arm64"}
    assert 'go test -c -o "$RUNNER_TEMP/gateway-test/gateway.test" ./internal/gateway' in step["run"]
    assert "-vet=off" not in step["run"]
    assert "GOMEMLIMIT" not in str(build)
    # Compiled from the macOS checkout path (the tests read repository files
    # from their runtime.Caller source paths); each part checks that path.
    mac_workspace = 'mac_workspace="/Users/runner/work/${GITHUB_REPOSITORY#*/}/${GITHUB_REPOSITORY#*/}"'
    assert mac_workspace in step["run"]
    assert 'sudo mount --bind "$GITHUB_WORKSPACE" "$mac_workspace"' in step["run"]
    gateway_parts = jobs["darwin-gateway"]
    assert gateway_parts["name"] == "Unix Standalone Lifecycle (macos-latest darwin gateway ${{ matrix.part }} of 6)"
    assert "darwin-gateway-test-binary" in gateway_parts["needs"]
    assert "needs.darwin-gateway-test-binary.result == 'success'" in gateway_parts["if"]
    run = next(s["run"] for s in gateway_parts["steps"] if "test2json" in s.get("run", ""))
    assert mac_workspace in run and 'if [ "$GITHUB_WORKSPACE" != "$mac_workspace" ]; then' in run
    assert '(cd "$pkg" && go tool test2json -t -p "github.com/defenseclaw/defenseclaw/$pkg"' in run
    assert '"$RUNNER_TEMP/gateway.test" -test.paniconexit0 -test.v=test2json -test.count=1' in run
    assert '-test.timeout=10m -test.run="$pattern"' in run
    # A part, and the darwin cli and hookcli step, fail when a selected test
    # reported no result (rel-1-0-10:GAP-1051): a -run name the binary does
    # not have runs nothing and passes.
    assert '--annotate "darwin gateway part $GO_TEST_SHARD failed" --expect-run "$pattern"' in run
    assert 'exit "${statuses[1]}"' in run
    unix_step = next(
        s["run"]
        for s in jobs["unix-standalone-lifecycle"]["steps"]
        if s.get("name") == "Go tests of the darwin paths in the CLI and hookcli packages"
    )
    assert '--annotate "darwin $UNIX_PACKAGE failed" --expect-run "$pattern"' in unix_step
    assert 'exit "${statuses[1]}"' in unix_step
    upload = next(s for s in build["steps"] if s.get("with", {}).get("name") == "darwin-gateway-test-binary")
    assert upload["with"]["retention-days"] == 7
    assert "go test" not in run.replace("go test -json", "")
    assert not any(
        "internal/gateway" == entry.get("package")
        for entry in jobs["unix-standalone-lifecycle"]["strategy"]["matrix"]["include"]
    )
    required = jobs["enterprise-required"]
    assert {"darwin-gateway-test-binary", "darwin-gateway"} <= set(required["needs"])
    assert "UNIX_LIFECYCLE DARWIN_GATEWAY_BINARY DARWIN_GATEWAY; do" in workflow
    assert "DC_TEST_NATIVE_GATEWAY" in workflow
    needs = "needs: [changes, go-test-gateway, go-test-audit, go-test-other, go-test-throughput, go-test-frozen-gateway, go-pinned]"
    assert needs in workflow
    # The frozen-gateway tests run alone in their own required job.
    assert 'test "$FROZEN_GATEWAY_RESULT" = success' in workflow
    frozen = jobs["go-test-frozen-gateway"]
    # It is selected by the classifier exactly as the other Go jobs are: a
    # string compared with a boolean is always unequal in a workflow
    # expression, which ran the job on pull requests that selected no Go.
    assert frozen["if"] == jobs["go-test-audit"]["if"]
    frozen_run = next(
        step["run"] for step in frozen["steps"] if step.get("name") == "Run the frozen-gateway tests alone"
    )
    # The two tests that ran in the remaining-package shard keep its race
    # detector and coverage profile; the parallel test runs without the race
    # detector; the profiles reach the combined one as a single part.
    assert "go test -v -race -gcflags=modernc.org/...=-d=checkptr=0 -p 1 -count=1" in frozen_run
    assert "go test -v -covermode=atomic -p 1 -count=1" in frozen_run
    assert "-coverprofile=coverage-go-frozen-gateway-race.out" in frozen_run
    assert "-coverprofile=coverage-go-frozen-gateway-parallel.out" in frozen_run
    assert "--output coverage-go-frozen-gateway.out" in frozen_run
    upload = next(step for step in frozen["steps"] if str(step.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "go-coverage-frozen-gateway"
    assert upload["with"]["path"] == "coverage-go-frozen-gateway.out"
    # ...and the classifier's answer for a workflow-only change is the string
    # 'false' the condition compares with, and 'true' for a Go change.
    spec = importlib.util.spec_from_file_location("ci_changes", ROOT / "scripts" / "ci_changes.py")
    ci_changes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ci_changes)
    for path, expected in (
        (".github/workflows/ci.yml", "false"),
        ("internal/gateway/connector/hookexec/hookexec.go", "true"),
    ):
        files = tmp_path / "files.txt"
        files.write_text(path + "\n", encoding="utf-8")
        assert ci_changes.main(["--event", "pull_request", "--files-from", str(files), "--get", "go"]) == 0
        assert capsys.readouterr().out.strip() == expected
    assert 'test "$AUDIT_RESULT" = success' in workflow
    assert "THROUGHPUT_RESULT" in workflow
    assert "go test -p 1 -count=1 -timeout 4m -v -run " in workflow
    assert "Go Throughput Test (no race)" in workflow
    assert "python3 scripts/merge_go_coverage.py" in workflow
    assert "go tool cover -func=coverage.out" in workflow
    assert "run: make go-test-cov" not in workflow

    sharder = (ROOT / "scripts/go_test_shards.py").read_text(encoding="utf-8")
    assert "Test|Fuzz|Example" in sharder


def _pinned_step(jobs: dict) -> str:
    job = jobs["go-pinned"]
    assert job["strategy"]["matrix"]["shard"] == list(range(8))
    step = next(
        step for step in job["steps"] if step.get("name") == "Run this shard of the Go tests that name a changed file"
    )
    assert step["env"]["PINNED_SHARDS"] == 8
    assert step["env"]["PINNED_SHARD"] == "${{ matrix.shard }}"
    return step["run"]


def _bash_major_version() -> int:
    # `mapfile` needs Bash 4+; macOS ships Bash 3.2 as /bin/bash. CI runs the
    # pinned script on ubuntu (Bash 5), so the test only skips on old shells.
    try:
        out = subprocess.run(
            ["bash", "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, check=True, timeout=30
        ).stdout.strip()
        return int(out)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


@pytest.mark.skipif(sys.platform == "win32", reason="the Go Pinned Tests job runs this bash script on ubuntu")
@pytest.mark.skipif(
    sys.platform != "win32" and _bash_major_version() < 4,
    reason="the pinned script uses mapfile, which needs Bash 4+ (macOS system bash is 3.2); the ubuntu CI job runs it",
)
def test_go_pinned_tests_run_every_selected_test_once_over_the_shards(tmp_path) -> None:
    # A README.md edit pins 490 internal/gateway tests: one go test process
    # ran them for 840 s and hit the 14m -timeout (#1489). The shards must
    # still run every selected test exactly once: a large target split by
    # go_test_shards.py --match, a small one (or one the script cannot split)
    # whole in one shard.
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    run = _pinned_step(yaml.safe_load(workflow)["jobs"])
    go_test = 'go test -count=1 -timeout 14m -run "$regex" "$package" || status=1'
    assert run.count(go_test) == 1
    record = tmp_path / "runs.tsv"
    script = tmp_path / "pinned.sh"
    script.write_text(run.replace(go_test, f'printf "%s\\t%s\\n" "$package" "$regex" >> "{record}"'), encoding="utf-8")
    shards = importlib.util.spec_from_file_location("go_test_shards", ROOT / "scripts/go_test_shards.py")
    module = importlib.util.module_from_spec(shards)
    assert shards.loader is not None
    shards.loader.exec_module(module)
    gateway = sorted({name for _, names in module.discover_test_files(ROOT / "internal/gateway") for name in names})
    picked = gateway[::4]
    targets = [
        {"package": "./internal/gateway", "run": "^(" + "|".join(picked) + ")$"},
        {"package": "./internal/hookpaths", "run": "^(TestA|TestB)$"},
        {"package": "./internal/flow", "run": "."},
    ]
    env = {"GO_TESTS": json.dumps(targets), "PINNED_SHARDS": "8", "PATH": os.environ["PATH"]}
    for shard in range(8):
        subprocess.run(["bash", str(script)], cwd=ROOT, env={**env, "PINNED_SHARD": str(shard)}, check=True)
    lines = [line.split("\t") for line in record.read_text(encoding="utf-8").splitlines()]
    gateway_regexes = [regex for package, regex in lines if package == "./internal/gateway"]
    assert len(gateway_regexes) >= 8
    ran = [name for regex in gateway_regexes for name in gateway if re.search(regex, name)]
    assert sorted(ran) == picked
    assert [regex for package, regex in lines if package != "./internal/gateway"] == ["^(TestA|TestB)$", "."]


def test_go_lint_restores_the_pinned_golangci_lint_and_only_main_saves_it() -> None:
    # Go Lint (golangci-lint) keeps the Makefile's pinned golangci-lint and
    # its recipe (make go-lint-analyzers); the binary and the analysis cache
    # come from main's latest entry, and a pull request never writes one.
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    steps = yaml.safe_load(workflow)["jobs"]["go-lint-analyzers"]["steps"]
    lint = next(step for step in steps if step.get("name") == "Go lint (golangci-lint on changed lines)")
    assert 'make go-lint-analyzers GOLANGCI_LINT="$bin"' in lint["run"]
    assert '"$bin" version 2>/dev/null | grep -qF " ${GOLANGCI_VERSION#v} "' in lint["run"]
    assert "sed -n 's/^GOLANGCI_LINT_VERSION := //p' Makefile" in workflow
    saves = [step for step in steps if str(step.get("uses", "")).startswith("actions/cache/save@")]
    assert len(saves) == 1
    assert "github.ref == 'refs/heads/main'" in saves[0]["if"]
    assert "github.event_name == 'push'" in saves[0]["if"]


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
}


def test_every_pull_request_job_has_a_twenty_minute_budget() -> None:
    # A hung test or lane fails within the pull request's 20-minute budget
    # instead of holding the PR for the default six hours. No job has an
    # exception: Go Lint runs go vet and golangci-lint as two jobs, and the
    # Windows enterprise lanes run in parts.
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
    # The Linux gateway shards take their -timeout from the plan, at most
    # TIMEOUT_CAP_SECONDS; with the slowest set-up measured on 11-13 (377 s:
    # checkout, Go cache, plugin build, race compile) and a minute for the
    # artifact uploads, the job ends inside its timeout-minutes.
    spec = importlib.util.spec_from_file_location("go_test_shards", ROOT / "scripts/go_test_shards.py")
    shards = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shards)
    job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]["go-test-gateway"]
    assert shards.TIMEOUT_CAP_SECONDS + 377 + 60 <= job["timeout-minutes"] * 60


def test_pull_request_workflows_use_no_actions_setup_go_cache() -> None:
    # actions/setup-go's own cache saves an entry per branch (520-700 MB
    # each, the repository's cache quota). In a pull request's scope a small
    # one was restored before main's shared Go cache (PR #1456: every macOS
    # job compiled cold). Pull request jobs use ./.github/actions/setup-go or
    # set cache: false.
    for name, job_id, job in _pull_request_jobs():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/setup-go@"):
                assert (step.get("with") or {}).get("cache") is False, (
                    f"{name}:{job_id} uses the actions/setup-go cache"
                )


def test_the_shared_go_cache_restores_only_its_own_entries() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/setup-go/action.yml").read_text(encoding="utf-8"))
    restore = next(step for step in action["runs"]["steps"] if step.get("id") == "restore")
    assert restore["with"]["restore-keys"].strip().splitlines() == ["${{ steps.paths.outputs.prefix }}"]


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


@pytest.mark.skipif(sys.platform == "win32", reason="the macOS jobs run this bash script")
def test_go_unix_test_pattern_selects_the_unix_and_darwin_tests() -> None:
    def names(path: Path) -> set[str]:
        return set(re.findall(r"^func (Test\w+)\(t \*testing\.T\)", path.read_text(encoding="utf-8"), re.M))

    script = ["bash", "scripts/go-unix-test-pattern.sh"]
    out = subprocess.run([*script, "internal/gateway"], cwd=ROOT, check=True, capture_output=True, text=True)
    pattern = out.stdout.strip()
    assert pattern.startswith("^(") and pattern.endswith(")$")
    selected = set(pattern[2:-2].split("|"))
    gateway = ROOT / "internal/gateway"
    darwin = set().union(*(names(path) for path in gateway.glob("*_darwin_test.go")))
    assert darwin and darwin <= selected
    # The open-loop throughput tests run alone in Go Throughput Test.
    open_loop = names(gateway / "gap0490_open_loop_test.go")
    assert open_loop and not open_loop & selected
    assert subprocess.run([*script], cwd=ROOT, capture_output=True).returncode == 2


def test_connector_matrix_runs_the_gateway_matrix_tests_in_guarded_parts() -> None:
    # Connector Matrix (packages and CLI) ran the internal/gateway matrix tests
    # beside cli, config and e2e: 950 s of its 1,200 s, cancelled when a
    # checkout took 308 s (PR #1456). They run in four guarded parts.
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = yaml.safe_load(workflow)["jobs"]["connector-matrix"]
    include = job["strategy"]["matrix"]["include"]
    assert include[0] == {"part": "packages", "label": "packages and CLI"}
    assert include[1:5] == [{"part": f"gateway-{i}", "label": f"gateway {i + 1} of 4"} for i in range(4)]
    assert [entry["part"] for entry in include[5:]] == ["0", "1", "2", "3"]
    run = next(step["run"] for step in job["steps"] if "connector-matrix-test" in step.get("run", ""))
    assert "CONNECTOR_MATRIX_GATEWAY_PARTS=4" in run
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    packages = makefile.split("else ifeq ($(CONNECTOR_MATRIX_PART),packages)", 1)[1].split("else ifneq", 1)[0]
    assert "./internal/gateway" not in packages
    assert "--package-dir internal/gateway --built-files" in makefile
    assert '--expect-run "$$run"' in makefile
    # The connector parts carry the same run-count guard: a selected test
    # that never ran (a name this GOOS does not build) failed nothing before
    # (GAP-1054, the GAP-1051 class).
    recipe = makefile.split("go-connector-matrix-test: sync-openclaw-extension", 1)[1].split("\nendif", 1)[0]
    connector = recipe.split("\nelse\n")[-1]
    assert "--package-dir internal/gateway/connector --built-files" in connector
    assert "go test -json" in connector
    assert '--expect-run "$$run"' in connector
    assert "go-connector-matrix-test: .SHELLFLAGS := -o pipefail -c" in makefile


# The Windows enterprise lanes run scripts/test-enterprise-windows-install.ps1
# in parts on fresh runners. Each part runs the lane's prelude (the preflight
# and the install, or the previous release's install and the upgrade), then a
# contiguous run of step groups (-Groups). These pin that the parts of a lane
# run every step of the lane exactly once, in the script's order.
WINDOWS_LANE = ROOT / "scripts/test-enterprise-windows-install.ps1"
WINDOWS_LANE_GROUPS = {
    "install": ["drift", "refusal", "operate", "reinstall"],
    "upgrade": ["drift", "refusal", "operate"],
}
WINDOWS_LANE_JOBS = {"enterprise-windows-install": "install", "enterprise-upgrade-windows": "upgrade"}


def _windows_lane_steps() -> list[tuple[str, str | None, str | None]]:
    """(title, group, prelude lane) of every Step in the script, in file order.

    group is None for a prelude step; the prelude lane is "upgrade" inside the
    top-level `if ($UpgradeFrom) {`, "install" in its `else {`, else None.
    """
    lines = WINDOWS_LANE.read_text(encoding="utf-8").splitlines()
    body = lines.index("try {")
    steps: list[tuple[str, str | None, str | None]] = []
    group = lane = None
    for line in lines[body + 1 : lines.index("catch {", body)]:
        opened = re.fullmatch(r"    if \(Test-StepGroup '(\w+)'\) \{", line)
        if opened:
            assert group is None and lane is None, line
            group = opened.group(1)
        elif line == "    if ($UpgradeFrom) {":
            assert group is None and lane is None, line
            lane = "upgrade"
        elif line == "    else {" and lane == "upgrade":
            lane = "install"
        elif line == "    }":
            group = None
            if lane == "install":
                lane = None
        step = re.fullmatch(r"\s+Step (['\"])(.+)\1", line)
        if step:
            steps.append((step.group(2), group, lane))
        else:
            assert not re.match(r"\s+Step\b", line), f"unparsed Step call: {line}"
    return steps


def _windows_lane_part(lane: str, groups: list[str]) -> list[str]:
    steps = _windows_lane_steps()
    prelude = [title for title, group, only in steps if group is None and only in (None, lane)]
    return prelude + [title for title, group, _ in steps if group in groups]


def test_windows_lane_script_runs_every_step_in_one_group_after_its_prelude() -> None:
    steps = _windows_lane_steps()
    text = WINDOWS_LANE.read_text(encoding="utf-8")
    # Every step after the first group is in a group; the groups are written
    # in their run order and each is one block.
    first = next(i for i, (_, group, _) in enumerate(steps) if group is not None)
    assert all(group is not None for _, group, _ in steps[first:])
    order = [group for _, group, _ in steps[first:]]
    assert list(dict.fromkeys(order)) == WINDOWS_LANE_GROUPS["install"]
    assert order == sorted(order, key=WINDOWS_LANE_GROUPS["install"].index)
    assert all(text.count(f"if (Test-StepGroup '{name}') {{") == 1 for name in WINDOWS_LANE_GROUPS["install"])
    prelude = [(title, lane) for title, group, lane in steps if group is None]
    assert [lane for _, lane in prelude] == [None, "upgrade", "upgrade", "upgrade", "install"], prelude
    assert prelude[0][0].startswith("preflight:")
    # Nothing was dropped when the steps moved into groups: the install lane
    # ran 17 steps and the upgrade lane 16 as one job.
    assert len(_windows_lane_part("install", WINDOWS_LANE_GROUPS["install"])) == 17
    assert len(_windows_lane_part("upgrade", WINDOWS_LANE_GROUPS["upgrade"])) == 16
    # The script takes only a contiguous, ordered run of its lane's groups.
    assert "[ValidateSet('drift', 'refusal', 'operate', 'reinstall')][string[]]$Groups = @()" in text
    assert "[string[]]$laneGroups = @('drift', 'refusal', 'operate')" in text
    assert "if (-not $UpgradeFrom) { $laneGroups += 'reinstall' }" in text
    assert "if ($Groups.Count -eq 0) { $Groups = $laneGroups }" in text
    assert "pass a contiguous run of" in text and "-Groups reinstall needs operate" in text


@pytest.mark.parametrize("job_id", sorted(WINDOWS_LANE_JOBS))
def test_windows_enterprise_lane_parts_run_every_step_once(job_id: str) -> None:
    lane = WINDOWS_LANE_JOBS[job_id]
    job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"][job_id]
    assert job["strategy"]["fail-fast"] is False
    legs = job["strategy"]["matrix"]["include"]
    assert len(legs) >= 2
    assert set(job["strategy"]["matrix"]) == {"include"}
    assert "${{ matrix.part }}" in job["name"]
    assert len({leg["part"] for leg in legs}) == len({leg["key"] for leg in legs}) == len(legs)
    # The legs' groups, in matrix order, are the lane's groups, each once.
    groups = [leg["groups"].split(" ") for leg in legs]
    assert [name for part in groups for name in part] == WINDOWS_LANE_GROUPS[lane]
    # So every step outside the prelude runs in exactly one leg, in order.
    full = _windows_lane_part(lane, WINDOWS_LANE_GROUPS[lane])
    prelude = _windows_lane_part(lane, [])
    ran = []
    for part in groups:
        steps = _windows_lane_part(lane, part)
        assert steps[: len(prelude)] == prelude
        assert len(steps) > len(prelude), part
        ran += steps[len(prelude) :]
    assert ran == full[len(prelude) :]
    lanes = [step for step in job["steps"] if "test-enterprise-windows-install.ps1" in str(step.get("run", ""))]
    assert len(lanes) == 1
    assert lanes[0]["env"]["LANE_GROUPS"] == "${{ matrix.groups }}"
    assert "-Groups ($env:LANE_GROUPS -split ' ')" in lanes[0]["run"]
    assert ("-UpgradeFrom" in lanes[0]["run"]) is (lane == "upgrade")
    uploads = [step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert uploads and all("${{ matrix.key }}" in step["with"]["name"] for step in uploads)
