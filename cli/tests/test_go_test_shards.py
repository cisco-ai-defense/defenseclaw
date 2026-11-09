# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from scripts.go_test_shards import (
    check_exact_cover,
    discover_test_files,
    match_test_files,
    partition_packages,
    partition_test_files,
    regex_names,
    run_shards,
)


def test_go_test_file_shards_are_deterministic_and_exhaustive(tmp_path: Path) -> None:
    (tmp_path / "small_test.go").write_text(
        "package sample\nfunc TestSmall(t *testing.T) {}\nfunc FuzzInput(f *testing.F) {}\nfunc ExampleSmall() {}\n",
        encoding="utf-8",
    )
    (tmp_path / "large_test.go").write_text(
        "package sample\nfunc TestLargeA(t *testing.T) {}\nfunc TestLargeB(t *testing.T) {}\n" + ("// weight\n" * 50),
        encoding="utf-8",
    )

    files = discover_test_files(tmp_path)
    first = partition_test_files(files, 2)
    second = partition_test_files(files, 2)

    assert first == second
    assert sorted(name for shard in first for name in shard) == [
        "ExampleSmall",
        "FuzzInput",
        "TestLargeA",
        "TestLargeB",
        "TestSmall",
    ]
    assert set(first[0]).isdisjoint(first[1])
    assert {"TestLargeA", "TestLargeB"} in (set(first[0]), set(first[1]))


def test_go_test_shards_reject_invalid_count() -> None:
    with pytest.raises(ValueError, match="positive"):
        partition_test_files([], 0)
    with pytest.raises(ValueError, match="cannot exceed"):
        partition_test_files([], 1)


def test_run_shards_runs_every_shard_with_its_regex_and_fails_on_any(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Local race targets run the gateway package as parallel shards because one
    # race-enabled binary outlives the 60m timeout; every shard must run with
    # its own -run regex, and one failing shard must fail the target.
    probe = (
        'import sys; args = sys.argv[1:]; print("shard", args[0], args[args.index("-run") + 1]);'
        ' sys.exit(3 if args[0] == "1" else 0)'
    )
    command = [sys.executable, "-c", probe, "{shard}"]

    assert run_shards([["TestA"], ["TestB", "TestC"]], command) == 1
    out = capsys.readouterr().out
    assert "shard 0 ^(?:TestA)$" in out
    assert "shard 1 ^(?:TestB|TestC)$" in out
    assert "--- shard 2/2 exit 3" in out
    assert run_shards([["TestA"]], command) == 0


def _write_package(root: Path) -> Path:
    package = root / "pkg"
    package.mkdir()
    (package / "heavy_test.go").write_text(
        "package pkg\nfunc TestHeavyA(t *testing.T) {}\nfunc TestHeavyB(t *testing.T) {}\n", encoding="utf-8"
    )
    (package / "light_test.go").write_text(
        "package pkg\nfunc TestLightA(t *testing.T) {}\nfunc TestLightB(t *testing.T) {}\n", encoding="utf-8"
    )
    (package / "new_test.go").write_text("package pkg\nfunc TestUnrecorded(t *testing.T) {}\n", encoding="utf-8")
    return package


def test_timed_shards_split_a_heavy_file_and_still_run_unrecorded_tests(tmp_path: Path) -> None:
    files = discover_test_files(_write_package(tmp_path))
    seconds = {"TestHeavyA": 100.0, "TestHeavyB": 100.0, "TestLightA": 1.0, "TestLightB": 1.0, "*": 0.5}

    shards = partition_test_files(files, 2, seconds)

    assert partition_test_files(files, 2, seconds) == shards
    names = [name for shard in shards for name in shard]
    assert sorted(names) == ["TestHeavyA", "TestHeavyB", "TestLightA", "TestLightB", "TestUnrecorded"]
    # The heavy file outweighs half a shard, so its two tests land apart.
    assert {"TestHeavyA", "TestHeavyB"} not in (set(shards[0]), set(shards[1]))
    assert check_exact_cover(shards, sorted(names)) == []


def test_split_tests_bounds_the_selector_even_when_a_file_has_many_fast_tests(tmp_path: Path) -> None:
    (tmp_path / "many_test.go").write_text(
        "package sample\n" + "".join(f"func TestFast{i}(t *testing.T) {{}}\n" for i in range(5)),
        encoding="utf-8",
    )
    for file_name, stem in (("heavy", "Heavy"), ("other", "Other")):
        (tmp_path / f"{file_name}_test.go").write_text(
            "package sample\n" + "".join(f"func Test{stem}{i}(t *testing.T) {{}}\n" for i in range(5)),
            encoding="utf-8",
        )
    files = discover_test_files(tmp_path)
    seconds = {"*": 1.0, **{f"Test{stem}{i}": 5.0 for stem in ("Heavy", "Other") for i in range(5)}}

    grouped = partition_test_files(files, 3, seconds)
    shards = partition_test_files(files, 3, seconds, split_tests=True)
    assert max(map(len, shards)) < max(map(len, grouped))
    assert sum(any(name.startswith("TestFast") for name in shard) for shard in shards) >= 2
    assert check_exact_cover(shards, [name for _, names in files for name in names]) == []
    one_file = [item for item in files if item[0].name == "many_test.go"]
    assert sorted(name for shard in partition_test_files(one_file, 2, seconds, split_tests=True) for name in shard) == [
        f"TestFast{i}" for i in range(5)
    ]
    with pytest.raises(ValueError, match="requires per-test timings"):
        partition_test_files(files, 3, split_tests=True)


def test_exact_cover_reports_missing_duplicate_and_unknown_items() -> None:
    problems = check_exact_cover([["A", "B"], ["B", "X"]], ["A", "B", "C"])

    assert "B is in 2 shards" in problems
    assert "C is in no shard" in problems
    assert "X was not discovered" in problems


def test_package_mode_splits_a_slow_package_and_covers_every_package_once(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/m\n", encoding="utf-8")
    _write_package(tmp_path)
    packages = ["example.com/m/pkg"] + [f"example.com/m/p{index}" for index in range(5)]
    timings = {
        "packages": {"example.com/m/pkg": 200.0, **{f"example.com/m/p{index}": 10.0 for index in range(4)}},
        "tests": {"pkg": {"TestHeavyA": 100.0, "TestHeavyB": 100.0, "*": 0.5}},
    }

    shards = partition_packages(packages, 3, timings, root=tmp_path)

    whole = sorted(package for shard in shards for package, regex in shard if not regex)
    parts = [regex_names(regex) for shard in shards for package, regex in shard if regex]
    # p4 has no recorded time and still runs.
    assert whole == [f"example.com/m/p{index}" for index in range(5)]
    assert len(parts) >= 2
    assert sorted(name for part in parts for name in part) == [
        "TestHeavyA",
        "TestHeavyB",
        "TestLightA",
        "TestLightB",
        "TestUnrecorded",
    ]


def test_linux_connector_parts_separate_the_ci_timeout_cluster() -> None:
    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-linux.json").read_text(encoding="utf-8"))
    connector = "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
    packages = sorted(
        set(timings["packages"])
        - {"github.com/defenseclaw/defenseclaw/internal/audit", "github.com/defenseclaw/defenseclaw/internal/gateway"}
    )
    shards = partition_packages(packages, 12, timings, root=root)
    parts = [regex_names(regex) for shard in shards for package, regex in shard if package == connector]
    assert parts

    # CI run 41444114280 timed out when these measured tests shared one
    # connector part. Their elapsed time alone exceeded most of its 11 minutes.
    observed_seconds = {
        "TestConnectorScopedHookReadFailureClearsGenericEnv": 149.5,
        "TestShellHookFailureRecordsNameTheOutcomeTheHookApplied": 103.3,
        "TestShellHookBlockSurvivesHostileEnvironments": 100.1,
        "TestShellHookLoweredBodyCapOnlyTightens": 73.8,
        "TestPerUserShellHookOutageOpenOnlyForAnOutage": 63.8,
        "TestPerUserShellHookOutageFollowsTheConfigNow": 44.2,
    }
    assert all(sum(observed_seconds.get(name, 0) for name in part) < 300 for part in parts)


def test_linux_remaining_package_shards_plan_inside_the_shared_deadline() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    shard_count = len(workflow["jobs"]["go-test-other"]["strategy"]["matrix"]["shard"])
    timings = json.loads((root / "scripts/test-timings/go-linux.json").read_text(encoding="utf-8"))
    prefix = "github.com/defenseclaw/defenseclaw/"
    packages = sorted(set(timings["packages"]) - {prefix + "internal/audit", prefix + "internal/gateway"})
    shards = partition_packages(packages, shard_count, timings, root=root)

    def planned(package: str, regex: str) -> float:
        if not regex:
            return float(timings["packages"][package])
        seconds = timings["tests"][package.removeprefix(prefix)]
        return sum(float(seconds.get(name, seconds["*"])) for name in regex_names(regex))

    # Run 42452817096: shard 9 held internal/cli (315 s) and a connector part
    # that its recorded times put at 308 s but that took 422 s and more, so the
    # part was stopped by the 16-minute shard deadline. The recorded times are
    # now the package wall times of that run. A shard step also spends time
    # building its race test binaries, which the recorded times leave out (402
    # s of package time took 540 s), so a shard plans at most 600 of the 960
    # seconds of the shared deadline.
    loads = [sum(planned(package, regex) for package, regex in shard) for shard in shards]
    assert max(loads) <= 600, loads


def test_connector_matrix_parts_balance_on_the_times_of_the_matrix_run() -> None:
    # The Connector Matrix job runs the connector package without -race, 4 parts
    # in a 20-minute job. Balanced on the -race times of go-linux.json, part 0
    # held most of the shell-hook tests and ran past the job limit while the other
    # parts ran 4 to 8 minutes (GAP-0834). The matrix has its own times, from a run of
    # the matrix tests in a 4-CPU Ubuntu 26.04 container.
    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-linux-connector-matrix.json").read_text(encoding="utf-8"))
    seconds = timings["tests"]["internal/gateway/connector"]
    pattern = "Connector|Hook|CodeGuard|Telemetry|OTLP|AgentHook|Mode|Setup|Teardown|Capability|Matrix"
    files = match_test_files(discover_test_files(root / "internal/gateway/connector"), pattern)
    parts = partition_test_files(files, 4, seconds)

    expected = sorted({name for _, names in files for name in names})
    assert check_exact_cover(parts, expected) == []
    default = seconds["*"]
    weights = [sum(seconds.get(name, default) for name in part) for part in parts]
    # The recorded run of the whole package is 1,413 s: each part is a quarter of
    # it (353 s) plus whatever the one test of 330 s forces; none may be near the
    # 840 s a part can use of the 14-minute go test limit.
    assert max(weights) < 1.25 * (sum(weights) / len(weights))
    assert max(weights) < 480


def test_linux_gateway_shards_separate_the_ci_timeout_cluster() -> None:
    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-linux.json").read_text(encoding="utf-8"))
    seconds = timings["tests"]["internal/gateway"]
    files = discover_test_files(root / "internal/gateway")
    shards = partition_test_files(files, 36, seconds)

    # These are top-level elapsed seconds from the red shard 20 CI artifact.
    # Unrecorded tests used to weigh 0.22 seconds and all landed with an
    # already slow test, exhausting the existing 11-minute Go test budget.
    observed = {
        "TestGAP0503HookToolRowsSurviveExpiredCompletionDuringFlood": 344.1,
        "TestGAP0503HandlerHeldSQLiteReportsDroppedToolRows": 22.8,
        "TestGAP0568ObserveOverBudgetStateWriteBlocks": 77.7,
        "TestOverLimitNativeWritesOfAuthorizedKeysAreBlockedOnTheHost": 80.3,
    }
    assert all(name in seconds for name in observed)
    holders = {name: next(i for i, shard in enumerate(shards) if name in shard) for name in observed}
    assert len(set(holders.values())) == len(observed)
    for index in holders.values():
        projected = sum(observed.get(name, float(seconds.get(name, seconds["*"]))) for name in shards[index])
        assert projected * 1.3 < 660, (index, projected)


def test_linux_gateway_cowork_corpus_replay_has_a_shard_of_its_own() -> None:
    root = Path(__file__).resolve().parents[2]
    seconds = json.loads((root / "scripts/test-timings/go-linux.json").read_text(encoding="utf-8"))["tests"][
        "internal/gateway"
    ]
    files = discover_test_files(root / "internal/gateway")
    shards = partition_test_files(files, 36, seconds)

    # The slowest top-level elapsed seconds from the rel/1.0.8 CI artifacts
    # after the Cowork merge (runs 41940219567 to 41962459501). Unrecorded,
    # the corpus replay weighed 0.21 seconds and joined a full shard 15,
    # which then ran 657 and 660 seconds into the 11-minute Go test budget.
    observed = {
        "TestCoworkShellReplaysTheToolCallCorpusWithBashVerdicts": 401.5,
        "TestRecoveredHookFailModeByDeployment": 94.9,
        "TestStrictInstallWindowGatesEveryRefusableInspectedCall": 43.7,
        "TestStrictTierBlocksAnsweredCallsDuringTheInstallWindow": 43.2,
        "TestGAP0563HookJudgeFallbackPersistsAfterEarlyTelemetry": 16.5,
    }
    assert all(name in seconds for name in observed)
    corpus = next(shard for shard in shards if "TestCoworkShellReplaysTheToolCallCorpusWithBashVerdicts" in shard)
    assert corpus == ["TestCoworkShellReplaysTheToolCallCorpusWithBashVerdicts"]
    assert observed["TestCoworkShellReplaysTheToolCallCorpusWithBashVerdicts"] * 1.3 < 660


def test_linux_gateway_shards_keep_ordinary_tests_covered() -> None:
    root = Path(__file__).resolve().parents[2]
    seconds = json.loads((root / "scripts/test-timings/go-linux.json").read_text(encoding="utf-8"))["tests"][
        "internal/gateway"
    ]
    files = discover_test_files(root / "internal/gateway")
    shards = partition_test_files(files, 36, seconds)
    names = [name for _, file_names in files for name in file_names]
    assert check_exact_cover(shards, names) == []
    assert sum("TestAgentHookDispatch_BlockFiresOnBlock" in shard for shard in shards) == 1


OPERATOR_COLLECTOR_PARTS = tuple(
    f"TestClaudeMarkedOperatorCollectorKeepsBytes{goos}" for goos in ("Linux", "Darwin", "Windows")
)


def test_windows_connector_shards_count_the_operator_collector_matrix() -> None:
    # GAP-2199: the operator collector matrix runs 126 full Claude
    # Setup/Teardown subtests (231 s on a native Windows preflight host).
    # Unrecorded, it weighed the 0.18 s "*" default, so the balancer put it
    # beside a full 288 s shard and the connector package hit its 660 s Go
    # timeout on the hosted runner (a slow run, not a blocked write).
    import json
    import statistics

    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-windows.json").read_text(encoding="utf-8"))
    tests = timings["tests"]["internal/gateway/connector"]
    files = discover_test_files(root / "internal/gateway/connector")
    shards = partition_test_files(files, 16, tests)
    measured = dict(tests, **{name: 231.3 / len(OPERATOR_COLLECTOR_PARTS) for name in OPERATOR_COLLECTOR_PARTS})
    default = tests["*"]
    weights = [sum(float(measured.get(name, default)) for name in shard) for shard in shards]
    for part in OPERATOR_COLLECTOR_PARTS:
        holder = next(i for i, shard in enumerate(shards) if part in shard)
        assert weights[holder] <= 1.25 * statistics.median(weights), (part, holder, weights)


def test_windows_operator_collector_matrix_fits_one_shard_timeout() -> None:
    # GAP-2645: alone in its shard, the one 126-subtest test still ran past
    # the 660 s connector -timeout on a hosted runner about 1.9 times slower
    # than the recorded 427.7 s. Split per fixture GOOS, each part has a
    # recorded time and stays under half that timeout.
    import json

    root = Path(__file__).resolve().parents[2]
    tests = json.loads((root / "scripts/test-timings/go-windows.json").read_text(encoding="utf-8"))["tests"][
        "internal/gateway/connector"
    ]
    names = {name for _, file_names in discover_test_files(root / "internal/gateway/connector") for name in file_names}
    assert "TestClaudeMarkedOperatorCollectorKeepsBytes" not in names | set(tests)
    for part in OPERATOR_COLLECTOR_PARTS:
        assert part in names, part
        assert 0 < float(tests[part]) <= 330, (part, tests.get(part))


def test_match_keeps_the_tests_a_run_pattern_selects_and_still_covers_them(tmp_path: Path) -> None:
    # The CI connector matrix shards only the connector tests its -run
    # pattern selects; every selected test is in exactly one part.
    (tmp_path / "a_test.go").write_text(
        "package sample\nfunc TestHookOne(t *testing.T) {}\nfunc TestPlain(t *testing.T) {}\n", encoding="utf-8"
    )
    (tmp_path / "b_test.go").write_text("package sample\nfunc TestOther(t *testing.T) {}\n", encoding="utf-8")
    (tmp_path / "c_test.go").write_text(
        "package sample\nfunc TestSetupTwo(t *testing.T) {}\nfunc TestModeThree(t *testing.T) {}\n", encoding="utf-8"
    )

    files = match_test_files(discover_test_files(tmp_path), "Hook|Setup|Mode")
    assert [names for _, names in files] == [("TestHookOne",), ("TestModeThree", "TestSetupTwo")]
    shards = partition_test_files(files, 2)
    assert check_exact_cover(shards, ["TestHookOne", "TestModeThree", "TestSetupTwo"]) == []
    with pytest.raises(ValueError):
        match_test_files(files, "Hook/sub")


def test_windows_hookexec_matrix_covers_each_test_once_with_time_headroom() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/windows-native.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["windows-go"]
    entries = job["strategy"]["matrix"]["include"]
    hookexec_parts = [(part["shard"], part["index"]) for part in entries if part["kind"] == "hookexec"]
    assert hookexec_parts == [(f"hx{index}", index) for index in range(5)]

    uv_step = next(step for step in job["steps"] if step.get("uses", "").startswith("astral-sh/setup-uv@"))
    assert "matrix.kind == 'hookexec'" in uv_step["if"]
    run = next(
        step["run"] for step in job["steps"] if step.get("name") == "Full native Windows Go test, vet, and build"
    )
    hookexec = run.split("if ($suiteKind -eq 'hookexec') {", 1)[1].split("if ($suiteKind -eq 'packages') {", 1)[0]
    packages = run.split("if ($suiteKind -eq 'packages') {", 1)[1].split("if ($suiteKind -eq 'gateway'", 1)[0]
    assert "$hookexecTestShardCount = 5" in run
    assert "'--package-dir', 'internal/gateway/connector/hookexec'" in hookexec
    assert "'--split-tests'" in hookexec
    assert "'--timings', 'scripts/test-timings/go-windows.json'" in hookexec
    assert "'-run', $shardPattern" in hookexec
    assert "'-timeout=11m'" in hookexec
    assert "-GoTestFailureSummaryPath $goFailureSummary" in hookexec
    assert "'--exclude', 'github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec'" in packages

    timings = json.loads((root / "scripts/test-timings/go-windows.json").read_text(encoding="utf-8"))
    seconds = timings["tests"]["internal/gateway/connector/hookexec"]
    files = discover_test_files(root / "internal/gateway/connector/hookexec")
    shards = partition_test_files(files, len(hookexec_parts), seconds, split_tests=True)
    discovered = sorted({name for _, names in files for name in names})
    assert check_exact_cover(shards, discovered) == []
    assert all(shards)
    assert max(map(len, shards)) <= 150
    assert sum("TestPerUserNativeHookOutageOpenOnlyForAnOutage" in shard for shard in shards) == 1
    assert sum("TestAgentHostHeaderIsSentOnlyByManagedHooks" in shard for shard in shards) == 1
    estimated = [sum(float(seconds.get(name, seconds["*"])) for name in shard) for shard in shards]
    assert max(estimated) < 0.6 * 14 * 60, estimated


def test_windows_remaining_package_control_stays_covered() -> None:
    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-windows.json").read_text(encoding="utf-8"))
    prefix = "github.com/defenseclaw/defenseclaw/"
    excluded = {
        prefix + path
        for path in ("internal/gateway", "internal/gateway/connector", "internal/gateway/connector/hookexec")
    }
    packages = sorted(set(timings["packages"]) - excluded)
    # The workflow runs the remaining packages in this many parts, one runner each.
    workflow = (root / ".github/workflows/windows-native.yml").read_text(encoding="utf-8")
    shard_count = int(re.search(r"\$remainingPackageShardCount = (\d+)", workflow).group(1))
    for index in range(shard_count):
        assert f"{{ shard: pk{index}, kind: packages, index: {index} }}" in workflow
    assert f"shard: pk{shard_count}," not in workflow
    shards = partition_packages(packages, shard_count, timings, root=root)
    control = prefix + "internal/hookpaths"
    # GAP-0749: the hookpaths program sweep (every form through Resolve on
    # native Windows, sixteen tests) and its archive table take about 20 minutes
    # on a hosted runner, more than one shard step. The package runs in parts:
    # every one of its tests is in exactly one part, no part is a whole
    # package, and no part is estimated past half the 14 minute go test timeout.
    parts = [regex for shard in shards for package, regex in shard if package == control]
    assert len(parts) >= 2 and all(parts), parts
    tests = sorted({name for _, names in discover_test_files(root / "internal/hookpaths") for name in names})
    assert check_exact_cover([regex_names(regex) for regex in parts], tests) == []
    seconds = timings["tests"]["internal/hookpaths"]
    for regex in parts:
        estimated = sum(float(seconds.get(name, seconds["*"])) for name in regex_names(regex))
        assert estimated <= 0.5 * 14 * 60, (regex, estimated)


def test_linux_remaining_package_hookpaths_runs_in_parts_under_the_race_timeout() -> None:
    root = Path(__file__).resolve().parents[2]
    timings = json.loads((root / "scripts/test-timings/go-linux.json").read_text(encoding="utf-8"))
    prefix = "github.com/defenseclaw/defenseclaw/"
    excluded = {prefix + path for path in ("internal/audit", "internal/gateway")}
    packages = sorted(set(timings["packages"]) - excluded)
    shards = partition_packages(packages, 12, timings, root=root)
    control = prefix + "internal/hookpaths"
    # The hookpaths program sweep and archive table take 7 to 8 minutes in the
    # race run of a hosted runner and hit the 11 minute go test timeout of the
    # remaining-package shard when the package ran whole (it was recorded at
    # 6 seconds). The package runs in parts: every one of its tests is in
    # exactly one part, no part is a whole package, and no part is estimated
    # past half the 11 minute go test timeout.
    parts = [regex for shard in shards for package, regex in shard if package == control]
    assert len(parts) >= 2 and all(parts), parts
    tests = sorted({name for _, names in discover_test_files(root / "internal/hookpaths") for name in names})
    assert check_exact_cover([regex_names(regex) for regex in parts], tests) == []
    seconds = timings["tests"]["internal/hookpaths"]
    for regex in parts:
        estimated = sum(float(seconds.get(name, seconds["*"])) for name in regex_names(regex))
        assert estimated <= 0.5 * 11 * 60, (regex, estimated)
