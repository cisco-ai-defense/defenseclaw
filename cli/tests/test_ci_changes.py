# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contract for the pull request suite classifier (scripts/ci_changes.py)."""

from __future__ import annotations

import fnmatch
import importlib.util
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ci_changes", ROOT / "scripts" / "ci_changes.py")
assert SPEC and SPEC.loader
ci_changes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_changes)

WORKFLOWS = ROOT / ".github" / "workflows"

# The main branch ruleset's required checks. Each must keep reporting on every
# pull request, whichever suites the classifier skips.
REQUIRED_CHECKS = {
    "ci.yml": {
        "Go Build (darwin/arm64)",
        "Go Build (linux/amd64)",
        "Go Build (linux/arm64)",
        "Go Lint",
        "Python Lint & Test",
        "TypeScript Build & Test",
        "Python Dependency Audit",
        "npm Dependency Audit",
        "make test (unified)",
        "Go Test",
        "Rego Policy Tests",
    },
}
# connector-live-e2e.yml builds its matrix at run time; every matrix it can
# choose must contain this cell (see the no-op test below).
REQUIRED_CONTRACT_CELL = {"os": "macos-latest", "connector": "codex"}

# A tiny repository index for the reference lookups: path -> text.
FAKE_REPO = {
    "cli/tests/test_docs_links.py": 'DOC = "docs-site/content/docs/tui.mdx"\n',
    "cli/tests/test_ci_workflow_efficiency.py": 'ROOT / ".github/workflows/ci.yml"\n',
    "cli/tests/test_unrelated.py": "def test_nothing(): pass\n",
    # This contract names paths as fixtures and never pins them.
    "cli/tests/test_ci_changes.py": 'CASE = "docs-site/content/docs/hitl.mdx"  # defenseclaw.tui\n',
    "cli/tests/test_status_panel.py": "from defenseclaw.tui import app\n",
    "cli/tests/tui/test_app_shell.py": "def test_mount(): pass\n",
    "cli/tests/tui/helpers.py": "def helper(): pass\n",
    "internal/gateway/health_docs_test.go": (
        'func TestHealthDocsMatch(t *testing.T) { read("docs-site/content/docs/health.mdx") }\n'
        "func TestHealthDocsLinks(t *testing.T) {}\n"
    ),
    "internal/cli/docs_paths_test.go": 'var sandboxDoc = "sandboxes.mdx"\n',
    "scripts/gen_envvars_docs.py": 'OUT = "docs-site/content/docs/reference/env-vars.mdx"\n',
    "scripts/live-connector-e2e/test-windows.ps1": "$ci = '.github\\workflows\\windows-native.yml'\n",
}


def fake_references(needles, pathspecs):
    needles = list(needles)
    include = [spec for spec in pathspecs if not spec.startswith(":!")]
    exclude = [spec[2:] for spec in pathspecs if spec.startswith(":!")]

    def selected(path: str) -> bool:
        def hit(spec: str) -> bool:
            return path.startswith(spec) if spec.endswith("/") else fnmatch.fnmatchcase(path, spec)

        return any(hit(spec) for spec in include) and not any(hit(spec) for spec in exclude)

    return sorted(
        path for path, text in FAKE_REPO.items() if selected(path) and any(n in text for n in needles)
    )


def classify(*files: str) -> dict:
    return ci_changes.classify(list(files), references=fake_references, read=FAKE_REPO.__getitem__)


def ran(outputs: dict) -> set[str]:
    groups = (
        "go",
        "go_pinned",
        "python",
        "python_tests",
        "python_lint",
        "wheel",
        "ts",
        "rego",
        "checks",
        "core",
        "install",
        "enterprise",
        "windows_go",
        "windows_python",
        "windows_pkg",
        "pwsh",
        "workflows",
        "code",
    )
    return {group for group in groups if outputs[group]}


ALL_GROUPS = ran(ci_changes.everything("test")) - {"go_pinned"}


@pytest.mark.parametrize(
    ("files", "expected", "py_select", "go_packages"),
    (
        pytest.param(["docs-site/content/docs/hitl.mdx"], set(), "", [], id="docs-unpinned"),
        pytest.param(
            ["docs-site/content/docs/tui.mdx"],
            {"python_tests"},
            "cli/tests/test_docs_links.py",
            [],
            id="docs-pinned-by-python-test",
        ),
        pytest.param(
            ["docs-site/content/docs/health.mdx"],
            {"go_pinned"},
            "",
            [{"package": "./internal/gateway", "run": "^(TestHealthDocsLinks|TestHealthDocsMatch)$"}],
            id="docs-pinned-by-go-test",
        ),
        pytest.param(
            ["docs/sandboxes.mdx"],
            {"go_pinned"},
            "",
            [{"package": "./internal/cli", "run": "."}],
            id="docs-pinned-by-go-helper-runs-package",
        ),
        pytest.param(
            ["docs-site/content/docs/reference/env-vars.mdx"],
            {"checks"},
            "",
            [],
            id="generated-docs-run-parity-checks",
        ),
        pytest.param(
            [".github/workflows/ci.yml"],
            {"workflows", "python_tests"},
            "cli/tests/test_ci_workflow_efficiency.py",
            [],
            id="workflow-only",
        ),
        pytest.param(
            [".github/workflows/windows-native.yml"],
            {"workflows", "pwsh"},
            "",
            [],
            id="workflow-pinned-by-powershell-harness",
        ),
        pytest.param(
            ["cli/defenseclaw/commands/cmd_status.py"],
            {"python", "python_tests", "python_lint", "wheel", "checks", "core", "install", "windows_python", "windows_pkg", "pwsh", "code"},
            "",
            [],
            id="python-only",
        ),
        pytest.param(
            ["cli/defenseclaw/tui/app.py"],
            {"python_tests", "python_lint", "wheel", "code"},
            "cli/tests/test_status_panel.py cli/tests/tui/test_app_shell.py",
            [],
            id="tui-only",
        ),
        pytest.param(
            ["internal/gateway/router.go"],
            {"go", "checks", "core", "install", "enterprise", "windows_go", "windows_pkg", "pwsh", "code"},
            "",
            [],
            id="go-only",
        ),
        pytest.param(
            ["packaging/windows/standalone/build-setup.sh"],
            {"install", "enterprise", "windows_go", "windows_python", "windows_pkg", "pwsh", "code"},
            "",
            [],
            id="windows-packaging",
        ),
        pytest.param(
            ["macos/DefenseClaw/App.swift"],
            set(),
            "",
            [],
            id="macos-app-has-its-own-workflow",
        ),
        pytest.param(
            ["extensions/defenseclaw/src/index.ts"],
            {"go", "python", "ts", "python_tests", "python_lint", "wheel", "checks", "core", "install", "enterprise", "windows_go", "windows_python", "windows_pkg", "pwsh", "code"},
            "",
            [],
            id="extension-is-embedded",
        ),
        pytest.param(["Makefile"], ALL_GROUPS, "", [], id="shared-makefile-runs-everything"),
        pytest.param(["somewhere/new.file"], ALL_GROUPS, "", [], id="unknown-path-runs-everything"),
        pytest.param(
            ["docs-site/content/docs/hitl.mdx", "internal/gateway/router.go"],
            {"go", "checks", "core", "install", "enterprise", "windows_go", "windows_pkg", "pwsh", "code"},
            "",
            [],
            id="mixed-is-the-union",
        ),
    ),
)
def test_pull_request_suites(files, expected, py_select, go_packages) -> None:
    outputs = classify(*files)
    assert ran(outputs) == expected
    assert outputs["py_select"] == py_select
    assert json.loads(outputs["go_tests"]) == go_packages


def test_large_pull_requests_and_empty_diffs_run_everything() -> None:
    many = [f"docs-site/content/docs/page-{index}.mdx" for index in range(ci_changes.LARGE_PR_FILES + 1)]
    assert ran(classify(*many)) == ALL_GROUPS
    assert ran(classify()) == ALL_GROUPS


def test_events_other_than_pull_request_run_everything(capsys) -> None:
    for event in ("push", "schedule", "workflow_dispatch", "merge_group"):
        assert ci_changes.main(["--event", event, "--get", "go"]) == 0
        assert capsys.readouterr().out.strip() == "true"
        assert ci_changes.main(["--event", event, "--get", "py_select"]) == 0
        assert capsys.readouterr().out.strip() == ""
    # A dispatch runs every suite on one commit, and pushes to the branch
    # after it must not cancel it (only the pull_request run is superseded).
    for name in ("ci.yml", "windows-native.yml"):
        workflow = _workflow(name)
        assert "workflow_dispatch" in workflow[True], name
        group = workflow["concurrency"]["group"]
        assert group.endswith("-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}"), name


def test_every_tracked_path_is_classified() -> None:
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    unknown = [path for path in tracked if ci_changes.suites_for(path) is None]
    # Root dotfiles and shared build inputs deliberately run everything.
    assert set(unknown) <= {".gitattributes", ".gitignore", "Makefile"}, unknown[:20]


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _check_names(job: dict) -> set[str]:
    name = job.get("name", "")
    matrix = job.get("strategy", {}).get("matrix", {})
    if "${{ matrix." not in name or not isinstance(matrix, dict):
        return {name}
    names = set()
    for row in matrix.get("include", []):
        names.add(re.sub(r"\$\{\{ matrix\.(\w+) \}\}", lambda m: str(row[m.group(1)]), name))
    return names


@pytest.mark.parametrize("workflow", sorted(REQUIRED_CHECKS))
def test_required_checks_always_report(workflow: str) -> None:
    jobs = _workflow(workflow)["jobs"]
    by_name = {}
    for job_id, job in jobs.items():
        for name in _check_names(job):
            by_name[name] = (job_id, job)
    for check in REQUIRED_CHECKS[workflow]:
        assert check in by_name, f"{workflow}: required check {check!r} has no job"
        job_id, job = by_name[check]
        matrix = job.get("strategy", {}).get("matrix")
        if matrix is not None and "${{ matrix." in job["name"]:
            # A matrix job skipped by its own if never reports the expanded
            # names, so it must start whenever the run is not cancelled.
            assert job.get("if") in (None, "${{ !cancelled() }}"), (workflow, job_id)


def test_aggregates_accept_skips_only_from_the_classifier() -> None:
    ci = _workflow("ci.yml")["jobs"]
    for job_id in ("go-test", "python-lint-test", "enterprise-required"):
        job = ci[job_id]
        assert job["if"] == "${{ always() }}"
        assert "changes" in job["needs"]
    native = _workflow("windows-native.yml")["jobs"]["windows-native-required"]
    assert "changes" in native["needs"]
    assert "$results.changes.result -eq 'success'" in native["steps"][0]["run"]


def test_workflows_read_only_outputs_the_classifier_writes() -> None:
    outputs = set(ci_changes.everything("test"))
    for name in ("ci.yml", "windows-native.yml"):
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        used = set(re.findall(r"steps\.classify\.outputs\.(\w+)", text))
        assert used, name
        assert used <= outputs, used - outputs
    live = (WORKFLOWS / "connector-live-e2e.yml").read_text(encoding="utf-8")
    assert "scripts/ci_changes.py --event pull_request --files-from - --get code" in live
    assert "code" in outputs


def test_no_code_pull_requests_keep_the_required_contract_name() -> None:
    live = (WORKFLOWS / "connector-live-e2e.yml").read_text(encoding="utf-8")
    matrices = {
        name: json.loads(re.search(rf"^\s*{name}='([^']+)'$", live, flags=re.MULTILINE).group(1))
        for name in ("full", "minimal", "noop")
    }
    for name, matrix in matrices.items():
        cells = [{"os": os, "connector": c} for os in matrix["os"] for c in matrix["connector"]]
        cells += [{key: row[key] for key in ("os", "connector")} for row in matrix.get("include", [])]
        assert REQUIRED_CONTRACT_CELL in cells, name
    noop = matrices["noop"]
    assert noop["os"] == ["macos-latest"] and noop["connector"] == ["codex"]
    assert noop["include"] == [
        {"os": "macos-latest", "connector": "codex", "runner": "ubuntu-latest", "noop": True}
    ]
    job = _workflow("connector-live-e2e.yml")["jobs"]["contract-matrix"]
    assert job["name"] == "Contract ${{ matrix.connector }} / ${{ matrix.os }}"
    assert job["runs-on"] == "${{ matrix.runner || matrix.os }}"
