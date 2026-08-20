"""Safety contracts for the persistent-macOS connector upgrade harness."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HARNESS = REPO / "scripts" / "live-connector-e2e" / "upgrade-regression.sh"
PERSIST = REPO / "scripts" / "live-connector-e2e" / "lib" / "persistent-macos.sh"
REPORT = REPO / "scripts" / "live-connector-e2e" / "report.py"
ANTIGRAVITY_DRIVER = REPO / "scripts" / "live-connector-e2e" / "drivers" / "antigravity.sh"
DRIVER_COMMON = REPO / "scripts" / "live-connector-e2e" / "drivers" / "_driver_common.sh"
MACOS_PERSISTENCE_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason="persistent-macos.sh filesystem contracts require POSIX paths, modes, and symlinks",
)


def _bash_executable() -> str:
    """Select Git Bash on Windows instead of the WSL app alias."""

    if os.name != "nt":
        return shutil.which("bash") or "bash"

    candidates: list[Path] = []
    if git := shutil.which("git"):
        candidates.append(Path(git).resolve().parent.parent / "bin" / "bash.exe")
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        if root := os.environ.get(variable):
            candidates.append(Path(root) / "Git" / "bin" / "bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.skip("Git Bash is required for the POSIX upgrade-regression contract on Windows")


def _bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [_bash_executable(), "-c", script],
        cwd=REPO,
        env=merged,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_report_artifact(
    results_dir: Path,
    name: str,
    *,
    connector: str,
    classification: str,
    baseline_status: str,
    candidate_status: str,
    rows: list[dict],
    baseline_version: str = "1.0.0",
    candidate_version: str = "1.1.0",
) -> Path:
    artifact = results_dir / name
    artifact.mkdir()
    (artifact / "classification.json").write_text(
        json.dumps(
            {
                "connector": connector,
                "classification": classification,
                "baseline_version": baseline_version,
                "candidate_version": candidate_version,
                "baseline_status": baseline_status,
                "candidate_status": candidate_status,
            }
        ),
        encoding="utf-8",
    )
    (artifact / "results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    return artifact


def _write_unclassified_radar_artifact(
    results_dir: Path,
    name: str,
    rows: list[dict],
) -> Path:
    artifact = results_dir / name
    artifact.mkdir()
    (artifact / "results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    return artifact


def _run_report(
    report_module: dict,
    monkeypatch: pytest.MonkeyPatch,
    results_dir: Path,
    *,
    open_issue: bool,
) -> tuple[int, list[tuple[str, str]]]:
    issue_calls: list[tuple[str, str]] = []
    report_module["main"].__globals__["open_or_update_issue"] = lambda body, run_url: issue_calls.append(
        (body, run_url)
    )
    argv = [str(REPORT), "--results-dir", str(results_dir), "--run-url", "https://example.test/run"]
    if open_issue:
        argv.append("--open-issue")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    return report_module["main"](), issue_calls


def test_harness_cli_exposes_workflow_contract() -> None:
    proc = subprocess.run(
        [_bash_executable(), str(HARNESS), "--help"],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    for flag in (
        "--connector",
        "--baseline-version",
        "--candidate-version",
        "--results",
        "--classification-output",
    ):
        assert flag in proc.stdout


def test_harness_never_globally_installs_or_removes_auth_homes() -> None:
    text = HARNESS.read_text(encoding="utf-8")
    persist_text = PERSIST.read_text(encoding="utf-8")
    assert "npm install -g" not in text
    assert "npm i -g" not in text
    assert "@anthropic-ai/claude-code" not in text
    assert "rm -rf" not in text
    assert 'export DEFENSECLAW_HOME="${SCRATCH}/defenseclaw"' in text
    assert 'export DC_E2E_AGENT_WORKSPACE="${SCRATCH}/workspace"' in text
    assert 'cd "${DC_E2E_AGENT_WORKSPACE}"' in text
    assert "--no-restart" in text
    assert "--skip-git-repo-check" in text
    assert "switching to isolated candidate without re-running" in text
    assert "defenseclaw-gateway stop" in text
    assert 'if [ "${LOCK_ACQUIRED}" = "1" ]' in text
    assert "antigravity.google/cli/install.sh" not in text
    assert 'HOME="${install_home}" DISABLE_AUTOUPDATER=1' in text
    assert 'dc_timeout 240 "${source}" install "${requested}"' in text
    assert 'install_home="$(dc_persist_realpath "${install_home}")"' in text
    assert '"${install_home}"/.local/share/claude/versions/*' in text
    claude_case = text.index("  claudecode)\n", text.index('case "${CONNECTOR}" in'))
    disable_autoupdater = text.index("export DISABLE_AUTOUPDATER=1", claude_case)
    baseline_install = text.index("dc_upgrade_install_claude_native", claude_case)
    assert disable_autoupdater < baseline_install
    assert "read -r DC_PERSIST_WS_PORT DC_PERSIST_API_PORT DC_PERSIST_SCANNER_PORT" in persist_text


def test_antigravity_permission_flag_precedes_print_prompt() -> None:
    expected = '--dangerously-skip-permissions --print "${prompt}"'
    assert expected in HARNESS.read_text(encoding="utf-8")
    assert expected in ANTIGRAVITY_DRIVER.read_text(encoding="utf-8")


def test_block_probe_forbids_model_retries() -> None:
    text = DRIVER_COMMON.read_text(encoding="utf-8")
    assert "If that exact command is blocked or denied, stop immediately." in text
    assert "Do not retry, rewrite, encode, split, or run an alternative command." in text


def test_gateway_start_auth_failure_is_classified_as_credentials(tmp_path: Path) -> None:
    auth_log = tmp_path / "auth.log"
    infrastructure_log = tmp_path / "infrastructure.log"
    auth_log.write_text(
        "Your access token could not be refreshed because your refresh token was already used. "
        "Please log out and sign in again.\n",
        encoding="utf-8",
    )
    infrastructure_log.write_text(
        "listen tcp 127.0.0.1:12345: bind: address already in use\n",
        encoding="utf-8",
    )

    proc = _bash(
        """
        set -euo pipefail
        . "${DRIVER_COMMON_PATH}"
        dc_file_looks_like_auth_failure "${AUTH_LOG}"
        if dc_file_looks_like_auth_failure "${INFRASTRUCTURE_LOG}"; then
          exit 1
        fi
        """,
        env={
            "AUTH_LOG": str(auth_log),
            "DRIVER_COMMON_PATH": str(DRIVER_COMMON),
            "INFRASTRUCTURE_LOG": str(infrastructure_log),
        },
    )
    assert proc.returncode == 0, proc.stderr

    harness_text = HARNESS.read_text(encoding="utf-8")
    start = harness_text.index(
        'baseline_gateway_start_log="${ARTIFACTS_DIR}/gateway/baseline-start.log"'
    )
    end = harness_text.index("GATEWAY_STARTED=1")
    start_block = harness_text[start:end]
    assert 'dc_file_looks_like_auth_failure "${baseline_gateway_start_log}"' in start_block
    assert 'CLASSIFICATION="auth_failure"' in start_block
    assert "HARNESS_EXIT_CODE=3" in start_block


def test_harness_captures_quiescent_v8_canonical_evidence() -> None:
    text = HARNESS.read_text(encoding="utf-8")
    assert "for name in gateway.log audit.db judge_bodies.db watchdog.log" in text
    assert "gateway.jsonl" not in text

    cleanup = text[text.index("dc_upgrade_cleanup() {") : text.index("trap dc_upgrade_cleanup EXIT")]
    assert cleanup.index("defenseclaw-gateway stop") < cleanup.index("dc_upgrade_copy_artifacts")


@MACOS_PERSISTENCE_ONLY
def test_snapshot_restore_preserves_exact_bytes_and_mode(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = home / ".codex" / "config.toml"
    snapshot = tmp_path / "snapshot"
    config.parent.mkdir(parents=True)
    original = b'model = "original"\n# keep whitespace  \n'
    config.write_bytes(original)
    config.chmod(0o640)

    proc = _bash(
        f"""
        set -euo pipefail
        dc_err() {{ printf '%s\n' "$*" >&2; }}
        . {PERSIST!s}
        dc_persist_snapshot_init {snapshot!s}
        dc_persist_snapshot_file {config!s}
        printf '%s\n' changed > {config!s}
        chmod 600 {config!s}
        dc_persist_restore_files
        """,
        env={"HOME": str(home)},
    )
    assert proc.returncode == 0, proc.stderr
    assert config.read_bytes() == original
    assert stat.S_IMODE(config.stat().st_mode) == 0o640


@MACOS_PERSISTENCE_ONLY
def test_snapshot_restore_removes_only_created_file_not_parent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    parent = home / ".gemini" / "config"
    config = parent / "hooks.json"
    snapshot = tmp_path / "snapshot"
    parent.mkdir(parents=True)

    proc = _bash(
        f"""
        set -euo pipefail
        dc_err() {{ printf '%s\n' "$*" >&2; }}
        . {PERSIST!s}
        dc_persist_snapshot_init {snapshot!s}
        dc_persist_snapshot_file {config!s}
        printf '{{}}\n' > {config!s}
        dc_persist_restore_files
        """,
        env={"HOME": str(home)},
    )
    assert proc.returncode == 0, proc.stderr
    assert not config.exists()
    assert parent.is_dir()


@MACOS_PERSISTENCE_ONLY
def test_snapshot_rejects_symlinked_connector_config(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    config = home / "config.toml"
    config.symlink_to(target)
    snapshot = tmp_path / "snapshot"

    proc = _bash(
        f"""
        set -euo pipefail
        dc_err() {{ printf '%s\n' "$*" >&2; }}
        . {PERSIST!s}
        dc_persist_snapshot_init {snapshot!s}
        dc_persist_snapshot_file {config!s}
        """,
        env={"HOME": str(home)},
    )
    assert proc.returncode != 0
    assert "symlinked config" in proc.stderr
    assert target.read_text(encoding="utf-8") == "secret"


@MACOS_PERSISTENCE_ONLY
def test_lock_release_refuses_another_process_owner(tmp_path: Path) -> None:
    lock = tmp_path / "active.lock"
    lock.mkdir()
    (lock / "pid").write_text("999999\n", encoding="utf-8")
    proc = _bash(
        f"""
        set -euo pipefail
        dc_err() {{ printf '%s\n' "$*" >&2; }}
        . {PERSIST!s}
        dc_persist_release_lock {lock!s}
        """
    )
    assert proc.returncode != 0
    assert "refusing to release" in proc.stderr
    assert lock.is_dir()
    assert (lock / "pid").read_text(encoding="utf-8") == "999999\n"


def test_report_prefers_candidate_version_over_known_good_baseline() -> None:
    summarize = runpy.run_path(str(REPORT))["summarize"]
    _cells, versions, failures = summarize(
        [
            {
                "connector": "codex",
                "os": "macos",
                "event": "baseline:lifecycle:fires",
                "status": "pass",
                "version": "0.142.5",
            },
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "0.144.1",
                "detail": "hook missing",
            },
        ]
    )
    assert versions[("codex", "macos")] == "0.144.1"
    assert failures == [("codex", "macos", "candidate-upgrade:lifecycle:fires", "hook missing")]


def test_report_issue_rows_only_include_candidate_regressions(tmp_path: Path) -> None:
    report_module = runpy.run_path(str(REPORT))
    load_candidate_regression_results = report_module["load_candidate_regression_results"]
    load_classifications = report_module["load_classifications"]
    summarize = report_module["summarize"]

    candidate = tmp_path / "connector-version-radar-codex-0.144.1"
    auth_failure = tmp_path / "connector-version-radar-claudecode-2.1.208"
    candidate.mkdir()
    auth_failure.mkdir()
    (candidate / "classification.json").write_text(
        json.dumps(
            {
                "connector": "codex",
                "classification": "candidate_regression",
                "baseline_version": "0.142.5",
                "candidate_version": "0.144.1",
                "baseline_status": "pass",
                "candidate_status": "fail",
            }
        ),
        encoding="utf-8",
    )
    (auth_failure / "classification.json").write_text(
        json.dumps(
            {
                "connector": "claudecode",
                "classification": "auth_failure",
                "baseline_version": "2.1.208",
                "candidate_version": "2.1.209",
                "baseline_status": "fail",
                "candidate_status": "not_run",
            }
        ),
        encoding="utf-8",
    )
    (candidate / "results.jsonl").write_text(
        json.dumps(
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:tool-block:enforced",
                "status": "fail",
                "version": "0.144.1",
                "detail": "block verdict missing",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (auth_failure / "results.jsonl").write_text(
        json.dumps(
            {
                "connector": "claudecode",
                "os": "macos",
                "event": "baseline:lifecycle:agent",
                "status": "fail",
                "version": "2.1.208",
                "detail": "login expired",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    rows = load_candidate_regression_results(load_classifications(tmp_path))
    _cells, versions, failures = summarize(rows)

    assert versions[("codex", "macos")] == "0.144.1"
    assert failures == [
        ("codex", "macos", "candidate-upgrade:tool-block:enforced", "block verdict missing")
    ]


def test_report_auth_only_failure_is_rendered_as_lab_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="auth_failure",
        baseline_status="fail",
        candidate_status="not_run",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "baseline:lifecycle:agent",
                "status": "fail",
                "version": "1.0.0",
                "detail": "login expired",
            }
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=False,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "Operational lab failures (not candidate regressions)" in captured.out
    assert "auth_failure" in captured.out
    assert "Lab failure events (not candidate regressions)" in captured.out
    assert "login expired" not in captured.out
    assert "regression issue body" not in captured.err
    assert "login expired" not in captured.err


def test_report_candidate_only_failure_keeps_regression_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "baseline:lifecycle:fires",
                "status": "pass",
                "version": "1.0.0",
                "detail": "",
            },
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "candidate hook missing",
            },
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert len(issue_calls) == 1
    assert "Candidate regression events" in captured.out
    assert "Operational lab failures" not in captured.out
    assert "regression issue body" in captured.err
    assert "candidate-upgrade:lifecycle:fires" in issue_calls[0][0]
    assert "candidate hook missing" in issue_calls[0][0]


def test_report_mixed_failures_separates_lab_and_candidate_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:tool-block:enforced",
                "status": "fail",
                "version": "1.1.0",
                "detail": "candidate block verdict missing",
            }
        ],
    )
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-claudecode-2.1.0",
        connector="claudecode",
        classification="auth_failure",
        baseline_status="fail",
        candidate_status="not_run",
        baseline_version="2.0.0",
        candidate_version="2.1.0",
        rows=[
            {
                "connector": "claudecode",
                "os": "macos",
                "event": "baseline:lifecycle:agent",
                "status": "fail",
                "version": "2.0.0",
                "detail": "baseline login expired",
            }
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert len(issue_calls) == 1
    assert "auth_failure" in captured.out
    assert "baseline:lifecycle:agent" in captured.out
    assert "candidate-upgrade:tool-block:enforced" in captured.out
    issue_body = issue_calls[0][0]
    assert "candidate-upgrade:tool-block:enforced" in issue_body
    assert "candidate block verdict missing" in issue_body
    assert "claudecode" not in issue_body
    assert "baseline login expired" not in issue_body
    assert "baseline login expired" not in captured.err


def test_report_auth_classification_never_calls_issue_api_without_failed_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="auth_failure",
        baseline_status="not_run",
        candidate_status="not_run",
        rows=[],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "auth_failure" in captured.out
    assert "no candidate-regression failures to file" in captured.err
    assert "regression issue body" not in captured.err


@pytest.mark.parametrize(
    ("classification", "baseline_status", "candidate_status"),
    [
        ("baseline_failure", "fail", "not_run"),
        ("infrastructure_failure", "not_run", "not_run"),
    ],
)
def test_report_other_operational_classifications_stay_red_without_raw_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    classification: str,
    baseline_status: str,
    candidate_status: str,
) -> None:
    _write_report_artifact(
        tmp_path,
        f"connector-version-radar-codex-{classification}",
        connector="codex",
        classification=classification,
        baseline_status=baseline_status,
        candidate_status=candidate_status,
        rows=[],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert classification in captured.out
    assert "not candidate regressions" in captured.out
    assert "regression issue body" not in captured.err


def test_report_contradictory_candidate_evidence_cannot_enter_regression_content(
    tmp_path: Path,
) -> None:
    artifact = _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="fail",
        candidate_status="fail",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "must remain lab evidence",
            }
        ],
    )
    assert artifact.is_dir()

    report_module = runpy.run_path(str(REPORT))
    classifications = report_module["load_classifications"](tmp_path)
    rows = report_module["load_candidate_regression_results"](classifications)

    assert rows == []
    assert len(classifications) == 1
    assert classifications[0].is_lab_failure
    assert not classifications[0].is_candidate_regression


def test_report_failed_baseline_row_cannot_enter_regression_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "baseline:lifecycle:fires",
                "status": "fail",
                "version": "1.0.0",
                "detail": "sensitive contradictory baseline detail",
            },
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "sensitive candidate detail",
            },
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "candidate-regression evidence contains a failed baseline row" in captured.out
    assert "Operational lab failures (not candidate regressions)" in captured.out
    assert "regression issue body" not in captured.err
    assert "sensitive contradictory baseline detail" not in captured.out
    assert "sensitive contradictory baseline detail" not in captured.err
    assert "sensitive candidate detail" not in captured.out
    assert "sensitive candidate detail" not in captured.err


def test_report_malformed_candidate_result_row_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifact = _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "baseline:lifecycle:fires",
                "status": "pass",
                "version": "1.0.0",
                "detail": "",
            },
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "sensitive candidate detail",
            },
        ],
    )
    results = artifact / "results.jsonl"
    results.write_text(
        results.read_text(encoding="utf-8") + '{"event":"baseline:truncated"',
        encoding="utf-8",
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "candidate-regression result evidence is unreadable or malformed" in captured.out
    assert "Operational lab failures (not candidate regressions)" in captured.out
    assert "regression issue body" not in captured.err
    assert "sensitive candidate detail" not in captured.out
    assert "sensitive candidate detail" not in captured.err


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("os", []),
        ("detail", {"secret": "sensitive structured detail"}),
    ],
)
def test_report_structurally_invalid_candidate_result_row_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    field: str,
    invalid_value: object,
) -> None:
    candidate_row = {
        "connector": "codex",
        "os": "macos",
        "event": "candidate-upgrade:lifecycle:fires",
        "status": "fail",
        "version": "1.1.0",
        "detail": "sensitive candidate detail",
    }
    candidate_row[field] = invalid_value
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[candidate_row],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "candidate-regression result evidence is unreadable or malformed" in captured.out
    assert "Operational lab failures (not candidate regressions)" in captured.out
    assert "regression issue body" not in captured.err
    assert "sensitive candidate detail" not in captured.out
    assert "sensitive candidate detail" not in captured.err
    assert "sensitive structured detail" not in captured.out
    assert "sensitive structured detail" not in captured.err


@pytest.mark.parametrize(
    "raw_row",
    [
        '{"event":"truncated"',
        json.dumps(["not", "an", "object"]),
        json.dumps(
            {
                "connector": "codex",
                "os": [],
                "event": "pass:invalid",
                "status": "pass",
                "version": "1.1.0",
                "detail": "sensitive pass detail",
            }
        ),
    ],
)
def test_report_invalid_pass_result_evidence_stays_red(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    raw_row: str,
) -> None:
    artifact = _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="pass",
        baseline_status="pass",
        candidate_status="pass",
        rows=[],
    )
    (artifact / "results.jsonl").write_text(raw_row + "\n", encoding="utf-8")

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "pass (invalid evidence)" in captured.out
    assert "classified radar result evidence is unreadable or malformed" in captured.out
    assert "Operational lab failures (not candidate regressions)" in captured.out
    assert "regression issue body" not in captured.err
    assert "sensitive pass detail" not in captured.out
    assert "sensitive pass detail" not in captured.err


def test_report_candidate_connector_must_match_artifact_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="claudecode",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[
            {
                "connector": "claudecode",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "must not escape the swapped artifact",
            }
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "does not match its artifact identity" in captured.out
    assert "regression issue body" not in captured.err
    assert "must not escape the swapped artifact" not in captured.err


def test_report_candidate_version_must_match_artifact_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-9.9.9",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        candidate_version="1.1.0",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "must not escape the renamed artifact",
            }
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "does not match its artifact identity" in captured.out
    assert "regression issue body" not in captured.err
    assert "must not escape the renamed artifact" not in captured.err


def test_report_malformed_classification_is_lab_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifact = tmp_path / "connector-version-radar-codex-1.1.0"
    artifact.mkdir()
    (artifact / "classification.json").write_text("{malformed", encoding="utf-8")
    (artifact / "results.jsonl").write_text("", encoding="utf-8")

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "(invalid evidence)" in captured.out
    assert "unreadable or malformed" in captured.out
    assert "regression issue body" not in captured.err


def test_report_all_missing_radar_classifications_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_unclassified_radar_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        [
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "must not become regression content",
            }
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert not issue_calls
    assert "invalid_classification (invalid evidence)" in captured.out
    assert "classification evidence is missing" in captured.out
    assert "Lab failure events (not candidate regressions)" in captured.out
    assert "regression issue body" not in captured.err
    assert "must not become regression content" not in captured.err


def test_report_mixed_missing_classification_stays_out_of_candidate_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_report_artifact(
        tmp_path,
        "connector-version-radar-codex-1.1.0",
        connector="codex",
        classification="candidate_regression",
        baseline_status="pass",
        candidate_status="fail",
        rows=[
            {
                "connector": "codex",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "1.1.0",
                "detail": "candidate regression detail",
            }
        ],
    )
    _write_unclassified_radar_artifact(
        tmp_path,
        "connector-version-radar-claudecode-2.1.0",
        [
            {
                "connector": "claudecode",
                "os": "macos",
                "event": "candidate-upgrade:lifecycle:fires",
                "status": "fail",
                "version": "2.1.0",
                "detail": "missing classification detail",
            }
        ],
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert len(issue_calls) == 1
    assert "classification evidence is missing" in captured.out
    assert "claudecode" in captured.out
    issue_body = issue_calls[0][0]
    assert "candidate regression detail" in issue_body
    assert "claudecode" not in issue_body
    assert "missing classification detail" not in issue_body
    assert "missing classification detail" not in captured.err


def test_report_preserves_unclassified_live_e2e_issue_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "results.jsonl").write_text(
        json.dumps(
            {
                "connector": "codex",
                "os": [],
                "event": "invalid:row",
                "status": "fail",
                "version": "1.1.0",
                "detail": "invalid legacy detail",
            }
        )
        + "\n"
        + json.dumps(
            {
                "connector": "codex",
                "os": "linux",
                "event": "tool-block:enforced",
                "status": "fail",
                "version": "1.1.0",
                "detail": "block verdict missing",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    rc, issue_calls = _run_report(
        runpy.run_path(str(REPORT)),
        monkeypatch,
        tmp_path,
        open_issue=True,
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert len(issue_calls) == 1
    assert "## Failing events" in captured.out
    assert "Operational lab failures" not in captured.out
    assert "tool-block:enforced" in issue_calls[0][0]
    assert "invalid:row" not in captured.out
    assert "invalid legacy detail" not in captured.out
    assert "invalid legacy detail" not in captured.err
