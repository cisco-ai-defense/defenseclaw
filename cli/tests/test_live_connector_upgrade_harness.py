"""Safety contracts for the persistent-macOS connector upgrade harness."""

from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HARNESS = REPO / "scripts" / "live-connector-e2e" / "upgrade-regression.sh"
PERSIST = REPO / "scripts" / "live-connector-e2e" / "lib" / "persistent-macos.sh"
REPORT = REPO / "scripts" / "live-connector-e2e" / "report.py"
ANTIGRAVITY_DRIVER = REPO / "scripts" / "live-connector-e2e" / "drivers" / "antigravity.sh"
DRIVER_COMMON = REPO / "scripts" / "live-connector-e2e" / "drivers" / "_driver_common.sh"


def _bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=REPO,
        env=merged,
        text=True,
        capture_output=True,
        check=False,
    )


def test_harness_cli_exposes_workflow_contract() -> None:
    proc = subprocess.run(
        ["bash", str(HARNESS), "--help"],
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
    summarize = report_module["summarize"]

    candidate = tmp_path / "connector-version-radar-codex-0.144.1"
    auth_failure = tmp_path / "connector-version-radar-claudecode-2.1.208"
    candidate.mkdir()
    auth_failure.mkdir()
    (candidate / "classification.json").write_text(
        json.dumps({"classification": "candidate_regression"}),
        encoding="utf-8",
    )
    (auth_failure / "classification.json").write_text(
        json.dumps({"classification": "auth_failure"}),
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

    rows = load_candidate_regression_results(tmp_path)
    _cells, versions, failures = summarize(rows)

    assert versions[("codex", "macos")] == "0.144.1"
    assert failures == [
        ("codex", "macos", "candidate-upgrade:tool-block:enforced", "block verdict missing")
    ]
