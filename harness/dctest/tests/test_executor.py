"""Executor: command capture + redaction."""

from __future__ import annotations

from dctest.services.executor import run_command


def test_run_command_captures_stdout(tmp_path):
    out_dir = tmp_path / "case"
    transcript = run_command(
        command="echo hello-dctest",
        cwd=tmp_path,
        env_overrides=None,
        out_dir=out_dir,
        timeout_s=10,
    )
    assert transcript.exit_code == 0
    assert "hello-dctest" in transcript.stdout_path.read_text(encoding="utf-8")


def test_run_command_redacts_known_secrets(tmp_path):
    out_dir = tmp_path / "case"
    fake = "sk-A" + ("X" * 32)
    transcript = run_command(
        command=f"echo {fake}",
        cwd=tmp_path,
        env_overrides=None,
        out_dir=out_dir,
        timeout_s=10,
    )
    text = transcript.stdout_path.read_text(encoding="utf-8")
    assert fake not in text
    assert "[REDACTED]" in text


def test_run_command_times_out(tmp_path):
    out_dir = tmp_path / "case"
    transcript = run_command(
        command="sleep 5",
        cwd=tmp_path,
        env_overrides=None,
        out_dir=out_dir,
        timeout_s=1,
    )
    assert transcript.timed_out is True
    assert transcript.exit_code == 124
