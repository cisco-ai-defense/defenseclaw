"""Subprocess wrapper for AI agent backends.

Three backends are supported, mirroring avarice:

* ``claude``  - invokes ``claude -p`` with ``stream-json`` output
* ``codex``   - invokes ``codex exec --json``
* ``manual``  - writes prompts to ``staged/`` and returns; user runs an agent
                externally, then calls ``dctest collect``.

For each invocation, the full prompt, argv, stdout, and stderr are written
under ``runs/<run-id>/logs/<stage>/<ts>/``. Verdicts always come from a
file the agent writes (``verdict.json``), never from the subprocess return
code.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dctest import utc_now
from dctest.config import get_settings
from dctest.exceptions import StageRunnerError
from dctest.models import AgentTranscript

Backend = Literal["claude", "codex", "manual"]


@dataclass
class StageInvocation:
    """Inputs to a single agent invocation."""

    run_id: str
    stage: str
    prompt: str
    add_dirs: list[Path]
    backend: Backend
    model: str | None = None
    timeout_s: int | None = None
    capture_output_path: Path | None = None


@dataclass
class StageOutcome:
    """Result of a single agent invocation."""

    backend: Backend
    transcript: AgentTranscript
    last_message: str
    capture_existed: bool


def _now_slug() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def _logs_dir(run_id: str, stage: str) -> Path:
    settings = get_settings()
    return settings.runs_root / run_id / "logs" / stage / _now_slug()


def _write_prompt(d: Path, prompt: str) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    path = d / "prompt.txt"
    path.write_text(prompt, encoding="utf-8")
    return path


def _write_argv(d: Path, argv: list[str]) -> Path:
    path = d / "argv.txt"
    path.write_text("\n".join(argv) + "\n", encoding="utf-8")
    return path


def build_claude_argv(
    *,
    model: str | None,
    add_dirs: list[Path],
) -> list[str]:
    settings = get_settings()
    chosen_model = model or settings.claude_model
    argv: list[str] = [
        settings.claude_bin,
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    if chosen_model:
        argv += ["--model", chosen_model]
    for d in add_dirs:
        argv += ["--add-dir", str(d)]
    argv += [
        "--permission-mode",
        "acceptEdits",
        "--allowedTools",
        "Read,Write,Edit,Bash,Glob,Grep",
    ]
    return argv


def build_codex_argv(*, model: str | None, cwd: Path) -> list[str]:
    settings = get_settings()
    chosen_model = model or settings.codex_model
    argv: list[str] = [
        settings.codex_bin,
        "exec",
        "--json",
        "--ignore-user-config",
        "--sandbox",
        "workspace-write",
        "--skip-git-repo-check",
        # Don't persist session files for every case — keeps ``~/.codex/sessions/``
        # from filling up with thousands of multi-megabyte transcripts during a
        # full sweep and removes a (small) fsync hotspot under --jobs > 1.
        "--ephemeral",
        "-C",
        str(cwd),
    ]
    if chosen_model:
        argv += ["--model", chosen_model]
    return argv


def _parse_claude_stream(stdout_path: Path) -> str:
    """Extract the final assistant message from a stream-json transcript."""
    last = ""
    if not stdout_path.exists():
        return last
    for line in stdout_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("type") == "result":
            r = payload.get("result")
            if isinstance(r, str) and r:
                last = r
    return last


def _parse_codex_stream(stdout_path: Path) -> str:
    """Extract the last assistant message from a codex JSONL transcript."""
    last = ""
    if not stdout_path.exists():
        return last
    for line in stdout_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = payload.get("msg") or {}
        if msg.get("type") == "agent_message" and isinstance(msg.get("message"), str):
            last = msg["message"]
        elif payload.get("type") == "message" and isinstance(payload.get("content"), str):
            last = payload["content"]
    return last


def run_stage(invocation: StageInvocation) -> StageOutcome:
    """Dispatch a prompt to the chosen backend and persist artifacts.

    For ``manual`` backend, this writes the prompt + a manifest under
    ``staged/<stage>/`` and returns an outcome with an empty last_message;
    the caller is expected to subsequently invoke the equivalent of
    ``dctest collect`` to ingest the agent's verdict file.
    """
    settings = get_settings()
    ts_dir = _logs_dir(invocation.run_id, invocation.stage)
    prompt_path = _write_prompt(ts_dir, invocation.prompt)

    if invocation.backend == "manual":
        manifest = {
            "run_id": invocation.run_id,
            "stage": invocation.stage,
            "created_at": utc_now().isoformat() + "Z",
            "instructions": (
                "Open the prompt.txt in this directory in your AI agent of choice "
                "(Claude Code, Codex, etc.), execute the work it describes, then "
                "write the per-case verdict.json files where the prompt asks. "
                "When done, run `dctest collect`."
            ),
            "prompt": str(prompt_path),
            "add_dirs": [str(p) for p in invocation.add_dirs],
        }
        (ts_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        transcript = AgentTranscript(
            backend="manual",
            argv=[],
            cwd=invocation.add_dirs[0] if invocation.add_dirs else Path.cwd(),
            started_at=utc_now(),
            ended_at=utc_now(),
            exit_code=0,
            timed_out=False,
            prompt_path=prompt_path,
            stdout_path=ts_dir / "agent.stdout.txt",
            stderr_path=ts_dir / "agent.stderr.txt",
        )
        return StageOutcome(
            backend="manual", transcript=transcript, last_message="", capture_existed=False
        )

    cwd = invocation.add_dirs[0] if invocation.add_dirs else Path.cwd()
    if invocation.backend == "claude":
        argv = build_claude_argv(model=invocation.model, add_dirs=invocation.add_dirs)
        stdout_path = ts_dir / "agent.stdout.json"
    elif invocation.backend == "codex":
        argv = build_codex_argv(model=invocation.model, cwd=cwd)
        stdout_path = ts_dir / "agent.stdout.jsonl"
    else:  # pragma: no cover - exhaustively handled above
        raise StageRunnerError(f"Unknown backend: {invocation.backend!r}")

    _write_argv(ts_dir, argv)
    stderr_path = ts_dir / "agent.stderr.txt"
    last_message_path = ts_dir / "last-message.txt"
    timeout = invocation.timeout_s or settings.agent_timeout_s
    env = os.environ.copy()
    started = utc_now()
    timed_out = False
    try:
        completed = subprocess.run(
            argv,
            input=invocation.prompt,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")
        exit_code = completed.returncode
    except FileNotFoundError as e:
        stderr_path.write_text(f"backend binary not found: {e}\n", encoding="utf-8")
        stdout_path.write_text("", encoding="utf-8")
        exit_code = 127
    except subprocess.TimeoutExpired as e:
        stdout_path.write_text(
            e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            encoding="utf-8",
        )
        stderr_path.write_text(
            e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or ""),
            encoding="utf-8",
        )
        exit_code = 124
        timed_out = True
    ended = utc_now()

    if invocation.backend == "claude":
        last = _parse_claude_stream(stdout_path)
    else:
        last = _parse_codex_stream(stdout_path)
    if last:
        last_message_path.write_text(last, encoding="utf-8")

    capture_existed = bool(
        invocation.capture_output_path
        and invocation.capture_output_path.exists()
    )

    transcript = AgentTranscript(
        backend=invocation.backend,
        argv=argv,
        cwd=cwd,
        started_at=started,
        ended_at=ended,
        exit_code=exit_code,
        timed_out=timed_out,
        prompt_path=prompt_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        last_message_path=last_message_path if last else None,
    )
    return StageOutcome(
        backend=invocation.backend,
        transcript=transcript,
        last_message=last,
        capture_existed=capture_existed,
    )
