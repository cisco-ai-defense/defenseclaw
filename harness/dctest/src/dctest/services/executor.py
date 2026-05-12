"""Local shell executor for defenseclaw commands under test.

Distinct from ``stage_runner.py`` (which talks to an AI agent backend).
This module runs the actual command described by a TestCase and captures
its stdout/stderr/exit code/timing into the per-case directory.
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from dctest import utc_now
from dctest.config import get_settings
from dctest.models import CommandTranscript

# Patterns we redact from captured stdout/stderr when ``redact_logs`` is true.
_REDACT_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk_live_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk_test_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    re.compile(r"gho_[A-Za-z0-9]{30,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    re.compile(r"xoxb-[A-Za-z0-9\-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
]


def _redact(text: str) -> str:
    out = text
    for pat in _REDACT_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def _write(path: Path, text: str, *, redact: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _redact(text) if redact else text
    path.write_text(payload, encoding="utf-8")


def _ensure_python_shim(shim_dir: Path) -> None:
    """Install a ``shim_dir/python`` wrapper that execs the dctest-venv python.

    Several case YAMLs use ``$(python -c "import dctest.prompt_loader ...")``
    to compute fixture paths. That only works if ``python`` resolves to an
    interpreter that has ``dctest`` importable — which is the venv-bundled
    interpreter dctest itself runs under (``sys.executable``), NOT bare
    ``python3`` from PATH (which may be a different framework / version).

    NOTE: On macOS, ``python.framework`` resolves symlinks before deriving
    ``sys.prefix``, so a symlink to ``<venv>/bin/python`` would skip the venv
    site-packages. We therefore write a tiny POSIX ``sh`` wrapper that does
    ``exec "<absolute-path>" "$@"`` — the framework sees ``argv[0]`` as the
    venv python and picks up its ``pyvenv.cfg`` correctly.
    """
    shim_dir.mkdir(parents=True, exist_ok=True)
    target = shim_dir / "python"
    desired = sys.executable or shutil.which("python3")
    if not desired:
        return

    wrapper_body = f'#!/bin/sh\nexec "{desired}" "$@"\n'
    needs_write = True
    if target.is_symlink():
        # Stale symlink from previous (broken) shim impl. Drop it.
        with contextlib.suppress(OSError):
            target.unlink()
    elif target.exists():
        try:
            current = target.read_text(encoding="utf-8")
            if current == wrapper_body and os.access(target, os.X_OK):
                needs_write = False
        except OSError:
            pass

    if not needs_write:
        return
    target.write_text(wrapper_body, encoding="utf-8")
    target.chmod(0o755)


def _build_case_path(base_env: dict[str, str]) -> str:
    """Compose a deterministic PATH for case subshells.

    Order (highest precedence first):
      1. ``<harness>/runtime/bin`` — python -> python3 shim.
      2. The directory holding the current ``sys.executable`` — ensures
         ``dctest`` and any other console-script entry points installed in
         the harness venv are on PATH.
      3. The directory holding ``defenseclaw_bin`` (resolved if available,
         else fall back to ``~/.local/bin`` which is where the wheel installs
         the console script).
      4. The directory holding ``defenseclaw_gateway_bin``.
      5. The caller's existing PATH.
    """
    settings = get_settings()
    parts: list[str] = []

    shim_dir = settings.effective_python_shim_dir()
    _ensure_python_shim(shim_dir)
    parts.append(str(shim_dir))

    dctest_bin_dir = Path(sys.executable).parent
    parts.append(str(dctest_bin_dir))

    for name in (settings.defenseclaw_bin, settings.defenseclaw_gateway_bin):
        resolved = shutil.which(name)
        if resolved:
            parts.append(str(Path(resolved).parent))
            continue
        # Fall back to ~/.local/bin where pipx / pip-user installs land.
        local_bin = Path.home() / ".local" / "bin"
        if local_bin.is_dir():
            parts.append(str(local_bin))

    existing = base_env.get("PATH", "")
    if existing:
        parts.append(existing)

    # Dedupe while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for p in parts:
        if not p or p in seen:
            continue
        seen.add(p)
        deduped.append(p)
    return os.pathsep.join(deduped)


def run_command(
    *,
    command: str,
    cwd: Path,
    env_overrides: dict[str, str] | None,
    out_dir: Path,
    timeout_s: int | None = None,
    shell: bool = True,
) -> CommandTranscript:
    """Run a command and capture stdout/stderr/exit-code to ``out_dir``.

    The transcript is also written to disk as ``transcript.json`` alongside
    the raw ``stdout.txt`` and ``stderr.txt``. Returns the in-memory
    CommandTranscript so callers can inspect it directly.
    """
    settings = get_settings()
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / "stdout.txt"
    stderr_path = out_dir / "stderr.txt"
    cmd_path = out_dir / "command.txt"
    cmd_path.write_text(command + "\n", encoding="utf-8")

    env = os.environ.copy()
    if env_overrides:
        env.update({k: str(v) for k, v in env_overrides.items()})
    env["PATH"] = _build_case_path(env)

    timeout = timeout_s or settings.command_timeout_s
    started = utc_now()
    timed_out = False
    try:
        if shell:
            argv: list[str] | str = command
        else:
            argv = shlex.split(command)
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout_text = completed.stdout
        stderr_text = completed.stderr
        exit_code = completed.returncode
    except subprocess.TimeoutExpired as e:
        stdout_text = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr_text = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        exit_code = 124
        timed_out = True
    ended = utc_now()

    _write(stdout_path, stdout_text, redact=settings.redact_logs)
    _write(stderr_path, stderr_text, redact=settings.redact_logs)
    (out_dir / "exit_code.txt").write_text(f"{exit_code}\n", encoding="utf-8")

    transcript = CommandTranscript(
        command=command,
        cwd=cwd,
        env_overrides=env_overrides or {},
        started_at=started,
        ended_at=ended,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    (out_dir / "transcript.json").write_text(
        transcript.model_dump_json(indent=2), encoding="utf-8"
    )
    return transcript


def python_interpreter() -> str:
    return sys.executable
