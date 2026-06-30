"""Async command execution for the Textual TUI."""

from __future__ import annotations

import asyncio
import contextlib
import ntpath
import os
import signal
import sys
import time

if os.name == "posix":
    import pty
from collections.abc import AsyncIterator
from dataclasses import dataclass

from defenseclaw.gateway import resolve_gateway_binary


@dataclass(frozen=True)
class CommandEvent:
    kind: str
    text: str = ""
    exit_code: int | None = None
    duration: float = 0.0


class CommandAlreadyRunningError(RuntimeError):
    """Raised when a second command is submitted while one is active."""


class CommandExecutor:
    """Single-flight subprocess executor.

    The Phase 1 implementation covers non-interactive subprocesses.
    PTY execution is intentionally isolated behind the same API so the
    full interactive escape hatch can be added without touching panels.
    """

    def __init__(self, *, use_pty: bool | None = None) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._master_fd: int | None = None
        self._cancelled = False
        if use_pty and os.name != "posix":
            # The 'pty' module is POSIX-only and is not imported elsewhere;
            # fail fast with a clear message instead of a NameError deep in
            # _run_pty when a caller forces PTY mode on Windows.
            raise ValueError(
                "PTY execution (use_pty=True) is only supported on POSIX platforms"
            )
        self.use_pty = os.name == "posix" if use_pty is None else use_pty

    @property
    def is_running(self) -> bool:
        return self._process is not None

    async def cancel(self) -> None:
        process = self._process
        if process is None:
            return
        self._cancelled = True
        if process.returncode is None:
            process.send_signal(signal.SIGINT)

    def write_stdin(self, text: str) -> None:
        """Forward user keystrokes to an interactive command PTY/stdin."""

        if not text:
            return
        master_fd = self._master_fd
        if master_fd is not None:
            with contextlib.suppress(OSError):
                os.write(master_fd, text.encode())
            return
        process = self._process
        if process is not None and process.stdin is not None:
            process.stdin.write(text.encode())

    async def run(
        self,
        binary: str,
        args: tuple[str, ...],
        *,
        stdin_input: str | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> AsyncIterator[CommandEvent]:
        """Run ``binary`` with ``args``.

        ``stdin_input`` feeds a secret to the child over stdin instead of
        exposing it in argv (e.g. ``keys set`` reads a hidden prompt).
        ``env_overrides`` injects secret-bearing variables into the child
        environment so they never appear in the process command line.

        When ``stdin_input`` is supplied we always use a plain pipe rather
        than a PTY: in canonical PTY mode the kernel would echo the fed
        secret back onto stdout before the child disables echo, leaking it
        into the captured output we render.
        """

        if self._process is not None:
            raise CommandAlreadyRunningError("A command is already running.")

        resolved_argv = resolve_subprocess_argv(binary, args)
        started = time.monotonic()
        self._cancelled = False
        child_env = os.environ.copy()
        if env_overrides:
            child_env.update(env_overrides)
        yield CommandEvent("start", " ".join((binary, *args)))

        if self.use_pty and stdin_input is None:
            async for event in self._run_pty(resolved_argv, started, env=child_env):
                yield event
            return

        try:
            process = await asyncio.create_subprocess_exec(
                *resolved_argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=child_env,
            )
        except OSError as exc:
            yield CommandEvent("output", f"Failed to start: {exc}")
            yield CommandEvent("done", exit_code=1, duration=time.monotonic() - started)
            return

        self._process = process
        if stdin_input is not None and process.stdin is not None:
            with contextlib.suppress(OSError):
                process.stdin.write(stdin_input.encode())
                await process.stdin.drain()
        try:
            assert process.stdout is not None
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                yield CommandEvent("output", line.decode(errors="replace").rstrip("\n"))
            exit_code = await process.wait()
        finally:
            self._process = None

        duration = time.monotonic() - started
        if self._cancelled and exit_code == 0:
            exit_code = 130
        yield CommandEvent("done", exit_code=exit_code, duration=duration)

    async def _run_pty(
        self,
        resolved_argv: tuple[str, ...],
        started: float,
        *,
        env: dict[str, str] | None = None,
    ) -> AsyncIterator[CommandEvent]:
        master_fd: int | None = None
        slave_fd: int | None = None
        try:
            master_fd, slave_fd = pty.openpty()
            process = await asyncio.create_subprocess_exec(
                *resolved_argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=os.environ.copy() if env is None else env,
            )
        except OSError as exc:
            for fd in (master_fd, slave_fd):
                if fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            yield CommandEvent("output", f"Failed to start: {exc}")
            yield CommandEvent("done", exit_code=1, duration=time.monotonic() - started)
            return

        assert master_fd is not None
        assert slave_fd is not None
        os.close(slave_fd)
        self._process = process
        self._master_fd = master_fd
        try:
            while True:
                if process.returncode is not None:
                    break
                try:
                    chunk = await asyncio.to_thread(os.read, master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                for text in _split_terminal_chunk(chunk.decode(errors="replace")):
                    yield CommandEvent("output", text)
            exit_code = await process.wait()
        finally:
            self._process = None
            self._master_fd = None
            with contextlib.suppress(OSError):
                os.close(master_fd)

        duration = time.monotonic() - started
        if self._cancelled and exit_code == 0:
            exit_code = 130
        yield CommandEvent("done", exit_code=exit_code, duration=duration)


def resolve_subprocess_argv(binary: str, args: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve a TUI command to argv that Windows can launch directly.

    Console-script shims on Windows are commonly ``.cmd`` files.  The low-level
    process API used by ``asyncio.create_subprocess_exec`` does not invoke a
    command interpreter, so it cannot execute those shims.  Self-invocations
    always use the current Python interpreter and module entry point instead;
    this also avoids relying on PATH on every platform.
    """

    binary_name = ntpath.basename(binary).lower()
    if binary_name in {"defenseclaw", "defenseclaw.exe", "defenseclaw.cmd", "defenseclaw.bat"}:
        if not sys.executable:
            raise RuntimeError("Cannot resolve DefenseClaw CLI: Python executable is unknown")
        return (os.path.abspath(sys.executable), "-m", "defenseclaw.main", *args)
    if binary == "defenseclaw-gateway":
        return (resolve_gateway_binary() or "defenseclaw-gateway", *args)
    return (binary, *args)


def _split_terminal_chunk(text: str) -> tuple[str, ...]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = normalized.split("\n")
    if normalized.endswith("\n"):
        parts = parts[:-1]
    return tuple(part for part in parts if part)
