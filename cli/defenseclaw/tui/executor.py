"""Async command execution for the Textual TUI."""

from __future__ import annotations

import asyncio
import contextlib
import ntpath
import os
import signal
import subprocess
import sys
import time

if os.name == "posix":
    import pty
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Protocol

from defenseclaw.gateway import resolve_gateway_binary

_CREATE_SUSPENDED = 0x00000004


@dataclass(frozen=True)
class CommandEvent:
    kind: str
    text: str = ""
    exit_code: int | None = None
    duration: float = 0.0
    cancelled: bool = False


class ProcessTree(Protocol):
    async def cancel(self, process: asyncio.subprocess.Process, grace: float, force: float) -> None: ...

    def close(self) -> None: ...


class CommandAlreadyRunningError(RuntimeError):
    """Raised when a second command is submitted while one is active."""


class CommandExecutor:
    """Single-flight subprocess executor.

    The Phase 1 implementation covers non-interactive subprocesses.
    PTY execution is intentionally isolated behind the same API so the
    full interactive escape hatch can be added without touching panels.
    """

    def __init__(
        self,
        *,
        use_pty: bool | None = None,
        cancel_grace: float = 0.5,
        cancel_force: float = 2.0,
        process_tree_factory: Callable[[int], ProcessTree | None] | None = None,
    ) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._process_tree: ProcessTree | None = None
        self._master_fd: int | None = None
        self._cancelled = False
        self._cancel_lock = asyncio.Lock()
        self._cancel_grace = cancel_grace
        self._cancel_force = cancel_force
        self._process_tree_factory = process_tree_factory or _windows_process_tree
        if use_pty and os.name != "posix":
            # The 'pty' module is POSIX-only and is not imported elsewhere;
            # fail fast with a clear message instead of a NameError deep in
            # _run_pty when a caller forces PTY mode on Windows.
            raise ValueError("PTY execution (use_pty=True) is only supported on POSIX platforms")
        self.use_pty = os.name == "posix" if use_pty is None else use_pty

    @property
    def is_running(self) -> bool:
        return self._process is not None

    async def cancel(self) -> bool:
        async with self._cancel_lock:
            process = self._process
            if process is None or process.returncode is not None or self._cancelled:
                return False
            self._cancelled = True
            if process.stdin is not None:
                with contextlib.suppress(OSError):
                    process.stdin.close()
            if self._process_tree is not None:
                await self._process_tree.cancel(process, self._cancel_grace, self._cancel_force)
                return True
            process.send_signal(signal.SIGINT)
            try:
                await asyncio.wait_for(asyncio.shield(process.wait()), timeout=self._cancel_grace)
            except TimeoutError:
                process.kill()
                await asyncio.wait_for(asyncio.shield(process.wait()), timeout=self._cancel_force)
            return True

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
                **managed_subprocess_kwargs(),
            )
        except OSError as exc:
            yield CommandEvent("output", f"Failed to start: {exc}")
            yield CommandEvent("done", exit_code=1, duration=time.monotonic() - started)
            return

        self._process = process
        try:
            self._process_tree = self._process_tree_factory(process.pid)
            if os.name == "nt" and self._process_tree is None:
                raise OSError("Windows process tree setup returned no job object")
        except OSError as exc:
            process.kill()
            await process.wait()
            self._process = None
            yield CommandEvent("output", f"Failed to secure process tree: {exc}")
            yield CommandEvent("done", exit_code=1, duration=time.monotonic() - started)
            return
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
            async with self._cancel_lock:
                self._process = None
                if self._process_tree is not None:
                    self._process_tree.close()
                    self._process_tree = None

        duration = time.monotonic() - started
        if self._cancelled:
            exit_code = 130
        yield CommandEvent("done", exit_code=exit_code, duration=duration, cancelled=self._cancelled)

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
            async with self._cancel_lock:
                self._process = None
                self._master_fd = None
                with contextlib.suppress(OSError):
                    os.close(master_fd)

        duration = time.monotonic() - started
        if self._cancelled:
            exit_code = 130
        yield CommandEvent("done", exit_code=exit_code, duration=duration, cancelled=self._cancelled)


def _windows_process_tree(pid: int) -> ProcessTree | None:
    if os.name != "nt":
        return None
    from defenseclaw.tui.windows_process import WindowsJob

    return WindowsJob(pid)


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
        resolved = resolve_gateway_binary()
        if not resolved:
            raise RuntimeError("Cannot resolve DefenseClaw gateway executable")
        return (resolved, *args)
    return (binary, *args)


def captured_subprocess_kwargs() -> dict[str, int]:
    """Return platform flags for a noninteractive, captured child process.

    Windows console executables allocate a transient console when their parent
    is a graphical or detached process. The TUI already captures each child's
    standard streams, so suppressing that extra console does not detach the
    process or change its output, exit status, cancellation, or wait behavior.
    """

    if os.name != "nt":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}


def managed_subprocess_kwargs() -> dict[str, int]:
    """Return flags for a command that will immediately enter a Job Object.

    Suspending Windows commands closes the launch-to-assignment race: no child
    code can create an escaping descendant before :class:`WindowsJob` owns and
    resumes the root process. Other TUI subprocess call sites use
    :func:`captured_subprocess_kwargs` and are never suspended.
    """

    kwargs = captured_subprocess_kwargs()
    if os.name == "nt":
        kwargs["creationflags"] |= _CREATE_SUSPENDED
    return kwargs


def _split_terminal_chunk(text: str) -> tuple[str, ...]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = normalized.split("\n")
    if normalized.endswith("\n"):
        parts = parts[:-1]
    return tuple(part for part in parts if part)
