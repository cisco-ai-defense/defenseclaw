"""Async command execution for the Textual TUI."""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import ntpath
import os
import re
import signal
import subprocess
import sys
import time

if os.name == "posix":
    import pty
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Protocol

from defenseclaw import credential_provenance
from defenseclaw.gateway import resolve_gateway_binary

_CREATE_SUSPENDED = 0x00000004
_PIPE_FRAGMENT_FLUSH_SECONDS = 0.05
_PIPE_FRAGMENT_MAX_CHARS = 64 * 1024
# A colour code cut by a read boundary ("\x1b[9" | "0m..."): held back so the
# next read completes it instead of showing "[90m" text (GAP-1543).
_INCOMPLETE_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*)?\Z")


@dataclass(frozen=True)
class CommandEvent:
    kind: str
    text: str = ""
    exit_code: int | None = None
    duration: float = 0.0
    cancelled: bool = False
    # An "output" piece that goes on the line shown last: that line was shown
    # before its newline arrived, as "restarting..." is (GAP-2284).
    continues: bool = False


class ProcessTree(Protocol):
    async def cancel(self, process: asyncio.subprocess.Process, grace: float, force: float) -> None: ...

    def close(self) -> None: ...


class CommandAlreadyRunningError(RuntimeError):
    """Raised when a second command is submitted while one is active."""


class CommandExecutor:
    """Single-flight subprocess executor.

    POSIX uses a PTY for interactive commands. Native Windows uses captured
    pipes plus chunked output and writable stdin, which preserves prompt text
    that does not end in a newline (for example Click's ``Select:`` prompt).
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
            except asyncio.TimeoutError:
                # The grace wait is torn down across loop iterations, so the
                # child can exit naturally and its transport can finish right
                # at the deadline. asyncio then raises ProcessLookupError from
                # kill(); the process is already gone, so the cancel still
                # completes with a single cancelled result.
                with contextlib.suppress(ProcessLookupError):
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
        if process is not None and process.stdin is not None and not process.stdin.is_closing():
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
        # Children reload ~/.defenseclaw/.env themselves (GAP-1176).
        child_env = credential_provenance.child_environ()
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
            # Write the payload, then close stdin: the child sees EOF after
            # the secret instead of waiting for more input, and nothing typed
            # later in Activity can reach a secret-reading prompt.
            with contextlib.suppress(OSError, ConnectionError):
                process.stdin.write(stdin_input.encode())
                await process.stdin.drain()
            with contextlib.suppress(OSError, ConnectionError):
                process.stdin.close()
        try:
            assert process.stdout is not None
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            pending = ""
            open_line = False
            while True:
                try:
                    chunk = await asyncio.wait_for(
                        process.stdout.read(4096),
                        timeout=_PIPE_FRAGMENT_FLUSH_SECONDS,
                    )
                except asyncio.TimeoutError:
                    # A newline-less interactive prompt must become visible
                    # while the child is waiting for stdin. Delay only long
                    # enough to coalesce ordinary cross-chunk line fragments.
                    ready, pending = _hold_incomplete_escape(pending)
                    for event in _output_events(ready, open_line):
                        yield event
                    open_line = _line_left_open(ready, open_line)
                    continue
                if not chunk:
                    break
                pending += decoder.decode(chunk)
                complete, separator, trailing = pending.rpartition("\n")
                if not separator:
                    while len(pending) >= _PIPE_FRAGMENT_MAX_CHARS:
                        bounded, pending = (
                            pending[:_PIPE_FRAGMENT_MAX_CHARS],
                            pending[_PIPE_FRAGMENT_MAX_CHARS:],
                        )
                        for event in _output_events(bounded, open_line):
                            yield event
                        open_line = _line_left_open(bounded, open_line)
                    continue
                for event in _output_events(complete, open_line):
                    yield event
                open_line = False
                pending = trailing
            pending += decoder.decode(b"", final=True)
            for event in _output_events(pending, open_line):
                yield event
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
        # A read can end inside a UTF-8 character or a colour code; carry
        # the cut part into the next read (GAP-1543).
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        carry = ""
        # A read can also end inside a line; showing each piece as its own
        # line broke words ("amp, cl" / "audecode"). Hold the unfinished line
        # until its newline, or show it after a short pause so a prompt
        # without a newline still appears (GAP-1772), as the pipe path does.
        partial = ""
        open_line = False
        read: asyncio.Future[bytes] | None = None
        try:
            while True:
                if read is None:
                    if process.returncode is not None:
                        break
                    read = asyncio.ensure_future(asyncio.to_thread(os.read, master_fd, 4096))
                if partial:
                    done, _ = await asyncio.wait({read}, timeout=_PIPE_FRAGMENT_FLUSH_SECONDS)
                    if not done:
                        for event in _output_events(partial, open_line):
                            yield event
                        open_line = _line_left_open(partial, open_line)
                        partial = ""
                        continue
                try:
                    chunk = await read
                except OSError:
                    break
                finally:
                    read = None
                if not chunk:
                    break
                ready, carry = _hold_incomplete_escape(carry + decoder.decode(chunk))
                text_so_far = partial + ready
                cut = max(text_so_far.rfind("\n"), text_so_far.rfind("\r")) + 1
                complete, partial = text_so_far[:cut], text_so_far[cut:]
                for event in _output_events(complete, open_line):
                    yield event
                open_line = _line_left_open(complete, open_line)
                while len(partial) >= _PIPE_FRAGMENT_MAX_CHARS:
                    bounded, partial = partial[:_PIPE_FRAGMENT_MAX_CHARS], partial[_PIPE_FRAGMENT_MAX_CHARS:]
                    for event in _output_events(bounded, open_line):
                        yield event
                    open_line = _line_left_open(bounded, open_line)
            for event in _output_events(partial + carry + decoder.decode(b"", final=True), open_line):
                yield event
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


def _hold_incomplete_escape(text: str) -> tuple[str, str]:
    """Split ``text`` into what can be shown now and a cut trailing escape."""

    match = _INCOMPLETE_ESCAPE_RE.search(text)
    if match is None:
        return text, ""
    return text[: match.start()], text[match.start() :]


def _output_events(text: str, open_line: bool) -> tuple[CommandEvent, ...]:
    """Output events for ``text``. While a line shown before its newline is
    still open, the first piece of ``text`` goes on that line (GAP-2284)."""

    continues = open_line and not text.startswith(("\n", "\r"))
    return tuple(
        CommandEvent("output", part, continues=continues and index == 0)
        for index, part in enumerate(_split_terminal_chunk(text))
    )


def _line_left_open(text: str, open_line: bool) -> bool:
    """Whether the last line is still open after showing ``text``."""

    return open_line if not text else not text.endswith(("\n", "\r"))


def _split_terminal_chunk(text: str) -> tuple[str, ...]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = normalized.split("\n")
    if normalized.endswith("\n"):
        parts = parts[:-1]
    return tuple(part for part in parts if part)
