# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Track 9 — v7 CLI contracts (schemas, settings, alerts subcommands).

Pure-``unittest`` (no pytest dependency) so that ``make test`` works
against the production venv created by ``make install`` / ``make pycli``
without needing the ``[dependency-groups] dev`` packages.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol
from unittest.mock import MagicMock, call, patch

from click.testing import CliRunner

from tests.environment import isolated_home_env

ROOT = Path(__file__).resolve().parents[2]
_GO_BUILD_TIMEOUT_SECONDS = 300
_SCAN_TIMEOUT_SECONDS = 30
_PROCESS_TERMINATE_GRACE_SECONDS = 1
_PROCESS_REAP_TIMEOUT_SECONDS = 10
_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_SIGTERM = getattr(signal, "SIGTERM", 15)
_SIGKILL = getattr(signal, "SIGKILL", 9)


class _ProcessTreeOwner(Protocol):
    def terminate(self, process: subprocess.Popen[bytes]) -> tuple[bytes | None, bytes | None]: ...

    def close(self) -> None: ...


def _decode_process_output(output: bytes | str | None) -> str:
    """Decode captured output explicitly and preserve malformed diagnostics."""

    if output is None:
        return ""
    if isinstance(output, str):
        return output
    return output.decode("utf-8", errors="replace")


def _communicate_after_termination(
    process: subprocess.Popen[bytes],
) -> tuple[bytes | None, bytes | None]:
    """Reap a terminated root process without allowing cleanup to hang."""

    try:
        return process.communicate(timeout=_PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate(timeout=_PROCESS_REAP_TIMEOUT_SECONDS)


class _WindowsProcessTreeOwner:
    """Adapt the existing TUI Job Object to a synchronous test subprocess."""

    def __init__(self, pid: int) -> None:
        from defenseclaw.tui.windows_process import WindowsJob

        # The process was created suspended, so no compiler child can escape
        # before WindowsJob assigns the root and resumes the entire tree.
        self._job = WindowsJob(pid, allow_breakaway=False)

    def terminate(self, process: subprocess.Popen[bytes]) -> tuple[bytes | None, bytes | None]:
        self.close()  # KILL_ON_JOB_CLOSE terminates compiler/linker descendants.
        return _communicate_after_termination(process)

    def close(self) -> None:
        self._job.close()


class _PosixProcessTreeOwner:
    """Own the new session/process group created for one test subprocess."""

    def __init__(self, pid: int) -> None:
        self._process_group = pid

    def _signal_group(self, process: subprocess.Popen[bytes], sig: int) -> None:
        try:
            _kill_process_group(self._process_group, sig)
        except ProcessLookupError:
            return
        except OSError:
            # If group signalling is unavailable after a partial launch, still
            # terminate and reap the root process handle we own.
            if process.poll() is None:
                process.kill()

    def terminate(self, process: subprocess.Popen[bytes]) -> tuple[bytes | None, bytes | None]:
        self._signal_group(process, _SIGTERM)
        try:
            return process.communicate(timeout=_PROCESS_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self._signal_group(process, _SIGKILL)
            return _communicate_after_termination(process)

    def close(self) -> None:
        return


def _kill_process_group(process_group: int, sig: int) -> None:
    """Call the POSIX-only group signal API behind a mockable boundary."""

    os.killpg(process_group, sig)


def _process_tree_popen_kwargs(platform: str | None = None) -> dict[str, int | bool]:
    """Return race-free process-tree flags for the requested host platform."""

    platform = os.name if platform is None else platform
    if platform == "nt":
        no_window = getattr(subprocess, "CREATE_NO_WINDOW", _CREATE_NO_WINDOW)
        return {"creationflags": no_window | _CREATE_SUSPENDED}
    return {"start_new_session": True}


def _new_process_tree_owner(process: subprocess.Popen[bytes]) -> _ProcessTreeOwner:
    if os.name == "nt":
        return _WindowsProcessTreeOwner(process.pid)
    return _PosixProcessTreeOwner(process.pid)


def _run_captured_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run an argv-only command with captured UTF-8 output and tree cleanup."""

    command = [os.fspath(arg) for arg in argv]
    process = subprocess.Popen(
        command,
        cwd=os.fspath(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_process_tree_popen_kwargs(),
    )
    owner: _ProcessTreeOwner | None = None
    try:
        try:
            owner = _new_process_tree_owner(process)
        except BaseException:
            process.kill()
            _communicate_after_termination(process)
            raise

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            stdout, stderr = owner.terminate(process)
            raise subprocess.TimeoutExpired(
                command,
                timeout,
                output=_decode_process_output(stdout),
                stderr=_decode_process_output(stderr),
            ) from None
        except BaseException:
            owner.terminate(process)
            raise

        return subprocess.CompletedProcess(
            command,
            process.returncode,
            _decode_process_output(stdout),
            _decode_process_output(stderr),
        )
    finally:
        if owner is not None:
            owner.close()


def _go_test_binary_name(platform: str | None = None) -> str:
    platform = os.name if platform is None else platform
    suffix = ".exe" if platform == "nt" else ""
    return f"defenseclaw-schema-test{suffix}"


def _timeout_diagnostics(label: str, exc: subprocess.TimeoutExpired) -> str:
    return (
        f"{label} exceeded its {exc.timeout:g}s timeout after its process tree "
        f"was terminated and reaped\nstdout:\n{_decode_process_output(exc.output)}"
        f"\nstderr:\n{_decode_process_output(exc.stderr)}"
    )


def _nonzero_diagnostics(label: str, result: subprocess.CompletedProcess[str], timeout: float) -> str:
    return (
        f"{label} failed with exit code {result.returncode} "
        f"(timeout budget: {timeout:g}s)\nstdout:\n{result.stdout}"
        f"\nstderr:\n{result.stderr}"
    )


class _GoTestBinary:
    """One disposable gateway/CLI executable built for schema tests."""

    def __init__(self, directory: tempfile.TemporaryDirectory[str], path: Path) -> None:
        self._directory = directory
        self.path = path
        self._closed = False

    @classmethod
    def build(cls, *, timeout: float = _GO_BUILD_TIMEOUT_SECONDS) -> _GoTestBinary:
        directory = tempfile.TemporaryDirectory(prefix="defenseclaw-go-schema-")
        build_dir = Path(directory.name).resolve()
        try:
            build_dir.relative_to(ROOT)
        except ValueError:
            pass
        else:
            directory.cleanup()
            raise RuntimeError("Go test binary directory must be outside the source tree")

        binary = build_dir / _go_test_binary_name()
        go_temp = build_dir / "go-tmp"
        go_temp.mkdir()
        build_env = os.environ.copy()
        build_env["GOTMPDIR"] = os.fspath(go_temp)
        argv = [
            "go",
            "build",
            "-trimpath",
            "-o",
            os.fspath(binary),
            "./cmd/defenseclaw",
        ]
        try:
            result = _run_captured_process(
                argv,
                cwd=ROOT,
                env=build_env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            directory.cleanup()
            raise RuntimeError(_timeout_diagnostics("Go test-binary build", exc)) from exc
        except BaseException:
            directory.cleanup()
            raise
        if result.returncode != 0:
            directory.cleanup()
            raise RuntimeError(_nonzero_diagnostics("Go test-binary build", result, timeout))
        if not binary.is_file():
            directory.cleanup()
            raise RuntimeError(f"Go build succeeded without creating {binary}")
        return cls(directory, binary)

    def scan_code(
        self,
        source: Path,
        *,
        home: Path,
        timeout: float = _SCAN_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(isolated_home_env(home))
        try:
            return _run_captured_process(
                [os.fspath(self.path), "scan", "code", os.fspath(source), "--json"],
                cwd=ROOT,
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(_timeout_diagnostics("Built scan-code command", exc)) from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._directory.cleanup()


class _GoTestBinaryFixture:
    """Lazily build once per Python process and clean up at interpreter exit."""

    def __init__(self, builder: Callable[[], _GoTestBinary] | None = None) -> None:
        self._builder = builder or _GoTestBinary.build
        self._binary: _GoTestBinary | None = None
        self._lock = threading.Lock()

    def get(self) -> _GoTestBinary:
        with self._lock:
            if self._binary is None:
                self._binary = self._builder()
            return self._binary

    def close(self) -> None:
        with self._lock:
            binary = self._binary
            self._binary = None
        if binary is not None:
            binary.close()


_GO_TEST_BINARY_FIXTURE = _GoTestBinaryFixture()
atexit.register(_GO_TEST_BINARY_FIXTURE.close)


class TestAlertsSubcommands(unittest.TestCase):
    """`defenseclaw alerts {acknowledge,dismiss}` should route through LogActivity."""

    CASES = [
        (["acknowledge", "--severity", "all"], "Acknowledged"),
        (["dismiss", "--severity", "HIGH"], "Dismissed"),
    ]

    def test_subcommands_route_through_log_activity(self) -> None:
        from defenseclaw.commands.cmd_alerts import alerts
        from defenseclaw.config import default_config
        from defenseclaw.context import AppContext

        for args, substr in self.CASES:
            with self.subTest(args=args, substr=substr):
                app = AppContext()
                app.cfg = default_config()
                app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
                store = MagicMock()
                store.acknowledge_alerts.return_value = 2
                store.dismiss_alerts_visible.return_value = 1
                app.store = store
                app.logger = MagicMock()

                runner = CliRunner()
                result = runner.invoke(alerts, args, obj=app, catch_exceptions=False)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn(substr, result.output)
                self.assertTrue(app.logger.log_activity.called)


class TestSettingsSave(unittest.TestCase):
    def test_settings_save_invokes_activity(self) -> None:
        from defenseclaw.commands.cmd_settings import settings_cmd
        from defenseclaw.config import default_config
        from defenseclaw.context import AppContext

        app = AppContext()
        app.cfg = default_config()
        app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
        os.makedirs(app.cfg.data_dir, exist_ok=True)
        app.store = MagicMock()
        app.logger = MagicMock()

        runner = CliRunner()
        result = runner.invoke(settings_cmd, ["save"], obj=app, catch_exceptions=False)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Saved configuration", result.output)
        self.assertTrue(app.logger.log_activity.called)

    def test_settings_save_reports_managed_permission_error_without_traceback(self) -> None:
        from defenseclaw.commands.cmd_settings import settings_cmd
        from defenseclaw.config import default_config
        from defenseclaw.context import AppContext

        app = AppContext()
        app.cfg = default_config()
        app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
        app.cfg.save = MagicMock(
            side_effect=PermissionError(
                "managed_enterprise config changes require operating-system administrator privileges"
            )
        )
        app.logger = MagicMock()

        result = CliRunner().invoke(
            settings_cmd,
            ["save"],
            obj=app,
            catch_exceptions=False,
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Failed to save config", result.output)
        self.assertIn("administrator privileges", result.output)
        self.assertNotIn("Traceback", result.output)
        app.logger.log_activity.assert_not_called()


class TestAibomProvenance(unittest.TestCase):
    def test_aibom_json_has_provenance(self) -> None:
        from defenseclaw.config import default_config
        from defenseclaw.inventory.claw_inventory import build_claw_aibom
        from defenseclaw.provenance import stamp_aibom_inventory

        cfg = default_config()
        inv = build_claw_aibom(cfg, live=False, categories={"skills"})
        stamp_aibom_inventory(inv, cfg)
        self.assertIn("provenance", inv)
        self.assertEqual(inv["provenance"]["schema_version"], 7)
        for item in inv.get("skills", []):
            self.assertIn("provenance", item)


@unittest.skipUnless(shutil.which("go"), "go not on PATH")
class TestGoScanCodeJSONSchema(unittest.TestCase):
    """The built gateway/CLI scan JSON must validate against the schema.

    Skipped when ``go`` or ``jsonschema`` is unavailable (the latter only
    ships in ``[dependency-groups] dev``); the Go e2e job covers the
    same contract from the Go side via ``test/e2e/v7_golden_events_test.go``.
    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        try:
            import jsonschema
        except ImportError as exc:
            raise unittest.SkipTest("jsonschema not installed (dev-only dependency)") from exc
        cls.jsonschema = jsonschema
        cls.go_binary = _GO_TEST_BINARY_FIXTURE.get()

    def test_go_scan_code_json_validates_schema(self) -> None:
        schema_path = ROOT / "schemas" / "scan-result.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.go"
            p.write_text('package x\nvar _ = "x"\n', encoding="utf-8")
            proc = self.go_binary.scan_code(
                p,
                home=Path(tmp),
            )
            self.assertEqual(
                proc.returncode,
                0,
                _nonzero_diagnostics("Built scan-code command", proc, _SCAN_TIMEOUT_SECONDS),
            )
            doc = json.loads(proc.stdout)
            self.jsonschema.validate(instance=doc, schema=schema)


class TestGoSchemaBinaryFixture(unittest.TestCase):
    def test_fixture_builds_once_and_reuses_binary(self) -> None:
        binary = MagicMock(spec=_GoTestBinary)
        builder = MagicMock(return_value=binary)
        fixture = _GoTestBinaryFixture(builder)

        self.assertIs(fixture.get(), binary)
        self.assertIs(fixture.get(), binary)
        builder.assert_called_once_with()

        fixture.close()
        binary.close.assert_called_once_with()

    def test_build_uses_unique_absolute_platform_binary_and_distinct_budget(self) -> None:
        captured: dict[str, object] = {}

        def successful_build(argv, *, cwd, env, timeout):
            captured.update(argv=list(argv), cwd=cwd, env=env, timeout=timeout)
            output = Path(argv[4])
            output.write_bytes(b"test binary")
            return subprocess.CompletedProcess(list(argv), 0, "", "")

        with patch(f"{__name__}._run_captured_process", side_effect=successful_build):
            binary = _GoTestBinary.build()
        try:
            argv = captured["argv"]
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[:4], ["go", "build", "-trimpath", "-o"])
            output = Path(argv[4])
            self.assertTrue(output.is_absolute())
            self.assertEqual(output.name, _go_test_binary_name())
            self.assertNotIn(ROOT, output.parents)
            self.assertEqual(captured["cwd"], ROOT)
            self.assertEqual(captured["env"]["GOTMPDIR"], os.fspath(output.parent / "go-tmp"))
            self.assertEqual(captured["timeout"], _GO_BUILD_TIMEOUT_SECONDS)
            self.assertNotEqual(_GO_BUILD_TIMEOUT_SECONDS, _SCAN_TIMEOUT_SECONDS)
        finally:
            build_dir = binary.path.parent
            binary.close()
        self.assertFalse(build_dir.exists())

    def test_windows_executable_name_and_process_flags(self) -> None:
        self.assertEqual(_go_test_binary_name("nt"), "defenseclaw-schema-test.exe")
        self.assertEqual(_go_test_binary_name("posix"), "defenseclaw-schema-test")
        self.assertEqual(
            _process_tree_popen_kwargs("nt"),
            {"creationflags": _CREATE_NO_WINDOW | _CREATE_SUSPENDED},
        )
        self.assertEqual(_process_tree_popen_kwargs("posix"), {"start_new_session": True})

    def test_compile_timeout_terminates_tree_and_removes_build_directory(self) -> None:
        process = MagicMock(spec=subprocess.Popen)
        process.pid = 1234
        process.communicate.side_effect = subprocess.TimeoutExpired(["go"], 0.01)
        owner = MagicMock(spec=_ProcessTreeOwner)
        owner.terminate.return_value = (b"partial-out", b"partial-err")
        build_dir: Path | None = None

        def capture_process(*args, **kwargs):
            nonlocal build_dir
            build_dir = Path(args[0][4]).parent
            return process

        with (
            patch(f"{__name__}.subprocess.Popen", side_effect=capture_process),
            patch(f"{__name__}._new_process_tree_owner", return_value=owner),
            self.assertRaisesRegex(RuntimeError, "Go test-binary build.*0.01s"),
        ):
            _GoTestBinary.build(timeout=0.01)

        owner.terminate.assert_called_once_with(process)
        owner.close.assert_called_once_with()
        self.assertIsNotNone(build_dir)
        self.assertFalse(build_dir.exists())

    def test_command_timeout_terminates_tree_and_preserves_diagnostics(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="go-schema-command-timeout-")
        binary_path = Path(directory.name).resolve() / _go_test_binary_name()
        binary_path.write_bytes(b"test binary")
        binary = _GoTestBinary(directory, binary_path)
        process = MagicMock(spec=subprocess.Popen)
        process.pid = 5678
        process.communicate.side_effect = subprocess.TimeoutExpired([os.fspath(binary_path)], 0.01)
        owner = MagicMock(spec=_ProcessTreeOwner)
        owner.terminate.return_value = (b"scan-out", b"scan-err")
        try:
            with (
                patch(f"{__name__}.subprocess.Popen", return_value=process),
                patch(f"{__name__}._new_process_tree_owner", return_value=owner),
                tempfile.TemporaryDirectory(prefix="go-schema-home-") as home,
                self.assertRaisesRegex(RuntimeError, "(?s)Built scan-code command.*scan-err"),
            ):
                binary.scan_code(Path(home) / "x.go", home=Path(home), timeout=0.01)
        finally:
            binary.close()

        owner.terminate.assert_called_once_with(process)
        owner.close.assert_called_once_with()

    def test_interruption_terminates_tree_and_reraises(self) -> None:
        process = MagicMock(spec=subprocess.Popen)
        process.pid = 9012
        process.communicate.side_effect = KeyboardInterrupt
        owner = MagicMock(spec=_ProcessTreeOwner)
        owner.terminate.return_value = (b"", b"")

        with (
            patch(f"{__name__}.subprocess.Popen", return_value=process),
            patch(f"{__name__}._new_process_tree_owner", return_value=owner),
            self.assertRaises(KeyboardInterrupt),
        ):
            _run_captured_process(
                ["go", "build"],
                cwd=ROOT,
                env=os.environ.copy(),
                timeout=1,
            )

        owner.terminate.assert_called_once_with(process)
        owner.close.assert_called_once_with()

    def test_nonzero_build_failure_reports_output_and_cleans_directory(self) -> None:
        build_dir: Path | None = None

        def failed_build(argv, *, cwd, env, timeout):
            nonlocal build_dir
            build_dir = Path(argv[4]).parent
            return subprocess.CompletedProcess(list(argv), 17, "compiler stdout", "compiler stderr")

        with (
            patch(f"{__name__}._run_captured_process", side_effect=failed_build),
            self.assertRaisesRegex(RuntimeError, "(?s)exit code 17.*compiler stdout.*compiler stderr"),
        ):
            _GoTestBinary.build()

        self.assertIsNotNone(build_dir)
        self.assertFalse(build_dir.exists())

    def test_posix_timeout_escalates_from_process_group_term_to_kill(self) -> None:
        process = MagicMock(spec=subprocess.Popen)
        process.pid = 2468
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["go"], _PROCESS_TERMINATE_GRACE_SECONDS),
            (b"out", b"err"),
        ]
        owner = _PosixProcessTreeOwner(process.pid)

        with patch(f"{__name__}._kill_process_group") as killpg:
            output = owner.terminate(process)

        self.assertEqual(output, (b"out", b"err"))
        self.assertEqual(
            killpg.call_args_list,
            [
                call(process.pid, _SIGTERM),
                call(process.pid, _SIGKILL),
            ],
        )

    def test_invalid_utf8_diagnostics_are_replaced_not_dropped(self) -> None:
        self.assertEqual(_decode_process_output(b"before\xffafter"), "before\ufffdafter")

    @unittest.skipUnless(os.name == "nt", "native Windows Job Object regression")
    def test_windows_timeout_reaps_compiler_shaped_child_tree(self) -> None:
        from defenseclaw.process_liveness import pid_alive

        child = "import time; time.sleep(60)"
        root = (
            "import os,pathlib,subprocess,sys,time; "
            f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
            "pathlib.Path(sys.argv[1]).write_text("
            "f'root={os.getpid()}\\nchild={p.pid}\\n',encoding='utf-8'); "
            "time.sleep(60)"
        )
        with tempfile.TemporaryDirectory(prefix="go-schema-tree-") as tmp:
            pid_file = Path(tmp) / "pids.txt"
            with self.assertRaises(subprocess.TimeoutExpired):
                _run_captured_process(
                    [sys.executable, "-c", root, os.fspath(pid_file)],
                    cwd=ROOT,
                    env=os.environ.copy(),
                    timeout=5,
                )
            pids = {
                key: int(value)
                for key, value in (line.split("=", 1) for line in pid_file.read_text(encoding="utf-8").splitlines())
            }
            deadline = time.monotonic() + 2
            while any(pid_alive(pid) for pid in pids.values()) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(
                {name: pid for name, pid in pids.items() if pid_alive(pid)},
                "timed-out process tree still has active Windows processes",
            )


class TestScanResultSchemaEmbedded(unittest.TestCase):
    def test_embedded_matches_repo_schema(self) -> None:
        emb = ROOT / "internal" / "cli" / "embed" / "scan-result.json"
        src = ROOT / "schemas" / "scan-result.json"
        self.assertEqual(emb.read_text(), src.read_text())


if __name__ == "__main__":
    unittest.main()
