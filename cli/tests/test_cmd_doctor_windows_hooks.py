"""Windows-native Codex/Claude Doctor hook validation regressions."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import defenseclaw.doctor_hooks as doctor_hooks

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import (
    _check_claudecode_hooks,
    _check_codex_hooks,
    _check_hook_contract_lock,
    _DoctorResult,
)
from defenseclaw.doctor_hooks import (
    _CLAUDE_REQUIRED_HOOKS,
    _CODEX_HOOK_SPECS,
    _codex_command_hook_hash,
    _codex_hook_state_key_source,
    _codex_policy_executable,
    _codex_trusted_hash,
    _commands_from_hooks,
    _inspect_codex_effective_hook_policy,
    _InspectionError,
    _packaged_windows_install_root,
    _read_claude_registry_policy,
    _split_windows,
    _validate_codex_hook_contract,
    resolve_windows_command,
    validate_windows_hook_registration,
)


class WindowsHookDoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="doctor-win-hooks-")
        self.root = Path(self.temp.name)
        self.profile = self.root / "Disposable Profile"
        self.install = self.profile / "DefenseClaw Install"
        self.data = self.profile / ".defenseclaw"
        self.install.mkdir(parents=True)
        self.data.mkdir()
        self.cfg = MagicMock()
        self.cfg.data_dir = str(self.data)
        self.policy_inspector = patch(
            "defenseclaw.doctor_hooks._codex_effective_policy_inspector",
            return_value=(False, "test effective requirements"),
        )
        self.policy_inspector_mock = self.policy_inspector.start()
        self.addCleanup(self.policy_inspector.stop)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_claude_managed_paths_use_program_files_known_folder(self) -> None:
        trusted = self.root / "Trusted Program Files"
        attacker = self.root / "Attacker Program Files"
        with (
            patch.dict(os.environ, {"ProgramFiles": str(attacker)}),
            patch(
                "defenseclaw.doctor_hooks._windows_known_folder_path",
                return_value=str(trusted),
            ),
        ):
            paths = doctor_hooks._default_claude_managed_settings_paths()

        self.assertEqual(paths, (str(trusted / "ClaudeCode" / "managed-settings.json"),))

    def test_claude_managed_paths_fail_closed_without_known_folder(self) -> None:
        with patch("defenseclaw.doctor_hooks._windows_known_folder_path", return_value=""):
            with self.assertRaisesRegex(_InspectionError, "trusted Windows Program Files"):
                doctor_hooks._default_claude_managed_settings_paths()

    @unittest.skipUnless(os.name == "nt", "Windows Known Folder contract")
    def test_known_folder_lookup_ignores_process_profile_overrides(self) -> None:
        folder_id = "f1b32785-6fba-4fcf-9d55-7b8e7f157091"
        expected = doctor_hooks._windows_known_folder_path(folder_id)
        self.assertTrue(expected)

        spoofed = str(self.root / "spoofed-local-app-data")
        with patch.dict(
            os.environ,
            {"LOCALAPPDATA": spoofed, "USERPROFILE": str(self.root / "spoofed-profile")},
        ):
            observed = doctor_hooks._windows_known_folder_path(folder_id)

        self.assertEqual(os.path.normcase(observed), os.path.normcase(expected))

    def _runtime(self, name: str = "defenseclaw-hook.exe", body: bytes | None = None) -> Path:
        path = self.install / name
        if body is None:
            body = b"MZfixture" if name.endswith(".exe") else b"rem defenseclaw-managed-hook v6\r\n"
        path.write_bytes(body)
        return path

    @staticmethod
    def _encoded_hook_command(
        runtime: Path, connector: str = "codex", *, legacy: bool = False, unqualified: bool = False
    ) -> str:
        literal = str(runtime).replace("'", "''")
        if legacy and unqualified:
            raise ValueError("legacy and unqualified fixtures are mutually exclusive")
        if legacy:
            script = (
                "$ErrorActionPreference='Stop'; "
                "$env:NoDefaultCurrentDirectoryInExePath='1'; "
                f"& '{literal}' hook --connector {connector}; exit $LASTEXITCODE"
            )
        else:
            start_process = "Start-Process" if unqualified else r"Microsoft.PowerShell.Management\Start-Process"
            script = (
                "$ErrorActionPreference='Stop'; "
                "$env:NoDefaultCurrentDirectoryInExePath='1'; "
                f"$hookProcess={start_process} -FilePath '{literal}' "
                f"-ArgumentList @('hook','--connector','{connector}') "
                "-NoNewWindow -Wait -PassThru; exit $hookProcess.ExitCode"
            )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
            f"-NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"
        )

    def _lock(
        self,
        connector: str,
        config: Path,
        *,
        version: str = "v6",
        contract: str | None = None,
        runtime_paths: list[str] | None = None,
    ) -> None:
        if contract is None:
            contract = "codex-hooks-v1" if connector == "codex" else "claudecode-hooks-v1"
        normalized_agent_version = {
            "codex-hooks-v1": "0.124.0",
            "codex-hooks-v2": "0.129.0",
            "codex-hooks-v3": "0.133.0",
            "claudecode-hooks-v1": "2.1.152",
        }[contract]
        locations = {"hook_config_paths": [str(config)]}
        if runtime_paths is not None:
            locations["hook_script_paths"] = runtime_paths
        (self.data / "hook_contract_lock.json").write_text(
            json.dumps(
                {
                    "version": 2,
                    "connectors": {
                        connector: {
                            "contract_id": contract,
                            "compatibility_status": "known",
                            "raw_agent_version": normalized_agent_version,
                            "normalized_agent_version": normalized_agent_version,
                            "hook_script_version": version,
                            "locations": locations,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    def _config(
        self,
        connector: str,
        command: str,
        *,
        extra_command: str = "",
        windows_command: str | None = None,
        codex_features: bool = True,
        codex_managed: bool = False,
    ) -> Path:
        if connector == "codex":
            path = self.profile / ".codex" / ("managed_config.toml" if codex_managed else "config.toml")
            path.parent.mkdir(exist_ok=True)
            selected_windows = windows_command or command
            escaped_extra = extra_command.replace("\\", "\\\\").replace('"', '\\"')
            escaped = command.replace("\\", "\\\\").replace('"', '\\"')
            escaped_windows = selected_windows.replace("\\", "\\\\").replace('"', '\\"')
            rows: list[str] = []
            trust_rows: list[tuple[str, str]] = []
            state_source = _codex_hook_state_key_source(str(path))
            for event, (event_key, matcher, timeout) in _CODEX_HOOK_SPECS.items():
                matcher_text = "" if matcher is None else f'matcher = "{matcher}", '
                groups = (
                    f'{event} = [{{ {matcher_text}hooks = [{{ type = "command", '
                    f'command = "{escaped}", command_windows = "{escaped_windows}", timeout = {timeout} }}] }}'
                )
                managed_handler = {
                    "type": "command",
                    "command": command,
                    "command_windows": selected_windows,
                    "timeout": timeout,
                }
                state_key = f"{state_source}:{event_key}:0:0"
                trust_rows.append((state_key, _codex_command_hook_hash(event_key, matcher, managed_handler)))
                if event == "PostToolUse" and escaped_extra:
                    groups += f', {{ hooks = [{{ type = "command", command = "{escaped_extra}", timeout = 30 }}] }}'
                rows.append(groups + "]")
            if not codex_managed:
                rows.extend(
                    [
                        "",
                        "[hooks.state]",
                        *(
                            f"{json.dumps(key)} = {{ trusted_hash = {json.dumps(trusted_hash)} }}"
                            for key, trusted_hash in trust_rows
                        ),
                    ]
                )
            path.write_text(
                (("[features]\nhooks = true\n\n" if codex_features else "") + "[hooks]\n") + "\n".join(rows) + "\n",
                encoding="utf-8",
            )
        else:
            path = self.profile / ".claude" / "settings.json"
            path.parent.mkdir(exist_ok=True)
            bare_exec = not any(token in command for token in (" hook ", "-File ", "-EncodedCommand "))
            events: dict[str, object] = {}
            for event, (matcher, timeout) in _CLAUDE_REQUIRED_HOOKS.items():
                handler: dict[str, object] = {"type": "command", "command": command, "timeout": timeout}
                if bare_exec:
                    handler["args"] = ["hook", "--connector", "claudecode"]
                if event == "MessageDisplay":
                    handler["async"] = True
                entry: dict[str, object] = {"hooks": [handler]}
                if matcher is not None:
                    entry["matcher"] = matcher
                events[event] = [entry]
            if extra_command:
                assert isinstance(events["PostToolUse"], list)
                events["PostToolUse"].append({"hooks": [{"type": "command", "command": extra_command, "timeout": 30}]})
            path.write_text(json.dumps({"hooks": events}), encoding="utf-8")
        self._lock(connector, path)
        return path

    def _validate(
        self,
        connector: str,
        config: Path,
        *,
        search_path: str = "",
        pathext: str = ".EXE;.CMD",
        managed_settings_paths: tuple[str, ...] | None = (),
        inspect_effective_policy: bool = True,
        workspace_dir: str = "",
        cli_settings: str | None = None,
        remote_settings_path: str | None = None,
        managed_enterprise: bool = False,
    ):
        return validate_windows_hook_registration(
            connector=connector,
            config_path=str(config),
            data_dir=str(self.data),
            install_root=str(self.install),
            search_path=search_path,
            pathext=pathext,
            claude_managed_settings_paths=managed_settings_paths,
            inspect_effective_policy=inspect_effective_policy,
            workspace_dir=workspace_dir,
            claude_cli_settings=cli_settings,
            claude_remote_settings_path=remote_settings_path,
            managed_enterprise=managed_enterprise,
        )

    def _contract_check(self, connector: str, config: Path) -> tuple[_DoctorResult, str]:
        obsolete = [
            str(self.data / "hooks" / "inspect-tool.sh"),
            str(self.data / "hooks" / ("codex-hook.sh" if connector == "codex" else "claude-code-hook.sh")),
        ]
        self._lock(connector, config, runtime_paths=obsolete)
        result = _DoctorResult()
        output = io.StringIO()
        previous = cmd_doctor._json_mode
        cmd_doctor._json_mode = False
        try:
            with (
                contextlib.redirect_stdout(output),
                patch("defenseclaw.inventory.agent_discovery._windows_acl_write_error", return_value=None),
                patch(
                    "defenseclaw.doctor_hooks._windows_known_folder_path",
                    return_value=str(self.root / "Trusted Program Files"),
                ),
                patch("defenseclaw.commands.cmd_doctor.subprocess.run") as run_mock,
            ):
                _check_hook_contract_lock(
                    self.cfg,
                    connector,
                    result,
                    platform_name="nt",
                    config_path=str(config),
                    install_root=str(self.install),
                    search_path=str(self.install),
                    pathext=".EXE;.CMD;.PS1",
                )
            run_mock.assert_not_called()
        finally:
            cmd_doctor._json_mode = previous
        return result, output.getvalue()

    def test_healthy_quoted_executable_path_with_spaces_for_claude(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("Windows-native executable", check.detail)
        self.assertIn("entries=28", check.detail)

    def test_native_stable_hook_runtime_is_accepted_for_codex_and_claude(self) -> None:
        local_app_data = self.root / "Local AppData"
        runtime = local_app_data / "DefenseClaw" / "HookRuntime" / "defenseclaw-hook.exe"
        runtime.parent.mkdir(parents=True)
        runtime.write_bytes(b"MZfixture")

        with (
            patch(
                "defenseclaw.doctor_hooks._windows_known_folder_path",
                return_value=str(local_app_data),
            ),
            patch("defenseclaw.inventory.agent_discovery._windows_acl_write_error", return_value=None),
        ):
            for connector in ("codex", "claudecode"):
                with self.subTest(connector=connector):
                    config = self._config(connector, f'"{runtime}" hook --connector {connector}')
                    check = self._validate(connector, config)
                    self.assertEqual(check.state, "healthy", check.detail)
                    self.assertEqual(os.path.normcase(check.target), os.path.normcase(str(runtime)))

    def test_healthy_claude_exec_form_with_path_spaces(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", str(runtime))
        document = json.loads(config.read_text(encoding="utf-8"))
        for entries in document["hooks"].values():
            entries[0]["hooks"][0]["args"] = ["hook", "--connector", "claudecode"]
        config.write_text(json.dumps(document), encoding="utf-8")

        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertEqual(os.path.normcase(check.target), os.path.normcase(str(runtime)))

    def test_claude_exec_form_rejects_malformed_args(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", str(runtime))
        document = json.loads(config.read_text(encoding="utf-8"))
        for entries in document["hooks"].values():
            entries[0]["hooks"][0]["args"] = "hook --connector claudecode"
        config.write_text(json.dumps(document), encoding="utf-8")

        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "malformed", check.detail)

    def test_codex_bare_executable_uses_safe_pathext_order(self) -> None:
        self._runtime("defenseclaw-hook.cmd")
        exe = self._runtime()
        command = "set NoDefaultCurrentDirectoryInExePath=1&& defenseclaw-hook hook --connector codex"
        config = self._config("codex", command)
        check = self._validate(
            "codex",
            config,
            search_path=str(self.install),
            pathext=".EXE;.CMD;.PS1",
        )
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertEqual(os.path.normcase(check.target), os.path.normcase(str(exe)))

    def test_codex_native_hash_matches_vendor_canonical_identity(self) -> None:
        self.assertEqual(
            _codex_command_hook_hash(
                "pre_tool_use",
                "*",
                {
                    "type": "command",
                    "command": "generic-command",
                    "command_windows": "windows-command",
                    "timeout": 30,
                    "async": False,
                    "statusMessage": "Checking DefenseClaw policy",
                },
            ),
            "sha256:00d233bf308896ec04f67e2fee61ac2962df3c0afbe80c9d8bc6975ec3697786",
        )

    def test_codex_native_hash_matches_go_encoder_for_line_separators(self) -> None:
        handler = {
            "type": "command",
            "command": "generic-command",
            "command_windows": "C:\\Tools\\line\u2028paragraph\u2029\\defenseclaw-hook.exe",
            "timeout": 30,
            "async": False,
            "statusMessage": "Checking\u2028DefenseClaw\u2029policy",
        }
        expected = "sha256:1534d4ba6c374c49c19398a340d64feee0a2d9639d7f2d42e03c6b1573623aac"

        # Cross-language fixture from Go's codexCommandHookHashForPlatform,
        # whose encoding/json serializer escapes U+2028 and U+2029.
        self.assertEqual(
            _codex_command_hook_hash("pre_tool_use", "PowerShell\u2028Command\u2029", handler),
            expected,
        )
        self.assertEqual(
            _codex_trusted_hash("pre_tool_use", "PowerShell\u2028Command\u2029", handler),
            expected,
        )

    def test_codex_current_contract_requires_exact_native_trust_matrix(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector codex'
        config = self._config("codex", command)
        document = tomllib.loads(config.read_text(encoding="utf-8"))
        state = document["hooks"]["state"]
        self._lock("codex", config, contract="codex-hooks-v3")

        check = self._validate("codex", config)
        self.assertEqual(check.state, "healthy", check.detail)

        tampered = config.read_text(encoding="utf-8").replace(
            next(iter(state.values()))["trusted_hash"],
            "sha256:" + "0" * 64,
            1,
        )
        config.write_text(tampered, encoding="utf-8")
        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("not trusted", check.detail)

    def test_codex_obsolete_gateway_precedes_current_contract_trust_mismatch(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector codex'
        config = self._config("codex", command)
        self._lock("codex", config, contract="codex-hooks-v3")

        obsolete = self._runtime("defenseclaw-gateway.exe")
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                str(runtime).replace("\\", "\\\\"), str(obsolete).replace("\\", "\\\\")
            ),
            encoding="utf-8",
        )

        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("obsolete gateway launcher", check.detail)
        self.assertIn("defenseclaw setup codex --yes --restart", check.detail)

    def test_codex_post_install_policy_change_and_inspection_failure_are_blocking(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        original = config.read_bytes()

        healthy = self._validate("codex", config)
        self.assertEqual(healthy.state, "healthy", healthy.detail)

        with patch(
            "defenseclaw.doctor_hooks._codex_effective_policy_inspector",
            return_value=(True, "changed cloud requirements"),
        ):
            blocked = self._validate("codex", config)
        self.assertEqual(blocked.state, "policy-blocked", blocked.detail)
        self.assertIn("allow_managed_hooks_only=true", blocked.detail)
        self.assertIn("changed cloud requirements", blocked.detail)

        with patch(
            "defenseclaw.doctor_hooks._codex_effective_policy_inspector",
            side_effect=OSError("app-server unavailable"),
        ):
            unavailable = self._validate("codex", config)
        self.assertEqual(unavailable.state, "policy-blocked", unavailable.detail)
        self.assertIn("cannot inspect effective Codex policy", unavailable.detail)
        self.assertEqual(config.read_bytes(), original)

    def test_passive_codex_registration_check_never_starts_policy_inspector(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        self.policy_inspector_mock.reset_mock()

        check = self._validate("codex", config, inspect_effective_policy=False)

        self.assertTrue(check.healthy, check.detail)
        self.policy_inspector_mock.assert_not_called()

    def test_codex_effective_policy_inspector_uses_bounded_app_server_rpc(self) -> None:
        class RecordingBytesIO(io.BytesIO):
            recorded = b""
            bytes_read = 0

            def read(self, size: int = -1) -> bytes:
                value = super().read(size)
                self.bytes_read += len(value)
                return value

            def close(self) -> None:
                self.recorded = self.getvalue()
                super().close()

        stdin = RecordingBytesIO()
        stdout = io.BytesIO(
            b'{"id":1,"result":{"codexHome":"C:\\\\Users\\\\test\\\\.codex"}}\n'
            b'{"id":2,"result":{"requirements":{"allowManagedHooksOnly":true}}}\n'
        )
        stderr = RecordingBytesIO(b"x" * (96 * 1024))
        process = SimpleNamespace(
            pid=1234,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            poll=MagicMock(return_value=0),
            wait=MagicMock(return_value=0),
            terminate=MagicMock(),
            kill=MagicMock(),
        )
        job = MagicMock()
        job.terminate_sync.return_value = True
        executable = str(self.install / "codex.exe")
        config = self.profile / ".codex" / "config.toml"
        with (
            patch("defenseclaw.doctor_hooks._codex_policy_executable", return_value=executable),
            patch("defenseclaw.doctor_hooks.subprocess.Popen", return_value=process) as popen,
            patch("defenseclaw.tui.windows_process.WindowsJob", return_value=job) as job_type,
        ):
            managed_only, source = _inspect_codex_effective_hook_policy(str(self.data), str(config))

        self.assertTrue(managed_only)
        self.assertIn(executable, source)
        messages = [json.loads(line) for line in stdin.recorded.splitlines()]
        self.assertEqual(
            [message.get("method") for message in messages],
            [
                "initialize",
                "initialized",
                "configRequirements/read",
            ],
        )
        popen.assert_called_once()
        argv = popen.call_args.args[0]
        self.assertEqual(argv, [executable, "app-server", "--stdio"])
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(popen.call_args.kwargs["env"]["CODEX_HOME"], str(config.parent))
        creationflags = popen.call_args.kwargs["creationflags"]
        if os.name == "nt":
            self.assertTrue(creationflags & getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self.assertTrue(creationflags & getattr(subprocess, "CREATE_SUSPENDED", 0x00000004))
        else:
            self.assertEqual(creationflags, 0)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        if os.name == "nt":
            job_type.assert_called_once_with(1234, allow_breakaway=False)
            job.terminate_sync.assert_called_once_with(timeout=2)
            job.close.assert_called_once()
        else:
            job_type.assert_not_called()
            job.terminate_sync.assert_not_called()
            job.close.assert_not_called()
        self.assertEqual(stderr.bytes_read, 96 * 1024)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object cleanup contract")
    def test_codex_policy_cleanup_closes_nonempty_job_before_descendant_held_pipes(self) -> None:
        job_closed = threading.Event()

        class JobHeldStdout:
            def __init__(self) -> None:
                self.responses = iter(
                    (
                        b'{"id":1,"result":{}}\n',
                        b'{"id":2,"result":{"requirements":null}}\n',
                    )
                )
                self.closed = False

            def readline(self, _limit: int) -> bytes:
                try:
                    return next(self.responses)
                except StopIteration:
                    job_closed.wait(5)
                    return b""

            def close(self) -> None:
                if not job_closed.is_set():
                    raise AssertionError("stdout closed before kill-on-close Job handle")
                self.closed = True

        class JobHeldStderr:
            def __init__(self) -> None:
                self.closed = False

            def read(self, _size: int) -> bytes:
                job_closed.wait(5)
                return b""

            def close(self) -> None:
                if not job_closed.is_set():
                    raise AssertionError("stderr closed before kill-on-close Job handle")
                self.closed = True

        stdin = io.BytesIO()
        stdout = JobHeldStdout()
        stderr = JobHeldStderr()
        process = SimpleNamespace(
            pid=1234,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            poll=MagicMock(return_value=0),
            wait=MagicMock(return_value=0),
            terminate=MagicMock(),
            kill=MagicMock(),
        )
        job = MagicMock()
        job.terminate_sync.return_value = False
        job.close.side_effect = job_closed.set
        executable = str(self.install / "codex.exe")
        config = self.profile / ".codex" / "config.toml"

        with (
            patch("defenseclaw.doctor_hooks._codex_policy_executable", return_value=executable),
            patch("defenseclaw.doctor_hooks.subprocess.Popen", return_value=process),
            patch("defenseclaw.tui.windows_process.WindowsJob", return_value=job),
            self.assertRaises(_InspectionError) as raised,
        ):
            _inspect_codex_effective_hook_policy(str(self.data), str(config))

        self.assertIn("Job Object did not become empty", raised.exception.detail)
        job.close.assert_called_once()
        self.assertTrue(stdout.closed)
        self.assertTrue(stderr.closed)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object cleanup contract")
    def test_codex_policy_cleanup_preserves_primary_rpc_error(self) -> None:
        process = SimpleNamespace(
            pid=1234,
            stdin=io.BytesIO(),
            stdout=io.BytesIO(b'{"id":1,"result":{}}\n{"id":2,"error":{"code":-32000,"message":"primary failure"}}\n'),
            stderr=io.BytesIO(),
            poll=MagicMock(return_value=0),
            wait=MagicMock(return_value=0),
            terminate=MagicMock(),
            kill=MagicMock(),
        )
        job = MagicMock()
        job.terminate_sync.side_effect = OSError("secondary cleanup failure")
        executable = str(self.install / "codex.exe")
        config = self.profile / ".codex" / "config.toml"

        with (
            patch("defenseclaw.doctor_hooks._codex_policy_executable", return_value=executable),
            patch("defenseclaw.doctor_hooks.subprocess.Popen", return_value=process),
            patch("defenseclaw.tui.windows_process.WindowsJob", return_value=job),
            self.assertRaises(_InspectionError) as raised,
        ):
            _inspect_codex_effective_hook_policy(str(self.data), str(config))

        self.assertIn("Codex policy RPC 2 failed", raised.exception.detail)
        self.assertIn("primary failure", raised.exception.detail)
        self.assertNotIn("secondary cleanup failure", raised.exception.detail)
        job.close.assert_called_once()

    def test_codex_policy_executable_admits_exact_setup_selected_lock_evidence(self) -> None:
        executable = self.install / "codex.exe"
        executable.write_bytes(b"MZnative-codex")
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        lock = {
            "version": 2,
            "connectors": {
                "codex": {
                    "contract_id": "codex-hooks-v3",
                    "compatibility_status": "known",
                    "raw_agent_version": "codex-cli 0.144.3",
                    "normalized_agent_version": "0.144.3",
                    "agent_executable": str(executable),
                    "agent_executable_source": "setup-selected",
                    "agent_executable_sha256": digest,
                }
            },
        }
        (self.data / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
        with (
            patch("defenseclaw.inventory.agent_discovery._windows_acl_write_error", return_value=None),
            patch("defenseclaw.agent_selection.is_setup_trusted_binary", return_value=True),
            patch("defenseclaw.agent_selection.stable_executable_sha256", return_value=digest),
        ):
            selected = _codex_policy_executable(str(self.data))

        self.assertEqual(os.path.normcase(selected), os.path.normcase(str(executable)))

    def test_codex_policy_executable_rejects_command_processor_wrapper(self) -> None:
        executable = self.install / "codex.cmd"
        executable.write_text("@echo off\r\n", encoding="utf-8")
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        lock = {
            "version": 2,
            "connectors": {
                "codex": {
                    "contract_id": "codex-hooks-v3",
                    "compatibility_status": "known",
                    "raw_agent_version": "codex-cli 0.144.3",
                    "normalized_agent_version": "0.144.3",
                    "agent_executable": str(executable),
                    "agent_executable_source": "setup-selected",
                    "agent_executable_sha256": digest,
                }
            },
        }
        (self.data / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")

        with self.assertRaises(_InspectionError) as raised:
            _codex_policy_executable(str(self.data))

        self.assertEqual(raised.exception.state, "policy-blocked")
        self.assertIn("native Windows .exe", raised.exception.detail)

    def test_codex_policy_executable_never_uses_automatic_discovery_cache(self) -> None:
        (self.data / "agent_discovery.json").write_text(
            json.dumps({"agents": {"codex": {"binary_path": str(self.install / "codex.cmd")}}}),
            encoding="utf-8",
        )
        with self.assertRaises(_InspectionError) as raised:
            _codex_policy_executable(str(self.data))

        self.assertEqual(raised.exception.state, "policy-blocked")
        self.assertIn("protected Codex executable evidence", raised.exception.detail)

    def test_codex_registration_ignores_stale_discovery_wrapper_after_protected_policy_check(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        wrapper = self.root / "node" / "codex.CMD"
        wrapper.parent.mkdir()
        wrapper.write_text("@echo off\r\n", encoding="utf-8")
        (self.data / "agent_discovery.json").write_text(
            json.dumps({"agents": {"codex": {"installed": True, "binary_path": str(wrapper)}}}),
            encoding="utf-8",
        )

        check = self._validate("codex", config)

        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("policy=test effective requirements", check.detail)
        self.policy_inspector_mock.assert_called_once_with(str(self.data), str(config))

    def test_codex_contract_lock_cannot_downgrade_a_current_agent(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        lock_path = self.data / "hook_contract_lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["connectors"]["codex"]["normalized_agent_version"] = "0.144.3"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

        check = self._validate("codex", config)

        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("does not match the recorded agent version", check.detail)

    def test_codex_requires_complete_exact_installed_hook_matrix(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector codex'
        mutations = {
            "missing-event": lambda document: document["hooks"].pop("PermissionRequest"),
            "narrow-matcher": lambda document: document["hooks"]["PreToolUse"][0].update({"matcher": "Bash"}),
            "async-enforcement": lambda document: document["hooks"]["PreToolUse"][0]["hooks"][0].update(
                {"async": True}
            ),
            "wrong-timeout": lambda document: document["hooks"]["Stop"][0]["hooks"][0].update({"timeout": 30}),
            "split-native-identity": lambda document: document["hooks"]["PreToolUse"][0]["hooks"][0].update(
                {"command_windows": command + " --different"}
            ),
            "duplicate-owned-handler": lambda document: document["hooks"]["PreToolUse"][0]["hooks"].append(
                dict(document["hooks"]["PreToolUse"][0]["hooks"][0])
            ),
            "unexpected-owned-event": lambda document: document["hooks"].update(
                {"FutureEvent": document["hooks"]["PreToolUse"]}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                config = self._config("codex", command)
                document = tomllib.loads(config.read_text(encoding="utf-8"))
                mutate(document)

                with self.assertRaises(_InspectionError) as raised:
                    _validate_codex_hook_contract(document, "codex-hooks-v1", str(config))

                self.assertEqual(raised.exception.state, "stale")

    def test_codex_explicitly_disabled_hooks_raise_malformed(self) -> None:
        document = {
            "features": {"hooks": False},
            "hooks": {"PreToolUse": [{"hooks": [{"command": "defenseclaw-hook.exe hook --connector codex"}]}]},
        }

        with self.assertRaises(_InspectionError) as raised:
            _commands_from_hooks(document, "codex")

        self.assertEqual(raised.exception.state, "malformed")
        self.assertIn("explicitly disabled", raised.exception.detail)

    def test_healthy_codex_synchronous_encoded_invocation(self) -> None:
        runtime = self._runtime()
        command = self._encoded_hook_command(runtime)
        config = self._config("codex", command, codex_features=False)

        check = self._validate("codex", config)

        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("Windows-native executable", check.detail)

    def test_codex_legacy_non_waiting_encoded_invocation_requires_repair(self) -> None:
        runtime = self._runtime()
        command = self._encoded_hook_command(runtime, legacy=True)
        config = self._config("codex", command, codex_features=False)

        check = self._validate("codex", config)

        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("legacy non-waiting launcher", check.detail)
        self.assertIn("repair", check.detail)

    def test_codex_unqualified_start_process_invocation_requires_repair(self) -> None:
        runtime = self._runtime()
        command = self._encoded_hook_command(runtime, unqualified=True)
        config = self._config("codex", command, codex_features=False)

        check = self._validate("codex", config)

        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("unqualified Start-Process launcher", check.detail)
        self.assertIn("repair", check.detail)

    def test_codex_command_windows_encoded_invocation_without_feature_override(self) -> None:
        runtime = self._runtime()
        command = self._encoded_hook_command(runtime)
        config = self._config(
            "codex",
            f'"{runtime}" hook --connector codex',
            windows_command=command,
            codex_features=False,
        )

        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("not byte-identical", check.detail)

    def test_codex_encoded_obsolete_gateway_is_classified_as_stale(self) -> None:
        legacy = self._runtime("defenseclaw-gateway.exe")
        command = self._encoded_hook_command(legacy)
        config = self._config(
            "codex",
            command,
            windows_command=command,
            codex_features=False,
        )

        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("obsolete gateway launcher", check.detail)

    def test_healthy_managed_cmd_registration(self) -> None:
        runtime = self._runtime("defenseclaw-hook.cmd")
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("Windows-native CMD", check.detail)

    def test_healthy_managed_powershell_registration(self) -> None:
        runtime = self._runtime(
            "defenseclaw-hook.ps1",
            b"# defenseclaw-managed-hook v6\n# passive wrapper fixture\n",
        )
        command = f'powershell.exe -NoProfile -NonInteractive -File "{runtime}" hook --connector claudecode'
        config = self._config("claudecode", command)
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("Windows-native PowerShell", check.detail)

    def test_powershell_registration_rejects_unsafe_launcher_switches(self) -> None:
        runtime = self._runtime(
            "defenseclaw-hook.ps1",
            b"# defenseclaw-managed-hook v6\n# passive wrapper fixture\n",
        )
        for switch, value in (("-Command", "ignored"), ("-EncodedCommand", "Zg==")):
            with self.subTest(switch=switch):
                command = (
                    f"powershell.exe -NoProfile -NonInteractive {switch} {value} "
                    f'-File "{runtime}" hook --connector claudecode'
                )
                config = self._config("claudecode", command)
                check = self._validate("claudecode", config)
                self.assertEqual(check.state, "malformed")
                self.assertIn("unsupported launcher arguments", check.detail)

    def test_stale_wrapper_version_is_rejected(self) -> None:
        runtime = self._runtime("defenseclaw-hook.cmd", b"rem defenseclaw-managed-hook v5\r\n")
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale")
        self.assertIn("expected v6", check.detail)

    def test_unrelated_foreign_hook_is_preserved_beside_managed_hook(self) -> None:
        runtime = self._runtime()
        managed = f'"{runtime}" hook --connector claudecode'
        config = self._config("claudecode", managed, extra_command='"C:\\Tools\\formatter.exe" --quiet')
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "healthy", check.detail)

    def test_codex_complete_contract_allows_unrelated_foreign_hook(self) -> None:
        runtime = self._runtime()
        managed = f'"{runtime}" hook --connector codex'
        config = self._config("codex", managed, extra_command='"C:\\Tools\\formatter.exe" --quiet')

        check = self._validate("codex", config)

        self.assertEqual(check.state, "healthy", check.detail)

    def test_foreign_hook_with_managed_text_is_not_classified_as_owned(self) -> None:
        runtime = self._runtime()
        managed = f'"{runtime}" hook --connector claudecode'
        foreign = '"C:\\Tools\\formatter.exe" --label "hook --connector claudecode"'
        config = self._config("claudecode", managed, extra_command=foreign)

        check = self._validate("claudecode", config)

        self.assertEqual(check.state, "healthy", check.detail)

    def test_claude_requires_complete_broad_hook_contract_with_exact_execution_modes(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector claudecode'
        mutations = {
            "notification-only": lambda document: document.update(
                {"hooks": {"Notification": document["hooks"]["Notification"]}}
            ),
            "missing-pretooluse": lambda document: document["hooks"].pop("PreToolUse"),
            "narrow-pretooluse": lambda document: document["hooks"]["PreToolUse"][0].update({"matcher": "Bash"}),
            "whitespace-pretooluse": lambda document: document["hooks"]["PreToolUse"][0].update({"matcher": " * "}),
            "async-pretooluse": lambda document: document["hooks"]["PreToolUse"][0]["hooks"][0].update({"async": True}),
            "sync-message-display": lambda document: document["hooks"]["MessageDisplay"][0]["hooks"][0].update(
                {"async": False}
            ),
            "async-rewake-pretooluse": lambda document: document["hooks"]["PreToolUse"][0]["hooks"][0].update(
                {"asyncRewake": True}
            ),
            "async-rewake-message-display": lambda document: document["hooks"]["MessageDisplay"][0]["hooks"][0].update(
                {"asyncRewake": True}
            ),
            "non-command-pretooluse": lambda document: document["hooks"]["PreToolUse"][0]["hooks"][0].update(
                {"type": "http"}
            ),
            "conditional-pretooluse": lambda document: document["hooks"]["PreToolUse"][0]["hooks"][0].update(
                {"if": "Bash(git *)"}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                config = self._config("claudecode", command)
                document = json.loads(config.read_text(encoding="utf-8"))
                mutate(document)
                config.write_text(json.dumps(document), encoding="utf-8")
                check = self._validate("claudecode", config)
                self.assertNotEqual(check.state, "healthy", check.detail)
                self.assertIn("repair", check.detail)

    def test_claude_accepts_effective_matcher_supersets_and_ignored_matchers(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector claudecode'
        mutations = {
            "file-changed-superset": lambda document: document["hooks"]["FileChanged"][0].update(
                {"matcher": document["hooks"]["FileChanged"][0]["matcher"] + "|README.md"}
            ),
            "stop-matcher-is-ignored": lambda document: document["hooks"]["Stop"][0].update(
                {"matcher": "ignored-by-claude"}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                config = self._config("claudecode", command)
                document = json.loads(config.read_text(encoding="utf-8"))
                mutate(document)
                config.write_text(json.dumps(document), encoding="utf-8")

                check = self._validate("claudecode", config)

                self.assertEqual(check.state, "healthy", check.detail)

    def test_claude_reports_disable_all_hooks_as_policy_blocked(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        document = json.loads(config.read_text(encoding="utf-8"))
        document["disableAllHooks"] = True
        config.write_text(json.dumps(document), encoding="utf-8")

        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("disableAllHooks", check.detail)

    def test_claude_reports_locally_inspectable_managed_policy_blockers(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector claudecode'
        policy_path = self.root / "managed-settings.json"
        for policy, evidence in (
            ({"allowManagedHooksOnly": True}, "allowManagedHooksOnly"),
            ({"strictPluginOnlyCustomization": ["hooks"]}, "plugins or managed settings"),
            ({"disableAllHooks": True}, "disableAllHooks"),
            ({"policyHelper": "C:\\Program Files\\Policy\\helper.exe"}, "dynamic policyHelper"),
        ):
            with self.subTest(policy=policy):
                config = self._config("claudecode", command)
                policy_path.write_text(json.dumps(policy), encoding="utf-8")
                check = self._validate(
                    "claudecode",
                    config,
                    managed_settings_paths=(str(policy_path),),
                )
                self.assertEqual(check.state, "policy-blocked", check.detail)
                self.assertIn(evidence, check.detail)

    def test_claude_managed_policy_merge_and_precedence_are_applied(self) -> None:
        runtime = self._runtime()
        command = f'"{runtime}" hook --connector claudecode'
        config = self._config("claudecode", command)
        base = self.root / "managed-settings.json"
        dropin = self.root / "20-security.json"
        base.write_text(json.dumps({"strictPluginOnlyCustomization": ["hooks"]}), encoding="utf-8")
        dropin.write_text(json.dumps({"strictPluginOnlyCustomization": ["skills"]}), encoding="utf-8")
        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(base), str(dropin)),
        )
        self.assertEqual(check.state, "policy-blocked", check.detail)

        document = json.loads(config.read_text(encoding="utf-8"))
        document["disableAllHooks"] = True
        config.write_text(json.dumps(document), encoding="utf-8")
        base.write_text(json.dumps({"disableAllHooks": False}), encoding="utf-8")
        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(base),),
        )
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("user settings sets disableAllHooks=true", check.detail)

    def test_claude_reads_windows_registry_managed_policy_without_executing_it(self) -> None:
        key = MagicMock()
        key.__enter__.return_value = key
        fake_winreg = SimpleNamespace(
            HKEY_LOCAL_MACHINE=object(),
            KEY_READ=1,
            KEY_WOW64_64KEY=2,
            REG_SZ=3,
            REG_EXPAND_SZ=4,
            OpenKey=MagicMock(return_value=key),
            QueryValueEx=MagicMock(return_value=(json.dumps({"allowManagedHooksOnly": True}), 3)),
        )
        with (
            patch.dict(sys.modules, {"winreg": fake_winreg}),
            patch("defenseclaw.doctor_hooks.os.name", "nt"),
        ):
            policy = _read_claude_registry_policy("HKEY_LOCAL_MACHINE")
        self.assertEqual(policy, {"allowManagedHooksOnly": True})
        fake_winreg.OpenKey.assert_called_once()

        fake_winreg.QueryValueEx.return_value = ("   ", 3)
        with (
            patch.dict(sys.modules, {"winreg": fake_winreg}),
            patch("defenseclaw.doctor_hooks.os.name", "nt"),
        ):
            policy = _read_claude_registry_policy("HKEY_LOCAL_MACHINE")
        self.assertIsNone(policy)

    def test_claude_ignores_policy_helper_from_hkcu_user_settings(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')

        def registry_policy(hive_name: str):
            if hive_name == "HKEY_CURRENT_USER":
                return {"policyHelper": "C:\\Users\\me\\untrusted-policy-helper.exe"}
            return None

        with (
            patch("defenseclaw.doctor_hooks._read_claude_registry_policy", side_effect=registry_policy),
            patch("defenseclaw.doctor_hooks._default_claude_managed_settings_paths", return_value=()),
        ):
            check = self._validate("claudecode", config, managed_settings_paths=None)

        self.assertEqual(check.state, "healthy", check.detail)

    def test_claude_workspace_and_cli_sources_follow_precedence(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        workspace = self.root / "workspace"
        settings_dir = workspace / ".claude"
        settings_dir.mkdir(parents=True)
        project = settings_dir / "settings.json"
        local = settings_dir / "settings.local.json"
        project.write_text(json.dumps({"disableAllHooks": True}), encoding="utf-8")

        check = self._validate("claudecode", config, workspace_dir=str(workspace))
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn(str(project), check.detail)

        local.write_text(json.dumps({"disableAllHooks": False}), encoding="utf-8")
        check = self._validate("claudecode", config, workspace_dir=str(workspace))
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn(f"workspace={workspace}", check.detail)

        check = self._validate(
            "claudecode",
            config,
            workspace_dir=str(workspace),
            cli_settings=json.dumps({"disableAllHooks": True}),
        )
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("CLI --settings", check.detail)

    def test_claude_remote_source_replaces_lower_managed_tiers(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        managed = self.root / "managed-settings.json"
        managed.write_text(json.dumps({"allowManagedHooksOnly": False}), encoding="utf-8")
        remote = self.root / "remote-settings.json"
        remote.write_text(json.dumps({"allowManagedHooksOnly": True}), encoding="utf-8")

        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(managed),),
            remote_settings_path=str(remote),
        )
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("remote/server-managed settings", check.detail)
        self.assertIn(str(remote), check.detail)

    def test_claude_policy_helper_only_blocks_when_its_file_tier_is_active(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        managed = self.root / "managed-settings.json"
        managed.write_text(
            json.dumps({"policyHelper": {"path": r"C:\Program Files\Policy\helper.exe"}}),
            encoding="utf-8",
        )
        remote = self.root / "remote-settings.json"
        remote.write_text(json.dumps({"allowManagedHooksOnly": False}), encoding="utf-8")

        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(managed),),
            remote_settings_path=str(remote),
        )
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("remote/server-managed settings", check.detail)

        remote.write_text("{}", encoding="utf-8")
        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(managed),),
            remote_settings_path=str(remote),
        )
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("dynamic policyHelper", check.detail)
        self.assertIn(str(managed), check.detail)

    def test_claude_managed_enterprise_validates_the_winning_hook_matrix(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", str(runtime))
        document = json.loads(config.read_text(encoding="utf-8"))
        for groups in document["hooks"].values():
            for group in groups:
                for handler in group["hooks"]:
                    handler["args"].append("--enterprise-managed")
        config.write_text(json.dumps(document), encoding="utf-8")

        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(config),),
            managed_enterprise=True,
        )
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("managed_source=explicit managed settings", check.detail)

        remote = self.root / "remote-settings.json"
        remote.write_text(json.dumps({"model": "remote-wins"}), encoding="utf-8")
        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(config),),
            remote_settings_path=str(remote),
            managed_enterprise=True,
        )
        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("remote/server-managed settings", check.detail)
        self.assertIn("no hooks table", check.detail)

        remote.write_text("{}", encoding="utf-8")
        check = self._validate(
            "claudecode",
            config,
            managed_settings_paths=(str(config),),
            remote_settings_path=str(remote),
            managed_enterprise=True,
        )
        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("managed_source=explicit managed settings", check.detail)

    def test_claude_managed_enterprise_rejects_hkcu_hook_authority(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", str(runtime))
        document = json.loads(config.read_text(encoding="utf-8"))
        for groups in document["hooks"].values():
            for group in groups:
                for handler in group["hooks"]:
                    handler["args"].append("--enterprise-managed")

        def registry_policy(hive_name: str):
            return document if hive_name == "HKEY_CURRENT_USER" else None

        with (
            patch("defenseclaw.doctor_hooks._read_claude_registry_policy", side_effect=registry_policy),
            patch("defenseclaw.doctor_hooks._default_claude_managed_settings_paths", return_value=()),
        ):
            check = self._validate(
                "claudecode",
                config,
                managed_settings_paths=None,
                managed_enterprise=True,
            )

        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn("administrator-managed settings source", check.detail)

    def test_codex_requires_complete_trusted_event_matrix(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        body = config.read_text(encoding="utf-8")
        config.write_text(
            "\n".join(line for line in body.splitlines() if not line.startswith("Stop = ")) + "\n",
            encoding="utf-8",
        )
        check = self._validate("codex", config)
        self.assertEqual(check.state, "missing", check.detail)
        self.assertIn("Stop", check.detail)

        config = self._config("codex", f'"{runtime}" hook --connector codex')
        body = config.read_text(encoding="utf-8")
        config.write_text(body.replace('trusted_hash = "sha256:', 'trusted_hash = "sha256:0', 1), encoding="utf-8")
        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("not trusted", check.detail)

    def test_codex_rejects_non_command_handler(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        body = config.read_text(encoding="utf-8")
        config.write_text(body.replace('type = "command"', 'type = "http"', 1), encoding="utf-8")
        check = self._validate("codex", config)
        self.assertEqual(check.state, "malformed", check.detail)
        self.assertIn("type", check.detail)

    def test_claude_requires_command_type_and_rejects_async_rewake(self) -> None:
        runtime = self._runtime()
        for key, on_group in (("asyncRewake", False), ("async_rewake", True)):
            with self.subTest(key=key, on_group=on_group):
                config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
                document = json.loads(config.read_text(encoding="utf-8"))
                group = document["hooks"]["PreToolUse"][0]
                target = group if on_group else group["hooks"][0]
                target[key] = True
                config.write_text(json.dumps(document), encoding="utf-8")
                check = self._validate("claudecode", config)
                self.assertEqual(check.state, "stale", check.detail)
                self.assertIn(key, check.detail)

        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        document = json.loads(config.read_text(encoding="utf-8"))
        document["hooks"]["PreToolUse"][0]["hooks"][0]["type"] = "http"
        config.write_text(json.dumps(document), encoding="utf-8")
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "malformed", check.detail)

    def test_claude_message_display_must_be_observational_async(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        document = json.loads(config.read_text(encoding="utf-8"))
        document["hooks"]["MessageDisplay"][0]["hooks"][0]["async"] = False
        config.write_text(json.dumps(document), encoding="utf-8")
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "stale", check.detail)
        self.assertIn("MessageDisplay", check.detail)

    def test_codex_managed_only_policy_is_reported_from_exact_source(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        requirements = self.root / "ProgramData" / "OpenAI" / "Codex" / "requirements.toml"
        requirements.parent.mkdir(parents=True)
        requirements.write_text("allow_managed_hooks_only = true\n", encoding="utf-8")
        self.policy_inspector_mock.return_value = (True, str(requirements))

        check = self._validate("codex", config)

        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn(str(requirements), check.detail)
        self.assertIn("allow_managed_hooks_only=true", check.detail)

    def test_codex_managed_source_is_automatically_trusted_without_state(self) -> None:
        runtime = self._runtime()
        config = self._config(
            "codex",
            f'"{runtime}" hook --connector codex',
            codex_managed=True,
        )
        self._lock("codex", config, contract="codex-hooks-v3")
        requirements = self.root / "ProgramData" / "OpenAI" / "Codex" / "requirements.toml"
        self.policy_inspector_mock.return_value = (True, str(requirements))

        self.assertNotIn("trusted_hash", config.read_text(encoding="utf-8"))
        check = self._validate("codex", config)

        self.assertEqual(check.state, "healthy", check.detail)
        self.assertIn("source-trusted from managed_config.toml", check.detail)
        self.assertIn(str(requirements), check.detail)

    def test_codex_cloud_effective_policy_uses_protected_setup_binary(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        codex = self.root / "Codex" / "codex.exe"
        codex.parent.mkdir()
        codex.write_bytes(b"MZ")
        source = f"Codex app-server {codex} effective requirements"
        self.policy_inspector_mock.return_value = (True, source)

        check = self._validate("codex", config)

        self.assertEqual(check.state, "policy-blocked", check.detail)
        self.assertIn(source, check.detail)
        self.policy_inspector_mock.assert_called_once_with(str(self.data), str(config))

    def test_missing_registrations_have_only_native_repair_guidance(self) -> None:
        for connector, filename, repair in (
            ("codex", "missing.toml", "setup codex --yes --restart"),
            ("claudecode", "missing.json", "setup claude-code --yes --restart"),
        ):
            with self.subTest(connector=connector):
                check = self._validate(connector, self.root / filename)
                self.assertEqual(check.state, "missing")
                self.assertIn(repair, check.detail)
                self.assertNotRegex(
                    check.detail.lower(),
                    r"\.sh\b|\bchmod\b|\bbash\b|\bwsl\b|\bunset\b|hook script",
                )

    def test_malformed_arguments_are_rejected(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector claudecode')
        check = self._validate("codex", config)
        self.assertEqual(check.state, "foreign")

        config = self._config("codex", f'"{runtime}" hook --connector codex --extra')
        check = self._validate("codex", config)
        self.assertEqual(check.state, "malformed")

    def test_stale_gateway_launcher_and_contract_are_distinct(self) -> None:
        legacy = self._runtime("defenseclaw-gateway.exe")
        config = self._config("codex", f'"{legacy}" hook --connector codex')
        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale")
        self.assertIn("obsolete gateway launcher", check.detail)

        current = self._runtime()
        config = self._config("codex", f'"{current}" hook --connector codex')
        (self.data / "hook_contract_lock.json").unlink()
        check = self._validate("codex", config)
        self.assertEqual(check.state, "stale")
        self.assertIn("contract lock is missing", check.detail)

    def test_foreign_same_basename_outside_install_root_is_rejected(self) -> None:
        foreign_dir = self.root / "Other Product"
        foreign_dir.mkdir()
        foreign = foreign_dir / "defenseclaw-hook.exe"
        foreign.write_bytes(b"MZ")
        config = self._config("claudecode", f'"{foreign}" hook --connector claudecode')
        check = self._validate("claudecode", config)
        self.assertEqual(check.state, "foreign")
        self.assertIn("escapes", check.detail)

    def test_reparse_or_symlink_target_is_rejected(self) -> None:
        linked = self._runtime()
        config = self._config("claudecode", f'"{linked}" hook --connector claudecode')
        real_detector = __import__("defenseclaw.doctor_hooks", fromlist=["is_link_or_reparse"]).is_link_or_reparse

        def simulated_reparse(path: str) -> bool:
            return os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(linked)) or real_detector(path)

        with patch("defenseclaw.doctor_hooks.is_link_or_reparse", side_effect=simulated_reparse):
            check = self._validate("claudecode", config)
        self.assertEqual(check.state, "foreign")
        self.assertRegex(check.detail, "symlink|reparse")

    def test_access_denied_is_not_reported_as_missing(self) -> None:
        config = self.root / "denied.toml"
        with patch("defenseclaw.doctor_hooks.os.lstat", side_effect=PermissionError("denied")):
            check = self._validate("codex", config)
        self.assertEqual(check.state, "access-denied")

    def test_target_replacement_race_is_stale_and_has_no_side_effect(self) -> None:
        runtime = self._runtime()
        config = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        real_lstat = os.lstat
        runtime_stat = os.lstat(runtime)
        changed = SimpleNamespace(
            st_dev=runtime_stat.st_dev,
            st_ino=runtime_stat.st_ino + 1,
            st_size=runtime_stat.st_size,
            st_mtime_ns=runtime_stat.st_mtime_ns,
            st_mode=runtime_stat.st_mode,
        )
        runtime_stats = iter((runtime_stat, changed))

        def race_runtime_lstat(path: str | os.PathLike[str]):
            if os.path.normcase(os.path.abspath(os.fspath(path))) == os.path.normcase(os.path.abspath(str(runtime))):
                return next(runtime_stats)
            return real_lstat(path)

        with (
            patch("defenseclaw.doctor_hooks.is_link_or_reparse", return_value=False),
            patch("defenseclaw.doctor_hooks.os.path.realpath", side_effect=os.path.abspath),
            patch(
                "defenseclaw.doctor_hooks.os.lstat",
                side_effect=race_runtime_lstat,
            ),
        ):
            check = self._validate("claudecode", config)
        self.assertEqual(check.state, "stale")
        self.assertIn("changed during inspection", check.detail)

    def test_doctor_validates_registered_codex_and_claude_commands(self) -> None:
        runtime = self._runtime()
        codex = self._config(
            "codex",
            "set NoDefaultCurrentDirectoryInExePath=1&& defenseclaw-hook.exe hook --connector codex",
        )
        claude = self._config("claudecode", f'"{runtime}" hook --connector claudecode')
        runtime_before = runtime.read_bytes()
        cases = (
            ("codex", _check_codex_hooks, codex),
            ("claudecode", _check_claudecode_hooks, claude),
        )
        for connector, check_hooks, config in cases:
            with self.subTest(config=config.name):
                self._lock(connector, config)
                result = _DoctorResult()
                config_before = config.read_bytes()
                with (
                    patch(
                        "defenseclaw.doctor_hooks._windows_known_folder_path",
                        return_value=str(self.root / "Trusted Program Files"),
                    ),
                    patch("defenseclaw.commands.cmd_doctor.subprocess.run") as run_mock,
                ):
                    check_hooks(
                        self.cfg,
                        result,
                        platform_name="nt",
                        config_path=str(config),
                        install_root=str(self.install),
                        search_path=str(self.install),
                        pathext=".EXE;.CMD",
                    )
                run_mock.assert_not_called()
                self.assertEqual((result.passed, result.failed), (1, 0))
                self.assertEqual(result.to_dict()["checks"], result.checks)
                self.assertIn(str(runtime), result.checks[0]["detail"])
                self.assertNotRegex(result.checks[0]["detail"].lower(), r"\.sh\b|\bbash\b|\bwsl\b")
                self.assertEqual(config.read_bytes(), config_before)
        self.assertEqual(runtime.read_bytes(), runtime_before)

    def test_packaged_doctor_derives_native_install_root_from_verified_state(self) -> None:
        bin_dir = self.install / "bin"
        python_dir = self.install / "runtime" / "python"
        installer_dir = self.install / "installer"
        bin_dir.mkdir()
        python_dir.mkdir(parents=True)
        installer_dir.mkdir()
        python = python_dir / "python.exe"
        python.write_bytes(b"MZembedded-python")
        runtime = bin_dir / "defenseclaw-hook.exe"
        runtime.write_bytes(b"MZfixture")
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        state = {
            "schema_version": 1,
            "install_kind": "native-windows-exe",
            "install_scope": "user",
            "install_root": str(self.install),
            "command_dir": str(bin_dir),
            "runtime": str(python_dir),
            "data_root": str(self.data),
        }
        (installer_dir / "install-state.json").write_text(json.dumps(state), encoding="utf-8")
        result = _DoctorResult()
        with (
            patch("defenseclaw.doctor_hooks.sys.executable", str(python)),
            patch.dict(os.environ, {"DEFENSECLAW_INSTALL_ROOT": str(self.install)}),
            patch("defenseclaw.inventory.agent_discovery._windows_acl_write_error", return_value=None),
        ):
            _check_codex_hooks(
                self.cfg,
                result,
                platform_name="nt",
                config_path=str(config),
                search_path=str(bin_dir),
                pathext=".EXE;.CMD",
            )
        self.assertEqual((result.passed, result.failed), (1, 0), result.checks)
        self.assertIn(str(runtime), result.checks[0]["detail"])

    def test_packaged_install_root_rejects_unbound_environment_or_state(self) -> None:
        python_dir = self.install / "runtime" / "python"
        installer_dir = self.install / "installer"
        python_dir.mkdir(parents=True)
        installer_dir.mkdir()
        python = python_dir / "python.exe"
        python.write_bytes(b"MZembedded-python")
        state = {
            "schema_version": 1,
            "install_kind": "native-windows-exe",
            "install_scope": "user",
            "install_root": str(self.install),
            "command_dir": str(self.install / "bin"),
            "runtime": str(python_dir),
            "data_root": str(self.data),
        }
        state_path = installer_dir / "install-state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        with patch("defenseclaw.inventory.agent_discovery._windows_acl_write_error", return_value=None):
            self.assertIsNone(
                _packaged_windows_install_root(
                    str(self.data),
                    executable=str(python),
                    declared_root=str(self.root / "spoofed-install"),
                )
            )
            state["data_root"] = str(self.root / "other-data")
            state_path.write_text(json.dumps(state), encoding="utf-8")
            self.assertIsNone(
                _packaged_windows_install_root(
                    str(self.data),
                    executable=str(python),
                    declared_root=str(self.install),
                )
            )

    def test_windows_contract_uses_live_codex_and_claude_runtime_in_human_and_json(self) -> None:
        runtime = self._runtime()
        cases = (
            (
                "codex",
                "set NoDefaultCurrentDirectoryInExePath=1&& defenseclaw-hook hook --connector codex",
            ),
            ("claudecode", f'"{runtime}" hook --connector claudecode'),
        )
        for connector, command in cases:
            with self.subTest(connector=connector):
                config = self._config(connector, command)
                result, human = self._contract_check(connector, config)
                check = result.checks[-1]
                serialized = json.dumps(result.to_dict())
                structured = json.loads(serialized)

                self.assertEqual(check["status"], "pass", check)
                self.assertIn(f"runtime_path={runtime}", check["detail"])
                self.assertIn(check["detail"], human)
                self.assertIn(str(runtime), structured["checks"][-1]["detail"])
                self.assertNotRegex(
                    (human + serialized).lower(),
                    r"inspect-tool\.sh|codex-hook\.sh|claude-code-hook\.sh|\bbash\b|\bwsl\b|\bchmod\b",
                )

    def test_windows_contract_reports_actual_invalid_registration(self) -> None:
        managed = self._runtime()
        legacy = self._runtime("defenseclaw-gateway.exe")
        foreign_dir = self.root / "Other Product"
        foreign_dir.mkdir()
        foreign = foreign_dir / "defenseclaw-hook.exe"
        foreign.write_bytes(b"MZforeign")
        cases = (
            ("stale", f'"{legacy}" hook --connector codex', str(legacy)),
            ("foreign", f'"{foreign}" hook --connector codex', str(foreign)),
            ("malformed", f'"{managed}" hook --connector codex --extra', "runtime_command="),
        )
        for expected_state, command, evidence in cases:
            with self.subTest(state=expected_state):
                config = self._config("codex", command)
                result, human = self._contract_check("codex", config)
                detail = result.checks[-1]["detail"]

                self.assertEqual(result.checks[-1]["status"], "fail", detail)
                self.assertIn(f"runtime_state={expected_state}", detail)
                self.assertIn(evidence, detail)
                self.assertIn("setup codex --yes --restart", detail)
                self.assertIn(detail, human)
                self.assertNotRegex(
                    detail.lower(),
                    r"inspect-tool\.sh|codex-hook\.sh|claude-code-hook\.sh|\bbash\b|\bwsl\b|\bchmod\b",
                )

    def test_windows_codex_contract_ignores_other_discovered_installation(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        lock_path = self.data / "hook_contract_lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        entry = lock["connectors"]["codex"]
        entry.update(
            {
                "agent_executable": str(self.install / "codex.exe"),
                "agent_executable_source": "setup-selected",
                "agent_executable_sha256": "a" * 64,
            }
        )
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        (self.data / "agent_discovery.json").write_text(
            json.dumps({"agents": {"codex": {"version": "codex-cli 99.0.0"}}}),
            encoding="utf-8",
        )
        result = _DoctorResult()

        _check_hook_contract_lock(
            self.cfg,
            "codex",
            result,
            platform_name="nt",
            config_path=str(config),
            install_root=str(self.install),
            search_path=str(self.install),
            pathext=".EXE;.CMD",
        )

        self.assertEqual(result.checks[-1]["status"], "pass", result.checks[-1])
        self.assertNotIn("99.0.0", result.checks[-1]["detail"])

    def test_windows_contract_preserves_access_denied_classification(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        self._lock(
            "codex",
            config,
            runtime_paths=[str(self.data / "hooks" / "inspect-tool.sh")],
        )
        result = _DoctorResult()
        with patch("defenseclaw.doctor_hooks.os.lstat", side_effect=PermissionError("denied")):
            _check_hook_contract_lock(
                self.cfg,
                "codex",
                result,
                platform_name="nt",
                config_path=str(config),
                install_root=str(self.install),
                search_path=str(self.install),
                pathext=".EXE;.CMD",
            )
        detail = result.checks[-1]["detail"]
        self.assertEqual(result.checks[-1]["status"], "fail")
        self.assertIn("runtime_state=access-denied", detail)
        self.assertIn(str(config), detail)
        self.assertNotIn("inspect-tool.sh", detail)

    @unittest.skipUnless(os.name == "nt", "native Windows disposable-state smoke test")
    def test_native_windows_uses_only_disposable_state(self) -> None:
        runtime = self._runtime()
        cases = (
            (
                "codex",
                "set NoDefaultCurrentDirectoryInExePath=1&& defenseclaw-hook.exe hook --connector codex",
            ),
            ("claudecode", f'"{runtime}" hook --connector claudecode'),
        )
        for connector, command in cases:
            with self.subTest(connector=connector):
                config = self._config(connector, command)
                result, human = self._contract_check(connector, config)
                detail = result.checks[-1]["detail"]

                self.assertEqual(result.passed, 1, result.checks)
                self.assertTrue(str(config).startswith(self.temp.name))
                self.assertIn(f"runtime_path={runtime}", detail)
                self.assertNotIn(".sh", human)

    @unittest.skipUnless(os.name == "nt", "Windows ACL validation")
    def test_native_windows_rejects_untrusted_launcher_acl(self) -> None:
        runtime = self._runtime()
        config = self._config("codex", f'"{runtime}" hook --connector codex')
        with patch(
            "defenseclaw.inventory.agent_discovery._windows_acl_write_error",
            return_value="ACL grants write access to untrusted principal Everyone",
        ):
            check = self._validate("codex", config)
        self.assertEqual(check.state, "foreign")
        self.assertIn("untrusted ownership or ACL", check.detail)


class WindowsHookResolutionTests(unittest.TestCase):
    def test_double_quoted_call_target_preserves_literal_apostrophes(self) -> None:
        self.assertEqual(
            _split_windows(r"""& "C:\Tools\hook''name.ps1" hook"""),
            ["&", r"C:\Tools\hook''name.ps1", "hook"],
        )

    def test_pathext_is_case_insensitive_and_ignores_unsafe_extensions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="doctor-pathext-") as tmp:
            Path(tmp, "defenseclaw-hook.ps1").write_text("untrusted", encoding="utf-8")
            cmd = Path(tmp, "DefenseClaw-Hook.CMD")
            cmd.write_text("rem defenseclaw-managed-hook v6\n", encoding="utf-8")
            resolved = resolve_windows_command(
                "defenseclaw-hook",
                search_path=tmp,
                pathext="PS1;.CMD;.EXE",
            )
        self.assertEqual(os.path.normcase(resolved or ""), os.path.normcase(str(cmd)))


if __name__ == "__main__":
    unittest.main()
