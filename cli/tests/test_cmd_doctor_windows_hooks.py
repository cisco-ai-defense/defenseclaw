"""Windows-native Codex/Claude Doctor hook validation regressions."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import (
    _check_claudecode_hooks,
    _check_codex_hooks,
    _check_hook_contract_lock,
    _DoctorResult,
)
from defenseclaw.doctor_hooks import (
    _split_windows,
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

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _runtime(self, name: str = "defenseclaw-hook.exe", body: bytes | None = None) -> Path:
        path = self.install / name
        if body is None:
            body = b"MZfixture" if name.endswith(".exe") else b"rem defenseclaw-managed-hook v6\r\n"
        path.write_bytes(body)
        return path

    def _lock(
        self,
        connector: str,
        config: Path,
        *,
        version: str = "v6",
        runtime_paths: list[str] | None = None,
    ) -> None:
        contract = "codex-hooks-v1" if connector == "codex" else "claudecode-hooks-v1"
        locations = {"hook_config_paths": [str(config)]}
        if runtime_paths is not None:
            locations["hook_script_paths"] = runtime_paths
        (self.data / "hook_contract_lock.json").write_text(
            json.dumps(
                {
                    "connectors": {
                        connector: {
                            "contract_id": contract,
                            "compatibility_status": "known",
                            "hook_script_version": version,
                            "locations": locations,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

    def _config(self, connector: str, command: str, *, extra_command: str = "") -> Path:
        if connector == "codex":
            path = self.profile / ".codex" / "config.toml"
            path.parent.mkdir(exist_ok=True)
            extra = ""
            if extra_command:
                escaped_extra = extra_command.replace("\\", "\\\\").replace('"', '\\"')
                extra = (
                    '\nPostToolUse = [{ hooks = [{ type = "command", '
                    f'command = "{escaped_extra}", timeout = 30 }}] }}]'
                )
            escaped = command.replace("\\", "\\\\").replace('"', '\\"')
            path.write_text(
                "[features]\nhooks = true\n\n[hooks]\n"
                'PreToolUse = [{ hooks = [{ type = "command", '
                f'command = "{escaped}", timeout = 30 }}] }}]' + extra + "\n",
                encoding="utf-8",
            )
        else:
            path = self.profile / ".claude" / "settings.json"
            path.parent.mkdir(exist_ok=True)
            events: dict[str, object] = {
                "PreToolUse": [{"hooks": [{"type": "command", "command": command, "timeout": 30000}]}]
            }
            if extra_command:
                events["PostToolUse"] = [{"hooks": [{"type": "command", "command": extra_command, "timeout": 30000}]}]
            path.write_text(json.dumps({"hooks": events}), encoding="utf-8")
        self._lock(connector, path)
        return path

    def _validate(self, connector: str, config: Path, *, search_path: str = "", pathext: str = ".EXE;.CMD"):
        return validate_windows_hook_registration(
            connector=connector,
            config_path=str(config),
            data_dir=str(self.data),
            install_root=str(self.install),
            search_path=search_path,
            pathext=pathext,
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
        self.assertIn("entries=1", check.detail)

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
                with patch("defenseclaw.commands.cmd_doctor.subprocess.run") as run_mock:
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
