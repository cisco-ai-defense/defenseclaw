# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Native Windows reset regression for a runtime located under data home."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import venv
from pathlib import Path


@unittest.skipUnless(sys.platform == "win32", "Windows file locking regression")
class WindowsManagedVenvResetTests(unittest.TestCase):
    def test_windows_process_access_mask_constants_preserve_required_rights(self) -> None:
        from defenseclaw.commands import cmd_uninstall

        access_mask = (
            cmd_uninstall._WIN_SYNCHRONIZE  # noqa: SLF001
            | cmd_uninstall._WIN_PROCESS_QUERY_LIMITED_INFORMATION  # noqa: SLF001
        )

        self.assertEqual(access_mask, 0x00101000)

    def test_deferred_helper_accepts_utf8_shim_for_non_ascii_profile(self) -> None:
        from defenseclaw.commands import windows_uninstall_helper

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "kévin profile"
            install_root = profile / ".local" / "bin"
            data_dir = profile / ".defenseclaw"
            managed_venv = data_dir / ".venv"
            install_root.mkdir(parents=True)
            managed_venv.mkdir(parents=True)
            target = install_root / "defenseclaw-gateway.exe"
            target.write_bytes(b"MZfixture")
            (install_root / "defenseclaw.cmd").write_text(
                f'@echo off\r\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\r\n',
                encoding="utf-8",
            )
            plan = {
                "install_root": str(install_root),
                "data_dir": str(data_dir),
                "managed_venv": str(managed_venv),
                "protected_paths": [],
                "binary_targets": [str(target)],
                "remove_data_dir": False,
            }

            _install_root, _data_dir, targets = windows_uninstall_helper._validate_plan(plan)

            self.assertEqual(targets, [os.path.normcase(os.path.abspath(target))])

    def test_deferred_helper_rejects_unowned_target_and_reports_failure(self) -> None:
        source = Path(__file__).resolve().parents[1] / "defenseclaw" / "commands" / "windows_uninstall_helper.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "helper.py"
            manifest = root / "plan.json"
            status = root / "status.json"
            ready = root / "ready.json"
            shutil.copyfile(source, helper)
            manifest.write_text(
                json.dumps(
                    {
                        "parent_pid": os.getpid(),
                        "parent_executable": os.path.realpath(sys._base_executable),
                        "install_root": str(root / "bin"),
                        "data_dir": str(root / "data"),
                        "managed_venv": str(root / "data" / ".venv"),
                        "protected_paths": [str(root)],
                        "binary_targets": [str(root / "outside" / "defenseclaw.cmd")],
                        "remove_data_dir": False,
                        "ready_path": str(ready),
                        "status_path": str(status),
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys._base_executable, "-I", str(helper), str(manifest)],
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(status.read_text(encoding="utf-8"))["status"], "failed")
            self.assertFalse(ready.exists())

    def test_reset_from_managed_venv_with_loaded_native_module(self) -> None:
        repo_cli = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "user-home"
            data_dir = home / ".defenseclaw"
            managed_venv = data_dir / ".venv"
            home.mkdir()
            venv.EnvBuilder(with_pip=False, system_site_packages=True).create(managed_venv)
            python = managed_venv / "Scripts" / "python.exe"
            site_packages = managed_venv / "Lib" / "site-packages"
            inherited = next(Path(path) for path in sys.path if path.lower().endswith("site-packages"))
            (site_packages / "test-runtime.pth").write_text(f"{inherited}\n{repo_cli}\n", encoding="utf-8")

            for relative in (
                "config.yaml",
                "audit.db",
                "logs/gateway.log",
                "policies/default.yaml",
                "quarantine/finding.json",
                "tokens/session",
                "future-state/value.bin",
            ):
                target = data_dir / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("reset me", encoding="utf-8")

            bootstrap = root / "invoke_reset.py"
            bootstrap.write_text(
                textwrap.dedent(
                    """
                    import importlib.util
                    import shutil
                    import sys
                    from pathlib import Path

                    source = Path(importlib.util.find_spec("_bz2").origin)
                    loaded = Path(sys.prefix) / "loaded-native" / source.name
                    loaded.parent.mkdir()
                    shutil.copy2(source, loaded)
                    sys.modules.pop("_bz2", None)
                    spec = importlib.util.spec_from_file_location("_bz2", loaded)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules["_bz2"] = module
                    spec.loader.exec_module(module)

                    from defenseclaw.main import main
                    sys.argv = ["defenseclaw", "reset", "--yes"]
                    main()
                    """
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update(
                {
                    "DEFENSECLAW_HOME": str(data_dir),
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "PYTHONPATH": str(repo_cli),
                    "PATH": str(managed_venv / "Scripts"),
                    "PYTHONUTF8": "1",
                }
            )

            reset = subprocess.run(
                [str(python), str(bootstrap)],
                env=env,
                capture_output=True,
                check=False,
            )
            output = (reset.stdout + reset.stderr).decode("utf-8")
            self.assertEqual(reset.returncode, 0, output)
            self.assertIn(
                "Reset complete. Run 'defenseclaw quickstart' to reinstall.",
                output,
            )
            self.assertTrue(python.is_file())
            self.assertEqual({path.name for path in data_dir.iterdir()}, {".venv"})

            version = subprocess.run(
                [str(python), "-m", "defenseclaw.main", "--version"],
                env=env,
                capture_output=True,
                check=False,
            )
            self.assertEqual(version.returncode, 0, version.stderr.decode("utf-8"))
            self.assertIn("defenseclaw", version.stdout.decode("utf-8").lower())

            status = subprocess.run(
                [str(python), "-m", "defenseclaw.main", "status"],
                env=env,
                capture_output=True,
                check=False,
            )
            status_output = (status.stdout + status.stderr).decode("utf-8")
            self.assertNotEqual(status.returncode, 0)
            self.assertIn("run 'defenseclaw init' first", status_output)
            self.assertEqual({path.name for path in data_dir.iterdir()}, {".venv"})

    def test_full_uninstall_defers_running_managed_venv_and_removes_windows_launchers(self) -> None:
        repo_cli = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "user-home"
            data_dir = home / ".defenseclaw"
            managed_venv = data_dir / ".venv"
            install_root = home / ".local" / "bin"
            home.mkdir()
            install_root.mkdir(parents=True)
            venv.EnvBuilder(with_pip=False, system_site_packages=True).create(managed_venv)
            python = managed_venv / "Scripts" / "python.exe"
            site_packages = managed_venv / "Lib" / "site-packages"
            inherited = next(Path(path) for path in sys.path if path.lower().endswith("site-packages"))
            (site_packages / "test-runtime.pth").write_text(f"{inherited}\n{repo_cli}\n", encoding="utf-8")
            (data_dir / "audit.db").write_bytes(b"disposable")

            launchers = tuple(
                install_root / name for name in ("defenseclaw.cmd", "defenseclaw-gateway.exe", "defenseclaw-hook.exe")
            )
            for launcher in launchers:
                launcher.write_text("disposable test artifact", encoding="utf-8")
            launchers[0].write_text(
                f'@echo off\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\n',
                encoding="ascii",
            )
            unrelated = install_root / "keep.txt"
            unrelated.write_text("preserve", encoding="utf-8")

            bootstrap = root / "invoke_uninstall.py"
            bootstrap.write_text(
                textwrap.dedent(
                    """
                    from defenseclaw.commands import cmd_uninstall
                    cmd_uninstall._stop_gateway = lambda plan: None
                    from defenseclaw.main import main
                    import sys
                    sys.argv = ["defenseclaw", "uninstall", "--all", "--binaries", "--yes"]
                    main()
                    """
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update(
                {
                    "DEFENSECLAW_HOME": str(data_dir),
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "PYTHONPATH": str(repo_cli),
                    "PATH": str(managed_venv / "Scripts"),
                    "PYTHONUTF8": "1",
                }
            )

            uninstall = subprocess.run(
                [str(python), str(bootstrap)],
                env=env,
                capture_output=True,
                check=False,
            )
            output = (uninstall.stdout + uninstall.stderr).decode("utf-8")
            self.assertEqual(uninstall.returncode, 0, output)
            self.assertIn("deferred cleanup: scheduled", output)
            match = re.search(r"result: ([^)]+\.json)", output)
            self.assertIsNotNone(match, output)
            status_path = Path(match.group(1))

            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and (
                data_dir.exists() or any(path.exists() for path in launchers) or not status_path.exists()
            ):
                time.sleep(0.1)

            self.assertFalse(data_dir.exists())
            self.assertFalse(any(path.exists() for path in launchers))
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")
            self.assertEqual(json.loads(status_path.read_text(encoding="utf-8"))["status"], "succeeded")
            status_path.unlink()

            repeated = subprocess.run(
                [sys.executable, str(bootstrap)],
                env=env,
                capture_output=True,
                check=False,
            )
            repeated_output = (repeated.stdout + repeated.stderr).decode("utf-8")
            self.assertEqual(repeated.returncode, 0, repeated_output)
            self.assertIn("not installed", repeated_output)
