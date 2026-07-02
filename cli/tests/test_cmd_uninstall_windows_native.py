# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Native Windows reset regression for a runtime located under data home."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
import venv
from pathlib import Path


@unittest.skipUnless(sys.platform == "win32", "Windows file locking regression")
class WindowsManagedVenvResetTests(unittest.TestCase):
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
                "connector_backups/openclaw/openclaw.json.json",
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
            self.assertIn("✓", output)
            self.assertIn("Reset complete", output)
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
