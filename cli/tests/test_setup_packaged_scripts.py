# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""The enterprise Setup's embedded Python scripts, run against the real package.

cmd/defenseclaw-setup embeds these scripts as Go string constants. Its own
tests use fake modules, so only running them here catches a call that no
longer matches the package API.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SETUP_MAIN = ROOT / "cmd" / "defenseclaw-setup" / "main.go"
VERSION = "9.9.9"


def _script(name: str) -> str:
    match = re.search(rf"^const {name} = `(.*?)`$", SETUP_MAIN.read_text(encoding="utf-8"), re.DOTALL | re.MULTILINE)
    assert match is not None, f"{name} not found in {SETUP_MAIN}"
    return match.group(1)


@pytest.fixture()
def install(tmp_path: Path) -> dict[str, Path]:
    home = tmp_path / "home"
    data = home / ".defenseclaw"
    data.mkdir(parents=True)
    manifest = tmp_path / "upgrade-manifest.json"
    manifest.write_text(json.dumps({"schema_version": 2, "release_version": VERSION}), encoding="utf-8")
    return {"home": home, "data": data, "openclaw": home / ".openclaw", "manifest": manifest}


def _run(install: dict[str, Path], script: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("DEFENSECLAW_") and key not in {"CLAUDE_CONFIG_DIR", "CODEX_HOME"}
    }
    env.update(
        HOME=str(install["home"]),
        USERPROFILE=str(install["home"]),
        DEFENSECLAW_HOME=str(install["data"]),
        DEFENSECLAW_CONFIG=str(install["data"] / "config.yaml"),
        DEFENSECLAW_NO_UPDATE_CHECK="1",
    )
    return subprocess.run(
        [sys.executable, "-X", "utf8", "-c", script, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _write_config(install: dict[str, Path], version: int) -> None:
    (install["data"] / "config.yaml").write_text(f"config_version: {version}\n", encoding="utf-8")


def test_canonical_state_validation_accepts_a_current_config(install: dict[str, Path]) -> None:
    _write_config(install, 8)

    result = _run(install, _script("packagedCanonicalStateValidationScript"), str(install["data"]), VERSION, str(install["manifest"]))

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_canonical_state_validation_refuses_a_config_that_needs_migrating(install: dict[str, Path]) -> None:
    _write_config(install, 7)

    result = _run(install, _script("packagedCanonicalStateValidationScript"), str(install["data"]), VERSION, str(install["manifest"]))

    assert result.returncode != 0
    assert "defenseclaw migrate" in result.stderr


@pytest.mark.parametrize("name", ["packagedMigrationScript", "packagedMigrationPreflightScript"])
def test_migration_scripts_report_nothing_to_do_for_a_current_config(install: dict[str, Path], name: str) -> None:
    _write_config(install, 8)

    result = _run(install, _script(name), "0.8.10", VERSION, str(install["openclaw"]), str(install["data"]), str(install["manifest"]))

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "0"


def test_migration_preflight_reports_the_pending_0x_import(install: dict[str, Path]) -> None:
    _write_config(install, 7)

    result = _run(
        install,
        _script("packagedMigrationPreflightScript"),
        "0.8.4",
        VERSION,
        str(install["openclaw"]),
        str(install["data"]),
        str(install["manifest"]),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "1"
    assert (install["data"] / "config.yaml").read_text(encoding="utf-8") == "config_version: 7\n"


@pytest.mark.parametrize(
    "name", ["packagedMigrationScript", "packagedMigrationPreflightScript", "packagedCanonicalStateValidationScript"]
)
def test_scripts_refuse_another_release_manifest(install: dict[str, Path], name: str) -> None:
    _write_config(install, 8)
    install["manifest"].write_text(json.dumps({"release_version": "0.0.1"}), encoding="utf-8")
    args = (
        (str(install["data"]), VERSION, str(install["manifest"]))
        if name == "packagedCanonicalStateValidationScript"
        else ("0.8.10", VERSION, str(install["openclaw"]), str(install["data"]), str(install["manifest"]))
    )

    result = _run(install, _script(name), *args)

    assert result.returncode != 0
    assert "upgrade manifest version mismatch" in result.stderr
