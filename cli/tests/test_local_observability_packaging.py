# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""A fresh wheel owns the complete stack bundle and Python controller."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "bundles" / "local_observability_stack"


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build wheels")
def test_wheel_resolves_complete_stack_outside_source_checkout(tmp_path: Path) -> None:
    output = tmp_path / "wheel"
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [shutil.which("uv"), "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    wheel = next(output.glob("defenseclaw-*.whl"))
    expected_assets = {
        path.relative_to(BUNDLE).as_posix()
        for path in BUNDLE.rglob("*")
        if path.is_file()
    }
    prefix = "defenseclaw/_data/local_observability_stack/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        packaged_assets = {
            name.removeprefix(prefix) for name in names if name.startswith(prefix)
        }
        assert expected_assets <= packaged_assets
        assert "defenseclaw/observability/local_stack.py" in names
        entry_points = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        assert (
            "defenseclaw-observability = defenseclaw.observability.local_stack:main"
            in archive.read(entry_points).decode("utf-8")
        )
        archive.extractall(tmp_path / "site")

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "import pathlib,sys;sys.path.insert(0,sys.argv[1]);"
                "from defenseclaw.paths import bundled_local_observability_dir;"
                "p=bundled_local_observability_dir();"
                "assert p.is_dir();assert (p/'docker-compose.yml').is_file();"
                "assert sys.argv[2] not in str(p);print(p)"
            ),
            str(tmp_path / "site"),
            str(REPO_ROOT),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "_data" in probe.stdout
