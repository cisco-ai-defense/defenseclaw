# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A fresh wheel owns the complete native Local Splunk runtime."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "bundles" / "splunk_local_bridge"


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build wheels")
def test_wheel_resolves_complete_splunk_bundle_outside_checkout(
    tmp_path: Path,
) -> None:
    output = tmp_path / "wheel"
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [shutil.which("uv"), "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    wheel = next(output.glob("defenseclaw-*.whl"))
    expected_assets = {
        path.relative_to(BUNDLE).as_posix()
        for path in BUNDLE.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    prefix = "defenseclaw/_data/splunk_local_bridge/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        packaged_assets = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        assert expected_assets <= packaged_assets
        for relative_path in expected_assets:
            assert archive.read(prefix + relative_path) == (BUNDLE / Path(relative_path)).read_bytes(), (
                f"packaged Local Splunk asset drifted: {relative_path}"
            )
        assert "defenseclaw/observability/local_splunk.py" in names
        archive.extractall(tmp_path / "site")

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import pathlib,sys;sys.path.insert(0,sys.argv[1]);"
                "from defenseclaw.paths import bundled_splunk_bridge_dir;"
                "from defenseclaw.observability.local_splunk import validate_bundle_assets;"
                "p=validate_bundle_assets(bundled_splunk_bridge_dir());"
                "assert (p/'compose'/'docker-compose.local.yml').is_file();"
                "assert (p/'splunk'/'apps'/'defenseclaw_local_mode'/'lookups'/'dcso_severity_labels.csv').is_file();"
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
