"""Run the isolated Cowork transaction smoke on a Windows PowerShell host."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name != "nt", reason="Windows registry smoke needs a Windows host")
def test_cowork_registry_preimages_roundtrip_and_reader_repair():
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the standalone Windows lifecycle")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(root / "packaging/windows/tests/enterprise-cowork-delivery-smoke.ps1"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Cowork registry snapshot roundtrip and owned reader repair checks passed" in result.stdout
