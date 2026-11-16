# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Fleet source release asset must run its own policy compiler CTest."""

from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POLICY_PAGE = Path("docs-site/content/docs/edge-connector/policies.mdx")


@pytest.mark.skipif(sys.platform == "win32", reason="the tar/make release target runs on POSIX")
def test_fleet_release_asset_ships_policy_page_for_compiler_ctest(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    subprocess.run(
        ["make", "dist-fleet-assets", f"DIST_DIR={dist}"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=True,
    )
    archive = dist / "defenseclaw-fleet-assets.tar.gz"
    assert archive.is_file()
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(extracted)],
                   capture_output=True, text=True, timeout=30, check=True)
    # Run the same Python test that the extracted source registers with CTest.
    compiler_test = subprocess.run(
        [sys.executable, str(extracted / "edge-connector" / "tests" / "test_policy_compiler.py"),
         "PolicyCompilerExitTest.test_the_policies_page_examples_compile"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert compiler_test.returncode == 0, compiler_test.stdout + compiler_test.stderr
    assert "Ran 1 test" in compiler_test.stderr
    assert (extracted / POLICY_PAGE).is_file()


@pytest.mark.skipif(sys.platform == "win32", reason="the release asset builder runs on POSIX")
def test_install_smoke_assets_include_fleet_policy_page(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    build = subprocess.run(
        ["bash", str(ROOT / "scripts" / "build-release-assets.sh"),
         "9.9.9", str(assets), "linux/amd64"],
        cwd=ROOT, capture_output=True, text=True, timeout=900, check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    with tarfile.open(assets / "defenseclaw-fleet-assets.tar.gz", "r:gz") as archive:
        page = archive.extractfile(str(POLICY_PAGE))
        assert page is not None
        assert page.read() == (ROOT / POLICY_PAGE).read_bytes()
