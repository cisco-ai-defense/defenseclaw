"""Hermetic contract tests for the Windows x64 runtime PE checks."""

from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "scripts" / "windows_installer_artifacts.py"
SCANNER_RUNTIME_SH = ROOT / "packaging" / "windows" / "standalone" / "build-scanner-runtime.sh"
SPEC = importlib.util.spec_from_file_location("windows_installer_artifacts", HELPER_PATH)
assert SPEC and SPEC.loader
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)


def _pe_bytes(machine: int) -> bytes:
    header = bytearray(b"MZ" + b"\0" * 62)
    header[0x3C:0x40] = (64).to_bytes(4, "little")
    return bytes(header) + b"PE\0\0" + machine.to_bytes(2, "little") + b"\0" * 18


def test_foreign_pe_prune_drops_pips_non_x64_launchers_and_repairs_record(tmp_path: Path) -> None:
    # MCP Scanner 4.8 -> pip-audit -> pip vendors distlib launchers for every
    # Windows architecture; Setup refuses any non-x64 PE in its payload.
    site = tmp_path / "site-packages"
    distlib = site / "pip" / "_vendor" / "distlib"
    metadata = site / "pip-26.2.2.dist-info"
    distlib.mkdir(parents=True)
    metadata.mkdir()
    machines = {"t32.exe": 0x014C, "t64.exe": 0x8664, "t64-arm.exe": 0xAA64,
                "w32.exe": 0x014C, "w64.exe": 0x8664, "w64-arm.exe": 0xAA64}
    for name, machine in machines.items():
        (distlib / name).write_bytes(_pe_bytes(machine))
    (distlib / "scripts.py").write_text("X = 1\n", encoding="utf-8")
    (metadata / "RECORD").write_text(
        "".join(f"pip/_vendor/distlib/{name},,\n" for name in sorted(machines))
        + "pip/_vendor/distlib/scripts.py,,\npip-26.2.2.dist-info/RECORD,,\n",
        encoding="utf-8",
    )

    result = artifacts.prune_foreign_portable_executables(site)

    assert result == {
        "removed_foreign_pe": [
            "pip/_vendor/distlib/t32.exe",
            "pip/_vendor/distlib/t64-arm.exe",
            "pip/_vendor/distlib/w32.exe",
            "pip/_vendor/distlib/w64-arm.exe",
        ],
        "rewritten_records": 1,
    }
    assert sorted(path.name for path in distlib.iterdir()) == ["scripts.py", "t64.exe", "w64.exe"]
    assert (metadata / "RECORD").read_text(encoding="utf-8") == (
        "pip/_vendor/distlib/t64.exe,,\npip/_vendor/distlib/w64.exe,,\n"
        "pip/_vendor/distlib/scripts.py,,\npip-26.2.2.dist-info/RECORD,,\n"
    )
    # Every PE left is Windows x64, which is what Setup's inventory check demands.
    for path in site.rglob("*.exe"):
        assert artifacts._pe_machine(path) == artifacts.IMAGE_FILE_MACHINE_AMD64


@pytest.mark.parametrize("machine", [0x014C, 0xAA64])
def test_foreign_pe_prune_refuses_an_unlisted_non_x64_pe(tmp_path: Path, machine: int) -> None:
    site = tmp_path / "site-packages"
    (site / "example").mkdir(parents=True)
    (site / "example" / "helper.dll").write_bytes(_pe_bytes(machine))

    with pytest.raises(artifacts.ArtifactError, match=r"example/helper\.dll"):
        artifacts.prune_foreign_portable_executables(site)
    assert (site / "example" / "helper.dll").exists()


def test_x64_pe_check_accepts_an_x64_only_runtime(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "python" / "Lib" / "site-packages" / "pip").mkdir(parents=True)
    (runtime / "python" / "python.exe").write_bytes(_pe_bytes(0x8664))
    (runtime / "python" / "Lib" / "site-packages" / "pip" / "t64.exe").write_bytes(_pe_bytes(0x8664))
    (runtime / "python" / "README.txt").write_text("not a PE\n", encoding="utf-8")

    assert artifacts.refuse_foreign_portable_executables(runtime) == {"x64_pe": 2}


@pytest.mark.parametrize("machine", [0x014C, 0xAA64])
@pytest.mark.parametrize(
    "relative",
    ["python/Lib/site-packages/pip/_vendor/distlib/t32.exe", "python/vcruntime140.dll"],
)
def test_x64_pe_check_refuses_any_non_x64_pe_and_removes_nothing(tmp_path: Path, machine: int, relative: str) -> None:
    # The whole-tree check before the scanner runtime is archived: even a
    # launcher prune-foreign-pe would remove fails here (rel-1-0-6:GAP-0107).
    runtime = tmp_path / "runtime"
    (runtime / "python").mkdir(parents=True)
    (runtime / "python" / "python.exe").write_bytes(_pe_bytes(0x8664))
    foreign = runtime / relative
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_bytes(_pe_bytes(machine))

    with pytest.raises(artifacts.ArtifactError, match=re.escape(f"{relative} (machine 0x{machine:04x})")):
        artifacts.refuse_foreign_portable_executables(runtime)
    assert foreign.exists()


def test_x64_pe_check_refuses_a_tree_without_a_pe(tmp_path: Path) -> None:
    (tmp_path / "runtime").mkdir()
    (tmp_path / "runtime" / "README.txt").write_text("x\n", encoding="utf-8")

    with pytest.raises(artifacts.ArtifactError, match="not a Windows runtime"):
        artifacts.refuse_foreign_portable_executables(tmp_path / "runtime")


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="POSIX symlinks")
def test_foreign_pe_checks_follow_a_symlinked_file(tmp_path: Path) -> None:
    # The archive step reads a symlink as the file it names, so the checks do too.
    outside = tmp_path / "outside.dll"
    outside.write_bytes(_pe_bytes(0x014C))
    site = tmp_path / "runtime" / "site-packages"
    (site / "example").mkdir(parents=True)
    (site / "example" / "x64.dll").write_bytes(_pe_bytes(0x8664))
    os.symlink(outside, site / "example" / "helper.dll")

    with pytest.raises(artifacts.ArtifactError, match=r"example/helper\.dll"):
        artifacts.prune_foreign_portable_executables(site)
    with pytest.raises(artifacts.ArtifactError, match=r"example/helper\.dll"):
        artifacts.refuse_foreign_portable_executables(tmp_path / "runtime")


def test_scanner_runtime_builder_prunes_and_checks_pes_before_the_archive() -> None:
    # The standalone Windows scanner runtime (ProgramData\Cisco\
    # DefenseClaw-ScannerRuntime) is built by its own script; rc FINAL of
    # 1.0.8 still shipped pip's t32/w32/t64-arm/w64-arm.exe in it
    # (rel-1-0-6:GAP-0107).
    build = SCANNER_RUNTIME_SH.read_text(encoding="utf-8")
    helper = 'python3 -I "${REPO_ROOT}/scripts/windows_installer_artifacts.py"'
    prune = f'{helper} prune-foreign-pe --root "${{SITE}}"'
    check = f'{helper} check-x64-pe --root "${{RT}}"'
    assert build.count(prune) == 1
    assert build.count(check) == 1
    prune_at, check_at = build.index(prune), build.index(check)
    archive_at = build.index('echo "==> runtime.zip"')
    # After the last write into site-packages, before the archive.
    assert build.rindex('--target "${SITE}"') < prune_at < check_at < archive_at
    for writer in ("normalize_tiktoken_ranks.py", "win_unicode_console-0.5/", "DC_WHEEL"):
        assert build.rindex(writer) < prune_at
    # The archive step only removes files after the check; it adds none.
    tail = build[check_at:]
    assert "uv pip" not in tail and "write_bytes" not in tail
