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

"""rel-1-0-10 GAP-0006: an upgrade built its fresh environment from a uv
cache whose LiteLLM files had been changed through a hard link, so the MCP
scanner did not import; `mcp scan` said the scanner was not installed and
doctor passed it. The installers now compare every package with its wheel
RECORD and download a damaged one again; doctor and `mcp scan` name it."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from defenseclaw import venv_integrity
from defenseclaw.commands import cmd_doctor

from tests.helpers import POWERSHELL, run_powershell

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "cli" / "defenseclaw" / "venv_integrity.py"
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
BASH = shutil.which("bash")
UV = shutil.which("uv")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _site(tmp_path: Path, files: dict[str, bytes]) -> Path:
    site = tmp_path / "site-packages"
    info = site / "demo-2.0.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: Demo_Pkg\nVersion: 2.0\n\nbody\n")
    rows = []
    for name, data in files.items():
        path = site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        rows.append(f"{name},sha256={_b64(data)},{len(data)}\n")
    rows.append("demo-2.0.dist-info/RECORD,,\n")
    (info / "RECORD").write_text("".join(rows))
    return site


def test_damaged_files_names_changed_resized_and_missing_files(tmp_path: Path) -> None:
    site = _site(
        tmp_path,
        {
            "demo/__init__.py": b"from demo.loader import NEW\n",
            "demo/loader.py": b"NEW = 2\n",
            "demo/data.bin": b"\x00" * 8,
            "demo/gone.py": b"x = 1\n",
        },
    )
    assert venv_integrity.damaged_files(site) == {}
    (site / "demo" / "loader.py").write_bytes(b"OLD = 1\n")  # same size, other content
    (site / "demo" / "__init__.py").write_bytes(b"from demo.ocr import use_rust\n")
    (site / "demo" / "gone.py").unlink()
    damaged = venv_integrity.damaged_files(site)
    assert list(damaged) == ["Demo_Pkg"]
    assert sorted(damaged["Demo_Pkg"]) == [
        "demo/__init__.py (30 bytes, the wheel has 28)",
        "demo/gone.py (missing)",
        "demo/loader.py (content differs from the wheel)",
    ]
    assert venv_integrity.damaged_files(site, {"other"}) == {}
    assert list(venv_integrity.damaged_files(site, {venv_integrity.normalize("demo.pkg")})) == ["Demo_Pkg"]
    done = subprocess.run([sys.executable, "-I", str(MODULE), str(site)], capture_output=True, text=True, timeout=60)
    assert done.returncode == venv_integrity.DAMAGED_EXIT, done.stderr
    assert done.stdout == "Demo_Pkg\n"
    assert "Demo_Pkg: demo/gone.py (missing)" in done.stderr
    assert subprocess.run([sys.executable, "-I", str(MODULE)], capture_output=True, timeout=60).returncode == 2


def _wheel(directory: Path, name: str, version: str, files: dict[str, bytes]) -> Path:
    info = f"{name}-{version}.dist-info"
    files = dict(files)
    files[f"{info}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    files[f"{info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = "".join(f"{path},sha256={_b64(data)},{len(data)}\n" for path, data in files.items())
    files[f"{info}/RECORD"] = (record + f"{info}/RECORD,,\n").encode()
    path = directory / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            archive.writestr(member, data)
    return path


def _install_sh_functions(*names: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    bodies = []
    for name in names:
        if f"\n{name}() {{" not in text and name != "make_venv":
            continue  # a helper an older installer did not have
        start = text.index(f"\n{name}() {{") + 1
        bodies.append(text[start : text.index("\n}\n", start) + 3])
    return "".join(bodies)


@pytest.mark.skipif(os.name == "nt" or BASH is None or UV is None, reason="POSIX installer with uv")
def test_install_sh_heals_an_environment_built_from_a_changed_uv_cache(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    loader = b"NEW = 2  # the loader of the wheel\n"
    demo = _wheel(staging, "dcdemo", "2.0", {"dcdemo/__init__.py": b"from dcdemo.loader import NEW\n", "dcdemo/loader.py": loader})
    wheel = _wheel(
        staging,
        "defenseclaw",
        "0.0.1",
        {"defenseclaw/__init__.py": b"", "defenseclaw/venv_integrity.py": MODULE.read_bytes()},
    )
    digest = hashlib.sha256(demo.read_bytes()).hexdigest()
    (staging / "requirements.txt").write_text(f"dcdemo @ {demo.as_uri()} --hash=sha256:{digest}\n")
    script = tmp_path / "make.sh"
    script.write_text(
        "set -euo pipefail\n"
        "info() { echo \"info: $*\"; }\nwarn() { echo \"warn: $*\"; }\nerr() { echo \"err: $*\" >&2; }\n"
        f"STAGING={staging}\nREQUIREMENTS=requirements.txt\nWHEEL={wheel.name}\nDEFENSECLAW_HOME={tmp_path}\n"
        + _install_sh_functions("install_venv_packages", "make_venv")
        + "make_venv \"$1\"\n"
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "UV_CACHE_DIR": str(tmp_path / "cache"),
        "UV_NO_CONFIG": "1",
        "UV_LINK_MODE": "hardlink",
        "UV_OFFLINE": "1",
    }

    def make(venv: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run([BASH, str(script), str(venv)], capture_output=True, text=True, env=env, timeout=300)

    first = make(tmp_path / "first")
    assert first.returncode == 0, first.stdout + first.stderr
    installed = next((tmp_path / "first").glob("lib/python*/site-packages/dcdemo/loader.py"))
    if installed.stat().st_nlink < 2:
        pytest.skip("uv did not hard-link the package from its cache on this filesystem")
    # Something writes into the installed file in place: the cached copy changes too.
    with open(installed, "r+b") as handle:
        handle.truncate(0)
        handle.write(b"OLD = 1\n")
    second = make(tmp_path / "second")
    assert second.returncode == 0, second.stdout + second.stderr
    rebuilt = next((tmp_path / "second").glob("lib/python*/site-packages/dcdemo/loader.py"))
    assert rebuilt.read_bytes() == loader, second.stdout + second.stderr
    assert "dcdemo" in second.stdout and "differ from their wheels" in second.stdout
    python = next((tmp_path / "second").glob("bin/python"))
    assert subprocess.run([str(python), "-c", "import dcdemo"], capture_output=True, timeout=60).returncode == 0


def _ps1_function(name: str) -> str:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    match = re.search(rf"^function {re.escape(name)}[ (]", text, re.M)
    assert match is not None, name
    return text[match.start() : text.index("\n}\n", match.start()) + 3]


def test_install_ps1_checks_every_new_environment_after_the_wheel() -> None:
    venv = _ps1_function("New-Venv")
    assert venv.index("Invoke-UvPipInstall $wheelArgs") < venv.index("Repair-DamagedPackages $python $Where $lockArgs $wheelArgs")


@pytest.mark.skipif(POWERSHELL is None or os.name == "nt", reason="needs pwsh running shebang fakes")
def test_install_ps1_downloads_a_damaged_package_again(tmp_path: Path) -> None:
    calls = tmp_path / "calls.log"
    state = tmp_path / "checked-once"
    scripts = tmp_path / "venv" / "Scripts"
    scripts.mkdir(parents=True)
    python = scripts / "python"
    python.write_text(
        "#!/bin/sh\n"
        f"echo \"python $*\" >>\"{calls}\"\n"
        f"if [ -e \"{state}\" ]; then exit 0; fi\n"
        f": >\"{state}\"\n"
        "echo litellm\necho \"litellm: litellm/rust_bridge/loader.py (815 bytes, the wheel has 1070)\" >&2\nexit 3\n"
    )
    uv = tmp_path / "uv"
    uv.write_text(f"#!/bin/sh\necho \"uv $*\" >>\"{calls}\"\nexit 0\n")
    for fake in (python, uv):
        fake.chmod(0o755)
    functions = "".join(
        _ps1_function(name)
        for name in ("Invoke-Native", "Get-NativeProbe", "Invoke-BelowNormal", "Invoke-Uv", "Invoke-UvPipInstall", "Repair-DamagedPackages")
    )
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "$ErrorActionPreference = \"Stop\"\n"
        f"$Uv = \"{uv}\"\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        "function Test-DiskFull { return $false }\n"
        "function Repair-TiktokenRanks([string]$P, [string]$W) { }\n"
        + functions
        + f"$ok = Repair-DamagedPackages \"{python}\" \"the final environment\" @(\"pip\", \"install\", \"-r\", \"lock.txt\") @(\"pip\", \"install\", \"dc.whl\")\n"
        "Write-Host \"result=$ok\"\n"
    )
    done = run_powershell(["-NoProfile", "-File", str(harness)], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "result=True" in done.stdout, done.stdout
    assert "litellm in the final environment differ from their wheels" in done.stdout
    log = calls.read_text().splitlines()
    assert "uv cache clean litellm" in log, log
    assert "uv pip install -r lock.txt --reinstall-package litellm" in log, log
    assert "uv pip install dc.whl --reinstall-package litellm" in log, log
    assert len([line for line in log if line.startswith("python -I ")]) == 2, log


_UNIMPORTABLE = "ImportError: cannot import name \x27use_litellm_rust\x27 from \x27litellm.rust_bridge.ocr\x27"


def _check_scanners_rows(mcp_import_error: str, damaged: dict[str, list[str]]) -> dict[str, dict]:
    def run(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="skill-scanner 2.3.2\n", stderr="")

    cfg = type("Cfg", (), {})()
    result = cmd_doctor._DoctorResult()
    with (
        patch("defenseclaw.commands.cmd_doctor.resolve_scanner_binary", side_effect=lambda b: "/opt/dc/.venv/bin/" + b),
        patch("defenseclaw.commands.cmd_doctor.subprocess.run", side_effect=run),
        patch("defenseclaw.commands.cmd_doctor._scanner_version_note", side_effect=lambda dist, v: ("pass", f"{dist} {v}")),
        patch.object(venv_integrity, "damaged_files", return_value=damaged),
        patch.object(venv_integrity, "import_error", return_value=mcp_import_error) as probe,
    ):
        cmd_doctor._check_scanners(cfg, result)
    assert probe.call_args.args == ("from mcpscanner import Config, Scanner",)
    return {check["label"]: check for check in result.checks}


@pytest.mark.skipif(sys.version_info < (3, 11), reason="the scanners need Python 3.11")
def test_doctor_fails_a_scanner_that_is_installed_but_does_not_import() -> None:
    rows = _check_scanners_rows(
        _UNIMPORTABLE,
        {"litellm": ["litellm/rust_bridge/__init__.py (264 bytes, the wheel has 320)"]},
    )
    row = rows["Scanner: mcp-scanner"]
    assert row["status"] == "fail", row
    assert "is installed but does not import (" + _UNIMPORTABLE + ")" in row["detail"]
    assert "litellm: litellm/rust_bridge/__init__.py (264 bytes, the wheel has 320)" in row["detail"]
    assert venv_integrity.install_repair_hint("the Python environment", windows=os.name == "nt") in row["detail"]

    healthy = _check_scanners_rows("", {})
    assert healthy["Scanner: mcp-scanner"]["status"] == "pass"
    assert healthy["Scanner: mcp-scanner"]["detail"].endswith(", imports")


def test_mcp_scan_says_the_scanner_is_installed_but_does_not_import() -> None:
    from defenseclaw.scanner import mcp

    damaged = {"litellm": ["litellm/rust_bridge/__init__.py (264 bytes, the wheel has 320)"]}
    with (
        patch("importlib.metadata.version", return_value="4.8.7"),
        patch.object(venv_integrity, "damaged_files", return_value=damaged),
    ):
        text = mcp.mcp_scanner_import_error(ImportError(_UNIMPORTABLE.split(": ", 1)[1]))
    assert "not installed" not in text
    assert text.startswith("error: cisco-ai-mcp-scanner 4.8.7 is installed but does not import: " + _UNIMPORTABLE)
    assert "litellm/rust_bridge/__init__.py (264 bytes, the wheel has 320)" in text
    assert venv_integrity.install_repair_hint("the Python environment", windows=os.name == "nt") in text
    assert "mcp_scanner_import_error(exc)" in Path(mcp.__file__).read_text(encoding="utf-8")


def test_the_repair_hint_follows_the_platform_doctor_sees(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Windows row names the install command, also when doctor runs its
    # Windows checks with a patched os view, as the doctor tests do.
    windows = venv_integrity.install_repair_hint("the gateway", windows=True)
    assert "running the install command again" in windows and "defenseclaw-upgrade.sh" not in windows
    assert "`bash defenseclaw-upgrade.sh --yes`" in venv_integrity.install_repair_hint("the gateway", windows=False)
    monkeypatch.setattr(cmd_doctor, "os", type("NtOs", (), {"name": "nt"})())
    assert cmd_doctor._install_repair_hint("the gateway") == windows


def test_import_error_reports_the_last_line_of_a_failed_import() -> None:
    assert venv_integrity.import_error("import json") == ""
    failed = venv_integrity.import_error("from json import no_such_name")
    assert failed.startswith("ImportError: cannot import name"), failed


# --- rel-1-0-10 GAP-0938: doctor remembers a passing import probe -----------

_PROBE_STATEMENT = "from mcpscanner import Config, Scanner"
_KEY = {"python": "/v/bin/python", "defenseclaw": "1.0.10", "package": [1, 2], "mcp": ["4.0", [3, 4]], "lite": ["1.1", [5, 6]]}


def _probe(cache: Path, key: dict, result: str | None = "") -> tuple[str | None, object]:
    with patch.object(venv_integrity, "import_error", return_value=result) as child:
        return venv_integrity.cached_import_error(_PROBE_STATEMENT, str(cache), key), child


def test_a_passing_probe_is_remembered_and_skips_the_child(tmp_path: Path) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    first, child = _probe(cache, _KEY)
    assert first == "" and child.call_count == 1
    second, child = _probe(cache, dict(_KEY))
    assert second == "" and child.call_count == 0
    if os.name != "nt":
        assert (cache.stat().st_mode & 0o077) == 0


@pytest.mark.parametrize(
    "change",
    [
        {"python": "/other/bin/python"},
        {"defenseclaw": "1.0.11"},
        {"package": [1, 3]},
        {"package": None},
        {"mcp": ["4.1", [3, 4]]},
        {"mcp": ["4.0", [9, 4]]},
        {"mcp": ["4.0", [3, 9]]},
        {"lite": ["1.2", [5, 6]]},
        {"lite": ["1.1", [5, 7]]},
    ],
)
def test_every_part_of_the_key_runs_the_probe_again(tmp_path: Path, change: dict) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    _probe(cache, _KEY)
    _, child = _probe(cache, {**_KEY, **change})
    assert child.call_count == 1


@pytest.mark.parametrize(
    "content",
    ["", "not json", "[]", "null", "{\"key\": {}}", "{\"key\": null, \"error\": \"\", \"at\": 1}"],
)
def test_a_corrupt_cache_runs_the_probe_again(tmp_path: Path, content: str) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    cache.write_text(content, encoding="utf-8")
    result, child = _probe(cache, _KEY)
    assert result == "" and child.call_count == 1
    # and the run repaired the cache
    _, child = _probe(cache, _KEY)
    assert child.call_count == 0


def test_a_cache_with_the_wrong_field_types_runs_the_probe_again(tmp_path: Path) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    for record in (
        {"key": _KEY, "error": 3, "at": time.time()},
        {"key": _KEY, "error": "", "at": "now"},
        {"key": _KEY, "error": "", "at": True},
        {"key": _KEY, "error": "", "at": time.time() + 3600},
    ):
        cache.write_text(json.dumps(record), encoding="utf-8")
        _, child = _probe(cache, _KEY)
        assert child.call_count == 1, record


def test_a_broken_import_is_still_reported_and_a_key_change_clears_it(tmp_path: Path) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    broken, child = _probe(cache, _KEY, _UNIMPORTABLE)
    assert broken == _UNIMPORTABLE and child.call_count == 1
    again, child = _probe(cache, _KEY, "")
    assert again == _UNIMPORTABLE and child.call_count == 0  # the failure is remembered
    repaired, child = _probe(cache, {**_KEY, "lite": ["1.1", [8, 6]]}, "")
    assert repaired == "" and child.call_count == 1  # a repair changes the key: probed again
    assert _probe(cache, {**_KEY, "lite": ["1.1", [8, 6]]})[0] == ""


def test_the_remembered_results_expire(tmp_path: Path) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    now = time.time()
    cache.write_text(json.dumps({"key": _KEY, "error": "", "at": now - venv_integrity.PROBE_PASS_MAX_AGE - 5}))
    assert _probe(cache, _KEY)[1].call_count == 1
    cache.write_text(json.dumps({"key": _KEY, "error": "boom", "at": now - venv_integrity.PROBE_FAIL_MAX_AGE - 5}))
    assert _probe(cache, _KEY)[1].call_count == 1


def test_a_timeout_and_an_unwritable_cache_are_not_remembered(tmp_path: Path) -> None:
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    assert _probe(cache, _KEY, None)[0] is None
    assert not cache.exists()
    missing = tmp_path / "no-such-dir" / venv_integrity.PROBE_CACHE_NAME
    result, child = _probe(missing, _KEY)
    assert result == "" and child.call_count == 1


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlinked_cache_is_not_read(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"key": _KEY, "error": "", "at": time.time()}))
    cache = tmp_path / venv_integrity.PROBE_CACHE_NAME
    cache.symlink_to(real)
    assert _probe(cache, _KEY)[1].call_count == 1


def test_probe_key_follows_the_package_folder_and_the_distribution_record(tmp_path: Path, monkeypatch) -> None:
    pkg = tmp_path / "dcprobepkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(tmp_path))
    first = venv_integrity.probe_key("dcprobepkg", ("no-such-distribution-xyz",), "1.0.10")
    assert first["package"] and first["no-such-distribution-xyz"] is None
    assert first["python"] == sys.executable and first["defenseclaw"] == "1.0.10"
    os.utime(pkg, ns=(1_000_000_000, 2_000_000_000))
    assert venv_integrity.probe_key("dcprobepkg", ("no-such-distribution-xyz",), "1.0.10") != first
    assert venv_integrity.probe_key("dcprobepkg", ("no-such-distribution-xyz",), "1.0.11") != first
    assert venv_integrity.probe_key("no_such_pkg_xyz", (), "1")["package"] is None
    real = venv_integrity.probe_key("pytest", ("pytest",), "1")
    assert real["pytest"][0] and real["pytest"][1]  # version and a RECORD stamp


@pytest.mark.skipif(sys.version_info < (3, 11), reason="the scanners need Python 3.11")
def test_doctor_runs_the_child_once_per_environment_and_still_fails_a_broken_one(tmp_path: Path) -> None:
    def rows(error: str) -> tuple[dict, object]:
        def run(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="skill-scanner 2.3.2\n", stderr="")

        cfg = type("Cfg", (), {"data_dir": str(tmp_path)})()
        result = cmd_doctor._DoctorResult()
        with (
            patch("defenseclaw.commands.cmd_doctor.resolve_scanner_binary", side_effect=lambda b: "/opt/dc/.venv/bin/" + b),
            patch("defenseclaw.commands.cmd_doctor.subprocess.run", side_effect=run),
            patch("defenseclaw.commands.cmd_doctor._scanner_version_note", side_effect=lambda dist, v: ("pass", f"{dist} {v}")),
            patch.object(venv_integrity, "damaged_files", return_value={}),
            patch.object(venv_integrity, "probe_key", return_value=dict(_KEY)),
            patch.object(venv_integrity, "import_error", return_value=error) as child,
        ):
            cmd_doctor._check_scanners(cfg, result)
        return {c["label"]: c for c in result.checks}["Scanner: mcp-scanner"], child

    row, child = rows("")
    assert row["status"] == "pass" and child.call_count == 1
    row, child = rows(_UNIMPORTABLE)  # remembered pass: no child, the old result
    assert row["status"] == "pass" and child.call_count == 0
    (tmp_path / venv_integrity.PROBE_CACHE_NAME).unlink()
    row, child = rows(_UNIMPORTABLE)
    assert row["status"] == "fail" and _UNIMPORTABLE in row["detail"] and child.call_count == 1
    row, child = rows("")  # a remembered failure still fails (until its key changes or it expires)
    assert row["status"] == "fail" and child.call_count == 0
