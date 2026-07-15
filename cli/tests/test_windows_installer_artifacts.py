"""Hermetic release-contract tests for the native Windows installer artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "scripts" / "windows_installer_artifacts.py"
BUILD_PS1 = ROOT / "scripts" / "build-windows-installer.ps1"
AUTHENTICODE_PS1 = ROOT / "scripts" / "windows-authenticode.ps1"
BINARY_IDENTITY_PS1 = ROOT / "scripts" / "windows-binary-identity.ps1"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yaml"
SPEC = importlib.util.spec_from_file_location("windows_installer_artifacts", HELPER_PATH)
assert SPEC and SPEC.loader
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()


def _write_zip(path: Path, files: dict[str, bytes]) -> None:
    path.write_bytes(_zip_bytes(files))


def _metadata(name: str, version: str, requires: str | None = None) -> bytes:
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {name}",
        f"Version: {version}",
        "License-Expression: Apache-2.0",
    ]
    if requires:
        lines.append(f"Requires-Dist: {requires}")
    return ("\n".join(lines) + "\n\n").encode()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> argparse.Namespace:
    version = "1.2.3"
    source_commit = "a" * 40
    payload = tmp_path / "payload"
    payload.mkdir()

    stdlib = _zip_bytes({"json/__init__.py": b"# stdlib\n"})
    python_name = "python-3.14.6-embed-amd64.zip"
    _write_zip(payload / python_name, {"python.exe": b"python", "python314.zip": stdlib})

    gateway_name = f"defenseclaw_{version}_windows_amd64.zip"
    _write_zip(
        payload / gateway_name,
        {"defenseclaw.exe": b"gateway", "defenseclaw-hook.exe": b"hook"},
    )

    wheel_name = f"defenseclaw-{version}-py3-none-any.whl"
    _write_zip(
        payload / wheel_name,
        {
            "defenseclaw/__init__.py": b"__version__ = '1.2.3'\n",
            f"defenseclaw-{version}.dist-info/METADATA": _metadata("defenseclaw", version),
        },
    )
    compat_name = "yara_python-4.5.4.post1-py3-none-any.whl"
    _write_zip(
        payload / compat_name,
        {
            "yara/__init__.py": b"# compat\n",
            "yara_python-4.5.4.post1.dist-info/METADATA": _metadata("yara-python", "4.5.4.post1"),
        },
    )

    defense_metadata = f"defenseclaw-{version}.dist-info"
    yara_metadata = "yara_python-4.5.4.post1.dist-info"
    site_files = {
        "defenseclaw/__init__.py": b"__version__ = '1.2.3'\n",
        f"{defense_metadata}/METADATA": _metadata("defenseclaw", version, "yara-python>=4.5.4"),
        f"{defense_metadata}/RECORD": (
            f"defenseclaw/__init__.py,,\n{defense_metadata}/METADATA,,\n{defense_metadata}/RECORD,,\n"
        ).encode(),
        "yara/__init__.py": b"# compat\n",
        f"{yara_metadata}/METADATA": _metadata("yara-python", "4.5.4.post1"),
        f"{yara_metadata}/RECORD": (
            f"yara/__init__.py,,\n{yara_metadata}/METADATA,,\n{yara_metadata}/RECORD,,\n"
        ).encode(),
    }
    _write_zip(payload / "site-packages.zip", site_files)

    for name, data in {
        "defenseclaw-launcher.exe": b"launcher",
        "defenseclaw-startup.exe": b"startup",
        "cosign.exe": b"cosign",
        "requirements-release.txt": b"example==1 --hash=sha256:abc\n",
        "upgrade-manifest.json": b"{}\n",
    }.items():
        (payload / name).write_bytes(data)

    names = sorted(path.name for path in payload.iterdir())
    manifest = {
        "schema_version": 2,
        "version": version,
        "source_commit": source_commit,
        "distribution_flavor": "oss",
        "python_version": "3.14.6",
        "gateway_archive": gateway_name,
        "wheel": wheel_name,
        "python_embed": python_name,
        "yara_compat_wheel": compat_name,
        "upgrade_manifest": "upgrade-manifest.json",
        "site_packages": "site-packages.zip",
        "launcher": "defenseclaw-launcher.exe",
        "startup_launcher": "defenseclaw-startup.exe",
        "cosign_verifier": "cosign.exe",
        "files": {name: _sha256(payload / name) for name in names},
    }
    setup = tmp_path / "DefenseClawSetup-x64.exe"
    setup.write_bytes(b"signed setup fixture")
    with zipfile.ZipFile(payload / gateway_name) as gateway:
        gateway_sha256 = hashlib.sha256(gateway.read("defenseclaw.exe")).hexdigest()
        hook_sha256 = hashlib.sha256(gateway.read("defenseclaw-hook.exe")).hexdigest()
    module_sum = "h1:" + base64.b64encode(b"\x01" * 32).decode()
    dependency = {"path": "example.com/security/module", "version": "v1.2.3", "sum": module_sum}
    component_hashes = {
        "setup": _sha256(setup),
        "gateway": gateway_sha256,
        "hook": hook_sha256,
        "launcher": _sha256(payload / "defenseclaw-launcher.exe"),
        "startup-launcher": _sha256(payload / "defenseclaw-startup.exe"),
        "cosign": _sha256(payload / "cosign.exe"),
    }
    authenticode_files = {}

    def add_evidence(installed_path: str, sbom_name: str, digest: str) -> None:
        authenticode_files[installed_path] = {
            "schema_version": 1,
            "installed_path": installed_path,
            "sbom_file_name": sbom_name,
            "sha256": digest,
            "expected": {"policy": "fixture"},
            "observed": {"status": "Valid", "embedded_signatures": [{}]},
        }

    add_evidence(setup.name, f"./{setup.name}", component_hashes["setup"])
    for installed_path in (
        "bin/defenseclaw.exe",
        "bin/skill-scanner.exe",
        "bin/mcp-scanner.exe",
        "bin/defenseclaw-observability.exe",
    ):
        add_evidence(installed_path, "./payload/defenseclaw-launcher.exe", component_hashes["launcher"])
    add_evidence(
        "bin/defenseclaw-startup.exe",
        "./payload/defenseclaw-startup.exe",
        component_hashes["startup-launcher"],
    )
    add_evidence("bin/defenseclaw-gateway.exe", "./expanded/gateway/defenseclaw.exe", gateway_sha256)
    add_evidence("bin/defenseclaw-hook.exe", "./expanded/gateway/defenseclaw-hook.exe", hook_sha256)
    add_evidence(
        "runtime/python/python.exe",
        "./expanded/python/python.exe",
        hashlib.sha256(b"python").hexdigest(),
    )
    add_evidence("runtime/tools/cosign.exe", "./payload/cosign.exe", component_hashes["cosign"])
    manifest["unsigned"] = False
    manifest["authenticode"] = {
        "schema_version": 1,
        "files": {name: evidence for name, evidence in authenticode_files.items() if name != setup.name},
    }
    (payload / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    embedded = tmp_path / "installer-payload.zip"
    artifacts.deterministic_zip(payload, embedded, 1_700_000_000, include_root=True)
    authenticode_inventory = tmp_path / "authenticode-inventory.json"
    authenticode_inventory.write_text(json.dumps({"schema_version": 1, "files": authenticode_files}), encoding="utf-8")
    go_inventory = tmp_path / "go-components.json"
    go_inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": {
                    label: {
                        "sha256": digest,
                        "runtime": "go1.26.4",
                        "module": {"path": "github.com/defenseclaw/defenseclaw", "version": "(devel)"},
                        "dependencies": [dependency],
                    }
                    for label, digest in component_hashes.items()
                },
            }
        ),
        encoding="utf-8",
    )
    return argparse.Namespace(
        setup=setup,
        payload_root=payload,
        embedded_payload=embedded,
        output=tmp_path / "DefenseClawSetup-x64.exe.sbom.json",
        version=version,
        source_commit=source_commit,
        source_epoch=1_700_000_000,
        python_version="3.14.6",
        cosign_version="2.6.2",
        go_inventory=go_inventory,
        authenticode_inventory=authenticode_inventory,
    )


def test_deterministic_zip_is_root_path_mtime_and_creation_order_independent(tmp_path: Path) -> None:
    roots = []
    for index, order in enumerate((("b.txt", "a.txt"), ("a.txt", "b.txt"))):
        root = tmp_path / f"root-{index}" / "payload"
        root.mkdir(parents=True)
        for name in order:
            (root / name).write_text(name, encoding="utf-8")
            os.utime(root / name, (time.time() + index * 1000, time.time() + index * 1000))
        roots.append(root)

    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    artifacts.deterministic_zip(roots[0], first, 1_700_000_001, include_root=True)
    artifacts.deterministic_zip(roots[1], second, 1_700_000_001, include_root=True)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == ["payload/a.txt", "payload/b.txt"]
        assert len({entry.date_time for entry in archive.infolist()}) == 1


def test_site_packages_normalization_removes_cache_paths_and_repairs_record(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    metadata = site / "example-1.0.dist-info"
    cache = site / "example" / "__pycache__"
    metadata.mkdir(parents=True)
    cache.mkdir(parents=True)
    (site / "example" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (cache / "module.cpython-314.pyc").write_bytes(b"C:\\host-specific\\module.py")
    (metadata / "direct_url.json").write_text(
        json.dumps({"url": "file:///C:/host-specific/example.whl"}), encoding="utf-8"
    )
    (metadata / "uv_cache.json").write_text(
        json.dumps({"timestamp": {"secs_since_epoch": 1_700_000_123}}), encoding="utf-8"
    )
    (metadata / "RECORD").write_text(
        "example/module.py,,\n"
        "example/__pycache__/module.cpython-314.pyc,,\n"
        "example-1.0.dist-info/direct_url.json,,\n"
        "example-1.0.dist-info/uv_cache.json,,\n"
        "example-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )

    result = artifacts.normalize_site_packages(site)

    assert result == {
        "removed_bytecode": 1,
        "removed_local_origins": 1,
        "removed_uv_cache": 1,
        "rewritten_records": 1,
    }
    assert not cache.exists()
    assert not (metadata / "direct_url.json").exists()
    assert not (metadata / "uv_cache.json").exists()
    assert (metadata / "RECORD").read_text(encoding="utf-8") == (
        "example/module.py,,\nexample-1.0.dist-info/RECORD,,\n"
    )


def test_builder_binds_authenticode_inventory_to_payload_provenance_and_sbom() -> None:
    build = BUILD_PS1.read_text(encoding="utf-8")
    helper = AUTHENTICODE_PS1.read_text(encoding="utf-8")
    assert ". $WindowsAuthenticodeHelper" in build
    assert "Get-DefenseClawAuthenticodeEvidence" in build
    assert build.index(". $WindowsAuthenticodeHelper") < build.index("Get-DefenseClawAuthenticodeEvidence")
    assert "schema_version = 2" in build
    assert "authenticode = $releaseAuthenticode" in build
    assert "'--authenticode-inventory', $authenticodeInventoryPath" in build
    assert "function Get-DefenseClawTimestampEvidence" in helper
    assert "ExpectedSignerThumbprintSha256" in helper


def test_builder_checks_distroot_gateway_and_hook_identity_before_signing() -> None:
    build = BUILD_PS1.read_text(encoding="utf-8")
    assert ". $WindowsBinaryIdentityHelper" in build
    gateway_check = (
        "-Path $gatewayBinary -ExpectedName 'defenseclaw-gateway' `\n"
        "    -ExpectedVersion $Version -ExpectedCommit $sourceCommit"
    )
    hook_check = (
        "-Path $hookBinary -ExpectedName 'defenseclaw-hook' `\n"
        "    -ExpectedVersion $Version -ExpectedCommit $sourceCommit"
    )
    assert gateway_check in build
    assert hook_check in build
    signing_call = "$payloadSigned = Set-FileSignaturesIfConfigured"
    assert build.index(gateway_check) < build.index(signing_call)
    assert build.index(hook_check) < build.index(signing_call)


def test_reproducible_launcher_builds_include_final_pe_resources() -> None:
    build = BUILD_PS1.read_text(encoding="utf-8")
    function = re.search(
        r"(?ms)^function Build-VerifiedGoBinary\b.*?(?=^function |\Z)", build
    )
    assert function
    body = function.group(0)
    assert "foreach ($target in @($verification, $Output))" in body
    assert "Set-WindowsExecutableResource $target $ResourceComponent" in body
    assert body.index("Set-WindowsExecutableResource") < body.index("Get-FileHashHex $target")
    assert "Build-VerifiedGoBinary $launcher" in build and "$reproducibilityRoot 'launcher'" in build
    assert "Build-VerifiedGoBinary $startupLauncher" in build and "$reproducibilityRoot 'startup'" in build


def test_signed_release_stages_offline_resource_verifier_before_lifecycle() -> None:
    build = BUILD_PS1.read_text(encoding="utf-8")
    publish = re.search(
        r"(?ms)^function Publish-SetupAcceptanceResourceInputs\b.*?(?=^function |\Z)",
        build,
    )
    assert publish
    for name in (
        "DefenseClawWindowsResourceVerifier-x64.exe",
        "DefenseClawWindowsResourceIcon.png",
        "DefenseClawWindowsResourceVersion.txt",
    ):
        assert name in publish.group(0)
    assert "Build-VerifiedGoBinary $verifier './internal/tools/windowsresources'" in publish.group(0)
    assert "Publish-SetupAcceptanceResourceInputs $out" in build

    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    builder = "./scripts/build-windows-installer.ps1"
    lifecycle = "./scripts/invoke-windows-setup-standard-user-ci.ps1"
    assert release.index(builder) < release.index(lifecycle)


def test_offline_chain_and_timeout_helpers_are_strictly_bounded() -> None:
    authenticode = AUTHENTICODE_PS1.read_text(encoding="utf-8")
    identity = BINARY_IDENTITY_PS1.read_text(encoding="utf-8")
    assert "DisableCertificateDownloads" in authenticode
    assert "$chain.ChainPolicy.DisableCertificateDownloads = $true" in authenticode
    assert "runtime with cache-only certificate-chain support" in authenticode
    assert "$process.WaitForExit($remaining)" in identity
    assert "$drainTask.Wait($remaining)" in identity
    assert "$process.WaitForExit()" not in identity


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process identity")
def test_stale_or_off_commit_distroot_binary_identity_is_rejected(tmp_path: Path) -> None:
    go = shutil.which("go")
    pwsh = shutil.which("pwsh")
    if not go or not pwsh:
        pytest.skip("Go and PowerShell are required for the binary identity regression test")

    source = tmp_path / "main.go"
    source.write_text(
        "package main\n"
        "import (\"encoding/json\"; \"os\")\n"
        "func main() { _ = json.NewEncoder(os.Stdout).Encode(map[string]any{"
        "\"schema_version\": 1, \"name\": os.Getenv(\"DC_IDENTITY_NAME\"), "
        "\"version\": os.Getenv(\"DC_IDENTITY_VERSION\"), "
        "\"commit\": os.Getenv(\"DC_IDENTITY_COMMIT\")}) }\n",
        encoding="utf-8",
    )
    executable = tmp_path / "distroot-binary.exe"
    build_env = os.environ.copy()
    build_env["CGO_ENABLED"] = "0"
    subprocess.run(
        [go, "build", "-o", executable, source],
        check=True,
        capture_output=True,
        text=True,
        env=build_env,
    )
    expected_commit = "a" * 40
    command = (
        ". $env:DC_IDENTITY_HELPER; "
        "Assert-DefenseClawBinaryIdentity -Path $env:DC_IDENTITY_BINARY "
        "-ExpectedName defenseclaw-gateway -ExpectedVersion 1.2.3 "
        "-ExpectedCommit $env:DC_EXPECTED_COMMIT | Out-Null"
    )
    base_env = os.environ.copy()
    base_env.update(
        {
            "DC_IDENTITY_HELPER": str(BINARY_IDENTITY_PS1),
            "DC_IDENTITY_BINARY": str(executable),
            "DC_IDENTITY_NAME": "defenseclaw-gateway",
            "DC_EXPECTED_COMMIT": expected_commit,
        }
    )
    cases = (
        ("1.2.2", expected_commit, "binary version mismatch"),
        ("1.2.3", "b" * 40, "binary source commit mismatch"),
    )
    for version, commit, diagnostic in cases:
        env = base_env.copy()
        env["DC_IDENTITY_VERSION"] = version
        env["DC_IDENTITY_COMMIT"] = commit
        result = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode != 0
        assert diagnostic in (result.stdout + result.stderr)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handle inheritance")
def test_binary_identity_output_drain_shares_the_process_deadline(tmp_path: Path) -> None:
    go = shutil.which("go")
    pwsh = shutil.which("pwsh")
    if not go or not pwsh:
        pytest.skip("Go and PowerShell are required for the binary identity timeout regression")

    source = tmp_path / "main.go"
    source.write_text(
        "package main\n"
        'import ("encoding/json"; "os"; "os/exec")\n'
        "func main() {\n"
        ' child := exec.Command("cmd.exe", "/d", "/c", "ping -n 6 127.0.0.1 >nul")\n'
        " child.Stdout = os.Stdout; child.Stderr = os.Stderr; _ = child.Start()\n"
        ' _ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version":1,'
        '"name":"defenseclaw-gateway","version":"1.2.3",'
        '"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})\n'
        "}\n",
        encoding="utf-8",
    )
    executable = tmp_path / "inherited-output.exe"
    subprocess.run(
        [go, "build", "-o", executable, source],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    command = (
        ". $env:DC_IDENTITY_HELPER; "
        "Assert-DefenseClawBinaryIdentity -Path $env:DC_IDENTITY_BINARY "
        "-ExpectedName defenseclaw-gateway -ExpectedVersion 1.2.3 "
        "-ExpectedCommit ('a' * 40) -TimeoutSeconds 1"
    )
    env = os.environ.copy()
    env.update(
        {
            "DC_IDENTITY_HELPER": str(BINARY_IDENTITY_PS1),
            "DC_IDENTITY_BINARY": str(executable),
        }
    )
    started = time.monotonic()
    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    elapsed = time.monotonic() - started
    assert result.returncode != 0
    assert "identity output streams did not close within 1 seconds" in result.stdout + result.stderr
    assert elapsed < 5


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Authenticode")
def test_digest_only_authenticode_evidence_is_strict_mode_safe(tmp_path: Path) -> None:
    go = shutil.which("go")
    pwsh = shutil.which("pwsh")
    if not go or not pwsh:
        pytest.skip("Go and PowerShell are required for the native Authenticode regression test")

    source = tmp_path / "main.go"
    source.write_text("package main\nfunc main() {}\n", encoding="utf-8")
    executable = tmp_path / "unsigned.exe"
    build_env = os.environ.copy()
    build_env["CGO_ENABLED"] = "0"
    subprocess.run(
        [go, "build", "-o", executable, source],
        check=True,
        capture_output=True,
        text=True,
        env=build_env,
    )

    test_env = os.environ.copy()
    test_env["DEFENSECLAW_AUTHENTICODE_HELPER"] = str(AUTHENTICODE_PS1)
    test_env["DEFENSECLAW_UNSIGNED_PE"] = str(executable)
    command = """
Set-StrictMode -Version Latest
. $env:DEFENSECLAW_AUTHENTICODE_HELPER
$evidence = Get-DefenseClawAuthenticodeEvidence `
    -Path $env:DEFENSECLAW_UNSIGNED_PE `
    -InstalledPath 'runtime/tools/cosign.exe' `
    -SbomFileName './payload/cosign.exe' `
    -Policy 'digest-only-upstream' `
    -ExpectedStatus 'NotSigned' `
    -ExpectedPublisher '' `
    -TimestampRequired $false
if (@($evidence.observed.embedded_signatures).Count -ne 0) {
    throw 'unsigned evidence unexpectedly contains embedded signatures'
}
"""
    subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
        env=test_env,
    )


def test_merged_spdx_covers_exact_and_expanded_windows_payload(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    summary = artifacts.build_sbom(args)
    document = json.loads(args.output.read_text(encoding="utf-8"))

    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["comment"] == f"DefenseClaw source commit: {args.source_commit}"
    assert summary["python_distributions"] == 2
    assert summary["go_modules"] == 2
    assert summary["payload_digests"] == 10
    assert summary["authenticode_files"] == 10
    assert {package["name"] for package in document["packages"]} >= {
        "DefenseClaw Windows Setup",
        "DefenseClaw embedded installer payload",
        "CPython embeddable runtime",
        "DefenseClaw gateway executable",
        "DefenseClaw hook executable",
        "DefenseClaw native CLI launcher",
        "DefenseClaw native startup launcher",
        "Sigstore Cosign verifier",
        "defenseclaw",
        "yara-python",
        "Go standard library",
        "example.com/security/module",
    }
    file_names = {file["fileName"] for file in document["files"]}
    assert "./expanded/python/stdlib/json/__init__.py" in file_names
    assert "./expanded/site-packages/defenseclaw/__init__.py" in file_names
    assert "./expanded/gateway/defenseclaw-hook.exe" in file_names
    setup_package = next(package for package in document["packages"] if package["name"] == "DefenseClaw Windows Setup")
    assert setup_package["checksums"][0]["checksumValue"] == _sha256(args.setup)
    setup_file = next(file for file in document["files"] if file["fileName"] == "./DefenseClawSetup-x64.exe")
    assert setup_file["comment"].startswith("DefenseClaw Authenticode evidence: ")
    hook_file = next(
        file for file in document["files"] if file["fileName"] == "./expanded/gateway/defenseclaw-hook.exe"
    )
    assert '"installed_path":"bin/defenseclaw-hook.exe"' in hook_file["comment"]


def test_sbom_fails_closed_when_payload_digest_no_longer_matches(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    (args.payload_root / "cosign.exe").write_bytes(b"tampered")
    with pytest.raises(artifacts.ArtifactError, match="Payload digest mismatch for cosign.exe"):
        artifacts.build_sbom(args)


def test_sbom_fails_closed_when_required_component_is_absent(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    (args.payload_root / "cosign.exe").unlink()
    with pytest.raises(artifacts.ArtifactError, match="Payload digest coverage mismatch"):
        artifacts.build_sbom(args)


def test_sbom_fails_closed_when_go_inventory_is_not_for_exact_binary(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    inventory = json.loads(args.go_inventory.read_text(encoding="utf-8"))
    inventory["components"]["setup"]["sha256"] = "0" * 64
    args.go_inventory.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(artifacts.ArtifactError, match="Go inventory binary digest does not match"):
        artifacts.build_sbom(args)


def test_sbom_fails_closed_when_release_authenticode_evidence_differs(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    inventory = json.loads(args.authenticode_inventory.read_text(encoding="utf-8"))
    inventory["files"]["bin/defenseclaw-hook.exe"]["sha256"] = "0" * 64
    args.authenticode_inventory.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(artifacts.ArtifactError, match="Release and payload Authenticode evidence differ"):
        artifacts.build_sbom(args)


def test_sbom_fails_closed_when_bound_authenticode_digest_differs(tmp_path: Path) -> None:
    args = _fixture(tmp_path)
    inventory = json.loads(args.authenticode_inventory.read_text(encoding="utf-8"))
    inventory["files"]["bin/defenseclaw-hook.exe"]["sha256"] = "0" * 64
    args.authenticode_inventory.write_text(json.dumps(inventory), encoding="utf-8")
    manifest_path = args.payload_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["authenticode"]["files"]["bin/defenseclaw-hook.exe"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    artifacts.deterministic_zip(args.payload_root, args.embedded_payload, args.source_epoch, include_root=True)
    with pytest.raises(artifacts.ArtifactError, match="evidence digest does not match SPDX file"):
        artifacts.build_sbom(args)
