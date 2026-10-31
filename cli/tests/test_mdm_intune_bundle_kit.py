# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts and Windows execution tests for signed bundles in the Intune kit."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MDM = ROOT / "packaging" / "mdm"
KIT = MDM / "intune" / "windows"
PACKAGER = KIT / "New-DefenseClawIntunePackage.ps1"
LAUNCHER = KIT / "Install-DefenseClawIntune.ps1"
DETECT = MDM / "windows" / "detect.ps1"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_packager_validates_bundle_inputs_before_hashing_setup() -> None:
    script = _text(PACKAGER)
    for parameter in ("BundlePath", "TrustAnchorPath", "RequireBundle"):
        assert f"[string]${parameter} = ''" in script
    setup_hash = script.index("$setup = (Resolve-Path -LiteralPath $SetupPath)")
    for refusal in (
        "if ($BundlePath -and $ConfigPath -and $BaseConfigPath)",
        "if ($BundlePath -and -not $ConfigPath -and -not $BaseConfigPath)",
        "if ($TrustAnchorPath -and -not $BundlePath)",
        "if ($BundlePath -and -not $RequireBundle)",
    ):
        assert script.index(refusal) < setup_hash
    for name in ("policy.dcbundle", "bundle-anchors.json"):
        assert f"Get-FileHash -LiteralPath (Join-Path $content '{name}')" in script
    assert "bundle_sha256   = $bundlePin" in script
    assert "trust_anchors_sha256 = $anchorPin" in script


def test_detection_twin_is_outside_uploaded_content() -> None:
    script = _text(PACKAGER)
    assert "Join-Path $OutputDirectory 'detect-bundle.ps1'" in script
    assert "Join-Path $content 'detect-bundle.ps1'" not in script
    assert "[regex]::Matches($detectText, [regex]::Escape($bundleDefault))).Count -ne 1" in script
    assert "[regex]::Matches($detectText, [regex]::Escape($versionDefault))).Count -ne 1" in script


def test_launcher_checks_pins_before_running_setup() -> None:
    script = _text(LAUNCHER)
    assert "$Pins.PSObject.Properties[$Name]" in script
    run = script.index("$run = Invoke-DefenseClawNative")
    for code in ("mdm_invalid_arguments", "mdm_package_incomplete", "mdm_hash_mismatch", "mdm_input_too_large"):
        assert code in script[:run]
    # A package with config.yaml and a bundle is the single app: Setup gets
    # both and stages the first install from the config (private #2).
    assert "pins both config.yaml and a policy bundle" not in script
    assert "if ($Uninstall -and $bundlePin -and -not $pins.config_sha256)" in script
    assert script.index("if ($anchorPin -and -not $bundlePin)") < run
    assert "if ($bundlePin) {\n    $arguments += ('BUNDLE='" in script
    assert "if ($anchorPin) {\n        $arguments += ('TRUSTANCHORS='" in script


def test_bundle_detection_fails_on_a_revoked_signer_before_applied() -> None:
    # GAP-0106: status keeps applied truthful and warns key_revoked; the
    # bundle detection turns that warning into NotDetected with its reason.
    script = _text(DETECT)
    revoked = script.index("[string]$_.code -eq 'key_revoked'")
    assert revoked < script.index("-not $status.applied")
    assert "is revoked in the installed trust anchors" in script[revoked:]


def _ps51() -> str | None:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    for part in ("SysWOW64", "System32"):
        path = Path(system_root) / part / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if path.is_file():
            return str(path)
    return shutil.which("powershell.exe")


def _windows_shells() -> tuple[str, str]:
    pwsh = shutil.which("pwsh.exe") or shutil.which("pwsh")
    ps51 = _ps51()
    if not pwsh or not ps51:
        pytest.skip(f"Windows PowerShell 5.1 and pwsh 7 required (ps51={bool(ps51)}, pwsh={bool(pwsh)})")
    return pwsh, ps51


def _run_ps(exe: str, script: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )


@pytest.fixture
def windows_kit(tmp_path: Path) -> dict[str, Path | str]:
    pwsh, ps51 = _windows_shells()
    setup = tmp_path / "DefenseClawSetup-Enterprise-Standalone-x64.exe"
    setup.write_bytes(b"stub Setup for packager checks")
    bundle = tmp_path / "input.dcbundle"
    bundle_config = (
        "guardrail:\n  block_at: HIGH\n  rule_pack: testpack\n  custom_packs:\n"
        "    testpack:\n      path: policies/guardrail/testpack\n"
        "      digest: sha256:" + "a" * 64 + "\n"
    )
    manifest = {
        "files": [
            {"path": "config.yaml", "sha256": hashlib.sha256(bundle_config.encode()).hexdigest()},
            {"path": "policies/guardrail/testpack/rules.yaml", "sha256": "b" * 64},
        ]
    }
    with tarfile.open(bundle, "w:gz") as archive:
        for name, data in (
            ("manifest.json", json.dumps(manifest).encode()),
            ("config.yaml", bundle_config.encode()),
            ("policies/guardrail/testpack/rules.yaml", b"rules: []\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    anchors = tmp_path / "anchors.json"
    anchors.write_text('{"schema_version":1,"anchors":[]}', encoding="ascii")
    config = tmp_path / "config.yaml"
    config.write_text(
        "config_version: 9\n"
        + bundle_config.replace("policies/guardrail/testpack", r"C:\ProgramData\DefenseClaw-RulePacks\testpack"),
        encoding="ascii",
    )
    return {
        "pwsh": pwsh,
        "ps51": ps51,
        "setup": setup,
        "bundle": bundle,
        "anchors": anchors,
        "config": config,
        "sha": hashlib.sha256(setup.read_bytes()).hexdigest(),
        "tmp": tmp_path,
    }


@pytest.fixture
def compiled_kit(windows_kit: dict[str, Path | str]) -> dict[str, Path | str]:
    setup = Path(windows_kit["setup"])
    setup.unlink()
    source = r"""
using System;
using System.IO;
public class StubSetup {
    static string Q(string s) { return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""; }
    public static int Main(string[] args) {
        string marker = Environment.GetEnvironmentVariable("DC_TEST_MARKER");
        if (marker != null) File.WriteAllText(marker, "started");
        string[] enc = new string[args.Length];
        for (int i = 0; i < args.Length; i++) enc[i] = Q(args[i]);
        Console.WriteLine("{\"schema_version\":2,\"ok\":true,\"action\":\"ensure\",\"exit_code\":0,\"argv\":[" + String.Join(",", enc) + "]}");
        return 0;
    }
}
"""
    builder = Path(windows_kit["tmp"]) / "build-stub.ps1"
    builder.write_text(
        "param([string]$OutputPath)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "$source = @'\n" + source + "\n'@\n"
        "Add-Type -TypeDefinition $source -OutputAssembly $OutputPath -OutputType ConsoleApplication\n",
        encoding="ascii",
    )
    built = _run_ps(str(windows_kit["ps51"]), builder, str(setup))
    if built.returncode != 0 or not setup.is_file():
        pytest.skip(f"Add-Type cannot compile the Setup stub: {built.stderr[:300]}")
    windows_kit["sha"] = hashlib.sha256(setup.read_bytes()).hexdigest()
    return windows_kit


def _package(kit: dict[str, Path | str], name: str, *options: str) -> tuple[Path, subprocess.CompletedProcess[str]]:
    out = Path(kit["tmp"]) / name
    if "-BundlePath" in options and "-BaseConfigPath" not in options and "-ConfigPath" not in options:
        options = (*options, "-BaseConfigPath", str(kit["config"]))
    result = _run_ps(
        str(kit["pwsh"]),
        PACKAGER,
        "-SetupPath",
        str(kit["setup"]),
        "-Sha256",
        str(kit["sha"]),
        "-OutputDirectory",
        str(out),
        *options,
    )
    return out, result


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell behavior")
def test_bundle_package_pins_copies_and_generates_detection(windows_kit: dict[str, Path | str]) -> None:
    out, result = _package(
        windows_kit,
        "bundle",
        "-BundlePath",
        str(windows_kit["bundle"]),
        "-TrustAnchorPath",
        str(windows_kit["anchors"]),
        "-RequireBundle",
        "7",
        "-ProductVersion",
        "1.2.3",
    )
    assert result.returncode == 0, result.stderr
    content = out / "content"
    assert {p.name for p in content.iterdir()} == {
        "DefenseClawSetup-Enterprise-Standalone-x64.exe",
        "Install-DefenseClawIntune.ps1",
        "policy.dcbundle",
        "bundle-anchors.json",
        "intune-package.json",
    }
    pins = json.loads((content / "intune-package.json").read_text(encoding="utf-8"))
    assert pins["config_sha256"] == ""
    for name, field in (("policy.dcbundle", "bundle_sha256"), ("bundle-anchors.json", "trust_anchors_sha256")):
        assert pins[field] == hashlib.sha256((content / name).read_bytes()).hexdigest()
    generated = out / "detect-bundle.ps1"
    assert generated.is_file() and generated.parent == out
    before, after = _text(DETECT).splitlines(), _text(generated).splitlines()
    assert len(before) == len(after)
    assert [(a, b) for a, b in zip(before, after) if a != b] == [
        ("    [string]$MinimumVersion = '',", "    [string]$MinimumVersion = '1.2.3',"),
        ("    [string]$RequireBundle = '',", "    [string]$RequireBundle = '7',"),
    ]
    parser = Path(windows_kit["tmp"]) / "parse.ps1"
    parser.write_text(
        "param([string]$File)\n$tokens = $null; $errors = $null\n"
        "[Management.Automation.Language.Parser]::ParseFile($File, [ref]$tokens, [ref]$errors) | Out-Null\n"
        "if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }\n",
        encoding="ascii",
    )
    for exe, paths in (
        (str(windows_kit["ps51"]), (LAUNCHER, generated)),
        (str(windows_kit["pwsh"]), (LAUNCHER, PACKAGER, generated)),
    ):
        for path in paths:
            assert _run_ps(exe, parser, str(path)).returncode == 0
    assert "Uninstall command: cmd.exe /c exit 0" in result.stdout
    assert "Dependency:" in result.stdout and "Custom script" in result.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell behavior")
@pytest.mark.parametrize(
    ("options", "message"),
    [
        (
            ("-BundlePath", "{bundle}", "-ConfigPath", "{config}", "-BaseConfigPath", "{config}", "-RequireBundle", "7"),
            "only for a bundle-only app",
        ),
        (("-BundlePath", "{bundle}", "-ConfigPath", "{config}"), "-RequireBundle is required"),
        (("-TrustAnchorPath", "{anchors}"), "needs -BundlePath"),
        (("-BundlePath", "{bundle}"), "-RequireBundle is required"),
        (("-RequireBundle", "7"), "needs -BundlePath"),
        (("-BundlePath", "{bundle}", "-RequireBundle", "0"), "positive version number"),
        (("-BundlePath", "{bundle}", "-RequireBundle", "abc"), "positive version number"),
        (("-BundlePath", "{bundle}", "-RequireBundle", "7", "-ProductVersion", "bad"), "valid version"),
        (("-BundlePath", "{empty}", "-RequireBundle", "7"), "1 to 4194304 bytes"),
        (("-BundlePath", "{large_bundle}", "-RequireBundle", "7"), "1 to 4194304 bytes"),
        (
            ("-BundlePath", "{bundle}", "-RequireBundle", "7", "-TrustAnchorPath", "{invalid_anchors}"),
            "schema_version 1",
        ),
        (
            ("-BundlePath", "{bundle}", "-RequireBundle", "7", "-TrustAnchorPath", "{private_anchors}"),
            "contains a private key",
        ),
        (
            ("-BundlePath", "{bundle}", "-RequireBundle", "7", "-TrustAnchorPath", "{large_anchors}"),
            "exceeds 65536 bytes",
        ),
    ],
)
def test_packager_refuses_invalid_inputs(
    windows_kit: dict[str, Path | str],
    options: tuple[str, ...],
    message: str,
) -> None:
    scratch = Path(windows_kit["tmp"])
    (scratch / "empty.dcbundle").write_bytes(b"")
    (scratch / "large.dcbundle").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    (scratch / "invalid-anchors.json").write_text("[]", encoding="ascii")
    (scratch / "large-anchors.json").write_bytes(b"x" * 65537)
    (scratch / "private-anchors.json").write_text(
        '{"schema_version":1,"note":"' + "-----BEGIN " + 'PRIVATE KEY-----"}', encoding="ascii"
    )
    inputs = dict(windows_kit)
    inputs.update(
        empty=scratch / "empty.dcbundle",
        large_bundle=scratch / "large.dcbundle",
        invalid_anchors=scratch / "invalid-anchors.json",
        private_anchors=scratch / "private-anchors.json",
        large_anchors=scratch / "large-anchors.json",
    )
    resolved = tuple(str(inputs[value[1:-1]]) if value.startswith("{") else value for value in options)
    out, result = _package(windows_kit, "rejected", *resolved)
    assert result.returncode != 0
    assert message in result.stderr
    assert not (out / "content").exists()


def _launch(content: Path, ps51: str, marker: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
    env = os.environ.copy()
    env["DC_TEST_MARKER"] = str(marker)
    result = _run_ps(ps51, content / LAUNCHER.name, env=env)
    document = json.loads(result.stdout.strip().splitlines()[-1])
    return result, document


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell behavior")
def test_launcher_passes_only_pinned_inputs(compiled_kit: dict[str, Path | str]) -> None:
    windows_kit = compiled_kit
    marker = Path(windows_kit["tmp"]) / "started"
    for name, options, expected in (
        (
            "with-anchors",
            (
                "-BundlePath",
                str(windows_kit["bundle"]),
                "-TrustAnchorPath",
                str(windows_kit["anchors"]),
                "-RequireBundle",
                "7",
            ),
            ("BUNDLE=", "TRUSTANCHORS="),
        ),
        ("bundle-only", ("-BundlePath", str(windows_kit["bundle"]), "-RequireBundle", "7"), ("BUNDLE=",)),
        ("base", ("-ConfigPath", str(windows_kit["config"])), ("CONFIG=",)),
        (
            "single-app",
            (
                "-ConfigPath",
                str(windows_kit["config"]),
                "-BundlePath",
                str(windows_kit["bundle"]),
                "-TrustAnchorPath",
                str(windows_kit["anchors"]),
                "-RequireBundle",
                "7",
            ),
            ("CONFIG=", "BUNDLE=", "TRUSTANCHORS="),
        ),
    ):
        out, built = _package(windows_kit, name, *options)
        assert built.returncode == 0, built.stderr
        content = out / "content"
        if name == "base":
            (content / "policy.dcbundle").write_bytes(b"unpinned")
        marker.unlink(missing_ok=True)
        result, document = _launch(content, str(windows_kit["ps51"]), marker)
        assert result.returncode == 0, result.stderr
        assert marker.is_file()
        assert document["schema_version"] == 2
        assert document["argv"][:2] == ["/ensure", "JSON=1"]
        assert document["argv"][2:] == [
            prefix
            + str(
                content
                / {"BUNDLE=": "policy.dcbundle", "TRUSTANCHORS=": "bundle-anchors.json", "CONFIG=": "config.yaml"}[
                    prefix
                ]
            )
            for prefix in expected
        ]


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell behavior")
@pytest.mark.parametrize(
    ("mutation", "code", "exit_code"),
    [
        ("bundle-byte", "mdm_hash_mismatch", 1603),
        ("anchors-byte", "mdm_hash_mismatch", 1603),
        ("bundle-delete", "mdm_package_incomplete", 1603),
        ("config-pin-without-file", "mdm_package_incomplete", 1603),
        ("anchors-only", "mdm_invalid_arguments", 1639),
        ("anchors-large", "mdm_input_too_large", 1639),
    ],
)
def test_launcher_refuses_tampered_packages(
    compiled_kit: dict[str, Path | str],
    mutation: str,
    code: str,
    exit_code: int,
) -> None:
    windows_kit = compiled_kit
    out, built = _package(
        windows_kit,
        mutation,
        "-BundlePath",
        str(windows_kit["bundle"]),
        "-TrustAnchorPath",
        str(windows_kit["anchors"]),
        "-RequireBundle",
        "7",
    )
    assert built.returncode == 0, built.stderr
    content = out / "content"
    pins_path = content / "intune-package.json"
    pins = json.loads(pins_path.read_text(encoding="utf-8"))
    if mutation == "bundle-byte":
        (content / "policy.dcbundle").write_bytes(b"changed")
    elif mutation == "anchors-byte":
        (content / "bundle-anchors.json").write_bytes(b"changed")
    elif mutation == "bundle-delete":
        (content / "policy.dcbundle").unlink()
    elif mutation == "config-pin-without-file":
        pins["config_sha256"] = "0" * 64
    elif mutation == "anchors-only":
        pins["bundle_sha256"] = ""
    else:
        (content / "bundle-anchors.json").write_bytes(b"x" * 65537)
    pins_path.write_text(json.dumps(pins), encoding="utf-8")
    marker = Path(windows_kit["tmp"]) / "started"
    marker.unlink(missing_ok=True)
    result, document = _launch(content, str(windows_kit["ps51"]), marker)
    assert result.returncode == exit_code, result.stderr
    assert document["schema_version"] == 2
    assert document["errors"][0]["code"] == code
    assert not marker.exists()
