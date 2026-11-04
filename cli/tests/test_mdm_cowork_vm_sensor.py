# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Anthropic v1.7 host-delivery template and lifecycle result contracts."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "packaging/mdm/macos/cowork-vm-sensor.mobileconfig.tmpl"
SCHEMA = ROOT / "packaging/mdm/contract/lifecycle-result.schema.json"


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_cowork_mdm_profile_selects_the_architecture_and_string_settings(arch: str) -> None:
    rendered = TEMPLATE.read_text().replace("__ARCH__", arch).replace("__VENDOR_ID__", escape("assigned-vendor"))
    profile = plistlib.loads(rendered.encode("utf-8"))
    assert profile["PayloadType"] == "Configuration"
    assert profile["PayloadScope"] == "System"
    assert len(profile["PayloadContent"]) == 1
    payload = profile["PayloadContent"][0]
    assert payload["PayloadType"] == "com.anthropic.claudefordesktop"
    assert payload["coworkEDRIntegration"] == (
        f"/Library/Application Support/Cisco/DefenseClaw/Cowork/defenseclaw-cowork-{arch}.tar.gz"
    )
    assert payload["coworkEDRIntegrationVendor"] == "assigned-vendor"
    settings = {k for k in payload if not k.startswith("Payload")}
    assert settings == {"coworkEDRIntegration", "coworkEDRIntegrationVendor"}


def _result(platform: str = "darwin", profile: str = "standalone") -> dict:
    return {
        "schema_version": 2,
        "ok": True,
        "action": "status",
        "noop": False,
        "profile": profile,
        "platform": platform,
        "product_version": "1.0.8",
        "installed": True,
        "transaction_pending": False,
        "services": [],
        "readiness": {k: False for k in ("gateway", "guardian", "enumerator", "sensor_helper")},
        "inspection": {"local": "active", "ai_defense": "disabled"},
        "machine_policy": {},
        "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": False,
        "security_complete": False,
        "errors": [],
        "exit_code": 0,
    }


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


@pytest.mark.parametrize("platform", ["darwin", "windows", "linux"])
def test_cowork_result_supports_disabled_and_incomplete_delivery(platform: str) -> None:
    result = _result(platform)
    result["cowork_vm_sensor"] = {"enabled": False, "host_ready": False, "settings_ready": False}
    validator = _validator()
    validator.validate(result)
    result["cowork_vm_sensor"] = {
        "enabled": True,
        "host_ready": False,
        "settings_ready": False,
        "reason_codes": ["platform_unsupported" if platform == "linux" else "signature_not_ready"],
    }
    validator.validate(result)


@pytest.mark.parametrize("platform", ["darwin", "windows"])
def test_cowork_ready_delivery_does_not_assert_vm_execution(platform: str) -> None:
    result = _result(platform)
    result["cowork_vm_sensor"] = {"enabled": True, "host_ready": True, "settings_ready": True}
    validator = _validator()
    validator.validate(result)
    result["cowork_vm_sensor"]["runtime_running"] = True
    assert list(validator.iter_errors(result))


def test_cowork_result_rejects_secure_client_and_unchecked_deployment() -> None:
    validator = _validator()
    state = {"enabled": False, "host_ready": False, "settings_ready": False}
    result = _result(profile="secure_client")
    validator.validate(result)
    result["cowork_vm_sensor"] = state
    assert list(validator.iter_errors(result))
    result = {
        key: value
        for key, value in _result().items()
        if key
        not in {
            "installed",
            "transaction_pending",
            "services",
            "readiness",
            "inspection",
            "machine_policy",
            "enrollment",
        }
    }
    result.update(ok=False, errors=[{"code": "not_root", "message": "run as root"}], exit_code=1)
    validator.validate(result)
    result["cowork_vm_sensor"] = state
    assert list(validator.iter_errors(result))


def test_cowork_result_rejects_impossible_readiness_and_unknown_fields() -> None:
    result = _result()
    validator = _validator()
    for state in (
        {"enabled": False, "host_ready": True, "settings_ready": False},
        {"enabled": False, "host_ready": False, "settings_ready": True},
        {"enabled": True, "host_ready": False},
        {"enabled": True, "host_ready": False, "settings_ready": False, "reason_codes": ["not a code"]},
    ):
        result["cowork_vm_sensor"] = state
        assert list(validator.iter_errors(result)), state
    result = _result("linux")
    result["cowork_vm_sensor"] = {"enabled": True, "host_ready": True, "settings_ready": True}
    assert list(validator.iter_errors(result))


def _run_unix_wrapper(tmp_path: Path, arguments: list[str], platform: str = "macos"):
    """Run the real wrapper with host operations isolated to the temp fixture."""
    import shlex
    import subprocess

    wrapper = (ROOT / "packaging/mdm" / platform / "defenseclaw-enterprise.sh").read_text()
    wrapper = wrapper.removesuffix('dc_main "$@"\n')
    gateway = tmp_path / "gateway"
    gateway.touch()
    parent = tmp_path / "private-stage"
    parent.mkdir(exist_ok=True)
    trace = tmp_path / "arguments"
    observed = tmp_path / "observed-package"
    observed_signature = tmp_path / "observed-signature"
    controls = f"""
DC_TEST_GATEWAY={shlex.quote(str(gateway))}
DC_TEST_STAGE={shlex.quote(str(parent))}
DC_TEST_TRACE={shlex.quote(str(trace))}
DC_TEST_OBSERVED={shlex.quote(str(observed))}
DC_TEST_SIGNATURE={shlex.quote(str(observed_signature))}
dc_layout() {{ DC_GATEWAY=$DC_TEST_GATEWAY; DC_LOG=""; DC_OS_GROUP=macos; }}
dc_log() {{ :; }}
dc_platform() {{ printf '%s\\n' "$DC_SCRIPT_OS"; }}
id() {{ printf '0\\n'; }}
dc_stage_parent() {{ DC_STAGE_PARENT=$DC_TEST_STAGE; }}
dc_sweep_stages() {{ :; }}
dc_stat_uid() {{ printf '0\\n'; }}
dc_trusted_path() {{ return 0; }}
dc_binaries_damaged() {{ return 1; }}
dc_resume_rotation() {{ :; }}
dc_annotate_package_step() {{ :; }}
dc_emit_result() {{ printf '{{}}\\n'; }}
dc_cleanup() {{ [ -z "$DC_STAGE" ] || rm -rf "$DC_STAGE"; }}
dc_run_lifecycle_retry() {{
    printf '%s\\0' "$@" >"$DC_TEST_TRACE"
    # Change the original after staging. Only the private copy may reach ensure.
    [ -z "$DC_COWORK_PACKAGE" ] || printf 'replaced' >"$DC_COWORK_PACKAGE"
    [ -z "$DC_COWORK_SIGNATURE" ] || printf 'replaced' >"$DC_COWORK_SIGNATURE"
    for argument do
        case "$argument" in
            --cowork-package=*) cat "${{argument#*=}}" >"$DC_TEST_OBSERVED" ;;
            --cowork-signature=*) cat "${{argument#*=}}" >"$DC_TEST_SIGNATURE" ;;
        esac
    done
}}
dc_main "$@"
"""
    result = subprocess.run(
        ["sh", "-c", wrapper + controls, "wrapper-test", *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin"},
    )
    return result, trace, observed, observed_signature, parent


def test_mdm_cowork_inputs_are_private_copies_forwarded_to_ensure(tmp_path: Path) -> None:
    archive = tmp_path / "defenseclaw-cowork-arm64.tar.gz"
    signature = tmp_path / "release.sig"
    archive.write_bytes(b"release archive")
    signature.write_bytes(b"detached signature")
    result, trace, observed, observed_signature, parent = _run_unix_wrapper(
        tmp_path, ["--cowork-package", str(archive), "--cowork-signature", str(signature)]
    )
    assert result.returncode == 0, result.stderr + result.stdout
    args = trace.read_bytes().split(b"\0")
    assert args[1:3] == [b"macos", b"ensure"]
    assert observed.read_bytes() == b"release archive"
    assert observed_signature.read_bytes() == b"detached signature"
    assert archive.read_bytes() == signature.read_bytes() == b"replaced"
    assert not list(parent.iterdir()), "temporary inputs must be removed after the lifecycle finishes"
    assert any(arg.startswith(b"--cowork-package=") and str(parent).encode() in arg for arg in args)
    assert any(arg.startswith(b"--cowork-signature=") and str(parent).encode() in arg for arg in args)


def test_mdm_cowork_signature_can_arrive_after_the_archive(tmp_path: Path) -> None:
    signature = tmp_path / "later.sig"
    signature.write_bytes(b"later signature")
    result, trace, _, observed_signature, _ = _run_unix_wrapper(tmp_path, ["--cowork-signature", str(signature)])
    assert result.returncode == 0, result.stderr + result.stdout
    args = trace.read_bytes().split(b"\0")
    assert not any(arg.startswith(b"--cowork-package=") for arg in args)
    assert observed_signature.read_bytes() == b"later signature"


def test_mdm_cowork_off_path_passes_no_inputs(tmp_path: Path) -> None:
    result, trace, observed, signature, _ = _run_unix_wrapper(tmp_path, [])
    assert result.returncode == 0, result.stderr + result.stdout
    assert b"--cowork-" not in trace.read_bytes()
    assert not observed.exists() and not signature.exists()


@pytest.mark.parametrize(
    ("platform", "extra"),
    [
        ("linux", []),
        ("macos", ["--action", "status"]),
        ("macos", ["--action", "verify"]),
        ("macos", ["--bundle-file", "/unopened/policy.dcbundle"]),
    ],
)
def test_mdm_cowork_inputs_refuse_unsupported_actions_before_lifecycle(
    tmp_path: Path, platform: str, extra: list[str]
) -> None:
    archive = tmp_path / "defenseclaw-cowork-arm64.tar.gz"
    archive.write_bytes(b"release archive")
    result, trace, _, _, _ = _run_unix_wrapper(tmp_path, ["--cowork-package", str(archive), *extra], platform)
    assert result.returncode == 2
    assert '"code":"mdm_invalid_arguments"' in result.stdout
    assert not trace.exists()
    assert archive.read_bytes() == b"release archive"


def test_windows_mdm_and_installer_forward_both_authenticated_inputs() -> None:
    wrapper = (ROOT / "packaging/mdm/windows/Invoke-DefenseClawEnterprise.ps1").read_text()
    installer = (ROOT / "packaging/windows/install-enterprise.ps1").read_text()
    assert "$script:MaxCoworkPackageBytes = 512MB" in wrapper
    assert "$script:MaxCoworkSignatureBytes = 1MB" in wrapper
    assert "SpecialFolder]::CommonApplicationData" in wrapper[wrapper.index("function New-WrapperStaging") :]
    for field, property_name, flag in (
        ("CoworkPackagePath", "COWORKPACKAGE", "--cowork-package"),
        ("CoworkSignaturePath", "COWORKSIGNATURE", "--cowork-signature"),
    ):
        assert f"[string]${field}" in wrapper
        assert f"Copy-WrapperInput -Source ${field}" in wrapper
        assert f'"{property_name}=$cowork' in wrapper
        assert f"@('{flag}', $cowork" in wrapper
        assert f"$arguments['{field}'] = ${field}" in installer
    assert "if ($EnterpriseProfile -cne 'Standalone' -and ($CoworkPackagePath -or $CoworkSignaturePath))" in installer
