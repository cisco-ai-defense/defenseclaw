# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Windows enterprise payload signer pin.

A production enterprise lifecycle accepts a payload file only when its valid
Authenticode signature names the DefenseClaw publisher, or a certificate an
administrator listed by SHA-256 fingerprint. Before the pin, any valid signer
was accepted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-payload-signer-smoke.ps1"
LIFECYCLE_CLI = ROOT / "internal" / "cli" / "windows_enterprise_service.go"


def read(path: Path) -> str:
    assert path.is_file(), f"required Windows enterprise artifact is missing: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    end = source.find("\nfunction ", start + 1)
    return source[start : end if end != -1 else len(source)]


def test_every_authenticode_source_check_pins_the_publisher() -> None:
    module = read(MODULE)
    assert "$script:DefenseClawPayloadPublisher = 'Cisco Systems, Inc.'" in module

    signer = function_body(module, "Assert-DefenseClawPayloadSigner")
    assert "Get-DefenseClawCertificateCommonName -Certificate $certificate" in signer
    assert "SimpleName" not in signer
    assert "[StringComparison]::Ordinal" in signer
    assert "Get-DefenseClawCertificateSha256" in signer
    assert "-ccontains $fingerprint" in signer
    assert "not the DefenseClaw publisher" in signer

    regular = function_body(module, "Assert-DefenseClawRegularSource")
    # The publisher check runs for every production Authenticode source and is
    # skipped only by the certification-only -AllowUnsigned relaxation.
    assert "if (-not $AllowUnsigned) {" in regular
    assert regular.index("SignatureStatus]::Valid") < regular.index(
        "Assert-DefenseClawPayloadSigner"
    )

    descriptor = function_body(module, "Get-DefenseClawSourceDescriptor")
    assert "trusted_signer_sha256 = $trustedSigners" in descriptor
    assert "-AdditionalTrustedSignerSha256 $trustedSigners" in descriptor

    current = function_body(module, "Assert-DefenseClawSourceDescriptorCurrent")
    assert "Get-DefenseClawSourceTrustedSigners -Source $Source" in current

    install = function_body(module, "Install-DefenseClawSourceDescriptor")
    assert "Get-DefenseClawSourceTrustedSigners -Source $Source" in install

    sources = function_body(module, "Get-DefenseClawLifecycleSources")
    assert sources.count("-AdditionalTrustedSignerSha256 $AdditionalTrustedSignerSha256") == 2

    lifecycle = function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    assert "[string[]]$AdditionalTrustedSignerSha256" in lifecycle
    assert "cannot be combined with -AllowUnsigned" in lifecycle
    assert lifecycle.index("ConvertTo-DefenseClawTrustedSignerSet") < lifecycle.index(
        "Assert-DefenseClawAdministrator"
    )
    assert "-AdditionalTrustedSignerSha256 $trustedSigners" in lifecycle


def test_fingerprint_parameter_accepts_only_sha256() -> None:
    for source, name in (
        (read(MODULE), "ConvertTo-DefenseClawTrustedSignerSet"),
        (read(INSTALLER), "ConvertTo-DefenseClawBootstrapTrustedSignerSet"),
    ):
        body = function_body(source, name)
        assert "'^[0-9A-Fa-f]{64}\\z'" in body
        assert "'^[0-9A-Fa-f]{40}\\z'" in body
        assert "SHA-1" in body
        assert "ToLowerInvariant()" in body


def test_installer_pins_module_signer_before_import() -> None:
    installer = read(INSTALLER)
    assert "[string[]]$AdditionalTrustedSignerSha256," in installer

    trust = function_body(installer, "Assert-DefenseClawBootstrapModuleTrust")
    assert trust.index("SignatureStatus]::Valid") < trust.index(
        "Assert-DefenseClawBootstrapModuleSigner"
    )
    bootstrap_signer = function_body(installer, "Assert-DefenseClawBootstrapModuleSigner")
    assert "'Cisco Systems, Inc.'" in bootstrap_signer
    assert "[StringComparison]::Ordinal" in bootstrap_signer
    assert (
        "Get-DefenseClawBootstrapCertificateCommonName -Certificate $certificate"
        in bootstrap_signer
    )
    assert "SimpleName" not in bootstrap_signer

    main = installer[installer.index("$bootstrapEnvironment = $null") :]
    assert "cannot be combined with -AllowUnsigned" in main
    assert main.index("ConvertTo-DefenseClawBootstrapTrustedSignerSet") < main.index(
        "Assert-DefenseClawBootstrapModuleTrust"
    )
    assert main.index("-AdditionalTrustedSignerSha256 $trustedSigners") < main.index(
        "Import-Module"
    )
    assert "AdditionalTrustedSignerSha256 = $trustedSigners" in main


def test_endpoint_signer_pin_matches_the_assembly_publisher_contract() -> None:
    """Every endpoint pin must accept exactly what Setup assembly accepts.

    The Setup EXE carries no additional trusted signer, so if the publisher
    enforced when the managed payload is assembled differs from the endpoint
    pin, a cleanly assembled Setup fails every endpoint lifecycle action.
    """
    literal = r"'([^']+)'"
    assembly_ps = read(ROOT / "packaging" / "scripts" / "lib" / "assert-cisco-signature.ps1")
    assembly_sh = read(ROOT / "packaging" / "scripts" / "lib" / "assert-cisco-signature.sh")
    broker = read(ROOT / "internal" / "managed" / "cmidbroker" / "library_trust.go")
    publishers = {
        "assembly (pwsh)": re.search(
            r"^\$script:DefenseClawCiscoPublisherCN = " + literal, assembly_ps, re.MULTILINE
        ),
        "assembly (bash)": re.search(
            r"^readonly _DEFENSECLAW_CISCO_PUBLISHER_CN=" + literal, assembly_sh, re.MULTILINE
        ),
        "lifecycle module": re.search(
            r"^\$script:DefenseClawPayloadPublisher = " + literal, read(MODULE), re.MULTILINE
        ),
        "bootstrap installer": re.search(
            r"\[string\]::Equals\(\$publisher, " + literal,
            function_body(read(INSTALLER), "Assert-DefenseClawBootstrapModuleSigner"),
        ),
        "cmid broker": re.search(r'^const CMIDLibraryPublisher = "([^"]+)"', broker, re.MULTILINE),
    }
    missing = [name for name, match in publishers.items() if match is None]
    assert not missing, f"publisher literal not found for: {missing}"
    values = {name: match.group(1) for name, match in publishers.items()}
    assert set(values.values()) == {"Cisco Systems, Inc."}, values

    # Both sides compare the same certificate name form, and assembly checks
    # every Authenticode payload file before it is embedded.
    assert "Get-CiscoSignatureCommonName -Certificate $sig.SignerCertificate" in assembly_ps
    assert "SimpleName" not in function_body(assembly_ps, "Assert-CiscoSignature")
    assert "subjectCommonName(certificateSubject(context))" in read(
        ROOT / "internal" / "managed" / "cmidbroker" / "library_trust_windows.go"
    )
    assert "Assert-CiscoSignature -Path (Join-Path $PayloadDir $name)" in read(
        ROOT / "packaging" / "scripts" / "lib" / "assemble.ps1"
    )
    assert 'defenseclaw_assert_cisco_signature "${PAYLOAD_DIR}/${name}"' in read(
        ROOT / "packaging" / "scripts" / "lib" / "assemble.sh"
    )


def _reader_code(source: str, name: str) -> str:
    """The reader's statements, without comments and with its name normalized."""
    body = function_body(source, name).replace(name, "READER")
    lines = [line.rstrip() for line in body.splitlines()]
    return "\n".join(line for line in lines if line.strip() and not line.lstrip().startswith("#"))


def test_every_publisher_pin_reads_the_subject_common_name_the_same_way() -> None:
    """The simple display name falls back to OU, O, or e-mail without a CN.

    Every PowerShell pin reads the CN attribute from the DER subject with the
    same code, so the module, the installer bootstrap, and Setup assembly
    cannot drift apart. The smoke exercises that code on both engines.
    """
    readers = {
        "lifecycle module": _reader_code(read(MODULE), "Get-DefenseClawCertificateCommonName"),
        "bootstrap installer": _reader_code(
            read(INSTALLER), "Get-DefenseClawBootstrapCertificateCommonName"
        ),
        "assembly (pwsh)": _reader_code(
            read(ROOT / "packaging" / "scripts" / "lib" / "assert-cisco-signature.ps1"),
            "Get-CiscoSignatureCommonName",
        ),
    }
    reference = readers["lifecycle module"]
    assert "$Certificate.SubjectName.RawData" in reference
    assert "SimpleName" not in reference
    assert "if ($commonNames.Count -ne 1) {" in reference
    for name, code in readers.items():
        assert code == reference, f"{name} reads the subject common name differently"


def _run_bash_assembly_helper(tmp_path: Path, subject: str) -> subprocess.CompletedProcess[str]:
    certificate = tmp_path / "signer.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", subject, "-keyout", str(tmp_path / "signer.key"), "-out", str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    signature = tmp_path / "signature.p7"
    subprocess.run(
        ["openssl", "crl2pkcs7", "-nocrl", "-certfile", str(certificate), "-out", str(signature)],
        check=True,
        capture_output=True,
    )
    # A stand-in for osslsigncode: the signature itself is accepted, and the
    # PKCS#7 it "extracts" carries the fixture certificate, so only the
    # helper's common-name check decides the outcome.
    tools = tmp_path / "bin"
    tools.mkdir()
    shim = tools / "osslsigncode"
    shim.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  verify) exit 0 ;;\n"
        "  extract-signature)\n"
        '    while [ "$#" -gt 0 ]; do\n'
        '      if [ "$1" = "-out" ]; then cp "$FIXTURE_SIGNATURE" "$2"; exit $?; fi\n'
        "      shift\n"
        "    done ;;\n"
        "esac\n"
        "exit 1\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    payload = tmp_path / "payload.exe"
    payload.write_bytes(b"MZ")
    helper = ROOT / "packaging" / "scripts" / "lib" / "assert-cisco-signature.sh"
    return subprocess.run(
        [
            "bash",
            "-c",
            'die() { echo "die $1: $2" >&2; exit "$1"; }; . "$1"; '
            'defenseclaw_assert_cisco_signature "$2"',
            "assert-cisco-signature-test",
            str(helper),
            str(payload),
        ],
        env={
            **os.environ,
            "PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}",
            "FIXTURE_SIGNATURE": str(signature),
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _bash_major_version() -> int:
    bash = shutil.which("bash")
    if bash is None:
        return 0
    completed = subprocess.run(
        [bash, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, check=False
    )
    return int(completed.stdout.strip() or 0)


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("openssl") is None or _bash_major_version() < 4,
    reason="requires bash 4+ and openssl",
)
@pytest.mark.parametrize(
    ("subject", "accepted"),
    [
        ("/CN=Cisco Systems, Inc./O=Cisco Systems, Inc./C=US", True),
        ("/OU=Cisco Systems, Inc./O=Example/C=US", False),
        ("/CN=Cisco Systems, Inc./CN=Example/C=US", False),
        ("/O=Example commonName = Cisco Systems, Inc./C=US", False),
        ("/CN=Cisco Systems Inc./O=Cisco Systems, Inc./C=US", False),
    ],
    ids=["publisher", "ou-only", "two-common-names", "name-in-another-value", "near-miss"],
)
def test_bash_assembly_helper_reads_exactly_one_common_name(
    tmp_path: Path, subject: str, accepted: bool
) -> None:
    completed = _run_bash_assembly_helper(tmp_path, subject)
    detail = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    if accepted:
        assert completed.returncode == 0, detail
    else:
        assert completed.returncode == 4, detail
        assert "does not carry a certificate with CN" in completed.stderr or (
            "no certificate subjects found" in completed.stderr
        ), detail


def test_cli_forwards_additional_signers_as_one_file_argument() -> None:
    cli = read(LIFECYCLE_CLI)
    assert '"additional-trusted-signer-sha256"' in cli
    assert (
        'args = append(args, "-AdditionalTrustedSignerSha256", '
        'strings.Join(opts.additionalTrustedSignerSHA256, ","))'
    ) in cli


def windows_powershell_engines() -> list[str]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = [
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "PowerShell" / "7" / "pwsh.exe",
    ]
    engines: list[str] = []
    for candidate in candidates:
        if candidate.is_file() and str(candidate) not in engines:
            engines.append(str(candidate))
    if not engines:
        fallback = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
        if fallback:
            engines.append(fallback)
    return engines


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_payload_signer_smoke_runs_on_every_engine(engine: str | None) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SMOKE),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, (
        f"payload signer smoke failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    for field in (
        "ok",
        "bootstrap_signer_pinned",
        "module_signer_pinned",
        "signer_common_name_required",
        "signer_fingerprint_validated",
        "lifecycle_parameter_validated",
    ):
        assert report[field] is True, field
    if report["foreign_signer_available"]:
        assert report["foreign_signer_rejected"] is True
        assert report["foreign_descriptor_recheck_pinned"] is True
