# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_third_party_license_text_and_platform_packaging_contracts():
    third_party = (ROOT / "THIRD_PARTY_LICENSES.txt").read_text(encoding="utf-8")
    section_separator = "=" * 78
    heading, first_section, _ = third_party.partition(f"{section_separator}\n")
    assert first_section
    assert "not an exhaustive inventory" in " ".join(heading.split())

    def exact_section(title: str) -> str:
        marker = f"{section_separator}\n{title}\n{section_separator}\n\n"
        assert third_party.count(marker) == 1
        remainder = third_party.partition(marker)[2]
        body, next_section, _ = remainder.partition(f"\n{section_separator}\n")
        return body if next_section else remainder

    section_digests = {
        "mvdan.cc/sh/v3 v3.13.1 (BSD-3-Clause)": (
            "ce63850f77649f00d1394045e2794ffb09a5596beabac51c9548edd958845d7c"
        ),
        "github.com/google/cel-go v0.30.0 (LICENSE)": (
            "4cdb9af102dfbb0ca03d87d6f650a505df098646a4080f4665b389ad9c6caa02"
        ),
        "github.com/antlr4-go/antlr/v4 v4.13.1 (LICENSE)": (
            "683fcd416d83b64781e229a3c2a598462fbf55c5c9fea54be244766b22c033cf"
        ),
        "golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f (LICENSE)": (
            "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
        ),
        "golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f (PATENTS)": (
            "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"
        ),
        "github.com/NVIDIA/OpenShell/sdk/go v0.0.0-20260926030648-4ce767fc0cad (LICENSE)": (
            "c4be3acebe12527d7de689933d98329b4065f8c50cd929d0365584eafe6c20dd"
        ),
    }
    for title, digest in section_digests.items():
        assert digest in heading
        assert hashlib.sha256(exact_section(title).encode()).hexdigest() == digest

    provenance_urls = (
        "https://github.com/mvdan/sh/blob/v3.13.1/LICENSE",
        "https://github.com/google/cel-go/blob/v0.30.0/LICENSE",
        "https://github.com/antlr4-go/antlr/blob/v4.13.1/LICENSE",
        "https://github.com/golang/exp/blob/"
        "746e56fc9e2fafde18176275ce0b96b06ac53955/LICENSE",
        "https://github.com/golang/exp/blob/"
        "746e56fc9e2fafde18176275ce0b96b06ac53955/PATENTS",
        "https://github.com/NVIDIA/OpenShell/blob/v0.1.1/LICENSE",
    )
    for provenance_url in provenance_urls:
        assert provenance_url in heading
    assert "cel.dev/expr v0.25.2 is Apache-2.0-only" in heading

    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    go_sum = (ROOT / "go.sum").read_text(encoding="utf-8")
    go_mod_requirements = (
        "\tgithub.com/google/cel-go v0.30.0\n",
        "\tmvdan.cc/sh/v3 v3.13.1\n",
        "\tcel.dev/expr v0.25.2 // indirect\n",
        "\tgithub.com/NVIDIA/OpenShell/sdk/go v0.0.0-20260926030648-4ce767fc0cad\n",
        "\tgithub.com/antlr4-go/antlr/v4 v4.13.1 // indirect\n",
        "\tgolang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect\n",
    )
    for requirement in go_mod_requirements:
        assert requirement in go_mod

    go_module_sums = (
        "cel.dev/expr v0.25.2 h1:K6j46C81hXtZQfuX60cVWQFBJahKSE2gfRbNuvr5bFs=",
        "github.com/antlr4-go/antlr/v4 v4.13.1 "
        "h1:SqQKkuVZ+zWkMMNkjy5FZe5mr5WURWnlpmOuzYWrPrQ=",
        "github.com/google/cel-go v0.30.0 "
        "h1:ll54AkzKunWkBn9wSoiUXbFZXYZTkdJGNXTBXUoolGo=",
        "golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f "
        "h1:W3F4c+6OLc6H2lb//N1q4WpJkhzJCK5J6kUi1NTVXfM=",
        "mvdan.cc/sh/v3 v3.13.1 "
        "h1:DP3TfgZhDkT7lerUdnp6PTGKyxxzz6T+cOlY/xEvfWk=",
    )
    for module_sum in go_module_sums:
        assert f"{module_sum}\n" in go_sum

    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    notice_words = " ".join(notice.split())
    assert "GoReleaser archive Syft SBOM sidecars" in notice
    assert "Windows Setup merged SPDX 2.3 SBOM" in notice
    assert "not an exhaustive dependency inventory" in notice_words
    notice_dependencies = (
        "CEL-Go (github.com/google/cel-go) — Apache-2.0 with BSD-3-Clause component",
        "CEL expression protobufs (cel.dev/expr) — Apache-2.0",
        "ANTLR4 Go runtime (github.com/antlr4-go/antlr/v4) — BSD-3-Clause",
        "Go experimental packages (golang.org/x/exp) — BSD-3-Clause",
    )
    for dependency in notice_dependencies:
        assert dependency in notice

    # These pins came from the complete module ZIPs after their Go h1 hashes
    # were independently checked against go.sum, not from the rendered notice.
    host_stage_pins = json.loads(
        (ROOT / "cli/tests/testdata/host_stage_license_pins.json").read_text(encoding="utf-8")
    )["modules"]
    assert len(host_stage_pins) == 15
    for module in host_stage_pins:
        name, version, module_sum = module["module"], module["version"], module["go_sum"]
        assert f"{name} {version} {module_sum}\n" in go_sum
        assert re.search(rf"^\s+{re.escape(name)} {re.escape(version)}(?: // indirect)?$", go_mod, re.M)
        provenance = f"  Module: {name}\n  Version: {version}\n  Go ZIP h1: {module_sum}\n"
        assert third_party.count(provenance) == 1
        for member in module["files"]:
            title = f"{name} {version} ({member['path']})"
            assert hashlib.sha256(exact_section(title).encode()).hexdigest() == member["sha256"]
    manifest_paths = (
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/openclaw.plugin.json",
        "extensions/defenseclaw/package-lock.json",
        "docs-site/package.json",
        "docs-site/package-lock.json",
    )
    for manifest_path in manifest_paths:
        assert (ROOT / manifest_path).is_file()
        assert manifest_path in notice
        assert manifest_path in heading
    assert "the runtime archive carries them as root package.json" in notice_words
    assert "is not placed in that runtime archive" in notice_words
    assert "not a DefenseClaw runtime artifact" in notice_words

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f"include {name}" in manifest

    bundle_builder = (ROOT / "scripts/build-macos-bundle.sh").read_text(encoding="utf-8")
    windows_builder = (ROOT / "scripts/windows-native-ci.ps1").read_text(encoding="utf-8-sig")
    windows_installer = (ROOT / "scripts/build-windows-installer.ps1").read_text(
        encoding="utf-8-sig"
    )
    windows_gateway_license_staging = """\
    foreach ($file in @('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.txt')) {
        foreach ($targetRoot in @($gatewayVerificationStage, $stage)) {
            Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) -Destination $targetRoot -Force
        }
    }"""
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f'cp {name} ' in bundle_builder
    assert windows_gateway_license_staging in windows_builder
    assert (
        "foreach ($file in @('pyproject.toml', 'README.md', 'LICENSE', 'NOTICE', "
        "'THIRD_PARTY_LICENSES.txt', 'MANIFEST.in'))"
    ) in windows_builder
    assert (
        "Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) "
        "-Destination $packageStage -Force"
    ) in windows_builder
    assert (
        """\
        '--source', $stage,
        '--output', $gatewayArchive,"""
        in windows_builder
    )
    assert (
        """\
        '--source', $gatewayVerificationStage,
        '--output', $gatewayArchiveVerification,"""
        in windows_builder
    )
    assert "gateway ZIP must contain exactly one root $file file" in windows_builder
    assert "gateway ZIP $file differs from the canonical source file" in windows_builder
    assert "Expand-Archive -LiteralPath $gatewayZip -DestinationPath $gatewayPayloadDir" in (
        windows_installer
    )
    assert "Write-ZipFromDirectory $gatewayPayloadDir $embeddedGatewayZip" in windows_installer
