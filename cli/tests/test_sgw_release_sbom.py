# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import unicodedata
import zipfile
from pathlib import Path

import pytest

from cli.tests.test_windows_installer_artifacts import (
    SGW_CORE_TERMS,
    _fixture,
    _metadata,
    _with_wheel_record,
)
from scripts import release_candidate, release_certification, stage_sgw_modules, windows_installer_artifacts


def _source_only_wheel(tmp_path: Path, version: str = "0.8.11") -> Path:
    root = stage_sgw_modules.ROOT
    prefix = "defenseclaw/_data/sgw"
    dist_info = f"defenseclaw-{version}.dist-info"
    entries = _with_wheel_record(
        {
            "defenseclaw/__init__.py": f'__version__ = "{version}"\n'.encode(),
            "defenseclaw/main.py": b'def main():\n    print("defenseclaw fixture")\n',
            "defenseclaw/observability/__init__.py": b"",
            "defenseclaw/observability/local_stack.py": (
                b'def main():\n    print("defenseclaw observability fixture")\n'
            ),
            f"{prefix}/sgw_module.py": (root / "scripts/sgw_module.py").read_bytes(),
            f"{prefix}/s-gw-module.json": (root / "release/s-gw-module.json").read_bytes(),
            f"{prefix}/s-gw-runners.json": stage_sgw_modules.sanitized_runtime_manifest(
                (root / "release/s-gw-runners.json").read_bytes()
            ),
            f"{dist_info}/METADATA": _metadata(
                "defenseclaw",
                version,
                license_files=("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"),
            ),
            f"{dist_info}/WHEEL": stage_sgw_modules.EXPECTED_WHEEL_METADATA,
            f"{dist_info}/entry_points.txt": stage_sgw_modules.EXPECTED_ENTRY_POINTS,
            f"{dist_info}/licenses/LICENSE": (root / "LICENSE").read_bytes(),
            f"{dist_info}/licenses/NOTICE": (root / "NOTICE").read_bytes(),
            f"{dist_info}/licenses/THIRD_PARTY_LICENSES.txt": (root / "THIRD_PARTY_LICENSES.txt").read_bytes(),
        },
        dist_info,
    )
    wheel = tmp_path / f"defenseclaw-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(entries.items()):
            archive.writestr(name, payload)
    return wheel


def _wheel_entries(path: Path) -> tuple[dict[str, bytes], str]:
    with zipfile.ZipFile(path) as archive:
        entries = {
            info.filename: archive.read(info) for info in archive.infolist() if not info.filename.endswith("/RECORD")
        }
    metadata_name = next(name for name in entries if name.endswith(".dist-info/METADATA"))
    return entries, Path(metadata_name).parent.as_posix()


def _write_wheel(path: Path, entries: dict[str, bytes], dist_info: str) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(_with_wheel_record(entries, dist_info).items()):
            info = zipfile.ZipInfo(name)
            # ZipInfo rewrites backslashes on Windows unless the literal test name is restored.
            info.filename = name
            archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED)


def test_sgw_release_generators_and_sbom_tests_are_certification_sensitive() -> None:
    policy = json.loads((release_candidate.ROOT / "release/certification-policy.json").read_text(encoding="utf-8"))
    sensitive = set(policy["release_sensitive_paths"])

    assert {
        "LICENSE",
        "NOTICE",
        "setup.py",
        "defenseclaw_build_backend.py",
        "scripts/windows_installer_artifacts.py",
        "cli/tests/test_windows_installer_artifacts.py",
        "cli/tests/test_sgw_release_sbom.py",
    } <= sensitive
    for path in (
        "LICENSE",
        "NOTICE",
        "setup.py",
        "defenseclaw_build_backend.py",
        "scripts/windows_installer_artifacts.py",
        "cli/tests/test_sgw_release_sbom.py",
        "cli/tests/test_windows_installer_artifacts.py",
    ):
        assert release_certification._is_sensitive([path], list(sensitive))


def test_sgw_sbom_is_a_required_runtime_and_release_asset_from_0811() -> None:
    version = "0.8.11"
    protected_wheel = release_candidate._expected_release_artifacts(version)["wheel"]
    sbom = f"{protected_wheel}.sbom.json"

    assert release_candidate.sgw_sbom_asset_name("0.8.10") is None
    assert release_candidate.sgw_sbom_asset_name(version) == sbom
    assert sbom in release_candidate.runtime_asset_names(version)
    source_only = release_candidate.runtime_asset_names(version, source_only_sgw=True)
    assert sbom not in source_only
    assert set(release_candidate.runtime_asset_names(version)) - set(source_only) == {sbom}
    assert sbom in release_candidate.payload_asset_names(version, "notarized")
    assert sbom in release_candidate.published_asset_names(version, "notarized")


def test_source_only_runtime_profile_validates_exact_apache_wheel(tmp_path: Path) -> None:
    version = "0.8.11"
    wheel = _source_only_wheel(tmp_path, version)

    result = stage_sgw_modules.validate_source_only_wheel(wheel, version=version)

    assert result["production_modules"] is False
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    shutil.copy2(wheel, runtime / wheel.name)
    release_candidate._validate_sgw_runtime_sbom(
        runtime,
        version,
        canonical_wheel=True,
        source_only_sgw=True,
    )


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required for an isolated wheel install")
def test_source_only_fixture_installs_with_both_console_commands(tmp_path: Path) -> None:
    uv = shutil.which("uv") or ""
    wheel = _source_only_wheel(tmp_path)
    environment = tmp_path / "venv"
    subprocess.run(
        [uv, "venv", "--python", sys.executable, str(environment)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [uv, "pip", "install", "--python", str(python), "--no-deps", str(wheel)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    expected = {
        f"defenseclaw{suffix}": "defenseclaw fixture",
        f"defenseclaw-observability{suffix}": "defenseclaw observability fixture",
    }
    for name, output in expected.items():
        completed = subprocess.run(
            [str(scripts / name)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.stdout.strip() == output


@pytest.mark.parametrize(
    ("member", "replacement"),
    (
        ("WHEEL", None),
        ("entry_points.txt", None),
        ("WHEEL", b"Wheel-Version: 9.9\n"),
        ("entry_points.txt", b"[console_scripts]\ndefenseclaw = attacker:main\n"),
    ),
)
def test_source_only_wheel_rejects_missing_or_tampered_operational_metadata(
    tmp_path: Path,
    member: str,
    replacement: bytes | None,
) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / f"bad-{member}.whl"
    entries, dist_info = _wheel_entries(source)
    path = f"{dist_info}/{member}"
    if replacement is None:
        entries.pop(path)
    else:
        entries[path] = replacement
    _write_wheel(changed, entries, dist_info)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="operational metadata"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


@pytest.mark.parametrize(
    ("member", "replacement"),
    (
        ("WHEEL", None),
        ("entry_points.txt", None),
        ("WHEEL", b"Wheel-Version: 9.9\n"),
        ("entry_points.txt", b"[console_scripts]\ndefenseclaw = attacker:main\n"),
    ),
)
def test_production_wheel_rejects_missing_or_tampered_operational_metadata(
    tmp_path: Path,
    member: str,
    replacement: bytes | None,
) -> None:
    fixture = _fixture(tmp_path)
    wheel = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    entries, dist_info = _wheel_entries(wheel)
    path = f"{dist_info}/{member}"
    if replacement is None:
        entries.pop(path)
    else:
        entries[path] = replacement
    _write_wheel(wheel, entries, dist_info)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="operational metadata"):
        stage_sgw_modules._validate_wheel_license_metadata(
            wheel,
            version=fixture.version,
            core_terms=SGW_CORE_TERMS,
        )


@pytest.mark.parametrize("change", ["mixed-license", "production-file"])
def test_source_only_wheel_profile_rejects_non_source_inventory(
    tmp_path: Path,
    change: str,
) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / f"changed-{change}.whl"
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(changed, "w") as output:
        for info in source_archive.infolist():
            payload = source_archive.read(info)
            if change == "mixed-license" and info.filename.endswith(".dist-info/METADATA"):
                payload = payload.replace(
                    b"License-Expression: Apache-2.0\n",
                    f"License-Expression: {stage_sgw_modules.SGW_MIXED_LICENSE}\n".encode(),
                )
            output.writestr(info, payload)
        if change == "production-file":
            output.writestr("defenseclaw/_data/sgw/checksums.txt", b"unexpected\n")

    expected = "license expression" if change == "mixed-license" else "inventory mismatch"
    with pytest.raises(stage_sgw_modules.DeliveryError, match=expected):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


def test_source_only_wheel_rejects_case_aliased_production_inventory(tmp_path: Path) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / "case-aliased-production.whl"
    entries, dist_info = _wheel_entries(source)
    entries["DefenseClaw/_DATA/SGW/modules/windows-x64/s-gw-module.tar.gz"] = b"unexpected\n"
    _write_wheel(changed, entries, dist_info)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="hierarchy aliases|s-gw inventory mismatch"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


def test_source_only_wheel_rejects_case_insensitive_member_collision(tmp_path: Path) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / "case-collision.whl"
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(changed, "w") as output:
        for info in source_archive.infolist():
            output.writestr(info, source_archive.read(info))
        output.writestr(
            "DefenseClaw/_DATA/SGW/sgw_module.py",
            (stage_sgw_modules.ROOT / "scripts/sgw_module.py").read_bytes(),
        )

    with pytest.raises(stage_sgw_modules.DeliveryError, match="case-insensitive member aliases"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "defenseclaw\\_data\\sgw\\checksums.txt",
        "defenseclaw/../defenseclaw/_data/sgw/checksums.txt",
        "defenseclaw/_data/sgw/CON.txt",
        "defenseclaw/_data/sgw/COM¹.txt",
        unicodedata.normalize("NFD", "defenseclaw/café.py"),
    ],
)
def test_source_only_wheel_rejects_noncanonical_member_paths(tmp_path: Path, unsafe_name: str) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / "noncanonical-member.whl"
    entries, dist_info = _wheel_entries(source)
    entries[unsafe_name] = b"unexpected\n"
    _write_wheel(changed, entries, dist_info)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="non-canonical wheel member path"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


@pytest.mark.parametrize(
    "members",
    (
        {"Foo/a.py": b"a\n", "foo/b.py": b"b\n"},
        {"foo": b"file\n", "foo/bar.py": b"child\n"},
        {"foo/bar.py": b"child\n", "foo": b"file\n"},
    ),
)
def test_source_only_wheel_rejects_cross_platform_hierarchy_collisions(
    tmp_path: Path,
    members: dict[str, bytes],
) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / "hierarchy-collision.whl"
    entries, dist_info = _wheel_entries(source)
    entries.update(members)
    _write_wheel(changed, entries, dist_info)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="hierarchy|used as a directory"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


def test_source_only_wheel_rejects_unrecorded_member(tmp_path: Path) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / "unrecorded-member.whl"
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(changed, "w") as output:
        for info in source_archive.infolist():
            output.writestr(info, source_archive.read(info))
        output.writestr("defenseclaw/unrecorded.py", b"unexpected\n")

    with pytest.raises(stage_sgw_modules.DeliveryError, match="RECORD inventory"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


@pytest.mark.parametrize("change", ["record-self-hash", "unselected-member-hash"])
def test_source_only_wheel_rejects_inconsistent_complete_record(tmp_path: Path, change: str) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / f"bad-{change}.whl"
    entries, dist_info = _wheel_entries(source)
    entries["defenseclaw/__init__.py"] = b"# fixture\n"
    recorded = _with_wheel_record(entries, dist_info)
    record_name = f"{dist_info}/RECORD"
    if change == "record-self-hash":
        recorded[record_name] = recorded[record_name].replace(
            f"{record_name},,\n".encode(),
            f"{record_name},sha256={'A' * 43},1\n".encode(),
        )
    else:
        recorded["defenseclaw/__init__.py"] = b"# changed after RECORD\n"
    with zipfile.ZipFile(changed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(recorded.items()):
            archive.writestr(name, payload)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="RECORD entry.*inconsistent"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


@pytest.mark.parametrize("kind", ["fifo", "dos-directory", "dos-reparse"])
def test_source_only_wheel_rejects_non_regular_sgw_member(tmp_path: Path, kind: str) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / f"unsafe-{kind}.whl"
    target = "defenseclaw/_data/sgw/sgw_module.py"
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(changed, "w") as output:
        for info in source_archive.infolist():
            payload = source_archive.read(info)
            if info.filename == target:
                if kind == "fifo":
                    info.create_system = 3
                    info.external_attr = (stat.S_IFIFO | 0o600) << 16
                elif kind == "dos-directory":
                    info.external_attr |= 0x10
                else:
                    info.external_attr |= 0x400
            output.writestr(info, payload)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="unsafe .*member"):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


@pytest.mark.parametrize(
    ("header", "value", "expected"),
    [
        ("Name", "defenseclaw", "identity"),
        ("Version", "0.8.11", "version"),
    ],
)
def test_source_only_wheel_rejects_duplicate_identity_headers(
    tmp_path: Path,
    header: str,
    value: str,
    expected: str,
) -> None:
    source = _source_only_wheel(tmp_path)
    changed = tmp_path / f"duplicate-{header.lower()}.whl"
    entries, dist_info = _wheel_entries(source)
    metadata_name = f"{dist_info}/METADATA"
    entries[metadata_name] = entries[metadata_name].rstrip(b"\n") + f"\n{header}: {value}\n\n".encode()
    _write_wheel(changed, entries, dist_info)

    with pytest.raises(stage_sgw_modules.DeliveryError, match=expected):
        stage_sgw_modules.validate_source_only_wheel(changed, version="0.8.11")


def test_source_only_runtime_profile_rejects_sbom_and_production_wheel(tmp_path: Path) -> None:
    version = "0.8.11"
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    wheel = _source_only_wheel(runtime, version)
    (runtime / f"{wheel.name}.sbom.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="profile forbids"):
        release_candidate._validate_sgw_runtime_sbom(
            runtime,
            version,
            canonical_wheel=True,
            source_only_sgw=True,
        )

    production_root = tmp_path / "production"
    production_root.mkdir()
    fixture = _fixture(production_root)
    protected = tmp_path / "protected"
    protected.mkdir()
    production_wheel = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    protected_name = release_candidate._expected_release_artifacts(fixture.version)["wheel"]
    release_candidate._write_protected_artifact(production_wheel, protected / protected_name)
    with pytest.raises(release_candidate.CandidateError, match="source-only.*inventory mismatch"):
        release_candidate._validate_sgw_runtime_sbom(
            protected,
            fixture.version,
            source_only_sgw=True,
        )


def test_runtime_validator_binds_sgw_sbom_to_protected_wheel(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    version = fixture.version
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    canonical = runtime / f"defenseclaw-{version}-py3-none-any.whl"
    shutil.copy2(fixture.payload_root / canonical.name, canonical)
    protected_name = release_candidate._expected_release_artifacts(version)["wheel"]
    release_candidate._write_protected_artifact(canonical, runtime / protected_name)
    sbom_name = release_candidate.sgw_sbom_asset_name(version)
    assert sbom_name is not None
    with pytest.raises(release_candidate.CandidateError, match="SBOM is unavailable"):
        release_candidate._validate_sgw_runtime_sbom(runtime, version)
    shutil.copy2(fixture.sgw_sbom, runtime / sbom_name)

    release_candidate._validate_sgw_runtime_sbom(runtime, version)

    document = json.loads((runtime / sbom_name).read_text(encoding="utf-8"))
    document["files"] = document["files"][1:]
    (runtime / sbom_name).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="incomplete or differs"):
        release_candidate._validate_sgw_runtime_sbom(runtime, version)


def test_release_workflow_authenticates_sgw_sbom_before_runtime_sealing() -> None:
    workflow = (release_candidate.ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")
    generate = workflow.index("scripts/stage_sgw_modules.py generate-sbom")
    verify = workflow.index("scripts/stage_sgw_modules.py verify-sbom", generate)
    prepare = workflow.index("scripts/release_candidate.py prepare-runtime", verify)

    assert "--authenticate" in workflow[verify:prepare]
    assert "--source-only-sgw" not in workflow
    assert generate < verify < prepare


def test_core_license_text_must_be_actual_terms_not_a_pointer() -> None:
    with pytest.raises(stage_sgw_modules.DeliveryError, match="placeholder"):
        stage_sgw_modules.validated_core_license_text(
            "The proprietary license terms supplied separately are a placeholder for the approved artifact."
        )

    terms = (
        "Permission is granted to run s-gw Core with an authenticated DefenseClaw distribution. "
        "No redistribution rights are granted by these test license terms."
    )
    assert stage_sgw_modules.validated_core_license_text(terms) == terms


def test_sgw_sbom_rejects_wheel_metadata_that_does_not_declare_core_license(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    source = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    tampered = tmp_path / "tampered.whl"
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(tampered, "w") as output:
        for info in source_archive.infolist():
            payload = source_archive.read(info)
            if info.filename.endswith(".dist-info/METADATA"):
                payload = payload.replace(
                    f"License-Expression: {stage_sgw_modules.SGW_MIXED_LICENSE}\n".encode(),
                    b"License-Expression: Apache-2.0\n",
                )
            output.writestr(info, payload)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="license expression is inconsistent"):
        stage_sgw_modules._build_sgw_sbom(
            tampered,
            version=fixture.version,
            source_commit=fixture.source_commit,
            source_epoch=fixture.source_epoch,
            authenticate=False,
        )


@pytest.mark.parametrize("change", ["missing", "tampered"])
def test_wheel_license_validator_rejects_missing_or_tampered_license(tmp_path: Path, change: str) -> None:
    fixture = _fixture(tmp_path)
    source = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    tampered = tmp_path / f"{change}-license.whl"

    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(tampered, "w") as output:
        for info in source_archive.infolist():
            payload = source_archive.read(info)
            if info.filename.endswith(".dist-info/licenses/LICENSE"):
                if change == "missing":
                    continue
                payload = bytes([payload[0] ^ 1]) + payload[1:]
            output.writestr(info, payload)

    expected = "lacks its exact license files" if change == "missing" else "LICENSE differs from the source"
    with pytest.raises(stage_sgw_modules.DeliveryError, match=expected):
        stage_sgw_modules._validate_wheel_license_metadata(
            tampered,
            version=fixture.version,
            core_terms=SGW_CORE_TERMS,
        )


@pytest.mark.parametrize("record_change", ["missing", "corrupt"])
@pytest.mark.parametrize("member_kind", ["METADATA", "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"])
def test_wheel_license_validator_rejects_bad_record_rows(
    tmp_path: Path,
    record_change: str,
    member_kind: str,
) -> None:
    fixture = _fixture(tmp_path)
    source = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    tampered = tmp_path / f"{record_change}-{member_kind.lower()}-record.whl"

    with zipfile.ZipFile(source) as source_archive:
        metadata_name = next(name for name in source_archive.namelist() if name.endswith(".dist-info/METADATA"))
        dist_info = Path(metadata_name).parent.as_posix()
        selected = {
            "METADATA": metadata_name,
            "LICENSE": f"{dist_info}/licenses/LICENSE",
            "NOTICE": f"{dist_info}/licenses/NOTICE",
            "THIRD_PARTY_LICENSES.txt": f"{dist_info}/licenses/THIRD_PARTY_LICENSES.txt",
        }[member_kind]
        record_name = f"{dist_info}/RECORD"
        with zipfile.ZipFile(tampered, "w") as output:
            found = False
            for info in source_archive.infolist():
                payload = source_archive.read(info)
                if info.filename == record_name:
                    rows = []
                    for row in payload.decode("utf-8").splitlines():
                        name, digest_value, size = row.split(",", 2)
                        if name != selected:
                            rows.append(row)
                            continue
                        found = True
                        if record_change == "corrupt":
                            rows.append(f"{name},sha256={'A' * 43},{size}")
                    payload = ("\n".join(rows) + "\n").encode("utf-8")
                output.writestr(info, payload)
            assert found

    expected = "absent from RECORD" if record_change == "missing" else "RECORD entry is inconsistent"
    with pytest.raises(stage_sgw_modules.DeliveryError, match=expected):
        stage_sgw_modules._validate_wheel_license_metadata(
            tampered,
            version=fixture.version,
            core_terms=SGW_CORE_TERMS,
        )


def test_release_validator_requires_exact_imported_sgw_inventory(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    windows_installer_artifacts.build_sbom(fixture)
    manifest_path = fixture.payload_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    provenance = {
        "inputs": {
            "embedded_payload_sha256": sha256(fixture.embedded_payload),
            "payload_files": manifest["files"],
            "payload_manifest_sha256": sha256(manifest_path),
            "wheel": manifest["wheel"],
            "wheel_sha256": manifest["files"][manifest["wheel"]],
            "sgw_sbom_sha256": sha256(fixture.sgw_sbom),
        }
    }
    release_candidate._validate_windows_setup_sbom(
        fixture.output,
        version=fixture.version,
        commit=fixture.source_commit,
        setup_sha256=sha256(fixture.setup),
        provenance=provenance,
    )

    document = json.loads(fixture.output.read_text(encoding="utf-8"))
    npm_root = next(
        package
        for package in document["packages"]
        if str(package.get("comment", "")).startswith("DefenseClaw s-gw inventory role=npm-root")
    )
    npm_root["licenseDeclared"] = stage_sgw_modules.SGW_CORE_LICENSE
    fixture.output.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="npm root license"):
        release_candidate._validate_windows_setup_sbom(
            fixture.output,
            version=fixture.version,
            commit=fixture.source_commit,
            setup_sha256=sha256(fixture.setup),
            provenance=provenance,
        )
