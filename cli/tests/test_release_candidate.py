# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
import base64
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

from scripts import release_candidate

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.8.4"
COMMIT = "a" * 40
TEST_CERTIFICATE_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MAMCAQA=\n"
    b"-----END CERTIFICATE-----\n"
)
# The unit fixture only exercises canonical PEM/DER framing.  The release workflow
# immediately asks Cosign to validate the real X.509 certificate and exact OIDC identity.
TEST_CERTIFICATE_WRAPPER = base64.b64encode(TEST_CERTIFICATE_PEM)
RELEASE_ARTIFACTS = release_candidate._expected_release_artifacts(VERSION)
PROTECTED_WHEEL = RELEASE_ARTIFACTS["wheel"]
PHASE_TWO_MUTATOR_SOURCE = (ROOT / "cli/defenseclaw/phase_two_mutator.py").read_text(encoding="utf-8")
HARD_CUT_BUNDLE_TRANSACTION_SOURCE = """
import base64
import json
import os
import stat
import shutil

_MAX_BUNDLE_ROLLBACK_METADATA_BYTES = 4_194_304

def _fsync_directory_chain(path, *, stop):
    current = path
    while True:
        _fsync_directory(current)
        if current == stop:
            break
        parent = current.parent
        if parent == current:
            raise RuntimeError("backup root is not an ancestor")
        current = parent

def _serialize_windows_security(security):
    return {
        "owner": base64.b64encode(security.owner).decode("ascii"),
        "dacl": base64.b64encode(security.dacl).decode("ascii"),
        "dacl_protected": security.dacl_protected,
    }

def _activate_local_observability_manifest(*, was_running: bool):
    existing_paths = {"managed/existing"}
    created_paths = {"managed/created"}
    managed_paths = existing_paths | created_paths
    backup_root = object()
    backup_managed = backup_root / "managed"
    backup_created = backup_root / "created"
    backup_retired = backup_root / "retired"
    _mkdir_private(backup_managed)
    _mkdir_private(backup_created)
    _mkdir_private(backup_retired)
    _fsync_directory_chain(backup_managed, stop=backup_root)
    _fsync_directory_chain(backup_created, stop=backup_root)
    _fsync_directory_chain(backup_retired, stop=backup_root)
    old_sha256 = {}
    old_modes = {}
    created_sha256 = {}
    old_windows_security = {}
    for path in existing_paths:
        backup_path = backup_managed / path
        shutil.copy2(path, backup_path)
        _fsync_file(backup_path)
        _fsync_directory_chain(backup_path.parent, stop=backup_root)
        old_sha256[path] = _sha256_file(backup_path)
        old_modes[path] = stat.S_IMODE(path.stat().st_mode)
        if os.name == "nt":
            old_windows_security[path] = _serialize_windows_security(
                windows_acl.capture_path(path)
            )
    for path in created_paths:
        created_claim = backup_created / path
        _atomic_copy_file("stage", created_claim)
        _fsync_file(created_claim)
        _fsync_directory_chain(created_claim.parent, stop=backup_root)
        created_sha256[path] = _sha256_file(created_claim)
    backup_metadata = {
        "schema_version": 2,
        "managed_paths": sorted(managed_paths),
        "existing_paths": sorted(existing_paths),
        "old_sha256": old_sha256,
        "old_modes": old_modes,
        "created_sha256": created_sha256,
        "old_windows_security": old_windows_security,
        "restart_required": was_running,
    }
    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode("utf-8")
    if not 0 < len(serialized_metadata) <= _MAX_BUNDLE_ROLLBACK_METADATA_BYTES:
        raise OSError("rollback metadata exceeds the bridge reader bound")
    _atomic_write_bytes(backup_root / "refresh-backup.json", serialized_metadata)
    mutation_started = False
    mutation_started = True
    for path in created_paths:
        created_claim = backup_created / path
        destination = path
        os.link(created_claim, destination)
    for path in existing_paths:
        destination = path
        _atomic_copy_file("stage", destination)
    return mutation_started
"""


def _write_release_inventory(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(json.dumps([rows]), encoding="utf-8")


def test_release_progression_requires_target_newer_than_reviewed_and_published(
    tmp_path: Path,
) -> None:
    releases = tmp_path / "releases.json"
    _write_release_inventory(
        releases,
        [
            {
                "tag_name": "0.8.3",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "0.9.0-rc1",
                "draft": False,
                "prerelease": True,
            },
            {
                "tag_name": "1.0.0",
                "draft": True,
                "prerelease": False,
            },
        ],
    )

    assert release_candidate.validate_release_progression("0.8.4", releases) == (
        "0.8.3",
        "0.8.3",
    )

    with pytest.raises(release_candidate.CandidateError, match="strictly newer"):
        release_candidate.validate_release_progression("0.8.3", releases)


def test_release_progression_uses_published_stable_max_even_when_policy_lags(
    tmp_path: Path,
) -> None:
    releases = tmp_path / "releases.json"
    _write_release_inventory(
        releases,
        [
            {
                "tag_name": "0.8.5",
                "draft": False,
                "prerelease": False,
            }
        ],
    )

    with pytest.raises(release_candidate.CandidateError, match=r"current stable 0\.8\.5"):
        release_candidate.validate_release_progression("0.8.4", releases)


def test_release_progression_fails_closed_on_unorderable_stable_release(
    tmp_path: Path,
) -> None:
    releases = tmp_path / "releases.json"
    _write_release_inventory(
        releases,
        [
            {
                "tag_name": "v0.8.3",
                "draft": False,
                "prerelease": False,
            }
        ],
    )

    with pytest.raises(release_candidate.CandidateError, match="non-canonical tag"):
        release_candidate.validate_release_progression("0.8.4", releases)


def _fake_gateway(
    os_name: str,
    arch: str,
    *,
    version: str = VERSION,
    commit: str = COMMIT,
) -> bytes:
    payload = bytearray(256)
    if os_name == "linux":
        payload[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", payload, 18, {"amd64": 62, "arm64": 183}[arch])
    elif os_name == "darwin":
        payload[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into(
            "<I",
            payload,
            4,
            {"amd64": 0x01000007, "arm64": 0x0100000C}[arch],
        )
    elif os_name == "windows":
        payload[:2] = b"MZ"
        pe_offset = 128
        struct.pack_into("<I", payload, 0x3C, pe_offset)
        payload[pe_offset : pe_offset + 4] = b"PE\0\0"
        struct.pack_into("<H", payload, pe_offset + 4, {"amd64": 0x8664, "arm64": 0xAA64}[arch])
    else:  # pragma: no cover - fixture callers use the release platform matrix
        raise AssertionError(os_name)
    payload.extend(f"\nDefenseClaw {version}\ncommit={commit}\n".encode())
    return bytes(payload)


def _write_archive_payload(path: Path, payload: bytes) -> None:
    if path.suffix == ".dcgateway":
        payload = release_candidate.PROTECTED_ARTIFACT_MAGIC + payload.translate(
            release_candidate.PROTECTED_ARTIFACT_TRANSLATION
        )
    path.write_bytes(payload)


def _write_tar_members(
    path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for info, member_payload in members:
            archive.addfile(
                info,
                None if member_payload is None else io.BytesIO(member_payload),
            )
    _write_archive_payload(path, payload.getvalue())


def _write_tar(path: Path, member_name: str, payload: bytes = b"fixture") -> None:
    info = tarfile.TarInfo(member_name)
    info.size = len(payload)
    _write_tar_members(path, [(info, payload)])


def _write_zip(path: Path, member_name: str, payload: bytes = b"candidate gateway") -> None:
    archive_payload = io.BytesIO()
    with zipfile.ZipFile(archive_payload, mode="w") as archive:
        archive.writestr(member_name, payload)
    _write_archive_payload(path, archive_payload.getvalue())


def _read_wheel_members(path: Path) -> dict[str, bytes]:
    payload: Path | io.BytesIO
    if path.suffix == ".dcwheel":
        payload = io.BytesIO(release_candidate._protected_payload(path))
    else:
        payload = path
    with zipfile.ZipFile(payload) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _write_wheel_members(path: Path, members: dict[str, bytes]) -> None:
    archive_payload = io.BytesIO()
    with zipfile.ZipFile(archive_payload, mode="w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    payload = archive_payload.getvalue()
    if path.suffix == ".dcwheel":
        payload = release_candidate.PROTECTED_ARTIFACT_MAGIC + payload.translate(
            release_candidate.PROTECTED_ARTIFACT_TRANSLATION
        )
    path.write_bytes(payload)


def _rewrite_wheel_controller(path: Path, protocol: int) -> None:
    members = _read_wheel_members(path)
    members["defenseclaw/commands/cmd_upgrade.py"] = (
        f"_UPGRADE_PROTOCOL_VERSION = {protocol}\n"
        '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
        "def _prepare_hard_cut_rollback_plan(): pass\n"
        "def _execute_hard_cut_rollback(): pass\n"
        "def _poll_health(): pass\n"
        "_prepare_hard_cut_rollback_plan()\n"
    ).encode()
    _write_wheel_members(path, members)


def _transform_wheel_controller(path: Path, transform) -> None:
    members = _read_wheel_members(path)
    controller_name = "defenseclaw/commands/cmd_upgrade.py"
    source = members[controller_name].decode("utf-8")
    members[controller_name] = transform(source).encode("utf-8")
    _write_wheel_members(path, members)


def _runtime_dir(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            archive_name = f"defenseclaw_{VERSION}_{os_name}_{arch}.tar.gz"
            _write_tar(runtime / archive_name, "defenseclaw", _fake_gateway(os_name, arch))
            (runtime / f"{archive_name}.sbom.json").write_text("{}\n", encoding="utf-8")
    for arch in ("amd64", "arm64"):
        archive_name = f"defenseclaw_{VERSION}_windows_{arch}.zip"
        _write_zip(
            runtime / archive_name,
            "defenseclaw.exe",
            _fake_gateway("windows", arch),
        )
        (runtime / f"{archive_name}.sbom.json").write_text("{}\n", encoding="utf-8")

    wheel = runtime / f"defenseclaw-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("defenseclaw/__init__.py", f'__version__ = "{VERSION}"\n')
        archive.writestr(
            "defenseclaw/commands/cmd_upgrade.py",
            "_UPGRADE_PROTOCOL_VERSION = 2\n"
            '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
            "def _is_bridge_to_hard_cut_phase(): return True\n"
            "def _require_release_owned_hard_cut_handoff(): pass\n"
            "def _acquire_bridge_rollback_artifacts(): pass\n"
            "def _prepare_hard_cut_rollback_plan(): pass\n"
            "def _write_hard_cut_recovery_journal(): pass\n"
            "def _recover_interrupted_hard_cut(): pass\n"
            "def _run_phase_two_mutator(): pass\n"
            "def _execute_hard_cut_rollback(): pass\n"
            "def _poll_health(): pass\n"
            "def _create_backup(): pass\n"
            "def upgrade():\n"
            "    if _is_bridge_to_hard_cut_phase():\n"
            "        _require_release_owned_hard_cut_handoff()\n"
            "    if _is_bridge_to_hard_cut_phase():\n"
            "        _acquire_bridge_rollback_artifacts()\n"
            "    _create_backup()\n"
            "    _prepare_hard_cut_rollback_plan()\n",
        )
        archive.writestr(
            "defenseclaw/migrations.py",
            'def _migrate_fixture(): pass\nMIGRATIONS = [("0.8.4", "fixture migration", _migrate_fixture)]\n',
        )
        archive.writestr("defenseclaw/phase_two_mutator.py", PHASE_TWO_MUTATOR_SOURCE)
        archive.writestr(
            "defenseclaw/install_publish.py",
            (ROOT / "cli/defenseclaw/install_publish.py").read_bytes(),
        )
        archive.writestr(
            "defenseclaw/bundle_refresh.py",
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE,
        )
        archive.writestr(
            f"defenseclaw-{VERSION}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: defenseclaw\nVersion: {VERSION}\n",
        )
    _write_tar(runtime / f"defenseclaw-plugin-{VERSION}.tar.gz", "package/package.json")
    (runtime / "upgrade-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "runtime_config_version": 7,
                "release_version": VERSION,
                "controller_upgrade_protocol": 2,
                "min_upgrade_protocol": 1,
                "migration_failure_policy": "fail",
                "required_cli_migrations": [VERSION],
                "tested_source_versions": [
                    "0.8.3",
                    "0.8.2",
                    "0.8.1",
                    "0.8.0",
                    "0.7.2",
                    "0.7.1",
                    "0.6.6",
                    "0.6.5",
                    "0.6.4",
                    "0.6.3",
                    "0.6.2",
                    "0.6.1",
                    "0.6.0",
                    "0.5.0",
                    "0.4.0",
                ],
                "platform_tested_source_versions": {"windows": ["0.8.3", "0.8.2", "0.8.1", "0.8.0"]},
                "release_artifacts": RELEASE_ARTIFACTS,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (runtime / "CHANGELOG.md").write_text("# Candidate notes\n", encoding="utf-8")
    release_candidate.prepare_runtime(runtime, VERSION)
    return runtime


def _macos_dir(tmp_path: Path, macos_verification_status: str = "notarized") -> Path:
    macos = tmp_path / "macos"
    macos.mkdir()
    for name in release_candidate.macos_asset_names(VERSION, macos_verification_status):
        path = macos / name
        if name.endswith(".dmg"):
            path.write_bytes(b"candidate dmg")
        else:
            _write_zip(
                path,
                "DefenseClawMac.app/Contents/Info.plist",
                b"candidate app",
            )
    return macos


def _candidate_before_seal(
    tmp_path: Path,
    macos_verification_status: str = "notarized",
) -> Path:
    root = tmp_path / "candidate"
    release_candidate.assemble(
        _runtime_dir(tmp_path),
        _macos_dir(tmp_path, macos_verification_status),
        root,
        VERSION,
        COMMIT,
        macos_verification_status,
    )
    (root / "dist/checksums.txt.sig").write_bytes(b"sigstore signature")
    return root


def _sealed_candidate(
    tmp_path: Path,
    macos_verification_status: str = "notarized",
) -> Path:
    root = _candidate_before_seal(tmp_path, macos_verification_status)
    certificate = root / "dist/checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_WRAPPER)
    release_candidate.canonicalize_release_certificate(certificate)
    release_candidate.seal(root, VERSION, COMMIT)
    return root


def test_candidate_seals_and_verifies_exact_publish_set(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)

    release_candidate.verify(root, VERSION, COMMIT)
    assert (root / "dist/checksums.txt.pem").read_bytes() == TEST_CERTIFICATE_PEM

    manifest = json.loads((root / "release-candidate.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in manifest["assets"]] == list(
        release_candidate.published_asset_names(VERSION, "notarized")
    )
    checksums = release_candidate._parse_checksums(root / "dist/checksums.txt")
    assert tuple(sorted(checksums)) == release_candidate.payload_asset_names(
        VERSION, "notarized"
    )
    for name in release_candidate.resolver_asset_names(VERSION):
        assert (root / "dist" / name).read_bytes() == (release_candidate.RESOLVER_ASSET_SOURCES[name].read_bytes())
    assert (root / "RELEASE_NOTES.md").read_text(encoding="utf-8") == "# Candidate notes\n"

    release_json = tmp_path / "published.json"
    release_json.write_text(
        json.dumps(
            {
                "tagName": VERSION,
                "isDraft": False,
                "isImmutable": True,
                "assets": [
                    {
                        "name": item["name"],
                        "digest": f"sha256:{item['sha256']}",
                    }
                    for item in manifest["assets"]
                ],
            }
        ),
        encoding="utf-8",
    )
    release_candidate.verify_published_release(root, release_json, VERSION, COMMIT)


def test_publication_can_omit_every_windows_specific_asset(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _sealed_candidate(tmp_path)
    manifest = json.loads((root / "release-candidate.json").read_text(encoding="utf-8"))
    omitted = set(release_candidate.windows_release_binary_names(VERSION))
    assert len(omitted) == 6
    published_assets = [
        {
            "name": item["name"],
            "digest": f"sha256:{item['sha256']}",
        }
        for item in manifest["assets"]
        if item["name"] not in omitted
    ]
    release_json = tmp_path / "published-without-windows.json"
    release_json.write_text(
        json.dumps(
            {
                "tagName": VERSION,
                "isDraft": False,
                "isImmutable": True,
                "assets": published_assets,
            }
        ),
        encoding="utf-8",
    )

    release_candidate.verify_published_release(
        root,
        release_json,
        VERSION,
        COMMIT,
        omit_windows_binaries=True,
    )
    with pytest.raises(release_candidate.CandidateError, match="differ from the sealed candidate"):
        release_candidate.verify_published_release(root, release_json, VERSION, COMMIT)

    status = release_candidate.main(
        [
            "list-assets",
            "--root",
            str(root),
            "--version",
            VERSION,
            "--commit",
            COMMIT,
            "--omit-windows-binaries",
        ]
    )
    listed = set(capsys.readouterr().out.splitlines())
    assert status == 0
    assert listed == {item["name"] for item in published_assets}
    assert listed.isdisjoint(omitted)


def test_certificate_command_canonicalizes_strict_cosign_wrapper_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_WRAPPER)
    original_replace = release_candidate.os.replace
    replacements: list[tuple[Path, Path]] = []

    def record_replace(source: str | Path, destination: str | Path) -> None:
        replacements.append((Path(source), Path(destination)))
        original_replace(source, destination)

    monkeypatch.setattr(release_candidate.os, "replace", record_replace)
    status = release_candidate.main(
        ["canonicalize-certificate", "--certificate", str(certificate)]
    )

    assert status == 0
    assert certificate.read_bytes() == TEST_CERTIFICATE_PEM
    assert len(replacements) == 1
    assert replacements[0][0].parent == certificate.parent
    assert replacements[0][1] == certificate
    assert "release certificate canonicalized" in capsys.readouterr().out


def test_certificate_canonicalization_accepts_canonical_raw_pem(tmp_path: Path) -> None:
    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_PEM)

    release_candidate.canonicalize_release_certificate(certificate)

    assert certificate.read_bytes() == TEST_CERTIFICATE_PEM


def test_windows_named_and_opened_certificate_timestamp_views_do_not_false_positive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_WRAPPER)
    real_lstat = Path.lstat

    def timestamp_skewed_lstat(candidate: Path):
        info = real_lstat(candidate)
        if candidate != certificate:
            return info

        class _TimestampSkewedStat:
            st_ctime_ns = info.st_ctime_ns + 1

            def __getattr__(self, name: str):
                return getattr(info, name)

        return _TimestampSkewedStat()

    monkeypatch.setattr(Path, "lstat", timestamp_skewed_lstat)

    release_candidate.canonicalize_release_certificate(certificate)

    assert certificate.read_bytes() == TEST_CERTIFICATE_PEM


def test_release_certificate_same_api_timestamp_change_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_WRAPPER)
    real_lstat = Path.lstat
    certificate_lstat_calls = 0

    def timestamp_mutating_lstat(candidate: Path):
        nonlocal certificate_lstat_calls
        info = real_lstat(candidate)
        if candidate != certificate:
            return info
        certificate_lstat_calls += 1
        changed = certificate_lstat_calls > 1

        class _TimestampMutatedStat:
            st_ctime_ns = info.st_ctime_ns + int(changed)

            def __getattr__(self, name: str):
                return getattr(info, name)

        return _TimestampMutatedStat()

    monkeypatch.setattr(Path, "lstat", timestamp_mutating_lstat)

    with pytest.raises(release_candidate.CandidateError, match="changed while being read"):
        release_candidate.canonicalize_release_certificate(certificate)

    assert certificate.read_bytes() == TEST_CERTIFICATE_WRAPPER


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        TEST_CERTIFICATE_WRAPPER + b"\n",
        base64.b64encode(TEST_CERTIFICATE_PEM.rstrip(b"\n")),
        base64.b64encode(TEST_CERTIFICATE_PEM + TEST_CERTIFICATE_PEM),
        TEST_CERTIFICATE_PEM + TEST_CERTIFICATE_PEM,
        TEST_CERTIFICATE_PEM.replace(b"\n", b"\r\n"),
        b"\xef\xbb\xbf" + TEST_CERTIFICATE_PEM,
        b"A" * (release_candidate.MAX_RELEASE_CERTIFICATE_BYTES + 1),
    ],
)
def test_certificate_canonicalization_rejects_noncanonical_or_ambiguous_input(
    tmp_path: Path,
    payload: bytes,
) -> None:
    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_bytes(payload)

    with pytest.raises(release_candidate.CandidateError, match="release certificate"):
        release_candidate.canonicalize_release_certificate(certificate)

    assert certificate.read_bytes() == payload


def test_certificate_atomic_publication_failure_preserves_cosign_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate = tmp_path / "checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_WRAPPER)

    def fail_replace(_source: str | Path, _destination: str | Path) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(release_candidate.os, "replace", fail_replace)
    with pytest.raises(release_candidate.CandidateError, match="atomically publish"):
        release_candidate.canonicalize_release_certificate(certificate)

    assert certificate.read_bytes() == TEST_CERTIFICATE_WRAPPER
    assert not list(tmp_path.glob(".checksums.txt.pem.canonical-*"))


def test_seal_and_verify_reject_base64_wrapped_modern_certificate(tmp_path: Path) -> None:
    unsealed = _candidate_before_seal(tmp_path)
    certificate = unsealed / "dist/checksums.txt.pem"
    certificate.write_bytes(TEST_CERTIFICATE_WRAPPER)
    with pytest.raises(release_candidate.CandidateError, match="canonical raw PEM"):
        release_candidate.seal(unsealed, VERSION, COMMIT)

    sealed_root = tmp_path / "sealed-case"
    sealed_root.mkdir()
    sealed = _sealed_candidate(sealed_root)
    (sealed / "dist/checksums.txt.pem").write_bytes(TEST_CERTIFICATE_WRAPPER)
    with pytest.raises(release_candidate.CandidateError, match="canonical raw PEM"):
        release_candidate.verify(sealed, VERSION, COMMIT)


def test_candidate_seals_and_verifies_explicit_unverified_macos_assets(
    tmp_path: Path,
) -> None:
    root = _sealed_candidate(tmp_path, "unverified")

    release_candidate.verify(root, VERSION, COMMIT)

    manifest = json.loads((root / "release-candidate.json").read_text(encoding="utf-8"))
    expected_names = release_candidate.published_asset_names(VERSION, "unverified")
    assert manifest["macos_verification_status"] == "unverified"
    assert [item["name"] for item in manifest["assets"]] == list(expected_names)
    assert release_candidate.macos_asset_names(VERSION, "unverified") == (
        f"DefenseClawMac-{VERSION}-macos-arm64-unverified.dmg",
        f"DefenseClawMac-{VERSION}-macos-arm64-unverified.zip",
    )
    assert not any(
        name in expected_names
        for name in release_candidate.macos_asset_names(VERSION, "notarized")
    )
    checksums = release_candidate._parse_checksums(root / "dist/checksums.txt")
    assert tuple(sorted(checksums)) == release_candidate.payload_asset_names(
        VERSION, "unverified"
    )

    release_json = tmp_path / "published-unverified.json"
    release_json.write_text(
        json.dumps(
            {
                "tagName": VERSION,
                "isDraft": False,
                "isImmutable": True,
                "assets": [
                    {
                        "name": item["name"],
                        "digest": f"sha256:{item['sha256']}",
                    }
                    for item in manifest["assets"]
                ],
            }
        ),
        encoding="utf-8",
    )
    release_candidate.verify_published_release(root, release_json, VERSION, COMMIT)


def test_windows_release_gate_does_not_require_a_posix_execute_bit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = tmp_path / "defenseclaw-upgrade.sh"
    resolver.write_bytes(b"#!/usr/bin/env bash\n" + release_candidate.RESOLVER_COMPLETENESS_MARKER + b"\n")
    resolver.chmod(0o600)
    monkeypatch.setitem(
        release_candidate.RESOLVER_ASSET_SOURCES,
        "defenseclaw-upgrade.sh",
        resolver,
    )
    monkeypatch.setattr(release_candidate.os, "name", "nt")

    assert release_candidate._validated_resolver_source("defenseclaw-upgrade.sh") == resolver


def test_local_release_harness_stages_exact_reviewed_resolvers(tmp_path: Path) -> None:
    release_dir = tmp_path / "release"
    release_dir.mkdir()

    release_candidate.stage_resolvers(release_dir, VERSION)

    assert {path.name for path in release_dir.iterdir()} == set(
        release_candidate.resolver_asset_names(VERSION)
    )
    for name in release_candidate.resolver_asset_names(VERSION):
        assert (release_dir / name).read_bytes() == release_candidate.RESOLVER_ASSET_SOURCES[
            name
        ].read_bytes()

    with pytest.raises(release_candidate.CandidateError, match="destination already exists"):
        release_candidate.stage_resolvers(release_dir, VERSION)


def test_exact_reviewed_release_sources_have_cross_platform_lf_attributes() -> None:
    reviewed = (
        "scripts/upgrade.sh",
        "scripts/upgrade.ps1",
        "cli/defenseclaw/install_publish.py",
    )
    for relative in reviewed:
        completed = subprocess.run(
            ["git", "check-attr", "eol", "--", relative],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        assert completed.stdout.strip().endswith(": eol: lf")
        assert b"\r\n" not in (ROOT / relative).read_bytes()


def test_exact_gateway_is_safely_extracted_from_runtime_candidate(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    output = tmp_path / "extracted/defenseclaw"

    release_candidate.extract_gateway(runtime, output, VERSION, "darwin", "arm64")

    assert output.read_bytes() == _fake_gateway("darwin", "arm64")
    assert output.stat().st_mode & 0o111


def test_gateway_archive_attestation_covers_all_six_platform_binaries(
    tmp_path: Path,
) -> None:
    runtime = _runtime_dir(tmp_path)

    release_candidate._validate_gateway_archives(runtime, VERSION, commit=COMMIT)


def test_gateway_archive_attestation_accepts_safe_goreleaser_directory_members(
    tmp_path: Path,
) -> None:
    runtime = _runtime_dir(tmp_path)
    archive_path = runtime / RELEASE_ARTIFACTS["gateways"]["linux"]["amd64"]
    gateway = _fake_gateway("linux", "amd64")
    directory = tarfile.TarInfo("packaging/")
    directory.type = tarfile.DIRTYPE
    readme = tarfile.TarInfo("packaging/README.md")
    readme.size = len(b"release metadata")
    binary = tarfile.TarInfo("defenseclaw")
    binary.size = len(gateway)
    _write_tar_members(
        archive_path,
        [
            (directory, None),
            (readme, b"release metadata"),
            (binary, gateway),
        ],
    )

    release_candidate._validate_gateway_archives(runtime, VERSION, commit=COMMIT)


@pytest.mark.parametrize(
    ("os_name", "arch", "payload"),
    [
        ("linux", "arm64", _fake_gateway("linux", "amd64")),
        ("darwin", "amd64", _fake_gateway("linux", "amd64")),
        ("windows", "arm64", _fake_gateway("windows", "amd64")),
    ],
)
def test_gateway_archive_attestation_rejects_os_or_architecture_mismatch(
    tmp_path: Path,
    os_name: str,
    arch: str,
    payload: bytes,
) -> None:
    runtime = _runtime_dir(tmp_path)
    archive_name = RELEASE_ARTIFACTS["gateways"][os_name][arch]
    archive_path = runtime / archive_name
    if os_name == "windows":
        _write_zip(archive_path, "defenseclaw.exe", payload)
    else:
        _write_tar(archive_path, "defenseclaw", payload)

    with pytest.raises(
        release_candidate.CandidateError,
        match="architecture mismatch|not a 64-bit Mach-O",
    ):
        release_candidate.verify_runtime(runtime, VERSION)


def test_gateway_archive_attestation_rejects_unsafe_and_duplicate_members(
    tmp_path: Path,
) -> None:
    runtime = _runtime_dir(tmp_path)
    archive_path = runtime / RELEASE_ARTIFACTS["gateways"]["linux"]["amd64"]
    _write_tar(archive_path, "../defenseclaw", _fake_gateway("linux", "amd64"))

    with pytest.raises(release_candidate.CandidateError, match="unsafe member"):
        release_candidate.verify_runtime(runtime, VERSION)

    payload = _fake_gateway("linux", "amd64")
    members = []
    for _index in range(2):
        member = tarfile.TarInfo("defenseclaw")
        member.size = len(payload)
        members.append((member, payload))
    _write_tar_members(archive_path, members)

    with pytest.raises(release_candidate.CandidateError, match="duplicate member"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_gateway_archive_attestation_rejects_version_or_commit_drift(
    tmp_path: Path,
) -> None:
    runtime = _runtime_dir(tmp_path)
    archive_path = runtime / RELEASE_ARTIFACTS["gateways"]["linux"]["amd64"]
    _write_tar(
        archive_path,
        "defenseclaw",
        _fake_gateway("linux", "amd64", version="9.9.9"),
    )

    with pytest.raises(release_candidate.CandidateError, match="does not embed release version"):
        release_candidate.verify_runtime(runtime, VERSION)

    commit_case = tmp_path / "commit"
    commit_case.mkdir()
    runtime = _runtime_dir(commit_case)
    with pytest.raises(release_candidate.CandidateError, match="does not embed release commit"):
        release_candidate._validate_gateway_archives(runtime, VERSION, commit="b" * 40)


def test_only_manifest_bound_protocol_two_artifacts_are_installable(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)

    protected_gateway = runtime / RELEASE_ARTIFACTS["gateways"]["linux"]["amd64"]
    assert protected_gateway.read_bytes().startswith(release_candidate.PROTECTED_ARTIFACT_MAGIC)
    with tarfile.open(
        fileobj=io.BytesIO(release_candidate._protected_payload(protected_gateway)), mode="r:gz"
    ) as archive:
        assert any(Path(member.name).name == "defenseclaw" for member in archive.getmembers())
    with pytest.raises(tarfile.TarError):
        tarfile.open(protected_gateway, mode="r:gz")
    canonical_gateway = runtime / f"defenseclaw_{VERSION}_linux_amd64.tar.gz"
    assert canonical_gateway.read_bytes() == release_candidate._refusal_envelope_payload(VERSION)
    with pytest.raises(tarfile.TarError):
        tarfile.open(canonical_gateway, mode="r:gz")
    tar = shutil.which("tar")
    if tar is None:
        pytest.skip("system tar is unavailable")
    extraction = tmp_path / "legacy-extraction"
    extraction.mkdir()
    completed = subprocess.run(
        [tar, "-xzf", str(canonical_gateway), "-C", str(extraction)],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode != 0
    assert not list(extraction.iterdir())

    assert not zipfile.is_zipfile(runtime / PROTECTED_WHEEL)
    with zipfile.ZipFile(io.BytesIO(release_candidate._protected_payload(runtime / PROTECTED_WHEEL))) as wheel:
        assert any(name.endswith(".dist-info/METADATA") for name in wheel.namelist())
    assert not zipfile.is_zipfile(runtime / f"defenseclaw-{VERSION}-py3-none-any.whl")
    assert not zipfile.is_zipfile(runtime / RELEASE_ARTIFACTS["gateways"]["windows"]["amd64"])
    assert not zipfile.is_zipfile(runtime / f"defenseclaw_{VERSION}_windows_amd64.zip")
    bridge_message = release_candidate._refusal_envelope_payload(VERSION).decode()
    assert "must be installed by the release-owned staged upgrade resolver" in bridge_message
    assert "requires the 0.8.4 upgrade bridge" not in bridge_message

    hard_cut_message = release_candidate._refusal_envelope_payload("0.8.5").decode()
    assert "requires the 0.8.4 upgrade bridge" in hard_cut_message


def test_published_protected_wheel_is_rejected_by_package_managers_before_install(
    tmp_path: Path,
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is unavailable")
    runtime = _runtime_dir(tmp_path)
    protected = runtime / PROTECTED_WHEEL
    renamed = tmp_path / f"defenseclaw-{VERSION}-py3-none-any.whl"
    shutil.copyfile(protected, renamed)
    for index, candidate in enumerate((protected, renamed)):
        target = tmp_path / f"managed-site-packages-{index}"
        completed = subprocess.run(
            [
                uv,
                "pip",
                "install",
                "--target",
                str(target),
                "--no-deps",
                str(candidate),
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert completed.returncode != 0
        assert not target.exists() or {entry.name for entry in target.iterdir()} <= {".lock"}


def test_manifest_cannot_point_resolvers_at_legacy_refusal_names(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    manifest_path = runtime / "upgrade-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["release_artifacts"]["wheel"] = f"defenseclaw-{VERSION}-py3-none-any.whl"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="release_artifacts"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_candidate_verification_rejects_artifact_mutation(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)
    wheel = root / "dist" / PROTECTED_WHEEL
    wheel.write_bytes(wheel.read_bytes() + b"mutated")

    with pytest.raises(release_candidate.CandidateError, match="asset digests changed"):
        release_candidate.verify(root, VERSION, COMMIT)


def test_candidate_verification_rejects_resolver_mutation(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)
    resolver = root / "dist/defenseclaw-upgrade.sh"
    resolver.write_bytes(resolver.read_bytes() + b"# mutation\n")

    with pytest.raises(release_candidate.CandidateError, match="asset digests changed"):
        release_candidate.verify(root, VERSION, COMMIT)


def test_candidate_verification_rejects_unsealed_extra_asset(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)
    (root / "dist/unreviewed.bin").write_bytes(b"not tested")

    with pytest.raises(release_candidate.CandidateError, match="file set changed"):
        release_candidate.verify(root, VERSION, COMMIT)


def test_candidate_verification_rejects_unsealed_directory(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)
    (root / "dist/unreviewed").mkdir()

    with pytest.raises(release_candidate.CandidateError, match="non-file entries"):
        release_candidate.verify(root, VERSION, COMMIT)


@pytest.mark.parametrize("status", ["", "adhoc", "signed-unnotarized"])
def test_candidate_assembly_rejects_unsupported_macos_status(
    tmp_path: Path,
    status: str,
) -> None:
    with pytest.raises(release_candidate.CandidateError, match="verification status"):
        release_candidate.assemble(
            _runtime_dir(tmp_path),
            _macos_dir(tmp_path),
            tmp_path / "candidate",
            VERSION,
            COMMIT,
            status,
        )


def test_candidate_assembly_rejects_macos_names_that_disagree_with_status(
    tmp_path: Path,
) -> None:
    with pytest.raises(release_candidate.CandidateError, match="missing regular file"):
        release_candidate.assemble(
            _runtime_dir(tmp_path),
            _macos_dir(tmp_path),
            tmp_path / "candidate",
            VERSION,
            COMMIT,
            "unverified",
        )


def test_candidate_assembly_rejects_mixed_macos_asset_sets(tmp_path: Path) -> None:
    macos = _macos_dir(tmp_path, "unverified")
    (macos / f"DefenseClawMac-{VERSION}-macos-arm64.dmg").write_bytes(b"unexpected")

    with pytest.raises(release_candidate.CandidateError, match="does not match"):
        release_candidate.assemble(
            _runtime_dir(tmp_path),
            macos,
            tmp_path / "candidate",
            VERSION,
            COMMIT,
            "unverified",
        )


def test_candidate_verification_binds_unverified_names_to_unverified_status(
    tmp_path: Path,
) -> None:
    root = _sealed_candidate(tmp_path, "unverified")
    manifest_path = root / "release-candidate.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["macos_verification_status"] = "notarized"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="missing regular file"):
        release_candidate.verify(root, VERSION, COMMIT)


def test_runtime_verification_rejects_mismatched_upgrade_manifest(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    manifest = json.loads((runtime / "upgrade-manifest.json").read_text(encoding="utf-8"))
    manifest["release_version"] = "9.9.9"
    (runtime / "upgrade-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="release_version"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_rejects_wheel_protocol_drift(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    _rewrite_wheel_controller(
        runtime / PROTECTED_WHEEL,
        protocol=1,
    )

    with pytest.raises(release_candidate.CandidateError, match="controller protocol"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_protocol_two_even_when_manifest_matches(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    _rewrite_wheel_controller(wheel, protocol=1)
    manifest_path = runtime / "upgrade-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["controller_upgrade_protocol"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="protocol-2 bridge controller"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_release_owned_handoff_call(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    _transform_wheel_controller(
        wheel,
        lambda source: source.replace(
            "        _require_release_owned_hard_cut_handoff()\n",
            "        pass\n",
        ),
    )

    with pytest.raises(release_candidate.CandidateError, match="release-owned handoff gate"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_repository_controller_handoff_is_the_first_guarded_call() -> None:
    source = (
        ROOT / "cli" / "defenseclaw" / "commands" / "cmd_upgrade.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    entrypoints = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "upgrade"
    ]
    assert len(entrypoints) == 1
    calls = release_candidate._upgrade_controller_calls(entrypoints[0])
    guarded_first = release_candidate._direct_hard_cut_guard_first_calls(entrypoints[0])
    handoffs = [
        (line, guarded)
        for name, line, guarded in calls
        if name == "_require_release_owned_hard_cut_handoff"
    ]
    assert len(handoffs) == 1
    assert handoffs[0][1]
    assert ("_require_release_owned_hard_cut_handoff", handoffs[0][0]) in guarded_first


@pytest.mark.parametrize(
    "guard",
    [
        "not _is_bridge_to_hard_cut_phase()",
        "_is_bridge_to_hard_cut_phase() and False",
    ],
)
def test_bridge_candidate_rejects_inverted_or_dead_handoff_guard(
    tmp_path: Path,
    guard: str,
) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    expected = "    if _is_bridge_to_hard_cut_phase():\n        _require_release_owned_hard_cut_handoff()\n"
    replacement = f"    if {guard}:\n        _require_release_owned_hard_cut_handoff()\n"
    _transform_wheel_controller(
        wheel,
        lambda source: source.replace(expected, replacement),
    )

    with pytest.raises(release_candidate.CandidateError, match="release-owned handoff gate"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_handoff_before_acquisition_or_backup(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    original = (
        "    if _is_bridge_to_hard_cut_phase():\n"
        "        _require_release_owned_hard_cut_handoff()\n"
        "    if _is_bridge_to_hard_cut_phase():\n"
        "        _acquire_bridge_rollback_artifacts()\n"
    )
    reordered = (
        "    if _is_bridge_to_hard_cut_phase():\n"
        "        _acquire_bridge_rollback_artifacts()\n"
        "    if _is_bridge_to_hard_cut_phase():\n"
        "        _require_release_owned_hard_cut_handoff()\n"
    )
    _transform_wheel_controller(wheel, lambda source: source.replace(original, reordered))

    with pytest.raises(
        release_candidate.CandidateError,
        match="before bridge artifact acquisition or backup",
    ):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_schema_two_tested_source_policy(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    manifest_path = runtime / "upgrade-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    manifest["schema_version"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="schema_version must be 2"):
        release_candidate.verify_runtime(runtime, VERSION)

    manifest["schema_version"] = 2
    manifest["platform_tested_source_versions"]["windows"].append("0.7.2")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="reviewed Windows matrix"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_phase_two_mutator_wrapper(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    members.pop("defenseclaw/phase_two_mutator.py")
    _write_wheel_members(wheel, members)

    with pytest.raises(release_candidate.CandidateError, match="invalid candidate wheel"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_exact_wheel_shipped_install_publisher(
    tmp_path: Path,
) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    members["defenseclaw/install_publish.py"] += b"\n# unreviewed mutation\n"
    _write_wheel_members(wheel, members)

    with pytest.raises(release_candidate.CandidateError, match="exact reviewed install publisher"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_rejects_duplicate_wheel_publisher_member(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    archive_payload = io.BytesIO()
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(archive_payload, mode="w") as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)
            archive.writestr(
                "defenseclaw/install_publish.py",
                members["defenseclaw/install_publish.py"],
            )
    wheel.write_bytes(
        release_candidate.PROTECTED_ARTIFACT_MAGIC
        + archive_payload.getvalue().translate(release_candidate.PROTECTED_ARTIFACT_TRANSLATION)
    )

    with pytest.raises(release_candidate.CandidateError, match="duplicate member"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_rejects_mutator_wrapper_that_drops_child_lease(
    tmp_path: Path,
) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    members["defenseclaw/phase_two_mutator.py"] = PHASE_TWO_MUTATOR_SOURCE.replace(
        'pass_fds=(lease_fd,) if os.name == "posix" else (),',
        "pass_fds=(),",
    ).encode()
    _write_wheel_members(wheel, members)

    with pytest.raises(release_candidate.CandidateError, match="hand the lease to its child"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_rejects_dead_branch_lease_decoy(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    members["defenseclaw/phase_two_mutator.py"] = PHASE_TWO_MUTATOR_SOURCE.replace(
        'pass_fds=(lease_fd,) if os.name == "posix" else (),',
        "pass_fds=() if True else (lease_fd,),",
    ).encode()
    _write_wheel_members(wheel, members)

    with pytest.raises(release_candidate.CandidateError, match="hand the lease to its child"):
        release_candidate.verify_runtime(runtime, VERSION)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor inheritance canary")
def test_candidate_wheel_mutator_holds_lease_for_real_child_lifetime(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    wrapper = tmp_path / "phase_two_mutator.py"
    wrapper.write_bytes(_read_wheel_members(wheel)["defenseclaw/phase_two_mutator.py"])
    lease = tmp_path / "phase-two-mutator.lease"
    descriptor = os.open(lease, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    child_marker = tmp_path / "child-completed"
    child = (
        "import os, pathlib, sys, time; "
        "os.fstat(int(sys.argv[1])); "
        "time.sleep(0.25); "
        "pathlib.Path(sys.argv[2]).write_text('held', encoding='utf-8')"
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(wrapper),
                "--defenseclaw-phase-two-mutator",
                str(lease),
                str(descriptor),
                "--",
                sys.executable,
                "-c",
                child,
                str(descriptor),
                str(child_marker),
            ],
            pass_fds=(descriptor,),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        os.close(descriptor)

    assert completed.returncode == 0, completed.stderr
    assert time.monotonic() - started >= 0.2
    assert child_marker.read_text(encoding="utf-8") == "held"


@pytest.mark.parametrize(
    "member",
    [
        "defenseclaw/observability/v8_activation.py",
        "defenseclaw/tui/services/v8_event_history.py",
        "defenseclaw/_data/config/v8/observability.yaml",
        "defenseclaw/_data/telemetry/v8/catalog.json",
    ],
)
def test_bridge_candidate_rejects_v8_runtime_resources(tmp_path: Path, member: str) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    members[member] = b"v8 runtime must not ship in the bridge\n"
    _write_wheel_members(wheel, members)

    with pytest.raises(release_candidate.CandidateError, match="v8 runtime resources"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_rejects_post_bridge_migration(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / PROTECTED_WHEEL
    members = _read_wheel_members(wheel)
    members["defenseclaw/migrations.py"] = (
        b"def _migrate_fixture(): pass\n"
        b'MIGRATIONS = [("0.8.4", "bridge", _migrate_fixture), '
        b'("0.8.5", "hard cut", _migrate_fixture)]\n'
    )
    _write_wheel_members(wheel, members)

    with pytest.raises(release_candidate.CandidateError, match="post-bridge migration"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_non_bridge_candidate_allows_forward_keyed_migration(tmp_path: Path) -> None:
    version = "0.8.5"
    wheel = tmp_path / f"defenseclaw-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr(
            "defenseclaw/commands/cmd_upgrade.py",
            "_UPGRADE_PROTOCOL_VERSION = 2\n"
            '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
            "def _is_bridge_to_hard_cut_phase(): return True\n"
            "def _require_release_owned_hard_cut_handoff(): pass\n"
            "def _acquire_bridge_rollback_artifacts(): pass\n"
            "def _prepare_hard_cut_rollback_plan(): pass\n"
            "def _write_hard_cut_recovery_journal(): pass\n"
            "def _recover_interrupted_hard_cut(): pass\n"
            "def _run_phase_two_mutator(): pass\n"
            "def _execute_hard_cut_rollback(): pass\n"
            "def _poll_health(): pass\n"
            "def _create_backup(): pass\n"
            "def upgrade():\n"
            "    if _is_bridge_to_hard_cut_phase():\n"
            "        _require_release_owned_hard_cut_handoff()\n"
            "    if _is_bridge_to_hard_cut_phase():\n"
            "        _acquire_bridge_rollback_artifacts()\n"
            "    _create_backup()\n"
            "    _prepare_hard_cut_rollback_plan()\n",
        )
        archive.writestr(
            "defenseclaw/migrations.py",
            "def _migrate_fixture(): pass\n"
            'MIGRATIONS = [("0.8.5", "hard cut", _migrate_fixture), '
            '("0.8.6", "forward keyed", _migrate_fixture)]\n',
        )
        archive.writestr("defenseclaw/phase_two_mutator.py", PHASE_TWO_MUTATOR_SOURCE)
        archive.writestr(
            "defenseclaw/install_publish.py",
            (ROOT / "cli/defenseclaw/install_publish.py").read_bytes(),
        )
        archive.writestr(
            "defenseclaw/bundle_refresh.py",
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE,
        )
        archive.writestr(
            f"defenseclaw-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: defenseclaw\nVersion: {version}\n",
        )
    (tmp_path / "upgrade-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "release_version": version,
                "controller_upgrade_protocol": 2,
                "min_upgrade_protocol": 2,
                "migration_failure_policy": "fail",
                "minimum_source_version": "0.8.4",
                "required_bridge_version": "0.8.4",
                "auto_bridge_from": ["0.8.3"],
                "required_cli_migrations": ["0.8.5"],
                "tested_source_versions": ["0.8.3"],
                "platform_tested_source_versions": {"windows": ["0.8.3"]},
            }
        ),
        encoding="utf-8",
    )

    release_candidate._validate_wheel(wheel, version)


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "restart_required": was_running,\n',
                "",
            ),
            "restart_required",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        _fsync_file(backup_path)\n",
                "",
            ),
            "not fsynced",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        _fsync_directory_chain(backup_path.parent, stop=backup_root)\n",
                "",
            ),
            "directory entries are not fsynced",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        _fsync_directory_chain(backup_path.parent, stop=backup_root)\n",
                "        _fsync_directory_chain(backup_path.parent, stop=backup_path.parent)\n",
            ),
            "must include the backup root",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        _fsync_file(backup_path)\n"
                "        _fsync_directory_chain(backup_path.parent, stop=backup_root)\n",
                "        _fsync_directory_chain(backup_path.parent, stop=backup_root)\n"
                "        _fsync_file(backup_path)\n",
            ),
            "before directory entries",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        old_modes[path] = stat.S_IMODE(path.stat().st_mode)\n",
                "        old_modes[path] = 0o600\n",
            ),
            "exact digest and mode inventory",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "schema_version": 2,\n',
                '        "schema_version": 1,\n',
            ),
            "schema version 2",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    managed_paths = existing_paths | created_paths\n",
                "    managed_paths = existing_paths\n",
            ),
            "exact existing/created union",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "created_sha256": created_sha256,\n',
                "",
            ),
            "created_sha256",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "created_sha256": created_sha256,\n',
                '        "created_sha256": (created_sha256, {})[0],\n',
            ),
            "created_sha256 is not bound",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "old_windows_security": old_windows_security,\n',
                "",
            ),
            "old_windows_security",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
                "    serialized_metadata = b\"not the metadata object\"\n",
            ),
            "publish its exact schema-2 metadata object",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    if not 0 < len(serialized_metadata) <= _MAX_BUNDLE_ROLLBACK_METADATA_BYTES:\n"
                "        raise OSError(\"rollback metadata exceeds the bridge reader bound\")\n",
                "",
            ),
            "serialized metadata is not bounded",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "len(serialized_metadata) <= _MAX_BUNDLE_ROLLBACK_METADATA_BYTES",
                "len(serialized_metadata) >= _MAX_BUNDLE_ROLLBACK_METADATA_BYTES",
            ),
            "invalid size bound",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '    backup_created = backup_root / "created"\n',
                '    backup_created = backup_root / "claims"\n',
            ),
            "created rollback custody",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    _mkdir_private(backup_retired)\n",
                "",
            ),
            "retired rollback custody is not durably created",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        _fsync_file(created_claim)\n",
                "",
            ),
            "claims are not durably retained",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        _fsync_directory_chain(created_claim.parent, stop=backup_root)\n",
                "",
            ),
            "claims are not durably retained",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        created_sha256[path] = _sha256_file(created_claim)\n",
                "",
            ),
            "claim digest inventory is incomplete",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        os.link(created_claim, destination)\n",
                "",
            ),
            "lack one no-replace publication",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "                windows_acl.capture_path(path)\n",
                "                windows_acl.private_security_for_directory(path)\n",
            ),
            "not captured and serialized exactly",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        if os.name == "nt":\n',
                '        if os.name != "nt":\n',
            ),
            "not platform-exact",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "owner": base64.b64encode(security.owner).decode("ascii"),\n',
                "",
            ),
            "lacks exact owner/DACL fields",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        "owner": base64.b64encode(security.owner).decode("ascii"),\n',
                '        "owner": (base64.b64encode(security.owner).decode("ascii"), "forged")[1],\n',
            ),
            "not canonically serialized",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "        destination = path\n",
                '        destination = "foreign/path"\n',
                1,
            ),
            "not claim-bound",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                '        _atomic_copy_file("stage", created_claim)\n',
                '        _atomic_copy_file("stage", created_claim)\n'
                '        _atomic_copy_file("extra", created_claim)\n',
            ),
            "lacks one retained target-created claim loop",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
                '    _atomic_copy_file("stage", path)\n'
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
            ),
            "ambiguous copy mutation",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
                '    _atomic_write_bytes("canonical", b"early mutation")\n'
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
            ),
            "ambiguous direct file write",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
                '    path.write_bytes(b"early mutation")\n'
                "    serialized_metadata = json.dumps(backup_metadata, sort_keys=True).encode(\"utf-8\")\n",
            ),
            "bypasses its reviewed publication primitives",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "            old_windows_security[path] = _serialize_windows_security(\n",
                "            old_windows_security['wrong'] = _serialize_windows_security(\n",
            ),
            "not keyed by its exact path",
        ),
        (
            HARD_CUT_BUNDLE_TRANSACTION_SOURCE.replace(
                "    _atomic_write_bytes(backup_root / \"refresh-backup.json\", serialized_metadata)\n"
                "    mutation_started = False\n"
                "    mutation_started = True\n",
                "    mutation_started = False\n"
                "    mutation_started = True\n"
                "    _atomic_write_bytes(backup_root / \"refresh-backup.json\", serialized_metadata)\n",
            ),
            "not durable before first mutation",
        ),
    ],
)
def test_hard_cut_candidate_requires_durable_bundle_rollback_authority(
    source: str,
    message: str,
) -> None:
    with pytest.raises(release_candidate.CandidateError, match=message):
        release_candidate._validate_hard_cut_bundle_transaction(source)


def test_hard_cut_candidate_rejects_legacy_minimal_bundle_transaction() -> None:
    source = """
import shutil

def _fsync_directory_chain(path, *, stop):
    while path != stop:
        _fsync_directory(path)
        path = path.parent

def _activate_local_observability_manifest(*, was_running: bool):
    managed_paths = {"managed/file"}
    backup_root = object()
    backup_metadata = {
        "managed_paths": sorted(managed_paths),
        "restart_required": was_running,
    }
    for path in managed_paths:
        backup_path = path
        shutil.copy2(path, backup_path)
        _fsync_file(backup_path)
        _fsync_directory_chain(backup_path.parent, stop=backup_root)
    _atomic_write_bytes(backup_root / "refresh-backup.json", b"metadata")
    mutation_started = True
    return mutation_started
"""
    with pytest.raises(
        release_candidate.CandidateError,
        match="metadata size bound",
    ):
        release_candidate._validate_hard_cut_bundle_transaction(source)


def test_hard_cut_auto_bridge_exactly_matches_older_published_baselines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "upgrade-baselines.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "published_baselines": ["0.8.4", "0.8.3", "0.8.2"],
                "published_baseline_config_versions": {
                    "0.8.4": 7,
                    "0.8.3": 7,
                    "0.8.2": 6,
                },
                "platform_published_baselines": {"windows": ["0.8.4", "0.8.3"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(release_candidate, "UPGRADE_BASELINES_PATH", policy)
    digest_policy = tmp_path / "historical-artifact-digests.json"
    digest_policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signed_wheel_coverage_starts_at": "0.8.2",
                "signed_checksum_exceptions": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        release_candidate,
        "HISTORICAL_ARTIFACT_DIGESTS_PATH",
        digest_policy,
    )
    manifest_path = tmp_path / "upgrade-manifest.json"
    manifest = {
        "schema_version": 2,
        "runtime_config_version": 8,
        "release_version": "0.8.5",
        "min_upgrade_protocol": 2,
        "controller_upgrade_protocol": 2,
        "migration_failure_policy": "fail",
        "minimum_source_version": "0.8.4",
        "required_bridge_version": "0.8.4",
        "auto_bridge_from": ["0.8.3"],
        "tested_source_versions": ["0.8.4", "0.8.3", "0.8.2"],
        "platform_tested_source_versions": {"windows": ["0.8.4", "0.8.3"]},
        "release_artifacts": release_candidate._expected_release_artifacts("0.8.5"),
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(release_candidate, "_runtime_config_version_from_source", lambda: 8)

    with pytest.raises(release_candidate.CandidateError, match="exactly match every"):
        release_candidate._validate_upgrade_manifest(manifest_path, "0.8.5")

    manifest["auto_bridge_from"] = ["0.8.3", "0.8.2"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    release_candidate._validate_upgrade_manifest(manifest_path, "0.8.5")


def test_bridge_candidate_accepts_schema_two_policy_before_bridge_is_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "upgrade-baselines.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "published_baselines": ["0.8.3", "0.8.2"],
                "published_baseline_config_versions": {
                    "0.8.3": 7,
                    "0.8.2": 6,
                },
                "platform_published_baselines": {"windows": ["0.8.3", "0.8.2"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(release_candidate, "UPGRADE_BASELINES_PATH", policy)
    digest_policy = tmp_path / "historical-artifact-digests.json"
    digest_policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signed_wheel_coverage_starts_at": "0.8.2",
                "signed_checksum_exceptions": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        release_candidate,
        "HISTORICAL_ARTIFACT_DIGESTS_PATH",
        digest_policy,
    )

    assert release_candidate._load_upgrade_baseline_policy() == (
        ["0.8.3", "0.8.2"],
        {"windows": ["0.8.3", "0.8.2"]},
    )


def test_schema1_bridge_contract_without_tested_policy_has_normalized_error(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "upgrade-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_version": "0.8.3",
                "min_upgrade_protocol": 1,
                "controller_upgrade_protocol": 1,
                "migration_failure_policy": "fail",
                "minimum_source_version": "0.8.2",
                "required_bridge_version": "0.8.2",
                "auto_bridge_from": ["0.8.1"],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        release_candidate.CandidateError,
        match="bridge contract requires the schema-2 tested-source policy",
    ):
        release_candidate._validate_upgrade_manifest(manifest_path, "0.8.3")


def test_sealer_requires_digest_exceptions_for_exact_unsigned_baseline_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "historical-artifact-digests.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signed_wheel_coverage_starts_at": "0.6.1",
                "signed_checksum_exceptions": {
                    "0.6.0": {
                        "defenseclaw-0.6.0-py3-none-any.whl": "0" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        release_candidate,
        "HISTORICAL_ARTIFACT_DIGESTS_PATH",
        policy,
    )

    with pytest.raises(release_candidate.CandidateError, match="exactly match"):
        release_candidate._validate_historical_artifact_digest_policy(["0.6.1", "0.6.0", "0.5.0"])


def test_bridge_candidate_runtime_attestation_matches_gateway_source(tmp_path: Path) -> None:
    manifest_path = _runtime_dir(tmp_path) / "upgrade-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["runtime_config_version"] = 8
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="runtime_config_version"):
        release_candidate._validate_upgrade_manifest(manifest_path, VERSION)
