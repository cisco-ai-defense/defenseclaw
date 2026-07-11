# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import release_candidate

VERSION = "0.8.4"
COMMIT = "a" * 40


def _write_tar(path: Path, member_name: str) -> None:
    payload = b"candidate gateway"
    info = tarfile.TarInfo(member_name)
    info.size = len(payload)
    with tarfile.open(path, mode="w:gz") as archive:
        archive.addfile(info, io.BytesIO(payload))


def _write_zip(path: Path, member_name: str, payload: bytes = b"candidate gateway") -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        archive.writestr(member_name, payload)


def _rewrite_wheel_controller(path: Path, protocol: int) -> None:
    with zipfile.ZipFile(path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members["defenseclaw/commands/cmd_upgrade.py"] = (
        f"_UPGRADE_PROTOCOL_VERSION = {protocol}\n"
        '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
        "def _prepare_hard_cut_rollback_plan(): pass\n"
        "def _execute_hard_cut_rollback(): pass\n"
        "def _poll_health(): pass\n"
        "_prepare_hard_cut_rollback_plan()\n"
    ).encode()
    with zipfile.ZipFile(path, mode="w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)


def _runtime_dir(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    for os_name in ("darwin", "linux"):
        for arch in ("amd64", "arm64"):
            archive_name = f"defenseclaw_{VERSION}_{os_name}_{arch}.tar.gz"
            _write_tar(runtime / archive_name, "defenseclaw")
            (runtime / f"{archive_name}.sbom.json").write_text("{}\n", encoding="utf-8")
    for arch in ("amd64", "arm64"):
        archive_name = f"defenseclaw_{VERSION}_windows_{arch}.zip"
        _write_zip(runtime / archive_name, "defenseclaw.exe")
        (runtime / f"{archive_name}.sbom.json").write_text("{}\n", encoding="utf-8")

    wheel = runtime / f"defenseclaw-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("defenseclaw/__init__.py", f'__version__ = "{VERSION}"\n')
        archive.writestr(
            "defenseclaw/commands/cmd_upgrade.py",
            "_UPGRADE_PROTOCOL_VERSION = 2\n"
            '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
            "def _prepare_hard_cut_rollback_plan(): pass\n"
            "def _write_hard_cut_recovery_journal(): pass\n"
            "def _recover_interrupted_hard_cut(): pass\n"
            "def _run_phase_two_mutator(): pass\n"
            "def _execute_hard_cut_rollback(): pass\n"
            "def _poll_health(): pass\n"
            "_prepare_hard_cut_rollback_plan()\n",
        )
        archive.writestr(
            "defenseclaw/migrations.py",
            "def _migrate_fixture(): pass\n"
            'MIGRATIONS = [("0.8.4", "fixture migration", _migrate_fixture)]\n',
        )
        archive.writestr("defenseclaw/phase_two_mutator.py", "def main(): return 0\n")
        archive.writestr(
            f"defenseclaw-{VERSION}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: defenseclaw\nVersion: {VERSION}\n",
        )
    _write_tar(runtime / f"defenseclaw-plugin-{VERSION}.tar.gz", "package/package.json")
    (runtime / "upgrade-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_version": VERSION,
                "controller_upgrade_protocol": 2,
                "min_upgrade_protocol": 1,
                "migration_failure_policy": "fail",
                "required_cli_migrations": [VERSION],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (runtime / "CHANGELOG.md").write_text("# Candidate notes\n", encoding="utf-8")
    return runtime


def _macos_dir(tmp_path: Path) -> Path:
    macos = tmp_path / "macos"
    macos.mkdir()
    (macos / f"DefenseClawMac-{VERSION}-macos-arm64.dmg").write_bytes(b"candidate dmg")
    _write_zip(
        macos / f"DefenseClawMac-{VERSION}-macos-arm64.zip",
        "DefenseClawMac.app/Contents/Info.plist",
        b"candidate app",
    )
    return macos


def _sealed_candidate(tmp_path: Path) -> Path:
    root = tmp_path / "candidate"
    release_candidate.assemble(
        _runtime_dir(tmp_path),
        _macos_dir(tmp_path),
        root,
        VERSION,
        COMMIT,
        "notarized",
    )
    (root / "dist/checksums.txt.sig").write_bytes(b"sigstore signature")
    (root / "dist/checksums.txt.pem").write_bytes(b"sigstore certificate")
    release_candidate.seal(root, VERSION, COMMIT)
    return root


def test_candidate_seals_and_verifies_exact_publish_set(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)

    release_candidate.verify(root, VERSION, COMMIT)

    manifest = json.loads((root / "release-candidate.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in manifest["assets"]] == list(
        release_candidate.published_asset_names(VERSION)
    )
    checksums = release_candidate._parse_checksums(root / "dist/checksums.txt")
    assert tuple(sorted(checksums)) == release_candidate.payload_asset_names(VERSION)
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


def test_exact_gateway_is_safely_extracted_from_runtime_candidate(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    output = tmp_path / "extracted/defenseclaw"

    release_candidate.extract_gateway(runtime, output, VERSION, "darwin", "arm64")

    assert output.read_bytes() == b"candidate gateway"
    assert output.stat().st_mode & 0o111


def test_candidate_verification_rejects_artifact_mutation(tmp_path: Path) -> None:
    root = _sealed_candidate(tmp_path)
    wheel = root / "dist" / f"defenseclaw-{VERSION}-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"mutated")

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


def test_candidate_assembly_requires_notarized_macos_artifacts(tmp_path: Path) -> None:
    with pytest.raises(release_candidate.CandidateError, match="requires a notarized macOS app"):
        release_candidate.assemble(
            _runtime_dir(tmp_path),
            _macos_dir(tmp_path),
            tmp_path / "candidate",
            VERSION,
            COMMIT,
            "adhoc",
        )


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
        runtime / f"defenseclaw-{VERSION}-py3-none-any.whl",
        protocol=1,
    )

    with pytest.raises(release_candidate.CandidateError, match="controller protocol"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_protocol_two_even_when_manifest_matches(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / f"defenseclaw-{VERSION}-py3-none-any.whl"
    _rewrite_wheel_controller(wheel, protocol=1)
    manifest_path = runtime / "upgrade-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["controller_upgrade_protocol"] = 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="protocol-2 bridge controller"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_requires_phase_two_mutator_wrapper(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / f"defenseclaw-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {
            name: archive.read(name)
            for name in archive.namelist()
            if name != "defenseclaw/phase_two_mutator.py"
        }
    with zipfile.ZipFile(wheel, mode="w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)

    with pytest.raises(release_candidate.CandidateError, match="invalid candidate wheel"):
        release_candidate.verify_runtime(runtime, VERSION)


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
    wheel = runtime / f"defenseclaw-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members[member] = b"v8 runtime must not ship in the bridge\n"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)

    with pytest.raises(release_candidate.CandidateError, match="v8 runtime resources"):
        release_candidate.verify_runtime(runtime, VERSION)


def test_bridge_candidate_rejects_post_bridge_migration(tmp_path: Path) -> None:
    runtime = _runtime_dir(tmp_path)
    wheel = runtime / f"defenseclaw-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members["defenseclaw/migrations.py"] = (
        b"def _migrate_fixture(): pass\n"
        b'MIGRATIONS = [("0.8.4", "bridge", _migrate_fixture), '
        b'("0.8.5", "hard cut", _migrate_fixture)]\n'
    )
    with zipfile.ZipFile(wheel, mode="w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)

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
            "def _prepare_hard_cut_rollback_plan(): pass\n"
            "def _write_hard_cut_recovery_journal(): pass\n"
            "def _recover_interrupted_hard_cut(): pass\n"
            "def _run_phase_two_mutator(): pass\n"
            "def _execute_hard_cut_rollback(): pass\n"
            "def _poll_health(): pass\n"
            "_prepare_hard_cut_rollback_plan()\n",
        )
        archive.writestr(
            "defenseclaw/migrations.py",
            "def _migrate_fixture(): pass\n"
            'MIGRATIONS = [("0.8.5", "hard cut", _migrate_fixture), '
            '("0.8.6", "forward keyed", _migrate_fixture)]\n',
        )
        archive.writestr("defenseclaw/phase_two_mutator.py", "def main(): return 0\n")
        archive.writestr(
            f"defenseclaw-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: defenseclaw\nVersion: {version}\n",
        )
    (tmp_path / "upgrade-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_version": version,
                "controller_upgrade_protocol": 2,
                "min_upgrade_protocol": 2,
                "migration_failure_policy": "fail",
                "minimum_source_version": "0.8.4",
                "required_bridge_version": "0.8.4",
                "auto_bridge_from": ["0.8.3"],
                "required_cli_migrations": ["0.8.5"],
            }
        ),
        encoding="utf-8",
    )

    release_candidate._validate_wheel(wheel, version)


def test_hard_cut_auto_bridge_exactly_matches_older_published_baselines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "upgrade-baselines.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "published_baselines": ["0.8.4", "0.8.3", "0.8.2"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(release_candidate, "UPGRADE_BASELINES_PATH", policy)
    manifest_path = tmp_path / "upgrade-manifest.json"
    manifest = {
        "schema_version": 1,
        "release_version": "0.8.5",
        "min_upgrade_protocol": 2,
        "controller_upgrade_protocol": 2,
        "migration_failure_policy": "fail",
        "minimum_source_version": "0.8.4",
        "required_bridge_version": "0.8.4",
        "auto_bridge_from": ["0.8.3"],
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release_candidate.CandidateError, match="exactly match every"):
        release_candidate._validate_upgrade_manifest(manifest_path, "0.8.5")

    manifest["auto_bridge_from"] = ["0.8.3", "0.8.2"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    release_candidate._validate_upgrade_manifest(manifest_path, "0.8.5")
