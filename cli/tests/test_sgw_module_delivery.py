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

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

import pytest
from build.env import DefaultIsolatedEnv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import build

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
try:
    from scripts import sgw_module, stage_sgw_modules, sync_sgw_vendor
finally:
    sys.path.pop(0)

MODULE_MANIFEST = ROOT / "release" / "s-gw-module.json"
RUNTIME_MANIFEST = ROOT / "release" / "s-gw-runners.json"
TARGETS = stage_sgw_modules.TARGETS
CORE_LICENSE_TERMS = (
    "Permission is granted to run this s-gw Core fixture solely with the authenticated "
    "DefenseClaw distribution. No redistribution rights are granted by these test terms."
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_stage_cli_uses_source_defaults_for_blank_path_environment(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("DEFENSECLAW_SGW_ARTIFACT_DIR", value)
    monkeypatch.setenv("DEFENSECLAW_SGW_RUNTIME_MANIFEST", value)

    args = stage_sgw_modules.parse_args(["stage", "--destination", "staged"])

    assert args.artifact_dir == Path("dist/sgw")
    assert args.runtime_manifest == Path("release/s-gw-runners.json")


def test_stage_cli_preserves_explicit_path_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_SGW_ARTIFACT_DIR", "custom/artifacts")
    monkeypatch.setenv("DEFENSECLAW_SGW_RUNTIME_MANIFEST", "custom/runtime.json")

    args = stage_sgw_modules.parse_args(["stage", "--destination", "staged"])

    assert args.artifact_dir == Path("custom/artifacts")
    assert args.runtime_manifest == Path("custom/runtime.json")


def signature(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.b64encode(private_key.sign(payload)).decode("ascii")


def configure_signing(runtime: dict) -> Ed25519PrivateKey:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    runtime["redistribution_status"] = "approved"
    runtime["signature_policy"] = {
        "algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM,
        "public_key": public_pem.decode("ascii"),
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
    }
    return private_key


def launch_admission(target: str) -> dict:
    common = {
        "schema_version": 1,
        "signature_scope": "installed-runner-bytes",
        "dependency_policy": "system-only-v1",
    }
    if target.startswith("linux-"):
        return {**common, "mode": "linux-sealed-memfd-v1"}
    if target.startswith("win32-"):
        return {
            **common,
            "mode": "windows-locked-image-v1",
            "pe_machine": "x86_64" if target.endswith("-x64") else "arm64",
            "required_mitigations": sgw_module.WINDOWS_RUNNER_MITIGATIONS,
        }
    return {
        **common,
        "mode": "darwin-running-code-v1",
        "team_id": "ABCDE12345",
        "signing_id": "com.cisco.defenseclaw.s-gw-core",
        "cdhash": "1" * 40,
        "required_cs_flags": sgw_module.MACOS_RUNNER_CS_FLAGS,
    }


def native_payload(target: str, label: str) -> bytes:
    if target.startswith("linux-"):
        machine = 62 if target.endswith("-x64") else 183
        value = bytearray(64)
        value[:4] = b"\x7fELF"
        value[4:7] = b"\x02\x01\x01"
        value[16:18] = (2).to_bytes(2, "little")
        value[18:20] = machine.to_bytes(2, "little")
        value[20:24] = (1).to_bytes(4, "little")
        value[24 : 24 + len(label)] = label.encode("ascii")
        return bytes(value)
    if target.startswith("darwin-"):
        cpu_type = 0x01000007 if target.endswith("-x64") else 0x0100000C
        return b"\xcf\xfa\xed\xfe" + cpu_type.to_bytes(4, "little") + label.encode("ascii")
    machine = 0x8664 if target.endswith("-x64") else 0xAA64
    value = bytearray(128)
    value[:2] = b"MZ"
    value[60:64] = (64).to_bytes(4, "little")
    value[64:68] = b"PE\0\0"
    value[68:70] = machine.to_bytes(2, "little")
    value[70 : 70 + len(label)] = label.encode("ascii")
    return bytes(value)


def isolated_build_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    for name in (
        "LICENSE",
        "MANIFEST.in",
        "NOTICE",
        "README.md",
        "THIRD_PARTY_LICENSES.txt",
        "defenseclaw_build_backend.py",
        "pyproject.toml",
        "setup.py",
    ):
        shutil.copy2(ROOT / name, source / name)
    for name in ("bundles", "cli", "release", "schemas", "scripts", "third_party"):
        shutil.copytree(
            ROOT / name,
            source / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules"),
        )
    registry = source / "internal" / "envvars" / "registry.json"
    registry.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "internal" / "envvars" / "registry.json", registry)
    editable_sgw = source / "cli" / "defenseclaw" / "_data" / "sgw"
    shutil.rmtree(editable_sgw, ignore_errors=True)
    stage_sgw_modules.stage(
        argparse.Namespace(
            root=source,
            destination=editable_sgw,
            artifact_dir=source / "missing-sgw-artifacts",
            runtime_manifest=source / "release" / "s-gw-runners.json",
            require_all=False,
        )
    )
    return source


def fake_release(tmp_path: Path) -> tuple[Path, Path]:
    runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    private_key = configure_signing(runtime)
    source_root = tmp_path / "components"
    artifact_dir = tmp_path / "artifacts"
    source_root.mkdir()
    artifact_dir.mkdir()

    ui_root = tmp_path / "console-ui"
    (ui_root / "assets").mkdir(parents=True)
    (ui_root / "index.html").write_text("<main>pending enrollments</main>\n", encoding="utf-8")
    write_json(
        ui_root / "capabilities.json",
        {
            "schema_version": 1,
            "capabilities": [
                "defenseclaw.pending-enrollment.v1",
                "defenseclaw.approval-console-session.v1",
            ],
        },
    )
    (ui_root / "assets" / "app.js").write_text("console.log('approval');\n", encoding="utf-8")
    ui_archive = source_root / "s-gw-console-ui.tar.gz"
    with tarfile.open(ui_archive, "w:gz") as archive:
        archive.add(ui_root, arcname="console-ui")

    for target in TARGETS:
        records = runtime["targets"][target]["components"]
        runner_source = source_root / f"{target}-runner"
        runner_source.write_bytes(native_payload(target, "runner"))
        runner_source.chmod(0o755)
        helper_source = source_root / f"{target}-helper"
        if target.startswith("win32-"):
            helper_source.write_text("Write-Output 'credential helper'\n", encoding="utf-8")
        else:
            helper_source.write_bytes(native_payload(target, "helper"))
            helper_source.chmod(0o755)
        license_source = source_root / f"{target}-THIRD_PARTY_LICENSES.txt"
        license_source.write_bytes(
            (
                f"{stage_sgw_modules.SGW_CORE_LICENSE_BEGIN}\n"
                f"{CORE_LICENSE_TERMS}\n"
                f"{stage_sgw_modules.SGW_CORE_LICENSE_END}\n"
                f"s-gw dependency licenses for {target}\n"
            ).encode(),
        )
        sources = {
            "runner": runner_source,
            "credential_helper": helper_source,
            "approval_ui": ui_archive,
            "license_bundle": license_source,
        }
        for name, source in sources.items():
            records[name]["path"] = str(source)
            records[name]["sha256"] = digest(source)
        write_module_artifact(artifact_dir, module, runtime, target, sources, private_key)

    runtime_path = tmp_path / "approved-runtimes.json"
    write_json(runtime_path, runtime)
    return runtime_path, artifact_dir


def write_module_artifact(
    artifact_dir: Path,
    module: dict,
    runtime: dict,
    target: str,
    sources: dict[str, Path],
    private_key: Ed25519PrivateKey,
) -> None:
    package = artifact_dir / f"package-{target}"
    (package / "dist").mkdir(parents=True)
    (package / "dist" / "console-ui" / "assets").mkdir(parents=True)
    (package / "package.json").write_text('{"name":"@s-gw/s-gw","version":"0.2.0"}\n', encoding="utf-8")
    (package / "dist" / "cli.js").write_text("export {};\n", encoding="utf-8")
    (package / "dist" / "mcp-server.js").write_text("export {};\n", encoding="utf-8")
    (package / "dist" / "console-ui" / "index.html").write_text(
        "<main>pending enrollments</main>\n",
        encoding="utf-8",
    )
    write_json(
        package / "dist" / "console-ui" / "capabilities.json",
        {
            "schema_version": 1,
            "capabilities": [
                "defenseclaw.pending-enrollment.v1",
                "defenseclaw.approval-console-session.v1",
            ],
        },
    )
    (package / "dist" / "console-ui" / "assets" / "app.js").write_text(
        "console.log('approval');\n",
        encoding="utf-8",
    )

    records = runtime["targets"][target]["components"]
    runner_destination = PurePosixPath(records["runner"]["destination"])
    helper_destination = PurePosixPath(records["credential_helper"]["destination"])
    runner = package.joinpath(*runner_destination.parts)
    helper = package.joinpath(*helper_destination.parts)
    license_destination = PurePosixPath(records["license_bundle"]["destination"])
    licenses = package.joinpath(*license_destination.parts)
    runner.parent.mkdir(parents=True, exist_ok=True)
    helper.parent.mkdir(parents=True, exist_ok=True)
    runner.write_bytes(sources["runner"].read_bytes())
    helper.write_bytes(sources["credential_helper"].read_bytes())
    licenses.write_bytes(sources["license_bundle"].read_bytes())
    runner.chmod(0o755)
    if records["credential_helper"]["executable"]:
        helper.chmod(0o755)

    file_paths = sorted(item.relative_to(package).as_posix() for item in package.rglob("*") if item.is_file())
    files = {relative: digest(package / relative) for relative in file_paths}
    component_files = {
        "runner": [runner_destination.as_posix()],
        "credential_helper": [helper_destination.as_posix()],
        "approval_ui": [
            "dist/console-ui/assets/app.js",
            "dist/console-ui/capabilities.json",
            "dist/console-ui/index.html",
        ],
        "license_bundle": [license_destination.as_posix()],
    }
    for name, installed_files in component_files.items():
        record = records[name]
        installed_sha256 = sgw_module.component_inventory_sha256(
            {relative: files[relative] for relative in installed_files}
        )
        record["installed_sha256"] = installed_sha256
        record["signature"] = signature(
            private_key,
            sgw_module.component_signature_payload(
                target,
                name,
                record["destination"],
                record["sha256"],
                installed_sha256,
            ),
        )
    module_installed_sha256 = sgw_module.module_inventory_sha256(files)
    target_record = runtime["targets"][target]
    admission = launch_admission(target)
    admission_sha256 = sgw_module.runner_launch_admission_sha256(target, admission)
    target_record["runner_launch_admission"] = admission
    target_record["module_installed_sha256"] = module_installed_sha256
    target_record["module_signature"] = signature(
        private_key,
        sgw_module.module_signature_payload(
            target,
            module,
            module_installed_sha256,
            admission_sha256,
            sgw_module.runner_contract_sha256(),
        ),
    )
    components = {
        "runner": {
            "artifact_sha256": records["runner"]["sha256"],
            "installed_sha256": records["runner"]["installed_sha256"],
            "signature": records["runner"]["signature"],
            "destination": runner_destination.as_posix(),
            "files": component_files["runner"],
        },
        "credential_helper": {
            "artifact_sha256": records["credential_helper"]["sha256"],
            "installed_sha256": records["credential_helper"]["installed_sha256"],
            "signature": records["credential_helper"]["signature"],
            "destination": helper_destination.as_posix(),
            "files": component_files["credential_helper"],
        },
        "approval_ui": {
            "artifact_sha256": records["approval_ui"]["sha256"],
            "installed_sha256": records["approval_ui"]["installed_sha256"],
            "signature": records["approval_ui"]["signature"],
            "destination": "dist/console-ui",
            "files": component_files["approval_ui"],
        },
        "license_bundle": {
            "artifact_sha256": records["license_bundle"]["sha256"],
            "installed_sha256": records["license_bundle"]["installed_sha256"],
            "signature": records["license_bundle"]["signature"],
            "destination": license_destination.as_posix(),
            "files": component_files["license_bundle"],
        },
    }
    metadata = {
        "schema_version": 1,
        "package_name": module["package_name"],
        "package_version": module["package_version"],
        "upstream_revision": module["upstream_revision"],
        "upstream_tree": module["upstream_tree"],
        "minimum_node_version": module["minimum_node_version"],
        "build_toolchain": module["build_toolchain"],
        "target": target,
        "production_ready": True,
        "inventory_excludes": ["defenseclaw-module.json"],
        "signature_policy": {
            "algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM,
            "public_key_sha256": runtime["signature_policy"]["public_key_sha256"],
        },
        "runner_contract": sgw_module.RUNNER_CONTRACT,
        "runner_contract_sha256": sgw_module.runner_contract_sha256(),
        "runner_launch_admission": admission,
        "runner_launch_admission_sha256": admission_sha256,
        "module_installed_sha256": module_installed_sha256,
        "module_signature": target_record["module_signature"],
        "components": components,
        "runner": {
            "path": runner_destination.as_posix(),
            "sha256": files[runner_destination.as_posix()],
            "signature": records["runner"]["signature"],
        },
        "files": files,
    }
    write_json(package / "defenseclaw-module.json", metadata)
    filename = module["artifact"]["filename_template"].format(target=target)
    artifact = artifact_dir / filename
    with tarfile.open(artifact, "w:gz") as archive:
        archive.add(package, arcname="package")
    artifact.with_suffix(artifact.suffix + ".sha256").write_text(
        f"{digest(artifact)}  {artifact.name}\n",
        encoding="ascii",
    )


def stage_args(
    tmp_path: Path,
    *,
    runtime: Path = RUNTIME_MANIFEST,
    artifact_dir: Path | None = None,
    require_all: bool = False,
) -> argparse.Namespace:
    return argparse.Namespace(
        root=ROOT,
        destination=tmp_path / "staged",
        artifact_dir=artifact_dir or tmp_path / "missing-artifacts",
        runtime_manifest=runtime,
        require_all=require_all,
    )


def test_source_stage_omits_production_modules_and_fails_closed(tmp_path: Path) -> None:
    args = stage_args(tmp_path)
    result = stage_sgw_modules.stage(args)

    assert result["production_modules"] is False
    assert {item.name for item in args.destination.iterdir()} == {
        "sgw_module.py",
        "s-gw-module.json",
        "s-gw-runners.json",
    }
    license_output = tmp_path / "NOTICE"
    source_notice = (ROOT / "NOTICE").read_bytes()
    license_output.write_bytes(source_notice)
    contract = stage_sgw_modules.materialize_wheel_license_metadata(
        argparse.Namespace(
            staged_root=args.destination,
            output=license_output,
            base_notice=ROOT / "NOTICE",
        )
    )
    assert contract == {
        "schema_version": 1,
        "production_modules": False,
        "license_expression": "Apache-2.0",
        "license_file": None,
        "license_sha256": None,
    }
    assert license_output.read_bytes() == source_notice

    before = {item.name: item.read_bytes() for item in args.destination.iterdir()}
    args.require_all = True
    with pytest.raises(stage_sgw_modules.DeliveryError, match="all six"):
        stage_sgw_modules.stage(args)
    assert {item.name: item.read_bytes() for item in args.destination.iterdir()} == before


def test_wheel_and_release_entrypoints_use_the_authenticated_stager() -> None:
    setup_source = (ROOT / "setup.py").read_text(encoding="utf-8")
    package_config = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    source_manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    release_workflow = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")

    assert 'root / "scripts" / "stage_sgw_modules.py"' in setup_source
    assert '"_data/sgw/modules/*/*.tar.gz"' in package_config
    assert '"_data/sgw/modules/*/*.sha256"' in package_config
    assert "prune cli/defenseclaw/_data/sgw" in source_manifest
    assert "scripts/stage_sgw_modules.py stage" in makefile
    assert "darwin-x64 darwin-arm64 linux-x64 linux-arm64 win32-x64 win32-arm64" in release_workflow
    assert "DEFENSECLAW_REQUIRE_SGW_MODULES=1" in release_workflow
    assert "scripts/stage_sgw_modules.py verify-wheel" in release_workflow


def test_source_quickstart_explicitly_opts_out_without_staged_modules() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    install_docs = (ROOT / "docs-site" / "content" / "docs" / "get-started" / "install.mdx").read_text(encoding="utf-8")

    assert "SOURCE_CREDENTIAL_PROTECTION ?= 0" in makefile
    assert '0) credential_flag="--no-credential-protection"' in makefile
    assert '1) credential_flag="--credential-protection"' in makefile
    assert '"$$credential_flag"' in makefile
    assert "defenseclaw init --no-credential-protection" in install_docs
    assert "make all SOURCE_CREDENTIAL_PROTECTION=1" in install_docs

    enabled = subprocess.run(
        [
            "make",
            "-n",
            "_bundle-data",
            "SOURCE_CREDENTIAL_PROTECTION=1",
            "SGW_REQUIRE_MODULES=0",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert enabled.returncode == 0, enabled.stdout + enabled.stderr
    assert 'DEFENSECLAW_REQUIRE_SGW_MODULES="1"' in enabled.stdout

    for contradiction in (
        "SGW_REQUIRE_MODULES=0",
        "DEFENSECLAW_REQUIRE_SGW_MODULES=0",
        "SGW_REQUIRE_MODULES_EFFECTIVE=0",
    ):
        database = subprocess.run(
            [
                "make",
                "-pn",
                "_source-credential-protection-preflight",
                "SOURCE_CREDENTIAL_PROTECTION=1",
                contradiction,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert database.returncode == 0, database.stdout + database.stderr
        lines = set(database.stdout.splitlines())
        assert "SGW_REQUIRE_MODULES_EFFECTIVE := 1" in lines
        assert "DEFENSECLAW_REQUIRE_SGW_MODULES := 1" in lines

        child_env = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "-s",
                "-f",
                "Makefile",
                "-f",
                "-",
                "SOURCE_CREDENTIAL_PROTECTION=1",
                contradiction,
                "print-sgw-child-env",
            ],
            cwd=ROOT,
            input=("print-sgw-child-env:\n\t@printf '%s\\n' \"$${DEFENSECLAW_REQUIRE_SGW_MODULES}\"\n"),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert child_env.returncode == 0, child_env.stdout + child_env.stderr
        assert child_env.stdout.strip() == "1"

    invalid = subprocess.run(
        ["make", "_source-credential-protection-preflight", "SOURCE_CREDENTIAL_PROTECTION=invalid"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert invalid.returncode != 0
    assert "SOURCE_CREDENTIAL_PROTECTION must be 0 or 1" in invalid.stderr


def test_pep517_build_dependencies_pin_signature_verification() -> None:
    package_config = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    source_manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert 'requires = ["setuptools==82.0.1", "cryptography==48.0.1"]' in package_config
    assert 'build-backend = "defenseclaw_build_backend"' in package_config
    assert 'backend-path = ["."]' in package_config
    assert "include defenseclaw_build_backend.py" in source_manifest


def test_vendor_inventory_binds_each_file_to_its_git_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    source_root = ROOT / manifest["source_path"]
    inventory = json.loads((ROOT / manifest["source_inventory"]).read_text(encoding="utf-8"))
    assert inventory["schema_version"] == 2
    for record in inventory["files"]:
        value = (source_root / record["path"]).read_bytes()
        assert sync_sgw_vendor.git_blob_oid(value) == record["git_blob"]

    copied_source = tmp_path / "upstream"
    copied_inventory = tmp_path / "SOURCE_MANIFEST.json"
    shutil.copytree(source_root, copied_source)
    write_json(copied_inventory, inventory)

    monkeypatch.setattr(sync_sgw_vendor, "module_manifest", lambda: manifest)

    def checked_path(_relative: object, *, label: str) -> Path:
        return copied_source if label == "source_path" else copied_inventory

    monkeypatch.setattr(sync_sgw_vendor, "checked_repo_path", checked_path)
    assert sync_sgw_vendor.verify() == 0

    inventory["files"][0]["git_blob"] = "0" * 40
    write_json(copied_inventory, inventory)
    with pytest.raises(sync_sgw_vendor.VendorError, match="Git blob identity mismatch"):
        sync_sgw_vendor.verify()


def test_sgw_checkout_contract_uses_git_modes_and_exact_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source.ts"
    source.write_text("export {};\n", encoding="utf-8")

    if os.name != "nt":
        source.chmod(0o644)
        assert sync_sgw_vendor.checkout_mode(source, platform_name="posix") == 0o644
    assert sync_sgw_vendor.checkout_mode(source, platform_name="nt") is None

    attributes = set((ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines())
    assert {
        "LICENSE text eol=lf",
        "NOTICE text eol=lf",
        "third_party/s-gw/upstream/** -text",
        "third_party/s-gw/patches/*.patch -text -whitespace",
    }.issubset(attributes)


def test_isolated_pep517_sdist_excludes_staged_modules_and_wheel_restages_them(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    if importlib.util.find_spec("build.__main__") is None:
        pytest.fail("the locked build frontend is unavailable")

    tmp_path = tmp_path_factory.mktemp("p")
    runtime, artifact_dir = fake_release(tmp_path)
    source = isolated_build_source(tmp_path)

    staged = source / "cli" / "defenseclaw" / "_data" / "sgw" / "modules" / "linux-x64"
    staged.mkdir(parents=True, exist_ok=True)
    (staged / "must-not-enter-sdist.bin").write_bytes(b"proprietary runtime marker")

    sdist_output = tmp_path / "sdist"
    sdist_result = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(sdist_output), str(source)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": ""},
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert sdist_result.returncode == 0, sdist_result.stdout + sdist_result.stderr
    sdists = list(sdist_output.glob("defenseclaw-*.tar.gz"))
    assert len(sdists) == 1
    with tarfile.open(sdists[0], "r:gz") as archive:
        members = archive.getnames()
        assert not any("/cli/defenseclaw/_data/sgw/" in name for name in members)
        assert not any(name.endswith("/s-gw-core.txt") for name in members)
        assert any(name.endswith("/scripts/sgw_module.py") for name in members)
        assert any(name.endswith("/defenseclaw_build_backend.py") for name in members)
        assert any(name.endswith("/third_party/s-gw/upstream/docs/ui/THIRD_PARTY_NOTICES.md") for name in members)
        package_metadata = [name for name in members if name.endswith("/PKG-INFO")]
        assert package_metadata
        for metadata_name in package_metadata:
            sdist_metadata = BytesParser(policy=policy.default).parsebytes(archive.extractfile(metadata_name).read())
            assert sdist_metadata.get_all("License-Expression") == ["Apache-2.0"]
            assert "license-expression" in [value.lower() for value in sdist_metadata.get_all("Dynamic", [])]
            assert sorted(sdist_metadata.get_all("License-File", [])) == stage_sgw_modules.WHEEL_LICENSE_FILES
        notice_members = [name for name in members if name.count("/") == 1 and name.endswith("/NOTICE")]
        assert len(notice_members) == 1
        assert archive.extractfile(notice_members[0]).read() == (ROOT / "NOTICE").read_bytes()
        unpacked = tmp_path / "u"
        if hasattr(tarfile, "data_filter"):
            archive.extractall(unpacked, filter="data")
        else:
            archive.extractall(unpacked)
    roots = [item for item in unpacked.iterdir() if item.is_dir()]
    assert len(roots) == 1

    source_output = tmp_path / "source-wheel"
    source_env = {**os.environ, "PYTHONPATH": ""}
    source_env.pop("DEFENSECLAW_REQUIRE_SGW_MODULES", None)
    source_env.pop("DEFENSECLAW_SGW_ARTIFACT_DIR", None)
    source_env.pop("DEFENSECLAW_SGW_RUNTIME_MANIFEST", None)
    source_result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(source_output), str(roots[0])],
        cwd=tmp_path,
        env=source_env,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert source_result.returncode == 0, source_result.stdout + source_result.stderr
    source_wheels = list(source_output.glob("defenseclaw-*.whl"))
    assert len(source_wheels) == 1
    with zipfile.ZipFile(source_wheels[0]) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1
        source_metadata = BytesParser(policy=policy.default).parsebytes(archive.read(metadata_names[0]))
        assert source_metadata.get_all("License-Expression") == ["Apache-2.0"]
        assert source_metadata.get_all("License") is None
        source_dynamic = [value.lower() for value in source_metadata.get_all("Dynamic", [])]
        assert "license-expression" in source_dynamic
        assert "license-file" in source_dynamic
        assert sorted(source_metadata.get_all("License-File", [])) == stage_sgw_modules.WHEEL_LICENSE_FILES
        dist_info = PurePosixPath(metadata_names[0]).parent
        assert archive.read(f"{dist_info}/licenses/NOTICE") == (ROOT / "NOTICE").read_bytes()
        assert archive.read(f"{dist_info}/licenses/THIRD_PARTY_LICENSES.txt") == (
            ROOT / "THIRD_PARTY_LICENSES.txt"
        ).read_bytes()

    output = tmp_path / "wheel"
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(output), str(roots[0])],
        cwd=tmp_path,
        env={
            **os.environ,
            "DEFENSECLAW_REQUIRE_SGW_MODULES": "1",
            "DEFENSECLAW_SGW_ARTIFACT_DIR": str(artifact_dir),
            "DEFENSECLAW_SGW_RUNTIME_MANIFEST": str(runtime),
            "PYTHONPATH": "",
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    wheels = list(output.glob("defenseclaw-*.whl"))
    assert len(wheels) == 1
    verified = stage_sgw_modules.verify_wheel(argparse.Namespace(wheel=wheels[0]))
    assert set(verified["targets"]) == set(TARGETS)
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1
        metadata = BytesParser(policy=policy.default).parsebytes(archive.read(metadata_names[0]))
        assert metadata.get_all("License-Expression") == [stage_sgw_modules.SGW_MIXED_LICENSE]
        assert metadata.get_all("License") is None
        dynamic = [value.lower() for value in metadata.get_all("Dynamic", [])]
        assert "license-expression" in dynamic
        assert "license-file" in dynamic
        assert sorted(metadata.get_all("License-File", [])) == stage_sgw_modules.WHEEL_LICENSE_FILES
        dist_info = PurePosixPath(metadata_names[0]).parent
        notice = archive.read(f"{dist_info}/licenses/NOTICE")
        assert notice.startswith((ROOT / "NOTICE").read_bytes())
        assert notice == stage_sgw_modules.production_notice((ROOT / "NOTICE").read_bytes(), CORE_LICENSE_TERMS)
        assert archive.read(f"{dist_info}/licenses/THIRD_PARTY_LICENSES.txt") == (
            ROOT / "THIRD_PARTY_LICENSES.txt"
        ).read_bytes()


def test_prepared_metadata_matches_source_production_and_editable_wheels(tmp_path: Path) -> None:
    runtime, artifact_dir = fake_release(tmp_path)
    source = isolated_build_source(tmp_path)
    source_notice = (ROOT / "NOTICE").read_bytes()
    production_notice = stage_sgw_modules.production_notice(source_notice, CORE_LICENSE_TERMS)

    def runner(overrides: dict[str, str]):
        def run(command: list[str], cwd: str | None, extra_environ: dict[str, str]) -> None:
            env = {**os.environ, **extra_environ, "PYTHONPATH": ""}
            for name in (
                "DEFENSECLAW_REQUIRE_SGW_MODULES",
                "DEFENSECLAW_SGW_ARTIFACT_DIR",
                "DEFENSECLAW_SGW_RUNTIME_MANIFEST",
            ):
                env.pop(name, None)
            env.update(overrides)
            result = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stdout + result.stderr)

        return run

    source_env: dict[str, str] = {}
    production_env = {
        "DEFENSECLAW_REQUIRE_SGW_MODULES": "1",
        "DEFENSECLAW_SGW_ARTIFACT_DIR": str(artifact_dir),
        "DEFENSECLAW_SGW_RUNTIME_MANIFEST": str(runtime),
    }
    editable_sgw = source / "cli" / "defenseclaw" / "_data" / "sgw"

    def editable_files() -> dict[str, bytes]:
        if not editable_sgw.is_dir() or editable_sgw.is_symlink():
            return {}
        return {
            path.relative_to(editable_sgw).as_posix(): path.read_bytes()
            for path in editable_sgw.rglob("*")
            if path.is_file()
        }

    with DefaultIsolatedEnv() as build_env:
        source_builder = build.ProjectBuilder(
            source,
            python_executable=build_env.python_executable,
            runner=runner(source_env),
        )
        build_env.install(source_builder.build_system_requires)
        build_env.install(source_builder.get_requires_for_build("wheel"))
        build_env.install(source_builder.get_requires_for_build("editable"))

        prepared_modes: dict[str, Path] = {}
        builders: dict[str, build.ProjectBuilder] = {}
        for label, overrides, expected_expression, expected_notice in (
            ("source", source_env, "Apache-2.0", source_notice),
            ("production", production_env, stage_sgw_modules.SGW_MIXED_LICENSE, production_notice),
        ):
            shutil.rmtree(source / "build", ignore_errors=True)
            builder = build.ProjectBuilder(
                source,
                python_executable=build_env.python_executable,
                runner=runner(overrides),
            )
            metadata_root = tmp_path / f"{label}-metadata"
            metadata_root.mkdir()
            prepared = Path(builder.metadata_path(metadata_root))
            prepared_modes[label] = prepared
            builders[label] = builder
            prepared_files = {
                path.relative_to(prepared).as_posix(): path.read_bytes()
                for path in prepared.rglob("*")
                if path.is_file()
            }
            prepared_metadata = BytesParser(policy=policy.default).parsebytes(prepared_files["METADATA"])
            assert prepared_metadata.get_all("License-Expression") == [expected_expression]
            assert prepared_files["licenses/NOTICE"] == expected_notice

            wheel_root = tmp_path / f"{label}-prepared-wheel"
            wheel_root.mkdir()
            wheel = Path(builder.build("wheel", wheel_root, metadata_directory=str(prepared)))
            with zipfile.ZipFile(wheel) as archive:
                for relative, payload in prepared_files.items():
                    assert archive.read(f"{prepared.name}/{relative}") == payload

            if label == "production":
                stage_sgw_modules._validate_wheel_license_metadata(
                    wheel,
                    version="0.8.6",
                    core_terms=CORE_LICENSE_TERMS,
                )

        for desired_mode, prepared_mode in (("production", "source"), ("source", "production")):
            output = tmp_path / f"{desired_mode}-from-{prepared_mode}-metadata"
            output.mkdir()
            with pytest.raises(build.BuildBackendException):
                builders[desired_mode].build(
                    "wheel",
                    output,
                    metadata_directory=str(prepared_modes[prepared_mode]),
                )

        prepared_editable_modes: dict[str, Path] = {}
        prepared_editable_files: dict[str, dict[str, bytes]] = {}
        for label, expected_expression, expected_notice in (
            ("source", "Apache-2.0", source_notice),
            ("production", stage_sgw_modules.SGW_MIXED_LICENSE, production_notice),
        ):
            shutil.rmtree(editable_sgw, ignore_errors=True)
            shutil.rmtree(source / "build", ignore_errors=True)
            metadata_root = tmp_path / f"{label}-editable-metadata"
            metadata_root.mkdir()
            prepared_result = builders[label].prepare("editable", metadata_root)
            assert prepared_result is not None
            assert not editable_sgw.exists()
            prepared = Path(prepared_result)
            prepared_editable_modes[label] = prepared
            prepared_files = {
                path.relative_to(prepared).as_posix(): path.read_bytes()
                for path in prepared.rglob("*")
                if path.is_file()
            }
            prepared_editable_files[label] = prepared_files
            metadata = BytesParser(policy=policy.default).parsebytes(prepared_files["METADATA"])
            assert metadata.get_all("License-Expression") == [expected_expression]
            assert prepared_files["licenses/NOTICE"] == expected_notice

            output = tmp_path / f"{label}-prepared-editable"
            output.mkdir()
            editable = Path(
                builders[label].build(
                    "editable",
                    output,
                    metadata_directory=str(prepared),
                )
            )
            assert editable_sgw.is_dir()
            with zipfile.ZipFile(editable) as archive:
                for relative, payload in prepared_files.items():
                    assert archive.read(f"{prepared.name}/{relative}") == payload
            for relative, payload in prepared_files.items():
                assert (prepared / relative).read_bytes() == payload
            if label == "production":
                stage_sgw_modules._validate_wheel_license_metadata(
                    editable,
                    version="0.8.6",
                    core_terms=CORE_LICENSE_TERMS,
                )

        for desired_mode, prepared_mode in (("production", "source"), ("source", "production")):
            shutil.rmtree(editable_sgw, ignore_errors=True)
            output = tmp_path / f"{desired_mode}-editable-from-{prepared_mode}-metadata"
            output.mkdir()
            with pytest.raises(build.BuildBackendException):
                builders[desired_mode].build(
                    "editable",
                    output,
                    metadata_directory=str(prepared_editable_modes[prepared_mode]),
                )
            assert not editable_sgw.exists()
            for relative, payload in prepared_editable_files[prepared_mode].items():
                assert (prepared_editable_modes[prepared_mode] / relative).read_bytes() == payload

        invalid_metadata = tmp_path / "missing-editable.dist-info"
        invalid_output = tmp_path / "invalid-prepared-editable"
        invalid_output.mkdir()
        shutil.rmtree(editable_sgw, ignore_errors=True)
        with pytest.raises(build.BuildBackendException, match="editable .dist-info directory is unavailable"):
            builders["source"].build(
                "editable",
                invalid_output,
                metadata_directory=str(invalid_metadata),
            )
        assert not editable_sgw.exists()

        shutil.rmtree(editable_sgw, ignore_errors=True)
        editable_root = tmp_path / "source-editable"
        editable_root.mkdir()
        source_builder = build.ProjectBuilder(
            source,
            python_executable=build_env.python_executable,
            runner=runner(source_env),
        )
        editable = Path(source_builder.build("editable", editable_root))
        with zipfile.ZipFile(editable) as archive:
            metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            editable_metadata = BytesParser(policy=policy.default).parsebytes(archive.read(metadata_name))
            assert editable_metadata.get_all("License-Expression") == ["Apache-2.0"]
            dist_info = PurePosixPath(metadata_name).parent
            assert archive.read(f"{dist_info}/licenses/NOTICE") == source_notice
        assert set(editable_files()) == {
            "s-gw-module.json",
            "s-gw-runners.json",
            "sgw_module.py",
        }

        production_editable = build.ProjectBuilder(
            source,
            python_executable=build_env.python_executable,
            runner=runner(production_env),
        )
        shutil.rmtree(editable_sgw, ignore_errors=True)
        production_editable_root = tmp_path / "production-editable"
        production_editable_root.mkdir()
        editable = Path(production_editable.build("editable", production_editable_root))
        stage_sgw_modules._validate_wheel_license_metadata(
            editable,
            version="0.8.6",
            core_terms=CORE_LICENSE_TERMS,
        )
        editable_contract = stage_sgw_modules.staged_wheel_license_contract(editable_sgw)
        assert editable_contract == (stage_sgw_modules.SGW_MIXED_LICENSE, CORE_LICENSE_TERMS)

        stale_source_root = tmp_path / "source-editable-with-production-runtime"
        stale_source_root.mkdir()
        stale_files = editable_files()
        with pytest.raises(
            build.BuildBackendException,
            match="editable s-gw runtime differs from authenticated staging",
        ):
            source_builder.build("editable", stale_source_root)
        assert editable_files() == stale_files

        tampered_files = (
            editable_sgw / "sgw_module.py",
            editable_sgw / "s-gw-module.json",
            editable_sgw / "modules" / "linux-x64" / "s-gw-module.tar.gz",
        )
        for index, path in enumerate(tampered_files):
            original = path.read_bytes()
            assert original
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            output = tmp_path / f"production-editable-tampered-{index}"
            output.mkdir()
            try:
                with pytest.raises(
                    build.BuildBackendException,
                    match="editable s-gw runtime differs from authenticated staging",
                ):
                    production_editable.build("editable", output)
                assert path.read_bytes() != original
            finally:
                path.write_bytes(original)

        shutil.rmtree(editable_sgw, ignore_errors=True)
        outside = tmp_path / "outside-editable-sgw"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("unchanged\n", encoding="utf-8")
        try:
            editable_sgw.parent.mkdir(parents=True, exist_ok=True)
            editable_sgw.symlink_to(outside, target_is_directory=True)
        except OSError:
            pass
        else:
            unsafe_output = tmp_path / "unsafe-editable-sgw"
            unsafe_output.mkdir()
            with pytest.raises(build.BuildBackendException, match="editable s-gw runtime path is unsafe"):
                source_builder.build("editable", unsafe_output)
            assert editable_sgw.is_symlink()
            assert list(outside.iterdir()) == [sentinel]
            assert sentinel.read_text(encoding="utf-8") == "unchanged\n"
            editable_sgw.unlink()


def test_release_checks_use_locked_cryptography_environment() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")
    preflight = workflow.index("- name: Install locked s-gw verification dependencies")
    preflight_check = workflow.index(".venv/bin/python scripts/build_sgw_module.py", preflight)
    runtime_setup = workflow.index("- name: Install locked runtime build dependencies")
    runtime_build = workflow.index(".venv/bin/python scripts/build_sgw_module.py", runtime_setup)

    assert "uv sync --locked --no-dev" in workflow[preflight:preflight_check]
    assert "uv sync --locked --no-dev" in workflow[runtime_setup:runtime_build]
    assert "python3 scripts/build_sgw_module.py" not in workflow


def test_release_pins_sgw_node_toolchain_immediately_before_build() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")
    pin = workflow.index("- name: Pin the reviewed s-gw build toolchain")
    build = workflow.index("- name: Build stamped CLI, plugin, and upgrade policy", pin)
    pinned_step = workflow[pin:build]

    assert 'node-version: "24.18.1"' in pinned_step
    assert "third_party/s-gw/upstream/package-lock.json" in pinned_step
    assert workflow[pin:build].count("- name:") == 1


def test_partial_artifact_set_does_not_touch_destination(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "partial"
    artifact_dir.mkdir()
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    artifact = artifact_dir / module["artifact"]["filename_template"].format(target=TARGETS[0])
    artifact.write_bytes(b"not a module")
    artifact.with_suffix(artifact.suffix + ".sha256").write_text("0" * 64 + "  " + artifact.name + "\n")
    args = stage_args(tmp_path, artifact_dir=artifact_dir)
    args.destination.mkdir()
    marker = args.destination / "keep.txt"
    marker.write_text("unchanged\n", encoding="utf-8")

    with pytest.raises(stage_sgw_modules.DeliveryError, match="partial"):
        stage_sgw_modules.stage(args)
    assert marker.read_text(encoding="utf-8") == "unchanged\n"


def test_full_artifact_set_is_sanitized_staged_and_verified_in_wheel(tmp_path: Path) -> None:
    runtime, artifact_dir = fake_release(tmp_path)
    args = stage_args(tmp_path, runtime=runtime, artifact_dir=artifact_dir, require_all=True)
    result = stage_sgw_modules.stage(args)

    assert set(result["targets"]) == set(TARGETS)
    staged_runtime = json.loads((args.destination / "s-gw-runners.json").read_text(encoding="utf-8"))
    assert all(
        component["path"] is None
        for record in staged_runtime["targets"].values()
        for component in record["components"].values()
    )
    for target in TARGETS:
        artifact = args.destination / "modules" / target / "s-gw-module.tar.gz"
        assert artifact.is_file()
        assert digest(artifact) == result["targets"][target]

    license_output = tmp_path / "NOTICE"
    license_output.write_bytes((ROOT / "NOTICE").read_bytes())
    contract = stage_sgw_modules.materialize_wheel_license_metadata(
        argparse.Namespace(
            staged_root=args.destination,
            output=license_output,
            base_notice=ROOT / "NOTICE",
        )
    )
    assert contract["production_modules"] is True
    assert contract["license_expression"] == stage_sgw_modules.SGW_MIXED_LICENSE
    assert contract["license_file"] == "NOTICE"
    assert contract["license_sha256"] == digest(license_output)
    assert license_output.read_bytes() == stage_sgw_modules.production_notice(
        (ROOT / "NOTICE").read_bytes(), CORE_LICENSE_TERMS
    )

    wheel = tmp_path / "defenseclaw-test.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in sorted(args.destination.rglob("*")):
            if item.is_file():
                archive.write(item, f"defenseclaw/_data/sgw/{item.relative_to(args.destination).as_posix()}")
    verified = stage_sgw_modules.verify_wheel(argparse.Namespace(wheel=wheel))
    assert verified["targets"] == result["targets"]


def test_production_notice_enforces_shared_output_limit() -> None:
    prefix = "License rights are granted by this fixture. "
    terms = prefix + "x" * (stage_sgw_modules.MAX_CORE_LICENSE_BYTES - len(prefix.encode("utf-8")))
    framing = (
        b"\n"
        + stage_sgw_modules.SGW_CORE_LICENSE_BEGIN.encode("ascii")
        + b"\n"
        + terms.encode("utf-8")
        + b"\n"
        + stage_sgw_modules.SGW_CORE_LICENSE_END.encode("ascii")
        + b"\n"
    )
    base_size = stage_sgw_modules.MAX_WHEEL_NOTICE_BYTES - len(framing)
    assert 0 < base_size < stage_sgw_modules.MAX_SOURCE_LICENSE_BYTES
    base_notice = b"N" * (base_size - 1) + b"\n"

    payload = stage_sgw_modules.production_notice(base_notice, terms)
    assert len(payload) == stage_sgw_modules.MAX_WHEEL_NOTICE_BYTES

    with pytest.raises(stage_sgw_modules.DeliveryError, match="production wheel NOTICE has an invalid size"):
        stage_sgw_modules.production_notice(b"N" * base_size + b"\n", terms)


def test_tampered_artifact_checksum_is_rejected_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, artifact_dir = fake_release(tmp_path)
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    target = TARGETS[-1]
    artifact = artifact_dir / module["artifact"]["filename_template"].format(target=target)
    artifact.write_bytes(artifact.read_bytes() + b"tampered")

    def unexpected_archive_validation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("checksums must be validated before any module archive")

    monkeypatch.setattr(stage_sgw_modules, "validate_module_archive", unexpected_archive_validation)
    args = stage_args(tmp_path, runtime=runtime, artifact_dir=artifact_dir, require_all=True)
    args.destination.mkdir()
    marker = args.destination / "keep.txt"
    marker.write_text("unchanged\n", encoding="utf-8")

    with pytest.raises(stage_sgw_modules.DeliveryError, match="checksum does not match"):
        stage_sgw_modules.stage(args)
    assert marker.read_text(encoding="utf-8") == "unchanged\n"
