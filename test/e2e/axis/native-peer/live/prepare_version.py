# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Prepare only the separately reviewed real-version inputs; never run images."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

import prepare as fixed
from artifact_archive import ZipEvidence, json_object, ordinary, sha

RECEIPT_SHA = "e24ee1736320e9df281e0ab7049b2df8cbacbf27d81d31fc46e21cef09b165b7"
SCOPE = "fixed_linux_native_claude_2_1_292_version_only_v1"
LOADER_SHA = "76b812138a1d4be51ae095e94920e1fd1c5d25f793651baf834d05a2c455c040"
LOADER_SIZE = 853616
LOADER_LEAF = "claude-runtime-loader"
VENDOR_SHA = "d23f28ef84f5459a25d2d4cf999a7debd41df83507160446983d4ca65554e50f"
VENDOR_SIZE = 245203032
# Independently reviewed fixed artifact identities. No CLI/env override or
# caller-selected artifact, receipt or image identity.
PINS = {
    "peer": dict(fixed.PINS["peer"]),
    "loader": {
        "commit": "0ad2618803ecd69a7a1df782c70f38b699d74d13",
        "run": 39193900521,
        "artifact": 12161286875,
        "archive": "4001eaf9cf2321ba9d695fe49d53168192f9d6b4649d715c1f88c12242da8060",
        "provenance": "f533f74bfff81d5cf36b7f6975a7a41d06ccbcc97be114ba09c2835b821bcf41",
        "workflow": ".github/workflows/axis-native-claude-loader-build.yml",
        "stem": "axis-fixed-shared-musl-loader-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "workflow_dispatch",
    },
    "wrapper": {
        "commit": "f9d907144b2adb97d33a3e5a8c8a89b22629ded1",
        "run": 39199601189,
        "artifact": 12162799813,
        "archive": "acfe0492ecf2c2670aab32af1411d722fc1ffa4758eedf2e44809fb33c1dd0d3",
        "provenance": "3b63059284ac539d0c903adc613759e4cc428ef501640a2b595a156fc176b191",
        "workflow": ".github/workflows/axis-native-harness-build.yml",
        "stem": "axis-reviewed-native-harness-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "workflow_dispatch",
    },
    "driver": {
        "commit": "e01a8838c43b06f02103c5bde65f32462895f34f",
        "run": 39200076588,
        "artifact": 12163566207,
        "archive": "ea184cd5a84397bbe6d2306d24eccf5f5d2ace172189f4af59179cbc8e49d69a",
        "provenance": "031f646cb5d45a7c2bf311218d0681350aee28603d1bd0405e19a4c12f73c8de",
        "workflow": ".github/workflows/axis-native-driver-build.yml",
        "stem": "axis-fixed-native-outer-driver-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "push",
    },
}
WRAPPER_IMAGE = {"sha256": "1493e1678ed0533a7a6fa81aa8bd04a0bad667aac43cbb10f3caec8f82d8c208", "size": 3510398}
DRIVER_IMAGE = {"sha256": "31345e92f7e5ce7468cf78a81f04d8b4c3c400d86e6612c3388e877735955fa3", "size": 3244158}


def inspector():
    path = Path(__file__).resolve().parent.parent / "claude/inspect_artifact.py"
    spec = importlib.util.spec_from_file_location("fixed_official_claude_inspector", path)
    fixed.require(spec is not None and spec.loader is not None, "reviewed inspector unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admission():
    for role in ("peer", "loader", "wrapper", "driver"):
        pin = PINS[role]
        fixed.require(
            isinstance(pin, dict)
            and all(re.fullmatch("[0-9a-f]{64}", pin.get(key, "")) for key in ("archive", "provenance"))
            and re.fullmatch("[0-9a-f]{40}", pin.get("commit", ""))
            and type(pin.get("run")) is int
            and pin["run"] > 0
            and type(pin.get("artifact")) is int
            and pin["artifact"] > 0,
            "separate version artifact admission is closed",
        )
    for image in (WRAPPER_IMAGE, DRIVER_IMAGE):
        fixed.require(
            isinstance(image, dict)
            and set(image) == {"sha256", "size"}
            and re.fullmatch("[0-9a-f]{64}", image["sha256"])
            and type(image["size"]) is int
            and 64 <= image["size"] <= 32 << 20,
            "separate version image admission is closed",
        )


def loader_manifest(archive, pin):
    raw = archive.read("PROVENANCE.json")
    fixed.require(sha(raw) == pin["provenance"], "loader provenance differs")
    value = json_object(raw)
    fixed.require(
        value.get("repository") == fixed.REPOSITORY
        and value.get("workflow") == pin["workflow"]
        and value.get("build_commit") == pin["commit"]
        and value.get("run_id") == str(pin["run"])
        and value.get("run_attempt") == "1"
        and value.get("scope") == "fixed_shared_musl_1_2_6_loader_build_only"
        and value.get("build_succeeded") is True
        and all(
            value.get(k) is False
            for k in ("loader_or_vendor_execution", "runtime_admission", "production_certification")
        ),
        "loader build identity differs",
    )
    files = value.get("files")
    fixed.require(
        isinstance(files, dict) and set(archive.files) == set(files) | {"PROVENANCE.json"}, "loader manifest differs"
    )
    for name, record in files.items():
        fixed.record_matches(archive.read(name), record)
    return raw


def reacquire_vendor(root, receipt, download=None, run_tool=None):
    """Exact official URLs/signature, with host tools only and no vendor exec."""
    review = receipt["claude_version"]
    module = inspector()
    download = module.download if download is None else download
    run_tool = module.tool if run_tool is None else run_tool
    source, evidence = root / "source", root / "preparation-evidence"
    home = root / "private-signature-verification"
    home.mkdir(mode=0o700)
    for url, name, expected, limit in (
        (module.MANIFEST, "claude-manifest.json", review["manifest_sha256"], 1 << 20),
        (module.SIGNATURE, "claude-manifest.json.sig", review["signature_sha256"], 64 << 10),
        (module.KEY, "claude-release-key.asc", review["key_sha256"], 128 << 10),
    ):
        info = download(url, source / name, limit)
        fixed.require(
            info["sha256"] == expected and sha(ordinary(source / name, limit)) == expected,
            "reviewed release metadata differs",
        )
    gpg = [
        "/usr/bin/gpg",
        "--no-options",
        "--homedir",
        str(home.resolve()),
        "--batch",
        "--no-tty",
        "--no-autostart",
        "--no-auto-key-retrieve",
        "--no-auto-key-import",
        "--disable-dirmngr",
    ]
    key, manifest, signature = (
        source / name for name in ("claude-release-key.asc", "claude-manifest.json", "claude-manifest.json.sig")
    )
    code, out, err = run_tool(
        gpg + ["--with-colons", "--fingerprint", "--show-keys", str(key.resolve())], home, 256 << 10
    )
    fixed.require(
        code == 0 and module.key_fingerprint(out) == review["signer_fingerprint"], "reviewed release key differs"
    )
    code, out, err = run_tool(
        gpg + ["--import-options", "import-minimal", "--import", str(key.resolve())], home, 256 << 10
    )
    fixed.require(code == 0, "reviewed release key import refused")
    code, out, err = run_tool(
        gpg + ["--status-fd", "1", "--verify", str(signature.resolve()), str(manifest.resolve())], home, 256 << 10
    )
    fixed.require(
        code == 0 and module.valid_signature(out)["primary_fingerprint"] == review["signer_fingerprint"],
        "reviewed release signature differs",
    )
    (evidence / "claude-signature-status.txt").write_bytes(out)  # public GPG status only
    published = module.manifest_checksums(ordinary(manifest, 1 << 20))["linux-x64-musl"]
    fixed.require(
        published is not None and published["sha256"] == VENDOR_SHA and published["size"] in (None, VENDOR_SIZE),
        "signed fixed musl release differs",
    )
    fixed.require(
        review["version"] == "2.1.292"
        and review["platform"] == "linux-x64-musl"
        and review["url"] == module.BASE + "/linux-x64-musl/claude",
        "fixed vendor selector differs",
    )
    info = download(review["url"], root / "images/claude-musl", VENDOR_SIZE)
    fixed.require(info["sha256"] == VENDOR_SHA and info["size"] == VENDOR_SIZE, "fixed vendor bytes differ")
    headers = module.elf_headers(root / "images/claude-musl")
    fixed.require(
        headers["type"] == "ET_EXEC"
        and headers["pt_interp"] == "/lib/ld-musl-x86_64.so.1"
        and headers["writable_executable_load"] is False,
        "fixed vendor ELF differs",
    )
    (root / "images/claude-musl").chmod(0o500)
    license_info = download(module.LICENSE, evidence / "CLAUDE-LICENSE.md", 128 << 10)
    fixed.require(
        license_info["sha256"] == "728158fd1037143fad6907e8fa34804177e598b7326519503fe83cafdef849e6",
        "fixed vendor license differs",
    )


def prepare(root, metadata_api=fixed.api, download=None, vendor=None):
    admission()  # before paths, API, directories, downloads or tool startup
    fixed.require(download is not None, "fixed Actions download required")
    raw_receipt = ordinary(Path(__file__).with_name("REVIEWED-CLAUDE-VERSION.json"), 64 << 10)
    fixed.require(sha(raw_receipt) == RECEIPT_SHA, "fixed version receipt differs")
    receipt = json_object(raw_receipt)
    fixed.require(receipt["scope"] == SCOPE, "fixed version receipt scope differs")
    root.mkdir(mode=0o700)
    for name in ("images", "proofs", "source", "preparation-evidence"):
        (root / name).mkdir(mode=0o700)
    (root / "REVIEWED-ARTIFACTS.json").write_bytes(raw_receipt)
    archives = {}
    for role, pin in PINS.items():
        run, artifact = (
            metadata_api(f"actions/runs/{pin['run']}/attempts/1"),
            metadata_api(f"actions/artifacts/{pin['artifact']}"),
        )
        fixed.check_actions(pin, run, artifact)
        raw = download(pin["artifact"])
        fixed.require(
            len(raw) == artifact["size_in_bytes"] and sha(raw) == pin["archive"], "fixed version archive differs"
        )
        archive = ZipEvidence(raw)
        if role == "peer":
            fixed.peer_manifest(archive, pin["provenance"])
        elif role == "loader":
            loader_manifest(archive, pin)
        else:
            fixed.flat_manifest(archive, pin)
        archives[role] = archive
        provenance_member = "build-artifact/PROVENANCE.json" if role == "peer" else "PROVENANCE.json"
        (root / "preparation-evidence" / f"{role}-PROVENANCE.json").write_bytes(archive.read(provenance_member))
        for label, value in (("run", run), ("artifact", artifact)):
            (root / "preparation-evidence" / f"{role}-{label}.json").write_text(json.dumps(value, indent=2) + "\n")
    members = [
        ("peer", "build-artifact/bin/defenseclaw-axis-peer", receipt["images"][0], False),
        ("peer", "build-artifact/static/bwrap-static-musl-repeat-a", receipt["images"][1], True),
        ("loader", "musl-loader-repeat-a", receipt["loader"], False),
        ("wrapper", "bin/reviewed-harness", {"path": "images/reviewed-wrapper", **WRAPPER_IMAGE}, True),
        ("driver", "bin/fixed-outer-driver", {"path": "images/fixed-driver", **DRIVER_IMAGE}, True),
    ]
    for role, member, identity, static in members:
        data = fixed.select(archives[role], member, identity["sha256"], identity["size"])
        if static:
            fixed.static_elf(data)
        path = root / identity["path"]
        path.write_bytes(data)
        path.chmod(0o500)
    for role, member, path, digest in (
        (
            "peer",
            "build-artifact/static/STATIC-CLOSURE.json",
            "proofs/STATIC-CLOSURE.json",
            receipt["static_closure_sha256"],
        ),
        ("peer", "build-artifact/PROVENANCE.json", "proofs/peer-PROVENANCE.json", PINS["peer"]["provenance"]),
        ("loader", "LOADER-CLOSURE.json", "proofs/LOADER-CLOSURE.json", receipt["loader_closure_sha256"]),
        ("loader", "PROVENANCE.json", "proofs/loader-PROVENANCE.json", PINS["loader"]["provenance"]),
    ):
        (root / path).write_bytes(fixed.select(archives[role], member, digest))
    (vendor or reacquire_vendor)(root, receipt)
    record = {
        "scope": "fixed_real_claude_version_input_preparation",
        "receipt_sha256": RECEIPT_SHA,
        "execution_performed": False,
        "production_certification": False,
        "full_runtime_or_dlopen_closure_established": False,
    }
    (root / "preparation-evidence/PREPARATION.json").write_text(json.dumps(record, indent=2) + "\n")


def stable_metadata(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def verify_excluded_loader(fd, registered):
    fixed.require(
        isinstance(registered, dict) and set(registered) == {"leaf", "device", "inode", "size", "sha256"},
        "registered loader shape differs",
    )
    fixed.require(
        registered["leaf"] == LOADER_LEAF
        and type(registered["size"]) is int
        and registered["size"] == LOADER_SIZE
        and registered["sha256"] == LOADER_SHA
        and all(type(registered[k]) is int and registered[k] > 0 for k in ("device", "inode")),
        "registered loader identity differs",
    )
    before = os.fstat(fd)
    fixed.require(
        stat.S_ISREG(before.st_mode)
        and stat.S_IMODE(before.st_mode) == 0o500
        and before.st_uid == os.geteuid()
        and before.st_nlink == 1
        and before.st_size == LOADER_SIZE
        and (before.st_dev, before.st_ino) == (registered["device"], registered["inode"]),
        "retained loader object differs",
    )
    hashed, offset = hashlib.sha256(), 0
    while offset < LOADER_SIZE:
        data = os.pread(fd, min(64 << 10, LOADER_SIZE - offset), offset)
        fixed.require(bool(data), "retained loader truncated")
        hashed.update(data)
        offset += len(data)
    fixed.require(
        hashed.hexdigest() == LOADER_SHA and stable_metadata(before) == stable_metadata(os.fstat(fd)),
        "retained loader changed",
    )


def copy_fixture(parent, destination, depth, budget, registered, held_loader, relative=()):
    fixed.require(depth <= 3, "fixture depth bound")
    names = os.listdir(parent)
    fixed.require(len(names) <= 32, "fixture member bound")
    for name in sorted(names):
        fixed.require(fixed.fixture_member_name(name, relative), "fixture name differs")
        budget[0] += 1
        fixed.require(budget[0] <= 32, "fixture total member bound")
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            metadata = os.fstat(child)
            fixed.require(metadata.st_uid == os.geteuid(), "fixture member owner differs")
            if relative == () and name == LOADER_LEAF:
                verify_excluded_loader(child, registered)
                fixed.require(
                    stable_metadata(os.fstat(child)) == stable_metadata(os.fstat(held_loader)),
                    "registered loader entry replaced",
                )
                continue  # never copy loader bytes into the evidence artifact
            target = destination / name
            if stat.S_ISDIR(metadata.st_mode):
                fixed.require(name not in fixed.TREE_FILES, "fixed tree evidence must be a regular file")
                target.mkdir(mode=0o700)
                copy_fixture(child, target, depth + 1, budget, registered, held_loader, (*relative, name))
            else:
                fixed.require(
                    stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= 64 << 10,
                    "fixture file type or size differs",
                )
                raw = os.pread(child, (64 << 10) + 1, 0)
                fixed.require(
                    len(raw) == metadata.st_size and stable_metadata(metadata) == stable_metadata(os.fstat(child)),
                    "fixture file changed",
                )
                budget[1] += len(raw)
                fixed.require(budget[1] <= 1 << 20, "fixture total byte bound")
                target.write_bytes(raw)
                target.chmod(0o600)
        finally:
            os.close(child)


def collect():
    evidence = Path("live-evidence")
    evidence.mkdir(mode=0o700, exist_ok=True)
    record = {
        "scope": "fixed_real_claude_version_evidence_collection",
        "fixture_copied": False,
        "production_certification": False,
    }
    try:
        result = json_object(ordinary(evidence / "DRIVER-RESULT.json", 1 << 20))
        fixed.require(
            result.get("scope") == "fixed_linux_native_peer_outer_driver_v1"
            and result.get("fixed_suite") == "claude-version"
            and result.get("production_certification") is False
            and result.get("whole_wrapper_namespace_cleanup_observed") is True
            and type(result.get("pending_driver_cleanup")) is int
            and result.get("pending_driver_cleanup") == 0
            and type(result.get("pending_driver_loader_resources")) is int
            and result.get("pending_driver_loader_resources") == 0,
            "version whole-wrapper cleanup unavailable",
        )
        nested = result.get("wrapper_record")
        if not isinstance(nested, dict):
            raw = result.get("wrapper_stdout", "")
            fixed.require(isinstance(raw, str) and len(raw.encode()) <= 64 << 10, "version wrapper output differs")
            nested = json_object(raw.encode())
        fixed.require(
            nested.get("scope") == SCOPE
            and nested.get("fixed_suite") == "claude-version"
            and nested.get("artifact_receipt_sha256") == RECEIPT_SHA
            and nested.get("production_certification") is False
            and nested.get("common_launch_gate_qualified") is False
            and nested.get("outer_namespace_cleanup_observed") is True
            and all(
                type(nested.get(k)) is int and nested.get(k) == 0
                for k in (
                    "pending_native_cleanup",
                    "pending_outer_cleanup",
                    "pending_version_resources",
                    "pending_outer_loader_resources",
                )
            ),
            "version native cleanup unavailable",
        )
        fixture = nested.get("synthetic_fixture")
        fixed.require(
            isinstance(fixture, str) and re.fullmatch("/tmp/dc-axis-native-peer-[0-9a-f]{32}", fixture),
            "version fixture identity differs",
        )
        root = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(root)
            fixed.require(
                metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
                "version fixture owner differs",
            )
            loader = os.open(LOADER_LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=root)
            try:
                registered = result.get("retained_loader")
                verify_excluded_loader(loader, registered)
                target = evidence / "synthetic-fixture"
                target.mkdir(mode=0o700)
                budget = [0, 0]
                copy_fixture(root, target, 0, budget, registered, loader)
                verify_excluded_loader(loader, registered)
                record.update(fixture_copied=True, members=budget[0], bytes=budget[1], excluded_loader=registered)
            finally:
                os.close(loader)
        finally:
            os.close(root)
    except (ValueError, OSError):
        record["error"] = "fixed_version_evidence_not_fully_copied"
    finally:
        (evidence / "COLLECTION.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    fixed.require(
        os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "fixed disposable CI only",
    )
    if sys.argv[1:] == ["--collect-fixed-evidence"]:
        collect()
        return
    fixed.require(len(sys.argv) == 1, "fixed version preparation selector only")
    prepare(
        Path("live-inputs"),
        download=lambda artifact: fixed.command(
            ["gh", "api", f"repos/{fixed.REPOSITORY}/actions/artifacts/{artifact}/zip"]
        ),
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print("fixed version input preparation refused")
        raise SystemExit(1)
