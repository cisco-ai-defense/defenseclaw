# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Prepare only exact reviewed fixed-canary artifacts; never execute images."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[5] / "internal/axis/native"))
from artifact_archive import ZipEvidence, json_object, ordinary, sha  # noqa: E402
from verify_native_artifact import manifest as peer_manifest  # noqa: E402
from verify_native_artifact import record_matches, static_elf

REPOSITORY = "cisco-ai-defense/defenseclaw"
RECEIPT_SHA = "6db10d2a73ee7860bb0d7ad8a6155166d2b59e7d504513e1222a634aac55c668"
# Independently reviewed source/build/image inputs; no caller or API chooses a
# pin. This source recipe needs its own review and explicit run authorization.
DRIVER_PROVENANCE_SHA = "1c0a98c32b475b967670e335acaf81c442083eae4a8b43197b531b3315b45e05"
PINS = {
    "peer": {
        "commit": "c914cb9a66d3e05a11d5eac4dcf4da7a8c0de139",
        "run": 39158759518,
        "artifact": 12148605722,
        "archive": "68e5d232ed286cfbbbbcb212170cc6bf0aff4536cfbc98fb7129da1315a99085",
        "provenance": "7d6fd05f40006e334921fa4efec58a033b3c2bbaf707d7be03b6322bc81ac59c",
        "workflow": ".github/workflows/axis-native-peer-build.yml",
        "stem": "axis-private-native-peer-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "push",
    },
    "payload": {
        "commit": "6a1f7080a39fbdfa39b98f3ea7db02516910dc3d",
        "run": 39171740021,
        "artifact": 12152816365,
        "archive": "f27e44a36ff6d2349dff1ad38909f279ca027d429e85cb03a04b77322feb92db",
        "provenance": "70979ab492b883e5c6c9d0c583477b9f1cb999b6d14fdc6a89ad356aa8134dae",
        "workflow": ".github/workflows/axis-native-payload-build.yml",
        "stem": "axis-fixed-native-payload-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "workflow_dispatch",
    },
    "wrapper": {
        "commit": "c76a05c3df66f43e76c6566b53aa2b3c1c7bca0b",
        "run": 39172460882,
        "artifact": 12153515281,
        "archive": "ce84ed94fce099b59bea6b0593f23d7e845c3734ab1e62ea9f794fb38faa6e68",
        "provenance": "d84f37d59f7830eda86de0bd562acbb85a0ddb2d7c8e42132f019c0f4a434b60",
        "workflow": ".github/workflows/axis-native-harness-build.yml",
        "stem": "axis-reviewed-native-harness-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "workflow_dispatch",
    },
    "driver": {
        "commit": "c63c08b86de46981f85d29e9d43add02bfea5b2c",
        "run": 39173104546,
        "artifact": 12153496454,
        "archive": "83b916e71464d25a2470986ce8f9f60ff0e3bfb8e0e0df5b52d7827a25adfa7f",
        "workflow": ".github/workflows/axis-native-driver-build.yml",
        "stem": "axis-fixed-native-outer-driver-linux-",
        "branch": "codex/axis-sandbox-feasibility",
        "event": "push",
    },
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(argv, bound=128 << 20):
    # Trusted host GH only. This read-only Actions token remains in host metadata
    # processes and is never placed in prepared images or the driver's env.
    env = {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "SYSTEMROOT",
            "WINDIR",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "GH_TOKEN",
            "GITHUB_TOKEN",
        )
        if key in os.environ
    }
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    captured, failed = {}, threading.Event()

    def drain(label, stream, limit):
        try:
            captured[label] = stream.read(limit + 1)
            if len(captured[label]) > limit:
                failed.set()
        except Exception:
            failed.set()

    readers = [
        threading.Thread(target=drain, args=(label, stream, limit), daemon=True)
        for label, stream, limit in [("stdout", process.stdout, bound), ("stderr", process.stderr, 64 << 10)]
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + 60
    try:
        while process.poll() is None and not failed.is_set() and time.monotonic() < deadline:
            failed.wait(0.01)
        require(time.monotonic() < deadline, "metadata operation deadline")
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
            raise ValueError("metadata output bound")
        for reader in readers:
            reader.join(timeout=2)
        require(
            not failed.is_set() and all(not reader.is_alive() for reader in readers) and process.returncode == 0,
            "metadata operation refused",
        )
        return captured["stdout"]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for reader, stream in zip(readers, (process.stdout, process.stderr), strict=True):
            if not reader.is_alive():
                stream.close()


def api(path):
    return json_object(command(["gh", "api", f"repos/{REPOSITORY}/{path}"], 1 << 20))


def mapping(value, key):
    result = value.get(key)
    require(isinstance(result, dict), "metadata object differs")
    return result


def check_actions(pin, run, artifact):
    require(
        run.get("id") == pin["run"] and run.get("run_attempt") == 1 and run.get("head_sha") == pin["commit"],
        "run identity differs",
    )
    require(
        mapping(run, "repository").get("full_name") == REPOSITORY
        and mapping(run, "head_repository").get("full_name") == REPOSITORY,
        "foreign source",
    )
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success" and run.get("path") == pin["workflow"],
        "build did not succeed",
    )
    require(run.get("head_branch") == pin["branch"] and run.get("event") == pin["event"], "build route differs")
    require(
        artifact.get("id") == pin["artifact"]
        and artifact.get("expired") is False
        and artifact.get("digest") == "sha256:" + pin["archive"],
        "artifact identity differs",
    )
    require(artifact.get("name") == pin["stem"] + pin["commit"], "artifact name differs")
    require(
        mapping(artifact, "workflow_run").get("id") == pin["run"]
        and mapping(artifact, "workflow_run").get("head_sha") == pin["commit"],
        "artifact source differs",
    )
    require(
        type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= 128 << 20,
        "artifact size differs",
    )


def flat_manifest(archive, pin):
    raw = archive.read("PROVENANCE.json")
    require(sha(raw) == pin["provenance"], "external provenance pin differs")
    value = json_object(raw)
    require(
        value.get("repository") == REPOSITORY
        and value.get("workflow") == pin["workflow"]
        and value.get("build_commit") == pin["commit"]
        and value.get("run_id") == pin["run"]
        and value.get("run_attempt") == 1,
        "provenance run differs",
    )
    files = value.get("files")
    require(
        isinstance(files, dict) and set(archive.files) == set(files) | {"PROVENANCE.json"},
        "complete file manifest differs",
    )
    for name, record in files.items():
        record_matches(archive.read(name), record)
    return raw


def select(archive, member, digest, size=None):
    raw = archive.read(member)
    require(sha(raw) == digest and (size is None or len(raw) == size), "fixed member differs")
    return raw


def prepare(root, metadata_api=api, download=None):
    require(
        isinstance(DRIVER_PROVENANCE_SHA, str) and re.fullmatch("[0-9a-f]{64}", DRIVER_PROVENANCE_SHA),
        "driver artifact admission is closed",
    )
    require(download is not None, "fixed download primitive required")
    receipt = ordinary(Path(__file__).with_name("REVIEWED-ARTIFACTS.json"), 64 << 10)
    require(sha(receipt) == RECEIPT_SHA, "combined receipt source differs")
    root.mkdir(mode=0o700)
    evidence = root / "preparation-evidence"
    evidence.mkdir(mode=0o700)
    images, proofs, source = root / "images", root / "proofs", root / "source"
    for directory in (images, proofs, source):
        directory.mkdir(mode=0o700)
    (root / "REVIEWED-ARTIFACTS.json").write_bytes(receipt)
    archives = {}
    for role, original in PINS.items():
        pin = dict(original)
        if role == "driver":
            pin["provenance"] = DRIVER_PROVENANCE_SHA
        run, artifact = (
            metadata_api(f"actions/runs/{pin['run']}/attempts/1"),
            metadata_api(f"actions/artifacts/{pin['artifact']}"),
        )
        check_actions(pin, run, artifact)
        raw = download(pin["artifact"])
        require(len(raw) == artifact["size_in_bytes"] and sha(raw) == pin["archive"], "archive bytes differ")
        archive = ZipEvidence(raw)
        if role == "peer":
            peer_manifest(archive, pin["provenance"])
        else:
            flat_manifest(archive, pin)
        for label, value in [("run", run), ("artifact", artifact)]:
            (evidence / (role + "-" + label + ".json")).write_text(json.dumps(value, indent=2) + "\n")
        archives[role] = archive
    members = [
        (
            "peer",
            "build-artifact/bin/defenseclaw-axis-peer",
            images / "peer",
            "274717415360304d4ff14096faa13cc98fcf7eaba5409dcd1c800350d4048665",
            2722752,
        ),
        (
            "peer",
            "build-artifact/static/bwrap-static-musl-repeat-a",
            images / "bwrap-static-musl",
            "b4d1a59426c6a52e9f9a0d57d03d620e4dfc1beef976201a3afc0c1b492ee37d",
            198584,
        ),
        (
            "payload",
            "bin/payload",
            images / "fixed-payload",
            "3990927d43320f78586fc669c1a700ecf4c7c8359ba6ada3e41ccd56d4e78e9d",
            1929342,
        ),
        (
            "wrapper",
            "bin/reviewed-harness",
            images / "reviewed-wrapper",
            "485aa37bf8fda4aa35f41247c802931fd73decfac28eda60ed8ea44577f63e87",
            3473534,
        ),
        (
            "driver",
            "bin/fixed-outer-driver",
            images / "fixed-driver",
            "0f7ef1d91cd6a95d09b93341ca0cd59628d1c1346538002f554e0477cef23d60",
            3211390,
        ),
    ]
    for role, member, target, digest, size in members:
        raw = select(archives[role], member, digest, size)
        if role != "peer" or target.name == "bwrap-static-musl":
            static_elf(raw)
        target.write_bytes(raw)
        target.chmod(0o500)
    for role, member, target, digest in [
        (
            "peer",
            "build-artifact/static/STATIC-CLOSURE.json",
            proofs / "STATIC-CLOSURE.json",
            "e6ce4df2d0118cfa0b1a26f554e4dcbd039d1fa3b77ad0d7628d5a3d1ba9665b",
        ),
        ("peer", "build-artifact/PROVENANCE.json", proofs / "peer-PROVENANCE.json", PINS["peer"]["provenance"]),
        ("payload", "PROVENANCE.json", proofs / "payload-PROVENANCE.json", PINS["payload"]["provenance"]),
        (
            "payload",
            "source/test/e2e/axis/native-peer/payload/main_linux.go",
            source / "payload-main_linux.go",
            "aa695d4df73865cce90afd8dab41c819949a6f8dec66b9fe1a641be035df815e",
        ),
    ]:
        target.write_bytes(select(archives[role], member, digest))
    for role in ("wrapper", "driver"):
        (evidence / (role + "-PROVENANCE.json")).write_bytes(archives[role].read("PROVENANCE.json"))
    record = {
        "scope": "fixed_linux_native_peer_input_preparation",
        "execution_performed": False,
        "production_certification": False,
        "full_upstream_review_repeated": False,
        "admission_basis": "exact_previously_dual_reviewed_archive_and_provenance_pins",
        "receipt_sha256": RECEIPT_SHA,
        "images": {
            path.name: {"sha256": sha(ordinary(path)), "size": path.stat().st_size} for path in sorted(images.iterdir())
        },
    }
    (evidence / "PREPARATION.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    require(
        os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "fixed disposable CI preparation only",
    )
    if sys.argv[1:] == ["--collect-fixed-evidence"]:
        collect()
        return
    require(len(sys.argv) == 1, "fixed preparation selector only")
    prepare(
        Path("live-inputs"),
        download=lambda artifact: command(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact}/zip"]),
    )


def collect():
    evidence = Path("live-evidence")
    evidence.mkdir(mode=0o700, exist_ok=True)
    record = {
        "scope": "fixed_linux_native_peer_evidence_collection",
        "fixture_copied": False,
        "production_certification": False,
    }
    try:
        result = json_object(ordinary(evidence / "DRIVER-RESULT.json", 1 << 20))
        require(
            result.get("scope") == "fixed_linux_native_peer_outer_driver_v1"
            and result.get("whole_wrapper_namespace_cleanup_observed") is True
            and result.get("pending_driver_cleanup") == 0,
            "whole-wrapper cleanup not observed",
        )
        nested = result.get("wrapper_record")
        if not isinstance(nested, dict):
            raw = result.get("wrapper_stdout", "")
            require(isinstance(raw, str) and len(raw.encode()) <= 64 << 10, "fixed raw wrapper output differs")
            nested = json_object(raw.encode())
        require(
            nested.get("scope") == "fixed_linux_native_peer_offline_contributor_v1"
            and nested.get("production_certification") is False,
            "fixed nested result differs",
        )
        fixture = nested.get("synthetic_fixture")
        if fixture is None:
            return
        require(nested.get("artifact_receipt_sha256") == RECEIPT_SHA, "fixed nested receipt differs")
        require(
            isinstance(fixture, str) and re.fullmatch("/tmp/dc-axis-native-peer-[0-9a-f]{32}", fixture),
            "fixed fixture identity differs",
        )
        root = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(root)
            require(
                metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700, "fixture ownership differs"
            )
            destination = evidence / "synthetic-fixture"
            destination.mkdir(mode=0o700)
            budget = [0, 0]
            copy_fixture(root, destination, 0, budget)
            record["fixture_copied"], record["members"], record["bytes"] = True, budget[0], budget[1]
        finally:
            os.close(root)
    except (ValueError, OSError):
        record["error"] = "fixed_failure_evidence_not_fully_copied"
    finally:
        (evidence / "COLLECTION.json").write_text(json.dumps(record, indent=2) + "\n")


TREE_FILES = frozenset(
    f"tree-{role}.{suffix}" for role in ("parent", "child", "grandchild") for suffix in ("ready", "heartbeat")
)


def fixture_member_name(name, relative):
    # Dot-containing names belong only to these six fixed public work files.
    return bool(re.fullmatch("[a-z0-9-]{1,64}", name)) or relative == ("work",) and name in TREE_FILES


def copy_fixture(parent, destination, depth, budget, relative=()):
    require(depth <= 3, "fixture depth bound")
    names = os.listdir(parent)
    require(len(names) <= 32, "fixture member bound")
    for name in sorted(names):
        require(fixture_member_name(name, relative), "fixture member name differs")
        budget[0] += 1
        require(budget[0] <= 32, "fixture total member bound")
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            metadata = os.fstat(child)
            require(metadata.st_uid == os.geteuid(), "fixture member owner differs")
            target = destination / name
            if stat.S_ISDIR(metadata.st_mode):
                require(name not in TREE_FILES, "fixed tree evidence must be a regular file")
                target.mkdir(mode=0o700)
                copy_fixture(child, target, depth + 1, budget, (*relative, name))
            else:
                require(
                    stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= 64 << 10,
                    "fixture file type or size differs",
                )
                with os.fdopen(os.dup(child), "rb") as stream:
                    raw = stream.read((64 << 10) + 1)
                require(len(raw) == metadata.st_size, "fixture file changed")
                budget[1] += len(raw)
                require(budget[1] <= 1 << 20, "fixture total byte bound")
                target.write_bytes(raw)
                target.chmod(0o600)
        finally:
            os.close(child)


if __name__ == "__main__":
    main()
