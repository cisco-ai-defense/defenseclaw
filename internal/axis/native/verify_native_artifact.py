#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Inert peer build-evidence review. Never authorizes or executes a sandbox."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import struct
import subprocess
import threading
import time
from pathlib import Path, PurePosixPath

from artifact_archive import (
    FILE_LIMIT,
    DecodeBudget,
    LzmaReader,
    ZipEvidence,
    deb_data,
    json_object,
    ordinary,
    path_name,
    sha,
    tar_files,
)

REPOSITORY = "cisco-ai-defense/defenseclaw"
WORKFLOW = ".github/workflows/axis-native-peer-build.yml"
AXIS = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
BWRAP = "8e51677abd7e3338e4952370bf7d902e37d8cbb6"
LOCK = "9fb53262adf9c0b9ec3fb434dd04a5fe17572d6a522b4b5e3fb31cd2c6bef325"
SEED = "d6556677c6decd2d5d786ca082ac2bcdb37fc92130d45b7002a7e8bffe2154db"
PEER_TEST_COUNT = 19
PATCHES = {
    "patches/axis-offline-bpf.patch": "914b75d4ad1da26f4f9850886093fb3560ade14d9870dd604de20a33d2f179f2",
    "patches/mxc-owned-bubblewrap.patch": "422aff2de2719878e6fe10a6c097153c58dc3f58d3fa53ee97b2b1d1ea43d5e8",
    "patches/bwrap-owned-fds.patch": "1563032b5bfbd74b56214119f1287de3a7e63c9054898b58c6cd9603948dd621",
    "mxc-literal-argv.patch": "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d",
}
# Windows-only inputs remain source evidence; Linux neither applies this
# overlay nor derives compiled unit roots from these explicitly listed files.
WINDOWS_SOURCE = {
    "WINDOWS.md",
    "prepare_windows_build.py",
    "src/windows.rs",
    "src/windows_bootstrap.rs",
    "src/windows_io.rs",
    "src/windows_transport.rs",
    "patches/mxc-owned-windows-psec.patch",
}
SOURCES = {
    "Cargo.toml",
    "Cargo.lock",
    "README.md",
    "prepare_build.py",
    "test_prepare_build.py",
    "src/lib.rs",
    "src/main.rs",
    "src/namespace.rs",
    "src/conversation.rs",
    "src/custody.rs",
    "src/linux.rs",
    "src/owner.rs",
    "src/transport.rs",
    "src/wire.rs",
    "patches/README.md",
    "patches/bwrap-COPYING",
    "patches/bwrap-owned-fd-tests.c",
    "static/README.md",
    "static/sources.json",
    "static/build_static.py",
    "static/test_build_static.py",
    "static/musl-LICENSE",
    "static/libcap-LICENSE",
    "reviewed-linux-seed.lock",
} | set(PATCHES) | WINDOWS_SOURCE
C_TESTS = [
    "topology_refuses_nested_bind_mounts_and_malformed_inventory",
    "locator_refuses_deleted_traversal_and_unrepresentable_names",
    "cloned_view_uses_reopened_mount_id_and_still_refuses_nested_aliases",
    "immutable_copy_preserves_seals_size_and_every_byte",
    "readonly_root_is_nonrecursive_and_source_noexec_is_preserved",
]
DEPENDENCIES = {
    "axis": {
        "lock": "788c5b5ea12b19176969d495f53d2c97a8e056d035832ec529ffc042fd97f3b2",
        "tests": [
            "linux::seccomp::tests::private_offline_export_denies_every_socket_without_installing_filter",
            "linux::seccomp::tests::private_offline_export_keeps_explicit_blocked_syscalls_and_refuses_unknown",
        ],
    },
    "mxc": {
        "lock": "2d145ff3861cd19d1f50969083f8ac59e4d4fd50b030bef12f365a5fcc87afa0",
        "tests": [
            "owned_bubblewrap::tests::filter_copy_starts_at_zero_and_ignores_caller_offset_changes",
            "owned_bubblewrap::tests::fixed_image_uses_verified_copy_route_without_path_or_legacy_data_options",
            "owned_bubblewrap::tests::guest_destinations_refuse_alias_components_and_synthetic_roots",
            "owned_bubblewrap::tests::static_structure_refuses_interpreter_dynamic_and_mutable_images",
        ],
    },
}


def require(value, message="evidence does not match reviewed contract"):
    if not value:
        raise ValueError(message)


def digest_argument(value):
    require(re.fullmatch(r"[0-9a-f]{64}", value) is not None, "an exact lowercase SHA256 is required")
    return value


def command(argv, *, cwd=None, bound=8 << 20):
    # Only trusted host Git/GH are invoked, never archive/build/runtime images.
    env = {
        name: os.environ[name]
        for name in ("SYSTEMROOT", "WINDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PATH")
        if name in os.environ
    }
    process = subprocess.Popen(
        argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
    )
    captured, failed = {}, threading.Event()

    def read(label, stream):
        try:
            raw = stream.read(bound + 1)
            if len(raw) > bound:
                failed.set()
            captured[label] = raw
        except Exception:
            failed.set()

    readers = [
        threading.Thread(target=read, args=(label, stream), daemon=True)
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + 60
    try:
        while process.poll() is None and not failed.is_set() and time.monotonic() < deadline:
            failed.wait(0.01)
        require(time.monotonic() < deadline, "host metadata operation reached its deadline")
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
            raise ValueError("host metadata operation exceeded its bound")
        for reader in readers:
            reader.join(timeout=2)
        require(not any(reader.is_alive() for reader in readers), "host metadata pipe did not close")
        require(not failed.is_set() and process.returncode == 0, "trusted host metadata operation refused")
        return captured["stdout"]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        # A timed-out synchronous reader can hold a buffered IO lock. Never
        # close its stream synchronously; fail and leave it to process teardown.
        for reader, stream in zip(readers, (process.stdout, process.stderr), strict=True):
            if not reader.is_alive():
                stream.close()


def git(root: Path, *args):
    return command(["git", "--no-replace-objects", "-c", "core.autocrlf=false", "-C", str(root), *args])


def blob(root: Path, commit: str, name: str):
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None)
    path_name(name)
    return git(root, "cat-file", "blob", f"{commit}:{name}")


def api(path: str):
    return json_object(command(["gh", "api", f"repos/{REPOSITORY}/{path}"]))


def actions(options):
    run = api(f"actions/runs/{options.run}/attempts/{options.attempt}")
    artifact = api(f"actions/artifacts/{options.artifact}")
    require(type(run.get("id")) is int and type(run.get("run_attempt")) is int)
    require(run.get("id") == options.run and run.get("run_attempt") == options.attempt)
    require(run.get("repository", {}).get("full_name") == REPOSITORY)
    require(run.get("head_repository", {}).get("full_name") == REPOSITORY)
    require(run.get("head_sha") == options.commit and run.get("path") == WORKFLOW)
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "failed or incomplete build")
    branch, event = run.get("head_branch"), run.get("event")
    require(
        (branch in {"codex/axis-peer-experiments", "codex/axis-native-build"} and event == "workflow_dispatch")
        or (branch in {"codex/axis-native-build", "codex/axis-sandbox-feasibility"} and event == "push")
    )
    require(
        type(artifact.get("id")) is int and artifact.get("id") == options.artifact and artifact.get("expired") is False
    )
    require(artifact.get("name") == "axis-private-native-peer-linux-" + options.commit)
    require(artifact.get("digest") == "sha256:" + options.archive_sha256)
    require(artifact.get("workflow_run", {}).get("id") == options.run)
    require(artifact.get("workflow_run", {}).get("head_sha") == options.commit)
    require(type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= FILE_LIMIT)
    return artifact["size_in_bytes"]


def record_matches(raw: bytes, record: dict):
    require(isinstance(record, dict) and set(record) == {"sha256", "size"})
    require(type(record["size"]) is int and record["size"] >= 0)
    digest_argument(record["sha256"])
    require(record == {"sha256": sha(raw), "size": len(raw)}, "file bytes differ from manifest")


def manifest(archive: ZipEvidence, provenance_hash: str):
    raw = archive.read("build-artifact/PROVENANCE.json", 4 << 20)
    require(sha(raw) == provenance_hash, "external provenance pin differs")
    provenance = json_object(raw)
    require(
        set(provenance)
        == {
            "variant",
            "source_commits",
            "toolchain",
            "mode",
            "locked_build",
            "lock_review_requires_external_receipt",
            "peer_execution_performed",
            "contained_payload_execution",
            "customer_activation",
            "static_bwrap_runtime_supplied",
            "static_bwrap_build_candidate",
            "unit_scope",
            "c_unit_scope",
            "overlay_files",
            "patch_sha256",
            "files",
        },
        "unknown provenance schema",
    )
    files = provenance.get("files")
    require(isinstance(files, dict) and files)
    require(
        set(archive.files)
        == {"build-artifact/" + path_name(name) for name in files}
        | {"Cargo.lock", "build-artifact/PROVENANCE.json", "build-artifact/WORKFLOW.json"},
        "ZIP inventory differs from manifest",
    )
    require(archive.read("Cargo.lock") == archive.read("build-artifact/source/Cargo.lock"))
    for name, record in files.items():
        record_matches(archive.read("build-artifact/" + name), record)
    require(provenance.get("variant") == "private_linux_owned_fd_peer_build_only")
    require(provenance.get("source_commits") == {"axis": AXIS, "mxc": MXC, "bwrap": BWRAP})
    require(provenance.get("toolchain") == "1.95.0" and provenance.get("mode") == "locked")
    for field in ("locked_build", "lock_review_requires_external_receipt"):
        require(provenance.get(field) is True)
    for field in (
        "peer_execution_performed",
        "contained_payload_execution",
        "customer_activation",
        "static_bwrap_runtime_supplied",
    ):
        require(provenance.get(field) is False)
    require(provenance.get("patch_sha256") == PATCHES)
    require(provenance.get("unit_scope") == "protocol_fake_processes_and_owned_inert_fds_only")
    require(provenance.get("c_unit_scope") == "separate_parsers_flags_and_owned_inert_copy_executable_only")
    return provenance, raw


def source_inputs(archive: ZipEvidence, options):
    require(
        {
            name.removeprefix("build-artifact/source/")
            for name in archive.files
            if name.startswith("build-artifact/source/")
        }
        == SOURCES
    )
    for name in SOURCES:
        source = "internal/axis/native/" + name
        if name == "reviewed-linux-seed.lock":
            source = "test/e2e/axis/mxc-runner/Cargo.lock"
        elif name == "mxc-literal-argv.patch":
            source = "test/e2e/axis/patches/mxc-literal-argv.patch"
        require(
            archive.read("build-artifact/source/" + name, 2 << 20) == blob(options.repository, options.commit, source),
            "committed source differs",
        )
    for name, expected in PATCHES.items():
        require(sha(archive.read("build-artifact/source/" + name)) == expected)
    require(sha(archive.read("build-artifact/source/Cargo.lock")) == LOCK)
    require(sha(archive.read("build-artifact/source/reviewed-linux-seed.lock")) == SEED)
    workflow = archive.object("build-artifact/WORKFLOW.json")
    require(workflow.get("repository") == REPOSITORY and workflow.get("workflow_commit") == options.commit)
    require(
        str(workflow.get("run_id")) == str(options.run) and str(workflow.get("run_attempt")) == str(options.attempt)
    )
    require(set(workflow) == {"repository", "workflow_commit", "run_id", "run_attempt", "peer_or_sandbox_execution"})
    require(workflow["peer_or_sandbox_execution"] is False)


def registry_lock(raw):
    import tomllib

    packages = tomllib.loads(raw.decode())["package"]
    registry, local = {}, set()
    for package in packages:
        identity = package["name"], package["version"]
        if "source" not in package:
            require(identity not in local)
            local.add(identity)
        else:
            require(package["source"] == "registry+https://github.com/rust-lang/crates.io-index")
            digest_argument(package["checksum"])
            require(identity not in registry)
            registry[identity] = package["checksum"]
    return registry, local


def locks(archive):
    candidate = archive.read("build-artifact/source/Cargo.lock")
    seed = archive.read("build-artifact/source/reviewed-linux-seed.lock")
    proposed, local = registry_lock(candidate)
    reviewed, _ = registry_lock(seed)
    require(
        local
        == {
            ("axis-core", "0.3.5"),
            ("axis-sandbox", "0.3.5"),
            ("mxc-sdk", "1.0.1"),
            ("defenseclaw-axis-native", "0.0.0"),
        }
    )
    require(len(proposed) == 221 and all(reviewed.get(key) == value for key, value in proposed.items()))
    require(
        archive.object("build-artifact/LOCK-ADMISSION.json")
        == {
            "registry_packages": 221,
            "new_registry_versions": [],
            "seed_sha256": SEED,
            "candidate_sha256": LOCK,
        }
    )


def reconstruct(archive, root, commit, patches, scratch):
    scratch.mkdir(mode=0o700)
    expected = set()
    for name in patches:
        raw = archive.read("build-artifact/source/" + name)
        paths = set(re.findall(rb"^\+\+\+ b/(.+)$", raw, re.MULTILINE))
        require(paths, "patch source inventory is absent")
        for value in paths:
            path_name(value.decode("ascii"))
        expected.update(value.decode("ascii") for value in paths)
        for value in re.findall(rb"^--- a/(.+)$", raw, re.MULTILINE):
            relative = path_name(value.decode("ascii"))
            destination = scratch / relative
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(blob(root, commit, relative))
        patch = scratch.parent / (name.replace("/", "-") + ".input")
        patch.write_bytes(raw)
        command(
            ["git", "-c", "core.autocrlf=false", "apply", "--check", "--whitespace=error-all", str(patch)], cwd=scratch
        )
        command(["git", "-c", "core.autocrlf=false", "apply", "--whitespace=error-all", str(patch)], cwd=scratch)
    return {name: sha(ordinary(scratch / name, 2 << 20)) for name in sorted(expected)}


def peer_test_inventory(archive):
    expected = set()
    for name in SOURCES - WINDOWS_SOURCE:
        if name.startswith("src/") and name.endswith(".rs"):
            raw = archive.read("build-artifact/source/" + name).decode()
            expected.update(
                f"{PurePosixPath(name).stem}::tests::{test}"
                for test in re.findall(r"#\[test\]\s+fn ([A-Za-z_][A-Za-z_0-9]*)\(\)", raw)
            )
    return expected


def unit_gates(archive):
    peer = archive.object("build-artifact/RUST-UNIT-TESTS.json")
    require(set(peer) == {"tests", "passed", "peer_execution_performed", "contained_payload_execution", "scope"})
    require(peer["scope"] == "protocol_fake_processes_and_owned_inert_fds_only")
    expected = peer_test_inventory(archive)
    require(
        len(expected) == PEER_TEST_COUNT
        and peer.get("tests") == sorted(expected)
        and peer.get("passed") == PEER_TEST_COUNT
    )
    require(peer.get("peer_execution_performed") is False and peer.get("contained_payload_execution") is False)
    dependency_gates = archive.object("build-artifact/DEPENDENCY-PURE-UNIT-TESTS.json")
    require(set(dependency_gates) == set(DEPENDENCIES))
    for name, spec in DEPENDENCIES.items():
        gate = dependency_gates[name]
        require(set(gate) == {"tests", "passed", "workspace_lock_sha256", "scope", "sandbox_or_peer_execution"})
        require(gate["scope"] == "BPF_export_or_inert_memfd_path_validation_only")
        require(gate.get("tests") == spec["tests"] and gate.get("passed") == len(spec["tests"]))
        require(gate.get("workspace_lock_sha256") == spec["lock"] and gate.get("sandbox_or_peer_execution") is False)
        output = archive.read(f"build-artifact/{name.upper()}-PURE-UNIT-TESTS.txt").decode()
        require(set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE)) == set(spec["tests"]))
    c = archive.object("build-artifact/BWRAP-INERT-UNIT-TESTS.json")
    require(
        set(c)
        == {
            "tests",
            "passed",
            "scope",
            "unit_execution_performed",
            "bubblewrap_main_called",
            "namespace_or_mount_or_workload_execution",
        }
    )
    require(c["scope"] == "parsers_flags_and_owned_inert_copy_only")
    require(c.get("tests") == C_TESTS and c.get("passed") == 5 and c.get("unit_execution_performed") is True)
    require(c.get("bubblewrap_main_called") is False and c.get("namespace_or_mount_or_workload_execution") is False)
    require(
        archive.read("build-artifact/BWRAP-INERT-UNIT-TESTS.txt").decode().splitlines()
        == C_TESTS + ["PASS 5 inert owned-FD tests; no namespace, mount or workload execution"]
    )
    require(
        set(
            re.findall(
                r"^test (\S+) \.\.\. ok$", archive.read("build-artifact/RUST-UNIT-TESTS.txt").decode(), re.MULTILINE
            )
        )
        == expected
    )


def static_elf(raw):
    require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01", "not a static ELF64 image")
    kind, machine, version = struct.unpack_from("<HHI", raw, 16)
    entry, offset = struct.unpack_from("<QQ", raw, 24)
    header, width, count = struct.unpack_from("<HHH", raw, 52)
    require((kind, machine, version, header, width) == (2, 62, 1, 64, 56))
    require(1 <= count <= 128 and offset >= 64 and offset + count * width <= len(raw))
    executable_entry, loads = False, 0
    for index in range(count):
        ptype, flags, start, address, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", raw, offset + index * width)
        require(ptype not in {2, 3}, "static image has interpreter or dynamic program headers")
        require(start + size <= len(raw) and size <= memory and address + memory <= 1 << 64)
        if ptype == 1:
            loads += 1
            executable_entry |= bool(flags & 1) and address <= entry < address + size
    require(executable_entry and loads, "ELF entry is outside executable file-backed load segments")
    return {
        "elf": "ELF64_LE_ET_EXEC_X86_64",
        "load_segments": loads,
        "program_headers": count,
        "pt_interp": False,
        "pt_dynamic": False,
    }


def core(record):
    return {"sha256": record["sha256"], "size": record["size"]}


def merge_package_links(aliases, identity, links):
    for name, (kind, target) in links.items():
        previous = aliases.get(name)
        if previous is None:
            require(len(aliases) < 16384, "package link catalog exceeds its bound")
            aliases[name] = {"kind": kind, "target": target, "owners": {identity}}
        else:
            require((previous["kind"], previous["target"]) == (kind, target), "package links conflict")
            previous["owners"].add(identity)


def copyright_target(identity, package, aliases, installed, installed_links):
    """Resolve archive link metadata only. Never consult or traverse host paths."""
    path = "usr/share/doc/" + package + "/copyright"
    followed = set()
    for _ in range(32):
        parts = path.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            require(index == len(parts) or "/" + prefix not in installed, "copyright path crosses a recorded file")
            alias = aliases.get(prefix)
            if alias is None:
                continue
            require(prefix not in followed, "package copyright link cycle")
            declared = installed_links.get("/" + prefix)
            require(
                declared is not None
                and alias["kind"] == b"2"
                and declared["target"] == alias["target"]
                and declared["package"] in alias["owners"],
                "copyright link is not declared by its archive owner",
            )
            if not followed:
                require(declared["package"] == identity, "copyright redirect is not owned by its originating package")
            followed.add(prefix)
            target = alias["target"]
            base = [] if target.startswith("/") else parts[: index - 1]
            for component in target.split("/"):
                if component in {"", "."}:
                    continue
                if component == "..":
                    require(base, "package copyright link escapes the archive root")
                    base.pop()
                else:
                    base.append(component)
            path = path_name("/".join(base + parts[index:]))
            require(path.startswith("usr/share/doc/"), "copyright link escapes the documentation root")
            break
        else:
            record = installed.get("/" + path)
            require(
                record is not None and path.endswith("/copyright"),
                "copyright target is not recorded: " + identity + " -> " + path,
            )
            require(followed or record["package"] == identity, "copyright file belongs to another package")
            return record
    raise ValueError("package copyright link chain exceeds its bound")


def copyright_notices(archive, packages, installed, aliases, installed_links):
    notices = {"build-artifact/static/copyright-" + value["package"] + ".txt" for value in packages.values()}
    require({name for name in archive.files if name.startswith("build-artifact/static/copyright-")} == notices)
    for identity, package in packages.items():
        record = copyright_target(identity, package["package"], aliases, installed, installed_links)
        record_matches(archive.read("build-artifact/static/copyright-" + package["package"] + ".txt"), core(record))


def package_inputs(archive, budget):
    evidence = archive.object("build-artifact/static/UBUNTU-PACKAGES.json")
    require(set(evidence) == {"packages", "installed_files", "installed_links"})
    packages, installed, installed_links = (
        evidence["packages"],
        evidence["installed_files"],
        evidence["installed_links"],
    )
    require(all(isinstance(value, dict) for value in (packages, installed, installed_links)) and packages and installed)
    require(len(packages) <= 64 and len(installed) <= 8192 and len(installed_links) <= 8192)
    for name, value in installed_links.items():
        require(name.startswith("/") and path_name(name[1:]))
        require(set(value) == {"target", "package"} and value["package"] in packages)
    aliases = {}
    for identity, package in packages.items():
        require(set(package) == {"package", "version", "architecture", "archive_sha256", "deb", "origins"})
        require(package["architecture"] in {"amd64", "all"})
        require(re.fullmatch(r"[a-z0-9+.-]+(?::[a-z0-9]+)?", identity) is not None)
        require(re.fullmatch(r"[a-z0-9+.-]+", package["package"]) is not None)
        require(identity.split(":", 1)[0] == package["package"])
        require(
            package["origins"]
            and all(
                re.fullmatch(
                    r"https?://(?:azure\.archive|archive|security)\.ubuntu\.com/ubuntu/? "
                    r"noble(?:-updates|-security)?/[A-Za-z0-9_-]+",
                    origin,
                )
                for origin in package["origins"]
            )
        )
        label = package["deb"].split("/build-artifact/", 1)
        require(len(label) == 2)
        relative = path_name(label[1])
        require(relative.startswith("static/package-downloads/") and relative.endswith(".deb"))
        raw = archive.read("build-artifact/" + relative)
        require(sha(raw) == package["archive_sha256"])
        needed = {name.removeprefix("/") for name, value in installed.items() if value["package"] == identity}
        required_links = {
            name.removeprefix("/") for name, value in installed_links.items() if value["package"] == identity
        }
        require(needed or required_links)
        links = {}
        with deb_data(raw) as stream:
            payload = tar_files(stream, needed, budget=budget, links=links)
        for name in required_links:
            require(
                links.get(name) == (b"2", installed_links["/" + name]["target"]),
                "copyright link differs from its package archive",
            )
        merge_package_links(aliases, identity, links)
        for name, data in payload.items():
            record_matches(data, core(installed["/" + name]))
    require(
        all(
            set(value) == {"sha256", "size", "package"} and value["package"] in packages for value in installed.values()
        )
    )
    require(not any("/" + name in installed for name in aliases), "package file and link inventories conflict")
    require(all(name.removeprefix("/") in aliases for name in installed_links))
    copyright_notices(archive, packages, installed, aliases, installed_links)
    compiler = archive.object("build-artifact/static/COMPILER-INPUTS.json")
    require(
        set(compiler)
        == {
            "gcc",
            "cc1",
            "collect2",
            "as",
            "ld",
            "ar",
            "ranlib",
            "make",
            "readelf",
            "nm",
            "crtbeginS.o",
            "crtendS.o",
            "libgcc.a",
            "libgcc_eh.a",
        }
    )
    for value in compiler.values():
        require(set(value) == {"path", "sha256", "size"})
        require(value["path"] in installed and core(value) == core(installed[value["path"]]))
    uapi = archive.object("build-artifact/static/UAPI.json")
    require(uapi and len(uapi) <= 4096)
    for label, value in uapi.items():
        require(set(value) == {"source", "sha256", "size"})
        path_name(label)
        require(label.split("/", 1)[0] in {"linux", "asm", "asm-generic"})
        require(value["source"] in installed and core(value) == core(installed[value["source"]]))
        require(installed[value["source"]]["package"].split(":", 1)[0] == "linux-libc-dev")
    return compiler


def closure(archive, provenance, options):
    prefix = "build-artifact/static/"
    receipt_raw = archive.read(prefix + "STATIC-CLOSURE.json")
    receipt = json_object(receipt_raw)
    require(
        set(receipt)
        == {
            "variant",
            "source_pins",
            "builds",
            "reproducible_image",
            "source_date_epoch",
            "compiler_bootstrapped_from_source",
            "selected_compiler_and_link_inputs_package_bytes_verified",
            "compiler_dynamic_libraries_and_lto_plugin_verified",
            "bubblewrap_execution_performed",
            "sandbox_execution_performed",
            "runtime_admission",
            "native_fd_mounts_qualified",
        }
    )
    pins = archive.object("build-artifact/source/static/sources.json")
    require(receipt.get("source_pins") == pins and receipt.get("variant") == "static_musl_bwrap_build_only")
    require(receipt.get("source_date_epoch") == "1775403096")
    for field in ("reproducible_image", "selected_compiler_and_link_inputs_package_bytes_verified"):
        require(receipt.get(field) is True)
    for field in (
        "compiler_bootstrapped_from_source",
        "compiler_dynamic_libraries_and_lto_plugin_verified",
        "bubblewrap_execution_performed",
        "sandbox_execution_performed",
        "runtime_admission",
        "native_fd_mounts_qualified",
    ):
        require(receipt.get(field) is False)
    require(pins.get("runtime_admission") is False and pins["bubblewrap"]["commit"] == BWRAP)
    require(pins["bubblewrap"]["overlay_sha256"] == PATCHES["patches/bwrap-owned-fds.patch"])
    require(
        archive.read(prefix + "BWRAP-PINNED-SOURCE.tar") == git(options.bubblewrap, "archive", "--format=tar", BWRAP),
        "pinned Bubblewrap archive differs",
    )
    budget = DecodeBudget()
    for name in ("musl", "libcap"):
        source = pins[name]
        filename = source["archive"].rsplit("/", 1)[1]
        raw = archive.read(prefix + filename)
        require(sha(raw) == source["archive_sha256"] and len(raw) == source["archive_size"])
        top = f"{name}-{source['version']}"
        needed = {f"{top}/{source['license_file']}"}
        if name == "musl":
            needed.add(top + "/src/ldso/dlopen.c")
        import gzip

        stream = gzip.GzipFile(fileobj=io.BytesIO(raw)) if name == "musl" else LzmaReader(io.BytesIO(raw))
        with stream:
            files = tar_files(stream, needed, all_regular=True, budget=budget)
        license_bytes = files[f"{top}/{source['license_file']}"]
        require(sha(license_bytes) == source["license_sha256"])
        require(
            license_bytes
            == archive.read(prefix + name + "-LICENSE")
            == archive.read("build-artifact/source/static/" + name + "-LICENSE")
        )
        if name == "musl":
            dlopen = files[top + "/src/ldso/dlopen.c"]
            require(b"Dynamic loading not supported" in dlopen and b"return 0;" in dlopen)
    compiler = package_inputs(archive, budget)
    builds = receipt.get("builds")
    require(isinstance(builds, list) and len(builds) == 2)
    images = []
    for name, build in zip(("repeat-a", "repeat-b"), builds, strict=True):
        require(set(build) == {"image", "elf", "link_inputs", "musl_static_dlopen_refusal", "execution_performed"})
        image = archive.read(prefix + "bwrap-static-musl-" + name)
        record_matches(image, build["image"])
        require(build["execution_performed"] is False and build["elf"] == static_elf(image))
        require(build["musl_static_dlopen_refusal"] == sha(dlopen))
        require(archive.read(prefix + name + "/dlopen.c") == dlopen)
        linked = build["link_inputs"]
        key = next((key for key in linked if key.endswith(f"/static-build/{name}/bwrap-build/bubblewrap.o")), None)
        require(key is not None)
        root = key.removesuffix(f"/static-build/{name}/bwrap-build/bubblewrap.o")
        require(root.startswith("/") and ".." not in PurePosixPath(root).parts)
        staging = root + "/static-build/" + name
        expected = {
            staging + "/bwrap-build/" + stem + ".o" for stem in ("bubblewrap", "bind-mount", "network", "utils")
        }
        expected |= {staging + "/musl-prefix/lib/" + stem for stem in ("libc.a", "Scrt1.o", "crti.o", "crtn.o")}
        expected.add(staging + "/libcap-source/libcap-2.78/libcap/libcap.a")
        expected |= {compiler[stem]["path"] for stem in ("crtbeginS.o", "crtendS.o", "libgcc.a", "libgcc_eh.a")}
        require(set(linked) == expected, "static link closure has unknown inputs")
        loads = set(re.findall(r"^LOAD (.+)$", archive.read(prefix + "LINK-" + name + ".map").decode(), re.MULTILINE))
        require(loads == expected)
        musl_prefix = archive.object(prefix + name + "/MUSL-PREFIX.json")
        for label, value in linked.items():
            require(set(value) == {"retained", "sha256", "size"})
            retained = path_name(value["retained"])
            require(retained.startswith(name + "/link-inputs/"))
            record_matches(archive.read(prefix + retained), core(value))
            if "/musl-prefix/" in label:
                require(core(value) == musl_prefix[label.split("/musl-prefix/", 1)[1]])
            for role in ("crtbeginS.o", "crtendS.o", "libgcc.a", "libgcc_eh.a"):
                if label == compiler[role]["path"]:
                    require(core(value) == core(compiler[role]))
        images.append(image)
    require(images[0] == images[1], "independent static images differ")
    require(
        provenance.get("static_bwrap_build_candidate")
        == {
            "candidate_supplied": True,
            "runtime_admission": False,
            "image_sha256": sha(images[0]),
            "independent_roots_reproducible": True,
        }
    )
    return images[0], receipt_raw


def verify(options):
    require(re.fullmatch(r"[0-9a-f]{40}", options.commit) is not None)
    require(not options.staging.exists(), "staging must be a fresh caller-owned directory")
    expected_size = actions(options)
    raw = ordinary(options.archive)
    require(len(raw) == expected_size and sha(raw) == options.archive_sha256, "external ZIP pin differs")
    archive = ZipEvidence(raw)
    provenance, provenance_raw = manifest(archive, options.provenance_sha256)
    source_inputs(archive, options)
    locks(archive)
    unit_gates(archive)
    options.staging.mkdir(mode=0o700)
    options.staging_created = True
    scratch = options.staging / "reconstruction"
    scratch.mkdir(mode=0o700)
    observed = {}
    for name, root, commit, overlays, license_file in (
        ("axis", options.axis, AXIS, ["patches/axis-offline-bpf.patch"], "LICENSE"),
        ("mxc", options.mxc, MXC, ["mxc-literal-argv.patch", "patches/mxc-owned-bubblewrap.patch"], "LICENSE.md"),
        ("bwrap", options.bubblewrap, BWRAP, ["patches/bwrap-owned-fds.patch"], "COPYING"),
    ):
        observed[name] = reconstruct(archive, root, commit, overlays, scratch / name)
        retained_name = name + ("-COPYING" if name == "bwrap" else "-LICENSE")
        require(archive.read("build-artifact/upstream/" + retained_name) == blob(root, commit, license_file))
        if name != "bwrap":
            lock_path = "Cargo.lock" if name == "axis" else "src/Cargo.lock"
            require(archive.read(f"build-artifact/upstream/{name}-Cargo.lock") == blob(root, commit, lock_path))
    require(observed == provenance.get("overlay_files"), "reconstructed overlay bytes differ")
    build_inputs = archive.object("build-artifact/BUILD-INPUTS.json")
    require(
        set(build_inputs)
        == {
            "source_commits",
            "patch_sha256",
            "overlay_files",
            "mode",
            "static_build_requested",
            "dependency_pure_unit_gates_requested",
            "peer_or_sandbox_execution",
        }
    )
    require(build_inputs["source_commits"] == {"axis": AXIS, "mxc": MXC, "bwrap": BWRAP})
    require(build_inputs.get("overlay_files") == observed and build_inputs.get("patch_sha256") == PATCHES)
    require(build_inputs.get("mode") == "locked" and build_inputs.get("peer_or_sandbox_execution") is False)
    require(
        build_inputs.get("static_build_requested") is True
        and build_inputs.get("dependency_pure_unit_gates_requested") is True
    )
    toolchain = archive.read("build-artifact/TOOLCHAIN.txt").decode()
    require(toolchain.startswith("rustc 1.95.0 ") and "host: x86_64-unknown-linux-gnu" in toolchain)
    bwrap, static_receipt = closure(archive, provenance, options)
    peer = archive.read("build-artifact/bin/defenseclaw-axis-peer")
    require(len(peer) >= 64 and peer[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<H", peer, 18)[0] == 62)
    images = options.staging / "images"
    proofs = options.staging / "proofs"
    images.mkdir(mode=0o700)
    proofs.mkdir(mode=0o700)
    (images / "peer").write_bytes(peer)
    (images / "bwrap-static-musl").write_bytes(bwrap)
    (proofs / "peer-PROVENANCE.json").write_bytes(provenance_raw)
    (proofs / "STATIC-CLOSURE.json").write_bytes(static_receipt)
    (proofs / "WORKFLOW.json").write_bytes(archive.read("build-artifact/WORKFLOW.json"))
    receipt = {
        "format_version": 1,
        "scope": "inert_linux_native_peer_build_review_v1",
        "verified": True,
        "execution_performed": False,
        "production_certification": False,
        "runtime_admission": False,
        "repository": REPOSITORY,
        "workflow": WORKFLOW,
        "workflow_sha256": sha(blob(options.repository, options.commit, WORKFLOW)),
        "axis_commit": AXIS,
        "mxc_commit": MXC,
        "bubblewrap_commit": BWRAP,
        "static_closure_sha256": sha(static_receipt),
        "builds": [
            {
                "role": "peer_and_static_bwrap",
                "commit": options.commit,
                "run": options.run,
                "artifact": options.artifact,
                "archive_sha256": options.archive_sha256,
                "provenance_sha256": options.provenance_sha256,
            }
        ],
        "images": [
            {"role": "peer", "path": "images/peer", "sha256": sha(peer), "size": len(peer)},
            {"role": "static_musl_bwrap", "path": "images/bwrap-static-musl", "sha256": sha(bwrap), "size": len(bwrap)},
        ],
        "verified_scope": "exact_actions_source_locks_unit_evidence_and_static_musl_link_inputs_only",
        "trusted_build_environment": "reviewed_GitHub_workflow_Ubuntu_authenticated_APT_and_rustup",
        "independent_APT_signature_verification": False,
        "verifier_sha256": sha(ordinary(Path(__file__))),
        "archive_reader_sha256": sha(ordinary(Path(__file__).with_name("artifact_archive.py"))),
    }
    (options.staging / "PEER-REVIEW.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--archive-sha256", required=True, type=digest_argument)
    parser.add_argument("--provenance-sha256", required=True, type=digest_argument)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run", required=True, type=int)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("--artifact", required=True, type=int)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--axis", required=True, type=Path)
    parser.add_argument("--mxc", required=True, type=Path)
    parser.add_argument("--bubblewrap", required=True, type=Path)
    parser.add_argument("--staging", required=True, type=Path)
    options = parser.parse_args()
    require(options.run > 0 and options.attempt > 0 and options.artifact > 0)
    try:
        verify(options)
    except Exception as error:
        if getattr(options, "staging_created", False):
            (options.staging / "REVIEW-FAILED.json").write_text(
                json.dumps(
                    {
                        "verified": False,
                        "runtime_admission": False,
                        "execution_performed": False,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        raise SystemExit("artifact review refused: " + str(error)) from error
    print("PASS inert peer artifact review; no execution or runtime admission")


if __name__ == "__main__":
    main()
