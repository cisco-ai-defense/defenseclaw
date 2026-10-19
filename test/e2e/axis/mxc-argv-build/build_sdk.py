#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Compile the pinned argv SDK patch and execute only reviewed pure unit tests."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import selectors
import shutil
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
LOCK_SHA256 = "2d145ff3861cd19d1f50969083f8ac59e4d4fd50b030bef12f365a5fcc87afa0"
PATCH_SHA256 = "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d"
TOOLCHAIN = "1.95.0"
MAX_LOG_BYTES = 8 * 1024 * 1024
SDK = "src/mxc-sdk/src/"
NEW_FILES = {
    SDK + name
    for name in (
        "core/mxc_common/literal_argv.rs",
        "core/mxc_engine/literal_argv.rs",
        "literal_argv.rs",
    )
}
PATCH_PATHS = NEW_FILES | {
    SDK + name
    for name in (
        "backends/bubblewrap/common/bwrap_command.rs",
        "backends/bubblewrap/common/bwrap_runner.rs",
        "backends/seatbelt/common/seatbelt_runner.rs",
        "core/mxc_common/mod.rs",
        "core/mxc_common/sandbox_process.rs",
        "core/mxc_common/validator.rs",
        "core/mxc_engine/dispatch.rs",
        "core/mxc_engine/mod.rs",
        "lib.rs",
        "policy/exact/mod.rs",
        "policy.rs",
    )
}
PURE_TESTS = (
    "core_modules::mxc_common::literal_argv::tests::literal_command_preserves_empty_metacharacter_and_unicode_arguments",
    "core_modules::mxc_common::literal_argv::tests::literal_command_preserves_non_utf8_os_arguments",
    "core_modules::mxc_common::literal_argv::tests::literal_command_refuses_empty_relative_nul_and_oversize_values",
    "core_modules::mxc_common::literal_argv::tests::typed_validation_rejects_command_ambiguity_and_retains_common_policy_checks",
    "core_modules::mxc_common::literal_argv::tests::an_unimplemented_backend_refuses_without_calling_legacy_spawn",
    "core_modules::mxc_engine::literal_argv::tests::unsupported_argv_backend_refuses_before_platform_or_spawn",
    "literal_argv::tests::argv_preparation_rejects_ambiguous_legacy_command",
    "literal_argv::tests::argv_preparation_refuses_abstract_process_selection",
    "literal_argv::tests::argv_preparation_preserves_empty_environment_and_policy",
    "backend_modules::bubblewrap::common::bwrap_command::tests::literal_argv_does_not_use_the_shell_command_tail",
)
SEATBELT_TEST = (
    "backend_modules::seatbelt::common::seatbelt_runner::tests::"
    "literal_command_preserves_argv_without_constructing_a_shell"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def private_environment(root: Path, inherited: dict[str, str]) -> dict[str, str]:
    rustup = Path(inherited.get("RUSTUP_HOME", ""))
    require(rustup.is_absolute() and rustup.is_dir(), "provision pinned RUSTUP_HOME before building")
    environment = {
        "PATH": inherited["PATH"],
        "RUSTUP_HOME": str(rustup.resolve()),
        "CARGO_TERM_COLOR": "never",
        "CARGO_INCREMENTAL": "0",
        "CARGO_BUILD_JOBS": "2",
        "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
        "CARGO_NET_RETRY": "2",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for key, name in (("HOME", "home"), ("CARGO_HOME", "cargo"), ("TMPDIR", "tmp")):
        directory = root / name
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        environment[key] = str(directory)
    for key in ("SSL_CERT_FILE", "CARGO_HTTP_CAINFO"):
        if key in inherited:
            certificate = Path(inherited[key])
            require(
                certificate.is_absolute() and certificate.is_file(), "CA override must name an existing absolute file"
            )
            environment[key] = str(certificate)
    return environment


def verify_lock(source: Path) -> None:
    lock = source / "src/Cargo.lock"
    require(
        lock.is_file() and not lock.is_symlink() and digest(lock) == LOCK_SHA256,
        "upstream Cargo.lock differs from the reviewed unchanged lock",
    )


def pinned_tools(environment: dict[str, str], system: str, machine: str) -> dict[str, str]:
    triples = {
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
        ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
    }
    require((system, machine) in triples, "no reviewed native toolchain layout for this host")
    binary = Path(environment["RUSTUP_HOME"]) / "toolchains" / f"{TOOLCHAIN}-{triples[system, machine]}" / "bin"
    tools = {name: str(binary / name) for name in ("rustc", "cargo", "rustfmt")}
    require(
        all(Path(path).is_file() and not Path(path).is_symlink() for path in tools.values()),
        "preprovision all pinned toolchain binaries; helper will not install them",
    )
    environment["PATH"] = str(binary) + os.pathsep + environment["PATH"]
    environment["RUSTC"] = tools["rustc"]
    return tools


def verify_patch(patch: Path) -> None:
    require(
        patch.is_file() and not patch.is_symlink() and digest(patch) == PATCH_SHA256,
        "literal argv patch differs from its reviewed digest",
    )
    paths = re.findall(r"^\+\+\+ b/(.+)$", patch.read_text(encoding="utf-8"), re.MULTILINE)
    require(
        len(paths) == len(PATCH_PATHS) and set(paths) == PATCH_PATHS,
        "literal argv patch inventory differs from the exact 14 Rust paths",
    )


def verify_dirty_inventory(status: str) -> None:
    entries = status.split("\0")
    require(entries[-1] == "", "invalid NUL-delimited source inventory")
    actual = {}
    for entry in entries[:-1]:
        require(len(entry) > 3 and entry[2] == " ", "unexpected source status record")
        require(entry[3:] not in actual, "duplicate source status record")
        actual[entry[3:]] = entry[:2]
    expected = {path: "??" if path in NEW_FILES else " M" for path in PATCH_PATHS}
    require(actual == expected, "patched source has unexpected files, status or Cargo edits")


def selected_tests(listing: str, system: str) -> list[str]:
    require(system in ("Linux", "Darwin"), "only native Linux/macOS unit builds are supported")
    expected = [*PURE_TESTS, *([SEATBELT_TEST] if system == "Darwin" else [])]
    listed = re.findall(r"^(.+): test$", listing, re.MULTILINE)
    require(len(set(expected)) == len(expected), "duplicate pure test allowlist entry")
    require(all(listed.count(name) == 1 for name in expected), "expected exact pure tests are missing or duplicated")
    return expected


def verify_single_test(output: str, name: str) -> None:
    require(
        len(re.findall(rf"^test {re.escape(name)} \.\.\. ok$", output, re.MULTILINE)) == 1
        and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE) is not None,
        "exact unit command did not report one passing, non-ignored test",
    )


def cleanup_command(process: subprocess.Popen, may_signal_group: bool) -> None:
    if may_signal_group:
        # The leader has never been reaped, or wait explicitly timed out.
        # Its retained PID prevents this exact session's group ID being reused.
        require(process.returncode is None, "refuse to group-signal a reaped build command")
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.returncode is None:
        process.wait(timeout=10)


class Build:
    def __init__(self, root: Path, environment: dict[str, str]):
        self.root = root
        self.environment = environment
        self.commands: list[dict[str, object]] = []
        self.logs = root / "build-artifact/logs"
        self.logs.mkdir(parents=True)

    def command(self, label: str, argv: list[str], cwd: Path, timeout: int = 1200) -> str:
        record: dict[str, object] = {"label": label, "argv": argv, "cwd": str(cwd), "timeout_seconds": timeout}
        self.commands.append(record)
        started = time.monotonic()
        captured = bytearray()
        log = self.logs / f"{len(self.commands):02d}-{label}.log"
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=self.environment,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert process.stdout is not None
        may_signal_group = True
        try:
            with selectors.DefaultSelector() as selector, log.open("xb") as output:
                selector.register(process.stdout, selectors.EVENT_READ)
                os.set_blocking(process.stdout.fileno(), False)
                while selector.get_map():
                    require(time.monotonic() - started < timeout, f"{label} exceeded its deadline")
                    for key, _ in selector.select(timeout=0.1):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        remaining = MAX_LOG_BYTES - len(captured)
                        output.write(chunk[:remaining])
                        captured.extend(chunk[:remaining])
                        require(len(chunk) <= remaining, f"{label} exceeded its bounded log limit")
                # Disable group signalling before any wait may reap the
                # leader, including an asynchronously interrupted wait. Only
                # an explicit timeout guarantees the leader is still held.
                may_signal_group = False
                try:
                    status = process.wait(timeout=max(1, timeout - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    may_signal_group = True
                    raise
            record["exit_code"] = status
            require(status == 0, f"{label} failed with exit {status}; inspect its captured log")
        finally:
            cleanup_command(process, may_signal_group)
            process.stdout.close()
            record["duration_seconds"] = round(time.monotonic() - started, 3)
        return captured.decode("utf-8", errors="replace")


def build(root: Path = ROOT) -> None:
    system = platform.system()
    require(system in ("Linux", "Darwin"), "this compile/unit gate requires native Linux or macOS")
    source = root / "mxc-source"
    require(source.is_dir() and not source.is_symlink(), "provide a fresh exact MXC checkout")
    artifact = root / "build-artifact"
    require(not artifact.exists() and not artifact.is_symlink(), "use a fresh build directory")
    environment = private_environment(root / "private-state", dict(os.environ))
    gate = Build(root, environment)
    workflow_commit = os.environ.get("GITHUB_SHA", "")
    provenance: dict[str, object] = {
        "scope": "contributor_sdk_compile_and_pure_unit_tests_only",
        "mxc_commit": MXC_COMMIT,
        "patch_sha256": PATCH_SHA256,
        "upstream_lock_sha256": LOCK_SHA256,
        "toolchain": TOOLCHAIN,
        "platform": {"system": system, "machine": platform.machine()},
        "defenseclaw_source_commit": workflow_commit,
        "workflow": {key: os.environ.get(key) for key in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")},
        "sandbox_or_payload_execution": False,
        "production_qualification": False,
        "commands": gate.commands,
        "passed": False,
    }
    try:
        require(
            re.fullmatch(r"[0-9a-f]{40}", workflow_commit) is not None,
            "record the exact reviewed workflow source commit",
        )
        top = gate.command("source-root", ["git", "rev-parse", "--show-toplevel"], source).strip()
        require(Path(top).resolve() == source.resolve(), "MXC checkout root differs")
        require(
            gate.command("source-pin", ["git", "rev-parse", "HEAD"], source).strip() == MXC_COMMIT,
            "MXC source commit differs",
        )
        require(
            not gate.command(
                "source-clean", ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], source
            ),
            "MXC source must be clean before applying the exact patch",
        )
        verify_lock(source)
        patch = root / "mxc-literal-argv.patch"
        verify_patch(patch)
        gate.command("patch-check", ["git", "apply", "--check", "--whitespace=error-all", str(patch)], source)
        gate.command("patch-apply", ["git", "apply", "--whitespace=error-all", str(patch)], source)
        verify_dirty_inventory(
            gate.command(
                "patched-inventory", ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], source
            )
        )
        verify_lock(source)
        for name in sorted(PATCH_PATHS):
            target = artifact / "patched-source" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            original = source / name
            require(original.is_file() and not original.is_symlink(), "patched Rust source must be a regular file")
            shutil.copyfile(original, target)
        for name in ("build_sdk.py", "test_build_sdk.py", "README.md", "mxc-literal-argv.patch", "workflow.yml"):
            shutil.copyfile(root / name, artifact / name)
        shutil.copyfile(source / "src/Cargo.lock", artifact / "upstream-Cargo.lock")
        shutil.copyfile(source / "LICENSE.md", artifact / "MXC-LICENSE.md")
        tools = pinned_tools(environment, system, platform.machine())
        versions = gate.command("rustc-version", [tools["rustc"], "--version", "--verbose"], source)
        require(versions.startswith(f"rustc {TOOLCHAIN} "), "provision the exact Rust compiler")
        cargo_version = gate.command("cargo-version", [tools["cargo"], "--version", "--verbose"], source)
        require(cargo_version.startswith(f"cargo {TOOLCHAIN} "), "provision the exact Cargo version")
        # Parse all edited Rust before the dependency build; check formatting
        # only for new files so upstream formatting remains untouched.
        for index, name in enumerate(sorted(PATCH_PATHS)):
            gate.command(
                f"syntax-{index:02d}",
                [
                    tools["rustfmt"],
                    "--edition",
                    "2021",
                    "--config",
                    "skip_children=true",
                    "--emit",
                    "stdout",
                    str(source / name),
                ],
                source,
                60,
            )
        gate.command(
            "new-source-format",
            [
                tools["rustfmt"],
                "--edition",
                "2021",
                "--config",
                "skip_children=true",
                "--check",
                *[str(source / name) for name in sorted(NEW_FILES)],
            ],
            source,
            60,
        )
        cargo = [tools["cargo"]]
        common = ["--locked", "--no-default-features", "-p", "mxc-sdk", "--lib"]
        gate.command("sdk-build", [*cargo, "build", *common], source / "src")
        listing = gate.command(
            "unit-list", [*cargo, "test", *common, "--", "--list", "--format", "terse"], source / "src"
        )
        names = selected_tests(listing, system)
        (artifact / "SELECTED-TESTS.json").write_text(json.dumps(names, indent=2) + "\n", encoding="utf-8")
        for index, name in enumerate(names):
            output = gate.command(
                f"pure-unit-{index:02d}",
                [*cargo, "test", *common, name, "--", "--exact", "--test-threads=1", "--format", "pretty"],
                source / "src",
                60,
            )
            verify_single_test(output, name)
        verify_lock(source)
        verify_dirty_inventory(
            gate.command("final-inventory", ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], source)
        )
        require(
            all(digest(source / name) == digest(artifact / "patched-source" / name) for name in PATCH_PATHS),
            "build changed reviewed patched source",
        )
        provenance["passed"] = True
        provenance["pure_tests_passed"] = len(names)
    finally:
        provenance["files"] = {
            path.relative_to(artifact).as_posix(): {"sha256": digest(path), "bytes": path.stat().st_size}
            for path in sorted(artifact.rglob("*"))
            if path.is_file()
        }
        (artifact / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build()
