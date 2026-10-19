# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Inert build-admission tests; no compiler, peer or sandbox is launched."""

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare_build as build


def lock(*, version="1.0.0", checksum="a" * 64, source=None, paths=None):
    source = source or "registry+https://github.com/rust-lang/crates.io-index"
    paths = build.PATH_PACKAGES if paths is None else paths
    parts = [
        f'version = 4\n\n[[package]]\nname = "safe"\nversion = "{version}"\n'
        f'source = "{source}"\nchecksum = "{checksum}"\n'
    ]
    for name, value in sorted(paths):
        parts.append(f'\n[[package]]\nname = "{name}"\nversion = "{value}"\n')
    return "".join(parts).encode()


class BuildAdmissionTests(unittest.TestCase):
    def test_windows_evidence_is_not_an_applied_linux_patch_or_native_test_input(self):
        self.assertTrue(build.WINDOWS_SOURCE <= build.SOURCE)
        self.assertFalse(build.WINDOWS_SOURCE & build.PATCHES.keys())
        names = {"src/linux.rs", "src/windows.rs", "src/windows_future.rs"}

        def read(path):
            self.assertNotEqual(path.name, "windows.rs")
            return b"#[test]\nfn fixed() {}\n"

        with patch.object(build, "SOURCE", names), patch.object(build, "ordinary", side_effect=read) as source:
            self.assertEqual(
                build.native_test_inventory(), {"linux::tests::fixed", "windows_future::tests::fixed"}
            )
            self.assertEqual(source.call_count, 2)

    def test_same_reviewed_registry_and_exact_path_packages_admit(self):
        result = build.admit_lock(lock(), lock())
        self.assertEqual(result["registry_packages"], 1)
        self.assertEqual(result["new_registry_versions"], [])

    def test_new_version_checksum_and_git_source_refuse_before_compilation(self):
        for candidate in (
            lock(version="2.0.0"),
            lock(checksum="b" * 64),
            lock(source="git+https://example.invalid/code#fixed"),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                build.admit_lock(lock(), candidate)

    def test_missing_and_extra_local_package_refuse(self):
        for paths in (set(), build.PATH_PACKAGES | {("unreviewed-local", "0.0.0")}):
            with self.subTest(paths=paths), self.assertRaises(RuntimeError):
                build.admit_lock(lock(), lock(paths=paths))

    def test_bounded_read_refuses_growth_after_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inert.txt"
            path.write_bytes(b"small")
            with patch.object(Path, "open", return_value=io.BytesIO(b"x" * 17)):
                with self.assertRaises(RuntimeError):
                    build.ordinary(path, 16)

    def test_empty_diagnostic_hash_is_retained_but_empty_source_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.stderr"
            path.write_bytes(b"")
            self.assertEqual(build.sha(path), build.hashlib.sha256(b"").hexdigest())
            with self.assertRaises(RuntimeError):
                build.ordinary(path)

    def test_dependency_unit_gate_inventory_is_six_fixed_nonspawning_tests(self):
        self.assertEqual(sum(len(value["tests"]) for value in build.DEPENDENCY_TESTS.values()), 6)
        for value in build.DEPENDENCY_TESTS.values():
            self.assertEqual(len(value["tests"]), 2 if value["package"] == "axis-sandbox" else 4)
            self.assertTrue(all(name.startswith(value["prefix"]) for name in value["tests"]))

    def test_inert_c_evidence_refuses_missing_extra_reordered_or_incomplete_results(self):
        lines = [*build.C_TESTS, build.C_TEST_SUMMARY]
        build.admit_c_test_output("\n".join(lines) + "\n")
        for bad in (lines[:-1], lines[1:], [*lines, "extra"], [*reversed(lines[:-1]), lines[-1]]):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                build.admit_c_test_output("\n".join(bad) + "\n")

    def test_patch_path_traversal_refuses(self):
        self.assertEqual(build.patch_paths(b"+++ b/src/fixed.rs\n"), {"src/fixed.rs"})
        for name in (b"../escape", b"/absolute", b"src//alias", b"src/./alias"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                build.patch_paths(b"+++ b/" + name + b"\n")

    def test_build_environment_does_not_forward_tokens_or_loader_overrides(self):
        with (
            patch.dict(
                build.os.environ,
                {
                    "GITHUB_TOKEN": "fixed-public-canary",
                    "LD_PRELOAD": "fixed-public-canary",
                    "RUSTFLAGS": "fixed-public-canary",
                },
            ),
            patch.object(build.subprocess, "run") as run,
        ):
            run.return_value.stdout = "fixed"
            build.command(["fixed-build-tool"], capture=True)
            environment = run.call_args.kwargs["env"]
            self.assertFalse({"GITHUB_TOKEN", "LD_PRELOAD", "RUSTFLAGS"} & environment.keys())
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertEqual(run.call_args.kwargs["timeout"], 1800)


if __name__ == "__main__":
    unittest.main()
