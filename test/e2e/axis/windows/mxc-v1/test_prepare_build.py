# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-helper regressions; these tests never invoke Cargo or a probe."""

from __future__ import annotations

import importlib.util
import io
import os
import re
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

_SPEC = importlib.util.spec_from_file_location(
    "windows_psec_prepare_build", Path(__file__).with_name("prepare_build.py")
)
assert _SPEC is not None and _SPEC.loader is not None
build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build)


class BuildGuardTests(TestCase):
    def test_probe_slice_accepts_only_reviewed_distinct_fixed_contracts(self) -> None:
        self.assertEqual(
            build.PROBE_SLICE_CONTRACTS,
            {
                "standalone-boundary": (
                    "standalone_std_boundary_native_identity_environment",
                    "fixed_windows_native_psec_boundary_native_identity_environment",
                ),
                "dll-startup-only": (
                    "standalone_std_fixed_dll_startup_diagnostic",
                    "fixed_windows_native_psec_dll_startup_diagnostic",
                ),
                "claude-version-only": (
                    "standalone_std_fixed_signed_claude_version",
                    "fixed_windows_native_psec_signed_claude_version",
                ),
                "claude-create-control-only": (
                    "standalone_std_fixed_signed_claude_create_control",
                    "fixed_windows_uncontained_claude_create_control",
                ),
            },
        )
        with (
            mock.patch.object(build.sys, "argv", ["prepare_build.py", "build-locked", "--probe-slice", "unreviewed"]),
            mock.patch.object(build.sys, "stderr", io.StringIO()),
            mock.patch.object(build, "command") as command,
            mock.patch.object(build, "verify_source") as source,
            self.assertRaises(SystemExit) as failure,
        ):
            build.main()
        self.assertEqual(failure.exception.code, 2)
        command.assert_not_called()
        source.assert_not_called()

    def test_boundary_packages_three_images_and_adds_only_its_startup_test_gates(self) -> None:
        boundary = build.artifact_binaries("standalone-boundary")
        self.assertEqual(boundary, (build.BINARY, build.LOADER_BINARY, build.BOUNDARY_BINARY))
        self.assertEqual(sum(map(len, build.pure_environment_tests("standalone-boundary").values())), 14)
        self.assertEqual(sum(map(len, build.native_directory_custody_tests("standalone-boundary").values())), 3)
        for mode in ("dll-startup-only", "claude-version-only", "claude-create-control-only"):
            self.assertEqual(build.artifact_binaries(mode), boundary + (build.DLL_BINARY,))
            self.assertEqual(build.pure_environment_tests(mode), build.PURE_ENVIRONMENT_TESTS)
            self.assertEqual(build.native_directory_custody_tests(mode), build.NATIVE_DIRECTORY_CUSTODY_TESTS)
        self.assertEqual(sum(map(len, build.PURE_ENVIRONMENT_TESTS.values())), 9)
        with self.assertRaises(ValueError):
            build.artifact_binaries("unreviewed")
        with self.assertRaises(ValueError):
            build.pure_environment_tests("unreviewed")

    def test_boundary_startup_gates_name_real_pure_tests(self) -> None:
        root = Path(__file__).resolve().parent
        source = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("src/native_environment.rs", "src/native_identity.rs", "src/private_native_record.rs")
        )
        for names in build.PURE_STARTUP_ENVIRONMENT_TESTS.values():
            for name in names:
                self.assertRegex(source, r"#\[test\]\s*fn " + re.escape(name.rsplit("::", 1)[-1]) + r"\(")
        for name in build.native_directory_custody_tests("standalone-boundary")["defenseclaw-axis-windows-psec-probe"]:
            if "private_native_record" in name:
                self.assertRegex(source, r"#\[test\]\s*fn " + re.escape(name.rsplit("::", 1)[-1]) + r"\(")

    def test_profile_component_and_token_root_gates_name_real_pure_tests(self) -> None:
        root = Path(__file__).resolve().parent
        source = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in ("src/native_environment.rs", "src/native_identity.rs")
        )
        expected = {
            "defenseclaw-axis-windows-psec-boundary-child": [
                "native_environment::tests::ordinary_native_profile_component_confines_literal_windows_names",
            ],
            "defenseclaw-axis-windows-psec-probe": [
                "probe::native_environment::tests::ordinary_native_profile_component_confines_literal_windows_names",
                "probe::native_identity::tests::profile_directory_query_requires_bounded_complete_native_result",
            ],
        }
        for mode in build.PROBE_SLICE_CONTRACTS:
            inventory = build.pure_environment_tests(mode)
            for binary, names in expected.items():
                for name in names:
                    self.assertIn(name, inventory[binary])
                    self.assertRegex(source, r"#\[test\]\s*fn " + re.escape(name.rsplit("::", 1)[-1]) + r"\(")

    def test_source_identity_must_match_exact_commit(self) -> None:
        with (
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(build, "command", return_value="other-commit") as command,
            self.assertRaisesRegex(RuntimeError, "reviewed commit"),
        ):
            build.verify_source("axis-source", build.AXIS_COMMIT)
        self.assertEqual(command.call_args.args[0], ["git", "rev-parse", "HEAD"])

    def test_dirty_pinned_source_refused_before_patch(self) -> None:
        with (
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(build, "command", side_effect=[build.MXC_COMMIT, " M src/policy.rs"]),
            self.assertRaisesRegex(RuntimeError, "must be clean"),
        ):
            build.verify_source("mxc-source", build.MXC_COMMIT)

    def test_locked_build_without_lock_stops_before_source_or_tool_execution(self) -> None:
        with (
            mock.patch.object(build.sys, "argv", ["prepare_build.py", "build-locked"]),
            mock.patch.object(build.sys, "platform", "win32"),
            mock.patch.object(build.platform, "machine", return_value="AMD64"),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(Path, "is_file", return_value=False),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(build, "command") as command,
            self.assertRaisesRegex(RuntimeError, "reviewed combined Cargo.lock"),
        ):
            build.main()
        command.assert_not_called()

    def test_build_commands_do_not_inherit_credentials_or_rust_overrides(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {
                    "PATH": "/safe/bin",
                    "HOME": "/build",
                    "ANTHROPIC_API_KEY": "synthetic",
                    "LD_PRELOAD": "/synthetic",
                    "RUSTFLAGS": "synthetic",
                },
                clear=True,
            ),
            mock.patch.object(build.subprocess, "run", return_value=SimpleNamespace(stdout="identity\n")) as run,
        ):
            self.assertEqual(build.command(["git", "rev-parse", "HEAD"], capture=True), "identity")
        arguments = run.call_args.kwargs
        self.assertFalse(arguments["shell"])
        self.assertTrue(arguments["check"])
        self.assertLessEqual(arguments["timeout"], 2400)
        self.assertEqual(arguments["env"]["PATH"], "/safe/bin")
        self.assertNotIn("ANTHROPIC_API_KEY", arguments["env"])
        self.assertNotIn("LD_PRELOAD", arguments["env"])
        self.assertNotIn("RUSTFLAGS", arguments["env"])

    def test_generate_lock_refuses_broken_lock_symlink_before_tool_execution(self) -> None:
        def is_link(path: Path) -> bool:
            return path.name == "Cargo.lock"

        with (
            mock.patch.object(build.sys, "argv", ["prepare_build.py", "generate-lock"]),
            mock.patch.object(build.sys, "platform", "win32"),
            mock.patch.object(build.platform, "machine", return_value="AMD64"),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(Path, "is_symlink", is_link),
            mock.patch.object(build, "command") as command,
            self.assertRaisesRegex(RuntimeError, "without Cargo.lock"),
        ):
            build.main()
        command.assert_not_called()

    def test_extra_source_change_is_refused(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        with (
            mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "?? extra.rs"]),
            self.assertRaisesRegex(RuntimeError, "reviewed MXC overlay paths"),
        ):
            build.verify_build_sources(axis, mxc)

    def test_staged_source_change_is_refused(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        with (
            mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "src/staged.rs"]),
            self.assertRaisesRegex(RuntimeError, "staging is not permitted"),
        ):
            build.verify_build_sources(axis, mxc)

    def test_only_exact_modified_and_added_overlay_paths_are_accepted(self) -> None:
        axis = Path("axis")
        mxc = Path("mxc")
        status = "\n".join(
            [f" M {path}" for path in sorted(build.PATCHED_PATHS)]
            + [f"?? {path}" for path in sorted(build.ADDED_PATHS)]
        )
        with mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "", build.MXC_COMMIT, status, ""]):
            build.verify_build_sources(axis, mxc)

    def test_missing_added_overlay_file_is_refused(self) -> None:
        status = "\n".join(f" M {path}" for path in sorted(build.PATCHED_PATHS))
        with (
            mock.patch.object(build, "command", side_effect=[build.AXIS_COMMIT, "", "", build.MXC_COMMIT, status]),
            self.assertRaisesRegex(RuntimeError, "reviewed MXC overlay paths"),
        ):
            build.verify_build_sources(Path("axis"), Path("mxc"))

    def test_fingerprints_detect_added_file_mutation_outside_git_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in build.PATCHED_PATHS | build.ADDED_PATHS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"fixed source\n")
            before = build.overlay_fingerprints(root)
            changed = sorted(build.ADDED_PATHS)[0]
            (root / changed).write_bytes(b"changed source\n")
            after = build.overlay_fingerprints(root)
            self.assertNotEqual(before[changed], after[changed])
            self.assertEqual(set(before), build.PATCHED_PATHS | build.ADDED_PATHS)

    def test_overlay_junction_is_refused_before_read(self) -> None:
        with (
            mock.patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    st_size=42,
                ),
            ),
            mock.patch.object(build, "digest") as digest,
            self.assertRaisesRegex(RuntimeError, "bounded regular file"),
        ):
            build.overlay_fingerprints(Path("mxc"))
        digest.assert_not_called()

    def test_windows_overlay_requires_all_four_reviewed_paths(self) -> None:
        rows = ["1\t0\t" + path for path in sorted(build.WINDOWS_ARGV_PATCH_PATHS)]
        with mock.patch.object(build, "command", return_value="\n".join(rows)):
            build.verify_windows_patch_paths(Path("mxc"))
        for changed in [rows[:-1], rows + ["1\t0\tunreviewed.rs"], rows[:-1] + [rows[0]]]:
            with (
                self.subTest(rows=changed),
                mock.patch.object(build, "command", return_value="\n".join(changed)),
                self.assertRaisesRegex(RuntimeError, "four reviewed source paths"),
            ):
                build.verify_windows_patch_paths(Path("mxc"))

    def test_native_identity_overlay_cannot_add_an_unreviewed_sdk_path(self) -> None:
        rows = ["1\t0\t" + path for path in sorted(build.IDENTITY_PATCH_PATHS)]
        with mock.patch.object(build, "command", return_value="\n".join(rows)):
            build.verify_identity_patch_paths(Path("mxc"))
        for changed in [rows[:-1], rows + ["1\t0\tunreviewed.rs"], rows[:-1] + [rows[0]]]:
            with (
                self.subTest(rows=changed),
                mock.patch.object(build, "command", return_value="\n".join(changed)),
                self.assertRaisesRegex(RuntimeError, "four reviewed source paths"),
            ):
                build.verify_identity_patch_paths(Path("mxc"))


class FixedControlBuildTests(TestCase):
    def test_fifth_overlay_accepts_only_exact_two_paths_and_digest(self) -> None:
        rows = "\n".join("1\t1\t" + name for name in sorted(build.CONTROL_PATCH_PATHS))
        with (
            mock.patch.object(build, "digest", return_value=build.CONTROL_PATCH_SHA256),
            mock.patch.object(build, "command", return_value=rows),
        ):
            build.verify_control_patch_paths(Path("mxc"))
        for changed in [rows + "\n1\t1\tCargo.toml", rows.replace("secenv.rs", "other.rs")]:
            with (
                mock.patch.object(build, "digest", return_value=build.CONTROL_PATCH_SHA256),
                mock.patch.object(build, "command", return_value=changed),
                self.assertRaisesRegex(RuntimeError, "two reviewed"),
            ):
                build.verify_control_patch_paths(Path("mxc"))
        with (
            mock.patch.object(build, "digest", return_value="0" * 64),
            mock.patch.object(build, "command") as command,
            self.assertRaisesRegex(RuntimeError, "differs"),
        ):
            build.verify_control_patch_paths(Path("mxc"))
        command.assert_not_called()

    def test_control_patch_source_hash_matches_registry_without_running_git(self) -> None:
        self.assertEqual(build.digest(build.CONTROL_PATCH), build.CONTROL_PATCH_SHA256)

    def test_control_feature_and_selector_are_bound_before_fixture_setup(self) -> None:
        import tomllib

        cargo = tomllib.loads(build.ROOT.joinpath("Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(cargo["features"], {"fixed-claude-create-control": []})
        source = build.ROOT.joinpath("src/probe.rs").read_text(encoding="utf-8")
        gate = source.index('create_control_only == cfg!(feature = "fixed-claude-create-control")')
        self.assertLess(gate, source.index("let system = PathBuf::from"))
        self.assertLess(gate, source.index("let owned = tempfile::Builder::new()"))
