# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build admission tests; no Rust tool, test binary or sandbox is executed."""

import importlib.util
import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

_SPEC = importlib.util.spec_from_file_location("mxc_argv_build", Path(__file__).with_name("build_sdk.py"))
assert _SPEC is not None and _SPEC.loader is not None
sdk = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sdk)


class BuildAdmissionTests(TestCase):
    def test_patch_matches_exact_reviewed_digest_and_inventory(self):
        patch = Path(__file__).with_name("mxc-literal-argv.patch")
        if not patch.exists():
            patch = Path(__file__).parents[1] / "patches/mxc-literal-argv.patch"
        sdk.verify_patch(patch)
        self.assertEqual(len(sdk.PATCH_PATHS), 14)
        self.assertEqual(len(sdk.NEW_FILES), 3)
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "patch"
            changed.write_bytes(patch.read_bytes() + b"\n")
            with self.assertRaisesRegex(RuntimeError, "digest"):
                sdk.verify_patch(changed)

    def test_only_exact_dirty_inventory_is_accepted(self):
        inventory = {path: "??" if path in sdk.NEW_FILES else " M" for path in sdk.PATCH_PATHS}

        def encoded(values):
            return "".join(f"{status} {path}\0" for path, status in values.items())

        sdk.verify_dirty_inventory(encoded(inventory))
        for changed in (
            {**inventory, "src/Cargo.toml": " M"},
            {**inventory, "src/Cargo.lock": " M"},
            {**inventory, "unreviewed.rs": "??"},
            {**inventory, next(iter(sdk.NEW_FILES)): "A "},
            dict(list(inventory.items())[1:]),
        ):
            with self.subTest(paths=sorted(changed)), self.assertRaises(RuntimeError):
                sdk.verify_dirty_inventory(encoded(changed))
        with self.assertRaises(RuntimeError):
            sdk.verify_dirty_inventory(encoded(inventory) + encoded(inventory))

    def test_tampered_lock_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/Cargo.lock").write_text("unreviewed resolution\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "reviewed unchanged lock"):
                sdk.verify_lock(root)

    def test_private_environment_drops_credentials_proxy_and_build_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rustup = root / "installed-rustup"
            rustup.mkdir()
            inherited = {
                "PATH": os.defpath,
                "RUSTUP_HOME": str(rustup),
                **{
                    key: "synthetic-must-not-forward"
                    for key in (
                        "GITHUB_TOKEN",
                        "CARGO_REGISTRY_TOKEN",
                        "HTTP_PROXY",
                        "HTTPS_PROXY",
                        "LD_PRELOAD",
                        "DYLD_INSERT_LIBRARIES",
                        "RUSTFLAGS",
                        "RUSTC_WRAPPER",
                        "CARGO_BUILD_RUSTFLAGS",
                        "CARGO_HOME",
                        "HOME",
                        "GIT_CONFIG_COUNT",
                    )
                },
            }
            environment = sdk.private_environment(root / "private", inherited)
            for key in inherited.keys() - {"PATH", "RUSTUP_HOME", "HOME", "CARGO_HOME"}:
                self.assertNotIn(key, environment)
            for key in ("HOME", "CARGO_HOME", "TMPDIR"):
                self.assertTrue(Path(environment[key]).is_relative_to(root / "private"))
            self.assertNotEqual(environment["HOME"], inherited["HOME"])
            self.assertNotEqual(environment["CARGO_HOME"], inherited["CARGO_HOME"])

    def test_exact_platform_test_inventory_must_exist_once(self):
        for system, count in (("Linux", 10), ("Darwin", 11)):
            names = [*sdk.PURE_TESTS, *([sdk.SEATBELT_TEST] if system == "Darwin" else [])]
            listing = "\n".join(f"{name}: test" for name in names)
            self.assertEqual(len(sdk.selected_tests(listing, system)), count)
            for changed in ("", listing.split("\n", 1)[1], listing + "\n" + names[0] + ": test"):
                with self.assertRaises(RuntimeError):
                    sdk.selected_tests(changed, system)
        with self.assertRaises(RuntimeError):
            sdk.selected_tests(listing, "Windows")

    def test_missing_pinned_toolchain_refuses_without_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {"PATH": os.defpath, "RUSTUP_HOME": directory}
            with self.assertRaisesRegex(RuntimeError, "will not install"):
                sdk.pinned_tools(environment, "Linux", "x86_64")
            binary = Path(directory) / "toolchains/1.95.0-x86_64-unknown-linux-gnu/bin"
            binary.mkdir(parents=True)
            for name in ("cargo", "rustc", "rustfmt"):
                (binary / name).write_bytes(b"inert tool fixture; never executed")
            tools = sdk.pinned_tools(environment, "Linux", "x86_64")
            self.assertEqual(environment["RUSTC"], str(binary / "rustc"))
            self.assertEqual(environment["PATH"].split(os.pathsep)[0], str(binary))
            self.assertEqual(set(tools), {"cargo", "rustc", "rustfmt"})

    def test_workflow_keeps_exact_sources_and_compile_only_entrypoint(self):
        workflow = Path(__file__).with_name("workflow.yml")
        if not workflow.exists():
            workflow = Path(__file__).parents[4] / ".github/workflows/axis-mxc-argv-build.yml"
        source = workflow.read_text(encoding="utf-8")
        for required in (
            "branches: [codex/axis-sandbox-feasibility]",
            sdk.MXC_COMMIT,
            f"rustup toolchain install {sdk.TOOLCHAIN}",
            "contents: read",
            "persist-credentials: false",
            "run: python3 build_sdk.py",
            "runner: ubuntu-24.04",
            "runner: macos-14",
        ):
            self.assertIn(required, source)
        self.assertNotIn("run_live", source)
        self.assertNotIn("workflow_run:", source)

    def test_zero_ignored_or_wrong_test_cannot_pass(self):
        name = sdk.PURE_TESTS[0]
        good = f"test {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 999 filtered out\n"
        sdk.verify_single_test(good, name)
        for output in (
            "test result: ok. 0 passed; 0 failed; 0 ignored;",
            good.replace(name, "wrong"),
            good + good,
            good.replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"),
        ):
            with self.assertRaises(RuntimeError):
                sdk.verify_single_test(output, name)

    def test_source_pin_refusal_runs_no_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "mxc-source"
            source.mkdir()
            environment = {"PATH": os.defpath}
            with (
                mock.patch.object(sdk.platform, "system", return_value="Linux"),
                mock.patch.dict(sdk.os.environ, {"GITHUB_SHA": "a" * 40}),
                mock.patch.object(sdk, "private_environment", return_value=environment),
                mock.patch.object(sdk.Build, "command", side_effect=[str(source), "wrong-commit"]) as command,
            ):
                with self.assertRaisesRegex(RuntimeError, "source commit differs"):
                    sdk.build(root)
            self.assertEqual(command.call_count, 2)
            self.assertTrue(all(call.args[1][0] == "git" for call in command.call_args_list))

    def test_failed_capture_stops_only_owned_unreaped_group_before_wait(self):
        process = mock.Mock(pid=123, returncode=None)
        events = []
        process.wait.side_effect = lambda **_: events.append("wait")
        with (
            mock.patch.object(sdk.os, "killpg", create=True, side_effect=lambda *_: events.append("kill")) as kill,
            mock.patch.object(sdk.signal, "SIGKILL", 9, create=True),
        ):
            sdk.cleanup_command(process, True)
        kill.assert_called_once_with(123, 9)
        self.assertEqual(events, ["kill", "wait"])

    def test_reaped_command_is_never_group_signalled(self):
        process = mock.Mock(pid=123, returncode=0)
        with mock.patch.object(sdk.os, "killpg", create=True) as kill:
            sdk.cleanup_command(process, False)
            with self.assertRaisesRegex(RuntimeError, "reaped"):
                sdk.cleanup_command(process, True)
        kill.assert_not_called()
        process.wait.assert_not_called()
