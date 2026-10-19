# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Synthetic verifier refusal tests; no host tool or runtime executes."""

import copy
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import prepare_build
import verify_native_artifact as verify
from artifact_archive import ZipEvidence, sha
from test_artifact_archive import zipped


def image(ptype=1):
    raw = bytearray(128)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 2, 62, 1)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HHH", raw, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", raw, 64, ptype, 5, 0, 0, 0, len(raw), len(raw), 4096)
    return bytes(raw)


def declared_links(aliases):
    return {
        "/" + name: {"target": value["target"], "package": next(iter(value["owners"]))}
        for name, value in aliases.items()
    }


def metadata():
    options = SimpleNamespace(run=7, attempt=2, artifact=9, commit="a" * 40, archive_sha256="b" * 64)
    run = {
        "id": 7,
        "run_attempt": 2,
        "repository": {"full_name": verify.REPOSITORY},
        "head_repository": {"full_name": verify.REPOSITORY},
        "head_sha": options.commit,
        "path": verify.WORKFLOW,
        "status": "completed",
        "conclusion": "success",
        "head_branch": "codex/axis-peer-experiments",
        "event": "workflow_dispatch",
    }
    artifact = {
        "id": 9,
        "expired": False,
        "name": "axis-private-native-peer-linux-" + options.commit,
        "digest": "sha256:" + options.archive_sha256,
        "size_in_bytes": 123,
        "workflow_run": {"id": 7, "head_sha": options.commit},
    }
    return options, run, artifact


def manifest_fixture(*, bad_file=False, extra=False, patches=None):
    lock = b"inert lock"
    provenance = {
        "files": {"source/Cargo.lock": {"sha256": sha(lock), "size": len(lock)}},
        "variant": "private_linux_owned_fd_peer_build_only",
        "source_commits": {"axis": verify.AXIS, "mxc": verify.MXC, "bwrap": verify.BWRAP},
        "toolchain": "1.95.0",
        "mode": "locked",
        "locked_build": True,
        "lock_review_requires_external_receipt": True,
        "peer_execution_performed": False,
        "contained_payload_execution": False,
        "customer_activation": False,
        "static_bwrap_runtime_supplied": False,
        "patch_sha256": verify.PATCHES if patches is None else patches,
        "static_bwrap_build_candidate": {},
        "unit_scope": "protocol_fake_processes_and_owned_inert_fds_only",
        "c_unit_scope": "separate_parsers_flags_and_owned_inert_copy_executable_only",
        "overlay_files": {},
    }
    raw = json.dumps(provenance).encode()
    files = [
        ("Cargo.lock", lock),
        ("build-artifact/source/Cargo.lock", b"tampered" if bad_file else lock),
        ("build-artifact/PROVENANCE.json", raw),
        ("build-artifact/WORKFLOW.json", b"{}"),
    ]
    if extra:
        files.append(("build-artifact/unlisted", b"extra"))
    return ZipEvidence(zipped(files)), sha(raw)


class VerifierTests(unittest.TestCase):
    def test_host_metadata_capture_is_bounded_and_environment_has_no_provider_secrets(self):
        process = SimpleNamespace(stdout=io.BytesIO(b"fixed"), stderr=io.BytesIO(b""), poll=lambda: 0, returncode=0)
        with (
            patch.dict(verify.os.environ, {"ANTHROPIC_API_KEY": "fixed-public-canary", "LD_PRELOAD": "fixed"}),
            patch.object(verify.subprocess, "Popen", return_value=process) as spawn,
        ):
            self.assertEqual(verify.command(["fixed-host-metadata-tool"], bound=8), b"fixed")
            self.assertNotIn("ANTHROPIC_API_KEY", spawn.call_args.kwargs["env"])
            self.assertNotIn("LD_PRELOAD", spawn.call_args.kwargs["env"])
            self.assertIs(spawn.call_args.kwargs["shell"], False)
        process = SimpleNamespace(stdout=io.BytesIO(b"x" * 9), stderr=io.BytesIO(b""), poll=lambda: 0, returncode=0)
        with patch.object(verify.subprocess, "Popen", return_value=process), self.assertRaises(ValueError):
            verify.command(["fixed-host-metadata-tool"], bound=8)

    def test_unjoined_synchronous_pipe_is_not_closed_on_failure(self):
        class LiveReader:
            def __init__(self, **kwargs):
                pass

            def start(self):
                pass

            def join(self, timeout):
                pass

            def is_alive(self):
                return True

        process = SimpleNamespace(stdout=io.BytesIO(b""), stderr=io.BytesIO(b""), poll=lambda: 0, returncode=0)
        with (
            patch.object(verify.threading, "Thread", LiveReader),
            patch.object(verify.subprocess, "Popen", return_value=process),
            self.assertRaises(ValueError),
        ):
            verify.command(["fixed-host-metadata-tool"])
        self.assertFalse(process.stdout.closed)
        self.assertFalse(process.stderr.closed)

    def test_actions_requires_exact_successful_source_workflow_and_external_artifact_digest(self):
        options, run, artifact = metadata()
        with patch.object(verify, "api", side_effect=[run, artifact]):
            self.assertEqual(verify.actions(options), 123)
        for target, key, value in [
            ("run", "conclusion", "failure"),
            ("run", "status", "in_progress"),
            ("run", "path", ".github/workflows/other.yml"),
            ("run", "head_sha", "c" * 40),
            ("run", "head_repository", {"full_name": "untrusted/fork"}),
            ("run", "event", "pull_request"),
            ("run", "head_branch", "unreviewed"),
            ("run", "run_attempt", 1),
            ("artifact", "expired", True),
            ("artifact", "digest", "sha256:" + "d" * 64),
            ("artifact", "size_in_bytes", verify.FILE_LIMIT + 1),
            ("artifact", "workflow_run", {"id": 8, "head_sha": options.commit}),
        ]:
            changed_run, changed_artifact = copy.deepcopy(run), copy.deepcopy(artifact)
            (changed_run if target == "run" else changed_artifact)[key] = value
            with (
                self.subTest(target=target, key=key),
                patch.object(verify, "api", side_effect=[changed_run, changed_artifact]),
                self.assertRaises(ValueError),
            ):
                verify.actions(options)

    def test_manifest_refuses_tampered_missing_extra_or_unknown_overlay_evidence(self):
        archive, digest = manifest_fixture()
        verify.manifest(archive, digest)
        for options in ({"bad_file": True}, {"extra": True}, {"patches": {"unknown": "a" * 64}}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                verify.manifest(*manifest_fixture(**options))
        with self.assertRaises(ValueError):
            verify.manifest(archive, "0" * 64)

    def test_static_elf_refuses_dynamic_interpreter_foreign_and_oversized_segments(self):
        self.assertFalse(verify.static_elf(image())["pt_dynamic"])
        foreign = bytearray(image())
        struct.pack_into("<H", foreign, 18, 183)
        outside = bytearray(image())
        struct.pack_into("<Q", outside, 96, 1 << 30)
        for raw in (image(2), image(3), bytes(foreign), bytes(outside), image()[:100]):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                verify.static_elf(raw)

    def test_static_elf_entry_requires_executable_file_backed_bytes(self):
        self.assertEqual(verify.static_elf(image())["load_segments"], 1)
        outside = bytearray(image())
        struct.pack_into("<Q", outside, 24, 0x1000)
        bss = bytearray(image())
        struct.pack_into("<Q", bss, 24, 200)
        struct.pack_into("<Q", bss, 104, 256)
        nonexec = bytearray(image())
        struct.pack_into("<I", nonexec, 68, 4)
        overflow = bytearray(image())
        struct.pack_into("<Q", overflow, 80, (1 << 64) - 1)
        for raw in (outside, bss, nonexec, overflow):
            with self.subTest(raw=raw[24:32]), self.assertRaises(ValueError):
                verify.static_elf(raw)

    def test_copyright_notice_is_bound_to_originating_packages_archive_links(self):
        packages = {name: {"package": name} for name in ("compiler", "compiler-base", "other")}
        installed = {
            "/usr/share/doc/compiler-base/copyright": {"package": "compiler-base", "sha256": sha(b"A"), "size": 1},
            "/usr/share/doc/other/copyright": {"package": "other", "sha256": sha(b"B"), "size": 1},
        }
        aliases = {}
        verify.merge_package_links(aliases, "compiler", {"usr/share/doc/compiler": (b"2", "compiler-base")})
        entries = [
            ("build-artifact/static/copyright-" + name + ".txt", b"B" if name == "other" else b"A") for name in packages
        ]
        verify.copyright_notices(ZipEvidence(zipped(entries)), packages, installed, aliases, declared_links(aliases))
        swapped = [(name, b"B" if name.endswith("copyright-compiler.txt") else value) for name, value in entries]
        with self.assertRaises(ValueError):
            verify.copyright_notices(
                ZipEvidence(zipped(swapped)), packages, installed, aliases, declared_links(aliases)
            )
        with self.assertRaises(ValueError):
            verify.copyright_notices(ZipEvidence(zipped(entries)), packages, installed, {}, {})
        with self.assertRaises(ValueError):
            verify.merge_package_links(aliases, "other", {"usr/share/doc/compiler": (b"2", "other")})

    def test_copyright_links_refuse_escape_cycle_foreign_ownership_and_excess_depth(self):
        installed = {"/usr/share/doc/base/copyright": {"package": "base"}}
        for target, owner in [
            ("../../../../../base", "compiler"),
            ("compiler", "compiler"),
            ("base", "other"),
        ]:
            aliases = {}
            verify.merge_package_links(aliases, owner, {"usr/share/doc/compiler": (b"2", target)})
            with self.subTest(target=target, owner=owner), self.assertRaises(ValueError):
                verify.copyright_target("compiler", "compiler", aliases, installed, declared_links(aliases))
        aliases = {}
        for index in range(33):
            name = "compiler" if index == 0 else "alias" + str(index)
            verify.merge_package_links(aliases, "compiler", {"usr/share/doc/" + name: (b"2", "alias" + str(index + 1))})
        with self.assertRaises(ValueError):
            verify.copyright_target("compiler", "compiler", aliases, installed, declared_links(aliases))

    def test_copyright_links_require_every_declared_owner_and_documentation_root(self):
        installed = {"/usr/share/doc/base/copyright": {"package": "base"}, "/etc/foo/copyright": {"package": "other"}}
        aliases = {}
        verify.merge_package_links(aliases, "compiler", {"usr/share/doc/compiler": (b"2", "middle")})
        verify.merge_package_links(aliases, "middle", {"usr/share/doc/middle": (b"2", "base")})
        declared = declared_links(aliases)
        self.assertEqual(
            verify.copyright_target("compiler", "compiler", aliases, installed, declared), {"package": "base"}
        )
        for changed in (
            {name: value for name, value in declared.items() if not name.endswith("/middle")},
            {**declared, "/usr/share/doc/middle": {"target": "base", "package": "other"}},
            {**declared, "/usr/share/doc/middle": {"target": "other", "package": "middle"}},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                verify.copyright_target("compiler", "compiler", aliases, installed, changed)
        aliases = {}
        verify.merge_package_links(aliases, "compiler", {"usr/share/doc/compiler": (b"2", "/etc/foo")})
        with self.assertRaises(ValueError):
            verify.copyright_target("compiler", "compiler", aliases, installed, declared_links(aliases))

    def test_copyright_hard_link_redirects_refuse_as_unsupported_by_builder(self):
        installed = {"/usr/share/doc/base/copyright": {"package": "base"}}
        aliases = {}
        verify.merge_package_links(
            aliases, "compiler", {"usr/share/doc/compiler/copyright": (b"1", "./usr/share/doc/base/copyright")}
        )
        with self.assertRaises(ValueError):
            verify.copyright_target("compiler", "compiler", aliases, installed, declared_links(aliases))
        aliases = {}
        verify.merge_package_links(aliases, "compiler", {"usr/share/doc/compiler": (b"1", "usr/share/doc/base")})
        with self.assertRaises(ValueError):
            verify.copyright_target("compiler", "compiler", aliases, installed, declared_links(aliases))

    def test_regular_record_refuses_boolean_float_size_and_extra_keys(self):
        verify.record_matches(b"a", {"sha256": sha(b"a"), "size": 1})
        for value in (
            {"sha256": sha(b"a"), "size": True},
            {"sha256": sha(b"a"), "size": 1.0},
            {"sha256": sha(b"a"), "size": 1, "unknown": 0},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                verify.record_matches(b"a", value)

    def test_source_inventory_requires_explicit_review_when_build_inputs_change(self):
        self.assertEqual(verify.PEER_TEST_COUNT, prepare_build.NATIVE_TEST_COUNT)
        self.assertEqual(
            verify.SOURCES, prepare_build.SOURCE | {"Cargo.lock", "reviewed-linux-seed.lock", "mxc-literal-argv.patch"}
        )
        self.assertEqual(verify.PATCHES, prepare_build.PATCHES)
        self.assertEqual(verify.WINDOWS_SOURCE, prepare_build.WINDOWS_SOURCE)
        self.assertEqual(
            verify.WINDOWS_SOURCE,
            {
                "WINDOWS.md",
                "prepare_windows_build.py",
                "src/windows.rs",
                "src/windows_bootstrap.rs",
                "src/windows_io.rs",
                "src/windows_transport.rs",
                "patches/mxc-owned-windows-psec.patch",
            },
        )
        self.assertFalse(verify.WINDOWS_SOURCE & verify.PATCHES.keys())
        self.assertEqual(
            {name: spec["tests"] for name, spec in verify.DEPENDENCIES.items()},
            {name: sorted(spec["tests"]) for name, spec in prepare_build.DEPENDENCY_TESTS.items()},
        )

    def test_linux_test_evidence_excludes_only_the_reviewed_windows_source_inventory(self):
        names = {"src/linux.rs", "src/windows.rs", "src/windows_future.rs"}

        def read(name):
            self.assertNotEqual(name, "build-artifact/source/src/windows.rs")
            return b"#[test]\nfn fixed() {}\n"

        archive = SimpleNamespace(read=read)
        with patch.object(verify, "SOURCES", names):
            self.assertEqual(
                verify.peer_test_inventory(archive), {"linux::tests::fixed", "windows_future::tests::fixed"}
            )

    def test_existing_staging_is_refused_before_metadata_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "owned.txt"
            sentinel.write_bytes(b"preserve")
            options = SimpleNamespace(commit="a" * 40, staging=root)
            with patch.object(verify, "actions") as api, self.assertRaises(ValueError):
                verify.verify(options)
            api.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"preserve")
            self.assertFalse((root / "REVIEW-FAILED.json").exists())

    def test_registry_refuses_duplicate_package_git_sources_and_invalid_checksums(self):
        safe = (
            b'[[package]]\nname="fixed"\nversion="1"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'
            + b"a" * 64
            + b'"\n'
        )
        self.assertEqual(len(verify.registry_lock(safe)[0]), 1)
        for raw in (
            safe + safe,
            safe.replace(
                b"registry+https://github.com/rust-lang/crates.io-index", b"git+https://example.invalid/source"
            ),
            safe.replace(b"a" * 64, b"wrong"),
        ):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                verify.registry_lock(raw)


if __name__ == "__main__":
    unittest.main()
