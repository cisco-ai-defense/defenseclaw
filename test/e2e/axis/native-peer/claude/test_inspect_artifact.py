# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Synthetic inputs only: no network, external reader, installer, or image runs."""

import ast
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import inspect_artifact as inspect


def release(**extra):
    return json.dumps(
        {"version": inspect.VERSION, "platforms": {p: {"checksum": "a" * 64} for p in inspect.PLATFORMS}, **extra}
    ).encode()


def signature(primary=inspect.FINGERPRINT, algorithm="8"):
    return (
        "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG "
        + "A" * 40
        + " 2026-10-18 1792281600 0 4 0 22 "
        + algorithm
        + " 00 "
        + primary
        + "\n"
    ).encode()


def image():
    raw = bytearray(128)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQ", raw, 16, 3, 62, 1, 0x400000, 64)
    struct.pack_into("<HHH", raw, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x400000, 0, 128, 128, 4096)
    return raw


class InspectorTests(unittest.TestCase):
    def test_signed_manifest_fixed_version_variants_and_duplicate_keys(self):
        self.assertEqual(set(inspect.manifest_checksums(release())), set(inspect.PLATFORMS))
        for raw in (
            release(version="2.1.293"),
            b'{"version":"a","version":"b"}',
            release(platforms={"linux-x64": {"checksum": "bad"}}),
            release(platforms={"linux-x64-musl": {"checksum": "a" * 64}}),
        ):
            with self.subTest(raw=raw), self.assertRaises(inspect.InspectionError):
                inspect.manifest_checksums(raw)
        checks = inspect.manifest_checksums(release(platforms={"linux-x64": {"checksum": "a" * 64}}))
        self.assertIsNone(checks["linux-x64-musl"])

    def test_effective_stream_bound_and_deadline(self):
        output = io.BytesIO()
        info = inspect.bounded_copy(io.BytesIO(b"abcd"), output, 4, 1, clock=lambda: 0)
        self.assertEqual(info, {"sha256": inspect.digest(b"abcd"), "size": 4})
        for data, clock in ((b"abcde", lambda: 0), (b"a", lambda: 2)):
            output = io.BytesIO()
            with self.assertRaises(inspect.InspectionError):
                inspect.bounded_copy(io.BytesIO(data), output, 4, 1, clock=clock)
            self.assertLessEqual(len(output.getvalue()), 4)
        for error in (
            inspect.InspectionError("private-secret-path"),
            OSError(13, "private-secret-path", "/private-secret-path"),
            inspect.urllib.error.HTTPError("https://private-secret-path", 503, "private-secret-path", {}, None),
        ):
            summary = inspect.error_summary(error)
            self.assertNotIn("private-secret-path", json.dumps(summary))
            self.assertEqual(set(summary), {"category", "gate", "errno", "http_status"})
            self.assertIsNone(summary["gate"])
            if isinstance(error, inspect.urllib.error.HTTPError):
                error.close()
        self.assertEqual(
            inspect.error_summary(inspect.InspectionError("HTTP redirect refused"))["gate"],
            "http_redirect_refused",
        )

    def test_url_and_all_redirects_refused_before_network(self):
        with mock.patch.object(inspect.urllib.request, "build_opener") as opener:
            for url in (
                inspect.MANIFEST + "?x=1",
                "http://downloads.claude.ai/a",
                "https://attacker.invalid/claude",
                inspect.BASE + "/../claude",
            ):
                with self.subTest(url=url), self.assertRaises(inspect.InspectionError):
                    inspect.download(url, Path("unused"), 4)
            opener.assert_not_called()
        with self.assertRaises(inspect.InspectionError):
            inspect.NoRedirect().redirect_request(None, None, 302, "", {}, inspect.MANIFEST)

    def test_key_and_signature_require_independent_primary_and_strong_hash(self):
        listing = ("pub:-:255:22:key:0:0:::::\nfpr:::::::::" + inspect.FINGERPRINT + ":\n").encode()
        self.assertEqual(inspect.key_fingerprint(listing), inspect.FINGERPRINT)
        self.assertEqual(inspect.valid_signature(signature())["primary_fingerprint"], inspect.FINGERPRINT)
        for status in (
            signature("B" * 40),
            signature(algorithm="2"),
            signature() * 2,
            signature() + b"[GNUPG:] REVKEYSIG untrusted\n",
            b"",
        ):
            with self.subTest(status=status), self.assertRaises(inspect.InspectionError):
                inspect.valid_signature(status)
        with self.assertRaises(inspect.InspectionError):
            inspect.key_fingerprint(listing.replace(inspect.FINGERPRINT.encode(), b"B" * 40))

    def test_elf_executable_entry_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data"
            path.write_bytes(image())
            self.assertIsNone(inspect.elf_headers(path)["pt_interp"])
            for offset, fmt, value in ((24, "<Q", 0x500000), (18, "<H", 183), (56, "<H", 129), (64 + 32, "<Q", 129)):
                raw = image()
                struct.pack_into(fmt, raw, offset, value)
                path.write_bytes(raw)
                with self.subTest(offset=offset), self.assertRaises(inspect.InspectionError):
                    inspect.elf_headers(path)

    def test_dynamic_metadata_is_data_not_dependency_authority(self):
        parsed = inspect.dynamic_metadata(
            b"0 (NEEDED) Shared library: [libc.so.6]\n"
            b"0 (RUNPATH) Library runpath: [$ORIGIN/lib]\n"
            b"1: 0 FUNC GLOBAL DEFAULT UND dlopen@GLIBC_2.34\n"
        )
        self.assertEqual(parsed["needed"], ["libc.so.6"])
        self.assertEqual(parsed["runpath"], ["$ORIGIN/lib"])
        self.assertTrue(parsed["imports_dlopen"])
        self.assertFalse(parsed["runtime_dlopen_closure_established"])

    def test_artifact_cannot_include_vendor_binary_or_unknown_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "RESULT.json").write_text("{}", encoding="utf-8")
            self.assertEqual(set(inspect.artifact_inventory(root)), {"RESULT.json"})
            (root / "claude").write_bytes(image())
            with self.assertRaises(inspect.InspectionError):
                inspect.artifact_inventory(root)

    def test_reader_output_overflow_or_deadline_kills_and_waits(self):
        class Stream:
            def __init__(self, fd):
                self.fd = fd
                self.closed = False

            def fileno(self):
                return self.fd

            def close(self):
                self.closed = True

        class Process:
            def __init__(self):
                self.stdout, self.stderr = Stream(3), Stream(4)
                self.returncode = None
                self.killed, self.waited = False, False

            def poll(self):
                return self.returncode

            def kill(self):
                self.killed = True
                self.returncode = -9

            def wait(self, timeout):
                self.waited = True
                return self.returncode

        class Poll:
            def __init__(self):
                self.entries = {}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def register(self, stream, event, data):
                self.entries[stream] = SimpleNamespace(fileobj=stream, fd=stream.fd, data=data)

            def get_map(self):
                return self.entries

            def select(self, timeout):
                return [(key, 1) for key in self.entries.values()]

        for deadline in (False, True):
            process = Process()
            with (
                self.subTest(deadline=deadline),
                mock.patch.object(inspect.subprocess, "Popen", return_value=process),
                mock.patch.object(inspect.selectors, "DefaultSelector", Poll),
                mock.patch.object(inspect.os, "set_blocking"),
                mock.patch.object(inspect.os, "read", return_value=b"12345"),
                mock.patch.object(inspect.time, "monotonic", side_effect=[0, 31] if deadline else [0, 0]),
            ):
                with self.assertRaises(inspect.InspectionError):
                    inspect.tool(["/usr/bin/readelf", "data"], Path("unused"), limit=4)
            self.assertTrue(process.killed and process.waited)
            self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_process_targets_are_only_installed_data_readers(self):
        # Inspect actual subprocess call sites rather than invoke any reader tool.
        source = Path(inspect.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ]
        self.assertEqual([node.func.attr for node in calls], ["Popen"])
        gpg_bases = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "gpg" for target in node.targets)
        ]
        self.assertEqual(len(gpg_bases), 1)
        fixed_options = {node.value for node in gpg_bases[0].elts if isinstance(node, ast.Constant)}
        self.assertTrue(
            {
                "--no-options",
                "--homedir",
                "--no-autostart",
                "--no-auto-key-retrieve",
                "--no-auto-key-import",
                "--disable-dirmngr",
            }.issubset(fixed_options)
        )
        # Every key/signature operation must use that guarded base, preventing a
        # later verification branch from implicitly starting a helper or fetching keys.
        guarded_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "tool"
            and node.args
            and isinstance(node.args[0], ast.BinOp)
            and isinstance(node.args[0].left, ast.Name)
            and node.args[0].left.id == "gpg"
        ]
        self.assertEqual(len(guarded_calls), 3)
        with mock.patch.object(inspect.subprocess, "Popen") as spawn:
            with self.assertRaises(inspect.InspectionError):
                inspect.tool(["./claude", "--version"], Path("unused"))
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
