# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import copy
import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import prepare_version as version
from artifact_archive import ZipEvidence, sha


class VersionPreparationTests(unittest.TestCase):
    def test_closed_wrapper_or_driver_refuses_before_paths_and_network(self):
        # Inject closed input admission even after future reviewed source pins
        # are populated. Tests must never gain real acquisition authority.
        for role in ("wrapper", "driver"):
            with (
                self.subTest(role=role),
                tempfile.TemporaryDirectory() as temporary,
                mock.patch.dict(version.PINS, {role: None}),
            ):
                root = Path(temporary) / "must-not-exist"
                with self.assertRaises(ValueError):
                    version.prepare(
                        root,
                        metadata_api=lambda _: self.fail("API reached"),
                        download=lambda _: self.fail("download reached"),
                    )
                self.assertFalse(root.exists())

    def test_version_receipt_is_distinct_and_exact(self):
        path = Path(version.__file__).with_name("REVIEWED-CLAUDE-VERSION.json")
        data = path.read_bytes()
        value = json.loads(data)
        self.assertEqual(sha(data), version.RECEIPT_SHA)
        self.assertNotEqual(version.RECEIPT_SHA, version.fixed.RECEIPT_SHA)
        self.assertEqual(value["scope"], version.SCOPE)
        self.assertEqual(value["images"][2]["sha256"], version.VENDOR_SHA)
        self.assertEqual(value["loader"]["sha256"], version.LOADER_SHA)

    def fake_vendor(self, root, bad_signature=False, bad_metadata=False):
        receipt = json.loads(Path(version.__file__).with_name("REVIEWED-CLAUDE-VERSION.json").read_bytes())
        review = receipt["claude_version"]
        metadata = {
            "manifest": b"public synthetic manifest",
            "signature": b"public synthetic signature",
            "key": b"public synthetic key",
        }
        review["manifest_sha256"], review["signature_sha256"], review["key_sha256"] = (
            sha(metadata[k]) for k in ("manifest", "signature", "key")
        )
        vendor, license_data = b"inert text, never an image", b"public synthetic license"
        calls, tools = [], []
        module = SimpleNamespace(
            MANIFEST="https://fixed.invalid/manifest",
            SIGNATURE="https://fixed.invalid/signature",
            KEY="https://fixed.invalid/key",
            BASE="https://fixed.invalid/release",
            LICENSE="https://fixed.invalid/license",
        )
        review["url"] = module.BASE + "/linux-x64-musl/claude"
        module.key_fingerprint = lambda _: review["signer_fingerprint"]
        module.valid_signature = lambda _: {"primary_fingerprint": review["signer_fingerprint"]}
        module.manifest_checksums = lambda _: {"linux-x64-musl": {"sha256": sha(vendor), "size": len(vendor)}}
        module.elf_headers = lambda _: {
            "type": "ET_EXEC",
            "pt_interp": "/lib/ld-musl-x86_64.so.1",
            "writable_executable_load": False,
        }

        def download(url, path, bound):
            calls.append(url)
            contents = {
                module.MANIFEST: metadata["manifest"],
                module.SIGNATURE: metadata["signature"],
                module.KEY: metadata["key"],
                review["url"]: vendor,
                module.LICENSE: license_data,
            }[url]
            if bad_metadata and url == module.MANIFEST:
                contents += b"changed"
            self.assertLessEqual(len(contents), bound)
            path.write_bytes(contents)
            return {"sha256": sha(contents), "size": len(contents)}

        def tool(argv, home, bound):
            tools.append(argv)
            self.assertEqual(argv[0], "/usr/bin/gpg")
            self.assertIn("--no-autostart", argv)
            self.assertIn("--disable-dirmngr", argv)
            self.assertNotIn(review["url"], calls)
            return (1 if bad_signature and "--verify" in argv else 0), b"public synthetic GPG status", b""

        for name in ("source", "images", "preparation-evidence"):
            (root / name).mkdir()
        return receipt, module, download, tool, vendor, calls, tools

    def test_vendor_download_follows_key_and_signature_and_never_executes_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, module, download, tool, vendor, calls, tools = self.fake_vendor(root)
            # The license digest is independently pinned in source. A fake
            # license intentionally fails that last gate, after all reader-only
            # steps, and cannot turn these inert bytes into an admitted input.
            with (
                mock.patch.object(version, "inspector", return_value=module),
                mock.patch.object(version, "VENDOR_SHA", sha(vendor)),
                mock.patch.object(version, "VENDOR_SIZE", len(vendor)),
            ):
                with self.assertRaisesRegex(ValueError, "license"):
                    version.reacquire_vendor(root, receipt, download, tool)
            self.assertEqual(len(tools), 3)
            self.assertEqual(calls[:3], [module.MANIFEST, module.SIGNATURE, module.KEY])
            self.assertEqual(calls[-2:], [receipt["claude_version"]["url"], module.LICENSE])
            self.assertEqual((root / "images/claude-musl").read_bytes(), vendor)

    def test_bad_signature_or_metadata_stops_before_vendor_download(self):
        for kind in ("signature", "metadata"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                receipt, module, download, tool, vendor, calls, tools = self.fake_vendor(
                    root, bad_signature=kind == "signature", bad_metadata=kind == "metadata"
                )
                with mock.patch.object(version, "inspector", return_value=module):
                    with self.assertRaises(ValueError):
                        version.reacquire_vendor(root, receipt, download, tool)
                self.assertNotIn(receipt["claude_version"]["url"], calls)
                if kind == "metadata":
                    self.assertEqual(tools, [])

    def loader_metadata(self, data):
        return SimpleNamespace(
            st_dev=11,
            st_ino=22,
            st_mode=stat.S_IFREG | 0o500,
            st_nlink=1,
            st_uid=12345,
            st_gid=12345,
            st_size=len(data),
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

    def test_same_name_loader_is_not_excluded_without_registered_fileid_and_hash(self):
        data = b"fixed public synthetic loader bytes"
        metadata = self.loader_metadata(data)
        registered = {"leaf": version.LOADER_LEAF, "device": 11, "inode": 22, "size": len(data), "sha256": sha(data)}
        with (
            mock.patch.object(version, "LOADER_SIZE", len(data)),
            mock.patch.object(version, "LOADER_SHA", sha(data)),
            mock.patch.object(version.os, "geteuid", return_value=12345, create=True),
            mock.patch.object(version.os, "fstat", return_value=metadata),
            mock.patch.object(version.os, "pread", side_effect=lambda fd, n, at: data[at : at + n], create=True),
        ):
            version.verify_excluded_loader(999, registered)
            for key in registered:
                candidate = dict(registered)
                candidate[key] = None
                with self.subTest(key=key), self.assertRaises(ValueError):
                    version.verify_excluded_loader(999, candidate)
            replaced = copy.copy(metadata)
            replaced.st_ino += 1
            with mock.patch.object(version.os, "fstat", return_value=replaced), self.assertRaises(ValueError):
                version.verify_excluded_loader(999, registered)
            with (
                mock.patch.object(version.os, "pread", return_value=b"x" * len(data), create=True),
                self.assertRaises(ValueError),
            ):
                version.verify_excluded_loader(999, registered)

    def test_collector_omits_only_registered_root_loader_and_copies_public_bytes(self):
        loader, public = b"public synthetic loader", b"public fixed canary\n"
        loader_stat = self.loader_metadata(loader)
        public_stat = copy.copy(loader_stat)
        public_stat.st_ino, public_stat.st_mode, public_stat.st_size = 23, stat.S_IFREG | 0o600, len(public)
        registered = {
            "leaf": version.LOADER_LEAF,
            "device": 11,
            "inode": 22,
            "size": len(loader),
            "sha256": sha(loader),
        }
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            with (
                mock.patch.object(version, "LOADER_SIZE", len(loader)),
                mock.patch.object(version, "LOADER_SHA", sha(loader)),
                mock.patch.object(version.os, "O_NOFOLLOW", 0, create=True),
                mock.patch.object(version.os, "O_CLOEXEC", 0, create=True),
                mock.patch.object(version.os, "O_NONBLOCK", 0, create=True),
                mock.patch.object(version.os, "geteuid", return_value=12345, create=True),
                mock.patch.object(version.os, "listdir", return_value=[version.LOADER_LEAF, "readonly"]),
                mock.patch.object(
                    version.os,
                    "open",
                    side_effect=lambda name, *args, **kwargs: 101 if name == version.LOADER_LEAF else 102,
                ),
                mock.patch.object(version.os, "close"),
                mock.patch.object(
                    version.os, "fstat", side_effect=lambda fd: loader_stat if fd in (101, 999) else public_stat
                ),
                mock.patch.object(
                    version.os,
                    "pread",
                    side_effect=lambda fd, n, at: (loader if fd in (101, 999) else public)[at : at + n],
                    create=True,
                ),
            ):
                budget = [0, 0]
                version.copy_fixture(100, target, 0, budget, registered, 999)
            self.assertEqual(sorted(p.name for p in target.iterdir()), ["readonly"])
            self.assertEqual((target / "readonly").read_bytes(), public)
            self.assertEqual(budget, [2, len(public)])

    def test_loader_manifest_requires_complete_members_and_false_execution_claims(self):
        pin = dict(version.PINS["loader"])
        content = b"public inert manifest fixture"
        value = {
            "repository": version.fixed.REPOSITORY,
            "workflow": pin["workflow"],
            "build_commit": pin["commit"],
            "run_id": str(pin["run"]),
            "run_attempt": "1",
            "scope": "fixed_shared_musl_1_2_6_loader_build_only",
            "build_succeeded": True,
            "loader_or_vendor_execution": False,
            "runtime_admission": False,
            "production_certification": False,
            "files": {"fixed.txt": {"sha256": sha(content), "size": len(content)}},
        }
        for mutation in ("none", "extra", "execute"):
            candidate = copy.deepcopy(value)
            if mutation == "execute":
                candidate["loader_or_vendor_execution"] = True
            raw = json.dumps(candidate).encode()
            pin["provenance"] = sha(raw)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("PROVENANCE.json", raw)
                archive.writestr("fixed.txt", content)
                if mutation == "extra":
                    archive.writestr("extra.txt", b"extra")
            archive = ZipEvidence(stream.getvalue())
            if mutation == "none":
                version.loader_manifest(archive, pin)
            else:
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    version.loader_manifest(archive, pin)

    def test_fixed_tree_file_name_cannot_be_replaced_by_a_directory(self):
        name = "tree-parent.ready"
        metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=12345)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            with (
                mock.patch.object(version.os, "O_NOFOLLOW", 0, create=True),
                mock.patch.object(version.os, "O_CLOEXEC", 0, create=True),
                mock.patch.object(version.os, "O_NONBLOCK", 0, create=True),
                mock.patch.object(version.os, "geteuid", return_value=12345, create=True),
                mock.patch.object(version.os, "listdir", return_value=[name]) as listed,
                mock.patch.object(version.os, "open", return_value=101),
                mock.patch.object(version.os, "close"),
                mock.patch.object(version.os, "fstat", return_value=metadata),
            ):
                with self.assertRaisesRegex(ValueError, "must be a regular file"):
                    version.copy_fixture(100, target, 1, [0, 0], None, 999, ("work",))
                self.assertEqual(listed.call_count, 1)
                self.assertFalse((target / name).exists())


if __name__ == "__main__":
    unittest.main()
