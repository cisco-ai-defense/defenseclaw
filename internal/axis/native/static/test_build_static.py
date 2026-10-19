# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Inert closure admission tests: no downloads, compiler or runtime executes."""

import io
import stat
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from static import build_static as build


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as output:
        for name, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))
            else:
                output.addfile(member)
    data.seek(0)
    return tarfile.open(fileobj=data, mode="r:")


def image(ptype=1):
    data = bytearray(128)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 62, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, ptype, 5, 0, 0, 0, len(data), len(data), 4096)
    return bytes(data)


class ClosureAdmissionTests(unittest.TestCase):
    def test_copyright_chain_inventories_intermediate_links_and_refuses_escape_or_cycle(self):
        root = Path(tempfile.gettempdir()).resolve() / "fixed-doc-root"
        links = {root / "compiler": "middle", root / "middle": "base"}

        def metadata(path):
            return SimpleNamespace(st_mode=stat.S_IFLNK if path in links else stat.S_IFREG)

        with (
            patch.object(Path, "resolve", autospec=True, side_effect=lambda path, **_: path),
            patch.object(Path, "lstat", autospec=True, side_effect=metadata),
            patch.object(Path, "readlink", autospec=True, side_effect=lambda path: Path(links[path])),
        ):
            target, chain = build.copyright_chain(root / "compiler" / "copyright", root)
            self.assertEqual(target, root / "base" / "copyright")
            self.assertEqual(chain, [(root / "compiler", "middle"), (root / "middle", "base")])
            for target in ("../../outside", "compiler"):
                links[root / "compiler"] = target
                with self.subTest(target=target), self.assertRaises(RuntimeError):
                    build.copyright_chain(root / "compiler" / "copyright", root)

    def test_copyright_inventory_retains_each_intermediate_package_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            packages = build.Packages(Mock(), Path(directory))
            target = Path("/usr/share/doc/base/copyright")
            chain = [(Path("/usr/share/doc/compiler"), "middle"), (Path("/usr/share/doc/middle"), "base")]
            with (
                patch.object(build, "copyright_chain", return_value=(target, chain)),
                patch.object(packages, "package_for", side_effect=["compiler", "middle"]) as owner,
                patch.object(packages, "add") as add,
            ):
                self.assertEqual(packages.copyright("compiler"), target)
                self.assertEqual([call.args[0] for call in owner.call_args_list], [path for path, _ in chain])
                self.assertEqual(packages.links[str(chain[1][0])], {"target": "base", "package": "middle"})
                add.assert_called_once_with(target)

    def test_empty_prefix_header_is_inventoried_only_with_explicit_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / "inert-empty.h"
            header.write_bytes(b"")
            self.assertEqual(build.record(header, allow_empty=True), {"size": 0, "sha256": build.digest(b"")})
            with self.assertRaises(RuntimeError):
                build.record(header)
            with self.assertRaises(RuntimeError):
                build.raw(header)
            header.write_bytes(b"oversized")
            with self.assertRaises(RuntimeError):
                build.raw(header, 4, allow_empty=True)

    def test_mount_compat_checks_libc_constants_before_selecting_uapi_spelling(self):
        header = build.mount_compat_header().decode()
        self.assertLess(header.index("#include <sys/mount.h>"), header.index("#if MS_NOUSER"))
        self.assertLess(header.index("#error Unexpected musl mount constants"), header.index("#undef MS_NOUSER"))
        self.assertLess(header.index("#undef MS_MGC_VAL"), header.index("#include <linux/mount.h>"))
        self.assertEqual(header.count("#undef "), 3)
        self.assertNotIn("pragma", header)

    def test_only_bounded_regular_entries_below_exact_prefix_admit(self):
        with archive([("fixed", tarfile.DIRTYPE), ("fixed/source.c", tarfile.REGTYPE)]) as value:
            self.assertEqual(len(build.tar_inventory(value, "fixed")), 2)
        cases = [
            [("../escape", tarfile.REGTYPE)],
            [("/fixed/source.c", tarfile.REGTYPE)],
            [("other/source.c", tarfile.REGTYPE)],
            [("fixed/./source.c", tarfile.REGTYPE)],
            [("fixed/a", tarfile.SYMTYPE)],
            [("fixed/a", tarfile.LNKTYPE)],
            [("fixed/a", tarfile.CHRTYPE)],
            [("fixed/a", tarfile.REGTYPE), ("fixed/a", tarfile.REGTYPE)],
            [("fixed/a", tarfile.REGTYPE), ("fixed/a/child", tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), archive(entries) as value, self.assertRaises(RuntimeError):
                build.tar_inventory(value, "fixed")

    def test_privileged_mode_and_oversized_archive_refuse(self):
        for size, mode in ((1, 0o4755), (build.LIMIT + 1, 0o644)):
            member = tarfile.TarInfo("fixed/a")
            member.size, member.mode = size, mode
            with self.subTest(size=size), self.assertRaises(RuntimeError):
                build.tar_inventory([member], "fixed")

    def test_static_elf_refuses_interpreter_dynamic_foreign_and_truncated_headers(self):
        self.assertEqual(build.elf(image())["load_segments"], 1)
        foreign = bytearray(image())
        struct.pack_into("<H", foreign, 18, 183)
        for value in (image(2), image(3), bytes(foreign), image()[:100]):
            with self.subTest(value=value[:20]), self.assertRaises(RuntimeError):
                build.elf(value)

    def test_link_map_requires_exact_owned_static_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            obj, archive_path, foreign = (Path(directory) / name for name in ("owned.o", "libc.a", "foreign.so"))
            for path in (obj, archive_path, foreign):
                path.write_bytes(b"inert")
            expected = {obj, archive_path}
            good = f"LOAD {obj}\nLOAD {archive_path}\n"
            self.assertEqual(len(build.admit_link_map(good, expected)), 2)
            for text in (good + f"LOAD {foreign}\n", f"LOAD {obj}\n", "LOAD relative.a\n", "no inventory"):
                with self.subTest(text=text), self.assertRaises(RuntimeError):
                    build.admit_link_map(text, expected)

    def test_build_environment_is_exact_and_has_no_overrides_or_credentials(self):
        env = build.environment(Path("/fixed-home"))
        self.assertEqual(set(env), {"PATH", "HOME", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH"})
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertFalse({"REALGCC", "LD_PRELOAD", "GITHUB_TOKEN", "CFLAGS", "MAKEFLAGS"} & env.keys())

    def test_redirects_to_other_hosts_or_cleartext_refuse(self):
        import urllib.request

        request = urllib.request.Request("https://musl.libc.org/releases/fixed")
        for url in ("http://musl.libc.org/fixed", "https://unreviewed.invalid/fixed"):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                build.SameHostRedirect().redirect_request(request, None, 302, "fixed", {}, url)

    def test_only_exact_installed_ubuntu_origin_admits(self):
        policy = (
            "fixed:\n  Installed: 1.0\n  Version table:\n *** 1.0 500\n"
            "        500 http://azure.archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n     0.9 500\n"
            "        500 https://unreviewed.invalid/ubuntu noble/main amd64 Packages\n"
        )
        self.assertEqual(len(build.ubuntu_origins(policy, "1.0")), 1)
        for text, version in ((policy, "0.9"), (policy, "2.0"), (policy.replace("noble-updates/", "other/"), "1.0")):
            with self.subTest(version=version), self.assertRaises(RuntimeError):
                build.ubuntu_origins(text, version)

    def test_package_payload_hash_must_match_installed_input(self):
        for value in (b"x", b"altered"):
            with tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory)
                commands = Mock(home=evidence)
                packages = build.Packages(commands, evidence)
                packages.packages = {"fixed": {"deb": "inert.deb", "package": "fixed"}}
                packages.files = {"/fixed/a": {"sha256": build.digest(value), "package": "fixed"}}
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w") as output:
                    member = tarfile.TarInfo("./fixed/a")
                    member.size = 1
                    output.addfile(member, io.BytesIO(b"x"))
                buffer.seek(0)
                process = Mock(stdout=buffer)
                process.wait.return_value = 0
                process.poll.return_value = 0
                with (
                    patch.object(build.subprocess, "Popen", return_value=process),
                    patch.object(packages, "copyright", return_value=evidence / "inert-notice"),
                    patch.object(build.shutil, "copyfile"),
                ):
                    if value == b"x":
                        packages.finish()
                        self.assertTrue((evidence / "UBUNTU-PACKAGES.json").is_file())
                    else:
                        with self.assertRaises(RuntimeError):
                            packages.finish()

    def test_package_link_payload_must_match_installed_target_even_without_regular_inputs(self):
        for target in ("base", "different"):
            with tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory)
                packages = build.Packages(Mock(home=evidence), evidence)
                packages.packages = {"fixed": {"deb": "inert.deb", "package": "fixed"}}
                packages.links = {"/usr/share/doc/fixed": {"target": "base", "package": "fixed"}}
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w") as output:
                    member = tarfile.TarInfo("./usr/share/doc/fixed")
                    member.type, member.linkname = tarfile.SYMTYPE, target
                    output.addfile(member)
                buffer.seek(0)
                process = Mock(stdout=buffer)
                process.wait.return_value, process.poll.return_value = 0, 0
                with (
                    patch.object(build.subprocess, "Popen", return_value=process),
                    patch.object(packages, "copyright", return_value=evidence / "notice"),
                    patch.object(build.shutil, "copyfile"),
                ):
                    if target == "base":
                        packages.finish()
                    else:
                        with self.assertRaises(RuntimeError):
                            packages.finish()

    def test_exact_runner_mirror_file_requires_only_reviewed_ubuntu_urls(self):
        policy = (
            "fixed:\n  Version table:\n *** 1.0 500\n"
            "        500 mirror+file:/etc/apt/apt-mirrors.txt noble-updates/main amd64 Packages\n"
        )
        mapping = b"http://azure.archive.ubuntu.com/ubuntu/\nhttp://security.ubuntu.com/ubuntu/\n"
        self.assertEqual(len(build.ubuntu_origins(policy, "1.0", mapping)), 2)
        prioritized = (
            b"http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
            b"https://archive.ubuntu.com/ubuntu/\tpriority:2\n"
            b"https://security.ubuntu.com/ubuntu/\tpriority:3\n"
        )
        self.assertEqual(len(build.ubuntu_origins(policy, "1.0", prioritized)), 3)
        for candidate in (
            None,
            b"https://unreviewed.invalid/ubuntu\n",
            b"http://archive.ubuntu.com/other\n",
            b"http://archive.ubuntu.com/ubuntu extra\n",
            b"http://archive.ubuntu.com/ubuntu priority:1 unreviewed\n",
            b"http://archive.ubuntu.com/ubuntu priority:arbitrary\n",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                build.ubuntu_origins(policy, "1.0", candidate)
        with self.assertRaises(RuntimeError):
            build.ubuntu_origins(policy.replace("apt-mirrors.txt", "arbitrary.txt"), "1.0", mapping)


if __name__ == "__main__":
    unittest.main()
