# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Inert synthetic archive regressions; no tools or runtime images execute."""

import gzip
import io
import lzma
import stat
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import artifact_archive as archive


def zipped(names):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as output:
        for name, value in names:
            output.writestr(name, value)
    return data.getvalue()


def tarred(names, *, kind=tarfile.REGTYPE):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.GNU_FORMAT) as output:
        for name, value in names:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(value) if kind == tarfile.REGTYPE else 0
            output.addfile(member, io.BytesIO(value) if member.size else None)
    return data.getvalue()


def deb(data, name="data.tar.xz"):
    out = bytearray(b"!<arch>\n")
    for label, value in [("debian-binary", b"2.0\n"), ("control.tar.gz", b"fixed"), (name, data)]:
        out.extend(f"{label + '/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(value):<10}`\n".encode())
        out.extend(value)
        if len(value) & 1:
            out.extend(b"\n")
    return bytes(out)


class ArchiveTests(unittest.TestCase):
    def test_nested_streams_share_one_aggregate_decoded_budget(self):
        budget = archive.DecodeBudget(8)
        one = archive.BoundedReader(io.BytesIO(b"first"), budget=budget)
        self.assertEqual(one.read(5), b"first")
        two = archive.BoundedReader(io.BytesIO(b"second"), budget=budget)
        with self.assertRaises(ValueError):
            two.read(6)

    def test_json_refuses_duplicate_nonfinite_and_nonobject_values(self):
        self.assertEqual(archive.json_object(b'{"fixed":1}'), {"fixed": 1})
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b"[]"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                archive.json_object(raw)

    def test_zip_refuses_alias_traversal_links_and_file_ancestors(self):
        for names in [
            [("../x", b"a")],
            [("a:b", b"a")],
            [("a", b"a"), ("A", b"a")],
            [("a", b"a"), ("a/b", b"a")],
        ]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                archive.ZipEvidence(zipped(names))
        with self.assertRaises(ValueError):
            archive.ZipEvidence(zipped([("axb", b"a")]).replace(b"axb", b"a\\b"))
        member = zipfile.ZipInfo("link")
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            archive.ZipEvidence(zipped([(member, b"target")]))

    def test_zip_count_total_and_member_bounds_are_effective(self):
        raw = zipped([("one", b"a" * 20), ("two", b"b")])
        with patch.object(archive, "MEMBER_LIMIT", 1), self.assertRaises(ValueError):
            archive.ZipEvidence(raw)
        with patch.object(archive, "TOTAL_LIMIT", 20), self.assertRaises(ValueError):
            archive.ZipEvidence(raw)
        value = archive.ZipEvidence(raw)
        with self.assertRaises(ValueError):
            value.read("one", 10)
        with self.assertRaises(ValueError):
            archive.ZipEvidence(zipped([("unexpected-directory/", b"")]))

    def test_zip_member_bound_precedes_zipfile_member_allocation_and_rejects_false_count(self):
        many = zipped([(f"fixed-{index}", b"") for index in range(16385)])
        false_count = bytearray(many)
        struct.pack_into("<HH", false_count, len(false_count) - 14, 1, 1)
        zip64 = bytearray(zipped([("one", b"fixed")]))
        struct.pack_into("<HH", zip64, len(zip64) - 14, 0xFFFF, 0xFFFF)
        for raw in (many, bytes(false_count), bytes(zip64)):
            with (
                self.subTest(size=len(raw)),
                patch.object(archive.zipfile, "ZipFile") as parse,
                self.assertRaises(ValueError),
            ):
                archive.ZipEvidence(raw)
            parse.assert_not_called()

    def test_bounded_ordinary_read_and_reparse_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixed"
            path.write_bytes(b"tiny")
            with patch.object(Path, "open", return_value=io.BytesIO(b"x" * 17)), self.assertRaises(ValueError):
                archive.ordinary(path, 16)
            with (
                patch.object(
                    Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
                ),
                self.assertRaises(ValueError),
            ):
                archive.ordinary(path)

    def test_tar_regular_and_bounded_gnu_longname(self):
        name = "source/" + "x" * 120
        self.assertEqual(archive.tar_files(io.BytesIO(tarred([(name, b"public")])), {name}), {name: b"public"})
        with patch.object(archive, "MEMBER_LIMIT", 1), self.assertRaises(ValueError):
            archive.tar_files(io.BytesIO(tarred([(name, b"public")])), {name})

    def test_tar_captures_bounded_link_metadata_without_host_traversal(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w", format=tarfile.GNU_FORMAT) as output:
            for name, target, kind in [
                ("./usr/share/doc/compiler", "compiler-base", tarfile.SYMTYPE),
                ("./usr/share/doc/hard/copyright", "usr/share/doc/compiler-base/copyright", tarfile.LNKTYPE),
            ]:
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, target
                output.addfile(member)
        links = {}
        self.assertEqual(archive.tar_files(io.BytesIO(data.getvalue()), set(), links=links), {})
        self.assertEqual(
            links,
            {
                "usr/share/doc/compiler": (b"2", "compiler-base"),
                "usr/share/doc/hard/copyright": (b"1", "usr/share/doc/compiler-base/copyright"),
            },
        )
        malformed = data.getvalue().replace(b"compiler-base", b"compiler:base")
        # Restore the first header checksum after the fixed-length target edit.
        header = bytearray(malformed[:512])
        header[148:156] = b" " * 8
        header[148:156] = f"{sum(header):06o}\0 ".encode()
        with self.assertRaises(ValueError):
            archive.tar_files(io.BytesIO(bytes(header) + malformed[512:]), set(), links={})

    def test_tar_refuses_duplicates_traversal_required_links_and_bad_tail(self):
        cases = [
            tarred([("x", b"a"), ("./x", b"b")]),
            tarred([("../x", b"a")]),
            tarred([("x", b"")], kind=tarfile.SYMTYPE),
            tarred([("x", b"a")]) + b"bad",
        ]
        for raw in cases:
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                archive.tar_files(io.BytesIO(raw), {"x"})

    def test_tar_refuses_truncation_checksum_and_decompressed_overflow(self):
        raw = tarred([("x", b"abc")])
        for bad in (raw[:600], b"!" + raw[1:]):
            with self.subTest(bad=bad[:10]), self.assertRaises(ValueError):
                archive.tar_files(io.BytesIO(bad), {"x"})
        with patch.object(archive, "TOTAL_LIMIT", 1024), self.assertRaises(ValueError):
            archive.tar_files(archive.BoundedReader(io.BytesIO(raw), 1024), {"x"})

    def test_deb_xz_gzip_and_zstd_are_read_as_data_only(self):
        raw = tarred([("./usr/include/fixed.h", b"public")])
        cases = [("data.tar.xz", lzma.compress(raw)), ("data.tar.gz", gzip.compress(raw))]
        try:
            from compression import zstd
        except ImportError:
            zstd = None
        if zstd is not None:
            cases.append(("data.tar.zst", zstd.compress(raw)))
        for name, compressed in cases:
            with self.subTest(name=name), archive.deb_data(deb(compressed, name)) as stream:
                self.assertEqual(archive.tar_files(stream, {"usr/include/fixed.h"}), {"usr/include/fixed.h": b"public"})

    def test_deb_unknown_codec_truncation_and_duplicate_member_refuse(self):
        good = deb(lzma.compress(tarred([("x", b"a")])))
        for raw in (good[:-2], good.replace(b"data.tar.xz/", b"data.tar.zz/"), good + good[8:]):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                archive.deb_data(raw)

    def test_xz_reader_refuses_truncated_and_concatenated_streams(self):
        compressed = lzma.compress(b"fixed")
        for raw in (compressed[:-4], compressed + compressed):
            with self.subTest(raw=raw[:10]), self.assertRaises(ValueError):
                archive.LzmaReader(io.BytesIO(raw)).read(20)


if __name__ == "__main__":
    unittest.main()
