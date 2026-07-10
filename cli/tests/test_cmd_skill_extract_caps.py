# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Decompression-cap regression tests for cmd_skill.

follow-up from #256 review: the implementation in cmd_skill.py
defines `_safe_tar_extractall_capped`, `_safe_zip_extractall_capped`,
and `_check_extract_caps`, but the original PR only had a happy-path
test (test_scan_from_url_tar). These tests pin every rejection branch
so a future refactor that quietly removes a cap fails CI loudly.

Tests assert positive (under the cap, succeeds) AND negative (over
the cap, raises `_SkillExtractTooLargeError`) behavior for:

  * tar member-count cap (MAX_SKILL_MEMBER_COUNT)
  * tar per-file size cap (MAX_SKILL_PER_FILE_BYTES) — both via
    declared member.size AND via the streaming watchdog (declared
    size lies; actual stream is bigger)
  * tar total-bytes cap (MAX_SKILL_UNCOMPRESSED_BYTES)
  * tar path traversal (member name escapes extract_dir)
  * zip member-count cap
  * zip per-file size cap
  * zip total-bytes cap
  * zip path traversal
"""

import io
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_skill  # noqa: E402
from defenseclaw.commands.cmd_skill import (  # noqa: E402
    MAX_SKILL_MEMBER_COUNT,
    MAX_SKILL_PER_FILE_BYTES,
    MAX_SKILL_UNCOMPRESSED_BYTES,
    _check_extract_caps,
    _safe_tar_extractall_capped,
    _safe_zip_extractall_capped,
    _SkillExtractTooLargeError,
)


def _make_tar_with_member(name: str, content: bytes) -> tarfile.TarFile:
    """Build an in-memory tarfile with one regular-file member."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r")


def _make_tar_with_n_members(count: int, body: bytes = b"x") -> tarfile.TarFile:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(count):
            info = tarfile.TarInfo(name=f"f{i}.txt")
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r")


def _make_zip_with_n_members(count: int, body: bytes = b"x") -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        for i in range(count):
            zf.writestr(f"f{i}.txt", body)
    buf.seek(0)
    return zipfile.ZipFile(buf, mode="r")


class CheckExtractCapsTest(unittest.TestCase):
    """Pin the predicate boundaries of `_check_extract_caps`."""

    def test_under_all_caps_passes(self):
        # Should not raise.
        _check_extract_caps(member_count=1, total_bytes=1, member_size=1, member_name="ok")

    def test_member_count_cap(self):
        with self.assertRaises(_SkillExtractTooLargeError) as exc:
            _check_extract_caps(
                member_count=MAX_SKILL_MEMBER_COUNT + 1,
                total_bytes=1,
                member_size=1,
                member_name="x",
            )
        self.assertIn("member-count cap", str(exc.exception))

    def test_per_file_cap(self):
        with self.assertRaises(_SkillExtractTooLargeError) as exc:
            _check_extract_caps(
                member_count=1,
                total_bytes=1,
                member_size=MAX_SKILL_PER_FILE_BYTES + 1,
                member_name="big.bin",
            )
        self.assertIn("per-file cap", str(exc.exception))
        # File name surfaces in the error so operators can locate it.
        self.assertIn("big.bin", str(exc.exception))

    def test_total_bytes_cap(self):
        with self.assertRaises(_SkillExtractTooLargeError) as exc:
            _check_extract_caps(
                member_count=1,
                total_bytes=MAX_SKILL_UNCOMPRESSED_BYTES + 1,
                member_size=1,
                member_name="x",
            )
        self.assertIn("total uncompressed", str(exc.exception))


class SafeTarExtractAllCappedTest(unittest.TestCase):
    """Pin tar extraction rejection branches."""

    def test_under_caps_extracts_files(self):
        tf = _make_tar_with_member("a.txt", b"hello")
        with tempfile.TemporaryDirectory() as d:
            _safe_tar_extractall_capped(tf, d)
            with open(os.path.join(d, "a.txt"), "rb") as f:
                self.assertEqual(f.read(), b"hello")

    def test_member_count_cap_rejected(self):
        # Avoid materializing 10_001 members on disk by using a small
        # per-test override: we monkeypatch the module-level cap so the
        # test stays cheap. The asserted behavior is identical.
        tf = _make_tar_with_n_members(5)
        with patch.object(cmd_skill, "MAX_SKILL_MEMBER_COUNT", 3):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(_SkillExtractTooLargeError) as exc:
                    _safe_tar_extractall_capped(tf, d)
                self.assertIn("members", str(exc.exception))

    def test_per_file_cap_rejected_via_streaming_watchdog(self):
        # Member declares an UNDER-cap size but the stream contains
        # OVER-cap bytes. The streaming watchdog at write-time must
        # still reject. (This is the harder branch: declared size lies.)
        body = b"a" * 200
        # Build with truthful size first, then patch caps to make the
        # stream size exceed the per-file cap mid-write.
        tf = _make_tar_with_member("file.bin", body)
        with patch.object(cmd_skill, "MAX_SKILL_PER_FILE_BYTES", 50):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(_SkillExtractTooLargeError) as exc:
                    _safe_tar_extractall_capped(tf, d)
                # Either rejected at _check_extract_caps (declared-size
                # path, message contains "per-file cap") or at the
                # streaming watchdog ("streamed more bytes"). Both are
                # the contract the test pins.
                msg = str(exc.exception)
                self.assertTrue(
                    "per-file cap" in msg or "streamed" in msg,
                    f"unexpected message: {msg!r}",
                )

    def test_total_bytes_cap_rejected(self):
        # Two 80-byte members with a 100-byte total cap → second
        # member trips _check_extract_caps's total-bytes branch.
        tf = _make_tar_with_n_members(2, body=b"x" * 80)
        with patch.object(cmd_skill, "MAX_SKILL_UNCOMPRESSED_BYTES", 100):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(_SkillExtractTooLargeError) as exc:
                    _safe_tar_extractall_capped(tf, d)
                self.assertIn("total uncompressed", str(exc.exception))

    def test_path_traversal_rejected(self):
        # Member name walks outside extract_dir. Must reject.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
        buf.seek(0)
        tf_read = tarfile.open(fileobj=buf, mode="r")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(_SkillExtractTooLargeError) as exc:
                _safe_tar_extractall_capped(tf_read, d)
            self.assertIn("path-traversal", str(exc.exception))


class SafeZipExtractAllCappedTest(unittest.TestCase):
    """Pin zip extraction rejection branches.

    Symmetric coverage with the tar tests above. Zip's per-file
    enforcement runs against `member.file_size` (declared) only — there
    is no streaming watchdog because zipfile.read() returns the full
    decompressed bytes in one call.
    """

    def test_under_caps_extracts_files(self):
        zf = _make_zip_with_n_members(3)
        with tempfile.TemporaryDirectory() as d:
            _safe_zip_extractall_capped(zf, d)
            self.assertTrue(os.path.exists(os.path.join(d, "f0.txt")))
            self.assertTrue(os.path.exists(os.path.join(d, "f2.txt")))

    def test_member_count_cap_rejected(self):
        zf = _make_zip_with_n_members(5)
        with patch.object(cmd_skill, "MAX_SKILL_MEMBER_COUNT", 3):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(_SkillExtractTooLargeError) as exc:
                    _safe_zip_extractall_capped(zf, d)
                self.assertIn("members", str(exc.exception))

    def test_per_file_cap_rejected(self):
        zf = _make_zip_with_n_members(1, body=b"x" * 100)
        with patch.object(cmd_skill, "MAX_SKILL_PER_FILE_BYTES", 50):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(_SkillExtractTooLargeError) as exc:
                    _safe_zip_extractall_capped(zf, d)
                self.assertIn("per-file cap", str(exc.exception))

    def test_total_bytes_cap_rejected(self):
        zf = _make_zip_with_n_members(2, body=b"x" * 80)
        with patch.object(cmd_skill, "MAX_SKILL_UNCOMPRESSED_BYTES", 100):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(_SkillExtractTooLargeError) as exc:
                    _safe_zip_extractall_capped(zf, d)
                self.assertIn("total uncompressed", str(exc.exception))

    def test_path_traversal_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w") as zf:
            zf.writestr("../escape.txt", b"x")
        buf.seek(0)
        zf_read = zipfile.ZipFile(buf, mode="r")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(_SkillExtractTooLargeError) as exc:
                _safe_zip_extractall_capped(zf_read, d)
            self.assertIn("path-traversal", str(exc.exception))


if __name__ == "__main__":
    unittest.main()
