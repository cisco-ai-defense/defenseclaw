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

"""Unit tests for the shared safety primitives (defenseclaw.safety)."""

from __future__ import annotations

import os
import unittest
import urllib.error
import urllib.request

from defenseclaw.safety import (
    DotenvValueError,
    NoRedirectError,
    SafetyError,
    assert_within_roots,
    build_no_redirect_opener,
    is_symlink,
    is_within_roots,
    reject_symlink,
    sanitize_dotenv_value,
)


class TestRejectSymlink(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def test_regular_file_allowed(self) -> None:
        p = os.path.join(self.tmp, "real")
        with open(p, "w") as fh:
            fh.write("x")
        self.assertFalse(is_symlink(p))
        self.assertEqual(reject_symlink(p), p)

    def test_symlink_rejected(self) -> None:
        target = os.path.join(self.tmp, "target")
        with open(target, "w") as fh:
            fh.write("x")
        link = os.path.join(self.tmp, "link")
        os.symlink(target, link)
        self.assertTrue(is_symlink(link))
        with self.assertRaises(SafetyError):
            reject_symlink(link, what="config")

    def test_missing_path_not_symlink(self) -> None:
        self.assertFalse(is_symlink(os.path.join(self.tmp, "nope")))


class TestWithinRoots(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def test_contained(self) -> None:
        root = os.path.join(self.tmp, "root")
        os.makedirs(os.path.join(root, "a", "b"))
        self.assertTrue(is_within_roots(os.path.join(root, "a", "b"), [root]))
        self.assertTrue(is_within_roots(root, [root]))  # equal to root

    def test_escape_rejected(self) -> None:
        root = os.path.join(self.tmp, "root")
        os.makedirs(root)
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        self.assertFalse(is_within_roots(outside, [root]))
        with self.assertRaises(SafetyError):
            assert_within_roots(outside, [root], what="skill dir")

    def test_symlink_escape_rejected(self) -> None:
        root = os.path.join(self.tmp, "root")
        os.makedirs(root)
        secret = os.path.join(self.tmp, "secret")
        os.makedirs(secret)
        link = os.path.join(root, "link")
        os.symlink(secret, link)
        # realpath of link escapes root, so containment must fail.
        self.assertFalse(is_within_roots(link, [root]))

    def test_sibling_prefix_not_contained(self) -> None:
        # /tmp/x/root must NOT match candidate /tmp/x/root-evil
        root = os.path.join(self.tmp, "root")
        os.makedirs(root)
        evil = os.path.join(self.tmp, "root-evil")
        os.makedirs(evil)
        self.assertFalse(is_within_roots(evil, [root]))


class TestSanitizeDotenvValue(unittest.TestCase):
    def test_plain_value_ok(self) -> None:
        self.assertEqual(sanitize_dotenv_value("abc123"), "abc123")
        self.assertEqual(
            sanitize_dotenv_value("/home/user/.local/bin"), "/home/user/.local/bin"
        )

    def test_newline_rejected(self) -> None:
        with self.assertRaises(DotenvValueError):
            sanitize_dotenv_value("tok\nDEFENSECLAW_DISABLE_REDACTION=1", key="TOKEN")

    def test_carriage_return_rejected(self) -> None:
        with self.assertRaises(DotenvValueError):
            sanitize_dotenv_value("tok\rEVIL=1")

    def test_nul_rejected(self) -> None:
        with self.assertRaises(DotenvValueError):
            sanitize_dotenv_value("tok\x00")


class TestNoRedirectOpener(unittest.TestCase):
    def test_redirect_raises(self) -> None:
        opener = build_no_redirect_opener()
        # Find the no-redirect handler and exercise redirect_request directly.
        nr = next(
            h
            for h in opener.handlers
            if isinstance(h, urllib.request.HTTPRedirectHandler)
        )
        req = urllib.request.Request("https://example.com/a")
        with self.assertRaises(NoRedirectError):
            nr.redirect_request(req, None, 302, "Found", {}, "https://evil.example/b")


if __name__ == "__main__":
    unittest.main()
