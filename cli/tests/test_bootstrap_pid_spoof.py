# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for avarice F-2188 / F-2189 (bootstrap sidecar trusts
any live PID).

The vulnerability allowed a local user to plant ``gateway.pid``
pointing at any long-running unrelated process (e.g. ``/bin/sleep``)
and have ``defenseclaw quickstart`` / ``init`` skip starting the real
sidecar. With the inspect hook defaulting to ``open`` while the
sidecar is down, every tool call would forward uninspected. We now
require the PID's cmdline to advertise a known gateway binary name.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.bootstrap import (  # noqa: E402
    _pid_file_running,
    _pid_looks_like_gateway,
)


class PidLooksLikeGatewayTests(unittest.TestCase):

    def test_known_binary_name_accepted(self):
        """defenseclaw-gateway in argv0 is the canonical gateway."""
        fake_cmdline = b"defenseclaw-gateway\x00--config=/etc/dc.yaml\x00"

        class FakeFile:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *_args):
                return False

            def read(self_inner):
                return fake_cmdline

        with patch("builtins.open", return_value=FakeFile()):
            self.assertTrue(_pid_looks_like_gateway(12345))

    def test_unrelated_binary_rejected(self):
        """A planted PID file pointing at /bin/sleep must be rejected."""
        fake_cmdline = b"/bin/sleep\x000\x00"

        class FakeFile:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *_args):
                return False

            def read(self_inner):
                return fake_cmdline

        with patch("builtins.open", return_value=FakeFile()):
            self.assertFalse(_pid_looks_like_gateway(12345),
                             "F-2188 regression: /bin/sleep accepted as gateway")

    def test_empty_cmdline_rejected(self):
        class FakeFile:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *_args):
                return False

            def read(self_inner):
                return b""

        with patch("builtins.open", return_value=FakeFile()):
            self.assertFalse(_pid_looks_like_gateway(12345))


class PidFileRunningTests(unittest.TestCase):

    def test_pid_zero_rejected(self):
        """PID 0/1 are special and should never be accepted as a gateway."""
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, "gateway.pid")
            with open(pid_file, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"pid": 1}))
            self.assertFalse(_pid_file_running(pid_file),
                             "F-2188 regression: PID 1 accepted")

    def test_negative_pid_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, "gateway.pid")
            with open(pid_file, "w", encoding="utf-8") as fh:
                fh.write("-7")
            self.assertFalse(_pid_file_running(pid_file))


if __name__ == "__main__":
    unittest.main()
