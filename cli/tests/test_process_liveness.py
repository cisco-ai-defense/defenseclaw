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

"""Tests for cross-platform PID liveness used by the gateway lifecycle."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw import process_liveness
from defenseclaw.process_liveness import pid_alive, pid_file_alive, read_pid_file


class TestPidAlive(unittest.TestCase):
    def test_own_process_is_alive(self):
        self.assertTrue(pid_alive(os.getpid()))

    def test_nonexistent_pid_is_dead(self):
        # A very high PID is overwhelmingly unlikely to be live.
        self.assertFalse(pid_alive(999_999_999))

    def test_non_positive_pids_are_dead(self):
        # 0 and negatives are signal/process-group sentinels, never daemon PIDs.
        self.assertFalse(pid_alive(0))
        self.assertFalse(pid_alive(-1))


class TestReadPidFile(unittest.TestCase):
    def _write(self, content: str) -> str:
        fh = tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False)
        fh.write(content)
        fh.flush()
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_missing_file(self):
        self.assertIsNone(read_pid_file("/nonexistent/gateway.pid"))

    def test_bare_integer(self):
        self.assertEqual(read_pid_file(self._write("4321")), 4321)

    def test_json_object(self):
        path = self._write(json.dumps({"pid": 5678, "executable": "/x"}))
        self.assertEqual(read_pid_file(path), 5678)

    def test_empty_file(self):
        self.assertIsNone(read_pid_file(self._write("")))

    def test_garbage(self):
        self.assertIsNone(read_pid_file(self._write("not-a-number")))

    def test_json_without_pid_key(self):
        self.assertIsNone(read_pid_file(self._write(json.dumps({"foo": 1}))))


class TestPidFileAlive(unittest.TestCase):
    def _write(self, content: str) -> str:
        fh = tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False)
        fh.write(content)
        fh.flush()
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_alive_for_own_pid_bare(self):
        self.assertTrue(pid_file_alive(self._write(str(os.getpid()))))

    def test_alive_for_own_pid_json(self):
        self.assertTrue(pid_file_alive(self._write(json.dumps({"pid": os.getpid()}))))

    def test_dead_for_stale_pid(self):
        self.assertFalse(pid_file_alive(self._write("999999999")))

    def test_dead_for_missing_file(self):
        self.assertFalse(pid_file_alive("/nonexistent/gateway.pid"))


class TestProcessIdentity(unittest.TestCase):
    def test_windows_image_path_uses_windows_basename_rules(self):
        with patch.object(process_liveness.sys, "platform", "win32"), patch.object(
            process_liveness,
            "_process_image_path_windows",
            return_value=r"C:\Program Files\DefenseClaw\DEFENSECLAW-GATEWAY.EXE",
        ):
            self.assertEqual(
                process_liveness.process_argv0_basename(1234),
                "defenseclaw-gateway.exe",
            )


if __name__ == "__main__":
    unittest.main()
