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
import sys
import tempfile
import unittest
from subprocess import CompletedProcess
from unittest.mock import mock_open, patch

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

    @unittest.skipUnless(sys.platform == "win32", "Windows process snapshot only")
    def test_windows_parent_snapshot_reports_live_parent(self):
        self.assertEqual(
            process_liveness._process_parent_id_windows(os.getpid()),
            os.getppid(),
        )


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

    def test_oversized_pid_file_is_rejected(self):
        self.assertIsNone(read_pid_file(self._write("1" * (process_liveness._MAX_PID_FILE_BYTES + 1))))

    def test_non_utf8_pid_file_is_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".pid", delete=False) as fh:
            fh.write(b"\xff")
            path = fh.name
        self.addCleanup(os.unlink, path)
        self.assertIsNone(read_pid_file(path))

    @unittest.skipIf(os.name == "nt", "symlink creation is not generally available on Windows")
    def test_symlink_pid_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "target.pid")
            link = os.path.join(directory, "gateway.pid")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("4321")
            os.symlink(target, link)
            self.assertIsNone(read_pid_file(link))

    @unittest.skipIf(os.name == "nt", "FIFOs are unavailable on Windows")
    def test_fifo_pid_file_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = os.path.join(directory, "gateway.pid")
            os.mkfifo(fifo)
            self.assertIsNone(read_pid_file(fifo))


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
    def test_macos_fallback_preserves_spaces_in_executable_path(self):
        ps_result = CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="/Users/Test User/.local/bin/defenseclaw-gateway\n",
            stderr="",
        )
        with (
            patch.object(process_liveness.sys, "platform", "darwin"),
            patch("builtins.open", mock_open()) as proc_open,
            patch.object(
                process_liveness.subprocess,
                "run",
                return_value=ps_result,
            ) as run,
        ):
            proc_open.side_effect = FileNotFoundError
            self.assertEqual(
                process_liveness.process_argv0_basename(1234),
                "defenseclaw-gateway",
            )

        run.assert_called_once_with(
            ["/bin/ps", "-p", "1234", "-o", "comm="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            stdin=process_liveness.subprocess.DEVNULL,
            env={"LC_ALL": "C", "LANG": "C"},
        )

    def test_macos_fallback_rejects_near_match_with_spaces(self):
        ps_result = CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="/Users/Test User/.local/bin/defenseclaw-gateway-helper\n",
            stderr="",
        )
        with (
            patch.object(process_liveness.sys, "platform", "darwin"),
            patch("builtins.open", side_effect=FileNotFoundError),
            patch.object(
                process_liveness.subprocess,
                "run",
                return_value=ps_result,
            ) as run,
        ):
            self.assertFalse(process_liveness.process_is_gateway(1234))

        run.assert_called_once_with(
            ["/bin/ps", "-p", "1234", "-o", "comm="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            stdin=process_liveness.subprocess.DEVNULL,
            env={"LC_ALL": "C", "LANG": "C"},
        )

    def test_macos_ps_helper_does_not_inherit_path_or_gateway_token(self):
        ps_result = CompletedProcess(
            args=["/bin/ps"],
            returncode=0,
            stdout="/opt/defenseclaw/defenseclaw-gateway\n",
            stderr="",
        )
        with (
            patch.object(process_liveness.sys, "platform", "darwin"),
            patch("builtins.open", side_effect=FileNotFoundError),
            patch.dict(
                os.environ,
                {
                    "PATH": "/tmp/attacker-controlled",
                    "DEFENSECLAW_GATEWAY_TOKEN": "must-not-reach-ps",
                },
                clear=True,
            ),
            patch.object(
                process_liveness.subprocess,
                "run",
                return_value=ps_result,
            ) as run,
        ):
            self.assertEqual(
                process_liveness.process_argv0_basename(1234),
                "defenseclaw-gateway",
            )

        command = run.call_args.args[0]
        helper_env = run.call_args.kwargs["env"]
        self.assertEqual(command[0], "/bin/ps")
        self.assertEqual(helper_env, {"LC_ALL": "C", "LANG": "C"})
        self.assertNotIn("PATH", helper_env)
        self.assertNotIn("DEFENSECLAW_GATEWAY_TOKEN", helper_env)

    def test_windows_image_path_uses_windows_basename_rules(self):
        with (
            patch.object(process_liveness.sys, "platform", "win32"),
            patch.object(
                process_liveness,
                "_process_image_path_windows",
                return_value=r"C:\Program Files\DefenseClaw\DEFENSECLAW-GATEWAY.EXE",
            ),
        ):
            self.assertEqual(
                process_liveness.process_argv0_basename(1234),
                "defenseclaw-gateway.exe",
            )


if __name__ == "__main__":
    unittest.main()
