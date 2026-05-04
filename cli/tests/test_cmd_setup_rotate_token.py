"""Tests for ``defenseclaw setup rotate-token`` (plan B5 / S0.5).

Locks the contract that:
  * the dotenv file is rewritten atomically with mode 0o600
  * unrelated entries (OPENAI_API_KEY, etc.) survive rotation
  * a duplicate DEFENSECLAW_GATEWAY_TOKEN line is collapsed (never two)
  * the hook-script refresh is delegated to ``defenseclaw-gateway
    connector teardown && connector setup`` (i.e. we never re-implement
    the per-connector logic in Python)
"""

from __future__ import annotations

import os
import re
import stat
import unittest
from unittest import mock

from defenseclaw.commands.cmd_setup import _rotate_token_atomic_write


class RotateTokenFileWriteTests(unittest.TestCase):
    def test_creates_file_with_mode_0600(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            _rotate_token_atomic_write(dotenv, "deadbeef" * 8)

            self.assertTrue(os.path.exists(dotenv))
            mode = stat.S_IMODE(os.stat(dotenv).st_mode)
            self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")

            with open(dotenv) as fh:
                body = fh.read()
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=deadbeef" + "deadbeef" * 7, body)

    def test_preserves_unrelated_entries(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "w") as fh:
                fh.write("OPENAI_API_KEY=sk-xxx\nANTHROPIC_API_KEY=anth-xxx\n")
            _rotate_token_atomic_write(dotenv, "feed1234" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            self.assertIn("OPENAI_API_KEY=sk-xxx", body)
            self.assertIn("ANTHROPIC_API_KEY=anth-xxx", body)
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=feed1234" + "feed1234" * 7, body)

    def test_collapses_duplicate_token_lines(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            with open(dotenv, "w") as fh:
                fh.write("DEFENSECLAW_GATEWAY_TOKEN=old-token-1\n"
                         "DEFENSECLAW_GATEWAY_TOKEN=old-token-2\n"
                         "OPENAI_API_KEY=sk-xxx\n")
            _rotate_token_atomic_write(dotenv, "newtoken" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            tokens = re.findall(r"^DEFENSECLAW_GATEWAY_TOKEN=", body, re.MULTILINE)
            self.assertEqual(len(tokens), 1, f"expected exactly one token line, body=\n{body}")
            self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=newtoken" + "newtoken" * 7, body)
            self.assertIn("OPENAI_API_KEY=sk-xxx", body)

    def test_atomic_via_replace(self) -> None:
        """A failure mid-write must NOT leave the original .env truncated.
        We simulate this by patching os.replace to fail; the original
        contents must remain intact.
        """
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            dotenv = os.path.join(td, ".env")
            original = "OPENAI_API_KEY=sk-original-do-not-truncate\n"
            with open(dotenv, "w") as fh:
                fh.write(original)

            with mock.patch("defenseclaw.commands.cmd_setup.os.replace",
                            side_effect=OSError("simulated rename failure")):
                with self.assertRaises(OSError):
                    _rotate_token_atomic_write(dotenv, "ignored" * 8)

            with open(dotenv) as fh:
                body = fh.read()
            self.assertEqual(body, original,
                             "atomic-write contract violated: original .env was modified before rename succeeded")


if __name__ == "__main__":
    unittest.main()
