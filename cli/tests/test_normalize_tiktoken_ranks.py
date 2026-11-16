# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The managed Windows scanner runtime gets LiteLLM's tiktoken rank files with
the bytes tiktoken checks (GAP-2395)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "normalize_tiktoken_ranks.py"
SPEC = importlib.util.spec_from_file_location("normalize_tiktoken_ranks", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ranks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ranks)

CL100K = "9b5ad71b2ce5302211f9c61530b329a4922fc6a4"
O200K = "fb374d419588a4632f3f557e76b4b70aebbca790"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class NormalizeTiktokenRanksTest(unittest.TestCase):
    def _site(self, files: dict[str, bytes], expected: list[bytes]) -> Path:
        site = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(site, ignore_errors=True))
        (site / "tiktoken_ext").mkdir()
        (site / "tiktoken_ext" / "openai_public.py").write_text(
            "".join(f'    expected_hash="{hashlib.sha256(e).hexdigest()}",\n' for e in expected)
        )
        folder = site / ranks.TOKENIZERS
        folder.mkdir(parents=True)
        record = []
        for name, data in files.items():
            (folder / name).write_bytes(data)
            record.append(f"litellm/litellm_core_utils/tokenizers/{name},sha256={_b64(data)},{len(data)}\r\n")
        record.append("litellm/__init__.py,,\r\n")
        info = site / "litellm-1.103.10.dist-info"
        info.mkdir()
        (info / "RECORD").write_text("".join(record), newline="")
        return site

    def test_crlf_rank_files_get_their_published_bytes_and_record(self) -> None:
        cl100k = b"IQ== 0\nIg== 1\n"
        o200k = b"Iw== 0\n"
        site = self._site(
            {
                CL100K: cl100k.replace(b"\n", b"\r\n"),
                O200K: o200k,
                "anthropic_tokenizer.json": b"{\r\n}\r\n",
                "__init__.py": b"",
            },
            [cl100k, o200k],
        )
        self.assertEqual(ranks.normalize(site), [f"litellm/litellm_core_utils/tokenizers/{CL100K}"])
        folder = site / ranks.TOKENIZERS
        self.assertEqual((folder / CL100K).read_bytes(), cl100k)
        self.assertEqual((folder / O200K).read_bytes(), o200k)
        self.assertEqual((folder / "anthropic_tokenizer.json").read_bytes(), b"{\r\n}\r\n")
        record = (site / "litellm-1.103.10.dist-info" / "RECORD").read_bytes().decode()
        self.assertIn(f"litellm/litellm_core_utils/tokenizers/{CL100K},sha256={_b64(cl100k)},{len(cl100k)}\r\n", record)
        self.assertIn("litellm/__init__.py,,\r\n", record)
        # A second run changes nothing.
        self.assertEqual(ranks.normalize(site), [])

    def test_a_rank_file_that_matches_no_hash_fails_the_build(self) -> None:
        site = self._site({CL100K: b"tampered\r\n"}, [b"IQ== 0\n"])
        with self.assertRaises(SystemExit) as raised:
            ranks.normalize(site)
        self.assertIn("matches no tiktoken expected_hash", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
