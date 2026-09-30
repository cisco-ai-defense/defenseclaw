# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The installed LiteLLM must load its tokenizers without network access.

LiteLLM points tiktoken at tokenizer files bundled in its wheel. tiktoken
verifies each cached file against a pinned SHA-256 and re-downloads it on a
mismatch, so a wheel whose bundled files were altered (the compiled
win_amd64 wheels from LiteLLM 1.96 on ship them with CRLF line endings)
makes ``import litellm`` fetch from openaipublic.blob.core.windows.net and
fail on offline or egress-restricted machines.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

# The tiktoken encodings LiteLLM bundles, with the hashes tiktoken_ext.openai_public
# checks them against. tiktoken names each cache file after sha1(url).
_BUNDLED_ENCODINGS = {
    "cl100k_base": "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7",
    "o200k_base": "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d",
    "p50k_base": "94b5ca7dff4d00767bc256fdd1b27e5b17361d7b8a5f968547f9f23eb70d2069",
}
_ENCODING_URL = "https://openaipublic.blob.core.windows.net/encodings/{}.tiktoken"


def test_installed_litellm_bundles_tiktoken_files_tiktoken_accepts() -> None:
    spec = importlib.util.find_spec("litellm")
    assert spec is not None and spec.submodule_search_locations
    tokenizers = Path(next(iter(spec.submodule_search_locations))) / "litellm_core_utils" / "tokenizers"
    for name, expected in _BUNDLED_ENCODINGS.items():
        cache_key = hashlib.sha1(_ENCODING_URL.format(name).encode()).hexdigest()
        data = (tokenizers / cache_key).read_bytes()
        crlf_lines = data.count(b"\r\n")
        assert hashlib.sha256(data).hexdigest() == expected, (
            f"{name}: bundled tokenizer does not match tiktoken's hash "
            f"({crlf_lines} CRLF lines); tiktoken would re-download it"
        )


_NO_NETWORK_IMPORT = textwrap.dedent(
    """
    import socket
    import sys

    attempts = []

    def _blocked(*args, **kwargs):
        attempts.append(repr(args[:2]))
        raise OSError("network disabled by test")

    socket.getaddrinfo = _blocked
    socket.create_connection = _blocked
    socket.socket.connect = _blocked
    socket.socket.connect_ex = _blocked

    import litellm
    import tiktoken

    import defenseclaw.llm
    import defenseclaw.scanner.mcp
    import defenseclaw.scanner.skill
    import skill_scanner
    if sys.version_info >= (3, 11):
        import mcpscanner

    for name in ("cl100k_base", "o200k_base", "p50k_base"):
        tiktoken.get_encoding(name)

    if attempts:
        sys.exit("network attempted: " + ", ".join(attempts))
    """
)


def test_importing_scanner_stack_makes_no_network_calls() -> None:
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"TIKTOKEN_CACHE_DIR", "CUSTOM_TIKTOKEN_CACHE_DIR", "DATA_GYM_CACHE_DIR"}
    }
    # LiteLLM's model cost map refresh is a separate, documented opt-out that
    # falls back to the bundled copy; this test covers the tokenizer path.
    env["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    cli_dir = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (cli_dir, env.get("PYTHONPATH"))))
    result = subprocess.run(
        [sys.executable, "-c", _NO_NETWORK_IMPORT],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
