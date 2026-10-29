#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Give LiteLLM's vendored tiktoken rank files their published bytes.

LiteLLM points ``TIKTOKEN_CACHE_DIR`` at its own
``litellm/litellm_core_utils/tokenizers`` folder and loads ``cl100k_base``
when it is imported. tiktoken uses a cached rank file only when its SHA-256
is the one ``tiktoken_ext/openai_public.py`` expects; otherwise it deletes
the file and downloads it again into that folder. The Windows LiteLLM wheel
ships those files with CRLF line ends, so none of them matches. In the
managed Windows scanner runtime the folder is read-only for the gateway
service, and the LLM judge failed with ``[Errno 13] Permission denied`` once
anything had deleted the file (GAP-2395). This rewrites each rank file whose
CRLF form is the only difference back to LF, updates the wheel RECORD, and
fails the build for a rank file that matches no expected hash either way.

Usage: normalize_tiktoken_ranks.py <site-packages>
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

TOKENIZERS = Path("litellm", "litellm_core_utils", "tokenizers")
RANK_NAME = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_HASH = re.compile(r"""expected_hash\s*=\s*["']([0-9a-f]{64})["']""")


def expected_hashes(site: Path) -> set[str]:
    source = site / "tiktoken_ext" / "openai_public.py"
    hashes = set(EXPECTED_HASH.findall(source.read_text(encoding="utf-8")))
    if not hashes:
        raise SystemExit(f"normalize_tiktoken_ranks: {source} lists no expected_hash")
    return hashes


def record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def update_record(site: Path, rewritten: dict[str, bytes]) -> None:
    records = sorted(site.glob("litellm-*.dist-info/RECORD"))
    if len(records) != 1:
        raise SystemExit(f"normalize_tiktoken_ranks: expected one litellm RECORD, found {len(records)}")
    with open(records[0], encoding="utf-8", newline="") as handle:
        lines = handle.read().splitlines(keepends=True)
    seen = set()
    for index, line in enumerate(lines):
        path = line.split(",", 1)[0]
        if path in rewritten:
            data = rewritten[path]
            ending = "\r\n" if line.endswith("\r\n") else "\n"
            lines[index] = f"{path},{record_hash(data)},{len(data)}{ending}"
            seen.add(path)
    missing = sorted(set(rewritten) - seen)
    if missing:
        raise SystemExit(f"normalize_tiktoken_ranks: RECORD does not list {', '.join(missing)}")
    records[0].write_text("".join(lines), encoding="utf-8", newline="")


def normalize(site: Path) -> list[str]:
    folder = site / TOKENIZERS
    if not folder.is_dir():
        raise SystemExit(f"normalize_tiktoken_ranks: {folder} is missing")
    hashes = expected_hashes(site)
    rewritten: dict[str, bytes] = {}
    for path in sorted(folder.iterdir()):
        if not path.is_file() or not RANK_NAME.match(path.name):
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() in hashes:
            continue
        lf = data.replace(b"\r\n", b"\n")
        if hashlib.sha256(lf).hexdigest() not in hashes:
            raise SystemExit(
                f"normalize_tiktoken_ranks: {path} matches no tiktoken expected_hash, with or without CRLF"
            )
        path.write_bytes(lf)
        rewritten[(TOKENIZERS / path.name).as_posix()] = lf
    if rewritten:
        update_record(site, rewritten)
    return sorted(rewritten)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    fixed = normalize(Path(argv[1]))
    print(f"    tiktoken rank files restored to their published bytes: {len(fixed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
