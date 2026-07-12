#!/usr/bin/env python3
"""Generate the pinned Unicode 13.0 hash-v1 scalar repertoire.

The generator is intentionally offline: download the official DerivedAge file
separately, then pass its local path with ``--source``.  The pinned digest keeps
an unexpected or modified input from changing the cross-language contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

UNICODE_VERSION = "13.0.0"
SOURCE_URL = "https://www.unicode.org/Public/13.0.0/ucd/DerivedAge.txt"
SOURCE_SHA256 = "e779a443d3aa2a3166a15becaa2b737c922480e32c0453d5956093633555078f"
SURROGATE_FIRST = 0xD800
SURROGATE_LAST = 0xDFFF
MAX_SCALAR = 0x10FFFF


def _parse_ranges(source: bytes) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for raw_line in source.decode("utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ";" not in line:
            continue
        codepoints, raw_age = (part.strip() for part in line.split(";", 1))
        try:
            age = tuple(int(part) for part in raw_age.split("."))
        except ValueError:
            continue
        if age > (13, 0):
            continue
        if ".." in codepoints:
            raw_first, raw_last = codepoints.split("..", 1)
            first, last = int(raw_first, 16), int(raw_last, 16)
        else:
            first = last = int(codepoints, 16)

        # Unicode scalar values exclude the surrogate range.  DerivedAge also
        # carries an age for surrogates, so split explicitly rather than relying
        # on the source file's current line boundaries.
        if first < SURROGATE_FIRST:
            ranges.append((first, min(last, SURROGATE_FIRST - 1)))
        if last > SURROGATE_LAST:
            ranges.append((max(first, SURROGATE_LAST + 1), last))

    ranges.sort()
    merged: list[tuple[int, int]] = []
    for first, last in ranges:
        if not 0 <= first <= last <= MAX_SCALAR:
            raise ValueError("DerivedAge contains an invalid scalar range")
        if merged and first <= merged[-1][1]:
            raise ValueError("DerivedAge contains overlapping assigned ranges")
        if merged and first == merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], last)
        else:
            merged.append((first, last))
    return merged


def _encoded_ranges(ranges: list[tuple[int, int]]) -> list[str]:
    return [f"{first:06X}-{last:06X}" for first, last in ranges]


def _ranges_from_manifest(path: Path) -> list[tuple[int, int]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        encoded_ranges = document["ranges"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as error:
        raise SystemExit(f"cannot load the checked-in Unicode repertoire manifest: {path}") from error
    if not isinstance(encoded_ranges, list) or not encoded_ranges:
        raise SystemExit("Unicode repertoire manifest ranges must be a non-empty list")

    ranges: list[tuple[int, int]] = []
    for encoded in encoded_ranges:
        if (
            not isinstance(encoded, str)
            or len(encoded) != 13
            or encoded[6] != "-"
            or any(character not in "0123456789ABCDEF" for character in encoded[:6] + encoded[7:])
        ):
            raise SystemExit("Unicode repertoire manifest contains a non-canonical range")
        first, last = int(encoded[:6], 16), int(encoded[7:], 16)
        if not 0 <= first <= last <= MAX_SCALAR:
            raise SystemExit("Unicode repertoire manifest contains an invalid scalar range")
        if first <= SURROGATE_LAST and last >= SURROGATE_FIRST:
            raise SystemExit("Unicode repertoire manifest contains a surrogate")
        if ranges and first <= ranges[-1][1] + 1:
            raise SystemExit("Unicode repertoire manifest ranges are overlapping or not compacted")
        ranges.append((first, last))
    return ranges


def _range_digest(encoded: list[str]) -> str:
    canonical = "".join(f"{item}\n" for item in encoded).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _manifest(ranges: list[tuple[int, int]]) -> str:
    encoded = _encoded_ranges(ranges)
    document = {
        "schema_version": 1,
        "unicode_version": UNICODE_VERSION,
        "source": SOURCE_URL,
        "source_sha256": SOURCE_SHA256,
        "range_encoding": "inclusive uppercase six-digit hexadecimal START-END",
        "range_digest_canonicalization": "each encoded range followed by LF",
        "range_sha256": _range_digest(encoded),
        "scalar_count": sum(last - first + 1 for first, last in ranges),
        "ranges": encoded,
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def _go_source(ranges: list[tuple[int, int]]) -> str:
    encoded = _encoded_ranges(ranges)
    entries = "\n".join(f"\t{{first: 0x{first:06X}, last: 0x{last:06X}}}," for first, last in ranges)
    return f'''// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by scripts/generate_unicode13_repertoire.py; DO NOT EDIT.

package redaction

import "sort"

const unicode13RangesSHA256 = "{_range_digest(encoded)}"

type unicode13Range struct {{
\tfirst rune
\tlast  rune
}}

var unicode13Ranges = [...]unicode13Range{{
{entries}
}}

func isUnicode13Repertoire(value string) bool {{
\tfor _, scalar := range value {{
\t\tindex := sort.Search(len(unicode13Ranges), func(index int) bool {{
\t\t\treturn unicode13Ranges[index].last >= scalar
\t\t}})
\t\tif index == len(unicode13Ranges) || unicode13Ranges[index].first > scalar {{
\t\t\treturn false
\t\t}}
\t}}
\treturn true
}}
'''


def _python_source(ranges: list[tuple[int, int]]) -> str:
    encoded = _encoded_ranges(ranges)
    entries = "\n".join(f"    (0x{first:06X}, 0x{last:06X})," for first, last in ranges)
    return f'''"""Pinned Unicode 13.0 scalar repertoire for observability hash-v1.

Code generated by scripts/generate_unicode13_repertoire.py; DO NOT EDIT.
"""

from __future__ import annotations

_UNICODE13_RANGES_SHA256 = "{_range_digest(encoded)}"

_UNICODE13_RANGES: tuple[tuple[int, int], ...] = (
{entries}
)


def _is_unicode13_repertoire(value: str) -> bool:
    for character in value:
        scalar = ord(character)
        low = 0
        high = len(_UNICODE13_RANGES)
        while low < high:
            middle = (low + high) // 2
            if _UNICODE13_RANGES[middle][1] < scalar:
                low = middle + 1
            else:
                high = middle
        if low == len(_UNICODE13_RANGES) or _UNICODE13_RANGES[low][0] > scalar:
            return False
    return True
'''


def _write_or_check(path: Path, content: str, check: bool) -> None:
    if check:
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise SystemExit(f"generated file is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, help="local official DerivedAge-13.0.0.txt")
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()

    repository = arguments.repository.resolve()
    manifest_path = repository / "schemas/telemetry/v8/redaction/unicode-age-13.0.json"
    if arguments.source is not None:
        source = arguments.source.read_bytes()
        if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
            raise SystemExit("DerivedAge source digest does not match the pinned Unicode 13.0 file")
        ranges = _parse_ranges(source)
    elif arguments.check:
        # Clean checkouts do not need a network fetch or a separately retained
        # copy of DerivedAge.  The checked-in manifest carries the source
        # identity; exact manifest regeneration below verifies all metadata,
        # the canonical range digest, scalar count, and compact range encoding.
        ranges = _ranges_from_manifest(manifest_path)
    else:
        parser.error("--source is required unless --check is used")

    _write_or_check(
        manifest_path,
        _manifest(ranges),
        arguments.check,
    )
    _write_or_check(
        repository / "internal/observability/redaction/unicode13.go",
        _go_source(ranges),
        arguments.check,
    )
    _write_or_check(
        repository / "cli/defenseclaw/observability/unicode13.py",
        _python_source(ranges),
        arguments.check,
    )


if __name__ == "__main__":
    main()
