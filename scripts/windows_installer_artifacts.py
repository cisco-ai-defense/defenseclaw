#!/usr/bin/env python3
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

"""Foreign-PE checks for the Windows x64 standalone scanner runtime.

packaging/windows/standalone/build-scanner-runtime.sh runs this helper to
remove the listed non-x64 portable executables from the unpacked wheels and to
refuse a runtime tree that still holds any. It uses only the Python standard
library.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path


class ArtifactError(RuntimeError):
    """Raised when a runtime tree violates the Windows x64 release contract."""


#: Windows PE machine type of the only architecture Setup installs.
IMAGE_FILE_MACHINE_AMD64 = 0x8664

#: Non-x64 portable executables a pinned wheel ships that the Windows x64
#: runtime never runs, removed on purpose (Setup refuses any non-x64 PE in its
#: payload). pip, which MCP Scanner 4.8 pulls in through pip-audit, vendors
#: distlib's script launchers for every Windows architecture; on x64 CPython
#: distlib only uses t64.exe and w64.exe, which stay. Any other non-x64 PE
#: fails the build here instead of failing Setup on a user's machine.
FOREIGN_PE_REMOVALS = frozenset(
    {
        "pip/_vendor/distlib/t32.exe",
        "pip/_vendor/distlib/t64-arm.exe",
        "pip/_vendor/distlib/w32.exe",
        "pip/_vendor/distlib/w64-arm.exe",
    }
)


def _pe_machine(path: Path) -> int | None:
    """The PE header's machine type, or ``None`` when *path* is not a PE."""

    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            return None
        offset = int.from_bytes(header[0x3C:0x40], "little", signed=True)
        if offset < 0:
            return None
        stream.seek(offset)
        signature = stream.read(6)
    if len(signature) < 6 or signature[:4] != b"PE\0\0":
        return None
    return int.from_bytes(signature[4:6], "little")


def _portable_executables(root: Path) -> tuple[int, list[tuple[str, int]]]:
    """Count the PEs under *root* and list the non-x64 ones.

    Files are read the way an archive step reads them (a symlink counts as the
    file it names), so nothing that is shipped escapes the check.
    """

    inspected = 0
    foreign: list[tuple[str, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        machine = _pe_machine(path)
        if machine is None:
            continue
        inspected += 1
        if machine != IMAGE_FILE_MACHINE_AMD64:
            foreign.append((path.relative_to(root).as_posix(), machine))
    return inspected, foreign


def prune_foreign_portable_executables(root: Path) -> dict[str, object]:
    """Remove the listed non-x64 PEs from site-packages and repair RECORD.

    Raises ``ArtifactError`` for a non-x64 PE that is not listed, so a new
    one is a reviewed decision rather than a Setup failure.
    """

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ArtifactError(f"site-packages root is not a directory: {root}")
    removed: list[str] = []
    unexpected: list[str] = []
    for relative, machine in _portable_executables(root)[1]:
        if relative in FOREIGN_PE_REMOVALS:
            (root / relative).unlink()
            removed.append(relative)
        else:
            unexpected.append(f"{relative} (machine 0x{machine:04x})")
    if unexpected:
        raise ArtifactError(
            "non-x64 portable executables in the Windows x64 runtime (Setup refuses them): "
            + ", ".join(unexpected)
        )
    removed_set = set(removed)
    rewritten_records = 0
    for record in sorted(root.glob("*.dist-info/RECORD")):
        rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8-sig"))))
        retained = [row for row in rows if not (row and row[0].replace("\\", "/") in removed_set)]
        if len(retained) == len(rows):
            continue
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(retained)
        record.write_text(output.getvalue(), encoding="utf-8", newline="\n")
        rewritten_records += 1
    return {"removed_foreign_pe": removed, "rewritten_records": rewritten_records}


def refuse_foreign_portable_executables(root: Path) -> dict[str, int]:
    """Fail unless every PE in a whole runtime tree is Windows x64.

    The last check before a Windows x64 runtime is archived (the standalone
    scanner runtime, rel-1-0-6:GAP-0107): it removes nothing, and a tree with
    no PE at all is refused as the wrong root.
    """

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ArtifactError(f"runtime root is not a directory: {root}")
    inspected, foreign = _portable_executables(root)
    if foreign:
        raise ArtifactError(
            "non-x64 portable executables in the Windows x64 runtime (Setup refuses them): "
            + ", ".join(f"{relative} (machine 0x{machine:04x})" for relative, machine in foreign)
        )
    if not inspected:
        raise ArtifactError(f"no portable executable under {root}: not a Windows runtime")
    return {"x64_pe": inspected}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prune_parser = subparsers.add_parser(
        "prune-foreign-pe", help="remove the listed non-x64 PEs from site-packages; refuse any other"
    )
    prune_parser.add_argument("--root", type=Path, required=True)

    x64_parser = subparsers.add_parser(
        "check-x64-pe", help="refuse a runtime tree that holds any non-x64 PE"
    )
    x64_parser.add_argument("--root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "prune-foreign-pe":
            result = prune_foreign_portable_executables(args.root)
        else:
            result = refuse_foreign_portable_executables(args.root)
    except (ArtifactError, OSError, ValueError) as exc:
        raise SystemExit(f"windows installer artifact error: {exc}") from exc
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
