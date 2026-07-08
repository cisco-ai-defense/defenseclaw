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
#
# SPDX-License-Identifier: Apache-2.0

"""Apply or verify Cisco Apache-2.0 headers in the imported macOS app."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

COPYRIGHT = "Copyright 2026 Cisco Systems, Inc. and its affiliates"
SPDX = "SPDX-License-Identifier: Apache-2.0"
BODY = [
    COPYRIGHT,
    "",
    'Licensed under the Apache License, Version 2.0 (the "License");',
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at",
    "",
    "    http://www.apache.org/licenses/LICENSE-2.0",
    "",
    "Unless required by applicable law or agreed to in writing, software",
    'distributed under the License is distributed on an "AS IS" BASIS,',
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License.",
    "",
    SPDX,
]


def line_header(prefix: str) -> str:
    return "\n".join(prefix if not line else f"{prefix} {line}" for line in BODY) + "\n\n"


def markdown_header() -> str:
    return "<!--\n" + "\n".join(BODY) + "\n-->\n\n"


def xml_header() -> str:
    return "<!--\n" + "\n".join(BODY) + "\n-->\n"


def header_for(path: Path) -> str | None:
    if path.suffix == ".swift" or path.suffix == ".xcconfig" or path.name == "project.pbxproj":
        return line_header("//")
    if path.suffix in {".sh", ".py", ".toml"} or path.name == ".gitignore":
        return line_header("#")
    if path.suffix == ".md":
        return markdown_header()
    if path.suffix in {".plist", ".entitlements", ".xcscheme", ".xml"}:
        return xml_header()
    return None


def insertion_offset(path: Path, text: str) -> int:
    first_line_end = text.find("\n") + 1
    if text.startswith("#!") or text.startswith("// !$*UTF8*$!"):
        return first_line_end
    if text.startswith("<?xml"):
        return first_line_end
    return 0


def has_header(text: str) -> bool:
    prefix = "\n".join(text.splitlines()[:28])
    return all(
        marker in prefix
        for marker in (
            COPYRIGHT,
            'Licensed under the Apache License, Version 2.0 (the "License");',
            "http://www.apache.org/licenses/LICENSE-2.0",
            SPDX,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix", action="store_true", help="insert missing headers")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "macos" / "DefenseClawMac",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"macOS app source not found: {root}", file=sys.stderr)
        return 2

    missing: list[Path] = []
    unsupported: list[Path] = []
    asset_manifest = root / "ASSET_LICENSES.md"

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root)
        header = header_for(path)
        if header is None:
            if path.suffix == ".png" or (
                path.name == "Contents.json" and "Assets.xcassets" in relative.parts
            ):
                continue
            unsupported.append(relative)
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            if path.suffix in {".plist", ".entitlements"} and path.read_bytes().startswith(b"bplist"):
                print(f"skipping binary property list (cannot embed a text header): {relative}")
                continue
            print(f"cannot decode text file as UTF-8: {relative}", file=sys.stderr)
            unsupported.append(relative)
            continue
        if has_header(text):
            continue
        if not args.fix:
            missing.append(relative)
            continue
        offset = insertion_offset(path, text)
        path.write_text(text[:offset] + header + text[offset:], encoding="utf-8")

    if not asset_manifest.is_file():
        missing.append(Path("ASSET_LICENSES.md"))

    if unsupported:
        print("macOS app files with no declared license-header policy:", file=sys.stderr)
        for path in unsupported:
            print(f"  {path}", file=sys.stderr)
    if missing:
        print("macOS app files missing Cisco Apache-2.0 headers:", file=sys.stderr)
        for path in missing:
            print(f"  {path}", file=sys.stderr)

    if unsupported or missing:
        return 1
    print("macOS app license headers OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
