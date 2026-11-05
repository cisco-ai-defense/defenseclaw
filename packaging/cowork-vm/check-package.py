#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check a Claude Cowork VM sensor package against the package rules.

Anthropic's EDR integration guide (v1.7, sections 3.3 and 4.6) and our own:
one gzip tar of regular files and folders only, install.sh at the top level,
at most 512 MiB packed and 1 GiB unpacked, plus the layout install.sh needs,
owner 0, no absolute or parent paths, and the architecture and version baked
into install.sh.

    check-package.py [--arch amd64|arm64] [--version V] PACKAGE...

Exit 0 when every package passes, 1 when any rule fails (each one printed).
"""

from __future__ import annotations

import argparse
import gzip
import os
import sys
import tarfile

MAX_PACKED = 512 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024
REQUIRED = {
    "install.sh": 0o755,
    "VERSION": 0o644,
    "config.yaml.tmpl": 0o644,
    "bin/defenseclaw-gateway": 0o755,
    "bin/defenseclaw-sensor-helper": 0o755,
    "licenses/LICENSE": 0o644,
    "licenses/NOTICE": 0o644,
    "licenses/THIRD_PARTY_LICENSES.txt": 0o644,
}
ELF_MACHINE = {"amd64": 0x3E, "arm64": 0xB7}


def check(path: str, arch: str | None, version: str | None) -> list[str]:
    problems: list[str] = []
    packed = os.path.getsize(path)
    if packed > MAX_PACKED:
        problems.append(f"package is {packed} bytes, over the 512 MiB limit")
    with open(path, "rb") as handle:
        if handle.read(2) != b"\x1f\x8b":
            return problems + ["not a gzip file"]
    with gzip.open(path, "rb") as raw:
        header = raw.read(512)
    # ustar, so no pax or GNU extension headers reach the unpacker.
    if header[257:263] != b"ustar\x00":
        problems.append("the archive is not plain ustar")
    unpacked = 0
    members: dict[str, tarfile.TarInfo] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                problems.append(f"{name}: not a regular file or folder (type {member.type!r})")
            if name.startswith(("/", "./")) or ".." in name.split("/") or not name:
                problems.append(f"{name}: not a plain relative path")
            if member.uid != 0 or member.gid != 0:
                problems.append(f"{name}: owner {member.uid}:{member.gid}, want 0:0")
            if member.mode & 0o022:
                problems.append(f"{name}: writable by group or others ({oct(member.mode)})")
            if member.mode & 0o7000:
                problems.append(f"{name}: setuid, setgid or sticky bit")
            key = name.rstrip("/")
            if key in members:
                problems.append(f"{name}: listed twice")
            members[key] = member
            if member.isfile():
                unpacked += member.size
        for name, mode in REQUIRED.items():
            member = members.get(name)
            if member is None or not member.isfile():
                problems.append(f"{name}: missing")
            elif member.mode & 0o777 != mode:
                problems.append(f"{name}: mode {oct(member.mode & 0o777)}, want {oct(mode)}")
        install = members.get("install.sh")
        if install is not None and install.isfile():
            text = archive.extractfile(install).read().decode("utf-8", "replace")
            if "@ARCH@" in text or "@VERSION@" in text:
                problems.append("install.sh: architecture or version not baked in")
            for token in ("@VM_ARCH@", "@SENSOR_VERSION@", "@COLLECTOR@", "@HOMES@", "@POLICY_DIR@"):
                if token not in text:
                    problems.append(f"install.sh: its render step lost the {token} placeholder")
            if arch and f'PKG_ARCH="{arch}"' not in text:
                problems.append(f"install.sh: not built for {arch}")
            if version and f'PKG_VERSION="{version}"' not in text:
                problems.append(f"install.sh: not built for version {version}")
        if arch:
            for name in ("bin/defenseclaw-gateway", "bin/defenseclaw-sensor-helper"):
                member = members.get(name)
                if member is None or not member.isfile():
                    continue
                head = archive.extractfile(member).read(20)
                if head[:4] != b"\x7fELF" or int.from_bytes(head[18:20], "little") != ELF_MACHINE[arch]:
                    problems.append(f"{name}: not a linux/{arch} executable")
    if unpacked > MAX_UNPACKED:
        problems.append(f"unpacked size {unpacked} bytes, over the 1 GiB limit")
    if not problems:
        print(f"{path}: ok ({packed} bytes packed, {unpacked} unpacked, {len(members)} entries)")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--arch", choices=sorted(ELF_MACHINE))
    parser.add_argument("--version")
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()
    failed = False
    for path in args.packages:
        for problem in check(path, args.arch, args.version):
            print(f"{path}: {problem}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
