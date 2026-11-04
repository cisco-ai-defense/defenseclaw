#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check a Claude Cowork package signature against Anthropic's signature rules.

The EDR integration guide (v1.7, section 3.4) refuses a signature that is not
a detached binary OpenPGP signature over the package file, that carries a
notation, a policy URL or a preferred key server, or that expires more than
730 days after it was made (or never). This script parses the signature packet
itself, so the expiry is exact (gpg prints 2y as "2y0d0h0m", which a day-only
reading gets wrong), and cross-checks with `gpg --list-packets` when gpg is
installed. With --package and --public-key it also verifies the signature.

    verify-signature.py SIG [--package PKG --public-key KEY.asc] [--fingerprint FPR]

Exit 0 when every rule passes, 1 when any fails (each one printed), 2 on usage.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

MAX_EXPIRY_SECONDS = 730 * 86400
SUBPACKET_CREATED = 2
SUBPACKET_EXPIRES = 3
FORBIDDEN_SUBPACKETS = {20: "notation", 24: "preferred key server", 26: "policy URL"}
SIGCLASS_BINARY = 0x00


def read_packets(data: bytes) -> list[tuple[int, bytes]]:
    packets, pos = [], 0
    while pos < len(data):
        ctb = data[pos]
        pos += 1
        if not ctb & 0x80:
            raise ValueError("not an OpenPGP packet (armored or corrupt)")
        if ctb & 0x40:  # new format
            tag = ctb & 0x3F
            first = data[pos]
            if first < 192:
                length, pos = first, pos + 1
            elif first < 224:
                length, pos = ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
            elif first == 255:
                length, pos = int.from_bytes(data[pos + 1 : pos + 5], "big"), pos + 5
            else:
                raise ValueError("partial body lengths are not allowed in a signature")
        else:  # old format
            tag = (ctb >> 2) & 0x0F
            kind = ctb & 0x03
            if kind == 3:
                raise ValueError("indeterminate packet length")
            size = (1, 2, 4)[kind]
            length, pos = int.from_bytes(data[pos : pos + size], "big"), pos + size
        if pos + length > len(data):
            raise ValueError("truncated packet")
        packets.append((tag, data[pos : pos + length]))
        pos += length
    return packets


def subpackets(area: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(area):
        first = area[pos]
        if first < 192:
            length, pos = first, pos + 1
        elif first < 255:
            length, pos = ((first - 192) << 8) + area[pos + 1] + 192, pos + 2
        else:
            length, pos = int.from_bytes(area[pos + 1 : pos + 5], "big"), pos + 5
        if length == 0 or pos + length > len(area):
            raise ValueError("malformed signature subpacket")
        out.append((area[pos] & 0x7F, area[pos + 1 : pos + length]))
        pos += length
    return out


def check_rules(data: bytes, now: float) -> tuple[list[str], dict]:
    problems: list[str] = []
    info: dict = {}
    if data.lstrip().startswith(b"-----BEGIN"):
        return ["the signature is ASCII armored; it must be binary"], info
    try:
        packets = read_packets(data)
    except (ValueError, IndexError) as error:
        return [f"cannot parse the signature: {error}"], info
    if len(packets) != 1 or packets[0][0] != 2:
        return [f"want exactly one signature packet, found tags {[t for t, _ in packets]}"], info
    body = packets[0][1]
    version = body[0]
    info["version"] = version
    if version == 4:
        sigclass, hashed_len = body[1], int.from_bytes(body[4:6], "big")
        hashed = body[6 : 6 + hashed_len]
        rest = body[6 + hashed_len :]
        unhashed = rest[2 : 2 + int.from_bytes(rest[0:2], "big")]
    elif version == 6:
        sigclass, hashed_len = body[1], int.from_bytes(body[4:8], "big")
        hashed = body[8 : 8 + hashed_len]
        rest = body[8 + hashed_len :]
        unhashed = rest[4 : 4 + int.from_bytes(rest[0:4], "big")]
    else:
        return [f"signature version {version}; only v4 and v6 signatures are supported"], info
    info["sigclass"] = sigclass
    if sigclass != SIGCLASS_BINARY:
        problems.append(f"signature class 0x{sigclass:02x}; a binary document signature (0x00) is required")
    try:
        hashed_sub, unhashed_sub = subpackets(hashed), subpackets(unhashed)
    except (ValueError, IndexError) as error:
        return problems + [str(error)], info
    for kind, value in hashed_sub + unhashed_sub:
        if kind in FORBIDDEN_SUBPACKETS:
            problems.append(f"the signature carries a {FORBIDDEN_SUBPACKETS[kind]} ({value[:60]!r})")
        if kind == 33 and len(value) > 1:
            info["fingerprint"] = value[1:].hex().upper()
    created = [int.from_bytes(v, "big") for k, v in hashed_sub if k == SUBPACKET_CREATED]
    expires = [int.from_bytes(v, "big") for k, v in hashed_sub if k == SUBPACKET_EXPIRES]
    if len(created) != 1:
        problems.append("the signature has no single hashed creation time")
    elif created[0] > now + 86400:
        problems.append("the signature was made in the future")
    if len(expires) != 1 or expires[0] == 0:
        problems.append("the signature does not expire; it must expire within 730 days")
    elif expires[0] > MAX_EXPIRY_SECONDS:
        problems.append(f"the signature expires {expires[0] / 86400:.2f} days after it was made; at most 730 are allowed")
    elif created and created[0] + expires[0] <= now:
        problems.append("the signature has expired; sign the package again")
    if created and expires:
        info["created"], info["expires_after_days"] = created[0], expires[0] / 86400
    return problems, info


def gpg_cross_check(sig: str) -> list[str]:
    gpg = shutil.which("gpg")
    if gpg is None:
        return []
    with tempfile.TemporaryDirectory() as home:
        result = subprocess.run([gpg, "--homedir", home, "--batch", "--list-packets", sig],
                                capture_output=True, text=True, check=False)
    listing = (result.stdout + result.stderr).lower()
    problems = []
    if listing.count(":signature packet:") != 1:
        problems.append("gpg --list-packets does not show exactly one signature packet")
    for word in ("notation", "policy:", "preferred keyserver"):
        if word in listing:
            problems.append(f"gpg --list-packets shows a {word.rstrip(':')}")
    if "sigclass 0x00" not in listing:
        problems.append("gpg --list-packets does not show sigclass 0x00")
    return problems


def gpg_verify(sig: str, package: str, public_key: str, fingerprint: str | None) -> list[str]:
    gpg = shutil.which("gpg")
    if gpg is None:
        return ["gpg is not installed, so the signature cannot be verified"]
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        imported = subprocess.run([gpg, "--homedir", home, "--batch", "--import", public_key],
                                  capture_output=True, text=True, check=False)
        if imported.returncode != 0:
            return [f"cannot import {public_key}: {imported.stderr.strip()[:200]}"]
        result = subprocess.run([gpg, "--homedir", home, "--batch", "--status-fd", "1", "--verify", sig, package],
                                capture_output=True, text=True, check=False)
    valid = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if result.returncode != 0 or not valid:
        return [f"the signature does not verify {package} with {public_key}"]
    if fingerprint and fingerprint.replace(" ", "").upper() not in (valid[0][2].upper(), valid[0][-1].upper()):
        return [f"signed by {valid[0][2]}, not by the expected key {fingerprint}"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("signature")
    parser.add_argument("--package", help="the package file the signature covers")
    parser.add_argument("--public-key", help="the vendor public key (armored or binary)")
    parser.add_argument("--fingerprint", help="the signing key fingerprint the signature must name")
    args = parser.parse_args()
    if bool(args.package) != bool(args.public_key):
        parser.error("--package and --public-key go together")
    if args.package and os.path.basename(args.signature) != os.path.basename(args.package) + ".sig":
        print(f"{args.signature}: must be named {os.path.basename(args.package)}.sig", file=sys.stderr)
        return 1
    with open(args.signature, "rb") as handle:
        data = handle.read(65537)
    if len(data) > 65536:
        print(f"{args.signature}: larger than 64 KiB, not a detached signature", file=sys.stderr)
        return 1
    problems, info = check_rules(data, time.time())
    if not problems:
        problems += gpg_cross_check(args.signature)
    if not problems and info.get("fingerprint") and args.fingerprint:
        if info["fingerprint"] != args.fingerprint.replace(" ", "").upper():
            problems.append(f"issuer {info['fingerprint']} is not the expected key {args.fingerprint}")
    if not problems and args.package:
        problems += gpg_verify(args.signature, args.package, args.public_key, args.fingerprint)
    for problem in problems:
        print(f"{args.signature}: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"{args.signature}: ok (v{info['version']}, binary, expires {info.get('expires_after_days', 0):.0f} days "
          f"after signing{', verified' if args.package else ''})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
