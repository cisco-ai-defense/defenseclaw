#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501
"""Build the real-values denylist for the Windows shell corpus (kept OUTSIDE git, mode 600, never printed; counts only).

  mkdenylist.py OUT.jsonl [--old-corpus CORPUS ...] [--person NAME ...]

Sources, all read at run time on the dev host: the ssh config (host aliases, host names, users), `dc-hosts` (aliases, IPs, instance ids), the AWS account id,
the identities found in an earlier, unredacted corpus (EC2AMAZ / WIN computer names, SIDs, the AD DNS domain that follows a computer name, its NetBIOS form,
DOMAIN\\user pairs, UPNs), and --person names (the owner's names). build.py (--denylist) redacts these values and the leak scan fails if one survives.
No real value is written in this file.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess

GENERIC = {"ubuntu", "localhost", "administrator", "ec2-user", "root", "alice", "public", "user", "users", "admin", "system", "guest", "default"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--old-corpus", action="append", default=[])
    ap.add_argument("--person", action="append", default=[])
    ap.add_argument("--ssh-config", default="~/.ssh/config")
    a = ap.parse_args()
    cats: dict[str, set[str]] = {}

    def add(cat: str, v: str, minlen: int = 4) -> None:
        v = v.strip().strip(".,;:()[]\"'`")
        if len(v) >= minlen and v.lower() not in GENERIC:
            cats.setdefault(cat, set()).add(v)

    try:
        with open(os.path.expanduser(a.ssh_config)) as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0].lower() in ("host", "hostname", "user"):
                    for t in p[1:]:
                        if "*" not in t and "." not in t:    # dotted names are public (github.com ...)
                            add({"host": "hostalias", "hostname": "hostalias", "user": "labuser"}[p[0].lower()], t)
    except OSError:
        pass
    reg = subprocess.run(["bash", "-lc", "source ~/dc-eh/bin/dcenv >/dev/null 2>&1; dc-hosts --json 2>/dev/null || dc-hosts 2>/dev/null"],
                         capture_output=True, text=True, timeout=120).stdout
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", reg):
        if all(int(x) < 256 for x in m.group(0).split(".")) and not m.group(0).startswith(("0.", "127.", "255.")):
            add("ip", m.group(0), 7)
    for m in re.finditer(r"\b(?:dc|ip|EC2AMAZ|WIN)-[A-Za-z0-9-]+\b|\bdefenseclaw-[a-z0-9-]+\b", reg):
        add("hostalias", m.group(0))
    for m in re.finditer(r"\bi-[0-9a-f]{17}\b", reg):
        add("instance", m.group(0))
    acct = subprocess.run(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], capture_output=True, text=True).stdout.strip()
    if re.fullmatch(r"\d{12}", acct):
        add("account", acct)
    for p in a.person:
        add("person", p, 3)

    flat: list[str] = []

    def walk(o) -> None:
        if isinstance(o, str):
            flat.append(o)
        elif isinstance(o, list):
            for x in o:
                walk(x)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)

    for path in a.old_corpus:
        with open(path, errors="replace") as f:
            for line in f:
                try:
                    walk(json.loads(line))
                except ValueError:
                    pass
    text = "\n".join(flat)
    for m in re.finditer(r"\bEC2AMAZ-[A-Za-z0-9]+\b|\bWIN-[A-Z0-9]{11}\b", text, re.I):
        add("computername", m.group(0))
    for m in re.finditer(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b", text):
        add("sid", m.group(0))
    for m in re.finditer(r"\bi-[0-9a-f]{17}\b", text):
        if m.group(0) != "i-0123456789abcdef0":
            add("instance", m.group(0))
    doms = {m.group(1).lower() for m in re.finditer(r"\b(?:EC2AMAZ|WIN)-[A-Za-z0-9]+\.((?:[a-z0-9-]+\.)+[a-z]{2,})\b", text, re.I)}
    for d in doms:
        add("labdomain", d)
        add("netbios", d.split(".")[0], 3)
        add("netbios", d.split(".")[0].upper(), 3)
        for m in re.finditer(r"\b[a-z0-9.-]*" + re.escape(d) + r"\b", text, re.I):
            add("labfqdn", m.group(0))
        for m in re.finditer(r"\b([A-Za-z0-9._-]+)@" + re.escape(d) + r"\b", text, re.I):
            add("upn", m.group(0))
            add("labuser", m.group(1), 3)
    nb = {x.lower() for x in cats.get("netbios", set())}
    for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9-]{2,14})\\{1,2}([A-Za-z][A-Za-z0-9._$-]{1,30})\b", text):
        if m.group(1).lower() in nb:
            add("domuser", m.group(0).replace("\\\\", "\\"))
            add("labuser", m.group(2), 3)

    with open(a.out, "w") as f:
        for c, vs in sorted(cats.items()):
            for v in sorted(vs):
                f.write(json.dumps({"cat": c, "v": v}) + "\n")
    os.chmod(a.out, 0o600)
    print({c: len(v) for c, v in sorted(cats.items())})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
