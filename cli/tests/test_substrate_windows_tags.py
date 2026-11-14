# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Substrate Go tests that need a Unix-only fixture carry its build tag.

The Windows x64 Go suite compiles every test of internal/gateway and internal/substrate/kit. A new
internal/gateway/substrate_*_test.go that uses a fixture of a `//go:build !windows` test file (the sandbox
ingress fixtures, newSubstrateFixture) breaks the whole Windows package, which failed 27 shards of a pull request
three times. This test finds that on Linux, in the first Python shard, instead of on the Windows runners.
The actor kit runs in Linux actor images only, so every kit test file is `//go:build linux`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GATEWAY = REPO / "internal" / "gateway"
KIT = REPO / "internal" / "substrate" / "kit"

_BUILD = re.compile(r"^//go:build (.+)$", re.MULTILINE)
_DECL = re.compile(r"^(?:func|type|var|const)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_BLOCK_NAME = re.compile(r"^\t([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|[A-Za-z\[\]*.]+\s*=)", re.MULTILINE)


def _constraint(path: Path) -> str:
    match = _BUILD.search(path.read_text(encoding="utf-8").split("\npackage ", 1)[0])
    return match.group(1).strip() if match else ""


def _declared(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(_DECL.findall(text))


def test_every_kit_test_file_is_linux_only() -> None:
    untagged = [p.name for p in sorted(KIT.glob("*_test.go")) if _constraint(p) != "linux"]
    assert not untagged, f"add //go:build linux to {untagged}: the actor kit refuses other systems"


def test_gateway_substrate_tests_that_use_a_unix_only_fixture_are_tagged() -> None:
    unix_only: dict[str, str] = {}
    for path in sorted(GATEWAY.glob("*_test.go")):
        if _constraint(path) == "!windows":
            for name in _declared(path):
                unix_only.setdefault(name, path.name)
    # Names that are common words are not fixtures; keep the check to fixture-like helpers.
    candidates = {n: f for n, f in unix_only.items() if len(n) > 8}
    offenders: list[str] = []
    for path in sorted(GATEWAY.glob("substrate_*_test.go")):
        if _constraint(path):
            continue
        text = path.read_text(encoding="utf-8")
        own = _declared(path)
        used = sorted(n for n in candidates if n not in own and re.search(rf"\b{re.escape(n)}\b", text))
        if used:
            offenders.append(f"{path.name} uses {used[:3]} from {candidates[used[0]]}")
    assert not offenders, "add //go:build !windows to: " + "; ".join(offenders)
