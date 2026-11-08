# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Which gateway token in ``~/.defenseclaw/.env`` is an adopted copy.

The gateway token lives in ``.env`` under two spellings
(``DEFENSECLAW_GATEWAY_TOKEN`` and ``OPENCLAW_GATEWAY_TOKEN``). When DefenseClaw
adopts the token OpenClaw holds in ``openclaw.json`` it writes both and records
the SHA-256 of what it wrote in a comment line, the marker. A spelling that still
holds that value is an adopted copy. When the other spelling holds a different
value the operator saved it, and the adopted copy must not shadow it: every
``.env`` reader leaves the adopted copy out (GAP-0847). The Go readers do the
same (``internal/envvars/gateway_token_adoption.go``) and the two must agree.

The marker is a comment, so a reader that does not know it, and a file it was
lost from, behave as before: the earlier spelling wins.
"""

from __future__ import annotations

import hashlib
import os

from defenseclaw.connector_paths import is_secret_ref_text
from defenseclaw.file_permissions import dotenv_line_ending

GATEWAY_TOKEN_NAMES = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN")
_MARKER = b"# defenseclaw: adopted gateway token sha256="


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def marker_line(token: str) -> bytes:
    """The ``.env`` comment line that records *token* as the adopted value."""
    return _MARKER + _digest(token).encode("ascii")


def _same_name(left: str, right: str) -> bool:
    return left.upper() == right.upper() if os.name == "nt" else left == right


def is_shadowed(shadowed: set[str], key: str) -> bool:
    """True when *key* names a spelling in *shadowed* (names compare as the platform does)."""
    return any(_same_name(name, key) for name in shadowed)


def with_adopted_marker(body: bytes, token: str) -> bytes:
    """*body* with every marker line replaced by one that records *token*.

    The caller checks the whole result against ``MAX_DOTENV_BYTES`` before it
    publishes anything.
    """
    newline = dotenv_line_ending(body)
    kept = [line for line in body.splitlines(keepends=True) if not line.strip().startswith(_MARKER)]
    out = b"".join(kept)
    if out and not out.endswith((b"\r", b"\n")):
        out += newline
    return out + marker_line(token) + newline


def shadowed_names(body: bytes) -> set[str]:
    """The gateway-token spellings of *body* that hold only the adopted copy
    while the other spelling holds a different value; empty without a marker,
    when the spellings agree, or when neither is an adopted copy."""
    digest = ""
    entries: list[tuple[str, str]] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(b"#"):
            if not digest and line.startswith(_MARKER):
                digest = line[len(_MARKER):].strip().decode("ascii", "replace")
            continue
        raw_key, separator, raw_value = line.partition(b"=")
        if not separator:
            continue
        try:
            key = raw_key.strip().decode("ascii")
            value = raw_value.strip().decode("utf-8")
        except UnicodeError:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("\"", "\x27"):
            value = value[1:-1]
        if not value or is_secret_ref_text(value):
            continue
        for name in GATEWAY_TOKEN_NAMES:
            if _same_name(name, key):
                entries.append((name, value))
    if not digest:
        return set()
    adopted = {name for name, value in entries if _digest(value) == digest}
    explicit = {name for name, value in entries if _digest(value) != digest}
    return adopted - explicit if explicit else set()
