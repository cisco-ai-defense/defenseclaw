# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 13: Policy share/import payload codec.

Python port of ``docs-site/components/policy-creator/lib/share.ts``.

The web UI puts a gzip+base64url blob in the URL fragment
(``#policy=v1.<...>``); the TUI uses the same payload format so a
URL copied from the docs-site Creator pastes cleanly into
``defenseclaw policy import --paste`` and a draft authored in the TUI
can be shared back via the same URL fragment.

Hard limits mirror the TS module:

* ``MAX_PAYLOAD_CHARS`` (~128 KB base64url) - rejected before we
  touch the decompressor so a hostile payload can't allocate runaway
  buffers.
* ``MAX_DECOMPRESSED_BYTES`` (1 MB) - sanity bound against gzip-bomb
  amplification (gzip can hit ~1000:1 on highly compressible input).
"""

from __future__ import annotations

import base64
import dataclasses
import gzip
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, cast

from defenseclaw.tui.creator.types import (
    Policy,
)

VERSION = "v1"
HASH_KEY = "policy"
MAX_PAYLOAD_CHARS = 128_000
MAX_DECOMPRESSED_BYTES = 1_000_000

DecodeFailureReason = Literal["version", "too-large", "malformed", "invalid-shape"]


class DecodeFailure(Enum):
    """Tagged failure reasons - matches the ``DecodeFailure`` union in
    the TS source. The TUI surfaces each reason with its own
    operator-facing copy so the resolution path is unambiguous (paste
    a fresh URL vs install a newer DefenseClaw).
    """

    VERSION = "version"
    TOO_LARGE = "too-large"
    MALFORMED = "malformed"
    INVALID_SHAPE = "invalid-shape"


@dataclass(frozen=True, slots=True)
class DecodeOk:
    policy: Policy
    unknown_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DecodeErr:
    reason: DecodeFailure


DecodeResult = DecodeOk | DecodeErr


# --- Known top-level keys (for "unknown field" surfacing) -------------------
#
# Kept in lockstep with the ``Policy`` dataclass + ``share.ts``'s
# ``KNOWN_POLICY_TOP_LEVEL_KEYS``. A dedicated unit test asserts this
# list matches every field of the bundled ``default`` preset so the
# easy regression (adding a Policy field but forgetting this set) is
# caught at CI rather than silently dropped on import.
KNOWN_POLICY_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "name",
        "description",
        "basedOn",
        "guardrail",
        "admission",
        "firewall",
        "audit",
        "enforcement",
        "watch",
        "severity_matrix",
        "skill_actions",
        "scanner_overrides",
        "scanners",
        "suppressions",
        "sensitive_tools",
        "judges",
        "first_party_allow_list",
        "webhooks",
        "custom_rego",
        "correlator",
        "cisco_ai_defense",
        "rule_pack",
    }
)


def unknown_top_level_keys(value: Any) -> tuple[str, ...]:
    """Surface keys we'd silently drop on emit so the operator can
    decide whether to update the build or accept the data loss.
    """

    if not isinstance(value, dict):
        return ()
    return tuple(k for k in value if k not in KNOWN_POLICY_TOP_LEVEL_KEYS)


def looks_like_policy(value: Any) -> bool:
    """Minimal structural sanity check on parsed JSON.

    Mirrors ``looksLikePolicy`` in the TS source. We deliberately do
    NOT enforce the full schema - older drafts may legitimately omit
    newer fields, and rich-typed validation runs once the policy
    mounts inside the wizard or playground modal.
    """

    if not isinstance(value, dict):
        return False
    name = value.get("name")
    if not isinstance(name, str) or not name:
        return False
    skill_actions = value.get("skill_actions")
    if not isinstance(skill_actions, dict):
        return False
    return True


# --- base64url helpers -----------------------------------------------------


def _bytes_to_base64url(data: bytes) -> str:
    """Base64url encode without padding (mirrors ``btoa`` + replace)."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_to_bytes(payload: str) -> bytes | None:
    """Restore standard base64 padding then decode. Returns ``None``
    on illegal characters so the caller can map to ``MALFORMED``."""

    if not re.fullmatch(r"[A-Za-z0-9_\-]*", payload):
        return None
    pad = (-len(payload)) % 4
    try:
        return base64.urlsafe_b64decode(payload + "=" * pad)
    except Exception:
        return None


# --- Encode ----------------------------------------------------------------


def _serialize_policy(policy: Policy) -> dict[str, Any]:
    """Serialize ``Policy`` into a JSON-safe dict.

    Mirrors what ``JSON.stringify(policy)`` produces in the browser:
    nested dataclasses become objects, ``SeverityActionMatrix``
    dataclass attrs (``critical``, ``high``, ...) become object keys,
    and lists/dicts pass through. Values that aren't already
    JSON-safe (no Python-only types in ``Policy``) are caught by
    ``json.dumps`` raising.
    """

    return cast(dict[str, Any], dataclasses.asdict(policy))


def encode_policy(policy: Policy) -> str:
    """Encode a ``Policy`` as ``v1.<base64url(gzip(json))>``.

    Suitable for pasting into the docs-site Creator's
    ``#policy=`` fragment, copying through chat, or storing as a
    file payload. The TUI's ``defenseclaw policy export --paste``
    surfaces this string verbatim.
    """

    payload = json.dumps(
        _serialize_policy(policy),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    compressed = gzip.compress(payload.encode("utf-8"), mtime=0)
    return f"{VERSION}.{_bytes_to_base64url(compressed)}"


# --- Decode ----------------------------------------------------------------


def _parse_payload(blob: str) -> tuple[str, str] | DecodeErr:
    dot = blob.find(".")
    if dot < 0:
        return DecodeErr(DecodeFailure.MALFORMED)
    return blob[:dot], blob[dot + 1 :]


def _decompress_bounded(data: bytes, max_bytes: int) -> bytes | DecodeErr:
    """Decompress ``data`` with a hard upper bound on the produced
    bytes. We pump fixed-size reads through ``gzip.GzipFile`` and
    bail the moment we cross the cap so a 1000:1 bomb stays
    bounded.
    """

    try:
        with gzip.GzipFile(fileobj=__import__("io").BytesIO(data)) as fh:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return DecodeErr(DecodeFailure.TOO_LARGE)
                chunks.append(chunk)
            return b"".join(chunks)
    except OSError:
        return DecodeErr(DecodeFailure.MALFORMED)


def _hydrate_policy(parsed: dict[str, Any]) -> Policy:
    """Convert a JSON-decoded mapping into a ``Policy`` dataclass.

    Mirrors ``normalizeImportedPolicy`` plus the implicit field
    rehydration that the TS ``Policy`` interface gets for free
    because everything is already an object literal. We use
    ``draft.deserialize`` for the heavy lifting since it already
    knows how to walk every nested field.
    """

    from defenseclaw.tui.creator.draft import policy_from_dict

    return policy_from_dict(parsed)


def normalize_imported_policy(parsed: dict[str, Any]) -> dict[str, Any]:
    """Backfill fields added after share-link v1 shipped.

    Older drafts may legitimately omit ``correlator`` /
    ``cisco_ai_defense`` - we add safe defaults instead of crashing
    when downstream code (emit, validators, sections) reads them.
    Mutates ``parsed`` in place AND returns it so callers can chain.
    """

    if not isinstance(parsed.get("correlator"), list):
        parsed["correlator"] = []

    aid = parsed.get("cisco_ai_defense")
    if not isinstance(aid, dict):
        parsed["cisco_ai_defense"] = {
            "enabled": False,
            "endpoint": "",
            "api_key_env": "",
            "scan_hook_surface": True,
        }
    else:
        parsed["cisco_ai_defense"] = {
            "enabled": bool(aid.get("enabled", False)),
            "endpoint": aid["endpoint"] if isinstance(aid.get("endpoint"), str) else "",
            "api_key_env": (
                aid["api_key_env"]
                if isinstance(aid.get("api_key_env"), str)
                else ""
            ),
            # Default-on: matches the gateway's
            # ``CiscoAIDefenseConfig.HookSurfaceEnabled()``. When AID
            # is disabled the knob is inert; when enabled it inherits
            # the "scan everywhere" default.
            "scan_hook_surface": aid.get("scan_hook_surface") is not False,
        }

    based_on = parsed.get("basedOn")
    if based_on not in ("default", "strict", "permissive"):
        parsed["basedOn"] = "default"

    return parsed


def decode_policy(blob: str) -> DecodeResult:
    """Decode a ``v1.<base64url(gzip(json))>`` blob back into a
    ``Policy``.

    Returns a tagged result so the caller can map each reason to
    operator-facing copy:

    * ``VERSION`` - "this share link was generated by a newer build"
    * ``TOO_LARGE`` - "payload exceeds the safe size cap"
    * ``MALFORMED`` - "could not decode/decompress; check the URL"
    * ``INVALID_SHAPE`` - "decoded but does not look like a Policy"
    """

    head = _parse_payload(blob)
    if isinstance(head, DecodeErr):
        return head
    version, body = head

    if version != VERSION:
        return DecodeErr(DecodeFailure.VERSION)
    if len(body) > MAX_PAYLOAD_CHARS:
        return DecodeErr(DecodeFailure.TOO_LARGE)

    raw = _base64url_to_bytes(body)
    if raw is None:
        return DecodeErr(DecodeFailure.MALFORMED)

    decompressed = _decompress_bounded(raw, MAX_DECOMPRESSED_BYTES)
    if isinstance(decompressed, DecodeErr):
        # Fall back to plain UTF-8 (old browsers without
        # CompressionStream encoded the payload uncompressed).
        if len(raw) > MAX_DECOMPRESSED_BYTES:
            return DecodeErr(DecodeFailure.TOO_LARGE)
        try:
            json_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return decompressed
    else:
        try:
            json_text = decompressed.decode("utf-8")
        except UnicodeDecodeError:
            return DecodeErr(DecodeFailure.MALFORMED)

    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError:
        return DecodeErr(DecodeFailure.MALFORMED)

    if not looks_like_policy(parsed):
        return DecodeErr(DecodeFailure.INVALID_SHAPE)

    unknown = unknown_top_level_keys(parsed)
    parsed = normalize_imported_policy(parsed)
    try:
        policy = _hydrate_policy(parsed)
    except (TypeError, ValueError, KeyError):
        return DecodeErr(DecodeFailure.INVALID_SHAPE)

    return DecodeOk(policy=policy, unknown_keys=unknown)


# --- URL-fragment helpers (parity with the docs-site flow) -----------------


_HASH_PARAM_RE = re.compile(r"(?:^|&)policy=([^&]*)")


def extract_payload_from_hash(hash_text: str) -> str | None:
    """Pull the ``policy=...`` value out of a URL fragment.

    Accepts either a bare fragment (``v1.abc``) or the full key/value
    form the docs-site uses (``policy=v1.abc&utm=foo``). Returns
    ``None`` if nothing matches; callers can then surface
    ``DecodeFailure.MALFORMED`` to the operator.
    """

    cleaned = hash_text.lstrip("#").strip()
    if not cleaned:
        return None
    if "=" not in cleaned:
        # Treat the whole thing as the payload itself.
        return cleaned
    match = _HASH_PARAM_RE.search(cleaned)
    if not match:
        return None
    return match.group(1) or None
