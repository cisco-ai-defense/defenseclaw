# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``creator/share.py`` (Phase 13 - codec)."""

from __future__ import annotations

import dataclasses
import gzip
import json

import pytest

from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.share import (
    DecodeErr,
    DecodeFailure,
    DecodeOk,
    KNOWN_POLICY_TOP_LEVEL_KEYS,
    MAX_DECOMPRESSED_BYTES,
    MAX_PAYLOAD_CHARS,
    VERSION,
    decode_policy,
    encode_policy,
    extract_payload_from_hash,
    looks_like_policy,
    normalize_imported_policy,
    unknown_top_level_keys,
)


def test_round_trip_default_preset():
    policy = load_preset("default")
    encoded = encode_policy(policy)

    assert encoded.startswith(f"{VERSION}.")
    result = decode_policy(encoded)
    assert isinstance(result, DecodeOk)
    assert result.unknown_keys == ()
    # Round-trip preserves every field.
    assert dataclasses.asdict(result.policy) == dataclasses.asdict(policy)


def test_round_trip_with_modifications_preserves_changes():
    policy = load_preset("default")
    policy.name = "share-test"
    policy.guardrail.block_threshold = 1
    policy.firewall.default_action = "deny"
    policy.webhooks = []  # ensure list survives round-trip even when empty

    encoded = encode_policy(policy)
    result = decode_policy(encoded)
    assert isinstance(result, DecodeOk)
    assert result.policy.name == "share-test"
    assert result.policy.guardrail.block_threshold == 1
    assert result.policy.firewall.default_action == "deny"


def test_decode_rejects_bad_version():
    encoded = encode_policy(load_preset("default"))
    body = encoded.split(".", 1)[1]
    bad = f"v9.{body}"
    result = decode_policy(bad)
    assert isinstance(result, DecodeErr)
    assert result.reason == DecodeFailure.VERSION


def test_decode_rejects_payload_over_size_cap():
    big = "x" * (MAX_PAYLOAD_CHARS + 10)
    result = decode_policy(f"{VERSION}.{big}")
    assert isinstance(result, DecodeErr)
    assert result.reason == DecodeFailure.TOO_LARGE


def test_decode_rejects_malformed_base64():
    # ``$`` is illegal base64url.
    result = decode_policy(f"{VERSION}.$$$")
    assert isinstance(result, DecodeErr)
    assert result.reason == DecodeFailure.MALFORMED


def test_decode_rejects_invalid_shape():
    # gzip + base64url-encode an empty object so the shape check fails.
    payload = json.dumps({})
    blob = gzip.compress(payload.encode("utf-8"), mtime=0)
    import base64

    encoded = base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")
    result = decode_policy(f"{VERSION}.{encoded}")
    assert isinstance(result, DecodeErr)
    assert result.reason == DecodeFailure.INVALID_SHAPE


def test_decode_rejects_gzip_bomb():
    # Compress 2 MB of zeros; raw payload base64 stays small but the
    # decompressed size exceeds the bound.
    payload = b"0" * (MAX_DECOMPRESSED_BYTES + 2_000_000)
    blob = gzip.compress(payload, mtime=0)
    import base64

    encoded = base64.urlsafe_b64encode(blob).rstrip(b"=").decode("ascii")
    if len(encoded) > MAX_PAYLOAD_CHARS:
        pytest.skip("base64 payload itself trips the size cap before decompression")
    result = decode_policy(f"{VERSION}.{encoded}")
    assert isinstance(result, DecodeErr)
    assert result.reason == DecodeFailure.TOO_LARGE


def test_unknown_top_level_keys_surfaces_extras():
    payload = {
        "name": "x",
        "skill_actions": {},
        "this_field_doesnt_exist": True,
    }
    keys = unknown_top_level_keys(payload)
    assert keys == ("this_field_doesnt_exist",)


def test_normalize_imported_policy_backfills_correlator():
    payload: dict = {"name": "x", "skill_actions": {}}
    result = normalize_imported_policy(payload)
    assert result["correlator"] == []


def test_normalize_imported_policy_backfills_aid():
    payload: dict = {"name": "x", "skill_actions": {}}
    result = normalize_imported_policy(payload)
    aid = result["cisco_ai_defense"]
    assert aid["enabled"] is False
    assert aid["scan_hook_surface"] is True


def test_known_policy_top_level_keys_matches_default_preset():
    # If somebody adds a new field to ``Policy`` and the default preset,
    # they must also bump KNOWN_POLICY_TOP_LEVEL_KEYS or imports of
    # newer drafts will silently drop the field.
    asdict = dataclasses.asdict(load_preset("default"))
    extra = set(asdict.keys()) - set(KNOWN_POLICY_TOP_LEVEL_KEYS)
    assert not extra, (
        f"Add these keys to KNOWN_POLICY_TOP_LEVEL_KEYS: {sorted(extra)}"
    )


def test_extract_payload_from_hash_handles_both_forms():
    assert extract_payload_from_hash("#policy=v1.abc") == "v1.abc"
    assert extract_payload_from_hash("policy=v1.abc&utm=x") == "v1.abc"
    assert extract_payload_from_hash("#v1.bare") == "v1.bare"
    assert extract_payload_from_hash("") is None
    assert extract_payload_from_hash("#") is None


def test_looks_like_policy_requires_name_and_skill_actions():
    assert looks_like_policy({"name": "x", "skill_actions": {}}) is True
    assert looks_like_policy({"name": "x"}) is False
    assert looks_like_policy({"skill_actions": {}}) is False
    assert looks_like_policy("not-a-dict") is False
    assert looks_like_policy([1, 2, 3]) is False
