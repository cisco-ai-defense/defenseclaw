"""Cross-language golden and failure tests for observability hash-v1."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from defenseclaw.observability.hash_v1 import (
    HashV1Error,
    HashV1ErrorCode,
    _normalize_hash_v1_value,
    hash_v1,
)
from defenseclaw.observability.unicode13 import (
    _UNICODE13_RANGES,
    _UNICODE13_RANGES_SHA256,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_GOLDEN_FILE = _REPOSITORY_ROOT / "internal" / "observability" / "redaction" / "testdata" / "hash_v1_golden.json"
_UNICODE13_MANIFEST = _REPOSITORY_ROOT / "schemas" / "telemetry" / "v8" / "redaction" / "unicode-age-13.0.json"


def _golden_fixture() -> dict[str, object]:
    return json.loads(_GOLDEN_FILE.read_text(encoding="utf-8"))


def test_unicode13_generated_ranges_match_manifest() -> None:
    manifest = json.loads(_UNICODE13_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["unicode_version"] == "13.0.0"
    assert manifest["source"] == "https://www.unicode.org/Public/13.0.0/ucd/DerivedAge.txt"
    assert manifest["source_sha256"] == "e779a443d3aa2a3166a15becaa2b737c922480e32c0453d5956093633555078f"
    assert manifest["range_encoding"] == "inclusive uppercase six-digit hexadecimal START-END"
    assert manifest["range_digest_canonicalization"] == "each encoded range followed by LF"

    encoded_ranges = manifest["ranges"]
    assert isinstance(encoded_ranges, list)
    parsed_ranges = tuple(
        tuple(int(endpoint, 16) for endpoint in str(encoded_range).split("-", 1)) for encoded_range in encoded_ranges
    )
    assert parsed_ranges == _UNICODE13_RANGES
    assert all(
        encoded_range == f"{first:06X}-{last:06X}"
        for encoded_range, (first, last) in zip(encoded_ranges, parsed_ranges, strict=True)
    )
    assert all(
        first <= last
        and (index == 0 or parsed_ranges[index - 1][1] < first)
        and not (first <= 0xDFFF and last >= 0xD800)
        for index, (first, last) in enumerate(parsed_ranges)
    )
    canonical = "".join(f"{encoded_range}\n" for encoded_range in encoded_ranges).encode("ascii")
    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == manifest["range_sha256"] == _UNICODE13_RANGES_SHA256
    assert sum(last - first + 1 for first, last in parsed_ranges) == manifest["scalar_count"]


def test_hash_v1_matches_shared_go_golden_vectors() -> None:
    fixture = _golden_fixture()
    assert fixture["contract"] == "hash-v1"
    default_key = bytes.fromhex(str(fixture["default_key_hex"]))
    assert hashlib.sha256(default_key).hexdigest()[:12] == fixture["default_key_id"]
    vectors = fixture["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        value = str(vector["value"])
        field_class = str(vector["field_class"])
        key = bytes.fromhex(str(vector.get("key_hex", fixture["default_key_hex"])))
        if "key_id" in vector:
            assert hashlib.sha256(key).hexdigest()[:12] == vector["key_id"]
        normalized = _normalize_hash_v1_value(value, field_class)
        assert normalized == vector["normalized"], vector["name"]
        token = hash_v1(value, field_class, key or default_key)
        assert token == vector["token"], vector["name"]
        assert value not in token
        assert normalized not in token


def test_hash_v1_matches_shared_go_error_vectors() -> None:
    fixture = _golden_fixture()
    default_key = bytes.fromhex(str(fixture["default_key_hex"]))
    vectors = fixture["error_vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        value = str(vector["value"])
        field_class = str(vector["field_class"])
        key = bytes.fromhex(str(vector.get("key_hex", fixture["default_key_hex"])))
        with pytest.raises(HashV1Error) as caught:
            hash_v1(value, field_class, key or default_key)
        assert caught.value.code is HashV1ErrorCode(str(vector["error"])), vector["name"]
        assert not value or value not in str(caught.value)


@pytest.mark.parametrize(
    "field_class",
    [
        "metadata",
        "identifier",
        "content",
        "reason",
        "evidence",
        "error",
        "path",
        "credential",
    ],
)
def test_hash_v1_supports_every_field_class(field_class: str) -> None:
    assert hash_v1("value", field_class, bytes(32)).startswith(f"<hashed class={field_class} ")


def test_non_scheme_prefix_uses_lexical_path_fallback() -> None:
    assert hash_v1("1https://example.test/%zz", "path", bytes(32)).startswith("<hashed class=path ")


@pytest.mark.parametrize(
    ("value", "field_class", "key", "code", "secret"),
    [
        (
            b"\xff\xfe",
            "content",
            bytes(32),
            HashV1ErrorCode.INVALID_UTF8,
            "",
        ),
        (
            "private-value",
            "content",
            b"short-secret",
            HashV1ErrorCode.INVALID_KEY,
            "short-secret",
        ),
        (
            "private-value",
            "unknown",
            bytes(32),
            HashV1ErrorCode.UNSUPPORTED_CLASS,
            "private-value",
        ),
    ],
)
def test_typed_failures_are_value_safe(
    value: str | bytes,
    field_class: str,
    key: bytes,
    code: HashV1ErrorCode,
    secret: str,
) -> None:
    with pytest.raises(HashV1Error) as caught:
        hash_v1(value, field_class, key)
    assert caught.value.code is code
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert not secret or secret not in str(caught.value)


def test_unpaired_surrogate_is_invalid_utf8() -> None:
    with pytest.raises(HashV1Error) as caught:
        hash_v1("\ud800", "content", bytes(32))
    assert caught.value.code is HashV1ErrorCode.INVALID_UTF8


def test_rotation_changes_safe_key_identity_and_digest() -> None:
    value = "/var/lib/defenseclaw/state.db"
    first = hash_v1(value, "path", bytes(32))
    second = hash_v1(value, "path", bytes([1]) * 32)
    assert first != second
    assert "key=66687aadf862" in first
    assert "key=72cd6e8422c4" in second


def test_uri_userinfo_never_appears_in_token() -> None:
    token = hash_v1(
        "https://operator:super-secret@example.test/path",
        "path",
        bytes(32),
    )
    for forbidden in ("operator", "super-secret", "example.test", "/path"):
        assert forbidden not in token
