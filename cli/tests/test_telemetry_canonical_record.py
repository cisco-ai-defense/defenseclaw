# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import decimal
import importlib.util
import math
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/telemetry_canonical_record.py"


@pytest.fixture(scope="module")
def canonical() -> ModuleType:
    spec = importlib.util.spec_from_file_location("telemetry_canonical_record_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("1783080000000000000", "1.78308e18"),
        ("1.2300", "1.23"),
        ("123e-2", "1.23"),
        ("1000", "1e3"),
        ("-1000", "-1e3"),
        ("0.001", "1e-3"),
        ("10", "10"),
        ("-0", "0"),
        ("-0.0e999", "0"),
        ("1e+0009", "1e9"),
        ("1.2300e100000000000000000000", "1.23e100000000000000000000"),
        ("123456789012345678901234567890.1234500", "123456789012345678901234567890.12345"),
    ),
)
def test_decimal_vectors_match_the_go_value_canonical_contract(
    canonical: ModuleType,
    source: str,
    expected: str,
) -> None:
    assert canonical.normalize_exact_decimal(source) == expected


def test_record_encoder_normalizes_only_value_payload_numbers(canonical: ModuleType) -> None:
    record = {
        "schema_version": 1000,
        "provenance": {"config_generation": 1000},
        "body": {
            "large": 1783080000000000000,
            "decimal": decimal.Decimal("1.2300"),
            "negative_zero": decimal.Decimal("-0E+4"),
            "nested": [1000, {"small": decimal.Decimal("0.0010")}],
        },
    }
    assert canonical.canonical_record_json(record) == (
        '{"body":{"decimal":1.23,"large":1.78308e18,"negative_zero":0,'
        '"nested":[1e3,{"small":1e-3}]},"provenance":{"config_generation":1000},"schema_version":1000}'
    )


def test_text_canonicalizer_preserves_exact_decimal_without_binary_rounding(canonical: ModuleType) -> None:
    source = '{"schema_version":1,"body":{"precise":0.123456789012345678901234567890,"large":1783080000000000000}}'
    assert canonical.canonicalize_record_json_text(source) == (
        '{"body":{"large":1.78308e18,"precise":0.12345678901234567890123456789},"schema_version":1}'
    )


@pytest.mark.parametrize("source", ("NaN", "Infinity", "-Infinity", "01", "1.", " 1", "1 "))
def test_decimal_normalizer_rejects_invalid_or_nonfinite_lexemes(
    canonical: ModuleType,
    source: str,
) -> None:
    with pytest.raises(canonical.CanonicalRecordError, match="finite JSON decimal"):
        canonical.normalize_exact_decimal(source)


@pytest.mark.parametrize("value", (math.nan, math.inf, -math.inf, decimal.Decimal("NaN")))
def test_record_encoder_rejects_nonfinite_native_numbers(canonical: ModuleType, value: object) -> None:
    with pytest.raises(canonical.CanonicalRecordError, match="not finite"):
        canonical.canonical_record_json({"body": {"value": value}})


def test_decimal_normalizer_rejects_oversize_input(
    canonical: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(canonical, "MAX_CANONICAL_VALUE_BYTES", 8)
    with pytest.raises(canonical.CanonicalRecordError, match="encoded-size bound"):
        canonical.normalize_exact_decimal("123456789")


def test_decimal_normalizer_handles_exponents_beyond_python_integer_digit_limit(canonical: ModuleType) -> None:
    exponent = "9" * 5000
    assert canonical.normalize_exact_decimal("1e+" + exponent) == "1e" + exponent


@pytest.mark.parametrize(
    "record",
    (
        {"body": {"value": "bad\ud800"}},
        {"body": {"bad\udfff": "value"}},
    ),
)
def test_record_encoder_rejects_unpaired_surrogates(canonical: ModuleType, record: object) -> None:
    with pytest.raises(canonical.CanonicalRecordError, match="unpaired surrogate"):
        canonical.canonical_record_json(record)


def test_object_keys_use_utf8_byte_order_and_minimal_string_escapes(canonical: ModuleType) -> None:
    assert canonical.canonical_record_json({"body": {"é": "line\n雪", "z": "</script>"}}) == (
        '{"body":{"z":"</script>","é":"line\\n雪"}}'
    )


def test_backspace_and_form_feed_match_go_json_encoder_in_values_and_object_keys(
    canonical: ModuleType,
) -> None:
    record = {
        "body": {
            "\f": "\b",
            "nested": ["prefix\bsuffix", {"value": "prefix\fsuffix"}],
            "\b": "\f",
        }
    }

    assert canonical.canonical_record_json(record) == (
        '{"body":{"\\b":"\\f","\\f":"\\b",'
        '"nested":["prefix\\bsuffix",{"value":"prefix\\fsuffix"}]}}'
    )


def test_text_entry_point_reencodes_unicode_control_escapes_like_go_json_encoder(
    canonical: ModuleType,
) -> None:
    source = (
        '{"body":{"\\u000c":"\\u0008","nested":["\\b",{"value":"\\f"}],'
        '"\\u0008":"\\u000c"}}'
    )

    assert canonical.canonicalize_record_json_text(source) == (
        '{"body":{"\\b":"\\f","\\f":"\\b","nested":["\\b",{"value":"\\f"}]}}'
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (-0.0, "0"),
        (1e-7, "1e-7"),
        (1e20, "1e20"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e308"),
    ),
)
def test_structured_and_text_float_vectors_match_go_shortest_exact_normalization(
    canonical: ModuleType,
    value: float,
    expected: str,
) -> None:
    wanted = '{"body":{"value":' + expected + "}}"
    assert canonical.canonical_record_json({"body": {"value": value}}) == wanted
    assert canonical.canonicalize_record_json_text('{"body":{"value":' + repr(value) + "}}") == wanted
