#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Pure deterministic JSON encoder for compiler-owned telemetry records.

Only numbers below the canonical ``body`` and ``instrument_data`` Value roots
use shortest-exact decimal normalization. Schema-defined envelope integers keep
their ordinary signed or unsigned plain base-10 spelling.
"""

from __future__ import annotations

import decimal
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final


class CanonicalRecordError(ValueError):
    """A record value cannot be encoded under the closed canonical contract."""


MAX_CANONICAL_VALUE_BYTES: Final = 1_048_576
_JSON_NUMBER: Final = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
_VALUE_ROOTS: Final = frozenset({"body", "instrument_data"})


def _unsigned_compare(left: str, right: str) -> int:
    if len(left) != len(right):
        return -1 if len(left) < len(right) else 1
    return (left > right) - (left < right)


def _unsigned_add(left: str, right: str) -> str:
    carry = 0
    result: list[str] = []
    left_at = len(left) - 1
    right_at = len(right) - 1
    while left_at >= 0 or right_at >= 0 or carry:
        total = carry
        if left_at >= 0:
            total += ord(left[left_at]) - ord("0")
            left_at -= 1
        if right_at >= 0:
            total += ord(right[right_at]) - ord("0")
            right_at -= 1
        result.append(chr(ord("0") + total % 10))
        carry = total // 10
    return "".join(reversed(result))


def _unsigned_subtract(left: str, right: str) -> str:
    """Return left-right for canonical unsigned decimals where left >= right."""

    borrow = 0
    result: list[str] = []
    right_at = len(right) - 1
    for left_at in range(len(left) - 1, -1, -1):
        digit = ord(left[left_at]) - ord("0") - borrow
        subtract = ord(right[right_at]) - ord("0") if right_at >= 0 else 0
        right_at -= 1
        if digit < subtract:
            digit += 10
            borrow = 1
        else:
            borrow = 0
        result.append(chr(ord("0") + digit - subtract))
    normalized = "".join(reversed(result)).lstrip("0")
    return normalized or "0"


def _signed_decimal(text: str) -> tuple[int, str]:
    negative = text.startswith("-")
    if text[:1] in {"-", "+"}:
        text = text[1:]
    digits = text.lstrip("0")
    if not digits:
        return 0, "0"
    return (-1 if negative else 1), digits


def _signed_add_small(value: tuple[int, str], delta: int) -> tuple[int, str]:
    sign, digits = value
    if delta == 0:
        return value
    delta_sign = -1 if delta < 0 else 1
    delta_digits = str(abs(delta))
    if sign == 0:
        return delta_sign, delta_digits
    if sign == delta_sign:
        return sign, _unsigned_add(digits, delta_digits)
    comparison = _unsigned_compare(digits, delta_digits)
    if comparison == 0:
        return 0, "0"
    if comparison > 0:
        return sign, _unsigned_subtract(digits, delta_digits)
    return delta_sign, _unsigned_subtract(delta_digits, digits)


def _signed_text(value: tuple[int, str]) -> str:
    sign, digits = value
    return ("-" if sign < 0 else "") + ("0" if sign == 0 else digits)


def _signed_bounded_int(value: tuple[int, str], bound: int) -> int | None:
    sign, digits = value
    comparison = _unsigned_compare(digits, str(bound))
    if comparison > 0:
        return None
    magnitude = int(digits)
    return -magnitude if sign < 0 else magnitude


def _validated_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalRecordError("canonical record string contains an unpaired surrogate")
    return value


def normalize_exact_decimal(text: str) -> str:
    """Return the shortest exact plain/scientific spelling of one JSON number."""

    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_CANONICAL_VALUE_BYTES:
        raise CanonicalRecordError("canonical number exceeds the encoded-size bound")
    if _JSON_NUMBER.fullmatch(text) is None:
        raise CanonicalRecordError("canonical number is not a finite JSON decimal")
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    exponent_text = "0"
    exponent_at = max(text.find("e"), text.find("E"))
    if exponent_at >= 0:
        exponent_text = text[exponent_at + 1 :]
        text = text[:exponent_at]
    integer, separator, fraction = text.partition(".")
    if not separator:
        fraction = ""
    digits = (integer + fraction).lstrip("0")
    if not digits:
        return "0"
    exponent = _signed_add_small(_signed_decimal(exponent_text), -len(fraction))
    trimmed = digits.rstrip("0")
    if not trimmed:
        return "0"
    exponent = _signed_add_small(exponent, len(digits) - len(trimmed))
    digits = trimmed

    scientific_exponent = _signed_add_small(exponent, len(digits) - 1)
    scientific = digits[0]
    if len(digits) > 1:
        scientific += "." + digits[1:]
    if scientific_exponent[0] != 0:
        scientific += "e" + _signed_text(scientific_exponent)

    point_value = _signed_add_small(exponent, len(digits))
    point = _signed_bounded_int(point_value, MAX_CANONICAL_VALUE_BYTES)
    plain: str | None = None
    if point is not None:
        if point <= 0:
            size = 2 - point + len(digits)
            if size <= MAX_CANONICAL_VALUE_BYTES:
                plain = "0." + "0" * (-point) + digits
        elif point >= len(digits):
            if point <= MAX_CANONICAL_VALUE_BYTES:
                plain = digits + "0" * (point - len(digits))
        elif len(digits) + 1 <= MAX_CANONICAL_VALUE_BYTES:
            plain = digits[:point] + "." + digits[point:]
    result = plain if plain is not None and len(plain) <= len(scientific) else scientific
    return "-" + result if negative else result


def _native_number_text(value: int | float | decimal.Decimal) -> str:
    if isinstance(value, bool):
        raise CanonicalRecordError("Boolean is not a canonical number")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalRecordError("native record number is not finite")
        return repr(value)
    if isinstance(value, decimal.Decimal):
        if not value.is_finite():
            raise CanonicalRecordError("parsed record decimal is not finite")
        return str(value)
    raise CanonicalRecordError("unsupported canonical record number")


def _encode(value: Any, *, value_numbers: bool, root: bool = False) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(_validated_string(value), ensure_ascii=False, allow_nan=False)
    if isinstance(value, (int, float, decimal.Decimal)):
        text = _native_number_text(value)
        return normalize_exact_decimal(text) if value_numbers or isinstance(value, decimal.Decimal) else text
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalRecordError("canonical record object has a non-string key")
        members: list[str] = []
        keys = tuple(_validated_string(key) for key in value)
        for key in sorted(keys, key=lambda item: item.encode("utf-8")):
            child_value_numbers = value_numbers or root and key in _VALUE_ROOTS
            members.append(
                json.dumps(key, ensure_ascii=False, allow_nan=False)
                + ":"
                + _encode(value[key], value_numbers=child_value_numbers)
            )
        return "{" + ",".join(members) + "}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "[" + ",".join(_encode(item, value_numbers=value_numbers) for item in value) + "]"
    raise CanonicalRecordError("unsupported canonical record value")


def canonical_record_json(value: Any) -> str:
    """Encode one complete canonical record with payload-only number rules."""

    if not isinstance(value, Mapping):
        raise CanonicalRecordError("canonical record must be an object")
    return _encode(value, value_numbers=False, root=True)


def canonicalize_record_json_text(value: str) -> str:
    """Parse and canonicalize one compiler-to-compiler record JSON fact."""

    if not isinstance(value, str):
        raise CanonicalRecordError("canonical record JSON fact is not text")
    try:
        decoded = json.loads(
            value,
            parse_float=decimal.Decimal,
            parse_int=int,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (ValueError, decimal.InvalidOperation) as exc:
        raise CanonicalRecordError("canonical record JSON fact is invalid") from exc
    return canonical_record_json(decoded)


__all__ = [
    "CanonicalRecordError",
    "MAX_CANONICAL_VALUE_BYTES",
    "canonical_record_json",
    "canonicalize_record_json_text",
    "normalize_exact_decimal",
]
