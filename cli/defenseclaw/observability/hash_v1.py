"""Cross-language ``hash-v1`` redaction correlation primitive.

The public function returns only a non-reversible token.  This module never
loads keys from process state and its typed failures contain no caller values,
key identifiers, or key material.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum

from defenseclaw.observability.unicode13 import _is_unicode13_repertoire

_DOMAIN = b"defenseclaw-redaction-hash-v1"
_KEY_BYTES = 32
_FIELD_CLASSES = frozenset(
    {
        "metadata",
        "identifier",
        "content",
        "reason",
        "evidence",
        "error",
        "path",
        "credential",
    }
)
_HIERARCHICAL_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_SUB_DELIMS = frozenset("!$&'()*+,;=")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class HashV1ErrorCode(str, Enum):
    """Value-free failure codes shared with the Go implementation."""

    INVALID_UTF8 = "invalid_utf8"
    INVALID_KEY = "invalid_key"
    UNSUPPORTED_CLASS = "unsupported_class"
    UNICODE_REPERTOIRE = "unicode_repertoire"
    NORMALIZATION_FAILED = "normalization_failed"


@dataclass(eq=False)
class HashV1Error(ValueError):
    """A typed, value-safe hash-v1 failure."""

    code: HashV1ErrorCode

    def __str__(self) -> str:
        return f"redaction hash-v1 failed: {self.code.value}"


def hash_v1(
    value: str | bytes,
    field_class: str,
    key: bytes,
) -> str:
    """Return the v1 keyed token for *value* without exposing normalization."""

    decoded = _decode_utf8(value)
    if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
        raise HashV1Error(HashV1ErrorCode.INVALID_KEY)
    if field_class not in _FIELD_CLASSES:
        raise HashV1Error(HashV1ErrorCode.UNSUPPORTED_CLASS)

    normalized = _normalize_hash_v1_value(decoded, field_class)
    message = b"\x00".join((_DOMAIN, field_class.encode("ascii"), normalized.encode("utf-8")))
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    key_id = hashlib.sha256(key).hexdigest()[:12]
    original_length = len(decoded.encode("utf-8"))
    return f"<hashed class={field_class} v=1 key={key_id} len={original_length} hmac={digest}>"


def _decode_utf8(value: str | bytes) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        raise HashV1Error(HashV1ErrorCode.INVALID_UTF8)
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            pass
        else:
            return value
        raise HashV1Error(HashV1ErrorCode.INVALID_UTF8)
    raise HashV1Error(HashV1ErrorCode.INVALID_UTF8)


def _normalize_hash_v1_value(value: str, field_class: str) -> str:
    if field_class not in _FIELD_CLASSES:
        raise HashV1Error(HashV1ErrorCode.UNSUPPORTED_CLASS)
    if not _is_unicode13_repertoire(value):
        raise HashV1Error(HashV1ErrorCode.UNICODE_REPERTOIRE)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        pass
    else:
        value = unicodedata.normalize("NFC", value)
        if field_class != "path":
            return value
        if _is_windows_drive_path(value):
            return _normalize_lexical_path(value)
        if _HIERARCHICAL_URI.match(value) is not None:
            return _normalize_absolute_uri(value)
        return _normalize_lexical_path(value)
    # Raise after leaving the handler so the safe error retains no value-bearing
    # Unicode exception as its cause or context.
    raise HashV1Error(HashV1ErrorCode.INVALID_UTF8)


def _is_windows_drive_path(value: str) -> bool:
    return len(value) >= 2 and _is_ascii_letter(value[0]) and value[1] == ":"


def _normalize_lexical_path(value: str) -> str:
    value = value.replace("\\", "/")
    prefix = ""
    absolute = False
    unc_root = False
    rest = value
    if rest.startswith("//"):
        prefix = "//"
        rest = rest[2:].lstrip("/")
        parts = [part for part in rest.split("/") if part]
        if len(parts) >= 2 and all(part not in (".", "..") for part in parts[:2]):
            prefix += f"{parts[0]}/{parts[1]}"
            rest = "/".join(parts[2:])
            absolute = True
            unc_root = True
    elif rest.startswith("/"):
        prefix = "/"
        absolute = True
        rest = rest[1:].lstrip("/")
    elif len(rest) >= 2 and _is_ascii_letter(rest[0]) and rest[1] == ":":
        prefix = rest[0].lower() + ":"
        rest = rest[2:]
        if rest.startswith("/"):
            prefix += "/"
            absolute = True
            rest = rest.lstrip("/")

    segments: list[str] = []
    for segment in rest.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments and segments[-1] != "..":
                segments.pop()
            elif not absolute:
                segments.append(segment)
        else:
            segments.append(segment)

    joined = "/".join(segments)
    if not prefix:
        return joined
    if not joined:
        return prefix
    if prefix.endswith("/"):
        return prefix + joined
    if unc_root:
        return prefix + "/" + joined
    return prefix + joined


def _normalize_absolute_uri(value: str) -> str:
    if not _is_ascii_uri(value):
        raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
    colon = value.find(":")
    if colon <= 0:
        raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
    scheme = value[:colon].lower()
    rest = value[colon + 1 :]
    if not rest.startswith("//"):
        raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)

    fragment_at = rest.find("#")
    if fragment_at >= 0:
        _normalize_uri_component(rest[fragment_at + 1 :], "query_fragment")
        rest = rest[:fragment_at]

    query = ""
    has_query = False
    query_at = rest.find("?")
    if query_at >= 0:
        has_query = True
        query = _normalize_uri_component(rest[query_at + 1 :], "query_fragment")
        rest = rest[:query_at]

    authority = ""
    has_authority = rest.startswith("//")
    path = rest
    if has_authority:
        authority_end = rest.find("/", 2)
        if authority_end < 0:
            authority = rest[2:]
            path = ""
        else:
            authority = rest[2:authority_end]
            path = rest[authority_end:]
        authority = _normalize_uri_authority(authority, scheme)

    path = _normalize_uri_component(path, "path")
    path = _remove_uri_dot_segments(path)
    result = f"{scheme}:"
    if has_authority:
        result += f"//{authority}"
    result += path
    if has_query:
        result += f"?{query}"
    return result


def _normalize_uri_component(value: str, component: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "%":
            if index + 2 >= len(value) or value[index + 1] not in _HEX_DIGITS or value[index + 2] not in _HEX_DIGITS:
                raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
            decoded = chr(int(value[index + 1 : index + 3], 16))
            if _is_uri_unreserved(decoded):
                result.append(decoded)
            else:
                result.append("%" + value[index + 1 : index + 3].upper())
            index += 3
            continue
        if not _is_allowed_uri_character(character, component):
            raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
        result.append(character)
        index += 1
    return "".join(result)


def _normalize_uri_authority(authority: str, scheme: str) -> str:
    userinfo = ""
    hostport = authority
    at = authority.rfind("@")
    if at >= 0:
        userinfo = _normalize_uri_component(authority[:at], "userinfo") + "@"
        hostport = authority[at + 1 :]

    bracketed = hostport.startswith("[")
    port = ""
    explicit_port = False
    if bracketed:
        close_at = hostport.find("]")
        if close_at < 0:
            raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
        host = hostport[1:close_at]
        remainder = hostport[close_at + 1 :]
        if remainder:
            if not remainder.startswith(":"):
                raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
            explicit_port = True
            port = remainder[1:]
        if not _is_valid_ip_literal(host):
            raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
        host = _normalize_uri_host_case(host)
    else:
        if hostport.count(":") > 1:
            raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            explicit_port = True
        else:
            host = hostport
        host = _normalize_uri_host_case(_normalize_uri_component(host, "reg_name"))

    if not host or (explicit_port and not port):
        raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)

    if port:
        if not port.isascii() or not port.isdecimal():
            raise HashV1Error(HashV1ErrorCode.NORMALIZATION_FAILED)
        if _is_default_port(scheme, port):
            port = ""

    if bracketed:
        host = f"[{host}]"
    if port:
        host += f":{port}"
    return userinfo + host


def _remove_uri_dot_segments(path: str) -> str:
    input_buffer = path
    output = bytearray()
    slash_positions: list[int] = []
    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = input_buffer[2:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = input_buffer[3:]
            _remove_last_uri_segment(output, slash_positions)
        elif input_buffer == "/..":
            input_buffer = "/"
            _remove_last_uri_segment(output, slash_positions)
        elif input_buffer in (".", ".."):
            input_buffer = ""
        else:
            length = _first_uri_segment_length(input_buffer)
            if input_buffer[0] == "/":
                slash_positions.append(len(output))
            output.extend(input_buffer[:length].encode("ascii"))
            input_buffer = input_buffer[length:]
    return output.decode("ascii")


def _first_uri_segment_length(value: str) -> int:
    start = 1 if value.startswith("/") else 0
    slash_at = value.find("/", start)
    return len(value) if slash_at < 0 else slash_at


def _remove_last_uri_segment(value: bytearray, slash_positions: list[int]) -> None:
    if slash_positions:
        del value[slash_positions.pop() :]
    else:
        value.clear()


def _is_ascii_uri(value: str) -> bool:
    return all("!" <= character <= "~" and character != "\\" for character in value)


def _is_allowed_uri_character(character: str, component: str) -> bool:
    if _is_uri_unreserved(character) or character in _SUB_DELIMS:
        return True
    if component == "path":
        return character in "/:@"
    if component == "query_fragment":
        return character in "/?:@"
    if component == "userinfo":
        return character == ":"
    return False


def _is_valid_ip_literal(value: str) -> bool:
    if not value or "%" in value:
        return False
    if value[0] in "vV":
        dot_at = value.find(".")
        if dot_at < 2 or dot_at == len(value) - 1:
            return False
        if any(character not in _HEX_DIGITS for character in value[1:dot_at]):
            return False
        return all(
            _is_uri_unreserved(character) or character in _SUB_DELIMS or character == ":"
            for character in value[dot_at + 1 :]
        )
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _is_default_port(scheme: str, port: str) -> bool:
    canonical_port = port.lstrip("0") or "0"
    return (scheme, canonical_port) in {
        ("http", "80"),
        ("https", "443"),
    }


def _normalize_uri_host_case(host: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(host):
        character = host[index]
        if (
            character == "%"
            and index + 2 < len(host)
            and host[index + 1] in _HEX_DIGITS
            and host[index + 2] in _HEX_DIGITS
        ):
            decoded = chr(int(host[index + 1 : index + 3], 16))
            if _is_uri_unreserved(decoded):
                result.append(decoded.lower())
            else:
                result.append("%" + host[index + 1 : index + 3].upper())
            index += 3
            continue
        result.append(character.lower())
        index += 1
    return "".join(result)


def _is_uri_unreserved(character: str) -> bool:
    return _is_ascii_letter(character) or character.isascii() and character.isdecimal() or character in "-._~"


def _is_ascii_letter(character: str) -> bool:
    return "a" <= character <= "z" or "A" <= character <= "Z"
