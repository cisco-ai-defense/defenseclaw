# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""OS metadata files in a skill folder (GAP-0106).

A skill copied from macOS (tar, zip, a file share) or through Windows
Explorer carries files the OS writes on its own: AppleDouble ``._name``
sidecars with a file's Finder info and extended attributes, ``.DS_Store``
folder views, ``Thumbs.db`` thumbnail caches and ``desktop.ini`` folder
settings. skill-scanner read the binary ones as opaque files, so a plain-text
skill scored "critically low analyzability" (HIGH) and the install watcher
quarantined it in action mode. A file counts as metadata only when its name
and its format both say so and it cannot carry file content: an AppleDouble
file needs its companion file, Finder info, an empty resource fork and small
attributes under known Apple names only. Anything else (a data fork, resource
data, an unknown attribute, a metadata name without the format) is scanned
like any other file. internal/scanner/skill_metadata.go applies the same
checks for the install watcher.
"""

from __future__ import annotations

import os
import struct

from defenseclaw.models import Finding

RULE_OS_METADATA_FILE = "OS_METADATA_FILE"

_APPLEDOUBLE_MAX_BYTES = 64 << 10
_APPLEDOUBLE_MAX_ATTR_BYTES = 4 << 10
_APPLEDOUBLE_MAX_ENTRIES = 8
_APPLEDOUBLE_MAX_ATTRS = 64
_DS_STORE_MAX_BYTES = 1 << 20
_THUMBS_DB_MAX_BYTES = 4 << 20
_DESKTOP_INI_MAX_BYTES = 64 << 10

# Extended attributes macOS sets on a downloaded or edited text file;
# "com.apple.metadata:" names hold Spotlight values (where-from, tags).
_APPLEDOUBLE_ATTR_NAMES = frozenset({
    "com.apple.quarantine",
    "com.apple.provenance",
    "com.apple.macl",
    "com.apple.lastuseddate#PS",
    "com.apple.TextEncoding",
})
_SPOTLIGHT_PREFIX = "com.apple.metadata:"

_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
# Stream names of Office documents, macros and embedded packages: an OLE
# file with one of them is a document, not a thumbnail cache.
_OLE_DOCUMENT_STREAMS = tuple(
    name.encode("utf-16-le")
    for name in ("WordDocument", "Workbook", "Book", "PowerPoint Document", "VBA", "Macros",
                 "_VBA_PROJECT", "Ole10Native", "ObjectPool", "Package")
)

APPLEDOUBLE_KIND = "macOS AppleDouble sidecar (Finder info and extended attributes, no file content)"
DS_STORE_KIND = "macOS Finder folder settings (.DS_Store)"
THUMBS_DB_KIND = "Windows Explorer thumbnail cache (Thumbs.db)"


def _attr_name_ok(name: str) -> bool:
    if name in _APPLEDOUBLE_ATTR_NAMES:
        return True
    return name.startswith(_SPOTLIGHT_PREFIX) and len(name) > len(_SPOTLIGHT_PREFIX)


def _read_bounded(path: str, limit: int) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _companion_exists(root: str, rel: str) -> bool:
    """Whether the ``._name`` file at rel describes a file or folder that is there."""
    parts = rel.replace("\\", "/").split("/")
    name = parts.pop()
    if parts and parts[0] == "__MACOSX":
        parts = parts[1:]
    return os.path.lexists(os.path.join(root, *parts, name[2:]))


def is_appledouble_metadata(data: bytes) -> bool:
    """AppleDouble (RFC 1740, as macOS writes it) with metadata only."""
    if len(data) < 26 or data[:8] != b"\x00\x05\x16\x07\x00\x02\x00\x00":
        return False
    (count,) = struct.unpack_from(">H", data, 24)
    head = 26 + 12 * count
    if count == 0 or count > _APPLEDOUBLE_MAX_ENTRIES or head > len(data):
        return False
    for i in range(count):
        entry_id, off, length = struct.unpack_from(">III", data, 26 + 12 * i)
        if off < head or off + length > len(data):
            return False
        if entry_id == 9:  # Finder info
            if not _finder_info_ok(data, off, length):
                return False
        elif entry_id == 2:  # resource fork
            if not _empty_resource_fork(data[off:off + length]):
                return False
        else:  # a data fork or any other entry can hold content
            return False
    return True


def _finder_info_ok(data: bytes, off: int, length: int) -> bool:
    """32 bytes of Finder info, then optionally two pad bytes and an ATTR block."""
    if length < 32:
        return False
    if length == 32:
        return True
    h, end = off + 34, off + length
    if h + 36 > end or data[h:h + 4] != b"ATTR":
        return False
    total_size, data_start, data_length = struct.unpack_from(">III", data, h + 8)
    (num_attrs,) = struct.unpack_from(">H", data, h + 34)
    if total_size > len(data) or data_start + data_length > len(data) or num_attrs > _APPLEDOUBLE_MAX_ATTRS:
        return False
    p = h + 36
    for _ in range(num_attrs):
        if p + 11 > end:
            return False
        value_off, value_len = struct.unpack_from(">II", data, p)
        name_len = data[p + 10]
        if name_len < 2 or p + 11 + name_len > end:
            return False
        raw = data[p + 11:p + 11 + name_len]
        if raw[-1] != 0 or b"\x00" in raw[:-1]:
            return False
        try:
            name = raw[:-1].decode("utf-8")
        except UnicodeDecodeError:
            return False
        if not _attr_name_ok(name):
            return False
        if value_len > _APPLEDOUBLE_MAX_ATTR_BYTES:
            return False
        if value_off < data_start or value_off + value_len > data_start + data_length:
            return False
        p = (p + 11 + name_len + 3) & ~3
    return True


def _empty_resource_fork(fork: bytes) -> bool:
    if not fork:
        return True
    return 16 <= len(fork) <= 512 and struct.unpack_from(">I", fork, 8)[0] == 0


def is_ds_store(data: bytes) -> bool:
    if len(data) < 36 or data[:8] != b"\x00\x00\x00\x01Bud1":
        return False
    off, size, off2 = struct.unpack_from(">III", data, 8)
    return off == off2 and size > 0 and 4 + off + size <= len(data)


def is_thumbs_db(data: bytes) -> bool:
    if len(data) < 512 or data[:8] != _OLE_MAGIC or data[28:30] != b"\xfe\xff":
        return False
    if struct.unpack_from("<H", data, 30)[0] not in (9, 12):
        return False
    return not any(stream in data for stream in _OLE_DOCUMENT_STREAMS)


def is_utf16_text(data: bytes) -> bool:
    """UTF-16 with a byte order mark and no control characters but tab and line breaks."""
    if len(data) < 4 or len(data) % 2 or data[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        return False
    try:
        text = data[2:].decode("utf-16-le" if data[:2] == b"\xff\xfe" else "utf-16-be")
    except UnicodeDecodeError:
        return False
    return not any(ch == "\x7f" or (ord(ch) < 0x20 and ch not in "\t\r\n") for ch in text)


def classify(root: str, rel: str, size: int) -> tuple[str, bool]:
    """(metadata kind to leave out, whether to re-encode as UTF-8) for a regular file."""
    name = os.path.basename(rel)
    path = os.path.join(root, rel)
    if name.startswith("._") and len(name) > 2:
        if size <= _APPLEDOUBLE_MAX_BYTES and _companion_exists(root, rel):
            data = _read_bounded(path, _APPLEDOUBLE_MAX_BYTES)
            if data is not None and is_appledouble_metadata(data):
                return APPLEDOUBLE_KIND, False
    elif name == ".DS_Store":
        if size <= _DS_STORE_MAX_BYTES:
            data = _read_bounded(path, _DS_STORE_MAX_BYTES)
            if data is not None and is_ds_store(data):
                return DS_STORE_KIND, False
    elif name.lower() == "thumbs.db":
        if size <= _THUMBS_DB_MAX_BYTES:
            data = _read_bounded(path, _THUMBS_DB_MAX_BYTES)
            if data is not None and is_thumbs_db(data):
                return THUMBS_DB_KIND, False
    elif name.lower() == "desktop.ini":
        if size <= _DESKTOP_INI_MAX_BYTES:
            data = _read_bounded(path, _DESKTOP_INI_MAX_BYTES)
            if data is not None and is_utf16_text(data):
                return "", True
    return "", False


def metadata_findings(metadata: list[tuple[str, str]], scanner: str) -> list[Finding]:
    """INFO findings naming each OS metadata file a scan copy left out."""
    return [
        Finding(
            id=f"{RULE_OS_METADATA_FILE}_{rel}",
            severity="INFO",
            title="OS metadata file not scanned",
            description=(
                f"{rel} is a {kind}. Its format was checked and it holds no file content, "
                "so the content scan left it out."
            ),
            location=rel,
            remediation=(
                "Remove OS metadata files from the skill folder; on macOS, create archives "
                "with COPYFILE_DISABLE=1 to leave out ._ files."
            ),
            rule_id=RULE_OS_METADATA_FILE,
            scanner=scanner,
            tags=["POLICY_VIOLATION", "analyzer:os_metadata"],
        )
        for rel, kind in metadata
    ]
