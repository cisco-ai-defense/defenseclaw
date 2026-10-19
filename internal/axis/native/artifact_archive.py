# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bounded inert archive readers. Never extract paths or execute archive tools."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import lzma
import re
import stat
import struct
import zipfile
from pathlib import Path

FILE_LIMIT = 128 << 20
TOTAL_LIMIT = 512 << 20
MEMBER_LIMIT = 16384


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path_name(name: str) -> str:
    if (
        not name
        or len(name) > 4096
        or name.startswith("/")
        or any(ord(value) < 32 or ord(value) == 127 for value in name)
        or any(value in name for value in ("\\", ":"))
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise ValueError("archive has an unsafe member name")
    return name


def ordinary(path: Path, bound: int = FILE_LIMIT) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
        raise ValueError("input must be a non-reparse regular file")
    with path.open("rb") as stream:
        data = stream.read(bound + 1)
    if len(data) > bound:
        raise ValueError("input exceeds its byte bound")
    return data


def json_object(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("JSON has duplicate keys")
            result[key] = value
        return result

    if len(raw) > 4 << 20:
        raise ValueError("JSON exceeds its byte bound")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: fail("nonfinite JSON"))
    if not isinstance(value, dict):
        raise ValueError("JSON must be an object")
    return value


def fail(message: str):
    raise ValueError(message)


def zip_inventory(raw: bytes):
    """Bound central-directory parsing before zipfile allocates member objects."""
    if len(raw) < 22 or raw[-22:-18] != b"PK\x05\x06":
        raise ValueError("ZIP requires an unambiguous comment-free end record")
    disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4H2IH", raw, len(raw) - 18)
    if (
        disk
        or directory_disk
        or disk_count != count
        or not 1 <= count <= MEMBER_LIMIT
        or count == 0xFFFF
        or comment
        or size > 16 << 20
        or offset + size != len(raw) - 22
    ):
        raise ValueError("ZIP central-directory count, size or disk contract differs")
    cursor, seen = offset, 0
    while cursor < offset + size:
        if seen >= count or cursor + 46 > offset + size or raw[cursor : cursor + 4] != b"PK\x01\x02":
            raise ValueError("ZIP central-directory record inventory differs")
        compressed, uncompressed = struct.unpack_from("<II", raw, cursor + 20)
        name, extra, note, start_disk = struct.unpack_from("<4H", raw, cursor + 28)
        local = struct.unpack_from("<I", raw, cursor + 42)[0]
        end = cursor + 46 + name + extra + note
        if (
            not 1 <= name <= 4096
            or end > offset + size
            or start_disk
            or local >= offset
            or compressed == 0xFFFFFFFF
            or uncompressed == 0xFFFFFFFF
        ):
            raise ValueError("ZIP central-directory member is unsupported")
        at, extra_end = cursor + 46 + name, cursor + 46 + name + extra
        while at < extra_end:
            if at + 4 > extra_end:
                raise ValueError("ZIP extra field is truncated")
            tag, length = struct.unpack_from("<HH", raw, at)
            at += 4 + length
            if tag == 1 or at > extra_end:
                raise ValueError("ZIP64 or malformed extra fields are unsupported")
        cursor, seen = end, seen + 1
    if cursor != offset + size or seen != count:
        raise ValueError("ZIP central-directory count differs")


class ZipEvidence:
    def __init__(self, raw: bytes):
        if not raw or len(raw) > FILE_LIMIT:
            raise ValueError("ZIP exceeds its byte bound")
        zip_inventory(raw)
        self.archive = zipfile.ZipFile(io.BytesIO(raw))
        self.files = {}
        names, total = set(), 0
        members = self.archive.infolist()
        if not members or len(members) > MEMBER_LIMIT:
            raise ValueError("ZIP has an unsupported member count")
        for member in members:
            if member.orig_filename != member.filename:
                raise ValueError("ZIP name was normalized or truncated by the host")
            name = path_name(member.filename.removesuffix("/"))
            if name.casefold() in names:
                raise ValueError("ZIP has duplicate or case-ambiguous names")
            names.add(name.casefold())
            mode = member.external_attr >> 16
            if (
                member.is_dir()
                or member.flag_bits & 1
                or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or stat.S_IFMT(mode) not in {0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG}
                or mode & 0o6000
                or member.file_size > FILE_LIMIT
                or member.file_size < 0
                or (member.is_dir() and member.file_size)
            ):
                raise ValueError("ZIP has an unsupported member")
            total += member.file_size
            if total > TOTAL_LIMIT:
                raise ValueError("ZIP exceeds its total byte bound")
            if not member.is_dir():
                self.files[name] = member
        for name in self.files:
            if any("/".join(name.split("/")[:index]) in self.files for index in range(1, name.count("/") + 1)):
                raise ValueError("ZIP member is a file ancestor")

    def read(self, name: str, bound: int = FILE_LIMIT) -> bytes:
        member = self.files.get(path_name(name))
        if member is None or member.file_size > bound:
            raise ValueError("missing or oversized ZIP evidence")
        with self.archive.open(member) as stream:
            raw = stream.read(bound + 1)
        if len(raw) != member.file_size or len(raw) > bound:
            raise ValueError("ZIP member differs from its declared size")
        return raw

    def object(self, name: str) -> dict:
        return json_object(self.read(name, 4 << 20))


class DecodeBudget:
    def __init__(self, bound: int = TOTAL_LIMIT):
        self.remaining = bound

    def charge(self, size: int):
        self.remaining -= size
        if self.remaining < 0:
            raise ValueError("nested decompression exceeds its aggregate byte bound")


class BoundedReader(io.RawIOBase):
    """Cap decompressed bytes independently of archive size declarations."""

    def __init__(self, source, bound: int = TOTAL_LIMIT, *, budget: DecodeBudget | None = None):
        self.source, self.remaining = source, bound
        self.budget = budget if budget is not None else DecodeBudget(bound)

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            size = self.remaining + 1
        raw = self.source.read(min(size, self.remaining + 1, self.budget.remaining + 1))
        self.remaining -= len(raw)
        self.budget.charge(len(raw))
        if self.remaining < 0:
            raise ValueError("decompression exceeds its total byte bound")
        return raw

    def readinto(self, buffer):
        raw = self.read(len(buffer))
        buffer[: len(raw)] = raw
        return len(raw)


class LzmaReader(io.RawIOBase):
    def __init__(self, source):
        self.source = source
        self.decoder = lzma.LZMADecompressor(memlimit=FILE_LIMIT)

    def read(self, size=-1):
        if not 0 <= size <= TOTAL_LIMIT + 1:
            raise ValueError("unsupported decompressor read size")
        result = bytearray()
        while len(result) < size and not self.decoder.eof:
            raw = self.source.read(64 << 10) if self.decoder.needs_input else b""
            if not raw and self.decoder.needs_input:
                raise ValueError("xz stream is truncated")
            result.extend(self.decoder.decompress(raw, max_length=size - len(result)))
        if self.decoder.eof and (self.decoder.unused_data or self.source.read(1)):
            raise ValueError("xz stream has trailing or concatenated data")
        return bytes(result)


def tar_files(
    stream,
    required: set[str],
    *,
    all_regular: bool = False,
    budget: DecodeBudget | None = None,
    links: dict[str, tuple[bytes, str]] | None = None,
) -> dict[str, bytes]:
    """Read selected regular bytes only; reject path/count/size ambiguity."""
    found, seen = {}, set()
    source, count, pending = BoundedReader(stream, budget=budget), 0, None
    while True:
        header = exact(source, 512)
        if header == bytes(512):
            if pending is not None or exact(source, 512) != bytes(512):
                raise ValueError("tar has incomplete metadata or termination")
            while tail := source.read(64 << 10):
                if any(tail):
                    raise ValueError("tar has nonzero trailing bytes")
            break
        count += 1
        if count > MEMBER_LIMIT or number(header[148:156]) != sum(header[:148] + b" " * 8 + header[156:]):
            raise ValueError("tar has excess headers or a bad checksum")
        size, kind = number(header[124:136]), header[156:157]
        if size > FILE_LIMIT or header[257:263] not in {b"ustar\0", b"ustar "}:
            raise ValueError("tar has an oversized or unsupported header")
        name = header[:100].split(b"\0", 1)[0]
        prefix = header[345:500].split(b"\0", 1)[0] if header[257:263] == b"ustar\0" else b""
        name = ((prefix + b"/") if prefix else b"") + name
        # Count metadata headers too. Only bounded GNU names and Git's fixed
        # global commit comment are supported; unknown PAX overrides refuse.
        if kind in {b"L", b"g"}:
            if pending is not None or size > 8192:
                raise ValueError("unsupported tar metadata chain")
            raw = exact(source, size)
            if kind == b"L":
                if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                    raise ValueError("malformed GNU tar long name")
                pending = raw[:-1]
            elif not re.fullmatch(rb"52 comment=[0-9a-f]{40}\n", raw):
                raise ValueError("unsupported global tar metadata")
        else:
            name = pending if pending is not None else name
            pending = None
            decoded = name.decode("utf-8")
            while decoded.startswith("./"):
                decoded = decoded[2:]
            is_directory = kind == b"5"
            if decoded not in {"", "."} or not is_directory:
                decoded = path_name(decoded.removesuffix("/") if is_directory else decoded)
                if decoded in seen:
                    raise ValueError("tar has duplicate normalized names")
                seen.add(decoded)
            if kind not in {b"\0", b"0", b"5", b"1", b"2"} or (all_regular and kind in {b"1", b"2"}):
                raise ValueError("tar has an unsupported member type")
            if kind not in {b"\0", b"0"} and size:
                raise ValueError("non-regular tar member has bytes")
            if links is not None and kind in {b"1", b"2"}:
                target = header[157:257].split(b"\0", 1)[0].decode("utf-8")
                if (
                    not target
                    or any(ord(value) < 32 or ord(value) == 127 for value in target)
                    or any(value in target for value in ("\\", ":"))
                ):
                    raise ValueError("tar has an unsupported link target")
                links[decoded] = (kind, target)
            if decoded in required:
                if kind not in {b"\0", b"0"}:
                    raise ValueError("required tar input is not a regular file")
                found[decoded] = exact(source, size)
            else:
                remaining = size
                while remaining:
                    remaining -= len(exact(source, min(remaining, 64 << 10)))
        if any(exact(source, (-size) % 512)):
            raise ValueError("tar has nonzero member padding")
    if set(found) != required:
        raise ValueError("tar required input inventory differs")
    return found


def exact(stream, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            raise ValueError("archive is truncated")
        result.extend(part)
    return bytes(result)


def number(raw: bytes) -> int:
    value = raw.rstrip(b"\0 ").lstrip(b" ")
    if not value or re.fullmatch(rb"[0-7]+", value) is None:
        raise ValueError("tar numeric field is unsupported")
    return int(value, 8)


def deb_data(raw: bytes):
    if len(raw) > FILE_LIMIT or raw[:8] != b"!<arch>\n":
        raise ValueError("package is not a bounded ar archive")
    offset, members = 8, {}
    while offset < len(raw):
        header = raw[offset : offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("package has a malformed ar header")
        name = header[:16].decode("ascii").strip().removesuffix("/")
        if not header[48:58].strip().isdigit() or name in members or len(members) >= 3:
            raise ValueError("package has ambiguous ar members")
        size = int(header[48:58])
        offset += 60
        if size > FILE_LIMIT or offset + size > len(raw):
            raise ValueError("package ar member exceeds its bound")
        members[name] = raw[offset : offset + size]
        offset += size
        if offset & 1:
            if raw[offset : offset + 1] != b"\n":
                raise ValueError("package ar padding differs")
            offset += 1
    data = [name for name in members if name in {"data.tar.xz", "data.tar.gz", "data.tar.zst"}]
    control = [name for name in members if name in {"control.tar.xz", "control.tar.gz", "control.tar.zst"}]
    if members.get("debian-binary") != b"2.0\n" or len(data) != 1 or len(control) != 1 or len(members) != 3:
        raise ValueError("unsupported Debian package member inventory")
    stream = io.BytesIO(members[data[0]])
    if data[0].endswith(".xz"):
        return LzmaReader(stream)
    if data[0].endswith(".gz"):
        return gzip.GzipFile(fileobj=stream)
    try:
        from compression import zstd
    except ImportError as error:
        raise ValueError("zstd package verification requires Python 3.14 compression.zstd") from error
    return zstd.ZstdFile(stream, options={zstd.DecompressionParameter.window_log_max: 27})
