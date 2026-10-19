# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Fixed public release inspection. Never execute the installer or vendor images."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import selectors
import ssl
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "2.1.292"
PLATFORMS = ("linux-x64", "linux-x64-musl")
FINGERPRINT = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
BASE = "https://downloads.claude.ai/claude-code-releases/" + VERSION
INSTALLER = "https://downloads.claude.ai/claude-code-releases/bootstrap.sh"
KEY = "https://downloads.claude.ai/keys/claude-code.asc"
LICENSE = "https://raw.githubusercontent.com/anthropics/claude-code/fbe20e00e2851fc01506f54f98a8f0b875af3847/LICENSE.md"
MANIFEST = BASE + "/manifest.json"
SIGNATURE = MANIFEST + ".sig"
ALLOWED_URLS = frozenset(
    (INSTALLER, KEY, LICENSE, MANIFEST, SIGNATURE, *(BASE + "/" + p + "/claude" for p in PLATFORMS))
)
SOURCE_PATHS = (
    ".github/workflows/axis-native-claude-inspect.yml",
    "test/e2e/axis/native-peer/claude/README.md",
    "test/e2e/axis/native-peer/claude/inspect_artifact.py",
    "test/e2e/axis/native-peer/claude/test_inspect_artifact.py",
)
REPORT = Path("claude-inspect-report")
PRIVATE = Path("claude-inspect-private")
IMAGE_LIMIT = 512 * 1024 * 1024
TOOL_LIMIT = 8 * 1024 * 1024
REPORT_LIMIT = 20 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")


class InspectionError(ValueError):
    """A fixed inspection gate refused the available data."""


def require(condition, reason):
    if not condition:
        raise InspectionError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def manifest_checksums(raw):
    require(0 < len(raw) <= 1024 * 1024, "manifest size")
    try:
        obj = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InspectionError("manifest JSON") from exc
    require(isinstance(obj, dict) and obj.get("version") == VERSION, "manifest version")
    variants = obj.get("platforms")
    require(isinstance(variants, dict) and len(variants) <= 32, "manifest platforms")
    result = {}
    for name in PLATFORMS:
        if name not in variants:
            result[name] = None
            continue
        entry = variants[name]
        require(isinstance(entry, dict), "manifest platform entry")
        checksum = entry.get("checksum")
        require(isinstance(checksum, str) and HEX.fullmatch(checksum), "manifest checksum")
        if "size" in entry:
            require(type(entry["size"]) is int and 0 < entry["size"] <= IMAGE_LIMIT, "manifest image size")
        # No URL or command from the signed document becomes authority.
        result[name] = {"sha256": checksum, "size": entry.get("size")}
    require(result["linux-x64"] is not None, "linux-x64 not published")
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InspectionError("HTTP redirect refused")


def bounded_copy(reader, writer, limit, deadline, clock=time.monotonic):
    total = 0
    hashed = hashlib.sha256()
    while True:
        require(clock() < deadline, "download deadline")
        chunk = reader.read(min(64 * 1024, limit + 1 - total))
        require(isinstance(chunk, bytes), "download bytes")
        if not chunk:
            break
        total += len(chunk)
        require(total <= limit, "download byte limit")
        writer.write(chunk)
        hashed.update(chunk)
    require(total > 0, "empty download")
    return {"sha256": hashed.hexdigest(), "size": total}


def download(url, destination, limit):
    require(url in ALLOWED_URLS, "download URL refused")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    request = urllib.request.Request(
        url, headers={"Accept-Encoding": "identity", "User-Agent": "DefenseClaw-inert-inspection"}
    )
    deadline = time.monotonic() + 180
    with opener.open(request, timeout=15) as response, destination.open("xb") as output:
        require(response.status == 200 and response.geturl() == url, "HTTP response")
        require(response.headers.get("Content-Encoding", "identity") == "identity", "HTTP content encoding")
        length = response.headers.get("Content-Length")
        require(length is None or (length.isdecimal() and 0 < int(length) <= limit), "HTTP content length")
        result = bounded_copy(response, output, limit, deadline)
        require(length is None or int(length) == result["size"], "HTTP length mismatch")
    return {"url": url, **result}


def tool(argv, home, limit=TOOL_LIMIT, seconds=30):
    """Only trusted installed data readers; no shell, loader, or vendor execution."""
    require(argv[0] in ("/usr/bin/gpg", "/usr/bin/readelf"), "tool refused")
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home.resolve()),
        "LC_ALL": "C",
        "LANG": "C",
        "GNUPGHOME": str(home.resolve()),
    }
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, close_fds=True
    )
    stdout, stderr = bytearray(), bytearray()
    deadline = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as poll:
            for stream, target in ((process.stdout, stdout), (process.stderr, stderr)):
                os.set_blocking(stream.fileno(), False)
                poll.register(stream, selectors.EVENT_READ, target)
            while poll.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "tool deadline")
                for key, _ in poll.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, min(64 * 1024, limit + 1 - len(stdout) - len(stderr)))
                    if chunk:
                        key.data.extend(chunk)
                        require(len(stdout) + len(stderr) <= limit, "tool output limit")
                    else:
                        poll.unregister(key.fileobj)
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return process.returncode, bytes(stdout), bytes(stderr)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def key_fingerprint(colons):
    rows = colons.decode("ascii").splitlines()
    primaries = []
    public_count = 0
    awaiting = False
    for row in rows:
        fields = row.split(":")
        require(len(fields) >= 10, "key listing row")
        if fields[0] == "pub":
            public_count += 1
            require(fields[1] not in ("r", "e", "d"), "unusable public key")
            awaiting = True
        elif fields[0] == "fpr" and awaiting:
            primaries.append(fields[9])
            awaiting = False
    require(public_count == 1 and primaries == [FINGERPRINT], "release key fingerprint")
    return FINGERPRINT


def valid_signature(status):
    rows = status.decode("ascii").splitlines()
    signatures = []
    bad = {
        "BADSIG",
        "ERRSIG",
        "EXPSIG",
        "EXPKEYSIG",
        "REVKEYSIG",
        "KEYEXPIRED",
        "SIGEXPIRED",
        "NO_PUBKEY",
        "FAILURE",
        "ERROR",
        "NODATA",
    }
    for row in rows:
        require(row.startswith("[GNUPG:] "), "signature status row")
        fields = row[9:].split()
        require(fields and fields[0] not in bad, "signature refusal")
        if fields[0] == "VALIDSIG":
            require(len(fields) in (10, 11), "signature status shape")
            primary = fields[10] if len(fields) == 11 else fields[1]
            require(
                primary == FINGERPRINT and fields[7] in ("1", "3", "19", "22") and fields[8] in ("8", "9", "10"),
                "signature key or algorithm",
            )
            signatures.append(fields[1])
    require(len(signatures) == 1, "one valid release signature required")
    return {"primary_fingerprint": FINGERPRINT, "signing_fingerprint": signatures[0]}


def elf_headers(path):
    size = path.stat().st_size
    require(64 <= size <= IMAGE_LIMIT, "ELF size")
    with path.open("rb") as image:
        header = image.read(64)
        require(header[:7] == b"\x7fELF\x02\x01\x01", "ELF64 little endian required")
        kind, machine, version = struct.unpack_from("<HHI", header, 16)
        entry, offset = struct.unpack_from("<QQ", header, 24)
        ehsize, phsize, count = struct.unpack_from("<HHH", header, 52)
        require(kind in (2, 3) and machine == 62 and version == 1 and ehsize == 64, "ELF amd64 executable required")
        require(
            phsize == 56 and 0 < count <= 128 and offset >= 64 and offset + count * phsize <= size, "ELF program table"
        )
        image.seek(offset)
        programs = image.read(count * phsize)
        interpreters, executable_entry, wx = [], False, False
        loads = 0
        for index in range(count):
            ptype, flags, pos, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", programs, index * phsize)
            require(pos + filesz <= size and filesz <= memsz, "ELF segment bounds")
            if ptype == 1:
                loads += 1
                executable_entry |= bool(flags & 1 and vaddr <= entry < vaddr + filesz)
                wx |= flags & 3 == 3
            if ptype == 3:
                require(1 < filesz <= 4096, "ELF interpreter size")
                image.seek(pos)
                raw = image.read(filesz)
                require(raw[-1:] == b"\0" and b"\0" not in raw[:-1], "ELF interpreter string")
                text = raw[:-1].decode("ascii")
                require(text.startswith("/") and all(32 < ord(c) < 127 for c in text), "ELF interpreter path")
                interpreters.append(text)
        require(executable_entry and loads > 0 and len(interpreters) <= 1, "ELF entry/interpreter")
    return {
        "class": 64,
        "endian": "little",
        "machine": "x86_64",
        "type": "ET_EXEC" if kind == 2 else "ET_DYN",
        "entry": entry,
        "pt_interp": interpreters[0] if interpreters else None,
        "load_segments": loads,
        "writable_executable_load": wx,
    }


def dynamic_metadata(raw):
    text = raw.decode("utf-8", errors="strict")
    result = {"needed": [], "rpath": [], "runpath": []}
    for tag, value in re.findall(r"\((NEEDED|RPATH|RUNPATH)\)[^\n]*?\[([^\]\n]*)\]", text):
        require(0 < len(value) <= 4096 and all(32 <= ord(c) < 127 for c in value), "dynamic metadata string")
        target = result[{"NEEDED": "needed", "RPATH": "rpath", "RUNPATH": "runpath"}[tag]]
        require(len(target) < 128, "dynamic metadata count")
        target.append(value)
    result["imports_dlopen"] = bool(re.search(r"\bUND\b[^\n]*\bdlopen(?:@|\s|$)", text))
    result["imports_dlsym"] = bool(re.search(r"\bUND\b[^\n]*\bdlsym(?:@|\s|$)", text))
    result["runtime_dlopen_closure_established"] = False
    return result


def ordinary(path, limit):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, "ordinary bounded file required"
    )
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "file byte limit")
    return raw


def write_json(path, obj):
    raw = (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()
    require(len(raw) <= 1024 * 1024, "JSON report bound")
    path.write_bytes(raw)


def error_summary(exc):
    if isinstance(exc, InspectionError):
        category = "gate_refused"
    elif isinstance(exc, urllib.error.HTTPError):
        category = "http_error"
    elif isinstance(exc, UnicodeError):
        category = "text_decode_error"
    elif isinstance(exc, subprocess.SubprocessError):
        category = "reader_process_error"
    else:
        category = "os_error"
    errno = getattr(exc, "errno", None)
    status = getattr(exc, "code", None) if isinstance(exc, urllib.error.HTTPError) else None
    return {
        "category": category,
        "gate": {
            "HTTP redirect refused": "http_redirect_refused",
            "HTTP response": "http_response_refused",
            "HTTP content encoding": "http_content_encoding_refused",
            "HTTP content length": "http_content_length_refused",
            "HTTP length mismatch": "http_length_mismatch",
            "download deadline": "download_deadline",
            "download byte limit": "download_byte_limit",
            "empty download": "empty_download",
            "signed binary checksum mismatch": "signed_binary_checksum_mismatch",
            "signed binary size mismatch": "signed_binary_size_mismatch",
        }.get(str(exc))
        if isinstance(exc, InspectionError)
        else None,
        "errno": errno if type(errno) is int and 0 < errno <= 4095 else None,
        "http_status": status if type(status) is int and 400 <= status <= 599 else None,
    }


def artifact_inventory(root):
    allowed = {
        "PREBUILD.json",
        "RESULT.json",
        "installer.sh.txt",
        "manifest.json",
        "manifest.json.sig",
        "release-key.asc",
        "LICENSE.md",
        "TOOLS.json",
        "key-list.txt",
        "key-import.txt",
        "signature-status.txt",
        *(p + "-readelf.txt" for p in PLATFORMS),
        *("source/" + p for p in SOURCE_PATHS),
    }
    directories = {parent.as_posix() for name in allowed for parent in Path(name).parents if parent != Path(".")}
    files, total = {}, 0
    for path in root.rglob("*"):
        require(not path.is_symlink(), "artifact symlink")
        name = path.relative_to(root).as_posix()
        if path.is_dir():
            require(name in directories, "artifact directory refused")
            continue
        require(name in allowed, "artifact member refused")
        raw = ordinary(path, TOOL_LIMIT)
        total += len(raw)
        require(total <= REPORT_LIMIT and len(files) < 32, "artifact bounds")
        files[name] = {"sha256": digest(raw), "size": len(raw)}
    return files


def inspect(report, private, result):
    result["inspection_stage"] = "installed_readers"
    home = private / "gnupg"
    home.mkdir(mode=0o700)
    tools = {}
    for name in ("gpg", "readelf"):
        path = Path("/usr/bin") / name
        raw = ordinary(path.resolve(strict=True), 32 * 1024 * 1024)
        code, out, err = tool([str(path), "--version"], home, 64 * 1024)
        require(code == 0, "installed reader unavailable")
        tools[name] = {
            "path": str(path),
            "resolved_path": str(path.resolve()),
            "sha256": digest(raw),
            "size": len(raw),
            "version": out.decode("utf-8"),
            "stderr": err.decode("utf-8"),
        }
    write_json(report / "TOOLS.json", tools)
    downloads = result["downloads"]
    result["inspection_stage"] = "fetch_public_metadata"
    for url, name, limit in (
        (INSTALLER, "installer.sh.txt", 128 * 1024),
        (MANIFEST, "manifest.json", 1024 * 1024),
        (SIGNATURE, "manifest.json.sig", 64 * 1024),
        (KEY, "release-key.asc", 128 * 1024),
        (LICENSE, "LICENSE.md", 128 * 1024),
    ):
        downloads[name] = download(url, report / name, limit)
    gpg = [
        "/usr/bin/gpg",
        "--no-options",
        "--homedir",
        str(home.resolve()),
        "--batch",
        "--no-tty",
        "--no-autostart",
        "--no-auto-key-retrieve",
        "--no-auto-key-import",
        "--disable-dirmngr",
    ]
    result["inspection_stage"] = "inspect_release_key"
    code, out, err = tool(
        gpg + ["--with-colons", "--fingerprint", "--show-keys", str((report / "release-key.asc").resolve())],
        home,
        256 * 1024,
    )
    (report / "key-list.txt").write_bytes(out + b"\n" + err)
    require(code == 0, "public key inspection failed")
    key_fingerprint(out)
    result["inspection_stage"] = "import_release_key"
    code, out, err = tool(
        gpg + ["--import-options", "import-minimal", "--import", str((report / "release-key.asc").resolve())],
        home,
        256 * 1024,
    )
    (report / "key-import.txt").write_bytes(out + b"\n" + err)
    require(code == 0, "public key import failed")
    result["inspection_stage"] = "verify_manifest_signature"
    code, out, err = tool(
        gpg
        + [
            "--status-fd",
            "1",
            "--verify",
            str((report / "manifest.json.sig").resolve()),
            str((report / "manifest.json").resolve()),
        ],
        home,
        256 * 1024,
    )
    (report / "signature-status.txt").write_bytes(out + b"\n" + err)
    require(code == 0, "release signature failed")
    result["signature"] = valid_signature(out)
    result["inspection_stage"] = "parse_signed_manifest"
    variants = manifest_checksums(ordinary(report / "manifest.json", 1024 * 1024))
    for name in PLATFORMS:
        if variants[name] is None:
            result["variants"][name] = {"published": False}
            continue
        image = private / name
        result["inspection_stage"] = "download_" + name
        info = download(BASE + "/" + name + "/claude", image, IMAGE_LIMIT)
        require(info["sha256"] == variants[name]["sha256"], "signed binary checksum mismatch")
        require(variants[name]["size"] in (None, info["size"]), "signed binary size mismatch")
        result["inspection_stage"] = "elf_headers_" + name
        headers = elf_headers(image)
        result["inspection_stage"] = "readelf_" + name
        code, out, err = tool(
            [
                "/usr/bin/readelf",
                "--wide",
                "--file-header",
                "--program-headers",
                "--dynamic",
                "--version-info",
                "--notes",
                "--dyn-syms",
                str(image.resolve()),
            ],
            home,
        )
        (report / (name + "-readelf.txt")).write_bytes(out + b"\n" + err)
        require(code == 0, "readelf inspection failed")
        result["variants"][name] = {
            "published": True,
            **info,
            **headers,
            **dynamic_metadata(out),
            "readelf_stderr_bytes": len(err),
        }
    result["inspection_stage"] = "complete"


def main():
    require(len(sys.argv) == 1, "no inspector arguments accepted")
    os.umask(0o077)
    require(sys.platform == "linux" and platform.machine() == "x86_64", "Linux amd64 runner")
    require(
        os.environ.get("GITHUB_REPOSITORY") == "cisco-ai-defense/defenseclaw"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
        "manual repository scope",
    )
    require(REPORT.is_dir() and not REPORT.is_symlink() and not PRIVATE.exists(), "fresh output scope")
    PRIVATE.mkdir(mode=0o700)
    result = {
        "scope": "fixed_official_claude_linux_elf_inspection_only",
        "version": VERSION,
        "signing_key_fingerprint": FINGERPRINT,
        "platforms": list(PLATFORMS),
        "repository": os.environ["GITHUB_REPOSITORY"],
        "workflow": ".github/workflows/axis-native-claude-inspect.yml",
        "commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "python": sys.version,
        "downloads": {},
        "variants": {},
        "inspection_complete": False,
        "inspection_stage": "before_inspection",
        "vendor_execution_performed": False,
        "installer_execution_performed": False,
        "runtime_admission": False,
        "production_certification": False,
        "error": None,
    }
    failed = False
    try:
        inspect(REPORT, PRIVATE, result)
        result["inspection_complete"] = True
    except (InspectionError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        failed = True
        # Exception messages can contain private runner paths; publish only closed
        # categories, a fixed stage, and bounded numeric OS/HTTP codes.
        result["error"] = error_summary(exc)
    finally:
        write_json(REPORT / "RESULT.json", result)
        write_json(REPORT / "ARTIFACT-MANIFEST.json", artifact_inventory(REPORT))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
