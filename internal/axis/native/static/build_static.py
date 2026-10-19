#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-only static musl closure; never executes Bubblewrap or a sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
GCC = Path("/usr/bin/x86_64-linux-gnu-gcc-13")
EPOCH = "1775403096"
LIMIT = 4 << 20
C_FILES = ("bubblewrap.c", "bind-mount.c", "network.c", "utils.c")
WARNINGS = (
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Werror=shadow",
    "-Werror=empty-body",
    "-Werror=strict-prototypes",
    "-Werror=missing-prototypes",
    "-Werror=implicit-function-declaration",
    "-Werror=pointer-arith",
    "-Werror=init-self",
    "-Werror=missing-declarations",
    "-Werror=return-type",
    "-Werror=overflow",
    "-Werror=int-conversion",
    "-Werror=parentheses",
    "-Werror=incompatible-pointer-types",
    "-Werror=misleading-indentation",
    "-Werror=missing-include-dirs",
    "-Werror=aggregate-return",
    "-Werror=switch-default",
    "-Wswitch-enum",
    "-Wno-missing-field-initializers",
    "-Wno-error=missing-field-initializers",
    "-Werror=format=2",
    "-Werror=format-security",
    "-Werror=format-nonliteral",
)


def raw(path: Path, bound: int = 256 << 20, *, allow_empty: bool = False) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise RuntimeError(f"not a regular non-symlink file: {path}")
    with path.open("rb") as stream:
        data = stream.read(bound + 1)
    if (not data and not allow_empty) or len(data) > bound:
        raise RuntimeError(f"file exceeds bound or is empty: {path}")
    return data


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(path: Path, *, allow_empty: bool = False) -> dict[str, object]:
    data = raw(path, allow_empty=allow_empty)
    return {"sha256": digest(data), "size": len(data)}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def environment(home: Path) -> dict[str, str]:
    # Fixed build environment only. In particular no REALGCC, CC, loader,
    # pkg-config, make flags, token or inherited compiler overrides survive.
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": EPOCH}


class Commands:
    def __init__(self, evidence: Path):
        self.evidence = evidence
        self.home = evidence / "build-home"
        self.home.mkdir()
        self.number = 0

    def run(self, argv: list[str], cwd: Path, *, extra: dict[str, str] | None = None) -> str:
        self.number += 1
        stem = self.evidence / f"command-{self.number:03d}"
        env = environment(self.home)
        if extra:
            if set(extra) - {"CC", "CFLAGS", "AR", "RANLIB"}:
                raise RuntimeError("unexpected build environment extension")
            env.update(extra)
        write_json(stem.with_suffix(".json"), {"argv": argv, "cwd": str(cwd), "environment": env})
        # Logs go to files rather than an unbounded in-memory PIPE. A failed
        # build retains its exact command and both diagnostics for review.
        with stem.with_suffix(".stdout").open("wb") as stdout, stem.with_suffix(".stderr").open("wb") as stderr:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                timeout=900,
                check=False,
            )
        if result.returncode:
            raise RuntimeError(f"static build command {self.number} failed ({result.returncode}); see {stem}")
        return raw(stem.with_suffix(".stdout"), 32 << 20).decode() if stem.with_suffix(".stdout").stat().st_size else ""


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, newurl):
        old, new = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme != "https" or new.netloc != old.netloc or new.username or new.password:
            raise RuntimeError("unreviewed source redirect")
        return super().redirect_request(request, file, code, message, headers, newurl)


def fetch(pin: dict[str, object], target: Path) -> None:
    url = str(pin["archive"])
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"musl.libc.org", "www.kernel.org"}:
        raise RuntimeError("unreviewed source URL")
    opener = urllib.request.build_opener(SameHostRedirect())
    with opener.open(url, timeout=30) as response, target.open("xb") as output:
        data = response.read(LIMIT + 1)
        if len(data) > LIMIT or len(data) != pin["archive_size"] or digest(data) != pin["archive_sha256"]:
            raise RuntimeError("source archive size/hash differs")
        output.write(data)


def tar_inventory(archive: tarfile.TarFile, prefix: str) -> list[tarfile.TarInfo]:
    members = []
    names = set()
    total = 0
    for member in archive:
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (
            not name
            or parts[0] != prefix
            or any(part in ("", ".", "..") for part in parts)
            or "\\" in name
            or name in names
            or not (member.isfile() or member.isdir())
            or member.mode & 0o7000
            or member.size < 0
            or member.size > LIMIT
        ):
            raise RuntimeError("source archive has an inadmissible entry")
        names.add(name)
        total += member.size
        members.append(member)
        if len(members) > 4096 or total > 32 << 20:
            raise RuntimeError("source archive exceeds extraction bounds")
    if not members:
        raise RuntimeError("source archive is empty")
    for member in members:
        parents = PurePosixPath(member.name.rstrip("/")).parents
        for parent in parents:
            if str(parent) in names and not next(m for m in members if m.name.rstrip("/") == str(parent)).isdir():
                raise RuntimeError("source archive has a file ancestor")
    return members


def extract(path: Path, destination: Path, prefix: str) -> Path:
    destination.mkdir()
    # No extractall/filter-version dependence. Validate the whole tar first,
    # then write only ordinary files into a fresh private directory.
    with tarfile.open(path, "r:*") as archive:
        members = tar_inventory(archive, prefix)
        for member in sorted(members, key=lambda value: (not value.isdir(), value.name)):
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError("source archive regular file has no data")
                with source, target.open("xb") as output:
                    data = source.read(LIMIT + 1)
                    if len(data) != member.size:
                        raise RuntimeError("source archive file size differs")
                    output.write(data)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination / prefix


def elf(data: bytes) -> dict[str, object]:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise RuntimeError("static image must be ELF64 little-endian")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    offset = struct.unpack_from("<Q", data, 32)[0]
    header_size, entry_size, count = struct.unpack_from("<HHH", data, 52)
    if kind != 2 or machine != 62 or version != 1 or header_size != 64 or entry_size != 56 or not 1 <= count <= 128:
        raise RuntimeError("static image has unsupported ELF structure")
    if offset < 64 or offset + entry_size * count > len(data):
        raise RuntimeError("static image program headers exceed file")
    loads = 0
    executable = False
    for index in range(count):
        ptype, flags, start, _, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", data, offset + index * 56)
        if ptype in {2, 3}:
            raise RuntimeError("static image has PT_DYNAMIC or PT_INTERP")
        if start + size > len(data) or size > memory:
            raise RuntimeError("static image segment exceeds file or memory")
        if ptype == 1:
            loads += 1
            executable |= bool(flags & 1)
    if not loads or not executable:
        raise RuntimeError("static image lacks executable load segment")
    return {
        "elf": "ELF64_LE_ET_EXEC_X86_64",
        "load_segments": loads,
        "program_headers": count,
        "pt_interp": False,
        "pt_dynamic": False,
    }


def admit_link_map(text: str, expected: set[Path]) -> list[str]:
    entries = re.findall(r"^LOAD (.+)$", text, re.MULTILINE)
    if not entries:
        raise RuntimeError("link map has no explicit input inventory")
    seen = set()
    for entry in entries:
        path = Path(entry)
        if not path.is_absolute() or path.suffix not in {".a", ".o"}:
            raise RuntimeError("link map has unexpected or non-absolute input")
        seen.add(path.resolve(strict=True))
    required = {path.resolve(strict=True) for path in expected}
    if seen != required:
        raise RuntimeError(f"link input closure differs: extra={seen - required}, missing={required - seen}")
    return sorted(map(str, seen))


def ubuntu_url(value: str) -> bool:
    parsed = urllib.parse.urlsplit(value)
    return (
        parsed.scheme in {"https", "http"}
        and parsed.hostname in {"azure.archive.ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com"}
        and parsed.netloc == parsed.hostname
        and parsed.path.rstrip("/") == "/ubuntu"
        and not parsed.query
        and not parsed.fragment
    )


def ubuntu_origins(policy: str, version: str, mirrors: bytes | None = None) -> list[str]:
    selected = False
    sources = []
    for line in policy.splitlines():
        heading = re.fullmatch(r"\s*(?:\*\*\*\s+)?(\S+)\s+\d+\s*", line)
        if heading:
            selected = heading[1] == version
            continue
        if not selected:
            continue
        entry = re.fullmatch(r"\s+\d+ (\S+) (\S+) (?:amd64|all) Packages", line)
        if entry:
            if not entry[2].startswith(("noble/", "noble-updates/", "noble-security/")):
                raise RuntimeError("compiler input uses an unreviewed package origin")
            urls = [entry[1]]
            if entry[1] == "mirror+file:/etc/apt/apt-mirrors.txt":
                if not mirrors or len(mirrors) > 16 << 10:
                    raise RuntimeError("exact Ubuntu runner mirror mapping is required")
                urls = []
                for mirror in mirrors.decode("ascii").splitlines():
                    fields = mirror.split("#", 1)[0].split()
                    if not fields:
                        continue
                    if len(fields) not in {1, 2} or (
                        len(fields) == 2 and not re.fullmatch(r"priority:[1-9][0-9]{0,3}", fields[1])
                    ):
                        raise RuntimeError("unexpected Ubuntu runner mirror syntax")
                    urls.append(fields[0])
            if not urls or any(not ubuntu_url(url) for url in urls):
                raise RuntimeError("compiler input uses an unreviewed package origin")
            sources.extend(url + " " + entry[2] for url in urls)
    if not sources:
        raise RuntimeError("installed compiler input has no exact Ubuntu24.04 APT origin")
    return sorted(set(sources))


def copyright_chain(path: Path, root: Path = Path("/usr/share/doc")) -> tuple[Path, list[tuple[Path, str]]]:
    """Inventory every bounded shared-documentation link before resolving it."""
    if not root.is_absolute() or root.resolve(strict=True) != root or not path.is_relative_to(root):
        raise RuntimeError("copyright path is outside the canonical documentation root")
    pending, current, links, seen = list(path.relative_to(root).parts), root, [], set()
    while pending:
        current /= pending.pop(0)
        if not stat.S_ISLNK(current.lstat().st_mode):
            continue
        if current in seen or len(links) >= 32:
            raise RuntimeError("copyright link chain is cyclic or oversized")
        seen.add(current)
        target = str(current.readlink())
        if not target or len(target) > 4096 or any(ord(value) < 32 or ord(value) == 127 for value in target):
            raise RuntimeError("copyright link target is unsupported")
        links.append((current, target))
        redirected = Path(os.path.normpath(current.parent / target))
        if not redirected.is_relative_to(root):
            raise RuntimeError("copyright link escapes the documentation root")
        pending = list(redirected.relative_to(root).parts) + pending
        current = root
    if not stat.S_ISREG(current.lstat().st_mode) or current.resolve(strict=True) != current:
        raise RuntimeError("copyright does not resolve to an ordinary recorded file")
    return current, links


class Packages:
    """Match installed inputs to SHA256-admitted Ubuntu package payloads."""

    def __init__(self, commands: Commands, evidence: Path):
        self.commands, self.evidence = commands, evidence
        self.files: dict[str, dict[str, object]] = {}
        self.links: dict[str, dict[str, str]] = {}
        self.packages: dict[str, dict[str, str]] = {}
        self.directory = evidence / "package-downloads"
        self.directory.mkdir()

    def add(self, path: Path) -> None:
        path = path.resolve(strict=True)
        name = str(path)
        if name in self.files:
            return
        package = self.package_for(path)
        self.files[name] = {**record(path), "package": package}

    def package_for(self, path: Path) -> str:
        name = str(path)
        # All callers supply fixed tools, their reported support files, the
        # three fixed UAPI trees, or package license paths. No caller workload.
        owner = self.commands.run(["/usr/bin/dpkg-query", "-S", name], self.directory).strip()
        if "\n" in owner or ": " not in owner:
            raise RuntimeError("installed input has ambiguous package ownership")
        package, reported = owner.rsplit(": ", 1)
        if reported != name or "," in package or not re.fullmatch(r"[a-z0-9+.-]+(?::[a-z0-9]+)?", package):
            raise RuntimeError("installed input package owner differs")
        if package not in self.packages:
            query = self.commands.run(
                [
                    "/usr/bin/dpkg-query",
                    "-W",
                    "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}",
                    package,
                ],
                self.directory,
            )
            identity, version, arch, status = query.strip().split("\t")
            if status != "installed" or arch not in {"amd64", "all"}:
                raise RuntimeError("unexpected build package status/architecture")
            records = self.commands.run(["/usr/bin/apt-cache", "show", f"{identity}:{arch}={version}"], self.directory)
            candidates = []
            for block in records.strip().split("\n\n"):
                fields = dict(re.findall(r"^([A-Za-z0-9-]+): (.*)$", block, re.MULTILINE))
                if (
                    fields.get("Package") == identity
                    and fields.get("Version") == version
                    and fields.get("Architecture") == arch
                ):
                    candidates.append(fields)
            hashes = {candidate.get("SHA256", "") for candidate in candidates}
            if len(hashes) != 1 or not re.fullmatch(r"[a-f0-9]{64}", next(iter(hashes), "")):
                raise RuntimeError("exact installed package lacks authenticated APT SHA256 metadata")
            policy = self.commands.run(["/usr/bin/apt-cache", "policy", f"{identity}:{arch}"], self.directory)
            mirrors = None
            if "mirror+file:/etc/apt/apt-mirrors.txt" in policy:
                mirrors = raw(Path("/etc/apt/apt-mirrors.txt"), 16 << 10)
                (self.evidence / "APT-MIRRORS.txt").write_bytes(mirrors)
            origins = ubuntu_origins(policy, version, mirrors)
            work = self.directory / package.replace(":", "_")
            work.mkdir()
            self.commands.run(["/usr/bin/apt-get", "download", f"{identity}:{arch}={version}"], work)
            debs = list(work.glob("*.deb"))
            if len(debs) != 1 or digest(raw(debs[0])) != next(iter(hashes)):
                raise RuntimeError("downloaded toolchain package hash differs from APT metadata")
            self.packages[package] = {
                "package": identity,
                "version": version,
                "architecture": arch,
                "archive_sha256": next(iter(hashes)),
                "deb": str(debs[0]),
                "origins": origins,
            }
        return package

    def copyright(self, name: str) -> Path:
        path, links = copyright_chain(Path("/usr/share/doc") / name / "copyright")
        for link, target in links:
            value = {"target": target, "package": self.package_for(link)}
            if str(link) in self.links and self.links[str(link)] != value:
                raise RuntimeError("copyright link changed during inventory")
            self.links[str(link)] = value
        self.add(path)
        return path

    def finish(self) -> None:
        # Copyright paths can be shared through a different binary package.
        # Include that package too, including the UAPI syscall exception and
        # GCC runtime exception; no notices are omitted just because UAPI was
        # staged after the compiler tools were inventoried.
        noticed = set()
        while True:
            pending = {value["package"] for value in self.packages.values()} - noticed
            if not pending:
                break
            for name in sorted(pending):
                copyright_path = self.copyright(name)
                shutil.copyfile(copyright_path, self.evidence / f"copyright-{name}.txt")
                noticed.add(name)
        # One streaming pass per admitted .deb, never extract package contents.
        # Confirm the bytes we actually used, rather than treating dpkg ownership
        # or its MD5 list as a SHA256 attestation of installed file contents.
        for package, metadata in self.packages.items():
            required = {path for path, value in self.files.items() if value["package"] == package}
            required_links = {path for path, value in self.links.items() if value["package"] == package}
            seen, seen_links = set(), set()
            process = subprocess.Popen(
                ["/usr/bin/dpkg-deb", "--fsys-tarfile", metadata["deb"]],
                env=environment(self.commands.home),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
            try:
                assert process.stdout is not None
                with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                    for member in archive:
                        path = "/" + member.name.removeprefix("./")
                        if path in required_links:
                            if (
                                not member.issym()
                                or member.linkname != self.links[path]["target"]
                                or path in seen_links
                            ):
                                raise RuntimeError("installed copyright link differs from admitted package payload")
                            seen_links.add(path)
                        if path not in required:
                            continue
                        if not member.isfile() or member.size > 256 << 20:
                            raise RuntimeError("package input is not an admitted ordinary file")
                        stream = archive.extractfile(member)
                        assert stream is not None
                        with stream:
                            value = stream.read((256 << 20) + 1)
                        if len(value) != member.size or digest(value) != self.files[path]["sha256"]:
                            raise RuntimeError("installed toolchain input differs from admitted package payload")
                        seen.add(path)
                if process.wait(timeout=30) or seen != required or seen_links != required_links:
                    raise RuntimeError("toolchain package payload inventory differs")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                if process.stdout is not None:
                    process.stdout.close()
        write_json(
            self.evidence / "UBUNTU-PACKAGES.json",
            {"packages": self.packages, "installed_files": self.files, "installed_links": self.links},
        )


def toolchain(commands: Commands, evidence: Path) -> tuple[dict[str, Path], Packages]:
    if not GCC.is_file():
        raise RuntimeError("exact GCC13 driver unavailable; no compiler fallback")
    if commands.run([str(GCC), "-dumpmachine"], evidence).strip() != "x86_64-linux-gnu":
        raise RuntimeError("unexpected compiler target")
    inputs = {"gcc": GCC.resolve(strict=True)}
    for name in ("cc1", "collect2", "as", "ld"):
        reported = commands.run([str(GCC), f"-print-prog-name={name}"], evidence).strip()
        found = (
            Path(reported)
            if reported.startswith("/")
            else Path(shutil.which(reported, path="/usr/bin:/bin") or "/unavailable")
        )
        inputs[name] = found.resolve(strict=True)
    for name in ("crtbeginS.o", "crtendS.o", "libgcc.a", "libgcc_eh.a"):
        reported = commands.run([str(GCC), f"-print-file-name={name}"], evidence).strip()
        if not reported.startswith("/"):
            raise RuntimeError("compiler runtime/startup object unavailable")
        inputs[name] = Path(reported).resolve(strict=True)
    for name in ("ar", "ranlib", "make", "readelf", "nm"):
        inputs[name] = Path(f"/usr/bin/{name}").resolve(strict=True)
    packages = Packages(commands, evidence)
    for path in inputs.values():
        packages.add(path)
    for flag, name in (
        ("--version", "GCC-VERSION.txt"),
        ("-dumpspecs", "GCC-SPECS.txt"),
        ("-print-search-dirs", "GCC-SEARCH.txt"),
    ):
        (evidence / name).write_text(commands.run([str(GCC), flag], evidence), encoding="utf-8")
    write_json(
        evidence / "COMPILER-INPUTS.json", {name: {"path": str(path), **record(path)} for name, path in inputs.items()}
    )
    return inputs, packages


def stage_uapi(destination: Path, packages: Packages) -> dict[str, dict[str, object]]:
    destination.mkdir()
    inventory = {}
    for source, guest in (
        (Path("/usr/include/linux"), "linux"),
        (Path("/usr/include/asm-generic"), "asm-generic"),
        (Path("/usr/include/x86_64-linux-gnu/asm"), "asm"),
    ):
        if source.is_symlink() or not source.is_dir():
            raise RuntimeError("expected native Linux UAPI tree unavailable")
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise RuntimeError("UAPI tree contains a link/special entry")
            target = destination / guest / path.relative_to(source)
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if len(inventory) >= 4096:
                    raise RuntimeError("UAPI file count exceeds bound")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw(path, LIMIT))
                packages.add(path)
                owner = packages.files[str(path.resolve())]["package"].split(":")[0]
                if owner != "linux-libc-dev":
                    raise RuntimeError("UAPI input belongs to unexpected package")
                inventory[target.relative_to(destination).as_posix()] = {"source": str(path), **record(target)}
    return inventory


def mount_compat_header():
    # musl 1.2.6 and the pinned Linux UAPI spell three equivalent macros
    # differently. Check their libc values before selecting the UAPI spelling;
    # retain all -Werror gates and do not alter either admitted source tree.
    return b"""#include <sys/mount.h>
#if MS_NOUSER != (1U << 31) || MS_MGC_VAL != 0xc0ed0000
#error Unexpected musl mount constants
#endif
#if MS_RMT_MASK != (MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_I_VERSION | MS_LAZYTIME)
#error Unexpected musl mount mask
#endif
#undef MS_NOUSER
#undef MS_RMT_MASK
#undef MS_MGC_VAL
#include <linux/mount.h>
"""


def one_build(
    root: Path,
    archives: dict[str, Path],
    pins: dict[str, object],
    bwrap: Path,
    commands: Commands,
    inputs: dict[str, Path],
    uapi: Path,
    evidence: Path,
) -> tuple[Path, dict[str, object]]:
    root.mkdir()
    musl = extract(archives["musl"], root / "musl-source", "musl-1.2.6")
    cap = extract(archives["libcap"], root / "libcap-source", "libcap-2.78")
    for name, directory in (("musl", musl), ("libcap", cap)):
        pin = pins[name]
        license_bytes = raw(directory / pin["license_file"])
        if digest(license_bytes) != pin["license_sha256"] or license_bytes != raw(HERE / f"{name}-LICENSE"):
            raise RuntimeError("source license differs from reviewed bytes")
    dlopen = raw(musl / "src/ldso/dlopen.c")
    if b"Dynamic loading not supported" not in dlopen or b"return 0;" not in dlopen:
        raise RuntimeError("expected static musl dlopen refusal unavailable")
    prefix = root / "musl-prefix"
    build = root / "musl-build"
    build.mkdir()
    mapping = f"-ffile-prefix-map={root}=/dc-static -fdebug-prefix-map={root}=/dc-static"
    flags = f"-O2 -g0 {mapping}"
    commands.run(
        [
            str(musl / "configure"),
            "--target=x86_64-linux-gnu",
            f"--prefix={prefix}",
            "--disable-shared",
            "--enable-static",
        ],
        build,
        extra={"CC": str(GCC), "CFLAGS": flags, "AR": str(inputs["ar"]), "RANLIB": str(inputs["ranlib"])},
    )
    commands.run([str(inputs["make"]), "-j2"], build)
    # A private absolute prefix only; this target writes no host runtime paths.
    commands.run([str(inputs["make"]), "install"], build)
    wrapper = prefix / "bin/musl-gcc"
    compiler_specs = raw(prefix / "lib/musl-gcc.specs")
    if b"-nostdinc" not in compiler_specs or b"-nostdlib" not in compiler_specs:
        raise RuntimeError("unexpected generated musl compiler specs")
    cap_flags = f"-O2 -g0 -I{uapi} {mapping}"
    commands.run(
        [
            str(inputs["make"]),
            "-C",
            str(cap / "libcap"),
            "-j2",
            "libcap.a",
            "libcap.pc",
            f"CC={wrapper}",
            f"BUILD_CC={GCC}",
            f"AR={inputs['ar']}",
            f"RANLIB={inputs['ranlib']}",
            "SHARED=no",
            "PTHREADS=no",
            "GOLANG=no",
            "PAM_CAP=no",
            "USE_GPERF=no",
            "lib=lib",
            f"prefix={prefix}",
            f"COPTS={cap_flags}",
            f"BUILD_COPTS={flags}",
        ],
        root,
    )
    objects = root / "bwrap-build"
    objects.mkdir()
    config = objects / "config.h"
    config.write_bytes(b'#define PACKAGE_STRING "bubblewrap 0.9.0"\n')
    mount_compat = objects / "mount-compat.h"
    mount_compat.write_bytes(mount_compat_header())
    common = [
        str(wrapper),
        "-D_GNU_SOURCE",
        "-O2",
        "-g0",
        "-fno-pie",
        "-fstack-protector-strong",
        "-include",
        str(mount_compat),
        *mapping.split(),
        f"-ffile-prefix-map={bwrap}=/dc-bwrap",
        f"-I{objects}",
        f"-I{bwrap}",
        f"-I{cap / 'libcap/include'}",
        f"-I{uapi}",
        *WARNINGS,
    ]
    object_paths = []
    for name in C_FILES:
        target = objects / f"{Path(name).stem}.o"
        commands.run([*common, "-c", str(bwrap / name), "-o", str(target)], objects)
        object_paths.append(target)
    image = objects / "bwrap-static-musl"
    map_path = evidence / f"LINK-{root.name}.map"
    trace = commands.run(
        [
            str(wrapper),
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
            "-Wl,--cref",
            f"-Wl,-Map,{map_path}",
            "-Wl,--trace",
            *map(str, object_paths),
            str(cap / "libcap/libcap.a"),
            "-o",
            str(image),
        ],
        objects,
    )
    (evidence / f"LINK-{root.name}.trace").write_text(trace, encoding="utf-8")
    expected = set(object_paths) | {
        cap / "libcap/libcap.a",
        prefix / "lib/libc.a",
        prefix / "lib/Scrt1.o",
        prefix / "lib/crti.o",
        prefix / "lib/crtn.o",
    }
    expected |= {inputs[name] for name in ("crtbeginS.o", "crtendS.o", "libgcc.a", "libgcc_eh.a")}
    linked = admit_link_map(raw(map_path, 32 << 20).decode(), expected)
    structure = elf(raw(image, 16 << 20))
    run_evidence = evidence / root.name
    run_evidence.mkdir()
    for path in (
        config,
        mount_compat,
        prefix / "lib/musl-gcc.specs",
        build / "config.mak",
        musl / "src/ldso/dlopen.c",
        cap / "libcap/cap_names.h",
        cap / "libcap/libcap.pc",
    ):
        shutil.copyfile(path, run_evidence / path.name)
    prefix_inventory = {}
    for path in sorted(prefix.rglob("*")):
        if path.is_file() and not path.is_symlink():
            # musl's admitted generic bits/hwcap.h is intentionally empty.
            # Inventory its exact bytes without weakening source/image gates.
            prefix_inventory[path.relative_to(prefix).as_posix()] = record(path, allow_empty=True)
        elif path.is_symlink():
            raise RuntimeError("unexpected link in private static musl prefix")
    write_json(run_evidence / "MUSL-PREFIX.json", prefix_inventory)
    retained = run_evidence / "link-inputs"
    retained.mkdir()
    input_inventory = {}
    for index, name in enumerate(linked):
        path = Path(name)
        target = retained / f"{index:02d}-{path.name}"
        shutil.copyfile(path, target)
        input_inventory[name] = {"retained": target.relative_to(evidence).as_posix(), **record(path)}
    (run_evidence / "ELF.txt").write_text(
        commands.run([str(inputs["readelf"]), "-aW", str(image)], root), encoding="utf-8"
    )
    (run_evidence / "SYMBOLS.txt").write_text(
        commands.run([str(inputs["nm"]), "-a", str(image)], root), encoding="utf-8"
    )
    return image, {
        "image": record(image),
        "elf": structure,
        "link_inputs": input_inventory,
        "musl_static_dlopen_refusal": digest(dlopen),
        "execution_performed": False,
    }


def build(peer: Path, bwrap: Path, artifact: Path) -> dict[str, object]:
    if os.uname().machine != "x86_64" or not Path("/etc/os-release").is_file():
        raise RuntimeError("static closure requires disposable Ubuntu24.04 x86_64")
    release = Path("/etc/os-release").read_text()
    if not re.search(r"^ID=ubuntu$", release, re.MULTILINE) or not re.search(
        r'^VERSION_ID="24\.04"$', release, re.MULTILINE
    ):
        raise RuntimeError("static closure recipe is pinned to Ubuntu24.04")
    evidence = artifact / "static"
    evidence.mkdir()
    (evidence / "OS-RELEASE").write_text(release, encoding="utf-8")
    commands = Commands(evidence)
    pins = json.loads(raw(HERE / "sources.json"))
    if pins["runtime_admission"] is not False or pins["bubblewrap"]["overlay_sha256"] != digest(
        raw(peer / "patches/bwrap-owned-fds.patch")
    ):
        raise RuntimeError("static source contract differs from reviewed C seam")
    work = peer / "static-build"
    work.mkdir()
    # The exact baseline plus separately retained applied overlay supplies the
    # complete Bubblewrap source used here, including its build/license files.
    # No compiled or generated file is executed by this archive command.
    commands.run(
        [
            "/usr/bin/git",
            "archive",
            "--format=tar",
            "--output",
            str(evidence / "BWRAP-PINNED-SOURCE.tar"),
            pins["bubblewrap"]["commit"],
        ],
        bwrap,
    )
    archives = {}
    for name in ("musl", "libcap"):
        pin = pins[name]
        target = evidence / Path(urllib.parse.urlsplit(pin["archive"]).path).name
        fetch(pin, target)
        archives[name] = target
    inputs, packages = toolchain(commands, evidence)
    uapi = work / "uapi"
    write_json(evidence / "UAPI.json", stage_uapi(uapi, packages))
    # Confirm all package-derived bytes before using their staged UAPI in C.
    packages.finish()
    for name in ("musl-LICENSE", "libcap-LICENSE"):
        shutil.copyfile(HERE / name, evidence / name)
    results = []
    for name in ("repeat-a", "repeat-b"):
        image, result = one_build(work / name, archives, pins, bwrap, commands, inputs, uapi, evidence)
        shutil.copyfile(image, evidence / f"bwrap-static-musl-{name}")
        results.append(result)
    if results[0]["image"] != results[1]["image"]:
        raise RuntimeError("independent staging roots produced different static image bytes")
    receipt = {
        "variant": "static_musl_bwrap_build_only",
        "source_pins": pins,
        "builds": results,
        "reproducible_image": True,
        "source_date_epoch": EPOCH,
        "compiler_bootstrapped_from_source": False,
        "selected_compiler_and_link_inputs_package_bytes_verified": True,
        "compiler_dynamic_libraries_and_lto_plugin_verified": False,
        "bubblewrap_execution_performed": False,
        "sandbox_execution_performed": False,
        "runtime_admission": False,
        "native_fd_mounts_qualified": False,
    }
    write_json(evidence / "STATIC-CLOSURE.json", receipt)
    return {
        "candidate_supplied": True,
        "runtime_admission": False,
        "image_sha256": results[0]["image"]["sha256"],
        "independent_roots_reproducible": True,
    }
