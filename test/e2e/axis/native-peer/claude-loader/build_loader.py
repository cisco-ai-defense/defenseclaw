#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build one fixed shared musl loader; never invoke it or a vendor image."""

from __future__ import annotations

import importlib.util
import json
import platform
import re
import shutil
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STATIC = ROOT / "internal/axis/native/static"
ARTIFACT = ROOT / "claude-loader-artifact"
WORK = ROOT / "claude-loader-work"
MAX_IMAGE = 4 << 20
COMPILER_NAMES = {
    "ar",
    "as",
    "cc1",
    "collect2",
    "crtbeginS.o",
    "crtendS.o",
    "gcc",
    "ld",
    "libgcc.a",
    "libgcc_eh.a",
    "make",
    "nm",
    "ranlib",
    "readelf",
}


def recipe():
    spec = importlib.util.spec_from_file_location("reviewed_axis_static_build", STATIC / "build_static.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("reviewed compiler recipe unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loader_elf(data: bytes) -> dict[str, int | str]:
    """Check finite loader structure, not compatibility or dlopen coverage."""
    if not 64 <= len(data) <= MAX_IMAGE or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("loader ELF identification differs")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    ehsize, phsize, count = struct.unpack_from("<HHH", data, 52)
    if (kind, machine, version, ehsize, phsize) != (3, 62, 1, 64, 56) or not 1 <= count <= 128:
        raise ValueError("loader ELF header differs")
    if phoff < 64 or phoff + count * 56 > len(data):
        raise ValueError("loader program table exceeds image")
    executable_entry = False
    loads = 0
    dynamic = None
    for index in range(count):
        tag, flags, offset, address, _, files, memory, align = struct.unpack_from("<IIQQQQQQ", data, phoff + index * 56)
        if (
            files > memory
            or address > (1 << 64) - 1 - memory
            or offset > len(data)
            or files > len(data) - offset
            or flags & ~7
        ):
            raise ValueError("loader segment bounds differ")
        if align > 1 and (align & (align - 1) or offset % align != address % align):
            raise ValueError("loader segment alignment differs")
        if tag == 3 or flags & 3 == 3:
            raise ValueError("loader interpreter or writable executable segment refused")
        if tag == 1:
            loads += 1
            executable_entry |= bool(flags & 1) and address <= entry < address + files
        if tag == 2:
            if dynamic is not None or not files or files % 16 or files > 64 << 10:
                raise ValueError("loader dynamic table differs")
            dynamic = (offset, files)
    if not loads or not executable_entry or dynamic is None:
        raise ValueError("loader entry or dynamic table missing")
    offset, size = dynamic
    terminated = False
    for cursor in range(offset, offset + size, 16):
        tag, _ = struct.unpack_from("<qQ", data, cursor)
        if tag == 0:
            terminated = True
            break
        if tag in {1, 15, 29}:  # DT_NEEDED, DT_RPATH, DT_RUNPATH
            raise ValueError("loader declares another runtime dependency or search path")
    if not terminated:
        raise ValueError("loader dynamic table is unterminated")
    return {"elf": "ELF64_LE_ET_DYN_X86_64", "program_headers": count, "load_segments": loads}


def compiler_pins(module, expected: dict, read=None) -> None:
    if set(expected) != COMPILER_NAMES:
        raise RuntimeError("compiler pin inventory differs")
    read = module.raw if read is None else read
    for value in expected.values():
        if set(value) != {"path", "size", "sha256"} or not str(value["path"]).startswith("/"):
            raise RuntimeError("compiler pin shape differs")
        data = read(Path(value["path"]))
        if len(data) != value["size"] or module.digest(data) != value["sha256"]:
            raise RuntimeError("selected compiler input differs from reviewed c914 bytes")


def linked_inputs(module, text: str, build: Path, inputs: dict) -> dict:
    entries = re.findall(r"^LOAD (.+)$", text, re.MULTILINE)
    if not entries or len(entries) > 4096:
        raise RuntimeError("loader link inventory missing or excessive")
    objects = (build / "obj").resolve(strict=True)
    allowed = {inputs["libgcc.a"].resolve(strict=True), inputs["libgcc_eh.a"].resolve(strict=True)}
    records = {}
    for entry in entries:
        path = Path(entry)
        if not path.is_absolute():
            path = build / path
        path = path.resolve(strict=True)
        generated = path.is_relative_to(objects) and path.suffix in {".lo", ".o"}
        if not generated and path not in allowed:
            raise RuntimeError("loader linked an unreviewed external input")
        data = module.raw(path, MAX_IMAGE)
        records[str(path)] = {"size": len(data), "sha256": module.digest(data)}
    return records


def one_build(module, root: Path, archive: Path, pin: dict, commands, inputs: dict) -> tuple[Path, dict]:
    root.mkdir()
    source = module.extract(archive, root / "source", "musl-1.2.6")
    license_data = module.raw(source / "COPYRIGHT")
    if module.digest(license_data) != pin["license_sha256"] or license_data != module.raw(STATIC / "musl-LICENSE"):
        raise RuntimeError("musl license differs")
    build = root / "build"
    build.mkdir()
    mapping = f"-ffile-prefix-map={root}=/dc-musl-loader -fdebug-prefix-map={root}=/dc-musl-loader"
    link_map = root / "loader-link.map"
    commands.run(
        [
            str(source / "configure"),
            "--target=x86_64-linux-gnu",
            f"--prefix={root / 'private-prefix'}",
            "--syslibdir=/lib",
            "--enable-shared",
            "--disable-static",
            f"LDFLAGS=-Wl,--build-id=none -Wl,-Map,{link_map} -Wl,-t",
        ],
        build,
        extra={
            "CC": str(module.GCC),
            "CFLAGS": f"-O2 -g0 {mapping}",
            "AR": str(inputs["ar"]),
            "RANLIB": str(inputs["ranlib"]),
        },
    )
    # No install target, runtime probe, loader self-test or invocation of an
    # output file. Upstream configure/make and compiler programs are trusted
    # build inputs on this disposable runner.
    commands.run([str(inputs["make"]), "-j2", "lib/libc.so"], build)
    image = build / "lib/libc.so"
    data = module.raw(image, MAX_IMAGE)
    elf = loader_elf(data)
    link_inputs = linked_inputs(module, module.raw(link_map, 16 << 20).decode(), build, inputs)
    symbols = commands.run([str(inputs["nm"]), "-D", "--defined-only", str(image)], build)
    names = {line.split()[-1] for line in symbols.splitlines() if line.split()}
    if not {"__libc_start_main", "dlopen", "dlsym", "pthread_create"} <= names:
        raise RuntimeError("required musl entry points absent")
    readelf = commands.run([str(inputs["readelf"]), "--wide", "-h", "-l", "-d", str(image)], build)
    (root / "loader-readelf.txt").write_text(readelf, encoding="utf-8")
    return image, {
        "image": module.record(image),
        "elf": elf,
        "link_map": module.record(link_map),
        "link_inputs": link_inputs,
    }


def build() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("fixed loader requires Linux x86-64")
    module = recipe()
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    if "ID=ubuntu" not in release or 'VERSION_ID="24.04"' not in release:
        raise RuntimeError("fixed compiler recipe requires Ubuntu 24.04")
    expected = json.loads(module.raw(HERE / "compiler-inputs.json"))
    compiler_pins(module, expected)
    evidence = ARTIFACT / "build"
    evidence.mkdir()
    WORK.mkdir()
    commands = module.Commands(evidence)
    inputs, packages = module.toolchain(commands, evidence)
    actual = json.loads(module.raw(evidence / "COMPILER-INPUTS.json"))
    if actual != expected:
        raise RuntimeError("compiler discovery differs from reviewed exact inputs")
    # Authenticate the selected installed compiler/startup/link bytes against
    # exact Ubuntu package payloads before the first musl compilation.
    packages.finish()
    pins = json.loads(module.raw(STATIC / "sources.json"))
    pin = pins["musl"]
    if (
        pin["version"] != "1.2.6"
        or pin["archive_sha256"] != "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
    ):
        raise RuntimeError("fixed official musl source differs")
    archive = evidence / "musl-1.2.6.tar.gz"
    module.fetch(pin, archive)
    shutil.copyfile(STATIC / "musl-LICENSE", evidence / "musl-LICENSE")
    (evidence / "OS-RELEASE").write_text(release, encoding="utf-8")
    builds = []
    for name in ("repeat-a", "repeat-b"):
        image, result = one_build(module, WORK / name, archive, pin, commands, inputs)
        shutil.copyfile(image, ARTIFACT / f"musl-loader-{name}")
        for filename in ("loader-link.map", "loader-readelf.txt"):
            shutil.copyfile(WORK / name / filename, evidence / f"{name}-{filename}")
        builds.append(result)
    if builds[0]["image"] != builds[1]["image"]:
        raise RuntimeError("independent shared musl builds differ")
    module.write_json(
        ARTIFACT / "LOADER-CLOSURE.json",
        {
            "scope": "fixed_shared_musl_1_2_6_loader_build_only",
            "source": pin,
            "builds": builds,
            "reproducible_image": True,
            "source_date_epoch": module.EPOCH,
            "selected_compiler_inputs_match_reviewed_c914": True,
            "selected_compiler_and_link_inputs_package_bytes_verified": True,
            "compiler_dynamic_libraries_and_lto_plugin_verified": False,
            "fully_hermetic_build": False,
            "loader_or_vendor_execution": False,
            "runtime_admission": False,
            "production_certification": False,
        },
    )


def main() -> int:
    try:
        build()
        return 0
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        # Preserve command logs in build/, without publishing arbitrary local
        # exception/path text as a successful closure receipt.
        print(f"fixed musl loader build refused ({type(error).__name__})")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
