# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Synthetic bytes and fake readers only: no compiler, download or ELF runs."""

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import build_loader as build


def image():
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQ", data, 16, 3, 62, 1, 128, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 2)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 256, 256, 4096)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 208, 208, 0, 32, 32, 8)
    return data


class LoaderTests(unittest.TestCase):
    def test_inert_shared_loader_shape(self):
        self.assertEqual(build.loader_elf(image())["load_segments"], 1)

    def test_external_runtime_dependency_or_search_path_refused(self):
        for tag in (1, 15, 29):
            with self.subTest(tag=tag):
                data = image()
                struct.pack_into("<qQ", data, 208, tag, 7)
                with self.assertRaises(ValueError):
                    build.loader_elf(data)

    def test_interpreter_writable_code_and_nonfile_entry_refused(self):
        for mutation in ("interpreter", "wx", "entry", "machine", "table", "missing-null"):
            with self.subTest(mutation=mutation):
                data = image()
                if mutation == "interpreter":
                    struct.pack_into("<I", data, 120, 3)
                elif mutation == "wx":
                    struct.pack_into("<I", data, 68, 7)
                elif mutation == "entry":
                    struct.pack_into("<Q", data, 24, 4096)
                elif mutation == "machine":
                    struct.pack_into("<H", data, 18, 183)
                elif mutation == "table":
                    struct.pack_into("<H", data, 56, 129)
                else:
                    struct.pack_into("<qQqQ", data, 208, 5, 0, 6, 0)
                with self.assertRaises(ValueError):
                    build.loader_elf(data)

    def test_truncated_and_oversized_loader_refused(self):
        for data in (image()[:199], bytes(build.MAX_IMAGE + 1)):
            with self.assertRaises(ValueError):
                build.loader_elf(data)

    def test_compiler_drift_or_omitted_input_refused_before_build(self):
        class Fake:
            digest = staticmethod(lambda data: hashlib.sha256(data).hexdigest())

        expected = {
            name: {"path": "/synthetic/" + name, "size": 4, "sha256": hashlib.sha256(b"same").hexdigest()}
            for name in build.COMPILER_NAMES
        }
        build.compiler_pins(Fake, expected, lambda _: b"same")
        with self.assertRaises(RuntimeError):
            build.compiler_pins(Fake, expected, lambda _: b"drift")
        expected.pop("gcc")
        with self.assertRaises(RuntimeError):
            build.compiler_pins(Fake, expected, lambda _: b"same")

    def test_exact_reviewed_compiler_inventory_is_finite(self):
        expected = json.loads((Path(__file__).parent / "compiler-inputs.json").read_text(encoding="utf-8"))
        self.assertEqual(set(expected), build.COMPILER_NAMES)
        self.assertTrue(all(0 < value["size"] <= 32 << 20 for value in expected.values()))
        self.assertEqual(expected["gcc"]["sha256"], "1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26")

    def test_link_map_rejects_external_libc_and_escaping_input(self):
        module = build.recipe()  # Imports definitions only; no command runs.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = root / "build"
            (work / "obj").mkdir(parents=True)
            (work / "obj/fixed.lo").write_bytes(b"inert object")
            libraries = {name: root / name for name in ("libgcc.a", "libgcc_eh.a")}
            for path in libraries.values():
                path.write_bytes(b"inert compiler archive")
            linked = build.linked_inputs(module, "LOAD obj/fixed.lo\n", work, libraries)
            self.assertEqual(len(linked), 1)
            extra = root / "libc.a"
            extra.write_bytes(b"unreviewed external archive")
            for text in ("LOAD ../libc.a\n", f"LOAD {extra}\n", ""):
                with self.assertRaises(RuntimeError):
                    build.linked_inputs(module, text, work, libraries)


if __name__ == "__main__":
    unittest.main()
