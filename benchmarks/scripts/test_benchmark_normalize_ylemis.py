#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("benchmark_normalize_ylemis.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_ylemis", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class YlemisNormalizerTests(unittest.TestCase):
    def test_converts_source_character_offsets_to_utf8_byte_offsets(self) -> None:
        text = "ग्राहक PAN ABCDE1234F"
        value = "ABCDE1234F"
        start = text.index(value)
        span, entity_type = MODULE.normalized_span(
            text,
            {"type": "pan", "start": start, "end": start + len(value)},
            "unicode-case",
        )

        self.assertEqual("pan", entity_type)
        self.assertEqual(len(text[:start].encode("utf-8")), span["start"])
        self.assertEqual(len(text[: start + len(value)].encode("utf-8")), span["end"])
        self.assertEqual(value, text.encode("utf-8")[span["start"] : span["end"]].decode("utf-8"))

    def test_ascii_offsets_remain_unchanged(self) -> None:
        span, _ = MODULE.normalized_span("PAN ABCDE1234F", {"type": "pan", "start": 4, "end": 14})
        self.assertEqual({"label": "pan", "start": 4, "end": 14}, span)


if __name__ == "__main__":
    unittest.main()
