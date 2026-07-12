# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = ROOT / "scripts/generate_observability_v8_reference.py"
SPEC = importlib.util.spec_from_file_location("observability_v8_reference_generator", GENERATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


def test_observability_v8_reference_regeneration_is_byte_identical() -> None:
    outputs = generator._outputs(generator.SCHEMA_PATH.read_bytes())
    for path in (
        generator.CANONICAL_YAML,
        generator.CANONICAL_MARKDOWN,
    ):
        assert path.read_bytes() == outputs[path]


def test_observability_v8_reference_validates_and_covers_source_surface() -> None:
    schema = json.loads(generator.SCHEMA_PATH.read_bytes())
    document = yaml.safe_load(generator.CANONICAL_YAML.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)

    observability_schema = generator._resolve(schema, schema["$defs"]["observability"])
    expected_paths = generator._schema_paths(schema, observability_schema, "observability")
    actual_paths = generator._document_paths(document)
    assert expected_paths <= actual_paths

    expected_kinds = {kind for kind, _ in generator._destination_variants(schema)}
    actual_kinds = {item["kind"] for item in document["observability"]["destinations"]}
    assert actual_kinds == expected_kinds


def test_observability_v8_staged_python_data_is_byte_identical_when_present() -> None:
    staged = (
        generator.PYTHON_DATA_DIR / generator.SCHEMA_PATH.name,
        generator.PYTHON_DATA_DIR / generator.CANONICAL_YAML.name,
        generator.PYTHON_DATA_DIR / generator.CANONICAL_MARKDOWN.name,
    )
    if not all(path.is_file() for path in staged):
        return
    assert (generator.PYTHON_DATA_DIR / generator.SCHEMA_PATH.name).read_bytes() == generator.SCHEMA_PATH.read_bytes()
    assert (generator.PYTHON_DATA_DIR / generator.CANONICAL_YAML.name).read_bytes() == generator.CANONICAL_YAML.read_bytes()
    assert (generator.PYTHON_DATA_DIR / generator.CANONICAL_MARKDOWN.name).read_bytes() == generator.CANONICAL_MARKDOWN.read_bytes()
