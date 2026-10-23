# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""All registered observability buckets belong to a single Markdown table."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_bucket_catalog_is_one_complete_table():
    registry = yaml.safe_load((ROOT / "schemas/telemetry/v8/registry.yaml").read_text())
    fields = registry["structural_contract"]["envelope"]["fields"]
    expected = next(field["enum"] for field in fields if field["name"] == "bucket")
    text = (ROOT / "docs-site/content/docs/reference/observability/index.mdx").read_text()
    section = text.split("## Buckets\n", 1)[1].split("\n## ", 1)[0]
    tables = re.findall(r"(?m)^\| Bucket \|[^\n]*\n(?:\|[^\n]*\n)+", section)
    assert len(tables) == 1
    actual = re.findall(r"(?m)^\| `([^`]+)` \|", tables[0])
    assert sorted(actual) == sorted(expected)
