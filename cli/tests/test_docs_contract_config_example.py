# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The complete example must state the inputs native validation requires."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_complete_config_example_declares_its_secret_inputs():
    page = (ROOT / "docs-site/content/docs/reference/configuration/index.mdx").read_text()
    intro, body = page.split("```yaml\nconfig_version: 9", 1)
    prerequisites = intro.split("## config.yaml schema", 1)[1]
    example = yaml.safe_load("config_version: 9" + body.split("\n```", 1)[0])
    inputs = set()

    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key == "env" or key.endswith("_env")) and isinstance(item, str) and item:
                    inputs.add(item)
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(example["observability"])
    assert inputs, "the example no longer illustrates credential-backed destinations"
    assert "Before validating this example" in prerequisites
    for name in inputs:
        assert f"`{name}`" in prerequisites, name
