# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""AD group examples must show the platform spelling beside the selector."""

from pathlib import Path

import pytest
import yaml

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


@pytest.mark.parametrize(
    "page",
    ["guardrail/user-and-group-policies.mdx", "enterprise/identity-and-authentication.mdx"],
)
def test_ad_group_example_names_macos_selector(page: str) -> None:
    text = (DOCS / page).read_text(encoding="utf-8")
    marker = '```yaml title="macOS AD group selector"\n'
    assert marker in text, page
    snippet = text.split(marker, 1)[1].split("```", 1)[0].strip()
    match = yaml.safe_load(snippet)
    assert match["match"]["groups"] == [r"CORP\contractors"]
    assert "name@domain" in text and "DOMAIN\\group" in text
