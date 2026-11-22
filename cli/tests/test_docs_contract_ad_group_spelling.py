# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""AD group examples must show the platform spelling beside the selector.

Since GAP-1124 one AD group selector works on every OS, so a page may title its
example block "macOS AD group selector" or "DOMAIN\\name group selector". Either
way the example must select CORP\\contractors, and the page must spell the
account forms out: name@domain beside DOMAIN\\group or DOMAIN\\name.
"""

from pathlib import Path

import pytest
import yaml

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"
MARKERS = (
    '```yaml title="macOS AD group selector"\n',
    '```yaml title="DOMAIN\\name group selector"\n',
)


@pytest.mark.parametrize(
    "page",
    ["guardrail/user-and-group-policies.mdx", "enterprise/identity-and-authentication.mdx"],
)
def test_ad_group_example_names_macos_selector(page: str) -> None:
    text = (DOCS / page).read_text(encoding="utf-8")
    marker = next((m for m in MARKERS if m in text), None)
    assert marker is not None, page
    snippet = text.split(marker, 1)[1].split("```", 1)[0].strip()
    match = yaml.safe_load(snippet)
    assert match["match"]["groups"] == [r"CORP\contractors"]
    assert "name@domain" in text, page
    assert "DOMAIN\\group" in text or "DOMAIN\\name" in text, page
