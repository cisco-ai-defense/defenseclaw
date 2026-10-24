# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("page", "required"),
    [
        ("connectors/openclaw.mdx", "setup remove openclaw --yes --force"),
        ("how-to/policies/write-a-custom-rule.mdx", "redacted.secret.id-"),
    ],
)
def test_operator_recipe_accounts_for_removal_guards_and_redaction(page, required):
    content = (Path(__file__).resolve().parents[2] / "docs-site/content/docs" / page).read_text(encoding="utf-8")
    assert required in content
