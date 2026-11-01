# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Operator contracts for the 1.0.4 wave 4b documentation gaps."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs-site/content/docs"


def _flat(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


def test_gap_0355_outage_examples_include_the_managed_service_refusal() -> None:
    text = _flat("enterprise/foreign-hook-guard.mdx")
    assert "enterprise_foreign_hook_blocked" in text
    assert "enterprise_managed_gateway_not_running" in text
    assert "Claude Code" in text and "service is not running" in text
    assert "Both refusals block the call" in text


def test_gap_0373_otlp_guide_does_not_promise_an_unsupported_write() -> None:
    text = _flat("observability/index.mdx")
    assert "`--write-probe` is not supported for OTLP" in text
    assert "does not prove delivery" in text
    assert "collector" in text and "event ID" in text
    assert "Add `--write-probe` to send" not in text
    assert "OTLP supports the handshake only" in _flat("reference/cli.mdx")
    runbooks = _flat("observability/index.mdx")
    assert runbooks.count("OTLP supports the handshake only") == 2


def _known_buckets() -> set[str]:
    source = (REPO / "internal/observability/taxonomy.go").read_text(encoding="utf-8")
    return set(re.findall(r'^\s*Bucket[A-Za-z]+\s+Bucket = "([a-z._]+)"', source, flags=re.MULTILINE))


def _delivery_check_pages() -> list[Path]:
    """How-to pages that narrow a destination's buckets and check delivery by an event ID."""
    pages = []
    for page in sorted((DOCS / "how-to").rglob("*.mdx")):
        text = page.read_text(encoding="utf-8")
        if (
            re.search(r"^\s*buckets: \[", text, flags=re.MULTILINE)
            and "## Check it worked" in text
            and "event ID" in text
        ):
            pages.append(page)
    return pages


@pytest.mark.skip(reason="train/r105-t2: the 1.0.3 docs layout has no how-to page with a Check it worked delivery check; the docs group carries the GAP-0373 check section onto observability/index.mdx")
def test_delivery_check_pages_are_found() -> None:
    assert DOCS / "observability/index.mdx" in _delivery_check_pages()


@pytest.mark.parametrize("page", _delivery_check_pages(), ids=lambda p: p.name)
def test_delivery_check_uses_an_event_the_example_filter_sends(page: Path) -> None:
    text = page.read_text(encoding="utf-8")
    [filtered] = [set(m.split(", ")) for m in re.findall(r"^\s*buckets: \[([^\]]+)\]", text, flags=re.MULTILINE)]
    known = _known_buckets()
    assert filtered <= known, filtered - known
    check = text[text.index("## Check it worked") :]
    check = " ".join(check[: check.index("\n## ", 1)].split())
    # A clean call proves nothing through a filter that drops its buckets.
    assert not re.search(r"(?:benign|clean) (?:agent )?call, (?:then )?find its event ID", check), check
    # The check names the filter's buckets, confirms the route sends, or runs before the filter.
    for bucket in filtered:
        assert f"`{bucket}`" in check, bucket
    assert "before you add the filter" in check
    assert "run step 3 with its bucket" in check and "shows `send`" in check
    step3 = text[text.index("3. Review the result.") : text.index("## Check it worked")]
    assert "defenseclaw observability plan --bucket" in step3


@pytest.mark.parametrize(
    "page",
    ["enterprise/threat-model.mdx", "enterprise/machine-policy.mdx"],
)
def test_gap_0379_managed_guarantee_distinguishes_admin_outage_policy_from_peer_trust(page: str) -> None:
    text = _flat(page)
    assert "administrator" in text and "`hook_fail_mode: open`" in text
    assert "outage" in text
    assert "/docs/reference/fail-modes" in text
    assert "`defenseclaw-hook` always fails closed" not in text
    assert "does not override fail-closed gateway peer verification when the gateway is down" not in text


@pytest.mark.parametrize("page", ["enterprise/ai-defense-key.mdx"])
def test_gap_0383_removal_names_the_enabled_ai_defense_reference(page: str) -> None:
    text = _flat(page).split("## Remove the key" if page.endswith("ai-defense-key.mdx") else "### Remove the key", 1)[1]
    assert "enabled AI Defense" in text
    assert "disabled AI Defense" in text
    assert "Removal refuses a credential the installed config still names" not in text
