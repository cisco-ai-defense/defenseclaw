# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Static checks that the managed-sandbox docs keep the claims the live round
verified (GAP-0047, 0203, 0302, 0319, 0372, 0386, 0394, 0398, 0404, 0408)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def _read(rel: str) -> str:
    return (DOCS / rel).read_text(encoding="utf-8")


def test_docs_never_prescribe_sandbox_run_mount_or_yolo_flags() -> None:
    # `sandbox run` has no --mount or --yolo flag (GAP-0319, GAP-0372, GAP-0404).
    pattern = re.compile(r"sandbox run[^\n`]*--(mount|yolo)\b")
    files = list(DOCS.rglob("*.mdx")) + list((ROOT / "docs").glob("*.md"))
    offenders = [str(p.relative_to(ROOT)) for p in files if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_no_sandbox_variable_is_not_an_unconditional_bypass() -> None:
    guide = " ".join(_read("sandboxes/guide.mdx").split())
    bullet = guide.split("DEFENSECLAW_NO_SANDBOX=1 claude` runs the harness", 1)[1][:400]
    assert "where your organization allows it" in bullet  # GAP-0047
    assert "required_for" in bullet
    env = " ".join(_read("reference/env-vars.mdx").split())
    assert "still refused" in env.split("`DEFENSECLAW_NO_SANDBOX`", 1)[1][:900]


def test_admin_docs_use_the_packaged_gateway_path() -> None:
    concepts = _read("enterprise/concepts.mdx")  # GAP-0203
    assert "/opt/defenseclaw/bin/defenseclaw-gateway" in concepts
    assert "command not found" in concepts


def test_managed_sandbox_page_states_the_verified_residuals_and_limits() -> None:
    # The residuals and flag limits moved to the sandbox reference page.
    page = _read("enterprise/sandboxes.mdx")
    assert "hidepid" in page  # GAP-0302
    assert "openshell.admin.when_unavailable" in page  # GAP-0408
    assert "user_approvals: null" not in page  # GAP-0394
    assert "--pack, --profile and --harness" in page  # GAP-0068 policy test
    assert "no flag that asks for a live mount" in page  # GAP-0319


def test_windows_rule_pack_folder_is_not_left_readable_by_users() -> None:
    windows = _read("enterprise/windows.mdx")
    assert "leave the inherited `Users`" not in " ".join(windows.split())  # GAP-0386
    assert "sc.exe showsid DefenseClawGateway" in windows


def test_lifecycle_explains_a_hand_edit_is_applied_not_drift() -> None:
    lifecycle = _read("enterprise/lifecycle.mdx")
    assert "A hand edit of the config is applied, not reported as drift" in lifecycle  # GAP-0398


def test_coverage_and_cli_keep_managed_sandbox_platform_support() -> None:
    coverage = _read("segmentation.mdx")
    rows = [line.split("|") for line in coverage.splitlines() if line.startswith("| **")]
    linux = next(row[3] for row in rows if "Linux, managed" in row[1])
    mac = next(row[3] for row in rows if "macOS, managed" in row[1])
    assert linux.strip().startswith("Yes"), linux
    assert all(term in linux for term in ("Docker", "MicroVM", "KVM", "copy")), linux
    assert mac.strip().startswith("Yes"), mac
    assert all(term in mac for term in ("MicroVM", "Apple silicon", "copy")), mac
    assert next(row[3] for row in rows if "Windows" in row[1]).strip().startswith("No")

    reference = " ".join(_read("reference/sandbox-cli.mdx").split())
    install = reference.split("### `sandbox kernel-feed install`", 1)[1].split("```", 1)[0]
    assert "where sandboxes are not supported" not in install
    assert "per-user" in install and "managed" in install
