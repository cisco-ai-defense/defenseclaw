# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0350: release-floor refusals, recovery and package coverage limits."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs-site/content/docs"
REFERENCE = "enterprise/operate/reference.mdx"
LIFECYCLE = "enterprise/operate/lifecycle.mdx"
TROUBLESHOOTING = "troubleshooting/enterprise/index.mdx"
OPERATOR_CONTRACT = "packaging/mdm/contract/management-agent.md"
CONTRACT_FLOOR = "### 5.3 Release floor"
CONTACT = "contact your administrator"


def _flat(page: str) -> str:
    return " ".join((DOCS / page).read_text(encoding="utf-8").split())


def _section(page: str, heading: str) -> str:
    text = (DOCS / page).read_text(encoding="utf-8")
    start = text.index(heading)
    rest = text[start + len(heading) :]
    end = re.search(r"^#{1,3} ", rest, flags=re.MULTILINE)
    return " ".join((rest[: end.start()] if end else rest).split())


def _go_source(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def _table_row(page: str, code: str) -> str:
    [row] = [
        line for line in (DOCS / page).read_text(encoding="utf-8").splitlines() if line.startswith(f"| `{code}` |")
    ]
    return row


@pytest.mark.parametrize("page", [LIFECYCLE, TROUBLESHOOTING])
def test_gap_0350_release_floor_and_recovery_are_documented(page: str) -> None:
    text = _flat(page)
    assert "product_floor_refused" in text
    assert "min_product_version" in text
    assert "/docs/enterprise/operate/reference#release-floor-limits" in text
    # Owner hold: the recovery is the administrator's, not a public procedure.
    assert CONTACT in text


def test_gap_0350_package_floor_limits_include_old_scripts_and_windows() -> None:
    text = _section(REFERENCE, "### Release floor limits")
    for fact in ("older than 1.0.4", "`rpm`", "`dnf`", "`dpkg -i`", "macOS Installer", "Windows Setup"):
        assert fact in text
    assert "apt hook" in text
    assert "retained floor checker" in text
    assert CONTACT in text
    assert "release-floor-limits" in _flat("appendix/upgrade-from-0-8.mdx")


def test_every_run_checks_the_floor_including_a_same_release_repair() -> None:
    """rel-1-0-4:GAP-2033: the page said a repair or ensure that keeps the
    recorded release skips the floor check; the lifecycle checks every run."""
    text = _section(REFERENCE, "### Release floor limits")
    assert "every `install`, `upgrade`, `repair` and `ensure` checks the confirmed bundle's release floor" in text
    assert "including a repair or ensure that keeps the recorded release" in text
    assert "does not check the floor again" not in text
    assert "`bundle_state_unreadable`" in text
    assert "The floor is read from the confirmed bundle's manifest" in text
    row = _table_row(TROUBLESHOOTING, "bundle_state_unreadable")
    assert "does not check the release floor again" not in row
    assert "the release floor is still checked" in row
    # Ground truth: no record or version test gates the check
    # (internal/enterpriseunix/lifecycle.go), the floor comes from the
    # manifest only (enterprisebundle ConfirmedProductFloor), and a damaged
    # config is the warning (bundleapply.go).
    lifecycle = _go_source("internal/enterpriseunix/lifecycle.go")
    assert "// Every candidate must meet an authenticated floor." in lifecycle
    assert "} else if err := env.BundleProductFloorRefusal(p.version); err != nil {" in lifecycle
    assert "m, err := s.ConfirmedManifest()" in _go_source("internal/enterprisebundle/product_floor.go")
    assert (
        'r.AddWarning(codeBundleStateUnreadable, "cannot read the current policy bundle, so the config the last deployment committed is kept'
        in _go_source("internal/enterpriseunix/bundleapply.go")
    )


def test_troubleshooting_lists_floor_codes_in_the_right_tables() -> None:
    text = (DOCS / TROUBLESHOOTING).read_text(encoding="utf-8")
    errors = text[text.index("## Lifecycle error codes") : text.index("### Warnings")]
    warnings = text[text.index("### Warnings") : text.index("## Kernel sensor warnings")]
    # product_floor_refused is an error (exit 1, or 3 from floor-check), with a Fix column.
    [row] = [line for line in errors.splitlines() if line.startswith("| `product_floor_refused` |")]
    assert row.count(" | ") == 3, row
    assert CONTACT in row
    assert "product_floor_refused" not in warnings
    for code in ("bundle_state_unreadable", "floor_checker_not_kept"):
        [row] = [line for line in warnings.splitlines() if line.startswith(f"| `{code}` |")]
        assert row.count(" | ") == 2, row


def _contract_text() -> str:
    return (REPO / OPERATOR_CONTRACT).read_text(encoding="utf-8")


def _contract_section(heading: str) -> str:
    text = _contract_text()
    start = text.index(heading)
    end = text.index("\n## ", start + 1)
    return text[start:end]


# Owner hold: no public signed-bundle procedure or walkthrough. Release-floor
# docs say what the current package does, plus "contact your administrator";
# no recovery step that needs a signed bundle (deliver, sign, apply, restore or
# confirm one, lower --min-product-version, run floor-check).
_BUNDLE_PROCEDURE = re.compile(r"\bbundle\s+(?:sign|apply|verify|floor-check)\b")
_SIGNED_BUNDLE_RECOVERY = re.compile(
    r"\b(?:deliver|restore|apply|sign|confirm|send|push)\b[^.;|]*\bbundle\b"
    r"|--min-product-version|signed with a lower|lower floor|lower-the-release-floor|\bfloor-check\b",
    flags=re.IGNORECASE,
)


def _floor_recovery_texts() -> dict[str, str]:
    """Every release-floor passage of the public site and the contract."""
    texts = {
        f"{REFERENCE} Release floor limits": _section(REFERENCE, "### Release floor limits"),
        f"{LIFECYCLE} Roll back": _section(LIFECYCLE, "## Roll back"),
        f"{OPERATOR_CONTRACT} 5.3": " ".join(_contract_section(CONTRACT_FLOOR).split()),
    }
    for code in ("product_floor_refused", "bundle_state_unreadable", "floor_checker_not_kept"):
        texts[f"{TROUBLESHOOTING} {code}"] = _table_row(TROUBLESHOOTING, code)
    for page in sorted(DOCS.rglob("*.mdx")):
        for sentence in _sentences(" ".join(page.read_text(encoding="utf-8").split())):
            if "floor" in sentence:
                texts[f"{page.relative_to(DOCS)}: {sentence[:60]}"] = sentence
    return texts


def test_no_release_floor_recovery_needs_a_signed_bundle() -> None:
    hits = [
        f"{where}: {match.group(0)}"
        for where, text in _floor_recovery_texts().items()
        for match in _SIGNED_BUNDLE_RECOVERY.finditer(text)
    ]
    assert not hits, hits
    for page in sorted(DOCS.rglob("*.mdx")):
        text = page.read_text(encoding="utf-8")
        assert "Lower the release floor" not in text, page
    assert "Lower the release floor" not in _contract_text()


def test_no_public_page_carries_a_signed_bundle_procedure() -> None:
    hits = []
    for page in sorted(DOCS.rglob("*.mdx")):
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            if _BUNDLE_PROCEDURE.search(line):
                hits.append(f"{page.relative_to(DOCS)}:{number}: {line.strip()}")
    assert not hits, hits


def test_operator_contract_states_the_floor_without_a_procedure() -> None:
    section = _contract_section(CONTRACT_FLOOR)
    assert "```" not in section
    assert not _BUNDLE_PROCEDURE.search(section), section
    flat = " ".join(section.split())
    assert "`product_floor_refused`" in flat
    assert "DefenseClaw 1.0.4 and later refuse to install a release below" in flat
    assert "do not lift it" in flat
    assert "Older packages do not check the floor in any script and can complete below it" in flat
    assert CONTACT in flat


# Package scripts that run the floor check: a gateway without the marker is one
# from before 1.0.4, which has no check of its own.
_FLOOR_SCRIPTS = (
    "packaging/linux/preinstall.sh",
    "packaging/linux/apt-downgrade-guard.sh",
    "scripts/build-macos-enterprise-pkg.sh",
)


def _floor_doc_texts() -> dict[str, str]:
    texts = {
        page.relative_to(DOCS).as_posix(): _flat(page.relative_to(DOCS).as_posix()) for page in DOCS.rglob("*.mdx")
    }
    texts[OPERATOR_CONTRACT] = " ".join(_contract_text().split())
    return texts


def _sentences(text: str) -> list[str]:
    return re.split(r"(?<=\.)\s+", text)


def _says_older_packages_complete(text: str) -> bool:
    return any(
        ("older than 1.0.4" in s or "Older packages" in s) and re.search(r"\bcomplete[s]? below\b", s)
        for s in _sentences(text)
    )


def test_postinstall_floor_refusal_is_promised_only_for_packages_with_the_check() -> None:
    """A package older than 1.0.4 has no floor check in its preinstall, postinstall
    or ensure, so no page may say a postinstall refuses a release below the floor
    without naming 1.0.4 or later packages (loop round 3 finding)."""
    hits = []
    for page, text in _floor_doc_texts().items():
        for sentence in _sentences(text):
            if "postinstall" not in sentence or "refuse" not in sentence:
                continue
            if "floor" not in sentence:
                continue
            if "1.0.4 or later" not in sentence and "1.0.4 and later" not in sentence:
                hits.append(f"{page}: {sentence}")
    assert not hits, hits
    for page, text in _floor_doc_texts().items():
        # An unscoped "the device never goes below the floor" is the same promise.
        assert "oldest release you can install" not in text, page
        assert "a device does not install a release below" not in text, page
        assert "only its postinstall `ensure` refuses" not in text, page


_PREINSTALL_PROMISE = re.compile(r"\bbefore (?:they|it) replaces? (?:any )?files\b|\bbefore (?:any|its) files?\b")


def test_preinstall_floor_check_is_qualified_by_the_gateway_it_needs() -> None:
    """The preinstall asks only a 1.0.4 or later installed gateway or the kept
    checker. With an older installed gateway and no kept checker it installs
    the files and only the postinstall can refuse, so every page that promises
    the check before files are replaced says so (loop round 1 finding 2)."""
    promising = {
        page: text
        for page, text in _floor_doc_texts().items()
        if any("floor" in s and _PREINSTALL_PROMISE.search(s) for s in _sentences(text))
    }
    assert {REFERENCE, OPERATOR_CONTRACT} <= set(promising), sorted(promising)
    for page, text in promising.items():
        for fact in (
            "only with a gateway that has the check",
            "the installed gateway when it is 1.0.4 or later",
            "installed gateway is older than 1.0.4 or gone",
            "an older package was installed below the floor",
            "after its files are in place" if page == OPERATOR_CONTRACT else "after the files are in place",
        ):
            assert fact in text, (page, fact)


def test_floor_docs_say_an_older_package_completes_below_the_floor() -> None:
    pages = {page: text for page, text in _floor_doc_texts().items() if "`floor_checker_not_kept`" in text}
    assert {REFERENCE, TROUBLESHOOTING, OPERATOR_CONTRACT} <= set(pages), sorted(pages)
    for page, text in pages.items():
        assert _says_older_packages_complete(text), page
    # The roll-back section, where the floor is introduced, says it too.
    assert _says_older_packages_complete(_section(LIFECYCLE, "## Roll back"))
    assert _says_older_packages_complete(_section(REFERENCE, "### Release floor limits"))
    assert _says_older_packages_complete(" ".join(_contract_section(CONTRACT_FLOOR).split()))
    row = _table_row(TROUBLESHOOTING, "floor_checker_not_kept")
    assert _says_older_packages_complete(row), row
