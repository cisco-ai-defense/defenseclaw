# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Managed package commands must not inherit the per-user CLI's promises."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs-site/content/docs"


@pytest.mark.parametrize(
    ("page", "facts", "obsolete"),
    [
        (
            "enterprise/runtime/tetragon-reference.mdx",
            ("With Plane C off, `ensure` writes an `off` drop-in",),
            ("produce the same policy digest and no drop-in",),
        ),
        (
            "reference/sandboxes/cli.mdx",
            ("per-user feed installer", "standalone managed Linux and macOS"),
            ("a managed host, where sandboxes are not supported",),
        ),
        (
            "enterprise/plan/concepts.mdx",
            ("manifest` on Linux, macOS and Windows",),
            ("manifest` on Linux and macOS",),
        ),
        (
            "reference/commands/cli.mdx",
            (
                "`init` and `quickstart` are not shipped",
                "`doctor` prints administrator guidance and exits `1`",
                "`show` and `verify` take `--json`",
                "`export` prints the selected vendor format",
                "read the installed managed config and runtime automatically",
                "defenseclaw tool status <name> [--connector X]",
            ),
            ("All three take `--json`", "defenseclaw tool list/status"),
        ),
        (
            "reference/configuration/env-vars.mdx",
            ("On managed Linux and macOS", "enterprise macos status"),
            (),
        ),
        (
            "reference/commands/tui.mdx",
            ("Managed packages ship no TUI", "enterprise macos status"),
            ("The editor still opens",),
        ),
    ],
)
def test_managed_package_command_scope(page, facts, obsolete):
    text = " ".join((DOCS / page).read_text(encoding="utf-8").split())
    for fact in facts:
        assert fact in text, (page, fact)
    for claim in obsolete:
        assert claim not in text, (page, claim)


@pytest.mark.parametrize("page", ["enterprise/mdm/index.mdx", "enterprise/mdm/intune/macos.mdx"])
def test_mdm_live_delivery_names_the_test_build(page):
    text = (DOCS / page).read_text()
    assert "`9.9.9`" in text
    assert "f9ed814b1" in text
    assert "test build" in text


def test_mdm_invalid_candidate_code_is_consistent():
    for page in (
        "enterprise/mdm/index.mdx",
        "enterprise/mdm/reference.mdx",
        "enterprise/mdm/workspace-one.mdx",
        "enterprise/mdm/configmgr.mdx",
        "enterprise/mdm/intune/tenant-reference.mdx",
    ):
        text = (DOCS / page).read_text()
        if page.endswith("workspace-one.mdx"):
            text = text.split("## macOS", 1)[0]
        assert "invalid_arguments" in text, page
        assert "1639" in text, page


def _windows_config_verbs() -> set[str]:
    """The `config` subcommands the Windows package's Go binary registers."""
    cli = REPO / "internal/cli"
    sources = {
        f: f.read_text(encoding="utf-8")
        for f in cli.glob("*.go")
        if not f.name.endswith("_test.go")
    }
    everything = "\n".join(sources.values())
    verbs = set()
    for ident in re.findall(r"configCmd\.AddCommand\(([^)]*)\)", everything):
        for name in (part.strip() for part in ident.split(",")):
            use = re.search(r"var " + re.escape(name) + r" = &cobra\.Command\{\s*Use:\s*\"(\w+)", everything)
            assert use, name
            verbs.add(use.group(1))
    # The managed Windows refusals of `config set` / `config unset`.
    guard = sources[cli / "managed_host_guard.go"]
    loop = re.search(r"for _, verb := range \[\]string\{([^}]*)\}\s*\{[^}]*?addManagedWindowsAnswer\(configCmd", guard)
    assert loop
    verbs.update(re.findall(r"\"(\w+)\"", loop.group(1)))
    return verbs


def _windows_package_section() -> str:
    text = (DOCS / "reference/commands/cli.mdx").read_text(encoding="utf-8")
    start = text.index("Windows has no sandbox-only command.")
    return text[start:text.index("\n## ", start)]


def test_windows_package_config_commands_are_the_shipped_ones():
    verbs = _windows_config_verbs()
    assert {"migrate", "validate", "set", "unset"} <= verbs
    assert not verbs & {"get", "show"}
    section = _windows_package_section()
    # Every config command the section offers, leaving out the sentences
    # that say which ones the package lacks.
    offered = " ".join(s for s in _sentences(section) if not re.search(r"\bno `config ", s))
    named = set(re.findall(r"`config (\w+)", offered))
    assert named, section
    assert named <= verbs, named - verbs
    flat = " ".join(section.split())
    assert "there is no `config get` or `config show`" in flat
    assert "config validate 'C:\\ProgramData\\Cisco\\DefenseClaw\\etc\\config.yaml'" in flat


def test_no_page_runs_config_get_or_show_with_the_windows_package_cli():
    pattern = re.compile(r"defenseclaw\.exe['\"]?\s+config\s+(get|show)\b")
    for page in DOCS.rglob("*.mdx"):
        assert not pattern.search(page.read_text(encoding="utf-8")), page


_UNTRUSTED_SETUP_INPUT = re.compile(
    r"non-administrator (?:owns or )?can (?:change|write)|non-administrator owns", re.I
)
_SETUP_INPUT_FILE = re.compile(r"`CONFIG=`|`MANIFEST=`|config (?:or manifest )?file|manifest file", re.I)


def _sentences(text: str):
    for paragraph in re.split(r"\n\s*\n", text):
        flat = " ".join(paragraph.split())
        yield from re.split(r"(?<=[.!?])\s+(?=[A-Z`])", flat)


def test_untrusted_setup_input_is_documented_as_1639_everywhere():
    """Standalone Setup reports an untrusted CONFIG=/MANIFEST= file as
    invalid_arguments, exit 1639 (standaloneEnterpriseSetupInputError);
    only a token that is not elevated is 1603. The MDM wrappers' own
    mdm_untrusted_input stays 1603 and is not this refusal."""
    checked = 0
    for page in DOCS.rglob("*.mdx"):
        for sentence in _sentences(page.read_text(encoding="utf-8")):
            if not (_UNTRUSTED_SETUP_INPUT.search(sentence) and _SETUP_INPUT_FILE.search(sentence)):
                continue
            if re.search(r"wrapper|mdm_untrusted_input", sentence, re.I):
                continue
            if not re.search(r"`\d{4}`", sentence):
                continue
            checked += 1
            assert "`1639`" in sentence, (page, sentence)
            assert "`1603`" not in sentence, (page, sentence)
    assert checked >= 4


def test_setup_time_budget_names_the_recovery_after_timeoutseconds():
    """GAP-2509: a standalone Setup run stopped at TIMEOUTSECONDS runs one
    recovery child bounded on its own (enterpriseSetupRecoveryTimeout), so
    Setup can run that much longer. An MDM time budget of TIMEOUTSECONDS ends
    Setup inside its recovery and leaves verify failing; the pages that give
    the budget name the extra minutes."""
    source = (REPO / "cmd/defenseclaw-enterprise-setup/lifecycle_timeout.go").read_text(encoding="utf-8")
    match = re.search(r"var enterpriseSetupRecoveryTimeout = (\d+) \* time\.Minute", source)
    assert match, "recovery bound not found"
    minutes = match.group(1)
    mdm = (DOCS / "enterprise/mdm/reference.mdx").read_text(encoding="utf-8")
    time_bullet = mdm[mdm.index("- **Time.**"):mdm.index("- **One run at a time.**")]
    assert f"`TIMEOUTSECONDS` plus {minutes} minutes" in time_bullet, time_bullet
    windows = (DOCS / "enterprise/install/reference/windows.mdx").read_text(encoding="utf-8")
    row = next(line for line in windows.splitlines() if line.startswith("| `TIMEOUTSECONDS=<n>`"))
    assert f"`TIMEOUTSECONDS` plus {minutes} minutes" in row, row
    # The limit counts from Setup's start (opts.Started), so the budget holds
    # when the payload checks and unpacking are slow (GAP-2509 review row).
    assert "opts.Started.Add(opts.LifecycleTimeout)" in source, "deadline no longer counts from Setup's start"
    assert "counted from when Setup starts" in time_bullet, time_bullet
    assert "counted from when Setup starts" in row, row
    # A change counted from Setup's start needs the payload checks (11-26 s
    # live) plus the lifecycle start minimum (minimumEnterpriseLifecycleStart,
    # about 67 s for /ensure), so 60-90 never starts one; the pages that give
    # the 60 to 7200 range name the effective minimum (GAP-2509 checker P4).
    assert "const minimumEnterpriseLifecycleStart = 60 * time.Second" in source, "lifecycle start minimum moved"
    cli = (DOCS / "reference/commands/cli.mdx").read_text(encoding="utf-8")
    cli_row = next(line for line in cli.splitlines() if line.startswith("| `TIMEOUTSECONDS=<n>`"))
    mdm_row = next(line for line in mdm.splitlines() if line.startswith("| `TIMEOUTSECONDS=`"))
    for text in (time_bullet, row, mdm_row, cli_row):
        assert "at least about 2 minutes" in text or "at least about 120" in text, text
        assert "only `/verify` and `/status`" in text, text
