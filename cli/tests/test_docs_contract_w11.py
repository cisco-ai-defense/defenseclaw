# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""T6 doc findings (rel-1-0-4 W11): each page says what the code does."""

import json
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs-site/content/docs"


def _page(rel: str) -> str:
    return " ".join((DOCS / rel).read_text(encoding="utf-8").split())


def _enterprise_acp_subcommands() -> set[str]:
    names = set()
    for path in (REPO / "internal/cli").glob("enterprise_acp*.go"):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8")
        for var, use in re.findall(r'var (enterpriseACP\w+Cmd) = &cobra\.Command\{\s*Use:\s*"([\w-]+)"', text):
            if var != "enterpriseACPCmd":
                names.add(use)
    return names


def test_managed_acp_pages_name_every_enterprise_acp_subcommand():
    # GAP-0548: the pages listed enroll, verify and revoke, not list and setup.
    subcommands = _enterprise_acp_subcommands()
    assert {"enroll", "verify", "revoke", "list", "setup"} <= subcommands
    for rel in ("features/acp-guard.mdx", "reference/apis/acp-guard.mdx"):
        section = _page(rel).split("## Managed computers", 1)[1].split("## ", 1)[0]
        for name in sorted(subcommands):
            assert f"`{name}`" in section or f"enterprise acp {name}" in section, (rel, name)


def test_sandbox_exit_status_names_usage_errors():
    # GAP-0549: unknown flags and commands exit 2 (usageFlagError); a refused
    # --output value is an error from the command and exits 1.
    exit_code = (REPO / "internal/cli/exit_code.go").read_text(encoding="utf-8")
    assert "rootCmd.SetFlagErrorFunc(usageFlagError)" in exit_code
    assert '"sandbox"' not in exit_code.split("usageFlagErrorExempt = ", 1)[1].split("\n", 1)[0]
    ui = (REPO / "internal/openshell/sandboxcli/ui.go").read_text(encoding="utf-8")
    assert "--output must be text or json" in ui
    text = _page("reference/sandboxes/cli.mdx")
    bullet = text.split("**Exit status.**", 1)[1].split("## ", 1)[0]
    assert "an unknown command or flag" in bullet and "exits `2`" in bullet
    assert "`-o yaml`, is an error and exits `1`" in bullet


def test_sandbox_doctor_help_states_the_json_exit_status():
    # GAP-0549 class: sandbox doctor exits 1 on a failed check with --output
    # json too (GAP-0308), but its help said the JSON run exits 0.
    doctor = (REPO / "internal/openshell/sandboxcli/doctor.go").read_text(encoding="utf-8")
    assert "a failed check exits 1 in either format" in doctor
    for rel in (
        "internal/cli/sandbox.go",
        "internal/cli/testdata/sandbox_commands.json",
        "cli/defenseclaw/commands/cmd_sandbox.py",
    ):
        source = " ".join((REPO / rel).read_text(encoding="utf-8").replace("\\n", " ").split())
        assert "the exit status is 0" not in source, rel
        assert "with --output json too" in source, rel


def test_turn_off_page_says_what_a_scoped_enable_does_after_a_global_disable():
    # GAP-0550: `guardrail enable --connector codex` after `setup guardrail
    # --disable` changed nothing; the page said it brought the agent back.
    text = _page("how-to/guardrail/turn-off-the-guardrail.mdx")
    assert "Add `--connector codex` to bring back one agent" not in text
    assert "After `setup guardrail --disable`, `defenseclaw guardrail enable --connector codex` changes nothing" in text
    assert "exits `1`" in text


def test_rule_recipes_page_names_the_suppressions_the_catalog_holds():
    # GAP-0555: the catalog holds the strict pack's suppressions and the
    # default pack's tool suppressions, not every pack's.
    recipes = json.loads((REPO / "docs-site/data/policy-recipes.json").read_text(encoding="utf-8"))
    if isinstance(recipes, dict):
        recipes = recipes["recipes"]
    layers = {
        "pre_judge_strip": "pre_judge_strips",
        "finding_suppression": "finding_suppressions",
        "tool_suppression": "tool_suppressions",
    }
    in_catalog = {(r["source"], layers[r["kind"]]) for r in recipes if r["kind"] in layers}
    shipped = set()
    for pack in sorted(p for p in (REPO / "policies/guardrail").iterdir() if (p / "suppressions.yaml").is_file()):
        data = yaml.safe_load((pack / "suppressions.yaml").read_text(encoding="utf-8")) or {}
        for layer in layers.values():
            if data.get(layer):
                shipped.add((f"policies/guardrail/{pack.name}/suppressions.yaml", layer))
    text = _page("reference/policy/rule-recipes.mdx")
    if in_catalog != shipped:
        assert "plus the suppressions the packs ship" not in text
    for source, _layer in sorted(in_catalog):
        assert f"`{source}`" in text, source
    strict = yaml.safe_load((REPO / "policies/guardrail/strict/suppressions.yaml").read_text(encoding="utf-8"))
    if not strict.get("tool_suppressions"):
        assert "the strict pack has none" in text


def test_hook_contracts_page_does_not_promise_observe_mode_without_a_contract():
    # GAP-0554: setup said "Continuing in observe mode", then the gateway
    # refused the version and stayed down. Setup now refuses in both modes.
    setup = (REPO / "cli/defenseclaw/commands/cmd_setup.py").read_text(encoding="utf-8")
    assert "Continuing in observe mode under the connector's established warning policy" not in setup
    text = _page("reference/apis/hook-contracts.mdx")
    assert "allowed in observe mode" not in text
    assert "Setup keeps observe mode and refuses action mode" not in text
    assert "refused in observe and action mode before any change" in text
    devin = _page("reference/connectors/devin.mdx")
    assert "setup keeps it in observe mode" not in devin


def test_hook_refusal_codes_section_says_where_the_codes_are():
    # GAP-0556: the page said the agent reports the codes in its hook output;
    # an unenrolled account's text carries no code, and the gateway log does.
    hookexec = (REPO / "internal/gateway/connector/hookexec/hookexec.go").read_text(encoding="utf-8")
    explanation = hookexec.split("const unixUnenrolledAccountExplanation = ", 1)[1].split("\n\n", 1)[0]
    assert "enterprise_managed_uid_unregistered" not in explanation
    text = _page("troubleshooting/enterprise/index.mdx")
    section = text.split("## Hook refusal codes", 1)[1]
    assert "An agent reports these codes in its hook output" not in section
    assert "an unenrolled account's does not" in section
    assert "journalctl -u defenseclaw-gateway" in section
