# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policy panel parity tests for the Textual model slice."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from defenseclaw.tui.panels.policy import (
    POLICY_TAB_JUDGE,
    POLICY_TAB_OPA,
    POLICY_TAB_POLICIES,
    POLICY_TAB_RULE_PACKS,
    POLICY_TAB_SUPPRESSIONS,
    PolicyPanelModel,
    PolicyRule,
    PreJudgeStrip,
    RuleFile,
    SuppressionsConfig,
    ToolSuppression,
    aibom_scan_intent,
    clamp_yaml_body,
    ordered_judge_names,
    policy_edit_intent,
    policy_test_intent,
)


def make_config(policy_dir: Path, rule_pack_dir: Path | None = None) -> SimpleNamespace:
    guardrail = SimpleNamespace(
        rule_pack_dir=str(rule_pack_dir or ""),
        enabled=True,
        mode="action",
        scanner_mode="both",
        connector="",
    )
    return SimpleNamespace(
        policy_dir=str(policy_dir),
        guardrail=guardrail,
        claw=SimpleNamespace(mode="codex"),
        active_connector=lambda: "codex",
    )


def write_policy(policy_dir: Path, name: str, extra: dict[str, object] | None = None) -> Path:
    data: dict[str, object] = {
        "name": name,
        "description": f"{name} policy",
        "admission": {"scan_on_install": True, "allow_list_bypass_scan": True},
        "skill_actions": {
            "critical": {"install": "block", "file": "quarantine", "runtime": "disable"},
            "high": {"install": "block", "file": "quarantine", "runtime": "disable"},
            "medium": {"install": "none", "file": "none", "runtime": "enable"},
            "low": {"install": "none", "file": "none", "runtime": "enable"},
            "info": {"install": "none", "file": "none", "runtime": "enable"},
        },
        "guardrail": {
            "block_threshold": 4,
            "alert_threshold": 2,
            "hilt": {"enabled": True, "min_severity": "MEDIUM"},
            "cisco_trust_level": "full",
            "patterns": {"injection": ["ignore previous"], "secrets": ["sk-"]},
            "severity_mappings": {"injection": "HIGH"},
        },
        "firewall": {"allowed_domains": ["api.github.com"], "blocked_destinations": ["169.254.169.254"]},
        "first_party_allow_list": [{"target_name": "defenseclaw"}],
        "webhooks": [{"name": "ops"}],
    }
    if extra:
        data.update(extra)
    path = policy_dir / f"{name}.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def write_rule_pack(root: Path, name: str = "default") -> Path:
    pack = root / "guardrail" / name
    (pack / "rules").mkdir(parents=True)
    (pack / "judge").mkdir(parents=True)
    (pack / "rules" / "c2.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "category": "c2",
                "rules": [
                    {
                        "id": "C2-WEBHOOK-SITE",
                        "pattern": "(?i)webhook\\.site",
                        "title": "webhook.site",
                        "severity": "HIGH",
                        "confidence": 0.9,
                        "tags": ["exfiltration", "c2"],
                    },
                    {
                        "id": "C2-NGROK",
                        "pattern": "(?i)ngrok\\.io",
                        "title": "ngrok",
                        "severity": "HIGH",
                        "confidence": 0.8,
                        "tags": ["exfiltration"],
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (pack / "suppressions.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "pre_judge_strips": [
                    {
                        "id": "STRIP-SYSTEM",
                        "pattern": "\\bsystem\\b",
                        "context": "metadata",
                        "applies_to": ["pii"],
                    }
                ],
                "finding_suppressions": [
                    {
                        "id": "SUPP-IP",
                        "finding_pattern": "JUDGE-PII-IP",
                        "entity_pattern": "^127\\.",
                        "reason": "loopback",
                    }
                ],
                "tool_suppressions": [
                    {
                        "tool_pattern": "^status$",
                        "suppress_findings": ["JUDGE-PII-USER"],
                        "reason": "status metadata",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (pack / "sensitive-tools.yaml").write_text(
        yaml.safe_dump({"version": 1, "tools": [{"name": "read_file", "result_inspection": True}]}),
        encoding="utf-8",
    )
    return pack


def test_policy_create_n_key_signals_quick_start_wizard(tmp_path: Path) -> None:
    """Pressing ``n`` (or ``+``) on the Policies tab signals the app to
    push the Quick Start ModalScreen rather than opening the legacy
    inline form. The model must NOT push any policy_command_intent on
    its own — that's the wizard's responsibility once Save is hit."""

    write_policy(tmp_path, "default")
    model = PolicyPanelModel(make_config(tmp_path))
    model.active_tab = POLICY_TAB_POLICIES
    model.load_policies()

    for key in ("n", "+"):
        action = model.handle_key(key)
        assert action.handled is True
        assert action.open_quick_start is True
        assert action.intent is None
        assert "Quick Start" in action.hint


def test_policies_key_dispatch_overlay_filter_and_click_selection(tmp_path: Path) -> None:
    for name in ("alpha", "beta", "gamma"):
        write_policy(tmp_path, name)
    (tmp_path / "rego").mkdir()
    (tmp_path / "rego" / "data.json").write_text(json.dumps({"config": {"policy_name": "beta"}}), encoding="utf-8")

    model = PolicyPanelModel(make_config(tmp_path))
    model.active_tab = POLICY_TAB_POLICIES
    model.load_policies()
    assert [policy.name for policy in model.policies] == ["alpha", "beta", "gamma"]
    assert model.active_policy == "beta"

    model.policy_cursor = 2
    model.set_policy_filter("beta")
    assert model.policy_cursor == 0
    assert model.selected_policy_name() == "beta"
    model.clear_policy_filter()

    model.handle_policies_key("j")
    assert model.policy_cursor == 1
    action = model.handle_policies_key("enter")
    assert action.intent is None
    assert model.policy_detail_open is True
    assert model.policy_detail_name == "beta"
    assert "beta policy" in model.policy_detail_yaml

    model.handle_key("esc")
    assert model.policy_detail_open is False

    action = model.handle_policies_key("a")
    assert action.intent is not None
    assert action.intent.args == ("policy", "activate", "beta")
    assert action.intent.binary == "defenseclaw"

    assert model.handle_policies_key("s").detail_opened is True
    model.handle_key("esc")
    assert model.handle_policies_key("d").intent.args == ("policy", "delete", "beta")
    assert model.handle_policies_key("l").intent.args == ("policy", "list")
    assert model.handle_policies_key("v").intent.args == ("policy", "validate")

    model.handle_click(x=2, rel_y=8)
    assert model.policy_cursor == 2
    assert model.selected_policy_name() == "gamma"

    # ``n`` now signals the app shell to push the Quick Start
    # ModalScreen — there's no in-panel form anymore.
    action = model.handle_policies_key("n")
    assert action.open_quick_start is True
    assert action.intent is None


def test_policies_empty_and_active_states(tmp_path: Path) -> None:
    model = PolicyPanelModel(make_config(tmp_path))
    model.load_policies()
    assert model.policies == ()
    for key in ("enter", "a", "s", "d"):
        assert model.handle_policies_key(key).intent is None
    assert "no policies yet" in model.view_policies(80, 20)

    write_policy(tmp_path, "a")
    write_policy(tmp_path, "b")
    (tmp_path / "rego").mkdir()
    (tmp_path / "rego" / "data.json").write_text(
        json.dumps({"config": {"policy_name": "b"}}), encoding="utf-8"
    )

    model.load_policies()
    assert model.active_policy == "b"
    names = [policy.name for policy in model.policies]
    assert names == ["a", "b"]
    # Symlinked active.yaml is not honored anymore (matches CLI / Go TUI).
    # Defensive check: a stray active.yaml in the dir is filtered out so
    # it doesn't render as a phantom policy row.
    (tmp_path / "active.yaml").write_text("name: active\n", encoding="utf-8")
    model.load_policies()
    assert "active" not in [policy.name for policy in model.policies]


def test_load_policies_merges_bundled_presets(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """``load_policies`` walks the user policy_dir AND the bundled presets,
    tagging each row with its source. User-dir entries take precedence over
    bundled ones with the same stem.
    """
    bundled_policies = bundled_assets / "policies"
    write_policy(bundled_policies, "default")
    write_policy(bundled_policies, "strict")
    write_policy(bundled_policies, "permissive")

    write_policy(tmp_path, "prod-tight")
    # Operator-overridden default — should hide the bundled default row.
    write_policy(tmp_path, "default", extra={"description": "operator override"})

    model = PolicyPanelModel(make_config(tmp_path))
    model.load_policies()

    by_name = {p.name: p for p in model.policies}
    assert set(by_name) == {"prod-tight", "default", "strict", "permissive"}
    assert by_name["prod-tight"].source == "user"
    assert by_name["default"].source == "user"
    assert by_name["default"].description == "operator override"
    assert by_name["strict"].source == "bundled"
    assert by_name["permissive"].source == "bundled"

    # User entries sort before bundled, then alphabetic within each group.
    assert [p.name for p in model.policies] == [
        "default",
        "prod-tight",
        "permissive",
        "strict",
    ]


def test_active_policy_name_falls_back_to_bundled_data_json(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """When the user has no ``rego/data.json`` (fresh install), the active
    policy is read from the bundled fallback so the panel header still
    shows something useful instead of a blank string.
    """
    bundled_rego = bundled_assets / "policies" / "rego"
    bundled_rego.mkdir(parents=True, exist_ok=True)
    (bundled_rego / "data.json").write_text(
        json.dumps({"config": {"policy_name": "default"}}), encoding="utf-8"
    )

    from defenseclaw.tui.services.policy_state import active_policy_name

    assert active_policy_name(tmp_path) == "default"

    # User data.json wins over bundled when present.
    (tmp_path / "rego").mkdir()
    (tmp_path / "rego" / "data.json").write_text(
        json.dumps({"config": {"policy_name": "prod-tight"}}), encoding="utf-8"
    )
    assert active_policy_name(tmp_path) == "prod-tight"


def test_materialize_bundled_copies_yaml_rego_and_guardrail(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """``materialize_bundled`` seeds the user policy_dir from the bundled
    asset tree without overwriting existing files, and triggers a reload
    so the resulting rows show ``source="user"``.
    """
    bundled_policies = bundled_assets / "policies"
    bundled_rego = bundled_assets / "policies" / "rego"
    bundled_guardrail = bundled_assets / "policies" / "guardrail"

    write_policy(bundled_policies, "default")
    write_policy(bundled_policies, "strict")
    bundled_rego.mkdir(parents=True, exist_ok=True)
    (bundled_rego / "admission.rego").write_text(
        "package defenseclaw.admission\n", encoding="utf-8"
    )
    (bundled_rego / "data.json").write_text(
        json.dumps({"config": {"policy_name": "default"}}), encoding="utf-8"
    )
    profile_dir = bundled_guardrail / "default" / "rules"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "secrets.yaml").write_text(
        "version: 1\ncategory: secrets\nrules: []\n", encoding="utf-8"
    )

    # Pre-existing user file must NOT be clobbered.
    write_policy(tmp_path, "default", extra={"description": "operator override"})

    model = PolicyPanelModel(make_config(tmp_path))
    written = model.materialize_bundled()

    written_paths = {Path(p) for p in written}
    assert tmp_path / "strict.yaml" in written_paths
    assert tmp_path / "default.yaml" not in written_paths  # not clobbered
    assert tmp_path / "rego" / "admission.rego" in written_paths
    assert tmp_path / "rego" / "data.json" in written_paths
    assert tmp_path / "guardrail" / "default" in written_paths

    # Reload happens automatically; bundled-source rows for materialized
    # files become user-source rows on the next render.
    by_source = {p.name: p.source for p in model.policies}
    assert by_source.get("default") == "user"
    assert by_source.get("strict") == "user"

    # Re-running is idempotent — every file already exists, nothing
    # gets re-written.
    second = model.materialize_bundled()
    assert second == ()


def test_capital_M_key_runs_materialize_with_summary_hint(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """Pressing ``M`` on the Policies tab triggers ``materialize_bundled``
    in the model and returns a hint that names the first few files
    that landed in the user dir, so the activity strip can echo it.
    """
    bundled_policies = bundled_assets / "policies"
    write_policy(bundled_policies, "default")
    write_policy(bundled_policies, "strict")
    write_policy(bundled_policies, "permissive")

    model = PolicyPanelModel(make_config(tmp_path))
    model.active_tab = POLICY_TAB_POLICIES
    model.load_policies()
    assert all(p.source == "bundled" for p in model.policies)

    action = model.handle_policies_key("M")
    assert action.handled is True
    assert action.reload_requested is True
    # Hint must summarize what just happened so the activity strip
    # has something useful to render.
    assert "Materialized" in action.hint
    assert "default.yaml" in action.hint or "permissive.yaml" in action.hint

    # The bundled rows are now backed by user files.
    sources = {p.name: p.source for p in model.policies}
    assert sources["default"] == "user"
    assert sources["strict"] == "user"

    # Pressing again with everything already materialized produces
    # the "nothing to do" hint instead of crashing or returning a
    # misleading "Materialized 0" message.
    action = model.handle_policies_key("M")
    assert action.handled is True
    assert "Nothing to materialize" in action.hint


def test_view_policies_renders_active_and_bundled_badges(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """The Policies tab body shows ``[active]`` next to the active policy
    and ``[bundled]`` next to rows backed by the bundled preset tree, and
    counts user vs bundled separately in the header.
    """
    bundled_policies = bundled_assets / "policies"
    write_policy(bundled_policies, "default")
    write_policy(bundled_policies, "strict")

    write_policy(tmp_path, "prod-tight")
    (tmp_path / "rego").mkdir()
    (tmp_path / "rego" / "data.json").write_text(
        json.dumps({"config": {"policy_name": "prod-tight"}}), encoding="utf-8"
    )

    model = PolicyPanelModel(make_config(tmp_path))
    model.active_tab = POLICY_TAB_POLICIES
    body = model.view_policies(80, 20)

    assert "1 user, 2 bundled" in body
    assert "active: prod-tight" in body
    assert "prod-tight" in body
    # Badges are rendered with backslash-escaped square brackets so
    # Rich treats them as literal text instead of style spans.
    assert "\\[active]" in body
    assert "\\[bundled]" in body


def test_policy_reload_intent_targets_gateway_binary() -> None:
    """``policy_reload_intent`` must invoke ``defenseclaw-gateway``,
    not ``defenseclaw``.

    The Python ``defenseclaw`` CLI does not expose ``policy reload``
    (see ``cli/defenseclaw/commands/cmd_policy.py`` - 7 subcommands,
    none of them ``reload``); the Go original lived under the gateway
    binary, and the Python migration kept that split. Mismatched
    binary => silent breakage when an operator presses ``r`` on the
    OPA tab. The registry already had this right; the intent
    factories did not.
    """
    from defenseclaw.tui.services.policy_state import policy_reload_intent

    intent = policy_reload_intent(origin="policy:opa")
    assert intent.binary == "defenseclaw-gateway"
    assert intent.args == ("policy", "reload")
    # The full argv (used by the executor) must match too.
    assert intent.argv == ("defenseclaw-gateway", "policy", "reload")


def test_rule_pack_switch_uses_gateway_reload_intent(tmp_path: Path) -> None:
    """Switching guardrail rule packs (Enter on a non-active pack)
    fires the same ``defenseclaw-gateway policy reload`` intent so the
    gateway picks up the new pack. Pre-Phase-4 this called
    ``defenseclaw policy reload`` and silently failed.
    """
    pack = write_rule_pack(tmp_path, name="default")
    write_rule_pack(tmp_path, name="strict")

    model = PolicyPanelModel(make_config(tmp_path / "policies", pack))
    model.load()
    model.active_tab = POLICY_TAB_RULE_PACKS
    # cursor on a non-active pack
    model.pack_cursor = next(i for i, name in enumerate(model.packs) if name != model.active_pack)
    action = model.handle_rule_pack_key("enter")

    assert action.handled
    assert action.intent is not None
    assert action.intent.binary == "defenseclaw-gateway"
    assert action.intent.args == ("policy", "reload")


def test_view_policies_renders_readiness_banner_for_problems(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """The Policies tab body surfaces a single-line readiness banner
    when ``readiness_summary()`` reports any ``warn``/``fail`` check.
    Clean state (all ``pass``) suppresses the banner so it doesn't
    drown out the list.
    """
    bundled_policies = bundled_assets / "policies"
    write_policy(bundled_policies, "default")

    # tmp_path is a real dir, so policy_dir passes; but no active
    # marker (no rego/data.json), no rule pack -> two warns surface.
    model = PolicyPanelModel(make_config(tmp_path))
    body = model.view_policies(120, 30)

    assert "Readiness:" in body
    assert "WARN" in body  # status badge for the unconfigured rule pack
    assert "Active policy" in body or "Rule pack" in body


def test_view_policies_filter_no_match_hint(
    tmp_path: Path, bundled_assets: Path
) -> None:
    """An over-aggressive filter shouldn't show "no policies yet" — that
    message is for fresh installs. We tell the user how to clear the
    filter instead.
    """
    bundled_policies = bundled_assets / "policies"
    write_policy(bundled_policies, "default")

    model = PolicyPanelModel(make_config(tmp_path))
    model.active_tab = POLICY_TAB_POLICIES
    model.load_policies()
    model.set_policy_filter("zzzzz-no-match")

    body = model.view_policies(80, 20)
    assert "no policies match" in body
    assert "esc" in body
    assert "create" not in body  # different message from empty-state


def test_outer_tabs_suppressions_inner_tabs_and_subtab_clicks(tmp_path: Path) -> None:
    pack = write_rule_pack(tmp_path)
    model = PolicyPanelModel(make_config(tmp_path / "policies", pack))
    model.load()

    assert model.active_tab == POLICY_TAB_POLICIES
    model.handle_key("]")
    assert model.active_tab == POLICY_TAB_RULE_PACKS
    model.handle_key("[")
    assert model.active_tab == POLICY_TAB_POLICIES
    model.handle_key("tab")
    assert model.active_tab == POLICY_TAB_RULE_PACKS
    model.handle_key("shift+tab")
    assert model.active_tab == POLICY_TAB_POLICIES

    model.active_tab = POLICY_TAB_SUPPRESSIONS
    model.handle_key("tab")
    assert model.active_tab == POLICY_TAB_SUPPRESSIONS
    assert model.supp_section == 1
    model.handle_key("shift+tab")
    assert model.supp_section == 0

    assert model.sub_tab_hit_test(0) == POLICY_TAB_POLICIES
    opa_x = sum(len(name) + 4 for name in ("Policies", "Rule Packs", "Judge Prompts", "Suppressions"))
    assert model.sub_tab_hit_test(opa_x) == POLICY_TAB_OPA
    model.set_sub_tab(POLICY_TAB_JUDGE)
    assert model.active_tab == POLICY_TAB_JUDGE


def test_rule_pack_activation_rule_detail_and_editor_intents(tmp_path: Path) -> None:
    pack = write_rule_pack(tmp_path, "default")
    write_rule_pack(tmp_path, "strict")
    model = PolicyPanelModel(make_config(tmp_path / "policies", pack))
    model.load()
    assert model.packs == ("default", "strict")

    model.pack_cursor = 1
    action = model.handle_rule_pack_key("enter")
    assert action.intent is not None
    assert action.intent.args == ("policy", "reload")
    assert model.active_pack == "strict"

    model.pack_cursor = 1
    model.handle_rule_pack_key("enter")
    assert model.pack_detail is True
    assert model.rule_cursor == 0
    assert model.handle_rule_pack_key("enter").detail_opened is True
    assert model.rule_detail_open is True
    assert model.rule_detail_path.endswith("c2.yaml")
    assert "C2-WEBHOOK-SITE" in model.rule_detail_yaml

    action = model.handle_key("e")
    assert action.intent is not None
    assert action.intent.kind == "editor"
    assert action.intent.editor_path.endswith("c2.yaml")

    embedded = PolicyPanelModel()
    embedded.pack_rules = (
        RuleFile(category="c2", rules=(PolicyRule(id="X", title="x"),), source_path=""),
    )
    assert embedded.open_rule_detail() is True
    assert embedded.rule_detail_path == ""
    assert embedded.handle_key("e").intent is None


def test_rule_file_path_flat_index_matches_preview_cursor() -> None:
    model = PolicyPanelModel()
    model.pack_rules = (
        RuleFile(
            category="a",
            source_path="/a.yaml",
            rules=(PolicyRule(id="a1"), PolicyRule(id="a2")),
        ),
        RuleFile(category="b", source_path="/b.yaml", rules=(PolicyRule(id="b1"),)),
    )

    for cursor, want in ((0, "/a.yaml"), (1, "/a.yaml"), (2, "/b.yaml"), (3, "")):
        model.rule_cursor = cursor
        assert model.rule_file_path_at_cursor() == want


def test_judge_order_and_embedded_exfil_prompt_are_loaded(tmp_path: Path) -> None:
    pack = write_rule_pack(tmp_path)
    model = PolicyPanelModel(make_config(tmp_path / "policies", pack))
    model.load()

    assert "exfil" in model.judges
    assert "exfil" in model.judge_names
    assert ordered_judge_names({"custom": object(), "pii": object(), "exfil": object(), "aaa": object()}) == (
        "pii",
        "exfil",
        "aaa",
        "custom",
    )

    model.judge_cursor = model.judge_names.index("exfil")
    out = model.view_judge(120, 40)
    for needle in ("exfil", "data-exfiltration safety classifier", "Sensitive File Access", "Exfiltration Channel"):
        assert needle in out


def test_suppressions_delete_writes_yaml_and_editor_intent(tmp_path: Path) -> None:
    pack = write_rule_pack(tmp_path)
    model = PolicyPanelModel(make_config(tmp_path / "policies", pack))
    model.load()
    assert model.suppressions is not None
    assert model.suppressions.total == 3

    model.active_tab = POLICY_TAB_SUPPRESSIONS
    model.supp_section = 0
    model.supp_cursor = 0
    assert model.handle_suppressions_key("d").handled is True
    assert model.suppressions.total == 2
    saved = yaml.safe_load((pack / "suppressions.yaml").read_text(encoding="utf-8"))
    assert saved["pre_judge_strips"] == []

    action = model.handle_suppressions_key("e")
    assert action.intent is not None
    assert action.intent.kind == "editor"
    assert action.intent.editor_path.endswith("suppressions.yaml")

    model.suppressions = SuppressionsConfig(
        pre_judge_strips=(PreJudgeStrip(id="p"),),
        tool_suppressions=(ToolSuppression(tool_pattern="x"),),
    )
    assert model.suppressions_summary() == (
        ("Pre-Judge Strips", 1),
        ("Finding Suppressions", 0),
        ("Tool Suppressions", 1),
    )


def test_suppression_selection_exposes_delete_and_editor_metadata(tmp_path: Path) -> None:
    pack = write_rule_pack(tmp_path)
    model = PolicyPanelModel(make_config(tmp_path / "policies", pack))
    model.load()
    model.active_tab = POLICY_TAB_SUPPRESSIONS

    selected = model.selected_suppression()
    assert selected is not None
    assert selected.section_name == "Pre-Judge Strips"
    assert selected.label == "STRIP-SYSTEM"
    assert selected.can_delete is True
    assert selected.edit_intent is not None
    assert selected.edit_intent.kind == "editor"
    assert selected.edit_intent.editor_path.endswith("suppressions.yaml")

    model.supp_section = 2
    selected = model.selected_suppression()
    assert selected is not None
    assert selected.section_name == "Tool Suppressions"
    assert selected.label == "^status$"
    assert "JUDGE-PII-USER" in selected.detail


def test_opa_rego_keys_filter_tests_and_run_in_panel_intents(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    rego_dir = policy_dir / "rego"
    rego_dir.mkdir(parents=True)
    (rego_dir / "admission.rego").write_text("package defenseclaw\nallow := true\n", encoding="utf-8")
    (rego_dir / "admission_test.rego").write_text("package defenseclaw\n", encoding="utf-8")

    model = PolicyPanelModel(make_config(policy_dir))
    model.load_rego_files()
    assert [Path(path).name for path in model.rego_files] == ["admission.rego"]
    assert "allow" in model.rego_source

    assert model.handle_opa_key("t").intent is None
    assert [Path(path).name for path in model.rego_files] == ["admission.rego", "admission_test.rego"]
    assert model.handle_opa_key("v").intent.args == ("policy", "validate")
    assert model.handle_opa_key("r").intent.args == ("policy", "reload")

    action = model.handle_opa_key("T")
    assert action.intent is not None
    assert action.intent.args == ("policy", "test")
    assert action.intent.run_in_panel is True
    assert action.intent.timeout_seconds == 30
    assert model.rego_output

    action = model.handle_opa_key("E")
    assert action.intent is not None
    assert action.intent.kind == "editor"
    assert action.intent.editor_path.endswith(".rego")

    model.apply_rego_test_result("", RuntimeError("boom"))
    assert model.rego_output == "policy test failed: boom"
    model.apply_rego_test_result("ok\n")
    assert model.rego_output == "ok"


def test_rego_action_state_exposes_bounded_test_and_editor_intents(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    rego_dir = policy_dir / "rego"
    rego_dir.mkdir(parents=True)
    (rego_dir / "admission.rego").write_text("package defenseclaw\n", encoding="utf-8")

    model = PolicyPanelModel(make_config(policy_dir))
    model.load_rego_files()

    state = model.rego_action_state()
    assert state.selected_name == "admission.rego"
    assert state.can_edit is True
    assert state.validate_intent.args == ("policy", "validate")
    assert state.reload_intent.args == ("policy", "reload")
    assert state.test_intent == policy_test_intent()
    assert state.test_intent.run_in_panel is True
    assert state.test_intent.timeout_seconds == 30
    assert state.edit_intent is not None
    assert state.edit_intent.editor_fallback == "vi"


def test_yaml_overlay_clamping_and_scroll_key_behavior() -> None:
    text = "\n".join(f"- id: line-{index}" for index in range(40))
    window = clamp_yaml_body(text, 20, 1, 0)
    assert window.first == 1
    assert window.last == 1
    assert window.total == 40
    assert all(len(line) <= 20 for line in window.rendered.splitlines())

    model = PolicyPanelModel()
    model.policy_detail_open = True
    model.policy_detail_name = "sensitive-paths"
    model.policy_detail_yaml = text
    out = model.render_policy_detail_overlay(60, 10)
    assert len(out.splitlines()) <= 10
    assert "/ 40" in out
    assert "line-0" in out

    model.policy_detail_scroll = 1 << 30
    out = model.render_policy_detail_overlay(60, 10)
    assert "line-39" in out
    assert model.policy_detail_scroll < 40

    model.policy_detail_scroll = 0
    model.handle_key("down")
    model.handle_key("down")
    assert model.policy_detail_scroll == 2
    model.handle_key("pgup")
    assert model.policy_detail_scroll == 0
    model.handle_key("esc")
    assert model.policy_detail_open is False


def test_policy_profile_guardrail_aibom_readiness_and_edit_intent_summaries(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    pack = write_rule_pack(tmp_path)
    write_policy(policy_dir, "prod")
    (policy_dir / "rego").mkdir()
    (policy_dir / "rego" / "admission.rego").write_text("package defenseclaw\n", encoding="utf-8")
    (policy_dir / "rego" / "data.json").write_text(json.dumps({"config": {"policy_name": "prod"}}), encoding="utf-8")

    model = PolicyPanelModel(make_config(policy_dir, pack))
    model.load()
    model.load_policies()
    summary = model.selected_policy_summary()
    assert summary is not None
    assert summary.name == "prod"
    assert summary.active is True
    assert summary.guardrail.hilt_enabled is True
    assert ("injection", 1) in summary.guardrail.pattern_counts
    assert summary.firewall_allowed_domains == 1
    assert summary.first_party_allow_count == 1
    assert summary.webhook_count == 1

    runtime = model.guardrail_summary()
    assert runtime.enabled is True
    assert runtime.mode == "action"
    assert runtime.rule_count == 2
    assert runtime.judge_count >= 1
    assert runtime.suppression_count == 3

    aibom = model.aibom_summary({"skills": [1, 2], "plugins": [1], "mcp": []})
    assert aibom.connector == "codex"
    assert ("skills", 2) in aibom.categories
    assert aibom.scan_intent.args == ("aibom", "scan", "--json")
    assert aibom_scan_intent(("skills", "plugins", "mcp")).args == (
        "aibom",
        "scan",
        "--json",
        "--only",
        "skills,plugins,mcp",
    )

    readiness = model.readiness_summary()
    assert any(check.title == "Policy directory" and check.status == "pass" for check in readiness)
    assert any(check.title == "Active policy" and check.status == "pass" for check in readiness)
    assert policy_edit_intent("guardrail").args == ("policy", "edit", "guardrail")
