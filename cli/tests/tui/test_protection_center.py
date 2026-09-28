# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Protection center model: posture, opt-in packs, chains, families, keys → intents, weakening."""

from __future__ import annotations

import os
import re
import string
from types import SimpleNamespace

import pytest
from defenseclaw.policy_catalog import ConnectorPack, ProtectionPack, RuleFamily, ScopePosture, ToolChain
from defenseclaw.tui import policy_panel
from defenseclaw.tui.policy_panel import (
    composed_pack_path,
    hilt_change_modal,
    mode_change_modal,
    policy_threshold_modal,
    protection_change_modal,
)
from defenseclaw.tui.screens.posture_picker import approval_choices, threshold_choices
from defenseclaw.tui.services.policy_state import (
    POLICY_VIEWS,
    PackRule,
    PoliciesPanelModel,
    actions_weaken,
    hilt_intent,
    hilt_weakens,
    matrix_lines,
    mode_intent,
    mode_weakens,
    pack_profile,
    policies_keys_hint,
    policy_keymap_rows,
    posture_summary,
    protection_intent,
    severity_actions,
    threshold_intent,
    threshold_weakens,
    use_pack_intent,
)
from test_policy_state import DEFAULT, PERMISSIVE, STRICT


# Built from the policy_catalog contracts, so a field rename fails here.
def Posture(scope: str, **fields: object) -> ScopePosture:  # noqa: N802 - reads like the dataclass
    values: dict[str, object] = {
        "mode": "observe",
        "mode_source": "global",
        "hilt": "off",
        "pack": "default",
        "pack_path": "/p/guardrail/default",
        "pack_source": "global",
        "protection": (),
    }
    values.update(fields)
    return ScopePosture(scope=scope, **values)  # type: ignore[arg-type]


def Pack(name: str, title: str, **fields: object) -> ProtectionPack:  # noqa: N802
    values: dict[str, object] = {
        "summary": "Blocks what it covers.",
        "covers": "what it covers",
        "rule_count": 3,
        "rule_ids": ("a", "b", "c"),
        "status": "selectable",
    }
    values.update(fields)
    return ProtectionPack(name=name, title=title, **values)  # type: ignore[arg-type]


def Chain(id: str, title: str, **fields: object) -> ToolChain:  # noqa: A002, N802
    values: dict[str, object] = {
        "severity": "HIGH",
        "domain": "sql",
        "can_block": False,
        "event_window": 9,
        "time_window_seconds": 1800,
        "requires": ("same session",),
        "note": "",
    }
    values.update(fields)
    return ToolChain(id=id, title=title, **values)  # type: ignore[arg-type]


def Family(name: str, rules: int, enabled: int, description: str = "") -> RuleFamily:  # noqa: N802
    return RuleFamily(name=name, rules=rules, enabled=enabled, description=description)


POSTURES = (
    Posture("global"),
    Posture(
        "codex",
        mode="action",
        mode_source="override",
        hilt="HIGH+",
        pack="strict",
        pack_path="/p/guardrail/strict",
        pack_source="override",
        protection=("database-destruction-protection",),
    ),
    Posture("claudecode"),
)
PACKS = (
    Pack("ssh-authorized-keys-protection", "SSH authorized_keys", rule_count=0, rule_ids=(), status="staged"),
    Pack("database-destruction-protection", "Database destruction", covers="DELETE without WHERE, TRUNCATE"),
    Pack("kubernetes-production-protection", "Kubernetes production"),
    Pack("cloud-production-protection", "Cloud production", rule_count=4),
    Pack("infrastructure-destruction-protection", "Infrastructure destruction", rule_count=5),
    Pack("privacy-high-assurance", "Privacy high-assurance", rule_count=13),
)
CHAINS = (
    Chain("chain.guardrails_off", "Guardrails off then egress", domain="security-controls"),
    Chain("chain.sqlite_delete", "SQLite read then unbounded delete", severity="CRITICAL", can_block=True),
    Chain("chain.shell", "Reverse shell persistence", severity="CRITICAL", domain="host", can_block=True),
    Chain("chain.xp", "xp_cmdshell enable then invoke"),
    Chain("chain.mystery", "Something new", domain="quantum"),
)
FAMILIES = {
    "/p/guardrail/default": (
        Family("command", 128, 128, "Execution and destructive commands"),
        Family("secret", 23, 23),
    ),
    "/p/guardrail/strict": (Family("command", 139, 139),),
}


def protection_model(*, multi: bool = True, sandbox: bool = True) -> PoliciesPanelModel:
    model = PoliciesPanelModel(sandbox_supported=sandbox)
    connectors = {"codex": SimpleNamespace(), "claudecode": SimpleNamespace()} if multi else {}
    model.set_config(SimpleNamespace(guardrail=SimpleNamespace(connectors=connectors), policy_dir="/home/u/policies"))
    model.apply_policies([DEFAULT, PERMISSIVE, STRICT])
    model.apply_packs(
        ConnectorPack("global", "default", "/p/guardrail/default", "default"),
        [
            ConnectorPack("codex", "strict", "/p/guardrail/strict", "override"),
            ConnectorPack("claudecode", "default", "/p/guardrail/default", "default"),
        ],
        [],
    )
    model.apply_protection(
        POSTURES,
        PACKS,
        pack_rules={"database-destruction-protection": (PackRule("impact.sql_unbounded_delete", "CRITICAL", "SQL"),)},
        families=FAMILIES,
        chains=CHAINS,
    )
    return model


# ---- posture ----------------------------------------------------------------


def test_posture_is_the_default_view_and_rows_show_each_scopes_tool_call_levels() -> None:
    model = protection_model()
    assert model.view == "posture"
    rows = model.data_table_rows(80)
    columns = model.data_table_columns(80)
    assert [row[0] for row in rows] == ["global", "codex", "claudecode"]
    # codex's strict pack blocks MEDIUM+ and alerts on LOW+; the others use default levels.
    assert rows[1][2:5] == ("MEDIUM+", "LOW+", "HIGH+")
    assert rows[0][2:5] == ("CRITICAL", "MEDIUM+", "off")
    assert rows[1][6] == "1/5" and rows[0][6] == "0/5"
    widest = [max(len(c), *(len(r[i]) for r in rows)) for i, c in enumerate(columns)]
    assert sum(widest) + 2 * len(widest) <= 74
    assert len(model.data_table_rows(160)[0]) == len(model.data_table_columns(160)) == 7


def test_pack_profile_mirrors_the_gateway_folder_name_rule() -> None:
    assert pack_profile("/x/guardrail/strict") == "strict"
    assert pack_profile("/x/Permissive/") == "permissive"
    for path in ("", "/x/guardrail/default", "/x/balanced", "/x/guardrail/protected-codex", "/x/mine"):
        assert pack_profile(path) == "default"


def test_posture_summary_and_matrix_follow_block_then_approval_then_alert() -> None:
    assert severity_actions("CRITICAL", "MEDIUM+", "HIGH+") == (
        ("CRITICAL", "block"),
        ("HIGH", "ask"),
        ("MEDIUM", "alert"),
        ("LOW", "allow"),
    )
    # Approval at CRITICAL never asks while CRITICAL already blocks.
    assert dict(severity_actions("CRITICAL", "MEDIUM+", "CRITICAL"))["CRITICAL"] == "block"
    assert posture_summary("codex", "observe", "CRITICAL", "MEDIUM+", "HIGH+").startswith("codex logs only")
    assert "blocks MEDIUM+" in posture_summary("codex", "action", "MEDIUM+", "LOW+", "off")
    assert matrix_lines("observe", "CRITICAL", "MEDIUM+", "off")[0].endswith("log (would block)")
    model = protection_model()
    model.handle_key("down")
    title, lines = model.aside()
    assert title.endswith("codex")
    assert any(line.startswith("  HIGH") for line in lines)


def test_posture_keys_ask_for_the_right_flow_on_the_highlighted_scope() -> None:
    model = protection_model()
    model.handle_key("down")
    for key, kind in (("m", "toggle_mode"), ("b", "pick_block"), ("a", "pick_alert"), ("h", "pick_hilt")):
        action = model.handle_key(key)
        assert (action.kind, action.connector) == (kind, "codex")
    assert model.handle_key("p").kind == "pick_pack"
    model.handle_key("up")
    assert model.handle_key("m").connector == ""
    # b and a set the scope's own tool-call levels, so no active policy is needed.
    none_active = protection_model()
    none_active.apply_policies([PERMISSIVE, STRICT])
    assert none_active.handle_key("b").kind == "pick_block"
    assert PoliciesPanelModel().handle_key("m").kind == "hint"  # nothing loaded yet


def test_intents_build_the_exact_argv() -> None:
    assert mode_intent("observe", "codex").argv == (
        "defenseclaw",
        "guardrail",
        "mode",
        "observe",
        "--connector",
        "codex",
    )
    assert mode_intent("action").args == ("guardrail", "mode", "action")
    assert threshold_intent("block", "HIGH+").args == ("policy", "edit", "guardrail", "--block-threshold", "3")
    assert threshold_intent("alert", "LOW+").args == ("policy", "edit", "guardrail", "--alert-threshold", "1")
    assert hilt_intent("HIGH+", "codex").args == (
        "guardrail",
        "hilt",
        "on",
        "--min-severity",
        "HIGH",
        "--connector",
        "codex",
        "--yes",
    )
    assert hilt_intent("off").args == ("guardrail", "hilt", "off", "--yes")
    assert protection_intent("privacy-high-assurance", enable=True, connector="codex").args == (
        "guardrail",
        "protection",
        "enable",
        "privacy-high-assurance",
        "--connector",
        "codex",
    )
    assert protection_intent("privacy-high-assurance", enable=False).args == (
        "guardrail",
        "protection",
        "disable",
        "privacy-high-assurance",
    )
    assert use_pack_intent("strict", "codex").args == ("guardrail", "use-pack", "strict", "--connector", "codex")
    with pytest.raises(ValueError):
        threshold_intent("block", "none")


def test_single_connector_install_sets_mode_and_approval_globally() -> None:
    model = protection_model(multi=False)
    codex = model.scope_row("codex")
    assert model.command_connector(codex) == ""
    assert protection_model().command_connector(codex) == "codex"
    modal = mode_change_modal(model, codex, "observe")
    assert modal.details[-1].endswith("defenseclaw guardrail mode observe")
    kubernetes = model.protection_pack("kubernetes-production-protection")
    enable = protection_change_modal(model, codex, kubernetes, True)
    assert enable.details[-1].endswith("enable kubernetes-production-protection")


# ---- weakening ----------------------------------------------------------------


def test_weakening_rules_for_mode_levels_and_approval() -> None:
    assert mode_weakens("action", "observe") and not mode_weakens("observe", "action")
    assert threshold_weakens("MEDIUM+", "CRITICAL") and threshold_weakens("MEDIUM+", "HIGH+")
    assert not threshold_weakens("CRITICAL", "HIGH+")
    assert hilt_weakens("HIGH+", "off") and hilt_weakens("HIGH+", "CRITICAL")
    assert not hilt_weakens("off", "HIGH+") and not hilt_weakens("HIGH+", "MEDIUM+")
    assert actions_weaken(
        severity_actions("CRITICAL", "MEDIUM+", "HIGH+"), severity_actions("CRITICAL", "MEDIUM+", "off")
    ) == ("HIGH",)


def test_consequence_modals_turn_red_only_when_protection_weakens() -> None:
    model = protection_model()
    codex, global_row = model.scope_row("codex"), model.scope_row("")
    assert mode_change_modal(model, codex, "observe").actions[0].danger is True
    assert mode_change_modal(model, global_row, "action").actions[0].danger is False
    # The Policies view's b / a: the policy's LLM-traffic levels.
    assert policy_threshold_modal("block", "HIGH+", model.active_policy()).actions[0].danger is False
    loosen = policy_threshold_modal("block", "CRITICAL", STRICT)
    assert loosen.actions[0].danger is False  # not the active policy: nothing changes yet
    strict_active = STRICT.__class__(**{**STRICT.__dict__, "active": True})
    assert policy_threshold_modal("block", "CRITICAL", strict_active).actions[0].danger is True
    assert hilt_change_modal(model, codex, "off").actions[0].danger is True
    assert hilt_change_modal(model, codex, "MEDIUM+").actions[0].danger is False
    database = model.protection_pack("database-destruction-protection")
    assert protection_change_modal(model, codex, database, False).actions[0].danger is True
    kubernetes = model.protection_pack("kubernetes-production-protection")
    # claudecode's default pack keeps its levels in the composed folder.
    assert protection_change_modal(model, model.scope_row("claudecode"), kubernetes, True).actions[0].danger is False
    # codex's strict pack is composed into protected-codex/strict, so it keeps strict levels.
    assert protection_change_modal(model, codex, kubernetes, True).actions[0].danger is False
    assert composed_pack_path(model, codex).endswith(os.path.join("protected-codex", "strict"))
    # With no policy_dir the CLI composes under <data_dir>/policies; the preview says the same.
    model.set_config(SimpleNamespace(policy_dir="", data_dir="/dc"))
    assert composed_pack_path(model, codex) == os.path.join("/dc", "policies", "guardrail", "protected-codex", "strict")


def test_global_changes_name_the_connectors_that_keep_their_own_setting() -> None:
    model = protection_model()
    global_row = model.scope_row("")
    assert any("codex" in line for line in mode_change_modal(model, global_row, "action").details)
    kubernetes = model.protection_pack("kubernetes-production-protection")
    assert any("codex" in line for line in protection_change_modal(model, global_row, kubernetes, True).details)
    assert any("claudecode" in line for line in hilt_change_modal(model, global_row, "HIGH+").details)


# ---- opt-in packs -------------------------------------------------------------


def test_optin_rows_follow_the_scope_and_staged_packs_never_turn_on() -> None:
    model = protection_model()
    assert model.handle_key("2").kind == "render"
    rows = model.data_table_rows(80)
    assert [row[-1] for row in rows] == ["○ off"] * 5 + ["─ staged"]  # staged listed last
    assert model.handle_key("s").kind == "render"
    assert model.scope_name() == "codex"
    assert model.data_table_rows(80)[0][-1] == "● on"
    action = model.handle_key("space")
    assert (action.kind, action.pack, action.enable, action.connector) == (
        "toggle_protection",
        "database-destruction-protection",
        False,
        "codex",
    )
    model.handle_key("down")
    assert model.handle_key("enter").enable is True
    for _ in range(5):
        model.handle_key("down")
    assert model.handle_key("space").kind == "hint"
    title, lines = model.aside()
    assert title == "SSH authorized_keys" and any("staged" in line.lower() for line in lines)
    model.handle_key("s")
    model.handle_key("s")
    assert model.scope_name() == "global"


def test_optin_aside_lists_the_rules() -> None:
    model = protection_model()
    model.handle_key("2")
    _title, lines = model.aside()
    assert "  impact.sql_unbounded_delete · CRITICAL · SQL" in lines
    model.handle_key("down")
    assert "  a" in model.aside()[1]  # rule ids only when the titles are unknown


# ---- chains and families ------------------------------------------------------


def test_chains_are_grouped_by_domain_and_the_cursor_skips_headers() -> None:
    model = protection_model()
    model.handle_key("3")
    rows = model.data_table_rows(80)
    headers = [row[1] for row in rows if not row[0]]
    assert headers == ["── SQL", "── Host", "── Security controls", "── Other"]
    assert rows[1][:2] == ("✓", "SQLite read then unbounded delete")
    assert model.cursor == 1  # not the SQL header
    model.handle_key("down")
    model.handle_key("down")
    assert model.selected_chain().id == "chain.shell"  # the Host header was skipped
    model.cursor = 0  # a click on a header moves back onto a chain
    assert model.selected_chain() is not None
    title, lines = model.aside()
    assert title and any(line.startswith("Looks at the last 9 tool calls") for line in lines)
    assert model.handle_key("space").kind == "none"  # read-only


def test_rule_families_follow_the_scopes_pack() -> None:
    model = protection_model()
    model.handle_key("4")
    assert [row[0] for row in model.data_table_rows(80)] == ["command", "secret"]
    model.handle_key("s")
    assert model.data_table_rows(80) == (("command", "139", "139", "-"),)
    assert model.aside()[0] == "Rule family · command"


# ---- keys, hints, help ----------------------------------------------------------

_HINT_KEYS = {"Space": "space", "Enter": "enter"}


@pytest.mark.parametrize("view", POLICY_VIEWS)
def test_every_hinted_key_is_handled_and_fits_80_columns(view: str) -> None:
    hint = policies_keys_hint(view)
    assert len(hint) <= 78
    for segment in hint.removeprefix("KEYS").split("|"):
        token = segment.strip().split(" ")[0]
        if token in {"read-only", "read-only:"} or token.startswith("1-"):
            continue
        for key in token.split("/"):
            model = protection_model()
            model.set_view(view)
            assert model.handle_key(_HINT_KEYS.get(key, key)).handled, (view, key)


def _help_mentions(rows, view: str, key: str) -> bool:
    names = {"space": "Space", "enter": "Enter", "escape": "Esc", "up": "Up", "down": "Down"}
    want = names.get(key, key)
    for keys, _what, views in rows:
        if view not in views:
            continue
        if keys.startswith("1 ") and key.isdigit():
            return True
        if want in re.split(r"[ /,]+", keys.replace(" or ", " ")):
            return True
    return False


@pytest.mark.parametrize("view", POLICY_VIEWS)
def test_every_handled_key_is_in_the_help_sheet(view: str) -> None:
    rows = policy_keymap_rows(True)
    for key in [*string.ascii_lowercase, *"1234567", "space", "enter", "escape", "up", "down"]:
        model = protection_model()
        model.set_view(view)
        model.detail_open = True  # so Esc has something to close
        if model.handle_key(key).handled:
            assert _help_mentions(rows, view, key), (view, key)


def test_unsupported_sandbox_drops_the_seventh_view() -> None:
    model = protection_model(sandbox=False)
    assert model.views() == POLICY_VIEWS[:-1]
    assert model.handle_key("7").kind == "hint"
    assert "1-6" in model.keys_hint()
    assert policy_keymap_rows(False)[0][0] == "1 … 6"


def test_header_switcher_and_nav_fit_80_columns() -> None:
    model = protection_model()
    header = model.header(64)
    assert len(header) <= 64 and header.startswith("● default policy")
    assert model.header(0).endswith("5 chains (2 can block)")
    for view in POLICY_VIEWS:
        model.set_view(view)
        # The active view is drawn reversed with a space either side.
        switcher = "  ".join(f" {k} {t} " if active else f"{k} {t}" for k, t, active in model.view_switcher())
        assert len(switcher) <= 76
    model.set_view("posture")
    nav = model.nav_entries()
    assert [entry[0] for entry in nav] == list(POLICY_VIEWS)
    assert nav[0][3] is True and nav[1][2] == "1/5"


def test_pickers_mark_the_current_level_and_the_weaker_ones() -> None:
    block = threshold_choices("block", "HIGH+")
    assert [(c.value, c.current, c.weaker) for c in block] == [
        ("CRITICAL", False, True),
        ("HIGH+", True, False),
        ("MEDIUM+", False, False),
    ]
    approval = approval_choices("HIGH+")
    assert [c.value for c in approval if c.weaker] == ["off", "CRITICAL"]


def test_read_catalog_survives_a_broken_protection_catalog(monkeypatch) -> None:
    from defenseclaw import policy_catalog

    def boom(*_args, **_kwargs):
        raise OSError("tool-chains.json is unreadable")

    monkeypatch.setattr(policy_catalog, "tool_chains", boom, raising=False)
    monkeypatch.setattr(policy_catalog, "scope_postures", lambda cfg: list(POSTURES), raising=False)
    monkeypatch.setattr(policy_catalog, "protection_packs", lambda: list(PACKS), raising=False)
    monkeypatch.setattr(policy_catalog, "rule_families", lambda path: list(FAMILIES.get(path, ())), raising=False)
    config = SimpleNamespace(policy_dir="", data_dir="", guardrail=SimpleNamespace(rule_pack_dir="", connectors={}))
    read = policy_panel.read_policy_catalog(config)
    assert read.posture_error == "tool-chains.json is unreadable"
    assert [row.scope for row in read.postures] == ["global", "codex", "claudecode"]
    assert set(read.families) == {"/p/guardrail/default", "/p/guardrail/strict"}
    assert read.pack_rules["database-destruction-protection"] == (PackRule("a"), PackRule("b"), PackRule("c"))
    model = PoliciesPanelModel()
    model.apply_protection(read.postures, read.protection, chains=read.chains)
    model.set_posture_error(read.posture_error)
    model.loaded = True
    model.set_view("chains")
    assert "tool-chains.json" in model.headline() and model.empty_state() == ""


def test_a_composed_pack_shows_its_base_and_why_its_levels_changed() -> None:
    model = PoliciesPanelModel()
    composed = Posture(
        "codex",
        pack="protected-codex",
        pack_path="/p/guardrail/protected-codex",
        pack_source="override",
        protection=("database-destruction-protection",),
    )
    model.apply_protection([Posture("global"), composed], PACKS, pack_bases={"/p/guardrail/protected-codex": "strict"})
    model.handle_key("down")
    assert model.data_table_rows(74)[1][5] == "strict+1"
    assert model.data_table_rows(74)[1][2] == "CRITICAL"  # the folder name reads as default levels
    assert any(line.startswith("Rule pack: protected-codex = strict + 1") for line in model.aside()[1])


async def test_the_toggle_button_grows_to_fit_a_longer_label() -> None:
    from defenseclaw.tui.policy_panel import PolicyPanelMixin
    from textual.app import App
    from textual.containers import Horizontal
    from textual.widgets import Button

    class Harness(App[None]):
        CSS = "Button { height: 1; min-width: 8; border: none; }"

        def compose(self):  # type: ignore[no-untyped-def]
            with Horizontal():
                yield Button("Turn on", id="toggle")
                yield Button("Refresh", id="refresh")

    app = Harness()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        PolicyPanelMixin._set_button_label(app, "#toggle", "Turn off")  # type: ignore[arg-type]
        await pilot.pause()
        # A button is its label plus one pad cell each side.
        assert app.query_one("#toggle", Button).size.width >= len("Turn off") + 2
