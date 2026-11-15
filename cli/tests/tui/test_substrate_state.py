# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Agent Substrate rows of the Sandboxes panel: the list parser, the row model and the palette rows."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from defenseclaw.tui.command_line import infer_command_risk
from defenseclaw.tui.registry_data import GO_PARITY_REGISTRY
from defenseclaw.tui.services.sandbox_state import SandboxesPanelModel, decode_sandbox
from defenseclaw.tui.services.substrate_state import (
    SIGNED_OUT_NOTE,
    SUBSTRATE_MAX_ROWS,
    SubstrateList,
    parse_substrate_list,
    substrate_needs_terminal,
)

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def _actor(name: str, atespace: str = "team-a", **extra: object) -> dict[str, object]:
    created = (NOW - timedelta(minutes=95)).isoformat().replace("+00:00", "Z")
    return {
        "atespace": atespace,
        "name": name,
        "uid": "u-" + name,
        "profile": "standard",
        "connector": "claude",
        "template": "agent-claude:1",
        "state": "running",
        "created_at": created,
        **extra,
    }


def _list(*actors: dict[str, object]) -> str:
    return json.dumps({"actors": list(actors)})


def _model(*actors: dict[str, object]) -> SandboxesPanelModel:
    model = SandboxesPanelModel()
    model.set_substrate(parse_substrate_list(0, _list(*actors)))
    return model


# ---- the parser ---------------------------------------------------------------


def test_a_valid_list_becomes_rows_and_a_shared_name_keeps_its_atespace() -> None:
    result = parse_substrate_list(
        0, _list(_actor("fix-tests-7f3a"), _actor("dup", "team-a"), _actor("dup", "team-b", state="suspended"))
    )
    assert [row.ref for row in result.rows] == ["team-a/dup", "team-b/dup", "fix-tests-7f3a"]
    assert result.rows[2].connector == "claude" and result.rows[2].profile == "standard"
    assert result.rows[1].state == "suspended"
    assert result.rows[2].age_text(NOW) == "1h35m"
    assert not result.more and not result.note and not result.line


@pytest.mark.parametrize("stdout", ['{"actors": []}', '{"actors": null}', "{}"])
def test_an_empty_list_has_no_rows_and_no_note(stdout: str) -> None:
    assert parse_substrate_list(0, stdout) == SubstrateList()


def test_signed_out_is_the_sign_in_line() -> None:
    result = parse_substrate_list(4, "", "not signed in")
    assert result.rows == () and result.note == SIGNED_OUT_NOTE == result.line


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "reason"),
    [
        (
            1,
            "",
            "starting\nthe cluster could not do that right now (unavailable); try again in a minute\n",
            "cluster could not",
        ),
        (3, "", "this cluster does not offer that yet", "does not offer"),
        (2, "", "Error: No such command 'substrate'.", "No such command"),
        (127, "", "", "exited 127"),
        (0, "not json", "", "could not be read"),
        (0, "[1, 2]", "", "could not be read"),
        (0, '{"actors": "x"}', "", "could not be read"),
    ],
)
def test_a_failure_is_one_dim_line_with_its_reason(returncode: int, stdout: str, stderr: str, reason: str) -> None:
    result = parse_substrate_list(returncode, stdout.encode(), stderr.encode())
    assert result.rows == ()
    assert result.note.startswith("Agent Substrate: ") and reason in result.note
    assert "\n" not in result.note


def test_a_huge_list_is_cut_with_a_count() -> None:
    result = parse_substrate_list(0, _list(*(_actor(f"agent-{i:03d}") for i in range(SUBSTRATE_MAX_ROWS + 70))))
    assert len(result.rows) == SUBSTRATE_MAX_ROWS and result.more == 70
    assert "+70 more" in result.line


def test_names_a_command_line_could_misread_are_dropped() -> None:
    result = parse_substrate_list(
        0, _list(_actor("ok"), _actor("--yes"), _actor("a b"), _actor("x", "bad name"), _actor("gone", deleted=True))
    )
    assert [row.ref for row in result.rows] == ["ok"]


def test_terminal_text_in_a_field_is_neutralised() -> None:
    result = parse_substrate_list(0, _list(_actor("ok", state="run\x1b[31mning", profile="p\nq")))
    row = result.rows[0]
    assert "\x1b" not in row.state and "\n" not in row.profile


# ---- the row model ------------------------------------------------------------


def test_substrate_rows_follow_the_openshell_rows_with_a_runtime_column() -> None:
    model = _model(_actor("fix-tests-7f3a"))
    model.rows = (decode_sandbox({"name": "myapp-claude-7f3a", "harness": "claudecode", "phase": "ready"}),)
    assert "Runtime" in model.data_table_columns(compact=True) and "Runtime" in model.data_table_columns()
    for compact in (True, False):
        columns = model.data_table_columns(compact)
        rows = model.data_table_rows(compact)
        assert [len(row) for row in rows] == [len(columns)] * 2
        runtime = columns.index("Runtime")
        assert [row[runtime] for row in rows] == ["openshell", "substrate"]
        assert [row[0] for row in rows] == ["myapp-claude-7f3a", "fix-tests-7f3a"]


def test_without_substrate_rows_the_table_is_unchanged() -> None:
    model = SandboxesPanelModel()
    model.rows = (decode_sandbox({"name": "myapp", "harness": "claudecode", "phase": "ready"}),)
    assert "Runtime" not in model.data_table_columns(compact=True) and "Runtime" not in model.data_table_columns()
    assert all("substrate" not in row for row in model.data_table_rows())


def test_keys_on_a_substrate_row_are_connect_pull_and_delete() -> None:
    model = _model(_actor("alpha-1"), _actor("dup", "team-a"), _actor("dup", "team-b"))
    assert model.selected_substrate().ref == "alpha-1"
    assert "c connect" in model.keys_line() and "P pull" in model.keys_line() and "R review" not in model.keys_line()
    assert [(key, model.handle_key(key).kind, model.handle_key(key).sandbox) for key in "cPd"] == [
        ("c", "substrate_connect", "alpha-1"),
        ("P", "substrate_pull", "alpha-1"),
        ("d", "substrate_delete", "alpha-1"),
    ]
    model.handle_key("down")
    assert model.handle_key("c").sandbox == "team-a/dup"
    for key in "UsR":
        action = model.handle_key(key)
        assert action.kind == "hint" and "Agent Substrate" in action.hint
    assert model.handle_key("enter").kind == "hint" and not model.detail_open


def test_the_cursor_stays_on_its_agent_when_the_list_refreshes() -> None:
    model = _model(_actor("aaa"), _actor("bbb"))
    model.handle_key("down")
    model.set_substrate(parse_substrate_list(0, _list(_actor("000"), _actor("aaa"), _actor("bbb"))))
    assert model.selected_substrate().ref == "bbb"
    model.drop_substrate("bbb")
    assert [row.ref for row in model.substrate_rows] == ["000", "aaa"]


# ---- the palette rows ---------------------------------------------------------

PALETTE = {row[0]: row for row in GO_PARITY_REGISTRY if row[2][:1] == ("substrate",)}


def test_the_palette_offers_the_user_commands_and_not_the_administrator_ones() -> None:
    assert set(PALETTE) == {
        "substrate login",
        "substrate run claude",
        "substrate list",
        "substrate connect",
        "substrate pull",
        "substrate approvals",
        "substrate doctor",
        "substrate usage",
    }
    assert not {"setup", "bundle", "template"} & {row[2][1] for row in PALETTE.values()}
    for name in ("substrate connect", "substrate pull"):
        assert PALETTE[name][5] is True and PALETTE[name][6] == "<name>"
    assert PALETTE["substrate run claude"][2] == ("substrate", "run", "claude")


def test_read_commands_run_without_a_preview_and_the_others_ask_first() -> None:
    for name in ("substrate list", "substrate approvals", "substrate doctor", "substrate usage"):
        assert infer_command_risk(PALETTE[name][4], PALETTE[name][2]) == "read-only"
    for name in ("substrate login", "substrate run claude", "substrate connect", "substrate pull"):
        assert infer_command_risk(PALETTE[name][4], PALETTE[name][2]) != "read-only"


def test_only_the_interactive_commands_take_the_terminal() -> None:
    assert [
        substrate_needs_terminal(tuple(row[2]))
        for row in PALETTE.values()
        if row[0] in {"substrate login", "substrate run claude", "substrate connect", "substrate pull"}
    ] == [True] * 4
    assert not any(
        substrate_needs_terminal(("substrate", verb)) for verb in ("list", "approvals", "doctor", "usage", "delete")
    )
    assert not substrate_needs_terminal(("sandbox", "connect"))
