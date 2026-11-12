"""The OpenCode plugin-folder advice names every folder the way its repair does."""

from __future__ import annotations

import shlex

import pytest
from defenseclaw import connector_paths
from defenseclaw.connector_paths import PluginCustodyPath


def _unsafe(*names: str) -> list[PluginCustodyPath]:
    return [PluginCustodyPath(name, "mode") for name in names]


@pytest.mark.parametrize(
    "name",
    ["/home/a/hostile; fix: dir", "/home/a/a:b dir", "/home/a/x, y", "/home/a/it\x27s"],
)
def test_a_hostile_folder_name_is_quoted_in_the_cause_clause(name: str) -> None:
    advice = connector_paths.opencode_custody_text(_unsafe(name))
    assert advice.named == shlex.quote(name)
    assert advice.command == "chmod go-w " + shlex.quote(name)
    sentence = f"{advice.named} {advice.why}; {advice.action}"
    assert sentence.startswith(shlex.quote(name) + " is group/other writable")


def test_every_name_of_a_list_is_quoted() -> None:
    advice = connector_paths.opencode_custody_text(_unsafe("/home/a/ok", "/home/a/x, y", "/home/a/p; fix: q"))
    listed = shlex.quote("/home/a/x, y") + ", " + shlex.quote("/home/a/p; fix: q")
    assert advice.named == "/home/a/ok (and " + listed + ")"


def test_an_ordinary_folder_name_is_written_as_it_is() -> None:
    advice = connector_paths.opencode_custody_text(_unsafe("/home/a/.config/opencode"))
    assert advice.named == "/home/a/.config/opencode"
