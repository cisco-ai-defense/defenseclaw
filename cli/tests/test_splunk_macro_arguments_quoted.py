"""Splunk Workbench macro arguments are quoted inside the macro definitions."""

from __future__ import annotations

import re
from pathlib import Path

MACROS = (
    Path(__file__).resolve().parents[2]
    / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default/macros.conf"
)


def _macros_with_arguments() -> dict[str, tuple[list[str], str]]:
    found: dict[str, tuple[list[str], str]] = {}
    for stanza in re.split(r"^\[", MACROS.read_text(encoding="utf-8"), flags=re.M)[1:]:
        name, _, body = stanza.partition("]")
        if "(" not in name:
            continue
        args = re.search(r"^args\s*=\s*(.+)$", body, re.M)
        definition = re.search(r"^definition\s*=\s*(.+)$", body, re.M)
        assert args and definition, name
        found[name] = ([a.strip() for a in args.group(1).split(",")], definition.group(1))
    return found


def test_every_macro_argument_is_quoted_where_the_definition_uses_it() -> None:
    # Splunk strips the quotes around a macro argument (a dashboard token
    # saved with |s arrives as its bare text). An unquoted $run_filter$ then
    # becomes `*="*" OR run_id=*`, which the where command rejects for the
    # default token value *, and compares two field names for any other value.
    macros = _macros_with_arguments()
    assert macros, "the app defines argument macros"
    bare: list[str] = []
    for name, (args, definition) in macros.items():
        for arg in args:
            for match in re.finditer(r"\$" + re.escape(arg) + r"\$", definition):
                before, after = definition[: match.start()][-1:], definition[match.end() :][:1]
                if before != '"' or after != '"':
                    bare.append(f"{name}: ${arg}$")
    assert not bare, bare
