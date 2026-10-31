"""Splunk Workbench macro arguments are quoted inside the macro definitions."""

from __future__ import annotations

import html
import re
from pathlib import Path

APP = (
    Path(__file__).resolve().parents[2]
    / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default"
)
MACROS = APP / "macros.conf"


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


_QUOTED_TOKEN = re.compile(r"\$[\w.:]+\|s\$")


def _shipped_queries() -> list[tuple[str, str]]:
    queries = []
    for match in re.finditer(r"^\[([^\]]+)\]\n((?:(?!\[).*\n?)*)", (APP / "savedsearches.conf").read_text(encoding="utf-8"), re.M):
        search = re.search(r"^search\s*=\s*(.+)$", match.group(2), re.M)
        if search:
            queries.append((f"saved:{match.group(1)}", search.group(1)))
    for view in sorted((APP / "data/ui/views").glob("*.xml")):
        text = view.read_text(encoding="utf-8")
        for index, query in enumerate(re.findall(r"<query>(.*?)</query>", text, re.S)):
            queries.append((f"view:{view.stem}#{index}", html.unescape(query).strip()))
    return queries


def _token_inside_string_literal(query: str) -> str | None:
    """Return the first |s token that sits inside a double-quoted SPL string."""
    inside, index = False, 0
    while index < len(query):
        token = _QUOTED_TOKEN.match(query, index)
        if token:
            if inside:
                return token.group(0)
            index = token.end()
            continue
        if query[index] == "\\":
            index += 2
            continue
        if query[index] == '"':
            inside = not inside
        index += 1
    return None


def test_dashboard_tokens_saved_with_s_never_sit_inside_a_string_literal() -> None:
    # GAP-0207: SimpleXML replaces $x|s$ by the value in double quotes, so a
    # token inside "..." closes the literal early. The Workbench "Guided SPL
    # pivots" table became "`dcso_workbench_summary("*","*")`", which Splunk
    # refuses for any value ("'*' only takes numbers"). The query now joins the
    # literal text and the token with the eval concatenation dot.
    queries = _shipped_queries()
    assert len(queries) > 200
    assert any(name.startswith("view:search_and_drilldown") for name, _ in queries)
    bad = [(name, token) for name, query in queries if (token := _token_inside_string_literal(query))]
    assert not bad, bad


def test_the_literal_scanner_catches_the_old_pivot_query() -> None:
    old = 'eval spl="`dcso_workbench_timeline($run_id|s$,$session_id|s$)`"'
    new = 'eval spl="`dcso_workbench_timeline(" . $run_id|s$ . "," . $session_id|s$ . ")`"'
    assert _token_inside_string_literal(old) == "$run_id|s$"
    assert _token_inside_string_literal(new) is None
