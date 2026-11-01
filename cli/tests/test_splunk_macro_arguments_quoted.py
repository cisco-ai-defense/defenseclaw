"""Splunk Workbench macro arguments are quoted inside the macro definitions."""

from __future__ import annotations

import html
import re
from pathlib import Path
from urllib.parse import quote

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


def _backtick_spans(text: str) -> list[tuple[int, int]]:
    """Backtick spans (macro calls) that are not inside a double-quoted literal."""
    spans, inside, index, begin = [], False, 0, None
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"' and begin is None:
            inside = not inside
        elif char == "`" and not inside:
            if begin is None:
                begin = index
            else:
                spans.append((begin, index + 1))
                begin = None
        index += 1
    return spans


def test_every_macro_argument_is_decoded_or_passed_on_where_the_definition_uses_it() -> None:
    # Splunk strips the quotes around a macro argument (a dashboard token
    # saved with |s arrives as its bare text, with one level of backslashes
    # removed), so the old bare $run_filter$ became `*="*" OR run_id=*` for the
    # default token and a quote in the token left the string literal. The
    # views pass "$tok|u$" (URL-encoded, quote-free) and every macro compares
    # urldecode("$arg$"); a nested macro call may pass "$arg$" on unchanged.
    macros = _macros_with_arguments()
    assert macros, "the app defines argument macros"
    bad: list[str] = []
    for name, (args, definition) in macros.items():
        calls = _backtick_spans(definition)
        for arg in args:
            for match in re.finditer(r"\$" + re.escape(arg) + r"\$", definition):
                nested = any(begin <= match.start() < end for begin, end in calls)
                decoded = definition[: match.start()].endswith('urldecode("') and definition[match.end() :].startswith('")')
                passed_on = nested and definition[: match.start()][-1:] == '"' and definition[match.end() :][:1] == '"'
                if not (decoded or passed_on):
                    bad.append(f"{name}: ${arg}$")
    assert not bad, bad


def _encode_uri_component(value: str) -> str:
    # What SimpleXML's $token|u$ filter produces (JavaScript encodeURIComponent).
    return quote(value, safe="-_.!~*'()")


INJECTION_SHAPED_TOKENS = (
    "*",
    "abc",
    'x") OR 1=1 OR ("',
    'x" OR run_id!="',
    'a\\"b',
    "x` | delete `",
    "x | outputlookup evil",
    "$session_id$",
)


def test_an_injection_shaped_token_stays_inside_its_string_literal() -> None:
    # F-0608 on Splunk 10.2: substitute each hostile token into every macro
    # definition as the view would pass it and require that no new quote,
    # backtick or pipe appears outside the literal, i.e. the quote state of the
    # definition is exactly the benign one.
    macros = _macros_with_arguments()
    for token in INJECTION_SHAPED_TOKENS:
        encoded = _encode_uri_component(token)
        assert not set('"\\` |$\n') & set(encoded), (token, encoded)
        for name, (args, definition) in macros.items():
            benign, hostile = definition, definition
            for arg in args:
                benign = benign.replace(f"${arg}$", "abc")
                hostile = hostile.replace(f"${arg}$", encoded)
            assert _quote_parity(hostile) == _quote_parity(benign), (name, token)
            assert hostile.count("`") == benign.count("`"), (name, token)
            assert hostile.count("|") == benign.count("|"), (name, token)


def _quote_parity(text: str) -> int:
    count, index = 0, 0
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        count += text[index] == '"'
        index += 1
    return count


def test_the_old_quoted_form_is_what_an_injection_shaped_token_breaks() -> None:
    # The pre-fix form that put the decoded token between quotes: the token's
    # own quote ends the literal and changes the quote state.
    definition = '| where ("$run_filter$"="*" OR run_id="$run_filter$")'
    benign = definition.replace("$run_filter$", "abc")
    hostile = definition.replace("$run_filter$", 'x") OR 1=1 OR ("')
    assert _quote_parity(hostile) != _quote_parity(benign)


def test_every_view_hands_macros_url_encoded_tokens() -> None:
    bad: list[str] = []
    for view in sorted((APP / "data/ui/views").glob("*.xml")):
        for index, query in enumerate(re.findall(r"<query>(.*?)</query>", view.read_text(encoding="utf-8"), re.S)):
            text = html.unescape(query)
            for begin, end in _backtick_spans(text):
                call = text[begin:end]
                if _QUOTED_TOKEN.search(call):
                    bad.append(f"{view.stem}#{index}: {call[:80]}")
                for match in re.finditer(r"\$[\w.:]+\|u\$", call):
                    if call[match.start() - 1] != '"' or call[match.end()] != '"':
                        bad.append(f"{view.stem}#{index}: unquoted {match.group(0)}")
    assert not bad, bad


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
