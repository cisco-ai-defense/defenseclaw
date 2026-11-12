# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Pin the claims of the Claude Cowork page to the code that backs them.

``docs-site/content/docs/connectors/cowork.mdx`` lists the hook events, the
reason codes, the tool vocabulary, the ``status --json`` keys, the machine
policy drop-in paths and the engine build. Each list is read from the page and
compared with its source: the Go files are parsed as text, the Python module is
imported. A change to either side fails here until the other follows.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs-site/content/docs/connectors/cowork.mdx"
GO_CONNECTOR = ROOT / "internal/gateway/connector"
GO_COWORK = GO_CONNECTOR / "cowork.go"
GO_COWORK_PLUGIN = GO_CONNECTOR / "claudecode_cowork.go"
GO_COWORK_BLOCK = ROOT / "internal/enterprisestatus/cowork_block.go"
GO_POLICY_PATHS = ROOT / "internal/enterprisepolicy/paths.go"
GO_CODESIG = ROOT / "internal/codesig/codesig.go"
COWORK_PY = ROOT / "cli/defenseclaw/cowork.py"
DOCTOR_PY = ROOT / "cli/defenseclaw/commands/cmd_doctor.py"
CONTRACTS = ROOT / "cli/defenseclaw/inventory/hook_contracts.json"
THREAT_MODELS = (
    ROOT / "docs-site/content/docs/enterprise/threat-model.mdx",
    ROOT / "docs/ENTERPRISE-THREAT-MODEL.md",
    ROOT / "docs/LINUX-ENTERPRISE-THREAT-MODEL.md",
    ROOT / "docs/MACOS-ENTERPRISE-THREAT-MODEL.md",
    ROOT / "docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md",
)

_NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """The text under ``heading`` (a ``##`` or ``###`` line) up to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(heading + "\n")
    rest = text[start + len(heading) :]
    stop = re.search(rf"^#{{1,{level}}} ", rest, re.M)
    return rest[: stop.start()] if stop else rest


def _table(section: str, header_first_cell: str) -> list[list[str]]:
    """The body rows of the table whose header starts with ``header_first_cell``."""
    rows: list[list[str]] = []
    in_table = False
    width = 0
    for line in section.splitlines():
        if not in_table:
            if line.startswith("|") and line.strip("| ").split("|")[0].strip() == header_first_cell:
                in_table = True
                width = len(line.strip().strip("|").split("|"))
            continue
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        assert len(cells) == width, f"table cell count differs from its header: {line[:100]}"
        rows.append(cells)
    assert rows, f"table '{header_first_cell}' not found"
    return rows


def _ticks(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def _go_block(text: str, opener: str) -> str:
    start = text.index(opener)
    return text[text.index("{", start) + 1 : text.index("\n}", start)]


# ---- events


def _go_events() -> list[str]:
    block = _go_block(GO_COWORK_PLUGIN.read_text(encoding="utf-8"), "var CoworkPluginHookEvents")
    return re.findall(r'"(\w+)"', block)


def test_the_event_table_is_the_plugin_hook_events():
    events = _go_events()
    assert len(events) == len(set(events)) == 10, events
    section = _section(_page(), "## What DefenseClaw inspects and can block")
    documented: list[str] = []
    for row in _table(section, "Event"):
        documented += _ticks(row[0])
    assert sorted(documented) == sorted(events)
    word = _NUMBER_WORDS[len(events)]
    assert f"Cowork runs {word} hook events. DefenseClaw registers all {word} for the plugin route." in section
    assert f"for the {word} events above" in _page()


def test_the_python_event_set_matches_the_go_event_list():
    from defenseclaw.cowork import COWORK_EVENTS

    assert set(COWORK_EVENTS) == set(_go_events())


# ---- reason codes


def _cowork_status_reason_codes() -> set[str]:
    """The reason_code of every CoworkStatus(...) cowork.py builds: the
    fourth positional argument or the reason_code keyword."""
    tree = ast.parse(COWORK_PY.read_text(encoding="utf-8"))
    codes: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "CoworkStatus"):
            continue
        values = [kw.value for kw in node.keywords if kw.arg == "reason_code"]
        positional = [arg for arg in node.args if not isinstance(arg, ast.Starred)]
        if len(positional) >= 4:
            values.append(positional[3])
        for value in values:
            assert isinstance(value, ast.Constant) and isinstance(value.value, str), ast.dump(value)
            if value.value:
                codes.add(value.value)
    return codes


def test_the_reason_code_table_is_the_cowork_py_reason_codes():
    codes = _cowork_status_reason_codes()
    assert codes and all(code.startswith("cowork_") for code in codes), codes
    section = _section(_page(), "### Check it")
    documented = set()
    for row in _table(section, "Row says"):
        documented.update(_ticks(row[1]))
    assert documented == codes


def test_the_managed_reason_codes_are_the_cowork_block_reasons():
    source = GO_COWORK_BLOCK.read_text(encoding="utf-8")
    codes = set(re.findall(r'CoworkReason\w+\s*=\s*"(\w+)"', source))
    assert len(codes) == 3, codes
    section = _section(_page(), "### Configured versus covered")
    (row,) = [r for r in _table(section, "Field or line") if r[0] == "`reason`"]
    # The cell says why `configured` is false, then lists the codes.
    assert set(_ticks(row[1])) - {"configured"} == codes


# ---- the tool vocabulary


def _go_tool_vocabulary() -> tuple[dict[str, str], dict[str, str], set[str]]:
    source = GO_COWORK.read_text(encoding="utf-8")
    class_values = dict(re.findall(r'(CoworkTool\w+)\s+CoworkToolClass = "(\w+)"', source))
    pair = re.compile(r'"([^"]+)":\s*(CoworkTool\w+)')
    tools = {n: class_values[c] for n, c in pair.findall(_go_block(source, "var coworkTools"))}
    servers = {n: class_values[c] for n, c in pair.findall(_go_block(source, "var coworkServers"))}
    assert tools and servers
    return tools, servers, set(class_values.values())


def _class_for(name: str, tools: dict[str, str], servers: dict[str, str]) -> str | None:
    """connector.CoworkToolClassFor, with ``mcp__<server>__*`` taken as the server."""
    if name in tools:
        return tools[name]
    parts = name.split("__")
    if parts[0] != "mcp" or len(parts) != 3 or not parts[2]:
        return None
    return servers.get(parts[1])


def _documented_tools(section: str) -> list[tuple[str, list[str], str | None]]:
    """(row label, tool names or wildcards, class stated in the row) for each row of the tool table."""
    out = []
    for cells in _table(section, "Tool"):
        names: list[str] = []
        last_server = ""
        for tick in _ticks(cells[0]):
            if "<" in tick:
                continue
            if tick.startswith("mcp__"):
                names.append(tick)
                last_server = tick.split("__")[1]
            elif last_server:
                names.append(f"mcp__{last_server}__{tick}")
        stated = re.search(r"[Cc]lass `(\w+)`", cells[2])
        out.append((cells[0], names, stated.group(1) if stated else None))
    return out


def test_the_tool_table_lists_every_cowork_tool_and_server():
    tools, servers, _ = _go_tool_vocabulary()
    section = _section(_page(), "## Cowork tools")
    rows = _documented_tools(section)
    documented = {n for _, names, _ in rows for n in names}
    for tool in tools:
        assert tool in documented, f"{tool} is in coworkTools but not in the tool table"
    text = " ".join(section.split())
    for server in servers:
        listed = any(f"mcp__{server}__" in n for n in documented) or re.search(
            rf"servers?\b.*`{re.escape(server)}`|`{re.escape(server)}`.*servers", text
        )
        assert listed, f"the {server} server is in coworkServers but not in the tool table"


def test_the_tool_table_classes_are_the_code_classes():
    tools, servers, class_values = _go_tool_vocabulary()
    rows = _documented_tools(_section(_page(), "## Cowork tools"))
    stated_rows = 0
    for label, names, stated in rows:
        if stated is None:
            continue
        stated_rows += 1
        assert stated in class_values, (label, stated)
        if label.startswith("Other tools of the"):
            names = [f"mcp__{t}__x" for t in _ticks(label)]
        assert names, label
        for name in names:
            assert _class_for(name, tools, servers) == stated, (label, name, stated)
    assert stated_rows >= 8
    # The page tells readers to find the class in this audit field.
    assert "`cowork_tool_class`" in _page()
    assert "coworkToolClassExtra = \"cowork_tool_class\"" in (ROOT / "internal/gateway/claude_cowork.go").read_text(
        encoding="utf-8"
    )


def test_the_documented_tool_names_are_cowork_tools():
    # A name the page lists as a Cowork tool must be one the code classifies,
    # or the page promises a mapping the gateway does not apply.
    tools, servers, _ = _go_tool_vocabulary()
    for label, names, _ in _documented_tools(_section(_page(), "## Cowork tools")):
        for name in names:
            if name.startswith("mcp__workspace__") and name not in tools:
                continue  # an unknown workspace tool keeps the generic MCP path, by design
            assert _class_for(name, tools, servers) is not None, (label, name)


# ---- status --json and doctor


def test_status_json_keys_are_the_cowork_status_keys():
    from defenseclaw.cowork import CoworkStatus

    keys = list(CoworkStatus(False, "x").as_dict())
    section = _section(_page(), "### Check it")
    (sentence,) = re.findall(r"`status --json` has a `cowork` object with ([^.]+)\.", section)
    assert re.findall(r"`(\w+)`", sentence) == keys
    check_id = re.search(r"The doctor check id is `([\w.]+)`", section).group(1)
    assert f'check_id="{check_id}"' in DOCTOR_PY.read_text(encoding="utf-8")


# ---- managed drop-in paths and the engine build


def test_the_drop_in_paths_are_the_claude_code_machine_policy_paths():
    paths = GO_POLICY_PATHS.read_text(encoding="utf-8")
    name = re.search(r'DefenseClawDropInName\s*=\s*"([^"]+)"', paths).group(1)
    block = _go_block(paths, "func ClaudeManagedDir")
    linux, macos = re.findall(r'^\s*"(/[^"]+)",$', block, re.M)
    windows_tail = re.search(r"programFiles \+ `([^`]+)`", block).group(1)
    section = _section(_page(), "## Managed computers")
    documented = {row[0]: _ticks(row[1]) for row in _table(section, "OS")}
    assert documented == {
        "macOS": [f"{macos}/managed-settings.d/{name}"],
        "Windows": [f"C:\\Program Files{windows_tail}\\managed-settings.d\\{name}"],
        "Linux": [f"{linux}/managed-settings.d/{name}"],
    }


def test_the_engine_trust_rows_match_the_code_signature_constants():
    source = GO_CODESIG.read_text(encoding="utf-8")
    team = re.search(r'AnthropicTeamID\s*=\s*"(\w+)"', source).group(1)
    signing_id = re.search(r'ClaudeCodeSigningID\s*=\s*"([\w.-]+)"', source).group(1)
    publishers = re.findall(r'"([^"]+)"', re.search(r"var AnthropicPublishers = \[\]string\{([^}]*)\}", source).group(1))
    assert len(publishers) == 2
    section = _section(_page(), "### The engine build")
    rows = {row[0]: row[1] for row in _table(section, "OS")}
    assert f"team `{team}`" in rows["macOS"] and f"identifier `{signing_id}`" in rows["macOS"]
    for publisher in publishers:
        assert f"`{publisher}`" in rows["Windows"]
    # Audit review S6: the threat models name both signer names too.
    windows_model = " ".join((ROOT / "docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md").read_text(encoding="utf-8").split())
    (r38,) = [line for line in (ROOT / "docs/ENTERPRISE-THREAT-MODEL.md").read_text(encoding="utf-8").splitlines()
              if line.startswith("| R38 |")]
    for text in (windows_model, r38):
        assert all(f"`{publisher}`" in text for publisher in publishers), text[:200]


def test_the_vm_limit_is_scoped_to_the_hook():
    # Audit review S6: DefenseClaw's hook does not see what a command did
    # inside the VM; say it of the hook, as the Cowork page does.
    for path in (PAGE, *THREAT_MODELS):
        text = " ".join(path.read_text(encoding="utf-8").split())
        for match in re.finditer(r"what a (?:shell )?command (?:did|ran)", text, re.I):
            before = text[max(0, match.start() - 40) : match.start()]
            after = text[match.end() : match.end() + 60]
            scoped = before.endswith("hook sees tool calls, not ") or "is not visible from the hook" in after
            assert scoped, (path.name, before + match.group(0) + after)


def test_the_engine_version_is_the_vocabulary_engine_version():
    version = re.search(r'CoworkVocabularyEngineVersion = "([\d.]+)"', GO_COWORK.read_text(encoding="utf-8")).group(1)
    text = _page()
    assert f"measured on engines {version} and " in text
    assert f"Engine {version} resolves to a known contract (`claudecode-hooks-v2`)" in text
    contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))

    def walk(node):
        if isinstance(node, dict):
            if node.get("contract_id") == "claudecode-hooks-v2":
                yield node
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)

    (contract,) = list(walk(contracts))
    floor = tuple(int(p) for p in contract["agent_version"]["min_inclusive"].split("."))
    assert floor <= tuple(int(p) for p in version.split(".")), contract["agent_version"]


# The sensor's names, its package and its asset names. "Cowork VM" alone is
# Anthropic's VM and is named on purpose (R39).
_SENSOR_TERMS = re.compile(r"vm[ _-]?sensor|sensor package|cowork[_-]vm|defenseclaw-cowork-(?:amd64|arm64)", re.I)


# Every public doc: the docs site, docs/, the CHANGELOG and the README
# (audit review 2 N3, review 3).
_PUBLIC_DOCS = (
    *sorted((ROOT / "docs-site/content").rglob("*.mdx")),
    *sorted((ROOT / "docs").rglob("*.md")),
    ROOT / "CHANGELOG.md",
    ROOT / "README.md",
)


@pytest.mark.parametrize("path", _PUBLIC_DOCS, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_public_docs_do_not_name_the_vm_sensor(path):
    # The Cowork VM sensor is undocumented by owner decision.
    text = path.read_text(encoding="utf-8")
    assert not _SENSOR_TERMS.findall(text), _SENSOR_TERMS.findall(text)
    assert _SENSOR_TERMS.search("the Cowork VM sensor") and not _SENSOR_TERMS.search("the Cowork VM")


def test_the_printed_uninstall_step_is_the_documented_reminder():
    """GAP-0084: the CLI line is the one guaranteed channel, and the page says so."""
    from defenseclaw.commands import cmd_uninstall

    text = _page()
    assert cmd_uninstall._COWORK_PLUGIN_STAYS in text
    assert "best effort" in text
    assert "guaranteed reminder" in text
