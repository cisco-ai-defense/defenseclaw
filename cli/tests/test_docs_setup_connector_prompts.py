"""GAP-0619: the add-or-remove-an-agent page shows every prompt setup asks, in order.

`defenseclaw setup <connector>` asks the enforcement mode first, then
Add/Replace/Cancel (or the --replace confirm), then the LLM judge question in
action mode. The page listed only Add/Replace, so a reader typed `a` at the
mode prompt. The prompt texts are read from the CLI source so a reworded
prompt fails here until the page follows.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs-site/content/docs/guardrail/switching-connectors.mdx"
SETUP_SOURCE = ROOT / "cli/defenseclaw/commands/cmd_setup.py"


def _source_literal(pattern: str) -> str:
    match = re.search(pattern, SETUP_SOURCE.read_text(encoding="utf-8"))
    assert match is not None, f"prompt not found in cmd_setup.py: {pattern}"
    return match.group(1)


def _prompts() -> list[str]:
    mode_section = _source_literal(r'ux\.section\(f"(Enforcement mode for) \{')
    select_mode = _source_literal(r'click\.prompt\(\s*"\s*(Select mode)",\s*type=click\.Choice\(\["1", "2"\]\)')
    choose = _source_literal(r'click\.prompt\(\s*"\s*(Choose)",\s*type=click\.Choice\(\["a", "r", "c"\]')
    add_option = _source_literal(r'ux\.echo\("\s*(\[a\] Add\s+— [^"]+)"\)')
    replace_confirm = _source_literal(
        r'f"\s*Replace \{\', \'\.join\(existing_others\)\} with \{connector\}\? (This removes the other connector\(s\)\.)"'
    )
    judge = _source_literal(r'click\.confirm\(\s*"\s*(Add LLM judge on top of rule scanning\?)",\s*default=already')
    return [
        f"{mode_section} Codex",
        f"{select_mode} (1, 2) [1]:",
        add_option,
        f"{choose} (a, r, c) [a]:",
        f"{judge} [y/N]:",
        f"Replace codex with claudecode? {replace_confirm} [y/N]:",
        f"{judge} [y/N]:",
    ]


def test_page_shows_every_setup_prompt_in_the_order_setup_asks() -> None:
    page = PAGE.read_text(encoding="utf-8")
    position = 0
    for prompt in _prompts():
        found = page.find(prompt, position)
        assert found >= 0, f"page does not show {prompt!r} after offset {position}"
        position = found + len(prompt)


def test_page_says_which_flags_answer_the_mode_and_judge_prompts() -> None:
    page = " ".join(PAGE.read_text(encoding="utf-8").split())
    assert "Passing `--mode observe` or `--mode action` answers this question" in page
    assert "`--enable-judge` or `--no-enable-judge` answers it" in page
    assert "Letters are rejected here" in page
