"""Validate ``TestCase.command`` strings against the CLI surface registry.

The linter parses each case command with :func:`shlex.split`, walks the
registry tree to find the deepest matching subcommand, and then checks
every ``--flag`` and ``-x`` token against the resolved node's flag set.

Findings are emitted with stable codes so the report can suppress those
the case author has already declared "expected" via
``expected_to_fail_at: ["cli-registry"]``.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import Enum

from dctest.models.case import TestCase
from dctest.services.cli_registry import CliNode


class LintCode(str, Enum):
    UNKNOWN_BINARY = "UNKNOWN_BINARY"
    MISSING_SUBCOMMAND = "MISSING_SUBCOMMAND"
    MISSING_FLAG = "MISSING_FLAG"
    UNPARSEABLE_COMMAND = "UNPARSEABLE_COMMAND"


@dataclass
class LintFinding:
    case_id: str
    code: LintCode
    message: str
    expected: bool = False


@dataclass
class LintReport:
    findings: list[LintFinding] = field(default_factory=list)

    @property
    def unexpected(self) -> list[LintFinding]:
        return [f for f in self.findings if not f.expected]

    @property
    def expected(self) -> list[LintFinding]:
        return [f for f in self.findings if f.expected]

    @property
    def ok(self) -> bool:
        return not self.unexpected


# A flag-looking token must start with ``--`` and be followed by an
# alphanumeric, or be a single ``-x``/``-X`` short flag. We deliberately
# avoid matching ``-`` alone (stdin sentinel) or numeric-only tokens like
# ``-5``.
_LONG_FLAG = re.compile(r"^--[A-Za-z][\w\-]*(?:=.*)?$")
_SHORT_FLAG = re.compile(r"^-[A-Za-z]$")

_KNOWN_BINARIES = {"defenseclaw", "defenseclaw-gateway"}


def _safe_tokenize(command: str) -> list[list[str]]:
    """Split ``command`` into argv-style token lists, one per invocation.

    A case's ``command:`` is often a multi-line shell block: pipelines,
    ``set -e``, conditionals, file redirection, here-docs, sub-shells.
    We don't want to validate every line — only the ones whose first
    token is a known binary. We also handle pipelines and ``&&``/``||``
    chains by splitting on those separators first.
    """
    if not command.strip():
        return []
    out: list[list[str]] = []
    for raw_line in command.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "set ", "EOF", "rm ")):
            continue
        # Split by pipes / && / || / ; — but preserve quoted spans.
        # shlex doesn't handle these natively, so we do a coarse split
        # then call shlex per segment.
        segments = re.split(r"\s*(?:\|\||&&|;|\|)\s*", line)
        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue
            try:
                tokens = shlex.split(seg, posix=True)
            except ValueError:
                tokens = []
            if not tokens:
                continue
            head = tokens[0]
            # Skip env-prefix invocations: ``FOO=bar defenseclaw ...``.
            while "=" in head and not head.startswith("-"):
                tokens = tokens[1:]
                if not tokens:
                    break
                head = tokens[0]
            if not tokens:
                continue
            head = tokens[0]
            if head not in _KNOWN_BINARIES:
                # Could be ``curl``, ``test``, ``$(python -c ...)`` etc. —
                # not our job to validate. Skip silently.
                continue
            out.append(tokens)
    return out


def _walk(registry: dict[str, CliNode], tokens: list[str]) -> tuple[CliNode | None, list[str]]:
    """Resolve ``tokens`` to (deepest_node, remaining_tokens).

    Walks subcommands greedily. Any token that isn't a subcommand of the
    current node terminates the walk; remaining tokens are returned for
    flag validation.
    """
    if not tokens:
        return None, []
    binary = tokens[0]
    root = registry.get(binary)
    if root is None:
        return None, tokens[1:]

    node = root
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            break
        if node.has_subcommand(tok):
            node = node.subcommands[tok]
            i += 1
            continue
        # Unknown subcommand — stop walking.
        break
    return node, tokens[i:]


def lint_case(case: TestCase, registry: dict[str, CliNode]) -> list[LintFinding]:
    """Return all findings for one case.

    Findings are not yet marked ``expected`` here — that's done in
    :func:`lint_cases` so we can consult the case's
    ``expected_to_fail_at`` field per finding.
    """
    findings: list[LintFinding] = []
    try:
        invocations = _safe_tokenize(case.command)
    except Exception as exc:  # pragma: no cover — paranoia
        findings.append(
            LintFinding(
                case_id=case.id,
                code=LintCode.UNPARSEABLE_COMMAND,
                message=f"shlex failed: {exc}",
            )
        )
        return findings

    if not invocations:
        return findings

    for tokens in invocations:
        binary = tokens[0]
        if binary not in registry:
            findings.append(
                LintFinding(
                    case_id=case.id,
                    code=LintCode.UNKNOWN_BINARY,
                    message=(
                        f"Binary '{binary}' not present in the registry; "
                        "is it installed and on PATH? "
                        "Run `dctest registry build` to refresh."
                    ),
                )
            )
            continue

        node, remaining = _walk(registry, tokens)
        if node is None:
            continue
        # Pinpoint the deepest matched subcommand path for clearer reporting.
        path_walked: list[str] = [binary]
        cur = registry[binary]
        i = 1
        while i < len(tokens) - len(remaining):
            tok = tokens[i]
            if cur.has_subcommand(tok):
                cur = cur.subcommands[tok]
                path_walked.append(tok)
                i += 1
            else:
                break

        # Any leading non-flag token in ``remaining`` (other than positional
        # values) is an unknown subcommand if it could plausibly be one
        # (lowercase, alphabetic, no slash).
        first_unknown = next((t for t in remaining if _looks_like_subcommand(t)), None)
        if first_unknown is not None and not _is_value_position(
            first_unknown, remaining, node
        ):
            findings.append(
                LintFinding(
                    case_id=case.id,
                    code=LintCode.MISSING_SUBCOMMAND,
                    message=(
                        f"`{' '.join(path_walked)} {first_unknown}` — "
                        f"'{first_unknown}' is not a known subcommand of "
                        f"`{' '.join(path_walked)}`."
                    ),
                )
            )

        for tok in remaining:
            if _is_flag(tok):
                # Normalize ``--foo=bar`` to ``--foo`` for membership check.
                flag = tok.split("=", 1)[0]
                if flag not in node.flags:
                    findings.append(
                        LintFinding(
                            case_id=case.id,
                            code=LintCode.MISSING_FLAG,
                            message=(
                                f"`{' '.join(path_walked)} {flag}` — "
                                f"'{flag}' is not a known flag of "
                                f"`{' '.join(path_walked)}`."
                            ),
                        )
                    )
    return findings


def _is_flag(tok: str) -> bool:
    return bool(_LONG_FLAG.match(tok) or _SHORT_FLAG.match(tok))


def _looks_like_subcommand(tok: str) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9\-]*$", tok))


def _is_value_position(tok: str, remaining: list[str], node: CliNode) -> bool:
    """Best-effort: is ``tok`` a positional VALUE rather than a subcommand?

    Heuristic: if the case command supplies more positional tokens than the
    deepest node declares as subcommands, assume the extras are values for
    the leaf command (e.g. ``defenseclaw skill scan my-skill``). Without a
    full grammar this is approximate but it avoids most false positives.
    """
    # If the deepest matched node has no subcommands, treat any extra word
    # as a positional VALUE for that leaf (e.g. ``defenseclaw skill scan
    # my-skill``). We don't track per-flag value annotations, so this is
    # the strongest signal we have for "this isn't a typo of a subcommand".
    _ = remaining, tok  # silenced for future per-flag-value heuristics
    return not node.subcommands


def lint_cases(
    cases: list[TestCase], registry: dict[str, CliNode]
) -> LintReport:
    """Lint every case; mark findings expected based on ``expected_to_fail_at``."""
    report = LintReport()
    for case in cases:
        for f in lint_case(case, registry):
            if "cli-registry" in case.expected_to_fail_at:
                f.expected = True
            report.findings.append(f)
    return report
