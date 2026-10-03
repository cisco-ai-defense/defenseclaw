# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Rule-pack overlay scanner — honors ``guardrail.rule_pack_dir`` at scan time.

**Finding R4.** The Go gateway loads a rule pack from ``guardrail.rule_pack_dir``
(``internal/guardrail/rulepack.go::LoadRulePack``) and applies its regex rules
to LLM traffic at runtime. The install-time Python scanners (skill / mcp /
plugin) historically ignored that directory, so a custom or ``strict`` rule pack
never influenced what ``defenseclaw skill|mcp|plugin scan`` flagged. This module
closes that gap: when an operator has configured a rule pack, the SAME pack's
detection rules are applied to the artifact text the scanners inspect, so
scan-time triage lines up with what the gateway would catch on traffic.

Faithful-but-bounded scope choices (documented for the integrator who sequences
this against the scanner-flip — see session notes):

* We honor the **configured** ``effective_rule_pack_dir(connector)``. When it is
  unset (the built-in default, ``""``) we add NO overlay, so default-install
  scans are unchanged and gain no false positives. The gateway's compiled-in
  baseline is unaffected; "honor rule_pack_dir" means honor it *when set*.
* We apply ``rules/*.yaml`` (precise, severity-carrying regex rules) plus the
  regex pattern families in ``rules/local-patterns.yaml``
  (``injection_regexes``, ``pii_data_regexes``). The raw substring phrase lists
  (``injection`` / ``pii_requests`` / ``secrets`` / ``exfiltration``) are
  intentionally skipped: they are high-false-positive on static prose / source,
  and the precise ``rules/*.yaml`` already cover secrets / commands / paths.
  Flipping this on is a one-line change if a 1:1 traffic match is later wanted.
* ``suppressions.yaml`` / ``sensitive-tools.yaml`` / ``judge/*.yaml`` are
  traffic- and LLM-oriented and are not applied to static artifacts here.
* The data-loss/PII record rules (the ``enterprise-data`` category and the
  ``pii_data_regexes`` family) are skipped too: they find personal data in
  traffic, and on source code they match field names and example numbers in
  help text (GAP-2168).

The overlay is wired into the scan commands via :func:`maybe_wrap`, which wraps
the underlying scanner so every ``scan()`` call site picks up the overlay with
no per-call-site edits. When no rule pack is configured ``maybe_wrap`` returns
the inner scanner untouched, so the common path has zero behavior change.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TypeAlias

import yaml

from defenseclaw.models import Finding
from defenseclaw.scanner.plugin_scanner.helpers import PySource, python_source
from defenseclaw.scanner.plugin_scanner.self_identity import is_first_party_self_target

try:  # Python 3.11+
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse

_log = logging.getLogger(__name__)

# Bounds for the on-disk walk so a pathological target (huge monorepo, vendored
# deps) can't turn a scan into a filesystem crawl. These are deliberately
# generous — the goal is a safety valve, not a tuned limit.
_MAX_FILE_BYTES = 512 * 1024
_MAX_FILES = 2000
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}
# Extensions we never read as text (binaries / archives / media). Anything not
# listed is attempted as UTF-8 and skipped if it fails to decode.
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".tgz", ".bz2", ".xz", ".7z", ".so", ".dylib", ".dll", ".bin",
    ".wasm", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mov", ".mp3", ".wav",
    ".jar", ".class", ".pyc", ".o", ".a",
}

# Local-patterns regex families we apply, with the severity / id / tag the
# overlay finding carries. Substring families are intentionally omitted (see
# module docstring).
_REGEX_FAMILIES = {
    "injection_regexes": ("HIGH", "RP-INJECTION", "Prompt-injection pattern", "prompt-injection"),
}
# Rule categories that describe data in traffic, not artifact code (GAP-2168).
_TRAFFIC_DATA_CATEGORIES = frozenset({"enterprise-data"})
_GO_UNICODE_SCALAR_ESCAPE = re.compile(
    r"(?P<slashes>\\+)x\{(?P<codepoint>[0-9A-Fa-f]{1,6})\}"
)

# A literal prefilter (GAP-2070): every match of a rule must contain certain
# ASCII literals, e.g. ``ignore`` and one of ``previous|prior``. A node is a
# lower-case literal or an ("and"|"or", [nodes]) tuple. Checking it with
# ``in`` on the folded text is far cheaper than a full ``re.search``, and a
# rule whose literals are absent cannot match, so results are unchanged.
_Required: TypeAlias = "str | tuple[str, list]"
_REPEATS = {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}
# The only non-ASCII characters that ``re.IGNORECASE`` matches to an ASCII
# letter. Folding them first keeps the prefilter exact for (?i) rules.
_ASCII_CASE_FOLD = {0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"}

# Windowed search (GAP-2070): in a file over _WINDOW_MIN_TEXT characters a
# rule is searched only in the lines around its anchor literals (every match
# contains one), _WINDOW_SLACK characters and one line on each side, and only in windows
# that hold all of the rule's required literals. Python's re otherwise walks
# every position of a 400 KB adapter for each prose rule. Small files and
# rules without a usable anchor get a plain search.
_WINDOW_MIN_TEXT = 4096
_WINDOW_SLACK = 512
_ANCHOR_MIN_LEN = 3


@dataclass
class _CompiledRule:
    rule_id: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    confidence: float
    tags: list[str]
    category: str
    # Literals every match contains (None: no prefilter).
    required: _Required | None = None
    # Literals one of which every match contains (None: plain search).
    anchors: list[str] | None = None
    # Rules whose expression is a write/append/delete of a path. On Python
    # source a hit counts only when the matched value reaches a write call:
    # a file name in a data list or a message is not an access (GAP-2069,
    # GAP-2124).
    path_write: bool = False


@dataclass
class RulePack:
    """A compiled rule pack ready to match against artifact text."""

    source_dir: str
    rules: list[_CompiledRule] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.rules

    def scan_text(self, text: str, *, location: str = "", python: bool = False) -> list[Finding]:
        """Return one finding per matching rule (first hit), with line number.

        With *python* set, a hit is confirmed on the source with comments
        and docstrings blanked, the same view the plugin scanner's source
        rules use (GAP-1877); ``path_write`` rules also need the matched
        value to reach a write call (GAP-2069, GAP-2124). The view is built
        only when a rule hits.
        """
        if not text:
            return []
        folded = _fold(text)
        py: PySource | None | bool = False  # False: not built yet
        code = text
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.required is not None and not _holds(rule.required, folded):
                continue
            source = text
            m = _search(rule, text, folded)
            if m is not None and python:
                if py is False:
                    py = python_source(text)
                    code = text if py is None else "\n".join(py.code)
                source = code
                if rule.path_write and py is not None:
                    m = next(
                        (
                            hit
                            for hit in rule.pattern.finditer(source)
                            if py.path_written(source.count("\n", 0, hit.start()))
                        ),
                        None,
                    )
                else:
                    m = _search(rule, source, folded)
            if m is None:
                continue
            line_no = source.count("\n", 0, m.start()) + 1
            loc = f"{location}:{line_no}" if location else ""
            findings.append(
                Finding(
                    id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=(
                        f"Matched guardrail rule-pack rule {rule.rule_id} "
                        f"(category={rule.category}, confidence={rule.confidence:g}). "
                        f"Source pack: {self.source_dir}"
                    ),
                    location=loc,
                    scanner="rule-pack",
                    tags=list(rule.tags),
                    rule_id=rule.rule_id,
                    line_number=line_no,
                )
            )
        return findings

    def scan_path(self, path: str) -> list[Finding]:
        """Walk *path* (file or dir) and apply :meth:`scan_text` to text files."""
        findings: list[Finding] = []
        if os.path.isfile(path):
            text = _read_text(path)
            if text is not None:
                findings.extend(
                    self.scan_text(text, location=os.path.basename(path), python=_is_python(path))
                )
            return findings

        if not os.path.isdir(path):
            return findings

        seen = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                if seen >= _MAX_FILES:
                    _log.debug("rule-pack overlay hit file cap (%d) under %s", _MAX_FILES, path)
                    return findings
                full = os.path.join(root, fname)
                text = _read_text(full)
                if text is None:
                    continue
                seen += 1
                rel = os.path.relpath(full, path)
                findings.extend(self.scan_text(text, location=rel, python=_is_python(fname)))
        return findings


RulePackOverlayCache: TypeAlias = dict[str, RulePack]


def _is_python(path: str) -> bool:
    return path.casefold().endswith(".py")


def _fold(text: str) -> str:
    """Lower-case *text* so ASCII literals match it as ``re.IGNORECASE`` does."""
    if text.isascii() or not any(chr(c) in text for c in _ASCII_CASE_FOLD):
        return text.lower()
    return text.translate(_ASCII_CASE_FOLD).lower()


def _holds(node: _Required, folded: str) -> bool:
    if isinstance(node, str):
        return node in folded
    op, kids = node
    # Plain loops: this runs per rule and file, and generator overhead
    # showed up in the GAP-2070 profile.
    want = op != "and"
    for k in kids:
        if (k in folded if isinstance(k, str) else _holds(k, folded)) is want:
            return want
    return not want


def _search(rule: _CompiledRule, text: str, folded: str) -> re.Match[str] | None:
    """``rule.pattern.search(text)``, limited to anchor windows in big files."""
    if rule.anchors is None or len(text) < _WINDOW_MIN_TEXT or len(folded) != len(text):
        return rule.pattern.search(text)
    spans: list[tuple[int, int]] = []
    for lit in rule.anchors:
        i = folded.find(lit)
        while i >= 0:
            spans.append((i, i + len(lit)))
            i = folded.find(lit, i + 1)
    if not spans:
        return None
    spans.sort()
    windows: list[list[int]] = []
    for lo, hi in spans:
        # Whole lines, plus one more line on each side, so a match that
        # spans a long line and the next one (a CSV header and a row) fits.
        lo = text.rfind("\n", 0, max(lo - _WINDOW_SLACK, 0))
        lo = text.rfind("\n", 0, lo) + 1 if lo > 0 else 0
        hi = text.find("\n", min(hi + _WINDOW_SLACK, len(text)))
        hi = text.find("\n", hi + 1) if hi >= 0 else -1
        hi = len(text) if hi < 0 else hi
        if windows and lo <= windows[-1][1]:
            windows[-1][1] = max(windows[-1][1], hi)
        else:
            windows.append([lo, hi])
    for lo, hi in windows:
        if rule.required is not None and not _holds(rule.required, folded[lo:hi]):
            continue
        m = rule.pattern.search(text, lo, hi)
        if m is not None:
            return m
    return None


def _anchors(node: _Required | None, pattern: re.Pattern[str]) -> list[str] | None:
    """A literal set one of which every match contains, for :func:`_search`.

    None when there is no such set of usable literals, or when the pattern
    has an end anchor (``$`` / ``\\Z`` without MULTILINE) that a window's
    end would satisfy falsely.
    """
    if node is None:
        return None
    if "\\Z" in pattern.pattern or "\\z" in pattern.pattern:
        return None
    if "$" in pattern.pattern and not pattern.flags & re.MULTILINE:
        return None
    if isinstance(node, str):
        return [node] if len(node) >= _ANCHOR_MIN_LEN or not node.isascii() else None
    op, kids = node
    sets = [_anchors(k, pattern) for k in kids]
    if op == "or":
        if any(a is None for a in sets):
            return None
        return [lit for a in sets for lit in a]
    usable = [a for a in sets if a is not None]
    if not usable:
        return None
    # Prefer the child with the longest shortest literal: rarer in text.
    return max(usable, key=lambda a: (min(len(x) for x in a), -len(a)))


def _required_literals(pattern: str) -> _Required | None:
    """Literals every match of *pattern* contains, or None when unknown."""
    try:
        return _required_seq(_sre_parse.parse(pattern))
    except Exception:  # noqa: BLE001 - no prefilter is always safe
        return None


def _uncased(cp: int) -> bool:
    c = chr(cp)
    return cp >= 0x80 and c.lower() == c == c.upper()


def _required_seq(items) -> _Required | None:
    parts: list = []
    run: list[str] = []

    def flush() -> None:
        if run:
            parts.append("".join(run).lower())
            run.clear()

    for op, av in items:
        name = getattr(op, "name", str(op))
        if name == "LITERAL" and (av < 0x80 or _uncased(av)):
            run.append(chr(av))
            continue
        flush()
        sub = None
        if name == "IN" and av and all(getattr(o, "name", "") == "LITERAL" and _uncased(v) for o, v in av):
            # A set of uncased non-ASCII characters, such as zero-width
            # spaces: rare in text, so a good prefilter.
            sub = ("or", [chr(v) for _, v in av])
        elif name == "SUBPATTERN":
            sub = _required_seq(av[-1])
        elif name == "ATOMIC_GROUP":
            sub = _required_seq(av)
        elif name in _REPEATS and av[0] >= 1:
            sub = _required_seq(av[2])
        elif name == "BRANCH":
            alts = [_required_seq(b) for b in av[1]]
            if all(a is not None for a in alts):
                sub = ("or", alts)
        if sub is not None:
            parts.append(sub)
    flush()
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else ("and", parts)


def _read_text(path: str) -> str | None:
    """Read *path* as UTF-8 text, or None if binary / too large / unreadable."""
    if os.path.splitext(path)[1].lower() in _BINARY_EXTS:
        return None
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="strict") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def load_rule_pack(dir_path: str) -> RulePack:
    """Load and compile a rule pack from *dir_path*.

    Mirrors the Go loader's graceful degradation: a missing directory, missing
    files, or an unparseable / wrong-version YAML yields an empty (or partial)
    pack rather than raising. An invalid regex is logged and skipped, matching
    ``rulepack.go::checkPattern``.
    """
    pack = RulePack(source_dir=dir_path)
    if not dir_path or not os.path.isdir(dir_path):
        return pack

    rules_dir = os.path.join(dir_path, "rules")
    if not os.path.isdir(rules_dir):
        return pack

    for entry in sorted(os.listdir(rules_dir)):
        if not entry.endswith(".yaml"):
            continue
        full = os.path.join(rules_dir, entry)
        try:
            with open(full, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as exc:
            _log.debug("rule-pack: skip %s (parse error: %s)", full, exc)
            continue
        if not isinstance(raw, dict) or raw.get("version") != 1:
            _log.debug("rule-pack: skip %s (missing/unsupported version)", full)
            continue
        if entry == "local-patterns.yaml":
            _compile_local_patterns(raw, pack)
        else:
            _compile_rules_file(raw, pack)

    return pack


def _compile_rules_file(raw: dict, pack: RulePack) -> None:
    """Compile a ``rules/<category>.yaml`` file into the pack."""
    category = str(raw.get("category", "") or "rule")
    if category in _TRAFFIC_DATA_CATEGORIES:
        return
    for rule in raw.get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        # Tool-call-only rules are evaluated only at an authenticated tool
        # boundary. Static artifact scanning cannot establish that context.
        if rule.get("tool_call_only") is True:
            continue
        # ``enabled: false`` disables a single rule; absent / true keeps it.
        if rule.get("enabled") is False:
            continue
        pattern = rule.get("pattern", "")
        rule_id = str(rule.get("id", "") or "")
        if not pattern or not rule_id:
            continue
        compiled = _compile(pattern, rule_id)
        if compiled is None:
            continue
        expression = str(rule.get("expression", "") or "")
        required = _required_literals(compiled.pattern)
        pack.rules.append(
            _CompiledRule(
                rule_id=rule_id,
                pattern=compiled,
                title=str(rule.get("title", "") or rule_id),
                severity=str(rule.get("severity", "MEDIUM") or "MEDIUM").upper(),
                confidence=float(rule.get("confidence", 0.0) or 0.0),
                tags=[str(t) for t in (rule.get("tags") or [])],
                category=category,
                required=required,
                anchors=_anchors(required, compiled),
                path_write="f.paths" in expression
                and "f.commands" not in expression
                and any(f"PATH_ACCESS_{a}" in expression for a in ("WRITE", "APPEND", "DELETE")),
            )
        )


def _compile_local_patterns(raw: dict, pack: RulePack) -> None:
    """Compile the regex pattern families of ``rules/local-patterns.yaml``."""
    for family, (severity, id_prefix, title, tag) in _REGEX_FAMILIES.items():
        patterns = raw.get(family) or []
        if not isinstance(patterns, list):
            continue
        for idx, pattern in enumerate(patterns):
            if not pattern:
                continue
            rule_id = f"{id_prefix}-{idx}"
            compiled = _compile(str(pattern), rule_id)
            if compiled is None:
                continue
            required = _required_literals(compiled.pattern)
            pack.rules.append(
                _CompiledRule(
                    rule_id=rule_id,
                    pattern=compiled,
                    title=title,
                    severity=severity,
                    confidence=0.0,
                    tags=[tag],
                    category="local-pattern",
                    required=required,
                    anchors=_anchors(required, compiled),
                )
            )


def _compile(pattern: str, rule_id: str) -> re.Pattern[str] | None:
    # Go/RE2 accepts ``\x{10FFFF}`` Unicode scalar escapes while Python's
    # ``re`` does not. Translate only that representational difference so the
    # static-artifact overlay does not silently drop shipped rules containing
    # zero-width or other non-ASCII scalars. This is not validation: the
    # gateway's strict Go loader remains authoritative for the source pattern,
    # and every other unsupported construct still fails closed to "no Python
    # overlay rule" here.
    translated = _translate_go_unicode_scalar_escapes(pattern)
    try:
        return re.compile(translated)
    except re.error as exc:
        _log.debug("rule-pack: invalid regex in %s (%s): %s", rule_id, exc, pattern)
        return None


def _translate_go_unicode_scalar_escapes(pattern: str) -> str:
    """Translate valid Go ``\\x{...}`` scalar escapes for Python ``re``."""

    def _replace(match: re.Match[str]) -> str:
        slashes = match.group("slashes")
        # An even-length run escapes every backslash, so none remains to
        # introduce the apparent ``\x{...}`` token at the end of the run.
        # For an odd-length run, preserve the escaped pairs and translate only
        # the final, unescaped scalar token.
        if len(slashes) % 2 == 0:
            return match.group(0)
        value = int(match.group("codepoint"), 16)
        if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
            return match.group(0)
        return slashes[:-1] + re.escape(chr(value))

    return _GO_UNICODE_SCALAR_ESCAPE.sub(_replace, pattern)


def _resolve_dir(cfg, connector: str | None) -> str:
    """Resolve the effective rule-pack dir; honor it only when set (R4 scope)."""
    gc = getattr(cfg, "guardrail", None)
    if gc is None or not hasattr(gc, "effective_rule_pack_dir"):
        return ""
    return gc.effective_rule_pack_dir(connector or "") or ""


def _active_connector(cfg, connector: str | None) -> str | None:
    if connector:
        return connector
    if hasattr(cfg, "active_connector"):
        try:
            return cfg.active_connector()
        except Exception:  # pragma: no cover - defensive
            return None
    return None


def overlay_findings(
    cfg,
    connector: str | None = None,
    *,
    path: str | None = None,
    text: str | None = None,
) -> list[Finding]:
    """Load the effective rule pack and return findings for *path* and/or *text*.

    Returns ``[]`` when no rule pack is configured (the field is unset) or the
    pack is empty — callers can extend their result findings unconditionally.
    """
    resolved = _active_connector(cfg, connector)
    dir_path = _resolve_dir(cfg, resolved)
    if not dir_path:
        return []
    pack = load_rule_pack(dir_path)
    if pack.is_empty():
        return []
    findings: list[Finding] = []
    if path:
        findings.extend(pack.scan_path(path))
    if text:
        findings.extend(pack.scan_text(text, location="(definition)"))
    return findings


def text_from_mcp_server(target: str, server_entry) -> str:
    """Flatten an MCP server registration to scannable text.

    MCP scan targets are URLs / server names rather than filesystem paths, so we
    feed the rule pack the server's command line, args, env values and url —
    the parts a malicious registration would hide a reverse shell, exfil URL or
    leaked secret in.
    """
    parts: list[str] = [target or ""]
    if server_entry is not None:
        parts.append(getattr(server_entry, "name", "") or "")
        parts.append(getattr(server_entry, "command", "") or "")
        parts.extend(str(a) for a in (getattr(server_entry, "args", None) or []))
        env = getattr(server_entry, "env", None) or {}
        if isinstance(env, dict):
            parts.extend(f"{k}={v}" for k, v in env.items())
        parts.append(getattr(server_entry, "url", "") or "")
    return "\n".join(p for p in parts if p)


class RulePackOverlayScanner:
    """Wraps a scanner so each ``scan()`` result also carries rule-pack findings.

    The wrapped scanner's behavior is preserved verbatim; we only append findings
    from the configured rule pack. The overlay never raises into the caller — a
    failure there is logged and the underlying scan result is returned intact.
    """

    def __init__(self, inner, pack: RulePack, connector: str | None) -> None:
        self.inner = inner
        self.pack = pack
        self.connector = connector

    def name(self) -> str:
        return self.inner.name()

    def __getattr__(self, item):
        # Transparently expose any other attribute/method of the wrapped scanner
        # so callers that reach past the Scanner protocol keep working.
        return getattr(self.inner, item)

    def scan(self, target, *args, **kwargs):
        result = self.inner.scan(target, *args, **kwargs)
        started = time.monotonic()
        try:
            self._apply_overlay(result, target, kwargs)
        except Exception as exc:  # pragma: no cover - defensive
            _log.debug("rule-pack overlay failed for %r: %s", target, exc)
        # The reported scan duration covers the overlay too (GAP-2070).
        if isinstance(getattr(result, "duration", None), timedelta):
            result.duration += timedelta(seconds=time.monotonic() - started)
        return result

    def _apply_overlay(self, result, target, kwargs) -> None:
        # The plugin scanner's exact self-identity exclusion also covers the
        # optional rule-pack overlay. Without this guard the base scanner would
        # return clean while the overlay immediately re-scanned the same
        # bundled runtime and recreated the self-hits.
        if (
            isinstance(target, str)
            and not kwargs.get("include_self", False)
            and is_first_party_self_target(
                target,
                trusted_paths=kwargs.get("trusted_self_paths") or (),
            )
        ):
            return
        new: list[Finding]
        if isinstance(target, str) and os.path.exists(target):
            new = self.pack.scan_path(target)
        else:
            text = text_from_mcp_server(
                target if isinstance(target, str) else "",
                kwargs.get("server_entry"),
            )
            new = self.pack.scan_text(text, location="(definition)") if text else []
        if not new:
            return
        existing = {(f.id, f.location) for f in result.findings}
        for f in new:
            if (f.id, f.location) not in existing:
                # Canonical v8 attributes nested findings to the parent scan
                # producer; retain the overlay engine as finding metadata.
                provenance = f"analyzer:{f.scanner}" if f.scanner else ""
                if provenance and provenance not in f.tags:
                    f.tags.append(provenance)
                f.scanner = result.scanner
                result.findings.append(f)


def maybe_wrap(
    inner,
    cfg,
    connector: str | None = None,
    *,
    pack_cache: RulePackOverlayCache | None = None,
):
    """Wrap *inner* with the rule-pack overlay iff a rule pack is configured.

    Returns *inner* unchanged when no pack is set (or it is empty), so the common
    no-rule-pack path has zero behavior change and pays no extra disk reads.
    Fan-out callers can provide a per-operation *pack_cache*: it de-duplicates
    identical effective directories while preserving an explicit connector
    lookup, so one peer's pack can never bleed into another peer's scan.
    """
    resolved = _active_connector(cfg, connector)
    dir_path = _resolve_dir(cfg, resolved)
    if not dir_path:
        return inner
    cache_key = os.path.normcase(
        os.path.realpath(os.path.abspath(os.path.expanduser(dir_path)))
    )
    if pack_cache is not None and cache_key in pack_cache:
        pack = pack_cache[cache_key]
    else:
        pack = load_rule_pack(dir_path)
        if pack_cache is not None:
            pack_cache[cache_key] = pack
    if pack.is_empty():
        return inner
    return RulePackOverlayScanner(inner, pack, resolved)
