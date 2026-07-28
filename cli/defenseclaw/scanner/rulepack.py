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

The overlay is wired into the scan commands via :func:`maybe_wrap`, which wraps
the underlying scanner so every ``scan()`` call site picks up the overlay with
no per-call-site edits. When no rule pack is configured ``maybe_wrap`` returns
the inner scanner untouched, so the common path has zero behavior change.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

import yaml

from defenseclaw.models import Finding

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
    "pii_data_regexes": ("MEDIUM", "RP-PII-DATA", "PII data pattern", "pii"),
}


@dataclass
class _CompiledRule:
    rule_id: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    confidence: float
    tags: list[str]
    category: str


@dataclass
class RulePack:
    """A compiled rule pack ready to match against artifact text."""

    source_dir: str
    rules: list[_CompiledRule] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.rules

    def scan_text(self, text: str, *, location: str = "") -> list[Finding]:
        """Return one finding per matching rule (first hit), with line number."""
        if not text:
            return []
        findings: list[Finding] = []
        for rule in self.rules:
            m = rule.pattern.search(text)
            if m is None:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
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
                findings.extend(self.scan_text(text, location=os.path.basename(path)))
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
                findings.extend(self.scan_text(text, location=rel))
        return findings


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
    for rule in raw.get("rules", []) or []:
        if not isinstance(rule, dict):
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
        pack.rules.append(
            _CompiledRule(
                rule_id=rule_id,
                pattern=compiled,
                title=str(rule.get("title", "") or rule_id),
                severity=str(rule.get("severity", "MEDIUM") or "MEDIUM").upper(),
                confidence=float(rule.get("confidence", 0.0) or 0.0),
                tags=[str(t) for t in (rule.get("tags") or [])],
                category=category,
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
            pack.rules.append(
                _CompiledRule(
                    rule_id=rule_id,
                    pattern=compiled,
                    title=title,
                    severity=severity,
                    confidence=0.0,
                    tags=[tag],
                    category="local-pattern",
                )
            )


def _compile(pattern: str, rule_id: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern)
    except re.error as exc:
        _log.debug("rule-pack: invalid regex in %s (%s): %s", rule_id, exc, pattern)
        return None


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
        try:
            self._apply_overlay(result, target, kwargs)
        except Exception as exc:  # pragma: no cover - defensive
            _log.debug("rule-pack overlay failed for %r: %s", target, exc)
        return result

    def _apply_overlay(self, result, target, kwargs) -> None:
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


def maybe_wrap(inner, cfg, connector: str | None = None):
    """Wrap *inner* with the rule-pack overlay iff a rule pack is configured.

    Returns *inner* unchanged when no pack is set (or it is empty), so the common
    no-rule-pack path has zero behavior change and pays no extra disk reads.
    """
    resolved = _active_connector(cfg, connector)
    dir_path = _resolve_dir(cfg, resolved)
    if not dir_path:
        return inner
    pack = load_rule_pack(dir_path)
    if pack.is_empty():
        return inner
    return RulePackOverlayScanner(inner, pack, resolved)
