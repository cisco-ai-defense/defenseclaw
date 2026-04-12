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

"""Shared utilities for the plugin scanner.

Comment stripping, path detection, file collection, finding factory,
deduplication, and assessment computation.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from defenseclaw.scanner.plugin_scanner.rules import (
    DEPRIORITIZED_PATH_PATTERNS,
    TAXONOMY_MAP,
)
from defenseclaw.scanner.plugin_scanner.types import (
    Assessment,
    AssessmentCategory,
    Finding,
    ScanMetadata,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Scanner name
# ---------------------------------------------------------------------------

SCANNER_NAME = "defenseclaw-plugin-scanner"

# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------

MAX_EVIDENCE_LEN = 200
SECRET_REDACT_RE = re.compile(
    r"(?:AKIA|sk_live_|pk_live_|sk_test_|pk_test_|ghp_|gho_|ghu_|ghs_|ghr_|xox[bpors]-|AIza|eyJ)[A-Za-z0-9\-_+/=.]{6,}"
)


def sanitise_evidence(line: str, redact: bool = False) -> str:
    """Truncate and optionally redact a source line for use as evidence."""
    evidence = line.strip()
    if redact:
        evidence = SECRET_REDACT_RE.sub(lambda m: m.group(0)[:6] + "***REDACTED***", evidence)
    if len(evidence) > MAX_EVIDENCE_LEN:
        evidence = evidence[:MAX_EVIDENCE_LEN] + "\u2026"
    return evidence


# ---------------------------------------------------------------------------
# Comment / path helpers
# ---------------------------------------------------------------------------


def strip_comment(line: str) -> str:
    """Strip single-line comments from a line.

    Preserves strings containing "//". Avoids false-positive pattern
    matches on commented-out code.
    """
    in_string: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        prev = line[i - 1] if i > 0 else ""

        if in_string:
            if ch == in_string and prev != "\\":
                in_string = None
            i += 1
            continue

        if ch in ('"', "'", "`"):
            in_string = ch
            i += 1
            continue

        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            return line[:i].rstrip()

        i += 1

    return line


def is_comment_line(line: str) -> bool:
    """Quick check if a raw line is a single-line comment."""
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def is_test_path(rel_path: str) -> bool:
    return any(pat.search(rel_path) for pat in DEPRIORITIZED_PATH_PATTERNS)


def downgrade(severity: str) -> str:
    """Downgrade severity by one level (for test-path findings)."""
    mapping = {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM",
        "MEDIUM": "LOW",
        "LOW": "INFO",
        "INFO": "INFO",
    }
    return mapping.get(severity, severity)


# ---------------------------------------------------------------------------
# File system helpers
# ---------------------------------------------------------------------------


# Directories that are always safe to skip (build artifacts, VCS, IDE config,
# and Python virtual environments).
_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", "dist", "build", "coverage",
    ".git", ".svn", ".hg",
    ".vscode", ".idea",
    ".tox", "__pycache__", ".mypy_cache",
    "venv", ".venv", "env",
})

# Safety cap — high enough for any real plugin tree, low enough to bound cost.
_MAX_DEPTH = 20


def collect_files(
    directory: str,
    extensions: list[str],
    max_depth: int = _MAX_DEPTH,
    max_file_bytes: int = 2 * 1024 * 1024,
    _depth: int = 0,
    *,
    _scan_root: str | None = None,
    _seen_inodes: set[int] | None = None,
    _symlink_escapes: list[str] | None = None,
    _depth_truncations: list[str] | None = None,
    _oversized_files: list[str] | None = None,
) -> list[str]:
    """Recursively collect files with given extensions.

    - Symlinked dirs/files that escape *scan_root* are skipped and recorded.
    - Inode tracking prevents symlink cycles.
    - Only known-benign directories are skipped; other dot-prefixed dirs are scanned.
    - Depth limit raised to 20; truncated directories are recorded.
    - Files exceeding *max_file_bytes* are skipped and recorded in *_oversized_files*
      without being read, preventing memory exhaustion from crafted large files.
    """
    if _scan_root is None:
        _scan_root = os.path.realpath(directory)
    if _seen_inodes is None:
        _seen_inodes = set()
    if _symlink_escapes is None:
        _symlink_escapes = []
    if _depth_truncations is None:
        _depth_truncations = []

    if _depth >= max_depth:
        _depth_truncations.append(directory)
        return []

    files: list[str] = []
    try:
        entries = os.listdir(directory)
    except OSError:
        return files

    for entry in entries:
        # Skip known-benign directories only; scan other dot-prefixed dirs
        if entry in _SKIP_DIRS:
            continue

        full_path = os.path.join(directory, entry)
        try:
            # --- Symlink containment ---
            # NOTE: There is a theoretical TOCTOU race between os.path.islink()
            # and os.path.realpath(): the symlink target could change between
            # the two calls. Acceptable for static plugin scanning where the
            # directory is not modified concurrently.
            if os.path.islink(full_path):
                real = os.path.realpath(full_path)
                # Block symlinks that escape the scan root
                if not real.startswith(_scan_root + os.sep) and real != _scan_root:
                    _symlink_escapes.append(full_path)
                    continue
                # Cycle detection via inode
                try:
                    ino = os.stat(real).st_ino
                except OSError:
                    continue
                if ino in _seen_inodes:
                    continue
                _seen_inodes.add(ino)

            if os.path.isdir(full_path):
                nested = collect_files(
                    full_path,
                    extensions,
                    max_depth,
                    max_file_bytes,
                    _depth + 1,
                    _scan_root=_scan_root,
                    _seen_inodes=_seen_inodes,
                    _symlink_escapes=_symlink_escapes,
                    _depth_truncations=_depth_truncations,
                    _oversized_files=_oversized_files,
                )
                files.extend(nested)
            elif any(entry.endswith(ext) for ext in extensions):
                if max_file_bytes > 0:
                    try:
                        if os.path.getsize(full_path) > max_file_bytes:
                            if _oversized_files is not None:
                                _oversized_files.append(full_path)
                            continue
                    except OSError:
                        pass
                files.append(full_path)
        except OSError:
            continue

    return files


def check_lockfile_presence(directory: str) -> bool:
    for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        if os.path.isfile(os.path.join(directory, name)):
            return True
    return False


def dir_exists(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------


def make_finding(
    id_num: int,
    *,
    rule_id: str,
    severity: str,
    confidence: float,
    title: str,
    description: str,
    evidence: str | None = None,
    location: str | None = None,
    remediation: str | None = None,
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        id=f"plugin-{id_num}",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence=evidence,
        location=location,
        remediation=remediation,
        scanner=SCANNER_NAME,
        tags=tags or [],
        taxonomy=TAXONOMY_MAP.get(rule_id),
    )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Merge multiple hits on the same rule into one finding with occurrence_count."""
    seen: dict[str, Finding] = {}
    out: list[Finding] = []

    for f in findings:
        key = f"{f.rule_id or ''}::{f.title}"
        existing = seen.get(key)
        if existing is not None:
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = f.severity
                existing.confidence = f.confidence
                existing.location = f.location
                existing.evidence = f.evidence
        else:
            from copy import copy

            c = copy(f)
            c.tags = list(f.tags)  # shallow copy list
            c.occurrence_count = 1
            seen[key] = c
            out.append(c)

    return out


# ---------------------------------------------------------------------------
# Assessment computation
# ---------------------------------------------------------------------------

_ASSESSMENT_CATEGORIES: list[dict[str, list[str] | str]] = [
    {
        "name": "permissions",
        "tags": [],
        "rule_ids": ["PERM-DANGEROUS", "PERM-WILDCARD", "PERM-NONE", "TOOL-PERM-DANGEROUS"],
    },
    {"name": "supply-chain", "tags": ["supply-chain"], "rule_ids": []},
    {"name": "credentials", "tags": ["credential-theft"], "rule_ids": []},
    {"name": "exfiltration", "tags": ["exfiltration"], "rule_ids": []},
    {
        "name": "code-execution",
        "tags": ["code-execution"],
        "rule_ids": ["SRC-EVAL", "SRC-NEW-FUNC", "SRC-CHILD-PROC", "SRC-EXEC", "SRC-DENO-RUN", "SRC-BUN-SPAWN"],
    },
    {"name": "obfuscation", "tags": ["obfuscation"], "rule_ids": []},
    {"name": "gateway-integrity", "tags": ["gateway-manipulation"], "rule_ids": []},
    {"name": "cognitive-tampering", "tags": ["cognitive-tampering"], "rule_ids": []},
]


def _category_status(findings: list[Finding]) -> str:
    if not findings:
        return "pass"
    max_sev = 0
    for f in findings:
        rank = SEVERITY_RANK.get(f.severity, 0)
        if rank > max_sev:
            max_sev = rank
    if max_sev >= 4:
        return "fail"
    if max_sev >= 3:
        return "warn"
    return "info"


_SEV_SORT_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def compute_assessment(findings: list[Finding]) -> Assessment:
    categories: list[AssessmentCategory] = []

    for cat in _ASSESSMENT_CATEGORIES:
        cat_tags: list[str] = cat["tags"]  # type: ignore[assignment]
        cat_rule_ids: list[str] = cat["rule_ids"]  # type: ignore[assignment]

        relevant = [
            f for f in findings if (f.rule_id or "") in cat_rule_ids or any(t in (f.tags or []) for t in cat_tags)
        ]
        status = _category_status(relevant)

        if not relevant:
            summary = "No issues detected."
        else:
            counts: dict[str, int] = {}
            for f in relevant:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            parts = sorted(counts.items(), key=lambda x: _SEV_SORT_ORDER.get(x[0], 5))
            parts_str = ", ".join(f"{count} {sev}" for sev, count in parts)
            n = len(relevant)
            summary = f"{n} finding{'s' if n > 1 else ''}: {parts_str}."

        categories.append(
            AssessmentCategory(
                name=cat["name"],  # type: ignore[arg-type]
                status=status,
                summary=summary,
            )
        )

    has_critical = any(f.severity == "CRITICAL" for f in findings)
    has_high = any(f.severity == "HIGH" for f in findings)
    has_medium = any(f.severity == "MEDIUM" for f in findings)
    max_confidence = max((f.confidence or 0 for f in findings), default=0)

    if has_critical:
        verdict = "malicious"
        confidence = min(max_confidence, 0.95)
        n_crit = sum(1 for f in findings if f.severity == "CRITICAL")
        summary = f"Plugin has {n_crit} critical finding(s) indicating likely malicious behaviour."
    elif has_high:
        verdict = "suspicious"
        confidence = min(max_confidence, 0.85)
        n_high = sum(1 for f in findings if f.severity == "HIGH")
        summary = f"Plugin has {n_high} high-severity finding(s) requiring review."
    elif has_medium:
        verdict = "suspicious"
        confidence = min(max_confidence, 0.6)
        n_med = sum(1 for f in findings if f.severity == "MEDIUM")
        summary = f"Plugin has {n_med} medium-severity finding(s). Review recommended."
    elif findings:
        verdict = "benign"
        confidence = 0.8
        summary = "Plugin has only low/informational findings."
    else:
        verdict = "benign"
        confidence = 0.9
        summary = "No security issues detected."

    return Assessment(
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        categories=categories,
    )


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------


def build_result(
    target: str,
    findings: list[Finding],
    start_ms: float,
    metadata: ScanMetadata | None = None,
) -> ScanResult:
    import time

    elapsed_ms = time.time() * 1000 - start_ms
    return ScanResult(
        scanner=SCANNER_NAME,
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        duration_ns=int(elapsed_ms * 1_000_000),
        metadata=metadata,
        assessment=compute_assessment(findings),
    )
