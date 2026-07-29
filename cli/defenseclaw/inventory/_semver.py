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
"""Semantic-version parsing and comparison shared across the CLI.

Lifted from scripts/connector-version-radar.py so agent_discovery.py can
pick "highest supported version" among multiple installed copies of a
connector (Claude Code / Codex / Cursor) without cross-importing a
top-level script. Precomparison is strict semver 2.0 for the parts we
care about: major.minor.patch plus dot-separated prerelease
identifiers, ignoring build metadata.

Only three public entry points intentionally: parse_version() to build a
SemVersion from an arbitrary CLI / package.json string, SemVersion.compare()
to totally order two of them, and pick_highest_supported() to select the
best candidate from a list given a minimum inclusive bound.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable
from functools import cmp_to_key

# Matches the first "x.y.z(-prerelease)?(+build)?" substring in a
# larger string so we tolerate outputs like "codex-cli 0.145.0" or
# "1.9.0 (build 42)".
#
# scripts/connector-version-radar.py maintains its OWN copy of this
# regex (see `_VERSION_RE` there). The radar is a standalone script
# invoked outside the `defenseclaw` package import path (macOS lab
# runners, cron jobs); making it import from this module would drag
# the whole CLI dependency tree into every invocation. If either copy
# ever diverges, the drift-guard test
# ``test_semver_regex_matches_across_files`` in
# ``cli/tests/test_agent_discovery.py`` trips — keep both definitions
# byte-for-byte identical.
_VERSION_RE = re.compile(
    r"(?<![0-9A-Za-z])v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?(?![0-9A-Za-z])"
)


@dataclasses.dataclass(frozen=True)
class SemVersion:
    """A parsed semantic-version triple with optional prerelease chain."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @property
    def stable(self) -> bool:
        return not self.prerelease

    @property
    def normalized(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            return f"{base}-{'.'.join(self.prerelease)}"
        return base

    def compare(self, other: SemVersion) -> int:
        own_core = (self.major, self.minor, self.patch)
        other_core = (other.major, other.minor, other.patch)
        if own_core != other_core:
            return 1 if own_core > other_core else -1
        # Per semver 2.0 §11: a version with prerelease has lower
        # precedence than one without.
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        # Compare prerelease identifiers pairwise. Numeric identifiers
        # order numerically; alphanumeric order lexically; numeric <
        # alphanumeric when they collide.
        for own, theirs in zip(self.prerelease, other.prerelease, strict=False):
            if own == theirs:
                continue
            own_numeric = own.isdigit()
            theirs_numeric = theirs.isdigit()
            if own_numeric and theirs_numeric:
                return 1 if int(own) > int(theirs) else -1
            if own_numeric != theirs_numeric:
                return -1 if own_numeric else 1
            return 1 if own > theirs else -1
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return 1 if len(self.prerelease) > len(other.prerelease) else -1


def parse_version(value: str, *, require_stable: bool = False) -> SemVersion:
    """Extract and normalize the first semantic version in ``value``.

    Raises ValueError when no x.y.z substring is present or when
    ``require_stable`` is set and the parsed value carries a prerelease
    tail. Callers that just want "best-effort or None" should use
    ``parse_version_or_none``.
    """
    match = _VERSION_RE.search(value.strip())
    if not match:
        raise ValueError("no semantic x.y.z version found")
    prerelease = tuple(filter(None, (match.group("prerelease") or "").split(".")))
    parsed = SemVersion(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
        prerelease=prerelease,
    )
    if require_stable and not parsed.stable:
        raise ValueError(f"stable channel returned prerelease {parsed.normalized}")
    return parsed


def parse_version_or_none(value: str) -> SemVersion | None:
    """Best-effort variant of ``parse_version`` — returns None on any parse error."""
    try:
        return parse_version(value)
    except ValueError:
        return None


def pick_highest_supported(
    candidates: Iterable[tuple[str, str]],
    min_inclusive: str,
) -> tuple[str, str] | None:
    """Select the "best" (source, version) tuple from ``candidates``.

    Selection policy (used by the hook installer's discovery pass):

    1. Parse every candidate; drop entries whose version string is
       not semver-shaped.
    2. Prefer the highest version that is >= ``min_inclusive``.
    3. If no candidate meets the minimum, fall back to the highest
       version overall so the operator debugging the "why weren't
       hooks installed" case sees an actual version in the discovery
       cache (and the Go hook-contract gate reports "unsupported"
       rather than "unversioned").

    Returns ``None`` when ``candidates`` is empty or nothing parsed.
    The returned tuple's ``source`` field is verbatim from the input
    so callers can render it in ``agent_discovery.json`` /
    ``defenseclaw agent discover --json``.
    """
    parsed: list[tuple[str, str, SemVersion]] = []
    for source, raw in candidates:
        version = parse_version_or_none(raw)
        if version is None:
            continue
        parsed.append((source, raw, version))
    if not parsed:
        return None

    minimum = parse_version_or_none(min_inclusive) if min_inclusive else None

    supported = [entry for entry in parsed if minimum is None or entry[2].compare(minimum) >= 0]
    pool = supported or parsed
    # Stable sort so ties on version pick the first source (which is
    # the order the collector visited candidate roots — usually
    # native-installer > npm globals > NVM > editor extensions). We
    # sort via cmp_to_key because SemVersion is a plain frozen
    # dataclass and doesn't implement __lt__.
    pool.sort(key=cmp_to_key(lambda a, b: a[2].compare(b[2])))
    best = pool[-1]  # highest after ascending sort
    for entry in reversed(pool):
        if entry[2].compare(best[2]) == 0:
            best = entry
        else:
            break
    return best[0], best[1]
