#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Check that every installed distribution's requirements are met.

This is ``pip check`` / ``uv pip check`` for DefenseClaw's managed Python
environments, with one allowance (GAP-0020): MCP Scanner 4.8.7 pins
``litellm==1.93.2``, which carries GHSA-w4c7-34wj-hqm8, GHSA-g5ff-637f-6q2m
and CVE-2026-114612. DefenseClaw overrides that pin (``[tool.uv]
override-dependencies`` in pyproject.toml), and every installer installs the
complete hash-pinned lock with ``--no-deps``, so the environment holds the
secure LiteLLM instead. The allowance covers only that distribution
version, that requirement, and an installed LiteLLM inside DefenseClaw's
secure range; any other unmet requirement still fails.

TODO(mcp-scanner 4.8.8): cisco-ai-defense/mcp-scanner#295 relaxes the pin.
Once DefenseClaw pins a release that admits the secure LiteLLM, empty
ALLOWED_OVERRIDES and this is a plain dependency check again.

Usage: python -I check_python_dependency_metadata.py [--path SITE_PACKAGES ...]
Exit 0 when consistent, 1 with one line per problem otherwise.
"""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import platform
import sys

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

# (distribution, its exact version, the requirement it declares) ->
# the range the installed package must be in for the override to stand.
ALLOWED_OVERRIDES: dict[tuple[str, str, str], tuple[str, str]] = {
    ("cisco-ai-mcp-scanner", "4.8.7", "litellm==1.93.2"): ("litellm", ">=1.103.10,<1.104.0"),
}


def _environment(extra: str = "") -> dict[str, str]:
    return {"extra": extra}


def problems(paths: list[str] | None = None) -> list[str]:
    dists = list(metadata.distributions(path=paths) if paths else metadata.distributions())
    installed: dict[str, str] = {}
    for dist in dists:
        name = dist.metadata.get("Name")
        if name:
            installed.setdefault(canonicalize_name(name), dist.version)
    found: list[str] = []
    python_version = platform.python_version()
    for dist in dists:
        name = dist.metadata.get("Name")
        if not name:
            continue
        requires_python = dist.metadata.get("Requires-Python")
        if requires_python and not SpecifierSet(requires_python).contains(python_version, prereleases=True):
            found.append(f"{name} {dist.version}: Python {python_version} violates Requires-Python {requires_python}")
        for raw in dist.requires or ():
            try:
                requirement = Requirement(raw)
            except InvalidRequirement:
                found.append(f"{name} {dist.version}: unparsable requirement {raw!r}")
                continue
            if requirement.marker and not requirement.marker.evaluate(_environment()):
                continue
            key = canonicalize_name(requirement.name)
            version = installed.get(key)
            if version is None:
                found.append(f"{name} {dist.version}: missing {requirement.name}")
                continue
            if not requirement.specifier or requirement.specifier.contains(version, prereleases=True):
                continue
            declared = f"{key}{requirement.specifier}"
            allowed = ALLOWED_OVERRIDES.get((canonicalize_name(name), dist.version, declared))
            if allowed and allowed[0] == key and SpecifierSet(allowed[1]).contains(version, prereleases=True):
                continue
            found.append(f"{name} {dist.version}: {requirement.name} {version} violates {requirement.specifier}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--path", action="append", help="site-packages folder to check (default: this interpreter)")
    args = parser.parse_args(argv)
    found = problems(args.path)
    for line in found:
        print(line, file=sys.stderr)
    if not found:
        print("dependency metadata ok")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
