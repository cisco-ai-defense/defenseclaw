# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Claude Code-specific public artifacts and explicit path-retirement check."""

import re

REPOSITORY = "anthropics/claude-code"
CONTRACT_FILES = ("CHANGELOG.md",)
CONSUMER_ANCHORS = (
    (r'ToolUseID\s+string|"permissionDecision":\s*"deny"', 2),
    (r"ToolUseID|permissionDecision|behavior", 2),
    (r"features\[", 2),
    (r"SessionStart.*startup|group\.matcher\s*=", 2),
    (r'^\s*state\[key\]\s*=.*"trusted_hash"', 2),
    (r"normalizedHandler :=", 17),
    (r'"async".*false', 2),
    (r"requirements\.toml|SystemRequirementsPath", 2),
    (r"\bSessionID:\s*req.SessionID", 10),
)


def static_conflicts(changes, contract, context, spec, decode):
    """Only an explicit, unqualified retirement of a currently registered path."""
    found = []
    for change in changes:
        path, before, after = change["path"], change["before"], change["after"]
        if path == "CHANGELOG.md" and before and after:
            previous_lines, fenced, scoped = set(before.splitlines()), False, False
            for line in after.splitlines():
                if re.match(r"^\s*(?:```|~~~)", line):
                    fenced = not fenced
                if not fenced and re.match(r"^#{1,6} ", line):
                    scoped = not bool(re.match(r"^#{1,6} (?:Changelog\b|\d+\.\d+\.\d+\b)", line, re.I))
                if line in previous_lines:
                    continue
                match = re.fullmatch(r"(?:- )?Hooks are no longer read from `([^`]+)`\.", line)
                if match and not scoped and not fenced and match[1] in contract["hook_config_path_templates"]:
                    found.append(
                        {
                            "invariant": "discovery",
                            "path": path,
                            "reason": "an explicit upstream statement retires a path in our current hook contract",
                        }
                    )
    return found
