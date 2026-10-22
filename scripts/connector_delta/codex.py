# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Codex-specific indicators, static contracts and pinned evidence extraction."""

import difflib
import re

REPOSITORY = "openai/codex"
CONTRACT_FILES = ()
CONSUMER_ANCHORS = (
    (r'ToolUseID\s+string|"permissionDecision":\s*"deny"', 2),
    (r"ToolUseID|permissionDecision|behavior", 2),
    (r"features\[", 2),
    (r"SessionStart.*startup|group\.matcher\s*=", 2),
    (r'^\s*state\[key\]\s*=.*"trusted_hash"', 2),
    (r"^func codexUsesManagedHookLayer", 4),
    (r"normalizedHandler :=", 17),
    (r"^func codexVersionForTOML", 4),
    (r"^func codexCanonicalJSON", 8),
    (r'"async".*false', 2),
    (r"requirements\.toml|SystemRequirementsPath", 2),
    (r'hookScript := filepath.Join\(hookDir, "codex-hook.sh"\)', 23),
    (r"\bSessionID:\s*req.SessionID", 10),
)


def extra_indicator(patch):
    # A hook request's type can be unchanged context while its identity/input fields change.
    return "codex_hooks::" in patch and any(
        re.search(r"\bcodex_hooks::\w+Request\s*\{", hunk)
        and re.search(
            r"(?m)^[+-][ \t]*(?:session_id|turn_id|cwd|transcript_path|tool_name|tool_input|tool_response)[ \t]*:",
            hunk,
        )
        for hunk in re.split(r"(?m)^@@", patch)
    )


def node(schema, keys):
    for key in keys:
        if not isinstance(schema, dict):
            return {}
        properties = schema.get("properties", {})
        schema = properties.get(key, {}) if isinstance(properties, dict) else {}
    return schema if isinstance(schema, dict) else {}


def static_conflicts(changes, contract, context, spec, decode):
    """Small checks only. Unsupported schemas/source semantics remain review."""
    found = []
    for change in changes:
        path, before, after = change["path"], change["before"], change["after"]
        if path in spec.get("input_schemas", []) and before and after:
            old_schema, new_schema = decode(before), decode(after)
            if not all(isinstance(value, dict) and value.get("type") == "object" for value in (old_schema, new_schema)):
                continue  # Property constraints on a non-object schema do not prove an incoming field type.
            old_field = node(old_schema, ["tool_use_id"])
            new_field = node(new_schema, ["tool_use_id"])
            local = re.sub(r"/\*[\s\S]*?\*/", "", context[spec["local_files"][0]])
            anchor = re.search(r"(?m)^\d+:\s*ToolUseID\s+string\s+`json:\"tool_use_id", local)
            if (
                anchor
                and set(old_field) <= {"type", "description", "title"}
                and set(new_field) <= {"type", "description", "title"}
                and old_field.get("type") == "string"
                and new_field.get("type") in ("integer", "number", "object", "array", "boolean")
            ):
                found.append(
                    {
                        "invariant": "payload/correlation",
                        "path": path,
                        "reason": "tool_use_id no longer has the string type consumed by the local decoder",
                    }
                )
        if path in spec.get("output_schemas", []) and before and after:
            keys = ["hookSpecificOutput", "permissionDecision"]
            old_schema, new_schema = decode(before), decode(after)
            # JSON Schema properties do not constrain non-object instances. Do not
            # promote a keyword match inside a conditional/alternative schema to proof.
            if not all(
                isinstance(schema, dict)
                and schema.get("type", "object") == "object"
                and node(schema, ["hookSpecificOutput"]).get("type", "object") == "object"
                for schema in (old_schema, new_schema)
            ):
                continue
            old, new = node(old_schema, keys), node(new_schema, keys)
            emitted = any(
                re.search(r'(?m)^\d+:\s*"permissionDecision":\s*"deny",?\s*$', text) for text in context.values()
            )
            simple = all(set(field) <= {"type", "enum", "description", "title"} for field in (old, new))
            if (
                emitted
                and simple
                and old.get("type") == new.get("type") == "string"
                and isinstance(old.get("enum"), list)
                and isinstance(new.get("enum"), list)
                and "deny" in old.get("enum", [])
                and new.get("enum")
                and "deny" not in new["enum"]
            ):
                found.append(
                    {
                        "invariant": "decision",
                        "path": path,
                        "reason": "the response schema newly rejects our emitted deny value",
                    }
                )
    return found


def upstream_support(spec, changes, parent, revision, read_source):
    """Follow one narrow producer -> event -> filter chain; never execute upstream code."""
    lifecycle = any(
        c["path"] == "codex-rs/core/src/session/session.rs"
        and any(
            line.startswith(("+", "-")) and "SessionStartSource::" in line
            for line in difflib.unified_diff(c["before"].splitlines(), c["after"].splitlines())
        )
        for c in changes
    )
    identity = any(
        re.search(
            r"(?m)^\+.*\bsession_id\s*:.*\.session_id\(\)",
            "\n".join(difflib.unified_diff(c["before"].splitlines(), c["after"].splitlines())),
        )
        for c in changes
    )
    support = {}
    selectors = (
        [
            (
                "codex-rs/hooks/src/events/session_start.rs",
                r"(?:pub enum SessionStartSource|pub fn as_str|fn matcher_input|pub\(crate\) async fn run)\b",
            ),
            (
                "codex-rs/hooks/src/events/common.rs",
                r"(?:pub\(crate\) fn matches_matcher|fn is_(?:exact|match_all)_matcher)\b",
            ),
            ("codex-rs/hooks/src/engine/dispatcher.rs", r"pub\(crate\) fn select_handlers(?:_for_matcher_inputs)?\b"),
        ]
        if lifecycle
        else []
    )
    if identity:
        selectors += [
            ("codex-rs/core/src/session/session.rs", r"pub\(crate\) fn (?:thread_id|session_id)\b"),
            ("codex-rs/core/src/agent/control.rs", r"pub\(crate\) fn (?:with_session_id|session_id)\b"),
            (
                "codex-rs/protocol/src/session_id.rs",
                r"impl From<(?:ThreadId|SessionId)> for (?:String|ThreadId|SessionId)\b",
            ),
        ]
    if availability_witnesses(changes):
        selectors.append(("codex-rs/hooks/src/engine/mod.rs", r"pub\(crate\) fn new\b"))
    if any(re.search(r"\b(?:version_for_toml|trusted_hash)\b", c["before"] + c["after"]) for c in changes):
        selectors.append(("codex-rs/config/src/fingerprint.rs", r"(?:pub fn version_for_toml|fn canonical_json)\b"))
    for path, pattern in selectors:
        support[path] = {}
        for side, sha in (("before", parent), ("after", revision)):
            try:
                lines = read_source(sha, path).split("#[cfg(test)]")[0].splitlines()
            except FileNotFoundError:
                continue  # Unsupported source layout is missing evidence, never a compatibility verdict.
            indices = set()
            for n, line in enumerate(lines):
                if re.search(pattern, line):
                    indent = line[: len(line) - len(line.lstrip())]
                    end = next((i for i in range(n + 1, min(len(lines), n + 250)) if lines[i] == indent + "}"), None)
                    if end is not None:
                        indices.update(range(n, end + 1))  # Whole rustfmt-formatted blocks, not arbitrary windows.
            excerpt = "\n".join(f"{i + 1}: {lines[i]}" for i in sorted(indices))
            support[path][side] = excerpt if len(indices) <= 240 and len(excerpt) <= 16000 else ""
    for change in changes:
        if lifecycle and change["path"] == "codex-rs/core/src/session/session.rs":
            support.setdefault(change["path"], {})
            for side in ("before", "after"):
                lines = change[side].splitlines()
                indices = sorted(
                    {
                        i
                        for n, line in enumerate(lines)
                        if re.search(r"let forked_from_id\s*=|queue_pending_session_start_source\(", line)
                        for i in range(n, min(len(lines), n + 5))
                    }
                )[:20]
                support[change["path"]][side] = (
                    support[change["path"]].get(side, "") + "\n" + "\n".join(f"{i + 1}: {lines[i]}" for i in indices)
                )
    return support


def availability_witnesses(changes):
    """Narrow high-recall indicator; a second judge must establish actual consumer loss."""
    pattern = re.compile(r"if cfg!\((windows|unix)\)\s*\{\s*return Self\s*\{\s*handlers:\s*Vec::new\(\),")
    return [
        {"path": c["path"], "os": match[1], "change": "New OS-specific early return with no hook handlers."}
        for c in changes
        if c["path"] == "codex-rs/hooks/src/engine/mod.rs"
        for match in pattern.finditer(c["after"])
        if match[0] not in c["before"]
    ]


def literal_source_witnesses(changes, context, support):
    """Finite literal comparison, not a Rust interpreter or a runtime break verdict."""
    local = context.get("internal/gateway/connector/codex.go", "")
    matchers = set(re.findall(r'"SessionStart"\s*,\s*"([a-z_|]+)"', local))
    matchers.update(re.findall(r'if eventType == "SessionStart"[\s\S]{0,350}?group\.matcher\s*=\s*"([a-z_|]+)"', local))
    protocol = support.get("codex-rs/hooks/src/events/session_start.rs", {})
    wire = {
        side: dict(re.findall(r'Self::(\w+)\s*=>\s*"([a-z_]+)"', protocol.get(side, "")))
        for side in ("before", "after")
    }
    witnesses = []
    arm = re.compile(
        r"((?:InitialHistory::\w+(?:\(_\))?\s*\|\s*)*InitialHistory::\w+(?:\(_\))?)"
        r"(?:\s+if\s+([^=\n]+))?\s*=>\s*\{?\s*codex_hooks::SessionStartSource::(\w+)"
    )
    for change in changes:
        if change["path"] != "codex-rs/core/src/session/session.rs":
            continue
        bodies = [
            re.findall(r"let session_start_source = match &initial_history \{([\s\S]*?)\n\s*\};", change[s])
            for s in ("before", "after")
        ]
        if any(len(body) != 1 for body in bodies):
            continue
        old, new = [list(arm.finditer(re.sub(r"/\*[\s\S]*?\*/|//[^\n]*", "", body[0]))) for body in bodies]
        for after in new:
            cases = set(re.split(r"\s*\|\s*", after[1]))
            for before in old:
                if before[2] or not cases <= set(re.split(r"\s*\|\s*", before[1])) or before[3] == after[3]:
                    continue
                for matcher in sorted(matchers):
                    old_value, new_value = wire["before"].get(before[3]), wire["after"].get(after[3])
                    if (
                        old_value
                        and new_value
                        and old_value in matcher.split("|")
                        and new_value not in matcher.split("|")
                    ):
                        witnesses.append(
                            {
                                "cases": sorted(cases),
                                "before_variant": before[3],
                                "after_variant": after[3],
                                "after_guard": after[2] or "",
                                "local_matcher": matcher,
                                "scope": "Existing case changes literal source; verify dispatch in supplied support.",
                            }
                        )
    return witnesses


def requires_semantic_review(changes, runtime):
    """Withhold a routine verdict when these Codex semantics remain unresolved."""
    return any(
        re.search(
            r"^[+-](?![+-]).*(?:\bSessionStartSource::|\bRequirementsPath\b|\bhandlers\s*:\s*Vec::new\(\))",
            line,
        )
        or (
            re.search(r"^[+-](?![+-]).*\bsession_id\s*:", line)
            and (extra_indicator(delta) or re.search(r"(?:^|[/_])hooks?(?:[/_.]|$)", c["path"]))
        )
        for c in changes
        if c["path"] in runtime
        for delta in ["\n".join(difflib.unified_diff(c["before"].splitlines(), c["after"].splitlines()))]
        for line in delta.splitlines()
    ) or bool(availability_witnesses(changes))
