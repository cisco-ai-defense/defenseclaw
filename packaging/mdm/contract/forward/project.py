#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# SPDX-License-Identifier: Apache-2.0

"""Reference projection of a DefenseClaw management document through its
forward schema (management-agent.md, "What to forward").

Projection is allowlist-and-drop: a member the forward schema does not list
is removed, and so is a value that does not fit its schema (a string outside
its pattern or enum, a number of the wrong type). Nothing is rejected, so a
member a newer DefenseClaw adds never breaks the sender; it is simply not
forwarded until a forward schema lists it.

Standard library only:

    python3 project.py <forward-schema.json> < document.json > forwardable.json
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

DROP = object()


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"forward schemas use local references only: {ref}")
        schema = root["$defs"][ref[len("#/$defs/"):]]
    return schema


def _string(value: str, schema: dict[str, Any]) -> Any:
    if "const" in schema and value != schema["const"]:
        return DROP
    if "enum" in schema and value not in schema["enum"]:
        return DROP
    if "pattern" in schema and not re.search(schema["pattern"], value):
        return DROP
    if not any(key in schema for key in ("const", "enum", "pattern")):
        return DROP
    return value


def project_value(value: Any, schema: dict[str, Any], root: dict[str, Any]) -> Any:
    """Project value through schema; DROP when nothing of it may be sent."""
    schema = _resolve(schema, root)
    kind = schema.get("type")
    if "const" in schema:
        return value if value == schema["const"] and type(value) is type(schema["const"]) else DROP
    if kind == "object" or "properties" in schema:
        if not isinstance(value, dict):
            return DROP
        out: dict[str, Any] = {}
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties")
        names = schema.get("propertyNames", {}).get("pattern")
        for key, member in value.items():
            if key in properties:
                projected = project_value(member, properties[key], root)
            elif isinstance(extra, dict) and names and re.search(names, key):
                projected = project_value(member, extra, root)
            else:
                continue
            if projected is not DROP:
                out[key] = projected
        return out
    if kind == "array":
        if not isinstance(value, list):
            return DROP
        items = schema.get("items", {})
        out_list = [p for p in (project_value(item, items, root) for item in value) if p is not DROP]
        limit = schema.get("maxItems")
        return out_list[:limit] if limit is not None else out_list
    if kind == "string":
        return _string(value, schema) if isinstance(value, str) else DROP
    if kind == "boolean":
        return value if isinstance(value, bool) else DROP
    if kind == "integer":
        return value if isinstance(value, int) and not isinstance(value, bool) else DROP
    if "enum" in schema:
        return value if value in schema["enum"] else DROP
    return DROP


def project(document: Any, schema: dict[str, Any]) -> Any:
    """Project a whole document; an unsendable document projects to {}."""
    projected = project_value(document, schema, schema)
    return {} if projected is DROP else projected


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: project.py <forward-schema.json> < document.json", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        schema = json.load(handle)
    document = json.load(sys.stdin)
    json.dump(project(document, schema), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
