"""MCP Scanner's small ``yara-python`` API subset backed by YARA-X.

This module is packaged only in DefenseClaw's native Windows runtime.
It deliberately implements the exact surface used by cisco-ai-mcp-scanner
4.3.0 instead of claiming general yara-python compatibility.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yara_x

__defenseclaw_yarax_compat__ = True
__version__ = "4.5.4.post1"


class Error(Exception):
    """Translate YARA-X compile/scan failures to yara-python's base error."""


@dataclass(frozen=True, slots=True)
class Match:
    """The match fields consumed by MCP Scanner 4.3.0."""

    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]


class Rules:
    """Compiled YARA-X rules exposing yara-python's ``match(data=...)``."""

    def __init__(self, rules: yara_x.Rules) -> None:
        self._rules = rules

    def match(self, *, data: str | bytes | bytearray | memoryview) -> list[Match]:
        if isinstance(data, str):
            scan_data = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            scan_data = bytes(data)
        else:
            raise TypeError("data must be str or bytes-like")

        try:
            results = self._rules.scan(scan_data)
        except (yara_x.ScanError, yara_x.TimeoutError) as exc:
            raise Error(str(exc)) from exc

        return [
            Match(
                rule=rule.identifier,
                namespace=rule.namespace,
                tags=tuple(rule.tags),
                meta=dict(rule.metadata),
            )
            for rule in results.matching_rules
        ]


def compile(*, sources: Mapping[str, str]) -> Rules:
    """Compile a yara-python ``sources`` mapping with namespace fidelity."""

    if not isinstance(sources, Mapping):
        raise TypeError("sources must be a mapping of namespace to source text")

    compiler = yara_x.Compiler()
    try:
        for namespace, source in sources.items():
            if not isinstance(namespace, str) or not isinstance(source, str):
                raise TypeError("source namespaces and text must be strings")
            compiler.new_namespace(namespace)
            compiler.add_source(source, origin=namespace)
        return Rules(compiler.build())
    except yara_x.CompileError as exc:
        raise Error(str(exc)) from exc


__all__ = ["Error", "Match", "Rules", "compile"]
