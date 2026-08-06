# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-OS connector support — the Python single source of truth.

Windows support is not a boolean derived from connector topology.  A native
agent/runtime and a DefenseClaw integration that can be wired without WSL are
both required. The resulting status is one of ``supported``, ``preview``,
``not_certified``, or ``unsupported`` and always carries a reason.

DefenseClaw runs hook-only on Windows: most agents invoke the native Go hook
entrypoint directly. Cursor invokes a native PowerShell adapter first because
its Windows command-hook transport materializes stdin as PowerShell pipeline
objects. There is no Windows guardrail-proxy lifecycle. The proxy/chat
connectors (``openclaw`` and ``zeptoclaw``) therefore cannot run on Windows,
so the TUI/CLI must not offer or accept them there.

This module mirrors ``internal/gateway/connector/platform_support.go``.  Tests
pin the two taxonomies and all Python presentation lists together.  macOS and
Linux retain their historical behavior: every built-in and plugin connector is
offered there.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

SupportStatus = Literal["supported", "preview", "not_certified", "unsupported"]

SUPPORTED: SupportStatus = "supported"
PREVIEW: SupportStatus = "preview"
NOT_CERTIFIED: SupportStatus = "not_certified"
UNSUPPORTED: SupportStatus = "unsupported"

PROXY_CONNECTORS: frozenset[str] = frozenset({"openclaw", "zeptoclaw"})

LOCAL_OBSERVABILITY_UNSUPPORTED_REASON = "Bundled local observability is unavailable on this operating system."
LOCAL_SPLUNK_UNSUPPORTED_REASON = "Bundled Local Splunk is unavailable on this operating system."
# Compatibility name retained for callers that predate the native controller.
LOCAL_SHELL_STACKS_UNSUPPORTED_REASON = LOCAL_SPLUNK_UNSUPPORTED_REASON


@dataclass(frozen=True)
class ConnectorPlatformSupport:
    """Support classification for one connector on one operating system."""

    status: SupportStatus
    reason: str

    @property
    def available(self) -> bool:
        """Whether setup/presentation may offer this connector."""
        return self.status in {SUPPORTED, PREVIEW}


# Keep in exact parity with the Go ``windowsConnectorSupport`` map. A working
# upstream Windows binary is not sufficient for DefenseClaw certification.
WINDOWS_CONNECTOR_SUPPORT: dict[str, ConnectorPlatformSupport] = {
    "codex": ConnectorPlatformSupport(
        SUPPORTED,
        "Codex CLI and the DefenseClaw hook entrypoint are supported on native "
        "Windows x64; authentic packaged plus official-client validation metadata "
        "is not recorded and live evidence remains false.",
    ),
    "claudecode": ConnectorPlatformSupport(
        SUPPORTED,
        "Claude Code and the DefenseClaw native executable hook entrypoint are "
        "supported on native Windows x64; immutable packaged plus official-client "
        "validation metadata is not recorded and live evidence remains false.",
    ),
    "cursor": ConnectorPlatformSupport(
        SUPPORTED,
        "Cursor Agent and the DefenseClaw PowerShell hook adapter are available "
        "on native Windows x64; official-client validation metadata is not recorded "
        "and live evidence remains false.",
    ),
    "windsurf": ConnectorPlatformSupport(
        SUPPORTED,
        "Legacy Cascade-only hooks and the native PowerShell adapter are supported on Windows x64. "
        "Devin Local (the current default), its separate lifecycle hooks, cloud, ACP, and managed higher-layer "
        "enforcement are not covered; packaged and official-client validation metadata is not recorded.",
    ),
    "geminicli": ConnectorPlatformSupport(
        UNSUPPORTED,
        "Gemini CLI native Windows support is excluded from this release because "
        "the intended product and audience path was discontinued; existing "
        "non-Windows support is unchanged.",
    ),
    "copilot": ConnectorPlatformSupport(
        SUPPORTED,
        "The DefenseClaw GitHub Copilot CLI integration is supported on native Windows x64; "
        "authentication, HITL, and official-client live evidence remain unverified and unclaimed.",
    ),
    "antigravity": ConnectorPlatformSupport(
        SUPPORTED,
        "The Antigravity integration is supported on native Windows x64; authentication, HITL, "
        "and official-client live evidence remain unverified and unclaimed.",
    ),
    "opencode": ConnectorPlatformSupport(
        SUPPORTED,
        "OpenCode native Windows setup is supported; official-client validation "
        "metadata is not recorded and live evidence remains false. OpenCode recommends WSL but does "
        "not require it.",
    ),
    "amp": ConnectorPlatformSupport(
        SUPPORTED,
        "Amp and the DefenseClaw system policy plugin are supported on native Windows x64.",
    ),
    "hermes": ConnectorPlatformSupport(
        SUPPORTED,
        "Hermes native shell hooks use a direct DefenseClaw executable; "
        "packaged and official-client Windows x64 validation metadata is not recorded, "
        "running-client state remains pending reload, and live evidence remains false.",
    ),
    "openhands": ConnectorPlatformSupport(
        UNSUPPORTED,
        "OpenHands CLI requires WSL; DefenseClaw does not implement a WSL connector path.",
    ),
    "omnigent": ConnectorPlatformSupport(
        SUPPORTED,
        "OmniGent 0.7.0 is supported on native Windows in degraded mode; "
        "DefenseClaw uses its awaited in-process policy API "
        "without terminal wrapping or filesystem/network sandbox parity.",
    ),
    "openclaw": ConnectorPlatformSupport(
        UNSUPPORTED,
        "DefenseClaw on Windows is hook-only; OpenClaw integration requires the guardrail proxy.",
    ),
    "zeptoclaw": ConnectorPlatformSupport(
        UNSUPPORTED,
        "ZeptoClaw publishes macOS/Linux builds and its DefenseClaw integration requires the guardrail proxy.",
    ),
}

WINDOWS_SUPPORTED_CONNECTORS: frozenset[str] = frozenset(
    name for name, support in WINDOWS_CONNECTOR_SUPPORT.items() if support.status == SUPPORTED
)
WINDOWS_PREVIEW_CONNECTORS: frozenset[str] = frozenset(
    name for name, support in WINDOWS_CONNECTOR_SUPPORT.items() if support.status == PREVIEW
)
WINDOWS_NOT_CERTIFIED_CONNECTORS: frozenset[str] = frozenset(
    name for name, support in WINDOWS_CONNECTOR_SUPPORT.items() if support.status == NOT_CERTIFIED
)
WINDOWS_UNSUPPORTED_CONNECTORS: frozenset[str] = frozenset(
    name for name, support in WINDOWS_CONNECTOR_SUPPORT.items() if support.status == UNSUPPORTED
)

WINDOWS_CERTIFIED_ARCHITECTURES: frozenset[str] = frozenset({"amd64"})
WINDOWS_NOT_CERTIFIED_ARCHITECTURES: frozenset[str] = frozenset({"arm64"})
WINDOWS_UNSUPPORTED_FEATURES: frozenset[str] = frozenset(
    {
        "sandbox",
        "enterprise-hooks",
        "openhands",
        "omnigent-terminal-sandbox",
        "openclaw",
        "zeptoclaw",
    }
)


def host_os() -> str:
    """Return a Go-``GOOS``-style token for the current host."""
    return _normalize_os_name(sys.platform)


def _normalize_os_name(os_name: str) -> str:
    value = (os_name or "").strip().lower()
    if value.startswith("win"):
        return "windows"
    if value == "darwin":
        return "darwin"
    if value.startswith("linux"):
        return "linux"
    return value


def is_proxy_connector(name: str) -> bool:
    """Report whether *name* is a proxy/chat connector."""
    return name in PROXY_CONNECTORS


def connector_platform_support(
    name: str,
    os_name: str | None = None,
) -> ConnectorPlatformSupport:
    """Return the status and reason for *name* on *os_name*.

    Unknown/plugin connectors require separate native Windows certification.
    macOS and Linux preserve their historical supported behavior.
    """
    resolved_os = host_os() if os_name is None else _normalize_os_name(os_name)
    if resolved_os == "windows":
        return WINDOWS_CONNECTOR_SUPPORT.get(
            name,
            ConnectorPlatformSupport(
                NOT_CERTIFIED,
                "This connector has not completed native Windows x64 certification.",
            ),
        )
    return ConnectorPlatformSupport(
        SUPPORTED,
        f"Connector setup is supported on {resolved_os or 'this platform'}.",
    )


def connector_support_status(name: str, os_name: str | None = None) -> SupportStatus:
    """Return only the support status for presentation/serialization."""
    return connector_platform_support(name, os_name).status


def connector_support_reason(name: str, os_name: str | None = None) -> str:
    """Return the operator-facing reason for the connector's status."""
    return connector_platform_support(name, os_name).reason


def connector_supported_on_os(name: str, os_name: str | None = None) -> bool:
    """Report whether *name* may be offered/used on *os_name*.

    Preview connectors are deliberately available. Not-certified and
    unsupported connectors are hidden from pickers and rejected by setup.
    """
    return connector_platform_support(name, os_name).available


def connector_preview_on_os(name: str, os_name: str | None = None) -> bool:
    """Report whether *name* is available as a preview on *os_name*."""
    return connector_support_status(name, os_name) == PREVIEW


def local_observability_stack_supported(os_name: str | None = None) -> bool:
    """Whether the shared Python-backed observability controller is available."""

    resolved_os = host_os() if os_name is None else _normalize_os_name(os_name)
    return resolved_os in {"windows", "darwin", "linux"}


def local_splunk_stack_supported(os_name: str | None = None) -> bool:
    """Whether bundled Local Splunk has a certified lifecycle controller."""

    resolved_os = host_os() if os_name is None else _normalize_os_name(os_name)
    return resolved_os in {"windows", "darwin", "linux"}


def local_shell_stacks_supported(os_name: str | None = None) -> bool:
    """Backward-compatible alias for bundled Local Splunk availability."""

    return local_splunk_stack_supported(os_name)


def is_local_observability_stack_destination(
    *,
    name: str = "",
    preset_id: str = "",
    kind: str = "",
    endpoint: str = "",
) -> bool:
    """Classify config/runtime state owned by bundled local observability."""

    if preset_id == "local-otlp" or name in {"local-observability", "local-otlp-logs"}:
        return True
    return False


def is_local_splunk_stack_destination(
    *,
    preset_id: str = "",
    kind: str = "",
    endpoint: str = "",
) -> bool:
    """Classify loopback Splunk HEC state owned by the local Splunk stack."""

    if kind != "splunk_hec":
        return False
    if preset_id == "splunk-enterprise":
        return False
    parsed = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
    return (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}


def is_local_shell_stack_destination(
    *,
    name: str = "",
    preset_id: str = "",
    kind: str = "",
    endpoint: str = "",
) -> bool:
    """Backward-compatible union classifier for older callers."""

    return is_local_observability_stack_destination(
        name=name, preset_id=preset_id, kind=kind, endpoint=endpoint
    ) or is_local_splunk_stack_destination(
        preset_id=preset_id,
        kind=kind,
        endpoint=endpoint,
    )


def destination_platform_unsupported(
    *,
    name: str = "",
    preset_id: str = "",
    kind: str = "",
    endpoint: str = "",
    os_name: str | None = None,
) -> bool:
    """Whether a destination belongs to a local stack unavailable here."""

    return (
        not local_observability_stack_supported(os_name)
        and is_local_observability_stack_destination(
            name=name,
            preset_id=preset_id,
            kind=kind,
            endpoint=endpoint,
        )
    ) or (
        not local_splunk_stack_supported(os_name)
        and is_local_splunk_stack_destination(
            preset_id=preset_id,
            kind=kind,
            endpoint=endpoint,
        )
    )


def supported_connectors(names: Iterable[str], os_name: str | None = None) -> list[str]:
    """Filter *names* to supported/preview entries, preserving order."""
    return [n for n in names if connector_supported_on_os(n, os_name)]
