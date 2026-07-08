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

DefenseClaw runs hook-only on Windows: agents invoke the native Go hook
entrypoint (``defenseclaw-hook``) directly, and there is no Windows
guardrail-proxy lifecycle. The proxy/chat connectors (``openclaw`` and
``zeptoclaw``) therefore cannot run on Windows, so the TUI/CLI must not offer
or accept them there.

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

LOCAL_SHELL_STACKS_UNSUPPORTED_REASON = (
    "Local observability and local Splunk are unsupported on native Windows."
)


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
        "Codex CLI and the DefenseClaw hook entrypoint are certified on native Windows x64.",
    ),
    "claudecode": ConnectorPlatformSupport(
        SUPPORTED,
        "Claude Code with Git for Windows and native hooks is certified on native Windows x64.",
    ),
    "cursor": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw Cursor integration has not completed native Windows x64 certification.",
    ),
    "windsurf": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw Windsurf integration has not completed native Windows x64 certification.",
    ),
    "geminicli": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw Gemini CLI integration has not completed native Windows x64 certification.",
    ),
    "copilot": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw GitHub Copilot CLI integration has not completed native Windows x64 certification.",
    ),
    "antigravity": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw Antigravity integration has not completed native Windows x64 certification.",
    ),
    "opencode": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw OpenCode integration has not completed native Windows x64 certification.",
    ),
    "hermes": ConnectorPlatformSupport(
        NOT_CERTIFIED,
        "The DefenseClaw Hermes integration has not completed native Windows x64 certification.",
    ),
    "openhands": ConnectorPlatformSupport(
        UNSUPPORTED,
        "OpenHands CLI requires WSL; DefenseClaw does not implement a WSL connector path.",
    ),
    "omnigent": ConnectorPlatformSupport(
        UNSUPPORTED,
        "OmniGent has no supported native Windows terminal/sandbox path for this connector.",
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
        "omnigent",
        "openclaw",
        "zeptoclaw",
        "local-observability-shell-stack",
        "splunk-shell-stack",
        "native-desktop-toasts",
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


def local_shell_stacks_supported(os_name: str | None = None) -> bool:
    """Whether extensionless Bash-backed local telemetry stacks may run.

    This is the authoritative capability boundary for both the bundled local
    observability stack and the bundled local Splunk stack.  Keeping it in the
    platform taxonomy makes CLI and TUI behavior injectable in tests without
    probing executables or mutating operator state.
    """

    resolved_os = host_os() if os_name is None else _normalize_os_name(os_name)
    return resolved_os != "windows"


def is_local_shell_stack_destination(
    *,
    name: str = "",
    preset_id: str = "",
    kind: str = "",
    endpoint: str = "",
) -> bool:
    """Classify config/runtime state owned by the unsupported local stacks."""

    if preset_id == "local-otlp" or name in {"local-observability", "local-otlp-logs"}:
        return True
    if kind != "splunk_hec":
        return False
    if preset_id == "splunk-enterprise":
        return False
    parsed = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
    return (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}


def destination_platform_unsupported(
    *,
    name: str = "",
    preset_id: str = "",
    kind: str = "",
    endpoint: str = "",
    os_name: str | None = None,
) -> bool:
    """Whether a destination belongs to a local stack unavailable here."""

    return not local_shell_stacks_supported(os_name) and is_local_shell_stack_destination(
        name=name,
        preset_id=preset_id,
        kind=kind,
        endpoint=endpoint,
    )


def supported_connectors(
    names: Iterable[str], os_name: str | None = None
) -> list[str]:
    """Filter *names* to supported/preview entries, preserving order."""
    return [n for n in names if connector_supported_on_os(n, os_name)]
