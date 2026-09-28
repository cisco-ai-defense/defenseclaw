# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Semantic checks for the ``openshell:`` config section.

Mirrors ``OpenShellConfig.Validate`` and ``Config.ValidateOpenShell`` in
internal/config/openshell.go for everything the v8 schema cannot express
(egress pattern grammar, project-relative mask globs, copy-mode path globs,
positive quantities, listener collisions), so a Python writer never saves a
section the Go gateway refuses to load. The shared corpus testdata/openshell/config_validation_cases.yaml pins the
parity; the input is a document that already passed the v8 schema.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

# Go: DefaultGatewayAPIPort and the guardrail.port loader default.
DEFAULT_GATEWAY_API_PORT = 18970
DEFAULT_GUARDRAIL_PORT = 4000

_HOST_LABEL = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")
_CPU = re.compile(r"([0-9]{1,6})(\.[0-9]{1,3})?|([0-9]{1,9})m")
_MEMORY = re.compile(r"([0-9]{1,15})(Ki|Mi|Gi|Ti|k|K|M|G|T)?")
_MEMORY_MULTIPLIER = {
    "": 1,
    "k": 1000,
    "K": 1000,
    "M": 1000**2,
    "G": 1000**3,
    "T": 1000**4,
    "Ki": 1 << 10,
    "Mi": 1 << 20,
    "Gi": 1 << 30,
    "Ti": 1 << 40,
}
_PACK_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# Go: openShellPrefixBits, a CIDR prefix length without leading zeros.
_PREFIX_BITS = re.compile(r"0|[1-9][0-9]{0,2}")
_DRIVE_LETTER = re.compile(r"[A-Za-z]:")
_MAX_INT64 = (1 << 63) - 1
# Go: MaxOpenShellProjectGlobBytes.
MAX_PROJECT_GLOB_BYTES = 4096


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Go's netip.ParseAddr; a zoned address is returned as None (never valid here)."""
    if "%" in value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _valid_egress_host_name(name: str) -> bool:
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    if not all(_HOST_LABEL.fullmatch(label) for label in labels):
        return False
    return "a" <= labels[-1][0] <= "z"


def valid_egress_pattern(pattern: str) -> bool:
    """``ValidateOpenShellEgressPattern``: a host name, "*.<host>", an IP address or a CIDR prefix."""
    p = pattern.strip().lower()
    if not p or p == "*":
        return False
    if p.startswith("*."):
        return _valid_egress_host_name(p[2:])
    if "*" in p:
        return False
    if "/" in p:
        addr_part, _, bits = p.partition("/")
        addr = _parse_ip(addr_part)
        if addr is None or not _PREFIX_BITS.fullmatch(bits) or int(bits) > addr.max_prefixlen:
            return False
        # Go refuses an IPv4-mapped prefix shorter than /96.
        return not (isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None and int(bits) < 96)
    bare = p[1:-1] if len(p) >= 2 and p[0] == "[" and p[-1] == "]" else p
    return _parse_ip(bare) is not None or _valid_egress_host_name(p)


def _go_glob_well_formed(segment: str) -> bool:
    """Go's path.Match syntax check: escapes and character classes must be complete."""
    i, n = 0, len(segment)

    def escaped(j: int) -> int:
        # getEsc: a class character, optionally escaped; -1 when malformed.
        if j >= n or segment[j] in "-]":
            return -1
        if segment[j] == "\\":
            j += 1
            if j >= n:
                return -1
        j += 1
        return j if j < n else -1

    while i < n:
        c = segment[i]
        if c == "\\":
            if i + 1 >= n:
                return False
            i += 2
        elif c == "[":
            i += 1
            if i < n and segment[i] == "^":
                i += 1
            ranges = 0
            while True:
                if i < n and segment[i] == "]" and ranges > 0:
                    i += 1
                    break
                i = escaped(i)
                if i < 0:
                    return False
                if segment[i] == "-":
                    i = escaped(i + 1)
                    if i < 0:
                        return False
                ranges += 1
        else:
            i += 1
    return True


def valid_copy_pattern(pattern: str) -> bool:
    """``ValidateOpenShellCopyPattern``: an absolute, "~/" or "**/" path glob of well-formed segments."""
    p = pattern.strip()
    if not p or "\x00" in p:
        return False
    anchored = (
        p.startswith(("/", "~/", "**/"))
        or p in ("~", "**")
        or (len(p) > 2 and _DRIVE_LETTER.match(p) is not None and p[2] in "/\\")
    )
    return anchored and all(_go_glob_well_formed(segment) for segment in p.split("/"))


def valid_project_glob(glob: str) -> bool:
    """``ValidateOpenShellProjectGlob``: a project-relative glob that cannot escape the project."""
    g = glob.strip()
    if not g or len(g.encode("utf-8")) > MAX_PROJECT_GLOB_BYTES or "\x00" in g:
        return False
    if g.startswith(("/", "~")) or "\\" in g or _DRIVE_LETTER.match(g):
        return False
    return ".." not in g.split("/")


def valid_cpu(value: str) -> bool:
    """``ParseOpenShellCPU``: positive cores ("2", "1.5") or millicores ("500m")."""
    match = _CPU.fullmatch(value.strip())
    if match is None:
        return False
    if match.group(3) is not None:
        return int(match.group(3)) > 0
    milli = int(match.group(1)) * 1000
    fraction = (match.group(2) or ".")[1:]
    if fraction:
        milli += int(fraction.ljust(3, "0"))
    return milli > 0


def valid_memory(value: str) -> bool:
    """``ParseOpenShellMemory``: positive bytes with an optional unit, within int64."""
    match = _MEMORY.fullmatch(value.strip())
    if match is None:
        return False
    number = int(match.group(1))
    multiplier = _MEMORY_MULTIPLIER[match.group(2) or ""]
    return 0 < number <= _MAX_INT64 // multiplier


def _resources_error(path: str, raw: Any) -> tuple[str, str] | None:
    resources = _mapping(raw)
    cpu = resources.get("cpu")
    if isinstance(cpu, str) and cpu != "" and not valid_cpu(cpu):
        return f"{path}.cpu", 'use positive cores ("2", "1.5") or millicores ("500m")'
    memory = resources.get("memory")
    if isinstance(memory, str) and memory != "" and not valid_memory(memory):
        return f"{path}.memory", 'use a positive size such as "512Mi" or "4Gi"'
    return None


def _globs_error(path: str, raw: Any) -> tuple[str, str] | None:
    for index, glob in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(glob, str) or not valid_egress_pattern(glob):
            return (
                f"{path}[{index}]",
                'use a host name, "*.<host>", an IP address or a CIDR prefix without a scheme, port or path',
            )
    return None


def _project_globs_error(path: str, raw: Any) -> tuple[str, str] | None:
    for index, glob in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(glob, str) or not valid_project_glob(glob):
            return (
                f"{path}[{index}]",
                'use a project-relative glob with forward slashes, without a leading "/" or "~" or a ".." segment',
            )
    return None


def _port(value: Any, default: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def openshell_error(document: Mapping[str, Any]) -> tuple[str, str] | None:
    """Return ``(path, action)`` for the first ``openshell`` problem, or None."""
    section = _mapping(document.get("openshell"))
    if not section:
        return None
    egress = _mapping(section.get("egress"))
    admin = _mapping(section.get("admin"))
    workdir = _mapping(section.get("workdir"))

    ingress, egress_port = _port(section.get("ingress_port")), _port(section.get("egress_port"))
    if ingress != 0 and ingress == egress_port:
        return "openshell.egress_port", "use different ingress_port and egress_port values"
    for path, raw in (
        ("openshell.workdir.masks", workdir.get("masks")),
        ("openshell.workdir.unmask", workdir.get("unmask")),
    ):
        error = _project_globs_error(path, raw)
        if error is not None:
            return error
    for path, raw in (
        ("openshell.egress.block", egress.get("block")),
        ("openshell.egress.allow", egress.get("allow")),
        ("openshell.egress.unblocked", egress.get("unblocked")),
        ("openshell.admin.egress_block", admin.get("egress_block")),
        ("openshell.admin.egress_allow_only", admin.get("egress_allow_only")),
    ):
        error = _globs_error(path, raw)
        if error is not None:
            return error
    for path, raw in (
        ("openshell.resources", section.get("resources")),
        ("openshell.admin.max_resources", admin.get("max_resources")),
    ):
        error = _resources_error(path, raw)
        if error is not None:
            return error
    for index, glob in enumerate(admin.get("require_copy_for") or []):
        if isinstance(glob, str) and not valid_copy_pattern(glob):
            return (
                f"openshell.admin.require_copy_for[{index}]",
                'use an absolute path glob or one starting with "~/", with well-formed wildcards',
            )
    digest = admin.get("required_pack_digest")
    if isinstance(digest, str) and digest:
        if not _PACK_DIGEST.fullmatch(digest):
            return "openshell.admin.required_pack_digest", "use sha256:<64 lowercase hex digits>"
        if not str(admin.get("required_pack") or "").strip():
            return "openshell.admin.required_pack_digest", "set openshell.admin.required_pack to the pinned pack"

    if section.get("enabled") is True:
        return _listeners_error(document, ingress, egress_port)
    return None


def _listeners_error(document: Mapping[str, Any], ingress: int, egress: int) -> tuple[str, str] | None:
    """``Config.validateOpenShellListeners``: only an enabled section binds."""
    api_port = _port(_mapping(document.get("gateway")).get("api_port")) or DEFAULT_GATEWAY_API_PORT
    guardrail_port = _port(_mapping(document.get("guardrail")).get("port", DEFAULT_GUARDRAIL_PORT))
    ports = {
        "ingress_port": ingress or api_port + 1,
        "egress_port": egress or api_port + 2,
    }
    for key, port in ports.items():
        path = f"openshell.{key}"
        if port > 65535:
            return path, f"gateway.api_port {api_port} leaves no room for the derived port; set openshell.{key}"
        if port == api_port:
            return path, "use a port other than gateway.api_port"
        if guardrail_port > 0 and port == guardrail_port:
            return path, "use a port other than guardrail.port"
    if ports["ingress_port"] == ports["egress_port"]:
        return "openshell.egress_port", "use different effective ingress and egress ports"
    return None
