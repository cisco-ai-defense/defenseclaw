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

"""Explicit, short-lived agent executable evidence for connector setup.

The ordinary discovery cache is an inventory acceleration and never grants
permission to execute a cached path.  An explicit first-run/setup selection
instead performs a fresh trusted-path probe and writes this protected receipt.
The gateway may consume it only while installing or repairing the connector,
then seals the exact executable identity into ``hook_contract_lock.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defenseclaw.connector_contracts import normalize_agent_version
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.inventory import agent_discovery
from defenseclaw.inventory.plugin_identity import is_link_or_reparse

SELECTION_FILENAME = "agent_selection.json"
SELECTION_SCHEMA_VERSION = 1
SELECTION_LIFETIME = timedelta(minutes=15)
_CODEX_WINDOWS_PLATFORM_VARIANTS = (
    ("codex-win32-x64", "x86_64-pc-windows-msvc"),
    ("codex-win32-arm64", "aarch64-pc-windows-msvc"),
)
_MAX_AGENT_EXECUTABLE_BYTES = 512 * 1024 * 1024
_SUPPORTED_CONNECTORS = frozenset({"codex", "claudecode"})


@dataclass(frozen=True)
class SetupAgentSelection:
    """One executable selected by an explicit connector setup action."""

    connector: str
    executable: str
    raw_version: str
    normalized_version: str
    sha256: str


def record_setup_agent_selections(
    data_dir: str | os.PathLike[str],
    connectors: Iterable[str],
) -> tuple[dict[str, SetupAgentSelection], dict[str, str]]:
    """Probe and persist explicit executable selections for supported agents.

    Returns ``(selections, errors)``.  A connector that is not installed in an
    admissible location is reported rather than represented by weak evidence;
    callers decide whether their workflow supports pre-provisioning hooks for
    an agent that is not installed yet.
    """

    target_dir = os.path.abspath(os.fspath(data_dir))
    requested = tuple(
        dict.fromkeys(
            name
            for raw in connectors
            if (name := agent_discovery._normalize_connector(str(raw))) in _SUPPORTED_CONNECTORS
        )
    )
    selections: dict[str, SetupAgentSelection] = {}
    errors: dict[str, str] = {}
    for connector in requested:
        try:
            selections[connector] = _select_agent_executable(target_dir, connector)
        except OSError as exc:
            errors[connector] = str(exc)

    now = datetime.now(timezone.utc)
    expires = now + SELECTION_LIFETIME
    payload = {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "updated_at": _format_rfc3339(now),
        "selections": {
            name: {
                "connector": selection.connector,
                "source": "setup-selected",
                "executable": selection.executable,
                "raw_version": selection.raw_version,
                "normalized_version": selection.normalized_version,
                "sha256": selection.sha256,
                "selected_at": _format_rfc3339(now),
                "expires_at": _format_rfc3339(expires),
            }
            for name, selection in sorted(selections.items())
        },
    }
    body = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_private_bytes(os.path.join(target_dir, SELECTION_FILENAME), body)
    return selections, errors


def _select_agent_executable(data_dir: str, connector: str) -> SetupAgentSelection:
    spec = agent_discovery._SPECS[connector]
    rejection = "no installed executable was found in a built-in or operator-approved trusted prefix"
    for candidate in _setup_agent_candidates(connector, spec, data_dir):
        if not is_setup_trusted_binary(candidate, data_dir):
            continue
        executable = os.path.realpath(os.path.abspath(candidate))
        raw_version, probe_error = agent_discovery._version_for_agent_binary(
            connector,
            executable,
            spec.version_args,
            # The setup-specific admission immediately above already binds the
            # candidate to token-resolved roots and validates its ACL chain.
            # Generic discovery roots intentionally follow the discovery
            # environment and must not override that stronger setup decision.
            require_trusted_binary_paths=False,
            data_dir=data_dir,
        )
        if probe_error or not raw_version:
            rejection = probe_error or "version probe returned no version"
            continue
        normalized = normalize_agent_version(raw_version)
        if not normalized:
            rejection = f"could not normalize agent version {raw_version!r}"
            continue
        try:
            digest = stable_executable_sha256(executable)
        except OSError as exc:
            rejection = str(exc)
            continue
        return SetupAgentSelection(
            connector=connector,
            executable=executable,
            raw_version=raw_version,
            normalized_version=normalized,
            sha256=digest,
        )
    raise OSError(f"cannot select {connector} executable: {rejection}")


def is_setup_trusted_binary(candidate: str, data_dir: str) -> bool:
    """Admit only built-in or protected-config prefixes, never env extras."""

    try:
        resolved = os.path.realpath(os.path.abspath(candidate))
    except (OSError, ValueError):
        return False
    if is_link_or_reparse(candidate) or is_link_or_reparse(resolved):
        return False
    _require, configured = agent_discovery._ai_discovery_trust_config(data_dir)
    allowed_roots = agent_discovery._expand_bin_prefixes((*_builtin_setup_trusted_prefixes(), *configured))
    matching_roots = tuple(root for root in allowed_roots if agent_discovery._path_is_within(resolved, root))
    if not matching_roots:
        return False
    if os.name == "nt":
        # Doctor starts this exact path to inspect Codex's merged policy. A
        # CMD/BAT wrapper is not executable authority: Windows dispatches it
        # through the inherited command processor and its mutable Node/JS
        # payload is not covered by the wrapper digest. Bind only the native
        # image that CreateProcess launches directly.
        if os.path.splitext(resolved)[1].casefold() != ".exe":
            return False
        return any(agent_discovery._windows_acl_chain_is_safe(resolved, root) for root in matching_roots)
    # Reuse the complete executable/owner validation after independently
    # proving the match did not come solely from a mutable environment prefix.
    return agent_discovery._is_trusted_binary_path(resolved, data_dir=data_dir)


def _setup_agent_candidates(connector: str, spec, data_dir: str) -> tuple[str, ...]:
    """Enumerate PATH candidates plus exact names under trusted API roots."""

    discovered = list(agent_discovery._binary_candidates_for_agent(connector, spec))
    _require, configured = agent_discovery._ai_discovery_trust_config(data_dir)
    roots = agent_discovery._expand_bin_prefixes((*_builtin_setup_trusted_prefixes(), *configured))
    candidates: list[str] = []
    paired_codex_root = ""
    if connector == "codex" and discovered:
        # `_binary_candidates_for_agent` preserves PATH precedence, so its
        # first entry is the CLI the user actually launches.  When that entry
        # is npm's CMD wrapper, prefer the native image from the same approved
        # package root over an unrelated Codex Desktop image discovered later.
        # The native candidate still passes the normal root, ACL, version, and
        # digest admission checks before it can be selected.
        path_candidate = os.path.realpath(os.path.abspath(discovered[0]))
        if os.path.splitext(path_candidate)[1].casefold() != ".exe":
            for root in roots:
                if agent_discovery._path_is_within(path_candidate, root):
                    recognized, paired = _codex_wrapper_native_candidates(
                        root,
                        path_candidate,
                        _CODEX_WINDOWS_PLATFORM_VARIANTS,
                    )
                    if not recognized:
                        paired = _codex_npm_native_candidates(root)
                    if recognized or paired:
                        candidates.extend(paired)
                        paired_codex_root = os.path.normcase(os.path.abspath(root))
                        break
    candidates.extend(discovered)
    names = {
        "codex": ("codex.exe", "codex.cmd", "codex.bat", "codex.com"),
        "claudecode": ("claude.exe", "claude.cmd", "claude.bat", "claude.com"),
    }[connector]
    for root in roots:
        for name in names:
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate):
                candidates.append(candidate)
        if connector == "codex" and os.path.basename(root).casefold() == "bin":
            try:
                candidates.extend(str(path) for path in sorted(Path(root).glob("*/codex.exe")) if path.is_file())
            except OSError:
                pass
        if connector == "codex" and os.path.normcase(os.path.abspath(root)) != paired_codex_root:
            candidates.extend(_codex_npm_native_candidates(root))

    # Prefer a native image over a script wrapper. This both avoids shell
    # interpretation and binds the protected digest to the process that
    # actually implements app-server when a native Codex install is present.
    # Python's sort is stable: move native images ahead of wrappers while
    # preserving PATH/discovery precedence within each class.  A stale package
    # tree must not outrank the currently selected Codex executable merely
    # because its absolute path sorts first.
    candidates.sort(key=lambda value: os.path.splitext(value)[1].casefold() != ".exe")
    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(os.path.abspath(candidate))
        if key not in seen:
            seen.add(key)
            result.append(candidate)
    return tuple(result)


def _codex_npm_native_candidates(root: str) -> tuple[str, ...]:
    """Return bounded native Codex images below an approved npm/pnpm root.

    The Windows npm launcher is a mutable ``.cmd`` wrapper and cannot be the
    executable identity sealed into the hook contract.  The official package
    ships the real image at one of the fixed package-relative paths below.
    Enumerating only those paths keeps the existing trusted-root, reparse, ACL,
    version, and digest checks authoritative without recursively searching a
    package-manager tree or granting the wrapper execution authority.
    """

    package_variants = (
        ("node_modules", "@openai", "codex", "node_modules", "@openai"),
        ("node_modules", "@openai"),
    )
    candidates: list[str] = []
    for prefix in package_variants:
        for package_name, target in _CODEX_WINDOWS_PLATFORM_VARIANTS:
            candidate = os.path.join(
                root,
                *prefix,
                package_name,
                "vendor",
                target,
                "bin",
                "codex.exe",
            )
            if os.path.isfile(candidate):
                candidates.append(candidate)
    candidates.extend(_codex_pnpm_native_candidates(root, _CODEX_WINDOWS_PLATFORM_VARIANTS, ()))
    return tuple(candidates)


def _codex_wrapper_native_candidates(
    root: str,
    wrapper: str,
    platform_variants: tuple[tuple[str, str], ...],
) -> tuple[bool, tuple[str, ...]]:
    """Pair an npm/pnpm PATH shim to the exact package-native executable."""

    try:
        root = os.path.realpath(os.path.abspath(root))
        wrapper = os.path.realpath(os.path.abspath(wrapper))
        if not agent_discovery._path_is_within(wrapper, root) or os.path.splitext(wrapper)[1].casefold() not in {
            ".cmd",
            ".bat",
        }:
            return False, ()
        with open(wrapper, "rb") as stream:
            body = stream.read(65_537)
        if len(body) > 65_536:
            return False, ()
        text = body.decode("utf-8-sig")
    except (OSError, UnicodeError, ValueError):
        return False, ()

    package_roots: dict[str, tuple[Path, Path]] = {}
    saw_target = False
    target_pattern = re.compile(
        r'"([^"\r\n]*node_modules[\\/]@openai[\\/]codex[\\/]bin[\\/]codex\.js)"',
        re.IGNORECASE,
    )
    for match in target_pattern.finditer(text):
        saw_target = True
        value = match.group(1)
        folded = value.casefold()
        if folded.startswith("%~dp0\\"):
            relative = value[len("%~dp0\\") :].replace("\\", os.sep).replace("/", os.sep)
            target = os.path.join(os.path.dirname(wrapper), relative)
        elif folded.startswith("%dp0%\\"):
            relative = value[len("%dp0%\\") :].replace("\\", os.sep).replace("/", os.sep)
            target = os.path.join(os.path.dirname(wrapper), relative)
        elif os.path.isabs(value):
            target = value
        else:
            continue
        lexical_target = os.path.abspath(target)
        if not agent_discovery._path_is_within(lexical_target, root):
            continue
        if not os.path.isfile(lexical_target):
            continue
        resolved_target = os.path.realpath(lexical_target)
        if not agent_discovery._path_is_within(resolved_target, root):
            continue
        target_path = Path(resolved_target)
        if tuple(part.casefold() for part in target_path.parts[-5:]) != (
            "node_modules",
            "@openai",
            "codex",
            "bin",
            "codex.js",
        ):
            continue
        lexical_package_root = Path(lexical_target).parents[1]
        resolved_package_root = target_path.parents[1]
        package_roots[os.path.normcase(str(lexical_package_root))] = (
            lexical_package_root,
            resolved_package_root,
        )
    if len(package_roots) != 1:
        return saw_target, ()

    lexical_package_root, resolved_package_root = next(iter(package_roots.values()))
    candidates: list[str] = []
    seen: set[str] = set()
    for package_name, target in platform_variants:
        bases = (
            lexical_package_root,
            lexical_package_root / "node_modules" / "@openai" / package_name,
            lexical_package_root.parent / package_name,
            lexical_package_root.parents[1] / ".pnpm" / "node_modules" / "@openai" / package_name,
            resolved_package_root,
            resolved_package_root / "node_modules" / "@openai" / package_name,
            resolved_package_root.parent / package_name,
            resolved_package_root.parents[1] / ".pnpm" / "node_modules" / "@openai" / package_name,
        )
        for base in bases:
            candidate = os.path.realpath(base / "vendor" / target / "bin" / "codex.exe")
            key = os.path.normcase(os.path.abspath(candidate))
            if key in seen or not agent_discovery._path_is_within(candidate, root):
                continue
            if os.path.isfile(candidate):
                seen.add(key)
                candidates.append(candidate)
    return True, tuple(candidates)


def _codex_pnpm_native_candidates(
    root: str,
    platform_variants: tuple[tuple[str, str], ...],
    generations: tuple[str, ...],
) -> tuple[str, ...]:
    """Resolve the platform package paired with pnpm's active Codex link."""

    root = os.path.realpath(os.path.abspath(root))
    candidates: list[str] = []
    seen: set[str] = set()
    try:
        if generations:
            active_packages = [
                Path(root) / "global" / generation / "node_modules" / "@openai" / "codex" for generation in generations
            ]
        else:
            # Generic root enumeration is allowed only when exactly one active
            # pnpm generation exists. PATH-specific discovery above pairs the
            # wrapper to its exact generation and therefore tolerates stale
            # generations without selecting them.
            active_packages = sorted(Path(root).glob("global/*/node_modules/@openai/codex"))
            active_generations = {str(package.parents[2]) for package in active_packages}
            if len(active_generations) > 1:
                return ()
    except (IndexError, OSError):
        return ()
    for active_package in active_packages:
        if not active_package.is_dir():
            continue
        resolved_package = Path(os.path.realpath(active_package))
        if not agent_discovery._path_is_within(str(resolved_package), root):
            continue
        try:
            virtual_node_modules = resolved_package.parents[1]
            generation_node_modules = active_package.parents[1]
        except IndexError:
            continue
        dependency_roots = (
            virtual_node_modules,
            generation_node_modules / ".pnpm" / "node_modules",
        )
        for dependency_root in dependency_roots:
            for package_name, target in platform_variants:
                linked_candidate = dependency_root / "@openai" / package_name / "vendor" / target / "bin" / "codex.exe"
                candidate = os.path.realpath(linked_candidate)
                key = os.path.normcase(os.path.abspath(candidate))
                if key in seen or not agent_discovery._path_is_within(candidate, root):
                    continue
                if os.path.isfile(candidate):
                    seen.add(key)
                    candidates.append(candidate)
    return tuple(candidates)


def _builtin_setup_trusted_prefixes() -> tuple[str, ...]:
    """Resolve Windows roots through APIs, independent of inherited env vars."""

    if os.name != "nt":
        return agent_discovery._builtin_trusted_bin_prefixes()

    local = _windows_known_folder("F1B32785-6FBA-4FCF-9D55-7B8E7F157091")
    roaming = _windows_known_folder("3EB685DB-65F9-4CF6-A03A-E3EF65729F3D")
    profile = _windows_known_folder("5E6C858F-0E22-4760-9AFE-EA3317B67173")
    program_files = tuple(
        value
        for value in (
            _windows_known_folder("6D809377-6AF0-444B-8957-A3773F02200E"),
            _windows_known_folder("7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E"),
        )
        if value
    )
    roots: list[str] = []
    if local:
        roots.extend(
            (
                os.path.join(local, "Programs", "OpenAI", "Codex", "bin"),
                os.path.join(local, "OpenAI", "Codex", "bin"),
                os.path.join(local, "OpenAI", "Codex", "runtimes"),
                os.path.join(local, "Microsoft", "WinGet", "Links"),
                os.path.join(local, "pnpm"),
            )
        )
    if roaming:
        roots.append(os.path.join(roaming, "npm"))
    if profile:
        roots.extend((os.path.join(profile, ".local", "bin"), os.path.join(profile, "scoop", "shims")))
    for root in program_files:
        roots.extend((os.path.join(root, "nodejs"), os.path.join(root, "OpenAI", "Codex", "bin")))
    system = _windows_system_directory()
    if system:
        roots.append(system)
    return tuple(dict.fromkeys(os.path.abspath(root) for root in roots if root))


def _windows_known_folder(identifier: str) -> str:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    value = uuid.UUID(identifier)
    raw = value.bytes_le
    guid = GUID.from_buffer_copy(raw)
    path = ctypes.c_wchar_p()
    token = wintypes.HANDLE()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    # A null token lets Known Folder resolution consume process-level profile
    # overrides inherited from an agent. Bind setup authority to the actual
    # current-user token, matching internal/winpath on the native Go side.
    token_query = 0x0008
    token_impersonate = 0x0004
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        token_query | token_impersonate,
        ctypes.byref(token),
    ):
        return ""
    try:
        result = shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, token, ctypes.byref(path))
        if result != 0:
            return ""
        return os.path.abspath(path.value or "") if path.value else ""
    finally:
        if path:
            ole32 = ctypes.WinDLL("ole32", use_last_error=True)
            ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
            ole32.CoTaskMemFree.restype = None
            ole32.CoTaskMemFree(ctypes.cast(path, ctypes.c_void_p))
        kernel32.CloseHandle(token)


def _windows_system_directory() -> str:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = kernel32.GetSystemDirectoryW(buffer, size)
    if length == 0 or length >= size:
        return ""
    return os.path.abspath(buffer.value)


def stable_executable_sha256(path: str) -> str:
    """Hash one stable, non-reparse regular file with a bounded size."""

    descriptor = -1
    try:
        before = os.lstat(path)
        if is_link_or_reparse(path) or not stat.S_ISREG(before.st_mode):
            raise OSError(f"selected agent executable is not a regular non-reparse file: {path}")
        if before.st_size <= 0 or before.st_size > _MAX_AGENT_EXECUTABLE_BYTES:
            raise OSError(f"selected agent executable has an invalid size: {path}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise OSError(f"selected agent executable changed while opening: {path}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or is_link_or_reparse(path):
            raise OSError(f"selected agent executable changed while hashing: {path}")
        return digest.hexdigest()
    except OSError:
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _format_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
