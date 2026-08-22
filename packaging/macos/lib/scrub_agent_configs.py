#!/usr/bin/env python3
"""
Remove DefenseClaw-owned entries from a user's native agent hook config
file. Intended to be invoked by the macOS uninstaller's --purge path so
the agent doesn't keep calling a deleted hook script and fail-close every
subsequent tool call.

Stdlib-only by design (macOS system Python 3.9 has no tomllib). Targets
the file shapes DefenseClaw's connectors write:

  ~/.cursor/hooks.json     — JSON flat-hooks shape
  ~/.claude/settings.json  — JSON nested {hooks: {event: [{hooks:[...]}]}}
  ~/.codex/config.toml     — TOML; DefenseClaw owns [hooks], [otel],
                             and the top-level notify array
  ~/.config/amp/plugins/defenseclaw.ts
                           — standalone managed plugin; remove or restore only
                             through its exact managed-backup authority
  ~/.config/opencode/plugins/defenseclaw.js
                           — standalone managed plugin with the same exact
                             target-bound restore authority

Exit codes:
  0   — file successfully scrubbed (or no changes were needed)
  2   — file missing (nothing to do)
  3   — unsupported connector
  4   — cleanup incomplete; inspect the target and rerun

Usage:
  scrub_agent_configs.py CONNECTOR FILE [DATADIR_PATTERN|MANAGED_BACKUP_FILE] [--retain-authority]
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass

DEFAULT_MARKERS = (
    "/.defenseclaw/hooks/",
    "/defenseclaw/hooks/",
    "defenseclaw-managed-hook",
    "notify-bridge.sh",
)

# Markers that identify a Codex [otel] block as DefenseClaw-managed even
# when it doesn't contain a hooks-dir path. DefenseClaw configures Codex
# to send OTLP to a loopback DefenseClaw gateway, so an endpoint value
# pointing at 127.0.0.1 (or localhost) is a strong signal. We deliberately
# DO NOT match on "otlp_endpoint" alone — a user with their own vendor
# OTel setup would then get their block scrubbed too.
CODEX_OTEL_DC_MARKERS = (
    "127.0.0.1",
    "localhost",
    "defenseclaw",
)


def looks_owned(value: object, markers: tuple[str, ...]) -> bool:
    """Best-effort recursive check: does any string in the structure
    contain one of our markers? Used for JSON shapes."""
    if isinstance(value, str):
        return any(m in value for m in markers)
    if isinstance(value, list):
        return any(looks_owned(v, markers) for v in value)
    if isinstance(value, dict):
        return any(looks_owned(v, markers) for v in value.values())
    return False


# ---------- JSON: Cursor + Claude Code -----------------------------------


def scrub_cursor(path: str, markers: tuple[str, ...]) -> tuple[bool, str | None]:
    """Drop DefenseClaw entries from ~/.cursor/hooks.json.

    Shape: { "version": 1, "hooks": { "<event>": [ {entry}, ... ] } }
    Each entry has "command" pointing at the hook script. We drop any
    entry whose command matches a marker. Events with no entries left
    are removed too, so we don't leave empty arrays floating around.
    """
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        return False, "not a JSON object"
    hooks = cfg.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in list(hooks.items()):
            if not isinstance(entries, list):
                continue
            kept = [e for e in entries if not looks_owned(e, markers)]
            if not kept:
                del hooks[event]
            else:
                hooks[event] = kept
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)
        f.write("\n")
    return True, None


# DefenseClaw-owned keys in Claude Code's settings.json env block.
# Kept in sync with claudeCodeOtelEnvKeys in
# internal/gateway/connector/claudecode.go.
CLAUDE_MANAGED_ENV_KEYS = frozenset(
    {
        "CLAUDE_CODE_ENABLE_TELEMETRY",
        "DEFENSECLAW_FAIL_MODE",
        "OTEL_METRICS_EXPORTER",
        "OTEL_LOGS_EXPORTER",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "OTEL_LOG_USER_PROMPTS",
        "OTEL_RESOURCE_ATTRIBUTES",
        "OTEL_SERVICE_NAME",
    }
)


def scrub_claudecode(path: str, markers: tuple[str, ...]) -> tuple[bool, str | None]:
    """Drop DefenseClaw entries from ~/.claude/settings.json.

    Shape: { "hooks": { "<event>": [ {"hooks":[{entry}, ...]}, ... ] } }
    Nested one level deeper than Cursor's; otherwise the same idea.
    Also strips DefenseClaw-owned keys from the top-level "env" block
    (kept in sync with claudeCodeOtelEnvKeys in the Go connector), and
    strips any additional env value that references our data-dir markers.
    Non-DefenseClaw env entries are preserved.
    """
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        return False, "not a JSON object"
    hooks = cfg.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in list(hooks.items()):
            if not isinstance(groups, list):
                continue
            kept_groups: list = []
            for grp in groups:
                if not isinstance(grp, dict):
                    kept_groups.append(grp)
                    continue
                inner = grp.get("hooks")
                if not isinstance(inner, list):
                    if not looks_owned(grp, markers):
                        kept_groups.append(grp)
                    continue
                kept_inner = [h for h in inner if not looks_owned(h, markers)]
                if kept_inner:
                    grp["hooks"] = kept_inner
                    kept_groups.append(grp)
            if kept_groups:
                hooks[event] = kept_groups
            else:
                del hooks[event]
    env = cfg.get("env")
    if isinstance(env, dict):
        for key in list(env.keys()):
            if key in CLAUDE_MANAGED_ENV_KEYS:
                del env[key]
                continue
            if looks_owned(env[key], markers):
                del env[key]
        if not env:
            del cfg["env"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)
        f.write("\n")
    return True, None


# ---------- TOML: Codex --------------------------------------------------
#
# Codex's writer marshals a Go map[string]interface{} so it produces a
# canonical TOML shape. DefenseClaw owns three top-level entries
# wholesale (see internal/gateway/connector/codex.go):
#   - [hooks] table        — every value references our script path
#   - [otel] table         — endpoint points at the loopback gateway
#   - notify = [...] array — invokes our notify-bridge.sh
#
# We deliberately scrub these wholesale rather than parsing TOML, because:
#   1. stdlib doesn't have tomllib on Python < 3.11 and we cannot rely
#      on tomli being installed on the admin's machine.
#   2. Codex's writer overwrites these three top-level keys on every
#      install, so deleting them entirely matches the install contract.
#
# Anything outside those three keys is left alone (model preferences,
# project trust list, personality, etc.).


TOML_TOP_LEVEL_RE = re.compile(r"^\[([^\[\].\s]+)\]\s*$")
# Any TOML table header: simple `[name]`, dotted `[projects.foo]`, or
# array-of-tables `[[array.of.tables]]`. Used to bound the "section
# references DefenseClaw" scan so a matched marker inside `[hooks]`
# can't accidentally swallow the next unrelated section.
TOML_TABLE_HEADER_RE = re.compile(r"^\s*\[\[?[^\[\]]+\]\]?\s*$")


def scrub_codex(path: str, markers: tuple[str, ...]) -> tuple[bool, str | None]:
    """Remove [hooks], [otel] tables and the `notify` array from a
    Codex config.toml when their contents reference DefenseClaw.

    Operates on lines; preserves everything else verbatim. Multi-line
    table arrays ([[hooks.event]] style) aren't used by Codex's writer,
    so we don't need to handle them — but if someone introduces them
    we just won't touch their content (safe failure mode)."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        return False, str(e)

    out: list[str] = []
    i = 0
    n = len(lines)
    changed = False

    def section_references_dc(start: int, extra_markers: tuple[str, ...] = ()) -> tuple[bool, int]:
        """Look ahead from `start` (line right after a [section] header)
        until the next table header or EOF. Returns (matched, end_idx)
        where end_idx is the line index where the next section starts
        (or n)."""
        combined = markers + extra_markers
        j = start
        matched = False
        while j < n:
            line = lines[j]
            stripped = line.strip()
            # Stop at ANY table header — simple, dotted, or array-of-tables.
            if TOML_TABLE_HEADER_RE.match(stripped):
                break
            if any(m in line for m in combined):
                matched = True
            j += 1
        return matched, j

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Top-level [hooks] or [otel] table?
        m = TOML_TOP_LEVEL_RE.match(stripped)
        if m and m.group(1) in ("hooks", "otel"):
            # `[hooks]` uses the standard marker scan (hook script paths
            # under ~/.defenseclaw/hooks/ match the markers).
            # `[otel]` needs extra Codex-specific markers because its body
            # is scalars like `otlp_endpoint = "http://127.0.0.1:18970/v1/..."`
            # that don't match the hook-path markers. Anything with an
            # `otlp_endpoint` line pointing at loopback or defenseclaw is
            # considered DefenseClaw-managed.
            extra: tuple[str, ...] = ()
            if m.group(1) == "otel":
                extra = CODEX_OTEL_DC_MARKERS
            matched, end = section_references_dc(i + 1, extra)
            if matched:
                # Drop the header AND every line up to the next section.
                changed = True
                i = end
                # Also eat one trailing blank line if present, to keep
                # the file tidy.
                while i < n and lines[i].strip() == "":
                    i += 1
                    break
                continue
            else:
                out.append(line)
                i += 1
                continue

        # Top-level `notify = [...]` (single line or multi-line array)?
        if re.match(r"^\s*notify\s*=", line):
            # Single-line: notify = [...]
            if "]" in line:
                if any(m in line for m in markers):
                    changed = True
                    i += 1
                    continue
                out.append(line)
                i += 1
                continue
            # Multi-line: collect until the closing bracket.
            buf = [line]
            j = i + 1
            while j < n:
                buf.append(lines[j])
                if "]" in lines[j]:
                    break
                j += 1
            joined = "".join(buf)
            if any(m in joined for m in markers):
                changed = True
                i = j + 1
                continue
            out.extend(buf)
            i = j + 1
            continue

        out.append(line)
        i += 1

    if not changed:
        return True, None

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(out)
    return True, None


# ---------- whole-file managed plugins: Amp + OpenCode -----------------


MANAGED_PLUGIN_BACKUP_VERSION = 1
MANAGED_PLUGIN_MAX_BYTES = 64 * 1024 * 1024
MANAGED_TARGET_FROM_AUTHORITY = "--target-from-authority"
MANAGED_RETAIN_AUTHORITY = "--retain-authority"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DARWIN_WRITE_ACL_PERMISSIONS = frozenset(
    {
        "add_file",
        "add_subdirectory",
        "append",
        "chown",
        "delete",
        "delete_child",
        "write",
        "writeattr",
        "writeextattr",
        "writesecurity",
    }
)
DARWIN_READ_ONLY_ACL_PERMISSIONS = frozenset(
    {
        "directory_inherit",
        "execute",
        "file_inherit",
        "limit_inherit",
        "list",
        "only_inherit",
        "read",
        "readattr",
        "readextattr",
        "readsecurity",
        "search",
    }
)
DARWIN_ACL_PERMISSIONS = DARWIN_WRITE_ACL_PERMISSIONS | DARWIN_READ_ONLY_ACL_PERMISSIONS
DARWIN_LS_MODE_RE = re.compile(
    r"^[d-][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-][+@]?$"
)


@dataclass(frozen=True)
class ManagedPluginSpec:
    connector: str
    logical_name: str
    target_suffix: str
    backup_suffix: str
    label: str
    max_bytes: int = MANAGED_PLUGIN_MAX_BYTES
    target_from_authority: bool = False


AMP_PLUGIN_SPEC = ManagedPluginSpec(
    connector="amp",
    logical_name="config",
    target_suffix=os.path.join(".config", "amp", "plugins", "defenseclaw.ts"),
    backup_suffix=os.path.join(".defenseclaw", "connector_backups", "amp", "config.json"),
    label="Amp",
)
OPENCODE_PLUGIN_SPEC = ManagedPluginSpec(
    connector="opencode",
    logical_name="config",
    target_suffix=os.path.join(".config", "opencode", "plugins", "defenseclaw.js"),
    backup_suffix=os.path.join(".defenseclaw", "connector_backups", "opencode", "config.json"),
    label="OpenCode",
    target_from_authority=True,
)
MANAGED_PLUGIN_SPECS = {spec.connector: spec for spec in (AMP_PLUGIN_SPEC, OPENCODE_PLUGIN_SPEC)}


def _normalized_absolute(path: str, label: str) -> str:
    if not isinstance(path, str) or not path or any(character in path for character in "\x00\r\n"):
        raise ValueError(f"{label} is empty or malformed")
    if not os.path.isabs(path):
        raise ValueError(f"{label} must be absolute")
    normalized = os.path.abspath(os.path.normpath(path))
    if path != normalized:
        raise ValueError(f"{label} must be normalized")
    return normalized


def _managed_plugin_home_and_backup(spec: ManagedPluginSpec, backup_path: str) -> tuple[str, str]:
    """Bind backup authority to one fixed location beneath a user home."""

    backup = _normalized_absolute(backup_path, f"{spec.label} backup path")
    suffix_parts = spec.backup_suffix.split(os.sep)
    backup_parts = backup.split(os.sep)
    if len(backup_parts) <= len(suffix_parts) or backup_parts[-len(suffix_parts) :] != suffix_parts:
        raise ValueError(f"{spec.label} backup path is outside the expected connector backup location")
    home_parts = backup_parts[: -len(suffix_parts)]
    home = os.sep.join(home_parts) or os.sep
    if not home.startswith(os.sep) or home == os.sep:
        raise ValueError(f"{spec.label} backup path does not identify a safe user home")
    expected_backup = os.path.join(home, spec.backup_suffix)
    if backup != expected_backup:
        raise ValueError(f"{spec.label} backup path is outside the expected connector backup location")
    return home, backup


def _resolve_managed_plugin_target(
    spec: ManagedPluginSpec,
    home: str,
    requested_path: str,
    captured_path: str,
) -> str:
    """Resolve an explicit or authority-derived plugin path without fallback."""

    captured = _normalized_absolute(captured_path, f"captured {spec.label} plugin path")
    if requested_path == MANAGED_TARGET_FROM_AUTHORITY:
        if not spec.target_from_authority:
            raise ValueError(f"{spec.label} cleanup does not support authority-derived targets")
        plugin = captured
    else:
        plugin = _normalized_absolute(requested_path, f"{spec.label} plugin path")
        if plugin != captured:
            raise ValueError(f"{spec.label} backup target path does not match the managed plugin")

    if spec.target_from_authority:
        if os.path.basename(plugin) != "defenseclaw.js" or os.path.basename(os.path.dirname(plugin)) != "plugins":
            raise ValueError(f"{spec.label} backup target is not its exact managed plugin filename")
    elif plugin != os.path.join(home, spec.target_suffix):
        raise ValueError(f"{spec.label} plugin/backup paths do not belong to the same user home")
    return plugin


def _stable_file_metadata(info: os.stat_result) -> tuple[object, ...]:
    """Return mutation-relevant metadata without access-time noise."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
        getattr(info, "st_flags", None),
    )


def _same_stable_file_metadata(expected: os.stat_result, current: os.stat_result) -> bool:
    return os.path.samestat(expected, current) and _stable_file_metadata(expected) == _stable_file_metadata(current)


def _require_stable_file_metadata(expected: os.stat_result, current: os.stat_result, label: str) -> None:
    if not _same_stable_file_metadata(expected, current):
        raise OSError(f"{label} changed during cleanup")


def _validate_darwin_acl_output(output: str, path: str, label: str, *, private: bool) -> None:
    """Parse fixed-locale ``/bin/ls -lde`` output without accepting unknown ACEs."""

    lines = output.splitlines()
    mode_field = lines[0].split(maxsplit=1)[0] if lines else ""
    if DARWIN_LS_MODE_RE.fullmatch(mode_field) is None:
        raise OSError(f"cannot interpret {label} macOS ACL: {path}")

    acl_lines: list[str] = []
    for line in lines[1:]:
        normalized = line.strip().lower()
        if not normalized:
            continue
        entry = re.fullmatch(r"(\d+):\s+(.+)", normalized)
        if entry is None or int(entry.group(1)) != len(acl_lines):
            raise OSError(f"cannot interpret {label} macOS ACL: {path}")
        acl_lines.append(normalized)

    # ``ls -lde`` marks an ACL with ``+``; ``@`` means extended
    # attributes without an ACL. Refuse output whose marker and entries
    # disagree rather than silently discarding an unfamiliar line shape.
    if mode_field.endswith("+") != bool(acl_lines):
        raise OSError(f"cannot interpret {label} macOS ACL: {path}")
    for line in acl_lines:
        padded = f" {line} "
        allow_index = padded.rfind(" allow ")
        deny_index = padded.rfind(" deny ")
        if allow_index > deny_index:
            disposition = "allow"
            disposition_index = allow_index
        elif deny_index > allow_index:
            disposition = "deny"
            disposition_index = deny_index
        else:
            raise OSError(f"cannot interpret {label} macOS ACL: {path}")

        permissions_text = padded[
            disposition_index + len(disposition) + 2 :
        ].strip()
        if re.fullmatch(r"[a-z_]+(?:,[a-z_]+)*", permissions_text) is None:
            raise OSError(f"cannot interpret {label} macOS ACL: {path}")
        granted = {permission.strip() for permission in permissions_text.split(",")}
        if not granted or not granted <= DARWIN_ACL_PERMISSIONS:
            raise OSError(f"cannot interpret {label} macOS ACL: {path}")
        if disposition == "deny":
            continue
        if private:
            raise OSError(f"{label} has an allow ACL entry: {path}")
        if granted & DARWIN_WRITE_ACL_PERMISSIONS:
            raise OSError(f"{label} has a write-capable ACL: {path}")


def _validate_darwin_acl(path: str, before: os.stat_result, label: str, *, private: bool) -> None:
    """Reject write-capable (or any private-authority allow) macOS ACL."""

    if sys.platform != "darwin":
        return
    try:
        result = subprocess.run(
            ["/bin/ls", "-lde", "--", path],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"cannot inspect {label} macOS ACL: {path}") from exc
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise OSError(f"cannot revalidate {label} after ACL inspection: {path}") from exc
    if not _same_stable_file_metadata(before, after):
        raise OSError(f"{label} changed during ACL inspection: {path}")
    if result.returncode != 0:
        raise OSError(f"cannot inspect {label} macOS ACL: {path}")
    _validate_darwin_acl_output(result.stdout, path, label, private=private)


def _validate_owned_directory(path: str, label: str, *, private: bool = False) -> None:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError(f"unsafe non-directory or symlink in {label} path: {path}")
    if info.st_uid != os.geteuid():
        raise OSError(f"{label} path is not owned by the target user: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if private and mode & 0o077:
        raise OSError(f"{label} private path has broad permissions: {path}")
    if mode & 0o022:
        raise OSError(f"{label} path is group/other writable: {path}")
    _validate_darwin_acl(path, info, f"{label} directory", private=private)


def _validate_managed_plugin_backup_chain(spec: ManagedPluginSpec, home: str) -> None:
    # Validate every user-controlled component used below. The parent of HOME
    # is administered by macOS; starting at HOME also keeps this helper
    # testable under a private temporary directory.
    relatives = [""]
    for suffix in (os.path.dirname(spec.backup_suffix),):
        current = ""
        for component in suffix.split(os.sep):
            current = os.path.join(current, component)
            if current not in relatives:
                relatives.append(current)
    for relative in relatives:
        _validate_owned_directory(
            os.path.join(home, relative) if relative else home,
            spec.label,
            # The writer explicitly protects the final per-connector
            # authority directory. Older installs may have non-writable 0755
            # intermediate state directories, so do not invent a migration
            # requirement for those ancestors during uninstall.
            private=relative == os.path.dirname(spec.backup_suffix),
        )


def _trusted_system_directory_symlink(path: str, info: os.stat_result) -> bool:
    if info.st_uid != 0:
        return False
    try:
        parent = os.lstat(os.path.dirname(path))
    except OSError:
        return False
    return stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not (stat.S_IMODE(parent.st_mode) & 0o022)


def _validate_managed_plugin_target_chain_once(spec: ManagedPluginSpec, clean: str) -> None:
    trusted_owners = {0, os.geteuid()}
    current = clean
    while True:
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            trusted_darwin_alias = sys.platform == "darwin" and current in {"/etc", "/tmp", "/var"}
            if current == clean or not (trusted_darwin_alias or _trusted_system_directory_symlink(current, info)):
                raise OSError(f"unsafe directory symlink in {spec.label} target path: {current}")
            current = os.path.dirname(current)
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(f"unsafe non-directory in {spec.label} target path: {current}")
        writable = bool(stat.S_IMODE(info.st_mode) & 0o022)
        trusted_sticky = current != clean and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if info.st_uid not in trusted_owners or (writable and not trusted_sticky):
            raise OSError(f"{spec.label} target directory has unsafe custody: {current}")
        _validate_darwin_acl(current, info, f"{spec.label} target directory", private=False)
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def _validate_managed_plugin_target_chain(spec: ManagedPluginSpec, plugin_path: str) -> None:
    """Validate lexical and resolved target directory chains."""

    parent = os.path.dirname(plugin_path)
    _validate_managed_plugin_target_chain_once(spec, parent)
    resolved = os.path.realpath(parent)
    if resolved != parent:
        _validate_managed_plugin_target_chain_once(spec, resolved)


def _open_regular_file(path: str, *, private: bool, max_bytes: int, label: str) -> tuple[int, os.stat_result]:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError(f"unsafe non-regular or symlinked file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not os.path.samestat(before, info):
            raise OSError(f"file identity changed or is hard-linked: {path}")
        if info.st_uid != os.geteuid():
            raise OSError(f"file is not owned by the target user: {path}")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise OSError(f"file is group/other writable: {path}")
        if private and stat.S_IMODE(info.st_mode) & 0o077:
            raise OSError(f"managed backup authority is not private: {path}")
        _validate_darwin_acl(path, before, label, private=private)
        current = os.lstat(path)
        if not _same_stable_file_metadata(info, current):
            raise OSError(f"file changed after ACL inspection: {path}")
        if info.st_size > max_bytes:
            raise OSError(f"file exceeds the {label} cleanup size bound: {path}")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _read_fd_bounded(
    fd: int,
    expected_info: os.stat_result,
    max_bytes: int,
    label: str,
) -> bytes:
    before = os.fstat(fd)
    _require_stable_file_metadata(expected_info, before, label)
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > max_bytes:
        raise OSError(f"file exceeds the {label} cleanup size bound")
    after = os.fstat(fd)
    _require_stable_file_metadata(expected_info, after, label)
    return payload


def _revalidate_open_file_digest(
    fd: int,
    expected_info: os.stat_result,
    expected_digest: str,
    max_bytes: int,
    label: str,
) -> None:
    payload = _read_fd_bounded(fd, expected_info, max_bytes, label)
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise OSError(f"{label} content changed during cleanup")


def _parse_managed_plugin_backup(spec: ManagedPluginSpec, payload: bytes) -> tuple[str, bool, int, bytes, str]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {spec.label} backup JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{spec.label} backup must be a JSON object")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != MANAGED_PLUGIN_BACKUP_VERSION:
        raise ValueError(f"{spec.label} backup version is missing or unsupported")
    if document.get("connector") != spec.connector or document.get("logical_name") != spec.logical_name:
        raise ValueError(f"{spec.label} backup connector identity is invalid")
    captured = _normalized_absolute(document.get("path", ""), f"captured {spec.label} plugin path")

    post_hash = document.get("post_sha256")
    if not isinstance(post_hash, str) or SHA256_RE.fullmatch(post_hash) is None:
        raise ValueError(f"{spec.label} backup post hash is missing or invalid")
    existed = document.get("existed")
    if not isinstance(existed, bool):
        raise ValueError(f"{spec.label} backup existed flag is invalid")
    mode = document.get("mode", 0)
    if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0 or mode > 0o777:
        raise ValueError(f"{spec.label} backup mode is invalid")

    pristine_hash = document.get("pristine_sha256")
    pristine_encoded = document.get("pristine_bytes", "")
    if not isinstance(pristine_encoded, str):
        raise ValueError(f"{spec.label} backup pristine payload is invalid")
    try:
        pristine = base64.b64decode(pristine_encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{spec.label} backup pristine payload is not canonical base64") from exc
    if len(pristine) > spec.max_bytes:
        raise ValueError(f"{spec.label} backup pristine payload exceeds its size bound")

    if existed:
        if not isinstance(pristine_hash, str) or SHA256_RE.fullmatch(pristine_hash) is None:
            raise ValueError(f"{spec.label} backup pristine hash is invalid")
        if hashlib.sha256(pristine).hexdigest() != pristine_hash:
            raise ValueError(f"{spec.label} backup pristine payload hash does not match")
        if mode == 0:
            mode = 0o600
    else:
        if pristine_hash != "missing" or pristine:
            raise ValueError(f"{spec.label} missing-file backup carries invalid pristine state")
        if mode != 0:
            raise ValueError(f"{spec.label} missing-file backup carries an invalid mode")
        mode = 0
    return captured, existed, mode, pristine, post_hash


def _hash_open_file(
    fd: int,
    expected_info: os.stat_result,
    max_bytes: int,
    label: str,
) -> str:
    payload = _read_fd_bounded(fd, expected_info, max_bytes, label)
    return hashlib.sha256(payload).hexdigest()


def _replace_managed_plugin(
    spec: ManagedPluginSpec,
    plugin_path: str,
    plugin_fd: int,
    plugin_info: os.stat_result,
    expected_hash: str,
    pristine: bytes,
    mode: int,
) -> None:
    parent = os.path.dirname(plugin_path)
    name = os.path.basename(plugin_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(parent, directory_flags)
    temporary = f".{name}.defenseclaw-restore.{os.getpid()}.{secrets.token_hex(8)}"
    temporary_fd = -1
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not _same_stable_file_metadata(plugin_info, named):
            raise OSError(f"{spec.label} plugin changed after its hash was verified")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(temporary, flags, mode, dir_fd=directory_fd)
        view = memoryview(pristine)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise OSError(f"short write while restoring {spec.label} plugin")
            view = view[written:]
        os.fchmod(temporary_fd, mode)
        os.fsync(temporary_fd)
        # Re-read the still-open source descriptor and then re-check its name
        # immediately before the atomic replace. Identity alone does not catch
        # an editor writing new bytes through the same inode.
        _revalidate_open_file_digest(
            plugin_fd,
            plugin_info,
            expected_hash,
            spec.max_bytes,
            f"{spec.label} plugin",
        )
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not _same_stable_file_metadata(plugin_info, named):
            raise OSError(f"{spec.label} plugin changed before its atomic restore")
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = ""
        os.fsync(directory_fd)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


def _remove_managed_plugin(
    spec: ManagedPluginSpec,
    plugin_path: str,
    plugin_fd: int,
    plugin_info: os.stat_result,
    expected_hash: str,
) -> None:
    parent = os.path.dirname(plugin_path)
    name = os.path.basename(plugin_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(parent, directory_flags)
    try:
        _revalidate_open_file_digest(
            plugin_fd,
            plugin_info,
            expected_hash,
            spec.max_bytes,
            f"{spec.label} plugin",
        )
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not _same_stable_file_metadata(plugin_info, named):
            raise OSError(f"{spec.label} plugin changed after its hash was verified")
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _consume_managed_plugin_authority(
    spec: ManagedPluginSpec,
    backup: str,
    backup_fd: int,
    backup_info: os.stat_result,
    expected_hash: str,
) -> None:
    """Consume only the unchanged private receipt and durably sync its parent."""

    _revalidate_open_file_digest(
        backup_fd,
        backup_info,
        expected_hash,
        spec.max_bytes,
        f"{spec.label} backup authority",
    )
    current_backup = os.lstat(backup)
    if not stat.S_ISREG(current_backup.st_mode) or not _same_stable_file_metadata(backup_info, current_backup):
        raise OSError(f"{spec.label} backup authority changed during cleanup")
    parent = os.path.dirname(backup)
    name = os.path.basename(backup)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(parent, directory_flags)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not _same_stable_file_metadata(backup_info, named):
            raise OSError(f"{spec.label} backup authority changed before cleanup commit")
        _revalidate_open_file_digest(
            backup_fd,
            backup_info,
            expected_hash,
            spec.max_bytes,
            f"{spec.label} backup authority",
        )
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not _same_stable_file_metadata(backup_info, named):
            raise OSError(f"{spec.label} backup authority changed before cleanup commit")
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def scrub_managed_plugin(
    spec: ManagedPluginSpec,
    path: str,
    backup_path: str,
    *,
    retain_authority: bool = False,
) -> tuple[bool, str | None]:
    """Restore/remove a managed plugin only under exact backup authority.

    Unlike the structured connector configs above, marker-based surgery is
    unsafe for a standalone TypeScript program. The backup identity binds the
    connector, logical name, target path, pristine bytes, and exact
    post-install hash. Drift or any unsafe path/file shape is a hard refusal.
    """
    home, backup = _managed_plugin_home_and_backup(spec, backup_path)
    _validate_managed_plugin_backup_chain(spec, home)

    backup_fd, backup_info = _open_regular_file(backup, private=True, max_bytes=spec.max_bytes, label=spec.label)
    try:
        payload = _read_fd_bounded(
            backup_fd,
            backup_info,
            spec.max_bytes,
            f"{spec.label} backup authority",
        )
        backup_hash = hashlib.sha256(payload).hexdigest()
        captured, existed, mode, pristine, post_hash = _parse_managed_plugin_backup(spec, payload)

        plugin_path = _resolve_managed_plugin_target(spec, home, path, captured)

        if not os.path.lexists(plugin_path):
            if existed:
                raise OSError(f"{spec.label} target is missing but its backup requires an exact restore")
            _revalidate_open_file_digest(
                backup_fd,
                backup_info,
                backup_hash,
                spec.max_bytes,
                f"{spec.label} backup authority",
            )
            if not retain_authority:
                _consume_managed_plugin_authority(
                    spec,
                    backup,
                    backup_fd,
                    backup_info,
                    backup_hash,
                )
            return True, None

        _validate_managed_plugin_target_chain(spec, plugin_path)

        plugin_fd, plugin_info = _open_regular_file(
            plugin_path,
            private=False,
            max_bytes=spec.max_bytes,
            label=spec.label,
        )
        try:
            current_hash = _hash_open_file(
                plugin_fd,
                plugin_info,
                spec.max_bytes,
                f"{spec.label} plugin",
            )
            pristine_hash = hashlib.sha256(pristine).hexdigest() if existed else ""
            already_restored = (
                existed
                and current_hash == pristine_hash
                and stat.S_IMODE(plugin_info.st_mode) == mode
            )
            if current_hash != post_hash and not already_restored:
                return False, (f"{spec.label} plugin drifted after setup; preserving it and its backup")

            # The private receipt is the only authority for a whole-file
            # mutation. Re-read it after target inspection so an in-place
            # same-inode edit cannot authorize stale captured data.
            _revalidate_open_file_digest(
                backup_fd,
                backup_info,
                backup_hash,
                spec.max_bytes,
                f"{spec.label} backup authority",
            )
            if already_restored:
                _revalidate_open_file_digest(
                    plugin_fd,
                    plugin_info,
                    current_hash,
                    spec.max_bytes,
                    f"{spec.label} plugin",
                )
            elif existed:
                _replace_managed_plugin(
                    spec,
                    plugin_path,
                    plugin_fd,
                    plugin_info,
                    current_hash,
                    pristine,
                    mode,
                )
            else:
                _remove_managed_plugin(
                    spec,
                    plugin_path,
                    plugin_fd,
                    plugin_info,
                    current_hash,
                )
        finally:
            os.close(plugin_fd)

        if retain_authority:
            _revalidate_open_file_digest(
                backup_fd,
                backup_info,
                backup_hash,
                spec.max_bytes,
                f"{spec.label} backup authority",
            )
        else:
            _consume_managed_plugin_authority(
                spec,
                backup,
                backup_fd,
                backup_info,
                backup_hash,
            )
        return True, None
    finally:
        os.close(backup_fd)


def scrub_amp(path: str, backup_path: str) -> tuple[bool, str | None]:
    return scrub_managed_plugin(AMP_PLUGIN_SPEC, path, backup_path)


def scrub_opencode(path: str, backup_path: str) -> tuple[bool, str | None]:
    return scrub_managed_plugin(OPENCODE_PLUGIN_SPEC, path, backup_path)


# ---------- dispatch -----------------------------------------------------


HANDLERS = {
    "cursor": scrub_cursor,
    "claudecode": scrub_claudecode,
    "codex": scrub_codex,
}


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    connector = argv[1]
    path = argv[2]
    managed_spec = MANAGED_PLUGIN_SPECS.get(connector)
    if managed_spec is not None:
        retain_authority = len(argv) == 5 and argv[4] == MANAGED_RETAIN_AUTHORITY
        if len(argv) not in {4, 5} or not argv[3] or (len(argv) == 5 and not retain_authority):
            print(
                f"{managed_spec.label} cleanup requires its managed backup metadata path",
                file=sys.stderr,
            )
            return 4
        authority_target = path == MANAGED_TARGET_FROM_AUTHORITY and managed_spec.target_from_authority
        if not os.path.lexists(argv[3]):
            if authority_target or not os.path.lexists(path):
                return 2
            print(
                f"scrub failed for {path}: {managed_spec.label} backup authority is missing",
                file=sys.stderr,
            )
            return 4
        try:
            ok, err = scrub_managed_plugin(
                managed_spec,
                path,
                argv[3],
                retain_authority=retain_authority,
            )
        except (OSError, ValueError) as e:
            print(f"scrub failed for {path}: {e}", file=sys.stderr)
            return 4
        if not ok:
            print(f"scrub skipped: {err}", file=sys.stderr)
            return 4
        return 0

    markers = list(DEFAULT_MARKERS)
    if len(argv) >= 4 and argv[3]:
        markers.insert(0, argv[3])
    markers_t = tuple(markers)

    handler = HANDLERS.get(connector)
    if handler is None:
        print(f"unsupported connector: {connector}", file=sys.stderr)
        return 3
    if not os.path.exists(path):
        return 2
    try:
        ok, err = handler(path, markers_t)
    except (OSError, ValueError) as e:
        print(f"scrub failed for {path}: {e}", file=sys.stderr)
        return 4
    if not ok:
        print(f"scrub skipped: {err}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
