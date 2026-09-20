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

Exit codes:
  0   — file successfully scrubbed (or no changes were needed)
  2   — file missing (nothing to do)
  3   — unsupported connector
  4   — file unreadable / parse failure (left untouched)

Usage:
  scrub_agent_configs.py CONNECTOR FILE [DATADIR_PATTERN|AMP_BACKUP_FILE]
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
import sys

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
    with open(path, "r", encoding="utf-8") as f:
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
CLAUDE_MANAGED_ENV_KEYS = frozenset({
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
})


def scrub_claudecode(path: str, markers: tuple[str, ...]) -> tuple[bool, str | None]:
    """Drop DefenseClaw entries from ~/.claude/settings.json.

    Shape: { "hooks": { "<event>": [ {"hooks":[{entry}, ...]}, ... ] } }
    Nested one level deeper than Cursor's; otherwise the same idea.
    Also strips DefenseClaw-owned keys from the top-level "env" block
    (kept in sync with claudeCodeOtelEnvKeys in the Go connector), and
    strips any additional env value that references our data-dir markers.
    Non-DefenseClaw env entries are preserved.
    """
    with open(path, "r", encoding="utf-8") as f:
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
        with open(path, "r", encoding="utf-8") as f:
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


# ---------- managed plugin: Amp -----------------------------------------


AMP_BACKUP_VERSION = 1
AMP_BACKUP_SUFFIX = os.path.join(
    ".defenseclaw", "connector_backups", "amp", "config.json"
)
AMP_PLUGIN_SUFFIX = os.path.join(
    ".config", "amp", "plugins", "defenseclaw.ts"
)
AMP_MAX_BACKUP_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _normalized_absolute(path: str, label: str) -> str:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError(f"{label} is empty or malformed")
    if not os.path.isabs(path):
        raise ValueError(f"{label} must be absolute")
    return os.path.abspath(os.path.normpath(path))


def _amp_home_and_paths(plugin_path: str, backup_path: str) -> tuple[str, str, str]:
    """Bind both inputs to the two fixed per-user Amp/DefenseClaw locations."""
    plugin = _normalized_absolute(plugin_path, "Amp plugin path")
    backup = _normalized_absolute(backup_path, "Amp backup path")
    suffix_parts = AMP_BACKUP_SUFFIX.split(os.sep)
    backup_parts = backup.split(os.sep)
    if (
        len(backup_parts) <= len(suffix_parts)
        or backup_parts[-len(suffix_parts):] != suffix_parts
    ):
        raise ValueError(
            "Amp backup path is outside the expected connector backup location"
        )
    home_parts = backup_parts[:-len(suffix_parts)]
    home = os.sep.join(home_parts) or os.sep
    if not home.startswith(os.sep) or home == os.sep:
        raise ValueError("Amp backup path does not identify a safe user home")
    expected_backup = os.path.join(home, AMP_BACKUP_SUFFIX)
    expected_plugin = os.path.join(home, AMP_PLUGIN_SUFFIX)
    if backup != expected_backup or plugin != expected_plugin:
        raise ValueError("Amp plugin/backup paths do not belong to the same user home")
    return home, plugin, backup


def _validate_owned_directory(path: str) -> None:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError(f"unsafe non-directory or symlink in Amp path: {path}")
    if info.st_uid != os.geteuid():
        raise OSError(f"Amp path is not owned by the target user: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise OSError(f"Amp path is group/other writable: {path}")


def _validate_amp_directory_chains(home: str) -> None:
    # Validate every user-controlled component used below. The parent of HOME
    # is administered by macOS; starting at HOME also keeps this helper
    # testable under a private temporary directory.
    for relative in (
        "",
        ".config",
        os.path.join(".config", "amp"),
        os.path.join(".config", "amp", "plugins"),
        ".defenseclaw",
        os.path.join(".defenseclaw", "connector_backups"),
        os.path.join(".defenseclaw", "connector_backups", "amp"),
    ):
        _validate_owned_directory(
            os.path.join(home, relative) if relative else home
        )


def _open_regular_file(
    path: str, *, private: bool, max_bytes: int
) -> tuple[int, os.stat_result]:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError(f"unsafe non-regular or symlinked file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not os.path.samestat(before, info)
        ):
            raise OSError(f"file identity changed or is hard-linked: {path}")
        if info.st_uid != os.geteuid():
            raise OSError(f"file is not owned by the target user: {path}")
        if private and stat.S_IMODE(info.st_mode) & 0o077:
            raise OSError(f"managed backup authority is not private: {path}")
        if info.st_size > max_bytes:
            raise OSError(f"file exceeds the Amp cleanup size bound: {path}")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def _read_fd_bounded(fd: int, max_bytes: int) -> bytes:
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
        raise OSError("file exceeds the Amp cleanup size bound")
    return payload


def _parse_amp_backup(
    payload: bytes, plugin_path: str
) -> tuple[bool, int, bytes, str]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Amp backup JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("Amp backup must be a JSON object")
    version = document.get("version")
    if isinstance(version, bool) or version != AMP_BACKUP_VERSION:
        raise ValueError("Amp backup version is missing or unsupported")
    if document.get("connector") != "amp" or document.get("logical_name") != "config":
        raise ValueError("Amp backup connector identity is invalid")
    captured = _normalized_absolute(
        document.get("path", ""), "captured Amp plugin path"
    )
    if captured != plugin_path:
        raise ValueError("Amp backup target path does not match the managed plugin")

    post_hash = document.get("post_sha256")
    if not isinstance(post_hash, str) or SHA256_RE.fullmatch(post_hash) is None:
        raise ValueError("Amp backup post hash is missing or invalid")
    existed = document.get("existed")
    if not isinstance(existed, bool):
        raise ValueError("Amp backup existed flag is invalid")
    mode = document.get("mode", 0)
    if (
        isinstance(mode, bool)
        or not isinstance(mode, int)
        or mode < 0
        or mode > 0o777
    ):
        raise ValueError("Amp backup mode is invalid")

    pristine_hash = document.get("pristine_sha256")
    pristine_encoded = document.get("pristine_bytes", "")
    if not isinstance(pristine_encoded, str):
        raise ValueError("Amp backup pristine payload is invalid")
    try:
        pristine = base64.b64decode(pristine_encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Amp backup pristine payload is not canonical base64") from exc
    if len(pristine) > AMP_MAX_BACKUP_BYTES:
        raise ValueError("Amp backup pristine payload exceeds its size bound")

    if existed:
        if (
            not isinstance(pristine_hash, str)
            or SHA256_RE.fullmatch(pristine_hash) is None
        ):
            raise ValueError("Amp backup pristine hash is invalid")
        if hashlib.sha256(pristine).hexdigest() != pristine_hash:
            raise ValueError("Amp backup pristine payload hash does not match")
        if mode == 0:
            mode = 0o600
    else:
        if pristine_hash != "missing" or pristine:
            raise ValueError("Amp missing-file backup carries invalid pristine state")
        mode = 0
    return existed, mode, pristine, post_hash


def _hash_open_file(fd: int) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 64 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def _replace_amp_plugin(
    plugin_path: str,
    plugin_info: os.stat_result,
    pristine: bytes,
    mode: int,
) -> None:
    parent = os.path.dirname(plugin_path)
    name = os.path.basename(plugin_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    directory_fd = os.open(parent, directory_flags)
    temporary = (
        f".{name}.defenseclaw-restore.{os.getpid()}.{secrets.token_hex(8)}"
    )
    temporary_fd = -1
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not os.path.samestat(
            plugin_info, named
        ):
            raise OSError("Amp plugin changed after its hash was verified")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(
            os, "O_CLOEXEC", 0
        )
        flags |= getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(temporary, flags, mode, dir_fd=directory_fd)
        view = memoryview(pristine)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise OSError("short write while restoring Amp plugin")
            view = view[written:]
        os.fchmod(temporary_fd, mode)
        os.fsync(temporary_fd)
        # Re-check immediately before the atomic replace. This refuses to
        # overwrite a file that drifted during cleanup.
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not os.path.samestat(
            plugin_info, named
        ):
            raise OSError("Amp plugin changed before its atomic restore")
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


def _remove_amp_plugin(plugin_path: str, plugin_info: os.stat_result) -> None:
    parent = os.path.dirname(plugin_path)
    name = os.path.basename(plugin_path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    directory_fd = os.open(parent, directory_flags)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or not os.path.samestat(
            plugin_info, named
        ):
            raise OSError("Amp plugin changed after its hash was verified")
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def scrub_amp(path: str, backup_path: str) -> tuple[bool, str | None]:
    """Restore/remove the managed Amp plugin only under exact backup authority.

    Unlike the structured connector configs above, marker-based surgery is
    unsafe for a standalone TypeScript program. The backup identity binds the
    connector, logical name, target path, pristine bytes, and exact
    post-install hash. Drift or any unsafe path/file shape is a hard refusal.
    """
    home, plugin_path, backup = _amp_home_and_paths(path, backup_path)
    _validate_amp_directory_chains(home)

    backup_fd, backup_info = _open_regular_file(
        backup, private=True, max_bytes=AMP_MAX_BACKUP_BYTES
    )
    try:
        payload = _read_fd_bounded(backup_fd, AMP_MAX_BACKUP_BYTES)
        existed, mode, pristine, post_hash = _parse_amp_backup(
            payload, plugin_path
        )
    finally:
        os.close(backup_fd)

    plugin_fd, plugin_info = _open_regular_file(
        plugin_path, private=False, max_bytes=AMP_MAX_BACKUP_BYTES
    )
    try:
        if _hash_open_file(plugin_fd) != post_hash:
            return False, "Amp plugin drifted after setup; preserving it and its backup"
        if existed:
            _replace_amp_plugin(plugin_path, plugin_info, pristine, mode)
        else:
            _remove_amp_plugin(plugin_path, plugin_info)
    finally:
        os.close(plugin_fd)

    # Remove only the exact authority file we opened. A concurrent replacement
    # is preserved and reported instead of unlinking by pathname.
    current_backup = os.lstat(backup)
    if not stat.S_ISREG(current_backup.st_mode) or not os.path.samestat(
        backup_info, current_backup
    ):
        raise OSError("Amp backup authority changed during cleanup")
    os.unlink(backup)
    return True, None


# ---------- dispatch -----------------------------------------------------


HANDLERS = {
    "cursor":     scrub_cursor,
    "claudecode": scrub_claudecode,
    "codex":      scrub_codex,
}


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    connector = argv[1]
    path = argv[2]
    if connector == "amp":
        if len(argv) != 4 or not argv[3]:
            print(
                "Amp cleanup requires its managed backup metadata path",
                file=sys.stderr,
            )
            return 4
        if not os.path.lexists(path):
            return 2
        try:
            ok, err = scrub_amp(path, argv[3])
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
