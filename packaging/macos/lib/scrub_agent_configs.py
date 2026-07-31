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

Exit codes:
  0   — file successfully scrubbed (or no changes were needed)
  2   — file missing (nothing to do)
  3   — unsupported connector
  4   — file unreadable / parse failure (left untouched)
  5   — managed OpenCode plugin drifted (plugin and backup preserved)

Usage:
  scrub_agent_configs.py CONNECTOR FILE [DATADIR_PATTERN_OR_BACKUP]
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
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


# ---------- whole-file plugin: OpenCode ---------------------------------


def _read_regular_nofollow(path: str, limit: int = 2 * 1024 * 1024) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("not a single-link regular file")
        if info.st_size > limit:
            raise ValueError("file exceeds managed restore limit")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError("file exceeds managed restore limit")
        return data
    finally:
        os.close(fd)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_opencode_target(path: object) -> str | None:
    """Return the absolute, cleaned path shape stored by the Go backup code."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return None
    try:
        return os.path.normpath(os.path.abspath(path))
    except (OSError, ValueError):
        return None


def restore_opencode(backup_path: str, expected_target: str) -> tuple[bool, str | None]:
    """Restore OpenCode's whole-file plugin only when it still matches the
    exact bytes DefenseClaw installed. A drifted plugin is preserved so purge
    cannot erase user changes or delete the only pristine snapshot. The backup
    target must also match the explicit plugin path selected by the caller."""
    backup_raw = _read_regular_nofollow(backup_path)
    backup = json.loads(backup_raw.decode("utf-8"))
    if not isinstance(backup, dict):
        return False, "backup is not an object"
    if (
        backup.get("version") != 1
        or backup.get("connector") != "opencode"
        or backup.get("logical_name") != "config"
    ):
        return False, "backup identity mismatch"

    target = _normalize_opencode_target(backup.get("path"))
    if target is None:
        return False, "backup target is not absolute"
    requested_target = _normalize_opencode_target(expected_target)
    if requested_target is None:
        return False, "requested OpenCode plugin target is not absolute"
    if target != requested_target:
        return False, "backup target does not match requested OpenCode plugin"
    if os.path.basename(target) != "defenseclaw.js" or os.path.basename(os.path.dirname(target)) != "plugins":
        return False, "backup target is not an OpenCode plugin path"
    parent = os.path.dirname(target)
    parent_info = os.lstat(parent)
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
        return False, "plugin parent is not a direct directory"

    expected = backup.get("post_sha256") or backup.get("pristine_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}|missing", expected):
        return False, "backup post hash is invalid"
    try:
        current = _read_regular_nofollow(target)
        current_hash = _sha256(current)
    except FileNotFoundError:
        current_hash = "missing"
    if current_hash != expected:
        return False, "managed OpenCode plugin changed after Setup"

    if backup.get("existed") is True:
        encoded = backup.get("pristine_bytes")
        pristine_hash = backup.get("pristine_sha256")
        if not isinstance(encoded, str) or not isinstance(pristine_hash, str):
            return False, "pristine snapshot is incomplete"
        pristine = base64.b64decode(encoded, validate=True)
        if _sha256(pristine) != pristine_hash:
            return False, "pristine snapshot hash mismatch"
        mode = backup.get("mode")
        mode = (mode if isinstance(mode, int) else 0o600) & 0o777
        if mode == 0:
            mode = 0o600
        temp = os.path.join(parent, f".defenseclaw.restore.{os.getpid()}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temp, flags, mode)
        try:
            view = memoryview(pristine)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while restoring plugin")
                view = view[written:]
            os.fsync(fd)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
        try:
            os.replace(temp, target)
        finally:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
    else:
        try:
            os.unlink(target)
        except FileNotFoundError:
            pass
    os.unlink(backup_path)
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
    if connector == "opencode":
        if len(argv) < 4 or not argv[3]:
            print("opencode restore requires a managed backup path", file=sys.stderr)
            return 4
        backup_path = argv[3]
        if not os.path.exists(backup_path):
            return 2
        try:
            ok, err = restore_opencode(backup_path, path)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
            print(f"restore failed for {path}: {e}", file=sys.stderr)
            return 4
        if not ok:
            print(f"restore skipped: {err}", file=sys.stderr)
            return 5 if err == "managed OpenCode plugin changed after Setup" else 4
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
