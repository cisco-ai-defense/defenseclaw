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

"""defenseclaw skill — Manage skills: scan, block, allow, list, disable, enable,
quarantine, restore, info, install.

Mirrors internal/cli/skill.go.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.commands import compute_verdict as _compute_verdict
from defenseclaw.context import AppContext, pass_ctx

_WINDOWS_LAUNCHER_EXTENSIONS = (".com", ".exe", ".bat", ".cmd")
_CLAWHUB_OUTPUT_LIMIT = 16 * 1024


def _windows_environment(name: str, default: str = "") -> str:
    for key, value in os.environ.items():
        if key.casefold() == name.casefold():
            return value
    return default


def _windows_launcher_extensions(pathext: str | None = None) -> tuple[str, ...]:
    """Return PATHEXT's safe executable subset, preserving its precedence."""
    raw = pathext if pathext is not None else _windows_environment("PATHEXT")
    requested = [item.strip().lower() for item in raw.split(";") if item.strip()]
    ordered = [item if item.startswith(".") else f".{item}" for item in requested]
    safe = [item for item in ordered if item in _WINDOWS_LAUNCHER_EXTENSIONS]
    for extension in _WINDOWS_LAUNCHER_EXTENSIONS:
        if extension not in safe:
            safe.append(extension)
    return tuple(safe)


def _case_insensitive_child(directory: str, filename: str) -> str | None:
    """Resolve one regular directory entry without executing or importing it."""
    try:
        entries = {entry.name.casefold(): entry for entry in os.scandir(directory)}
    except OSError:
        return None
    entry = entries.get(filename.casefold())
    if entry is None:
        return None
    try:
        if not entry.is_file():
            return None
    except OSError:
        return None
    return os.path.abspath(entry.path)


def _resolve_windows_launcher(
    binary: str,
    *,
    search_path: str | None = None,
    pathext: str | None = None,
) -> str | None:
    """Resolve a binary using Windows/PATHEXT semantics, never extensionless.

    npm installs both a Unix shell wrapper and Windows launchable siblings in
    ``node_modules/.bin``.  Only the allowlisted PATHEXT suffixes are eligible;
    their configured order is honored, with COM/EXE/BAT/CMD as deterministic
    fallbacks when PATHEXT is absent or incomplete.
    """
    directory, filename = os.path.split(binary)
    directories: list[str]
    if directory:
        directories = [directory]
    else:
        path_value = search_path if search_path is not None else _windows_environment("PATH")
        separator = ";" if ";" in path_value or os.pathsep == ";" else os.pathsep
        directories = [item.strip().strip('"') for item in path_value.split(separator) if item.strip()]

    _base, extension = os.path.splitext(filename)
    extensions = _windows_launcher_extensions(pathext)
    if extension:
        if extension.lower() not in extensions:
            return None
        candidate_names = [filename]
    else:
        candidate_names = [f"{filename}{item}" for item in extensions]

    for path_entry in directories:
        directory_path = os.path.abspath(path_entry or os.curdir)
        for candidate_name in candidate_names:
            found = _case_insensitive_child(directory_path, candidate_name)
            if found:
                return found
    return None


def _resolve_command(binary: str, *, local_first: bool = False) -> str | None:
    """Resolve an absolute executable path with platform-native semantics."""
    if os.name == "nt":
        if local_first:
            local = os.path.join(os.getcwd(), "node_modules", ".bin", binary)
            found = _resolve_windows_launcher(local)
            if found:
                return found
        return _resolve_windows_launcher(binary)

    if local_first:
        local = os.path.join(os.getcwd(), "node_modules", ".bin", binary)
        if os.path.isfile(local) and os.access(local, os.X_OK):
            return os.path.abspath(local)
    found = shutil.which(binary)
    return os.path.abspath(found) if found else None


def _trusted_windows_command_processor() -> str:
    """Return the system-owned command processor used only for CMD/BAT shims."""
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise OSError("Windows system directory is unavailable")
    command_processor = os.path.abspath(os.path.join(buffer.value, "cmd.exe"))
    if not os.path.isfile(command_processor):
        raise OSError("trusted Windows command processor was not found")
    return command_processor


def _cmd_environment_value(value: str) -> str:
    """Validate a value for quoted expansion by a fixed, non-user batch script."""
    if any(character in value for character in ('"', "\r", "\n", "\x00")):
        raise ValueError("Windows launcher arguments cannot contain quotes or line breaks")
    # Expansion happens once inside quotes with delayed expansion disabled.
    # The control script intentionally does not use CALL, which would trigger
    # a second expansion pass over percent signs and carets.
    return value


def _bounded_pipe_reader(pipe: Any, sink: bytearray) -> None:
    try:
        while chunk := pipe.read(8192):
            remaining = _CLAWHUB_OUTPUT_LIMIT - len(sink)
            if remaining > 0:
                sink.extend(chunk[:remaining])
    finally:
        pipe.close()


def _run_clawhub_process(
    argv: list[str],
    *,
    timeout: int,
    cwd: str | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an untrusted ClawHub launcher with bounded captured output.

    CMD/BAT files are interpreted by the trusted system ``cmd.exe``.  The
    command script is fixed text and all external values travel through a
    private environment after validation, so user input is never interpolated
    into a shell command string.  Delayed expansion is disabled and the child
    starts from an owned temporary working directory before the fixed script
    changes to the explicitly supplied staging directory.
    """
    import tempfile

    if not argv or not os.path.isabs(argv[0]):
        raise OSError("ClawHub launcher could not be resolved to an absolute path")

    child_argv = list(argv)
    child_env = os.environ.copy()
    launch_cwd = os.path.abspath(cwd) if cwd else None
    stdin_data = input_text.encode("utf-8") if input_text is not None else None

    with tempfile.TemporaryDirectory(prefix="defenseclaw-clawhub-launch-") as control_dir:
        if os.name == "nt" and os.path.splitext(argv[0])[1].lower() in {".cmd", ".bat"}:
            command_processor = _trusted_windows_command_processor()
            child_env["DEFENSECLAW_CLAWHUB_LAUNCHER"] = _cmd_environment_value(argv[0])
            child_env["DEFENSECLAW_CLAWHUB_CWD"] = _cmd_environment_value(launch_cwd or control_dir)
            placeholders: list[str] = []
            for index, argument in enumerate(argv[1:]):
                key = f"DEFENSECLAW_CLAWHUB_ARG_{index}"
                child_env[key] = _cmd_environment_value(argument)
                placeholders.append(f'"%{key}%"')
            script_path = os.path.join(control_dir, "launch.cmd")
            script = (
                "@echo off\r\n"
                'cd /d "%DEFENSECLAW_CLAWHUB_CWD%" || exit /b 1\r\n'
                '"%DEFENSECLAW_CLAWHUB_LAUNCHER%" ' + " ".join(placeholders) + "\r\n"
            )
            with open(script_path, "x", encoding="ascii", newline="") as handle:
                handle.write(script)
            child_argv = [command_processor, "/d", "/v:off", "/s", "/c", "launch.cmd"]
            launch_cwd = control_dir
        elif launch_cwd is None:
            launch_cwd = control_dir

        process = subprocess.Popen(
            child_argv,
            cwd=launch_cwd,
            env=child_env,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None and process.stderr is not None
        stdout = bytearray()
        stderr = bytearray()
        readers = [
            threading.Thread(target=_bounded_pipe_reader, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=_bounded_pipe_reader, args=(process.stderr, stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        if stdin_data is not None:
            assert process.stdin is not None
            process.stdin.write(stdin_data)
            process.stdin.close()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        finally:
            for reader in readers:
                reader.join()

    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _external_failure_detail(result: subprocess.CompletedProcess[str]) -> str:
    detail = (result.stderr or result.stdout).strip()
    if not detail:
        return f"exit status {result.returncode}"
    detail = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", detail)
    detail = re.sub(
        r"(?i)\b(token|secret|password|authorization|api[_-]?key)\b(\s*[:=]\s*)(\S+)",
        r"\1\2<redacted>",
        detail,
    )
    if len(detail.encode("utf-8")) >= _CLAWHUB_OUTPUT_LIMIT:
        detail += "\n[output truncated]"
    return detail




@click.group()
def skill() -> None:
    """Manage agent skills — search, install, scan, block, allow, disable, enable, quarantine, restore.

    Multi-connector: skills are tracked per-connector. ``skill list``
    and no-target ``skill scan`` cover every configured connector by default
    (pass ``--connector X`` to narrow to one peer). Policy commands accept
    ``--connector X`` to target one configured peer; bare allow/unblock apply
    to matching connector copies when present and otherwise keep the legacy
    unscoped policy behavior.
    """


# ---------------------------------------------------------------------------
# skill search
# ---------------------------------------------------------------------------

def _resolve_clawhub_search_argv(query: str, allow_remote_fetch: bool) -> list[str]:
    """Resolve the safest available launcher for ``clawhub search``.

    F-1481: ``skill search`` is a read-only, pre-admission lookup, but plain
    ``npx clawhub`` resolves and EXECUTES the third-party ``clawhub`` npm
    package — fetching it from the network on first use — so an attacker who
    controls (or typosquats) the registry entry runs code on the operator host
    just from a search. We reduce that exposure here:

      1. Prefer a locally-installed, pinned ``clawhub`` binary on PATH. Running
         an already-installed binary performs no network fetch of executable
         code, so the supply-chain decision was made at install time, not at
         search time.
      2. Otherwise fall back to ``npx --no-install clawhub``, which uses an
         already-cached package and REFUSES to fetch it from the network.
      3. Only when the operator explicitly opts in with --allow-remote-fetch do
         we permit plain ``npx`` to fetch+execute from the network.

    Residual risk (cannot be fully closed while delegating to the clawhub
    registry): even a locally-installed or npx-cached ``clawhub`` is third-party
    code, and the search itself queries a remote registry. --allow-remote-fetch
    re-opens the original fetch-and-execute-on-search exposure; it exists only
    as an explicit, documented operator decision.
    """
    local = _resolve_command("clawhub", local_first=True)
    if local:
        return [local, "search", query]
    npx = _resolve_command("npx")
    if not npx:
        raise OSError("neither a launchable clawhub nor npx executable was found")
    if allow_remote_fetch:
        # Explicit operator opt-in: npx may fetch+execute clawhub from the
        # network. This re-opens the F-1481 supply-chain exposure by design.
        return [npx, "clawhub", "search", query]
    # Default: never let npx silently fetch+execute from the network. With
    # --no-install npx uses only an already-cached package and errors out if it
    # would have to download one.
    return [npx, "--no-install", "clawhub", "search", query]


def _clawhub_unavailable(stderr: str) -> bool:
    """Heuristic: did ``npx clawhub`` fail because the clawhub package itself
    is missing or mispackaged, rather than because the search errored?

    The external clawhub npm package has shipped broken builds whose own
    Node entrypoint dies with ``ERR_MODULE_NOT_FOUND`` / ``Cannot find
    module`` before it ever runs the query. That is a packaging fault in
    clawhub, not a DefenseClaw bug, so we want to surface a concise hint
    instead of echoing the raw Node stack trace at the operator.
    """
    s = stderr.lower()
    return (
        "err_module_not_found" in s
        or "cannot find module" in s
        or "cannot find package" in s
    )


def _clawhub_args(*args: str) -> list[str]:
    """Prefer a real clawhub binary; fall back to npx for on-demand installs."""
    found = _resolve_command("clawhub", local_first=True)
    if found:
        return [found, *args]
    npx = _resolve_command("npx")
    if npx:
        return [npx, "clawhub", *args]
    raise OSError("neither a launchable clawhub nor npx executable was found")


@skill.command()
@click.argument("query")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@click.option(
    "--allow-remote-fetch",
    is_flag=True,
    help="Permit npx to fetch+execute the clawhub package from the network "
    "(supply-chain risk — see docs). Default: use a local/cached clawhub only.",
)
@pass_ctx
def search(app: AppContext, query: str, as_json: bool, allow_remote_fetch: bool) -> None:
    """Search the ClawHub skill registry (not local connector skills).

    Delegates to a locally-installed ``clawhub`` binary (or a cached
    ``npx clawhub``). This queries the remote ClawHub registry of
    installable skills — it does NOT list or search the skills already
    installed under a connector (use ``skill list`` for that).

    \b
    F-1481: by default this refuses to let ``npx`` fetch+execute the clawhub
    package from the network at search time; pass --allow-remote-fetch to opt
    into the original fetch-on-search behavior (supply-chain risk).

    \b
    Examples:
      defenseclaw skill search wiki
      defenseclaw skill search database --json
      defenseclaw skill search wiki --allow-remote-fetch
    """
    try:
        argv = _resolve_clawhub_search_argv(query, allow_remote_fetch)
        result = _run_clawhub_process(argv, timeout=30)
    except (OSError, ValueError) as exc:
        click.echo(
            "error: clawhub not found — install the clawhub binary, or install "
            f"Node.js (npx) and pass --allow-remote-fetch to fetch it ({exc})",
            err=True,
        )
        raise SystemExit(1)
    except subprocess.TimeoutExpired:
        click.echo("error: clawhub search timed out", err=True)
        raise SystemExit(1)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if _clawhub_unavailable(stderr):
            click.echo(
                "error: skill registry unavailable — the 'clawhub' CLI failed to "
                "load (it may be broken or not installed).\n"
                "  Try: npx clawhub --version",
                err=True,
            )
            raise SystemExit(1)
        hint = ""
        # F-1481: with --no-install, npx fails (rather than fetching) when the
        # clawhub package is not already cached. Point the operator at the
        # explicit opt-in rather than silently fetching+executing.
        if "--no-install" in argv:
            hint = (
                " (clawhub not installed/cached — install it or rerun with "
                "--allow-remote-fetch to fetch it from the network)"
            )
        click.echo(
            f"error: clawhub search failed: {stderr or 'unknown error'}{hint}",
            err=True,
        )
        raise SystemExit(1)

    output = result.stdout.strip()
    if not output:
        if as_json:
            click.echo(json.dumps([]))
            return
        click.echo(f"No skills found matching {query!r} in the ClawHub registry")
        return

    if as_json:
        rows = []
        for line in output.splitlines():
            parts = line.split(None, 2)
            if len(parts) >= 2:
                name = parts[0]
                score = ""
                description = parts[1] if len(parts) >= 2 else ""
                if description.startswith("(") and description.endswith(")"):
                    score = description
                    description = ""
                elif len(parts) >= 3:
                    description = parts[1]
                    score = parts[2] if len(parts) >= 3 else ""
                rows.append({"name": name, "description": description, "score": score.strip("()")})
        click.echo(json.dumps(rows, indent=2))
        return

    click.echo(ux.dim("ClawHub registry results (remote — not your installed skills):"))
    click.echo(output)


# ---------------------------------------------------------------------------
# OpenClaw helpers — sidecar API first, local `openclaw` binary as fallback
# ---------------------------------------------------------------------------

def _run_openclaw(*args: str) -> str | None:
    """Run an openclaw CLI command and return the JSON body, or None on failure.

    OpenClaw may write JSON to stdout or stderr (and stderr may contain
    Node.js warnings around the JSON).  We try both streams, falling back
    to substring extraction when the whole stream isn't valid JSON.
    """
    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
        prefix = openclaw_cmd_prefix()
        result = subprocess.run(
            [*prefix, openclaw_bin(), *args],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    for stream in (result.stdout, result.stderr):
        text = (stream or "").strip()
        if not text:
            continue
        # Fast path: entire stream is valid JSON
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass
        # Slow path: find the first { or [ and try from there
        for ch in ("{", "["):
            idx = text.find(ch)
            if idx < 0:
                continue
            candidate = text[idx:]
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                pass
    return None


def _api_bind_host(app: AppContext) -> str:
    """Resolve the API bind address, mirroring sidecar.runAPI in Go.

    In standalone sandbox mode with a non-localhost guardrail host,
    the Go gateway binds to guardrail.host (the bridge IP) instead
    of 127.0.0.1.
    """
    if app.cfg.openshell.is_standalone() and app.cfg.guardrail.host not in ("", "localhost"):
        return app.cfg.guardrail.host
    return "127.0.0.1"


def _sidecar_client(app: AppContext):
    """Build an OrchestratorClient from the app's gateway config."""
    from defenseclaw.gateway import OrchestratorClient

    return OrchestratorClient(
        host=_api_bind_host(app),
        port=app.cfg.gateway.api_port,
        token=app.cfg.gateway.resolved_token(),
    )


def _list_skills_via_sidecar(app: AppContext) -> dict[str, Any] | None:
    """Fetch skills from the sidecar REST API (GET /skills)."""
    try:
        data = _sidecar_client(app).list_skills()
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _list_openclaw_skills_full(
    app: AppContext | None = None, connector: str | None = None
) -> dict[str, Any] | None:
    """Get the full skill list, dispatching on the resolved connector.

    For ``openclaw`` (the historical default) we keep the sidecar →
    CLI fallback chain. For Codex / Claude Code / ZeptoClaw we walk
    the connector-specific skill directories via
    :func:`defenseclaw.skill_list.list_skills` (S4.4 adapter).

    ``connector`` is the resolved multi-connector override
    (``skill list --connector <name>``); it dispatches on that
    connector instead of the active one. Defaults to the active
    connector, so single-connector behaviour is unchanged.

    The returned shape stays ``{"skills": [...]}`` — same as
    ``openclaw skills list --json`` — so every downstream caller in
    this module continues to work unchanged.
    """
    if app is not None:
        active = app.cfg.active_connector() if hasattr(app.cfg, "active_connector") else "openclaw"
        resolved = connector or active
        if resolved != "openclaw":
            from defenseclaw.skill_list import list_skills as _adapter_list
            return {"skills": _adapter_list(app.cfg, connector=resolved)}

        # OpenClaw: prefer the live sidecar — it sees runtime state
        # the static CLI doesn't (recently-toggled skills, etc.).
        # The sidecar only reflects the active connector, so use it
        # only when the resolved connector matches the active one.
        if resolved == active:
            result = _list_skills_via_sidecar(app)
            if result is not None:
                return result

    out = _run_openclaw("skills", "list", "--json")
    if out is None:
        # Last-ditch fallback: walk the OpenClaw filesystem layout so
        # `defenseclaw skill list` doesn't go silent when the
        # `openclaw` binary isn't on PATH (sandbox installs, CI, etc.).
        if app is not None and hasattr(app.cfg, "skill_dirs"):
            from defenseclaw.skill_list import list_skills as _adapter_list
            return {"skills": _adapter_list(app.cfg, prefer_cli=False, connector=connector or None)}
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _get_openclaw_skill_info(
    name: str, app: AppContext | None = None, connector: str | None = None,
) -> dict[str, Any] | None:
    """Get info for a single skill.

    For OpenClaw, prefers the sidecar → CLI fallback chain. For
    other connectors, walks the connector-specific skill
    directories — there is no per-connector ``info`` subcommand.

    ``connector`` overrides the resolved connector so a multi-connector
    caller (``skill info/scan --connector <name>``) can inspect the selected
    configured connector's skill; defaults to the resolved connector context.
    """
    if app is not None:
        resolved = connector or (
            app.cfg.active_connector() if hasattr(app.cfg, "active_connector") else "openclaw"
        )
        if resolved != "openclaw":
            from defenseclaw.skill_list import list_skills as _adapter_list
            for s in _adapter_list(app.cfg, connector=resolved):
                if s.get("name") == name:
                    return s
            return None

        full = _list_skills_via_sidecar(app)
        if full is not None:
            for s in full.get("skills", []):
                if s.get("name") == name:
                    return s

    out = _run_openclaw("skills", "info", name, "--json")
    if out is None:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and "error" in data:
        return None
    return data


# ---------------------------------------------------------------------------
# Scan map / actions map builders (mirror Go buildSkillScanMap / buildSkillActionsMap)
# ---------------------------------------------------------------------------

_SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "info")


def _severity_counts_from_raw(raw_json: str) -> dict[str, int]:
    """E4i: bucket a scan's findings into critical/high/medium/low/info.

    Parses the stored ``raw_json`` (``ScanResult.to_json()``) so no extra DB
    round-trip is needed. Returns a dict with all five buckets present (0 when
    absent) so consumers (skill list --json, skill info, and the TUI render
    half) get a stable shape. Unknown/blank severities are ignored.
    """
    counts = {b: 0 for b in _SEVERITY_BUCKETS}
    if not raw_json:
        return counts
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return counts
    for f in data.get("findings", []) or []:
        sev = str(f.get("severity", "")).strip().lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _scan_payload_from_latest(ls: dict[str, Any]) -> dict[str, Any]:
    finding_count = ls["finding_count"]
    return {
        "target": ls["target"],
        "clean": finding_count == 0,
        "max_severity": ls["max_severity"] if finding_count > 0 else "CLEAN",
        "total_findings": finding_count,
        # E4i: per-severity breakdown alongside the existing max+total.
        "severity_counts": _severity_counts_from_raw(ls.get("raw_json", "")),
    }


def _build_scan_map(store) -> dict[str, dict[str, Any]]:
    """Build a map of skill-name -> latest scan entry from the DB."""
    scan_map: dict[str, dict[str, Any]] = {}
    if store is None:
        return scan_map
    try:
        latest = store.latest_scans_by_scanner("skill-scanner")
    except Exception:
        return scan_map
    for ls in latest:
        name = os.path.basename(ls["target"])
        scan_map[name] = _scan_payload_from_latest(ls)
    return scan_map


def _latest_skill_scan_for_connector(
    app: AppContext, skill_name: str, connector: str,
) -> dict[str, Any] | None:
    if app.store is None:
        return None
    try:
        latest = app.store.latest_scans_by_scanner("skill-scanner")
    except Exception:
        return None
    matches: list[tuple[Any, dict[str, Any]]] = []
    for ls in latest:
        if os.path.basename(ls["target"]) != skill_name:
            continue
        payload = _scan_payload_from_latest(ls)
        if connector and not _scan_entry_matches_connector(app, payload, connector):
            continue
        matches.append((ls.get("timestamp"), payload))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def _build_actions_map(store, connector: str = "") -> dict[str, Any]:
    """Build a map of skill-name -> effective ActionEntry from the DB.

    Resolves most-specific-wins per name (SK-4): the connector-scoped row
    overrides the global row when ``connector`` is given, so each connector's
    table/card shows that connector's effective actions. ``connector=""``
    returns only the global rows (today's behavior).
    """
    from defenseclaw.models import ActionEntry
    actions_map: dict[str, ActionEntry] = {}
    if store is None:
        return actions_map
    try:
        entries = store.list_actions_by_type("skill")
    except Exception:
        return actions_map
    for e in entries:
        if e.connector == "" and e.target_name not in actions_map:
            actions_map[e.target_name] = e
    if connector:
        seen_scoped: set[str] = set()
        for e in entries:
            if e.connector == connector and e.target_name not in seen_scoped:
                actions_map[e.target_name] = e
                seen_scoped.add(e.target_name)
    return actions_map


def _scan_entry_matches_connector(
    app: AppContext, scan_data: dict[str, Any] | None, connector: str,
) -> bool:
    """Best-effort connector filter for historical skill scans.

    The scan table is not connector-tagged, so use the recorded local target
    path and the requested connector's configured skill dirs. Unknown/non-local
    targets do not match an explicit connector; unscoped info keeps the legacy
    phantom behavior.
    """
    if not connector or not scan_data:
        return True
    target = str(scan_data.get("target") or "")
    if not target:
        return False
    real_target = os.path.realpath(target)
    try:
        roots = app.cfg.skill_dirs(connector)
    except Exception:  # noqa: BLE001 — fail closed for explicit connector scope.
        return False
    return any(
        real_target == os.path.realpath(root)
        or real_target.startswith(os.path.realpath(root) + os.sep)
        for root in roots
    )


def _skill_info_card(
    app: AppContext,
    skill_name: str,
    info_map: dict[str, Any] | None,
    *,
    connector: str = "",
    filter_scan_to_connector: bool = False,
    suppress_global_action_only: bool = False,
) -> dict[str, Any] | None:
    """Build the rendered ``skill info`` payload for one connector scope."""
    if (
        isinstance(info_map, dict)
        and "not found" in str(info_map.get("error") or "").lower()
    ):
        info_map = None
    scan_map = _build_scan_map(app.store)
    scan_entry: dict[str, Any] | None = None
    if (
        filter_scan_to_connector
        and connector
    ):
        scan_entry = _latest_skill_scan_for_connector(app, skill_name, connector)
    elif skill_name in scan_map:
        scan_entry = scan_map[skill_name]
    actions_map = _build_actions_map(app.store, connector)
    scoped_action = None
    if suppress_global_action_only and connector and app.store is not None:
        try:
            scoped_action = app.store.get_action("skill", skill_name, connector)
        except Exception:
            scoped_action = None

    if info_map is None:
        if (
            suppress_global_action_only
            and connector
            and skill_name in actions_map
            and scoped_action is None
            and scan_entry is None
        ):
            return None
        if scan_entry is None and skill_name not in actions_map:
            return None
        info_map = {"name": skill_name}
    else:
        info_map = dict(info_map)

    if connector:
        info_map["connector"] = connector
    if scan_entry is not None:
        info_map["scan"] = scan_entry
    if skill_name in actions_map:
        ae = actions_map[skill_name]
        if not ae.actions.is_empty():
            info_map["actions"] = ae.actions.to_dict()
    return info_map


def _print_skill_info_card(
    info_map: dict[str, Any], skill_name: str, *, show_connector: bool = False,
) -> None:
    click.echo(f"{ux.bold('Skill:')}       {info_map.get('name', skill_name)}")
    if show_connector and info_map.get("connector"):
        click.echo(f"{ux.bold('Connector:')}   {info_map['connector']}")
    if info_map.get("description"):
        click.echo(f"{ux.bold('Description:')} {info_map['description']}")
    if info_map.get("source"):
        click.echo(f"{ux.bold('Source:')}      {info_map['source']}")
    if info_map.get("baseDir"):
        click.echo(f"{ux.bold('Path:')}        {info_map['baseDir']}")
    if info_map.get("filePath"):
        click.echo(f"{ux.bold('File:')}        {info_map['filePath']}")
    click.echo(f"{ux.bold('Eligible:')}    {info_map.get('eligible', False)}")
    click.echo(f"{ux.bold('Bundled:')}     {info_map.get('bundled', False)}")
    if info_map.get("homepage"):
        click.echo(f"{ux.bold('Homepage:')}    {info_map['homepage']}")

    scan_data = info_map.get("scan")
    if scan_data:
        click.echo()
        click.echo(ux.bold("Last Scan:"))
        if scan_data.get("clean"):
            ux.ok("Verdict:  CLEAN", indent="  ")
        else:
            # SK-3: label the count plainly and stamp the *severity word* with
            # the matching colour (was: "{n} CRITICAL findings" always in
            # yellow, conflating the total count with the max severity).
            n = scan_data.get("total_findings", 0)
            sev = scan_data.get("max_severity", "INFO")
            sev_color = {
                "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan",
            }.get(sev, "white")
            click.echo(
                f"  {ux.bold('Verdict:')}  {n} findings "
                f"(max severity: {ux._style(sev, fg=sev_color, bold=True)})"
            )
        click.echo(f"  {ux.bold('Target:')}   {scan_data.get('target', '')}")

    actions_data = info_map.get("actions")
    if actions_data or info_map.get("connector"):
        from defenseclaw.models import ActionState
        state = ActionState.from_dict(actions_data)
        click.echo()
        click.echo(f"{ux.bold('Actions:')}     {state.summary()}")


# ---------------------------------------------------------------------------
# skill list
# ---------------------------------------------------------------------------

def _skill_status(s: dict[str, Any]) -> str:
    if s.get("disabled"):
        return "disabled"
    if s.get("blockedByAllowlist"):
        return "blocked"
    if s.get("eligible"):
        return "active"
    return "inactive"


def _skill_status_display(
    s: dict[str, Any],
    action_entry: Any = None,
    scan_entry: dict[str, Any] | None = None,
) -> str:
    if s.get("disabled"):
        return "✗ disabled"
    if s.get("blockedByAllowlist"):
        return "✗ blocked"
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine":
            return "✗ quarantined"
        if a.install == "block":
            return "✗ blocked"
        if a.runtime == "disable":
            return "✗ disabled"
        if a.install == "allow":
            return "✓ allowed"
    if scan_entry:
        sev = scan_entry.get("max_severity", "CLEAN")
        if sev in ("CRITICAL", "HIGH"):
            return "✗ rejected"
        if sev in ("MEDIUM", "LOW"):
            return "⚠ warning"
    if s.get("eligible"):
        return "✓ ready"
    if s.get("source") in ("enforcement", "scan-history"):
        return "✗ removed"
    return "✗ missing"


def _skill_display_name(s: dict[str, Any]) -> str:
    emoji = (s.get("emoji", "") or "").strip()
    name = s.get("name", "")

    # Different terminals still render emoji widths a little differently,
    # so lead with the actual skill name and keep the icon as a suffix.
    if not emoji:
        return name

    return f"{name} {emoji}"


@skill.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output merged skill list as JSON")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "List skills for a specific configured connector. "
        "Default: every configured connector (on a single-connector install, "
        "just that one). Pass --connector <name> to narrow the listing to "
        "one configured peer."
    ),
)
@pass_ctx
def list_skills(app: AppContext, as_json: bool, connector_flag: str) -> None:
    """List skills with their latest scan severity.

    By default this lists **every configured connector's** skills — on a
    multi-connector install each connector gets its own connector-tagged
    section/table, so you no longer have to re-run with ``--connector``
    per peer. ``--connector <name>`` narrows the listing to one configured
    connector. Single-connector installs are unchanged (one table).
    """
    from defenseclaw.commands import resolve_list_connectors

    connectors = resolve_list_connectors(app, connector_flag)

    scan_map = _build_scan_map(app.store)
    # SK-4: resolve the effective actions per connector (connector-scoped row
    # overrides global) so each connector's table/card shows its own actions.

    if as_json:
        if len(connectors) > 1:
            groups = []
            for c in connectors:
                actions_map = _build_actions_map(app.store, c)
                groups.append({
                    "connector": c,
                    "skills": _skill_list_json_items(
                        _collect_skills_for_connector(app, c, scan_map, actions_map),
                        scan_map,
                        actions_map,
                        connector=c,
                    ),
                })
            click.echo(json.dumps(groups, indent=2, default=str))
        else:
            actions_map = _build_actions_map(app.store, connectors[0])
            skills = _collect_skills_for_connector(app, connectors[0], scan_map, actions_map)
            items = _skill_list_json_items(
                skills,
                scan_map,
                actions_map,
                connector=connectors[0] if connector_flag and connector_flag.strip() else "",
            )
            payload = (
                {"connector": connectors[0], "skills": items}
                if connector_flag and connector_flag.strip()
                else items
            )
            click.echo(json.dumps(payload, indent=2, default=str))
        return

    shown_any = False
    for connector in connectors:
        actions_map = _build_actions_map(app.store, connector)
        skills = _collect_skills_for_connector(app, connector, scan_map, actions_map)
        if not skills:
            if connector == "openclaw":
                click.echo(ux.dim("No skills found. Is openclaw installed?"))
            else:
                click.echo(
                    f"No skills found for connector={connector!r} "
                    f"{ux.dim('(checked the connector-specific skill directories).')}",
                )
            continue
        _print_skill_list_table(skills, scan_map, actions_map, connector)
        shown_any = True

    if shown_any:
        from defenseclaw.commands import hint
        hint("Scan all skills:  defenseclaw skill scan all")


def _collect_skills_for_connector(
    app: AppContext,
    connector: str,
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
) -> list[dict[str, Any]]:
    """Resolve the merged skill list for a single connector.

    Returns the post-phantom skill list. OpenClaw-only audit-DB phantoms
    (enforcement-only / scan-history-only entries) are folded in exactly
    as the single-connector path did.
    """
    oc_list = _list_openclaw_skills_full(app, connector=connector)
    skills = oc_list.get("skills", []) if oc_list else []

    # The ``actions`` and ``scan_results`` tables are connector-untagged in
    # the shared audit DB (see cli/defenseclaw/db.py). Phantom rows from
    # those maps were historically OpenClaw-owned, so injecting them on a
    # non-OpenClaw connector (codex, claudecode, zeptoclaw) would surface
    # skills that the active framework does not actually have on disk —
    # which is exactly the leak users were seeing in the Skills tab. Only
    # surface phantoms when the connector is OpenClaw; for the others the
    # connector-aware filesystem walk (skill_list.list_skills →
    # cfg.skill_dirs()) is the source of truth.
    if connector != "openclaw":
        return skills

    known_names = {s.get("name", "") for s in skills}
    for name, ae in actions_map.items():
        if name not in known_names:
            skills.append({
                "name": name,
                "description": "",
                "emoji": "",
                "eligible": False,
                "disabled": ae.actions.runtime == "disable",
                "blockedByAllowlist": False,
                "source": "enforcement",
                "bundled": False,
                "homepage": "",
            })
            known_names.add(name)

    for name in scan_map:
        if name not in known_names:
            skills.append({
                "name": name,
                "description": "",
                "emoji": "",
                "eligible": False,
                "disabled": False,
                "blockedByAllowlist": False,
                "source": "scan-history",
                "bundled": False,
                "homepage": "",
            })
            known_names.add(name)

    return skills


def _skill_list_json_items(
    skills: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    *,
    connector: str = "",
) -> list[dict[str, Any]]:
    items = []
    for s in skills:
        name = s.get("name", "")
        item: dict[str, Any] = {
            "name": name,
            "description": s.get("description", ""),
            "source": s.get("source", ""),
            "status": _skill_status(s),
            "eligible": s.get("eligible", False),
            "disabled": s.get("disabled", False),
            "bundled": s.get("bundled", False),
        }
        if connector:
            item["connector"] = connector
        hp = s.get("homepage", "")
        if hp:
            item["homepage"] = hp
        if name in scan_map:
            item["scan"] = scan_map[name]
        if name in actions_map:
            ae = actions_map[name]
            if not ae.actions.is_empty():
                item["actions"] = ae.actions.to_dict()
        verdict_label, _ = _compute_verdict(actions_map.get(name), scan_map.get(name))
        item["verdict"] = verdict_label
        items.append(item)
    return items


def _print_skill_list_json(
    skills: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    *,
    connector: str = "",
) -> None:
    click.echo(json.dumps(
        _skill_list_json_items(skills, scan_map, actions_map, connector=connector),
        indent=2,
        default=str,
    ))


def _print_skill_list_table(
    skills: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    connector: str = "",
) -> None:
    from rich.console import Console
    from rich.table import Table

    from defenseclaw.commands import list_scope_title

    ready_count = sum(
        1 for s in skills if s.get("eligible") and not s.get("disabled")
    )

    detail = f"({ready_count}/{len(skills)} ready)"
    title = (
        list_scope_title("Skills", connector, detail)
        if connector
        else f"Skills {detail}"
    )
    console = Console()
    table = Table(title=title)
    table.add_column("Status", style="bold", no_wrap=True)
    table.add_column("Skill", no_wrap=True, overflow="ellipsis", max_width=24)
    table.add_column("Description", no_wrap=True, overflow="ellipsis", max_width=34)
    table.add_column("Source", no_wrap=True, overflow="ellipsis", max_width=18)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Actions", no_wrap=True, overflow="ellipsis", max_width=18)

    for s in skills:
        name = s.get("name", "")
        display_name = _skill_display_name(s)
        status_display = _skill_status_display(s, actions_map.get(name), scan_map.get(name))
        desc = s.get("description", "")
        source = s.get("source", "")

        severity = "-"
        sev_style = ""
        if name in scan_map:
            severity = scan_map[name]["max_severity"]
            sev_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "CLEAN": "green",
            }.get(severity, "")

        actions_str = "-"
        if name in actions_map:
            actions_str = actions_map[name].actions.summary()

        verdict_label, verdict_style = _compute_verdict(
            actions_map.get(name), scan_map.get(name),
        )

        status_style = ""
        if "✗" in status_display:
            status_style = "red"
        elif "✓" in status_display:
            status_style = "green"

        table.add_row(
            f"[{status_style}]{status_display}[/{status_style}]" if status_style else status_display,
            display_name,
            desc,
            source,
            f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
            f"[{verdict_style}]{verdict_label}[/{verdict_style}]" if verdict_style else verdict_label,
            actions_str,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# skill scan
# ---------------------------------------------------------------------------

def _build_skill_scanner(app: AppContext, use_llm: bool | None = None):
    """Construct a :class:`SkillScannerWrapper` with the unified LLM lane
    defaulted on whenever a model resolves (SK-6).

    ``use_llm`` tri-states the ``--use-llm/--no-use-llm`` option:

    * ``None``  → auto: enable the LLM analyzer iff a unified model resolves
      for ``scanners.skill``. The scanner itself still fails safe — if the
      model later can't be built it logs-and-skips the LLM analyzer.
    * ``True``  → force the LLM lane on.
    * ``False`` → force it off (local analyzers only).

    The resolved value overrides ``SkillScannerConfig.use_llm`` for this run
    only via a ``dataclasses.replace`` copy — the shared config object is
    never mutated.
    """
    import dataclasses

    from defenseclaw.scanner._llm_env import litellm_model
    from defenseclaw.scanner.rulepack import maybe_wrap
    from defenseclaw.scanner.skill import SkillScannerWrapper

    llm = app.cfg.resolve_llm("scanners.skill")
    effective = bool(litellm_model(llm)) if use_llm is None else use_llm

    cfg = app.cfg.scanners.skill_scanner
    if cfg.use_llm != effective:
        cfg = dataclasses.replace(cfg, use_llm=effective)

    scanner = SkillScannerWrapper(
        cfg,
        app.cfg.effective_inspect_llm(),
        app.cfg.cisco_ai_defense,
        llm=llm,
    )
    # R4: overlay the configured guardrail rule pack so `skill scan` flags what
    # the gateway's rule lanes would catch. No-op when no rule_pack_dir is set.
    return maybe_wrap(scanner, app.cfg)


def _skill_scan_findings_verdict(result: Any, *, blocked: bool = False) -> str:
    from defenseclaw.commands import _scan_ui

    if blocked:
        return _scan_ui.VERDICT_BLOCKED
    if str(result.max_severity()).upper() == "INFO":
        return _scan_ui.VERDICT_INFO
    return _scan_ui.VERDICT_WARN


def _skill_scan_would_install_block(
    app: AppContext,
    pe: Any,
    skill_name: str,
    skill_path: str,
    result: Any,
    *,
    connector: str | None = None,
) -> bool:
    if result.is_clean():
        return False
    from defenseclaw.enforce.admission import evaluate_admission

    eval_connector = connector or (
        app.cfg.active_connector() if hasattr(app.cfg, "active_connector") else ""
    )
    decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=skill_name,
        source_path=skill_path,
        scan_result=result,
        fallback_actions=app.cfg.skill_actions,
        connector=eval_connector,
        asset_policy=app.cfg.asset_policy,
    )
    if decision.verdict == "allowed":
        return False
    return decision.action.install == "block"


@skill.command()
@click.argument("target", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output scan results as JSON")
@click.option("--path", "scan_path", default="", help="Override skill directory path")
@click.option("--remote", is_flag=True, help="Scan via sidecar API (for skills on a remote host)")
@click.option("--all", "scan_all", is_flag=True, help="Scan all configured skills (also the default with no TARGET)")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scope to one connector. With no TARGET, scans all skills for "
        "that connector. Without --connector, no TARGET scans every "
        "configured connector's skills."
    ),
)
@click.option(
    "--action", is_flag=True, default=False,
    help="Apply enforcement actions (quarantine/block/disable) based on findings",
)
@click.option(
    "--use-llm/--no-use-llm", "use_llm", default=None,
    help=(
        "Run the unified LLM analyzer in addition to the local scanner. "
        "Default (auto): on whenever a model is configured for scanners.skill, "
        "off otherwise. The LLM lane fails safe if no model can be resolved."
    ),
)
@pass_ctx
def scan(
    app: AppContext,
    target: str | None,
    as_json: bool,
    scan_path: str,
    remote: bool,
    scan_all: bool,
    connector_flag: str,
    action: bool,
    use_llm: bool | None,
) -> None:
    """Scan configured skills, or scan one skill by name, path, URL, or 'all'.

    With no TARGET, scans configured skills. On multi-connector installs this
    scans every configured connector; pass ``--connector <name>`` to narrow to a
    single connector. ``--all`` remains an explicit/backward-compatible alias
    for the no-TARGET bulk scan.

    Uses the native cisco-ai-skill-scanner SDK for local scans.

    Remote scanning (--remote):
      When the sidecar runs on a remote host (e.g. via SSM port-forward),
      pass --remote to send the scan request to the sidecar API instead of
      running the scanner locally.

    URL targets (fetch-to-temp):
      Pass an https:// URL or clawhub:// URI to download a skill package
      to a temp directory, scan it locally, then clean up. This lets you
      pre-screen skills before installing them.

      Examples:
        defenseclaw skill scan https://example.com/skills/my-skill.tar.gz
        defenseclaw skill scan clawhub://my-skill@1.2.3
    """
    if action and remote:
        click.echo(
            "error: --action is not supported with --remote; enforcement "
            "actions (quarantine/block/disable) require local file access",
            err=True,
        )
        raise SystemExit(1)

    # URL target → fetch-to-temp scan (Option 3)
    if scan_all and target not in (None, "all"):
        click.echo("error: provide either TARGET or --all, not both", err=True)
        raise SystemExit(2)

    if target and _is_url_target(target):
        if action:
            click.echo(
                "error: --action is not supported with URL targets; "
                "URL scans are pre-screening only",
                err=True,
            )
            raise SystemExit(1)
        _scan_from_url(app, target, as_json)
        return

    # Connector-scoped parity with MCP/list: a missing TARGET means "scan
    # configured skills" (all configured connectors by default, or the selected
    # connector when --connector is present). --all remains a readable alias.
    if not target and not scan_path:
        scan_all = True

    scanner = _build_skill_scanner(app, use_llm)

    if scan_all or target == "all":
        # Resolve which connector(s) `--all` should fan out across — for BOTH
        # the local and --remote paths. An explicit --connector targets exactly
        # one; otherwise a multi-connector install scans every configured connector
        # (so "all skills" means every connector's skills, not just the
        # primary's). Single-connector installs keep the original single pass
        # (connector=None ⇒ the active connector).
        from defenseclaw.commands import resolve_list_connector
        if connector_flag:
            connectors: list[str | None] = [resolve_list_connector(app, connector_flag)]
        elif hasattr(app.cfg, "active_connectors") and len(app.cfg.active_connectors()) > 1:
            connectors = list(app.cfg.active_connectors())
        else:
            connectors = [None]
        json_rows: list[dict[str, Any]] = []
        for c in connectors:
            if len(connectors) > 1 and not as_json:
                click.echo(ux._style(f"\n── connector: {c} ──", fg="cyan"))
            if remote:
                rows = _scan_all_remote(app, as_json, connector=c)
            else:
                rows = _scan_all(app, scanner, as_json, enforce=action, connector=c)
            if as_json:
                json_rows.extend(rows or [])
        if as_json:
            click.echo(json.dumps(json_rows, indent=2, default=str))
        return

    if not target:
        raise click.UsageError("Missing argument 'TARGET'.")

    # Resolve scan directory
    scan_dir = scan_path
    scan_connector = ""
    if not scan_dir:
        if not connector_flag:
            # Bare named scans must fan out over every configured connector copy
            # before the active connector's info path can short-circuit.
            matches = _skill_match_dir_scopes(app, target)
            if len(matches) > 1:
                json_rows: list[dict[str, Any]] = []
                if remote:
                    for match_connector, match_dir in matches:
                        if not as_json:
                            click.echo(ux._style(f"\n── connector: {match_connector} ──", fg="cyan"))
                        _scan_via_sidecar(
                            app,
                            target=match_dir,
                            name=os.path.basename(match_dir),
                            as_json=as_json,
                            connector=match_connector,
                            json_sink=json_rows if as_json else None,
                        )
                    if as_json:
                        click.echo(json.dumps(json_rows, indent=2, default=str))
                    return
                for match_connector, match_dir in matches:
                    if not as_json:
                        click.echo(ux._style(f"\n── connector: {match_connector} ──", fg="cyan"))
                    _scan_one_local_skill(
                        app,
                        scanner,
                        scan_dir=match_dir,
                        as_json=as_json,
                        action=action,
                        connector=match_connector,
                        json_sink=json_rows if as_json else None,
                    )
                if as_json:
                    click.echo(json.dumps(json_rows, indent=2, default=str))
                return
            if matches:
                scan_connector, scan_dir = matches[0]

    if not scan_dir:
        info = _get_openclaw_skill_info(target, app, connector=connector_flag or None)
        if info and _skill_info_path(info):
            scan_dir = _skill_info_path(info) or ""
            if connector_flag:
                from defenseclaw.commands import resolve_list_connector as _resolve_scan_connector
                scan_connector = _resolve_scan_connector(app, connector_flag)
        else:
            # ND-1: resolve a bare name across every configured connector (not
            # just the active one). Scanning is read-only, so if multiple
            # connectors contain the same skill name, fan out across every
            # matching copy instead of asking for --connector.
            matches = _skill_match_dir_scopes(app, target, connector_flag)
            if len(matches) > 1:
                json_rows: list[dict[str, Any]] = []
                if remote:
                    for match_connector, match_dir in matches:
                        if not as_json:
                            click.echo(ux._style(f"\n── connector: {match_connector} ──", fg="cyan"))
                        _scan_via_sidecar(
                            app,
                            target=match_dir,
                            name=os.path.basename(match_dir),
                            as_json=as_json,
                            connector=match_connector,
                            json_sink=json_rows if as_json else None,
                        )
                    if as_json:
                        click.echo(json.dumps(json_rows, indent=2, default=str))
                    return
                for match_connector, match_dir in matches:
                    if not as_json:
                        click.echo(ux._style(f"\n── connector: {match_connector} ──", fg="cyan"))
                    _scan_one_local_skill(
                        app,
                        scanner,
                        scan_dir=match_dir,
                        as_json=as_json,
                        action=action,
                        connector=match_connector,
                        json_sink=json_rows if as_json else None,
                    )
                if as_json:
                    click.echo(json.dumps(json_rows, indent=2, default=str))
                return
            if matches:
                scan_connector, scan_dir = matches[0]

        # F-0501: ``scan_dir`` here came from a connector-reported
        # ``baseDir``/``path`` (an UNTRUSTED connector home / sidecar
        # response) or from name-based resolution. A malicious connector
        # could report a baseDir OUTSIDE the configured skill roots
        # (e.g. ``/etc`` or ``~/.ssh``) and DefenseClaw would happily scan
        # — and, with ``--action``, quarantine/move — files there. Reject a
        # derived scan dir that escapes the configured skill roots. The
        # explicit ``--path`` operator override is intentionally exempt
        # (handled above: ``scan_path`` skips this block).
        if scan_dir:
            from defenseclaw.safety import SafetyError, assert_within_roots
            roots = _scan_skill_roots(app, scan_connector or connector_flag)
            if roots:
                try:
                    assert_within_roots(scan_dir, roots, what="skill scan dir")
                except SafetyError:
                    click.echo(
                        f"error: refusing to scan {target!r}: resolved path "
                        f"{scan_dir!r} is outside the configured skill "
                        f"directories. Use --path to scan an explicit location.",
                        err=True,
                    )
                    raise SystemExit(1)

    if not scan_dir and not remote:
        click.echo(f"error: could not resolve skill {target!r} — use --path to specify manually", err=True)
        raise SystemExit(1)

    # --remote: delegate scan to sidecar API — skip local policy checks
    # since enforcement runs on the remote host.
    if remote:
        remote_connector = scan_connector
        if connector_flag:
            from defenseclaw.commands import resolve_list_connector as _resolve_remote_connector
            remote_connector = _resolve_remote_connector(app, connector_flag)
        _scan_via_sidecar(
            app,
            target=scan_dir or target,
            name=os.path.basename(scan_dir) if scan_dir else target,
            as_json=as_json,
            connector=remote_connector,
        )
        return

    from defenseclaw.commands import resolve_list_connector

    # Resolve before policy checks so --connector X reads that connector's
    # scoped allow/block rows instead of the global row only.
    connector = scan_connector or resolve_list_connector(app, connector_flag)
    _scan_one_local_skill(
        app,
        scanner,
        scan_dir=scan_dir,
        as_json=as_json,
        action=action,
        connector=connector,
    )


def _scan_one_local_skill(
    app: AppContext,
    scanner: Any,
    *,
    scan_dir: str,
    as_json: bool,
    action: bool,
    connector: str,
    json_sink: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    from defenseclaw.commands import _scan_ui
    from defenseclaw.enforce import PolicyEngine

    name = os.path.basename(scan_dir)

    pe = PolicyEngine(app.store)

    if pe.is_blocked_for_connector("skill", name, connector):
        if as_json:
            payload = _skill_scan_error_json_payload(
                scan_dir,
                RuntimeError(f"{name} is blocked by policy"),
                connector=connector,
            )
            _emit_skill_json_payload(payload, json_sink=json_sink)
            if json_sink is None:
                raise SystemExit(2)
            return payload
        click.echo(f"BLOCKED: {name} — remove from block list first", err=True)
        raise SystemExit(2)

    # F-0282: a bare ``pe.is_allowed("skill", name)`` check skips the scan
    # on a NAME match alone. An operator allow that was registered for a
    # trusted skill at a specific path would then also wave through a
    # *different* on-disk skill that merely shares the name. Route the
    # allow decision through the shared admission evaluator, which compares
    # the presented ``source_path`` against any path-pinned allow (and fails
    # closed on a mismatch — see F-0401). Only a genuine manual allow that
    # matches the presented asset skips the scan; everything else falls
    # through to a fresh scan.
    from defenseclaw.enforce.admission import evaluate_admission as _evaluate_admission
    allow_decision = _evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=name,
        source_path=scan_dir or "",
        connector=connector,
    )
    if allow_decision.verdict == "allowed" and allow_decision.source == "manual-allow":
        if as_json:
            payload = _skill_scan_skipped_json_payload(
                name,
                scan_dir,
                reason="manual-allow",
                connector=connector,
            )
            _emit_skill_json_payload(payload, json_sink=json_sink)
            return payload
        click.echo(ux._style(f"ALLOWED (skip scan): {name}", fg="green"))
        return None

    ctx = _scan_ui.ScanContext.for_skill(
        connector=connector,
        paths=[scan_dir],
        as_json=as_json,
    )
    _scan_ui.render_preamble(ctx, target_count=1)

    captured_stdout = None
    try:
        if as_json:
            with _capture_skill_scan_stdout() as stdout_buffer:
                captured_stdout = stdout_buffer
                result = scanner.scan(scan_dir)
            _emit_captured_scan_stdout(captured_stdout.getvalue())
        else:
            result = scanner.scan(scan_dir)
    except Exception as exc:
        if as_json:
            if captured_stdout is not None:
                _emit_captured_scan_stdout(captured_stdout.getvalue())
            payload = _skill_scan_error_json_payload(scan_dir, exc, connector=connector)
            _emit_skill_json_payload(payload, json_sink=json_sink)
            if json_sink is None:
                raise SystemExit(1)
            return payload
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    payload: dict[str, Any] | None = None
    if as_json:
        payload = _skill_scan_result_json_payload(result, connector=connector)
        _emit_skill_json_payload(payload, json_sink=json_sink)
    else:
        # Per-target glyph line (S6.3 — shared scan UX) sits above the
        # existing detailed Skill / Target / Duration / Findings block
        # so the new summary numbers tie back to a clear verdict.
        enforcement_blocks = False
        if result.is_clean():
            _scan_ui.render_per_target_status(
                ctx, target=name, verdict=_scan_ui.VERDICT_CLEAN, findings=0,
            )
        else:
            enforcement_blocks = (
                action
                and _skill_scan_would_install_block(
                    app, pe, name, scan_dir, result, connector=connector,
                )
            )
            _scan_ui.render_per_target_status(
                ctx,
                target=name,
                verdict=_skill_scan_findings_verdict(result, blocked=enforcement_blocks),
                detail=f"max severity: {result.max_severity()}",
                findings=len(result.findings),
            )
        click.echo()
        _print_result(name, result)
        _scan_ui.render_summary(
            ctx,
            clean=1 if result.is_clean() else 0,
            blocked=1 if not result.is_clean() and enforcement_blocks else 0,
            errored=0,
            total=1,
            findings=len(result.findings),
            duration_ms=int(result.duration.total_seconds() * 1000),
        )
        from defenseclaw.commands import hint
        if result.is_clean():
            hint("Scan MCP servers:  defenseclaw mcp scan --all")
        else:
            hint(
                f"Block this skill:  defenseclaw skill block {name}",
                "View alerts:       defenseclaw alerts",
            )

    if not result.is_clean() and action:
        _apply_scan_enforcement(app, pe, name, scan_dir, result, connector=connector)
    return payload


def _skill_scan_result_json_payload(result: Any, *, connector: str = "") -> dict[str, Any]:
    payload = json.loads(result.to_json())
    if connector:
        payload = {
            "scanner": payload["scanner"],
            "connector": connector,
            **{k: v for k, v in payload.items() if k != "scanner"},
        }
    return payload


def _skill_scan_error_json_payload(
    target: str, exc: Exception, *, connector: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scanner": "skill-scanner",
        "target": target,
        "error": f"scan failed: {exc}",
        "findings": [],
    }
    if connector:
        payload = {
            "scanner": payload["scanner"],
            "connector": connector,
            "target": payload["target"],
            "error": payload["error"],
            "findings": payload["findings"],
        }
    return payload


def _skill_scan_skipped_json_payload(
    name: str, target: str, *, reason: str, connector: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scanner": "skill-scanner",
        "target": target,
        "name": name,
        "skipped": True,
        "reason": reason,
        "findings": [],
    }
    if connector:
        payload = {
            "scanner": payload["scanner"],
            "connector": connector,
            **{k: v for k, v in payload.items() if k != "scanner"},
        }
    return payload


def _emit_skill_json_payload(
    payload: dict[str, Any], *, json_sink: list[dict[str, Any]] | None = None,
) -> None:
    if json_sink is not None:
        json_sink.append(payload)
        return
    click.echo(json.dumps(payload, indent=2, default=str))


def _emit_captured_scan_stdout(text: str) -> None:
    for line in text.splitlines():
        if line:
            click.echo(line, err=True)


@contextmanager
def _capture_skill_scan_stdout() -> Iterator[Any]:
    """Capture scanner stdout so JSON-mode stdout remains parseable."""
    import contextlib
    import io
    import sys
    import tempfile

    captured = io.StringIO()
    original_stdout = sys.stdout
    fd: int | None = None
    saved_fd: int | None = None
    tmp = None

    for stream in (original_stdout, getattr(sys, "__stdout__", None)):
        if stream is None:
            continue
        try:
            fd = stream.fileno()
            break
        except (AttributeError, io.UnsupportedOperation, OSError):
            continue
    if fd is None:
        try:
            os.fstat(1)
            fd = 1
        except OSError:
            fd = None

    if fd is not None:
        try:
            original_stdout.flush()
            saved_fd = os.dup(fd)
            tmp = tempfile.TemporaryFile(mode="w+b")
            os.dup2(tmp.fileno(), fd)
        except OSError:
            if saved_fd is not None:
                os.close(saved_fd)
            if tmp is not None:
                tmp.close()
            fd = None
            saved_fd = None
            tmp = None

    try:
        with contextlib.redirect_stdout(captured):
            yield captured
    finally:
        if fd is not None and saved_fd is not None and tmp is not None:
            try:
                original_stdout.flush()
            except OSError:
                pass
            os.dup2(saved_fd, fd)
            os.close(saved_fd)
            tmp.seek(0)
            captured.write(tmp.read().decode(errors="replace"))
            tmp.close()


def _apply_scan_enforcement(
    app: AppContext,
    pe,
    skill_name: str,
    skill_path: str,
    result,
    connector: str | None = None,
) -> None:
    """Apply configured skill_actions policy based on scan severity.

    Allow-listed skills are exempt from auto-enforcement — only a manual
    ``skill block`` can override an allow entry.

    ``connector`` attributes persisted enforcement to a specific connector
    during multi-connector ``--all``/``--connector`` scans. A bare ``None`` keeps
    legacy global writes for direct internal callers.
    """
    from defenseclaw.enforce.admission import evaluate_admission

    eval_connector = connector or (
        app.cfg.active_connector() if hasattr(app.cfg, "active_connector") else ""
    )
    decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=skill_name,
        source_path=skill_path,
        scan_result=result,
        fallback_actions=app.cfg.skill_actions,
        connector=eval_connector,
        asset_policy=app.cfg.asset_policy,
    )

    if decision.verdict == "allowed":
        click.echo(f"[scan] {skill_name!r} is allow-listed — skipping auto-enforcement")
        return

    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    sev = result.max_severity()
    action_cfg = decision.action

    if action_cfg.file == "none" and action_cfg.runtime != "disable" and action_cfg.install == "none":
        return

    enforcement_reason = f"post-scan: {len(result.findings)} findings, max={sev}"
    applied_actions: list[str] = []

    if action_cfg.file == "quarantine":
        if connector:
            pe.set_source_path("skill", skill_name, skill_path, connector)
        else:
            pe.set_source_path("skill", skill_name, skill_path)
        se = SkillEnforcer(app.cfg.quarantine_dir)
        dest = se.quarantine(skill_name, skill_path)
        if dest:
            applied_actions.append(f"quarantined to {dest}")
            if connector:
                pe.quarantine_for_connector("skill", skill_name, connector, enforcement_reason)
            else:
                pe.quarantine("skill", skill_name, enforcement_reason)
        else:
            click.echo(f"[scan] quarantine failed for {skill_name!r}", err=True)

    if action_cfg.runtime == "disable":
        try:
            client = _sidecar_client(app)
            client.disable_skill(skill_name)
            applied_actions.append("disabled via gateway")
            if connector:
                pe.disable_for_connector("skill", skill_name, connector, enforcement_reason)
            else:
                pe.disable("skill", skill_name, enforcement_reason)
        except Exception:
            click.echo(f"[scan] gateway disable failed for {skill_name!r} — skipping runtime disable", err=True)

    if action_cfg.install == "block":
        if connector:
            pe.block_for_connector("skill", skill_name, connector, enforcement_reason)
        else:
            pe.block("skill", skill_name, enforcement_reason)
        applied_actions.append("added to block list")

    if applied_actions:
        actions_str = ", ".join(applied_actions)
        click.echo(f"[scan] enforcement: {skill_name!r}: {actions_str}")
        if app.logger:
            detail = f"severity={sev} findings={len(result.findings)}"
            app.logger.log_action("scan-enforced", skill_name, f"{detail}; {actions_str}")


def _enable_skill_via_gateway(app: AppContext, skill_name: str) -> bool:
    """Best-effort runtime re-enable; returns True only on confirmed success."""
    client = _sidecar_client(app)
    try:
        resp = client.enable_skill(skill_name)
    except Exception as exc:
        click.echo(f"error: gateway enable failed: {exc}", err=True)
        return False

    if resp.get("status") != "enabled":
        click.echo(f"error: gateway returned unexpected response: {resp}", err=True)
        return False
    return True


def _render_skill_scan_empty_state(connector: str, dirs: list[str]) -> None:
    click.echo(f"No skills found for connector={connector!r} in configured directories:")
    if dirs:
        for d in dirs:
            click.echo(f"  {d}")
    else:
        click.echo(f"  (no skill directories configured for connector={connector!r})")


def _scan_all(
    app: AppContext,
    scanner,
    as_json: bool,
    *,
    enforce: bool = False,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    from defenseclaw.commands import _scan_ui
    from defenseclaw.enforce import PolicyEngine

    active = (
        app.cfg.active_connector()
        if hasattr(app.cfg, "active_connector")
        else "openclaw"
    )
    resolved_connector = connector or active

    # The list adapter is connector-aware: non-OpenClaw connectors use the
    # shared filesystem discovery rules, while OpenClaw keeps its sidecar/CLI
    # chain. Always pass the resolved connector so a non-active Codex scan sees
    # the child skills inside its reserved .system container.
    oc_list = _list_openclaw_skills_full(app, connector=resolved_connector)
    if oc_list and oc_list.get("skills"):
        skill_entries = [
            entry for entry in oc_list["skills"]
            if isinstance(entry, dict) and entry.get("name")
        ]
    else:
        skill_entries = []

    pe = PolicyEngine(app.store)
    verdicts = []
    errors = 0

    connector = resolved_connector

    # Build the target list up front so we can render an accurate
    # preamble (count + sources) before the first scanner run.
    targets: list[tuple[str, str]] = []  # (name, base_dir)
    sources: list[str] = []
    scan_dirs = list(app.cfg.skill_dirs(resolved_connector))
    unresolved_names: set[str] = set()

    if skill_entries:
        from defenseclaw.safety import is_symlink, is_within_roots

        for info in skill_entries:
            name = str(info["name"])
            base_dir = _skill_info_path(info)
            if not base_dir:
                resolved_info = _get_openclaw_skill_info(
                    name,
                    app,
                    connector=resolved_connector,
                )
                base_dir = _skill_info_path(resolved_info)
            if not base_dir:
                unresolved_names.add(name)
                continue
            # Connector homes are untrusted. Apply the same containment gate
            # to list-adapter paths as the filesystem fallback below so
            # expanding .system never turns a symlink/junction into an
            # out-of-root scan.
            if is_symlink(base_dir):
                click.echo(
                    f"[scan] skipping symlinked skill entry {name!r}",
                    err=True,
                )
                continue
            if not is_within_roots(base_dir, scan_dirs):
                click.echo(
                    f"[scan] skipping skill entry {name!r}: resolves outside "
                    f"configured skill roots",
                    err=True,
                )
                continue
            targets.append((name, base_dir))
        sources = sorted({os.path.dirname(p) for _, p in targets if p})
    if not skill_entries or unresolved_names:
        # Fall back to directory scan — resolve the target connector's
        # skill dirs so the selected configured connector's skills are scanned.
        # For an incomplete authoritative listing, supplement only entries that
        # lacked usable paths; complete listings never enter this branch.
        from defenseclaw.safety import is_symlink, is_within_roots
        from defenseclaw.skill_discovery import discover_skill_directories

        dirs = scan_dirs
        sources = sorted({*sources, *dirs})
        seen_names: set[str] = {name for name, _path in targets}
        for skill_dir in dirs:
            if not os.path.isdir(skill_dir):
                continue
            for discovered in discover_skill_directories(
                skill_dir, connector=resolved_connector
            ):
                entry = discovered.name
                path = discovered.path
                if entry in seen_names:
                    continue
                if skill_entries and entry not in unresolved_names:
                    continue
                # F-0502: ``os.path.isdir`` follows symlinks, so a symlinked
                # entry under a skill root (connector homes are UNTRUSTED)
                # would be scanned at its realpath — anywhere on the host.
                # Skip symlinked entries and require the realpath to stay
                # under the skill root before scanning.
                if is_symlink(path):
                    click.echo(
                        f"[scan] skipping symlinked skill entry {entry!r} in {skill_dir}",
                        err=True,
                    )
                    continue
                if not os.path.isdir(path):
                    continue
                if not is_within_roots(path, [skill_dir]):
                    click.echo(
                        f"[scan] skipping skill entry {entry!r}: resolves "
                        f"outside skill root {skill_dir}",
                        err=True,
                    )
                    continue
                seen_names.add(entry)
                unresolved_names.discard(entry)
                targets.append((entry, path))

        for name in sorted(unresolved_names):
            click.echo(f"[scan] warning: no baseDir for {name}", err=True)

    if not targets:
        if not as_json:
            _render_skill_scan_empty_state(connector, scan_dirs)
        return []

    ctx = _scan_ui.ScanContext.for_skill(
        connector=connector, paths=sources, as_json=as_json,
    )
    _scan_ui.render_preamble(ctx, target_count=len(targets))

    import time
    started = time.monotonic()
    json_rows: list[dict[str, Any]] = []

    for name, base_dir in targets:
        captured_stdout = None
        try:
            if as_json:
                with _capture_skill_scan_stdout() as stdout_buffer:
                    captured_stdout = stdout_buffer
                    result = scanner.scan(base_dir)
                _emit_captured_scan_stdout(captured_stdout.getvalue())
            else:
                result = scanner.scan(base_dir)
            if app.logger:
                app.logger.log_scan(result)
            verdicts.append({"name": name, "result": result})
            if as_json:
                json_rows.append(_skill_scan_result_json_payload(result, connector=connector))
            else:
                enforcement_blocks = False
                if result.is_clean():
                    _scan_ui.render_per_target_status(
                        ctx, target=name, verdict=_scan_ui.VERDICT_CLEAN, findings=0,
                    )
                else:
                    enforcement_blocks = (
                        enforce
                        and _skill_scan_would_install_block(
                            app, pe, name, base_dir, result, connector=connector,
                        )
                    )
                    _scan_ui.render_per_target_status(
                        ctx,
                        target=name,
                        verdict=_skill_scan_findings_verdict(
                            result, blocked=enforcement_blocks,
                        ),
                        detail=f"max severity: {result.max_severity()}",
                        findings=len(result.findings),
                    )
                v = verdicts[-1]
                v["blocked"] = bool(enforcement_blocks)
                v["findings"] = len(result.findings)
            if not result.is_clean() and enforce:
                _apply_scan_enforcement(app, pe, name, base_dir, result, connector=connector)
        except Exception as exc:
            errors += 1
            if not as_json:
                _scan_ui.render_per_target_status(
                    ctx,
                    target=name,
                    verdict=_scan_ui.VERDICT_ERROR,
                    detail=str(exc),
                )
            else:
                if captured_stdout is not None:
                    _emit_captured_scan_stdout(captured_stdout.getvalue())
                json_rows.append(
                    _skill_scan_error_json_payload(base_dir, exc, connector=connector)
                )

    if not as_json and verdicts:
        clean = sum(1 for v in verdicts if v["result"].is_clean())
        blocked = sum(1 for v in verdicts if v.get("blocked"))
        findings = sum(int(v.get("findings") or 0) for v in verdicts)
        duration_ms = int((time.monotonic() - started) * 1000)
        _scan_ui.render_summary(
            ctx,
            clean=clean,
            blocked=blocked,
            errored=errors,
            total=len(verdicts) + errors,
            findings=findings,
            duration_ms=duration_ms,
        )
        from defenseclaw.commands import hint
        if findings:
            hint("View alerts:       defenseclaw alerts")
        else:
            hint("Scan MCP servers:  defenseclaw mcp scan --all")
    return json_rows


def _skill_basename(target: str) -> str:
    """Normalise a skill reference to its bare directory name.

    Mirrors ``Config.installed_skill_candidates``: drop any leading path
    component and a leading ``@`` scope marker.
    """
    name = target
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    return name.lstrip("@")


def _skill_search_dirs(app: AppContext, connector: str = "") -> list[str]:
    """Skill directories to resolve a bare name against (ND-1).

    With ``connector`` set, scope to that one peer's dirs. Otherwise search
    the union of **every configured connector's** skill dirs — active-connector
    dirs FIRST so a name present on the active peer keeps resolving exactly
    as before, while a skill that only lives on a NON-active peer becomes
    reachable by bare name too. Order-preserving and de-duplicated.
    """
    if connector:
        from defenseclaw.commands import resolve_list_connector
        return list(app.cfg.skill_dirs(resolve_list_connector(app, connector)))
    dirs: list[str] = list(app.cfg.skill_dirs())  # active connector, first
    for d in _all_active_skill_dirs(app):
        if d not in dirs:
            dirs.append(d)
    return dirs


def _skill_match_dirs(app: AppContext, target: str, connector: str = "") -> list[str]:
    """Every on-disk skill directory that contains ``target`` (ND-1).

    One path per connector dir that holds a ``<target>`` subdirectory,
    active-connector matches first. Empty when nothing matches. Callers that
    must refuse an ambiguous bare name (e.g. ``skill scan``) inspect the
    length; :func:`_resolve_path` just takes the first (active-wins) match.
    """
    name = _skill_basename(target)
    matches: list[str] = []
    for d in _skill_search_dirs(app, connector):
        candidate = os.path.join(d, name)
        if os.path.isdir(candidate) and candidate not in matches:
            matches.append(candidate)
    return matches


def _skill_match_dir_scopes(app: AppContext, target: str, connector: str = "") -> list[tuple[str, str]]:
    """Every ``(connector, path)`` pair that contains ``target``.

    This is the connector-aware sibling of :func:`_skill_match_dirs` for
    commands that need to label/evaluate the matched connector, not just scan a
    filesystem path.
    """
    from defenseclaw.safety import is_symlink

    def _matched_candidate(skill_root: str, skill_name: str) -> str | None:
        candidate = os.path.join(skill_root, skill_name)
        if not os.path.isdir(candidate) or is_symlink(candidate):
            return None
        return os.path.realpath(candidate)

    name = _skill_basename(target)
    if connector:
        from defenseclaw.commands import resolve_list_connector
        resolved = resolve_list_connector(app, connector)
        scoped_matches: list[tuple[str, str]] = []
        for d in app.cfg.skill_dirs(resolved):
            candidate = _matched_candidate(d, name)
            if candidate and (resolved, candidate) not in scoped_matches:
                scoped_matches.append((resolved, candidate))
        return scoped_matches

    matches: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for c in _active_skill_connectors(app):
        for d in app.cfg.skill_dirs(c):
            candidate = _matched_candidate(d, name)
            if candidate and candidate not in seen_paths:
                matches.append((c, candidate))
                seen_paths.add(candidate)
    return matches


def _resolve_path(app: AppContext, target: str, connector: str = "") -> str | None:
    """Resolve a skill name or path to an actual directory.

    A bare name resolves across **every configured connector** (ND-1), not just
    the active one, so a skill living on a non-active peer is findable
    without ``--connector``. When the same name exists under more than one
    connector the active-connector copy wins here; verbs that must reject the
    ambiguity instead use :func:`_skill_match_dirs`.

    F-0503: the resolved path is stored as the pinned ``source_path`` of an
    allow/block entry (``skill allow``/``skill block`` → ``pe.set_source_path``)
    and is later compared against a presented asset's path during admission.
    Refuse symlinked candidates and return a canonical realpath so the stored
    allow entry is frozen to a concrete directory that cannot be swapped under
    it.
    """
    from defenseclaw.safety import is_symlink

    def _freeze(candidate: str) -> str | None:
        if is_symlink(candidate):
            return None
        return os.path.realpath(candidate)

    if os.path.isdir(target):
        return _freeze(target)
    matches = _skill_match_dirs(app, target, connector)
    for candidate in matches:
        frozen = _freeze(candidate)
        if frozen:
            return frozen
    return None


def _scan_skill_roots(app: AppContext, connector_flag: str) -> list[str]:
    """Configured skill roots a connector-reported scan dir must live under.

    F-0501: when ``--connector`` is given we scope containment to that
    connector's skill dirs; otherwise we allow the union across every
    configured connector (a skill may legitimately live under any of them).
    Returns ``[]`` when skill dirs can't be enumerated (older configs) so
    the caller fails open rather than blocking every scan — the connector
    info path is still the only place this is consulted.
    """
    cfg = app.cfg
    if not (hasattr(cfg, "skill_dirs") and callable(cfg.skill_dirs)):
        return []
    if connector_flag:
        try:
            from defenseclaw.commands import resolve_list_connector
            return list(cfg.skill_dirs(resolve_list_connector(app, connector_flag)))
        except Exception:  # noqa: BLE001 — fall back to the union below.
            pass
    return _all_active_skill_dirs(app)


def _all_active_skill_dirs(app: AppContext) -> list[str]:
    """Union of skill directories across every configured connector.

    Quarantine/restore resolve and validate against this union so each
    configured connector's skill can still be managed; single-connector installs
    collapse to that one connector's dirs, so their behavior is unchanged.
    Order-preserving and de-duplicated.
    """
    cfg = app.cfg
    if hasattr(cfg, "active_connectors"):
        try:
            connectors: list[str | None] = list(cfg.active_connectors()) or [None]
        except Exception:  # noqa: BLE001 — fall back to the active connector.
            connectors = [None]
    else:
        connectors = [None]
    dirs: list[str] = []
    for c in connectors:
        for d in cfg.skill_dirs(c):
            if d not in dirs:
                dirs.append(d)
    return dirs


def _active_skill_connectors(app: AppContext) -> list[str]:
    cfg = app.cfg
    if hasattr(cfg, "active_connectors"):
        try:
            names = [n for n in cfg.active_connectors() if n]
            if names:
                return names
        except Exception:  # noqa: BLE001 — fall back to singular active connector.
            pass
    if hasattr(cfg, "active_connector"):
        active = cfg.active_connector()
        if active:
            return [active]
    return ["openclaw"]


def _skill_info_path(info: dict[str, Any] | None) -> str:
    if not info:
        return ""
    for key in ("baseDir", "path", "filePath"):
        value = info.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


# ---------------------------------------------------------------------------
# Option 2: Remote scan via sidecar API
# ---------------------------------------------------------------------------

def _scan_via_sidecar(
    app: AppContext,
    target: str,
    name: str,
    as_json: bool,
    fatal: bool = True,
    connector: str = "",
    json_sink: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Send a scan request to the sidecar REST API (POST /v1/skill/scan).

    Used when DefenseClaw sidecar runs on a remote host and the CLI connects
    via SSM port-forward or direct network access.

    ``fatal`` controls error handling: single-target scans exit 1 on failure
    (default), but the multi-connector ``--all`` fan-out passes ``fatal=False``
    so one connector's remote error (e.g. a sidecar 500 on a malformed skill
    dir) is reported per-target and the rest of the fleet still gets scanned.
    """
    client = _sidecar_client(app)

    if not as_json:
        click.echo(ux.dim(f"[scan] remote skill-scanner via sidecar -> {target}"))

    try:
        data = client.scan_skill(target=target, name=name)
    except Exception as exc:
        if as_json:
            payload = _skill_scan_error_json_payload(target, exc, connector=connector)
            _emit_skill_json_payload(payload, json_sink=json_sink)
            if fatal:
                raise SystemExit(1)
            return payload
        click.echo(f"error: remote scan failed: {exc}", err=True)
        if fatal:
            raise SystemExit(1)
        return None

    if as_json:
        payload = _skill_remote_scan_json_payload(data, connector=connector)
        _emit_skill_json_payload(payload, json_sink=json_sink)
        return payload

    findings = data.get("findings") or data.get("Findings") or []
    max_sev = data.get("max_severity", "INFO")
    click.echo(f"  {ux._style('Skill:', fg='bright_black', bold=True)}    {name}")
    click.echo(f"  {ux._style('Target:', fg='bright_black', bold=True)}   {target} {ux.dim('(remote)')}")
    click.echo(f"  {ux._style('Findings:', fg='bright_black', bold=True)} {len(findings)}")

    if not findings:
        ux.ok("Verdict:  CLEAN", indent="  ")
    else:
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(max_sev, "white")
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        counts = {}
        for f in findings:
            s = f.get("severity") or f.get("Severity") or "INFO"
            counts[s] = counts.get(s, 0) + 1
        breakdown = ", ".join(
            f"{counts[s]} {s.lower()}" for s in sev_order if s in counts
        )
        verdict_txt = f"Verdict:  {max_sev} ({breakdown})"
        click.echo(f"  {ux._style(verdict_txt, fg=color, bold=True)}")
        click.echo()
        for f in findings:
            sev = f.get("severity") or f.get("Severity") or "INFO"
            title = f.get("title") or f.get("Title") or ""
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            click.echo(f"    {ux._style(f'[{sev}]', fg=sev_color, bold=True)}", nl=False)
            click.echo(f" {title}")
    return None


def _skill_remote_scan_json_payload(
    data: dict[str, Any], *, connector: str = "",
) -> dict[str, Any]:
    payload = dict(data)
    if connector:
        scanner = payload.pop("scanner", "skill-scanner")
        payload = {"scanner": scanner, "connector": connector, **payload}
    return payload


def _scan_all_remote(
    app: AppContext, as_json: bool, connector: str | None = None,
) -> list[dict[str, Any]]:
    """Scan all skills via the sidecar API.

    ``connector`` selects whose skill list to scan; when None it falls back to
    the active connector. The caller fans this out over every configured connector
    so ``skill scan --all --remote`` covers the whole fleet, matching the local
    ``--all`` path.
    """
    oc_list = _list_openclaw_skills_full(app, connector=connector)
    if not oc_list or not oc_list.get("skills"):
        if not as_json:
            click.echo("No skills found via sidecar.")
        return []

    json_rows: list[dict[str, Any]] = []
    for s in oc_list["skills"]:
        name = s.get("name", "")
        base_dir = s.get("baseDir") or s.get("filePath") or ""
        if not base_dir:
            click.echo(f"[scan] warning: no path for {name}", err=True)
            continue
        _scan_via_sidecar(
            app,
            target=base_dir,
            name=name,
            as_json=as_json,
            fatal=False,
            connector=connector or "",
            json_sink=json_rows if as_json else None,
        )
        if not as_json:
            click.echo()
    return json_rows


# ---------------------------------------------------------------------------
# Option 3: Fetch-to-temp scan (URL / registry targets)
# ---------------------------------------------------------------------------

def _is_url_target(target: str) -> bool:
    """Check if the target is a URL or registry reference."""
    return target.startswith("https://") or target.startswith("http://") or target.startswith("clawhub://")


def _scan_from_url(app: AppContext, url: str, as_json: bool) -> None:
    """Fetch a skill and scan locally, then clean up.

    Supports two schemes:
      clawhub://name[@version]  — uses `npx clawhub install` into a temp dir
      https://...               — downloads a .tar.gz or .zip archive
    """
    if url.startswith("clawhub://"):
        _scan_from_clawhub(app, url, as_json)
    else:
        _scan_from_http(app, url, as_json)


def _scan_from_clawhub(app: AppContext, uri: str, as_json: bool) -> Any:
    """Download a skill from the npm registry, scan locally, then clean up.

    Skills are bundled inside the 'openclaw' npm package at skills/<name>/.
    Flow: fetch openclaw tarball from npm → extract skills/<name>/ → scan → delete.
    """
    import shutil
    import tempfile

    from defenseclaw.registries.adapters._base import (
        MAX_SKILL_ARCHIVE_BYTES,
        IngestError,
        http_get,
    )

    name, _version = _parse_clawhub_uri(uri)
    if not name:
        click.echo(f"error: invalid clawhub URI: {uri}", err=True)
        raise SystemExit(1)

    if not as_json:
        click.echo(f"[scan] fetching skill {name!r} from openclaw registry ...")

    # Get the tarball URL from npm
    try:
        meta = json.loads(http_get(
            "https://registry.npmjs.org/openclaw/latest",
            accept="application/json",
            timeout=30,
        ))
        tarball_url = meta.get("dist", {}).get("tarball")
    except (IngestError, json.JSONDecodeError) as exc:
        click.echo(f"error: npm registry lookup failed: {exc}", err=True)
        raise SystemExit(1)

    if not tarball_url:
        click.echo("error: could not resolve openclaw tarball URL from npm", err=True)
        raise SystemExit(1)

    if not as_json:
        click.echo(f"[scan] downloading {tarball_url}")

    tmpdir = tempfile.mkdtemp(prefix="defenseclaw-clawhub-")
    try:
        raw = http_get(
            tarball_url,
            accept="application/gzip, application/x-tar, application/octet-stream, */*;q=0.5",
            timeout=120,
            max_bytes=MAX_SKILL_ARCHIVE_BYTES,
            payload_label="skill archive",
        )

        archive_path = os.path.join(tmpdir, "openclaw.tgz")
        with open(archive_path, "wb") as f:
            f.write(raw)

        if not as_json:
            size_mb = os.path.getsize(archive_path) / (1024 * 1024)
            click.echo(f"[scan] downloaded {size_mb:.1f} MB, extracting skill {name!r} ...")

        skill_prefix = f"package/skills/{name}/"
        skill_dir = os.path.join(tmpdir, "skill")
        os.makedirs(skill_dir, exist_ok=True)

        if not as_json:
            click.echo(
                f"[scan] extracting prefix={skill_prefix!r} → {skill_dir!s}"
            )
        # ("Untrusted skill archives can decompress
        # without an output cap"): _safe_tar_extract enforces the same
        # post-decompression caps as _scan_from_http; surface the
        # rejection cleanly so the temp tree (cleaned in `finally`) does
        # not appear to have completed extraction.
        try:
            _safe_tar_extract(archive_path, skill_dir, skill_prefix, strip=3)
        except _SkillExtractTooLargeError as exc:
            click.echo(f"error: clawhub skill archive rejected: {exc}", err=True)
            raise SystemExit(1)

        os.unlink(archive_path)  # free disk immediately

        found = bool(os.listdir(skill_dir))
        if not as_json and found:
            click.echo(f"[scan] extracted entries in skill_dir: {os.listdir(skill_dir)!r}")

        if not found:
            click.echo(f"error: skill {name!r} not found in openclaw package", err=True)
            raise SystemExit(1)

        if not as_json:
            click.echo(f"[scan] skill-scanner -> {skill_dir}")

        result = _build_skill_scanner(app).scan(skill_dir)

        if app.logger:
            app.logger.log_scan(result)

        if as_json:
            click.echo(result.to_json())
        else:
            _print_result(name, result)
        return result

    except IngestError as exc:
        click.echo(f"error: download failed: {exc}", err=True)
        raise SystemExit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if not as_json:
            click.echo("[scan] cleaned up temporary files")


def _scan_from_http(
    app: AppContext,
    url: str,
    as_json: bool,
    *,
    expected_sha256: str = "",
    require_sha256: bool = False,
    allow_private: bool = False,
    auth_env: str = "",
) -> Any:
    """Download a skill archive from HTTP(S), extract, scan, then clean up."""
    import hashlib
    import shutil
    import tarfile
    import tempfile
    import zipfile

    from defenseclaw.registries.adapters._base import (
        MAX_SKILL_ARCHIVE_BYTES,
        IngestError,
        http_get,
    )

    if not as_json:
        click.echo(f"[scan] fetching skill from {url}")

    expected_sha256 = expected_sha256.strip().lower()
    if require_sha256 and not expected_sha256:
        click.echo("error: sha256 is required for registry http(s) skill archives", err=True)
        raise SystemExit(1)
    if expected_sha256 and not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        click.echo("error: sha256 must be 64 lowercase or uppercase hex chars", err=True)
        raise SystemExit(1)

    tmpdir = tempfile.mkdtemp(prefix="defenseclaw-skill-")
    try:
        raw = http_get(
            url,
            auth_env=auth_env,
            accept="application/gzip, application/x-tar, application/zip, application/octet-stream, */*;q=0.5",
            allow_private=allow_private,
            timeout=60,
            max_bytes=MAX_SKILL_ARCHIVE_BYTES,
            payload_label="skill archive",
        )
        if expected_sha256:
            actual_sha256 = hashlib.sha256(raw).hexdigest()
            if actual_sha256 != expected_sha256:
                click.echo(
                    "error: sha256 mismatch for skill archive "
                    f"(expected {expected_sha256}, got {actual_sha256})",
                    err=True,
                )
                raise SystemExit(1)

        download_path = os.path.join(tmpdir, "download")
        with open(download_path, "wb") as f:
            f.write(raw)

        extract_dir = os.path.join(tmpdir, "skill")
        os.makedirs(extract_dir, exist_ok=True)

        # ("Untrusted skill archives can decompress
        # without an output cap"): replace the legacy `tf.extractall` /
        # `zf.extractall` calls with capped streaming extractors so a
        # malicious registry or scan URL cannot turn a small compressed
        # body into multi-GB extraction or a member-count flood. Caps
        # are enforced in :func:`_safe_tar_extractall_capped` and
        # :func:`_safe_zip_extractall_capped`. On violation we delete
        # the temp tree (the outer ``finally`` already handles that)
        # and surface a clear error.
        try:
            if tarfile.is_tarfile(download_path):
                if not as_json:
                    click.echo(f"[scan] tarfile: extracting {download_path!s} -> {extract_dir!s}")
                with tarfile.open(download_path) as tf:
                    members = tf.getnames()
                    if not as_json:
                        n = len(members)
                        preview = members[:20]
                        more = f" ... ({n} total)" if n > 20 else ""
                        click.echo(f"[scan] tarfile: members={n} first={preview!r}{more}")
                    _safe_tar_extractall_capped(tf, extract_dir)
                if not as_json:
                    click.echo(f"[scan] tarfile: extractall done -> listing={os.listdir(extract_dir)!r}")
            elif zipfile.is_zipfile(download_path):
                with zipfile.ZipFile(download_path) as zf:
                    _safe_zip_extractall_capped(zf, extract_dir)
            else:
                click.echo("error: unsupported archive format (expected .tar.gz or .zip)", err=True)
                raise SystemExit(1)
        except _SkillExtractTooLargeError as exc:
            click.echo(f"error: skill archive rejected: {exc}", err=True)
            raise SystemExit(1)

        entries = os.listdir(extract_dir)
        skill_dir = extract_dir
        if len(entries) == 1:
            single = os.path.join(extract_dir, entries[0])
            if os.path.isdir(single):
                skill_dir = single

        name = os.path.basename(skill_dir)
        if not as_json:
            click.echo(f"[scan] skill-scanner -> {skill_dir} (fetched)")

        result = _build_skill_scanner(app).scan(skill_dir)

        if app.logger:
            app.logger.log_scan(result)

        if as_json:
            click.echo(result.to_json())
        else:
            _print_result(name, result)
        return result

    except IngestError as exc:
        click.echo(f"error: download failed: {exc}", err=True)
        raise SystemExit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


_CLAWHUB_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def _parse_clawhub_uri(uri: str) -> tuple[str, str | None]:
    """Parse clawhub://name[@version] → (name, version or None).

    Names are restricted to alphanumeric, dots, hyphens, and underscores
    to prevent path traversal when used in tar extraction prefixes.
    """
    path = uri.removeprefix("clawhub://")
    if not path:
        return ("", None)

    version: str | None = None
    if "@" in path:
        name, version = path.split("@", 1)
    else:
        name = path

    if not _CLAWHUB_NAME_RE.match(name):
        return ("", None)
    return (name, version)


# ("Untrusted skill archives can decompress without an
# output cap"): MAX_SKILL_ARCHIVE_BYTES only caps the *compressed*
# response body (128 MiB); a tiny tar/zip can still expand into many GB
# or millions of members. The constants below bound total uncompressed
# bytes, the member count, and per-file size on extraction. They are
# generous enough for legitimate skill archives but bound the worst
# case attackers can amplify into disk/CPU exhaustion.
MAX_SKILL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024  # 512 MiB
MAX_SKILL_MEMBER_COUNT = 10_000
MAX_SKILL_PER_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB


class _SkillExtractTooLargeError(Exception):
    """Raised when a tar/zip archive exceeds the post-decompression caps."""


def _check_extract_caps(member_count: int, total_bytes: int, member_size: int, member_name: str) -> None:
    if member_count > MAX_SKILL_MEMBER_COUNT:
        raise _SkillExtractTooLargeError(
            f"archive exceeds member-count cap "
            f"({member_count} > {MAX_SKILL_MEMBER_COUNT})"
        )
    if member_size > MAX_SKILL_PER_FILE_BYTES:
        raise _SkillExtractTooLargeError(
            f"archive entry {member_name!r} exceeds per-file cap "
            f"({member_size} > {MAX_SKILL_PER_FILE_BYTES})"
        )
    if total_bytes > MAX_SKILL_UNCOMPRESSED_BYTES:
        raise _SkillExtractTooLargeError(
            f"archive total uncompressed size exceeds cap "
            f"({total_bytes} > {MAX_SKILL_UNCOMPRESSED_BYTES})"
        )


def _safe_tar_extractall_capped(tf, extract_dir: str) -> None:
    """Extract every regular file from *tf* into *extract_dir* with caps.

    Enforces `MAX_SKILL_MEMBER_COUNT`, `MAX_SKILL_PER_FILE_BYTES`, and
    `MAX_SKILL_UNCOMPRESSED_BYTES`. Uses ``filter="data"`` semantics
    (skip symlinks/hardlinks/devices) to avoid path-traversal and
    privileged-bit smuggling. Raises `_SkillExtractTooLargeError` on cap
    violation; callers must propagate so the temp directory is removed.
    """
    safe_root = os.path.realpath(extract_dir)
    members = tf.getmembers()
    if len(members) > MAX_SKILL_MEMBER_COUNT:
        raise _SkillExtractTooLargeError(
            f"tar archive lists {len(members)} members "
            f"(> {MAX_SKILL_MEMBER_COUNT})"
        )
    total = 0
    seen = 0
    for member in members:
        if member.issym() or member.islnk() or member.isdev() or member.ischr() or member.isblk() or member.isfifo():
            continue
        target = os.path.realpath(os.path.join(extract_dir, member.name))
        if not (target == safe_root or target.startswith(safe_root + os.sep)):
            raise _SkillExtractTooLargeError(
                f"tar archive contains path-traversal entry {member.name!r}"
            )
        if member.isdir():
            os.makedirs(target, exist_ok=True)
            continue
        if not member.isfile():
            continue
        seen += 1
        size = max(member.size, 0)
        total += size
        _check_extract_caps(seen, total, size, member.name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        src = tf.extractfile(member)
        if src is None:
            continue
        try:
            written = 0
            with open(target, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_SKILL_PER_FILE_BYTES:
                        raise _SkillExtractTooLargeError(
                            f"tar entry {member.name!r} streamed "
                            f"more bytes than per-file cap "
                            f"({written} > {MAX_SKILL_PER_FILE_BYTES})"
                        )
                    dst.write(chunk)
        finally:
            src.close()


def _safe_zip_extractall_capped(zf, extract_dir: str) -> None:
    """Extract every entry from *zf* into *extract_dir* with caps.

    Enforces the same suite of limits as
    :func:`_safe_tar_extractall_capped`. Refuses path traversal and
    streams per-file content with a watchdog on the per-file cap.
    """
    safe_root = os.path.realpath(extract_dir)
    infolist = zf.infolist()
    if len(infolist) > MAX_SKILL_MEMBER_COUNT:
        raise _SkillExtractTooLargeError(
            f"zip archive lists {len(infolist)} members "
            f"(> {MAX_SKILL_MEMBER_COUNT})"
        )
    total = 0
    seen = 0
    for member in infolist:
        target = os.path.realpath(os.path.join(extract_dir, member.filename))
        if not (target == safe_root or target.startswith(safe_root + os.sep)):
            raise _SkillExtractTooLargeError(
                f"zip archive contains path-traversal entry {member.filename!r}"
            )
        if member.is_dir():
            os.makedirs(target, exist_ok=True)
            continue
        seen += 1
        size = max(member.file_size, 0)
        total += size
        _check_extract_caps(seen, total, size, member.filename)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(member, "r") as src, open(target, "wb") as dst:
            written = 0
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_SKILL_PER_FILE_BYTES:
                    raise _SkillExtractTooLargeError(
                        f"zip entry {member.filename!r} streamed more "
                        f"bytes than per-file cap "
                        f"({written} > {MAX_SKILL_PER_FILE_BYTES})"
                    )
                dst.write(chunk)


def _safe_tar_extract(
    archive_path: str, dest_dir: str, prefix: str, *, strip: int = 0
) -> None:
    """Extract members under *prefix* from a tar archive into *dest_dir*.

    Each member name is validated after stripping *strip* leading path
    components to prevent path traversal (``..`` segments, absolute paths,
    or symlinks escaping *dest_dir*). ("Untrusted skill archives can decompress without an output cap"):
    enforces the same global member-count, per-file, and total-bytes
    caps that the HTTP scan path applies via
    :func:`_safe_tar_extractall_capped`.
    """
    import tarfile

    real_dest = os.path.realpath(dest_dir)
    with tarfile.open(archive_path, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_SKILL_MEMBER_COUNT:
            raise _SkillExtractTooLargeError(
                f"tar archive lists {len(members)} members "
                f"(> {MAX_SKILL_MEMBER_COUNT})"
            )
        total = 0
        seen = 0
        for member in members:
            if not member.name.startswith(prefix):
                continue
            if member.issym() or member.islnk():
                continue

            parts = member.name.split("/")
            if len(parts) <= strip:
                continue
            stripped = os.path.join(*parts[strip:])
            target = os.path.realpath(os.path.join(dest_dir, stripped))
            if not (target == real_dest or target.startswith(real_dest + os.sep)):
                continue
            if ".." in stripped.split(os.sep):
                continue

            if member.isdir():
                os.makedirs(target, exist_ok=True)
            elif member.isfile():
                seen += 1
                size = max(member.size, 0)
                total += size
                _check_extract_caps(seen, total, size, member.name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with tf.extractfile(member) as src:
                    if src is None:
                        continue
                    written = 0
                    with open(target, "wb") as dst:
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > MAX_SKILL_PER_FILE_BYTES:
                                raise _SkillExtractTooLargeError(
                                    f"tar entry {member.name!r} streamed "
                                    f"more bytes than per-file cap "
                                    f"({written} > {MAX_SKILL_PER_FILE_BYTES})"
                                )
                            dst.write(chunk)


def _print_result(name: str, result) -> None:
    click.echo(f"  {ux._style('Skill:', fg='bright_black', bold=True)}    {name}")
    click.echo(f"  {ux._style('Target:', fg='bright_black', bold=True)}   {result.target}")
    click.echo(f"  {ux._style('Duration:', fg='bright_black', bold=True)} {result.duration.total_seconds():.2f}s")
    click.echo(f"  {ux._style('Findings:', fg='bright_black', bold=True)} {len(result.findings)}")

    if result.is_clean():
        ux.ok("Verdict:  CLEAN", indent="  ")
    else:
        sev = result.max_severity()
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        counts = {}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        breakdown = ", ".join(
            f"{counts[s]} {s.lower()}" for s in sev_order if s in counts
        )
        verdict_txt = f"Verdict:  {sev} ({breakdown})"
        click.echo(f"  {ux._style(verdict_txt, fg=color, bold=True)}")
        click.echo()
        for f in result.findings:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            click.echo(f"    {ux._style(f'[{f.severity}]', fg=sev_color, bold=True)}", nl=False)
            click.echo(f" {f.title}")
            if f.location:
                click.echo(f"      {ux.dim('Location:')} {f.location}")
            if f.description:
                desc = f.description[:120] + "..." if len(f.description) > 120 else f.description
                click.echo(f"      {desc}")
            if f.remediation:
                click.echo(f"      {ux.dim('Fix:')} {f.remediation}")


# ---------------------------------------------------------------------------
# skill block / allow / unblock / disable / enable
#
# SK-4: these accept ``--connector`` to scope policy. Bare block/disable keep
# the legacy unscoped row; bare allow/unblock fan out to matching configured
# connector copies (plus stale scoped rows) when there is connector-specific
# state to touch. The connector dimension lives in the audit store's
# per-connector column via PolicyEngine ``*_for_connector``; reads resolve
# most-specific-wins (connector entry, then global). Runtime honoring is at the
# admission gate (enforce/admission.py threads the connector). Mirrors the
# ``mcp`` N2 / plugin P-A commands.
# ---------------------------------------------------------------------------

_CONNECTOR_SCOPE_HELP = (
    "Scope to one connector (default: matching connector copies when present; "
    "otherwise unscoped policy). "
    "Pass --connector <name> to narrow to that peer."
)


def _resolve_connector_scope(app: AppContext, connector_flag: str) -> str:
    """Validate a connector-scoped skill policy flag.

    Bare policy commands intentionally write a global row. When a connector is
    supplied, route through the same resolver as list/scan/info/install so a
    typo cannot create inert policy state for a non-existent connector.
    """
    if not connector_flag:
        return ""
    from defenseclaw.commands import resolve_list_connector
    return resolve_list_connector(app, connector_flag)


def _skill_policy_fanout_connectors(
    app: AppContext, pe: Any, skill_name: str,
) -> list[str]:
    """Connectors where a bare skill policy command should apply.

    The set includes matching on-disk connector copies plus any connector that
    already has scoped enforcement for the skill, so bare allow/unblock can
    clean stale connector-scoped rows even after a copy was removed.
    """
    active_order = {c: i for i, c in enumerate(_active_skill_connectors(app))}
    seen: set[str] = set()
    connectors: list[str] = []

    def add(connector: str) -> None:
        if not connector or connector in seen:
            return
        seen.add(connector)
        connectors.append(connector)

    for connector, _path in _skill_match_dir_scopes(app, skill_name):
        add(connector)

    if pe is not None:
        for entry in pe.list_by_type("skill"):
            if entry.target_name == skill_name and entry.connector:
                add(entry.connector)

    return sorted(connectors, key=lambda c: active_order.get(c, len(active_order)))


def _skill_has_connector_enforcement(
    app: AppContext, skill_name: str, connector: str,
) -> bool:
    if app.store is None:
        return False
    return (
        app.store.has_action("skill", skill_name, "install", "block", connector)
        or app.store.has_action("skill", skill_name, "install", "allow", connector)
        or app.store.has_action("skill", skill_name, "file", "quarantine", connector)
        or app.store.has_action("skill", skill_name, "runtime", "disable", connector)
    )


def _format_connector_scope_list(connectors: list[str]) -> str:
    return ", ".join(f"connector={connector}" for connector in connectors)


def _resolve_skill_quarantine_restore_scopes(
    app: AppContext, pe: Any, skill_name: str, connector_flag: str,
) -> list[tuple[str, Any | None]]:
    """Resolve which quarantine action rows a restore command should use.

    Explicit ``--connector`` narrows to that connector. Bare restore restores
    the legacy global quarantine row plus every configured connector-scoped
    quarantine row for the skill.
    """
    if connector_flag:
        connector = _resolve_connector_scope(app, connector_flag)
        return [(connector, pe.get_action("skill", skill_name, connector))]

    matches: list[tuple[str, Any]] = []
    global_entry = pe.get_action("skill", skill_name)
    if global_entry is not None and global_entry.actions.file == "quarantine":
        matches.append(("", global_entry))

    active_order = {c: i for i, c in enumerate(_active_skill_connectors(app))}
    seen_connectors: set[str] = set()
    for entry in pe.list_by_type("skill"):
        c = entry.connector
        if not c or c in seen_connectors:
            continue
        seen_connectors.add(c)
        scoped_entry = pe.get_action("skill", skill_name, c)
        if scoped_entry is not None and scoped_entry.actions.file == "quarantine":
            matches.append((c, scoped_entry))

    if matches:
        return sorted(matches, key=lambda item: active_order.get(item[0], len(active_order)))
    return [("", global_entry)]


@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for blocking")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def block(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Add a skill to the install block list.

    Blocked skills are rejected by 'skill install' before any scan.
    Does not affect already-running skills — use 'skill disable' or
    'skill quarantine' for that.

    Bare ``skill block <name>`` records a global block that covers configured
    connector copies; ``--connector <name>`` narrows the block to one peer.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual block via CLI"

    connector = _resolve_connector_scope(app, connector_flag)
    if connector:
        if pe.is_blocked_for_connector("skill", skill_name, connector):
            if app.store and app.store.has_action(
                "skill", skill_name, "install", "block", connector,
            ):
                click.echo(f"Already blocked for {connector}: {skill_name}")
            else:
                click.echo(f"Already blocked globally (covers {connector}): {skill_name}")
            return
        pe.block_for_connector("skill", skill_name, connector, reason)
        skill_path = _resolve_path(app, skill_name, connector)
        if skill_path:
            pe.set_source_path("skill", skill_name, skill_path, connector)
        click.secho(
            f"[skill] {skill_name!r} added to block list (connector={connector})",
            fg="red",
        )
    else:
        pe.block("skill", skill_name, reason)
        skill_path = _resolve_path(app, skill_name)
        if skill_path:
            pe.set_source_path("skill", skill_name, skill_path)
        affected_connectors = [
            target_connector
            for target_connector, _path in _skill_match_dir_scopes(app, skill_name)
        ]
        suffix = (
            f" for {_format_connector_scope_list(affected_connectors)}"
            if affected_connectors
            else ""
        )
        click.secho(f"[skill] {skill_name!r} added to block list{suffix}", fg="red")

    if app.logger:
        app.logger.log_action(
            "skill-block", skill_name, f"reason={reason} connector={connector}",
        )

    from defenseclaw.commands import hint
    hint(f"Unblock later:  defenseclaw skill unblock {skill_name}")


# ---------------------------------------------------------------------------
# skill unblock
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scope to one connector (default: clear matching connector copies and unscoped state). "
        "Pass --connector <name> to clear only that peer's per-connector state; "
        "a global block stays in force."
    ),
)
@pass_ctx
def unblock(app: AppContext, name: str, connector_flag: str) -> None:
    """Remove a skill from the block list and clear all enforcement state.

    Clears block, quarantine, and disable actions without adding to the
    allow list — the skill will go through normal scanning on next install.

    Bare clears matching connector-scoped and unscoped enforcement state;
    ``--connector <name>`` clears only that peer's per-connector state (a
    global block stays in force — unblock it without --connector to lift it).

    To also restore quarantined files, run 'skill restore' after unblocking.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    # SK-4 connector-scoped unblock: EXACT-match on the targeted peer so a
    # connector unblock never falsely reports (or clears) the global block.
    connector = _resolve_connector_scope(app, connector_flag)
    if connector:
        has_state = bool(app.store) and (
            app.store.has_action("skill", skill_name, "install", "block", connector)
            or app.store.has_action("skill", skill_name, "install", "allow", connector)
            or app.store.has_action("skill", skill_name, "file", "quarantine", connector)
            or app.store.has_action("skill", skill_name, "runtime", "disable", connector)
        )
        if not has_state:
            click.echo(
                f"[skill] {skill_name!r} has no enforcement state to clear for {connector}"
            )
            return
        pe.remove_action_for_connector("skill", skill_name, connector)
        click.secho(
            f"[skill] {skill_name!r} all enforcement state cleared "
            f"(connector={connector}) (allow/block/quarantine/disable)",
            fg="green",
        )
        if app.logger:
            app.logger.log_action(
                "skill-unblock", skill_name, f"manual unblock via CLI connector={connector}",
            )
        return

    targets = _skill_policy_fanout_connectors(app, pe, skill_name)
    has_unscoped_state = bool(app.store) and (
        pe.is_blocked("skill", skill_name)
        or pe.is_allowed("skill", skill_name)
        or pe.is_quarantined("skill", skill_name)
        or app.store.has_action("skill", skill_name, "runtime", "disable")
    )
    has_scoped_state = any(
        _skill_has_connector_enforcement(app, skill_name, target_connector)
        for target_connector in targets
    )
    if targets and (has_unscoped_state or has_scoped_state):
        for target_connector in targets:
            pe.remove_action_for_connector("skill", skill_name, target_connector)
            click.secho(
                f"[skill] {skill_name!r} all enforcement state cleared "
                f"(connector={target_connector}) (allow/block/quarantine/disable)",
                fg="green",
            )
        if has_unscoped_state:
            pe.remove_action("skill", skill_name)
        click.echo(
            "  The skill will go through normal scanning on next install."
        )
        if app.logger:
            app.logger.log_action(
                "skill-unblock", skill_name, "manual unblock via CLI connector=all",
            )
        return

    has_state = (
        pe.is_blocked("skill", skill_name)
        or pe.is_allowed("skill", skill_name)
        or pe.is_quarantined("skill", skill_name)
        or app.store.has_action("skill", skill_name, "runtime", "disable")
    )
    if not has_state:
        click.echo(f"[skill] {skill_name!r} has no enforcement state to clear")
        return

    entry = pe.get_action("skill", skill_name)
    saved_path = entry.source_path if entry else ""
    runtime_disabled = bool(entry and entry.actions.runtime == "disable")

    runtime_cleared = True
    if runtime_disabled:
        runtime_cleared = _enable_skill_via_gateway(app, skill_name)

    if runtime_cleared:
        pe.remove_action("skill", skill_name)
        click.secho(
            f"[skill] {skill_name!r} all enforcement state cleared "
            "(allow/block/quarantine/disable)",
            fg="green",
        )
    else:
        pe.unblock("skill", skill_name)
        pe.clear_quarantine("skill", skill_name)
        click.secho(
            f"[skill] {skill_name!r} install/file enforcement cleared; "
            "runtime disable remains until the gateway is reachable",
            fg="yellow",
        )
    if saved_path:
        restore_hint = f"--path \"{saved_path}\""
    else:
        restore_hint = "--path <original-dir>"
    click.echo(
        f"  Tip: if files are quarantined, run "
        f"'defenseclaw skill restore {skill_name} {restore_hint}'"
    )

    if app.logger:
        app.logger.log_action("skill-unblock", skill_name, "manual unblock via CLI")


# ---------------------------------------------------------------------------
# skill allow
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for allowing")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def allow(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Add a skill to the install allow list.

    Allow-listed skills skip the scan gate during install.
    Adding a skill also removes it from the block list.

    Bare ``skill allow <name>`` allows matching configured connector copies;
    ``--connector <name>`` narrows the allow to one peer. If no connector copy
    or scoped policy row exists, the legacy unscoped allow row is used.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual allow via CLI"

    # SK-4 connector-scoped allow: write the narrowed entry and clear residual
    # file/runtime state for that peer. The gateway runtime-enable dance below
    # is for the global/OpenClaw runtime lane and stays on the bare path.
    connector = _resolve_connector_scope(app, connector_flag)
    if connector:
        if pe.is_allowed_for_connector("skill", skill_name, connector):
            if app.store and app.store.has_action(
                "skill", skill_name, "install", "allow", connector,
            ):
                click.echo(f"Already allowed for {connector}: {skill_name}")
            else:
                click.echo(f"Already allowed globally (covers {connector}): {skill_name}")
            return
        pe.allow_for_connector("skill", skill_name, connector, reason)
        skill_path = _resolve_path(app, skill_name, connector)
        if skill_path:
            pe.set_source_path("skill", skill_name, skill_path, connector)
        click.secho(
            f"[skill] {skill_name!r} added to allow list (connector={connector})",
            fg="green",
        )
        if app.logger:
            app.logger.log_action(
                "skill-allow", skill_name, f"reason={reason} connector={connector}",
            )
        return

    targets = _skill_policy_fanout_connectors(app, pe, skill_name)
    if targets:
        for target_connector in targets:
            pe.allow_for_connector("skill", skill_name, target_connector, reason)
            skill_path = _resolve_path(app, skill_name, target_connector)
            if skill_path:
                pe.set_source_path("skill", skill_name, skill_path, target_connector)
            click.secho(
                f"[skill] {skill_name!r} added to allow list "
                f"(connector={target_connector})",
                fg="green",
            )
        if app.store and pe.get_action("skill", skill_name) is not None:
            pe.remove_action("skill", skill_name)
        if app.logger:
            app.logger.log_action(
                "skill-allow", skill_name, f"reason={reason} connector=all",
            )
        return

    entry = pe.get_action("skill", skill_name)
    runtime_disabled = bool(entry and entry.actions.runtime == "disable")
    runtime_cleared = True
    if runtime_disabled:
        runtime_cleared = _enable_skill_via_gateway(app, skill_name)

    if runtime_cleared:
        pe.allow("skill", skill_name, reason)
    else:
        app.store.set_action_field("skill", skill_name, "install", "allow", reason)

    skill_path = _resolve_path(app, skill_name)
    if skill_path:
        pe.set_source_path("skill", skill_name, skill_path)
    if runtime_cleared:
        click.secho(f"[skill] {skill_name!r} added to allow list", fg="green")
    else:
        click.secho(
            f"[skill] {skill_name!r} added to allow list; runtime disable remains until the gateway is reachable",
            fg="yellow",
        )

    if app.logger:
        app.logger.log_action("skill-allow", skill_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# skill disable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

_SKILL_RUNTIME_PROBE_CONNECTORS = {"codex", "claudecode"}


def _normalize_runtime_connector(connector: str) -> str:
    from defenseclaw import connector_paths
    return connector_paths.normalize(connector or "openclaw")


def _active_connector_name(app: AppContext) -> str:
    if hasattr(app.cfg, "active_connector"):
        return _normalize_runtime_connector(app.cfg.active_connector() or "openclaw")
    return "openclaw"


def _skill_runtime_probe_enforced(connector: str) -> bool:
    return _normalize_runtime_connector(connector) in _SKILL_RUNTIME_PROBE_CONNECTORS


def _skill_runtime_fanout_connectors(
    app: AppContext, pe: Any, skill_name: str, *, include_stale: bool,
) -> list[str]:
    if include_stale:
        raw_connectors = _skill_policy_fanout_connectors(app, pe, skill_name)
    else:
        raw_connectors = [c for c, _path in _skill_match_dir_scopes(app, skill_name)]

    seen: set[str] = set()
    connectors: list[str] = []
    for connector in raw_connectors:
        normalized = _normalize_runtime_connector(connector)
        if normalized and normalized not in seen:
            seen.add(normalized)
            connectors.append(normalized)
    return connectors


def _skill_runtime_should_fanout(
    app: AppContext, active_connector: str, targets: list[str],
) -> bool:
    return bool(targets) and (
        len(_active_skill_connectors(app)) > 1
        or active_connector != "openclaw"
        or active_connector not in targets
    )


def _warn_skill_runtime_disable_advisory(skill_name: str, connector: str, scoped: bool) -> None:
    scope = f"connector={connector}" if scoped else f"active connector={connector}"
    click.secho(
        f"warning: skill runtime disable is advisory for {scope}; that connector "
        "does not emit skill runtime events DefenseClaw can gate. Use "
        f"'defenseclaw skill quarantine {skill_name}"
        + (f" --connector {connector}" if scoped else "")
        + "' for hard enforcement on that peer.",
        fg="yellow",
    )


@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for disabling")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def disable(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Disable a skill at runtime.

    OpenClaw uses the gateway RPC. Hook connectors store a runtime-disable
    policy row that the hook runtime gate enforces when that connector emits
    skill runtime events. This is runtime-only — it does not block install or
    quarantine files.

    Bare records the disable for every matching configured connector copy when
    one can be found, falling back to the legacy unscoped row for older
    single-connector layouts. ``--connector <name>`` narrows the
    runtime-disable record to that peer.
    """
    from defenseclaw.enforce import PolicyEngine
    skill_name = os.path.basename(name)

    active = _active_connector_name(app)

    if not reason:
        reason = "manual disable via CLI"

    connector = _resolve_connector_scope(app, connector_flag)
    pe = PolicyEngine(app.store)
    target_connector = _normalize_runtime_connector(connector or active)

    if not connector_flag:
        fanout_connectors = _skill_runtime_fanout_connectors(
            app, pe, skill_name, include_stale=False,
        )
        if _skill_runtime_should_fanout(app, target_connector, fanout_connectors):
            gateway_client = None
            for target in fanout_connectors:
                if target == "openclaw":
                    gateway_client = gateway_client or _sidecar_client(app)
                    try:
                        gateway_client.disable_skill(skill_name)
                    except Exception as exc:
                        click.echo(f"error: gateway disable failed: {exc}", err=True)
                        raise SystemExit(1)
                    click.echo(
                        f"[skill] {skill_name!r} disabled via gateway RPC "
                        f"(connector={target})"
                    )
                else:
                    click.echo(
                        f"[skill] {skill_name!r} runtime disable recorded "
                        f"(connector={target})"
                    )
                    if _skill_runtime_probe_enforced(target):
                        click.echo(
                            f"  Enforced by hook runtime gate for connector={target}."
                        )
                    else:
                        _warn_skill_runtime_disable_advisory(skill_name, target, True)

                pe.disable_for_connector("skill", skill_name, target, reason)

            if app.logger:
                app.logger.log_action(
                    "skill-disable", skill_name, f"reason={reason} connector=all",
                )
            return

    if target_connector == "openclaw":
        client = _sidecar_client(app)
        try:
            client.disable_skill(skill_name)
        except Exception as exc:
            click.echo(f"error: gateway disable failed: {exc}", err=True)
            raise SystemExit(1)

        click.echo(f'[skill] {skill_name!r} disabled via gateway RPC')
    elif connector_flag:
        click.echo(
            f"[skill] {skill_name!r} runtime disable recorded "
            f"(connector={target_connector})"
        )
        if _skill_runtime_probe_enforced(target_connector):
            click.echo(
                f"  Enforced by hook runtime gate for connector={target_connector}."
            )
        else:
            _warn_skill_runtime_disable_advisory(skill_name, target_connector, True)
    else:
        click.echo(f"[skill] {skill_name!r} runtime disable recorded globally")
        if _skill_runtime_probe_enforced(target_connector):
            click.echo(
                "  Enforced by hook runtime gates for connectors that emit skill events."
            )
        else:
            _warn_skill_runtime_disable_advisory(skill_name, target_connector, False)

    if connector:
        pe.disable_for_connector("skill", skill_name, target_connector, reason)
    else:
        pe.disable("skill", skill_name, reason)

    if app.logger:
        app.logger.log_action(
            "skill-disable", skill_name, f"reason={reason} connector={connector}",
        )


# ---------------------------------------------------------------------------
# skill enable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def enable(app: AppContext, name: str, connector_flag: str) -> None:
    """Enable a previously disabled skill.

    This is a runtime-only action. Bare clears runtime-disable records for
    every matching configured connector copy plus any legacy unscoped row.
    ``--connector <name>`` clears only that peer's runtime-disable record.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    active = _active_connector_name(app)
    connector = _resolve_connector_scope(app, connector_flag)
    target_connector = _normalize_runtime_connector(connector or active)
    pe = PolicyEngine(app.store)

    if not connector_flag:
        fanout_connectors = _skill_runtime_fanout_connectors(
            app, pe, skill_name, include_stale=True,
        )
        if _skill_runtime_should_fanout(app, target_connector, fanout_connectors):
            gateway_client = None
            for target in fanout_connectors:
                if target == "openclaw":
                    gateway_client = gateway_client or _sidecar_client(app)
                    try:
                        gateway_client.enable_skill(skill_name)
                    except Exception as exc:
                        click.echo(f"error: gateway enable failed: {exc}", err=True)
                        raise SystemExit(1)
                    click.echo(
                        f"[skill] {skill_name!r} enabled via gateway RPC "
                        f"(connector={target})"
                    )
                else:
                    click.echo(
                        f"[skill] {skill_name!r} runtime disable cleared "
                        f"(connector={target})"
                    )
                pe.enable_for_connector("skill", skill_name, target)

            pe.enable("skill", skill_name)
            if app.logger:
                app.logger.log_action(
                    "skill-enable",
                    skill_name,
                    "re-enabled via CLI connector=all",
                )
            return

    if target_connector == "openclaw":
        client = _sidecar_client(app)
        try:
            client.enable_skill(skill_name)
        except Exception as exc:
            click.echo(f"error: gateway enable failed: {exc}", err=True)
            raise SystemExit(1)
        click.echo(f'[skill] {skill_name!r} enabled via gateway RPC')
    elif connector_flag:
        click.echo(
            f"[skill] {skill_name!r} runtime disable cleared "
            f"(connector={target_connector})"
        )
    else:
        click.echo(f"[skill] {skill_name!r} global runtime disable cleared")

    if connector:
        pe.enable_for_connector("skill", skill_name, target_connector)
    else:
        pe.enable("skill", skill_name)

    if app.logger:
        app.logger.log_action(
            "skill-enable", skill_name, f"re-enabled via CLI connector={connector}",
        )


# ---------------------------------------------------------------------------
# skill quarantine
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help="Connector whose copy of the skill to quarantine "
    "(default: quarantine every matching copy across configured connectors).",
)
@click.option("--reason", default="", help="Reason for quarantine")
@pass_ctx
def quarantine(app: AppContext, name: str, connector_flag: str, reason: str) -> None:
    """Quarantine a skill's files to the quarantine area.

    Moves the skill's directory to ~/.defenseclaw/quarantine/skills/ and records
    the action. The skill can be restored with 'skill restore'.

    On a multi-connector install a bare skill name quarantines every matching
    copy across configured connectors; pass --connector to scope the operation to
    one connector.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    skill_name = os.path.basename(name)
    if not skill_name or ".." in name:
        click.echo(f"error: invalid skill name {name!r}", err=True)
        raise SystemExit(1)

    resolved_connector = ""
    if connector_flag:
        from defenseclaw.commands import resolve_list_connector
        resolved_connector = resolve_list_connector(app, connector_flag)
        scope_dirs = app.cfg.skill_dirs(resolved_connector)
    else:
        scope_dirs = _all_active_skill_dirs(app)

    if os.path.isabs(name):
        # Validate absolute paths resolve inside a configured skill directory
        real = os.path.realpath(name)
        allowed_roots = [os.path.realpath(c) for c in scope_dirs]
        if any(real == root for root in allowed_roots):
            click.echo(
                f"error: path {name!r} must point to a specific skill directory, not the skill root",
                err=True,
            )
            raise SystemExit(1)
        if not any(real.startswith(root + os.sep) for root in allowed_roots):
            click.echo(
                f"error: path {name!r} is not inside a configured skill directory\n"
                f"  Allowed roots: {', '.join(allowed_roots)}",
                err=True,
            )
            raise SystemExit(1)
        targets: list[tuple[str, str]] = [(resolved_connector, real)]
    else:
        targets = _skill_match_dir_scopes(app, skill_name, connector_flag)

    if not targets:
        click.echo(f"error: could not locate skill {skill_name!r} — provide an absolute path", err=True)
        raise SystemExit(1)

    se = SkillEnforcer(app.cfg.quarantine_dir)
    if not reason:
        reason = "manual quarantine via CLI"
    pe = PolicyEngine(app.store)

    for target_connector, skill_path in targets:
        dest = se.quarantine(skill_name, skill_path, connector=target_connector)
        if dest is None:
            click.echo(f"error: skill path does not exist: {skill_path}", err=True)
            raise SystemExit(1)

        suffix = f" (connector={target_connector})" if target_connector else ""
        click.echo(f"[skill] {skill_name!r} quarantined to {dest}{suffix}")

        if target_connector:
            pe.quarantine_for_connector("skill", skill_name, target_connector, reason)
            pe.set_source_path("skill", skill_name, skill_path, target_connector)
        else:
            pe.quarantine("skill", skill_name, reason)
            pe.set_source_path("skill", skill_name, skill_path)

        if app.logger:
            app.logger.log_action(
                "skill-quarantine",
                skill_name,
                f"reason={reason}, connector={target_connector}, dest={dest}",
            )


# ---------------------------------------------------------------------------
# skill restore
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help="Connector whose skill dirs the restore destination must fall within "
    "(default: any configured connector).",
)
@click.option("--path", "restore_path", default="", help="Override restore destination (defaults to original path)")
@pass_ctx
def restore(app: AppContext, name: str, connector_flag: str, restore_path: str) -> None:
    """Restore a quarantined skill to its original location.

    By default restores to the original path recorded during quarantine.
    Use --path to override the restore destination.

    The destination is validated against every configured connector's skill
    directories (so each configured connector's skill restores correctly);
    pass --connector to scope the validation to one connector.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)
    targets = _resolve_skill_quarantine_restore_scopes(
        app, pe, skill_name, connector_flag,
    )
    if restore_path and len(targets) > 1:
        click.echo(
            "error: --path with multiple quarantined connector copies is ambiguous; "
            "pass --connector <name> to restore one copy to an explicit path",
            err=True,
        )
        raise SystemExit(1)

    se = SkillEnforcer(app.cfg.quarantine_dir)
    existing_targets = [
        (target_connector, entry)
        for target_connector, entry in targets
        if se.is_quarantined(skill_name, target_connector)
    ]
    if not existing_targets:
        click.echo(f"error: {skill_name!r} is not quarantined", err=True)
        raise SystemExit(1)

    for resolved_connector, entry in existing_targets:
        target_restore_path = restore_path
        if not target_restore_path:
            if entry is None or not entry.source_path:
                click.echo(
                    f"error: no stored path for {skill_name!r}"
                    + (
                        f" on connector={resolved_connector}"
                        if resolved_connector else ""
                    )
                    + " — use --path to specify restore destination",
                    err=True,
                )
                raise SystemExit(1)
            target_restore_path = entry.source_path

        if not (hasattr(app.cfg, "skill_dirs") and callable(app.cfg.skill_dirs)):
            allowed_roots = None
        elif resolved_connector:
            allowed_roots = app.cfg.skill_dirs(resolved_connector)
        else:
            allowed_roots = _all_active_skill_dirs(app)
        real_restore = os.path.realpath(target_restore_path)
        if allowed_roots:
            if not any(
                real_restore.startswith(os.path.realpath(r) + os.sep)
                or real_restore == os.path.realpath(r)
                for r in allowed_roots
            ):
                click.echo(
                    "error: restore path must be within configured skill directories",
                    err=True,
                )
                raise SystemExit(1)

        if not se.restore(
            skill_name,
            target_restore_path,
            allowed_roots=allowed_roots,
            connector=resolved_connector,
        ):
            click.echo(
                f"error: restore failed for {skill_name!r}"
                + (f" on connector={resolved_connector}" if resolved_connector else ""),
                err=True,
            )
            raise SystemExit(1)

        suffix = f" (connector={resolved_connector})" if resolved_connector else ""
        click.echo(f"[skill] {skill_name!r} restored to {target_restore_path}{suffix}")

        if resolved_connector:
            pe.clear_quarantine_for_connector("skill", skill_name, resolved_connector)
            pe.set_source_path("skill", skill_name, target_restore_path, resolved_connector)
        else:
            pe.clear_quarantine("skill", skill_name)
            pe.set_source_path("skill", skill_name, target_restore_path)

        if app.logger:
            app.logger.log_action(
                "skill-restore",
                skill_name,
                f"connector={resolved_connector}, restored to {target_restore_path}",
            )


# ---------------------------------------------------------------------------
# skill info
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output skill info as JSON")
@click.option(
    "--connector", "connector_flag", default="",
    help="Inspect a specific connector's skill (multi-connector installs)",
)
@pass_ctx
def info(app: AppContext, name: str, as_json: bool, connector_flag: str) -> None:
    """Show detailed information about a skill.

    Displays merged skill metadata for configured connector copies, latest scan
    results from the DefenseClaw audit database, and enforcement actions.
    """
    from defenseclaw.commands import resolve_list_connector

    skill_name = os.path.basename(name)
    if connector_flag:
        connector = resolve_list_connector(app, connector_flag)
        info_map = _skill_info_card(
            app,
            skill_name,
            _get_openclaw_skill_info(skill_name, app, connector=connector),
            connector=connector,
            filter_scan_to_connector=True,
        )
        cards = [info_map] if info_map is not None else []
    else:
        cards: list[dict[str, Any]] = []
        for c in _active_skill_connectors(app):
            found = _get_openclaw_skill_info(skill_name, app, connector=c)
            card = _skill_info_card(
                app,
                skill_name,
                found,
                connector=c,
                filter_scan_to_connector=True,
                suppress_global_action_only=True,
            )
            if card is not None:
                cards.append(card)
        if not cards:
            # SK-2: a true miss must error rather than render a blank
            # "Eligible: False / Bundled: False" card that implies the skill
            # exists. Keep rendering when a scan-history or enforcement record
            # carries the name, so a quarantined/removed-but-scanned skill stays
            # inspectable in unscoped mode.
            fallback = _skill_info_card(app, skill_name, None)
            if fallback is not None:
                cards.append(fallback)

    if not cards:
        click.echo(f"error: skill {skill_name!r} not found", err=True)
        raise SystemExit(1)

    if as_json:
        payload: Any = cards if len(cards) > 1 else cards[0]
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    for idx, card in enumerate(cards):
        if idx:
            click.echo()
        _print_skill_info_card(card, skill_name, show_connector=True)


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------

def _skill_install_targets(
    app: AppContext, connectors: list[str], *, explicit_connector: bool = False,
) -> list[tuple[str, str]]:
    """Return ``(connector, install_root)`` targets for registry installs."""
    targets: list[tuple[str, str]] = []
    skipped: list[str] = []
    for connector in connectors:
        dirs = [d for d in app.cfg.skill_dirs(connector) if d]
        if not dirs:
            skipped.append(connector)
            continue
        targets.append((connector, dirs[0]))

    if not targets:
        if explicit_connector and connectors:
            click.echo(
                f"error: connector {connectors[0]!r} does not expose a skill install directory",
                err=True,
            )
        else:
            click.echo(
                "error: no configured connector exposes a skill install directory",
                err=True,
            )
        raise SystemExit(1)

    for connector in skipped:
        click.echo(
            f"[install] skipping connector={connector}: no skill install directory"
        )
    return targets


def _find_clawhub_staged_skill(stage_dir: str, skill_name: str) -> str | None:
    """Find the skill directory produced by ``clawhub install`` in a staging cwd."""
    stage_root = os.path.realpath(stage_dir)
    candidates = [
        os.path.join(stage_dir, "skills", skill_name),
        os.path.join(stage_dir, skill_name),
    ]
    for candidate in candidates:
        if not os.path.isdir(candidate) or _is_path_alias(candidate):
            continue
        candidate_root = os.path.realpath(candidate)
        if not _path_is_within(stage_root, candidate_root):
            continue
        if _validate_staged_skill_tree(candidate_root):
            return candidate_root
    return None


def _is_path_alias(path: str) -> bool:
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def _path_is_within(root: str, candidate: str) -> bool:
    try:
        return os.path.normcase(os.path.commonpath([root, candidate])) == os.path.normcase(root)
    except ValueError:
        return False


def _validate_staged_skill_tree(skill_root: str) -> bool:
    """Accept only a real SKILL.md tree with no symlink/reparse escapes."""
    manifest = os.path.join(skill_root, "SKILL.md")
    if not os.path.isfile(manifest) or _is_path_alias(manifest):
        return False
    for current_root, directories, filenames in os.walk(skill_root, followlinks=False):
        if not _path_is_within(skill_root, os.path.realpath(current_root)):
            return False
        for name in [*directories, *filenames]:
            entry = os.path.join(current_root, name)
            if _is_path_alias(entry):
                return False
    return True


def _remove_skill_tree_path(path: str) -> None:
    """Remove one staged/install tree without following a path alias."""
    if not os.path.lexists(path):
        return
    if os.path.islink(path):
        os.unlink(path)
        return
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction and isjunction(path):
        os.rmdir(path)
        return
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _copy_skill_tree_to_connector(
    source_path: str,
    install_root: str,
    skill_name: str,
    *,
    force: bool,
) -> str:
    import tempfile

    if os.path.basename(skill_name) != skill_name or not _CLAWHUB_NAME_RE.fullmatch(skill_name):
        click.echo("error: invalid ClawHub skill identity", err=True)
        raise SystemExit(1)
    if not _validate_staged_skill_tree(source_path):
        click.echo("error: staged ClawHub skill contains an unsafe path alias", err=True)
        raise SystemExit(1)
    if os.path.lexists(install_root) and _is_path_alias(install_root):
        click.echo("error: connector skill directory is a path alias", err=True)
        raise SystemExit(1)
    os.makedirs(install_root, exist_ok=True)
    target_path = os.path.join(install_root, skill_name)
    real_root = os.path.realpath(install_root)
    real_target = os.path.realpath(target_path)
    if not _path_is_within(real_root, real_target) or real_target == real_root:
        click.echo("error: resolved install path escapes the connector skill directory", err=True)
        raise SystemExit(1)

    if os.path.realpath(source_path) == real_target:
        return target_path
    if os.path.lexists(target_path):
        if _is_path_alias(target_path):
            click.echo("error: existing connector skill destination is a path alias", err=True)
            raise SystemExit(1)
        if not force:
            click.echo(
                f"error: skill {skill_name!r} already exists at {target_path}; pass --force to replace it",
                err=True,
            )
            raise SystemExit(1)

    # Copy into a private sibling stage while preserving links. Preserving a
    # link here is intentional: dereferencing it could copy data outside the
    # validated source tree. The staged-tree validation below rejects the link
    # before the tree is published.
    stage_path = tempfile.mkdtemp(prefix=f".dclaw-stage-{skill_name}-", dir=install_root)
    try:
        shutil.copytree(source_path, stage_path, symlinks=True, dirs_exist_ok=True)
        if not _validate_staged_skill_tree(stage_path):
            click.echo("error: copied ClawHub skill contains an unsafe path alias", err=True)
            raise SystemExit(1)

        if os.path.lexists(target_path):
            if _is_path_alias(target_path):
                click.echo("error: connector skill destination became a path alias", err=True)
                raise SystemExit(1)
            _remove_skill_tree_path(target_path)
        os.replace(stage_path, target_path)
        stage_path = ""

        # Validate the installed name as a final mutation-boundary check before
        # callers scan or expose the connector tree.
        if not _validate_staged_skill_tree(target_path):
            _remove_skill_tree_path(target_path)
            click.echo("error: installed ClawHub skill contains an unsafe path alias", err=True)
            raise SystemExit(1)
        return target_path
    finally:
        if stage_path:
            try:
                _remove_skill_tree_path(stage_path)
            except OSError as exc:
                click.echo(
                    f"[install] warning: could not remove staged skill tree {stage_path}: {exc}",
                    err=True,
                )


def _rollback_skill_install_paths(paths: list[str]) -> None:
    seen: set[str] = set()
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            if os.path.isdir(path) and not _is_path_alias(path):
                shutil.rmtree(path)
        except OSError as exc:
            click.echo(
                f"[install] warning: could not remove partial install {path}: {exc}",
                err=True,
            )


def _scan_installed_skill_for_connector(
    app: AppContext,
    pe: Any,
    scanner: Any,
    skill_name: str,
    skill_path: str,
    *,
    connector: str,
    take_action: bool,
    rollback_paths: list[str] | None = None,
) -> None:
    from defenseclaw.enforce.admission import evaluate_admission
    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    click.echo(f"[install] scanning {skill_path} (connector={connector})...")
    try:
        result = scanner.scan(skill_path)
    except Exception as exc:
        _rollback_skill_install_paths(rollback_paths or [skill_path])
        click.echo(
            f"error: scan failed for connector={connector}: {exc}",
            err=True,
        )
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    _print_result(skill_name, result)

    post_decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=skill_name,
        source_path=skill_path,
        scan_result=result,
        fallback_actions=app.cfg.skill_actions,
        connector=connector,
        asset_policy=app.cfg.asset_policy,
    )

    if post_decision.verdict == "allowed":
        click.echo(
            f"[install] {skill_name!r} became allow-listed for connector={connector} "
            "— skipping post-scan enforcement"
        )
        if app.logger:
            app.logger.log_action(
                "install-allowed",
                skill_name,
                f"reason=allow-listed-post-scan connector={connector}",
            )
        return

    if post_decision.verdict == "clean":
        click.echo(f"[install] {skill_name!r} installed and clean (connector={connector})")
        if app.logger:
            app.logger.log_action(
                "install-clean", skill_name, f"verdict=clean connector={connector}",
            )
        return

    sev = result.max_severity()
    detail = f"severity={sev} findings={len(result.findings)} connector={connector}"

    if not take_action:
        click.echo(
            f"[install] {len(result.findings)} {sev} findings in {skill_name!r} "
            f"(connector={connector}; no action taken — pass --action to enforce)"
        )
        if app.logger:
            app.logger.log_action("install-warning", skill_name, detail)
        return

    action_cfg = post_decision.action
    enforcement_reason = (
        f"post-install scan: {len(result.findings)} findings, max={sev}"
    )
    applied_actions: list[str] = []

    if action_cfg.file == "quarantine":
        se = SkillEnforcer(app.cfg.quarantine_dir)
        dest = se.quarantine(skill_name, skill_path, connector=connector)
        if dest:
            applied_actions.append(f"quarantined to {dest}")
            pe.quarantine_for_connector("skill", skill_name, connector, enforcement_reason)
        else:
            click.echo("[install] quarantine failed", err=True)

    if action_cfg.runtime == "disable":
        target_connector = _normalize_runtime_connector(connector)
        if target_connector == "openclaw":
            client = _sidecar_client(app)
            try:
                client.disable_skill(skill_name)
                applied_actions.append("disabled via gateway")
                pe.disable_for_connector("skill", skill_name, connector, enforcement_reason)
            except Exception as exc:
                click.echo(f"[install] gateway disable failed: {exc}", err=True)
        else:
            applied_actions.append(f"runtime disable recorded for connector={connector}")
            pe.disable_for_connector("skill", skill_name, connector, enforcement_reason)

    if action_cfg.install == "block":
        pe.block_for_connector("skill", skill_name, connector, enforcement_reason)
        applied_actions.append("added to block list")

    if action_cfg.install == "allow":
        pe.allow_for_connector("skill", skill_name, connector, enforcement_reason)
        applied_actions.append("added to allow list")

    pe.set_source_path("skill", skill_name, skill_path, connector)

    if applied_actions:
        actions_str = ", ".join(applied_actions)
        click.echo(f"[install] {skill_name!r}: {actions_str} ({detail})")
        if app.logger:
            app.logger.log_action(
                "install-enforced", skill_name, f"{detail}; {actions_str}",
            )
        click.echo(
            f"error: skill {skill_name!r} had {sev} findings for connector={connector} "
            f"— actions applied: {actions_str}",
            err=True,
        )
        raise SystemExit(1)

    click.echo(
        f"[install] warning: {len(result.findings)} {sev} findings in {skill_name!r} "
        f"(connector={connector})"
    )
    if app.logger:
        app.logger.log_action("install-warning", skill_name, detail)


@skill.command()
@click.argument("name")
@click.option("--force", is_flag=True, help="Force install (overwrites existing)")
@click.option("--action", "take_action", is_flag=True, help="Apply skill_actions policy based on scan severity")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Install/scan only this configured connector "
        "(default: every configured connector)"
    ),
)
@pass_ctx
def install(app: AppContext, name: str, force: bool, take_action: bool, connector_flag: str) -> None:
    """Install and scan a ClawHub skill for configured connector skill dirs.

    By default, stages the package once via clawhub, installs a copy into each
    configured connector skill directory, and scans/evaluates each connector
    copy. Pass --connector <name> to install and scan only that connector.

    By default, install only runs the scan and reports findings — no enforcement
    actions are taken. Pass --action to apply the configured skill_actions policy
    (quarantine, disable, block) based on scan severity.

    Use --force to overwrite an existing skill.
    """
    import tempfile

    from defenseclaw.commands import resolve_list_connectors
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.admission import evaluate_admission

    skill_name = os.path.basename(name)
    if skill_name != name or not skill_name or not _CLAWHUB_NAME_RE.fullmatch(skill_name):
        click.echo(f"error: invalid ClawHub skill name {name!r}", err=True)
        raise SystemExit(2)

    connectors = resolve_list_connectors(app, connector_flag)
    targets = _skill_install_targets(
        app, connectors, explicit_connector=bool(connector_flag),
    )
    pe = PolicyEngine(app.store)

    pre_decisions: dict[str, Any] = {}
    for connector, _install_root in targets:
        decision = evaluate_admission(
            pe,
            policy_dir=app.cfg.policy_dir,
            target_type="skill",
            name=skill_name,
            source_path=name,
            fallback_actions=app.cfg.skill_actions,
            connector=connector,
            asset_policy=app.cfg.asset_policy,
            # F-0283: a quarantined skill must NOT be (re)installed. Without
            # this flag the admission evaluator never consulted quarantine
            # state, so an asset that a prior scan quarantined could be
            # reinstalled straight past the gate. Reject quarantined installs.
            include_quarantine=True,
        )
        pre_decisions[connector] = decision

        if decision.verdict == "blocked":
            if app.logger:
                app.logger.log_action(
                    "install-rejected", skill_name, f"reason=blocked connector={connector}",
                )
            click.echo(
                f"error: skill {skill_name!r} is on the block list for connector={connector}"
                f" — run 'defenseclaw skill allow {skill_name} --connector {connector}' to unblock",
                err=True,
            )
            raise SystemExit(1)

        if decision.verdict == "rejected" and decision.source == "quarantine":
            if app.logger:
                app.logger.log_action(
                    "install-rejected", skill_name, f"reason=quarantined connector={connector}",
                )
            click.echo(
                f"error: skill {skill_name!r} is quarantined for connector={connector}"
                f" — release the quarantine before reinstalling",
                err=True,
            )
            raise SystemExit(1)

    # Install via clawhub
    click.echo(
        f"[install] installing {skill_name!r} via clawhub for "
        + ", ".join(f"connector={connector}" for connector, _root in targets)
        + "..."
    )
    installed_paths: list[str] = []
    installed_by_connector: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="defenseclaw-clawhub-install-") as stage_dir:
        _run_clawhub_install(skill_name, force, cwd=stage_dir)
        staged_skill = _find_clawhub_staged_skill(stage_dir, skill_name)
        if not staged_skill:
            click.echo(
                f"[install] could not locate staged ClawHub skill {skill_name!r} "
                "after install",
                err=True,
            )
            if app.logger:
                app.logger.log_action(
                    "install-rolled-back", skill_name,
                    "reason=staged-skill-unresolved scan=skipped",
                )
            raise SystemExit(1)

        for connector, install_root in targets:
            skill_path = _copy_skill_tree_to_connector(
                staged_skill, install_root, skill_name, force=force,
            )
            installed_paths.append(skill_path)
            installed_by_connector[connector] = skill_path
            click.echo(
                f"[install] installed {skill_name!r} -> {skill_path} "
                f"(connector={connector})"
            )

    scanner = _build_skill_scanner(app)
    for connector, _install_root in targets:
        skill_path = installed_by_connector[connector]
        pre_decision = pre_decisions[connector]
        if pre_decision.verdict == "allowed":
            if pre_decision.source == "scan-disabled":
                click.echo(
                    f"[install] policy allows {skill_name!r} without scan "
                    f"(connector={connector})"
                )
            else:
                click.echo(
                    f"[install] {skill_name!r} is on the allow list for "
                    f"connector={connector} — skipping scan"
                )
            pe.set_source_path("skill", skill_name, skill_path, connector)
            if app.logger:
                app.logger.log_action(
                    "install-allowed",
                    skill_name,
                    f"reason=allow-listed connector={connector}",
                )
            continue

        _scan_installed_skill_for_connector(
            app,
            pe,
            scanner,
            skill_name,
            skill_path,
            connector=connector,
            take_action=take_action,
            rollback_paths=installed_paths,
        )


def _run_clawhub_install(skill_name: str, force: bool, cwd: str | None = None) -> None:
    try:
        args = _clawhub_args("install", skill_name)
        if force:
            args.append("--force")
        result = _run_clawhub_process(args, timeout=300, cwd=cwd)
    except subprocess.TimeoutExpired:
        click.echo("error: clawhub install timed out after 300s", err=True)
        raise SystemExit(1)
    except (OSError, ValueError) as exc:
        click.echo(f"error: could not launch clawhub install: {exc}", err=True)
        raise SystemExit(1)
    if result.returncode != 0:
        click.echo(
            f"error: clawhub install failed: {_external_failure_detail(result)}",
            err=True,
        )
        raise SystemExit(1)


def _run_clawhub_uninstall(skill_name: str, cwd: str | None = None) -> None:
    """Best-effort rollback for a partial install.

    Runs `clawhub uninstall <skill>` with a short timeout. We
    intentionally do not raise on rollback failures — the caller is
    already exiting non-zero — but we surface the error to the
    operator so they can manually remediate.
    """
    try:
        args = _clawhub_args("uninstall", skill_name)
        result = _run_clawhub_process(args, timeout=120, cwd=cwd, input_text="y\n")
    except subprocess.TimeoutExpired:
        click.echo(
            f"[install] warning: clawhub uninstall of {skill_name!r} timed out — manual cleanup may be required",
            err=True,
        )
    except (OSError, ValueError) as exc:
        click.echo(
            f"[install] warning: clawhub uninstall of {skill_name!r} failed: {exc} — manual cleanup may be required",
            err=True,
        )
    else:
        if result.returncode != 0:
            click.echo(
                f"[install] warning: clawhub uninstall of {skill_name!r} failed: "
                f"{_external_failure_detail(result)} — manual cleanup may be required",
                err=True,
            )
