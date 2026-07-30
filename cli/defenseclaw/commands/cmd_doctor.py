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

"""defenseclaw doctor — Verify credentials, endpoints, and connectivity.

Runs after setup to catch bad API keys, unreachable services, and
misconfiguration before the user discovers them at runtime.
"""

from __future__ import annotations

import base64
import contextlib
import io
import ipaddress
import json
import os
import queue
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from types import SimpleNamespace

import click

from defenseclaw import credential_provenance, ux
from defenseclaw.audit_actions import ACTION_DOCTOR
from defenseclaw.connector_paths import (
    codex_home,
    connector_config_files,
    hermes_config_path,
    hermes_legacy_config_path,
    omnigent_config_path,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.doctor_engine import (
    RepairDecision,
    RepairRecord,
    RepairRunSummary,
    RepairSpec,
    default_repair_verifier,
    legacy_outcome_state,
    stable_doctor_id,
)
from defenseclaw.doctor_gateway import (
    GATEWAY_PROCESS_NAMES,
    GatewayEvidence,
    ListenerEvidence,
    PIDRecord,
    ProcessEvidence,
    gateway_executable_name,
    parse_pid_record_bytes,
    paths_same,
    pid_file_fingerprint,
    pid_file_fingerprint_from_fd,
    read_pid_record,
)
from defenseclaw.doctor_hooks import (
    WindowsHookCheck,
    _packaged_windows_install_root,
    validate_windows_hook_registration,
)
from defenseclaw.envvars import active_security_overrides
from defenseclaw.file_lock import FileLockTimeoutError, locked_file_update
from defenseclaw.file_permissions import (
    MAX_DOTENV_BYTES,
    atomic_write_private_bytes,
    darwin_acl_confidentiality_error,
    darwin_acl_write_error,
    dotenv_key_is_process_control,
    dotenv_key_is_valid,
    read_regular_file_no_follow,
    trusted_system_subprocess_env,
)
from defenseclaw.gateway import gateway_api_client_host
from defenseclaw.process_liveness import pid_alive
from defenseclaw.safety import NoRedirectError, build_no_redirect_opener, is_symlink
from defenseclaw.scanner_binary import resolve_scanner_binary
from defenseclaw.webhooks import list_webhooks, validate_webhook_url

# Doctor status markers, recomputed per emission so the per-call
# TTY/NO_COLOR gate in ``ux._color_enabled`` takes effect. Caching at
# module load froze the gate to whatever the import-time stdout was —
# fine for normal runs, broken for tests that monkey-patch stdout
# between invocations and for ``--json-output`` runs that toggle
# ``_json_mode`` part-way through a process.
_DOCTOR_MARKERS: dict[str, tuple[str, str]] = {
    "pass": ("✓", "green"),
    "fail": ("✗", "red"),
    "warn": ("⚠", "yellow"),
    "skip": ("-", "bright_black"),
}
_DOCTOR_GALILEO_CANARY_LIMIT = 4


def _normalized_gateway_token(value: object) -> str:
    """Preserve token bytes while treating whitespace-only values as empty."""
    return value if isinstance(value, str) and value.strip() else ""


def _gateway_api_host(cfg) -> str:
    """Return the same connectable API host used by gateway clients/setup."""
    return gateway_api_client_host(cfg)


def _gateway_api_port(cfg) -> int:
    """Return a validated gateway API port, or zero for malformed config."""
    try:
        port = int(getattr(getattr(cfg, "gateway", None), "api_port", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return port if 1 <= port <= 65_535 else 0


def _gateway_api_url(cfg, path: str) -> str:
    """Build an HTTP URL for the configured local gateway API."""
    host = _gateway_api_host(cfg)
    authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    api_port = _gateway_api_port(cfg)
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"http://{authority_host}:{api_port}{normalized_path}"


def _gateway_api_host_is_loopback(cfg) -> bool:
    """Return True only for a literal loopback gateway connect target."""
    host = _gateway_api_host(cfg).strip("[]")
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _doctor_subsection(title: str) -> None:
    """Print a doctor sub-section divider.

    Format: blank line, then ``  ── <title> ──`` with the title bold
    and the box-drawing dashes dimmed in TTY mode. Plain mode keeps
    The legacy uncolored layout so cron logs and log shippers see
    the same byte stream they always have.
    """
    ux.echo()
    if ux._color_enabled():
        ux.echo("  " + ux.dim("──") + " " + ux._style(title, fg="cyan", bold=True) + " " + ux.dim("──"))
    else:
        ux.echo(f"  ── {title} ──")


def _doctor_marker(tag: str) -> str:
    """Return the inline marker for ``tag`` (``pass``/``fail``/...).

    Color-on: ``✓`` (or matching glyph) painted in the tag's color.
    Color-off: legacy 4-char verb in square brackets (``[PASS]``,
    ``[FAIL]``, ...) so screen scrapers that grep doctor output for
    ``[PASS]`` keep working unchanged. The width difference between
    the two formats is intentional and documented — interactive
    sessions get a tighter glyph, CI logs get a wider verb.
    """
    glyph, fg = _DOCTOR_MARKERS.get(tag, ("?", "white"))
    if ux._color_enabled():
        return ux._style(glyph, fg=fg, bold=True)
    # Plain mode → legacy "[VERB]" so existing log pattern matchers
    # (and any cron job that splits on `[FAIL]`) keep matching.
    verb = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}.get(tag, tag.upper())
    return f"[{verb}]"


class _DoctorResult:
    """One schema-v2 Doctor run with health and repairs kept separate.

    The legacy top-level counters and ``checks`` list remain present so older
    TUI/cache consumers continue to work.  New consumers should use
    ``schema_version``, ``summary``, ``repairs``, and ``repair_summary``.
    """

    __slots__ = (
        "passed",
        "failed",
        "warned",
        "skipped",
        "checks",
        "repairs",
        "repair_summary",
        "section",
        "run_id",
        "mode",
        "passive",
    )

    def __init__(
        self,
        *,
        mode: str = "check",
        run_id: str | None = None,
        passive: bool = False,
    ) -> None:
        self.passed = 0
        self.failed = 0
        self.warned = 0
        self.skipped = 0
        self.checks: list[dict] = []
        self.repairs: list[dict] = []
        self.repair_summary = RepairRunSummary()
        self.section = "general"
        self.run_id = run_id or str(uuid.uuid4())
        self.mode = mode
        self.passive = passive

    def set_section(self, section: str) -> None:
        self.section = section.strip() or "general"

    def record(
        self,
        tag: str,
        label: str = "",
        detail: str = "",
        *,
        check_id: str = "",
        reason_code: str = "",
        remediation: str = "",
        duration_ms: int = 0,
    ) -> None:
        if tag == "pass":
            self.passed += 1
        elif tag == "fail":
            self.failed += 1
        elif tag == "warn":
            self.warned += 1
        else:
            self.skipped += 1
        if label:
            self.checks.append(
                {
                    "check_id": check_id or stable_doctor_id("check", self.section, label),
                    "section": self.section,
                    "status": tag,
                    "label": label,
                    "detail": detail,
                    "reason_code": reason_code,
                    "remediation": remediation,
                    "duration_ms": max(0, int(duration_ms)),
                }
            )

    def record_repair(self, record: RepairRecord) -> None:
        self.repairs.append(record.to_dict())
        self.repair_summary.record(record.state)

    def to_dict(self) -> dict:
        repair_failed = bool(self.repair_summary.failed or self.repair_summary.blocked)
        outcome = "failed" if self.failed or repair_failed else "healthy"
        if outcome == "healthy" and (
            self.warned
            or self.repair_summary.planned
            or self.repair_summary.manual
            or self.repair_summary.declined
            or self.repair_summary.requires_confirmation
        ):
            outcome = "warning"
        return {
            "schema_version": 2,
            "run_id": self.run_id,
            "mode": self.mode,
            "passive": self.passive,
            "outcome": outcome,
            "exit_code": 1 if outcome == "failed" else 0,
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "skipped": self.skipped,
            "summary": {
                "passed": self.passed,
                "failed": self.failed,
                "warned": self.warned,
                "skipped": self.skipped,
            },
            "checks": self.checks,
            "repair_summary": self.repair_summary.to_dict(),
            "repairs": self.repairs,
        }


DOCTOR_CACHE_FILENAME = "doctor_cache.json"


def _write_doctor_cache(cfg, result: _DoctorResult) -> None:
    """Persist the doctor snapshot to ``<data_dir>/doctor_cache.json``.

    The Textual TUI Overview panel reads this file to show cached health and
    repair summaries without re-probing every network endpoint on every
    redraw. Writing the cache from inside the CLI means the command and TUI
    share the same result contract, including failed or blocked repairs.

    The write is best-effort — a failure here must not break the
    actual doctor run, so we swallow and log to stderr.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return
    path = os.path.join(data_dir, DOCTOR_CACHE_FILENAME)
    payload = dict(result.to_dict())
    # RFC3339 in UTC avoids TZ confusion between CLI and TUI runs.
    import datetime as _dt

    payload["captured_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        if os.name != "nt" and getattr(os, "geteuid", lambda: -1)() == 0:
            sudo_uid = str(os.environ.get("SUDO_UID", "") or "").strip()
            if sudo_uid.isdecimal() and os.path.isdir(data_dir):
                owner_uid = getattr(os.stat(data_dir, follow_symlinks=False), "st_uid", 0)
                if owner_uid == int(sudo_uid):
                    ux.echo(
                        f"warning: skipped doctor cache at {path}: "
                        "sudo would replace a user-owned cache with a root-owned file",
                        err=True,
                    )
                    return
        body = json.dumps(payload, indent=2).encode("utf-8")
        atomic_write_private_bytes(path, body)
    except OSError as exc:
        ux.echo(
            f"warning: could not write doctor cache at {path}: {exc}",
            err=True,
        )


_json_mode = False

# Optional per-row label suffix (e.g. ``"[codex]"``). Defaults to empty so
# single-connector output is byte-identical; the Services section sets it
# around each connector's hook check on multi-connector installs so the
# rows ("Codex hooks [codex]", "Claude Code hooks [claudecode]", …) are
# attributable instead of reading as one primary connector.
_label_suffix = ""

# Probe bodies are bounded before decoding so an endpoint cannot make doctor
# buffer an unbounded response. Most probe bodies are rendered only as short
# diagnostics, but /health is structured input and can legitimately exceed
# the display limit on multi-connector installs.
_HTTP_PROBE_DISPLAY_BYTES = 2_000
_HEALTH_DOCUMENT_MAX_BYTES = 1_048_576


@contextlib.contextmanager
def _capture_stdout_when_json():
    """Keep third-party probe chatter from corrupting ``--json-output``.

    Some optional provider SDKs print helper text directly to stdout instead
    of returning it to us. In JSON mode stdout is the machine-readable result
    channel, so the final ``json.dumps`` below must be the only stdout write.
    """
    if not _json_mode:
        yield
        return
    with contextlib.redirect_stdout(io.StringIO()):
        yield


@contextlib.contextmanager
def _doctor_label_suffix(suffix: str):
    """Append ``suffix`` to every :func:`_emit` row label within the block."""
    global _label_suffix
    prev = _label_suffix
    _label_suffix = suffix
    try:
        yield
    finally:
        _label_suffix = prev


def _emit(
    tag: str,
    label: str,
    detail: str = "",
    *,
    r: _DoctorResult | None = None,
    check_id: str = "",
    reason_code: str = "",
    remediation: str = "",
) -> None:
    if label and _label_suffix:
        label = f"{label} {_label_suffix}"
    if not _json_mode:
        marker = _doctor_marker(tag)
        # Marker + label form the row's primary signal. We bold the
        # label only when color is on so plain-text output keeps its
        # legacy width. Detail text is intentionally NOT dimmed —
        # operators read paths, ports, and HTTP codes from there.
        if ux._color_enabled():
            line = f"  {marker} {ux.bold(label)}"
        else:
            line = f"  {marker} {label}"
        if detail:
            # Em-dash separator dims so it visually recedes between
            # the bold label and the detail value without losing the
            # connection between the two halves.
            line += "  " + ux.dim("—") + f"  {detail}"
        ux.echo(line)
    if r is not None:
        r.record(
            tag,
            label,
            detail,
            check_id=check_id,
            reason_code=reason_code,
            remediation=remediation,
        )


def _emit_hint(text: str, *, indent: str = "      ") -> None:
    """Print an advisory hint line attached to the previous check row.

    Hints don't count toward the pass/fail/warn/skip tally and are
    suppressed in JSON mode (consumers parse the result dict, not
    rendered text). Used today by the AI Defense probe to surface
    the bound endpoint after a 401 — the most common cause is a
    valid key for a different region, and the API can't disambiguate
    that on its own.
    """
    if _json_mode:
        return
    ux.echo(f"{indent}{ux.dim('↪ ' + text)}")


def _emit_aid_hint(text: str) -> None:
    """Convenience wrapper for AI Defense hint rows.

    Kept as a named helper (rather than calling ``_emit_hint``
    directly at every site) so tests and grep can target the
    AI-Defense-specific hints without false matches against future
    hints from other probes.
    """
    _emit_hint(text)


def _resolve_api_key(env_name: str, dotenv_path: str) -> str:
    """Resolve an API key from env → .env file → empty."""
    data_dir = os.path.dirname(os.path.abspath(dotenv_path))
    scope = SimpleNamespace(data_dir=data_dir)
    val = os.environ.get(env_name, "")
    if val:
        if credential_provenance.was_injected_from_dotenv(
            data_dir,
            env_name,
            val,
        ) and _gateway_dotenv_safety_problem(scope):
            return ""
        return val
    try:
        if _gateway_dotenv_safety_problem(scope):
            return ""
        body = read_regular_file_no_follow(dotenv_path, max_bytes=MAX_DOTENV_BYTES)
        expected = env_name.encode("ascii")
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(b"#"):
                continue
            key, separator, value = line.partition(b"=")
            if not separator or key.strip() != expected:
                continue
            value = value.strip()
            if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {b'"', b"'"}:
                value = value[1:-1]
            try:
                return value.decode("utf-8")
            except UnicodeError:
                return ""
    except (OSError, UnicodeError):
        pass
    return ""


_GENERATED_HOOK_SENTINELS: dict[str, dict[str, tuple[str, ...]]] = {
    "codex": {
        "codex-hook.sh": ("defenseclaw_response_failure_reason",),
        "_hardening.sh": (
            "defenseclaw_response_failure_reason",
            "possible token drift",
        ),
    },
    "claudecode": {
        "claude-code-hook.sh": ("defenseclaw_response_failure_reason",),
        "_hardening.sh": (
            "defenseclaw_response_failure_reason",
            "possible token drift",
        ),
    },
}


_GENERATED_HOOK_REGEN_COMMANDS: dict[str, str] = {
    "codex": "defenseclaw setup codex --yes --restart",
    "claudecode": "defenseclaw setup claude-code --yes --restart",
}


def _registered_hook_script_paths(
    settings: dict,
    script_name: str,
) -> list[str]:
    """Extract registered hook script paths from an agent settings object."""
    paths: list[str] = []
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        return paths

    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            hook_list = entry.get("hooks", []) if isinstance(entry, dict) else []
            if not isinstance(hook_list, list):
                continue
            for hook in hook_list:
                cmd = hook.get("command", "") if isinstance(hook, dict) else ""
                if not isinstance(cmd, str) or script_name not in cmd:
                    continue
                try:
                    tokens = shlex.split(cmd, posix=os.name != "nt")
                except ValueError:
                    tokens = [cmd]
                match = next((tok for tok in tokens if script_name in tok), cmd)
                if len(match) >= 2 and match[0] == match[-1] and match[0] in {'"', "'"}:
                    match = match[1:-1]
                paths.append(os.path.abspath(os.path.expanduser(match)))

    deduped: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def _stale_generated_hook_reasons(
    cfg,
    connector: str,
    *,
    hook_script_paths: list[str] | None = None,
) -> list[str]:
    """Return stale/missing generated-hook diagnostics for *connector*.

    Generated hooks live outside the package in ``cfg.data_dir/hooks``.
    When a user updates the source/venv but the gateway has not been
    restarted yet, Codex/Claude can still execute an older script. This
    check intentionally looks for tiny, non-secret template sentinels
    rather than comparing whole files, because setup renders runtime
    values into the scripts.
    """
    connector = (connector or "").lower()
    sentinels = _GENERATED_HOOK_SENTINELS.get(connector)
    if not sentinels:
        return []

    hook_dir = os.path.join(getattr(cfg, "data_dir", "") or "", "hooks")
    reasons: list[str] = []

    expected_script_paths = {
        filename: os.path.abspath(os.path.join(hook_dir, filename))
        for filename in sentinels
        if filename.endswith(".sh") and filename != "_hardening.sh"
    }
    script_path_overrides = [os.path.abspath(p) for p in (hook_script_paths or []) if p]

    for filename, needles in sentinels.items():
        expected_path = os.path.abspath(os.path.join(hook_dir, filename))
        if filename in expected_script_paths and script_path_overrides:
            paths = script_path_overrides
        elif filename == "_hardening.sh" and script_path_overrides:
            paths = [os.path.join(os.path.dirname(path), filename) for path in script_path_overrides]
        else:
            paths = [expected_path]

        for path in paths:
            path = os.path.abspath(path)
            display = filename if path == expected_path else f"{filename} at {path}"
            if filename in expected_script_paths and path != expected_path:
                reasons.append(f"{filename} registered at {path}; expected {expected_path}")
            try:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            except FileNotFoundError:
                reasons.append(f"{display} missing")
                continue
            except OSError as exc:
                reasons.append(f"{display} unreadable: {exc}")
                continue

            missing = [needle for needle in needles if needle not in text]
            if missing:
                reasons.append(f"{display} missing {', '.join(missing)}")
    return reasons


def _check_generated_hook_freshness(
    cfg,
    connector: str,
    label: str,
    r: _DoctorResult,
    *,
    hook_script_paths: list[str] | None = None,
) -> None:
    reasons = _stale_generated_hook_reasons(cfg, connector, hook_script_paths=hook_script_paths)
    if not reasons:
        _emit("pass", f"{label} freshness", "generated scripts include latest diagnostics", r=r)
        return

    detail = "; ".join(reasons[:2])
    if len(reasons) > 2:
        detail += f"; +{len(reasons) - 2} more"
    regen = _GENERATED_HOOK_REGEN_COMMANDS.get(
        (connector or "").lower(),
        "defenseclaw-gateway restart",
    )
    _emit(
        "warn",
        f"{label} freshness",
        f"stale generated script ({detail}); run `{regen}` to regenerate and re-register hooks",
        r=r,
    )


def _http_probe(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    response_limit: int = _HTTP_PROBE_DISPLAY_BYTES,
    allow_truncation: bool = True,
    bypass_proxy: bool = False,
) -> tuple[int, str]:
    """Run one HTTP probe with a portable total wall-clock deadline.

    ``urllib`` applies its timeout to individual socket operations, so a peer
    can otherwise keep Doctor alive indefinitely by trickling one byte before
    every read timeout.  A daemon worker bounds the entire open/read sequence
    on Linux, macOS, and Windows.  A timed-out worker owns no mutable Doctor
    state and cannot delay process exit.
    """

    if timeout <= 0:
        return 0, "probe timeout must be positive"
    result: queue.Queue[tuple[int, str]] = queue.Queue(maxsize=1)

    def _run() -> None:
        try:
            value = _http_probe_once(
                url,
                method=method,
                headers=headers,
                body=body,
                timeout=timeout,
                verify_tls=verify_tls,
                response_limit=response_limit,
                allow_truncation=allow_truncation,
                bypass_proxy=bypass_proxy,
            )
        except Exception as exc:  # noqa: BLE001 - redact arbitrary transport detail.
            value = (0, f"{type(exc).__name__}: probe failed")
        try:
            result.put_nowait(value)
        except queue.Full:
            pass

    worker = threading.Thread(target=_run, name="defenseclaw-doctor-http", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return 0, f"probe exceeded {timeout:g}s total deadline"
    try:
        return result.get_nowait()
    except queue.Empty:
        return 0, "probe ended without a result"


def _http_probe_once(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    response_limit: int = _HTTP_PROBE_DISPLAY_BYTES,
    allow_truncation: bool = True,
    bypass_proxy: bool = False,
) -> tuple[int, str]:
    """Fire an HTTP request; return (status_code, body_text). Returns (0, error) on failure.

    Redirects are NOT followed. Several probes attach credential-bearing
    headers (Cisco AI-Defense ``X-Cisco-AI-Defense-API-Key``, Splunk HEC
    ``Authorization: Splunk ...``, LLM API keys). Python's default opener
    transparently replays those headers to a 30x redirect target, so a
    hostile or misconfigured endpoint could harvest the secret simply by
    returning a redirect. We route through ``build_no_redirect_opener`` and
    surface a refused redirect as a non-following ``(0, message)`` result —
    the same shape callers already treat as "could not complete the probe".
    Loopback requests also bypass environment-configured HTTP proxies. This
    prevents local gateway bearer tokens from being forwarded to a proxy and
    prevents a proxy response from impersonating local gateway health.

    ``response_limit`` is a byte bound, not just a post-read display slice.
    The default retains the compact diagnostic-body behavior. Structured
    callers such as the sidecar health check opt into a larger bounded document
    and disable truncation so an oversized response is rejected rather than
    parsed as if it were complete.
    """
    if response_limit <= 0:
        raise ValueError("response_limit must be positive")

    def _read_response(stream) -> str:
        raw = stream.read(response_limit + 1)
        if len(raw) > response_limit and not allow_truncation:
            return f"response exceeds {response_limit}-byte limit"
        return raw[:response_limit].decode("utf-8", errors="replace")

    context = None
    if not verify_tls and url.lower().startswith("https://"):
        context = ssl._create_unverified_context()
    # Preserve the verify_tls / SSL-context behavior by passing an
    # HTTPSHandler carrying the (possibly unverified) context to the opener.
    # urllib does not consistently bypass proxies for 127.0.0.1 when NO_PROXY
    # is unset, so install an explicit empty ProxyHandler for loopback.
    try:
        req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        try:
            loopback_host = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback_host = host == "localhost"
    except ValueError as exc:
        return 0, str(exc)
    handlers: list[urllib.request.BaseHandler] = []
    if bypass_proxy or loopback_host:
        handlers.append(urllib.request.ProxyHandler({}))
    handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = build_no_redirect_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, _read_response(resp)
    except urllib.error.HTTPError as exc:
        body_text = ""
        try:
            body_text = _read_response(exc)
        except Exception:
            pass
        return exc.code, body_text
    except NoRedirectError as exc:
        # Refused redirect: report as an unreachable probe so the caller warns
        # instead of leaking the auth header to the redirect target.
        return 0, str(exc)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, str(exc)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_config(cfg, r: _DoctorResult) -> None:
    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config

    cfg_path = str(config_path_for_data_dir(cfg.data_dir))
    if not os.path.isfile(cfg_path):
        _emit("fail", "Config file", "not found — run 'defenseclaw init'", r=r)
        return
    try:
        validation = inspect_v8_config("validate", config_path=cfg_path)
    except ConfigInspectError as exc:
        _emit(
            "fail",
            "Config validation",
            str(exc),
            r=r,
            check_id="doctor.config.canonical-v8",
            reason_code="canonical-validation-failed",
            remediation="defenseclaw config validate",
        )
        return
    if validation.valid is not True:
        _emit(
            "fail",
            "Config validation",
            "canonical v8 validator returned no validity decision",
            r=r,
            check_id="doctor.config.canonical-v8",
            reason_code="canonical-validation-unavailable",
            remediation="defenseclaw config validate",
        )
        return
    _emit(
        "pass",
        "Config file",
        f"{cfg_path}; canonical schema v8 valid",
        r=r,
        check_id="doctor.config.canonical-v8",
    )


def _doctor_config_present(cfg) -> bool:
    """Return whether Doctor has an initialized config it may repair."""
    from defenseclaw.config import config_path_for_data_dir

    data_dir = getattr(cfg, "data_dir", None)
    # Compatibility for narrow config facades used by embedding callers; the
    # real CLI Config always carries data_dir and takes the strict path below.
    if data_dir is None:
        return True
    if not str(data_dir).strip():
        return False
    return os.path.isfile(config_path_for_data_dir(data_dir))


_CONFIG_PREFLIGHT_REPAIR_ID = "doctor.config.canonical-v8.preflight"


def _plan_canonical_config_preflight(cfg) -> RepairDecision:
    """Authorize mutations only from one initialized canonical-v8 config."""

    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config

    data_dir = getattr(cfg, "data_dir", None)
    if data_dir is None or not str(data_dir).strip():
        reason = "authoritative DefenseClaw data directory is unavailable"
        return RepairDecision("blocked", reason, blockers=(reason,))
    config_path = config_path_for_data_dir(data_dir)
    if not os.path.isfile(config_path):
        reason = "config.yaml is missing; run `defenseclaw init` before applying repairs"
        return RepairDecision("blocked", reason, blockers=(reason,))
    try:
        validation = inspect_v8_config("validate", config_path=str(config_path))
    except (ConfigInspectError, OSError, ValueError) as exc:
        reason = (
            f"{type(exc).__name__}: canonical-v8 configuration preflight failed; "
            "run `defenseclaw config validate` before applying repairs"
        )
        return RepairDecision("blocked", reason, blockers=("canonical-v8 validation failed",))
    if validation.valid is not True:
        reason = (
            "canonical-v8 validator returned no positive validity decision; "
            "run `defenseclaw config validate` before applying repairs"
        )
        return RepairDecision("blocked", reason, blockers=("canonical-v8 validation unavailable",))
    return RepairDecision("noop", f"{config_path}; canonical schema v8 valid")


def _fix_canonical_config_preflight(cfg, *, assume_yes: bool) -> tuple[str, str]:
    """Defense-in-depth adapter; the preflight is expected to plan as a no-op."""

    del assume_yes
    decision = _plan_canonical_config_preflight(cfg)
    if decision.state == "noop":
        return ("skip", decision.detail)
    return ("fail", decision.detail)


def _env_names_equal(left: str, right: str, *, platform_name: str | None = None) -> bool:
    """Compare environment names with native platform semantics."""
    platform_name = platform_name or os.name
    return left.casefold() == right.casefold() if platform_name == "nt" else left == right


_CANONICAL_GATEWAY_TOKEN_ENV = "DEFENSECLAW_GATEWAY_TOKEN"
_LEGACY_GATEWAY_TOKEN_ENV = "OPENCLAW_GATEWAY_TOKEN"


def _known_gateway_token_env(name: str) -> str:
    """Return the canonical spelling for a built-in gateway token env name."""
    for candidate in (_CANONICAL_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
        if _env_names_equal(name, candidate):
            return candidate
    return ""


def _custom_gateway_token_env(cfg) -> str:
    """Return an explicitly configured external token provider, if any."""
    gateway = getattr(cfg, "gateway", None)
    configured = str(getattr(gateway, "token_env", "") or "").strip()
    return configured if configured and not _known_gateway_token_env(configured) else ""


def _configured_gateway_data_dir(cfg) -> str:
    """Return a normalized configured data directory, never the implicit CWD."""
    raw_data_dir = str(getattr(cfg, "data_dir", "") or "")
    if not raw_data_dir.strip():
        return ""
    try:
        return os.path.abspath(raw_data_dir)
    except (OSError, ValueError):
        return ""


def _gateway_dotenv_tokens(data_dir: str) -> dict[str, str]:
    """Read the token values the Go daemon will inject into its child."""
    values: dict[str, str] = {}
    normalized_data_dir = _configured_gateway_data_dir(SimpleNamespace(data_dir=data_dir))
    if not normalized_data_dir:
        return values
    path = os.path.join(normalized_data_dir, ".env")
    try:
        body = read_regular_file_no_follow(path, max_bytes=MAX_DOTENV_BYTES)
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(b"#"):
                continue
            raw_key, separator, raw_value = line.partition(b"=")
            if not separator:
                continue
            try:
                key = raw_key.strip().decode("ascii")
            except UnicodeError:
                continue
            canonical_key = _known_gateway_token_env(key)
            if not canonical_key:
                continue
            value = raw_value.strip()
            if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {b'"', b"'"}:
                value = value[1:-1]
            try:
                decoded_value = value.decode("utf-8")
            except UnicodeError:
                continue
            normalized = _normalized_gateway_token(decoded_value)
            if normalized:
                values[canonical_key] = normalized
    except OSError:
        return {}
    return values


def _gateway_data_dir_integrity_problem(cfg) -> str:
    """Return why another local principal can replace managed state paths."""
    data_dir = _configured_gateway_data_dir(cfg)
    if not data_dir:
        return "gateway data directory is unavailable"
    try:
        if is_symlink(data_dir):
            return "gateway data directory is a symbolic link or reparse point"
        info = os.lstat(data_dir)
        if getattr(info, "st_file_attributes", 0) & 0x400:
            return "gateway data directory is a symbolic link or reparse point"
        if not stat.S_ISDIR(info.st_mode):
            return "gateway data directory is not a directory"
        if os.name == "nt":
            from defenseclaw.file_permissions import windows_acl_custody_write_error

            problem = windows_acl_custody_write_error(
                data_dir,
                allow_current_user=True,
                require_current_user_owner=True,
            )
            return f"gateway data directory has unsafe ACLs ({problem})" if problem else ""
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid) and info.st_uid != geteuid():
            return "gateway data directory is not owned by the current user"
        if stat.S_IMODE(info.st_mode) & 0o022:
            return "gateway data directory is writable by another local principal"
        if sys.platform == "darwin":
            acl_problem = darwin_acl_write_error(data_dir)
            if acl_problem:
                return f"gateway data directory has unsafe ACLs ({acl_problem})"
    except OSError:
        return "gateway data directory could not be safely inspected"
    return ""


def _gateway_dotenv_safety_problem(cfg) -> str:
    """Return why credential/lifecycle repair must not consume ``.env``."""
    data_dir = _configured_gateway_data_dir(cfg)
    if not data_dir:
        return "gateway data directory is unavailable"
    if data_dir_problem := _gateway_data_dir_integrity_problem(cfg):
        return data_dir_problem
    path = os.path.join(data_dir, ".env")
    if not os.path.lexists(path):
        return ""
    try:
        if is_symlink(path):
            return "dotenv is a symbolic link or reparse point"
        info = os.lstat(path)
        if getattr(info, "st_file_attributes", 0) & 0x400:
            return "dotenv is a symbolic link or reparse point"
        if not stat.S_ISREG(info.st_mode):
            return "dotenv is not a regular file"
        read_regular_file_no_follow(path, max_bytes=MAX_DOTENV_BYTES)
        if os.name == "nt":
            from defenseclaw.file_permissions import windows_acl_confidentiality_error

            return windows_acl_confidentiality_error(path) or ""
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid) and info.st_uid != geteuid():
            return "dotenv is not owned by the current user"
        if stat.S_IMODE(info.st_mode) != 0o600:
            return "dotenv permissions are not 0600"
        if sys.platform == "darwin":
            return darwin_acl_write_error(path) or darwin_acl_confidentiality_error(path) or ""
    except OSError:
        return "dotenv could not be safely inspected"
    return ""


def _daemon_effective_gateway_token(cfg) -> tuple[str, str, str]:
    """Resolve the token a newly started gateway child will actually use.

    The Go daemon replaces inherited canonical/legacy token variables with
    values from ``.env`` whenever that file contains either token. A custom
    ``gateway.token_env`` remains externally managed and retains precedence.
    Return ``(token, env_name, source_label)`` without ever rendering the
    token itself.
    """
    gateway = getattr(cfg, "gateway", None)
    if gateway is None:
        return "", "", ""

    configured_env = str(getattr(gateway, "token_env", "") or "").strip()
    custom_env = _custom_gateway_token_env(cfg)
    if custom_env:
        custom_value = _normalized_gateway_token(os.environ.get(custom_env, ""))
        if custom_value:
            return custom_value, custom_env, "configured token provider"

    dotenv_values = _gateway_dotenv_tokens(str(getattr(cfg, "data_dir", "") or ""))
    if dotenv_values:
        configured_known = _known_gateway_token_env(configured_env)
        if configured_known and dotenv_values.get(configured_known):
            return (
                dotenv_values[configured_known],
                configured_known,
                "gateway dotenv",
            )
        for candidate in (_CANONICAL_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
            if dotenv_values.get(candidate):
                return dotenv_values[candidate], candidate, "gateway dotenv"

    resolved = _normalized_gateway_token(gateway.resolved_token())
    if not resolved:
        return "", configured_env, ""
    if configured_env and _normalized_gateway_token(os.environ.get(configured_env, "")):
        return resolved, configured_env, "configured environment"
    for candidate in (_CANONICAL_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
        if _normalized_gateway_token(os.environ.get(candidate, "")) == resolved:
            return resolved, candidate, "process environment"
    return resolved, "", "gateway config"


def _missing_gateway_token_detail(cfg) -> str:
    """Return an actionable missing-token message without false fix promises."""
    custom_env = _custom_gateway_token_env(cfg)
    if custom_env:
        return (
            f"custom token provider {custom_env!r} is empty — populate it or "
            "explicitly change gateway.token_env; auto-fix preserves custom providers"
        )
    return "no gateway token is configured — run `defenseclaw doctor --fix` to generate and persist one"


def _cli_effective_gateway_token(cfg) -> tuple[str, str]:
    """Return the token/source normal Python gateway clients will use."""
    gateway = getattr(cfg, "gateway", None)
    if gateway is None:
        return "", ""
    configured_env = str(getattr(gateway, "token_env", "") or "").strip()
    if configured_env:
        value = _normalized_gateway_token(os.environ.get(configured_env, ""))
        if value:
            return value, configured_env
    for name in (_CANONICAL_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
        value = _normalized_gateway_token(os.environ.get(name, ""))
        if value:
            return value, name
    literal = _normalized_gateway_token(getattr(gateway, "token", ""))
    return (literal, "gateway.token") if literal else ("", "")


def _gateway_cli_token_mismatch_detail(cfg, daemon_token: str) -> str:
    """Explain a CLI-vs-daemon provider mismatch without rendering values."""
    stale_parent_names = tuple(str(name) for name in getattr(cfg, "_doctor_stale_parent_gateway_env_names", ()) if name)
    if stale_parent_names:
        name = stale_parent_names[0]
        return (
            f"gateway accepted the repaired daemon token, but the parent shell still "
            f"exports {name}; unset or update {name}, then start a new shell"
        )

    cli_token, source = _cli_effective_gateway_token(cfg)
    if not cli_token or cli_token == daemon_token:
        return ""
    if source == "gateway.token":
        return (
            "gateway accepted the daemon-effective token, but normal CLI commands "
            "resolve deprecated gateway.token differently; remove or update that "
            "config value"
        )
    return (
        f"gateway accepted the daemon-effective token, but normal CLI commands "
        f"resolve {source} differently; unset or update {source} in the parent shell"
    )


def _gateway_rotated_provider_converged(cfg) -> bool:
    """Return whether a rotated canonical token has effective precedence."""
    configured = str(getattr(getattr(cfg, "gateway", None), "token_env", "") or "").strip()
    return not configured or _env_names_equal(configured, _CANONICAL_GATEWAY_TOKEN_ENV)


def _check_hilt_support(cfg, connector: str, r: _DoctorResult) -> None:
    guardrail = getattr(cfg, "guardrail", None)
    # Resolve the connector's EFFECTIVE hilt + mode (per-connector override >
    # global default) so a multi-connector install reports each connector's
    # own human-approval posture, not just the primary's. Falls back to the
    # global block for older configs without the effective_* resolvers.
    hilt = getattr(guardrail, "hilt", None)
    mode_src = getattr(guardrail, "mode", "") or "observe"
    if guardrail is not None and hasattr(guardrail, "effective_hilt"):
        try:
            hilt = guardrail.effective_hilt(connector)
        except Exception:  # noqa: BLE001 — keep the global hilt block.
            pass
    if guardrail is not None and hasattr(guardrail, "effective_mode"):
        try:
            mode_src = guardrail.effective_mode(connector) or mode_src
        except Exception:  # noqa: BLE001 — keep the global mode.
            pass
    if not bool(getattr(hilt, "enabled", False)):
        _emit("pass", "Human approval", "disabled (default)", r=r)
        return

    min_sev = (getattr(hilt, "min_severity", "") or "HIGH").upper()
    mode = mode_src.lower()
    if mode != "action":
        _emit("warn", "Human approval", f"enabled at {min_sev}, but {connector} mode is observe", r=r)
        return

    if connector == "openclaw":
        _emit("pass", "Human approval", f"OpenClaw prompts supported at {min_sev}+", r=r)
    elif connector == "claudecode":
        _emit("pass", "Human approval", f"Claude Code PreToolUse ask supported at {min_sev}+", r=r)
    elif connector == "copilot":
        _emit("pass", "Human approval", f"Copilot CLI preToolUse ask supported at {min_sev}+", r=r)
    elif connector == "cursor":
        _emit("warn", "Human approval", "Cursor ask is supported only on documented ask-capable hook events", r=r)
    elif connector == "codex":
        _emit(
            "warn",
            "Human approval",
            "Codex has no native ask surface here; confirm verdicts alert with raw_action preserved",
            r=r,
        )
    elif connector == "zeptoclaw":
        _emit(
            "warn",
            "Human approval",
            "ZeptoClaw has no native ask surface; confirm verdicts alert with raw_action preserved",
            r=r,
        )
    elif connector in {"hermes", "windsurf", "geminicli", "openhands", "opencode"}:
        _emit(
            "warn",
            "Human approval",
            f"{connector} can block supported hook events but has no native human approval surface",
            r=r,
        )
    elif connector == "antigravity":
        _emit(
            "pass",
            "Human approval",
            "Antigravity supports native PreToolUse ask; decision=ask overrides --dangerously-skip-permissions",
            r=r,
        )
    elif connector == "omnigent":
        _emit(
            "pass",
            "Human approval",
            "OmniGent supports native ASK on request, tool_call, and llm_request; post-action confirms use fallback",
            r=r,
        )
    else:
        _emit("warn", "Human approval", f"connector {connector!r} support is unknown", r=r)


def _check_audit_db(cfg, r: _DoctorResult) -> None:
    from defenseclaw.doctor_recovery import AuditDBHealthStatus, inspect_audit_db

    db_path = str(getattr(cfg, "audit_db", "") or "")
    health = inspect_audit_db(
        db_path,
        data_dir=str(getattr(cfg, "data_dir", "") or ""),
    )
    if health.status is AuditDBHealthStatus.MISSING:
        _emit(
            "fail",
            "Audit database",
            f"not found at {db_path}",
            r=r,
            check_id="doctor.state.audit-db",
            reason_code="audit-db-missing",
            remediation=("defenseclaw doctor --fix --fix-id doctor.state.audit-db.initialize"),
        )
        return
    if health.status is AuditDBHealthStatus.INVALID:
        reason = health.reason_code
        if reason == "audit-db-schema-incomplete":
            detail = "required schema is incomplete"
            remediation = "defenseclaw migrations apply"
        elif reason == "audit-db-corrupt":
            detail = "SQLite quick_check reported corruption"
            remediation = "restore the audit database from a trusted backup"
        elif reason in {
            "audit-db-integrity-unavailable",
            "audit-db-changed-during-inspection",
        }:
            detail = f"read-only integrity check failed ({reason})"
            remediation = "restore the audit database from a trusted backup"
        else:
            detail = f"private custody validation failed ({reason})"
            remediation = "restore the audit database from a trusted backup"
        _emit(
            "fail",
            "Audit database",
            detail,
            r=r,
            check_id="doctor.state.audit-db",
            reason_code=reason,
            remediation=remediation,
        )
        return
    _emit(
        "pass",
        "Audit database",
        f"{db_path}; SQLite quick_check=ok; required schema present",
        r=r,
        check_id="doctor.state.audit-db",
    )

    try:
        free_bytes = shutil.disk_usage(os.path.dirname(os.path.abspath(db_path)) or os.curdir).free
    except OSError:
        return
    if free_bytes < 256 * 1024 * 1024:
        _emit(
            "warn",
            "Audit storage capacity",
            f"less than 256 MiB free ({free_bytes // (1024 * 1024)} MiB)",
            r=r,
            check_id="doctor.state.audit-storage-capacity",
            reason_code="audit-storage-low",
            remediation="free disk space before continuing gateway operation",
        )


def _check_device_identity(cfg, r: _DoctorResult) -> None:
    """Validate the local Ed25519 identity and its continuity evidence."""

    from defenseclaw.doctor_recovery import (
        DeviceKeyHealthStatus,
        inspect_device_key,
    )

    gateway = getattr(cfg, "gateway", None)
    target = str(getattr(gateway, "device_key_file", "") or "")
    health = inspect_device_key(
        target,
        data_dir=str(getattr(cfg, "data_dir", "") or ""),
    )
    if health.status is DeviceKeyHealthStatus.VALID:
        _emit(
            "pass",
            "Device identity",
            "Ed25519 key custody and HMAC-bound provenance are valid",
            r=r,
            check_id="doctor.identity.device-key",
            reason_code=health.reason_code,
        )
        return
    if health.status is DeviceKeyHealthStatus.LEGACY_UNPROVENANCED:
        _emit(
            "warn",
            "Device identity",
            "Ed25519 key is valid and private, but cryptographic provenance is unavailable",
            r=r,
            check_id="doctor.identity.device-key",
            reason_code=health.reason_code,
            remediation="review identity continuity before sandbox pairing; do not replace an in-use key",
        )
        return
    if health.status is DeviceKeyHealthStatus.MISSING:
        _emit(
            "fail",
            "Device identity",
            f"device key is missing at {target}",
            r=r,
            check_id="doctor.identity.device-key",
            reason_code=health.reason_code,
            remediation=("defenseclaw doctor --fix --fix-id doctor.identity.device-key.initialize"),
        )
        return
    _emit(
        "fail",
        "Device identity",
        f"device key recovery is unsafe: {health.reason_code}",
        r=r,
        check_id="doctor.identity.device-key",
        reason_code=health.reason_code,
        remediation="stop the gateway and restore the identity from a trusted backup; Doctor will not overwrite it",
    )


def _health_remediation_text(choices: tuple[object, ...]) -> str:
    """Render one bounded health remediation without shell interpolation."""

    if not choices:
        return ""
    choice = choices[0]
    argv = tuple(getattr(choice, "argv", ()) or ())
    if argv and all(isinstance(part, str) for part in argv):
        return " ".join(argv)
    return str(getattr(choice, "summary", "") or "")


def _check_component_connector_compatibility(
    cfg,
    connectors: list[str],
    r: _DoctorResult,
) -> None:
    """Render bounded component and connector-contract evidence.

    Discovery is read from the existing protected cache only.  This keeps
    ``doctor --fix --dry-run`` read-only and prevents Doctor from executing an
    unsupported connector binary merely to decide whether it should be
    repaired.
    """

    from defenseclaw.doctor_health import (
        HealthStatus,
        build_health_report,
        read_cached_discovery,
    )

    enabled = tuple(connector for connector in connectors if _connector_enabled(cfg, connector))
    try:
        discovery = read_cached_discovery(str(getattr(cfg, "data_dir", "") or ""))
        report = build_health_report(
            enabled,
            discovery,
            components=_doctor_component_evidence(cfg),
        )
    except Exception as exc:  # noqa: BLE001 - emit only the exception class.
        _emit(
            "warn",
            "Compatibility evidence",
            f"{type(exc).__name__}: bounded compatibility probes were unavailable",
            r=r,
            check_id="doctor.compatibility.evidence",
            reason_code="compatibility-evidence-unavailable",
            remediation="defenseclaw version --json --no-drift-exit",
        )
        return

    component_required = {"cli", "gateway"}
    if "openclaw" in enabled:
        component_required.add("plugin")
    for finding in report.components:
        label = f"Component compatibility: {finding.component}"
        remediation = _health_remediation_text(finding.remediations)
        detail = finding.summary
        if finding.installed_version:
            detail += f"; installed={finding.installed_version}"
        if finding.expected_version and finding.expected_version != finding.installed_version:
            detail += f"; expected={finding.expected_version}"
        if finding.component not in component_required and finding.status is HealthStatus.UNAVAILABLE:
            tag = "skip"
            detail = f"{finding.component} is not required by the active connector set"
        elif finding.status is HealthStatus.SUPPORTED:
            tag = "pass"
        elif finding.status is HealthStatus.UNSUPPORTED:
            tag = "fail"
        elif finding.status is HealthStatus.UNTESTED:
            tag = "warn"
        else:
            tag = "fail"
        _emit(
            tag,
            label,
            detail,
            r=r,
            check_id=f"doctor.component.{finding.component}.compatibility",
            reason_code=finding.reason_code,
            remediation=remediation,
        )

    for finding in report.connectors:
        detail = finding.summary
        if finding.installed_version:
            detail += f"; installed={finding.installed_version}"
        if finding.contract_id:
            detail += f"; contract={finding.contract_id}"
        if finding.supported_agent_ranges:
            ranges = []
            for supported in finding.supported_agent_ranges:
                bounds = " ".join(
                    part
                    for part in (
                        f">={supported.min_inclusive}" if supported.min_inclusive else "",
                        f"<{supported.max_exclusive}" if supported.max_exclusive else "",
                    )
                    if part
                )
                ranges.append(bounds or supported.contract_id)
            detail += f"; supported={','.join(ranges)}"

        if finding.status is HealthStatus.SUPPORTED:
            tag = "pass"
        elif finding.status is HealthStatus.UNSUPPORTED:
            tag = "fail"
        elif finding.status is HealthStatus.UNAVAILABLE and finding.reason_code == "connector-agent-unavailable":
            tag = "fail"
        else:
            tag = "warn"
        _emit(
            tag,
            f"Connector compatibility: {finding.connector}",
            detail,
            r=r,
            check_id=f"doctor.connector.{finding.connector}.compatibility",
            reason_code=finding.reason_code,
            remediation=_health_remediation_text(finding.remediations),
        )


def _check_scanners(cfg, r: _DoctorResult) -> None:
    bins = [
        ("skill-scanner", cfg.scanners.skill_scanner.binary),
        ("mcp-scanner", cfg.scanners.mcp_scanner.binary),
    ]
    for name, binary in bins:
        path = resolve_scanner_binary(binary)
        if path:
            _emit("pass", f"Scanner: {name}", path, r=r)
        else:
            _emit(
                "fail",
                f"Scanner: {name}",
                f"'{binary}' not found in the managed environment or on PATH",
                r=r,
            )


def _gateway_fleet_expected_enabled(cfg) -> bool:
    """Mirror the gateway's connector/host fleet-loop decision."""
    gateway = getattr(cfg, "gateway", None)
    fleet_mode = str(getattr(gateway, "fleet_mode", "") or "").strip().lower()
    if fleet_mode in {"enabled", "on", "true"}:
        return True
    if fleet_mode in {"disabled", "off", "false"}:
        return False

    if not _doctor_active_connectors(cfg):
        return False
    connector = _active_connector(cfg)
    if connector in {"openclaw", "zeptoclaw"}:
        return True
    if connector not in {"codex", "claudecode"}:
        return False
    host = str(getattr(gateway, "host", "") or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or host.casefold() == "localhost":
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        # The Go runtime intentionally does not resolve DNS here; a non-empty
        # hostname expresses an external fleet endpoint.
        return True


def _subsystem_expected_enabled(cfg, sub: str) -> bool | None:
    """Return whether a sidecar subsystem is *expected* to be enabled
    based on the on-disk config, or ``None`` if the subsystem has no
    meaningful off/on toggle in config.

    The sidecar reads ``config.yaml`` only at startup, so this
    predicate is used by :func:`_check_sidecar` to detect stale
    sidecars: if a subsystem reports ``disabled`` but config says it
    should be enabled, the running process is out of date and needs a
    restart (most commonly after ``defenseclaw setup …``).
    """
    if sub == "telemetry":
        # Exact-v8 startup always binds the unified observability runtime: its
        # mandatory local SQLite destination exists even when no remote export
        # is configured. The retired OTel master-switch DTO cannot describe
        # this subsystem and made doctor accept a stale disabled runtime.
        return getattr(cfg, "_source_config_version", 0) == 8
    if sub == "gateway":
        return _gateway_fleet_expected_enabled(cfg)
    if sub == "watcher":
        watcher = getattr(getattr(cfg, "gateway", None), "watcher", None)
        return None if watcher is None else bool(getattr(watcher, "enabled", False))
    if sub == "guardrail":
        guardrail = getattr(cfg, "guardrail", None)
        if guardrail is None:
            return None
        if not bool(getattr(guardrail, "enabled", False)):
            return False
        connectors = _doctor_active_connectors(cfg)
        if not connectors:
            return False
        effective_enabled = getattr(guardrail, "effective_enabled", None)
        if callable(effective_enabled):
            enabled_states: list[bool] = []
            for connector in connectors:
                try:
                    enabled_states.append(bool(effective_enabled(connector)))
                except Exception:  # noqa: BLE001 - fall back to global config.
                    enabled_states = []
                    break
            if enabled_states:
                return any(enabled_states)
        return True
    if sub == "sandbox":
        oc = getattr(cfg, "openshell", None)
        if oc is None:
            return None
        is_standalone = getattr(oc, "is_standalone", None)
        return bool(is_standalone()) if callable(is_standalone) else False
    # The local API has no off switch.
    return None


def _check_sidecar(cfg, r: _DoctorResult) -> dict | None:
    bind = _gateway_api_host(cfg)
    url = _gateway_api_url(cfg, "/health")
    code, body = _http_probe(
        url,
        timeout=5.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
        bypass_proxy=True,
    )
    if code == 200:
        _emit("pass", "Sidecar API", f"{bind}:{cfg.gateway.api_port}", r=r)

        try:
            health = json.loads(body)
            if not isinstance(health, dict):
                raise TypeError("health response is not an object")
            subsystems = ["gateway", "watcher", "guardrail", "api", "telemetry", "sandbox"]
            stale_hint_printed = False
            for sub in subsystems:
                expected = _subsystem_expected_enabled(cfg, sub)
                info = health.get(sub)
                if info is None:
                    if sub in {"gateway", "watcher", "guardrail", "api", "telemetry"} or expected is True:
                        _emit("fail", f"  └─ {sub}", "absent from health response", r=r)
                    continue
                if not isinstance(info, dict) or not info:
                    _emit("fail", f"  └─ {sub}", "malformed health entry", r=r)
                    continue
                raw_state = info.get("state", info.get("status", "unknown"))
                if not isinstance(raw_state, str):
                    _emit("fail", f"  └─ {sub}", "malformed health state", r=r)
                    continue
                details = info.get("details")
                if details is not None and not isinstance(details, dict):
                    _emit("fail", f"  └─ {sub}", "malformed health details", r=r)
                    continue
                state = raw_state.strip() or "unknown"
                normalized_state = state.lower()
                if normalized_state in ("running", "healthy"):
                    if expected is False and sub in {
                        "gateway",
                        "watcher",
                        "guardrail",
                        "sandbox",
                    }:
                        _emit(
                            "warn",
                            f"  └─ {sub}",
                            "running but disabled in config — sidecar is stale, restart it",
                            r=r,
                        )
                        continue
                    detail = state
                    if sub == "guardrail" and isinstance(details, dict):
                        detail += f" (mode={details.get('mode', '?')})"
                    _emit("pass", f"  └─ {sub}", detail, r=r)
                elif normalized_state in ("disabled", "stopped"):
                    # Cross-check the sidecar's view against on-disk
                    # config. A divergence here is almost always a
                    # stale sidecar — the operator ran `defenseclaw
                    # setup …` but never restarted the gateway, so its
                    # in-memory view is out of date. Surface this as a
                    # WARN (not SKIP) so it doesn't get lost in the
                    # noise.
                    if expected is True:
                        _emit(
                            "warn",
                            f"  └─ {sub}",
                            "disabled (reported by sidecar) but enabled in config — sidecar is stale, restart it",
                            r=r,
                        )
                        if not stale_hint_printed:
                            _emit(
                                "warn",
                                "  ",
                                "Run: defenseclaw-gateway restart",
                                r=r,
                            )
                            stale_hint_printed = True
                    else:
                        # When the sidecar published a `details.summary`
                        # (today: gateway standalone-mode short-circuit
                        # in runGatewayLoop), surface it instead of the
                        # generic "disabled (reported by sidecar)".
                        # Otherwise an operator reading doctor output
                        # has no way to tell apart "intentionally
                        # disabled" from "broken but the sidecar
                        # quietly gave up". Falls back to the generic
                        # message when no summary is published, so
                        # other subsystems (telemetry / sandbox / …)
                        # are unaffected.
                        details_obj = details or {}
                        summary = ""
                        if isinstance(details_obj, dict):
                            raw = details_obj.get("summary")
                            if isinstance(raw, str):
                                summary = raw.strip()
                        detail_msg = f"disabled — {summary}" if summary else "disabled (reported by sidecar)"
                        _emit("skip", f"  └─ {sub}", detail_msg, r=r)
                else:
                    _emit("fail", f"  └─ {sub}", state, r=r)
            return health
        except (json.JSONDecodeError, TypeError):
            detail = body if body.startswith("response exceeds") else "could not parse /health response"
            _emit("warn", "Sidecar health JSON", detail, r=r)
    else:
        _emit("fail", "Sidecar API", f"not reachable on port {cfg.gateway.api_port}", r=r)
    return None


def _check_gateway_auth(cfg, r: _DoctorResult) -> bool:
    """Verify that the CLI's resolved token authenticates to the local API.

    ``/health`` is intentionally public, so a healthy response only proves
    liveness.  Probe ``/status`` as well or Doctor can report a green sidecar
    while every real CLI and hook request receives HTTP 401.
    """
    token, _token_env, _token_source = _daemon_effective_gateway_token(cfg)
    if not token:
        _emit(
            "fail",
            "Gateway authentication",
            _missing_gateway_token_detail(cfg),
            r=r,
        )
        return False

    trust = _trusted_gateway_listener(cfg)
    if not trust.trusted:
        _emit(
            "fail",
            "Gateway authentication",
            f"{trust.detail}; refusing to send the gateway token",
            r=r,
        )
        return False

    code, body = _http_probe(
        _gateway_api_url(cfg, "/status"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=3.0,
        response_limit=64 * 1024,
        allow_truncation=False,
        bypass_proxy=True,
    )
    if code == 200:
        runtime_ok, runtime_detail = _authenticated_runtime_matches(cfg, trust.pid, body)
        if not runtime_ok:
            _emit("fail", "Gateway authentication", runtime_detail, r=r)
            return True
        mismatch_detail = _gateway_cli_token_mismatch_detail(cfg, token)
        if mismatch_detail:
            _emit("fail", "Gateway authentication", mismatch_detail, r=r)
        else:
            _emit("pass", "Gateway authentication", "local token accepted", r=r)
    elif code in {401, 403, 503}:
        _emit(
            "fail",
            "Gateway authentication",
            f"local token rejected (HTTP {code}) — run `defenseclaw doctor --fix` to reconcile the running gateway",
            r=r,
        )
    elif code == 0:
        _emit(
            "fail",
            "Gateway authentication",
            "gateway authentication could not be verified because the trusted status endpoint was unreachable",
            r=r,
        )
    else:
        _emit(
            "fail",
            "Gateway authentication",
            f"verification unavailable (HTTP {code})",
            r=r,
        )
    return True


def _authenticated_runtime_matches(cfg, trusted_pid: int, body: str) -> tuple[bool, str]:
    """Require authenticated runtime metadata to match local process trust."""
    try:
        payload = json.loads(body)
        runtime = payload.get("runtime", {}) if isinstance(payload, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return False, "authenticated runtime metadata is malformed"
    if not isinstance(runtime, dict):
        return False, "authenticated runtime metadata is unavailable"
    try:
        runtime_pid = int(runtime.get("pid", 0) or 0)
    except (TypeError, ValueError):
        runtime_pid = 0
    if runtime_pid <= 0:
        return False, "authenticated runtime PID is unavailable"
    if runtime_pid != trusted_pid:
        return False, "authenticated runtime identity does not match the managed listener"
    runtime_home = runtime.get("data_dir", "")
    if not isinstance(runtime_home, str) or not runtime_home.strip():
        return False, "authenticated runtime data home is unavailable"
    if not paths_same(runtime_home, cfg.data_dir):
        return False, "authenticated runtime uses a different canonical data home"
    return True, ""


def _check_openclaw_gateway(cfg, r: _DoctorResult) -> None:
    url = f"http://{cfg.gateway.host}:{cfg.gateway.port}/health"
    code, _ = _http_probe(url, timeout=5.0)
    if code == 200:
        _emit("pass", "OpenClaw gateway", f"{cfg.gateway.host}:{cfg.gateway.port}", r=r)
    else:
        _emit("fail", "OpenClaw gateway", f"not reachable at {cfg.gateway.host}:{cfg.gateway.port}", r=r)


def _openclaw_active(cfg) -> bool:
    """True only when OpenClaw is positively among the active connectors.

    Drives the connector-aware token-env messaging (D1): the legacy
    ``OPENCLAW_GATEWAY_TOKEN`` var is "the configured var" only on a genuine
    OpenClaw install; on a hook install it is stale drift. Reuses
    :func:`_doctor_active_connectors`, so an ambiguous/legacy config that
    floors to the singular ``openclaw`` path default still reads as active —
    conservative on purpose: we treat OpenClaw as *inactive* only when we can
    see a real, OpenClaw-free active set.
    """
    return "openclaw" in _doctor_active_connectors(cfg)


def _check_gateway_token_env_alignment(cfg, r: _DoctorResult) -> None:
    """Detect the OPENCLAW_/DEFENSECLAW_ token-env drift the user hit.

    This is the doctor surface for the rebranding fix
    (cmd_agent/_resolve_gateway_target + config/GatewayConfig). The
    auto-detect ladder in Phase 1-2 already MASKS the misconfig at
    runtime — `agent usage` works either way — but doctor should
    still flag the stale ``token_env`` so operators can clean it up
    via `--fix` and rely on the explicit (faster, no-fallthrough)
    path going forward.

    Triggers when ALL of these hold:

    * ``cfg.gateway.token_env`` is set to a non-empty string.
    * That env var is empty in ``os.environ``.
    * The CANONICAL var (``DEFENSECLAW_GATEWAY_TOKEN``) IS populated.

    "fail" tag (not "warn") is intentional — without the auto-detect
    fall-through, this exact config would fail every `agent usage`
    call. The fall-through is a safety net, not the design.
    """
    gw = getattr(cfg, "gateway", None)
    if gw is None:
        return

    configured_env = getattr(gw, "token_env", "") or ""
    if not configured_env:
        # No env var configured at all — handled by other checks
        # (e.g. _check_sidecar's auth probe). Not our concern here.
        return

    configured_val = _normalized_gateway_token(os.environ.get(configured_env, ""))
    if configured_val:
        # Configured var IS populated — happy path. Nothing to flag.
        _emit("pass", "Gateway token env", f"{configured_env} is set", r=r)
        return

    # Stale token_env: configured var is empty. Check whether the
    # canonical DEFENSECLAW_ var is populated instead — that's the
    # drift case worth fixing.
    canonical = _normalized_gateway_token(os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", ""))
    if canonical:
        custom_env = _custom_gateway_token_env(cfg)
        if custom_env:
            _emit(
                "warn",
                "Gateway token env",
                f"custom token provider {custom_env!r} is empty; the canonical "
                "fallback is populated. Auto-fix preserves custom providers — "
                "populate that provider or intentionally change gateway.token_env.",
                r=r,
            )
            return
        _emit(
            "fail",
            "Gateway token env",
            f"cfg.gateway.token_env={configured_env!r} is empty in env, "
            "but DEFENSECLAW_GATEWAY_TOKEN is set. Run `defenseclaw doctor "
            "--fix` to repoint token_env at the canonical var.",
            r=r,
        )
        return

    legacy = _normalized_gateway_token(os.environ.get("OPENCLAW_GATEWAY_TOKEN", ""))
    if legacy and not _env_names_equal(configured_env, "OPENCLAW_GATEWAY_TOKEN"):
        # Custom token_env that's empty, but legacy OPENCLAW_ has a
        # value. Rare; flag as warn so the operator can decide.
        _emit(
            "warn",
            "Gateway token env",
            f"cfg.gateway.token_env={configured_env!r} is empty, but "
            "OPENCLAW_GATEWAY_TOKEN has a legacy value. Migrate via "
            "`defenseclaw keys set DEFENSECLAW_GATEWAY_TOKEN <value>`.",
            r=r,
        )
        return

    # Both vars empty — no token configured anywhere. When token_env still
    # carries the legacy ``OPENCLAW_GATEWAY_TOKEN`` default on an install that
    # is NOT running OpenClaw, don't present that var as the one the operator
    # must set (D1): the gateway auto-generates the canonical
    # ``DEFENSECLAW_GATEWAY_TOKEN`` on first boot, so the only real action is
    # to repoint the stale token_env. Only when OpenClaw is genuinely active is
    # ``OPENCLAW_GATEWAY_TOKEN`` the legitimate var to set.
    if _env_names_equal(configured_env, "OPENCLAW_GATEWAY_TOKEN") and not _openclaw_active(cfg):
        _emit(
            "warn",
            "Gateway token env",
            "the gateway auto-generates DEFENSECLAW_GATEWAY_TOKEN on first "
            "boot, but cfg.gateway.token_env still points at legacy "
            "OPENCLAW_GATEWAY_TOKEN on a non-OpenClaw install — run "
            "`defenseclaw doctor --fix` to repoint it.",
            r=r,
        )
        return

    custom_env = _custom_gateway_token_env(cfg)
    if custom_env:
        _emit(
            "warn",
            "Gateway token env",
            f"custom token provider {custom_env!r} is empty — populate it or "
            "intentionally change gateway.token_env; auto-fix preserves custom providers",
            r=r,
        )
        return

    # Generic "no token anywhere" state (custom token_env, or OpenClaw is
    # genuinely active). Other checks (sidecar /health probe) catch the
    # downstream effect; we just report the local config state.
    _emit(
        "warn",
        "Gateway token env",
        f"{configured_env} is empty and no DEFENSECLAW_GATEWAY_TOKEN "
        "fallback is present. Start the gateway (auto-generates a "
        "token) or run `defenseclaw keys set DEFENSECLAW_GATEWAY_TOKEN`.",
        r=r,
    )


def _read_pid_from_file(pid_file: str) -> int:
    """Return the live PID recorded in ``gateway.pid``, or 0.

    Tolerates both the legacy plain-integer format and the current
    ``{"pid": N, ...}`` JSON envelope. Returns 0 on any read/parse
    error or when the PID is not actually alive — callers treat 0 as
    "no live sidecar to inspect".
    """
    record = read_pid_record(pid_file)
    if record.status != "ok" or not pid_alive(record.pid):
        return 0
    return record.pid


@dataclass(frozen=True)
class _GatewayTrust:
    """Result of proving that the configured API target is the managed PID."""

    code: str
    detail: str
    pid: int = 0
    home_bound: bool = False
    record: PIDRecord | None = None
    process: ProcessEvidence | None = None
    authenticated_migration: bool = False

    @property
    def trusted(self) -> bool:
        return self.code == "trusted" and self.pid > 0


@dataclass(frozen=True)
class _GatewayLifecycleSelection:
    """One custody-checked controller selected for a Doctor lifecycle call."""

    executable: str | None
    requires_running_process: bool


def _gateway_executable_matches(
    record: PIDRecord,
    process: ProcessEvidence,
    *,
    platform_name: str,
) -> bool:
    """Mirror the daemon's platform-specific executable comparison."""
    if not record.executable:
        return False
    if (
        platform_name.startswith("linux")
        and not record.data_dir
        and process.executable == record.executable + " (deleted)"
    ):
        # Linux marks the old mapped inode this way after an atomic binary
        # replacement. This exact path+suffix exception is migration-only.
        return True
    return paths_same(record.executable, process.executable)


def _gateway_process_home_binding(
    cfg,
    record: PIDRecord,
    process: ProcessEvidence,
    *,
    platform_name: str,
) -> tuple[bool, bool]:
    """Return ``(bound_to_this_home, positively_foreign_home)``."""
    if record.data_dir:
        matches = paths_same(record.data_dir, cfg.data_dir)
        return matches, not matches
    if not platform_name.startswith("linux"):
        return False, False

    for env_name in ("DEFENSECLAW_DATA_DIR", "DEFENSECLAW_HOME"):
        value = _read_linux_process_env_var(process.pid, env_name)
        if value:
            matches = paths_same(value, cfg.data_dir)
            return matches, not matches
    return False, False


def _darwin_origin_main_launch_generation_matches(
    record: PIDRecord,
    process: ProcessEvidence,
) -> bool:
    """Bridge localized origin/main lstart text to the native start epoch."""
    if record.data_dir or not record.start_time:
        return False
    try:
        recorded_lower_bound = int(record.start_time)
        native_start = int(process.start_identity.partition(".")[0])
    except (TypeError, ValueError, OverflowError):
        return False
    delta = native_start - recorded_lower_bound
    # origin/main captured StartTime immediately before cmd.Start; mirror the
    # daemon's bounded child-registration window without trying to reproduce
    # the inherited locale/timezone used by its `ps -o lstart=` string.
    return 0 <= delta <= 5


def _gateway_process_trust(
    cfg,
    record: PIDRecord,
    process: ProcessEvidence | None,
    *,
    platform_name: str,
) -> _GatewayTrust:
    """Prove a PID generation and bind it to this installation when possible."""
    if record.status == "missing":
        return _GatewayTrust("missing", "managed gateway PID file is missing", record=record)
    if record.status == "malformed":
        return _GatewayTrust("identity", "managed gateway PID file is invalid", record=record)
    if record.status in {"denied", "unavailable"}:
        return _GatewayTrust(
            "unavailable",
            "managed gateway PID record could not be verified",
            record=record,
        )
    if process is None or process.status == "missing":
        return _GatewayTrust(
            "missing_process",
            "recorded gateway process does not exist",
            record=record,
            process=process,
        )
    if process.status in {"denied", "unavailable"}:
        return _GatewayTrust(
            "unavailable",
            "managed gateway process identity could not be verified",
            record=record,
            process=process,
        )
    deleted_linux_migration = (
        platform_name.startswith("linux")
        and not record.data_dir
        and bool(record.executable)
        and process.executable == record.executable + " (deleted)"
    )
    process_name_source = record.executable if deleted_linux_migration else process.executable
    if (
        gateway_executable_name(
            process_name_source,
            platform_name=platform_name,
        )
        not in GATEWAY_PROCESS_NAMES
    ):
        return _GatewayTrust(
            "identity",
            "recorded PID belongs to an unexpected executable",
            record=record,
            process=process,
        )
    if not record.executable or not record.start_identity:
        return _GatewayTrust(
            "legacy_identity",
            "legacy PID record lacks strong executable/start identity",
            record=record,
            process=process,
        )
    if not _gateway_executable_matches(record, process, platform_name=platform_name):
        return _GatewayTrust(
            "identity",
            "recorded gateway executable identity changed",
            record=record,
            process=process,
        )
    start_identity_matches = record.start_identity == process.start_identity
    if platform_name == "darwin" and _darwin_origin_main_launch_generation_matches(record, process):
        start_identity_matches = True
    if not start_identity_matches:
        return _GatewayTrust(
            "identity",
            "recorded gateway process start identity changed",
            record=record,
            process=process,
        )
    home_bound, foreign_home = _gateway_process_home_binding(
        cfg,
        record,
        process,
        platform_name=platform_name,
    )
    if foreign_home:
        return _GatewayTrust(
            "foreign_home",
            "managed PID record belongs to a different canonical data home",
            record.pid,
            record=record,
            process=process,
        )
    if not home_bound:
        return _GatewayTrust(
            "unbound_home",
            "gateway process identity is not bound to this canonical data home",
            record.pid,
            record=record,
            process=process,
        )
    return _GatewayTrust(
        "trusted",
        "managed gateway process identity is current",
        record.pid,
        home_bound=home_bound,
        record=record,
        process=process,
    )


def _managed_gateway_process_trust(
    cfg,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> _GatewayTrust:
    """Collect and validate the managed process identity for this home."""
    data_dir = _configured_gateway_data_dir(cfg)
    if not data_dir:
        return _GatewayTrust("unavailable", "gateway data directory is unavailable")
    platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
    evidence = evidence or GatewayEvidence(platform_name=platform_name)
    record = evidence.pid_record(os.path.join(data_dir, "gateway.pid"))
    process = evidence.process(record.pid) if record.status == "ok" else None
    return _gateway_process_trust(
        cfg,
        record,
        process,
        platform_name=platform_name,
    )


def _authenticated_origin_main_gateway_lifecycle_trust(
    cfg,
    process_trust: _GatewayTrust,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> _GatewayTrust:
    """Bridge one origin/main PID generation into current lifecycle control.

    The previous release wrote executable + kernel start identity but no
    ``data_dir``. That record remains insufficient for signal-based control.
    For an attended Doctor lifecycle repair only, corroborate it with exact
    listener ownership and token-authenticated runtime PID/home metadata. The
    Go daemon then permits only the authenticated graceful shutdown request;
    it never turns this bridge into OS-signal authority.
    """
    if process_trust.code not in {"trusted", "unbound_home"}:
        return process_trust
    record = process_trust.record
    process = process_trust.process
    if (
        record is None
        or process is None
        or bool(record.data_dir.strip())
        or not record.executable.strip()
        or not record.start_identity.strip()
    ):
        return process_trust
    if not _gateway_api_host_is_loopback(cfg):
        return _GatewayTrust(
            "unavailable",
            "configured API target is not loopback; refusing to send gateway credentials",
            process_trust.pid,
            record=record,
            process=process,
        )
    api_port = _gateway_api_port(cfg)
    if not api_port:
        return _GatewayTrust(
            "unavailable",
            "configured API port is invalid",
            process_trust.pid,
            record=record,
            process=process,
        )

    platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
    evidence = evidence or GatewayEvidence(platform_name=platform_name)
    listener = _managed_gateway_listener_evidence(
        api_port,
        host=_gateway_api_host(cfg),
        platform_name=platform_name,
        evidence=evidence,
    )
    strong_identity = _GatewayTrust(
        "trusted",
        "origin/main gateway process identity is current",
        process_trust.pid,
        record=record,
        process=process,
    )
    endpoint_trust = _gateway_listener_trust(strong_identity, listener)
    if not endpoint_trust.trusted:
        return _GatewayTrust(
            endpoint_trust.code,
            "gateway process identity is not bound to this canonical data home; " + endpoint_trust.detail,
            endpoint_trust.pid,
            record=record,
            process=process,
        )

    token, _token_env_name, _token_source = _daemon_effective_gateway_token(cfg)
    if not token:
        return _GatewayTrust(
            "unbound_home",
            "origin/main gateway identity is strong, but no token is available to authenticate its runtime home",
            process_trust.pid,
            record=record,
            process=process,
        )
    code, body = _http_probe(
        _gateway_api_url(cfg, "/status"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=3.0,
        response_limit=64 * 1024,
        allow_truncation=False,
        bypass_proxy=True,
    )
    if code != 200:
        detail = "transport failure" if code == 0 else f"HTTP {code}"
        return _GatewayTrust(
            "unbound_home",
            f"origin/main gateway runtime-home authentication failed ({detail})",
            process_trust.pid,
            record=record,
            process=process,
        )
    runtime_ok, runtime_detail = _authenticated_runtime_matches(
        cfg,
        process_trust.pid,
        body,
    )
    if not runtime_ok:
        return _GatewayTrust(
            "unbound_home",
            runtime_detail,
            process_trust.pid,
            record=record,
            process=process,
        )
    return _GatewayTrust(
        "trusted",
        "origin/main gateway listener and authenticated runtime home are current; "
        "eligible for one bounded graceful migration",
        process_trust.pid,
        home_bound=True,
        record=record,
        process=process,
        authenticated_migration=True,
    )


def _managed_gateway_process_trust_for_lifecycle(
    cfg,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> _GatewayTrust:
    """Return process trust, allowing only the authenticated upgrade bridge."""
    if evidence is None and platform_name is None:
        process_trust = _managed_gateway_process_trust(cfg)
    else:
        process_trust = _managed_gateway_process_trust(
            cfg,
            evidence=evidence,
            platform_name=platform_name,
        )
    record = process_trust.record
    if record is None or bool(record.data_dir.strip()) or process_trust.code not in {"trusted", "unbound_home"}:
        return process_trust
    return _authenticated_origin_main_gateway_lifecycle_trust(
        cfg,
        process_trust,
        evidence=evidence,
        platform_name=platform_name,
    )


def _gateway_listener_trust(
    process_trust: _GatewayTrust,
    listener: ListenerEvidence,
) -> _GatewayTrust:
    """Combine strong process identity with exact endpoint ownership."""
    if not process_trust.trusted:
        return process_trust
    if listener.status == "missing":
        return _GatewayTrust(
            "missing_listener",
            "no listener on the configured API endpoint",
            process_trust.pid,
            home_bound=process_trust.home_bound,
            record=process_trust.record,
            process=process_trust.process,
            authenticated_migration=process_trust.authenticated_migration,
        )
    if listener.status == "ambiguous":
        return _GatewayTrust(
            "ambiguous_listener",
            listener.reason or "multiple processes own the configured API endpoint",
            process_trust.pid,
            home_bound=process_trust.home_bound,
            record=process_trust.record,
            process=process_trust.process,
            authenticated_migration=process_trust.authenticated_migration,
        )
    if listener.status in {"denied", "unavailable"}:
        return _GatewayTrust(
            "unavailable",
            listener.reason or "gateway listener ownership could not be verified",
            process_trust.pid,
            home_bound=process_trust.home_bound,
            record=process_trust.record,
            process=process_trust.process,
            authenticated_migration=process_trust.authenticated_migration,
        )
    if listener.pid != process_trust.pid:
        return _GatewayTrust(
            "foreign_listener",
            "configured API endpoint is owned by another process",
            process_trust.pid,
            home_bound=process_trust.home_bound,
            record=process_trust.record,
            process=process_trust.process,
            authenticated_migration=process_trust.authenticated_migration,
        )
    return _GatewayTrust(
        "trusted",
        "managed gateway owns the configured API endpoint",
        process_trust.pid,
        home_bound=process_trust.home_bound,
        record=process_trust.record,
        process=process_trust.process,
        authenticated_migration=process_trust.authenticated_migration,
    )


def _trusted_gateway_listener(
    cfg,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> _GatewayTrust:
    """Prove an exact local API target before sending a master token."""
    host = _gateway_api_host(cfg)
    api_port = _gateway_api_port(cfg)
    if not api_port:
        return _GatewayTrust("unavailable", "configured API port is invalid")

    platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
    evidence = evidence or GatewayEvidence(platform_name=platform_name)
    process_trust = _managed_gateway_process_trust(
        cfg,
        evidence=evidence,
        platform_name=platform_name,
    )
    if not process_trust.trusted:
        return process_trust
    listener = _managed_gateway_listener_evidence(
        api_port,
        host=host,
        platform_name=platform_name,
        evidence=evidence,
    )
    return _gateway_listener_trust(process_trust, listener)


def _trusted_gateway_listener_for_lifecycle(
    cfg,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> _GatewayTrust:
    """Prove an endpoint, with the authenticated origin/main bridge if needed."""
    if evidence is None and platform_name is None:
        endpoint_trust = _trusted_gateway_listener(cfg)
    else:
        endpoint_trust = _trusted_gateway_listener(
            cfg,
            evidence=evidence,
            platform_name=platform_name,
        )
    if (
        endpoint_trust.code in {"trusted", "unbound_home"}
        and endpoint_trust.record is not None
        and not endpoint_trust.record.data_dir.strip()
    ):
        return _authenticated_origin_main_gateway_lifecycle_trust(
            cfg,
            endpoint_trust,
            evidence=evidence,
            platform_name=platform_name,
        )
    return endpoint_trust


def _read_linux_process_env_var(pid: int, var_name: str) -> str | None:
    """Read one Linux process variable exactly from its NUL-delimited table."""
    if not 0 < pid <= 2_147_483_647 or not var_name:
        return None
    try:
        with open(f"/proc/{pid}/environ", "rb") as process_environment:
            blob = process_environment.read()
    except (FileNotFoundError, PermissionError, OSError):
        return None
    for entry in blob.split(b"\x00"):
        if not entry:
            continue
        key, separator, value = entry.partition(b"=")
        if separator and key.decode("utf-8", errors="replace") == var_name:
            return value.decode("utf-8", errors="replace")
    return ""


def _read_process_env_var(pid: int, var_name: str) -> str | None:
    """Return the named env var's value from a running process's env.

    Tries ``/proc/<pid>/environ`` first (Linux fast path; no
    subprocess), falls back to ``ps eww -p <pid>`` (macOS / BSD where
    /proc isn't a thing, plus a backup path if /proc read fails).
    The fallback parses the FIRST line of ps output (the env line)
    and matches ``VAR=`` tokens; it intentionally does NOT shell out
    to grep so this works with hostile env values (which can contain
    spaces, single quotes, equals signs).

    Returns:
      * The env-var value (possibly empty string "") on success.
      * ``None`` when the process is gone, the env is unreadable
        (perms — common on macOS for processes owned by other users),
        or the var is genuinely not in the process env. ``None`` is
        the "I don't know" sentinel; callers MUST treat it as
        "can't detect drift" not "drift confirmed". Conflating the
        two would turn a permissions blip into a false alarm that
        nags the operator to restart a healthy sidecar.
    """
    if pid <= 0 or not var_name:
        return None

    # Linux fast path: /proc/<pid>/environ is null-separated KEY=VALUE.
    if sys.platform.startswith("linux") or os.path.exists(f"/proc/{pid}"):
        exact_value = _read_linux_process_env_var(pid, var_name)
        if exact_value is not None:
            return exact_value

    # macOS / fallback: ps eww -p <pid> prints "PID TTY STAT TIME CMD ENV...".
    # We ask for just the args (the env appears inline on macOS).
    try:
        proc = subprocess.run(
            ["/bin/ps", "eww", "-p", str(pid)],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None

    # ps output: header line, then one or more lines for the process.
    # The env tokens are space-separated VAR=VALUE pairs. Iterate
    # tokens and pick the first one whose key matches; this handles
    # multi-line output and values that don't contain unescaped spaces.
    needle = var_name + "="
    for line in proc.stdout.splitlines()[1:]:
        for token in line.split():
            if token.startswith(needle):
                return token[len(needle) :]
    # We could parse, but the var wasn't there — definitive absence.
    return ""


def _check_windows_gateway_diagnostics(
    cfg,
    r: _DoctorResult,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> bool:
    """Run the complete native Windows gateway identity diagnostic set.

    Returns ``True`` when the Windows checks were applicable.  ``evidence``
    and ``platform_name`` are explicit seams so every branch is testable on
    non-Windows CI without pretending the host platform changed globally.
    """
    platform_name = platform_name or sys.platform
    if platform_name != "win32":
        return False
    data_dir = _configured_gateway_data_dir(cfg)
    if not data_dir:
        _emit("fail", "Gateway PID identity", "gateway data directory is unavailable", r=r)
        return True
    evidence = evidence or GatewayEvidence(platform_name=platform_name)
    pid_path = os.path.join(data_dir, "gateway.pid")
    record = evidence.pid_record(pid_path)
    process = evidence.process(record.pid) if record.status == "ok" else None
    process_trust = _gateway_process_trust(
        cfg,
        record,
        process,
        platform_name="win32",
    )
    identity_ok = process_trust.trusted
    if identity_ok:
        _emit(
            "pass",
            "Gateway PID identity",
            "executable, process start identity, and data home match",
            r=r,
        )
    elif process_trust.code == "unavailable":
        _emit("skip", "Gateway PID identity", process_trust.detail, r=r)
    else:
        _emit("fail", "Gateway PID identity", process_trust.detail, r=r)

    api_port = _gateway_api_port(cfg)
    api_host = _gateway_api_host(cfg)
    listener = evidence.listener(api_port, host=api_host)

    # Exact native listener ownership + strong PID/home identity authorizes
    # both loopback and documented local standalone bridge addresses. Requests
    # never use proxy state and never follow redirects.
    token, _token_env, _token_source = _daemon_effective_gateway_token(cfg)
    status_code = 0
    status_body = ""
    trust = _gateway_listener_trust(process_trust, listener)
    if not api_port:
        status_error = "configured API port is invalid"
    elif not token:
        status_error = "no local gateway authentication state is configured"
    elif not trust.trusted:
        status_error = f"{trust.detail}; refusing to send the gateway token"
    else:
        status_code, status_body = _http_probe(
            _gateway_api_url(cfg, "/status"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=3.0,
            response_limit=64 * 1024,
            allow_truncation=False,
            bypass_proxy=True,
        )
        status_error = ""

    runtime: dict = {}
    if status_code == 200:
        try:
            payload = json.loads(status_body)
            candidate = payload.get("runtime", {}) if isinstance(payload, dict) else {}
            if isinstance(candidate, dict):
                runtime = candidate
        except (json.JSONDecodeError, TypeError):
            runtime = {}

    runtime_pid = runtime.get("pid", 0)
    try:
        runtime_pid = int(runtime_pid)
    except (TypeError, ValueError):
        runtime_pid = 0

    if listener.status == "missing":
        _emit("fail", "Gateway listener owner", "no listener on the configured API port", r=r)
    elif listener.status == "ambiguous":
        _emit(
            "fail",
            "Gateway listener owner",
            listener.reason or "multiple processes own the configured API endpoint",
            r=r,
        )
    elif listener.status in {"denied", "unavailable"}:
        _emit("skip", "Gateway listener owner", listener.reason or "listener inspection unavailable", r=r)
    elif record.status != "ok" or listener.pid != record.pid:
        _emit("fail", "Gateway listener owner", "configured API port is owned by an unexpected process", r=r)
    elif not identity_ok:
        _emit("fail", "Gateway listener owner", "listener PID matches an unverified or stale PID record", r=r)
    elif runtime_pid and runtime_pid != listener.pid:
        _emit("fail", "Gateway listener owner", "authenticated runtime identity does not match listener owner", r=r)
    else:
        _emit("pass", "Gateway listener owner", "configured API listener is owned by the managed gateway", r=r)

    if status_error == "no local gateway authentication state is configured":
        _emit(
            "fail",
            "Gateway token drift",
            _missing_gateway_token_detail(cfg),
            r=r,
        )
    elif status_error:
        _emit("fail", "Gateway token drift", status_error, r=r)
    elif status_code in {401, 403, 503}:
        _emit("fail", "Gateway token drift", "gateway authentication drift detected", r=r)
    elif status_code == 0:
        _emit(
            "fail",
            "Gateway token drift",
            "gateway authentication could not be verified because the trusted status endpoint was unreachable",
            r=r,
        )
    elif status_code != 200:
        _emit("fail", "Gateway token drift", f"authentication verification failed (HTTP {status_code})", r=r)
    elif not runtime:
        _emit("fail", "Gateway token drift", "authenticated runtime metadata is unavailable", r=r)
    else:
        _emit("pass", "Gateway token drift", "local authentication state matches the live gateway", r=r)

    runtime_home = runtime.get("data_dir", "") if runtime else ""
    if process_trust.code == "foreign_home":
        _emit(
            "fail",
            "Gateway home",
            "managed PID record is bound to a different canonical data home",
            r=r,
        )
    elif status_error and status_error != "no local gateway authentication state is configured":
        _emit("skip", "Gateway home", status_error, r=r)
    elif status_code in {401, 403, 503}:
        _emit("skip", "Gateway home", "authentication drift prevents trusted runtime-home inspection", r=r)
    elif status_code == 0:
        _emit("skip", "Gateway home", "gateway is unreachable; runtime home could not be inspected", r=r)
    elif status_code != 200 or not isinstance(runtime_home, str) or not runtime_home.strip():
        _emit("skip", "Gateway home", "authenticated runtime-home evidence is unavailable", r=r)
    elif not paths_same(runtime_home, cfg.data_dir):
        _emit("fail", "Gateway home", "running gateway uses a different canonical data home", r=r)
    else:
        _emit("pass", "Gateway home", "running gateway uses this canonical data home", r=r)
    return True


def _check_gateway_token_drift(cfg, r: _DoctorResult) -> None:
    """Compare daemon-effective auth state only after strong PID/home proof.

    This is a read-only fallback for platforms where endpoint ownership or the
    authenticated status probe is unavailable.  It deliberately reuses the
    daemon-effective provider (including custom ``token_env`` values) instead
    of hard-coding the canonical variable, and never reads an untrusted PID's
    environment.
    """
    trust = _managed_gateway_process_trust(cfg)
    if trust.code in {"missing", "missing_process"}:
        return
    if not trust.trusted:
        _emit(
            "skip",
            "Gateway token drift",
            f"{trust.detail}; process authentication state was not inspected",
            r=r,
        )
        return

    configured_token, token_env_name, _token_source = _daemon_effective_gateway_token(cfg)
    if not configured_token or not token_env_name:
        return

    process_token = _read_process_env_var(trust.pid, token_env_name)
    if process_token is None:
        _emit(
            "skip",
            "Gateway token drift",
            f"could not inspect managed sidecar pid {trust.pid} authentication environment",
            r=r,
        )
        return
    process_token = _normalized_gateway_token(process_token)
    if not process_token:
        _emit(
            "skip",
            "Gateway token drift",
            f"managed sidecar pid {trust.pid} has no inspectable {token_env_name} value",
            r=r,
        )
        return

    if process_token == configured_token:
        _emit(
            "pass",
            "Gateway token drift",
            f"managed sidecar pid {trust.pid} authentication matches the daemon-effective provider",
            r=r,
        )
        return

    _emit(
        "fail",
        "Gateway token drift",
        f"managed sidecar pid {trust.pid} authentication differs from the "
        "daemon-effective provider. Run `defenseclaw doctor --fix` (or "
        "`defenseclaw-gateway restart`) to reconcile.",
        r=r,
    )


def _lsof_gateway_listener_evidence(port: int, *, host: str = "") -> ListenerEvidence:
    """Inspect one API listener through a fixed, trusted ``lsof`` binary.

    Uses ``lsof`` (present on macOS and many Linux installs), then filters its
    machine-readable endpoint records for either the exact connect address or
    an unspecified/wildcard bind.  An exact ``lsof -iTCP@host:port`` selector
    alone is insufficient on macOS: it omits a ``0.0.0.0``/``::`` listener
    even though that listener receives loopback traffic.
    """
    if not 1 <= port <= 65_535:
        return ListenerEvidence("unavailable", reason="configured API port is invalid")
    lsof_path = _trusted_lsof_path()
    if not lsof_path:
        return ListenerEvidence("unavailable", reason="trusted lsof binary is unavailable")
    selector = f"-iTCP:{port}"
    target_host = host.strip("[]")
    if target_host and target_host.casefold() != "localhost":
        try:
            target_version = ipaddress.ip_address(target_host).version
        except ValueError:
            return ListenerEvidence("unavailable", reason="configured API host is not an IP literal")
        selector = f"-i{target_version}TCP:{port}"
    try:
        proc = subprocess.run(
            [
                lsof_path,
                "-nP",
                "-a",
                selector,
                "-sTCP:LISTEN",
                "-Fpn",
            ],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ListenerEvidence("unavailable", reason="lsof listener inspection failed")
    if proc.returncode != 0:
        if proc.returncode == 1 and not proc.stdout.strip():
            return ListenerEvidence("missing", reason="no TCP listener on the configured API endpoint")
        return ListenerEvidence("unavailable", reason="lsof listener inspection failed")
    listener_pids: set[int] = set()
    current_pid = 0
    for raw_line in proc.stdout.splitlines():
        if raw_line.startswith("p"):
            try:
                current_pid = int(raw_line[1:])
            except ValueError:
                current_pid = 0
        elif raw_line.startswith("n") and current_pid and _lsof_listener_address_matches(raw_line[1:], host, port):
            listener_pids.add(current_pid)
    if len(listener_pids) == 1:
        return ListenerEvidence("ok", pid=next(iter(listener_pids)))
    if len(listener_pids) > 1:
        # Multiple owners can occur with SO_REUSEPORT. Returning an arbitrary
        # first PID could authorize a bearer request to an attacker-controlled
        # listener selected by the kernel, so ambiguity fails closed.
        return ListenerEvidence(
            "ambiguous",
            reason="multiple processes own listeners for the configured API endpoint",
        )
    return ListenerEvidence("missing", reason="no TCP listener on the configured API endpoint")


def _gateway_listener_pid(port: int, *, host: str = "") -> int:
    """Backward-compatible PID view over the structured lsof evidence."""
    listener = _lsof_gateway_listener_evidence(port, host=host)
    return listener.pid if listener.status == "ok" else 0


def _trusted_lsof_path() -> str:
    """Return a fixed system lsof path, never a PATH-resolved executable."""
    for candidate in ("/usr/sbin/lsof", "/usr/bin/lsof"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _lsof_listener_address_matches(endpoint: str, host: str, port: int) -> bool:
    """Match an lsof listener endpoint to an exact or wildcard target."""
    endpoint = endpoint.strip()
    if endpoint.endswith(" (LISTEN)"):
        endpoint = endpoint[: -len(" (LISTEN)")].rstrip()
    address, separator, raw_port = endpoint.rpartition(":")
    if not separator or raw_port != str(port):
        return False
    address = address.strip().strip("[]")
    if not host:
        return True
    if address == "*":
        return True
    try:
        local_address = ipaddress.ip_address(address)
        if host.strip("[]").casefold() == "localhost":
            return local_address.is_unspecified or local_address.is_loopback
        target_address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return local_address.version == target_address.version and (
        local_address.is_unspecified or local_address == target_address
    )


def _linux_gateway_listener_evidence(
    port: int,
    *,
    host: str = "",
    proc_root: str = "/proc",
) -> ListenerEvidence:
    """Resolve one Linux TCP listener owner without optional userland tools.

    Linux exposes listening socket inodes in ``/proc/net/tcp*`` and each
    process's descriptors as ``socket:[inode]`` links.  Require every socket
    inode for the port to resolve to the same PID; partial visibility and
    ``SO_REUSEPORT`` ambiguity fail closed.
    """
    if not 1 <= port <= 65_535:
        return ListenerEvidence("unavailable", reason="configured API port is invalid")

    target_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    target_is_localhost = False
    if host:
        target_host = host.strip("[]")
        if target_host.casefold() == "localhost":
            target_is_localhost = True
        else:
            try:
                target_address = ipaddress.ip_address(target_host)
            except ValueError:
                return ListenerEvidence("unavailable", reason="configured API host is not an IP literal")

    socket_inodes: set[str] = set()
    table_found = False
    for table_name in ("tcp", "tcp6"):
        table_path = os.path.join(proc_root, "net", table_name)
        try:
            with open(table_path, encoding="ascii") as table:
                rows = table.readlines()[1:]
            table_found = True
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return ListenerEvidence("unavailable", reason="Linux listener table could not be read")
        for row in rows:
            fields = row.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if local_port != port or not fields[9].isdigit():
                continue
            try:
                packed = bytes.fromhex(fields[1].rsplit(":", 1)[0])
                if table_name == "tcp":
                    local_address = ipaddress.ip_address(packed[::-1])
                else:
                    # Linux exposes each 32-bit IPv6 word in host byte order.
                    network_bytes = b"".join(packed[index : index + 4][::-1] for index in range(0, len(packed), 4))
                    local_address = ipaddress.ip_address(network_bytes)
            except ValueError:
                continue
            address_matches = target_address is None or (
                local_address.version == target_address.version
                and (local_address.is_unspecified or local_address == target_address)
            )
            if target_is_localhost:
                address_matches = local_address.is_unspecified or local_address.is_loopback
            if not address_matches:
                continue
            socket_inodes.add(fields[9])

    if not table_found:
        return ListenerEvidence("unavailable", reason="Linux listener tables are unavailable")
    if not socket_inodes:
        return ListenerEvidence("missing", reason="no TCP listener on the configured API endpoint")

    owners_by_inode: dict[str, set[int]] = {inode: set() for inode in socket_inodes}
    try:
        process_entries = list(os.scandir(proc_root))
    except OSError:
        return ListenerEvidence("unavailable", reason="Linux process descriptors could not be enumerated")
    for process_entry in process_entries:
        if not process_entry.name.isdigit():
            continue
        pid = int(process_entry.name)
        if not 0 < pid <= 2_147_483_647:
            continue
        try:
            descriptors = os.scandir(os.path.join(process_entry.path, "fd"))
        except OSError:
            continue
        with descriptors:
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor.path)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    inode = target[8:-1]
                    if inode in owners_by_inode:
                        owners_by_inode[inode].add(pid)

    if any(not owners for owners in owners_by_inode.values()):
        return ListenerEvidence("unavailable", reason="listener owner could not be resolved from Linux descriptors")
    if any(len(owners) > 1 for owners in owners_by_inode.values()):
        return ListenerEvidence(
            "ambiguous",
            reason="multiple processes own listeners for the configured API endpoint",
        )
    owners = {next(iter(inode_owners)) for inode_owners in owners_by_inode.values()}
    if len(owners) != 1:
        return ListenerEvidence(
            "ambiguous",
            reason="multiple processes own listeners for the configured API endpoint",
        )
    return ListenerEvidence("ok", pid=next(iter(owners)))


def _linux_gateway_listener_pid(
    port: int,
    *,
    host: str = "",
    proc_root: str = "/proc",
) -> int:
    """Backward-compatible PID view over native Linux listener evidence."""
    listener = _linux_gateway_listener_evidence(port, host=host, proc_root=proc_root)
    return listener.pid if listener.status == "ok" else 0


def _managed_gateway_listener_evidence(
    port: int,
    *,
    host: str = "",
    platform_name: str | None = None,
    evidence: GatewayEvidence | None = None,
) -> ListenerEvidence:
    """Return structured listener ownership through the safest native path."""
    platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
    if platform_name == "win32":
        evidence = evidence or GatewayEvidence(platform_name="win32")
        return evidence.listener(port, host=host)
    if platform_name.startswith("linux"):
        listener = _linux_gateway_listener_evidence(port, host=host)
        if listener.status != "unavailable":
            return listener
    return _lsof_gateway_listener_evidence(port, host=host)


def _managed_gateway_listener_pid(
    port: int,
    *,
    host: str = "",
    platform_name: str | None = None,
) -> int:
    """Return a listener PID through the native platform evidence path."""
    listener = _managed_gateway_listener_evidence(
        port,
        host=host,
        platform_name=platform_name,
    )
    return listener.pid if listener.status == "ok" else 0


def _check_gateway_home_mismatch(cfg, r: _DoctorResult) -> None:
    """Report home ownership only from the same strong trust chain as auth."""
    code, _ = _http_probe(
        _gateway_api_url(cfg, "/health"),
        timeout=5.0,
        bypass_proxy=True,
    )
    if code != 200:
        return

    trust = _trusted_gateway_listener(cfg)
    if trust.trusted:
        _emit(
            "pass",
            "Gateway home",
            "managed listener is bound to this canonical data home",
            r=r,
        )
        return
    if trust.code == "foreign_home":
        _emit(
            "fail",
            "Gateway home",
            "managed PID record is bound to a different canonical data home",
            r=r,
        )
        return
    if trust.code in {"foreign_listener", "ambiguous_listener"}:
        _emit("fail", "Gateway home", trust.detail, r=r)
        return
    _emit(
        "skip",
        "Gateway home",
        f"{trust.detail}; canonical runtime-home ownership was not inferred",
        r=r,
    )


def _check_windows_native_hooks(
    cfg,
    connector: str,
    label: str,
    r: _DoctorResult,
    *,
    config_path: str | None = None,
    install_root: str | None = None,
    search_path: str | None = None,
    pathext: str | None = None,
) -> None:
    """Validate the command Windows setup actually registered, without running it."""
    check = _windows_native_hook_check(
        cfg,
        connector,
        config_path=config_path,
        install_root=install_root,
        search_path=search_path,
        pathext=pathext,
    )
    status = "pass" if check.healthy else "fail"
    _emit(status, label, f"{check.state}: {check.detail}", r=r)


def _windows_native_hook_check(
    cfg,
    connector: str,
    *,
    config_path: str | None = None,
    install_root: str | None = None,
    search_path: str | None = None,
    pathext: str | None = None,
) -> WindowsHookCheck:
    """Return the authoritative passive runtime inspection for Windows.

    Both the Services registration row and the Hook contract row use this
    exact path.  The lock records portable generated assets for digest and
    freshness checks; the live agent registration is the source of truth for
    the runtime Windows will actually resolve.
    """
    paths = _hook_health_paths_from_lock(cfg, connector)
    if config_path is None:
        if paths:
            config_path = paths[0]
        elif connector == "codex":
            config_path = os.path.join(codex_home(), "managed_config.toml")
        else:
            config_path = connector_config_files(connector)[0]
    if install_root is None:
        install_root = _packaged_windows_install_root(getattr(cfg, "data_dir", "") or "")
    if install_root is None:
        install_root = os.path.expanduser("~/.local/bin")
    return validate_windows_hook_registration(
        connector=connector,
        config_path=config_path,
        data_dir=getattr(cfg, "data_dir", "") or "",
        install_root=install_root,
        search_path=os.environ.get("PATH", "") if search_path is None else search_path,
        pathext=os.environ.get("PATHEXT", "") if pathext is None else pathext,
        workspace_dir=_workspace_dir(cfg) if connector == "claudecode" else "",
        managed_enterprise=(
            connector == "claudecode"
            and str(getattr(cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
        ),
    )


def _check_claudecode_hooks(
    cfg,
    r: _DoctorResult,
    *,
    platform_name: str | None = None,
    config_path: str | None = None,
    install_root: str | None = None,
    search_path: str | None = None,
    pathext: str | None = None,
) -> None:
    if (platform_name or os.name) == "nt":
        _check_windows_native_hooks(
            cfg,
            "claudecode",
            "Claude Code hooks",
            r,
            config_path=config_path,
            install_root=install_root,
            search_path=search_path,
            pathext=pathext,
        )
        return
    # Honor an explicitly modeled config path on every platform.  This keeps
    # Doctor bound to the same Claude invocation that the caller selected and
    # avoids accidentally inspecting an unrelated process-wide
    # CLAUDE_CONFIG_DIR while validating a project or alternate home.
    settings_path = config_path or connector_config_files("claudecode")[0]
    if not os.path.isfile(settings_path):
        _emit("fail", "Claude Code hooks", f"{settings_path} not found", r=r)
        return
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        _emit("fail", "Claude Code hooks", f"cannot read {settings_path}: {exc}", r=r)
        return
    hooks = settings.get("hooks", {})
    if not hooks:
        _emit("fail", "Claude Code hooks", "no hooks registered in settings.json", r=r)
        return
    hook_script_paths = _registered_hook_script_paths(settings, "claude-code-hook.sh")
    dc_hooks = 0
    for _event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            hook_list = entry.get("hooks", []) if isinstance(entry, dict) else []
            for h in hook_list:
                cmd = h.get("command", "") if isinstance(h, dict) else ""
                if "defenseclaw" in cmd or "claude-code-hook" in cmd:
                    dc_hooks += 1
    if dc_hooks > 0:
        _emit("pass", "Claude Code hooks", f"{dc_hooks} DefenseClaw hook(s) registered", r=r)
        _check_generated_hook_freshness(
            cfg,
            "claudecode",
            "Claude Code hooks",
            r,
            hook_script_paths=hook_script_paths,
        )
    else:
        _emit("fail", "Claude Code hooks", "no DefenseClaw hooks found in settings.json", r=r)


def _check_codex_hooks(
    cfg,
    r: _DoctorResult,
    *,
    platform_name: str | None = None,
    config_path: str | None = None,
    install_root: str | None = None,
    search_path: str | None = None,
    pathext: str | None = None,
) -> None:
    if (platform_name or os.name) == "nt":
        _check_windows_native_hooks(
            cfg,
            "codex",
            "Codex hooks",
            r,
            config_path=config_path,
            install_root=install_root,
            search_path=search_path,
            pathext=pathext,
        )
        return
    hook_dir = os.path.join(cfg.data_dir, "hooks")
    hook_script = os.path.join(hook_dir, "codex-hook.sh")
    if os.path.isfile(hook_script):
        _emit("pass", "Codex hooks", f"hook script at {hook_script}", r=r)
        _check_generated_hook_freshness(cfg, "codex", "Codex hooks", r)
    else:
        _emit("fail", "Codex hooks", f"hook script not found at {hook_script}", r=r)


# ---------------------------------------------------------------------------
# Generic per-connector hook-health (D4)
# ---------------------------------------------------------------------------

# Connectors whose hooks live in an agent config file but that lack a bespoke
# Services check above. Each maps to (home-relative fallback path(s), marker
# substrings). The fallback paths mirror the Go source of truth in
# ``internal/gateway/connector/hook_only.go`` (hermesConfigPath / cursorHooksPath
# / windsurfHooksPath / geminiSettingsPath / opencodePluginPath); the gateway's
# hook_contract_lock.json is consulted first and these are only the offline
# fallback. Markers are matched as raw substrings (see _file_references_marker)
# so the check stays format-agnostic: hermes is YAML, cursor/windsurf/geminicli
# are JSON, opencode is a flat ``.js`` plugin (existence + substring).
_HOOK_HEALTH_FALLBACK: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "hermes": (
        (os.path.join(".hermes", "config.yaml"),),
        ("hermes-hook.sh", "hook --connector hermes", "defenseclaw"),
    ),
    "cursor": (
        (os.path.join(".cursor", "hooks.json"),),
        ("cursor-hook.sh", "hook --connector cursor", "defenseclaw"),
    ),
    "windsurf": (
        (os.path.join(".codeium", "windsurf", "hooks.json"),),
        ("windsurf-hook.sh", "hook --connector windsurf", "defenseclaw"),
    ),
    "geminicli": (
        (os.path.join(".gemini", "settings.json"),),
        ("geminicli-hook.sh", "hook --connector geminicli", "defenseclaw"),
    ),
    "opencode": (
        (os.path.join(".config", "opencode", "plugins", "defenseclaw.js"),),
        ("defenseclaw",),
    ),
    "omnigent": (
        (os.path.join(".omnigent", "config.yaml"),),
        ("defenseclaw_omnigent_policy", "defenseclaw_guardrail"),
    ),
}

_HOOK_HEALTH_LABELS = {
    "hermes": "Hermes hooks",
    "cursor": "Cursor hooks",
    "windsurf": "Windsurf hooks",
    "geminicli": "Gemini CLI hooks",
    "opencode": "OpenCode hooks",
    "omnigent": "OmniGent policy",
}


def _file_references_marker(path: str, markers: tuple[str, ...]) -> bool:
    """Report whether the file at ``path`` contains any ``markers`` substring.

    Deliberately format-agnostic — no JSON/YAML parse — because the five
    connectors this serves store hook entries in different shapes (hermes
    YAML, cursor/windsurf/geminicli JSON, opencode a flat ``.js`` plugin).
    Mirrors the Go self-heal guard's ``configFileReferencesHook`` (raw-bytes
    substring match) so doctor and the guard agree on what "the hook is
    installed" means. A missing/unreadable file reports ``False``.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return False
    return any(m and m in data for m in markers)


def _split_configured_hook_command(command: str, *, platform_name: str | None = None) -> list[str]:
    """Split the narrow command shape DefenseClaw writes into hooks.json."""
    is_windows = (platform_name or os.name) == "nt"
    try:
        parts = shlex.split(command, posix=not is_windows)
    except ValueError:
        return []
    if is_windows:
        if parts and parts[0] == "&":
            parts = parts[1:]
        normalized = []
        for part in parts:
            if len(part) >= 2 and part[0] == part[-1] and part[0] in {"'", '"'}:
                quote = part[0]
                part = part[1:-1]
                if quote == "'":
                    part = part.replace("''", "'")
            normalized.append(part)
        parts = normalized
    return parts


def _powershell_literal(value: str) -> str:
    """Return one inert single-quoted PowerShell string literal."""
    return "'" + value.replace("'", "''") + "'"


def _cursor_health_row(document: str) -> dict[str, object] | None:
    try:
        parsed = json.loads(document)
    except (json.JSONDecodeError, TypeError):
        return None
    connectors = parsed.get("connectors") if isinstance(parsed, dict) else None
    if not isinstance(connectors, list):
        return None
    for row in connectors:
        if isinstance(row, dict) and str(row.get("name") or "").strip().lower() == "cursor":
            return row
    return None


def _windows_system_powershell() -> tuple[str, str]:
    """Resolve Windows PowerShell through the kernel's system directory.

    ``SystemRoot``/``WINDIR`` and ``PATH`` are process inputs, so they cannot
    select an executable used by Doctor's live Cursor probe. Return the
    custody-checked absolute executable and authoritative Windows directory,
    or two empty strings when that proof is unavailable.
    """
    if os.name != "nt":
        return "", ""

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    get_system_directory.restype = wintypes.UINT

    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    written = int(get_system_directory(buffer, size))
    if written <= 0 or written >= size:
        return "", ""
    system_directory = os.path.abspath(buffer.value)
    windows_directory = os.path.dirname(system_directory)
    executable = os.path.join(
        system_directory,
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    if not os.path.isfile(executable):
        return "", ""

    from defenseclaw.file_permissions import (
        UnsafePathError,
        reject_reparse_path,
        windows_acl_custody_write_error,
    )

    try:
        reject_reparse_path(executable)
    except (OSError, UnsafePathError):
        return "", ""
    custody_chain = [executable]
    parent = os.path.dirname(executable)
    system_identity = os.path.normcase(os.path.normpath(system_directory))
    while True:
        custody_chain.append(parent)
        if os.path.normcase(os.path.normpath(parent)) == system_identity:
            break
        next_parent = os.path.dirname(parent)
        if not next_parent or next_parent == parent:
            return "", ""
        parent = next_parent
    for candidate in custody_chain:
        if (
            windows_acl_custody_write_error(
                candidate,
                allow_current_user=False,
            )
            is not None
        ):
            return "", ""
    return executable, windows_directory


def _probe_cursor_windows_runtime(cfg, adapter_path: str) -> tuple[bool, str]:
    """Exercise Cursor's real PowerShell transport and verify gateway receipt.

    A valid fail-open response alone is insufficient: the launcher deliberately
    emits one when the gateway is unavailable. Compare the live Cursor request
    counter before/after so Doctor proves stdin -> adapter -> launcher ->
    gateway -> stdout instead of merely proving that files exist.
    """
    gateway = getattr(cfg, "gateway", None)
    try:
        api_port = int(getattr(gateway, "api_port", 0) or 0)
    except (TypeError, ValueError):
        api_port = 0
    if api_port <= 0 or api_port > 65535:
        return False, "cannot resolve the sidecar API port for a Cursor runtime probe"

    health_url = _gateway_api_url(cfg, "/health")
    before_code, before_body = _http_probe(
        health_url,
        timeout=3.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
        bypass_proxy=True,
    )
    before = _cursor_health_row(before_body) if before_code == 200 else None
    if before is None:
        return False, "sidecar /health has no live Cursor connector row"

    payload = json.dumps(
        {
            "hook_event_name": "sessionStart",
            "session_id": "defenseclaw-doctor-probe",
            "source": "defenseclaw-doctor",
            "workspace_roots": [],
        },
        separators=(",", ":"),
    )
    vendor_input = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            prefix="defenseclaw-cursor-doctor-",
            delete=False,
        ) as fh:
            fh.write(payload)
            vendor_input = fh.name

        # This mirrors Cursor 3.9's Windows command-hook boundary. Paths are
        # encoded as PowerShell literals, the whole script is UTF-16LE/base64,
        # and subprocess receives an argv list (never shell=True).
        script = (
            "$OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"Get-Content -LiteralPath {_powershell_literal(vendor_input)} -Raw | "
            f"& {{ $input | & {_powershell_literal(adapter_path)} }}"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        powershell, windows_directory = _windows_system_powershell()
        if not powershell:
            return False, "the custody-verified system PowerShell executable is unavailable"
        child_env = trusted_system_subprocess_env()
        child_env["SystemRoot"] = windows_directory
        child_env["WINDIR"] = windows_directory
        for name in ("HOME", "USERPROFILE"):
            value = os.environ.get(name)
            if value:
                child_env[name] = value
        data_dir = os.path.abspath(str(getattr(cfg, "data_dir", "") or ""))
        if data_dir:
            child_env["DEFENSECLAW_HOME"] = data_dir
            child_env["DEFENSECLAW_DATA_DIR"] = data_dir
        proc = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ],
            capture_output=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=child_env,
            timeout=15.0,
            check=False,
            creationflags=creationflags,
        )
    except FileNotFoundError:
        return False, "powershell.exe is unavailable for the Cursor runtime probe"
    except subprocess.TimeoutExpired:
        return False, "Cursor runtime probe timed out"
    except OSError as exc:
        return False, f"Cursor runtime probe could not start: {exc}"
    finally:
        if vendor_input:
            try:
                os.remove(vendor_input)
            except OSError:
                pass

    stdout = proc.stdout[:_HTTP_PROBE_DISPLAY_BYTES].decode("utf-8", errors="replace").lstrip("\ufeff").strip()
    stderr = proc.stderr[:_HTTP_PROBE_DISPLAY_BYTES].decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        detail = stderr.splitlines()[0] if stderr else f"exit code {proc.returncode}"
        return False, f"configured Cursor adapter failed: {detail}"
    try:
        response = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return False, "configured Cursor adapter returned no valid JSON response"
    if not isinstance(response, dict) or response.get("continue") is not True:
        return False, "configured Cursor adapter did not return an allow response"

    after_code, after_body = _http_probe(
        health_url,
        timeout=3.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
        bypass_proxy=True,
    )
    after = _cursor_health_row(after_body) if after_code == 200 else None
    if after is None:
        return False, "sidecar /health lost the Cursor connector row after the probe"
    try:
        before_requests = int(before.get("requests") or 0)
        after_requests = int(after.get("requests") or 0)
        before_errors = int(before.get("errors") or 0)
        after_errors = int(after.get("errors") or 0)
    except (TypeError, ValueError):
        return False, "sidecar returned invalid Cursor counter values"
    if after_requests <= before_requests:
        return False, "adapter returned allow JSON but the gateway Cursor request counter did not advance"
    if after_errors > before_errors:
        return False, "gateway Cursor error counter increased during the runtime probe"
    return True, f"live round trip OK (requests {before_requests}->{after_requests})"


def _check_cursor_configured_runtime(
    cfg,
    path: str,
    label: str,
    r: _DoctorResult,
    *,
    platform_name: str | None = None,
    probe_runtime: bool = True,
) -> None:
    """Validate the exact command Cursor invokes, not generated shell assets.

    The hook contract lock records portable script assets, while Windows
    Cursor uses ``cursor-hook.ps1`` to preserve the vendor's PowerShell object
    pipeline before invoking ``defenseclaw-hook.exe``. Parse the live
    hooks.json, verify every DefenseClaw-owned entry uses one consistent,
    reachable runtime, and ensure Cursor's host-side failClosed flag agrees
    with the connector's effective observe/action mode.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _emit("fail", label, f"cannot parse configured hook file {path}: {exc}", r=r)
        return

    hooks = document.get("hooks") if isinstance(document, dict) else None
    if not isinstance(hooks, dict):
        _emit("fail", label, f"configured hook file has no hooks object: {path}", r=r)
        return

    managed: list[tuple[str, dict[str, object], str]] = []
    for event, raw_entries in hooks.items():
        if not isinstance(raw_entries, list):
            continue
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                continue
            command = str(raw_entry.get("command") or "").strip()
            if "hook --connector cursor" in command or "cursor-hook.sh" in command or "cursor-hook.ps1" in command:
                managed.append((str(event), raw_entry, command))

    if not managed:
        _emit("fail", label, f"{path} has no DefenseClaw Cursor command entries", r=r)
        return

    commands = {command for _event, _entry, command in managed}
    if len(commands) != 1:
        _emit("fail", label, "DefenseClaw Cursor entries use inconsistent commands", r=r)
        return
    command = next(iter(commands))
    argv = _split_configured_hook_command(command, platform_name=platform_name)
    if not argv:
        _emit("fail", label, f"cannot parse configured Cursor command: {command}", r=r)
        return

    target = os.path.expanduser(argv[0])
    basename = os.path.basename(target).lower()
    native = basename in {"defenseclaw-hook", "defenseclaw-hook.exe"}
    shell_script = basename == "cursor-hook.sh"
    windows_adapter = basename == "cursor-hook.ps1"
    if native:
        if argv[1:] != ["hook", "--connector", "cursor"]:
            _emit("fail", label, f"configured Cursor launcher has unexpected arguments: {command}", r=r)
            return
        if (platform_name or os.name) == "nt":
            _emit(
                "fail",
                label,
                "Cursor on Windows is configured to invoke the native launcher directly; "
                "run `defenseclaw setup cursor` to install the PowerShell input adapter",
                r=r,
            )
            return
    elif shell_script or windows_adapter:
        if len(argv) != 1:
            _emit("fail", label, f"configured Cursor script has unexpected arguments: {command}", r=r)
            return
    else:
        _emit("fail", label, f"configured Cursor command is not a DefenseClaw hook runtime: {command}", r=r)
        return

    resolved = target if os.path.isabs(target) else (shutil.which(target) or "")
    if not resolved or not os.path.isfile(resolved):
        _emit("fail", label, f"configured Cursor hook runtime is missing: {target}", r=r)
        return
    adapter_markers = (
        "defenseclaw-managed-hook v8",
        "--input-file",
        "defenseclaw-hook.exe",
        "ProcessStartInfo",
        "RedirectStandardOutput",
        "WaitForExit",
    )
    if windows_adapter and not all(_file_references_marker(resolved, (marker,)) for marker in adapter_markers):
        _emit("fail", label, f"configured Cursor Windows adapter is stale or invalid: {resolved}", r=r)
        return

    guardrail = getattr(cfg, "guardrail", None)
    mode_resolver = getattr(guardrail, "effective_mode", None)
    fail_resolver = getattr(guardrail, "effective_hook_fail_mode", None)
    mode = str(mode_resolver("cursor") if callable(mode_resolver) else "observe").strip().lower()
    fail_mode = str(fail_resolver("cursor") if callable(fail_resolver) else "open").strip().lower()
    expected_fail_closed = mode == "action" and fail_mode == "closed"
    mismatched = [
        event for event, entry, _command in managed if (entry.get("failClosed") is True) != expected_fail_closed
    ]
    if mismatched:
        _emit(
            "fail",
            label,
            f"configured failClosed does not match mode={mode or 'observe'} "
            f"(expected {str(expected_fail_closed).lower()}): {', '.join(sorted(mismatched))}",
            r=r,
        )
        return

    runtime_detail = ""
    if windows_adapter and (platform_name or os.name) == "nt" and probe_runtime:
        managed_runtime_paths = _hook_runtime_paths_from_lock(cfg, "cursor")
        if not any(paths_same(resolved, candidate) for candidate in managed_runtime_paths):
            _emit(
                "fail",
                label,
                "configured Cursor adapter is not the exact runtime recorded by "
                "DefenseClaw setup; refusing to execute it",
                r=r,
            )
            return
        if is_symlink(resolved):
            _emit("fail", label, "configured Cursor adapter is a symbolic link", r=r)
            return
        if os.name == "nt":
            from defenseclaw.file_permissions import windows_acl_write_error

            if acl_problem := windows_acl_write_error(resolved):
                _emit(
                    "fail",
                    label,
                    f"configured Cursor adapter has unsafe integrity ACLs ({acl_problem})",
                    r=r,
                )
                return
        runtime_ok, runtime_detail = _probe_cursor_windows_runtime(cfg, resolved)
        if not runtime_ok:
            _emit("fail", label, runtime_detail, r=r)
            return

    _emit(
        "pass",
        label,
        f"configured runtime={resolved}; entries={len(managed)}; "
        f"mode={mode or 'observe'}; failClosed={str(expected_fail_closed).lower()}"
        + (f"; {runtime_detail}" if runtime_detail else ""),
        r=r,
    )


def _hook_health_paths_from_lock(cfg, connector: str) -> list[str]:
    """Return the hook config path(s) the gateway actually wrote for
    ``connector``, read from ``hook_contract_lock.json``.

    This is the authoritative source — exactly what Setup patched, captured
    from ``HookConfigPathsForConnector`` / ``ResolvedConnectorLocations`` on
    the Go side — so doctor watches the real files rather than guessing.
    Returns ``[]`` when the lock file is absent/unreadable or carries no path
    for the connector; the caller then falls back to the static map.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return []
    try:
        with open(os.path.join(data_dir, "hook_contract_lock.json"), encoding="utf-8") as fh:
            lock = json.load(fh)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    entry = (lock.get("connectors") or {}).get(connector) or {}
    locations = entry.get("locations") or {}
    if not isinstance(locations, dict):
        return []
    return [str(p) for p in (locations.get("hook_config_paths") or []) if p]


def _hook_runtime_paths_from_lock(cfg, connector: str) -> list[str]:
    """Return the installed runtime artifacts recorded for a hook connector."""
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return []
    try:
        with open(os.path.join(data_dir, "hook_contract_lock.json"), encoding="utf-8") as fh:
            lock = json.load(fh)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    entry = (lock.get("connectors") or {}).get(connector) or {}
    locations = entry.get("locations") or {}
    if not isinstance(locations, dict):
        return []
    return [str(p) for p in (locations.get("hook_script_paths") or []) if p]


def _omnigent_runtime_paths_from_backups(cfg) -> list[str]:
    """Recover OmniGent runtime targets when the hook lock is absent."""
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return []
    paths: list[str] = []
    for logical in ("module", "pth"):
        backup_path = os.path.join(
            data_dir,
            "connector_backups",
            "omnigent",
            f"{logical}.json",
        )
        try:
            with open(backup_path, encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if record.get("connector") != "omnigent" or record.get("logical_name") != logical:
            continue
        target = str(record.get("path") or "").strip()
        if target and target not in paths:
            paths.append(target)
    return paths


def _check_omnigent_policy_health(cfg, r: _DoctorResult) -> None:
    """Verify the config, policy module, and Python import shim as one unit."""
    config_paths = _hook_health_paths_from_lock(cfg, "omnigent") or [omnigent_config_path()]
    config_path = next((p for p in config_paths if os.path.isfile(p)), "")
    config_ok = bool(config_path) and all(
        _file_references_marker(config_path, (marker,))
        for marker in ("defenseclaw_omnigent_policy", "defenseclaw_guardrail")
    )
    if not config_ok:
        _emit("fail", "OmniGent policy", "config is missing the DefenseClaw policy registration", r=r)
        return

    runtime_paths = _hook_runtime_paths_from_lock(cfg, "omnigent") or _omnigent_runtime_paths_from_backups(cfg)
    module_path = next((p for p in runtime_paths if p.endswith(".py")), "")
    pth_path = next((p for p in runtime_paths if p.endswith(".pth")), "")
    if not module_path or not pth_path:
        _emit(
            "fail",
            "OmniGent policy",
            "hook contract lock does not record both the policy module and .pth import shim",
            r=r,
        )
        return
    if not os.path.isfile(module_path) or not all(
        _file_references_marker(module_path, (marker,)) for marker in ("POLICY_REGISTRY", "defenseclaw_policy")
    ):
        _emit("fail", "OmniGent policy", f"policy module is missing or invalid: {module_path}", r=r)
        return
    try:
        with open(pth_path, encoding="utf-8") as fh:
            import_path = fh.read().strip()
    except (OSError, UnicodeError):
        import_path = ""
    if not import_path or os.path.realpath(import_path) != os.path.realpath(os.path.dirname(module_path)):
        _emit("fail", "OmniGent policy", f".pth import shim is missing or points elsewhere: {pth_path}", r=r)
        return
    _emit("pass", "OmniGent policy", f"config={config_path}; module={module_path}; import={pth_path}", r=r)


def _check_hook_health(cfg, connector: str, r: _DoctorResult) -> None:
    """Generic "is this connector's hook installed and reachable?" row.

    Covers hermes / cursor / windsurf / geminicli / opencode — active
    connectors that previously got NO Services hook row at all, so an operator
    could not tell from doctor whether their hooks were installed (D4).
    Resolves the hook file from ``hook_contract_lock.json`` first (what the
    gateway actually wrote), then the static fallback map, and
    raw-substring-checks it for a DefenseClaw marker. (The Connectors section's
    ``_check_hook_contract_lock`` validates contract/version drift — a
    different concern from "does the hook file exist and reference us".)
    """
    fallback = _HOOK_HEALTH_FALLBACK.get(connector)
    if fallback is None:
        return  # not a generic-hook connector — nothing to check
    rel_candidates, markers = fallback
    label = _HOOK_HEALTH_LABELS.get(connector, f"{connector} hooks")
    home = os.path.expanduser("~")
    # Prefer the lock-file's recorded paths; fall back to the static map.
    candidates = _hook_health_paths_from_lock(cfg, connector)
    if not candidates:
        candidates = (
            [hermes_config_path()] if connector == "hermes" else [os.path.join(home, rel) for rel in rel_candidates]
        )
    present = [p for p in candidates if os.path.isfile(p)]
    if not present:
        _emit("fail", label, "hook file not found: " + ", ".join(candidates), r=r)
        return
    for path in present:
        if _file_references_marker(path, markers):
            if connector == "cursor":
                _check_cursor_configured_runtime(
                    cfg,
                    path,
                    label,
                    r,
                    probe_runtime=not r.passive,
                )
            else:
                _emit("pass", label, f"reachable at {path}", r=r)
            return
    _emit(
        "fail",
        label,
        "hook file exists but does not reference DefenseClaw: " + ", ".join(present),
        r=r,
    )


def _check_hermes_legacy_config(r: _DoctorResult, *, platform_name: str | None = None) -> None:
    """Warn about the pre-native-Windows Hermes config without migrating it.

    Native Hermes uses ``HERMES_HOME`` or ``%LOCALAPPDATA%\\hermes``. Older
    DefenseClaw builds wrote ``~/.hermes/config.yaml`` on every platform. That
    file can contain credentials, so doctor only reports it and leaves any
    review, merge, archival, or deletion to the operator.
    """
    if (platform_name or os.name) != "nt":
        return

    current = os.path.abspath(hermes_config_path())
    legacy = os.path.abspath(hermes_legacy_config_path())
    if os.path.normcase(current) == os.path.normcase(legacy) or not os.path.isfile(legacy):
        return

    current_state = "already exists" if os.path.isfile(current) else "does not exist yet"
    _emit(
        "warn",
        "Hermes config migration",
        f"legacy Hermes config found at {legacy}. Native Hermes now uses {current}, "
        f"which {current_state}. Review and merge any needed settings manually, then "
        "re-run `defenseclaw setup hermes`. DefenseClaw will not copy or delete the "
        "legacy file because it may contain credentials.",
        r=r,
    )


def _check_connector_hooks(cfg, connector: str, r: _DoctorResult) -> None:
    """Run the Services hook/health check matching *connector*.

    Single dispatch point so the Services section can iterate every active
    connector (multi-connector installs) instead of probing only the
    primary. Unknown connectors are skipped silently (no new failure row).
    """
    if connector == "openclaw":
        _check_openclaw_gateway(cfg, r)
    elif connector == "claudecode":
        _check_claudecode_hooks(cfg, r)
    elif connector == "codex":
        _check_codex_hooks(cfg, r)
    elif connector == "zeptoclaw":
        _check_zeptoclaw_config(cfg, r)
    elif connector == "copilot":
        _check_copilot_hooks(cfg, r)
    elif connector == "openhands":
        _check_openhands_hooks(cfg, r)
    elif connector == "antigravity":
        _check_antigravity_hooks(cfg, r)
    elif connector == "omnigent":
        _check_omnigent_policy_health(cfg, r)
    elif connector in _HOOK_HEALTH_FALLBACK:
        # hermes / cursor / windsurf / geminicli / opencode — generic
        # lock-file-driven hook-health row (D4).
        _check_hook_health(cfg, connector, r)
        if connector == "hermes":
            _check_hermes_legacy_config(r)


def _workspace_dir(cfg) -> str:
    resolver = getattr(cfg, "connector_workspace_dir", None)
    if callable(resolver):
        try:
            return resolver()
        except Exception:
            pass
    claw = getattr(cfg, "claw", None)
    raw = (getattr(claw, "workspace_dir", "") or "").strip()
    if not raw:
        return ""
    return os.path.abspath(os.path.expanduser(raw))


def _path_is_inside(path: str, parent: str) -> bool:
    if not path or not parent:
        return False
    try:
        path_abs = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        parent_abs = os.path.realpath(os.path.abspath(os.path.expanduser(parent)))
        return os.path.commonpath([path_abs, parent_abs]) == parent_abs
    except (OSError, ValueError):
        return False


def _hook_json_references(path: str, script_name: str) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return False

    stack = [raw]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key in ("command", "bash", "cmd"):
                value = current.get(key)
                if isinstance(value, str) and ("defenseclaw" in value or script_name in value):
                    return True
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return False


def _check_antigravity_hooks(cfg, r: _DoctorResult) -> None:
    """Validate the Antigravity hook wiring.

    Antigravity (`agy` v1.0.x) reads PreToolUse hooks from
    ``~/.gemini/config/hooks.json`` in a Claude-Code-compatible
    nested schema. This was determined empirically during the
    v0.5.0 smoke test — earlier installs wrote a flat schema to
    ``~/.gemini/antigravity-cli/hooks.json`` (the path advertised
    by ``agy --help``), but agy never evaluated entries from that
    file at runtime.

    The connector is deliberately global-only — agy merges every
    discovered hooks file (the canonical
    ``~/.gemini/config/hooks.json``, the legacy
    ``~/.gemini/antigravity-cli/hooks.json``, project-local
    ``<workspace>/.antigravitycli/hooks.json``, and the legacy
    ``~/.gemini/hooks.json``), so writing to more than one
    location causes the same hook to fire multiple times per
    tool call.

    This check emits up to three independent signals:

    1. PASS / FAIL on the canonical ``~/.gemini/config/hooks.json``.
    2. WARN if the legacy ``~/.gemini/antigravity-cli/hooks.json``
       still contains DefenseClaw-managed entries (left over from
       a pre-v0.5.0 install). agy ignores this file at runtime
       but it pollutes the operator's view of "where is the hook
       registered" and is the #1 source of confusion for anyone
       upgrading from an older DefenseClaw release.
    3. WARN on additional discovered locations (legacy
       ``~/.gemini/hooks.json``, workspace-local
       ``.antigravitycli/hooks.json``) — these *do* fire and
       cause duplicate evaluations.
    """
    home = os.path.expanduser("~")
    canonical = os.path.join(home, ".gemini", "config", "hooks.json")
    legacy = os.path.join(home, ".gemini", "antigravity-cli", "hooks.json")

    # Signal 1: canonical path validation.
    if not os.path.isfile(canonical):
        _emit(
            "fail",
            "Antigravity hooks",
            f"not found at {canonical} (agy v1.0.x reads PreToolUse "
            "hooks from this path; re-run `defenseclaw setup antigravity`)",
            r=r,
        )
    elif _hook_json_references(canonical, "antigravity-hook.sh"):
        _emit("pass", "Antigravity hooks", f"reachable at {canonical}", r=r)
    else:
        _emit(
            "fail",
            "Antigravity hooks",
            f"{canonical} exists but does not reference DefenseClaw hook script",
            r=r,
        )

    # Signal 2: legacy-path migration warning. agy ignores this
    # file at runtime so its presence won't break the integration,
    # but it *will* mislead operators who run `agy --help` (which
    # still advertises antigravity-cli/) and inspect the file
    # expecting to see DefenseClaw-managed entries.
    if os.path.isfile(legacy) and _hook_json_references(legacy, "antigravity-hook.sh"):
        _emit(
            "warn",
            "Antigravity hooks",
            "stale DefenseClaw entries found at "
            f"{legacy} from a pre-v0.5.0 install. agy v1.0.x ignores "
            "this path at runtime (it reads from "
            "~/.gemini/config/hooks.json). Safe to delete the file or "
            "remove the defenseclaw-antigravity-* keys to declutter; "
            "leaving it in place will not break the integration but "
            "will confuse anyone who inspects it.",
            r=r,
        )

    # Signal 3: duplicate-firing warning. These paths *are*
    # evaluated by agy and would cause one tool call to fire
    # multiple DefenseClaw hooks per discovered file.
    workspace = _workspace_dir(cfg)
    extras = [os.path.join(home, ".gemini", "hooks.json")]
    if workspace:
        extras.append(os.path.join(workspace, ".antigravitycli", "hooks.json"))
    duplicates = [
        extra for extra in extras if os.path.isfile(extra) and _hook_json_references(extra, "antigravity-hook.sh")
    ]
    if duplicates:
        _emit(
            "warn",
            "Antigravity hooks",
            "DefenseClaw hook also registered in additional discovered "
            "files (will cause duplicate firings): " + ", ".join(duplicates),
            r=r,
        )


def _check_openhands_hooks(cfg, r: _DoctorResult) -> None:
    workspace = _workspace_dir(cfg)
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, ".openhands", "hooks.json")]
    if workspace:
        candidates.insert(0, os.path.join(workspace, ".openhands", "hooks.json"))
    present = [path for path in candidates if os.path.isfile(path)]
    if not present:
        _emit(
            "fail",
            "OpenHands hooks",
            "not found in OpenHands SDK search paths: " + ", ".join(candidates),
            r=r,
        )
        return
    for path in present:
        if _hook_json_references(path, "openhands-hook.sh"):
            _emit("pass", "OpenHands hooks", f"reachable at {path}", r=r)
            return
    _emit(
        "fail",
        "OpenHands hooks",
        "hooks.json exists but does not reference DefenseClaw hook script: " + ", ".join(present),
        r=r,
    )


def _check_copilot_hooks(cfg, r: _DoctorResult) -> None:
    workspace = _workspace_dir(cfg)
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not workspace:
        path = os.path.join(os.path.expanduser("~"), ".copilot", "hooks", "defenseclaw.json")
        if not os.path.isfile(path):
            _emit("fail", "Copilot hooks", f"{path} not found", r=r)
            return
        if _hook_json_references(path, "copilot-hook.sh"):
            _emit("pass", "Copilot hooks", f"reachable at {path}", r=r)
            return
        _emit("fail", "Copilot hooks", f"{path} does not reference DefenseClaw hook script", r=r)
        return
    if _path_is_inside(workspace, data_dir):
        _emit(
            "fail",
            "Copilot hooks",
            f"workspace_dir points inside DefenseClaw data dir ({workspace}); run setup from the target repository",
            r=r,
        )
        return
    path = os.path.join(workspace, ".github", "hooks", "defenseclaw.json")
    if not os.path.isfile(path):
        _emit("fail", "Copilot hooks", f"{path} not found", r=r)
        return
    if _hook_json_references(path, "copilot-hook.sh"):
        _emit("pass", "Copilot hooks", f"reachable at {path}", r=r)
    else:
        _emit("fail", "Copilot hooks", f"{path} does not reference DefenseClaw hook script", r=r)


def _check_zeptoclaw_config(cfg, r: _DoctorResult) -> None:
    config_path = os.path.expanduser("~/.zeptoclaw/config.json")
    if not os.path.isfile(config_path):
        _emit("fail", "ZeptoClaw config", f"{config_path} not found", r=r)
        return
    try:
        with open(config_path, encoding="utf-8") as fh:
            zcfg = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        _emit("fail", "ZeptoClaw config", f"cannot read {config_path}: {exc}", r=r)
        return
    providers = zcfg.get("providers", {})
    proxy_count = 0
    for name, prov in providers.items():
        if not isinstance(prov, dict):
            continue
        api_base = prov.get("api_base", "")
        if "defenseclaw" in api_base or "/c/zeptoclaw" in api_base:
            proxy_count += 1
    if proxy_count > 0:
        _emit("pass", "ZeptoClaw config", f"{proxy_count} provider(s) routed through proxy", r=r)
    else:
        _emit("fail", "ZeptoClaw config", "no providers routed through DefenseClaw proxy", r=r)


def _check_guardrail_proxy(cfg, r: _DoctorResult) -> None:
    if not cfg.guardrail.enabled:
        _emit("skip", "Guardrail proxy", "disabled", r=r)
        return

    closed_detail = _guardrail_proxy_intentionally_closed(cfg)
    if closed_detail:
        _emit("pass", "Guardrail proxy", closed_detail, r=r)
        return

    if not cfg.guardrail.model:
        _emit(
            "warn",
            "Guardrail proxy",
            "guardrail.model is empty — relying on fetch-interceptor routing",
            r=r,
        )

    host = getattr(cfg.guardrail, "host", None) or "127.0.0.1"
    url = f"http://{host}:{cfg.guardrail.port}/health/liveliness"
    code, _ = _http_probe(url, timeout=5.0)
    if code == 200:
        _emit("pass", "Guardrail proxy", f"healthy on port {cfg.guardrail.port}", r=r)
    else:
        _emit("fail", "Guardrail proxy", f"not responding on port {cfg.guardrail.port}", r=r)


# Connectors that enforce in-process via an agent-native lifecycle surface
# (hook bus or OmniGent's custom policy API) and talk directly to their
# upstream provider. They do NOT bind the guardrail proxy listener on port
# 4000. Proxy connectors (openclaw, zeptoclaw) are deliberately absent.
_HOOK_ENFORCED_CONNECTORS = frozenset(
    {
        "codex",
        "claudecode",
        "hermes",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
        "openhands",
        "antigravity",
        "opencode",
        "omnigent",
    }
)


def _guardrail_proxy_intentionally_closed(cfg) -> str:
    """Return a detail string when the proxy port is expected to be closed.

    Hook/policy-enforced connectors feed DefenseClaw through the agent's
    native lifecycle surface
    while the agent talks directly to its upstream provider. Port
    4000 is deliberately unbound in that topology, so doctor must
    not report a hard proxy failure. Action mode IS supported on
    this surface — enforcement happens via the PreToolUse deny
    verdict, not the proxy.

    Evaluated over the FULL active set, not just the primary connector
    (D6): the port is only "intentionally closed" when EVERY active
    connector is hook-enforced. If ANY active connector is a proxy type
    (openclaw/zeptoclaw) — or an unknown connector that may bind the
    listener — this returns ``""`` so :func:`_check_guardrail_proxy` runs
    the real ``/health/liveliness`` probe. Previously the singular primary
    decided this alone, so a hook-enforced primary masked a proxy peer that
    genuinely needed port 4000 up and the probe was wrongly skipped.
    """
    gc = cfg.guardrail
    connectors = _doctor_active_connectors(cfg)
    if not connectors:
        return ""
    if any(c not in _HOOK_ENFORCED_CONNECTORS for c in connectors):
        return ""
    modes = {c: _doctor_effective_guardrail_mode(gc, c) for c in sorted(connectors)}
    # Preserve the exact single-connector wording; aggregate (sorted, stable)
    # for a multi-connector all-hook-enforced fan-out.
    label = connectors[0] if len(connectors) == 1 else ", ".join(sorted(connectors))
    if len(connectors) == 1:
        mode = modes.get(connectors[0], "observe")
        if connectors[0] == "omnigent":
            if mode == "action":
                return "policy-enforced for omnigent (mode=action via ALLOW/ASK/DENY) — proxy port intentionally closed"
            return "policy-driven for omnigent (mode=observe) — proxy port intentionally closed"
        if mode == "action":
            return f"hook-enforced for {label} (mode=action via PreToolUse deny) — proxy port intentionally closed"
        return f"hook-driven for {label} (mode=observe) — proxy port intentionally closed"
    if "omnigent" not in modes and all(mode == "action" for mode in modes.values()):
        return f"hook-enforced for {label} (mode=action via PreToolUse deny) — proxy port intentionally closed"
    if "omnigent" not in modes and all(mode != "action" for mode in modes.values()):
        return f"hook-driven for {label} (mode=observe) — proxy port intentionally closed"
    parts = []
    for connector, mode in modes.items():
        if connector == "omnigent" and mode == "action":
            parts.append("omnigent (mode=action via ALLOW/ASK/DENY)")
        elif connector == "omnigent":
            parts.append("omnigent (mode=observe via custom policy API)")
        elif mode == "action":
            parts.append(f"{connector} (mode=action via PreToolUse deny)")
        else:
            parts.append(f"{connector} (mode=observe)")
    prefix = "enforced" if all(mode == "action" for mode in modes.values()) else "native-driven"
    return f"{prefix} for {', '.join(parts)} — proxy port intentionally closed"


def _doctor_effective_guardrail_mode(gc, connector: str) -> str:
    mode = (getattr(gc, "mode", "") or "observe").strip().lower()
    if hasattr(gc, "effective_mode"):
        try:
            mode = (gc.effective_mode(connector) or mode).strip().lower()
        except Exception:  # noqa: BLE001 — keep the global fallback.
            pass
    return "action" if mode == "action" else "observe"


def _check_llm_api_key(cfg, r: _DoctorResult) -> None:
    """Verify the unified LLM key used by the guardrail proxy.

    In v5 the guardrail's LLM settings come from
    ``Config.resolve_llm("guardrail")`` — which layers
    ``guardrail.llm`` on top of the top-level ``llm:`` block. We
    read from there rather than the legacy ``guardrail.api_key_env``/
    ``guardrail.model`` fields so edits to the unified block are
    honored without re-running ``setup``.

    Local providers (Ollama, vLLM, LM Studio) and localhost base URLs
    skip the API-key check entirely — these runtimes don't
    authenticate incoming requests, so demanding a key would surface
    a misleading failure. We still warn if the model string is
    empty, because without it Bifrost has nothing to route to.
    """
    gc = cfg.guardrail
    if not gc.enabled:
        _emit("skip", "LLM API key", "guardrail disabled", r=r)
        return

    # Hook/policy-only connectors do not route LLM traffic through the
    # guardrail provider. When the optional judge is also off, requiring a
    # guardrail LLM key is a false failure: local regex/Cisco-AID policy lanes
    # remain fully functional without one.
    judge = getattr(gc, "judge", None)
    if _guardrail_proxy_intentionally_closed(cfg) and not bool(getattr(judge, "enabled", False)):
        _emit(
            "skip",
            "LLM API key",
            "not required by hook/policy enforcement while the LLM judge is disabled",
            r=r,
        )
        return

    llm = cfg.resolve_llm("guardrail")
    model = llm.model or gc.model or ""

    if llm.is_local_provider():
        base = llm.base_url or "(default)"
        if not model:
            _emit(
                "warn",
                "LLM API key",
                f"local provider '{llm.provider}' configured (base_url={base}) but no model set",
                r=r,
            )
        else:
            _emit(
                "skip",
                "LLM API key",
                f"local provider '{llm.provider}' needs no key (base_url={base}, model={model})",
                r=r,
            )
        return

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    # Pre-v5 configs stash the env name on ``guardrail.api_key_env``;
    # Config.load() migrates that into cfg.guardrail.llm.api_key_env
    # so resolve_llm() picks it up, but tests (and any in-memory
    # Config constructed without load()) may still rely on the
    # legacy field. Fall back here so those paths don't spuriously
    # report "api_key_env not configured".
    env_name = llm.api_key_env or gc.api_key_env or "DEFENSECLAW_LLM_KEY"
    api_key = llm.resolved_api_key()
    if not api_key:
        api_key = _resolve_api_key(env_name, dotenv_path)

    if not api_key:
        _emit("fail", "LLM API key", f"{env_name} not set (checked env + {dotenv_path})", r=r)
        return
    # Route by the resolved provider prefix first. A bare Bedrock model
    # with ``provider: bedrock`` is valid config; treating the bare model
    # id as the provider made doctor say it "cannot verify" Bedrock keys.
    # Env-name fallback remains last-resort only for empty provider/model
    # configs so a misleading variable name cannot override an explicit
    # provider.
    provider = llm.provider_prefix()
    if not provider and "/" in model:
        provider = model.split("/", 1)[0].lower()

    anthropic_provider = provider == "anthropic" or (
        provider == "" and env_name.startswith("ANTHROPIC")
    )
    if anthropic_provider:
        if r.passive:
            _emit(
                "skip",
                "LLM API key (Anthropic)",
                f"{env_name} is set; passive mode avoids the inference-based authentication probe",
                r=r,
            )
        else:
            _verify_anthropic(api_key, r, model)
    elif provider == "openai":
        _verify_openai(api_key, r)
    elif provider in ("bedrock", "amazon-bedrock"):
        _verify_bedrock(api_key, r)
    elif provider == "" and env_name.startswith("OPENAI"):
        _verify_openai(api_key, r)
    elif provider == "" and env_name.startswith("AWS_BEARER_TOKEN_BEDROCK"):
        _verify_bedrock(api_key, r)
    else:
        _emit(
            "pass",
            "LLM API key",
            f"{env_name} is set (cannot verify provider '{provider or model}')",
            r=r,
        )


def _check_llm_reachable(cfg, r: _DoctorResult) -> None:
    """One-shot ``llm.ping`` against the guardrail's resolved LLM.

    Complements :func:`_check_llm_api_key`: where that probe asserts the
    key is *plausible* against provider-specific introspection endpoints,
    this probe sends a single ``max_tokens=1`` chat to LiteLLM with the
    full resolved provider routing — exactly the path the gateway and
    scanners exercise at runtime. Skipped when the guardrail is off or
    the model is unset because there's nothing meaningful to ping.

    Implementation detail: ``defenseclaw.llm.ping`` returns
    ``(ok, message)`` and never raises, so the doctor can render the
    outcome without catching exceptions itself.
    """
    gc = cfg.guardrail
    if not gc.enabled:
        _emit("skip", "LLM reachable", "guardrail disabled", r=r)
        return
    llm = cfg.resolve_llm("guardrail")
    if not (llm.model or "").strip():
        _emit("skip", "LLM reachable", "no model configured", r=r)
        return
    if r.passive:
        _emit(
            "skip",
            "LLM reachable",
            "passive mode avoids the billable max_tokens=1 inference probe",
            r=r,
        )
        return
    try:
        from defenseclaw import llm as _llm
    except Exception as exc:
        _emit("warn", "LLM reachable", f"llm.ping unavailable: {exc}", r=r)
        return
    with _capture_stdout_when_json():
        ok, msg = _llm.ping(llm, timeout=5)
    if ok:
        _emit("pass", "LLM reachable", msg, r=r)
    else:
        _emit("warn", "LLM reachable", msg, r=r)


def _check_regional_provider_config(cfg, r: _DoctorResult) -> None:
    """Sanity-check provider-typed sub-blocks on the resolved LLM.

    Bedrock requires a region; Vertex requires both ``project_id`` and
    a region; Azure requires an ``endpoint`` and an ``api_version``.
    We emit ``fail`` when the structured block is in use but missing a
    required field — the runtime would otherwise reject every call with
    a cryptic upstream error. When the structured block is absent we
    skip silently so non-regional setups don't see noise.
    """
    if not cfg.guardrail.enabled:
        _emit("skip", "Regional provider", "guardrail disabled", r=r)
        return
    llm = cfg.resolve_llm("guardrail")
    label = "Regional provider"
    provider = (llm.provider or "").strip().lower()
    if provider in ("bedrock", "amazon-bedrock") and llm.bedrock is not None:
        b = llm.bedrock
        region = (b.region or llm.region or "").strip()
        if not region:
            _emit("fail", label, "bedrock configured without a region", r=r)
            return
        mode = (b.auth_mode or "").strip().lower() or "api_key"
        if mode == "iam_credentials" and not (b.access_key_env and b.secret_key_env):
            _emit(
                "warn",
                label,
                "bedrock auth_mode=iam_credentials requires access/secret key env names",
                r=r,
            )
            return
        if mode == "profile" and not b.profile_name:
            _emit("warn", label, "bedrock auth_mode=profile requires profile_name", r=r)
            return
        _emit("pass", label, f"bedrock region={region} auth_mode={mode}", r=r)
        return
    if provider == "vertex_ai" and llm.vertex is not None:
        v = llm.vertex
        if not (v.project_id or "").strip():
            _emit("fail", label, "vertex_ai configured without project_id", r=r)
            return
        if not (v.region or llm.region or "").strip():
            _emit("fail", label, "vertex_ai configured without region", r=r)
            return
        mode = (v.auth_mode or "").strip().lower() or "service_account"
        if mode == "service_account" and not (v.service_account_json_env or "").strip():
            _emit(
                "warn",
                label,
                "vertex_ai auth_mode=service_account requires service_account_json_env",
                r=r,
            )
            return
        _emit("pass", label, f"vertex_ai project={v.project_id} region={v.region or llm.region}", r=r)
        return
    if provider == "azure" and llm.azure is not None:
        a = llm.azure
        if not (a.endpoint or "").strip():
            _emit("fail", label, "azure configured without endpoint", r=r)
            return
        if not (a.api_version or "").strip():
            _emit("warn", label, "azure configured without api_version", r=r)
            return
        _emit(
            "pass",
            label,
            f"azure endpoint={a.endpoint} api_version={a.api_version}",
            r=r,
        )
        return
    _emit("skip", label, "no regional provider in use", r=r)


def _check_custom_provider_overlay(cfg, r: _DoctorResult) -> None:
    """Validate ``~/.defenseclaw/custom-providers.json`` consistency.

    Checks:

    * The overlay file parses (anything else is silently treated as
      empty by ``LoadProviders`` on the Go side, but here we surface
      the parse error so the operator can fix it).
    * Any ``instance_name`` referenced in a resolved LLM block points
      at an actual overlay entry. A typo here would route requests
      through the default provider instead of the operator's custom
      endpoint — a silent fallback that's hard to debug later.
    * Per-instance TLS settings declare exactly one of
      ``ca_cert_pem`` or ``insecure_skip_verify``; declaring both is
      almost always a misconfiguration (we accept it on the Go side,
      but the warning matches the CLI's own validation).
    * When an overlay entry declares ``base_url``, the host portion of
      that URL must appear in the entry's ``domains`` list. The Go
      gateway's ``inferProviderFromURL`` resolves an inbound request
      to an overlay entry by host match; if the host is absent from
      ``domains`` the resolver bails before the instance-binding
      branch and the overlay's TLS / sub-block posture silently does
      not apply.
    """
    label = "Custom-provider overlay"
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        _emit("skip", label, "no data_dir configured", r=r)
        return
    path = os.path.join(data_dir, "custom-providers.json")
    if not os.path.isfile(path):
        _emit("skip", label, "no overlay configured", r=r)
        return
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        _emit("fail", label, f"cannot parse {path}: {exc}", r=r)
        return
    providers = payload.get("providers") or []
    if not isinstance(providers, list):
        _emit("fail", label, "providers field must be a list", r=r)
        return
    names: set[str] = set()
    for entry in providers:
        if isinstance(entry, dict) and entry.get("name"):
            names.add(str(entry["name"]).strip().lower())
    missing: list[tuple[str, str]] = []
    for component in ("", "guardrail", "guardrail.judge", "scanners.skill", "scanners.mcp", "scanners.plugin"):
        try:
            resolved = cfg.resolve_llm(component)
        except Exception:
            continue
        name = (getattr(resolved, "instance_name", "") or "").strip().lower()
        if name and name not in names:
            missing.append((component or "llm", name))
    if missing:
        rows = ", ".join(f"{c}->{n}" for c, n in missing)
        _emit("fail", label, f"instance_name not found in overlay: {rows}", r=r)
        return
    tls_warns: list[str] = []
    family_warns: list[str] = []
    auth_warns: list[str] = []
    domain_warns: list[str] = []
    bedrock_auth_modes = {"api_key", "iam_credentials", "profile", "instance_role"}
    vertex_auth_modes = {"service_account", "adc", "workload_identity"}
    azure_auth_modes = {"api_key", "managed_identity"}
    for entry in providers:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "?")
        tls = entry.get("tls") or {}
        if isinstance(tls, dict) and tls.get("ca_cert_pem") and tls.get("insecure_skip_verify"):
            tls_warns.append(name)
        # Domain coverage: when an overlay declares base_url, requests
        # whose X-DC-Target-URL (fetch-interceptor agents) or connector
        # snapshot URL (native binaries like ZeptoClaw / Codex) carry
        # that same URL must be recognizable to the Go gateway's
        # inferProviderFromURL. If the host portion of base_url is
        # not in this entry's domains, the resolver returns "" and
        # bails before the instance-binding branch — the overlay's
        # TLS / sub-block posture then silently does not apply and
        # the user sees stock TLS / default routing instead.
        base_url_raw = str(entry.get("base_url") or "").strip()
        if base_url_raw:
            try:
                parsed = urllib.parse.urlparse(base_url_raw)
                host = (parsed.hostname or "").lower()
            except ValueError:
                host = ""
            entry_domains = entry.get("domains") or []
            domain_strs: list[str] = []
            if isinstance(entry_domains, list):
                for d in entry_domains:
                    s = str(d or "").strip().lower()
                    if s:
                        domain_strs.append(s)
            if host:
                covered = any(host == d or host.endswith("." + d) for d in domain_strs)
                if not covered:
                    rendered = ", ".join(domain_strs) if domain_strs else "(empty)"
                    domain_warns.append(f"{name}: base_url host {host!r} not covered by domains [{rendered}]")
        # Family-mismatch: a bedrock/vertex/azure sub-block paired with
        # a base_provider_type from a different family is dead config.
        # The Go gateway tolerates it (the dispatcher only consults the
        # matching family) but surfacing it here saves the operator a
        # confused stare at "why is my Bedrock region not applied?".
        bpt = str(entry.get("base_provider_type") or "").strip().lower()
        if entry.get("bedrock") and bpt and bpt != "bedrock":
            family_warns.append(f"{name}: bedrock sub-block with base_provider_type={bpt!r}")
        if entry.get("vertex") and bpt and bpt != "vertex_ai":
            family_warns.append(f"{name}: vertex sub-block with base_provider_type={bpt!r}")
        if entry.get("azure") and bpt and bpt != "azure":
            family_warns.append(f"{name}: azure sub-block with base_provider_type={bpt!r}")
        # Unknown auth_mode values are stored verbatim by the resolver
        # and silently ignored by the dispatcher. Catch them here.
        bedrock = entry.get("bedrock") or {}
        vertex = entry.get("vertex") or {}
        azure = entry.get("azure") or {}
        if isinstance(bedrock, dict):
            mode = str(bedrock.get("auth_mode") or "").strip().lower()
            if mode and mode not in bedrock_auth_modes:
                auth_warns.append(f"{name}: bedrock.auth_mode={mode!r}")
        if isinstance(vertex, dict):
            mode = str(vertex.get("auth_mode") or "").strip().lower()
            if mode and mode not in vertex_auth_modes:
                auth_warns.append(f"{name}: vertex.auth_mode={mode!r}")
        if isinstance(azure, dict):
            mode = str(azure.get("auth_mode") or "").strip().lower()
            if mode and mode not in azure_auth_modes:
                auth_warns.append(f"{name}: azure.auth_mode={mode!r}")
    # Role+overlay duplicate-field detection: when both a resolved LLM
    # role *and* the overlay it references set the same scalar, the
    # role wins (per the documented precedence). The overlay value is
    # then dead config — informational, not a failure, but worth a
    # heads-up so operators reconcile the two.
    dup_warns: list[str] = []
    overlay_by_name: dict[str, dict] = {}
    for entry in providers:
        if isinstance(entry, dict) and entry.get("name"):
            overlay_by_name[str(entry["name"]).strip().lower()] = entry
    for component in ("", "guardrail", "guardrail.judge", "scanners.skill", "scanners.mcp", "scanners.plugin"):
        try:
            resolved = cfg.resolve_llm(component)
        except Exception:
            continue
        inst_name = (getattr(resolved, "instance_name", "") or "").strip().lower()
        if not inst_name or inst_name not in overlay_by_name:
            continue
        overlay_entry = overlay_by_name[inst_name]
        # Scalar role fields whose role-level value silences the overlay
        # equivalent are tracked here. Sub-block scalars (Bedrock.Region
        # vs role.bedrock.region) are checked field-by-field on the
        # resolved object — _apply_instance_overlay already does the
        # merge, so equality here means the role explicitly set the
        # value and the overlay declared a different one.
        if resolved.base_url and overlay_entry.get("base_url") and resolved.base_url != overlay_entry.get("base_url"):
            dup_warns.append(
                f"{component or 'llm'}: base_url role={resolved.base_url!r} "
                f"overlay={overlay_entry['base_url']!r} (role wins)"
            )
        # Bedrock/Vertex/Azure: compare each scalar field where both
        # sides have a value. The overlay value is dead config.
        role_b = getattr(resolved, "bedrock", None)
        ov_b = overlay_entry.get("bedrock") or {}
        if role_b is not None and isinstance(ov_b, dict):
            for fld in ("region", "auth_mode", "profile_name", "inference_profile"):
                rv = (getattr(role_b, fld, "") or "").strip()
                ov = str(ov_b.get(fld) or "").strip()
                if rv and ov and rv != ov:
                    dup_warns.append(f"{component or 'llm'}: bedrock.{fld} role={rv!r} overlay={ov!r} (role wins)")
        role_v = getattr(resolved, "vertex", None)
        ov_v = overlay_entry.get("vertex") or {}
        if role_v is not None and isinstance(ov_v, dict):
            for fld in ("project_id", "region", "auth_mode", "service_account_json_env"):
                rv = (getattr(role_v, fld, "") or "").strip()
                ov = str(ov_v.get(fld) or "").strip()
                if rv and ov and rv != ov:
                    dup_warns.append(f"{component or 'llm'}: vertex.{fld} role={rv!r} overlay={ov!r} (role wins)")
        role_a = getattr(resolved, "azure", None)
        ov_a = overlay_entry.get("azure") or {}
        if role_a is not None and isinstance(ov_a, dict):
            for fld in ("endpoint", "api_version", "auth_mode"):
                rv = (getattr(role_a, fld, "") or "").strip()
                ov = str(ov_a.get(fld) or "").strip()
                if rv and ov and rv != ov:
                    dup_warns.append(f"{component or 'llm'}: azure.{fld} role={rv!r} overlay={ov!r} (role wins)")
    if tls_warns:
        _emit(
            "warn",
            label,
            "instances declare both ca_cert_pem and insecure_skip_verify: " + ", ".join(tls_warns),
            r=r,
        )
    if family_warns:
        _emit(
            "warn",
            label,
            "overlay sub-block family does not match base_provider_type: " + "; ".join(family_warns),
            r=r,
        )
    if auth_warns:
        _emit(
            "warn",
            label,
            "overlay declares unrecognized auth_mode: " + "; ".join(auth_warns),
            r=r,
        )
    if domain_warns:
        _emit(
            "warn",
            label,
            "base_url host not declared in domains (gateway cannot resolve "
            "the overlay from inbound URL): " + "; ".join(domain_warns),
            r=r,
        )
    if dup_warns:
        _emit(
            "warn",
            label,
            "role and overlay disagree (role wins, overlay value is dead config): " + "; ".join(dup_warns),
            r=r,
        )
    if tls_warns or family_warns or auth_warns or domain_warns or dup_warns:
        return
    _emit("pass", label, f"{len(providers)} overlay entries OK", r=r)


# Default model used for the Anthropic auth probe when the configured model
# is not an Anthropic model. The probe sends max_tokens=1 so cost is
# negligible; any valid model id accepted by the account works. We pick a
# stable identifier that the OpenClaw docs list as generally available.
# Operators running against an older plan can override via
# DEFENSECLAW_ANTHROPIC_PROBE_MODEL.
_ANTHROPIC_DEFAULT_PROBE_MODEL = "claude-3-5-haiku-latest"


def _anthropic_probe_model(configured_model: str) -> str:
    if configured_model.startswith("anthropic/"):
        # Use the model the operator actually intends to call — avoids a
        # surprising "valid key, but model not enabled" 403 when the
        # default probe model isn't in the account's allowed list.
        return configured_model.split("/", 1)[1]
    override = os.environ.get("DEFENSECLAW_ANTHROPIC_PROBE_MODEL", "").strip()
    if override:
        return override
    return _ANTHROPIC_DEFAULT_PROBE_MODEL


# Default model used for the Anthropic auth probe when the configured model
# is not an Anthropic model. The probe sends max_tokens=1 so cost is
# negligible; any valid model id accepted by the account works. We pick a
# stable identifier that the OpenClaw docs list as generally available.
# Operators running against an older plan can override via
# DEFENSECLAW_ANTHROPIC_PROBE_MODEL.
_ANTHROPIC_DEFAULT_PROBE_MODEL = "claude-3-5-haiku-latest"


def _verify_anthropic(api_key: str, r: _DoctorResult, configured_model: str = "") -> None:
    probe_model = _anthropic_probe_model(configured_model)
    payload = json.dumps(
        {
            "model": probe_model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        }
    ).encode()
    code, body = _http_probe(
        "https://api.anthropic.com/v1/messages",
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        body=payload,
        timeout=15.0,
    )
    if code == 200:
        _emit("pass", "LLM API key (Anthropic)", "authenticated successfully", r=r)
    elif code == 401:
        _emit("fail", "LLM API key (Anthropic)", "invalid key (401 Unauthorized)", r=r)
    elif code == 403:
        _emit("fail", "LLM API key (Anthropic)", "forbidden (403) — key may be revoked or restricted", r=r)
    elif code == 429:
        _emit("pass", "LLM API key (Anthropic)", "authenticated (rate limited, but key is valid)", r=r)
    elif code == 400:
        _emit("pass", "LLM API key (Anthropic)", "authenticated (model/request error, but key accepted)", r=r)
    elif code == 0:
        _emit("warn", "LLM API key (Anthropic)", f"could not reach api.anthropic.com: {body}", r=r)
    else:
        try:
            err_body = json.loads(body)
            msg = err_body.get("error", {}).get("message", body[:120])
        except (json.JSONDecodeError, TypeError):
            msg = body[:120]
        _emit("fail", "LLM API key (Anthropic)", f"HTTP {code}: {msg}", r=r)


def _verify_openai(api_key: str, r: _DoctorResult) -> None:
    code, body = _http_probe(
        "https://api.openai.com/v1/models",
        method="GET",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=10.0,
    )
    if code == 200:
        _emit("pass", "LLM API key (OpenAI)", "authenticated successfully", r=r)
    elif code == 401:
        _emit("fail", "LLM API key (OpenAI)", "invalid key (401 Unauthorized)", r=r)
    elif code == 0:
        _emit("warn", "LLM API key (OpenAI)", f"could not reach api.openai.com: {body}", r=r)
    else:
        _emit("fail", "LLM API key (OpenAI)", f"HTTP {code}", r=r)


# Region used when we have to probe Bedrock but no region is pinned on
# the resolved LLM config or in the environment. us-east-1 has the
# broadest Bedrock foundation-model availability, which is what the
# probe queries — a key that's valid in another region still returns
# 200 here because the listFoundationModels endpoint is bearer-token
# authed, not region-scoped auth. Operators running Bedrock in an
# isolated partition (GovCloud etc.) should override via AWS_REGION.
_BEDROCK_DEFAULT_REGION = "us-east-1"


def _bedrock_region() -> str:
    for env_var in ("AWS_REGION", "AWS_REGION_NAME", "AWS_DEFAULT_REGION"):
        val = os.environ.get(env_var, "").strip()
        if val:
            return val
    return _BEDROCK_DEFAULT_REGION


def _verify_bedrock(api_key: str, r: _DoctorResult) -> None:
    """Verify an AWS Bedrock API key (short-term ABSK bearer token).

    LiteLLM and the DefenseClaw scanner bridge authenticate to Bedrock
    via ``Authorization: Bearer <ABSK…>`` — the short-term API key
    format AWS introduced alongside GA of Bedrock. That's a different
    auth path from the long-term SigV4 ``AKIA…`` key-id / secret pair:

    * ``ABSK…``  → bearer token, verifiable with a single GET.
    * ``AKIA…``  → SigV4 credentials; we can't verify without signing,
                  which would pull in botocore just for the doctor.
                  Emit a ``warn`` pointing at ``aws sts get-caller-identity``.
    * anything else → shape we don't recognize; pass with a note, same
                      as the generic fallback in ``_check_llm_api_key``.

    The foundation-models list endpoint is a cheap GET that returns
    the list of models enabled for the account. ``200`` confirms auth
    is working end-to-end; ``401/403`` flags a bad or scoped-out key
    before the operator discovers it at scan time.
    """
    if api_key.startswith("AKIA") or api_key.startswith("ASIA"):
        _emit(
            "warn",
            "LLM API key (Bedrock)",
            "AWS SigV4 credentials detected — doctor skips signed probes; run 'aws sts get-caller-identity' to verify.",
            r=r,
        )
        return
    if not api_key.startswith("ABSK"):
        _emit(
            "pass",
            "LLM API key (Bedrock)",
            f"key is set ({len(api_key)} chars) but shape not recognized; assuming operator knows what they're doing.",
            r=r,
        )
        return
    region = _bedrock_region()
    url = f"https://bedrock.{region}.amazonaws.com/foundation-models"
    code, body = _http_probe(
        url,
        method="GET",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=10.0,
    )
    if code == 200:
        _emit("pass", "LLM API key (Bedrock)", f"authenticated successfully ({region})", r=r)
    elif code == 401:
        _emit("fail", "LLM API key (Bedrock)", "invalid key (401 Unauthorized)", r=r)
    elif code == 403:
        # 403 from Bedrock usually means the token is valid but the
        # IAM policy/resource doesn't grant bedrock:ListFoundationModels.
        # That's a policy problem, not a key problem — downgrade to warn
        # so the scan still runs (the scanner uses InvokeModel, which
        # may be permitted even when List is not).
        _emit(
            "warn",
            "LLM API key (Bedrock)",
            "403 Forbidden — key authenticates but lacks bedrock:ListFoundationModels; InvokeModel may still work.",
            r=r,
        )
    elif code == 0:
        _emit(
            "warn",
            "LLM API key (Bedrock)",
            f"could not reach bedrock.{region}.amazonaws.com: {body}",
            r=r,
        )
    else:
        _emit("fail", "LLM API key (Bedrock)", f"HTTP {code}", r=r)


def _check_cisco_ai_defense(cfg, r: _DoctorResult) -> None:
    gc = cfg.guardrail
    if not gc.enabled or gc.scanner_mode not in ("remote", "both"):
        _emit("skip", "Cisco AI Defense", "not configured for remote scanning", r=r)
        return

    endpoint = cfg.cisco_ai_defense.endpoint
    key_env = cfg.cisco_ai_defense.api_key_env
    if not endpoint:
        _emit("fail", "Cisco AI Defense", "endpoint not configured", r=r)
        return

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    api_key = _resolve_api_key(key_env, dotenv_path) if key_env else ""

    if not api_key:
        display = key_env if key_env.isupper() and len(key_env) < 50 else "(env var not configured properly)"
        _emit("fail", "Cisco AI Defense", f"{display} not set", r=r)
        return
    if r.passive:
        _emit(
            "skip",
            "Cisco AI Defense",
            f"passive mode validated configuration and credential presence only; endpoint={endpoint}",
            r=r,
        )
        return

    # Probe the actual inspect route the runtime scanner hits rather
    # than /health. Two reasons:
    #
    # 1. Cisco AI Defense authenticates with the
    #    ``X-Cisco-AI-Defense-API-Key`` header, not ``Authorization:
    #    Bearer`` — the gateway-side scanner already sets this (see
    #    internal/gateway/cisco_inspect.go::Inspect). A doctor probe
    #    using the wrong header got 403 on preview deployments even
    #    when the same key worked end-to-end at runtime, which made
    #    the diagnostic actively misleading ("authentication failed"
    #    reported against a perfectly good key).
    #
    # 2. Some AID deployments (notably preview) don't expose an
    #    unauthenticated ``/health`` route at all, so even with the
    #    right header the probe would come back with a 404 / 5xx and
    #    be hard to interpret. The ``/api/v1/inspect/chat`` route is
    #    load-bearing on every deployment because the runtime uses
    #    it, so probing it here exercises the same code path an
    #    operator's real traffic will hit.
    probe_url = endpoint.rstrip("/") + "/api/v1/inspect/chat"
    probe_body = b'{"messages":[{"role":"user","content":"defenseclaw-doctor-probe"}],"metadata":{},"config":{}}'
    code, body = _http_probe(
        probe_url,
        method="POST",
        headers={
            "X-Cisco-AI-Defense-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body=probe_body,
        timeout=float(cfg.cisco_ai_defense.timeout_ms) / 1000.0,
    )

    if code == 200:
        _emit("pass", "Cisco AI Defense", endpoint, r=r)
    elif code == 401 or code == 403:
        _emit("fail", "Cisco AI Defense", f"authentication failed (HTTP {code})", r=r)
        # AI Defense has three regional deployments (us / eu / preview)
        # and all of them reply with the same opaque "401 invalid api
        # key" body — there's no way for the API itself to tell the
        # operator "your key is for a different region". Surface the
        # endpoint that was probed plus an actionable next step right
        # under the failure so a wrong-region key (the most common
        # post-rotation cause) doesn't get misdiagnosed as a revoked
        # one. Hints are advisory rows: not counted in the result
        # tally and suppressed in JSON mode (consumers there see the
        # endpoint via the spec, not the rendered hint).
        _emit_aid_hint(f"endpoint: {endpoint}")
        _emit_aid_hint("if the key was issued for a different region, run: defenseclaw setup")
    elif code == 0:
        _emit("warn", "Cisco AI Defense", f"endpoint unreachable: {body[:100]}", r=r)
        _emit_aid_hint(f"endpoint: {endpoint}")
    else:
        _emit("warn", "Cisco AI Defense", f"HTTP {code} (unexpected — endpoint responded but not 200)", r=r)
        _emit_aid_hint(f"endpoint: {endpoint}")


def _check_observability(cfg, r: _DoctorResult, *, live_health: dict | None = None) -> None:
    """Inspect v8 status and exercise each enabled Galileo runtime route."""
    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.config_inspect import ConfigInspectError
    from defenseclaw.observability.custody_status import inspect_connector_custody
    from defenseclaw.observability.v8_config import V8ConfigError
    from defenseclaw.observability.v8_status import inspect_v8_operator_status

    config_path = config_path_for_data_dir(cfg.data_dir)
    try:
        status = inspect_v8_operator_status(config_path)
    except (ConfigInspectError, V8ConfigError, ValueError) as exc:
        _emit("fail", "Observability v8 effective plan", str(exc), r=r)
        return
    _check_observability_v8_status(status, r, live_health=live_health)
    _check_connector_export_custody(
        inspect_connector_custody(
            status.local_path or getattr(cfg, "audit_db", os.path.join(cfg.data_dir, "audit.db")),
            cfg.data_dir,
        ),
        r,
    )
    _check_galileo_trace_canaries(
        status,
        r,
        config_path=str(config_path),
        data_dir=cfg.data_dir,
    )


def _check_connector_export_custody(report, r: _DoctorResult) -> None:
    """Render per-instance custody and bounded native-ingest evidence.

    This is intentionally diagnostic only. In particular, doctor never edits
    a connector exporter, and an ``external`` row is the expected result for
    a migrated connector until the operator runs explicit managed setup.
    """

    if report.state != "available":
        _emit(
            "skip",
            "Connector export custody",
            f"unavailable ({report.reason}); correlation remains active for received telemetry",
            r=r,
        )
        return
    if not report.instances:
        _emit(
            "skip",
            "Connector export custody",
            "no connector instance has emitted correlation evidence yet",
            r=r,
        )
    for item in report.instances:
        suffix = "" if item.default else f"/{item.connector_instance_id[:8]}"
        label = f"Connector OTLP: {item.connector}{suffix}"
        if item.custody == "external":
            tag = "warn"
            conditions = [
                "native exporter bypasses DefenseClaw",
                "migration left its endpoint and credentials untouched",
                "run explicit managed connector setup to opt in",
            ]
            if item.credential_state == "invalid":
                tag = "fail"
                conditions.append(f"invalid credentials observed ({item.authentication_failures} recent failures)")
            elif item.credential_state == "recovered":
                conditions.append(f"credentials recovered after {item.authentication_failures} recent failures")
            if item.normalized_batches and item.drop_only_batches == item.normalized_batches:
                tag = "fail"
                conditions.append(
                    f"drop-only native stream ({item.drop_only_batches}/{item.normalized_batches} batches)"
                )
            elif item.drop_only_batches:
                conditions.append(
                    f"partial drop-only evidence ({item.drop_only_batches}/{item.normalized_batches} batches)"
                )
            _emit(
                tag,
                label,
                "custody=external; " + "; ".join(conditions),
                r=r,
            )
            continue
        if item.custody == "hook_only":
            _emit(
                "pass",
                label,
                "custody=hook_only; no native exporter is expected; correlation remains active on hook telemetry",
                r=r,
            )
            continue

        tag = "pass"
        conditions: list[str] = []
        if item.managed_config_state == "drifted":
            tag = "fail"
            conditions.append("managed-exporter drift detected")
        elif item.managed_config_state == "unverifiable":
            tag = "warn"
            conditions.append("managed-exporter state is unverifiable")
        elif item.managed_config_state == "verified":
            conditions.append(f"managed-exporter verified ({item.managed_config_files} files)")
        else:
            conditions.append(f"managed-exporter={item.managed_config_state}")

        if item.credential_state == "invalid":
            tag = "fail"
            conditions.append(f"invalid credentials observed ({item.authentication_failures} recent failures)")
        elif item.credential_state == "recovered":
            if tag == "pass":
                tag = "warn"
            conditions.append(f"credentials recovered after {item.authentication_failures} recent failures")
        else:
            conditions.append("credentials=no recent failure")

        if item.normalized_batches and item.drop_only_batches == item.normalized_batches:
            tag = "fail"
            conditions.append(f"drop-only native stream ({item.drop_only_batches}/{item.normalized_batches} batches)")
        elif item.drop_only_batches:
            if tag == "pass":
                tag = "warn"
            conditions.append(
                f"partial drop-only evidence ({item.drop_only_batches}/{item.normalized_batches} batches)"
            )
        else:
            conditions.append(f"normalized_batches={item.normalized_batches}")
        _emit(
            tag,
            label,
            f"custody=defenseclaw; profile={item.profile_version}; " + "; ".join(conditions),
            r=r,
        )

    if report.unattributed_authentication_failures:
        _emit(
            "warn",
            "Native OTLP credentials",
            f"invalid credential attempts could not be attributed to a trusted connector; "
            f"count={report.unattributed_authentication_failures}; "
            f"last={report.last_unattributed_authentication_failure or 'unknown'}",
            r=r,
        )
    if report.event_rows_truncated:
        _emit(
            "warn",
            "Connector OTLP evidence",
            "recent evidence reached the bounded read limit; drop-only and credential counts are partial",
            r=r,
        )


def _check_galileo_trace_canaries(
    status,
    r: _DoctorResult,
    *,
    config_path: str,
    data_dir: str,
) -> None:
    """Emit real canaries up to the automatic enabled-Galileo limit."""

    from defenseclaw.observability.trace_canary import TraceCanaryError, run_trace_canary

    destinations = [
        destination
        for destination in status.destinations
        if destination.enabled and getattr(destination, "preset", "") == "galileo"
    ]
    if r.passive:
        if destinations:
            _emit(
                "skip",
                "Galileo canaries",
                f"passive mode suppresses synthetic trace export; configured={len(destinations)}",
                r=r,
            )
        return
    for destination in destinations[:_DOCTOR_GALILEO_CANARY_LIMIT]:
        label = f"Galileo canary: {destination.name}"
        try:
            result = run_trace_canary(
                destination=destination.name,
                config_path=config_path,
                data_dir=data_dir,
                timeout=15.0,
            )
        except TraceCanaryError as exc:
            _emit(
                "fail",
                label,
                f"{exc.failure_class}: {exc.message}",
                r=r,
            )
            continue
        _emit(
            "pass",
            label,
            f"acknowledged; trace_id={result.trace_id}; generation={result.generation}",
            r=r,
        )
    remaining = len(destinations) - _DOCTOR_GALILEO_CANARY_LIMIT
    if remaining > 0:
        _emit(
            "warn",
            "Galileo canary coverage",
            f"untested={remaining}; automatic_limit={_DOCTOR_GALILEO_CANARY_LIMIT}; "
            "remaining enabled routes retain bounded runtime-health checks",
            r=r,
        )


def _check_observability_v8_status(
    status,
    r: _DoctorResult,
    *,
    live_health: dict | None = None,
) -> None:
    """Render one canonical v8 operator snapshot into doctor checks."""

    from defenseclaw.observability.v8_status import (
        destination_health_from_gateway,
        retention_health_from_gateway,
    )

    retention = "unbounded" if status.unbounded_retention else f"{status.retention_days} days"
    local_path = status.local_path or "built-in data directory"
    _emit(
        "warn" if status.unbounded_retention else "pass",
        "Local SQLite",
        f"retention={retention}; path={local_path}",
        r=r,
    )
    if status.judge_bodies_path:
        _emit(
            "pass",
            "Judge-body store",
            f"capture={'enabled' if status.judge_bodies_enabled else 'disabled'}; "
            f"retention={retention}; path={status.judge_bodies_path}",
            r=r,
        )

    destination_health = destination_health_from_gateway(live_health)
    for destination in status.destinations:
        signals = ",".join(destination.selected_signals) or "none"
        detail = (
            f"kind={destination.kind}; signals={signals}; policy={destination.policy_form}; "
            f"buckets={len(destination.buckets)}; redaction={destination.redaction_label}; "
            f"limits={destination.delivery_limits_label}"
        )
        if destination.endpoint:
            detail += f"; target={destination.endpoint}"
        live = destination_health.get(destination.name)
        tag = "pass" if destination.enabled else "skip"
        if destination.enabled and live is not None:
            live_state = live.state or "unavailable"
            detail += f"; health={live_state}"
            if live.reason:
                detail += f"/{live.reason}"
            detail += f"; queue={live.queue_label}; last={live.activity_label}; circuit={live.circuit_label}"
            if live_state == "unavailable" and destination.kind != "sqlite":
                tag = "warn"
            elif live_state in {"degraded", "initializing", "draining"}:
                tag = "warn"
            elif live_state in {"failing", "stopped", "disabled"}:
                tag = "fail"
            if live.circuit_state == "half_open":
                tag = "warn"
                detail += "; one bounded recovery probe is in progress"
            elif live.circuit_state == "open":
                if live.last_failure_class in {
                    "authentication",
                    "permanent_payload",
                    "unsafe_endpoint",
                }:
                    tag = "fail"
                elif tag == "pass":
                    tag = "warn"
                destination_arg = shlex.quote(destination.name)
                detail += (
                    "; export work is automatically suppressed while local SQLite "
                    "continues; repair credentials/endpoint and reload the gateway, "
                    "or explicitly disable this optional route with "
                    f"`defenseclaw setup observability disable {destination_arg}`"
                )
        elif destination.enabled and destination.kind != "sqlite":
            tag = "warn"
            detail += "; health=unavailable; queue=unavailable; last=unavailable"
        _emit(
            tag,
            f"Destination: {destination.name}",
            detail if destination.enabled else f"disabled; {detail}",
            r=r,
        )

    retention_state, retention_failure = retention_health_from_gateway(live_health)
    if retention_state:
        detail = retention_state
        if retention_failure:
            detail += f"; failure={retention_failure}"
        _emit(
            "warn" if retention_state in {"degraded", "stopped"} else "pass",
            "Retention controller",
            detail,
            r=r,
        )

    collected = sum(bool(bucket.collected_signals) for bucket in status.buckets)
    _emit(
        "pass",
        "Bucket catalog",
        f"version={status.bucket_catalog_version}; collected={collected}/{len(status.buckets)}",
        r=r,
    )
    for code, path, summary in status.warnings:
        _emit("warn", f"Observability warning: {code}", f"{path}: {summary}", r=r)


def _check_webhooks(cfg, r: _DoctorResult) -> None:
    """Validate every entry in ``webhooks[]`` (notifier webhooks).

    Checks (per entry):

    * SSRF guard — same validation the Go gateway runs at start-up
      (non-http(s) scheme, private/link-local, metadata endpoints).
    * Secret presence — for types that require one (pagerduty, webex,
      signed generic) the ``secret_env`` variable must resolve to a
      non-empty value.
    * Reachability — a best-effort OPTIONS request. We do *not* dispatch
      a synthetic payload here because receivers may page on-call; for
      that use ``defenseclaw setup webhook test <name>`` explicitly.
    """
    try:
        entries = list_webhooks(cfg.data_dir)
    except Exception as exc:
        _emit("warn", "Webhooks", f"could not enumerate webhooks: {exc}", r=r)
        return

    if not entries:
        _emit("skip", "Webhooks", "no webhooks configured", r=r)
        return

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    for v in entries:
        label = f"{v.name} (webhook/{v.type})"

        if not v.enabled:
            _emit("skip", label, "disabled", r=r)
            continue

        try:
            validate_webhook_url(v.url)
        except ValueError as exc:
            _emit("fail", label, f"URL rejected by SSRF guard: {exc}", r=r)
            continue

        # Secret-presence: pagerduty routing key and webex bot token are
        # required at runtime; for generic, an HMAC secret is optional
        # but we warn loudly if the caller wired a secret_env that
        # doesn't resolve.
        if v.secret_env:
            secret_value = _resolve_api_key(v.secret_env, dotenv_path)
            if not secret_value:
                if v.type in ("pagerduty", "webex"):
                    _emit("fail", label, f"env var {v.secret_env!r} is empty", r=r)
                    continue
                _emit("warn", label, f"env var {v.secret_env!r} is empty", r=r)
        elif v.type in ("pagerduty", "webex"):
            _emit("fail", label, "secret_env is required for this type", r=r)
            continue

        if v.type == "webex" and not v.room_id:
            _emit("fail", label, "room_id is required for webex", r=r)
            continue

        # Reachability probe — OPTIONS is the safest, many webhooks
        # reject HEAD. Chat providers typically 405/400/404 on OPTIONS
        # from unknown origins; that still proves the host is live.
        code, body = _http_probe(v.url, method="OPTIONS", timeout=5.0)
        if code == 0:
            _emit("warn", label, f"unreachable: {body[:100]}", r=r)
        elif 500 <= code < 600:
            _emit("warn", label, f"server error (HTTP {code})", r=r)
        else:
            _emit("pass", label, f"reachable (HTTP {code})", r=r)


def _check_virustotal(cfg, r: _DoctorResult) -> None:
    sc = cfg.scanners.skill_scanner
    vt_key = sc.resolved_virustotal_api_key()
    if not sc.use_virustotal or not vt_key:
        _emit("skip", "VirusTotal API", "not enabled", r=r)
        return

    code, _ = _http_probe(
        "https://www.virustotal.com/api/v3/files/upload_url",
        headers={"x-apikey": vt_key},
        timeout=10.0,
    )

    if code == 200:
        _emit("pass", "VirusTotal API", "key valid", r=r)
    elif code == 401 or code == 403:
        _emit("fail", "VirusTotal API", "invalid or unauthorized key", r=r)
    elif code == 0:
        _emit("warn", "VirusTotal API", "could not reach virustotal.com", r=r)
    else:
        _emit("warn", "VirusTotal API", f"HTTP {code}", r=r)


# ---------------------------------------------------------------------------
# Security-overrides check (env-var registry-driven)
# ---------------------------------------------------------------------------

# Severity → doctor-tag mapping. Anything we surface in doctor is at
# minimum a 'warn' because the operator made a deliberate choice; we
# don't want to FAIL on legitimate dev/test overrides. High-impact
# overrides still warn loudly so they stand out in the summary line.
_OVERRIDE_TAG_BY_IMPACT = {
    "high": "warn",
    "medium": "warn",
    "low": "warn",
}


def _check_security_overrides(cfg, r: _DoctorResult) -> None:
    """Surface DEFENSECLAW_* env vars that weaken security defaults.

    Reads the centralized registry (``cli/defenseclaw/envvars.py``) and
    emits one warn per active opt-out so operators can see at a glance
    which bypasses are in effect. Idle installs see a single PASS row
    ("none active") — typical for production deployments.

    Why this matters: the codebase has ~70 ``DEFENSECLAW_*`` env vars
    and several of them (legacy privacy overrides,
    ``DEFENSECLAW_CODEX_LOOPBACK_TRUST``,
    ...) materially weaken security defaults. Without this check an
    operator has no way to spot a forgotten override left over from a
    debugging session.
    """
    try:
        active = active_security_overrides()
    except (FileNotFoundError, ValueError) as exc:
        # Registry load failure is a programmer error (malformed JSON,
        # missing file) — surface it loudly without bringing down the
        # rest of doctor.
        _emit("fail", "Security overrides", f"registry load failed: {exc}", r=r)
        return

    private_env_name = "DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS"
    active = [entry for entry in active if entry.name != private_env_name]
    configured = getattr(getattr(cfg, "guardrail", None), "allow_private_upstreams", [])
    config_entries = configured if isinstance(configured, (list, tuple)) else []
    env_entries = os.environ.get(private_env_name, "").split(",")
    private_entries: list[str] = []
    sources: list[str] = []
    for source, values in (("config.yaml", config_entries), ("environment", env_entries)):
        added_source = False
        for value in values:
            normalized = str(value).strip()
            if normalized and normalized not in private_entries:
                private_entries.append(normalized)
                added_source = True
        if added_source:
            sources.append(source)

    if not active and not private_entries:
        _emit("pass", "Security overrides", "none active", r=r)
        return

    if private_entries:
        detail = f"active entries: {', '.join(private_entries)} | impact=high | sources={', '.join(sources)}"
        _emit("warn", "Private upstream allowlist", detail, r=r)

    for entry in active:
        tag = _OVERRIDE_TAG_BY_IMPACT.get(entry.security_impact, "warn")
        # Detail format: "<name>: <purpose-headline> | impact=<level> | <security-note> | fix: <hint>"
        # Split on a true sentence boundary (period + whitespace + capital
        # letter) so that internal periods inside IP literals
        # ("100.64.0.0/10"), filenames (".aws/credentials"), and common
        # abbreviations ("e.g.", "i.e.", "etc.") don't truncate the headline
        # mid-thought.
        sentence_break = re.search(r"\.\s+(?=[A-Z])", entry.purpose)
        purpose_one_liner = (entry.purpose[: sentence_break.start()] if sentence_break else entry.purpose).strip()
        if len(purpose_one_liner) > 100:
            purpose_one_liner = purpose_one_liner[:97] + "..."
        bits = [purpose_one_liner, f"impact={entry.security_impact}"]
        if entry.security_note:
            note = entry.security_note
            if len(note) > 90:
                note = note[:87] + "..."
            bits.append(note)
        if entry.replacement_hint:
            # Truncated replacement hint; full text lives in the
            # auto-generated docs page.
            hint = entry.replacement_hint
            if len(hint) > 80:
                hint = hint[:77] + "..."
            bits.append(f"fix: {hint}")
        detail = f"{entry.name}: " + " | ".join(bits)
        _emit(tag, "Security override", detail, r=r)


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------


def _record_doctor_action(app: AppContext, cfg, r: _DoctorResult, mode: str) -> None:
    """Emit one canonical action fact unless the operator requested passivity."""

    if r.passive:
        return
    from requests import RequestException

    from defenseclaw.logger import CanonicalObservabilityError, Logger

    try:
        logger = app.logger
        if logger is None and _plan_canonical_config_preflight(cfg).state == "noop":
            # Main deliberately avoids Store.init() for Doctor so inspection
            # cannot create a missing database. The canonical recorder is lazy
            # and needs no Store, network, or secret lookup at construction.
            logger = Logger.from_config(cfg)
            app.logger = logger
        if logger is None:
            return
        logger.log_action(
            ACTION_DOCTOR,
            mode,
            " ".join(
                (
                    f"run_id={r.run_id}",
                    f"passed={r.passed}",
                    f"failed={r.failed}",
                    f"warned={r.warned}",
                    f"skipped={r.skipped}",
                    f"repairs_applied={r.repair_summary.applied}",
                    f"repairs_failed={r.repair_summary.failed}",
                    f"repairs_blocked={r.repair_summary.blocked}",
                )
            ),
        )
    except (CanonicalObservabilityError, RequestException):
        # Doctor commonly runs precisely because the local gateway is absent,
        # unauthorized, or unhealthy. The best-effort audit fact must never
        # replace the already-rendered health/repair result with a late crash.
        return


@click.command()
@click.option(
    "--json-output",
    "--json",
    "json_out",
    is_flag=True,
    help="Output the schema-v2 health and repair result as JSON",
)
@click.option(
    "--fix",
    "do_fix",
    is_flag=True,
    help=(
        "Plan and repair eligible issues (missing audit state, stale PID files, "
        "gateway token/lifecycle drift, dotenv perms). Identity and unsupported "
        "component/connector decisions remain explicit and attended. NOTE: "
        "gateway repair may START or RESTART the sidecar — preview with --dry-run."
    ),
)
@click.option("--yes", "assume_yes", is_flag=True, help="When used with --fix, apply fixes without prompting")
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    help=(
        "When used with --fix, list the fixers that would run without "
        "mutating anything on disk. Useful as a preview step before "
        "approving a real ``--fix --yes`` run from a TUI/CI wrapper."
    ),
)
@click.option(
    "--fix-id",
    "fix_ids",
    multiple=True,
    metavar="REPAIR_ID",
    help=(
        "Apply only the named repair and its declared dependencies (repeatable). "
        "Policy-changing or experimental repairs are never selected by a "
        "blanket --fix --yes."
    ),
)
@click.option(
    "--passive",
    is_flag=True,
    help=(
        "Skip probes that create synthetic telemetry, invoke an LLM, or submit "
        "inspection content. --fix --dry-run is always passive."
    ),
)
@pass_ctx
def doctor(
    app: AppContext,
    json_out: bool,
    do_fix: bool,
    assume_yes: bool,
    dry_run: bool,
    fix_ids: tuple[str, ...] = (),
    passive: bool = False,
) -> None:
    """Verify credentials, endpoints, and connectivity.

    Runs a series of checks against every configured service and API key
    to catch problems before they surface at runtime. On multi-connector
    installs it inventories and runs hook/health checks for every active
    connector (each row tagged ``[<connector>]``), not just the primary.
    For up to four enabled Galileo destinations it emits a content-free
    generated trace and requires an acknowledgement from that exact runtime
    route; additional enabled routes receive a bounded coverage warning.

    Use ``--fix`` to plan and auto-repair applicable issues (stale sidecar PID
    files, a safely absent audit database, missing gateway tokens, token-env
    drift, stopped/stale gateways, dotenv permissions, and pristine config
    backups). Gateway repair may **start or restart the gateway sidecar**,
    which briefly interrupts in-flight requests; preview the applicable set
    first with ``--fix --dry-run``. A missing device identity is a
    no-overwrite, custody-bound, explicitly selected attended recovery.
    Select policy-changing work by its exact ``--fix-id``; blanket ``--yes``
    never opts into it. Component release drift and unsupported/untested
    connector versions appear in the repair plan but remain attended
    upgrade/vendor decisions rather than blind unattended mutations.

    ``--passive`` suppresses probes that create telemetry, invoke an LLM, or
    submit inspection content; every dry-run is passive. Doctor no longer
    tears connectors down as part of ``--fix`` (it only *reports*
    inactive-connector residue); run ``defenseclaw-gateway connector teardown
    --connector <name>`` to remove a specific connector. Other destructive or
    ambiguous fixes still require the relevant setup command explicitly.

    Exit codes: 0 = no hard failure, 1 = a failed health check or a
    failed/dependency-blocked repair.
    """
    global _json_mode
    if dry_run and not do_fix:
        raise click.UsageError("--dry-run requires --fix")
    if assume_yes and not do_fix:
        raise click.UsageError("--yes requires --fix")
    if fix_ids and not do_fix:
        raise click.UsageError("--fix-id requires --fix")
    if json_out and do_fix and not dry_run and not assume_yes:
        raise click.UsageError("--json-output repair runs require --yes or --dry-run")

    cfg = app.cfg
    mode = "plan" if do_fix and dry_run else "repair" if do_fix else "check"
    r = _DoctorResult(mode=mode, passive=passive or dry_run)
    _json_mode = json_out

    if not json_out:
        ux.echo()
        ux.echo(ux._style("DefenseClaw Doctor", fg="cyan", bold=True))
        ux.echo(ux._style("══════════════════", fg="cyan"))
        ux.echo()

    startup_diagnostics = getattr(app, "doctor_startup_diagnostics", None)
    if startup_diagnostics is not None:
        r.set_section("configuration")
        if not json_out:
            _doctor_subsection("Configuration")
        for check in startup_diagnostics.checks:
            _emit(check.status, check.label, check.detail, r=r)
        if not (do_fix and dry_run):
            _write_doctor_cache(cfg, r)
        if json_out:
            click.echo(json.dumps(r.to_dict(), indent=2))
        else:
            _doctor_subsection("Summary")
            parts = []
            if r.passed:
                parts.append(ux._style(f"{r.passed} passed", fg="green", bold=True))
            if r.failed:
                parts.append(ux._style(f"{r.failed} failed", fg="red", bold=True))
            if r.warned:
                parts.append(ux._style(f"{r.warned} warnings", fg="yellow", bold=True))
            ux.echo("  " + ", ".join(parts))
            ux.echo()
            ux.warn(startup_diagnostics.remediation, indent="  ")
            ux.echo()
        raise SystemExit(1)

    # Repair first, then diagnose the resulting state.  The former ordering
    # ran fixers after every check, leaving already-repaired failures in the
    # result and forcing a misleading exit 1 until the operator ran Doctor a
    # second time.
    if do_fix:
        r.set_section("repairs")
        if not json_out:
            _doctor_subsection("Auto-fix" + (" (dry-run)" if dry_run else ""))
            _emit_hint(_auto_fix_hint(dry_run))
        _run_fixers_with_lock(
            cfg,
            r,
            assume_yes=assume_yes,
            json_out=json_out,
            dry_run=dry_run,
            fix_ids=fix_ids,
        )

    r.set_section("configuration")
    _check_config(cfg, r)
    _check_audit_db(cfg, r)
    _check_device_identity(cfg, r)

    # S6.5 — surface the active connector + its configured paths
    # before any scanner runs. Operators routinely point doctor at a
    # config that *thinks* it's running on (say) Codex but actually
    # has stale openclaw.json paths under .openclaw/extensions; a
    # per-connector inventory pass catches that drift.
    if not json_out:
        _doctor_subsection("Connectors")
    r.set_section("connectors")
    active_connector = _active_connector(cfg)
    # Inventory EVERY active connector uniformly — there is no separate
    # "single" vs "multi" rendering. ``_doctor_active_connectors`` returns one
    # name on a single-connector install and N on a fan-out install, so the
    # same loop covers both: each connector gets its own block tagged
    # "[<connector>]" carrying its paths, effective policy, rule pack, and
    # hook contract. On a genuinely unconfigured install it returns ``[]`` and
    # we render an explicit empty state instead of fabricating a phantom
    # "openclaw" row (D3) — the operator should read "nothing is set up", not a
    # never-configured OpenClaw install reported as broken.
    inventory_connectors = _doctor_active_connectors(cfg)
    _check_component_connector_compatibility(cfg, inventory_connectors, r)
    if not inventory_connectors:
        _emit(
            "skip",
            "Connectors",
            "no connector configured — run 'defenseclaw setup <connector>'",
            r=r,
        )
    for _c in inventory_connectors:
        if not _connector_enabled(cfg, _c):
            # Operator-disabled (guardrail disable --connector X): the Go boot
            # loop drops it from the active set and tears its hooks down, so
            # the inventory/contract probes below would read as active and the
            # missing hook artifacts would FAIL spuriously. Surface it once,
            # explicitly disabled, and skip the active-enforcement checks
            # (mirrors cmd_status's DISABLED row). (N1)
            with _doctor_label_suffix(f"[{_c}]"):
                _emit(
                    "skip",
                    "Connector",
                    f"{_CONNECTOR_LABELS.get(_c, _c)} — operator-disabled "
                    f"(guardrail disable --connector {_c}); hooks torn down",
                    r=r,
                )
            continue
        with _doctor_label_suffix(f"[{_c}]"):
            _check_connector_inventory(cfg, _c, r)
            _check_hook_contract_lock(cfg, _c, r)
    # S7.5 — surface inactive-connector residue (backup files / hook
    # scripts left over from a previous connector). Without this check
    # operators who switch connectors via 'defenseclaw setup guardrail
    # --agent <new>' get a silent half-state where the old adapter's
    # config patches are still on disk. This is a global filesystem sweep
    # (not per-active-connector), so it runs once against the install.
    _check_connector_residue(cfg, active_connector, r)
    # Surface a dead-end asset_policy.plugin.registry_required flag, which can
    # only ever deny (no plugin-registry pipeline exists in v1) and silently
    # blocks all plugins under enforcement. (OTHER-5)
    _check_plugin_registry_required(cfg, r)

    if not json_out:
        _doctor_subsection("Scanners")
    r.set_section("scanners")
    _check_scanners(cfg, r)
    _check_scan_coverage(cfg, r)

    if not json_out:
        _doctor_subsection("Services")
    r.set_section("services")
    sidecar_health = _check_sidecar(cfg, r)
    _check_gateway_token_env_alignment(cfg, r)
    if not _check_windows_gateway_diagnostics(cfg, r):
        # Preserve the established Linux/macOS evidence collectors. Windows
        # uses the native/injectable path above because os.kill(pid, 0), lsof,
        # /proc, and ps are not reliable evidence there.
        auth_attempted = _check_gateway_auth(cfg, r)
        if not auth_attempted:
            _check_gateway_token_drift(cfg, r)
        _check_gateway_home_mismatch(cfg, r)
    # Run the per-connector hook/health check for EVERY active connector,
    # not just the primary. ``_doctor_active_connectors`` returns the single
    # active connector on single-connector installs (no label suffix applied,
    # so their Services output is unchanged), N on a fan-out install (each row
    # tagged "[<connector>]" so the codex/claudecode/antigravity rows are
    # individually attributable), and ``[]`` when nothing is configured — in
    # which case the loop emits no hook rows rather than probing a phantom
    # "openclaw" gateway (D3).
    hook_connectors = _doctor_active_connectors(cfg)
    # Single-vs-multi label suffix is decided over the ENABLED set: an
    # operator-disabled connector is reported separately (below) and must not
    # flip a genuinely single-connector install into multi-connector "[name]"
    # labeling. (N1)
    _enabled_hook_connectors = [c for c in hook_connectors if _connector_enabled(cfg, c)]
    _multi_hooks = len(_enabled_hook_connectors) > 1
    for _conn in hook_connectors:
        if not _connector_enabled(cfg, _conn):
            # Disabled connector: hooks were torn down, so probing hook health
            # / HILT would FAIL spuriously. Mark it disabled and move on,
            # mirroring the inventory loop and cmd_status. (N1)
            with _doctor_label_suffix(f"[{_conn}]"):
                _emit(
                    "skip",
                    "Connector hooks",
                    f"{_CONNECTOR_LABELS.get(_conn, _conn)} — operator-disabled; hooks torn down",
                    r=r,
                )
            continue
        with _doctor_label_suffix(f"[{_conn}]" if _multi_hooks else ""):
            _check_connector_hooks(cfg, _conn, r)
            # Human-approval (HILT) support is per-connector: each connector
            # has a different native ask surface AND may carry its own hilt
            # override, so run it for EVERY active connector (tagged like the
            # hook rows) instead of only the primary.
            _check_hilt_support(cfg, _conn, r)
    _check_guardrail_proxy(cfg, r)
    if not json_out:
        _doctor_subsection("Credentials")
    r.set_section("credentials")
    _check_llm_api_key(cfg, r)
    _check_llm_reachable(cfg, r)
    _check_regional_provider_config(cfg, r)
    _check_custom_provider_overlay(cfg, r)
    _check_cisco_ai_defense(cfg, r)
    _check_virustotal(cfg, r)
    _check_registry_credentials(cfg, r)
    if not json_out:
        _doctor_subsection("Observability")
    r.set_section("observability")
    _check_observability(cfg, r, live_health=sidecar_health)
    if not json_out:
        _doctor_subsection("Webhooks")
    r.set_section("webhooks")
    _check_webhooks(cfg, r)

    # Surface any DEFENSECLAW_* env-var bypass that's currently active.
    # The registry at internal/envvars/registry.json is the single
    # source of truth; operators with no overrides set see a single
    # PASS row here.
    if not json_out:
        _doctor_subsection("Security Overrides")
    r.set_section("security-overrides")
    _check_security_overrides(cfg, r)

    # Persist the cached snapshot before exit so the Textual TUI (and any
    # other cron-style caller) can pick it up without re-probing. We
    # do this *before* the SystemExit(1) below so failing runs still
    # update the cache — the TUI needs to see "doctor last reported
    # 2 failures", not a stale green state from yesterday.
    if not (do_fix and dry_run):
        _write_doctor_cache(cfg, r)

    if json_out:
        click.echo(json.dumps(r.to_dict(), indent=2))
    else:
        _doctor_subsection("Summary")
        parts = []
        if r.passed:
            parts.append(ux._style(f"{r.passed} passed", fg="green", bold=True))
        if r.failed:
            parts.append(ux._style(f"{r.failed} failed", fg="red", bold=True))
        if r.warned:
            parts.append(ux._style(f"{r.warned} warnings", fg="yellow", bold=True))
        if r.skipped:
            parts.append(ux._style(f"{r.skipped} skipped", fg="bright_black"))
        ux.echo("  Health: " + ", ".join(parts))
        if do_fix:
            repair_parts = []
            for state, count in r.repair_summary.to_dict().items():
                if count:
                    repair_parts.append(f"{count} {state.replace('_', ' ')}")
            ux.echo("  Repairs: " + (", ".join(repair_parts) if repair_parts else "none selected"))
        ux.echo()

    repair_failed = bool(r.repair_summary.failed or r.repair_summary.blocked)
    _record_doctor_action(app, cfg, r, mode)

    if r.failed or repair_failed:
        if not json_out:
            # Surface the remediation hint in yellow — it's the
            # primary call-to-action when doctor fails. We use
            # ``ux.warn`` rather than ``ux.err`` because the line
            # itself isn't a failure; the failures above are.
            ux.warn("Fix the failures above, then re-run: defenseclaw doctor", indent="  ")
            ux.echo()
        raise SystemExit(1)


# Note: earlier revisions exposed a ``run_doctor_checks(cfg)`` helper
# that bundled a subset of checks for ``setup --verify``. It was never
# wired up — ``cmd_setup.py`` calls each ``_check_*`` directly — and the
# helper also wrote a partial cache that would clobber a full-coverage
# ``doctor_cache.json``. It has been removed to prevent the Overview
# panel from silently reporting "3 pass" after a partial verify.


# ---------------------------------------------------------------------------
# Registry-driven credentials check
# ---------------------------------------------------------------------------


def _check_registry_credentials(cfg, r: _DoctorResult) -> None:
    """Report any REQUIRED credential the current config needs but is unset.

    The per-feature ``_check_*`` helpers above do *connectivity* checks
    against specific APIs (Cisco AI Defense, VirusTotal, etc.). This
    extra pass is a belt-and-braces sweep using the credentials
    registry: any REQUIRED entry that isn't set is flagged here so new
    features automatically get coverage the moment they're added to
    ``defenseclaw.credentials.CREDENTIALS``.
    """
    from defenseclaw.credentials import Requirement, classify

    for status in classify(cfg):
        if status.requirement is Requirement.REQUIRED and not status.resolution.is_set:
            _emit(
                "fail",
                f"credential {status.resolution.env_name}",
                detail=f"required by {status.spec.feature} — "
                f"set with 'defenseclaw keys set {status.resolution.env_name}'",
                r=r,
            )


# ---------------------------------------------------------------------------
# --fix auto-repair
# ---------------------------------------------------------------------------

_AUTO_FIX_DRY_RUN_HINT = (
    "dry-run: previewing fixers; nothing on disk changes. A real --fix --yes "
    "may start or restart the gateway sidecar; doctor never runs "
    "connector teardown."
)

_AUTO_FIX_REAL_HINT = (
    "blast radius: gateway repair may START or RESTART the sidecar "
    "(a restart interrupts in-flight requests); teardown is never run. Re-run with "
    "--dry-run to preview without mutating."
)


def _auto_fix_hint(dry_run: bool) -> str:
    return _AUTO_FIX_DRY_RUN_HINT if dry_run else _AUTO_FIX_REAL_HINT


def _fixer_blocker(cfg, title: str, dotenv_safety_problem: str) -> str:
    """Return why a dotenv-dependent fixer must not run, or an empty string."""
    dotenv_dependent_fixers = {
        "gateway token",
        "gateway token_env",
        "gateway token drift",
        "gateway service",
    }
    if title not in dotenv_dependent_fixers:
        return ""

    rotation_required = bool(getattr(cfg, "_doctor_gateway_token_rotation_required", False))
    token_rotated = bool(getattr(cfg, "_doctor_gateway_token_was_rotated", False))
    if title == "gateway token":
        return dotenv_safety_problem if dotenv_safety_problem and not rotation_required else ""

    provider_not_converged = token_rotated and not _gateway_rotated_provider_converged(cfg)
    should_block = (
        bool(dotenv_safety_problem)
        or (rotation_required and not token_rotated)
        or (title in {"gateway token drift", "gateway service"} and provider_not_converged)
    )
    if not should_block:
        return ""
    if title in {"gateway token drift", "gateway service"} and provider_not_converged:
        return "gateway.token_env did not converge on the rotated canonical provider"
    if rotation_required and not token_rotated:
        return "required gateway token rotation did not complete"
    return dotenv_safety_problem


def _plan_existing_fixer(
    fixer,
    cfg,
    *,
    effects: tuple[str, ...],
) -> RepairDecision:
    """Run the read-only branch of one legacy fixer."""

    try:
        tag, detail = fixer(cfg, assume_yes=True, plan_only=True)
    except Exception as exc:  # noqa: BLE001 - redact arbitrary exception text.
        return RepairDecision(
            "blocked",
            f"{type(exc).__name__}: planner raised unexpectedly",
            effects=effects,
        )
    if tag == "plan":
        state_key = ""
        if fixer is _fix_gateway_token:
            if _CANONICAL_GATEWAY_TOKEN_ENV in detail:
                state_key = "gateway-token-canonical-present"
            elif _LEGACY_GATEWAY_TOKEN_ENV in detail:
                state_key = "gateway-token-legacy-present"
        return RepairDecision(
            "applicable",
            detail,
            effects=effects,
            state_key=state_key,
        )
    if tag == "fail":
        return RepairDecision("blocked", detail, effects=effects, blockers=(detail,))
    if tag == "warn":
        return RepairDecision("blocked", detail, effects=effects, blockers=(detail,))
    manual_markers = (
        "externally managed",
        "run `",
        "run '",
        "no backup strategy",
        "no backup found",
        "review ",
    )
    if any(marker in detail.casefold() for marker in manual_markers):
        return RepairDecision("manual", detail, effects=effects)
    return RepairDecision("noop", detail, effects=effects)


def _recovery_gateway_blocker(cfg) -> str:
    """Require positive evidence that local state is not in active use."""

    projected_repairs = set(getattr(cfg, "_doctor_projected_repair_ids", ()))
    if "doctor.gateway.pid.remove-stale" in projected_repairs:
        # Dry-run planners do not mutate the PID file. A preceding applicable
        # stale-PID plan has already proven that record removable and the
        # endpoint absent, so model only that bounded effect while rechecking
        # listener inactivity. This lets the dependent recovery produce one
        # coherent plan without weakening the real apply-time proof.
        listener = _verified_listener_gateway_evidence(cfg)
        if listener.status == "missing":
            return ""
        if listener.status == "ok":
            return "the verified managed gateway is running; stop it before recovering durable state"
        return "configured gateway endpoint inactivity could not be proven" + (
            f" ({listener.reason})" if listener.reason else ""
        )

    process = _managed_gateway_process_trust(cfg)
    if process.trusted:
        return "the verified managed gateway process is running; stop it before recovering durable state"
    if process.code not in {"missing", "missing_process"}:
        return "managed gateway process inactivity could not be proven" + (
            f" ({process.detail})" if process.detail else ""
        )

    listener = _verified_listener_gateway_evidence(cfg)
    if listener.status == "missing":
        return ""
    if listener.status == "ok":
        return "the verified managed gateway is running; stop it before recovering durable state"
    return "configured gateway endpoint inactivity could not be proven" + (
        f" ({listener.reason})" if listener.reason else ""
    )


def _plan_audit_db_recovery(cfg) -> RepairDecision:
    from defenseclaw.doctor_recovery import (
        AuditDBHealthStatus,
        RecoveryDisposition,
        inspect_audit_db,
        plan_missing_audit_db,
    )

    target = str(getattr(cfg, "audit_db", "") or "")
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    effects = ("initialize a verified empty audit schema without replacing an existing name",)
    if not _doctor_config_present(cfg):
        reason = "config.yaml is missing; refusing to create durable audit state"
        return RepairDecision("blocked", reason, effects=effects, blockers=(reason,))
    health = inspect_audit_db(target, data_dir=data_dir)
    if health.status is AuditDBHealthStatus.VALID:
        return RepairDecision(
            "noop",
            "audit database passed private-custody, integrity, and schema checks",
            effects=effects,
        )
    if health.status is AuditDBHealthStatus.INVALID:
        remediation = (
            "run `defenseclaw migrations apply` after a trusted backup review"
            if health.reason_code == "audit-db-schema-incomplete"
            else "restore the audit database from a trusted backup"
        )
        detail = (
            f"existing audit database is not safe to use ({health.reason_code}); "
            f"{remediation}; Doctor will not replace it"
        )
        return RepairDecision(
            "blocked",
            detail,
            effects=effects,
            blockers=(health.reason_code,),
        )

    plan = plan_missing_audit_db(target, data_dir=data_dir)
    if plan.disposition is RecoveryDisposition.BLOCKED:
        return RepairDecision(
            "blocked",
            f"audit database recovery refused: {plan.reason_code}",
            effects=effects,
            blockers=(plan.reason_code,),
        )
    if blocker := _recovery_gateway_blocker(cfg):
        return RepairDecision("blocked", blocker, effects=effects, blockers=(blocker,))
    return RepairDecision(
        "applicable",
        f"create {target} with the current audit schema using no-overwrite publication",
        effects=effects,
    )


def _fix_audit_db_recovery(cfg, *, assume_yes: bool) -> tuple[str, str]:
    from defenseclaw.doctor_recovery import (
        AuditDBHealthStatus,
        RecoveryApplyStatus,
        RecoveryRefusedError,
        apply_audit_db_recovery,
        inspect_audit_db,
        plan_missing_audit_db,
    )

    target = str(getattr(cfg, "audit_db", "") or "")
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    if not _doctor_config_present(cfg):
        return ("fail", "config.yaml is missing; refusing to create durable audit state")
    health = inspect_audit_db(target, data_dir=data_dir)
    if health.status is AuditDBHealthStatus.VALID:
        return ("skip", "audit database already passed integrity and schema checks")
    if health.status is AuditDBHealthStatus.INVALID:
        return (
            "fail",
            f"existing audit database is invalid ({health.reason_code}); refusing to replace it",
        )
    if blocker := _recovery_gateway_blocker(cfg):
        return ("fail", blocker)
    plan = plan_missing_audit_db(target, data_dir=data_dir)
    if not assume_yes and not click.confirm(
        f"    Initialize the missing audit database at {target}?",
        default=True,
    ):
        return ("skip", "declined by user")
    try:
        result = apply_audit_db_recovery(
            plan,
            approved=True,
            unattended=assume_yes,
        )
    except RecoveryRefusedError as exc:
        return ("fail", f"audit database recovery refused: {exc.code}")
    if result.status is RecoveryApplyStatus.CREATED:
        return ("pass", f"created and verified the audit database at {target}")
    return ("fail", f"audit database recovery failed: {result.reason_code}")


def _plan_device_key_recovery(cfg) -> RepairDecision:
    from defenseclaw.doctor_recovery import (
        DeviceKeyHealthStatus,
        RecoveryDisposition,
        inspect_device_key,
        plan_missing_device_key,
    )

    gateway = getattr(cfg, "gateway", None)
    target = str(getattr(gateway, "device_key_file", "") or "")
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    effects = (
        "mint a new Ed25519 device identity",
        "publish HMAC-bound provenance before making the key visible",
    )
    if not _doctor_config_present(cfg):
        reason = "config.yaml is missing; refusing to mint durable device identity state"
        return RepairDecision("blocked", reason, effects=effects, blockers=(reason,))
    health = inspect_device_key(target, data_dir=data_dir)
    if health.status is DeviceKeyHealthStatus.VALID:
        return RepairDecision(
            "noop",
            "device identity passed private-custody, payload, and provenance checks",
            effects=effects,
        )
    if health.status is DeviceKeyHealthStatus.LEGACY_UNPROVENANCED:
        return RepairDecision(
            "noop",
            f"existing device identity is structurally valid but uses legacy provenance "
            f"({health.reason_code}); continuity is preserved and Doctor will not replace it",
            effects=effects,
        )
    if health.status is DeviceKeyHealthStatus.INVALID:
        detail = (
            f"existing device identity is invalid ({health.reason_code}); restore the "
            "identity from a trusted backup or re-pair it explicitly; Doctor will not replace it"
        )
        return RepairDecision(
            "blocked",
            detail,
            effects=effects,
            blockers=(health.reason_code,),
        )

    plan = plan_missing_device_key(target, data_dir=data_dir)
    if plan.disposition is RecoveryDisposition.BLOCKED:
        return RepairDecision(
            "blocked",
            f"device identity recovery refused: {plan.reason_code}",
            effects=effects,
            blockers=(plan.reason_code,),
        )
    if blocker := _recovery_gateway_blocker(cfg):
        return RepairDecision("blocked", blocker, effects=effects, blockers=(blocker,))
    return RepairDecision(
        "requires_confirmation",
        "mint a new device identity only after an attended continuity review",
        effects=effects,
    )


def _fix_device_key_recovery(cfg, *, assume_yes: bool) -> tuple[str, str]:
    from defenseclaw.doctor_recovery import (
        DeviceKeyHealthStatus,
        RecoveryApplyStatus,
        RecoveryRefusedError,
        apply_device_key_recovery,
        inspect_device_key,
        plan_missing_device_key,
    )

    # The declarative engine deliberately passes assume_yes=False for
    # experimental repairs.  Keep this defense in depth in case another caller
    # reaches the adapter directly.
    if assume_yes:
        return (
            "warn",
            "device identity recovery requires an attended confirmation; blanket --yes was ignored",
        )
    gateway = getattr(cfg, "gateway", None)
    target = str(getattr(gateway, "device_key_file", "") or "")
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    if not _doctor_config_present(cfg):
        return ("fail", "config.yaml is missing; refusing to mint durable device identity state")
    health = inspect_device_key(target, data_dir=data_dir)
    if health.status in {
        DeviceKeyHealthStatus.VALID,
        DeviceKeyHealthStatus.LEGACY_UNPROVENANCED,
    }:
        return ("skip", "existing device identity is valid and will be preserved")
    if health.status is DeviceKeyHealthStatus.INVALID:
        return (
            "fail",
            f"existing device identity is invalid ({health.reason_code}); refusing to replace it",
        )
    if blocker := _recovery_gateway_blocker(cfg):
        return ("fail", blocker)
    plan = plan_missing_device_key(target, data_dir=data_dir)
    if not click.confirm(
        "    Mint a NEW device identity? Existing pairings tied to a prior key will not be recoverable.",
        default=False,
    ):
        return ("skip", "declined by user")
    try:
        result = apply_device_key_recovery(plan, approved=True, unattended=False)
    except RecoveryRefusedError as exc:
        return ("fail", f"device identity recovery refused: {exc.code}")
    if result.status is RecoveryApplyStatus.CREATED:
        return ("pass", f"created a provenance-bound device identity at {target}")
    return ("fail", f"device identity recovery failed: {result.reason_code}")


def _connector_compatibility_problems(cfg) -> tuple[object, ...]:
    """Return current unsupported/untested connector findings."""

    from defenseclaw.doctor_health import (
        HealthStatus,
        assess_connector_health,
        read_cached_discovery,
    )

    connectors = tuple(connector for connector in _doctor_active_connectors(cfg) if _connector_enabled(cfg, connector))
    if not connectors:
        return ()
    discovery = read_cached_discovery(str(getattr(cfg, "data_dir", "") or ""))
    findings = assess_connector_health(connectors, discovery)
    return tuple(finding for finding in findings if finding.status is not HealthStatus.SUPPORTED)


def _plan_connector_compatibility_review(cfg) -> RepairDecision:
    """Offer an attended evidence refresh, never an unsupported install."""

    from defenseclaw.doctor_health import RemediationKind

    try:
        problems = _connector_compatibility_problems(cfg)
    except Exception as exc:  # noqa: BLE001 - never render cache/probe output.
        return RepairDecision(
            "manual",
            f"{type(exc).__name__}: connector compatibility evidence is unavailable; "
            "rerun bounded discovery before making a version decision",
            effects=("refresh bounded local agent version evidence without emitting telemetry",),
        )
    if not problems:
        return RepairDecision("noop", "active connector versions match registered contracts")
    summary = ", ".join(f"{finding.connector}={finding.status.value}/{finding.reason_code}" for finding in problems)
    refresh_argv = (
        "defenseclaw",
        "agent",
        "discover",
        "--refresh",
        "--no-emit-otel",
    )
    has_bounded_refresh = any(
        choice.kind is RemediationKind.COMMAND and choice.argv == refresh_argv
        for finding in problems
        for choice in finding.remediations
    )
    if has_bounded_refresh:
        return RepairDecision(
            "requires_confirmation",
            "unsupported or untested connector evidence can be refreshed with "
            "attended approval; Doctor will run only bounded version discovery, "
            f"not install or launch connector workloads ({summary})",
            effects=("refresh bounded local agent version evidence without emitting telemetry",),
        )
    return RepairDecision(
        "manual",
        "unsupported or untested external connector versions require an "
        f"attended vendor/setup decision ({summary}); Doctor will not execute them",
        effects=("review vendor version changes and rerun connector setup interactively",),
    )


def _plan_connector_compatibility_gate(cfg) -> RepairDecision:
    """Block lifecycle only on positive unsupported connector evidence."""

    from defenseclaw.doctor_health import HealthStatus

    try:
        problems = _connector_compatibility_problems(cfg)
    except Exception as exc:  # noqa: BLE001 - never render cache/probe output.
        return RepairDecision(
            "noop",
            f"{type(exc).__name__}: connector compatibility evidence is unavailable; "
            "no unsupported version decision was inferred",
        )
    unsupported = tuple(
        finding
        for finding in problems
        if finding.status is HealthStatus.UNSUPPORTED
    )
    if unsupported:
        summary = ", ".join(
            f"{finding.connector}={finding.reason_code}"
            for finding in unsupported
        )
        return RepairDecision(
            "manual",
            "gateway lifecycle repair is blocked by positively unsupported "
            f"connector compatibility evidence ({summary})",
            blockers=("unsupported connector compatibility",),
        )
    if problems:
        return RepairDecision(
            "noop",
            "connector version evidence is unavailable or untested, but no "
            "positively unsupported version was observed; the separate "
            "compatibility review remains available",
        )
    return RepairDecision("noop", "no unsupported active connector version was observed")


def _fix_connector_compatibility_review(cfg, *, assume_yes: bool) -> tuple[str, str]:
    from defenseclaw.doctor_health import (
        RemediationAuthorizationError,
        RemediationKind,
        authorize_remediation,
    )

    if assume_yes:
        return (
            "warn",
            "connector compatibility review requires attended approval; blanket --yes was ignored",
        )
    problems = _connector_compatibility_problems(cfg)
    if not problems:
        return ("skip", "connector compatibility already matches registered contracts")
    refresh_argv = (
        "defenseclaw",
        "agent",
        "discover",
        "--refresh",
        "--no-emit-otel",
    )
    refresh_choice = next(
        (
            choice
            for finding in problems
            for choice in finding.remediations
            if choice.kind is RemediationKind.COMMAND and choice.argv == refresh_argv
        ),
        None,
    )
    if refresh_choice is None:
        return (
            "skip",
            "manual connector vendor/setup decision required; Doctor has no bounded executable remediation",
        )
    if not click.confirm(
        "    Refresh connector version evidence now? This runs version discovery "
        "only; it will not install, upgrade, downgrade, or launch connector workloads.",
        default=False,
    ):
        return ("skip", "declined by user")
    try:
        argv = authorize_remediation(
            refresh_choice,
            confirmed=True,
            unattended=False,
        )
    except RemediationAuthorizationError as exc:
        return ("fail", f"connector evidence refresh authorization failed: {exc.code}")
    if argv != refresh_argv:
        return ("fail", "connector evidence refresh resolved an unexpected command")
    try:
        from defenseclaw.inventory import agent_discovery

        agent_discovery.discover_agents(
            use_cache=False,
            refresh=True,
            data_dir=str(getattr(cfg, "data_dir", "") or ""),
        )
    except Exception as exc:  # noqa: BLE001 - do not render probe output.
        return (
            "fail",
            f"{type(exc).__name__}: bounded connector version discovery failed; no version change was attempted",
        )
    remaining = _connector_compatibility_problems(cfg)
    if not remaining:
        return ("pass", "refreshed version evidence now matches registered connector contracts")
    summary = ", ".join(f"{finding.connector}={finding.status.value}/{finding.reason_code}" for finding in remaining)
    return (
        "skip",
        "manual connector vendor/setup decision remains after attended evidence "
        f"refresh ({summary}); no version change was attempted",
    )


def _component_compatibility_problems(cfg) -> tuple[object, ...]:
    selection = _gateway_lifecycle_selection(cfg)
    return _component_compatibility_problems_for_executable(
        cfg,
        selection.executable,
    )


def _component_compatibility_problems_for_executable(
    cfg,
    gateway_executable: str | None,
) -> tuple[object, ...]:
    from defenseclaw.doctor_health import (
        HealthStatus,
        assess_component_health,
    )

    required = {"cli", "gateway"}
    enabled_connectors = {
        connector for connector in _doctor_active_connectors(cfg) if _connector_enabled(cfg, connector)
    }
    if "openclaw" in enabled_connectors:
        required.add("plugin")
    findings = assess_component_health(
        _doctor_component_evidence_for_executable(gateway_executable)
    )

    return tuple(
        finding
        for finding in findings
        if finding.component in required and finding.status is not HealthStatus.SUPPORTED
    )


def _doctor_component_evidence(cfg) -> tuple[object, ...]:
    """Probe component versions through Doctor's exact lifecycle selection."""
    selection = _gateway_lifecycle_selection(cfg)
    return _doctor_component_evidence_for_executable(selection.executable)


def _doctor_component_evidence_for_executable(
    gateway_executable: str | None,
) -> tuple[object, ...]:
    """Probe component versions with one already-selected gateway controller."""
    from defenseclaw.doctor_health import probe_component_evidence

    return probe_component_evidence(gateway_executable=gateway_executable)


def _plan_component_compatibility_review(cfg) -> RepairDecision:
    """Expose component drift to ``--fix`` without launching an upgrade."""

    try:
        problems = _component_compatibility_problems(cfg)
    except Exception as exc:  # noqa: BLE001 - never render probe output.
        return RepairDecision(
            "manual",
            f"{type(exc).__name__}: component compatibility evidence is unavailable",
            effects=("review the bounded component version report before changing releases",),
        )

    if not problems:
        return RepairDecision("noop", "required DefenseClaw components use one supported release")

    details: list[str] = []
    for finding in problems:
        remediation = _health_remediation_text(finding.remediations)
        item = f"{finding.component}={finding.status.value}/{finding.reason_code}"
        if remediation:
            item += f" (review: {remediation})"
        details.append(item)
    return RepairDecision(
        "manual",
        "component release drift requires an attended upgrade/reinstall decision; "
        "Doctor will not launch an upgrade from inside a repair transaction "
        f"({'; '.join(details)})",
        effects=("review authenticated DefenseClaw upgrade or trusted component reinstall",),
    )


def _plan_component_compatibility_gate(cfg) -> RepairDecision:
    """Block lifecycle only on positive component release mismatch."""

    from defenseclaw.doctor_health import HealthStatus

    try:
        problems = _component_compatibility_problems(cfg)
    except Exception as exc:  # noqa: BLE001 - never render probe output.
        return RepairDecision(
            "noop",
            f"{type(exc).__name__}: component compatibility evidence is unavailable; "
            "no unsupported release decision was inferred",
        )
    unsupported = tuple(
        finding
        for finding in problems
        if finding.status is HealthStatus.UNSUPPORTED
    )
    if unsupported:
        summary = ", ".join(
            f"{finding.component}={finding.reason_code}"
            for finding in unsupported
        )
        return RepairDecision(
            "manual",
            "gateway lifecycle repair is blocked by positively unsupported "
            f"component compatibility evidence ({summary})",
            blockers=("unsupported component compatibility",),
        )
    if problems:
        return RepairDecision(
            "noop",
            "component version evidence is unavailable or untested, but no "
            "positive release mismatch was observed; the separate compatibility "
            "review remains available",
        )
    return RepairDecision("noop", "no unsupported required component release was observed")


def _fix_compatibility_gate(cfg, *, assume_yes: bool) -> tuple[str, str]:
    del cfg, assume_yes
    return ("skip", "compatibility safety gate already converged")


def _fix_component_compatibility_review(cfg, *, assume_yes: bool) -> tuple[str, str]:
    del cfg, assume_yes
    return (
        "warn",
        "component release changes require an attended upgrade or trusted reinstall",
    )


def _doctor_repair_specs() -> tuple[RepairSpec, ...]:
    """Return the ordered declarative repair graph.

    The order remains compatible with the credential A/B transaction while
    dependencies are now visible to JSON/TUI consumers instead of existing
    only as title-string control flow.
    """

    definitions = (
        (
            "doctor.credentials.dotenv.protect",
            "defenseclaw dotenv perms",
            "safe",
            _fix_dotenv_perms,
            (),
            ("enforce owner-only credential-file custody",),
            False,
            False,
        ),
        (
            "doctor.gateway.token.ensure",
            "gateway token",
            "disruptive",
            _fix_gateway_token,
            ("doctor.credentials.dotenv.protect",),
            (
                "create or rotate the locally managed gateway token",
                "repoint a supported legacy token provider in config.yaml when exposure rotation requires it",
            ),
            True,
            False,
        ),
        (
            "doctor.gateway.token-env.canonicalize",
            "gateway token_env",
            "safe",
            _fix_gateway_token_env,
            ("doctor.gateway.token.ensure",),
            ("save the canonical gateway token provider in config.yaml",),
            False,
            False,
        ),
        (
            "doctor.gateway.token.reconcile-runtime",
            "gateway token drift",
            "disruptive",
            _fix_gateway_token_drift,
            (
                "doctor.state.audit-db.initialize",
                "doctor.identity.device-key.initialize",
                "doctor.gateway.token.ensure",
                "doctor.gateway.token-env.canonicalize",
                "doctor.component.compatibility.gate",
                "doctor.connector.compatibility.gate",
            ),
            ("restart a verified gateway generation and authenticate its replacement",),
            True,
            False,
        ),
        (
            "doctor.gateway.service.reconcile",
            "gateway service",
            "disruptive",
            _fix_gateway_service,
            (
                "doctor.state.audit-db.initialize",
                "doctor.identity.device-key.initialize",
                "doctor.gateway.pid.remove-stale",
                "doctor.gateway.token.ensure",
                "doctor.gateway.token-env.canonicalize",
                "doctor.gateway.token.reconcile-runtime",
                "doctor.component.compatibility.gate",
                "doctor.connector.compatibility.gate",
            ),
            ("start or restart the verified managed gateway",),
            True,
            False,
        ),
        (
            "doctor.connector.backup.capture",
            "pristine config backup",
            "safe",
            _fix_pristine_backup,
            (),
            ("capture a restorable connector configuration baseline",),
            False,
            False,
        ),
        (
            "doctor.policy.plugin-registry.clear-dead-end",
            "plugin registry dead-end",
            "policy",
            _fix_plugin_registry_required,
            (),
            ("change explicit plugin admission policy in config.yaml",),
            False,
            True,
        ),
    )
    specs: list[RepairSpec] = [
        RepairSpec(
            repair_id=_CONFIG_PREFLIGHT_REPAIR_ID,
            label="canonical configuration preflight",
            risk="safe",
            plan=_plan_canonical_config_preflight,
            apply=_fix_canonical_config_preflight,
            effects=(),
        ),
        RepairSpec(
            repair_id="doctor.gateway.pid.remove-stale",
            label="stale gateway PID file",
            risk="safe",
            plan=lambda cfg: _plan_existing_fixer(
                _fix_stale_pid,
                cfg,
                effects=("remove positively stale same-install PID state",),
            ),
            apply=_fix_stale_pid,
            dependencies=(_CONFIG_PREFLIGHT_REPAIR_ID,),
            effects=("remove positively stale same-install PID state",),
        ),
        RepairSpec(
            repair_id="doctor.state.audit-db.initialize",
            label="missing audit database",
            risk="safe",
            plan=_plan_audit_db_recovery,
            apply=_fix_audit_db_recovery,
            verify=lambda cfg: default_repair_verifier(_plan_audit_db_recovery, cfg),
            dependencies=(
                _CONFIG_PREFLIGHT_REPAIR_ID,
                "doctor.gateway.pid.remove-stale",
            ),
            effects=("initialize a verified empty audit schema without replacing an existing name",),
        ),
        RepairSpec(
            repair_id="doctor.identity.device-key.initialize",
            label="missing device identity",
            risk="experimental",
            plan=_plan_device_key_recovery,
            apply=_fix_device_key_recovery,
            verify=lambda cfg: default_repair_verifier(_plan_device_key_recovery, cfg),
            effects=(
                "mint a new Ed25519 device identity",
                "publish HMAC-bound provenance before making the key visible",
            ),
            dependencies=(
                _CONFIG_PREFLIGHT_REPAIR_ID,
                "doctor.gateway.pid.remove-stale",
            ),
            explicit_selection_required=True,
        ),
        RepairSpec(
            repair_id="doctor.component.compatibility.gate",
            label="component compatibility safety gate",
            risk="safe",
            plan=_plan_component_compatibility_gate,
            apply=_fix_compatibility_gate,
            dependencies=(_CONFIG_PREFLIGHT_REPAIR_ID,),
            effects=(),
        ),
        RepairSpec(
            repair_id="doctor.connector.compatibility.gate",
            label="connector compatibility safety gate",
            risk="safe",
            plan=_plan_connector_compatibility_gate,
            apply=_fix_compatibility_gate,
            dependencies=(_CONFIG_PREFLIGHT_REPAIR_ID,),
            effects=(),
        ),
        RepairSpec(
            repair_id="doctor.component.compatibility.review",
            label="component compatibility",
            risk="experimental",
            plan=_plan_component_compatibility_review,
            apply=_fix_component_compatibility_review,
            dependencies=(_CONFIG_PREFLIGHT_REPAIR_ID,),
            effects=("review authenticated DefenseClaw upgrade or trusted component reinstall",),
            explicit_selection_required=True,
        ),
        RepairSpec(
            repair_id="doctor.connector.compatibility.review",
            label="connector compatibility",
            risk="experimental",
            plan=_plan_connector_compatibility_review,
            apply=_fix_connector_compatibility_review,
            dependencies=(_CONFIG_PREFLIGHT_REPAIR_ID,),
            effects=("review vendor version changes and rerun connector setup interactively",),
            explicit_selection_required=True,
        ),
    ]
    for (
        repair_id,
        label,
        risk,
        fixer,
        dependencies,
        effects,
        may_restart,
        explicit_selection_required,
    ) in definitions:
        specs.append(
            RepairSpec(
                repair_id=repair_id,
                label=label,
                risk=risk,
                plan=lambda cfg, _fixer=fixer, _effects=effects: _plan_existing_fixer(
                    _fixer,
                    cfg,
                    effects=_effects,
                ),
                apply=fixer,
                dependencies=(
                    (_CONFIG_PREFLIGHT_REPAIR_ID, *dependencies)
                    if _CONFIG_PREFLIGHT_REPAIR_ID not in dependencies
                    else dependencies
                ),
                effects=effects,
                may_restart=may_restart,
                explicit_selection_required=explicit_selection_required,
            )
        )
    return tuple(specs)


def _repair_display_tag(state: str) -> str:
    if state == "applied":
        return "pass"
    if state in {"failed", "blocked"}:
        return "fail"
    if state in {"applicable", "manual", "requires_confirmation"}:
        return "warn"
    return "skip"


def _doctor_platform_name(platform_name: str | None = None) -> str:
    """Return the stable platform name used by repair declarations."""

    current = (platform_name or sys.platform).strip().casefold()
    if current.startswith("linux"):
        return "linux"
    if current in {"nt", "windows"} or current.startswith("win"):
        return "win32"
    return current


def _legacy_apply_decision(
    spec: RepairSpec,
    tag: str,
    detail: str,
) -> RepairDecision:
    """Translate a legacy fixer result without guessing that warnings succeeded."""

    normalized_tag = tag.strip().casefold()
    lowered = detail.casefold()
    if normalized_tag == "warn":
        # These two warnings describe a completed, bounded step.  The dotenv
        # fixer intentionally hands an exposed file to the dependent token
        # rotation transaction; the gateway lifecycle fixer may complete its
        # ownership repair while a separately diagnosed upstream subsystem
        # remains operationally degraded.
        dotenv_handoff = (
            spec.repair_id == "doctor.credentials.dotenv.protect"
            and "leaving the file unchanged until" in lowered
            and "gateway-token fixer" in lowered
        )
        verified_lifecycle = spec.repair_id == "doctor.gateway.service.reconcile" and "ownership verified" in lowered
        if dotenv_handoff or verified_lifecycle:
            return RepairDecision("applied", detail, effects=spec.effects)
        return RepairDecision(
            "failed",
            detail,
            effects=spec.effects,
            blockers=(detail,),
        )

    state = legacy_outcome_state(normalized_tag, detail)
    blockers = (detail,) if state in {"failed", "blocked"} else ()
    return RepairDecision(
        state,
        detail,
        effects=spec.effects,
        blockers=blockers,
    )


def _stable_topological_repair_specs(
    specs: tuple[RepairSpec, ...],
    selected_ids: set[str],
) -> tuple[tuple[RepairSpec, ...], tuple[str, ...]]:
    """Order the selected repair graph and report bounded registry defects."""

    first_by_id: dict[str, RepairSpec] = {}
    declaration_order: list[str] = []
    duplicate_ids: set[str] = set()
    for spec in specs:
        if spec.repair_id in first_by_id:
            duplicate_ids.add(spec.repair_id)
            continue
        first_by_id[spec.repair_id] = spec
        declaration_order.append(spec.repair_id)

    active_ids = (
        {repair_id for repair_id in selected_ids if repair_id in first_by_id}
        if selected_ids
        else set(first_by_id)
    )
    indegree = {repair_id: 0 for repair_id in active_ids}
    dependents: dict[str, list[str]] = {repair_id: [] for repair_id in active_ids}
    missing_edges: list[str] = []
    for repair_id in declaration_order:
        if repair_id not in active_ids:
            continue
        for dependency in first_by_id[repair_id].dependencies:
            if dependency not in first_by_id:
                missing_edges.append(f"{repair_id} -> {dependency}")
                continue
            if dependency not in active_ids:
                missing_edges.append(f"{repair_id} -> unselected {dependency}")
                continue
            indegree[repair_id] += 1
            dependents[dependency].append(repair_id)

    remaining = set(active_ids)
    ordered_ids: list[str] = []
    while remaining:
        ready = next(
            (
                repair_id
                for repair_id in declaration_order
                if repair_id in remaining and indegree[repair_id] == 0
            ),
            "",
        )
        if not ready:
            break
        remaining.remove(ready)
        ordered_ids.append(ready)
        for dependent in dependents[ready]:
            indegree[dependent] -= 1

    blockers: list[str] = []
    if duplicate_ids:
        blockers.append("duplicate repair IDs: " + ", ".join(sorted(duplicate_ids)))
    if missing_edges:
        blockers.append("missing repair dependencies: " + ", ".join(sorted(missing_edges)))
    if remaining:
        blockers.append("cyclic repair dependencies: " + ", ".join(sorted(remaining)))
        ordered_ids.extend(
            repair_id for repair_id in declaration_order if repair_id in remaining
        )
    return tuple(first_by_id[repair_id] for repair_id in ordered_ids), tuple(blockers)


def _run_fixers(
    cfg,
    r: _DoctorResult,
    *,
    assume_yes: bool,
    json_out: bool,
    dry_run: bool = False,
    fix_ids: tuple[str, ...] = (),
) -> None:
    """Plan or apply the declarative repair graph.

    Dry-run executes only each fixer's explicit read-only planner.  Real runs
    preserve the established credential ordering, while schema-v2 records
    keep repair attempts out of post-repair health counts.
    """
    # NOTE (D7): the connector-teardown fixer was deliberately REMOVED from
    # this list. Doctor is a diagnostic — it *reports* inactive-connector
    # residue (a WARN from _check_connector_residue) but must never run
    # ``connector teardown`` as a side effect of ``--fix``, which on a
    # multi-connector install could destroy a live connector. The
    # _fix_connector_residue helper is retained (and still excludes the full
    # active set) for the tracked follow-up that promotes teardown to a
    # first-class ``defenseclaw connector teardown`` CLI surface; until then,
    # operators run ``defenseclaw-gateway connector teardown --connector
    # <name>`` explicitly.
    specs = _doctor_repair_specs()
    known_ids = {spec.repair_id for spec in specs}
    explicit_ids = set(fix_ids)
    selected_ids = set(explicit_ids)
    for unknown_id in sorted(selected_ids - known_ids):
        record = RepairRecord(
            repair_id=unknown_id,
            label=unknown_id,
            state="failed",
            risk="safe",
            detail="unknown Doctor repair ID",
            blockers=("repair ID is not registered",),
            platform=sys.platform,
        )
        r.record_repair(record)
        if not json_out:
            _emit("fail", f"fix: {unknown_id}", detail=record.detail)

    if selected_ids:
        dependencies_by_id = {spec.repair_id: spec.dependencies for spec in specs}
        pending = list(selected_ids & known_ids)
        while pending:
            current = pending.pop()
            for dependency in dependencies_by_id.get(current, ()):
                if dependency not in selected_ids:
                    selected_ids.add(dependency)
                    pending.append(dependency)

    ordered_specs, graph_blockers = _stable_topological_repair_specs(specs, selected_ids)
    if graph_blockers:
        graph_record = RepairRecord(
            repair_id="doctor.repair.graph",
            label="repair dependency graph",
            state="failed",
            risk="safe",
            detail="Doctor repair registry is invalid; affected repairs will fail closed",
            blockers=graph_blockers,
            platform=sys.platform,
        )
        r.record_repair(graph_record)
        if not json_out:
            _emit("fail", "fix: repair dependency graph", detail=graph_record.detail)

    dotenv_safety_problem = ""
    external_gateway_env_names: list[str] = []
    data_dir = str(getattr(cfg, "data_dir", "") or "")
    for env_name in (_CANONICAL_GATEWAY_TOKEN_ENV, _LEGACY_GATEWAY_TOKEN_ENV):
        value = _normalized_gateway_token(os.environ.get(env_name, ""))
        if value and not credential_provenance.was_injected_from_dotenv(
            data_dir,
            env_name,
            value,
        ):
            external_gateway_env_names.append(env_name)
    setattr(cfg, "_doctor_external_gateway_env_names", tuple(external_gateway_env_names))

    outcomes: dict[str, str] = {}
    outcome_state_keys: dict[str, str] = {}
    platform_name = _doctor_platform_name()
    for spec in ordered_specs:
        started = time.monotonic()
        unsupported_platform = platform_name not in spec.platforms
        dependency_states = {dependency: outcomes.get(dependency, "not-run") for dependency in spec.dependencies}
        acceptable_dependency_states = {"applicable", "noop", "applied"} if dry_run else {"noop", "applied"}
        unsatisfied_dependencies = tuple(
            dependency for dependency, state in dependency_states.items() if state not in acceptable_dependency_states
        )

        if graph_blockers:
            decision = RepairDecision(
                "blocked",
                "repair registry validation failed; repair was not attempted",
                effects=spec.effects,
                blockers=graph_blockers,
            )
        elif unsupported_platform:
            decision = RepairDecision(
                "manual",
                f"repair is unavailable on platform {platform_name!r}",
                effects=spec.effects,
                blockers=(f"supported platforms: {', '.join(spec.platforms)}",),
            )
        elif unsatisfied_dependencies:
            blockers = tuple(
                f"{dependency} ended in {dependency_states[dependency]}" for dependency in unsatisfied_dependencies
            )
            decision = RepairDecision(
                "blocked",
                "prerequisite repair did not converge; dependent repair was not attempted",
                effects=spec.effects,
                blockers=blockers,
            )
        else:
            projected_attr = "_doctor_projected_repair_ids"
            projected_state_attr = "_doctor_projected_repair_state_keys"
            previous_projection = getattr(cfg, projected_attr, None)
            previous_state_projection = getattr(cfg, projected_state_attr, None)
            had_previous_projection = hasattr(cfg, projected_attr)
            had_previous_state_projection = hasattr(cfg, projected_state_attr)
            projected_repairs = (
                tuple(
                    repair_id
                    for repair_id, state in outcomes.items()
                    if state == "applicable"
                )
                if dry_run
                else ()
            )
            setattr(cfg, projected_attr, projected_repairs)
            setattr(
                cfg,
                projected_state_attr,
                tuple(outcome_state_keys.values()) if dry_run else (),
            )
            try:
                try:
                    plan = spec.plan(cfg)
                except Exception as exc:  # noqa: BLE001 - preserve typed/redacted output.
                    plan = RepairDecision(
                        "failed",
                        f"{type(exc).__name__}: planner raised unexpectedly",
                        effects=spec.effects,
                        blockers=("repair planner did not complete",),
                    )
            finally:
                if had_previous_projection:
                    setattr(cfg, projected_attr, previous_projection)
                else:
                    delattr(cfg, projected_attr)
                if had_previous_state_projection:
                    setattr(cfg, projected_state_attr, previous_state_projection)
                else:
                    delattr(cfg, projected_state_attr)
            blocker = "" if dry_run else _fixer_blocker(cfg, spec.label, dotenv_safety_problem)
            if plan.state not in {"applicable", "requires_confirmation"}:
                decision = plan
            elif dry_run and spec.risk == "experimental":
                decision = RepairDecision(
                    "requires_confirmation",
                    f"{plan.detail}; real repair requires an attended confirmation",
                    effects=plan.effects or spec.effects,
                    blockers=plan.blockers,
                    state_key=plan.state_key,
                )
            elif dry_run and spec.explicit_selection_required and spec.repair_id not in explicit_ids:
                decision = RepairDecision(
                    "requires_confirmation",
                    f"{plan.detail}; real repair requires explicit --fix-id {spec.repair_id}",
                    effects=plan.effects or spec.effects,
                    blockers=plan.blockers,
                    state_key=plan.state_key,
                )
            elif dry_run:
                decision = plan
            elif (spec.explicit_selection_required or spec.risk == "experimental") and (
                spec.repair_id not in explicit_ids
            ):
                decision = RepairDecision(
                    "manual",
                    f"{spec.risk} repair requires explicit --fix-id {spec.repair_id}",
                    effects=plan.effects or spec.effects,
                )
            elif spec.risk == "experimental" and assume_yes:
                decision = RepairDecision(
                    "requires_confirmation",
                    "experimental repair requires an attended confirmation; blanket --yes was deliberately ignored",
                    effects=plan.effects or spec.effects,
                )
            elif blocker:
                repair_scope = (
                    "credential repair" if spec.label == "gateway token" else "credential or lifecycle repair"
                )
                decision = RepairDecision(
                    "blocked",
                    f"blocked because {blocker}; review and securely replace .env before {repair_scope}",
                    effects=spec.effects,
                    blockers=(blocker,),
                )
            else:
                try:
                    tag, detail = spec.apply(
                        cfg,
                        assume_yes=False if spec.risk == "experimental" else assume_yes,
                    )
                    decision = _legacy_apply_decision(spec, tag, detail)
                    if decision.state == "applied" and spec.verify is not None:
                        try:
                            verified = spec.verify(cfg)
                        except Exception as exc:  # noqa: BLE001 - redact arbitrary verifier output.
                            decision = RepairDecision(
                                "failed",
                                f"{type(exc).__name__}: postcondition verifier raised unexpectedly",
                                effects=decision.effects or spec.effects,
                                blockers=("repair postcondition could not be verified",),
                            )
                        else:
                            if verified.state == "applied":
                                decision = RepairDecision(
                                    "applied",
                                    f"{decision.detail}; {verified.detail}",
                                    effects=verified.effects or decision.effects or spec.effects,
                                    state_key=verified.state_key or decision.state_key,
                                )
                            else:
                                decision = RepairDecision(
                                    "failed",
                                    f"postcondition verification did not converge: {verified.detail}",
                                    effects=verified.effects or decision.effects or spec.effects,
                                    blockers=verified.blockers
                                    or ("repair postcondition did not converge",),
                                    state_key=verified.state_key,
                                )
                except Exception as exc:  # defensive — one fixer shouldn't abort the rest
                    # ``error`` is not a Doctor schema status and used to fall
                    # through as a skipped check, allowing a broken repair to
                    # preserve exit 0. Do not render arbitrary exception text:
                    # filesystem and child-process errors can contain secrets.
                    decision = RepairDecision(
                        "failed",
                        f"{type(exc).__name__}: fixer raised unexpectedly",
                        effects=spec.effects,
                    )
                if spec.label in {"defenseclaw dotenv perms", "gateway token"}:
                    dotenv_safety_problem = _gateway_dotenv_safety_problem(cfg)

        record = RepairRecord(
            repair_id=spec.repair_id,
            label=spec.label,
            state=decision.state,
            risk=spec.risk,
            detail=decision.detail,
            dependencies=spec.dependencies,
            effects=decision.effects or spec.effects,
            blockers=decision.blockers,
            may_restart=spec.may_restart,
            explicit_selection_required=spec.explicit_selection_required,
            platform=platform_name,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        )
        r.record_repair(record)
        outcomes[spec.repair_id] = record.state
        if dry_run and record.state == "applicable" and decision.state_key:
            outcome_state_keys[spec.repair_id] = decision.state_key
        if not json_out:
            _emit(
                _repair_display_tag(record.state),
                f"fix: {spec.label} [{spec.repair_id}]",
                detail=record.detail,
            )


def _run_fixers_with_lock(
    cfg,
    r: _DoctorResult,
    *,
    assume_yes: bool,
    json_out: bool,
    dry_run: bool = False,
    fix_ids: tuple[str, ...] = (),
) -> None:
    """Serialize real repair transactions without making previews write state."""

    if dry_run:
        _run_fixers(
            cfg,
            r,
            assume_yes=assume_yes,
            json_out=json_out,
            dry_run=True,
            fix_ids=fix_ids,
        )
        return

    data_dir = _configured_gateway_data_dir(cfg)
    integrity_problem = _gateway_data_dir_integrity_problem(cfg)
    if integrity_problem:
        record = RepairRecord(
            repair_id="doctor.repair.transaction-lock",
            label="repair transaction",
            state="blocked",
            risk="safe",
            detail=f"{integrity_problem}; no repair was attempted",
            blockers=(integrity_problem,),
            platform=sys.platform,
        )
        r.record_repair(record)
        if not json_out:
            _emit("fail", "fix: repair transaction", detail=record.detail)
        return

    lock_target = os.path.join(data_dir, ".doctor-repair")
    try:
        with locked_file_update(lock_target, timeout_seconds=0.25):
            _run_fixers(
                cfg,
                r,
                assume_yes=assume_yes,
                json_out=json_out,
                dry_run=False,
                fix_ids=fix_ids,
            )
    except FileLockTimeoutError:
        record = RepairRecord(
            repair_id="doctor.repair.transaction-lock",
            label="repair transaction",
            state="blocked",
            risk="safe",
            detail="another Doctor repair owns the installation lock; retry after it completes",
            blockers=("repair transaction lock is busy",),
            platform=sys.platform,
        )
        r.record_repair(record)
        if not json_out:
            _emit("fail", "fix: repair transaction", detail=record.detail)
    except OSError:
        record = RepairRecord(
            repair_id="doctor.repair.transaction-lock",
            label="repair transaction",
            state="failed",
            risk="safe",
            detail="the cross-platform repair lock could not be acquired; no repair was attempted",
            blockers=("repair transaction lock is unavailable",),
            platform=sys.platform,
        )
        r.record_repair(record)
        if not json_out:
            _emit("fail", "fix: repair transaction", detail=record.detail)


def _active_connector(cfg) -> str:
    """Return the active connector name in lowercase.

    Prefer the unified ``Config.active_connector()`` from S4.1 — it
    handles the legacy ``guardrail.connector`` field plus the
    ``claw.mode`` fallback the same way the rest of the CLI does.
    Falls back to ``"openclaw"`` for older configs that predate the
    method.
    """
    if hasattr(cfg, "active_connector"):
        try:
            return (cfg.active_connector() or "openclaw").lower()
        except Exception:
            pass
    return (getattr(getattr(cfg, "guardrail", None), "connector", "") or "openclaw").lower()


def _doctor_active_connectors(cfg) -> list[str]:
    """Return the connectors doctor should inventory / probe, in stable order.

    Prefers ``Config.active_connectors()`` — the authoritative set that the
    rest of the CLI fans out over. Crucially that resolver returns ``[]`` on a
    genuinely unconfigured install (every connector marker cleared, e.g. after
    ``setup remove`` drops the last one); doctor must honor that empty signal
    and render an explicit "no connector configured" state rather than
    flooring to the singular :func:`_active_connector`, whose ``"openclaw"``
    path-resolution default would fabricate a phantom OpenClaw connector on an
    install that never used OpenClaw (D3).

    Only legacy configs that predate ``active_connectors()`` fall back to the
    singular primary, preserving their single-connector behavior. Names are
    lowercased and de-duplicated; the empty list is returned verbatim so
    callers can distinguish "nothing configured" from "one connector".
    """
    getter = getattr(cfg, "active_connectors", None)
    if callable(getter):
        try:
            ordered: list[str] = []
            for c in getter():
                name = str(c).strip().lower()
                if name and name not in ordered:
                    ordered.append(name)
            return ordered
        except Exception:  # noqa: BLE001 — fall back to the singular primary.
            pass
    primary = _active_connector(cfg)
    return [primary] if primary else []


def _connector_enabled(cfg, connector: str) -> bool:
    """Whether *connector* is effectively enabled (not operator-disabled).

    ``Config.active_connectors()`` returns every key in
    ``guardrail.connectors`` regardless of its ``enabled`` flag, so a
    connector turned off via ``guardrail disable --connector X`` still shows
    up in :func:`_doctor_active_connectors`. The Go boot loop drops a
    ``enabled: false`` connector from the active set and tears its hooks down,
    so doctor must not render it as active — its inventory/contract/hook rows
    would read as live enforcement and its (intentionally) missing hook
    artifacts would FAIL spuriously.

    Mirrors ``cmd_status._is_enabled`` (the sibling fix): default ``True`` so
    single-connector installs and any never-disabled connector keep reading as
    active; only an explicit ``enabled: false`` resolves to ``False``. (N1)
    """
    gc = getattr(cfg, "guardrail", None)
    if gc is None or not hasattr(gc, "effective_enabled"):
        return True
    try:
        return bool(gc.effective_enabled(connector))
    except Exception:  # noqa: BLE001
        return True


_CONNECTOR_LABELS = {
    "openclaw": "OpenClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "zeptoclaw": "ZeptoClaw",
    "hermes": "Hermes",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "geminicli": "Gemini CLI",
    "copilot": "GitHub Copilot CLI",
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "omnigent": "OmniGent",
}


def _emit_rule_pack_row(path: str, kind: str, r: _DoctorResult) -> None:
    """Validate a resolved rule-pack directory and emit one doctor row.

    *kind* is a human label for the source of the path (``"configured
    rule_pack_dir"`` or ``"built-in default rule pack"``). A directory that is
    missing — or present but empty — silently degrades guardrail enforcement
    because the gateway loads zero rule packs from it, so both cases WARN; a
    populated directory passes. (D9)
    """
    if not os.path.isdir(path):
        _emit(
            "warn",
            "Rule pack",
            f"{kind} not found on disk: {path} — guardrail enforcement would run with no rule packs",
            r=r,
        )
        return
    try:
        with os.scandir(path) as entries:
            has_contents = any(True for _ in entries)
    except OSError:
        has_contents = False
    if not has_contents:
        _emit(
            "warn",
            "Rule pack",
            f"{kind} is empty: {path} — guardrail enforcement would run with no rule packs",
            r=r,
        )
        return
    _emit("pass", "Rule pack", f"{path} ({kind})", r=r)


def _check_connector_inventory(cfg, connector: str, r: _DoctorResult) -> None:
    """Surface one connector and everything it resolves to.

    Each connector has its own conventions for where skills, plugins,
    and MCP server registrations live. ``Config.skill_dirs()`` /
    ``plugin_dirs()`` / ``mcp_servers()`` are now polymorphic per
    connector (S4.1), so this check makes that mapping visible to the
    operator: if Codex is active but skill_dirs() still points at
    ``~/.openclaw/skills``, that's a config bug doctor should flag.

    Rendered identically for every active connector (the caller tags each
    block with a "[<connector>]" suffix) so the output reads the same
    whether one or many connectors are active — there is no separate
    single- vs multi-connector layout. Alongside the path inventory this
    also surfaces the connector's effective guardrail mode and rule pack.
    """
    label = _CONNECTOR_LABELS.get(connector, connector)
    if connector not in _CONNECTOR_LABELS:
        _emit(
            "warn",
            "Connector",
            f"unknown connector {connector!r} — known: " + ", ".join(sorted(_CONNECTOR_LABELS)),
            r=r,
        )
    else:
        _emit("pass", "Connector", label, r=r)

    # Effective guardrail mode for this connector (falls back to the
    # global guardrail.mode when the connector sets no override).
    gc = getattr(cfg, "guardrail", None)
    if gc is not None and hasattr(gc, "effective_mode"):
        try:
            mode = (gc.effective_mode(connector) or "").strip()
        except Exception:  # noqa: BLE001
            mode = ""
        if mode:
            try:
                from defenseclaw.fail_mode import connector_fail_mode_report

                fail_mode = connector_fail_mode_report(cfg, connector)
            except Exception:  # noqa: BLE001 - doctor must still report partial state.
                fail_mode = {"effective": "unknown", "provenance": "unavailable"}
            _emit(
                "pass",
                "Mode",
                f"{mode}; fail-mode={fail_mode['effective']}; provenance={fail_mode['provenance']}",
                r=r,
            )

    workspace = _workspace_dir(cfg)
    if workspace:
        _emit("pass", "Connector scope", f"workspace ({workspace})", r=r)
    else:
        _emit("pass", "Connector scope", "global user config", r=r)

    # Skill dirs (scoped to this connector so a multi-connector loop
    # inventories each connector's own layout, not just the primary's).
    try:
        sdirs = cfg.skill_dirs(connector) if hasattr(cfg, "skill_dirs") else []
    except Exception as exc:
        _emit("warn", "Skill paths", f"could not enumerate: {exc}", r=r)
        sdirs = []
    if sdirs:
        existing = sum(1 for d in sdirs if os.path.isdir(d))
        detail = f"{existing}/{len(sdirs)} present — " + ", ".join(sdirs)
        if existing == 0:
            _emit("warn", "Skill paths", detail, r=r)
        else:
            _emit("pass", "Skill paths", detail, r=r)
    else:
        _emit("skip", "Skill paths", f"no skill dirs configured for {label}", r=r)

    # Plugin dirs (scoped to this connector).
    try:
        pdirs = cfg.plugin_dirs(connector) if hasattr(cfg, "plugin_dirs") else []
    except Exception as exc:
        _emit("warn", "Plugin paths", f"could not enumerate: {exc}", r=r)
        pdirs = []
    if pdirs:
        existing = sum(1 for d in pdirs if os.path.isdir(d))
        detail = f"{existing}/{len(pdirs)} present — " + ", ".join(pdirs)
        if existing == 0:
            _emit("warn", "Plugin paths", detail, r=r)
        else:
            _emit("pass", "Plugin paths", detail, r=r)
    else:
        _emit("skip", "Plugin paths", f"no plugin dirs configured for {label}", r=r)

    # MCP servers (scoped to this connector).
    try:
        servers = cfg.mcp_servers(connector) if hasattr(cfg, "mcp_servers") else []
    except Exception as exc:
        _emit("warn", "MCP servers", f"could not enumerate: {exc}", r=r)
        servers = []
    count = len(servers)
    if count:
        names = ", ".join(s.name for s in servers[:5])
        more = f" (+{count - 5} more)" if count > 5 else ""
        _emit("pass", "MCP servers", f"{count} configured: {names}{more}", r=r)
    else:
        _emit("skip", "MCP servers", "no MCP servers registered", r=r)

    # Effective rule pack for this connector (falls back to built-in
    # defaults when no rule_pack_dir is configured). Warn when the resolved
    # directory is missing/empty on disk — that silently degrades enforcement.
    if gc is not None and hasattr(gc, "effective_rule_pack_dir"):
        try:
            rule_pack_dir = (gc.effective_rule_pack_dir(connector) or "").strip()
        except Exception:  # noqa: BLE001
            rule_pack_dir = ""
        if rule_pack_dir:
            _emit_rule_pack_row(rule_pack_dir, "configured rule_pack_dir", r)
        else:
            # No explicit rule_pack_dir → the gateway resolves the built-in
            # default to <data_dir>/policies/guardrail/default and loads packs
            # from there (Go: config.go cfg.Guardrail.RulePackDir fallback +
            # the viper default). Validate THAT resolved path rather than
            # emitting a benign "no dir set" skip: if it is unseeded or has
            # been deleted, enforcement silently runs with no rule packs while
            # doctor would otherwise show green. (D9)
            data_dir = getattr(cfg, "data_dir", "") or ""
            if data_dir:
                default_dir = os.path.join(data_dir, "policies", "guardrail", "default")
                _emit_rule_pack_row(default_dir, "built-in default rule pack", r)
            else:
                _emit(
                    "skip",
                    "Rule pack",
                    "built-in defaults (data_dir unresolved)",
                    r=r,
                )

    # Detection strategy + judge gating for this connector (read-only). This
    # is root #4 in the doctor fix-plan made visible: the judge can be
    # configured globally yet silently NOT run for a given connector, so
    # surface what actually fires rather than what's merely configured.
    # ``detection_strategy`` is a global guardrail field
    # (regex_only | regex_judge | judge_first); the judge ADDITIONALLY has to
    # be enabled, and — for hook-enforced connectors — this connector must be
    # listed in ``guardrail.judge.hook_connectors`` (or "*") for the hook lane
    # to forward content to the LLM judge (Go: JudgeConfig.HookConnectorEnabled).
    # Proxy connectors (openclaw/zeptoclaw) run the judge via the proxy lane
    # whenever it is enabled. Report-only: this does NOT touch the judge
    # wiring. (N3)
    if gc is not None:
        strategy = (getattr(gc, "detection_strategy", "") or "").strip() or "regex_judge"
        judge = getattr(gc, "judge", None)
        judge_enabled = bool(getattr(judge, "enabled", False)) if judge is not None else False
        detail = f"strategy={strategy}"
        if not judge_enabled:
            detail += "; judge disabled (regex/Cisco-AID lanes only)"
        elif connector not in _HOOK_ENFORCED_CONNECTORS:
            # Proxy connector: the judge runs in the proxy lane.
            detail += "; judge active (proxy lane)"
        else:
            hook_conns = list(getattr(judge, "hook_connectors", []) or [])
            gated_on = any(entry.strip() == "*" or entry.strip().lower() == connector.lower() for entry in hook_conns)
            if gated_on:
                detail += "; judge active (hook lane)"
            else:
                detail += (
                    "; judge enabled but NOT gated for this connector's hook "
                    "lane (regex/Cisco-AID lanes only) — add it to "
                    "guardrail.judge.hook_connectors to forward content to the judge"
                )
        _emit("pass", "Detection", detail, r=r)


def _check_hook_contract_lock(
    cfg,
    connector: str,
    r: _DoctorResult,
    *,
    platform_name: str | None = None,
    config_path: str | None = None,
    install_root: str | None = None,
    search_path: str | None = None,
    pathext: str | None = None,
) -> None:
    if connector in {"openclaw", "zeptoclaw"}:
        _emit("skip", "Hook contract", f"{connector} uses proxy/chat surfaces", r=r)
        return
    data_dir = getattr(cfg, "data_dir", "") or ""
    lock_path = os.path.join(data_dir, "hook_contract_lock.json")
    try:
        with open(lock_path, encoding="utf-8") as fh:
            lock = json.load(fh)
    except FileNotFoundError:
        _emit("warn", "Hook contract", "no hook_contract_lock.json yet — restart gateway after setup", r=r)
        return
    except Exception as exc:
        _emit("fail", "Hook contract", f"cannot read {lock_path}: {exc}", r=r)
        return

    entry = (lock.get("connectors") or {}).get(connector) or {}
    if not entry:
        _emit("warn", "Hook contract", f"no lock entry for active connector {connector}", r=r)
        return

    status = str(entry.get("compatibility_status") or "")
    contract = str(entry.get("contract_id") or "")
    raw_version = str(entry.get("raw_agent_version") or "")
    normalized = str(entry.get("normalized_agent_version") or "")
    script_version = str(entry.get("hook_script_version") or "")
    detail = f"contract={contract or '?'} status={status or '?'}"
    if raw_version:
        detail += f" agent={raw_version}"
    if normalized:
        detail += f" normalized={normalized}"
    if script_version:
        detail += f" script={script_version}"
    locations = entry.get("locations") or {}
    native_runtime = None
    if (platform_name or os.name) == "nt" and connector in {"codex", "claudecode"}:
        native_runtime = _windows_native_hook_check(
            cfg,
            connector,
            config_path=config_path,
            install_root=install_root,
            search_path=search_path,
            pathext=pathext,
        )
    if isinstance(locations, dict):
        workspace_dir = str(locations.get("workspace_dir") or "").strip()
        hook_paths = [str(v) for v in locations.get("hook_config_paths", []) if v]
        runtime_paths = [str(v) for v in locations.get("hook_script_paths", []) if v]
        if (platform_name or os.name) == "nt":
            # The lock also records portable generated assets for digest and
            # freshness checks.  They are not Windows runtimes.  Retain real
            # native artifacts such as Cursor's .ps1 adapter and OmniGent's
            # .py/.pth files, but never label a generated shell script as the
            # configured Windows runtime.
            runtime_paths = [path for path in runtime_paths if not path.lower().endswith(".sh")]
        if native_runtime is not None:
            runtime_paths = []
        if workspace_dir:
            detail += f" workspace={workspace_dir}"
        if hook_paths:
            detail += f" hook_path={hook_paths[0]}"
        if runtime_paths:
            detail += f" runtime_path={runtime_paths[0]}"
    if native_runtime is not None:
        detail += f" {native_runtime.runtime_description}"

    # Native Codex setup records the exact executable, version, and digest used
    # to select the hook contract.  Automatic discovery can legitimately find a
    # different installation (for example an npm .CMD wrapper ahead of the
    # desktop app on PATH); it must not override that protected setup evidence.
    protected_codex_agent = connector == "codex" and all(
        (
            str(entry.get("agent_executable") or "").strip(),
            str(entry.get("agent_executable_sha256") or "").strip(),
            str(entry.get("agent_executable_source") or "").strip() == "setup-selected",
        )
    )
    current_version = "" if protected_codex_agent else _discovered_agent_version(data_dir, connector)
    if current_version and raw_version and current_version != raw_version:
        _emit(
            "fail",
            "Hook contract",
            f"drift: lock has {raw_version!r}, discovery now reports {current_version!r}"
            + (f"; {native_runtime.runtime_description}" if native_runtime is not None else ""),
            r=r,
        )
        return
    if native_runtime is not None and not native_runtime.healthy:
        _emit("fail", "Hook contract", detail, r=r)
    elif status == "unknown":
        _emit("fail", "Hook contract", detail, r=r)
    elif status in {"known", "unversioned"}:
        _emit("pass", "Hook contract", detail, r=r)
    else:
        _emit("warn", "Hook contract", detail, r=r)


def _discovered_agent_version(data_dir: str, connector: str) -> str:
    try:
        with open(os.path.join(data_dir, "agent_discovery.json"), encoding="utf-8") as fh:
            disc = json.load(fh)
    except Exception:
        return ""
    signal = (disc.get("agents") or {}).get(connector) or {}
    return str(signal.get("version") or "").strip()


# Maps connector name → list of *expected* artifact filenames (relative
# to data_dir) that Connector.Setup writes. When the active connector
# is X but data_dir contains Y's artifacts, that's residue from a prior
# install and Connector.Teardown was never invoked for Y.
#
# OpenClaw can leave either the old ``<openclaw.json>.pristine`` backup
# next to its config or a managed backup under connector_backups/, so it
# is handled separately by :func:`_check_connector_residue`.
_CONNECTOR_RESIDUE_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "claudecode": (
        "claudecode_backup.json",
        os.path.join("connector_backups", "claudecode", "settings.json.json"),
    ),
    "codex": (
        "codex_backup.json",
        "codex_config_backup.json",
        os.path.join("connector_backups", "codex", "config.toml.json"),
    ),
    "zeptoclaw": (
        "zeptoclaw_backup.json",
        os.path.join("connector_backups", "zeptoclaw", "config.json.json"),
    ),
}
_OPENCLAW_RESIDUE_ARTIFACTS: tuple[str, ...] = (os.path.join("connector_backups", "openclaw", "openclaw.json.json"),)


def _residue_active_set(cfg, active: str) -> set[str]:
    """Return every connector that is genuinely active (never residue).

    On a multi-connector install each active connector's backups are
    legitimate state, so the residue sweep must exclude the FULL
    ``active_connectors()`` set — not just the singular primary. Scoping to
    the primary alone made all-but-one connector look like residue, which
    raised a false WARN and (through the fixer) shelled
    ``connector teardown`` against a live connector (D7).

    The singular ``active`` argument is unioned in so older configs / tests
    that pass a primary but expose no ``active_connectors()`` keep their
    exact single-connector behavior.
    """
    out = {(active or "").strip().lower()}
    getter = getattr(cfg, "active_connectors", None)
    if callable(getter):
        try:
            for c in getter():
                name = str(c).strip().lower()
                if name:
                    out.add(name)
        except Exception:  # noqa: BLE001 — keep the singular primary.
            pass
    out.discard("")
    return out


def _plugin_registry_required_offenders(cfg) -> list[str]:
    """Return where ``asset_policy.plugin.registry_required`` is explicitly on.

    Labels are ``"global"`` for the top-level per-type policy and
    ``"connector:<name>"`` for each per-connector override that sets it to a
    literal ``True`` (the per-connector field is tri-state — ``None`` means
    inherit, so only an explicit ``True`` is an offender; an inherited-from-
    global require is already covered by the ``"global"`` label). Shared by the
    OTHER-5 check and fixer.
    """
    ap = getattr(cfg, "asset_policy", None)
    if ap is None:
        return []
    offenders: list[str] = []
    plugin = getattr(ap, "plugin", None)
    if plugin is not None and bool(getattr(plugin, "registry_required", False)):
        offenders.append("global")
    connectors = getattr(ap, "connectors", None) or {}
    for name, pc in connectors.items():
        pc_plugin = getattr(pc, "plugin", None) if pc is not None else None
        if pc_plugin is not None and getattr(pc_plugin, "registry_required", None) is True:
            offenders.append(f"connector:{name}")
    return offenders


def _check_plugin_registry_required(cfg, r: _DoctorResult) -> None:
    """Flag a dead-end ``asset_policy.plugin.registry_required=true``.

    There is no plugin-registry pipeline in v1 — nothing can populate
    ``asset_policy.plugin.registry`` (``registry sync``/``promote``/``approve``
    are skill+mcp only, and ``registry require --type`` no longer offers
    ``plugin``). So a leftover ``plugin.registry_required: true`` is a
    dead-end: with the default ``registry_empty_action: deny`` and asset-policy
    enforcement on, the gateway blocks EVERY plugin (``required + empty
    registry + default-deny`` → ``registry-required-empty``) with no operator
    recovery path but hand-editing config.

    Surfaces it (WARN) so ``doctor --fix`` can clear it. Checks the global
    per-type policy AND every per-connector override. Report-only here; the
    matching fixer does the clearing. (OTHER-5, doctor half)
    """
    ap = getattr(cfg, "asset_policy", None)
    if ap is None:
        return
    offenders = _plugin_registry_required_offenders(cfg)
    if not offenders:
        _emit(
            "pass",
            "Plugin registry policy",
            "no dead-end plugin.registry_required flag set",
            r=r,
        )
        return
    enforcing = bool(getattr(ap, "enabled", False))
    where = ", ".join(offenders)
    impact = (
        "blocks ALL plugins (the plugin registry can never be populated in v1)"
        if enforcing
        else "would block ALL plugins once asset-policy enforcement is enabled"
    )
    _emit(
        "warn",
        "Plugin registry policy",
        f"plugin.registry_required=true [{where}] is a dead-end — {impact}; run 'doctor --fix' to clear it",
        r=r,
    )


def _check_connector_residue(cfg, active: str, r: _DoctorResult) -> None:
    """Detect leftover artifacts from connectors that aren't active.

    Each connector's ``Setup`` writes a pristine backup of the agent
    framework's config plus (for some connectors) hook scripts and env
    files. ``Teardown`` removes them. When an operator switches
    connectors without first running ``defenseclaw guardrail disable``
    (or the gateway crashes mid-handoff), we end up with the *prior*
    connector's residue on disk.

    This check walks every known connector that isn't the active one and emits
    a WARN listing any artifact still present. Operators should clean each
    residual connector directly with
    ``defenseclaw-gateway connector teardown --connector <name>``.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        _emit("skip", "Connector residue", "no data dir configured", r=r)
        return

    # Exclude the FULL active set, not just the singular primary (D7): an
    # active connector can never be its own residue. Build the inactive set
    # explicitly so unknown active connectors (plugins) don't accidentally
    # suppress residue detection.
    active_set = _residue_active_set(cfg, active)
    inactive = [name for name in _CONNECTOR_RESIDUE_ARTIFACTS if name not in active_set]

    found: list[tuple[str, str]] = []  # (connector_name, full_path)
    for name in inactive:
        for filename in _CONNECTOR_RESIDUE_ARTIFACTS[name]:
            full = os.path.join(data_dir, filename)
            if os.path.isfile(full):
                found.append((name, full))

    # OpenClaw's pristine backup is its only residue marker and lives
    # next to openclaw.json, not under data_dir. Only flag it when
    # OpenClaw is *not* among the active connectors.
    if "openclaw" not in active_set:
        for filename in _OPENCLAW_RESIDUE_ARTIFACTS:
            full = os.path.join(data_dir, filename)
            if os.path.isfile(full):
                found.append(("openclaw", full))
        oc_path = getattr(getattr(cfg, "claw", None), "config_file", "") or ""
        oc_path = os.path.expanduser(oc_path)
        if oc_path:
            pristine = oc_path + ".pristine"
            if os.path.isfile(pristine):
                found.append(("openclaw", pristine))

    if not found:
        _emit(
            "pass",
            "Connector residue",
            "no leftover artifacts from inactive connectors",
            r=r,
        )
        return

    # Group residue by connector for a readable message — operators
    # need to see "Codex left X behind" not just a flat path list.
    by_conn: dict[str, list[str]] = {}
    for name, path in found:
        by_conn.setdefault(name, []).append(path)
    parts = []
    for name in sorted(by_conn):
        paths = ", ".join(by_conn[name])
        parts.append(f"{name}: {paths}")
    detail = (
        "found residue from inactive connectors — "
        + "; ".join(parts)
        + ". Run 'defenseclaw-gateway connector teardown --connector <name>' "
        "for each residual connector, or "
        "'defenseclaw uninstall --keep-openclaw' for a manual sweep."
    )
    _emit("warn", "Connector residue", detail, r=r)


def _check_scan_coverage(cfg, r: _DoctorResult) -> None:
    """Advertise what each scanner will check.

    Mirrors the bullet list rendered by ``_scan_ui.render_preamble``
    so operators see the *same* category contract from doctor as
    they see when they actually run the scanner. Anything we can't
    look up via :func:`_scan_ui.categories_for` falls through as
    SKIP — the helper is the source of truth.
    """
    del cfg  # unused: categories are static per component
    from defenseclaw.commands import _scan_ui

    for component in _scan_ui.supported_components():
        cats = _scan_ui.categories_for(component)
        label = _scan_ui._COMPONENT_LABELS.get(  # type: ignore[attr-defined]
            component,
            (component, component + "s"),
        )[0]
        if cats:
            _emit(
                "pass",
                f"Scanner coverage ({label})",
                "; ".join(cats),
                r=r,
            )
        else:
            _emit("skip", f"Scanner coverage ({label})", "no categories registered", r=r)


def _verified_listener_gateway_evidence(
    cfg,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> ListenerEvidence:
    """Return structured endpoint evidence without trusting ``gateway.pid``."""
    gateway = getattr(cfg, "gateway", None)
    if gateway is None:
        return ListenerEvidence("unavailable", reason="gateway configuration is unavailable")
    try:
        api_port = int(getattr(gateway, "api_port", 0) or 0)
    except (TypeError, ValueError):
        return ListenerEvidence("unavailable", reason="configured API port is invalid")
    host = _gateway_api_host(cfg)
    platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
    evidence = evidence or GatewayEvidence(platform_name=platform_name)
    listener = _managed_gateway_listener_evidence(
        api_port,
        host=host,
        platform_name=platform_name,
        evidence=evidence,
    )
    if listener.status != "ok":
        return listener
    process = evidence.process(listener.pid)
    if (
        process.status == "ok"
        and gateway_executable_name(
            process.executable,
            platform_name=platform_name,
        )
        in GATEWAY_PROCESS_NAMES
    ):
        return listener
    return ListenerEvidence(
        "unavailable",
        pid=listener.pid,
        reason="listener exists but its process identity could not be verified as DefenseClaw",
    )


def _verified_listener_gateway_pid(
    cfg,
    *,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
) -> int:
    """Backward-compatible PID view over structured endpoint evidence."""
    listener = _verified_listener_gateway_evidence(
        cfg,
        evidence=evidence,
        platform_name=platform_name,
    )
    return listener.pid if listener.status == "ok" else 0


def _remove_stale_pid_if_unchanged(
    pid_file: str,
    inspected_fingerprint: tuple[int, int, int, int, bytes],
    *,
    platform_name: str | None = None,
) -> tuple[str, str]:
    """Delete only the PID-file object represented by prior evidence."""

    changed_detail = "gateway PID record changed or disappeared after inspection; no replacement was deleted"
    platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
    if platform_name != "win32":
        parent = os.path.dirname(os.path.abspath(pid_file)) or os.curdir
        try:
            quarantine_dir = tempfile.mkdtemp(
                prefix=".gateway-pid-doctor-",
                dir=parent,
            )
        except OSError as exc:
            return ("fail", f"could not create a private PID-file quarantine beside {pid_file}: {exc}")
        quarantined = os.path.join(quarantine_dir, os.path.basename(pid_file))
        try:
            os.rename(pid_file, quarantined)
        except FileNotFoundError:
            with contextlib.suppress(OSError):
                os.rmdir(quarantine_dir)
            return ("warn", changed_detail)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.rmdir(quarantine_dir)
            return ("fail", f"could not atomically quarantine {pid_file} for safe removal: {exc}")

        # The rename atomically claims whichever pathname object exists at that
        # instant. Delete only if that claimed object is the one Doctor
        # inspected. A publisher may create a fresh gateway.pid after the
        # rename; it is independent and remains untouched.
        if pid_file_fingerprint(quarantined) == inspected_fingerprint:
            try:
                os.unlink(quarantined)
            except OSError as exc:
                return (
                    "fail",
                    f"could not remove the verified stale PID record; it remains preserved at {quarantined}: {exc}",
                )
            with contextlib.suppress(OSError):
                os.rmdir(quarantine_dir)
            return ("pass", "")

        # The claimed object is a concurrent replacement. Restore a regular
        # replacement with a no-clobber hard link when the canonical pathname
        # is still absent. Keep the quarantined link even after restoration:
        # another publisher could replace the restored pathname before a
        # cleanup unlink, otherwise making this safety copy its last link.
        try:
            quarantined_info = os.lstat(quarantined)
        except OSError as exc:
            return (
                "fail",
                f"{changed_detail}; the quarantined record could not be inspected at {quarantined}: {exc}",
            )
        if not stat.S_ISREG(quarantined_info.st_mode):
            return (
                "fail",
                f"{changed_detail}; a non-regular replacement remains preserved at {quarantined}",
            )
        try:
            os.link(
                quarantined,
                pid_file,
                follow_symlinks=False,
            )
        except FileExistsError:
            return (
                "fail",
                f"{changed_detail}; the current pathname and quarantined "
                f"replacement at {quarantined} were both preserved",
            )
        except (NotImplementedError, OSError) as exc:
            return (
                "fail",
                f"{changed_detail}; the replacement remains preserved at "
                f"{quarantined} because no-overwrite restoration failed: {exc}",
            )
        return (
            "warn",
            f"{changed_detail}; the replacement was restored without overwrite "
            f"and a safety link remains at {quarantined}",
        )

    # On Windows, a separate fingerprint followed by pathname deletion can
    # remove a replacement published in between. Hold a descriptor that denies
    # both writes and delete-sharing, compare that exact object, then mark that
    # same handle for deletion.
    from defenseclaw.windows_acl import delete_regular_fd, open_regular_mutation_fd

    try:
        fd = open_regular_mutation_fd(pid_file)
    except OSError as exc:
        error = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if error in {2, 3}:
            return ("warn", changed_detail)
        return (
            "fail",
            f"could not exclusively claim {pid_file} for safe removal: {exc}",
        )
    outcome = ("pass", "")
    try:
        if pid_file_fingerprint_from_fd(fd) != inspected_fingerprint:
            outcome = ("warn", changed_detail)
        else:
            delete_regular_fd(fd)
    except OSError as exc:
        outcome = ("fail", f"could not remove {pid_file} through its verified handle: {exc}")
    try:
        os.close(fd)
    except OSError:
        # A failed close leaves the delete disposition ambiguous. Never report
        # successful convergence in that state.
        return ("fail", f"could not close the verified PID-file handle for {pid_file}")
    return outcome


def _fix_stale_pid(
    cfg,
    *,
    assume_yes: bool,
    evidence: GatewayEvidence | None = None,
    platform_name: str | None = None,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Remove only a stale PID record that has not changed since inspection."""
    data_dir = _configured_gateway_data_dir(cfg)
    if not data_dir:
        return ("fail", "gateway data directory is unavailable; refusing PID-file repair")
    pid_file = os.path.join(data_dir, "gateway.pid")
    inspected_fingerprint = pid_file_fingerprint(pid_file)
    if not inspected_fingerprint:
        record = read_pid_record(pid_file)
        if record.status == "missing":
            return ("skip", "no pid file")
        return (
            "fail",
            "PID record is unsafe or could not be bound to one inspection; refusing to remove it",
        )
    record = parse_pid_record_bytes(inspected_fingerprint[4])
    if pid_file_fingerprint(pid_file) != inspected_fingerprint:
        return (
            "fail",
            "PID record is unsafe or changed during inspection; refusing to remove it",
        )
    if record.status in {"denied", "unavailable"}:
        return ("warn", record.reason or "PID record could not be safely inspected")

    stale_reason = ""
    if record.status == "malformed":
        listener = _verified_listener_gateway_evidence(
            cfg,
            evidence=evidence,
            platform_name=platform_name,
        )
        if listener.status == "ok":
            return (
                "warn",
                "PID record is malformed but a verified gateway still owns the "
                "configured endpoint; preserving management state",
            )
        if listener.status != "missing":
            return (
                "warn",
                f"PID record is malformed but endpoint absence is not proven "
                f"({listener.reason or listener.status}); preserving management state",
            )
        stale_reason = record.reason or "PID record is malformed"
    else:
        platform_name = platform_name or ("win32" if os.name == "nt" else sys.platform)
        evidence = evidence or GatewayEvidence(platform_name=platform_name)
        process = evidence.process(record.pid)
        trust = _gateway_process_trust(
            cfg,
            record,
            process,
            platform_name=platform_name,
        )
        if trust.trusted:
            return (
                "skip",
                f"pid {record.pid} has current executable, start, and data-home identity",
            )
        if trust.code in {"legacy_identity", "unbound_home", "unavailable"}:
            return (
                "warn",
                f"{trust.detail}; preserving the PID record and refusing automatic lifecycle repair",
            )
        stale_reason = trust.detail

    if plan_only:
        return ("plan", f"remove stale PID record {pid_file}: {stale_reason}")

    if not assume_yes and not click.confirm(
        f"    Remove stale pid file {pid_file} ({stale_reason})?",
        default=True,
    ):
        return ("skip", "declined by user")

    removal_tag, removal_detail = _remove_stale_pid_if_unchanged(
        pid_file,
        inspected_fingerprint,
    )
    if removal_tag != "pass":
        return (removal_tag, removal_detail)
    return ("pass", f"removed {pid_file}: {stale_reason}")


def _fix_gateway_token(
    cfg,
    *,
    assume_yes: bool,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Re-sync or create the gateway token for the active connector."""
    if not _doctor_config_present(cfg):
        return ("skip", "config.yaml is missing; run `defenseclaw init` before generating a token")

    rotate_required = bool(getattr(cfg, "_doctor_gateway_token_rotation_required", False))
    active_connector = _active_connector(cfg)

    if active_connector == "openclaw" and not rotate_required:
        from defenseclaw.commands.cmd_setup import (
            _detect_openclaw_gateway_token,
            _save_secret_to_dotenv,
        )

        token = _normalized_gateway_token(_detect_openclaw_gateway_token(cfg.claw.config_file))
        if token:
            env_var = "OPENCLAW_GATEWAY_TOKEN"
            current = _gateway_dotenv_tokens(cfg.data_dir).get(env_var, "")
            if current == token:
                return ("skip", "token already persisted and in sync")
            if plan_only:
                return ("plan", f"persist {env_var} from the trusted OpenClaw configuration")
            if not assume_yes and not click.confirm(
                f"    Update {env_var} in ~/.defenseclaw/.env from OpenClaw?",
                default=True,
            ):
                return ("skip", "declined by user")
            _save_secret_to_dotenv(env_var, token, cfg.data_dir)
            return ("pass", f"{env_var} updated from openclaw.json")
        # OpenClaw can be local and unauthenticated while the DefenseClaw
        # sidecar still requires its own canonical token. Fall through to
        # canonical generation instead of leaving that sidecar broken.

    env_var = _CANONICAL_GATEWAY_TOKEN_ENV
    current, _current_env, _current_source = _daemon_effective_gateway_token(cfg)
    if current and not rotate_required:
        return ("skip", f"{env_var} already set")

    configured_env = (getattr(cfg.gateway, "token_env", "") or "").strip()
    if configured_env and not any(
        _env_names_equal(configured_env, allowed) for allowed in (_LEGACY_GATEWAY_TOKEN_ENV, env_var)
    ):
        if rotate_required:
            return (
                "fail",
                f"token_env={configured_env!r} is externally managed and may have "
                "been exposed; rotate that provider manually before restarting",
            )
        return ("skip", f"token_env={configured_env!r} is externally managed; not generating a replacement")

    action = "Rotate" if rotate_required else "Generate and store"
    if plan_only:
        verb = "rotate" if rotate_required else "generate"
        provider_effect = ""
        if rotate_required and _env_names_equal(
            configured_env,
            _LEGACY_GATEWAY_TOKEN_ENV,
        ):
            provider_effect = (
                f"; repoint gateway.token_env from {_LEGACY_GATEWAY_TOKEN_ENV!r} "
                f"to {_CANONICAL_GATEWAY_TOKEN_ENV!r} in config.yaml"
            )
        return (
            "plan",
            f"{verb} {env_var} in {os.path.join(cfg.data_dir, '.env')} "
            f"({'restart and authenticate replacement gateway' if rotate_required else 'value remains redacted'})"
            f"{provider_effect}",
        )
    if not assume_yes and not click.confirm(
        f"    {action} {env_var} in {cfg.data_dir}/.env?",
        default=True,
    ):
        return ("skip", "declined by user")

    import secrets

    token = secrets.token_hex(32)
    if rotate_required:
        return _rotate_exposed_gateway_token(cfg, token)

    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    try:
        _save_secret_to_dotenv(env_var, token, cfg.data_dir)
    except OSError as exc:
        return ("fail", f"could not persist gateway token: {exc}")
    return ("pass", f"generated {env_var} in {os.path.join(cfg.data_dir, '.env')} (value redacted)")


def _rotate_exposed_gateway_token(cfg, token: str) -> tuple[str, str]:
    """Rotate an exposed token across one fail-closed A/B lifecycle boundary."""
    from defenseclaw.commands.cmd_setup import _rotate_token_transaction
    from defenseclaw.context import AppContext

    gateway = getattr(cfg, "gateway", None)
    configured_env = str(getattr(gateway, "token_env", "") or "").strip()
    repointed = bool(configured_env) and _env_names_equal(
        configured_env,
        _LEGACY_GATEWAY_TOKEN_ENV,
    )

    # The transaction starts B from an authoritative reload of config.yaml.
    # Repoint the one supported legacy provider before taking its snapshot so
    # B cannot reload the still-exposed legacy value. Custom providers were
    # rejected by _fix_gateway_token before this helper is reached.
    if repointed:
        try:
            gateway.token_env = _CANONICAL_GATEWAY_TOKEN_ENV
            cfg.save()
        except (OSError, AttributeError):
            gateway.token_env = configured_env
            return (
                "fail",
                "could not repoint the legacy gateway token provider before the fail-closed rotation transaction",
            )

    app = AppContext()
    app.cfg = cfg
    dotenv_path = os.path.join(cfg.data_dir, ".env")
    try:
        _rotate_token_transaction(
            app,
            dotenv_path,
            token,
            "action=doctor-exposure-rotation restart=true",
            recover_previous_runtime=False,
        )
    except Exception as exc:  # noqa: BLE001 - redact transaction internals.
        restore_failed = False
        if repointed:
            gateway.token_env = configured_env
            try:
                cfg.save()
            except (OSError, AttributeError):
                restore_failed = True
        detail = (
            "exposed-token rotation did not reach verified gateway B; "
            "the compromised generation was not intentionally restarted"
        )
        if restore_failed:
            detail += "; the prior gateway.token_env could not be restored"
        return ("fail", f"{detail} ({type(exc).__name__})")

    # Keep this Doctor process aligned with B. If the value came from a stale
    # parent export, _doctor_stale_parent_gateway_env_names still preserves the
    # actionable warning for subsequent shells.
    os.environ[_CANONICAL_GATEWAY_TOKEN_ENV] = token
    setattr(cfg, "_doctor_gateway_token_was_rotated", True)
    setattr(cfg, "_doctor_gateway_token_activation_verified", True)
    setattr(
        cfg,
        "_doctor_stale_parent_gateway_env_names",
        tuple(getattr(cfg, "_doctor_external_gateway_env_names", ())),
    )
    return (
        "pass",
        f"rotated {_CANONICAL_GATEWAY_TOKEN_ENV} in {dotenv_path} after prior "
        "read exposure; gateway B reached verified readiness (value redacted)",
    )


def _fix_gateway_token_env(
    cfg,
    *,
    assume_yes: bool,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Repoint ``cfg.gateway.token_env`` at the canonical var when stale.

    Companion to :func:`_check_gateway_token_env_alignment`. The check
    just flags drift; this fixer actually rewrites
    ``cfg.gateway.token_env`` from the legacy ``OPENCLAW_GATEWAY_TOKEN``
    (or any other empty-in-env value) to ``DEFENSECLAW_GATEWAY_TOKEN``
    when the latter is populated. Saves config.yaml in place.

    Returns ``("skip", ...)`` when no fix is needed (config already
    aligned, or no canonical token to repoint AT), ``("pass", ...)``
    when the rewrite lands successfully, ``("fail", ...)`` on write
    error.

    Why ``cfg.save()`` and not a surgical YAML patch: ``GatewayConfig``
    is a small dataclass and the save round-trips through the
    canonical writer — this guarantees the field is serialized the
    same way as anywhere else in the codebase. Surgical patching
    would diverge from the live config schema if a future field is
    added between writes.
    """
    gw = getattr(cfg, "gateway", None)
    if gw is None:
        return ("skip", "no gateway config")
    if not _doctor_config_present(cfg):
        return ("skip", "config.yaml is missing; refusing to create it from an auto-fix")

    configured_env = getattr(gw, "token_env", "") or ""
    canonical = "DEFENSECLAW_GATEWAY_TOKEN"
    exposure_rotation = bool(getattr(cfg, "_doctor_gateway_token_was_rotated", False))
    projected_state_keys = set(
        getattr(cfg, "_doctor_projected_repair_state_keys", ())
    )
    canonical_projected = "gateway-token-canonical-present" in projected_state_keys

    # Already on the canonical name — nothing to do, regardless of whether
    # the value is populated. The missing-value fixer owns that case.
    if _env_names_equal(configured_env, canonical):
        return ("skip", f"token_env already set to {canonical}")
    if (
        plan_only
        and canonical_projected
        and bool(getattr(cfg, "_doctor_gateway_token_rotation_required", False))
        and _env_names_equal(configured_env, _LEGACY_GATEWAY_TOKEN_ENV)
    ):
        return (
            "skip",
            "the preceding exposed-token rotation plan already discloses and "
            f"performs the gateway.token_env repoint to {canonical}",
        )

    # A populated configured provider is working and retains precedence. In
    # particular, do not rewrite an active OpenClaw token merely because the
    # canonical fallback is also present.
    if not exposure_rotation and configured_env and _normalized_gateway_token(os.environ.get(configured_env, "")):
        return ("skip", f"configured token provider {configured_env} is populated")

    # Don't touch a custom operator override. Only auto-repoint the
    # legacy OPENCLAW_ default.
    if configured_env and not _env_names_equal(configured_env, "OPENCLAW_GATEWAY_TOKEN"):
        return (
            "skip",
            f"token_env={configured_env!r} is a custom override; not auto-rewriting",
        )

    # Only proceed when the canonical var is actually populated —
    # otherwise we'd be repointing at another empty var, which buys
    # nothing and obscures the underlying "no token anywhere" state.
    if not _normalized_gateway_token(os.environ.get(canonical, "")) and not canonical_projected:
        return ("skip", f"{canonical} is not set; nothing to repoint at")

    if plan_only:
        return (
            "plan",
            f"repoint gateway.token_env from {configured_env!r} to {canonical!r} in config.yaml",
        )

    if not assume_yes and not click.confirm(
        f"    Repoint cfg.gateway.token_env from {configured_env!r} to {canonical!r} in config.yaml?",
        default=True,
    ):
        return ("skip", "declined by user")

    try:
        gw.token_env = canonical
        cfg.save()
    except (OSError, AttributeError) as exc:
        gw.token_env = configured_env
        return ("fail", f"could not save config: {type(exc).__name__}: {exc}")

    return ("pass", f"token_env repointed to {canonical}")


def _gateway_lifecycle_selection(
    cfg,
    *,
    search_path: str | None = None,
) -> _GatewayLifecycleSelection:
    """Select the exact executable used by compatibility and lifecycle work."""
    from defenseclaw.commands.cmd_setup import (
        _gateway_lifecycle_executable,
        _trusted_gateway_lifecycle_executable,
    )

    process_trust = _managed_gateway_process_trust_for_lifecycle(cfg)
    if (
        process_trust.trusted
        and process_trust.record is not None
        and not process_trust.authenticated_migration
    ):
        candidate = process_trust.record.executable
        if not candidate or not os.path.isabs(candidate):
            return _GatewayLifecycleSelection(None, True)
        executable = _trusted_gateway_lifecycle_executable(
            str(os.path.realpath(candidate))
        )
        return _GatewayLifecycleSelection(executable, True)

    return _GatewayLifecycleSelection(
        _gateway_lifecycle_executable(search_path=search_path),
        False,
    )


def _repair_gateway_lifecycle(cfg, *, start_if_stopped: bool) -> tuple[bool, str]:
    """Run setup's ownership-aware gateway lifecycle in the selected home.

    The setup boundary resolves the verified packaged Windows sibling instead
    of trusting PATH, validates live PID identity before a restart, and waits
    for API readiness.  Pin all supported home/config variables so a Doctor
    process launched from another checkout cannot repair the wrong install.
    Presentation is captured to preserve ``doctor --json-output``.
    """
    from defenseclaw.commands.cmd_setup import (
        _restart_defense_gateway,
        _rotate_token_child_environment,
    )
    from defenseclaw.config import config_path_for_data_dir

    data_dir = os.path.abspath(cfg.data_dir)
    config_file = str(config_path_for_data_dir(data_dir))
    token, token_env_name, _token_source = _daemon_effective_gateway_token(cfg)
    child_env = _rotate_token_child_environment(data_dir, config_file, token)
    if token_env_name and (not dotenv_key_is_valid(token_env_name) or dotenv_key_is_process_control(token_env_name)):
        return False, "configured gateway token_env is unsafe for lifecycle execution"
    if token and token_env_name:
        child_env[token_env_name] = token

    selection = _gateway_lifecycle_selection(
        cfg,
        search_path=child_env.get("PATH", os.defpath),
    )
    if selection.executable is None:
        if selection.requires_running_process:
            return False, "verified running gateway executable is unavailable"
        return False, "binary not found"
    from defenseclaw.commands.cmd_setup import _trusted_gateway_lifecycle_executable

    revalidated_executable = _trusted_gateway_lifecycle_executable(
        selection.executable
    )
    if (
        revalidated_executable is None
        or os.path.normcase(os.path.abspath(revalidated_executable))
        != os.path.normcase(os.path.abspath(selection.executable))
    ):
        if selection.requires_running_process:
            return False, "verified running gateway executable is unavailable"
        return False, "binary not found"
    try:
        compatibility_problems = _component_compatibility_problems_for_executable(
            cfg,
            revalidated_executable,
        )
    except Exception:
        # Preserve the compatibility gate's fail-open-on-unknown policy:
        # only positive unsupported evidence blocks lifecycle work.
        compatibility_problems = ()
    if compatibility_problems:
        from defenseclaw.doctor_health import HealthStatus

        if any(
            finding.status is HealthStatus.UNSUPPORTED
            for finding in compatibility_problems
        ):
            return (
                False,
                "selected lifecycle components are positively unsupported",
            )

    managed_env = {
        "DEFENSECLAW_HOME": data_dir,
        "DEFENSECLAW_DATA_DIR": data_dir,
        "DEFENSECLAW_CONFIG": config_file,
    }
    previous_env = {name: os.environ.get(name) for name in managed_env}
    output = io.StringIO()
    try:
        os.environ.update(managed_env)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            repaired = _restart_defense_gateway(
                data_dir,
                start_if_stopped=start_if_stopped,
                child_env=child_env,
                lifecycle_executable=revalidated_executable,
                lifecycle_executable_requires_running=selection.requires_running_process,
            )
    finally:
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    rendered = " ".join(output.getvalue().split())
    safe_reasons = (
        "live gateway.pid did not verify as DefenseClaw gateway",
        "binary not found",
        "API health timed out",
        "ready after launcher timeout",
        "timed out; final status is not healthy",
        "not running — skipping restart",
        "verified running executable is no longer active",
        "binary is not a verified executable file",
    )
    reason = next((candidate for candidate in safe_reasons if candidate in rendered), "")
    if not repaired and not reason:
        reason = "managed lifecycle did not reach verified readiness"
    return repaired, reason


def _fix_gateway_token_drift(
    cfg,
    *,
    assume_yes: bool,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Restart the sidecar when its in-memory token != current .env.

    Companion to :func:`_check_gateway_token_drift`. The check just
    flags the drift; this fixer offers to bounce the sidecar so it
    re-reads the dotenv and starts serving the current token. We
    deliberately do NOT touch the dotenv itself — the operator's
    intent is preserved.

    Why a restart and not an in-place token reload: the sidecar
    holds the token in memory in a dozen places (auth middleware,
    connector credentials, hook scripts cached on disk). A
    SIGHUP-style reload would have to walk all of those; a clean
    restart is the only honest fix.

    Returns ``("skip", ...)`` when there's nothing to fix (no drift
    detected, no live sidecar, can't introspect), ``("pass", ...)``
    on successful restart, ``("fail", ...)`` when the restart
    invocation errors out.
    """
    if not _doctor_config_present(cfg):
        return ("skip", "config.yaml is missing; refusing to restart an uninitialized gateway")

    projected_repairs = set(getattr(cfg, "_doctor_projected_repair_ids", ()))
    if plan_only and "doctor.gateway.pid.remove-stale" in projected_repairs:
        return (
            "skip",
            "the preceding stale-PID removal plan establishes that no managed "
            "gateway generation remains to reconcile",
        )
    if (
        plan_only
        and "doctor.gateway.token.ensure" in projected_repairs
        and bool(getattr(cfg, "_doctor_gateway_token_rotation_required", False))
    ):
        return (
            "skip",
            "the preceding exposed-token rotation plan already performs the "
            "gateway A/B restart and authenticated replacement verification",
        )

    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    process_trust = _managed_gateway_process_trust_for_lifecycle(cfg)
    if process_trust.code in {"missing", "missing_process"}:
        return ("skip", "no live sidecar to restart")
    if not process_trust.trusted:
        return (
            "fail",
            f"{process_trust.detail}; refusing to send credentials or restart. "
            "Stop an older unbound generation through the trusted service "
            "manager that launched it, verify it exited, then rerun "
            "`defenseclaw doctor --fix` to remove the stale record and start "
            "a current bound generation.",
        )
    pid = process_trust.pid
    inspected_fingerprint = pid_file_fingerprint(pid_file)
    if not inspected_fingerprint:
        return ("fail", "gateway PID record is unsafe or changed during inspection")

    probe_token, token_env_name, token_source = _daemon_effective_gateway_token(cfg)
    if not probe_token:
        projected_state_keys = set(
            getattr(cfg, "_doctor_projected_repair_state_keys", ())
        )
        known_token_projected = bool(
            projected_state_keys
            & {
                "gateway-token-canonical-present",
                "gateway-token-legacy-present",
            }
        )
        if plan_only and known_token_projected:
            listener_trust = _trusted_gateway_listener(cfg)
            if listener_trust.code in {"foreign_listener", "ambiguous_listener"}:
                return (
                    "fail",
                    f"{listener_trust.detail}; refusing to plan a credential-bearing restart",
                )
            if not listener_trust.trusted and listener_trust.code not in {
                "missing_listener",
                "unavailable",
            }:
                return (
                    "fail",
                    f"{listener_trust.detail}; refusing automatic authentication repair",
                )
            return (
                "plan",
                f"restart verified sidecar pid {pid} after the preceding managed "
                "token persistence, then authenticate and verify the replacement; "
                "no placeholder credential was sent during planning",
            )
        return ("skip", "no configured gateway token to reconcile")

    # The authenticated endpoint is authoritative, but a master token is sent
    # only after exact listener/PID/home identity is proven. Listener-only
    # uncertainty may fall back to read-only process-environment evidence, but
    # identity, home, foreign-owner, and ambiguity failures never authorize a
    # lifecycle mutation.
    auth_rejected = False
    trust = _trusted_gateway_listener_for_lifecycle(cfg)
    if trust.code in {"foreign_listener", "ambiguous_listener"}:
        return (
            "fail",
            f"{trust.detail}; refusing to send the configured token",
        )
    if trust.trusted:
        code, body = _http_probe(
            _gateway_api_url(cfg, "/status"),
            headers={"Authorization": f"Bearer {probe_token}"},
            timeout=3.0,
            response_limit=64 * 1024,
            allow_truncation=False,
            bypass_proxy=True,
        )
        if code == 200:
            runtime_ok, runtime_detail = _authenticated_runtime_matches(cfg, trust.pid, body)
            if runtime_ok:
                return ("skip", "gateway already accepts the configured token")
            return ("fail", runtime_detail)
        auth_rejected = code in {401, 403, 503}
        if not auth_rejected:
            detail = "transport failure" if code == 0 else f"HTTP {code}"
            return (
                "fail",
                f"trusted gateway authentication verification was unavailable ({detail}); "
                "refusing to restart based only on process-environment evidence",
            )
    elif trust.code not in {"missing_listener", "unavailable"}:
        return (
            "fail",
            f"{trust.detail}; refusing automatic authentication repair",
        )

    if not auth_rejected:
        if not token_env_name:
            return ("skip", f"authentication could not be verified ({trust.detail})")
        process_token = _read_process_env_var(pid, token_env_name)
        if process_token is None:
            return ("skip", f"could not inspect sidecar pid {pid} env or verify authentication")
        process_token = _normalized_gateway_token(process_token)
        if not process_token:
            return ("skip", f"sidecar pid {pid} has no inspectable {token_env_name} value")
        if process_token == probe_token:
            return ("skip", "sidecar token already matches the daemon-effective token")

    if plan_only:
        return (
            "plan",
            f"restart verified sidecar pid {pid} and authenticate the replacement "
            f"with the {token_source or 'configured token'}",
        )

    if not assume_yes and not click.confirm(
        f"    Restart sidecar (pid {pid}) to pick up the {token_source or 'configured token'}? "
        "In-flight requests will be interrupted.",
        default=True,
    ):
        return ("skip", "declined by user")

    if pid_file_fingerprint(pid_file) != inspected_fingerprint:
        return (
            "fail",
            "gateway PID record changed after verification; refusing to restart a replacement",
        )
    repaired, lifecycle_detail = _repair_gateway_lifecycle(cfg, start_if_stopped=False)
    if not repaired:
        return (
            "fail",
            f"gateway restart or readiness verification failed ({lifecycle_detail}); run `defenseclaw-gateway status`",
        )

    # A public /health readiness result is not enough to claim authentication
    # repair. Re-resolve the daemon-effective token and verify it against the
    # replacement process using the strongest evidence available.
    replacement_token, _replacement_env, _replacement_source = _daemon_effective_gateway_token(cfg)
    if not replacement_token:
        return ("fail", "gateway restarted but no daemon-effective token remains configured")
    replacement_trust = _trusted_gateway_listener(cfg)
    if not replacement_trust.trusted:
        return (
            "fail",
            "gateway restarted but replacement endpoint ownership/authentication "
            f"could not be verified ({replacement_trust.detail})",
        )
    code, body = _http_probe(
        _gateway_api_url(cfg, "/status"),
        headers={"Authorization": f"Bearer {replacement_token}"},
        timeout=3.0,
        response_limit=64 * 1024,
        allow_truncation=False,
        bypass_proxy=True,
    )
    if code != 200:
        return ("fail", f"gateway restarted but still rejects configured authentication (HTTP {code})")
    runtime_ok, runtime_detail = _authenticated_runtime_matches(
        cfg,
        replacement_trust.pid,
        body,
    )
    if not runtime_ok:
        return ("fail", runtime_detail)
    return ("pass", "sidecar restarted and authenticated token acceptance was verified")


def _gateway_service_health_assessment(cfg, health: dict) -> tuple[str, str]:
    """Classify health without treating operational failures as stale config.

    Returns ``(kind, detail)`` where kind is ``healthy``, ``repairable``,
    ``operational``, or ``invalid``.  Only deterministic on-disk/runtime
    divergence is repairable; reconnecting/error/starting states generally
    depend on an upstream service and must remain diagnostics, not restart
    loops.
    """
    healthy_states = {"running", "healthy"}
    inactive_states = {"disabled", "stopped"}
    repair_reasons: list[str] = []
    operational_reasons: list[str] = []
    invalid_reasons: list[str] = []

    api = health.get("api")
    if not isinstance(api, dict):
        return ("invalid", "required api subsystem is absent from health")
    api_state = api.get("state", api.get("status", ""))
    if not isinstance(api_state, str):
        return ("invalid", "required api subsystem has malformed health state")
    api_state = api_state.strip().lower()
    if api_state in inactive_states:
        repair_reasons.append(f"required api subsystem reports {api_state}")
    elif api_state not in healthy_states:
        operational_reasons.append(f"required api subsystem reports {api_state or 'unknown'}")

    for subsystem in ("gateway", "watcher", "telemetry", "guardrail", "sandbox"):
        info = health.get(subsystem)
        expected = _subsystem_expected_enabled(cfg, subsystem)
        if not isinstance(info, dict):
            if expected is True:
                invalid_reasons.append(f"{subsystem} is enabled in config but absent from health")
            continue
        raw_state = info.get("state", info.get("status", ""))
        if not isinstance(raw_state, str):
            invalid_reasons.append(f"{subsystem} has malformed health state")
            continue
        state = raw_state.strip().lower()

        if expected is True and state in inactive_states:
            repair_reasons.append(f"{subsystem} is enabled in config but reports {state}")
        elif (
            expected is False
            and subsystem
            in {
                "gateway",
                "watcher",
                "guardrail",
                "sandbox",
            }
            and state in healthy_states
        ):
            repair_reasons.append(f"{subsystem} is disabled in config but reports {state}")
        elif state not in healthy_states | inactive_states:
            operational_reasons.append(f"{subsystem} reports {state or 'unknown'}")

    if invalid_reasons:
        return ("invalid", "; ".join(invalid_reasons))
    if operational_reasons:
        return ("operational", "; ".join(operational_reasons))
    if repair_reasons:
        return ("repairable", "; ".join(repair_reasons))
    return ("healthy", "gateway health matches the current configuration")


def _gateway_service_health_repair_reason(cfg, health: dict) -> str:
    """Compatibility view returning only deterministic repairable drift."""
    kind, detail = _gateway_service_health_assessment(cfg, health)
    return detail if kind == "repairable" else ""


def _gateway_restart_cooldown_remaining(
    trust: _GatewayTrust,
    *,
    now: float | None = None,
    cooldown_seconds: float = 60.0,
) -> int:
    """Return a bounded cooldown for a recently started managed generation."""

    record = trust.record
    if not trust.trusted or record is None or not record.start_time:
        return 0
    try:
        started_at = float(record.start_time)
    except (TypeError, ValueError, OverflowError):
        return 0
    current = time.time() if now is None else now
    age = current - started_at
    if age < 0 or age >= cooldown_seconds:
        return 0
    return max(1, int(cooldown_seconds - age))


def _fix_gateway_service(
    cfg,
    *,
    assume_yes: bool,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Start an absent gateway or restart one with stale subsystem state."""
    if not _doctor_config_present(cfg):
        return ("skip", "config.yaml is missing; run `defenseclaw init` before starting the gateway")

    projected_repairs = set(getattr(cfg, "_doctor_projected_repair_ids", ()))
    if plan_only and "doctor.gateway.token.reconcile-runtime" in projected_repairs:
        return (
            "skip",
            "the preceding runtime-token reconciliation plan already restarts "
            "and verifies the managed gateway; service health will be re-evaluated afterward",
        )
    if (
        plan_only
        and "doctor.gateway.token.ensure" in projected_repairs
        and bool(getattr(cfg, "_doctor_gateway_token_rotation_required", False))
    ):
        return (
            "skip",
            "the preceding exposed-token rotation plan already performs and "
            "verifies the gateway A/B restart; service health will be re-evaluated afterward",
        )
    stale_pid_projected = (
        plan_only and "doctor.gateway.pid.remove-stale" in projected_repairs
    )

    code, body = _http_probe(
        _gateway_api_url(cfg, "/health"),
        timeout=3.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
        bypass_proxy=True,
    )

    reason = ""
    process_trust: _GatewayTrust | None = None
    inspected_fingerprint: tuple[int, int, int, int, bytes] | None = None
    if code == 200:
        try:
            health = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return ("skip", "gateway is reachable; health details are not parseable")
        if not isinstance(health, dict):
            return ("skip", "gateway is reachable; health details are not an object")
        health_kind, reason = _gateway_service_health_assessment(cfg, health)
        if health_kind == "healthy":
            return ("skip", "gateway service already healthy and current")
        if health_kind in {"operational", "invalid"}:
            return (
                "skip",
                f"gateway is reachable but {reason}; automatic restart was not attempted",
            )
        endpoint_trust = _trusted_gateway_listener_for_lifecycle(cfg)
        if not endpoint_trust.trusted:
            return (
                "fail",
                f"gateway health suggests repair, but {endpoint_trust.detail}; refusing lifecycle mutation",
            )
        process_trust = endpoint_trust
        inspected_fingerprint = pid_file_fingerprint(os.path.join(cfg.data_dir, "gateway.pid"))
    else:
        if code != 0:
            return (
                "fail",
                f"configured gateway endpoint returned HTTP {code} without a valid health document; "
                "refusing automatic startup/restart",
            )
        reason = "gateway service is unreachable"
        process_trust = _managed_gateway_process_trust_for_lifecycle(cfg)
        pid_path = os.path.join(cfg.data_dir, "gateway.pid")
        listener = _managed_gateway_listener_evidence(
            _gateway_api_port(cfg),
            host=_gateway_api_host(cfg),
        )
        if stale_pid_projected:
            process_trust = _GatewayTrust(
                "missing",
                "preceding repair plan removes positively stale managed PID state",
            )
        if process_trust.trusted:
            inspected_fingerprint = pid_file_fingerprint(pid_path)
            if listener.status == "ok" and listener.pid != process_trust.pid:
                return (
                    "fail",
                    "configured API endpoint is owned by another process; refusing to restart the managed gateway",
                )
            if listener.status in {"ambiguous", "denied", "unavailable"}:
                return (
                    "fail",
                    f"{listener.reason or 'configured API endpoint ownership is unavailable'}; "
                    "refusing to restart the managed gateway",
                )
        elif process_trust.code == "missing":
            if listener.status != "missing":
                return (
                    "fail",
                    f"{listener.reason or 'configured API endpoint ownership is unavailable'}; "
                    "refusing to start a potentially conflicting gateway",
                )
        else:
            return (
                "fail",
                f"{process_trust.detail}; refusing automatic gateway startup/restart. "
                "Run `defenseclaw doctor --fix` again after reconciling gateway.pid.",
            )

    pid = process_trust.pid if process_trust and process_trust.trusted else 0
    if process_trust and (cooldown := _gateway_restart_cooldown_remaining(process_trust)):
        return (
            "warn",
            f"managed gateway generation started recently; restart cooldown has {cooldown}s remaining",
        )
    if pid and not inspected_fingerprint:
        return ("fail", "gateway PID record changed or is unsafe; refusing lifecycle mutation")
    action = "restart" if pid else "start"
    if plan_only:
        return (
            "plan",
            f"{action} the verified managed gateway because {reason}; "
            "verify replacement listener ownership and complete health",
        )
    if not assume_yes and not click.confirm(
        f"    {action.capitalize()} the gateway because {reason}?",
        default=True,
    ):
        return ("skip", "declined by user")

    if pid and pid_file_fingerprint(os.path.join(cfg.data_dir, "gateway.pid")) != inspected_fingerprint:
        return (
            "fail",
            "gateway PID record changed after verification; refusing to restart a replacement",
        )
    repaired, lifecycle_detail = _repair_gateway_lifecycle(cfg, start_if_stopped=True)
    if not repaired:
        return (
            "fail",
            f"could not {action} gateway service ({lifecycle_detail}); run `defenseclaw-gateway status`",
        )

    verified_code, verified_body = _http_probe(
        _gateway_api_url(cfg, "/health"),
        timeout=3.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
        bypass_proxy=True,
    )
    if verified_code != 200:
        return (
            "fail",
            f"gateway {action}ed but the complete health document is unavailable (HTTP {verified_code})",
        )
    try:
        verified_health = json.loads(verified_body)
    except (json.JSONDecodeError, TypeError):
        return ("fail", f"gateway {action}ed but its health document is not parseable")
    if not isinstance(verified_health, dict):
        return ("fail", f"gateway {action}ed but its health document is not an object")
    verified_api = verified_health.get("api")
    verified_api_state = (
        verified_api.get("state", verified_api.get("status", "")) if isinstance(verified_api, dict) else ""
    )
    if not isinstance(verified_api_state, str) or verified_api_state.strip().lower() not in {
        "running",
        "healthy",
    }:
        return ("fail", f"gateway {action}ed but the local API is not ready")
    verified_kind, verified_detail = _gateway_service_health_assessment(cfg, verified_health)
    if verified_kind in {"repairable", "invalid"}:
        return (
            "fail",
            f"gateway {action}ed but repair did not converge: {verified_detail}",
        )
    replacement_trust = _trusted_gateway_listener(cfg)
    if not replacement_trust.trusted:
        return (
            "fail",
            f"gateway {action}ed but replacement ownership did not converge: {replacement_trust.detail}",
        )
    if verified_kind == "operational":
        return (
            "warn",
            f"gateway service {action}ed and ownership verified; {verified_detail}",
        )
    return ("pass", f"gateway service {action}ed: {reason}")


def _fix_dotenv_perms(
    cfg,
    *,
    assume_yes: bool,
    platform_name: str | None = None,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Protect the dotenv with POSIX 0600 or a private Windows DACL."""
    from defenseclaw.file_permissions import (
        protect_private_file,
        windows_acl_confidentiality_error,
        windows_acl_write_error,
    )

    data_dir = _configured_gateway_data_dir(cfg)
    if not data_dir:
        return (
            "fail",
            "gateway data directory is unavailable; refusing to repair or consume dotenv credentials",
        )
    if data_dir_problem := _gateway_data_dir_integrity_problem(cfg):
        return (
            "fail",
            f"{data_dir_problem}; refusing to repair or consume dotenv credentials",
        )
    path = os.path.join(data_dir, ".env")
    try:
        if is_symlink(path):
            return ("fail", "dotenv is a symbolic link or reparse point; refusing permission repair")
        info = os.lstat(path)
    except FileNotFoundError:
        return ("skip", "no dotenv file")
    except OSError as exc:
        return ("warn", f"dotenv could not be safely inspected: {type(exc).__name__}")
    reparse_point = 0x400
    if getattr(info, "st_file_attributes", 0) & reparse_point:
        return ("fail", "dotenv is a symbolic link or reparse point; refusing permission repair")
    if not stat.S_ISREG(info.st_mode):
        return ("fail", "dotenv is not a regular file; refusing permission repair")

    platform_name = platform_name or sys.platform
    if platform_name in {"nt", "win32"}:
        problem = windows_acl_confidentiality_error(path)
        integrity_problem = windows_acl_write_error(path)
        if integrity_problem is not None:
            return (
                "fail",
                f"dotenv integrity is untrusted ({integrity_problem}); refusing to "
                "bless or consume its contents. Review the file, replace it securely, "
                "then rerun Doctor.",
            )
        if problem is not None and "read access" in problem.lower():
            setattr(cfg, "_doctor_gateway_token_rotation_required", True)
            if plan_only:
                return (
                    "plan",
                    "replace the read-exposed dotenv through the dependent "
                    "gateway-token rotation transaction and apply a private Windows DACL",
                )
            return (
                "warn",
                "dotenv ACL exposed its contents; leaving the file unchanged until "
                "the gateway-token fixer can atomically replace it with a rotated "
                "token and private DACL. Rotate any other credentials stored in it.",
            )
        if problem is None:
            try:
                current = os.lstat(path)
            except OSError:
                return ("warn", "dotenv changed while its Windows DACL was inspected")
            if is_symlink(path) or not os.path.samestat(info, current):
                return ("warn", "dotenv changed while its Windows DACL was inspected")
            return ("skip", "permissions already use a private Windows DACL")
        if plan_only:
            return ("plan", f"protect {path} with a private Windows DACL")
        if not assume_yes and not click.confirm(
            f"    Tighten the Windows ACL on {path}?",
            default=True,
        ):
            return ("skip", "declined by user")
        try:
            protect_private_file(path)
            remaining_problem = windows_acl_confidentiality_error(path)
        except OSError as exc:
            return ("fail", f"could not protect dotenv with a private Windows DACL: {exc}")
        if remaining_problem is not None:
            return ("fail", f"dotenv Windows ACL remains unsafe: {remaining_problem}")
        return ("pass", f"protected {path} with a private Windows DACL")

    mode = info.st_mode & 0o777
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and info.st_uid != geteuid():
        return (
            "fail",
            "dotenv is not owned by the current user; refusing permission or credential repair",
        )
    if mode & 0o022:
        return (
            "fail",
            "dotenv was writable by another local principal; refusing to bless or "
            "consume its contents. Review the file, replace it securely, then rerun Doctor.",
        )
    acl_write_problem = darwin_acl_write_error(path) if platform_name == "darwin" else None
    if acl_write_problem is not None:
        return (
            "fail",
            f"dotenv integrity is untrusted ({acl_write_problem}); refusing to bless "
            "or consume its contents. Review the file, replace it securely, then rerun Doctor.",
        )
    acl_read_problem = darwin_acl_confidentiality_error(path) if platform_name == "darwin" else None
    if mode & 0o044 or acl_read_problem is not None:
        setattr(cfg, "_doctor_gateway_token_rotation_required", True)
        if plan_only:
            return (
                "plan",
                "replace the read-exposed dotenv through the dependent "
                "gateway-token rotation transaction and enforce mode 0600",
            )
        return (
            "warn",
            "dotenv permissions exposed its contents; leaving the file unchanged "
            "until the gateway-token fixer can atomically replace it with a rotated "
            "token and mode 0600. Rotate any other credentials stored in it.",
        )
    if mode == 0o600 and acl_read_problem is None:
        try:
            current = os.lstat(path)
        except OSError:
            return ("warn", "dotenv changed while its permissions were inspected")
        if is_symlink(path) or not os.path.samestat(info, current):
            return ("warn", "dotenv changed while its permissions were inspected")
        return ("skip", "permissions already 0600")

    prompt = f"    Tighten {path} permissions from {mode:04o} to 0600?"
    if acl_read_problem:
        prompt = f"    Remove the read-capable extended ACL from {path} and enforce 0600?"
    if plan_only:
        return ("plan", f"enforce owner-only permissions on {path}")
    if not assume_yes and not click.confirm(prompt, default=True):
        return ("skip", "declined by user")

    try:
        protect_private_file(path)
        repaired = os.lstat(path)
        if is_symlink(path) or not stat.S_ISREG(repaired.st_mode) or not os.path.samestat(info, repaired):
            return ("fail", "dotenv changed while its repaired permissions were verified")
        if stat.S_IMODE(repaired.st_mode) != 0o600:
            return ("fail", f"dotenv permissions on {path} are still not 0600 after repair")
        remaining_acl_problem = darwin_acl_confidentiality_error(path) if platform_name == "darwin" else None
        if remaining_acl_problem is not None:
            return ("fail", f"dotenv extended ACL remains unsafe: {remaining_acl_problem}")
        verified = os.lstat(path)
        if not os.path.samestat(repaired, verified) or stat.S_IMODE(verified.st_mode) != 0o600:
            return ("fail", "dotenv changed while its repaired permissions were verified")
        return ("pass", f"set {path} to 0600")
    except OSError as exc:
        return ("fail", f"chmod failed: {exc}")


def _fix_pristine_backup(
    cfg,
    *,
    assume_yes: bool,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Capture a pristine backup of the active connector's config if one
    isn't recorded yet.

    For openclaw: backs up openclaw.json via the guardrail module.
    For other connectors: checks for their respective backup files in
    the data directory.
    """
    del assume_yes  # unused: capturing a snapshot is always safe
    if not _doctor_config_present(cfg):
        return ("skip", "config.yaml is missing; refusing to snapshot an uninitialized install")
    active_connector = _active_connector(cfg)

    if active_connector == "openclaw":
        from defenseclaw.guardrail import (
            pristine_backup_path,
            record_pristine_backup,
        )

        oc_path = cfg.claw.config_file
        if not oc_path:
            return ("skip", "no openclaw.json configured")
        if not os.path.isfile(os.path.expanduser(oc_path)):
            return ("skip", "openclaw.json not present")
        existing = pristine_backup_path(oc_path, cfg.data_dir)
        if existing:
            return ("skip", f"already captured at {existing}")
        if plan_only:
            return ("plan", f"capture a pristine OpenClaw configuration backup for {oc_path}")
        created = record_pristine_backup(oc_path, cfg.data_dir)
        if created:
            return ("pass", f"captured pristine backup at {created}")
        return ("warn", "could not capture backup (permissions?)")

    backup_names = _CONNECTOR_RESIDUE_ARTIFACTS.get(active_connector)
    if not backup_names:
        return ("skip", f"no backup strategy for connector {active_connector}")
    for backup_name in backup_names:
        backup_path = os.path.join(cfg.data_dir, backup_name)
        if os.path.isfile(backup_path):
            return ("skip", f"backup exists at {backup_path}")
    return ("skip", "no backup found — run `defenseclaw setup guardrail` to create one")


def _fix_plugin_registry_required(
    cfg,
    *,
    assume_yes: bool,
    plan_only: bool = False,
) -> tuple[str, str]:
    """Clear a dead-end ``asset_policy.plugin.registry_required=true``.

    Companion to :func:`_check_plugin_registry_required`. Resets the flag to
    ``False`` (global) / ``None`` (per-connector inherit) everywhere it is
    explicitly on, then saves config.yaml. No plugin-registry pipeline exists
    in v1, so the flag can only ever deny — clearing it is always safe and
    non-disruptive (config write only; no sidecar restart).

    Returns ``("skip", …)`` when nothing is set, ``("pass", …)`` on a
    successful rewrite, ``("fail", …)`` on write error. (OTHER-5)
    """
    offenders = _plugin_registry_required_offenders(cfg)
    if not offenders:
        return ("skip", "no plugin.registry_required flag set")

    if plan_only:
        return (
            "plan",
            f"clear the dead-end plugin.registry_required flag for [{', '.join(offenders)}] in config.yaml",
        )

    if not assume_yes and not click.confirm(
        f"    Clear the dead-end plugin.registry_required flag for [{', '.join(offenders)}] in config.yaml?",
        default=True,
    ):
        return ("skip", "declined by user")

    if not _doctor_config_present(cfg):
        return ("skip", "config.yaml is missing; refusing to create it from an auto-fix")

    ap = getattr(cfg, "asset_policy", None)
    plugin = getattr(ap, "plugin", None)
    connector_plugins = [
        pc_plugin
        for pc in (getattr(ap, "connectors", None) or {}).values()
        if pc is not None
        and (pc_plugin := getattr(pc, "plugin", None)) is not None
        and getattr(pc_plugin, "registry_required", None) is True
    ]
    original_global = getattr(plugin, "registry_required", None) if plugin is not None else None
    original_connector_values = [
        (pc_plugin, getattr(pc_plugin, "registry_required", None)) for pc_plugin in connector_plugins
    ]
    try:
        if plugin is not None and bool(getattr(plugin, "registry_required", False)):
            plugin.registry_required = False
        for pc_plugin in connector_plugins:
            # Tri-state per-connector field: None = inherit the (now cleared)
            # global value, so reset to None rather than False.
            pc_plugin.registry_required = None
        cfg.save()
    except (OSError, AttributeError) as exc:
        if plugin is not None:
            plugin.registry_required = original_global
        for pc_plugin, original_value in original_connector_values:
            pc_plugin.registry_required = original_value
        return ("fail", f"could not save config: {type(exc).__name__}: {exc}")

    return ("pass", f"cleared plugin.registry_required [{', '.join(offenders)}]")


def _fix_connector_residue(cfg, *, assume_yes: bool) -> tuple[str, str]:
    """Run ``defenseclaw-gateway connector teardown`` for every inactive
    connector that still has artifacts on disk.

    Inactive-connector residue is detected with the same logic as
    :func:`_check_connector_residue`, then this fixer shells out to the
    S7.2 sentinel for each residual connector. The sentinel is the
    canonical place to do this — ``Connector.Teardown`` knows about
    hook scripts, env files, and config patches that the residue check
    can't reasonably enumerate. We never call the OpenClaw Python
    helpers here because the gateway sentinel handles every connector
    uniformly.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return ("skip", "no data dir configured")

    # Exclude the FULL active set so the teardown sentinel can never fire
    # against a live connector (D7) — the same rule the residue *check* uses.
    active_set = _residue_active_set(cfg, _active_connector(cfg))
    inactive_residue: list[str] = []
    for name, artifacts in _CONNECTOR_RESIDUE_ARTIFACTS.items():
        if name in active_set:
            continue
        if any(os.path.isfile(os.path.join(data_dir, f)) for f in artifacts):
            inactive_residue.append(name)

    if "openclaw" not in active_set:
        if any(os.path.isfile(os.path.join(data_dir, f)) for f in _OPENCLAW_RESIDUE_ARTIFACTS):
            inactive_residue.append("openclaw")
        oc_path = getattr(getattr(cfg, "claw", None), "config_file", "") or ""
        oc_path = os.path.expanduser(oc_path)
        if oc_path and os.path.isfile(oc_path + ".pristine"):
            inactive_residue.append("openclaw")

    if not inactive_residue:
        return ("skip", "no inactive-connector residue detected")

    inactive_residue = sorted(set(inactive_residue))

    if not assume_yes and not click.confirm(
        f"    Run 'defenseclaw-gateway connector teardown' for {', '.join(inactive_residue)}?",
        default=True,
    ):
        return ("skip", "declined by user")

    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return ("warn", "defenseclaw-gateway not on PATH — install the binary and re-run")

    cleaned: list[str] = []
    failed: list[str] = []
    import subprocess as _sub

    for name in inactive_residue:
        try:
            proc = _sub.run(
                [gw, "connector", "teardown", "--connector", name],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, _sub.TimeoutExpired) as exc:
            failed.append(f"{name}: {exc}")
            continue
        if proc.returncode == 0:
            cleaned.append(name)
        else:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            tail = err[-1] if err else f"rc={proc.returncode}"
            failed.append(f"{name}: {tail}")

    if cleaned and not failed:
        return ("pass", f"teardown ran for: {', '.join(cleaned)}")
    if cleaned and failed:
        return ("warn", f"partial: cleaned={','.join(cleaned)}; failed={'; '.join(failed)}")
    return ("warn", f"teardown failed: {'; '.join(failed)}")
