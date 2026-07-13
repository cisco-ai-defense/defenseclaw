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
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import click

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_DOCTOR
from defenseclaw.connector_paths import (
    connector_config_files,
    hermes_config_path,
    hermes_legacy_config_path,
    omnigent_config_path,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.doctor_gateway import (
    GATEWAY_PROCESS_NAMES,
    GatewayEvidence,
    canonical_path,
    gateway_executable_name,
)
from defenseclaw.doctor_hooks import (
    WindowsHookCheck,
    _packaged_windows_install_root,
    validate_windows_hook_registration,
)
from defenseclaw.envvars import active_security_overrides
from defenseclaw.safety import NoRedirectError, build_no_redirect_opener
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


def _doctor_subsection(title: str) -> None:
    """Print a doctor sub-section divider.

    Format: blank line, then ``  ── <title> ──`` with the title bold
    and the box-drawing dashes dimmed in TTY mode. Plain mode keeps
    The legacy uncolored layout so cron logs and log shippers see
    the same byte stream they always have.
    """
    click.echo()
    if ux._color_enabled():
        click.echo("  " + ux.dim("──") + " " + ux._style(title, fg="cyan", bold=True) + " " + ux.dim("──"))
    else:
        click.echo(f"  ── {title} ──")


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
    __slots__ = ("passed", "failed", "warned", "skipped", "checks")

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.warned = 0
        self.skipped = 0
        self.checks: list[dict] = []

    def record(self, tag: str, label: str = "", detail: str = "") -> None:
        if tag == "pass":
            self.passed += 1
        elif tag == "fail":
            self.failed += 1
        elif tag == "warn":
            self.warned += 1
        else:
            self.skipped += 1
        if label:
            self.checks.append({"status": tag, "label": label, "detail": detail})

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "skipped": self.skipped,
            "checks": self.checks,
        }


DOCTOR_CACHE_FILENAME = "doctor_cache.json"


def _write_doctor_cache(cfg, result: _DoctorResult) -> None:
    """Persist the doctor snapshot to ``<data_dir>/doctor_cache.json``.

    The Go TUI Overview panel (see ``internal/tui/doctor_cache.go``,
    P3-#21) reads this file to show a cached pass/fail/warn/skip
    summary without having to re-probe every network endpoint on
    every redraw. Writing the cache from inside the CLI means the
    two frontends never drift: anything a user sees in
    ``defenseclaw doctor`` is exactly what the TUI will display on
    next refresh, and operators running under cron pick up the same
    status for Overview.

    The write is best-effort — a failure here must not break the
    actual doctor run, so we swallow and log to stderr.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        return
    path = os.path.join(data_dir, DOCTOR_CACHE_FILENAME)
    payload = dict(result.to_dict())
    # Use a consistent ISO-8601 timestamp the Go side already parses
    # as time.Time. RFC3339 in UTC avoids any TZ-confusion between
    # CLI and TUI runs.
    import datetime as _dt
    import tempfile

    payload["captured_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    tmp_path = ""
    try:
        os.makedirs(data_dir, exist_ok=True)
        # Use NamedTemporaryFile so concurrent doctor runs (e.g. a
        # cron job plus a manual invocation) don't collide on a
        # shared ".tmp" filename. Each writer gets a unique path,
        # then atomically replaces the canonical cache.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=data_dir,
            prefix=".doctor_cache.",
            suffix=".tmp",
            delete=False,
        ) as fh:
            tmp_path = fh.name
            json.dump(payload, fh, indent=2)
        # Atomic replace so a concurrent TUI read never sees a
        # half-written JSON document.
        os.replace(tmp_path, path)
        tmp_path = ""
    except OSError as exc:
        click.echo(
            f"warning: could not write doctor cache at {path}: {exc}",
            err=True,
        )
    finally:
        # Best-effort cleanup of an orphaned tempfile if replace()
        # failed or an exception fired mid-write.
        if tmp_path:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


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


def _emit(tag: str, label: str, detail: str = "", *, r: _DoctorResult | None = None) -> None:
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
        click.echo(line)
    if r is not None:
        r.record(tag, label, detail)


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
    click.echo(f"{indent}{ux.dim('↪ ' + text)}")


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
    val = os.environ.get(env_name, "")
    if val:
        return val
    try:
        with open(dotenv_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                if k == env_name:
                    return v
    except FileNotFoundError:
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

    req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
    context = None
    if not verify_tls and url.lower().startswith("https://"):
        context = ssl._create_unverified_context()
    # Preserve the verify_tls / SSL-context behavior by passing an
    # HTTPSHandler carrying the (possibly unverified) context to the opener.
    opener = build_no_redirect_opener(urllib.request.HTTPSHandler(context=context))
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

    cfg_path = str(config_path_for_data_dir(cfg.data_dir))
    if os.path.isfile(cfg_path):
        _emit("pass", "Config file", cfg_path, r=r)
    else:
        _emit("fail", "Config file", "not found — run 'defenseclaw init'", r=r)


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
    db_path = cfg.audit_db
    if os.path.isfile(db_path):
        _emit("pass", "Audit database", db_path, r=r)
    else:
        _emit("fail", "Audit database", f"not found at {db_path}", r=r)


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
        return bool(getattr(getattr(cfg, "otel", None), "enabled", False))
    if sub == "splunk":
        return bool(getattr(getattr(cfg, "splunk", None), "enabled", False))
    if sub == "guardrail":
        return bool(getattr(getattr(cfg, "guardrail", None), "enabled", False))
    if sub == "sandbox":
        oc = getattr(cfg, "openshell", None)
        if oc is None:
            return False
        is_standalone = getattr(oc, "is_standalone", None)
        return bool(is_standalone()) if callable(is_standalone) else False
    # gateway / watcher / api have no on/off switch — they are
    # unconditionally wired up by the sidecar when it boots.
    return None


def _check_sidecar(cfg, r: _DoctorResult) -> None:
    bind = "127.0.0.1"
    if getattr(cfg, "openshell", None) and cfg.openshell.is_standalone():
        bind = getattr(cfg.guardrail, "host", None) or bind
    url = f"http://{bind}:{cfg.gateway.api_port}/health"
    code, body = _http_probe(
        url,
        timeout=5.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
    )
    if code == 200:
        _emit("pass", "Sidecar API", f"{bind}:{cfg.gateway.api_port}", r=r)

        try:
            health = json.loads(body)
            subsystems = ["gateway", "watcher", "guardrail", "api", "telemetry", "splunk", "sandbox"]
            stale_hint_printed = False
            for sub in subsystems:
                info = health.get(sub, {})
                if not info:
                    continue
                state = info.get("state", info.get("status", "unknown"))
                if state.lower() in ("running", "healthy"):
                    detail = state
                    if sub == "guardrail" and info.get("details"):
                        detail += f" (mode={info['details'].get('mode', '?')})"
                    _emit("pass", f"  └─ {sub}", detail, r=r)
                elif state.lower() in ("disabled", "stopped"):
                    # Cross-check the sidecar's view against on-disk
                    # config. A divergence here is almost always a
                    # stale sidecar — the operator ran `defenseclaw
                    # setup …` but never restarted the gateway, so its
                    # in-memory view is out of date. Surface this as a
                    # WARN (not SKIP) so it doesn't get lost in the
                    # noise.
                    expected = _subsystem_expected_enabled(cfg, sub)
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
                        details_obj = info.get("details") or {}
                        summary = ""
                        if isinstance(details_obj, dict):
                            raw = details_obj.get("summary")
                            if isinstance(raw, str):
                                summary = raw.strip()
                        detail_msg = f"disabled — {summary}" if summary else "disabled (reported by sidecar)"
                        _emit("skip", f"  └─ {sub}", detail_msg, r=r)
                else:
                    _emit("fail", f"  └─ {sub}", state, r=r)
        except (json.JSONDecodeError, TypeError):
            detail = body if body.startswith("response exceeds") else "could not parse /health response"
            _emit("warn", "Sidecar health JSON", detail, r=r)
    else:
        _emit("fail", "Sidecar API", f"not reachable on port {cfg.gateway.api_port}", r=r)


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

    configured_val = os.environ.get(configured_env, "")
    if configured_val:
        # Configured var IS populated — happy path. Nothing to flag.
        _emit("pass", "Gateway token env", f"{configured_env} is set", r=r)
        return

    # Stale token_env: configured var is empty. Check whether the
    # canonical DEFENSECLAW_ var is populated instead — that's the
    # drift case worth fixing.
    canonical = os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", "")
    if canonical:
        _emit(
            "fail",
            "Gateway token env",
            f"cfg.gateway.token_env={configured_env!r} is empty in env, "
            "but DEFENSECLAW_GATEWAY_TOKEN is set. Run `defenseclaw doctor "
            "--fix` to repoint token_env at the canonical var.",
            r=r,
        )
        return

    legacy = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    if legacy and configured_env != "OPENCLAW_GATEWAY_TOKEN":
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
    if configured_env == "OPENCLAW_GATEWAY_TOKEN" and not _openclaw_active(cfg):
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
    if not os.path.isfile(pid_file):
        return 0
    try:
        with open(pid_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError:
        return 0
    try:
        pid = int(raw)
    except ValueError:
        try:
            pid = int(json.loads(raw).get("pid", 0))
        except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
            return 0
    if pid <= 0:
        return 0
    from defenseclaw.process_liveness import pid_alive

    if not pid_alive(pid):
        return 0
    return pid


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
    proc_environ = f"/proc/{pid}/environ"
    if os.path.isfile(proc_environ):
        try:
            with open(proc_environ, "rb") as fh:
                blob = fh.read()
        except (OSError, PermissionError):
            blob = b""
        if blob:
            for entry in blob.split(b"\x00"):
                if not entry:
                    continue
                key, sep, value = entry.partition(b"=")
                if sep and key.decode("utf-8", errors="replace") == var_name:
                    return value.decode("utf-8", errors="replace")
            # /proc was readable but the var isn't there — definitive
            # absence.
            return ""

    # macOS / fallback: ps eww -p <pid> prints "PID TTY STAT TIME CMD ENV...".
    # We ask for just the args (the env appears inline on macOS).
    try:
        proc = subprocess.run(
            ["ps", "eww", "-p", str(pid)],
            capture_output=True,
            text=True,
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
    evidence = evidence or GatewayEvidence(platform_name=platform_name)
    pid_path = os.path.join(cfg.data_dir, "gateway.pid")
    record = evidence.pid_record(pid_path)

    identity_ok = False
    process = None
    if record.status == "missing":
        _emit("fail", "Gateway PID identity", "managed gateway PID file is missing", r=r)
    elif record.status == "malformed":
        _emit("fail", "Gateway PID identity", record.reason or "managed gateway PID file is invalid", r=r)
    elif record.status in {"denied", "unavailable"}:
        _emit("skip", "Gateway PID identity", record.reason or "PID file inspection unavailable", r=r)
    else:
        process = evidence.process(record.pid)
        if process.status == "missing":
            _emit("fail", "Gateway PID identity", "stale PID file: recorded process does not exist", r=r)
        elif process.status in {"denied", "unavailable"}:
            _emit("skip", "Gateway PID identity", process.reason or "process inspection unavailable", r=r)
        else:
            live_name = gateway_executable_name(process.executable)
            if live_name not in GATEWAY_PROCESS_NAMES:
                _emit("fail", "Gateway PID identity", "recorded PID belongs to an unexpected executable", r=r)
            elif record.executable and canonical_path(record.executable) != canonical_path(process.executable):
                _emit("fail", "Gateway PID identity", "stale or reused PID: executable path changed", r=r)
            elif record.start_identity and record.start_identity != process.start_identity:
                _emit("fail", "Gateway PID identity", "stale or reused PID: process start identity changed", r=r)
            elif not record.start_identity:
                _emit(
                    "skip",
                    "Gateway PID identity",
                    "legacy PID record has no process start identity",
                    r=r,
                )
            else:
                identity_ok = True
                _emit("pass", "Gateway PID identity", "executable and process start identity match", r=r)

    try:
        api_port = int(getattr(cfg.gateway, "api_port", 0) or 0)
    except (TypeError, ValueError):
        api_port = 0
    listener = evidence.listener(api_port)

    # The management request is intentionally fixed to loopback. The port is
    # the validated integer from gateway config; neither a configured remote
    # host nor a redirect can receive the bearer token.
    token = cfg.gateway.resolved_token()
    status_code = 0
    status_body = ""
    if not 1 <= api_port <= 65_535:
        status_error = "configured API port is invalid"
    elif not token:
        status_error = "no local gateway authentication state is configured"
    else:
        status_code, status_body = _http_probe(
            f"http://127.0.0.1:{api_port}/status",
            headers={"Authorization": f"Bearer {token}"},
            timeout=3.0,
            response_limit=64 * 1024,
            allow_truncation=False,
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

    if status_error:
        _emit("skip", "Gateway token drift", status_error, r=r)
    elif status_code in {401, 403, 503}:
        _emit("fail", "Gateway token drift", "gateway authentication drift detected", r=r)
    elif status_code == 0:
        _emit("skip", "Gateway token drift", "gateway is unreachable; authentication could not be inspected", r=r)
    elif status_code != 200:
        _emit("skip", "Gateway token drift", f"authentication inspection unavailable (HTTP {status_code})", r=r)
    elif not runtime:
        _emit("skip", "Gateway token drift", "authenticated runtime metadata is unavailable", r=r)
    else:
        _emit("pass", "Gateway token drift", "local authentication state matches the live gateway", r=r)

    runtime_home = runtime.get("data_dir", "") if runtime else ""
    if status_code in {401, 403, 503}:
        _emit("skip", "Gateway home", "authentication drift prevents trusted runtime-home inspection", r=r)
    elif status_code == 0:
        _emit("skip", "Gateway home", "gateway is unreachable; runtime home could not be inspected", r=r)
    elif status_code != 200 or not isinstance(runtime_home, str) or not runtime_home.strip():
        _emit("skip", "Gateway home", "authenticated runtime-home evidence is unavailable", r=r)
    elif canonical_path(runtime_home) != canonical_path(cfg.data_dir):
        _emit("fail", "Gateway home", "running gateway uses a different canonical data home", r=r)
    else:
        _emit("pass", "Gateway home", "running gateway uses this canonical data home", r=r)
    return True


def _check_gateway_token_drift(cfg, r: _DoctorResult) -> None:
    """Detect a stale-sidecar-token vs current-.env-token mismatch.

    Failure mode this closes: the sidecar caches its auth token at
    startup (from env / dotenv). If anything later rewrites
    ``~/.defenseclaw/.env`` — Phase 4 migration, a fresh
    ``EnsureGatewayToken`` run, manual ``defenseclaw keys set``, an
    install script that touches the dotenv — the running sidecar
    keeps using the OLD token while the CLI reads the NEW one. Every
    subsequent ``defenseclaw agent usage`` (and any other auth'd API
    call) returns HTTP 401 with no hint of the root cause.

    Triggers when ALL of these hold:

    * ``gateway.pid`` exists and the recorded PID is alive.
    * The sidecar process's ``DEFENSECLAW_GATEWAY_TOKEN`` env var is
      readable and non-empty.
    * The current ``.env``'s ``DEFENSECLAW_GATEWAY_TOKEN`` is non-empty.
    * The two differ.

    "fail" tag is intentional — this configuration is BROKEN at
    runtime (every API call returns 401), not just suboptimal.
    Operators need to know this, not a soft "warn".

    Permission-denied / process-gone cases emit ``"skip"`` rather
    than ``"warn"`` — those aren't drift, just "can't tell". Nagging
    on indeterminacy would erode trust in the check.
    """
    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    pid = _read_pid_from_file(pid_file)
    if pid == 0:
        # No running sidecar — nothing to compare against. Other
        # checks (e.g. _check_sidecar) handle the "sidecar down"
        # case; this one is exclusively about drift between live
        # process and on-disk dotenv.
        return

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    dotenv_token = ""
    if os.path.isfile(dotenv_path):
        try:
            with open(dotenv_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("DEFENSECLAW_GATEWAY_TOKEN="):
                        value = line[len("DEFENSECLAW_GATEWAY_TOKEN=") :]
                        # Strip optional surrounding quotes the same
                        # way config._load_dotenv_into_os does, so
                        # the comparison matches the value the CLI
                        # would actually send.
                        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                            value = value[1:-1]
                        dotenv_token = value
                        break
        except OSError:
            return
    if not dotenv_token:
        # No token in .env to compare against. _check_sidecar /
        # _check_gateway_token_env_alignment surface the upstream
        # "no token configured" state; nothing to report here.
        return

    process_token = _read_process_env_var(pid, "DEFENSECLAW_GATEWAY_TOKEN")
    if process_token is None:
        # Couldn't read the process env — permissions or process
        # raced away. Skip silently rather than warn; "can't tell"
        # is not drift.
        _emit(
            "skip",
            "Gateway token drift",
            f"could not inspect sidecar (pid {pid}) env — permissions?",
            r=r,
        )
        return
    if not process_token:
        # Sidecar started with no DEFENSECLAW_GATEWAY_TOKEN in env.
        # Either it's an older binary that read the dotenv directly,
        # or the user started it manually without sourcing the
        # dotenv. The check below would falsely flag "drift" here;
        # treat this as inconclusive and let _check_sidecar surface
        # the auth issue if one exists.
        _emit(
            "skip",
            "Gateway token drift",
            f"sidecar (pid {pid}) has no DEFENSECLAW_GATEWAY_TOKEN in env; comparing dotenv to process not meaningful",
            r=r,
        )
        return

    if process_token == dotenv_token:
        _emit(
            "pass",
            "Gateway token drift",
            f"sidecar (pid {pid}) token matches ~/.defenseclaw/.env",
            r=r,
        )
        return

    # Mismatch confirmed. Do not render either credential, including hashes or
    # prefixes: Doctor output is routinely cached, logged, and screenshotted.
    _emit(
        "fail",
        "Gateway token drift",
        f"sidecar (pid {pid}) authentication differs from the configured "
        "state. Every API call will "
        "return HTTP 401. Run `defenseclaw doctor --fix` (or "
        "`defenseclaw-gateway restart`) to reconcile.",
        r=r,
    )


def _gateway_listener_pid(port: int) -> int:
    """Best-effort PID of whatever is listening on the local API *port*.

    Uses ``lsof`` (present on macOS and most Linux installs). Returns 0
    when the listener can't be determined — callers degrade to "can't
    tell" rather than guessing, so an absent ``lsof`` never produces a
    false alarm.
    """
    if port <= 0:
        return 0
    try:
        proc = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 0
    if proc.returncode != 0:
        return 0
    for token in proc.stdout.split():
        try:
            return int(token)
        except ValueError:
            continue
    return 0


def _check_gateway_home_mismatch(cfg, r: _DoctorResult) -> None:
    """Warn when a gateway from a DIFFERENT home is holding the API port.

    Each home's hook scripts (under ``cfg.data_dir/hooks``) post to the
    API port with that home's token. If a gateway started from another
    ``DEFENSECLAW_HOME`` — typically a sandbox under ``/tmp`` left over
    from testing — is squatting on that single port, every hook call
    fails auth (401) even though each half looks healthy on its own.
    This is invisible to :func:`_check_gateway_token_drift`, which only
    compares process-vs-dotenv WITHIN one home.

    To avoid false alarms we only warn on a POSITIVELY identified
    foreign home: the API answers, this config's ``gateway.pid`` is not
    a live process, AND the actual listener reports a data dir that
    differs from ``cfg.data_dir``. When the listener can't be introspected
    (no ``lsof``, perms, no env var) we stay silent — "can't tell" is not
    a mismatch, same discipline as the token-drift check.
    """
    bind = "127.0.0.1"
    if getattr(cfg, "openshell", None) and cfg.openshell.is_standalone():
        bind = getattr(cfg.guardrail, "host", None) or bind
    api_port = cfg.gateway.api_port
    code, _ = _http_probe(f"http://{bind}:{api_port}/health", timeout=5.0)
    if code != 200:
        # Nothing answering — `_check_sidecar` already reports "down".
        return

    # Is the gateway THIS config tracks the one that's actually alive?
    if _read_pid_from_file(os.path.join(cfg.data_dir, "gateway.pid")):
        _emit(
            "pass",
            "Gateway home",
            f"sidecar on :{api_port} belongs to this config ({cfg.data_dir})",
            r=r,
        )
        return

    # The port is served, but not by the gateway this config started
    # (our pid file is stale/dead). Try to identify the squatter's home.
    listener_pid = _gateway_listener_pid(api_port)
    foreign_home = ""
    if listener_pid:
        foreign_home = (
            _read_process_env_var(listener_pid, "DEFENSECLAW_DATA_DIR")
            or _read_process_env_var(listener_pid, "DEFENSECLAW_HOME")
            or ""
        )
    if not foreign_home:
        # Couldn't positively identify a foreign home — stay silent
        # rather than nag (the listener may simply be this home's
        # gateway with a stale pid file and no data-dir env var).
        return
    if os.path.normpath(foreign_home) == os.path.normpath(cfg.data_dir):
        # Same home after all; the pid file was just stale.
        _emit(
            "pass",
            "Gateway home",
            f"sidecar on :{api_port} serves this config ({cfg.data_dir})",
            r=r,
        )
        return

    _emit(
        "warn",
        "Gateway home",
        f"a gateway from {foreign_home} is holding port {api_port}, but this "
        f"config is {cfg.data_dir} — hooks here will get HTTP 401. It is a "
        "leftover sandbox gateway; restart from a clean shell "
        "(`unset DEFENSECLAW_HOME DEFENSECLAW_DATA_DIR`), then "
        "`defenseclaw-gateway restart`.",
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
        config_path = paths[0] if paths else connector_config_files(connector)[0]
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
    settings_path = connector_config_files("claudecode")[0]
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

    health_url = f"http://127.0.0.1:{api_port}/health"
    before_code, before_body = _http_probe(
        health_url,
        timeout=3.0,
        response_limit=_HEALTH_DOCUMENT_MAX_BYTES,
        allow_truncation=False,
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
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ],
            capture_output=True,
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
                _check_cursor_configured_runtime(cfg, path, label, r)
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

    if provider == "anthropic":
        _verify_anthropic(api_key, r, model)
    elif provider == "openai":
        _verify_openai(api_key, r)
    elif provider in ("bedrock", "amazon-bedrock"):
        _verify_bedrock(api_key, r)
    elif provider == "" and env_name.startswith("ANTHROPIC"):
        # Model string missing — fall back to env name prefix.
        _verify_anthropic(api_key, r, model)
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


def _check_observability(cfg, r: _DoctorResult) -> None:
    """Walk every observability destination (gateway OTel + audit_sinks)
    and probe each one according to its kind.

    This replaces the old Splunk-only check. Destinations are discovered
    via the observability writer so any preset wired up through
    ``setup observability add`` is exercised here without extra
    branching. Disabled destinations are skipped, not failed — users
    often keep e.g. a dev Datadog sink disabled in prod configs.
    """
    from defenseclaw.observability import list_destinations
    from defenseclaw.observability.presets import PRESETS

    try:
        destinations = list_destinations(cfg.data_dir)
    except Exception as exc:
        _emit("warn", "Observability", f"could not enumerate destinations: {exc}", r=r)
        return

    if not destinations:
        _emit("skip", "Observability", "no destinations configured", r=r)
        return

    for d in destinations:
        label_kind = _destination_label_kind(d, PRESETS)
        label = f"{d.name} ({label_kind})"

        if not d.enabled:
            _emit("skip", label, "disabled", r=r)
            continue

        # Route the probe by destination target/kind. The keys here are
        # the same ones used by `observability.presets.Preset.kind` and
        # `internal/config/sinks.go`, so adding a new preset means
        # adding one branch here, at most.
        if d.target == "otel":
            _probe_otel_destination(cfg, d, r)
        elif d.kind == "splunk_hec":
            _probe_splunk_hec(cfg, d, r)
        elif d.kind == "otlp_logs":
            _probe_otlp_logs(cfg, d, r)
        elif d.kind == "http_jsonl":
            _probe_http_jsonl(cfg, d, r)
        else:
            _emit("warn", label, f"no probe for kind '{d.kind}'", r=r)


def _probe_otel_destination(cfg, d, r: _DoctorResult) -> None:
    """Lightweight reachability check for the gateway OTel exporter.

    Probing OTLP properly (gRPC health + TLS + auth) is non-trivial, so
    we do a best-effort TCP/HTTP check against the endpoint. A full
    semantic probe lives in `setup observability test` — doctor is for
    connectivity smoke checks only.
    """
    import socket
    from urllib.parse import urlparse

    label = f"{d.name} (OTLP)"
    endpoint = d.endpoint
    if not endpoint:
        _emit("fail", label, "no endpoint configured", r=r)
        return

    parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        _emit("fail", label, f"unparseable endpoint: {endpoint}", r=r)
        return

    try:
        with socket.create_connection((host, port), timeout=5.0):
            _emit("pass", label, f"{host}:{port} reachable", r=r)
    except (TimeoutError, OSError) as exc:
        _emit("warn", label, f"{host}:{port} not reachable: {exc}", r=r)


# HEC internal reply codes from Splunk docs — used to surface
# actionable diagnostics instead of the raw HTTP status code.
# Source: https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.2/get-data-with-http-event-collector/troubleshoot-http-event-collector
_HEC_CODES = {
    0: "success",
    1: "token is disabled — enable it in Splunk HEC settings",
    2: "no authorization — token is required",
    3: "invalid authorization header format",
    4: "invalid token — check the token value in your config",
    5: "no data in request",
    6: "invalid data format",
    7: "incorrect index — the index does not exist in Splunk",
    9: "server busy — Splunk HEC is overloaded",
    10: "data channel missing",
    11: "invalid data channel",
    12: "event field is required",
    13: "event field cannot be blank",
    17: "HEC is healthy",
    18: "HEC unhealthy — queues are full",
}


def _parse_hec_response(body: str) -> tuple[int | None, str]:
    """Parse a Splunk HEC JSON response body.

    Returns (hec_code, human_readable_message). hec_code is None when
    the body is not valid HEC JSON (e.g. a load balancer error page).
    """
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return None, body[:120] if body else ""
    hec_code = obj.get("code")
    text = obj.get("text", "")
    if hec_code is None:
        return None, text or body[:120]
    human = _HEC_CODES.get(hec_code)
    if human:
        return hec_code, human
    return hec_code, text or f"HEC code {hec_code}"


def _probe_splunk_hec(cfg, d, r: _DoctorResult) -> None:
    """HEC probe: POST a minimal test event and surface actionable diagnostics.

    Interprets both the HTTP status code and the Splunk HEC JSON reply
    code in the response body so operators see specific failure reasons
    (wrong index, disabled token, server busy, etc.) rather than a
    generic HTTP status.
    """
    label = f"{d.name} ({_splunk_hec_label_kind(d)})"
    endpoint, token = _resolve_audit_sink_endpoint_and_token(cfg, d)
    if not endpoint or not token:
        _emit("fail", label, "endpoint or token missing — set splunk_hec.token_env in config", r=r)
        return

    # Warn if the token is stored inline rather than via token_env.
    _check_splunk_token_posture(cfg, d, label, r)

    verify_tls = _splunk_hec_tls_verify_enabled(cfg, d)
    http_code, body = _http_probe(
        endpoint,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
        body=json.dumps({"event": "defenseclaw-doctor-probe", "sourcetype": "_json"}).encode(),
        timeout=10.0,
        verify_tls=verify_tls,
    )

    if http_code == 200:
        hec_code, msg = _parse_hec_response(body)
        if hec_code is not None and hec_code not in (0, 17):
            _emit("warn", label, f"unexpected HEC response on 200: {msg}", r=r)
        else:
            _emit("pass", label, endpoint, r=r)
        return

    hec_code, hec_msg = _parse_hec_response(body)

    if http_code in (401, 403):
        if hec_code == 1:
            _emit("fail", label, "token is disabled — enable the HEC token in Splunk", r=r)
        elif hec_code == 4:
            _emit("fail", label, "invalid token — verify splunk_hec.token_env points to the correct value", r=r)
        elif hec_code in (2, 3):
            _emit("fail", label, f"authorization error: {hec_msg}", r=r)
        else:
            _emit("fail", label, f"authentication failed (HTTP {http_code}): {hec_msg}", r=r)
        return

    if http_code == 400:
        if hec_code == 7:
            index_hint = f" (configured index: {d.index!r})" if getattr(d, "index", None) else ""
            msg = f"incorrect index{index_hint} — create the index in Splunk or update splunk_hec.index"
            _emit("fail", label, msg, r=r)
        else:
            _emit("fail", label, f"bad request: {hec_msg}", r=r)
        return

    if http_code in (503, 429):
        if hec_code == 18:
            _emit("warn", label, "Splunk HEC queues are full — indexer may be overloaded", r=r)
        elif hec_code == 9:
            _emit("warn", label, "Splunk HEC server busy — consider reducing flush frequency", r=r)
        else:
            _emit("warn", label, f"HEC temporarily unavailable (HTTP {http_code}): {hec_msg}", r=r)
        return

    if http_code == 0:
        if any(kw in body.lower() for kw in ("ssl", "certificate", "tls")):
            _emit(
                "fail",
                label,
                f"TLS error — check insecure_skip_verify setting and endpoint certificate: {body[:120]}",
                r=r,
            )
        else:
            _emit("warn", label, f"unreachable: {body[:120]}", r=r)
        return

    _emit("warn", label, f"HTTP {http_code}: {hec_msg or body[:120]}", r=r)


def _truthy_config_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _splunk_hec_tls_verify_enabled(cfg, d) -> bool:
    """Resolve effective TLS verification for a Splunk HEC doctor probe."""
    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.observability.writer import _load_yaml

    try:
        doc = _load_yaml(str(config_path_for_data_dir(cfg.data_dir)))
    except Exception:
        doc = {}

    for sink in doc.get("audit_sinks") or []:
        if not isinstance(sink, dict) or sink.get("name") != d.name:
            continue
        sub = sink.get("splunk_hec") or {}
        if isinstance(sub, dict):
            return not _truthy_config_bool(sub.get("insecure_skip_verify", False))
        break

    splunk_cfg = getattr(cfg, "splunk", None)
    if hasattr(splunk_cfg, "tls_verify_enabled"):
        return bool(splunk_cfg.tls_verify_enabled())
    return True


def _check_splunk_token_posture(cfg, d, label: str, r: _DoctorResult) -> None:
    """Warn if the HEC token is stored inline in config rather than via token_env.

    Splunk's own best practices recommend against storing HEC tokens in
    configuration files. This check surfaces that posture issue during
    doctor so operators are nudged toward token_env before it becomes a
    security finding.
    """
    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.observability.writer import _load_yaml

    try:
        doc = _load_yaml(str(config_path_for_data_dir(cfg.data_dir)))
    except Exception:
        return
    sinks = doc.get("audit_sinks") or []
    for sink in sinks:
        if not isinstance(sink, dict) or sink.get("name") != d.name:
            continue
        sub = sink.get("splunk_hec") or {}
        if isinstance(sub, dict) and sub.get("token") and not sub.get("token_env"):
            _emit(
                "warn",
                label,
                "HEC token is stored inline in config — use token_env to reference an "
                "environment variable instead (see Splunk HEC security best practices)",
                r=r,
            )
        return


def _destination_label_kind(d, presets) -> str:
    if d.kind == "splunk_hec":
        return _splunk_hec_label_kind(d)
    if d.preset_id in presets:
        return presets[d.preset_id].display_name
    return d.kind


def _splunk_hec_label_kind(d) -> str:
    if d.preset_id == "splunk-enterprise":
        return "Splunk Enterprise (HEC)"
    return "Splunk HEC"


def _probe_otlp_logs(cfg, d, r: _DoctorResult) -> None:
    """OTLP-logs sink: connectivity check only (no valid empty payload)."""
    import socket
    from urllib.parse import urlparse

    label = f"{d.name} (OTLP logs)"
    endpoint = d.endpoint
    if not endpoint:
        _emit("fail", label, "no endpoint configured", r=r)
        return
    parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        _emit("fail", label, f"unparseable endpoint: {endpoint}", r=r)
        return
    try:
        with socket.create_connection((host, port), timeout=5.0):
            _emit("pass", label, f"{host}:{port} reachable", r=r)
    except (TimeoutError, OSError) as exc:
        _emit("warn", label, f"{host}:{port} not reachable: {exc}", r=r)


def _probe_http_jsonl(cfg, d, r: _DoctorResult) -> None:
    """Generic HTTP JSONL audit sink: do a HEAD/OPTIONS request —
    probing an unknown endpoint with POST could fire real events.
    (Distinct from notifier webhooks[]; see _check_webhooks below.)"""
    label = f"{d.name} (http_jsonl)"
    endpoint = d.endpoint
    if not endpoint:
        _emit("fail", label, "no URL configured", r=r)
        return
    # OPTIONS is the safest — many webhooks reject HEAD.
    code, body = _http_probe(endpoint, method="OPTIONS", timeout=5.0)
    # 200-499 all count as "reachable" for a webhook; only 5xx / 0
    # indicate a real connectivity problem.
    if code == 0:
        _emit("warn", label, f"unreachable: {body[:100]}", r=r)
    elif 500 <= code < 600:
        _emit("warn", label, f"server error (HTTP {code})", r=r)
    else:
        _emit("pass", label, f"{endpoint} reachable (HTTP {code})", r=r)


def _resolve_audit_sink_endpoint_and_token(cfg, d) -> tuple[str, str]:
    """Read the raw audit_sinks entry for ``d.name`` to recover the
    endpoint and resolve its token env var. ``Destination.endpoint``
    already exposes the endpoint for display, but tokens live in
    preset-specific fields (``token_env``, ``bearer_env``, etc.), so we
    go back to the YAML here.
    """
    import os

    # Late import: this module is loaded on every CLI invocation, but
    # the YAML read only matters for operators who have audit sinks.
    # _load_yaml takes a full file path, not a data_dir — mirror the
    # writer's layout, respecting explicit managed config overrides.
    from defenseclaw.config import config_path_for_data_dir
    from defenseclaw.observability.writer import _load_yaml

    try:
        doc = _load_yaml(str(config_path_for_data_dir(cfg.data_dir)))
    except Exception:
        return d.endpoint, ""

    # The token_env key lives inside the kind-specific sub-block (e.g.
    # `splunk_hec.token_env`, `http_jsonl.bearer_env`). Walk both
    # levels so we don't care which convention a given sink uses.
    sinks = doc.get("audit_sinks") or []
    token_env = ""
    for sink in sinks:
        if not isinstance(sink, dict) or sink.get("name") != d.name:
            continue
        token_env = str(sink.get("token_env", "") or "")
        if not token_env:
            # Nested: splunk_hec.token_env / otlp_logs.token_env / http_jsonl.bearer_env
            for sub_key in ("splunk_hec", "otlp_logs", "http_jsonl"):
                sub = sink.get(sub_key) or {}
                if isinstance(sub, dict):
                    token_env = str(sub.get("token_env") or sub.get("bearer_env") or "")
                    if token_env:
                        break
        break

    if not token_env:
        return d.endpoint, ""

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    token = _resolve_api_key(token_env, dotenv_path)
    return d.endpoint, token


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
    and several of them (``DEFENSECLAW_DISABLE_REDACTION``,
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

    if not active:
        _emit("pass", "Security overrides", "none active", r=r)
        return

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


@click.command()
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON")
@click.option(
    "--fix",
    "do_fix",
    is_flag=True,
    help=(
        "Auto-repair safe issues (stale PID files, token-env drift, dotenv "
        "perms). NOTE: the token-drift fixer may RESTART the gateway sidecar "
        "to reconcile a stale token — preview the full set with --dry-run."
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
@pass_ctx
def doctor(
    app: AppContext,
    json_out: bool,
    do_fix: bool,
    assume_yes: bool,
    dry_run: bool,
) -> None:
    """Verify credentials, endpoints, and connectivity.

    Runs a series of checks against every configured service and API key
    to catch problems before they surface at runtime. On multi-connector
    installs it inventories and runs hook/health checks for every active
    connector (each row tagged ``[<connector>]``), not just the primary.

    Use ``--fix`` to auto-repair safe issues (stale sidecar PID files,
    gateway token-env drift, dotenv permissions, pristine config backups).
    One fixer — gateway token *drift* — may **restart the gateway sidecar**
    to reconcile a stale in-memory token, which briefly interrupts in-flight
    requests; preview the full set first with ``--fix --dry-run``. Doctor no
    longer tears connectors down as part of ``--fix`` (it only *reports*
    inactive-connector residue); run ``defenseclaw-gateway connector teardown
    --connector <name>`` to remove a specific connector. Other destructive or
    ambiguous fixes still require the relevant setup command explicitly.

    Exit codes: 0 = all pass, 1 = any failure.
    """
    global _json_mode
    cfg = app.cfg
    r = _DoctorResult()
    _json_mode = json_out

    if not json_out:
        click.echo()
        click.echo(ux._style("DefenseClaw Doctor", fg="cyan", bold=True))
        click.echo(ux._style("══════════════════", fg="cyan"))
        click.echo()

    _check_config(cfg, r)
    _check_audit_db(cfg, r)

    # S6.5 — surface the active connector + its configured paths
    # before any scanner runs. Operators routinely point doctor at a
    # config that *thinks* it's running on (say) Codex but actually
    # has stale openclaw.json paths under .openclaw/extensions; a
    # per-connector inventory pass catches that drift.
    if not json_out:
        _doctor_subsection("Connectors")
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
    _check_scanners(cfg, r)
    _check_scan_coverage(cfg, r)

    if not json_out:
        _doctor_subsection("Services")
    _check_sidecar(cfg, r)
    _check_gateway_token_env_alignment(cfg, r)
    if not _check_windows_gateway_diagnostics(cfg, r):
        # Preserve the established Linux/macOS evidence collectors. Windows
        # uses the native/injectable path above because os.kill(pid, 0), lsof,
        # /proc, and ps are not reliable evidence there.
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
    _check_llm_api_key(cfg, r)
    _check_llm_reachable(cfg, r)
    _check_regional_provider_config(cfg, r)
    _check_custom_provider_overlay(cfg, r)
    _check_cisco_ai_defense(cfg, r)
    _check_virustotal(cfg, r)
    _check_registry_credentials(cfg, r)
    if not json_out:
        _doctor_subsection("Observability")
    _check_observability(cfg, r)
    if not json_out:
        _doctor_subsection("Webhooks")
    _check_webhooks(cfg, r)

    # Surface any DEFENSECLAW_* env-var bypass that's currently active.
    # The registry at internal/envvars/registry.json is the single
    # source of truth; operators with no overrides set see a single
    # PASS row here.
    if not json_out:
        _doctor_subsection("Security Overrides")
    _check_security_overrides(cfg, r)

    if do_fix:
        if not json_out:
            _doctor_subsection("Auto-fix" + (" (dry-run)" if dry_run else ""))
            # Blast-radius banner (D8): one fixer restarts the sidecar, so make
            # the cost of a real --fix run explicit before it runs, and point
            # at --dry-run as the safe preview.
            _emit_hint(_auto_fix_hint(dry_run))
        _run_fixers(
            cfg,
            r,
            assume_yes=assume_yes,
            json_out=json_out,
            dry_run=dry_run,
        )

    # Persist the cached snapshot before exit so the Go TUI (and any
    # other cron-style caller) can pick it up without re-probing. We
    # do this *before* the SystemExit(1) below so failing runs still
    # update the cache — the TUI needs to see "doctor last reported
    # 2 failures", not a stale green state from yesterday.
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
        click.echo("  " + ", ".join(parts))
        click.echo()

    if r.failed:
        if not json_out:
            # Surface the remediation hint in yellow — it's the
            # primary call-to-action when doctor fails. We use
            # ``ux.warn`` rather than ``ux.err`` because the line
            # itself isn't a failure; the failures above are.
            ux.warn("Fix the failures above, then re-run: defenseclaw doctor", indent="  ")
            click.echo()
        raise SystemExit(1)

    if app.logger:
        app.logger.log_action(
            ACTION_DOCTOR,
            "health-check",
            f"passed={r.passed} failed={r.failed} warned={r.warned} skipped={r.skipped}",
        )


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
    "may restart the gateway sidecar for token drift; doctor never runs "
    "connector teardown."
)

_AUTO_FIX_REAL_HINT = (
    "blast radius: the token-drift fixer may RESTART the gateway sidecar "
    "(interrupts in-flight requests); teardown is never run. Re-run with "
    "--dry-run to preview without mutating."
)


def _auto_fix_hint(dry_run: bool) -> str:
    return _AUTO_FIX_DRY_RUN_HINT if dry_run else _AUTO_FIX_REAL_HINT


def _run_fixers(
    cfg,
    r: _DoctorResult,
    *,
    assume_yes: bool,
    json_out: bool,
    dry_run: bool = False,
) -> None:
    """Run each fixer in sequence, narrating what changed.

    Fixers are intentionally *small* and independent. All but one are
    non-disruptive; the lone exception is ``gateway token drift``, which may
    **restart the gateway sidecar** to reconcile a stale in-memory token (it
    prompts first unless ``--yes``, and briefly interrupts in-flight
    requests). That blast radius is surfaced to the operator by the banner at
    the Auto-fix section and the ``--fix`` help text (D8). Anything that needs
    a full re-patch — or that would tear a connector down — is deferred to the
    human.

    With ``dry_run=True`` we *list* each fixer instead of invoking it.
    The reported tag is always ``"skip"`` and the detail explains the
    fixer would run; this lets a TUI / CI caller render a preview
    before granting an explicit ``--yes`` to mutate anything.
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
    fixers = [
        ("stale gateway PID file", _fix_stale_pid),
        ("gateway token", _fix_gateway_token),
        ("gateway token_env", _fix_gateway_token_env),
        ("gateway token drift", _fix_gateway_token_drift),
        ("defenseclaw dotenv perms", _fix_dotenv_perms),
        ("pristine config backup", _fix_pristine_backup),
        ("plugin registry dead-end", _fix_plugin_registry_required),
    ]

    for title, fn in fixers:
        if dry_run:
            outcome = ("skip", "would run (dry-run; no changes made)")
        else:
            try:
                outcome = fn(cfg, assume_yes=assume_yes)
            except Exception as exc:  # defensive — one fixer shouldn't abort the rest
                outcome = ("error", f"{type(exc).__name__}: {exc}")

        tag, detail = outcome
        if json_out:
            r.record(tag, f"fix: {title}", detail)
        else:
            _emit(tag, f"fix: {title}", detail=detail, r=r)


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
            _emit("pass", "Mode", mode, r=r)

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

    current_version = _discovered_agent_version(data_dir, connector)
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


def _fix_stale_pid(cfg, *, assume_yes: bool) -> tuple[str, str]:
    """Remove a ``gateway.pid`` file whose recorded PID is no longer alive."""
    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    if not os.path.isfile(pid_file):
        return ("skip", "no pid file")

    try:
        with open(pid_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError as exc:
        return ("warn", f"unreadable: {exc}")

    try:
        pid = int(raw)
    except ValueError:
        try:
            pid = int(json.loads(raw).get("pid", 0))
        except (json.JSONDecodeError, ValueError, TypeError):
            pid = 0
    if pid <= 0:
        return ("warn", "malformed pid file — leaving in place")

    try:
        os.kill(pid, 0)
        return ("skip", f"pid {pid} still alive")
    except (ProcessLookupError, PermissionError, OSError):
        pass

    if not assume_yes and not click.confirm(f"    Remove stale pid file {pid_file}?", default=True):
        return ("skip", "declined by user")

    try:
        os.unlink(pid_file)
        return ("pass", f"removed {pid_file}")
    except OSError as exc:
        return ("fail", f"could not remove {pid_file}: {exc}")


def _fix_gateway_token(cfg, *, assume_yes: bool) -> tuple[str, str]:
    """Re-sync gateway token from the active connector's config."""
    active_connector = _active_connector(cfg)

    if active_connector == "openclaw":
        from defenseclaw.commands.cmd_setup import (
            _detect_openclaw_gateway_token,
            _save_secret_to_dotenv,
        )

        token = _detect_openclaw_gateway_token(cfg.claw.config_file)
        if not token:
            return ("skip", "no token in openclaw.json")
        env_var = "OPENCLAW_GATEWAY_TOKEN"
        current = os.environ.get(env_var, "")
        if current == token:
            return ("skip", "token already in sync")
        if not assume_yes and not click.confirm(
            f"    Update {env_var} in ~/.defenseclaw/.env from OpenClaw?",
            default=True,
        ):
            return ("skip", "declined by user")
        _save_secret_to_dotenv(env_var, token, cfg.data_dir)
        return ("pass", f"{env_var} updated from openclaw.json")

    env_var = "DEFENSECLAW_GATEWAY_TOKEN"
    dotenv_path = os.path.join(cfg.data_dir, ".env")
    if not os.path.isfile(dotenv_path):
        return ("skip", f"no .env at {dotenv_path}")
    current = os.environ.get(env_var, "")
    if current:
        return ("skip", f"{env_var} already set")
    return ("skip", f"connector {active_connector} — set {env_var} manually if needed")


def _fix_gateway_token_env(cfg, *, assume_yes: bool) -> tuple[str, str]:
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

    configured_env = getattr(gw, "token_env", "") or ""
    canonical = "DEFENSECLAW_GATEWAY_TOKEN"

    # Already on the canonical name — nothing to do, regardless of
    # whether the var is actually populated. Other fixers handle the
    # missing-value case.
    if configured_env == canonical:
        return ("skip", f"token_env already set to {canonical}")

    # Don't touch a custom operator override. Only auto-repoint the
    # legacy OPENCLAW_ default.
    if configured_env and configured_env != "OPENCLAW_GATEWAY_TOKEN":
        return (
            "skip",
            f"token_env={configured_env!r} is a custom override; not auto-rewriting",
        )

    # Only proceed when the canonical var is actually populated —
    # otherwise we'd be repointing at another empty var, which buys
    # nothing and obscures the underlying "no token anywhere" state.
    if not os.environ.get(canonical, ""):
        return ("skip", f"{canonical} is not set; nothing to repoint at")

    if not assume_yes and not click.confirm(
        f"    Repoint cfg.gateway.token_env from {configured_env!r} to {canonical!r} in config.yaml?",
        default=True,
    ):
        return ("skip", "declined by user")

    try:
        gw.token_env = canonical
        cfg.save()
    except (OSError, AttributeError) as exc:
        return ("fail", f"could not save config: {type(exc).__name__}: {exc}")

    return ("pass", f"token_env repointed to {canonical}")


def _fix_gateway_token_drift(cfg, *, assume_yes: bool) -> tuple[str, str]:
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
    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    pid = _read_pid_from_file(pid_file)
    if pid == 0:
        return ("skip", "no live sidecar to restart")

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    if not os.path.isfile(dotenv_path):
        return ("skip", "no .env file to compare against")

    dotenv_token = ""
    try:
        with open(dotenv_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("DEFENSECLAW_GATEWAY_TOKEN="):
                    value = line[len("DEFENSECLAW_GATEWAY_TOKEN=") :]
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                        value = value[1:-1]
                    dotenv_token = value
                    break
    except OSError as exc:
        return ("warn", f"could not read {dotenv_path}: {exc}")
    if not dotenv_token:
        return ("skip", "no DEFENSECLAW_GATEWAY_TOKEN in .env to reconcile")

    process_token = _read_process_env_var(pid, "DEFENSECLAW_GATEWAY_TOKEN")
    if process_token is None:
        return ("skip", f"could not inspect sidecar pid {pid} env")
    if not process_token:
        return ("skip", f"sidecar pid {pid} has no DEFENSECLAW_GATEWAY_TOKEN in env")
    if process_token == dotenv_token:
        return ("skip", "sidecar token already matches .env")

    # Drift confirmed. Find the gateway binary and offer to restart.
    gw_binary = shutil.which("defenseclaw-gateway")
    if not gw_binary:
        return (
            "warn",
            "drift detected but defenseclaw-gateway not on PATH; restart the sidecar manually to reconcile",
        )

    if not assume_yes and not click.confirm(
        f"    Restart sidecar (pid {pid}) to pick up the current .env token? In-flight requests will be interrupted.",
        default=True,
    ):
        return ("skip", "declined by user")

    try:
        result = subprocess.run(
            [gw_binary, "restart"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ("fail", "restart command timed out after 30s")
    except OSError as exc:
        return ("fail", f"could not invoke restart: {exc}")

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "restart failed").strip().splitlines()
        return ("fail", detail[0] if detail else "restart failed")

    return ("pass", f"sidecar restarted; will now serve token from {dotenv_path}")


def _fix_dotenv_perms(cfg, *, assume_yes: bool) -> tuple[str, str]:
    """Ensure the dotenv file (which holds secrets) is not world-readable."""
    path = os.path.join(cfg.data_dir, ".env")
    if not os.path.isfile(path):
        return ("skip", "no dotenv file")

    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError as exc:
        return ("warn", f"stat failed: {exc}")

    if mode == 0o600:
        return ("skip", "permissions already 0600")

    if not assume_yes and not click.confirm(f"    Tighten {path} permissions from {mode:04o} to 0600?", default=True):
        return ("skip", "declined by user")

    try:
        os.chmod(path, 0o600)
        return ("pass", f"set {path} to 0600")
    except OSError as exc:
        return ("fail", f"chmod failed: {exc}")


def _fix_pristine_backup(cfg, *, assume_yes: bool) -> tuple[str, str]:
    """Capture a pristine backup of the active connector's config if one
    isn't recorded yet.

    For openclaw: backs up openclaw.json via the guardrail module.
    For other connectors: checks for their respective backup files in
    the data directory.
    """
    del assume_yes  # unused: capturing a snapshot is always safe
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


def _fix_plugin_registry_required(cfg, *, assume_yes: bool) -> tuple[str, str]:
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

    if not assume_yes and not click.confirm(
        f"    Clear the dead-end plugin.registry_required flag for [{', '.join(offenders)}] in config.yaml?",
        default=True,
    ):
        return ("skip", "declined by user")

    ap = getattr(cfg, "asset_policy", None)
    try:
        plugin = getattr(ap, "plugin", None)
        if plugin is not None and bool(getattr(plugin, "registry_required", False)):
            plugin.registry_required = False
        for pc in (getattr(ap, "connectors", None) or {}).values():
            pc_plugin = getattr(pc, "plugin", None) if pc is not None else None
            if pc_plugin is not None and getattr(pc_plugin, "registry_required", None) is True:
                # Tri-state per-connector field: None = inherit the (now
                # cleared) global value, so reset to None rather than False.
                pc_plugin.registry_required = None
        cfg.save()
    except (OSError, AttributeError) as exc:
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
