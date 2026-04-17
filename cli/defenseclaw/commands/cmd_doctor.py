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

import json
import os
import shutil
import urllib.error
import urllib.request

import click

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.webhooks import list_webhooks, validate_webhook_url

_PASS = click.style("PASS", fg="green", bold=True)
_FAIL = click.style("FAIL", fg="red", bold=True)
_WARN = click.style("WARN", fg="yellow", bold=True)
_SKIP = click.style("SKIP", fg="bright_black")


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
    payload["captured_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
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


def _emit(tag: str, label: str, detail: str = "", *, r: _DoctorResult | None = None) -> None:
    if not _json_mode:
        icons = {"pass": _PASS, "fail": _FAIL, "warn": _WARN, "skip": _SKIP}
        icon = icons.get(tag, tag)
        line = f"  [{icon}] {label}"
        if detail:
            line += f"  —  {detail}"
        click.echo(line)
    if r is not None:
        r.record(tag, label, detail)


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


def _http_probe(url: str, *, method: str = "GET", headers: dict | None = None,
                body: bytes | None = None, timeout: float = 10.0) -> tuple[int, str]:
    """Fire an HTTP request; return (status_code, body_text). Returns (0, error) on failure."""
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")[:2000]
    except urllib.error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        return exc.code, body_text
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, str(exc)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_config(cfg, r: _DoctorResult) -> None:
    if os.path.isfile(os.path.join(cfg.data_dir, "config.yaml")):
        _emit("pass", "Config file", cfg.data_dir + "/config.yaml", r=r)
    else:
        _emit("fail", "Config file", "not found — run 'defenseclaw init'", r=r)


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
        path = shutil.which(binary)
        if path:
            _emit("pass", f"Scanner: {name}", path, r=r)
        else:
            _emit("fail", f"Scanner: {name}", f"'{binary}' not on PATH", r=r)


def _check_sidecar(cfg, r: _DoctorResult) -> None:
    bind = "127.0.0.1"
    if getattr(cfg, "openshell", None) and cfg.openshell.is_standalone():
        bind = getattr(cfg.guardrail, "host", None) or bind
    url = f"http://{bind}:{cfg.gateway.api_port}/health"
    code, body = _http_probe(url, timeout=5.0)
    if code == 200:
        _emit("pass", "Sidecar API", f"{bind}:{cfg.gateway.api_port}", r=r)

        try:
            health = json.loads(body)
            subsystems = ["gateway", "watcher", "guardrail", "api", "telemetry", "splunk", "sandbox"]
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
                    _emit("skip", f"  └─ {sub}", "disabled in config", r=r)
                else:
                    _emit("fail", f"  └─ {sub}", state, r=r)
        except (json.JSONDecodeError, TypeError):
            _emit("warn", "Sidecar health JSON", "could not parse /health response", r=r)
    else:
        _emit("fail", "Sidecar API", f"not reachable on port {cfg.gateway.api_port}", r=r)


def _check_openclaw_gateway(cfg, r: _DoctorResult) -> None:
    url = f"http://{cfg.gateway.host}:{cfg.gateway.port}/health"
    code, _ = _http_probe(url, timeout=5.0)
    if code == 200:
        _emit("pass", "OpenClaw gateway", f"{cfg.gateway.host}:{cfg.gateway.port}", r=r)
    else:
        _emit("fail", "OpenClaw gateway", f"not reachable at {cfg.gateway.host}:{cfg.gateway.port}", r=r)


def _check_guardrail_proxy(cfg, r: _DoctorResult) -> None:
    if not cfg.guardrail.enabled:
        _emit("skip", "Guardrail proxy", "disabled", r=r)
        return

    if not cfg.guardrail.model:
        _emit(
            "warn", "Guardrail proxy",
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


def _check_llm_api_key(cfg, r: _DoctorResult) -> None:
    gc = cfg.guardrail
    if not gc.enabled:
        _emit("skip", "LLM API key", "guardrail disabled", r=r)
        return

    env_name = gc.api_key_env
    if not env_name:
        _emit("fail", "LLM API key", "api_key_env not configured", r=r)
        return

    dotenv_path = os.path.join(cfg.data_dir, ".env")
    api_key = _resolve_api_key(env_name, dotenv_path)

    if not api_key:
        _emit("fail", "LLM API key", f"{env_name} not set (checked env + {dotenv_path})", r=r)
        return

    model = gc.model or ""
    # Route by *provider prefix* (the segment before the first "/"). The
    # env-name prefix is a last-resort fallback ONLY used when the model
    # string is empty or has no provider prefix — routing on env name can
    # easily misfire (e.g. an operator reusing ANTHROPIC_API_KEY to hold a
    # bearer token for a proxy). Provider prefixes come from OpenClaw's
    # model registry; see https://docs.openclaw.ai/providers/.
    provider = ""
    if "/" in model:
        provider = model.split("/", 1)[0].lower()
    elif model:
        provider = model.lower()

    if provider == "anthropic":
        _verify_anthropic(api_key, r, model)
    elif provider == "openai":
        _verify_openai(api_key, r)
    elif provider == "" and env_name.startswith("ANTHROPIC"):
        # Model string missing — fall back to env name prefix.
        _verify_anthropic(api_key, r, model)
    elif provider == "" and env_name.startswith("OPENAI"):
        _verify_openai(api_key, r)
    else:
        _emit(
            "pass", "LLM API key",
            f"{env_name} is set (cannot verify provider '{model}')", r=r,
        )


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


def _verify_anthropic(api_key: str, r: _DoctorResult, configured_model: str = "") -> None:
    probe_model = _anthropic_probe_model(configured_model)
    payload = json.dumps({
        "model": probe_model,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }).encode()
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

    health_url = endpoint.rstrip("/") + "/health"
    code, body = _http_probe(
        health_url,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=float(cfg.cisco_ai_defense.timeout_ms) / 1000.0,
    )

    if code == 200:
        _emit("pass", "Cisco AI Defense", endpoint, r=r)
    elif code == 401 or code == 403:
        _emit("fail", "Cisco AI Defense", f"authentication failed (HTTP {code})", r=r)
    elif code == 0:
        _emit("warn", "Cisco AI Defense", f"endpoint unreachable: {body[:100]}", r=r)
    else:
        _emit("warn", "Cisco AI Defense", f"HTTP {code} (endpoint may not support /health)", r=r)


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
        label_kind = PRESETS[d.preset_id].display_name if d.preset_id in PRESETS else d.kind
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


def _probe_splunk_hec(cfg, d, r: _DoctorResult) -> None:
    """HEC probe: POST a single test event with the resolved token."""
    endpoint, token = _resolve_audit_sink_endpoint_and_token(cfg, d)
    if not endpoint or not token:
        _emit("fail", f"{d.name} (Splunk HEC)", "endpoint or token missing", r=r)
        return

    code, body = _http_probe(
        endpoint,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
        body=json.dumps({"event": "defenseclaw-doctor-probe", "sourcetype": "_json"}).encode(),
        timeout=10.0,
    )

    label = f"{d.name} (Splunk HEC)"
    if code == 200:
        _emit("pass", label, endpoint, r=r)
    elif code in (401, 403):
        _emit("fail", label, f"authentication failed (HTTP {code})", r=r)
    elif code == 0:
        _emit("warn", label, f"unreachable: {body[:100]}", r=r)
    else:
        _emit("warn", label, f"HTTP {code}", r=r)


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
    # writer's layout (CONFIG_FILE_NAME under data_dir).
    from defenseclaw.observability.writer import CONFIG_FILE_NAME, _load_yaml

    try:
        doc = _load_yaml(os.path.join(cfg.data_dir, CONFIG_FILE_NAME))
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
# Main command
# ---------------------------------------------------------------------------

@click.command()
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON")
@pass_ctx
def doctor(app: AppContext, json_out: bool) -> None:
    """Verify credentials, endpoints, and connectivity.

    Runs a series of checks against every configured service and API key
    to catch problems before they surface at runtime.

    Exit codes: 0 = all pass, 1 = any failure.
    """
    global _json_mode
    cfg = app.cfg
    r = _DoctorResult()
    _json_mode = json_out

    if not json_out:
        click.echo()
        click.echo("DefenseClaw Doctor")
        click.echo("══════════════════")
        click.echo()

    _check_config(cfg, r)
    _check_audit_db(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Scanners ──")
    _check_scanners(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Services ──")
    _check_sidecar(cfg, r)
    _check_openclaw_gateway(cfg, r)
    _check_guardrail_proxy(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Credentials ──")
    _check_llm_api_key(cfg, r)
    _check_cisco_ai_defense(cfg, r)
    _check_virustotal(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Observability ──")
    _check_observability(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Webhooks ──")
    _check_webhooks(cfg, r)

    # Persist the cached snapshot before exit so the Go TUI (and any
    # other cron-style caller) can pick it up without re-probing. We
    # do this *before* the SystemExit(1) below so failing runs still
    # update the cache — the TUI needs to see "doctor last reported
    # 2 failures", not a stale green state from yesterday.
    _write_doctor_cache(cfg, r)

    if json_out:
        click.echo(json.dumps(r.to_dict(), indent=2))
    else:
        click.echo()
        click.echo("  ── Summary ──")
        parts = []
        if r.passed:
            parts.append(click.style(f"{r.passed} passed", fg="green"))
        if r.failed:
            parts.append(click.style(f"{r.failed} failed", fg="red"))
        if r.warned:
            parts.append(click.style(f"{r.warned} warnings", fg="yellow"))
        if r.skipped:
            parts.append(click.style(f"{r.skipped} skipped", dim=True))
        click.echo("  " + ", ".join(parts))
        click.echo()

    if r.failed:
        if not json_out:
            click.echo("  Fix the failures above, then re-run: defenseclaw doctor")
            click.echo()
        raise SystemExit(1)

    if app.logger:
        app.logger.log_action(
            "doctor", "health-check",
            f"passed={r.passed} failed={r.failed} warned={r.warned} skipped={r.skipped}",
        )


# Note: earlier revisions exposed a ``run_doctor_checks(cfg)`` helper
# that bundled a subset of checks for ``setup --verify``. It was never
# wired up — ``cmd_setup.py`` calls each ``_check_*`` directly — and the
# helper also wrote a partial cache that would clobber a full-coverage
# ``doctor_cache.json``. It has been removed to prevent the Overview
# panel from silently reporting "3 pass" after a partial verify.
