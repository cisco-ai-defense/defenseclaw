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
    # Route by *provider prefix* (the segment before the first "/"), not by
    # substring. A substring check on "anthropic" used to match Bedrock
    # inference profile ids like "amazon-bedrock/us.anthropic.claude-haiku-4-5"
    # and send non-Anthropic credentials (e.g. an AWS Bedrock bearer token held
    # in BIFROST_API_KEY) to api.anthropic.com, producing a spurious 401 FAIL.
    # Provider prefixes come from OpenClaw's model registry; see the docs at
    # https://docs.openclaw.ai/providers/ for the canonical list.
    provider = model.split("/", 1)[0].lower() if "/" in model else model.lower()
    if provider == "anthropic" or env_name.startswith("ANTHROPIC"):
        _verify_anthropic(api_key, r)
    elif provider == "openai" or env_name.startswith("OPENAI"):
        _verify_openai(api_key, r)
    else:
        _emit(
            "pass", "LLM API key",
            f"{env_name} is set (cannot verify provider '{model}')", r=r,
        )


def _verify_anthropic(api_key: str, r: _DoctorResult) -> None:
    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
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


def _check_splunk(cfg, r: _DoctorResult) -> None:
    if not cfg.splunk.enabled:
        _emit("skip", "Splunk HEC", "disabled", r=r)
        return

    hec_token = cfg.splunk.resolved_hec_token()
    if not cfg.splunk.hec_endpoint or not hec_token:
        _emit("fail", "Splunk HEC", "endpoint or token missing", r=r)
        return

    code, body = _http_probe(
        cfg.splunk.hec_endpoint,
        method="POST",
        headers={
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json",
        },
        body=json.dumps({"event": "defenseclaw-doctor-probe", "sourcetype": "_json"}).encode(),
        timeout=10.0,
    )

    if code == 200:
        _emit("pass", "Splunk HEC", cfg.splunk.hec_endpoint, r=r)
    elif code == 401 or code == 403:
        _emit("fail", "Splunk HEC", f"authentication failed (HTTP {code})", r=r)
    elif code == 0:
        _emit("warn", "Splunk HEC", f"unreachable: {body[:100]}", r=r)
    else:
        _emit("warn", "Splunk HEC", f"HTTP {code}", r=r)


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
    _check_splunk(cfg, r)

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


def run_doctor_checks(cfg) -> _DoctorResult:
    """Run all doctor checks programmatically (for use by setup --verify)."""
    r = _DoctorResult()

    click.echo()
    click.echo("  ── Verifying configuration ──")
    _check_llm_api_key(cfg, r)
    _check_guardrail_proxy(cfg, r)
    _check_sidecar(cfg, r)
    _check_openclaw_gateway(cfg, r)
    _check_cisco_ai_defense(cfg, r)

    click.echo()
    if r.failed:
        click.echo(click.style(f"  ⚠ {r.failed} check(s) failed", fg="red")
                    + " — review above and fix before using DefenseClaw")
    elif r.warned:
        click.echo(click.style(f"  {r.passed} passed, {r.warned} warning(s)", fg="yellow"))
    else:
        click.echo(click.style(f"  All {r.passed} checks passed", fg="green"))
    click.echo()
    return r
