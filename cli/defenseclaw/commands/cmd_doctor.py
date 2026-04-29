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


def _check_hilt_support(cfg, connector: str, r: _DoctorResult) -> None:
    guardrail = getattr(cfg, "guardrail", None)
    hilt = getattr(guardrail, "hilt", None)
    if not bool(getattr(hilt, "enabled", False)):
        _emit("pass", "Human approval", "disabled (default)", r=r)
        return

    min_sev = (getattr(hilt, "min_severity", "") or "HIGH").upper()
    mode = (getattr(guardrail, "mode", "") or "observe").lower()
    if mode != "action":
        _emit("warn", "Human approval", f"enabled at {min_sev}, but guardrail.mode is observe", r=r)
        return

    if connector == "openclaw":
        _emit("pass", "Human approval", f"OpenClaw prompts supported at {min_sev}+", r=r)
    elif connector == "claudecode":
        _emit("pass", "Human approval", f"Claude Code PreToolUse ask supported at {min_sev}+", r=r)
    elif connector == "codex":
        _emit(
            "warn", "Human approval",
            "Codex uses native PermissionRequest prompts only; PreToolUse ask is unsupported",
            r=r,
        )
    elif connector == "zeptoclaw":
        _emit(
            "warn", "Human approval",
            "ZeptoClaw has no native before-tool hook; unsupported confirmations alert only",
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
        path = shutil.which(binary)
        if path:
            _emit("pass", f"Scanner: {name}", path, r=r)
        else:
            _emit("fail", f"Scanner: {name}", f"'{binary}' not on PATH", r=r)


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
    code, body = _http_probe(url, timeout=5.0)
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
                            "disabled (reported by sidecar) but enabled in config "
                            "— sidecar is stale, restart it",
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
                        _emit("skip", f"  └─ {sub}", "disabled (reported by sidecar)", r=r)
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


def _check_claudecode_hooks(cfg, r: _DoctorResult) -> None:
    settings_path = os.path.expanduser("~/.claude/settings.json")
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
    else:
        _emit("fail", "Claude Code hooks", "no DefenseClaw hooks found in settings.json", r=r)


def _check_codex_hooks(cfg, r: _DoctorResult) -> None:
    hook_dir = os.path.join(cfg.data_dir, "hooks")
    hook_script = os.path.join(hook_dir, "codex-hook.sh")
    if os.path.isfile(hook_script):
        _emit("pass", "Codex hooks", f"hook script at {hook_script}", r=r)
    else:
        _emit("fail", "Codex hooks", f"hook script not found at {hook_script}", r=r)


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


def _guardrail_proxy_intentionally_closed(cfg) -> str:
    """Return a detail string when the proxy port is expected to be closed.

    Codex and Claude Code default to observability-only mode: hooks and
    native OTel feed DefenseClaw, but the agent talks directly to its
    upstream provider. In that mode port 4000 is deliberately unbound, so
    doctor must not report a hard proxy failure.
    """
    connector = _active_connector(cfg)
    gc = cfg.guardrail
    if connector == "codex" and not getattr(gc, "codex_enforcement_enabled", False):
        return "observability-only for Codex — proxy port intentionally closed"
    if connector == "claudecode" and not getattr(gc, "claudecode_enforcement_enabled", False):
        return "observability-only for Claude Code — proxy port intentionally closed"
    return ""


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

    llm = cfg.resolve_llm("guardrail")
    model = llm.model or gc.model or ""

    if llm.is_local_provider():
        base = llm.base_url or "(default)"
        if not model:
            _emit(
                "warn", "LLM API key",
                f"local provider '{llm.provider}' configured (base_url={base}) but no model set",
                r=r,
            )
        else:
            _emit(
                "skip", "LLM API key",
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
            "pass", "LLM API key",
            f"{env_name} is set (cannot verify provider '{provider or model}')", r=r,
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

# Default model used for the Anthropic auth probe when the configured model
# is not an Anthropic model. The probe sends max_tokens=1 so cost is
# negligible; any valid model id accepted by the account works. We pick a
# stable identifier that the OpenClaw docs list as generally available.
# Operators running against an older plan can override via
# DEFENSECLAW_ANTHROPIC_PROBE_MODEL.
_ANTHROPIC_DEFAULT_PROBE_MODEL = "claude-3-5-haiku-latest"

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
            "warn", "LLM API key (Bedrock)",
            "AWS SigV4 credentials detected — doctor skips signed probes; "
            "run 'aws sts get-caller-identity' to verify.",
            r=r,
        )
        return
    if not api_key.startswith("ABSK"):
        _emit(
            "pass", "LLM API key (Bedrock)",
            f"key is set ({len(api_key)} chars) but shape not recognized; "
            "assuming operator knows what they're doing.",
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
            "warn", "LLM API key (Bedrock)",
            "403 Forbidden — key authenticates but lacks "
            "bedrock:ListFoundationModels; InvokeModel may still work.",
            r=r,
        )
    elif code == 0:
        _emit(
            "warn", "LLM API key (Bedrock)",
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
@click.option("--fix", "do_fix", is_flag=True, help="Auto-repair safe issues (stale PIDs, OpenClaw token drift, etc.)")
@click.option("--yes", "assume_yes", is_flag=True, help="When used with --fix, apply fixes without prompting")
@pass_ctx
def doctor(app: AppContext, json_out: bool, do_fix: bool, assume_yes: bool) -> None:
    """Verify credentials, endpoints, and connectivity.

    Runs a series of checks against every configured service and API key
    to catch problems before they surface at runtime.

    Use ``--fix`` to auto-repair safe issues (stale sidecar PID files,
    OpenClaw gateway token drift, missing .env file, and unpatched
    openclaw.json when the guardrail is enabled). Destructive or
    ambiguous fixes still require the operator to run the relevant
    setup command explicitly.

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

    # S6.5 — surface the active connector + its configured paths
    # before any scanner runs. Operators routinely point doctor at a
    # config that *thinks* it's running on (say) Codex but actually
    # has stale openclaw.json paths under .openclaw/extensions; a
    # per-connector inventory pass catches that drift.
    if not json_out:
        click.echo()
        click.echo("  ── Connector ──")
    active_connector = _active_connector(cfg)
    _check_connector_inventory(cfg, active_connector, r)
    # S7.5 — surface inactive-connector residue (backup files / hook
    # scripts left over from a previous connector). Without this check
    # operators who switch connectors via 'defenseclaw setup guardrail
    # --agent <new>' get a silent half-state where the old adapter's
    # config patches are still on disk.
    _check_connector_residue(cfg, active_connector, r)

    if not json_out:
        click.echo()
        click.echo("  ── Scanners ──")
    _check_scanners(cfg, r)
    _check_scan_coverage(cfg, r)

    if not json_out:
        click.echo()
        click.echo("  ── Services ──")
    _check_sidecar(cfg, r)
    if active_connector == "openclaw":
        _check_openclaw_gateway(cfg, r)
    elif active_connector == "claudecode":
        _check_claudecode_hooks(cfg, r)
    elif active_connector == "codex":
        _check_codex_hooks(cfg, r)
    elif active_connector == "zeptoclaw":
        _check_zeptoclaw_config(cfg, r)
    _check_hilt_support(cfg, active_connector, r)
    _check_guardrail_proxy(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Credentials ──")
    _check_llm_api_key(cfg, r)
    _check_cisco_ai_defense(cfg, r)
    _check_virustotal(cfg, r)
    _check_registry_credentials(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Observability ──")
    _check_observability(cfg, r)
    if not json_out:
        click.echo()
        click.echo("  ── Webhooks ──")
    _check_webhooks(cfg, r)

    if do_fix:
        if not json_out:
            click.echo()
            click.echo("  ── Auto-fix ──")
        _run_fixers(cfg, r, assume_yes=assume_yes, json_out=json_out)

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

def _run_fixers(cfg, r: _DoctorResult, *, assume_yes: bool, json_out: bool) -> None:
    """Run each fixer in sequence, narrating what changed.

    Fixers are intentionally *small* and independent — none of them
    restart the sidecar or mutate connector configs beyond what setup
    already would. Anything that needs a full re-patch is deferred to
    the human.
    """
    fixers = [
        ("stale gateway PID file",   _fix_stale_pid),
        ("gateway token",            _fix_gateway_token),
        ("defenseclaw dotenv perms", _fix_dotenv_perms),
        ("pristine config backup",   _fix_pristine_backup),
        ("connector residue",        _fix_connector_residue),
    ]

    for title, fn in fixers:
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
    return (getattr(getattr(cfg, "guardrail", None), "connector", "")
            or "openclaw").lower()


_CONNECTOR_LABELS = {
    "openclaw": "OpenClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "zeptoclaw": "ZeptoClaw",
}


def _check_connector_inventory(cfg, connector: str, r: _DoctorResult) -> None:
    """Surface the active connector and the directories it points at.

    Each connector has its own conventions for where skills, plugins,
    and MCP server registrations live. ``Config.skill_dirs()`` /
    ``plugin_dirs()`` / ``mcp_servers()`` are now polymorphic per
    connector (S4.1), so this check makes that mapping visible to the
    operator: if Codex is active but skill_dirs() still points at
    ``~/.openclaw/skills``, that's a config bug doctor should flag.
    """
    label = _CONNECTOR_LABELS.get(connector, connector)
    if connector not in _CONNECTOR_LABELS:
        _emit(
            "warn", "Active connector",
            f"unknown connector {connector!r} — known: "
            + ", ".join(sorted(_CONNECTOR_LABELS)),
            r=r,
        )
    else:
        _emit("pass", "Active connector", label, r=r)

    # Skill dirs.
    try:
        sdirs = cfg.skill_dirs() if hasattr(cfg, "skill_dirs") else []
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

    # Plugin dirs.
    try:
        pdirs = cfg.plugin_dirs() if hasattr(cfg, "plugin_dirs") else []
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

    # MCP servers.
    try:
        servers = cfg.mcp_servers() if hasattr(cfg, "mcp_servers") else []
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


# Maps connector name → list of *expected* artifact filenames (relative
# to data_dir) that Connector.Setup writes. When the active connector
# is X but data_dir contains Y's artifacts, that's residue from a prior
# install and Connector.Teardown was never invoked for Y.
#
# The OpenClaw pristine backup lives at ``<openclaw.json>.pristine``,
# which is not under data_dir, so it is handled separately by
# :func:`_check_connector_residue`.
_CONNECTOR_RESIDUE_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "claudecode": ("claudecode_backup.json",),
    "codex": ("codex_backup.json",),
    "zeptoclaw": ("zeptoclaw_backup.json",),
}


def _check_connector_residue(cfg, active: str, r: _DoctorResult) -> None:
    """Detect leftover artifacts from connectors that aren't active.

    Each connector's ``Setup`` writes a pristine backup of the agent
    framework's config plus (for some connectors) hook scripts and env
    files. ``Teardown`` removes them. When an operator switches
    connectors without first running ``defenseclaw guardrail disable``
    (or the gateway crashes mid-handoff), we end up with the *prior*
    connector's residue on disk.

    This check walks every known connector that isn't the active one
    and emits a WARN listing any artifact still present. The matching
    fixer (``fix: connector residue``) calls
    ``defenseclaw-gateway connector teardown --connector <name>`` for
    each residual connector to clean it up via the canonical sentinel.
    """
    data_dir = getattr(cfg, "data_dir", "") or ""
    if not data_dir:
        _emit("skip", "Connector residue", "no data dir configured", r=r)
        return

    # Build the inactive set explicitly so unknown active connectors
    # (plugins) don't accidentally suppress residue detection.
    inactive = [
        name for name in _CONNECTOR_RESIDUE_ARTIFACTS
        if name != active.lower()
    ]

    found: list[tuple[str, str]] = []  # (connector_name, full_path)
    for name in inactive:
        for filename in _CONNECTOR_RESIDUE_ARTIFACTS[name]:
            full = os.path.join(data_dir, filename)
            if os.path.isfile(full):
                found.append((name, full))

    # OpenClaw's pristine backup is its only residue marker and lives
    # next to openclaw.json, not under data_dir. Only flag it when
    # OpenClaw is *not* the active connector.
    if active.lower() != "openclaw":
        oc_path = getattr(getattr(cfg, "claw", None), "config_file", "") or ""
        oc_path = os.path.expanduser(oc_path)
        if oc_path:
            pristine = oc_path + ".pristine"
            if os.path.isfile(pristine):
                found.append(("openclaw", pristine))

    if not found:
        _emit(
            "pass", "Connector residue",
            "no leftover artifacts from inactive connectors", r=r,
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
        + ". Run 'defenseclaw doctor --fix' to invoke "
        "'defenseclaw-gateway connector teardown' for each, or "
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
            component, (component, component + "s"),
        )[0]
        if cats:
            _emit(
                "pass", f"Scanner coverage ({label})",
                "; ".join(cats), r=r,
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

    if not assume_yes and not click.confirm(
        f"    Remove stale pid file {pid_file}?", default=True
    ):
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

    if not assume_yes and not click.confirm(
        f"    Tighten {path} permissions from {mode:04o} to 0600?", default=True
    ):
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

    backup_map = {
        "claudecode": "claudecode_backup.json",
        "codex": "codex_backup.json",
        "zeptoclaw": "zeptoclaw_backup.json",
    }
    backup_name = backup_map.get(active_connector)
    if not backup_name:
        return ("skip", f"no backup strategy for connector {active_connector}")
    backup_path = os.path.join(cfg.data_dir, backup_name)
    if os.path.isfile(backup_path):
        return ("skip", f"backup exists at {backup_path}")
    return ("skip", "no backup found — run `defenseclaw setup guardrail` to create one")


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

    active = _active_connector(cfg)
    inactive_residue: list[str] = []
    for name, artifacts in _CONNECTOR_RESIDUE_ARTIFACTS.items():
        if name == active:
            continue
        if any(os.path.isfile(os.path.join(data_dir, f)) for f in artifacts):
            inactive_residue.append(name)

    if active != "openclaw":
        oc_path = getattr(getattr(cfg, "claw", None), "config_file", "") or ""
        oc_path = os.path.expanduser(oc_path)
        if oc_path and os.path.isfile(oc_path + ".pristine"):
            inactive_residue.append("openclaw")

    if not inactive_residue:
        return ("skip", "no inactive-connector residue detected")

    inactive_residue = sorted(set(inactive_residue))

    if not assume_yes and not click.confirm(
        f"    Run 'defenseclaw-gateway connector teardown' for "
        f"{', '.join(inactive_residue)}?",
        default=True,
    ):
        return ("skip", "declined by user")

    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return ("warn",
                "defenseclaw-gateway not on PATH — install the binary and re-run")

    cleaned: list[str] = []
    failed: list[str] = []
    import subprocess as _sub
    for name in inactive_residue:
        try:
            proc = _sub.run(
                [gw, "connector", "teardown", "--connector", name],
                capture_output=True, text=True, timeout=60,
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
        return ("warn",
                f"partial: cleaned={','.join(cleaned)}; failed={'; '.join(failed)}")
    return ("warn", f"teardown failed: {'; '.join(failed)}")
