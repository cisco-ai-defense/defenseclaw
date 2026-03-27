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

"""defenseclaw setup — Configure DefenseClaw settings and integrations.

Mirrors internal/cli/setup.go.
"""

from __future__ import annotations

import json as _json
import os
import shutil
import socket
import subprocess

import click

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.paths import bundled_extensions_dir, splunk_bridge_bin


@click.group()
def setup() -> None:
    """Configure DefenseClaw components."""


@setup.command("skill-scanner")
@click.option("--use-llm", is_flag=True, default=None, help="Enable LLM analyzer")
@click.option("--use-behavioral", is_flag=True, default=None, help="Enable behavioral analyzer")
@click.option("--enable-meta", is_flag=True, default=None, help="Enable meta-analyzer")
@click.option("--use-trigger", is_flag=True, default=None, help="Enable trigger analyzer")
@click.option("--use-virustotal", is_flag=True, default=None, help="Enable VirusTotal scanner")
@click.option("--use-aidefense", is_flag=True, default=None, help="Enable AI Defense analyzer")
@click.option("--llm-provider", default=None, help="LLM provider (anthropic or openai)")
@click.option("--llm-model", default=None, help="LLM model name")
@click.option("--llm-consensus-runs", type=int, default=None, help="LLM consensus runs (0=disabled)")
@click.option("--policy", default=None, help="Scan policy preset (strict, balanced, permissive)")
@click.option("--lenient", is_flag=True, default=None, help="Tolerate malformed skills")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_skill_scanner(
    app: AppContext,
    use_llm, use_behavioral, enable_meta, use_trigger,
    use_virustotal, use_aidefense,
    llm_provider, llm_model, llm_consensus_runs,
    policy, lenient, verify, non_interactive,
) -> None:
    """Configure skill-scanner analyzers, API keys, and policy.

    Interactively configure how skill-scanner runs. Enables LLM analysis,
    behavioral dataflow analysis, meta-analyzer filtering, and more.

    LLM and Cisco AI Defense settings are stored in the shared
    inspect_llm and cisco_ai_defense config sections.

    Use --non-interactive with flags for CI/scripted configuration.
    """
    sc = app.cfg.scanners.skill_scanner
    llm = app.cfg.inspect_llm
    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        if use_llm is not None:
            sc.use_llm = use_llm
        if use_behavioral is not None:
            sc.use_behavioral = use_behavioral
        if enable_meta is not None:
            sc.enable_meta = enable_meta
        if use_trigger is not None:
            sc.use_trigger = use_trigger
        if use_virustotal is not None:
            sc.use_virustotal = use_virustotal
        if use_aidefense is not None:
            sc.use_aidefense = use_aidefense
        if llm_provider is not None:
            llm.provider = llm_provider
        if llm_model is not None:
            llm.model = llm_model
        if llm_consensus_runs is not None:
            sc.llm_consensus_runs = llm_consensus_runs
        if policy is not None:
            sc.policy = policy
        if lenient is not None:
            sc.lenient = lenient
    else:
        _interactive_setup(sc, llm, aid, app.cfg.data_dir)

    app.cfg.save()
    _print_summary(sc, llm, aid)

    if verify:
        from defenseclaw.commands.cmd_doctor import _check_scanners, _check_virustotal, _DoctorResult
        click.echo("  ── Verifying scanner configuration ──")
        r = _DoctorResult()
        _check_scanners(app.cfg, r)
        _check_virustotal(app.cfg, r)
        click.echo()
        if r.failed:
            click.echo("  Tip: fix the issues above, then run 'defenseclaw doctor' to re-check.")
            click.echo()

    if app.logger:
        parts = [f"use_llm={sc.use_llm}", f"use_behavioral={sc.use_behavioral}", f"enable_meta={sc.enable_meta}"]
        if llm.provider:
            parts.append(f"llm_provider={llm.provider}")
        if sc.policy:
            parts.append(f"policy={sc.policy}")
        app.logger.log_action("setup-skill-scanner", "config", " ".join(parts))


def _interactive_setup(sc, llm, aid, data_dir: str) -> None:
    click.echo()
    click.echo("  Skill Scanner Configuration")
    click.echo("  ────────────────────────────")
    click.echo(f"  Binary: {sc.binary}")
    click.echo()

    sc.use_behavioral = click.confirm("  Enable behavioral analyzer (dataflow analysis)?", default=sc.use_behavioral)
    sc.use_llm = click.confirm("  Enable LLM analyzer (semantic analysis)?", default=sc.use_llm)

    if sc.use_llm:
        _configure_inspect_llm(llm, data_dir)
        sc.enable_meta = click.confirm("  Enable meta-analyzer (false positive filtering)?", default=sc.enable_meta)
        sc.llm_consensus_runs = click.prompt(
            "  LLM consensus runs (0 = disabled)", type=int, default=sc.llm_consensus_runs,
        )
    else:
        llm.api_key = ""
        llm.api_key_env = ""

    sc.use_trigger = click.confirm("  Enable trigger analyzer (vague description checks)?", default=sc.use_trigger)
    sc.use_virustotal = click.confirm("  Enable VirusTotal binary scanner?", default=sc.use_virustotal)
    if sc.use_virustotal:
        _prompt_and_save_secret("VIRUSTOTAL_API_KEY", sc.virustotal_api_key, data_dir)
        sc.virustotal_api_key = ""
        sc.virustotal_api_key_env = "VIRUSTOTAL_API_KEY"
    else:
        sc.virustotal_api_key = ""
        sc.virustotal_api_key_env = ""

    sc.use_aidefense = click.confirm("  Enable Cisco AI Defense analyzer?", default=sc.use_aidefense)
    if sc.use_aidefense:
        _configure_cisco_ai_defense(aid, data_dir)
    else:
        aid.api_key = ""
        aid.api_key_env = ""

    click.echo()
    choices = ["strict", "balanced", "permissive"]
    val = click.prompt(
        f"  Scan policy preset ({'/'.join(choices)})",
        default=sc.policy or "none", show_default=True,
    )
    if val in choices:
        sc.policy = val
    elif val == "none":
        sc.policy = ""

    sc.lenient = click.confirm("  Lenient mode (tolerate malformed skills)?", default=sc.lenient)


def _configure_inspect_llm(llm, data_dir: str) -> None:
    """Prompt for shared inspect_llm settings (provider, model, API key).

    The API key is stored in ~/.defenseclaw/.env, not in config.yaml.
    """
    from defenseclaw.guardrail import detect_api_key_env
    llm.provider = click.prompt(
        "  LLM provider (anthropic/openai)",
        default=llm.provider or "anthropic",
    )
    llm.model = click.prompt("  LLM model name", default=llm.model or "", show_default=False)
    env_name = detect_api_key_env(f"{llm.provider}/{llm.model}")
    _prompt_and_save_secret(env_name, llm.api_key, data_dir)
    llm.api_key = ""
    llm.api_key_env = env_name
    llm.base_url = click.prompt(
        "  LLM base URL (leave blank to use provider default)",
        default=llm.base_url or "", show_default=False,
    )
    llm.timeout = click.prompt("  LLM timeout (seconds)", type=int, default=llm.timeout)
    llm.max_retries = click.prompt("  LLM max retries", type=int, default=llm.max_retries)


def _configure_cisco_ai_defense(aid, data_dir: str) -> None:
    """Prompt for shared cisco_ai_defense settings (endpoint, API key).

    The API key is stored in ~/.defenseclaw/.env, not in config.yaml.
    """
    aid.endpoint = click.prompt(
        "  Cisco AI Defense endpoint URL",
        default=aid.endpoint,
    )
    _prompt_and_save_secret("CISCO_AI_DEFENSE_API_KEY", aid.api_key, data_dir)
    aid.api_key = ""
    aid.api_key_env = "CISCO_AI_DEFENSE_API_KEY"


def _prompt_and_save_secret(env_name: str, current: str, data_dir: str) -> None:
    """Prompt for a secret, save it to ~/.defenseclaw/.env, and set it in os.environ.

    The value is never returned — callers should store only the *env var name*
    in config.yaml (via the corresponding ``*_env`` field).
    """
    dotenv_path = os.path.join(data_dir, ".env")
    dotenv_val = _load_dotenv(dotenv_path).get(env_name, "")
    env_val = os.environ.get(env_name, "")
    effective = current or env_val or dotenv_val
    if effective:
        hint = _mask(effective)
    else:
        hint = "(not set)"
    val = click.prompt(f"  {env_name} [{hint}]", default="", show_default=False)
    secret = val or effective
    if secret:
        _save_secret_to_dotenv(env_name, secret, data_dir)


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]


def _load_dotenv(path: str) -> dict[str, str]:
    """Read a KEY=VALUE .env file into a dict."""
    result: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                if k:
                    result[k] = v
    except FileNotFoundError:
        pass
    return result


def _write_dotenv(path: str, entries: dict[str, str]) -> None:
    """Write entries to a .env file with mode 0600."""
    lines = [f"{k}={v}\n" for k, v in sorted(entries.items())]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.writelines(lines)


def _print_summary(sc, llm, aid) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows: list[tuple[str, str, str]] = [
        ("scanners.skill_scanner", "use_behavioral", str(sc.use_behavioral).lower()),
        ("scanners.skill_scanner", "use_llm", str(sc.use_llm).lower()),
    ]
    if sc.use_llm:
        rows.append(("inspect_llm", "provider", llm.provider))
        if llm.model:
            rows.append(("inspect_llm", "model", llm.model))
        rows.append(("scanners.skill_scanner", "enable_meta", str(sc.enable_meta).lower()))
        if sc.llm_consensus_runs > 0:
            rows.append(("scanners.skill_scanner", "llm_consensus_runs", str(sc.llm_consensus_runs)))
        api_key = llm.resolved_api_key()
        if api_key:
            rows.append(("inspect_llm", "api_key_env", llm.api_key_env or "(in .env)"))
    if sc.use_trigger:
        rows.append(("scanners.skill_scanner", "use_trigger", "true"))
    if sc.use_virustotal:
        rows.append(("scanners.skill_scanner", "use_virustotal", "true"))
        vt_key = sc.resolved_virustotal_api_key()
        if vt_key:
            rows.append(("scanners.skill_scanner", "virustotal_api_key_env", sc.virustotal_api_key_env or "(in .env)"))
    if sc.use_aidefense:
        rows.append(("scanners.skill_scanner", "use_aidefense", "true"))
        rows.append(("cisco_ai_defense", "endpoint", aid.endpoint))
    if sc.policy:
        rows.append(("scanners.skill_scanner", "policy", sc.policy))
    if sc.lenient:
        rows.append(("scanners.skill_scanner", "lenient", "true"))

    for section, key, val in rows:
        click.echo(f"    {section}.{key + ':':<22s} {val}")
    click.echo()


# ---------------------------------------------------------------------------
# setup mcp-scanner
# ---------------------------------------------------------------------------

@setup.command("mcp-scanner")
@click.option("--analyzers", default=None, help="Comma-separated analyzer list (yara,api,llm,behavioral,readiness)")
@click.option("--llm-provider", default=None, help="LLM provider (anthropic or openai)")
@click.option("--llm-model", default=None, help="LLM model for semantic analysis")
@click.option("--scan-prompts", is_flag=True, default=None, help="Scan MCP prompts")
@click.option("--scan-resources", is_flag=True, default=None, help="Scan MCP resources")
@click.option("--scan-instructions", is_flag=True, default=None, help="Scan server instructions")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_mcp_scanner(
    app: AppContext,
    analyzers,
    llm_provider, llm_model,
    scan_prompts, scan_resources, scan_instructions,
    non_interactive,
) -> None:
    """Configure mcp-scanner analyzers and scan options.

    Interactively configure how mcp-scanner runs. MCP servers are managed
    via ``defenseclaw mcp set/unset`` rather than directory watching.

    LLM and Cisco AI Defense settings are stored in the shared
    inspect_llm and cisco_ai_defense config sections.

    Use --non-interactive with flags for CI/scripted configuration.
    """
    mc = app.cfg.scanners.mcp_scanner
    llm = app.cfg.inspect_llm
    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        if analyzers is not None:
            mc.analyzers = analyzers
        if llm_provider is not None:
            llm.provider = llm_provider
        if llm_model is not None:
            llm.model = llm_model
        if scan_prompts is not None:
            mc.scan_prompts = scan_prompts
        if scan_resources is not None:
            mc.scan_resources = scan_resources
        if scan_instructions is not None:
            mc.scan_instructions = scan_instructions
    else:
        _interactive_mcp_setup(mc, app.cfg)

    app.cfg.save()
    _print_mcp_summary(mc, llm, aid)

    if app.logger:
        parts = [f"analyzers={mc.analyzers or 'default'}"]
        if llm.provider:
            parts.append(f"llm_provider={llm.provider}")
        if llm.model:
            parts.append(f"llm_model={llm.model}")
        parts.append("mcp_managed_via=openclaw_config")
        app.logger.log_action("setup-mcp-scanner", "config", " ".join(parts))


def _interactive_mcp_setup(mc, cfg) -> None:
    llm = cfg.inspect_llm
    aid = cfg.cisco_ai_defense

    click.echo()
    click.echo("  MCP Scanner Configuration")
    click.echo("  ──────────────────────────")
    click.echo(f"  Binary: {mc.binary}")
    click.echo()

    mc.analyzers = click.prompt(
        "  Analyzers (comma-separated, e.g. yara,behavioral,readiness)",
        default=mc.analyzers or "yara",
    )

    use_llm = click.confirm("  Enable LLM analyzer?", default=bool(llm.model))
    if use_llm:
        _configure_inspect_llm(llm, cfg.data_dir)
        if "llm" not in mc.analyzers:
            mc.analyzers = f"{mc.analyzers},llm" if mc.analyzers else "llm"

    click.echo()
    use_api = click.confirm("  Enable API analyzer (Cisco AI Defense)?", default=False)
    if use_api:
        _configure_cisco_ai_defense(aid, cfg.data_dir)
        if "api" not in mc.analyzers:
            mc.analyzers = f"{mc.analyzers},api" if mc.analyzers else "api"

    click.echo()
    mc.scan_prompts = click.confirm("  Scan MCP prompts?", default=mc.scan_prompts)
    mc.scan_resources = click.confirm("  Scan MCP resources?", default=mc.scan_resources)
    mc.scan_instructions = click.confirm("  Scan server instructions?", default=mc.scan_instructions)



def _print_mcp_summary(mc, llm, aid) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows: list[tuple[str, str, str]] = [
        ("scanners.mcp_scanner", "analyzers", mc.analyzers or "(all)"),
    ]
    if llm.provider:
        rows.append(("inspect_llm", "provider", llm.provider))
    if llm.model:
        rows.append(("inspect_llm", "model", llm.model))
        api_key = llm.resolved_api_key()
        if api_key:
            rows.append(("inspect_llm", "api_key", _mask(api_key)))
    if aid.endpoint:
        rows.append(("cisco_ai_defense", "endpoint", aid.endpoint))
    if mc.scan_prompts:
        rows.append(("scanners.mcp_scanner", "scan_prompts", "true"))
    if mc.scan_resources:
        rows.append(("scanners.mcp_scanner", "scan_resources", "true"))
    if mc.scan_instructions:
        rows.append(("scanners.mcp_scanner", "scan_instructions", "true"))

    for section, key, val in rows:
        click.echo(f"    {section}.{key + ':':<22s} {val}")
    click.echo()


# ---------------------------------------------------------------------------
# setup gateway
# ---------------------------------------------------------------------------

@setup.command("gateway")
@click.option("--remote", is_flag=True, help="Configure for a remote OpenClaw gateway (requires auth token)")
@click.option("--host", default=None, help="Gateway host")
@click.option("--port", type=int, default=None, help="Gateway WebSocket port")
@click.option("--api-port", type=int, default=None, help="Sidecar REST API port")
@click.option("--token", default=None, help="Gateway auth token")
@click.option("--ssm-param", default=None, help="AWS SSM parameter name for token")
@click.option("--ssm-region", default=None, help="AWS region for SSM")
@click.option("--ssm-profile", default=None, help="AWS CLI profile for SSM")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_gateway(
    app: AppContext,
    remote: bool,
    host, port, api_port, token,
    ssm_param, ssm_region, ssm_profile,
    verify: bool,
    non_interactive: bool,
) -> None:
    """Configure gateway connection for the DefenseClaw sidecar.

    By default configures for a local OpenClaw instance (auth token from
    ~/.defenseclaw/.env when OpenClaw requires it).
    Use --remote to configure for a remote gateway that requires an auth token,
    optionally fetched from AWS SSM Parameter Store.
    """
    gw = app.cfg.gateway

    data_dir = app.cfg.data_dir

    if non_interactive:
        if host is not None:
            gw.host = host
        if port is not None:
            gw.port = port
        if api_port is not None:
            gw.api_port = api_port
        if token is not None:
            _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", token, data_dir)
            gw.token = ""
            gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
        elif ssm_param:
            fetched = _fetch_ssm_token(ssm_param, ssm_region or "us-east-1", ssm_profile)
            if fetched:
                _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", fetched, data_dir)
                gw.token = ""
                gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
            else:
                click.echo("error: failed to fetch token from SSM", err=True)
                raise SystemExit(1)
        elif not gw.resolved_token():
            detected = _detect_openclaw_gateway_token(app.cfg.claw.config_file)
            if detected:
                _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected, data_dir)
                gw.token = ""
                gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
    elif remote:
        _interactive_gateway_remote(gw, data_dir)
    else:
        _interactive_gateway_local(gw, app.cfg.claw.config_file, data_dir)

    app.cfg.save()
    _print_gateway_summary(gw)

    if verify:
        from defenseclaw.commands.cmd_doctor import _check_openclaw_gateway, _check_sidecar, _DoctorResult
        click.echo("  ── Verifying gateway connectivity ──")
        r = _DoctorResult()
        _check_openclaw_gateway(app.cfg, r)
        _check_sidecar(app.cfg, r)
        click.echo()
        if r.failed:
            click.echo("  Tip: fix the issues above, then run 'defenseclaw doctor' to re-check.")
            click.echo()

    if app.logger:
        mode = "remote" if (remote or gw.resolved_token()) else "local"
        app.logger.log_action("setup-gateway", "config", f"mode={mode} host={gw.host} port={gw.port}")


def _interactive_gateway_local(gw, openclaw_config_file: str, data_dir: str) -> None:
    click.echo()
    click.echo("  Gateway Configuration (local)")
    click.echo("  ─────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)
    gw.token = ""
    detected = _detect_openclaw_gateway_token(openclaw_config_file)
    if detected:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected, data_dir)
        click.echo(f"  OpenClaw token saved to ~/.defenseclaw/.env ({_mask(detected)})")
    gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
    click.echo()
    click.echo("  Auth: token is read from OPENCLAW_GATEWAY_TOKEN in ~/.defenseclaw/.env when set.")
    click.echo("  OpenClaw may require this even for 127.0.0.1.")


def _interactive_gateway_remote(gw, data_dir: str) -> None:
    click.echo()
    click.echo("  Gateway Configuration (remote)")
    click.echo("  ──────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)

    click.echo()
    use_ssm = click.confirm("  Fetch token from AWS SSM Parameter Store?", default=True)

    token_value: str = ""
    if use_ssm:
        param = click.prompt(
            "  SSM parameter name",
            default="/openclaw/openclaw-bedrock/gateway-token",
        )
        region = click.prompt("  AWS region", default="us-east-1")
        profile = click.prompt("  AWS CLI profile", default="devops")

        click.echo("  Fetching token from SSM...", nl=False)
        fetched = _fetch_ssm_token(param, region, profile)
        if fetched:
            token_value = fetched
            click.echo(f" ok ({_mask(fetched)})")
        else:
            click.echo(" failed")
            click.echo("  Falling back to manual entry.")
            _prompt_and_save_secret("OPENCLAW_GATEWAY_TOKEN", gw.token, data_dir)
            gw.token = ""
            gw.token_env = "OPENCLAW_GATEWAY_TOKEN"
            return
    else:
        _prompt_and_save_secret("OPENCLAW_GATEWAY_TOKEN", gw.token, data_dir)

    if token_value:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", token_value, data_dir)

    gw.token = ""
    gw.token_env = "OPENCLAW_GATEWAY_TOKEN"

    if not gw.resolved_token():
        click.echo("  warning: no token set — sidecar will fail to connect to a remote gateway", err=True)


def _detect_openclaw_gateway_token(openclaw_config_file: str) -> str:
    """Read the gateway auth token from openclaw.json (gateway.auth.token)."""
    from pathlib import Path

    path = openclaw_config_file
    if path.startswith("~/"):
        path = str(Path.home() / path[2:])
    try:
        with open(path) as f:
            cfg = _json.load(f)
        return cfg.get("gateway", {}).get("auth", {}).get("token", "")
    except (OSError, ValueError, KeyError):
        return ""


def _fetch_ssm_token(param: str, region: str, profile: str | None) -> str | None:
    cmd = [
        "aws", "ssm", "get-parameter",
        "--name", param,
        "--with-decryption",
        "--query", "Parameter.Value",
        "--output", "text",
        "--region", region,
    ]
    if profile:
        cmd.extend(["--profile", profile])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ---------------------------------------------------------------------------
# setup guardrail
# ---------------------------------------------------------------------------

@setup.command("guardrail")
@click.option("--disable", is_flag=True, help="Disable guardrail and revert OpenClaw config")
@click.option("--mode", "guard_mode", type=click.Choice(["observe", "action"]), default=None,
              help="Guardrail mode")
@click.option("--scanner-mode", type=click.Choice(["local", "remote"]), default=None,
              help="Scanner mode (local patterns or remote Cisco API)")
@click.option("--cisco-endpoint", default=None, help="Cisco AI Defense API endpoint")
@click.option("--cisco-api-key-env", default=None, help="Env var name holding Cisco AI Defense API key")
@click.option("--cisco-timeout-ms", type=int, default=None, help="Cisco AI Defense timeout (ms)")
@click.option("--port", "guard_port", type=int, default=None, help="Guardrail proxy port")
@click.option("--block-message", default=None,
              help="Custom message shown when a request is blocked (empty = default)")
@click.option("--restart", is_flag=True, help="Restart defenseclaw-gateway and openclaw gateway after setup")
@click.option("--verify/--no-verify", default=True, help="Run connectivity checks after setup (default: on)")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_guardrail(
    app: AppContext,
    disable: bool,
    guard_mode, guard_port,
    scanner_mode, cisco_endpoint, cisco_api_key_env, cisco_timeout_ms,
    block_message,
    restart: bool,
    verify: bool,
    non_interactive: bool,
) -> None:
    """Configure the LLM guardrail (routes LLM traffic through the Go proxy for inspection).

    Routes all LLM traffic through the built-in Go guardrail proxy.
    Every prompt and response is inspected for prompt injection, secrets,
    PII, and data exfiltration patterns.

    Two modes:
      observe — log findings, never block (default, recommended to start)
      action  — block prompts/responses that match security policies

    Use --disable to turn off the guardrail and restore direct LLM access.
    """

    gc = app.cfg.guardrail

    if disable:
        _disable_guardrail(app, gc, restart=restart)
        return

    aid = app.cfg.cisco_ai_defense

    if non_interactive:
        if guard_mode is not None:
            gc.mode = guard_mode
        if scanner_mode is not None:
            gc.scanner_mode = scanner_mode
        if cisco_endpoint is not None:
            aid.endpoint = cisco_endpoint
        if cisco_api_key_env is not None:
            aid.api_key_env = cisco_api_key_env
        if cisco_timeout_ms is not None:
            aid.timeout_ms = cisco_timeout_ms
        if guard_port is not None:
            gc.port = guard_port
        if block_message is not None:
            gc.block_message = block_message
        gc.enabled = True
    else:
        _interactive_guardrail_setup(app, gc)

    if not gc.enabled:
        click.echo("  Guardrail not enabled. Run again without declining to configure.")
        return

    ok, warnings = execute_guardrail_setup(app, save_config=True)
    if not ok:
        return

    aid = app.cfg.cisco_ai_defense

    # --- Summary ---
    click.echo()
    rows = [
        ("guardrail.mode", gc.mode),
        ("guardrail.port", str(gc.port)),
        ("guardrail.model", gc.model),
        ("guardrail.model_name", gc.model_name),
        ("guardrail.api_key_env", gc.api_key_env),
    ]
    if gc.block_message:
        truncated = gc.block_message[:60] + "..." if len(gc.block_message) > 60 else gc.block_message
        rows.append(("guardrail.block_message", truncated))
    if gc.scanner_mode in ("remote", "both"):
        rows.append(("cisco_ai_defense.endpoint", aid.endpoint))
        rows.append(("cisco_ai_defense.api_key_env", aid.api_key_env))
        rows.append(("cisco_ai_defense.timeout_ms", str(aid.timeout_ms)))
    for key, val in rows:
        click.echo(f"    {key + ':':<30s} {val}")
    click.echo()

    if warnings:
        click.echo("  ── Warnings ──────────────────────────────────────────")
        for w in warnings:
            click.echo(f"  ⚠ {w}")
        click.echo()

    if restart:
        _restart_services(app.cfg.data_dir, app.cfg.gateway.host, app.cfg.gateway.port)
    else:
        click.echo("  Next steps:")
        click.echo("    1. Restart the defenseclaw sidecar:")
        click.echo("       defenseclaw-gateway restart")
        click.echo("       (openclaw gateway auto-reloads — no restart needed)")
        click.echo("    2. Or re-run with --restart:")
        click.echo("       defenseclaw setup guardrail --restart")
        click.echo()

    click.echo("  To disable and revert:")
    click.echo("    defenseclaw setup guardrail --disable")
    click.echo()

    if app.logger:
        app.logger.log_action(
            "setup-guardrail", "config",
            f"mode={gc.mode} scanner_mode={gc.scanner_mode} port={gc.port} model={gc.model}",
        )


def execute_guardrail_setup(
    app: AppContext,
    *,
    save_config: bool = True,
) -> tuple[bool, list[str]]:
    """Run guardrail setup steps 0–7.

    Returns (success, warnings).  When *save_config* is False the caller
    is responsible for calling ``app.cfg.save()`` (used by ``init`` which
    saves once at the end).
    """
    from defenseclaw.guardrail import (
        _derive_master_key,
        install_openclaw_plugin,
        patch_openclaw_config,
    )

    gc = app.cfg.guardrail
    warnings: list[str] = []

    # --- Pre-flight checks ---
    claw_cfg_file = app.cfg.claw.config_file
    oc_config_path = (
        os.path.expanduser(claw_cfg_file) if claw_cfg_file.startswith("~/") else claw_cfg_file
    )
    if not os.path.isfile(oc_config_path):
        click.echo(f"  ✗ OpenClaw config not found: {app.cfg.claw.config_file}")
        click.echo("    Make sure OpenClaw is installed and initialized.")
        click.echo("    Expected location: ~/.openclaw/openclaw.json")
        return False, warnings

    if not gc.model or not gc.model_name:
        click.echo("  ✗ Model or model_name is empty — cannot configure guardrail.")
        click.echo("    Run interactively (without --non-interactive) to set the model.")
        return False, warnings

    if "/" not in gc.model:
        click.echo(f"  ⚠ Model '{gc.model}' has no provider prefix (e.g. anthropic/{gc.model}).")
        click.echo("    The proxy will attempt to infer the provider from the model name,")
        click.echo("    but this may route to the wrong API. Run interactively to set it explicitly.")
        warnings.append(
            f"Model '{gc.model}' has no provider prefix — provider will be inferred at runtime. "
            "Run 'defenseclaw setup guardrail' interactively to fix."
        )

    click.echo()

    click.echo("  ✓ Guardrail proxy is built into the Go binary (no Python deps)")

    # --- Step 1: Install OpenClaw plugin ---
    plugin_source = _find_plugin_source()
    if plugin_source:
        openclaw_home = app.cfg.claw.home_dir
        method, cli_error = install_openclaw_plugin(plugin_source, openclaw_home)
        if method == "cli":
            click.echo("  ✓ OpenClaw plugin installed (via openclaw CLI)")
        elif method == "manual":
            click.echo("  ✓ OpenClaw plugin installed to extensions/")
        elif method == "error":
            click.echo(f"  ✗ OpenClaw plugin installation failed: {cli_error}")
            warnings.append(
                "Plugin not installed — tool interception will not work. "
                "Try: make plugin-install && defenseclaw setup guardrail"
            )
        else:
            click.echo("  ⚠ OpenClaw plugin not built — run 'make plugin && make plugin-install'")
            warnings.append(
                "Plugin not built — tool interception will not work. "
                "Build with: make plugin && make plugin-install"
            )
    else:
        click.echo("  ⚠ OpenClaw plugin not found at ~/.defenseclaw/extensions/")
        warnings.append(
            "Plugin not found — run 'make plugin-install' to stage it, "
            "then re-run setup"
        )

    # --- Step 2: Patch OpenClaw config ---
    master_key = _derive_master_key(app.cfg.gateway.device_key_file)

    prev_model = patch_openclaw_config(
        openclaw_config_file=app.cfg.claw.config_file,
        model_name=gc.model_name,
        proxy_port=gc.port,
        master_key=master_key,
        original_model=gc.original_model,
        litellm_host=gc.host or "localhost",
    )
    if prev_model is not None:
        click.echo(f"  ✓ OpenClaw config patched: {app.cfg.claw.config_file}")
        if prev_model and not gc.original_model:
            gc.original_model = prev_model
    else:
        click.echo(f"  ✗ Failed to patch OpenClaw config: {app.cfg.claw.config_file}")
        click.echo("    File may be malformed or unreadable. Check the JSON syntax.")
        warnings.append(
            "OpenClaw config not patched — LLM traffic will not be routed through the guardrail. "
            f"Fix {app.cfg.claw.config_file} and re-run setup"
        )

    # --- Step 3: Save DefenseClaw config ---
    if save_config:
        try:
            app.cfg.save()
            click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
        except OSError as exc:
            click.echo(f"  ✗ Failed to save config: {exc}")
            warnings.append("Config not saved — settings will be lost on next run")

    if gc.original_model:
        click.echo(f"  ✓ Original model saved for revert: {gc.original_model}")

    # --- Step 4: Write .env file for API keys ---
    if gc.api_key_env:
        env_val = os.environ.get(gc.api_key_env, "")
        dotenv_path = os.path.join(app.cfg.data_dir, ".env")
        existing_dotenv = _load_dotenv(dotenv_path)

        if not env_val and gc.api_key_env not in existing_dotenv:
            click.echo()
            click.echo(f"  ⚠ {gc.api_key_env} is not set in your current environment")
            env_val = click.prompt(
                f"  Enter the value for {gc.api_key_env}",
                hide_input=True,
                default="",
            )
            if not env_val:
                click.echo("    Skipped — the guardrail proxy will fail without this key.")
                click.echo(f"    You can set it later in {dotenv_path}")
                warnings.append(f"{gc.api_key_env} not set — sidecar will fail to start")

        if env_val:
            existing_dotenv[gc.api_key_env] = env_val

        if existing_dotenv:
            _write_dotenv(dotenv_path, existing_dotenv)
            click.echo(f"  ✓ API keys written to {dotenv_path} (mode 0600)")

    # --- Step 5: Write guardrail_runtime.json ---
    _write_guardrail_runtime(app.cfg.data_dir, gc)

    # --- Step 8: Restore sandbox ownership if in standalone mode ---
    if app.cfg.openshell.is_standalone():
        sandbox_home = app.cfg.openshell.effective_sandbox_home()
        oc_target = os.path.join(sandbox_home, ".openclaw")
        if os.path.islink(oc_target):
            oc_target = os.readlink(oc_target)
        try:
            subprocess.run(
                ["chown", "-R", "sandbox:sandbox", oc_target],
                capture_output=True, check=False,
            )
        except FileNotFoundError:
            pass

    return True, warnings


def _interactive_guardrail_setup(app: AppContext, gc) -> None:
    from defenseclaw.guardrail import (
        KNOWN_PROVIDERS,
        detect_api_key_env,
        detect_current_model,
        guess_provider,
        model_to_proxy_name,
    )

    click.echo()
    click.echo("  LLM Guardrail Configuration")
    click.echo("  ────────────────────────────")
    click.echo()
    click.echo("  Routes all LLM traffic through a local inspection proxy.")
    click.echo("  Every prompt and response is scanned for security issues.")
    click.echo()

    if not click.confirm("  Enable LLM guardrail?", default=True):
        gc.enabled = False
        return

    gc.enabled = True

    click.echo()
    click.echo("  Modes:")
    click.echo("    observe — log and alert only, never block (recommended to start)")
    click.echo("    action  — block prompts/responses that match security policies")
    gc.mode = click.prompt(
        "  Mode", type=click.Choice(["observe", "action"]), default=gc.mode or "observe",
    )

    if gc.mode == "action":
        click.echo()
        click.echo("  When mode is 'action', blocked requests show a message to the user.")
        if gc.block_message:
            preview = gc.block_message[:80] + ("..." if len(gc.block_message) > 80 else "")
            click.echo(f"  Current: \"{preview}\"")
        else:
            click.echo("  Default: \"I'm unable to process this request. DefenseClaw detected...\"")
        if click.confirm("  Use a custom block message?", default=bool(gc.block_message)):
            gc.block_message = click.prompt("  Block message", default=gc.block_message or "")
        else:
            gc.block_message = ""

    click.echo()
    click.echo("  Scanner modes:")
    click.echo("    local  — pattern matching only, no network calls (fastest)")
    click.echo("    remote — Cisco AI Defense cloud API only")
    sm_default = gc.scanner_mode or "local"
    if sm_default == "both":
        sm_default = "local"
    gc.scanner_mode = click.prompt(
        "  Scanner mode", type=click.Choice(["local", "remote"]),
        default=sm_default,
    )

    if gc.scanner_mode in ("remote", "both"):
        click.echo()
        click.echo("  Cisco AI Defense Configuration")
        click.echo("  ──────────────────────────────")
        aid = app.cfg.cisco_ai_defense
        aid.endpoint = click.prompt(
            "  API endpoint", default=aid.endpoint,
        )
        cisco_key_env = aid.api_key_env or "CISCO_AI_DEFENSE_API_KEY"
        env_val = os.environ.get(cisco_key_env, "")
        if env_val:
            click.echo(f"  API key env var: {cisco_key_env} ({_mask(env_val)})")
        else:
            click.echo(f"  API key env var: {cisco_key_env} (not set)")
            click.echo(f"    Set it before starting: export {cisco_key_env}=your-key")
        aid.api_key_env = click.prompt(
            "  API key env var name", default=cisco_key_env,
        )
        aid.timeout_ms = click.prompt(
            "  Timeout (ms)", default=aid.timeout_ms, type=int,
        )

    gc.port = click.prompt("  Guardrail proxy port", default=gc.port or 4000, type=int)

    # Detect current model
    current_model, current_provider = detect_current_model(app.cfg.claw.config_file)
    click.echo()

    # If model has no provider/ prefix, ask the user to confirm the provider.
    if current_model and not current_provider and "/" not in current_model:
        guessed = guess_provider(current_model)
        click.echo(f"  Current OpenClaw model: {current_model}")
        click.echo(f"  No provider prefix detected (e.g. anthropic/{current_model}).")
        provider_choices = click.Choice(KNOWN_PROVIDERS)
        chosen = click.prompt(
            "  Which provider hosts this model?",
            type=provider_choices,
            default=guessed if guessed else None,
        )
        current_model = f"{chosen}/{current_model}"
        current_provider = chosen
        click.echo(f"  Using: {current_model}")
        click.echo()

    routed_prefixes = ("defenseclaw/",)
    is_already_routed = current_model and any(current_model.startswith(p) for p in routed_prefixes)

    if current_model and not is_already_routed:
        click.echo(f"  Current OpenClaw model: {current_model}")
        if click.confirm("  Route this model through the guardrail?", default=True):
            gc.model = current_model
            gc.model_name = model_to_proxy_name(current_model)
            gc.original_model = current_model
        else:
            gc.model = click.prompt("  Upstream model (e.g. anthropic/claude-sonnet-4-20250514)")
            gc.model_name = model_to_proxy_name(gc.model)
    elif is_already_routed:
        click.echo(f"  Already routed through guardrail: {current_model}")
        if gc.model:
            click.echo(f"  Upstream model: {gc.model}")
        else:
            click.echo("  Upstream model not configured — need to set it.")
            gc.model = click.prompt("  Upstream model (e.g. anthropic/claude-sonnet-4-20250514)")
            gc.model_name = model_to_proxy_name(gc.model)
        if not gc.original_model or any(gc.original_model.startswith(p) for p in routed_prefixes):
            gc.original_model = gc.model
    else:
        gc.model = click.prompt("  Upstream model (e.g. anthropic/claude-sonnet-4-20250514)")
        gc.model_name = model_to_proxy_name(gc.model)

    if not gc.model_name:
        gc.model_name = model_to_proxy_name(gc.model)

    if not gc.model or not gc.model_name:
        click.echo("  Error: model and model_name must not be empty.")
        gc.enabled = False
        return

    # API key env var
    if not gc.api_key_env or _looks_like_secret(gc.api_key_env):
        gc.api_key_env = detect_api_key_env(gc.model)

    env_val = os.environ.get(gc.api_key_env, "")
    dotenv_path = os.path.join(app.cfg.data_dir, ".env")
    existing_dotenv = _load_dotenv(dotenv_path)
    dotenv_val = existing_dotenv.get(gc.api_key_env, "")
    click.echo()
    if env_val:
        click.echo(f"  API key env var: {gc.api_key_env} ({_mask(env_val)})")
        if not click.confirm("  Use this env var?", default=True):
            gc.api_key_env = _prompt_env_var_name(gc.api_key_env)
    elif dotenv_val:
        click.echo(f"  API key: {gc.api_key_env} ({_mask(dotenv_val)}) — from {dotenv_path}")
        if not click.confirm("  Use this key?", default=True):
            gc.api_key_env = _prompt_env_var_name(gc.api_key_env)
    else:
        click.echo(f"  API key env var: {gc.api_key_env} (not set in environment or .env)")
        click.echo("  The key will be saved to ~/.defenseclaw/.env during setup.")
        gc.api_key_env = _prompt_env_var_name(gc.api_key_env)


def _disable_guardrail(app: AppContext, gc, *, restart: bool = False) -> None:
    from defenseclaw.guardrail import restore_openclaw_config, uninstall_openclaw_plugin

    click.echo()
    click.echo("  Disabling LLM guardrail...")
    warnings: list[str] = []

    # Restore OpenClaw config (model + remove defenseclaw provider + plugins.allow)
    if gc.original_model:
        if restore_openclaw_config(app.cfg.claw.config_file, gc.original_model):
            click.echo(f"  ✓ OpenClaw model restored to: {gc.original_model}")
        else:
            click.echo(f"  ✗ Could not restore OpenClaw config: {app.cfg.claw.config_file}")
            click.echo("    The file may be missing or contain invalid JSON.")
            warnings.append(
                f"Manually edit {app.cfg.claw.config_file}: "
                f"set agents.defaults.model.primary to \"{gc.original_model}\" "
                "and remove the \"defenseclaw\" provider from models.providers"
            )
    else:
        click.echo("  ⚠ No original model on record — cannot revert LLM routing")
        click.echo("    The model in openclaw.json may still point to defenseclaw/...")
        warnings.append(
            f"Check {app.cfg.claw.config_file} and set agents.defaults.model.primary "
            "to your desired model (e.g. anthropic/claude-sonnet-4-20250514)"
        )

    # Uninstall OpenClaw plugin
    openclaw_home = app.cfg.claw.home_dir
    result = uninstall_openclaw_plugin(openclaw_home)
    if result == "cli":
        click.echo("  ✓ OpenClaw plugin uninstalled (via openclaw CLI)")
    elif result == "manual":
        click.echo("  ✓ OpenClaw plugin removed from extensions/")
    elif result == "error":
        ext_dir = os.path.join(os.path.expanduser(openclaw_home), "extensions", "defenseclaw")
        click.echo(f"  ✗ Could not remove OpenClaw plugin at {ext_dir}")
        warnings.append(f"Manually delete: rm -rf {ext_dir}")
    else:
        click.echo("  ✓ OpenClaw plugin not installed (nothing to remove)")

    gc.enabled = False
    try:
        app.cfg.save()
        click.echo("  ✓ Config saved")
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}")
        warnings.append("Config not saved — guardrail may re-enable on next run")

    if warnings:
        click.echo()
        click.echo("  ── Manual steps required ─────────────────────────────")
        for w in warnings:
            click.echo(f"  ⚠ {w}")

    if restart:
        click.echo()
        _restart_services(app.cfg.data_dir, app.cfg.gateway.host, app.cfg.gateway.port)
    else:
        click.echo()
        click.echo("  Restart the defenseclaw sidecar for changes to take effect:")
        click.echo("    defenseclaw-gateway restart")
        click.echo("    (openclaw gateway auto-reloads — no restart needed)")
        click.echo()
        click.echo("  Or re-run with --restart:")
        click.echo("    defenseclaw setup guardrail --disable --restart")
    click.echo()

    if app.logger:
        app.logger.log_action("setup-guardrail", "config", "disabled")


def _write_guardrail_runtime(data_dir: str, gc) -> None:
    """Write guardrail_runtime.json so the Python guardrail module can hot-reload settings."""
    import json

    runtime_file = os.path.join(data_dir, "guardrail_runtime.json")
    payload = {
        "mode": gc.mode,
        "scanner_mode": gc.scanner_mode,
        "block_message": gc.block_message,
    }
    try:
        os.makedirs(data_dir, exist_ok=True)
        with open(runtime_file, "w") as f:
            json.dump(payload, f)
        click.echo(f"  ✓ Guardrail runtime config written to {runtime_file}")
    except OSError as exc:
        click.echo(f"  ⚠ Failed to write runtime config: {exc}")


def _print_guardrail_summary(gc, openclaw_config_file: str, *, restart: bool = False) -> None:
    click.echo()
    click.echo("  ✓ Config saved to ~/.defenseclaw/config.yaml")
    click.echo("  ✓ Guardrail proxy configured (built into Go binary)")
    click.echo(f"  ✓ OpenClaw config patched: {openclaw_config_file}")
    if gc.original_model:
        click.echo(f"  ✓ Original model saved for revert: {gc.original_model}")
    click.echo()

    rows = [
        ("mode", gc.mode),
        ("scanner_mode", gc.scanner_mode),
        ("port", str(gc.port)),
        ("model", gc.model),
        ("model_name", gc.model_name),
        ("api_key_env", gc.api_key_env),
    ]
    for key, val in rows:
        click.echo(f"    guardrail.{key + ':':<16s} {val}")
    click.echo()


def _find_plugin_source() -> str | None:
    """Locate the built OpenClaw plugin.

    Checks ~/.defenseclaw/extensions/defenseclaw first (production install),
    then the repo source tree (dev).
    """
    d = bundled_extensions_dir()
    resolved = str(d.resolve())
    if os.path.isdir(resolved) and os.path.isfile(os.path.join(resolved, "package.json")):
        return resolved
    return None


# ---------------------------------------------------------------------------
# Service restart helpers
# ---------------------------------------------------------------------------

def _is_pid_alive(pid_file: str) -> bool:
    """Check if the process in the given PID file is alive (signal 0)."""
    try:
        with open(pid_file) as f:
            raw = f.read().strip()
        try:
            pid = int(raw)
        except ValueError:
            import json as _json
            pid = _json.loads(raw)["pid"]
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, KeyError, ProcessLookupError, PermissionError, OSError):
        return False


def _restart_services(data_dir: str, oc_host: str = "127.0.0.1", oc_port: int = 18789) -> None:
    """Restart defenseclaw-gateway and verify openclaw gateway health."""
    click.echo("  Restarting services...")
    click.echo("  ──────────────────────")

    _restart_defense_gateway(data_dir)
    _check_openclaw_gateway(oc_host, oc_port)

    click.echo()


def _restart_defense_gateway(data_dir: str) -> None:
    pid_file = os.path.join(data_dir, "gateway.pid")
    was_running = _is_pid_alive(pid_file)

    action = "restarting" if was_running else "starting"
    click.echo(f"  defenseclaw-gateway: {action}...", nl=False)

    cmd = ["defenseclaw-gateway", "restart"] if was_running else ["defenseclaw-gateway", "start"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            click.echo(" ✓")
        else:
            click.echo(" ✗")
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"    {line}")
    except FileNotFoundError:
        click.echo(" ✗ (binary not found)")
        click.echo("    Build with: make gateway")
    except subprocess.TimeoutExpired:
        click.echo(" ✗ (timed out)")


def _openclaw_gateway_healthy(host: str, port: int, timeout: float = 5.0) -> bool:
    """Probe the OpenClaw gateway HTTP health endpoint."""
    import urllib.error
    import urllib.request

    url = f"http://{host}:{port}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _check_openclaw_gateway(host: str = "127.0.0.1", port: int = 18789) -> None:
    """Verify the OpenClaw gateway remains healthy after a config change.

    OpenClaw watches openclaw.json and auto-restarts on certain changes
    (e.g. plugins.allow).  A full restart cycle takes ~30s, so a quick
    health check can give a false positive — the gateway answers, then
    goes down for the restart.  We therefore:

      1. Wait up to 30s for the gateway to become healthy.
      2. Keep monitoring for another 30s to make sure it *stays* healthy
         through any config-triggered restart.
      3. If it goes unhealthy during that window, wait up to 60s for
         recovery before giving up.
    """
    import time

    initial_wait = 30
    stable_window = 30
    recovery_timeout = 60
    poll_interval = 3

    click.echo("  openclaw gateway: monitoring...", nl=False)

    start = time.monotonic()

    # Phase 1 — wait for initial healthy response
    healthy = False
    while time.monotonic() - start < initial_wait:
        if _openclaw_gateway_healthy(host, port):
            healthy = True
            break
        time.sleep(poll_interval)

    if not healthy:
        click.echo(" not running")
        click.echo("    Gateway did not respond within 30s.")
        click.echo("    Start manually: openclaw gateway")
        return

    # Phase 2 — confirm stability for stable_window seconds
    click.echo(" up", nl=False)
    stable_start = time.monotonic()
    went_unhealthy = False

    while time.monotonic() - stable_start < stable_window:
        time.sleep(poll_interval)
        if not _openclaw_gateway_healthy(host, port):
            went_unhealthy = True
            click.echo(" → restarting...", nl=False)
            break

    if not went_unhealthy:
        elapsed = int(time.monotonic() - start)
        click.echo(f" ✓ (healthy, stable for {elapsed}s)")
        return

    # Phase 3 — gateway went unhealthy (config-triggered restart);
    #           wait up to recovery_timeout for it to come back
    recovery_start = time.monotonic()
    recovered = False
    while time.monotonic() - recovery_start < recovery_timeout:
        if _openclaw_gateway_healthy(host, port):
            recovered = True
            break
        time.sleep(poll_interval)

    if recovered:
        elapsed = int(time.monotonic() - start)
        click.echo(f" ✓ (recovered after restart, {elapsed}s)")
    else:
        elapsed = int(time.monotonic() - start)
        click.echo(f" ✗ (unhealthy after {elapsed}s)")
        click.echo("    Gateway did not recover after config-triggered restart.")
        click.echo("    Check: openclaw gateway status")
        click.echo("    Logs: ~/.openclaw/logs/gateway.err.log")


def _looks_like_secret(value: str) -> bool:
    """Detect if a value looks like an actual secret rather than an env var name."""
    if not value:
        return False
    prefixes = ("sk-", "sk-ant-", "sk-proj-", "ghp_", "gho_", "xoxb-", "xoxp-")
    if any(value.startswith(p) for p in prefixes):
        return True
    if len(value) > 30 and not value.isupper():
        return True
    return False


def _prompt_env_var_name(default: str) -> str:
    """Prompt for an env var name, rejecting values that look like actual secrets."""
    while True:
        val = click.prompt("  Env var name (e.g. ANTHROPIC_API_KEY)", default=default)
        if _looks_like_secret(val):
            click.echo("  That looks like an actual API key, not an env var name.")
            click.echo("  Enter the NAME of the environment variable (e.g. ANTHROPIC_API_KEY).")
            continue
        return val


def _print_gateway_summary(gw) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    resolved = gw.resolved_token()
    rows = [
        ("host", gw.host),
        ("port", str(gw.port)),
        ("api_port", str(gw.api_port)),
        ("token", f"via {gw.token_env} (in .env)" if resolved else "(none — local mode)"),
    ]

    for key, val in rows:
        click.echo(f"    gateway.{key + ':':<12s} {val}")
    click.echo()

    if resolved:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
    else:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
        click.echo("  (local mode — ensure OpenClaw is running on this machine)")
    click.echo()


# ---------------------------------------------------------------------------
# setup splunk
# ---------------------------------------------------------------------------

_SPLUNK_O11Y_INGEST_TEMPLATE = "ingest.{realm}.observability.splunkcloud.com"
_SPLUNK_GENERAL_TERMS_URL = "https://www.splunk.com/en_us/legal/splunk-general-terms.html"

_SPLUNK_LOCAL_HEC_DEFAULTS = {
    "hec_endpoint": "http://127.0.0.1:8088/services/collector/event",
    "index": "defenseclaw_local",
    "source": "defenseclaw",
    "sourcetype": "defenseclaw:json",
}


@setup.command("splunk")
@click.option("--o11y", "enable_o11y", is_flag=True, default=False,
              help="Enable Splunk Observability Cloud (OTLP traces + metrics)")
@click.option("--logs", "enable_logs", is_flag=True, default=False,
              help="Enable local Splunk Enterprise via Docker (HEC logs + dashboards)")
@click.option("--realm", default=None, help="Splunk O11y realm (e.g. us1, us0, eu0)")
@click.option("--access-token", default=None, help="Splunk O11y access token")
@click.option("--app-name", default=None, help="OTEL service name (default: defenseclaw)")
@click.option("--disable", is_flag=True, help="Disable Splunk integration(s)")
@click.option("--accept-splunk-license", is_flag=True,
              help="Acknowledge the Splunk General Terms for local Splunk enablement")
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_splunk(
    app: AppContext,
    enable_o11y: bool,
    enable_logs: bool,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
    disable: bool,
    accept_splunk_license: bool,
    non_interactive: bool,
) -> None:
    """Configure Splunk integration for DefenseClaw.

    Two independent pipelines are available:

    \b
      --o11y   Splunk Observability Cloud (traces + metrics via OTLP HTTP)
               No local infrastructure needed. Requires a Splunk access token.
    \b
      --logs   Local Splunk Enterprise (Docker, HEC logs + dashboards)
               Spins up a local Splunk container. Requires Docker.

    Both can run simultaneously. Without flags, runs an interactive wizard.
    """
    if disable:
        _disable_splunk(app, enable_o11y, enable_logs, non_interactive)
        return

    if not enable_o11y and not enable_logs and not non_interactive:
        _interactive_splunk_setup(app, realm, access_token, app_name)
        return

    if not enable_o11y and not enable_logs and non_interactive:
        click.echo("  error: specify --o11y, --logs, or both with --non-interactive", err=True)
        raise SystemExit(1)

    did_o11y = False
    did_logs = False

    if enable_o11y:
        _setup_o11y(app, realm or "us1", access_token, app_name or "defenseclaw",
                    non_interactive=non_interactive)
        did_o11y = True

    if enable_logs:
        did_logs = _setup_logs(
            app,
            non_interactive=non_interactive,
            accept_splunk_license=accept_splunk_license,
        )

    if not did_o11y and not did_logs:
        return

    app.cfg.save()
    click.echo("  Config saved to ~/.defenseclaw/config.yaml")
    click.echo()
    _print_splunk_status(app)
    _print_splunk_next_steps(did_o11y, did_logs)

    if app.logger:
        parts: list[str] = []
        if did_o11y:
            parts.append("o11y=enabled")
        if did_logs:
            parts.append("logs=enabled")
        app.logger.log_action("setup-splunk", "config", " ".join(parts))


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def _interactive_splunk_setup(
    app: AppContext,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
) -> None:
    click.echo()
    click.echo("  Splunk Integration Setup")
    click.echo("  ────────────────────────")
    click.echo()
    click.echo("  DefenseClaw supports two Splunk pipelines. You can enable one or both.")
    click.echo()
    click.echo("  1. Splunk Observability Cloud (O11y)")
    click.echo("     Sends traces + metrics + logs via OTLP HTTP directly to Splunk cloud.")
    click.echo("     No local infrastructure needed. Requires a Splunk O11y access token.")
    click.echo()
    click.echo("  2. Local Splunk Enterprise (Logs)")
    click.echo("     Spins up a local Splunk container via Docker. Audit events are sent")
    click.echo("     via HEC. Includes pre-built dashboards for DefenseClaw.")
    click.echo("     Requires Docker.")
    click.echo()

    did_o11y = False
    did_logs = False

    if click.confirm("  Enable Splunk Observability Cloud (traces + metrics)?", default=False):
        _interactive_o11y(app, realm, access_token, app_name)
        did_o11y = True
        click.echo()

    if click.confirm("  Enable local Splunk Enterprise (Docker, HEC logs)?", default=False):
        did_logs = _interactive_logs(app)

    if not did_o11y and not did_logs:
        click.echo()
        click.echo("  No Splunk pipelines enabled. Run again to configure.")
        return

    app.cfg.save()
    click.echo()
    click.echo("  Config saved to ~/.defenseclaw/config.yaml")
    click.echo()
    _print_splunk_status(app)
    _print_splunk_next_steps(did_o11y, did_logs)

    if app.logger:
        parts = []
        if did_o11y:
            parts.append("o11y=enabled")
        if did_logs:
            parts.append("logs=enabled")
        app.logger.log_action("setup-splunk", "config", " ".join(parts))


def _interactive_o11y(
    app: AppContext,
    realm: str | None,
    access_token: str | None,
    app_name: str | None,
) -> None:
    click.echo()
    click.echo("  Splunk Observability Cloud")
    click.echo("  ──────────────────────────")
    click.echo()

    realm = click.prompt("  Realm (e.g. us1, us0, eu0)", default=realm or "us1")
    access_token = _prompt_splunk_token(access_token)
    app_name = click.prompt("  Service name", default=app_name or "defenseclaw")

    click.echo()
    click.echo("  Signals to export:")
    enable_traces = click.confirm("    Enable traces?", default=True)
    enable_metrics = click.confirm("    Enable metrics?", default=True)
    enable_logs = click.confirm("    Enable logs (to Log Observer)?", default=False)

    _apply_o11y_config(
        app, realm, access_token, app_name,
        enable_traces=enable_traces,
        enable_metrics=enable_metrics,
        enable_logs=enable_logs,
    )


def _prompt_splunk_token(current: str | None) -> str:
    env_val = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
    if current:
        hint = _mask(current)
    elif env_val:
        hint = f"from env: {_mask(env_val)}"
    else:
        hint = "(not set)"

    val = click.prompt(f"  Access token [{hint}]", default="", show_default=False, hide_input=True)
    if val:
        return val
    return current or env_val


def _interactive_logs(app: AppContext) -> bool:
    click.echo()
    click.echo("  Local Splunk Enterprise")
    click.echo("  ───────────────────────")
    click.echo()

    if not _accept_splunk_license_interactive():
        click.echo("  Local Splunk enablement cancelled.")
        return False

    ok = _preflight_docker()
    if not ok:
        return False

    index = click.prompt("  Index name", default="defenseclaw_local")
    source = click.prompt("  Source", default="defenseclaw")
    sourcetype = click.prompt("  Sourcetype", default="defenseclaw:json")

    _apply_logs_config(app, index=index, source=source, sourcetype=sourcetype,
                       bootstrap_bridge=True)
    return True


# ---------------------------------------------------------------------------
# Non-interactive setup helpers
# ---------------------------------------------------------------------------

def _setup_o11y(
    app: AppContext,
    realm: str,
    access_token: str | None,
    app_name: str,
    *,
    non_interactive: bool,
) -> None:
    token = access_token or os.environ.get("SPLUNK_ACCESS_TOKEN", "")
    if not token and non_interactive:
        click.echo("  error: --access-token required (or set SPLUNK_ACCESS_TOKEN env var)", err=True)
        raise SystemExit(1)
    if not token:
        token = _prompt_splunk_token(None)
    if not token:
        click.echo("  error: access token is required for Splunk O11y", err=True)
        raise SystemExit(1)

    _apply_o11y_config(
        app, realm, token, app_name,
        enable_traces=True,
        enable_metrics=True,
        enable_logs=False,
    )
    click.echo(f"  Splunk O11y configured (realm={realm})")


def _setup_logs(
    app: AppContext,
    *,
    non_interactive: bool,
    accept_splunk_license: bool,
) -> bool:
    if not _ensure_splunk_license_acceptance(
        accept_splunk_license=accept_splunk_license,
        non_interactive=non_interactive,
    ):
        return False

    ok = _preflight_docker()
    if not ok:
        if non_interactive:
            click.echo("  error: Docker is required for --logs", err=True)
            raise SystemExit(1)
        return False

    _apply_logs_config(
        app,
        index="defenseclaw_local",
        source="defenseclaw",
        sourcetype="defenseclaw:json",
        bootstrap_bridge=True,
    )
    click.echo("  Local Splunk Enterprise configured")
    return True


def _print_splunk_license_notice() -> None:
    click.echo("  Local Splunk enablement requires acceptance of the Splunk General Terms:")
    click.echo(f"    {_SPLUNK_GENERAL_TERMS_URL}")
    click.echo("  If you do not agree, do not download, start, access, or use the software.")
    click.echo()


def _accept_splunk_license_interactive() -> bool:
    _print_splunk_license_notice()
    return click.confirm(
        "  Do you accept the Splunk General Terms for this local Splunk workflow?",
        default=False,
    )


def _ensure_splunk_license_acceptance(
    *,
    accept_splunk_license: bool,
    non_interactive: bool,
) -> bool:
    if accept_splunk_license:
        return True

    if non_interactive:
        click.echo("  error: --accept-splunk-license is required with --logs --non-interactive", err=True)
        click.echo(f"         Review the Splunk General Terms: {_SPLUNK_GENERAL_TERMS_URL}", err=True)
        raise SystemExit(1)

    if not _accept_splunk_license_interactive():
        click.echo("  Local Splunk enablement cancelled.")
        return False

    return True


# ---------------------------------------------------------------------------
# Config writers
# ---------------------------------------------------------------------------

def _apply_o11y_config(
    app: AppContext,
    realm: str,
    access_token: str,
    app_name: str,
    *,
    enable_traces: bool,
    enable_metrics: bool,
    enable_logs: bool,
) -> None:
    ingest = _SPLUNK_O11Y_INGEST_TEMPLATE.format(realm=realm)
    otel = app.cfg.otel

    otel.enabled = True
    otel.headers["X-SF-Token"] = "${SPLUNK_ACCESS_TOKEN}"

    otel.traces.enabled = enable_traces
    if enable_traces:
        otel.traces.endpoint = ingest
        otel.traces.protocol = "http"
        otel.traces.url_path = "/v2/trace/otlp"

    otel.metrics.enabled = enable_metrics
    if enable_metrics:
        otel.metrics.endpoint = ingest
        otel.metrics.protocol = "http"
        otel.metrics.url_path = "/v2/datapoint/otlp"

    otel.logs.enabled = enable_logs
    if enable_logs:
        otel.logs.endpoint = ingest
        otel.logs.protocol = "http"
        otel.logs.url_path = "/v1/log/otlp"

    _save_secret_to_dotenv("SPLUNK_ACCESS_TOKEN", access_token, app.cfg.data_dir)
    _save_secret_to_dotenv("OTEL_SERVICE_NAME", app_name, app.cfg.data_dir)


def _apply_logs_config(
    app: AppContext,
    *,
    index: str,
    source: str,
    sourcetype: str,
    bootstrap_bridge: bool,
) -> None:
    contract: dict[str, str] | None = None
    if bootstrap_bridge:
        contract = _bootstrap_bridge(app.cfg.data_dir)
        if not contract:
            raise SystemExit(1)

    sc = app.cfg.splunk
    sc.enabled = True
    sc.hec_endpoint = (contract or {}).get("hec_url", _SPLUNK_LOCAL_HEC_DEFAULTS["hec_endpoint"])
    sc.index = index
    sc.source = source
    sc.sourcetype = sourcetype
    sc.verify_tls = False
    sc.batch_size = 50
    sc.flush_interval_s = 5

    hec_token = (contract or {}).get("hec_token", "")
    if hec_token:
        _save_secret_to_dotenv("DEFENSECLAW_SPLUNK_HEC_TOKEN", hec_token, app.cfg.data_dir)
        sc.hec_token = ""
        sc.hec_token_env = "DEFENSECLAW_SPLUNK_HEC_TOKEN"


# ---------------------------------------------------------------------------
# Bridge bootstrap
# ---------------------------------------------------------------------------

def _resolve_bridge_bin(data_dir: str) -> str | None:
    """Locate the splunk-claw-bridge script. Checks ~/.defenseclaw/splunk-bridge/
    first (seeded by init), then the bundled source."""
    return splunk_bridge_bin(data_dir)


def _bootstrap_bridge(data_dir: str) -> dict[str, str] | None:
    """Start the local Splunk bridge and return the connection contract."""
    bridge = _resolve_bridge_bin(data_dir)
    if not bridge:
        click.echo("  Splunk bridge runtime not found.")
        click.echo("  Run 'defenseclaw init' to seed it, or install from source.")
        return None

    click.echo("  Starting local Splunk (this takes ~2 minutes)...")
    try:
        result = subprocess.run(
            [bridge, "up", "--output", "json"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            click.echo(f"  Bridge startup failed (exit {result.returncode})")
            err = (result.stderr or result.stdout or "").strip()
            for line in err.splitlines()[:5]:
                click.echo(f"    {line}")
            return None

        contract = _json.loads(result.stdout.strip())
        click.echo("  Local Splunk is ready")
        web_url = contract.get("splunk_web_url", "http://127.0.0.1:8000")
        click.echo(f"    Web UI: {web_url}")
        username = contract.get("username", "")
        if username:
            click.echo(f"    Username: {username}")
        return contract
    except subprocess.TimeoutExpired:
        click.echo("  Bridge startup timed out after 5 minutes")
        return None
    except (_json.JSONDecodeError, OSError) as exc:
        click.echo(f"  Bridge startup error: {exc}")
        return None


# ---------------------------------------------------------------------------
# Docker pre-flight
# ---------------------------------------------------------------------------

def _preflight_docker() -> bool:
    """Check Docker is installed and running. Return True if OK."""
    click.echo("  Pre-flight checks:")
    docker = shutil.which("docker")
    if not docker:
        click.echo("    Docker installed... NOT FOUND")
        click.echo("    Install Docker: https://docs.docker.com/get-docker/")
        return False
    click.echo("    Docker installed... ok")

    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            click.echo("    Docker daemon running... NOT RUNNING")
            click.echo("    Start Docker and try again.")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        click.echo("    Docker daemon running... NOT RUNNING")
        return False
    click.echo("    Docker daemon running... ok")

    for port, label in [(8000, "Splunk Web"), (8088, "HEC")]:
        if _port_in_use(port):
            click.echo(f"    Port {port} ({label})... IN USE")
            click.echo(f"    Free port {port} or stop the existing Splunk instance.")
            return False
        click.echo(f"    Port {port} ({label})... available")

    return True


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---------------------------------------------------------------------------
# Disable
# ---------------------------------------------------------------------------

def _disable_splunk(
    app: AppContext,
    o11y_only: bool,
    logs_only: bool,
    non_interactive: bool,
) -> None:
    disable_both = not o11y_only and not logs_only

    click.echo()
    click.echo("  Disabling Splunk integration...")

    if disable_both or o11y_only:
        app.cfg.otel.enabled = False
        click.echo("    Splunk O11y (OTLP): disabled")

    if disable_both or logs_only:
        app.cfg.splunk.enabled = False
        click.echo("    Splunk Enterprise (HEC): disabled")
        _stop_bridge(app.cfg.data_dir)

    app.cfg.save()
    click.echo("  Config saved")
    click.echo()

    if app.logger:
        parts = []
        if disable_both or o11y_only:
            parts.append("o11y=disabled")
        if disable_both or logs_only:
            parts.append("logs=disabled")
        app.logger.log_action("setup-splunk", "config", " ".join(parts))


def _stop_bridge(data_dir: str) -> None:
    bridge = _resolve_bridge_bin(data_dir)
    if not bridge:
        return
    try:
        subprocess.run(
            [bridge, "down"], capture_output=True, text=True, timeout=60,
        )
        click.echo("    Local Splunk container stopped")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        click.echo("    Could not stop local Splunk container (may not be running)")


# ---------------------------------------------------------------------------
# Secret storage
# ---------------------------------------------------------------------------

def _save_secret_to_dotenv(key: str, value: str, data_dir: str) -> None:
    """Write a secret to ~/.defenseclaw/.env (mode 0600).

    Also sets os.environ so that resolver methods (e.g.
    ``resolved_token()``, ``resolved_api_key()``) return the correct
    value within the same process without requiring a restart.
    """
    if not value:
        return
    dotenv_path = os.path.join(data_dir, ".env")
    existing = _load_dotenv(dotenv_path)
    existing[key] = value
    _write_dotenv(dotenv_path, existing)
    os.environ[key] = value


# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------

def _print_splunk_status(app: AppContext) -> None:
    otel = app.cfg.otel
    sc = app.cfg.splunk

    if otel.enabled:
        click.echo("  Splunk Observability (OTLP):")
        click.echo("    Status:      enabled")
        if otel.traces.endpoint:
            realm = otel.traces.endpoint.replace("ingest.", "").replace(".observability.splunkcloud.com", "")
            click.echo(f"    Realm:       {realm}")
        if otel.traces.enabled:
            click.echo(f"    Traces:      {otel.traces.endpoint}{otel.traces.url_path}")
        else:
            click.echo("    Traces:      disabled")
        if otel.metrics.enabled:
            click.echo(f"    Metrics:     {otel.metrics.endpoint}{otel.metrics.url_path}")
        else:
            click.echo("    Metrics:     disabled")
        if otel.logs.enabled:
            click.echo(f"    Logs:        {otel.logs.endpoint}{otel.logs.url_path}")
        else:
            click.echo("    Logs:        disabled")
        dotenv_path = os.path.join(app.cfg.data_dir, ".env")
        dotenv = _load_dotenv(dotenv_path)
        svc = dotenv.get("OTEL_SERVICE_NAME", os.environ.get("OTEL_SERVICE_NAME", "defenseclaw"))
        click.echo(f"    Service:     {svc}")
        click.echo()

    if sc.enabled:
        click.echo("  Splunk Enterprise (HEC):")
        click.echo("    Status:      enabled")
        click.echo(f"    HEC:         {sc.hec_endpoint}")
        click.echo(f"    Index:       {sc.index}")
        click.echo(f"    Source:      {sc.source}")
        click.echo(f"    Sourcetype:  {sc.sourcetype}")
        click.echo()

    if not otel.enabled and not sc.enabled:
        click.echo("  No Splunk integrations are currently enabled.")
        click.echo()


def _print_splunk_next_steps(did_o11y: bool, did_logs: bool) -> None:
    click.echo("  Next steps:")
    click.echo("    1. Start (or restart) the DefenseClaw sidecar:")
    click.echo("       defenseclaw-gateway restart")
    if did_logs:
        click.echo("    2. Open local Splunk Web at http://127.0.0.1:8000")
    click.echo()
    click.echo("  To disable:")
    if did_o11y and did_logs:
        click.echo("    defenseclaw setup splunk --disable            # both")
        click.echo("    defenseclaw setup splunk --disable --o11y     # O11y only")
        click.echo("    defenseclaw setup splunk --disable --logs     # local only")
    elif did_o11y:
        click.echo("    defenseclaw setup splunk --disable --o11y")
    elif did_logs:
        click.echo("    defenseclaw setup splunk --disable --logs")


# ---------------------------------------------------------------------------
# setup sandbox
# ---------------------------------------------------------------------------

@setup.command("sandbox")
@click.option("--sandbox-ip", default="10.200.0.2", help="Bridge IP of the sandbox (default: 10.200.0.2)")
@click.option("--host-ip", default="10.200.0.1", help="Bridge IP of the host (default: 10.200.0.1)")
@click.option("--sandbox-home", default=None, help="Sandbox user home directory (default: /home/sandbox)")
@click.option("--openclaw-port", type=int, default=18789, help="OpenClaw gateway port inside sandbox")
@click.option("--policy", type=click.Choice(["default", "strict", "permissive"]), default="default", help="Network policy template")
@click.option("--dns", default="8.8.8.8,1.1.1.1", help="DNS nameservers (comma-separated, or 'host')")
@click.option("--no-auto-pair", is_flag=True, help="Disable automatic device pre-pairing")
@click.option("--disable", is_flag=True, help="Revert to host mode (no sandbox)")
@click.option("--non-interactive", is_flag=True, help="Skip confirmation prompts")
@pass_ctx
def setup_sandbox(
    app: AppContext,
    sandbox_ip: str,
    host_ip: str,
    sandbox_home: str | None,
    openclaw_port: int,
    policy: str,
    dns: str,
    no_auto_pair: bool,
    disable: bool,
    non_interactive: bool,
) -> None:
    """Configure DefenseClaw for openshell-sandbox standalone mode.

    Full orchestration: configures networking, generates systemd units,
    patches OpenClaw config, sets up device pairing, and installs policy.

    \b
    Example:
      defenseclaw setup sandbox --sandbox-ip 10.200.0.2 --host-ip 10.200.0.1
      defenseclaw setup sandbox --policy strict --no-auto-pair
      defenseclaw setup sandbox --disable
    """
    import platform

    if disable:
        _disable_sandbox(app)
        return

    if platform.system() != "Linux":
        click.echo("  ERROR: Sandbox mode requires Linux.", err=True)
        raise SystemExit(1)

    sandbox_home = sandbox_home or app.cfg.openshell.effective_sandbox_home()
    data_dir = app.cfg.data_dir

    click.echo()
    click.echo("  Configuring sandbox mode ...")

    # 1. Validate prerequisites
    _validate_sandbox_prerequisites(sandbox_home)

    # 2. Configure DefenseClaw
    app.cfg.openshell.mode = "standalone"
    app.cfg.openshell.sandbox_home = sandbox_home
    if no_auto_pair:
        app.cfg.openshell.auto_pair = False

    app.cfg.gateway.host = sandbox_ip
    app.cfg.gateway.port = openclaw_port
    app.cfg.guardrail.host = host_ip
    app.cfg.gateway.watcher.enabled = True
    app.cfg.gateway.watcher.skill.enabled = True
    app.cfg.gateway.watcher.skill.take_action = True

    app.cfg.claw.home_dir = os.path.join(sandbox_home, ".openclaw")
    app.cfg.claw.config_file = os.path.join(sandbox_home, ".openclaw", "openclaw.json")

    click.echo(f"    openshell.mode:       standalone")
    click.echo(f"    openshell.sandbox_home: {sandbox_home}")
    click.echo(f"    gateway.host:         {sandbox_ip}")
    click.echo(f"    guardrail.host:       {host_ip}")
    click.echo(f"    claw.home_dir:        {app.cfg.claw.home_dir}")

    # 3. Read gateway auth token from OpenClaw config (same as non-sandbox mode).
    #    OpenClaw owns the token — DefenseClaw never generates or injects one.
    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    detected_token = _detect_openclaw_gateway_token(oc_config)
    if detected_token:
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", detected_token, data_dir)
        app.cfg.gateway.token = ""
        app.cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        click.echo(f"    gateway.token:        read from openclaw.json ({_mask(detected_token)})")
    else:
        click.echo(f"    gateway.token:        not found (sidecar will auto-detect on connect)")

    # 4. Install policy template
    _install_policy_template(data_dir, policy)
    click.echo(f"    policy template:      {policy}")

    # 5. Generate DNS resolv.conf
    _generate_resolv_conf(data_dir, dns)
    click.echo(f"    dns nameservers:      {dns}")

    # 6. Patch sandbox-side OpenClaw config (port + bind only, never the token)
    if os.path.isfile(oc_config):
        _patch_openclaw_gateway(oc_config, openclaw_port)
        click.echo(f"    openclaw.json:        patched (gateway.port={openclaw_port}, gateway.bind=lan)")

    # 7. Generate systemd unit files
    _generate_systemd_units(data_dir, sandbox_home, host_ip, sandbox_ip, app.cfg)
    click.echo(f"    systemd units:        generated in {data_dir}")

    # 8. Generate launcher scripts
    _generate_launcher_scripts(data_dir, sandbox_home, host_ip, app.cfg)
    click.echo(f"    launcher scripts:     generated in {data_dir}")

    # 9. Device pre-pairing
    if not no_auto_pair:
        paired = _pre_pair_device(data_dir, sandbox_home)
        if paired:
            click.echo(f"    device pairing:       pre-paired")
        else:
            click.echo(f"    device pairing:       skipped (device.key not found)")
    else:
        click.echo(f"    device pairing:       manual (--no-auto-pair)")

    # 10. Fix ownership and traversal — all files written above (openclaw.json
    #     patch, paired.json, policy templates) were created as root. Restore
    #     sandbox ownership so the OpenClaw process can read/write them.
    #     Also ensure parent directories (e.g. /root/) have o+x so the sandbox
    #     user can follow the symlink to the real OpenClaw home.
    oc_target = os.path.join(sandbox_home, ".openclaw")
    if os.path.islink(oc_target):
        oc_target = os.readlink(oc_target)
    try:
        subprocess.run(
            ["chown", "-R", "sandbox:sandbox", oc_target],
            capture_output=True, check=False,
        )
    except FileNotFoundError:
        pass

    from defenseclaw.commands.cmd_init import _ensure_parent_traversal
    _ensure_parent_traversal(oc_target)

    # 11. Save config
    app.cfg.save()

    # 12. Install systemd units and launcher scripts (if systemd present)
    has_systemd = shutil.which("systemctl") is not None
    installed = _install_systemd_units(data_dir) if has_systemd else False

    # 13. Generate convenience run-sandbox.sh for non-systemd environments
    _generate_run_sandbox_script(data_dir, host_ip, app.cfg)

    click.echo()
    click.echo("  ── Summary ───────────────────────────────────────────")
    click.echo()
    click.echo("  Sandbox mode configured successfully.")
    click.echo()

    if installed:
        click.echo("  ✓ Systemd units installed and daemon reloaded")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Run 'defenseclaw setup guardrail' to configure LLM interception")
        click.echo(f"       (will set baseUrl to http://{host_ip}:{app.cfg.guardrail.port})")
        click.echo()
        click.echo("    2. Start the sandbox:")
        click.echo("       sudo systemctl start defenseclaw-sandbox.target")
    elif has_systemd:
        click.echo("  ⚠ Systemd units were generated but could not be installed automatically.")
        click.echo(f"    Files are at: {data_dir}/systemd/ and {data_dir}/scripts/")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Install systemd units manually (requires root):")
        click.echo(f"       sudo cp {data_dir}/systemd/*.service /etc/systemd/system/")
        click.echo(f"       sudo cp {data_dir}/systemd/*.target /etc/systemd/system/")
        click.echo(f"       sudo mkdir -p /usr/local/lib/defenseclaw")
        click.echo(f"       sudo cp {data_dir}/scripts/*.sh /usr/local/lib/defenseclaw/")
        click.echo(f"       sudo chmod +x /usr/local/lib/defenseclaw/*.sh")
        click.echo(f"       sudo systemctl daemon-reload")
        click.echo()
        click.echo("    2. Run 'defenseclaw setup guardrail' to configure LLM interception")
        click.echo(f"       (will set baseUrl to http://{host_ip}:{app.cfg.guardrail.port})")
        click.echo()
        click.echo("    3. Start the sandbox:")
        click.echo("       sudo systemctl start defenseclaw-sandbox.target")
    else:
        click.echo("  ℹ No systemd detected (container/minimal environment).")
        click.echo()
        click.echo("  Next steps:")
        click.echo("    1. Run 'defenseclaw setup guardrail' to configure LLM interception")
        click.echo(f"       (will set baseUrl to http://{host_ip}:{app.cfg.guardrail.port})")
        click.echo()
        click.echo("    2. Start the sandbox manually:")
        click.echo(f"       sudo {data_dir}/scripts/run-sandbox.sh")
        click.echo()
        click.echo("    To stop:")
        click.echo(f"       sudo {data_dir}/scripts/run-sandbox.sh stop")
    click.echo()


def _restore_openclaw_ownership(data_dir: str, sandbox_home: str) -> None:
    """Restore original ownership of the OpenClaw home directory from backup.

    Reads the backup file saved during init, runs chown -R to restore
    original uid:gid, removes the symlink from sandbox home, and
    deletes the backup file.
    """
    import json as _json_mod
    from defenseclaw.commands.cmd_init import OPENCLAW_OWNERSHIP_BACKUP

    backup_path = os.path.join(data_dir, OPENCLAW_OWNERSHIP_BACKUP)
    if not os.path.isfile(backup_path):
        return

    try:
        with open(backup_path) as f:
            backup = _json_mod.load(f)
    except (OSError, _json_mod.JSONDecodeError) as exc:
        click.echo(f"  Ownership:     failed to read backup ({exc})")
        return

    openclaw_home = backup.get("openclaw_home", "")
    uid = backup.get("original_uid")
    gid = backup.get("original_gid")

    if not openclaw_home or uid is None or gid is None:
        click.echo("  Ownership:     invalid backup data")
        return

    # Restore ownership
    try:
        result = subprocess.run(
            ["chown", "-R", f"{uid}:{gid}", openclaw_home],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            click.echo(f"  Ownership:     restored to {uid}:{gid} on {openclaw_home}")
        else:
            click.echo(f"  Ownership:     restore failed ({result.stderr.strip()})")
    except FileNotFoundError:
        click.echo("  Ownership:     chown not found")

    # Restore parent directory permissions (remove o+x we added)
    for entry in backup.get("parents_modified", []):
        ppath = entry.get("path", "")
        orig_mode = entry.get("original_mode", "")
        if ppath and orig_mode:
            try:
                os.chmod(ppath, int(orig_mode, 8))
                click.echo(f"  Traversal:     restored {ppath} to {orig_mode}")
            except OSError:
                pass

    # Remove symlink from sandbox home
    symlink_path = os.path.join(sandbox_home, ".openclaw")
    if os.path.islink(symlink_path):
        try:
            os.remove(symlink_path)
            click.echo(f"  Symlink:       removed {symlink_path}")
        except OSError as exc:
            click.echo(f"  Symlink:       remove failed ({exc})")

    # Remove backup file
    try:
        os.remove(backup_path)
    except OSError:
        pass


def _disable_sandbox(app: AppContext) -> None:
    """Revert to host mode: restore OpenClaw ownership, clean up symlink, reset config."""
    sandbox_home = app.cfg.openshell.effective_sandbox_home()

    # Restore gateway config in openclaw.json BEFORE removing the symlink
    oc_config = os.path.join(sandbox_home, ".openclaw", "openclaw.json")
    if os.path.isfile(oc_config):
        _restore_openclaw_gateway(oc_config)

    # Restore original OpenClaw ownership and remove symlink
    _restore_openclaw_ownership(app.cfg.data_dir, sandbox_home)

    app.cfg.openshell.mode = ""
    app.cfg.gateway.host = "127.0.0.1"
    app.cfg.gateway.port = 18789
    app.cfg.guardrail.host = "localhost"
    app.cfg.gateway.watcher.enabled = False
    app.cfg.claw.home_dir = "~/.openclaw"
    app.cfg.claw.config_file = "~/.openclaw/openclaw.json"
    app.cfg.claw.openclaw_home_original = ""
    app.cfg.save()
    click.echo("  Sandbox mode disabled. Config reverted to host mode.")
    click.echo("  Re-run 'defenseclaw setup guardrail' to update openclaw.json baseUrl.")


def _validate_sandbox_prerequisites(sandbox_home: str) -> None:
    """Check that required prerequisites exist."""
    import pwd
    try:
        pwd.getpwnam("sandbox")
    except KeyError:
        click.echo("  WARNING: 'sandbox' user not found. Run 'defenseclaw init --sandbox' first.", err=True)

    if not os.path.isdir(sandbox_home):
        click.echo(f"  WARNING: sandbox home {sandbox_home} does not exist.", err=True)


def _patch_openclaw_gateway(openclaw_config: str, port: int) -> bool:
    """Patch gateway port and bind into openclaw.json for sandbox mode.

    Only sets mode/port/bind — the auth token is owned by OpenClaw and
    never written by DefenseClaw.
    """
    try:
        st = os.stat(openclaw_config)
        with open(openclaw_config) as f:
            cfg = _json.load(f)
    except (OSError, _json.JSONDecodeError):
        return False

    gw = cfg.setdefault("gateway", {})
    gw["mode"] = "local"
    gw["port"] = port
    gw["bind"] = "lan"

    with open(openclaw_config, "w") as f:
        _json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    try:
        os.chown(openclaw_config, st.st_uid, st.st_gid)
    except OSError:
        pass
    return True


def _restore_openclaw_gateway(openclaw_config: str) -> bool:
    """Remove gateway.* fields from openclaw.json."""
    try:
        st = os.stat(openclaw_config)
        with open(openclaw_config) as f:
            cfg = _json.load(f)
    except (OSError, _json.JSONDecodeError):
        return False

    gw = cfg.get("gateway", {})
    for key in ("mode", "port", "bind", "token"):
        gw.pop(key, None)
    auth = gw.get("auth", {})
    auth.pop("token", None)

    with open(openclaw_config, "w") as f:
        _json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    try:
        os.chown(openclaw_config, st.st_uid, st.st_gid)
    except OSError:
        pass
    return True


def _install_policy_template(data_dir: str, policy_name: str) -> None:
    """Copy the selected policy template to the data dir."""
    policy_dir = os.path.join(data_dir, "policies")
    os.makedirs(policy_dir, exist_ok=True)

    repo_root = _find_repo_root()
    if not repo_root:
        click.echo("  WARNING: Could not find repo root. Policy templates not installed.", err=True)
        return

    rego_src = os.path.join(repo_root, "policies", "openshell", "default.rego")
    data_src = os.path.join(repo_root, "policies", "openshell", f"{policy_name}-data.yaml")

    for src, dst_name in [(rego_src, "openshell-policy.rego"), (data_src, "openshell-policy.yaml")]:
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(data_dir, dst_name))


def _generate_resolv_conf(data_dir: str, dns_arg: str) -> None:
    """Write sandbox-resolv.conf with configured nameservers."""
    if dns_arg == "host":
        nameservers = _parse_host_resolv()
    else:
        nameservers = [ns.strip() for ns in dns_arg.split(",") if ns.strip()]

    if not nameservers:
        nameservers = ["8.8.8.8", "1.1.1.1"]

    resolv_path = os.path.join(data_dir, "sandbox-resolv.conf")
    with open(resolv_path, "w") as f:
        for ns in nameservers:
            f.write(f"nameserver {ns}\n")


def _parse_host_resolv() -> list[str]:
    """Parse nameservers from host /etc/resolv.conf."""
    try:
        with open("/etc/resolv.conf") as f:
            return [
                line.split()[1]
                for line in f
                if line.strip().startswith("nameserver") and len(line.split()) >= 2
            ]
    except OSError:
        return []


def _generate_systemd_units(
    data_dir: str,
    sandbox_home: str,
    host_ip: str,
    sandbox_ip: str,
    cfg,
) -> None:
    """Generate systemd unit files for the sandbox and sidecar."""
    systemd_dir = os.path.join(data_dir, "systemd")
    os.makedirs(systemd_dir, exist_ok=True)

    sandbox_unit = f"""[Unit]
Description=OpenShell Sandbox (DefenseClaw-managed)
Documentation=https://github.com/defenseclaw/defenseclaw
After=network.target

[Service]
Type=exec
ExecStartPre=/usr/local/lib/defenseclaw/pre-sandbox.sh
ExecStart=/usr/local/lib/defenseclaw/start-sandbox.sh
ExecStartPost=/usr/local/lib/defenseclaw/post-sandbox.sh
ExecStopPost=/usr/local/lib/defenseclaw/cleanup-sandbox.sh

Restart=on-failure
RestartSec=5
RestartMaxDelaySec=60

StandardOutput=journal
StandardError=journal
SyslogIdentifier=openshell-sandbox

[Install]
WantedBy=defenseclaw-sandbox.target
"""

    sidecar_unit = f"""[Unit]
Description=DefenseClaw Gateway Sidecar
Documentation=https://github.com/defenseclaw/defenseclaw
After=openshell-sandbox.service
Wants=openshell-sandbox.service

[Service]
Type=exec
ExecStart=/usr/local/bin/defenseclaw-gateway run

Restart=on-failure
RestartSec=3
RestartMaxDelaySec=30

StandardOutput=journal
StandardError=journal
SyslogIdentifier=defenseclaw-gateway

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={data_dir}
ReadOnlyPaths={sandbox_home}/.openclaw

[Install]
WantedBy=defenseclaw-sandbox.target
"""

    target_unit = """[Unit]
Description=DefenseClaw Sandbox (sandbox + sidecar)
Wants=openshell-sandbox.service defenseclaw-gateway.service

[Install]
WantedBy=multi-user.target
"""

    with open(os.path.join(systemd_dir, "openshell-sandbox.service"), "w") as f:
        f.write(sandbox_unit)
    with open(os.path.join(systemd_dir, "defenseclaw-gateway.service"), "w") as f:
        f.write(sidecar_unit)
    with open(os.path.join(systemd_dir, "defenseclaw-sandbox.target"), "w") as f:
        f.write(target_unit)


def _install_systemd_units(data_dir: str) -> bool:
    """Install generated systemd units and launcher scripts into system paths.

    Returns True if all steps succeeded.
    """
    import glob
    import shutil

    systemd_src = os.path.join(data_dir, "systemd")
    scripts_src = os.path.join(data_dir, "scripts")
    systemd_dst = "/etc/systemd/system"
    scripts_dst = "/usr/local/lib/defenseclaw"

    if not os.path.isdir(systemd_src):
        click.echo("    systemd install:     skipped (units not generated)")
        return False

    try:
        for f in glob.glob(os.path.join(systemd_src, "*.service")) + \
                 glob.glob(os.path.join(systemd_src, "*.target")):
            shutil.copy2(f, systemd_dst)

        os.makedirs(scripts_dst, exist_ok=True)
        if os.path.isdir(scripts_src):
            for f in glob.glob(os.path.join(scripts_src, "*.sh")):
                shutil.copy2(f, scripts_dst)
                os.chmod(os.path.join(scripts_dst, os.path.basename(f)), 0o755)

        import subprocess
        subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True, check=True,
        )
        click.echo("    systemd install:     units and scripts installed")
        return True
    except PermissionError:
        click.echo("    systemd install:     skipped (not root)")
        return False
    except FileNotFoundError:
        click.echo("    systemd install:     skipped (systemctl not found)")
        return False
    except subprocess.CalledProcessError as exc:
        click.echo(f"    systemd install:     daemon-reload failed ({exc})")
        return False


def _generate_launcher_scripts(
    data_dir: str,
    sandbox_home: str,
    host_ip: str,
    cfg,
) -> None:
    """Generate launcher shell scripts for the sandbox lifecycle."""
    scripts_dir = os.path.join(data_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)

    api_port = cfg.gateway.api_port
    guardrail_port = cfg.guardrail.port

    pre_sandbox = f"""#!/bin/bash
set -euo pipefail

SANDBOX_HOME="{sandbox_home}"
OC_LINK="$SANDBOX_HOME/.openclaw"

# Resolve the real OpenClaw home (follows symlink)
if [ -L "$OC_LINK" ]; then
    OC_REAL=$(readlink "$OC_LINK")
else
    OC_REAL="$OC_LINK"
fi

# Ensure parent directories are traversable (o+x) so the sandbox user
# can follow the symlink. /root/ is typically 700 which blocks access.
dir=$(dirname "$OC_REAL")
while [ "$dir" != "/" ] && [ -n "$dir" ]; do
    perms=$(stat -c %a "$dir" 2>/dev/null || echo "")
    if [ -n "$perms" ]; then
        other_x=$((perms % 10))
        if [ $((other_x & 1)) -eq 0 ]; then
            chmod o+x "$dir"
            echo "Added o+x to $dir"
        fi
    fi
    dir=$(dirname "$dir")
done

# Fix ownership — ensure sandbox user owns everything under OpenClaw home
chown -R sandbox:sandbox "$OC_REAL" 2>/dev/null || true

# Also fix /home/sandbox/.openclaw (the actual home dir, not just symlink target).
# Node.js uses atomic writes (write-to-temp then rename) which bypass default
# ACLs entirely, and explicit open(path, 0600) resets the ACL mask to ---.
# Both patterns require a blanket fix-up on every startup.
_fix_acls() {{
    local target="$1"
    [ -d "$target" ] || return 0
    chown -R sandbox:sandbox "$target" 2>/dev/null || true
    setfacl -R -m u:sandbox:rwX "$target" 2>/dev/null || true
    setfacl -R -d -m u:sandbox:rwX "$target" 2>/dev/null || true
    setfacl -R -m m::rwx "$target" 2>/dev/null || true
    setfacl -R -d -m m::rwx "$target" 2>/dev/null || true
}}

if command -v setfacl >/dev/null 2>&1; then
    _fix_acls "$OC_REAL"
    # Sandbox home may differ from symlink target (e.g. /home/sandbox/.openclaw
    # is a real dir while OC_REAL points to /root/.openclaw).
    if [ "$SANDBOX_HOME/.openclaw" != "$OC_REAL" ] && [ -d "$SANDBOX_HOME/.openclaw" ]; then
        _fix_acls "$SANDBOX_HOME/.openclaw"
    fi
    # Parent traversal via ACL (targeted — doesn't open /root to all users)
    dir="$OC_REAL"
    while [ "$dir" != "/" ] && [ -n "$dir" ]; do
        dir=$(dirname "$dir")
        setfacl -m u:sandbox:rx "$dir" 2>/dev/null || true
    done
fi

for ns in $(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{{print $1}}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done

find "$SANDBOX_HOME/.openclaw/agents/" -name "*.lock" -delete 2>/dev/null || true

if [ -f "$SANDBOX_HOME/.openclaw/gateway.pid" ]; then
    pid=$(cat "$SANDBOX_HOME/.openclaw/gateway.pid")
    if ! (kill -0 "$pid" 2>/dev/null && \\
          grep -q openshell "/proc/$pid/cmdline" 2>/dev/null); then
        rm -f "$SANDBOX_HOME/.openclaw/gateway.pid"
        echo "Cleaned stale PID file (pid=$pid)"
    fi
fi
"""

    start_sandbox = f"""#!/bin/bash
set -euo pipefail

DEFENSECLAW_DIR="{data_dir}"
RESOLV_FILE="$DEFENSECLAW_DIR/sandbox-resolv.conf"
POLICY_REGO="$DEFENSECLAW_DIR/openshell-policy.rego"
POLICY_DATA="$DEFENSECLAW_DIR/openshell-policy.yaml"
SANDBOX_HOME="{sandbox_home}"

exec unshare --mount -- bash -c '
    mount --bind '"$RESOLV_FILE"' /etc/resolv.conf
    exec openshell-sandbox \\
        --policy-rules '"$POLICY_REGO"' \\
        --policy-data '"$POLICY_DATA"' \\
        --log-level info \\
        --timeout 0 \\
        -w '"$SANDBOX_HOME"' \\
        -- '"$SANDBOX_HOME"'/start-openclaw.sh
'
"""

    post_sandbox = f"""#!/bin/bash
set -euo pipefail

DEFENSECLAW_DIR="{data_dir}"
HOST_IP="{host_ip}"
API_PORT={api_port}
GUARDRAIL_PORT={guardrail_port}

# Wait for the veth pair to come up
for i in $(seq 1 30); do
    if ip addr show | grep -q "$HOST_IP"; then
        break
    fi
    sleep 1
done

if ! ip addr show | grep -q "$HOST_IP"; then
    echo "WARNING: veth pair not detected — openshell-sandbox manages networking internally" >&2
fi

# Attempt iptables injection into the sandbox namespace.
# openshell-sandbox creates namespaces programmatically and may not expose
# them in a way compatible with 'ip netns exec'. In that case, network
# policy is enforced by openshell-sandbox's built-in OPA proxy, which
# reads allowed endpoints from the policy data YAML.
NS=$(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{{print $1}}' | head -1)
if [ -z "$NS" ]; then
    echo "NOTE: sandbox namespace not accessible via ip netns — OPA proxy handles network policy"
    exit 0
fi

if ip netns exec "$NS" true 2>/dev/null; then
    for ns in $(grep '^nameserver' "$DEFENSECLAW_DIR/sandbox-resolv.conf" | awk '{{print $2}}'); do
        ip netns exec "$NS" iptables -I OUTPUT 1 -p udp -d "$ns" --dport 53 -j ACCEPT 2>/dev/null || true
    done

    ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" --dport "$API_PORT" -j ACCEPT 2>/dev/null || true
    ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp -d "$HOST_IP" --dport "$GUARDRAIL_PORT" -j ACCEPT 2>/dev/null || true

    echo "Injected iptables rules into namespace $NS"
else
    echo "NOTE: cannot enter namespace $NS — OPA proxy handles network policy"
fi
"""

    cleanup_sandbox = """#!/bin/bash
for ns in $(ip netns list 2>/dev/null | grep -E 'sandbox|openshell' | awk '{print $1}'); do
    ip netns delete "$ns" 2>/dev/null && echo "Cleaned orphan namespace: $ns"
done

for veth in $(ip link show 2>/dev/null | grep -oP 'veth-h-\\S+(?=@)'); do
    ip link delete "$veth" 2>/dev/null && echo "Cleaned stale veth: $veth"
done
"""

    start_openclaw = f"""#!/bin/bash
set -euo pipefail

export NO_PROXY="{host_ip}${{NO_PROXY:+,$NO_PROXY}}"

exec openclaw gateway run
"""

    for name, content in [
        ("pre-sandbox.sh", pre_sandbox),
        ("start-sandbox.sh", start_sandbox),
        ("post-sandbox.sh", post_sandbox),
        ("cleanup-sandbox.sh", cleanup_sandbox),
    ]:
        path = os.path.join(scripts_dir, name)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)

    oc_script = os.path.join(sandbox_home, "start-openclaw.sh")
    try:
        with open(oc_script, "w") as f:
            f.write(start_openclaw)
        os.chmod(oc_script, 0o755)
    except OSError:
        click.echo(f"  WARNING: Could not write {oc_script}. Create it manually.", err=True)


def _generate_run_sandbox_script(data_dir: str, host_ip: str, cfg) -> None:
    """Generate a standalone run-sandbox.sh that starts everything without systemd."""
    scripts_dir = os.path.join(data_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)

    gateway_bin = shutil.which("defenseclaw-gateway") or "defenseclaw-gateway"
    api_bind = host_ip
    api_port = cfg.gateway.api_port

    script = f"""#!/bin/bash
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$(dirname "$SCRIPTS_DIR")"
PIDFILE="$DATA_DIR/sandbox.pids"
ACL_FIXER_PID=""

# ---------------------------------------------------------------------------
# kill_tree PID — recursively kill a process and all its descendants.
# Walks children depth-first so leaves die before parents, preventing zombies
# from being reparented to PID 1.
# ---------------------------------------------------------------------------
kill_tree() {{
    local pid=$1 sig=${{2:-TERM}}
    local children
    children=$(ps -o pid= --ppid "$pid" 2>/dev/null || true)
    for child in $children; do
        kill_tree "$child" "$sig"
    done
    kill -"$sig" "$pid" 2>/dev/null || true
}}

stop_sandbox() {{
    echo "Stopping sandbox processes..."

    # 1. Kill the ACL fixer first (lightweight, no children)
    if [ -n "$ACL_FIXER_PID" ] && kill -0 "$ACL_FIXER_PID" 2>/dev/null; then
        kill "$ACL_FIXER_PID" 2>/dev/null || true
        wait "$ACL_FIXER_PID" 2>/dev/null || true
        echo "  stopped acl-fixer (pid $ACL_FIXER_PID)"
    fi

    # 2. Kill tracked processes and their entire process trees
    if [ -f "$PIDFILE" ]; then
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill_tree "$pid" TERM
                echo "  sent SIGTERM to $name tree (pid $pid)"
            fi
        done < "$PIDFILE"

        # Give processes 3 seconds to exit gracefully
        sleep 3

        # Escalate to SIGKILL for anything still alive
        while read -r pid name; do
            if kill -0 "$pid" 2>/dev/null; then
                kill_tree "$pid" KILL
                echo "  sent SIGKILL to $name tree (pid $pid)"
            fi
        done < "$PIDFILE"

        # Reap all children to prevent zombies
        while read -r pid name; do
            wait "$pid" 2>/dev/null || true
        done < "$PIDFILE"

        rm -f "$PIDFILE"
    fi

    # 3. Kill any orphaned sandbox-related processes not tracked in the PID file.
    #    These can accumulate when previous runs used an older stop mechanism
    #    or when the script was killed without cleanup.
    _kill_strays() {{
        local pat="$1"
        local pids
        pids=$(pgrep -f "$pat" 2>/dev/null || true)
        for p in $pids; do
            # Don't kill ourselves or our parent
            [ "$p" = "$$" ] && continue
            [ "$p" = "$PPID" ] && continue
            kill "$p" 2>/dev/null && echo "  killed stray $pat (pid $p)"
        done
    }}
    _kill_strays openshell-sandbox
    _kill_strays defenseclaw-gateway
    _kill_strays "openclaw$"
    _kill_strays openclaw-gateway
    _kill_strays "dmesg --follow"

    # 4. Clean up network namespace and veth pairs
    "$SCRIPTS_DIR/cleanup-sandbox.sh" 2>/dev/null || true

    # 5. Reap any remaining background jobs (ACL fixer, etc.)
    wait 2>/dev/null || true

    echo "Sandbox stopped."
}}

if [ "${{1:-}}" = "stop" ]; then
    stop_sandbox
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run-sandbox.sh requires root" >&2
    exit 1
fi

trap 'stop_sandbox; exit 0' EXIT INT TERM

rm -f "$PIDFILE"

# 1. Clean stale state
echo "==> Cleaning stale state..."
"$SCRIPTS_DIR/pre-sandbox.sh"

# 2. Start openshell-sandbox in background
echo "==> Starting openshell-sandbox..."
"$SCRIPTS_DIR/start-sandbox.sh" &
SANDBOX_PID=$!
echo "$SANDBOX_PID openshell-sandbox" >> "$PIDFILE"
echo "  openshell-sandbox started (pid $SANDBOX_PID)"

# 3. Wait for sandbox namespace to appear
echo "==> Waiting for sandbox namespace..."
for i in $(seq 1 30); do
    if ! kill -0 "$SANDBOX_PID" 2>/dev/null; then
        echo "ERROR: openshell-sandbox exited prematurely" >&2
        wait "$SANDBOX_PID" 2>/dev/null
        exit 1
    fi
    if ip netns list 2>/dev/null | grep -qE 'sandbox|openshell'; then
        break
    fi
    sleep 1
done

if ! ip netns list 2>/dev/null | grep -qE 'sandbox|openshell'; then
    echo "ERROR: sandbox namespace not created after 30s" >&2
    exit 1
fi
echo "  namespace ready"

# 4. Inject iptables rules
echo "==> Injecting iptables rules..."
"$SCRIPTS_DIR/post-sandbox.sh"

# 5. Start defenseclaw-gateway
echo "==> Starting defenseclaw-gateway..."
{gateway_bin} &
GATEWAY_PID=$!
echo "$GATEWAY_PID defenseclaw-gateway" >> "$PIDFILE"
echo "  defenseclaw-gateway started (pid $GATEWAY_PID)"

sleep 2

# 6. Health check
if curl -sf "http://{api_bind}:{api_port}/health" -o /dev/null 2>/dev/null; then
    echo ""
    echo "==> Sandbox is running"
    echo "    sidecar health: http://{api_bind}:{api_port}/health"
    echo "    stop with:      $SCRIPTS_DIR/run-sandbox.sh stop"
    echo ""
else
    echo "WARNING: sidecar health check failed (http://{api_bind}:{api_port}/health)" >&2
fi

# 7. Background ACL fixer — OpenClaw uses atomic writes (write-to-temp then
# rename) which bypass POSIX default ACLs, and explicit open(path, 0600)
# resets the ACL mask to ---.  This loop periodically re-applies correct ACLs
# so the sandbox user can always read/write OpenClaw config and extensions.
_fix_sandbox_acls() {{
    while kill -0 "$SANDBOX_PID" 2>/dev/null; do
        sleep 5
        for d in /root/.openclaw /home/sandbox/.openclaw; do
            [ -d "$d" ] || continue
            setfacl -R -m u:sandbox:rwX "$d" 2>/dev/null || true
            setfacl -R -m m::rwx "$d" 2>/dev/null || true
        done
    done
}}
_fix_sandbox_acls &
ACL_FIXER_PID=$!

# Keep running until signalled
wait
"""

    path = os.path.join(scripts_dir, "run-sandbox.sh")
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)


def _extract_ed25519_pubkey(key_data: bytes) -> "bytes | None":
    """Extract the Ed25519 public key from a device key file.

    Supports PEM-encoded seeds (as written by the Go gateway) and raw
    32/64-byte keys. Returns the 32-byte public key or None.
    """
    import base64

    # PEM format: -----BEGIN ED25519 PRIVATE KEY-----\n<base64 seed>\n-----END ...
    text = key_data.decode("utf-8", errors="replace")
    if "BEGIN ED25519 PRIVATE KEY" in text:
        lines = text.strip().splitlines()
        b64_lines = [l for l in lines if not l.startswith("-----")]
        try:
            seed = base64.b64decode("".join(b64_lines))
        except Exception:
            return None
        if len(seed) != 32:
            return None
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub_bytes = priv.public_key().public_bytes_raw()
        return pub_bytes

    # Raw binary: 64-byte key (seed + pub) or 32-byte pub
    if len(key_data) == 64:
        return key_data[32:]
    if len(key_data) == 32:
        return key_data
    return None


def _pre_pair_device(data_dir: str, sandbox_home: str) -> bool:
    """Pre-inject the sidecar's device key into OpenClaw's devices/paired.json."""
    import base64
    import hashlib
    import time

    device_key_file = os.path.join(data_dir, "device.key")
    if not os.path.isfile(device_key_file):
        return False

    try:
        with open(device_key_file, "rb") as f:
            key_data = f.read()
    except OSError:
        return False

    pub_key = _extract_ed25519_pubkey(key_data)
    if pub_key is None:
        return False

    pub_b64 = base64.urlsafe_b64encode(pub_key).decode().rstrip("=")
    device_id = hashlib.sha256(pub_key).hexdigest()

    devices_dir = os.path.join(sandbox_home, ".openclaw", "devices")
    paired_path = os.path.join(devices_dir, "paired.json")
    paired: dict = {}

    if os.path.isfile(paired_path):
        try:
            with open(paired_path) as f:
                paired = _json.load(f)
            if not isinstance(paired, dict):
                paired = {}
        except (OSError, _json.JSONDecodeError):
            paired = {}

    now_ms = int(time.time() * 1000)
    existing = paired.get(device_id, {})
    paired[device_id] = {
        "deviceId": device_id,
        "publicKey": pub_b64,
        "displayName": "defenseclaw-sidecar",
        "platform": "linux",
        "deviceFamily": existing.get("deviceFamily"),
        "clientId": "gateway-client",
        "clientMode": "backend",
        "role": "operator",
        "roles": ["operator"],
        "scopes": [
            "operator.read",
            "operator.write",
            "operator.admin",
            "operator.approvals",
        ],
        "approvedScopes": [
            "operator.read",
            "operator.write",
            "operator.admin",
            "operator.approvals",
        ],
        "tokens": existing.get("tokens", {}),
        "createdAtMs": existing.get("createdAtMs", now_ms),
        "approvedAtMs": now_ms,
    }

    os.makedirs(devices_dir, exist_ok=True)
    with open(paired_path, "w") as f:
        _json.dump(paired, f, indent=2)
        f.write("\n")

    # Ensure the sandbox user can read the paired device file
    try:
        import pwd as _pwd
        import shutil
        sandbox_uid = _pwd.getpwnam("sandbox").pw_uid
        sandbox_gid = _pwd.getpwnam("sandbox").pw_gid
        for d in [devices_dir, paired_path]:
            shutil.chown(d, sandbox_uid, sandbox_gid)
    except (KeyError, OSError):
        pass

    return True


def _find_repo_root() -> str | None:
    """Walk up from this file to find the repo root (contains policies/ dir)."""
    path = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.isdir(os.path.join(path, "policies")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return None
