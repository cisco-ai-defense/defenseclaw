"""defenseclaw setup — Configure DefenseClaw settings and integrations.

Mirrors internal/cli/setup.go.
"""

from __future__ import annotations

import os
import subprocess

import click

from defenseclaw.context import AppContext, pass_ctx


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
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_skill_scanner(
    app: AppContext,
    use_llm, use_behavioral, enable_meta, use_trigger,
    use_virustotal, use_aidefense,
    llm_provider, llm_model, llm_consensus_runs,
    policy, lenient, non_interactive,
) -> None:
    """Configure skill-scanner analyzers, API keys, and policy.

    Interactively configure how skill-scanner runs. Enables LLM analysis,
    behavioral dataflow analysis, meta-analyzer filtering, and more.

    API keys are stored in ~/.defenseclaw/config.yaml and injected as
    environment variables when skill-scanner runs.

    Use --non-interactive with flags for CI/scripted configuration.
    """
    sc = app.cfg.scanners.skill_scanner

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
            sc.llm_provider = llm_provider
        if llm_model is not None:
            sc.llm_model = llm_model
        if llm_consensus_runs is not None:
            sc.llm_consensus_runs = llm_consensus_runs
        if policy is not None:
            sc.policy = policy
        if lenient is not None:
            sc.lenient = lenient
    else:
        _interactive_setup(sc)

    app.cfg.save()
    _print_summary(sc)

    if app.logger:
        parts = [f"use_llm={sc.use_llm}", f"use_behavioral={sc.use_behavioral}", f"enable_meta={sc.enable_meta}"]
        if sc.llm_provider:
            parts.append(f"llm_provider={sc.llm_provider}")
        if sc.policy:
            parts.append(f"policy={sc.policy}")
        app.logger.log_action("setup-skill-scanner", "config", " ".join(parts))


def _interactive_setup(sc) -> None:
    click.echo()
    click.echo("  Skill Scanner Configuration")
    click.echo("  ────────────────────────────")
    click.echo(f"  Binary: {sc.binary}")
    click.echo()

    sc.use_behavioral = click.confirm("  Enable behavioral analyzer (dataflow analysis)?", default=sc.use_behavioral)
    sc.use_llm = click.confirm("  Enable LLM analyzer (semantic analysis)?", default=sc.use_llm)

    if sc.use_llm:
        sc.llm_provider = click.prompt(
            "  LLM provider (anthropic/openai)",
            default=sc.llm_provider or "anthropic",
        )
        sc.llm_model = click.prompt("  LLM model name", default=sc.llm_model or "", show_default=False)
        sc.enable_meta = click.confirm("  Enable meta-analyzer (false positive filtering)?", default=sc.enable_meta)
        sc.llm_consensus_runs = click.prompt(
            "  LLM consensus runs (0 = disabled)", type=int, default=sc.llm_consensus_runs,
        )
        sc.llm_api_key = _prompt_secret("SKILL_SCANNER_LLM_API_KEY", sc.llm_api_key)

    sc.use_trigger = click.confirm("  Enable trigger analyzer (vague description checks)?", default=sc.use_trigger)
    sc.use_virustotal = click.confirm("  Enable VirusTotal binary scanner?", default=sc.use_virustotal)
    if sc.use_virustotal:
        sc.virustotal_api_key = _prompt_secret("VIRUSTOTAL_API_KEY", sc.virustotal_api_key)

    sc.use_aidefense = click.confirm("  Enable Cisco AI Defense analyzer?", default=sc.use_aidefense)
    if sc.use_aidefense:
        sc.aidefense_api_key = _prompt_secret("AI_DEFENSE_API_KEY", sc.aidefense_api_key)

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


def _prompt_secret(env_name: str, current: str) -> str:
    env_val = os.environ.get(env_name, "")
    if current:
        hint = _mask(current)
    elif env_val:
        hint = f"from env: {_mask(env_val)}"
    else:
        hint = "(not set)"
    val = click.prompt(f"  {env_name} [{hint}]", default="", show_default=False)
    if val:
        return val
    return current or env_val


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]


def _print_summary(sc) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows = [
        ("use_behavioral", str(sc.use_behavioral).lower()),
        ("use_llm", str(sc.use_llm).lower()),
    ]
    if sc.use_llm:
        rows.append(("llm_provider", sc.llm_provider))
        if sc.llm_model:
            rows.append(("llm_model", sc.llm_model))
        rows.append(("enable_meta", str(sc.enable_meta).lower()))
        if sc.llm_consensus_runs > 0:
            rows.append(("llm_consensus_runs", str(sc.llm_consensus_runs)))
        if sc.llm_api_key:
            rows.append(("llm_api_key", _mask(sc.llm_api_key)))
    if sc.use_trigger:
        rows.append(("use_trigger", "true"))
    if sc.use_virustotal:
        rows.append(("use_virustotal", "true"))
        if sc.virustotal_api_key:
            rows.append(("virustotal_api_key", _mask(sc.virustotal_api_key)))
    if sc.use_aidefense:
        rows.append(("use_aidefense", "true"))
        if sc.aidefense_api_key:
            rows.append(("aidefense_api_key", _mask(sc.aidefense_api_key)))
    if sc.policy:
        rows.append(("policy", sc.policy))
    if sc.lenient:
        rows.append(("lenient", "true"))

    for key, val in rows:
        click.echo(f"    scanners.skill_scanner.{key + ':':<22s} {val}")
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
@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")
@pass_ctx
def setup_gateway(
    app: AppContext,
    remote: bool,
    host, port, api_port, token,
    ssm_param, ssm_region, ssm_profile,
    non_interactive: bool,
) -> None:
    """Configure gateway connection for the DefenseClaw sidecar.

    By default configures for a local OpenClaw instance (no token needed).
    Use --remote to configure for a remote gateway that requires an auth token,
    optionally fetched from AWS SSM Parameter Store.
    """
    gw = app.cfg.gateway

    if non_interactive:
        if host is not None:
            gw.host = host
        if port is not None:
            gw.port = port
        if api_port is not None:
            gw.api_port = api_port
        if token is not None:
            gw.token = token
        elif ssm_param:
            fetched = _fetch_ssm_token(ssm_param, ssm_region or "us-east-1", ssm_profile)
            if fetched:
                gw.token = fetched
            else:
                click.echo("error: failed to fetch token from SSM", err=True)
                raise SystemExit(1)
    elif remote:
        _interactive_gateway_remote(gw)
    else:
        _interactive_gateway_local(gw)

    app.cfg.save()
    _print_gateway_summary(gw)

    if app.logger:
        mode = "remote" if (remote or gw.token) else "local"
        app.logger.log_action("setup-gateway", "config", f"mode={mode} host={gw.host} port={gw.port}")


def _interactive_gateway_local(gw) -> None:
    click.echo()
    click.echo("  Gateway Configuration (local)")
    click.echo("  ─────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)
    gw.token = ""
    click.echo()
    click.echo("  Local mode: no auth token needed.")


def _interactive_gateway_remote(gw) -> None:
    click.echo()
    click.echo("  Gateway Configuration (remote)")
    click.echo("  ──────────────────────────────")
    click.echo()

    gw.host = click.prompt("  Gateway host", default=gw.host)
    gw.port = click.prompt("  Gateway port", default=gw.port, type=int)
    gw.api_port = click.prompt("  Sidecar API port", default=gw.api_port, type=int)

    click.echo()
    use_ssm = click.confirm("  Fetch token from AWS SSM Parameter Store?", default=True)

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
            gw.token = fetched
            click.echo(f" ok ({_mask(fetched)})")
        else:
            click.echo(" failed")
            click.echo("  Falling back to manual entry.")
            gw.token = _prompt_secret("OPENCLAW_GATEWAY_TOKEN", gw.token)
    else:
        gw.token = _prompt_secret("OPENCLAW_GATEWAY_TOKEN", gw.token)

    if not gw.token:
        click.echo("  warning: no token set — sidecar will fail to connect to a remote gateway", err=True)


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


def _print_gateway_summary(gw) -> None:
    click.echo()
    click.echo("  Saved to ~/.defenseclaw/config.yaml")
    click.echo()

    rows = [
        ("host", gw.host),
        ("port", str(gw.port)),
        ("api_port", str(gw.api_port)),
        ("token", _mask(gw.token) if gw.token else "(none — local mode)"),
    ]

    for key, val in rows:
        click.echo(f"    gateway.{key + ':':<12s} {val}")
    click.echo()

    if gw.token:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
    else:
        click.echo("  Start the sidecar with:")
        click.echo("    defenseclaw-gateway")
        click.echo("  (local mode — ensure OpenClaw is running on this machine)")
    click.echo()
