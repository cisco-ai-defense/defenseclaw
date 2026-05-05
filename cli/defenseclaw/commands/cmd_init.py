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

"""defenseclaw init — Initialize DefenseClaw environment.

Mirrors internal/cli/init.go.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import click

from defenseclaw import ux
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.inventory import agent_discovery
from defenseclaw.paths import (
    bundled_guardrail_profiles_dir,
    bundled_local_observability_dir,
    bundled_rego_dir,
    bundled_splunk_bridge_dir,
)


@click.command("init")
@click.option("--skip-install", is_flag=True, help="Skip automatic scanner dependency installation")
@click.option("--enable-guardrail", is_flag=True, help="Configure LLM guardrail during init")
@click.option("--sandbox", is_flag=True, help="Set up sandbox mode (Linux only: creates sandbox user and directories)")
@click.option("--non-interactive", is_flag=True, help="Run the guided first-run backend without prompts.")
@click.option("--yes", "-y", is_flag=True, help="Assume defaults/yes for first-run prompts.")
@click.option("--rescan-agents", is_flag=True, help="Refresh cached local agent discovery before choosing a connector.")
@click.option(
    "--connector",
    type=click.Choice([
        "codex", "claudecode", "claude-code", "zeptoclaw", "openclaw",
        "hermes", "cursor", "windsurf", "geminicli", "copilot",
    ], case_sensitive=False),
    default=None,
    help="Agent connector to configure.",
)
@click.option(
    "--profile",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default=None,
    help="Protection profile. Defaults to observe.",
)
@click.option(
    "--scanner-mode",
    type=click.Choice(["local", "remote", "both"], case_sensitive=False),
    default="local",
    show_default=True,
    help="Scanner backend to configure.",
)
@click.option("--with-judge/--no-judge", default=False, help="Enable or disable the LLM judge.")
@click.option(
    "--fail-mode",
    type=click.Choice(["open", "closed"], case_sensitive=False),
    default=None,
    help=(
        "Hook fail-mode for response-layer failures (gateway returns 4xx, malformed JSON, "
        "or missing action). 'open' = allow + log (recommended); 'closed' = block. "
        "Transport failures (gateway unreachable / 5xx) ALWAYS allow unless "
        "DEFENSECLAW_STRICT_AVAILABILITY=1, regardless of this setting."
    ),
)
@click.option(
    "--human-approval/--no-human-approval",
    "human_approval",
    default=None,
    help=(
        "Human-In-the-Loop (HITL): require operator approval before risky tool "
        "actions execute. Only fires in action mode — observe mode logs without "
        "blocking, regardless of this flag. Omitting the flag preserves the "
        "current setting; you can still flip it later via "
        "`defenseclaw setup guardrail`."
    ),
)
@click.option(
    "--hilt-min-severity",
    type=click.Choice(["HIGH", "MEDIUM", "LOW", "CRITICAL"], case_sensitive=False),
    default=None,
    help=(
        "Lowest finding severity that triggers a HITL approval prompt. Defaults "
        "to HIGH on first install. CRITICAL findings always block regardless of "
        "this setting."
    ),
)
@click.option("--llm-provider", default="", help="Unified LLM provider (openai, anthropic, ollama, etc.).")
@click.option("--llm-model", default="", help="Unified LLM model, preferably provider/model.")
@click.option("--llm-api-key", default="", help="LLM API key to save into .env (config stores only the env name).")
@click.option(
    "--llm-api-key-env",
    default="DEFENSECLAW_LLM_KEY",
    show_default=True,
    help="Env var name for the unified LLM key.",
)
@click.option("--llm-base-url", default="", help="Local/proxy LLM base URL.")
@click.option("--cisco-endpoint", default="", help="Cisco AI Defense endpoint.")
@click.option("--cisco-api-key", default="", help="Cisco AI Defense key to save into .env.")
@click.option(
    "--cisco-api-key-env",
    default="CISCO_AI_DEFENSE_API_KEY",
    show_default=True,
    help="Env var name for Cisco AI Defense key.",
)
@click.option("--start-gateway/--no-start-gateway", default=None, help="Start the gateway sidecar after setup.")
@click.option("--verify/--no-verify", default=None, help="Run targeted readiness checks before exiting.")
@click.option("--json-summary", is_flag=True, help="Emit the final first-run report as JSON.")
@click.option("--verbose", is_flag=True, help="Show full subprocess/setup output.")
@pass_ctx
def init_cmd(  # noqa: PLR0913 - first-run CLI mirrors the setup surface.
    app: AppContext,
    skip_install: bool,
    enable_guardrail: bool,
    sandbox: bool,
    non_interactive: bool,
    yes: bool,
    rescan_agents: bool,
    connector: str | None,
    profile: str | None,
    scanner_mode: str,
    with_judge: bool,
    fail_mode: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    llm_provider: str,
    llm_model: str,
    llm_api_key: str,
    llm_api_key_env: str,
    llm_base_url: str,
    cisco_endpoint: str,
    cisco_api_key: str,
    cisco_api_key_env: str,
    start_gateway: bool | None,
    verify: bool | None,
    json_summary: bool,
    verbose: bool,
) -> None:
    """Initialize DefenseClaw environment.

    Creates ~/.defenseclaw/, default config, SQLite database,
    and installs scanner dependencies.

    Use --sandbox to set up openshell-sandbox standalone mode (Linux only).
    Use --enable-guardrail to configure the LLM guardrail inline.
    """
    import platform

    if _use_guided_first_run(
        non_interactive=non_interactive,
        yes=yes,
        connector=connector,
        profile=profile,
        with_judge=with_judge,
        fail_mode=fail_mode,
        human_approval=human_approval,
        hilt_min_severity=hilt_min_severity,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
        llm_base_url=llm_base_url,
        cisco_endpoint=cisco_endpoint,
        cisco_api_key=cisco_api_key,
        start_gateway=start_gateway,
        verify=verify,
        json_summary=json_summary,
    ):
        _run_first_run_cmd(
            skip_install=skip_install,
            enable_guardrail=enable_guardrail,
            sandbox=sandbox,
            non_interactive=non_interactive,
            yes=yes,
            rescan_agents=rescan_agents,
            connector=connector,
            profile=profile,
            scanner_mode=scanner_mode,
            with_judge=with_judge,
            fail_mode=fail_mode,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_api_key=llm_api_key,
            llm_api_key_env=llm_api_key_env,
            llm_base_url=llm_base_url,
            cisco_endpoint=cisco_endpoint,
            cisco_api_key=cisco_api_key,
            cisco_api_key_env=cisco_api_key_env,
            start_gateway=start_gateway,
            verify=verify,
            json_summary=json_summary,
            verbose=verbose,
        )
        return

    from defenseclaw.config import config_path, default_config, detect_environment, load
    from defenseclaw.db import Store
    from defenseclaw.logger import Logger

    if sandbox and platform.system() != "Linux":
        ux.err("Sandbox mode requires Linux.", indent="  ")
        raise SystemExit(1)

    ux.banner("Environment")

    from defenseclaw import __version__
    click.echo(f"  DefenseClaw:   {ux.bold('v' + __version__)}")
    gw_version = _get_gateway_version()
    if gw_version:
        click.echo(f"  Gateway:       {ux.bold(gw_version)}")
    else:
        click.echo("  Gateway:       " + ux._style("not found", fg="yellow"))

    env = detect_environment()
    click.echo(f"  Platform:      {ux.bold(env)}")

    cfg_file = config_path()
    is_new_config = not os.path.exists(cfg_file)
    if is_new_config:
        cfg = default_config()
        click.echo("  Config:        " + ux._style("created new defaults", fg="green"))
    else:
        cfg = load()
        click.echo("  Config:        " + ux.dim("preserved existing"))

    cfg.environment = env
    click.echo(f"  Claw mode:     {ux.bold(cfg.claw.mode)}")
    click.echo(f"  Claw home:     {cfg.claw_home_dir()}")

    dirs = [
        cfg.data_dir, cfg.quarantine_dir,
        cfg.plugin_dir, cfg.policy_dir,
    ]

    data_dir_real = os.path.realpath(cfg.data_dir)
    for d in dirs:
        os.makedirs(d, exist_ok=True)

    external_dirs = list(cfg.skill_dirs())
    for d in external_dirs:
        d_real = os.path.realpath(d)
        if d_real.startswith(data_dir_real + os.sep):
            os.makedirs(d, exist_ok=True)
    click.echo("  Directories:   " + ux._style("created", fg="green"))

    _seed_rego_policies(cfg.policy_dir)
    _seed_guardrail_profiles(cfg.policy_dir)
    _seed_splunk_bridge(cfg.data_dir)
    _seed_local_observability_stack(cfg.data_dir)

    cfg.save()
    click.echo(f"  Config file:   {cfg_file}")

    store = Store(cfg.audit_db)
    store.init()
    click.echo(f"  Audit DB:      {cfg.audit_db}")

    logger = Logger(store, cfg.splunk)
    logger.log_action("init", cfg.data_dir, f"environment={env}")

    ux.banner("Scanners")
    _install_scanners(cfg, logger, skip_install)
    _show_scanner_defaults(cfg)

    ux.banner("Gateway")
    _setup_gateway_defaults(cfg, logger, is_new_config=is_new_config)

    ux.banner("Guardrail")
    guardrail_ok = False
    if enable_guardrail:
        guardrail_ok = _setup_guardrail_inline(app, cfg, logger)
    else:
        _install_guardrail(cfg, logger, skip_install)
        click.echo()
        click.echo("  Run 'defenseclaw init --enable-guardrail' or")
        click.echo("  'defenseclaw setup guardrail' to enable the guardrail proxy.")

    ux.banner("Skills")
    click.echo("  CodeGuard:     skipped (opt in with 'defenseclaw codeguard install --target skill')")

    cfg.save()

    # Sandbox setup (Linux only)
    if sandbox:
        already_configured = cfg.openshell.is_standalone()
        if already_configured:
            ux.banner("Sandbox")
            click.echo(
                "  Sandbox:       "
                + ux._style("already configured", fg="green")
                + ux.dim(" (openshell.mode=standalone)")
            )
        else:
            ux.banner("Sandbox")
            from defenseclaw.commands.cmd_init_sandbox import _init_sandbox
            sandbox_ok = _init_sandbox(cfg, logger)

            if sandbox_ok:
                ux.banner("Sandbox Networking")
                from defenseclaw.commands.cmd_setup_sandbox import setup_sandbox
                app.cfg = cfg
                ctx = click.Context(setup_sandbox, parent=click.get_current_context())
                ctx.invoke(setup_sandbox, sandbox_ip="10.200.0.2", host_ip="10.200.0.1",
                           sandbox_home=None, openclaw_port=18789, dns="8.8.8.8,1.1.1.1",
                           policy="default", no_auto_pair=False, disable=False,
                           non_interactive=True)

    sidecar_started = False
    if not sandbox:
        ux.banner("Sidecar")
        _start_gateway(cfg, logger)
        sidecar_started = True

        if guardrail_ok and sidecar_started:
            click.echo("  " + ux.dim("Restarting sidecar to apply guardrail config..."))
            _restart_gateway_quiet()

    # Final completion banner. We render it as a plain divider with
    # bold success text so the eye lands here when the operator
    # scrolls back up after a long init.
    click.echo()
    click.echo("  " + ux.dim("─" * 54))
    click.echo()
    ux.ok("DefenseClaw initialized.", indent="  ")
    click.echo()
    click.echo("  " + ux.bold("Next steps:"))
    if sandbox and not guardrail_ok:
        click.echo(
            f"    {ux.accent('defenseclaw setup guardrail')}   "
            + ux.dim("Enable LLM traffic inspection")
        )
    elif not guardrail_ok:
        click.echo(
            f"    {ux.accent('defenseclaw setup guardrail')}   "
            + ux.dim("Enable LLM traffic inspection")
        )
    if not sidecar_started and not sandbox:
        click.echo(
            f"    {ux.accent('defenseclaw-gateway start')}     "
            + ux.dim("Start the sidecar")
        )
    click.echo(
        f"    {ux.accent('defenseclaw setup')}            "
        + ux.dim("Customize scanners and policies")
    )
    click.echo(
        f"    {ux.accent('defenseclaw doctor')}           "
        + ux.dim("Verify connectivity and credentials")
    )
    click.echo(
        f"    {ux.accent('defenseclaw skill scan all')}   "
        + ux.dim("Scan installed OpenClaw skills")
    )
    click.echo(
        f"    {ux.accent('defenseclaw mcp scan --all')}   "
        + ux.dim("Scan configured MCP servers")
    )

    store.close()


def _stdin_is_tty() -> bool:
    try:
        return click.get_text_stream("stdin").isatty()
    except Exception:
        return False


def _use_guided_first_run(**kwargs) -> bool:
    if kwargs.get("json_summary"):
        return True
    if kwargs.get("non_interactive") or kwargs.get("yes"):
        return True
    if kwargs.get("connector") or kwargs.get("profile"):
        return True
    if kwargs.get("with_judge"):
        return True
    # Explicit --fail-mode means the operator opted into the
    # guided flow even if no other flags were passed.
    if kwargs.get("fail_mode"):
        return True
    # Explicit HITL flags imply intent to use the guided flow:
    # ``--human-approval`` is a tri-state, so check ``is not None``
    # rather than truthiness — ``--no-human-approval`` is a real
    # signal too.
    if kwargs.get("human_approval") is not None:
        return True
    if kwargs.get("hilt_min_severity"):
        return True
    if kwargs.get("start_gateway") is not None or kwargs.get("verify") is not None:
        return True
    for key in (
        "llm_provider",
        "llm_model",
        "llm_api_key",
        "llm_base_url",
        "cisco_endpoint",
        "cisco_api_key",
    ):
        if kwargs.get(key):
            return True
    return _stdin_is_tty()


def _run_first_run_cmd(  # noqa: PLR0913 - mirrors click options.
    *,
    skip_install: bool,
    enable_guardrail: bool,
    sandbox: bool,
    non_interactive: bool,
    yes: bool,
    rescan_agents: bool,
    connector: str | None,
    profile: str | None,
    scanner_mode: str,
    with_judge: bool,
    fail_mode: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    llm_provider: str,
    llm_model: str,
    llm_api_key: str,
    llm_api_key_env: str,
    llm_base_url: str,
    cisco_endpoint: str,
    cisco_api_key: str,
    cisco_api_key_env: str,
    start_gateway: bool | None,
    verify: bool | None,
    json_summary: bool,
    verbose: bool,
) -> None:
    from defenseclaw.bootstrap import FirstRunOptions, run_first_run
    from defenseclaw.ux import CLIRenderer

    if not non_interactive and not yes and not json_summary and _stdin_is_tty():
        (
            connector,
            profile,
            scanner_mode,
            with_judge,
            fail_mode,
            human_approval,
            hilt_min_severity,
            start_gateway,
            verify,
        ) = _prompt_first_run(
            connector=connector,
            profile=profile,
            scanner_mode=scanner_mode,
            with_judge=with_judge,
            fail_mode=fail_mode,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
            start_gateway=start_gateway,
            verify=verify,
            rescan_agents=rescan_agents,
        )

    connector = _normalize_connector_arg(
        connector,
        discover_default=True,
        refresh_agents=rescan_agents,
    )
    if profile is None:
        profile = "observe"
    if start_gateway is None:
        start_gateway = False
    if verify is None:
        verify = True

    opts = FirstRunOptions(
        connector=connector,
        profile=profile,
        scanner_mode=scanner_mode,
        with_judge=with_judge,
        skip_install=skip_install,
        sandbox=sandbox,
        start_gateway=start_gateway,
        verify=verify,
        verbose=verbose,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
        llm_api_key_env=llm_api_key_env,
        llm_base_url=llm_base_url,
        cisco_endpoint=cisco_endpoint,
        cisco_api_key=cisco_api_key,
        cisco_api_key_env=cisco_api_key_env,
        # Empty string means "leave the existing value alone" — the
        # bootstrap layer treats "" as a no-op so first-run flows
        # that don't surface this option don't accidentally reset
        # an operator's earlier choice.
        hook_fail_mode=(fail_mode or "").lower(),
        # HITL: ``None`` is "leave alone", ``True``/``False`` set
        # the toggle. Empty severity preserves the existing floor;
        # bootstrap normalizes case and falls back to ``HIGH`` on
        # invalid values.
        human_approval=human_approval,
        hilt_min_severity=hilt_min_severity or "",
    )
    report = run_first_run(opts)
    if json_summary:
        click.echo(json.dumps(report.to_dict(), indent=2))
        return
    _render_first_run_report(report, CLIRenderer())
    if report.status == "needs_attention":
        raise SystemExit(1)


def _prompt_first_run(
    *,
    connector: str | None,
    profile: str | None,
    scanner_mode: str,
    with_judge: bool,
    fail_mode: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    start_gateway: bool | None,
    verify: bool | None,
    rescan_agents: bool,
) -> tuple[str, str, str, bool, str, bool | None, str | None, bool, bool]:
    ux.section("DefenseClaw First-Run Setup")
    ux.subhead(
        "This wizard writes config.yaml, then runs targeted readiness checks.",
    )
    click.echo()
    connector_choices = list(KNOWN_CONNECTORS)
    if connector:
        connector = _normalize_connector_arg(connector)
    else:
        disc = agent_discovery.discover_agents(refresh=rescan_agents)
        table = agent_discovery.render_discovery_table(disc).rstrip()
        if table:
            click.echo(table)
            click.echo()
        connector = click.prompt(
            "  Connector",
            type=click.Choice(connector_choices, case_sensitive=False),
            default=agent_discovery.first_installed(disc, "codex"),
            show_choices=True,
        )
    if profile is None:
        profile = click.prompt(
            "  " + ux.bold("Protection profile"),
            type=click.Choice(["observe", "action"], case_sensitive=False),
            default="observe",
            show_choices=True,
        )
    scanner_mode = click.prompt(
        "  " + ux.bold("Scanner mode"),
        type=click.Choice(["local", "remote", "both"], case_sensitive=False),
        default=scanner_mode or "local",
        show_choices=True,
    )
    with_judge = click.confirm("  " + ux.bold("Enable LLM judge now?"), default=with_judge)
    # Hook fail-mode: surface the choice so first-run operators
    # don't have to discover `defenseclaw guardrail fail-mode` to
    # change it later. We only ask when the operator hasn't already
    # supplied --fail-mode explicitly. Default is "open" because
    # silently bricking the agent on a transient gateway response
    # error is worse than leaking a single tool call.
    if fail_mode is None:
        ux.section("Hook fail-mode (response-layer failures)")
        ux.subhead(
            "What hooks do when the gateway returns 4xx, malformed JSON, or no action.",
        )
        ux.subhead(
            "Transport failures (gateway down / 5xx) ALWAYS allow unless "
            "DEFENSECLAW_STRICT_AVAILABILITY=1.",
        )
        fail_mode = click.prompt(
            "  " + ux.bold("Fail mode"),
            type=click.Choice(["open", "closed"], case_sensitive=False),
            default="open",
            show_choices=True,
        )
    # Human-In-the-Loop (HITL). HITL only fires in action mode —
    # the gateway short-circuits in observe mode regardless of
    # the toggle, so prompting for it in observe mode is just
    # noise that misleads operators about what their answer
    # does. We still honor an explicit --human-approval flag in
    # observe mode (handled by the caller) so an operator who
    # plans to flip to action later doesn't lose their setting.
    if (profile or "observe").lower() == "action" and human_approval is None:
        ux.section("Human-In-the-Loop approvals (HITL)")
        ux.subhead(
            "Action mode can pause risky tool calls and ask you to approve them.",
        )
        ux.subhead(
            "CRITICAL findings always block — HITL covers the lower severities you "
            "want to review first.",
        )
        human_approval = click.confirm(
            "  " + ux.bold("Require human approval for risky actions?"),
            default=False,
        )
        if human_approval and hilt_min_severity is None:
            hilt_min_severity = click.prompt(
                "  " + ux.bold("Minimum severity that triggers approval"),
                type=click.Choice(
                    ["HIGH", "MEDIUM", "LOW", "CRITICAL"],
                    case_sensitive=False,
                ),
                default="HIGH",
                show_choices=True,
            ).upper()
    start_gateway = click.confirm(
        "  " + ux.bold("Start gateway after setup?"),
        default=bool(start_gateway),
    )
    verify = click.confirm(
        "  " + ux.bold("Run targeted readiness checks?"),
        default=True if verify is None else bool(verify),
    )
    return (
        connector,
        profile,
        scanner_mode,
        with_judge,
        fail_mode,
        human_approval,
        hilt_min_severity,
        start_gateway,
        verify,
    )


def _normalize_connector_arg(
    connector: str | None,
    *,
    discover_default: bool = False,
    refresh_agents: bool = False,
) -> str:
    if connector is None and discover_default:
        try:
            disc = agent_discovery.discover_agents(refresh=refresh_agents)
            connector = agent_discovery.first_installed(disc, "codex")
        except Exception:
            connector = "codex"
    value = (connector or "codex").strip().lower()
    if value in {"claude-code", "claude_code", "claude"}:
        return "claudecode"
    return value


def _render_first_run_report(report, renderer) -> None:
    subtitle = f"status={report.status} connector={report.connector} profile={report.profile}"
    renderer.title("DefenseClaw First-Run", subtitle)
    renderer.section("Setup")
    for step in report.setup:
        renderer.step(step.status, step.name, step.detail)
    renderer.section("Readiness")
    for step in report.readiness:
        renderer.step(step.status, step.name, step.detail)
    renderer.section("Next")
    for cmd in report.next_commands[:5]:
        renderer.echo(f"  {cmd}")


def _seed_rego_policies(policy_dir: str) -> None:
    """Copy bundled Rego policies into the user's policy_dir if not already present."""
    bundled_rego = bundled_rego_dir()
    if not bundled_rego.is_dir():
        return

    dest_rego = os.path.join(policy_dir, "rego")
    os.makedirs(dest_rego, exist_ok=True)

    for src in bundled_rego.iterdir():
        if src.suffix in (".rego", ".json") and not src.name.startswith("."):
            dst = os.path.join(dest_rego, src.name)
            if not os.path.exists(dst):
                shutil.copy2(str(src), dst)

    click.echo(f"  Rego policies: {dest_rego}")


def _seed_guardrail_profiles(policy_dir: str) -> None:
    """Copy bundled guardrail rule-pack profiles (default/strict/permissive) into
    the user's policy_dir if not already present. Operators can then edit the
    YAML in place and `defenseclaw policy reload` will pick up the changes.
    """
    bundled = bundled_guardrail_profiles_dir()
    if bundled is None:
        return

    dest_root = os.path.join(policy_dir, "guardrail")
    os.makedirs(dest_root, exist_ok=True)

    seeded: list[str] = []
    preserved: list[str] = []
    for profile_dir in bundled.iterdir():
        if not profile_dir.is_dir() or profile_dir.name.startswith("."):
            continue
        dst = os.path.join(dest_root, profile_dir.name)
        if os.path.isdir(dst):
            preserved.append(profile_dir.name)
            continue
        shutil.copytree(str(profile_dir), dst)
        seeded.append(profile_dir.name)

    if seeded:
        click.echo(f"  Guardrail rule packs: seeded {', '.join(sorted(seeded))} in {dest_root}")
    if preserved:
        click.echo(f"  Guardrail rule packs: preserved existing ({', '.join(sorted(preserved))})")


def _seed_splunk_bridge(data_dir: str) -> None:
    """Copy vendored Splunk bridge runtime into ~/.defenseclaw/splunk-bridge/."""
    bundled = _resolve_splunk_bridge_bundle()
    if not bundled.is_dir():
        return

    dest = os.path.join(data_dir, "splunk-bridge")
    if os.path.isdir(dest):
        click.echo(f"  Splunk bridge: preserved existing ({dest})")
        return

    shutil.copytree(str(bundled), dest)
    bridge_bin = os.path.join(dest, "bin", "splunk-claw-bridge")
    if os.path.isfile(bridge_bin):
        os.chmod(bridge_bin, 0o755)
    click.echo(f"  Splunk bridge: seeded in {dest}")


def _resolve_splunk_bridge_bundle():
    """Resolve the vendored local Splunk runtime from package data or source tree."""
    return bundled_splunk_bridge_dir()


def _seed_local_observability_stack(data_dir: str) -> None:
    """Copy bundled Prom/Loki/Tempo/Grafana stack into ~/.defenseclaw/observability-stack/.

    Mirrors _seed_splunk_bridge so ``defenseclaw setup
    local-observability`` can drive a user-editable copy of the stack
    (dashboards, alert rules, prom config) without requiring the
    operator to unpack the wheel. Preserves an existing seeded copy so
    operator edits survive subsequent ``init`` runs.
    """
    bundled = bundled_local_observability_dir()
    if not bundled.is_dir():
        return

    dest = os.path.join(data_dir, "observability-stack")
    if os.path.isdir(dest):
        click.echo(f"  Observability stack: preserved existing ({dest})")
        return

    shutil.copytree(str(bundled), dest)
    bridge_bin = os.path.join(dest, "bin", "openclaw-observability-bridge")
    if os.path.isfile(bridge_bin):
        os.chmod(bridge_bin, 0o755)
    shim = os.path.join(dest, "run.sh")
    if os.path.isfile(shim):
        os.chmod(shim, 0o755)
    click.echo(f"  Observability stack: seeded in {dest}")


def _install_scanners(cfg, logger, skip: bool) -> None:
    if skip:
        click.echo("  Scanners:      skipped (--skip-install)")
        return

    _verify_scanner_sdk("skill-scanner", "skill_scanner")
    _verify_scanner_sdk("mcp-scanner", "mcpscanner", min_python=(3, 11))


def _verify_scanner_sdk(name: str, import_name: str, min_python: tuple[int, ...] | None = None) -> None:
    """Check that a scanner SDK is importable; report status."""
    import importlib
    import sys

    pad = max(14 - len(name), 1)
    label = name + ":" + " " * pad

    if min_python and sys.version_info < min_python:
        ver = ".".join(str(v) for v in min_python)
        click.echo(f"  {label}{ux._style(f'requires Python >={ver}', fg='yellow')} {ux.dim('(skipped)')}")
        return

    try:
        importlib.import_module(import_name)
        click.echo(f"  {label}{ux._style('available', fg='green')}")
    except ImportError:
        click.echo(f"  {label}{ux._style('not installed', fg='yellow')}")
        click.echo("                 " + ux.dim("install with: pip install defenseclaw"))


def _show_scanner_defaults(cfg) -> None:
    """Display the default scanner configuration set during init."""
    sc = cfg.scanners.skill_scanner
    mc = cfg.scanners.mcp_scanner

    click.echo()
    click.echo(f"  skill-scanner: policy={sc.policy}, lenient={sc.lenient}")
    click.echo(f"  mcp-scanner:   analyzers={mc.analyzers}")
    click.echo()
    click.echo("  Run 'defenseclaw setup' to customize scanner settings.")


def _ensure_device_key(path: str) -> None:
    """Create the Ed25519 device key file if it doesn't exist.

    The Go gateway creates this on first start, but the guardrail setup
    needs it earlier to derive the proxy master key. Uses the same PEM
    format as internal/gateway/device.go.
    """
    if os.path.exists(path):
        return
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    os.makedirs(os.path.dirname(path), exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    import base64
    b64_seed = base64.b64encode(seed).decode()
    pem_data = (
        "-----BEGIN ED25519 PRIVATE KEY-----\n"
        f"{b64_seed}\n"
        "-----END ED25519 PRIVATE KEY-----\n"
    )
    # Create the file with 0o600 atomically so the key is never
    # world-readable, even for the brief window between open() and
    # the previous chmod(). ``O_EXCL`` ensures we don't overwrite a
    # concurrently-created key (idempotent early-exit already covered
    # the is-it-there case above).
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        # Another process won the race — trust its key and exit.
        return
    with os.fdopen(fd, "w") as f:
        f.write(pem_data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _resolve_openclaw_gateway(claw_config_file: str) -> dict[str, str | int]:
    """Read gateway host, port, and token from openclaw.json.

    Looks for gateway.port and gateway.auth.token when gateway.mode is 'local'.
    Always uses the shared gateway.auth.token — device-auth.json is a
    client-side cache used by the OpenClaw Node.js client, not by our Go gateway.
    """
    from defenseclaw.config import _read_openclaw_config

    result: dict[str, str | int] = {
        "host": "127.0.0.1",
        "port": 18789,
        "token": "",
    }

    oc = _read_openclaw_config(claw_config_file)
    if not oc:
        return result

    gw = oc.get("gateway", {})
    if not isinstance(gw, dict):
        return result

    mode = gw.get("mode", "local")
    if mode == "local":
        result["host"] = "127.0.0.1"
    else:
        result["host"] = gw.get("host", "127.0.0.1")

    if "port" in gw:
        try:
            result["port"] = int(gw["port"])
        except (ValueError, TypeError):
            pass

    auth = gw.get("auth", {})
    if isinstance(auth, dict):
        token = auth.get("token", "")
        if token:
            result["token"] = token

    return result


def _resolve_gateway_for_connector(cfg) -> dict[str, str | int]:
    """Resolve gateway host/port/token based on the active connector.

    OpenClaw: reads from openclaw.json.
    Others: return loopback defaults (no token — rely on device key auth).
    """
    connector = (cfg.guardrail.connector or "openclaw").lower()

    if connector == "openclaw":
        return _resolve_openclaw_gateway(cfg.claw.config_file)

    return {
        "host": "127.0.0.1",
        "port": 18789,
        "token": "",
    }


def _setup_gateway_defaults(cfg, logger, is_new_config: bool = True) -> None:
    """Resolve gateway settings from the active connector and display them.

    Only applies connector values (host/port/token) when creating a new config.
    Existing configs preserve user-customized gateway settings.
    """
    connector = (cfg.guardrail.connector or "openclaw").lower()
    gw_info = _resolve_gateway_for_connector(cfg)
    token_configured = False
    if is_new_config:
        cfg.gateway.host = gw_info["host"]
        cfg.gateway.port = gw_info["port"]

    if connector == "openclaw" and gw_info["token"]:
        from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", gw_info["token"], cfg.data_dir)
        cfg.gateway.token = ""
        cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        token_configured = True
    elif gw_info["token"]:
        from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv
        env_name = f"{connector.upper()}_GATEWAY_TOKEN"
        _save_secret_to_dotenv(env_name, gw_info["token"], cfg.data_dir)
        cfg.gateway.token = ""
        cfg.gateway.token_env = env_name
        token_configured = True
    else:
        cfg.gateway.token_env = cfg.gateway.token_env or "OPENCLAW_GATEWAY_TOKEN"
        token_configured = bool(cfg.gateway.resolved_token())

    if not cfg.gateway.device_key_file:
        cfg.gateway.device_key_file = os.path.join(cfg.data_dir, "device.key")

    _ensure_device_key(cfg.gateway.device_key_file)

    click.echo(f"  Gateway:       {cfg.gateway.host}:{cfg.gateway.port} (connector: {connector})")
    # Plan B2 / S0.2: the sidecar synthesizes a CSPRNG token on first
    # boot and persists it to ~/.defenseclaw/.env (mode 0600). The
    # "none" branch is now an instruction, not a security mode.
    token_status = (
        "configured"
        if token_configured
        else "auto-generated on first boot (~/.defenseclaw/.env)"
    )
    click.echo(f"  Token:         {token_status}")
    click.echo(f"  API port:      {cfg.gateway.api_port}")
    click.echo(f"  Watcher:       enabled={cfg.gateway.watcher.enabled}")
    click.echo(f"  AI discovery:  enabled={cfg.ai_discovery.enabled}, mode={cfg.ai_discovery.mode}")
    click.echo(f"  Skill watch:   enabled={cfg.gateway.watcher.skill.enabled}, "
               f"take_action={cfg.gateway.watcher.skill.take_action}")
    plugin_dirs = cfg.gateway.watcher.plugin.dirs or cfg.plugin_dirs()
    click.echo(f"  Plugin watch:  enabled={cfg.gateway.watcher.plugin.enabled}, "
               f"take_action={cfg.gateway.watcher.plugin.take_action}")
    click.echo(f"  Plugin dirs:   {', '.join(plugin_dirs)}")
    click.echo(f"  Device key:    {cfg.gateway.device_key_file}")
    click.echo()
    click.echo("  Run 'defenseclaw setup gateway' to customize.")

    logger.log_action("init-gateway", "config",
                       f"host={cfg.gateway.host} port={cfg.gateway.port}")


def _install_guardrail(cfg, logger, skip: bool) -> None:
    """Report guardrail proxy status (built into Go binary, no external deps)."""
    if skip:
        click.echo("  Guardrail:     skipped (--skip-install)")
        return

    click.echo("  Guardrail:     built into Go binary (no external dependencies)")
    logger.log_action("install-dep", "guardrail", "builtin")


def _ensure_uv() -> None:
    if shutil.which("uv"):
        return

    click.echo("  uv: not found, installing...", nl=False)
    try:
        subprocess.run(
            ["sh", "-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"],
            capture_output=True, check=True,
        )
        _add_uv_to_path()
        click.echo(" done")
    except (subprocess.CalledProcessError, FileNotFoundError):
        click.echo(" failed")
        click.echo("    install uv manually: curl -LsSf https://astral.sh/uv/install.sh | sh")
        click.echo("    then re-run: defenseclaw init")


def _add_uv_to_path() -> None:
    home = os.path.expanduser("~")
    for extra in [f"{home}/.local/bin", f"{home}/.cargo/bin"]:
        if extra not in os.environ.get("PATH", ""):
            os.environ["PATH"] = extra + ":" + os.environ.get("PATH", "")


def _install_with_uv(pkg: str) -> bool:
    uv = shutil.which("uv")
    if not uv:
        return False
    try:
        result = subprocess.run(
            [uv, "tool", "install", "--python", "3.13", pkg],
            capture_output=True, text=True,
        )
        if result.returncode == 0 or "already installed" in result.stderr:
            return True
        return False
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _install_codeguard_skill(cfg, logger) -> None:
    """Deprecated no-op: native CodeGuard assets are explicit opt-in only."""
    _ = cfg
    _ = logger
    click.echo("  CodeGuard:     skipped (explicit opt-in required)")


def _setup_guardrail_inline(app, cfg, logger) -> bool:
    """Run the full interactive guardrail setup during init.

    Returns True if guardrail was successfully configured.
    """
    from defenseclaw.commands.cmd_setup import (
        _interactive_guardrail_setup,
        execute_guardrail_setup,
    )
    from defenseclaw.context import AppContext

    if not isinstance(app, AppContext):
        app = AppContext()
    app.cfg = cfg
    app.logger = logger

    gc = cfg.guardrail
    _interactive_guardrail_setup(app, gc)

    if not gc.enabled:
        click.echo("  Guardrail not enabled.")
        click.echo("  You can enable it later with 'defenseclaw setup guardrail'.")
        return False

    ok, warnings = execute_guardrail_setup(app, save_config=False)

    if warnings:
        ux.banner("Warnings")
        for w in warnings:
            ux.warn(w, indent="  ")

    if ok:
        click.echo()
        click.echo(
            "  Guardrail:     "
            + ux._style("mode=", fg="bright_black")
            + ux._style(gc.mode, fg="green", bold=True)
            + ux._style(", model=", fg="bright_black")
            + ux.bold(gc.model_name)
        )
        click.echo("  To disable:    " + ux.accent("defenseclaw setup guardrail --disable"))
        logger.log_action(
            "init-guardrail", "config",
            f"mode={gc.mode} scanner_mode={gc.scanner_mode} port={gc.port} model={gc.model}",
        )

    return ok


def _start_gateway(cfg, logger) -> None:
    """Start the defenseclaw-gateway sidecar and verify it is running."""
    gw_bin = shutil.which("defenseclaw-gateway")
    if not gw_bin:
        click.echo("  Sidecar:       not found (binary not installed)")
        click.echo("                 install with: make gateway-install")
        return

    pid_file = os.path.join(cfg.data_dir, "gateway.pid")
    if _is_sidecar_running(pid_file):
        pid = _read_pid(pid_file)
        click.echo(f"  Sidecar:       already running (PID {pid})")
        return

    started = False
    click.echo("  Sidecar:       " + ux.dim("starting..."), nl=False)
    try:
        result = subprocess.run(
            ["defenseclaw-gateway", "start"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            click.echo(" " + ux._style("✓", fg="green", bold=True))
            pid = _read_pid(pid_file)
            if pid:
                click.echo(f"  PID:           {ux.bold(str(pid))}")
            logger.log_action("init-sidecar", "start", f"pid={pid or 'unknown'}")
            started = True
        else:
            click.echo(" " + ux._style("✗", fg="red", bold=True))
            err = (result.stderr or result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:3]:
                    click.echo(f"                 {ux.dim(line)}")
            click.echo("                 " + ux.dim("check: defenseclaw-gateway status"))
    except FileNotFoundError:
        click.echo(" " + ux._style("✗", fg="red", bold=True) + ux.dim(" (binary not found)"))
    except subprocess.TimeoutExpired:
        click.echo(" " + ux._style("✗", fg="red", bold=True) + ux.dim(" (timed out)"))
        click.echo("                 " + ux.dim("check: defenseclaw-gateway status"))

    if started:
        bind = "127.0.0.1"
        if cfg.openshell.is_standalone() and cfg.guardrail.host not in ("", "localhost"):
            bind = cfg.guardrail.host
        _check_sidecar_health(cfg.gateway.api_port, bind=bind)


def _get_gateway_version() -> str | None:
    """Try to get the gateway binary version."""
    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return None
    try:
        result = subprocess.run(
            [gw, "--version"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip().split()[-1] if result.stdout.strip() else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _restart_gateway_quiet() -> None:
    """Restart the gateway sidecar silently (used after guardrail setup during init)."""
    gw = shutil.which("defenseclaw-gateway")
    if not gw:
        return
    try:
        subprocess.run(
            [gw, "restart"], capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _is_sidecar_running(pid_file: str) -> bool:
    """Check if the gateway sidecar process is alive."""
    pid = _read_pid(pid_file)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _read_pid(pid_file: str) -> int | None:
    """Read PID from the sidecar's PID file."""
    try:
        with open(pid_file) as f:
            raw = f.read().strip()
        try:
            return int(raw)
        except ValueError:
            import json
            return json.loads(raw)["pid"]
    except (FileNotFoundError, ValueError, KeyError, OSError):
        return None


def _check_sidecar_health(api_port: int, retries: int = 3, bind: str = "127.0.0.1") -> dict | None:
    """Poll the sidecar REST API and return parsed health JSON (or None)."""
    import json as _json
    import time
    import urllib.error
    import urllib.request

    url = f"http://{bind}:{api_port}/health"
    for i in range(retries):
        time.sleep(1)
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="replace")
                    try:
                        health = _json.loads(body)
                    except (_json.JSONDecodeError, TypeError):
                        health = None
                    _print_health_summary(health)
                    return health
        except (urllib.error.URLError, OSError, ValueError):
            pass

    click.echo("  Health:        not responding")
    click.echo("                 check: defenseclaw-gateway status")
    return None


def _print_health_summary(health: dict | None) -> None:
    """Render a compact health summary from /health JSON."""
    if not health:
        click.echo("  Health:        ok ✓")
        return

    subsystems = ["gateway", "watcher", "guardrail", "api", "telemetry", "splunk", "sandbox"]
    parts = []
    for sub in subsystems:
        info = health.get(sub, {})
        if not info:
            continue
        state = info.get("state", info.get("status", "unknown"))
        if state.lower() in ("running", "healthy"):
            parts.append(f"{sub}:ok")
        elif state.lower() in ("disabled", "stopped"):
            parts.append(f"{sub}:off")
        else:
            parts.append(f"{sub}:{state}")

    if parts:
        click.echo(f"  Health:        {', '.join(parts)}")
    else:
        click.echo("  Health:        ok ✓")
