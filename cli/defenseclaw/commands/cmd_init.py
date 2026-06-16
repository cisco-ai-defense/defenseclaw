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
from typing import TYPE_CHECKING

import click

from defenseclaw import connector_paths, platform_support, ux

if TYPE_CHECKING:
    from defenseclaw.bootstrap import StepResult
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.inventory import agent_discovery
from defenseclaw.paths import (
    bundled_guardrail_profiles_dir,
    bundled_local_observability_dir,
    bundled_rego_dir,
    bundled_splunk_bridge_dir,
)
from defenseclaw.safety import DotenvValueError, sanitize_dotenv_value


@click.command("init")
@click.option("--skip-install", is_flag=True, help="Skip automatic scanner dependency installation")
@click.option("--enable-guardrail", is_flag=True, help="Configure LLM guardrail during init")
@click.option("--sandbox", is_flag=True, help="Set up sandbox mode (Linux only: creates sandbox user and directories)")
@click.option("--non-interactive", is_flag=True, help="Run the guided first-run backend without prompts.")
@click.option("--yes", "-y", is_flag=True, help="Assume defaults/yes for first-run prompts.")
@click.option("--rescan-agents", is_flag=True, help="Refresh cached local agent discovery before choosing a connector.")
@click.option(
    "--connector",
    type=click.Choice(
        [
            "codex",
            "claudecode",
            "claude-code",
            "zeptoclaw",
            "openclaw",
            "hermes",
            "cursor",
            "windsurf",
            "geminicli",
            "copilot",
            "openhands",
            "antigravity",
            "opencode",
        ],
        case_sensitive=False,
    ),
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
    "--observe-all",
    is_flag=True,
    help=(
        "Configure every detected hook connector in observe (log-only) mode. "
        "Combine with --action-connectors to enforce on a subset. Works without "
        "a TTY for scripted setups."
    ),
)
@click.option(
    "--action-connectors",
    default="",
    help=(
        "Comma-separated connectors to configure in action (enforcing) mode. "
        "The named connectors are configured even on their own; pair with "
        "--observe-all to bring up everything else in observe."
    ),
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
    observe_all: bool,
    action_connectors: str,
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

    The guided wizard detects every installed hook connector, brings them all
    up in observe mode, and asks which subset should enforce (action mode).
    For scripted setups use --observe-all to configure all detected hook
    connectors in observe, and --action-connectors a,b to enforce on a subset
    (the two compose). With neither flag (nor --connector), init keeps the
    legacy single-connector default.

    Use --sandbox to set up openshell-sandbox standalone mode (Linux only).
    Use --enable-guardrail to configure the LLM guardrail inline.
    """
    import platform

    if _use_guided_first_run(
        non_interactive=non_interactive,
        yes=yes,
        connector=connector,
        profile=profile,
        observe_all=observe_all,
        action_connectors=action_connectors,
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
            observe_all=observe_all,
            action_connectors=action_connectors,
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
        cfg.data_dir,
        cfg.quarantine_dir,
        cfg.plugin_dir,
        cfg.policy_dir,
    ]

    data_dir_real = os.path.realpath(cfg.data_dir)
    # F-0122: these directories hold operator-private state — the audit
    # database, quarantined payloads, plugins and policies. Bare
    # ``os.makedirs`` honors the process umask, so under the common 022
    # umask the audit DB's parent is created world-readable (0755),
    # leaking audit state to other local users. Force 0700 on creation
    # *and* tighten any pre-existing directory so the perms are
    # deterministic regardless of umask.
    for d in dirs:
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)

    external_dirs = list(cfg.skill_dirs())
    for d in external_dirs:
        d_real = os.path.realpath(d)
        if d_real.startswith(data_dir_real + os.sep):
            os.makedirs(d, mode=0o700, exist_ok=True)
            os.chmod(d, 0o700)
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

    ux.banner("Notifications")
    _onboard_notifications(
        cfg,
        logger,
        non_interactive=non_interactive,
        yes=yes,
        is_new_config=is_new_config,
    )

    ux.banner("Notifications")
    _onboard_notifications(
        cfg,
        logger,
        non_interactive=non_interactive,
        yes=yes,
        is_new_config=is_new_config,
    )

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
                ctx.invoke(
                    setup_sandbox,
                    sandbox_ip="10.200.0.2",
                    host_ip="10.200.0.1",
                    sandbox_home=None,
                    openclaw_port=18789,
                    dns="8.8.8.8,1.1.1.1",
                    policy="default",
                    no_auto_pair=False,
                    disable=False,
                    non_interactive=True,
                )

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
        click.echo(f"    {ux.accent('defenseclaw setup guardrail')}   " + ux.dim("Enable LLM traffic inspection"))
    elif not guardrail_ok:
        click.echo(f"    {ux.accent('defenseclaw setup guardrail')}   " + ux.dim("Enable LLM traffic inspection"))
    if not sidecar_started and not sandbox:
        click.echo(f"    {ux.accent('defenseclaw-gateway start')}     " + ux.dim("Start the sidecar"))
    click.echo(f"    {ux.accent('defenseclaw setup')}            " + ux.dim("Customize scanners and policies"))
    click.echo(f"    {ux.accent('defenseclaw doctor')}           " + ux.dim("Verify connectivity and credentials"))
    click.echo(f"    {ux.accent('defenseclaw skill scan all')}   " + ux.dim("Scan installed agent skills"))
    click.echo(f"    {ux.accent('defenseclaw mcp scan --all')}   " + ux.dim("Scan configured MCP servers"))
    click.echo(f"    {ux.accent('defenseclaw setup <connector>')} " + ux.dim("Add another agent (codex, claudecode)"))

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
    # The multi-connector flags drive a non-interactive guided run: detect
    # everything and observe by default, with --action-connectors enforcing a
    # subset. Either flag is enough to opt into the guided backend.
    if kwargs.get("observe_all") or kwargs.get("action_connectors"):
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
    observe_all: bool,
    action_connectors: str,
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
    from defenseclaw.bootstrap import (
        FirstRunOptions,
        _next_commands,
        _rollup_status,
        run_first_run,
    )
    from defenseclaw.ux import CLIRenderer

    connector_settings: list[dict] | None = None
    # --observe-all / --action-connectors express an explicit, scripted
    # connector selection. Honor them deterministically even on a TTY instead
    # of dropping into the wizard (which would silently ignore the flags).
    flag_driven_multi = observe_all or bool(_parse_connector_list(action_connectors))
    if (
        not flag_driven_multi
        and not non_interactive
        and not yes
        and not json_summary
        and _stdin_is_tty()
    ):
        (
            connector_settings,
            scanner_mode,
            with_judge,
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

    # Non-interactive / no-TTY path. With --observe-all / --action-connectors
    # this fans out to every detected hook connector (observe by default, the
    # named subset enforcing). Without those flags it keeps the legacy
    # single-connector contract: one connector from --connector (or discovery)
    # in --profile. The interactive path above may also hand back several
    # connectors, each with its own profile/fail-mode/HITL.
    if not connector_settings:
        connector_settings = _build_noninteractive_connector_settings(
            connector=connector,
            profile=profile,
            observe_all=observe_all,
            action_connectors=action_connectors,
            fail_mode=fail_mode,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
            rescan_agents=rescan_agents,
        )
    if start_gateway is None:
        start_gateway = False
    if verify is None:
        verify = True

    primary = connector_settings[0]
    extras = connector_settings[1:]
    # When extra connectors will be merged in after the primary bootstrap,
    # defer the gateway start to a single reconcile at the end so its
    # set-difference setup wires hooks for EVERY connector in one pass
    # (instead of starting with only the primary in the map).
    defer_gateway = bool(extras) and bool(start_gateway)

    opts = FirstRunOptions(
        connector=primary["connector"],
        profile=primary["profile"] or "observe",
        scanner_mode=scanner_mode,
        with_judge=with_judge,
        skip_install=skip_install,
        sandbox=sandbox,
        start_gateway=(False if defer_gateway else start_gateway),
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
        hook_fail_mode=(primary["fail_mode"] or "").lower(),
        # HITL: ``None`` is "leave alone", ``True``/``False`` set
        # the toggle. Empty severity preserves the existing floor;
        # bootstrap normalizes case and falls back to ``HIGH`` on
        # invalid values.
        human_approval=primary["human_approval"],
        hilt_min_severity=primary["hilt_min_severity"] or "",
    )
    report = run_first_run(opts)

    activated = [primary["connector"]]
    if extras:
        activated, sidecar_step = _activate_additional_connectors(
            primary,
            extras,
            start_gateway=bool(start_gateway),
            quiet=json_summary,
        )
        # When the gateway start was deferred (multi-connector + start_gateway),
        # run_first_run recorded a stale "Sidecar not started (--no-start-gateway)"
        # Setup step. Replace it with the real outcome of the reconcile restart
        # so the rendered report (and --json-summary) reflect the running gateway
        # instead of contradicting it.
        if sidecar_step is not None:
            replaced = False
            merged: list = []
            for s in report.setup:
                if s.name == "Sidecar":
                    merged.append(sidecar_step)
                    replaced = True
                else:
                    merged.append(s)
            if not replaced:
                merged.append(sidecar_step)
            report.setup = merged
            report.status = _rollup_status(report.setup, report.readiness)
            # next_commands was derived from the stale skip step (which carried
            # "defenseclaw-gateway start"); recompute so the "Next" hints match
            # the now-started gateway. _next_commands only reads cfg.data_dir,
            # which the report already exposes.
            report.next_commands = _next_commands(
                report.setup, report.readiness, report, report.profile
            )

    if json_summary:
        payload = report.to_dict()
        if len(activated) > 1:
            payload["connectors"] = activated
        click.echo(json.dumps(payload, indent=2))
        return
    _render_first_run_report(report, CLIRenderer())
    if len(activated) > 1:
        click.echo()
        click.echo("  Configured connectors: " + ", ".join(activated))
    if report.status == "needs_attention":
        raise SystemExit(1)


def _parse_connector_list(raw: str | None) -> list[str]:
    """Parse a comma/space-separated connector string into an ordered,
    de-duplicated, normalized list. Empty/blank entries are dropped."""
    out: list[str] = []
    for part in (raw or "").replace(" ", ",").split(","):
        token = part.strip()
        if not token:
            continue
        norm = _normalize_connector_arg(token)
        if norm and norm not in out:
            out.append(norm)
    return out


def _installed_hook_connectors(disc) -> list[str]:
    """Installed connectors that can run as multi-connector hook peers.

    Used to pre-fill the first-run connector prompt so an operator with
    codex + claudecode + antigravity installed can bring all of them up in
    one pass. Proxy-backed connectors (e.g. openclaw) are excluded — they
    cannot be multi-connector peers."""
    from defenseclaw.commands.cmd_setup import _HOOK_ENFORCED_CONNECTORS

    order = getattr(agent_discovery, "DISCOVERY_PRECEDENCE", None) or sorted(disc.agents)
    names: list[str] = []
    for name in order:
        sig = disc.agents.get(name)
        if sig and sig.installed and name in _HOOK_ENFORCED_CONNECTORS and name not in names:
            names.append(name)
    return names


def _prompt_connector_selection(connector: str | None, rescan_agents: bool) -> list[str]:
    """Prompt for ONE OR MORE connectors to configure during first run.

    Returns an ordered, de-duplicated list (first = primary). A single name
    keeps the legacy single-connector setup; multiple names fan the
    wizard's per-connector questions out so several agents can be brought
    up in one pass. Defaults to every installed hook connector so the
    common "start everything I have" case is a single Enter."""
    if connector:
        names = _parse_connector_list(connector)
        if names:
            return names
    disc = agent_discovery.discover_agents(refresh=rescan_agents)
    table = agent_discovery.render_discovery_table(disc).rstrip()
    if table:
        click.echo(table)
        click.echo()
    _note_proxy_connectors(disc)
    installed = _installed_hook_connectors(disc)
    default = ",".join(installed) if installed else agent_discovery.first_installed(disc, "codex")
    if installed:
        ux.subhead(
            "Every detected connector is pre-selected — press Enter to configure them "
            "all in observe mode, or edit the list to drop some.",
        )
    else:
        ux.subhead(
            "Enter one connector, or a comma-separated list to set up several at once "
            "(e.g. codex,claudecode,antigravity).",
        )
    raw = click.prompt("  Connector(s)", default=default, show_default=True)
    names = _parse_connector_list(raw)
    if not names:
        names = [agent_discovery.first_installed(disc, "codex")]
    return names


def _note_proxy_connectors(disc) -> None:
    """Surface detected proxy connectors (openclaw, zeptoclaw) during selection.

    They drive the single LLM proxy port, so they can't join the observe-all
    multi-connector set and aren't pre-selected here. Point the operator at
    their dedicated setup so a detected proxy agent isn't silently skipped."""
    order = getattr(agent_discovery, "DISCOVERY_PRECEDENCE", None) or sorted(disc.agents)
    detected: list[str] = []
    for name in order:
        if not platform_support.is_proxy_connector(name):
            continue
        signal = disc.agents.get(name)
        if signal is not None and signal.installed:
            detected.append(name)
    if not detected:
        return
    ux.subhead(
        f"Detected proxy connector(s): {', '.join(detected)}. These run on the LLM "
        f"proxy and can't join the observe-all set — configure separately with "
        f"'defenseclaw setup {detected[0]}'.",
    )


def _prompt_action_connectors(connectors: list[str]) -> list[str]:
    """Ask which of the configured connectors should run in ACTION mode.

    Every connector defaults to observe (log-only). The operator names the
    subset to enforce; a blank answer keeps everything in observe. The reply
    is intersected with the configured list so a typo can't enable a connector
    that isn't being set up."""
    ux.section("Enforcement mode")
    ux.subhead(
        "All connectors start in observe (log-only). Name the ones that should "
        "ACTION (block/enforce); leave blank to keep everything in observe.",
    )
    ux.subhead("Configured: " + ", ".join(connectors))
    raw = click.prompt(
        "  " + ux.bold("Action-mode connector(s)"),
        default="",
        show_default=False,
    )
    requested = _parse_connector_list(raw)
    allowed = set(connectors)
    action: list[str] = []
    for name in requested:
        if name not in allowed:
            click.echo(
                f"  ⚠ {name}: not in the configured connector list; ignoring.",
                err=True,
            )
            continue
        if name not in action:
            action.append(name)
    return action


def _prompt_action_policy(
    *,
    fail_mode: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
) -> tuple[str | None, bool | None, str | None]:
    """Ask the action-mode policy knobs once, shared by every action connector.

    These (hook fail-mode + HITL) only matter when at least one connector
    enforces, so we ask them a single time after the action subset is known
    rather than per connector. Pre-supplied flags skip the matching prompt."""
    # Hook fail-mode: surface the choice so first-run operators don't have to
    # discover `defenseclaw guardrail fail-mode` later. Default is "open"
    # because silently bricking the agent on a transient gateway response
    # error is worse than leaking a single tool call.
    if fail_mode is None:
        ux.section("Hook fail-mode (response-layer failures)")
        ux.subhead(
            "What hooks do when the gateway returns 4xx, malformed JSON, or no action.",
        )
        ux.subhead(
            "Transport failures (gateway down / 5xx) ALWAYS allow unless DEFENSECLAW_STRICT_AVAILABILITY=1.",
        )
        fail_mode = click.prompt(
            "  " + ux.bold("Fail mode"),
            type=click.Choice(["open", "closed"], case_sensitive=False),
            default="open",
            show_choices=True,
        )
    # Human-In-the-Loop (HITL) only fires in action mode, so it is only asked
    # here (after at least one connector opted into action).
    if human_approval is None:
        ux.section("Human-In-the-Loop approvals (HITL)")
        ux.subhead(
            "Action mode can pause risky tool calls and ask you to approve them.",
        )
        ux.subhead(
            "CRITICAL findings always block — HITL covers the lower severities you want to review first.",
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
    return fail_mode, human_approval, hilt_min_severity


def _supported_action_connectors(
    candidates: list[str],
    *,
    data_dir: str | os.PathLike[str] | None,
) -> list[str]:
    """Filter *candidates* to those whose installed version maps to a known
    hook contract in action mode.

    Unverified connectors are dropped (the caller configures them in observe
    instead) with a warning, matching the gate the Go gateway applies at boot
    and that :func:`_activate_additional_connectors` applies to extras. Gating
    here means the primary connector is checked too, so first-run never writes
    a global action mode the gateway then refuses to enforce."""
    from defenseclaw.commands.cmd_setup import (
        _check_connector_version_supported_for_setup,
    )

    out: list[str] = []
    for name in candidates:
        key = connector_paths.normalize(name)
        if _check_connector_version_supported_for_setup(
            key, mode="action", emit=False, data_dir=data_dir
        ):
            out.append(key)
        else:
            click.echo(
                f"  ⚠ {key}: installed version is not verified against a known hook "
                "contract; configuring in observe mode. Set "
                "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing.",
                err=True,
            )
    return out


def _build_noninteractive_connector_settings(
    *,
    connector: str | None,
    profile: str | None,
    observe_all: bool,
    action_connectors: str,
    fail_mode: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    rescan_agents: bool,
) -> list[dict]:
    """Build the ``connector_settings`` list for non-interactive / no-TTY init.

    Default (no multi flags): legacy single-connector contract — one connector
    from ``--connector`` or discovery, in ``--profile`` (observe by default).

    ``--observe-all`` and/or ``--action-connectors`` switch to the
    multi-connector contract: every detected hook connector in observe, with
    the named ``--action-connectors`` enforced. The two flags are composable so
    scripts can declare exactly which agents observe and which act.
    """
    from defenseclaw.commands.cmd_setup import _HOOK_ENFORCED_CONNECTORS

    action_list = _parse_connector_list(action_connectors)

    def _single(connector_name: str | None, *, discover: bool) -> list[dict]:
        return [
            {
                "connector": _normalize_connector_arg(
                    connector_name,
                    discover_default=discover,
                    refresh_agents=rescan_agents,
                ),
                "profile": profile if profile is not None else "observe",
                "fail_mode": fail_mode,
                "human_approval": human_approval,
                "hilt_min_severity": hilt_min_severity,
            }
        ]

    # No multi flags: preserve the historical single-connector behavior
    # (explicit --connector, else discovery-backed default).
    if not observe_all and not action_list:
        return _single(connector, discover=connector is None)

    # An explicit --connector alongside the multi flags is ambiguous; the
    # single connector wins to avoid surprising scripted callers. Warn so the
    # operator knows --observe-all / --action-connectors were not applied.
    if connector:
        if observe_all or action_list:
            click.echo(
                f"  ⚠ --connector {connector} takes precedence; ignoring "
                "--observe-all/--action-connectors. Drop --connector to configure "
                "multiple connectors.",
                err=True,
            )
        return _single(connector, discover=False)

    disc = agent_discovery.discover_agents(refresh=rescan_agents)
    detected = _installed_hook_connectors(disc)

    configured: list[str] = []
    if observe_all:
        configured.extend(detected)
    for name in action_list:
        if name not in _HOOK_ENFORCED_CONNECTORS:
            click.echo(
                f"  ⚠ {name}: not a hook-enforced connector; skipping --action-connectors entry.",
                err=True,
            )
            continue
        if name not in detected:
            click.echo(
                f"  ⚠ {name}: not detected as installed; configuring anyway "
                "(use --rescan-agents to refresh discovery).",
                err=True,
            )
        if name not in configured:
            configured.append(name)

    # Nothing detected and nothing valid named → fall back to a single
    # discovery-backed connector so init still does something useful.
    if not configured:
        return _single(None, discover=True)

    action_set = set(
        _supported_action_connectors(
            [name for name in configured if name in action_list],
            data_dir=None,
        )
    )
    settings: list[dict] = []
    for name in configured:
        is_action = name in action_set
        settings.append(
            {
                "connector": name,
                "profile": "action" if is_action else "observe",
                "fail_mode": (fail_mode if is_action else None),
                "human_approval": (human_approval if is_action else None),
                "hilt_min_severity": (hilt_min_severity if is_action else None),
            }
        )
    return settings


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
) -> tuple[list[dict], str, bool, bool, bool]:
    ux.section("DefenseClaw First-Run Setup")
    ux.subhead(
        "This wizard writes config.yaml, then runs targeted readiness checks.",
    )
    click.echo()
    connectors = _prompt_connector_selection(connector, rescan_agents)

    # Scanner mode and the LLM judge are process-wide guardrail config
    # fields (not per-connector), so they are asked once regardless of how
    # many connectors are being configured.
    scanner_mode = click.prompt(
        "  " + ux.bold("Scanner mode"),
        type=click.Choice(["local", "remote", "both"], case_sensitive=False),
        default=scanner_mode or "local",
        show_choices=True,
    )
    with_judge = click.confirm("  " + ux.bold("Enable LLM judge now?"), default=with_judge)

    # Every connector defaults to observe. The operator names the subset to
    # enforce instead of choosing observe/action for each one. An explicit
    # `--profile` with a single explicit `--connector` keeps the legacy
    # single-connector intent without re-prompting.
    if connector and profile is not None and len(connectors) == 1:
        requested_action = list(connectors) if profile.lower() == "action" else []
    else:
        requested_action = _prompt_action_connectors(connectors)

    # Gate action connectors on hook-contract support; unverified ones are
    # downgraded to observe (still guarded, just non-blocking).
    action_set = set(_supported_action_connectors(requested_action, data_dir=None))

    # The action-only policy knobs (fail-mode + HITL) are asked once and
    # shared across every connector being enabled in action mode.
    shared_fail, shared_human, shared_sev = fail_mode, human_approval, hilt_min_severity
    if action_set:
        shared_fail, shared_human, shared_sev = _prompt_action_policy(
            fail_mode=fail_mode,
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity,
        )

    connector_settings: list[dict] = []
    for c in connectors:
        is_action = c in action_set
        connector_settings.append(
            {
                "connector": c,
                "profile": "action" if is_action else "observe",
                "fail_mode": (shared_fail if is_action else None),
                "human_approval": (shared_human if is_action else None),
                "hilt_min_severity": (shared_sev if is_action else None),
            }
        )

    start_gateway = click.confirm(
        "  " + ux.bold("Start gateway after setup?"),
        default=bool(start_gateway),
    )
    verify = click.confirm(
        "  " + ux.bold("Run targeted readiness checks?"),
        default=True if verify is None else bool(verify),
    )
    return connector_settings, scanner_mode, with_judge, start_gateway, verify


def _activate_additional_connectors(
    primary: dict,
    extras: list[dict],
    *,
    start_gateway: bool,
    quiet: bool = False,
) -> tuple[list[str], StepResult | None]:
    """Merge the extra first-run connectors into ``guardrail.connectors``.

    The primary connector was already bootstrapped via ``run_first_run``
    (scanners, device key, observability, its own global mode/fail/HITL).
    This folds each additional connector into the multi-connector map with
    its OWN per-connector overrides (mode / hook_fail_mode / HITL), seeds
    the primary into the map so ``active_connectors()`` lists them all, and
    keeps the singular ``guardrail.connector`` / ``claw.mode`` mirror at the
    sorted-first primary for backward-compatible readers. Hooks for every
    connector are installed by the gateway's set-difference reconcile on the
    single (re)start below.

    Returns ``(active_connectors, sidecar_step)`` where ``sidecar_step`` is the
    structured outcome of the deferred gateway (re)start (or ``None`` when the
    gateway was not started). Callers fold ``sidecar_step`` back into the
    first-run report so its Setup section reflects the real gateway state
    instead of the stale "not started" placeholder written while the start was
    deferred."""
    from defenseclaw import config as cfg_mod
    from defenseclaw.commands.cmd_setup import (
        _check_connector_version_supported_for_setup,
    )
    from defenseclaw.config import HILTConfig, PerConnectorGuardrailConfig

    primary_name = connector_paths.normalize(primary["connector"])
    try:
        cfg = cfg_mod.load()
    except Exception as exc:  # noqa: BLE001 — surface and fall back to primary-only.
        click.echo(f"  ✗ could not reload config to add connectors: {exc}", err=True)
        return [primary_name], None

    gc = cfg.guardrail
    if not getattr(gc, "connectors", None):
        gc.connectors = {}
    # Seed the primary so the multi map represents every active connector.
    # An empty override means it inherits the global mode/fail/HITL that
    # run_first_run already wrote for it.
    gc.connectors.setdefault(primary_name, PerConnectorGuardrailConfig())

    for s in extras:
        key = connector_paths.normalize(s["connector"])
        pc = gc.connectors.get(key) or PerConnectorGuardrailConfig()
        mode = (s["profile"] or "observe").lower()
        # Parity with single-connector setup: an extra connector may only be
        # configured in enforcing (action) mode when its installed version maps
        # to a known hook contract. Otherwise downgrade it to observe (still
        # guarded, just non-blocking) and tell the operator. The Go gateway
        # applies the same gate at boot (skipping unverified action connectors),
        # so without this the CLI would silently write an action-mode connector
        # the gateway then refuses to enforce.
        if mode == "action" and not _check_connector_version_supported_for_setup(
            key, mode="action", emit=False, data_dir=getattr(cfg, "data_dir", None)
        ):
            click.echo(
                f"  ⚠ {key}: installed version is not verified against a known "
                "hook contract; configuring in observe mode. Set "
                "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 only for exploratory testing.",
                err=True,
            )
            mode = "observe"
        pc.mode = "action" if mode == "action" else "observe"
        if s["fail_mode"]:
            pc.hook_fail_mode = "closed" if s["fail_mode"].lower() == "closed" else "open"
        if s["human_approval"] is not None:
            pc.hilt = HILTConfig(
                enabled=bool(s["human_approval"]),
                min_severity=(s["hilt_min_severity"] or "HIGH").upper(),
            )
        gc.connectors[key] = pc

    # Keep the singular mirror pointing at the sorted-first connector so
    # legacy single-connector readers (older Go binaries, single-connector
    # Python paths) keep working.
    primary_key = sorted(gc.connectors)[0]
    gc.connector = primary_key
    cfg.claw.mode = primary_key

    try:
        cfg.save()
    except OSError as exc:
        click.echo(f"  ✗ failed to save multi-connector config: {exc}", err=True)
        return [primary_key], None

    active = sorted(gc.connectors)
    # Keep stdout machine-clean under --json-summary: the human prose below
    # would otherwise prefix the JSON document and break parsers. The gateway
    # is still started when requested; only the narration is suppressed.
    if not quiet:
        click.echo("  ✓ Configured connectors: " + ", ".join(active))
    # Start (or restart) the gateway ONCE here so its set-difference reconcile
    # wires hooks for every connector in the map. The structured result is
    # returned (not echoed) so the caller can replace the stale "Sidecar not
    # started" placeholder in the deferred first-run report — otherwise the
    # report would contradict the gateway it just (re)started.
    sidecar_step = None
    if start_gateway:
        from defenseclaw.bootstrap import _start_gateway_structured

        sidecar_step = _start_gateway_structured(cfg)
    return active, sidecar_step


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
    renderer.echo("  Adding another agent later: defenseclaw setup <connector>")


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


_OBSERVABILITY_STACK_REFRESH_PATHS: tuple[str, ...] = ("bin", "run.sh")


def _seed_local_observability_stack(data_dir: str) -> None:
    """Copy bundled Prom/Loki/Tempo/Grafana stack into ~/.defenseclaw/observability-stack/.

    Mirrors _seed_splunk_bridge so ``defenseclaw setup
    local-observability`` can drive a user-editable copy of the stack
    (dashboards, alert rules, prom config) without requiring the
    operator to unpack the wheel.

    On a fresh data dir we copy the entire bundle. On a re-init, we
    *preserve* operator-editable config (dashboards, prom rules,
    compose overrides, OTel collector config) but *refresh* the
    maintainer-owned bridge entry points (``bin/`` and ``run.sh``) so
    bug fixes shipped in the wheel actually reach previously-seeded
    installs. Without this, a stale seeded bridge (e.g. one missing
    the bash 3.2 ``set -u`` empty-array guard on macOS) would keep
    crashing even after ``pip install --upgrade``.
    """
    bundled = bundled_local_observability_dir()
    if not bundled.is_dir():
        return

    dest = os.path.join(data_dir, "observability-stack")
    if not os.path.isdir(dest):
        shutil.copytree(str(bundled), dest)
        _ensure_observability_stack_executables(dest)
        click.echo(f"  Observability stack: seeded in {dest}")
        return

    refreshed = _refresh_observability_stack_scripts(bundled, dest)
    _ensure_observability_stack_executables(dest)
    if refreshed:
        joined = ", ".join(sorted(refreshed))
        click.echo(f"  Observability stack: preserved existing ({dest}); refreshed {joined}")
    else:
        click.echo(f"  Observability stack: preserved existing ({dest})")


def _refresh_observability_stack_scripts(bundled, dest: str) -> list[str]:
    """Overwrite maintainer-owned scripts in ``dest`` from ``bundled``.

    Only files under :data:`_OBSERVABILITY_STACK_REFRESH_PATHS` are
    refreshed — these are pure code (the ``openclaw-observability-bridge``
    bash entry point and its ``run.sh`` shim) and have no operator
    config baked in, so unconditional overwrite is safe.

    Returns the list of relative paths that were actually rewritten so
    the caller can surface a clear status line. Best-effort: missing
    sources are skipped silently and copy failures are surfaced as
    warnings rather than failing ``init`` outright.
    """
    refreshed: list[str] = []
    for rel in _OBSERVABILITY_STACK_REFRESH_PATHS:
        src = bundled / rel
        if not src.exists():
            continue
        target = os.path.join(dest, rel)
        try:
            if src.is_dir():
                if os.path.isdir(target):
                    shutil.rmtree(target)
                shutil.copytree(str(src), target)
            else:
                os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
                shutil.copy2(str(src), target)
        except OSError as exc:
            click.echo(
                f"  warning: could not refresh observability stack {rel}: {exc}",
                err=True,
            )
            continue
        refreshed.append(rel)
    return refreshed


def _ensure_observability_stack_executables(dest: str) -> None:
    """Make sure the bridge entry points are executable after a copy."""
    for rel in (
        os.path.join("bin", "openclaw-observability-bridge"),
        "run.sh",
    ):
        path = os.path.join(dest, rel)
        if os.path.isfile(path):
            try:
                os.chmod(path, 0o755)
            except OSError:
                pass


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
    pem_data = f"-----BEGIN ED25519 PRIVATE KEY-----\n{b64_seed}\n-----END ED25519 PRIVATE KEY-----\n"
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
    # SU-03: resolve the OpenClaw gateway only when openclaw is a genuinely
    # active connector. A hook-only install leaves guardrail.connector empty and
    # would otherwise phantom-default to "openclaw" here, inheriting OpenClaw's
    # gateway endpoint and (worse) its token. active_connectors() returns [] for
    # an unconfigured install and the real connector set otherwise, so the
    # phantom can never sneak in.
    if "openclaw" in cfg.active_connectors():
        return _resolve_openclaw_gateway(cfg.claw.config_file)

    return {
        "host": "127.0.0.1",
        "port": 18789,
        "token": "",
    }


def _validate_gateway_token(env_name: str, token: str) -> None:
    """Reject a gateway token that would corrupt the dotenv file.

    The token originates from connector-controlled state (openclaw.json) and
    is therefore untrusted. A value containing a newline, carriage return, or
    NUL would be parsed as a *second* KEY=VALUE assignment by the config
    loader, letting an attacker inject arbitrary environment entries (e.g.
    DEFENSECLAW_DISABLE_REDACTION=1). Fail clearly at the boundary where the
    token enters rather than relying solely on the writer's sanitization.
    """
    try:
        sanitize_dotenv_value(token, key=env_name)
    except DotenvValueError as exc:
        raise click.ClickException(
            f"Refusing to persist the gateway token: {exc}. "
            "The connector reported a token containing control characters; "
            "fix the gateway configuration (e.g. openclaw.json) and retry."
        ) from exc


def _setup_gateway_defaults(cfg, logger, is_new_config: bool = True) -> None:
    """Resolve gateway settings from the active connector and display them.

    Only applies connector values (host/port/token) when creating a new config.
    Existing configs preserve user-customized gateway settings.
    """
    # SU-03: display the real primary connector (active_connector()), and gate
    # the OpenClaw token-env on openclaw actually being active — never the
    # phantom default of an empty guardrail.connector.
    connector = cfg.active_connector()
    openclaw_active = "openclaw" in cfg.active_connectors()
    gw_info = _resolve_gateway_for_connector(cfg)
    token_configured = False
    if is_new_config:
        cfg.gateway.host = gw_info["host"]
        cfg.gateway.port = gw_info["port"]

    if openclaw_active and gw_info["token"]:
        from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

        # The OpenClaw gateway token is read from the connector-controlled
        # openclaw.json and is untrusted. Validate at this boundary — before
        # it reaches the dotenv writer — so a token carrying a newline/CR/NUL
        # (which would inject extra KEY=VALUE lines into ~/.defenseclaw/.env)
        # fails loudly with an operator-facing error instead of being relied
        # on the writer's defense-in-depth sanitization alone. F-0361.
        _validate_gateway_token("OPENCLAW_GATEWAY_TOKEN", gw_info["token"])
        _save_secret_to_dotenv("OPENCLAW_GATEWAY_TOKEN", gw_info["token"], cfg.data_dir)
        cfg.gateway.token = ""
        cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
        token_configured = True
    else:
        # Hook-only / non-openclaw install (or openclaw with no token):
        # default token_env to the canonical DEFENSECLAW_ name (the Go gateway
        # auto-generates it on first boot and writes ~/.defenseclaw/.env).
        # Preserve any operator-set value to respect explicit overrides from
        # `defenseclaw setup gateway`. `resolved_token()` still falls back to a
        # legacy OPENCLAW_GATEWAY_TOKEN already in .env, so upgraders keep
        # authenticating without manual remediation. (_resolve_gateway_for_
        # connector only ever returns a token for openclaw, so the prior
        # per-connector-name token branch was unreachable and is dropped.)
        cfg.gateway.token_env = cfg.gateway.token_env or "DEFENSECLAW_GATEWAY_TOKEN"
        token_configured = bool(cfg.gateway.resolved_token())

    if not cfg.gateway.device_key_file:
        cfg.gateway.device_key_file = os.path.join(cfg.data_dir, "device.key")

    _ensure_device_key(cfg.gateway.device_key_file)

    click.echo(f"  Gateway:       {cfg.gateway.host}:{cfg.gateway.port} (connector: {connector})")
    # Plan B2 / S0.2: the sidecar synthesizes a CSPRNG token on first
    # boot and persists it to ~/.defenseclaw/.env (mode 0600). The
    # "none" branch is now an instruction, not a security mode.
    token_status = "configured" if token_configured else "auto-generated on first boot (~/.defenseclaw/.env)"
    click.echo(f"  Token:         {token_status}")
    click.echo(f"  API port:      {cfg.gateway.api_port}")
    click.echo(f"  Watcher:       enabled={cfg.gateway.watcher.enabled}")
    click.echo(f"  AI discovery:  enabled={cfg.ai_discovery.enabled}, mode={cfg.ai_discovery.mode}")
    click.echo(
        f"  Skill watch:   enabled={cfg.gateway.watcher.skill.enabled}, "
        f"take_action={cfg.gateway.watcher.skill.take_action}"
    )
    plugin_dirs = cfg.gateway.watcher.plugin.dirs or cfg.plugin_dirs()
    click.echo(
        f"  Plugin watch:  enabled={cfg.gateway.watcher.plugin.enabled}, "
        f"take_action={cfg.gateway.watcher.plugin.take_action}"
    )
    click.echo(f"  Plugin dirs:   {', '.join(plugin_dirs)}")
    click.echo(f"  Device key:    {cfg.gateway.device_key_file}")
    click.echo()
    click.echo("  Run 'defenseclaw setup gateway' to customize.")

    logger.log_action("init-gateway", "config", f"host={cfg.gateway.host} port={cfg.gateway.port}")


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
            capture_output=True,
            check=True,
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
            capture_output=True,
            text=True,
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


def _onboard_notifications(
    cfg,
    logger,
    *,
    non_interactive: bool,
    yes: bool,
    is_new_config: bool,
) -> None:
    """Surface the desktop-notifications opt-in prompt on first run.

    Mirrors the single-question contract documented in the
    ``macos-block-and-hitl-notifications`` plan: a fresh install is
    asked once, the answer is persisted to
    ``notifications.enabled``, and subsequent ``defenseclaw init``
    invocations stay quiet (the operator can rerun
    ``defenseclaw setup notifications`` to flip it).

    Decision tree:
      * Existing config (``is_new_config=False``) → never prompt;
        print the current state for visibility. Re-running ``init``
        on a configured install must not re-litigate onboarding.
      * ``--non-interactive`` or ``--yes`` or non-TTY stdin (CI) →
        keep platform default, print a one-liner pointing at
        ``setup notifications``.
      * Otherwise → ``click.confirm`` with the platform-aware
        default.

    The ``cfg`` mutation is in-memory; the caller does the
    ``cfg.save()`` so this helper composes with whatever else
    ``init`` decides to write.
    """
    nc = cfg.notifications

    if not is_new_config:
        # Re-run of ``init`` against an existing config. We can't
        # safely tell "operator said no last time" from "operator
        # never saw the prompt" without a separate sentinel, and
        # re-prompting on every init would be irritating, so the
        # rule is: ask only at first-install. Operators flip the
        # toggle later via ``defenseclaw setup notifications``.
        state = "ON" if nc.enabled else "OFF"
        click.echo(f"  Notifications: {ux.dim('preserving current setting')} ({state})")
        click.echo("  " + ux.dim("Toggle later with: defenseclaw setup notifications"))
        return

    if non_interactive or yes or not _stdin_is_tty():
        state = "ON" if nc.enabled else "OFF"
        click.echo(f"  Notifications: {ux.dim('platform default')} ({state})")
        click.echo("  " + ux.dim("Toggle later with: defenseclaw setup notifications"))
        return

    desired = click.confirm(
        "  Show desktop notifications for blocks and approval requests?",
        default=bool(nc.enabled),
    )

    if desired == bool(nc.enabled):
        state = "ON" if desired else "OFF"
        click.echo("  Notifications: " + ux._style(state, fg="green") + ux.dim(" (unchanged)"))
        return

    nc.enabled = desired
    state = "ON" if desired else "OFF"
    click.echo("  Notifications: " + ux._style(state, fg="green"))
    click.echo("  " + ux.dim("Re-run: defenseclaw setup notifications"))
    logger.log_action(
        "init-notifications-toggle",
        "config",
        f"enabled={desired!s}",
    )


def _stdin_is_tty() -> bool:
    """Best-effort TTY probe used by the notifications onboarding.

    Wrapped so unit tests can monkey-patch a single point. ``init``
    already routes around interactive prompts when ``--non-interactive``
    or ``--yes`` is set, so this is the last-mile guard for piped /
    redirected stdin.
    """
    import sys

    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _onboard_notifications(
    cfg,
    logger,
    *,
    non_interactive: bool,
    yes: bool,
    is_new_config: bool,
) -> None:
    """Surface the desktop-notifications opt-in prompt on first run.

    Mirrors the single-question contract documented in the
    ``macos-block-and-hitl-notifications`` plan: a fresh install is
    asked once, the answer is persisted to
    ``notifications.enabled``, and subsequent ``defenseclaw init``
    invocations stay quiet (the operator can rerun
    ``defenseclaw setup notifications`` to flip it).

    Decision tree:
      * Existing config (``is_new_config=False``) → never prompt;
        print the current state for visibility. Re-running ``init``
        on a configured install must not re-litigate onboarding.
      * ``--non-interactive`` or ``--yes`` or non-TTY stdin (CI) →
        keep platform default, print a one-liner pointing at
        ``setup notifications``.
      * Otherwise → ``click.confirm`` with the platform-aware
        default.

    The ``cfg`` mutation is in-memory; the caller does the
    ``cfg.save()`` so this helper composes with whatever else
    ``init`` decides to write.
    """
    nc = cfg.notifications

    if not is_new_config:
        # Re-run of ``init`` against an existing config. We can't
        # safely tell "operator said no last time" from "operator
        # never saw the prompt" without a separate sentinel, and
        # re-prompting on every init would be irritating, so the
        # rule is: ask only at first-install. Operators flip the
        # toggle later via ``defenseclaw setup notifications``.
        state = "ON" if nc.enabled else "OFF"
        click.echo(f"  Notifications: {ux.dim('preserving current setting')} ({state})")
        click.echo("  " + ux.dim("Toggle later with: defenseclaw setup notifications"))
        return

    if non_interactive or yes or not _stdin_is_tty():
        state = "ON" if nc.enabled else "OFF"
        click.echo(f"  Notifications: {ux.dim('platform default')} ({state})")
        click.echo("  " + ux.dim("Toggle later with: defenseclaw setup notifications"))
        return

    desired = click.confirm(
        "  Show desktop notifications for blocks and approval requests?",
        default=bool(nc.enabled),
    )

    if desired == bool(nc.enabled):
        state = "ON" if desired else "OFF"
        click.echo("  Notifications: " + ux._style(state, fg="green") + ux.dim(" (unchanged)"))
        return

    nc.enabled = desired
    state = "ON" if desired else "OFF"
    click.echo("  Notifications: " + ux._style(state, fg="green"))
    click.echo("  " + ux.dim("Re-run: defenseclaw setup notifications"))
    logger.log_action(
        "init-notifications-toggle",
        "config",
        f"enabled={desired!s}",
    )


def _stdin_is_tty() -> bool:
    """Best-effort TTY probe used by the notifications onboarding.

    Wrapped so unit tests can monkey-patch a single point. ``init``
    already routes around interactive prompts when ``--non-interactive``
    or ``--yes`` is set, so this is the last-mile guard for piped /
    redirected stdin.
    """
    import sys

    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


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
            "init-guardrail",
            "config",
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
            capture_output=True,
            text=True,
            timeout=30,
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
            [gw, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
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
            [gw, "restart"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _is_sidecar_running(pid_file: str) -> bool:
    """Check if the gateway sidecar process is alive AND its
    process command line looks like the DefenseClaw gateway.

    Avarice F-2189: a stale or planted gateway.pid containing the
    PID of an unrelated live process used to convince the legacy
    init flow that the sidecar was already running. Generated
    hooks then forwarded uninspected traffic because their default
    fail mode is "open" until the gateway is up. We require both
    that the PID is alive AND that its argv0 is one of the known
    gateway binary names.
    """
    pid = _read_pid(pid_file)
    if pid is None or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    return _pid_looks_like_gateway(pid)


def _pid_looks_like_gateway(pid: int) -> bool:
    """Require the live process's argv0 basename to match a known
    DefenseClaw gateway binary name *exactly*.

    Delegates to the shared, fail-closed identity check in
    ``process_liveness`` (same as bootstrap). Avarice F-0121: the previous
    check accepted any basename starting with the generic ``defenseclaw``
    prefix, so a planted process such as ``defenseclaw-not-gateway`` was
    accepted as the live sidecar and init skipped starting the real one.
    """
    from defenseclaw.process_liveness import process_is_gateway

    return process_is_gateway(pid)


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
