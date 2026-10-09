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

"""defenseclaw quickstart — zero-prompt first-run setup.

Designed for ``make all`` and ``install.sh --quickstart``. Picks safe
defaults (observe profile, local scanner, no judge) and runs every step
of the install flow without asking the user a single question. Power
users who want something different should use ``defenseclaw init`` or
``defenseclaw setup guardrail`` instead.
"""

from __future__ import annotations

import json
import os
import sys

import click

from defenseclaw import ux


@click.command("quickstart")
@click.option(
    "--mode",
    type=click.Choice(["observe", "action"], case_sensitive=False),
    default=None,
    help=(
        "Protection profile. observe logs findings; action blocks. "
        "Omit it to keep the connector's current mode (observe on a new install)."
    ),
)
@click.option(
    "--scanner",
    "scanner_mode",
    type=click.Choice(["local", "remote", "both"], case_sensitive=False),
    default="local",
    show_default=True,
    help="Scanner backend. 'local' is the zero-key default; 'remote'/'both' require CISCO_AI_DEFENSE_API_KEY.",
)
@click.option(
    "--with-judge/--no-judge",
    "with_judge",
    default=False,
    help="Enable the LLM Judge adjudicator (reuses the unified DEFENSECLAW_LLM_KEY).",
)
@click.option(
    "--fail-mode",
    type=click.Choice(["open", "closed"], case_sensitive=False),
    default=None,
    help=(
        "Hook fail-mode for delivery, authentication, and invalid gateway responses. "
        "'closed' (the default on a new install) blocks where the hook supports it, "
        "so the agent's tools are blocked while the gateway is down; 'open' allows + logs. "
        "Omit it to keep the current setting. "
        "DEFENSECLAW_STRICT_AVAILABILITY=1 additionally forces transport and "
        "missing-token failures closed. "
        "Change it later with `defenseclaw guardrail fail-mode open|closed`."
    ),
)
@click.option(
    "--human-approval/--no-human-approval",
    "human_approval",
    default=None,
    help=(
        "HITL: require operator approval before risky tool actions (action mode "
        "only — observe mode logs without blocking, regardless of this flag). "
        "Quickstart is non-interactive: omit the flag to keep whatever the "
        "current config has."
    ),
)
@click.option(
    "--hilt-min-severity",
    type=click.Choice(["HIGH", "MEDIUM", "LOW", "CRITICAL"], case_sensitive=False),
    default=None,
    help=(
        "Lowest finding severity that triggers a HITL approval prompt. Only "
        "meaningful when --human-approval is on. CRITICAL findings always "
        "block."
    ),
)
@click.option(
    "--force",
    is_flag=True,
    help="Re-run all steps even if the environment is already initialized.",
)
@click.option(
    "--connector",
    "--agent",
    "agent_name",
    type=click.Choice(
        [
            "openclaw",
            "zeptoclaw",
            "claudecode",
            "codex",
            "hermes",
            "cursor",
            "devin",
            "copilot",
            "openhands",
            "antigravity",
            "opencode",
            "amp",
            "omnigent",
            "kiro",
        ],
        case_sensitive=False,
    ),
    default=None,
    help="Agent framework connector (alias: --agent). "
    "Quickstart configures one connector: an explicit value wins, otherwise "
    "the single configured/detected connector is used. A picked_connector hint "
    "is used only when no configured/detected connector exists. Bare quickstart "
    "errors when the connector choice is ambiguous.",
)
@click.option(
    "--skip-gateway",
    is_flag=True,
    help="Do not start the sidecar at the end of quickstart.",
)
@click.option("--json-summary", "--json", "json_summary", is_flag=True, help="Emit the first-run summary as JSON.")
def quickstart_cmd(
    mode: str | None,
    scanner_mode: str,
    with_judge: bool,
    fail_mode: str | None,
    human_approval: bool | None,
    hilt_min_severity: str | None,
    force: bool,
    agent_name: str | None,
    skip_gateway: bool,
    json_summary: bool,
) -> None:
    """Zero-prompt end-to-end setup with safe defaults.

    Equivalent to running ``init`` → ``setup guardrail`` → ``gateway
    start`` but with a scripted, non-interactive UX. Missing API keys
    are listed at the end so the operator knows exactly what (if
    anything) to wire up before the guardrail becomes useful.
    """
    from defenseclaw import config as cfg_mod
    from defenseclaw import platform_support
    from defenseclaw.bootstrap import FirstRunOptions, run_first_run
    from defenseclaw.commands.cmd_init import _render_first_run_report, refuse_first_run_when_managed
    from defenseclaw.commands.cmd_setup import (
        _detect_installed_connectors,
        _read_picked_connector,
    )
    from defenseclaw.ux import CLIRenderer

    refuse_first_run_when_managed()
    connector_source: dict[str, str] = {}
    if agent_name:
        connector = agent_name
        _refuse_roster_narrowing(cfg_mod, connector, mode)
    else:
        data_dir = str(cfg_mod.default_data_path())
        picked_path = os.path.join(data_dir, "picked_connector")
        picked = _read_picked_connector(data_dir)
        detected = _detect_installed_connectors()
        configured = _configured_quickstart_connectors(cfg_mod)
        candidates = sorted({name for name in [*configured, *detected] if name})
        proxy = next((c for c in configured if c in _PROXY_CONNECTORS), "")
        if len(candidates) > 1 and proxy:
            # GAP-2466: no hook connector can join a guarded OpenClaw/ZeptoClaw
            # ('setup <c> --yes' and 'init' are refused), so offer only the
            # commands that work: reconfigure it or switch with --replace.
            label = _connector_label(proxy)
            ux.echo(
                "  \u2717 Multiple connectors detected/configured: "
                f"{_connector_labels(candidates)}.\n"
                f"    This install guards {label}, which is proxy-backed and cannot run next to hook connectors.\n"
                "    Quickstart configures one connector on a new install. No changes made.\n"
                f"    Reconfigure {label}: defenseclaw setup {proxy}\n"
                f"    Switch this install to a hook connector and remove {label}: "
                "defenseclaw setup <connector> --replace\n"
                "    See what is guarded now: defenseclaw status",
                err=True,
            )
            sys.exit(2)
        if len(candidates) > 1 and configured:
            # GAP-1352: on an install that already guards connectors,
            # 'quickstart --connector X' refuses (it would narrow the roster),
            # so point at the commands that keep the roster.
            ux.echo(
                "  ✗ Multiple connectors detected/configured: "
                f"{', '.join(candidates)}.\n"
                f"    This install already guards: {', '.join(dict.fromkeys(configured))}.\n"
                "    Quickstart configures one connector on a new install.\n"
                "    Add or reconfigure one and keep the rest: defenseclaw setup <connector> --yes\n"
                "    Change the whole set: defenseclaw init\n"
                "    See what is guarded now: defenseclaw status",
                err=True,
            )
            sys.exit(2)
        if len(candidates) > 1:
            ux.echo(
                "  ✗ Multiple connectors detected/configured: "
                f"{', '.join(candidates)}.\n"
                "    Quickstart configures one connector.\n"
                "    Re-run with --connector <name>, then add the others with\n"
                "    'defenseclaw setup <connector>'. To pick several at once,\n"
                "    run 'defenseclaw init' (the picker 'make all' uses).",
                err=True,
            )
            sys.exit(2)
        if len(candidates) == 1:
            connector = candidates[0]
            if picked and picked != connector:
                ux.echo(
                    "  ✗ Connector choice is ambiguous.\n"
                    f"    picked_connector says {picked}, but the active/detected connector is {connector}.\n"
                    "    Re-run with --connector <name>.",
                    err=True,
                )
                sys.exit(2)
        elif picked:
            connector = picked
            connector_source = {
                "type": "picked_connector",
                "connector": connector,
                "path": picked_path,
            }
        else:
            ux.echo(
                "  ✗ Could not detect an agent framework on this host.\n"
                "    Re-run with an explicit connector, e.g. "
                "`defenseclaw quickstart --connector hermes`.",
                err=True,
            )
            sys.exit(2)

    support = platform_support.connector_platform_support(connector)
    if not support.available:
        raise click.ClickException(
            f"connector {connector!r} is {support.status} on "
            f"{platform_support.host_os()}: {support.reason}"
        )

    # A repeat quickstart keeps the configured mode, and with it the fail mode
    # action implies, instead of silently dropping to observe (GAP-0979).
    kept_mode = "" if mode else _configured_quickstart_mode(cfg_mod, connector)
    profile = mode or kept_mode or "observe"
    if kept_mode and not json_summary:
        ux.echo(f"  Keeping {_connector_label(connector)} in {kept_mode} mode (pass --mode to change it).")

    # First-run doctor and Inventory must see the same fresh host scan that
    # selected the connector, including explicit --connector on macOS/Windows.
    from defenseclaw.inventory import agent_discovery

    # From here on only the chosen connector's CLI runs as a probe (GAP-0901).
    token = agent_discovery.restrict_probes([connector])
    click.get_current_context().call_on_close(lambda: agent_discovery.end_probe_restriction(token))

    if not (platform_support.host_os() == "windows" and connector == "opencode"):
        # Native Windows OpenCode uses a protected exact executable selection;
        # a generic discovery pass before that selection would override it.
        agent_discovery.discover_agents(
            use_cache=False, refresh=True, data_dir=str(cfg_mod.default_data_path())
        )

    report = run_first_run(
        FirstRunOptions(
            connector=connector,
            connector_settings=[{"connector": connector}],
            profile=profile,
            scanner_mode=scanner_mode,
            with_judge=with_judge,
            start_gateway=not skip_gateway,
            verify=True,
            force=force,
            # Empty string when --fail-mode is omitted means "leave the
            # existing cfg.guardrail.hook_fail_mode untouched". Quickstart
            # is non-interactive so we never prompt — operators flip this
            # via the flag or via `defenseclaw guardrail fail-mode`.
            hook_fail_mode=(fail_mode or "").lower(),
            # HITL: ``None`` preserves the current toggle, so a quickstart
            # rerun never silently disables HITL on an operator who set
            # it via ``defenseclaw setup guardrail`` last week.
            human_approval=human_approval,
            hilt_min_severity=hilt_min_severity or "",
        )
    )
    if skip_gateway:
        # GAP-2052: bootstrap words a skipped start with init's flag; name
        # the one quickstart has.
        for step in report.setup:
            if step.name == "Sidecar" and step.status == "skip":
                step.detail = "not started (--skip-gateway)"
    _require_operational_success(
        report,
        gateway_requested=not skip_gateway,
    )
    if json_summary:
        payload = report.to_dict()
        if connector_source:
            payload["connector_source"] = connector_source
        click.echo(json.dumps(payload, indent=2))
    else:
        if connector_source:
            click.echo(
                f"  Using picked connector hint: {connector} from {connector_source['path']}"
            )
        _render_first_run_report(report, CLIRenderer())
    if report.status == "needs_attention":
        sys.exit(1)


def _require_operational_success(report, *, gateway_requested: bool) -> None:
    """Make quickstart's requested operational outcomes command-fatal.

    Bootstrap warnings are normally advisory so interactive first-run flows
    can finish with remediation hints. Quickstart is an automation boundary:
    its selected connector must be established, and a requested gateway start
    must leave the sidecar running. Promote only those warnings before
    rendering so human output, JSON, and the process exit status agree.
    """
    from defenseclaw.bootstrap import _rollup_status

    if gateway_requested:
        settings_failure = any(
            step.name == "Sidecar"
            and step.status in {"warn", "fail"}
            and "settings.json" in step.detail
            for step in report.setup
        )
        if settings_failure:
            from defenseclaw.connector_paths import claude_config_dir

            settings_path = os.path.join(claude_config_dir(), "settings.json")
            for step in report.setup + report.readiness:
                if step.name == "Sidecar":
                    step.status = "fail"
                    step.detail = (
                        f"Claude Code settings file {settings_path} cannot be written. "
                        "Make it writable or ask your administrator, then rerun quickstart."
                    )
                    step.next_command = ""
        for step in report.setup + report.readiness:
            if step.name in {"Connector", "Connector runtime", "Sidecar"} and step.status == "warn":
                step.status = "fail"

    report.status = _rollup_status(report.setup, report.readiness)


def _refuse_roster_narrowing(cfg_mod, connector: str, mode: str | None = None) -> None:
    """Stop ``quickstart --connector X`` from silently dropping other connectors.

    First-run setup rebuilds the roster around the one connector it is
    given, so on an install that already guards other connectors quickstart
    would leave their hooks installed while the gateway stops enforcing them
    (GAP-1078). Refuse and point at the commands that keep (or deliberately
    change) the roster instead.
    """
    from defenseclaw import connector_paths

    wanted = connector_paths.normalize(connector)
    configured = list(dict.fromkeys(connector_paths.normalize(c) for c in _configured_quickstart_connectors(cfg_mod)))
    if not [c for c in configured if c and c != wanted]:
        return
    slug = "claude-code" if wanted == "claudecode" else wanted
    mode_flag = f" --mode {mode}" if mode else ""
    proxies = [c for c in configured if c in _PROXY_CONNECTORS]
    if proxies and wanted not in _PROXY_CONNECTORS:
        # GAP-2452: a hook connector would remove the guarded proxy
        # connector's plugin and leave it unguarded (as 'setup <c>', GAP-2426).
        # GAP-2466: display names, as the setup/init refusal.
        proxy_label = _connector_label(proxies[0])
        ux.echo(
            f"  \u2717 This install already guards: {_connector_labels(configured)}.\n"
            f"    {proxy_label} is proxy-backed and cannot run next to hook connectors, so quickstart\n"
            f"    would remove its DefenseClaw plugin and leave it unguarded. No changes made.\n"
            f"    Switch this install to {_connector_label(wanted)}: defenseclaw setup {slug} --replace{mode_flag}",
            err=True,
        )
        sys.exit(2)
    if wanted in _PROXY_CONNECTORS:
        # Proxy-backed connectors cannot run next to hook connectors, so
        # "keep the rest" is refused (GAP-1407); --replace switches (GAP-1455).
        others = [c for c in configured if c and c != wanted]
        if len(others) == 1:
            target = pronoun = _connector_label(others[0])
        else:
            target, pronoun = "these connectors", "them"
        lines = [
            f"  \u2717 This install already guards: {_connector_labels(configured)}.",
            f"    {_connector_label(wanted)} is proxy-backed and cannot run next to {target}. No changes made.",
            f"    Switch to it and remove {pronoun}: defenseclaw setup {slug} --replace{mode_flag}",
        ]
        guarded_proxy = next((c for c in others if c in _PROXY_CONNECTORS), "")
        if guarded_proxy:
            # GAP-2468: init does not switch a proxy install to the other
            # proxy connector, so offer to keep the guarded one instead.
            lines.append(f"    Keep guarding {_connector_label(guarded_proxy)}: defenseclaw setup {guarded_proxy}")
        else:
            lines.append("    Change the whole set instead: defenseclaw init")
        click.echo("\n".join(lines), err=True)
        sys.exit(2)
    ux.echo(
        f"  \u2717 This install already guards: {', '.join(configured)}.\n"
        "    Quickstart configures one connector and would stop guarding the others.\n"
        f"    Add or reconfigure {wanted} and keep the rest: defenseclaw setup {slug} --yes{mode_flag}\n"
        f"    Guard only {wanted} and remove the others: defenseclaw setup {slug} --replace{mode_flag}\n"
        "    Change the whole set: defenseclaw init",
        err=True,
    )
    sys.exit(2)


_PROXY_CONNECTORS = frozenset({"openclaw", "zeptoclaw"})


def _connector_label(name: str) -> str:
    """Display name of a connector (OpenClaw, Claude Code), as setup prints it."""
    from defenseclaw.commands.cmd_setup import _CONNECTOR_META

    return _CONNECTOR_META.get(name, {}).get("label", name)


def _connector_labels(names) -> str:
    return ", ".join(_connector_label(n) for n in names)


def _configured_quickstart_mode(cfg_mod, connector: str) -> str:
    """The mode *connector* already runs in, or "" when quickstart has not set it up yet."""
    from defenseclaw import connector_paths, policy_catalog

    wanted = connector_paths.normalize(connector)
    if wanted not in {connector_paths.normalize(c) for c in _configured_quickstart_connectors(cfg_mod)}:
        return ""
    try:
        return policy_catalog.mode_label(cfg_mod.load().guardrail.effective_mode(wanted))
    except Exception:  # noqa: BLE001 - an unreadable config falls back to the new-install default.
        return ""


def _configured_quickstart_connectors(cfg_mod) -> list[str]:
    """Return meaningful active connectors from an existing config, if any."""
    try:
        config_file = cfg_mod.config_path()
        if not os.path.exists(config_file):
            return []
        cfg_mod.require_v8_config()
        cfg = cfg_mod.load()
    except Exception:
        return []

    try:
        if getattr(cfg.guardrail, "connectors", None):
            return list(cfg.active_connectors())
        active = cfg.active_connector()
    except Exception:
        return []
    if active == "openclaw" and not (
        getattr(cfg.guardrail, "enabled", False) and (cfg.guardrail.connector or "").strip()
    ):
        # The implicit "openclaw" default, not a guarded OpenClaw (GAP-2452).
        return []
    return [active]
