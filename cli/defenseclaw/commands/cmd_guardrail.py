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

"""``defenseclaw guardrail`` — day-to-day guardrail policy controls.

Today operators have to use ``defenseclaw setup guardrail [--disable]``,
which interleaves "I want to flip the enabled bit" with "I want to
re-prompt for model / scanner-mode / Cisco endpoint / judge config".
That works for first-time setup but feels heavy for the very common
case of "the guardrail is acting up, give me a quick off switch".

This command surfaces the common policy levers directly:

  defenseclaw guardrail status         # enabled? roster of active connectors + their modes
  defenseclaw guardrail enable         # turn on + connector setup
  defenseclaw guardrail disable        # turn off + connector teardown
  defenseclaw guardrail mode           # observe (log only) vs action (enforce)
  defenseclaw guardrail block-at       # lowest severity the guardrail blocks at
  defenseclaw guardrail alert-at       # lowest severity the guardrail raises an alert at
  defenseclaw guardrail fail-mode      # open vs closed on hook failures
  defenseclaw guardrail hilt           # human-in-the-loop prompting
  defenseclaw guardrail block-message  # message shown when an action is blocked
  defenseclaw guardrail validate-pack  # strict offline rule-pack validation
  defenseclaw guardrail use-pack       # switch the rule pack, globally or per connector
  defenseclaw guardrail protection     # opt-in protection packs on/off per scope

All of these accept ``--connector X`` to scope the change to one
configured peer on a multi-connector install (one gateway enforces N
hook connectors). Without ``--connector`` the change applies globally
(legacy single-connector behaviour, unchanged). They resolve the active
connector(s) from ``Config.active_connector(s)()`` and delegate the
actual config-patch work to the Go sidecar's ``Connector.Setup`` /
``Connector.Teardown`` (running at sidecar boot when the relevant flag
flips). The Python side never has to know how Codex / Claude Code /
Antigravity / ZeptoClaw configure themselves.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys

import click

from defenseclaw import ux
from defenseclaw.config import _assert_config_write_allowed, config_path_for_data_dir
from defenseclaw.connector_contracts import normalize_connector
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.fail_mode import (
    _UPSTREAM_FAIL_OPEN_CONNECTORS,
    fail_mode_transaction_lock,
    reconcile_connector_registration,
    resolve_connector_fail_mode,
    restore_fail_mode_transaction,
    snapshot_fail_mode_transaction,
)

# Note: ``defenseclaw.commands.cmd_setup._restart_services`` is
# intentionally NOT imported at module load. Importing cmd_setup
# pulls in the heavy ``click`` command tree (every setup subcommand,
# every connector wizard) which we don't need when the operator runs
# ``defenseclaw guardrail status`` or any of the no-restart paths
# below. Each subcommand imports ``_restart_services`` lazily inside
# its ``if restart`` branch — keeps cmd_guardrail importable in
# trimmed-down environments and lets tests patch
# ``cmd_setup._restart_services`` (the canonical lookup target) once
# rather than per-subcommand.

_CONNECTOR_LABELS = {
    "openclaw": "OpenClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "zeptoclaw": "ZeptoClaw",
    "hermes": "Hermes",
    "cursor": "Cursor",
    "devin": "Devin",
    "copilot": "GitHub Copilot CLI",
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "amp": "Amp",
    "omnigent": "OmniGent",
    "kiro": "Kiro",
}

_RUNTIME_FAIL_MODE_CONNECTORS = frozenset({"amp", "claudecode", "codex", "opencode"})



def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _confirm_proceed() -> bool:
    """Ask the shared "  Proceed?" confirm (on stderr, so ``| tail`` shows it).

    When stdin is a terminal but stdout and stderr both go into a pipe
    (``guardrail fail-mode open 2>&1 | tail``), the prompt would sit in the
    pipe and the command looked hung (GAP-1432). Refuse instead and name
    --yes; scripts that answer on a piped stdin keep the prompt.
    """
    if _isatty(sys.stdin) and not _isatty(sys.stdout) and not _isatty(sys.stderr):
        ux.echo(
            "  ✗ This change needs your confirmation, but the output is piped, so the prompt "
            "would be hidden. Re-run it with --yes to apply it, or without the pipe.",
            err=True,
        )
        raise SystemExit(2)
    return click.confirm("  Proceed?", default=True, err=True)


def _preflight_config_write(app: AppContext) -> None:
    """Surface managed-mode write rejection before an interactive prompt."""
    cfg_path = str(config_path_for_data_dir(app.cfg.data_dir))
    try:
        _assert_config_write_allowed(cfg_path)
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise SystemExit(1) from exc


def _resolve_active_connector(cfg) -> str:
    """Return the active connector for ``cfg``, lowercased.

    Mirrors :meth:`Config.active_connector` but tolerates older
    in-process configs that haven't been migrated yet.
    """
    if cfg is None:
        return "openclaw"
    if hasattr(cfg, "active_connector") and callable(cfg.active_connector):
        try:
            name = (cfg.active_connector() or "").strip().lower()
            if name:
                return name
        except Exception:
            pass
    if hasattr(cfg, "guardrail") and hasattr(cfg.guardrail, "connector"):
        name = (cfg.guardrail.connector or "").strip().lower()
        if name:
            return name
    return "openclaw"


def _enabled_connectors_need_model(cfg, connector: str) -> bool:
    """Report whether re-enabling routes LLM traffic through the proxy."""
    from defenseclaw.platform_support import is_proxy_connector

    names: list[str] = []
    resolver = getattr(cfg, "active_connectors", None)
    if callable(resolver):
        try:
            names = list(resolver() or [])
        except Exception:
            names = []
    if not names:
        names = [connector]
    return any(is_proxy_connector(normalize_connector(name) or name) for name in names)


def _connector_label(name: str) -> str:
    return _CONNECTOR_LABELS.get(name, name)


def _active_connector_set(cfg, fallback: str) -> list[str]:
    """Return the full active-connector set (multi-connector aware).

    Falls back to ``[fallback]`` for older configs or single-connector
    installs so enable/disable messaging stays accurate either way.
    """
    if cfg is not None and hasattr(cfg, "active_connectors"):
        try:
            names = list(cfg.active_connectors())
            if names:
                return names
        except Exception:  # noqa: BLE001 — fall back to the primary connector.
            pass
    return [fallback]


def _active_connector_display(cfg, fallback: str) -> str:
    """Render the active-connector set as a ``Label (name)`` list.

    A global guardrail change (enable/disable without ``--connector``) affects
    EVERY active connector, so the messaging names them all; single-connector
    installs collapse to one ``Label (name)`` via the ``_active_connector_set``
    fallback. Keeps the user-facing scope honest on multi-connector installs.
    """
    return ", ".join(
        f"{_connector_label(n)} ({n})" for n in _active_connector_set(cfg, fallback)
    )


def _resolve_member_connector(app, requested: str) -> str | None:
    """Return the canonical ``guardrail.connectors`` key matching
    ``requested`` (case/alias-insensitive), or ``None`` if it is not a member."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    req = normalize_connector(requested)
    for key in conns:
        if normalize_connector(key) == req:
            return key
    return None


def _verify_agents_before_enable(app: AppContext, connectors: list[str]) -> None:
    """Re-verify the agent executables an enable is about to set up.

    Windows (and OpenHands on macOS) admit a connector only against a freshly
    verified agent executable. ``guardrail disable`` removes the connector's
    proof and the short-lived selection from the last setup has expired, so an
    enable that only restarted the gateway left it refusing the connector as
    "agent version not probed" (GAP-0069). A no-op on other hosts. Runs before
    the config is saved, so a failed check changes nothing.
    """
    from defenseclaw.commands import cmd_setup

    cmd_setup._record_windows_setup_agent_selections(app.cfg.data_dir, list(connectors))


def _toggle_connector_guardrail(
    app: AppContext, requested: str, *, enable: bool, restart: bool, yes: bool
) -> None:
    """Enable/disable the guardrail for a SINGLE connector.

    Per-connector analog of the global enable/disable: it flips
    ``guardrail.connectors[X].enabled`` and (on restart) lets the Go boot
    loop run that one connector's ``Setup``/``Teardown`` via the existing
    set-difference path — the others are untouched. The connector's other
    policy fields (mode/hilt/rule_pack_dir) are retained so re-enable
    restores it with no re-prompt.

    ``--connector`` is a multi-connector feature: on a single-connector
    install (no ``guardrail.connectors`` map) it points the operator at the
    global switch rather than silently creating a one-entry map.
    """
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    verb = "enable" if enable else "disable"

    if not conns:
        ux.err("--connector is only valid on multi-connector installs.", indent="  ")
        ux.subhead(
            f"This is a single-connector install; use 'defenseclaw guardrail {verb}' "
            "(no --connector).",
            indent="    ",
        )
        raise SystemExit(1)

    key = _resolve_member_connector(app, requested)
    if key is None:
        ux.err(f"Connector {requested!r} is not configured.", indent="  ")
        ux.subhead("Configured connectors: " + ", ".join(sorted(conns)), indent="    ")
        raise SystemExit(1)

    label = _connector_label(key.strip().lower())

    # No-op if already in the requested state.
    if app.cfg.guardrail.effective_enabled(key) == enable:
        state = "enabled" if enable else "disabled"
        click.echo(f"  {ux.dim(f'Connector {label} is already {state}.')}")
        return

    if not enable:
        _preflight_config_write(app)

    # Disabling the last remaining enabled connector is effectively a global
    # disable — warn so the operator can use the clearer command.
    if not enable:
        still_enabled = [
            k
            for k in conns
            if k != key and app.cfg.guardrail.effective_enabled(k)
        ]
        if not still_enabled:
            ux.subhead(
                f"{label} is the only enabled connector; disabling it leaves the "
                "gateway with nothing to enforce (equivalent to 'guardrail disable').",
                indent="  ",
            )

    click.echo()
    word = "Enabling" if enable else "Disabling"
    click.echo(f"  {ux.bold(f'{word} guardrail')} for {label} ({key}) only")
    action = "setup" if enable else "teardown"
    if restart and not _gateway_running(app):
        # GAP-1370: say plainly that a stopped gateway gets started.
        ux.subhead(
            f"The gateway is stopped; it will be started so the {label} connector {action} runs now.",
            indent="  ",
        )
    elif restart:
        ux.subhead(
            f"Will restart the gateway so the {label} connector {action} runs immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            f"--no-restart specified: flag persisted but the connector {action} won't "
            "run until you restart the gateway manually.",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    if enable and restart:
        _verify_agents_before_enable(app, [key])

    # Mutate the per-connector entry, preserving its other policy fields.
    from defenseclaw.config import PerConnectorGuardrailConfig

    entry = conns.get(key)
    if entry is None:
        entry = PerConnectorGuardrailConfig()
        conns[key] = entry
    entry.enabled = bool(enable)
    try:
        app.cfg.save()
        ux.ok(
            f"Config saved (guardrail.connectors.{key}.enabled = {str(enable).lower()})",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise SystemExit(1)

    if restart:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=key,
            teardown=not enable,
            # Report "setup complete" only once the gateway admitted the
            # connector (GAP-0069).
            wait_for_connector_ready=enable,
        )
        ux.ok(f"{label} connector {action} complete", indent="  ")
        click.echo()

    _log_guardrail_action(
        app,
        f"guardrail-{verb}",
        f"connector={key} scope=per-connector "
        f"enabled={str(enable).lower()} restart={restart}",
    )


@click.group("guardrail")
def guardrail() -> None:
    """Control guardrail policy: status, enable/disable, fail-mode, hilt, block-message.

    Quick day-to-day levers that wrap ``defenseclaw setup guardrail`` so
    operators don't have to navigate the full setup flow just to adjust
    posture. Subcommands:

    \b
      status         enabled state + roster (mode/fail/rule-pack/hilt/judge)
      enable/disable flip enforcement on/off
      mode           observe (log only) vs action (enforce)
      block-at       lowest severity prompts, completions and tool calls are blocked at
      alert-at       lowest severity prompts, completions and tool calls raise an alert at
      fail-mode      open vs closed when a hook fails
      hilt           human-in-the-loop prompting
      block-message  message shown when an action is blocked
      list-packs     list rule packs + the dir each connector enforces
      use-pack       switch the rule pack, globally or for one connector
      protection     turn opt-in protection packs on/off per scope
      validate-pack  validate one pack with the authoritative Go loader
      profile        identity-based guardrail profiles: list, show, explain

    \b
    Multi-connector: one gateway enforces N hook connectors. Each policy
    subcommand takes ``--connector X`` to scope the change to a single
    configured peer (e.g. 'guardrail disable --connector codex'); omit it
    to apply globally. 'guardrail --connector' scopes policy to a peer that
    'setup' has already configured — it does not add new connectors.
    """


#: Sentinel the Go judge gate (``JudgeConfig.HookConnectorEnabled``) reads
#: as "every hook connector". Mirrored locally so the status readout never
#: disagrees with what the gateway enforces.
_JUDGE_ALL_SENTINEL = "*"
_JUDGE_RUNNING_STRATEGIES = frozenset({"regex_judge", "judge_first"})


def _configured_hook_scan_strategies(gc) -> dict[str, str]:
    """Return configured hook-lane scan strategies by user-facing lane.

    Hook connectors expose prompt, tool-call, and tool-output surfaces. The
    Go config still calls tool output ``completion`` because it shares the
    proxy lane's output-shaped judge, but the status UI should speak in hook
    terms. Empty per-lane fields inherit the global strategy.
    """
    base = (getattr(gc, "detection_strategy", "") or "regex_judge").strip() or "regex_judge"
    prompt = (getattr(gc, "detection_strategy_prompt", "") or "").strip() or base
    completion = (getattr(gc, "detection_strategy_completion", "") or "").strip() or base
    tool_call = (getattr(gc, "detection_strategy_tool_call", "") or "").strip() or base
    return {
        "prompt": prompt,
        "tool-call": tool_call,
        "tool-output": completion,
    }


def _effective_hook_scan_strategies(gc, connector: str) -> dict[str, str]:
    """Return the scan strategies that actually apply to one hook connector."""
    judge_cfg = getattr(gc, "judge", None)
    judge_enabled = bool(getattr(judge_cfg, "enabled", False))
    judge_gate = list(getattr(judge_cfg, "hook_connectors", None) or [])
    judge_selected = _judge_gated(judge_gate, connector)
    effective: dict[str, str] = {}
    for lane, strategy in _configured_hook_scan_strategies(gc).items():
        normalized = (strategy or "").strip().lower() or "regex_judge"
        if judge_enabled and judge_selected and normalized in _JUDGE_RUNNING_STRATEGIES:
            effective[lane] = normalized
        else:
            effective[lane] = "regex_only"
    return effective


def _style_strategy(strategy: str) -> str:
    if strategy == "judge_first":
        return ux._style(strategy, fg="yellow", bold=True)
    if strategy == "regex_judge":
        return ux._style(strategy, fg="cyan", bold=True)
    return ux.dim(strategy)


def _scan_value(gc, connector: str) -> str:
    strategies = _effective_hook_scan_strategies(gc, connector)
    values = list(strategies.values())
    if values and all(v == values[0] for v in values):
        return values[0]
    return ", ".join(f"{lane}:{strategy}" for lane, strategy in strategies.items())


def _style_scan_value(value: str) -> str:
    if "," not in value and ":" not in value:
        return _style_strategy(value)
    parts: list[str] = []
    for part in value.split(", "):
        if ":" not in part:
            parts.append(part)
            continue
        lane, strategy = part.split(":", 1)
        parts.append(f"{lane}:{_style_strategy(strategy)}")
    return ", ".join(parts)


def _judge_gated(gate, name: str) -> bool:
    """True when the hook-lane judge gate covers ``name``.

    Mirrors the Go gate match (TrimSpace + EqualFold, ``*`` = every
    connector). Kept local rather than importing cmd_judge's private gate
    helpers so this command stays self-contained across lanes.
    """
    want = (name or "").strip().lower()
    for entry in gate or []:
        e = (entry or "").strip()
        if e == _JUDGE_ALL_SENTINEL or e.lower() == want:
            return True
    return False


def _connector_judge_value(gc, name: str) -> str:
    strategies = _effective_hook_scan_strategies(gc, name)
    if any(strategy in _JUDGE_RUNNING_STRATEGIES for strategy in strategies.values()):
        return "on"
    return "off"


def _style_judge_value(value: str) -> str:
    if value == "on":
        return ux._style(value, fg="green", bold=True)
    return ux.dim(value)


def _style_mode(mode: str) -> str:
    if mode == "action":
        return ux._style(mode, fg="green", bold=True)
    return ux._style(mode, fg="yellow") if mode == "observe" else mode


def _style_fail_mode(mode: str) -> str:
    if mode == "closed":
        return ux._style(mode, fg="yellow", bold=True)
    if mode == "open":
        return ux._style(mode, fg="green")
    return mode


def _visible_pad(styled: str, raw: str, width: int) -> str:
    return styled + (" " * max(width - len(raw), 0))


def _terminal_width() -> int:
    try:
        return shutil.get_terminal_size((120, 20)).columns
    except OSError:
        return 120


def _render_connector_table(rows: list[dict[str, tuple[str, str]]]) -> None:
    columns = [
        ("label", "Connector"),
        ("key", "Key"),
        ("state", "State"),
        ("mode", "Mode"),
        ("fail", "Fail"),
        ("rule_pack", "Rule pack"),
        ("levels", "Block/alert"),
        ("hilt", "HILT"),
        ("scan", "Scan"),
        ("judge", "Judge"),
    ]
    widths = {
        key: max(len(header), *(len(row[key][0]) for row in rows))
        for key, header in columns
    }
    gap = "  "
    table_width = 6 + sum(widths[key] for key, _ in columns) + len(gap) * (len(columns) - 1)
    if table_width > _terminal_width():
        _render_connector_blocks(rows)
        return

    header = gap.join(
        _visible_pad(ux._style(header, fg="bright_black", bold=True), header, widths[key])
        for key, header in columns
    )
    separator = gap.join(ux.dim("-" * widths[key]) for key, _ in columns)
    click.echo(f"      {header}")
    click.echo(f"      {separator}")
    for row in rows:
        click.echo(
            "      "
            + gap.join(
                _visible_pad(row[key][1], row[key][0], widths[key])
                for key, _ in columns
            )
        )


def _render_connector_blocks(rows: list[dict[str, tuple[str, str]]]) -> None:
    fields = [
        ("key", "key"),
        ("state", "state"),
        ("mode", "mode"),
        ("fail", "fail"),
        ("rule_pack", "rule-pack"),
        ("levels", "block/alert"),
        ("hilt", "hilt"),
        ("scan", "scan"),
        ("judge", "judge"),
    ]
    label_width = max(len(label) for _, label in fields)
    for row in rows:
        click.echo(f"      - {row['label'][1]}")
        for key, label in fields:
            label_raw = label + ":"
            label_styled = ux._style(label_raw, fg="bright_black", bold=True)
            click.echo(
                f"          {_visible_pad(label_styled, label_raw, label_width + 1)} "
                f"{row[key][1]}"
            )


def _echo_status_json(
    gc, rows: list[dict[str, tuple[str, str]]], warnings: list[str], profile: dict | None = None
) -> None:
    """Machine-readable ``guardrail status``: the same fields as the table."""
    import json  # noqa: PLC0415

    keys = ("state", "mode", "fail", "rule_pack", "levels", "hilt", "scan", "judge")
    connectors = []
    for row in rows:
        item = {"connector": row["key"][0], "label": row["label"][0]}
        item.update({("fail_mode" if key == "fail" else key): row[key][0] for key in keys})
        connectors.append(item)
    payload = {"enabled": bool(gc.enabled), "port": gc.port, "connectors": connectors, "warnings": warnings}
    if profile is not None:
        payload["profile"] = profile
    click.echo(json.dumps(payload, indent=2, sort_keys=True))


def profile_status_text(cfg, result: dict) -> str:
    """One line naming the guardrail profile that decides for this account.

    *result* comes from ``current_user_guardrail_profile``. Status, guardrail
    status and doctor show it, because the per-connector settings they list
    are ``guardrail.*``, which a matching profile replaces (GAP-0056). A
    connector or agent another assignment picks is named too (GAP-0075).
    """
    from defenseclaw import policy_catalog

    user = str(result.get("user") or "this account")
    if result.get("error"):
        count = len(getattr(cfg.guardrail, "profiles", {}) or {})
        if result.get("timed_out"):
            return (
                f"unknown for {user}: the gateway is running but did not answer in time; "
                f"the directory lookup may be slow ({count} profile(s) configured)"
            )
        return f"unknown for {user}: the gateway did not answer ({count} profile(s) configured)"
    name = str(result.get("profile") or "")
    if not name:
        text = f"none for {user} (guardrail.* applies)"
    else:
        effective = result.get("effective") or {}
        # config_version 9 names the pack (rule_pack); a v8 gateway sends its dir.
        pack = str(effective.get("rule_pack") or "").strip()
        pack_dir = str(effective.get("rule_pack_dir") or "")
        if not pack:
            pack = policy_catalog.pack_name_for_path(cfg, pack_dir)[0] if pack_dir.strip() else "default"
        reason = str(result.get("match") or "")
        if result.get("matched_group"):
            reason += f" {result['matched_group']}"
        text = f"{name} for {user} (by {reason}): mode {effective.get('mode') or 'observe'}, rule pack {pack}"
    scoped = []
    for item in result.get("overrides") or []:
        subject = " ".join(
            part
            for part in (_connector_label(item.get("connector") or ""), item.get("agent") and f"agent {item['agent']}")
            if part
        )
        scoped.append(f"{item.get('profile')} for {subject} (by {item.get('match')})")
    if scoped:
        text += "; except " + ", ".join(scoped)
    return text


@guardrail.command("status")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the roster to a single active connector (multi-connector installs). "
    "Omit to show every active connector.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the status as JSON.")
@pass_ctx
def status_cmd(app: AppContext, connector_flag: str | None, as_json: bool = False) -> None:
    """Show whether the guardrail is enabled and how each active connector is set.

    One block per active connector: enabled state, mode (observe or action),
    fail mode, rule pack, block/alert levels, human approval (HILT), hook scan
    strategy and judge. --connector NAME shows just that connector. With no
    connector set up, status says so and names the setup command.
    """
    from defenseclaw import policy_catalog

    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)
    fail_mode = (getattr(gc, "hook_fail_mode", "") or "open").lower()
    if not as_json:
        ux.section("Guardrail status", indent="  ")
        enabled_txt = "yes" if gc.enabled else "no"
        enabled_val = ux._style(enabled_txt, fg="green") if gc.enabled else ux._style(enabled_txt, fg="yellow")
        ux.echo(f"  • {ux._style('enabled:', fg='bright_black', bold=True)}    {enabled_val}")

    # Resolve the full active set and render exactly one coherent view: a
    # per-connector block for EACH active connector. active_connectors()
    # returns [connector] on a single-connector install and the full set on
    # a fan-out install, so the same loop drives both — no len()-based
    # branching, no singular "connector / mode / fail-mode" lines that would
    # imply one connector's posture is THE posture.
    try:
        actives = (
            list(app.cfg.active_connectors())
            if hasattr(app.cfg, "active_connectors")
            else [connector]
        )
    except Exception:  # noqa: BLE001 — fall back to the primary connector.
        actives = [connector]

    # G5 (phantom openclaw): when nothing is configured, active_connectors()
    # returns [] — render an explicit empty state instead of flooring to
    # ["openclaw"], which would imply a phantom connector is enforcing. The
    # config root (active_connectors→[] + has_connector_configured) is already
    # fixed; this is the command-layer consumer that must not re-introduce the
    # floor.
    configured = (
        app.cfg.has_connector_configured()
        if hasattr(app.cfg, "has_connector_configured")
        else True
    )
    if not actives and not configured:
        if as_json:
            _echo_status_json(gc, [], [])
            return
        ux.echo(
            f"  • {ux._style('connectors:', fg='bright_black', bold=True)} "
            f"{ux.dim('(none configured)')}"
        )
        ux.subhead(
            "No connector configured — run 'defenseclaw setup <connector>' to "
            "enable enforcement.",
            indent="    ",
        )
        click.echo()
        return
    if not actives:
        # Older config without active_connectors() but a connector IS set
        # (has_connector_configured true) — keep the legacy single-connector
        # floor so those installs still render their one block.
        actives = [connector]
    # Only proxy connectors (openclaw, zeptoclaw) use guardrail.port; hook
    # connectors have no proxy listener (GAP-1649).
    from defenseclaw.platform_support import PROXY_CONNECTORS

    proxy_in_use = any(normalize_connector(n) in PROXY_CONNECTORS for n in actives)

    # G3: optional --connector scoping. Default shows the full roster (uniform
    # layout, unchanged); --connector X narrows it to one active peer, matched
    # case-insensitively against the active set (mirrors the sibling commands).
    if connector_flag:
        want = connector_flag.strip().lower()
        scoped = [n for n in actives if n.strip().lower() == want]
        if not scoped:
            ux.err(f"Connector {connector_flag!r} is not active.", indent="  ")
            ux.subhead("Active connectors: " + ", ".join(actives), indent="    ")
            raise SystemExit(1)
        actives = scoped

    rows: list[dict[str, tuple[str, str]]] = []
    any_disabled = False
    runtime_drift_rows: list[str] = []
    runtime_limit_rows: list[str] = []
    for name in actives:
        cmode = gc.effective_mode(name) if hasattr(gc, "effective_mode") else (gc.mode or "observe")
        configured_cfm = gc.effective_hook_fail_mode(name) if hasattr(gc, "effective_hook_fail_mode") else fail_mode
        cfm = configured_cfm
        fail_drift = ""
        if normalize_connector(name) in _RUNTIME_FAIL_MODE_CONNECTORS:
            runtime_state = resolve_connector_fail_mode(app.cfg, name)
            if runtime_state.runtime is not None:
                cfm = runtime_state.runtime
            else:
                cfm = "unknown"
            # A connector disabled on purpose had its hooks removed, so the
            # missing hooks are not drift (GAP-1648).
            enforcing = gc.enabled and (gc.effective_enabled(name) if hasattr(gc, "effective_enabled") else True)
            if runtime_state.drift and enforcing:
                fail_drift = f" (desired {runtime_state.desired}; drift: " + ", ".join(runtime_state.drift) + ")"
                runtime_drift_rows.append(f"{_connector_label(name)} ({name}){fail_drift}")
        elif normalize_connector(name) in _UPSTREAM_FAIL_OPEN_CONNECTORS:
            # Copilot CLI, Antigravity and Hermes fail open upstream whatever
            # is configured; `defenseclaw status` reports the same.
            cfm = "open"
            runtime_limit_rows.append(
                f"{_connector_label(name)} ({name}) is upstream-enforced fail-open"
                f" (configured provenance: {configured_cfm})"
            )
        elif _cursor_stays_fail_closed(gc, name):
            # Cursor hooks always fail closed in action mode, whatever is
            # saved; show that, like `guardrail fail-mode` (GAP-1717).
            cfm = "closed"
        # Per-connector on/off: a connector turned off via
        # `guardrail disable --connector X` is reported as disabled so the
        # roster never implies it is enforcing when its hooks have been torn
        # down.
        c_enabled = (
            gc.effective_enabled(name)
            if hasattr(gc, "effective_enabled")
            else True
        )
        # A connector only enforces when the GLOBAL guardrail is on AND it
        # has not been individually disabled. Folding the global kill switch
        # in here stops the roster from rendering a green "enabled" connector
        # while the top-level line (and the gateway, which tears every
        # connector down when guardrail.enabled is false) report it off.
        if not gc.enabled:
            state_raw = "disabled (guardrail off)"
            state = ux._style(state_raw, fg="yellow")
        elif c_enabled:
            state_raw = "enabled"
            state = ux._style(state_raw, fg="green")
        else:
            state_raw = "disabled"
            state = ux._style(state_raw, fg="yellow")
        fail_raw = cfm
        cfm_display = _style_fail_mode(cfm)
        if not (gc.enabled and c_enabled) and not as_json:
            # A disabled connector has no hooks and so no fail mode; match
            # `guardrail fail-mode`, which shows "disabled (no hooks)" (GAP-1953).
            fail_raw = "-"
            cfm_display = ux.dim(fail_raw)
            any_disabled = True
        # Each connector can scan against its OWN rule pack (per-connector
        # override, else the global pack); surface it so the roster shows which
        # policy each peer is enforcing. Empty dir = the built-in default pack.
        rp_dir = (
            gc.effective_rule_pack_dir(name)
            if hasattr(gc, "effective_rule_pack_dir")
            else ""
        )
        # A composed protection pack (protected-<scope>/<profile>) is named
        # after its scope folder, not its profile folder.
        rule_pack_raw = policy_catalog.pack_name_for_path(app.cfg, rp_dir)[0] if rp_dir.strip() else "default"
        rule_pack = ux.accent(rule_pack_raw) if rule_pack_raw != "default" else ux.dim(rule_pack_raw)
        # Per-connector HILT (human-in-the-loop): on@<min-severity> or off, so
        # the roster reflects `guardrail hilt --connector X` overrides.
        hilt_eff = gc.effective_hilt(name) if hasattr(gc, "effective_hilt") else None
        if hilt_eff is not None and getattr(hilt_eff, "enabled", False):
            hilt_raw = f"on@{(getattr(hilt_eff, 'min_severity', '') or 'HIGH').upper()}"
            hilt_str = (
                ux._style(hilt_raw, fg="yellow", bold=True)
            )
        else:
            hilt_raw = "off"
            hilt_str = ux.dim(hilt_raw)
        scan_raw = _scan_value(gc, name)
        judge_raw = _connector_judge_value(gc, name)
        # Tool-call block / alert levels (guardrail.block_at / alert_at, else
        # the rule pack's), highlighted when a setting replaces the pack's.
        levels = policy_catalog.scope_levels(app.cfg, name)
        levels_raw = f"{levels.block_at}/{levels.alert_at}"
        levels_str = ux.dim(levels_raw) if levels.source == "pack" else ux.accent(levels_raw)
        rows.append(
            {
                "label": (_connector_label(name), _connector_label(name)),
                "key": (name, ux.dim(name)),
                "state": (state_raw, state),
                "mode": (cmode or "observe", _style_mode(cmode or "observe")),
                "fail": (fail_raw, cfm_display),
                "rule_pack": (rule_pack_raw, rule_pack),
                "levels": (levels_raw, levels_str),
                "hilt": (hilt_raw, hilt_str),
                "scan": (scan_raw, _style_scan_value(scan_raw)),
                "judge": (judge_raw, _style_judge_value(judge_raw)),
            }
        )
    from defenseclaw.gateway import current_user_guardrail_profile

    profile = current_user_guardrail_profile(app.cfg)
    if as_json:
        _echo_status_json(gc, rows, runtime_drift_rows + runtime_limit_rows, profile)
        return
    _render_connector_table(rows)
    for drift_row in runtime_drift_rows:
        ux.warn("runtime fail-mode drift: " + drift_row, indent="  ")
    for limit_row in runtime_limit_rows:
        ux.warn("connector limitation: " + limit_row, indent="  ")
    if profile is not None:
        ux.echo(f"  • {ux._style('profile:', fg='bright_black', bold=True)}    {profile_status_text(app.cfg, profile)}")
        for note in profile.get("warnings") or []:
            ux.warn(str(note), indent="    ")
        if (profile.get("directory") or {}).get("message"):
            ux.warn(str(profile["directory"]["message"]), indent="    ")
        if profile.get("profile") or profile.get("overrides"):
            ux.subhead(
                "The table shows guardrail.*; the profile settings above decide for you. "
                "Details: defenseclaw guardrail profile explain [--connector NAME] [--agent ID]",
                indent="    ",
            )
    ux.echo(f"  • {ux.dim('fail = invalid, unauthorized, incomplete, or unreachable gateway responses')}")
    if any_disabled:
        ux.echo(f"  • {ux.dim('fail - = disabled connector (no hooks, so no fail mode)')}")

    if proxy_in_use:
        ux.echo(f"  • {ux._style('port:', fg='bright_black', bold=True)}       {gc.port}")
    click.echo()
    if gc.enabled:
        click.echo(f"  {ux.dim('Disable with:')}  defenseclaw guardrail disable")
    else:
        click.echo(f"  {ux.dim('Enable with:')}   defenseclaw guardrail enable")
    click.echo()


@guardrail.command("disable")
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway after disabling (default: on; needed to run connector teardown).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the disable to a single connector (multi-connector installs only). "
    "Omit to disable the whole guardrail.",
)
@pass_ctx
def disable_cmd(
    app: AppContext, restart: bool, yes: bool, connector_flag: str | None
) -> None:
    """Disable the LLM guardrail and run connector teardown.

    Without ``--connector`` this is the global kill switch: it sets
    ``guardrail.enabled = false`` in ~/.defenseclaw/config.yaml and (when
    --restart is on, the default) restarts the gateway so the sidecar boot
    path runs ``Connector.Teardown`` for EVERY active connector.

    With ``--connector X`` it scopes the disable to one connector: the boot
    loop drops X from the active set so only X's hooks/config are torn down
    (the others keep running). X's policy is retained so a later
    ``guardrail enable --connector X`` restores it with no re-prompt.
    """
    if connector_flag:
        _toggle_connector_guardrail(
            app, connector_flag, enable=False, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)

    if not gc.enabled:
        click.echo(f"  {ux.dim('Guardrail is already disabled')} ({_active_connector_display(app.cfg, connector)}).")
        return

    _preflight_config_write(app)

    # A connector disabled on its own (`guardrail disable --connector X`) was
    # already torn down; name only the connectors this teardown reaches, as
    # `guardrail enable` does (GAP-1985, the twin of GAP-1809).
    _actives = _active_connector_set(app.cfg, connector)
    _already_off = [name for name in _actives if _disabled_on_its_own(gc, name)]
    _torn_down = [name for name in _actives if name not in _already_off]

    click.echo()
    if len(_actives) > 1 or _already_off:
        if _torn_down:
            _targets = ", ".join(f"{_connector_label(n)} ({n})" for n in _torn_down)
        else:
            _targets = "no connectors (every active connector is already disabled on its own)"
        click.echo(f"  {ux.bold('Disabling guardrail')} for {_targets}")
        for name in _already_off:
            ux.subhead(f"{_connector_label(name)} ({name}) is already disabled on its own.", indent="  ")
    else:
        click.echo(f"  {ux.bold('Disabling guardrail')} for {_active_connector_display(app.cfg, connector)}")
    if restart and not _gateway_running(app):
        # GAP-1370: say plainly that a stopped gateway gets started.
        ux.subhead(
            "The gateway is stopped; it will be started so the connector teardown runs now.",
            indent="  ",
        )
    elif restart:
        ux.subhead(
            "Will restart the gateway so the connector teardown runs immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: gateway will continue running with the old policy "
            "until you restart it manually ('defenseclaw-gateway restart').",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    gc.enabled = False
    try:
        app.cfg.save()
        ux.ok("Config saved (guardrail.enabled = false)", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        ux.subhead("Re-run after fixing the underlying I/O error.", indent="    ")
        raise SystemExit(1)

    if restart:
        # Lazy import: see module-level note. We import the cmd_setup
        # MODULE rather than the function so test patches that target
        # ``defenseclaw.commands.cmd_setup._restart_services`` (the
        # canonical lookup target) intercept the call. ``from
        # cmd_setup import _restart_services`` would bind a local
        # name at lazy-import time which still picks up an active
        # patch, but going through ``cmd_setup._restart_services()``
        # is the more obviously-correct form for readers.
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
            connectors=_actives,
            summary_exclude=frozenset(_already_off),
            teardown=True,
        )
        # In a multi-connector install the gateway boot loop tears down
        # every active connector on restart, so report them all rather
        # than implying only the primary was affected; one already disabled
        # on its own was torn down before (GAP-1985).
        if len(_actives) > 1 or _already_off:
            ux.ok(
                f"connector teardown complete for {len(_torn_down)} connector"
                f"{'' if len(_torn_down) == 1 else 's'}: " + (", ".join(_torn_down) or "none"),
                indent="  ",
            )
        else:
            ux.ok(f"{_connector_label(connector)} connector teardown complete", indent="  ")
        click.echo()

    _log_guardrail_action(
        app,
        "guardrail-disable",
        f"connector={connector} restart={restart}",
    )


@guardrail.command("enable")
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway after enabling (default: on; needed to run connector setup).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the enable to a single connector (multi-connector installs only). "
    "Omit to enable the whole guardrail.",
)
@pass_ctx
def enable_cmd(
    app: AppContext, restart: bool, yes: bool, connector_flag: str | None
) -> None:
    """Re-enable the LLM guardrail using the existing config.

    Without ``--connector`` this is the inverse of the global disable: it
    sets ``guardrail.enabled = true`` and (when --restart is on) restarts
    the gateway so the sidecar runs ``Connector.Setup`` for the active
    connector. Use ``defenseclaw setup guardrail`` instead when you actually
    want to re-configure the model / scanner-mode / connector.

    With ``--connector X`` it re-enables a single previously-disabled
    connector: the boot loop runs X's ``Setup`` again while the others are
    untouched.
    """
    if connector_flag:
        _toggle_connector_guardrail(
            app, connector_flag, enable=True, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)

    if gc.enabled:
        click.echo(f"  {ux.dim('Guardrail is already enabled')} ({_active_connector_display(app.cfg, connector)}).")
        return

    # Sanity-check that there's enough config for re-enable to actually
    # work. A proxy connector (openclaw, zeptoclaw) routes LLM traffic
    # through the guardrail, so with no model it would silently forward to
    # an unconfigured upstream; fail fast with a pointer to the full setup.
    # Hook connectors never need a model (init enables them without one),
    # so enable stays the inverse of disable for them (GAP-1562).
    if _enabled_connectors_need_model(app.cfg, connector) and not (gc.model or app.cfg.llm.model):
        ux.err("Cannot enable: guardrail.model is not set.", indent="  ")
        ux.subhead("Run 'defenseclaw setup guardrail' to configure first.", indent="    ")
        raise SystemExit(1)

    # The boot loop runs Connector.Setup for every active connector that
    # is not disabled on its own (`guardrail disable --connector X` is
    # kept); name exactly those, here and in the result (GAP-1809).
    _actives = _active_connector_set(app.cfg, connector)
    _kept_off = [
        name for name in _actives if hasattr(gc, "effective_enabled") and not gc.effective_enabled(name)
    ]
    _set_up = [name for name in _actives if name not in _kept_off]

    click.echo()
    if _set_up:
        _targets = ", ".join(f"{_connector_label(n)} ({n})" for n in _set_up)
    else:
        _targets = "no connectors (every active connector is disabled on its own)"
    click.echo(f"  {ux.bold('Enabling guardrail')} for {_targets}")
    if not restart:
        for name in _kept_off:
            ux.subhead(
                f"{_connector_label(name)} ({name}) stays disabled; turn it on with: "
                f"defenseclaw guardrail enable --connector {name}",
                indent="  ",
            )
    if restart:
        ux.subhead(
            "Will restart the gateway so the connector setup runs immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: enabled flag is persisted but the connector "
            "setup won't run until you restart the gateway manually.",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    if restart and _set_up:
        _verify_agents_before_enable(app, _set_up)

    gc.enabled = True
    try:
        app.cfg.save()
        ux.ok("Config saved (guardrail.enabled = true)", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise SystemExit(1)

    if restart:
        # Lazy import via module: see disable_cmd above for rationale.
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
            connectors=_actives,
            **({"summary_exclude": frozenset(_kept_off)} if _kept_off else {}),
            # With every active connector being set up, report "setup
            # complete" only once the gateway admitted them (GAP-0069).
            wait_for_connector_ready=bool(_set_up) and not _kept_off,
        )
        if len(_set_up) > 1:
            ux.ok(
                f"connector setup complete for {len(_set_up)} connectors: "
                + ", ".join(_set_up),
                indent="  ",
            )
        elif _set_up:
            ux.ok(f"{_connector_label(_set_up[0])} connector setup complete", indent="  ")
        for name in _kept_off:
            ux.subhead(
                f"{_connector_label(name)} ({name}) stays disabled; turn it on with: "
                f"defenseclaw guardrail enable --connector {name}",
                indent="  ",
            )
        click.echo()

    _log_guardrail_action(
        app,
        "guardrail-enable",
        f"connector={connector} restart={restart}",
    )


def _apply_scoped_fail_mode_transaction(
    app: AppContext,
    *,
    key: str,
    mode: str,
    restart: bool,
    label: str,
    entry: object | None,
    stored_mode: str,
) -> None:
    """Persist and refresh one connector under the transaction-wide lock."""

    from defenseclaw.config import PerConnectorGuardrailConfig

    gc = app.cfg.guardrail
    conns = gc.connectors
    with fail_mode_transaction_lock(app.cfg):
        try:
            snapshots = snapshot_fail_mode_transaction(app.cfg, [key])
        except OSError as exc:
            ux.err(f"Could not snapshot fail-mode transaction: {exc}", indent="  ")
            raise click.Abort() from exc

        old_entry = entry
        old_mode = stored_mode
        if entry is None:
            entry = PerConnectorGuardrailConfig()
            conns[key] = entry
        entry.hook_fail_mode = mode
        try:
            app.cfg.save()
            ux.ok(
                f"Config saved (guardrail.connectors.{key}.hook_fail_mode = {mode})",
                indent="  ",
            )
        except OSError as exc:
            if old_entry is None:
                conns.pop(key, None)
            else:
                old_entry.hook_fail_mode = old_mode
            restore_fail_mode_transaction(snapshots)
            ux.err(f"Failed to save config: {exc}", indent="  ")
            raise click.Abort() from exc

        if restart and gc.enabled:
            try:
                reconcile_connector_registration(app.cfg, key)
            except (OSError, RuntimeError) as exc:
                if old_entry is None:
                    conns.pop(key, None)
                else:
                    old_entry.hook_fail_mode = old_mode
                try:
                    restore_fail_mode_transaction(snapshots)
                except OSError as rollback_exc:
                    ux.err(f"Fail-mode update failed and rollback was incomplete: {rollback_exc}", indent="  ")
                    raise click.Abort() from rollback_exc
                ux.err(f"Fail-mode update failed; previous config and registration restored: {exc}", indent="  ")
                raise click.Abort() from exc
            ux.ok(f"{label} runtime registration refreshed and verified with fail={mode}.", indent="  ")
            click.echo()
        elif not restart:
            ux.warn(
                "--no-restart saved the desired value, but runtime registration was not refreshed; "
                "status will report drift until reconciliation succeeds.",
                indent="  ",
            )
        elif not gc.enabled:
            ux.warn(
                "guardrail is currently disabled — value will take effect "
                "the next time you run 'defenseclaw guardrail enable'.",
                indent="  ",
            )


def _set_connector_fail_mode(app: AppContext, requested: str, mode: str | None, *, restart: bool, yes: bool) -> None:
    """Show or set the hook fail mode for a SINGLE connector.

    Per-connector analog of the global ``guardrail fail-mode``: writes
    ``guardrail.connectors[X].hook_fail_mode`` so one connector can run a
    different delivery/response fail posture than its peers. On restart the Go
    boot loop regenerates that connector's hook with the new ``FAIL_MODE``;
    the others are untouched.

    ``--connector`` is a multi-connector feature: on a single-connector
    install (no ``guardrail.connectors`` map) it points the operator at the
    global command rather than silently creating a one-entry map.
    """
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        ux.err("--connector is only valid on multi-connector installs.", indent="  ")
        ux.subhead(
            "This is a single-connector install; use 'defenseclaw guardrail fail-mode' "
            "(no --connector) to set the global fail mode.",
            indent="    ",
        )
        raise SystemExit(1)

    key = _resolve_member_connector(app, requested)
    if key is None:
        ux.err(f"Connector {requested!r} is not configured.", indent="  ")
        ux.subhead("Configured connectors: " + ", ".join(sorted(conns)), indent="    ")
        raise SystemExit(1)

    gc = app.cfg.guardrail
    label = _connector_label(key.strip().lower())
    global_fm = (gc.hook_fail_mode or "open").lower()
    current = (
        gc.effective_hook_fail_mode(key)
        if hasattr(gc, "effective_hook_fail_mode")
        else global_fm
    ).lower()
    if current not in ("open", "closed"):
        current = "open"

    entry = conns.get(key)
    stored_mode = str(getattr(entry, "hook_fail_mode", "") or "").strip().lower()
    has_override = stored_mode in ("open", "closed")
    configured_mode = stored_mode if has_override else global_fm
    runtime_state = resolve_connector_fail_mode(app.cfg, key)

    # No mode argument → just report this connector's effective value and
    # whether it is an override or inherited from the global default.
    if mode is None:
        click.echo()
        runtime_value = (
            "open (Hermes upstream; failures cannot be made fail-closed)"
            if normalize_connector(key) == "hermes"
            else runtime_state.runtime or "unknown"
        )
        click.echo(f"  {ux.bold(f'{label} ({key}) hook_fail_mode:')} {ux.accent(runtime_value)}")
        if has_override:
            ux.subhead(f"per-connector override (global default: {global_fm}).", indent="  ")
        else:
            ux.subhead(f"inherited from global default ({global_fm}).", indent="  ")
        if runtime_state.drift:
            ux.warn(
                f"Runtime drift (desired {runtime_state.desired}): " + ", ".join(runtime_state.drift),
                indent="  ",
            )
        click.echo()
        return

    pinned = _cursor_pinned_fail_mode(gc, key)
    if pinned is not None and mode != pinned:
        _refuse_cursor_fail_mode(gc, key, mode, pinned)

    if mode == configured_mode and runtime_state.desired == mode and runtime_state.current:
        ux.echo(f"  {ux.dim(f'{label} hook fail mode is already')} {mode!r} {ux.dim('— nothing to do.')}")
        return

    click.echo()
    if mode == configured_mode:
        click.echo(f"  {ux.bold(f'Reconciling {label} hook runtime:')} {ux.accent(mode)}")
        ux.warn("Persisted policy matches, but installed runtime state is stale or inconsistent.", indent="  ")
    else:
        ux.echo(
            f"  {ux.bold(f'Changing {label} hook fail mode:')} {configured_mode} {ux.dim('→')} {ux.accent(mode)}"
        )
    if normalize_connector(key) == "hermes" and mode == "closed":
        ux.warn(
            "Hermes will remain fail-open; this value is stored only as requested policy provenance.",
            indent="  ",
        )
        ux.subhead(
            "Timeout, nonzero exit, malformed output, authentication, and transport failures continue "
            "in upstream Hermes. Only valid synchronous JSON can block.",
            indent="    ",
        )
    elif mode == "closed":
        ux.warn(f"Invalid or unavailable gateway responses will now BLOCK {label}.", indent="  ")
        ux.subhead(
            "A 4xx, malformed/incomplete response, timeout, or connection failure will exit 2 from this "
            "connector's hooks. Make sure your gateway is healthy first.",
            indent="    ",
        )
    else:
        ux.subhead(
            f"Invalid or unavailable gateway responses will now ALLOW {label} and log the failure to "
            "~/.defenseclaw/logs/hook-failures.jsonl.",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise click.Abort()

    _apply_scoped_fail_mode_transaction(
        app,
        key=key,
        mode=mode,
        restart=restart,
        label=label,
        entry=entry,
        stored_mode=stored_mode,
    )

    _log_guardrail_action(
        app,
        "guardrail-fail-mode",
        f"connector={key} scope=per-connector new={mode} restart={restart}",
    )


def _multi_connector_fail_mode_targets(app: AppContext) -> list[str]:
    """Return active connectors for bare fail-mode writes in multi installs."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        return []
    return [name for name in _active_connector_set(app.cfg, _resolve_active_connector(app.cfg)) if name in conns]


def _apply_global_fail_mode_transaction(
    app: AppContext,
    *,
    mode: str,
    restart: bool,
    fail_mode_targets: list[str],
    single_connector: str,
    single_runtime: bool,
    target_modes: dict[str, str] | None = None,
) -> None:
    """Persist global/fan-out fail mode and atomically refresh registrations.

    ``target_modes`` overrides the value written for a target (Cursor keeps
    the value its guardrail mode pins).
    """

    gc = app.cfg.guardrail
    transaction_targets = fail_mode_targets or ([single_connector] if single_runtime else [])
    with fail_mode_transaction_lock(app.cfg):
        try:
            snapshots = snapshot_fail_mode_transaction(app.cfg, transaction_targets)
        except OSError as exc:
            ux.err(f"Could not snapshot fail-mode transaction: {exc}", indent="  ")
            raise click.Abort() from exc

        old_global = gc.hook_fail_mode
        old_entries: dict[str, tuple[object | None, str]] = {}
        gc.hook_fail_mode = mode
        if fail_mode_targets:
            from defenseclaw.config import PerConnectorGuardrailConfig

            for name in fail_mode_targets:
                entry = gc.connectors.get(name)
                old_entries[name] = (entry, str(getattr(entry, "hook_fail_mode", "") or ""))
                if entry is None:
                    entry = PerConnectorGuardrailConfig()
                    gc.connectors[name] = entry
                # Explicit fan-out makes the operation truthful in mixed
                # observe/action installs and prevents old overrides from
                # silently defeating the requested global posture.
                entry.hook_fail_mode = (target_modes or {}).get(name, mode)
        try:
            app.cfg.save()
            if fail_mode_targets:
                # A pinned connector (Cursor) keeps its own value; say so
                # instead of counting it in the overrides (GAP-1432). A
                # connector disabled on its own has its value saved too, so
                # it is counted and named as staying disabled (GAP-2178).
                pinned = {name: (target_modes or {}).get(name, mode) for name in fail_mode_targets}
                disabled = {name for name in fail_mode_targets if _disabled_on_its_own(gc, name)}
                kept = "".join(
                    f"; {_connector_label(name)} stays {value}"
                    for name, value in sorted(pinned.items())
                    if value != mode and name not in disabled
                )
                kept += "".join(
                    f"; {_connector_label(name)} saved, stays disabled until "
                    f"'defenseclaw guardrail enable --connector {name}'"
                    for name in sorted(disabled)
                )
                changed = sum(1 for value in pinned.values() if value == mode)
                when = "" if gc.enabled else " — applies when the guardrail is enabled"
                ux.ok(
                    f"Config saved (global default + {changed} connector overrides = {mode}{kept}){when}",
                    indent="  ",
                )
            else:
                ux.ok(f"Config saved (guardrail.hook_fail_mode = {mode})", indent="  ")
        except OSError as exc:
            gc.hook_fail_mode = old_global
            for name, (old_entry, old_mode) in old_entries.items():
                if old_entry is None:
                    gc.connectors.pop(name, None)
                else:
                    old_entry.hook_fail_mode = old_mode
            restore_fail_mode_transaction(snapshots)
            ux.err(f"Failed to save config: {exc}", indent="  ")
            raise click.Abort() from exc

        if restart and gc.enabled:
            used_full_restart = False
            gateway_stopped = False
            try:
                # GAP-2071: a connector disabled on its own has no hooks to
                # refresh or verify; its value is only saved for later.
                disabled = frozenset(name for name in transaction_targets if _disabled_on_its_own(gc, name))
                live_targets = [name for name in transaction_targets if name not in disabled]
                runtime_targets = [
                    name for name in live_targets if normalize_connector(name) in _RUNTIME_FAIL_MODE_CONNECTORS
                ]
                if live_targets and len(runtime_targets) == len(live_targets):
                    for name in runtime_targets:
                        reconcile_connector_registration(app.cfg, name)
                elif not _gateway_running(app):
                    # GAP-1370: like the --connector form, never start a
                    # gateway the user stopped; it loads the saved value
                    # when it starts.
                    gateway_stopped = True
                    for name in runtime_targets:
                        reconcile_connector_registration(app.cfg, name)
                else:
                    from defenseclaw.commands import cmd_setup

                    used_full_restart = True
                    cmd_setup._restart_services(
                        app.cfg.data_dir,
                        app.cfg.gateway.host,
                        app.cfg.gateway.port,
                        connector=single_connector,
                        connectors=_active_connector_set(app.cfg, single_connector),
                        summary_exclude=disabled,
                    )
                    for name in runtime_targets:
                        state = resolve_connector_fail_mode(app.cfg, name)
                        if not state.current:
                            raise OSError(
                                f"connector runtime verification failed for {name}: " + ", ".join(state.drift)
                            )
            except (OSError, RuntimeError, click.ClickException) as exc:
                gc.hook_fail_mode = old_global
                for name, (old_entry, old_mode) in old_entries.items():
                    if old_entry is None:
                        gc.connectors.pop(name, None)
                    else:
                        old_entry.hook_fail_mode = old_mode
                try:
                    restore_fail_mode_transaction(snapshots)
                except OSError as rollback_exc:
                    ux.err(f"Fail-mode update failed and rollback was incomplete: {rollback_exc}", indent="  ")
                    raise click.Abort() from rollback_exc
                if used_full_restart:
                    try:
                        from defenseclaw.commands import cmd_setup

                        cmd_setup._restart_services(
                            app.cfg.data_dir,
                            app.cfg.gateway.host,
                            app.cfg.gateway.port,
                            connector=single_connector,
                            connectors=_active_connector_set(app.cfg, single_connector),
                        )
                    except (OSError, RuntimeError, click.ClickException) as rollback_exc:
                        ux.err(
                            "Fail-mode update failed and the previous files were restored, "
                            f"but runtime rollback failed: {rollback_exc}",
                            indent="  ",
                        )
                        raise click.Abort() from rollback_exc
                ux.err(f"Fail-mode update failed; previous config and registration restored: {exc}", indent="  ")
                raise click.Abort() from exc
            if gateway_stopped:
                _note_applies_on_start("new fail mode")
            else:
                ux.ok("Selected connector runtime registrations refreshed and verified.", indent="  ")
            click.echo()
        elif not restart:
            ux.warn(
                "--no-restart saved desired values, but runtime registrations were not refreshed; "
                "status will report drift until reconciliation succeeds.",
                indent="  ",
            )
        elif not gc.enabled and not fail_mode_targets:
            # The fan-out summary already says when it applies (GAP-2178).
            ux.warn(
                "guardrail is currently disabled — value will take effect "
                "the next time you run 'defenseclaw guardrail enable'.",
                indent="  ",
            )


@guardrail.command("fail-mode")
@click.argument("mode", required=False, type=click.Choice(["open", "closed"]))
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway so hooks are regenerated with the new fail mode (default: on).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the fail mode to a single connector (multi-connector installs only). "
    "Omit to show/set the global default.",
)
@pass_ctx
def fail_mode_cmd(
    app: AppContext,
    mode: str | None,
    restart: bool,
    yes: bool,
    connector_flag: str | None,
) -> None:
    """Show or change the hook failure behavior.

    The hook fail mode controls what generated hooks do when delivery or
    authentication fails, or when the DefenseClaw gateway returns a 4xx,
    an unparseable JSON body, or no ``action`` field. Two values are supported:

      \b
      open   — allow the tool/prompt and log the failure.
               A gateway outage never blocks your agent.
      closed — block supported events when inspection is unavailable.
               The default on a new install: every prompt and
               tool call is inspected or blocked.

    Transport failures (gateway unreachable / timeout / 5xx) follow the
    same connector-scoped setting. ``DEFENSECLAW_STRICT_AVAILABILITY=1``
    additionally forces transport and missing-token failures closed.

    Without an argument this prints the current value. With
    ``open`` or ``closed`` it persists the choice to ~/.defenseclaw/
    config.yaml and (when --restart is on) restarts the gateway so
    the regenerated hooks pick up the new value immediately.

    With ``--connector X`` it scopes the fail mode to a single connector
    (multi-connector installs only), writing a per-connector override
    while the global default and the other connectors are left untouched.
    """
    if connector_flag:
        _set_connector_fail_mode(
            app, connector_flag, mode, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    current = (gc.hook_fail_mode or "open").lower()
    if current not in ("open", "closed"):
        current = "open"

    if mode is None:
        click.echo()
        click.echo(f"  {ux.bold('guardrail.hook_fail_mode:')} {ux.accent(current)}")
        # Per-connector effective fail mode: one line per active connector so
        # a 3-connector install shows all three (and a single-connector install
        # shows exactly that one). Mirrors `guardrail status`; the global value
        # above is the fallback each connector inherits unless it carries a
        # `--connector` override.
        _actives = _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        click.echo()
        click.echo(f"  {ux._style('per connector:', fg='bright_black', bold=True)}")
        _open_names: list[str] = []
        for _name in _actives:
            _eff = gc.effective_hook_fail_mode(_name) if hasattr(gc, "effective_hook_fail_mode") else current
            _enforcing = gc.enabled and (gc.effective_enabled(_name) if hasattr(gc, "effective_enabled") else True)
            if not _enforcing:
                # A disabled connector has no hooks, so it has no fail mode and
                # its missing hooks are not drift (GAP-1717, like GAP-1648).
                _eff = "disabled (no hooks)"
            elif normalize_connector(_name) in _RUNTIME_FAIL_MODE_CONNECTORS:
                _state = resolve_connector_fail_mode(app.cfg, _name)
                _eff = _state.runtime or "unknown"
                if _state.drift:
                    _eff += f" (desired {_state.desired}; drift: {', '.join(_state.drift)})"
            elif normalize_connector(_name) == "hermes":
                _eff = f"open (Hermes upstream; configured provenance: {_eff})"
            elif _is_proxy_connector(_name):
                _eff = "closed (proxy-backed, no hooks: blocked while the gateway is down)"
            elif _cursor_stays_fail_closed(gc, _name):
                _eff = "closed (Cursor hooks always fail closed in action mode)"
            if _eff.startswith("open") and normalize_connector(_name) != "hermes":
                _open_names.append(_name)
            _eff_disp = ux._style(_eff, fg="yellow") if _eff == "closed" else _eff
            click.echo(f"      - {_connector_label(_name)} ({_name}): {_eff_disp}")
        click.echo()
        # One rule per view: each connector follows the value shown above
        # (GAP-1717: a global "ALLOW" line contradicted Cursor's "closed").
        if current == "open":
            ux.subhead(
                "Invalid, unauthorized, incomplete, and unreachable gateway responses ALLOW the "
                "tool/prompt for connectors that are open above and BLOCK it for those that are closed.",
                indent="  ",
            )
            click.echo(f"  {ux.dim('Switch to closed:')} defenseclaw guardrail fail-mode closed")
        else:
            # Name Hermes only when it is configured (GAP-2116).
            _hermes_note = (
                "; Hermes remains fail-open"
                if any(normalize_connector(n) == "hermes" for n in _actives)
                else ""
            )
            ux.subhead(
                "Invalid, unauthorized, incomplete, and unreachable gateway responses BLOCK connectors "
                f"that are closed above{_hermes_note}.",
                indent="  ",
            )
            if _open_names:
                # GAP-1109: a connector override (or observe mode) keeps these
                # open although the global default is closed.
                _warn_still_fail_open(gc, _open_names)
            click.echo(f"  {ux.dim('Switch to open:')}   defenseclaw guardrail fail-mode open")
        click.echo()
        return

    fail_mode_targets = _multi_connector_fail_mode_targets(app)
    target_modes: dict[str, str] = {}
    runtime_states = {}
    if fail_mode_targets:
        # Mutation comparisons use the stored posture; runtime agreement is
        # checked separately so a stale installation can never be a no-op.
        configured = getattr(gc, "connectors", {}) or {}
        for name in fail_mode_targets:
            entry = configured.get(name)
            stored = str(getattr(entry, "hook_fail_mode", "") or "").strip().lower()
            target_modes[name] = stored if stored in ("open", "closed") else current
            runtime_states[name] = resolve_connector_fail_mode(app.cfg, name)
    # Cursor keeps the value its guardrail mode pins (GAP-1432).
    desired_modes = {name: _cursor_pinned_fail_mode(gc, name) or mode for name in fail_mode_targets}

    if (
        fail_mode_targets
        and all(target_modes[name] == desired_modes[name] for name in fail_mode_targets)
        and all(
            (runtime_states[name].desired == desired_modes[name] and runtime_states[name].current)
            or _disabled_on_its_own(gc, name)
            or not gc.enabled
            for name in fail_mode_targets
        )
    ):
        scope = "for all active connectors" if gc.enabled else "for configured connectors"
        ux.echo(f"  {ux.dim('Hook fail mode is already')} {mode!r} {ux.dim(f'{scope} — nothing to do.')}")
        return
    single_connector = _resolve_active_connector(app.cfg)
    single_pinned = None if fail_mode_targets else _cursor_pinned_fail_mode(gc, single_connector)
    if single_pinned is not None and mode != single_pinned:
        _refuse_cursor_fail_mode(gc, single_connector, mode, single_pinned)
    single_state = (
        resolve_connector_fail_mode(app.cfg, single_connector)
        if not fail_mode_targets and normalize_connector(single_connector) in _RUNTIME_FAIL_MODE_CONNECTORS
        else None
    )
    if (
        not fail_mode_targets
        and mode == current
        and (single_state is None or (single_state.desired == mode and single_state.current))
    ):
        if normalize_connector(single_connector) == "hermes":
            ux.echo(
                f"  {ux.dim('Configured Hermes fail-mode provenance is already')} {mode!r}"
                f" {ux.dim('— runtime remains upstream fail-open.')}"
            )
        else:
            ux.echo(f"  {ux.dim('Hook fail mode is already')} {mode!r} {ux.dim('— nothing to do.')}")
        return

    click.echo()
    guardrail_off = not gc.enabled
    if fail_mode_targets:
        if guardrail_off:
            click.echo(f"  {ux.bold('Saving hook fail mode for configured connectors:')} {ux.accent(mode)}")
        else:
            click.echo(f"  {ux.bold('Changing hook fail mode for active connectors:')} {ux.accent(mode)}")
        for name in fail_mode_targets:
            old = target_modes.get(name, current)
            if guardrail_off and _disabled_on_its_own(gc, name):
                click.echo(
                    f"      - {_connector_label(name)} ({name}): disabled (no hooks); "
                    f"{desired_modes[name]} is saved; it stays disabled until "
                    f"'defenseclaw guardrail enable --connector {name}'"
                )
                continue
            if guardrail_off:
                # GAP-2156: a global disable removed every hook, so nothing
                # changes now; read like the per-connector disabled line.
                click.echo(
                    f"      - {_connector_label(name)} ({name}): guardrail off (no hooks); "
                    f"{desired_modes[name]} is saved for when it is turned on again"
                )
                continue
            if _disabled_on_its_own(gc, name):
                # Like the bare view: no hooks, so no fail mode (GAP-1977).
                click.echo(
                    f"      - {_connector_label(name)} ({name}): disabled (no hooks); "
                    f"{mode} is saved for when it is turned on again"
                )
                continue
            if desired_modes[name] != mode:
                click.echo(
                    f"      - {_connector_label(name)} ({name}): stays {desired_modes[name]} "
                    + ux.dim(
                        f"(Cursor {'action' if desired_modes[name] == 'closed' else 'observe'} mode "
                        f"keeps hook failures {desired_modes[name]})"
                    )
                )
                continue
            # Show what guardrail status shows: an observe connector without
            # its own value already runs fail-open, and a hook-installed
            # connector shows its installed runtime value (GAP-1370).
            shown = gc.effective_hook_fail_mode(name) if hasattr(gc, "effective_hook_fail_mode") else old
            installed = getattr(runtime_states[name], "runtime", None)
            if normalize_connector(name) in _RUNTIME_FAIL_MODE_CONNECTORS and installed:
                shown = installed
            if _cursor_stays_fail_closed(gc, name) and mode == "open":
                click.echo(
                    f"      - {_connector_label(name)} ({name}): stays closed; Cursor hooks always fail "
                    "closed in action mode (open is saved for observe mode)"
                )
            elif shown != mode:
                # The fan-out saves the value as the connector's own setting,
                # which applies in observe mode too (GAP-1977).
                note = ux.dim(" (its own setting, also in observe mode)") if _observe_keeps_fail_open(gc, name) else ""
                ux.echo(
                    f"      - {_connector_label(name)} ({name}): {shown} {ux.dim('→')} {ux.accent(mode)}{note}"
                )
            elif old != mode:
                click.echo(f"      - {_connector_label(name)} ({name}): already {mode}; saved as its own setting")
            elif not runtime_states[name].current:
                click.echo(f"      - {_connector_label(name)} ({name}): reconcile stale runtime")
            else:
                click.echo(f"      - {_connector_label(name)} ({name}): already {mode}")
    elif current == mode:
        click.echo(
            f"  {ux.bold('Re-applying hook fail mode:')} {ux.accent(mode)} "
            f"{ux.dim('(reconcile the installed hooks)')}"
        )
    else:
        ux.echo(f"  {ux.bold('Changing hook fail mode:')} {current} {ux.dim('→')} {ux.accent(mode)}")
    active_names = fail_mode_targets or [single_connector]
    if mode == "closed" and not fail_mode_targets:
        # The multi-connector fan-out gives every connector its own value,
        # so observe mode no longer keeps it fail-open (GAP-1977).
        _observe_open = [name for name in active_names if _observe_keeps_fail_open(gc, name)]
        if _observe_open:
            ux.warn(
                f"{', '.join(_observe_open)} stays fail-open while in observe mode. "
                f"Switch to action with: {_mode_action_command(gc)}",
                indent="  ",
            )
    hermes_targeted = any(normalize_connector(name) == "hermes" for name in active_names)
    non_hermes_targeted = any(normalize_connector(name) != "hermes" for name in active_names)
    if mode == "closed" and hermes_targeted and not non_hermes_targeted:
        ux.warn(
            "Hermes will remain fail-open; closed is stored only as requested policy provenance.",
            indent="  ",
        )
        ux.subhead(
            "Only valid synchronous Hermes JSON can block. Timeout, nonzero exit, malformed output, "
            "authentication, and transport failures continue upstream.",
            indent="    ",
        )
    elif mode == "closed" and guardrail_off:
        ux.subhead(
            "Once the guardrail is enabled, invalid or unavailable gateway responses will BLOCK "
            "supported connectors." + (" Hermes remains fail-open." if hermes_targeted else ""),
            indent="  ",
        )
    elif mode == "closed":
        ux.warn(
            "Invalid or unavailable gateway responses will now BLOCK supported connectors.",
            indent="  ",
        )
        ux.subhead(
            "A 4xx, malformed/incomplete response, timeout, or connection failure blocks connectors "
            "with a native fail-closed surface."
            + (" Hermes remains fail-open." if hermes_targeted else ""),
            indent="    ",
        )
    elif all(_is_proxy_connector(name) for name in active_names):
        # GAP-2448: OpenClaw/ZeptoClaw have no hooks; the plugin blocks while
        # the gateway is down whatever this value says.
        labels = ", ".join(_connector_label(name) for name in active_names)
        ux.warn(
            f"{labels} is proxy-backed and has no hooks, so the hook fail mode does not apply to it: "
            "its requests stay blocked (fail-closed) while the gateway is down.",
            indent="  ",
        )
        ux.subhead("open is saved for hook connectors you set up later.", indent="    ")
    else:
        ux.subhead(
            ("Once the guardrail is enabled, invalid or unavailable gateway responses will ALLOW"
             if guardrail_off
             else "Invalid or unavailable gateway responses will now ALLOW")
            + " the agent and log the failure to ~/.defenseclaw/logs/hook-failures.jsonl.",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        # click.Abort routes through Click's exception handler and
        # cooperates with the result callbacks the setup group
        # registers (e.g., the auto-restart suppression keyed on
        # _SETUP_RESTART_HANDLED_KEY in cmd_setup.py); a bare
        # SystemExit bypasses that machinery.
        raise click.Abort()

    _apply_global_fail_mode_transaction(
        app,
        mode=mode,
        restart=restart,
        fail_mode_targets=fail_mode_targets,
        single_connector=single_connector,
        single_runtime=single_state is not None,
        target_modes=desired_modes,
    )

    _log_guardrail_action(
        app,
        "guardrail-fail-mode",
        (
            f"scope=active-connectors count={len(fail_mode_targets)} new={mode} restart={restart}"
            if fail_mode_targets
            else f"old={current} new={mode} restart={restart}"
        ),
    )


def _is_proxy_connector(name: str) -> bool:
    from defenseclaw.platform_support import PROXY_CONNECTORS

    return normalize_connector(name) in PROXY_CONNECTORS


def _cursor_pinned_fail_mode(gc, name: str) -> str | None:
    """Cursor's hook failure mode follows its guardrail mode, or None for others.

    Cursor's managed hooks are fail-closed in action mode and fail-open in
    observe mode, as ``setup cursor`` writes them. A fail-mode change that
    stored the other value left doctor failing "inconsistent Cursor posture"
    until ``setup cursor`` (GAP-1432).
    """
    if normalize_connector(name) != "cursor":
        return None
    mode = gc.effective_mode(name) if hasattr(gc, "effective_mode") else getattr(gc, "mode", "observe")
    return "closed" if str(mode or "").strip().lower() == "action" else "open"


def _refuse_cursor_fail_mode(gc, name: str, mode: str, pinned: str) -> None:
    other = "observe" if pinned == "closed" else "action"
    current = "action" if pinned == "closed" else "observe"
    multi = bool(getattr(gc, "connectors", {}) or {})
    ux.err(f"Cursor in {current} mode keeps hook failures {pinned}; fail mode {mode} is not applied.", indent="  ")
    ux.subhead(
        f"To change it, switch Cursor's guardrail mode: defenseclaw guardrail mode {other}"
        + (" --connector cursor" if multi else ""),
        indent="    ",
    )
    raise SystemExit(1)


def _observe_keeps_fail_open(gc, name: str) -> bool:
    """Observe mode keeps a connector fail-open unless it has its own fail mode."""
    if normalize_connector(name) == "hermes":
        return False
    override = gc._connector_override(name) if hasattr(gc, "_connector_override") else None
    if override is not None and str(getattr(override, "hook_fail_mode", "") or "").strip():
        return False
    mode = gc.effective_mode(name) if hasattr(gc, "effective_mode") else getattr(gc, "mode", "observe")
    return str(mode or "").strip().lower() != "action"


def _mode_action_command(gc) -> str:
    multi = bool(getattr(gc, "connectors", {}) or {})
    return "defenseclaw guardrail mode action" + (" --connector <name>" if multi else "")


def _warn_still_fail_open(gc, open_names: list[str]) -> None:
    """Name the command that really closes each still-open connector (GAP-1341)."""
    observe_open = [name for name in open_names if _observe_keeps_fail_open(gc, name)]
    other_open = [name for name in open_names if name not in observe_open]
    if observe_open:
        ux.warn(
            f"Still fail-open: {', '.join(observe_open)} (observe mode keeps hooks fail-open). "
            f"Switch to action with: {_mode_action_command(gc)}",
            indent="  ",
        )
    if other_open:
        fix = (
            "defenseclaw guardrail fail-mode closed --connector <name>"
            if getattr(gc, "connectors", {}) or {}
            else "defenseclaw guardrail fail-mode closed"
        )
        ux.warn(f"Still fail-open: {', '.join(other_open)}. Close it with: {fix}", indent="  ")


_HILT_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _set_connector_hilt(
    app: AppContext,
    requested: str,
    state: str | None,
    min_severity: str | None,
    *,
    restart: bool,
    yes: bool,
) -> None:
    """Show or set the HILT (human-in-the-loop) policy for ONE connector.

    Per-connector analog of the global ``guardrail hilt``: writes a full
    ``guardrail.connectors[X].hilt`` block so one connector can prompt for
    approval at a different severity (or not at all) than its peers. The
    hook decision path reads it via ``EffectiveHILT(connector)``; a present
    block fully replaces the global one, an absent block inherits it.

    ``--connector`` is a multi-connector feature: on a single-connector
    install it points the operator at the global command instead of
    silently creating a one-entry map.
    """
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        ux.err("--connector is only valid on multi-connector installs.", indent="  ")
        ux.subhead(
            "This is a single-connector install; use 'defenseclaw guardrail hilt' "
            "(no --connector) to set the global HILT policy.",
            indent="    ",
        )
        raise SystemExit(1)

    key = _resolve_member_connector(app, requested)
    if key is None:
        ux.err(f"Connector {requested!r} is not configured.", indent="  ")
        ux.subhead("Configured connectors: " + ", ".join(sorted(conns)), indent="    ")
        raise SystemExit(1)

    gc = app.cfg.guardrail
    label = _connector_label(key.strip().lower())
    eff = gc.effective_hilt(key)
    cur_enabled = bool(eff.enabled)
    cur_min = (eff.min_severity or "HIGH").upper()
    entry = conns.get(key)
    has_override = entry is not None and getattr(entry, "hilt", None) is not None

    # No change requested → report this connector's effective HILT and
    # whether it is an explicit override or inherited from the global block.
    if state is None and min_severity is None:
        click.echo()
        click.echo(
            f"  {ux.bold(f'{label} ({key}) hilt:')} "
            f"enabled={ux.accent(str(cur_enabled).lower())} "
            f"min_severity={ux.accent(cur_min)}"
        )
        if has_override:
            gm = (gc.hilt.min_severity or "HIGH").upper()
            ux.subhead(
                f"per-connector override (global: enabled={str(bool(gc.hilt.enabled)).lower()} "
                f"min_severity={gm}).",
                indent="  ",
            )
        else:
            ux.subhead("inherited from the global HILT block.", indent="  ")
        click.echo()
        return

    # Start from the effective values so a partial change (e.g. only
    # --min-severity) preserves the other field.
    new_enabled = cur_enabled if state is None else (state == "on")
    new_min = cur_min if min_severity is None else min_severity.upper()

    if has_override and new_enabled == cur_enabled and new_min == cur_min:
        ux.echo(
            f"  {ux.dim(f'{label} HILT is already')} "
            f"enabled={str(new_enabled).lower()} min_severity={new_min} "
            f"{ux.dim('— nothing to do.')}"
        )
        return

    click.echo()
    click.echo(
        f"  {ux.bold(f'Updating {label} HILT:')} "
        f"enabled={ux.accent(str(new_enabled).lower())} "
        f"min_severity={ux.accent(new_min)}"
    )
    if new_enabled:
        ux.subhead(
            f"{label} will prompt for approval on confirmable actions at/above "
            f"{new_min} (CRITICAL findings still block outright).",
            indent="  ",
        )
    else:
        ux.subhead(
            f"{label} will NOT prompt — actions resolve straight to allow/alert/block.",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise click.Abort()

    from defenseclaw.config import HILTConfig, PerConnectorGuardrailConfig

    if entry is None:
        entry = PerConnectorGuardrailConfig()
        conns[key] = entry
    entry.hilt = HILTConfig(enabled=new_enabled, min_severity=new_min)
    try:
        app.cfg.save()
        ux.ok(
            f"Config saved (guardrail.connectors.{key}.hilt: "
            f"enabled={str(new_enabled).lower()} min_severity={new_min})",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort()

    if restart and gc.enabled:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=key,
        )
        ux.ok(f"Gateway restarted, {label} HILT policy applied.", indent="  ")
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    _log_hilt(
        app,
        f"connector={key} scope=per-connector "
        f"enabled={str(new_enabled).lower()} min_severity={new_min} restart={restart}",
    )


def _log_hilt(app: AppContext, details: str) -> None:
    """Audit a saved HILT change; a stopped gateway only skips the audit event."""
    _log_guardrail_action(app, "guardrail-hilt", details)


def _multi_connector_hilt_targets(app: AppContext) -> list[str]:
    """Return active connectors for bare HILT writes in multi installs."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        return []
    return [
        name
        for name in _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        if name in conns
    ]


@guardrail.command("hilt")
@click.argument("state", required=False, type=click.Choice(["on", "off"]))
@click.option(
    "--min-severity",
    "min_severity",
    default=None,
    type=click.Choice(_HILT_SEVERITIES, case_sensitive=False),
    help="Severity at/above which a confirmable action prompts for approval.",
)
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope HILT to a single connector (multi-connector installs only). "
    "Omit to show/set the global default.",
)
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway so the new HILT policy takes effect (default: on).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def hilt_cmd(
    app: AppContext,
    state: str | None,
    min_severity: str | None,
    connector_flag: str | None,
    restart: bool,
    yes: bool,
) -> None:
    """Show or change the human-in-the-loop (HILT) approval policy.

    HILT pauses a *confirmable* action whose severity is at/above the
    minimum and asks the operator to approve it, instead of silently
    allowing it or hard-blocking. CRITICAL findings always block outright.

    \b
    Examples:
      defenseclaw guardrail hilt                          # show global HILT
      defenseclaw guardrail hilt on --min-severity HIGH
      defenseclaw guardrail hilt off
      defenseclaw guardrail hilt on --connector codex     # per-connector override

    Without an argument this prints the current value. ``on``/``off``
    toggles it and ``--min-severity`` sets the threshold; either may be
    given alone (the other field is preserved). With ``--connector X`` it
    writes a per-connector override (multi-connector installs only) while
    the global default and the other connectors are left untouched.
    """
    if connector_flag:
        _set_connector_hilt(
            app, connector_flag, state, min_severity, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    cur_enabled = bool(gc.hilt.enabled)
    cur_min = (gc.hilt.min_severity or "HIGH").upper()

    if state is None and min_severity is None:
        click.echo()
        click.echo(
            f"  {ux.bold('guardrail.hilt.enabled:')} "
            f"{ux.accent(str(cur_enabled).lower())}"
        )
        click.echo(
            f"  {ux.bold('guardrail.hilt.min_severity:')} {ux.accent(cur_min)}"
        )
        # Per-connector effective HILT: one block per active connector so a
        # 3-connector install shows all three (a single-connector install
        # shows exactly that one). The global values above are what each
        # connector inherits unless it carries a `--connector` override.
        _actives = _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        click.echo()
        click.echo(f"  {ux._style('per connector:', fg='bright_black', bold=True)}")
        for _name in _actives:
            _eff = (
                gc.effective_hilt(_name)
                if hasattr(gc, "effective_hilt")
                else gc.hilt
            )
            _e_enabled = bool(getattr(_eff, "enabled", False))
            _e_min = (getattr(_eff, "min_severity", "") or "HIGH").upper()
            click.echo(
                f"      - {_connector_label(_name)} ({_name}): "
                f"enabled={str(_e_enabled).lower()} min_severity={_e_min}"
            )
        click.echo()
        ux.subhead(
            "CRITICAL findings always block; HILT confirms risky confirmable "
            "actions at/above min_severity.",
            indent="  ",
        )
        click.echo()
        return

    hilt_targets = _multi_connector_hilt_targets(app)
    target_hilts: dict[str, tuple[bool, str, bool, str]] = {}
    if hilt_targets:
        for name in hilt_targets:
            eff = (
                gc.effective_hilt(name)
                if hasattr(gc, "effective_hilt")
                else gc.hilt
            )
            old_enabled = bool(getattr(eff, "enabled", False))
            old_min = (getattr(eff, "min_severity", "") or "HIGH").upper()
            desired_enabled = old_enabled if state is None else (state == "on")
            desired_min = old_min if min_severity is None else min_severity.upper()
            target_hilts[name] = (old_enabled, old_min, desired_enabled, desired_min)

    new_enabled = cur_enabled if state is None else (state == "on")
    new_min = cur_min if min_severity is None else min_severity.upper()

    if hilt_targets and all(
        old_enabled == desired_enabled and old_min == desired_min
        for old_enabled, old_min, desired_enabled, desired_min in target_hilts.values()
    ):
        ux.echo(
            f"  {ux.dim('HILT is already')} "
            f"{ux.dim('in the requested state for all active connectors — nothing to do.')}"
        )
        return
    if not hilt_targets and new_enabled == cur_enabled and new_min == cur_min:
        ux.echo(
            f"  {ux.dim('HILT is already')} "
            f"enabled={str(new_enabled).lower()} min_severity={new_min} "
            f"{ux.dim('— nothing to do.')}"
        )
        return

    click.echo()
    if hilt_targets:
        click.echo(f"  {ux.bold('Updating HILT for active connectors:')}")
        for name in hilt_targets:
            old_enabled, old_min, desired_enabled, desired_min = target_hilts[name]
            if old_enabled == desired_enabled and old_min == desired_min:
                continue
            ux.echo(
                f"      - {_connector_label(name)} ({name}): "
                f"enabled={str(old_enabled).lower()} {ux.dim('→')} "
                f"{ux.accent(str(desired_enabled).lower())}, "
                f"min_severity={old_min} {ux.dim('→')} {ux.accent(desired_min)}"
            )
    else:
        ux.echo(
            f"  {ux.bold('Updating HILT:')} "
            f"enabled={str(cur_enabled).lower()} {ux.dim('→')} "
            f"{ux.accent(str(new_enabled).lower())}, "
            f"min_severity={cur_min} {ux.dim('→')} {ux.accent(new_min)}"
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise click.Abort()

    if hilt_targets:
        from defenseclaw.config import HILTConfig, PerConnectorGuardrailConfig

        for name in hilt_targets:
            _, _, desired_enabled, desired_min = target_hilts[name]
            entry = gc.connectors.get(name)
            if entry is None:
                entry = PerConnectorGuardrailConfig()
                gc.connectors[name] = entry
            entry.hilt = HILTConfig(enabled=desired_enabled, min_severity=desired_min)
    else:
        gc.hilt.enabled = new_enabled
        gc.hilt.min_severity = new_min
    try:
        app.cfg.save()
        if hilt_targets:
            ux.ok(
                f"Config saved ({len(hilt_targets)} connector HILT overrides updated)",
                indent="  ",
            )
        else:
            ux.ok(
                f"Config saved (guardrail.hilt: enabled={str(new_enabled).lower()} "
                f"min_severity={new_min})",
                indent="  ",
            )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort()

    from defenseclaw.commands import cmd_setup

    if restart and gc.enabled:
        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=_resolve_active_connector(app.cfg),
            connectors=_active_connector_set(app.cfg, _resolve_active_connector(app.cfg)),
        )
        ux.ok("Gateway restarted, HILT policy applied.", indent="  ")
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    _log_hilt(
        app,
        (
            f"scope=active-connectors count={len(hilt_targets)} "
            f"state={state or 'preserve'} min_severity={min_severity or 'preserve'} restart={restart}"
            if hilt_targets
            else f"enabled={str(new_enabled).lower()} min_severity={new_min} restart={restart}"
        ),
    )


def _set_connector_block_message(
    app: AppContext,
    requested: str,
    message: str | None,
    *,
    clear: bool,
    restart: bool,
    yes: bool,
) -> None:
    """Show or set the custom block message for ONE connector.

    Per-connector analog of the global ``guardrail block-message``: writes
    ``guardrail.connectors[X].block_message``. The hook block path resolves
    it via ``EffectiveBlockMessage(connector)`` — a per-connector message
    wins over the global one, and an empty value inherits the global / the
    built-in default.

    ``--connector`` is a multi-connector feature: on a single-connector
    install it points the operator at the global command instead of
    silently creating a one-entry map.
    """
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        ux.err("--connector is only valid on multi-connector installs.", indent="  ")
        ux.subhead(
            "This is a single-connector install; use 'defenseclaw guardrail "
            "block-message' (no --connector) to set the global message.",
            indent="    ",
        )
        raise SystemExit(1)

    key = _resolve_member_connector(app, requested)
    if key is None:
        ux.err(f"Connector {requested!r} is not configured.", indent="  ")
        ux.subhead("Configured connectors: " + ", ".join(sorted(conns)), indent="    ")
        raise SystemExit(1)

    gc = app.cfg.guardrail
    label = _connector_label(key.strip().lower())
    entry = conns.get(key)
    cur = entry.block_message if entry is not None else ""
    has_override = bool(cur)
    eff = gc.effective_block_message(key)

    if message is None and not clear:
        click.echo()
        if eff:
            click.echo(f"  {ux.bold(f'{label} ({key}) block_message:')} {ux.accent(eff)}")
        else:
            click.echo(
                f"  {ux.bold(f'{label} ({key}) block_message:')} {ux.dim('(built-in default)')}"
            )
        if has_override:
            ux.subhead("per-connector override.", indent="  ")
        else:
            ux.subhead("inherited from the global message / built-in default.", indent="  ")
        click.echo()
        return

    new_msg = "" if clear else message
    if new_msg == cur:
        ux.echo(
            f"  {ux.dim(f'{label} block message unchanged — nothing to do.')}"
        )
        return

    click.echo()
    if new_msg:
        click.echo(f"  {ux.bold(f'Setting {label} block message:')} {ux.accent(new_msg)}")
    else:
        click.echo(
            f"  {ux.bold(f'Clearing {label} block message')} "
            f"{ux.dim('(inherit global / built-in default)')}"
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise click.Abort()

    from defenseclaw.config import PerConnectorGuardrailConfig

    if entry is None:
        entry = PerConnectorGuardrailConfig()
        conns[key] = entry
    entry.block_message = new_msg
    try:
        app.cfg.save()
        ux.ok(
            f"Config saved (guardrail.connectors.{key}.block_message updated)",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort()

    if restart and gc.enabled and not _gateway_running(app):
        _note_applies_on_start(f"{label} block message")
    elif restart and gc.enabled:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=key,
        )
        ux.ok(f"Gateway restarted, {label} block message applied.", indent="  ")
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    _log_guardrail_action(
        app,
        "guardrail-block-message",
        f"connector={key} scope=per-connector cleared={clear} restart={restart}",
    )


def _multi_connector_block_message_targets(app: AppContext) -> list[str]:
    """Return active connectors for bare block-message writes in multi installs."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        return []
    return [
        name
        for name in _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        if name in conns
    ]


@guardrail.command("block-message")
@click.argument("message", required=False)
@click.option(
    "--clear",
    is_flag=True,
    help="Clear the custom message (revert to the global / built-in default).",
)
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the message to a single connector (multi-connector installs only). "
    "Omit to show/set the global default.",
)
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway so the new message takes effect (default: on).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def block_message_cmd(
    app: AppContext,
    message: str | None,
    clear: bool,
    connector_flag: str | None,
    restart: bool,
    yes: bool,
) -> None:
    """Show or change the custom message shown when an action is blocked.

    On a block verdict the live verdict reason is shown when present; this
    custom message is used as the user-facing text for block verdicts that
    carry no specific reason (and on the proxy path it replaces the default
    text). An empty message falls back to the built-in default. Audit rows
    and notifications always keep the real verdict reason.

    \b
    Examples:
      defenseclaw guardrail block-message
      defenseclaw guardrail block-message "Blocked by Acme Security — see #sec-help"
      defenseclaw guardrail block-message --clear
      defenseclaw guardrail block-message "Codex policy" --connector codex

    With ``--connector X`` it writes a per-connector override (multi-connector
    installs only) while the global default and the other connectors are
    left untouched.
    """
    if message is not None and clear:
        ux.err("Pass a message or --clear, not both.", indent="  ")
        raise click.Abort()

    if connector_flag:
        _set_connector_block_message(
            app, connector_flag, message, clear=clear, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    current = gc.block_message or ""

    if message is None and not clear:
        click.echo()
        if current:
            click.echo(f"  {ux.bold('guardrail.block_message:')} {ux.accent(current)}")
        else:
            click.echo(
                f"  {ux.bold('guardrail.block_message:')} {ux.dim('(built-in default)')}"
            )
        # Per-connector effective block message: one line per active connector
        # so a 3-connector install shows all three (a single-connector install
        # shows exactly that one). The global value above is what each connector
        # inherits unless it carries a `--connector` override.
        _actives = _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        click.echo()
        click.echo(f"  {ux._style('per connector:', fg='bright_black', bold=True)}")
        for _name in _actives:
            _eff = (
                gc.effective_block_message(_name)
                if hasattr(gc, "effective_block_message")
                else current
            )
            _shown = ux.accent(_eff) if _eff else ux.dim("(built-in default)")
            click.echo(f"      - {_connector_label(_name)} ({_name}): {_shown}")
        click.echo()
        return

    block_message_targets = _multi_connector_block_message_targets(app)
    target_messages: dict[str, str] = {}
    if block_message_targets:
        target_messages = {
            name: (
                gc.effective_block_message(name)
                if hasattr(gc, "effective_block_message")
                else current
            )
            for name in block_message_targets
        }

    new_msg = "" if clear else message
    if (
        block_message_targets
        and new_msg == current
        and all(value == new_msg for value in target_messages.values())
    ):
        ux.echo(
            f"  {ux.dim('Block message unchanged for all active connectors — nothing to do.')}"
        )
        return
    if not block_message_targets and new_msg == current:
        ux.echo(f"  {ux.dim('Block message unchanged — nothing to do.')}")
        return

    click.echo()
    if block_message_targets:
        if new_msg:
            click.echo(
                f"  {ux.bold('Setting block message for active connectors:')} "
                f"{ux.accent(new_msg)}"
            )
        else:
            click.echo(
                f"  {ux.bold('Clearing block message for active connectors')} "
                f"{ux.dim('(revert to built-in default)')}"
            )
        for name in block_message_targets:
            old = target_messages.get(name, current)
            if old == new_msg:
                continue
            old_label = old if old else "(built-in default)"
            new_label = new_msg if new_msg else "(built-in default)"
            ux.echo(
                f"      - {_connector_label(name)} ({name}): "
                f"{old_label} {ux.dim('→')} {ux.accent(new_label)}"
            )
    elif new_msg:
        click.echo(f"  {ux.bold('Setting block message:')} {ux.accent(new_msg)}")
    else:
        click.echo(
            f"  {ux.bold('Clearing block message')} {ux.dim('(revert to built-in default)')}"
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise click.Abort()

    gc.block_message = new_msg
    if block_message_targets:
        from defenseclaw.config import PerConnectorGuardrailConfig

        for name in block_message_targets:
            entry = gc.connectors.get(name)
            if entry is None:
                entry = PerConnectorGuardrailConfig()
                gc.connectors[name] = entry
            entry.block_message = new_msg
    try:
        app.cfg.save()
        if block_message_targets:
            ux.ok(
                f"Config saved (guardrail.block_message and {len(block_message_targets)} "
                "connector block_message overrides updated)",
                indent="  ",
            )
        else:
            ux.ok("Config saved (guardrail.block_message updated)", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort()

    if restart and gc.enabled and not _gateway_running(app):
        _note_applies_on_start("block message")
    elif restart and gc.enabled:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=_resolve_active_connector(app.cfg),
            connectors=_active_connector_set(app.cfg, _resolve_active_connector(app.cfg)),
        )
        ux.ok("Gateway restarted, block message applied.", indent="  ")
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    _log_guardrail_action(
        app,
        "guardrail-block-message",
        (
            f"scope=active-connectors count={len(block_message_targets)} "
            f"cleared={clear} restart={restart}"
            if block_message_targets
            else f"cleared={clear} restart={restart}"
        ),
    )


#: Built-in guardrail rule-pack presets — parity with the ``--rule-pack``
#: choice in ``setup`` (default | strict | permissive). ``setup`` owns the
#: write side; this is the day-to-day listing surface. Descriptions are
#: intentionally short. Kept local (not imported from cmd_setup) to preserve
#: this module's lazy-import discipline for the read-only paths.
_RULE_PACK_PRESETS = (
    ("default", "Balanced built-in pack — the shipped baseline."),
    ("strict", "Tighter thresholds; blocks more aggressively."),
    ("permissive", "Looser thresholds; favors availability over blocking."),
)


_NEVER_ALLOWED_PRIVATE_UPSTREAMS = frozenset({"169.254.169.254", "169.254.170.2", "fd00:ec2::254"})


def _private_upstream_ips(target: str) -> list[str]:
    """The addresses ``target`` (an IP or a hostname) stands for, checked the
    way the gateway checks guardrail.allow_private_upstreams."""
    import ipaddress
    import socket

    try:
        addresses = [ipaddress.ip_address(target)]
    except ValueError:
        if "/" in target:
            raise click.ClickException(f"{target} is a CIDR range; give single addresses or a hostname.") from None
        try:
            infos = socket.getaddrinfo(target, 443, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise click.ClickException(f"could not resolve {target}: {exc}") from None
        addresses = []
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            if ip not in addresses:
                addresses.append(ip)
    out = []
    for ip in addresses:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        text = str(ip)
        if text in _NEVER_ALLOWED_PRIVATE_UPSTREAMS or ip.is_loopback or ip.is_link_local \
                or ip.is_multicast or ip.is_unspecified:
            raise click.ClickException(
                f"{target} resolves to {text}; loopback, link-local and cloud metadata addresses are never allowed."
            )
        out.append(text)
    return out


_restart_option = click.option(
    "--restart/--no-restart",
    default=True,
    help=(
        "Restart a running gateway when the change needs it, so it enforces the change now "
        "(default: on; a stopped gateway is never started)."
    ),
)


@guardrail.command("allow-private-upstream")
@click.argument("targets", nargs=-1)
@click.option("--remove", is_flag=True, help="Remove these addresses instead of adding them.")
@_restart_option
@pass_ctx
def guardrail_allow_private_upstream(app: AppContext, targets: tuple[str, ...], remove: bool, restart: bool) -> None:
    """Let the guardrail proxy reach an LLM endpoint on a private address.

    The proxy refuses upstreams that resolve to private addresses. An AWS
    PrivateLink (VPC interface) endpoint for Bedrock is one: its hostname
    resolves to the endpoint's private IPs, and every proxied call fails.
    Give the hostname or its IPs; a hostname is resolved now and its private
    addresses are stored in guardrail.allow_private_upstreams. Run it again if
    the endpoint's addresses change. With no arguments it lists the entries.
    Loopback, link-local and cloud metadata addresses are never allowed.
    A running gateway is restarted so the proxy uses the change now
    (``--no-restart`` to skip).

    \b
    Example:
      defenseclaw guardrail allow-private-upstream bedrock-runtime.us-east-1.amazonaws.com
    """
    gc = app.cfg.guardrail
    current = [str(v).strip() for v in (gc.allow_private_upstreams or []) if str(v).strip()]
    if not targets:
        if current:
            click.echo("  guardrail.allow_private_upstreams: " + ", ".join(current))
        else:
            click.echo("  guardrail.allow_private_upstreams: (none)")
        return
    import ipaddress

    wanted: list[str] = []
    for target in targets:
        for ip in _private_upstream_ips(target.strip()):
            if not remove and not ipaddress.ip_address(ip).is_private:
                click.echo(f"  {ip} ({target}) is a public address; the proxy already reaches it.")
                continue
            if ip not in wanted:
                wanted.append(ip)
    if remove:
        updated = [ip for ip in current if ip not in wanted]
    else:
        updated = current + [ip for ip in wanted if ip not in current]
    if updated == current:
        ux.ok("No change: guardrail.allow_private_upstreams is " + (", ".join(current) or "(none)"), indent="  ")
        return
    gc.allow_private_upstreams = updated
    try:
        app.cfg.save()
    except OSError as exc:
        raise click.ClickException(f"could not save the config: {exc}") from exc
    ux.ok("guardrail.allow_private_upstreams: " + (", ".join(updated) or "(none)"), indent="  ")
    # The proxy reads the allowlist at start, so apply it the way use-pack
    # does; the OpenClaw error names only this command (GAP-1897).
    outcome = _apply_to_running_gateway(app, needs_restart=True, restart=restart, quiet=False)
    click.echo("  " + _GATEWAY_OUTCOMES[outcome])
    if outcome in _GATEWAY_UNCONFIRMED:
        raise SystemExit(1)


@guardrail.command("validate-pack")
@click.argument("path", type=click.Path(path_type=str))
@click.option(
    "--json",
    "json_out",
    is_flag=True,
    help="Emit the versioned validation result as deterministic JSON.",
)
def validate_pack_cmd(path: str, json_out: bool) -> None:
    """Validate rule pack PATH without starting or contacting the gateway.

    The installed ``defenseclaw-gateway`` binary performs the authoritative
    schema, fallback, category, and Go/RE2 pattern checks. Invalid packs exit
    non-zero. Python only validates and renders the versioned helper protocol;
    it never substitutes an independent validator.
    """
    from defenseclaw import rulepack_validation

    if not path.strip():
        raise click.UsageError("PATH must not be empty.")

    try:
        result = rulepack_validation.validate_rule_pack(path)
    except rulepack_validation.RulePackValidationBridgeError as exc:
        if json_out:
            click.echo(
                json.dumps(
                    rulepack_validation.bridge_error_wire(exc),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        else:
            click.echo(
                "Rule pack validation unavailable: " + str(exc),
                err=True,
            )
        raise SystemExit(2) from exc

    if json_out:
        click.echo(
            json.dumps(
                result.to_wire_dict(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    elif result.valid:
        summary = result.summary or {}
        click.echo(
            "Rule pack valid: " + rulepack_validation.safe_display_path(path)
        )
        click.echo(
            "  rules: "
            f"{summary['enabled_rule_count']}/{summary['rule_count']} enabled "
            f"across {summary['rule_file_count']} files"
        )
        click.echo(
            "  components: "
            f"judges={summary['judge_count']} "
            f"judge_categories={summary['judge_category_count']} "
            f"local_patterns={summary['local_pattern_count']} "
            f"suppressions={summary['suppression_count']} "
            f"sensitive_tools={summary['sensitive_tool_count']}"
        )
        click.echo(f"  digest: {summary['digest']}")
        click.echo(f"  files digest: {summary['files_digest']} (the guardrail.custom_packs pin)")
    else:
        issue = result.error
        assert issue is not None
        click.echo(
            "Rule pack invalid: " + rulepack_validation.safe_display_path(path),
            err=True,
        )
        click.echo(
            f"  {issue.code} at {issue.path}: {issue.reason}",
            err=True,
        )

    if not result.valid:
        raise SystemExit(1)


@guardrail.command("list-packs")
@click.option("--json", "json_out", is_flag=True, help="Print the rule packs as JSON.")
@pass_ctx
def list_packs_cmd(app: AppContext, json_out: bool) -> None:
    """List the available guardrail rule packs and who enforces which.

    Shows the built-in presets, custom packs found under
    ``<policy_dir>/guardrail/`` or configured anywhere, and the resolved
    rule-pack directory each active connector is actually enforcing
    (per-connector override > global pack > built-in default). Switch packs
    with ``defenseclaw guardrail use-pack``. Read-only — it changes nothing.
    """
    from defenseclaw import policy_catalog

    if json_out:
        click.echo(
            json.dumps(
                {
                    "version": 1,
                    "global": policy_catalog.global_pack(app.cfg).to_json(),
                    "connectors": [row.to_json() for row in policy_catalog.effective_packs(app.cfg)],
                    "packs": [pack.to_json() for pack in policy_catalog.discover_rule_packs(app.cfg)],
                },
                indent=2,
            )
        )
        return

    gc = app.cfg.guardrail
    ux.section("Guardrail rule packs", indent="  ")

    ux.echo(f"  • {ux._style('built-in presets:', fg='bright_black', bold=True)}")
    for pname, desc in _RULE_PACK_PRESETS:
        click.echo(f"      - {ux.accent(pname)}: {ux.dim(desc)}")
    click.echo()

    try:
        custom = [p for p in policy_catalog.discover_rule_packs(app.cfg) if p.kind == "custom"]
    except Exception:  # noqa: BLE001 — discovery is best-effort in a listing.
        custom = []
    if custom:
        ux.echo(f"  • {ux._style('custom packs:', fg='bright_black', bold=True)}")
        for pack in custom:
            used = f" (used by {', '.join(pack.used_by)})" if pack.used_by else ""
            click.echo(f"      - {ux.accent(pack.name)}: {pack.path}{ux.dim(used)}")
        click.echo()

    global_dir = str((gc.effective_rule_pack_dir() if hasattr(gc, "effective_rule_pack_dir") else "") or "").strip()
    ux.echo(
        f"  • {ux._style('global rule-pack dir:', fg='bright_black', bold=True)} "
        + (ux.accent(global_dir) if global_dir else ux.dim("(built-in default)"))
    )

    # Per-connector resolved dirs: which pack each active connector enforces.
    # Mirrors the roster in `guardrail status`; an empty dir means the
    # built-in default pack.
    connector = _resolve_active_connector(app.cfg)
    try:
        actives = (
            list(app.cfg.active_connectors())
            if hasattr(app.cfg, "active_connectors")
            else [connector]
        )
    except Exception:  # noqa: BLE001 — fall back to the primary connector.
        actives = [connector]
    configured = (
        app.cfg.has_connector_configured()
        if hasattr(app.cfg, "has_connector_configured")
        else True
    )
    click.echo()
    # G5 parity: don't fabricate a phantom openclaw row when nothing is set up.
    if not actives and not configured:
        ux.echo(
            f"  • {ux._style('per connector:', fg='bright_black', bold=True)} "
            f"{ux.dim('(none configured)')}"
        )
        click.echo()
        return
    if not actives:
        actives = [connector]

    ux.echo(f"  • {ux._style('per connector:', fg='bright_black', bold=True)}")
    for name in actives:
        rp_dir = (
            (
                gc.effective_rule_pack_dir(name)
                if hasattr(gc, "effective_rule_pack_dir")
                else global_dir
            )
            or ""
        ).strip()
        shown = ux.accent(rp_dir) if rp_dir else ux.dim("(built-in default)")
        click.echo(f"      - {_connector_label(name)} ({name}): {shown}")
    click.echo()


#: How a saved rule-pack / mode change reached the running gateway (also the
#: ``gateway`` field of the ``--json`` results).
_GATEWAY_OUTCOMES = {
    "restarted": "Restarted the gateway; it applies the change now.",
    "live": "The running gateway applies it now.",
    "not_running": "The gateway isn't running; it loads this when it starts.",
    "guardrail_off": "The guardrail is off; this takes effect when you run defenseclaw guardrail enable.",
    "restart_needed": (
        "The running gateway keeps the previous setting until you restart it: defenseclaw-gateway restart."
    ),
    "restart_failed": (
        "The change is saved, but the gateway restart failed; run defenseclaw-gateway restart, "
        "then defenseclaw doctor."
    ),
    "still_starting": (
        "The change is saved. The gateway is still starting and was kept running, so protection is "
        "not confirmed yet; check it with: defenseclaw-gateway status (restart it only if it does "
        "not become healthy)."
    ),
}
#: Outcomes that leave the change unconfirmed: the command exits 1.
_GATEWAY_UNCONFIRMED = frozenset({"restart_failed", "still_starting"})


def _resolve_scope_connector(app: AppContext, connector: str) -> tuple[str, str]:
    """``(config key, "")`` for an active connector, else ``(name, problem)``.

    A single-connector install (no ``guardrail.connectors`` map) accepts its
    one active connector: an override block for it keeps the active set.
    """
    key = _resolve_member_connector(app, connector)
    if key is not None:
        return key, ""
    requested = normalize_connector(connector)
    try:
        actives = [normalize_connector(c) for c in app.cfg.active_connectors()]
    except Exception:  # noqa: BLE001 — treat an unreadable roster as empty.
        actives = []
    if not (getattr(app.cfg.guardrail, "connectors", None) or {}) and requested in actives:
        return requested, ""
    return requested, (
        f"{connector!r} is not an active connector here (active: {', '.join(actives) or 'none'}); nothing was changed."
    )


def _connector_block_for_write(gc, key: str):
    """The ``guardrail.connectors[key]`` override block, created if missing."""
    conns = getattr(gc, "connectors", None)
    if conns is None:
        conns = {}
        gc.connectors = conns
    block = conns.get(key)
    if block is None:
        from defenseclaw.config import PerConnectorGuardrailConfig

        block = PerConnectorGuardrailConfig()
        conns[key] = block
    return block


def _cursor_stays_fail_closed(gc, name: str) -> bool:
    """Cursor's hook contract fails closed in action mode whatever is saved."""
    if normalize_connector(name) != "cursor":
        return False
    try:
        return (gc.effective_mode(name) or "").strip().lower() == "action"
    except Exception:  # noqa: BLE001 — an unknown connector keeps the saved value.
        return False


def _disabled_on_its_own(gc, name: str) -> bool:
    """Whether *name* was turned off with `guardrail disable --connector` (no hooks)."""
    return hasattr(gc, "effective_enabled") and not gc.effective_enabled(name)


def _gateway_running(app: AppContext) -> bool:
    # Same probe as cmd_setup._is_pid_alive, without importing cmd_setup.
    from defenseclaw.process_liveness import pid_file_alive

    try:
        return pid_file_alive(os.path.join(app.cfg.data_dir, "gateway.pid"))
    except Exception:  # noqa: BLE001 — an unreadable PID file means "not running".
        return False


_STOPPED_NOTE_KEY = "defenseclaw.guardrail.stopped_gateway_note"


def _note_applies_on_start(what: str) -> None:
    """A saved change for a stopped gateway, which is never started here (GAP-1370).

    The audit step that follows every caller prints this together with the
    skipped audit event, so the user reads one note instead of two overlapping
    "gateway isn't running" lines (GAP-1718).
    """
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        _echo_stopped_gateway_note(what, audit_skipped=False)
        return
    ctx.meta[_STOPPED_NOTE_KEY] = what


def _pop_stopped_gateway_note() -> str | None:
    ctx = click.get_current_context(silent=True)
    return ctx.meta.pop(_STOPPED_NOTE_KEY, None) if ctx is not None else None


def _echo_stopped_gateway_note(what: str | None, *, audit_skipped: bool) -> None:
    if not what:
        ux.echo(
            "  ⚠ The gateway isn't running, so the audit event was not recorded; "
            "the change applies when it starts (defenseclaw-gateway start).",
            err=True,
        )
        return
    tail = "; the audit event was not recorded" if audit_skipped else ""
    ux.echo(
        f"  ⚠ The gateway isn't running, so it was left stopped: the {what} applies when it starts "
        f"(defenseclaw-gateway start){tail}.",
        err=True,
    )


def _apply_to_running_gateway(app: AppContext, *, needs_restart: bool, restart: bool, quiet: bool) -> str:
    """Make a saved guardrail change reach a running gateway; returns the outcome.

    The gateway reloads config.yaml and swaps in a new configuration
    generation (levels, packs, rules, mode, profiles), so most changes are
    ``live``. Only what setup bakes into installed hooks (enablement, hook
    fail mode) or a listener needs ``needs_restart``; a stopped gateway is
    never started here. ``quiet`` sends the restart progress to stderr so
    ``--json`` stdout stays parseable.
    """
    if not getattr(app.cfg.guardrail, "enabled", False):
        return "guardrail_off"
    if not _gateway_running(app):
        return "not_running"
    if not needs_restart:
        return "live"
    if not restart:
        return "restart_needed"
    import contextlib
    import sys

    from defenseclaw.commands import cmd_setup

    with contextlib.redirect_stdout(sys.stderr) if quiet else contextlib.nullcontext():
        restarted = cmd_setup._restart_defense_gateway(app.cfg.data_dir, start_if_stopped=False)
    if restarted:
        return "restarted"
    return "still_starting" if cmd_setup._take_gateway_left_starting() else "restart_failed"


def _log_guardrail_change(app: AppContext, operation: str, details: str) -> None:
    """Audit a saved change; a stopped or refusing gateway only skips the event.

    The gateway admits only registered audit actions (internal/audit/actions.go),
    so these changes are recorded as a ``config-update`` Activity mutation whose
    target and diff name the setting (``config:guardrail-mode:codex``,
    ``mode: observe -> action``); a plain action lost the details (GAP-1217).
    """
    from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError

    pending = _pop_stopped_gateway_note()
    if not app.logger:
        if pending:
            _echo_stopped_gateway_note(pending, audit_skipped=False)
        return
    try:
        app.logger.log_config_change(operation, details)
    except CanonicalObservabilityUnavailableError:
        _echo_stopped_gateway_note(pending, audit_skipped=True)
        return
    except CanonicalObservabilityError as exc:
        ux.echo(f"  ⚠ Change saved, but the gateway did not confirm the audit event ({exc}).", err=True)
    if pending:
        _echo_stopped_gateway_note(pending, audit_skipped=False)


def _log_guardrail_action(app: AppContext, action: str, details: str) -> None:
    """Record the audit event of an already saved guardrail change.

    The change is on disk before this runs, so a stopped gateway (for example
    after ``defenseclaw-gateway stop``) or a refused event only skips the audit
    event with one plain line; it never fails the command with a traceback.
    """
    from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError

    pending = _pop_stopped_gateway_note()
    if not app.logger:
        if pending:
            _echo_stopped_gateway_note(pending, audit_skipped=False)
        return
    try:
        app.logger.log_action(action, "config", details)
    except CanonicalObservabilityUnavailableError:
        _echo_stopped_gateway_note(pending, audit_skipped=True)
        return
    except CanonicalObservabilityError as exc:
        ux.echo(f"  ⚠ Change saved, but the gateway did not confirm the audit event ({exc}).", err=True)
    if pending:
        _echo_stopped_gateway_note(pending, audit_skipped=False)


# ---------------------------------------------------------------------------
# guardrail use-pack / protection / rule / suppress — config.yaml keys only
# ---------------------------------------------------------------------------
#
# The rule pack a scope uses and its customisation live in config.yaml:
# guardrail[.connectors.C|.profiles.P[.connectors.C]].{rule_pack, rules}. The
# gateway composes the pack in memory and swaps it in on its next reload
# (it watches config.yaml), so none of these commands touch a rule file or
# restart the gateway.

_RULE_PACK_NAME = re.compile(r"[^a-z0-9_-]+")
#: A rule id as the shipped packs spell it: ``SEC-AWS-KEY``, ``exec.remote_ip_download_execute_same_artifact``.
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _cli_actor() -> str:
    """``cli:<os-user>``, the writer's actor for a CLI change."""
    from defenseclaw import config_writer

    try:
        import getpass

        user = getpass.getuser()
    except Exception:  # noqa: BLE001 — no account name is still a CLI change.
        user = "unknown"
    return f"{config_writer.ACTOR_PREFIX_CLI}{user}"


def _scope_key(connector_key: str | None, profile: str | None) -> str:
    """Dotted config path of a guardrail scope block."""
    key = "guardrail"
    if profile:
        key += f".profiles.{profile}"
    if connector_key:
        key += f".connectors.{connector_key}"
    return key


def _scope_block(cfg, connector_key: str | None, profile: str | None):
    """The config block of a scope (None when it isn't written yet)."""
    block = cfg.guardrail
    if profile:
        block = (getattr(block, "profiles", None) or {}).get(profile)
        if block is None:
            return None
    if connector_key:
        block = (getattr(block, "connectors", None) or {}).get(connector_key)
    return block


def _scope_rules(cfg, connector_key: str | None, profile: str | None):
    block = _scope_block(cfg, connector_key, profile)
    return getattr(block, "rules", None) if block is not None else None


def _scope_words(connector_key: str | None, profile: str | None) -> str:
    if profile and connector_key:
        return f"{_connector_label(connector_key)} in profile {profile}"
    if profile:
        return f"profile {profile}"
    if connector_key:
        return _connector_label(connector_key)
    return "every connector"


def _write_guardrail_config(app: AppContext, changes, reason: str, fail) -> object:
    """Apply *changes* through the config writer; *fail(exit_code, message)*
    reports a refused or failed write and exits."""
    from defenseclaw import config_writer

    try:
        return config_writer.apply(
            changes, _cli_actor(), reason, path=str(config_path_for_data_dir(app.cfg.data_dir))
        )
    except config_writer.ManagedConfigWriteError:
        from defenseclaw.enforce.asset_lists import audit_managed_refusal

        audit_managed_refusal("guardrail-config", getattr(changes[0], "path", "") or "guardrail", f"command={reason}")
        fail(
            3,
            "This device is managed: change the guardrail in the admin config (MDM or management plane). "
            "Nothing was changed.",
        )
    except config_writer.ConfigWriteError as exc:
        fail(1, f"Failed to save config: {config_writer.plain_error(exc)}")
    return None


def _registered_pack_names(gc: object) -> str:
    """The guardrail.custom_packs names use-pack accepts, for the unknown-pack message."""
    names = sorted(getattr(gc, "custom_packs", None) or {})
    return f"not a registered guardrail.custom_packs name ({', '.join(names)})" if names else (
        "not a registered guardrail.custom_packs name (none registered)"
    )


def _applied_note(app: AppContext, result: object) -> str:
    """How the change reaches the gateway, with the config generation."""
    generation = getattr(result, "generation", 0)
    stamp = f" (config generation {generation})" if generation else ""
    if not getattr(app.cfg.guardrail, "enabled", False):
        return f"Saved{stamp}. The guardrail is off; this takes effect when you run defenseclaw guardrail enable."
    if not _gateway_running(app):
        return f"Saved{stamp}. The gateway isn't running; it loads this when it starts."
    return f"Saved{stamp}. The running gateway applies it on its next reload."


def _resolve_profile(app: AppContext, profile: str | None, fail) -> str | None:
    if not profile:
        return None
    name = profile.strip()
    if name not in (getattr(app.cfg.guardrail, "profiles", None) or {}):
        fail(1, f"There's no guardrail profile called {name!r}. Nothing was changed.")
    return name


_scope_options = [
    click.option("--connector", "connector", default=None, help="Only this connector."),
    click.option("--profile", "profile", default=None, help="Only subjects of this guardrail profile."),
]


def _with_scope_options(fn):
    for option in reversed(_scope_options):
        fn = option(fn)
    return fn


@guardrail.command("use-pack")
@click.argument("pack", required=False)
@click.option(
    "--connector",
    "connector",
    default=None,
    help="Switch only this connector (writes its guardrail.connectors entry).",
)
@click.option(
    "--clear",
    is_flag=True,
    help="With --connector: drop that connector's pack so it uses the global one.",
)
@click.option(
    "--no-validate",
    "no_validate",
    is_flag=True,
    help="Skip validating a built-in pack (a custom pack is always validated: its digest is pinned).",
)
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def use_pack_cmd(
    app: AppContext,
    pack: str | None,
    connector: str | None,
    clear: bool,
    no_validate: bool,
    json_out: bool,
) -> None:
    """Switch the guardrail rule pack, globally or for one connector.

    PACK is a built-in preset (default, strict, permissive), a key of
    ``guardrail.custom_packs`` (a pack you already registered), the name of a
    pack under ``<policy_dir>/guardrail/``, or a directory path (``./NAME``
    for a folder in the current directory that shares a pack's name). It is
    written as ``guardrail.rule_pack``; a custom directory is also pinned as
    ``guardrail.custom_packs.NAME`` with its validated digest, so an edited
    pack is refused until it is pinned again. Without ``--connector`` every
    connector uses PACK and per-connector packs are removed. ``--clear
    --connector X`` removes X's pack. The running gateway picks it up on its
    next reload; nothing is restarted.
    """
    from defenseclaw import config_writer, policy_catalog, rulepack_validation

    def _finish(
        *,
        ok: bool,
        exit_code: int,
        message: str,
        pack_name: str = "",
        path: str = "",
        cleared: list[str] | None = None,
        validation: dict | None = None,
        warning: str = "",
    ) -> None:
        if json_out:
            click.echo(
                json.dumps(
                    {
                        "version": 1,
                        "ok": ok,
                        "scope": scope,
                        "connector": connector_key,
                        "pack": pack_name,
                        "path": path,
                        "cleared_overrides": list(cleared or []),
                        "validation": validation,
                        "message": message,
                    },
                    indent=2,
                )
            )
        else:
            if warning:
                ux.warn(warning, indent="  ")
            (ux.ok if ok else ux.err)(message, indent="  ")
        if exit_code:
            raise SystemExit(exit_code)

    def _fail(exit_code: int, message: str) -> None:
        _finish(ok=False, exit_code=exit_code, message=message)

    scope = "connector" if connector else "global"
    connector_key: str | None = None
    gc = app.cfg.guardrail

    if clear and not connector:
        raise click.UsageError("--clear needs --connector NAME (the global pack can't be cleared, only switched).")
    if clear and pack:
        raise click.UsageError("Pass either PACK or --clear, not both.")
    if not clear and not (pack or "").strip():
        raise click.UsageError("Missing PACK: a preset (default, strict, permissive) or a rule-pack directory.")

    if connector:
        connector_key, problem = _resolve_scope_connector(app, connector)
        if problem:
            _fail(1, problem)

    if clear:
        block = (getattr(gc, "connectors", None) or {}).get(connector_key)
        previous = policy_catalog.configured_pack_dir(app.cfg, block)
        fallback = policy_catalog.global_pack(app.cfg)
        if not previous:
            _finish(
                ok=True,
                exit_code=0,
                pack_name=fallback.pack,
                path=fallback.path,
                message=(
                    f"{_connector_label(connector_key)} has no rule pack of its own; it already uses the global pack."
                ),
            )
            return
        _preflight_config_write(app)
        key = _scope_key(connector_key, None)
        result = _write_guardrail_config(
            app,
            [
                config_writer.Change(f"{key}.rule_pack", unset=True),
                config_writer.Change(f"{key}.rule_pack_dir", unset=True),
            ],
            f"guardrail use-pack --clear --connector {connector_key}",
            _fail,
        )
        previous_name = policy_catalog.pack_name_for_path(app.cfg, previous)[0]
        _log_guardrail_change(
            app, "guardrail-use-pack", f"scope={connector_key} pack={fallback.pack} previous={previous_name}"
        )
        _finish(
            ok=True,
            exit_code=0,
            pack_name=fallback.pack,
            path=fallback.path,
            message=(
                f"{_connector_label(connector_key)} now uses the global rule pack '{fallback.pack}'. "
                f"{_applied_note(app, result)}"
            ),
        )
        return

    # Resolve PACK -> (name, directory, kind).
    raw = (pack or "").strip()
    registered = (getattr(gc, "custom_packs", None) or {}).get(raw)
    if raw in policy_catalog.RULE_PACK_PRESETS:
        path = policy_catalog.preset_pack_dir(app.cfg, raw)
        pack_name, kind = raw, "preset"
    elif registered is not None:
        # A pack already registered under guardrail.custom_packs: select it by
        # name, keeping its pinned digest (an edited pack is refused below).
        path = policy_catalog.normalize_pack_path(str(getattr(registered, "path", "") or ""))
        pack_name, kind = raw, "registered"
        if not os.path.isdir(path):
            _finish(
                ok=False,
                exit_code=1,
                pack_name=raw,
                path=path,
                message=f"Rule pack {raw!r} is registered at {path}, which isn't a directory. Nothing was changed.",
            )
    else:
        candidate = policy_catalog.normalize_pack_path(raw)
        # A bare name is the installed pack of that name even when the current
        # directory has a folder called NAME; ./NAME selects the folder (GAP-1576).
        bare = not (os.sep in raw or (os.altsep and os.altsep in raw) or raw.startswith(("~", ".")))
        named = (
            [p for p in policy_catalog.discover_rule_packs(app.cfg) if p.name == raw and os.path.isdir(p.path)]
            if bare
            else []
        )
        if named:
            candidate = named[0].path
        elif not os.path.isdir(candidate):
            _finish(
                ok=False,
                exit_code=1,
                pack_name=raw,
                path=candidate,
                message=(
                    f"No rule pack {raw!r}: not a preset ({', '.join(policy_catalog.RULE_PACK_PRESETS)}), "
                    f"{_registered_pack_names(gc)}, and not an existing directory. Nothing was changed."
                ),
            )
        path = candidate
        pack_name, kind = policy_catalog.pack_name_for_path(app.cfg, path)

    if kind == "preset" and not os.path.isdir(path):
        _finish(
            ok=False,
            exit_code=1,
            pack_name=pack_name,
            path=path,
            message=f"The '{pack_name}' preset isn't installed at {path}; run defenseclaw init. Nothing was changed.",
        )

    validation: dict | None = None
    warning = ""
    digest = ""
    if kind != "preset" or not no_validate:
        try:
            result = rulepack_validation.validate_rule_pack(path)
        except rulepack_validation.RulePackValidationBridgeError as exc:
            validation = rulepack_validation.bridge_error_wire(exc)
            if kind != "preset":
                _finish(
                    ok=False,
                    exit_code=2,
                    pack_name=pack_name,
                    path=path,
                    validation=validation,
                    message=f"Can't validate {path} ({exc}), so its digest can't be pinned. Nothing was changed.",
                )
            warning = f"Couldn't validate the built-in '{pack_name}' pack ({exc}); using it anyway."
        else:
            validation = result.to_wire_dict()
            if not result.valid:
                issue = result.error
                detail = f": {issue.code} at {issue.path}: {issue.reason}" if issue is not None else ""
                _finish(
                    ok=False,
                    exit_code=1,
                    pack_name=pack_name,
                    path=path,
                    validation=validation,
                    message=f"Rule pack {path} is invalid{detail}. Nothing was changed.",
                )
            # The pin covers the pack's own files, not the embedded defaults.
            digest = str((result.summary or {}).get("files_digest", "") or "")
            pinned = str(getattr(registered, "digest", "") or "").strip().lower().removeprefix("sha256:")
            if kind == "registered" and digest.lower() != pinned:
                _finish(
                    ok=False,
                    exit_code=1,
                    pack_name=pack_name,
                    path=path,
                    validation=validation,
                    message=(
                        f"Rule pack {pack_name!r} no longer matches the digest registered for it. Review the pack, "
                        f"then pin it: defenseclaw config set guardrail.custom_packs.{pack_name}.digest "
                        f"sha256:{digest}. Nothing was changed."
                    ),
                )

    _preflight_config_write(app)
    changes: list = []
    name = pack_name
    if kind == "custom":
        name = _RULE_PACK_NAME.sub("-", pack_name.lower()).strip("-_")[:64] or "custom"
        if name in policy_catalog.RULE_PACK_PRESETS:
            name = f"custom-{name}"
        changes.append(
            config_writer.Change(f"guardrail.custom_packs.{name}", {"path": path, "digest": f"sha256:{digest}"})
        )
    key = _scope_key(connector_key, None)
    changes.append(config_writer.Change(f"{key}.rule_pack", name))
    changes.append(config_writer.Change(f"{key}.rule_pack_dir", unset=True))
    cleared: list[str] = []
    if connector_key is None:
        for other, block in sorted((getattr(gc, "connectors", None) or {}).items()):
            if policy_catalog.configured_pack_dir(app.cfg, block):
                other_key = _scope_key(other, None)
                changes.append(config_writer.Change(f"{other_key}.rule_pack", unset=True))
                changes.append(config_writer.Change(f"{other_key}.rule_pack_dir", unset=True))
                cleared.append(other)
    previous_pack = (
        policy_catalog.pack_name_for_path(
            app.cfg, policy_catalog.configured_pack_dir(app.cfg, _scope_block(app.cfg, connector_key, None))
        )[0]
        if connector_key and policy_catalog.configured_pack_dir(app.cfg, _scope_block(app.cfg, connector_key, None))
        else policy_catalog.global_pack(app.cfg).pack
    )
    result = _write_guardrail_config(app, changes, f"guardrail use-pack {name}", _fail)
    if connector_key is None:
        message = f"All connectors now use the '{pack_name}' rule pack."
        if cleared:
            message += " Removed per-connector packs for: " + ", ".join(cleared) + "."
    else:
        message = f"{_connector_label(connector_key)} now uses the '{pack_name}' rule pack."
    _log_guardrail_change(
        app,
        "guardrail-use-pack",
        f"scope={connector_key or scope} pack={name} previous={previous_pack}"
        + (f" cleared={','.join(cleared)}" if cleared else ""),
    )
    _finish(
        ok=True,
        exit_code=0,
        pack_name=pack_name,
        path=path,
        cleared=cleared,
        validation=validation,
        warning=warning,
        message=f"{message} {_applied_note(app, result)}",
    )


@guardrail.group("protection")
def protection() -> None:
    """Turn the opt-in protection packs on and off, per scope.

    \b
      list     the packs, and which scopes have which on
      enable   add a pack to a scope's guardrail.rules.protections
      disable  take it out again

    The gateway layers a scope's protection packs on its rule pack in memory
    (a pack's rules replace base rules with the same id). Global ones apply
    to every connector. A pack asserts something about the connector's
    environment (for example that its cloud credentials reach production);
    DefenseClaw takes that as the operator's word and never infers it from
    resource names.
    """


@protection.command("list")
@click.option("--json", "json_out", is_flag=True, help="Print the packs and scopes as JSON.")
@pass_ctx
def protection_list_cmd(app: AppContext, json_out: bool) -> None:
    """List the opt-in protection packs and which scopes have them on.

    Read-only. A scope is the global rule pack or one active connector.
    """
    from defenseclaw import policy_catalog

    packs = policy_catalog.protection_packs()
    scopes = [
        {"scope": row.scope, "pack": row.pack, "path": row.pack_path, "enabled": list(row.protection)}
        for row in policy_catalog.scope_postures(app.cfg)
    ]
    if json_out:
        click.echo(json.dumps({"version": 1, "packs": [p.to_json() for p in packs], "scopes": scopes}, indent=2))
        return

    ux.section("Opt-in protection packs", indent="  ")
    if not packs:
        click.echo(f"  {ux.dim('No protection packs are installed with this DefenseClaw.')}")
    width = max((len(p.name) for p in packs), default=0)
    for pack in packs:
        state = f"{pack.rule_count} rules" if pack.selectable else "staged, not available yet"
        ux.echo(f"  • {ux.accent(pack.name.ljust(width))}  {pack.covers}  {ux.dim('(' + state + ')')}")
    click.echo()
    ux.echo(f"  • {ux._style('on per scope:', fg='bright_black', bold=True)}")
    for scope in scopes:
        who = "global" if scope["scope"] == "global" else f"{_connector_label(scope['scope'])} ({scope['scope']})"
        enabled = ", ".join(scope["enabled"]) or ux.dim("none")
        ux.echo(f"      - {who}: {enabled} {ux.dim('· pack ' + str(scope['pack']))}")
    click.echo()
    ux.subhead(
        "Turn one on with: defenseclaw guardrail protection enable NAME [--connector NAME] [--profile NAME]",
        indent="  ",
    )
    click.echo()


@protection.command("enable")
@click.argument("name")
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def protection_enable_cmd(
    app: AppContext, name: str, connector: str | None, profile: str | None, json_out: bool
) -> None:
    """Turn opt-in protection pack NAME on for a scope.

    Adds NAME to ``guardrail[.profiles.P][.connectors.C].rules.protections``.
    See ``defenseclaw guardrail protection list`` for the pack names.
    """
    _change_protection(app, name, connector, profile, enable=True, json_out=json_out)


@protection.command("disable")
@click.argument("name")
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def protection_disable_cmd(
    app: AppContext, name: str, connector: str | None, profile: str | None, json_out: bool
) -> None:
    """Turn opt-in protection pack NAME off for a scope."""
    _change_protection(app, name, connector, profile, enable=False, json_out=json_out)


def _change_protection(
    app: AppContext,
    name: str,
    connector: str | None,
    profile: str | None,
    *,
    enable: bool,
    json_out: bool,
) -> None:
    from defenseclaw import config_writer, policy_catalog

    scope = "global"
    connector_key: str | None = None

    def _finish(*, ok: bool, exit_code: int, message: str, protection: tuple[str, ...] | list[str] = ()) -> None:
        if json_out:
            click.echo(
                json.dumps(
                    {
                        "version": 1,
                        "ok": ok,
                        "scope": scope,
                        "profile": profile_name,
                        "protection": list(protection),
                        "message": message,
                    },
                    indent=2,
                )
            )
        else:
            (ux.ok if ok else ux.err)(message, indent="  ")
        if exit_code:
            raise SystemExit(exit_code)

    def _fail(exit_code: int, message: str) -> None:
        _finish(ok=False, exit_code=exit_code, message=message)

    profile_name: str | None = None
    profile_name = _resolve_profile(app, profile, _fail)
    if connector:
        if profile_name:
            connector_key = normalize_connector(connector)
        else:
            connector_key, problem = _resolve_scope_connector(app, connector)
            if problem:
                _fail(1, problem)
        scope = normalize_connector(connector_key)

    packs = policy_catalog.protection_packs()
    pack = next((p for p in packs if p.name == name), None)
    if pack is None:
        available = ", ".join(p.name for p in packs if p.selectable) or "none on this install"
        _fail(1, f"There's no opt-in protection pack called {name!r} (available: {available}). Nothing was changed.")
    if not pack.selectable:
        _fail(
            1,
            f"{pack.title} ({pack.name}) is staged, not available yet: it has no rules DefenseClaw "
            "can enforce. Nothing was changed.",
        )

    where = _scope_words(connector_key, profile_name)
    rules = _scope_rules(app.cfg, connector_key, profile_name)
    on_now = [str(n) for n in (getattr(rules, "protections", None) or [])]
    if (name in on_now) == enable:
        state = "on" if enable else "off"
        _finish(
            ok=True,
            exit_code=0,
            protection=on_now,
            message=f"{pack.title} is already {state} for {where}; nothing was changed.",
        )
        return

    wanted = (set(on_now) | {name}) if enable else (set(on_now) - {name})
    order = {p.name: index for index, p in enumerate(packs)}
    desired = sorted(wanted, key=lambda n: order.get(n, len(order)))
    path = f"{_scope_key(connector_key, profile_name)}.rules.protections"
    change = config_writer.Change(path, desired) if desired else config_writer.Change(path, unset=True)
    _preflight_config_write(app)
    verb = "enable" if enable else "disable"
    result = _write_guardrail_config(app, [change], f"guardrail protection {verb} {name}", _fail)
    _log_guardrail_change(
        app,
        "guardrail-protection",
        f"scope={_scope_key(connector_key, profile_name)} pack={name} enabled={str(enable).lower()} "
        f"protection={','.join(desired)}",
    )
    message = f"{pack.title} is {'on' if enable else 'off'} for {where}."
    if enable:
        message += (
            f" Only keep it on if it's true for {where}: DefenseClaw takes the pack as your word "
            "about that environment and blocks what it proves there."
        )
    _finish(ok=True, exit_code=0, protection=desired, message=f"{message} {_applied_note(app, result)}")


@guardrail.group("rule")
def rule_group() -> None:
    """Turn individual rules on or off, or change their severity, per scope.

    \b
      enable    guardrail.rules.enable += ID
      disable   guardrail.rules.disable += ID
      severity  guardrail.rules.severity_overrides[ID] = SEVERITY

    IDs are case-sensitive, as the pack spells them. An ID the scope's rule
    pack doesn't have is refused by the gateway when it reloads (the previous
    configuration keeps running).
    """


def _rule_ids(rules, field: str) -> list[str]:
    return [str(v) for v in (getattr(rules, field, None) or []) if str(v or "").strip()]


def _change_rule_lists(
    app: AppContext, rule_id: str, connector: str | None, profile: str | None, *, enable: bool, json_out: bool
) -> None:
    from defenseclaw import config_writer

    def _fail(exit_code: int, message: str) -> None:
        if json_out:
            click.echo(json.dumps({"version": 1, "ok": False, "rule": rule_id, "message": message}, indent=2))
        else:
            ux.err(message, indent="  ")
        raise SystemExit(exit_code)

    rule_id = rule_id.strip()
    if not _RULE_ID.fullmatch(rule_id):
        _fail(1, f"{rule_id!r} isn't a rule ID (letters, digits, ., _ and -). Nothing was changed.")
    profile_name = _resolve_profile(app, profile, _fail)
    connector_key = None
    if connector:
        if profile_name:
            connector_key = normalize_connector(connector)
        else:
            connector_key, problem = _resolve_scope_connector(app, connector)
            if problem:
                _fail(1, problem)
    rules = _scope_rules(app.cfg, connector_key, profile_name)
    add_to, remove_from = ("enable", "disable") if enable else ("disable", "enable")
    target = _rule_ids(rules, add_to)
    other = _rule_ids(rules, remove_from)
    key = _scope_key(connector_key, profile_name)
    changes = []
    if rule_id not in target:
        changes.append(config_writer.Change(f"{key}.rules.{add_to}", [*target, rule_id]))
    if rule_id in other:
        rest = [v for v in other if v != rule_id]
        changes.append(
            config_writer.Change(f"{key}.rules.{remove_from}", rest)
            if rest
            else config_writer.Change(f"{key}.rules.{remove_from}", unset=True)
        )
    where = _scope_words(connector_key, profile_name)
    state = "on" if enable else "off"
    if not changes:
        message = f"Rule {rule_id} is already turned {state} for {where}; nothing was changed."
        result = None
    else:
        _preflight_config_write(app)
        result = _write_guardrail_config(app, changes, f"guardrail rule {add_to} {rule_id}", _fail)
        _log_guardrail_change(app, "guardrail-rule", f"scope={key} rule={rule_id} {add_to}=true")
        message = f"Rule {rule_id} is turned {state} for {where}. {_applied_note(app, result)}"
    if json_out:
        click.echo(json.dumps({"version": 1, "ok": True, "rule": rule_id, "scope": key, "message": message}, indent=2))
    else:
        ux.ok(message, indent="  ")


@rule_group.command("enable")
@click.argument("rule_id")
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def rule_enable_cmd(app: AppContext, rule_id: str, connector: str | None, profile: str | None, json_out: bool) -> None:
    """Turn rule RULE_ID on for a scope (guardrail.rules.enable)."""
    _change_rule_lists(app, rule_id, connector, profile, enable=True, json_out=json_out)


@rule_group.command("disable")
@click.argument("rule_id")
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def rule_disable_cmd(app: AppContext, rule_id: str, connector: str | None, profile: str | None, json_out: bool) -> None:
    """Turn rule RULE_ID off for a scope (guardrail.rules.disable)."""
    _change_rule_lists(app, rule_id, connector, profile, enable=False, json_out=json_out)


@rule_group.command("severity")
@click.argument("rule_id")
@click.argument("severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "default"], case_sensitive=False))
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def rule_severity_cmd(
    app: AppContext, rule_id: str, severity: str, connector: str | None, profile: str | None, json_out: bool
) -> None:
    """Set rule RULE_ID's severity for a scope; ``default`` removes the override."""
    from defenseclaw import config_writer

    def _fail(exit_code: int, message: str) -> None:
        if json_out:
            click.echo(json.dumps({"version": 1, "ok": False, "rule": rule_id, "message": message}, indent=2))
        else:
            ux.err(message, indent="  ")
        raise SystemExit(exit_code)

    rule_id = rule_id.strip()
    if not _RULE_ID.fullmatch(rule_id):
        _fail(1, f"{rule_id!r} isn't a rule ID (letters, digits, ., _ and -). Nothing was changed.")
    profile_name = _resolve_profile(app, profile, _fail)
    connector_key = normalize_connector(connector) if connector else None
    if connector and not profile_name:
        connector_key, problem = _resolve_scope_connector(app, connector)
        if problem:
            _fail(1, problem)
    # A dotted ID (exec.remote_ip_...) is one key, not a path of keys.
    overrides = config_writer.parse_path(f"{_scope_key(connector_key, profile_name)}.rules.severity_overrides")
    key = config_writer.format_path((*overrides, rule_id))
    level = severity.upper()
    change = config_writer.Change(key, unset=True) if level == "DEFAULT" else config_writer.Change(key, level)
    _preflight_config_write(app)
    result = _write_guardrail_config(app, [change], f"guardrail rule severity {rule_id} {level}", _fail)
    scope_key = _scope_key(connector_key, profile_name)
    _log_guardrail_change(app, "guardrail-rule", f"scope={scope_key} rule={rule_id} severity={level}")
    what = "keeps its pack severity" if level == "DEFAULT" else f"is {level}"
    message = f"Rule {rule_id} {what} for {_scope_words(connector_key, profile_name)}. {_applied_note(app, result)}"
    if json_out:
        payload = {"version": 1, "ok": True, "rule": rule_id, "severity": level, "message": message}
        click.echo(json.dumps(payload, indent=2))
    else:
        ux.ok(message, indent="  ")


@guardrail.group("suppress")
def suppress_group() -> None:
    """Add or remove finding suppressions (guardrail.rules.suppressions)."""


@suppress_group.command("add")
@click.argument("suppression_id")
@click.option("--finding", "finding_pattern", required=True, help="Finding IDs to suppress (regular expression).")
@click.option(
    "--entity", "entity_pattern", default="", help="Only when the matched value fits this regular expression."
)
@click.option("--reason", required=True, help="Why this is safe to suppress (recorded in config.yaml).")
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def suppress_add_cmd(
    app: AppContext,
    suppression_id: str,
    finding_pattern: str,
    entity_pattern: str,
    reason: str,
    connector: str | None,
    profile: str | None,
    json_out: bool,
) -> None:
    """Add suppression SUPPRESSION_ID to a scope."""
    _change_suppression(
        app,
        suppression_id,
        connector,
        profile,
        entry={
            "id": suppression_id.strip().upper(),
            "finding_pattern": finding_pattern,
            "entity_pattern": entity_pattern,
            "reason": reason,
        },
        json_out=json_out,
    )


@suppress_group.command("remove")
@click.argument("suppression_id")
@_with_scope_options
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def suppress_remove_cmd(
    app: AppContext, suppression_id: str, connector: str | None, profile: str | None, json_out: bool
) -> None:
    """Remove suppression SUPPRESSION_ID from a scope."""
    _change_suppression(app, suppression_id, connector, profile, entry=None, json_out=json_out)


def _change_suppression(
    app: AppContext,
    suppression_id: str,
    connector: str | None,
    profile: str | None,
    *,
    entry: dict | None,
    json_out: bool,
) -> None:
    from defenseclaw import config_writer

    sid = suppression_id.strip().upper()

    def _done(ok: bool, exit_code: int, message: str) -> None:
        if json_out:
            click.echo(json.dumps({"version": 1, "ok": ok, "suppression": sid, "message": message}, indent=2))
        else:
            (ux.ok if ok else ux.err)(message, indent="  ")
        if exit_code:
            raise SystemExit(exit_code)

    def _fail(exit_code: int, message: str) -> None:
        _done(False, exit_code, message)

    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{0,127}", sid):
        _fail(1, f"{sid!r} isn't a suppression ID (letters, digits, _ and -). Nothing was changed.")
    profile_name = _resolve_profile(app, profile, _fail)
    connector_key = normalize_connector(connector) if connector else None
    if connector and not profile_name:
        connector_key, problem = _resolve_scope_connector(app, connector)
        if problem:
            _fail(1, problem)
    rules = _scope_rules(app.cfg, connector_key, profile_name)
    current = [
        {
            "id": str(getattr(s, "id", "")),
            "finding_pattern": str(getattr(s, "finding_pattern", "")),
            "entity_pattern": str(getattr(s, "entity_pattern", "")),
            "reason": str(getattr(s, "reason", "")),
        }
        for s in (getattr(rules, "suppressions", None) or [])
    ]
    exists = any(s["id"] == sid for s in current)
    where = _scope_words(connector_key, profile_name)
    if entry is not None and exists:
        _fail(1, f"Suppression {sid} already exists for {where}; remove it first. Nothing was changed.")
    if entry is None and not exists:
        _done(True, 0, f"There's no suppression {sid} for {where}; nothing was changed.")
        return
    if entry is not None:
        clean = {k: v for k, v in entry.items() if v}
        updated = [*current, clean]
    else:
        updated = [s for s in current if s["id"] != sid]
    updated = [{k: v for k, v in s.items() if v} for s in updated]
    path = f"{_scope_key(connector_key, profile_name)}.rules.suppressions"
    change = config_writer.Change(path, updated) if updated else config_writer.Change(path, unset=True)
    _preflight_config_write(app)
    verb = "add" if entry is not None else "remove"
    result = _write_guardrail_config(app, [change], f"guardrail suppress {verb} {sid}", _fail)
    _log_guardrail_change(app, "guardrail-suppress", f"scope={_scope_key(connector_key, profile_name)} id={sid} {verb}")
    state = "added" if entry is not None else "removed"
    _done(True, 0, f"Suppression {sid} {state} for {where}. {_applied_note(app, result)}")


# ---------------------------------------------------------------------------
# guardrail mode — observe vs action without re-running setup
# ---------------------------------------------------------------------------


@guardrail.command("mode")
@click.argument("mode", required=False, type=click.Choice(["observe", "action"]))
@click.option(
    "--connector",
    "connector",
    default=None,
    help="Set only this connector's mode (writes its per-connector override).",
)
@click.option(
    "--clear",
    is_flag=True,
    help="With --connector: drop that connector's mode override so it follows the global mode.",
)
@_restart_option
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def mode_cmd(
    app: AppContext, mode: str | None, connector: str | None, clear: bool, restart: bool, json_out: bool
) -> None:
    """Switch the guardrail between observe (log only) and action (enforce).

    Sets only ``guardrail.mode``, or with ``--connector X`` only
    ``guardrail.connectors.X.mode`` (creating that block if needed); ``--clear
    --connector X`` removes X's override. The guardrail's on/off state, rule
    pack and port are never touched. A connector without its own fail mode
    fails open in observe mode and uses the global hook fail mode
    (``guardrail fail-mode``) in action mode; the command says when that
    changes. The running gateway applies a mode change on its next reload.
    A changed hook fail mode is re-rendered into the hook scripts of Claude
    Code, Codex, Amp and OpenCode in place; the other hook connectors need a
    gateway restart (``--no-restart`` to skip; a stopped gateway is never
    started).
    """
    from defenseclaw import policy_catalog

    if clear and not connector:
        raise click.UsageError("--clear needs --connector NAME (the global mode can't be cleared, only switched).")
    if clear and mode:
        raise click.UsageError("Pass either MODE or --clear, not both.")
    if not clear and not mode:
        raise click.UsageError("Missing MODE: observe or action.")

    gc = app.cfg.guardrail
    scope = "global"
    connector_key: str | None = None

    def _effective(key: str | None) -> str:
        return policy_catalog.mode_label(gc.effective_mode(key) if key else gc.mode)

    def _finish(
        *,
        ok: bool,
        exit_code: int,
        message: str,
        new_mode: str = "",
        previous: str = "",
        source: str = "",
        changed: bool = False,
        not_covered: list[str] | None = None,
        gateway: str | None = None,
        notes: list[str] | None = None,
        **_ignored: object,
    ) -> None:
        if json_out:
            click.echo(
                json.dumps(
                    {
                        "version": 1,
                        "ok": ok,
                        "scope": scope,
                        "mode": new_mode,
                        "previous": previous,
                        "mode_source": source,
                        "changed": changed,
                        "not_covered": list(not_covered or []),
                        "gateway": gateway,
                        "message": message,
                    },
                    indent=2,
                )
            )
        else:
            (ux.ok if ok else ux.warn if gateway == "still_starting" else ux.err)(message, indent="  ")
            for note in notes or []:
                ux.subhead(note, indent="    ")
        if exit_code:
            raise SystemExit(exit_code)

    if connector:
        connector_key, problem = _resolve_scope_connector(app, connector)
        scope = normalize_connector(connector_key)
        if problem:
            _finish(ok=False, exit_code=1, message=problem)

    try:
        actives = [str(c) for c in app.cfg.active_connectors()]
    except Exception:  # noqa: BLE001 — treat an unreadable roster as empty.
        actives = []

    def _override(key: str) -> str:
        block = gc._connector_override(key) if hasattr(gc, "_connector_override") else None
        return (getattr(block, "mode", "") or "").strip() if block is not None else ""

    affected = [connector_key] if connector_key else [c for c in actives if not _override(c)]
    fail_before = {c: gc.effective_hook_fail_mode(c) for c in affected}
    previous = _effective(connector_key)

    if connector_key is None:
        if (gc.mode or "").strip() == mode:
            _finish(
                ok=True,
                exit_code=0,
                new_mode=previous,
                previous=previous,
                source="global",
                message=f"The global guardrail mode is already {mode}; nothing was changed.",
            )
            return
    elif clear:
        if not _override(connector_key):
            _finish(
                ok=True,
                exit_code=0,
                new_mode=previous,
                previous=previous,
                source="global",
                message=(
                    f"{_connector_label(scope)} has no mode override; it already follows the global mode ({previous})."
                ),
            )
            return
    elif _override(connector_key) == mode:
        _finish(
            ok=True,
            exit_code=0,
            new_mode=previous,
            previous=previous,
            source="override",
            message=f"{_connector_label(scope)} is already in {mode} mode; nothing was changed.",
        )
        return

    # The gateway refuses to start a connector in action mode when its
    # installed version is not verified against a hook contract (for example
    # after an observe-mode quickstart that never probed it). Probe, and record
    # the discovery evidence the gateway reads, before saving, so the switch
    # either works or changes nothing.
    becomes_action = mode == "action" or (clear and policy_catalog.mode_label(gc.mode) == "action")
    if becomes_action:
        from defenseclaw.commands.cmd_setup import _check_connector_version_supported_for_setup

        unverified = [
            c
            for c in affected
            if policy_catalog.mode_label(gc.effective_mode(c)) != "action"
            and not _check_connector_version_supported_for_setup(
                c, mode="action", emit=not json_out, data_dir=app.cfg.data_dir, _allow_prompt=False
            )
        ]
        if unverified:
            names = ", ".join(_connector_label(c) for c in unverified)
            _finish(
                ok=False,
                exit_code=1,
                new_mode=previous,
                previous=previous,
                message=(
                    f"Nothing was changed: {names} can't run in action mode because its installed "
                    "version could not be verified against a DefenseClaw hook contract, so the "
                    "gateway would refuse to start it."
                ),
                notes=[
                    "Fix what the check above reports (see: defenseclaw agent discover --refresh), "
                    f"then run: defenseclaw guardrail mode action{f' --connector {scope}' if connector_key else ''}"
                ],
            )
    _preflight_config_write(app)
    if connector_key is None:
        gc.mode = mode
    elif clear:
        _connector_block_for_write(gc, connector_key).mode = ""
    else:
        _connector_block_for_write(gc, connector_key).mode = mode
    new_mode = _effective(connector_key)
    source = "override" if connector_key and not clear else "global"
    fail_after = {c: gc.effective_hook_fail_mode(c) for c in affected}
    fail_flips = {c: fm for c, fm in fail_after.items() if fm != fail_before[c]}
    if fail_flips:
        # Only hook connectors bake a fail mode into their registration.
        from defenseclaw.commands.cmd_setup import _HOOK_ENFORCED_CONNECTORS

        fail_flips = {c: fm for c, fm in fail_flips.items() if normalize_connector(c) in _HOOK_ENFORCED_CONNECTORS}

    try:
        app.cfg.save()
    except (OSError, ValueError) as exc:
        _finish(ok=False, exit_code=1, new_mode=previous, previous=previous, message=f"Failed to save config: {exc}")
    _log_guardrail_change(
        app, "guardrail-mode", f"scope={scope} mode={new_mode} previous={previous} cleared={str(clear).lower()}"
    )
    # Decisions read the gateway's live configuration generation, so a mode
    # change reloads hot. A hook fail mode that flipped is baked into the hook
    # script: connectors with a runtime registration are re-rendered in place,
    # as ``guardrail fail-mode`` does, and only the rest (or a failed
    # re-render) restart the gateway so it re-bakes them.
    needs_restart = {c for c in fail_flips if normalize_connector(c) not in _RUNTIME_FAIL_MODE_CONNECTORS}
    if fail_flips and gc.enabled:
        for c in set(fail_flips) - needs_restart:
            try:
                reconcile_connector_registration(app.cfg, c)
            except OSError:
                needs_restart.add(c)
    outcome = _apply_to_running_gateway(app, needs_restart=bool(needs_restart), restart=restart, quiet=json_out)

    plain = {"action": "blocks findings at or above the block-at severity", "observe": "logs findings, blocks nothing"}
    if connector_key is None:
        message = f"The global guardrail mode is now {new_mode}: it {plain[new_mode]}."
        not_covered = [c for c in actives if _override(c) and policy_catalog.mode_label(_override(c)) != new_mode]
    elif clear:
        message = f"{_connector_label(scope)} follows the global mode again ({new_mode}: it {plain[new_mode]})."
        not_covered = []
    else:
        message = f"{_connector_label(scope)} is now in {new_mode} mode: it {plain[new_mode]}."
        not_covered = []
    consequence = {
        "closed": "the action is blocked if the hook can't reach the gateway",
        "open": "the action goes ahead if the hook can't reach the gateway",
    }
    notes = [
        f"Hook failures for {_connector_label(c)} now fail {fm}: {consequence.get(fm, fm)}."
        for c, fm in fail_flips.items()
    ]
    notes.extend(
        f"{_connector_label(c)} keeps its own mode ({policy_catalog.mode_label(_override(c))}); "
        f"change it with: defenseclaw guardrail mode {new_mode} --connector {c}"
        for c in not_covered
    )
    _finish(
        ok=outcome not in _GATEWAY_UNCONFIRMED,
        exit_code=1 if outcome in _GATEWAY_UNCONFIRMED else 0,
        new_mode=new_mode,
        previous=previous,
        source=source,
        changed=True,
        not_covered=not_covered,
        gateway=outcome,
        notes=notes,
        message=f"{message} {_GATEWAY_OUTCOMES[outcome]}",
    )


_LEVEL_CHOICES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "inherit")
_LEVEL_WORDS = {
    "block_at": {
        "noun": "block",
        "command": "block-at",
        "does": "blocks tool calls, prompts and LLM traffic at",
        "done": "are blocked at",
    },
    "alert_at": {
        "noun": "alert",
        "command": "alert-at",
        "does": "alerts on tool calls, prompts and LLM traffic at",
        "done": "raise an alert at",
    },
}
_LEVEL_SOURCE_WORDS = {"override": "its own", "global": "the global", "pack": "its rule pack's"}


def _set_tool_call_level(app: AppContext, setting: str, level: str, connector: str | None, *, json_out: bool) -> None:
    """``guardrail block-at`` / ``alert-at``: set one scope's guardrail level.

    Writes only ``guardrail.<setting>`` or ``guardrail.connectors.<C>.<setting>``
    (``inherit`` clears it); precedence and clamp are the gateway's
    (``policy_catalog.resolve_levels``). The running gateway applies it on
    its next reload.
    """
    from defenseclaw import policy_catalog

    words = _LEVEL_WORDS[setting]
    noun = words["noun"]
    gc = app.cfg.guardrail
    value = "" if level.lower() == "inherit" else level.upper()
    scope = "global"
    connector_key: str | None = None

    def _own(key: str | None) -> str:
        block = gc if key is None else gc._connector_override(key)
        return policy_catalog.level_value(getattr(block, setting, "")) if block is not None else ""

    def _levels() -> policy_catalog.ScopeLevels:
        return policy_catalog.scope_levels(app.cfg, connector_key or "")

    def _setting(levels: policy_catalog.ScopeLevels) -> tuple[str, str, int]:
        """``(effective label, source, rank)`` of this command's setting."""
        if setting == "block_at":
            return levels.block_at, levels.block_source, levels.block_rank
        return levels.alert_at, levels.alert_source, levels.alert_rank

    def _finish(
        *,
        ok: bool,
        exit_code: int,
        message: str,
        previous: str,
        gateway: str | None = None,
        notes: list[str] | None = None,
        requested: bool = False,
    ) -> None:
        levels = _levels()
        if json_out:
            click.echo(
                json.dumps(
                    {
                        "version": 1,
                        "ok": ok,
                        "scope": scope,
                        "setting": setting,
                        # A failure reports the level asked for; nothing was written.
                        "level": (value if requested else _own(connector_key)) or "inherit",
                        "previous": previous or "inherit",
                        "source": _setting(levels)[1],
                        "effective_block_at": levels.block_at,
                        "effective_alert_at": levels.alert_at,
                        "gateway": gateway,
                        "message": message,
                    },
                    indent=2,
                )
            )
        else:
            (ux.ok if ok else ux.warn if gateway == "still_starting" else ux.err)(message, indent="  ")
            for note in notes or []:
                ux.subhead(note, indent="    ")
        if exit_code:
            raise SystemExit(exit_code)

    if connector:
        connector_key, problem = _resolve_scope_connector(app, connector)
        scope = normalize_connector(connector_key)
        if problem:
            # Not a connector here: it stores nothing, and would follow the global default.
            connector_key = None
            _finish(ok=False, exit_code=1, message=problem, previous="", requested=True)
    subject = f"{_connector_label(scope)} ({scope})" if connector_key else ""

    previous = _own(connector_key)
    if previous == value:
        label, source, _rank = _setting(_levels())
        if connector_key and value:
            message = f"{subject} already has its own {noun} level, {value}; nothing was changed."
        elif connector_key:
            message = (
                f"{subject} has no {noun} level of its own; it already follows "
                f"{_LEVEL_SOURCE_WORDS[source]} {noun} level ({label}); nothing was changed."
            )
        elif value:
            message = f"The global {noun} level is already {value}; nothing was changed."
        else:
            message = (
                f"No global {noun} level is set, so each connector uses its own or its rule pack's; "
                "nothing was changed."
            )
        _finish(ok=True, exit_code=0, message=message, previous=previous)
        return

    try:
        actives = [str(c) for c in app.cfg.active_connectors()]
    except Exception:  # noqa: BLE001 — treat an unreadable roster as empty.
        actives = []
    # A global value replaces the level of every connector without its own,
    # whatever its rule pack says: remember them to name the ones it loosens.
    followers = {} if connector_key else {c: _setting(policy_catalog.scope_levels(app.cfg, c)) for c in actives}
    global_rank = _setting(_levels())[2]

    _preflight_config_write(app)
    target = gc if connector_key is None else _connector_block_for_write(gc, connector_key)
    setattr(target, setting, value)
    try:
        app.cfg.save()
    except (OSError, ValueError) as exc:
        setattr(target, setting, previous)
        _finish(ok=False, exit_code=1, message=f"Failed to save config: {exc}", previous=previous, requested=True)
    _log_guardrail_change(
        app,
        f"guardrail-{words['command']}",
        f"scope={scope} {setting}={value or 'inherit'} previous={previous or 'inherit'}",
    )
    # One threshold model: every guardrail surface reads the level from the
    # gateway's live configuration generation, so it reloads hot.
    outcome = _apply_to_running_gateway(app, needs_restart=False, restart=False, quiet=json_out)

    levels = _levels()
    label, source, _rank = _setting(levels)
    if connector_key and value:
        message = f"{subject} now {words['does']} {label}."
    elif connector_key:
        message = f"{subject} follows {_LEVEL_SOURCE_WORDS[source]} {noun} level again: {label}."
    elif value:
        message = (
            f"The global {noun} level is now {value}: tool calls, prompts and LLM traffic {words['done']} {label} "
            "unless a connector has its own."
        )
    else:
        pack = policy_catalog.global_pack(app.cfg).pack
        message = (
            f"The global {noun} level is cleared: each connector without its own uses its rule pack's "
            f"({label} for the {pack} pack)."
        )
    notes: list[str] = []
    if levels.alert_clamped:
        notes.append(
            f"Alerts start at {levels.alert_at}, not {policy_catalog.level_label(levels.wanted_alert_rank)}: "
            "anything that blocks also alerts."
        )
    if connector_key and policy_catalog.mode_label(gc.effective_mode(connector_key)) != "action":
        notes.append(
            f"{_connector_label(scope)} is in observe mode, so it only logs; the levels apply once it's in action mode."
        )
    elif not connector_key and policy_catalog.mode_label(gc.mode) != "action":
        notes.append(
            "The global mode is observe, so connectors that follow it only log; "
            "the levels apply once they're in action mode."
        )
    for name, (old_label, _old_source, old_rank) in followers.items():
        own = _own(name)
        if own:
            notes.append(
                f"{_connector_label(name)} ({name}) keeps its own {noun} level ({own}); change it with: "
                f"defenseclaw guardrail {words['command']} {value or 'inherit'} --connector {name}"
            )
            continue
        new_label, _new_source, new_rank = _setting(policy_catalog.scope_levels(app.cfg, name))
        # Only a connector whose own rule pack set a different level than the
        # global default's is loosened behind the operator's back.
        if new_rank > old_rank and old_rank != global_rank:
            notes.append(
                f"{_connector_label(name)} ({name}) now {words['does']} {new_label} instead of {old_label}; "
                f"keep it with: defenseclaw guardrail {words['command']} "
                f"{policy_catalog.level_name(old_rank)} --connector {name}"
            )
    _finish(
        ok=outcome not in _GATEWAY_UNCONFIRMED,
        exit_code=1 if outcome in _GATEWAY_UNCONFIRMED else 0,
        message=f"{message} {_GATEWAY_OUTCOMES[outcome]}",
        previous=previous,
        gateway=outcome,
        notes=notes,
    )


def _level_command(setting: str):
    words = _LEVEL_WORDS[setting]

    @click.argument("level", metavar="LEVEL", type=click.Choice(_LEVEL_CHOICES, case_sensitive=False))
    @click.option(
        "--connector",
        "connector",
        default=None,
        help=f"Set only this connector's {words['noun']} level (writes its per-connector override).",
    )
    @click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
    @pass_ctx
    def command(app: AppContext, level: str, connector: str | None, json_out: bool) -> None:
        _set_tool_call_level(app, setting, level, connector, json_out=json_out)

    return command


block_at_cmd = guardrail.command(
    "block-at",
    help="""Set the lowest severity at which the guardrail blocks.

    LEVEL is CRITICAL, HIGH, MEDIUM or LOW (any case), or inherit to clear
    the value. Sets only ``guardrail.block_at``, or with ``--connector X``
    only ``guardrail.connectors.X.block_at``. A connector's own level wins
    over the global one, which wins over the rule pack's (strict blocks
    MEDIUM+, default and permissive CRITICAL). The level applies in action
    mode to every guardrail surface: prompts, completions and tool calls,
    on hooks and through the guardrail proxy. The running gateway applies
    it on its next reload.
    """,
)(_level_command("block_at"))

alert_at_cmd = guardrail.command(
    "alert-at",
    help="""Set the lowest severity at which the guardrail raises an alert.

    LEVEL is CRITICAL, HIGH, MEDIUM or LOW (any case), or inherit to clear
    the value. Sets only ``guardrail.alert_at``, or with ``--connector X``
    only ``guardrail.connectors.X.alert_at``; precedence and reload work
    like ``guardrail block-at``. Anything that blocks also
    alerts, so an alert level above the block level alerts from the block
    level instead (strict packs alert on LOW+, default MEDIUM+, permissive
    HIGH+).
    """,
)(_level_command("alert_at"))


# ---------------------------------------------------------------------------
# guardrail profile — identity-based guardrail profiles (read-only)
# ---------------------------------------------------------------------------


@guardrail.group("profile")
def profile_group() -> None:
    """Show identity-based guardrail profiles and which one a subject gets.

    \b
      list     the profiles, their assignments and the default
      show     one profile's settings
      explain  which profile a user, connector or agent resolves to

    Profiles live under ``guardrail.profiles`` in config.yaml; assignments
    are tried in order and the first match wins. Only verified identities
    select a profile, so ``explain`` asks the running gateway.
    """


def _profile_settings(profile) -> dict:
    out: dict = {}
    for key in ("description", "mode", "block_at", "alert_at", "rule_pack", "rule_pack_dir", "block_message"):
        value = getattr(profile, key, "")
        if value:
            out[key] = value
    if profile.hilt is not None:
        out["hilt"] = {"enabled": profile.hilt.enabled, "min_severity": profile.hilt.min_severity}
    if profile.connectors:
        out["connectors"] = {
            name: {
                key: value
                for key, value in (
                    ("mode", pc.mode),
                    ("block_at", pc.block_at),
                    ("alert_at", pc.alert_at),
                    ("rule_pack", getattr(pc, "rule_pack", "")),
                    ("rule_pack_dir", pc.rule_pack_dir),
                    ("block_message", pc.block_message),
                )
                if value
            }
            | ({"hilt": {"enabled": pc.hilt.enabled, "min_severity": pc.hilt.min_severity}} if pc.hilt else {})
            for name, pc in sorted(profile.connectors.items())
        }
    return out


def _assignment_json(assignment) -> dict:
    match = {
        key: list(values)
        for key, values in (
            ("groups", assignment.match.groups),
            ("users", assignment.match.users),
            ("connectors", assignment.match.connectors),
            ("agents", assignment.match.agents),
        )
        if values
    }
    return {"profile": assignment.profile, "match": match}


def _gateway_profile_warnings(app: AppContext) -> list[str]:
    """What the running gateway warns about the configured assignments.

    Empty when the gateway is not running: ``profile list`` works from the
    config file alone and only adds what the gateway can see (a group the
    host no longer knows).
    """
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    try:
        client = OrchestratorClient(
            host=gateway_api_client_host(app.cfg),
            port=app.cfg.gateway.api_port,
            token=app.cfg.gateway.resolved_token(),
            timeout=5,
        )
        try:
            result = client.guardrail_profile_resolve()
        finally:
            client.close()
    except Exception:  # noqa: BLE001 - no gateway, no extra warnings.
        return []
    return [str(note) for note in result.get("warnings") or []]


@profile_group.command("list")
@click.option("--json", "json_out", is_flag=True, help="Print the profiles as JSON.")
@pass_ctx
def profile_list_cmd(app: AppContext, json_out: bool) -> None:
    """List the guardrail profiles, their ordered assignments and the default."""
    gc = app.cfg.guardrail
    payload = {
        "version": 1,
        "profiles": {name: _profile_settings(gc.profiles[name]) for name in sorted(gc.profiles)},
        "assignments": [_assignment_json(a) for a in gc.profile_assignments],
        "default_profile": gc.default_profile,
    }
    warnings = _gateway_profile_warnings(app) if gc.profile_assignments else []
    if warnings:
        payload["warnings"] = warnings
    if json_out:
        click.echo(json.dumps(payload, indent=2))
        return
    ux.section("Guardrail profiles", indent="  ")
    if not gc.profiles:
        click.echo(f"  {ux.dim('No guardrail profiles are configured; guardrail.* applies to everyone.')}")
        click.echo()
        return
    for name in sorted(gc.profiles):
        profile = gc.profiles[name]
        summary = ", ".join(
            f"{key}={value}"
            for key, value in _profile_settings(profile).items()
            if key not in {"description", "connectors", "hilt"}
        )
        detail = ux.dim("(" + (summary or "inherits everything") + ")")
        ux.echo(f"  • {ux.accent(name)}  {profile.description or ''} {detail}")
    click.echo()
    ux.echo(f"  • {ux._style('assignments (first match wins):', fg='bright_black', bold=True)}")
    if not gc.profile_assignments:
        click.echo(f"      {ux.dim('none')}")
    for index, assignment in enumerate(gc.profile_assignments, start=1):
        match = "; ".join(f"{key}={','.join(values)}" for key, values in _assignment_json(assignment)["match"].items())
        ux.echo(f"      {index}. {assignment.profile} ← {match}")
    default = gc.default_profile or ux.dim("none (guardrail.* applies)")
    ux.echo(f"  • {ux._style('default:', fg='bright_black', bold=True)} {default}")
    for note in warnings:
        ux.warn(note, indent="  ")
    click.echo()


@profile_group.command("show")
@click.argument("name")
@click.option("--json", "json_out", is_flag=True, help="Print the profile as JSON.")
@pass_ctx
def profile_show_cmd(app: AppContext, name: str, json_out: bool) -> None:
    """Show one guardrail profile's settings and where it is assigned."""
    gc = app.cfg.guardrail
    profile = gc.profiles.get(name)
    if profile is None:
        known = ", ".join(sorted(gc.profiles)) or "none"
        ux.err(f"No guardrail profile named {name!r} (configured: {known}).")
        raise SystemExit(1)
    payload = {
        "version": 1,
        "name": name,
        "settings": _profile_settings(profile),
        "assignments": [_assignment_json(a) for a in gc.profile_assignments if a.profile == name],
        "default": gc.default_profile == name,
    }
    if json_out:
        click.echo(json.dumps(payload, indent=2))
        return
    ux.section(f"Guardrail profile {name}", indent="  ")
    settings = payload["settings"]
    if not settings:
        click.echo(f"  {ux.dim('Sets nothing; inherits guardrail.* for its subjects.')}")
    for key, value in settings.items():
        if isinstance(value, dict):
            value = json.dumps(value, sort_keys=True)
        click.echo(f"  {key}: {value}")
    assigned = payload["assignments"]
    click.echo(f"  assigned by: {len(assigned)} assignment(s){' and default_profile' if payload['default'] else ''}")
    click.echo()


def _age_text(seconds) -> str:
    """A short age such as ``45s`` or ``7m``."""
    seconds = int(seconds or 0)
    return f"{seconds}s" if seconds < 60 else f"{seconds // 60}m"


# How long explain waits for the gateway. The gateway looks the user up in the
# directory before it answers, and that lookup is bounded at 20 s (and the
# account lookup before it at 10 s), so the client waits longer than both.
PROFILE_EXPLAIN_TIMEOUT_SECONDS = 35


@profile_group.command("explain")
@click.option("--user", "user", default="", help="Account name, uid or SID to resolve (default: you).")
@click.option("--connector", "connector", default="", help="Connector the request would come from.")
@click.option("--agent", "agent", default="", help="Agent identity (agt-...) the request would carry.")
@click.option("--json", "json_out", is_flag=True, help="Print the resolution as JSON.")
@pass_ctx
def profile_explain_cmd(app: AppContext, user: str, connector: str, agent: str, json_out: bool) -> None:
    """Explain which guardrail profile a subject resolves to, and why.

    Asks the running gateway (loopback, gateway token), which resolves the
    user through the operating system the way it does for live requests.
    Without --user it explains the account running the command, also for
    --connector and --agent, as live requests always carry a user.
    """
    import getpass

    import requests

    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    if not user:
        try:
            user = getpass.getuser()
        except Exception:  # noqa: BLE001 - fall through to the error below.
            user = ""
        if not (user or connector or agent):
            ux.err("Name at least one of --user, --connector or --agent.")
            raise SystemExit(2)
    try:
        client = OrchestratorClient(
            host=gateway_api_client_host(app.cfg),
            port=app.cfg.gateway.api_port,
            token=app.cfg.gateway.resolved_token(),
            timeout=PROFILE_EXPLAIN_TIMEOUT_SECONDS,
        )
        try:
            result = client.guardrail_profile_resolve(user=user, connector=connector, agent=agent)
        finally:
            client.close()
    except requests.exceptions.ReadTimeout:
        # The gateway took the connection and is still resolving the user: it
        # is running, so "start it" would send the operator the wrong way.
        ux.err(
            f"The gateway did not answer within {PROFILE_EXPLAIN_TIMEOUT_SECONDS:g} s; "
            f"the directory lookup for {user or 'this account'} may be slow (SSSD or the domain controller). Try again."
        )
        raise SystemExit(1) from None
    except Exception as exc:  # noqa: BLE001 - report any transport or HTTP failure
        ux.err(f"Could not ask the gateway: {exc}")
        ux.subhead("Start it with: defenseclaw-gateway start", indent="  ")
        raise SystemExit(1) from None
    if json_out:
        click.echo(json.dumps(result, indent=2, sort_keys=True))
        return
    ux.section("Guardrail profile resolution", indent="  ")
    if not result.get("profiles_configured"):
        click.echo(f"  {ux.dim('No guardrail profiles are configured; guardrail.* applies.')}")
    subject = result.get("subject") or {}
    if subject:
        who = subject.get("upn") or subject.get("principal") or subject.get("user_name") or user
        groups = "groups unknown" if result.get("lookup_error") else f"{int(subject.get('group_count') or 0)} group(s)"
        click.echo(f"  user:    {who} ({groups})")
    profile = result.get("profile") or ux.dim("none (guardrail.* applies)")
    click.echo(f"  profile: {profile}")
    if result.get("match"):
        reason = result["match"]
        if result.get("matched_group"):
            reason += f" ({result['matched_group']})"
        click.echo(f"  match:   {reason}")
    if result.get("digest"):
        click.echo(f"  digest:  {result['digest']}")
    cache = result.get("cache") or {}
    if cache:
        age = int(cache.get("age_seconds") or 0)
        lifetime = age + int(cache.get("refresh_after_seconds") or 0)
        click.echo(
            f"  cache:   requests use directory facts {_age_text(age)} old "
            f"(profile {cache.get('profile') or 'none'}, match {cache.get('match')}); "
            f"the gateway refreshes them after {_age_text(lifetime)}"
        )
    if result.get("lookup_error"):
        ux.warn(f"user lookup failed: {result['lookup_error']}")
    for note in result.get("warnings") or []:
        ux.warn(str(note))
    if (result.get("directory") or {}).get("message"):
        ux.warn(str(result["directory"]["message"]))
    effective = result.get("effective") or {}
    if effective:
        scope = result.get("connector") or "global"
        hilt = effective.get("hilt") or {}
        click.echo(
            f"  applies ({scope}): mode={effective.get('mode', '')} block_at={effective.get('block_at') or 'pack'} "
            f"alert_at={effective.get('alert_at') or 'pack'} hilt={'on' if hilt.get('enabled') else 'off'} "
            f"rule_pack={effective.get('rule_pack_dir') or 'default'}"
        )
    click.echo()


# Register `defenseclaw guardrail judge` (hook-lane judge gate). The
# judge is opt-in per hook connector via
# ``guardrail.judge.hook_connectors`` — ``guardrail judge
# add/remove/list`` is the authoring surface for that gate so operators
# never have to hand-edit config.yaml. It lives here rather than under
# ``setup`` because it is a day-to-day policy lever like ``hilt`` and
# ``fail-mode``. cmd_judge keeps the same lazy-import discipline as
# this module (see its docstring).
from defenseclaw.commands.cmd_judge import judge as _judge_group  # noqa: E402

guardrail.add_command(_judge_group)
