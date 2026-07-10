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
  defenseclaw guardrail fail-mode      # open vs closed on hook failures
  defenseclaw guardrail hilt           # human-in-the-loop prompting
  defenseclaw guardrail block-message  # message shown when an action is blocked

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

import os
import shutil

import click

from defenseclaw import ux
from defenseclaw.config import _assert_config_write_allowed, config_path_for_data_dir
from defenseclaw.connector_contracts import normalize_connector
from defenseclaw.context import AppContext, pass_ctx

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
    "windsurf": "Windsurf",
    "geminicli": "Gemini CLI",
    "copilot": "GitHub Copilot CLI",
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "omnigent": "OmniGent",
}


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
    if restart:
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

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

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
        )
        ux.ok(f"{label} connector {action} complete", indent="  ")
        click.echo()

    if app.logger:
        app.logger.log_action(
            f"guardrail-{verb}",
            "config",
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
      fail-mode      open vs closed when a hook fails
      hilt           human-in-the-loop prompting
      block-message  message shown when an action is blocked
      list-packs     list rule packs + the dir each connector enforces

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


@guardrail.command("status")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the roster to a single active connector (multi-connector installs). "
    "Omit to show every active connector.",
)
@pass_ctx
def status_cmd(app: AppContext, connector_flag: str | None) -> None:
    """Show whether the guardrail is enabled and the active connector roster.

    The roster is rendered UNIFORMLY: one per-connector block for EACH
    active connector, with that connector's own (possibly differing)
    enabled state, mode, and fail mode. ``Config.active_connectors()``
    returns one name on a single-connector install and N on a fan-out
    install, so the exact same layout covers both — the operator never has
    to reason about connector count. There is no separate single-vs-multi
    rendering and no "primary" connector line.

    The connector row is the source of truth for hook posture: enabled state,
    mode, fail mode, rule pack, HILT, effective hook scan strategy, and judge
    state are shown together so the scan strategy cannot contradict the judge
    gate. ``--connector X`` narrows the roster to one active peer. When no
    connector is set up, status renders an explicit "none configured" state
    rather than a phantom ``openclaw``.
    """
    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)
    fail_mode = (getattr(gc, "hook_fail_mode", "") or "open").lower()
    ux.section("Guardrail status", indent="  ")
    enabled_txt = "yes" if gc.enabled else "no"
    enabled_val = ux._style(enabled_txt, fg="green") if gc.enabled else ux._style(enabled_txt, fg="yellow")
    click.echo(f"  • {ux._style('enabled:', fg='bright_black', bold=True)}    {enabled_val}")

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
        click.echo(
            f"  • {ux._style('connectors:', fg='bright_black', bold=True)} "
            f"{ux.dim('(none configured)')}"
        )
        ux.subhead(
            "No connector configured — run 'defenseclaw setup <connector>' to "
            "enable enforcement.",
            indent="    ",
        )
        click.echo(f"  • {ux._style('port:', fg='bright_black', bold=True)}       {gc.port}")
        click.echo()
        return
    if not actives:
        # Older config without active_connectors() but a connector IS set
        # (has_connector_configured true) — keep the legacy single-connector
        # floor so those installs still render their one block.
        actives = [connector]

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
    for name in actives:
        cmode = gc.effective_mode(name) if hasattr(gc, "effective_mode") else (gc.mode or "observe")
        cfm = (
            gc.effective_hook_fail_mode(name)
            if hasattr(gc, "effective_hook_fail_mode")
            else fail_mode
        )
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
        cfm_display = _style_fail_mode(cfm)
        # Each connector can scan against its OWN rule pack (per-connector
        # override, else the global pack); surface it so the roster shows which
        # policy each peer is enforcing. Empty dir = the built-in default pack.
        rp_dir = (
            gc.effective_rule_pack_dir(name)
            if hasattr(gc, "effective_rule_pack_dir")
            else ""
        )
        rule_pack_raw = os.path.basename(rp_dir.rstrip("/")) if rp_dir.strip() else "default"
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
        rows.append(
            {
                "label": (_connector_label(name), _connector_label(name)),
                "key": (name, ux.dim(name)),
                "state": (state_raw, state),
                "mode": (cmode or "observe", _style_mode(cmode or "observe")),
                "fail": (cfm, cfm_display),
                "rule_pack": (rule_pack_raw, rule_pack),
                "hilt": (hilt_raw, hilt_str),
                "scan": (scan_raw, _style_scan_value(scan_raw)),
                "judge": (judge_raw, _style_judge_value(judge_raw)),
            }
        )
    _render_connector_table(rows)
    click.echo(
        f"  • {ux.dim('fail = hook response-layer failures (4xx / bad JSON / missing action)')}"
    )

    click.echo(f"  • {ux._style('port:', fg='bright_black', bold=True)}       {gc.port}")
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

    click.echo()
    click.echo(f"  {ux.bold('Disabling guardrail')} for {_active_connector_display(app.cfg, connector)}")
    if restart:
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

    if not yes and not click.confirm("  Proceed?", default=True):
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
            connectors=_active_connector_set(app.cfg, connector),
        )
        # In a multi-connector install the gateway boot loop tears down
        # EVERY active connector on restart, so report them all rather
        # than implying only the primary was affected.
        _actives = _active_connector_set(app.cfg, connector)
        if len(_actives) > 1:
            ux.ok(
                f"connector teardown complete for {len(_actives)} connectors: "
                + ", ".join(_actives),
                indent="  ",
            )
        else:
            ux.ok(f"{_connector_label(connector)} connector teardown complete", indent="  ")
        click.echo()

    if app.logger:
        app.logger.log_action(
            "guardrail-disable",
            "config",
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
    # work. If model / api_key_env are empty the connector would
    # silently route real traffic through an unconfigured upstream, so
    # we fail fast with a remediation pointer to the full setup flow.
    if not (gc.model or app.cfg.llm.model):
        ux.err("Cannot enable: guardrail.model is not set.", indent="  ")
        ux.subhead("Run 'defenseclaw setup guardrail' to configure first.", indent="    ")
        raise SystemExit(1)

    click.echo()
    click.echo(f"  {ux.bold('Enabling guardrail')} for {_active_connector_display(app.cfg, connector)}")
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

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

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
            connectors=_active_connector_set(app.cfg, connector),
        )
        # The boot loop runs Connector.Setup for EVERY active connector;
        # report them all in a multi-connector install.
        _actives = _active_connector_set(app.cfg, connector)
        if len(_actives) > 1:
            ux.ok(
                f"connector setup complete for {len(_actives)} connectors: "
                + ", ".join(_actives),
                indent="  ",
            )
        else:
            ux.ok(f"{_connector_label(connector)} connector setup complete", indent="  ")
        click.echo()

    if app.logger:
        app.logger.log_action(
            "guardrail-enable",
            "config",
            f"connector={connector} restart={restart}",
        )


def _set_connector_fail_mode(
    app: AppContext, requested: str, mode: str | None, *, restart: bool, yes: bool
) -> None:
    """Show or set the hook fail mode for a SINGLE connector.

    Per-connector analog of the global ``guardrail fail-mode``: writes
    ``guardrail.connectors[X].hook_fail_mode`` so one connector can run a
    different response-layer fail posture than its peers. On restart the Go
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
    has_override = bool(getattr(entry, "hook_fail_mode", "")) if entry is not None else False

    # No mode argument → just report this connector's effective value and
    # whether it is an override or inherited from the global default.
    if mode is None:
        click.echo()
        click.echo(
            f"  {ux.bold(f'{label} ({key}) hook_fail_mode:')} {ux.accent(current)}"
        )
        if has_override:
            ux.subhead(
                f"per-connector override (global default: {global_fm}).", indent="  "
            )
        else:
            ux.subhead(
                f"inherited from global default ({global_fm}).", indent="  "
            )
        click.echo()
        return

    if mode == current:
        click.echo(
            f"  {ux.dim(f'{label} hook fail mode is already')} {mode!r} "
            f"{ux.dim('— nothing to do.')}"
        )
        return

    click.echo()
    click.echo(
        f"  {ux.bold(f'Changing {label} hook fail mode:')} {current} "
        f"{ux.dim('→')} {ux.accent(mode)}"
    )
    if mode == "closed":
        ux.warn(f"Response-layer failures will now BLOCK {label}.", indent="  ")
        ux.subhead(
            "A misconfigured gateway response (4xx, bad JSON) will exit 2 from this "
            "connector's hooks. Make sure your gateway is healthy first.",
            indent="    ",
        )
    else:
        ux.subhead(
            f"Response-layer failures will now ALLOW {label} and log the failure to "
            "~/.defenseclaw/logs/hook-failures.jsonl.",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise click.Abort()

    # Mutate the per-connector entry, preserving its other policy fields.
    from defenseclaw.config import PerConnectorGuardrailConfig

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
        ux.ok(
            f"Gateway restarted, {label} hook regenerated with fail={mode}.", indent="  "
        )
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    if app.logger:
        app.logger.log_action(
            "guardrail-fail-mode",
            "config",
            f"connector={key} scope=per-connector new={mode} restart={restart}",
        )


def _multi_connector_fail_mode_targets(app: AppContext) -> list[str]:
    """Return active connectors for bare fail-mode writes in multi installs."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    if not conns:
        return []
    return [
        name
        for name in _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        if name in conns
    ]


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
    """Show or change the hook fail mode (response-layer behavior).

    The hook fail mode controls what generated hooks do when the
    DefenseClaw gateway answers but the answer is bad — a 4xx, an
    unparseable JSON body, or a missing ``action`` field. Two values
    are supported:

      \b
      open   — allow the tool/prompt and log the failure.
               A misbehaving gateway never bricks your agent.
               Recommended for almost all installs.
      closed — block the tool/prompt on any gateway error.
               Choose for regulated workflows where every prompt
               MUST be inspected.

    Transport-layer failures (gateway unreachable / 5xx) are NOT
    governed by this setting — they always allow unless the agent's
    environment has ``DEFENSECLAW_STRICT_AVAILABILITY=1``. That is
    the dedicated escape hatch for sites that prefer agent downtime
    to a missed inspection during a real outage.

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
        for _name in _actives:
            _eff = (
                gc.effective_hook_fail_mode(_name)
                if hasattr(gc, "effective_hook_fail_mode")
                else current
            )
            _eff_disp = ux._style(_eff, fg="yellow") if _eff == "closed" else _eff
            click.echo(f"      - {_connector_label(_name)} ({_name}): {_eff_disp}")
        click.echo()
        if current == "open":
            ux.subhead(
                "Response-layer failures (4xx, malformed JSON) ALLOW the tool/prompt.",
                indent="  ",
            )
            click.echo(f"  {ux.dim('Switch to closed:')} defenseclaw guardrail fail-mode closed")
        else:
            ux.subhead(
                "Response-layer failures (4xx, malformed JSON) BLOCK the tool/prompt.",
                indent="  ",
            )
            click.echo(f"  {ux.dim('Switch to open:')}   defenseclaw guardrail fail-mode open")
        click.echo()
        ux.subhead(
            "Transport-layer failures (gateway unreachable) always allow unless "
            "DEFENSECLAW_STRICT_AVAILABILITY=1 is set in the agent env.",
            indent="  ",
        )
        click.echo()
        return

    fail_mode_targets = _multi_connector_fail_mode_targets(app)
    target_modes: dict[str, str] = {}
    if fail_mode_targets:
        target_modes = {
            name: (
                gc.effective_hook_fail_mode(name)
                if hasattr(gc, "effective_hook_fail_mode")
                else current
            ).lower()
            for name in fail_mode_targets
        }

    if fail_mode_targets and all(value == mode for value in target_modes.values()):
        click.echo(
            f"  {ux.dim('Hook fail mode is already')} {mode!r} "
            f"{ux.dim('for all active connectors — nothing to do.')}"
        )
        return
    if not fail_mode_targets and mode == current:
        click.echo(f"  {ux.dim('Hook fail mode is already')} {mode!r} {ux.dim('— nothing to do.')}")
        return

    click.echo()
    if fail_mode_targets:
        click.echo(
            f"  {ux.bold('Changing hook fail mode for active connectors:')} "
            f"{ux.accent(mode)}"
        )
        for name in fail_mode_targets:
            old = target_modes.get(name, current)
            if old != mode:
                click.echo(
                    f"      - {_connector_label(name)} ({name}): "
                    f"{old} {ux.dim('→')} {ux.accent(mode)}"
                )
    else:
        click.echo(f"  {ux.bold('Changing hook fail mode:')} {current} {ux.dim('→')} {ux.accent(mode)}")
    if mode == "closed":
        ux.warn(
            "Response-layer failures will now BLOCK the agent.",
            indent="  ",
        )
        ux.subhead(
            "A misconfigured gateway response (4xx, bad JSON) will exit 2 from "
            "every hook. Make sure your gateway is healthy before flipping this.",
            indent="    ",
        )
    else:
        ux.subhead(
            "Response-layer failures will now ALLOW the agent and log the failure to "
            "~/.defenseclaw/logs/hook-failures.jsonl.",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        # click.Abort routes through Click's exception handler and
        # cooperates with the result callbacks the setup group
        # registers (e.g., the auto-restart suppression keyed on
        # _SETUP_RESTART_HANDLED_KEY in cmd_setup.py); a bare
        # SystemExit bypasses that machinery.
        raise click.Abort()

    if fail_mode_targets:
        from defenseclaw.config import PerConnectorGuardrailConfig

        for name in fail_mode_targets:
            entry = gc.connectors.get(name)
            if entry is None:
                entry = PerConnectorGuardrailConfig()
                gc.connectors[name] = entry
            entry.hook_fail_mode = mode
    else:
        gc.hook_fail_mode = mode
    try:
        app.cfg.save()
        if fail_mode_targets:
            ux.ok(
                f"Config saved ({len(fail_mode_targets)} connector hook_fail_mode overrides = {mode})",
                indent="  ",
            )
        else:
            ux.ok(f"Config saved (guardrail.hook_fail_mode = {mode})", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort()

    if restart and gc.enabled:
        connector = _resolve_active_connector(app.cfg)
        # Lazy import via module: see disable_cmd above for rationale.
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
            connectors=_active_connector_set(app.cfg, connector),
        )
        ux.ok("Gateway restarted, hooks regenerated with the new fail mode.", indent="  ")
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    if app.logger:
        app.logger.log_action(
            "guardrail-fail-mode",
            "config",
            (
                f"scope=active-connectors count={len(fail_mode_targets)} new={mode} restart={restart}"
                if fail_mode_targets
                else f"old={current} new={mode} restart={restart}"
            ),
        )


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
        click.echo(
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

    if not yes and not click.confirm("  Proceed?", default=True):
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

    if app.logger:
        app.logger.log_action(
            "guardrail-hilt",
            "config",
            f"connector={key} scope=per-connector "
            f"enabled={str(new_enabled).lower()} min_severity={new_min} restart={restart}",
        )


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
        click.echo(
            f"  {ux.dim('HILT is already')} "
            f"{ux.dim('in the requested state for all active connectors — nothing to do.')}"
        )
        return
    if not hilt_targets and new_enabled == cur_enabled and new_min == cur_min:
        click.echo(
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
            click.echo(
                f"      - {_connector_label(name)} ({name}): "
                f"enabled={str(old_enabled).lower()} {ux.dim('→')} "
                f"{ux.accent(str(desired_enabled).lower())}, "
                f"min_severity={old_min} {ux.dim('→')} {ux.accent(desired_min)}"
            )
    else:
        click.echo(
            f"  {ux.bold('Updating HILT:')} "
            f"enabled={str(cur_enabled).lower()} {ux.dim('→')} "
            f"{ux.accent(str(new_enabled).lower())}, "
            f"min_severity={cur_min} {ux.dim('→')} {ux.accent(new_min)}"
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
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

    # Mirror the global HILT block into the OPA Rego data.json so the
    # Rego/proxy fallback path stays consistent with config.yaml (parity
    # with `setup guardrail`). Best-effort; the gateway reads config.yaml
    # directly for correctness. Per-connector overrides are hook-path only
    # and intentionally not mirrored (data.json is global).
    from defenseclaw.commands import cmd_setup

    if not hilt_targets:
        cmd_setup._sync_guardrail_hilt_to_opa(getattr(app.cfg, "policy_dir", ""), gc)

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

    if app.logger:
        app.logger.log_action(
            "guardrail-hilt",
            "config",
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
        click.echo(
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

    if not yes and not click.confirm("  Proceed?", default=True):
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

    if restart and gc.enabled:
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

    if app.logger:
        app.logger.log_action(
            "guardrail-block-message",
            "config",
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
        click.echo(
            f"  {ux.dim('Block message unchanged for all active connectors — nothing to do.')}"
        )
        return
    if not block_message_targets and new_msg == current:
        click.echo(f"  {ux.dim('Block message unchanged — nothing to do.')}")
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
            click.echo(
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

    if not yes and not click.confirm("  Proceed?", default=True):
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

    if restart and gc.enabled:
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

    if app.logger:
        app.logger.log_action(
            "guardrail-block-message",
            "config",
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


@guardrail.command("list-packs")
@pass_ctx
def list_packs_cmd(app: AppContext) -> None:
    """List the available guardrail rule packs and who enforces which.

    Shows the built-in presets accepted by ``defenseclaw setup <connector>
    --rule-pack`` alongside the resolved rule-pack directory each active
    connector is actually enforcing (per-connector override > global pack >
    built-in default). Read-only — it changes nothing.
    """
    gc = app.cfg.guardrail
    ux.section("Guardrail rule packs", indent="  ")

    click.echo(f"  • {ux._style('built-in presets:', fg='bright_black', bold=True)}")
    for pname, desc in _RULE_PACK_PRESETS:
        click.echo(f"      - {ux.accent(pname)}: {ux.dim(desc)}")
    click.echo()

    global_dir = (getattr(gc, "rule_pack_dir", "") or "").strip()
    click.echo(
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
        click.echo(
            f"  • {ux._style('per connector:', fg='bright_black', bold=True)} "
            f"{ux.dim('(none configured)')}"
        )
        click.echo()
        return
    if not actives:
        actives = [connector]

    click.echo(f"  • {ux._style('per connector:', fg='bright_black', bold=True)}")
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
