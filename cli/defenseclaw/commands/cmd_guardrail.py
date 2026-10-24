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
from collections.abc import Iterator
from contextlib import contextmanager

import click

from defenseclaw import ux
from defenseclaw.config import _assert_config_write_allowed, config_path_for_data_dir
from defenseclaw.config_writer import ConfigWriteError
from defenseclaw.connector_contracts import has_native_approval_prompt, normalize_connector
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.enforce import asset_lists
from defenseclaw.fail_mode import (
    FileSnapshot,
    fail_mode_transaction_lock,
    reconcile_connector_registration,
    registration_integrity_drift,
    resolve_connector_fail_mode,
    restore_fail_mode_transaction,
    snapshot_fail_mode_transaction,
    upstream_fail_open,
    upstream_hook_limit,
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
    "antigravity": "Antigravity",
    "opencode": "OpenCode",
    "amp": "Amp",
    "kiro": "Kiro",
}

_RUNTIME_FAIL_MODE_CONNECTORS = frozenset({"amp", "claudecode", "codex", "opencode"})


def _tracks_runtime_fail_mode(cfg, name: str) -> bool:
    """Whether a fail-mode change must refresh and verify *name*'s installed hooks.

    Copilot CLI, Antigravity and Hermes render the mode into their hook
    outside Secure Client (upstream_hook_limit), so an older hook can still
    render open while config.yaml says closed. Under Secure Client they stay
    open whatever is configured, so there is nothing to refresh.
    """
    key = normalize_connector(name)
    if key in _RUNTIME_FAIL_MODE_CONNECTORS:
        return True
    return bool(upstream_hook_limit(key)) and not upstream_fail_open(cfg, key)



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
    from defenseclaw import config_writer

    cfg_path = str(config_path_for_data_dir(app.cfg.data_dir))
    try:
        with open(cfg_path, "rb") as handle:
            current = handle.read()
    except OSError:
        current = b""
    if config_writer.managed_refuses(current, _cli_actor()):
        # The writer refuses every local actor on a managed standalone host,
        # elevated or not, so do not suggest admin elevation.
        ux.err(config_writer.MANAGED_REFUSAL, indent="  ")
        raise SystemExit(3)
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
        return ""
    configured = getattr(cfg, "has_connector_configured", None)
    if callable(configured) and not configured():
        return ""
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
    return ""


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
    """Return the configured ``guardrail.connectors`` key matching
    ``requested`` (case/alias-insensitive), or ``None`` if it is not a member."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    req = normalize_connector(requested)
    for key in conns:
        if normalize_connector(key) == req:
            return key
    return None


def _active_connector_keys(app: AppContext) -> list[str]:
    """Resolve active names to existing map keys before a bare policy write."""
    return [
        key
        for name in _active_connector_set(app.cfg, _resolve_active_connector(app.cfg))
        if (key := _resolve_member_connector(app, name)) is not None
    ]


def _verify_agents_before_enable(app: AppContext, connectors: list[str]) -> None:
    """Re-verify the agent executables an enable is about to set up.

    Windows admits a connector only against a freshly
    verified agent executable. ``guardrail disable`` removes the connector's
    proof and the short-lived selection from the last setup has expired, so an
    enable that only restarted the gateway left it refusing the connector as
    "agent version not probed" (GAP-0069). A no-op on other hosts. Runs before
    the config is saved, so a failed check changes nothing.
    """
    from defenseclaw.commands import cmd_setup

    cmd_setup._record_windows_setup_agent_selections(app.cfg.data_dir, list(connectors))


def _note_running_agent_restart() -> None:
    """A running agent keeps its previous OTLP token after connector setup."""

    ux.subhead(
        "Restart any running affected agent (for example Codex) to load refreshed OTLP credentials.",
        indent="  ",
    )


def _toggle_connector_guardrail(
    app: AppContext, requested: str, *, enable: bool, restart: bool, yes: bool
) -> None:
    """Enable/disable the guardrail for a SINGLE connector.

    Per-connector analog of the global enable/disable: it flips
    ``guardrail.connectors[X].enabled``; the gateway (its config reload, or
    the restart) runs that one connector's ``Setup``/``Teardown`` via the
    existing set-difference path — the others are untouched. The connector's other
    policy fields (mode/hilt/rule_pack) are retained so re-enable
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

    # With the global switch off the connector stays off whatever its own
    # flag says: this said "already enabled", or saved the flag and reported
    # setup complete, and changed nothing (GAP-0550).
    if enable and not app.cfg.guardrail.enabled:
        ux.err(f"The guardrail is off for every agent, so {label} stays off.", indent="  ")
        ux.subhead(
            f"Run {_turn_on_steps(app.cfg.guardrail, key)} to turn it back on; nothing was changed.",
            indent="    ",
        )
        raise SystemExit(1)

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
            f"--no-restart specified: a running gateway runs the connector {action} from "
            "config.yaml without a restart (Secure Client: at the next restart).",
            indent="  ",
        )
    click.echo()

    if not yes and not _confirm_proceed():
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    if enable and (restart or _gateway_running(app)):
        # A running gateway applies this connector flag on hot reload even
        # with --no-restart, so its agent proof must exist before the save.
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

        # Enable waits for the whole roster the gateway publishes (every
        # enabled connector), not this connector alone: an enabled peer is a
        # normal lock entry, so a wait on just this one rejected it as an
        # unexpected peer and failed after about 3 minutes (GAP-0163).
        roster = (
            [n for n in _active_connector_set(app.cfg, key) if app.cfg.guardrail.effective_enabled(n)]
            if enable
            else None
        )
        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=key,
            connectors=roster,
            teardown=not enable,
            # Report "setup complete" only once the gateway admitted the
            # connector (GAP-0069).
            wait_for_connector_ready=enable,
        )
        ux.ok(f"{label} connector {action} complete", indent="  ")
        click.echo()

    _note_running_agent_restart()
    _log_guardrail_action(
        app,
        f"guardrail-{verb}",
        f"connector={key} scope=per-connector "
        f"enabled={str(enable).lower()} restart={restart}",
    )


class _GuardrailGroup(click.Group):
    """Keep identity profile commands off the Secure Client command tree."""

    def _secure_client(self, ctx: click.Context) -> bool:
        from defenseclaw.commands.cmd_status import _enterprise_profile

        app = ctx.find_object(AppContext)
        cfg = app.cfg if app is not None else None
        if cfg is None:
            from defenseclaw.config import load

            try:
                cfg = load()
            except (OSError, ValueError, RuntimeError):
                return False
        return _enterprise_profile(cfg) == "secure_client"

    def list_commands(self, ctx: click.Context) -> list[str]:
        names = super().list_commands(ctx)
        return [name for name in names if name != "profile"] if self._secure_client(ctx) else names

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        if cmd_name == "profile" and self._secure_client(ctx):
            return None
        return super().get_command(ctx, cmd_name)


@click.group("guardrail", cls=_GuardrailGroup)
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
    gc, rows: list[dict[str, tuple[str, str]]], warnings: list[str], profile: dict | None = None,
    *, secure_client: bool = False,
) -> None:
    """Machine-readable ``guardrail status``: the same fields as the table."""
    import json  # noqa: PLC0415

    keys = ("state", "mode", "fail", "rule_pack", "levels", "hilt", "scan", "judge")
    connectors = []
    for row in rows:
        item = {"connector": row["key"][0], "label": row["label"][0]}
        item.update({("fail_mode" if key == "fail" else key): row[key][0] for key in keys})
        if item["fail_mode"] == "-":
            item["fail_mode"] = None
        connectors.append(item)
    payload = {
        "enabled": (
            bool(gc.enabled)
            if secure_client
            else bool(gc.enabled and any(item["state"] == "enabled" for item in connectors))
        ),
        "port": gc.port,
        "connectors": connectors,
        "warnings": warnings,
    }
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
    if result.get("agent_assignments_unchecked"):
        text += "; agent-scoped assignments not checked: the gateway did not list this account's agents"
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
    from defenseclaw.commands.cmd_status import _enterprise_profile

    secure_client = _enterprise_profile(app.cfg) == "secure_client"
    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)
    fail_mode = (getattr(gc, "hook_fail_mode", "") or "closed").lower()
    if not as_json:
        ux.section("Guardrail status", indent="  ")
        if secure_client:
            enabled_txt = "yes" if gc.enabled else "no"
            enabled_val = ux._style(enabled_txt, fg="green" if gc.enabled else "yellow")
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
            _echo_status_json(gc, [], [], secure_client=secure_client)
            return
        if not secure_client:
            ux.echo(f"  • {ux._style('enabled:', fg='bright_black', bold=True)}    {ux._style('no', fg='yellow')}")
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

    if not as_json and not secure_client:
        # The summary must describe the same selected rows as --json.
        all_enabled = gc.enabled and any(
            gc.effective_enabled(name) if hasattr(gc, "effective_enabled") else True
            for name in actives
        )
        enabled_txt = "yes" if all_enabled else "no"
        enabled_val = ux._style(enabled_txt, fg="green" if all_enabled else "yellow")
        ux.echo(f"  • {ux._style('enabled:', fg='bright_black', bold=True)}    {enabled_val}")

    from defenseclaw.hook_integrity import repair_command, unrunnable_hook_problem

    rows: list[dict[str, tuple[str, str]]] = []
    any_disabled = False
    runtime_drift_rows: list[str] = []
    runtime_limit_rows: list[str] = []
    posture_rows: list[str] = []
    for name in actives:
        if not secure_client and normalize_connector(name) == "cursor":
            runtime_limit_rows.append(
                "Cursor Agent CLI 2026.10.01 does not send beforeSubmitPrompt; prompt text is not inspected "
                "and fail-closed applies only to hook events the CLI sends. "
                "Check hook_decision rows for actual coverage"
            )
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
        elif upstream_fail_open(app.cfg, name):
            # Under Secure Client, Copilot CLI, Antigravity and Hermes fail
            # open upstream whatever is configured; `defenseclaw status`
            # reports the same.
            cfm = "open"
            runtime_limit_rows.append(
                f"{_connector_label(name)} ({name}) is upstream-enforced fail-open"
                f" (configured provenance: {configured_cfm})"
            )
        elif upstream_hook_limit(name):
            # Everywhere else their hooks follow the fail mode they render.
            runtime_state = resolve_connector_fail_mode(app.cfg, name)
            cfm = runtime_state.effective
            enforcing = gc.enabled and (gc.effective_enabled(name) if hasattr(gc, "effective_enabled") else True)
            if runtime_state.drift and enforcing:
                fail_drift = f" (desired {runtime_state.desired}; drift: " + ", ".join(runtime_state.drift) + ")"
                runtime_drift_rows.append(f"{_connector_label(name)} ({name}){fail_drift}")
            if cfm == "closed":
                runtime_limit_rows.append(f"{_connector_label(name)} ({name}) is closed: {runtime_state.limit}")
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
        if not secure_client and gc.enabled and c_enabled:
            unrunnable = unrunnable_hook_problem(app.cfg, name)
            if unrunnable:
                # The agent treats a hook it cannot start as a non-blocking
                # error, so "closed" in the table would be a false promise.
                posture_rows.append(
                    f"{_connector_label(name)} ({name}) is not guarded: {unrunnable}. Fail mode does not apply "
                    f"to a hook the agent does not run; repair: {repair_command(name, unrunnable)}"
                )
            elif cfm == "open" and not upstream_fail_open(app.cfg, name) and (
                (cmode or "") == "action" or _action_profiles_for(gc, name)
            ):
                # An upgrade keeps the fail mode an older setup chose, while a
                # new setup gives an action connector closed (GAP-0415). A
                # guardrail profile that puts the connector in action mode
                # for some accounts counts too (GAP-1282): fail mode is baked
                # into the hooks, so a profile cannot close it.
                scope = f" --connector {name}" if getattr(gc, "connectors", None) else ""
                where = (
                    "is in action mode"
                    if (cmode or "") == "action"
                    else "is in action mode for guardrail profile(s) " + ", ".join(_action_profiles_for(gc, name))
                )
                deployment = str(getattr(app.cfg, "deployment_mode", "") or "")
                managed_host = deployment.strip().lower() == "managed_enterprise"
                fix = (
                    f"set closed with defenseclaw guardrail fail-mode closed{scope}"
                    if managed_host
                    else "block them with the strict policy: defenseclaw guardrail use-pack strict"
                    + (f" --connector {name}" if scope else "")
                )
                posture_rows.append(
                    f"{_connector_label(name)} ({name}) {where} with fail mode open: while the gateway "
                    f"is down its hooks allow calls that policy blocks; {fix}"
                )
        fail_raw = cfm
        cfm_display = _style_fail_mode(cfm)
        if not (gc.enabled and c_enabled):
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
    from defenseclaw.gateway import current_user_guardrail_profile, gateway_reload_notice

    profile = None
    if not secure_client:
        profile = current_user_guardrail_profile(app.cfg)
        posture_rows.extend(policy_catalog.configured_hilt_warnings(app.cfg))
    if as_json:
        _echo_status_json(
            gc, rows, posture_rows + runtime_drift_rows + runtime_limit_rows, profile,
            secure_client=secure_client,
        )
        return
    _render_connector_table(rows)
    for posture_row in posture_rows:
        ux.warn(posture_row, indent="  ")
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
    # The rows describe config.yaml; say when the running gateway does not
    # enforce it yet (GAP-0352). Secure Client keeps the origin/main output.
    if not secure_client and (notice := gateway_reload_notice(app.cfg)):
        ux.warn(notice, indent="  ")
    ux.echo(f"  • {ux.dim('fail = invalid, unauthorized, incomplete, or unreachable gateway responses')}")
    if any_disabled:
        ux.echo(f"  • {ux.dim('fail - = disabled connector (no hooks, so no fail mode)')}")

    if proxy_in_use:
        ux.echo(f"  • {ux._style('port:', fg='bright_black', bold=True)}       {gc.port}")
    click.echo()
    if not gc.enabled:
        click.echo(f"  {ux.dim('Enable with:')}   defenseclaw guardrail enable")
    elif secure_client or any(
        gc.effective_enabled(name) if hasattr(gc, "effective_enabled") else True
        for name in actives
    ):
        click.echo(f"  {ux.dim('Disable with:')}  defenseclaw guardrail disable")
    else:
        click.echo(f"  {ux.dim('Enable with:')}   defenseclaw guardrail enable --connector <name>")
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

    _note_running_agent_restart()
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
            connector=_set_up[0] if _set_up and connector in _kept_off else connector,
            # Readiness covers the enabled roster only. A connector kept off
            # must neither suppress checks for its peers nor become a wait target.
            connectors=_set_up if _set_up else _actives,
            **({"summary_exclude": frozenset(_kept_off)} if _kept_off else {}),
            wait_for_connector_ready=bool(_set_up),
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

    _note_running_agent_restart()
    _log_guardrail_action(
        app,
        "guardrail-enable",
        f"connector={connector} restart={restart}",
    )


def _rollback_fail_mode_transaction(app: AppContext, snapshots: tuple[FileSnapshot, ...]) -> None:
    """Undo a saved fail-mode change after its registration refresh failed.

    The caller has already put the old values back in ``app.cfg``; saving
    again through the single writer reverts only those fields (a concurrent
    edit to config.yaml stays) and records the rollback as a generation.
    Then the registration files go back to their snapshot.
    """

    app.cfg.save(reason="rollback: guardrail fail-mode")
    restore_fail_mode_transaction(snapshots)


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
            # A failed writer commit leaves config.yaml as it was, and no
            # registration file has been touched yet.
            if old_entry is None:
                conns.pop(key, None)
            else:
                old_entry.hook_fail_mode = old_mode
            ux.err(
                f"Cannot write {config_path_for_data_dir(app.cfg.data_dir)}: {exc.strerror or exc}; "
                "the previous config.yaml is unchanged.", indent="  ",
            )
            raise SystemExit(1) from exc

        if restart and gc.enabled:
            try:
                reconcile_connector_registration(app.cfg, key)
            except (OSError, RuntimeError) as exc:
                if old_entry is None:
                    conns.pop(key, None)
                else:
                    old_entry.hook_fail_mode = old_mode
                try:
                    _rollback_fail_mode_transaction(app, snapshots)
                except (OSError, ConfigWriteError) as rollback_exc:
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


def _upstream_fail_open_note(connector: str) -> str:
    """Why closed cannot block *connector*'s hook failures (upstream fail-open)."""
    label = _connector_label(connector)
    if normalize_connector(connector) == "hermes":
        return (
            "Timeout, nonzero exit, malformed output, authentication, and transport failures continue "
            "in upstream Hermes. Only valid synchronous JSON can block."
        )
    return (
        f"{label} has no fail-closed hook contract: a call its hook cannot check (gateway down, "
        f"timeout, malformed response) is allowed, and {label} continues a call whose hook fails or "
        "times out. Only a block decision from the gateway blocks it."
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
        if upstream_fail_open(app.cfg, key):
            # Copilot CLI, Antigravity and (under Secure Client) Hermes fail
            # open upstream whatever is saved, as the unscoped view, status and
            # doctor say (GAP-0336).
            runtime_value = (
                f"open ({label} upstream; failures cannot be made fail-closed;"
                f" configured provenance: {configured_mode})"
            )
        elif runtime_state.limit:
            runtime_value = runtime_state.effective
            if runtime_value == "closed":
                runtime_value += f" ({runtime_state.limit})"
        elif normalize_connector(key) == "hermes":
            # Outside Secure Client the Hermes hook follows its resolved
            # value on every OS (GAP-0150, GAP-0269); it has no separate
            # runtime record to read.
            runtime_value = current
        else:
            runtime_value = runtime_state.runtime or "unknown"
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

    if mode == configured_mode and runtime_state.desired == mode and runtime_state.current:
        ux.echo(f"  {ux.dim(f'{label} hook fail mode is already')} {mode!r} {ux.dim('— nothing to do.')}")
        return

    if (
        mode == "closed" and not restart and gc.enabled and _tracks_runtime_fail_mode(app.cfg, key)
        and (runtime_state.desired != "closed" or not runtime_state.current)
    ):
        ux.err(f"{label} still has a hook that is not verified closed.", indent="  ")
        ux.subhead(
            f"Run: defenseclaw guardrail fail-mode closed --connector {key} --yes",
            indent="    ",
        )
        raise SystemExit(1)

    click.echo()
    if mode == configured_mode:
        click.echo(f"  {ux.bold(f'Reconciling {label} hook runtime:')} {ux.accent(mode)}")
        ux.warn("Persisted policy matches, but installed runtime state is stale or inconsistent.", indent="  ")
    else:
        ux.echo(
            f"  {ux.bold(f'Changing {label} hook fail mode:')} {configured_mode} {ux.dim('→')} {ux.accent(mode)}"
        )
    if mode == "closed" and upstream_fail_open(app.cfg, key):
        ux.warn(
            f"{label} will remain fail-open; this value is stored only as requested policy provenance.",
            indent="  ",
        )
        ux.subhead(_upstream_fail_open_note(key), indent="    ")
    elif normalize_connector(key) == "hermes" and mode == "closed":
        ux.warn(f"Invalid or unavailable gateway responses will now BLOCK {label} tool calls.", indent="  ")
        ux.subhead(_HERMES_UPSTREAM_TIMEOUT_NOTE, indent="    ")
    elif mode == "closed":
        ux.warn(f"Invalid or unavailable gateway responses will now BLOCK {label}.", indent="  ")
        ux.subhead(
            "A 4xx, malformed or incomplete response, timeout, or connection failure "
            + _CLOSED_FAILURE_SIGNALS.get(normalize_connector(key), "will exit 2 from this connector's hooks.")
            + " Make sure your gateway is healthy first.",
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
        old_entries: dict[str, tuple[object, str]] = {}
        gc.hook_fail_mode = mode
        if fail_mode_targets:
            for name in fail_mode_targets:
                entry = gc.connectors[name]
                old_entries[name] = (entry, str(getattr(entry, "hook_fail_mode", "") or ""))
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
                    f"; {_connector_label(name)} saved, stays disabled until {_turn_on_steps(gc, name)}"
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
            # A failed writer commit leaves config.yaml as it was, and no
            # registration file has been touched yet.
            gc.hook_fail_mode = old_global
            for name, (old_entry, old_mode) in old_entries.items():
                old_entry.hook_fail_mode = old_mode
            ux.err(
                f"Cannot write {config_path_for_data_dir(app.cfg.data_dir)}: {exc.strerror or exc}; "
                "the previous config.yaml is unchanged.", indent="  ",
            )
            raise SystemExit(1) from exc

        if restart and gc.enabled:
            used_full_restart = False
            gateway_stopped = False
            try:
                # GAP-2071: a connector disabled on its own has no hooks to
                # refresh or verify; its value is only saved for later.
                disabled = frozenset(name for name in transaction_targets if _disabled_on_its_own(gc, name))
                live_targets = [name for name in transaction_targets if name not in disabled]
                runtime_targets = [name for name in live_targets if _tracks_runtime_fail_mode(app.cfg, name)]

                # A mixed install needs a gateway restart for its other
                # connectors. Close every mode-aware hook first: an old open
                # Copilot or Hermes registration otherwise allows calls while
                # the gateway is between processes.
                if mode == "closed":
                    for name in runtime_targets:
                        reconcile_connector_registration(app.cfg, name)
                if live_targets and len(runtime_targets) == len(live_targets):
                    if mode != "closed":
                        for name in runtime_targets:
                            reconcile_connector_registration(app.cfg, name)
                elif not _gateway_running(app):
                    # GAP-1370: like the --connector form, never start a
                    # gateway the user stopped; it loads the saved value
                    # when it starts.
                    gateway_stopped = True
                    if mode != "closed":
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
                    old_entry.hook_fail_mode = old_mode
                try:
                    _rollback_fail_mode_transaction(app, snapshots)
                except (OSError, ConfigWriteError) as rollback_exc:
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


# What a per-user hook does while its gateway is down (Go
# config.HookOutageFailMode), as `guardrail fail-mode` explains it.
_PER_USER_OUTAGE_RULE = (
    "On a per-user install, hooks block when the gateway is unavailable in every policy tier. "
    "An error or unusable gateway answer, a missing token, and an install or upgrade also block."
)


def _refuse_per_user_open_mode(mode: str) -> None:
    """Refuse an open per-user outage mode, even before connector setup."""
    if mode == "open":
        ux.err(_PER_USER_OUTAGE_RULE, indent="  ")
        raise SystemExit(1)


def _show_per_user_outage_modes(app: AppContext) -> None:
    """Print each active per-user connector's gateway-outage mode and the rule behind it."""

    gc = app.cfg.guardrail
    click.echo()
    click.echo(f"  {ux.bold('gateway outage:')} closed in every policy tier")
    click.echo()
    click.echo(f"  {ux._style('per connector:', fg='bright_black', bold=True)}")
    for name in _active_connector_set(app.cfg, _resolve_active_connector(app.cfg)):
        enforcing = gc.enabled and (gc.effective_enabled(name) if hasattr(gc, "effective_enabled") else True)
        if not enforcing:
            shown = "disabled (no hooks)"
        elif _is_proxy_connector(name):
            shown = "closed (proxy-backed, no hooks: blocked while the gateway is down)"
        else:
            tier = gc.hook_policy_tier(name) if hasattr(gc, "hook_policy_tier") else "default"
            resolver = getattr(gc, "effective_hook_fail_mode", None)
            outage = resolver(name) if callable(resolver) else "closed"
            notes = [f"{tier} tier"]
            limit = upstream_hook_limit(name)
            if outage == "closed" and limit:
                # What closed cannot change for a vendor hook (GAP-0150).
                notes.append(limit)
            shown = f"{outage} ({'; '.join(notes)})"
            tracked = normalize_connector(name) in _RUNTIME_FAIL_MODE_CONNECTORS or bool(limit)
            state = resolve_connector_fail_mode(app.cfg, name) if tracked else None
            if state is not None and state.drift:
                shown += f" (installed {state.runtime or 'unknown'}; drift: {', '.join(state.drift)})"
        click.echo(f"      - {_connector_label(name)} ({name}): {shown}")
    click.echo()
    ux.subhead(_PER_USER_OUTAGE_RULE, indent="  ")
    click.echo(f"  {ux.dim('Gateway down:')} defenseclaw-gateway start; defenseclaw doctor if it does not start")
    click.echo()


@guardrail.command("fail-mode")
@click.argument("mode", required=False, type=click.Choice(["open", "closed"]))
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Refresh and verify runtime registrations, restarting a running gateway only when full connector setup "
    "is needed (default: on). --no-restart saves the desired value without refreshing registrations.",
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
    the gateway response fails. On a per-user install hooks block gateway
    outages in every policy tier, and ``open`` is unavailable. Managed
    administrators can select ``open`` for a classified outage; Secure Client
    keeps its own default. Two values are supported where available:

      \b
      open   — allow an eligible managed outage and log the failure.
      closed — block supported events when inspection is unavailable.
               The default on a new install: every prompt and
               tool call is inspected or blocked.

    Errors, unusable gateway answers, missing tokens and install windows
    block outside Secure Client in either mode.

    Without an argument this prints the current value. With
    ``open`` or ``closed`` it persists the choice to ~/.defenseclaw/
    config.yaml. With --restart (the default), enabled connectors'
    runtime registrations are refreshed and verified directly where
    supported. A running gateway restarts only when full connector setup
    is needed; a stopped gateway stays stopped. --no-restart saves the
    desired value without refreshing runtime registrations; check
    ``guardrail status`` for drift until reconciliation succeeds.

    With ``--connector X`` it scopes the fail mode to a single connector
    (multi-connector installs only), writing a per-connector override
    while the global default and the other connectors are left untouched.
    """
    managed_host = str(getattr(app.cfg, "deployment_mode", "") or "").strip().lower() == "managed_enterprise"
    secure_client = bool(getattr(app.cfg.guardrail, "_secure_client", False))
    if mode is not None and not managed_host and not secure_client:
        _refuse_per_user_open_mode(mode)
    if connector_flag:
        _set_connector_fail_mode(
            app, connector_flag, mode, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    # A bare write sets the global value every unlisted connector inherits
    # (an OpenShell policy connector, a connector set up later), so a no-op
    # needs the saved global value to be exactly the requested one.
    saved_global = str(gc.hook_fail_mode or "").strip().lower()
    current = saved_global if (managed_host or secure_client) and saved_global in ("open", "closed") else "closed"

    if mode is None and not managed_host and not secure_client:
        _show_per_user_outage_modes(app)
        return
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
            elif upstream_fail_open(app.cfg, _name):
                # Under Secure Client, Copilot CLI, Antigravity and Hermes fail
                # open upstream, as status, doctor and guardrail status say
                # (GAP-0336).
                _eff = f"open ({_connector_label(_name)} upstream; configured provenance: {_eff})"
            elif upstream_hook_limit(_name):
                _state = resolve_connector_fail_mode(app.cfg, _name)
                _eff = _state.effective
                if _state.drift:
                    _eff += f" (desired {_state.desired}; drift: {', '.join(_state.drift)})"
                elif _state.note:
                    _eff += f" ({_state.note})"
            elif _is_proxy_connector(_name):
                _eff = "closed (proxy-backed, no hooks: blocked while the gateway is down)"
            if _enforcing and normalize_connector(_name) not in _RUNTIME_FAIL_MODE_CONNECTORS:
                # A hook entry the agent skips, or one that does not run
                # DefenseClaw's current hook, leaves calls unchecked whatever
                # the fail mode (rel-1-0-4 GAP-0538, GAP-0600); the runtime
                # connectors above, and Copilot CLI, Antigravity and Hermes
                # resolved from their rendered hooks, carry it in their drift
                # already, so a drift already named is not printed twice.
                _drift = [d for d in registration_integrity_drift(app.cfg, _name) if d not in _eff]
                if _drift:
                    _eff += f" (drift: {', '.join(_drift)})"
            if _eff.startswith("open") and not upstream_fail_open(app.cfg, _name):
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
            # Name only the configured upstream fail-open connectors (GAP-2116,
            # GAP-0336).
            _upstream_open = [_connector_label(n) for n in _actives if upstream_fail_open(app.cfg, n)]
            _hermes_note = (
                f"; {', '.join(_upstream_open)} {'remains' if len(_upstream_open) == 1 else 'remain'} fail-open"
                if _upstream_open
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
            if managed_host:
                click.echo(f"  {ux.dim('Switch to open:')}   defenseclaw guardrail fail-mode open")
        click.echo()
        return

    fail_mode_targets = _active_connector_keys(app)
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
    desired_modes = dict.fromkeys(fail_mode_targets, mode)

    if (
        fail_mode_targets
        and saved_global == mode
        and all(target_modes[name] == desired_modes[name] for name in fail_mode_targets)
        and all(
            (runtime_states[name].desired == desired_modes[name] and runtime_states[name].current)
            or upstream_fail_open(app.cfg, name)
            or _disabled_on_its_own(gc, name)
            or not gc.enabled
            for name in fail_mode_targets
        )
    ):
        scope = "for all active connectors" if gc.enabled else "for configured connectors"
        ux.echo(f"  {ux.dim('Hook fail mode is already')} {mode!r} {ux.dim(f'{scope} — nothing to do.')}")
        return
    single_connector = _resolve_active_connector(app.cfg)
    single_state = (
        resolve_connector_fail_mode(app.cfg, single_connector)
        if not fail_mode_targets and _tracks_runtime_fail_mode(app.cfg, single_connector)
        else None
    )
    if mode == "closed" and not restart and gc.enabled:
        unclosed = [
            name for name in fail_mode_targets
            if _tracks_runtime_fail_mode(app.cfg, name)
            and not _disabled_on_its_own(gc, name)
            and (runtime_states[name].desired != "closed" or not runtime_states[name].current)
        ]
        if single_state is not None and (single_state.desired != "closed" or not single_state.current):
            unclosed.append(single_connector)
        if unclosed:
            ux.err("Registered hooks are not verified closed: " + ", ".join(unclosed), indent="  ")
            ux.subhead("Run: defenseclaw guardrail fail-mode closed --yes", indent="    ")
            raise SystemExit(1)
    if (
        not fail_mode_targets
        and saved_global == mode
        and (single_state is None or (single_state.desired == mode and single_state.current))
        and not registration_integrity_drift(app.cfg, single_connector)
    ):
        if upstream_fail_open(app.cfg, single_connector):
            ux.echo(
                f"  {ux.dim(f'Configured {_connector_label(single_connector)} fail-mode provenance is already')}"
                f" {mode!r} {ux.dim('— runtime remains upstream fail-open.')}"
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
                    f"{desired_modes[name]} is saved; it stays disabled until {_turn_on_steps(gc, name)}"
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
            if _tracks_runtime_fail_mode(app.cfg, name) and installed:
                shown = installed
            if shown != mode:
                ux.echo(f"      - {_connector_label(name)} ({name}): {shown} {ux.dim('→')} {ux.accent(mode)}")
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
    # Copilot CLI, Antigravity and (under Secure Client) Hermes stay fail-open
    # upstream whatever is saved (GAP-0336): closed is provenance for them.
    upstream_open = [name for name in active_names if upstream_fail_open(app.cfg, name)]
    upstream_labels = ", ".join(_connector_label(name) for name in upstream_open)
    upstream_note = (
        f" {upstream_labels} {'remains' if len(upstream_open) == 1 else 'remain'} fail-open."
        if upstream_open
        else ""
    )
    if mode == "closed" and upstream_open and len(upstream_open) == len(active_names):
        ux.warn(
            f"{upstream_labels} will remain fail-open; closed is stored only as requested policy provenance.",
            indent="  ",
        )
        for name in upstream_open:
            ux.subhead(_upstream_fail_open_note(name), indent="    ")
    elif mode == "closed" and guardrail_off:
        ux.subhead(
            "Once the guardrail is enabled, invalid or unavailable gateway responses will BLOCK "
            "supported connectors." + upstream_note,
            indent="  ",
        )
    elif mode == "closed":
        ux.warn(
            "Invalid or unavailable gateway responses will now BLOCK supported connectors.",
            indent="  ",
        )
        ux.subhead(
            "A 4xx, malformed/incomplete response, timeout, or connection failure blocks connectors "
            "with a native fail-closed surface." + upstream_note,
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


# What fail mode closed cannot change for Hermes on Linux and macOS: its hook
# blocks every failure DefenseClaw sees, but Hermes itself lets a call run when
# a hook times out or cannot start (GAP-0150).
# How a closed hook blocks a call it cannot check, for the connectors that
# answer with the agent's own deny instead of exit 2.
_CLOSED_FAILURE_SIGNALS = {
    "copilot": (
        "gets Copilot's own deny for preToolUse and permissionRequest; the hook exits 0. Copilot itself "
        "still lets a call run when the hook times out or cannot start."
    ),
    "antigravity": (
        'gets Antigravity\'s PreToolUse deny ({"decision":"deny"}); the hook exits 0. Antigravity itself '
        "still lets a call run when the hook times out or cannot start."
    ),
}


_HERMES_UPSTREAM_TIMEOUT_NOTE = (
    "A gateway that is down or gives an unusable answer blocks the Hermes tool call; Hermes itself "
    "still lets a call run when the hook times out or cannot start."
)


def _profile_connector_policies(gc, connector: str) -> list[tuple[str, str]]:
    """``(profile, mode)`` for each guardrail profile, for *connector*.

    *mode* is the mode the profile itself sets for the connector, "" when it
    inherits. A profile's own per-connector value wins over its profile-wide
    one, as the gateway resolves it (applyGuardrailProfile).
    """
    rows: list[tuple[str, str]] = []
    target = normalize_connector(connector)
    for pname, profile in sorted((getattr(gc, "profiles", None) or {}).items()):
        mode = str(getattr(profile, "mode", "") or "").strip().lower()
        for cname, override in (getattr(profile, "connectors", None) or {}).items():
            if normalize_connector(cname) == target and str(getattr(override, "mode", "") or "").strip():
                mode = str(override.mode).strip().lower()
        rows.append((str(pname), mode))
    return rows


def _action_profiles_for(gc, connector: str) -> list[str]:
    """Names of the guardrail profiles that put *connector* in action mode.

    An unset mode inherits and is not counted.
    """
    return [name for name, mode in _profile_connector_policies(gc, connector) if mode == "action"]


def _hilt_preview_lines(app: AppContext, key: str, label: str, enabled: bool, min_severity: str) -> list[str]:
    """What saving this connector HILT block does, line by line.

    The hook mode and HILT come from the gateway's own resolvers
    (``defenseclaw-gateway connector hilt-preview``), never from a Python
    copy: a legacy ``claude_code.mode``, ``codex.mode`` or
    ``connector_hooks.<c>.mode`` wins over the guardrail mode there, and a
    guardrail profile that sets a mode or its own HILT block changes what its
    accounts get. When the gateway cannot answer, the preview says so and
    promises nothing.
    """
    from defenseclaw import config_inspect

    try:
        preview = config_inspect.connector_hilt_preview(
            normalize_connector(key),
            enabled=enabled,
            min_severity=min_severity,
            config_path=str(config_path_for_data_dir(app.cfg.data_dir)),
        )
    except config_inspect.ConfigInspectError as exc:
        lines = [
            f"Could not resolve {label}'s hook mode with the gateway ({exc}). The saved HILT policy pauses "
            f"actions only where {label} runs in action mode; check an account with: "
            f"defenseclaw guardrail profile explain --user <name> --connector {normalize_connector(key)}"
        ]
        if enabled and not has_native_approval_prompt(key):
            # Whatever the mode, a connector without a native approval prompt
            # alerts instead of asking (_hilt_enable_notice).
            lines.append(_hilt_enable_notice(key, min_severity, secure_client=asset_lists.is_secure_client(app.cfg)))
        return lines
    base = preview.base
    if base.mode != "action":
        lines = [
            f"{label} is in {base.mode} mode, which does not pause actions for approval. "
            "The saved HILT policy applies when the connector uses action mode."
        ]
    elif base.enabled:
        # A connector without a native approval prompt alerts instead.
        lines = [_hilt_enable_notice(key, base.min_severity, secure_client=asset_lists.is_secure_client(app.cfg))]
    else:
        lines = [f"{label} will NOT prompt — actions resolve straight to allow/alert/block."]
    return lines + _hilt_profile_notes(preview, label)


def _hilt_profile_notes(preview, label: str) -> list[str]:
    """What a saved connector HILT change does for accounts on guardrail profiles.

    *preview* is the gateway's answer (``connector_hilt_preview``). A profile
    with its own HILT block is not reached by the change. One that follows it
    but runs the connector in another hook mode than the accounts on no
    profile pauses (action) or does not (observe) where the base line says the
    opposite, so its accounts get their own line.
    """
    base = preview.base
    action: list[str] = []
    passive: list[str] = []
    own: list[str] = []
    for scope in preview.profiles:
        if not scope.follows_connector_hilt:
            own.append(scope.profile)
        elif scope.mode != base.mode:
            (action if scope.mode == "action" else passive).append(scope.profile)
    notes: list[str] = []
    if action:
        names = ", ".join(action)
        if base.enabled:
            notes.append(
                f"Guardrail profile(s) {names} put {label} in action mode: their accounts will be prompted "
                f"for approval on confirmable actions at/above {base.min_severity} (CRITICAL findings still block "
                "outright)."
            )
        else:
            notes.append(
                f"Guardrail profile(s) {names} put {label} in action mode: their accounts will NOT be prompted; "
                "actions resolve straight to allow/alert/block."
            )
    if passive:
        notes.append(
            f"Guardrail profile(s) {', '.join(passive)} put {label} in observe mode: "
            "their accounts are not paused for approval."
        )
    if own:
        notes.append(
            f"Guardrail profile(s) {', '.join(own)} set their own HILT policy: this change does not apply to "
            "their accounts."
        )
    return notes


def _warn_still_fail_open(gc, open_names: list[str]) -> None:
    """Name the command that really closes each still-open connector (GAP-1341).

    The guardrail mode never keeps a hook fail-open (owner rule: open only
    under Secure Client or by an explicit open), so the fix is always the
    fail mode."""
    if open_names:
        fix = (
            "defenseclaw guardrail fail-mode closed --connector <name>"
            if getattr(gc, "connectors", {}) or {}
            else "defenseclaw guardrail fail-mode closed"
        )
        ux.warn(f"Still fail-open: {', '.join(open_names)}. Close it with: {fix}", indent="  ")


_HILT_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _hilt_enable_notice(
    connector: str, severity: str, *, mode: str = "action", secure_client: bool = False
) -> str:
    label = _connector_label(connector)
    observe_note = (
        f"{label} is in observe mode; HILT at/above {severity} does not pause actions "
        "until action mode is enabled. "
        if mode.strip().lower() != "action"
        else ""
    )
    if normalize_connector(connector) == "copilot":
        if secure_client:
            return (
                observe_note +
                f"{label} Secure Client will prompt for approval on supported confirmable "
                f"actions at/above {severity} (CRITICAL findings still block outright)."
            )
        return (
            observe_note +
            f"{label} cannot prove an approval prompt is available; action-mode "
            f"confirmations at/above {severity} are denied and audited as block "
            "(raw_action=confirm). CRITICAL findings still block outright."
        )
    if has_native_approval_prompt(connector):
        return (
            observe_note +
            f"{label} will prompt for approval on supported confirmable actions at/above "
            f"{severity} (CRITICAL findings still block outright)."
        )
    return (
        observe_note +
        f"{label} has no implemented native approval prompt; confirm verdicts at/above "
        f"{severity} produce alerts with raw_action=confirm preserved. CRITICAL findings still block outright."
    )


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
    for line in _hilt_preview_lines(app, key, label, new_enabled, new_min):
        ux.subhead(line, indent="  ")
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

    if not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )
    elif not asset_lists.is_secure_client(app.cfg):
        _report_hot_hilt(app)
    elif restart:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=key,
        )
        ux.ok(f"Gateway restarted, {label} HILT policy applied.", indent="  ")
        click.echo()

    _log_hilt(
        app,
        f"connector={key} scope=per-connector "
        f"enabled={str(new_enabled).lower()} min_severity={new_min} restart={restart}",
    )


def _report_hot_hilt(app: AppContext) -> None:
    """Say how a saved HILT change reaches the gateway off Secure Client.

    The gateway applies HILT from the new configuration generation, so the
    change needs no restart (GAP-0056); a Secure Client gateway reads the
    connector guardrail settings at start and keeps the restart of main
    (issue #1092).
    """
    outcome = _apply_to_running_gateway(app, needs_restart=False, restart=False, quiet=False)
    if outcome == "live":
        ux.ok(_GATEWAY_OUTCOMES[outcome], indent="  ")
    else:
        ux.echo(f"  {_GATEWAY_OUTCOMES[outcome]}")
    click.echo()


def _log_hilt(app: AppContext, details: str) -> None:
    """Audit a saved HILT change; a stopped gateway only skips the audit event."""
    _log_guardrail_action(app, "guardrail-hilt", details)


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
    help="On Secure Client, restart the gateway so the new HILT policy takes effect (default: on); "
    "elsewhere the running gateway applies it without a restart.",
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

    hilt_targets = _active_connector_keys(app)
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
        from defenseclaw.config import HILTConfig

        for name in hilt_targets:
            _, _, desired_enabled, desired_min = target_hilts[name]
            gc.connectors[name].hilt = HILTConfig(enabled=desired_enabled, min_severity=desired_min)
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

    if not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )
    elif not asset_lists.is_secure_client(app.cfg):
        _report_hot_hilt(app)
    elif restart:
        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=_resolve_active_connector(app.cfg),
            connectors=_active_connector_set(app.cfg, _resolve_active_connector(app.cfg)),
        )
        ux.ok("Gateway restarted, HILT policy applied.", indent="  ")
        click.echo()

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

    block_message_targets = _active_connector_keys(app)
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
        for name in block_message_targets:
            gc.connectors[name].block_message = new_msg
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

    # A bare pack name has the same meaning here as in list-packs/use-pack.
    if not os.path.exists(os.path.expanduser(path)) and not any(
        sep in path for sep in (os.sep, os.altsep) if sep
    ) and not path.startswith(("~", ".")):
        from defenseclaw import config, policy_catalog

        packs = policy_catalog.discover_rule_packs(config.load())
        named = next((p.path for p in packs if p.name == path), None)
        if named:
            path = named
        else:
            names = ", ".join(sorted(p.name for p in packs))
            message = f"no pack with the name {path!r} was found; available packs: {names}"
            if json_out:
                # --json promises the versioned result on stdout (GAP-1053).
                missing = rulepack_validation.RulePackValidationBridgeError(message, code="pack_not_found")
                click.echo(
                    json.dumps(
                        rulepack_validation.bridge_error_wire(missing),
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                raise SystemExit(1)
            raise click.ClickException(message)
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
        for warning in result.warnings:
            click.echo("warning: " + warning, err=True)
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
    "not_applied": (
        "The running gateway did not apply it and still enforces the previous setting "
        "(defenseclaw-gateway status says why); restart it to apply this: defenseclaw-gateway restart."
    ),
    "still_starting": (
        "The change is saved. The gateway is still starting and was kept running, so protection is "
        "not confirmed yet; check it with: defenseclaw-gateway status (restart it only if it does "
        "not become healthy)."
    ),
}
#: Outcomes that leave the change unconfirmed: the command exits 1.
_GATEWAY_UNCONFIRMED = frozenset({"restart_failed", "still_starting", "not_applied"})


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


def _disabled_on_its_own(gc, name: str) -> bool:
    """Whether *name* was turned off with `guardrail disable --connector` (no hooks)."""
    return hasattr(gc, "effective_enabled") and not gc.effective_enabled(name)


def _turn_on_steps(gc, name: str) -> str:
    """The commands that bring back *name*'s hooks, in order (GAP-0550).

    With the global switch off, `guardrail enable --connector` exits 1, and
    the global enable keeps a connector disabled on its own off.
    """
    steps = []
    if not gc.enabled:
        steps.append("'defenseclaw guardrail enable'")
    if _disabled_on_its_own(gc, name):
        steps.append(f"'defenseclaw guardrail enable --connector {name}'")
    return ", then ".join(steps)


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


def _unguarded_hook_connectors(app: AppContext, connectors: list[str]) -> list[tuple[str, str, str]]:
    """``(connector, why, repair)`` for each hook connector the running gateway does not guard.

    The same read-back first run uses: the gateway's started roster and the
    hook registration on disk (GAP-1035).
    """
    from defenseclaw.bootstrap import _connector_runtime_readiness
    from defenseclaw.commands.cmd_setup import _HOOK_ENFORCED_CONNECTORS

    found = []
    for name in connectors:
        key = normalize_connector(name)
        if key not in _HOOK_ENFORCED_CONNECTORS:
            continue
        try:
            step = _connector_runtime_readiness(app.cfg, key)
        except Exception:  # noqa: BLE001 - the change is saved; status and doctor still report it.
            continue
        if step is not None and step.status in ("warn", "fail"):
            found.append((key, step.detail, step.next_command))
    return found


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
        return _live_apply_outcome(app)
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


#: How long a saved change waits for the running gateway to report the new
#: config generation; its watcher lets a write settle for 0.5 s, then builds
#: the new policy generation.
_APPLY_CONFIRM_SECONDS = 10.0


def _live_apply_outcome(app: AppContext) -> str:
    """Whether the running gateway applied the config generation just saved.

    ``live`` when its health reports that generation, or when it cannot say
    (no answer, or no policy in its health); ``restart_needed`` when it applied
    the change but holds sections it reads only at start; ``not_applied`` when
    it still enforces an earlier generation: a rejected reload, or a gateway
    that never reloaded. After a 0.8.x upgrade an older gateway process
    refused the change while this said it applied it now (GAP-0362).
    """
    import time

    from defenseclaw import config_writer
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    try:
        want = config_writer.read_generation_state(config_path_for_data_dir(app.cfg.data_dir)).generation
        client = OrchestratorClient(
            host=gateway_api_client_host(app.cfg),
            port=app.cfg.gateway.api_port,
            token=app.cfg.gateway.resolved_token(),
            timeout=2,
        )
    except Exception:  # noqa: BLE001 - no recorded generation or no client: it cannot say.
        return "live"
    start = time.monotonic()
    try:
        while True:
            try:
                health = client.health()
                policy = health.get("policy")
                applied = int(policy["config_generation"])
            except Exception:  # noqa: BLE001 - no answer, or a gateway without policy health.
                return "live"
            if applied >= want:
                details = (health.get("config") or {}).get("details") or {}
                return "restart_needed" if details.get("restart_required") else "live"
            waited = time.monotonic() - start
            # A reload error older than this change clears once the new
            # generation builds, so it counts only after the watcher's turn.
            if waited >= _APPLY_CONFIRM_SECONDS or (waited >= 2 and policy.get("last_reload_error")):
                return "not_applied"
            time.sleep(0.25)
    finally:
        client.close()


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


def _rule_prune_scope(connector_key: str | None, profile: str | None) -> str:
    """Keep the owning scope when its last rule override is removed."""
    return _scope_key(None, profile) if profile else _scope_key(connector_key, None)


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


def _scope_pack_selections(cfg) -> dict[str, tuple[str | None, str | None, str]]:
    """Every guardrail scope block: config path -> (connector, profile, its ``rule_pack``)."""
    gc = cfg.guardrail
    selected = {"guardrail": (None, None, str(getattr(gc, "rule_pack", "") or "").strip())}
    for connector, block in sorted((getattr(gc, "connectors", None) or {}).items()):
        selected[_scope_key(connector, None)] = (connector, None, str(getattr(block, "rule_pack", "") or "").strip())
    for profile, block in sorted((getattr(gc, "profiles", None) or {}).items()):
        selected[_scope_key(None, profile)] = (None, profile, str(getattr(block, "rule_pack", "") or "").strip())
        for connector, sub in sorted((getattr(block, "connectors", None) or {}).items()):
            selected[_scope_key(connector, profile)] = (
                connector,
                profile,
                str(getattr(sub, "rule_pack", "") or "").strip(),
            )
    return selected


def _app_protection_pack_selections(cfg) -> dict[str, tuple[str | None, str, bool]]:
    """Every automatic-protection guardrail block: config path -> (connector,
    its ``rule_pack``, whether it is on). The gateway loads these packs for
    the connectors it protects automatically (appProtectionGuardrailOverride
    in internal/config/application_protection.go); use-pack never writes them."""
    ap = getattr(cfg, "application_protection", None)
    if ap is None:
        return {}
    on = bool(getattr(ap, "enabled", False))

    def _pack(block) -> str:
        return str(getattr(getattr(block, "guardrail", None), "rule_pack", "") or "").strip()

    selected = {"application_protection.guardrail": (None, _pack(ap), on)}
    for connector, entry in sorted((getattr(ap, "connectors", None) or {}).items()):
        selected[f"application_protection.connectors.{connector}.guardrail"] = (
            connector,
            _pack(entry),
            on and getattr(entry, "enabled", None) is not False,
        )
    return selected


def _repin_shared_scopes(cfg, name: str, written: set[str]) -> list[str]:
    """The scopes outside *written* (config paths) that select custom pack
    *name*: re-pinning its digest changes their policy too, so the prompt
    and the result name them, automatic-protection scopes included."""
    shared = []
    for path, (connector, profile, selected) in _scope_pack_selections(cfg).items():
        if path in written or selected != name:
            continue
        if connector is None and profile is None:
            shared.append("the global pack (every connector without its own pack)")
        else:
            shared.append(_scope_words(connector, profile))
    for path, (connector, selected, on) in _app_protection_pack_selections(cfg).items():
        if selected != name:
            continue
        words = (
            f"automatic protection for {_connector_label(connector)}"
            if connector
            else "automatic protection (connectors it protects that are not set up manually)"
        )
        shared.append(f"{words} ({path}{'' if on else ', when turned on'})")
    return shared


def _unused_pin_changes(cfg, after: dict[str, str]) -> tuple[list, list[str]]:
    """Unset the ``guardrail.custom_packs`` pins no scope selects once the
    scopes in *after* (config path -> its new ``rule_pack``, "" when unset)
    are written. A pin left behind keeps a path and digest no pack uses and
    outlives the folder it names (GAP-0127); ``use-pack DIR`` pins it again."""
    from defenseclaw import config_writer

    gc = cfg.guardrail
    selected = {path: pack for path, (_c, _p, pack) in _scope_pack_selections(cfg).items()}
    selected.update(after)
    # An automatic-protection pack keeps its pin; the gateway refuses a pack
    # name that is neither built in nor a custom_packs key.
    selected.update({path: pack for path, (_c, pack, _on) in _app_protection_pack_selections(cfg).items()})
    used = {str(name or "").strip() for name in selected.values()}
    dropped = sorted(name for name in (getattr(gc, "custom_packs", None) or {}) if name not in used)
    return [config_writer.Change(f"guardrail.custom_packs.{name}", unset=True) for name in dropped], dropped


def _dropped_pins_note(dropped: list[str]) -> str:
    if not dropped:
        return ""
    names = ", ".join(f"guardrail.custom_packs.{name}" for name in dropped)
    return f" Removed the pin no connector uses any more: {names}."


def _scope_words(connector_key: str | None, profile: str | None) -> str:
    if profile and connector_key:
        return f"{_connector_label(connector_key)} in profile {profile}"
    if profile:
        return f"profile {profile}"
    if connector_key:
        return _connector_label(connector_key)
    return "every connector"


def _refuse_managed_write(target: str, reason: str, fail) -> None:
    """Audit a guardrail change refused on a managed device, then report it
    (exit 3) through *fail(exit_code, message)*."""
    from defenseclaw.enforce.asset_lists import audit_managed_config_refusal

    audit_managed_config_refusal(target, reason)
    fail(
        3,
        "This device is managed: change the guardrail in the admin config (MDM or management plane). "
        "Nothing was changed.",
    )


def _refuse_if_managed_device(app: AppContext, reason: str, fail) -> None:
    """A managed device refuses every guardrail writer before any argument,
    scope or state check, so no other answer comes first."""
    from defenseclaw.enforce.asset_lists import is_managed_standalone

    if is_managed_standalone(app.cfg):
        _refuse_managed_write("guardrail", reason, fail)


def _guardrail_write_error(exc: BaseException) -> str:
    """Keep a busy validator refusal short and actionable."""
    from defenseclaw import config_writer
    from defenseclaw.config_inspect import ConfigInspectTimeoutError

    cause = exc.__cause__
    if isinstance(exc, ConfigInspectTimeoutError) or isinstance(cause, ConfigInspectTimeoutError):
        return (
            "Config check did not finish:\n"
            "  ✗ The configuration check timed out.\n"
            "  Nothing was changed; re-run the command."
        )
    return f"Failed to save config: {config_writer.plain_error(exc)}"


def _write_guardrail_config(
    app: AppContext, changes, reason: str, fail, *, snapshot: tuple[str, str] | None = None
) -> object:
    """Apply *changes* through the config writer; *fail(exit_code, message)*
    reports a refused or failed write and exits. With *snapshot* (the
    ``(path, sha256)`` :func:`_read_config_snapshot` returned) the write is a
    compare-and-swap: it lands only on those config.yaml bytes, and a file
    changed or removed since then raises
    :class:`config_writer.ConfigConflictError` for the caller."""
    from defenseclaw import config_writer

    target, expect_sha256 = snapshot or (str(config_path_for_data_dir(app.cfg.data_dir)), None)
    try:
        return config_writer.apply(changes, _cli_actor(), reason, expect_sha256=expect_sha256, path=target)
    except config_writer.ConfigConflictError as exc:
        if expect_sha256 is not None:
            raise
        fail(1, _guardrail_write_error(exc))
    except config_writer.ManagedConfigWriteError:
        _refuse_managed_write(getattr(changes[0], "path", "") or "guardrail", reason, fail)
    except (config_writer.ConfigWriteError, OSError) as exc:
        detail = _guardrail_write_error(exc)
        if "unknown rule" in detail and all(
            not str(change.path).startswith(("guardrail.connectors.", "guardrail.profiles."))
            for change in changes
        ):
            detail += " The global rule pack was checked; use --connector or --profile for another scope."
        fail(1, detail)
    return None


def _read_config_snapshot(app: AppContext, fail) -> tuple[str, str]:
    """Read config.yaml once, load ``app.cfg`` from exactly those bytes, and
    return ``(path, sha256)`` for a compare-and-swap write.

    ``use-pack --repin`` shows every change from this one read and asks;
    the write then lands only on these bytes. A pin lives in config.yaml, so
    a missing or empty file is refused: the config still in memory is not
    what is on disk, and nothing may build a config.yaml from it.
    """
    import hashlib

    from defenseclaw import config as cfg_mod

    path = config_path_for_data_dir(app.cfg.data_dir)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        fail(1, f"--repin replaces a pin in config.yaml, and there is no {path}. Nothing was changed.")
        raise
    except OSError as exc:
        fail(1, f"Failed to read config: {exc}. Nothing was changed.")
        raise
    try:
        source = cfg_mod.parse_config_yaml(cfg_mod.decode_config_bytes(raw)) or {}
    except Exception as exc:
        fail(1, f"Failed to load config: {exc}. Nothing was changed.")
        raise
    if not source:
        fail(1, f"--repin replaces a pin in config.yaml, and {path} is empty. Nothing was changed.")
    try:
        app.cfg = cfg_mod.load(parsed_source=source)
    except Exception as exc:
        fail(1, f"Failed to load config: {exc}. Nothing was changed.")
        raise
    return str(path), hashlib.sha256(raw).hexdigest()


def _planned_change_lines(changes) -> list[str]:
    """One line per config.yaml edit, exactly as the writer gets it."""
    lines = []
    for change in changes:
        if change.unset:
            lines.append(f"remove {change.path}")
        else:
            value = change.value if isinstance(change.value, str) else json.dumps(change.value, sort_keys=True)
            lines.append(f"set {change.path} = {value}")
    return lines


@contextmanager
def _config_lock(app: AppContext, fail) -> Iterator[None]:
    """Hold config.yaml.lock for a read-modify-write; the writer joins it."""
    from defenseclaw import config_writer

    try:
        with config_writer.hold_lock(str(config_path_for_data_dir(app.cfg.data_dir))):
            yield
    except config_writer.ConfigLockBusyError as exc:
        fail(1, f"Failed to save config: {config_writer.plain_error(exc)}")


def _listed_now(app: AppContext, dotted: str, loaded: list) -> list:
    """The list config.yaml holds at *dotted* now (the caller holds the lock).

    A list edit builds on it, not on the list loaded when the command
    started, so two edits of the same list compose instead of the last one
    overwriting the other (GAP-0304). *loaded* stands in while there is no
    config.yaml (or it can't be read; the writer then reports why).
    """
    import yaml

    from defenseclaw import config_writer

    try:
        with open(config_path_for_data_dir(app.cfg.data_dir), "rb") as handle:
            value = yaml.safe_load(handle.read()) or {}
    except (OSError, ValueError, yaml.YAMLError):
        return list(loaded)
    for part in config_writer.parse_path(dotted):
        value = value.get(part) if isinstance(value, dict) else None
    return list(value) if isinstance(value, list) else []


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
    outcome = _live_apply_outcome(app)
    if outcome != "live":
        return f"Saved{stamp}. {_GATEWAY_OUTCOMES[outcome]}"
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
@click.option(
    "--repin",
    is_flag=True,
    help="Replace the pinned digest of a custom pack edited since it was pinned (shows both digests and asks).",
)
@click.option("--yes", is_flag=True, help="With --repin: skip the confirmation prompt.")
@click.option("--json", "json_out", is_flag=True, help="Print the result as JSON.")
@pass_ctx
def use_pack_cmd(
    app: AppContext,
    pack: str | None,
    connector: str | None,
    clear: bool,
    no_validate: bool,
    repin: bool,
    yes: bool,
    json_out: bool,
) -> None:
    """Switch the guardrail rule pack, globally or for one connector.

    PACK is a built-in preset (default, strict, permissive), a key of
    ``guardrail.custom_packs`` (a pack you already registered), the name of a
    pack under ``<policy_dir>/guardrail/``, or a directory path (``./NAME``
    for a folder in the current directory that shares a pack's name). It is
    written as ``guardrail.rule_pack``; a custom directory is also pinned as
    ``guardrail.custom_packs.NAME`` with its validated digest, so an edited
    pack is refused until ``use-pack NAME --repin`` pins it again: it shows
    the pinned and the new digest and asks (``--yes`` for scripts), and it
    runs while that stale pin fails the config check. Without ``--connector`` every
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
        dropped: list[str] | None = None,
        dropped_pins: list[str] | None = None,
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
                        "dropped_pins": list(dropped_pins or []),
                        "dropped_rule_references": list(dropped or []),
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
    _refuse_if_managed_device(app, f"guardrail use-pack {'--clear' if clear else (pack or '').strip()}".strip(), _fail)

    if clear and not connector:
        raise click.UsageError("--clear needs --connector NAME (the global pack can't be cleared, only switched).")
    if clear and pack:
        raise click.UsageError("Pass either PACK or --clear, not both.")
    if clear and repin:
        raise click.UsageError("--repin re-pins a custom pack; it can't be combined with --clear.")
    if not clear and not (pack or "").strip():
        raise click.UsageError("Missing PACK: a preset (default, strict, permissive) or a rule-pack directory.")
    # A re-pin previews, confirms and writes one read of config.yaml.
    snapshot = _read_config_snapshot(app, _fail) if repin else None
    gc = app.cfg.guardrail

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
        pin_changes, dropped_pins = _unused_pin_changes(app.cfg, {key: ""})
        stale, dropped = _stale_rule_changes(app.cfg, fallback.path, connector_key)
        result = _write_guardrail_config(
            app,
            [config_writer.Change(f"{key}.rule_pack", unset=True), *pin_changes, *stale],
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
            dropped=dropped,
            dropped_pins=dropped_pins,
            message=(
                f"{_connector_label(connector_key)} now uses the global rule pack '{fallback.pack}'."
                + (f" Dropped rule references the pack does not have: {'; '.join(dropped)}." if dropped else "")
                + f"{_dropped_pins_note(dropped_pins)} {_applied_note(app, result)}"
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

    # A directory spelling is the same pinned pack even when its key differs
    # from the basename (or it is reached through a symlink). Check every pin
    # for that directory so conflicting aliases cannot silently re-pin it.
    path_pins = []
    if kind != "preset":
        canonical = os.path.normcase(os.path.realpath(path))
        path_pins = [
            (name, pin)
            for name, pin in sorted((getattr(gc, "custom_packs", None) or {}).items())
            if getattr(pin, "path", "")
            and os.path.normcase(os.path.realpath(policy_catalog.normalize_pack_path(pin.path))) == canonical
        ]
        if path_pins and kind != "registered":
            pack_name = path_pins[0][0]
            kind = "registered"

    if kind == "preset" and not os.path.isdir(path):
        _finish(
            ok=False,
            exit_code=1,
            pack_name=pack_name,
            path=path,
            message=f"The '{pack_name}' preset isn't installed at {path}; run defenseclaw init. Nothing was changed.",
        )
    if kind == "preset" and repin:
        raise click.UsageError(f"--repin re-pins a custom pack; '{pack_name}' is a built-in preset.")

    validation: dict | None = None
    warning = ""
    digest = ""
    # (pinned, new) when --repin replaces a stale pin; never without --repin.
    repinned: tuple[str, str] | None = None

    def _refuse_stale_pin(pinned: str) -> None:
        _finish(
            ok=False,
            exit_code=1,
            pack_name=pack_name,
            path=path,
            validation=validation,
            message=(
                f"Rule pack {pack_name!r} no longer matches the digest pinned for it ({pinned or 'none'}; "
                f"the pack is now sha256:{digest}). Review the pack, then re-pin it: defenseclaw guardrail "
                f"use-pack {raw} --repin (or defenseclaw config set guardrail.custom_packs.{name_for_pin}.digest "
                f"sha256:{digest}). Nothing was changed."
            ),
        )

    name_for_pin = pack_name
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
            # The pin of this pack: its key, or the key of the pin that names
            # this directory when it was given by path (path_pins).
            own_pin = registered if registered is not None else dict(path_pins).get(pack_name)
            pinned = str(getattr(own_pin, "digest", "") or "").strip().lower().removeprefix("sha256:")
            if kind == "registered" and digest.lower() != pinned:
                old_pin = f"sha256:{pinned}" if pinned else ""
                if not repin:
                    _refuse_stale_pin(old_pin)
                repinned = (old_pin, f"sha256:{digest}")
            # Another key that pins the same directory must not hide a stale
            # pin either; --repin replaces only this pack's own pin.
            for pin_name, pin in path_pins:
                if pin_name == pack_name:
                    continue
                pinned = str(getattr(pin, "digest", "") or "").strip().lower().removeprefix("sha256:")
                if digest and digest.lower() == pinned:
                    continue
                _finish(
                    ok=False,
                    exit_code=1,
                    pack_name=pack_name,
                    path=path,
                    validation=validation,
                    message=(
                        f"Rule pack {pin_name!r} no longer matches the digest registered for it. Review the pack, "
                        f"then pin it: defenseclaw config set guardrail.custom_packs.{pin_name}.digest "
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
        existing = (getattr(gc, "custom_packs", None) or {}).get(name)
        if existing is not None:
            existing_path = policy_catalog.normalize_pack_path(str(getattr(existing, "path", "") or ""))
            existing_digest = str(getattr(existing, "digest", "") or "").lower()
            if existing_path != path:
                _fail(
                    1,
                    f"Custom pack name {name!r} is already registered at {existing_path}. "
                    "Choose a different pack name or update the registered pack explicitly. Nothing was changed.",
                )
            if existing_digest != f"sha256:{digest.lower()}":
                # Same directory, edited since it was pinned: only --repin replaces the pin.
                name_for_pin = name
                if not repin:
                    _refuse_stale_pin(existing_digest)
                repinned = (existing_digest, f"sha256:{digest}")
        if existing is None or repinned is not None:
            changes.append(
                config_writer.Change(f"guardrail.custom_packs.{name}", {"path": path, "digest": f"sha256:{digest}"})
            )
    elif repinned is not None:
        # Keep the path the pin records, also when the pack was given by a
        # directory that pin names (path_pins).
        pin = registered if registered is not None else dict(path_pins).get(name)
        changes.append(
            config_writer.Change(
                f"guardrail.custom_packs.{name}",
                {"path": str(getattr(pin, "path", "") or ""), "digest": repinned[1]},
            )
        )
    shared: list[str] = []
    if repinned is not None:
        # The pin is one guardrail.custom_packs key: every other scope that
        # selects it enforces the edited pack too, so name them before asking.
        written = {_scope_key(connector_key, None)}
        if connector_key is None:
            written |= {_scope_key(other, None) for other in (getattr(gc, "connectors", None) or {})}
        shared = _repin_shared_scopes(app.cfg, name, written)
    shared_note = (
        f" The pin is shared, so the edited pack also applies to {', '.join(shared)}." if shared else ""
    )
    key = _scope_key(connector_key, None)
    changes.append(config_writer.Change(f"{key}.rule_pack", name))
    cleared: list[str] = []
    if connector_key is None:
        for other, block in sorted((getattr(gc, "connectors", None) or {}).items()):
            if policy_catalog.configured_pack_dir(app.cfg, block):
                other_key = _scope_key(other, None)
                changes.append(config_writer.Change(f"{other_key}.rule_pack", unset=True))
                cleared.append(other)
    pin_changes, dropped_pins = _unused_pin_changes(
        app.cfg, {key: name, **{_scope_key(other, None): "" for other in cleared}}
    )
    changes.extend(pin_changes)
    # Rule references the new pack does not ship would fail the whole save (GAP-0258, GAP-0261).
    stale, dropped = _stale_rule_changes(app.cfg, path, connector_key)
    changes.extend(stale)
    if repinned is not None:
        # Every edit the write makes, from the one read it is bound to.
        planned = _planned_change_lines(changes)
        if json_out and not yes:
            _fail(
                2,
                f"Re-pinning {name!r} from {repinned[0] or 'none'} to {repinned[1]} needs your confirmation; "
                f"pass --yes with --json.{shared_note} It would change config.yaml: {'; '.join(planned)}. "
                "Nothing was changed.",
            )
        if not json_out:
            ux.warn(
                f"Re-pin {name!r} at {path}: pinned {repinned[0] or 'none'}, the pack is now {repinned[1]}. "
                f"The gateway then enforces the edited pack.{shared_note}",
                indent="  ",
            )
            click.echo("  This changes config.yaml:")
            for line in planned:
                click.echo(f"    {line}")
            if not yes and not _confirm_proceed():
                click.echo(f"  {ux.dim('Cancelled.')} Nothing was changed.")
                raise SystemExit(1)
    previous_pack = (
        policy_catalog.pack_name_for_path(
            app.cfg, policy_catalog.configured_pack_dir(app.cfg, _scope_block(app.cfg, connector_key, None))
        )[0]
        if connector_key and policy_catalog.configured_pack_dir(app.cfg, _scope_block(app.cfg, connector_key, None))
        else policy_catalog.global_pack(app.cfg).pack
    )
    try:
        result = _write_guardrail_config(app, changes, f"guardrail use-pack {name}", _fail, snapshot=snapshot)
    except config_writer.ConfigConflictError:
        # config.yaml changed or went away after the read the preview showed.
        _fail(
            1,
            f"config changed, run again: {snapshot[0] if snapshot else 'config.yaml'} changed or was removed "
            "after --repin read it. Nothing was changed.",
        )
    if connector_key is None:
        message = f"All connectors now use the '{pack_name}' rule pack."
        if cleared:
            message += " Removed per-connector packs for: " + ", ".join(cleared) + "."
    else:
        message = f"{_connector_label(connector_key)} now uses the '{pack_name}' rule pack."
    if dropped:
        message += f" Dropped rule references the pack does not have: {'; '.join(dropped)}."
    if repinned is not None:
        message += f" Re-pinned {name!r} from {repinned[0] or 'none'} to {repinned[1]}.{shared_note}"
    _log_guardrail_change(
        app,
        "guardrail-use-pack",
        f"scope={connector_key or scope} pack={name} previous={previous_pack}"
        + (f" cleared={','.join(cleared)}" if cleared else "")
        + (f" repinned={repinned[0] or 'none'}->{repinned[1]}" if repinned is not None else "")
        + (f" repin_shared={';'.join(shared)}" if shared else ""),
    )
    _finish(
        ok=True,
        exit_code=0,
        pack_name=pack_name,
        path=path,
        cleared=cleared,
        dropped=dropped,
        dropped_pins=dropped_pins,
        validation=validation,
        warning=warning,
        message=f"{message}{_dropped_pins_note(dropped_pins)} {_applied_note(app, result)}",
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
    to every connector; disable a global pack at the global scope. A pack
    asserts something about the connector's
    environment (for example that its cloud credentials reach production);
    DefenseClaw takes that as the operator's word and never infers it from
    resource names.
    """


@protection.command("list")
@click.option("--json", "json_out", is_flag=True, help="Print the packs and scopes as JSON.")
@pass_ctx
def protection_list_cmd(app: AppContext, json_out: bool) -> None:
    """List the opt-in protection packs and which scopes have them on.

    Read-only. Scopes include global, active connectors, and configured profiles.
    """
    from defenseclaw import policy_catalog

    packs = policy_catalog.protection_packs()
    scopes = [
        {"scope": row.scope, "pack": row.pack, "path": row.pack_path, "enabled": list(row.protection)}
        for row in policy_catalog.scope_postures(app.cfg)
    ]
    gc = app.cfg.guardrail
    fallback = policy_catalog.global_pack(app.cfg).path
    for name, profile in sorted((getattr(gc, "profiles", None) or {}).items()):
        profile_scopes = [(None, f"profile:{name}")]
        profile_scopes.extend(
            (key, f"profile:{name}/connector:{key}")
            for key in sorted(getattr(profile, "connectors", None) or {})
        )
        for connector, scope in profile_scopes:
            blocks = _scope_blocks(app.cfg, connector, name)
            path = fallback
            for block in blocks:
                path = policy_catalog.configured_pack_dir(app.cfg, block) or path
            enabled = dict.fromkeys(
                [
                    *(pack for block in blocks for pack in policy_catalog.configured_protection(block)),
                    *policy_catalog.enabled_protection(path),
                ]
            )
            scopes.append({
                "scope": scope,
                "pack": policy_catalog.pack_name_for_path(app.cfg, path)[0],
                "path": path,
                "enabled": list(enabled),
            })
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
        if scope["scope"] == "global" or scope["scope"].startswith("profile:"):
            who = scope["scope"]
        else:
            who = f"{_connector_label(scope['scope'])} ({scope['scope']})"
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
    _refuse_if_managed_device(app, f"guardrail protection {'enable' if enable else 'disable'} {name}", _fail)
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
    path = f"{_scope_key(connector_key, profile_name)}.rules.protections"
    with _config_lock(app, _fail):
        on_now = _listed_ids(_listed_now(app, path, _rule_ids(rules, "protections")))
        if not enable:
            wider_scopes = [("guardrail", "global", None, None)]
            if connector_key:
                wider_scopes.append(
                    (_scope_key(connector_key, None), _scope_words(connector_key, None), connector_key, None)
                )
            if profile_name:
                wider_scopes.append(
                    (_scope_key(None, profile_name), _scope_words(None, profile_name), None, profile_name)
                )
            for wider_path, wider_words, wider_connector, wider_profile in wider_scopes:
                if wider_path == _scope_key(connector_key, profile_name):
                    continue
                wider_rules = _scope_rules(app.cfg, wider_connector, wider_profile)
                inherited = _listed_ids(
                    _listed_now(app, f"{wider_path}.rules.protections", _rule_ids(wider_rules, "protections"))
                )
                if name in inherited:
                    _fail(
                        1,
                        f"{pack.title} is still active for {where} because it is enabled at the "
                        f"{wider_words} scope. Disable it there to turn it off; nothing was changed.",
                    )
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
        change = (
            config_writer.Change(path, desired)
            if desired else config_writer.Change(
                path, unset=True, prune_empty_to=_rule_prune_scope(connector_key, profile_name)
            )
        )
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


def _listed_ids(values) -> list[str]:
    return [str(v) for v in (values or []) if str(v or "").strip()]


def _rule_ids(rules, field: str) -> list[str]:
    return _listed_ids(getattr(rules, field, None))


def _scope_blocks(cfg, connector_key: str | None, profile: str | None) -> list:
    """The config blocks that shape a scope, widest first: global, connector, profile, profile connector."""
    gc = cfg.guardrail
    profiles = getattr(gc, "profiles", None) or {}
    blocks = [gc, (getattr(gc, "connectors", None) or {}).get(connector_key) if connector_key else None]
    if profile:
        block = profiles.get(profile)
        blocks.append(block)
        if block is not None and connector_key:
            blocks.append((getattr(block, "connectors", None) or {}).get(connector_key))
    return [b for b in blocks if b is not None]


def _scope_rule_defaults(cfg, connector_key: str | None, profile: str | None) -> dict[str, bool]:
    """Rule id -> shipped on/off for the rule pack a scope enforces, protection packs layered on.

    Empty when the pack's rule files can't be read here (the caller then keeps the plain behaviour)."""
    from defenseclaw import policy_catalog

    blocks = _scope_blocks(cfg, connector_key, profile)
    pack_dir = ""
    for block in reversed(blocks):
        pack_dir = policy_catalog.configured_pack_dir(cfg, block)
        if pack_dir:
            break
    pack_dir = pack_dir or policy_catalog.scope_pack_path(cfg, connector_key or "")
    protections = [str(n) for b in blocks for n in (getattr(getattr(b, "rules", None), "protections", None) or [])]
    return policy_catalog.rule_defaults_with_protections(pack_dir, protections)


def _stale_rule_changes(cfg, pack_dir: str, connector_key: str | None) -> tuple[list, list[str]]:
    """Writer changes that drop ``guardrail.rules`` references the new rule pack does not ship.

    A rule id the pack lacks fails the whole config, so after a pack switch the
    old references would leave no single command that saves (GAP-0258, GAP-0261).
    A global switch covers every scope that has no pack of its own. Returns
    ``(changes, dropped "<key>.rules.<field>: <id>")``; nothing is dropped when the
    new pack's rules can't be read."""
    from defenseclaw import config_writer, policy_catalog

    base = policy_catalog.pack_rule_defaults(pack_dir)
    if not base:
        return [], []
    gc = cfg.guardrail
    scopes: list[tuple[str, object, str | None, str | None]] = []
    if connector_key:
        scopes.append((_scope_key(connector_key, None), _scope_block(cfg, connector_key, None), connector_key, None))
    else:
        scopes.append(("guardrail", gc, None, None))
        scopes.extend(
            (f"guardrail.connectors.{c}", b, c, None)
            for c, b in sorted((gc.connectors or {}).items())
        )
        for name, profile in sorted((gc.profiles or {}).items()):
            if getattr(profile, "rule_pack", ""):
                continue
            scopes.append((f"guardrail.profiles.{name}", profile, None, name))
            scopes.extend(
                (f"guardrail.profiles.{name}.connectors.{c}", b, c, name)
                for c, b in sorted((profile.connectors or {}).items())
                if not getattr(b, "rule_pack", "")
            )
    changes: list = []
    dropped: list[str] = []
    for key, block, scope_connector, scope_profile in scopes:
        rules = getattr(block, "rules", None)
        if rules is None:
            continue
        protections = [
            str(protection)
            for inherited in _scope_blocks(cfg, scope_connector, scope_profile)
            for protection in (getattr(getattr(inherited, "rules", None), "protections", None) or [])
        ]
        known = policy_catalog.rule_defaults_with_protections(pack_dir, protections)
        for field in ("enable", "disable"):
            ids = _rule_ids(rules, field)
            kept = [i for i in ids if i in known]
            if len(kept) != len(ids):
                dropped.extend(f"{key}.rules.{field}: {i}" for i in ids if i not in known)
                path = f"{key}.rules.{field}"
                changes.append(
                    config_writer.Change(path, kept)
                    if kept else config_writer.Change(
                        path, unset=True, prune_empty_to=_rule_prune_scope(scope_connector, scope_profile)
                    )
                )
        overrides = dict(getattr(rules, "severity_overrides", None) or {})
        kept_overrides = {i: v for i, v in overrides.items() if i in known}
        if len(kept_overrides) != len(overrides):
            dropped.extend(f"{key}.rules.severity_overrides: {i}" for i in overrides if i not in known)
            path = f"{key}.rules.severity_overrides"
            changes.append(
                config_writer.Change(path, kept_overrides)
                if kept_overrides else config_writer.Change(
                    path, unset=True, prune_empty_to=_rule_prune_scope(scope_connector, scope_profile)
                )
            )
    return changes, dropped


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

    _refuse_if_managed_device(app, f"guardrail rule {'enable' if enable else 'disable'} {rule_id.strip()}", _fail)
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
    key = _scope_key(connector_key, profile_name)
    where = _scope_words(connector_key, profile_name)
    state = "on" if enable else "off"
    with _config_lock(app, _fail):
        target = _listed_ids(_listed_now(app, f"{key}.rules.{add_to}", _rule_ids(rules, add_to)))
        other = _listed_ids(_listed_now(app, f"{key}.rules.{remove_from}", _rule_ids(rules, remove_from)))
        changes = []
        # enable is for rules the pack ships off and disable for rules it ships on: when the pack
        # already ships the rule in the wanted state (and no wider scope undoes that), dropping the
        # opposite entry is all it takes, and a leftover entry would only break a later pack switch (GAP-0258).
        own_block = _scope_block(app.cfg, connector_key, profile_name)
        undone_above = any(
            rule_id in _rule_ids(getattr(block, "rules", None), remove_from)
            for block in _scope_blocks(app.cfg, connector_key, profile_name)
            if block is not own_block
        )
        defaults = {} if undone_above else _scope_rule_defaults(app.cfg, connector_key, profile_name)
        shipped_as_wanted = defaults.get(rule_id) is enable
        if rule_id not in target and not shipped_as_wanted:
            changes.append(config_writer.Change(f"{key}.rules.{add_to}", [*target, rule_id]))
        if rule_id in other:
            rest = [v for v in other if v != rule_id]
            changes.append(
                config_writer.Change(f"{key}.rules.{remove_from}", rest)
                if rest
                else config_writer.Change(
                    f"{key}.rules.{remove_from}", unset=True,
                    prune_empty_to=_rule_prune_scope(connector_key, profile_name),
                )
            )
        if not changes:
            message = f"Rule {rule_id} is already turned {state} for {where}; nothing was changed."
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

    _refuse_if_managed_device(app, f"guardrail rule severity {rule_id.strip()} {severity.upper()}", _fail)
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
    scope_key = _scope_key(connector_key, profile_name)
    prune_to = _rule_prune_scope(connector_key, profile_name)
    change = (
        config_writer.Change(key, unset=True, prune_empty_to=prune_to)
        if level == "DEFAULT" else config_writer.Change(key, level)
    )
    _preflight_config_write(app)
    result = _write_guardrail_config(app, [change], f"guardrail rule severity {rule_id} {level}", _fail)
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

    _refuse_if_managed_device(app, f"guardrail suppress {'add' if entry is not None else 'remove'} {sid}", _fail)
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{0,127}", sid):
        _fail(1, f"{sid!r} isn't a suppression ID (letters, digits, _ and -). Nothing was changed.")
    profile_name = _resolve_profile(app, profile, _fail)
    connector_key = normalize_connector(connector) if connector else None
    if connector and not profile_name:
        connector_key, problem = _resolve_scope_connector(app, connector)
        if problem:
            _fail(1, problem)
    rules = _scope_rules(app.cfg, connector_key, profile_name)
    path = f"{_scope_key(connector_key, profile_name)}.rules.suppressions"
    where = _scope_words(connector_key, profile_name)
    with _config_lock(app, _fail):
        listed = _listed_now(app, path, list(getattr(rules, "suppressions", None) or []))
        current = [
            {
                field: str((s.get(field) if isinstance(s, dict) else getattr(s, field, "")) or "")
                for field in ("id", "finding_pattern", "entity_pattern", "reason")
            }
            for s in listed
        ]
        exists = any(s["id"] == sid for s in current)
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
        change = (
            config_writer.Change(path, updated)
            if updated else config_writer.Change(
                path, unset=True, prune_empty_to=_rule_prune_scope(connector_key, profile_name)
            )
        )
        _preflight_config_write(app)
        verb = "add" if entry is not None else "remove"
        result = _write_guardrail_config(app, [change], f"guardrail suppress {verb} {sid}", _fail)
    _log_guardrail_change(app, "guardrail-suppress", f"scope={_scope_key(connector_key, profile_name)} id={sid} {verb}")
    state = "added" if entry is not None else "removed"
    _done(True, 0, f"Suppression {sid} {state} for {where}. {_applied_note(app, result)}")


# ---------------------------------------------------------------------------
# guardrail mode — observe vs action without re-running setup
# ---------------------------------------------------------------------------


class _ActionHookInspectionError(Exception):
    def __init__(self, connector: str) -> None:
        self.connector = connector
        super().__init__(connector)


def _action_hook_switch_problems(
    cfg, *, connector: str | None = None, global_mode: str | None = None
) -> list[tuple[str, str]]:
    """Find hooks-off settings for the enabled connectors an action request would cover."""
    from defenseclaw import policy_catalog
    from defenseclaw.hook_integrity import agent_hook_switch_problems

    gc = cfg.guardrail
    if not gc.enabled:
        return []
    if connector:
        targets = [connector]
    else:
        desired_global_mode = gc.mode if global_mode is None else global_mode
        try:
            actives = cfg.active_connectors()
        except Exception as exc:  # noqa: BLE001 - an unreadable roster cannot prove enforcement.
            raise _ActionHookInspectionError("active connector roster") from exc
        targets = []
        for name in actives:
            override = gc._connector_override(name)
            mode = (getattr(override, "mode", "") or "").strip() if override is not None else ""
            if gc.effective_enabled(name) and policy_catalog.mode_label(mode or desired_global_mode) == "action":
                targets.append(name)

    switched_off = []
    for name in targets:
        try:
            problems = agent_hook_switch_problems(cfg, normalize_connector(name))
        except Exception as exc:  # noqa: BLE001 - unknown agent settings cannot prove enforcement.
            raise _ActionHookInspectionError(name) from exc
        switched_off.extend((name, problem) for problem in problems)
    return switched_off


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
    started). Cursor's hook fail mode follows its guardrail mode.
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
    becomes_action = mode == "action" or (clear and policy_catalog.mode_label(gc.mode) == "action")

    if becomes_action and gc.enabled:
        # An unchanged action request must check the agent too: its settings
        # may have turned the hooks off since the last mode change. Check
        # every connector the requested global action mode would cover, even
        # when the gateway is stopped and no runtime read-back is available.
        from defenseclaw.hook_integrity import repair_command

        try:
            switched_off = _action_hook_switch_problems(app.cfg, connector=connector_key, global_mode="action")
        except _ActionHookInspectionError as exc:
            _finish(
                ok=False,
                exit_code=1,
                new_mode=previous,
                previous=previous,
                message=f"Nothing was changed: {_connector_label(exc.connector)} hook settings could not be inspected.",
            )
            return
        if switched_off:
            details = "; ".join(f"{_connector_label(name)}: {problem}" for name, problem in switched_off)
            _finish(
                ok=False,
                exit_code=1,
                new_mode=previous,
                previous=previous,
                notes=[f"Next: {repair_command(name, problem)}" for name, problem in switched_off],
                message=f"Nothing was changed: action mode cannot guard these connectors: {details}",
            )
            return

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
    # Keep the persisted Cursor value in sync so later setup, status and
    # migration reads cannot see the previous mode's hook posture.
    for c in affected:
        if normalize_connector(c) == "cursor":
            if gc.connectors:
                _connector_block_for_write(gc, c).hook_fail_mode = fail_after[c]
            else:
                gc.hook_fail_mode = fail_after[c]
    fail_flips = {c: fm for c, fm in fail_after.items() if fm != fail_before[c]}
    if fail_flips:
        # Only hook connectors bake a fail mode into their registration.
        from defenseclaw.commands.cmd_setup import _HOOK_ENFORCED_CONNECTORS

        fail_flips = {c: fm for c, fm in fail_flips.items() if normalize_connector(c) in _HOOK_ENFORCED_CONNECTORS}

    try:
        app.cfg.save()
    except (OSError, ValueError, ConfigWriteError) as exc:
        _finish(ok=False, exit_code=1, new_mode=previous, previous=previous, message=_guardrail_write_error(exc))
    _log_guardrail_change(
        app, "guardrail-mode", f"scope={scope} mode={new_mode} previous={previous} cleared={str(clear).lower()}"
    )
    # Decisions read the gateway's live configuration generation, so a mode
    # change reloads hot. Only per-user Cursor's hook fail mode follows the
    # guardrail mode (observe open, action closed; every other hook keeps its
    # fail mode across a mode switch, owner rule): its registration bakes the
    # value, so a flip restarts the gateway, which re-bakes it.
    outcome = _apply_to_running_gateway(app, needs_restart=bool(fail_flips), restart=restart, quiet=json_out)
    unguarded = (
        _unguarded_hook_connectors(app, affected) if new_mode == "action" and outcome in ("live", "restarted") else []
    )

    observe_effect = "logs policy findings without blocking on them"
    if any(mode == "closed" for mode in fail_after.values()):
        observe_effect += "; a gateway outage can still deny a call when hook fail mode is closed"
    plain = {"action": "blocks findings at or above the block-at severity", "observe": observe_effect}
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
    if unguarded:
        # Action mode without registered hooks blocks nothing; the command must
        # not report success then (GAP-1035).
        notes = [f"Next: {step}" for _name, _detail, step in unguarded if step] + notes
        names = ", ".join(_connector_label(name) for name, _detail, _step in unguarded)
        _finish(
            ok=False,
            exit_code=1,
            new_mode=new_mode,
            previous=previous,
            source=source,
            changed=True,
            not_covered=not_covered,
            gateway=outcome,
            notes=notes,
            message=(
                f"The mode is saved as action, but {names} is not guarded, so nothing is blocked yet: "
                + "; ".join(detail for _name, detail, _step in unguarded)
            ),
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
    except (OSError, ValueError, ConfigWriteError) as exc:
        setattr(target, setting, previous)
        _finish(ok=False, exit_code=1, message=_guardrail_write_error(exc), previous=previous, requested=True)
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
    are all tried and the strictest matching profile wins. Only verified identities
    select a profile, so ``explain`` asks the running gateway.
    """


def _profile_settings(profile) -> dict:
    out: dict = {}
    for key in ("description", "mode", "block_at", "alert_at", "rule_pack", "block_message"):
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
                    ("rule_pack", pc.rule_pack),
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
    ux.echo(f"  • {ux._style('assignments (strictest match wins):', fg='bright_black', bold=True)}")
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
# directory before it answers, waiting at most 12 s for that lookup (and 10 s
# for the account lookup before it), so the client waits longer than both.
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
    import requests

    from defenseclaw.gateway import (
        OrchestratorClient,
        current_profile_account,
        gateway_api_client_host,
        gateway_reload_notice,
    )

    if not user:
        from defenseclaw.commands.cmd_status import _enterprise_profile

        user = current_profile_account(secure_client=_enterprise_profile(app.cfg) == "secure_client")[0]
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
        # A running gateway still on its previous port is not "stopped".
        notice = gateway_reload_notice(app.cfg)
        ux.subhead(notice or "Start it with: defenseclaw-gateway start", indent="  ")
        raise SystemExit(1) from None
    # The gateway answers 200 with lookup_error for an account it could not
    # name (a typo, or a bare name two accounts share); the answer is still
    # printed, and the command fails (GAP-1239).
    unresolved = bool(result.get("lookup_error")) and not (result.get("subject") or {}).get("user_id")
    if json_out:
        click.echo(json.dumps(result, indent=2, sort_keys=True))
        if unresolved:
            raise SystemExit(1)
        return
    ux.section("Guardrail profile resolution", indent="  ")
    # The answer is the gateway's, which may still run an earlier generation
    # of config.yaml (GAP-0363).
    if notice := gateway_reload_notice(app.cfg):
        ux.warn(notice, indent="  ")
    if not result.get("profiles_configured"):
        click.echo(f"  {ux.dim('No guardrail profiles are configured; guardrail.* applies.')}")
    subject = result.get("subject") or {}
    if subject:
        who = subject.get("upn") or subject.get("principal") or subject.get("user_name") or user
        groups = "groups unknown" if result.get("lookup_error") else f"{int(subject.get('group_count') or 0)} group(s)"
        click.echo(f"  user:    {who} ({groups})")
    profile = result.get("profile") or ux.dim("none (guardrail.* applies)")
    click.echo(f"  profile: {profile}")
    cache = result.get("cache") or {}
    cache_refused = cache.get("refused") is True or bool(cache.get("refused_reason"))
    cache_settled = cache.get("refused") is False and not cache_refused
    if result.get("match"):
        reason = result["match"]
        if result.get("matched_group"):
            reason += f" ({result['matched_group']})"
        # GAP-0275: this lookup worked, but the gateway's own is failing.
        # Show only the cache decision and refusal details the gateway supplied.
        if cache.get("match") == "default_lookup_failed" and result["match"] != "default_lookup_failed":
            if cache_refused:
                missing_fact = cache.get("refused_reason") or "missing fact not supplied by gateway"
                reason += f" (requests are refused: {missing_fact})"
            elif cache_settled:
                reason += (
                    " (requests use the default profile (default_lookup_failed); "
                    "no assignment needs the missing fact)"
                )
            else:
                reason += " (gateway reports default_lookup_failed for requests; refusal state not supplied)"
        click.echo(f"  match:   {reason}")
    if result.get("refused"):
        # GAP-0522: requests that need an unproven identity fact are refused;
        # the profile above is a candidate, not what the account gets.
        click.echo(f"  refused: {result.get('refused_reason') or 'an identity fact is unproven'}")
    if result.get("digest"):
        click.echo(f"  digest:  {result['digest']}")
    if cache:
        if cache_refused:
            missing_fact = cache.get("refused_reason") or "missing fact not supplied by gateway"
            cache_decision = f"(refused: {missing_fact}, match {cache.get('match')})"
        elif cache.get("match") == "default_lookup_failed" and not cache_settled:
            cache_decision = "(match default_lookup_failed; refusal state not supplied)"
        else:
            cache_decision = f"(profile {cache.get('profile') or 'none'}, match {cache.get('match')})"
        if cache.get("failing_since"):
            click.echo(
                f"  cache:   requests have no cached directory facts {cache_decision}; "
                "the gateway retries its directory lookup"
            )
        elif "age_seconds" in cache and "refresh_after_seconds" in cache:
            age = int(cache["age_seconds"])
            lifetime = age + int(cache["refresh_after_seconds"])
            click.echo(
                f"  cache:   requests use directory facts {_age_text(age)} old "
                f"{cache_decision}; the gateway refreshes them after {_age_text(lifetime)}"
            )
        else:
            click.echo(f"  cache:   directory fact age unavailable {cache_decision}")
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
    if unresolved:
        raise SystemExit(1)


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
