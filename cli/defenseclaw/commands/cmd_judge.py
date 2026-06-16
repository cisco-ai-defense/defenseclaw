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

"""``defenseclaw guardrail judge`` — LLM-judge configuration helpers.

The judge runs in two lanes with different control models:

* **Proxy lane** (openclaw / zeptoclaw): the judge runs automatically
  whenever ``guardrail.judge.enabled`` is true. There is no per-connector
  gate — nothing to add or remove.
* **Hook lane** (hermes, opencode, claudecode, …): gated per connector by
  ``guardrail.judge.hook_connectors``, **default off**. The gate ships
  empty deliberately — the judge adds latency (up to
  ``guardrail.judge.hook_timeout``, default 5s) and LLM cost per inspected
  hook call, so upgrades must not silently change behavior. The cost of
  that safety default is that every operator must perform an explicit
  opt-in, and before this command the only way to do that was hand-editing
  ``config.yaml`` and manually restarting the gateway.

``defenseclaw guardrail judge`` is that missing authoring surface:

  defenseclaw guardrail judge add hermes      # opt one connector in
  defenseclaw guardrail judge add all         # every hook connector
  defenseclaw guardrail judge remove opencode
  defenseclaw guardrail judge list            # gate + effective state

The group lives under ``guardrail`` (not ``setup``) because it is a
day-to-day policy lever, like ``guardrail hilt`` and ``guardrail
fail-mode`` — ``setup`` stays reserved for wizards and one-time
authoring. The flat ``add``/``remove``/``list`` shape gates only the
hook lane; proxy connectors are rejected with an explanation (their
lane is always judged when the judge is enabled), so the scoping lives
in validation rather than the command name.

Like ``cmd_guardrail`` (which registers this group), this module never
imports ``cmd_setup`` at module load — the heavy click tree isn't
needed for ``judge list``. Helpers lazily import it inside the command
bodies; tests patch ``cmd_setup._restart_services`` as usual.
"""

from __future__ import annotations

import click

from defenseclaw import connector_paths, ux
from defenseclaw.context import AppContext, pass_ctx

#: Sentinel accepted by the Go gate meaning "every hook connector".
ALL_CONNECTORS = "*"


def _connector_sets() -> tuple[frozenset[str], frozenset[str]]:
    """Return ``(hook_enforced, proxy_backed)`` lazily from cmd_setup."""
    from defenseclaw.commands.cmd_setup import (
        _HOOK_ENFORCED_CONNECTORS,
        _PROXY_BACKED_CONNECTORS,
    )

    return _HOOK_ENFORCED_CONNECTORS, _PROXY_BACKED_CONNECTORS


def _normalize_target(raw: str) -> str:
    """Normalize a CONNECTOR argument.

    ``all`` is the primary every-connector form (no shell quoting
    needed); the literal ``*`` — the actual config value — is accepted
    for parity with config.yaml and scripts. Rejects empty input here
    rather than relying on :func:`connector_paths.normalize`, whose
    empty-input behavior is to default to ``"openclaw"`` — which would
    turn a blank argument into a confusing "proxy-backed connector"
    error.
    """
    cleaned = (raw or "").strip()
    if not cleaned:
        raise click.ClickException("connector name is required ('all' for every hook connector)")
    if cleaned == ALL_CONNECTORS or cleaned.lower() == "all":
        return ALL_CONNECTORS
    return connector_paths.normalize(cleaned)


def _gate_is_all(gate: list[str]) -> bool:
    """True when the gate contains the every-connector sentinel.

    Matching mirrors the Go gate (``JudgeConfig.HookConnectorEnabled``:
    TrimSpace + EqualFold) so the CLI never disagrees with what the
    gateway actually enforces — a hand-edited ``" * "`` or ``Hermes``
    entry is live on the gateway and must be visible here too.
    """
    return any((entry or "").strip() == ALL_CONNECTORS for entry in gate)


def _gate_contains(gate: list[str], name: str) -> bool:
    """True when ``name`` (already normalized lowercase) is gated.

    Case-insensitive + whitespace-tolerant for Go-gate parity — see
    :func:`_gate_is_all`.
    """
    return any((entry or "").strip().lower() == name for entry in gate)


def _gate_without(gate: list[str], name: str) -> list[str]:
    """Return ``gate`` minus every entry matching ``name`` (fold/strip)."""
    return [e for e in gate if (e or "").strip().lower() != name]


def _validate_connector(name: str) -> None:
    """Reject names the hook gate can never apply to.

    Proxy-backed connectors get a dedicated message — their lane is
    always judged when the judge is enabled, so listing them in
    ``hook_connectors`` would *look* meaningful while doing nothing.
    """
    hook_enforced, proxy_backed = _connector_sets()
    if name in hook_enforced:
        return
    if name in proxy_backed:
        raise click.ClickException(
            f"'{name}' is a proxy-backed connector — its traffic is already "
            f"judged whenever guardrail.judge.enabled is true. "
            f"hook_connectors only gates hook-based connectors: "
            f"{', '.join(sorted(hook_enforced))}."
        )
    raise click.ClickException(
        f"unknown connector '{name}'. Hook-based connectors: "
        f"{', '.join(sorted(hook_enforced))} (or 'all')."
    )


def _warn_if_inert(app: AppContext, gc) -> None:
    """Surface the two states in which a gate edit silently does nothing."""
    if not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — the gate takes effect the "
            "next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )
    if not gc.judge.enabled:
        ux.warn(
            "guardrail.judge.enabled is false — the hook gate has no effect "
            "until the judge is enabled (defenseclaw setup guardrail).",
            indent="  ",
        )


def _warn_if_unconfigured(app: AppContext, name: str) -> None:
    if name == ALL_CONNECTORS:
        return
    try:
        active = set(app.cfg.active_connectors())
    except Exception:  # noqa: BLE001 — older configs; skip the hint.
        return
    if name not in active:
        ux.warn(
            f"'{name}' is not a configured connector yet "
            f"(active: {', '.join(sorted(active)) or 'none'}) — the gate "
            f"entry is kept and becomes effective once the connector is "
            f"set up.",
            indent="  ",
        )


def _gate_label(gate: list[str]) -> str:
    """Human form of the gate: the CLI speaks ``all``; the config stores
    the literal ``*`` (what the Go gate reads) but the display sticks to
    the input language."""
    if not gate:
        return "[] (hook lane off)"
    if _gate_is_all(gate):
        return "all"
    return str(gate)


def _save_and_restart(app: AppContext, gc, *, restart: bool, action: str) -> None:
    try:
        app.cfg.save()
        ux.ok(
            f"Config saved (guardrail.judge.hook_connectors: "
            f"{_gate_label(gc.judge.hook_connectors)})",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort() from exc

    _warn_if_inert(app, gc)

    if restart and gc.enabled:
        # Lazy import — see module docstring. The judge instance and its
        # hook wiring (APIServer.SetHookJudge) are built at sidecar
        # startup, so gate edits need a bounce to take effect.
        from defenseclaw.commands import cmd_setup

        actives = app.cfg.active_connectors()
        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=app.cfg.active_connector(),
            connectors=actives,
        )

    if app.logger:
        app.logger.log_action(
            "judge-hooks",
            "config",
            f"{action} hook_connectors={gc.judge.hook_connectors} restart={restart}",
        )


@click.group("judge")
def judge() -> None:
    """Gate which hook connectors forward content to the LLM judge.

    \b
    The judge always covers the proxy lane when enabled. Hook connectors
    (hermes, opencode, claudecode, …) are opt-in per connector via
    guardrail.judge.hook_connectors — empty means off.
    """


@judge.command("add")
@click.argument("connector")
@click.option(
    "--timeout",
    "hook_timeout",
    type=float,
    default=None,
    help=(
        "Also set guardrail.judge.hook_timeout (seconds). Caps the judge "
        "round-trip on the hook lane; 0/unset = gateway default (5s). The "
        "hook scripts allow 10s total, so values above ~8s risk the agent "
        "hanging up before a verdict lands."
    ),
)
@click.option(
    "--enable",
    is_flag=True,
    default=False,
    help=(
        "Also set guardrail.judge.enabled=true. By default 'judge add' only "
        "edits the hook gate and warns when the judge is off — the gate has "
        "no effect until the judge is enabled (via 'setup guardrail' or this "
        "flag)."
    ),
)
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway so the gate takes effect (default: on).",
)
@pass_ctx
def judge_add(
    app: AppContext,
    connector: str,
    hook_timeout: float | None,
    enable: bool,
    restart: bool,
) -> None:
    """Opt CONNECTOR into the hook-lane LLM judge ('all' = every hook connector).

    \b
    Examples:
      defenseclaw guardrail judge add hermes
      defenseclaw guardrail judge add hermes --enable
      defenseclaw guardrail judge add all
      defenseclaw guardrail judge add opencode --timeout 8
    """
    name = _normalize_target(connector)
    if name != ALL_CONNECTORS:
        _validate_connector(name)

    gc = app.cfg.guardrail
    gate = list(gc.judge.hook_connectors or [])

    timeout_changed = False
    if hook_timeout is not None:
        if hook_timeout < 0:
            raise click.ClickException("--timeout must be >= 0 (0 = gateway default)")
        if hook_timeout > 8:
            ux.warn(
                f"--timeout {hook_timeout:g}s leaves under "
                f"{max(0.0, 10 - hook_timeout):g}s of the hook scripts' 10s "
                f"budget for everything else (regex, AID, transport).",
                indent="  ",
            )
        if gc.judge.hook_timeout != hook_timeout:
            gc.judge.hook_timeout = hook_timeout
            timeout_changed = True

    # --enable is the J1 convenience opt-in: `judge add` populates the hook
    # gate but, by design, never flips judge.enabled — so a connector can be
    # "added" while the judge stays globally off and the gate sits inert.
    # Operators who want the add to also turn the judge on pass --enable
    # instead of running a separate `setup guardrail`. Idempotent: only a
    # real off→on transition counts as a change, so re-passing --enable on an
    # already-enabled judge never forces a needless save+restart.
    enable_changed = False
    if enable and not gc.judge.enabled:
        gc.judge.enabled = True
        enable_changed = True

    # Gate update: compute the change and stash the no-op reason instead
    # of echoing it inline — "nothing to do" must only print when the
    # WHOLE command is a no-op. A gate no-op combined with a --timeout
    # change still saves and restarts, and saying "nothing to do" right
    # before bouncing the gateway is a lie.
    gate_changed = False
    noop_reason = None
    click.echo()
    if enable_changed:
        click.echo("  " + ux.dim("enabling guardrail.judge.enabled (was off)."))
    if name == ALL_CONNECTORS:
        if _gate_is_all(gate):
            noop_reason = "hook_connectors is already all"
        else:
            if gate:
                click.echo(
                    "  "
                    + ux.dim(
                        f"replacing explicit list {gate} with all "
                        f"(covers every hook connector, including future ones)."
                    )
                )
            gc.judge.hook_connectors = [ALL_CONNECTORS]
            gate_changed = True
    elif _gate_is_all(gate):
        noop_reason = f"hook_connectors is all — '{name}' is already covered"
    elif _gate_contains(gate, name):
        noop_reason = f"'{name}' is already in hook_connectors"
    else:
        gate.append(name)
        gc.judge.hook_connectors = gate
        gate_changed = True

    if not gate_changed and not timeout_changed and not enable_changed:
        click.echo("  " + ux.dim(f"{noop_reason} — nothing to do."))
        _warn_if_inert(app, gc)
        click.echo()
        return
    if not gate_changed and noop_reason:
        saved = []
        if enable_changed:
            saved.append("judge.enabled")
        if timeout_changed:
            saved.append("hook_timeout")
        click.echo("  " + ux.dim(f"{noop_reason} — saving {' + '.join(saved)} only."))

    _warn_if_unconfigured(app, name)
    _save_and_restart(app, gc, restart=restart, action=f"add {name}")
    click.echo()


@judge.command("remove")
@click.argument("connector")
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway so the gate takes effect (default: on).",
)
@pass_ctx
def judge_remove(app: AppContext, connector: str, restart: bool) -> None:
    """Opt CONNECTOR out of the hook-lane LLM judge ('all' turns the lane off).

    \b
    Examples:
      defenseclaw guardrail judge remove opencode
      defenseclaw guardrail judge remove all      # hook lane off entirely
    """
    name = _normalize_target(connector)
    # Same validation as `add`: a typo or alias spelling (e.g.
    # `claude-code` for the canonical `claudecode`) must fail loudly,
    # not soft-succeed with "nothing to do" while the connector stays
    # judged — scripts chain on the exit code.
    if name != ALL_CONNECTORS:
        _validate_connector(name)

    gc = app.cfg.guardrail
    gate = list(gc.judge.hook_connectors or [])

    click.echo()
    if name == ALL_CONNECTORS:
        if not gate:
            click.echo("  " + ux.dim("hook_connectors is already empty — nothing to do."))
            click.echo()
            return
        gc.judge.hook_connectors = []
    elif _gate_is_all(gate):
        # Auto-expand the every-connector sentinel (J6): removing one
        # connector from `*` means "every hook connector except this one".
        # Materialize `*` into the canonical hook-enforced roster minus the
        # removed connector rather than erroring. We expand to the full
        # roster (not just the active connectors) so coverage still matches
        # what `*` meant — connectors set up later stay judged; only the
        # named one is dropped. `name` passed _validate_connector above, so
        # it is guaranteed a member of the roster.
        hook_enforced, _ = _connector_sets()
        gate = sorted(hook_enforced - {name})
        gc.judge.hook_connectors = gate
        click.echo(
            "  "
            + ux.dim(
                f"hook_connectors was all — expanded to every hook "
                f"connector except '{name}': {gate}."
            )
        )
    elif _gate_contains(gate, name):
        gate = _gate_without(gate, name)
        gc.judge.hook_connectors = gate
        if not gate:
            click.echo("  " + ux.dim("hook_connectors is now empty — hook-lane judge off."))
    else:
        click.echo("  " + ux.dim(f"'{name}' is not in hook_connectors — nothing to do."))
        click.echo()
        return

    _save_and_restart(app, gc, restart=restart, action=f"remove {name}")
    click.echo()


@judge.command("list")
@pass_ctx
def judge_list(app: AppContext) -> None:
    """Show the hook-lane gate and the effective per-connector judge state."""
    gc = app.cfg.guardrail
    gate = list(gc.judge.hook_connectors or [])
    hook_enforced, proxy_backed = _connector_sets()

    click.echo()
    click.echo(f"  {ux.bold('guardrail.judge.enabled:')}         {ux.accent(str(bool(gc.judge.enabled)).lower())}")
    click.echo(f"  {ux.bold('guardrail.judge.hook_connectors:')} {ux.accent(_gate_label(gate))}")
    timeout = gc.judge.hook_timeout or 0
    timeout_label = f"{timeout:g}s" if timeout else "5s (gateway default)"
    click.echo(f"  {ux.bold('guardrail.judge.hook_timeout:')}    {ux.accent(timeout_label)}")
    click.echo()

    try:
        actives = list(app.cfg.active_connectors())
    except Exception:  # noqa: BLE001 — older configs.
        actives = []
    if not actives:
        click.echo("  " + ux.dim("no connectors configured."))
        click.echo()
        return

    judged_prereqs = bool(gc.enabled) and bool(gc.judge.enabled)
    click.echo("  " + ux.bold("effective state per connector:"))
    for nm in actives:
        if nm in proxy_backed:
            state = (
                "judged (proxy lane)" if judged_prereqs else "judge off"
            )
            note = ""
        else:
            gated = _gate_is_all(gate) or _gate_contains(gate, nm)
            if nm not in hook_enforced:
                state = "unknown connector"
                note = ""
            elif judged_prereqs and gated:
                state = "judged (hook lane)"
                note = ""
            elif gated:
                state = "gated on, judge inactive"
                note = (
                    " — guardrail disabled"
                    if not gc.enabled
                    else " — judge disabled"
                )
            else:
                state = "regex + AID only"
                note = f" — opt in: defenseclaw guardrail judge add {nm}"
        click.echo(f"      - {nm}: {ux.accent(state)}{ux.dim(note)}")
    click.echo()
