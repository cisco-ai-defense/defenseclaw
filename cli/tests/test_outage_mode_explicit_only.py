# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Only an explicit choice saves a hook fail mode (owner decision 2026-10-23).

Setup, init, the TUI first-run form, ``guardrail mode`` and adding a connector
never write ``hook_fail_mode`` as a side effect, so a later switch to the
strict tier closes a gateway outage unless the operator explicitly saved open.
An explicit saved choice is never dropped: an init rerun keeps it unless the
run supplies a new one, and an upgrade from 1.0.0-1.0.3 keeps every saved
value it finds (a 1.0.x Cursor ``open`` may have been written by setup, so the
upgrade names it instead of guessing).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import click
import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config, load, prepare_fresh_v8_config
from defenseclaw.context import AppContext
from defenseclaw.migrations import _pending_migration_steps, migrate

from tests.environment import isolated_home_env

TIERS = {"default": "open", "permissive": "open", "strict": "closed"}


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", lambda *_a, **_k: True)
    monkeypatch.setattr(cmd_guardrail, "_gateway_running", lambda _app: False)
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.claw.mode = "cursor"
    cfg.guardrail.connector = "cursor"
    cfg.guardrail.enabled = True
    cfg.guardrail.mode = "observe"
    cfg.guardrail.rule_pack = "default"
    cfg.save = MagicMock()
    ctx = AppContext()
    ctx.cfg = cfg
    ctx.logger = MagicMock()
    return ctx


def _saved_fail_modes(gc) -> dict[str, str]:
    """Every hook_fail_mode the config would save."""
    saved = {}
    if getattr(gc, "_hook_fail_mode_saved", False):
        saved["global"] = gc.hook_fail_mode
    for name, entry in (gc.connectors or {}).items():
        if str(entry.hook_fail_mode or "").strip():
            saved[name] = entry.hook_fail_mode
    return saved


def _assert_tier_decides(gc, connectors=("cursor",)) -> None:
    assert _saved_fail_modes(gc) == {}
    for tier, want in TIERS.items():
        gc.rule_pack = tier
        for name in connectors:
            assert gc.effective_hook_fail_mode(name) == want, (tier, name)


def _mode(app, *args) -> None:
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["mode", *args, "--no-restart"], obj=app, catch_exceptions=False)
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("roster", ["single", "multi"])
@pytest.mark.parametrize("modes", [("action",), ("action", "observe"), ("action", "observe", "action")])
def test_guardrail_mode_never_saves_a_fail_mode(app, roster, modes) -> None:
    # Round d r2 P1: `guardrail mode` copied Cursor's effective (tier) mode
    # into hook_fail_mode, so `guardrail use-pack strict` then failed open.
    gc = app.cfg.guardrail
    if roster == "multi":
        gc.connectors = {"cursor": PerConnectorGuardrailConfig(), "codex": PerConnectorGuardrailConfig()}
    for mode in modes:
        _mode(app, mode)
    _assert_tier_decides(gc, ("cursor", "codex"))


def test_guardrail_mode_for_one_connector_never_saves_a_fail_mode(app) -> None:
    gc = app.cfg.guardrail
    gc.connectors = {"cursor": PerConnectorGuardrailConfig(), "codex": PerConnectorGuardrailConfig()}
    _mode(app, "action", "--connector", "cursor")
    _mode(app, "--clear", "--connector", "cursor")
    _assert_tier_decides(gc, ("cursor", "codex"))


@pytest.mark.parametrize("explicit", ["open", "closed"])
def test_guardrail_mode_keeps_an_explicit_choice(app, explicit) -> None:
    gc = app.cfg.guardrail
    gc.hook_fail_mode = explicit
    _mode(app, "action")
    _mode(app, "observe")
    assert _saved_fail_modes(gc) == {"global": explicit}
    for tier in TIERS:
        gc.rule_pack = tier
        assert gc.effective_hook_fail_mode("cursor") == explicit


@pytest.mark.parametrize("predecessor", ["cursor", "codex"])
@pytest.mark.parametrize("predecessor_mode", ["observe", "action"])
def test_adding_a_connector_saves_no_fail_mode_for_the_first(app, predecessor, predecessor_mode) -> None:
    # Setup seeded the in-memory "closed" placeholder of an unset global
    # value into an action predecessor's own entry.
    cfg = app.cfg
    cfg.claw.mode = cfg.guardrail.connector = predecessor
    cfg.guardrail.mode = predecessor_mode
    cmd_setup._write_connector_identity(cfg, "claudecode" if predecessor != "claudecode" else "codex", "add")
    _assert_tier_decides(cfg.guardrail, (predecessor,))


def test_adding_a_connector_keeps_an_explicit_global_choice(app) -> None:
    cfg = app.cfg
    cfg.guardrail.mode = "action"
    cfg.guardrail.hook_fail_mode = "open"
    cmd_setup._write_connector_identity(cfg, "codex", "add")
    cfg.guardrail.rule_pack = "strict"
    assert cfg.guardrail.effective_hook_fail_mode("cursor") == "open"


def _prompt(gc, answer: str) -> str:
    @click.command()
    def run() -> None:
        cmd_setup._prompt_hook_fail_mode(gc)

    result = CliRunner().invoke(run, [], input=answer, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return result.output


@pytest.mark.parametrize("tier", list(TIERS))
def test_enter_at_the_setup_prompt_saves_nothing(tmp_path, monkeypatch, tier) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = prepare_fresh_v8_config(default_config())
    cfg.guardrail.rule_pack = tier
    output = _prompt(cfg.guardrail, "\n")
    assert "Enter to keep the policy default" in output
    cfg.save()
    assert "hook_fail_mode" not in yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["guardrail"]
    _assert_tier_decides(cfg.guardrail)


@pytest.mark.parametrize("answer,explicit", [("1\n", "open"), ("2\n", "closed")])
def test_a_typed_setup_choice_is_saved_and_wins_over_every_tier(tmp_path, monkeypatch, answer, explicit) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = prepare_fresh_v8_config(default_config())
    _prompt(cfg.guardrail, answer)
    cfg.save()
    assert yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["guardrail"]["hook_fail_mode"] == explicit
    reloaded = load(data_dir=str(tmp_path)).guardrail
    for tier in TIERS:
        reloaded.rule_pack = tier
        assert reloaded.effective_hook_fail_mode("cursor") == explicit


def test_enter_keeps_a_saved_choice() -> None:
    from defenseclaw.config import GuardrailConfig

    gc = GuardrailConfig(hook_fail_mode="open", rule_pack="strict")
    output = _prompt(gc, "\n")
    assert "Enter to keep open" in output
    assert _saved_fail_modes(gc) == {"global": "open"}


def test_tui_first_run_saves_no_fail_mode_unless_one_is_picked() -> None:
    from defenseclaw.tui.panels.first_run import FirstRunPanelModel

    panel = FirstRunPanelModel()
    panel.cursor = 1
    panel.handle_key("right")  # action profile
    args = panel.args()
    assert args[args.index("--profile") + 1] == "action"
    assert "--fail-mode" not in args
    panel.cursor = 4
    for want in ("open", "closed"):
        panel.handle_key("right")
        args = panel.args()
        assert args[args.index("--fail-mode") + 1] == want


def test_init_cursor_posture_saves_no_fail_mode(app) -> None:
    from defenseclaw.bootstrap import pin_cursor_posture

    gc = app.cfg.guardrail
    for mode in ("observe", "action"):
        gc.mode = mode
        pin_cursor_posture(gc, "cursor")
        gc.connectors = {"cursor": PerConnectorGuardrailConfig(mode=mode)}
        pin_cursor_posture(gc, "cursor")
        gc.connectors = {}
    _assert_tier_decides(gc)


def _write(tmp_path, guardrail: dict, **extra) -> None:
    doc = {"config_version": 9, "guardrail": guardrail, "observability": {}, **extra}
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def _guardrail(tmp_path) -> dict:
    return yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["guardrail"]


@pytest.mark.parametrize("release", ["1.0.0", "1.0.3"])
@pytest.mark.parametrize("tier", list(TIERS))
@pytest.mark.parametrize("shape", ["global", "connector"])
def test_upgrade_never_loosens_a_closed_cursor_value(tmp_path, release, tier, shape) -> None:
    # 1.0.x action mode blocked Cursor during an outage: keep that.
    guardrail = {"mode": "action", "rule_pack": tier, "connector": "cursor"}
    if shape == "global":
        guardrail["hook_fail_mode"] = "closed"
    else:
        guardrail["connectors"] = {"cursor": {"hook_fail_mode": "closed"}, "codex": {}}
    _write(tmp_path, guardrail)
    migrate(str(tmp_path), from_version=release)
    saved = _guardrail(tmp_path)
    assert (saved if shape == "global" else saved["connectors"]["cursor"])["hook_fail_mode"] == "closed"
    assert load(data_dir=str(tmp_path)).guardrail.effective_hook_fail_mode("cursor") == "closed"


@pytest.mark.parametrize("release", ["1.0.0", "1.0.3", "1.0.4"])
@pytest.mark.parametrize("tier", list(TIERS))
@pytest.mark.parametrize("shape", ["global", "connector"])
def test_upgrade_keeps_a_1_0_x_cursor_open_and_names_it(tmp_path, capsys, release, tier, shape) -> None:
    # Loop round 2 P2: 1.0.x `guardrail fail-mode open` and `config set`
    # saved the same bytes setup wrote for an observe Cursor, so the upgrade
    # cannot tell them apart. It keeps the value (1.0.3 failed open here in
    # every tier, strict included) and names the command that hands the
    # decision to the tier.
    guardrail = {"mode": "observe", "rule_pack": tier, "connector": "cursor"}
    if shape == "global":
        guardrail["hook_fail_mode"] = "open"
        path = "guardrail.hook_fail_mode"
    else:
        guardrail["connectors"] = {"cursor": {"hook_fail_mode": "open"}, "codex": {}}
        path = "guardrail.connectors.cursor.hook_fail_mode"
    _write(tmp_path, guardrail)
    capsys.readouterr()
    migrate(str(tmp_path), from_version=release)
    saved = _guardrail(tmp_path)
    assert (saved if shape == "global" else saved["connectors"]["cursor"])["hook_fail_mode"] == "open"
    assert load(data_dir=str(tmp_path)).guardrail.effective_hook_fail_mode("cursor") == "open"
    out = capsys.readouterr()
    named = f"defenseclaw config unset {path}" in out.out + out.err
    assert named is (release != "1.0.4")


def test_upgrade_keeps_a_global_choice_beside_a_cursor_entry(tmp_path) -> None:
    # Old setup wrote the global value only for a Cursor without its own
    # entry; next to one, the global open is another connector's choice.
    _write(
        tmp_path,
        {
            "mode": "observe",
            "rule_pack": "strict",
            "connector": "cursor",
            "hook_fail_mode": "open",
            "connectors": {"cursor": {}, "codex": {}},
        },
    )
    migrate(str(tmp_path), from_version="1.0.3")
    assert _guardrail(tmp_path)["hook_fail_mode"] == "open"


def test_cursor_upgrade_step_does_not_hide_the_providers_fold(tmp_path) -> None:
    # Round d r2 P3: the providers fold runs only when no other step is
    # pending, so the Cursor step must not be counted before it.
    _write(tmp_path, {"mode": "observe", "connector": "cursor", "hook_fail_mode": "open"})
    (tmp_path / "custom-providers.json").write_text(
        json.dumps({"providers": [{"name": "acme", "domains": ["acme.example.test"]}]}), encoding="utf-8"
    )
    steps = [name for name, _fn in _pending_migration_steps(9, "1.0.3", str(tmp_path), str(tmp_path / "config.yaml"), 9)]
    assert steps == ["fold the legacy custom-providers.json into config.yaml"]


def _first_run_env(tmp_path, monkeypatch) -> None:
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", lambda *_a, **_k: True)


@pytest.mark.parametrize("saved", ["", "open", "closed"])
@pytest.mark.parametrize("choice", [None, "open", "closed"])
def test_init_rerun_keeps_each_saved_connector_fail_mode_unless_one_is_chosen(tmp_path, monkeypatch, saved, choice):
    # Loop round 2 P1: a multi-connector init rerun rebuilt every connector
    # block without its hook_fail_mode, so a saved closed fell to the tier
    # (open on default) during an outage.
    from defenseclaw import config as cfg_mod
    from defenseclaw.commands.cmd_init import _activate_additional_connectors

    _first_run_env(tmp_path, monkeypatch)
    other = {"": "", "open": "closed", "closed": "open"}[saved]
    cfg = default_config()
    cfg.guardrail.connector = "codex"
    cfg.claw.mode = "codex"
    cfg.guardrail.enabled = True
    before = {
        "codex": PerConnectorGuardrailConfig(mode="action", hook_fail_mode=saved),
        "claudecode": PerConnectorGuardrailConfig(mode="action", hook_fail_mode=other),
    }
    cfg.guardrail.connectors = dict(before)
    cfg.save()
    knobs = {"fail_mode": choice, "human_approval": None, "hilt_min_severity": None}
    _activate_additional_connectors(
        {"connector": "codex", "profile": "action", **knobs},
        [{"connector": "claudecode", "profile": "action", **knobs}],
        start_gateway=False,
        overrides_before=before,
    )
    gc = cfg_mod.load().guardrail
    for tier, tier_mode in TIERS.items():
        gc.rule_pack = tier
        assert gc.effective_hook_fail_mode("codex") == (choice or saved or tier_mode), tier
        assert gc.effective_hook_fail_mode("claudecode") == (choice or other or tier_mode), tier
    if not choice and not saved:
        assert _saved_fail_modes(gc) == {}


@pytest.mark.parametrize("saved", ["", "open", "closed"])
@pytest.mark.parametrize("choice", ["", "open", "closed"])
def test_first_run_choice_replaces_the_connectors_own_saved_mode(saved, choice) -> None:
    # The single-connector first run keeps the connector's own block; its
    # saved value would otherwise win over the global choice just made.
    from defenseclaw.bootstrap import FirstRunOptions, _apply_first_run_choices

    cfg = default_config()
    cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(hook_fail_mode=saved)}
    _apply_first_run_choices(cfg, FirstRunOptions(connector="codex", hook_fail_mode=choice), "codex", "action", "local")
    gc = cfg.guardrail
    for tier, tier_mode in TIERS.items():
        gc.rule_pack = tier
        assert gc.effective_hook_fail_mode("codex") == (choice or saved or tier_mode), tier


# Owner decision 2026-10-23, written out on its own so the table below checks
# the real writers and the real resolver against the rule, not against code.
def _rule(tier: str, install: str, saved: str) -> str:
    if saved in ("open", "closed"):
        return saved
    if install == "managed":
        return "closed"
    if install == "secure_client":
        return "open"
    return TIERS[tier]


def _setup_writers(app) -> None:
    """Every setup-time writer a user runs without choosing a fail mode."""
    cfg = app.cfg
    from defenseclaw.bootstrap import pin_cursor_posture

    _prompt(cfg.guardrail, "\n")
    pin_cursor_posture(cfg.guardrail, "cursor")
    for mode in ("action", "observe", "action"):
        _mode(app, mode)
    cmd_setup._write_connector_identity(cfg, "codex", "add")
    pin_cursor_posture(cfg.guardrail, "cursor")
    _mode(app, "observe", "--connector", "cursor")
    _mode(app, "action", "--connector", "codex")


_TABLE = [
    (tier, install, saved)
    for tier in TIERS
    for install in ("oss", "managed", "secure_client")
    for saved in ("unset", "open", "closed", "setup-written")
    # Managed installs refuse local setup writers; their config is the admin's.
    if not (install != "oss" and saved == "setup-written")
]


@pytest.mark.parametrize("tier,install,saved", _TABLE)
def test_outage_mode_table_through_the_real_writers_and_resolver(app, tier, install, saved) -> None:
    # Tier x install x saved mode. On an OSS install every setup writer runs
    # on the default tier first, then the tier changes: the round d r2 case
    # is `guardrail mode` after setup pinned Cursor, then strict.
    cfg = app.cfg
    gc = cfg.guardrail
    if install == "managed":
        cfg.deployment_mode = "managed_enterprise"
        cfg.enterprise_profile = "standalone"
    elif install == "secure_client":
        gc._secure_client = True
    if saved in ("open", "closed"):
        gc.hook_fail_mode = saved  # what `guardrail fail-mode` / `config set` save
    if install == "oss" and saved != "unset":
        _setup_writers(app)
    gc.rule_pack = tier
    want = _rule(tier, install, saved)
    for name in ("cursor", "codex"):
        assert gc.effective_hook_fail_mode(name) == want, (name, gc.connectors)
    if install == "oss" and saved == "setup-written":
        assert _saved_fail_modes(gc) == {}


# The Cursor hook contract lock records the outage mode its config gives (Go
# connector.OutageHookFailMode). With no setup-written Cursor pin any more,
# Setup readiness and doctor must not expect the guardrail mode's old pin.
@pytest.mark.parametrize(
    "mode,tier,lock,ready",
    [
        ("action", "default", "open", True),
        ("observe", "strict", "closed", True),
        ("action", "default", "closed", False),
        ("observe", "strict", "open", False),
    ],
)
def test_cursor_readiness_expects_the_outage_mode_lock(monkeypatch, tmp_path, mode, tier, lock, ready) -> None:
    from types import SimpleNamespace

    from defenseclaw.commands import cmd_doctor
    from defenseclaw.config import GuardrailConfig

    gc = GuardrailConfig(mode=mode, rule_pack=tier, connector="cursor")
    cfg = SimpleNamespace(data_dir=str(tmp_path), deployment_mode="local", guardrail=gc)
    effective = gc.effective_hook_fail_mode("cursor")
    monkeypatch.setattr("defenseclaw.fail_mode.connector_registration_lock_state", lambda *_a: (lock, ""))
    monkeypatch.setattr(
        "defenseclaw.fail_mode.connector_fail_mode_report",
        lambda *_a, **_k: {"configured": effective, "desired": effective, "effective": effective},
    )

    def passing(label):
        return lambda _cfg, _name, r, **_k: r.checks.append({"label": label, "status": "pass", "detail": ""})

    monkeypatch.setattr(cmd_doctor, "_check_hook_contract_lock", passing("Hook contract"))
    monkeypatch.setattr(cmd_doctor, "_check_connector_hooks", passing("Cursor hooks"))
    readiness = cmd_doctor.connector_setup_readiness(cfg, "cursor")
    assert bool(readiness) is ready, readiness
    if not ready:
        assert readiness.invariant == "fail-mode"


def test_cursor_lock_fail_mode_keeps_the_managed_reading() -> None:
    from types import SimpleNamespace

    from defenseclaw.commands.cmd_doctor import _cursor_lock_fail_mode
    from defenseclaw.config import GuardrailConfig

    for tier in TIERS:
        for mode in ("observe", "action"):
            gc = GuardrailConfig(mode=mode, rule_pack=tier, connector="cursor")
            per_user = SimpleNamespace(deployment_mode="local", guardrail=gc)
            assert _cursor_lock_fail_mode(per_user) == TIERS[tier]
            gc.hook_fail_mode = "closed"
            assert _cursor_lock_fail_mode(per_user) == "closed"
            managed = SimpleNamespace(deployment_mode="managed_enterprise", guardrail=gc)
            assert _cursor_lock_fail_mode(managed) == ("closed" if mode == "action" else "open")


@pytest.mark.parametrize("tier", list(TIERS))
@pytest.mark.parametrize("install", ["oss", "managed"])
@pytest.mark.parametrize("saved", ["unset", "open", "closed", "connector-open"])
def test_setup_guardrail_summary_shows_the_outage_mode_the_hooks_use(app, tier, install, saved) -> None:
    # GAP-1963: the summary printed the raw global field, which reads
    # "closed" in memory when nothing is saved, beside a status that said open.
    cfg = app.cfg
    gc = cfg.guardrail
    if install == "managed":
        cfg.deployment_mode = "managed_enterprise"
        cfg.enterprise_profile = "standalone"
    if saved in ("open", "closed"):
        gc.hook_fail_mode = saved
    elif saved == "connector-open":
        gc.connectors["cursor"] = PerConnectorGuardrailConfig(hook_fail_mode="open")
    gc.rule_pack = tier
    row = cmd_setup._guardrail_summary_hook_fail_mode(cfg, "cursor")
    want = gc.effective_hook_fail_mode("cursor")
    if install == "oss" and saved == "unset":
        assert row == f"{TIERS[tier]} (not saved; the {tier} policy tier decides)"
    else:
        assert row == want
    assert row.split()[0] == want
